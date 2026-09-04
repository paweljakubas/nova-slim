//! NovaSlim — off-circuit NIFS folding, sumcheck compression, and slim
//! on-chain proofs.
//!
//! A long computation is decomposed into `N` identical step circuits, each
//! proving `state_{i+1} = f(step_i, state_i)`.  The primary flow is:
//!
//! 1. [`run_fold_nifs`] folds all step witnesses into a single Relaxed-R1CS
//!    accumulator ([`nifs`] module — transparent, no trusted setup).
//! 2. [`run_compress_sumcheck`] compresses the final instance into a
//!    constant-size sumcheck proof ([`sumcheck`] module), or a **slim**
//!    on-chain proof via [`NifsSumcheckProof::to_slim`] (HashPC openings
//!    stripped).
//! 3. [`run_verify_slim`] verifies it with native field operations only.
//!
//! The step circuits must satisfy one invariant (checked by [`check_step_circuit`],
//! exposed to the CLI as the `params` operation): the number of public inputs
//! must equal the number of public outputs (`n_pub_in == n_pub_out`), so the
//! public-input block of step `i+1` must equal the public-output block of
//! step `i`.  Public inputs ARE the IVC state.
//!
//! The proof-system core (R1CS parsing, circom adapter) lives in the
//! `groth16-prover` crate; this crate adds the IVC folding layer on top.
//! The `nova-slim` CLI (`cli`) wraps the operations in this crate.

use ark_ff::{BigInteger, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2b512, Digest};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crate::circuit::SparseCircuit;
use crate::commitment::CommitmentScheme;
use crate::curve::{NovaCurve, ScalarField};

/// Optimization flags for folding and compression.
///
/// These flags can be combined freely:
/// - `parallel`: use rayon for independent row/column operations
/// - `lazy_commit`: defer Pedersen MSM to the final fold step
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OptFlags {
    /// Parallelize independent row operations (cross-term, sumcheck products)
    /// using rayon.
    pub parallel: bool,
    /// Defer the Pedersen commitment MSM to the final fold step, computing
    /// only incremental group additions during intermediate folds.
    pub lazy_commit: bool,
}

impl OptFlags {
    pub const NONE: Self = Self {
        parallel: false,
        lazy_commit: false,
    };
    pub const PARALLEL: Self = Self {
        parallel: true,
        lazy_commit: false,
    };
    pub const LAZY_COMMIT: Self = Self {
        parallel: false,
        lazy_commit: true,
    };
    pub const ALL: Self = Self {
        parallel: true,
        lazy_commit: true,
    };

    pub fn is_empty(&self) -> bool {
        *self == Self::NONE
    }
}

/// NIFS domain separators.
///
/// `NIFS_PARAMS_SEED` derives the transparent Pedersen basis; the transcript
/// prefix binds the fold sequence and is domain-separated from the folding
/// challenge hash to prevent cross-context challenge reuse.
pub const NIFS_PARAMS_SEED: &[u8] = b"groth16-prover-nova-nifs-params-v1";
pub const NIFS_TRANSCRIPT_PREFIX: &[u8] = b"groth16-prover-nova-nifs-transcript-v1";

/// Default SIS output dimension (`m`).  Used as the default for the
/// `--sis-param` CLI argument.  Production deployments should scale `m`
/// with the security parameter (e.g., `m = 128` for 128-bit PQ security).
pub const DEFAULT_SIS_PARAM: usize = commitment::SIS_OUTPUT_DIM;

/// Generic sparse R1CS circuit parser.
pub mod circuit;

/// Curve abstraction — makes the folding scheme curve-agnostic.
pub mod curve;

/// Commitment scheme abstraction (Pedersen, future SIS).
pub mod commitment;

/// NIFS folding module — Relaxed-R1CS over any commitment scheme.
pub mod nifs;

/// Sumcheck-based constant-size compression — a sumcheck argument over the
/// relaxed R1CS equation + HashPC commitments.
pub mod norm;
pub mod sumcheck;

/// JSON descriptor of a step circuit (emitted by the `params` operation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitDescriptor {
    pub n_wires: u32,
    pub n_constraints: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prv_in: u32,
}

/// Final Relaxed-R1CS instance in a NIFS bundle (public artifact).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NifsFinalInstance {
    /// Folded public input (IVC state), decimal field strings
    pub x: Vec<String>,
    /// Slack scalar `u`, decimal
    pub u: String,
    /// Pedersen commitment to the final witness (compressed G1 hex)
    pub w_commit: String,
    /// Pedersen commitment to the final error (compressed G1 hex)
    pub e_commit: String,
}

/// The NIFS bundle produced by [`run_fold_nifs`] — O(1) in the step count.
///
/// Consumed by the sumcheck compression ([`run_compress_sumcheck`]) and by
/// `nova-slim verify`.  `n_wires`/`n_constraints` are included so the verifier can
/// derive the transparent Pedersen basis for the commitment check without
/// re-loading the step circuit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NifsBundle {
    pub circuit: String,
    pub n_wires: u32,
    pub n_constraints: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub initial_state: Vec<String>,
    pub n_steps: usize,
    pub final_instance: NifsFinalInstance,
    pub transcript_final: String,
}

/// Compact CBOR codec for the public artifacts ([`NifsBundle`],
/// [`NifsSlimProof`], [`NifsSumcheckProof`]).
///
/// Field elements are stored as 32-byte little-endian values, curve points in
/// compressed form and digests as raw bytes — roughly half the size of the
/// decimal/hex JSON encoding.  Format version `v` guards against decoding
/// stale artifacts.
pub mod codec {
    use super::{NifsBundle, NifsFinalInstance, NifsSlimProof, NifsSumcheckProof};
    use ark_ff::PrimeField;
    use serde::{Deserialize, Serialize};
    use serde_bytes::ByteBuf;
    use std::error::Error;

    const FORMAT_VERSION: u8 = 1;

    /// A field element in its cheapest CBOR form: a plain integer when the
    /// value fits in u64 (sumcheck coefficients often do), otherwise the
    /// canonical 32-byte little-endian encoding.
    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum FrCbor {
        Small(u64),
        Wide(#[serde(with = "serde_bytes")] Box<[u8]>),
    }

    fn fr_enc<F: PrimeField>(f: &F) -> FrCbor {
        let big = f.into_bigint();
        let limbs = big.as_ref();
        if limbs.len() > 1 && limbs[1..].iter().all(|&x| x == 0) {
            FrCbor::Small(limbs[0])
        } else {
            let mut buf = Vec::with_capacity(32);
            f.serialize_compressed(&mut buf).expect("Fr serialize");
            FrCbor::Wide(Box::from(buf))
        }
    }

    fn fr_dec<F: PrimeField>(v: &FrCbor) -> Result<F, Box<dyn Error>> {
        match v {
            FrCbor::Small(x) => Ok(F::from(*x)),
            FrCbor::Wide(b) => Ok(F::deserialize_compressed(b.as_ref())?),
        }
    }

    fn fr_parse<F: PrimeField>(s: &str) -> Result<F, Box<dyn Error>> {
        s.parse::<F>()
            .map_err(|_| format!("invalid field element '{s}'").into())
    }

    fn frs_enc<F: PrimeField>(strs: &[String]) -> Result<Vec<FrCbor>, Box<dyn Error>> {
        strs.iter()
            .map(|s| Ok(fr_enc(&fr_parse::<F>(s)?)))
            .collect()
    }

    fn frs_dec<F: PrimeField>(vs: &[FrCbor]) -> Result<Vec<String>, Box<dyn Error>> {
        vs.iter()
            .map(|v| Ok(super::fr_to_string(&fr_dec::<F>(v)?)))
            .collect()
    }

    fn hash_enc(hex_str: &str) -> Result<ByteBuf, Box<dyn Error>> {
        Ok(ByteBuf::from(hex::decode(hex_str)?))
    }

    fn instance_enc<F: PrimeField>(i: &NifsFinalInstance) -> Result<InstanceCbor, Box<dyn Error>> {
        Ok(InstanceCbor {
            x: frs_enc::<F>(&i.x)?,
            u: fr_enc(&fr_parse::<F>(&i.u)?),
            w_commit: ByteBuf::from(hex::decode(&i.w_commit)?),
            e_commit: ByteBuf::from(hex::decode(&i.e_commit)?),
        })
    }

    fn instance_dec<F: PrimeField>(c: &InstanceCbor) -> Result<NifsFinalInstance, Box<dyn Error>> {
        Ok(NifsFinalInstance {
            x: frs_dec::<F>(&c.x)?,
            u: super::fr_to_string(&fr_dec::<F>(&c.u)?),
            w_commit: hex::encode(&c.w_commit),
            e_commit: hex::encode(&c.e_commit),
        })
    }

    #[derive(Serialize, Deserialize)]
    struct InstanceCbor {
        x: Vec<FrCbor>,
        u: FrCbor,
        w_commit: ByteBuf,
        e_commit: ByteBuf,
    }

    #[derive(Serialize, Deserialize)]
    struct Dims([u32; 4]);

    #[derive(Serialize, Deserialize)]
    struct BundleCbor {
        v: u8,
        circuit: String,
        dims: Dims,
        initial_state: Vec<FrCbor>,
        n_steps: u64,
        final_instance: InstanceCbor,
        transcript_final: ByteBuf,
    }

    #[derive(Serialize, Deserialize)]
    struct SlimProofCbor {
        v: u8,
        polys: Vec<Vec<FrCbor>>,
        r_challenges: Vec<FrCbor>,
        product_at_r: FrCbor,
        w_hash: ByteBuf,
        e_hash: ByteBuf,
        bundle_instance_hash: ByteBuf,
    }

    #[derive(Serialize, Deserialize)]
    struct SumcheckProofCbor {
        v: u8,
        circuit: String,
        dims: Dims,
        final_instance: InstanceCbor,
        polys: Vec<Vec<FrCbor>>,
        claims: Vec<FrCbor>,
        r_challenges: Vec<FrCbor>,
        product_at_r: FrCbor,
        w_hash: ByteBuf,
        e_hash: ByteBuf,
        w_opening: Vec<FrCbor>,
        e_opening: Vec<FrCbor>,
    }

    fn core_of(p: &NifsSumcheckProof) -> Result<(String, Dims), Box<dyn Error>> {
        Ok((
            p.circuit.clone(),
            Dims([p.n_wires, p.n_constraints, p.n_pub_out, p.n_pub_in]),
        ))
    }

    fn write<T: Serialize>(v: &T) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut out = Vec::new();
        ciborium::into_writer(v, &mut out)?;
        Ok(out)
    }

    fn check_version(v: u8) -> Result<(), Box<dyn Error>> {
        if v != FORMAT_VERSION {
            Err(
                format!("unsupported artifact format version {v} (expected {FORMAT_VERSION})")
                    .into(),
            )
        } else {
            Ok(())
        }
    }

    pub fn bundle_encode<F: PrimeField>(b: &NifsBundle) -> Result<Vec<u8>, Box<dyn Error>> {
        let dto = BundleCbor {
            v: FORMAT_VERSION,
            circuit: b.circuit.clone(),
            dims: Dims([b.n_wires, b.n_constraints, b.n_pub_out, b.n_pub_in]),
            initial_state: frs_enc::<F>(&b.initial_state)?,
            n_steps: b.n_steps as u64,
            final_instance: instance_enc::<F>(&b.final_instance)?,
            transcript_final: hash_enc(&b.transcript_final)?,
        };
        write(&dto)
    }

    pub fn bundle_decode<F: PrimeField>(bytes: &[u8]) -> Result<NifsBundle, Box<dyn Error>> {
        let d: BundleCbor =
            ciborium::from_reader(bytes).map_err(|e| format!("invalid CBOR bundle: {e}"))?;
        check_version(d.v)?;
        let [nw, nc, npo, npi] = d.dims.0;
        Ok(NifsBundle {
            circuit: d.circuit,
            n_wires: nw,
            n_constraints: nc,
            n_pub_out: npo,
            n_pub_in: npi,
            initial_state: frs_dec::<F>(&d.initial_state)?,
            n_steps: d.n_steps as usize,
            final_instance: instance_dec::<F>(&d.final_instance)?,
            transcript_final: hex::encode(&d.transcript_final),
        })
    }

    pub fn slim_proof_encode<F: PrimeField>(p: &NifsSlimProof) -> Result<Vec<u8>, Box<dyn Error>> {
        let dto = SlimProofCbor {
            v: FORMAT_VERSION,
            polys: p
                .sumcheck_polys
                .iter()
                .map(|row| frs_enc::<F>(row))
                .collect::<Result<_, _>>()?,
            r_challenges: frs_enc::<F>(&p.r_challenges)?,
            product_at_r: fr_enc(&fr_parse::<F>(&p.claimed_product_at_r)?),
            w_hash: hash_enc(&p.w_commit_hash)?,
            e_hash: hash_enc(&p.e_commit_hash)?,
            bundle_instance_hash: hash_enc(&p.bundle_final_instance_hash)?,
        };
        write(&dto)
    }

    pub fn slim_proof_decode<F: PrimeField>(bytes: &[u8]) -> Result<NifsSlimProof, Box<dyn Error>> {
        let d: SlimProofCbor =
            ciborium::from_reader(bytes).map_err(|e| format!("invalid CBOR slim proof: {e}"))?;
        check_version(d.v)?;
        Ok(NifsSlimProof {
            sumcheck_polys: d
                .polys
                .iter()
                .map(|row| frs_dec::<F>(row))
                .collect::<Result<Vec<_>, _>>()?,
            r_challenges: frs_dec::<F>(&d.r_challenges)?,
            claimed_product_at_r: super::fr_to_string(&fr_dec::<F>(&d.product_at_r)?),
            w_commit_hash: hex::encode(&d.w_hash),
            e_commit_hash: hex::encode(&d.e_hash),
            bundle_final_instance_hash: hex::encode(&d.bundle_instance_hash),
        })
    }

    // ── slim proof helpers ──────────────────────────────────────────────

    pub fn sumcheck_proof_encode<F: PrimeField>(
        p: &NifsSumcheckProof,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let (circuit, dims) = core_of(p)?;
        let dto = SumcheckProofCbor {
            v: FORMAT_VERSION,
            circuit,
            dims,
            final_instance: instance_enc::<F>(&p.final_instance)?,
            polys: p
                .sumcheck_polys
                .iter()
                .map(|row| frs_enc::<F>(row))
                .collect::<Result<_, _>>()?,
            claims: frs_enc::<F>(&p.sumcheck_claims)?,
            r_challenges: frs_enc::<F>(&p.r_challenges)?,
            product_at_r: fr_enc(&fr_parse::<F>(&p.claimed_product_at_r)?),
            w_hash: hash_enc(&p.w_commit_hash)?,
            e_hash: hash_enc(&p.e_commit_hash)?,
            w_opening: frs_enc::<F>(&p.w_opening)?,
            e_opening: frs_enc::<F>(&p.e_opening)?,
        };
        write(&dto)
    }

    pub fn sumcheck_proof_decode<F: PrimeField>(
        bytes: &[u8],
    ) -> Result<NifsSumcheckProof, Box<dyn Error>> {
        let d: SumcheckProofCbor =
            ciborium::from_reader(bytes).map_err(|e| format!("invalid CBOR proof: {e}"))?;
        check_version(d.v)?;
        let [nw, nc, npo, npi] = d.dims.0;
        Ok(NifsSumcheckProof {
            circuit: d.circuit.clone(),
            n_wires: nw,
            n_constraints: nc,
            n_pub_out: npo,
            n_pub_in: npi,
            final_instance: instance_dec::<F>(&d.final_instance)?,
            sumcheck_polys: d
                .polys
                .iter()
                .map(|row| frs_dec::<F>(row))
                .collect::<Result<_, _>>()?,
            sumcheck_claims: frs_dec::<F>(&d.claims)?,
            r_challenges: frs_dec::<F>(&d.r_challenges)?,
            claimed_product_at_r: super::fr_to_string(&fr_dec::<F>(&d.product_at_r)?),
            w_commit_hash: hex::encode(&d.w_hash),
            e_commit_hash: hex::encode(&d.e_hash),
            w_opening: frs_dec::<F>(&d.w_opening)?,
            e_opening: frs_dec::<F>(&d.e_opening)?,
        })
    }

    #[derive(Serialize, Deserialize)]
    struct Level1ProofCbor {
        v: u8,
        polys: Vec<Vec<FrCbor>>,
        claims: Vec<FrCbor>,
        r_challenges: Vec<FrCbor>,
        az_r: FrCbor,
        bz_r: FrCbor,
        fr_r: FrCbor,
        cz_r: FrCbor,
        er_r: FrCbor,
        u: FrCbor,
        w_hash: ByteBuf,
        e_hash: ByteBuf,
        w_opening: Vec<FrCbor>,
        e_opening: Vec<FrCbor>,
        bundle_instance_hash: ByteBuf,
        norm: Option<StepNormRecordCbor>,
    }

    /// CBOR form of a single norm certificate (flavour-tagged).
    #[derive(Serialize, Deserialize)]
    enum NormCertCbor {
        Range {
            per_coord_bits: Vec<u32>,
            bound_bits: u32,
        },
        Jl {
            y: ByteBuf,
            bound_bits: u32,
            len: usize,
            coord_bits: u32,
        },
    }

    /// CBOR form of a single step's norm certificate (witness + error).
    #[derive(Serialize, Deserialize)]
    struct StepNormCertCbor {
        cert_w: NormCertCbor,
        cert_e: NormCertCbor,
    }

    /// CBOR form of the norm record carried in a level-1 proof.
    #[derive(Serialize, Deserialize)]
    struct StepNormRecordCbor {
        mode: u8, // 0=none, 1=range, 2=jl
        bound_bits: u32,
        steps: Vec<StepNormCertCbor>,
    }

    fn norm_cert_enc(c: &super::norm::NormCertificate) -> NormCertCbor {
        match c {
            super::norm::NormCertificate::Range(r) => NormCertCbor::Range {
                per_coord_bits: r.per_coord_bits.clone(),
                bound_bits: r.bound_bits,
            },
            super::norm::NormCertificate::Jl(j) => NormCertCbor::Jl {
                y: ByteBuf::from(j.y.clone()),
                bound_bits: j.bound_bits,
                len: j.len,
                coord_bits: j.coord_bits,
            },
        }
    }

    fn norm_cert_dec(c: &NormCertCbor) -> Result<super::norm::NormCertificate, String> {
        Ok(match c {
            NormCertCbor::Range {
                per_coord_bits,
                bound_bits,
            } => super::norm::NormCertificate::Range(super::norm::RangeCertificate {
                per_coord_bits: per_coord_bits.clone(),
                bound_bits: *bound_bits,
            }),
            NormCertCbor::Jl {
                y,
                bound_bits,
                len,
                coord_bits,
            } => super::norm::NormCertificate::Jl(super::norm::JlCertificate {
                y: y.to_vec(),
                bound_bits: *bound_bits,
                len: *len,
                coord_bits: *coord_bits,
            }),
        })
    }

    fn norm_record_enc(r: &super::norm::StepNormRecord) -> StepNormRecordCbor {
        StepNormRecordCbor {
            mode: match r.mode {
                super::norm::NormMode::None => 0,
                super::norm::NormMode::Range => 1,
                super::norm::NormMode::Jl => 2,
            },
            bound_bits: r.bound_bits,
            steps: r
                .steps
                .iter()
                .map(|s| StepNormCertCbor {
                    cert_w: norm_cert_enc(&s.cert_w),
                    cert_e: norm_cert_enc(&s.cert_e),
                })
                .collect(),
        }
    }

    fn norm_record_dec(d: &StepNormRecordCbor) -> Result<super::norm::StepNormRecord, String> {
        let mode = match d.mode {
            0 => super::norm::NormMode::None,
            1 => super::norm::NormMode::Range,
            2 => super::norm::NormMode::Jl,
            other => return Err(format!("unknown norm mode tag {other}")),
        };
        let steps = d
            .steps
            .iter()
            .map(|s| {
                Ok(super::norm::StepNormCert {
                    cert_w: norm_cert_dec(&s.cert_w)?,
                    cert_e: norm_cert_dec(&s.cert_e)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(super::norm::StepNormRecord {
            mode,
            bound_bits: d.bound_bits,
            steps,
        })
    }

    pub fn level1_proof_encode<F: PrimeField>(
        p: &super::Level1SlimProof,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let dto = Level1ProofCbor {
            v: FORMAT_VERSION,
            polys: p
                .sumcheck_polys
                .iter()
                .map(|row| frs_enc::<F>(row))
                .collect::<Result<_, _>>()?,
            claims: frs_enc::<F>(&p.sumcheck_claims)?,
            r_challenges: frs_enc::<F>(&p.r_challenges)?,
            az_r: fr_enc(&fr_parse::<F>(&p.az_r)?),
            bz_r: fr_enc(&fr_parse::<F>(&p.bz_r)?),
            fr_r: fr_enc(&fr_parse::<F>(&p.fr_r)?),
            cz_r: fr_enc(&fr_parse::<F>(&p.cz_r)?),
            er_r: fr_enc(&fr_parse::<F>(&p.er_r)?),
            u: fr_enc(&fr_parse::<F>(&p.u)?),
            w_hash: hash_enc(&p.w_commit_hash)?,
            e_hash: hash_enc(&p.e_commit_hash)?,
            w_opening: frs_enc::<F>(&p.w_opening)?,
            e_opening: frs_enc::<F>(&p.e_opening)?,
            bundle_instance_hash: hash_enc(&p.bundle_final_instance_hash)?,
            norm: p.norm.as_ref().map(norm_record_enc),
        };
        write(&dto)
    }

    pub fn level1_proof_decode<F: PrimeField>(
        bytes: &[u8],
    ) -> Result<super::Level1SlimProof, Box<dyn Error>> {
        let d: Level1ProofCbor =
            ciborium::from_reader(bytes).map_err(|e| format!("invalid CBOR level-1 proof: {e}"))?;
        check_version(d.v)?;
        Ok(super::Level1SlimProof {
            sumcheck_polys: d
                .polys
                .iter()
                .map(|row| frs_dec::<F>(row))
                .collect::<Result<Vec<_>, _>>()?,
            sumcheck_claims: frs_dec::<F>(&d.claims)?,
            r_challenges: frs_dec::<F>(&d.r_challenges)?,
            az_r: super::fr_to_string(&fr_dec::<F>(&d.az_r)?),
            bz_r: super::fr_to_string(&fr_dec::<F>(&d.bz_r)?),
            fr_r: super::fr_to_string(&fr_dec::<F>(&d.fr_r)?),
            cz_r: super::fr_to_string(&fr_dec::<F>(&d.cz_r)?),
            er_r: super::fr_to_string(&fr_dec::<F>(&d.er_r)?),
            u: super::fr_to_string(&fr_dec::<F>(&d.u)?),
            w_commit_hash: hex::encode(&d.w_hash),
            e_commit_hash: hex::encode(&d.e_hash),
            w_opening: frs_dec::<F>(&d.w_opening)?,
            e_opening: frs_dec::<F>(&d.e_opening)?,
            bundle_final_instance_hash: hex::encode(&d.bundle_instance_hash),
            norm: d
                .norm
                .as_ref()
                .map(norm_record_dec)
                .transpose()
                .map_err(Box::<dyn Error>::from)?,
        })
    }

    impl super::Level1SlimProof {
        /// Compact binary encoding (CBOR).
        pub fn to_cbor<F: PrimeField>(&self) -> Result<Vec<u8>, Box<dyn Error>> {
            level1_proof_encode::<F>(self)
        }
        /// Decode a compact binary (CBOR) level-1 proof.
        pub fn from_cbor<F: PrimeField>(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
            level1_proof_decode::<F>(bytes)
        }
    }

    impl NifsBundle {
        /// Compact binary encoding (CBOR).
        pub fn to_cbor<F: PrimeField>(&self) -> Result<Vec<u8>, Box<dyn Error>> {
            bundle_encode::<F>(self)
        }
        /// Decode a compact binary (CBOR) bundle.
        pub fn from_cbor<F: PrimeField>(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
            bundle_decode::<F>(bytes)
        }
    }

    impl NifsSlimProof {
        pub fn to_cbor<F: PrimeField>(&self) -> Result<Vec<u8>, Box<dyn Error>> {
            slim_proof_encode::<F>(self)
        }
        pub fn from_cbor<F: PrimeField>(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
            slim_proof_decode::<F>(bytes)
        }
    }

    impl NifsSumcheckProof {
        pub fn to_cbor<F: PrimeField>(&self) -> Result<Vec<u8>, Box<dyn Error>> {
            sumcheck_proof_encode::<F>(self)
        }
        pub fn from_cbor<F: PrimeField>(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
            sumcheck_proof_decode::<F>(bytes)
        }
    }
}

/// Output of [`run_fold_nifs`]: the public bundle plus the private final
/// instance/witness (consumed by the compression prover).
#[derive(Debug, Clone)]
pub struct NifsFoldOutput<CS: CommitmentScheme> {
    pub bundle: NifsBundle,
    pub final_instance: nifs::RelaxedR1csInstance<CS>,
    pub final_witness: nifs::RelaxedR1csWitness<CS>,
    /// Per-fold-step pre-fold witnesses `(Z_j, E_j)` as hex field elements, in
    /// fold order.  These are the genuinely short vectors used for norm
    /// enforcement (the folded instance is field-scale and cannot be bounded).
    pub step_witnesses: Vec<(Vec<String>, Vec<String>)>,
}

/// Sumcheck-based compression proof.
///
/// Compresses a NIFS fold into a constant-size argument: a sumcheck proof
/// over the relaxed R1CS equation, HashPC commitments, and opening proofs.
/// The verifier never sees the full witness `Z` or error vector `E` — only
/// the sumcheck transcript and HashPC openings.
///
/// Proof size is O(log(n_constraints)) field elements (the sumcheck
/// messages) plus the opening proofs, independent of the step width.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NifsSumcheckProof {
    pub circuit: String,
    pub n_wires: u32,
    pub n_constraints: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    /// The final NIFS instance this proof certifies.
    pub final_instance: NifsFinalInstance,
    /// Sumcheck round polynomials (each is `[f(0), f(1)-f(0)]`).
    pub sumcheck_polys: Vec<Vec<String>>,
    /// Sumcheck claims (claimed sum + per-round evaluations).
    pub sumcheck_claims: Vec<String>,
    /// Random challenges derived by the verifier from the sumcheck transcript.
    pub r_challenges: Vec<String>,
    /// Claimed product MLE evaluation at `r`: `P_MLE(r)`.
    pub claimed_product_at_r: String,
    /// HashPC commitment to the witness vector `Z` (BLAKE2b-512 hex).
    pub w_commit_hash: String,
    /// HashPC opening proof for `Z` (truth table as decimal field strings).
    pub w_opening: Vec<String>,
    /// HashPC commitment to the error vector `E` (BLAKE2b-512 hex).
    pub e_commit_hash: String,
    /// HashPC opening proof for `E` (truth table as decimal field strings).
    pub e_opening: Vec<String>,
}

/// Summary of a successful NIFS bundle verification.
#[derive(Debug, Clone)]
pub struct VerifyOutput {
    pub steps: usize,
    pub transcript_final: String,
}

/// Load a step circuit from a `.r1cs` file.
pub fn load_circuit<C: NovaCurve>(
    path: &Path,
) -> Result<SparseCircuit<ScalarField<C>>, Box<dyn Error>> {
    let c = SparseCircuit::from_r1cs(
        path.to_str()
            .ok_or_else(|| format!("circuit path is not valid UTF-8: {path:?}"))?,
    )
    .map_err(|e| format!("failed to load circuit {}: {e}", path.display()))?;

    let expected_prime = ScalarField::<C>::MODULUS.to_bytes_le();
    if c.prime.iter().any(|&b| b != 0) && c.prime != expected_prime {
        let got_hex: String = c.prime.iter().rev().map(|b| format!("{b:02x}")).collect();
        let exp_hex: String = expected_prime
            .iter()
            .rev()
            .map(|b| format!("{b:02x}"))
            .collect();
        return Err(format!(
            "circuit prime mismatch: the .r1cs file was compiled for a different field \
             (got 0x{got_hex}, expected 0x{exp_hex}). \
             Use --curve to match the field the circuit was compiled for, \
             or recompile the circuit for this curve."
        )
        .into());
    }

    Ok(c)
}

/// Enforce the step-chain invariant: the public-input block (state in)
/// must have the same width as the public-output block (state out).
pub fn check_step_circuit<C: NovaCurve>(
    c: &SparseCircuit<ScalarField<C>>,
) -> Result<(), Box<dyn Error>> {
    if c.n_pub_in != c.n_pub_out {
        return Err(format!(
            "not a valid step circuit: n_pub_in ({}) != n_pub_out ({}) — \
             the public inputs must be exactly the IVC state and must have the \
             same width as the public outputs so that state_in[i+1] == state_out[i]",
            c.n_pub_in, c.n_pub_out
        )
        .into());
    }
    Ok(())
}

/// Build the JSON descriptor for a step circuit.
pub fn circuit_descriptor<C: NovaCurve>(c: &SparseCircuit<ScalarField<C>>) -> CircuitDescriptor {
    CircuitDescriptor {
        n_wires: c.n_wires,
        n_constraints: c.n_constraints,
        n_pub_out: c.n_pub_out,
        n_pub_in: c.n_pub_in,
        n_prv_in: c.n_prv_in,
    }
}

/// `params` — inspect a step circuit and return its JSON descriptor.
///
/// Loads the step circuit from a `.r1cs` file and validates that it
/// satisfies the IVC invariant (`n_pub_in == n_pub_out`).
pub fn run_params<C: NovaCurve>(circuit: &Path) -> Result<CircuitDescriptor, Box<dyn Error>> {
    let c = load_circuit::<C>(circuit)?;
    check_step_circuit::<C>(&c)?;
    Ok(circuit_descriptor::<C>(&c))
}

/// `fold` — fold step witnesses into a single Relaxed-R1CS instance.
///
/// Loads the step circuit and a directory of witness files, derives the
/// transparent Pedersen parameters, and folds every step instance into one
/// running accumulator via the NIFS.  Folding is linear-time and needs no
/// proving key.  Returns the O(1) [`NifsBundle`] (final instance + transcript)
/// plus the private final instance/witness for the compression proof.
pub fn run_fold_nifs<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &Path,
    steps: &Path,
) -> Result<NifsFoldOutput<CS>, Box<dyn Error>> {
    fold_nifs::<C, CS>(circuit, steps, OptFlags::NONE, DEFAULT_SIS_PARAM)
}

/// Like [`run_fold_nifs`] but with optimization flags and configurable SIS
/// output dimension.
pub fn run_fold_nifs_opt<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &Path,
    steps: &Path,
    opts: OptFlags,
    sis_param: usize,
) -> Result<NifsFoldOutput<CS>, Box<dyn Error>> {
    fold_nifs::<C, CS>(circuit, steps, opts, sis_param)
}

/// Core folding routine shared by [`run_fold_nifs`] and [`run_compress`]
/// (which re-folds deterministically to recover the private final witness).
fn fold_nifs<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &Path,
    steps: &Path,
    opts: OptFlags,
    sis_param: usize,
) -> Result<NifsFoldOutput<CS>, Box<dyn Error>> {
    let circuit_path_str = circuit.to_string_lossy().into_owned();
    let mut circuit = load_circuit::<C>(circuit)?;
    check_step_circuit::<C>(&circuit)?;

    let n_pub_out = circuit.n_pub_out as usize;
    let n_pub_in = circuit.n_pub_in as usize;
    let n_wires = circuit.n_wires as usize;
    let n_constraints = circuit.n_constraints as usize;

    let params = CS::params_from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints, sis_param);
    let zero_e = vec![ScalarField::<C>::zero(); n_constraints];

    let mut wtns_paths: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(steps)
        .map_err(|e| format!("failed to read steps dir {}: {e}", steps.display()))?
    {
        let entry = entry.map_err(|e| format!("failed to read steps dir entry: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("wtns") {
            wtns_paths.push(path);
        }
    }
    wtns_paths.sort();

    if wtns_paths.is_empty() {
        return Err(format!("no .wtns files found in steps dir {}", steps.display()).into());
    }
    eprintln!(
        "Folding {} step witnesses (NIFS) from {}",
        wtns_paths.len(),
        steps.display()
    );

    let mut acc_hash: Option<Vec<u8>> = None;
    let mut prev_out: Option<Vec<String>> = None;
    let mut initial_state: Vec<String> = Vec::new();
    let mut acc_u: Option<nifs::RelaxedR1csInstance<CS>> = None;
    let mut acc_w: Option<nifs::RelaxedR1csWitness<CS>> = None;
    let mut step_witnesses: Vec<(Vec<String>, Vec<String>)> = Vec::new();

    for (i, p) in wtns_paths.iter().enumerate() {
        circuit
            .load_witness(
                p.to_str()
                    .ok_or_else(|| format!("step witness path is not valid UTF-8: {p:?}"))?,
            )
            .map_err(|e| format!("failed to load witness {}: {e}", p.display()))?;
        let w = &circuit.witness;

        let out_fr = &w[1..1 + n_pub_out];
        let in_fr = &w[1 + n_pub_out..1 + n_pub_out + n_pub_in];
        let state_in: Vec<String> = in_fr.iter().map(fr_to_string).collect();
        let state_out: Vec<String> = out_fr.iter().map(fr_to_string).collect();

        if let Some(prev) = &prev_out {
            if state_in != *prev {
                return Err(format!(
                    "step {i} ({}): state_in does not chain to previous state_out. \
                     The step witnesses were not generated from a consistent state chain.",
                    p.display()
                )
                .into());
            }
        } else {
            initial_state = state_in.clone();
            acc_hash = Some(transcript_nifs_init::<C>(in_fr));
        }

        let x: Vec<ScalarField<C>> = w[1..1 + n_pub_out + n_pub_in].to_vec();
        let step_u = nifs::RelaxedR1csInstance {
            x,
            u: ScalarField::<C>::from(1u64),
            w_commit: CS::commit_witness(&params, w),
            e_commit: CS::zero(sis_param),
        };
        let step_w = nifs::RelaxedR1csWitness {
            w: w.to_vec(),
            e: zero_e.clone(),
        };
        step_witnesses.push((
            step_w.w.iter().map(fr_to_string).collect(),
            step_w.e.iter().map(fr_to_string).collect(),
        ));

        match acc_u.take() {
            None => {
                acc_u = Some(step_u);
                acc_w = Some(step_w);
            }
            Some(u_acc) => {
                let w_acc = acc_w.take().expect("running witness must exist");
                let acc = acc_hash.as_ref().expect("transcript initialized");
                let challenge = nifs::fold_challenge::<CS>(acc, &u_acc, &step_u);
                let (u3, w3) = nifs::fold_with_opts::<CS>(
                    &params,
                    &circuit.l,
                    &circuit.r,
                    &circuit.o,
                    &u_acc,
                    &w_acc,
                    &step_u,
                    &step_w,
                    challenge,
                    opts.parallel,
                );
                acc_u = Some(u3);
                acc_w = Some(w3);
            }
        }

        acc_hash = Some(transcript_nifs_step::<C, CS>(
            acc_hash.as_ref().expect("transcript initialized"),
            acc_u.as_ref().expect("running instance"),
        ));
        prev_out = Some(state_out);
        eprintln!(
            "  step {i:>3}: folded (u = {})",
            fr_to_string(&acc_u.as_ref().expect("running instance").u)
        );
    }

    let final_u = acc_u.ok_or("no step witnesses folded")?;
    let final_w = acc_w.expect("final witness present");
    let transcript_final = hex::encode(acc_hash.as_ref().expect("transcript finalized"));

    let bundle = NifsBundle {
        circuit: circuit_path_str,
        n_wires: circuit.n_wires,
        n_constraints: circuit.n_constraints,
        n_pub_out: circuit.n_pub_out,
        n_pub_in: circuit.n_pub_in,
        initial_state,
        n_steps: wtns_paths.len(),
        final_instance: NifsFinalInstance {
            x: final_u.x.iter().map(fr_to_string).collect(),
            u: fr_to_string(&final_u.u),
            w_commit: commitment_hex(&final_u.w_commit),
            e_commit: commitment_hex(&final_u.e_commit),
        },
        transcript_final,
    };

    Ok(NifsFoldOutput {
        bundle,
        final_instance: final_u,
        final_witness: final_w,
        step_witnesses,
    })
}

/// `compress` — compress a NIFS bundle into a constant-size proof.
///
/// No proving key is needed — the sumcheck protocol is transparent.  Folds
/// the step witnesses, builds the sumcheck compression proof (one sumcheck
/// argument + HashPC openings), and writes the JSON proof to `out`.
pub fn run_compress_sumcheck<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &Path,
    steps: &Path,
    out: &Path,
) -> Result<CompressOutput, Box<dyn Error>> {
    run_compress_sumcheck_opt::<C, CS>(circuit, steps, out, OptFlags::NONE, DEFAULT_SIS_PARAM)
}

/// Like [`run_compress_sumcheck`] but with optimization flags and configurable
/// SIS output dimension.
pub fn run_compress_sumcheck_opt<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &Path,
    steps: &Path,
    out: &Path,
    opts: OptFlags,
    sis_param: usize,
) -> Result<CompressOutput, Box<dyn Error>> {
    let c = load_circuit::<C>(circuit)?;
    check_step_circuit::<C>(&c)?;

    let folded = fold_nifs::<C, CS>(circuit, steps, opts, sis_param)?;
    let mut rng = rand::thread_rng();
    let cproof = prove_sumcheck_compression_opt::<C, CS>(&c, &folded, &mut rng, opts)?;

    let cbor = codec::sumcheck_proof_encode::<ScalarField<C>>(&cproof)
        .map_err(|e| format!("failed to serialize sumcheck proof: {e}"))?;
    fs::write(out, &cbor)
        .map_err(|e| format!("failed to write sumcheck proof to {}: {e}", out.display()))?;
    eprintln!(
        "Sumcheck proof written to {} ({} bytes, u = {})",
        out.display(),
        cbor.len(),
        fr_to_string(&folded.final_instance.u)
    );
    Ok(CompressOutput {
        bytes: cbor.len(),
        bundle: folded.bundle,
    })
}

/// Verify a sumcheck compression proof against a NIFS bundle (CLI path).
///
/// Loads the NIFS bundle and the compact CBOR sumcheck proof, then runs
/// [`verify_sumcheck_compression`].  No verifying key is needed.
pub fn run_verify_sumcheck<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    ivc: &Path,
    sumcheck_proof: &Path,
) -> Result<VerifyOutput, Box<dyn Error>> {
    run_verify_sumcheck_opt::<C, CS>(ivc, sumcheck_proof, DEFAULT_SIS_PARAM)
}

/// Like [`run_verify_sumcheck`] but with configurable SIS output dimension.
pub fn run_verify_sumcheck_opt<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    ivc: &Path,
    sumcheck_proof: &Path,
    sis_param: usize,
) -> Result<VerifyOutput, Box<dyn Error>> {
    let bundle_bytes =
        fs::read(ivc).map_err(|e| format!("failed to read IVC bundle {}: {e}", ivc.display()))?;
    let bundle: NifsBundle = codec::bundle_decode::<ScalarField<C>>(&bundle_bytes)
        .map_err(|e| format!("failed to parse IVC bundle as NIFS bundle: {e}"))?;

    let proof_bytes = fs::read(sumcheck_proof).map_err(|e| {
        format!(
            "failed to read sumcheck proof {}: {e}",
            sumcheck_proof.display()
        )
    })?;
    let sc_proof: NifsSumcheckProof = codec::sumcheck_proof_decode::<ScalarField<C>>(&proof_bytes)
        .map_err(|e| format!("failed to parse sumcheck proof: {e}"))?;

    verify_sumcheck_compression_inner::<C, CS>(&bundle, &sc_proof, sis_param, None)
}

fn circuit_path_display<C: NovaCurve>(_c: &SparseCircuit<ScalarField<C>>) -> String {
    // The circuit's source path is only known to the file-based loaders; the
    // in-memory path records the step circuit's provenance as its identity is
    // carried by the bundle instead.
    String::new()
}

/// Output of [`run_compress_sumcheck`].
#[derive(Debug, Clone)]
pub struct CompressOutput {
    pub bytes: usize,
    pub bundle: NifsBundle,
}

/// Build a sumcheck compression proof over an already-folded NIFS instance
/// (in-memory).
///
/// Produces a sumcheck proof over the relaxed R1CS equation plus HashPC
/// opening proofs.  The proof size is O(log(n_constraints)) field elements
/// (the sumcheck messages), independent of the step width.
pub fn prove_sumcheck_compression<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &SparseCircuit<ScalarField<C>>,
    folded: &NifsFoldOutput<CS>,
    _rng: &mut impl rand::RngCore,
) -> Result<NifsSumcheckProof, Box<dyn Error>> {
    prove_sumcheck_compression_opt::<C, CS>(circuit, folded, _rng, OptFlags::NONE)
}

/// Like [`prove_sumcheck_compression`] but with optimization flags.
pub fn prove_sumcheck_compression_opt<
    C: NovaCurve,
    CS: CommitmentScheme<Scalar = ScalarField<C>>,
>(
    circuit: &SparseCircuit<ScalarField<C>>,
    folded: &NifsFoldOutput<CS>,
    _rng: &mut impl rand::RngCore,
    opts: OptFlags,
) -> Result<NifsSumcheckProof, Box<dyn Error>> {
    let n_wires = circuit.n_wires as usize;
    let n_constraints = circuit.n_constraints as usize;
    let params =
        commitment::PedersenParams::<C>::from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints);

    // Build the full witness: Z = folded wire vector, E = error vector.
    let z = &folded.final_witness.w;
    let e = &folded.final_witness.e;
    let u = folded.final_instance.u;

    // Run sumcheck prover.
    let (proof, r_challenges) =
        sumcheck::prove_with_opts::<C>(&circuit.l, &circuit.r, &circuit.o, z, u, e, opts.parallel);

    // Build product vector and evaluate its MLE at r (for the final check).
    let n_padded = sumcheck::next_power_of_two(n_constraints);
    let products: Vec<ScalarField<C>> = if opts.parallel {
        (0..n_constraints)
            .into_par_iter()
            .map(|j| {
                let az = sumcheck::eval_row_mle(&circuit.l[j], z);
                let bz = sumcheck::eval_row_mle(&circuit.r[j], z);
                let cz = sumcheck::eval_row_mle(&circuit.o[j], z);
                az * bz - u * cz - e[j]
            })
            .collect()
    } else {
        (0..n_constraints)
            .map(|j| {
                let az = sumcheck::eval_row_mle(&circuit.l[j], z);
                let bz = sumcheck::eval_row_mle(&circuit.r[j], z);
                let cz = sumcheck::eval_row_mle(&circuit.o[j], z);
                az * bz - u * cz - e[j]
            })
            .collect()
    };
    let mut products_padded = products;
    products_padded.resize(n_padded, ScalarField::<C>::zero());

    let claimed_product_at_r = if r_challenges.is_empty() {
        products_padded[0]
    } else {
        sumcheck::eval_dense_mle(&products_padded, &r_challenges)
    };

    // HashPC commitments for W and E.
    let (w_hash, _) = sumcheck::poly_commit::<C>(z, &params.basis_w);
    let (e_hash, _) = sumcheck::poly_commit::<C>(e, &params.basis_e);

    // HashPC opening proofs.
    let w_opening = sumcheck::create_opening::<C>(z);
    let e_opening = sumcheck::create_opening::<C>(e);

    Ok(NifsSumcheckProof {
        circuit: circuit_path_display::<C>(circuit),
        n_wires: circuit.n_wires,
        n_constraints: circuit.n_constraints,
        n_pub_out: circuit.n_pub_out,
        n_pub_in: circuit.n_pub_in,
        final_instance: folded.bundle.final_instance.clone(),
        sumcheck_polys: proof
            .polys
            .iter()
            .map(|p| p.iter().map(fr_to_string).collect())
            .collect(),
        sumcheck_claims: proof.claims.iter().map(fr_to_string).collect(),
        r_challenges: r_challenges.iter().map(fr_to_string).collect(),
        claimed_product_at_r: fr_to_string(&claimed_product_at_r),
        w_commit_hash: hex::encode(&w_hash),
        w_opening: w_opening.table.iter().map(fr_to_string).collect(),
        e_commit_hash: hex::encode(&e_hash),
        e_opening: e_opening.table.iter().map(fr_to_string).collect(),
    })
}

/// Verify a sumcheck compression proof against a NIFS bundle (in-memory).
///
/// Checks, in order:
///   1. the proof's final instance matches the bundle's final instance
///   2. the sumcheck proof is valid (Fiat-Shamir consistent, round
///      polynomials sum correctly)
///   3. `claimed_product_at_r == 0` (the relaxed R1CS equation holds at
///      the random point `r`; by Schwartz–Zippel, this implies the equation
///      holds for all constraints)
///   4. the HashPC opening proofs for W and E are consistent with the
///      committed hashes and the claimed evaluations at `r`
///   5. the Pedersen commitments to W and E match the bundle's final instance
pub fn verify_sumcheck_compression<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    bundle: &NifsBundle,
    proof: &NifsSumcheckProof,
) -> Result<VerifyOutput, Box<dyn Error>> {
    verify_sumcheck_compression_inner::<C, CS>(bundle, proof, DEFAULT_SIS_PARAM, None)
}

/// Like [`verify_sumcheck_compression`] but with configurable SIS output dimension.
///
/// When a public `circuit` is supplied, additionally runs the circuit-backed
/// PCS opening `(OP)` check (recomputing the MLEs of `AZ⊙BZ`, `CZ`, `E` at
/// the random point from the opened witness/error truth tables and asserting
/// the residual vanishes) — same as the level-1 complete-verifier check.
pub fn verify_sumcheck_compression_opt<
    C: NovaCurve,
    CS: CommitmentScheme<Scalar = ScalarField<C>>,
>(
    bundle: &NifsBundle,
    proof: &NifsSumcheckProof,
    sis_param: usize,
    circuit: Option<&SparseCircuit<ScalarField<C>>>,
) -> Result<VerifyOutput, Box<dyn Error>> {
    verify_sumcheck_compression_inner::<C, CS>(bundle, proof, sis_param, circuit)
}

fn verify_sumcheck_compression_inner<
    C: NovaCurve,
    CS: CommitmentScheme<Scalar = ScalarField<C>>,
>(
    bundle: &NifsBundle,
    proof: &NifsSumcheckProof,
    sis_param: usize,
    circuit: Option<&SparseCircuit<ScalarField<C>>>,
) -> Result<VerifyOutput, Box<dyn Error>> {
    if proof.final_instance != bundle.final_instance {
        return Err("sumcheck proof was not created for this NIFS bundle".into());
    }
    if proof.n_wires != bundle.n_wires
        || proof.n_constraints != bundle.n_constraints
        || proof.n_pub_out != bundle.n_pub_out
        || proof.n_pub_in != bundle.n_pub_in
    {
        return Err("sumcheck proof does not match the NIFS bundle parameters".into());
    }

    let n_wires = bundle.n_wires as usize;
    let n_constraints = bundle.n_constraints as usize;

    // 1. Reconstruct the sumcheck proof.
    let sc_proof = sumcheck::SumcheckProof::<C> {
        claims: frs_from_strings::<ScalarField<C>>(&proof.sumcheck_claims)?,
        polys: proof
            .sumcheck_polys
            .iter()
            .map(|p| frs_from_strings::<ScalarField<C>>(p))
            .collect::<Result<Vec<_>, _>>()?,
    };

    // 2. Verify the sumcheck.
    let (sc_ok, verifier_r, final_claim) = sumcheck::verify::<C>(&sc_proof);
    if !sc_ok {
        return Err("sumcheck proof failed: round polynomials are inconsistent".into());
    }

    // Verify Fiat-Shamir challenges match.
    let claimed_r = frs_from_strings::<ScalarField<C>>(&proof.r_challenges)?;
    if verifier_r != claimed_r {
        return Err("sumcheck Fiat-Shamir challenges do not match".into());
    }

    // 3. Check final_claim == 0.
    if !final_claim.is_zero() {
        return Err(format!(
            "sumcheck final claim is non-zero ({}) — the relaxed R1CS equation does not hold",
            fr_to_string(&final_claim)
        )
        .into());
    }

    // 4. Verify HashPC opening proofs.
    let claimed_product = proof
        .claimed_product_at_r
        .parse::<ScalarField<C>>()
        .map_err(|_| format!("invalid claimed_product_at_r"))?;
    if claimed_product != final_claim {
        return Err("claimed product MLE evaluation does not match sumcheck final claim".into());
    }

    // Verify W opening: check hash matches and MLE evaluation at r.
    let w_opening = sumcheck::OpeningProof::<C> {
        table: frs_from_strings::<ScalarField<C>>(&proof.w_opening)?,
    };
    let w_hash =
        hex::decode(&proof.w_commit_hash).map_err(|e| format!("invalid w_commit_hash hex: {e}"))?;
    // Verify the W opening truth table hashes to the committed value.
    let actual_w_hash: Vec<u8> = {
        let mut h = Blake2b512::new();
        for val in &w_opening.table {
            let mut buf = Vec::new();
            val.serialize_compressed(&mut buf).unwrap();
            h.update(&buf);
        }
        h.finalize().to_vec()
    };
    if actual_w_hash != w_hash {
        return Err("W HashPC opening truth table hash mismatch".into());
    }

    // Verify E opening similarly.
    let e_opening = sumcheck::OpeningProof::<C> {
        table: frs_from_strings::<ScalarField<C>>(&proof.e_opening)?,
    };
    let e_hash =
        hex::decode(&proof.e_commit_hash).map_err(|e| format!("invalid e_commit_hash hex: {e}"))?;
    let actual_e_hash: Vec<u8> = {
        let mut h = Blake2b512::new();
        for val in &e_opening.table {
            let mut buf = Vec::new();
            val.serialize_compressed(&mut buf).unwrap();
            h.update(&buf);
        }
        h.finalize().to_vec()
    };
    if actual_e_hash != e_hash {
        return Err("E HashPC opening truth table hash mismatch".into());
    }

    // 5. Verify commitments match the bundle.
    let params = CS::params_from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints, sis_param);
    let w_vec = &w_opening.table[..n_wires.min(w_opening.table.len())];
    let expected_w_commit: CS::Commitment = commitment_parse(&bundle.final_instance.w_commit)?;
    if CS::commit_witness(&params, w_vec) != expected_w_commit {
        return Err("W commitment does not match the NIFS bundle".into());
    }
    let e_vec = &e_opening.table[..n_constraints.min(e_opening.table.len())];
    let expected_e_commit: CS::Commitment = commitment_parse(&bundle.final_instance.e_commit)?;
    if CS::commit_error(&params, e_vec) != expected_e_commit {
        return Err("E commitment does not match the NIFS bundle".into());
    }

    // 6. Circuit-backed PCS opening `(OP)`, when a public circuit is supplied.
    //    Recompute `AZ⊙BZ`, `CZ`, `E` MLEs at `r` from the opened witness/
    //    error truth tables via the public circuit and assert the *residual*
    //    `fr − u·cz − e` recomputed this way equals the sumcheck final claim
    //    (zero).  This binds the evaluation to the committed witness without
    //    trusting the prover's claimed evaluations.
    if let Some(circuit) = circuit {
        let r = &verifier_r;
        let n_constraints = circuit.n_constraints as usize;
        let rec = sumcheck::recompute_circuit_evals::<C>(
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &w_opening.table,
            n_constraints,
            r,
        );
        let (_, _, cz_rec, fr_rec) = rec;
        let e_rec = if n_constraints > 0 {
            sumcheck::eval_dense_mle(&e_opening.table, r)
        } else {
            ScalarField::<C>::zero()
        };
        let u_val = bundle
            .final_instance
            .u
            .parse::<ScalarField<C>>()
            .map_err(|_| "invalid u in bundle final instance")?;
        let residual_rec = fr_rec - u_val * cz_rec - e_rec;
        // The sumcheck proved `MLE(AZ⊙BZ − u·CZ − E)(r) == 0`; the OP-recomputed
        // residual must therefore also vanish.
        if !residual_rec.is_zero() {
            return Err(
                "PCS opening: recomputed residual MLE at r is non-zero (evaluation not bound to opened witness)"
                    .into(),
            );
        }
    }

    Ok(VerifyOutput {
        steps: bundle.n_steps,
        transcript_final: bundle.transcript_final.clone(),
    })
}

/// Slim sumcheck compression proof — on-chain friendly.
///
/// Minimal on-chain proof: sumcheck protocol data + audit hashes only.
///
/// Circuit metadata (`circuit`, `n_wires`, `n_constraints`, `n_pub_out`,
/// `n_pub_in`) and the folded final instance (`x`, `u`, `w_commit`,
/// `e_commit`) are **not** included — the verifier reads them from the
/// [`NifsBundle`] that is always co-located with the proof.  This keeps the
/// on-chain payload small regardless of the commitment scheme's security
/// parameter or the circuit's public-input dimensions.
///
/// Soundness model: the sumcheck proves knowledge of Z,E satisfying the
/// relaxed R1CS `(AZ)∘(BZ) = u·(CZ) + E` at a random point r.
/// By Schwartz–Zippel, this holds for all constraints with overwhelming
/// probability.  The HashPC opening proofs (binding Z,E to the Pedersen
/// commitments `w_commit`, `e_commit`) are verified off-chain as an audit
/// trail — they are not needed for on-chain soundness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NifsSlimProof {
    /// Sumcheck round polynomials (each is `[f(0), f(1)-f(0)]`).
    /// The round claims are implicitly `f(0) + f(1)` for each poly —
    /// the verifier re-derives them from the polys alone.
    pub sumcheck_polys: Vec<Vec<String>>,
    pub r_challenges: Vec<String>,
    pub claimed_product_at_r: String,
    /// BLAKE2b-512 hash of the committed witness Z (for off-chain audit).
    pub w_commit_hash: String,
    /// BLAKE2b-512 hash of the committed error E (for off-chain audit).
    pub e_commit_hash: String,
    /// Hash of the bundle's `final_instance` — binds the slim proof to the
    /// specific folded instance it was generated for.  The verifier checks
    /// this matches the bundle, preventing proof re-use across bundles.
    pub bundle_final_instance_hash: String,
}

impl NifsSumcheckProof {
    /// Strip opening proofs and redundant metadata to produce a minimal
    /// on-chain proof.  Circuit metadata and the final instance are
    /// excluded — the verifier reads them from the NIFS bundle.
    pub fn to_slim(&self) -> NifsSlimProof {
        // Hash the full final_instance (x, u, w_commit, e_commit) to bind
        // the slim proof to the specific folded instance.
        let instance_str = format!(
            "{}|{}|{}|{}",
            self.final_instance.x.join(":"),
            self.final_instance.u,
            self.final_instance.w_commit,
            self.final_instance.e_commit,
        );
        let hash = blake2::Blake2b512::digest(instance_str.as_bytes());
        let bundle_final_instance_hash = hex::encode(&hash[..32]);

        NifsSlimProof {
            sumcheck_polys: self.sumcheck_polys.clone(),
            r_challenges: self.r_challenges.clone(),
            claimed_product_at_r: self.claimed_product_at_r.clone(),
            w_commit_hash: self.w_commit_hash.clone(),
            e_commit_hash: self.e_commit_hash.clone(),
            bundle_final_instance_hash,
        }
    }
}

/// Level-1 slim proof with degree-2 sumcheck + commitment bindings.
///
/// This proof type uses the additive degree-2 sumcheck over the raw
/// relaxed-R1CS expression (keeping AZ, BZ, CZ, E as separate MLEs),
/// plus HashPC opening proofs that bind W and E to the bundle's
/// Pedersen commitments.  This closes the "free E" gap that the slim
/// path leaves open.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Level1SlimProof {
    /// Degree-2 sumcheck round polynomials, each `[g(0), g(1), g(2)]`.
    pub sumcheck_polys: Vec<Vec<String>>,
    /// Sumcheck claims (initial sum + per-round + final).
    pub sumcheck_claims: Vec<String>,
    /// Fiat-Shamir random challenges.
    pub r_challenges: Vec<String>,
    /// Claimed MLE evaluations at random point r.
    pub az_r: String,
    pub bz_r: String,
    pub fr_r: String,
    pub cz_r: String,
    pub er_r: String,
    /// Slack scalar u.
    pub u: String,
    /// BLAKE2b-512 hash of the committed witness Z.
    pub w_commit_hash: String,
    /// HashPC opening proof for Z.
    pub w_opening: Vec<String>,
    /// BLAKE2b-512 hash of the committed error E.
    pub e_commit_hash: String,
    /// HashPC opening proof for E.
    pub e_opening: Vec<String>,
    /// Hash of the bundle's `final_instance` (binds proof to bundle).
    pub bundle_final_instance_hash: String,
    /// Optional per-step norm-enforcement record (audit-only): a certificate
    /// per fold step over that step's pre-fold witness `Z_j` and error `E_j`.
    /// `None` when no norm check was requested (backward compatible).
    pub norm: Option<norm::StepNormRecord>,
}

/// Verify a slim sumcheck compression proof against a NIFS bundle (in-memory).
///
/// Checks the sumcheck protocol (round polynomials, Fiat-Shamir, final claim)
/// but **skips** the HashPC opening proofs and Pedersen commitment checks.
/// This is the on-chain verification path — lightweight enough for Plutus.
///
/// The bundle supplies all circuit metadata and the folded final instance;
/// the slim proof contains only the sumcheck data.
///
/// Round claims are not stored in the proof — the verifier re-derives them
/// from the polynomial coefficients (`claims[r] = polys[r][0] + polys[r][1]`).
///
/// Full soundness (including commitment binding) requires an off-chain
/// verifier to check the opening proofs against `w_commit_hash`/`e_commit_hash`.
#[allow(unused_assignments)]
pub fn verify_slim<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    bundle: &NifsBundle,
    proof: &NifsSlimProof,
) -> Result<VerifyOutput, Box<dyn Error>> {
    // Parse round polynomials from string encoding.
    let polys: Vec<Vec<ScalarField<C>>> = proof
        .sumcheck_polys
        .iter()
        .map(|row| frs_from_strings::<ScalarField<C>>(row))
        .collect::<Result<Vec<_>, _>>()?;
    let claimed_r = frs_from_strings::<ScalarField<C>>(&proof.r_challenges)?;

    // 0. Bundle binding: the proof must be tied to this specific bundle's
    //    final instance (hash of x || u || w_commit || e_commit).
    {
        let instance_str = format!(
            "{}|{}|{}|{}",
            bundle.final_instance.x.join(":"),
            bundle.final_instance.u,
            bundle.final_instance.w_commit,
            bundle.final_instance.e_commit,
        );
        let expected_hash = hex::encode(&blake2::Blake2b512::digest(instance_str.as_bytes())[..32]);
        if proof.bundle_final_instance_hash != expected_hash {
            return Err(
                "slim proof is not bound to this NIFS bundle (final instance hash mismatch)".into(),
            );
        }
    }

    let num_rounds = polys.len();

    // 1. Verifier-side sumcheck: reconstruct claims from polys and verify
    //    consistency + Fiat-Shamir challenges.
    //
    //    Each round's claim = polys[round][0] + polys[round][1].
    //    Fiat-Shamir challenge = HASH(claims[..=round] ++ polys[round]).
    let mut reconstructed_r: Vec<ScalarField<C>> = Vec::with_capacity(num_rounds);
    let mut claims: Vec<ScalarField<C>> = Vec::with_capacity(num_rounds + 1);
    let mut current_sum = ScalarField::<C>::zero();

    if num_rounds == 0 {
        // Trivial case: 0 rounds means the sole check is that
        // claimed_product_at_r == 0.
        let claimed_product = proof
            .claimed_product_at_r
            .parse::<ScalarField<C>>()
            .map_err(|_| "invalid claimed_product_at_r")?;
        if !claimed_product.is_zero() {
            return Err(format!(
                "sumcheck final claim is non-zero ({}) — the relaxed R1CS equation does not hold",
                fr_to_string(&claimed_product)
            )
            .into());
        }
        return Ok(VerifyOutput {
            steps: bundle.n_steps,
            transcript_final: bundle.transcript_final.clone(),
        });
    }

    for round in 0..num_rounds {
        let poly = &polys[round];
        if poly.len() < 2 {
            return Err("sumcheck polynomial has < 2 coefficients".into());
        }
        // poly = [f(0), f(1) - f(0)], so f(0) + f(1) = 2*poly[0] + poly[1].
        let f0 = poly[0];
        let f1 = poly[0] + poly[1];
        let claimed_sum = f0 + f1;

        // Verify: f(0) + f(1) == current_sum.
        if round == 0 {
            current_sum = claimed_sum;
        } else if claimed_sum != current_sum {
            return Err("sumcheck round polynomial inconsistent with previous claim".into());
        }
        claims.push(claimed_sum);

        // Re-derive Fiat-Shamir challenge (must match prover transcript).
        // hash_input = claims[..=round] ++ polys[round]
        let mut hash_input = claims.clone();
        hash_input.extend_from_slice(poly);
        let h = sumcheck::hash_field_elements::<C>(&hash_input);
        let ri = sumcheck::challenge_from_hash::<C>(&h);
        reconstructed_r.push(ri);

        // Fold for next round: current_sum = f(r_i).
        current_sum = poly[0] + poly[1] * ri;
    }

    // Verify Fiat-Shamir challenges match the prover's transcript.
    if reconstructed_r != claimed_r {
        return Err("sumcheck Fiat-Shamir challenges do not match".into());
    }

    // 2. Final claim must be zero (relaxed R1CS satisfied at random point).
    if !current_sum.is_zero() {
        return Err(format!(
            "sumcheck final claim is non-zero ({}) — the relaxed R1CS equation does not hold",
            fr_to_string(&current_sum)
        )
        .into());
    }

    // 3. Consistency check: claimed_product_at_r must match the sumcheck final claim.
    let claimed_product = proof
        .claimed_product_at_r
        .parse::<ScalarField<C>>()
        .map_err(|_| "invalid claimed_product_at_r")?;
    if claimed_product != current_sum {
        return Err("claimed product MLE evaluation does not match sumcheck final claim".into());
    }

    // NOTE: HashPC opening proofs and Pedersen commitment checks are intentionally
    // omitted — they are verified off-chain as an audit trail.

    Ok(VerifyOutput {
        steps: bundle.n_steps,
        transcript_final: bundle.transcript_final.clone(),
    })
}

/// Build a Level-1 slim proof from a folded NIFS instance.
///
/// Runs the degree-2 sumcheck over the raw relaxed-R1CS expression,
/// creates HashPC opening proofs for W and E (binding them to the
/// bundle's Pedersen commitments), and returns a [`Level1SlimProof`].
///
/// When `norm_mode` is [`norm::NormMode::Range`] or [`norm::NormMode::Jl`],
/// the returned proof carries a [`norm::NormCertBundle`] asserting the
/// infinity-norm of the folded witness `Z` and error `E` is ≤ `2^bound_bits`.
/// If the honest witness/error exceeds the bound, the proof is rejected up
/// front (bound too tight) — the caller must pick a `bound_bits` large enough.
pub fn prove_level1<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &SparseCircuit<ScalarField<C>>,
    folded: &NifsFoldOutput<CS>,
    opts: OptFlags,
    norm_mode: norm::NormMode,
    bound_bits: u32,
) -> Result<Level1SlimProof, Box<dyn Error>> {
    let n_wires = circuit.n_wires as usize;
    let n_constraints = circuit.n_constraints as usize;
    let params =
        commitment::PedersenParams::<C>::from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints);

    let z = &folded.final_witness.w;
    let e = &folded.final_witness.e;
    let u = folded.final_instance.u;

    // Run degree-2 sumcheck.
    let (sc_proof, r_challenges) = sumcheck::prove_degree2_opts::<C>(
        &circuit.l,
        &circuit.r,
        &circuit.o,
        z,
        u,
        e,
        opts.parallel,
    );

    // HashPC commitments.
    let (w_hash, _) = sumcheck::poly_commit::<C>(z, &params.basis_w);
    let (e_hash, _) = sumcheck::poly_commit::<C>(e, &params.basis_e);

    // HashPC opening proofs.
    let w_opening = sumcheck::create_opening::<C>(z);
    let e_opening = sumcheck::create_opening::<C>(e);

    // Bundle binding hash.
    let instance_str = format!(
        "{}|{}|{}|{}",
        folded.bundle.final_instance.x.join(":"),
        folded.bundle.final_instance.u,
        folded.bundle.final_instance.w_commit,
        folded.bundle.final_instance.e_commit,
    );
    let hash = blake2::Blake2b512::digest(instance_str.as_bytes());
    let bundle_final_instance_hash = hex::encode(&hash[..32]);

    // Optional norm section: per-step certificates over the *pre-fold* step
    // witnesses `(Z_j, E_j)` (audit-only).  The folded instance itself is
    // field-scale and cannot be bounded, so enforcement targets each step.
    let norm_section = if norm_mode == norm::NormMode::None {
        None
    } else {
        let step_w = folded
            .step_witnesses
            .iter()
            .map(|(z, e)| {
                Ok((
                    frs_from_strings::<ScalarField<C>>(z)?,
                    frs_from_strings::<ScalarField<C>>(e)?,
                ))
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        norm::StepNormRecord::make(
            norm_mode,
            &step_w,
            bound_bits,
            bound_bits.min(128),
        )
        .ok_or_else(|| {
            format!(
                "norm bound B = 2^{bound_bits} is too tight for this circuit's honest step witnesses"
            )
        })?
        .into()
    };

    Ok(Level1SlimProof {
        sumcheck_polys: sc_proof
            .polys
            .iter()
            .map(|p| p.iter().map(fr_to_string).collect())
            .collect(),
        sumcheck_claims: sc_proof.claims.iter().map(fr_to_string).collect(),
        r_challenges: r_challenges.iter().map(fr_to_string).collect(),
        az_r: fr_to_string(&sc_proof.az_r),
        bz_r: fr_to_string(&sc_proof.bz_r),
        fr_r: fr_to_string(&sc_proof.fr_r),
        cz_r: fr_to_string(&sc_proof.cz_r),
        er_r: fr_to_string(&sc_proof.er_r),
        u: fr_to_string(&u),
        w_commit_hash: hex::encode(&w_hash),
        w_opening: w_opening.table.iter().map(fr_to_string).collect(),
        e_commit_hash: hex::encode(&e_hash),
        e_opening: e_opening.table.iter().map(fr_to_string).collect(),
        bundle_final_instance_hash,
        norm: norm_section,
    })
}

/// /// Verify a Level-1 slim proof against a NIFS bundle.
///
/// Checks:
/// 1. Bundle binding (final_instance hash).
/// 2. Degree-2 sumcheck validity (round polys, Fiat-Shamir).
/// 3. Level-1 equation: `fr_r − u·cz_r − er_r == final_claim`.
/// 4. Final claim is zero (residual vanishes at the random point ⇒ relaxed
///    R1CS holds), closing the all-zeros / "free E" tautology.
/// 5. HashPC opening proofs for W and E (binds az_r/bz_r/cz_r/er_r to the
///    committed values).
/// 6. Pedersen commitment consistency with the bundle.
///
/// Norm enforcement (per-step, audit-only) is a separate check performed by
/// [`verify_level1_norm`], which re-folds the public step witnesses: it is
/// not part of this function because the per-step witnesses live in the fold
/// log, not in the bundle/proof.
pub fn verify_slim_level1<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    bundle: &NifsBundle,
    proof: &Level1SlimProof,
    sis_param: usize,
    circuit: Option<&SparseCircuit<ScalarField<C>>>,
) -> Result<VerifyOutput, Box<dyn Error>> {
    // 0. Bundle binding.
    {
        let instance_str = format!(
            "{}|{}|{}|{}",
            bundle.final_instance.x.join(":"),
            bundle.final_instance.u,
            bundle.final_instance.w_commit,
            bundle.final_instance.e_commit,
        );
        let expected_hash = hex::encode(&blake2::Blake2b512::digest(instance_str.as_bytes())[..32]);
        if proof.bundle_final_instance_hash != expected_hash {
            return Err(
                "level-1 proof is not bound to this NIFS bundle (final instance hash mismatch)"
                    .into(),
            );
        }
    }

    let n_wires = bundle.n_wires as usize;
    let n_constraints = bundle.n_constraints as usize;

    // 1. Parse and reconstruct the degree-2 sumcheck proof.
    let polys: Vec<[ScalarField<C>; 3]> = proof
        .sumcheck_polys
        .iter()
        .map(|row| {
            let frs: Vec<ScalarField<C>> = frs_from_strings::<ScalarField<C>>(row)?;
            if frs.len() != 3 {
                return Err("degree-2 polynomial must have exactly 3 evaluations".into());
            }
            Ok([frs[0], frs[1], frs[2]])
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

    let claims = frs_from_strings::<ScalarField<C>>(&proof.sumcheck_claims)?;
    let claimed_r = frs_from_strings::<ScalarField<C>>(&proof.r_challenges)?;
    let az_r = proof
        .az_r
        .parse::<ScalarField<C>>()
        .map_err(|_| "invalid az_r")?;
    let bz_r = proof
        .bz_r
        .parse::<ScalarField<C>>()
        .map_err(|_| "invalid bz_r")?;
    let fr_r = proof
        .fr_r
        .parse::<ScalarField<C>>()
        .map_err(|_| "invalid fr_r")?;
    let cz_r = proof
        .cz_r
        .parse::<ScalarField<C>>()
        .map_err(|_| "invalid cz_r")?;
    let er_r = proof
        .er_r
        .parse::<ScalarField<C>>()
        .map_err(|_| "invalid er_r")?;
    let u_val = proof.u.parse::<ScalarField<C>>().map_err(|_| "invalid u")?;

    let sc_proof = sumcheck::SumcheckProofDegree2 {
        claims,
        polys,
        az_r,
        bz_r,
        fr_r,
        cz_r,
        er_r,
    };

    // 2. Verify degree-2 sumcheck.
    let v_out = sumcheck::verify_degree2::<C>(&sc_proof);
    if !v_out.ok {
        return Err("degree-2 sumcheck verification failed".into());
    }

    // 3. Check Fiat-Shamir challenges match.
    if v_out.r_challenges != claimed_r {
        return Err("degree-2 sumcheck Fiat-Shamir challenges do not match".into());
    }

    // 4. Check the level-1 equation: fr_r - u * cz_r - er_r == final_claim,
    //    where `fr_r` is the MLE of the *product* `AZ⊙BZ` at r (sumchecked
    //    as a single MLE), NOT `az_r * bz_r`.
    let expected = fr_r - u_val * cz_r - er_r;
    if expected != v_out.final_claim {
        return Err(format!(
            "level-1 final equation check failed: fr - u*cz - er = {} != final_claim = {}",
            fr_to_string(&expected),
            fr_to_string(&v_out.final_claim)
        )
        .into());
    }

    // 5. Assert the final claim vanishes.  `final_claim == MLE(residual)@r`
    //    where `residual = AZ⊙BZ − u·CZ − E`.  Requiring `final_claim == 0`
    //    forces the residual polynomial to vanish at the random point r; by
    //    Schwartz–Zippel it is then identically zero, i.e. the relaxed R1CS
    //    equation holds for the committed Z, E (via the HashPC/Pedersen
    //    binding in steps 6–7).  Sumchecking the MLE-of-product (see
    //    `prove_degree2_opts`) is what makes this hold for *honest* relaxed
    //    witnesses — the older `az_r·bz_r` reconstruction is NOT equal to
    //    `MLE(az⊙bz)@r` and rejected every honest fold with `u != 1, e != 0`.
    if !v_out.final_claim.is_zero() {
        return Err(format!(
            "level-1 final claim is non-zero ({}) — the relaxed R1CS equation does not hold at the random point",
            fr_to_string(&v_out.final_claim)
        )
        .into());
    }

    // 6. Verify HashPC opening proofs (W and E).
    let w_opening = sumcheck::OpeningProof::<C> {
        table: frs_from_strings::<ScalarField<C>>(&proof.w_opening)?,
    };
    let w_hash =
        hex::decode(&proof.w_commit_hash).map_err(|e| format!("invalid w_commit_hash hex: {e}"))?;
    let actual_w_hash: Vec<u8> = {
        let mut h = Blake2b512::new();
        for val in &w_opening.table {
            let mut buf = Vec::new();
            val.serialize_compressed(&mut buf).unwrap();
            h.update(&buf);
        }
        h.finalize().to_vec()
    };
    if actual_w_hash != w_hash {
        return Err("W HashPC opening truth table hash mismatch".into());
    }

    let e_opening = sumcheck::OpeningProof::<C> {
        table: frs_from_strings::<ScalarField<C>>(&proof.e_opening)?,
    };
    let e_hash =
        hex::decode(&proof.e_commit_hash).map_err(|e| format!("invalid e_commit_hash hex: {e}"))?;
    let actual_e_hash: Vec<u8> = {
        let mut h = Blake2b512::new();
        for val in &e_opening.table {
            let mut buf = Vec::new();
            val.serialize_compressed(&mut buf).unwrap();
            h.update(&buf);
        }
        h.finalize().to_vec()
    };
    if actual_e_hash != e_hash {
        return Err("E HashPC opening truth table hash mismatch".into());
    }

    // 7. Verify Pedersen commitments match the bundle.
    let params = CS::params_from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints, sis_param);
    let w_vec = &w_opening.table[..n_wires.min(w_opening.table.len())];
    let expected_w_commit: CS::Commitment = commitment_parse(&bundle.final_instance.w_commit)?;
    if CS::commit_witness(&params, w_vec) != expected_w_commit {
        return Err("W commitment does not match the NIFS bundle".into());
    }
    let e_vec = &e_opening.table[..n_constraints.min(e_opening.table.len())];
    let expected_e_commit: CS::Commitment = commitment_parse(&bundle.final_instance.e_commit)?;
    if CS::commit_error(&params, e_vec) != expected_e_commit {
        return Err("E commitment does not match the NIFS bundle".into());
    }

    // 8. Circuit-backed PCS opening (the paper's `(OP)` predicate).  When a
    //    public circuit is supplied, bind every claimed evaluation
    //    (`az_r, bz_r, cz_r, fr_r, er_r`) to the *opened* witness/error truth
    //    tables:
    //      • `er_r` must equal `MLE(tt_E)(r)` — E is committed directly.
    //      • `az_r, bz_r, cz_r, fr_r` must equal the MLEs at `r` of `AZ=L·W`,
    //        `BZ=R·W`, `CZ=O·W`, `AZ⊙BZ` recomputed from the opened `tt_W`
    //        using the public circuit rows.  This closes the gap where a
    //        malicious prover could claim evaluations inconsistent with the
    //        committed witness.
    if let Some(circuit) = circuit {
        let r = &claimed_r;
        let n_constraints = circuit.n_constraints as usize;

        // E opening: MLE(tt_E)(r) == er_r.
        if n_constraints > 0 {
            let e_eval = sumcheck::eval_dense_mle(&e_opening.table, r);
            if e_eval != er_r {
                return Err("PCS opening: MLE(tt_E)(r) does not match claimed er_r".into());
            }
        }

        // W opening: recompute AZ/BZ/CZ/fr from the opened witness and check
        // against the claimed az_r/bz_r/cz_r/fr_r.
        let (az_rec, bz_rec, cz_rec, fr_rec) = sumcheck::recompute_circuit_evals::<C>(
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &w_opening.table,
            n_constraints,
            r,
        );
        if az_rec != az_r {
            return Err("PCS opening: recomputed AZ MLE at r != claimed az_r".into());
        }
        if bz_rec != bz_r {
            return Err("PCS opening: recomputed BZ MLE at r != claimed bz_r".into());
        }
        if cz_rec != cz_r {
            return Err("PCS opening: recomputed CZ MLE at r != claimed cz_r".into());
        }
        if fr_rec != fr_r {
            return Err("PCS opening: recomputed (AZ⊙BZ) MLE at r != claimed fr_r".into());
        }
    }

    Ok(VerifyOutput {
        steps: bundle.n_steps,
        transcript_final: bundle.transcript_final.clone(),
    })
}

/// Verify a Level-1 proof's per-step norm record (audit-only).
///
/// The norm record carried by the proof asserts a bound `B` on each fold
/// step's *pre-fold* witness `Z_j` and error `E_j`.  This verifier:
///
/// 1. Re-runs [`fold_nifs`] on the public circuit + step witnesses to
///    independently recompute the per-step witnesses (ground truth).
/// 2. Recomputes the [`norm::StepNormRecord`] from those witnesses.
/// 3. Requires the proof to carry a record, and cross-checks that the carried
///    record exactly equals the recomputed one (`verify_against`), which also
///    enforces that every step is within the public bound `B`.
/// 4. Returns the carried record so the caller can report audit metrics.
///
/// This is a genuine *audit* check: it does not affect the base soundness
/// proof ([`verify_slim_level1`]), but gives the verifier cryptographic
/// assurance that every pre-fold witness was short — closing the "conjectured
/// PQ" gap in [`norm::NormMode::Jl`] (SIS-style) and the range decomposition
/// in [`norm::NormMode::Range`].
pub fn verify_level1_norm<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &Path,
    steps: &Path,
    opts: OptFlags,
    sis_param: usize,
    bundle: &NifsBundle,
    proof: &Level1SlimProof,
    norm_mode: norm::NormMode,
    bound_bits: u32,
) -> Result<norm::StepNormRecord, Box<dyn Error>> {
    if norm_mode == norm::NormMode::None {
        return Err("norm audit requested with mode = none".into());
    }
    let folded: NifsFoldOutput<CS> = fold_nifs::<C, CS>(circuit, steps, opts, sis_param)?;
    if folded.bundle != *bundle {
        return Err("re-folded bundle differs from the level-1 bundle".into());
    }

    let carried = proof.norm.as_ref().ok_or_else(|| {
        format!(
            "level-1 proof carries no norm record (mode = {})",
            norm_mode.as_str()
        )
    })?;

    let step_w = folded
        .step_witnesses
        .iter()
        .map(|(z, e)| {
            Ok((
                frs_from_strings::<ScalarField<C>>(z)?,
                frs_from_strings::<ScalarField<C>>(e)?,
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

    let recomputed =
        norm::StepNormRecord::recompute(norm_mode, &step_w, bound_bits, bound_bits.min(128))
            .ok_or_else(|| {
                format!(
                    "recomputed per-step norms exceed public bound B = 2^{bound_bits} (mode = {})",
                    norm_mode.as_str()
                )
            })?;

    if !carried.verify_against(&recomputed, bound_bits) {
        return Err(format!(
            "per-step norm audit failed: carried record does not match ground-truth \
             recomputation or a step exceeds B = 2^{bound_bits} (mode = {})",
            norm_mode.as_str()
        )
        .into());
    }
    Ok(carried.clone())
}

/// Verify a slim sumcheck compression proof against a NIFS bundle (CLI path).
///
/// Loads the NIFS bundle and the compact CBOR slim proof, then runs
/// [`verify_slim`].  No verifying key is needed.
pub fn run_verify_slim<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    ivc: &Path,
    slim_proof: &Path,
) -> Result<VerifyOutput, Box<dyn Error>> {
    let bundle_bytes =
        fs::read(ivc).map_err(|e| format!("failed to read IVC bundle {}: {e}", ivc.display()))?;
    let bundle: NifsBundle = codec::bundle_decode::<ScalarField<C>>(&bundle_bytes)
        .map_err(|e| format!("failed to parse IVC bundle as NIFS bundle: {e}"))?;

    let proof_bytes = fs::read(slim_proof)
        .map_err(|e| format!("failed to read slim proof {}: {e}", slim_proof.display()))?;
    let sp: NifsSlimProof = codec::slim_proof_decode::<ScalarField<C>>(&proof_bytes)
        .map_err(|e| format!("failed to parse slim proof: {e}"))?;

    verify_slim::<C, CS>(&bundle, &sp)
}

/// Verify a Level-1 slim proof against a NIFS bundle (CLI path).
///
/// Loads the NIFS bundle and the compact CBOR level-1 proof, then runs
/// [`verify_slim_level1`].  Unlike the plain slim path, this verifier
/// additionally checks the final claim is zero, verifies the W/E HashPC
/// opening proofs, and checks Pedersen commitment consistency with the
/// bundle — closing the "free E" / all-zeros soundness gap.
///
/// When `norm_mode ≠ None`, the per-step norm audit is also run: this
/// requires the public `circuit` and `steps` inputs (to re-fold and recompute
/// the ground-truth step witnesses).  The audit cross-checks the record
/// carried in the proof against that recomputation.
pub fn run_verify_slim_level1<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    ivc: &Path,
    level1_proof: &Path,
    sis_param: usize,
    norm_mode: norm::NormMode,
    bound_bits: u32,
    circuit: Option<&Path>,
    steps: Option<&Path>,
    opts: OptFlags,
) -> Result<VerifyOutput, Box<dyn Error>> {
    let bundle_bytes =
        fs::read(ivc).map_err(|e| format!("failed to read IVC bundle {}: {e}", ivc.display()))?;
    let bundle: NifsBundle = codec::bundle_decode::<ScalarField<C>>(&bundle_bytes)
        .map_err(|e| format!("failed to parse IVC bundle as NIFS bundle: {e}"))?;

    let proof_bytes = fs::read(level1_proof).map_err(|e| {
        format!(
            "failed to read level-1 proof {}: {e}",
            level1_proof.display()
        )
    })?;
    let l1: Level1SlimProof = codec::level1_proof_decode::<ScalarField<C>>(&proof_bytes)
        .map_err(|e| format!("failed to parse level-1 proof: {e}"))?;

    // Load the public circuit (if supplied) so the verifier can run the
    // circuit-backed PCS opening check `(OP)`.
    let circuit_opt = match circuit {
        Some(p) => Some(load_circuit::<C>(p)?),
        None => None,
    };
    let out = verify_slim_level1::<C, CS>(&bundle, &l1, sis_param, circuit_opt.as_ref())?;

    if norm_mode != norm::NormMode::None {
        let circuit = circuit.ok_or_else(|| {
            "norm audit requires --circuit (needed to re-fold step witnesses)".to_string()
        })?;
        let steps = steps.ok_or_else(|| {
            "norm audit requires --steps (needed to re-fold step witnesses)".to_string()
        })?;
        let record = verify_level1_norm::<C, CS>(
            circuit, steps, opts, sis_param, &bundle, &l1, norm_mode, bound_bits,
        )?;
        eprintln!(
            "Per-step norm audit passed (mode = {}, B = 2^{}, {} steps, {} bytes of certs)",
            norm_mode.as_str(),
            bound_bits,
            record.steps.len(),
            record.size_bytes()
        );
    }

    Ok(out)
}

/// Compress a NIFS bundle into a Level-1 proof (degree-2 sumcheck + W/E
/// opening proofs + final-claim-zero check) and write it as CBOR.
pub fn run_compress_level1_opt<C: NovaCurve, CS: CommitmentScheme<Scalar = ScalarField<C>>>(
    circuit: &Path,
    steps: &Path,
    out: &Path,
    opts: OptFlags,
    sis_param: usize,
    norm_mode: norm::NormMode,
    bound_bits: u32,
) -> Result<CompressOutput, Box<dyn Error>> {
    let c = load_circuit::<C>(circuit)?;
    check_step_circuit::<C>(&c)?;

    let folded = fold_nifs::<C, CS>(circuit, steps, opts, sis_param)?;
    let l1 = prove_level1::<C, CS>(&c, &folded, opts, norm_mode, bound_bits)?;

    let cbor = codec::level1_proof_encode::<ScalarField<C>>(&l1)
        .map_err(|e| format!("failed to serialize level-1 proof: {e}"))?;
    fs::write(out, &cbor)
        .map_err(|e| format!("failed to write level-1 proof to {}: {e}", out.display()))?;
    eprintln!(
        "Level-1 proof written to {} ({} bytes, u = {})",
        out.display(),
        cbor.len(),
        fr_to_string(&folded.final_instance.u)
    );
    Ok(CompressOutput {
        bytes: cbor.len(),
        bundle: folded.bundle,
    })
}

// ────────────────────────────────────────────────────────────────────
// Field/point serialization helpers shared by all paths
// ────────────────────────────────────────────────────────────────────

/// Serialize a field element to its compressed bytes.
fn fr_bytes<F: PrimeField>(f: &F) -> Vec<u8> {
    let mut buf = Vec::new();
    f.serialize_compressed(&mut buf).expect("Fr serialize");
    buf
}

/// Serialize a slice of field elements to concatenated compressed bytes.
fn frs_bytes<F: PrimeField>(frs: &[F]) -> Vec<u8> {
    frs.iter().flat_map(fr_bytes).collect()
}

/// Hex of a compressed G1 point.
fn commitment_hex<T: CanonicalSerialize>(value: &T) -> String {
    let mut buf = Vec::new();
    value
        .serialize_compressed(&mut buf)
        .expect("commitment serialize");
    hex::encode(buf)
}

/// Initialize the NIFS transcript: `H(NIFS_TRANSCRIPT_PREFIX ‖ initial_state)`.
fn transcript_nifs_init<C: NovaCurve>(initial_state: &[ScalarField<C>]) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(frs_bytes::<ScalarField<C>>(initial_state));
    h.finalize().to_vec()
}

/// Extend the NIFS transcript with the running instance after a fold:
/// `H(acc ‖ instance_bytes)`.  The folding challenge (`nifs::fold_challenge`)
/// is domain-separated via `FOLD_PREFIX`.
fn transcript_nifs_step<C: NovaCurve, CS: CommitmentScheme>(
    acc_hash: &[u8],
    u: &nifs::RelaxedR1csInstance<CS>,
) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(acc_hash);
    h.update(nifs::instance_to_bytes::<CS>(u).expect("serialize instance"));
    h.finalize().to_vec()
}

fn commitment_parse<T: CanonicalDeserialize>(hex: &str) -> Result<T, Box<dyn Error>> {
    let bytes = hex::decode(hex).map_err(|e| format!("invalid commitment hex: {e}"))?;
    T::deserialize_compressed(&bytes[..])
        .map_err(|e| format!("failed to deserialize commitment: {e:?}").into())
}

/// Canonical decimal string for a field element.
///
/// arkworks' `Display` for BLS12-381 `Fr` emits an empty string for the
/// zero element, so serialize via the canonical bigint instead.
pub fn fr_to_string<F: PrimeField>(f: &F) -> String {
    f.into_bigint().to_string()
}

/// Parse decimal field-element strings back into `Fr`.
pub fn frs_from_strings<F: PrimeField>(strs: &[String]) -> Result<Vec<F>, Box<dyn Error>> {
    strs.iter()
        .map(|s| {
            s.parse::<F>()
                .map_err(|_| format!("invalid field element '{s}'").into())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{r1cs_to_bytes_sparse, wtns_to_bytes};
    use crate::commitment::PedersenCommitment;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;

    /// One-constraint step circuit `out = in · x` (wires `[1, out, in, x]`).
    fn step_r1cs_bytes() -> Vec<u8> {
        r1cs_to_bytes_sparse(
            4,
            1,
            1,
            1,
            &[vec![(2u32, Fr::from(1u64))]],
            &[vec![(3u32, Fr::from(1u64))]],
            &[vec![(1u32, Fr::from(1u64))]],
        )
    }

    fn write_step_wtns(dir: &Path, idx: usize, st_in: u64, x: u64) -> u64 {
        let st_out = st_in * x;
        fs::write(
            dir.join(format!("step_{idx:04}.wtns")),
            wtns_to_bytes(&[
                Fr::from(1u64),
                Fr::from(st_out),
                Fr::from(st_in),
                Fr::from(x),
            ]),
        )
        .unwrap();
        st_out
    }

    #[test]
    fn fr_to_string_roundtrip() {
        let f = Fr::from(123456789u64);
        let s = fr_to_string(&f);
        let back = frs_from_strings::<ark_bls12_381::Fr>(&[s]).unwrap();
        assert_eq!(back, vec![f]);
    }

    /// Fold 3 steps, produce a sumcheck compression proof, and verify it.
    #[test]
    fn sumcheck_compression_end_to_end() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }
        assert_eq!(state, 210);

        // 1. fold -> bundle + private final instance/witness
        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        assert_eq!(fold_out.bundle.n_steps, 3);
        assert_ne!(fold_out.final_instance.u, Fr::from(1u64));

        // 2. sumcheck compression proof (transparent — no trusted setup)
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc_proof = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap();

        // 3. Verify the sumcheck compression proof against the bundle.
        let vout = verify_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &sc_proof)
        .unwrap();
        assert_eq!(vout.steps, 3);

        // 4. Tamper resistance: flip a sumcheck claim → verification fails.
        let mut bad_proof = sc_proof.clone();
        bad_proof.sumcheck_claims[0] = fr_to_string(&(Fr::from(42u64)));
        assert!(
            verify_sumcheck_compression::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&fold_out.bundle, &bad_proof)
            .is_err(),
            "tampered sumcheck claim must fail verification"
        );

        // 5. Tamper resistance: wrong final instance → rejection.
        let mut bad_bundle = fold_out.bundle.clone();
        bad_bundle.final_instance.u = fr_to_string(&(fold_out.final_instance.u + Fr::from(1u64)));
        assert!(
            verify_sumcheck_compression::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&bad_bundle, &sc_proof)
            .is_err(),
            "wrong bundle instance must fail verification"
        );

        // 6. Circuit-backed PCS opening `(OP)`: with the public circuit the
        //    honest proof still passes, but a tampered witness truth table is
        //    rejected because the recomputed residual no longer vanishes.
        verify_sumcheck_compression_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &sc_proof, DEFAULT_SIS_PARAM, Some(&c))
        .unwrap();
        let mut tampered = sc_proof.clone();
        if !tampered.w_opening.is_empty() {
            tampered.w_opening[0] = fr_to_string(&(Fr::from(0u64) - Fr::from(9u64)));
            assert!(
                verify_sumcheck_compression_opt::<
                    crate::curve::Bls12_381,
                    PedersenCommitment<crate::curve::Bls12_381>,
                >(&fold_out.bundle, &tampered, DEFAULT_SIS_PARAM, Some(&c))
                .is_err(),
                "tampered W opening must be rejected by the circuit-backed PCS opening"
            );
        }
    }

    /// E2E: serialization roundtrip — the JSON-serialized NifsSumcheckProof
    /// can be deserialized and still verifies.
    #[test]
    fn sumcheck_compression_serialization_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc_proof = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap();

        // Serialize → deserialize → verify.
        let json = serde_json::to_string(&sc_proof).unwrap();
        let restored: NifsSumcheckProof = serde_json::from_str(&json).unwrap();
        let vout = verify_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &restored)
        .unwrap();
        assert_eq!(vout.steps, 2);
        assert_eq!(json.len(), sc_proof_json_size(&sc_proof));
    }

    /// E2E: fold with different step counts (1, 2, 4, 8) — proof size stays
    /// logarithmic, verification always passes.
    #[test]
    fn sumcheck_compression_varying_step_counts() {
        for &n_steps in &[1usize, 2, 4, 8] {
            let tmp = tempfile::tempdir().unwrap();
            let r1cs_path = tmp.path().join("step.r1cs");
            let steps_dir = tmp.path().join("steps");
            fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
            fs::create_dir(&steps_dir).unwrap();

            let mut state = 2u64;
            for i in 0..n_steps {
                state = write_step_wtns(&steps_dir, i, state, (i as u64) + 3);
            }

            let fold_out = run_fold_nifs::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&r1cs_path, &steps_dir)
            .unwrap();
            assert_eq!(fold_out.bundle.n_steps, n_steps);

            let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
            let mut rng = rand::thread_rng();
            let sc_proof = prove_sumcheck_compression::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&c, &fold_out, &mut rng)
            .unwrap();
            let vout = verify_sumcheck_compression::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&fold_out.bundle, &sc_proof)
            .unwrap();
            assert_eq!(vout.steps, n_steps);
        }
    }

    fn sc_proof_json_size(p: &NifsSumcheckProof) -> usize {
        serde_json::to_string(p).unwrap().len()
    }

    /// E2E: parallel NIFS fold produces identical bundle to sequential.
    #[test]
    fn parallel_nifs_fold_matches_sequential() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let seq = run_fold_nifs_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir, OptFlags::NONE, DEFAULT_SIS_PARAM)
        .unwrap();
        let par = run_fold_nifs_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(
            &r1cs_path,
            &steps_dir,
            OptFlags::PARALLEL,
            DEFAULT_SIS_PARAM,
        )
        .unwrap();

        assert_eq!(seq.bundle, par.bundle);
        assert_eq!(seq.final_instance, par.final_instance);
        assert_eq!(seq.final_witness, par.final_witness);
    }

    /// E2E: parallel sumcheck compression produces identical proof to sequential.
    #[test]
    fn parallel_sumcheck_matches_sequential() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();

        // Sequential fold
        let fold_seq = run_fold_nifs_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir, OptFlags::NONE, DEFAULT_SIS_PARAM)
        .unwrap();
        let mut rng = rand::thread_rng();
        let sc_seq = prove_sumcheck_compression_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_seq, &mut rng, OptFlags::NONE)
        .unwrap();

        // Parallel fold
        let fold_par = run_fold_nifs_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(
            &r1cs_path,
            &steps_dir,
            OptFlags::PARALLEL,
            DEFAULT_SIS_PARAM,
        )
        .unwrap();
        let mut rng = rand::thread_rng();
        let sc_par = prove_sumcheck_compression_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_par, &mut rng, OptFlags::PARALLEL)
        .unwrap();

        // Both must verify
        let v1 = verify_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_seq.bundle, &sc_seq)
        .unwrap();
        let v2 = verify_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_par.bundle, &sc_par)
        .unwrap();
        assert_eq!(v1.steps, v2.steps);
        assert_eq!(v1.transcript_final, v2.transcript_final);

        // Bundles must be identical (parallel fold produces same output)
        assert_eq!(fold_seq.bundle, fold_par.bundle);
    }

    /// E2E: parallel sumcheck compression produces byte-identical proof
    /// to sequential, and both slim proofs verify identically.
    #[test]
    fn parallel_sumcheck_proof_byte_identical() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let fold = run_fold_nifs_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir, OptFlags::NONE, DEFAULT_SIS_PARAM)
        .unwrap();

        // Sequential
        let mut rng = rand::thread_rng();
        let sc_seq = prove_sumcheck_compression_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold, &mut rng, OptFlags::NONE)
        .unwrap();

        // Parallel
        let mut rng = rand::thread_rng();
        let sc_par = prove_sumcheck_compression_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold, &mut rng, OptFlags::PARALLEL)
        .unwrap();

        // Proofs must be byte-identical
        let seq_json = serde_json::to_string(&sc_seq).unwrap();
        let par_json = serde_json::to_string(&sc_par).unwrap();
        assert_eq!(
            seq_json, par_json,
            "parallel and sequential proofs must be byte-identical"
        );

        // Slim proofs must be identical
        let slim_seq = sc_seq.to_slim();
        let slim_par = sc_par.to_slim();
        assert_eq!(slim_seq.sumcheck_polys, slim_par.sumcheck_polys);
        assert_eq!(slim_seq.r_challenges, slim_par.r_challenges);
        assert_eq!(slim_seq.claimed_product_at_r, slim_par.claimed_product_at_r);
        assert_eq!(
            slim_seq.bundle_final_instance_hash,
            slim_par.bundle_final_instance_hash
        );

        // Both slim proofs must verify
        let v_seq = verify_slim::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold.bundle, &slim_seq)
        .unwrap();
        let v_par = verify_slim::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold.bundle, &slim_par)
        .unwrap();
        assert_eq!(v_seq.steps, v_par.steps);
        assert_eq!(v_seq.transcript_final, v_par.transcript_final);
    }

    /// E2E: parallel sumcheck compression with --opt=all produces valid proof.
    #[test]
    fn parallel_sumcheck_opt_all_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let fold = run_fold_nifs_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir, OptFlags::ALL, DEFAULT_SIS_PARAM)
        .unwrap();

        let mut rng = rand::thread_rng();
        let sc = prove_sumcheck_compression_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold, &mut rng, OptFlags::ALL)
        .unwrap();

        // Must verify
        verify_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold.bundle, &sc)
        .unwrap();

        // Slim must verify
        let slim = sc.to_slim();
        let v =
            verify_slim::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(
                &fold.bundle,
                &slim,
            )
            .unwrap();
        assert_eq!(v.steps, 3);
    }

    /// E2E: --opt=all flag works through the CLI fold path.
    #[test]
    fn opt_all_flag_produces_valid_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir, OptFlags::ALL, DEFAULT_SIS_PARAM)
        .unwrap();
        assert_eq!(fold_out.bundle.n_steps, 3);

        // Verify the fold produced a valid instance
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let params = commitment::PedersenParams::<crate::curve::Bls12_381>::from_seed(
            NIFS_PARAMS_SEED,
            c.n_wires as usize,
            c.n_constraints as usize,
        );
        let w_commit = commitment::pedersen_commit::<crate::curve::Bls12_381>(
            &params.basis_w,
            &fold_out.final_witness.w,
        );
        assert_eq!(fold_out.final_instance.w_commit, w_commit);
    }

    // ── Slim-proof tests ──────────────────────────────────────────────

    #[test]
    fn slim_proof_is_much_smaller_than_full() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap();
        let slim = sc.to_slim();

        let full_json = serde_json::to_string(&sc).unwrap();
        let slim_json = serde_json::to_string(&slim).unwrap();

        // For the tiny 1-constraint test circuit the difference is modest;
        // on real circuits (7K+ constraints) the slim proof is ~98 % smaller.
        assert!(
            slim_json.len() < full_json.len(),
            "slim proof should be smaller than full: slim={} full={}",
            slim_json.len(),
            full_json.len()
        );
        assert!(!slim.w_commit_hash.is_empty());
        assert!(!slim.e_commit_hash.is_empty());
        // The opening tables are structurally absent from the slim JSON.
        assert!(
            !slim_json.contains("w_opening"),
            "slim JSON must not contain w_opening"
        );
        assert!(
            !slim_json.contains("e_opening"),
            "slim JSON must not contain e_opening"
        );
        // The full JSON does contain them.
        assert!(full_json.contains("w_opening"));
        assert!(full_json.contains("e_opening"));
    }

    #[test]
    fn slim_verify_accepts_valid_proof() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap();
        let slim = sc.to_slim();

        let v_full = verify_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &sc)
        .unwrap();
        let v_slim = verify_slim::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &slim)
        .unwrap();
        assert_eq!(v_full.steps, v_slim.steps);
        assert_eq!(v_full.transcript_final, v_slim.transcript_final);
    }

    #[test]
    fn slim_verify_rejects_tampered_poly() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let mut slim = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap()
        .to_slim();

        // The 1-constraint test circuit produces 0 sumcheck rounds (empty polys).
        // For circuits with >= 2 constraints, tamper a polynomial coefficient.
        if !slim.sumcheck_polys.is_empty() {
            slim.sumcheck_polys[0][0] = fr_to_string(&(Fr::from(42u64)));
            assert!(verify_slim::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&fold_out.bundle, &slim)
            .is_err());
        } else {
            // 1-constraint edge case: tamper claimed_product_at_r to verify it is checked.
            slim.claimed_product_at_r = fr_to_string(&(Fr::from(42u64)));
            assert!(verify_slim::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&fold_out.bundle, &slim)
            .is_err());
        }
    }

    #[test]
    fn slim_verify_rejects_tampered_product_at_r() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let mut slim = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap()
        .to_slim();

        slim.claimed_product_at_r = fr_to_string(&(Fr::from(999u64)));
        assert!(
            verify_slim::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(
                &fold_out.bundle,
                &slim
            )
            .is_err()
        );
    }

    #[test]
    fn slim_verify_does_not_check_commitment_hashes() {
        // Documentation test: slim verifier intentionally skips Pedersen/HashPC
        // checks. If someone accidentally re-adds them, this breaks.
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let mut slim = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap()
        .to_slim();

        slim.w_commit_hash = "00".repeat(64);
        slim.e_commit_hash = "00".repeat(64);

        assert!(
            verify_slim::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(
                &fold_out.bundle,
                &slim
            )
            .is_ok(),
            "slim verifier must not inspect commitment hashes"
        );
    }

    #[test]
    fn slim_verify_rejects_wrong_r_challenges() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let mut slim = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap()
        .to_slim();

        if !slim.r_challenges.is_empty() {
            slim.r_challenges[0] = fr_to_string(&(Fr::from(12345u64)));
            assert!(verify_slim::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&fold_out.bundle, &slim)
            .is_err());
        }
    }

    // ── Folding edge cases ────────────────────────────────────────────

    #[test]
    fn nifs_fold_single_step() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let state = 2u64;
        write_step_wtns(&steps_dir, 0, state, 3u64);

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        assert_eq!(fold_out.bundle.n_steps, 1);
        assert_eq!(fold_out.final_instance.u, Fr::from(1u64));
        assert!(fold_out.final_witness.e.iter().all(|x| x.is_zero()));
    }

    #[test]
    fn nifs_fold_empty_steps_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        assert!(run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .is_err());
    }

    #[test]
    fn nifs_fold_detects_broken_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let state0 = 2u64;
        let state1 = write_step_wtns(&steps_dir, 0, state0, 3u64);
        let _ = write_step_wtns(&steps_dir, 1, state1 + 1, 5u64); // break chain

        let err =
            fold_nifs::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(
                &r1cs_path,
                &steps_dir,
                OptFlags::NONE,
                DEFAULT_SIS_PARAM,
            )
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("state_in does not chain"),
            "expected chain-break error, got: {msg}"
        );
    }

    // ── Level-1 slim proof tests ──────────────────────────────────

    /// E2E: fold → prove_level1 → verify_slim_level1 passes for a
    /// 3-step chain.
    #[test]
    fn level1_verifier_e2e_test() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }
        assert_eq!(state, 210);

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        assert_eq!(fold_out.bundle.n_steps, 3);

        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let l1_proof = prove_level1::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, OptFlags::NONE, norm::NormMode::None, 64)
        .unwrap();

        let vout = verify_slim_level1::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &l1_proof, DEFAULT_SIS_PARAM, Some(&c))
        .unwrap();
        assert_eq!(vout.steps, 3);
    }

    /// Level-1 verifier rejects a degenerate all-zeros proof.
    #[test]
    fn level1_rejects_all_zeros() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();

        // Build a degenerate proof with wrong bundle hash.
        let bad_proof = Level1SlimProof {
            sumcheck_polys: vec![],
            sumcheck_claims: vec![fr_to_string(&Fr::zero())],
            r_challenges: vec![],
            az_r: fr_to_string(&Fr::zero()),
            bz_r: fr_to_string(&Fr::zero()),
            fr_r: fr_to_string(&Fr::zero()),
            cz_r: fr_to_string(&Fr::zero()),
            er_r: fr_to_string(&Fr::zero()),
            u: fr_to_string(&Fr::from(1u64)),
            w_commit_hash: "00".repeat(64),
            w_opening: vec![],
            e_commit_hash: "00".repeat(64),
            e_opening: vec![],
            bundle_final_instance_hash: "deadbeef".to_string(),
            norm: None,
        };

        let result = verify_slim_level1::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &bad_proof, DEFAULT_SIS_PARAM, None);
        assert!(
            result.is_err(),
            "degenerate all-zeros proof must be rejected"
        );
    }

    /// Level-1 verifier rejects tampered round polynomial.
    #[test]
    fn level1_rejects_tampered_poly() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();

        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut l1_proof = prove_level1::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, OptFlags::NONE, norm::NormMode::None, 64)
        .unwrap();

        // The 1-constraint test circuit produces 0 sumcheck rounds.
        if !l1_proof.sumcheck_polys.is_empty() {
            l1_proof.sumcheck_polys[0][0] = fr_to_string(&(Fr::from(42u64)));
            let result = verify_slim_level1::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&fold_out.bundle, &l1_proof, DEFAULT_SIS_PARAM, Some(&c));
            assert!(result.is_err(), "tampered poly must be rejected");
        }
    }

    /// Level-1 verifier rejects a claimed evaluation inconsistent with the
    /// opened witness (the PCS-opening `(OP)` binding check).
    #[test]
    fn level1_rejects_tampered_claimed_eval() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();

        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut l1_proof = prove_level1::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, OptFlags::NONE, norm::NormMode::None, 64)
        .unwrap();

        // Tamp er_r so it disagrees with MLE(tt_E)(r): this must be caught by
        // the PCS-opening check when a circuit is supplied.
        let tampered = Fr::from(0u64) - Fr::from(1u64);
        let orig_er = l1_proof.er_r.clone();
        l1_proof.er_r = fr_to_string(&tampered);
        let result = verify_slim_level1::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &l1_proof, DEFAULT_SIS_PARAM, Some(&c));
        assert!(
            result.is_err(),
            "tampered er_r must be rejected by the PCS-opening check"
        );

        // Without a circuit the same (unchanged-hash) proof is not OP-checked:
        // restore er_r and verify the plain path still accepts it.
        l1_proof.er_r = orig_er;
        let result_ok = verify_slim_level1::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &l1_proof, DEFAULT_SIS_PARAM, None);
        assert!(result_ok.is_ok(), "honest proof must pass with no circuit");

        // Now tamper az_r and expect rejection via the circuit-backed check.
        l1_proof.az_r = fr_to_string(&(Fr::from(0u64) - Fr::from(7u64)));
        let result2 = verify_slim_level1::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &l1_proof, DEFAULT_SIS_PARAM, Some(&c));
        assert!(
            result2.is_err(),
            "tampered az_r must be rejected by the circuit-backed PCS opening"
        );
    }

    /// Helper: fold a 3-step chain into a bundle + level-1 proof proving
    /// infrastructure (shared by the norm tests).  Also returns the circuit
    /// and steps paths so the norm-audit verifier can re-fold ground truth.
    fn norm_setup() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        NifsFoldOutput<PedersenCommitment<crate::curve::Bls12_381>>,
        SparseCircuit<Fr>,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();
        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }
        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        (tmp, r1cs_path, steps_dir, fold_out, c)
    }

    /// E2E: norm-enforced level-1 proof (Option A — range) verifies against a
    /// re-fold norm audit.
    #[test]
    fn level1_norm_range_e2e() {
        let (_tmp, r1cs_path, steps_dir, fold_out, c) = norm_setup();
        let l1 =
            prove_level1::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(
                &c,
                &fold_out,
                OptFlags::NONE,
                norm::NormMode::Range,
                64,
            )
            .unwrap();
        let rec = verify_level1_norm::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(
            &r1cs_path,
            &steps_dir,
            OptFlags::NONE,
            DEFAULT_SIS_PARAM,
            &fold_out.bundle,
            &l1,
            norm::NormMode::Range,
            64,
        )
        .unwrap();
        assert_eq!(rec.steps.len(), 3);
        assert!(l1.norm.is_some());
    }

    /// E2E: norm-enforced level-1 proof (Option B — JL) verifies against a
    /// re-fold norm audit.
    #[test]
    fn level1_norm_jl_e2e() {
        let (_tmp, r1cs_path, steps_dir, fold_out, c) = norm_setup();
        let l1 =
            prove_level1::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(
                &c,
                &fold_out,
                OptFlags::NONE,
                norm::NormMode::Jl,
                64,
            )
            .unwrap();
        verify_level1_norm::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(
            &r1cs_path,
            &steps_dir,
            OptFlags::NONE,
            DEFAULT_SIS_PARAM,
            &fold_out.bundle,
            &l1,
            norm::NormMode::Jl,
            64,
        )
        .unwrap();
        assert!(l1.norm.is_some());
    }

    /// E2E: a norm record with a bound tampered tighter than the honest
    /// recomputation is rejected by the re-fold audit.
    #[test]
    fn level1_norm_jl_rejects_tampered_w() {
        let (_tmp, r1cs_path, steps_dir, fold_out, c) = norm_setup();
        let mut l1 = prove_level1::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, OptFlags::NONE, norm::NormMode::Jl, 64)
        .unwrap();
        // Flip the carried bound_bits to a tighter value so it can no longer
        // equal the ground-truth recomputation.
        l1.norm.as_mut().unwrap().bound_bits = 8;
        let result = verify_level1_norm::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(
            &r1cs_path,
            &steps_dir,
            OptFlags::NONE,
            DEFAULT_SIS_PARAM,
            &fold_out.bundle,
            &l1,
            norm::NormMode::Jl,
            64,
        );
        assert!(result.is_err(), "tampered norm bound must be rejected");
    }

    /// E2E: requesting a norm audit when the proof carries no record is
    /// rejected.
    #[test]
    fn level1_norm_requires_certificate_in_proof() {
        let (_tmp, r1cs_path, steps_dir, fold_out, c) = norm_setup();
        let l1 =
            prove_level1::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(
                &c,
                &fold_out,
                OptFlags::NONE,
                norm::NormMode::None,
                64,
            )
            .unwrap();
        let result = verify_level1_norm::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(
            &r1cs_path,
            &steps_dir,
            OptFlags::NONE,
            DEFAULT_SIS_PARAM,
            &fold_out.bundle,
            &l1,
            norm::NormMode::Range,
            64,
        );
        assert!(result.is_err(), "missing norm record must be rejected");
    }

    /// E2E: proving with a bound too tight for the honest step witnesses fails
    /// up front.
    #[test]
    fn level1_norm_rejects_tight_bound_at_prove() {
        let (_tmp, _r1cs_path, _steps_dir, fold_out, c) = norm_setup();
        // A 1-bit bound cannot hold coordinates of magnitude ≥ 2.
        let result = prove_level1::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, OptFlags::NONE, norm::NormMode::Range, 1);
        assert!(
            result.is_err(),
            "bound too tight must be rejected at prove time"
        );
    }

    /// E2E: CBOR round-trip preserves the norm record, and a round-tripped
    /// proof still passes the re-fold norm audit.
    #[test]
    fn level1_norm_cbor_roundtrip() {
        let (_tmp, r1cs_path, steps_dir, fold_out, c) = norm_setup();
        let l1 =
            prove_level1::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(
                &c,
                &fold_out,
                OptFlags::NONE,
                norm::NormMode::Jl,
                64,
            )
            .unwrap();
        let bytes = l1.to_cbor::<Fr>().unwrap();
        let decoded = Level1SlimProof::from_cbor::<Fr>(&bytes).unwrap();
        assert_eq!(decoded.norm, l1.norm);
        verify_level1_norm::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(
            &r1cs_path,
            &steps_dir,
            OptFlags::NONE,
            DEFAULT_SIS_PARAM,
            &fold_out.bundle,
            &decoded,
            norm::NormMode::Jl,
            64,
        )
        .unwrap();
    }

    // ── Parameter-mismatch adversarial tests ──────────────────────────

    #[test]
    fn verify_rejects_wrong_circuit_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap();

        let mut bad_bundle = fold_out.bundle.clone();
        bad_bundle.n_constraints += 1;
        assert!(verify_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&bad_bundle, &sc)
        .is_err());
    }

    #[test]
    fn verify_rejects_malformed_field_strings() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let mut sc = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap();

        sc.claimed_product_at_r = "not_a_number".to_string();
        assert!(verify_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &sc)
        .is_err());
    }

    // ── Boundary step-count E2E tests for sumcheck ────────────────────

    #[test]
    fn sumcheck_exact_power_of_two_constraints() {
        for &n in &[1usize, 2, 4, 8] {
            let tmp = tempfile::tempdir().unwrap();
            let r1cs_path = tmp.path().join("step.r1cs");
            let steps_dir = tmp.path().join("steps");
            fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
            fs::create_dir(&steps_dir).unwrap();

            let mut state = 2u64;
            for i in 0..n {
                state = write_step_wtns(&steps_dir, i, state, (i as u64) + 3);
            }

            let fold_out = run_fold_nifs::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&r1cs_path, &steps_dir)
            .unwrap();
            let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
            let mut rng = rand::thread_rng();
            let sc = prove_sumcheck_compression::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&c, &fold_out, &mut rng)
            .unwrap();
            assert!(
                verify_sumcheck_compression::<
                    crate::curve::Bls12_381,
                    PedersenCommitment<crate::curve::Bls12_381>,
                >(&fold_out.bundle, &sc)
                .is_ok(),
                "failed for n={n}"
            );
        }
    }

    #[test]
    fn sumcheck_just_above_power_of_two() {
        // 3 constraints in the step circuit -> padded to 4 -> 2 rounds.
        // (step_r1cs_bytes has 1 constraint, so we reuse it with 3 steps)
        let n = 3usize;
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for i in 0..n {
            state = write_step_wtns(&steps_dir, i, state, (i as u64) + 3);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap();
        assert!(verify_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &sc)
        .is_ok());
    }

    #[test]
    fn parallel_slim_matches_sequential_slim() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();

        let fold_seq = run_fold_nifs_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir, OptFlags::NONE, DEFAULT_SIS_PARAM)
        .unwrap();
        let fold_par = run_fold_nifs_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(
            &r1cs_path,
            &steps_dir,
            OptFlags::PARALLEL,
            DEFAULT_SIS_PARAM,
        )
        .unwrap();

        let mut rng = rand::thread_rng();
        let slim_seq = prove_sumcheck_compression_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_seq, &mut rng, OptFlags::NONE)
        .unwrap()
        .to_slim();
        let mut rng = rand::thread_rng();
        let slim_par = prove_sumcheck_compression_opt::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_par, &mut rng, OptFlags::PARALLEL)
        .unwrap()
        .to_slim();

        let v_seq = verify_slim::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_seq.bundle, &slim_seq)
        .unwrap();
        let v_par = verify_slim::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&fold_par.bundle, &slim_par)
        .unwrap();
        assert_eq!(v_seq.steps, v_par.steps);
        assert_eq!(v_seq.transcript_final, v_par.transcript_final);
        assert_eq!(fold_seq.bundle, fold_par.bundle);
    }

    // ── Property-based tests (proptest) ─────────────────────────────────

    use proptest::prelude::*;

    /// Helper: fold 3 steps with random multipliers [x1, x2, x3] starting
    /// from state 2, produce a slim proof, and return everything needed
    /// for property checks.
    fn setup_slim(x1: u64, x2: u64, x3: u64) -> (NifsBundle, NifsSlimProof, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [x1, x2, x3].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap();
        let slim = sc.to_slim();

        (fold_out.bundle, slim, tmp)
    }

    /// Fold a 3-step chain, then build a Level-1 proof.  Returns the bundle,
    /// the level-1 proof, and the public circuit (needed for the circuit-backed
    /// PCS-opening `(OP)` check).
    fn setup_level1(
        x1: u64,
        x2: u64,
        x3: u64,
    ) -> (
        NifsBundle,
        Level1SlimProof,
        SparseCircuit<ScalarField<crate::curve::Bls12_381>>,
        tempfile::TempDir,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [x1, x2, x3].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            PedersenCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let l1 =
            prove_level1::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(
                &c,
                &fold_out,
                OptFlags::NONE,
                norm::NormMode::None,
                64,
            )
            .unwrap();

        (fold_out.bundle, l1, c, tmp)
    }

    proptest! {
        /// Property: a valid slim proof always verifies against its own bundle.
        #[test]
        fn prop_slim_accepts_valid(
            x1 in 2u64..20,
            x2 in 2u64..20,
            x3 in 2u64..20,
        ) {
            let (bundle, slim, _tmp) = setup_slim(x1, x2, x3);
            let v = verify_slim::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(&bundle, &slim);
            prop_assert!(v.is_ok(), "valid slim proof rejected: {:?}", v.err());
            let v = v.unwrap();
            prop_assert_eq!(v.steps, 3);
            prop_assert!(!v.transcript_final.is_empty());
        }

        /// Property: the circuit-backed PCS opening `(OP)` accepts an honest
        /// level-1 proof — the recomputed `AZ/BZ/CZ/fr` and `MLE(tt_E)(r)` agree
        /// with the prover's claimed evaluations for arbitrary random witnesses.
        #[test]
        fn prop_level1_complete_opening_accepts(
            x1 in 2u64..20,
            x2 in 2u64..20,
            x3 in 2u64..20,
        ) {
            let (bundle, l1, c, _tmp) = setup_level1(x1, x2, x3);
            let v = verify_slim_level1::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&bundle, &l1, DEFAULT_SIS_PARAM, Some(&c));
            prop_assert!(v.is_ok(), "level-1 OP check rejected honest proof: {:?}", v.err());
            let v = v.unwrap();
            prop_assert_eq!(v.steps, 3);
        }

        /// Property: tampering any of the level-1 claimed evaluations is
        /// rejected by the circuit-backed PCS opening `(OP)`, for arbitrary
        /// random witnesses.  `which` selects which of `az/bz/cz/fr/er` to flip.
        #[test]
        fn prop_level1_tampered_eval_rejected_op(
            x1 in 2u64..20,
            x2 in 2u64..20,
            x3 in 2u64..20,
            which in 0usize..5,
        ) {
            let (bundle, l1, c, _tmp) = setup_level1(x1, x2, x3);
            let mut bad = l1.clone();
            let one_more = Fr::from(1u64) + Fr::from(1u64);
            match which {
                0 => bad.az_r = fr_to_string(&one_more),
                1 => bad.bz_r = fr_to_string(&one_more),
                2 => bad.cz_r = fr_to_string(&one_more),
                3 => bad.fr_r = fr_to_string(&one_more),
                _ => bad.er_r = fr_to_string(&one_more),
            }
            let v = verify_slim_level1::<
                crate::curve::Bls12_381,
                PedersenCommitment<crate::curve::Bls12_381>,
            >(&bundle, &bad, DEFAULT_SIS_PARAM, Some(&c));
            // NOTE: tampering fr_r may fail the level-1 equation (step 4)
            // before reaching the OP check (step 8); either way it must be
            // rejected.  The az/bz/cz/er tampering is caught specifically by
            // the OP check.
            prop_assert!(v.is_err(), "tampered level-1 evaluation must be rejected");
        }

        /// Property: a slim proof for bundle A must NOT verify against a
        /// different (but valid) bundle B.
        #[test]
        fn prop_slim_rejects_cross_bundle(
            x1 in 2u64..20,
            x2 in 2u64..20,
            x3 in 2u64..20,
            y1 in 2u64..20,
            y2 in 2u64..20,
            y3 in 2u64..20,
        ) {
            let (bundle_a, slim_a, _tmp_a) = setup_slim(x1, x2, x3);
            let (bundle_b, _slim_b, _tmp_b) = setup_slim(y1, y2, y3);

            // The two bundles should differ (different random witnesses).
            // If they happen to be the same (extremely unlikely with
            // u64 ranges), skip.
            if bundle_a.final_instance == bundle_b.final_instance {
                return Ok(());
            }

            let v = verify_slim::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(&bundle_b, &slim_a);
            prop_assert!(v.is_err(), "cross-bundle proof should be rejected");
        }

        /// Property: tampering any single coefficient in any polynomial
        /// causes rejection.
        #[test]
        fn prop_slim_rejects_tampered_poly(
            x1 in 2u64..20,
            x2 in 2u64..20,
            x3 in 2u64..20,
            poly_idx in 0usize..2,
            coeff_idx in 0usize..2,
        ) {
            let (bundle, mut slim, _tmp) = setup_slim(x1, x2, x3);
            if slim.sumcheck_polys.is_empty() {
                // 0-round circuit (1 constraint): no polys to tamper.
                return Ok(());
            }
            let pi = poly_idx % slim.sumcheck_polys.len();
            let ci = coeff_idx % slim.sumcheck_polys[pi].len();

            let orig = slim.sumcheck_polys[pi][ci].clone();
            slim.sumcheck_polys[pi][ci] = fr_to_string(&(Fr::from(9999u64)));
            let v = verify_slim::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(&bundle, &slim);
            prop_assert!(v.is_err(), "tampered poly[{}][{}] should be rejected (orig={})", pi, ci, orig);
        }

        /// Property: tampering any single Fiat-Shamir challenge causes
        /// rejection.
        #[test]
        fn prop_slim_rejects_tampered_challenge(
            x1 in 2u64..20,
            x2 in 2u64..20,
            x3 in 2u64..20,
            idx in 0usize..3,
        ) {
            let (bundle, mut slim, _tmp) = setup_slim(x1, x2, x3);
            if slim.r_challenges.is_empty() {
                return Ok(());
            }
            let i = idx % slim.r_challenges.len();
            slim.r_challenges[i] = fr_to_string(&(Fr::from(42u64)));
            let v = verify_slim::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(&bundle, &slim);
            prop_assert!(v.is_err(), "tampered r_challenges[{}] should be rejected", i);
        }

        /// Property: tampering claimed_product_at_r causes rejection.
        #[test]
        fn prop_slim_rejects_tampered_product(
            x1 in 2u64..20,
            x2 in 2u64..20,
            x3 in 2u64..20,
            bad_val in 1u64..1000u64,
        ) {
            let (bundle, mut slim, _tmp) = setup_slim(x1, x2, x3);
            slim.claimed_product_at_r = fr_to_string(&(Fr::from(bad_val)));
            let v = verify_slim::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(&bundle, &slim);
            prop_assert!(v.is_err(), "tampered claimed_product_at_r should be rejected");
        }

        /// Property: tampering bundle_final_instance_hash causes rejection.
        #[test]
        fn prop_slim_rejects_tampered_instance_hash(
            x1 in 2u64..20,
            x2 in 2u64..20,
            x3 in 2u64..20,
        ) {
            let (bundle, mut slim, _tmp) = setup_slim(x1, x2, x3);
            slim.bundle_final_instance_hash = "deadbeef".to_string();
            let v = verify_slim::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(&bundle, &slim);
            prop_assert!(v.is_err(), "tampered bundle_final_instance_hash should be rejected");
        }

        /// Property: CBOR round-trip preserves slim proof validity.
        #[test]
        fn prop_slim_cbor_roundtrip(
            x1 in 2u64..20,
            x2 in 2u64..20,
            x3 in 2u64..20,
        ) {
            let (bundle, slim, _tmp) = setup_slim(x1, x2, x3);
            let cbor = slim.to_cbor::<Fr>().unwrap();
            let restored = NifsSlimProof::from_cbor::<Fr>(&cbor).unwrap();

            // Reconstructed proof must verify.
            let v = verify_slim::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(&bundle, &restored);
            prop_assert!(v.is_ok(), "CBOR round-trip proof rejected: {:?}", v.err());

            // Fields must match.
            prop_assert_eq!(restored.claimed_product_at_r, slim.claimed_product_at_r);
            prop_assert_eq!(restored.r_challenges, slim.r_challenges);
            prop_assert_eq!(restored.sumcheck_polys, slim.sumcheck_polys);
            prop_assert_eq!(restored.bundle_final_instance_hash, slim.bundle_final_instance_hash);
        }

        /// Property: slim proof size grows at most logarithmically with
        /// step count (and stays well under 1 KiB).
        #[test]
        fn prop_slim_proof_size_logarithmic(
            n1 in 2u64..10,
            n2 in 2u64..10,
            n3 in 2u64..10,
        ) {
            let (_bundle, slim, _tmp) = setup_slim(n1, n2, n3);
            let cbor = slim.to_cbor::<Fr>().unwrap();
            // For the 1-constraint test circuit: 0 sumcheck rounds, very small.
            // Should be well under 1 KiB.
            prop_assert!(
                cbor.len() < 1024,
                "slim proof CBOR {} bytes exceeds 1 KiB",
                cbor.len()
            );
        }

        /// Property: bundle_final_instance_hash is deterministic — same
        /// final instance always produces the same hash.
        #[test]
        fn prop_slim_instance_hash_deterministic(
            x1 in 2u64..20,
            x2 in 2u64..20,
            x3 in 2u64..20,
        ) {
            let (bundle, slim, _tmp) = setup_slim(x1, x2, x3);
            let instance_str = format!(
                "{}|{}|{}|{}",
                bundle.final_instance.x.join(":"),
                bundle.final_instance.u,
                bundle.final_instance.w_commit,
                bundle.final_instance.e_commit,
            );
            let hash = blake2::Blake2b512::digest(instance_str.as_bytes());
            let expected = hex::encode(&hash[..32]);
            prop_assert_eq!(slim.bundle_final_instance_hash, expected);
        }
    }

    // ── HashCommitment E2E tests ───────────────────────────────────

    use crate::commitment::HashCommitment;

    /// E2E: fold → compress → slim → verify with HashCommitment.
    #[test]
    fn hash_commit_e2e_fold_compress_slim_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }

        let fold_out = run_fold_nifs::<
            crate::curve::Bls12_381,
            HashCommitment<crate::curve::Bls12_381>,
        >(&r1cs_path, &steps_dir)
        .unwrap();
        let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc = prove_sumcheck_compression::<
            crate::curve::Bls12_381,
            HashCommitment<crate::curve::Bls12_381>,
        >(&c, &fold_out, &mut rng)
        .unwrap();

        // Full verify
        verify_sumcheck_compression::<
            crate::curve::Bls12_381,
            HashCommitment<crate::curve::Bls12_381>,
        >(&fold_out.bundle, &sc)
        .unwrap();

        // Slim verify
        let slim = sc.to_slim();
        let v = verify_slim::<crate::curve::Bls12_381, HashCommitment<crate::curve::Bls12_381>>(
            &fold_out.bundle,
            &slim,
        )
        .unwrap();
        assert_eq!(v.steps, 3);
        assert!(!v.transcript_final.is_empty());
    }

    // ── Parallel sumcheck proptests ────────────────────────────────

    proptest! {
        /// Property: parallel and sequential sumcheck compression
        /// produce byte-identical proofs and identical slim proofs.
        #[test]
        fn prop_parallel_sumcheck_matches_sequential_full(
            x1 in 2u64..20,
            x2 in 2u64..20,
            x3 in 2u64..20,
        ) {
            let tmp = tempfile::tempdir().unwrap();
            let r1cs_path = tmp.path().join("step.r1cs");
            let steps_dir = tmp.path().join("steps");
            fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
            fs::create_dir(&steps_dir).unwrap();

            let mut state = 2u64;
            for (i, x) in [x1, x2, x3].iter().enumerate() {
                state = write_step_wtns(&steps_dir, i, state, *x);
            }

            let c = load_circuit::<crate::curve::Bls12_381>(&r1cs_path).unwrap();
            let fold = run_fold_nifs_opt::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(&r1cs_path, &steps_dir, OptFlags::NONE, DEFAULT_SIS_PARAM).unwrap();

            let mut rng = rand::thread_rng();
            let sc_seq = prove_sumcheck_compression_opt::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(&c, &fold, &mut rng, OptFlags::NONE).unwrap();

            let mut rng = rand::thread_rng();
            let sc_par = prove_sumcheck_compression_opt::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(&c, &fold, &mut rng, OptFlags::PARALLEL).unwrap();

            // Proofs must be byte-identical
            let seq_json = serde_json::to_string(&sc_seq).unwrap();
            let par_json = serde_json::to_string(&sc_par).unwrap();
            prop_assert_eq!(seq_json, par_json);

            // Both must verify
            let v1 = verify_sumcheck_compression::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(&fold.bundle, &sc_seq);
            let v2 = verify_sumcheck_compression::<crate::curve::Bls12_381, PedersenCommitment<crate::curve::Bls12_381>>(&fold.bundle, &sc_par);
            prop_assert!(v1.is_ok(), "sequential proof rejected: {:?}", v1.err());
            prop_assert!(v2.is_ok(), "parallel proof rejected: {:?}", v2.err());

            // Slim proofs must be identical
            let slim_seq = sc_seq.to_slim();
            let slim_par = sc_par.to_slim();
            prop_assert_eq!(slim_seq.sumcheck_polys, slim_par.sumcheck_polys);
            prop_assert_eq!(slim_seq.r_challenges, slim_par.r_challenges);
            prop_assert_eq!(slim_seq.claimed_product_at_r, slim_par.claimed_product_at_r);
        }
    }

    #[cfg(feature = "bn254")]
    /// Build a 3-constraint step circuit: in·x = t1, t1·x = t2, t2·1 = out.
    /// This produces 2 sumcheck rounds (log2ceil(next_power_of_two(3)) = 2).
    fn multi_constraint_r1cs_bytes_bn254() -> Vec<u8> {
        type Fr = ScalarField<crate::curve::Bn254>;
        crate::circuit::r1cs_to_bytes_sparse(
            6, // n_wires: [1, out, in, x, t1, t2]
            1, // n_pub_out
            1, // n_pub_in
            3, // n_prv_in (x, t1, t2)
            // A (L): [in·x=t1, t1·x=t2, t2·1=out]
            &[
                vec![(2u32, Fr::from(1u64))], // in
                vec![(4u32, Fr::from(1u64))], // t1
                vec![(5u32, Fr::from(1u64))], // t2
            ],
            // B (R): [x, x, 1]
            &[
                vec![(3u32, Fr::from(1u64))], // x
                vec![(3u32, Fr::from(1u64))], // x
                vec![(0u32, Fr::from(1u64))], // 1
            ],
            // C (O): [t1, t2, out]
            &[
                vec![(4u32, Fr::from(1u64))], // t1
                vec![(5u32, Fr::from(1u64))], // t2
                vec![(1u32, Fr::from(1u64))], // out
            ],
        )
    }

    #[cfg(feature = "bn254")]
    fn write_bn254_step_wtns(dir: &std::path::Path, idx: usize, st_in: u64, x: u64) -> u64 {
        type Fr = ScalarField<crate::curve::Bn254>;
        let t1 = st_in * x;
        let t2 = t1 * x;
        let st_out = t2; // t2·1 = out
        fs::write(
            dir.join(format!("step_{idx:04}.wtns")),
            crate::circuit::wtns_to_bytes(&[
                Fr::from(1u64),
                Fr::from(st_out),
                Fr::from(st_in),
                Fr::from(x),
                Fr::from(t1),
                Fr::from(t2),
            ]),
        )
        .unwrap();
        st_out
    }

    #[cfg(feature = "bn254")]
    /// BN254 CBOR roundtrip: fold 3 steps with a 3-constraint circuit (2 sumcheck
    /// rounds), CBOR-encode the sumcheck proof, decode, and verify.
    /// Also CBOR-roundtrips the bundle to mirror the CLI path.
    #[test]
    fn bn254_sumcheck_cbor_roundtrip() {
        use crate::curve::Bn254;
        type Fr = ScalarField<Bn254>;
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        fs::write(&r1cs_path, multi_constraint_r1cs_bytes_bn254()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_bn254_step_wtns(&steps_dir, i, state, *x);
        }
        assert_eq!(state, 2 * 9 * 25 * 49);

        let fold =
            run_fold_nifs::<Bn254, PedersenCommitment<Bn254>>(&r1cs_path, &steps_dir).unwrap();
        assert_eq!(fold.bundle.n_steps, 3);

        let c = load_circuit::<Bn254>(&r1cs_path).unwrap();
        let mut rng = rand::thread_rng();
        let sc_proof = prove_sumcheck_compression_opt::<Bn254, PedersenCommitment<Bn254>>(
            &c,
            &fold,
            &mut rng,
            OptFlags::NONE,
        )
        .unwrap();

        // Verify in-memory (should pass).
        let v1 = verify_sumcheck_compression::<Bn254, PedersenCommitment<Bn254>>(
            &fold.bundle,
            &sc_proof,
        );
        assert!(v1.is_ok(), "in-memory verify failed: {:?}", v1.err());

        // CBOR roundtrip BOTH the bundle and the proof (mirrors CLI path).
        let bundle_cbor = fold.bundle.to_cbor::<Fr>().unwrap();
        let bundle_decoded = NifsBundle::from_cbor::<Fr>(&bundle_cbor).unwrap();
        assert_eq!(
            fold.bundle.final_instance, bundle_decoded.final_instance,
            "bundle final_instance changed after CBOR"
        );

        let proof_cbor = sc_proof.to_cbor::<Fr>().unwrap();
        let proof_decoded = NifsSumcheckProof::from_cbor::<Fr>(&proof_cbor).unwrap();

        // Verify with CBOR-roundtripped bundle and proof.
        let v2 = verify_sumcheck_compression::<Bn254, PedersenCommitment<Bn254>>(
            &bundle_decoded,
            &proof_decoded,
        );
        assert!(v2.is_ok(), "CBOR roundtrip verify failed: {:?}", v2.err());

        // CBOR roundtrip the slim proof.
        let slim = sc_proof.to_slim();
        let slim_cbor = slim.to_cbor::<Fr>().unwrap();
        let slim_decoded = NifsSlimProof::from_cbor::<Fr>(&slim_cbor).unwrap();
        assert_eq!(
            slim.sumcheck_polys, slim_decoded.sumcheck_polys,
            "slim polys changed"
        );

        let v3 = verify_slim::<Bn254, PedersenCommitment<Bn254>>(&bundle_decoded, &slim_decoded);
        assert!(
            v3.is_ok(),
            "slim CBOR roundtrip verify failed: {:?}",
            v3.err()
        );
    }

    #[cfg(feature = "bn254")]
    /// BN254 CBOR roundtrip with a single FrCbor element.
    #[test]
    fn bn254_frcbor_roundtrip() {
        use crate::curve::Bn254;
        type Fr = ScalarField<Bn254>;
        let mut rng = rand::thread_rng();

        // Build a minimal sumcheck proof with BN254 field elements.
        let polys: Vec<Vec<String>> = (0..5)
            .map(|_| {
                vec![
                    fr_to_string(&Fr::rand(&mut rng)),
                    fr_to_string(&Fr::rand(&mut rng)),
                ]
            })
            .collect();
        let claims: Vec<String> = (0..6).map(|_| fr_to_string(&Fr::rand(&mut rng))).collect();
        let r_challenges: Vec<String> = (0..5).map(|_| fr_to_string(&Fr::rand(&mut rng))).collect();

        let proof = NifsSumcheckProof {
            circuit: "test".into(),
            n_wires: 4,
            n_constraints: 3,
            n_pub_out: 1,
            n_pub_in: 2,
            final_instance: NifsFinalInstance {
                x: vec![fr_to_string(&Fr::rand(&mut rng))],
                u: fr_to_string(&Fr::rand(&mut rng)),
                w_commit: "aabb".into(),
                e_commit: "ccdd".into(),
            },
            sumcheck_polys: polys.clone(),
            sumcheck_claims: claims.clone(),
            r_challenges: r_challenges.clone(),
            claimed_product_at_r: fr_to_string(&Fr::rand(&mut rng)),
            w_commit_hash: "112233".into(),
            e_commit_hash: "445566".into(),
            w_opening: vec![fr_to_string(&Fr::rand(&mut rng))],
            e_opening: vec![fr_to_string(&Fr::rand(&mut rng))],
        };

        // CBOR roundtrip.
        let cbor = proof.to_cbor::<Fr>().unwrap();
        let decoded = NifsSumcheckProof::from_cbor::<Fr>(&cbor).unwrap();
        assert_eq!(
            proof.sumcheck_polys, decoded.sumcheck_polys,
            "polys changed after CBOR"
        );
        assert_eq!(
            proof.sumcheck_claims, decoded.sumcheck_claims,
            "claims changed after CBOR"
        );
        assert_eq!(
            proof.r_challenges, decoded.r_challenges,
            "r_challenges changed after CBOR"
        );
        assert_eq!(
            proof.claimed_product_at_r, decoded.claimed_product_at_r,
            "product changed after CBOR"
        );

        // Verify that each field element is actually the same value.
        for (i, (orig, rest)) in proof
            .sumcheck_claims
            .iter()
            .zip(decoded.sumcheck_claims.iter())
            .enumerate()
        {
            let o: Fr = orig.parse().unwrap();
            let d: Fr = rest.parse().unwrap();
            assert_eq!(o, d, "sumcheck_claims[{i}] value mismatch: {o} -> {d}");
        }
        for (i, (orig, rest)) in proof
            .sumcheck_polys
            .iter()
            .zip(decoded.sumcheck_polys.iter())
            .enumerate()
        {
            for (j, (a, b)) in orig.iter().zip(rest.iter()).enumerate() {
                let va: Fr = a.parse().unwrap();
                let vb: Fr = b.parse().unwrap();
                assert_eq!(va, vb, "polys[{i}][{j}] value mismatch: {va} -> {vb}");
            }
        }
    }
}
