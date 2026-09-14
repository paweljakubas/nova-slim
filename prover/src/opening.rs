//! On-chain-compatible commitment openings (P12).
//!
//! The Cardano verifier pins each commitment to a Merkle root over the
//! evaluations committed at `prove_level1` time.  Because Plutus's `blake2b_256`
//! cannot digest a 512-bit hash, the tree uses `blake2b_256` inside `blake2b_256`
//! with 32-byte big-endian field elements salted per position.
//!
//! This module mirrors the Aiken construction exactly (`opening_leaf`,
//! `empty_leaf`, `pad_leaves`, `fold_to_root` in
//! `cardano/nova-slim-verifier/lib/verifier.ak`), so a Rust-emitted opening
//! carries roots that recompute to the same commitment-hash digits the
//! validator checks.  The golden tests below pin the exact leaf/root outputs of
//! the reference Python mirror and of the Aiken test suite.

use ark_ff::{BigInteger, PrimeField};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::curve::{NovaCurve, ScalarField};

/// Canonical per-position salts for the W-side evaluations
/// `[az_r, bz_r, cz_r, fr_r]`, matching the Aiken `OpeningProof.w_salts`.
pub const W_SALTS: [&[u8]; 4] = [&[0x01], &[0x02], &[0x03], &[0x04]];

/// Canonical salt for the E-side evaluation `[er_r]`, matching the Aiken
/// `OpeningProof.e_salt`.
pub const E_SALT: &[u8] = &[0x05];

/// `blake2b_256(bytes)`, matching the on-chain `blake2b_256` builtin.
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Merkle leaf for one evaluation under its salt:
/// `blake2b_256(be32(eval mod p) || salt)`.
///
/// `be32` is the 32-byte big-endian encoding of the field element, i.e. the
/// same bytes Aiken's `integer_to_bytearray(True, 32, eval)` produces.
pub fn opening_leaf<F: PrimeField>(eval: &F, salt: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let be = eval.into_bigint().to_bytes_be();
    let off = 32 - be.len();
    // A reduced field element fits in 32 bytes; shorter encodings are
    // left-padded with zeros (the `off` prefix is already zeroed).
    buf[off..].copy_from_slice(&be);
    let mut input = Vec::with_capacity(32 + salt.len());
    input.extend_from_slice(&buf);
    input.extend_from_slice(salt);
    blake2b_256(&input)
}

/// Deterministic padding leaf used to complete an opening tree to the next
/// power of two: `blake2b_256(32 zero bytes)`.
pub fn empty_leaf() -> [u8; 32] {
    blake2b_256(&[0u8; 32])
}

fn next_power_of_two(n: usize) -> usize {
    let mut acc = 1usize;
    while acc < n {
        acc *= 2;
    }
    acc
}

fn fold_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(level.len() / 2);
    for pair in level.as_chunks::<2>().0 {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(&pair[0]);
        input.extend_from_slice(&pair[1]);
        out.push(blake2b_256(&input));
    }
    out
}

fn fold_to_root(level: &[[u8; 32]]) -> [u8; 32] {
    let mut current = level.to_vec();
    loop {
        if let [single] = current.as_slice() {
            return *single;
        }
        current = fold_level(&current);
    }
}

/// Merkle root over `evals` under per-position `salts`, padded with
/// `empty_leaf()` to the next power of two.
///
/// Mirrors the Aiken `opening_root`: one evaluation folds to its own leaf;
/// `evals.len() == salts.len()` and at least one evaluation is required.
pub fn opening_root<F: PrimeField>(
    evals: &[F],
    salts: &[&[u8]],
) -> Result<[u8; 32], Box<dyn Error>> {
    if evals.is_empty() || evals.len() != salts.len() {
        return Err(format!(
            "opening_root: {} evals vs {} salts (must be non-empty and equal)",
            evals.len(),
            salts.len()
        )
        .into());
    }
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(evals.len());
    for (eval, salt) in evals.iter().zip(salts.iter()) {
        leaves.push(opening_leaf(eval, salt));
    }
    let target = next_power_of_two(leaves.len());
    while leaves.len() < target {
        leaves.push(empty_leaf());
    }
    Ok(fold_to_root(&leaves))
}

/// Recompute an opening root from its evaluations and compare to a hex digest.
pub fn root_matches<F: PrimeField>(
    evals: &[F],
    salts: &[&[u8]],
    root_hex: &str,
) -> Result<bool, Box<dyn Error>> {
    Ok(hex::encode(opening_root(evals, salts)?) == root_hex)
}

/// The on-chain `OpeningProof` plus the commitment roots it binds, serialized
/// as hex so it survives the CBOR/JSON artifact path unchanged.
///
/// `com_w_hash` is the root of `[az_r, bz_r, cz_r, fr_r]` under `w_salts`;
/// `com_e_hash` is the root of `[er_r]` under `e_salt`.  These fill the
/// `com_w_hash` / `com_e_hash` fields of the Aiken `NifsBundle` datum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AikenOpening {
    pub w_salts: Vec<String>,
    pub e_salt: String,
    pub com_w_hash: String,
    pub com_e_hash: String,
}

/// Build the Aiken-compatible opening (canonical salts + commitment roots) for
/// a level-1 proof, computing `com_w_hash` and `com_e_hash` as the opening
/// Merkle roots of the evaluated polynomials.
pub fn aiken_opening_from_level1<C: NovaCurve>(
    proof: &crate::Level1SlimProof,
) -> Result<AikenOpening, Box<dyn Error>> {
    let parse = |s: &str| {
        s.parse::<ScalarField<C>>()
            .map_err(|_| format!("aiken_opening_from_level1: invalid field element: {s}"))
    };
    let az_r = parse(&proof.az_r)?;
    let bz_r = parse(&proof.bz_r)?;
    let cz_r = parse(&proof.cz_r)?;
    let fr_r = parse(&proof.fr_r)?;
    let er_r = parse(&proof.er_r)?;
    aiken_opening_from_evals(az_r, bz_r, cz_r, fr_r, er_r)
}

/// Build the Aiken-compatible opening from the raw evaluations a level-1
/// proof commits to: `[az_r, bz_r, cz_r, fr_r]` under `W_SALTS` for `com_w_hash`
/// and `[er_r]` under `E_SALT` for `com_e_hash`.
pub fn aiken_opening_from_evals<F: PrimeField>(
    az_r: F,
    bz_r: F,
    cz_r: F,
    fr_r: F,
    er_r: F,
) -> Result<AikenOpening, Box<dyn Error>> {
    let w_root = opening_root(&[az_r, bz_r, cz_r, fr_r], &W_SALTS)?;
    let e_root = opening_root(&[er_r], &[E_SALT])?;
    Ok(AikenOpening {
        w_salts: W_SALTS.iter().map(hex::encode).collect(),
        e_salt: hex::encode(E_SALT),
        com_w_hash: hex::encode(w_root),
        com_e_hash: hex::encode(e_root),
    })
}

/// Recompute both commitment roots from the raw evaluations and check they
/// match the opening carried by an already-emitted proof.
pub fn verify_aiken_opening<F: PrimeField>(
    az_r: F,
    bz_r: F,
    cz_r: F,
    fr_r: F,
    er_r: F,
    opening: &AikenOpening,
) -> Result<bool, Box<dyn Error>> {
    let mut w_salts: Vec<Vec<u8>> = Vec::with_capacity(opening.w_salts.len());
    for s in &opening.w_salts {
        w_salts.push(hex::decode(s)?);
    }
    let w_salt_refs: Vec<&[u8]> = w_salts.iter().map(|s| s.as_slice()).collect();
    let w_root = opening_root(&[az_r, bz_r, cz_r, fr_r], &w_salt_refs)?;
    let e_root = opening_root(&[er_r], &[hex::decode(&opening.e_salt)?.as_slice()])?;
    Ok(hex::encode(w_root) == opening.com_w_hash && hex::encode(e_root) == opening.com_e_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    fn h(s: &str) -> [u8; 32] {
        <[u8; 32]>::try_from(hex::decode(s).unwrap()).unwrap()
    }

    /// Leaf values pinned to the Aiken `golden_opening_leaf_values`.
    #[test]
    fn golden_leaf_values_match_aiken() {
        assert_eq!(
            opening_leaf(&Fr::from(2u64), &[0x01]),
            h("4dc550b6d70e17115932545b10ca42dfb184b5c4c25c1320090bd57f3734bc12")
        );
        assert_eq!(
            opening_leaf(&Fr::from(2u64), &[0x02]),
            h("f66e4dfeb6dbad7b5a51ff2ab0ce3afa73ac6c60469cb09ef0a15d41b5a3a2ef")
        );
        assert_eq!(
            opening_leaf(&Fr::from(0u64), &[0x01]),
            h("54b4c4ebb9feeb4425a865807f6f61888d0b86fbe4c84947af621673ac9feab1")
        );
    }

    /// Empty leaf pinned to the Aiken version (blake2b-256 of 32 zero bytes)
    /// and to the Python mirror.
    #[test]
    fn golden_empty_leaf_matches_aiken() {
        assert_eq!(
            empty_leaf(),
            h("89eb0d6a8a691dae2cd15ed0369931ce0a949ecafa5c3f93f8121833646e15c3")
        );
    }

    /// Single- and two-leaf roots pinned to Aiken `golden_opening_root_single_and_two_leaves`.
    #[test]
    fn golden_root_single_and_two_leaves_match_aiken() {
        let one = [0x01u8];
        let two = [0x02u8];
        assert_eq!(
            opening_root(&[Fr::from(2u64)], &[&one[..]]).unwrap(),
            h("4dc550b6d70e17115932545b10ca42dfb184b5c4c25c1320090bd57f3734bc12")
        );
        assert_eq!(
            opening_root(&[Fr::from(2u64), Fr::from(3u64)], &[&one[..], &two[..]]).unwrap(),
            h("2fee17cd477f4ced92215b970093a1bd3d1d4cdd4ff0145847162c1312a5046f")
        );
    }

    /// Three leaves pad to four with an empty leaf; pinned to Aiken
    /// `golden_opening_root_padding`.
    #[test]
    fn golden_root_padding_matches_aiken() {
        let one = [0x01u8];
        let two = [0x02u8];
        let three = [0x03u8];
        assert_eq!(
            opening_root(
                &[Fr::from(2u64), Fr::from(3u64), Fr::from(5u64)],
                &[&one[..], &two[..], &three[..]]
            )
            .unwrap(),
            h("08f5aba912810f710cfef0e58e3af79bcc12ce879c91854db4632550a342544d")
        );
    }

    /// The level-1 opening for `well_formed_proof(2, 3, 5)` must reproduce the
    /// pinned Aiken commitment roots and canonical salts.
    #[test]
    fn golden_level1_roots_match_aiken() {
        let az = Fr::from(2u64);
        let bz = Fr::from(3u64);
        let cz = Fr::from(5u64);
        let fr: Fr =
            "3202725691274893913491489135802108237160061751558547559614167388921935485580"
                .parse()
                .unwrap();
        let er: Fr =
            "3202725691274893913491489135802108237160061751558547559614167388921935485575"
                .parse()
                .unwrap();

        let opening = aiken_opening_from_evals(az, bz, cz, fr, er).unwrap();
        assert_eq!(opening.w_salts, ["01", "02", "03", "04"]);
        assert_eq!(opening.e_salt, "05");
        assert_eq!(
            opening.com_w_hash,
            "9df94619c00921fe8e1a681b239032a2d53811db87744a1f15808b1a5ddb800f"
        );
        assert_eq!(
            opening.com_e_hash,
            "0a595d63346e64f5ae4db194c37cf2a3511b782ffa4fa1fd9b7b916eb58a4019"
        );

        // Recomputing the roots from the carried openings must agree.
        assert!(verify_aiken_opening(az, bz, cz, fr, er, &opening).unwrap());

        // A tampered commitment root must be caught.
        let tampered = AikenOpening {
            com_w_hash: "00".repeat(64),
            ..opening.clone()
        };
        assert!(!verify_aiken_opening(az, bz, cz, fr, er, &tampered).unwrap());
    }

    /// The opening must be deterministic and independent of the digest
    /// internal buffer reuse.
    #[test]
    fn opening_is_deterministic() {
        let one = [0x01u8];
        let two = [0x02u8];
        let a = opening_root(&[Fr::from(7u64), Fr::from(11u64)], &[&one[..], &two[..]]).unwrap();
        let b = opening_root(&[Fr::from(7u64), Fr::from(11u64)], &[&one[..], &two[..]]).unwrap();
        assert_eq!(a, b);
    }

    /// Same evaluation under different salts yields different leaves.
    #[test]
    fn leaf_is_salt_sensitive() {
        assert_ne!(opening_leaf(&Fr::from(2u64), &[0x01]), opening_leaf(&Fr::from(2u64), &[0x02]));
    }

    /// Same salt under different evaluations yields different leaves.
    #[test]
    fn leaf_is_eval_sensitive() {
        assert_ne!(opening_leaf(&Fr::from(2u64), &[0x01]), opening_leaf(&Fr::from(3u64), &[0x01]));
    }

    /// A single evaluation must fold to its own leaf (no empty-leaf padding).
    #[test]
    fn root_single_leaf_is_leaf() {
        let salt = [0x09u8];
        assert_eq!(opening_root(&[Fr::from(7u64)], &[&salt[..]]).unwrap(), opening_leaf(&Fr::from(7u64), &salt));
    }

    /// Length mismatches must be rejected rather than silently truncated.
    #[test]
    fn root_rejects_length_mismatch() {
        let one = [0x01u8];
        assert!(opening_root(&[Fr::from(2u64), Fr::from(3u64)], &[&one[..]]).is_err());
        assert!(opening_root::<Fr>(&[], &[]).is_err());
    }
}