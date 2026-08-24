//! Generic sparse R1CS circuit parser — loads `.r1cs` constraint systems and
//! `.wtns` witness files for any `arkworks` prime field.
//!
//! Replaces the hard-coded `ark_bls12_381::Fr` dependency of the upstream
//! `groth16-prover` circom adapter with a fully generic `F: PrimeField`
//! implementation.

use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;
use nom::{
    bytes::complete::{tag, take},
    number::complete::{le_u32, le_u64},
    IResult,
};
use std::path::Path;

/// Parsed sparse R1CS circuit from a `.r1cs` file.
///
/// The matrices `l`, `r`, `o` store only non-zero `(wire_id, coefficient)`
/// entries per constraint, which is the native Circom format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseCircuit<F: PrimeField> {
    pub field_size: u32,
    pub prime: Vec<u8>,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prv_in: u32,
    pub n_constraints: u32,
    /// Sparse L matrix: per-constraint list of (wire_id, coeff)
    pub l: Vec<Vec<(u32, F)>>,
    /// Sparse R matrix: per-constraint list of (wire_id, coeff)
    pub r: Vec<Vec<(u32, F)>>,
    /// Sparse O matrix: per-constraint list of (wire_id, coeff)
    pub o: Vec<Vec<(u32, F)>>,
    /// Witness values (loaded separately from `.wtns`)
    pub witness: Vec<F>,
}

impl<F: PrimeField> SparseCircuit<F> {
    /// Load a sparse circuit from raw `.r1cs` bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        Self::parse_r1cs(data).map_err(|e| format!("Parse error: {:?}", e))
    }

    /// Load a sparse circuit from a `.r1cs` file path.
    pub fn from_r1cs<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let data = std::fs::read(path.as_ref())
            .map_err(|e| format!("Failed to read {}: {}", path.as_ref().display(), e))?;
        Self::from_bytes(&data)
    }

    /// Load a witness from raw `.wtns` bytes.
    pub fn load_witness_from_bytes(&mut self, data: &[u8], field_size: usize) -> Result<(), String> {
        let witness = parse_wtns(data, field_size)
            .map_err(|e| format!("Parse error: {:?}", e))?;
        if witness.len() != self.n_wires as usize {
            return Err(format!(
                "Witness length {} does not match n_wires {}",
                witness.len(), self.n_wires
            ));
        }
        self.witness = witness;
        Ok(())
    }

    /// Load a witness from a `.wtns` file path.
    pub fn load_witness<P: AsRef<Path>>(&mut self, path: P) -> Result<(), String> {
        let data = std::fs::read(path.as_ref())
            .map_err(|e| format!("Failed to read {}: {}", path.as_ref().display(), e))?;
        self.load_witness_from_bytes(&data, self.field_size as usize)
    }

    fn parse_r1cs(data: &[u8]) -> Result<Self, nom::Err<nom::error::Error<&[u8]>>> {
        let (header, constraints) = parse_r1cs_raw(data)?;
        Ok(SparseCircuit {
            field_size: header.field_size,
            prime: header.prime.to_vec(),
            n_wires: header.n_wires,
            n_pub_out: header.n_pub_out,
            n_pub_in: header.n_pub_in,
            n_prv_in: header.n_prv_in,
            n_constraints: header.n_constraints,
            l: constraints.iter().map(|(a, _, _)| a.clone()).collect(),
            r: constraints.iter().map(|(_, b, _)| b.clone()).collect(),
            o: constraints.iter().map(|(_, _, c)| c.clone()).collect(),
            witness: Vec::new(),
        })
    }
}

// ------------------------------------------------------------------
// .r1cs parser helpers (nom)
// ------------------------------------------------------------------

fn parse_r1cs_header(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, _) = tag(b"r1cs")(input)?;
    let (input, _version) = le_u32(input)?;
    let (input, _n_sections) = le_u32(input)?;
    Ok((input, ()))
}

#[derive(Debug)]
struct R1csHeader {
    field_size: u32,
    prime: Vec<u8>,
    n_wires: u32,
    n_pub_out: u32,
    n_pub_in: u32,
    n_prv_in: u32,
    _n_labels: u64,
    n_constraints: u32,
}

fn parse_header_section(input: &[u8]) -> IResult<&[u8], R1csHeader> {
    let (input, field_size) = le_u32(input)?;
    let (input, prime) = take(field_size as usize)(input)?;
    let (input, n_wires) = le_u32(input)?;
    let (input, n_pub_out) = le_u32(input)?;
    let (input, n_pub_in) = le_u32(input)?;
    let (input, n_prv_in) = le_u32(input)?;
    let (input, _n_labels) = le_u64(input)?;
    let (input, n_constraints) = le_u32(input)?;
    Ok((
        input,
        R1csHeader {
            field_size,
            prime: prime.to_vec(),
            n_wires,
            n_pub_out,
            n_pub_in,
            n_prv_in,
            _n_labels,
            n_constraints,
        },
    ))
}

type Constraint<F> = (Vec<(u32, F)>, Vec<(u32, F)>, Vec<(u32, F)>);

fn parse_r1cs_raw<F: PrimeField>(
    data: &[u8],
) -> Result<(R1csHeader, Vec<Constraint<F>>), nom::Err<nom::error::Error<&[u8]>>> {
    let (rest, _) = parse_r1cs_header(data)?;

    let mut header: Option<R1csHeader> = None;
    let mut constraints: Option<Vec<Constraint<F>>> = None;

    let mut rest = rest;
    while !rest.is_empty() {
        let (r, section_type) = le_u32(rest)?;
        let (r, section_size) = le_u64(r)?;
        let section_size = section_size as usize;
        let (r, section_data) = take(section_size)(r)?;

        match section_type {
            1 => {
                let (_, h) = parse_header_section(section_data)?;
                header = Some(h);
            }
            2 => {
                let (_, c) = parse_constraints_section(section_data)?;
                constraints = Some(c);
            }
            _ => {} // skip unknown sections
        }
        rest = r;
    }

    let header = header.ok_or_else(|| {
        nom::Err::Error(nom::error::Error::new(data, nom::error::ErrorKind::Tag))
    })?;
    let constraints = constraints.ok_or_else(|| {
        nom::Err::Error(nom::error::Error::new(data, nom::error::ErrorKind::Tag))
    })?;

    Ok((header, constraints))
}

fn parse_constraints_section<F: PrimeField>(
    input: &[u8],
) -> IResult<&[u8], Vec<Constraint<F>>> {
    let mut rest = input;
    let mut constraints = Vec::new();
    while !rest.is_empty() {
        let (r, a) = parse_sparse_vector(rest)?;
        let (r, b) = parse_sparse_vector(r)?;
        let (r, c) = parse_sparse_vector(r)?;
        constraints.push((a, b, c));
        rest = r;
    }
    Ok((&[], constraints))
}

fn parse_sparse_vector<F: PrimeField>(input: &[u8]) -> IResult<&[u8], Vec<(u32, F)>> {
    let (input, n_terms) = le_u32(input)?;
    let mut rest = input;
    let mut terms = Vec::with_capacity(n_terms as usize);
    for _ in 0..n_terms {
        let (r, wire) = le_u32(rest)?;
        let (r, val_bytes) = take(32usize)(r)?;
        let val = F::from_le_bytes_mod_order(val_bytes);
        rest = r;
        terms.push((wire, val));
    }
    Ok((rest, terms))
}

// ------------------------------------------------------------------
// .wtns parser helpers
// ------------------------------------------------------------------

fn parse_wtns_header(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, _) = tag(b"wtns")(input)?;
    let (input, _version) = le_u32(input)?;
    let (input, _n_sections) = le_u32(input)?;
    Ok((input, ()))
}

fn parse_wtns<F: PrimeField>(
    data: &[u8],
    field_size: usize,
) -> Result<Vec<F>, nom::Err<nom::error::Error<&[u8]>>> {
    let (rest, _) = parse_wtns_header(data)?;

    let mut witness = Vec::new();
    let mut rest = rest;
    while !rest.is_empty() {
        let (r, section_type) = le_u32(rest)?;
        let (r, section_size) = le_u64(r)?;
        let section_size = section_size as usize;
        let (r, section_data) = take(section_size)(r)?;

        if section_type == 2 {
            let n_wires = section_data.len() / field_size;
            let mut srest = section_data;
            for _ in 0..n_wires {
                let (sr, val_bytes) = take(field_size)(srest)?;
                let val = F::from_le_bytes_mod_order(val_bytes);
                witness.push(val);
                srest = sr;
            }
        }
        rest = r;
    }
    Ok(witness)
}

// ------------------------------------------------------------------
// Serialization helpers for tests (synthetic .r1cs / .wtns generation)
// ------------------------------------------------------------------

/// Serialize a field element to 32-byte little-endian (Circom binary format).
///
/// Uses arkworks' `CanonicalSerialize` which writes the canonical integer in
/// little-endian byte order.
fn fr_to_le_bytes<F: PrimeField>(val: &F) -> [u8; 32] {
    let mut buf = Vec::new();
    val.serialize_compressed(&mut buf).expect("Fr serialize");
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&buf);
    bytes
}

/// Serialize a witness slice to a valid Circom `.wtns` binary blob.
pub fn wtns_to_bytes<F: PrimeField>(witness: &[F]) -> Vec<u8> {
    let n_wires = witness.len() as u32;
    let field_size = 32u32;

    let mut out = Vec::new();
    out.extend_from_slice(b"wtns");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    // Section 1: header
    let mut header = Vec::new();
    header.extend_from_slice(&field_size.to_le_bytes());
    header.extend_from_slice(&[0u8; 32]); // prime placeholder
    header.extend_from_slice(&n_wires.to_le_bytes());

    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    // Section 2: witness data
    let mut data = Vec::new();
    for val in witness {
        data.extend_from_slice(&fr_to_le_bytes(val));
    }

    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&data);

    out
}

/// Serialize a *sparse* R1CS circuit to `.r1cs` bytes.
///
/// Takes the already-sparse `(wire_id, coefficient)` matrices directly.
/// The label map (section 3) is omitted; `parse_r1cs_raw` does not require it.
pub fn r1cs_to_bytes_sparse<F: PrimeField>(
    n_wires: u32,
    n_pub_out: u32,
    n_pub_in: u32,
    n_prv_in: u32,
    l: &[Vec<(u32, F)>],
    r: &[Vec<(u32, F)>],
    o: &[Vec<(u32, F)>],
) -> Vec<u8> {
    assert_eq!(l.len(), r.len());
    assert_eq!(l.len(), o.len());
    let n_constraints = l.len() as u32;
    let n_labels = n_wires as u64;
    let field_size = 32u32;
    let prime = F::MODULUS.to_bytes_le();

    let mut out = Vec::new();
    out.extend_from_slice(b"r1cs");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    // Section 1: header
    let mut header = Vec::new();
    header.extend_from_slice(&field_size.to_le_bytes());
    header.extend_from_slice(&prime);
    header.extend_from_slice(&n_wires.to_le_bytes());
    header.extend_from_slice(&n_pub_out.to_le_bytes());
    header.extend_from_slice(&n_pub_in.to_le_bytes());
    header.extend_from_slice(&n_prv_in.to_le_bytes());
    header.extend_from_slice(&n_labels.to_le_bytes());
    header.extend_from_slice(&n_constraints.to_le_bytes());

    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    // Section 2: constraints
    let mut constraints = Vec::new();
    for (a, b, c) in l.iter().zip(r).zip(o).map(|((a, b), c)| (a, b, c)) {
        for m in [a, b, c] {
            constraints.extend_from_slice(&(m.len() as u32).to_le_bytes());
            for &(wire, val) in m {
                constraints.extend_from_slice(&wire.to_le_bytes());
                constraints.extend_from_slice(&fr_to_le_bytes(&val));
            }
        }
    }

    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(constraints.len() as u64).to_le_bytes());
    out.extend_from_slice(&constraints);

    out
}
