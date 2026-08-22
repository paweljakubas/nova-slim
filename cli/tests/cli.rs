use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::NamedTempFile;

// ------------------------------------------------------------------
// Synthetic .r1cs generator (self-contained tests)
// ------------------------------------------------------------------

/// Generate a synthetic `.r1cs` file for the 3-gate multiplier circuit.
fn build_synthetic_r1cs() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"r1cs");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    let field_size = 32u32;
    let n_wires = 8u32;
    let n_pub_out = 1u32;
    let n_pub_in = 0u32;
    let n_prv_in = 4u32;
    let n_labels = 8u64;
    let n_constraints = 3u32;

    let mut header = Vec::new();
    header.extend_from_slice(&field_size.to_le_bytes());
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&n_wires.to_le_bytes());
    header.extend_from_slice(&n_pub_out.to_le_bytes());
    header.extend_from_slice(&n_pub_in.to_le_bytes());
    header.extend_from_slice(&n_prv_in.to_le_bytes());
    header.extend_from_slice(&n_labels.to_le_bytes());
    header.extend_from_slice(&n_constraints.to_le_bytes());

    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    let mut constraints = Vec::new();
    let mut write_vec = |terms: &[(u32, u64)]| {
        constraints.extend_from_slice(&(terms.len() as u32).to_le_bytes());
        for &(w, v) in terms {
            constraints.extend_from_slice(&w.to_le_bytes());
            constraints.push(v as u8);
            constraints.extend_from_slice(&vec![0u8; field_size as usize - 1]);
        }
    };

    // x1*x2 = x5
    write_vec(&[(2, 1)]);
    write_vec(&[(3, 1)]);
    write_vec(&[(6, 1)]);
    // x3*x4 = x6
    write_vec(&[(4, 1)]);
    write_vec(&[(5, 1)]);
    write_vec(&[(7, 1)]);
    // x5*x6 = a
    write_vec(&[(6, 1)]);
    write_vec(&[(7, 1)]);
    write_vec(&[(1, 1)]);

    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(constraints.len() as u64).to_le_bytes());
    out.extend_from_slice(&constraints);
    out
}

/// Generate a synthetic `.r1cs` for a 1-constraint step circuit with
/// `n_pub_out == n_pub_in == 1`: wires `[1, out, in, x]`, constraint `in·x = out`.
fn build_synthetic_step_r1cs() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"r1cs");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    let field_size = 32u32;
    let n_wires = 4u32;
    let n_pub_out = 1u32;
    let n_pub_in = 1u32;
    let n_prv_in = 1u32;
    let n_labels = 4u64;
    let n_constraints = 1u32;

    let mut header = Vec::new();
    header.extend_from_slice(&field_size.to_le_bytes());
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&n_wires.to_le_bytes());
    header.extend_from_slice(&n_pub_out.to_le_bytes());
    header.extend_from_slice(&n_pub_in.to_le_bytes());
    header.extend_from_slice(&n_prv_in.to_le_bytes());
    header.extend_from_slice(&n_labels.to_le_bytes());
    header.extend_from_slice(&n_constraints.to_le_bytes());

    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    let mut constraints = Vec::new();
    let mut write_vec = |terms: &[(u32, u64)]| {
        constraints.extend_from_slice(&(terms.len() as u32).to_le_bytes());
        for &(w, v) in terms {
            constraints.extend_from_slice(&w.to_le_bytes());
            constraints.push(v as u8);
            constraints.extend_from_slice(&vec![0u8; field_size as usize - 1]);
        }
    };

    // in * x = out  (A = wire 2, B = wire 3, C = wire 1)
    write_vec(&[(2, 1)]);
    write_vec(&[(3, 1)]);
    write_vec(&[(1, 1)]);

    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(constraints.len() as u64).to_le_bytes());
    out.extend_from_slice(&constraints);
    out
}

/// Serialize witness values to a valid Circom `.wtns` blob.  The values are
/// stored as canonical little-endian field elements (the values are small
/// u64s here, so the canonical form is 8 value bytes + 24 zero bytes), which
/// matches how `parse_wtns` reads them back via `from_le_bytes_mod_order`.
fn wtns_bytes(witness: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"wtns");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    let mut header = Vec::new();
    header.extend_from_slice(&32u32.to_le_bytes());
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&(witness.len() as u32).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    let mut data = Vec::new();
    for v in witness {
        data.extend_from_slice(&v.to_le_bytes());
        data.extend_from_slice(&[0u8; 24]);
    }
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&data);
    out
}

/// Write one chained step witness for the synthetic step circuit:
/// `[1, out, in, x]` with `out = in·x`.  Returns `out` as the next state in.
fn write_step_wtns(dir: &std::path::Path, idx: usize, st_in: u64, x: u64) -> u64 {
    let st_out = st_in * x;
    fs::write(
        dir.join(format!("step_{idx:04}.wtns")),
        wtns_bytes(&[1, st_out, st_in, x]),
    )
    .unwrap();
    st_out
}

// ------------------------------------------------------------------
// CardanoKeyOwnership step-circuit tests
//
// The Cardano Ed25519 key-ownership proof is split into a chain of
// `BitElementMulAny` steps (one scalar-mul bit per step).  The step circuit
// `cardano_ed25519_ownership_nova.circom` has `n_pub_in == n_pub_out == 24`
// (the IVC state = (dblIn[4][3], addIn[4][3])), which `nova-slim` enforces.
//
// The monolithic circuits (`cardano_ed25519_ownership.r1cs`,
    // `cardano_key_ownership.r1cs`) must be *rejected* by `nova-slim params` because
// their public-input width does not equal their public-output width.  The
// step-circuit tests (compile the .circom with
// `circom --prime bls12381 --r1cs --wasm`) skip when the compiled artifacts
// are not present.
// ------------------------------------------------------------------

/// Circom fixtures from the cardano-foundation/bls repo
/// (https://github.com/cardano-foundation/bls — circom/CardanoKeyOwnership).
///
/// Resolution order:
///   1. `$BLS_REPO_DIR` if set (must contain circom/CardanoKeyOwnership),
///   2. the sibling checkout `../../bls` next to this repository.
fn cardano_key_ownership_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("BLS_REPO_DIR") {
        return std::path::PathBuf::from(dir).join("circom/CardanoKeyOwnership");
    }
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("bls/circom/CardanoKeyOwnership")
}

/// True if the user compiled the Nova step circuit (r1cs + wasm).
fn nova_step_artifacts_present() -> bool {
    let dir = cardano_key_ownership_dir();
    dir.join("cardano_ed25519_ownership_nova.r1cs").exists()
        && dir
            .join("cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm")
            .exists()
}

fn snarkjs_available() -> bool {
    std::process::Command::new("snarkjs")
        .arg("--version")
        .output()
        .is_ok()
}

/// Curve25519 base point G in extended coordinates, base-2^85 limbs
/// (from `cardano_ed25519_ownership.circom`).
const ED25519_BASE_POINT_G: [[&str; 3]; 4] = [
    [
        "6836562328990639286768922",
        "21231440843933962135602345",
        "10097852978535018773096760",
    ],
    [
        "7737125245533626718119512",
        "23211375736600880154358579",
        "30948500982134506872478105",
    ],
    ["1", "0", "0"],
    [
        "20943500354259764865654179",
        "24722277920680796426601402",
        "31289658119428895172835987",
    ],
];

/// Edwards identity in extended coordinates (X=0, Y=1, Z=1, T=0).
const EDWARDS_IDENTITY: [[&str; 3]; 4] = [
    ["0", "0", "0"],
    ["1", "0", "0"],
    ["1", "0", "0"],
    ["0", "0", "0"],
];

/// Build one step's input JSON from the current (dblIn, addIn) state.
fn step_input_json(dbl: &[[String; 3]; 4], add: &[[String; 3]; 4], sel: &str) -> String {
    let mut fields = serde_json::Map::new();
    for (i, row) in dbl.iter().enumerate() {
        for (j, v) in row.iter().enumerate() {
            fields.insert(
                format!("dbl_in_{i}_{j}"),
                serde_json::Value::String(v.clone()),
            );
        }
    }
    for (i, row) in add.iter().enumerate() {
        for (j, v) in row.iter().enumerate() {
            fields.insert(
                format!("add_in_{i}_{j}"),
                serde_json::Value::String(v.clone()),
            );
        }
    }
    fields.insert("sel".into(), serde_json::Value::String(sel.into()));
    serde_json::Value::Object(fields).to_string()
}

/// Extract a [4][3] block (12 values) starting at witness index `base`.
fn extract_witness_state(w: &[serde_json::Value], base: usize) -> [[String; 3]; 4] {
    std::array::from_fn(|i| {
        std::array::from_fn(|j| w[base + 3 * i + j].as_str().unwrap().to_string())
    })
}

/// Generate `count` chained step witnesses with snarkjs into `dir`.
///
/// The state starts at (dblIn = G, addIn = identity) and each step's public
/// outputs (witness indices 1..25) feed the next step's public inputs, so the
/// `state_in[i+1] == state_out[i]` chain invariant holds by construction.
fn generate_nova_step_witnesses(
    dir: &std::path::Path,
    wasm: &std::path::Path,
    count: usize,
) -> Result<(), String> {
    let mut dbl = ED25519_BASE_POINT_G.map(|r| r.map(String::from));
    let mut add = EDWARDS_IDENTITY.map(|r| r.map(String::from));

    for i in 0..count {
        let input_path = dir.join(format!("input_{i}.json"));
        let wtns_path = dir.join(format!("step_{i:04}.wtns"));
        let json_path = dir.join(format!("step_{i:04}.json"));

        fs::write(&input_path, step_input_json(&dbl, &add, "1"))
            .map_err(|e| format!("failed to write {}: {e}", input_path.display()))?;

        let status = std::process::Command::new("snarkjs")
            .arg("wtns")
            .arg("calculate")
            .arg(wasm)
            .arg(&input_path)
            .arg(&wtns_path)
            .status()
            .map_err(|e| format!("snarkjs failed to start: {e}"))?;
        if !status.success() {
            return Err(format!(
                "snarkjs wtns calculate failed for step {i} ({} != 0)",
                status.code().unwrap_or(-1)
            ));
        }

        let status = std::process::Command::new("snarkjs")
            .arg("wtns")
            .arg("export")
            .arg("json")
            .arg(&wtns_path)
            .arg(&json_path)
            .status()
            .map_err(|e| format!("snarkjs failed to start: {e}"))?;
        if !status.success() {
            return Err(format!(
                "snarkjs wtns export json failed for step {i} ({} != 0)",
                status.code().unwrap_or(-1)
            ));
        }

        let w: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&json_path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let w = w.as_array().ok_or("witness JSON is not an array")?;
        if w.len() < 25 {
            return Err(format!(
                "witness JSON has {} elements, expected >= 25",
                w.len()
            ));
        }
        // Public outputs (24) live at indices 1..25: [dblOut, addOut].
        dbl = extract_witness_state(w, 1);
        add = extract_witness_state(w, 13);
    }
    Ok(())
}

/// `nova-slim params` must reject the monolithic Ed25519 ownership circuit:
/// its 256-bit public input `A` is not an IVC state.
#[test]
fn params_rejects_monolithic_ed25519_ownership() {
    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership.r1cs");
    if !circuit.exists() {
        eprintln!("fixture missing; skipping test: {}", circuit.display());
        return;
    }

    let mut cmd = Command::cargo_bin("nova-slim").unwrap();
    cmd.arg("params").arg("--circuit").arg(&circuit);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid step circuit"))
        .stderr(predicate::str::contains("n_pub_in (256) != n_pub_out (1)"));
}

/// Same invariant for the JubJub ownership circuit (public in = 2, public out = 0).
#[test]
fn params_rejects_jubjub_ownership() {
    let circuit = cardano_key_ownership_dir().join("cardano_key_ownership.r1cs");
    if !circuit.exists() {
        eprintln!("fixture missing; skipping test: {}", circuit.display());
        return;
    }

    let mut cmd = Command::cargo_bin("nova-slim").unwrap();
    cmd.arg("params").arg("--circuit").arg(&circuit);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid step circuit"))
        .stderr(predicate::str::contains("n_pub_in (2) != n_pub_out (0)"));
}

/// The synthetic multiplier circuit (1 pub out, 0 pub in) is not a step circuit.
#[test]
fn params_rejects_non_step_circuit() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_r1cs()).unwrap();

    let mut cmd = Command::cargo_bin("nova-slim").unwrap();
    cmd.arg("params").arg("--circuit").arg(r1cs.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid step circuit"))
        .stderr(predicate::str::contains("n_pub_in (0) != n_pub_out (1)"));
}

#[test]
fn params_missing_circuit() {
    let mut cmd = Command::cargo_bin("nova-slim").unwrap();
    cmd.arg("params")
        .arg("--circuit")
        .arg("/tmp/does-not-exist-nova.r1cs");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load circuit"));
}

#[test]
fn params_invalid_circuit() {
    let bad_r1cs = NamedTempFile::new().unwrap();
    fs::write(bad_r1cs.path(), b"not_a_valid_r1cs_file").unwrap();

    let mut cmd = Command::cargo_bin("nova-slim").unwrap();
    cmd.arg("params").arg("--circuit").arg(bad_r1cs.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load circuit"));
}

/// `nova-slim params` on the compiled step circuit reports the IVC state shape:
/// 24 public inputs = 24 public outputs, 1 private `sel` bit.
#[test]
fn params_accepts_cardano_ed25519_ownership_step() {
    if !nova_step_artifacts_present() {
        eprintln!("Nova step circuit artifacts missing; skipping params test");
        return;
    }

    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership_nova.r1cs");

    let mut cmd = Command::cargo_bin("nova-slim").unwrap();
    cmd.arg("params").arg("--circuit").arg(&circuit);

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "nova-slim params failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let desc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(desc["n_pub_out"], 24);
    assert_eq!(desc["n_pub_in"], 24);
    assert_eq!(desc["n_prv_in"], 1);
    assert!(desc["n_constraints"].as_u64().unwrap() > 0);
}

/// Full fold → verify flow on CardanoKeyOwnership over a 3-step Ed25519
/// scalar-mul chain (NIFS path, no proving key).
#[test]
fn cardano_ed25519_ownership_nova_fold_rejects_broken_chain() {
    if !nova_step_artifacts_present() {
        eprintln!("Nova step circuit artifacts missing; skipping broken-chain test");
        return;
    }
    if !snarkjs_available() {
        eprintln!("snarkjs not installed; skipping broken-chain test");
        return;
    }

    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership_nova.r1cs");
    let wasm = cardano_key_ownership_dir()
        .join("cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm");

    // Generate 3 consecutive witnesses, then drop step 1 from the chain.
    let full_dir = tempfile::tempdir().unwrap();
    generate_nova_step_witnesses(full_dir.path(), &wasm, 3).unwrap();

    let broken_dir = tempfile::tempdir().unwrap();
    fs::copy(
        full_dir.path().join("step_0000.wtns"),
        broken_dir.path().join("step_0000.wtns"),
    )
    .unwrap();
    fs::copy(
        full_dir.path().join("step_0002.wtns"),
        broken_dir.path().join("step_0001.wtns"),
    )
    .unwrap();

    let bundle_file = NamedTempFile::new().unwrap();
    let mut fold = Command::cargo_bin("nova-slim").unwrap();
    fold.arg("fold")
        .arg("--circuit")
        .arg(&circuit)
        .arg("--steps")
        .arg(broken_dir.path())
        .arg("--out")
        .arg(bundle_file.path());
    fold.assert()
        .failure()
        .stderr(predicate::str::contains(
            "state_in does not chain to previous state_out",
        ))
        .stderr(predicate::str::contains("step_0001.wtns"));
}

/// Tampering with any part of the IVC bundle is detected at verify time.
#[test]
fn cardano_ed25519_ownership_nova_verify_rejects_tampered_bundle() {
    if !nova_step_artifacts_present() {
        eprintln!("Nova step circuit artifacts missing; skipping tamper test");
        return;
    }
    if !snarkjs_available() {
        eprintln!("snarkjs not installed; skipping tamper test");
        return;
    }

    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership_nova.r1cs");
    let wasm = cardano_key_ownership_dir()
        .join("cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm");

    let steps_dir = tempfile::tempdir().unwrap();
    generate_nova_step_witnesses(steps_dir.path(), &wasm, 3).unwrap();

    // Fold the chain (NIFS path).
    let ivc = NamedTempFile::new().unwrap();
    let mut fold = Command::cargo_bin("nova-slim").unwrap();
    fold.arg("fold")
        .arg("--circuit")
        .arg(&circuit)
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(ivc.path());
    fold.assert().success();

    // Decode the bundle (compact CBOR), then corrupt the final instance.

    // Produce a slim proof for the honest bundle, then verify the tampered
    // bundle against it — the instance mismatch must be rejected.
    let slim_file = NamedTempFile::new().unwrap();
    let mut compress = Command::cargo_bin("nova-slim").unwrap();
    compress
        .arg("compress")
        .arg("--slim")
        .arg("--circuit")
        .arg(&circuit)
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(slim_file.path());
    compress.assert().success();

    let mut bundle: prover::NifsBundle =
        prover::NifsBundle::from_cbor::<ark_bls12_381::Fr>(&fs::read(ivc.path()).unwrap()).unwrap();
    bundle.final_instance.u = "999".to_string();
    fs::write(ivc.path(), bundle.to_cbor::<ark_bls12_381::Fr>().unwrap()).unwrap();

    let mut verify = Command::cargo_bin("nova-slim").unwrap();
    verify
        .arg("verify")
        .arg("--ivc")
        .arg(ivc.path())
        .arg("--slim-proof")
        .arg(slim_file.path());
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("not created for this NIFS bundle"));
}

// ------------------------------------------------------------------
// Help output
// ------------------------------------------------------------------

/// `nova-slim --help` lists all subcommands.
#[test]
fn help_top_level() {
    let mut cmd = Command::cargo_bin("nova-slim").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage: nova-slim <COMMAND>"))
        .stdout(predicate::str::contains("Commands:"))
        .stdout(predicate::str::contains("params"))
        .stdout(predicate::str::contains("fold"))
        .stdout(predicate::str::contains("compress"))
        .stdout(predicate::str::contains("verify"));
}

// ------------------------------------------------------------------
// Error cases
// ------------------------------------------------------------------

/// `nova-slim fold` fails early when the circuit is not a valid step circuit
/// (n_pub_in != n_pub_out), before any folding work happens.
#[test]
fn fold_rejects_non_step_circuit() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_r1cs()).unwrap();
    let steps_dir = tempfile::tempdir().unwrap();
    let ivc = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("nova-slim").unwrap();
    cmd.arg("fold")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(ivc.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid step circuit"));
}

/// `nova-slim verify` fails when the IVC bundle file does not exist.
#[test]
fn verify_missing_ivc() {
    let slim = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("nova-slim").unwrap();
    cmd.arg("verify")
        .arg("--ivc")
        .arg("/nonexistent/bundle.ivc.json")
        .arg("--slim-proof")
        .arg(slim.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to read IVC bundle"));
}

// ------------------------------------------------------------------
// NIFS folding (constant-size bundle)
// ------------------------------------------------------------------

/// Full `nova-slim fold` flow on a synthetic step circuit: folding is
/// transparent (no proving key), producing an O(1) NIFS bundle with a folded
/// Relaxed-R1CS final instance and a deterministic transcript.
#[test]
fn fold_nifs_end_to_end() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_step_r1cs()).unwrap();

    // State chain: 2 -> 6 -> 30 -> 210 (private factors 3, 5, 7).
    let steps_dir = tempfile::tempdir().unwrap();
    let mut state = 2u64;
    for (i, x) in [3u64, 5, 7].iter().enumerate() {
        state = write_step_wtns(steps_dir.path(), i, state, *x);
    }
    assert_eq!(state, 210);

    let bundle_file = NamedTempFile::new().unwrap();
    let mut cmd = Command::cargo_bin("nova-slim").unwrap();
    cmd.arg("fold")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(bundle_file.path());
    cmd.assert().success();

    let bundle: prover::NifsBundle =
        prover::NifsBundle::from_cbor::<ark_bls12_381::Fr>(&fs::read(bundle_file.path()).unwrap()).unwrap();
    assert_eq!(bundle.n_steps, 3);
    assert_eq!(bundle.initial_state, serde_json::json!(["2"]).as_array().unwrap()
        .iter().map(|v| v.as_str().unwrap().to_string()).collect::<Vec<_>>());
    // The final instance holds the *folded* accumulated state
    // (x_acc = x_0 + Σ r_i·x_i), not the last step's state — so just check
    // the structure and that folding is deterministic.
    assert_eq!(bundle.final_instance.x.len(), 2);
    assert_ne!(bundle.final_instance.u, "1");
    assert!(!bundle.final_instance.w_commit.is_empty());
    assert!(!bundle.final_instance.e_commit.is_empty());
    assert_eq!(bundle.transcript_final.len(), 128);

    // Folding is deterministic: re-folding the same witnesses yields the
    // exact same bundle (challenges are transcript-derived, not sampled).
    let rerun = NamedTempFile::new().unwrap();
    let mut cmd = Command::cargo_bin("nova-slim").unwrap();
    cmd.arg("fold")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(rerun.path());
    cmd.assert().success();
    let bundle2: prover::NifsBundle =
        prover::NifsBundle::from_cbor::<ark_bls12_381::Fr>(&fs::read(rerun.path()).unwrap()).unwrap();
    assert_eq!(bundle, bundle2);
}

/// `fold` isolates the exact step whose `state_in` breaks the chain.
#[test]
fn fold_nifs_rejects_broken_chain() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_step_r1cs()).unwrap();

    let full = tempfile::tempdir().unwrap();
    let mut state = 2u64;
    for (i, x) in [3u64, 5, 7].iter().enumerate() {
        state = write_step_wtns(full.path(), i, state, *x);
    }

    let broken = tempfile::tempdir().unwrap();
    fs::copy(
        full.path().join("step_0000.wtns"),
        broken.path().join("step_0000.wtns"),
    )
    .unwrap();
    fs::copy(
        full.path().join("step_0002.wtns"),
        broken.path().join("step_0001.wtns"),
    )
    .unwrap();

    let bundle_file = NamedTempFile::new().unwrap();
    let mut cmd = Command::cargo_bin("nova-slim").unwrap();
    cmd.arg("fold")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(broken.path())
        .arg("--out")
        .arg(bundle_file.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(
            "state_in does not chain to previous state_out",
        ))
        .stderr(predicate::str::contains("step_0001.wtns"));
}

/// `nova-slim verify` without a proof flag reports what is missing.
#[test]
fn verify_requires_a_proof_flag() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_step_r1cs()).unwrap();

    let steps_dir = tempfile::tempdir().unwrap();
    let mut state = 2u64;
    for (i, x) in [3u64, 5, 7].iter().enumerate() {
        state = write_step_wtns(steps_dir.path(), i, state, *x);
    }

    let bundle_file = NamedTempFile::new().unwrap();
    let mut fold = Command::cargo_bin("nova-slim").unwrap();
    fold.arg("fold")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(bundle_file.path());
    fold.assert().success();

    let mut verify = Command::cargo_bin("nova-slim").unwrap();
    verify.arg("verify").arg("--ivc").arg(bundle_file.path());
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("nothing to verify"));
}

/// Full slim flow at the CLI level on a synthetic step circuit:
///   fold → compress --slim → verify --slim-proof.
#[test]
fn nifs_compress_verify_end_to_end() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_step_r1cs()).unwrap();

    let steps_dir = tempfile::tempdir().unwrap();
    let mut state = 2u64;
    for (i, x) in [3u64, 5, 7].iter().enumerate() {
        state = write_step_wtns(steps_dir.path(), i, state, *x);
    }

    // 1. fold -> bundle
    let bundle_file = NamedTempFile::new().unwrap();
    let mut fold = Command::cargo_bin("nova-slim").unwrap();
    fold.arg("fold")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(bundle_file.path());
    fold.assert().success();

    // 2. compress --slim -> on-chain proof
    let proof_file = NamedTempFile::new().unwrap();
    let mut compress = Command::cargo_bin("nova-slim").unwrap();
    compress
        .arg("compress")
        .arg("--slim")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(proof_file.path());
    compress
        .assert()
        .success()
        .stderr(predicate::str::contains("Slim proof written"));

    // 3. verify the bundle with the slim proof
    let mut verify = Command::cargo_bin("nova-slim").unwrap();
    verify
        .arg("verify")
        .arg("--ivc")
        .arg(bundle_file.path())
        .arg("--slim-proof")
        .arg(proof_file.path());
    verify
        .assert()
        .success()
        .stderr(predicate::str::contains("slim sumcheck proof OK"));

    // 4. tampering the bundle's instance must fail verification
    let mut tampered: prover::NifsBundle =
        prover::NifsBundle::from_cbor::<ark_bls12_381::Fr>(&fs::read(bundle_file.path()).unwrap()).unwrap();
    tampered.final_instance.x[0] = (state + 1).to_string();
    let tampered_file = tempfile::NamedTempFile::new().unwrap();
    fs::write(tampered_file.path(), tampered.to_cbor::<ark_bls12_381::Fr>().unwrap()).unwrap();
    let mut verify2 = Command::cargo_bin("nova-slim").unwrap();
    verify2
        .arg("verify")
        .arg("--ivc")
        .arg(tampered_file.path())
        .arg("--slim-proof")
        .arg(proof_file.path());
    verify2.assert().failure();
}
