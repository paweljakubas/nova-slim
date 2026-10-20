//! Micro-benchmark: BLS12-381 G1 MSM, arkworks vs. the native (blst) backend.
//!
//! Motivated by the B1 fold breakdown, which showed the committed tiny-circuit
//! MSMs (15 bases) are naive-scalar-mul bound, so Pippenger-style acceleration
//! cannot help there.  This benchmark sweeps `n` to find where the native
//! backend actually starts to pay off.
//!
//! Run without the feature to get the arkworks baseline only:
//!   cargo run --release --bin benchmark_msm --features bls12-381
//! Run with it for the A/B comparison:
//!   cargo run --release --bin benchmark_msm --features native,bls12-381
//!
//! This is a standalone measurement tool; it is not part of any test target
//! and changes nothing in the library.

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use std::time::Instant;

fn derive_points_scalars(n: usize) -> (Vec<G1Affine>, Vec<Fr>) {
    let g = G1Affine::generator();
    let mut points = Vec::with_capacity(n);
    let mut scalars = Vec::with_capacity(n);
    let mut acc = Fr::from(0x9E3779B97F4A7C15u64);
    for i in 0..n {
        acc = acc * Fr::from(6364136223846793005u64) + Fr::from(i as u64 + 1);
        scalars.push(acc);
        points.push((g * Fr::from(i as u64 * 2654435761 + 7)).into_affine());
    }
    (points, scalars)
}

fn time_arkworks(points: &[G1Affine], scalars: &[Fr]) -> f64 {
    // best-of-5 to suppress scheduler noise
    let mut best = f64::INFINITY;
    for _ in 0..5 {
        let t = Instant::now();
        let _ = <ark_bls12_381::G1Projective as VariableBaseMSM>::msm(points, scalars).unwrap();
        best = best.min(t.elapsed().as_secs_f64() * 1e3);
    }
    best
}

#[cfg(feature = "native")]
fn time_native(points: &[G1Affine], scalars: &[Fr]) -> Option<f64> {
    let mut best = f64::INFINITY;
    for _ in 0..5 {
        let t = Instant::now();
        let _out = prover::native_msm::native_msm_g1(points, scalars)?;
        let dt = t.elapsed().as_secs_f64() * 1e3;
        best = best.min(dt);
    }
    // parity check against arkworks so a fast-but-wrong backend cannot win
    let out = prover::native_msm::native_msm_g1(points, scalars)?;
    let reference =
        G1Affine::from(<ark_bls12_381::G1Projective as VariableBaseMSM>::msm(points, scalars).unwrap());
    assert_eq!(out, reference, "native MSM disagrees with arkworks at n={}", points.len());
    Some(best)
}

fn main() {
    let sizes: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let sizes = if sizes.is_empty() {
        vec![15, 100, 500, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 65_536]
    } else {
        sizes
    };

    #[cfg(feature = "native")]
    {
        println!(
            "native backend: version {} flavor '{}'",
            prover::native_msm::backend_version(),
            prover::native_msm::backend_flavor()
        );
    }
    #[cfg(not(feature = "native"))]
    println!("native backend: DISABLED (build with --features native,bls12-381)");

    println!(
        "{:>8}  {:>12}  {:>12}  {:>10}",
        "n", "arkworks_ms", "native_ms", "speedup"
    );
    println!("{}", "-".repeat(48));

    for n in sizes {
        let (points, scalars) = derive_points_scalars(n);
        // warm-up
        let _ = time_arkworks(&points, &scalars);
        let ark = time_arkworks(&points, &scalars);

        #[cfg(feature = "native")]
        let native = time_native(&points, &scalars);
        #[cfg(not(feature = "native"))]
        let native: Option<f64> = None;

        match native {
            Some(nat) => println!(
                "{:>8}  {:>12.3}  {:>12.3}  {:>9.2}x",
                n,
                ark,
                nat,
                ark / nat
            ),
            None => println!("{:>8}  {:>12.3}  {:>12}  {:>10}", n, ark, "-", "-"),
        }
    }
}
