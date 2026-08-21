# NovaSlim benchmark — 20260821-201820

Measured with `benchmark_nova --release` (prover crate); slim IVC flow:
NIFS fold → sumcheck compress → verify. Witnesses pre-generated.

| Step circuit | Constraints | Steps | Fold total | Fold/step | Compress | Verify (full) | Verify (slim) | Slim proof | Bundle |
|---|---|---|---|---|---|---|---|---|---|
| `cardano_ed25519_ownership_nova` | 7,724 | 255 | 122.2 s / 120.1 s | 479 ms / 471 ms | 20.02 s / 19.86 s | 20.42 s / 20.39 s | 0.5 ms | 6.6 KiB | 5.1 KiB |

*Each cell shows baseline / --opt-parallel where two values are shown.*
