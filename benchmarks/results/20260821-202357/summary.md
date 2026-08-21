# NovaSlim benchmark — 20260821-202357

Measured with `benchmark_nova --release` (prover crate); slim IVC flow:
NIFS fold → sumcheck compress → verify. Witnesses pre-generated.

| Step circuit | Constraints | Steps | Fold total | Fold/step | Compress | Verify (full) | Verify (slim) | Slim proof | Bundle |
|---|---|---|---|---|---|---|---|---|---|
| `ed25519_verify_nova` | 7,724 | 255 | 120.7 s / 116.9 s | 473 ms / 458 ms | 20.01 s / 19.89 s | 20.05 s / 19.76 s | 0.3 ms | 6.6 KiB | 5.1 KiB |

*Each cell shows baseline / --opt-parallel where two values are shown.*
