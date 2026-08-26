pragma circom 2.0.0;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/bitify.circom";

// SHA-256 hash chain step (big): state_out = SHA256(state_in)
// Input: 64 bytes (512 bits) — large circuit for benchmarking.
// Nova-compatible: n_pub_in == n_pub_out == 32 (SHA-256 output is always 32 bytes).
// The input is 64 bytes but only the first 32 bytes are fed to SHA-256
// (padded internally).  The state output is the 32-byte digest.

template Sha256StepBig() {
    signal input state_in[64];    // public: IVC state (64 bytes input)
    signal output state_out[32];  // public: IVC state (32-byte digest)

    component n2b[64];
    component sha = Sha256(512);

    for (var i = 0; i < 64; i++) {
        n2b[i] = Num2Bits(8);
        n2b[i].in <== state_in[i];
        for (var j = 0; j < 8; j++) {
            sha.in[i * 8 + j] <== n2b[i].out[7 - j];
        }
    }

    component b2n[32];
    for (var i = 0; i < 32; i++) {
        b2n[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            b2n[i].in[7 - j] <== sha.out[i * 8 + j];
        }
        state_out[i] <== b2n[i].out;
    }
}

component main {
    public [state_in]
} = Sha256StepBig();
