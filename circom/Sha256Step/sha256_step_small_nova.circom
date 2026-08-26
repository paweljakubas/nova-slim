pragma circom 2.0.0;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/bitify.circom";

// SHA-256 hash chain step (small): state_out = SHA256(state_in)
// Input: 8 bytes (64 bits) — small circuit for benchmarking.
// Nova-compatible: n_pub_in == n_pub_out == 8.

template Sha256StepSmall() {
    signal input state_in[8];     // public: IVC state (previous hash, bytes)
    signal output state_out[8];   // public: IVC state (new hash, bytes)

    component n2b[8];
    component sha = Sha256(64);

    for (var i = 0; i < 8; i++) {
        n2b[i] = Num2Bits(8);
        n2b[i].in <== state_in[i];
        for (var j = 0; j < 8; j++) {
            sha.in[i * 8 + j] <== n2b[i].out[7 - j];
        }
    }

    component b2n[8];
    for (var i = 0; i < 8; i++) {
        b2n[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            b2n[i].in[7 - j] <== sha.out[i * 8 + j];
        }
        state_out[i] <== b2n[i].out;
    }
}

component main {
    public [state_in]
} = Sha256StepSmall();
