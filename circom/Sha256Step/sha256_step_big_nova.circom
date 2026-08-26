pragma circom 2.0.0;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/bitify.circom";

// SHA-256 hash chain step (big): state_out = SHA256(state_in || padding)
// Input: 32 bytes (256 bits) of state + 32 bytes (256 bits) of fixed padding.
// Total SHA-256 input: 512 bits -> ~60K constraints.
// Nova-compatible: n_pub_in == n_pub_out == 32.

template Sha256StepBig() {
    signal input state_in[32];    // public: IVC state (previous hash, bytes)
    signal output state_out[32];  // public: IVC state (new hash, bytes)

    component n2b[64];
    component sha = Sha256(512);

    // First 32 bytes: state_in
    for (var i = 0; i < 32; i++) {
        n2b[i] = Num2Bits(8);
        n2b[i].in <== state_in[i];
        for (var j = 0; j < 8; j++) {
            sha.in[i * 8 + j] <== n2b[i].out[7 - j];
        }
    }

    // Second 32 bytes: fixed padding (zeros)
    for (var i = 32; i < 64; i++) {
        for (var j = 0; j < 8; j++) {
            sha.in[i * 8 + j] <== 0;
        }
    }

    // Convert output bits to bytes
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
