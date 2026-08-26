pragma circom 2.0.0;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/bitify.circom";

// SHA-256 hash chain step: state_out = SHA256(state_in)
// Nova-compatible: n_pub_in == n_pub_out == 32 (bytes)
// Based on nova-bench (https://github.com/privacy-ethereum/nova-bench)
// Constraint count: ~27K (circomlib SHA-256 on 256 bits)
template Sha256Step() {
    signal input state_in[32];    // public: IVC state (previous hash, bytes)
    signal output state_out[32];  // public: IVC state (new hash, bytes)

    // Convert input bytes to bits
    component n2b[32];
    component sha = Sha256(256);

    for (var i = 0; i < 32; i++) {
        n2b[i] = Num2Bits(8);
        n2b[i].in <== state_in[i];
        for (var j = 0; j < 8; j++) {
            sha.in[i * 8 + j] <== n2b[i].out[7 - j];
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
} = Sha256Step();
