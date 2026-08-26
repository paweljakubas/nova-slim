pragma circom 2.0.0;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/bitify.circom";

// SHA-256 hash chain step (tiny): state_out = SHA256(state_in)
// Input: 1 byte (8 bits) — minimal SHA-256 circuit.
// Nova-compatible: n_pub_in == n_pub_out == 1.

template Sha256StepTiny() {
    signal input state_in;     // public: IVC state (1 byte)
    signal output state_out;   // public: IVC state (1 byte, truncated digest)

    component n2b = Num2Bits(8);
    component sha = Sha256(8);

    n2b.in <== state_in;
    for (var j = 0; j < 8; j++) {
        sha.in[j] <== n2b.out[7 - j];
    }

    component b2n = Bits2Num(8);
    for (var j = 0; j < 8; j++) {
        b2n.in[7 - j] <== sha.out[j];
    }
    state_out <== b2n.out;
}

component main {
    public [state_in]
} = Sha256StepTiny();
