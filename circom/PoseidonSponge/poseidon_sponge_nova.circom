pragma circom 2.0.0;

// PoseidonSponge — Nova IVC step circuit (hash chain).
//
//   state_out = Poseidon(state_in, domain)
//
// A chain of N steps computes H(...H(H(init, d_0), d_1)..., d_{N-1}).
// This mirrors the Sonobe hash_chain benchmark for cross-system comparison.
// The public input is exactly the state (n_pub_in == n_pub_out == 1).

include "../PoseidonPreimage/poseidon_bls12_381.circom";

template PoseidonSpongeStep() {
    signal input state_in;
    signal input domain;
    signal output state_out;

    component hasher = PoseidonBLS12_381();
    hasher.in0 <== state_in;
    hasher.in1 <== domain;
    state_out <== hasher.out;
}

component main {public [state_in]} = PoseidonSpongeStep();
