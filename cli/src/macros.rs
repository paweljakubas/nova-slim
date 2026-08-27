/// Dispatch a `(Curve, CommitmentSchemeArg)` pair to a monomorphised body.
///
/// `$body` is evaluated in a scope where `C` (curve type) and `CS`
/// (commitment-scheme type) are bound to the concrete instantiations.
macro_rules! dispatch {
    ($curve:expr, $commit:expr, $body:expr) => {
        match ($curve, $commit) {
            (crate::Curve::Bls12_381, crate::CommitmentSchemeArg::Pedersen) => {
                type C = Bls12_381;
                type CS = PedersenCommitment<Bls12_381>;
                $body
            }
            (crate::Curve::Bls12_381, crate::CommitmentSchemeArg::Sis) => {
                type C = Bls12_381;
                type CS = SisCommitment<Bls12_381>;
                $body
            }
            (crate::Curve::Bls12_381, crate::CommitmentSchemeArg::Hash) => {
                type C = Bls12_381;
                type CS = HashCommitment<Bls12_381>;
                $body
            }
            (crate::Curve::Bn254, crate::CommitmentSchemeArg::Pedersen) => {
                type C = Bn254;
                type CS = PedersenCommitment<Bn254>;
                $body
            }
            (crate::Curve::Bn254, crate::CommitmentSchemeArg::Sis) => {
                type C = Bn254;
                type CS = SisCommitment<Bn254>;
                $body
            }
            (crate::Curve::Bn254, crate::CommitmentSchemeArg::Hash) => {
                type C = Bn254;
                type CS = HashCommitment<Bn254>;
                $body
            }
            (crate::Curve::Pallas, crate::CommitmentSchemeArg::Pedersen) => {
                type C = Pallas;
                type CS = PedersenCommitment<Pallas>;
                $body
            }
            (crate::Curve::Pallas, crate::CommitmentSchemeArg::Sis) => {
                type C = Pallas;
                type CS = SisCommitment<Pallas>;
                $body
            }
            (crate::Curve::Pallas, crate::CommitmentSchemeArg::Hash) => {
                type C = Pallas;
                type CS = HashCommitment<Pallas>;
                $body
            }
            (crate::Curve::Vesta, crate::CommitmentSchemeArg::Pedersen) => {
                type C = Vesta;
                type CS = PedersenCommitment<Vesta>;
                $body
            }
            (crate::Curve::Vesta, crate::CommitmentSchemeArg::Sis) => {
                type C = Vesta;
                type CS = SisCommitment<Vesta>;
                $body
            }
            (crate::Curve::Vesta, crate::CommitmentSchemeArg::Hash) => {
                type C = Vesta;
                type CS = HashCommitment<Vesta>;
                $body
            }
            (crate::Curve::Grumpkin, crate::CommitmentSchemeArg::Pedersen) => {
                type C = Grumpkin;
                type CS = PedersenCommitment<Grumpkin>;
                $body
            }
            (crate::Curve::Grumpkin, crate::CommitmentSchemeArg::Sis) => {
                type C = Grumpkin;
                type CS = SisCommitment<Grumpkin>;
                $body
            }
            (crate::Curve::Grumpkin, crate::CommitmentSchemeArg::Hash) => {
                type C = Grumpkin;
                type CS = HashCommitment<Grumpkin>;
                $body
            }
            (crate::Curve::Bandersnatch, crate::CommitmentSchemeArg::Pedersen) => {
                type C = Bandersnatch;
                type CS = PedersenCommitment<Bandersnatch>;
                $body
            }
            (crate::Curve::Bandersnatch, crate::CommitmentSchemeArg::Sis) => {
                type C = Bandersnatch;
                type CS = SisCommitment<Bandersnatch>;
                $body
            }
            (crate::Curve::Bandersnatch, crate::CommitmentSchemeArg::Hash) => {
                type C = Bandersnatch;
                type CS = HashCommitment<Bandersnatch>;
                $body
            }
        }
    };
}
