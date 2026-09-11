use cardano/transaction.{OutputReference, Transaction}
use verifier.{
  NovaSlimDatum, SlimProof, SumOnly, WithNorm, WithOpening, WithOpeningNorm,
  verify_slim, verify_slim_level1, verify_slim_level1_with_norm,
  verify_slim_with_norm,
}

validator nova_slim {
  spend(
    datum: Option<NovaSlimDatum>,
    redeemer: SlimProof,
    _utxo: OutputReference,
    _self: Transaction,
  ) {
    when datum is {
      Some(SumOnly(bundle)) -> verify_slim(bundle, redeemer)
      Some(WithNorm(bundle, norm)) ->
        verify_slim_with_norm(bundle, redeemer, norm)
      Some(WithOpening(bundle, opening)) ->
        verify_slim_level1(bundle, redeemer, opening)
      Some(WithOpeningNorm(bundle, opening, norm)) ->
        verify_slim_level1_with_norm(bundle, redeemer, opening, norm)
      None -> False
    }
  }

  else(_) {
    fail
  }
}
