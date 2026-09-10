use cardano/transaction.{OutputReference, Transaction}
use verifier.{NovaSlimDatum, SlimProof, SumOnly, WithNorm, verify_slim, verify_slim_with_norm}

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
      None -> False
    }
  }

  else(_) {
    fail
  }
}
