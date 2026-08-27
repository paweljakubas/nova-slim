use cardano/transaction.{Transaction, OutputReference}
use verifier.{NifsBundle, SlimProof, verify_slim}

validator nova_slim {
  spend(datum: Option<NifsBundle>, redeemer: SlimProof, _utxo: OutputReference, _self: Transaction) {
    when datum is {
      Some(bundle) -> verify_slim(bundle, redeemer)
      None -> False
    }
  }
}
