# BIP32 Key Derivation for NovaSlim PoC

This directory contains actual BIP32-Ed25519 key derivations using `cardano-address`,
showing the real inputs and outputs that a NovaSlim step circuit would prove.

## Recovery Phrase

```
alien add jeans proof ghost word drama tuition change churn letter sting anchor liquid essay
```

## Derivation Path: m/1852'/1815'/0'/0/0

This is the standard Cardano Shelley derivation path for the first address of account 0.

### Step 0: Root Key

```bash
cardano-address key from-recovery-phrase Shelley < recovery-phrase.txt > root.xprv
```

Root extended private key (hex):
- chain_code: `885a4a049e6832b312a76a81dd035abbb432625b4ba9d687e26f56f578cde307`
- extended_key: `a8c5655d54e908e7182cc59a03e34342376598d5923d83bb0c82f675f867794f73881dd86d82c465e5ef151597ff612307302d7d2dff8fef69ad867b4bf4e38c`

### Step 1: Account Key (m/1852'/1815'/0')

```bash
cardano-address key child 1852H/1815H/0H < root.xprv > acct.xprv
cardano-address key public --with-chain-code < acct.xprv > acct.xpub
```

Account extended public key (hex):
- chain_code: `66aae6311aceac7c2c554ca6f35ceaf017e9d0991b35b05e4a91b2d9309d5233`
- extended_key: `cb2e49bf3dd03921280a244e1a6ee239a5526cfd6a3d5fa14733d3eca62cbe09`

### Step 2: Address Key (m/1852'/1815'/0'/0/0)

```bash
cardano-address key child 0/0 < acct.xprv > addr.xprv
cardano-address key public --with-chain-code < addr.xprv > addr.xpub
```

Address extended public key (hex):
- chain_code: `69f7aac922e1dda4dc742e9e5a10c100ddf7c30ecbe681046c4f2730f0269c19`
- extended_key: `b3f0e5a4114bf76c318512012cdecc67a7fc3f65c3713edfb05eff0635930fb3`

## NovaSlim Circuit Mapping

In a real BIP32-Ed25519 NovaSlim circuit, each step would prove:

| Step | Public Input | Private Input | Public Output |
|---|---|---|---|
| 1 (role) | Account XPub + chain code | Account XPrv | Role XPub + chain code |
| 2 (index) | Role XPub + chain code | Role XPrv | Address XPub + chain code |

The circuit would verify:
1. HMAC-SHA512(chain_code || child_index, parent_key) produces I_L and I_R
2. Child key = parent_key + I_L (scalar addition on Ed25519)
3. Child chain_code = I_R

## Files

- `recovery-phrase.txt` — 15-word recovery phrase
- `root.xprv` — root extended private key
- `acct.xprv` — account extended private key (m/1852'/1815'/0')
- `acct.xpub` — account extended public key
- `addr.xprv` — address extended private key (m/1852'/1815'/0'/0/0)
- `addr.xpub` — address extended public key

## Notes

- `cardano-address` derives Ed25519 keys using the BIP32-Ed25519 scheme (Khovratovich)
- Hardened derivation (`H`) requires the private key; non-hardened can use public key
- For the NovaSlim proof, the prover knows the private keys; the verifier only sees public keys
- The actual circuit would need ~10,560 constraints per step (HMAC-SHA512 + scalar addition)
