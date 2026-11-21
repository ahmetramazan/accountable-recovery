# Accountable key recovery with dispute windows: prototype

Prototype implementation of the paper *Accountable Key Recovery with Dispute Windows for
Smart-Contract Accounts*. It consists of

- `src/AccountableRecoveryModule.sol`: the account contract of Section 3.1 as an **ERC-7579 executor
  module** (transactions Request, Cancel, Dispute, Finalize, Advance and UpdateKey), with the checks
  of Section 4 (threshold BLS, Schnorr proof, DLEQ proof, hash-based decryption, batched
  verification of the evidence signatures, policy commitment).
- `src/BLS.sol`: BLS12-381 on the **EIP-2537 precompiles** (Prague): RFC 9380 hash to G1
  (`BLS12381G1_XMD:SHA-256_SSWU_RO_`, with SHA-256 and MODEXP for `hash_to_field`), BLS
  verification, MSM checks. Every precompile call forwards an explicit gas bound and first checks
  that the bound is available, so that a sender cannot make a valid input fail by limiting the gas.
- `src/mocks/`: a minimal modular account and an ECDSA owner validator (for tests only).
- `offchain/`: the guardians, the combiner and the auditor in Rust with
  [blst](https://github.com/supranational/blst): DKG (joint Feldman over G2), the two-round
  Approve protocol, Combine, Trace, Judge and UpdateKey; it also generates test vectors and runs the
  benchmarks.
- `test/`: Foundry tests that replay a complete scenario generated off-chain (request, cancel,
  finalize, advance, key update, policy dispute, dispute with outcome *bad*) and negative cases.

## Requirements

- [Foundry](https://book.getfoundry.sh/) ≥ 1.0 (`brew install foundry` or `foundryup`)
- Rust ≥ 1.80 (`rustup`)

## Running everything

```bash
git submodule update --init --recursive   # forge-std
./script/bench.sh
```

The script builds the contracts and the Rust tool, regenerates the test vectors, runs `forge test`,
starts `anvil --hardfork prague`, sends every transaction for n = 7, 20, 50 and writes

- `results/onchain.json`: total gas of each transaction (`gasUsed` of the receipt, so including the
  base cost of 21 000 gas and calldata) and the calldata cost;
- `results/offchain.json`: median running time of the off-chain algorithms (`REPS`, default 20).

Individual steps:

```bash
forge test -vv
cd offchain && cargo run --release -- fixtures
cd offchain && cargo run --release -- bench-onchain --rpc http://127.0.0.1:8545
cd offchain && cargo run --release -- bench-offchain --reps 20
```

## Encodings

All hashes are domain-separated and identical on and off chain (see `offchain/src/scheme.rs` and
the module): `m = keccak("AKR.request" ‖ chainid ‖ module ‖ account ‖ pk' ‖ e)`; H0 and H1 are
RFC 9380 hashes to G1 with DSTs `AKR-V01-H0-…` and `AKR-V01-H1-…`; H3 and H4 reduce two Keccak-256 outputs modulo r; `KDF(R,K) = keccak("AKR.kdf" ‖ R ‖ K)`; the key stream is
`keccak("AKR.ks" ‖ k ‖ i)`. Points use the uncompressed EIP-2537 encoding (128 bytes in G1, 256
bytes in G2). The module stores hashes of PK, PK_T and the list of evidence keys and receives the
points as calldata.

## Status

Research prototype, not audited. Do not use it to protect real assets.
