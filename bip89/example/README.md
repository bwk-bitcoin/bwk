# bwk-bip89-example

A BIP89 signing server and a wallet, with the tweak accumulator, in one binary. The
two sides only exchange serialized PSBTs. There is no network and no chain: funding
outputs are mock outpoints.

```sh
cargo run -p bwk-bip89-example
```

Keys, chain codes and signature randomness come from `rand`, so keys, scripts and
txids change on every run.

## Roles

The wallet descriptor is `tr(NUMS/<0;1>/*,multi_a(2,wallet/<0;1>/*,server/<0;1>/*))`,
where `NUMS` is BIP341's point H, the internal key no one can sign for.

```
+---------------+----------------------------------+-----------------------------------+
| Role          | Holds                            | Does                              |
+---------------+----------------------------------+-----------------------------------+
| Wallet        | Its secret key, every chain code | Builds the descriptor from the    |
| (wallet.rs)   | (its own, the NUMS key's and the | server's bare key. Signs tree     |
|               | server key's), the descriptor,   | roots (sign_tree_root) and builds |
|               | the proof trees, its UTXOs and   | proof trees (build_tree). Builds  |
|               | the next change index.           | spends and writes bundles and     |
|               |                                  | proofs (prepare). Adds its        |
|               |                                  | signature, finalizes and extracts |
|               |                                  | the transaction.                  |
| SigningServer | Its secret key and, per account, | Registers the template and roots  |
| (server.rs)   | the template, the recorded roots | (register), records later roots   |
|               | and a max outflow.               | (record_root), verifies a spend   |
|               |                                  | (verify_spend), refuses an        |
|               |                                  | outflow above the limit, then     |
|               |                                  | signs (sign_spend).               |
+---------------+----------------------------------+-----------------------------------+
```

The wallet is the BIP89 delegatee, the coordinator and the root signing key holder at
once. The server is the delegator: it gives the wallet a bare public key and never
sees a chain code. It accepts any base key of the template as root signer, as
`register` does; which keys a real service requires is its contract with its users.
The spending limit is the only policy of the example, and shows what the verified
outflow is for.

## Scenario

Account 1 has a limit of 50000 sats, fee included. Every spend pays a p2tr of a fixed
external key, with a fee of 1000 sats, and sends the rest to the next change index.

```
+------+--------------------------------------------------+---------------------------+
| Step | What happens                                     | Outcome                   |
+------+--------------------------------------------------+---------------------------+
| 1    | The server picks a random key, the wallet builds | Server key printed        |
|      | its descriptor on it.                            |                           |
| 2    | The wallet signs the receive and change roots at | Account 1 registered      |
|      | tree start 0, the server registers them with the |                           |
|      | template.                                        |                           |
| 3    | The wallet receives 100000 sats at receive index | Funding script printed    |
|      | 0.                                               |                           |
| 4    | Honest spend of 30000 sats.                      | Signed, outflow 31000,    |
|      |                                                  | txid and vsize printed    |
| 5    | Spend of 60000 sats from the 69000 sats change.  | Refused: outflow 61000    |
|      |                                                  | above the limit           |
| 6    | Forged change on the PSBT of step 4.             | Refused: NotCommitted     |
|      |                                                  | and MissingProof(1)       |
| 7    | The wallet signs the receive tree at 256, the    | Signed, outflow 31000     |
|      | server records it, the wallet receives 100000    |                           |
|      | sats at receive index 300 and spends 30000.      |                           |
+------+--------------------------------------------------+---------------------------+
```

## The forged change attack

Step 6 plays a compromised coordinator. Plain BIP89 `ChangeOutputVerification`
only checks that a change script is built from the template with the bundle's
tweaks, so it cannot tell a genuine tweak from any other scalar.

1. Take the honest PSBT of step 4.
2. Replace the change output's bundle with arbitrary scalars, not derived from any
   index, and rebuild the change script from them. `ChangeOutputVerification`
   passes.
3. Keep the proof of the genuine change: the server refuses with `NotCommitted`,
   since the forged bundle is under no recorded root.
4. Remove the proof: the server refuses with `MissingProof(1)`.

Such a change output would be unspendable and unfindable by any scan.
