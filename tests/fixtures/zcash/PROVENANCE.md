# Public Zcash response fixtures

These are public test data for protocol parsing and response-identity tests.
They contain no customer queries, wallet keys, or private-mode acceptance
evidence. Hex files contain one lowercase hexadecimal object followed by a
newline. `manifest.json` records exact source commits, Git blob identities,
source/file SHA-256 checksums, sizes, and upstream expected identifiers.

## Transactions

Source: official librustzcash `zcash_primitives 0.30.1`, commit
`97aefdc39a037da9c4f19a0e8a450d2c7932f53e`,
[`zcash_primitives/src/transaction/tests/data.rs`](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/transaction/tests/data.rs).

| File | Origin | Meaning |
|---|---|---|
| `testnet-v4-tx.hex` | `tx_read_write::TX_READ_WRITE` | Unchanged 2005-byte transaction from public testnet block 280003. |
| `zip244-v5-0.hex` | `zip_0244::make_test_vectors()[0]` | Unchanged public synthetic ZIP 244 vector with shielded components. |
| `zip244-v5-2.hex` | `zip_0244::make_test_vectors()[2]` | Unchanged public synthetic ZIP 244 vector with a transparent input. |
| `zip244-v5-2-auth-mutated.hex` | Derived from vector index 2 | Changes only the final byte of transparent input 0's scriptSig from `00` to `51`; it is not an unchanged upstream vector or a validity example. |

V4's upstream RPC txid is
`64f0bd7fe30ce23753358fe3a2dc835b8fba9c0274c4e2c54a6f73114cb55639`.
For v5, the manifest preserves upstream `txid` and `auth_digest` byte order;
`txid_rpc` is the byte-reversed hexadecimal display of the upstream txid, not a
newly calculated expected value. Upstream's
[`zip_0244` test](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/transaction/tests.rs#L960)
checks the transaction ID and authorizing commitment separately.

The derived pair is intended to exercise that distinction. The original
scriptSig is `0468984d0200`; its derived counterpart is `0468984d0251`.
The manifest records the changed zero-based byte offset. Tests must use the
maintained parser to assert these exact script values, equal txids, and unequal
authorizing commitments. A matching v5 txid alone does not authenticate all
authorizing bytes, and neither this fixture nor that comparison proves consensus
validity. The maintained implementations separate
[transparent effecting fields](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/transaction/txid.rs#L105)
from
[scriptSig authorizing data](https://github.com/zcash/librustzcash/blob/97aefdc39a037da9c4f19a0e8a450d2c7932f53e/zcash_primitives/src/transaction/txid.rs#L532).

The transaction data is used under the upstream MIT license, preserved in
`LICENSE-MIT-librustzcash`, including Electric Coin Company's copyright notice.
The synthetic vectors are not evidence of live testnet inclusion.

## Header

Source: official Zebra v6.3.0, commit
`f5c5277fe41eba9c74f37098738f93f35dd70d60`, paired
[`get_block_header_hash@testnet_10.snap`](https://github.com/ZcashFoundation/zebra/blob/f5c5277fe41eba9c74f37098738f93f35dd70d60/zebra-rpc/src/methods/tests/snapshots/get_block_header_hash%40testnet_10.snap)
and
[`get_block_header_hash_verbose@testnet_10.snap`](https://github.com/ZcashFoundation/zebra/blob/f5c5277fe41eba9c74f37098738f93f35dd70d60/zebra-rpc/src/methods/tests/snapshots/get_block_header_hash_verbose%40testnet_10.snap).

`testnet-header.hex` extracts the unchanged raw header bytes from the raw
snapshot's JSON string. `testnet-header-verbose.json` contains the paired
snapshot's JSON result object, with formatting normalized. Despite the snapshot
suffix, the returned header is public testnet block **1**, with upstream hash
`025579869bcf52a989337342f5f57a84f3a28b968f7d6a8307902b065a668d23`.
The reported confirmations and other chain-state metadata are fixture values,
not current observations or fields authenticated by the header hash.

The header data is used under Zebra's MIT license, preserved in
`LICENSE-MIT-zebra`, including the Zcash Foundation copyright notice.

## Public NU7 compact blocks

`testnet-compact-4465070.pb` and `testnet-compact-4465071.pb` are unframed
`CompactBlock` protobuf messages extracted from a successful
[`GetBlockRange`](https://testnet.zec.rocks/) response for public testnet heights
4,465,026 through 4,465,126 on 2026-10-06. The endpoint reported `test` and
`Zebra 7.0.0-rc.0` through `GetLightdInfo`. The manifest identifies the exact
gRPC response and extracted message bytes by SHA-256, along with the endpoint's
block hashes. No wallet address or viewing key was sent to fetch these blocks.

These public server responses exercise parsing, pool-data shape, and adjacent
block continuity. They do not prove consensus validity, wallet receipt or spend
ownership, attestation, release approval, or private-mode acceptance.

## Identity checks

Expected block/transaction identifiers come from upstream fixtures. Git blob
identities and SHA-256 checksums in the manifest identify source or fixture files;
they are not Zcash object identifiers. No protocol hash is implemented by the
extraction helper. The response tests must parse complete objects with the
maintained library and reject trailing bytes before comparing object identities.
