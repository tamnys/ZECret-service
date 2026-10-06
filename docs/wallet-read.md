# Local testnet wallet reader

The Rust wallet reader supplies Zcash testnet blockchain data to wallet software. It does not accept a seed, spending key, viewing key, or wallet database. The reference reader keeps its viewing key and SQLite wallet on your device and uses the maintained Zcash wallet scanner for shielded scanning and local balance calculation.

Wallet software can embed the Rust SDK or use the protected local bridge:

```text
wallet application → Rust SDK, directly or through authenticated loopback gRPC
  → local Tor → attested Phala TLS session → wrapper → loopback Zebra
```

Both paths require a wallet-capable, client-approved Phala release. They use the explicit `phala-trusted` profile, which trusts Phala's guest administration, KMS, and persistent runtime controls. The provider-independent profile remains unavailable. An older block-query-only endpoint or release policy cannot authorize wallet reads.

## Build and configure

Build on Linux with Rust 1.94.1 and the committed lockfile:

```sh
cargo build --locked -p zrpc-cli -p zrpc-wallet-reference
```

Set these paths and values for the exact approved deployment before starting the bridge:

| Variable | Required value |
| --- | --- |
| `ZRPC_BRIDGE_BIND` | Numeric loopback address with a nonzero port. |
| `ZRPC_CAPABILITY_DIR` | New owner-private directory path; the bridge creates it for this run. |
| `ZRPC_TICKET_STORE` | Existing owner-private free-ticket store. |
| `ZRPC_ISSUER_PUBLIC_DER`, `ZRPC_ISSUER_NAME`, `ZRPC_CRYPTO_HELPER` | Public issuer key, its approved name, and the separately built ticket-verification helper. |
| `ZRPC_ENDPOINT_HOST`, `ZRPC_ENDPOINT_PORT` | Approved Phala TLS-passthrough endpoint. |
| `ZRPC_TOR` | Absolute path to the local Tor executable. |
| `ZRPC_COLLATERAL`, `ZRPC_APP_COMPOSE`, `ZRPC_RELEASE_POLICY` | Current reviewed collateral, exact deployed Compose bytes, and a policy selecting a packaged wallet-capable release. |

The [live Phala query guide](../README.md#live-phala-testnet-queries) describes how to obtain free tickets. Each wallet RPC uses one ticket and one freshly verified connection. A ticket with an uncertain interrupted redemption is unavailable for reuse.

```sh
./target/debug/zrpc wallet-bridge \
  --privacy-profile phala-trusted --platform phala-dstack \
  --bind "$ZRPC_BRIDGE_BIND" --capability-dir "$ZRPC_CAPABILITY_DIR" \
  --ticket-store "$ZRPC_TICKET_STORE" \
  --issuer-public-der "$ZRPC_ISSUER_PUBLIC_DER" \
  --issuer-name "$ZRPC_ISSUER_NAME" --crypto-helper "$ZRPC_CRYPTO_HELPER" \
  --endpoint-host "$ZRPC_ENDPOINT_HOST" --endpoint-port "$ZRPC_ENDPOINT_PORT" \
  --tor-executable "$ZRPC_TOR" --collateral "$ZRPC_COLLATERAL" \
  --app-compose "$ZRPC_APP_COMPOSE" --release-policy "$ZRPC_RELEASE_POLICY"
```

The bridge binds only to loopback and creates a per-run capability file inside `ZRPC_CAPABILITY_DIR`. Keep that directory private and remove it only after the bridge exits. Wallet clients must add the capability as `x-zrpc-capability` gRPC metadata. `zrpc_wallet_sdk::bridge::LocalWalletAdapter` reads the private file and supplies that metadata for both this repository's protobuf client and the maintained `zcash_client_backend` client. Unmodified wallets without a local authentication hook cannot connect. Browser-origin requests and public gRPC reflection are rejected.

For responses without their own block reference, supporting releases attach the node tip observed before the backend read. The SDK exposes it as `WalletReadCompletion::node_read_context`; `read_from_request_with_context` also reports it before delivering items, including for an empty stream. The local bridge preserves it in gRPC metadata, which `NodeReadContext::read_metadata` validates. Hash bytes use the pinned protobuf's internal byte order. This observation is not an atomic snapshot of the returned balance, history, or UTXO set, and does not prove global chain freshness. Older releases report no context rather than inventing one.

Add `--dashboard` to the bridge command to open an optional, separate loopback status page. The bridge prints its one-time local link only to the operator's terminal. The page shows read activity, the last node height observed by a completed verified tip or info read, and the last committed scan heights reported by the native reference reader. These are historical observations; the node's estimate is not proof of global chain freshness, and a past read does not mean a verified connection is still open. The browser cannot send wallet RPCs or inspect wallet keys, balances, or memos. The reference reader reports only heights and compact-scan completion through the capability-protected local bridge without spending a ticket; its own scan output remains authoritative for local progress.

For a public chain-data check without a wallet key, use `zrpc-wallet-reference probe` with `info`, `tip`, or `block HEIGHT`. Each invocation makes one attested wallet RPC and uses one admission ticket:

```sh
./target/debug/zrpc-wallet-reference probe "$ZRPC_BRIDGE_BIND" "$ZRPC_CAPABILITY_DIR" info
./target/debug/zrpc-wallet-reference probe "$ZRPC_BRIDGE_BIND" "$ZRPC_CAPABILITY_DIR" tip
./target/debug/zrpc-wallet-reference probe "$ZRPC_BRIDGE_BIND" "$ZRPC_CAPABILITY_DIR" block "$ZRPC_BLOCK_HEIGHT"
```

Choose a block height present on the connected Testnet node; the displayed `node_height` is that node's progress, not a claim of global chain freshness.

## Reference wallet

Set `ZRPC_WALLET_DIR` to a new private directory, `ZRPC_UFVK_FILE` to an owner-private regular file containing a **testnet unified full viewing key**, `ZRPC_BIRTHDAY_HEIGHT` to the wallet's restoration birthday, and `ZRPC_CACHE_DIR` to an existing owner-private cache directory. The reference reader reads the viewing key locally and never gives it to the bridge. Use a batch size chosen for your device's measured memory capacity; the CLI has no implicit batch size.

```sh
./target/debug/zrpc-wallet-reference init \
  "$ZRPC_BRIDGE_BIND" "$ZRPC_CAPABILITY_DIR" \
  "$ZRPC_WALLET_DIR" "$ZRPC_UFVK_FILE" "$ZRPC_BIRTHDAY_HEIGHT"

./target/debug/zrpc-wallet-reference scan \
  "$ZRPC_BRIDGE_BIND" "$ZRPC_CAPABILITY_DIR" \
  "$ZRPC_WALLET_DIR/wallet.sqlite" "$ZRPC_CACHE_DIR/blocks.sqlite" \
  "$ZRPC_SCAN_BATCH_SIZE"

./target/debug/zrpc-wallet-reference pending \
  "$ZRPC_BRIDGE_BIND" "$ZRPC_CAPABILITY_DIR" \
  "$ZRPC_WALLET_DIR/wallet.sqlite"
```

`scan` resumes from the local wallet and compact-block cache after an interruption. Its report distinguishes committed wallet scan progress from the node's pending snapshot and labels transparent totals as unreconciled when the requested history or spentness checks are incomplete. Transparent history is staged in an unnamed local file and committed to the wallet only after the complete stream and chain anchor validate. If the filesystem does not support Linux `O_TMPFILE`, staging uses an anonymous memory-backed file; its memory use grows with the staged history. Other filesystem errors remain errors.

`pending` retrieves a finite node transaction-ID snapshot and its corresponding transactions. The snapshot may be newer than the wallet's scanned height. The reader validates both chain anchors and requires compatible consensus and note-decryption rules before committing the complete observation. If a member mines after the snapshot, its later observed mined height is preserved and the transition is counted separately. Later blocks may extend the chain; changed anchors, an interpretation boundary, or an interrupted transaction read require another scan or read. The report shows the wallet anchor, pending snapshot height and hash, and the number of newer blocks not yet scanned. It does not advance the wallet's confirmed scan height or claim an atomic balance or transaction-status snapshot.

For address checks that include pending transactions, `scan` leaves that portion unresolved until the finite snapshot checks complete. Open-ended address refresh requests recur even after a successful check; their count is reported separately from unfinished transaction and bounded-history work. Confirmed history is checked only through the scanned wallet height. A mempool observation is not a confirmation; scan again to reconcile it with mined chain data. Zebra keeps its mempool inactive while the node is behind the network tip.

## Embedded Rust integration

`zrpc_wallet_sdk::EmbeddedWalletAdapter::new(reader)` accepts a configured `WalletReader` and exposes the same typed clients as `LocalWalletAdapter`, including `maintained_scanner_client()` for the maintained wallet synchronization code. It creates no local listener or capability file. The in-process services retain the same request checks, verified upstream reads, ticket accounting, backpressure and cancellation. Keep the wallet database and viewing key in the calling wallet application.

The reference reader supports this path with `--embedded`. It uses the same endpoint, Tor, collateral, launch, release-policy and ticket inputs as the bridge:

```sh
./target/debug/zrpc-wallet-reference scan --embedded \
  --privacy-profile phala-trusted --platform phala-dstack \
  --endpoint-host "$ZRPC_ENDPOINT_HOST" --endpoint-port "$ZRPC_ENDPOINT_PORT" \
  --tor-executable "$ZRPC_TOR" --collateral "$ZRPC_COLLATERAL" \
  --app-compose "$ZRPC_APP_COMPOSE" --release-policy "$ZRPC_RELEASE_POLICY" \
  --ticket-store "$ZRPC_TICKET_STORE" \
  --issuer-public-der "$ZRPC_ISSUER_PUBLIC_DER" \
  --issuer-name "$ZRPC_ISSUER_NAME" --crypto-helper "$ZRPC_CRYPTO_HELPER" -- \
  "$ZRPC_WALLET_DIR/wallet.sqlite" "$ZRPC_CACHE_DIR/blocks.sqlite" \
  "$ZRPC_SCAN_BATCH_SIZE"
```

`init`, `pending` and `probe` accept the same embedded connection options before `--`, followed by their usual wallet or method inputs. A restart resumes from the same local wallet and cache; it opens freshly verified upstream connections rather than retaining authorization from the previous process.

The wallet bridge exposes only the pinned read-only lightwalletd-compatible methods. It rejects transaction submission, key management, testing-only methods, arbitrary forwarding, and unsupported networks. Tor, attestation, release matching, collateral validity, and the TLS connection binding must pass before a wallet request body is sent.
