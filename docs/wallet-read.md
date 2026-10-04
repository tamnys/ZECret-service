# Local testnet wallet reader

The Rust wallet reader supplies Zcash testnet blockchain data to wallet software. It does not accept a seed, spending key, viewing key, or wallet database. The reference reader keeps its viewing key and SQLite wallet on your device and uses the maintained Zcash wallet scanner for shielded scanning and local balance calculation.

The supported connection is:

```text
wallet application → authenticated loopback gRPC bridge → Rust wallet reader
  → local Tor → attested Phala TLS session → wrapper → loopback Zebra
```

The bridge requires a wallet-capable, client-approved Phala release. It uses the explicit `phala-trusted` profile, which trusts Phala's guest administration, KMS, and persistent runtime controls. The provider-independent profile remains unavailable. An older block-query-only endpoint or release policy cannot authorize wallet reads.

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

Add `--dashboard` to the bridge command to open an optional, separate loopback status page. The bridge prints its one-time local link only to the operator's terminal. The page shows whether a wallet read is in progress and the outcome of the last upstream read; it cannot send wallet RPCs or inspect wallet keys or balances. A past completed read does not mean a verified connection is still open. Node synchronization and wallet scan progress are not available from this bridge status page. The wallet application's own scan report is authoritative for its local progress.

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

`scan` resumes from the local wallet and compact-block cache after an interruption. Its report separates wallet scan height from node tip height and labels transparent totals as unreconciled when the requested history or spentness checks are incomplete. The wallet directory's Linux filesystem must support `O_TMPFILE`: transparent history is staged in an unnamed local file and committed to the wallet only after the complete stream and chain anchor validate. For address checks that include pending transactions, `scan` imports confirmed history but leaves the pending portion unresolved. `pending` observes transactions in Zebra's live mempool stream only after the wallet scan reaches the same node tip. A mempool observation is not a confirmation; scan again to reconcile it with mined chain data. Zebra keeps its mempool inactive while the node is behind the network tip.

The wallet bridge exposes only the pinned read-only lightwalletd-compatible methods. It rejects transaction submission, key management, testing-only methods, arbitrary forwarding, and unsupported networks. Tor, attestation, release matching, collateral validity, and the TLS connection binding must pass before a wallet request body is sent.
