# NU7 wallet-read live validation — 2026-10-05/06

This is internal test evidence for the operator-authorized, billable Phala run.
It does not approve a client release or the provider-independent privacy profile.
The operator approved a narrow release-age exception for the exact NU7 wallet
dependency graph; the pinned graph and its preflight results were merged in
PR #379. The x86_64 Zebra 7.0.0-rc.0 ticketed overlay was built twice and
published by PRs #380 and #381 at
`ghcr.io/tamnys/zecret-service-preview@sha256:627dcc4298bdaf629f090adc5dcdad6b1d64aaa11d65f83e869acb30f1db18af`.

The run used CVM `cvm_mjbR45jM`, app ID
`79bb833e6422447615c7e26b0d96186580722e1c`, on prod9 at the quoted
combined rate of $0.243120/hour. The original experiment ledger recorded its
creation before launch. Independent local DCAP verification of the live quote
and collateral reported UpToDate TCB, and authenticated event replay matched
the exact Compose digest
`b753726b723b21110ffb38fb966da20310b54aab17cdd1997914036bc7a325d2`.
The Phala-trusting profile accepted a **temporary, exact-instance** candidate
release and the retained TLS session sent ticketed requests through Tor. The
strict provider-independent profile remained blocked. The temporary embedded
release was withdrawn from source after the run; no general client approval is
packaged by this checkpoint.

Through the authenticated local bridge, `GetLightdInfo`, `GetLatestBlock`,
compact-block ranges of 3, 100, and 1,000 blocks, and transparent history for
a public Zcash documentation example address returned live testnet data. The
1000-block range completed without truncation. The node reached height
4,465,335, beyond NU7 activation at 4,465,026. A separate 18-block range
from 4,465,018 through 4,465,035 crossed activation and completed. A synthetic
view-only wallet resumed from an existing local database after applying the
maintained wallet schema migrations, then scanned through post-NU7 height
4,465,206 with `compact_scan_complete=true`. Its reported Sapling, Orchard,
Ironwood, and unreconciled transparent balances were zero. This wallet was
synthetic and had no customer keys or funds.

The wallet still reported **10 unresolved transparent-history requests** and
10 remaining transaction requests. The bridge's protocol does not supply a
complete mempool snapshot marker, so the reader did not claim an atomic or
complete transparent balance. A scan attempt also received one transient
`Unavailable`; its durable height survived and a retry completed. These facts
preclude claiming the full wallet-read acceptance plan is complete.

The bridge and scanner were stopped. At ledger generation 46, the explicit
`delete-tracked` command durably recorded intent generation 47 and Phala's
HTTP 204 deletion initiation. A subsequent authenticated workspace inventory
returned zero CVMs, and an exact detail read for this CVM returned 404. The
read was non-atomic. A reconciliation of that observation was committed at
generation 49. The ledger still reports `cleanup_complete=false`,
`independent_disk_deletion_verified=false`, and `billing_reconciled=false`;
therefore neither final storage deletion nor final billing is established.
The most recent retained historical modeled cost floor was $38.832817 before
this run and is not a final provider bill.
