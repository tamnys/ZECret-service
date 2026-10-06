# Phala wallet context hardware checkpoint, 2026-10-06

This internal checkpoint records live acceptance of the context-capable read
image. It is not completed reference-wallet acceptance or a distributed release
approval. The operator reconfirmed the narrow exact NU7 release-age exception;
checksum, advisory, runtime and attestation requirements remain in force.

## Artifact identities and update

- Source: `304a8c173277c3f0382241f1dc693e6faf8303c3` on main, with the same
  Git tree as native source `608219bec7b403f4f18f7965b69dfaeefcc64a41`.
- [Native build](https://github.com/tamnys/ZECret-service/actions/runs/37498404121)
  passed live source/advisory gates, native lifecycle tests and matching isolated
  binary builds. The native artifact ZIP digest is
  `sha256:1d381d6aee1de5681d6ff6352479a3ab759662ced12021245176057e554895ae`.
- [Image build](https://github.com/tamnys/ZECret-service/actions/runs/37502094126)
  produced equal image archives in two builds, passed its smoke checks and
  published `ghcr.io/tamnys/zecret-service-preview@sha256:a756418d5a394c156138d4c0b624459d41b5b628c3ad6842726835f95d3b3e35`.
  A separate registry read verified the manifest's content digest and the
  build-log config digest
  `sha256:5602769f827c2654355402366a8a0424a987ab11a73cd0df1575ab7c4663ad06`,
  including Linux/amd64 and user `10001:0`.
- Exact launch SHA-256:
  `ac7b4559f5709d4246196ec258add7ad56ad0541f2a3377b3112e7b12322b943`.
  Only the app and issuer image references changed. The quote image, preparation
  hook, public database volume, application identity and VM resources were retained.

The private exact-instance update adapter passed ten synthetic mock tests,
including wrong targets, changed launch bytes, budget/deadline/draft checks,
intent-before-mutation, interrupted updates and refusal to replay. Authenticated
inspection matched the current CVM, KMS encryption key and original ledger
generation 79. Provisioning returned HTTP 200 with the expected app and launch.
The subsequent PATCH had an uncertain response, which was retained without a
retry. Later authenticated observation resolved the execution outcome: the same
CVM was running, no update remained in progress, and the full launch readback
matched the exact candidate. Fresh guest uptime confirmed a reboot. This creates
no new VM or disk and resets neither the ledger nor the deadline.

## Live verification and reads

The existing CVM is `cvm_BKyNDJwl`, app
`5d58b973895b87dd0fd29316145979dbe87273fa`, VM UUID
`57f3fc0d-f4ff-4539-9119-e06759cc94f8`, on prod5. Its resources remain four
vCPUs, 8 GB memory and 80 GB disk at $0.243120/hour combined. The `-8443s`
TLS-passthrough endpoint is used through the managed Tor executable.

Fresh native verification passed under the Phala-trusting profile with the
reviewed guest, KMS key, new launch and exact retained TLS binding. It reported
`phala_trusted_authorized=true`, `private_accepted=false`, `query_sent=false`
and `simulation=false`. Expected measurements came from the previously reviewed
reference, not the first quote from this reboot. The temporary candidate manifest
SHA-256 is `312052c3747a86871f869e4e50983e60d0aec7c9d7c4500b3e42ea6591f25db3`;
its local inclusion is uncommitted and is not shipped by this checkpoint.

All three opt-in live bridge tests passed on this exact image:

- Info, balance and empty history preserved validated tip-before-read metadata:
  26.09 seconds. This context does not assert an atomic response snapshot.
- Twenty conformance calls completed in 85.47 seconds, including shielded blocks,
  three active commitment pools, trees, transaction details, transparent reads,
  UTXOs and both mempool interfaces.
- Concurrent local reads, an abandoned range and a subsequent fresh verified read
  completed in 14.32 seconds. No partial range was reported as complete.

A ticketed JSON-RPC chain-status read also passed: observed height 4,472,135,
estimated height and headers equal to that value, node-reported verification
progress 1.0 and active NU7 branch `77190ad9`. These are the node's observations,
not proof of global chain freshness. All tickets used here were issued free;
uncertain redemptions remained unavailable for reuse.

## Reference wallet and remaining acceptance

The saved synthetic view-only wallet resumed on the new image and reported
compact scanning complete at observed height 4,472,141, with ten successful mined
transparent-history reads and no unsupported filters. Pending reconciliation was
correctly deferred because the reader requires its local scanned tip and the
moving node tip to remain exactly equal across several attested RPCs. This is a
reproducible completion issue on an extending chain, not completed pending
acceptance. No further unchanged retries are justified by this checkpoint.

Exact locked upstream source establishes that the ten `All + Unspent` ephemeral
address checks recur after successful checks; they are not a queue that must
reach zero. Completion must distinguish a successful current observation from
scheduled refresh requests. Any correction must retain canonical-anchor and
reorganization checks, transaction decoding, incomplete-result handling and the
separation between wallet scan height and node observations.

Observed aggregate guest memory during this run was approximately 0.71 GB;
the public persistent mount used approximately 18.79 GB. One idle local bridge
sample used 7,412 KiB RSS. These samples do not establish peak memory or a
slow-consumer bound. The managed candidate verifier suite passed 53 tests and two
compile-fail checks; CLI and reference-reader builds passed. Maintained fixture
tests remain synthetic and distinct from this hardware evidence.

The original ledger remains generation 79 with no draft and a retained
conservative floor of $38.832817; this is not final billing. The $50 ceiling,
$45 deletion trigger and original deadline remain unchanged. Request deletion
by `2026-10-07T19:23:35Z`, preserving the approved hour before the hard deadline.
Phala guest administration and KMS remain explicit trusted assumptions. The
strict independent profile, actual filesystem discrepancy, independent disk
deletion evidence and final billing reconciliation remain unresolved.

## Additional SDK and resource checkpoint

A locally built, uncommitted reference reader completed a direct embedded SDK
info request against this image, observing node height 4,472,235. Its local SDK
transport uses no TCP bridge. This proves an embedded read, not complete embedded
wallet synchronization. Twelve SDK unit tests passed before a subsequent fixture
wire re-export; final affected-suite verification remains necessary.

The live slow-consumer/cancellation test passed in 40.29 seconds. An explicit
local controller paused consumption after two pinned blocks, then cancelled the
incomplete range and completed a fresh verified read. The two protobuf messages
contained 3,638 bytes and arrived 2.942767521 seconds after opening, including
attestation and startup. This small sample does not measure saturated Tor
throughput. Cancellation to completed fresh read took 1.892404869 seconds.

Client high-water memory was 9,204 KiB. Bridge RSS samples were 7,412 KiB before,
23,780 KiB while paused and 21,424 KiB afterward. Provider aggregate guest-memory
samples were 799,629,312, 828,997,632 and 824,807,424 bytes respectively. These
samples do not establish a workload-wide peak or capacity bound.

Live pending reconciliation exposed a second completion issue: transactions in a
finite mempool snapshot can become mined before their later raw-transaction
fetch. The client-only candidate now distinguishes wallet anchor H, snapshot tip
T and transactions mined after T, preserving canonical-anchor checks, strict
decoding and consensus interpretation. This latest correction has not been
rebuilt or accepted live; the previously built reader predates it.

Managed CLI tests passed (10 library and 19 binary tests). The full reference
suite then passed 35 of 37 tests. A subsequent focused run passed 21 of 23, with
14 unchanged cache tests filtered. Two failures remain: a synthetic file-backed
fixture reopens a regtest viewing key under testnet parameters, and maintained
fork recovery rejects a requested rewind above its safe checkpoint
(safe height 279,999; requested height 280,003). Passing transition guards do not
prove atomic storage or successful fork recovery while those tests fail.

The workspace's three-round correction fuse ends this checkpoint with those
items open. Feature source, user guidance and the temporary release catalog
remain uncommitted and unpackaged. PR 398 remains a draft evidence checkpoint;
no final wallet release is approved. No new VM, disk or server image was created
for these additional checks. Original budget, ledger and deletion deadlines
remain unchanged.
