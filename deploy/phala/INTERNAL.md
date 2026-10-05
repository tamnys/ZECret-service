# Package checkpoint notes

The Phala package reuses the reviewed Zebra v7.0.0-rc.0 metadata lock at
`deploy/gcp/zebra-release.lock.json` and the stage-only verifier at
`tools/gcp-guest/verify_zebra_release.py`. This is generic Zebra artifact
provenance, not a GCP deploy dependency. The explicit NU7 exception permits
staging, image-context preparation, publication, and launch-document rendering
while the seven-day hold is active. It is bound to the exact release asset ID
and digest in the stage receipt and copied into the local image context. The
earlier [native image smoke](../../records/phala-native-image-smoke.md)
covered Zebra 6.4.2; the Zebra 7 image still needs its own build and runtime
check. The stage receipt does not approve deployment or private mode. The
launch renderer rechecks that complete context and requires the pinned stage
receipt digest and exception identity; the GCP image runner retains its age
check. The verified stage receipt is
committed under `records/` and its exact SHA-256 is pinned in
`stock-candidate.lock.json`, so a caller-written receipt cannot exercise the
exception. The stock lock also pins the exact release-lock SHA-256, and
`prepare.py` verifies it before rendering. A later move of those shared inputs
must preserve the reviewed bytes and staging receipt contract.

The emitted `app-compose.json` is a local candidate. Its raw hash cannot be
called an authenticated Phala measurement until the provider accepts those
exact bytes and a post-deploy GET `/api/v1/cvms/{id}/compose_file` readback
matches. The initial [native Docker mount smoke](../../records/phala-native-mount-smoke.md)
confirmed tmpfs lifetime and public-state ownership, but did not run the
actual quote bridge. The later [actual-service probe](https://github.com/tamnys/ZECret-service/actions/runs/36701303221)
found that binding the host socket at `/run/dstack.sock` inside the quote
container made it visible through the shared `/run` volume in the app. The
corrected candidate binds that source at `/dstack.sock`, outside the shared
volume, and keeps app startup checks for both paths. The rebuilt image passed
the [native service smoke](https://github.com/tamnys/ZECret-service/actions/runs/36705200448)
with a synthetic root-owned backend. Phala's effective mount readback and
failure tests remain open; a local Docker run does not establish provider behavior.

The official Phala Cloud OpenAPI at commit
`7b36622c6eb4ff691b5818546c04c61b26e08809`, `AppComposeV2`, declares
`storage_fs` and `kms_enabled` but not `swap_size` or `key_provider`. The
renderer omits the latter two, which cannot be treated as supported Cloud
admission inputs without an updated schema or a provider-confirmed round trip.
This leaves no-swap and disk-key authorization unresolved. The OpenAPI may lag
the service, so this is a fail-closed packaging choice, not evidence that
Cloud rejects or strips those fields.

The pinned Python base is the official Docker Hub Linux amd64 manifest digest
`sha256:37134a49d21d2120e4c4d73bb76f8a4ab9aef31f096f7ec2ead48c2feead4332`;
its OCI manifest reports config digest
`sha256:b2bb53ac7b6fbe78a48c95b7c15130ea21de1674fc683fbc93158b0c23826823`
and created annotation `2026-09-19T00:58:14Z`. The two native hashes match the
unsigned, twice-matching Linux build receipt for source commit
`36822a65c96ae97213c491f2e084a5b1518df7c3`. `check-image-context`
recomputes all local build-input hashes and rejects extra paths; it does not
establish an OCI artifact or registry digest. Those identities only exist
after a separate local build and registry push respectively. A registry may
change OCI metadata on push, so compare the exact pushed digest with the
registry readback before using it in `launch-documents`.

The operator-only collateral fetcher is an independent Cargo workspace with
its own lock. It alone enables `dcap-qvl`'s `report` feature; the native `zrpc`
workspace keeps offline verification. The manifest pins registry version
`dcap-qvl=0.6.3`, and its lock pins crate checksum
`384b16fc9cbca8ec2a1302205487f29c421c51cdf7351f91c41f5ccbd1d1d17d`;
the fetch/serialization API was checked against upstream source commit
`e61f4fba357e96d68fc7d7be71635049841824fb`. The official
`dcap-qvl-cli verify`
prints a verified report rather than `QuoteCollateralV3` JSON, so it cannot
directly produce the native client's `--collateral` input. The helper's
`--fetch-from-phala-pccs` flag makes that external read explicit. No live
collateral has been fetched for this checkpoint.
