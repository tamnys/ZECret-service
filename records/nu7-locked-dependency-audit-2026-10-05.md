# NU7 wallet dependency age audit, 2026-10-05

The operator approved a seven-day-hold exception for Zebra 7.0.0-rc.0 and the six directly pinned wallet prereleases in [the NU7 review](nu7-upgrade-review-2026-10-05.md). A guarded Cargo resolution of the exact direct pins changed 64 registry package versions. This read-only crates.io API audit checked each changed package against the committed lockfile checksum and yank status at 2026-10-05T21:39:33.547822Z. All 64 matched; 21 were published after the seven-day cutoff 2026-09-28T21:39:33.547822Z.

The operator subsequently approved a narrow age exception for the 15 transitive versions listed below. All 21 exceptions apply only to these exact package/version/checksum entries in `Cargo.lock` SHA-256 `cb7b5af8150de926ccc82d259444a4ff3c0d16aa9b8f644b7ed259111e3f90b0`. This permits a locked build and validation, not a blanket exception for future resolutions, image approval, or CVM acceptance.

| Package | Version | Published UTC | SHA-256 | Age exception |
|---|---|---|---|---|
| `fpe` | `0.7.0` | 2026-09-30T20:11:26.787258Z | `5045d51a6a5e85e0a18d909eedd270c4d82ad634fee57ba707692fb3b1add5a7` | approved |
| `halo2_gadgets` | `0.6.0` | 2026-09-29T03:43:36.689484Z | `8862c7f2d99964760016516103fcc621352e77a505b22b0fc25140f09e4b8bb0` | approved |
| `halo2_poseidon` | `0.2.0` | 2026-09-29T03:43:33.189434Z | `800f76fa421515e2729192e3863bb0a58f30fe17a9a165ea5e778a157adeb579` | approved |
| `halo2_proofs` | `0.4.0` | 2026-09-29T03:43:34.222091Z | `f5af2a9457f494f862cd07b81c2e98a19f50b06a2057b7569450d7c26b167d1c` | approved |
| `incrementalmerkletree` | `0.9.0` | 2026-09-30T04:18:34.586867Z | `c3b0c166f7f34e02988f84a7bed22be9707b1569acc6aeb3afaf34152d0e0400` | approved |
| `orchard` | `0.16.0` | 2026-09-30T22:13:51.418592Z | `4ae7ceb7b5387bd76cf3c0712f57708795c925cecf097036cedb60b5c3706e8f` | approved |
| `pczt` | `0.10.0-pre.0` | 2026-10-02T16:35:27.354560Z | `e4875346691fe8d61ee4995e0be580530893f5aacf08d8fae14bfd2c0733ecb9` | approved |
| `sapling-crypto` | `0.9.0` | 2026-09-30T21:18:58.228413Z | `4a2cbdcfeef20006adf72699cd466f21fe349674277cc05d3fc9b7302db7b182` | approved |
| `shardtree` | `0.8.0` | 2026-09-30T19:38:58.517072Z | `211c5ae6ff1fda9efe2cd8b90737744b3b3989f98740319284946bf110b862ed` | approved |
| `zcash_address` | `0.14.0-pre.0` | 2026-10-01T02:24:15.435652Z | `43e96e21e873c5a12fcd2ee6b04315e23e8ca4488cf4929c0774483dad24a995` | approved |
| `zcash_client_backend` | `0.25.0-pre.0` | 2026-10-02T16:35:59.678903Z | `d1c2ce1c0d0a353c2c4554bf547c4c41a72adfd2047a37897a50b937798f67df` | approved |
| `zcash_client_sqlite` | `0.23.0-pre.0` | 2026-10-02T16:37:21.564374Z | `2e8954e0ebe6f1850f21e9b1da262ec214e149234db7bf424bc7816324619f2a` | approved |
| `zcash_keys` | `0.17.0-pre.0` | 2026-10-01T15:59:49.384667Z | `2fc5f0dfdaf6eb7f6252522f7c8f013754dd1ef22aec81c5c065f8704a2af278` | approved |
| `zcash_note_encryption` | `0.5.1` | 2026-09-30T19:31:28.484183Z | `4812d133908ebf1a1c91d2411a109f63a863a152633db1fc7fbb0f774edeae30` | approved |
| `zcash_pool_migration` | `0.2.0-pre.0` | 2026-10-02T16:36:35.537309Z | `a04b3479f0a71ac560fdf07ca5119b1c9d1e44a42991a3c0595612fd51b46440` | approved |
| `zcash_primitives` | `0.31.0-pre.0` | 2026-10-01T02:25:12.366769Z | `9e2f5bf9a1e5a16612cbbab5a112bcec36a3623d8585da0187dcb58a247bc078` | approved |
| `zcash_protocol` | `0.11.0-pre.0` | 2026-10-01T02:23:57.891392Z | `98aeb25d9f741670fd63f9dbf76bca87d87c4fd32e1a7469bc4c43c4d0af09f7` | approved |
| `zcash_script` | `0.6.0` | 2026-10-01T01:41:02.055010Z | `10106859d08a2a4119af8a0fa8db72afe35647768b562f94b7a2124adad41275` | approved |
| `zcash_transparent` | `0.11.0-pre.0` | 2026-10-01T02:24:33.317845Z | `eeb255bbf28f7a6ad34e2e94871569ed1f5604d2d3ccac2ef63e0e7ce1a8ed4b` | approved |
| `zip32` | `0.3.0` | 2026-09-29T18:03:42.386083Z | `601ab4bc5f8312fa39f5411e07eb66b538687064c6e936b34eaa78f1e99ebe4d` | approved |
| `zip321` | `0.10.0-pre.0` | 2026-10-02T16:34:53.131514Z | `2e3ae1d6a417376e485a1d230adf71601ea06e5f9e27f3f6931f79db52106952` | approved |

The whole set is pinned by [Cargo.lock](../Cargo.lock). Re-audit after any resolution change; the count and status above apply only to this exact lockfile. The project uses synthetic viewing-key fixtures only, and no real wallet state is part of this audit.

An OSV `querybatch` lookup for all 64 changed package name/version pairs returned no reported vulnerabilities on 2026-10-05. The response is retained in ignored local storage with SHA-256 `de4eed3305872924d5b397a299fcc60e261d068739477fe0055547eb1e759095`. This is a point-in-time advisory check, not proof that the packages are vulnerability-free or a substitute for compilation and runtime tests.
