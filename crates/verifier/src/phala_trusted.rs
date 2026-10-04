//! Phala-managed guest approval is separate from provider-independent approval.
//! The client packages exact reviewed manifest bytes; a local selection can
//! only narrow this catalog.

use crate::{PhalaTrustedPolicy, invalid_policy, workload::WorkloadPolicy};
use ez_hash::{Hasher, Sha256};
use serde::{
    Deserialize,
    de::{self, MapAccess, Visitor},
};
use std::{collections::BTreeMap, fmt};
use zrpc_protocol::{ErrorCode, SafeError};

struct EmbeddedRelease {
    id: &'static str,
    manifest_sha256: [u8; 32],
    manifest_json: &'static [u8],
}

const EMBEDDED_RELEASES: &[EmbeddedRelease] = &[
    EmbeddedRelease {
        id: "phala-prod9-testnet-20261001-1",
        manifest_sha256: [
            0x80, 0x73, 0xad, 0xda, 0x03, 0x3f, 0xf8, 0xb9, 0x64, 0xc4, 0x6d, 0x88, 0xe6, 0x72,
            0x04, 0x9c, 0x0f, 0x5b, 0x43, 0xd9, 0x46, 0xdc, 0x79, 0x8c, 0x46, 0x82, 0x1f, 0xe1,
            0x35, 0x23, 0x86, 0x69,
        ],
        manifest_json: include_bytes!("releases/phala-prod9-20261001.json"),
    },
    EmbeddedRelease {
        id: "phala-prod9-testnet-block-context-20261001-2",
        manifest_sha256: [
            0xd3, 0xc4, 0x65, 0x55, 0x8e, 0x62, 0x49, 0xf2, 0xdc, 0xb9, 0x1d, 0xa7, 0x42, 0x9e,
            0x81, 0xce, 0x89, 0x5d, 0x69, 0x48, 0xdb, 0xc1, 0x96, 0x20, 0xd2, 0x1f, 0xf3, 0xfd,
            0xa9, 0xd1, 0x06, 0xa1,
        ],
        manifest_json: include_bytes!("releases/phala-prod9-block-context-20261001.json"),
    },
    EmbeddedRelease {
        id: "phala-prod9-testnet-ticketed-20261001-3",
        manifest_sha256: [
            0x2c, 0xd7, 0x05, 0xcb, 0xa8, 0xae, 0xf0, 0xc5, 0x6f, 0x86, 0xda, 0x64, 0x97, 0xbb,
            0x08, 0xb1, 0x50, 0xa3, 0xf6, 0xda, 0xb1, 0xcc, 0xb4, 0x42, 0x56, 0x8b, 0x2f, 0xcc,
            0x8f, 0xd9, 0xd4, 0x39,
        ],
        manifest_json: include_bytes!("releases/phala-prod9-ticketed-20261001.json"),
    },
    EmbeddedRelease {
        id: "phala-prod9-testnet-blockcount-20261001-4",
        manifest_sha256: [
            0x51, 0xe7, 0x01, 0x61, 0x01, 0xb2, 0x2e, 0x18, 0x58, 0x8f, 0xf1, 0xac, 0xcb, 0xa9,
            0x19, 0xd6, 0x6f, 0x35, 0x71, 0xbb, 0x59, 0x1e, 0xcf, 0xcd, 0xee, 0xdb, 0x5f, 0x1d,
            0xd0, 0x67, 0xb7, 0x5c,
        ],
        manifest_json: include_bytes!("releases/phala-prod9-blockcount-20261001.json"),
    },
];

pub(crate) fn is_embedded(id: &str) -> bool {
    EMBEDDED_RELEASES.iter().any(|release| release.id == id)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    release_id: String,
    trust_model: String,
    stock_os_sha256: String,
    measurement_reference_sha256: String,
    launch_config_sha256: String,
    pre_launch_script_sha256: String,
    container_digests: Vec<String>,
    kms_identity: String,
    workload: WorkloadPolicy,
}

#[derive(Deserialize)]
struct Launch {
    docker_compose_file: String,
    #[serde(default)]
    pre_launch_script: String,
}

#[derive(Deserialize)]
struct Compose {
    services: UniqueServices,
}

#[derive(Deserialize)]
struct Service {
    image: String,
}

struct UniqueServices(BTreeMap<String, Service>);

impl<'de> Deserialize<'de> for UniqueServices {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ServicesVisitor;
        impl<'de> Visitor<'de> for ServicesVisitor {
            type Value = UniqueServices;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("unique, nonempty Compose services")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut services = BTreeMap::new();
                while let Some((name, service)) = map.next_entry::<String, Service>()? {
                    if name.is_empty() || services.insert(name, service).is_some() {
                        return Err(de::Error::custom("duplicate or empty Compose service"));
                    }
                }
                if services.is_empty() {
                    return Err(de::Error::custom("Compose services are empty"));
                }
                Ok(UniqueServices(services))
            }
        }
        deserializer.deserialize_map(ServicesVisitor)
    }
}

fn hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn digest_reference(value: &str) -> Option<String> {
    let (reference, digest) = value.split_once("@sha256:")?;
    if reference.is_empty()
        || !reference.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
        || !hex32(digest)
    {
        return None;
    }
    Some(format!("sha256:{digest}"))
}

fn launch_parts(raw: &[u8]) -> Option<([u8; 32], Vec<String>)> {
    if raw.len() > 256 * 1024 {
        return None;
    }
    let launch: Launch = serde_json::from_slice(raw).ok()?;
    let compose: Compose = serde_json::from_str(&launch.docker_compose_file).ok()?;
    let mut digests = compose
        .services
        .0
        .values()
        .map(|service| digest_reference(&service.image))
        .collect::<Option<Vec<_>>>()?;
    digests.sort_unstable();
    Some((Sha256::hash(launch.pre_launch_script.as_bytes()), digests))
}

/// Approval of a specific Phala-managed stock guest, KMS identity and launch.
/// This type does not claim isolation from Phala administrators or writable
/// runtime state. It cannot be created from server evidence or a local file.
pub struct PhalaTrustedRelease {
    id: String,
    manifest_sha256: [u8; 32],
    launch_sha256: [u8; 32],
    pre_launch_script_sha256: [u8; 32],
    container_digests: Vec<String>,
    workload: WorkloadPolicy,
}

impl PhalaTrustedRelease {
    pub fn selected(policy: &PhalaTrustedPolicy) -> Result<Vec<Self>, SafeError> {
        policy.validate()?;
        policy
            .reviewed_release_ids
            .iter()
            .map(|id| Self::one(id))
            .collect()
    }

    fn one(id: &str) -> Result<Self, SafeError> {
        let embedded = EMBEDDED_RELEASES
            .iter()
            .find(|entry| entry.id == id)
            .ok_or_else(|| {
                SafeError::new(
                    ErrorCode::UnknownRelease,
                    "No packaged Phala-trusting release is selected.",
                )
            })?;
        Self::from_embedded(embedded)
    }

    fn from_embedded(embedded: &EmbeddedRelease) -> Result<Self, SafeError> {
        if Sha256::hash(embedded.manifest_json) != embedded.manifest_sha256 {
            return Err(invalid_policy());
        }
        let manifest: Manifest =
            serde_json::from_slice(embedded.manifest_json).map_err(|_| invalid_policy())?;
        // The reference is the canonical serialized policy packaged in this
        // client, never a digest asserted by the peer or learned from a quote.
        let measurement_reference =
            serde_json::to_vec(&manifest.workload).map_err(|_| invalid_policy())?;
        if manifest.schema_version != 1
            || manifest.release_id != embedded.id
            || manifest.trust_model != "phala-managed-guest-kms-runtime"
            || !hex32(&manifest.stock_os_sha256)
            || !hex32(&manifest.measurement_reference_sha256)
            || manifest.measurement_reference_sha256
                != hex::encode(Sha256::hash(&measurement_reference))
            || !hex32(&manifest.launch_config_sha256)
            || !hex32(&manifest.pre_launch_script_sha256)
            || manifest.kms_identity.is_empty()
            || manifest.workload.validate().is_err()
            || hex::encode(manifest.workload.os_image_hash) != manifest.stock_os_sha256
            || hex::encode(manifest.workload.compose_hash) != manifest.launch_config_sha256
            || manifest.workload.key_provider.id != manifest.kms_identity
            || manifest.container_digests.is_empty()
            || !manifest
                .container_digests
                .iter()
                .all(|digest| digest.strip_prefix("sha256:").is_some_and(hex32))
        {
            return Err(invalid_policy());
        }
        let mut script_hash = [0u8; 32];
        hex::decode_to_slice(&manifest.pre_launch_script_sha256, &mut script_hash)
            .map_err(|_| invalid_policy())?;
        let mut expected = manifest.container_digests;
        expected.sort_unstable();
        Ok(Self {
            id: embedded.id.to_owned(),
            manifest_sha256: embedded.manifest_sha256,
            launch_sha256: manifest.workload.compose_hash,
            pre_launch_script_sha256: script_hash,
            container_digests: expected,
            workload: manifest.workload,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }
    pub fn workload(&self) -> &WorkloadPolicy {
        &self.workload
    }

    pub fn matches_launch_config(&self, raw: &[u8]) -> bool {
        if Sha256::hash(raw) != self.launch_sha256 {
            return false;
        }
        launch_parts(raw).is_some_and(|(script, images)| {
            script == self.pre_launch_script_sha256 && images == self.container_digests
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_selection_cannot_add_releases() {
        let mut policy = PhalaTrustedPolicy::default();
        assert!(PhalaTrustedRelease::selected(&policy).unwrap().is_empty());
        policy.phala_trusted_enabled = true;
        policy.reviewed_release_ids.push("SYNTHETIC".into());
        assert!(PhalaTrustedRelease::selected(&policy).is_err());
    }

    #[test]
    fn packaged_release_matches_only_the_reviewed_launch() {
        let mut policy = PhalaTrustedPolicy::default();
        policy.phala_trusted_enabled = true;
        policy
            .reviewed_release_ids
            .push("phala-prod9-testnet-20261001-1".into());
        let selected = PhalaTrustedRelease::selected(&policy).unwrap();
        assert_eq!(selected.len(), 1);
        let release = &selected[0];
        let launch = include_bytes!("../../../deploy/phala/releases/2026-10-01/app-compose.json");
        assert!(release.matches_launch_config(launch));
        let mut changed = launch.to_vec();
        changed[0] ^= 1;
        assert!(!release.matches_launch_config(&changed));
        assert!(!release.matches_launch_config(b"{}"));
    }

    #[test]
    fn block_context_release_rejects_previous_launch() {
        let mut policy = PhalaTrustedPolicy::default();
        policy.phala_trusted_enabled = true;
        policy
            .reviewed_release_ids
            .push("phala-prod9-testnet-block-context-20261001-2".into());
        let selected = PhalaTrustedRelease::selected(&policy).unwrap();
        assert_eq!(selected.len(), 1);
        let release = &selected[0];
        let current = include_bytes!(
            "../../../deploy/phala/releases/2026-10-01/block-context-app-compose.json"
        );
        let previous = include_bytes!("../../../deploy/phala/releases/2026-10-01/app-compose.json");
        assert!(release.matches_launch_config(current));
        assert!(!release.matches_launch_config(previous));
    }

    #[test]
    fn blockcount_release_rejects_previous_launch() {
        let policy = PhalaTrustedPolicy {
            phala_trusted_enabled: true,
            reviewed_release_ids: vec!["phala-prod9-testnet-blockcount-20261001-4".into()],
            ..PhalaTrustedPolicy::default()
        };
        let selected = PhalaTrustedRelease::selected(&policy).unwrap();
        let release = &selected[0];
        let current =
            include_bytes!("../../../deploy/phala/releases/2026-10-01/blockcount-app-compose.json");
        let previous =
            include_bytes!("../../../deploy/phala/releases/2026-10-01/ticketed-app-compose.json");
        assert!(release.matches_launch_config(current));
        assert!(!release.matches_launch_config(previous));
    }

    #[test]
    fn launch_parser_rejects_mutable_images_and_duplicate_services() {
        let image = format!("repo@sha256:{}", "a".repeat(64));
        let compose = format!(
            "{{\"services\":{{\"node\":{{\"image\":\"{image}\"}},\"node\":{{\"image\":\"{image}\"}}}}}}"
        );
        let launch = serde_json::json!({"docker_compose_file":compose});
        assert!(launch_parts(&serde_json::to_vec(&launch).unwrap()).is_none());
        let mutable = serde_json::json!({"docker_compose_file":"{\"services\":{\"node\":{\"image\":\"repo:latest\"}}}"});
        assert!(launch_parts(&serde_json::to_vec(&mutable).unwrap()).is_none());
    }
}
