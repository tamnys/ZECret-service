//! A node tip observation accompanying a single wallet read. This is not an
//! atomic snapshot of the response, a commitment to its contents, or evidence
//! of global chain freshness. The node may advance or reorganize after it is
//! observed, including while a streaming response is still being consumed.

use crate::wire;
use tonic::{
    Status,
    metadata::{MetadataMap, MetadataValue},
};

const SEMANTICS_KEY: &str = "x-zrpc-node-context";
const HEIGHT_KEY: &str = "x-zrpc-node-height";
const HASH_KEY: &str = "x-zrpc-node-hash-bin";
const SEMANTICS: &str = "tip-before-read-v1";

/// The validated loopback node tip observed immediately before dispatching
/// the associated backend read. `hash` has the pinned protobuf's internal
/// byte order, not conventional block explorer display order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeReadContext {
    pub height: u32,
    pub hash: [u8; 32],
}

fn invalid_context() -> Status {
    Status::data_loss("Invalid wallet node observation metadata.")
}

impl NodeReadContext {
    pub fn from_block_id(block: &wire::BlockId) -> Result<Self, Status> {
        Ok(Self {
            height: block.height.try_into().map_err(|_| invalid_context())?,
            hash: block
                .hash
                .as_slice()
                .try_into()
                .map_err(|_| invalid_context())?,
        })
    }

    /// Write only the locally produced observation. Existing values for these
    /// keys are removed rather than forwarding upstream or caller metadata.
    pub fn write_metadata(&self, metadata: &mut MetadataMap) -> Result<(), Status> {
        metadata.remove(SEMANTICS_KEY);
        metadata.remove(HEIGHT_KEY);
        metadata.remove_bin(HASH_KEY);
        metadata.insert(SEMANTICS_KEY, MetadataValue::from_static(SEMANTICS));
        metadata.insert(
            HEIGHT_KEY,
            self.height
                .to_string()
                .parse()
                .map_err(|_| invalid_context())?,
        );
        metadata.insert_bin(HASH_KEY, MetadataValue::from_bytes(&self.hash));
        Ok(())
    }

    /// Older approved images may omit the extension entirely. Once any field
    /// appears, all fields must occur exactly once in the supported format.
    pub fn read_metadata(metadata: &MetadataMap) -> Result<Option<Self>, Status> {
        let semantics = metadata.get_all(SEMANTICS_KEY);
        let heights = metadata.get_all(HEIGHT_KEY);
        let hashes = metadata.get_all_bin(HASH_KEY);
        let counts = (
            semantics.iter().count(),
            heights.iter().count(),
            hashes.iter().count(),
        );
        if counts == (0, 0, 0) {
            return Ok(None);
        }
        if counts != (1, 1, 1) {
            return Err(invalid_context());
        }
        if metadata
            .get(SEMANTICS_KEY)
            .and_then(|value| value.to_str().ok())
            != Some(SEMANTICS)
        {
            return Err(invalid_context());
        }
        let text = metadata
            .get(HEIGHT_KEY)
            .ok_or_else(invalid_context)?
            .to_str()
            .map_err(|_| invalid_context())?;
        let height: u32 = text.parse().map_err(|_| invalid_context())?;
        if text != height.to_string() {
            return Err(invalid_context());
        }
        let bytes = metadata
            .get_bin(HASH_KEY)
            .ok_or_else(invalid_context)?
            .to_bytes()
            .map_err(|_| invalid_context())?;
        let hash = bytes.as_ref().try_into().map_err(|_| invalid_context())?;
        Ok(Some(Self { height, hash }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> NodeReadContext {
        NodeReadContext {
            height: 4_465_071,
            hash: std::array::from_fn(|index| index as u8),
        }
    }

    #[test]
    fn metadata_round_trip_preserves_internal_hash_order_and_semantics() {
        let expected = context();
        let mut metadata = MetadataMap::new();
        expected.write_metadata(&mut metadata).unwrap();
        assert_eq!(metadata.get(SEMANTICS_KEY).unwrap(), SEMANTICS);
        assert_eq!(
            NodeReadContext::read_metadata(&metadata).unwrap(),
            Some(expected)
        );
        assert_eq!(
            NodeReadContext::read_metadata(&MetadataMap::new()).unwrap(),
            None
        );
        expected.write_metadata(&mut metadata).unwrap();
        assert_eq!(
            NodeReadContext::read_metadata(&metadata).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn partial_duplicate_and_malformed_metadata_are_rejected() {
        let mut complete = MetadataMap::new();
        context().write_metadata(&mut complete).unwrap();
        for key in [SEMANTICS_KEY, HEIGHT_KEY] {
            let mut partial = complete.clone();
            partial.remove(key);
            assert!(NodeReadContext::read_metadata(&partial).is_err());
            let mut duplicate = complete.clone();
            duplicate.append(key, complete.get(key).unwrap().clone());
            assert!(NodeReadContext::read_metadata(&duplicate).is_err());
        }
        let mut partial = complete.clone();
        partial.remove_bin(HASH_KEY);
        assert!(NodeReadContext::read_metadata(&partial).is_err());
        let mut duplicate = complete.clone();
        duplicate.append_bin(HASH_KEY, complete.get_bin(HASH_KEY).unwrap().clone());
        assert!(NodeReadContext::read_metadata(&duplicate).is_err());
        for value in ["-1", "+1", "01", "4294967296", "1,1", "", " 1"] {
            let mut malformed = complete.clone();
            malformed.insert(HEIGHT_KEY, value.parse().unwrap());
            assert!(NodeReadContext::read_metadata(&malformed).is_err());
        }
        let mut unsupported = complete.clone();
        unsupported.insert(SEMANTICS_KEY, "atomic-snapshot".parse().unwrap());
        assert!(NodeReadContext::read_metadata(&unsupported).is_err());
        for length in [0, 31, 33] {
            let mut malformed = complete.clone();
            malformed.insert_bin(HASH_KEY, MetadataValue::from_bytes(&vec![0; length]));
            assert!(NodeReadContext::read_metadata(&malformed).is_err());
        }
    }

    #[test]
    fn node_block_id_requires_protocol_height_and_exact_hash() {
        let expected = context();
        let mut block = wire::BlockId {
            height: u64::from(expected.height),
            hash: expected.hash.to_vec(),
        };
        assert_eq!(NodeReadContext::from_block_id(&block).unwrap(), expected);
        block.height = u64::from(u32::MAX) + 1;
        assert!(NodeReadContext::from_block_id(&block).is_err());
        block.height = 0;
        block.hash.pop();
        assert!(NodeReadContext::from_block_id(&block).is_err());
    }
}
