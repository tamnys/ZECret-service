//! Public testnet CompactBlock responses exercise the wallet wire validator.
//! These fixtures are untrusted chain data, never attestation or release evidence.

use prost::Message;
use zrpc_wallet_read::{RangeContinuity, validate_compact_block, wire};

const BLOCK_4465070: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/zcash/testnet-compact-4465070.pb"
));
const BLOCK_4465071: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/zcash/testnet-compact-4465071.pb"
));

fn blocks() -> [wire::CompactBlock; 2] {
    [
        wire::CompactBlock::decode(BLOCK_4465070).expect("pinned block 4465070"),
        wire::CompactBlock::decode(BLOCK_4465071).expect("pinned block 4465071"),
    ]
}

#[test]
fn public_nu7_compact_blocks_have_ironwood_actions_and_link() {
    let [first, second] = blocks();
    assert_eq!(first.height, 4_465_070);
    assert_eq!(second.height, 4_465_071);
    assert_eq!(first.hash, second.prev_hash);
    assert_eq!(first.hash.len(), 32);
    assert_eq!(second.hash.len(), 32);
    assert_eq!(
        hex::encode(first.hash.iter().rev().copied().collect::<Vec<_>>()),
        "0000c3fbeefb33b0813327abf05e4adbd84ab63cb39ac6c12f4b7b327c2bae93"
    );
    assert_eq!(
        hex::encode(second.hash.iter().rev().copied().collect::<Vec<_>>()),
        "000001c705c1aa6035af6d97feaf96fafa35e219bfa4e51017a1a0722a962736"
    );
    assert_eq!(first.vtx.len(), 1);
    assert_eq!(second.vtx.len(), 2);
    assert_eq!(
        second
            .vtx
            .iter()
            .map(|tx| tx.ironwood_actions.len())
            .sum::<usize>(),
        20
    );
    assert_eq!(
        second
            .chain_metadata
            .as_ref()
            .expect("chain metadata")
            .ironwood_commitment_tree_size,
        480_942
    );
    validate_compact_block(&first).unwrap();
    validate_compact_block(&second).unwrap();

    let mut continuity = RangeContinuity::new(4_465_070, 4_465_071, None);
    continuity.observe(&first).unwrap();
    continuity.observe(&second).unwrap();
    continuity.finish().unwrap();
}

#[test]
fn public_nu7_range_rejects_missing_or_changed_blocks() {
    let [first, second] = blocks();
    let mut incomplete = RangeContinuity::new(4_465_070, 4_465_071, None);
    incomplete.observe(&first).unwrap();
    assert!(incomplete.finish().is_err());

    let mut changed = second.clone();
    changed.prev_hash[0] ^= 1;
    let mut continuity = RangeContinuity::new(4_465_070, 4_465_071, None);
    continuity.observe(&first).unwrap();
    assert!(continuity.observe(&changed).is_err());

    let mut malformed = second;
    malformed.vtx[0].ironwood_actions[0].ciphertext.pop();
    assert!(validate_compact_block(&malformed).is_err());
}
