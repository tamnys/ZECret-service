//! Opt-in conformance probe for the exact pinned Zebra lightwallet service.
//! This uses a local public testnet node and no attestation or private wallet data.

use futures_util::StreamExt;
use std::{
    error::Error,
    net::SocketAddr,
    time::{Duration, Instant},
};
use tonic::Request;
use wire::compact_tx_streamer_server::CompactTxStreamer;
use zrpc_protocol::MAX_CONNECTION_LIFETIME_SECONDS;
use zrpc_protocol::PREVIEW_TESTNET_ADDRESS;
use zrpc_wallet_read::{backend::ZebraReadOnly, wire};

#[tokio::test]
#[ignore = "requires a native local Zebra v6.4.2 testnet lightwallet endpoint and observed range"]
async fn pinned_zebra_completes_observed_range_within_session_lifetime()
-> Result<(), Box<dyn Error>> {
    let address: SocketAddr = std::env::var("ZRPC_LIVE_ZEBRA_LIGHTWALLETD")?.parse()?;
    let start: u32 = std::env::var("ZRPC_LIVE_ZEBRA_RANGE_START")?.parse()?;
    let end: u32 = std::env::var("ZRPC_LIVE_ZEBRA_RANGE_END")?.parse()?;
    if start == 0 || start > end {
        return Err("range must be ascending and start above genesis".into());
    }
    let started = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(MAX_CONNECTION_LIFETIME_SECONDS),
        async move {
            let backend = ZebraReadOnly::new(address)?;
            let mut blocks = backend
                .get_block_range(Request::new(wire::BlockRange {
                    start: Some(wire::BlockId {
                        height: u64::from(start),
                        hash: vec![],
                    }),
                    end: Some(wire::BlockId {
                        height: u64::from(end),
                        hash: vec![],
                    }),
                }))
                .await?
                .into_inner();
            let mut expected = u64::from(start);
            while let Some(block) = blocks.next().await.transpose()? {
                assert_eq!(block.height, expected);
                eprintln!(
                    "public block height={} elapsed_ms={}",
                    block.height,
                    started.elapsed().as_millis()
                );
                expected += 1;
            }
            assert_eq!(expected, u64::from(end) + 1);
            Ok::<(), Box<dyn Error>>(())
        },
    )
    .await??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a native local Zebra v6.4.2 testnet lightwallet endpoint"]
async fn pinned_zebra_serves_wallet_read_families() -> Result<(), Box<dyn Error>> {
    let address: SocketAddr = std::env::var("ZRPC_LIVE_ZEBRA_LIGHTWALLETD")?.parse()?;
    let backend = ZebraReadOnly::new(address)?;
    let info = backend
        .get_lightd_info(Request::new(wire::Empty {}))
        .await?
        .into_inner();
    assert_eq!(info.chain_name, "test");
    assert!(info.taddr_support);

    let tip = backend
        .get_latest_block(Request::new(wire::ChainSpec {}))
        .await?
        .into_inner();
    assert!(tip.height > info.sapling_activation_height);
    assert_eq!(tip.hash.len(), 32);
    let selected = wire::BlockId {
        height: tip.height,
        hash: vec![],
    };
    let block = backend
        .get_block(Request::new(selected.clone()))
        .await?
        .into_inner();
    assert_eq!(block.height, tip.height);
    assert_eq!(block.hash, tip.hash);
    assert_eq!(block.prev_hash.len(), 32);
    assert!(block.chain_metadata.is_some());
    let nullifiers = backend
        .get_block_nullifiers(Request::new(selected.clone()))
        .await?
        .into_inner();
    assert_eq!(nullifiers.height, block.height);
    assert_eq!(nullifiers.hash, block.hash);
    if let Some(transaction) = block.vtx.first() {
        let full = backend
            .get_transaction(Request::new(wire::TxFilter {
                block: None,
                index: 0,
                hash: transaction.hash.clone(),
            }))
            .await?
            .into_inner();
        assert!(!full.data.is_empty());
        assert_eq!(full.height, block.height);
    }

    let tree = backend
        .get_tree_state(Request::new(selected.clone()))
        .await?
        .into_inner();
    assert_eq!(tree.network, "test");
    assert_eq!(tree.height, tip.height);
    assert_eq!(tree.hash.len(), 64);
    assert!(!tree.sapling_tree.is_empty());
    assert!(!tree.orchard_tree.is_empty());
    let latest_tree = backend
        .get_latest_tree_state(Request::new(wire::Empty {}))
        .await?
        .into_inner();
    assert!(latest_tree.height >= tree.height);

    let mut roots = backend
        .get_subtree_roots(Request::new(wire::GetSubtreeRootsArg {
            start_index: 0,
            shielded_protocol: wire::ShieldedProtocol::Sapling.into(),
            max_entries: 1,
        }))
        .await?
        .into_inner();
    let first_root = roots
        .next()
        .await
        .transpose()?
        .ok_or("missing Sapling subtree root")?;
    assert_eq!(first_root.root_hash.len(), 32);
    assert!(roots.next().await.transpose()?.is_none());

    let start = tip.height.checked_sub(1).ok_or("tip height unavailable")?;
    let mut blocks = backend
        .get_block_range(Request::new(wire::BlockRange {
            start: Some(wire::BlockId {
                height: start,
                hash: vec![],
            }),
            end: Some(selected),
        }))
        .await?
        .into_inner();
    let first = blocks
        .next()
        .await
        .transpose()?
        .ok_or("first compact block missing")?;
    let second = blocks
        .next()
        .await
        .transpose()?
        .ok_or("second compact block missing")?;
    assert_eq!(first.height, start);
    assert_eq!(second.height, tip.height);
    assert_eq!(second.prev_hash, first.hash);
    assert!(blocks.next().await.transpose()?.is_none());
    let mut nullifier_range = backend
        .get_block_range_nullifiers(Request::new(wire::BlockRange {
            start: Some(wire::BlockId {
                height: start,
                hash: vec![],
            }),
            end: Some(wire::BlockId {
                height: tip.height,
                hash: vec![],
            }),
        }))
        .await?
        .into_inner();
    for expected_height in [start, tip.height] {
        assert_eq!(
            nullifier_range.next().await.transpose()?.unwrap().height,
            expected_height
        );
    }
    assert!(nullifier_range.next().await.transpose()?.is_none());

    let addresses = vec![PREVIEW_TESTNET_ADDRESS.to_owned()];
    let filter = wire::TransparentAddressBlockFilter {
        address: addresses[0].clone(),
        range: Some(wire::BlockRange {
            start: Some(wire::BlockId {
                height: start,
                hash: vec![],
            }),
            end: Some(wire::BlockId {
                height: tip.height,
                hash: vec![],
            }),
        }),
    };
    let mut history = backend
        .get_taddress_transactions(Request::new(filter.clone()))
        .await?
        .into_inner();
    let mut alias = backend
        .get_taddress_txids(Request::new(filter))
        .await?
        .into_inner();
    assert!(history.next().await.transpose()?.is_none());
    assert!(alias.next().await.transpose()?.is_none());
    let balance = backend
        .get_taddress_balance(Request::new(wire::AddressList {
            addresses: addresses.clone(),
        }))
        .await?
        .into_inner();
    assert!(balance.value_zat >= 0);
    let utxos = backend
        .get_address_utxos(Request::new(wire::GetAddressUtxosArg {
            addresses,
            start_height: 0,
            max_entries: 0,
        }))
        .await?
        .into_inner();
    assert!(utxos.address_utxos.iter().all(|utxo| utxo.value_zat >= 0));
    let mut streamed_utxos = backend
        .get_address_utxos_stream(Request::new(wire::GetAddressUtxosArg {
            addresses: vec![PREVIEW_TESTNET_ADDRESS.to_owned()],
            start_height: 0,
            max_entries: 0,
        }))
        .await?
        .into_inner();
    assert!(streamed_utxos.next().await.transpose()?.is_none());
    // Zebra keeps the mempool inactive until it catches up to the network.
    // A staged local snapshot may lag the tip, so this probe does not claim
    // pending-transaction availability while the node is still syncing.
    if info.block_height >= info.estimated_height {
        let mut mempool = backend
            .get_mempool_tx(Request::new(wire::Exclude { txid: vec![] }))
            .await?
            .into_inner();
        if let Some(transaction) = mempool.next().await.transpose()? {
            assert_eq!(transaction.hash.len(), 32);
        }
    }
    Ok(())
}
