//! Opt-in conformance against the capability-protected native bridge. The
//! upstream RPCs still use WalletReader's Tor/attestation/ticket path. Inputs
//! are public testnet fixtures; this test never loads a wallet key.
//! The node must have reached both pinned NU7 fixture blocks. Twenty free
//! admission tickets cover the twenty upstream reads in a completed run;
//! interrupted or failed runs can also consume tickets.

use futures_util::stream;
use prost::Message;
use std::{error::Error, net::SocketAddr, path::PathBuf};
use zrpc_protocol::PREVIEW_TESTNET_ADDRESS;
use zrpc_wallet_read::{NodeReadContext, wire};
use zrpc_wallet_sdk::bridge::LocalWalletAdapter;

#[tokio::test]
#[ignore = "requires a live approved bridge, three tickets and a local resource controller"]
async fn verified_bridge_measures_slow_consumer_and_cancellation() -> Result<(), Box<dyn Error>> {
    use tokio::{io::AsyncReadExt, net::UnixListener};
    use zrpc_payments::PrivateDirectory;

    let bind: SocketAddr = std::env::var("ZRPC_LIVE_WALLET_BRIDGE")?.parse()?;
    let capability = PathBuf::from(std::env::var("ZRPC_LIVE_WALLET_CAPABILITY_DIR")?);
    let control = PathBuf::from(std::env::var("ZRPC_LIVE_RESOURCE_CONTROL_DIR")?);
    PrivateDirectory::open(&control)?;
    let socket = control.join("slow-consumer.sock");
    let mut adapter = LocalWalletAdapter::connect(bind, &capability).await?;
    let tip = adapter
        .client()
        .get_latest_block(wire::ChainSpec {})
        .await?
        .into_inner();
    let fixtures = [
        wire::CompactBlock::decode(
            include_bytes!("../../../tests/fixtures/zcash/testnet-compact-4465070.pb").as_slice(),
        )?,
        wire::CompactBlock::decode(
            include_bytes!("../../../tests/fixtures/zcash/testnet-compact-4465071.pb").as_slice(),
        )?,
    ];
    assert!(tip.height > fixtures[1].height);
    let started = std::time::Instant::now();
    let mut blocks = adapter
        .client()
        .get_block_range(range(fixtures[0].height, tip.height))
        .await?
        .into_inner();
    let mut bytes = 0_usize;
    for expected in &fixtures {
        let block = blocks
            .message()
            .await?
            .ok_or("range omitted a pinned block")?;
        assert_eq!(&block, expected);
        bytes = bytes
            .checked_add(block.encoded_len())
            .ok_or("payload size overflow")?;
    }
    let elapsed = started.elapsed();
    // Consumption stays paused until the controller has collected the guest
    // and bridge memory samples. No invented sleep, deadline or rate target.
    // Creating the socket now tells the controller both fixture blocks have
    // arrived and the consumer is paused, rather than still opening its RPC.
    let listener = UnixListener::bind(&socket)?;
    let (mut controller, _) = listener.accept().await?;
    let mut release = [0_u8; 1];
    controller.read_exact(&mut release).await?;
    assert_eq!(release, [b'c']);
    let memory = std::fs::read_to_string("/proc/self/status")?;
    let high_water = memory
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .ok_or("kernel memory high-water observation unavailable")?;
    drop(blocks);
    let cancelled = std::time::Instant::now();
    let next = adapter
        .client()
        .get_latest_block(wire::ChainSpec {})
        .await?
        .into_inner();
    assert!(next.height >= fixtures[1].height);
    assert_eq!(next.hash.len(), 32);
    // Protobuf payload/time is application throughput through Tor, including
    // attestation startup; it is not a saturated Tor capacity measurement.
    eprintln!(
        "resource_observation delivered_blocks={} protobuf_bytes={} open_to_items_elapsed_ns={} client_memory_high_water={} cancel_to_fresh_read_elapsed_ns={} partial_range_complete=false",
        fixtures.len(),
        bytes,
        elapsed.as_nanos(),
        high_water,
        cancelled.elapsed().as_nanos()
    );
    drop(listener);
    std::fs::remove_file(socket)?;
    Ok(())
}

fn selected(height: u64) -> wire::BlockId {
    wire::BlockId {
        height,
        hash: vec![],
    }
}

fn range(start: u64, end: u64) -> wire::BlockRange {
    wire::BlockRange {
        start: Some(selected(start)),
        end: Some(selected(end)),
    }
}

#[tokio::test]
#[ignore = "requires a context-capable live approved testnet bridge and three free tickets"]
async fn verified_bridge_preserves_context_on_unary_and_empty_streams() -> Result<(), Box<dyn Error>>
{
    let bind: SocketAddr = std::env::var("ZRPC_LIVE_WALLET_BRIDGE")?.parse()?;
    let capability = PathBuf::from(std::env::var("ZRPC_LIVE_WALLET_CAPABILITY_DIR")?);
    let mut adapter = LocalWalletAdapter::connect(bind, &capability).await?;
    let info = adapter.client().get_lightd_info(wire::Empty {}).await?;
    let context = NodeReadContext::read_metadata(info.metadata())?
        .ok_or("approved image omitted node context")?;
    assert!(context.height > 0);
    let balance = adapter
        .client()
        .get_taddress_balance(wire::AddressList {
            addresses: vec![PREVIEW_TESTNET_ADDRESS.to_owned()],
        })
        .await?;
    assert!(NodeReadContext::read_metadata(balance.metadata())?.is_some());
    assert!(balance.get_ref().value_zat >= 0);
    let history = adapter
        .client()
        .get_taddress_transactions(wire::TransparentAddressBlockFilter {
            address: PREVIEW_TESTNET_ADDRESS.to_owned(),
            range: Some(range(481_680, 481_710)),
        })
        .await?;
    assert!(NodeReadContext::read_metadata(history.metadata())?.is_some());
    let mut history = history.into_inner();
    assert!(history.message().await?.is_none());
    eprintln!(
        "node context preserved for info, balance and empty history; no atomic snapshot claimed"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a live approved testnet bridge and four free admission tickets"]
async fn verified_bridge_recovers_after_a_dropped_range_with_concurrent_readers()
-> Result<(), Box<dyn Error>> {
    let bind: SocketAddr = std::env::var("ZRPC_LIVE_WALLET_BRIDGE")?.parse()?;
    let capability = PathBuf::from(std::env::var("ZRPC_LIVE_WALLET_CAPABILITY_DIR")?);
    let mut first = LocalWalletAdapter::connect(bind, &capability).await?;
    let mut second = LocalWalletAdapter::connect(bind, &capability).await?;
    // The bridge deliberately serializes upstream reads. Concurrent local
    // callers must still receive separately verified, ticketed responses.
    let (first_tip, second_tip) = tokio::try_join!(
        first.client().get_latest_block(wire::ChainSpec {}),
        second.client().get_latest_block(wire::ChainSpec {}),
    )?;
    let first_tip = first_tip.into_inner();
    let second_tip = second_tip.into_inner();
    assert_eq!(first_tip.hash.len(), 32);
    assert_eq!(second_tip.hash.len(), 32);
    eprintln!("concurrent local tip reads complete");

    let fixture = wire::CompactBlock::decode(
        include_bytes!("../../../tests/fixtures/zcash/testnet-compact-4465070.pb").as_slice(),
    )?;
    let end = first_tip.height.min(second_tip.height);
    assert!(
        end > fixture.height,
        "node must pass the pinned NU7 fixture"
    );
    // Request the remaining observed chain, consume just its first validated
    // block, then abandon the result. No partial-range success is reported.
    let mut blocks = first
        .client()
        .get_block_range(range(fixture.height, end))
        .await?
        .into_inner();
    assert_eq!(blocks.message().await?.as_ref(), Some(&fixture));
    drop(blocks);

    let next = second
        .client()
        .get_latest_block(wire::ChainSpec {})
        .await?
        .into_inner();
    assert_eq!(next.hash.len(), 32);
    assert!(next.height >= fixture.height);
    eprintln!("partial range dropped; subsequent verified tip read complete");
    Ok(())
}

#[tokio::test]
#[ignore = "requires a live approved testnet bridge with tickets for every read family"]
async fn verified_bridge_serves_all_pinned_wallet_read_methods() -> Result<(), Box<dyn Error>> {
    let bind: SocketAddr = std::env::var("ZRPC_LIVE_WALLET_BRIDGE")?.parse()?;
    let capability = PathBuf::from(std::env::var("ZRPC_LIVE_WALLET_CAPABILITY_DIR")?);
    let mut adapter = LocalWalletAdapter::connect(bind, &capability).await?;
    let client = adapter.client();
    let fixture_a = wire::CompactBlock::decode(
        include_bytes!("../../../tests/fixtures/zcash/testnet-compact-4465070.pb").as_slice(),
    )?;
    let fixture_b = wire::CompactBlock::decode(
        include_bytes!("../../../tests/fixtures/zcash/testnet-compact-4465071.pb").as_slice(),
    )?;

    let info = client.get_lightd_info(wire::Empty {}).await?.into_inner();
    assert_eq!(info.chain_name, "test");
    assert!(info.taddr_support);
    eprintln!("GetLightdInfo complete node_height={}", info.block_height);
    assert!(
        info.block_height >= fixture_b.height,
        "node height {} has not reached pinned fixture height {}",
        info.block_height,
        fixture_b.height
    );

    let tip = client
        .get_latest_block(wire::ChainSpec {})
        .await?
        .into_inner();
    assert!(tip.height >= fixture_b.height);
    assert_eq!(tip.hash.len(), 32);
    eprintln!("GetLatestBlock complete node_height={}", tip.height);

    let block = client
        .get_block(selected(fixture_a.height))
        .await?
        .into_inner();
    assert_eq!(block, fixture_a);
    eprintln!("GetBlock complete pinned_public_fixture_match=true");
    let nullifiers = client
        .get_block_nullifiers(selected(fixture_a.height))
        .await?
        .into_inner();
    assert_eq!(nullifiers.height, fixture_a.height);
    assert_eq!(nullifiers.hash, fixture_a.hash);
    eprintln!("GetBlockNullifiers complete");

    let mut blocks = client
        .get_block_range(range(fixture_a.height, fixture_b.height))
        .await?
        .into_inner();
    assert_eq!(blocks.message().await?.as_ref(), Some(&fixture_a));
    assert_eq!(blocks.message().await?.as_ref(), Some(&fixture_b));
    assert!(blocks.message().await?.is_none());
    eprintln!("GetBlockRange complete pinned_public_fixture_match=true");
    let mut blocks = client
        .get_block_range_nullifiers(range(fixture_a.height, fixture_b.height))
        .await?
        .into_inner();
    assert_eq!(blocks.message().await?.as_ref(), Some(&nullifiers));
    let second = blocks
        .message()
        .await?
        .ok_or("nullifier range incomplete")?;
    assert_eq!(second.height, fixture_b.height);
    assert_eq!(second.hash, fixture_b.hash);
    assert_eq!(second.prev_hash, fixture_a.hash);
    assert!(blocks.message().await?.is_none());
    eprintln!("GetBlockRangeNullifiers complete");

    let tree = client
        .get_tree_state(selected(fixture_a.height))
        .await?
        .into_inner();
    assert_eq!(tree.network, "test");
    assert_eq!(tree.height, fixture_a.height);
    let mut display_hash = fixture_a.hash.clone();
    display_hash.reverse();
    assert_eq!(tree.hash, hex::encode(display_hash));
    assert!(!tree.sapling_tree.is_empty());
    assert!(!tree.orchard_tree.is_empty());
    assert!(!tree.ironwood_tree.is_empty());
    eprintln!("GetTreeState complete Sapling_Orchard_Ironwood=true");
    let latest = client
        .get_latest_tree_state(wire::Empty {})
        .await?
        .into_inner();
    assert_eq!(latest.network, "test");
    assert!(latest.height >= fixture_b.height);
    eprintln!("GetLatestTreeState complete");
    for protocol in [
        wire::ShieldedProtocol::Sapling,
        wire::ShieldedProtocol::Orchard,
        wire::ShieldedProtocol::Ironwood,
    ] {
        let mut roots = client
            .get_subtree_roots(wire::GetSubtreeRootsArg {
                start_index: 0,
                shielded_protocol: protocol.into(),
                max_entries: 1,
            })
            .await?
            .into_inner();
        let root = roots.message().await?;
        if let Some(root) = &root {
            assert_eq!(root.root_hash.len(), 32);
            assert_eq!(root.completing_block_hash.len(), 32);
        }
        assert!(roots.message().await?.is_none());
        eprintln!(
            "GetSubtreeRoots complete pool={protocol:?} entries={}",
            usize::from(root.is_some())
        );
    }

    let txid = fixture_a
        .vtx
        .first()
        .ok_or("public fixture has no transaction")?
        .hash
        .clone();
    let transaction = client
        .get_transaction(wire::TxFilter {
            block: None,
            index: 0,
            hash: txid,
        })
        .await?
        .into_inner();
    assert_eq!(transaction.height, fixture_a.height);
    assert!(!transaction.data.is_empty());
    eprintln!("GetTransaction complete");

    let filter = wire::TransparentAddressBlockFilter {
        address: PREVIEW_TESTNET_ADDRESS.to_owned(),
        range: Some(range(481_680, 481_710)),
    };
    let mut history = client
        .get_taddress_transactions(filter.clone())
        .await?
        .into_inner();
    let mut transactions = Vec::new();
    while let Some(tx) = history.message().await? {
        assert!((481_680..=481_710).contains(&tx.height));
        assert!(!tx.data.is_empty());
        transactions.push(tx);
    }
    // This fixed synthetic address has no history in the selected range.
    assert!(transactions.is_empty());
    eprintln!(
        "GetTaddressTransactions complete entries={}",
        transactions.len()
    );
    let mut alias = client.get_taddress_txids(filter).await?.into_inner();
    for expected in transactions {
        assert_eq!(alias.message().await?, Some(expected));
    }
    assert!(alias.message().await?.is_none());
    eprintln!("GetTaddressTxids complete compatibility_alias_match=true");

    let balance = client
        .get_taddress_balance(wire::AddressList {
            addresses: vec![PREVIEW_TESTNET_ADDRESS.to_owned()],
        })
        .await?
        .into_inner();
    assert!(balance.value_zat >= 0);
    eprintln!("GetTaddressBalance complete");
    let balance = client
        .get_taddress_balance_stream(stream::iter([wire::Address {
            address: PREVIEW_TESTNET_ADDRESS.to_owned(),
        }]))
        .await?
        .into_inner();
    assert!(balance.value_zat >= 0);
    eprintln!("GetTaddressBalanceStream complete");
    let request = wire::GetAddressUtxosArg {
        addresses: vec![PREVIEW_TESTNET_ADDRESS.to_owned()],
        start_height: 0,
        max_entries: 0,
    };
    let utxos = client
        .get_address_utxos(request.clone())
        .await?
        .into_inner();
    for utxo in utxos.address_utxos {
        assert!(utxo.value_zat >= 0);
        assert_eq!(utxo.txid.len(), 32);
    }
    eprintln!("GetAddressUtxos complete");
    let mut utxos = client.get_address_utxos_stream(request).await?.into_inner();
    while let Some(utxo) = utxos.message().await? {
        assert!(utxo.value_zat >= 0);
        assert_eq!(utxo.txid.len(), 32);
    }
    eprintln!("GetAddressUtxosStream complete");

    let mut mempool = client
        .get_mempool_tx(wire::Exclude { txid: vec![] })
        .await?
        .into_inner();
    while let Some(tx) = mempool.message().await? {
        assert_eq!(tx.hash.len(), 32);
    }
    eprintln!("GetMempoolTx complete");
    let mut mempool = client
        .get_mempool_stream(wire::Empty {})
        .await?
        .into_inner();
    while let Some(tx) = mempool.message().await? {
        assert_eq!(
            tx.height, 0,
            "a pending transaction must retain the protocol sentinel"
        );
        assert!(!tx.data.is_empty());
    }
    eprintln!("GetMempoolStream complete");
    Ok(())
}
