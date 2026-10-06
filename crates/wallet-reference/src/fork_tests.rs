//! Synthetic fork timing fixtures; no attestation or live-chain evidence.

use super::*;
use crate::cache::{CacheError, SqliteBlockCache};
use async_trait::async_trait;
use prost::Message;
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tonic::{Request, Response, Status, codegen::tokio_stream::Stream, transport::Server};
use zcash_client_backend::{
    data_api::{
        Account, OutputStatusFilter, TransactionDataRequest, TransactionStatusFilter,
        chain::{BlockSource, ChainState, error::Error as ChainError},
        scanning::ScanRange,
        testing::{
            AddressType, FakeCompactOutput, TestBuilder,
            pool::{ShieldedPoolTester, dsl::TestDsl},
            sapling::SaplingPoolTester,
        },
        wallet::ConfirmationsPolicy,
    },
    proto::service,
};
use zcash_client_sqlite::testing::db::TestDbFactory;
use zcash_keys::encoding::encode_transparent_address_p;
use zcash_primitives::{block::BlockHash, merkle_tree::write_commitment_tree};
use zcash_protocol::{
    TxId,
    consensus::{NetworkUpgrade, Parameters},
    local_consensus::LocalNetwork,
    value::Zatoshis,
};
use zrpc_wallet_sdk::bridge::wire::{
    self,
    compact_tx_streamer_server::{CompactTxStreamer, CompactTxStreamerServer},
};

type Replies<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;
fn replies<T: Send + 'static>(items: Vec<Result<T, Status>>) -> Response<Replies<T>> {
    Response::new(Box::pin(tonic::codegen::tokio_stream::iter(items)))
}
fn transcode<T: Message, U: Message + Default>(value: T) -> U {
    U::decode(value.encode_to_vec().as_slice()).unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Boundary {
    Tree,
    Blocks,
    Utxos,
    History,
}

#[derive(Clone)]
struct Branch {
    blocks: BTreeMap<u64, wire::CompactBlock>,
    trees: BTreeMap<u64, wire::TreeState>,
    utxo: wire::GetAddressUtxosReply,
}
struct State {
    branch: Branch,
    replacement: Branch,
    advertised_tip: u64,
    boundary: Option<Boundary>,
    switched: bool,
    unavailable: Vec<Vec<u8>>,
    status_reads: usize,
}
impl State {
    fn switch_at(&mut self, boundary: Boundary) -> bool {
        if self.boundary == Some(boundary) {
            self.branch = self.replacement.clone();
            self.boundary = None;
            self.switched = true;
            true
        } else {
            false
        }
    }
}
#[derive(Clone)]
struct FixtureService(Arc<Mutex<State>>);

// Generate only the unused RPC stubs; the tested handlers below retain the
// pinned generated server's protobuf framing and stream error semantics.
macro_rules! fixture_service {
    ($($unary:ident($input:ty) -> $output:ty;)* @streams
     $($method:ident($request:ty) -> $associated:ident<$item:ty>;)*) => {
        #[tonic::async_trait]
        impl CompactTxStreamer for FixtureService {
            $(async fn $unary(&self, _: Request<$input>) -> Result<Response<$output>, Status> {
                Err(Status::unimplemented("Synthetic fixture method unavailable."))
            })*
            $(type $associated = Replies<$item>;
              async fn $method(&self, _: Request<$request>) -> Result<Response<Self::$associated>, Status> {
                  Err(Status::unimplemented("Synthetic fixture method unavailable."))
              })*
            async fn get_latest_block(&self, _: Request<wire::ChainSpec>) -> Result<Response<wire::BlockId>, Status> {
                let state = self.0.lock().unwrap();
                let block = &state.branch.blocks[&state.advertised_tip];
                Ok(Response::new(wire::BlockId { height: block.height, hash: block.hash.clone() }))
            }
            async fn get_transaction(&self, request: Request<wire::TxFilter>) -> Result<Response<wire::RawTransaction>, Status> {
                let request = request.into_inner();
                assert!(request.block.is_none());
                assert_eq!(request.index, 0);
                let mut state = self.0.lock().unwrap();
                assert!(state.unavailable.contains(&request.hash));
                state.status_reads += 1;
                // These old-branch IDs are unavailable on the replacement
                // node. Do not fabricate raw transactions for fake compact IDs.
                Err(Status::not_found("Synthetic old-branch transaction unavailable."))
            }
            async fn get_block(&self, request: Request<wire::BlockId>) -> Result<Response<wire::CompactBlock>, Status> {
                let state = self.0.lock().unwrap();
                let height = request.into_inner().height;
                // The retained birthday frontier precedes the generated range
                // and has no wallet blocks-table row. Serve its public anchor
                // too so the real adapter verifies a precise-state rewind.
                let block = state.branch.blocks.get(&height).cloned().unwrap_or_else(|| {
                    let tree = &state.branch.trees[&height];
                    let chain = transcode::<_, service::TreeState>(tree.clone()).to_chain_state().unwrap();
                    wire::CompactBlock { height, hash: chain.block_hash().0.to_vec(), ..Default::default() }
                });
                Ok(Response::new(block))
            }
            type GetBlockRangeStream = Replies<wire::CompactBlock>;
            async fn get_block_range(&self, request: Request<wire::BlockRange>) -> Result<Response<Self::GetBlockRangeStream>, Status> {
                let range = request.into_inner();
                let start = range.start.unwrap().height;
                let end = range.end.unwrap().height;
                let mut state = self.0.lock().unwrap();
                let first = state.branch.blocks[&start].clone();
                if state.switch_at(Boundary::Blocks) {
                    return Ok(replies(vec![Ok(first), Err(Status::aborted("Synthetic branch changed during blocks."))]));
                }
                Ok(replies(state.branch.blocks.range(start..=end).map(|(_, block)| Ok(block.clone())).collect()))
            }
            async fn get_tree_state(&self, request: Request<wire::BlockId>) -> Result<Response<wire::TreeState>, Status> {
                let mut state = self.0.lock().unwrap();
                if state.switch_at(Boundary::Tree) {
                    return Err(Status::aborted("Synthetic branch changed during tree retrieval."));
                }
                let selected = request.into_inner();
                let tree = if selected.hash.is_empty() {
                    state.branch.trees[&selected.height].clone()
                } else {
                    state.branch.trees.values().find(|tree| {
                        transcode::<_, service::TreeState>((*tree).clone()).to_chain_state().unwrap().block_hash().0.as_slice() == selected.hash
                    }).unwrap().clone()
                };
                Ok(Response::new(tree))
            }
            type GetSubtreeRootsStream = Replies<wire::SubtreeRoot>;
            async fn get_subtree_roots(&self, _: Request<wire::GetSubtreeRootsArg>) -> Result<Response<Self::GetSubtreeRootsStream>, Status> {
                Ok(replies(vec![]))
            }
            type GetAddressUtxosStreamStream = Replies<wire::GetAddressUtxosReply>;
            async fn get_address_utxos_stream(&self, request: Request<wire::GetAddressUtxosArg>) -> Result<Response<Self::GetAddressUtxosStreamStream>, Status> {
                let request = request.into_inner();
                let mut state = self.0.lock().unwrap();
                let utxo = state.branch.utxo.clone();
                assert!(request.addresses.contains(&utxo.address));
                if state.switch_at(Boundary::Utxos) {
                    return Ok(replies(vec![Ok(utxo), Err(Status::aborted("Synthetic UTXO set interrupted by fork."))]));
                }
                Ok(replies(if utxo.height >= request.start_height { vec![Ok(utxo)] } else { vec![] }))
            }
            type GetTaddressTransactionsStream = Replies<wire::RawTransaction>;
            async fn get_taddress_transactions(&self, _: Request<wire::TransparentAddressBlockFilter>) -> Result<Response<Self::GetTaddressTransactionsStream>, Status> {
                self.0.lock().unwrap().switch_at(Boundary::History);
                // Empty EOF still requires the actual history helper's after
                // anchor check before a completed address check is committed.
                Ok(replies(vec![]))
            }
        }
    }
}
fixture_service! {
    get_block_nullifiers(wire::BlockId) -> wire::CompactBlock;
    send_transaction(wire::RawTransaction) -> wire::SendResponse;
    get_taddress_balance(wire::AddressList) -> wire::Balance;
    get_taddress_balance_stream(tonic::Streaming<wire::Address>) -> wire::Balance;
    get_latest_tree_state(wire::Empty) -> wire::TreeState;
    get_address_utxos(wire::GetAddressUtxosArg) -> wire::GetAddressUtxosReplyList;
    get_lightd_info(wire::Empty) -> wire::LightdInfo;
    ping(wire::Duration) -> wire::PingResponse;
    @streams
    get_block_range_nullifiers(wire::BlockRange) -> GetBlockRangeNullifiersStream<wire::CompactBlock>;
    get_taddress_txids(wire::TransparentAddressBlockFilter) -> GetTaddressTxidsStream<wire::RawTransaction>;
    get_mempool_tx(wire::Exclude) -> GetMempoolTxStream<wire::CompactTx>;
    get_mempool_stream(wire::Empty) -> GetMempoolStreamStream<wire::RawTransaction>;
}

struct Incoming(tokio::net::TcpListener);
impl Stream for Incoming {
    type Item = std::io::Result<tokio::net::TcpStream>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0
            .poll_accept(cx)
            .map(|result| Some(result.map(|(socket, _)| socket)))
    }
}

struct ObservedCache {
    inner: SqliteBlockCache,
    rewinds: Mutex<Vec<BlockHeight>>,
}
impl BlockSource for ObservedCache {
    type Error = CacheError;
    fn with_blocks<F, E>(
        &self,
        from: Option<BlockHeight>,
        limit: Option<usize>,
        with: F,
    ) -> Result<(), ChainError<E, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ChainError<E, Self::Error>>,
    {
        self.inner.with_blocks(from, limit, with)
    }
}
#[async_trait]
impl BlockCache for ObservedCache {
    fn get_tip_height(
        &self,
        range: Option<&ScanRange>,
    ) -> Result<Option<BlockHeight>, Self::Error> {
        self.inner.get_tip_height(range)
    }
    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
        self.inner.read(range).await
    }
    async fn insert(&self, blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
        self.inner.insert(blocks).await
    }
    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
        self.inner.delete(range).await
    }
    async fn truncate(&self, height: BlockHeight) -> Result<(), Self::Error> {
        self.rewinds.lock().unwrap().push(height);
        self.inner.truncate(height).await
    }
}

fn tree(state: &ChainState) -> wire::TreeState {
    // Each branch deliberately has only one Sapling leaf; construct its
    // legacy tree using maintained append/serialization, not custom encoding.
    let mut sapling = service::TreeState::default().sapling_tree().unwrap();
    if let Some(frontier) = state.final_sapling_tree().value() {
        assert_eq!(u64::from(frontier.position()), 0);
        sapling.append(frontier.leaf().clone()).unwrap();
    }
    assert!(state.final_orchard_tree().value().is_none());
    assert!(state.final_ironwood_tree().value().is_none());
    let mut encoded = Vec::new();
    write_commitment_tree(&sapling, &mut encoded).unwrap();
    wire::TreeState {
        network: "test".into(),
        height: u64::from(u32::from(state.block_height())),
        hash: state.block_hash().to_string(),
        sapling_tree: hex::encode(encoded),
        ..Default::default()
    }
}
fn blocks(cache: &SqliteBlockCache) -> BTreeMap<u64, wire::CompactBlock> {
    let mut result = BTreeMap::new();
    cache
        .with_blocks::<_, ()>(None, None, |block| {
            result.insert(block.height, transcode(block));
            Ok(())
        })
        .unwrap();
    result
}
fn network() -> LocalNetwork {
    let params = Network::TestNetwork;
    LocalNetwork {
        overwinter: params.activation_height(NetworkUpgrade::Overwinter),
        sapling: params.activation_height(NetworkUpgrade::Sapling),
        blossom: params.activation_height(NetworkUpgrade::Blossom),
        heartwood: params.activation_height(NetworkUpgrade::Heartwood),
        canopy: params.activation_height(NetworkUpgrade::Canopy),
        nu5: params.activation_height(NetworkUpgrade::Nu5),
        nu6: params.activation_height(NetworkUpgrade::Nu6),
        nu6_1: params.activation_height(NetworkUpgrade::Nu6_1),
        nu6_2: params.activation_height(NetworkUpgrade::Nu6_2),
        nu6_3: params.activation_height(NetworkUpgrade::Nu6_3),
        nu7: params.activation_height(NetworkUpgrade::Nu7),
    }
}

#[test]
fn recovery_chain_state_requires_canonical_height_hash_and_complete_trees() {
    let safe = BlockHeight::from_u32(279_999);
    let requested = safe + 4;
    let before = CompactBlock {
        height: u64::from(u32::from(safe)),
        hash: vec![1; 32],
        ..Default::default()
    };
    let tree = service::TreeState {
        network: "test".into(),
        height: before.height,
        hash: BlockHash([1; 32]).to_string(),
        ..Default::default()
    };
    let valid = checked_recovery_state(safe, requested, &before, tree.clone(), &before).unwrap();
    assert_eq!(valid.block_height(), safe);
    assert_eq!(valid.block_hash(), BlockHash([1; 32]));
    let mut above = tree.clone();
    above.height = u64::from(u32::from(requested + 1));
    let mut wrong_hash = tree.clone();
    wrong_hash.hash = BlockHash([2; 32]).to_string();
    let mut wrong_network = tree.clone();
    wrong_network.network = "main".into();
    let mut incomplete = tree.clone();
    incomplete.sapling_tree = "01".into();
    for invalid in [above, wrong_hash, wrong_network, incomplete] {
        assert!(checked_recovery_state(safe, requested, &before, invalid, &before).is_err());
    }
    let mut changed = before.clone();
    changed.hash[0] ^= 1;
    assert!(checked_recovery_state(safe, requested, &before, tree.clone(), &changed).is_err());
    assert!(checked_recovery_state(safe, safe - 1, &before, tree, &before).is_err());
}

#[tokio::test]
async fn maintained_sync_recovers_forks_at_tree_blocks_utxos_and_history_boundaries() {
    for boundary in [
        Boundary::Tree,
        Boundary::Blocks,
        Boundary::Utxos,
        Boundary::History,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source-cache.sqlite");
        let source = SqliteBlockCache::open(&source_path).unwrap();
        // TestState::cache is gated behind the maintained crate's unstable
        // feature. Reopen our owned public-block cache using its actual API.
        let source_read = SqliteBlockCache::open(&source_path).unwrap();
        let builder = TestBuilder::new()
            .with_network(network())
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(source)
            .with_account_from_sapling_activation(BlockHash([0; 32]));
        let mut scenario = TestDsl::from(builder).build::<SaplingPoolTester>();
        let account = scenario.get_account();
        let ufvk = account.usk().to_unified_full_viewing_key();
        let birthday = account.birthday().clone();
        let receivers = scenario
            .wallet()
            .get_transparent_receivers(account.id(), true, true)
            .unwrap();
        let address = *receivers.keys().next().unwrap();
        // Query another owned receiver with no transactions. Empty history is
        // accurate for this address on both branches, yet still needs anchors.
        let history_address = *receivers
            .keys()
            .find(|candidate| **candidate != address)
            .unwrap();
        let address_text = encode_transparent_address_p(&Network::TestNetwork, &address);
        let base = scenario.sapling_activation_height();
        let mut trees = BTreeMap::from([(
            u64::from(u32::from(base - 1)),
            tree(birthday.prior_chain_state()),
        )]);
        // The locked maintained sync implementation rewinds ten blocks. Keep
        // that rewind inside a retained shared prefix, with one earlier anchor.
        for _ in 0..=10 {
            let (height, _) = scenario.generate_empty_block();
            trees.insert(
                u64::from(u32::from(height)),
                tree(scenario.latest_cached_block().unwrap().chain_state()),
            );
        }
        let parent = scenario.latest_cached_block().unwrap().clone();
        let fvk = SaplingPoolTester::test_account_fvk(&scenario);
        let (fork_height, _, _) = scenario.generate_next_block(
            &fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(60_000),
        );
        trees.insert(
            u64::from(u32::from(fork_height)),
            tree(scenario.latest_cached_block().unwrap().chain_state()),
        );
        let (old_tip, _, old_txid) = scenario
            .generate_next_block_transparent(&[], &[(address, Zatoshis::const_from_u64(1_000))]);
        trees.insert(
            u64::from(u32::from(old_tip)),
            tree(scenario.latest_cached_block().unwrap().chain_state()),
        );
        let old_blocks = blocks(&source_read);
        // The maintained synthetic builder derives this script from the
        // transparent address. Its compact format includes transparent vout;
        // the project wire format omits that additional field.
        let mut script = None;
        source_read
            .with_blocks::<_, ()>(Some(old_tip), Some(1), |block| {
                script = Some(block.vtx[1].vout[0].script_pub_key.clone());
                Ok(())
            })
            .unwrap();
        let script = script.unwrap();
        let old_utxo = wire::GetAddressUtxosReply {
            address: address_text.clone(),
            txid: old_txid.as_ref().to_vec(),
            index: 0,
            script: script.clone(),
            value_zat: 1_000,
            height: u64::from(u32::from(old_tip)),
        };
        let initial = Branch {
            blocks: old_blocks,
            trees: trees.clone(),
            utxo: old_utxo.clone(),
        };
        let old_receipt = TxId::from_bytes(
            initial.blocks[&u64::from(u32::from(fork_height))].vtx[0]
                .hash
                .as_slice()
                .try_into()
                .unwrap(),
        );
        let old_tip_hash = initial.blocks[&u64::from(u32::from(old_tip))].hash.clone();
        let (new_tip, _) = scenario.generate_empty_block();
        trees.insert(
            u64::from(u32::from(new_tip)),
            tree(scenario.latest_cached_block().unwrap().chain_state()),
        );
        let old_extended = Branch {
            blocks: blocks(&source_read),
            trees: trees.clone(),
            utxo: old_utxo,
        };

        scenario.generate_block_at(
            fork_height,
            parent.chain_state().block_hash(),
            &[FakeCompactOutput::new(
                &fvk,
                AddressType::DefaultExternal,
                Zatoshis::const_from_u64(80_000),
            )],
            parent.sapling_end_size(),
            parent.orchard_end_size(),
            parent.ironwood_end_size(),
            false,
        );
        trees.insert(
            u64::from(u32::from(fork_height)),
            tree(scenario.latest_cached_block().unwrap().chain_state()),
        );
        let (replacement_utxo_height, _, new_txid) = scenario
            .generate_next_block_transparent(&[], &[(address, Zatoshis::const_from_u64(2_000))]);
        assert_eq!(replacement_utxo_height, old_tip);
        trees.insert(
            u64::from(u32::from(old_tip)),
            tree(scenario.latest_cached_block().unwrap().chain_state()),
        );
        assert_eq!(scenario.generate_empty_block().0, new_tip);
        trees.insert(
            u64::from(u32::from(new_tip)),
            tree(scenario.latest_cached_block().unwrap().chain_state()),
        );
        let replacement = Branch {
            blocks: blocks(&source_read),
            trees,
            utxo: wire::GetAddressUtxosReply {
                address: address_text,
                txid: new_txid.as_ref().to_vec(),
                index: 0,
                script,
                value_zat: 2_000,
                height: u64::from(u32::from(old_tip)),
            },
        };
        let replacement_receipt = TxId::from_bytes(
            replacement.blocks[&u64::from(u32::from(fork_height))].vtx[0]
                .hash
                .as_slice()
                .try_into()
                .unwrap(),
        );
        assert_ne!(
            initial.blocks[&u64::from(u32::from(old_tip))].hash,
            replacement.blocks[&u64::from(u32::from(old_tip))].hash
        );
        let replacement_hash = replacement.blocks[&u64::from(u32::from(new_tip))]
            .hash
            .clone();
        let state = Arc::new(Mutex::new(State {
            branch: initial,
            replacement,
            advertised_tip: u64::from(u32::from(old_tip)),
            boundary: None,
            switched: false,
            unavailable: vec![old_receipt.as_ref().to_vec(), old_txid.as_ref().to_vec()],
            status_reads: 0,
        }));
        let service = FixtureService(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bind = listener.local_addr().unwrap();
        let capability_dir = directory.path().join("capability-dir");
        PrivateDirectory::create(&capability_dir).unwrap();
        let capability = "11".repeat(32);
        fs::write(capability_dir.join("capability"), &capability).unwrap();
        fs::set_permissions(
            capability_dir.join("capability"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(
            Server::builder()
                .add_service(CompactTxStreamerServer::with_interceptor(
                    service,
                    move |request: Request<()>| {
                        if request
                            .metadata()
                            .get("x-zrpc-capability")
                            .map(|value| value.as_bytes())
                            != Some(capability.as_bytes())
                        {
                            return Err(Status::unauthenticated(
                                "Synthetic fixture capability required.",
                            ));
                        }
                        Ok(request)
                    },
                ))
                .serve_with_incoming_shutdown(Incoming(listener), async {
                    let _ = stopped.await;
                }),
        );
        let adapter = LocalWalletAdapter::connect(bind, &capability_dir)
            .await
            .unwrap();
        let mut client = adapter.maintained_scanner_client();
        let connection = Connection::open(directory.path().join("wallet.sqlite")).unwrap();
        rusqlite::vtab::array::load_module(&connection).unwrap();
        let mut wallet = WalletDb::from_connection(
            connection,
            Network::TestNetwork,
            SystemClock,
            UnwrapErr(SysRng),
        );
        init_wallet_db(&mut wallet, None).unwrap();
        let restored = wallet
            .import_account_ufvk(
                "synthetic fork view-only",
                &ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )
            .unwrap()
            .id();
        let cache = ObservedCache {
            inner: SqliteBlockCache::open(Path::new(":memory:")).unwrap(),
            rewinds: Mutex::new(vec![]),
        };
        // Use the fixture's finite chain length as one scan batch, not a new
        // production resource cap or retry policy.
        let batch = u32::from(new_tip) - u32::from(base) + 1;
        run_reference_sync(&mut client, &cache, &mut wallet, batch)
            .await
            .unwrap();
        assert_eq!(
            wallet.get_tx_height(old_receipt).unwrap(),
            Some(fork_height)
        );
        assert_eq!(wallet.get_tx_height(old_txid).unwrap(), Some(old_tip));
        assert_eq!(
            wallet
                .get_wallet_summary(ConfirmationsPolicy::MIN)
                .unwrap()
                .unwrap()
                .account_balances()[&restored]
                .total(),
            Zatoshis::const_from_u64(60_000)
        );
        // The maintained ZIP317 accounting places these small regular UTXOs
        // in uneconomic_value, which Balance::total deliberately excludes.
        // Assert their nonzero accounting separately rather than treating
        // them as spendable, pending or immature coinbase value.
        assert_eq!(
            wallet
                .get_wallet_summary(ConfirmationsPolicy::MIN)
                .unwrap()
                .unwrap()
                .account_balances()[&restored]
                .unshielded_regular_balance()
                .uneconomic_value(),
            Zatoshis::const_from_u64(1_000)
        );
        let requests_before = wallet.transaction_data_requests().unwrap();
        {
            let mut state = state.lock().unwrap();
            state.branch = old_extended;
            state.advertised_tip = u64::from(u32::from(new_tip));
            state.boundary = Some(boundary);
        }
        let history_request = || {
            let TransactionDataRequest::TransactionsInvolvingAddress(request) =
                TransactionDataRequest::transactions_involving_address(
                    history_address,
                    base,
                    Some(old_tip + 1),
                    None,
                    TransactionStatusFilter::Mined,
                    OutputStatusFilter::All,
                )
            else {
                unreachable!()
            };
            request
        };
        if boundary == Boundary::History {
            let result = enhance::process_mined_transparent_history(
                &mut client,
                &mut wallet,
                history_request(),
                directory.path(),
                false,
            )
            .await;
            assert_eq!(
                result.unwrap_err().to_string(),
                "transparent history changed during retrieval"
            );
            assert_eq!(wallet.transaction_data_requests().unwrap(), requests_before);
        } else {
            assert!(
                matches!(run_reference_sync(&mut client, &cache, &mut wallet, batch).await, Err(sync::Error::Server(status)) if status.code() == tonic::Code::Aborted)
            );
        }
        assert!(
            state.lock().unwrap().switched,
            "{boundary:?} boundary was not exercised"
        );
        assert_eq!(
            wallet
                .get_block_hash(old_tip)
                .unwrap()
                .unwrap()
                .0
                .as_slice(),
            old_tip_hash
        );
        assert_eq!(
            wallet
                .get_wallet_summary(ConfirmationsPolicy::MIN)
                .unwrap()
                .unwrap()
                .account_balances()[&restored]
                .total(),
            Zatoshis::const_from_u64(60_000)
        );
        assert_eq!(
            wallet
                .get_wallet_summary(ConfirmationsPolicy::MIN)
                .unwrap()
                .unwrap()
                .account_balances()[&restored]
                .unshielded_regular_balance()
                .uneconomic_value(),
            Zatoshis::const_from_u64(1_000)
        );
        run_reference_sync(&mut client, &cache, &mut wallet, batch)
            .await
            .unwrap();
        assert!(
            !cache.rewinds.lock().unwrap().is_empty(),
            "maintained rewind path was not exercised for {boundary:?}"
        );
        assert_eq!(
            wallet
                .get_block_hash(new_tip)
                .unwrap()
                .unwrap()
                .0
                .as_slice(),
            replacement_hash
        );
        let summary = wallet
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .unwrap()
            .unwrap();
        assert_eq!(summary.fully_scanned_height(), new_tip);
        // Compact scanning cannot establish the old transaction's expiry or
        // whether it returned to a mempool. The maintained wallet intentionally
        // retains its unmined receipt: total includes that conservative pending
        // value, rather than claiming that all 140k is confirmed or spendable.
        assert_eq!(
            summary.account_balances()[&restored].total(),
            Zatoshis::const_from_u64(140_000)
        );
        assert_eq!(wallet.get_tx_height(old_receipt).unwrap(), None);
        assert_eq!(wallet.get_tx_height(old_txid).unwrap(), None);
        assert_eq!(
            wallet.get_tx_height(replacement_receipt).unwrap(),
            Some(fork_height)
        );
        assert_eq!(wallet.get_tx_height(new_txid).unwrap(), Some(old_tip));
        let observer = Connection::open(directory.path().join("wallet.sqlite")).unwrap();
        let old_linkage: (Option<u32>, Option<u32>) = observer
            .query_row(
                "SELECT block, mined_height FROM transactions WHERE txid = ?",
                [old_receipt.as_ref()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(old_linkage, (None, None));
        let shielded_receipts: (u64, u64) = observer
            .query_row(
                "SELECT SUM(CASE WHEN t.mined_height IS NOT NULL THEN n.value ELSE 0 END),
                        SUM(CASE WHEN t.mined_height IS NULL THEN n.value ELSE 0 END)
                 FROM sapling_received_notes n
                 JOIN transactions t ON t.id_tx = n.transaction_id",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(shielded_receipts, (80_000, 60_000));
        let sapling_balance = summary.account_balances()[&restored].sapling_balance();
        assert!(sapling_balance.value_pending_spendability() >= Zatoshis::const_from_u64(60_000));
        assert!(sapling_balance.spendable_value() <= Zatoshis::const_from_u64(80_000));
        assert_eq!(
            summary.account_balances()[&restored]
                .unshielded_regular_balance()
                .uneconomic_value(),
            Zatoshis::const_from_u64(2_000)
        );
        assert!(matches!(
            enhance::process_mined_transparent_history(
                &mut client,
                &mut wallet,
                history_request(),
                directory.path(),
                false
            )
            .await
            .unwrap(),
            Some(enhance::MinedHistoryKind::Complete)
        ));
        for txid in [old_receipt, old_txid] {
            assert!(
                !enhance::process_transaction_request(
                    &mut client,
                    &mut wallet,
                    TransactionDataRequest::GetStatus(txid),
                )
                .await
                .unwrap()
            );
        }
        let unavailable_height: Option<u32> = observer
            .query_row(
                "SELECT confirmed_unmined_at_height FROM transactions WHERE txid = ?",
                [old_receipt.as_ref()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unavailable_height, Some(u32::from(new_tip)));
        assert_eq!(
            wallet
                .get_wallet_summary(ConfirmationsPolicy::MIN)
                .unwrap()
                .unwrap()
                .account_balances()[&restored]
                .total(),
            Zatoshis::const_from_u64(140_000)
        );
        // Exact locked SQLite lib.rs PRUNING_DEPTH is crate-private 100;
        // wallet.rs set_transaction_status uses that depth plus the public
        // builder expiry delta to terminate unknown-expiry status intents.
        // This is maintained policy, not a new production timeout or quota.
        const MAINTAINED_PRUNING_DEPTH: u32 = 100;
        let certainty_tip = old_tip
            + MAINTAINED_PRUNING_DEPTH
            + zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;
        while scenario
            .latest_cached_block()
            .unwrap()
            .chain_state()
            .block_height()
            < certainty_tip
        {
            let (height, _) = scenario.generate_empty_block();
            let mut state = state.lock().unwrap();
            state.branch.trees.insert(
                u64::from(u32::from(height)),
                tree(scenario.latest_cached_block().unwrap().chain_state()),
            );
        }
        {
            let mut state = state.lock().unwrap();
            state.branch.blocks = blocks(&source_read);
            state.advertised_tip = u64::from(u32::from(certainty_tip));
        }
        run_reference_sync(&mut client, &cache, &mut wallet, batch)
            .await
            .unwrap();
        for txid in [old_receipt, old_txid] {
            assert!(
                !enhance::process_transaction_request(
                    &mut client,
                    &mut wallet,
                    TransactionDataRequest::GetStatus(txid),
                )
                .await
                .unwrap()
            );
        }
        assert_eq!(state.lock().unwrap().status_reads, 4);
        let terminal_requests = wallet.transaction_data_requests().unwrap();
        for txid in [old_receipt, old_txid] {
            assert!(!terminal_requests.iter().any(|request| matches!(request,
                TransactionDataRequest::GetStatus(id) | TransactionDataRequest::Enhancement(id)
                if *id == txid)));
        }
        let summary = wallet
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .unwrap()
            .unwrap();
        assert_eq!(summary.fully_scanned_height(), certainty_tip);
        assert_eq!(
            summary.account_balances()[&restored].total(),
            Zatoshis::const_from_u64(80_000)
        );
        assert_eq!(
            summary.account_balances()[&restored]
                .unshielded_regular_balance()
                .uneconomic_value(),
            Zatoshis::const_from_u64(2_000)
        );
        assert_eq!(wallet.get_tx_height(old_receipt).unwrap(), None);
        assert_eq!(
            wallet.get_tx_height(replacement_receipt).unwrap(),
            Some(fork_height)
        );
        assert_eq!(
            wallet
                .get_block_hash(certainty_tip)
                .unwrap()
                .unwrap()
                .0
                .as_slice(),
            state.lock().unwrap().branch.blocks[&u64::from(u32::from(certainty_tip))].hash
        );
        drop(client);
        drop(adapter);
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}
