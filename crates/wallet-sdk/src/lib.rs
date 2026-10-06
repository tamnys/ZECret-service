//! Testnet wallet reads over one retained, Phala-trusting verified connection.
//! The SDK holds no wallet keys, decrypted notes, or wallet database.
#![forbid(unsafe_code)]

pub mod bridge;

use std::{collections::HashSet, future::Future, sync::Mutex};
use zrpc_client::inspection::{PrivateEndpointConfig, connect_phala_trusted_wallet};
use zrpc_payments::{ClientStore, IssuerPublic};
use zrpc_protocol::{ErrorCode, SafeError};
use zrpc_transport::WalletReadResult;
use zrpc_verifier::PhalaTrustedPolicy;
pub use zrpc_wallet_read::NodeReadContext;
use zrpc_wallet_read::{
    RangeContinuity, ReadMethod, SubtreeContinuity, WalletReadRequest, snapshot_wire, wire,
};

fn ticket_error() -> SafeError {
    SafeError::new(
        ErrorCode::PrivateModeUnavailable,
        "Wallet ticket unavailable.",
    )
}

fn invalid_chain() -> SafeError {
    SafeError::new(
        ErrorCode::BlockMismatch,
        "Wallet block range is incomplete or disconnected.",
    )
}

/// Every item is a pinned protobuf type. A result is complete only when
/// `WalletReader::read_from_request` returns successfully; a partial stream
/// must not be applied as a completed balance, history, or UTXO set.
pub enum WalletReadItem {
    LatestBlock(wire::BlockId),
    Block(wire::CompactBlock),
    BlockNullifiers(wire::CompactBlock),
    BlockRange(wire::CompactBlock),
    BlockRangeNullifiers(wire::CompactBlock),
    Transaction(wire::RawTransaction),
    TaddressTxids(wire::RawTransaction),
    TaddressTransactions(wire::RawTransaction),
    TaddressBalance(wire::Balance),
    TaddressBalanceStream(wire::Balance),
    MempoolTx(wire::CompactTx),
    MempoolStream(wire::RawTransaction),
    MempoolSnapshot(snapshot_wire::SnapshotItem),
    TreeState(wire::TreeState),
    LatestTreeState(wire::TreeState),
    SubtreeRoots(wire::SubtreeRoot),
    AddressUtxos(wire::GetAddressUtxosReplyList),
    AddressUtxosStream(wire::GetAddressUtxosReply),
    LightdInfo(wire::LightdInfo),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletReadCompletion {
    pub method: ReadMethod,
    pub delivered_items: u64,
    /// This describes only completion of one backend RPC, not an atomic chain
    /// snapshot or global node freshness.
    pub ticket_spent: bool,
    /// Last node height from this completed read, if it was a tip or info read.
    /// This is the node's own report, never a global freshness appraisal.
    pub node_observation: Option<NodeObservation>,
    /// Node tip observed before this backend read, if the approved image
    /// implements the extension. Never an atomic response snapshot.
    pub node_read_context: Option<NodeReadContext>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeObservation {
    pub height: u32,
    pub estimated_height: Option<u32>,
}

#[derive(Clone, Copy)]
struct RangeSpec {
    start: u32,
    end: u32,
}

#[derive(Clone, Copy)]
enum BlockSpec {
    Height(u32),
    Hash([u8; 32]),
}

fn block_spec(request: &WalletReadRequest) -> Option<BlockSpec> {
    let selected = match request {
        WalletReadRequest::Block(value)
        | WalletReadRequest::BlockNullifiers(value)
        | WalletReadRequest::TreeState(value) => value,
        _ => return None,
    };
    if selected.hash.is_empty() {
        Some(BlockSpec::Height(u32::try_from(selected.height).ok()?))
    } else {
        Some(BlockSpec::Hash(selected.hash.as_slice().try_into().ok()?))
    }
}

fn selected_block_matches(spec: BlockSpec, block: &wire::CompactBlock) -> bool {
    match spec {
        BlockSpec::Height(height) => block.height == u64::from(height),
        BlockSpec::Hash(hash) => block.hash.as_slice() == hash,
    }
}

fn valid_tree_state(tree: &wire::TreeState) -> bool {
    tree.network == "test"
        && tree.height <= u64::from(u32::MAX)
        && tree.hash.len() == 64
        && tree.hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn selected_tree_state_matches(spec: BlockSpec, tree: &wire::TreeState) -> bool {
    if !valid_tree_state(tree) {
        return false;
    }
    match spec {
        BlockSpec::Height(height) => tree.height == u64::from(height),
        BlockSpec::Hash(hash) => hex::decode(&tree.hash).is_ok_and(|mut display| {
            display.reverse();
            display.as_slice() == hash
        }),
    }
}

fn range_spec(request: &WalletReadRequest) -> Option<RangeSpec> {
    let range = match request {
        WalletReadRequest::BlockRange(value) | WalletReadRequest::BlockRangeNullifiers(value) => {
            value
        }
        _ => return None,
    };
    Some(RangeSpec {
        start: u32::try_from(range.start.as_ref()?.height).ok()?,
        end: u32::try_from(range.end.as_ref()?.height).ok()?,
    })
}

fn validate_snapshot_item(
    item: &snapshot_wire::SnapshotItem,
    has_tip: &mut bool,
    seen: &mut HashSet<[u8; 32]>,
) -> Result<(), SafeError> {
    match item.body.as_ref() {
        Some(snapshot_wire::snapshot_item::Body::Tip(tip))
            if !*has_tip && tip.height <= u64::from(u32::MAX) && tip.hash.len() == 32 =>
        {
            *has_tip = true;
            Ok(())
        }
        Some(snapshot_wire::snapshot_item::Body::Txid(id)) if *has_tip => {
            let id: [u8; 32] = id.as_slice().try_into().map_err(|_| invalid_chain())?;
            if seen.insert(id) {
                Ok(())
            } else {
                Err(invalid_chain())
            }
        }
        _ => Err(invalid_chain()),
    }
}

/// One SDK instance serializes access to its durable ticket store. Every read
/// obtains a fresh Tor stream, TLS connection, quote, collateral appraisal and
/// release approval. It never reconnects inside an RPC.
pub struct WalletReader {
    endpoint: PrivateEndpointConfig,
    collateral: Vec<u8>,
    app_compose: Vec<u8>,
    policy: PhalaTrustedPolicy,
    issuer: IssuerPublic,
    tickets: ClientStore,
}

impl WalletReader {
    pub fn new(
        endpoint: PrivateEndpointConfig,
        collateral: Vec<u8>,
        app_compose: Vec<u8>,
        policy: PhalaTrustedPolicy,
        issuer: IssuerPublic,
        tickets: ClientStore,
    ) -> Self {
        Self {
            endpoint,
            collateral,
            app_compose,
            policy,
            issuer,
            tickets,
        }
    }

    /// The request future is not polled until the retained TLS connection is
    /// verified. The sink is awaited for each item to propagate backpressure.
    /// Dropping this future cancels the RPC and leaves any claimed ticket
    /// uncertain. A failed sink likewise cannot turn a partial stream into a
    /// completed read.
    pub async fn read_from_request<F, Fut, S, SFut>(
        &mut self,
        request: F,
        sink: S,
        prior_block_hash: Option<[u8; 32]>,
    ) -> Result<WalletReadCompletion, SafeError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<WalletReadRequest, SafeError>>,
        S: FnMut(WalletReadItem) -> SFut,
        SFut: Future<Output = Result<(), SafeError>>,
    {
        self.read_from_request_with_context(request, sink, prior_block_hash, |_| Ok(()))
            .await
    }

    /// Observe validated response context before any result item is delivered.
    /// This also runs for empty streams. Older images report `None`; no
    /// observation is synthesized from an unrelated read.
    pub async fn read_from_request_with_context<F, Fut, S, SFut, O>(
        &mut self,
        request: F,
        mut sink: S,
        prior_block_hash: Option<[u8; 32]>,
        observe: O,
    ) -> Result<WalletReadCompletion, SafeError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<WalletReadRequest, SafeError>>,
        S: FnMut(WalletReadItem) -> SFut,
        SFut: Future<Output = Result<(), SafeError>>,
        O: FnOnce(Option<NodeReadContext>) -> Result<(), SafeError>,
    {
        let session = connect_phala_trusted_wallet(
            &self.endpoint,
            &self.collateral,
            &self.app_compose,
            &self.policy,
        )
        .await?;
        let method = Mutex::new(None);
        let range = Mutex::new(None);
        let selected_block = Mutex::new(None);
        let subtree = Mutex::new(None);
        let (result, node_read_context, marker) = session
            .read_from_request_async(
                || async {
                    let request = request().await?;
                    *method.lock().map_err(|_| invalid_chain())? = Some(request.method());
                    *range.lock().map_err(|_| invalid_chain())? = range_spec(&request);
                    *selected_block.lock().map_err(|_| invalid_chain())? = block_spec(&request);
                    *subtree.lock().map_err(|_| invalid_chain())? = match &request {
                        WalletReadRequest::SubtreeRoots(value) => {
                            Some((value.start_index, value.max_entries))
                        }
                        _ => None,
                    };
                    Ok(request)
                },
                || {
                    let ticket = self
                        .tickets
                        .preview_available()
                        .map_err(|_| ticket_error())?
                        .ok_or_else(ticket_error)?;
                    let authorization = self
                        .issuer
                        .authorization_for(ticket.token.expose())
                        .map_err(|_| ticket_error())?;
                    let marker = ticket.marker;
                    let store = &mut self.tickets;
                    Ok((authorization, marker, move || {
                        store.claim_available(&ticket).map_err(|_| ticket_error())?;
                        Ok(move || {
                            store
                                .release_untransmitted(&ticket)
                                .map_err(|_| ticket_error())
                        })
                    }))
                },
            )
            .await?;
        observe(node_read_context)?;
        let method = method
            .lock()
            .map_err(|_| invalid_chain())?
            .ok_or_else(invalid_chain)?;
        let range = *range.lock().map_err(|_| invalid_chain())?;
        let selected_block = *selected_block.lock().map_err(|_| invalid_chain())?;
        let subtree = *subtree.lock().map_err(|_| invalid_chain())?;
        let (delivered_items, node_observation) = drain_result(
            result,
            range,
            selected_block,
            subtree,
            prior_block_hash,
            &mut sink,
        )
        .await?;
        self.tickets
            .mark_spent(marker)
            .map_err(|_| ticket_error())?;
        Ok(WalletReadCompletion {
            method,
            delivered_items,
            ticket_spent: true,
            node_observation,
            node_read_context,
        })
    }
}

async fn drain_result<S, SFut>(
    result: WalletReadResult,
    range: Option<RangeSpec>,
    selected_block: Option<BlockSpec>,
    subtree: Option<(u32, u32)>,
    prior_block_hash: Option<[u8; 32]>,
    sink: &mut S,
) -> Result<(u64, Option<NodeObservation>), SafeError>
where
    S: FnMut(WalletReadItem) -> SFut,
    SFut: Future<Output = Result<(), SafeError>>,
{
    let mut delivered = 0_u64;
    let mut node_observation = None;
    macro_rules! emit {
        ($variant:ident, $item:expr) => {{
            sink(WalletReadItem::$variant($item)).await?;
            delivered = delivered.checked_add(1).ok_or_else(invalid_chain)?;
        }};
    }
    macro_rules! stream {
        ($stream:ident, $variant:ident) => {{
            while let Some(item) = $stream.next().await? {
                emit!($variant, item);
            }
        }};
    }
    match result {
        WalletReadResult::LatestBlock(item) => {
            node_observation = Some(NodeObservation {
                height: u32::try_from(item.height).map_err(|_| invalid_chain())?,
                estimated_height: None,
            });
            emit!(LatestBlock, item);
        }
        WalletReadResult::Block(item) => {
            zrpc_wallet_read::validate_compact_block(&item).map_err(|_| invalid_chain())?;
            if !selected_block.is_some_and(|selected| selected_block_matches(selected, &item)) {
                return Err(invalid_chain());
            }
            emit!(Block, item)
        }
        WalletReadResult::BlockNullifiers(item) => {
            zrpc_wallet_read::validate_nullifier_only_block(&item).map_err(|_| invalid_chain())?;
            if !selected_block.is_some_and(|selected| selected_block_matches(selected, &item)) {
                return Err(invalid_chain());
            }
            emit!(BlockNullifiers, item)
        }
        WalletReadResult::BlockRange(mut stream) => {
            let range = range.ok_or_else(invalid_chain)?;
            let mut continuity = RangeContinuity::new(range.start, range.end, prior_block_hash);
            while let Some(item) = stream.next().await? {
                continuity.observe(&item).map_err(|_| invalid_chain())?;
                emit!(BlockRange, item);
            }
            continuity.finish().map_err(|_| invalid_chain())?;
        }
        WalletReadResult::BlockRangeNullifiers(mut stream) => {
            let range = range.ok_or_else(invalid_chain)?;
            let mut continuity =
                RangeContinuity::new_nullifiers_only(range.start, range.end, prior_block_hash);
            while let Some(item) = stream.next().await? {
                continuity.observe(&item).map_err(|_| invalid_chain())?;
                emit!(BlockRangeNullifiers, item);
            }
            continuity.finish().map_err(|_| invalid_chain())?;
        }
        WalletReadResult::Transaction(item) => emit!(Transaction, item),
        WalletReadResult::TaddressTxids(mut value) => stream!(value, TaddressTxids),
        WalletReadResult::TaddressTransactions(mut value) => {
            stream!(value, TaddressTransactions)
        }
        WalletReadResult::TaddressBalance(item) => emit!(TaddressBalance, item),
        WalletReadResult::TaddressBalanceStream(item) => emit!(TaddressBalanceStream, item),
        WalletReadResult::MempoolTx(mut value) => stream!(value, MempoolTx),
        WalletReadResult::MempoolStream(mut value) => stream!(value, MempoolStream),
        WalletReadResult::MempoolSnapshot(mut value) => {
            let mut has_tip = false;
            let mut seen = HashSet::new();
            while let Some(item) = value.next().await? {
                validate_snapshot_item(&item, &mut has_tip, &mut seen)?;
                emit!(MempoolSnapshot, item);
            }
            if !has_tip {
                return Err(invalid_chain());
            }
        }
        WalletReadResult::TreeState(item) => {
            if !selected_block.is_some_and(|selected| selected_tree_state_matches(selected, &item))
            {
                return Err(invalid_chain());
            }
            emit!(TreeState, item)
        }
        WalletReadResult::LatestTreeState(item) => {
            if !valid_tree_state(&item) {
                return Err(invalid_chain());
            }
            emit!(LatestTreeState, item)
        }
        WalletReadResult::SubtreeRoots(mut value) => {
            let (start_index, max_entries) = subtree.ok_or_else(invalid_chain)?;
            let mut continuity = SubtreeContinuity::new(start_index, max_entries);
            while let Some(item) = value.next().await? {
                continuity.observe(&item).map_err(|_| invalid_chain())?;
                emit!(SubtreeRoots, item);
            }
        }
        WalletReadResult::AddressUtxos(item) => emit!(AddressUtxos, item),
        WalletReadResult::AddressUtxosStream(mut value) => {
            stream!(value, AddressUtxosStream)
        }
        WalletReadResult::LightdInfo(item) => {
            node_observation = Some(NodeObservation {
                height: u32::try_from(item.block_height).map_err(|_| invalid_chain())?,
                estimated_height: u32::try_from(item.estimated_height)
                    .ok()
                    .filter(|height| *height != 0),
            });
            emit!(LightdInfo, item);
        }
    }
    Ok((delivered, node_observation))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn node_progress_only_comes_from_completed_tip_or_info_reads() {
        let mut sink = |_item| std::future::ready(Ok(()));
        let (_, tip) = drain_result(
            WalletReadResult::LatestBlock(wire::BlockId {
                height: 42,
                hash: vec![7; 32],
            }),
            None,
            None,
            None,
            None,
            &mut sink,
        )
        .await
        .unwrap();
        assert_eq!(tip.unwrap().height, 42);
        assert_eq!(tip.unwrap().estimated_height, None);

        let (_, info) = drain_result(
            WalletReadResult::LightdInfo(wire::LightdInfo {
                block_height: 43,
                estimated_height: 47,
                ..Default::default()
            }),
            None,
            None,
            None,
            None,
            &mut sink,
        )
        .await
        .unwrap();
        assert_eq!(info.unwrap().estimated_height, Some(47));
        assert!(
            drain_result(
                WalletReadResult::LatestBlock(wire::BlockId {
                    height: u64::from(u32::MAX) + 1,
                    hash: vec![7; 32],
                }),
                None,
                None,
                None,
                None,
                &mut sink,
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn range_context_is_only_taken_from_typed_compact_block_reads() {
        let range = wire::BlockRange {
            start: Some(wire::BlockId {
                height: 50,
                hash: vec![],
            }),
            end: Some(wire::BlockId {
                height: 52,
                hash: vec![],
            }),
        };
        let selected = range_spec(&WalletReadRequest::BlockRange(range)).unwrap();
        assert_eq!((selected.start, selected.end), (50, 52));
        assert!(range_spec(&WalletReadRequest::LightdInfo(wire::Empty {})).is_none());
    }

    #[test]
    fn single_block_context_rejects_a_substituted_height_or_hash() {
        let selected = block_spec(&WalletReadRequest::Block(wire::BlockId {
            height: 42,
            hash: vec![],
        }))
        .unwrap();
        let block = wire::CompactBlock {
            height: 42,
            hash: vec![7; 32],
            ..Default::default()
        };
        assert!(selected_block_matches(selected, &block));
        let wrong_height = wire::CompactBlock {
            height: 43,
            ..block.clone()
        };
        assert!(!selected_block_matches(selected, &wrong_height));
        let by_hash = block_spec(&WalletReadRequest::BlockNullifiers(wire::BlockId {
            height: 0,
            hash: vec![7; 32],
        }))
        .unwrap();
        assert!(selected_block_matches(by_hash, &block));
        let wrong_hash = wire::CompactBlock {
            hash: vec![8; 32],
            ..block
        };
        assert!(!selected_block_matches(by_hash, &wrong_hash));
    }

    #[test]
    fn tree_state_context_uses_display_to_internal_hash_order() {
        let internal: Vec<u8> = (0..32).collect();
        let display: Vec<u8> = internal.iter().rev().copied().collect();
        let tree = wire::TreeState {
            network: "test".into(),
            height: 42,
            hash: hex::encode(display),
            ..Default::default()
        };
        let selected = block_spec(&WalletReadRequest::TreeState(wire::BlockId {
            height: 0,
            hash: internal.clone(),
        }))
        .unwrap();
        assert!(selected_tree_state_matches(selected, &tree));
        let mut wrong = internal;
        wrong[0] ^= 1;
        let wrong_selector = BlockSpec::Hash(wrong.try_into().unwrap());
        assert!(!selected_tree_state_matches(wrong_selector, &tree));
        assert!(selected_tree_state_matches(BlockSpec::Height(42), &tree));
        assert!(!selected_tree_state_matches(BlockSpec::Height(43), &tree));
    }

    #[test]
    fn mempool_snapshot_requires_one_tip_before_unique_protocol_order_ids() {
        use snapshot_wire::snapshot_item::Body;
        let tip = snapshot_wire::SnapshotItem {
            body: Some(Body::Tip(snapshot_wire::SnapshotTip {
                height: 42,
                hash: vec![7; 32],
            })),
        };
        let txid = snapshot_wire::SnapshotItem {
            body: Some(Body::Txid(vec![8; 32])),
        };
        let mut has_tip = false;
        let mut seen = HashSet::new();
        assert!(validate_snapshot_item(&txid, &mut has_tip, &mut seen).is_err());
        assert!(validate_snapshot_item(&tip, &mut has_tip, &mut seen).is_ok());
        assert!(validate_snapshot_item(&tip, &mut has_tip, &mut seen).is_err());
        assert!(validate_snapshot_item(&txid, &mut has_tip, &mut seen).is_ok());
        assert!(validate_snapshot_item(&txid, &mut has_tip, &mut seen).is_err());
        assert!(
            validate_snapshot_item(
                &snapshot_wire::SnapshotItem::default(),
                &mut has_tip,
                &mut seen
            )
            .is_err()
        );
        assert!(
            validate_snapshot_item(
                &snapshot_wire::SnapshotItem {
                    body: Some(Body::Txid(vec![1; 31])),
                },
                &mut has_tip,
                &mut seen
            )
            .is_err()
        );
    }
}
