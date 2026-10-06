//! Typed, read-only adapter for Zebra's loopback lightwalletd service.
//! Constructing this service does not expose it on a socket: the attested
//! wrapper must still authorize each remote call before invoking it.

use crate::{
    NodeReadContext, RangeContinuity, ReadMethod, SubtreeContinuity, snapshot_wire,
    validate_client_stream_address, validate_compact_block, validate_compact_tx,
    validate_nullifier_only_block, validate_unary_request, wire,
};
use futures_util::{StreamExt, stream};
use prost::Message;
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tonic::{
    Request, Response, Status,
    transport::{Channel, Endpoint},
};

type ReadStream<T> = futures_util::stream::BoxStream<'static, Result<T, Status>>;

pub struct MempoolSnapshot {
    pub tip: snapshot_wire::SnapshotTip,
    pub txids: Vec<[u8; 32]>,
}

#[tonic::async_trait]
pub trait MempoolSnapshotSource: Send + Sync {
    async fn mempool_snapshot(&self) -> Result<MempoolSnapshot, Status>;
}

fn unavailable() -> Status {
    Status::unavailable("Wallet node is unavailable.")
}

fn sanitize(error: Status) -> Status {
    Status::new(error.code(), "Wallet node request failed.")
}

fn invalid_data() -> Status {
    Status::data_loss("Invalid testnet wallet data from the node.")
}

fn contextual_response<T>(value: T, context: NodeReadContext) -> Result<Response<T>, Status> {
    let mut response = Response::new(value);
    context.write_metadata(response.metadata_mut())?;
    Ok(response)
}

fn check_block_id(id: &wire::BlockId) -> Result<(), Status> {
    if id.height > u32::MAX as u64 || id.hash.len() != 32 {
        return Err(invalid_data());
    }
    Ok(())
}

fn check_selected_block(
    block: &wire::CompactBlock,
    selected: &wire::BlockId,
) -> Result<(), Status> {
    validate_compact_block(block)?;
    if (!selected.hash.is_empty() && block.hash != selected.hash)
        || (selected.hash.is_empty() && block.height != selected.height)
    {
        return Err(invalid_data());
    }
    Ok(())
}

fn check_raw_transaction(tx: &wire::RawTransaction) -> Result<(), Status> {
    if tx.data.is_empty() || (tx.height != u64::MAX && tx.height > u32::MAX as u64) {
        return Err(invalid_data());
    }
    Ok(())
}

fn check_balance(balance: &wire::Balance) -> Result<(), Status> {
    if balance.value_zat < 0 {
        return Err(invalid_data());
    }
    Ok(())
}

fn check_tree_state(tree: &wire::TreeState) -> Result<(), Status> {
    if tree.network != "test"
        || tree.height > u32::MAX as u64
        || tree.hash.len() != 64
        || !tree.hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid_data());
    }
    Ok(())
}

fn check_selected_tree_state(
    tree: &wire::TreeState,
    selected: &wire::BlockId,
) -> Result<(), Status> {
    check_tree_state(tree)?;
    if selected.hash.is_empty() {
        if tree.height != selected.height {
            return Err(invalid_data());
        }
    } else {
        // Zebra's BlockId hash is in internal little-endian byte order,
        // while TreeState.hash is its conventional big-endian display hex.
        let mut display = hex::decode(&tree.hash).map_err(|_| invalid_data())?;
        display.reverse();
        if display != selected.hash {
            return Err(invalid_data());
        }
    }
    Ok(())
}

fn check_utxo(
    utxo: &wire::GetAddressUtxosReply,
    addresses: &HashSet<String>,
    start_height: u64,
) -> Result<(), Status> {
    if utxo.txid.len() != 32
        || utxo.index < 0
        || utxo.value_zat < 0
        || utxo.height > u32::MAX as u64
        || utxo.height < start_height
        || !addresses.contains(&utxo.address)
        || validate_client_stream_address(
            &wire::Address {
                address: utxo.address.clone(),
            }
            .encode_to_vec(),
        )
        .is_err()
    {
        return Err(invalid_data());
    }
    Ok(())
}

fn check_utxos(
    list: &wire::GetAddressUtxosReplyList,
    addresses: &HashSet<String>,
    start_height: u64,
    max_entries: u32,
) -> Result<(), Status> {
    if max_entries != 0 && list.address_utxos.len() > max_entries as usize {
        return Err(invalid_data());
    }
    let mut previous_height = None;
    for utxo in &list.address_utxos {
        check_utxo(utxo, addresses, start_height)?;
        if previous_height.is_some_and(|prior| utxo.height < prior) {
            return Err(invalid_data());
        }
        previous_height = Some(utxo.height);
    }
    Ok(())
}

fn check_info(info: &wire::LightdInfo) -> Result<(), Status> {
    if info.chain_name != "test" || !info.taddr_support || info.block_height > u32::MAX as u64 {
        return Err(invalid_data());
    }
    Ok(())
}

/// A numeric loopback endpoint is the only accepted backend destination. It
/// never uses a resolver, public URL, Unix socket supplied by a caller, or
/// credentials from request metadata.
#[derive(Clone)]
pub struct ZebraReadOnly {
    endpoint: Endpoint,
    snapshot_source: Option<Arc<dyn MempoolSnapshotSource>>,
}

impl ZebraReadOnly {
    pub fn new(addr: SocketAddr) -> Result<Self, Status> {
        if !addr.ip().is_loopback() || addr.port() == 0 {
            return Err(Status::invalid_argument("Wallet backend must be loopback."));
        }
        let endpoint = Endpoint::from_shared(format!("http://{addr}"))
            .map_err(|_| Status::invalid_argument("Invalid wallet backend."))?;
        Ok(Self {
            endpoint,
            snapshot_source: None,
        })
    }

    pub fn with_snapshot_source(mut self, source: Arc<dyn MempoolSnapshotSource>) -> Self {
        self.snapshot_source = Some(source);
        self
    }

    async fn client(
        &self,
    ) -> Result<wire::compact_tx_streamer_client::CompactTxStreamerClient<Channel>, Status> {
        let channel = self.endpoint.connect().await.map_err(|_| unavailable())?;
        let mut client = wire::compact_tx_streamer_client::CompactTxStreamerClient::new(channel);
        // No caller selection reaches a misconfigured mainnet or other node.
        // This public request contains no address, txid, or wallet state.
        let info = client
            .get_lightd_info(wire::Empty {})
            .await
            .map_err(sanitize)?
            .into_inner();
        check_info(&info)?;
        Ok(client)
    }

    async fn observe_tip(
        client: &mut wire::compact_tx_streamer_client::CompactTxStreamerClient<Channel>,
    ) -> Result<NodeReadContext, Status> {
        let tip = client
            .get_latest_block(wire::ChainSpec {})
            .await
            .map_err(sanitize)?
            .into_inner();
        NodeReadContext::from_block_id(&tip)
    }
}

fn checked_blocks(
    input: tonic::Streaming<wire::CompactBlock>,
    start: u32,
    end: u32,
    nullifiers_only: bool,
) -> ReadStream<wire::CompactBlock> {
    let continuity = Arc::new(Mutex::new(Some(if nullifiers_only {
        RangeContinuity::new_nullifiers_only(start, end, None)
    } else {
        RangeContinuity::new(start, end, None)
    })));
    let check_each = continuity.clone();
    let blocks = input.map(move |item| {
        let block = item.map_err(sanitize)?;
        let mut state = check_each.lock().map_err(|_| invalid_data())?;
        state.as_mut().ok_or_else(invalid_data)?.observe(&block)?;
        Ok(block)
    });
    // A transport EOF before the requested end height is an error item. A
    // consumer must observe the terminal gRPC status before accepting a range.
    let terminal = stream::once(async move {
        let mut state = continuity.lock().map_err(|_| invalid_data())?;
        state.take().ok_or_else(invalid_data)?.finish()
    })
    .filter_map(|result| async move { result.err().map(Err) });
    Box::pin(blocks.chain(terminal))
}

#[tonic::async_trait]
impl wire::compact_tx_streamer_server::CompactTxStreamer for ZebraReadOnly {
    async fn get_latest_block(
        &self,
        request: Request<wire::ChainSpec>,
    ) -> Result<Response<wire::BlockId>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetLatestBlock, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let response = client
            .get_latest_block(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_block_id(&response)?;
        Ok(Response::new(response))
    }
    async fn get_block(
        &self,
        request: Request<wire::BlockId>,
    ) -> Result<Response<wire::CompactBlock>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetBlock, &request.encode_to_vec())?;
        let selected = request.clone();
        let mut client = self.client().await?;
        let response = client
            .get_block(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_selected_block(&response, &selected)?;
        Ok(Response::new(response))
    }
    async fn get_block_nullifiers(
        &self,
        request: Request<wire::BlockId>,
    ) -> Result<Response<wire::CompactBlock>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetBlockNullifiers, &request.encode_to_vec())?;
        let selected = request.clone();
        let mut client = self.client().await?;
        let response = client
            .get_block_nullifiers(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        validate_nullifier_only_block(&response)?;
        if (!selected.hash.is_empty() && response.hash != selected.hash)
            || (selected.hash.is_empty() && response.height != selected.height)
        {
            return Err(invalid_data());
        }
        Ok(Response::new(response))
    }

    type GetBlockRangeStream = ReadStream<wire::CompactBlock>;
    async fn get_block_range(
        &self,
        request: Request<wire::BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetBlockRange, &request.encode_to_vec())?;
        let start = request.start.as_ref().ok_or_else(invalid_data)?.height as u32;
        let end = request.end.as_ref().ok_or_else(invalid_data)?.height as u32;
        let mut client = self.client().await?;
        let input = client
            .get_block_range(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        Ok(Response::new(checked_blocks(input, start, end, false)))
    }

    type GetBlockRangeNullifiersStream = ReadStream<wire::CompactBlock>;
    async fn get_block_range_nullifiers(
        &self,
        request: Request<wire::BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeNullifiersStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(
            ReadMethod::GetBlockRangeNullifiers,
            &request.encode_to_vec(),
        )?;
        let start = request.start.as_ref().ok_or_else(invalid_data)?.height as u32;
        let end = request.end.as_ref().ok_or_else(invalid_data)?.height as u32;
        let mut client = self.client().await?;
        let input = client
            .get_block_range_nullifiers(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        Ok(Response::new(checked_blocks(input, start, end, true)))
    }

    async fn get_transaction(
        &self,
        request: Request<wire::TxFilter>,
    ) -> Result<Response<wire::RawTransaction>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetTransaction, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let context = Self::observe_tip(&mut client).await?;
        let response = client
            .get_transaction(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_raw_transaction(&response)?;
        contextual_response(response, context)
    }
    async fn send_transaction(
        &self,
        _: Request<wire::RawTransaction>,
    ) -> Result<Response<wire::SendResponse>, Status> {
        Err(Status::permission_denied(
            "Transaction submission is unavailable.",
        ))
    }
    type GetTaddressTxidsStream = ReadStream<wire::RawTransaction>;
    async fn get_taddress_txids(
        &self,
        request: Request<wire::TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTxidsStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetTaddressTxids, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let context = Self::observe_tip(&mut client).await?;
        let input = client
            .get_taddress_txids(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        let output = input.map(|item| {
            let value = item.map_err(sanitize)?;
            check_raw_transaction(&value)?;
            Ok(value)
        });
        contextual_response(Box::pin(output), context)
    }
    type GetTaddressTransactionsStream = ReadStream<wire::RawTransaction>;
    async fn get_taddress_transactions(
        &self,
        request: Request<wire::TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTransactionsStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(
            ReadMethod::GetTaddressTransactions,
            &request.encode_to_vec(),
        )?;
        let mut client = self.client().await?;
        let context = Self::observe_tip(&mut client).await?;
        let input = client
            .get_taddress_transactions(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        let output = input.map(|item| {
            let value = item.map_err(sanitize)?;
            check_raw_transaction(&value)?;
            Ok(value)
        });
        contextual_response(Box::pin(output), context)
    }
    async fn get_taddress_balance(
        &self,
        request: Request<wire::AddressList>,
    ) -> Result<Response<wire::Balance>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetTaddressBalance, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let context = Self::observe_tip(&mut client).await?;
        let response = client
            .get_taddress_balance(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_balance(&response)?;
        contextual_response(response, context)
    }

    async fn get_taddress_balance_stream(
        &self,
        request: Request<tonic::Streaming<wire::Address>>,
    ) -> Result<Response<wire::Balance>, Status> {
        let mut incoming = request.into_inner();
        let mut addresses = Vec::new();
        let mut seen = HashSet::new();
        while let Some(value) = incoming.message().await.map_err(sanitize)? {
            validate_client_stream_address(&value.encode_to_vec())?;
            if addresses.len() >= 10_000 || !seen.insert(value.address.clone()) {
                return Err(Status::invalid_argument(
                    "Invalid testnet wallet read request.",
                ));
            }
            addresses.push(value);
        }
        if addresses.is_empty() {
            return Err(Status::invalid_argument(
                "Invalid testnet wallet read request.",
            ));
        }
        let mut client = self.client().await?;
        let context = Self::observe_tip(&mut client).await?;
        let response = client
            .get_taddress_balance_stream(stream::iter(addresses))
            .await
            .map_err(sanitize)?
            .into_inner();
        check_balance(&response)?;
        contextual_response(response, context)
    }

    type GetMempoolTxStream = ReadStream<wire::CompactTx>;
    async fn get_mempool_tx(
        &self,
        request: Request<wire::Exclude>,
    ) -> Result<Response<Self::GetMempoolTxStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetMempoolTx, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let context = Self::observe_tip(&mut client).await?;
        let input = client
            .get_mempool_tx(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        let output = input.map(|item| {
            let value = item.map_err(sanitize)?;
            validate_compact_tx(&value)?;
            Ok(value)
        });
        contextual_response(Box::pin(output), context)
    }
    type GetMempoolStreamStream = ReadStream<wire::RawTransaction>;
    async fn get_mempool_stream(
        &self,
        request: Request<wire::Empty>,
    ) -> Result<Response<Self::GetMempoolStreamStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetMempoolStream, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let context = Self::observe_tip(&mut client).await?;
        let input = client
            .get_mempool_stream(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        let output = input.map(|item| {
            let value = item.map_err(sanitize)?;
            check_raw_transaction(&value)?;
            Ok(value)
        });
        contextual_response(Box::pin(output), context)
    }
    async fn get_tree_state(
        &self,
        request: Request<wire::BlockId>,
    ) -> Result<Response<wire::TreeState>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetTreeState, &request.encode_to_vec())?;
        let selected = request.clone();
        let mut client = self.client().await?;
        let response = client
            .get_tree_state(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_selected_tree_state(&response, &selected)?;
        Ok(Response::new(response))
    }
    async fn get_latest_tree_state(
        &self,
        request: Request<wire::Empty>,
    ) -> Result<Response<wire::TreeState>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetLatestTreeState, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let response = client
            .get_latest_tree_state(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_tree_state(&response)?;
        Ok(Response::new(response))
    }
    type GetSubtreeRootsStream = ReadStream<wire::SubtreeRoot>;
    async fn get_subtree_roots(
        &self,
        request: Request<wire::GetSubtreeRootsArg>,
    ) -> Result<Response<Self::GetSubtreeRootsStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetSubtreeRoots, &request.encode_to_vec())?;
        let mut continuity = SubtreeContinuity::new(request.start_index, request.max_entries);
        let mut client = self.client().await?;
        let context = Self::observe_tip(&mut client).await?;
        let input = client
            .get_subtree_roots(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        let output = input.map(move |item| {
            let value = item.map_err(sanitize)?;
            continuity.observe(&value)?;
            Ok(value)
        });
        contextual_response(Box::pin(output), context)
    }
    async fn get_address_utxos(
        &self,
        request: Request<wire::GetAddressUtxosArg>,
    ) -> Result<Response<wire::GetAddressUtxosReplyList>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetAddressUtxos, &request.encode_to_vec())?;
        let addresses = request.addresses.iter().cloned().collect::<HashSet<_>>();
        let start_height = request.start_height;
        let max_entries = request.max_entries;
        let mut client = self.client().await?;
        let context = Self::observe_tip(&mut client).await?;
        let response = client
            .get_address_utxos(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_utxos(&response, &addresses, start_height, max_entries)?;
        contextual_response(response, context)
    }
    type GetAddressUtxosStreamStream = ReadStream<wire::GetAddressUtxosReply>;
    async fn get_address_utxos_stream(
        &self,
        request: Request<wire::GetAddressUtxosArg>,
    ) -> Result<Response<Self::GetAddressUtxosStreamStream>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetAddressUtxosStream, &request.encode_to_vec())?;
        let addresses = request.addresses.iter().cloned().collect::<HashSet<_>>();
        let start_height = request.start_height;
        let max_entries = request.max_entries;
        let mut client = self.client().await?;
        let context = Self::observe_tip(&mut client).await?;
        let input = client
            .get_address_utxos_stream(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        let mut previous_height = None;
        let mut count = 0_u64;
        let output = input.map(move |item| {
            let value = item.map_err(sanitize)?;
            check_utxo(&value, &addresses, start_height)?;
            if previous_height.is_some_and(|prior| value.height < prior) {
                return Err(invalid_data());
            }
            previous_height = Some(value.height);
            count = count.checked_add(1).ok_or_else(invalid_data)?;
            if max_entries != 0 && count > u64::from(max_entries) {
                return Err(invalid_data());
            }
            Ok(value)
        });
        contextual_response(Box::pin(output), context)
    }
    async fn get_lightd_info(
        &self,
        request: Request<wire::Empty>,
    ) -> Result<Response<wire::LightdInfo>, Status> {
        let request = request.into_inner();
        validate_unary_request(ReadMethod::GetLightdInfo, &request.encode_to_vec())?;
        let mut client = self.client().await?;
        let context = Self::observe_tip(&mut client).await?;
        let response = client
            .get_lightd_info(request)
            .await
            .map_err(sanitize)?
            .into_inner();
        check_info(&response)?;
        contextual_response(response, context)
    }
    async fn ping(
        &self,
        _: Request<wire::Duration>,
    ) -> Result<Response<wire::PingResponse>, Status> {
        Err(Status::permission_denied(
            "Testing methods are unavailable.",
        ))
    }
}

#[tonic::async_trait]
impl snapshot_wire::snapshot_read_server::SnapshotRead for ZebraReadOnly {
    type GetMempoolSnapshotStream = ReadStream<snapshot_wire::SnapshotItem>;

    async fn get_mempool_snapshot(
        &self,
        request: Request<snapshot_wire::SnapshotRequest>,
    ) -> Result<Response<Self::GetMempoolSnapshotStream>, Status> {
        validate_unary_request(
            ReadMethod::GetMempoolSnapshot,
            &request.into_inner().encode_to_vec(),
        )?;
        let source = self.snapshot_source.as_ref().ok_or_else(unavailable)?;
        let mut client = self.client().await?;
        let before = client
            .get_latest_block(wire::ChainSpec {})
            .await
            .map_err(sanitize)?
            .into_inner();
        check_block_id(&before)?;
        let snapshot = source.mempool_snapshot().await.map_err(sanitize)?;
        if snapshot.tip.height > u32::MAX as u64 || snapshot.tip.hash.len() != 32 {
            return Err(invalid_data());
        }
        let after = client
            .get_latest_block(wire::ChainSpec {})
            .await
            .map_err(sanitize)?
            .into_inner();
        check_block_id(&after)?;
        if before.height != snapshot.tip.height
            || before.hash != snapshot.tip.hash
            || after != before
        {
            return Err(Status::aborted(
                "Wallet node tip changed during the mempool read.",
            ));
        }
        let first = snapshot_wire::SnapshotItem {
            body: Some(snapshot_wire::snapshot_item::Body::Tip(snapshot.tip)),
        };
        let items = std::iter::once(Ok(first)).chain(snapshot.txids.into_iter().map(|txid| {
            Ok(snapshot_wire::SnapshotItem {
                body: Some(snapshot_wire::snapshot_item::Body::Txid(txid.to_vec())),
            })
        }));
        Ok(Response::new(Box::pin(stream::iter(items))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snapshot_wire::snapshot_read_server::SnapshotRead;
    use wire::compact_tx_streamer_server::CompactTxStreamer;
    use zrpc_protocol::PREVIEW_TESTNET_ADDRESS;

    #[derive(Clone)]
    struct ObservationNode {
        calls: Arc<Mutex<Vec<&'static str>>>,
        malformed_tip: bool,
    }

    struct ObservationCall<T> {
        node: ObservationNode,
        name: &'static str,
        value: T,
    }

    impl<Q: Send + 'static, T: Clone + Send + 'static> tonic::server::UnaryService<Q>
        for ObservationCall<T>
    {
        type Response = T;
        type Future = tonic::codegen::BoxFuture<Response<T>, Status>;

        fn call(&mut self, _: Request<Q>) -> Self::Future {
            self.node.calls.lock().unwrap().push(self.name);
            let mut response = Response::new(self.value.clone());
            // Upstream metadata is not a wrapper-produced observation.
            response
                .metadata_mut()
                .insert("x-zrpc-node-context", "atomic-snapshot".parse().unwrap());
            Box::pin(async move { Ok(response) })
        }
    }

    impl tonic::server::NamedService for ObservationNode {
        const NAME: &'static str = "cash.z.wallet.sdk.rpc.CompactTxStreamer";
    }

    impl tonic::codegen::Service<tonic::codegen::http::Request<tonic::body::Body>> for ObservationNode {
        type Response = tonic::codegen::http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(
            &mut self,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(
            &mut self,
            request: tonic::codegen::http::Request<tonic::body::Body>,
        ) -> Self::Future {
            let node = self.clone();
            Box::pin(async move {
                let response = match request.uri().path() {
                    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo" => {
                        let call = ObservationCall {
                            node,
                            name: "info",
                            value: wire::LightdInfo {
                                chain_name: "test".into(),
                                taddr_support: true,
                                block_height: 42,
                                ..Default::default()
                            },
                        };
                        tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                            wire::LightdInfo,
                            wire::Empty,
                        >::default())
                        .unary(call, request)
                        .await
                    }
                    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock" => {
                        let value = wire::BlockId {
                            height: 42,
                            hash: vec![7; if node.malformed_tip { 31 } else { 32 }],
                        };
                        let call = ObservationCall {
                            node,
                            name: "tip",
                            value,
                        };
                        tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                            wire::BlockId,
                            wire::ChainSpec,
                        >::default())
                        .unary(call, request)
                        .await
                    }
                    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTaddressBalance" => {
                        let call = ObservationCall {
                            node,
                            name: "balance",
                            value: wire::Balance { value_zat: 0 },
                        };
                        tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                            wire::Balance,
                            wire::AddressList,
                        >::default())
                        .unary(call, request)
                        .await
                    }
                    _ => tonic::codegen::http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(tonic::body::Body::empty())
                        .unwrap(),
                };
                Ok(response)
            })
        }
    }

    #[tokio::test]
    async fn balance_observes_tip_before_read_and_rejects_invalid_tip_before_private_dispatch() {
        for malformed_tip in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let calls = Arc::new(Mutex::new(Vec::new()));
            let service = ObservationNode {
                calls: calls.clone(),
                malformed_tip,
            };
            let incoming = stream::unfold(listener, |listener| async move {
                let connection = listener.accept().await.map(|(stream, _)| stream);
                Some((connection, listener))
            });
            let server = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(service)
                    .serve_with_incoming(Box::pin(incoming))
                    .await
                    .unwrap();
            });
            let backend = ZebraReadOnly::new(address).unwrap();
            let mut request = Request::new(wire::AddressList {
                addresses: vec![PREVIEW_TESTNET_ADDRESS.to_owned()],
            });
            request
                .metadata_mut()
                .insert("x-zrpc-node-height", "99".parse().unwrap());
            let result = backend.get_taddress_balance(request).await;
            if malformed_tip {
                assert_eq!(result.unwrap_err().code(), tonic::Code::DataLoss);
                assert_eq!(*calls.lock().unwrap(), vec!["info", "tip"]);
            } else {
                let response = result.unwrap();
                assert_eq!(response.get_ref().value_zat, 0);
                assert_eq!(
                    NodeReadContext::read_metadata(response.metadata()).unwrap(),
                    Some(NodeReadContext {
                        height: 42,
                        hash: [7; 32]
                    })
                );
                assert_eq!(*calls.lock().unwrap(), vec!["info", "tip", "balance"]);
            }
            server.abort();
            let _ = server.await;
        }
    }

    #[test]
    fn selected_block_must_match_height_or_hash() {
        let block = wire::CompactBlock {
            height: 42,
            hash: vec![7; 32],
            prev_hash: vec![6; 32],
            chain_metadata: Some(wire::ChainMetadata::default()),
            ..Default::default()
        };
        assert!(
            check_selected_block(
                &block,
                &wire::BlockId {
                    height: 42,
                    hash: vec![]
                }
            )
            .is_ok()
        );
        assert!(
            check_selected_block(
                &block,
                &wire::BlockId {
                    height: 41,
                    hash: vec![]
                }
            )
            .is_err()
        );
        assert!(
            check_selected_block(
                &block,
                &wire::BlockId {
                    height: 0,
                    hash: vec![7; 32]
                }
            )
            .is_ok()
        );
        assert!(
            check_selected_block(
                &block,
                &wire::BlockId {
                    height: 0,
                    hash: vec![8; 32]
                }
            )
            .is_err()
        );
    }

    #[test]
    fn utxo_set_must_match_requested_addresses_heights_order_and_count() {
        let addresses = HashSet::from([PREVIEW_TESTNET_ADDRESS.to_owned()]);
        let mut first = wire::GetAddressUtxosReply {
            address: PREVIEW_TESTNET_ADDRESS.to_owned(),
            txid: vec![1; 32],
            index: 0,
            script: vec![],
            value_zat: 10,
            height: 100,
        };
        let second = wire::GetAddressUtxosReply {
            height: 101,
            ..first.clone()
        };
        let list = wire::GetAddressUtxosReplyList {
            address_utxos: vec![first.clone(), second],
        };
        assert!(check_utxos(&list, &addresses, 100, 0).is_ok());
        assert!(check_utxos(&list, &addresses, 100, 1).is_err());
        assert!(check_utxos(&list, &addresses, 101, 0).is_err());
        let reversed = wire::GetAddressUtxosReplyList {
            address_utxos: list.address_utxos.iter().cloned().rev().collect(),
        };
        assert!(check_utxos(&reversed, &addresses, 100, 0).is_err());
        first.address = "t1Yzt1YSjHd8gdn6zaraWSpnbK7Sx9eWZ4u".into();
        assert!(check_utxo(&first, &addresses, 100).is_err());
    }

    #[test]
    fn selected_tree_state_uses_display_to_internal_hash_order() {
        let internal: Vec<u8> = (0..32).collect();
        let display: Vec<u8> = internal.iter().rev().copied().collect();
        let tree = wire::TreeState {
            network: "test".into(),
            height: 42,
            hash: hex::encode(display),
            ..Default::default()
        };
        assert!(
            check_selected_tree_state(
                &tree,
                &wire::BlockId {
                    height: 42,
                    hash: vec![]
                }
            )
            .is_ok()
        );
        assert!(
            check_selected_tree_state(
                &tree,
                &wire::BlockId {
                    height: 41,
                    hash: vec![]
                }
            )
            .is_err()
        );
        assert!(
            check_selected_tree_state(
                &tree,
                &wire::BlockId {
                    height: 0,
                    hash: internal.clone()
                }
            )
            .is_ok()
        );
        let mut wrong = internal;
        wrong[0] ^= 1;
        assert!(
            check_selected_tree_state(
                &tree,
                &wire::BlockId {
                    height: 0,
                    hash: wrong
                }
            )
            .is_err()
        );
    }

    #[test]
    fn backend_requires_numeric_loopback() {
        assert!(ZebraReadOnly::new("127.0.0.1:9067".parse().unwrap()).is_ok());
        assert!(ZebraReadOnly::new("[::1]:9067".parse().unwrap()).is_ok());
        assert!(ZebraReadOnly::new("0.0.0.0:9067".parse().unwrap()).is_err());
        assert!(ZebraReadOnly::new("192.0.2.1:9067".parse().unwrap()).is_err());
        assert!(ZebraReadOnly::new("127.0.0.1:0".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn submission_and_ping_cannot_reach_backend() {
        let backend = ZebraReadOnly::new("127.0.0.1:9067".parse().unwrap()).unwrap();
        assert_eq!(
            backend
                .send_transaction(Request::new(wire::RawTransaction::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            backend
                .ping(Request::new(wire::Duration::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn snapshot_requires_an_internal_source_before_connecting_to_zebra() {
        let backend = ZebraReadOnly::new("127.0.0.1:9067".parse().unwrap()).unwrap();
        assert_eq!(
            backend
                .get_mempool_snapshot(Request::new(snapshot_wire::SnapshotRequest {}))
                .await
                .err()
                .unwrap()
                .code(),
            tonic::Code::Unavailable
        );
    }
}
