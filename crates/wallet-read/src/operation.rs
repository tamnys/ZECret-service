//! Typed wallet requests. No generated submission or testing method is
//! representable here, and every value is validated before ticket selection.

use crate::{ReadMethod, snapshot_wire, validate_unary_request, wire};
use prost::Message;
use tonic::Status;

pub enum WalletReadRequest {
    LatestBlock(wire::ChainSpec),
    Block(wire::BlockId),
    BlockNullifiers(wire::BlockId),
    BlockRange(wire::BlockRange),
    BlockRangeNullifiers(wire::BlockRange),
    Transaction(wire::TxFilter),
    TaddressTxids(wire::TransparentAddressBlockFilter),
    TaddressTransactions(wire::TransparentAddressBlockFilter),
    TaddressBalance(wire::AddressList),
    TaddressBalanceStream(Vec<wire::Address>),
    MempoolTx(wire::Exclude),
    MempoolStream(wire::Empty),
    MempoolSnapshot(snapshot_wire::SnapshotRequest),
    TreeState(wire::BlockId),
    LatestTreeState(wire::Empty),
    SubtreeRoots(wire::GetSubtreeRootsArg),
    AddressUtxos(wire::GetAddressUtxosArg),
    AddressUtxosStream(wire::GetAddressUtxosArg),
    LightdInfo(wire::Empty),
}

impl WalletReadRequest {
    pub fn method(&self) -> ReadMethod {
        match self {
            Self::LatestBlock(_) => ReadMethod::GetLatestBlock,
            Self::Block(_) => ReadMethod::GetBlock,
            Self::BlockNullifiers(_) => ReadMethod::GetBlockNullifiers,
            Self::BlockRange(_) => ReadMethod::GetBlockRange,
            Self::BlockRangeNullifiers(_) => ReadMethod::GetBlockRangeNullifiers,
            Self::Transaction(_) => ReadMethod::GetTransaction,
            Self::TaddressTxids(_) => ReadMethod::GetTaddressTxids,
            Self::TaddressTransactions(_) => ReadMethod::GetTaddressTransactions,
            Self::TaddressBalance(_) => ReadMethod::GetTaddressBalance,
            Self::TaddressBalanceStream(_) => ReadMethod::GetTaddressBalanceStream,
            Self::MempoolTx(_) => ReadMethod::GetMempoolTx,
            Self::MempoolStream(_) => ReadMethod::GetMempoolStream,
            Self::MempoolSnapshot(_) => ReadMethod::GetMempoolSnapshot,
            Self::TreeState(_) => ReadMethod::GetTreeState,
            Self::LatestTreeState(_) => ReadMethod::GetLatestTreeState,
            Self::SubtreeRoots(_) => ReadMethod::GetSubtreeRoots,
            Self::AddressUtxos(_) => ReadMethod::GetAddressUtxos,
            Self::AddressUtxosStream(_) => ReadMethod::GetAddressUtxosStream,
            Self::LightdInfo(_) => ReadMethod::GetLightdInfo,
        }
    }

    pub fn validate(&self) -> Result<(), Status> {
        let method = self.method();
        let bytes = match self {
            Self::LatestBlock(value) => value.encode_to_vec(),
            Self::Block(value) | Self::BlockNullifiers(value) | Self::TreeState(value) => {
                value.encode_to_vec()
            }
            Self::BlockRange(value) | Self::BlockRangeNullifiers(value) => value.encode_to_vec(),
            Self::Transaction(value) => value.encode_to_vec(),
            Self::TaddressTxids(value) | Self::TaddressTransactions(value) => value.encode_to_vec(),
            Self::TaddressBalance(value) => value.encode_to_vec(),
            Self::TaddressBalanceStream(addresses) => {
                let list = wire::AddressList {
                    addresses: addresses
                        .iter()
                        .map(|value| value.address.clone())
                        .collect(),
                };
                validate_unary_request(ReadMethod::GetTaddressBalance, &list.encode_to_vec())?;
                return Ok(());
            }
            Self::MempoolTx(value) => value.encode_to_vec(),
            Self::MempoolStream(value) | Self::LatestTreeState(value) | Self::LightdInfo(value) => {
                value.encode_to_vec()
            }
            Self::MempoolSnapshot(value) => value.encode_to_vec(),
            Self::SubtreeRoots(value) => value.encode_to_vec(),
            Self::AddressUtxos(value) | Self::AddressUtxosStream(value) => value.encode_to_vec(),
        };
        validate_unary_request(method, &bytes).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_read_method_has_a_typed_operation() {
        let methods = [
            WalletReadRequest::LatestBlock(wire::ChainSpec {}),
            WalletReadRequest::Block(wire::BlockId::default()),
            WalletReadRequest::BlockNullifiers(wire::BlockId::default()),
            WalletReadRequest::BlockRange(wire::BlockRange::default()),
            WalletReadRequest::BlockRangeNullifiers(wire::BlockRange::default()),
            WalletReadRequest::Transaction(wire::TxFilter::default()),
            WalletReadRequest::TaddressTxids(wire::TransparentAddressBlockFilter::default()),
            WalletReadRequest::TaddressTransactions(wire::TransparentAddressBlockFilter::default()),
            WalletReadRequest::TaddressBalance(wire::AddressList::default()),
            WalletReadRequest::TaddressBalanceStream(vec![]),
            WalletReadRequest::MempoolTx(wire::Exclude::default()),
            WalletReadRequest::MempoolStream(wire::Empty {}),
            WalletReadRequest::MempoolSnapshot(snapshot_wire::SnapshotRequest {}),
            WalletReadRequest::TreeState(wire::BlockId::default()),
            WalletReadRequest::LatestTreeState(wire::Empty {}),
            WalletReadRequest::SubtreeRoots(wire::GetSubtreeRootsArg::default()),
            WalletReadRequest::AddressUtxos(wire::GetAddressUtxosArg::default()),
            WalletReadRequest::AddressUtxosStream(wire::GetAddressUtxosArg::default()),
            WalletReadRequest::LightdInfo(wire::Empty {}),
        ];
        let represented: std::collections::BTreeSet<_> = methods
            .iter()
            .map(|request| request.method().name())
            .collect();
        let allowed: std::collections::BTreeSet<_> =
            ReadMethod::ALL.iter().map(|method| method.name()).collect();
        assert_eq!(represented, allowed);
    }
}
