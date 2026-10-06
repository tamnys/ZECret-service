//! Pinned Zcash testnet lightwallet wire types. This crate grants no transport
//! or request authority; client and server validate each method separately.
#![forbid(unsafe_code)]

pub mod wire {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}
pub mod snapshot_wire {
    tonic::include_proto!("zrpc.wallet.snapshot.v1");
}
pub mod local_status_wire {
    tonic::include_proto!("zrpc.wallet.local.v1");
}

pub mod backend;
mod operation;
pub use operation::WalletReadRequest;
mod validation;
pub use validation::{
    RangeContinuity, SubtreeContinuity, validate_client_stream_address, validate_compact_block,
    validate_compact_tx, validate_nullifier_only_block, validate_unary_request,
};

/// The complete read-only subset of the pinned Zebra service. A method must
/// appear here before either bridge can route it; generated service methods
/// alone confer no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadMethod {
    GetLatestBlock,
    GetBlock,
    GetBlockNullifiers,
    GetBlockRange,
    GetBlockRangeNullifiers,
    GetTransaction,
    GetTaddressTxids,
    GetTaddressTransactions,
    GetTaddressBalance,
    GetTaddressBalanceStream,
    GetMempoolTx,
    GetMempoolStream,
    GetMempoolSnapshot,
    GetTreeState,
    GetLatestTreeState,
    GetSubtreeRoots,
    GetAddressUtxos,
    GetAddressUtxosStream,
    GetLightdInfo,
}

impl ReadMethod {
    pub const ALL: [Self; 19] = [
        Self::GetLatestBlock,
        Self::GetBlock,
        Self::GetBlockNullifiers,
        Self::GetBlockRange,
        Self::GetBlockRangeNullifiers,
        Self::GetTransaction,
        Self::GetTaddressTxids,
        Self::GetTaddressTransactions,
        Self::GetTaddressBalance,
        Self::GetTaddressBalanceStream,
        Self::GetMempoolTx,
        Self::GetMempoolStream,
        Self::GetMempoolSnapshot,
        Self::GetTreeState,
        Self::GetLatestTreeState,
        Self::GetSubtreeRoots,
        Self::GetAddressUtxos,
        Self::GetAddressUtxosStream,
        Self::GetLightdInfo,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::GetLatestBlock => "GetLatestBlock",
            Self::GetBlock => "GetBlock",
            Self::GetBlockNullifiers => "GetBlockNullifiers",
            Self::GetBlockRange => "GetBlockRange",
            Self::GetBlockRangeNullifiers => "GetBlockRangeNullifiers",
            Self::GetTransaction => "GetTransaction",
            Self::GetTaddressTxids => "GetTaddressTxids",
            Self::GetTaddressTransactions => "GetTaddressTransactions",
            Self::GetTaddressBalance => "GetTaddressBalance",
            Self::GetTaddressBalanceStream => "GetTaddressBalanceStream",
            Self::GetMempoolTx => "GetMempoolTx",
            Self::GetMempoolStream => "GetMempoolStream",
            Self::GetMempoolSnapshot => "GetMempoolSnapshot",
            Self::GetTreeState => "GetTreeState",
            Self::GetLatestTreeState => "GetLatestTreeState",
            Self::GetSubtreeRoots => "GetSubtreeRoots",
            Self::GetAddressUtxos => "GetAddressUtxos",
            Self::GetAddressUtxosStream => "GetAddressUtxosStream",
            Self::GetLightdInfo => "GetLightdInfo",
        }
    }

    pub fn path(self) -> String {
        if self == Self::GetMempoolSnapshot {
            format!("/zrpc.wallet.snapshot.v1.SnapshotRead/{}", self.name())
        } else {
            format!("/cash.z.wallet.sdk.rpc.CompactTxStreamer/{}", self.name())
        }
    }

    pub fn from_path(path: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|method| method.path() == path)
    }

    pub fn has_streaming_response(self) -> bool {
        matches!(
            self,
            Self::GetBlockRange
                | Self::GetBlockRangeNullifiers
                | Self::GetTaddressTxids
                | Self::GetTaddressTransactions
                | Self::GetMempoolTx
                | Self::GetMempoolStream
                | Self::GetMempoolSnapshot
                | Self::GetSubtreeRoots
                | Self::GetAddressUtxosStream
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ReadMethod;
    use std::collections::BTreeSet;

    #[test]
    fn every_pinned_service_method_has_an_explicit_read_or_deny_decision() {
        let source = include_str!("../proto/service.proto");
        let defined: BTreeSet<_> = source
            .lines()
            .filter_map(|line| line.trim().strip_prefix("rpc "))
            .map(|declaration| declaration.split('(').next().unwrap())
            .collect();
        let allowed: BTreeSet<_> = ReadMethod::ALL
            .iter()
            .filter(|method| **method != ReadMethod::GetMempoolSnapshot)
            .map(|method| method.name())
            .collect();
        let denied: BTreeSet<_> = ["SendTransaction", "Ping"].into_iter().collect();
        assert_eq!(defined, allowed.union(&denied).copied().collect());
        assert!(allowed.is_disjoint(&denied));
        assert!(
            ReadMethod::from_path("/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction")
                .is_none()
        );
        assert!(ReadMethod::from_path("/cash.z.wallet.sdk.rpc.CompactTxStreamer/Ping").is_none());
        assert!(
            ReadMethod::from_path("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo")
                .is_none()
        );
        assert!(ReadMethod::from_path("/rpc").is_none());
        assert_eq!(
            ReadMethod::from_path("/zrpc.wallet.snapshot.v1.SnapshotRead/GetMempoolSnapshot"),
            Some(ReadMethod::GetMempoolSnapshot)
        );
        assert_eq!(
            include_str!("../proto/snapshot.proto")
                .lines()
                .filter(|line| line.trim().starts_with("rpc "))
                .count(),
            1
        );
    }
}
