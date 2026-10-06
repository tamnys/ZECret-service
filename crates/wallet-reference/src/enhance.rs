//! Process the maintained wallet backend's raw-transaction enhancement,
//! status, and mined transparent-history requests. Other transparent filters
//! remain explicit in the report until their full protocol contract is met.

use rand::{rand_core::UnwrapErr, rngs::SysRng};
use rusqlite::Connection;
use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use zcash_client_backend::{
    data_api::wallet::decrypt_and_store_transaction,
    data_api::{
        OutputStatusFilter, TransactionDataRequest, TransactionStatus, TransactionStatusFilter,
        TransactionsInvolvingAddress, WalletRead, WalletWrite,
    },
    proto::{
        compact_formats::CompactBlock,
        service::{BlockId, BlockRange, RawTransaction, TransparentAddressBlockFilter, TxFilter},
    },
};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_keys::encoding::encode_transparent_address_p;
use zcash_primitives::{block::BlockHash, transaction::Transaction};
use zcash_protocol::{
    TxId,
    consensus::{BlockHeight, BranchId, Network},
};
use zrpc_wallet_sdk::bridge::LocalWalletAdapter;
use zrpc_wallet_sdk::bridge::MaintainedScannerClient;

#[derive(Default)]
pub struct EnhancementReport {
    pub enhanced: u64,
    pub status_checks: u64,
    /// Mined address-history ranges imported after checking the scanned anchor.
    pub mined_transparent_history_reads: u64,
    /// Mined history was read, but a complete pending-mempool view was unavailable.
    pub pending_unverified_checks: u64,
    /// Address checks completed against the finite local-node mempool snapshot.
    pub pending_snapshot_checks: u64,
    /// The request filter or range could not be handled by this reader.
    pub unsupported_history_requests: u64,
    pub remaining_requests: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChainTxState {
    Pending,
    Mined(BlockHeight),
    Orphaned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MinedHistoryKind {
    Complete,
    PendingUnresolved,
}

impl ChainTxState {
    fn from_wire_height(height: u64) -> Result<Self, &'static str> {
        match height {
            0 => Ok(Self::Pending),
            u64::MAX => Ok(Self::Orphaned),
            other => u32::try_from(other)
                .map(|value| Self::Mined(BlockHeight::from_u32(value)))
                .map_err(|_| "transaction height is invalid"),
        }
    }

    fn wallet_status(self) -> TransactionStatus {
        match self {
            Self::Pending | Self::Orphaned => TransactionStatus::NotInMainChain,
            Self::Mined(height) => TransactionStatus::Mined(height),
        }
    }

    fn mined_height(self) -> Option<BlockHeight> {
        match self {
            Self::Mined(height) => Some(height),
            Self::Pending | Self::Orphaned => None,
        }
    }
}

type LocalWallet = WalletDb<Connection, Network, SystemClock, UnwrapErr<SysRng>>;

fn decode_checked_transaction(
    raw: &RawTransaction,
    requested: TxId,
    parse_height: BlockHeight,
) -> Result<Transaction, &'static str> {
    let transaction = decode_transaction(raw, parse_height)?;
    if transaction.txid() != requested {
        return Err("node returned a transaction with the wrong identifier");
    }
    Ok(transaction)
}

pub(crate) fn decode_transaction(
    raw: &RawTransaction,
    parse_height: BlockHeight,
) -> Result<Transaction, &'static str> {
    let branch = BranchId::for_height(&Network::TestNetwork, parse_height);
    let mut encoded = raw.data.as_slice();
    let transaction = Transaction::read(&mut encoded, branch)
        .map_err(|_| "node returned an invalid Zcash transaction")?;
    if !encoded.is_empty() {
        return Err("node returned a transaction with trailing data");
    }
    Ok(transaction)
}

pub(crate) fn decode_pending_transaction(
    raw: &RawTransaction,
    next_height: BlockHeight,
) -> Result<Transaction, &'static str> {
    if raw.height != 0 {
        return Err("mempool stream contained a mined transaction");
    }
    decode_transaction(raw, next_height)
}

fn mined_history_bounds(
    start: BlockHeight,
    end_exclusive: Option<BlockHeight>,
    scanned_tip: BlockHeight,
    tx_status: &TransactionStatusFilter,
    output_status: &OutputStatusFilter,
) -> Option<(BlockHeight, BlockHeight, MinedHistoryKind)> {
    let kind = match (tx_status, output_status) {
        (TransactionStatusFilter::Mined, OutputStatusFilter::All) => MinedHistoryKind::Complete,
        (TransactionStatusFilter::All, OutputStatusFilter::Unspent) => {
            MinedHistoryKind::PendingUnresolved
        }
        _ => return None,
    };
    // An open-ended wallet request is bounded by the locally scanned tip. It
    // must not silently extend into blocks the wallet has not validated yet.
    let end_inclusive = match end_exclusive {
        Some(end) => u32::from(end).checked_sub(1)?,
        None => u32::from(scanned_tip),
    };
    if u32::from(start) > end_inclusive {
        return None;
    }
    Some((start, BlockHeight::from_u32(end_inclusive), kind))
}

fn matches_scanned_anchor(block: &CompactBlock, height: BlockHeight, hash: &BlockHash) -> bool {
    block.height == u64::from(u32::from(height)) && block.hash.as_slice() == hash.0
}

pub(crate) fn open_history_stage(stage_dir: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_TMPFILE)
        .open(stage_dir)
}

async fn process_mined_transparent_history(
    client: &mut MaintainedScannerClient,
    wallet: &mut LocalWallet,
    request: TransactionsInvolvingAddress,
    stage_dir: &Path,
    pending_snapshot_complete: bool,
) -> Result<Option<MinedHistoryKind>, Box<dyn Error>> {
    let tip = wallet
        .chain_height()?
        .ok_or("wallet chain tip unavailable")?;
    let Some((start, end, kind)) = mined_history_bounds(
        request.block_range_start(),
        request.block_range_end(),
        tip,
        request.tx_status_filter(),
        request.output_status_filter(),
    ) else {
        return Ok(None);
    };
    if end > tip {
        return Err("transparent history extends beyond the scanned wallet tip".into());
    }
    let anchor_selector = BlockId {
        height: u64::from(u32::from(end)),
        hash: vec![],
    };
    let before = client
        .get_block(anchor_selector.clone())
        .await?
        .into_inner();
    let scanned_hash = wallet
        .get_block_hash(end)?
        .ok_or("transparent history anchor is not in the scanned wallet")?;
    if !matches_scanned_anchor(&before, end, &scanned_hash) {
        return Err("transparent history anchor differs from the scanned wallet".into());
    }
    let mut stream = client
        .get_taddress_transactions(TransparentAddressBlockFilter {
            address: encode_transparent_address_p(&Network::TestNetwork, &request.address()),
            range: Some(BlockRange {
                start: Some(BlockId {
                    height: u64::from(u32::from(start)),
                    hash: vec![],
                }),
                end: Some(anchor_selector.clone()),
                pool_types: vec![],
            }),
        })
        .await?
        .into_inner();
    let mut previous_height = None;
    // Keep the untrusted stream out of the wallet database until the complete
    // range and its chain anchor have been checked. O_TMPFILE creates an
    // unnamed file on the wallet's own filesystem; failure is fail-closed.
    let mut stage = open_history_stage(stage_dir)?;
    let mut staged_count = 0_u64;
    while let Some(raw) = stream.message().await? {
        let ChainTxState::Mined(height) = ChainTxState::from_wire_height(raw.height)? else {
            return Err("transparent history contained a non-main-chain transaction".into());
        };
        if height < start || height > end || previous_height.is_some_and(|prior| height < prior) {
            return Err("transparent history violated the requested block order".into());
        }
        decode_transaction(&raw, height)?;
        stage.write_all(&raw.height.to_le_bytes())?;
        stage.write_all(&u64::try_from(raw.data.len())?.to_le_bytes())?;
        stage.write_all(&raw.data)?;
        staged_count = staged_count
            .checked_add(1)
            .ok_or("transparent history transaction count overflow")?;
        previous_height = Some(height);
    }
    // The stream reaching EOF does not prove the chain stayed on the same
    // branch while transactions arrived. Recheck the scanned range's tip before
    // marking an empty range complete. On any error, the wallet is retryable;
    // no full-history result is reported to the caller.
    let after = client.get_block(anchor_selector).await?.into_inner();
    if after.height != before.height || after.hash != before.hash {
        return Err("transparent history changed during retrieval".into());
    }
    stage.seek(SeekFrom::Start(0))?;
    wallet.transactionally(|wdb| -> Result<(), Box<dyn Error>> {
        for _ in 0..staged_count {
            let mut field = [0_u8; 8];
            stage.read_exact(&mut field)?;
            let ChainTxState::Mined(height) =
                ChainTxState::from_wire_height(u64::from_le_bytes(field))?
            else {
                return Err("staged history contained a non-main-chain transaction".into());
            };
            stage.read_exact(&mut field)?;
            let length = u64::from_le_bytes(field);
            let remaining = stage
                .metadata()?
                .len()
                .checked_sub(stage.stream_position()?)
                .ok_or("staged transparent history is incomplete")?;
            if length > remaining {
                return Err("staged transparent history is incomplete".into());
            }
            let mut data = Vec::new();
            data.try_reserve_exact(usize::try_from(length)?)?;
            data.resize(usize::try_from(length)?, 0);
            stage.read_exact(&mut data)?;
            let transaction = decode_transaction(
                &RawTransaction {
                    data,
                    height: u64::from(u32::from(height)),
                },
                height,
            )?;
            decrypt_and_store_transaction(&Network::TestNetwork, wdb, &transaction, Some(height))?;
        }
        if stage.stream_position()? != stage.metadata()?.len() {
            return Err("staged transparent history has trailing data".into());
        }
        // The mined range is complete only after its stream and chain anchor
        // are checked. All + Unspent also requires the complete local-node
        // mempool ID snapshot and full transactions at the same scanned tip.
        if kind == MinedHistoryKind::Complete || pending_snapshot_complete {
            wdb.notify_address_checked(request, end)?;
        }
        Ok(())
    })?;
    Ok(Some(kind))
}

pub async fn process_snapshot(
    adapter: &LocalWalletAdapter,
    client: &mut MaintainedScannerClient,
    wallet: &mut LocalWallet,
    stage_dir: &Path,
) -> Result<EnhancementReport, Box<dyn Error>> {
    let mut report = EnhancementReport::default();
    let requests = wallet.transaction_data_requests()?;
    let needs_pending_snapshot = requests.iter().any(|request| {
        matches!(request, TransactionDataRequest::TransactionsInvolvingAddress(history)
            if matches!(history.tx_status_filter(), TransactionStatusFilter::All)
                && matches!(history.output_status_filter(), OutputStatusFilter::Unspent))
    });
    if needs_pending_snapshot {
        crate::process_pending_snapshot(adapter, client, wallet, stage_dir).await?;
    }
    for request in requests {
        let (txid, enhance) = match request {
            TransactionDataRequest::GetStatus(txid) => (txid, false),
            TransactionDataRequest::Enhancement(txid) => (txid, true),
            TransactionDataRequest::TransactionsInvolvingAddress(history) => {
                match process_mined_transparent_history(
                    client,
                    wallet,
                    history,
                    stage_dir,
                    needs_pending_snapshot,
                )
                .await?
                {
                    Some(MinedHistoryKind::Complete) => {
                        report.mined_transparent_history_reads += 1;
                    }
                    Some(MinedHistoryKind::PendingUnresolved) => {
                        report.mined_transparent_history_reads += 1;
                        if needs_pending_snapshot {
                            report.pending_snapshot_checks += 1;
                        } else {
                            report.pending_unverified_checks += 1;
                        }
                    }
                    None => report.unsupported_history_requests += 1,
                }
                continue;
            }
        };
        let raw = match client
            .get_transaction(TxFilter {
                block: None,
                index: 0,
                hash: txid.as_ref().to_vec(),
            })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) if error.code() == tonic::Code::NotFound => {
                wallet.set_transaction_status(txid, TransactionStatus::TxidNotRecognized)?;
                report.status_checks += 1;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let state = ChainTxState::from_wire_height(raw.height)?;
        let parse_height = if let Some(height) = state.mined_height() {
            height
        } else {
            let tip = wallet
                .chain_height()?
                .ok_or("wallet chain tip unavailable")?;
            let next = u32::from(tip)
                .checked_add(1)
                .ok_or("wallet chain height overflow")?;
            BlockHeight::from_u32(next)
        };
        let transaction = decode_checked_transaction(&raw, txid, parse_height)?;
        if enhance {
            decrypt_and_store_transaction(
                &Network::TestNetwork,
                wallet,
                &transaction,
                state.mined_height(),
            )?;
            report.enhanced += 1;
        }
        wallet.set_transaction_status(txid, state.wallet_status())?;
        report.status_checks += 1;
    }
    report.remaining_requests = wallet.transaction_data_requests()?.len();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_stage_has_no_directory_entry() {
        let directory = tempfile::tempdir().unwrap();
        let mut file = open_history_stage(directory.path()).unwrap();
        file.write_all(b"synthetic transaction").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "synthetic transaction");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn pinned_testnet_transaction_requires_exact_id_and_no_trailing_data() {
        let data =
            hex::decode(include_str!("../../../tests/fixtures/zcash/testnet-v4-tx.hex").trim())
                .unwrap();
        let txid =
            TxId::from_hex("64f0bd7fe30ce23753358fe3a2dc835b8fba9c0274c4e2c54a6f73114cb55639")
                .unwrap();
        let height = BlockHeight::from_u32(280_003);
        let raw = RawTransaction {
            data,
            height: u64::from(u32::from(height)),
        };
        assert_eq!(
            decode_checked_transaction(&raw, txid, height)
                .unwrap()
                .txid(),
            txid
        );
        assert!(decode_checked_transaction(&raw, TxId::NULL, height).is_err());
        let mut trailing = raw;
        trailing.data.push(0);
        assert!(decode_checked_transaction(&trailing, txid, height).is_err());
    }

    #[test]
    fn transaction_status_sentinels_are_not_heights() {
        assert_eq!(ChainTxState::from_wire_height(0), Ok(ChainTxState::Pending));
        assert_eq!(
            ChainTxState::from_wire_height(u64::MAX),
            Ok(ChainTxState::Orphaned)
        );
        assert_eq!(
            ChainTxState::from_wire_height(42),
            Ok(ChainTxState::Mined(BlockHeight::from_u32(42)))
        );
        assert!(ChainTxState::from_wire_height(u64::from(u32::MAX) + 1).is_err());
    }

    #[test]
    fn pending_stream_requires_unmined_raw_transaction() {
        let data =
            hex::decode(include_str!("../../../tests/fixtures/zcash/testnet-v4-tx.hex").trim())
                .unwrap();
        let next_height = BlockHeight::from_u32(280_003);
        let raw = RawTransaction { data, height: 0 };
        assert!(decode_pending_transaction(&raw, next_height).is_ok());
        assert!(
            decode_pending_transaction(&RawTransaction { height: 1, ..raw }, next_height).is_err()
        );
    }

    #[test]
    fn transaction_id_bytes_are_protocol_order_not_display_order() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 7;
        let id = TxId::from_bytes(bytes);
        assert_eq!(id.as_ref()[0], 7);
        assert!(id.to_string().starts_with("00"));
    }

    #[test]
    fn mined_history_is_inclusive_on_wire_and_rejects_other_filters() {
        let start = BlockHeight::from_u32(100);
        let end_exclusive = Some(BlockHeight::from_u32(103));
        assert_eq!(
            mined_history_bounds(
                start,
                end_exclusive,
                BlockHeight::from_u32(102),
                &TransactionStatusFilter::Mined,
                &OutputStatusFilter::All,
            ),
            Some((
                start,
                BlockHeight::from_u32(102),
                MinedHistoryKind::Complete
            ))
        );
        assert!(
            mined_history_bounds(
                start,
                Some(start),
                BlockHeight::from_u32(102),
                &TransactionStatusFilter::Mined,
                &OutputStatusFilter::All,
            )
            .is_none()
        );
        assert!(
            mined_history_bounds(
                start,
                end_exclusive,
                BlockHeight::from_u32(102),
                &TransactionStatusFilter::All,
                &OutputStatusFilter::All,
            )
            .is_none()
        );
        assert_eq!(
            mined_history_bounds(
                start,
                end_exclusive,
                BlockHeight::from_u32(102),
                &TransactionStatusFilter::All,
                &OutputStatusFilter::Unspent,
            ),
            Some((
                start,
                BlockHeight::from_u32(102),
                MinedHistoryKind::PendingUnresolved
            ))
        );
        assert!(
            mined_history_bounds(
                start,
                end_exclusive,
                BlockHeight::from_u32(102),
                &TransactionStatusFilter::Mined,
                &OutputStatusFilter::Unspent,
            )
            .is_none()
        );
        assert_eq!(
            mined_history_bounds(
                start,
                None,
                BlockHeight::from_u32(102),
                &TransactionStatusFilter::Mined,
                &OutputStatusFilter::All,
            ),
            Some((
                start,
                BlockHeight::from_u32(102),
                MinedHistoryKind::Complete
            ))
        );
        assert!(
            mined_history_bounds(
                BlockHeight::from_u32(103),
                None,
                BlockHeight::from_u32(102),
                &TransactionStatusFilter::Mined,
                &OutputStatusFilter::All,
            )
            .is_none()
        );
    }

    #[test]
    fn transparent_history_anchor_uses_the_locally_scanned_hash() {
        let hash: [u8; 32] = std::array::from_fn(|index| index as u8);
        let height = BlockHeight::from_u32(102);
        let block = CompactBlock {
            height: 102,
            hash: hash.to_vec(),
            ..Default::default()
        };
        assert!(matches_scanned_anchor(&block, height, &BlockHash(hash)));
        assert!(!matches_scanned_anchor(
            &block,
            height,
            &BlockHash(hash.map(|value| 31 - value)),
        ));
        assert!(!matches_scanned_anchor(
            &block,
            BlockHeight::from_u32(103),
            &BlockHash(hash),
        ));
    }
}
