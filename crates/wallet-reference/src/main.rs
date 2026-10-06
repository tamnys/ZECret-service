//! Reference integration with the maintained Zcash wallet scanner. `init`
//! imports a viewing key into a new local database; `scan` opens that database.
//! Neither operation sends keys, seeds, or decrypted wallet data to the bridge.

use rand::{rand_core::UnwrapErr, rngs::SysRng};
use rusqlite::{Connection, OpenFlags};
use std::{
    env,
    error::Error,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};
use zcash_client_backend::{
    data_api::chain::BlockCache,
    data_api::wallet::{ConfirmationsPolicy, decrypt_and_store_transaction},
    data_api::{AccountBirthday, AccountPurpose, WalletRead, WalletWrite},
    proto::service::{
        BlockId, BlockRange, ChainSpec, Empty, GetMempoolTxRequest, RawTransaction,
        TransparentAddressBlockFilter, TxFilter,
    },
    sync,
};
use zcash_client_sqlite::{WalletDb, util::SystemClock, wallet::init::init_wallet_db};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::{block::BlockHash, transaction::Transaction};
use zcash_protocol::consensus::{BlockHeight, Network};
use zeroize::Zeroize;
use zrpc_payments::PrivateDirectory;
use zrpc_wallet_sdk::bridge::LocalWalletAdapter;

mod cache;
mod enhance;
use cache::SqliteBlockCache;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os();
    args.next();
    match args.next().as_deref().and_then(|mode| mode.to_str()) {
        Some("init") => init(args).await,
        Some("scan") => scan(args).await,
        Some("pending") => pending(args).await,
        Some("probe") => probe(args).await,
        _ => Err("usage: zrpc-wallet-reference {init|scan|pending|probe} ...".into()),
    }
}

fn parse_bind(value: OsString) -> Result<SocketAddr, Box<dyn Error>> {
    let bind: SocketAddr = value.to_string_lossy().parse()?;
    if !bind.ip().is_loopback() || bind.port() == 0 {
        return Err("bridge must use a loopback address with a nonzero port".into());
    }
    Ok(bind)
}

fn read_viewing_key(path: PathBuf) -> Result<UnifiedFullViewingKey, Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err("viewing key file must be owner-private and regular".into());
    }
    let mut encoded = String::new();
    file.read_to_string(&mut encoded)?;
    let decoded = UnifiedFullViewingKey::decode(&Network::TestNetwork, encoded.trim());
    encoded.zeroize();
    decoded.map_err(|_| "invalid testnet unified full viewing key".into())
}

// Public chain-data smoke test for an attested bridge. Each invocation makes
// exactly one wallet RPC and therefore consumes one free admission ticket.
async fn probe(mut args: env::ArgsOs) -> Result<(), Box<dyn Error>> {
    let usage = "usage: zrpc-wallet-reference probe LOOPBACK_HOST:PORT CAPABILITY_DIR {info|tip|block HEIGHT|range START_HEIGHT END_HEIGHT|history TESTNET_ADDRESS START_HEIGHT END_HEIGHT}";
    let bind = parse_bind(args.next().ok_or(usage)?)?;
    let capability_dir = PathBuf::from(args.next().ok_or(usage)?);
    let method = args.next().ok_or(usage)?;
    let mut history_address = None;
    let heights = match method.to_str() {
        Some("block") => {
            let height = args.next().ok_or(usage)?.to_string_lossy().parse::<u32>()?;
            Some((height, height))
        }
        Some("range") => {
            let start = args.next().ok_or(usage)?.to_string_lossy().parse::<u32>()?;
            let end = args.next().ok_or(usage)?.to_string_lossy().parse::<u32>()?;
            if start == 0 || start > end {
                return Err("range must be ascending and start above genesis".into());
            }
            Some((start, end))
        }
        Some("history") => {
            history_address = Some(args.next().ok_or(usage)?.to_string_lossy().into_owned());
            let start = args.next().ok_or(usage)?.to_string_lossy().parse::<u32>()?;
            let end = args.next().ok_or(usage)?.to_string_lossy().parse::<u32>()?;
            if start > end {
                return Err("history range must be ascending".into());
            }
            Some((start, end))
        }
        Some("info" | "tip") => None,
        _ => return Err(usage.into()),
    };
    if args.next().is_some() {
        return Err(usage.into());
    }
    let adapter = LocalWalletAdapter::connect(bind, &capability_dir).await?;
    let mut client = adapter.maintained_scanner_client();
    match method.to_str() {
        Some("info") => {
            let info = client.get_lightd_info(Empty {}).await?.into_inner();
            println!(
                "network={} node_height={}",
                info.chain_name, info.block_height
            );
        }
        Some("tip") => {
            let tip = client.get_latest_block(ChainSpec {}).await?.into_inner();
            println!("node_height={} hash_bytes={}", tip.height, tip.hash.len());
        }
        Some("block") => {
            let height = heights.ok_or(usage)?.0;
            let block = client
                .get_block(BlockId {
                    height: u64::from(height),
                    hash: vec![],
                })
                .await?
                .into_inner();
            if block.height != u64::from(height) {
                return Err("compact block height differs from request".into());
            }
            println!(
                "compact_height={} hash_bytes={} prev_hash_bytes={} transactions={}",
                block.height,
                block.hash.len(),
                block.prev_hash.len(),
                block.vtx.len()
            );
        }
        Some("range") => {
            let (start, end) = heights.ok_or(usage)?;
            let started = Instant::now();
            let mut stream = client
                .get_block_range(BlockRange {
                    start: Some(BlockId {
                        height: u64::from(start),
                        hash: vec![],
                    }),
                    end: Some(BlockId {
                        height: u64::from(end),
                        hash: vec![],
                    }),
                    pool_types: vec![],
                })
                .await?
                .into_inner();
            let mut expected = u64::from(start);
            let mut prior_hash: Option<Vec<u8>> = None;
            while let Some(block) = stream.message().await? {
                if block.height != expected || block.hash.len() != 32 || block.prev_hash.len() != 32
                {
                    return Err("compact block range differs from request".into());
                }
                if prior_hash
                    .as_deref()
                    .is_some_and(|hash| block.prev_hash != hash)
                {
                    return Err("compact block predecessor differs from prior hash".into());
                }
                println!(
                    "compact_height={} elapsed_ms={}",
                    block.height,
                    started.elapsed().as_millis()
                );
                prior_hash = Some(block.hash);
                expected += 1;
            }
            if expected != u64::from(end) + 1 {
                return Err("compact block range ended before requested height".into());
            }
            println!(
                "range_complete=true blocks={} elapsed_ms={}",
                expected - u64::from(start),
                started.elapsed().as_millis()
            );
        }
        Some("history") => {
            let (start, end) = heights.ok_or(usage)?;
            let started = Instant::now();
            let mut stream = client
                .get_taddress_transactions(TransparentAddressBlockFilter {
                    address: history_address.ok_or(usage)?,
                    range: Some(BlockRange {
                        start: Some(BlockId {
                            height: u64::from(start),
                            hash: vec![],
                        }),
                        end: Some(BlockId {
                            height: u64::from(end),
                            hash: vec![],
                        }),
                        pool_types: vec![],
                    }),
                })
                .await?
                .into_inner();
            let mut count = 0_u64;
            let mut previous = u64::from(start);
            while let Some(transaction) = stream.message().await? {
                if transaction.height < previous || transaction.height > u64::from(end) {
                    return Err("transparent history order differs from request".into());
                }
                previous = transaction.height;
                count += 1;
            }
            println!(
                "history_complete=true transactions={count} elapsed_ms={}",
                started.elapsed().as_millis()
            );
        }
        _ => return Err(usage.into()),
    }
    Ok(())
}

async fn init(mut args: env::ArgsOs) -> Result<(), Box<dyn Error>> {
    let usage = "usage: zrpc-wallet-reference init LOOPBACK_HOST:PORT CAPABILITY_DIR NEW_PRIVATE_DIR UFVK_FILE BIRTHDAY_HEIGHT";
    let bind = parse_bind(args.next().ok_or(usage)?)?;
    let capability_dir = PathBuf::from(args.next().ok_or(usage)?);
    let private_dir = PathBuf::from(args.next().ok_or(usage)?);
    let ufvk_file = PathBuf::from(args.next().ok_or(usage)?);
    let birthday_height: u32 = args.next().ok_or(usage)?.to_string_lossy().parse()?;
    if args.next().is_some() || birthday_height == 0 {
        return Err(usage.into());
    }

    let viewing_key = read_viewing_key(ufvk_file)?;
    let adapter = LocalWalletAdapter::connect(bind, &capability_dir).await?;
    let mut client = adapter.maintained_scanner_client();
    let prior_height = birthday_height - 1;
    let tree_state = client
        .get_tree_state(BlockId {
            height: u64::from(prior_height),
            hash: vec![],
        })
        .await?
        .into_inner();
    if tree_state.height != u64::from(prior_height) {
        return Err("birthday tree state height differs from the requested block".into());
    }
    let birthday = AccountBirthday::from_treestate(tree_state, None)?;

    PrivateDirectory::create(&private_dir)?;
    let wallet_path = private_dir.join("wallet.sqlite");
    let conn = Connection::open_with_flags(
        &wallet_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    fs::set_permissions(&wallet_path, fs::Permissions::from_mode(0o600))?;
    rusqlite::vtab::array::load_module(&conn)?;
    let mut wallet =
        WalletDb::from_connection(conn, Network::TestNetwork, SystemClock, UnwrapErr(SysRng));
    init_wallet_db(&mut wallet, None)?;
    wallet.import_account_ufvk(
        "reference",
        &viewing_key,
        &birthday,
        AccountPurpose::ViewOnly,
        None,
    )?;
    println!(
        "local testnet wallet initialized at {}",
        wallet_path.display()
    );
    Ok(())
}

type LocalWallet = WalletDb<Connection, Network, SystemClock, UnwrapErr<SysRng>>;

fn same_scanned_tip(height: BlockHeight, hash: BlockHash, node: &BlockId) -> bool {
    node.height == u64::from(u32::from(height)) && node.hash.as_slice() == hash.0
}

fn open_existing_wallet(wallet_path: &Path) -> Result<LocalWallet, Box<dyn Error>> {
    // The wallet database stays under an owner-private directory, separate
    // from the bridge. Never create it by typo or follow a symbolic link.
    let wallet_parent = wallet_path.parent().ok_or("wallet path has no parent")?;
    PrivateDirectory::open(wallet_parent)?;
    let metadata = fs::symlink_metadata(&wallet_path)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err("wallet database path must be an owner-private regular file".into());
    }
    let conn = Connection::open_with_flags(
        &wallet_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    rusqlite::vtab::array::load_module(&conn)?;

    // The wallet database is never mounted into or opened by the local bridge.
    // It must have been initialized with viewing keys by the wallet application.
    let mut wallet =
        WalletDb::from_connection(conn, Network::TestNetwork, SystemClock, UnwrapErr(SysRng));
    // The maintained wallet schema can change across dependency upgrades.
    // Apply its idempotent migrations before any read or scan of an existing DB.
    init_wallet_db(&mut wallet, None)?;
    if wallet.get_account_ids()?.is_empty() {
        return Err("wallet database has no locally imported viewing-key account".into());
    }
    Ok(wallet)
}

fn scan_progress(
    wallet: &LocalWallet,
    cache: &SqliteBlockCache,
) -> Result<(u32, u32), Box<dyn Error>> {
    let wallet_height = wallet
        .get_wallet_summary(ConfirmationsPolicy::default())?
        .map(|summary| u32::from(summary.fully_scanned_height()))
        .unwrap_or(0);
    let cache_height = cache.get_tip_height(None)?.map(u32::from).unwrap_or(0);
    Ok((wallet_height, cache_height))
}

async fn scan(mut args: env::ArgsOs) -> Result<(), Box<dyn Error>> {
    let usage = "usage: zrpc-wallet-reference scan LOOPBACK_HOST:PORT CAPABILITY_DIR WALLET_DB CACHE_DB BATCH_SIZE";
    let bind = parse_bind(args.next().ok_or(usage)?)?;
    let capability_dir = PathBuf::from(args.next().ok_or(usage)?);
    let wallet_path = PathBuf::from(args.next().ok_or(usage)?);
    let cache_path = PathBuf::from(args.next().ok_or(usage)?);
    let mut batch_size: u32 = args.next().ok_or(usage)?.to_string_lossy().parse()?;
    if args.next().is_some() || batch_size == 0 {
        return Err(usage.into());
    }
    if wallet_path == cache_path {
        return Err("wallet database and compact cache must differ".into());
    }
    PrivateDirectory::open(cache_path.parent().ok_or("cache path has no parent")?)?;
    let mut wallet = open_existing_wallet(&wallet_path)?;
    let adapter = LocalWalletAdapter::connect(bind, &capability_dir).await?;
    let mut client = adapter.maintained_scanner_client();
    let cache = SqliteBlockCache::open(&cache_path)?;
    let mut prior_progress = scan_progress(&wallet, &cache)?;
    loop {
        match sync::run(
            &mut client,
            &Network::TestNetwork,
            &cache,
            &mut wallet,
            batch_size,
        )
        .await
        {
            Ok(()) => break,
            Err(sync::Error::Server(status))
                if matches!(
                    status.code(),
                    tonic::Code::DeadlineExceeded | tonic::Code::Unavailable
                ) =>
            {
                // The maintained scanner commits complete ranges and wallet
                // scans locally. A new bridge RPC gets a fresh Tor stream,
                // attested TLS connection, and ticket; no failed stream or
                // ambiguous ticket is reused.
                let current = scan_progress(&wallet, &cache)?;
                if current.0 >= prior_progress.0
                    && current.1 >= prior_progress.1
                    && current != prior_progress
                {
                    prior_progress = current;
                    eprintln!(
                        "resuming verified wallet scan from wallet_height={} cache_height={}",
                        current.0, current.1
                    );
                    continue;
                }
                if status.code() == tonic::Code::DeadlineExceeded && batch_size > 1 {
                    batch_size = batch_size / 2 + batch_size % 2;
                    eprintln!(
                        "verified wallet stream timed out without progress; retry_batch_size={batch_size}"
                    );
                    continue;
                }
                return Err(Box::new(status));
            }
            Err(error) => return Err(Box::new(error)),
        }
    }
    let enhanced = enhance::process_snapshot(
        &mut client,
        &mut wallet,
        wallet_path.parent().ok_or("wallet path has no parent")?,
    )
    .await?;

    // Only local derived totals and heights are printed. `is_synced` is the
    // maintained wallet scanner's local progress, not a claim of global tip
    // freshness or provider-independent TEE isolation.
    if let Some(summary) = wallet.get_wallet_summary(ConfirmationsPolicy::default())? {
        println!(
            "wallet_scan_height={} wallet_tip_height={} compact_scan_complete={} accounts={} enhanced_transactions={} status_checks={} mined_transparent_history_reads={} pending_unverified_checks={} unsupported_history_requests={} remaining_transaction_requests={}",
            u32::from(summary.fully_scanned_height()),
            u32::from(summary.chain_tip_height()),
            summary.is_synced(),
            summary.account_balances().len(),
            enhanced.enhanced,
            enhanced.status_checks,
            enhanced.mined_transparent_history_reads,
            enhanced.pending_unverified_checks,
            enhanced.unsupported_history_requests,
            enhanced.remaining_requests,
        );
        for (account, balance) in summary.account_balances() {
            println!(
                "account={account:?} sapling_observed_zat={} orchard_observed_zat={} ironwood_observed_zat={} transparent_observed_zat_unreconciled={}",
                u64::from(balance.sapling_balance().total()),
                u64::from(balance.orchard_balance().total()),
                u64::from(balance.ironwood_balance().total()),
                u64::from(balance.unshielded_balance().total())
            );
        }
    } else {
        return Err("wallet scanner returned no summary".into());
    }
    Ok(())
}

fn checked_pending_transaction(
    expected_txid: &[u8],
    raw: &RawTransaction,
    next_height: BlockHeight,
) -> Result<Transaction, &'static str> {
    if expected_txid.len() != 32 {
        return Err("mempool returned an invalid transaction identifier");
    }
    let transaction = enhance::decode_pending_transaction(raw, next_height)?;
    if transaction.txid().as_ref().as_slice() != expected_txid {
        return Err("mempool returned a transaction with the wrong identifier");
    }
    Ok(transaction)
}

async fn pending(mut args: env::ArgsOs) -> Result<(), Box<dyn Error>> {
    let usage = "usage: zrpc-wallet-reference pending LOOPBACK_HOST:PORT CAPABILITY_DIR WALLET_DB";
    let bind = parse_bind(args.next().ok_or(usage)?)?;
    let capability_dir = PathBuf::from(args.next().ok_or(usage)?);
    let wallet_path = PathBuf::from(args.next().ok_or(usage)?);
    if args.next().is_some() {
        return Err(usage.into());
    }
    let mut wallet = open_existing_wallet(&wallet_path)?;
    let summary = wallet
        .get_wallet_summary(ConfirmationsPolicy::default())?
        .ok_or("scan the wallet before reading the mempool")?;
    if !summary.is_synced() {
        return Err("finish the local wallet scan before reading the mempool".into());
    }
    let local_tip = summary.chain_tip_height();
    let adapter = LocalWalletAdapter::connect(bind, &capability_dir).await?;
    let mut client = adapter.maintained_scanner_client();
    let node_tip = client.get_latest_block(ChainSpec {}).await?.into_inner();
    let local_hash = wallet
        .get_block_hash(local_tip)?
        .ok_or("wallet scan tip hash unavailable")?;
    if !same_scanned_tip(local_tip, local_hash, &node_tip) {
        return Err("wallet scan tip differs from the node; scan again first".into());
    }
    let next_height = BlockHeight::from_u32(
        u32::from(local_tip)
            .checked_add(1)
            .ok_or("wallet chain height overflow")?,
    );
    // The pinned Zebra GetMempoolStream stays open until the next block, so it
    // cannot finish a one-shot read when the chain is quiet. Its finite
    // GetMempoolTx result contains shielded compact transactions only.
    let mut stream = client
        .get_mempool_tx(GetMempoolTxRequest {
            exclude_txid_suffixes: vec![],
            pool_types: vec![],
        })
        .await?
        .into_inner();
    // The bridge serializes wallet RPCs while a stream is active. Finish this
    // stream before asking for full transactions on the same local client.
    let mut ids =
        enhance::open_history_stage(wallet_path.parent().ok_or("wallet path has no parent")?)?;
    let mut staged_count = 0_u64;
    while let Some(compact) = stream.message().await? {
        if compact.txid.len() != 32 {
            return Err("mempool returned an invalid transaction identifier".into());
        }
        ids.write_all(&compact.txid)?;
        staged_count = staged_count
            .checked_add(1)
            .ok_or("mempool transaction count overflow")?;
    }
    drop(stream);
    ids.seek(SeekFrom::Start(0))?;
    // Stage full transactions in an unnamed local file so a failed read
    // cannot partially update the wallet or consume unbounded memory.
    let mut stage =
        enhance::open_history_stage(wallet_path.parent().ok_or("wallet path has no parent")?)?;
    for _ in 0..staged_count {
        let mut txid = [0_u8; 32];
        ids.read_exact(&mut txid)?;
        let raw = client
            .get_transaction(TxFilter {
                block: None,
                index: 0,
                hash: txid.to_vec(),
            })
            .await?
            .into_inner();
        checked_pending_transaction(&txid, &raw, next_height)?;
        stage.write_all(&txid)?;
        stage.write_all(&u64::try_from(raw.data.len())?.to_le_bytes())?;
        stage.write_all(&raw.data)?;
    }
    if ids.stream_position()? != ids.metadata()?.len() {
        return Err("staged mempool identifiers have trailing bytes".into());
    }
    let after = client.get_latest_block(ChainSpec {}).await?.into_inner();
    if !same_scanned_tip(local_tip, local_hash, &after) {
        return Err("node tip changed during mempool read; scan again first".into());
    }
    stage.seek(SeekFrom::Start(0))?;
    wallet.transactionally(|wdb| -> Result<(), Box<dyn Error>> {
        for _ in 0..staged_count {
            let mut txid = [0_u8; 32];
            stage.read_exact(&mut txid)?;
            let mut length = [0_u8; 8];
            stage.read_exact(&mut length)?;
            let length = u64::from_le_bytes(length);
            let remaining = stage
                .metadata()?
                .len()
                .checked_sub(stage.stream_position()?)
                .ok_or("staged mempool data is incomplete")?;
            if length > remaining {
                return Err("staged mempool data is incomplete".into());
            }
            let mut data = Vec::new();
            data.try_reserve_exact(usize::try_from(length)?)?;
            data.resize(usize::try_from(length)?, 0);
            stage.read_exact(&mut data)?;
            let transaction = checked_pending_transaction(
                &txid,
                &RawTransaction { data, height: 0 },
                next_height,
            )?;
            decrypt_and_store_transaction(&Network::TestNetwork, wdb, &transaction, None)?;
        }
        if stage.stream_position()? != stage.metadata()?.len() {
            return Err("staged mempool data has trailing bytes".into());
        }
        Ok(())
    })?;
    // This is an observation, not a complete mempool snapshot: Zebra omits
    // transparent-only transactions and the mempool may change during reads.
    println!(
        "shielded_mempool_transactions_processed={staged_count} status=observed_incomplete_rescan_to_reconcile"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn bridge_target_must_be_loopback() {
        assert!(parse_bind(OsString::from("127.0.0.1:9067")).is_ok());
        assert!(parse_bind(OsString::from("0.0.0.0:9067")).is_err());
        assert!(parse_bind(OsString::from("127.0.0.1:0")).is_err());
    }

    #[test]
    fn viewing_key_file_rejects_permissive_modes_and_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("viewing-key");
        fs::write(&path, "synthetic-invalid-ufvk").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_viewing_key(path.clone()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = read_viewing_key(path.clone()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid testnet unified full viewing key"
        );
        let link = directory.path().join("link");
        symlink(path, &link).unwrap();
        assert!(read_viewing_key(link).is_err());
    }

    #[test]
    fn pending_reader_tip_comparison_uses_internal_hash_bytes() {
        let hash: [u8; 32] = std::array::from_fn(|index| index as u8);
        let height = BlockHeight::from_u32(42);
        assert!(same_scanned_tip(
            height,
            BlockHash(hash),
            &BlockId {
                height: 42,
                hash: hash.to_vec(),
            }
        ));
        assert!(!same_scanned_tip(
            height,
            BlockHash(hash),
            &BlockId {
                height: 42,
                hash: hash.iter().rev().copied().collect(),
            }
        ));
    }

    #[test]
    fn pending_compact_id_must_match_unmined_raw_transaction() {
        let data =
            hex::decode(include_str!("../../../tests/fixtures/zcash/testnet-v4-tx.hex").trim())
                .unwrap();
        let next_height = BlockHeight::from_u32(280_003);
        let raw = RawTransaction { data, height: 0 };
        let decoded = enhance::decode_pending_transaction(&raw, next_height).unwrap();
        let txid = decoded.txid();
        let expected = txid.as_ref().as_slice();
        assert!(checked_pending_transaction(expected, &raw, next_height).is_ok());
        assert!(checked_pending_transaction(&expected[..31], &raw, next_height).is_err());
        assert!(checked_pending_transaction(&[0; 32], &raw, next_height).is_err());
        assert!(
            checked_pending_transaction(
                expected,
                &RawTransaction { height: 1, ..raw },
                next_height
            )
            .is_err()
        );
    }
}
