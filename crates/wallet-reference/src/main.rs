//! Reference integration with the maintained Zcash wallet scanner. `init`
//! imports a viewing key into a new local database; `scan` opens that database.
//! Neither operation sends keys, seeds, or decrypted wallet data to the bridge.

use rand::{rand_core::UnwrapErr, rngs::SysRng};
use rusqlite::{Connection, OpenFlags};
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    ffi::OsString,
    fs::{self, File, OpenOptions},
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
    proto::compact_formats::CompactBlock,
    proto::service::{
        BlockId, BlockRange, ChainSpec, Empty, RawTransaction, TransparentAddressBlockFilter,
        TxFilter,
    },
    sync,
};
use zcash_client_sqlite::{
    WalletDb, error::SqliteClientError, util::SystemClock, wallet::init::init_wallet_db,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::{Transaction, components::sapling::zip212_enforcement};
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zeroize::Zeroize;
use zrpc_payments::{ClientStore, IssuerPublic, PrivateDirectory};
use zrpc_wallet_sdk::bridge::{
    LocalWalletAdapter, MaintainedScannerClient, WalletScanProgress, snapshot_wire,
};
use zrpc_wallet_sdk::{
    Backend, EmbeddedWalletAdapter, NodeReadContext, PhalaTrustedPolicy, PrivateEndpointConfig,
    WalletReader,
};

mod cache;
mod enhance;
#[cfg(test)]
mod fork_tests;
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
        Some("--help") => {
            println!(
                "zrpc-wallet-reference {{init|scan|pending|probe}} CONNECTION INPUTS\n\
CONNECTION is LOOPBACK_HOST:PORT CAPABILITY_DIR, or:\n\
{EMBEDDED_USAGE}\n\
init inputs: NEW_PRIVATE_DIR UFVK_FILE BIRTHDAY_HEIGHT\n\
scan inputs: WALLET_DB CACHE_DB BATCH_SIZE\n\
pending inputs: WALLET_DB\n\
probe inputs: {{info|tip|snapshot|block HEIGHT|range START_HEIGHT END_HEIGHT|history TESTNET_ADDRESS START_HEIGHT END_HEIGHT}}\n\
Embedded mode runs the same maintained scanner through the Rust SDK without a local bridge listener."
            );
            Ok(())
        }
        _ => Err("usage: zrpc-wallet-reference {init|scan|pending|probe} ...".into()),
    }
}

const EMBEDDED_USAGE: &str = "--embedded --privacy-profile phala-trusted --platform phala-dstack --endpoint-host HOST --endpoint-port PORT --tor-executable ABSOLUTE_PATH --collateral FILE --app-compose FILE --release-policy FILE --ticket-store PRIVATE_DIR --issuer-public-der FILE --issuer-name NAME --crypto-helper FILE --";

enum ReferenceConnection {
    Local {
        bind: SocketAddr,
        capability_dir: PathBuf,
    },
    Embedded(EmbeddedInputs),
}

struct EmbeddedInputs {
    host: String,
    port: u16,
    tor_executable: PathBuf,
    collateral: PathBuf,
    compose: PathBuf,
    policy: PathBuf,
    tickets: PathBuf,
    issuer_der: PathBuf,
    issuer_name: String,
    crypto_helper: PathBuf,
}

impl ReferenceConnection {
    fn parse(args: &mut impl Iterator<Item = OsString>) -> Result<Self, Box<dyn Error>> {
        let first = args.next().ok_or("connection inputs are required")?;
        if first != "--embedded" {
            return Ok(Self::Local {
                bind: parse_bind(first)?,
                capability_dir: PathBuf::from(
                    args.next().ok_or("capability directory is required")?,
                ),
            });
        }
        let mut values = BTreeMap::new();
        loop {
            let flag = args
                .next()
                .ok_or("embedded inputs require a -- separator")?;
            if flag == "--" {
                break;
            }
            let flag = flag.into_string().map_err(|_| "invalid embedded option")?;
            if !matches!(
                flag.as_str(),
                "--privacy-profile"
                    | "--platform"
                    | "--endpoint-host"
                    | "--endpoint-port"
                    | "--tor-executable"
                    | "--collateral"
                    | "--app-compose"
                    | "--release-policy"
                    | "--ticket-store"
                    | "--issuer-public-der"
                    | "--issuer-name"
                    | "--crypto-helper"
            ) {
                return Err("unsupported embedded option".into());
            }
            let value = args.next().ok_or("embedded option value is required")?;
            if value.is_empty() || value.to_string_lossy().starts_with("--") {
                return Err("embedded option value is required".into());
            }
            if values.insert(flag, value).is_some() {
                return Err("duplicate embedded option".into());
            }
        }
        fn required(
            values: &mut BTreeMap<String, OsString>,
            flag: &str,
        ) -> Result<OsString, Box<dyn Error>> {
            values
                .remove(flag)
                .ok_or_else(|| format!("embedded mode requires {flag}").into())
        }
        fn text(value: OsString) -> Result<String, Box<dyn Error>> {
            value
                .into_string()
                .map_err(|_| "embedded text value is not UTF-8".into())
        }
        if required(&mut values, "--privacy-profile")? != "phala-trusted"
            || required(&mut values, "--platform")? != "phala-dstack"
        {
            return Err("embedded mode requires the explicit phala-trusted profile and phala-dstack platform".into());
        }
        Ok(Self::Embedded(EmbeddedInputs {
            host: text(required(&mut values, "--endpoint-host")?)?,
            port: text(required(&mut values, "--endpoint-port")?)?.parse()?,
            tor_executable: required(&mut values, "--tor-executable")?.into(),
            collateral: required(&mut values, "--collateral")?.into(),
            compose: required(&mut values, "--app-compose")?.into(),
            policy: required(&mut values, "--release-policy")?.into(),
            tickets: required(&mut values, "--ticket-store")?.into(),
            issuer_der: required(&mut values, "--issuer-public-der")?.into(),
            issuer_name: text(required(&mut values, "--issuer-name")?)?,
            crypto_helper: required(&mut values, "--crypto-helper")?.into(),
        }))
    }

    async fn connect(self) -> Result<LocalWalletAdapter, Box<dyn Error>> {
        match self {
            Self::Local {
                bind,
                capability_dir,
            } => Ok(LocalWalletAdapter::connect(bind, &capability_dir).await?),
            Self::Embedded(input) => {
                let endpoint = PrivateEndpointConfig::for_platform(
                    Backend::PhalaDstack,
                    &input.host,
                    input.port,
                    input.tor_executable,
                )?;
                let policy = PhalaTrustedPolicy::from_json(&fs::read(input.policy)?)?;
                let issuer = IssuerPublic::from_public_der(
                    &input.crypto_helper,
                    &fs::read(input.issuer_der)?,
                    &input.issuer_name,
                )?;
                let tickets = ClientStore::open(&PrivateDirectory::open(&input.tickets)?)?;
                let reader = WalletReader::new(
                    endpoint,
                    fs::read(input.collateral)?,
                    fs::read(input.compose)?,
                    policy,
                    issuer,
                    tickets,
                );
                Ok(EmbeddedWalletAdapter::new(reader)?.into_adapter())
            }
        }
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
    let usage = "usage: zrpc-wallet-reference probe LOOPBACK_HOST:PORT CAPABILITY_DIR {info|tip|snapshot|block HEIGHT|range START_HEIGHT END_HEIGHT|history TESTNET_ADDRESS START_HEIGHT END_HEIGHT}";
    let connection = ReferenceConnection::parse(&mut args)?;
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
        Some("info" | "tip" | "snapshot") => None,
        _ => return Err(usage.into()),
    };
    if args.next().is_some() {
        return Err(usage.into());
    }
    let adapter = connection.connect().await?;
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
        Some("snapshot") => {
            // A one-RPC diagnostic of the local node's finite mempool snapshot.
            // It does not assert that any wallet is synchronized to this tip.
            let mut stream = adapter
                .snapshot_client()
                .get_mempool_snapshot(snapshot_wire::SnapshotRequest {})
                .await?
                .into_inner();
            let mut tip = None;
            let mut count = 0_u64;
            while let Some(item) = stream.message().await? {
                match item.body {
                    Some(snapshot_wire::snapshot_item::Body::Tip(anchor)) if tip.is_none() => {
                        if anchor.hash.len() != 32 {
                            return Err("mempool snapshot tip hash is malformed".into());
                        }
                        tip = Some(anchor.height);
                    }
                    Some(snapshot_wire::snapshot_item::Body::Txid(txid)) if tip.is_some() => {
                        if txid.len() != 32 {
                            return Err("mempool snapshot transaction ID is malformed".into());
                        }
                        count = count.checked_add(1).ok_or("mempool count overflow")?;
                    }
                    _ => return Err("mempool snapshot item order is malformed".into()),
                }
            }
            let height = tip.ok_or("mempool snapshot omitted its chain tip")?;
            println!(
                "node_snapshot_complete=true node_height={height} mempool_transactions={count}"
            );
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
    let connection = ReferenceConnection::parse(&mut args)?;
    let private_dir = PathBuf::from(args.next().ok_or(usage)?);
    let ufvk_file = PathBuf::from(args.next().ok_or(usage)?);
    let birthday_height: u32 = args.next().ok_or(usage)?.to_string_lossy().parse()?;
    if args.next().is_some() || birthday_height == 0 {
        return Err(usage.into());
    }

    let viewing_key = read_viewing_key(ufvk_file)?;
    let adapter = connection.connect().await?;
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

fn matches_pending_anchor(anchor: NodeReadContext, block: &CompactBlock) -> bool {
    block.height == u64::from(anchor.height) && block.hash.as_slice() == anchor.hash
}

fn pending_parse_height(
    wallet_height: u32,
    snapshot_height: u32,
) -> Result<Option<BlockHeight>, &'static str> {
    if snapshot_height < wallet_height {
        return Ok(None);
    }
    let wallet_next = BlockHeight::from_u32(
        wallet_height
            .checked_add(1)
            .ok_or("wallet chain height overflow")?,
    );
    let snapshot_next = BlockHeight::from_u32(
        snapshot_height
            .checked_add(1)
            .ok_or("snapshot chain height overflow")?,
    );
    // Transaction parsing uses the snapshot's actual consensus height. The
    // maintained wallet helper trial-decrypts unmined notes at its own known
    // tip + 1, so both interpretation regimes must agree before storing.
    if BranchId::for_height(&Network::TestNetwork, wallet_next)
        != BranchId::for_height(&Network::TestNetwork, snapshot_next)
        || zip212_enforcement(&Network::TestNetwork, wallet_next)
            != zip212_enforcement(&Network::TestNetwork, snapshot_next)
    {
        return Ok(None);
    }
    Ok(Some(snapshot_next))
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

async fn report_committed_scan(
    adapter: &LocalWalletAdapter,
    wallet: &LocalWallet,
) -> Result<bool, Box<dyn Error>> {
    let Some(summary) = wallet.get_wallet_summary(ConfirmationsPolicy::default())? else {
        return Ok(false);
    };
    let progress = WalletScanProgress {
        fully_scanned_height: u32::from(summary.fully_scanned_height()),
        wallet_tip_height: u32::from(summary.chain_tip_height()),
        compact_scan_complete: summary.is_synced(),
    };
    // The local dashboard is informational. A status failure cannot undo a
    // committed wallet scan or turn it into an accepted pending result.
    Ok(adapter.report_scan_progress(progress).await.is_ok())
}

type ReferenceSyncError<C> = sync::Error<
    <C as zcash_client_backend::data_api::chain::BlockSource>::Error,
    SqliteClientError,
    <LocalWallet as zcash_client_backend::data_api::WalletCommitmentTrees>::Error,
>;

fn checked_recovery_state(
    safe_height: BlockHeight,
    requested_height: BlockHeight,
    before: &CompactBlock,
    tree: zcash_client_backend::proto::service::TreeState,
    after: &CompactBlock,
) -> Result<zcash_client_backend::data_api::chain::ChainState, tonic::Status> {
    let invalid = || tonic::Status::data_loss("Wallet recovery chain anchor is inconsistent.");
    if safe_height > requested_height
        || before.height != u64::from(u32::from(safe_height))
        || before.hash.len() != 32
        || after.height != before.height
        || after.hash != before.hash
        || tree.network != "test"
    {
        return Err(invalid());
    }
    let state = tree.to_chain_state().map_err(|_| invalid())?;
    if state.block_height() != safe_height || state.block_hash().0.as_slice() != before.hash {
        return Err(invalid());
    }
    Ok(state)
}

/// The maintained scanner's height-only rewind can lack a blocks-table row
/// for an account's retained birthday checkpoint. Recover that precise state
/// using the maintained tree API, after verified canonical before/after reads.
async fn run_reference_sync<C>(
    client: &mut MaintainedScannerClient,
    cache: &C,
    wallet: &mut LocalWallet,
    batch_size: u32,
) -> Result<(), ReferenceSyncError<C>>
where
    C: BlockCache,
    C::Error: Error + Send + Sync + 'static,
{
    let mut recovery_floor = None;
    loop {
        match sync::run(client, &Network::TestNetwork, cache, wallet, batch_size).await {
            Err(sync::Error::Wallet(error @ SqliteClientError::RequestedRewindInvalid { .. })) => {
                let SqliteClientError::RequestedRewindInvalid {
                    safe_rewind_height: Some(safe_height),
                    requested_height,
                } = &error
                else {
                    return Err(sync::Error::Wallet(error));
                };
                let (safe_height, requested_height) = (*safe_height, *requested_height);
                let scanned = wallet.block_max_scanned().map_err(sync::Error::Wallet)?;
                // Each recovery must actually lower local scanned state and,
                // if repeated, reach an earlier checkpoint. Repeated failure at
                // the same point is returned, with no retry quota invented.
                if safe_height > requested_height
                    || scanned.is_none_or(|block| block.block_height() <= safe_height)
                    || recovery_floor.is_some_and(|prior| safe_height >= prior)
                {
                    return Err(sync::Error::Wallet(error));
                }
                let selector = BlockId {
                    height: u64::from(u32::from(safe_height)),
                    hash: vec![],
                };
                let before = client.get_block(selector.clone()).await?.into_inner();
                // Hash selectors are exclusive of height in the pinned wire
                // contract; compare the returned height explicitly below.
                let tree = client
                    .get_tree_state(BlockId {
                        height: 0,
                        hash: before.hash.clone(),
                    })
                    .await?
                    .into_inner();
                let after = client.get_block(selector).await?.into_inner();
                let state =
                    checked_recovery_state(safe_height, requested_height, &before, tree, &after)?;
                wallet
                    .truncate_to_chain_state(state)
                    .map_err(sync::Error::Wallet)?;
                cache
                    .truncate(safe_height)
                    .await
                    .map_err(sync::Error::Cache)?;
                if wallet
                    .block_max_scanned()
                    .map_err(sync::Error::Wallet)?
                    .is_some_and(|block| block.block_height() > safe_height)
                    || cache
                        .get_tip_height(None)
                        .map_err(sync::Error::Cache)?
                        .is_some_and(|height| height > safe_height)
                {
                    return Err(sync::Error::Server(tonic::Status::data_loss(
                        "Wallet recovery did not rewind local state.",
                    )));
                }
                recovery_floor = Some(safe_height);
            }
            result => return result,
        }
    }
}

async fn scan(mut args: env::ArgsOs) -> Result<(), Box<dyn Error>> {
    let usage = "usage: zrpc-wallet-reference scan LOOPBACK_HOST:PORT CAPABILITY_DIR WALLET_DB CACHE_DB BATCH_SIZE";
    let connection = ReferenceConnection::parse(&mut args)?;
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
    let adapter = connection.connect().await?;
    let mut client = adapter.maintained_scanner_client();
    let cache = SqliteBlockCache::open(&cache_path)?;
    let mut prior_progress = scan_progress(&wallet, &cache)?;
    let _ = report_committed_scan(&adapter, &wallet).await?;
    loop {
        match run_reference_sync(&mut client, &cache, &mut wallet, batch_size).await {
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
                    let _ = report_committed_scan(&adapter, &wallet).await?;
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
        &adapter,
        &mut client,
        &mut wallet,
        wallet_path.parent().ok_or("wallet path has no parent")?,
    )
    .await?;

    // Only local derived totals and heights are printed. `is_synced` is the
    // maintained wallet scanner's local progress, not a claim of global tip
    // freshness or provider-independent TEE isolation.
    if let Some(summary) = wallet.get_wallet_summary(ConfirmationsPolicy::default())? {
        let local_status_reported = report_committed_scan(&adapter, &wallet).await?;
        println!(
            "wallet_scan_height={} wallet_tip_height={} compact_scan_complete={} accounts={} enhanced_transactions={} status_checks={} mined_transparent_history_reads={} pending_snapshot_checks={} pending_snapshot_deferred={} pending_unverified_checks={} unsupported_history_requests={} remaining_transaction_requests={} recurring_address_refresh_requests={} remaining_nonrecurring_requests={} local_status_reported={}",
            u32::from(summary.fully_scanned_height()),
            u32::from(summary.chain_tip_height()),
            summary.is_synced(),
            summary.account_balances().len(),
            enhanced.enhanced,
            enhanced.status_checks,
            enhanced.mined_transparent_history_reads,
            enhanced.pending_snapshot_checks,
            enhanced.pending_snapshot_deferred,
            enhanced.pending_unverified_checks,
            enhanced.unsupported_history_requests,
            enhanced.remaining_requests,
            enhanced.recurring_address_refresh_requests,
            enhanced.remaining_nonrecurring_requests,
            local_status_reported,
        );
        if let Some(observation) = enhanced.pending_observation {
            println!(
                "pending_wallet_anchor_height={} pending_node_snapshot_height={} pending_node_snapshot_hash_internal={} node_blocks_not_scanned={} snapshot_transactions_mined_during_fetch={} pending_scope=finite_node_snapshot_confirmed_history_through_wallet_anchor",
                observation.wallet_height,
                observation.snapshot_tip.height,
                internal_hash_hex(observation.snapshot_tip.hash),
                observation.unscanned_blocks(),
                observation.mined_during_fetch
            );
        }
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

// Snapshot IDs describe membership at T. A later raw read can report that a
// member mined above T; preserve that later observation instead of calling it
// pending. The actual pending-stream decoder remains strict about height zero.
fn checked_snapshot_transaction(
    expected_txid: &[u8],
    raw: &RawTransaction,
    next_height: BlockHeight,
) -> Result<(Transaction, Option<BlockHeight>), &'static str> {
    if raw.height == 0 {
        return Ok((
            checked_pending_transaction(expected_txid, raw, next_height)?,
            None,
        ));
    }
    let mined_height = u32::try_from(raw.height)
        .map_err(|_| "snapshot transaction is orphaned or has an invalid mined height")?;
    if mined_height < u32::from(next_height) {
        return Err("snapshot transaction was already mined at or before its snapshot tip");
    }
    let snapshot_height = u32::from(next_height)
        .checked_sub(1)
        .ok_or("snapshot transaction height is invalid")?;
    if pending_parse_height(snapshot_height, mined_height - 1)?.is_none() {
        return Err("snapshot transaction interpretation changed; scan again first");
    }
    let height = BlockHeight::from_u32(mined_height);
    let transaction = enhance::decode_transaction(raw, height)?;
    if expected_txid.len() != 32 || transaction.txid().as_ref().as_slice() != expected_txid {
        return Err("mempool returned a transaction with the wrong identifier");
    }
    Ok((transaction, Some(height)))
}

async fn pending(mut args: env::ArgsOs) -> Result<(), Box<dyn Error>> {
    let usage = "usage: zrpc-wallet-reference pending LOOPBACK_HOST:PORT CAPABILITY_DIR WALLET_DB";
    let connection = ReferenceConnection::parse(&mut args)?;
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
    let adapter = connection.connect().await?;
    let mut client = adapter.maintained_scanner_client();
    let observation = process_pending_snapshot(
        &adapter,
        &mut client,
        &mut wallet,
        wallet_path.parent().ok_or("wallet path has no parent")?,
    )
    .await?
    .require_complete()?;
    println!(
        "mempool_transactions_processed={} wallet_anchor_height={} node_snapshot_height={} node_snapshot_hash_internal={} node_blocks_not_scanned={} snapshot_transactions_mined_during_fetch={} status=observed_at_node_snapshot_rescan_to_reconcile",
        observation.transaction_count,
        observation.wallet_height,
        observation.snapshot_tip.height,
        internal_hash_hex(observation.snapshot_tip.hash),
        observation.unscanned_blocks(),
        observation.mined_during_fetch
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingSnapshotOutcome {
    Complete(PendingObservation),
    RescanRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PendingObservation {
    pub transaction_count: u64,
    /// Snapshot members observed as mined above T by a later raw read. This
    /// is not a simultaneous status observation or a scanned-block count.
    pub mined_during_fetch: u64,
    pub wallet_height: u32,
    pub snapshot_tip: NodeReadContext,
}

impl PendingObservation {
    fn unscanned_blocks(self) -> u32 {
        // Construction requires snapshot_tip.height >= wallet_height.
        self.snapshot_tip.height - self.wallet_height
    }
}

fn internal_hash_hex(hash: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::new();
    for byte in hash {
        write!(&mut encoded, "{byte:02x}").expect("writing to String is infallible");
    }
    encoded
}

impl PendingSnapshotOutcome {
    fn require_complete(self) -> Result<PendingObservation, &'static str> {
        match self {
            Self::Complete(observation) => Ok(observation),
            Self::RescanRequired => Err(
                "node snapshot or interpretation differs from the scanned wallet; scan again first",
            ),
        }
    }
}

pub(crate) async fn process_pending_snapshot(
    adapter: &LocalWalletAdapter,
    client: &mut MaintainedScannerClient,
    wallet: &mut LocalWallet,
    stage_dir: &Path,
) -> Result<PendingSnapshotOutcome, Box<dyn Error>> {
    let local_tip = wallet
        .chain_height()?
        .ok_or("wallet chain tip unavailable")?;
    let local_hash = wallet
        .get_block_hash(local_tip)?
        .ok_or("wallet scan tip hash unavailable")?;
    let wallet_anchor = NodeReadContext {
        height: u32::from(local_tip),
        hash: local_hash.0,
    };
    let before = client
        .get_block(BlockId {
            height: u64::from(wallet_anchor.height),
            hash: vec![],
        })
        .await?
        .into_inner();
    if !matches_pending_anchor(wallet_anchor, &before) {
        return Ok(PendingSnapshotOutcome::RescanRequired);
    }
    // This project-specific read snapshots every local-node mempool ID,
    // including transparent-only transactions. The first item anchors the
    // finite set to an observed node tip. It can be newer than the wallet's
    // scanned tip; no confirmed block beyond that scanned tip is marked read.
    let mut snapshot_client = adapter.snapshot_client();
    let mut stream = snapshot_client
        .get_mempool_snapshot(snapshot_wire::SnapshotRequest {})
        .await?
        .into_inner();
    // The bridge serializes wallet RPCs while a stream is active. Finish this
    // stream before asking for full transactions on the same local client.
    let mut ids = enhance::open_history_stage(stage_dir)?;
    let mut staged_count = 0_u64;
    let mut snapshot_tip = None;
    while let Some(item) = stream.message().await? {
        match item.body {
            Some(snapshot_wire::snapshot_item::Body::Tip(tip)) if snapshot_tip.is_none() => {
                // The maintained scanner and project extension use distinct
                // generated protobuf types. Preserve their actual field bytes.
                let anchor = NodeReadContext {
                    height: tip
                        .height
                        .try_into()
                        .map_err(|_| "mempool snapshot height is malformed")?,
                    hash: tip
                        .hash
                        .as_slice()
                        .try_into()
                        .map_err(|_| "mempool snapshot hash is malformed")?,
                };
                if pending_parse_height(wallet_anchor.height, anchor.height)?.is_none()
                    || (anchor.height == wallet_anchor.height && anchor.hash != wallet_anchor.hash)
                {
                    return Ok(PendingSnapshotOutcome::RescanRequired);
                }
                snapshot_tip = Some(anchor);
            }
            Some(snapshot_wire::snapshot_item::Body::Txid(txid)) if snapshot_tip.is_some() => {
                if txid.len() != 32 {
                    return Err("mempool returned an invalid transaction identifier".into());
                }
                ids.write_all(&txid)?;
                staged_count = staged_count
                    .checked_add(1)
                    .ok_or("mempool transaction count overflow")?;
            }
            _ => return Err("mempool snapshot is malformed".into()),
        }
    }
    let snapshot_tip = snapshot_tip.ok_or("mempool snapshot omitted its chain tip")?;
    let next_height = pending_parse_height(wallet_anchor.height, snapshot_tip.height)?
        .ok_or("snapshot interpretation changed")?;
    drop(stream);
    ids.seek(SeekFrom::Start(0))?;
    // Stage full transactions in an unnamed local file so a failed read
    // cannot partially update the wallet or consume unbounded memory.
    let mut stage = enhance::open_history_stage(stage_dir)?;
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
        checked_snapshot_transaction(&txid, &raw, next_height)?;
        stage.write_all(&txid)?;
        stage.write_all(&raw.height.to_le_bytes())?;
        stage.write_all(&u64::try_from(raw.data.len())?.to_le_bytes())?;
        stage.write_all(&raw.data)?;
    }
    if ids.stream_position()? != ids.metadata()?.len() {
        return Err("staged mempool identifiers have trailing bytes".into());
    }
    let snapshot_after = client
        .get_block(BlockId {
            height: u64::from(snapshot_tip.height),
            hash: vec![],
        })
        .await?
        .into_inner();
    let wallet_after = if snapshot_tip.height == wallet_anchor.height {
        snapshot_after.clone()
    } else {
        client
            .get_block(BlockId {
                height: u64::from(wallet_anchor.height),
                hash: vec![],
            })
            .await?
            .into_inner()
    };
    commit_pending_stage(
        wallet,
        &mut stage,
        staged_count,
        wallet_anchor,
        snapshot_tip,
        &wallet_after,
        &snapshot_after,
    )
}

fn commit_pending_stage(
    wallet: &mut LocalWallet,
    stage: &mut File,
    staged_count: u64,
    wallet_anchor: NodeReadContext,
    snapshot_tip: NodeReadContext,
    wallet_after: &CompactBlock,
    snapshot_after: &CompactBlock,
) -> Result<PendingSnapshotOutcome, Box<dyn Error>> {
    // The production entry point remains bound to a TestNetwork LocalWallet.
    commit_pending_stage_for_store(
        wallet,
        stage,
        staged_count,
        wallet_anchor,
        snapshot_tip,
        wallet_after,
        snapshot_after,
    )
}

// Kept private so maintained synthetic stores can exercise this same atomic
// operation without relabeling their regtest viewing keys as testnet keys.
fn commit_pending_stage_for_store<P: zcash_protocol::consensus::Parameters + Clone>(
    wallet: &mut WalletDb<Connection, P, SystemClock, UnwrapErr<SysRng>>,
    stage: &mut File,
    staged_count: u64,
    wallet_anchor: NodeReadContext,
    snapshot_tip: NodeReadContext,
    wallet_after: &CompactBlock,
    snapshot_after: &CompactBlock,
) -> Result<PendingSnapshotOutcome, Box<dyn Error>> {
    let Some(next_height) = pending_parse_height(wallet_anchor.height, snapshot_tip.height)? else {
        return Ok(PendingSnapshotOutcome::RescanRequired);
    };
    // Reorganizations at either anchor invalidate all staged data. Ordinary
    // extensions above the snapshot do not. These checks precede opening the
    // wallet transaction, including when the finite snapshot is empty.
    if !matches_pending_anchor(wallet_anchor, wallet_after)
        || !matches_pending_anchor(snapshot_tip, snapshot_after)
    {
        return Ok(PendingSnapshotOutcome::RescanRequired);
    }
    stage.seek(SeekFrom::Start(0))?;
    let params = wallet.params().clone();
    let mined_during_fetch = wallet.transactionally(|wdb| -> Result<u64, Box<dyn Error>> {
        let mut mined_during_fetch = 0_u64;
        for _ in 0..staged_count {
            let mut txid = [0_u8; 32];
            stage.read_exact(&mut txid)?;
            let mut height = [0_u8; 8];
            stage.read_exact(&mut height)?;
            let height = u64::from_le_bytes(height);
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
            let (transaction, mined_height) =
                checked_snapshot_transaction(&txid, &RawTransaction { data, height }, next_height)?;
            decrypt_and_store_transaction(&params, wdb, &transaction, mined_height)?;
            if mined_height.is_some() {
                mined_during_fetch = mined_during_fetch
                    .checked_add(1)
                    .ok_or("snapshot mined-transaction count overflow")?;
            }
        }
        if stage.stream_position()? != stage.metadata()?.len() {
            return Err("staged mempool data has trailing bytes".into());
        }
        Ok(mined_during_fetch)
    })?;
    // Complete only for the node's local mempool at the snapshot instant. It
    // does not assert that the network mempool stayed unchanged afterward.
    Ok(PendingSnapshotOutcome::Complete(PendingObservation {
        transaction_count: staged_count,
        mined_during_fetch,
        wallet_height: wallet_anchor.height,
        snapshot_tip,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn embedded_args() -> Vec<OsString> {
        [
            "--embedded",
            "--privacy-profile",
            "phala-trusted",
            "--platform",
            "phala-dstack",
            "--endpoint-host",
            "rpc.example",
            "--endpoint-port",
            "443",
            "--tor-executable",
            "/usr/bin/tor",
            "--collateral",
            "/fixture/collateral",
            "--app-compose",
            "/fixture/compose",
            "--release-policy",
            "/fixture/policy",
            "--ticket-store",
            "/fixture/tickets",
            "--issuer-public-der",
            "/fixture/issuer.der",
            "--issuer-name",
            "fixture-issuer",
            "--crypto-helper",
            "/fixture/crypto-helper",
            "--",
            "wallet.sqlite",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn embedded_connection_uses_exact_inputs_without_local_bridge_configuration() {
        let mut args = embedded_args().into_iter();
        let ReferenceConnection::Embedded(input) = ReferenceConnection::parse(&mut args).unwrap()
        else {
            panic!("explicit embedded mode selected a local connection")
        };
        assert_eq!(input.host, "rpc.example");
        assert_eq!(input.port, 443);
        assert_eq!(input.tor_executable, Path::new("/usr/bin/tor"));
        assert_eq!(input.collateral, Path::new("/fixture/collateral"));
        assert_eq!(input.compose, Path::new("/fixture/compose"));
        assert_eq!(input.policy, Path::new("/fixture/policy"));
        assert_eq!(input.tickets, Path::new("/fixture/tickets"));
        assert_eq!(input.issuer_der, Path::new("/fixture/issuer.der"));
        assert_eq!(input.issuer_name, "fixture-issuer");
        assert_eq!(input.crypto_helper, Path::new("/fixture/crypto-helper"));
        assert_eq!(args.next().unwrap(), "wallet.sqlite");
        assert!(args.next().is_none());
    }

    #[test]
    fn embedded_connection_rejects_profile_provider_and_option_ambiguity() {
        for (flag, value) in [
            ("--privacy-profile", "provider-independent"),
            ("--platform", "gcp-tdx"),
        ] {
            let mut args = embedded_args();
            let index = args.iter().position(|arg| arg == flag).unwrap();
            args[index + 1] = OsString::from(value);
            assert!(ReferenceConnection::parse(&mut args.into_iter()).is_err());
        }
        let mut duplicate = embedded_args();
        duplicate.splice(
            1..1,
            [OsString::from("--endpoint-port"), OsString::from("444")],
        );
        assert!(ReferenceConnection::parse(&mut duplicate.into_iter()).is_err());
        let mut missing = embedded_args();
        let index = missing
            .iter()
            .position(|arg| arg == "--release-policy")
            .unwrap();
        missing.drain(index..index + 2);
        assert!(ReferenceConnection::parse(&mut missing.into_iter()).is_err());
        assert!(
            ReferenceConnection::parse(&mut [OsString::from("--embedded")].into_iter()).is_err()
        );
    }

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
    fn pending_reader_anchor_comparison_uses_internal_hash_bytes() {
        let hash: [u8; 32] = std::array::from_fn(|index| index as u8);
        let height = BlockHeight::from_u32(42);
        let anchor = NodeReadContext {
            height: u32::from(height),
            hash,
        };
        assert!(matches_pending_anchor(
            anchor,
            &CompactBlock {
                height: 42,
                hash: hash.to_vec(),
                ..Default::default()
            }
        ));
        assert!(!matches_pending_anchor(
            anchor,
            &CompactBlock {
                height: 42,
                hash: hash.iter().rev().copied().collect(),
                ..Default::default()
            }
        ));
    }

    fn pending_test_wallet(height: u32) -> (tempfile::TempDir, LocalWallet) {
        let directory = tempfile::tempdir().unwrap();
        let connection = Connection::open(directory.path().join("wallet.sqlite")).unwrap();
        rusqlite::vtab::array::load_module(&connection).unwrap();
        let mut wallet = WalletDb::from_connection(
            connection,
            Network::TestNetwork,
            SystemClock,
            UnwrapErr(SysRng),
        );
        init_wallet_db(&mut wallet, None).unwrap();
        wallet
            .update_chain_tip(BlockHeight::from_u32(height))
            .unwrap();
        (directory, wallet)
    }

    fn observed_block(anchor: NodeReadContext) -> CompactBlock {
        CompactBlock {
            height: u64::from(anchor.height),
            hash: anchor.hash.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn pending_observation_accepts_normal_extension_without_promoting_wallet_height() {
        let wallet_anchor = NodeReadContext {
            height: 4_472_141,
            hash: [1; 32],
        };
        let snapshot_tip = NodeReadContext {
            height: wallet_anchor.height + 1,
            hash: [2; 32],
        };
        let (directory, mut wallet) = pending_test_wallet(wallet_anchor.height);
        let mut stage = enhance::open_history_stage(directory.path()).unwrap();
        let result = commit_pending_stage(
            &mut wallet,
            &mut stage,
            0,
            wallet_anchor,
            snapshot_tip,
            &observed_block(wallet_anchor),
            &observed_block(snapshot_tip),
        )
        .unwrap()
        .require_complete()
        .unwrap();
        assert_eq!(result.transaction_count, 0);
        assert_eq!(result.mined_during_fetch, 0);
        assert_eq!(result.wallet_height, wallet_anchor.height);
        assert_eq!(result.snapshot_tip, snapshot_tip);
        assert_eq!(result.unscanned_blocks(), 1);
        assert_eq!(
            wallet.chain_height().unwrap(),
            Some(BlockHeight::from_u32(wallet_anchor.height))
        );
    }

    #[test]
    fn pending_changed_anchor_rejects_staged_data_before_wallet_mutation() {
        let wallet_anchor = NodeReadContext {
            height: 4_472_141,
            hash: [1; 32],
        };
        let snapshot_tip = NodeReadContext {
            height: wallet_anchor.height + 1,
            hash: [2; 32],
        };
        for changed_wallet in [false, true] {
            let (directory, mut wallet) = pending_test_wallet(wallet_anchor.height);
            let mut stage = enhance::open_history_stage(directory.path()).unwrap();
            // This record cannot be parsed. Anchor rejection must precede even
            // reading it, as well as opening a wallet transaction.
            stage
                .write_all(b"incomplete synthetic staged transaction")
                .unwrap();
            let mut wallet_after = observed_block(wallet_anchor);
            let mut snapshot_after = observed_block(snapshot_tip);
            if changed_wallet {
                wallet_after.hash[0] ^= 1;
            } else {
                snapshot_after.hash[0] ^= 1;
            }
            assert_eq!(
                commit_pending_stage(
                    &mut wallet,
                    &mut stage,
                    1,
                    wallet_anchor,
                    snapshot_tip,
                    &wallet_after,
                    &snapshot_after
                )
                .unwrap(),
                PendingSnapshotOutcome::RescanRequired
            );
            let observer = Connection::open(directory.path().join("wallet.sqlite")).unwrap();
            assert_eq!(
                observer
                    .query_row("SELECT COUNT(*) FROM transactions", [], |row| row
                        .get::<_, u64>(0))
                    .unwrap(),
                0
            );
            assert_eq!(
                wallet.chain_height().unwrap(),
                Some(BlockHeight::from_u32(wallet_anchor.height))
            );
        }
    }

    #[test]
    fn pending_node_behind_or_interpretation_boundary_requires_rescan() {
        use zcash_protocol::consensus::{NetworkUpgrade, Parameters};
        assert_eq!(pending_parse_height(4_472_141, 4_472_140).unwrap(), None);
        assert!(pending_parse_height(u32::MAX, u32::MAX).is_err());
        let nu7 = u32::from(
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu7)
                .unwrap(),
        );
        assert_eq!(pending_parse_height(nu7 - 2, nu7 - 1).unwrap(), None);
        let canopy = Network::TestNetwork
            .activation_height(NetworkUpgrade::Canopy)
            .unwrap();
        let before_nu5 = Network::TestNetwork
            .activation_height(NetworkUpgrade::Nu5)
            .unwrap()
            - 1;
        assert_eq!(
            BranchId::for_height(&Network::TestNetwork, canopy),
            BranchId::for_height(&Network::TestNetwork, before_nu5)
        );
        assert_ne!(
            zip212_enforcement(&Network::TestNetwork, canopy),
            zip212_enforcement(&Network::TestNetwork, before_nu5)
        );
        assert_eq!(
            pending_parse_height(u32::from(canopy) - 1, u32::from(before_nu5) - 1).unwrap(),
            None
        );
    }

    #[test]
    fn incomplete_pending_stage_rolls_back_the_wallet_transaction() {
        use zcash_client_backend::data_api::testing::{
            DataStoreFactory, TestBuilder,
            pool::{ShieldedPoolTester, dsl::TestDsl},
            sapling::SaplingPoolTester,
        };
        use zcash_client_sqlite::testing::db::TestDbFactory;
        use zcash_protocol::{
            consensus::{NetworkUpgrade, Parameters},
            local_consensus::LocalNetwork,
            value::Zatoshis,
        };
        // Use the maintained synthetic builder with the actual testnet
        // activation schedule: production parsing remains TestNetwork.
        let params = Network::TestNetwork;
        let network = LocalNetwork {
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
        };
        let cache = SqliteBlockCache::open(Path::new(":memory:")).unwrap();
        let builder = TestBuilder::new()
            .with_network(network)
            .with_data_store_factory(TestDbFactory::file_backed())
            .with_block_cache(cache)
            .with_account_from_sapling_activation(zcash_primitives::block::BlockHash([0; 32]));
        let mut scenario = TestDsl::from(builder).build::<SaplingPoolTester>();
        let account = scenario.get_account();
        let viewing_key = account.usk().to_unified_full_viewing_key();
        let birthday = account.birthday().clone();
        let (funding_height, _, _) =
            scenario.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60_000));
        let recipient = SaplingPoolTester::sk_default_address(&SaplingPoolTester::sk(&[0xf5; 32]));
        let txid = scenario.spend_to(&recipient, Zatoshis::const_from_u64(10_000));
        let tx = scenario.wallet().get_transaction(txid).unwrap().unwrap();
        let mut data = Vec::new();
        tx.write(&mut data).unwrap();
        let _original_file = scenario.reset().expect("file-backed synthetic wallet");
        // TestDb::reset intentionally uses the default in-memory factory.
        // Restore into an explicitly file-backed store so the independent
        // observer and reopened synthetic store see the same SQL state.
        *scenario.wallet_mut() = TestDbFactory::file_backed()
            .new_data_store(network, None, None)
            .unwrap();
        scenario
            .wallet_mut()
            .import_account_ufvk(
                "synthetic view-only restore",
                &viewing_key,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )
            .unwrap();
        scenario
            .wallet_mut()
            .update_chain_tip(funding_height)
            .unwrap();
        scenario.scan_cached_blocks(funding_height, 1);
        let wallet_file = scenario.reset().expect("file-backed restored wallet");
        let conn = Connection::open(wallet_file.path()).unwrap();
        rusqlite::vtab::array::load_module(&conn).unwrap();
        let mut wallet = WalletDb::from_connection(conn, network, SystemClock, UnwrapErr(SysRng));
        init_wallet_db(&mut wallet, None).unwrap();
        assert!(wallet.get_transaction(txid).unwrap().is_none());
        let directory = tempfile::tempdir().unwrap();
        let height = u32::from(funding_height);
        let anchor = NodeReadContext {
            height,
            hash: [1; 32],
        };
        let observer = Connection::open(wallet_file.path()).unwrap();
        let baseline: u64 = observer
            .query_row("SELECT COUNT(*) FROM transactions", [], |row| row.get(0))
            .unwrap();
        let mut stage = enhance::open_history_stage(directory.path()).unwrap();
        stage.write_all(tx.txid().as_ref()).unwrap();
        // This snapshot member mined in the next block before its raw read.
        // Its mined height must survive staging without promoting wallet H.
        stage
            .write_all(&u64::from(height + 1).to_le_bytes())
            .unwrap();
        stage
            .write_all(&u64::try_from(data.len()).unwrap().to_le_bytes())
            .unwrap();
        stage.write_all(&data).unwrap();
        // A second identifier without its length or body is not a complete
        // finite result. Any first-transaction writes must be rolled back.
        stage.write_all(&[3; 32]).unwrap();
        assert!(
            commit_pending_stage_for_store(
                &mut wallet,
                &mut stage,
                2,
                anchor,
                anchor,
                &observed_block(anchor),
                &observed_block(anchor)
            )
            .is_err()
        );
        assert_eq!(
            observer
                .query_row("SELECT COUNT(*) FROM transactions", [], |row| row
                    .get::<_, u64>(0))
                .unwrap(),
            baseline
        );
        assert!(wallet.get_transaction(txid).unwrap().is_none());
        assert_eq!(
            wallet.chain_height().unwrap(),
            Some(BlockHeight::from_u32(height))
        );
        // Positive control: the same first transaction must cause durable
        // writes when its finite result is complete. Otherwise the preceding
        // rollback assertion would not demonstrate an actual rolled-back write.
        stage
            .set_len(u64::try_from(32 + 8 + 8 + data.len()).unwrap())
            .unwrap();
        let observation = commit_pending_stage_for_store(
            &mut wallet,
            &mut stage,
            1,
            anchor,
            anchor,
            &observed_block(anchor),
            &observed_block(anchor),
        )
        .unwrap()
        .require_complete()
        .unwrap();
        assert_eq!(observation.mined_during_fetch, 1);
        // Maintained get_tx_height deliberately hides mined observations
        // above chain_tip_height. Prove preservation in SQL independently of
        // the wallet's still-unadvanced confirmed-height API.
        let stored_mined_height: u32 = observer
            .query_row(
                "SELECT mined_height FROM transactions WHERE txid = ?1",
                [txid.as_ref()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_mined_height, u32::from(funding_height + 1));
        assert_eq!(wallet.get_tx_height(txid).unwrap(), None);
        assert_eq!(wallet.chain_height().unwrap(), Some(funding_height));
        assert!(
            observer
                .query_row("SELECT COUNT(*) FROM transactions", [], |row| row
                    .get::<_, u64>(0))
                .unwrap()
                > baseline
        );
        assert_eq!(
            wallet.get_transaction(tx.txid()).unwrap().unwrap().txid(),
            tx.txid()
        );
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

    #[test]
    fn snapshot_member_can_mine_after_capture_without_becoming_pending() {
        let data =
            hex::decode(include_str!("../../../tests/fixtures/zcash/testnet-v4-tx.hex").trim())
                .unwrap();
        let next_height = BlockHeight::from_u32(280_003);
        let pending = RawTransaction { data, height: 0 };
        let txid = enhance::decode_pending_transaction(&pending, next_height)
            .unwrap()
            .txid();
        let (tx, mined) =
            checked_snapshot_transaction(txid.as_ref(), &pending, next_height).unwrap();
        assert_eq!(tx.txid(), txid);
        assert_eq!(mined, None);
        let later = RawTransaction {
            height: 280_004,
            ..pending
        };
        let (tx, mined) = checked_snapshot_transaction(txid.as_ref(), &later, next_height).unwrap();
        assert_eq!(tx.txid(), txid);
        assert_eq!(mined, Some(BlockHeight::from_u32(280_004)));
        assert!(checked_pending_transaction(txid.as_ref(), &later, next_height).is_err());
        assert!(checked_snapshot_transaction(&[0; 32], &later, next_height).is_err());
        let mut trailing = later.clone();
        trailing.data.push(0);
        assert!(checked_snapshot_transaction(txid.as_ref(), &trailing, next_height).is_err());
        // Even a same-regime height cannot bypass canonical transaction parsing.
        assert!(
            checked_snapshot_transaction(
                txid.as_ref(),
                &RawTransaction {
                    data: vec![],
                    height: 280_004
                },
                next_height
            )
            .is_err()
        );
    }

    #[test]
    fn snapshot_member_rejects_preexisting_mined_or_orphaned_or_incompatible_status() {
        use zcash_protocol::consensus::{NetworkUpgrade, Parameters};
        let data =
            hex::decode(include_str!("../../../tests/fixtures/zcash/testnet-v4-tx.hex").trim())
                .unwrap();
        let next_height = BlockHeight::from_u32(280_003);
        let raw = RawTransaction { data, height: 0 };
        let txid = enhance::decode_pending_transaction(&raw, next_height)
            .unwrap()
            .txid();
        for height in [280_001, 280_002, u64::MAX, u64::from(u32::MAX) + 1] {
            let response = RawTransaction {
                height,
                data: raw.data.clone(),
            };
            assert!(checked_snapshot_transaction(txid.as_ref(), &response, next_height).is_err());
        }
        let nu7 = Network::TestNetwork
            .activation_height(NetworkUpgrade::Nu7)
            .unwrap();
        // Regime validation precedes parsing; unsupported transitions must
        // demand another scan rather than guess the transaction branch.
        assert!(
            checked_snapshot_transaction(
                txid.as_ref(),
                &RawTransaction {
                    height: u64::from(u32::from(nu7)),
                    data: raw.data.clone()
                },
                nu7 - 1
            )
            .is_err()
        );
        let canopy = Network::TestNetwork
            .activation_height(NetworkUpgrade::Canopy)
            .unwrap();
        let before_nu5 = Network::TestNetwork
            .activation_height(NetworkUpgrade::Nu5)
            .unwrap()
            - 1;
        assert_eq!(
            BranchId::for_height(&Network::TestNetwork, canopy),
            BranchId::for_height(&Network::TestNetwork, before_nu5)
        );
        assert_ne!(
            zip212_enforcement(&Network::TestNetwork, canopy),
            zip212_enforcement(&Network::TestNetwork, before_nu5)
        );
        assert!(
            checked_snapshot_transaction(
                txid.as_ref(),
                &RawTransaction {
                    height: u64::from(u32::from(before_nu5)),
                    data: raw.data
                },
                canopy
            )
            .is_err()
        );
    }
}
