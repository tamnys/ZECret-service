//! Durable cache for public compact blocks. Initial wallet recovery does not
//! retain the entire requested chain range in process memory.

use async_trait::async_trait;
use prost::Message;
use rusqlite::{Connection, OpenFlags, params};
use std::{error::Error, fmt, path::Path, sync::Mutex};
use zcash_client_backend::{
    data_api::{
        chain::{BlockCache, BlockSource, error::Error as ChainError},
        scanning::ScanRange,
    },
    proto::compact_formats::CompactBlock,
};
use zcash_protocol::consensus::BlockHeight;

#[derive(Debug)]
pub enum CacheError {
    Database,
    Decode,
    Missing,
    Poisoned,
    Height,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Database => "compact block cache database unavailable",
            Self::Decode => "compact block cache contains malformed data",
            Self::Missing => "compact block cache range is incomplete",
            Self::Poisoned => "compact block cache lock unavailable",
            Self::Height => "compact block cache height is invalid",
        })
    }
}

impl Error for CacheError {}

pub struct SqliteBlockCache(Mutex<Connection>);

impl SqliteBlockCache {
    pub fn open(path: &Path) -> Result<Self, CacheError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| CacheError::Database)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS compact_blocks (
                height INTEGER PRIMARY KEY NOT NULL,
                payload BLOB NOT NULL
            );",
        )
        .map_err(|_| CacheError::Database)?;
        Ok(Self(Mutex::new(conn)))
    }

    fn selected(
        &self,
        start: u32,
        end: Option<u32>,
        limit: Option<usize>,
    ) -> Result<Vec<CompactBlock>, CacheError> {
        let conn = self.0.lock().map_err(|_| CacheError::Poisoned)?;
        let mut stmt = conn
            .prepare("SELECT height, payload FROM compact_blocks WHERE height >= ?1 AND (?2 IS NULL OR height < ?2) ORDER BY height ASC")
            .map_err(|_| CacheError::Database)?;
        let mut rows = stmt
            .query(params![i64::from(start), end.map(i64::from)])
            .map_err(|_| CacheError::Database)?;
        let mut result = Vec::new();
        let mut expected = start;
        while limit.is_none_or(|max| result.len() < max) {
            let Some(row) = rows.next().map_err(|_| CacheError::Database)? else {
                break;
            };
            let height: i64 = row.get(0).map_err(|_| CacheError::Database)?;
            if height != i64::from(expected) {
                return Err(CacheError::Missing);
            }
            let payload: Vec<u8> = row.get(1).map_err(|_| CacheError::Database)?;
            let block = CompactBlock::decode(payload.as_slice()).map_err(|_| CacheError::Decode)?;
            if block.height != u64::from(expected) {
                return Err(CacheError::Decode);
            }
            result.push(block);
            expected = expected.checked_add(1).ok_or(CacheError::Height)?;
        }
        if end.is_some_and(|end| expected != end)
            || limit.is_some_and(|requested| result.len() != requested)
        {
            return Err(CacheError::Missing);
        }
        Ok(result)
    }
}

impl BlockSource for SqliteBlockCache {
    type Error = CacheError;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ChainError<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ChainError<WalletErrT, Self::Error>>,
    {
        let start = if let Some(height) = from_height {
            height.into()
        } else {
            let conn = self
                .0
                .lock()
                .map_err(|_| ChainError::BlockSource(CacheError::Poisoned))?;
            let first: Option<i64> = conn
                .query_row("SELECT MIN(height) FROM compact_blocks", [], |row| {
                    row.get(0)
                })
                .map_err(|_| ChainError::BlockSource(CacheError::Database))?;
            let Some(first) = first else { return Ok(()) };
            u32::try_from(first).map_err(|_| ChainError::BlockSource(CacheError::Height))?
        };
        let blocks = self
            .selected(start, None, limit)
            .map_err(ChainError::BlockSource)?;
        for block in blocks {
            with_block(block)?;
        }
        Ok(())
    }
}

#[async_trait]
impl BlockCache for SqliteBlockCache {
    fn get_tip_height(
        &self,
        range: Option<&ScanRange>,
    ) -> Result<Option<BlockHeight>, Self::Error> {
        let conn = self.0.lock().map_err(|_| CacheError::Poisoned)?;
        let (start, end) = match range {
            Some(range) => (
                Some(i64::from(u32::from(range.block_range().start))),
                Some(i64::from(u32::from(range.block_range().end))),
            ),
            None => (None, None),
        };
        let tip: Option<i64> = conn
            .query_row(
                "SELECT MAX(height) FROM compact_blocks WHERE (?1 IS NULL OR height >= ?1) AND (?2 IS NULL OR height < ?2)",
                params![start, end],
                |row| row.get(0),
            )
            .map_err(|_| CacheError::Database)?;
        tip.map(|height| {
            u32::try_from(height)
                .map(BlockHeight::from_u32)
                .map_err(|_| CacheError::Height)
        })
        .transpose()
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
        self.selected(
            range.block_range().start.into(),
            Some(range.block_range().end.into()),
            None,
        )
    }

    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
        let mut conn = self.0.lock().map_err(|_| CacheError::Poisoned)?;
        let tx = conn.transaction().map_err(|_| CacheError::Database)?;
        for block in compact_blocks {
            let height = u32::try_from(block.height).map_err(|_| CacheError::Height)?;
            tx.execute(
                "INSERT OR REPLACE INTO compact_blocks(height, payload) VALUES(?1, ?2)",
                params![i64::from(height), block.encode_to_vec()],
            )
            .map_err(|_| CacheError::Database)?;
        }
        tx.commit().map_err(|_| CacheError::Database)
    }

    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
        let conn = self.0.lock().map_err(|_| CacheError::Poisoned)?;
        conn.execute(
            "DELETE FROM compact_blocks WHERE height >= ?1 AND height < ?2",
            params![
                i64::from(u32::from(range.block_range().start)),
                i64::from(u32::from(range.block_range().end))
            ],
        )
        .map_err(|_| CacheError::Database)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::data_api::{
        Account,
        scanning::ScanPriority,
        testing::{
            AddressType, CacheInsertionResult, TestCache,
            orchard::OrchardPoolTester,
            pool::{ShieldedPoolTester, dsl::TestDsl},
            sapling::SaplingPoolTester,
        },
        wallet::ConfirmationsPolicy,
    };
    use zcash_client_sqlite::testing::db::TestDbFactory;
    use zcash_protocol::{TxId, value::Zatoshis};

    pub struct TestInsertion(Vec<TxId>);

    impl CacheInsertionResult for TestInsertion {
        fn txids(&self) -> &[TxId] {
            &self.0
        }
    }

    // The maintained test builder generates encrypted notes. Route its block
    // inserts and scans through the cache used by the reference reader.
    impl TestCache for SqliteBlockCache {
        type BsError = CacheError;
        type BlockSource = Self;
        type InsertResult = TestInsertion;

        fn block_source(&self) -> &Self::BlockSource {
            self
        }

        fn insert(&mut self, block: &CompactBlock) -> Self::InsertResult {
            let conn = self.0.lock().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO compact_blocks(height, payload) VALUES(?1, ?2)",
                params![block.height as i64, block.encode_to_vec()],
            )
            .unwrap();
            TestInsertion(block.vtx.iter().map(|tx| tx.txid()).collect())
        }

        fn truncate_to_height(&mut self, height: BlockHeight) {
            let conn = self.0.lock().unwrap();
            conn.execute(
                "DELETE FROM compact_blocks WHERE height > ?1",
                params![i64::from(u32::from(height))],
            )
            .unwrap();
        }
    }

    const PUBLIC_BLOCK_4465070: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/zcash/testnet-compact-4465070.pb"
    ));
    const PUBLIC_BLOCK_4465071: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/zcash/testnet-compact-4465071.pb"
    ));

    fn block(height: u64) -> CompactBlock {
        CompactBlock {
            height,
            ..Default::default()
        }
    }

    fn range(start: u32, end: u32) -> ScanRange {
        ScanRange::from_parts(
            BlockHeight::from_u32(start)..BlockHeight::from_u32(end),
            ScanPriority::Historic,
        )
    }

    #[tokio::test]
    async fn incomplete_range_never_looks_complete() {
        let cache = SqliteBlockCache::open(Path::new(":memory:")).unwrap();
        cache.insert(vec![block(1), block(3)]).await.unwrap();
        assert!(matches!(
            cache.read(&range(1, 4)).await,
            Err(CacheError::Missing)
        ));
        assert!(matches!(
            cache.with_blocks::<_, ()>(Some(BlockHeight::from_u32(1)), None, |_| Ok(())),
            Err(ChainError::BlockSource(CacheError::Missing))
        ));
        cache.insert(vec![block(2)]).await.unwrap();
        assert_eq!(cache.read(&range(1, 4)).await.unwrap().len(), 3);
        assert!(matches!(
            cache.with_blocks::<_, ()>(Some(BlockHeight::from_u32(1)), Some(4), |_| Ok(())),
            Err(ChainError::BlockSource(CacheError::Missing))
        ));
        cache.delete(range(2, 4)).await.unwrap();
        assert_eq!(
            cache.get_tip_height(None).unwrap(),
            Some(BlockHeight::from_u32(1))
        );
    }

    #[tokio::test]
    async fn invalid_insert_rolls_back_entire_batch() {
        let cache = SqliteBlockCache::open(Path::new(":memory:")).unwrap();
        assert!(matches!(
            cache
                .insert(vec![block(1), block(u64::from(u32::MAX) + 1)])
                .await,
            Err(CacheError::Height)
        ));
        assert_eq!(cache.get_tip_height(None).unwrap(), None);
    }

    #[tokio::test]
    async fn public_nu7_blocks_survive_restart_without_partial_range_success() {
        let first = CompactBlock::decode(PUBLIC_BLOCK_4465070).unwrap();
        let second = CompactBlock::decode(PUBLIC_BLOCK_4465071).unwrap();
        assert_eq!(first.height, 4_465_070);
        assert_eq!(second.height, 4_465_071);
        assert_eq!(second.prev_hash, first.hash);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("compact.sqlite");
        let cache = SqliteBlockCache::open(&path).unwrap();
        cache.insert(vec![first.clone()]).await.unwrap();
        drop(cache);

        let cache = SqliteBlockCache::open(&path).unwrap();
        assert!(matches!(
            cache.read(&range(4_465_070, 4_465_072)).await,
            Err(CacheError::Missing)
        ));
        cache.insert(vec![second.clone()]).await.unwrap();
        drop(cache);

        let cache = SqliteBlockCache::open(&path).unwrap();
        let recovered = cache.read(&range(4_465_070, 4_465_072)).await.unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].hash, first.hash);
        assert_eq!(recovered[1].hash, second.hash);
        assert_eq!(
            recovered[1]
                .vtx
                .iter()
                .map(|tx| tx.ironwood_actions.len())
                .sum::<usize>(),
            20
        );
        let mut scanner_heights = Vec::new();
        cache
            .with_blocks::<_, ()>(Some(BlockHeight::from_u32(4_465_070)), Some(2), |block| {
                scanner_heights.push(block.height);
                Ok(())
            })
            .unwrap();
        assert_eq!(scanner_heights, [4_465_070, 4_465_071]);
    }

    #[test]
    fn synthetic_sapling_receipt_is_found_through_reference_cache() {
        let cache = SqliteBlockCache::open(Path::new(":memory:")).unwrap();
        let mut scenario = TestDsl::with_sapling_birthday_account(TestDbFactory::default(), cache)
            .build::<SaplingPoolTester>();
        scenario.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60_000));
        let balance = scenario
            .get_account_balance(ConfirmationsPolicy::MIN)
            .unwrap();
        assert_eq!(
            balance.sapling_balance().total(),
            Zatoshis::const_from_u64(60_000)
        );
    }

    #[test]
    fn synthetic_orchard_receipt_is_found_through_reference_cache() {
        let cache = SqliteBlockCache::open(Path::new(":memory:")).unwrap();
        let mut scenario = TestDsl::with_sapling_birthday_account(TestDbFactory::default(), cache)
            .build::<OrchardPoolTester>();
        scenario.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60_000));
        let balance = scenario
            .get_account_balance(ConfirmationsPolicy::MIN)
            .unwrap();
        assert_eq!(
            balance.orchard_balance().total(),
            Zatoshis::const_from_u64(60_000)
        );
    }

    #[test]
    fn synthetic_sapling_spend_changes_balance_after_mining() {
        let cache = SqliteBlockCache::open(Path::new(":memory:")).unwrap();
        let mut scenario = TestDsl::with_sapling_birthday_account(TestDbFactory::default(), cache)
            .build::<SaplingPoolTester>();
        let account = scenario.get_account().id();
        scenario.add_a_single_note_checking_balance(Zatoshis::const_from_u64(90_000));

        let recipient_key = SaplingPoolTester::sk(&[0xf5; 32]);
        let recipient = SaplingPoolTester::sk_default_address(&recipient_key);
        let txid = scenario.spend_to(&recipient, Zatoshis::const_from_u64(30_000));
        assert_eq!(
            scenario.get_spendable_balance(account, ConfirmationsPolicy::MIN),
            Zatoshis::ZERO
        );

        let (height, _) = scenario.generate_next_block_including(txid);
        scenario.scan_cached_blocks(height, 1);
        assert_eq!(
            scenario
                .get_account_balance(ConfirmationsPolicy::MIN)
                .unwrap()
                .sapling_balance()
                .total(),
            Zatoshis::const_from_u64(50_000)
        );
    }

    #[test]
    fn synthetic_orchard_reorg_replaces_orphaned_receipt() {
        let cache = SqliteBlockCache::open(Path::new(":memory:")).unwrap();
        let mut scenario = TestDsl::with_sapling_birthday_account(TestDbFactory::default(), cache)
            .build::<OrchardPoolTester>();
        let account = scenario.get_account().id();
        let (fork_height, _, _) =
            scenario.add_a_single_note_checking_balance(Zatoshis::const_from_u64(60_000));
        scenario.add_a_single_note_checking_balance(Zatoshis::const_from_u64(70_000));
        assert_eq!(
            scenario
                .get_account_balance(ConfirmationsPolicy::MIN)
                .unwrap()
                .orchard_balance()
                .total(),
            Zatoshis::const_from_u64(130_000)
        );

        scenario.truncate_to_height(fork_height);
        assert_eq!(
            scenario.get_spendable_balance(account, ConfirmationsPolicy::MIN),
            Zatoshis::const_from_u64(60_000)
        );
        let fvk = OrchardPoolTester::test_account_fvk(&scenario);
        let (height, _, _) = scenario.generate_next_block(
            &fvk,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(80_000),
        );
        scenario.scan_cached_blocks(height, 1);
        assert_eq!(
            scenario.get_spendable_balance(account, ConfirmationsPolicy::MIN),
            Zatoshis::const_from_u64(140_000)
        );
    }
}
