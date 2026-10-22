import asyncio
import datetime
import unittest.mock

import pytest
import sqlalchemy.dialects.postgresql
import sqlalchemy.exc
import sqlalchemy.sql.dml

import deliverydb.cache as cache_sync
import deliverydb.cache_async as cache_async
import deliverydb.model as dm


def _make_cache_entry(
    id: str = 'abc123',
    value: bytes = b'data',
    delete_after: datetime.datetime | None = None,
) -> dm.DBCache:
    now = datetime.datetime.now(datetime.timezone.utc)
    return dm.DBCache(
        id=id,
        descriptor={'type': 'test'},
        delete_after=delete_after,
        keep_until=now + datetime.timedelta(seconds=60),
        costs=10,
        size=len(value),
        value=value,
    )


# ---------------------------------------------------------------------------
# deliverydb.cache (sync)
# ---------------------------------------------------------------------------


class TestSyncAddOrUpdateCacheEntry:
    def test_issues_upsert_and_returns_true(self):
        session = unittest.mock.MagicMock()
        entry = _make_cache_entry()

        result = cache_sync.add_or_update_cache_entry(
            db_session=session,
            cache_entry=entry,
        )

        assert result is True
        session.execute.assert_called_once()
        session.commit.assert_called_once()
        session.rollback.assert_not_called()

        stmt = session.execute.call_args[0][0]
        assert isinstance(stmt, sqlalchemy.dialects.postgresql.Insert)

    def test_returns_false_and_rolls_back_on_exception(self):
        session = unittest.mock.MagicMock()
        session.execute.side_effect = Exception('db error')

        result = cache_sync.add_or_update_cache_entry(
            db_session=session,
            cache_entry=_make_cache_entry(),
        )

        assert result is False
        session.rollback.assert_called_once()
        session.commit.assert_not_called()

    def test_no_integrity_error_raised_to_caller(self):
        session = unittest.mock.MagicMock()
        session.execute.side_effect = sqlalchemy.exc.IntegrityError(
            statement=None,
            params=None,
            orig=Exception('dup key'),
        )

        result = cache_sync.add_or_update_cache_entry(
            db_session=session,
            cache_entry=_make_cache_entry(),
        )

        assert result is False
        session.rollback.assert_called_once()

    def test_insert_includes_revision_and_read_count_defaults(self):
        session = unittest.mock.MagicMock()
        cache_sync.add_or_update_cache_entry(
            db_session=session,
            cache_entry=_make_cache_entry(),
        )
        stmt = session.execute.call_args[0][0]
        compiled = stmt.compile(dialect=sqlalchemy.dialects.postgresql.dialect())
        assert 'revision' in compiled.params, 'revision missing from INSERT — will be NULL'
        assert compiled.params['revision'] == 0
        assert 'read_count' in compiled.params, 'read_count missing from INSERT — will be NULL'
        assert compiled.params['read_count'] == 0


class TestSyncFindCachedValue:
    def test_returns_none_when_entry_missing(self):
        session = unittest.mock.MagicMock()
        session.get.return_value = None

        assert cache_sync.find_cached_value(db_session=session, id='missing') is None

    def test_returns_none_when_stale(self):
        session = unittest.mock.MagicMock()
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        entry = _make_cache_entry(delete_after=past)
        session.get.return_value = entry

        assert cache_sync.find_cached_value(db_session=session, id=entry.id) is None

    def test_returns_value_and_updates_read_stats(self):
        session = unittest.mock.MagicMock()
        entry = _make_cache_entry(value=b'hello')
        entry.read_count = 3
        session.get.return_value = entry

        result = cache_sync.find_cached_value(db_session=session, id=entry.id)

        assert result == b'hello'
        assert entry.read_count == 4
        session.commit.assert_called_once()

    def test_rolls_back_on_commit_error(self):
        session = unittest.mock.MagicMock()
        session.commit.side_effect = Exception('commit failed')
        entry = _make_cache_entry(value=b'hello')
        entry.read_count = 0
        session.get.return_value = entry

        result = cache_sync.find_cached_value(db_session=session, id=entry.id)

        assert result == b'hello'
        session.rollback.assert_called_once()


# ---------------------------------------------------------------------------
# deliverydb.cache_async — add_or_update_cache_entry
# ---------------------------------------------------------------------------


class TestAsyncAddOrUpdateCacheEntry:
    @pytest.mark.asyncio
    async def test_issues_upsert_and_returns_true(self):
        session = unittest.mock.AsyncMock()
        entry = _make_cache_entry()

        result = await cache_async.add_or_update_cache_entry(
            db_session=session,
            cache_entry=entry,
        )

        assert result is True
        session.execute.assert_called_once()
        session.commit.assert_called_once()
        session.rollback.assert_not_called()

        stmt = session.execute.call_args[0][0]
        assert isinstance(stmt, sqlalchemy.dialects.postgresql.Insert)

    @pytest.mark.asyncio
    async def test_returns_false_and_rolls_back_on_exception(self):
        session = unittest.mock.AsyncMock()
        session.execute.side_effect = Exception('db error')

        result = await cache_async.add_or_update_cache_entry(
            db_session=session,
            cache_entry=_make_cache_entry(),
        )

        assert result is False
        session.rollback.assert_called_once()
        session.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_integrity_error_raised_to_caller(self):
        session = unittest.mock.AsyncMock()
        session.execute.side_effect = sqlalchemy.exc.IntegrityError(
            statement=None,
            params=None,
            orig=Exception('dup key'),
        )

        result = await cache_async.add_or_update_cache_entry(
            db_session=session,
            cache_entry=_make_cache_entry(),
        )

        assert result is False
        session.rollback.assert_called_once()

    @pytest.mark.asyncio
    async def test_insert_includes_revision_and_read_count_defaults(self):
        session = unittest.mock.AsyncMock()
        await cache_async.add_or_update_cache_entry(
            db_session=session,
            cache_entry=_make_cache_entry(),
        )
        stmt = session.execute.call_args[0][0]
        compiled = stmt.compile(dialect=sqlalchemy.dialects.postgresql.dialect())
        assert 'revision' in compiled.params, 'revision missing from INSERT — will be NULL'
        assert compiled.params['revision'] == 0
        assert 'read_count' in compiled.params, 'read_count missing from INSERT — will be NULL'
        assert compiled.params['read_count'] == 0


# ---------------------------------------------------------------------------
# deliverydb.cache_async — find_cached_value (fire-and-forget read stats)
# ---------------------------------------------------------------------------


class TestAsyncFindCachedValue:
    @pytest.mark.asyncio
    async def test_returns_none_when_entry_missing(self):
        session = unittest.mock.AsyncMock()
        session.get.return_value = None

        assert await cache_async.find_cached_value(db_session=session, id='missing') is None

    @pytest.mark.asyncio
    async def test_returns_none_when_stale(self):
        session = unittest.mock.AsyncMock()
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        entry = _make_cache_entry(id='stale', delete_after=past)
        session.get.return_value = entry

        assert await cache_async.find_cached_value(db_session=session, id='stale') is None

    @pytest.mark.asyncio
    async def test_returns_value_without_blocking_on_read_stat_write(self):
        session = unittest.mock.AsyncMock()
        entry = _make_cache_entry(id='hit1', value=b'payload')
        session.get.return_value = entry

        with unittest.mock.patch('asyncio.create_task') as mock_create_task:
            result = await cache_async.find_cached_value(
                db_session=session,
                id='hit1',
                db_url='postgresql://test/db',
            )

        assert result == b'payload'
        session.commit.assert_not_called()
        mock_create_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_task_spawned_without_db_url(self):
        session = unittest.mock.AsyncMock()
        session.get.return_value = _make_cache_entry(id='hit2', value=b'x')

        with unittest.mock.patch('asyncio.create_task') as mock_create_task:
            result = await cache_async.find_cached_value(db_session=session, id='hit2')

        assert result == b'x'
        mock_create_task.assert_not_called()


# ---------------------------------------------------------------------------
# deliverydb.cache_async — _update_read_stats (unit)
# ---------------------------------------------------------------------------


class TestUpdateReadStats:
    @pytest.mark.asyncio
    async def test_issues_server_side_increment_update(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        mock_session = unittest.mock.AsyncMock()

        with unittest.mock.patch(
            'deliverydb.sqlalchemy_session_async',
            return_value=mock_session,
        ):
            await cache_async._update_read_stats(
                db_url='postgresql://test/db',
                id='abc123',
                now=now,
            )

        mock_session.execute.assert_called_once()
        stmt = mock_session.execute.call_args[0][0]
        assert isinstance(stmt, sqlalchemy.sql.dml.Update)
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()
        mock_session.rollback.assert_not_called()

    @pytest.mark.asyncio
    async def test_rolls_back_and_closes_on_execute_error(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        mock_session = unittest.mock.AsyncMock()
        mock_session.execute.side_effect = Exception('write failed')

        with unittest.mock.patch(
            'deliverydb.sqlalchemy_session_async',
            return_value=mock_session,
        ):
            await cache_async._update_read_stats(
                db_url='postgresql://test/db',
                id='abc123',
                now=now,
            )

        mock_session.rollback.assert_called_once()
        mock_session.commit.assert_not_called()
        mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_uses_server_side_increment_not_read_modify_write(self):
        """read_count must be incremented server-side (read_count + 1) to avoid contention."""
        now = datetime.datetime.now(datetime.timezone.utc)
        mock_session = unittest.mock.AsyncMock()

        with unittest.mock.patch(
            'deliverydb.sqlalchemy_session_async',
            return_value=mock_session,
        ):
            await cache_async._update_read_stats(
                db_url='postgresql://test/db',
                id='abc123',
                now=now,
            )

        stmt = mock_session.execute.call_args[0][0]
        compiled = stmt.compile(dialect=sqlalchemy.dialects.postgresql.dialect())
        sql_str = str(compiled)
        # Must use server-side expression, not a literal integer
        assert (
            'read_count + :read_count_1' in sql_str
            or 'read_count +:' in sql_str
            or ('read_count' in sql_str and '+' in sql_str)
        ), f'expected server-side increment in SQL, got: {sql_str}'


# ---------------------------------------------------------------------------
# End-to-end: find_cached_value → asyncio.create_task → _update_read_stats
# ---------------------------------------------------------------------------


class TestReadStatEndToEnd:
    @pytest.mark.asyncio
    async def test_cache_hit_spawns_task_that_writes_update(self):
        read_session = unittest.mock.AsyncMock()
        read_session.get.return_value = _make_cache_entry(id='key1', value=b'v1')

        stat_session = unittest.mock.AsyncMock()

        with unittest.mock.patch(
            'deliverydb.sqlalchemy_session_async',
            return_value=stat_session,
        ):
            result = await cache_async.find_cached_value(
                db_session=read_session,
                id='key1',
                db_url='postgresql://test/db',
            )
            assert result == b'v1'
            # drain the spawned task
            await asyncio.gather(*asyncio.all_tasks() - {asyncio.current_task()})

        stat_session.execute.assert_called_once()
        stmt = stat_session.execute.call_args[0][0]
        assert isinstance(stmt, sqlalchemy.sql.dml.Update)
        stat_session.commit.assert_called_once()
        stat_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_hit_via_dbcached_function_writes_read_stat(self):
        """@dbcached_function cache hit must fire a background UPDATE for read stats."""
        db_session = unittest.mock.AsyncMock()
        stored_value = None

        async def fake_add_or_update(db_session, cache_entry):  # noqa: ARG001
            nonlocal stored_value
            stored_value = cache_entry.value
            return True

        db_session.get.side_effect = lambda _m, _id: (
            _make_cache_entry(id=_id, value=stored_value) if stored_value else None
        )

        stat_session = unittest.mock.AsyncMock()

        @cache_async.dbcached_function()
        async def expensive(x: int, db_session=None, db_url=None) -> int:
            return x * 2

        with (
            unittest.mock.patch(
                'deliverydb.cache_async.add_or_update_cache_entry',
                side_effect=fake_add_or_update,
            ),
            unittest.mock.patch(
                'deliverydb.sqlalchemy_session_async',
                return_value=stat_session,
            ),
        ):
            result1 = await expensive(x=5, db_session=db_session)
            assert result1 == 10
            assert stored_value is not None

            result2 = await expensive(x=5, db_session=db_session, db_url='postgresql://test/db')
            assert result2 == 10

            await asyncio.gather(*asyncio.all_tasks() - {asyncio.current_task()})

        stat_session.execute.assert_called_once()
        stat_session.commit.assert_called_once()
        stat_session.close.assert_called_once()
