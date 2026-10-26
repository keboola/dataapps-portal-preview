"""Access store backed by Keboola Storage tables — for apps deployed in Keboola.

The control-plane tables live in one bucket of one project. Instead of
re-implementing every rule of the SQLite store, each operation:

1. pulls every table into a throw-away SQLite `AccessStore` (they are
   small by design: `read_table` refuses a table at the preview cap);
2. runs the very same method on it — the same validation, the same cascades;
3. pushes only what changed: upserts via an incremental load, removals via a
   delete-by-key job.

So the local and the deployed store cannot drift apart in behaviour.

Storage tables need a single-column primary key for delete-by-key, so the
tables with a composite key carry an extra `row_key` column
(`app_id|subject_type|subject_id`, `email|key`, `local_group_id|email`). It is derived, never edited.
`row_access_rules` and `column_masks` have single keys (`rule_id`, `mask_id`) and need no row_key.

Reads may be served from the last mirror for `read_cache_seconds` (one admin
page calls several list methods; without the cache each would cost one
Storage call per table). Every write pulls fresh state first and refreshes the cache
with the result, so a write never builds on a stale read.

Concurrency: operations in one process are serialised. Two admin app
instances writing the *same row* at the same moment resolve last-writer-wins
per row; different rows never overwrite each other because only changed rows
are sent.
"""

from __future__ import annotations

import tempfile
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from typing import TypeVar

from kbc_access.config import ProviderSettings
from kbc_access.keboola_storage import StorageClient
from kbc_access.store import (
    TABLE_COLUMNS,
    TABLE_KEYS,
    AccessStore,
    AclSnapshot,
    App,
    ColumnMask,
    ColumnMaskInput,
    DatasetSecurity,
    RowAccessRule,
    RowAccessRuleInput,
    Grant,
    Group,
    LocalGroup,
    User,
)

ROW_KEY = "row_key"
ROW_KEY_SEPARATOR = "|"
T = TypeVar("T")


def storage_columns(table: str) -> list[str]:
    """Columns of the Storage table: the store's columns, plus row_key for composite keys."""
    columns = TABLE_COLUMNS[table]
    return [ROW_KEY, *columns] if len(TABLE_KEYS[table]) > 1 else list(columns)


def storage_primary_key(table: str) -> str:
    keys = TABLE_KEYS[table]
    return ROW_KEY if len(keys) > 1 else keys[0]


def _row_key(table: str, row: Mapping[str, str]) -> str:
    return ROW_KEY_SEPARATOR.join(row[k] for k in TABLE_KEYS[table])


def _with_row_key(table: str, row: dict[str, str]) -> dict[str, str]:
    return {ROW_KEY: _row_key(table, row), **row} if len(TABLE_KEYS[table]) > 1 else row


class KeboolaAccessStore:
    """Same public methods as `AccessStore`; state lives in Storage tables."""

    def __init__(
        self,
        client: StorageClient,
        bucket_id: str,
        providers: Mapping[str, ProviderSettings],
        *,
        read_cache_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._bucket = bucket_id
        self._providers = dict(providers)
        self._lock = Lock()
        self._scratch = tempfile.TemporaryDirectory(prefix="kbc-access-mirror-")
        self._cache_seconds = read_cache_seconds
        self._clock = clock
        self._mirror: AccessStore | None = None
        self._mirror_at = 0.0
        # row_keys of grants whose app is gone; removed from Storage on the next write.
        self._orphan_grants: set[str] = set()
        # Control-plane tables the last pull did not find in the bucket.
        self._absent_tables: list[str] = []
        # Set once every existing table is known to have every column this release writes.
        self._columns_checked = False

    def table_id(self, table: str) -> str:
        return f"{self._bucket}.{table}"

    # ---- schema --------------------------------------------------------------

    def missing_tables(self) -> list[str]:
        existing = set(self._client.list_tables(self._bucket))
        return [t for t in TABLE_COLUMNS if t not in existing]

    def ensure_schema(self) -> list[str]:
        """Create any missing control-plane table and add missing columns to the existing ones.

        Returns the names of the tables it created.
        """
        missing = self.missing_tables()
        created = []
        for table in missing:
            self._client.create_table(self._bucket, table, storage_columns(table), [storage_primary_key(table)])
            created.append(table)
        self.ensure_columns(skip=missing)
        return created

    def ensure_columns(self, *, skip: list[str] | None = None) -> list[str]:
        """Add the columns a newer release introduced (apps.access) to tables created before it.

        An incremental load whose header has a column the table lacks fails, so this runs
        before the first write. Returns "table.column" for every column it added.
        """
        added = []
        existing = set(self._client.list_tables(self._bucket)) - set(skip or [])
        for table in (t for t in TABLE_COLUMNS if t in existing):
            have = set(self._client.table_columns(self.table_id(table)))
            for column in storage_columns(table):
                if column not in have:
                    self._client.add_column(self.table_id(table), column)
                    added.append(f"{table}.{column}")
        self._columns_checked = True
        return added

    # ---- mirror ----------------------------------------------------------------

    def _pull(self) -> AccessStore:
        """Fresh mirror of every control-plane table. Callers hold the lock."""
        path = Path(self._scratch.name) / "mirror.sqlite"
        for suffix in ("", "-wal", "-shm"):
            Path(f"{path}{suffix}").unlink(missing_ok=True)
        mirror = AccessStore(path, self._providers)
        # A table added by a newer release (local groups) does not exist in an older
        # bucket yet: it reads as empty here and is created by the next write.
        existing = set(self._client.list_tables(self._bucket))
        self._absent_tables = [t for t in TABLE_COLUMNS if t not in existing]
        present = [t for t in TABLE_COLUMNS if t in existing]
        with ThreadPoolExecutor(max_workers=len(TABLE_COLUMNS)) as pool:
            fetched = dict(zip(present, pool.map(lambda t: self._client.read_table(self.table_id(t)), present), strict=True))
        fetched.update({t: [] for t in self._absent_tables})
        app_ids = {r.get("app_id", "") for r in fetched["apps"]}
        # A grant whose app row is gone (an interrupted delete) is not loaded, and is
        # queued for deletion so a later app with the same id cannot inherit it.
        orphans = [r for r in fetched["app_grants"] if r.get("app_id") not in app_ids]
        self._orphan_grants = {_row_key("app_grants", {c: r.get(c, "") for c in TABLE_COLUMNS["app_grants"]}) for r in orphans}
        fetched["app_grants"] = [r for r in fetched["app_grants"] if r.get("app_id") in app_ids]
        for table, rows in fetched.items():
            mirror.load_rows(table, [{c: r.get(c, "") for c in TABLE_COLUMNS[table]} for r in rows])
        self._mirror, self._mirror_at = mirror, self._clock()
        return mirror

    def _read(self, fn: Callable[[AccessStore], T]) -> T:
        with self._lock:
            fresh = self._mirror is not None and self._clock() - self._mirror_at < self._cache_seconds
            return fn(self._mirror if fresh and self._mirror is not None else self._pull())

    def _write(self, fn: Callable[[AccessStore], T]) -> T:
        with self._lock:
            mirror = self._pull()
            before = {t: {_row_key(t, r): r for r in mirror.dump_rows(t)} for t in TABLE_COLUMNS}
            result = fn(mirror)
            after = {t: {_row_key(t, r): r for r in mirror.dump_rows(t)} for t in TABLE_COLUMNS}
            # Upserts first (parents first), deletes last (dependents first): an interrupted
            # write leaves extra rows, never missing ones. A missing row can fail open —
            # e.g. a renamed, deactivated user whose old row is gone before the new one
            # exists would be let in again through a group grant.
            order = list(TABLE_COLUMNS)
            self._mirror = None  # whatever happens next, do not serve the pre-write state
            if self._absent_tables:
                self.ensure_schema()
            elif not self._columns_checked:
                self.ensure_columns()
            for table in order:
                changed = [
                    _with_row_key(table, row) for key, row in after[table].items() if before[table].get(key) != row
                ]
                self._client.upsert_rows(self.table_id(table), storage_columns(table), changed)
            for table in reversed(order):
                removed = [key for key in before[table] if key not in after[table]]
                if table == "app_grants":
                    removed += sorted(self._orphan_grants)
                self._client.delete_rows(self.table_id(table), storage_primary_key(table), removed)
            self._orphan_grants = set()
            self._mirror, self._mirror_at = mirror, self._clock()
            return result

    # ---- AccessStore interface ------------------------------------------------

    @property
    def providers(self) -> dict[str, ProviderSettings]:
        return dict(self._providers)

    def validate_group_id(self, provider: str, external_id: str) -> None:
        self._read(lambda s: s.validate_group_id(provider, external_id))

    def snapshot(self) -> AclSnapshot:
        return self._read(lambda s: s.snapshot())

    def list_apps(self) -> list[App]:
        return self._read(lambda s: s.list_apps())

    def list_users(self) -> list[User]:
        return self._read(lambda s: s.list_users())

    def list_groups(self) -> list[Group]:
        return self._read(lambda s: s.list_groups())

    def list_grants(self) -> list[Grant]:
        return self._read(lambda s: s.list_grants())

    def list_attributes(self) -> list[tuple[str, str, str]]:
        return self._read(lambda s: s.list_attributes())

    def attributes_for(self, email: str) -> dict[str, str]:
        return self._read(lambda s: s.attributes_for(email))

    def list_local_groups(self) -> list[LocalGroup]:
        return self._read(lambda s: s.list_local_groups())

    def list_local_group_members(self) -> dict[str, list[str]]:
        return self._read(lambda s: s.list_local_group_members())

    def local_groups_of(self, email: str) -> list[LocalGroup]:
        return self._read(lambda s: s.local_groups_of(email))

    def list_row_access_rules(self, dataset: str | None = None) -> list[RowAccessRule]:
        return self._read(lambda s: s.list_row_access_rules(dataset))

    def list_column_masks(self, dataset: str | None = None) -> list[ColumnMask]:
        return self._read(lambda s: s.list_column_masks(dataset))

    def dataset_security(self, dataset: str) -> DatasetSecurity:
        return self._read(lambda s: s.dataset_security(dataset))

    def upsert_app(self, app: App) -> None:
        self._write(lambda s: s.upsert_app(app))

    def delete_app(self, app_id: str) -> None:
        # SQLite cascades grants through the foreign key; the diff pushes those deletions too.
        self._write(lambda s: s.delete_app(app_id))

    def upsert_user(self, email: str, display_name: str, active: bool) -> None:
        self._write(lambda s: s.upsert_user(email, display_name, active))

    def update_user(self, email: str, *, new_email: str, display_name: str, active: bool) -> str:
        return self._write(lambda s: s.update_user(email, new_email=new_email, display_name=display_name, active=active))

    def delete_user(self, email: str) -> None:
        self._write(lambda s: s.delete_user(email))

    def create_group(self, provider: str, external_id: str, name: str) -> Group:
        return self._write(lambda s: s.create_group(provider, external_id, name))

    def update_group(self, group_id: str, *, provider: str, external_id: str, name: str) -> Group:
        return self._write(lambda s: s.update_group(group_id, provider=provider, external_id=external_id, name=name))

    def delete_group(self, group_id: str) -> None:
        self._write(lambda s: s.delete_group(group_id))

    def create_local_group(self, local_group_id: str, name: str, description: str = "") -> LocalGroup:
        return self._write(lambda s: s.create_local_group(local_group_id, name, description))

    def update_local_group(self, local_group_id: str, *, name: str, description: str = "") -> LocalGroup:
        return self._write(lambda s: s.update_local_group(local_group_id, name=name, description=description))

    def delete_local_group(self, local_group_id: str) -> None:
        self._write(lambda s: s.delete_local_group(local_group_id))

    def add_local_group_member(self, local_group_id: str, email: str) -> None:
        self._write(lambda s: s.add_local_group_member(local_group_id, email))

    def remove_local_group_member(self, local_group_id: str, email: str) -> None:
        self._write(lambda s: s.remove_local_group_member(local_group_id, email))

    def grant(self, app_id: str, subject_type: str, subject_id: str, granted_by: str) -> None:
        self._write(lambda s: s.grant(app_id, subject_type, subject_id, granted_by))

    def revoke(self, app_id: str, subject_type: str, subject_id: str) -> None:
        self._write(lambda s: s.revoke(app_id, subject_type, subject_id))

    def set_app_grants(self, subject_type: str, subject_id: str, app_ids: set[str], granted_by: str) -> tuple[set[str], set[str]]:
        return self._write(lambda s: s.set_app_grants(subject_type, subject_id, app_ids, granted_by))

    def set_dataset_security(
        self, dataset: str, rows: list[RowAccessRuleInput], masks: list[ColumnMaskInput]
    ) -> DatasetSecurity:
        return self._write(lambda s: s.set_dataset_security(dataset, rows, masks))

    def set_attribute(self, email: str, key: str, value: str) -> None:
        self._write(lambda s: s.set_attribute(email, key, value))

    def delete_attribute(self, email: str, key: str) -> None:
        self._write(lambda s: s.delete_attribute(email, key))
