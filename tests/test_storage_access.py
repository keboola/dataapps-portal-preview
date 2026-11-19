"""Direct Storage Access: pulling Storage tables into the dashboards' DuckDB."""

from __future__ import annotations

import json
import time

import duckdb
import pytest

from kbc_access.demo_seed import DEMO_TABLES, build_warehouse
from kbc_access.storage_access import (
    StorageAccessError,
    WarehouseRefresher,
    Workspace,
    select_sql,
    sync,
    workspace_from_env,
)

BUCKET = "in.c-apps-control-plane-demo"
ENV = {"KBC_TOKEN": "platform-token", "BRANCH_ID": "1234", "QUERY_SERVICE_URL": "https://query.example.keboola.com/",
       "WORKSPACE_ID": "999"}


@pytest.fixture
def source(settings, tmp_path):
    """A fake Query Service answering from a real demo warehouse, with strings like the real one."""
    path = tmp_path / "source.duckdb"
    build_warehouse(settings, path)
    calls: list[str] = []

    def query(workspace: Workspace, sql: str):
        calls.append(sql)
        table = sql.rsplit(".", 1)[1].strip('"')
        with duckdb.connect(str(path), read_only=True) as con:
            cur = con.execute(f"SELECT * FROM {table}")
            cols = [d[0] for d in cur.description]
            rows = [[None if v is None else str(v).lower() if isinstance(v, bool) else str(v) for v in r] for r in cur.fetchall()]
        return cols, rows

    query.calls = calls  # type: ignore[attr-defined]
    return query


def test_workspace_from_env_prefers_the_manifest(tmp_path):
    manifest = tmp_path / "ws.json"
    manifest.write_text(json.dumps({"workspaceId": "777"}))
    ws = workspace_from_env({**ENV, "KBC_WORKSPACE_MANIFEST_PATH": str(manifest)})
    assert ws.workspace_id == "777" and ws.query_service_url == "https://query.example.keboola.com"
    assert workspace_from_env(ENV).workspace_id == "999"


def test_missing_storage_access_env_names_the_setting():
    with pytest.raises(StorageAccessError, match="Storage Access") as info:
        workspace_from_env({"KBC_TOKEN": "t", "BRANCH_ID": "1"})
    assert "QUERY_SERVICE_URL" in str(info.value) and "WORKSPACE_ID" in str(info.value)
    assert "runtime.workspace.enabled" in str(info.value)


def test_branch_id_must_be_numeric():
    with pytest.raises(StorageAccessError, match="numeric"):
        workspace_from_env({**ENV, "BRANCH_ID": "default"})


def test_select_sql_quotes_and_validates():
    assert select_sql(f"{BUCKET}.drug_sales") == f'SELECT * FROM "{BUCKET}"."drug_sales"'
    for bad in ('in.c-x.t"; drop', "drug_sales", 'in.c-x."t"'):
        with pytest.raises(StorageAccessError):
            select_sql(bad)


def test_sync_rebuilds_typed_tables(source, tmp_path, settings):
    out = tmp_path / "wh.duckdb"
    counts = sync(workspace_from_env(ENV), [f"{BUCKET}.{t}" for t in DEMO_TABLES], out, source)
    assert counts["drug_sales"] == settings.seed.drug_sales_rows
    with duckdb.connect(str(out), read_only=True) as con:
        types = dict(con.execute("select column_name, data_type from information_schema.columns where table_name='drug_sales'").fetchall())
    assert types["sale_date"] == "DATE" and types["is_test"] == "BOOLEAN" and types["revenue"] == "DOUBLE"


def test_sync_refuses_two_tables_with_one_name(source, tmp_path):
    with pytest.raises(StorageAccessError, match="same name"):
        sync(workspace_from_env(ENV), [f"{BUCKET}.stores", "in.c-other.stores"], tmp_path / "wh.duckdb", source)


def test_refresher_syncs_on_start_and_keeps_old_data_on_failure(source, tmp_path):
    out = tmp_path / "wh.duckdb"
    refresher = WarehouseRefresher([f"{BUCKET}.companies"], out, 0.05, env=ENV, query=source)
    assert refresher.start() == {"companies": 3}
    before = len(source.calls)
    time.sleep(0.2)
    assert len(source.calls) > before  # background refresh ran
    refresher._query = lambda *a: (_ for _ in ()).throw(RuntimeError("query service down"))  # noqa: SLF001
    time.sleep(0.15)
    refresher.stop()
    with duckdb.connect(str(out), read_only=True) as con:
        assert con.execute("select count(*) from companies").fetchone()[0] == 3


def test_refresher_start_fails_without_storage_access(tmp_path):
    with pytest.raises(StorageAccessError):
        WarehouseRefresher([f"{BUCKET}.companies"], tmp_path / "wh.duckdb", 60, env={}).start()
