"""Load Storage tables into the dashboards' DuckDB through Direct Storage Access.

The Keboola "DuckDB-cached RO" pattern for read-only dashboards: pull each
table once through the Query Service into a local DuckDB file, serve every
dashboard query (via the data guard) from that file, and refresh it in the
background every `refresh_seconds`.

Direct Storage Access must be enabled in the app's config: `runtime.workspace.enabled`
set to true and the tables listed under `storage.output.tables` with
`unload_strategy: "direct-grant"`. The runtime then injects the
environment this module reads — KBC_TOKEN (the platform's token, NOT the
suite's own ACCESS_STORAGE_TOKEN), BRANCH_ID, QUERY_SERVICE_URL and the
workspace (KBC_WORKSPACE_MANIFEST_PATH, falling back to WORKSPACE_ID). A missing
variable fails the start with a message that names the setting to enable.

Query Service returns every cell as a string, so rows go through a CSV and
DuckDB's type detection — the same path input_tables uses — to get dates,
numbers and booleans back. The file is written under a temporary name and
renamed, so a query never sees a half-built warehouse.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
import tempfile
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from kbc_access.input_tables import build as build_from_csv

TABLE_ID = re.compile(r"^(in|out)\.c-[A-Za-z0-9_-]+\.[A-Za-z0-9_]+$")
REQUIRED_ENV = ("KBC_TOKEN", "BRANCH_ID", "QUERY_SERVICE_URL")
logger = logging.getLogger(__name__)


class StorageAccessError(RuntimeError):
    pass


@dataclass(frozen=True)
class Workspace:
    query_service_url: str
    token: str
    branch_id: str
    workspace_id: str


def workspace_from_env(env: Mapping[str, str]) -> Workspace:
    """The workspace the runtime provisioned for this app start."""
    missing = [name for name in REQUIRED_ENV if not env.get(name)]
    workspace_id = ""
    manifest = env.get("KBC_WORKSPACE_MANIFEST_PATH")
    if manifest and Path(manifest).is_file():
        workspace_id = str(json.loads(Path(manifest).read_text(encoding="utf-8")).get("workspaceId") or "")
    workspace_id = workspace_id or env.get("WORKSPACE_ID", "")
    if not workspace_id:
        missing.append("KBC_WORKSPACE_MANIFEST_PATH / WORKSPACE_ID")
    if missing:
        raise StorageAccessError(
            f"Direct Storage Access is not available ({', '.join(missing)} missing). In the app's config, set "
            "runtime.workspace.enabled to true and list the tables under storage.output.tables with unload_strategy 'direct-grant'."
        )
    if not env["BRANCH_ID"].isdigit():
        raise StorageAccessError(f"BRANCH_ID must be numeric for the Query Service (got {env['BRANCH_ID']!r})")
    return Workspace(env["QUERY_SERVICE_URL"].rstrip("/"), env["KBC_TOKEN"], env["BRANCH_ID"], workspace_id)


def select_sql(table_id: str) -> str:
    """`in.c-bucket.table` → `SELECT * FROM "in.c-bucket"."table"` (validated, so quoting is safe)."""
    if not TABLE_ID.fullmatch(table_id):
        raise StorageAccessError(f"Invalid table id '{table_id}'")
    bucket, table = table_id.rsplit(".", 1)
    return f'SELECT * FROM "{bucket}"."{table}"'


QueryFn = Callable[[Workspace, str], tuple[list[str], list[list[object]]]]


def query_service(workspace: Workspace, sql: str) -> tuple[list[str], list[list[object]]]:
    """Run one SELECT through the official Query Service SDK (it handles submit, poll and paging)."""
    from keboola_query_service import Client

    client = Client(base_url=workspace.query_service_url, token=workspace.token)
    result = client.execute_query(branch_id=workspace.branch_id, workspace_id=workspace.workspace_id, statements=[sql])[0]
    return [c.name for c in result.columns], result.data


def sync(workspace: Workspace, table_ids: list[str], out: Path, query: QueryFn = query_service) -> dict[str, int]:
    """Pull every table and rebuild `out`. The DuckDB table name is the Storage table name."""
    names = [t.rsplit(".", 1)[1] for t in table_ids]
    if len(set(names)) != len(names):
        raise StorageAccessError("Two tables with the same name cannot share one warehouse")
    with tempfile.TemporaryDirectory(prefix="kbc-access-sync-") as tmp:
        folder = Path(tmp)
        for table_id, name in zip(table_ids, names, strict=True):
            columns, rows = query(workspace, select_sql(table_id))
            with (folder / f"{name}.csv").open("w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(columns)
                writer.writerows(["" if v is None else v for v in row] for row in rows)
        return build_from_csv(folder, out, names)


class WarehouseRefresher:
    """Keeps the DuckDB file fresh: a first sync on start, then one every `interval_seconds`."""

    def __init__(self, table_ids: list[str], out: Path, interval_seconds: float, *,
                 env: Mapping[str, str] | None = None, query: QueryFn = query_service) -> None:
        self._tables = list(table_ids)
        self._out = out
        self._interval = interval_seconds
        self._env = env if env is not None else os.environ
        self._query = query
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def refresh_now(self) -> dict[str, int]:
        return sync(workspace_from_env(self._env), self._tables, self._out, self._query)

    def start(self) -> dict[str, int]:
        """Sync synchronously (the app must not serve an empty warehouse), then refresh in the background."""
        counts = self.refresh_now()
        self._thread = threading.Thread(target=self._loop, name="warehouse-refresh", daemon=True)
        self._thread.start()
        return counts

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                counts = self.refresh_now()
                logger.info("warehouse refreshed: %s", counts)
            except Exception:  # keep serving the last good file; the next tick retries
                logger.exception("warehouse refresh failed; keeping the previous data")
