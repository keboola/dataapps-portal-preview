"""Minimal Keboola Storage API client for small control-plane tables.

Only what the access store needs, over plain httpx:

* read a whole small table synchronously (`data-preview`, capped by the API);
* upsert rows (CSV upload → incremental `import-async` into a table with a primary key);
* delete rows by primary key (`DELETE .../rows` with a where filter);
* create a bucket and an (untyped) table from a CSV header, so it works on any backend.

Every write is an asynchronous Storage job; the client waits for it so a
caller that returns afterwards is guaranteed the change is visible.

The upload flow mirrors kbagent (`keboola_agent_cli/client/storage_tables.py`),
which is verified live: `files/prepare` with `federationToken=1`, then a
direct PUT to the cloud bucket (GCS bearer token or Azure SAS), then the
import job. AWS federated uploads need SigV4 signing and are not supported;
they fail with a clear error instead of a partial write.
"""

from __future__ import annotations

import csv
import io
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import quote, urlparse

import httpx

TOKEN_HEADER = "X-StorageApi-Token"
JOB_DONE = ("success", "error")


class StorageError(RuntimeError):
    """A Storage API call or job failed. The message never contains the token."""


@dataclass(frozen=True)
class StorageSettings:
    stack_url: str
    token: str
    http_timeout_seconds: float
    job_timeout_seconds: float
    job_poll_seconds: float
    # data-preview row cap requested per read; a table at the cap is refused, not truncated.
    preview_row_limit: int


class StorageClient:
    def __init__(
        self,
        settings: StorageSettings,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        stack = settings.stack_url.rstrip("/")
        if urlparse(stack).scheme != "https":
            raise ValueError(f"Stack URL must be https:// (got {settings.stack_url})")
        self._settings = settings
        self._sleep = sleep
        self._api = httpx.Client(
            base_url=stack,
            headers={TOKEN_HEADER: settings.token},
            timeout=settings.http_timeout_seconds,
            transport=transport,
        )
        # Cloud uploads go to a different host and must not carry the Storage token.
        self._cloud = httpx.Client(timeout=settings.http_timeout_seconds, transport=transport)

    def close(self) -> None:
        self._api.close()
        self._cloud.close()

    # ---- plumbing --------------------------------------------------------

    def _call(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        try:
            response = self._api.request(method, path, **kwargs)  # type: ignore[arg-type]
        except httpx.HTTPError as exc:
            raise StorageError(f"{method} {path} failed: {type(exc).__name__}") from exc
        if response.status_code >= 400:
            raise StorageError(f"{method} {path} failed: HTTP {response.status_code} {response.text[:300]}")
        return response

    def _wait(self, job: Mapping[str, object]) -> dict[str, object]:
        deadline = time.monotonic() + self._settings.job_timeout_seconds
        current = dict(job)
        while current.get("status") not in JOB_DONE:
            if time.monotonic() > deadline:
                raise StorageError(f"Storage job {current.get('id')} did not finish in {self._settings.job_timeout_seconds}s")
            self._sleep(self._settings.job_poll_seconds)
            current = self._call("GET", f"/v2/storage/jobs/{current['id']}").json()
        if current["status"] == "error":
            error = current.get("error") or {}
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise StorageError(f"Storage job {current.get('id')} failed: {message}")
        return current

    def _upload_csv(self, name: str, content: bytes) -> int:
        info = self._call(
            "POST", "/v2/storage/files/prepare",
            data={"name": name, "sizeBytes": str(len(content)), "federationToken": "1"},
        ).json()
        if gcs := info.get("gcsUploadParams"):
            url = f"https://storage.googleapis.com/{gcs['bucket']}/{gcs['key']}"
            response = self._cloud.put(url, content=content, headers={"Authorization": f"Bearer {gcs['access_token']}"})
            ok = (200,)
        elif abs_params := info.get("absUploadParams"):
            response = self._cloud.put(_abs_url(abs_params), content=content, headers={"x-ms-blob-type": "BlockBlob"})
            ok = (200, 201)
        elif (info.get("uploadParams") or {}).get("credentials"):
            raise StorageError("AWS stacks with federated upload credentials are not supported by this client")
        elif info.get("url"):
            response = self._cloud.put(info["url"], content=content)
            ok = (200, 201)
        else:
            raise StorageError("files/prepare returned no upload target")
        if response.status_code not in ok:
            # The provider body can contain signed URLs; report the status only.
            raise StorageError(f"Cloud upload failed: HTTP {response.status_code}")
        return int(info["id"])

    # ---- tables ------------------------------------------------------------

    def read_table(self, table_id: str) -> list[dict[str, str]]:
        """All rows of a small table. Raises if the table may hold more than the preview cap."""
        limit = self._settings.preview_row_limit
        text = self._call(
            "GET", f"/v2/storage/tables/{quote(table_id, safe='')}/data-preview", params={"limit": str(limit)}
        ).text
        rows = list(csv.DictReader(io.StringIO(text)))
        if len(rows) >= limit:
            raise StorageError(
                f"Table {table_id} has {limit}+ rows; the control-plane store reads tables of fewer rows only"
            )
        return rows

    def upsert_rows(self, table_id: str, columns: list[str], rows: Iterable[Mapping[str, str]]) -> None:
        """Incremental load: rows with an existing primary key are replaced, new ones added."""
        materialized = list(rows)
        if not materialized:
            return
        file_id = self._upload_csv(f"{table_id.split('.')[-1]}.csv", _csv_bytes(columns, materialized))
        job = self._call(
            "POST", f"/v2/storage/tables/{quote(table_id, safe='')}/import-async",
            data={"dataFileId": str(file_id), "incremental": "1", "delimiter": ",", "enclosure": '"'},
        ).json()
        self._wait(job)

    def delete_rows(self, table_id: str, column: str, values: Iterable[str]) -> None:
        """Delete rows whose `column` is one of `values` (one job for all of them)."""
        materialized = sorted(set(values))
        if not materialized:
            return
        params: list[tuple[str, str]] = [("whereColumn", column), ("whereOperator", "eq")]
        params += [("whereValues[]", v) for v in materialized]
        job = self._call("DELETE", f"/v2/storage/tables/{quote(table_id, safe='')}/rows", params=params).json()
        self._wait(job)

    def table_columns(self, table_id: str) -> list[str]:
        detail = self._call("GET", f"/v2/storage/tables/{quote(table_id, safe='')}").json()
        return [str(c) for c in detail.get("columns", [])]

    def add_column(self, table_id: str, name: str) -> None:
        """Add an untyped column to an existing table; existing rows read it as empty."""
        job = self._call("POST", f"/v2/storage/tables/{quote(table_id, safe='')}/columns", data={"name": name}).json()
        if isinstance(job, dict) and "id" in job and "status" in job:
            self._wait(job)

    def list_tables(self, bucket_id: str) -> list[str]:
        tables = self._call("GET", f"/v2/storage/buckets/{quote(bucket_id, safe='')}/tables").json()
        return [str(t["name"]) for t in tables]

    def bucket_exists(self, bucket_id: str) -> bool:
        try:
            self._call("GET", f"/v2/storage/buckets/{quote(bucket_id, safe='')}")
        except StorageError as exc:
            if "HTTP 404" in str(exc):
                return False
            raise
        return True

    def create_table(self, bucket_id: str, name: str, columns: list[str], primary_key: list[str]) -> None:
        """Create an empty table from a CSV header (untyped, so it works on every backend)."""
        self.create_table_from_csv(bucket_id, name, _csv_bytes(columns, []), primary_key)

    def create_table_from_csv(self, bucket_id: str, name: str, content: bytes, primary_key: list[str]) -> None:
        """Create a table (untyped) and load it with a CSV that has a header row."""
        file_id = self._upload_csv(f"{name}.csv", content)
        job = self._call(
            "POST", f"/v2/storage/buckets/{quote(bucket_id, safe='')}/tables-async",
            data={"name": name, "dataFileId": str(file_id), "primaryKey": ",".join(primary_key)},
        ).json()
        self._wait(job)

    def replace_table_csv(self, table_id: str, content: bytes) -> None:
        """Full load: the table's rows become exactly the CSV's rows (header row required)."""
        file_id = self._upload_csv(f"{table_id.split('.')[-1]}.csv", content)
        job = self._call(
            "POST", f"/v2/storage/tables/{quote(table_id, safe='')}/import-async",
            data={"dataFileId": str(file_id), "incremental": "0", "delimiter": ",", "enclosure": '"'},
        ).json()
        self._wait(job)


def _csv_bytes(columns: list[str], rows: list[Mapping[str, str]]) -> bytes:
    out = io.StringIO()
    # extrasaction="raise": a key outside `columns` is a bug in the caller, not data to drop.
    writer = csv.DictWriter(out, fieldnames=columns, extrasaction="raise", restval="", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(dict(row))
    return out.getvalue().encode("utf-8")


def _abs_url(params: Mapping[str, object]) -> str:
    """Blob URL from the SAS connection string Keboola returns for Azure stacks."""
    # "BlobEndpoint=https://...;SharedAccessSignature=sv=...": split on the first "=" only.
    parts = dict(p.split("=", 1) for p in str(params["absCredentials"]["SASConnectionString"]).split(";") if "=" in p)  # type: ignore[index]
    endpoint = parts["BlobEndpoint"].rstrip("/")
    return f"{endpoint}/{params['container']}/{params['blobName']}?{parts['SharedAccessSignature']}"
