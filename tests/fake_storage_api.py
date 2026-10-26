"""In-memory fake of the Keboola Storage API endpoints `StorageClient` uses.

Served through `httpx.MockTransport`, so the real client code (URL building,
headers, CSV encoding, job polling) runs unchanged against it. Test double
only: the library never imports this module.

Behaviour follows the documented API:

* every request to the stack must carry `X-StorageApi-Token` (401 otherwise);
* tables have a primary key; `data-preview` returns CSV (header + rows) and
  honours `limit` (default 100, documented maximum 1000);
* `files/prepare` returns `id` plus the upload target for the configured cloud
  (GCP `gcsUploadParams`, Azure `absUploadParams`, AWS `uploadParams` with
  federated credentials);
* the GCS PUT must carry the file's bearer token and must NOT carry the
  Storage token; the Azure PUT must carry the SAS query and `x-ms-blob-type`;
* async endpoints (`import-async`, `DELETE .../rows`, `tables-async`) answer
  with a job `{id, status: "waiting"}`; `GET /v2/storage/jobs/{id}` reports
  "processing" once, then applies the change and reports "success" (or
  "error"), so the client's polling loop is always exercised;
* `import-async` with incremental=1 upserts by primary key;
* `DELETE /tables/{id}/rows` deletes rows matching whereColumn/whereValues[]
  (no filter at all truncates the table, like the real endpoint);
* `tables-async` creates a table from a header-only CSV with `primaryKey`.

Failure injection: `fail_http(...)`, `fail_job(...)`, `cloud_put_status`,
`jobs_never_finish`.
"""

from __future__ import annotations

import csv
import io
import itertools
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from threading import RLock
from urllib.parse import parse_qs, unquote

import httpx

from kbc_access.keboola_storage import StorageClient, StorageSettings

STACK_URL = "https://connection.fake-stack.keboola.com"
TOKEN = "fake-storage-token-0123456789abcdef"
TOKEN_HEADER = "X-StorageApi-Token"
GCS_HOST = "storage.googleapis.com"
ABS_ENDPOINT = "https://fakeaccount.blob.core.windows.net"
# A SAS whose values themselves contain '=' (url-encoded signature ends with '%3D', plus a raw '=').
ABS_SAS = "sv=2023-01-03&ss=b&srt=o&sp=w&se=2026-09-25T00%3A00%3A00Z&sig=Ab%2BCd%2FEf%3D%3D&x=a=b"
PREVIEW_DEFAULT_LIMIT = 100
PREVIEW_MAX_LIMIT = 1000


class JobFailure(Exception):
    """Raised inside a job's apply step; turns the job into status 'error'."""


@dataclass
class FakeTable:
    table_id: str
    columns: list[str]
    primary_key: list[str]
    rows: list[dict[str, str]] = field(default_factory=list)

    def pk(self, row: dict[str, str]) -> tuple[str, ...]:
        return tuple(row[c] for c in self.primary_key)


@dataclass
class FakeJob:
    job_id: int
    kind: str
    apply: Callable[[], None]
    polls: int = 0
    status: str = "waiting"
    error: str | None = None
    forced_error: str | None = None


@dataclass
class HttpFailure:
    method: str
    path_contains: str
    status: int
    body: str
    times: int


@dataclass
class JobFailureRule:
    kind: str
    table_contains: str
    message: str
    times: int


def _csv_text(columns: list[str], rows: list[dict[str, str]]) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return out.getvalue()


class FakeStorageApi:
    def __init__(self, *, token: str = TOKEN, cloud: str = "gcs") -> None:
        self.token = token
        self.cloud = cloud  # "gcs" | "abs" | "aws" | "url"
        self.buckets: set[str] = set()
        self.tables: dict[str, FakeTable] = {}
        self.files: dict[int, dict[str, object]] = {}
        self.jobs: dict[int, FakeJob] = {}
        self._ids = itertools.count(1000)
        self._lock = RLock()
        # Observations for assertions.
        self.requests: list[httpx.Request] = []
        self.cloud_requests: list[httpx.Request] = []
        self.imports: list[tuple[str, int]] = []  # (table_id, rows in the file) per import job
        self.deletes: list[tuple[str, list[str]]] = []  # (table_id, where values) per delete job
        self.created_tables: list[str] = []
        self.added_columns: list[tuple[str, str]] = []  # (table_id, column) per add-column job
        # Failure injection.
        self.http_failures: list[HttpFailure] = []
        self.job_failures: list[JobFailureRule] = []
        self.cloud_put_status: int | None = None
        self.jobs_never_finish = False

    # ---- test helpers ------------------------------------------------------

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def client(self, *, sleep: Callable[[float], None] | None = None, **overrides: object) -> StorageClient:
        values: dict[str, object] = {
            "stack_url": STACK_URL,
            "token": self.token,
            "http_timeout_seconds": 5.0,
            "job_timeout_seconds": 30.0,
            "job_poll_seconds": 0.01,
            "preview_row_limit": PREVIEW_MAX_LIMIT,
        }
        values.update(overrides)
        return StorageClient(
            StorageSettings(**values),  # type: ignore[arg-type]
            transport=self.transport(),
            sleep=sleep or (lambda _seconds: None),
        )

    def add_bucket(self, bucket_id: str) -> None:
        self.buckets.add(bucket_id)

    def add_table(
        self, table_id: str, columns: list[str], primary_key: list[str], rows: list[dict[str, str]] | None = None
    ) -> FakeTable:
        self.buckets.add(table_id.rsplit(".", 1)[0])
        table = FakeTable(table_id, list(columns), list(primary_key), [dict(r) for r in rows or []])
        self.tables[table_id] = table
        return table

    def rows(self, table_id: str) -> list[dict[str, str]]:
        return [dict(r) for r in self.tables[table_id].rows]

    def fail_http(self, method: str, path_contains: str, *, status: int = 500, body: str = "Internal error", times: int = 1) -> None:
        self.http_failures.append(HttpFailure(method.upper(), path_contains, status, body, times))

    def fail_job(self, kind: str, *, table_contains: str = "", message: str = "Injected job failure", times: int = 1) -> None:
        """kind: 'import' | 'delete' | 'create'."""
        self.job_failures.append(JobFailureRule(kind, table_contains, message, times))

    def storage_requests(self, method: str | None = None, path_contains: str = "") -> list[httpx.Request]:
        return [
            r for r in self.requests
            if r.url.host != GCS_HOST and not str(r.url).startswith(ABS_ENDPOINT)
            and (method is None or r.method == method) and path_contains in unquote(r.url.path)
        ]

    # ---- dispatch ------------------------------------------------------------

    def handle(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            self.requests.append(request)
            if request.url.host == GCS_HOST or str(request.url).startswith(ABS_ENDPOINT):
                return self._cloud_put(request)
            if f"{request.url.scheme}://{request.url.host}" != STACK_URL:
                return self._error(404, f"Unknown host {request.url.host}")
            if request.headers.get(TOKEN_HEADER) != self.token:
                return self._error(401, "Invalid access token")
            path = unquote(request.url.path)
            for failure in self.http_failures:
                if failure.times > 0 and failure.method == request.method and failure.path_contains in path:
                    failure.times -= 1
                    return httpx.Response(failure.status, text=failure.body)
            return self._route(request, path)

    def _route(self, request: httpx.Request, path: str) -> httpx.Response:
        parts = path.strip("/").split("/")
        # parts: ["v2", "storage", ...]
        if parts[:2] != ["v2", "storage"]:
            return self._error(404, "Not found")
        rest = parts[2:]
        method = request.method
        if method == "POST" and rest == ["files", "prepare"]:
            return self._files_prepare(request)
        if method == "GET" and len(rest) == 2 and rest[0] == "jobs":
            return self._job_status(int(rest[1]))
        if rest[:1] == ["buckets"] and len(rest) >= 2:
            bucket_id = rest[1]
            if method == "GET" and len(rest) == 2:
                if bucket_id not in self.buckets:
                    return self._error(404, f"Bucket {bucket_id} not found")
                return self._json({"id": bucket_id})
            if method == "GET" and rest[2:] == ["tables"]:
                if bucket_id not in self.buckets:
                    return self._error(404, f"Bucket {bucket_id} not found")
                listed = [
                    {"id": t.table_id, "name": t.table_id.rsplit(".", 1)[1], "primaryKey": t.primary_key}
                    for t in self.tables.values() if t.table_id.rsplit(".", 1)[0] == bucket_id
                ]
                return self._json(listed)
            if method == "POST" and rest[2:] == ["tables-async"]:
                return self._tables_async(bucket_id, request)
        if rest[:1] == ["tables"] and len(rest) == 2 and method == "GET":
            if rest[1] not in self.tables:
                return self._error(404, f"Table {rest[1]} not found")
            table = self.tables[rest[1]]
            return self._json({"id": table.table_id, "columns": list(table.columns), "primaryKey": table.primary_key})
        if rest[:1] == ["tables"] and len(rest) == 3:
            table_id, action = rest[1], rest[2]
            if table_id not in self.tables:
                return self._error(404, f"Table {table_id} not found")
            if method == "GET" and action == "data-preview":
                return self._data_preview(self.tables[table_id], request)
            if method == "POST" and action == "import-async":
                return self._import_async(self.tables[table_id], request)
            if method == "DELETE" and action == "rows":
                return self._delete_rows(self.tables[table_id], request)
            if method == "POST" and action == "columns":
                return self._add_column(self.tables[table_id], request)
        return self._error(404, f"No fake route for {method} {path}")

    # ---- responses -----------------------------------------------------------

    @staticmethod
    def _json(payload: object, status: int = 200) -> httpx.Response:
        return httpx.Response(status, content=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})

    def _error(self, status: int, message: str) -> httpx.Response:
        return self._json({"error": message, "code": status, "status": "error"}, status)

    @staticmethod
    def _form(request: httpx.Request) -> dict[str, str]:
        parsed = parse_qs(request.content.decode("utf-8"), keep_blank_values=True)
        return {k: v[-1] for k, v in parsed.items()}

    # ---- files -----------------------------------------------------------------

    def _files_prepare(self, request: httpx.Request) -> httpx.Response:
        form = self._form(request)
        file_id = next(self._ids)
        key = f"exp-15/123/files/2026/09/24/{file_id}.{form['name']}"
        record: dict[str, object] = {"name": form["name"], "size": int(form["sizeBytes"]), "content": None}
        payload: dict[str, object] = {"id": file_id, "name": form["name"]}
        if self.cloud == "gcs":
            bearer = f"ya29.fake-gcs-token-{file_id}"
            record.update(bucket="kbc-fake-files", key=key, bearer=bearer)
            payload["gcsUploadParams"] = {
                "bucket": "kbc-fake-files", "key": key, "access_token": bearer,
                "token_type": "Bearer", "projectId": "kbc-fake",
            }
        elif self.cloud == "abs":
            record.update(container="exp-15-files", blob=key)
            payload["absUploadParams"] = {
                "blobName": key,
                "container": "exp-15-files",
                "accountName": "fakeaccount",
                "absCredentials": {
                    "SASConnectionString": f"BlobEndpoint={ABS_ENDPOINT};SharedAccessSignature={ABS_SAS}",
                    "expiration": "2026-09-25T00:00:00+0000",
                },
            }
        elif self.cloud == "aws":
            payload["uploadParams"] = {
                "key": key, "bucket": "kbc-fake-s3", "acl": "private",
                "credentials": {"AccessKeyId": "ASIAFAKE", "SecretAccessKey": "secret", "SessionToken": "session"},
            }
        elif self.cloud == "url":
            record.update(url_key=key)
            payload["url"] = f"{ABS_ENDPOINT}/presigned/{key}?sig=x"
        self.files[file_id] = record
        return self._json(payload)

    def _cloud_put(self, request: httpx.Request) -> httpx.Response:
        self.cloud_requests.append(request)
        if request.method != "PUT":
            return httpx.Response(405)
        if TOKEN_HEADER.lower() in {k.lower() for k in request.headers}:
            # The Storage token must never leave for the cloud provider.
            return httpx.Response(400, text="Storage token sent to cloud")
        if self.cloud_put_status is not None:
            return httpx.Response(self.cloud_put_status, text="<Error>signed-url-secret-in-body</Error>")
        url = str(request.url)
        for record in self.files.values():
            if request.url.host == GCS_HOST and url == f"https://{GCS_HOST}/{record.get('bucket')}/{record.get('key')}":
                if request.headers.get("Authorization") != f"Bearer {record['bearer']}":
                    return httpx.Response(401, text="bad bearer")
                record["content"] = request.content
                return httpx.Response(200)
            if "blob" in record and url == f"{ABS_ENDPOINT}/{record['container']}/{record['blob']}?{ABS_SAS}":
                if request.headers.get("x-ms-blob-type") != "BlockBlob":
                    return httpx.Response(400, text="missing x-ms-blob-type")
                record["content"] = request.content
                return httpx.Response(201)
            if "url_key" in record and url == f"{ABS_ENDPOINT}/presigned/{record['url_key']}?sig=x":
                record["content"] = request.content
                return httpx.Response(200)
        return httpx.Response(404, text="unknown upload target")

    def _file_csv(self, file_id: str) -> tuple[list[str], list[dict[str, str]]]:
        record = self.files.get(int(file_id))
        if record is None or record["content"] is None:
            raise JobFailure(f"File {file_id} was never uploaded")
        text = bytes(record["content"]).decode("utf-8")  # type: ignore[arg-type]
        reader = csv.DictReader(io.StringIO(text))
        return list(reader.fieldnames or []), list(reader)

    # ---- jobs --------------------------------------------------------------------

    def _new_job(self, kind: str, table_id: str, apply: Callable[[], None]) -> httpx.Response:
        job = FakeJob(next(self._ids), kind, apply)
        for rule in self.job_failures:
            if rule.times > 0 and rule.kind == kind and rule.table_contains in table_id:
                rule.times -= 1
                job.forced_error = rule.message
                break
        self.jobs[job.job_id] = job
        return self._json({"id": job.job_id, "status": "waiting", "operationName": kind}, 202)

    def _job_status(self, job_id: int) -> httpx.Response:
        job = self.jobs.get(job_id)
        if job is None:
            return self._error(404, f"Job {job_id} not found")
        job.polls += 1
        if job.status in ("waiting", "processing"):
            if self.jobs_never_finish or job.polls == 1:
                job.status = "processing"
            elif job.forced_error is not None:
                job.status, job.error = "error", job.forced_error
            else:
                try:
                    job.apply()
                    job.status = "success"
                except JobFailure as exc:
                    job.status, job.error = "error", str(exc)
        payload: dict[str, object] = {"id": job.job_id, "status": job.status, "operationName": job.kind}
        if job.error is not None:
            payload["error"] = {"code": "storage.jobFailed", "message": job.error}
        return self._json(payload)

    # ---- tables ------------------------------------------------------------------

    def _data_preview(self, table: FakeTable, request: httpx.Request) -> httpx.Response:
        limit = int(request.url.params.get("limit", PREVIEW_DEFAULT_LIMIT))
        limit = min(limit, PREVIEW_MAX_LIMIT)
        # No charset on purpose: the client must decode the CSV as UTF-8 anyway.
        return httpx.Response(200, content=_csv_text(table.columns, table.rows[:limit]).encode("utf-8"),
                              headers={"Content-Type": "text/csv"})

    def _import_async(self, table: FakeTable, request: httpx.Request) -> httpx.Response:
        form = self._form(request)
        incremental = form.get("incremental") == "1"

        def apply() -> None:
            header, rows = self._file_csv(form["dataFileId"])
            if set(header) != set(table.columns):
                raise JobFailure(f"CSV columns {header} do not match table columns {table.columns}")
            self.imports.append((table.table_id, len(rows)))
            if not incremental:
                table.rows = []
            index = {table.pk(r): i for i, r in enumerate(table.rows)}
            for row in rows:
                clean = {c: row[c] for c in table.columns}
                key = table.pk(clean)
                if key in index:
                    table.rows[index[key]] = clean
                else:
                    index[key] = len(table.rows)
                    table.rows.append(clean)

        return self._new_job("import", table.table_id, apply)

    def _add_column(self, table: FakeTable, request: httpx.Request) -> httpx.Response:
        name = self._form(request)["name"]

        def apply() -> None:
            if name in table.columns:
                raise JobFailure(f"Column {name} already exists")
            self.added_columns.append((table.table_id, name))
            table.columns.append(name)
            for row in table.rows:
                row[name] = ""

        return self._new_job("add_column", table.table_id, apply)

    def _delete_rows(self, table: FakeTable, request: httpx.Request) -> httpx.Response:
        column = request.url.params.get("whereColumn")
        values = request.url.params.get_list("whereValues[]")
        operator = request.url.params.get("whereOperator", "eq")

        def apply() -> None:
            if column is not None and column not in table.columns:
                raise JobFailure(f"Unknown column {column}")
            self.deletes.append((table.table_id, list(values)))
            if column is None:
                table.rows = []  # the real endpoint truncates without a filter
                return
            match = set(values)
            keep = (lambda r: r[column] not in match) if operator == "eq" else (lambda r: r[column] in match)
            table.rows = [r for r in table.rows if keep(r)]

        return self._new_job("delete", table.table_id, apply)

    def _tables_async(self, bucket_id: str, request: httpx.Request) -> httpx.Response:
        if bucket_id not in self.buckets:
            return self._error(404, f"Bucket {bucket_id} not found")
        form = self._form(request)
        table_id = f"{bucket_id}.{form['name']}"
        primary_key = [c for c in form.get("primaryKey", "").split(",") if c]

        def apply() -> None:
            if table_id in self.tables:
                raise JobFailure(f"Table {table_id} already exists")
            header, rows = self._file_csv(form["dataFileId"])
            missing = [c for c in primary_key if c not in header]
            if missing:
                raise JobFailure(f"Primary key columns {missing} not in the CSV header")
            self.tables[table_id] = FakeTable(table_id, header, primary_key, [dict(r) for r in rows])
            self.created_tables.append(table_id)

        return self._new_job("create", table_id, apply)
