"""Access store — the tables every app reads and the admin app writes.

In Keboola these are Storage tables in one bucket of one project. This module
is the local implementation of the same control-plane tables on SQLite, so several app
processes can read while the admin app writes. The table and column names
match the design doc (section 3) so a Storage-backed implementation can
replace this one behind the same methods.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from kbc_access.config import ProviderSettings
from kbc_access.security_model import (
    RULE_SUBJECT_TYPES,
    ROW_KINDS,
    SUBJECT_EVERYONE,
    TREATMENTS,
    Audience,
    FilterError,
    RowFilter,
    parse_filter,
)

if TYPE_CHECKING:
    from kbc_access.identity import Principal

logger = logging.getLogger(__name__)

SUBJECT_TYPES = ("user", "group", "local_group")
APP_SOURCES = ("manual", "discovered")
# Who may open an app: only principals with a matching grant (the default), or anyone the
# IdP signed in - for apps meant for the whole company, so nobody has to add everyone.
ACCESS_GRANTS = "grants"
ACCESS_ALL_SIGNED_IN = "all_signed_in"
APP_ACCESS = (ACCESS_GRANTS, ACCESS_ALL_SIGNED_IN)
# Dataset security (row access lines and column masks). Limits on what one admin save may carry.
ROW_LINES_MAX_PER_DATASET = 100
MASK_LINES_MAX_PER_DATASET = 200
FILTER_CONDITIONS_MAX = 20
FILTER_VALUES_MAX = 100
FILTER_VALUE_MAX_CHARS = 500
SECURITY_ID_BYTES = 6  # hex-encoded: 12 characters

APP_GRANTS_DDL = """
CREATE TABLE IF NOT EXISTS app_grants (
    app_id TEXT NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'group', 'local_group')),
    subject_id TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    PRIMARY KEY (app_id, subject_type, subject_id)
);
"""

# Also used by the migration that adds the column to a store created before it existed.
APPS_ACCESS_DDL = "access TEXT NOT NULL DEFAULT 'grants' CHECK (access IN ('grants', 'all_signed_in'))"

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS apps (
    app_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    project_id TEXT NOT NULL,
    config_id TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('manual', 'discovered')),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    {APPS_ACCESS_DDL}
);
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1))
);
CREATE TABLE IF NOT EXISTS groups (
    group_id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    external_id TEXT NOT NULL,
    name TEXT NOT NULL,
    UNIQUE (provider, external_id)
);
{APP_GRANTS_DDL}
CREATE TABLE IF NOT EXISTS user_attributes (
    email TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (email, key)
);
CREATE TABLE IF NOT EXISTS local_groups (
    local_group_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS local_group_members (
    local_group_id TEXT NOT NULL,
    email TEXT NOT NULL,
    PRIMARY KEY (local_group_id, email)
);
CREATE TABLE IF NOT EXISTS row_access_rules (
    rule_id TEXT PRIMARY KEY,
    dataset TEXT NOT NULL,
    position TEXT NOT NULL,
    kind TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    filter TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS column_masks (
    mask_id TEXT PRIMARY KEY,
    dataset TEXT NOT NULL,
    column_name TEXT NOT NULL,
    position TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    treatment TEXT NOT NULL
);
"""


# Column order per table; shared by every backend that mirrors these tables. The
# dict order is the write order of a mirror: parents before the rows that reference them.
TABLE_COLUMNS: dict[str, list[str]] = {
    "apps": ["app_id", "name", "url", "project_id", "config_id", "source", "active", "access"],
    "users": ["email", "display_name", "active"],
    "groups": ["group_id", "provider", "external_id", "name"],
    "local_groups": ["local_group_id", "name", "description"],
    "app_grants": ["app_id", "subject_type", "subject_id", "granted_by", "granted_at"],
    "user_attributes": ["email", "key", "value"],
    "local_group_members": ["local_group_id", "email"],
    "row_access_rules": ["rule_id", "dataset", "position", "kind", "subject_type", "subject_id", "filter"],
    "column_masks": ["mask_id", "dataset", "column_name", "position", "subject_type", "subject_id", "treatment"],
}
# Primary key per table (composite for grants and attributes).
TABLE_KEYS: dict[str, list[str]] = {
    "apps": ["app_id"],
    "users": ["email"],
    "groups": ["group_id"],
    "local_groups": ["local_group_id"],
    "app_grants": ["app_id", "subject_type", "subject_id"],
    "user_attributes": ["email", "key"],
    "local_group_members": ["local_group_id", "email"],
    "row_access_rules": ["rule_id"],
    "column_masks": ["mask_id"],
}
_INT_COLUMNS = {("apps", "active"), ("users", "active")}


# A column added by a newer release reads as empty from a backend written by an older one.
_EMPTY_DEFAULTS = {("apps", "access"): ACCESS_GRANTS}


def _from_text(table: str, column: str, value: str) -> object:
    if value == "" and (table, column) in _EMPTY_DEFAULTS:
        return _EMPTY_DEFAULTS[(table, column)]
    return int(value) if (table, column) in _INT_COLUMNS else value


class StoreError(ValueError):
    """Invalid input rejected by the store (shown to the admin as-is)."""


@dataclass(frozen=True)
class App:
    app_id: str
    name: str
    url: str
    project_id: str
    config_id: str
    source: str
    active: bool
    access: str = ACCESS_GRANTS


@dataclass(frozen=True)
class User:
    email: str
    display_name: str
    active: bool


@dataclass(frozen=True)
class Group:
    group_id: str
    provider: str
    external_id: str
    name: str


@dataclass(frozen=True)
class LocalGroup:
    local_group_id: str
    name: str
    description: str


@dataclass(frozen=True)
class Grant:
    app_id: str
    subject_type: str
    subject_id: str
    granted_by: str
    granted_at: str


@dataclass(frozen=True)
class RowAccessRule:
    """One row line of a dataset: `kind` (show / hide) for `subject`, rows matching `filter`.

    `filter` is None when the stored JSON is unreadable: the compiler then skips a show
    line and lets a hide line hide every row (fail closed).
    """

    rule_id: str
    dataset: str
    position: int
    kind: str
    subject_type: str
    subject_id: str
    filter: RowFilter | None


@dataclass(frozen=True)
class ColumnMask:
    """One masking line of a column; the first line (by position) whose subject matches wins."""

    mask_id: str
    dataset: str
    column_name: str
    position: int
    subject_type: str
    subject_id: str
    treatment: str


@dataclass(frozen=True)
class RowAccessRuleInput:
    """A row line as the admin submits it; the list order is the position within its kind."""

    kind: str
    subject_type: str
    subject_id: str
    filter: Mapping[str, object]
    rule_id: str | None = None


@dataclass(frozen=True)
class ColumnMaskInput:
    """A masking line as the admin submits it; the list order (per column) is the position."""

    column_name: str
    subject_type: str
    subject_id: str
    treatment: str
    mask_id: str | None = None


@dataclass(frozen=True)
class DatasetSecurity:
    """The row lines (show lines first, then hide lines, each by position) and masks of one dataset."""

    rows: tuple[RowAccessRule, ...] = ()
    masks: tuple[ColumnMask, ...] = ()


EMPTY_SECURITY = DatasetSecurity()


@dataclass(frozen=True)
class PrincipalSecurity:
    """What the compiler needs for one principal: who they are and every dataset's lines."""

    audience: Audience
    datasets: Mapping[str, DatasetSecurity]


@dataclass(frozen=True)
class AclSnapshot:
    """Everything the gate needs, read in one go so a decision sees one state."""

    apps: dict[str, App]
    users: dict[str, User]
    groups_by_external_id: dict[str, list[Group]]
    grants: list[Grant]
    # Suite-defined groups: id -> group, and email -> the ids that user belongs to.
    local_groups: dict[str, LocalGroup] = field(default_factory=dict)
    local_group_members: dict[str, frozenset[str]] = field(default_factory=dict)
    # Row lines and column masks by dataset.
    security: dict[str, DatasetSecurity] = field(default_factory=dict)

    def local_groups_of(self, email: str) -> frozenset[str]:
        """Ids of the local groups `email` is a member of (existing groups only)."""
        return self.local_group_members.get(email.strip().lower(), frozenset())

    def audience_of(self, principal: Principal) -> Audience:
        """The principal for subject matching: email, local groups (snapshot membership plus any the
        principal already carries) and the internal ids of the IdP groups its external ids map to."""
        email = principal.email.strip().lower()
        return Audience(
            email=email,
            local_groups=self.local_groups_of(email) | principal.local_groups,
            group_ids=frozenset(
                group.group_id
                for external_id in principal.groups
                for group in self.groups_by_external_id.get(external_id, [])
            ),
        )

    def security_for(self, principal: Principal) -> PrincipalSecurity:
        return PrincipalSecurity(audience=self.audience_of(principal), datasets=self.security)


_APP_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ATTR_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
LOCAL_GROUP_ID = re.compile(r"^[a-z0-9_-]{1,64}$")
SECURITY_ID = re.compile(r"^[0-9a-f]{12}$")
_DATASET_KEY = re.compile(r"^[a-z0-9_][a-z0-9_.-]{0,63}$")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _rule_from_row(row: sqlite3.Row) -> RowAccessRule:
    try:
        row_filter: RowFilter | None = parse_filter(json.loads(row["filter"]))
    except (TypeError, ValueError):  # json.JSONDecodeError and FilterError are ValueErrors
        logger.warning("row_access_rules row '%s' has an unreadable filter", row["rule_id"])
        row_filter = None
    try:
        position = int(row["position"])
    except (TypeError, ValueError):
        logger.warning("row_access_rules row '%s' has an unreadable position", row["rule_id"])
        position = 0
    return RowAccessRule(
        rule_id=row["rule_id"], dataset=row["dataset"], position=position, kind=row["kind"],
        subject_type=row["subject_type"], subject_id=row["subject_id"], filter=row_filter,
    )


def _mask_from_row(row: sqlite3.Row) -> ColumnMask:
    try:
        position = int(row["position"])
    except (TypeError, ValueError):
        logger.warning("column_masks row '%s' has an unreadable position", row["mask_id"])
        position = 0
    return ColumnMask(
        mask_id=row["mask_id"], dataset=row["dataset"], column_name=row["column_name"], position=position,
        subject_type=row["subject_type"], subject_id=row["subject_id"], treatment=row["treatment"],
    )


def _rule_order(rule: RowAccessRule) -> tuple[str, int, int, str]:
    return (rule.dataset, ROW_KINDS.index(rule.kind) if rule.kind in ROW_KINDS else len(ROW_KINDS), rule.position, rule.rule_id)


def _mask_order(mask: ColumnMask) -> tuple[str, str, int, str]:
    return (mask.dataset, mask.column_name, mask.position, mask.mask_id)


def _check_filter_limits(row_filter: RowFilter, where: str) -> None:
    if len(row_filter.conditions) > FILTER_CONDITIONS_MAX:
        raise StoreError(f"{where}: at most {FILTER_CONDITIONS_MAX} conditions per line")
    for condition in row_filter.conditions:
        values = condition.values or ()
        if len(values) > FILTER_VALUES_MAX:
            raise StoreError(f"{where}: at most {FILTER_VALUES_MAX} values in one list")
        for value in (*values, *([condition.value] if condition.value is not None else [])):
            if len(value) > FILTER_VALUE_MAX_CHARS:
                raise StoreError(f"{where}: a value is longer than {FILTER_VALUE_MAX_CHARS} characters")


def _check_id(given: str | None, seen: set[str], where: str) -> str | None:
    if not given:
        return None
    given = given.strip()
    if not SECURITY_ID.fullmatch(given):
        raise StoreError(f"{where}: invalid line id '{given}'")
    if given in seen:
        raise StoreError(f"{where}: line id '{given}' is used twice")
    seen.add(given)
    return given


class AccessStore:
    def __init__(self, path: Path, providers: Mapping[str, ProviderSettings]) -> None:
        self._path = path
        self._providers = dict(providers)
        self._patterns = {name: re.compile(p.group_id_pattern) for name, p in providers.items()}
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            self._migrate_app_grants(conn)
            self._migrate_apps_access(conn)

    @staticmethod
    def _migrate_app_grants(conn: sqlite3.Connection) -> None:
        """Widen the subject_type CHECK of a store created before local groups existed.

        SQLite cannot alter a CHECK constraint, so the table is rebuilt (rows kept).
        """
        row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'app_grants'").fetchone()
        if row is None or "'local_group'" in row["sql"]:
            return
        conn.execute("ALTER TABLE app_grants RENAME TO app_grants_old")
        conn.executescript(APP_GRANTS_DDL)
        conn.execute("INSERT INTO app_grants SELECT * FROM app_grants_old")
        conn.execute("DROP TABLE app_grants_old")

    @staticmethod
    def _migrate_apps_access(conn: sqlite3.Connection) -> None:
        """Add apps.access to a store created before it existed; existing apps keep needing grants."""
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(apps)").fetchall()}
        if "access" not in columns:
            conn.execute(f"ALTER TABLE apps ADD COLUMN {APPS_ACCESS_DDL}")

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ---- providers -------------------------------------------------------

    @property
    def providers(self) -> dict[str, ProviderSettings]:
        return dict(self._providers)

    def validate_group_id(self, provider: str, external_id: str) -> None:
        """Check an IdP group identifier against the provider's template."""
        if provider not in self._patterns:
            raise StoreError(f"Unknown provider '{provider}'. Known: {', '.join(sorted(self._patterns))}")
        if not self._patterns[provider].fullmatch(external_id):
            example = self._providers[provider].example
            raise StoreError(
                f"'{external_id}' is not a valid {self._providers[provider].label} group ID "
                f"(expected something like {example})"
            )

    # ---- apps ------------------------------------------------------------

    def upsert_app(self, app: App) -> None:
        if not _APP_ID.fullmatch(app.app_id):
            raise StoreError("App ID must be lowercase letters, digits, '-' or '_' (max 64)")
        if not app.name.strip():
            raise StoreError("App name is required")
        if app.source not in APP_SOURCES:
            raise StoreError(f"Unknown app source '{app.source}'")
        if app.access not in APP_ACCESS:
            raise StoreError(f"Unknown app access '{app.access}'. Known: {', '.join(APP_ACCESS)}")
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO apps (app_id, name, url, project_id, config_id, source, active, access)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (app_id) DO UPDATE SET name = excluded.name, url = excluded.url,
                     project_id = excluded.project_id, config_id = excluded.config_id,
                     source = excluded.source, active = excluded.active, access = excluded.access""",
                (app.app_id, app.name.strip(), app.url, app.project_id, app.config_id, app.source, int(app.active),
                 app.access),
            )

    def delete_app(self, app_id: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM apps WHERE app_id = ?", (app_id,))

    def list_apps(self) -> list[App]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM apps ORDER BY name").fetchall()
        return [App(**{**dict(r), "active": bool(r["active"])}) for r in rows]

    # ---- users -----------------------------------------------------------

    def upsert_user(self, email: str, display_name: str, active: bool) -> None:
        email = email.strip().lower()
        if not EMAIL_PATTERN.fullmatch(email):
            raise StoreError(f"'{email}' is not a valid email")
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO users (email, display_name, active) VALUES (?, ?, ?)
                   ON CONFLICT (email) DO UPDATE SET display_name = excluded.display_name,
                     active = excluded.active""",
                (email, display_name.strip() or email, int(active)),
            )

    def update_user(self, email: str, *, new_email: str, display_name: str, active: bool) -> str:
        """Edit a user; a changed email carries its grants and attributes along. Returns the email."""
        email = email.strip().lower()
        new_email = new_email.strip().lower()
        if not EMAIL_PATTERN.fullmatch(new_email):
            raise StoreError(f"'{new_email}' is not a valid email")
        with self._conn() as conn:
            if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone() is None:
                raise StoreError(f"Unknown user '{email}'")
            if new_email != email and conn.execute("SELECT 1 FROM users WHERE email = ?", (new_email,)).fetchone():
                raise StoreError(f"User '{new_email}' already exists")
            conn.execute(
                "UPDATE users SET email = ?, display_name = ?, active = ? WHERE email = ?",
                (new_email, display_name.strip() or new_email, int(active), email),
            )
            if new_email != email:
                conn.execute(
                    "UPDATE app_grants SET subject_id = ? WHERE subject_type = 'user' AND subject_id = ?",
                    (new_email, email),
                )
                conn.execute("UPDATE user_attributes SET email = ? WHERE email = ?", (new_email, email))
                conn.execute("UPDATE local_group_members SET email = ? WHERE email = ?", (new_email, email))
                for table in ("row_access_rules", "column_masks"):
                    conn.execute(
                        f"UPDATE {table} SET subject_id = ? WHERE subject_type = 'user' AND subject_id = ?",  # noqa: S608
                        (new_email, email),
                    )
        return new_email

    def delete_user(self, email: str) -> None:
        email = email.strip().lower()
        with self._conn() as conn:
            conn.execute("DELETE FROM users WHERE email = ?", (email,))
            conn.execute("DELETE FROM app_grants WHERE subject_type = 'user' AND subject_id = ?", (email,))
            conn.execute("DELETE FROM user_attributes WHERE email = ?", (email,))
            conn.execute("DELETE FROM local_group_members WHERE email = ?", (email,))
            self._drop_security_lines(conn, "user", email)

    def list_users(self) -> list[User]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY email").fetchall()
        return [User(email=r["email"], display_name=r["display_name"], active=bool(r["active"])) for r in rows]

    # ---- groups ----------------------------------------------------------

    def create_group(self, provider: str, external_id: str, name: str) -> Group:
        external_id = external_id.strip()
        self.validate_group_id(provider, external_id)
        if not name.strip():
            raise StoreError("Group name is required")
        group = Group(group_id=uuid.uuid4().hex[:12], provider=provider, external_id=external_id, name=name.strip())
        try:
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO groups (group_id, provider, external_id, name) VALUES (?, ?, ?, ?)",
                    (group.group_id, group.provider, group.external_id, group.name),
                )
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"Group {provider}:{external_id} already exists") from exc
        return group

    def update_group(self, group_id: str, *, provider: str, external_id: str, name: str) -> Group:
        """Edit a group in place; its grants stay attached because they reference group_id."""
        external_id = external_id.strip()
        self.validate_group_id(provider, external_id)
        if not name.strip():
            raise StoreError("Group name is required")
        try:
            with self._conn() as conn:
                updated = conn.execute(
                    "UPDATE groups SET provider = ?, external_id = ?, name = ? WHERE group_id = ?",
                    (provider, external_id, name.strip(), group_id),
                ).rowcount
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"Group {provider}:{external_id} already exists") from exc
        if not updated:
            raise StoreError(f"Unknown group '{group_id}'")
        return Group(group_id=group_id, provider=provider, external_id=external_id, name=name.strip())

    def set_app_grants(self, subject_type: str, subject_id: str, app_ids: set[str], granted_by: str) -> tuple[set[str], set[str]]:
        """Make `app_ids` exactly the apps granted to one subject. Returns (added, removed)."""
        if subject_type == "user":
            subject_id = subject_id.strip().lower()
        current = {g.app_id for g in self.list_grants() if g.subject_type == subject_type and g.subject_id == subject_id}
        added, removed = app_ids - current, current - app_ids
        for app_id in sorted(added):
            self.grant(app_id, subject_type, subject_id, granted_by)
        for app_id in sorted(removed):
            self.revoke(app_id, subject_type, subject_id)
        return added, removed

    def delete_group(self, group_id: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM groups WHERE group_id = ?", (group_id,))
            conn.execute("DELETE FROM app_grants WHERE subject_type = 'group' AND subject_id = ?", (group_id,))
            self._drop_security_lines(conn, "group", group_id)

    def list_groups(self) -> list[Group]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
        return [Group(**dict(r)) for r in rows]

    # ---- local groups ----------------------------------------------------

    def create_local_group(self, local_group_id: str, name: str, description: str = "") -> LocalGroup:
        local_group_id = local_group_id.strip()
        if not LOCAL_GROUP_ID.fullmatch(local_group_id):
            raise StoreError("Local group ID must be lowercase letters, digits, '-' or '_' (1-64 characters)")
        if not name.strip():
            raise StoreError("Local group name is required")
        group = LocalGroup(local_group_id, name.strip(), description.strip())
        try:
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO local_groups (local_group_id, name, description) VALUES (?, ?, ?)",
                    (group.local_group_id, group.name, group.description),
                )
        except sqlite3.IntegrityError as exc:
            raise StoreError(f"Local group '{local_group_id}' already exists") from exc
        return group

    def update_local_group(self, local_group_id: str, *, name: str, description: str = "") -> LocalGroup:
        if not name.strip():
            raise StoreError("Local group name is required")
        with self._conn() as conn:
            updated = conn.execute(
                "UPDATE local_groups SET name = ?, description = ? WHERE local_group_id = ?",
                (name.strip(), description.strip(), local_group_id),
            ).rowcount
        if not updated:
            raise StoreError(f"Unknown local group '{local_group_id}'")
        return LocalGroup(local_group_id, name.strip(), description.strip())

    def delete_local_group(self, local_group_id: str) -> None:
        """Remove the group with its memberships and its app grants."""
        with self._conn() as conn:
            conn.execute("DELETE FROM local_groups WHERE local_group_id = ?", (local_group_id,))
            conn.execute("DELETE FROM local_group_members WHERE local_group_id = ?", (local_group_id,))
            conn.execute(
                "DELETE FROM app_grants WHERE subject_type = 'local_group' AND subject_id = ?", (local_group_id,)
            )
            self._drop_security_lines(conn, "local_group", local_group_id)

    def list_local_groups(self) -> list[LocalGroup]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM local_groups ORDER BY name, local_group_id").fetchall()
        return [LocalGroup(**dict(r)) for r in rows]

    def add_local_group_member(self, local_group_id: str, email: str) -> None:
        """Add a registered user to a local group; adding an existing member is a no-op."""
        email = email.strip().lower()
        with self._conn() as conn:
            if conn.execute("SELECT 1 FROM local_groups WHERE local_group_id = ?", (local_group_id,)).fetchone() is None:
                raise StoreError(f"Unknown local group '{local_group_id}'")
            if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone() is None:
                raise StoreError("user must be registered first")
            conn.execute(
                "INSERT OR IGNORE INTO local_group_members (local_group_id, email) VALUES (?, ?)",
                (local_group_id, email),
            )

    def remove_local_group_member(self, local_group_id: str, email: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM local_group_members WHERE local_group_id = ? AND email = ?",
                (local_group_id, email.strip().lower()),
            )

    def list_local_group_members(self) -> dict[str, list[str]]:
        """Members (sorted emails) per local group id; groups without members map to an empty list."""
        with self._conn() as conn:
            ids = [r["local_group_id"] for r in conn.execute("SELECT local_group_id FROM local_groups")]
            rows = conn.execute("SELECT local_group_id, email FROM local_group_members ORDER BY email").fetchall()
        members: dict[str, list[str]] = {i: [] for i in ids}
        for r in rows:
            if r["local_group_id"] in members:
                members[r["local_group_id"]].append(r["email"])
        return members

    def local_groups_of(self, email: str) -> list[LocalGroup]:
        """Local groups a user belongs to, by name."""
        email = email.strip().lower()
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT g.* FROM local_groups g JOIN local_group_members m ON m.local_group_id = g.local_group_id
                   WHERE m.email = ? ORDER BY g.name, g.local_group_id""",
                (email,),
            ).fetchall()
        return [LocalGroup(**dict(r)) for r in rows]

    # ---- grants ----------------------------------------------------------

    def grant(self, app_id: str, subject_type: str, subject_id: str, granted_by: str) -> None:
        if subject_type not in SUBJECT_TYPES:
            raise StoreError(f"Subject type must be one of {SUBJECT_TYPES}")
        with self._conn() as conn:
            if conn.execute("SELECT 1 FROM apps WHERE app_id = ?", (app_id,)).fetchone() is None:
                raise StoreError(f"Unknown app '{app_id}'")
            if subject_type == "user":
                subject_id = subject_id.strip().lower()
                if conn.execute("SELECT 1 FROM users WHERE email = ?", (subject_id,)).fetchone() is None:
                    raise StoreError(f"Unknown user '{subject_id}' — create the user first")
            elif subject_type == "local_group":
                if conn.execute("SELECT 1 FROM local_groups WHERE local_group_id = ?", (subject_id,)).fetchone() is None:
                    raise StoreError(f"Unknown local group '{subject_id}'")
            elif conn.execute("SELECT 1 FROM groups WHERE group_id = ?", (subject_id,)).fetchone() is None:
                raise StoreError(f"Unknown group '{subject_id}'")
            conn.execute(
                """INSERT OR IGNORE INTO app_grants (app_id, subject_type, subject_id, granted_by, granted_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (app_id, subject_type, subject_id, granted_by, _now()),
            )

    def revoke(self, app_id: str, subject_type: str, subject_id: str) -> None:
        if subject_type == "user":
            subject_id = subject_id.strip().lower()
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM app_grants WHERE app_id = ? AND subject_type = ? AND subject_id = ?",
                (app_id, subject_type, subject_id),
            )

    def list_grants(self) -> list[Grant]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM app_grants ORDER BY app_id, subject_type, subject_id").fetchall()
        return [Grant(**dict(r)) for r in rows]

    # ---- user attributes -------------------------------------------------

    def set_attribute(self, email: str, key: str, value: str) -> None:
        email = email.strip().lower()
        if not _ATTR_KEY.fullmatch(key):
            raise StoreError("Attribute key must be lowercase snake_case")
        if not value.strip():
            raise StoreError("Attribute value is required (delete the attribute instead)")
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO user_attributes (email, key, value) VALUES (?, ?, ?)
                   ON CONFLICT (email, key) DO UPDATE SET value = excluded.value""",
                (email, key, value.strip()),
            )

    def delete_attribute(self, email: str, key: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM user_attributes WHERE email = ? AND key = ?", (email.strip().lower(), key))

    def attributes_for(self, email: str) -> dict[str, str]:
        with self._conn() as conn:
            rows = conn.execute("SELECT key, value FROM user_attributes WHERE email = ?", (email.lower(),)).fetchall()
        return {r["key"]: r["value"] for r in rows}

    def list_attributes(self) -> list[tuple[str, str, str]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT email, key, value FROM user_attributes ORDER BY email, key").fetchall()
        return [(r["email"], r["key"], r["value"]) for r in rows]

    # ---- dataset security (row access lines and column masks) ------------------

    @staticmethod
    def _drop_security_lines(conn: sqlite3.Connection, subject_type: str, subject_id: str) -> None:
        for table in ("row_access_rules", "column_masks"):
            conn.execute(
                f"DELETE FROM {table} WHERE subject_type = ? AND subject_id = ?",  # noqa: S608 - fixed names
                (subject_type, subject_id),
            )

    @staticmethod
    def _normalise_subject(conn: sqlite3.Connection, subject_type: str, subject_id: str, where: str) -> str:
        """The subject id (lowercased for a user, '' for everyone), or StoreError when no such subject exists."""
        if subject_type not in RULE_SUBJECT_TYPES:
            raise StoreError(f"{where}: subject type must be one of {', '.join(RULE_SUBJECT_TYPES)}")
        subject_id = subject_id.strip()
        if subject_type == SUBJECT_EVERYONE:
            if subject_id:
                raise StoreError(f"{where}: 'everyone' takes no subject id")
            return ""
        if subject_type == "user":
            subject_id = subject_id.lower()
            found = conn.execute("SELECT 1 FROM users WHERE email = ?", (subject_id,)).fetchone()
            label = "user"
        elif subject_type == "local_group":
            found = conn.execute("SELECT 1 FROM local_groups WHERE local_group_id = ?", (subject_id,)).fetchone()
            label = "local group"
        else:
            found = conn.execute("SELECT 1 FROM groups WHERE group_id = ?", (subject_id,)).fetchone()
            label = "group"
        if found is None:
            raise StoreError(f"{where}: unknown {label} '{subject_id}'")
        return subject_id

    @staticmethod
    def _new_id(conn: sqlite3.Connection, table: str, key: str) -> str:
        while True:
            candidate = uuid.uuid4().hex[: SECURITY_ID_BYTES * 2]
            if conn.execute(f"SELECT 1 FROM {table} WHERE {key} = ?", (candidate,)).fetchone() is None:  # noqa: S608
                return candidate

    def list_row_access_rules(self, dataset: str | None = None) -> list[RowAccessRule]:
        """Row lines of one dataset (or all): show lines then hide lines, each by position."""
        query, params = "SELECT * FROM row_access_rules", ()
        if dataset is not None:
            query, params = query + " WHERE dataset = ?", (dataset.strip().lower(),)
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return sorted((_rule_from_row(r) for r in rows), key=_rule_order)

    def list_column_masks(self, dataset: str | None = None) -> list[ColumnMask]:
        """Masking lines of one dataset (or all), by column, then position."""
        query, params = "SELECT * FROM column_masks", ()
        if dataset is not None:
            query, params = query + " WHERE dataset = ?", (dataset.strip().lower(),)
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return sorted((_mask_from_row(r) for r in rows), key=_mask_order)

    def dataset_security(self, dataset: str) -> DatasetSecurity:
        return DatasetSecurity(tuple(self.list_row_access_rules(dataset)), tuple(self.list_column_masks(dataset)))

    def set_dataset_security(
        self, dataset: str, rows: list[RowAccessRuleInput], masks: list[ColumnMaskInput]
    ) -> DatasetSecurity:
        """Make `rows` and `masks` exactly the security of one dataset: validated, then written as one unit.

        Errors name the line: `Row line 2: ...` (position in `rows`), `Mask on revenue, line 1: ...`
        (position among that column's masks).
        """
        dataset = dataset.strip().lower()
        if not _DATASET_KEY.fullmatch(dataset):
            raise StoreError("Dataset name must be lowercase letters, digits, '_', '.', '-' (max 64)")
        if len(rows) > ROW_LINES_MAX_PER_DATASET:
            raise StoreError(f"At most {ROW_LINES_MAX_PER_DATASET} row lines per dataset")
        if len(masks) > MASK_LINES_MAX_PER_DATASET:
            raise StoreError(f"At most {MASK_LINES_MAX_PER_DATASET} masking lines per dataset")
        seen_rule_ids: set[str] = set()
        seen_mask_ids: set[str] = set()
        with self._conn() as conn:
            prepared_rows: list[tuple[str | None, str, str, str, RowFilter]] = []
            for number, line in enumerate(rows, start=1):
                where = f"Row line {number}"
                if line.kind not in ROW_KINDS:
                    raise StoreError(f"{where}: kind must be one of {', '.join(ROW_KINDS)}")
                subject_id = self._normalise_subject(conn, line.subject_type, line.subject_id, where)
                try:
                    row_filter = parse_filter(line.filter)
                except FilterError as exc:
                    raise StoreError(f"{where}: {exc}") from exc
                _check_filter_limits(row_filter, where)
                rule_id = _check_id(line.rule_id, seen_rule_ids, where)
                if rule_id is not None:
                    owner = conn.execute("SELECT dataset FROM row_access_rules WHERE rule_id = ?", (rule_id,)).fetchone()
                    if owner is not None and owner["dataset"] != dataset:
                        raise StoreError(f"{where}: line id '{rule_id}' belongs to another dataset")
                prepared_rows.append((rule_id, line.kind, line.subject_type, subject_id, row_filter))
            prepared_masks: list[tuple[str | None, str, int, str, str, str]] = []
            per_column: dict[str, int] = {}
            for mask in masks:
                column = mask.column_name.strip().lower()
                per_column[column] = per_column.get(column, 0) + 1
                where = f"Mask on {column}, line {per_column[column]}"
                if not column:
                    raise StoreError(f"{where}: the column is required")
                if mask.treatment not in TREATMENTS:
                    raise StoreError(f"{where}: treatment must be one of {', '.join(TREATMENTS)}")
                subject_id = self._normalise_subject(conn, mask.subject_type, mask.subject_id, where)
                mask_id = _check_id(mask.mask_id, seen_mask_ids, where)
                if mask_id is not None:
                    owner = conn.execute("SELECT dataset FROM column_masks WHERE mask_id = ?", (mask_id,)).fetchone()
                    if owner is not None and owner["dataset"] != dataset:
                        raise StoreError(f"{where}: line id '{mask_id}' belongs to another dataset")
                prepared_masks.append((mask_id, column, per_column[column], mask.subject_type, subject_id, mask.treatment))

            conn.execute("DELETE FROM row_access_rules WHERE dataset = ?", (dataset,))
            conn.execute("DELETE FROM column_masks WHERE dataset = ?", (dataset,))
            saved_rows: list[RowAccessRule] = []
            positions = {kind: 0 for kind in ROW_KINDS}
            for rule_id, kind, subject_type, subject_id, row_filter in prepared_rows:
                positions[kind] += 1
                rule_id = rule_id or self._new_id(conn, "row_access_rules", "rule_id")
                conn.execute(
                    """INSERT INTO row_access_rules (rule_id, dataset, position, kind, subject_type, subject_id, filter)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (rule_id, dataset, str(positions[kind]), kind, subject_type, subject_id,
                     json.dumps(row_filter.to_json(), sort_keys=True)),
                )
                saved_rows.append(RowAccessRule(rule_id, dataset, positions[kind], kind, subject_type, subject_id, row_filter))
            saved_masks: list[ColumnMask] = []
            for mask_id, column, position, subject_type, subject_id, treatment in prepared_masks:
                mask_id = mask_id or self._new_id(conn, "column_masks", "mask_id")
                conn.execute(
                    """INSERT INTO column_masks (mask_id, dataset, column_name, position, subject_type, subject_id, treatment)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (mask_id, dataset, column, str(position), subject_type, subject_id, treatment),
                )
                saved_masks.append(ColumnMask(mask_id, dataset, column, position, subject_type, subject_id, treatment))
        return DatasetSecurity(tuple(sorted(saved_rows, key=_rule_order)), tuple(sorted(saved_masks, key=_mask_order)))

    # ---- raw table access (for mirroring into another backend) ------------

    def dump_rows(self, table: str) -> list[dict[str, str]]:
        """Every row of one table as strings, in the column order of TABLE_COLUMNS."""
        columns = TABLE_COLUMNS[table]
        with self._conn() as conn:
            rows = conn.execute(f"SELECT {', '.join(columns)} FROM {table}").fetchall()  # noqa: S608 — fixed identifiers
        return [{c: "" if r[c] is None else str(r[c]) for c in columns} for r in rows]

    def load_rows(self, table: str, rows: list[dict[str, str]]) -> None:
        """Replace one table's rows verbatim (no validation: the rows come from a trusted backend)."""
        columns = TABLE_COLUMNS[table]
        placeholders = ", ".join("?" for _ in columns)
        with self._conn() as conn:
            conn.execute(f"DELETE FROM {table}")  # noqa: S608
            conn.executemany(
                f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",  # noqa: S608
                [tuple(_from_text(table, c, row.get(c, "")) for c in columns) for row in rows],
            )

    # ---- snapshot --------------------------------------------------------

    def snapshot(self) -> AclSnapshot:
        """Read apps, users, groups, grants and local groups in a single transaction."""
        with self._conn() as conn:
            conn.execute("BEGIN")
            apps = conn.execute("SELECT * FROM apps").fetchall()
            users = conn.execute("SELECT * FROM users").fetchall()
            groups = conn.execute("SELECT * FROM groups").fetchall()
            grants = conn.execute("SELECT * FROM app_grants").fetchall()
            local_groups = conn.execute("SELECT * FROM local_groups").fetchall()
            members = conn.execute("SELECT * FROM local_group_members").fetchall()
            rule_rows = conn.execute("SELECT * FROM row_access_rules").fetchall()
            mask_rows = conn.execute("SELECT * FROM column_masks").fetchall()
        known_local = {r["local_group_id"] for r in local_groups}
        memberships: dict[str, set[str]] = {}
        for r in members:
            if r["local_group_id"] in known_local:
                memberships.setdefault(r["email"], set()).add(r["local_group_id"])
        rules_by_dataset: dict[str, list[RowAccessRule]] = {}
        for r in rule_rows:
            rule = _rule_from_row(r)
            rules_by_dataset.setdefault(rule.dataset, []).append(rule)
        masks_by_dataset: dict[str, list[ColumnMask]] = {}
        for r in mask_rows:
            mask = _mask_from_row(r)
            masks_by_dataset.setdefault(mask.dataset, []).append(mask)
        security = {
            name: DatasetSecurity(
                tuple(sorted(rules_by_dataset.get(name, []), key=_rule_order)),
                tuple(sorted(masks_by_dataset.get(name, []), key=_mask_order)),
            )
            for name in rules_by_dataset.keys() | masks_by_dataset.keys()
        }
        by_external: dict[str, list[Group]] = {}
        for r in groups:
            by_external.setdefault(r["external_id"], []).append(Group(**dict(r)))
        return AclSnapshot(
            apps={r["app_id"]: App(**{**dict(r), "active": bool(r["active"])}) for r in apps},
            users={r["email"]: User(email=r["email"], display_name=r["display_name"], active=bool(r["active"])) for r in users},
            groups_by_external_id=by_external,
            grants=[Grant(**dict(r)) for r in grants],
            local_groups={r["local_group_id"]: LocalGroup(**dict(r)) for r in local_groups},
            local_group_members={email: frozenset(ids) for email, ids in memberships.items()},
            security=security,
        )
