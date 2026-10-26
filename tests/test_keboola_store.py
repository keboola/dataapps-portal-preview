"""KeboolaAccessStore on the fake Storage API: same behaviour as the SQLite store.

Assertions check the rows in the fake API's tables (the source of truth), not
just what the store reports back through its mirror.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from kbc_access.config import Settings
from kbc_access.demo_seed import fill_store
from kbc_access.gate import decide
from kbc_access.identity import Principal
from kbc_access.keboola_storage import StorageError
from kbc_access.keboola_store import KeboolaAccessStore, storage_columns, storage_primary_key
from kbc_access.store import ACCESS_ALL_SIGNED_IN, ACCESS_GRANTS, TABLE_COLUMNS, AccessStore, App, StoreError
from tests.fake_storage_api import FakeStorageApi

BUCKET = "in.c-apps-control-plane"
FINANCE = "3f2b8c1e-7d4a-4e5b-9a61-2c8d0f4e1b7a"
SUPPLY = "5e6f7a8b-9c0d-4e1f-a2b3-c4d5e6f7a8b9"
PARTNER = "00g7pharmab0partner1"
SALES_MANAGERS = "8a1d4e2f-5b6c-4d7e-9f80-1a2b3c4d5e6f"
NEW_ENTRA_ID = "11111111-2222-4333-8444-555555555555"
PETR = "petr.sales@pharma-a.example"
OLGA = "olga.left@pharma-a.example"


@pytest.fixture
def api() -> FakeStorageApi:
    fake = FakeStorageApi()
    fake.add_bucket(BUCKET)
    return fake


@pytest.fixture
def store(api: FakeStorageApi, settings: Settings) -> KeboolaAccessStore:
    kstore = KeboolaAccessStore(api.client(), BUCKET, settings.providers, read_cache_seconds=0)
    kstore.ensure_schema()
    return kstore


@pytest.fixture
def seeded_store(store: KeboolaAccessStore, settings: Settings) -> KeboolaAccessStore:
    fill_store(settings, store)
    return store


def rows(api: FakeStorageApi, table: str) -> list[dict[str, str]]:
    return api.rows(f"{BUCKET}.{table}")


def _app(app_id: str = "sales", *, active: bool = True, name: str = "Sales") -> App:
    return App(app_id, name, f"https://{app_id}.example/", "123", f"cfg-{app_id}", "manual", active)


def _reset_counters(api: FakeStorageApi) -> None:
    api.imports.clear()
    api.deletes.clear()


# ---- schema -------------------------------------------------------------------


def test_ensure_schema_creates_all_tables_with_row_key(api: FakeStorageApi, settings: Settings) -> None:
    kstore = KeboolaAccessStore(api.client(), BUCKET, settings.providers, read_cache_seconds=0)
    assert kstore.missing_tables() == list(TABLE_COLUMNS)
    assert sorted(kstore.ensure_schema()) == sorted(TABLE_COLUMNS)
    for table in TABLE_COLUMNS:
        created = api.tables[f"{BUCKET}.{table}"]
        assert created.columns == storage_columns(table)
        assert created.primary_key == [storage_primary_key(table)]
    assert api.tables[f"{BUCKET}.app_grants"].columns[0] == "row_key"
    assert api.tables[f"{BUCKET}.app_grants"].primary_key == ["row_key"]
    assert api.tables[f"{BUCKET}.user_attributes"].primary_key == ["row_key"]
    assert api.tables[f"{BUCKET}.apps"].primary_key == ["app_id"]


OLD_APPS_COLUMNS = ["app_id", "name", "url", "project_id", "config_id", "source", "active"]


def test_bucket_from_before_access_column_reads_and_upgrades(api: FakeStorageApi, settings: Settings) -> None:
    """A bucket installed before apps.access: reads default to grants, the first write adds the column."""
    KeboolaAccessStore(api.client(), BUCKET, settings.providers, read_cache_seconds=0).ensure_schema()
    apps = api.tables[f"{BUCKET}.apps"]
    apps.columns = list(OLD_APPS_COLUMNS)
    apps.rows = [{"app_id": "legacy", "name": "Legacy", "url": "u", "project_id": "p", "config_id": "c",
                  "source": "discovered", "active": "1"}]
    kstore = KeboolaAccessStore(api.client(), BUCKET, settings.providers, read_cache_seconds=0)
    assert kstore.list_apps()[0].access == ACCESS_GRANTS
    assert api.added_columns == []  # reading never changes the schema

    kstore.upsert_app(App("everyone", "Everyone", "u", "p", "c", "manual", True, ACCESS_ALL_SIGNED_IN))
    assert api.added_columns == [(f"{BUCKET}.apps", "access")]
    assert apps.columns == [*OLD_APPS_COLUMNS, "access"]
    by_id = {r["app_id"]: r for r in rows(api, "apps")}
    assert by_id["everyone"]["access"] == "all_signed_in"
    assert by_id["legacy"]["access"] == ""  # untouched row: empty in Storage, read as grants
    assert {a.app_id: a.access for a in kstore.list_apps()} == {"legacy": "grants", "everyone": "all_signed_in"}

    kstore.upsert_app(App("second", "Second", "u", "p", "c", "manual", True))
    assert len(api.added_columns) == 1  # checked once per process


def test_ensure_schema_adds_missing_columns(api: FakeStorageApi, settings: Settings) -> None:
    kstore = KeboolaAccessStore(api.client(), BUCKET, settings.providers, read_cache_seconds=0)
    kstore.ensure_schema()
    api.tables[f"{BUCKET}.apps"].columns = list(OLD_APPS_COLUMNS)
    assert kstore.ensure_schema() == []
    assert api.tables[f"{BUCKET}.apps"].columns == storage_columns("apps")
    assert "row_key" not in api.tables[f"{BUCKET}.users"].columns


def test_ensure_schema_is_idempotent(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    created_before = list(api.created_tables)
    assert store.ensure_schema() == []
    assert store.missing_tables() == []
    assert api.created_tables == created_before


def test_ensure_schema_creates_only_the_missing_table(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    del api.tables[f"{BUCKET}.groups"]
    assert store.ensure_schema() == ["groups"]


# ---- apps -------------------------------------------------------------------------


def test_app_upsert_list_update_delete(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_app(_app("admin", name="Admin"))
    assert [a.app_id for a in store.list_apps()] == ["admin", "sales"]
    store.upsert_app(_app("sales", active=False, name="Sales v2"))
    sales = next(a for a in store.list_apps() if a.app_id == "sales")
    assert sales.name == "Sales v2" and sales.active is False
    assert {r["app_id"]: r["active"] for r in rows(api, "apps")} == {"sales": "0", "admin": "1"}
    store.delete_app("sales")
    assert [a.app_id for a in store.list_apps()] == ["admin"]
    assert [r["app_id"] for r in rows(api, "apps")] == ["admin"]


@pytest.mark.parametrize("app_id", ["Sales", "", "-x", "a b", "x" * 65, "a/b"])
def test_app_id_validated_and_nothing_sent(api: FakeStorageApi, store: KeboolaAccessStore, app_id: str) -> None:
    with pytest.raises(StoreError):
        store.upsert_app(_app(app_id))
    assert rows(api, "apps") == []
    assert api.imports == []


def test_delete_app_cascades_grants_in_storage(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_app(_app("supply"))
    store.upsert_user("a@b.example", "A", True)
    store.grant("sales", "user", "a@b.example", "admin@x.example")
    store.grant("supply", "user", "a@b.example", "admin@x.example")
    store.delete_app("sales")
    assert [g.app_id for g in store.list_grants()] == ["supply"]
    assert [r["row_key"] for r in rows(api, "app_grants")] == ["supply|user|a@b.example"]


# ---- users --------------------------------------------------------------------------


def test_user_crud_and_lowercasing(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_user(" Petr.Sales@Pharma-A.Example ", "Petr", True)
    assert [(u.email, u.display_name, u.active) for u in store.list_users()] == [(PETR, "Petr", True)]
    store.upsert_user(PETR, "  ", False)
    user = store.list_users()[0]
    assert user.display_name == PETR and user.active is False
    assert rows(api, "users") == [{"email": PETR, "display_name": PETR, "active": "0"}]


@pytest.mark.parametrize("email", ["nope", "a@b", "a b@c.d", "@c.d", ""])
def test_user_email_validated(store: KeboolaAccessStore, email: str) -> None:
    with pytest.raises(StoreError):
        store.upsert_user(email, "X", True)


def test_delete_user_cascades_grants_and_attributes_in_storage(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user("a@b.example", "A", True)
    store.upsert_user("c@d.example", "C", True)
    store.grant("sales", "user", "a@b.example", "x")
    store.grant("sales", "user", "c@d.example", "x")
    store.set_attribute("a@b.example", "company", "PHARMA_A")
    store.set_attribute("c@d.example", "company", "PHARMA_B")
    store.delete_user("A@B.example")
    assert [u.email for u in store.list_users()] == ["c@d.example"]
    assert store.attributes_for("a@b.example") == {}
    assert [r["email"] for r in rows(api, "users")] == ["c@d.example"]
    assert [r["subject_id"] for r in rows(api, "app_grants")] == ["c@d.example"]
    assert rows(api, "user_attributes") == [
        {"row_key": "c@d.example|company", "email": "c@d.example", "key": "company", "value": "PHARMA_B"}
    ]


def test_rename_user_moves_grants_and_attributes_in_storage(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user(PETR, "Petr", True)
    store.grant("sales", "user", PETR, "test")
    store.set_attribute(PETR, "company", "PHARMA_A")
    saved = store.update_user(PETR, new_email="Petr.New@Pharma-A.example", display_name="Petr N", active=True)
    assert saved == "petr.new@pharma-a.example"
    assert [u.email for u in store.list_users()] == [saved]
    assert store.attributes_for(saved) == {"company": "PHARMA_A"}
    assert store.attributes_for(PETR) == {}
    assert rows(api, "users") == [{"email": saved, "display_name": "Petr N", "active": "1"}]
    assert [(r["row_key"], r["subject_id"]) for r in rows(api, "app_grants")] == [(f"sales|user|{saved}", saved)]
    assert [(r["row_key"], r["email"]) for r in rows(api, "user_attributes")] == [(f"{saved}|company", saved)]


def test_rename_user_onto_existing_email_is_refused(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_user(PETR, "Petr", True)
    store.upsert_user("anna@x.example", "Anna", True)
    _reset_counters(api)
    with pytest.raises(StoreError, match="already exists"):
        store.update_user(PETR, new_email="anna@x.example", display_name="x", active=True)
    with pytest.raises(StoreError, match="Unknown user"):
        store.update_user("ghost@x.example", new_email="ghost@x.example", display_name="", active=True)
    assert api.imports == [] and api.deletes == []
    assert {r["email"] for r in rows(api, "users")} == {PETR, "anna@x.example"}


# ---- groups ----------------------------------------------------------------------------


@pytest.mark.parametrize(("provider", "external_id"), [("entra", FINANCE), ("entra", FINANCE.upper()), ("okta", PARTNER)])
def test_valid_group_ids(api: FakeStorageApi, store: KeboolaAccessStore, provider: str, external_id: str) -> None:
    group = store.create_group(provider, f"  {external_id} ", "G")
    assert group.external_id == external_id and len(group.group_id) == 12
    assert rows(api, "groups") == [
        {"group_id": group.group_id, "provider": provider, "external_id": external_id, "name": "G"}
    ]


@pytest.mark.parametrize(
    ("provider", "external_id"),
    [("entra", "finance"), ("entra", FINANCE[:-1]), ("entra", PARTNER), ("okta", "00g7pharmab0partner"),
     ("okta", FINANCE), ("google", "anything")],
)
def test_invalid_group_ids_rejected_and_nothing_sent(
    api: FakeStorageApi, store: KeboolaAccessStore, provider: str, external_id: str
) -> None:
    with pytest.raises(StoreError):
        store.create_group(provider, external_id, "G")
    assert rows(api, "groups") == [] and api.imports == []


def test_validate_group_id_message_has_example(store: KeboolaAccessStore) -> None:
    with pytest.raises(StoreError, match=FINANCE):
        store.validate_group_id("entra", "finance")
    store.validate_group_id("entra", FINANCE)


def test_duplicate_group_rejected(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.create_group("entra", FINANCE, "finance")
    with pytest.raises(StoreError, match="already exists"):
        store.create_group("entra", FINANCE, "finance again")
    assert len(rows(api, "groups")) == 1


def test_delete_group_cascades_grants_in_storage(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_app(_app("sales"))
    fin = store.create_group("entra", FINANCE, "finance")
    sup = store.create_group("entra", SUPPLY, "supply")
    store.grant("sales", "group", fin.group_id, "x")
    store.grant("sales", "group", sup.group_id, "x")
    store.delete_group(fin.group_id)
    assert [g.name for g in store.list_groups()] == ["supply"]
    assert [r["group_id"] for r in rows(api, "groups")] == [sup.group_id]
    assert [r["subject_id"] for r in rows(api, "app_grants")] == [sup.group_id]


def test_update_group_keeps_grants(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_app(_app("sales"))
    group = store.create_group("entra", SALES_MANAGERS, "sales-managers")
    store.grant("sales", "group", group.group_id, "x")
    with pytest.raises(StoreError, match="not a valid"):
        store.update_group(group.group_id, provider="entra", external_id="not-a-guid", name="x")
    updated = store.update_group(group.group_id, provider="entra", external_id=NEW_ENTRA_ID, name="Sales managers")
    assert updated.group_id == group.group_id
    snap = store.snapshot()
    assert decide(snap, Principal(PETR, frozenset({NEW_ENTRA_ID})), "sales").allowed
    assert not decide(snap, Principal(PETR, frozenset({SALES_MANAGERS})), "sales").allowed
    assert rows(api, "groups")[0]["external_id"] == NEW_ENTRA_ID
    assert len(rows(api, "app_grants")) == 1


# ---- grants -------------------------------------------------------------------------------


def test_grant_and_revoke(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user("a@b.example", "A", True)
    fin = store.create_group("entra", FINANCE, "finance")
    store.grant("sales", "user", " A@B.example ", "admin@x.example")
    store.grant("sales", "group", fin.group_id, "admin@x.example")
    _reset_counters(api)
    store.grant("sales", "group", fin.group_id, "someone-else")  # idempotent: nothing sent
    assert api.imports == [] and api.deletes == []
    grants = store.list_grants()
    assert [(g.subject_type, g.subject_id, g.granted_by) for g in grants] == [
        ("group", fin.group_id, "admin@x.example"),
        ("user", "a@b.example", "admin@x.example"),
    ]
    assert all(g.granted_at for g in grants)
    assert {r["row_key"] for r in rows(api, "app_grants")} == {f"sales|group|{fin.group_id}", "sales|user|a@b.example"}
    store.revoke("sales", "group", fin.group_id)
    store.revoke("sales", "user", "A@B.example")
    assert store.list_grants() == []
    assert rows(api, "app_grants") == []


def test_grant_to_unknown_subjects_rejected(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user("a@b.example", "A", True)
    with pytest.raises(StoreError, match="Unknown user"):
        store.grant("sales", "user", "ghost@b.example", "x")
    with pytest.raises(StoreError, match="Unknown group"):
        store.grant("sales", "group", FINANCE, "x")
    with pytest.raises(StoreError, match="Unknown app"):
        store.grant("nope", "user", "a@b.example", "x")
    with pytest.raises(StoreError, match="Subject type"):
        store.grant("sales", "role", "a@b.example", "x")
    assert rows(api, "app_grants") == []


def test_set_app_grants_is_exact(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    for app_id in ("sales", "supply", "admin"):
        store.upsert_app(_app(app_id))
    group = store.create_group("entra", SALES_MANAGERS, "sales-managers")
    store.grant("sales", "group", group.group_id, "seed")
    added, removed = store.set_app_grants("group", group.group_id, {"supply", "admin"}, "test")
    assert (added, removed) == ({"supply", "admin"}, {"sales"})
    assert {r["app_id"] for r in rows(api, "app_grants")} == {"supply", "admin"}
    _reset_counters(api)
    assert store.set_app_grants("group", group.group_id, {"supply", "admin"}, "test") == (set(), set())
    assert api.imports == [] and api.deletes == []


# ---- attributes -----------------------------------------------------------------------------


def test_attributes_crud(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.set_attribute("A@B.example", "company", " PHARMA_A ")
    store.set_attribute("a@b.example", "branch_code", "B1")
    assert store.attributes_for("A@B.EXAMPLE") == {"company": "PHARMA_A", "branch_code": "B1"}
    store.set_attribute("a@b.example", "company", "PHARMA_B")
    assert store.list_attributes() == [("a@b.example", "branch_code", "B1"), ("a@b.example", "company", "PHARMA_B")]
    store.delete_attribute("A@b.example", "company")
    assert store.attributes_for("a@b.example") == {"branch_code": "B1"}
    assert [r["row_key"] for r in rows(api, "user_attributes")] == ["a@b.example|branch_code"]


def test_attribute_validation(store: KeboolaAccessStore) -> None:
    with pytest.raises(StoreError):
        store.set_attribute("a@b.example", "Company", "v")
    with pytest.raises(StoreError):
        store.set_attribute("a@b.example", "company", "  ")


def test_hostile_attribute_value_round_trips_through_csv(store: KeboolaAccessStore) -> None:
    value = "x' OR '1'='1 -- \\ ž, \"quoted\"\nnext line"
    store.set_attribute("a@b.example", "company", value)
    assert store.attributes_for("a@b.example") == {"company": value}


# ---- parity with the SQLite store -------------------------------------------------------------


def test_seeded_store_decides_like_sqlite(seeded_store: KeboolaAccessStore, settings: Settings, tmp_path: Path) -> None:
    sqlite = AccessStore(tmp_path / "parity.sqlite", settings.providers)
    fill_store(settings, sqlite)

    assert seeded_store.list_apps() == sqlite.list_apps()
    assert seeded_store.list_users() == sqlite.list_users()
    assert seeded_store.list_attributes() == sqlite.list_attributes()
    strip = lambda gs: sorted((g.provider, g.external_id, g.name) for g in gs)  # noqa: E731 — group ids are random
    assert strip(seeded_store.list_groups()) == strip(sqlite.list_groups())

    fake = yaml.safe_load(settings.path(settings.require_gateway().fake_users_file).read_text(encoding="utf-8"))
    external = {key: gid for groups in fake["groups"].values() for key, gid in groups.items()}
    k_snap, s_snap = seeded_store.snapshot(), sqlite.snapshot()
    k_names = {g.group_id: g.name for g in seeded_store.list_groups()}
    s_names = {g.group_id: g.name for g in sqlite.list_groups()}

    def normalized(match: tuple[str, ...], names: dict[str, str]) -> tuple[str, ...]:
        return tuple(sorted(f"group:{names[m[6:]]}" if m.startswith("group:") else m for m in match))

    decisions = 0
    for user in [*fake["users"], {"email": "stranger@nowhere.example", "groups": ["all-employees"]}]:
        principal = Principal(user["email"], frozenset(external[g] for g in user["groups"]))
        for app_id in [*settings.apps, "unknown-app"]:
            k, s = decide(k_snap, principal, app_id), decide(s_snap, principal, app_id)
            assert (k.allowed, k.reason) == (s.allowed, s.reason), (user["email"], app_id)
            assert normalized(k.matched, k_names) == normalized(s.matched, s_names)
            decisions += 1
    assert decisions > 30
    # Sanity: the seed really produced a mix of outcomes.
    assert decide(k_snap, Principal(PETR, frozenset({SALES_MANAGERS})), "sales").allowed
    assert decide(k_snap, Principal(OLGA, frozenset({SALES_MANAGERS})), "sales").reason == "user_deactivated"


def test_fill_store_twice_is_stable(api: FakeStorageApi, seeded_store: KeboolaAccessStore, settings: Settings) -> None:
    before = {t: rows(api, t) for t in TABLE_COLUMNS}
    _reset_counters(api)
    fill_store(settings, seeded_store)
    assert {t: rows(api, t) for t in TABLE_COLUMNS} == before
    assert api.deletes == []


# ---- only changed rows are sent ----------------------------------------------------------------


def test_only_changed_rows_are_sent(api: FakeStorageApi, seeded_store: KeboolaAccessStore) -> None:
    _reset_counters(api)
    seeded_store.list_users()
    seeded_store.snapshot()
    assert api.imports == [] and api.deletes == []  # reads never write

    seeded_store.set_attribute(PETR, "company", "PHARMA_B")
    assert api.imports == [(f"{BUCKET}.user_attributes", 1)]
    assert api.deletes == []

    _reset_counters(api)
    seeded_store.set_attribute(PETR, "company", "PHARMA_B")  # no change: nothing sent
    assert api.imports == [] and api.deletes == []

    _reset_counters(api)
    seeded_store.delete_user(PETR)
    # One delete job per affected table, each with only Petr's keys; no upserts.
    assert api.imports == []
    assert dict(api.deletes) == {
        f"{BUCKET}.user_attributes": [f"{PETR}|company"],
        f"{BUCKET}.users": [PETR],
        # The seeded local group membership goes with the user.
        f"{BUCKET}.local_group_members": [f"emea-sales|{PETR}"],
    }


def test_rename_sends_one_job_per_table(api: FakeStorageApi, seeded_store: KeboolaAccessStore) -> None:
    seeded_store.grant("supply", "user", PETR, "test")
    _reset_counters(api)
    seeded_store.update_user(PETR, new_email="petr2@pharma-a.example", display_name="P", active=True)
    assert sorted(api.imports) == sorted([
        (f"{BUCKET}.users", 1), (f"{BUCKET}.app_grants", 1), (f"{BUCKET}.user_attributes", 1),
        (f"{BUCKET}.local_group_members", 1),
    ])
    assert sorted(t for t, _ in api.deletes) == sorted([
        f"{BUCKET}.users", f"{BUCKET}.app_grants", f"{BUCKET}.user_attributes", f"{BUCKET}.local_group_members",
    ])


# ---- robustness -----------------------------------------------------------------------------------


def _orphan_grant(api: FakeStorageApi) -> dict[str, str]:
    orphan = {
        "row_key": "ghost|user|a@b.example", "app_id": "ghost", "subject_type": "user",
        "subject_id": "a@b.example", "granted_by": "x", "granted_at": "2026-01-01T00:00:00+00:00",
    }
    api.tables[f"{BUCKET}.app_grants"].rows.append(orphan)
    return orphan


def test_orphan_grant_in_storage_is_ignored_on_read(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user("a@b.example", "A", True)
    store.grant("sales", "user", "a@b.example", "x")
    orphan = _orphan_grant(api)
    assert [g.app_id for g in store.list_grants()] == ["sales"]
    assert [g.app_id for g in store.snapshot().grants] == ["sales"]
    # The next write removes the orphan from Storage, so no later app can inherit it.
    store.set_attribute("a@b.example", "company", "PHARMA_A")
    assert orphan not in rows(api, "app_grants")
    assert [r["app_id"] for r in rows(api, "app_grants")] == ["sales"]


def test_orphan_grant_is_not_resurrected_by_recreating_the_app(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_user("a@b.example", "A", True)
    _orphan_grant(api)
    store.upsert_app(_app("ghost"))  # a new app that happens to reuse the id
    assert store.list_grants() == []


def test_failed_job_raises_and_store_reports_storage_truth(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user("a@b.example", "A", True)
    api.fail_job("import", table_contains="app_grants")
    with pytest.raises(StorageError, match="Injected job failure"):
        store.grant("sales", "user", "a@b.example", "x")
    # The failed change is not reported as applied: every read re-pulls Storage.
    assert store.list_grants() == []
    assert rows(api, "app_grants") == []
    # And the store recovers once Storage does.
    store.grant("sales", "user", "a@b.example", "x")
    assert [g.subject_id for g in store.list_grants()] == ["a@b.example"]


def test_read_failure_is_storage_error(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    api.fail_http("GET", "users/data-preview", status=500)
    with pytest.raises(StorageError, match="HTTP 500"):
        store.list_users()
    assert store.list_users() == []


def test_failed_rename_reports_error_and_not_the_new_email(api: FakeStorageApi, seeded_store: KeboolaAccessStore) -> None:
    api.fail_job("import", table_contains=".users")
    with pytest.raises(StorageError):
        seeded_store.update_user(PETR, new_email="petr2@pharma-a.example", display_name="P", active=True)
    assert "petr2@pharma-a.example" not in {u.email for u in seeded_store.list_users()}


def test_failed_rename_of_deactivated_user_does_not_fail_open(api: FakeStorageApi, seeded_store: KeboolaAccessStore) -> None:
    olga_groups = frozenset({SALES_MANAGERS})
    assert decide(seeded_store.snapshot(), Principal(OLGA, olga_groups), "sales").reason == "user_deactivated"
    api.fail_job("import", table_contains=".users")
    with pytest.raises(StorageError):
        seeded_store.update_user(OLGA, new_email="olga.new@pharma-a.example", display_name="Olga", active=False)
    snap = seeded_store.snapshot()
    # Upserts run before deletes, so the failed rename left Olga's (deactivated) row in place.
    assert decide(snap, Principal(OLGA, olga_groups), "sales").reason == "user_deactivated"
    assert "olga.new@pharma-a.example" not in snap.users


# ---- local groups -------------------------------------------------------------


def test_local_group_tables_are_created_with_the_others(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    assert api.tables[f"{BUCKET}.local_groups"].primary_key == ["local_group_id"]
    assert api.tables[f"{BUCKET}.local_group_members"].primary_key == ["row_key"]
    assert api.tables[f"{BUCKET}.local_group_members"].columns == ["row_key", "local_group_id", "email"]


def test_local_groups_are_pushed_to_storage(api: FakeStorageApi, seeded_store: KeboolaAccessStore) -> None:
    assert rows(api, "local_groups") == [
        {"local_group_id": "emea-sales", "name": "EMEA sales",
         "description": "Sales and finance people covering the EMEA region"}
    ]
    assert sorted(r["row_key"] for r in rows(api, "local_group_members")) == sorted(
        [f"emea-sales|{PETR}", "emea-sales|lucie.finance@pharma-a.example"]
    )


def test_local_group_lifecycle_in_storage(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user(PETR, "Petr", True)
    store.create_local_group("team", "Team", "desc")
    store.add_local_group_member("team", PETR)
    store.grant("sales", "local_group", "team", "test")
    assert rows(api, "local_group_members") == [{"row_key": f"team|{PETR}", "local_group_id": "team", "email": PETR}]
    assert store.snapshot().local_groups_of(PETR) == frozenset({"team"})
    assert decide(store.snapshot(), Principal(PETR, frozenset()), "sales").matched == ("local_group:team",)

    store.update_local_group("team", name="Team 2", description="")
    assert rows(api, "local_groups")[0]["name"] == "Team 2"

    store.delete_local_group("team")
    assert rows(api, "local_groups") == [] and rows(api, "local_group_members") == []
    assert rows(api, "app_grants") == []


def test_unregistered_member_rejected_and_nothing_sent(api: FakeStorageApi, store: KeboolaAccessStore) -> None:
    store.create_local_group("team", "Team")
    _reset_counters(api)
    with pytest.raises(StoreError, match="user must be registered first"):
        store.add_local_group_member("team", "ghost@x.example")
    assert api.imports == [] and api.deletes == []


def test_bucket_without_local_group_tables_reads_empty_and_gets_them_on_first_write(
    api: FakeStorageApi, settings: Settings
) -> None:
    kstore = KeboolaAccessStore(api.client(), BUCKET, settings.providers, read_cache_seconds=0)
    kstore.ensure_schema()
    for table in ("local_groups", "local_group_members"):
        del api.tables[f"{BUCKET}.{table}"]  # a bucket created before local groups existed
    assert kstore.list_local_groups() == [] and kstore.snapshot().local_groups == {}
    assert f"{BUCKET}.local_groups" not in api.tables  # reads never create tables
    kstore.create_local_group("team", "Team")
    assert [r["local_group_id"] for r in rows(api, "local_groups")] == ["team"]
    assert kstore.missing_tables() == []
