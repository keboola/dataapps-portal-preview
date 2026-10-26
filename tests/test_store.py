"""Access store: CRUD, validation, cascades and snapshots."""

from __future__ import annotations

from pathlib import Path

import pytest

from kbc_access.config import Settings
import sqlite3

from kbc_access.store import ACCESS_ALL_SIGNED_IN, ACCESS_GRANTS, AccessStore, App, StoreError

FINANCE = "3f2b8c1e-7d4a-4e5b-9a61-2c8d0f4e1b7a"
SUPPLY = "5e6f7a8b-9c0d-4e1f-a2b3-c4d5e6f7a8b9"
PARTNER = "00g7pharmab0partner1"


@pytest.fixture
def store(settings: Settings, tmp_path: Path) -> AccessStore:
    return AccessStore(tmp_path / "store.sqlite", settings.providers)


def _app(app_id: str = "sales", *, active: bool = True, name: str = "Sales") -> App:
    return App(app_id, name, f"https://{app_id}.example/", "123", f"cfg-{app_id}", "manual", active)


# ---- apps ---------------------------------------------------------------


def test_app_upsert_list_update_delete(store: AccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_app(_app("admin", name="Admin"))
    assert [a.app_id for a in store.list_apps()] == ["admin", "sales"]  # ordered by name
    store.upsert_app(_app("sales", active=False, name="Sales v2"))
    sales = next(a for a in store.list_apps() if a.app_id == "sales")
    assert sales.name == "Sales v2" and sales.active is False
    store.delete_app("sales")
    assert [a.app_id for a in store.list_apps()] == ["admin"]


@pytest.mark.parametrize("app_id", ["Sales", "", "-x", "a b", "x" * 65, "a/b"])
def test_app_id_validated(store: AccessStore, app_id: str) -> None:
    with pytest.raises(StoreError):
        store.upsert_app(_app(app_id))


def test_app_name_and_source_validated(store: AccessStore) -> None:
    with pytest.raises(StoreError):
        store.upsert_app(App("x", "  ", "u", "p", "c", "manual", True))
    with pytest.raises(StoreError):
        store.upsert_app(App("x", "X", "u", "p", "c", "imported", True))
    store.upsert_app(App("x", "X", "u", "p", "c", "discovered", True))


def test_app_access_defaults_to_grants_and_round_trips(store: AccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_app(App("all", "All", "u", "p", "c", "manual", True, ACCESS_ALL_SIGNED_IN))
    by_id = {a.app_id: a for a in store.list_apps()}
    assert by_id["sales"].access == ACCESS_GRANTS
    assert by_id["all"].access == ACCESS_ALL_SIGNED_IN
    assert store.snapshot().apps["all"].access == ACCESS_ALL_SIGNED_IN
    assert {r["app_id"]: r["access"] for r in store.dump_rows("apps")} == {"sales": "grants", "all": "all_signed_in"}


def test_app_access_validated(store: AccessStore) -> None:
    with pytest.raises(StoreError, match="Unknown app access 'public'"):
        store.upsert_app(App("x", "X", "u", "p", "c", "manual", True, "public"))


def test_load_rows_without_access_reads_as_grants(store: AccessStore) -> None:
    """Rows from a backend written before apps.access existed have no value for it."""
    store.load_rows("apps", [{"app_id": "old", "name": "Old", "url": "u", "project_id": "p", "config_id": "c",
                              "source": "discovered", "active": "1"}])
    assert store.list_apps()[0].access == ACCESS_GRANTS


def test_store_created_before_access_column_is_migrated(settings: Settings, tmp_path: Path) -> None:
    path = tmp_path / "old.sqlite"
    with sqlite3.connect(path) as conn:
        conn.execute(
            """CREATE TABLE apps (app_id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL,
               project_id TEXT NOT NULL, config_id TEXT NOT NULL,
               source TEXT NOT NULL CHECK (source IN ('manual', 'discovered')),
               active INTEGER NOT NULL CHECK (active IN (0, 1)))"""
        )
        conn.execute("INSERT INTO apps VALUES ('legacy', 'Legacy', 'u', 'p', 'c', 'manual', 1)")
    conn.close()
    store = AccessStore(path, settings.providers)
    assert store.list_apps()[0].access == ACCESS_GRANTS
    store.upsert_app(App("legacy", "Legacy", "u", "p", "c", "manual", True, ACCESS_ALL_SIGNED_IN))
    assert store.list_apps()[0].access == ACCESS_ALL_SIGNED_IN
    AccessStore(path, settings.providers)  # migrating twice is a no-op


def test_delete_app_cascades_grants(store: AccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user("a@b.example", "A", True)
    store.grant("sales", "user", "a@b.example", "admin@x.example")
    store.delete_app("sales")
    assert store.list_grants() == []


# ---- users --------------------------------------------------------------


def test_user_crud_and_lowercasing(store: AccessStore) -> None:
    store.upsert_user(" Petr.Sales@Pharma-A.Example ", "Petr", True)
    assert [(u.email, u.display_name, u.active) for u in store.list_users()] == [("petr.sales@pharma-a.example", "Petr", True)]
    store.upsert_user("petr.sales@pharma-a.example", "  ", False)
    user = store.list_users()[0]
    assert user.display_name == "petr.sales@pharma-a.example"  # blank name falls back to email
    assert user.active is False


@pytest.mark.parametrize("email", ["nope", "a@b", "a b@c.d", "@c.d", ""])
def test_user_email_validated(store: AccessStore, email: str) -> None:
    with pytest.raises(StoreError):
        store.upsert_user(email, "X", True)


def test_delete_user_cascades_grants_and_attributes(store: AccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user("a@b.example", "A", True)
    store.upsert_user("c@d.example", "C", True)
    store.grant("sales", "user", "a@b.example", "x")
    store.grant("sales", "user", "c@d.example", "x")
    store.set_attribute("a@b.example", "company", "PHARMA_A")
    store.set_attribute("c@d.example", "company", "PHARMA_B")
    store.delete_user("A@B.example")
    assert [u.email for u in store.list_users()] == ["c@d.example"]
    assert [g.subject_id for g in store.list_grants()] == ["c@d.example"]
    assert store.attributes_for("a@b.example") == {}
    assert store.attributes_for("c@d.example") == {"company": "PHARMA_B"}


# ---- groups -------------------------------------------------------------


@pytest.mark.parametrize(
    ("provider", "external_id"),
    [
        ("entra", FINANCE),
        ("entra", FINANCE.upper()),
        ("okta", PARTNER),
        ("okta", "00g1a2b3c4d5e6f7g8h9"),
    ],
)
def test_valid_group_ids(store: AccessStore, provider: str, external_id: str) -> None:
    group = store.create_group(provider, f"  {external_id} ", "G")
    assert group.external_id == external_id
    assert group.provider == provider
    assert len(group.group_id) == 12


@pytest.mark.parametrize(
    ("provider", "external_id"),
    [
        ("entra", "finance"),
        ("entra", FINANCE[:-1]),
        ("entra", FINANCE + "0"),
        ("entra", FINANCE.replace("-", "")),
        ("entra", "zf2b8c1e-7d4a-4e5b-9a61-2c8d0f4e1b7a"),
        ("entra", PARTNER),
        ("okta", "00g7pharmab0partner"),  # 19 chars
        ("okta", "00g7pharmab0partner12"),  # 21 chars
        ("okta", "01g7pharmab0partner1"),
        ("okta", "00g7pharma-0partner1"),
        ("okta", FINANCE),
        ("okta", "partner-pharma-b"),
        ("google", "anything"),
    ],
)
def test_invalid_group_ids(store: AccessStore, provider: str, external_id: str) -> None:
    with pytest.raises(StoreError):
        store.create_group(provider, external_id, "G")


def test_validate_group_id_message_has_example(store: AccessStore) -> None:
    with pytest.raises(StoreError, match="3f2b8c1e-7d4a-4e5b-9a61-2c8d0f4e1b7a"):
        store.validate_group_id("entra", "finance")


def test_group_name_required(store: AccessStore) -> None:
    with pytest.raises(StoreError):
        store.create_group("entra", FINANCE, "  ")


def test_duplicate_group_rejected(store: AccessStore) -> None:
    store.create_group("entra", FINANCE, "finance")
    with pytest.raises(StoreError, match="already exists"):
        store.create_group("entra", FINANCE, "finance again")
    assert len(store.list_groups()) == 1


def test_delete_group_cascades_grants(store: AccessStore) -> None:
    store.upsert_app(_app("sales"))
    fin = store.create_group("entra", FINANCE, "finance")
    sup = store.create_group("entra", SUPPLY, "supply")
    store.grant("sales", "group", fin.group_id, "x")
    store.grant("sales", "group", sup.group_id, "x")
    store.delete_group(fin.group_id)
    assert [g.name for g in store.list_groups()] == ["supply"]
    assert [g.subject_id for g in store.list_grants()] == [sup.group_id]


# ---- grants -------------------------------------------------------------


def test_grant_and_revoke(store: AccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user("a@b.example", "A", True)
    fin = store.create_group("entra", FINANCE, "finance")
    store.grant("sales", "user", " A@B.example ", "admin@x.example")
    store.grant("sales", "group", fin.group_id, "admin@x.example")
    store.grant("sales", "group", fin.group_id, "someone-else")  # idempotent
    grants = store.list_grants()
    assert [(g.subject_type, g.subject_id, g.granted_by) for g in grants] == [
        ("group", fin.group_id, "admin@x.example"),
        ("user", "a@b.example", "admin@x.example"),
    ]
    assert all(g.granted_at for g in grants)
    store.revoke("sales", "group", fin.group_id)
    store.revoke("sales", "user", "a@b.example")
    assert store.list_grants() == []


def test_revoke_user_is_case_insensitive_like_grant(store: AccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user("a@b.example", "A", True)
    store.grant("sales", "user", "A@B.example", "x")
    store.revoke("sales", "user", "A@B.example")
    assert store.list_grants() == []


def test_grant_to_unknown_subjects_rejected(store: AccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user("a@b.example", "A", True)
    fin = store.create_group("entra", FINANCE, "finance")
    with pytest.raises(StoreError, match="Unknown user"):
        store.grant("sales", "user", "ghost@b.example", "x")
    with pytest.raises(StoreError, match="Unknown group"):
        store.grant("sales", "group", "nosuchgroup", "x")
    with pytest.raises(StoreError, match="Unknown group"):
        # the external id is not the group id
        store.grant("sales", "group", FINANCE, "x")
    with pytest.raises(StoreError, match="Unknown app"):
        store.grant("nope", "user", "a@b.example", "x")
    with pytest.raises(StoreError, match="Unknown app"):
        store.grant("nope", "group", fin.group_id, "x")
    with pytest.raises(StoreError, match="Subject type"):
        store.grant("sales", "role", "a@b.example", "x")
    assert store.list_grants() == []


# ---- attributes ---------------------------------------------------------


def test_attributes_crud(store: AccessStore) -> None:
    store.set_attribute("A@B.example", "company", " PHARMA_A ")
    store.set_attribute("a@b.example", "branch_code", "B1")
    assert store.attributes_for("A@B.EXAMPLE") == {"company": "PHARMA_A", "branch_code": "B1"}
    store.set_attribute("a@b.example", "company", "PHARMA_B")
    assert store.attributes_for("a@b.example")["company"] == "PHARMA_B"
    assert store.list_attributes() == [("a@b.example", "branch_code", "B1"), ("a@b.example", "company", "PHARMA_B")]
    store.delete_attribute("A@b.example", "company")
    assert store.attributes_for("a@b.example") == {"branch_code": "B1"}


@pytest.mark.parametrize("key", ["Company", "1company", "company-name", "", "a" * 65, "company name"])
def test_attribute_key_validated(store: AccessStore, key: str) -> None:
    with pytest.raises(StoreError):
        store.set_attribute("a@b.example", key, "v")


@pytest.mark.parametrize("value", ["", "   "])
def test_attribute_value_required(store: AccessStore, value: str) -> None:
    with pytest.raises(StoreError):
        store.set_attribute("a@b.example", "company", value)


def test_attribute_value_stored_verbatim_even_if_hostile(store: AccessStore) -> None:
    value = "x' OR '1'='1 -- \\ ž"
    store.set_attribute("a@b.example", "company", value)
    assert store.attributes_for("a@b.example") == {"company": value}


# ---- snapshot -----------------------------------------------------------


def test_snapshot_contents(store: AccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_app(_app("admin", active=False))
    store.upsert_user("a@b.example", "A", False)
    fin = store.create_group("entra", FINANCE, "finance")
    store.grant("sales", "group", fin.group_id, "x")
    snap = store.snapshot()
    assert set(snap.apps) == {"sales", "admin"}
    assert snap.apps["admin"].active is False
    assert snap.users["a@b.example"].active is False
    assert snap.groups_by_external_id == {FINANCE: [fin]}
    assert [(g.app_id, g.subject_id) for g in snap.grants] == [("sales", fin.group_id)]


def test_snapshot_is_a_point_in_time_copy(store: AccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.upsert_user("a@b.example", "A", True)
    store.grant("sales", "user", "a@b.example", "x")
    before = store.snapshot()
    store.revoke("sales", "user", "a@b.example")
    store.delete_app("sales")
    assert len(before.grants) == 1 and "sales" in before.apps
    after = store.snapshot()
    assert after.grants == [] and after.apps == {}


def test_same_external_id_in_two_providers_is_two_groups(store: AccessStore, settings: Settings, tmp_path: Path) -> None:
    # Provider patterns differ, but the schema allows the same external id under two providers.
    from kbc_access.config import ProviderSettings

    providers = {
        **settings.providers,
        "other": ProviderSettings(label="Other", group_id_pattern=r"^.+$", example="x"),
    }
    s2 = AccessStore(tmp_path / "two.sqlite", providers)
    a = s2.create_group("entra", FINANCE, "a")
    b = s2.create_group("other", FINANCE, "b")
    assert {g.group_id for g in s2.snapshot().groups_by_external_id[FINANCE]} == {a.group_id, b.group_id}


def test_store_persists_across_instances(store: AccessStore, settings: Settings, tmp_path: Path) -> None:
    store.upsert_user("a@b.example", "A", True)
    again = AccessStore(tmp_path / "store.sqlite", settings.providers)
    assert [u.email for u in again.list_users()] == ["a@b.example"]


# ---- local groups ---------------------------------------------------------


def _store_with_user(store: AccessStore, email: str = "a@b.example") -> None:
    store.upsert_user(email, "A", True)


def test_local_group_create_rename_list_delete(store: AccessStore) -> None:
    group = store.create_local_group("emea-sales", " EMEA sales ", " Sales in EMEA ")
    assert (group.local_group_id, group.name, group.description) == ("emea-sales", "EMEA sales", "Sales in EMEA")
    store.create_local_group("a_team", "A team")
    assert [g.local_group_id for g in store.list_local_groups()] == ["a_team", "emea-sales"]  # ordered by name
    renamed = store.update_local_group("emea-sales", name="EMEA", description="")
    assert (renamed.name, renamed.description) == ("EMEA", "")
    store.delete_local_group("emea-sales")
    assert [g.local_group_id for g in store.list_local_groups()] == ["a_team"]


def test_local_group_duplicate_and_unknown(store: AccessStore) -> None:
    store.create_local_group("team", "Team")
    with pytest.raises(StoreError, match="already exists"):
        store.create_local_group("team", "Other")
    with pytest.raises(StoreError, match="Unknown local group"):
        store.update_local_group("nope", name="x")
    with pytest.raises(StoreError, match="name is required"):
        store.create_local_group("blank", "  ")


@pytest.mark.parametrize("local_group_id", ["", "Team", "a b", "a/b", "a.b", "x" * 65, "ž"])
def test_local_group_slug_validated(store: AccessStore, local_group_id: str) -> None:
    with pytest.raises(StoreError, match="Local group ID"):
        store.create_local_group(local_group_id, "Team")


@pytest.mark.parametrize("local_group_id", ["a", "0", "-", "_", "x" * 64, "a-b_c9"])
def test_local_group_valid_slugs(store: AccessStore, local_group_id: str) -> None:
    assert store.create_local_group(local_group_id, "Team").local_group_id == local_group_id


def test_local_group_members_add_remove_idempotent(store: AccessStore) -> None:
    store.create_local_group("team", "Team")
    _store_with_user(store, "a@b.example")
    _store_with_user(store, "c@d.example")
    store.add_local_group_member("team", "A@B.example")
    store.add_local_group_member("team", "a@b.example")  # idempotent
    store.add_local_group_member("team", "c@d.example")
    assert store.list_local_group_members() == {"team": ["a@b.example", "c@d.example"]}
    assert [g.local_group_id for g in store.local_groups_of("a@b.example")] == ["team"]
    store.remove_local_group_member("team", "a@b.example")
    store.remove_local_group_member("team", "a@b.example")  # removing a non-member is a no-op
    assert store.list_local_group_members() == {"team": ["c@d.example"]}


def test_unregistered_email_rejected_as_member(store: AccessStore) -> None:
    store.create_local_group("team", "Team")
    with pytest.raises(StoreError, match="user must be registered first"):
        store.add_local_group_member("team", "ghost@b.example")
    assert store.list_local_group_members() == {"team": []}


def test_member_of_unknown_local_group_rejected(store: AccessStore) -> None:
    _store_with_user(store)
    with pytest.raises(StoreError, match="Unknown local group"):
        store.add_local_group_member("nope", "a@b.example")


def test_deleting_user_removes_memberships(store: AccessStore) -> None:
    store.create_local_group("team", "Team")
    _store_with_user(store)
    store.add_local_group_member("team", "a@b.example")
    store.delete_user("a@b.example")
    assert store.list_local_group_members() == {"team": []}
    assert store.snapshot().local_groups_of("a@b.example") == frozenset()


def test_renaming_user_carries_memberships(store: AccessStore) -> None:
    store.create_local_group("team", "Team")
    _store_with_user(store)
    store.add_local_group_member("team", "a@b.example")
    store.update_user("a@b.example", new_email="new@b.example", display_name="A", active=True)
    assert store.list_local_group_members() == {"team": ["new@b.example"]}


def test_deactivating_user_keeps_memberships(store: AccessStore) -> None:
    store.create_local_group("team", "Team")
    _store_with_user(store)
    store.add_local_group_member("team", "a@b.example")
    store.upsert_user("a@b.example", "A", False)
    assert store.list_local_group_members() == {"team": ["a@b.example"]}


def test_deleting_local_group_removes_memberships_and_grants(store: AccessStore) -> None:
    store.upsert_app(_app("sales"))
    store.create_local_group("team", "Team")
    store.create_local_group("other", "Other")
    _store_with_user(store)
    store.add_local_group_member("team", "a@b.example")
    store.add_local_group_member("other", "a@b.example")
    store.grant("sales", "local_group", "team", "admin@x.example")
    store.grant("sales", "local_group", "other", "admin@x.example")
    store.delete_local_group("team")
    assert store.list_local_group_members() == {"other": ["a@b.example"]}
    assert [(g.subject_type, g.subject_id) for g in store.list_grants()] == [("local_group", "other")]


def test_grant_to_unknown_local_group_rejected(store: AccessStore) -> None:
    store.upsert_app(_app("sales"))
    with pytest.raises(StoreError, match="Unknown local group"):
        store.grant("sales", "local_group", "nope", "x")
    store.create_local_group("team", "Team")
    store.grant("sales", "local_group", "team", "x")
    store.grant("sales", "local_group", "team", "x")  # idempotent
    assert len(store.list_grants()) == 1


def test_local_group_id_is_its_own_namespace(store: AccessStore) -> None:
    # An IdP group and a local group may share a name without sharing grants.
    store.upsert_app(_app("sales"))
    idp = store.create_group("entra", FINANCE, "finance")
    store.create_local_group(idp.group_id, "Same id as an IdP group")
    store.grant("sales", "local_group", idp.group_id, "x")
    assert [(g.subject_type, g.subject_id) for g in store.list_grants()] == [("local_group", idp.group_id)]


def test_snapshot_carries_local_groups_and_members(store: AccessStore) -> None:
    store.create_local_group("team", "Team", "desc")
    store.create_local_group("empty", "Empty")
    _store_with_user(store)
    store.add_local_group_member("team", "a@b.example")
    snapshot = store.snapshot()
    assert set(snapshot.local_groups) == {"team", "empty"}
    assert snapshot.local_groups["team"].description == "desc"
    assert snapshot.local_group_members == {"a@b.example": frozenset({"team"})}
    assert snapshot.local_groups_of("A@B.example") == frozenset({"team"})
    assert snapshot.local_groups_of("nobody@b.example") == frozenset()


def test_dump_and_load_rows_roundtrip_local_group_tables(store: AccessStore, settings: Settings, tmp_path: Path) -> None:
    store.create_local_group("team", "Team", "desc")
    _store_with_user(store)
    store.add_local_group_member("team", "a@b.example")
    other = AccessStore(tmp_path / "other.sqlite", settings.providers)
    for table in ("local_groups", "local_group_members"):
        other.load_rows(table, store.dump_rows(table))
    assert other.list_local_groups() == store.list_local_groups()
    assert other.list_local_group_members() == {"team": ["a@b.example"]}


def test_old_store_without_local_group_support_is_upgraded_in_place(settings: Settings, tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "old.sqlite"
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE apps (app_id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, project_id TEXT NOT NULL,
                config_id TEXT NOT NULL, source TEXT NOT NULL, active INTEGER NOT NULL);
            CREATE TABLE app_grants (
                app_id TEXT NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
                subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'group')),
                subject_id TEXT NOT NULL, granted_by TEXT NOT NULL, granted_at TEXT NOT NULL,
                PRIMARY KEY (app_id, subject_type, subject_id));
            INSERT INTO apps VALUES ('sales', 'Sales', 'u', 'p', 'c', 'manual', 1);
            INSERT INTO app_grants VALUES ('sales', 'user', 'a@b.example', 'seed', '2026-01-01T00:00:00+00:00');
            """
        )
    upgraded = AccessStore(path, settings.providers)
    upgraded.create_local_group("team", "Team")
    upgraded.grant("sales", "local_group", "team", "x")
    assert {(g.subject_type, g.subject_id) for g in upgraded.list_grants()} == {
        ("user", "a@b.example"), ("local_group", "team"),
    }
    AccessStore(path, settings.providers)  # a second open leaves the upgraded schema alone
