"""Layer 2: app gate decisions and the TTL cache."""

from __future__ import annotations

from pathlib import Path

import pytest

from kbc_access.config import Settings
from kbc_access.gate import (
    ALLOWED,
    APP_INACTIVE,
    NO_GRANT,
    UNKNOWN_APP,
    USER_DEACTIVATED,
    Gate,
    accessible_apps,
    decide,
)
from kbc_access.identity import Principal
from kbc_access.store import ACCESS_ALL_SIGNED_IN, AccessStore, App

FINANCE = "3f2b8c1e-7d4a-4e5b-9a61-2c8d0f4e1b7a"
SUPPLY = "5e6f7a8b-9c0d-4e1f-a2b3-c4d5e6f7a8b9"
PARTNER = "00g7pharmab0partner1"


@pytest.fixture
def store(settings: Settings, tmp_path: Path) -> AccessStore:
    s = AccessStore(tmp_path / "gate.sqlite", settings.providers)
    s.upsert_app(App("sales", "Sales", "u", "p", "c", "manual", True))
    s.upsert_app(App("supply", "Supply", "u", "p", "c", "manual", True))
    s.upsert_app(App("admin", "Admin", "u", "p", "c", "manual", True))
    s.upsert_app(App("off", "Off", "u", "p", "c", "manual", False))
    return s


def _p(email: str, *groups: str) -> Principal:
    return Principal(email, frozenset(groups))


def test_all_signed_in_app_needs_no_grant(store: AccessStore) -> None:
    store.upsert_app(App("everyone", "Everyone", "u", "p", "c", "manual", True, ACCESS_ALL_SIGNED_IN))
    d = decide(store.snapshot(), _p("someone@nowhere.example"), "everyone")
    assert (d.allowed, d.reason, d.matched) == (True, ALLOWED, ("access:all_signed_in",))
    # Other apps still need a grant.
    assert decide(store.snapshot(), _p("someone@nowhere.example"), "sales").reason == NO_GRANT


def test_all_signed_in_still_blocks_deactivated_users_and_inactive_apps(store: AccessStore) -> None:
    store.upsert_app(App("everyone", "Everyone", "u", "p", "c", "manual", True, ACCESS_ALL_SIGNED_IN))
    store.upsert_app(App("off-all", "Off", "u", "p", "c", "manual", False, ACCESS_ALL_SIGNED_IN))
    store.upsert_user("olga@a.example", "Olga", False)
    assert decide(store.snapshot(), _p("olga@a.example"), "everyone").reason == USER_DEACTIVATED
    assert decide(store.snapshot(), _p("jan@b.example"), "off-all").reason == APP_INACTIVE


def test_launcher_lists_all_signed_in_apps_for_everyone(store: AccessStore) -> None:
    store.upsert_app(App("everyone", "Everyone", "u", "p", "c", "manual", True, ACCESS_ALL_SIGNED_IN))
    assert [a.app_id for a in accessible_apps(store.snapshot(), _p("nobody@x.example"))] == ["everyone"]


def test_user_grant(store: AccessStore) -> None:
    store.upsert_user("jan@b.example", "Jan", True)
    store.grant("sales", "user", "jan@b.example", "x")
    d = decide(store.snapshot(), _p("jan@b.example"), "sales")
    assert (d.allowed, d.reason, d.matched, d.app_id) == (True, ALLOWED, ("user:jan@b.example",), "sales")


def test_group_grant(store: AccessStore) -> None:
    fin = store.create_group("entra", FINANCE, "finance")
    store.grant("sales", "group", fin.group_id, "x")
    d = decide(store.snapshot(), _p("lucie@a.example", FINANCE), "sales")
    assert d.allowed and d.matched == (f"group:{fin.group_id}",)


def test_union_of_user_and_group_grants(store: AccessStore) -> None:
    store.upsert_user("anna@a.example", "Anna", True)
    fin = store.create_group("entra", FINANCE, "finance")
    sup = store.create_group("entra", SUPPLY, "supply")
    store.grant("supply", "user", "anna@a.example", "x")
    store.grant("supply", "group", fin.group_id, "x")
    store.grant("supply", "group", sup.group_id, "x")
    d = decide(store.snapshot(), _p("anna@a.example", FINANCE, SUPPLY, "unrelated"), "supply")
    assert d.allowed
    assert d.matched == tuple(sorted([f"group:{fin.group_id}", f"group:{sup.group_id}", "user:anna@a.example"]))


def test_grant_on_other_app_does_not_leak(store: AccessStore) -> None:
    fin = store.create_group("entra", FINANCE, "finance")
    store.grant("sales", "group", fin.group_id, "x")
    d = decide(store.snapshot(), _p("lucie@a.example", FINANCE), "admin")
    assert (d.allowed, d.reason, d.matched) == (False, NO_GRANT, ())


def test_no_grant(store: AccessStore) -> None:
    store.upsert_user("tomas@a.example", "T", True)
    d = decide(store.snapshot(), _p("tomas@a.example", "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e"), "sales")
    assert (d.allowed, d.reason) == (False, NO_GRANT)


def test_unregistered_group_id_in_header_grants_nothing(store: AccessStore) -> None:
    # A group row must exist; carrying the external id alone is not enough.
    d = decide(store.snapshot(), _p("x@a.example", FINANCE), "sales")
    assert d.reason == NO_GRANT


def test_group_id_match_is_exact(store: AccessStore) -> None:
    fin = store.create_group("entra", FINANCE, "finance")
    store.grant("sales", "group", fin.group_id, "x")
    assert not decide(store.snapshot(), _p("x@a.example", FINANCE.upper()), "sales").allowed
    assert not decide(store.snapshot(), _p("x@a.example", fin.group_id), "sales").allowed  # internal id is not an IdP id


def test_unknown_app(store: AccessStore) -> None:
    store.upsert_user("jan@b.example", "Jan", True)
    d = decide(store.snapshot(), _p("jan@b.example"), "nope")
    assert (d.allowed, d.reason) == (False, UNKNOWN_APP)


def test_inactive_app_beats_grants(store: AccessStore) -> None:
    store.upsert_user("jan@b.example", "Jan", True)
    store.grant("off", "user", "jan@b.example", "x")
    d = decide(store.snapshot(), _p("jan@b.example"), "off")
    assert (d.allowed, d.reason, d.matched) == (False, APP_INACTIVE, ())


def test_deactivated_user_overrides_group_grants(store: AccessStore) -> None:
    fin = store.create_group("entra", FINANCE, "finance")
    store.grant("sales", "group", fin.group_id, "x")
    store.upsert_user("olga@a.example", "Olga", False)
    d = decide(store.snapshot(), _p("olga@a.example", FINANCE), "sales")
    assert (d.allowed, d.reason, d.matched) == (False, USER_DEACTIVATED, ())


def test_deactivated_user_overrides_user_grant(store: AccessStore) -> None:
    store.upsert_user("olga@a.example", "Olga", True)
    store.grant("sales", "user", "olga@a.example", "x")
    assert decide(store.snapshot(), _p("olga@a.example"), "sales").allowed
    store.upsert_user("olga@a.example", "Olga", False)
    assert decide(store.snapshot(), _p("olga@a.example"), "sales").reason == USER_DEACTIVATED


def test_user_without_user_row_can_enter_via_group(store: AccessStore) -> None:
    fin = store.create_group("entra", FINANCE, "finance")
    store.grant("sales", "group", fin.group_id, "x")
    assert decide(store.snapshot(), _p("new@a.example", FINANCE), "sales").allowed


def test_accessible_apps(store: AccessStore) -> None:
    fin = store.create_group("entra", FINANCE, "finance")
    store.grant("supply", "group", fin.group_id, "x")
    store.grant("sales", "group", fin.group_id, "x")
    store.grant("off", "group", fin.group_id, "x")
    apps = accessible_apps(store.snapshot(), _p("lucie@a.example", FINANCE))
    assert [a.app_id for a in apps] == ["sales", "supply"]  # sorted by name, inactive excluded
    assert accessible_apps(store.snapshot(), _p("nobody@a.example")) == []


def test_seeded_personas(runtime) -> None:  # type: ignore[no-untyped-def]
    gate = runtime.gate
    fin, sup, partner = FINANCE, SUPPLY, PARTNER
    sales_mgr, admins, everyone = "8a1d4e2f-5b6c-4d7e-9f80-1a2b3c4d5e6f", "c0a8f1d2-3b4e-4c5d-8e6f-7a8b9c0d1e2f", "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e"
    assert gate.check(_p("petr.sales@pharma-a.example", sales_mgr, everyone), "sales").allowed
    assert not gate.check(_p("petr.sales@pharma-a.example", sales_mgr, everyone), "supply").allowed
    assert gate.check(_p("lucie.finance@pharma-a.example", fin, everyone), "supply").allowed
    assert gate.check(_p("eva.supply@pharma-a.example", sup, everyone), "supply").allowed
    assert gate.check(_p("jan.partner@pharma-b.example", partner), "sales").matched == ("user:jan.partner@pharma-b.example",)
    assert gate.check(_p("anna.admin@pharma-a.example", admins, everyone), "admin").allowed
    assert gate.check(_p("tomas.nogrant@pharma-a.example", everyone), "sales").reason == NO_GRANT
    assert gate.check(_p("olga.left@pharma-a.example", sales_mgr, everyone), "sales").reason == USER_DEACTIVATED
    assert [a.app_id for a in gate.accessible(_p("lucie.finance@pharma-a.example", fin, everyone))] == ["sales", "supply"]


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_gate_ttl_cache_revocation_visible_only_after_ttl(store: AccessStore) -> None:
    store.upsert_user("jan@b.example", "Jan", True)
    store.grant("sales", "user", "jan@b.example", "x")
    clock = FakeClock()
    gate = Gate(store, ttl_seconds=5, clock=clock)
    jan = _p("jan@b.example")
    assert gate.check(jan, "sales").allowed
    store.revoke("sales", "user", "jan@b.example")
    clock.now += 4.9
    assert gate.check(jan, "sales").allowed  # still cached
    clock.now += 0.1  # exactly TTL elapsed
    assert gate.check(jan, "sales").reason == NO_GRANT


def test_gate_ttl_cache_new_grant_visible_after_ttl(store: AccessStore) -> None:
    clock = FakeClock()
    gate = Gate(store, ttl_seconds=5, clock=clock)
    jan = _p("jan@b.example")
    assert not gate.check(jan, "sales").allowed
    store.upsert_user("jan@b.example", "Jan", True)
    store.grant("sales", "user", "jan@b.example", "x")
    assert not gate.check(jan, "sales").allowed
    clock.now += 5
    assert gate.check(jan, "sales").allowed


def test_gate_snapshot_reused_within_ttl(store: AccessStore) -> None:
    clock = FakeClock()
    gate = Gate(store, ttl_seconds=5, clock=clock)
    first = gate.snapshot()
    clock.now += 1
    assert gate.snapshot() is first
    clock.now += 10
    assert gate.snapshot() is not first


def test_gate_zero_ttl_always_reloads(store: AccessStore) -> None:
    clock = FakeClock()
    gate = Gate(store, ttl_seconds=0, clock=clock)
    store.upsert_user("jan@b.example", "Jan", True)
    store.grant("sales", "user", "jan@b.example", "x")
    assert gate.check(_p("jan@b.example"), "sales").allowed
    store.revoke("sales", "user", "jan@b.example")
    assert not gate.check(_p("jan@b.example"), "sales").allowed


# ---- local groups ---------------------------------------------------------


def _team(store: AccessStore, *emails: str) -> None:
    store.create_local_group("team", "Team")
    for email in emails:
        store.upsert_user(email, email, True)
        store.add_local_group_member("team", email)


def test_local_group_grant_allows_members(store: AccessStore) -> None:
    _team(store, "jan@b.example")
    store.grant("sales", "local_group", "team", "x")
    d = decide(store.snapshot(), _p("jan@b.example"), "sales")
    assert (d.allowed, d.reason, d.matched) == (True, ALLOWED, ("local_group:team",))


def test_local_group_grant_denies_non_members(store: AccessStore) -> None:
    _team(store, "jan@b.example")
    store.upsert_user("tomas@b.example", "T", True)
    store.grant("sales", "local_group", "team", "x")
    d = decide(store.snapshot(), _p("tomas@b.example"), "sales")
    assert (d.allowed, d.reason, d.matched) == (False, NO_GRANT, ())
    # An unregistered email is no member either.
    assert not decide(store.snapshot(), _p("ghost@b.example"), "sales").allowed


def test_local_group_membership_comes_from_the_store_not_the_principal(store: AccessStore) -> None:
    _team(store, "jan@b.example")
    store.grant("sales", "local_group", "team", "x")
    forged = Principal("tomas@b.example", frozenset(), local_groups=frozenset({"team"}))
    assert not decide(store.snapshot(), forged, "sales").allowed


def test_local_group_ids_in_the_roles_header_grant_nothing(store: AccessStore) -> None:
    _team(store, "jan@b.example")
    store.grant("sales", "local_group", "team", "x")
    assert not decide(store.snapshot(), _p("tomas@b.example", "team"), "sales").allowed


def test_union_of_user_idp_group_and_local_group_grants(store: AccessStore) -> None:
    _team(store, "anna@a.example")
    fin = store.create_group("entra", FINANCE, "finance")
    store.grant("supply", "user", "anna@a.example", "x")
    store.grant("supply", "group", fin.group_id, "x")
    store.grant("supply", "local_group", "team", "x")
    d = decide(store.snapshot(), _p("anna@a.example", FINANCE), "supply")
    assert d.allowed
    assert d.matched == tuple(sorted([f"group:{fin.group_id}", "local_group:team", "user:anna@a.example"]))


def test_kill_switch_overrides_local_group_grant(store: AccessStore) -> None:
    _team(store, "olga@a.example")
    store.grant("sales", "local_group", "team", "x")
    store.upsert_user("olga@a.example", "Olga", False)
    d = decide(store.snapshot(), _p("olga@a.example"), "sales")
    assert (d.allowed, d.reason, d.matched) == (False, USER_DEACTIVATED, ())


def test_removed_member_loses_access_after_cache_expiry(store: AccessStore) -> None:
    _team(store, "jan@b.example")
    store.grant("sales", "local_group", "team", "x")
    now = [0.0]
    gate = Gate(store, ttl_seconds=10, clock=lambda: now[0])
    assert gate.check(_p("jan@b.example"), "sales").allowed
    store.remove_local_group_member("team", "jan@b.example")
    assert gate.check(_p("jan@b.example"), "sales").allowed  # cached
    now[0] = 11.0
    assert not gate.check(_p("jan@b.example"), "sales").allowed


def test_accessible_apps_includes_local_group_grants(store: AccessStore) -> None:
    _team(store, "jan@b.example")
    store.grant("sales", "local_group", "team", "x")
    assert [a.app_id for a in accessible_apps(store.snapshot(), _p("jan@b.example"))] == ["sales"]
