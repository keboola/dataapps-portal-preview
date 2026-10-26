"""Layer 2 — app gate: may this principal open this app?

Access is the union of grants to the user's email, to every IdP group the
principal carries and to every local group the user is a member of (resolved
from the snapshot by email) - unless the app is marked "all signed in", which
lets in anyone the IdP signed in without looking at grants. Everything else is a
denial, and every denial has a reason code so the audit log and the deny page can
say why.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import Protocol

from kbc_access.identity import Principal
from kbc_access.store import ACCESS_ALL_SIGNED_IN, AclSnapshot, App

# Reason codes (stable strings — they appear in audit lines).
ALLOWED = "allowed"
UNKNOWN_APP = "unknown_app"
APP_INACTIVE = "app_inactive"
USER_DEACTIVATED = "user_deactivated"
NO_GRANT = "no_grant"


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    app_id: str
    # "user:<email>" / "group:<group_id>" / "local_group:<local_group_id>" for each grant that matched,
    # or "access:all_signed_in" when the app needs no grant.
    matched: tuple[str, ...]


def decide(snapshot: AclSnapshot, principal: Principal, app_id: str) -> GateDecision:
    app = snapshot.apps.get(app_id)
    if app is None:
        return GateDecision(False, UNKNOWN_APP, app_id, ())
    if not app.active:
        return GateDecision(False, APP_INACTIVE, app_id, ())
    # A deactivated user row is a kill switch: it overrides group grants too.
    user = snapshot.users.get(principal.email)
    if user is not None and not user.active:
        return GateDecision(False, USER_DEACTIVATED, app_id, ())
    # The principal exists only because the apps-proxy signed it in, so that is all such an app needs.
    if app.access == ACCESS_ALL_SIGNED_IN:
        return GateDecision(True, ALLOWED, app_id, (f"access:{ACCESS_ALL_SIGNED_IN}",))

    member_of = {
        group.group_id
        for external_id in principal.groups
        for group in snapshot.groups_by_external_id.get(external_id, [])
    }
    local_member_of = snapshot.local_groups_of(principal.email)
    matched = tuple(
        sorted(
            f"{g.subject_type}:{g.subject_id}"
            for g in snapshot.grants
            if g.app_id == app_id
            and (
                (g.subject_type == "user" and g.subject_id == principal.email)
                or (g.subject_type == "group" and g.subject_id in member_of)
                or (g.subject_type == "local_group" and g.subject_id in local_member_of)
            )
        )
    )
    if not matched:
        return GateDecision(False, NO_GRANT, app_id, ())
    return GateDecision(True, ALLOWED, app_id, matched)


def accessible_apps(snapshot: AclSnapshot, principal: Principal) -> list[App]:
    """Apps the principal may open, for the launcher. Not a security boundary."""
    return sorted(
        (app for app in snapshot.apps.values() if decide(snapshot, principal, app.app_id).allowed),
        key=lambda a: a.name,
    )


class AclSource(Protocol):
    def snapshot(self) -> AclSnapshot: ...


class Gate:
    """Caches the ACL snapshot for `ttl_seconds` so each request is one dict lookup."""

    def __init__(self, store: AclSource, ttl_seconds: float, clock: Callable[[], float] = time.monotonic) -> None:
        self._store = store
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = Lock()
        self._snapshot: AclSnapshot | None = None
        self._loaded_at = 0.0

    def snapshot(self) -> AclSnapshot:
        with self._lock:
            now = self._clock()
            if self._snapshot is None or now - self._loaded_at >= self._ttl:
                self._snapshot = self._store.snapshot()
                self._loaded_at = now
            return self._snapshot

    def check(self, principal: Principal, app_id: str) -> GateDecision:
        return decide(self.snapshot(), principal, app_id)

    def accessible(self, principal: Principal) -> list[App]:
        return accessible_apps(self.snapshot(), principal)
