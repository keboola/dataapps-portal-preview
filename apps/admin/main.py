"""Access admin — the Data App where an administrator decides who may open which app.

The app is a React single-page frontend (apps/admin/frontend, built to
frontend/dist) on top of a JSON API under /api. The API covers: an overview with
an access matrix, an access simulator, apps, discovery (this project's Data
Apps), users with their attributes, IdP groups (validated by provider templates),
local groups (suite-defined sets of registered users), the dataset security editor (row access lines, column masks and a "Test as" preview, see apps/admin/datasets.py), grants, and the audit log. Every /api route depends on `access.require`, so only
principals granted the `admin` app (the data-app-admins group in the seed) get
any data; the built shell (index.html + assets) is served without identity
because it carries none.

Every mutating endpoint calls the store, writes one `admin` audit line with an
identifier-only target, and answers `{"message": ...}`; a rejected change
answers `{"detail": ...}` with a 4xx status and leaves the store untouched.

CSRF: every non-GET /api request must carry the `kbc_access.web.CSRF_HEADER`
header or is refused with 403 before anything runs. A browser attaches a custom
header to a cross-origin request only after a CORS preflight, which this app
never allows, so a forged form or cross-site fetch cannot change access.

Discovery scans only the project the app runs in, with the Storage token the
app already has (see kbc_access.discovery). The import step does not trust the
submitted items: it scans again and imports only apps that really exist, with
the name and app ID the administrator confirmed.
"""

from __future__ import annotations

import re
from dataclasses import asdict
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from apps.admin.datasets import register_dataset_routes
from kbc_access.config import Settings
from kbc_access.discovery import DiscoveredApp, DiscoveryError, discover
from kbc_access.gate import GateDecision, decide
from kbc_access.identity import Principal
from kbc_access.store import ACCESS_GRANTS, SUBJECT_TYPES, App, Group, LocalGroup, StoreError
from kbc_access.web import Access, Runtime, build_runtime, install, mount_spa, require_csrf_header

APP_ID = "admin"
HERE = Path(__file__).parent
FRONTEND_DIST = HERE / "frontend" / "dist"
AUDIT_EVENTS = ("gate", "query", "admin")
REDACTED = "[redacted]"
DISCOVERY_UNAVAILABLE = "Discovery is available only when the admin app runs in Keboola."
# Characters the store's app_id pattern does not allow; replaced when deriving
# an app_id for a discovered app.
_APP_ID_INVALID = re.compile(r"[^a-z0-9_-]+")


# ---- request bodies ------------------------------------------------------


class SimulateIn(BaseModel):
    email: str = ""
    groups: list[str] = []
    extra: str = ""


class AppIn(BaseModel):
    app_id: str
    name: str
    url: str = ""
    project_id: str = ""
    config_id: str = ""
    active: bool = False
    # "grants" or "all_signed_in"; left out, an edit keeps the app's current value.
    access: str | None = None


class ImportItem(BaseModel):
    ds_app_id: str
    # Empty means "use what the scan suggested".
    local_id: str = ""
    name: str = ""


class ImportIn(BaseModel):
    items: list[ImportItem] = []


class UserIn(BaseModel):
    email: str
    display_name: str = ""


class UserEditIn(BaseModel):
    new_email: str
    display_name: str = ""
    active: bool = False
    app_ids: list[str] = []


class AttributeIn(BaseModel):
    value: str


class GroupIn(BaseModel):
    provider: str
    external_id: str
    name: str


class GroupEditIn(GroupIn):
    app_ids: list[str] = []


class LocalGroupIn(BaseModel):
    local_group_id: str
    name: str
    description: str = ""


class LocalGroupEditIn(BaseModel):
    name: str
    description: str = ""


class GrantIn(BaseModel):
    app_id: str
    subject_type: str
    subject_id: str


# ---- helpers ---------------------------------------------------------------


def suggested_app_id(slug: str, ds_app_id: str, taken: set[str]) -> str:
    """Readable local app_id for a discovered app: its slug, or slug-<id> if the slug is taken."""
    base = _APP_ID_INVALID.sub("-", (slug or f"app-{ds_app_id}").lower()).strip("-_") or f"app-{ds_app_id}"
    return base if base not in taken else f"{base}-{ds_app_id}"


def _redact(message: str, secret: str) -> str:
    return message.replace(secret, REDACTED) if secret else message


def default_discovery_source(settings: Settings) -> tuple[str, str] | None:
    """(stack URL, Storage token) when the app runs in Keboola; None locally."""
    if settings.store.backend == "keboola" and settings.store.keboola and settings.secrets.kbc_token:
        return settings.store.keboola.stack_url, settings.secrets.kbc_token
    return None


def _parse_groups(selected: list[str], extra: str) -> frozenset[str]:
    """Group identifiers for the simulator: selected external IDs plus free-typed ones."""
    typed = [part.strip() for part in re.split(r"[,\s]+", extra) if part.strip()]
    return frozenset([*selected, *typed])


def _decision(decision: GateDecision) -> dict[str, object]:
    return {"allowed": decision.allowed, "reason": decision.reason, "matched": list(decision.matched)}


def _fail(status_code: int, detail: str) -> HTTPException:
    """An API error: `{"detail": detail}` with `status_code`."""
    return HTTPException(status_code=status_code, detail=detail)


def create_app(
    runtime: Runtime,
    discovery_transport: httpx.BaseTransport | None = None,
    discovery_source: tuple[str, str] | None = None,
    frontend_dist: Path | None = None,
) -> FastAPI:
    """Build the admin app: the JSON API plus the built frontend from `frontend_dist`.

    Discovery uses `discovery_source` (stack URL, Storage token), by default the
    app's own Keboola store settings; locally there is none and the API says so.
    `discovery_transport` lets tests route those calls in-process.
    """
    app = FastAPI(title=runtime.settings.apps[APP_ID].name)
    access: Access = install(app, runtime, app_id=APP_ID, templates_dir=None)
    store = runtime.store
    audit = runtime.audit
    settings = runtime.settings
    # The gate runs first, then the CSRF check; endpoints re-declare access.require
    # to get the principal (FastAPI resolves it once per request).
    api = APIRouter(prefix="/api", dependencies=[Depends(access.require), Depends(require_csrf_header)])

    def _apps_by_id() -> dict[str, App]:
        return {a.app_id: a for a in store.list_apps()}

    def _providers() -> dict[str, dict[str, str]]:
        return {key: p.model_dump() for key, p in store.providers.items()}

    def _local_group_dict(group: LocalGroup, members: list[str]) -> dict[str, object]:
        return {**asdict(group), "members": members, "member_count": len(members)}

    def _local_groups_payload() -> list[dict[str, object]]:
        members = store.list_local_group_members()
        return [_local_group_dict(g, members.get(g.local_group_id, [])) for g in store.list_local_groups()]

    # ---- session ---------------------------------------------------------

    @api.get("/session")
    def session(principal: Principal = Depends(access.require)) -> dict[str, object]:
        return {
            "user": {"email": principal.email, "groups": sorted(principal.groups)},
            "app_name": settings.apps[APP_ID].name,
            "launcher_url": settings.app_url("launcher"),
            "switch_user_path": settings.ui.switch_user_path,
        }

    # ---- overview + access simulator ------------------------------------

    @api.get("/overview")
    def overview() -> dict[str, object]:
        snapshot = store.snapshot()
        apps = sorted(snapshot.apps.values(), key=lambda a: a.name)
        users = store.list_users()
        groups = store.list_groups()
        grants = store.list_grants()
        local_groups = _local_groups_payload()
        # User-level matrix: IdP groups are not stored, so each user is checked
        # with no groups — this shows exactly what the user grants give.
        user_matrix = {
            u.email: {
                a.app_id: _decision(decide(snapshot, Principal(email=u.email, groups=frozenset()), a.app_id))
                for a in apps
            }
            for u in users
        }
        # Group-level matrix: which apps each group is granted.
        group_grants = {
            g.group_id: sorted(gr.app_id for gr in grants if gr.subject_type == "group" and gr.subject_id == g.group_id)
            for g in groups
        }
        local_group_grants = {
            g["local_group_id"]: sorted(
                gr.app_id for gr in grants if gr.subject_type == "local_group" and gr.subject_id == g["local_group_id"]
            )
            for g in local_groups
        }
        return {
            "counts": {
                "apps": len(apps),
                "users": len(users),
                "groups": len(groups),
                "local_groups": len(local_groups),
                "grants": len(grants),
                "attributes": len(store.list_attributes()),
            },
            "apps": [asdict(a) for a in apps],
            "users": [asdict(u) for u in users],
            "groups": [asdict(g) for g in groups],
            "user_matrix": user_matrix,
            "group_grants": group_grants,
            "local_groups": local_groups,
            "local_group_grants": local_group_grants,
        }

    @api.post("/simulate")
    def simulate(body: SimulateIn) -> dict[str, object]:
        email = body.email.strip().lower()
        if not email or "@" not in email:
            raise _fail(400, "Enter the email of the principal to check.")
        snapshot = store.snapshot()
        apps = sorted(snapshot.apps.values(), key=lambda a: a.name)
        groups = _parse_groups(body.groups, body.extra)
        by_external = {g.external_id: g for g in store.list_groups()}
        # Local groups are resolved from the store by email, like for a real request.
        local_groups = snapshot.local_groups_of(email)
        principal = Principal(email=email, groups=groups, local_groups=local_groups)
        return {
            "email": email,
            "local_groups": [
                {"local_group_id": i, "name": snapshot.local_groups[i].name} for i in sorted(local_groups)
            ],
            "groups": [
                {"external_id": gid, "name": by_external[gid].name if gid in by_external else None}
                for gid in sorted(groups)
            ],
            "results": [{"app": asdict(a), "decision": _decision(decide(snapshot, principal, a.app_id))} for a in apps],
        }

    # ---- apps ------------------------------------------------------------

    @api.get("/apps")
    def list_apps() -> dict[str, object]:
        return {"apps": [asdict(a) for a in store.list_apps()]}

    @api.post("/apps")
    def save_app(body: AppIn, principal: Principal = Depends(access.require)) -> dict[str, object]:
        app_id = body.app_id.strip()
        existing = _apps_by_id().get(app_id)
        # Editing keeps the app's origin; anything created here is manual.
        source = existing.source if existing else "manual"
        app_access = body.access if body.access is not None else (existing.access if existing else ACCESS_GRANTS)
        try:
            store.upsert_app(
                App(app_id, body.name, body.url.strip(), body.project_id.strip(), body.config_id.strip(), source,
                    body.active, app_access.strip())
            )
        except StoreError as exc:
            raise _fail(400, str(exc)) from exc
        audit.admin(email=principal.email, action="app_update" if existing else "app_create", target=app_id)
        return {"message": f"App '{app_id}' saved."}

    @api.post("/apps/{app_id}/toggle")
    def toggle_app(app_id: str, principal: Principal = Depends(access.require)) -> dict[str, object]:
        current = _apps_by_id().get(app_id)
        if current is None:
            raise _fail(404, f"Unknown app '{app_id}'.")
        store.upsert_app(
            App(current.app_id, current.name, current.url, current.project_id, current.config_id,
                current.source, not current.active, current.access)
        )
        audit.admin(email=principal.email, action="app_activate" if not current.active else "app_deactivate", target=app_id)
        return {"message": f"App '{app_id}' {'activated' if not current.active else 'deactivated'}."}

    @api.delete("/apps/{app_id}")
    def delete_app(app_id: str, principal: Principal = Depends(access.require)) -> dict[str, object]:
        if app_id not in _apps_by_id():
            raise _fail(404, f"Unknown app '{app_id}'.")
        store.delete_app(app_id)
        audit.admin(email=principal.email, action="app_delete", target=app_id)
        return {"message": f"App '{app_id}' deleted with its grants."}

    # ---- discovery -------------------------------------------------------

    source = discovery_source or default_discovery_source(settings)

    def scan() -> list[DiscoveredApp]:
        assert source is not None
        stack_url, token = source
        return discover(
            stack_url, token,
            component_id=settings.discovery.data_apps_component_id,
            timeout_seconds=settings.discovery.http_timeout_seconds,
            transport=discovery_transport,
        )

    def classify(found: list[DiscoveredApp]) -> list[tuple[DiscoveredApp, str, str]]:
        """(app, status, local_id): what is already registered (by config or URL) and the suite's own launcher."""
        registered = store.list_apps()
        by_config = {a.config_id: a for a in registered if a.config_id}
        by_url = {a.url.rstrip("/"): a for a in registered if a.url}
        launcher_url = settings.app_url("launcher").rstrip("/") if "launcher" in settings.apps else ""
        taken = {a.app_id for a in registered}
        rows: list[tuple[DiscoveredApp, str, str]] = []
        for d in found:
            match = by_config.get(d.config_id) or by_url.get(d.url.rstrip("/"))
            status = ("registered" if match else "launcher" if d.url and d.url.rstrip("/") == launcher_url
                      else "not_deployed" if not d.url else "new")
            local_id = match.app_id if match else suggested_app_id(d.slug, d.app_id, taken)
            if status == "new":
                taken.add(local_id)
            rows.append((d, status, local_id))
        return rows

    @api.get("/discovery")
    def discovery_status() -> dict[str, object]:
        return {"available": source is not None}

    @api.post("/discovery/scan")
    def run_discovery(principal: Principal = Depends(access.require)) -> dict[str, object]:
        if source is None:
            raise _fail(400, DISCOVERY_UNAVAILABLE)
        try:
            rows = classify(scan())
        except (DiscoveryError, httpx.HTTPError, ValueError) as exc:
            audit.admin(email=principal.email, action="discovery_failed", target="project")
            raise _fail(502, _redact(f"Discovery failed: {exc}", source[1])) from exc
        audit.admin(email=principal.email, action="discovery_run", target="project")
        return {
            "results": [
                {
                    "ds_app_id": d.app_id, "config_id": d.config_id, "project_id": d.project_id, "name": d.name,
                    "name_source": d.name_source, "slug": d.slug, "url": d.url, "state": d.state,
                    "status": status, "local_id": local_id, "auth_mode": d.auth_mode,
                    "auth_providers": [
                        {"id": p.provider_id, "type": p.type, "issuer_url": p.issuer_url} for p in d.auth_providers
                    ],
                }
                for d, status, local_id in rows
            ]
        }

    @api.post("/discovery/import")
    def import_discovered(body: ImportIn, principal: Principal = Depends(access.require)) -> dict[str, object]:
        if source is None:
            raise _fail(400, DISCOVERY_UNAVAILABLE)
        if not body.items:
            raise _fail(400, "Select at least one discovered app to import.")
        try:
            # Scan again: import only apps that really exist in this project right now.
            current = {d.app_id: (d, status, local_id) for d, status, local_id in classify(scan())}
        except (DiscoveryError, httpx.HTTPError, ValueError) as exc:
            raise _fail(502, _redact(f"Discovery failed: {exc}", source[1])) from exc
        imported: list[str] = []
        problems: list[str] = []
        for item in body.items:
            row = current.get(item.ds_app_id)
            if row is None:
                problems.append(f"{item.ds_app_id}: no longer in this project")
                continue
            found, status, suggested = row
            if status != "new":
                problems.append(f"{found.name}: {status.replace('_', ' ')}")
                continue
            local_id = (item.local_id or suggested).strip()
            name = (item.name or found.name).strip()
            try:
                store.upsert_app(App(local_id, name, found.url, found.project_id, found.config_id, "discovered", True))
            except StoreError as exc:
                problems.append(f"{name}: {exc}")
                continue
            audit.admin(email=principal.email, action="app_import", target=local_id)
            imported.append(local_id)
        ok = f"Imported {len(imported)} app(s): {', '.join(imported)}. Nobody can open them until you grant access." if imported else None
        err = "Not imported: " + "; ".join(problems) if problems else None
        return {"message": ok, "error": err}

    # ---- users + attributes ----------------------------------------------

    def _known_user(email: str) -> str:
        """`email` normalized, or a 404 when no such user exists."""
        normalized = email.strip().lower()
        if normalized not in {u.email for u in store.list_users()}:
            raise _fail(404, f"Unknown user '{normalized}'.")
        return normalized

    def _granted_apps(subject_type: str, subject_id: str) -> list[str]:
        return sorted(
            {g.app_id for g in store.list_grants() if g.subject_type == subject_type and g.subject_id == subject_id}
        )

    def _apply_app_grants(principal: Principal, subject_type: str, subject_id: str, app_ids: list[str]) -> str:
        known = set(_apps_by_id())
        added, removed = store.set_app_grants(subject_type, subject_id, set(app_ids) & known, principal.email)
        for app_id in sorted(added):
            audit.admin(email=principal.email, action="grant", target=f"{app_id}:{subject_type}:{subject_id}")
        for app_id in sorted(removed):
            audit.admin(email=principal.email, action="revoke", target=f"{app_id}:{subject_type}:{subject_id}")
        return f"{len(added)} app(s) granted, {len(removed)} revoked"

    @api.get("/users")
    def list_users() -> dict[str, object]:
        attributes: dict[str, dict[str, str]] = {}
        for email, key, value in store.list_attributes():
            attributes.setdefault(email, {})[key] = value
        return {"users": [{**asdict(u), "attributes": attributes.get(u.email, {})} for u in store.list_users()]}

    @api.post("/users")
    def create_user(body: UserIn, principal: Principal = Depends(access.require)) -> dict[str, object]:
        normalized = body.email.strip().lower()
        if normalized in {u.email for u in store.list_users()}:
            raise _fail(409, f"User '{normalized}' already exists.")
        try:
            store.upsert_user(normalized, body.display_name, True)
        except StoreError as exc:
            raise _fail(400, str(exc)) from exc
        audit.admin(email=principal.email, action="user_create", target=normalized)
        return {"message": f"User '{normalized}' created."}

    @api.post("/users/{email}/toggle")
    def toggle_user(email: str, principal: Principal = Depends(access.require)) -> dict[str, object]:
        current = {u.email: u for u in store.list_users()}.get(email.strip().lower())
        if current is None:
            raise _fail(404, f"Unknown user '{email}'.")
        store.upsert_user(current.email, current.display_name, not current.active)
        audit.admin(
            email=principal.email, action="user_activate" if not current.active else "user_deactivate",
            target=current.email,
        )
        return {"message": f"User '{current.email}' {'activated' if not current.active else 'deactivated'}."}

    @api.delete("/users/{email}")
    def delete_user(email: str, principal: Principal = Depends(access.require)) -> dict[str, object]:
        normalized = _known_user(email)
        store.delete_user(normalized)
        audit.admin(email=principal.email, action="user_delete", target=normalized)
        return {"message": f"User '{normalized}' deleted with their grants and attributes."}

    @api.get("/users/{email}")
    def get_user(email: str) -> dict[str, object]:
        normalized = _known_user(email)
        user = {u.email: u for u in store.list_users()}[normalized]
        return {
            "user": asdict(user),
            "attributes": dict(sorted(store.attributes_for(normalized).items())),
            "apps": [asdict(a) for a in store.list_apps()],
            "granted": _granted_apps("user", normalized),
            "local_groups": [
                {"local_group_id": g.local_group_id, "name": g.name} for g in store.local_groups_of(normalized)
            ],
        }

    @api.put("/users/{email}")
    def edit_user(email: str, body: UserEditIn, principal: Principal = Depends(access.require)) -> dict[str, object]:
        email = _known_user(email)
        try:
            saved = store.update_user(email, new_email=body.new_email, display_name=body.display_name, active=body.active)
        except StoreError as exc:
            raise _fail(400, str(exc)) from exc
        audit.admin(email=principal.email, action="user_update", target=saved)
        if saved != email:
            audit.admin(email=principal.email, action="user_rename", target=f"{email}->{saved}")
        summary = _apply_app_grants(principal, "user", saved, body.app_ids)
        return {"message": f"User '{saved}' saved; {summary}.", "email": saved}

    @api.put("/users/{email}/attributes/{key}")
    def set_attribute(
        email: str, key: str, body: AttributeIn, principal: Principal = Depends(access.require)
    ) -> dict[str, object]:
        normalized = _known_user(email)
        key = key.strip()
        try:
            store.set_attribute(normalized, key, body.value)
        except StoreError as exc:
            raise _fail(400, str(exc)) from exc
        # Attribute values feed row-level security: the audit target is the key only.
        audit.admin(email=principal.email, action="attribute_set", target=f"{normalized}:{key}")
        return {"message": f"Attribute '{key}' set for '{normalized}'."}

    @api.delete("/users/{email}/attributes/{key}")
    def delete_attribute(email: str, key: str, principal: Principal = Depends(access.require)) -> dict[str, object]:
        normalized = email.strip().lower()
        store.delete_attribute(normalized, key)
        audit.admin(email=principal.email, action="attribute_delete", target=f"{normalized}:{key}")
        return {"message": f"Attribute '{key}' removed from '{normalized}'."}

    # ---- dataset security (row access lines, column masks, test as a user) ----

    register_dataset_routes(api, runtime, access)

    # ---- groups ----------------------------------------------------------

    def _known_group(group_id: str) -> Group:
        """The group, or a 404 when no such group exists."""
        group = {g.group_id: g for g in store.list_groups()}.get(group_id)
        if group is None:
            raise _fail(404, f"Unknown group '{group_id}'.")
        return group

    @api.get("/groups")
    def list_groups() -> dict[str, object]:
        return {"groups": [asdict(g) for g in store.list_groups()], "providers": _providers()}

    @api.post("/groups")
    def create_group(body: GroupIn, principal: Principal = Depends(access.require)) -> dict[str, object]:
        try:
            group = store.create_group(body.provider, body.external_id, body.name)
        except StoreError as exc:
            raise _fail(400, str(exc)) from exc
        audit.admin(email=principal.email, action="group_create", target=group.group_id)
        return {"message": f"Group '{group.name}' created."}

    @api.delete("/groups/{group_id}")
    def delete_group(group_id: str, principal: Principal = Depends(access.require)) -> dict[str, object]:
        _known_group(group_id)
        store.delete_group(group_id)
        audit.admin(email=principal.email, action="group_delete", target=group_id)
        return {"message": "Group deleted with its grants."}

    @api.get("/groups/{group_id}")
    def get_group(group_id: str) -> dict[str, object]:
        group = _known_group(group_id)
        return {
            "group": asdict(group),
            "providers": _providers(),
            "apps": [asdict(a) for a in store.list_apps()],
            "granted": _granted_apps("group", group_id),
        }

    @api.put("/groups/{group_id}")
    def edit_group(group_id: str, body: GroupEditIn, principal: Principal = Depends(access.require)) -> dict[str, object]:
        _known_group(group_id)
        try:
            group = store.update_group(group_id, provider=body.provider, external_id=body.external_id, name=body.name)
        except StoreError as exc:
            raise _fail(400, str(exc)) from exc
        audit.admin(email=principal.email, action="group_update", target=group_id)
        summary = _apply_app_grants(principal, "group", group_id, body.app_ids)
        return {"message": f"Group '{group.name}' saved; {summary}."}

    # ---- local groups ----------------------------------------------------

    def _known_local_group(local_group_id: str) -> dict[str, object]:
        """The local group with its members, or a 404 when no such group exists."""
        for group in _local_groups_payload():
            if group["local_group_id"] == local_group_id:
                return group
        raise _fail(404, f"Unknown local group '{local_group_id}'.")

    @api.get("/local-groups")
    def list_local_groups() -> list[dict[str, object]]:
        return _local_groups_payload()

    @api.post("/local-groups")
    def create_local_group(body: LocalGroupIn, principal: Principal = Depends(access.require)) -> JSONResponse:
        local_group_id = body.local_group_id.strip()
        if local_group_id in {g.local_group_id for g in store.list_local_groups()}:
            raise _fail(409, f"Local group '{local_group_id}' already exists.")
        try:
            store.create_local_group(local_group_id, body.name, body.description)
        except StoreError as exc:
            raise _fail(422, str(exc)) from exc
        audit.admin(email=principal.email, action="local_group_create", target=local_group_id)
        return JSONResponse(_known_local_group(local_group_id), status_code=201)

    @api.get("/local-groups/{local_group_id}")
    def get_local_group(local_group_id: str) -> dict[str, object]:
        return {**_known_local_group(local_group_id), "granted": _granted_apps("local_group", local_group_id)}

    @api.put("/local-groups/{local_group_id}")
    def edit_local_group(
        local_group_id: str, body: LocalGroupEditIn, principal: Principal = Depends(access.require)
    ) -> dict[str, object]:
        _known_local_group(local_group_id)
        try:
            store.update_local_group(local_group_id, name=body.name, description=body.description)
        except StoreError as exc:
            raise _fail(422, str(exc)) from exc
        audit.admin(email=principal.email, action="local_group_update", target=local_group_id)
        return _known_local_group(local_group_id)

    @api.delete("/local-groups/{local_group_id}")
    def delete_local_group(local_group_id: str, principal: Principal = Depends(access.require)) -> dict[str, object]:
        _known_local_group(local_group_id)
        store.delete_local_group(local_group_id)
        audit.admin(email=principal.email, action="local_group_delete", target=local_group_id)
        return {"message": "Local group deleted with its memberships and grants."}

    @api.put("/local-groups/{local_group_id}/members/{email}")
    def add_local_group_member(
        local_group_id: str, email: str, principal: Principal = Depends(access.require)
    ) -> dict[str, object]:
        _known_local_group(local_group_id)
        normalized = email.strip().lower()
        try:
            store.add_local_group_member(local_group_id, normalized)
        except StoreError as exc:
            raise _fail(422, str(exc)) from exc
        audit.admin(email=principal.email, action="local_group_member_add", target=f"{local_group_id}:{normalized}")
        return {"message": f"'{normalized}' is a member of '{local_group_id}'."}

    @api.delete("/local-groups/{local_group_id}/members/{email}")
    def remove_local_group_member(
        local_group_id: str, email: str, principal: Principal = Depends(access.require)
    ) -> dict[str, object]:
        _known_local_group(local_group_id)
        normalized = email.strip().lower()
        store.remove_local_group_member(local_group_id, normalized)
        audit.admin(email=principal.email, action="local_group_member_remove", target=f"{local_group_id}:{normalized}")
        return {"message": f"'{normalized}' removed from '{local_group_id}'."}

    # ---- grants ----------------------------------------------------------

    @api.get("/grants")
    def list_grants() -> dict[str, object]:
        return {
            "apps": [asdict(a) for a in store.list_apps()],
            "grants": [asdict(g) for g in store.list_grants()],
            "users": [asdict(u) for u in store.list_users()],
            "groups": [asdict(g) for g in store.list_groups()],
            "local_groups": [asdict(g) for g in store.list_local_groups()],
        }

    @api.post("/grants")
    def add_grant(body: GrantIn, principal: Principal = Depends(access.require)) -> dict[str, object]:
        subject_type = body.subject_type
        if subject_type not in SUBJECT_TYPES:
            raise _fail(400, f"Subject type must be one of {', '.join(SUBJECT_TYPES)}.")
        subject_id = body.subject_id.strip()
        if not subject_id:
            raise _fail(400, f"Pick a {subject_type} to grant.")
        if subject_type == "user":
            subject_id = subject_id.lower()
        try:
            store.grant(body.app_id, subject_type, subject_id, principal.email)
        except StoreError as exc:
            raise _fail(400, str(exc)) from exc
        audit.admin(email=principal.email, action="grant", target=f"{body.app_id}:{subject_type}:{subject_id}")
        return {"message": f"Granted {subject_type} '{subject_id}' access to '{body.app_id}'."}

    @api.post("/grants/revoke")
    def revoke_grant(body: GrantIn, principal: Principal = Depends(access.require)) -> dict[str, object]:
        store.revoke(body.app_id, body.subject_type, body.subject_id)
        audit.admin(email=principal.email, action="revoke", target=f"{body.app_id}:{body.subject_type}:{body.subject_id}")
        return {"message": f"Revoked {body.subject_type} '{body.subject_id}' from '{body.app_id}'."}

    # ---- audit -----------------------------------------------------------

    @api.get("/audit")
    def audit_log(event: str = "") -> dict[str, object]:
        lines = audit.tail(settings.audit.tail_lines)
        if event in AUDIT_EVENTS:
            lines = [line for line in lines if line.get("event") == event]
        else:
            event = ""
        return {"lines": lines, "event": event, "events": list(AUDIT_EVENTS), "tail_lines": settings.audit.tail_lines}

    app.include_router(api)
    # Last: the SPA fallback answers every GET no route above handled.
    mount_spa(app, frontend_dist or FRONTEND_DIST)
    return app


def create_default() -> FastAPI:
    """uvicorn --factory target (config [apps.admin] factory)."""
    return create_app(build_runtime())
