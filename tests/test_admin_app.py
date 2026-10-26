"""Access admin app: gating, CSRF, SPA shell, CRUD, simulator, audit view (JSON API).

Discovery is in test_admin_discovery.py, user/group editing in test_admin_edit.py.
"""

from __future__ import annotations

import json

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from apps.admin.main import create_app
from kbc_access.gate import decide
from kbc_access.identity import principal_from_headers
from kbc_access.web import CSRF_HEADER, DENY_MESSAGES, install
from tests.conftest import SPA_ASSET_BODY, SPA_ASSET_NAME, SPA_INDEX_MARKER

ADMIN = "anna.admin@pharma-a.example"
NOGRANT = "tomas.nogrant@pharma-a.example"
PETR = "petr.sales@pharma-a.example"
ENTRA_SALES_MANAGERS = "8a1d4e2f-5b6c-4d7e-9f80-1a2b3c4d5e6f"


@pytest.fixture
def client(runtime, frontend_dist) -> TestClient:
    # The SPA's API client sends the CSRF header on every request.
    return TestClient(create_app(runtime, frontend_dist=frontend_dist), headers={CSRF_HEADER: "1"})


@pytest.fixture
def bare_client(runtime, frontend_dist) -> TestClient:
    """A client that does not send the CSRF header (a forged cross-site request)."""
    return TestClient(create_app(runtime, frontend_dist=frontend_dist))


@pytest.fixture
def admin(headers_for) -> dict[str, str]:
    return headers_for(ADMIN)


def _audit_lines(runtime) -> list[dict]:
    path = runtime.settings.path(runtime.settings.audit.path)
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _admin_events(runtime) -> list[tuple[str, str]]:
    return [(e["action"], e["target"]) for e in _audit_lines(runtime) if e["event"] == "admin"]


# ---- gating -------------------------------------------------------------


def test_non_admin_gets_403_json(client, headers_for, runtime):
    response = client.get("/api/overview", headers=headers_for(NOGRANT))
    assert response.status_code == 403
    body = response.json()
    assert body["reason"] == "no_grant"
    assert body["detail"] == DENY_MESSAGES["no_grant"]
    assert body["user"]["email"] == NOGRANT
    assert isinstance(body["user"]["groups"], list)
    # The SPA's refusal screen links to the launcher and to switching user.
    assert body["launcher_url"] == runtime.settings.app_url("launcher")
    assert body["switch_user_path"] == runtime.settings.ui.switch_user_path


def test_non_admin_cannot_mutate(client, headers_for, runtime):
    response = client.post(
        "/api/users", json={"email": "intruder@x.example", "display_name": "X"}, headers=headers_for(PETR)
    )
    assert response.status_code == 403
    assert "intruder@x.example" not in {u.email for u in runtime.store.list_users()}


def test_missing_identity_is_401_json(client, runtime):
    response = client.get("/api/apps")
    assert response.status_code == 401
    body = response.json()
    assert body["reason"] == "not_authenticated" and body["detail"]
    assert body["switch_user_path"] == runtime.settings.ui.switch_user_path
    assert body["launcher_url"] == runtime.settings.app_url("launcher")


def test_health_check_post_root_still_works(client):
    response = client.post("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_session_describes_the_signed_in_admin(client, admin, runtime):
    body = client.get("/api/session", headers=admin).json()
    assert body["user"]["email"] == ADMIN
    assert body["app_name"] == runtime.settings.apps["admin"].name
    assert body["launcher_url"] == runtime.settings.app_url("launcher")
    assert body["switch_user_path"] == runtime.settings.ui.switch_user_path


def test_admin_sees_overview_with_matrix(client, admin, runtime):
    response = client.get("/api/overview", headers=admin)
    assert response.status_code == 200
    body = response.json()
    assert body["counts"]["apps"] == len(runtime.store.list_apps())
    assert set(body["counts"]) == {"apps", "users", "groups", "local_groups", "grants", "attributes"}
    assert [a["name"] for a in body["apps"]] == sorted(a["name"] for a in body["apps"])
    # User-level grant from the seed: jan.partner is granted the sales app directly.
    jan = body["user_matrix"]["jan.partner@pharma-b.example"]["sales"]
    assert jan["allowed"] and jan["matched"] == ["user:jan.partner@pharma-b.example"]
    sales_managers = next(g for g in body["groups"] if g["external_id"] == ENTRA_SALES_MANAGERS)
    assert "sales" in body["group_grants"][sales_managers["group_id"]]
    for path in ("/api/apps", "/api/discovery", "/api/users", "/api/groups", "/api/grants", "/api/audit"):
        assert client.get(path, headers=admin).status_code == 200, path


# ---- CSRF ---------------------------------------------------------------


def test_mutation_without_csrf_header_is_refused_and_changes_nothing(bare_client, admin, runtime):
    before = _admin_events(runtime) if runtime.settings.path(runtime.settings.audit.path).exists() else []
    response = bare_client.post("/api/users", json={"email": "forged@x.example", "display_name": ""}, headers=admin)
    assert response.status_code == 403
    assert response.json() == {"detail": "Missing CSRF header.", "reason": "csrf"}
    assert "forged@x.example" not in {u.email for u in runtime.store.list_users()}

    response = bare_client.delete(f"/api/users/{PETR}", headers=admin)
    assert response.status_code == 403
    assert PETR in {u.email for u in runtime.store.list_users()}
    assert _admin_events(runtime) == before


def test_reads_do_not_need_the_csrf_header(bare_client, admin):
    assert bare_client.get("/api/overview", headers=admin).status_code == 200


# ---- SPA shell ----------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/users/x", "/groups/some-id/edit"])
def test_spa_shell_is_served_without_identity(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert SPA_INDEX_MARKER in response.text
    assert response.headers["content-type"].startswith("text/html")


def test_spa_assets_are_served(client):
    response = client.get(f"/assets/{SPA_ASSET_NAME}")
    assert response.status_code == 200 and response.text == SPA_ASSET_BODY
    assert client.get("/assets/missing.js").status_code == 404


def test_unknown_api_path_is_json_404_not_the_shell(client, admin):
    for method in ("get", "post"):
        response = getattr(client, method)("/api/unknown", headers=admin)
        assert response.status_code == 404, method
        assert response.json() == {"detail": "Not Found"}


def test_missing_frontend_build_fails_fast(runtime, tmp_path):
    with pytest.raises(RuntimeError, match="npm ci && npm run build"):
        create_app(runtime, frontend_dist=tmp_path / "no-dist")


# ---- users + attributes -------------------------------------------------


def test_create_user_and_attribute(client, admin, runtime):
    response = client.post("/api/users", json={"email": "New.User@Pharma-A.example", "display_name": "New User"}, headers=admin)
    assert response.status_code == 200
    assert response.json() == {"message": "User 'new.user@pharma-a.example' created."}
    assert "new.user@pharma-a.example" in {u.email for u in runtime.store.list_users()}

    response = client.put(
        "/api/users/new.user@pharma-a.example/attributes/company", json={"value": "PHARMA_Z"}, headers=admin
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Attribute 'company' set for 'new.user@pharma-a.example'."
    assert runtime.store.attributes_for("new.user@pharma-a.example") == {"company": "PHARMA_Z"}
    users = {u["email"]: u for u in client.get("/api/users", headers=admin).json()["users"]}
    assert users["new.user@pharma-a.example"]["attributes"] == {"company": "PHARMA_Z"}

    events = _admin_events(runtime)
    assert ("user_create", "new.user@pharma-a.example") in events
    assert ("attribute_set", "new.user@pharma-a.example:company") in events
    # Attribute values never reach the audit log.
    assert "PHARMA_Z" not in runtime.settings.path(runtime.settings.audit.path).read_text(encoding="utf-8")

    response = client.delete("/api/users/new.user@pharma-a.example/attributes/company", headers=admin)
    assert response.json()["message"] == "Attribute 'company' removed from 'new.user@pharma-a.example'."
    assert runtime.store.attributes_for("new.user@pharma-a.example") == {}


def test_create_existing_user_is_409(client, admin):
    response = client.post("/api/users", json={"email": PETR.upper()}, headers=admin)
    assert response.status_code == 409
    assert response.json()["detail"] == f"User '{PETR}' already exists."


def test_invalid_user_and_attribute_show_store_error(client, admin):
    response = client.post("/api/users", json={"email": "not-an-email", "display_name": ""}, headers=admin)
    assert response.status_code == 400 and "is not a valid email" in response.json()["detail"]
    response = client.put(f"/api/users/{PETR}/attributes/Bad Key", json={"value": "x"}, headers=admin)
    assert response.status_code == 400
    assert "Attribute key must be lowercase snake_case" in response.json()["detail"]


def test_attribute_for_unknown_user_is_404(client, admin):
    response = client.put("/api/users/ghost@x.example/attributes/company", json={"value": "x"}, headers=admin)
    assert response.status_code == 404 and response.json()["detail"] == "Unknown user 'ghost@x.example'."


def test_malformed_body_is_a_readable_400(client, admin):
    response = client.post("/api/users", json={"display_name": "no email"}, headers=admin)
    assert response.status_code == 400
    assert response.json()["detail"].startswith("Invalid request: email:")


def test_toggle_user_deactivates_access(client, admin, runtime, headers_for):
    response = client.post(f"/api/users/{PETR}/toggle", headers=admin)
    assert response.json()["message"] == f"User '{PETR}' deactivated."
    petr = principal_from_headers(headers_for(PETR), runtime.settings.identity).principal
    decision = decide(runtime.store.snapshot(), petr, "sales")
    assert not decision.allowed and decision.reason == "user_deactivated"
    assert ("user_deactivate", PETR) in _admin_events(runtime)


def test_delete_user(client, admin, runtime):
    response = client.delete(f"/api/users/{PETR}", headers=admin)
    assert response.json()["message"] == f"User '{PETR}' deleted with their grants and attributes."
    assert PETR not in {u.email for u in runtime.store.list_users()}
    assert ("user_delete", PETR) in _admin_events(runtime)
    assert client.delete(f"/api/users/{PETR}", headers=admin).status_code == 404
    assert client.post(f"/api/users/{PETR}/toggle", headers=admin).status_code == 404


# ---- groups -------------------------------------------------------------


def test_create_group_validates_provider_template(client, admin, runtime):
    response = client.post(
        "/api/groups", json={"provider": "entra", "external_id": "not-a-guid", "name": "bad"}, headers=admin
    )
    assert response.status_code == 400
    assert "is not a valid Microsoft Entra ID group ID" in response.json()["detail"]
    assert "bad" not in {g.name for g in runtime.store.list_groups()}

    good = "11111111-2222-4333-8444-555555555555"
    response = client.post("/api/groups", json={"provider": "entra", "external_id": good, "name": "auditors"}, headers=admin)
    assert response.json() == {"message": "Group 'auditors' created."}
    created = next(g for g in runtime.store.list_groups() if g.name == "auditors")
    assert created.external_id == good
    assert ("group_create", created.group_id) in _admin_events(runtime)


def test_groups_endpoint_lists_provider_templates(client, admin, runtime):
    providers = client.get("/api/groups", headers=admin).json()["providers"]
    for key, provider in runtime.store.providers.items():
        assert providers[key] == {
            "label": provider.label, "group_id_pattern": provider.group_id_pattern, "example": provider.example,
        }


def test_delete_group(client, admin, runtime):
    finance = next(g for g in runtime.store.list_groups() if g.name == "finance")
    response = client.delete(f"/api/groups/{finance.group_id}", headers=admin)
    assert response.json() == {"message": "Group deleted with its grants."}
    assert finance.group_id not in {g.group_id for g in runtime.store.list_groups()}
    assert ("group_delete", finance.group_id) in _admin_events(runtime)
    response = client.delete(f"/api/groups/{finance.group_id}", headers=admin)
    assert response.status_code == 404 and response.json()["detail"] == f"Unknown group '{finance.group_id}'."


# ---- grants -------------------------------------------------------------


def test_grant_and_revoke_change_gate_decision(client, admin, runtime, headers_for):
    tomas = principal_from_headers(headers_for(NOGRANT), runtime.settings.identity).principal
    assert not decide(runtime.store.snapshot(), tomas, "sales").allowed

    response = client.post(
        "/api/grants", json={"app_id": "sales", "subject_type": "user", "subject_id": NOGRANT.upper()}, headers=admin
    )
    assert response.json()["message"] == f"Granted user '{NOGRANT}' access to 'sales'."
    decision = decide(runtime.store.snapshot(), tomas, "sales")
    assert decision.allowed
    assert decision.matched == (f"user:{NOGRANT}",)
    grants = client.get("/api/grants", headers=admin).json()["grants"]
    assert any(g["subject_id"] == NOGRANT and g["granted_by"] == ADMIN for g in grants)

    response = client.post(
        "/api/grants/revoke", json={"app_id": "sales", "subject_type": "user", "subject_id": NOGRANT}, headers=admin
    )
    assert response.json()["message"] == f"Revoked user '{NOGRANT}' from 'sales'."
    assert not decide(runtime.store.snapshot(), tomas, "sales").allowed

    events = _admin_events(runtime)
    assert ("grant", f"sales:user:{NOGRANT}") in events
    assert ("revoke", f"sales:user:{NOGRANT}") in events


def test_group_grant(client, admin, runtime, headers_for):
    all_employees = next(g for g in runtime.store.list_groups() if g.name == "all-employees")
    client.post(
        "/api/grants", json={"app_id": "sales", "subject_type": "group", "subject_id": all_employees.group_id},
        headers=admin,
    )
    tomas = principal_from_headers(headers_for(NOGRANT), runtime.settings.identity).principal
    assert decide(runtime.store.snapshot(), tomas, "sales").matched == (f"group:{all_employees.group_id}",)


def test_grant_errors(client, admin):
    response = client.post(
        "/api/grants", json={"app_id": "sales", "subject_type": "user", "subject_id": "ghost@x.example"}, headers=admin
    )
    assert response.status_code == 400 and "Unknown user" in response.json()["detail"]
    response = client.post("/api/grants", json={"app_id": "sales", "subject_type": "team", "subject_id": "x"}, headers=admin)
    assert response.status_code == 400 and response.json()["detail"].startswith("Subject type must be one of")
    response = client.post("/api/grants", json={"app_id": "sales", "subject_type": "group", "subject_id": " "}, headers=admin)
    assert response.status_code == 400 and response.json()["detail"] == "Pick a group to grant."


# ---- apps ---------------------------------------------------------------


def test_app_create_edit_toggle_delete(client, admin, runtime):
    response = client.post(
        "/api/apps",
        json={"app_id": "hr", "name": "HR board", "url": "https://hr.example", "project_id": "1", "config_id": "2", "active": True},
        headers=admin,
    )
    assert response.json() == {"message": "App 'hr' saved."}
    app = {a.app_id: a for a in runtime.store.list_apps()}["hr"]
    assert app.source == "manual" and app.active

    listed = {a["app_id"]: a for a in client.get("/api/apps", headers=admin).json()["apps"]}
    assert listed["hr"]["name"] == "HR board" and listed["hr"]["source"] == "manual"

    client.post("/api/apps", json={"app_id": "hr", "name": "HR dashboard", "url": "", "project_id": "1", "config_id": "2"}, headers=admin)
    app = {a.app_id: a for a in runtime.store.list_apps()}["hr"]
    assert app.name == "HR dashboard" and not app.active

    response = client.post("/api/apps/hr/toggle", headers=admin)
    assert response.json() == {"message": "App 'hr' activated."}
    assert {a.app_id: a for a in runtime.store.list_apps()}["hr"].active

    response = client.delete("/api/apps/hr", headers=admin)
    assert response.json() == {"message": "App 'hr' deleted with its grants."}
    assert "hr" not in {a.app_id for a in runtime.store.list_apps()}
    actions = [a for a, t in _admin_events(runtime) if t == "hr"]
    assert actions == ["app_create", "app_update", "app_activate", "app_delete"]

    assert client.delete("/api/apps/hr", headers=admin).status_code == 404
    response = client.post("/api/apps/hr/toggle", headers=admin)
    assert response.status_code == 404 and response.json()["detail"] == "Unknown app 'hr'."


def test_invalid_app_id_shows_error(client, admin):
    response = client.post("/api/apps", json={"app_id": "Bad App", "name": "x"}, headers=admin)
    assert response.status_code == 400 and "App ID must be lowercase" in response.json()["detail"]


def test_app_access_set_kept_on_edit_and_toggle(client, admin, runtime):
    def access() -> str:
        return {a.app_id: a for a in runtime.store.list_apps()}["hr"].access

    client.post("/api/apps", json={"app_id": "hr", "name": "HR", "active": True}, headers=admin)
    assert access() == "grants"
    client.post("/api/apps", json={"app_id": "hr", "name": "HR", "active": True, "access": "all_signed_in"}, headers=admin)
    assert access() == "all_signed_in"
    listed = {a["app_id"]: a for a in client.get("/api/apps", headers=admin).json()["apps"]}
    assert listed["hr"]["access"] == "all_signed_in"
    # An edit without the field and an activate/deactivate keep it.
    client.post("/api/apps", json={"app_id": "hr", "name": "HR board", "active": True}, headers=admin)
    assert access() == "all_signed_in"
    client.post("/api/apps/hr/toggle", headers=admin)
    assert access() == "all_signed_in"
    client.post("/api/apps", json={"app_id": "hr", "name": "HR board", "active": True, "access": "grants"}, headers=admin)
    assert access() == "grants"


def test_invalid_app_access_shows_error(client, admin):
    response = client.post("/api/apps", json={"app_id": "hr", "name": "HR", "access": "public"}, headers=admin)
    assert response.status_code == 400 and "Unknown app access 'public'" in response.json()["detail"]


# ---- simulator ----------------------------------------------------------


def test_access_simulator(client, admin):
    response = client.post(
        "/api/simulate",
        json={"email": f"  {PETR.upper()} ", "groups": [ENTRA_SALES_MANAGERS], "extra": "unknown-group, other"},
        headers=admin,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == PETR
    names = {g["external_id"]: g["name"] for g in body["groups"]}
    assert names["unknown-group"] is None and names["other"] is None
    assert names[ENTRA_SALES_MANAGERS] is not None
    results = {r["app"]["app_id"]: r["decision"] for r in body["results"]}
    # sales is granted to sales-managers; admin is not.
    assert results["sales"]["allowed"] and results["sales"]["matched"][0].startswith("group:")
    assert not results["admin"]["allowed"] and results["admin"]["reason"] == "no_grant"


def test_simulator_requires_email(client, admin):
    for email in ("", "no-at-sign"):
        response = client.post("/api/simulate", json={"email": email}, headers=admin)
        assert response.status_code == 400
        assert response.json()["detail"] == "Enter the email of the principal to check."


# ---- audit --------------------------------------------------------------


def test_audit_lists_admin_events_and_filters(client, admin):
    client.post("/api/users", json={"email": "audited@pharma-a.example", "display_name": ""}, headers=admin)
    body = client.get("/api/audit", params={"event": "admin"}, headers=admin).json()
    assert body["event"] == "admin" and body["events"] == ["gate", "query", "admin"] and body["tail_lines"] > 0
    assert any(line["action"] == "user_create" and line["target"] == "audited@pharma-a.example" for line in body["lines"])
    assert all(line["event"] == "admin" for line in body["lines"])
    assert all("allowed" not in line for line in body["lines"])  # admin events carry no decision

    gate = client.get("/api/audit", params={"event": "gate"}, headers=admin).json()
    assert gate["lines"] and all(line["event"] == "gate" for line in gate["lines"])
    assert any(line["allowed"] for line in gate["lines"])

    everything = client.get("/api/audit", params={"event": "bogus"}, headers=admin).json()
    assert everything["event"] == ""
    assert {line["event"] for line in everything["lines"]} >= {"gate", "admin"}


# ---- shared 401/403 handlers: HTML outside /api, JSON inside -------------


def test_install_answers_html_outside_api_and_json_inside(runtime, headers_for):
    app = FastAPI()
    access = install(app, runtime, app_id="sales", templates_dir=None)

    @app.get("/page")
    def page(principal=Depends(access.require)) -> dict:  # type: ignore[no-untyped-def]
        return {}

    @app.get("/api/thing")
    def thing(principal=Depends(access.require)) -> dict:  # type: ignore[no-untyped-def]
        return {}

    client = TestClient(app)
    denied = client.get("/page", headers=headers_for(NOGRANT))
    assert denied.status_code == 403 and "Sorry, you can't get in here" in denied.text
    assert denied.headers["content-type"].startswith("text/html")
    assert client.get("/api/thing", headers=headers_for(NOGRANT)).json()["reason"] == "no_grant"

    anonymous = client.get("/page")
    assert anonymous.status_code == 401 and anonymous.headers["content-type"].startswith("text/html")
    assert client.get("/api/thing").json()["reason"] == "not_authenticated"
