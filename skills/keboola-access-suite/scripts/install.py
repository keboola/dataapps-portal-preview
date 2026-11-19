"""Install the Data App access-control suite into a Keboola project (phase 1).

    uv run --with httpx --with pydantic --with pyyaml python scripts/install.py phase1 \
        --project "<kbagent alias>" --state-file .kbc-access-suite/state.json \
        --auth oidc --admin-email you@company.com \
        [--admin-group-provider entra --admin-group-id <IdP group id> --admin-group-name data-app-admins] \
        [--bucket-name apps-control-plane] [--yes]

Without --yes it prints the plan and changes nothing. With --yes it runs the
steps below, each idempotent (a re-run reuses what exists):

 1. resolve the project through kbagent (stack URL, project id);
 2. create the control-plane bucket if missing;
 3. mint a Storage token that can write that bucket only (a re-run rotates it);
 4. create the control-plane tables if missing;
 5. create the Access admin and App launcher Data Apps (Keboola-managed git);
 6. build each app's bundle and push it to its managed repo;
 7. write secrets (#ACCESS_STORAGE_TOKEN, #MASK_SALT) and the git block;
 8. deploy both apps and wait until they run;
 9. register both apps and the first administrator in the tables.

Login: the user picks any authentication type the Keboola apps-proxy offers
(`--auth`, see AUTH_MODES). password and public are set by the installer;
oidc, github and gitlab need provider details, which the user enters in the
Keboola UI (Data App → Authentication) after the install — until then the apps
stay behind a generated password, so nothing is ever exposed while unconfigured.

Secrets never touch argv, logs or stdout: the Storage token lives in memory and
goes to Keboola through 0600 temp files, and the git push URL is built in memory.
Progress goes to stderr as "[n/9] ..."; the final JSON summary to stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets as secrets_lib
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

SKILL_DIR = Path(__file__).resolve().parent.parent
SUITE = SKILL_DIR / "assets" / "suite"
sys.path.insert(0, str(SUITE / "src"))
sys.path.insert(0, str(SUITE / "scripts"))

from build_app_bundle import MANIFEST, load_manifest, reads_data, storage_access_grants  # noqa: E402
from build_app_bundle import build as build_bundle  # noqa: E402
from kbc_access.config import ProviderSettings, SeedSettings  # noqa: E402
from kbc_access.demo_seed import DEMO_TABLES, build_warehouse_from_seed, export_csvs  # noqa: E402
from kbc_access.keboola_storage import StorageClient, StorageError, StorageSettings  # noqa: E402
from kbc_access.keboola_store import KeboolaAccessStore  # noqa: E402
from kbc_access.store import TABLE_COLUMNS, App, StoreError  # noqa: E402

DATA_APPS_COMPONENT = "keboola.data-apps"
STEPS = 9
PHASE1_APPS = ("admin", "launcher")
PHASE2_APPS = ("sales", "supply")
# Username sent with the read-only clone token (the git service checks the token, not the name).
CLONE_USERNAME = "kbc-access-suite"
# Lifetime of the installer's own token for loading demo data and registering apps.
INSTALLER_TOKEN_TTL_SECONDS = 3600
# Every authentication type of the Keboola apps-proxy (keboola-as-code
# appsproxy/dataapps/auth/provider: oidc, gitlab, github, password) plus "no login".
# `identity`: whether the proxy then sends X-Kbc-User-Email / X-Kbc-User-Roles,
# which the access check needs. `in_ui`: provider details are entered in the
# Keboola UI; the installer deploys behind a password until then.
AUTH_MODES: dict[str, dict[str, object]] = {
    "oidc": {"label": "OpenID Connect (Entra ID, Okta, Google Workspace, …)", "identity": True, "in_ui": True},
    "github": {"label": "GitHub", "identity": True, "in_ui": True},
    "gitlab": {"label": "GitLab", "identity": True, "in_ui": True},
    "password": {"label": "Password (one shared password per app)", "identity": False, "in_ui": False},
    "public": {"label": "Public, no login", "identity": False, "in_ui": False},
}
# Storage client timeouts used by the installer itself (the apps get theirs from deployed.toml).
HTTP_TIMEOUT_SECONDS = 30.0
JOB_TIMEOUT_SECONDS = 180.0
JOB_POLL_SECONDS = 1.0
PREVIEW_ROW_LIMIT = 1000
DEPLOY_TIMEOUT_SECONDS = 600
SALT_BYTES = 32
PROVIDERS = {
    "entra": ProviderSettings(
        label="Microsoft Entra ID",
        group_id_pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        example="3f2b8c1e-7d4a-4e5b-9a61-2c8d0f4e1b7a",
    ),
    "okta": ProviderSettings(label="Okta", group_id_pattern=r"^00g[0-9A-Za-z]{17}$", example="00g1a2b3c4d5e6f7g8h9"),
}
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$")
BUCKET_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


class InstallError(RuntimeError):
    pass


def progress(step: int, message: str) -> None:
    print(f"[{step}/{STEPS}] {message}", file=sys.stderr, flush=True)


# ---- kbagent ------------------------------------------------------------------


def kbagent(*args: str, secret_values: tuple[str, ...] = ()) -> dict:
    """Run `kbagent --json <args>` and return its `data`. Output is never echoed."""
    proc = subprocess.run(["kbagent", "--json", *args], capture_output=True, text=True, check=False)
    out = proc.stdout
    start = out.find("{")
    if start < 0:
        raise InstallError(f"kbagent {args[0]} {args[1] if len(args) > 1 else ''} failed: {_scrub(proc.stderr[-500:], secret_values)}")
    envelope = json.loads(out[start:])
    if proc.returncode != 0 or envelope.get("status") != "ok":
        detail = envelope.get("error") or envelope.get("message") or proc.stderr[-500:]
        raise InstallError(f"kbagent {' '.join(args[:2])} failed: {_scrub(json.dumps(detail), secret_values)}")
    return envelope["data"]


def _scrub(text: str, values: tuple[str, ...]) -> str:
    for value in values:
        if value:
            text = text.replace(value, "[redacted]")
    return text


class SecretFile:
    """A 0600 temp file for handing a secret to kbagent; removed on exit."""

    def __init__(self, content: str) -> None:
        fd, name = tempfile.mkstemp(prefix="kbc-access-", suffix=".json")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        self.path = Path(name)

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, *_: object) -> None:
        self.path.unlink(missing_ok=True)


# ---- plan -----------------------------------------------------------------------


@dataclass(frozen=True)
class Plan:
    project: str
    state_file: Path
    bucket_stage: str
    bucket_name: str
    auth: str
    admin_email: str
    # The first admin's IdP group: all three or none.
    admin_group_provider: str | None
    admin_group_id: str | None
    admin_group_name: str | None
    slugs: dict[str, str]
    names: dict[str, str]
    size: str
    auto_suspend_seconds: int
    roles_separator: str

    @property
    def bucket_id(self) -> str:
        return f"{self.bucket_stage}.c-{self.bucket_name}"


def validate(plan: Plan) -> None:
    if not BUCKET_NAME.fullmatch(plan.bucket_name):
        raise InstallError("Bucket name may contain letters, digits, '-' and '_' only")
    if plan.auth not in AUTH_MODES:
        raise InstallError(f"--auth must be one of {', '.join(AUTH_MODES)}")
    if not EMAIL.fullmatch(plan.admin_email):
        raise InstallError(f"--admin-email '{plan.admin_email}' is not an email address")
    group = (plan.admin_group_provider, plan.admin_group_id, plan.admin_group_name)
    if any(group) and not all(group):
        raise InstallError("--admin-group-provider, --admin-group-id and --admin-group-name go together")
    if plan.admin_group_provider is not None and plan.admin_group_id is not None:
        if plan.admin_group_provider not in PROVIDERS:
            raise InstallError(f"--admin-group-provider must be one of {', '.join(PROVIDERS)}")
        if not re.fullmatch(PROVIDERS[plan.admin_group_provider].group_id_pattern, plan.admin_group_id):
            raise InstallError(
                f"--admin-group-id is not a valid {PROVIDERS[plan.admin_group_provider].label} group ID "
                f"(expected something like {PROVIDERS[plan.admin_group_provider].example})"
            )
    for app_id, slug in plan.slugs.items():
        if not SLUG.fullmatch(slug):
            raise InstallError(f"Slug for {app_id} must be lowercase letters, digits and '-' (2-64 chars)")


def login_summary(auth: str) -> str:
    mode = AUTH_MODES[auth]
    text = str(mode["label"])
    if mode["in_ui"]:
        text += " — you enter the provider details in the Keboola UI after install; until then the apps stay behind a generated password"
    if not mode["identity"]:
        text += " — WARNING: this login does not tell the apps who the user is, so the access check lets nobody in"
    return text


def create_auth(auth: str) -> str:
    """What kbagent can set at create time: the mode itself, or a closed password placeholder."""
    return "public" if auth == "public" else "password"


def describe(plan: Plan, project: dict) -> dict:
    return {
        "project": f"{project['project_name']} ({project['project_id']}) at {project['stack_url']}",
        "bucket": plan.bucket_id,
        "tables": list(TABLE_COLUMNS),
        "storage_token": f"write access to {plan.bucket_id} only; stored as the apps' #ACCESS_STORAGE_TOKEN secret",
        "apps": {
            app_id: {"name": plan.names[app_id], "slug": plan.slugs[app_id], "size": plan.size,
                     "auto_suspend_seconds": plan.auto_suspend_seconds, "git": "Keboola-managed repo"}
            for app_id in PHASE1_APPS
        },
        "login": login_summary(plan.auth),
        "first_admin": {
            "email": plan.admin_email,
            "group": f"{plan.admin_group_name} ({plan.admin_group_provider}: {plan.admin_group_id})" if plan.admin_group_id else None,
        },
    }


# ---- state ----------------------------------------------------------------------


def load_state(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def save_state(path: Path, state: dict) -> None:
    """Non-secret install state (ids and URLs) so a re-run finds what it made."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ---- steps ------------------------------------------------------------------------


def resolve_project(alias: str) -> dict:
    projects = kbagent("project", "list")
    match = next((p for p in projects if p["alias"] == alias), None)
    if match is None:
        raise InstallError(f"No kbagent project with alias '{alias}'. Known: {', '.join(p['alias'] for p in projects)}")
    return match


def ensure_bucket(plan: Plan) -> bool:
    buckets = kbagent("storage", "buckets", "--project", plan.project)["buckets"]
    if any(b.get("id") == plan.bucket_id for b in buckets):
        return False
    kbagent(
        "storage", "create-bucket", "--project", plan.project, "--stage", plan.bucket_stage,
        "--name", plan.bucket_name, "--description", "Access control plane for Data Apps (apps, users, groups, grants, attributes)",
    )
    return True


def mint_token(plan: Plan, state: dict, *, key: str = "token_id", access: str = "--bucket-write",
               description: str = "Data App access control") -> str:
    """A fresh bucket-scoped token; the previous one stored under `key` is revoked at the end of the run."""
    created = kbagent(
        "token", "create", "--project", plan.project,
        "--description", f"{description} ({plan.bucket_id})", access, plan.bucket_id,
    )
    token = str(created["token"])
    old = state.get(key)
    state[key] = str(created["id"])
    if old and old != state[key]:
        # Revoked only after the apps run with the new token (see run()). Saved now, so a
        # run that fails midway still revokes it next time instead of leaking it.
        state["revoke_token_ids"] = sorted({*state.get("revoke_token_ids", []), old})
    save_state(plan.state_file, state)
    return token


def expected_url(stack_url: str, slug: str, app_id: str) -> str:
    """Data App URL before its first deploy: https://<slug>-<app id>.hub.<stack host without "connection.">/.

    A managed-git app has no URL until it is deployed, but each bundle must know
    the launcher's URL. Verified against live apps on europe-west3.gcp; the
    installer compares it with the real URL after deploy and stops on a mismatch.
    """
    host = urlparse(stack_url).hostname or ""
    if not host.startswith("connection."):
        raise InstallError(f"Unexpected stack URL {stack_url}; cannot derive app URLs")
    return f"https://{slug}-{app_id}.hub.{host.removeprefix('connection.')}/"


def ensure_apps(plan: Plan, project: dict, state: dict, app_ids: tuple[str, ...] = PHASE1_APPS) -> dict[str, dict]:
    existing = {a["app_id"]: a for a in kbagent("data-app", "list", "--project", plan.project)["apps"]}
    apps: dict[str, dict] = {}
    for app_id in app_ids:
        known = state.get("apps", {}).get(app_id)
        if known and known["app_id"] in existing:
            apps[app_id] = known
            continue
        # No state (or a stale one): a deployed app's URL starts with "<slug>-"; a never
        # deployed one has no URL yet, so match it by name.
        by_slug = [
            a for a in existing.values()
            if (urlparse(a.get("url") or "").hostname or "").startswith(f"{plan.slugs[app_id]}-")
            or (not a.get("url") and a.get("name") == plan.names[app_id])
        ]
        if len(by_slug) == 1:
            found = by_slug[0]
            url = (found.get("url") or expected_url(project["stack_url"], plan.slugs[app_id], found["app_id"])).rstrip("/") + "/"
            apps[app_id] = {"app_id": found["app_id"], "config_id": found["config_id"], "url": url}
            state.setdefault("apps", {})[app_id] = apps[app_id]
            save_state(plan.state_file, state)
            continue
        if len(by_slug) > 1:
            raise InstallError(f"Several apps in the project use the slug '{plan.slugs[app_id]}'; pass another --{app_id}-slug")
        created = kbagent(
            "data-app", "create", "--project", plan.project, "--name", plan.names[app_id], "--slug", plan.slugs[app_id],
            "--use-managed-git-repo", "--type", "python-js", "--size", plan.size,
            "--auto-suspend", str(plan.auto_suspend_seconds), "--auth", create_auth(plan.auth),
        )
        url = created.get("url") or expected_url(project["stack_url"], plan.slugs[app_id], created["app_id"])
        apps[app_id] = {"app_id": created["app_id"], "config_id": created["config_id"], "url": url.rstrip("/") + "/"}
        state.setdefault("apps", {})[app_id] = apps[app_id]
        save_state(plan.state_file, state)
    return apps


def push_bundle(plan: Plan, project: dict, app_id: str, apps: dict[str, dict], data_bucket_id: str | None = None) -> str:
    """Build the app's git tree and push it to its managed repo. Returns the https clone URL."""
    ds_id = apps[app_id]["app_id"]
    repo = kbagent("data-app", "git-repo", "--project", plan.project, "--app-id", ds_id)
    https_url = repo.get("https_url") or ""
    if not https_url.startswith("https://"):
        raise InstallError(f"No managed git repo URL for {app_id} yet; wait a minute and re-run")
    credential = kbagent(
        "data-app", "git-credentials-create", "--project", plan.project, "--app-id", ds_id,
        "--type", "http_token", "--permissions", "readWrite", "--name", "kbc-access-suite-install", "--yes",
    )["credential"]
    git_token = str(credential["secret"])
    parsed = urlparse(https_url)
    push_url = f"{parsed.scheme}://{git_token}@{parsed.netloc}{parsed.path}"
    with tempfile.TemporaryDirectory(prefix=f"kbc-access-{app_id}-") as tmp:
        out = Path(tmp) / "repo"
        build_bundle(
            app_id=app_id, out=out, stack_url=project["stack_url"], bucket_id=plan.bucket_id,
            app_urls={a: v["url"] for a, v in apps.items()}, roles_separator=plan.roles_separator,
            data_bucket_id=data_bucket_id,
        )
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        for cmd in (
            ["git", "init", "-q", "-b", "main"],
            ["git", "add", "-A"],
            ["git", "-c", "user.name=kbc-access-suite", "-c", "user.email=kbc-access-suite@localhost",
             "commit", "-q", "-m", f"Deploy {plan.names[app_id]}"],
        ):
            subprocess.run(cmd, cwd=out, check=True, env=env, capture_output=True)
        push = subprocess.run(["git", "push", "-q", "--force", push_url, "HEAD:main"], cwd=out, env=env,
                              capture_output=True, text=True, check=False)
        if push.returncode != 0:
            raise InstallError(f"git push for {app_id} failed: {_scrub(push.stderr[-400:], (git_token, push_url))}")
    return https_url


def control_plane_grants(bucket_id: str) -> list[dict[str, str]]:
    """storage.output.tables entries that give the admin app Direct Storage Access to its own control-plane tables.

    The same `direct-grant` entry carries read and write: the app may SELECT, INSERT, UPDATE and DELETE
    those tables through the Query Service. Only the admin app (the one writer) gets it.
    """
    return [{"destination": f"{bucket_id}.{table}", "unload_strategy": "direct-grant"} for table in TABLE_COLUMNS]


def app_storage_grants(app_id: str, bucket_id: str, demo_bucket_id: str | None) -> list[dict[str, str]] | None:
    """Every Direct Storage Access grant the app needs, or None when it needs none (the launcher).

    The admin app writes its control-plane tables; every app that reads data (the dashboards, and the
    admin once the demo data exists) reads the demo tables.
    """
    manifest = load_manifest()
    grants: list[dict[str, str]] = []
    if app_id == "admin":
        grants += control_plane_grants(bucket_id)
    if demo_bucket_id and reads_data(manifest, app_id, demo_bucket_id):
        grants += storage_access_grants(manifest, demo_bucket_id)
    return grants or None


def sync_storage_access(project_alias: str, app: dict, grants: list[dict[str, str]]) -> bool:
    """Make the app's config carry exactly `grants` and the runtime workspace flag. Returns whether it changed.

    Only `storage` and `runtime.workspace` are touched: secrets, git and login stay as they are.
    """
    detail = kbagent("config", "detail", "--project", project_alias, "--component-id", DATA_APPS_COMPONENT,
                     "--config-id", app["config_id"])
    configuration = detail["configuration"]
    storage = configuration.setdefault("storage", {})
    runtime = configuration.setdefault("runtime", {})
    if (storage.get("output", {}).get("tables") == grants and "input" not in storage
            and runtime.get("workspace") == {"enabled": True}):
        return False
    storage.pop("input", None)  # data comes through Direct Storage Access, never input mapping
    storage.setdefault("output", {})["tables"] = grants
    # The grants only take effect in a Storage workspace, which the runtime provisions only with this flag.
    runtime["workspace"] = {"enabled": True}
    with SecretFile(json.dumps(configuration)) as config_path:
        kbagent("config", "update", "--project", project_alias, "--component-id", DATA_APPS_COMPONENT,
                "--config-id", app["config_id"], "--configuration-file", str(config_path),
                "--change-description", "kbc-access-suite: Direct Storage Access")
    return True


def configure_app(
    plan: Plan, app_id: str, app: dict, https_url: str, storage_token: str, mask_salt: str,
    *, storage_grants: list[dict] | None = None, authorization: dict | None = None,
) -> None:
    """Secrets, then the git block (and, for dashboards, the Direct Storage Access grants) written onto the full config.

    Authentication is left as it is unless `authorization` is given (phase 2 copies the admin app's).
    """
    with SecretFile(json.dumps({"#ACCESS_STORAGE_TOKEN": storage_token, "#MASK_SALT": mask_salt})) as secrets_path:
        kbagent("data-app", "secrets-set", "--project", plan.project, "--app-id", app["app_id"],
                "--secrets-file", str(secrets_path), "--no-hint-next", secret_values=(storage_token, mask_salt))
    # Earlier installs used #KBC_TOKEN, which the runtime ignores (it sets KBC_TOKEN itself).
    kbagent("data-app", "secrets-remove", "--project", plan.project, "--app-id", app["app_id"], "--key", "#KBC_TOKEN", "--yes")
    detail = kbagent("config", "detail", "--project", plan.project, "--component-id", DATA_APPS_COMPONENT,
                     "--config-id", app["config_id"])
    configuration = detail["configuration"]
    # The platform does not always inject the managed repo into the config; write it explicitly.
    git: dict[str, object] = {"repository": https_url, "branch": "main", "private": True}
    clone_secret: str = ""
    # Verified live: the runtime could not clone the managed repo ("Credentials are
    # incorrect or have expired") first for dashboards with an input mapping, later
    # also for the phase-1 apps on a plain redeploy. Every app therefore carries its
    # own read-only clone credential, so the clone never depends on the platform's.
    current = configuration.get("parameters", {}).get("dataApp", {}).get("git", {})
    if current.get("repository") == https_url and str(current.get("#password", "")).startswith("KBC::"):
        git.update({"username": current.get("username", ""), "#password": current["#password"]})
    else:
        credential = kbagent(
            "data-app", "git-credentials-create", "--project", plan.project, "--app-id", app["app_id"],
            "--type", "http_token", "--permissions", "readOnly", "--name", "kbc-access-suite-clone", "--yes",
        )["credential"]
        clone_secret = str(credential["secret"])
        git.update({"username": CLONE_USERNAME, "#password": clone_secret})
    configuration.setdefault("parameters", {}).setdefault("dataApp", {})["git"] = git
    if storage_grants is not None:
        storage = configuration.setdefault("storage", {})
        storage.pop("input", None)  # data comes through Direct Storage Access, never input mapping
        storage.setdefault("output", {})["tables"] = storage_grants
        # The grants only take effect in a Storage workspace, and the runtime provisions one
        # (injecting QUERY_SERVICE_URL / WORKSPACE_ID) only with this flag. kbagent adds it on
        # create since 0.87; apps created earlier lack it (seen live: the variables missing).
        configuration.setdefault("runtime", {})["workspace"] = {"enabled": True}
    if authorization is not None:
        configuration["authorization"] = authorization
    with SecretFile(json.dumps(configuration)) as config_path:
        kbagent("config", "update", "--project", plan.project, "--component-id", DATA_APPS_COMPONENT,
                "--config-id", app["config_id"], "--configuration-file", str(config_path),
                "--change-description", "kbc-access-suite: secrets and managed git",
                secret_values=(storage_token, mask_salt, clone_secret))
    written = kbagent("config", "detail", "--project", plan.project, "--component-id", DATA_APPS_COMPONENT,
                      "--config-id", app["config_id"])["configuration"]
    stored = written.get("parameters", {}).get("dataApp", {}).get("secrets", {})
    plain = [k for k, v in (stored.items() if isinstance(stored, dict) else []) if k.startswith("#") and not str(v).startswith("KBC::")]
    stored_git = written.get("parameters", {}).get("dataApp", {}).get("git", {})
    if "#password" in stored_git and not str(stored_git["#password"]).startswith("KBC::"):
        plain.append("git #password")
    if plain:
        raise InstallError(f"Secrets {plain} of {app_id} are not stored encrypted; aborting before deploy")


def deploy(plan: Plan, app_id: str, app: dict) -> None:
    kbagent("data-app", "deploy", "--project", plan.project, "--app-id", app["app_id"], "--wait",
            "--timeout", str(DEPLOY_TIMEOUT_SECONDS))
    real = (kbagent("data-app", "detail", "--project", plan.project, "--app-id", app["app_id"]).get("url") or "").rstrip("/") + "/"
    if real != "/" and real != app["url"]:
        raise InstallError(
            f"{app_id} is served at {real}, not at the derived {app['url']}; update the state file with the real URL and re-run"
        )


def register(plan: Plan, project: dict, apps: dict[str, dict], storage_token: str) -> None:
    client = StorageClient(StorageSettings(
        stack_url=project["stack_url"], token=storage_token, http_timeout_seconds=HTTP_TIMEOUT_SECONDS,
        job_timeout_seconds=JOB_TIMEOUT_SECONDS, job_poll_seconds=JOB_POLL_SECONDS, preview_row_limit=PREVIEW_ROW_LIMIT,
    ))
    try:
        store = KeboolaAccessStore(client, plan.bucket_id, PROVIDERS, read_cache_seconds=0)
        for app_id in PHASE1_APPS:
            if app_id == "launcher":
                continue  # the launcher lists apps; it is not itself gated
            store.upsert_app(App(app_id, plan.names[app_id], apps[app_id]["url"], str(project["project_id"]),
                                 apps[app_id]["config_id"], "manual", True))
        store.upsert_user(plan.admin_email, plan.admin_email, True)
        store.grant("admin", "user", plan.admin_email, "kbc-access-suite-install")
        if plan.admin_group_provider and plan.admin_group_id and plan.admin_group_name:
            group = next((g for g in store.list_groups()
                          if g.provider == plan.admin_group_provider and g.external_id == plan.admin_group_id), None)
            if group is None:
                group = store.create_group(plan.admin_group_provider, plan.admin_group_id, plan.admin_group_name)
            store.grant("admin", "group", group.group_id, "kbc-access-suite-install")
    finally:
        client.close()


def schema(plan: Plan, project: dict, storage_token: str) -> list[str]:
    client = StorageClient(StorageSettings(
        stack_url=project["stack_url"], token=storage_token, http_timeout_seconds=HTTP_TIMEOUT_SECONDS,
        job_timeout_seconds=JOB_TIMEOUT_SECONDS, job_poll_seconds=JOB_POLL_SECONDS, preview_row_limit=PREVIEW_ROW_LIMIT,
    ))
    try:
        return KeboolaAccessStore(client, plan.bucket_id, PROVIDERS, read_cache_seconds=0).ensure_schema()
    finally:
        client.close()


def next_steps(plan: Plan, apps: dict[str, dict]) -> list[str]:
    mode = AUTH_MODES[plan.auth]
    steps: list[str] = []
    if mode["in_ui"]:
        steps.append(
            f"In Keboola open each app (Data Apps → {', '.join(plan.names[a] for a in PHASE1_APPS)}) → Authentication, "
            f"choose {mode['label']} and enter the provider details; then redeploy the app."
        )
        steps.append("Register these redirect URIs at the provider: "
                     + ", ".join(f"{apps[a]['url']}_proxy/callback" for a in PHASE1_APPS))
    if not mode["identity"]:
        steps.append("This login sends no user identity; switch to OIDC, GitHub or GitLab in the Keboola UI before the access check can let anyone in.")
    steps.append(f"Open the launcher ({apps['launcher']['url']}) and sign in as {plan.admin_email}; it must list Access admin.")
    return steps


def run(plan: Plan) -> dict:
    state = load_state(plan.state_file)
    progress(1, f"Resolving project '{plan.project}'")
    project = resolve_project(plan.project)
    state.update({"project_id": project["project_id"], "stack_url": project["stack_url"], "bucket_id": plan.bucket_id})
    save_state(plan.state_file, state)

    progress(2, f"Bucket {plan.bucket_id}")
    created_bucket = ensure_bucket(plan)
    progress(3, "Minting a Storage token scoped to the bucket")
    storage_token = mint_token(plan, state)
    progress(4, "Control-plane tables")
    created_tables = schema(plan, project, storage_token)
    progress(5, "Creating the Access admin and App launcher apps")
    apps = ensure_apps(plan, project, state)
    mask_salt = secrets_lib.token_urlsafe(SALT_BYTES)
    repos: dict[str, str] = {}
    for app_id in PHASE1_APPS:
        progress(6, f"Building and pushing {plan.names[app_id]}")
        repos[app_id] = push_bundle(plan, project, app_id, apps, data_bucket_id=state.get("demo_bucket_id"))
    for app_id in PHASE1_APPS:
        progress(7, f"Secrets and git settings for {plan.names[app_id]}")
        configure_app(
            plan, app_id, apps[app_id], repos[app_id], storage_token, mask_salt,
            storage_grants=app_storage_grants(app_id, plan.bucket_id, state.get("demo_bucket_id")),
        )
    for app_id in PHASE1_APPS:
        progress(8, f"Deploying {plan.names[app_id]} (this can take a few minutes)")
        deploy(plan, app_id, apps[app_id])
    progress(9, "Registering apps and the first administrator")
    register(plan, project, apps, storage_token)

    revoked: list[str] = []
    for old in state.get("revoke_token_ids", []):
        kbagent("token", "delete", "--project", plan.project, "--token-id", str(old), "--yes")
        revoked.append(old)
    state["revoke_token_ids"] = []
    save_state(plan.state_file, state)
    return {
        "bucket": plan.bucket_id,
        "bucket_created": created_bucket,
        "tables_created": created_tables,
        "apps": {a: {"url": apps[a]["url"], "app_id": apps[a]["app_id"]} for a in PHASE1_APPS},
        "old_token_revoked": revoked,
        "login": login_summary(plan.auth),
        "next": next_steps(plan, apps),
    }


# ---- phase 2: demo data + dashboards --------------------------------------------


@dataclass(frozen=True)
class Phase2Plan:
    project: str
    state_file: Path
    # The phase 1 control-plane bucket (from the state file).
    bucket_id: str
    demo_bucket_stage: str
    demo_bucket_name: str
    grant_group_provider: str | None
    grant_group_id: str | None
    grant_group_name: str | None
    slugs: dict[str, str]
    names: dict[str, str]
    size: str
    auto_suspend_seconds: int
    roles_separator: str
    # Dashboards are created behind a password placeholder, then get the admin app's login.
    auth: str = "password"

    @property
    def demo_bucket_id(self) -> str:
        return f"{self.demo_bucket_stage}.c-{self.demo_bucket_name}"


def validate_phase2(plan: Phase2Plan, state: dict) -> None:
    if not all(a in state.get("apps", {}) for a in PHASE1_APPS):
        raise InstallError("Run phase1 first (the state file has no Access admin / App launcher)")
    if not BUCKET_NAME.fullmatch(plan.demo_bucket_name):
        raise InstallError("Demo bucket name may contain letters, digits, '-' and '_' only")
    if f"{plan.demo_bucket_stage}.c-{plan.demo_bucket_name}" == plan.bucket_id:
        raise InstallError("The demo data must not go into the control-plane bucket")
    group = (plan.grant_group_provider, plan.grant_group_id, plan.grant_group_name)
    if any(group) and not all(group):
        raise InstallError("--grant-group-provider, --grant-group-id and --grant-group-name go together")
    if plan.grant_group_provider and plan.grant_group_id:
        pattern = PROVIDERS[plan.grant_group_provider].group_id_pattern
        if not re.fullmatch(pattern, plan.grant_group_id):
            raise InstallError(f"--grant-group-id is not a valid {PROVIDERS[plan.grant_group_provider].label} group ID")
    for app_id, slug in plan.slugs.items():
        if not SLUG.fullmatch(slug):
            raise InstallError(f"Slug for {app_id} must be lowercase letters, digits and '-' (2-64 chars)")


def describe_phase2(plan: Phase2Plan, project: dict) -> dict:
    return {
        "project": f"{project['project_name']} ({project['project_id']}) at {project['stack_url']}",
        "demo_bucket": plan.demo_bucket_id,
        "demo_tables": list(DEMO_TABLES),
        "dashboards": {a: {"name": plan.names[a], "slug": plan.slugs[a], "size": plan.size,
                           "auto_suspend_seconds": plan.auto_suspend_seconds} for a in PHASE2_APPS},
        "data_access": "Direct Storage Access (direct-grant) to the demo tables, pulled into DuckDB at start and every 30 min",
        "storage_token": f"read-only access to {plan.bucket_id} (the access tables); stored as the dashboards' #ACCESS_STORAGE_TOKEN",
        "login": "copied from the Access admin app (a password placeholder if the admin has none yet)",
        "grant": f"{plan.grant_group_name} ({plan.grant_group_provider}: {plan.grant_group_id}) gets both dashboards"
                 if plan.grant_group_id else "nobody — grant access in the admin app",
    }


def mint_installer_token(plan: Phase2Plan) -> tuple[str, str]:
    """Short-lived token for this run only: write both buckets. Returns (token, id)."""
    created = kbagent(
        "token", "create", "--project", plan.project, "--description", "kbc-access-suite: phase 2 install (temporary)",
        "--bucket-write", plan.bucket_id, "--bucket-write", plan.demo_bucket_id,
        "--expires-in", str(INSTALLER_TOKEN_TTL_SECONDS),
    )
    return str(created["token"]), str(created["id"])


def storage_client(project: dict, token: str) -> StorageClient:
    return StorageClient(StorageSettings(
        stack_url=project["stack_url"], token=token, http_timeout_seconds=HTTP_TIMEOUT_SECONDS,
        job_timeout_seconds=JOB_TIMEOUT_SECONDS, job_poll_seconds=JOB_POLL_SECONDS, preview_row_limit=PREVIEW_ROW_LIMIT,
    ))


def load_demo_data(plan: Phase2Plan, project: dict, token: str) -> dict[str, str]:
    """Generate the demo tables and (re)load them into the demo bucket. Returns table → created/replaced."""
    manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    seed = SeedSettings.model_validate(manifest["demo_seed"])
    result: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="kbc-access-demo-") as tmp:
        warehouse = Path(tmp) / "demo.duckdb"
        build_warehouse_from_seed(seed, warehouse)
        files = export_csvs(warehouse, Path(tmp) / "csv")
        client = storage_client(project, token)
        try:
            existing = set(client.list_tables(plan.demo_bucket_id))
            for table in DEMO_TABLES:
                content = files[table].read_bytes()
                if table in existing:
                    client.replace_table_csv(f"{plan.demo_bucket_id}.{table}", content)
                    result[table] = "replaced"
                else:
                    client.create_table_from_csv(plan.demo_bucket_id, table, content, [])
                    result[table] = "created"
        finally:
            client.close()
    return result


def admin_authorization(plan: Phase2Plan, state: dict) -> dict | None:
    """The admin app's login block when it uses a real provider (OIDC/GitHub/GitLab), else None.

    Encrypted values in it are project-scoped (KBC::ProjectSecure), so they stay
    valid on another Data App of the same project.
    """
    config = kbagent("config", "detail", "--project", plan.project, "--component-id", DATA_APPS_COMPONENT,
                     "--config-id", state["apps"]["admin"]["config_id"])["configuration"]
    auth = config.get("authorization") or {}
    providers = (auth.get("app_proxy") or {}).get("auth_providers") or []
    if not any(p.get("type") in ("oidc", "github", "gitlab") for p in providers):
        return None
    for p in providers:
        for key, value in p.items():
            if key.startswith("#") and not str(value).startswith("KBC::ProjectSecure"):
                raise InstallError("The admin app's login secret is not project-scoped; set the dashboards' login in the Keboola UI")
    return auth


def register_dashboards(plan: Phase2Plan, project: dict, apps: dict[str, dict], token: str) -> str | None:
    """Register the dashboards; grant them to the chosen group. Returns the group's internal id, if any."""
    client = storage_client(project, token)
    try:
        store = KeboolaAccessStore(client, plan.bucket_id, PROVIDERS, read_cache_seconds=0)
        for app_id in PHASE2_APPS:
            store.upsert_app(App(app_id, plan.names[app_id], apps[app_id]["url"], str(project["project_id"]),
                                 apps[app_id]["config_id"], "manual", True))
        if not (plan.grant_group_provider and plan.grant_group_id and plan.grant_group_name):
            return None
        group = next((g for g in store.list_groups()
                      if g.provider == plan.grant_group_provider and g.external_id == plan.grant_group_id), None)
        if group is None:
            group = store.create_group(plan.grant_group_provider, plan.grant_group_id, plan.grant_group_name)
        for app_id in PHASE2_APPS:
            store.grant(app_id, "group", group.group_id, "kbc-access-suite-install")
        return group.group_id
    finally:
        client.close()


def run_phase2(plan: Phase2Plan) -> dict:
    state = load_state(plan.state_file)
    progress(1, f"Resolving project '{plan.project}'")
    project = resolve_project(plan.project)
    progress(2, f"Demo bucket {plan.demo_bucket_id}")
    buckets = kbagent("storage", "buckets", "--project", plan.project)["buckets"]
    created_bucket = not any(b.get("id") == plan.demo_bucket_id for b in buckets)
    if created_bucket:
        kbagent("storage", "create-bucket", "--project", plan.project, "--stage", plan.demo_bucket_stage,
                "--name", plan.demo_bucket_name, "--description", "Demo data for the access-control dashboards")
    progress(3, "Minting tokens (a temporary one for this run, a read-only one for the dashboards)")
    installer_token, installer_token_id = mint_installer_token(plan)
    dashboard_token = mint_token(plan, state, key="dashboard_token_id", access="--bucket-read",  # type: ignore[arg-type]
                                 description="Data App dashboards, read access tables")
    progress(4, "Loading the demo tables")
    tables = load_demo_data(plan, project, installer_token)
    progress(5, "Creating the dashboard apps")
    dashboards = ensure_apps(plan, project, state, PHASE2_APPS)  # type: ignore[arg-type]
    launcher = state["apps"]["launcher"]
    authorization = admin_authorization(plan, state)
    manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    grants = storage_access_grants(manifest, plan.demo_bucket_id)
    mask_salt = secrets_lib.token_urlsafe(SALT_BYTES)
    repos: dict[str, str] = {}
    for app_id in PHASE2_APPS:
        progress(6, f"Building and pushing {plan.names[app_id]}")
        repos[app_id] = push_bundle(plan, project, app_id, {app_id: dashboards[app_id], "launcher": launcher},  # type: ignore[arg-type]
                                    data_bucket_id=plan.demo_bucket_id)
    for app_id in PHASE2_APPS:
        progress(7, f"Secrets, Direct Storage Access and login for {plan.names[app_id]}")
        configure_app(plan, app_id, dashboards[app_id], repos[app_id], dashboard_token, mask_salt,  # type: ignore[arg-type]
                      storage_grants=grants, authorization=authorization)
    for app_id in PHASE2_APPS:
        progress(8, f"Deploying {plan.names[app_id]} (this can take a few minutes)")
        deploy(plan, app_id, dashboards[app_id])  # type: ignore[arg-type]
    admin = state["apps"]["admin"]
    progress(8, "Giving Access admin read access to the demo data and redeploying it")
    admin_grants = app_storage_grants("admin", plan.bucket_id, plan.demo_bucket_id)
    assert admin_grants is not None  # the admin always has its control-plane grants
    sync_storage_access(plan.project, admin, admin_grants)
    push_bundle(plan, project, "admin", {"admin": admin, "launcher": launcher}, data_bucket_id=plan.demo_bucket_id)  # type: ignore[arg-type]
    deploy(plan, "admin", admin)  # type: ignore[arg-type]
    progress(9, "Registering the dashboards" + (f" and granting them to {plan.grant_group_name}" if plan.grant_group_id else ""))
    group_id = register_dashboards(plan, project, dashboards, installer_token)

    revoked: list[str] = [installer_token_id]
    kbagent("token", "delete", "--project", plan.project, "--token-id", installer_token_id, "--yes")
    for old in state.get("revoke_token_ids", []):
        kbagent("token", "delete", "--project", plan.project, "--token-id", str(old), "--yes")
        revoked.append(old)
    state["revoke_token_ids"] = []
    state["demo_bucket_id"] = plan.demo_bucket_id
    save_state(plan.state_file, state)
    return {
        "demo_bucket": plan.demo_bucket_id,
        "demo_bucket_created": created_bucket,
        "demo_tables": tables,
        "dashboards": {a: {"url": dashboards[a]["url"], "app_id": dashboards[a]["app_id"]} for a in PHASE2_APPS},
        "login": "copied from Access admin" if authorization else "password placeholder — set the login in the Keboola UI",
        "granted_group": group_id,
        "tokens_revoked": revoked,
        "next": [
            *([] if authorization else ["Set each dashboard's Authentication in the Keboola UI (as for the admin) and redeploy."]),
            "Register these redirect URIs at the IdP: " + ", ".join(f"{dashboards[a]['url']}_proxy/callback" for a in PHASE2_APPS),
            "Row-level rules use the user attribute `company` (PHARMA_A/B/C): set it per user in the admin app; "
            "without it a user sees only public rows.",
            f"Open the launcher ({launcher['url']}): members of the granted group now see both dashboards.",
        ],
    }


# ---- redeploy: new code, nothing else ------------------------------------------

ALL_APPS = (*PHASE1_APPS, *PHASE2_APPS)
APP_NAMES = {
    "admin": "Access admin", "launcher": "App launcher",
    "sales": "Drug sales dashboard", "supply": "Supply chain dashboard",
}


@dataclass(frozen=True)
class RedeployPlan:
    project: str
    state_file: Path
    bucket_id: str
    demo_bucket_id: str | None
    app_ids: tuple[str, ...]
    roles_separator: str
    names: dict[str, str]


def validate_redeploy(plan: RedeployPlan, state: dict) -> None:
    unknown = [a for a in plan.app_ids if a not in ALL_APPS]
    if unknown:
        raise InstallError(f"Unknown app(s): {', '.join(unknown)}. Known: {', '.join(ALL_APPS)}")
    missing = [a for a in plan.app_ids if a not in state.get("apps", {})]
    if missing:
        raise InstallError(f"Not installed according to the state file: {', '.join(missing)}. Run phase1 / phase2 first")
    if "launcher" not in state.get("apps", {}):
        raise InstallError("The state file has no App launcher (every bundle links to its URL)")
    if any(a in PHASE2_APPS for a in plan.app_ids) and not plan.demo_bucket_id:
        raise InstallError("The state file has no demo bucket; run phase2 first")


def describe_redeploy(plan: RedeployPlan, project: dict, state: dict) -> dict:
    return {
        "project": f"{project['project_name']} ({project['project_id']}) at {project['stack_url']}",
        "apps": {a: state["apps"][a]["url"] for a in plan.app_ids},
        "does": "builds the current code, pushes it to each app's managed git repo and redeploys it",
        "storage_access": "sets each app's Direct Storage Access grants to what it needs (admin: control-plane tables, "
                          "plus the demo tables once they exist; dashboards: the demo tables)",
        "leaves_alone": "bucket, tables, tokens, secrets, login, grants and data",
    }


def run_redeploy(plan: RedeployPlan) -> dict:
    state = load_state(plan.state_file)
    project = resolve_project(plan.project)
    apps = state["apps"]
    synced: list[str] = []
    for app_id in plan.app_ids:
        grants = app_storage_grants(app_id, plan.bucket_id, plan.demo_bucket_id)
        if grants is not None and sync_storage_access(plan.project, apps[app_id], grants):
            synced.append(app_id)
        progress(1, f"Building and pushing {plan.names[app_id]}")
        push_bundle(plan, project, app_id, apps, data_bucket_id=plan.demo_bucket_id)  # type: ignore[arg-type]
    for app_id in plan.app_ids:
        progress(2, f"Deploying {plan.names[app_id]} (this can take a few minutes)")
        deploy(plan, app_id, apps[app_id])  # type: ignore[arg-type]
    return {"redeployed": {a: apps[a]["url"] for a in plan.app_ids}, "storage_access_updated": synced}


def parse(argv: list[str] | None) -> tuple[argparse.Namespace, Plan]:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("phase1", help="bucket, tables, admin + launcher apps")
    p.add_argument("--project", required=True, help="kbagent project alias")
    p.add_argument("--state-file", required=True, type=Path)
    p.add_argument("--bucket-name", default="apps-control-plane")
    p.add_argument("--bucket-stage", default="in", choices=["in", "out"])
    p.add_argument("--auth", required=True, choices=list(AUTH_MODES), help="login type of both apps")
    p.add_argument("--admin-email", required=True)
    p.add_argument("--admin-group-provider", choices=sorted(PROVIDERS))
    p.add_argument("--admin-group-id")
    p.add_argument("--admin-group-name")
    p.add_argument("--admin-slug", default="access-admin")
    p.add_argument("--launcher-slug", default="app-launcher")
    p.add_argument("--size", default="tiny", choices=["tiny", "small", "medium", "large"])
    p.add_argument("--auto-suspend-seconds", type=int, default=3600)
    p.add_argument("--roles-separator", default=",", help="separator the proxy uses between groups in X-Kbc-User-Roles")
    p.add_argument("--yes", action="store_true", help="execute; without it only the plan is printed")
    q = sub.add_parser("phase2", help="demo data + the two demo dashboards (after phase1)")
    q.add_argument("--project", required=True, help="kbagent project alias")
    q.add_argument("--state-file", required=True, type=Path, help="the phase1 state file")
    q.add_argument("--demo-bucket-name", default="apps-control-plane-demo")
    q.add_argument("--demo-bucket-stage", default="in", choices=["in", "out"])
    q.add_argument("--grant-group-provider", choices=sorted(PROVIDERS))
    q.add_argument("--grant-group-id")
    q.add_argument("--grant-group-name")
    q.add_argument("--sales-slug", default="drug-sales")
    q.add_argument("--supply-slug", default="supply-chain")
    q.add_argument("--size", default="tiny", choices=["tiny", "small", "medium", "large"])
    q.add_argument("--auto-suspend-seconds", type=int, default=3600)
    q.add_argument("--roles-separator", default=",", help="separator the proxy uses between groups in X-Kbc-User-Roles")
    q.add_argument("--yes", action="store_true", help="execute; without it only the plan is printed")
    r = sub.add_parser("redeploy", help="push the current code to installed apps and redeploy them; changes nothing else")
    r.add_argument("--project", required=True, help="kbagent project alias")
    r.add_argument("--state-file", required=True, type=Path, help="the state file of phase1 / phase2")
    r.add_argument("--apps", default=",".join(ALL_APPS), help=f"comma-separated subset of {', '.join(ALL_APPS)}")
    r.add_argument("--roles-separator", default=",", help="separator the proxy uses between groups in X-Kbc-User-Roles")
    r.add_argument("--yes", action="store_true", help="execute; without it only the plan is printed")
    args = parser.parse_args(argv)
    if args.command == "redeploy":
        state_file = args.state_file.expanduser()
        state = load_state(state_file)
        redeploy = RedeployPlan(
            project=args.project, state_file=state_file, bucket_id=str(state.get("bucket_id", "")),
            demo_bucket_id=state.get("demo_bucket_id"),
            app_ids=tuple(a.strip() for a in args.apps.split(",") if a.strip()),
            roles_separator=args.roles_separator, names=APP_NAMES,
        )
        return args, redeploy  # type: ignore[return-value]
    if args.command == "phase2":
        state = load_state(args.state_file.expanduser())
        phase2 = Phase2Plan(
            project=args.project, state_file=args.state_file.expanduser(), bucket_id=str(state.get("bucket_id", "")),
            demo_bucket_stage=args.demo_bucket_stage, demo_bucket_name=args.demo_bucket_name,
            grant_group_provider=args.grant_group_provider,
            grant_group_id=args.grant_group_id.strip() if args.grant_group_id else None,
            grant_group_name=args.grant_group_name.strip() if args.grant_group_name else None,
            slugs={"sales": args.sales_slug, "supply": args.supply_slug},
            names={"sales": "Drug sales dashboard", "supply": "Supply chain dashboard"},
            size=args.size, auto_suspend_seconds=args.auto_suspend_seconds, roles_separator=args.roles_separator,
        )
        return args, phase2  # type: ignore[return-value]
    plan = Plan(
        project=args.project, state_file=args.state_file.expanduser(), bucket_stage=args.bucket_stage,
        bucket_name=args.bucket_name, auth=args.auth, admin_email=args.admin_email.strip().lower(),
        admin_group_provider=args.admin_group_provider,
        admin_group_id=args.admin_group_id.strip() if args.admin_group_id else None,
        admin_group_name=args.admin_group_name.strip() if args.admin_group_name else None,
        slugs={"admin": args.admin_slug, "launcher": args.launcher_slug},
        names={"admin": "Access admin", "launcher": "App launcher"},
        size=args.size, auto_suspend_seconds=args.auto_suspend_seconds, roles_separator=args.roles_separator,
    )
    return args, plan


def main(argv: list[str] | None = None) -> int:
    args, plan = parse(argv)
    try:
        if isinstance(plan, RedeployPlan):
            state = load_state(plan.state_file)
            validate_redeploy(plan, state)
            project = resolve_project(plan.project)
            if not args.yes:
                print(json.dumps({"plan": describe_redeploy(plan, project, state), "execute_with": "--yes"}, indent=2))
                return 0
            print(json.dumps(run_redeploy(plan), indent=2))
            return 0
        if isinstance(plan, Phase2Plan):
            validate_phase2(plan, load_state(plan.state_file))
            project = resolve_project(plan.project)
            if not args.yes:
                print(json.dumps({"plan": describe_phase2(plan, project), "execute_with": "--yes"}, indent=2))
                return 0
            print(json.dumps(run_phase2(plan), indent=2))
            return 0
        validate(plan)
        project = resolve_project(plan.project)
        if not args.yes:
            print(json.dumps({"plan": describe(plan, project), "execute_with": "--yes"}, indent=2))
            return 0
        print(json.dumps(run(plan), indent=2))
    except (InstallError, StoreError, StorageError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
