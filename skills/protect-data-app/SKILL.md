---
name: protect-data-app
description: Wires access control into a Keboola Data App — the app gate (who may open it, from the ACL tables managed in the Access admin app) and, for apps that show data, the row/column-security data guard. Works for apps in the dataapps-portal-preview repo and for apps in their own repository (it vendors the kbc_access package), and re-running it on an app that already has an access check upgrades that check to the current one. Use together with keboola-data-app or dataapp-deployment whenever a Data App is scaffolded or an existing one must stop being "everyone behind the OIDC app", or when someone says "protect this app", "only finance should see this", "add access control", "upgrade the access check", "row level security in the app", "chraň appku", "přístupy do appky". Not for managing who has access (that is done in the Access admin app), and not for configuring the OIDC provider or its redirect URLs.
---

# Protect a Data App

Every app this skill touches gets exactly two things: a **gate** that runs
before any page, and (if the app shows warehouse data) the **data guard** so
each viewer sees only their rows and columns. Both come from the `kbc_access`
package in https://github.com/keboola/dataapps-portal-preview.

**The one rule that shapes everything:** this skill never decides *who* may
open the app. It does not ask for groups and does not write required roles
into env vars or code. It wires the check and makes sure the app is
registered; access is granted by an administrator in the **Access admin** app.

The one question it does ask: **is the app for everyone who has an account in
the identity provider?** Such an app is registered with
`access = all_signed_in`: the gate still runs, requires a signed-in user and
blocks deactivated users, but needs no grant. An admin can switch it either
way in **Access admin → Apps → Edit → Open to everyone signed in**.

## Checklist

Copy into the reply and tick off:

- [ ] 1. Where does the app live? (this repo / its own repo)
- [ ] 2. Existing access check? (none / vendored kbc_access → upgrade / home-made → replace)
- [ ] 3. App id: reuse the registered one, or pick a new one and confirm it
- [ ] 4. Access: reuse the registered value, or ask "everyone signed in, or only users granted in Access admin?"
- [ ] 5. Own repo only: vendor kbc_access with `scripts/vendor_access.py` (plan, then `--yes`)
- [ ] 6. Add the gate to every route / the top of the Streamlit script
- [ ] 7. If the app reads warehouse data: route every query through the data guard
- [ ] 8. Keep the Keboola health check (`POST /` → 200) outside the gate
- [ ] 9. Secrets: the app's own read-only `#ACCESS_STORAGE_TOKEN` and `#MASK_SALT`; list the secrets that became unused
- [ ] 10. Register the app if it is not registered (no grants)
- [ ] 11. Redeploy the app in Keboola and verify
- [ ] 12. Hand-off: what changed, who can open it, how to grant and test

## 1. Where does the app live?

- **In this repo** (`apps/<name>/`, deployed by the suite's bundle builder):
  the builder copies `src/kbc_access` and renders `config/deployed.toml`. Add
  the app to `[apps]` in `deploy/suite.toml` (`name`, `factory`, `paths`,
  `phase`) and use the snippets below with `build_runtime()`.
- **In its own repository** (a customer's GitHub repo, a Keboola-managed repo):
  the package is **vendored** — copied into the app repo by
  `scripts/vendor_access.py` together with a version marker and the access
  config. Never write a home-made check against the control-plane tables, and
  never install kbc_access from anywhere else.

## 2. Existing access check → upgrade

Look before changing anything:

```bash
find . -name kbc_access.vendored.json -not -path "./.git/*"
grep -rnE "apps-control-plane|app_grants|ACCESS_MODE|ACCESS_STORAGE_TOKEN|X-Kbc-User|x-kbc-user|X-Forwarded|kbc_access" \
  --include=*.py --include=*.toml --include=*.json --include=*.txt .
kbagent --json data-app secrets-list --project <alias> --app-id <data app id>   # keys only
```

- **Marker found** (`kbc_access.vendored.json`): an upgrade. Re-run step 5 with
  the same `--app-id`, `--vendor-dir` and `--config-path` (all recorded in the
  marker); the script reports "previous → new" and refuses a different app id.
  Then re-check steps 6–11 against the current snippets.
- **`kbc_access/` without a marker**: a hand-copied package. Step 5 replaces it
  and reports it as an unmarked copy.
- **Anything else** — code that reads `in.c-apps-control-plane` (or another
  control-plane bucket) through the Storage API, parses `X-Kbc-User-*` itself,
  switches on an env var or secret such as `ACCESS_MODE`, or keeps its own
  allow-list: **replace it**. Wire the kbc_access gate (steps 5–8), then delete
  the home-made code, its helper modules and the dependencies only it used.
  Home-made checks miss what the gate knows: `access = all_signed_in`, local
  groups, IdP group grants, deactivated users and apps, and the audit log.
- Tell the user which secrets and env vars became unused (for example
  `#ACCESS_MODE`). Remove them only after they confirm and the new version
  runs: `kbagent data-app secrets-remove --project <alias> --app-id <id> --key '#ACCESS_MODE' --yes`.
  `#ACCESS_STORAGE_TOKEN` and `#MASK_SALT` stay (step 9 checks them).

The snippets cover FastAPI (a dependency on every route) and Streamlit (a check
at the top of the script). For any other framework, run the Streamlit
snippet's `principal_from_headers` + `runtime.gate.check` before serving
anything.

## 3. App id

The id is the key in the `apps` table, in every grant and in every audit line.
**If the app is already registered, reuse its id** — a new id is a duplicate
row without the grants the admins already made. Read the table:

```bash
kbagent --json storage download-table --project <alias> \
  --table-id in.c-apps-control-plane.apps --output /tmp/apps.csv
```

Find the row by `config_id` (the Data App's configuration id) or `url`. For a
new app, derive the id from the name (`Drug sales v2` → `drug-sales-v2`;
lowercase `[a-z0-9_-]`, ≤ 64) and confirm it with the user.

## 4. Access value

For a registered app keep its `access` value (empty means `grants`: rows from
before the column existed read as "grants only"). Only for a new app ask: "For
everyone with an account in the IdP, or only for users granted in Access
admin?" Ask rather than assume; the default is grants only.

## 5. Own repo: vendor kbc_access

Clone the source and run the script from that clone (it copies from the clone
it sits in; `--source` points at another one):

```bash
git clone https://github.com/keboola/dataapps-portal-preview /tmp/dataapps-portal-preview
cd /tmp/dataapps-portal-preview          # optionally: git checkout <tag>
uv run --with pydantic python skills/protect-data-app/scripts/vendor_access.py \
  --target <app repo> --app-id <id from step 3> --app-name "<name>" \
  --app-url https://<app>.hub.<stack>/ --app-entrypoint <streamlit_app.py | module:create_default> \
  --app-port <port the app listens on> --launcher-url https://<app-launcher>.hub.<stack>/ \
  --stack-url https://connection.<stack> --bucket-id in.c-apps-control-plane --roles-separator ,
```

Read every value; never invent one. Stack URL: `kbagent --json project list`.
App URL: `kbagent --json data-app detail --project <alias> --app-id <id>`.
Launcher URL: the `launcher` row's `url` in the `apps` table. Bucket and roles
separator: what the suite was installed with (its `.kbc-access-suite/state.json`;
defaults `in.c-apps-control-plane` and `,`).

Without `--yes` it prints the plan (install or upgrade, previous and new
version, dependencies, conflicts) and writes nothing. Show it, then re-run with
`--yes`. It:

- copies the package to `<vendor-dir>/kbc_access` (default: the repo root, on
  `sys.path` for a Streamlit script or a module started from the root; pass
  `--vendor-dir src` when the app's code lives in `src/`);
- writes `<vendor-dir>/kbc_access.vendored.json` (source commit, date, app id);
- renders `config/kbc_access.toml` (`--config-path`, always `<dir>/<file>.toml`:
  `logs/` resolves against the directory above it) and validates it. An app
  with the data guard keeps its `[data]` and `[policy]` sections in its own
  file and passes `--extra-config <file>` on every run;
- merges the runtime dependencies into `requirements.txt` as a marked block. A
  dependency the app already lists keeps the app's line; a differing pin is
  reported in `dependency_conflicts` — resolve it with the user. Without a
  `requirements.txt`, add the listed dependencies to the app's dependency file.

Add `logs/` to the app's `.gitignore`. Commit everything the script wrote; never
edit it by hand — a re-run overwrites it.

## 6. Gate — Python (FastAPI)

```python
import os
from pathlib import Path
from fastapi import Depends, FastAPI, Request
from kbc_access.config import load_settings
from kbc_access.identity import Principal
from kbc_access.web import build_runtime, install

APP_ID = "drug-sales-v2"
ACCESS_CONFIG = Path(__file__).resolve().parent / "config" / "kbc_access.toml"  # own repo: adjust to where it is

def create_app(runtime) -> FastAPI:
    app = FastAPI()
    access = install(app, runtime, app_id=APP_ID, templates_dir=None)  # adds POST / health check + 401/403 pages

    @app.get("/")
    def home(request: Request, principal: Principal = Depends(access.require)):
        ...
    return app

def create_default() -> FastAPI:  # uvicorn --factory target
    # Own repo: explicit config path. In this repo: build_runtime() (the bundle sets KBC_ACCESS_CONFIG).
    return create_app(build_runtime(load_settings(ACCESS_CONFIG, dict(os.environ))))
```

`access.require` builds the principal **only** from `X-Kbc-User-Email` /
`X-Kbc-User-Roles` (set by the Keboola apps-proxy) and runs the gate. Never
read `X-Forwarded-*` or any other identity header — the proxy does not strip
them, so they are spoofable; the library audits their presence as hostile.

### Gate — Streamlit

Streamlit has no dependency injection; check once at the top of the script,
before anything renders:

```python
import os
from pathlib import Path
import streamlit as st
from kbc_access.config import load_settings
from kbc_access.identity import IdentityError, principal_from_headers
from kbc_access.web import build_runtime

APP_ID = "drug-sales-v2"
ACCESS_CONFIG = Path(__file__).resolve().parent / "config" / "kbc_access.toml"

@st.cache_resource
def _access_runtime():
    return build_runtime(load_settings(ACCESS_CONFIG, dict(os.environ)))

runtime = _access_runtime()
try:
    identity = principal_from_headers(st.context.headers, runtime.settings.identity)
except IdentityError:
    st.error("Not signed in."); st.stop()
principal = identity.principal
decision = runtime.gate.check(principal, APP_ID)
runtime.audit.gate(app_id=APP_ID, email=principal.email, allowed=decision.allowed, reason=decision.reason,
                   matched=decision.matched, hostile_headers=identity.hostile_headers, path="/")
if not decision.allowed:
    st.error("Sorry, you can't get in here."); st.stop()
```

The gate caches the ACL for `[gate] cache_ttl_seconds` (30 s): a grant or
revocation in Access admin applies within that window.

## 7. Data guard (apps that show data)

Never query the warehouse directly. Build the guard once and send plain SQL
against dataset names; it rewrites the query so the policy is inside it:

```python
from kbc_access.web import build_guard
guard = build_guard(runtime, APP_ID)

@app.get("/")
def home(request: Request, principal: Principal = Depends(access.require_with_attributes)):
    result = guard.run(principal, "SELECT company, SUM(revenue) FROM drug_sales GROUP BY 1")
    if result.error: ...            # rejected or failed — show the message, it is safe
    rows = result.result.rows       # masked / filtered for this viewer
```

`require_with_attributes` adds the viewer's attributes (e.g. `company`) from
the `user_attributes` table — row rules bind them as `:company`. The guard needs
`[data]` and `[policy]` in the config (own repo: `--extra-config`). If a dataset
the app needs is not in the policy yet, add it to the policy YAML in the same
change — it is code and gets reviewed like code. A dataset with no matching
grant does not exist for the viewer; design pages to handle "dataset not
visible" and `NULL` in masked columns instead of crashing.

## 8. Health check

Keboola probes Data Apps with `POST /`. `install()` registers it outside the
gate; do not add another `POST /` route. A Streamlit script defines no routes;
nothing to add.

## 9. Secrets

The config needs two Data App secrets (Keboola exposes secret `#NAME` as env
var `NAME`):

- **`#ACCESS_STORAGE_TOKEN`** — the app's **own** Storage token with **read**
  access to the control-plane bucket only. Never copy the Access admin's or the
  launcher's token: it can write the ACL, and the suite installer rotates and
  revokes it on every re-install, which breaks every app holding a copy. Secret
  values are encrypted, so you cannot tell which token an existing secret
  holds: on an upgrade, mint a new one and replace it. Hand it over in a 0600
  file, never in argv, and never print it:

  ```bash
  kbagent --json token create --project <alias> \
    --description "Data App access check: <app id> (read in.c-apps-control-plane)" \
    --bucket-read in.c-apps-control-plane          # returns the token once, and its id
  # write {"#ACCESS_STORAGE_TOKEN": "<token>"} to a chmod 600 temp file, then:
  kbagent data-app secrets-set --project <alias> --app-id <data app id> --secrets-file <file>
  ```

  Tell the user the new token's id. Once the app runs with it, the token it
  replaced may be revoked (`kbagent token delete`) if it was an app-only
  token — never the suite's own token.
- **`#MASK_SALT`** — required by the config loader in every app: URL-safe
  (`[A-Za-z0-9_-]`), at least 16 characters. Only the data guard uses it, as the
  salt of hashed column masks (`sha256(salt || value)`); a gate-only app still
  needs it set. Generate one per app
  (`python -c "import secrets; print(secrets.token_urlsafe(32))"`). Use the same
  value as another app only if hashed values must be comparable between the
  two. On an upgrade keep an existing `#MASK_SALT` (changing it changes every
  hashed value the app shows); set one only if it is missing.

Never name the token secret `#KBC_TOKEN`: the runtime sets `KBC_TOKEN` itself
and skips a secret of that name.

## 10. Register the app — without grants

Skip if step 3 found the row. Never re-register an existing app: the CLI upsert
would reset its `access` to the default.

- **App in its own repo:** Access admin → **Apps → Discover Data Apps** → import
  it under the id from step 3. For an "everyone signed in" app, then **Edit →
  Open to everyone signed in**.
- **App in this repo** (or any config whose token may write the bucket):

  ```bash
  python -m kbc_access.cli register-app --app-id drug-sales-v2 --name "Drug sales v2" \
    --url https://drug-sales-v2.<stack>/ --project-id <project id> --config-id <data app config id> \
    [--access all_signed_in]
  ```

  It prints `"grants": "none — grant access in the admin app"` (or "not
  needed" with `all_signed_in`). That is correct.

Until someone grants access, everyone gets the deny page — the safe default.
A newer Access admin adds the `access` column to an older `apps` table on its
first write; the vendored code reads both shapes.

## 11. Deploy and verify

Nothing changes until the app is redeployed. Own repo: the user commits and
pushes (do not push for them unless asked), then
`kbagent data-app deploy --project <alias> --app-id <data app id> --wait`.
Check `kbagent data-app logs` for errors at start (`Missing required
environment variables: …` names a missing secret). Open the app as a granted
and as an ungranted user; decisions land in `logs/audit.jsonl` in the container.

## 12. Hand-off to the user

Tell the user, in this order:

1. What changed: installed / upgraded from X to Y / replaced the home-made
   check, and which files, secrets and tokens are now unused.
2. Who can open it: unchanged for an existing app; for a new app **nobody yet**
   (or everyone signed in).
3. Grant access in **Access admin → Grants** (a user, an IdP group or a local
   group). IdP groups must first exist in **Groups**, with the provider's group
   ID (Entra: object ID GUID; Okta: `00g…`).
4. Check a decision without logging in as that person: the access simulator on
   the Access admin overview, or (in this repo)
   `python -m kbc_access.cli check --email <email> --group <group id> --app-id <app id>`.
5. To upgrade later, re-run this skill: it reads the marker and upgrades.

## Locally (this repo)

The suite runs locally with a fake IdP in front of each app and a SQLite store
(deployed apps use the Keboola Storage tables):

```bash
.venv/bin/python scripts/init_secrets.py
.venv/bin/python scripts/seed.py --config config/local.toml --reset
.venv/bin/python scripts/dev.py --config config/local.toml
```
