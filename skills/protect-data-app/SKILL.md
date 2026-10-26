---
name: protect-data-app
description: Wires access control into a Keboola Data App while it is being created — the app gate (who may open it, from the ACL table managed in the access admin app) and, for apps that show data, the row/column-security data guard. Use together with keboola-data-app or dataapp-deployment whenever a new Data App is scaffolded or an existing one must stop being "everyone behind the OIDC app", or when someone says "protect this app", "only finance should see this", "add access control", "row level security in the app", "chraň appku", "přístupy do appky". Not for managing who has access (that is done in the access admin app), and not for configuring the OIDC provider or its redirect URLs.
---

# Protect a Data App

Extends the Data App creation skills. Every app it touches gets exactly two
things: a **gate** that runs before any page, and (if the app shows warehouse
data) the **data guard** so each viewer sees only their rows and columns.

**The one rule that shapes everything:** this skill never decides *who* may
open the app. It does not ask for groups, does not write required roles into
env vars or code. It registers the app and wires the check; access is granted
by an administrator in the **Access admin** app. (That split comes from the
product brief: asking for groups at creation time is the wrong place — the
admin app is the source of truth.)

The one question it does ask: **is the app for everyone who has an account in
the identity provider?** Some apps (a company-wide report) are meant for the
whole company; granting everyone one by one would defeat the point. Such an
app is registered with `access = all_signed_in`: the gate still runs and
requires a signed-in user (and still blocks deactivated users), but no grant
is needed. An admin can switch it either way later in **Access admin → Apps →
Edit → Open to everyone signed in**.

## Checklist

Copy into the reply and tick off:

- [ ] 1. Pick the app id (lowercase, `[a-z0-9_-]`, ≤ 64) and confirm it with the user
- [ ] 1b. Ask: "For everyone with an account in the IdP, or only for users granted in Access admin?"
- [ ] 2. Add the gate to every route
- [ ] 3. If the app reads warehouse data: route every query through the data guard
- [ ] 4. Keep the Keboola health check (`POST /` → 200) outside the gate
- [ ] 5. Register the app (no grants; `--access all_signed_in` if the answer to 1b was "everyone")
- [ ] 6. Tell the user to grant access in the Access admin app (or that everyone signed in can open it), and how to test it

## 1. App id

The id is the key in the `apps` table and in every audit line. Derive it from
the app name (`Drug sales v2` → `drug-sales-v2`) and confirm. For an app found
by discovery in the admin app the id is `kbc-<project id>-<app id>`; reuse it.

## 2. Gate — Python (FastAPI)

```python
from fastapi import Depends, FastAPI, Request
from kbc_access.identity import Principal
from kbc_access.web import build_runtime, install

APP_ID = "drug-sales-v2"

def create_app(runtime) -> FastAPI:
    app = FastAPI()
    access = install(app, runtime, app_id=APP_ID, templates_dir=None)  # adds POST / health check + 401/403 pages

    @app.get("/")
    def home(request: Request, principal: Principal = Depends(access.require)):
        ...
    return app

def create_default() -> FastAPI:  # uvicorn --factory target
    return create_app(build_runtime())
```

`access.require` builds the principal **only** from `X-Kbc-User-Email` /
`X-Kbc-User-Roles` (set by the Keboola apps-proxy) and runs the gate. Never
read `X-Forwarded-*` or any other identity header — the proxy does not strip
them, so they are spoofable; the library audits their presence as hostile.

Add the app to `[apps]` in the suite config (`name`, `port`, `public_port`,
`factory`, `protected = true`).

### Gate — Streamlit

Streamlit has no dependency injection; check once at the top of the script:

```python
import streamlit as st
from kbc_access.identity import IdentityError, principal_from_headers
from kbc_access.web import build_runtime

runtime = st.cache_resource(build_runtime)()
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

## 3. Data guard (apps that show data)

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
the `user_attributes` table — row rules bind them as `:company`. If a dataset
the app needs is not in the policy yet, add it to the policy YAML
(`config/policies/*.yaml`) in the same change — it is code and gets reviewed
like code. A dataset with no matching grant simply does not exist for the
viewer; design pages to handle "dataset not visible" and `NULL` in masked
columns instead of crashing.

## 4. Health check

Keboola probes Data Apps with `POST /`. `install()` registers it outside the
gate; do not add another `POST /` route.

## 5. Register the app — without grants

```bash
python -m kbc_access.cli register-app --app-id drug-sales-v2 --name "Drug sales v2" \
  --url https://drug-sales-v2.<stack>/ --project-id <project id> --config-id <data app config id>
```

It prints `"grants": "none — grant access in the admin app"`. That is correct.
Until someone grants access, everyone gets the deny page — the safe default.

For an app the user wants open to everyone signed in (step 1b), add
`--access all_signed_in`; it prints `"grants": "not needed — everyone signed in
may open it"`. Ask rather than assume: the default stays "grants only".

## 6. Hand-off to the user

Tell the user, in this order:

1. The app is registered and **nobody can open it yet**.
2. Grant access in the **Access admin → Grants** page (a user or an IdP group).
   Groups must first exist in **Groups**, with the provider's group ID
   (Entra: object ID GUID; Okta: `00g…`).
3. Check the result without logging in as that person:
   `python -m kbc_access.cli check --email <email> --group <group id> --app-id <app id>`
   or the access simulator on the admin overview page.
4. The launcher lists the app for everyone who got access.

## Locally

The whole suite runs locally with a fake IdP in front of each app:

```bash
.venv/bin/python scripts/init_secrets.py
.venv/bin/python scripts/seed.py --config config/local.toml --reset
.venv/bin/python scripts/dev.py --config config/local.toml
```

Limitation to state when relevant: the access store is SQLite locally; the
Keboola Storage-table implementation of the same five tables is not built yet.
