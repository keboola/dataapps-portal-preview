---
name: keboola-access-suite
description: Installs per-user access control for Keboola Data Apps into a Keboola project, creating the control-plane bucket and tables, an Access admin app and an App launcher with the login type the user picks (OIDC, GitHub, GitLab, password or public), deployed from Keboola-managed git via kbagent. Use when someone wants to set up app access management, "who can open which data app", an app launcher or portal, or says "nainstaluj správu přístupů do data apek", "access control pro data appky", "rozcestník appek". Not for protecting one existing app (use protect-data-app) and not for configuring the identity provider itself.
---

# Keboola access suite — install

Puts the Data App access-control suite into one Keboola project:

- **Phase 1 (this skill):** a control-plane bucket with nine tables (`apps`,
  `users`, `groups`, `app_grants`, `user_attributes`, `local_groups`,
  `local_group_members`, `row_access_rules`, `column_masks`), the **Access admin**
  app (who may open which app) and the **App launcher** app (every app a person
  may open), with the login type the user chooses.
- **Phase 2:** demo data (a second bucket), and two demo dashboards (drug
  sales, supply chain) with row/column security, optionally granted to one IdP
  group. Runs after phase 1 (see "Phase 2" below).

All work goes through `scripts/install.py`, which drives **kbagent**. The script
is idempotent: a re-run reuses the bucket, tables and apps it finds and only
rotates the Storage token and redeploys.

## Checklist

Copy into the reply and tick off:

- [ ] 1. Preconditions checked
- [ ] 2. Project chosen and confirmed
- [ ] 3. Install parameters collected (bucket, login type, first admin)
- [ ] 4. Plan shown and confirmed by the user
- [ ] 5. Installed (`--yes`)
- [ ] 6. Login configured in the Keboola UI, verified in the launcher

## 1. Preconditions

```bash
kbagent --version && uv --version && git --version
kbagent --json project list
```

- The kbagent token for the project must be able to mint tokens
  (`canManageTokens`) and create app git credentials (an admin/master token).
  If `token create` or `git-credentials-create` answer 403, stop and say which.
- Refresh the bundled code if you are working from the repo:
  `python scripts/build_skill.py` (repo root). An installed skill already
  carries it in `assets/suite/`; if that folder is missing, stop.

## 2. Project

List projects with `kbagent --json project list`, propose the one whose name
matches what the user said, and **confirm alias, name and id with the user**.
Never hardcode a project.

## 3. Parameters to collect

Ask only for what you cannot read yourself:

| Parameter | Flag | Notes |
|---|---|---|
| Bucket name | `--bucket-name` | Offer the default **`apps-control-plane`** (→ `in.c-apps-control-plane`); the user may choose another. |
| Login type | `--auth` | Offer **every** type the Keboola apps-proxy supports (table below) and let the user pick. |
| First admin | `--admin-email` | gets the admin app directly — the email **exactly as the login reports it** (see below) |
| Admin group | `--admin-group-provider`, `--admin-group-id`, `--admin-group-name` | optional; an IdP group whose members all get the admin app |
| Slugs | `--admin-slug`, `--launcher-slug` | defaults `access-admin`, `app-launcher`; they become part of the URL — confirm before creating |

Login types (`--auth`):

| Value | What it is | Sends user identity? | Who configures it |
|---|---|---|---|
| `oidc` | OpenID Connect — Entra ID, Okta, Google Workspace, any OIDC IdP | yes (email, groups) | the user, in the Keboola UI after install |
| `github` | GitHub login | yes (email; groups to be verified) | the user, in the Keboola UI after install |
| `gitlab` | GitLab login | yes (email; groups to be verified) | the user, in the Keboola UI after install |
| `password` | one shared password per app | **no** | the installer |
| `public` | no login | **no** | the installer |

**Identity is the email.** Users, grants and the first admin are keyed by the
`email` claim — the only identity the Keboola proxy forwards (hardcoded, not
configurable per app). With Entra ID that is the user's **mail** attribute
(e.g. `jane.doe@company.com`), not the sign-in name / UPN
(`jane.doe@company.onmicrosoft.com`); Entra sends it automatically for the
`email` scope the proxy requests, no claim configuration needed. Ask for the
address the user receives mail at as `--admin-email`. A user **without** a mail
attribute gets no `email` claim and cannot sign in to the apps — give them a
mail attribute in Entra. After the first sign-in, the Email row of the
launcher's "What the launcher knows about you" shows exactly what arrived.

**Never ask for client IDs or secrets in chat** — for `oidc`, `github` and
`gitlab` the user enters them in the Keboola UI (Data App → Authentication).
Until they do, the installer keeps both apps behind a generated password, so
nothing is exposed. Say plainly that with `password` or `public` the apps
cannot tell who the user is, so the access check lets nobody in; those modes
only make sense as a temporary state.

## 4. Plan, then confirm

Run from this skill's directory, **without `--yes`**:

```bash
uv run --with httpx --with pydantic --with pyyaml --with duckdb python scripts/install.py phase1 \
  --project "<alias>" --state-file .kbc-access-suite/<alias-slug>.json \
  --bucket-name apps-control-plane --auth oidc --admin-email "<email>"
```

It prints the plan (project, bucket, tables, token scope, app names, slugs,
login type, first admin) and changes nothing. Show it and ask for a clear yes: the
run creates a bucket, a Storage token and two Data Apps in the project.

## 5. Install

The same command with `--yes`. Progress goes to stderr as `[n/9] …`; deploys
take a few minutes (the admin app's web UI ships as sources and is built with
`npm ci` + `npm run build` by its setup.sh inside the container). The JSON on stdout has both app URLs and a
`next` list of what the user still has to do. Keep the state file (ids and URLs only, no
secrets) — it makes a re-run exact.

On failure the message names the step; fix the cause and re-run the same
command. Known cases:

- `No managed git repo URL … yet` — the platform provisions repos
  asynchronously; wait a minute, re-run.
- a deploy stuck in `StartupProbeFailed` — read `kbagent data-app logs
  --project <alias> --app-id <id>`; the usual cause is a wrong secret or
  bucket, which a re-run rewrites.
- the admin deploy failing in setup with `Node.js … is too old` or an npm
  error — the container's Node.js is older than `node_min_version` in
  `deploy/suite.toml`, or the frontend build broke; the log names which.

## 6. After install

Relay the `next` steps. For `oidc` / `github` / `gitlab`:

1. In Keboola, open each app → **Authentication**, choose the type, enter the
   provider details (`references/idp-setup.md` explains what the IdP side
   needs), and redeploy the app.
2. Register the redirect URI of each app at the provider:
   `https://<app host>/_proxy/callback` (printed in `next`).
3. Open the launcher and sign in as the first admin: it must list **Access
   admin**. Its "What the launcher knows about you" table shows the groups the
   proxy sent — check each group appears **as its own entry**. If they arrive as
   one long value, the proxy joins them differently: re-run with
   `--roles-separator "<sep>"`.
4. In the admin app: add users, groups (by IdP group ID) and grants. The
   launcher and every app follow within `cache_ttl_seconds` (30 s).

## Phase 2 — demo data and dashboards

Only after phase 1 is healthy. Same state file; ask for the demo bucket name
(default **`apps-control-plane-demo`**) and, optionally, one IdP group that
should get both dashboards. Plan first, then `--yes`:

```bash
uv run --with httpx --with pydantic --with pyyaml --with duckdb python scripts/install.py phase2 \
  --project "<alias>" --state-file .kbc-access-suite/<alias-slug>.json \
  [--grant-group-provider entra --grant-group-id <group id> --grant-group-name <name>]
```

What it does: generates the demo tables and (re)loads them into the demo
bucket; creates **Drug sales dashboard** and **Supply chain dashboard** on
managed git; gives them **Direct Storage Access** to the demo tables
(`storage.output.tables` with `unload_strategy: "direct-grant"` and
`runtime.workspace.enabled: true` — never input mapping); at start and every
30 minutes each dashboard pulls the tables through the Query Service into a
local DuckDB and the data guard serves every query from it (the Keboola
"DuckDB-cached RO" pattern); gives them a Storage token that can only **read**
the access tables (`#ACCESS_STORAGE_TOKEN` — never `#KBC_TOKEN`, which the
runtime reserves for its own token); copies the admin app's login (OIDC etc.)
when it has one; deploys; registers both dashboards and grants them to the
group; finally gives the **Access admin** read access to the demo tables too and
redeploys it, so its security editor can preview what a user sees. Note:
Keboola's direct grant is read **and** write on those tables — the dashboards'
SQL is still read-only because every query goes through the rewriter, which
accepts SELECT only.

Tell the user afterwards: row-level rules use the user attribute `company`
(`PHARMA_A` / `PHARMA_B` / `PHARMA_C`) — set it per user in the admin app,
otherwise a user sees only public rows; the policy's "finance" and
"supply-chain" group IDs are demo placeholders, so those grants apply to nobody
until the policy file is edited to real group IDs.

## Updating an installed suite

To ship newer suite code (a new admin feature, a guard fix) to apps that are
already installed, without touching the bucket, tokens, secrets, login, grants
or data:

```bash
uv run --with httpx --with pydantic --with pyyaml --with duckdb python scripts/install.py redeploy \
  --project "<alias>" --state-file .kbc-access-suite/<alias-slug>.json [--apps admin,sales,supply]
```

Without `--yes` it prints which apps it would redeploy. With `--yes` it first
sets each app's Direct Storage Access grants to what it needs (only `storage` and
the workspace flag of the config change), then builds each bundle, pushes it to
the app's managed git repo and redeploys. Run
`python scripts/build_skill.py` first when working from the repo.

## What this skill does not do

- Configure the login provider — the user does that in the Keboola UI.
- Protect other existing apps — that is the `protect-data-app` skill.
