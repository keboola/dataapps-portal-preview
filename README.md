# Data Apps access portal (preview)

Per-user access control for [Keboola Data Apps](https://help.keboola.com/components/data-apps/).
A Data App behind the Keboola apps-proxy normally lets in everyone who passes the
OIDC login. This project adds what comes after the login:

- **App gate**: who may open which app. Grants go to user emails, IdP groups
  (Entra, Okta, ...) or local groups, and they live in Keboola Storage tables.
- **Data guard**: what each viewer sees inside an app. Row access lines and
  per-column masks are compiled into a secured relation per viewer, and every
  dashboard query is rewritten to read it instead of the physical table.
- **Access admin**: a Data App where an administrator manages apps, users,
  groups, grants and dataset security, simulates access ("Test as a user") and
  reads the audit log.
- **App launcher**: a portal listing every app the signed-in user may open,
  meant as the target of the company IdP tile.

Identity comes only from the `X-Kbc-User-Email` and `X-Kbc-User-Roles` headers
set by the Keboola apps-proxy. Every decision is written to an audit log.

## Repository layout

| Path | What it is |
|---|---|
| `src/kbc_access/` | The library: identity, gate, policy, compiler, query rewriter, data guard, Storage-backed store, audit, Data App discovery |
| `apps/admin/` | Access admin: FastAPI JSON API plus a React frontend (`apps/admin/frontend`, `@keboola/design`) |
| `apps/launcher/` | App launcher |
| `apps/sales/`, `apps/supply/` | Two demo dashboards protected by the gate and the data guard |
| `apps/gateway/` | Fake apps-proxy with a fake OIDC login, for local development only |
| `config/` | Local configuration, demo personas (`fake_users.yaml`) and dataset policies |
| `deploy/` | Settings and templates used to build each app's Keboola Data App bundle |
| `scripts/` | Local dev runner, demo seed, secrets init, app bundle and skill builders |
| `skills/` | Claude Code skills: `keboola-access-suite` installs the suite into a project, `protect-data-app` wires the gate and data guard into a new app |
| `docs/superpowers/specs/` | Design documents |

## Running locally

Requires Python 3.12, Node.js with npm (for the admin frontend) and
[uv](https://docs.astral.sh/uv/) or pip.

```bash
python -m venv .venv
.venv/bin/pip install -e . "fastapi~=0.141.1" "uvicorn[standard]~=0.53.0" "httpx~=0.28.1" \
  "jinja2~=3.1.6" "pydantic~=2.13.5" "pyyaml~=6.0.3" "sqlglot~=30.19.0" "duckdb~=1.5.5" \
  "python-multipart~=0.0.32" "keboola-query-service~=0.3.0" itsdangerous pytest
```

The runtime dependency list is kept in `deploy/suite.toml`.

```bash
.venv/bin/python scripts/init_secrets.py        # creates secrets.local.env (once)
.venv/bin/python scripts/seed.py --config config/local.toml
.venv/bin/python scripts/dev.py --config config/local.toml
```

`seed.py` builds a fake pharma warehouse in DuckDB and a pre-filled access store.
`dev.py` starts every app with a fake apps-proxy in front of it. Open the launcher
at http://127.0.0.1:8801 and sign in as one of the personas from
`config/fake_users.yaml` to see how access and data differ per user.

## Tests

```bash
.venv/bin/pytest
cd apps/admin/frontend && npm ci && npm test
```

## Deploying to Keboola

The `keboola-access-suite` skill installs the suite into a Keboola project with
the `kbagent` CLI: it creates the control-plane
bucket and tables, then deploys the Access admin and the App launcher as Data Apps
from Keboola-managed git. See `skills/keboola-access-suite/SKILL.md`. To protect
an additional app, follow `skills/protect-data-app/SKILL.md`.

## Status

This is a preview. Interfaces, table schemas and the deployment flow may still change.
