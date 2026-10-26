# Data App access control — merged design

- **Status:** DRAFT, not approved. No code until approved.
- **Date:** 2026-09-23
- **Supersedes:** the 2026-09-14 `kbc_guard` design (row/column security only, never written to disk; its content is folded in here as layer 4)
- **Sources** (verbatim transcripts in `docs/requirements/`, kept local and not published):
  - `2026-09-23-access-control-voice-brief.md` — who may open which app: ACL in a Keboola table, admin app, launcher, demo dashboards, skill
  - `2026-09-09-okta-data-app-authorization-call.md` — one shared Okta app as a gateway, authorization inside the app by reading `X-Kbc-User-Roles`, launcher as the Okta tile target
  - `2026-07-29-login-and-row-level-security-voice-note.md` — company → datasets → reports → tables → rows; rows flagged `public`/`private` and matched on a `company` column
  - the 2026-09-14 session design (principal, entitlement attributes, policy YAML, SQL rewriter, audit) and its explainer artifact

## 1. The problem in one paragraph

Today a Keboola Data App knows only one thing about the viewer: that the proxy let them through. Access is "everyone behind this OIDC app" and the warehouse sees one shared workspace identity for all viewers. Customers want two things the platform does not give them: **(a) which people may open which app**, managed by an admin rather than by pasting group IDs into app code, and **(b) which rows and columns each person sees inside an app**. Both must be answered from the same identity and the same source of truth, or they drift apart.

## 2. The model — four questions, asked in order

Every request to a protected app answers four questions. Each is a separate layer, testable alone, and each one fails closed.

| # | Question | Layer | Answered from | Failure → |
|---|---|---|---|---|
| 1 | Who is asking? | Identity | `X-Kbc-*` headers set by the apps-proxy | 401 page |
| 2 | May they open *this* app? | App gate | ACL table in Storage | "Sorry, you can't get in here" page |
| 3 | Which datasets, rows and columns may they see? | Data guard | policy + user attributes table | dataset absent / zero rows / column absent |
| 4 | What did we decide? | Audit | — | written for every decision above |

Layer 2 is the new requirement from the 2026-09-23 brief. Layer 3 is the 2026-09-14 design, extended with the report and `public`/`private` model from 2026-07-29. Layers 1 and 4 are shared, which is the point of merging: one principal, one audit trail.

### 2.1 Layer 1 — Identity (shared)

- **Login is OIDC via the apps-proxy.** One OIDC app registration (Entra or Okta) is shared by many Data Apps; managing its redirect URLs is outside this project (brief 02:00). The proxy authenticates and forwards `X-Kbc-User-Email` and `X-Kbc-User-Roles` (the IdP `groups` claim).
- **Principal** = `{email, groups[], attributes{}}`. Groups come from the headers; attributes come from Storage (layer 3).
- **Only `X-Kbc-*` headers are trusted.** The proxy strips client-sent `x-kbc-*` but does not strip `X-Forwarded-*`; any other identity-looking header is logged as hostile and ignored. (To be verified in Phase 0.)
- **Missing email or missing roles header → 401.** Never fall back to a default user.
- The 2026-07-29 note considered an in-app username/password login for a customer without an IdP. **Out of scope for v1** (see open question Q1); the principal is built so a second identity source could be added later without touching layers 2–4.

### 2.2 Layer 2 — App gate (new)

A mandatory function, `require_app_access(principal, app_id)`, is the first thing every protected app runs. It reads the ACL and either continues or renders the deny page. This replaces per-app env vars with required roles — the brief explicitly drops that approach (06:35) in favour of the table.

**Grant kinds** (brief 02:27): a specific **user** may open an app, or a **group** may open an app. Access = union of user grants and grants of every group the principal is in. No grant → denied.

**Groups are matched by their IdP identifier**, not display name, because names are mutable and not unique. Each group row records its provider, and the admin app validates the identifier with a provider template (brief 04:01):
- Entra: object ID, a GUID — `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` (case-insensitive).
- Okta: **to research in Phase 0.** Okta group IDs look like `00g…` (20 chars), but Okta's `groups` claim emits group *names* by default unless the claim is configured otherwise — which of the two reaches `X-Kbc-User-Roles` decides whether we match on ID or on name.
- Entra "groups overage": a user in more than ~200 groups gets a link instead of the groups claim. Phase 0 must check what the proxy forwards in that case; if it is empty, the user is denied, not admitted.

**Scope: one Keboola project.** The ACL lives in one project and apps in that project read it (brief 06:18). Discovery (below) lists only this project's apps (decided 2026-09-30), and enforcement for an app in another project would need that app to read this project's table — see open question Q3.

**Caching:** the gate caches the ACL for a short, configured TTL so a revoked grant takes effect within that TTL. The TTL is config, not a constant.

**The launcher is not a security boundary.** It only lists links. Every target app re-runs the gate, so a user who guesses a URL gets the same answer as one who clicks.

### 2.3 Layer 3 — Data guard (from 2026-09-14, extended)

The unchanged core: **the only identity the app has lives in an HTTP request, so the row filter must end up inside the SQL text** — the warehouse cannot tell viewers apart.

**Authorization chain** (2026-07-29 note, 02:10): principal → **reports** they may see → **datasets** each report reads → **row rule and column rules** per dataset. In this design a "report" is simply a protected app or a page inside one, so the report→user link *is* the layer-2 ACL; layer 3 only adds dataset, row and column rules.

**User attributes** come from a Storage table (`user_attributes`: email, key, value), e.g. `company`, `branch_code`, `clearance`. Groups *select* a rule; attributes *parameterise* it. Missing attribute → denied, never `NULL` (a `NULL` inside a `NOT(...)` restrictive rule can widen access).

**Policy document** — one YAML per protected dataset set, validated at startup and fingerprinted into every audit line. PostgreSQL RLS semantics:
- default deny: a dataset with no matching grant does not exist for the principal (absent from the schema endpoint too);
- permissive grants union, restrictive grants intersect and can never grant;
- a row rule may reference a column the principal cannot read.

The 2026-07-29 row model becomes the first built-in rule shape, not a special case:

```yaml
datasets:
  drug_sales:
    source: in.c-demo.drug_sales
    grants:
      - to: { group: any_authenticated }
        rows: "visibility = 'public' OR (visibility = 'private' AND company = :attr.company)"
        columns: { margin: mask_hash, customer_id: absent }
```

**Compiler** `policy × principal → secured relation` per dialect (Snowflake, BigQuery, DuckDB); attribute values rendered as dialect-owned, adversarially tested literals because Query Service has no parameter binding.

**Rewriter** — the chokepoint: `sqlglot` parse, whitelist relation names, replace every table node at any depth (CTEs, subqueries, UNION branches), refuse CTEs shadowing a dataset name, one read-only statement only, deny `information_schema` and file/external functions.

**Scalability concern** raised on 2026-07-29 (01:14): hand-mapping many packages × tables × users. Answer: rules are written per *shape* (one rule reused across all tables that carry `visibility` + `company`), attributes come from a table refreshed by a flow, and the admin app can suggest rules from column names — suggestion only, a human approves.

### 2.4 Layer 4 — Audit (shared)

One JSON line per decision to `logs/`, for both gate and guard: timestamp, email, app_id, decision, matched grants (user/group ids), datasets touched, columns masked/absent, policy fingerprint, query hash. **No row values, no attribute values.** A test asserts that no fixture value ever appears in a log line.

## 3. Data model (Storage tables, one bucket, one project)

| Table | Columns | Written by |
|---|---|---|
| `apps` | app_id, name, url, project_id, config_id, source (`manual`\|`discovered`), active, access (`grants`\|`all_signed_in`; added 2026-10, a missing value reads as `grants`) | admin app; discovery |
| `users` | email, display_name, active | admin app (manual, brief 04:01) |
| `groups` | group_id, provider (`entra`\|`okta`), external_id, name | admin app (manual, validated by provider template) |
| `app_grants` | app_id, subject_type (`user`\|`group`), subject_id, granted_by, granted_at | admin app |
| `user_attributes` | email, key, value | flow from HR/IAM, or admin app |

Policy YAML (layer 3) stays in the repo, not in a table, in v1: it is security-relevant code and should be reviewed and versioned like code. See Q4.

## 4. Deliverables

1. **`kbc_access` library** (Python) — layers 1–4: `identity`, `gate`, `policy`, `compiler`, `rewriter`, `audit`, `backends/{query_service,duckdb}`, plus a thin Streamlit/FastAPI helper so an app protects itself in one call.
2. **Admin app** — CRUD for apps, users, groups (with provider templates) and grants; view of who can open what; **discovery** of this project's Data Apps with the Storage token the app already has (decided 2026-09-30: no Manage token, no other projects) — names come from the apps' configs when the token may read them, otherwise from the URL slug, editable before import.
3. **Launcher app** — lists every app the principal may open, from `app_grants`; the natural target for the Okta/Entra tile (2026-09-09 call, 22:29).
4. **Two demo dashboards** with fake data — both behind the gate; at least one uses the data guard with the `public`/`private` + `company` rule so two users visibly see different rows and columns.
5. **Skill extension** for the Data App creation skill — when it scaffolds an app, it wires in `require_app_access` and the app's `app_id`, and registers the app in `apps`. It does **not** ask for groups: grants are set in the admin app (brief 05:21–05:50).

All four apps run as Keboola Data Apps behind the same shared OIDC app.

## 5. Build order

TDD throughout; for the rewriter, the adversarial test is written first and must fail before the fix.

- **Phase 0 — spike (answers, not code).** What exactly the apps-proxy forwards in `X-Kbc-User-Roles` for Entra and for Okta (IDs or names, overage case); that it strips client-sent `x-kbc-*` and passes `X-Forwarded-*` through; Manage API calls for listing an organization's projects and each project's Data Apps, and the token scope required; whether a Data App can write Storage tables (admin app) and read them cheaply (gate); whether Query Service accepts arbitrary nested `SELECT`; `sqlglot` round-trip fidelity for Snowflake and BigQuery.
- **Phase 1 — identity + app gate.** Principal extraction, hostile-header handling, ACL tables, `require_app_access`, deny page, audit lines for gate decisions. First demonstrable result: two users, one gets in, one gets the deny page.
- **Phase 2 — admin app + launcher.** CRUD, provider templates, grants view, launcher listing. Discovery behind a feature flag.
- **Phase 3 — demo dashboards.** Two fake-data dashboards behind the gate.
- **Phase 4 — data guard: policy + compiler.** YAML schema and validation, `user_attributes` loader, the `public`/`private` + `company` rule shape.
- **Phase 5 — rewriter + adversarial suite.** CTE shadowing, UNION reach-around, nested subqueries, `information_schema`, quote injection through attribute values, multi-statement, denied-column selection.
- **Phase 6 — backends.** Query Service and DuckDB behind one interface, same rewriter.
- **Phase 7 — skill extension.**
- **Phase 8 — real-project proof.** Deploy to a real Keboola project with a real IdP; two real users see different apps in the launcher and different rows/columns in the same dashboard.

Phases 1–3 alone deliver the 2026-09-23 brief. Phases 4–6 add row/column security on top without changing 1–3.

## 6. What this does not protect against

- Anyone who can change app code or merge to `main` can bypass the gate and the guard; enforcement is in the app, not the warehouse.
- The app's Storage token sees everything granted to its workspace. Native Snowflake row-access/masking policies would be stronger but need the warehouse session to know the end user, which the platform does not provide today. The policy YAML is kept shaped so it could later emit native policies.
- Discovery reads only this project's Data Apps list with the app's own Storage token; it creates no tokens and writes nothing outside the control-plane bucket.

## 7. Open questions

- **Q1.** In-app username/password login (2026-07-29) — drop for v1 and require OIDC everywhere? Proposed: yes, drop.
- ~~**Q2.** Discovery with a Manage token~~ — decided 2026-09-30: no Manage token; discovery is project-scoped with the app's Storage token.
- **Q3.** Apps in *other* projects — enforce them from this project's ACL (cross-project read), or limit v1 to one project? Proposed: one project in v1; discovery only lists.
- **Q4.** Row/column policy — YAML in the repo (reviewed like code) or editable in the admin app? Proposed: YAML in v1.
- **Q5.** Demo data shape — the 2026-07-29 pharma shape (drug sales, supply chain, stores; companies as tenants) or the banking shape from 2026-09-14 (loans, branches, masked national ID)? Proposed: pharma, since it carries the `company` rule.
- **Q6.** Target Keboola project and IdP (Entra or Okta) for Phase 8.
