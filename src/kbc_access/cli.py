"""Command line for scripts and skills: register an app, explain a gate decision.

    python -m kbc_access.cli register-app --app-id sales-v2 --name "Sales v2" --url http://... [--access all_signed_in]
    python -m kbc_access.cli check --email petr.sales@pharma-a.example --group <idp group id> [--app-id sales]

Reads KBC_ACCESS_CONFIG and the secrets like every app. `register-app` only
registers the app — it grants nobody: grants are made in the admin app. That
split is deliberate (voice brief 2026-09-23, 05:21–05:50): the skill that
creates an app must not decide who may open it. The one exception is
`--access all_signed_in`, for an app meant for everyone the IdP signs in (asked
when the app is protected); an admin can switch it back in the admin app.
"""

from __future__ import annotations

import argparse
import json
import sys

from kbc_access.gate import decide
from kbc_access.identity import Principal
from kbc_access.store import ACCESS_GRANTS, APP_ACCESS, App, StoreError
from kbc_access.web import build_runtime


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kbc_access.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    reg = sub.add_parser("register-app", help="add or update an app in the apps table")
    reg.add_argument("--app-id", required=True)
    reg.add_argument("--name", required=True)
    reg.add_argument("--url", required=True)
    reg.add_argument("--project-id", required=True)
    reg.add_argument("--config-id", required=True)
    reg.add_argument(
        "--access", choices=APP_ACCESS, default=ACCESS_GRANTS,
        help="grants (default): only granted principals; all_signed_in: anyone the IdP signed in",
    )

    chk = sub.add_parser("check", help="print the gate decision for a principal")
    chk.add_argument("--email", required=True)
    chk.add_argument("--group", action="append", default=[], help="IdP group id; repeatable")
    chk.add_argument("--app-id", help="one app; default: every registered app")

    args = parser.parse_args(argv)
    runtime = build_runtime()

    if args.command == "register-app":
        try:
            runtime.store.upsert_app(
                App(args.app_id, args.name, args.url, args.project_id, args.config_id, "manual", True, args.access)
            )
        except StoreError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        runtime.audit.admin(email="cli", action="register_app", target=args.app_id)
        if args.access == ACCESS_GRANTS:
            print(json.dumps({"registered": args.app_id, "grants": "none — grant access in the admin app"}))
        else:
            print(json.dumps({"registered": args.app_id, "access": args.access, "grants": "not needed — everyone signed in may open it"}))
        return 0

    snapshot = runtime.store.snapshot()
    principal = Principal(email=args.email.strip().lower(), groups=frozenset(args.group))
    app_ids = [args.app_id] if args.app_id else sorted(snapshot.apps)
    for app_id in app_ids:
        d = decide(snapshot, principal, app_id)
        print(json.dumps({"app_id": app_id, "allowed": d.allowed, "reason": d.reason, "matched": list(d.matched)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
