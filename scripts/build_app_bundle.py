"""Build the git tree of one Keboola Data App from this repo.

    python scripts/build_app_bundle.py --app-id admin --out /tmp/admin-bundle \
        --stack-url https://connection.europe-west3.gcp.keboola.com \
        --bucket-id in.c-apps-control-plane \
        --app-url admin=https://access-admin-123.hub.europe-west3.gcp.keboola.com/ \
        --app-url launcher=https://app-launcher-124.hub.europe-west3.gcp.keboola.com/ \
        --roles-separator ,

The output directory is exactly what gets pushed to the app's Keboola-managed
git repo: the library, the app package, `pyproject.toml`, `keboola-config/`
(nginx on 8888 → uvicorn, supervisord, setup.sh) and `config/deployed.toml`
rendered from `deploy/templates/`. An app that declares a `frontend` in the
manifest ships that npm project's sources only (never `node_modules/` or
`dist/`); its setup.sh checks the container's Node.js version and builds the
frontend with `npm ci` + `npm run build` at deploy time. Every app of the suite that should appear
in links (at least the launcher) must be given with `--app-url`, because a
deployed app knows other apps only by their public Data App URL.

Nothing is guessed: every value comes from an argument or from
`deploy/suite.toml`. The output directory must not exist or must be empty.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tomllib
from pathlib import Path
from string import Template

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "deploy" / "suite.toml"
TEMPLATES = ROOT / "deploy" / "templates"
# node_modules/ and dist/ are local build state: a bundle never ships them, the
# container builds the frontend itself (see _frontend_block).
IGNORED = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", "node_modules", "dist")
NODE_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
# Highest phase of the suite whose apps this builder can deploy.
BUILDABLE_PHASE = 2
# Named in the header of the rendered deployed.toml.
GENERATED_BY = "scripts/build_app_bundle.py"


def _render(name: str, **values: str) -> str:
    return Template((TEMPLATES / name).read_text(encoding="utf-8")).substitute(values)


def load_manifest() -> dict:
    """deploy/suite.toml, parsed."""
    return tomllib.loads(MANIFEST.read_text(encoding="utf-8"))


def frontend_dir(manifest: dict, app_id: str) -> str | None:
    """The app's npm frontend directory (relative to the repo root), or None if it has none.

    Raises ValueError when the declared directory is not shipped with the app or is not a
    buildable npm project with a lockfile (`npm ci` refuses to run without one).
    """
    app = manifest["apps"][app_id]
    rel = app.get("frontend")
    if rel is None:
        return None
    rel_path = Path(rel)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise ValueError(f"App '{app_id}': frontend must be a relative path inside the repo, got '{rel}'")
    if not any(rel_path == Path(p) or Path(p) in rel_path.parents for p in app["paths"]):
        raise ValueError(f"App '{app_id}': frontend '{rel}' is not inside any of its paths {app['paths']}")
    src = ROOT / rel_path
    for required in ("package.json", "package-lock.json"):
        if not (src / required).is_file():
            raise ValueError(f"App '{app_id}': frontend '{rel}' has no {required} (npm ci needs a lockfile)")
    return rel_path.as_posix()


def node_min_version(manifest: dict) -> str:
    """The oldest Node.js that may build a frontend, from the manifest's `node_min_version`."""
    value = manifest.get("node_min_version")
    if value is None:
        raise ValueError(f"{MANIFEST.name}: node_min_version is required when an app declares a frontend")
    if not isinstance(value, str) or not NODE_VERSION.match(value):
        raise ValueError(f"{MANIFEST.name}: node_min_version must look like '22.12.0', got {value!r}")
    return value


def _frontend_block(manifest: dict, frontend: str | None) -> str:
    """setup.sh step that checks Node.js and builds the frontend in the container; empty without one."""
    if frontend is None:
        return ""
    return _render("setup_frontend.sh.tmpl", frontend_dir=frontend, node_min_version=node_min_version(manifest))


def apps_section(entries: dict[str, dict[str, object]]) -> str:
    """[apps.<id>] sections of deployed.toml, one per entry (keys: name, port, factory, protected, public_url).

    Shared with skills/protect-data-app/scripts/vendor_access.py, which renders the
    same config for an app that lives in its own repository.
    """
    lines: list[str] = []
    for app_id, entry in sorted(entries.items()):
        lines += [
            "",
            f"[apps.{app_id}]",
            f"name = {_toml_string(str(entry['name']))}",
            f"port = {int(entry['port'])}",  # type: ignore[call-overload]
            f"factory = {_toml_string(str(entry['factory']))}",
            f"protected = {'true' if entry['protected'] else 'false'}",
            f"public_url = {_toml_string(str(entry['public_url']))}",
        ]
    return "\n".join(lines) + "\n"


def _toml_string(value: str) -> str:
    """A TOML basic string (JSON string escaping is valid TOML for these values)."""
    return json.dumps(value, ensure_ascii=False)


def suite_app_entry(manifest: dict, app_id: str, url: str) -> dict[str, object]:
    """The [apps.<id>] values of one suite app, as the bundles carry them."""
    app = manifest["apps"][app_id]
    return {
        "name": app["name"], "port": manifest["internal_port"], "factory": app["factory"],
        "protected": app_id != "launcher", "public_url": url,
    }


def _apps_block(manifest: dict, app_urls: dict[str, str]) -> str:
    """[apps.<id>] sections for every app with a known URL (the one being built included)."""
    return apps_section({app_id: suite_app_entry(manifest, app_id, url) for app_id, url in app_urls.items()})


def render_deployed_config(
    *, app_id: str, stack_url: str, bucket_id: str, roles_separator: str, data_block: str, apps_block: str,
    generated_by: str,
) -> str:
    """config/deployed.toml from deploy/templates/deployed.toml.tmpl (Keboola Storage store, proxy identity)."""
    return _render(
        "deployed.toml.tmpl",
        generated_by=generated_by,
        app_id=app_id,
        stack_url=stack_url.rstrip("/"),
        bucket_id=bucket_id,
        roles_separator=roles_separator,
        data_block=data_block,
        apps_block=apps_block,
    )


def _data_block(manifest: dict, data_bucket_id: str) -> str:
    """[data] and [policy] sections for an app that reads the demo tables via Direct Storage Access."""
    data = manifest["data"]
    files = ", ".join(f'"{f}"' for f in data["policy_files"])
    tables = ", ".join(f'"{data_bucket_id}.{t}"' for t in data["tables"])
    return (
        "[data]\n"
        "# Pulled through Direct Storage Access at start and every refresh_seconds.\n"
        f"storage_access_tables = [{tables}]\n"
        f"refresh_seconds = {data['refresh_seconds']}\n"
        f'duckdb_path = "{data["duckdb_path"]}"\n'
        f'dialect = "{data["dialect"]}"\n'
        f"max_result_rows = {data['max_result_rows']}\n"
        f"max_query_chars = {data['max_query_chars']}\n\n"
        "[policy]\n"
        f"files = [{files}]\n"
    )


def _policy_block(manifest: dict) -> str:
    """[policy] section for an app that only reads the policy files (the admin's data catalogue)."""
    files = ", ".join(f'"{f}"' for f in manifest["data"]["policy_files"])
    return f"[policy]\nfiles = [{files}]\n"


def reads_data(manifest: dict, app_id: str, data_bucket_id: str | None) -> bool:
    """Whether the app's bundle gets [data] (and its config Direct Storage Access to the demo tables)."""
    app = manifest["apps"][app_id]
    return bool(app.get("reads_data") or (app.get("reads_data_if_available") and data_bucket_id))


def storage_access_grants(manifest: dict, data_bucket_id: str) -> list[dict[str, str]]:
    """storage.output.tables entries that give a dashboard Direct Storage Access to the demo tables."""
    return [{"destination": f"{data_bucket_id}.{t}", "unload_strategy": "direct-grant"} for t in manifest["data"]["tables"]]


def _app_data_block(manifest: dict, app: dict, data_bucket_id: str | None) -> str:
    if app.get("reads_data") or (app.get("reads_data_if_available") and data_bucket_id):
        return _data_block(manifest, data_bucket_id or "") + "\n"
    if app.get("reads_policy"):
        return _policy_block(manifest) + "\n"
    return ""


def build(
    *, app_id: str, out: Path, stack_url: str, bucket_id: str, app_urls: dict[str, str], roles_separator: str,
    data_bucket_id: str | None = None,
) -> Path:
    manifest = load_manifest()
    apps = manifest["apps"]
    if app_id not in apps:
        raise ValueError(f"Unknown app '{app_id}'. Known: {', '.join(sorted(apps))}")
    if apps[app_id]["phase"] > BUILDABLE_PHASE:
        raise ValueError(f"App '{app_id}' belongs to phase {apps[app_id]['phase']}, which this builder does not deploy yet")
    unknown = set(app_urls) - set(apps)
    if unknown:
        raise ValueError(f"--app-url for unknown app(s): {', '.join(sorted(unknown))}")
    for required in {app_id, "launcher"}:
        if required not in app_urls:
            raise ValueError(f"--app-url {required}=<url> is required (links need its public URL)")
    for url in app_urls.values():
        if not url.startswith("https://") or not url.endswith("/"):
            raise ValueError(f"App URLs must be https:// and end with '/': {url}")
    if apps[app_id].get("reads_data") and not data_bucket_id:
        raise ValueError(f"App '{app_id}' reads demo data: --data-bucket-id is required")
    if out.exists() and any(out.iterdir()):
        raise ValueError(f"Output directory {out} is not empty")
    # Validated before anything is written, so a broken frontend never yields a half-built bundle.
    frontend = frontend_dir(manifest, app_id)
    frontend_step = _frontend_block(manifest, frontend)

    out.mkdir(parents=True, exist_ok=True)
    for rel in [*manifest["common"], *apps[app_id]["paths"]]:
        src = ROOT / rel
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst, ignore=IGNORED)
        else:
            shutil.copy2(src, dst)

    app = apps[app_id]
    port = str(manifest["internal_port"])
    (out / "config").mkdir(exist_ok=True)
    (out / "config" / "deployed.toml").write_text(
        render_deployed_config(
            app_id=app_id,
            stack_url=stack_url,
            bucket_id=bucket_id,
            roles_separator=roles_separator,
            data_block=_app_data_block(manifest, app, data_bucket_id),
            apps_block=_apps_block(manifest, app_urls),
            generated_by=GENERATED_BY,
        ),
        encoding="utf-8",
    )
    (out / "pyproject.toml").write_text(
        _render(
            "pyproject.toml.tmpl",
            app_id=app_id,
            app_name=app["name"],
            dependencies="\n".join(f'    "{d}",' for d in manifest["dependencies"]),
        ),
        encoding="utf-8",
    )
    nginx = out / "keboola-config" / "nginx" / "sites"
    supervisor = out / "keboola-config" / "supervisord" / "services"
    nginx.mkdir(parents=True)
    supervisor.mkdir(parents=True)
    (nginx / "default.conf").write_text(_render("nginx.conf.tmpl", internal_port=port), encoding="utf-8")
    (supervisor / "app.conf").write_text(
        _render("supervisord.conf.tmpl", factory=app["factory"], internal_port=port), encoding="utf-8"
    )
    setup = out / "keboola-config" / "setup.sh"
    setup.write_text(
        _render("setup.sh.tmpl", frontend_build=frontend_step),
        encoding="utf-8",
    )
    setup.chmod(0o755)
    (out / ".gitignore").write_text("logs/\n.venv/\n__pycache__/\n", encoding="utf-8")
    return out


def _parse_app_urls(values: list[str]) -> dict[str, str]:
    urls: dict[str, str] = {}
    for value in values:
        app_id, sep, url = value.partition("=")
        if not sep or not app_id or not url:
            raise ValueError(f"--app-url expects <app_id>=<url>, got '{value}'")
        urls[app_id] = url
    return urls


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--app-id", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--stack-url", required=True)
    parser.add_argument("--bucket-id", required=True)
    parser.add_argument("--app-url", action="append", default=[], required=True)
    parser.add_argument("--roles-separator", required=True)
    parser.add_argument("--data-bucket-id", help="bucket with the demo tables (dashboards only)")
    args = parser.parse_args(argv)
    try:
        out = build(
            app_id=args.app_id,
            out=args.out,
            stack_url=args.stack_url,
            bucket_id=args.bucket_id,
            app_urls=_parse_app_urls(args.app_url),
            roles_separator=args.roles_separator,
            data_bucket_id=args.data_bucket_id,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
