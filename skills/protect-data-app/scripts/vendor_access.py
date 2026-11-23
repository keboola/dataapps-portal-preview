"""Vendor the kbc_access package into a Data App that lives in its own repository.

    uv run --with pydantic python skills/protect-data-app/scripts/vendor_access.py \
        --target ~/repos/my-app --app-id kbc-1234-567890 --app-name "Margin report" \
        --app-url https://margin-report-567890.hub.europe-west3.gcp.keboola.com/ \
        --app-entrypoint streamlit_app.py --app-port 8501 \
        --launcher-url https://app-launcher-124.hub.europe-west3.gcp.keboola.com/ \
        --stack-url https://connection.europe-west3.gcp.keboola.com \
        --bucket-id in.c-apps-control-plane --roles-separator , [--yes]

Run it from a clone of https://github.com/keboola/dataapps-portal-preview (the
package is copied from that clone; `--source` points at another clone). Without
--yes it prints the plan and changes nothing. With --yes it:

 1. copies `src/kbc_access` to `<target>/<vendor-dir>/kbc_access`, replacing an
    earlier vendored copy (caches are never copied);
 2. writes `<vendor-dir>/kbc_access.vendored.json` — the source commit, so the
    next run can say "upgrading from X to Y";
 3. renders the access config (`--config-path`, default `config/kbc_access.toml`)
    from deploy/templates/deployed.toml.tmpl — the same rendering the suite's
    bundle builder uses — and validates it with the package's own loader;
 4. merges the package's runtime dependencies into `<target>/requirements.txt`
    (a marked block this script owns) when that file exists, otherwise only
    lists them.

The final JSON summary goes to stdout. No secret is read, written or printed:
#ACCESS_STORAGE_TOKEN and #MASK_SALT are set on the Data App separately.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

SKILL_DIR = Path(__file__).resolve().parent.parent
# The skill lives at <repo>/skills/protect-data-app, so the repo it ships in is two levels up.
DEFAULT_SOURCE = SKILL_DIR.parent.parent
PACKAGE = "kbc_access"
PACKAGE_SRC = Path("src") / PACKAGE
MARKER_NAME = f"{PACKAGE}.vendored.json"
MARKER_FORMAT = 1
GENERATED_BY = "skills/protect-data-app/scripts/vendor_access.py"
UPSTREAM_REPO = "https://github.com/keboola/dataapps-portal-preview"
IGNORED = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".DS_Store")
# Files whose presence identifies an unmarked directory as an earlier copy of kbc_access.
PACKAGE_FINGERPRINT = ("gate.py", "identity.py", "web.py")
# Top-level import name -> PyPI distribution, for every third-party module kbc_access imports.
# A new import without an entry here fails the run (and the tests), so the list cannot drift.
IMPORT_DISTRIBUTIONS = {
    "fastapi": "fastapi",
    "jinja2": "jinja2",
    "pydantic": "pydantic",
    "httpx": "httpx",
    "yaml": "pyyaml",
    "sqlglot": "sqlglot",
    "duckdb": "duckdb",
    "keboola_query_service": "keboola-query-service",
}
REQUIREMENTS_BEGIN = f"# >>> {PACKAGE} (managed by protect-data-app/vendor_access.py; a re-run rewrites this block) >>>"
REQUIREMENTS_END = f"# <<< {PACKAGE} <<<"
# The launcher entry in the rendered config; its values come from the suite manifest.
LAUNCHER_ID = "launcher"
# Settings.root is the config file's grandparent, and logs/ resolve against it, so the
# config must sit exactly one directory below the app root.
CONFIG_PATH_PARTS = 2
APP_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
BUCKET_ID = re.compile(r"^(in|out)\.c-[A-Za-z0-9_-]+$")
REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
# Placeholder secrets used only to validate the rendered config in memory (never written).
VALIDATION_ENV = {"MASK_SALT": "validation_salt_0123456789", "ACCESS_STORAGE_TOKEN": "validation-token-0123456789"}

ENV_DOC = {
    "KBC_ACCESS_CONFIG": (
        "Path of the access config. Read only by kbc_access.web.build_runtime() without arguments; "
        "the protect-data-app snippets call load_settings(<config path>, os.environ) instead, so the app "
        "does not need it."
    ),
    "ACCESS_STORAGE_TOKEN": (
        "Data App secret #ACCESS_STORAGE_TOKEN: the app's OWN Storage token with READ access to the "
        "control-plane bucket only (kbagent token create --bucket-read <bucket>). Never the Access admin's "
        "token: the suite installer rotates and revokes that one on every re-install."
    ),
    "MASK_SALT": (
        "Data App secret #MASK_SALT: URL-safe string of at least 16 characters. The config loader requires it "
        "in every app; only the data guard uses it, as the salt of hashed column masks (sha256(salt || value)). "
        "Use the same value as another app only if hashed values must be comparable between the two."
    ),
}


class VendorError(RuntimeError):
    pass


@dataclass(frozen=True)
class Plan:
    source: Path
    target: Path
    vendor_dir: Path
    config_path: Path
    app_id: str
    app_name: str
    app_url: str
    app_entrypoint: str
    app_port: int
    launcher_url: str
    stack_url: str
    bucket_id: str
    roles_separator: str
    extra_config: Path | None

    @property
    def package_dir(self) -> Path:
        return self.target / self.vendor_dir / PACKAGE

    @property
    def marker_path(self) -> Path:
        return self.target / self.vendor_dir / MARKER_NAME

    @property
    def config_file(self) -> Path:
        return self.target / self.config_path


# ---- source -------------------------------------------------------------------------


def _git(source: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(source), *args], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise VendorError(f"git {' '.join(args)} failed in {source}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def source_version(source: Path) -> dict[str, Any]:
    """Which commit of the source clone is being vendored. Requires a git checkout."""
    if not (source / ".git").exists():
        raise VendorError(f"{source} is not a git clone of {UPSTREAM_REPO}; clone it and pass --source")
    remote = subprocess.run(
        ["git", "-C", str(source), "remote", "get-url", "origin"], capture_output=True, text=True, check=False
    )
    return {
        "repository": remote.stdout.strip() if remote.returncode == 0 else None,
        "commit": _git(source, "rev-parse", "HEAD"),
        "describe": _git(source, "describe", "--tags", "--always"),
        "commit_date": _git(source, "log", "-1", "--format=%cI"),
        # Uncommitted changes in the package itself make the commit an inexact label.
        "dirty": bool(_git(source, "status", "--porcelain", "--", PACKAGE_SRC.as_posix())),
    }


def load_bundle_builder(source: Path) -> ModuleType:
    """scripts/build_app_bundle.py of the source clone (owns the deployed.toml rendering)."""
    import importlib.util

    path = source / "scripts" / "build_app_bundle.py"
    spec = importlib.util.spec_from_file_location("kbc_access_build_app_bundle", path)
    if spec is None or spec.loader is None:
        raise VendorError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_source(source: Path) -> None:
    for rel in (PACKAGE_SRC / "__init__.py", Path("deploy/templates/deployed.toml.tmpl"),
                Path("deploy/suite.toml"), Path("scripts/build_app_bundle.py")):
        if not (source / rel).is_file():
            raise VendorError(f"{source} has no {rel}: --source must be a clone of {UPSTREAM_REPO}")


# ---- dependencies --------------------------------------------------------------------


def third_party_imports(package_dir: Path) -> set[str]:
    """Top-level modules imported anywhere in the package, minus stdlib and the package itself."""
    found: set[str] = set()
    for path in package_dir.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".")[0])
    return {m for m in found if m not in sys.stdlib_module_names and m not in {PACKAGE, "__future__"}}


def _requirement_name(spec: str) -> str:
    match = REQUIREMENT_NAME.match(spec)
    if not match:
        raise VendorError(f"Cannot read a distribution name from '{spec}'")
    return re.sub(r"[-_.]+", "-", match.group(1)).lower()


def runtime_dependencies(source: Path, manifest: dict) -> list[str]:
    """Pinned requirements for what kbc_access imports, with the pins the suite deploys with."""
    pins = {_requirement_name(spec): spec for spec in manifest["dependencies"]}
    deps: list[str] = []
    for module in sorted(third_party_imports(source / PACKAGE_SRC)):
        dist = IMPORT_DISTRIBUTIONS.get(module)
        if dist is None:
            raise VendorError(f"kbc_access imports '{module}', which has no entry in IMPORT_DISTRIBUTIONS")
        spec = pins.get(_requirement_name(dist))
        if spec is None:
            raise VendorError(f"'{dist}' (imported by kbc_access) has no pinned version in deploy/suite.toml dependencies")
        deps.append(spec)
    return sorted(set(deps), key=_requirement_name)


def merge_requirements(text: str, deps: list[str]) -> tuple[str, list[dict[str, str]]]:
    """requirements.txt with the managed block rewritten.

    A dependency the app already declares outside the block is left to the app's own line
    and reported when its spec differs from the package's pin.
    """
    lines = text.splitlines()
    if REQUIREMENTS_BEGIN in lines:
        start = lines.index(REQUIREMENTS_BEGIN)
        if REQUIREMENTS_END not in lines[start:]:
            raise VendorError(f"requirements.txt has '{REQUIREMENTS_BEGIN}' without '{REQUIREMENTS_END}'")
        end = lines.index(REQUIREMENTS_END, start)
        lines = lines[:start] + lines[end + 1:]
    while lines and not lines[-1].strip():
        lines.pop()
    own: dict[str, str] = {}
    for line in lines:
        stripped = line.split("#", 1)[0].strip()
        if stripped and not stripped.startswith("-"):
            own[_requirement_name(stripped)] = stripped
    conflicts = [
        {"package": dep, "app_declares": own[_requirement_name(dep)]}
        for dep in deps
        if _requirement_name(dep) in own and own[_requirement_name(dep)].replace(" ", "") != dep.replace(" ", "")
    ]
    block = [d for d in deps if _requirement_name(d) not in own]
    if block:
        lines += (["", REQUIREMENTS_BEGIN] if lines else [REQUIREMENTS_BEGIN]) + block + [REQUIREMENTS_END]
    return "\n".join(lines) + "\n", conflicts


# ---- config --------------------------------------------------------------------------


def render_config(plan: Plan, bundle: ModuleType, manifest: dict) -> str:
    extra = ""
    if plan.extra_config is not None:
        extra = plan.extra_config.read_text(encoding="utf-8").strip() + "\n\n"
    apps = {
        plan.app_id: {
            "name": plan.app_name, "port": plan.app_port, "factory": plan.app_entrypoint,
            "protected": True, "public_url": plan.app_url,
        },
        LAUNCHER_ID: bundle.suite_app_entry(manifest, LAUNCHER_ID, plan.launcher_url),
    }
    return bundle.render_deployed_config(
        app_id=plan.app_id, stack_url=plan.stack_url, bucket_id=plan.bucket_id,
        roles_separator=plan.roles_separator, data_block=extra, apps_block=bundle.apps_section(apps),
        generated_by=GENERATED_BY,
    )


def validate_config(plan: Plan, text: str) -> None:
    """Load the rendered config with the source's own loader (placeholder secrets, in memory only)."""
    sys.path.insert(0, str(plan.source / "src"))
    try:
        from kbc_access.config import load_settings  # noqa: PLC0415
    except ModuleNotFoundError as exc:
        raise VendorError(f"Validating the config needs {exc.name}: run the script with `uv run --with pydantic python …`") from exc
    finally:
        sys.path.pop(0)
    with tempfile.TemporaryDirectory(prefix="kbc-access-vendor-") as tmp:
        path = Path(tmp) / plan.config_path
        path.parent.mkdir(parents=True)
        path.write_text(text, encoding="utf-8")
        try:
            settings = load_settings(path, VALIDATION_ENV)
        except Exception as exc:  # pydantic ValidationError, tomllib errors, ValueError
            raise VendorError(f"The rendered config does not load: {exc}") from exc
    if settings.store.backend != "keboola":
        raise VendorError("The rendered config must use the Keboola Storage store")


# ---- plan ----------------------------------------------------------------------------


def _url(value: str, flag: str) -> str:
    if not value.startswith("https://") or not value.endswith("/"):
        raise VendorError(f"{flag} must be https:// and end with '/': {value}")
    return value


def validate(plan: Plan) -> None:
    if not plan.target.is_dir():
        raise VendorError(f"--target {plan.target} is not a directory")
    if plan.target.resolve() == plan.source.resolve():
        raise VendorError("--target is the source clone itself; point it at the app's repository")
    if not APP_ID.fullmatch(plan.app_id):
        raise VendorError(f"--app-id '{plan.app_id}' must be lowercase [a-z0-9_-], at most 64 characters")
    if plan.app_id == LAUNCHER_ID:
        raise VendorError(f"--app-id '{LAUNCHER_ID}' is reserved for the suite's App launcher")
    if not BUCKET_ID.fullmatch(plan.bucket_id):
        raise VendorError(f"--bucket-id '{plan.bucket_id}' must look like in.c-apps-control-plane")
    if not plan.stack_url.startswith("https://"):
        raise VendorError(f"--stack-url must be https://: {plan.stack_url}")
    _url(plan.app_url, "--app-url")
    _url(plan.launcher_url, "--launcher-url")
    if not plan.app_name.strip() or not plan.app_entrypoint.strip():
        raise VendorError("--app-name and --app-entrypoint must not be empty")
    if not plan.roles_separator:
        raise VendorError("--roles-separator must not be empty")
    if plan.app_port <= 0:
        raise VendorError("--app-port must be a positive port number")
    for rel, flag in ((plan.vendor_dir, "--vendor-dir"), (plan.config_path, "--config-path")):
        if rel.is_absolute() or ".." in rel.parts:
            raise VendorError(f"{flag} must be a relative path inside the target repo, got '{rel}'")
    if len(plan.config_path.parts) != CONFIG_PATH_PARTS or plan.config_path.suffix != ".toml":
        raise VendorError("--config-path must be <directory>/<name>.toml, one level below the app root "
                          "(logs/ and other config-relative paths resolve against the app root)")
    if plan.extra_config is not None and not plan.extra_config.is_file():
        raise VendorError(f"--extra-config {plan.extra_config} is not a file")


def previous_version(plan: Plan) -> dict[str, Any] | None:
    """What is vendored now: the marker's content, an unmarked copy, or None."""
    if plan.marker_path.is_file():
        try:
            return json.loads(plan.marker_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise VendorError(f"{plan.marker_path} is not valid JSON: {exc}") from exc
    if plan.package_dir.exists():
        if all((plan.package_dir / f).is_file() for f in PACKAGE_FINGERPRINT):
            return {"source": None, "note": "unmarked copy of kbc_access (version unknown)"}
        raise VendorError(f"{plan.package_dir} exists and is not kbc_access; move it away or choose --vendor-dir")
    return None


def check_app_id(plan: Plan, previous: dict[str, Any] | None) -> None:
    """An upgrade keeps the app id it is registered under in the apps table."""
    old = (previous or {}).get("app_id")
    if old and old != plan.app_id:
        raise VendorError(
            f"This app was vendored as '{old}' (see {plan.marker_path.name}); its row in the apps table and its "
            f"grants use that id. Pass --app-id {old}, or delete the marker if the id really changes."
        )


def marker(plan: Plan, version: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": MARKER_FORMAT,
        "source": version,
        "vendored_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "app_id": plan.app_id,
        "package_path": (plan.vendor_dir / PACKAGE).as_posix(),
        "config_path": plan.config_path.as_posix(),
    }


def _label(version: dict[str, Any] | None) -> str | None:
    if version is None:
        return None
    src = version.get("source")
    if not isinstance(src, dict):
        return str(version.get("note", "unknown"))
    return f"{src['describe']} ({src['commit'][:12]}, {src['commit_date']}{', dirty' if src.get('dirty') else ''})"


def run(plan: Plan, *, execute: bool) -> dict[str, Any]:
    check_source(plan.source)
    validate(plan)
    version = source_version(plan.source)
    previous = previous_version(plan)
    check_app_id(plan, previous)
    bundle = load_bundle_builder(plan.source)
    manifest = bundle.load_manifest()
    deps = runtime_dependencies(plan.source, manifest)
    config_text = render_config(plan, bundle, manifest)
    validate_config(plan, config_text)

    requirements = plan.target / "requirements.txt"
    merged: tuple[str, list[dict[str, str]]] | None = None
    if requirements.is_file():
        merged = merge_requirements(requirements.read_text(encoding="utf-8"), deps)

    summary: dict[str, Any] = {
        "target": str(plan.target),
        "package": str(plan.package_dir),
        "version": {"previous": _label(previous), "new": _label({"source": version})},
        "action": "upgrade" if previous else "install",
        "config": str(plan.config_file),
        "marker": str(plan.marker_path),
        "dependencies": deps,
        "requirements_txt": (
            "managed block updated" if merged else
            "no requirements.txt: add the dependencies to the app's own dependency file (e.g. pyproject.toml)"
        ),
        "dependency_conflicts": merged[1] if merged else [],
        "env": ENV_DOC,
    }
    if not execute:
        return {"plan": summary, "execute_with": "--yes"}

    if plan.package_dir.exists():
        shutil.rmtree(plan.package_dir)
    plan.package_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(plan.source / PACKAGE_SRC, plan.package_dir, ignore=IGNORED)
    plan.marker_path.write_text(json.dumps(marker(plan, version), indent=2) + "\n", encoding="utf-8")
    plan.config_file.parent.mkdir(parents=True, exist_ok=True)
    plan.config_file.write_text(config_text, encoding="utf-8")
    if merged:
        requirements.write_text(merged[0], encoding="utf-8")
    summary["files_copied"] = sum(1 for p in plan.package_dir.rglob("*") if p.is_file())
    return summary


def parse(argv: list[str] | None) -> tuple[Plan, bool]:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, type=Path, help="root of the app's repository")
    parser.add_argument("--app-id", required=True, help="the app's id in the apps table (reuse it on an upgrade)")
    parser.add_argument("--app-name", required=True, help="display name (deny page title)")
    parser.add_argument("--app-url", required=True, help="the app's public Data App URL, https://…/")
    parser.add_argument("--app-entrypoint", required=True,
                        help="how the app starts: a uvicorn factory 'module:create_default' or a Streamlit script path")
    parser.add_argument("--app-port", required=True, type=int, help="port the app listens on in its container")
    parser.add_argument("--launcher-url", required=True, help="public URL of the suite's App launcher, https://…/")
    parser.add_argument("--stack-url", required=True, help="Keboola stack, e.g. https://connection.europe-west3.gcp.keboola.com")
    parser.add_argument("--bucket-id", required=True, help="control-plane bucket, e.g. in.c-apps-control-plane")
    parser.add_argument("--roles-separator", required=True,
                        help="separator the apps-proxy uses between groups in X-Kbc-User-Roles (the suite installs with ',')")
    parser.add_argument("--vendor-dir", type=Path, default=Path("."),
                        help="directory (relative to --target) that gets kbc_access/; default: the repo root, which "
                             "is on sys.path for a Streamlit script or a module started from the root")
    parser.add_argument("--config-path", type=Path, default=Path("config") / f"{PACKAGE}.toml",
                        help="config file relative to --target, exactly <dir>/<name>.toml (default config/kbc_access.toml)")
    parser.add_argument("--extra-config", type=Path,
                        help="TOML fragment appended to the config ([data] and [policy] for an app using the data guard)")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE,
                        help=f"clone of {UPSTREAM_REPO} to vendor from (default: the clone this script is in)")
    parser.add_argument("--yes", action="store_true", help="execute; without it only the plan is printed")
    args = parser.parse_args(argv)
    plan = Plan(
        source=args.source.resolve(), target=args.target.expanduser().resolve(), vendor_dir=args.vendor_dir,
        config_path=args.config_path, app_id=args.app_id, app_name=args.app_name, app_url=args.app_url,
        app_entrypoint=args.app_entrypoint, app_port=args.app_port, launcher_url=args.launcher_url,
        stack_url=args.stack_url, bucket_id=args.bucket_id, roles_separator=args.roles_separator,
        extra_config=args.extra_config,
    )
    return plan, args.yes


def main(argv: list[str] | None = None) -> int:
    plan, execute = parse(argv)
    try:
        result = run(plan, execute=execute)
    except (VendorError, tomllib.TOMLDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
