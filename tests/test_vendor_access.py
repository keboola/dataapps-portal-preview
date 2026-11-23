"""The protect-data-app skill's vendoring script: kbc_access copied into an app's own repo.

Runs against this repo as the source clone and a temp directory as the app repo.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from kbc_access.config import load_settings

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "skills" / "protect-data-app" / "scripts" / "vendor_access.py"
STACK = "https://connection.europe-west3.gcp.keboola.com"
APP_URL = "https://margin-report-567890.hub.europe-west3.gcp.keboola.com/"
LAUNCHER_URL = "https://app-launcher-124.hub.europe-west3.gcp.keboola.com/"
SECRETS = {"MASK_SALT": "salt_0123456789abcdef", "ACCESS_STORAGE_TOKEN": "t" * 20}


@pytest.fixture(scope="module")
def vendor():
    spec = importlib.util.spec_from_file_location("vendor_access", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["vendor_access"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def app_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "streamlit_app.py").write_text("import streamlit as st\n", encoding="utf-8")
    (repo / "requirements.txt").write_text("streamlit==1.50.0\nhttpx==0.27.0\n", encoding="utf-8")
    return repo


def _args(repo: Path, *extra: str, app_id: str = "kbc-1234-567890") -> list[str]:
    return [
        "--target", str(repo), "--app-id", app_id, "--app-name", "Margin report", "--app-url", APP_URL,
        "--app-entrypoint", "streamlit_app.py", "--app-port", "8501", "--launcher-url", LAUNCHER_URL,
        "--stack-url", STACK, "--bucket-id", "in.c-apps-control-plane", "--roles-separator", ",", *extra,
    ]


def _run(vendor, capsys, args: list[str]) -> tuple[int, dict | None, str]:
    code = vendor.main(args)
    out = capsys.readouterr()
    return code, (json.loads(out.out) if out.out.strip() else None), out.err


def _snapshot(repo: Path) -> dict[str, bytes]:
    return {p.relative_to(repo).as_posix(): p.read_bytes() for p in repo.rglob("*") if p.is_file()}


def test_dry_run_writes_nothing_and_shows_the_plan(vendor, capsys, app_repo):
    before = _snapshot(app_repo)
    code, result, _ = _run(vendor, capsys, _args(app_repo))
    assert code == 0
    assert result["execute_with"] == "--yes"
    assert result["plan"]["action"] == "install" and result["plan"]["version"]["previous"] is None
    assert set(result["plan"]["env"]) == {"KBC_ACCESS_CONFIG", "ACCESS_STORAGE_TOKEN", "MASK_SALT"}
    assert _snapshot(app_repo) == before


def test_install_copies_package_marker_config_and_requirements(vendor, capsys, app_repo):
    code, result, _ = _run(vendor, capsys, _args(app_repo, "--yes"))
    assert code == 0, result
    package = app_repo / "kbc_access"
    assert (package / "gate.py").is_file() and (package / "templates" / "denied.html").is_file()
    assert not list(package.rglob("__pycache__")) and not list(package.rglob("*.pyc"))
    assert result["files_copied"] > 0

    marker = json.loads((app_repo / "kbc_access.vendored.json").read_text())
    assert marker["app_id"] == "kbc-1234-567890"
    assert len(marker["source"]["commit"]) == 40
    assert marker["config_path"] == "config/kbc_access.toml"

    settings = load_settings(app_repo / "config" / "kbc_access.toml", SECRETS)
    assert settings.root == app_repo
    assert settings.store.backend == "keboola"
    assert settings.store.keboola.bucket_id == "in.c-apps-control-plane"
    assert settings.store.keboola.stack_url == STACK
    assert settings.identity.roles_separator == ","
    assert settings.apps["kbc-1234-567890"].protected and settings.app_url("kbc-1234-567890") == APP_URL
    assert settings.app_url("launcher") == LAUNCHER_URL
    assert settings.data is None
    assert "vendor_access.py" in (app_repo / "config" / "kbc_access.toml").read_text().splitlines()[0]

    requirements = (app_repo / "requirements.txt").read_text()
    assert requirements.startswith("streamlit==1.50.0\nhttpx==0.27.0\n")
    assert vendor.REQUIREMENTS_BEGIN in requirements and "fastapi~=" in requirements
    # httpx is the app's own line: kept, not duplicated, reported as a conflict with the pin.
    assert requirements.count("httpx") == 1
    assert result["dependency_conflicts"] == [{"package": "httpx~=0.28.1", "app_declares": "httpx==0.27.0"}]


def test_rerun_upgrades_replaces_the_copy_and_rewrites_the_block(vendor, capsys, app_repo):
    assert _run(vendor, capsys, _args(app_repo, "--yes"))[0] == 0
    marker_path = app_repo / "kbc_access.vendored.json"
    old = json.loads(marker_path.read_text())
    old["source"].update(commit="0" * 40, describe="v0.0.1", commit_date="2026-01-01T00:00:00+00:00")
    marker_path.write_text(json.dumps(old))
    (app_repo / "kbc_access" / "stale_module.py").write_text("x = 1\n")

    code, result, _ = _run(vendor, capsys, _args(app_repo, "--yes"))
    assert code == 0
    assert result["action"] == "upgrade"
    assert result["version"]["previous"].startswith("v0.0.1 (000000000000")
    assert result["version"]["new"] != result["version"]["previous"]
    assert not (app_repo / "kbc_access" / "stale_module.py").exists()
    assert json.loads(marker_path.read_text())["source"]["commit"] != "0" * 40
    requirements = (app_repo / "requirements.txt").read_text()
    assert requirements.count(vendor.REQUIREMENTS_BEGIN) == 1 and requirements.count("fastapi") == 1


def test_unmarked_copy_of_kbc_access_is_upgraded(vendor, capsys, app_repo):
    package = app_repo / "kbc_access"
    package.mkdir()
    for name in vendor.PACKAGE_FINGERPRINT:
        (package / name).write_text("# old copy\n")
    code, result, _ = _run(vendor, capsys, _args(app_repo, "--yes"))
    assert code == 0
    assert result["action"] == "upgrade" and "unmarked" in result["version"]["previous"]
    assert "old copy" not in (package / "gate.py").read_text()


def test_foreign_directory_named_kbc_access_is_refused(vendor, capsys, app_repo):
    (app_repo / "kbc_access").mkdir()
    (app_repo / "kbc_access" / "mine.py").write_text("")
    code, result, err = _run(vendor, capsys, _args(app_repo, "--yes"))
    assert code == 2 and result is None and "is not kbc_access" in err
    assert (app_repo / "kbc_access" / "mine.py").exists()


def test_upgrade_keeps_the_registered_app_id(vendor, capsys, app_repo):
    assert _run(vendor, capsys, _args(app_repo, "--yes"))[0] == 0
    code, _, err = _run(vendor, capsys, _args(app_repo, "--yes", app_id="margin-report"))
    assert code == 2 and "--app-id kbc-1234-567890" in err


@pytest.mark.parametrize("flag", ["--bucket-id", "--roles-separator", "--launcher-url", "--stack-url", "--app-url"])
def test_missing_required_parameter_fails(vendor, capsys, app_repo, flag):
    args = _args(app_repo)
    index = args.index(flag)
    del args[index:index + 2]
    with pytest.raises(SystemExit) as exc:
        vendor.main(args)
    assert exc.value.code == 2
    assert flag in capsys.readouterr().err


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (("--bucket-id", "apps-control-plane"), "--bucket-id"),
        (("--app-url", "http://insecure.example/"), "--app-url"),
        (("--launcher-url", "https://launcher.example"), "--launcher-url"),
        (("--roles-separator", ""), "--roles-separator"),
        (("--app-id", "Not Valid"), "--app-id"),
        (("--app-id", "launcher"), "reserved"),
    ],
)
def test_invalid_parameter_fails_before_writing(vendor, capsys, app_repo, change, message):
    args = _args(app_repo, "--yes")
    args[args.index(change[0]) + 1] = change[1]
    before = _snapshot(app_repo)
    code, _, err = _run(vendor, capsys, args)
    assert code == 2 and message in err
    assert _snapshot(app_repo) == before


def test_config_path_must_be_one_level_below_the_root(vendor, capsys, app_repo):
    code, _, err = _run(vendor, capsys, _args(app_repo, "--config-path", "kbc_access.toml"))
    assert code == 2 and "--config-path" in err


def test_custom_vendor_dir_and_extra_config(vendor, capsys, app_repo, tmp_path):
    extra = tmp_path / "data.toml"
    extra.write_text(
        '[data]\nduckdb_path = "data/warehouse.duckdb"\ndialect = "duckdb"\nmax_result_rows = 500\n'
        'max_query_chars = 20000\n\n[policy]\nfiles = ["config/policies/app.yaml"]\n',
        encoding="utf-8",
    )
    code, result, _ = _run(vendor, capsys, _args(app_repo, "--yes", "--vendor-dir", "src", "--extra-config", str(extra)))
    assert code == 0
    assert (app_repo / "src" / "kbc_access" / "web.py").is_file()
    assert (app_repo / "src" / "kbc_access.vendored.json").is_file()
    settings = load_settings(app_repo / "config" / "kbc_access.toml", SECRETS)
    assert settings.data is not None and settings.data.max_result_rows == 500
    assert settings.policy is not None


def test_broken_extra_config_is_rejected(vendor, capsys, app_repo, tmp_path):
    extra = tmp_path / "bad.toml"
    extra.write_text("[data]\nunknown_key = 1\n", encoding="utf-8")
    code, _, err = _run(vendor, capsys, _args(app_repo, "--yes", "--extra-config", str(extra)))
    assert code == 2 and "does not load" in err
    assert not (app_repo / "kbc_access").exists()


def test_without_requirements_txt_dependencies_are_only_listed(vendor, capsys, app_repo):
    (app_repo / "requirements.txt").unlink()
    code, result, _ = _run(vendor, capsys, _args(app_repo, "--yes"))
    assert code == 0
    assert not (app_repo / "requirements.txt").exists()
    assert "no requirements.txt" in result["requirements_txt"] and result["dependencies"]


def test_dependencies_cover_every_third_party_import(vendor):
    bundle = vendor.load_bundle_builder(ROOT)
    deps = vendor.runtime_dependencies(ROOT, bundle.load_manifest())
    names = {vendor._requirement_name(d) for d in deps}
    assert names == {"fastapi", "jinja2", "pydantic", "httpx", "pyyaml", "sqlglot", "duckdb", "keboola-query-service"}
    # The pins are the suite's own.
    assert all(d in bundle.load_manifest()["dependencies"] for d in deps)


def test_merge_requirements_is_idempotent(vendor):
    deps = ["fastapi~=0.141.1", "pyyaml~=6.0.3"]
    once, _ = vendor.merge_requirements("pandas==2.2.0\n", deps)
    twice, conflicts = vendor.merge_requirements(once, deps)
    assert once == twice and conflicts == []
    assert once.startswith("pandas==2.2.0\n\n" + vendor.REQUIREMENTS_BEGIN)


def test_vendored_copy_runs_on_its_own(vendor, capsys, app_repo):
    """The app imports the vendored copy (not this repo's src) and wires the gate from the rendered config."""
    assert _run(vendor, capsys, _args(app_repo, "--yes"))[0] == 0
    probe = (
        "import os, kbc_access\n"
        "from pathlib import Path\n"
        "from fastapi import FastAPI\n"
        "from kbc_access.config import load_settings\n"
        "from kbc_access.web import build_runtime, install\n"
        "assert Path(kbc_access.__file__).parent == Path.cwd() / 'kbc_access', kbc_access.__file__\n"
        "runtime = build_runtime(load_settings(Path('config/kbc_access.toml'), dict(os.environ)))\n"
        "install(FastAPI(), runtime, app_id='kbc-1234-567890', templates_dir=None)\n"
        "print('ok')\n"
    )
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "KBC_ACCESS_CONFIG"}}
    proc = subprocess.run([sys.executable, "-c", probe], cwd=app_repo, env={**env, **SECRETS},
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ok"
