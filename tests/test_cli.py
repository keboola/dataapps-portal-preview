import json

import pytest

from kbc_access import cli, web


@pytest.fixture
def cli_env(runtime, monkeypatch):
    # The CLI builds its own runtime; point it at the test runtime's settings.
    monkeypatch.setattr(web, "get_settings", lambda: runtime.settings)
    return runtime


def test_register_app_grants_nobody(cli_env, capsys):
    code = cli.main(["register-app", "--app-id", "new-app", "--name", "New app", "--url", "http://x/", "--project-id", "1", "--config-id", "2"])
    assert code == 0
    assert "new-app" in {a.app_id for a in cli_env.store.list_apps()}
    assert not [g for g in cli_env.store.list_grants() if g.app_id == "new-app"]
    assert json.loads(capsys.readouterr().out)["registered"] == "new-app"


def test_register_app_rejects_bad_id(cli_env, capsys):
    assert cli.main(["register-app", "--app-id", "Bad Id", "--name", "x", "--url", "u", "--project-id", "1", "--config-id", "2"]) == 2


def test_register_app_for_everyone_signed_in(cli_env, capsys):
    args = ["register-app", "--app-id", "everyone", "--name", "Everyone", "--url", "http://x/", "--project-id", "1",
            "--config-id", "2", "--access", "all_signed_in"]
    assert cli.main(args) == 0
    assert {a.app_id: a.access for a in cli_env.store.list_apps()}["everyone"] == "all_signed_in"
    assert json.loads(capsys.readouterr().out)["access"] == "all_signed_in"


def test_check_prints_decisions(cli_env, capsys):
    cli.main(["check", "--email", "petr.sales@pharma-a.example", "--group", "8a1d4e2f-5b6c-4d7e-9f80-1a2b3c4d5e6f"])
    decisions = {d["app_id"]: d for d in map(json.loads, capsys.readouterr().out.splitlines())}
    assert decisions["sales"]["allowed"] and not decisions["admin"]["allowed"]
    assert decisions["admin"]["reason"] == "no_grant"
