import pytest

from seeder import auth, cli, tenant
from seeder.catalog import canary_files
from seeder.graph import GraphError
from seeder.manifest import write_manifest
from tests.fake_graph import FakeSignIn, FakeTenant
from tests.manifest_factory import make_canary_dir, make_manifest


@pytest.fixture
def no_client_id(monkeypatch):
    monkeypatch.delenv(auth.CLIENT_ID_ENV, raising=False)
    monkeypatch.setattr(tenant, "SEEDER_CLIENT_ID", "")


# --- failure paths ----------------------------------------------------------------------

def test_unknown_command_exits_2(capsys):
    assert cli.main(["frobnicate"]) == 2
    assert "invalid choice" in capsys.readouterr().err


def test_no_command_exits_2(capsys):
    assert cli.main([]) == 2


@pytest.mark.parametrize("command", ["seed", "verify"])
def test_missing_client_id_is_one_clean_line(command, no_client_id, capsys, tmp_path):
    code = cli.main([command, "--manifest", str(tmp_path / "m.json")])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.err.startswith("error: No client ID")
    assert "--client-id" in captured.err
    assert "Traceback" not in captured.err + captured.out
    assert len(captured.err.strip().splitlines()) == 1


def test_missing_manifest_for_hash_exits_2(tmp_path, capsys):
    assert cli.main(["hash", "--manifest", str(tmp_path / "nope.json"), "--canary-dir", str(tmp_path)]) == 2
    assert "python -m seeder seed" in capsys.readouterr().out


def test_graph_error_is_one_line_exit_2_without_token(monkeypatch, capsys, tmp_path):
    def boom(**kwargs):
        raise GraphError("GET /me/messages as alice failed: HTTP 500", status=500, method="GET", path="/me/messages")

    monkeypatch.setattr(cli, "run_seed", boom)
    code = cli.main(["seed", "--client-id", "abc", "--manifest", str(tmp_path / "m.json")])
    err = capsys.readouterr().err
    assert code == 2
    assert err == "error: GET /me/messages as alice failed: HTTP 500\n"


def test_keyboard_interrupt_exits_130(monkeypatch, capsys, tmp_path):
    def interrupted(**kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_seed", interrupted)
    code = cli.main(["seed", "--client-id", "abc", "--manifest", str(tmp_path / "m.json")])
    assert code == 130
    assert "nothing was written" in capsys.readouterr().err


def test_bad_auth_mode_exits_2(capsys):
    assert cli.main(["seed", "--auth", "password"]) == 2


# --- happy paths ------------------------------------------------------------------------

def test_hash_against_a_tmp_manifest(tmp_path, capsys):
    canary = make_canary_dir(tmp_path)
    manifest_path = tmp_path / "seed-manifest.json"
    write_manifest(manifest_path, make_manifest())
    code = cli.main(["hash", "--manifest", str(manifest_path), "--canary-dir", str(canary)])
    assert code == 0
    assert capsys.readouterr().out.strip().endswith("40/40 entries reproduce the manifest hashes")


def test_generate_writes_20_files(tmp_path):
    out_dir = tmp_path / "canary"
    assert cli.main(["generate", "--canary-dir", str(out_dir)]) == 0
    assert sorted(p.name for p in out_dir.iterdir()) == sorted(f.name for f in canary_files())


def test_help_exits_0(capsys):
    assert cli.main(["--help"]) == 0
    assert "seed" in capsys.readouterr().out


def test_seed_then_verify_through_main(monkeypatch, tmp_path, capsys):
    fake = FakeTenant()
    signins: list[tuple] = []

    def fake_signin(client_id, tenant_id, *, mode, out):
        signins.append((client_id, tenant_id, mode))
        return FakeSignIn(out=out)

    monkeypatch.setattr(cli, "SignIn", fake_signin)
    monkeypatch.setattr(cli, "RequestsTransport", lambda: fake)
    manifest_path = tmp_path / "seed-manifest.json"
    common = ["--client-id", "cid", "--auth", "device", "--manifest", str(manifest_path)]
    assert cli.main(["seed", *common, "--mail-timeout", "5"]) == 0
    assert cli.main(["verify", *common]) == 0
    assert signins == [("cid", tenant.TENANT_ID, "device")] * 2
    assert "40/40 entries in the tenant match the manifest" in capsys.readouterr().out
