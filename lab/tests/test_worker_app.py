"""check-worker-app (L1.5): the Worker app's permissions, probed with its own app-only token."""

import datetime as dt
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from seeder import cli, tenant, worker_app
from seeder.auth import AuthError
from seeder.http import TransportError
from seeder.worker_app import (
    CLIENT_ID_ENV,
    GRAPH_SCOPES,
    OTHER_API_SCOPES,
    CREDENTIAL_TARGET,
    EXPECTED_ROLES,
    CredentialError,
    default_pfx_path,
    load_pfx,
    probes,
    resolve_worker_client_id,
    run_check,
)
from tests.fake_graph import APP_GRANTS, FakeSignIn, FakeTenant, make_app_token
from tests.fake_transport import json_response

CLIENT_ID = "11111111-2222-3333-4444-555555555555"
PASSWORD_SENTINEL = "pfx-password-SENTINEL-DO-NOT-LEAK"
TOKEN_SENTINEL = "token-signature-SENTINEL-DO-NOT-LEAK"


# ---- fixtures ------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_and_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RestoreProof Worker (test)")])
    now = dt.datetime(2026, 9, 27, tzinfo=dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


@pytest.fixture
def pfx(tmp_path, key_and_cert) -> Path:
    key, cert = key_and_cert
    data = pkcs12.serialize_key_and_certificates(
        b"rp-worker", key, cert, None, serialization.BestAvailableEncryption(PASSWORD_SENTINEL.encode())
    )
    path = tmp_path / "worker-graph.pfx"
    path.write_bytes(data)
    return path


def key_pem_lines(key) -> list[str]:
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    return [line for line in pem.splitlines() if line and not line.startswith("-----")]


def token_result(roles=None) -> dict:
    token = make_app_token(CLIENT_ID, signature=TOKEN_SENTINEL, **({} if roles is None else {"roles": roles}))
    return {"access_token": token, "token_type": "Bearer", "expires_in": 3599}


class FakeConfidentialApp:
    """msal.ConfidentialClientApplication look-alike. acquire_token_for_client returns `result`
    for Graph and, for the other APIs, `others[api]` or a token without roles."""

    def __init__(self, result: dict | None = None, others: dict[str, dict] | None = None) -> None:
        self.result = result if result is not None else token_result()
        self.others = others or {}
        self.calls: list[tuple] = []

    def acquire_token_for_client(self, scopes):
        self.calls.append(("for_client", tuple(scopes)))
        if list(scopes) == GRAPH_SCOPES:
            return dict(self.result)
        api = next(api for api, api_scopes in OTHER_API_SCOPES.items() if api_scopes == list(scopes))
        return dict(self.others.get(api) or token_result(roles=()))


def password_store(value: str | None = PASSWORD_SENTINEL):
    reads: list[str] = []

    def read(target: str) -> str | None:
        reads.append(target)
        return value

    read.reads = reads  # type: ignore[attr-defined]
    return read


def with_canary(fake: FakeTenant) -> FakeTenant:
    """alice's canary folder holds a file, as after `seed`."""
    fake.put_item(tenant.ONEDRIVE_DRIVE_ID, "canary.docx", b"canary")
    return fake


def check(pfx_path, *, fake=None, app=None, read_password=None, transport=None):
    """Runs run_check and returns (exit code, output lines, fake tenant)."""
    fake = fake if fake is not None else with_canary(FakeTenant())
    lines: list[str] = []
    code = run_check(
        client_id=CLIENT_ID,
        tenant_id=tenant.TENANT_ID,
        pfx_path=pfx_path,
        read_password=read_password or password_store(),
        transport=transport or fake,
        alice_token=FakeSignIn().token_provider(tenant.ALICE_UPN, "test"),
        app=app if app is not None else FakeConfidentialApp(),
        out=lines.append,
        sleep=lambda s: None,
    )
    return code, lines, fake


def row(lines: list[str], label: str) -> str:
    found = [line for line in lines if label in line]
    assert len(found) == 1, (label, lines)
    return found[0]


def assert_no_secret(texts, key=None) -> None:
    joined = "\n".join(texts)
    assert PASSWORD_SENTINEL not in joined
    assert TOKEN_SENTINEL not in joined
    assert "PRIVATE KEY" not in joined
    if key is not None:
        for line in key_pem_lines(key):
            assert line not in joined


# ---- failure paths: credential and sign-in -------------------------------------------------


def test_missing_credential_manager_entry_is_a_credential_error(pfx):
    read = password_store(None)
    with pytest.raises(CredentialError) as info:
        check(pfx, read_password=read)
    msg = str(info.value)
    assert CREDENTIAL_TARGET in msg
    assert "lab/entra/new-worker-app.ps1" in msg
    assert read.reads == [CREDENTIAL_TARGET]


def test_missing_pfx_file_is_a_credential_error(tmp_path):
    missing = tmp_path / "nope.pfx"
    with pytest.raises(CredentialError) as info:
        check(missing)
    assert str(missing) in str(info.value)
    assert "lab/entra/new-worker-app.ps1" in str(info.value)


def test_wrong_pfx_password_names_the_file_not_the_password(pfx):
    with pytest.raises(CredentialError) as info:
        check(pfx, read_password=password_store("wrong-password-SENTINEL"))
    msg = str(info.value)
    assert str(pfx) in msg and CREDENTIAL_TARGET in msg
    assert "wrong-password-SENTINEL" not in msg and PASSWORD_SENTINEL not in msg


def test_pfx_that_is_not_a_pfx_is_a_credential_error(tmp_path):
    bad = tmp_path / "bad.pfx"
    bad.write_bytes(b"not a pkcs12 file")
    with pytest.raises(CredentialError, match="can't be opened"):
        check(bad)


def test_pfx_without_a_private_key_is_a_credential_error(tmp_path, key_and_cert):
    _, cert = key_and_cert
    data = pkcs12.serialize_key_and_certificates(
        b"x", None, None, [cert], serialization.BestAvailableEncryption(PASSWORD_SENTINEL.encode())
    )
    path = tmp_path / "cert-only.pfx"
    path.write_bytes(data)
    with pytest.raises(CredentialError, match="no private key"):
        check(path)


def test_token_failure_is_an_auth_error_that_redacts_known_secrets(pfx, key_and_cert, capsys):
    app = FakeConfidentialApp(
        {
            "error": "invalid_client",
            # A server message never quotes the password, but if one did it must not get out.
            "error_description": f"AADSTS700027: Client assertion failed ({PASSWORD_SENTINEL}).",
            "access_token": TOKEN_SENTINEL,
        }
    )
    with pytest.raises(AuthError) as info:
        check(pfx, app=app)
    msg = str(info.value)
    assert "invalid_client" in msg and "AADSTS700027" in msg
    assert_no_secret([msg, repr(info.value), capsys.readouterr().out], key_and_cert[0])
    assert app.calls == [("for_client", ("https://graph.microsoft.com/.default",))]


def test_token_result_without_a_token_is_an_auth_error(pfx):
    with pytest.raises(AuthError, match="no access token"):
        check(pfx, app=FakeConfidentialApp({"token_type": "Bearer"}))


def test_no_request_reaches_graph_when_sign_in_fails(pfx):
    fake = FakeTenant()
    with pytest.raises(AuthError):
        check(pfx, fake=fake, app=FakeConfidentialApp({"error": "invalid_client"}))
    assert fake.headers_seen == []  # nothing at all, not only nothing with an app token


# ---- failure paths: unexpected answers ------------------------------------------------------


def test_unexpected_200_on_a_forbidden_mailbox_fails_the_check(pfx):
    # alice's mailbox answers: e.g. the Entra Mail.Read consent was left in place.
    fake = with_canary(FakeTenant(app_grants=APP_GRANTS | {f"mailbox:{tenant.ALICE_UPN.lower()}"}))
    code, lines, _ = check(pfx, fake=fake)
    assert code == 1
    line = row(lines, "alice's mailbox")
    assert line.startswith("UNEXPECTED") and " 403 " in line and " 200 " in line
    assert lines[-1] == f"{len(probes()) - 1}/{len(probes())} probes as expected; 1 UNEXPECTED"


def test_unexpected_200_on_another_site_fails_the_check(pfx):
    fake = FakeTenant(app_grants=APP_GRANTS | {f"site:{tenant.SHAREPOINT_HOST}"})
    code, lines, _ = check(pfx, fake=fake)
    assert code == 1
    assert row(lines, "tenant root site: the site").startswith("UNEXPECTED")
    assert row(lines, "tenant root site: its libraries").startswith("UNEXPECTED")


def test_unexpected_200_on_alices_whole_onedrive_fails_the_check(pfx):
    # Sites.Selected on her OneDrive instead of the folder grant would open the canary folder.
    site = f"site:{tenant.ONEDRIVE_HOST}:{tenant.ALICE_ONEDRIVE_SITE_PATH}"
    code, lines, _ = check(pfx, fake=with_canary(FakeTenant(app_grants=APP_GRANTS | {site})))
    assert code == 1
    assert row(lines, "alice's OneDrive: RestoreTest canary folder").startswith("UNEXPECTED")
    line = row(lines, "alice's OneDrive: files in her root")
    assert line.startswith("UNEXPECTED") and "2 other items" in line


def test_a_second_folder_visible_in_alices_root_fails_the_check(pfx):
    # SharePoint masks what the app may not see; if the canary folder shows up, it isn't masked.
    canary = f"folder:{tenant.ONEDRIVE_DRIVE_ID}/{tenant.ONEDRIVE_FOLDER_ID}"
    code, lines, _ = check(pfx, fake=with_canary(FakeTenant(app_grants=APP_GRANTS | {canary})))
    assert code == 1
    line = row(lines, "alice's OneDrive: files in her root")
    assert line.startswith("UNEXPECTED") and " 200 " in line and "1 other item" in line
    assert row(lines, "alice's OneDrive: RestoreTest canary folder").startswith("UNEXPECTED")
    assert row(lines, "alice's OneDrive: files in the RestoreTest canary folder").startswith("UNEXPECTED")


def test_unexpected_200_on_the_onedrive_host_site_fails_the_check(pfx):
    code, lines, _ = check(pfx, fake=with_canary(FakeTenant(app_grants=APP_GRANTS | {f"site:{tenant.ONEDRIVE_HOST}"})))
    assert code == 1
    assert row(lines, "OneDrive host root site").startswith("UNEXPECTED")


def test_403_on_an_allowed_site_fails_the_check(pfx):
    fake = with_canary(FakeTenant(app_grants=APP_GRANTS - {f"site:{tenant.SHAREPOINT_SITE_ID}"}))
    code, lines, _ = check(pfx, fake=fake)
    assert code == 1
    line = row(lines, "RestoreTest site: the site")
    assert line.startswith("UNEXPECTED") and " 200 " in line and " 403 " in line
    assert row(lines, "RestoreTarget library: the drive").startswith("UNEXPECTED")


def test_403_on_the_test_mailbox_fails_the_check(pfx):
    fake = with_canary(FakeTenant(app_grants=APP_GRANTS - {f"mailbox:{tenant.RESTORETEST_UPN.lower()}"}))
    code, lines, _ = check(pfx, fake=fake)
    assert code == 1
    assert row(lines, "restoretest's mailbox").startswith("UNEXPECTED")


def test_extra_role_in_the_token_fails_the_check_even_if_every_probe_passes(pfx):
    token = make_app_token(CLIENT_ID, roles=("Sites.Selected", "Files.SelectedOperations.Selected", "Mail.Read"))
    code, lines, _ = check(pfx, app=FakeConfidentialApp({"access_token": token}))
    assert code == 1
    line = row(lines, "token roles, Microsoft Graph")
    assert "UNEXPECTED" in line and "Mail.Read" in line
    assert lines[-1].endswith("; 1 UNEXPECTED")


def test_missing_role_in_the_token_fails_the_check(pfx):
    token = make_app_token(CLIENT_ID, roles=("Sites.Selected",))
    code, lines, _ = check(pfx, app=FakeConfidentialApp({"access_token": token}))
    assert code == 1
    assert "UNEXPECTED" in row(lines, "token roles, Microsoft Graph")


def test_token_that_is_not_a_jwt_fails_the_roles_row(pfx):
    fake = with_canary(FakeTenant())

    def transport(method, url, headers, body=None):
        # The fake tenant answers app-only calls only for JWT-shaped tokens; re-sign as one.
        if headers.get("Authorization", "").startswith("Bearer token:"):  # alice, delegated
            return fake.request(method, url, headers, body)
        return fake.request(method, url, {**headers, "Authorization": "Bearer " + make_app_token(CLIENT_ID)}, body)

    class Wrapped:
        request = staticmethod(transport)

    code, lines, _ = check(pfx, fake=fake, transport=Wrapped(), app=FakeConfidentialApp({"access_token": "opaque"}))
    assert code == 1
    assert "can't be read" in row(lines, "token roles, Microsoft Graph")


def test_no_response_on_a_probe_is_reported_and_fails_the_check(pfx):
    fake = with_canary(FakeTenant())

    class Flaky:
        def request(self, method, url, headers, body=None):
            if "/users/" in url and "alice" in url:
                raise TransportError("GET https://graph.microsoft.com/...: ConnectionError: reset")
            return fake.request(method, url, headers, body)

    code, lines, _ = check(pfx, fake=fake, transport=Flaky())
    assert code == 1
    line = row(lines, "alice's mailbox")
    assert line.startswith("UNEXPECTED") and "none" in line


def test_missing_client_id_is_an_auth_error(monkeypatch):
    monkeypatch.delenv(CLIENT_ID_ENV, raising=False)
    monkeypatch.setattr(tenant, "WORKER_CLIENT_ID", "")
    with pytest.raises(AuthError, match="No client ID for the RestoreProof Worker app"):
        resolve_worker_client_id(None, env={})


def test_cli_credential_error_is_one_line_exit_2(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "SignIn", fake_seeder_signin())
    monkeypatch.setattr(cli, "read_generic_credential", lambda target: None)
    code = cli.main(["check-worker-app", "--client-id", CLIENT_ID, "--pfx", str(tmp_path / "x.pfx")])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.err.startswith("error: Credential Manager has no generic credential")
    assert len(captured.err.strip().splitlines()) == 1
    assert "Traceback" not in captured.err + captured.out


@pytest.mark.parametrize(
    ("api", "role"),
    [("Exchange Online", "full_access_as_app"), ("SharePoint", "Sites.Read.All")],
)
def test_a_role_on_another_api_fails_the_check_although_graph_looks_right(pfx, api, role):
    # Such a consent never shows in the Graph token, and every Graph probe still answers as expected.
    app = FakeConfidentialApp(others={api: token_result(roles=(role,))})
    code, lines, _ = check(pfx, app=app)
    assert code == 1
    line = row(lines, f"token roles, {api}")
    assert "UNEXPECTED" in line and role in line
    assert lines[-1] == f"{len(probes())}/{len(probes())} probes as expected; 1 UNEXPECTED"


def test_a_token_error_on_another_api_is_an_auth_error(pfx):
    error = {"error": "invalid_resource", "error_description": "AADSTS500011: resource not found"}
    with pytest.raises(AuthError, match="invalid_resource"):
        check(pfx, app=FakeConfidentialApp(others={"Exchange Online": error}))


@pytest.mark.parametrize("error", [ConnectionError("proxy refused"), ValueError("Unable to get authority configuration")])
def test_msal_exceptions_are_auth_errors(pfx, error):
    class Raising(FakeConfidentialApp):
        def acquire_token_for_client(self, scopes):
            raise error

    with pytest.raises(AuthError, match=type(error).__name__):
        check(pfx, app=Raising())


@pytest.mark.parametrize("error", [ConnectionError("no route"), ValueError("Unable to get authority configuration")])
def test_cli_sign_in_exceptions_exit_2_without_a_traceback(monkeypatch, pfx, capsys, error):
    # MSAL's constructor already goes to the network (tenant discovery).
    def failing_app(*args, **kwargs):
        raise error

    monkeypatch.setattr(cli, "SignIn", fake_seeder_signin())
    monkeypatch.setattr(cli, "read_generic_credential", password_store())
    monkeypatch.setattr(cli, "RequestsTransport", lambda: FakeTenant())
    monkeypatch.setattr(worker_app.msal, "ConfidentialClientApplication", failing_app)
    code = cli.main(["check-worker-app", "--client-id", CLIENT_ID, "--pfx", str(pfx)])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.err.startswith("error: Sign-in as the RestoreProof Worker app failed")
    assert "Traceback" not in captured.err + captured.out


def test_restore_target_renamed_fails_the_root_listing(pfx):
    # Veeam's OneDrive restore finds the folder by name: a renamed one keeps its grant, but
    # restores would land in a new folder the app can't read.
    fake = with_canary(FakeTenant())
    fake.item_names[tenant.ONEDRIVE_TARGET_FOLDER_ID] = "RestoreTarget (old)"
    code, lines, _ = check(pfx, fake=fake)
    assert code == 1
    line = row(lines, "alice's OneDrive: files in her root")
    assert line.startswith("UNEXPECTED") and "RestoreTarget is named 'RestoreTarget (old)'" in line


def test_an_empty_root_listing_fails_the_check(pfx):
    # RestoreTarget moved out of her root: its ID still answers, but nothing is listed.
    fake = with_canary(FakeTenant())

    class Empty:
        def request(self, method, url, headers, body=None):
            if url.split("?")[0].endswith("/root/children"):
                return json_response(200, {"value": []})
            return fake.request(method, url, headers, body)

    code, lines, _ = check(pfx, fake=fake, transport=Empty())
    assert code == 1
    line = row(lines, "alice's OneDrive: files in her root")
    assert line.startswith("UNEXPECTED") and "RestoreTarget not listed" in line


def test_a_missing_canary_folder_fails_the_check_although_the_app_gets_404(pfx):
    # A deleted folder answers 404 too, so then the 404 rows prove nothing about masking.
    site = f"site:{tenant.ONEDRIVE_HOST}:{tenant.ALICE_ONEDRIVE_SITE_PATH}"
    fake = FakeTenant(app_grants=APP_GRANTS | {site})
    del fake.drives[tenant.ONEDRIVE_DRIVE_ID].folders[tenant.ONEDRIVE_FOLDER_ID]
    code, lines, _ = check(pfx, fake=fake)
    assert code == 1
    line = row(lines, "canary folder, read as alice")
    assert "UNEXPECTED" in line and "HTTP 404" in line


def test_an_empty_canary_folder_fails_the_check(pfx):
    code, lines, _ = check(pfx, fake=FakeTenant())  # not seeded
    assert code == 1
    line = row(lines, "canary folder, read as alice")
    assert "UNEXPECTED" in line and "seed" in line


# ---- happy paths ---------------------------------------------------------------------------


def test_everything_as_granted_passes(pfx, key_and_cert):
    app = FakeConfidentialApp()
    code, lines, fake = check(pfx, app=app)
    assert code == 0
    assert lines[-1] == f"{len(probes())}/{len(probes())} probes as expected"
    assert not any(line.startswith("UNEXPECTED") for line in lines)
    roles_line = row(lines, "token roles, Microsoft Graph")
    assert roles_line.rstrip().endswith("ok")
    assert "Files.SelectedOperations.Selected, Sites.Selected" in roles_line
    for api in OTHER_API_SCOPES:
        assert row(lines, f"token roles, {api}").rstrip().endswith("(none)  ok")
    assert row(lines, "canary folder, read as alice").rstrip().endswith("RestoreTest, 1 item  ok")
    asked = list(dict.fromkeys(scopes for _, scopes in app.calls))  # each probe asks again (MSAL caches)
    assert asked == [tuple(GRAPH_SCOPES)] + [tuple(v) for v in OTHER_API_SCOPES.values()]
    # the header names the app and the certificate, never the key
    _, cert = key_and_cert
    thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
    assert row(lines, "client ID").split()[-1] == CLIENT_ID
    assert thumbprint in row(lines, "certificate")
    assert "2027-09-27" in row(lines, "certificate")


def test_probe_table_covers_the_done_when():
    by_status: dict[int, set[str]] = {}
    for p in probes():
        by_status.setdefault(p.expected, set()).add(p.label)
    assert set(by_status) == {200, 403, 404}
    needed = {
        200: [
            "restoretest's mailbox",
            "RestoreTest site: the site",
            "RestoreTarget library: the drive",
            "alice's OneDrive: RestoreTarget folder",
            "alice's OneDrive: files in her root",
        ],
        403: [
            "alice's mailbox",
            "tenant root site: the site",
            "tenant root site: its libraries",
            "OneDrive host root site",
            "directory: list users",
        ],
        404: [
            "alice's OneDrive: RestoreTest canary folder",
            "alice's OneDrive: files in the RestoreTest canary folder",
        ],
    }
    for status, labels in needed.items():
        for label in labels:
            assert any(have.startswith(label) for have in by_status[status]), (status, label)


def test_only_the_root_listing_checks_what_is_listed():
    listing = [p for p in probes() if p.only_item is not None]
    assert [p.label for p in listing] == ["alice's OneDrive: files in her root (only RestoreTarget)"]
    assert listing[0].only_item == (tenant.ONEDRIVE_TARGET_FOLDER_ID, "RestoreTarget")
    assert listing[0].params is not None and "$top" not in listing[0].params  # a page of 1 would hide the rest


def test_the_check_only_reads_and_never_touches_other_drives_by_write(pfx):
    _, _, fake = check(pfx)
    assert fake.app_requests, "no request was sent"
    assert {method for method, _ in fake.app_requests} == {"GET"}
    assert len(fake.app_requests) == len(probes())


def test_every_probe_path_uses_the_ids_from_tenant_py():
    paths = " ".join(p.path for p in probes())
    for value in (
        tenant.RESTORETEST_UPN,
        tenant.ALICE_UPN,
        tenant.SHAREPOINT_SITE_ID,
        tenant.SHAREPOINT_HOST,
        tenant.RESTORE_TARGET_DRIVE_ID,
        tenant.ONEDRIVE_DRIVE_ID,
        tenant.ONEDRIVE_TARGET_FOLDER_ID,
        tenant.ONEDRIVE_FOLDER_ID,
        tenant.ALICE_ONEDRIVE_SITE_PATH,
    ):
        assert value in paths, value


def test_expected_roles_are_the_two_selected_scopes():
    assert EXPECTED_ROLES == frozenset({"Sites.Selected", "Files.SelectedOperations.Selected"})


def test_load_pfx_gives_the_thumbprint_and_expiry(pfx, key_and_cert):
    _, cert = key_and_cert
    loaded = load_pfx(pfx, PASSWORD_SENTINEL)
    assert loaded.thumbprint_sha1 == cert.fingerprint(hashes.SHA1()).hex().upper()
    assert loaded.not_after.date() == dt.date(2027, 9, 27)
    assert PASSWORD_SENTINEL not in repr(loaded) and "PRIVATE" not in repr(loaded)


def test_default_pfx_path_is_under_local_appdata():
    path = default_pfx_path({"LOCALAPPDATA": r"C:\Users\x\AppData\Local"})
    assert path == Path(r"C:\Users\x\AppData\Local") / "RestoreProof" / "lab" / "worker-graph.pfx"


def test_client_id_order_option_env_tenant(monkeypatch):
    monkeypatch.setattr(tenant, "WORKER_CLIENT_ID", "from-tenant")
    assert resolve_worker_client_id("from-cli", env={CLIENT_ID_ENV: "from-env"}) == "from-cli"
    assert resolve_worker_client_id(None, env={CLIENT_ID_ENV: "from-env"}) == "from-env"
    assert resolve_worker_client_id(None, env={}) == "from-tenant"


@pytest.mark.skipif(sys.platform != "win32", reason="Credential Manager is Windows only")
def test_credential_manager_read_of_an_unknown_target_is_none():
    assert worker_app.read_generic_credential("RestoreProof Lab - no such target 7f3a9c") is None


@pytest.mark.skipif(sys.platform == "win32", reason="checks the non-Windows message")
def test_credential_manager_off_windows_is_a_credential_error():
    with pytest.raises(CredentialError, match="Windows"):
        worker_app.read_generic_credential(CREDENTIAL_TARGET)


def fake_seeder_signin(signins: list[tuple] | None = None):
    def make(client_id, tenant_id, *, mode, out):
        if signins is not None:
            signins.append((client_id, tenant_id, mode))
        return FakeSignIn()

    return make


def test_cli_runs_the_check_end_to_end(monkeypatch, pfx, capsys):
    fake = with_canary(FakeTenant())
    made: list[tuple] = []
    signins: list[tuple] = []

    def fake_app(client_id, *, authority, client_credential, timeout):
        made.append((client_id, authority, sorted(client_credential), timeout))
        return FakeConfidentialApp()

    monkeypatch.setattr(cli, "SignIn", fake_seeder_signin(signins))
    monkeypatch.setattr(cli, "read_generic_credential", password_store())
    monkeypatch.setattr(cli, "RequestsTransport", lambda: fake)
    monkeypatch.setattr(worker_app.msal, "ConfidentialClientApplication", fake_app)
    code = cli.main(["check-worker-app", "--client-id", CLIENT_ID, "--pfx", str(pfx)])
    out = capsys.readouterr().out
    assert code == 0, out
    assert made == [
        (CLIENT_ID, f"https://login.microsoftonline.com/{tenant.TENANT_ID}", ["private_key", "public_certificate"], 60)
    ]
    assert signins == [(tenant.SEEDER_CLIENT_ID, tenant.TENANT_ID, "browser")]
    assert out.strip().endswith(f"{len(probes())}/{len(probes())} probes as expected")


# ---- secrets: the sentinel grep over every output ----------------------------------------------


@pytest.mark.parametrize(
    "scenario",
    ["ok", "unexpected", "no_credential", "wrong_password", "token_error", "no_response"],
)
def test_no_output_contains_a_secret(scenario, monkeypatch, pfx, key_and_cert, capsys):
    fake = with_canary(FakeTenant())
    app = FakeConfidentialApp()
    read = password_store()
    transport = fake
    if scenario == "unexpected":
        fake.app_grants.add(f"mailbox:{tenant.ALICE_UPN.lower()}")
    elif scenario == "no_credential":
        read = password_store(None)
    elif scenario == "wrong_password":
        read = password_store(PASSWORD_SENTINEL + "x")
    elif scenario == "token_error":
        app = FakeConfidentialApp(
            {
                "error": "invalid_client",
                "error_description": f"bad {PASSWORD_SENTINEL} {TOKEN_SENTINEL}",
                "access_token": TOKEN_SENTINEL,
            }
        )
    elif scenario == "no_response":

        class Down:
            def request(self, method, url, headers, body=None):
                raise TransportError(f"GET {url}: ConnectionError: {headers.get('Authorization')}")

        transport = Down()

    monkeypatch.setattr(worker_app, "_sleep", lambda seconds: None)  # no real retry waits
    monkeypatch.setattr(cli, "SignIn", fake_seeder_signin())
    monkeypatch.setattr(cli, "read_generic_credential", read)
    monkeypatch.setattr(cli, "RequestsTransport", lambda: transport)
    monkeypatch.setattr(worker_app.msal, "ConfidentialClientApplication", lambda *a, **k: app)
    code = cli.main(["check-worker-app", "--client-id", CLIENT_ID, "--pfx", str(pfx)])
    captured = capsys.readouterr()
    assert code == {"ok": 0, "unexpected": 1, "no_response": 1}.get(scenario, 2)
    assert_no_secret([captured.out, captured.err], key_and_cert[0])
