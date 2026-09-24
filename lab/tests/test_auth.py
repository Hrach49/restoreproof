import pytest

from seeder import auth
from seeder.auth import SCOPES, AuthError, SignIn, WrongAccountError, resolve_client_id
from seeder.tenant import ADMIN_UPN, ALICE_UPN, BOB_UPN, SEEDER_CLIENT_ID, TENANT_ID

SENTINEL = "sentinel-token-DO-NOT-LEAK"


def ok(upn: str, token: str) -> dict:
    return {"access_token": token, "id_token_claims": {"preferred_username": upn}}


class FakeApp:
    """msal.PublicClientApplication look-alike. `sign_ins` scripts what each interactive or
    device-flow sign-in returns; the fake remembers accounts that signed in successfully."""

    def __init__(self, sign_ins: list[dict] | None = None, silent: dict | None = None) -> None:
        self.sign_ins = list(sign_ins or [])
        self.silent = silent  # upn(lower) -> result or None; missing key -> cached token
        self.accounts: dict[str, dict] = {}
        self.tokens: dict[str, str] = {}
        self.calls: list[tuple] = []

    def _finish(self, result: dict) -> dict:
        if "access_token" in result and "error" not in result:
            upn = result["id_token_claims"]["preferred_username"]
            self.accounts[upn.lower()] = {"username": upn, "home_account_id": f"id-{upn}"}
            self.tokens[upn.lower()] = result["access_token"]
        return result

    def get_accounts(self, username=None):
        self.calls.append(("get_accounts", username))
        return [a for k, a in self.accounts.items() if username is None or k == username.lower()]

    def acquire_token_silent(self, scopes, account):
        self.calls.append(("silent", tuple(scopes), account["username"]))
        key = account["username"].lower()
        if self.silent is not None and key in self.silent:
            return self.silent.pop(key)
        return {"access_token": self.tokens[key]}

    def acquire_token_interactive(self, scopes, login_hint=None, prompt=None):
        self.calls.append(("interactive", tuple(scopes), login_hint, prompt))
        return self._finish(self.sign_ins.pop(0))

    def initiate_device_flow(self, scopes):
        self.calls.append(("device_init", tuple(scopes)))
        return {"user_code": "ABC123", "message": "To sign in, open https://microsoft.com/devicelogin and enter ABC123."}

    def acquire_token_by_device_flow(self, flow):
        self.calls.append(("device_finish", flow["user_code"]))
        return self._finish(self.sign_ins.pop(0))


def make(app, mode="browser"):
    lines: list[str] = []
    return SignIn("client-1", TENANT_ID, mode=mode, app=app, out=lines.append), lines


def kinds(app) -> list[str]:
    return [c[0] for c in app.calls if c[0] != "get_accounts"]


# ---- failure paths -------------------------------------------------------------------


def test_wrong_account_names_both(capsys):
    app = FakeApp([ok(BOB_UPN, SENTINEL)])
    signin, lines = make(app)
    with pytest.raises(WrongAccountError) as info:
        signin.token_provider(ALICE_UPN, "read alice's mail")()
    msg = str(info.value)
    assert f"You signed in as {BOB_UPN}, but this step needs {ALICE_UPN}" in msg
    for text in (msg, repr(info.value), capsys.readouterr().out, *lines):
        assert SENTINEL not in text


@pytest.mark.parametrize("mode", ["browser", "device"])
def test_msal_error_becomes_auth_error_without_token(mode, capsys):
    error = {
        "error": "invalid_client",
        "error_description": "AADSTS7000218: The request body must contain client_assertion.",
        "access_token": SENTINEL,  # never echoed even if present
    }
    app = FakeApp([error])
    signin, lines = make(app, mode)
    with pytest.raises(AuthError) as info:
        signin.token_provider(ALICE_UPN, "p")()
    msg = str(info.value)
    assert "invalid_client" in msg and "AADSTS7000218" in msg and ALICE_UPN in msg
    assert not isinstance(info.value, WrongAccountError)
    for text in (msg, repr(info.value), capsys.readouterr().out, *lines):
        assert SENTINEL not in text


def test_result_without_token_or_error_is_auth_error():
    app = FakeApp([{"id_token_claims": {"preferred_username": ALICE_UPN}}])
    signin, _ = make(app)
    with pytest.raises(AuthError, match="no access token"):
        signin.token_provider(ALICE_UPN, "p")()


def test_device_flow_that_cannot_start_is_auth_error():
    app = FakeApp()
    app.initiate_device_flow = lambda scopes: {"error": "unauthorized_client", "error_description": "public flows off"}
    signin, _ = make(app, "device")
    with pytest.raises(AuthError, match="public flows off"):
        signin.token_provider(ALICE_UPN, "p")()


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        SignIn("c", TENANT_ID, mode="magic", app=FakeApp())


# ---- sign-in flow --------------------------------------------------------------------


def test_first_sign_in_prints_banner_once_then_goes_silent():
    app = FakeApp([ok(ALICE_UPN.upper(), "t-alice")])  # UPN case differs: still the same account
    signin, lines = make(app)
    get = signin.token_provider(ALICE_UPN, "upload OneDrive files")

    assert get() == "t-alice"
    assert get() == "t-alice"
    assert signin.token_provider(ALICE_UPN, "read mail")() == "t-alice"

    banners = [l for l in lines if l.startswith("==>")]
    assert banners == [f"==> Sign in as {ALICE_UPN}  (upload OneDrive files)"]
    assert any("browser" in l for l in lines)
    assert kinds(app) == ["interactive", "silent", "silent"]
    assert app.calls[0] == ("interactive", tuple(SCOPES), ALICE_UPN, "select_account")


@pytest.mark.parametrize("silent_result", [None, {"error": "interaction_required", "error_description": "x"}])
def test_silent_failure_signs_in_again_with_banner(silent_result):
    app = FakeApp([ok(ALICE_UPN, "t1"), ok(ALICE_UPN, "t2")], silent={ALICE_UPN.lower(): silent_result})
    signin, lines = make(app)
    get = signin.token_provider(ALICE_UPN, "p")
    assert get() == "t1"
    assert get() == "t2"
    assert kinds(app) == ["interactive", "silent", "interactive"]
    assert len([l for l in lines if l.startswith("==>")]) == 2


def test_device_mode_prints_flow_message_and_upn():
    app = FakeApp([ok(BOB_UPN, "t-bob")])
    signin, lines = make(app, "device")
    assert signin.token_provider(BOB_UPN, "read bob's mail")() == "t-bob"
    assert lines[0] == f"==> Sign in as {BOB_UPN}  (read bob's mail)"
    assert "To sign in, open https://microsoft.com/devicelogin and enter ABC123." in lines
    assert any(BOB_UPN in l for l in lines[1:])
    assert kinds(app) == ["device_init", "device_finish"]


def test_two_accounts_keep_separate_tokens():
    app = FakeApp([ok(ALICE_UPN, "t-alice"), ok(BOB_UPN, "t-bob")])
    signin, lines = make(app)
    alice = signin.token_provider(ALICE_UPN, "a")
    bob = signin.token_provider(BOB_UPN, "b")
    assert alice() == "t-alice"
    assert bob() == "t-bob"
    assert alice() == "t-alice"
    assert bob() == "t-bob"
    assert kinds(app) == ["interactive", "interactive", "silent", "silent"]
    assert [c[2] for c in app.calls if c[0] == "silent"] == [ALICE_UPN, BOB_UPN]
    assert len([l for l in lines if l.startswith("==>")]) == 2


def test_default_app_is_built_lazily_with_the_tenant_authority(monkeypatch):
    built: list[tuple] = []

    class FakePCA(FakeApp):
        def __init__(self, client_id, **kwargs):
            built.append((client_id, kwargs))
            super().__init__([ok(ADMIN_UPN, "t")])

    monkeypatch.setattr(auth.msal, "PublicClientApplication", FakePCA)
    signin = SignIn("client-1", TENANT_ID, out=lambda _: None)
    get = signin.token_provider(ADMIN_UPN, "p")
    assert built == []  # nothing (and no network) until a token is needed
    assert get() == "t"
    assert get() == "t"
    assert built == [("client-1", {"authority": f"https://login.microsoftonline.com/{TENANT_ID}"})]


# ---- client id -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "cli, env, expected",
    [
        ("cli-id", {"RP_LAB_CLIENT_ID": "env-id"}, "cli-id"),
        (None, {"RP_LAB_CLIENT_ID": "env-id"}, "env-id"),
        ("  ", {"RP_LAB_CLIENT_ID": " env-id "}, "env-id"),
        ("", {"RP_LAB_CLIENT_ID": "env-id"}, "env-id"),
    ],
)
def test_resolve_client_id_precedence(cli, env, expected):
    assert resolve_client_id(cli, env=env) == expected


def test_resolve_client_id_falls_back_to_tenant_constant(monkeypatch):
    monkeypatch.setattr(auth.tenant, "SEEDER_CLIENT_ID", "const-id")
    assert resolve_client_id(None, env={}) == "const-id"
    assert resolve_client_id(None, env={"RP_LAB_CLIENT_ID": ""}) == "const-id"


def test_resolve_client_id_errors_when_nothing_set(monkeypatch):
    monkeypatch.setattr(auth.tenant, "SEEDER_CLIENT_ID", "")
    with pytest.raises(AuthError, match="lab/README.md") as info:
        resolve_client_id(None, env={})
    assert "--client-id" in str(info.value) and "RP_LAB_CLIENT_ID" in str(info.value)


def test_tenant_constant_is_a_string():
    assert isinstance(SEEDER_CLIENT_ID, str)
