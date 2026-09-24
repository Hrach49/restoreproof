"""Delegated sign-in with MSAL, one account at a time. Tokens stay in memory and are never printed."""

import os
from typing import Any, Callable, Mapping

import msal

from seeder import tenant

SCOPES = ["Mail.Send", "Mail.Read", "Files.ReadWrite", "Sites.ReadWrite.All", "User.Read"]
MODES = ("browser", "device")
CLIENT_ID_ENV = "RP_LAB_CLIENT_ID"


class AuthError(Exception):
    """Sign-in failed. The message never contains a token."""


class WrongAccountError(AuthError):
    """Someone signed in, but not as the account this step needs."""


def _msal_error(upn: str, result: Mapping[str, Any]) -> AuthError:
    # Only error and error_description: an MSAL result may also hold tokens.
    error = result.get("error") or "unknown_error"
    description = result.get("error_description") or ""
    return AuthError(f"Sign-in as {upn} failed: {error}: {description}".rstrip(": "))


class SignIn:
    """Hands out token providers per UPN. `app` is an msal.PublicClientApplication (or a test
    fake); by default it is created on the first token request so building a SignIn never
    touches the network. MSAL's default token cache is in memory; nothing is written to disk."""

    def __init__(
        self,
        client_id: str,
        tenant_id: str,
        *,
        mode: str = "browser",
        app: Any = None,
        out: Callable[[str], None] = print,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"auth mode must be one of {MODES}, not {mode!r}")
        self._client_id = client_id
        self._tenant_id = tenant_id
        self._mode = mode
        self._app = app
        self._out = out
        self._accounts: dict[str, Any] = {}  # lower-case UPN -> MSAL account

    def __repr__(self) -> str:
        return f"SignIn(mode={self._mode!r}, accounts={sorted(self._accounts)!r})"

    @property
    def app(self) -> Any:
        if self._app is None:
            self._app = msal.PublicClientApplication(
                self._client_id, authority=f"https://login.microsoftonline.com/{self._tenant_id}"
            )
        return self._app

    def token_provider(self, upn: str, purpose: str) -> Callable[[], str]:
        return lambda: self._token(upn, purpose)

    def _token(self, upn: str, purpose: str) -> str:
        account = self._accounts.get(upn.lower())
        if account is not None:
            result = self.app.acquire_token_silent(SCOPES, account=account)
            if result and result.get("access_token"):
                return result["access_token"]
            # None or an error (expired refresh token, interaction_required): sign in again.
        return self._sign_in(upn, purpose)

    def _sign_in(self, upn: str, purpose: str) -> str:
        self._out(f"==> Sign in as {upn}  ({purpose})")
        if self._mode == "device":
            flow = self.app.initiate_device_flow(scopes=SCOPES)
            if "user_code" not in flow:
                raise _msal_error(upn, flow)
            self._out(flow["message"])
            self._out(f"    Sign in as {upn}.")
            result = self.app.acquire_token_by_device_flow(flow)
        else:
            self._out(f"    A browser window opens; choose or type {upn}.")
            result = self.app.acquire_token_interactive(SCOPES, login_hint=upn, prompt="select_account")

        if "error" in result:
            raise _msal_error(upn, result)
        signed_in = (result.get("id_token_claims") or {}).get("preferred_username", "")
        if signed_in.lower() != upn.lower():
            raise WrongAccountError(
                f"You signed in as {signed_in or 'an unknown account'}, but this step needs {upn}. "
                f"Run the command again and pick {upn} in the account picker."
            )
        token = result.get("access_token")
        if not token:
            raise AuthError(f"Sign-in as {upn} returned no access token.")
        accounts = self.app.get_accounts(username=signed_in)
        if accounts:
            self._accounts[upn.lower()] = accounts[0]
        return token


def resolve_client_id(cli_value: str | None, env: Mapping[str, str] = os.environ) -> str:
    """--client-id, then RP_LAB_CLIENT_ID, then tenant.SEEDER_CLIENT_ID."""
    for value in (cli_value, env.get(CLIENT_ID_ENV), tenant.SEEDER_CLIENT_ID):
        if value and value.strip():
            return value.strip()
    raise AuthError(
        "No client ID for the seeder app. Pass --client-id or set RP_LAB_CLIENT_ID "
        "(the app registration is described in lab/README.md)."
    )
