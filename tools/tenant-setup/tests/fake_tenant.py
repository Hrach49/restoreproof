"""States for tests/FakeTenant.ps1 and the runner of Initialize-RestoreProofTenant.ps1 against them.

`never_seen()` is a tenant that has never seen RestoreProof: a site made for it with only its
Documents library, a licensed user with a OneDrive, two mailboxes and nothing of the app. Tests
change a copy of it, run the script, and read what it printed, wrote and left."""

import copy
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import certs
from pwsh import SCRIPT, TESTS_DIR, ps_string, run

TENANT = "aaaaaaaa-1111-4222-8333-444444444444"
DOMAIN = "contoso.onmicrosoft.com"
ADMIN = f"admin@{DOMAIN}"
USER = f"restoreproof@{DOMAIN}"
ADDRESS = f"restoretest@{DOMAIN}"
HOST = "contoso.sharepoint.com"
SITE_URL = f"https://{HOST}/sites/RestoreProof"
SITE_ID = f"{HOST},11111111-0000-4000-8000-000000000001,11111111-0000-4000-8000-000000000002"
ROOT_SITE_ID = f"{HOST},22222222-0000-4000-8000-000000000001,22222222-0000-4000-8000-000000000002"
ONEDRIVE_SITE_ID = "contoso-my.sharepoint.com,33333333-0000-4000-8000-000000000001,33333333-0000-4000-8000-000000000002"
ONEDRIVE_SITE_URL = "https://contoso-my.sharepoint.com/personal/restoreproof_contoso_onmicrosoft_com"
DRIVE = "b!userdrive000000000000000000000000000000000000000000000000000000"
DOCUMENTS = "44444444-0000-4000-8000-000000000001"
GRAPH_SP = "55555555-0000-4000-8000-000000000001"
ROLES = {
    "Sites.Selected": "883ea226-0bf2-4a8f-9f9d-92c9162a727d",
    "Files.SelectedOperations.Selected": "bd61925e-3bf4-4d62-bc0b-06b06c96d95c",
    "Lists.SelectedOperations.Selected": "23c5a9bd-d900-4ecf-be26-a0689755d9e5",
}
MAIL_READ = "810c84a8-4a9e-49e6-bf7d-12d183f40d01"
SITES_READWRITE_ALL = "9492366f-7969-46a4-8d15-ed1a20078fff"

_KEY, CERT = certs.make()
PEM = certs.pem(CERT)
THUMB = certs.thumbprint(CERT)
# A sentinel no output, request or file may hold: the Worker's key never reaches the script.
KEY_PEM = certs.key_pem(_KEY)


def mailbox(address, kind="UserMailbox", name="x"):
    return {"Name": name, "Alias": address.split("@")[0], "RecipientTypeDetails": kind,
            "PrimarySmtpAddress": address, "EmailAddresses": [f"SMTP:{address}"]}


def never_seen() -> dict:
    return {
        "modules": {"Microsoft.Graph.Authentication": "2.25.0", "ExchangeOnlineManagement": "3.7.2"},
        "signedInTenant": TENANT,
        "account": ADMIN,
        "organization": {"id": TENANT, "displayName": "Contoso", "verifiedDomains": [
            {"name": "contoso.com", "isInitial": False, "isDefault": True},
            {"name": DOMAIN, "isInitial": True, "isDefault": False}]},
        "graphServicePrincipal": {"id": GRAPH_SP, "appId": "00000003-0000-0000-c000-000000000000", "appRoles": [
            {"id": i, "value": n, "allowedMemberTypes": ["Application"]} for n, i in
            [*ROLES.items(), ("Mail.Read", MAIL_READ), ("Sites.ReadWrite.All", SITES_READWRITE_ALL)]]},
        "sites": [
            {"id": SITE_ID, "path": f"{HOST}:/sites/RestoreProof", "webUrl": SITE_URL, "displayName": "RestoreProof",
             "permissions": [], "lists": [
                 {"id": DOCUMENTS, "displayName": "Documents", "webUrl": f"{SITE_URL}/Shared%20Documents",
                  "template": "documentLibrary", "driveId": "b!documents0000000000000000000000000000000000000000000000000000", "permissions": []}]},
            {"id": ROOT_SITE_ID, "path": f"{HOST}:/", "webUrl": f"https://{HOST}", "displayName": "Communication site",
             "permissions": [], "lists": []},
            {"id": ONEDRIVE_SITE_ID, "path": "contoso-my.sharepoint.com:/personal/restoreproof_contoso_onmicrosoft_com",
             "webUrl": ONEDRIVE_SITE_URL, "displayName": "RestoreProof", "permissions": [], "lists": []},
        ],
        "users": [{"id": "66666666-0000-4000-8000-000000000001", "userPrincipalName": USER, "driveId": DRIVE}],
        "drives": [{"id": DRIVE, "webUrl": f"{ONEDRIVE_SITE_URL}/Documents", "siteUrl": ONEDRIVE_SITE_URL,
                    "forbidden": False, "root": {"id": "01ROOT0000000000000000000000000000", "permissions": []},
                    "items": [{"id": "01NOTES000000000000000000000000000", "name": "notes.txt", "kind": "file",
                               "parentPath": "/drive/root:", "permissions": []}]}],
        "applications": [],
        "servicePrincipals": [],
        "appRoleAssignments": [],
        "oauth2PermissionGrants": [],
        "memberOf": {},
        "exchange": {"recipients": [mailbox(ADMIN), mailbox(USER)], "isDehydrated": False,
                     "pointers": [], "scopes": [], "assignments": []},
        "failures": {},
    }


@dataclass
class Result:
    code: object
    out: str
    state: dict
    log: list
    profile: str | None
    profile_path: Path
    thrown: str = ""
    lines: list = field(default_factory=list)

    def graph(self, *methods):
        return [e for e in self.log if e["call"] == "graph" and (not methods or e["method"] in methods)]

    def writes(self):
        return self.graph("POST", "PATCH", "PUT", "DELETE")

    def exchange(self, *cmdlets):
        return [e for e in self.log if e["call"] == "exchange" and (not cmdlets or e["cmdlet"] in cmdlets)]

    def exchange_writes(self):
        return [e for e in self.exchange() if not e["cmdlet"].startswith(("Get-", "Test-"))]

    def changes(self) -> int:
        found = re.findall(r"^changes: (\d+)", self.out, re.MULTILINE)
        assert found, self.out
        return int(found[-1])


def run_setup(tmp_path: Path, state: dict, *params: str, certificate: str = PEM, name: str = "run") -> Result:
    folder = tmp_path / name
    folder.mkdir()
    state_in = folder / "state-in.json"
    state_out = folder / "state-out.json"
    profile = folder / "profile.json"
    cert_file = folder / "worker-graph.pem"
    state_in.write_text(json.dumps(state), encoding="utf-8")
    cert_file.write_text(certificate, encoding="ascii")
    named = {"-TenantId": TENANT, "-SiteUrl": SITE_URL, "-OneDriveUser": USER,
             "-WorkerCertificateFile": str(cert_file), "-ProfileFile": str(profile)}
    switches = []
    rest = list(params)
    while rest:
        name = rest.pop(0)
        if rest and not rest[0].startswith("-"):
            named[name] = rest.pop(0)
        else:
            switches.append(name)
    args = [x for pair in named.items() for x in pair] + switches
    quoted = " ".join(a if a.startswith("-") else ps_string(a) for a in args)
    command = f"""
        . {ps_string(TESTS_DIR / 'FakeTenant.ps1')} -StatePath {ps_string(state_in)}
        $global:LASTEXITCODE = 0
        $code = 'ok'
        try {{ & {ps_string(SCRIPT)} {quoted}; if ($LASTEXITCODE) {{ $code = "$LASTEXITCODE" }} }}
        catch {{ $code = 'throw'; Write-Host "THROWN: $($_.Exception.Message)"; Write-Host "TRACE: $($_.ScriptStackTrace -replace "`r?`n", ' | ')" }}
        Save-FakeTenant {ps_string(state_out)}
        Write-Host "EXIT: $code"
    """
    result = run(command, timeout=300)
    out = result.stdout
    assert state_out.exists(), f"the fake's state was not saved:\n{out}\n{result.stderr}"
    saved = json.loads(state_out.read_text(encoding="utf-8"))
    codes = re.findall(r"^EXIT: (\S+)$", out, re.MULTILINE)
    assert codes, f"no exit line:\n{out}\n{result.stderr}"
    thrown = re.findall(r"^THROWN: (.*)$", out, re.MULTILINE)
    return Result(
        code=codes[-1], out=out + result.stderr, state=saved["state"], log=saved["log"] or [],
        profile=profile.read_text(encoding="utf-8") if profile.exists() else None, profile_path=profile,
        thrown=thrown[-1] if thrown else "", lines=out.splitlines(),
    )


def copy_state(state: dict) -> dict:
    return copy.deepcopy(state)
