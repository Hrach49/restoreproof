"""Initialize-RestoreProofTenant.ps1 as a whole, against tests/FakeTenant.ps1 (W7.0, decision points
5 to 10), failure paths first: what it refuses before it signs in, what stops it with nothing
more changed, the check that never passes on a read it couldn't make; then a tenant that has never
seen RestoreProof, the writes it makes and nowhere else, each write grant behind its name check,
a second run that changes nothing and prints the same profile, -WhatIf and -CheckOnly."""

import json
import re

import jsonschema
import pytest

import certs
import fake_tenant as ft
from fake_tenant import ADDRESS, DRIVE, SITE_ID, copy_state, never_seen, run_setup
from pwsh import SHARED_SCHEMA


def schema():
    return json.loads(SHARED_SCHEMA.read_text(encoding="utf-8"))


def app_of(state):
    apps = [a for a in state["applications"] if a["displayName"] == "RestoreProof Worker"]
    assert len(apps) == 1
    return apps[0]


def sp_of(state):
    app = app_of(state)
    return next(s for s in state["servicePrincipals"] if s["appId"] == app["appId"])


def target_list(state):
    site = next(s for s in state["sites"] if s["id"] == SITE_ID)
    return next(l for l in site["lists"] if l["displayName"] == "RestoreTarget")


def target_folder(state):
    drive = next(d for d in state["drives"] if d["id"] == DRIVE)
    return next(i for i in drive["items"] if i["name"] == "RestoreTarget")


def set_up(tmp_path, state=None):
    """A tenant the script has set up once, and that run."""
    first = run_setup(tmp_path, state or never_seen(), name="first")
    assert first.code == "ok", first.out
    return first


# ---- refused before anything is read ----------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "change", "params", "words"),
    [
        ("no graph module", lambda s: s["modules"].pop("Microsoft.Graph.Authentication"), (), "Microsoft.Graph.Authentication is not installed"),
        ("an old exchange module", lambda s: s["modules"].update({"ExchangeOnlineManagement": "3.6.0"}), (), "3.7.2 or later is not installed"),
        ("the root site", None, ("-SiteUrl", "https://contoso.sharepoint.com/"), "root site"),
        ("a onedrive site", None, ("-SiteUrl", "https://contoso-my.sharepoint.com/personal/x"), "OneDrive host"),
        ("another mailbox name", None, ("-MailboxAddress", f"alice@{ft.DOMAIN}"), "restoretest@<domain>"),
        ("both whatif and checkonly", None, ("-WhatIf", "-CheckOnly"), "at most one of"),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_refused_with_nothing_changed(tmp_path, label, change, params, words):
    state = never_seen()
    if change and callable(change):
        change(state)
    result = run_setup(tmp_path, state, *params)
    assert result.code == "throw", result.out
    assert words in result.thrown
    assert result.writes() == [] and result.exchange_writes() == []


@pytest.mark.parametrize(
    ("certificate", "words"),
    [
        (ft.PEM + ft.KEY_PEM, "holds a private key"),
        (certs.pem(certs.make(bits=1024)[1]), "1024 bits"),
        (certs.pem(certs.make(days=5)[1]), "within 30 days"),
        ("not a certificate", "0 certificates"),
    ],
    ids=["a private key", "rsa 1024", "expiring", "garbage"],
)
def test_a_certificate_the_worker_cant_use_is_refused_before_signing_in(tmp_path, certificate, words):
    result = run_setup(tmp_path, never_seen(), certificate=certificate)
    assert result.code == "throw" and words in result.thrown
    assert result.log == []
    assert "PRIVATE KEY" not in result.out and ft.KEY_PEM.splitlines()[1] not in result.out


def test_another_signed_in_tenant_is_refused(tmp_path):
    state = never_seen()
    state["signedInTenant"] = "bbbbbbbb-1111-4222-8333-444444444444"
    result = run_setup(tmp_path, state)
    assert result.code == "throw" and "not aaaaaaaa-" in result.thrown
    assert result.graph() == [] and result.exchange() == []


def test_an_exchange_session_in_another_tenant_is_refused_before_any_exchange_read(tmp_path):
    """A partner's or a guest's account reaches its own organisation's Exchange (review finding 6)."""
    state = never_seen()
    state["exchangeTenant"] = "bbbbbbbb-1111-4222-8333-444444444444"
    result = run_setup(tmp_path, state)
    assert result.code == "throw" and "Exchange Online signed in to tenant 'bbbbbbbb-" in result.thrown
    assert result.graph() == [] and result.exchange() == []
    assert [e["call"] for e in result.log if e["call"].startswith("Disconnect")] == ["Disconnect-ExchangeOnline", "Disconnect-MgGraph"]


def test_a_failed_exchange_sign_in_still_ends_the_graph_session(tmp_path):
    state = never_seen()
    state["exchangeConnectFails"] = True
    result = run_setup(tmp_path, state)
    assert result.code == "throw" and "cancelled" in result.thrown
    assert [e["call"] for e in result.log if e["call"] == "Disconnect-MgGraph"] == ["Disconnect-MgGraph"]


def a_worker(tmp_path, body: str):
    """A stand-in rpworker.exe for -Worker: a .cmd whose body answers `graph certificate`."""
    cmd = tmp_path / "rpworker.cmd"
    cmd.write_text("@echo off\r\n" + body, encoding="ascii")
    return str(cmd)


def test_a_worker_that_cant_read_its_vault_is_named_by_its_own_words(tmp_path):
    """rpworker's own line, never a guess that leads to -Replace (review finding 4)."""
    worker = a_worker(tmp_path, "1>&2 echo vault error: the vault can't be read: run it elevated\r\nexit /b 1\r\n")
    result = run_setup(tmp_path, never_seen(), "-Worker", worker, certificate=None)
    assert result.code == "throw", result.out
    assert "rpworker graph certificate failed (exit 1): vault error: the vault can't be read: run it elevated" in result.thrown
    assert "never -Replace" in result.thrown
    assert result.log == []


def test_the_workers_pem_is_read_from_its_stdout_alone(tmp_path):
    pem = tmp_path / "out.pem"
    pem.write_text(ft.PEM, encoding="ascii")
    worker = a_worker(tmp_path, f'type "{pem}"\r\n1>&2 echo thumbprint {ft.THUMB} (SHA-1), expires 2028-10-16T00:00:00Z\r\nexit /b 0\r\n')
    result = run_setup(tmp_path, never_seen(), "-Worker", worker, "-WhatIf", certificate=None)
    assert result.code == "ok", result.out
    assert f"ok: the Worker's certificate {ft.THUMB}" in result.out


def test_a_dehydrated_exchange_without_the_switch_changes_nothing(tmp_path):
    state = never_seen()
    state["exchange"]["isDehydrated"] = True
    result = run_setup(tmp_path, state)
    assert result.code == "throw"
    assert "-AllowOrganizationCustomization" in result.thrown and "nothing was changed" in result.thrown
    assert result.writes() == [] and result.exchange_writes() == []


# ---- stopped with nothing more changed ------------------------------------------------------


def test_an_address_that_is_another_mailboxs_alias_stops_it(tmp_path):
    state = never_seen()
    other = ft.mailbox(f"bob@{ft.DOMAIN}")
    other["EmailAddresses"].append(f"smtp:{ADDRESS}")
    state["exchange"]["recipients"].append(other)
    result = run_setup(tmp_path, state)
    assert result.code == "throw" and "secondary address" in result.thrown
    assert result.writes() == [] and result.exchange_writes() == []


@pytest.mark.parametrize("kind", ["GroupMailbox", "MailUser"])
def test_an_address_of_another_kind_stops_it(tmp_path, kind):
    state = never_seen()
    state["exchange"]["recipients"].append(ft.mailbox(ADDRESS, kind))
    result = run_setup(tmp_path, state)
    assert result.code == "throw" and f"is a {kind}" in result.thrown
    assert result.writes() == [] and result.exchange_writes() == []


@pytest.mark.parametrize(
    ("the_list", "words"),
    [
        ({"displayName": "RestoreTarget", "webUrl": f"{ft.SITE_URL}/Lists/RestoreTarget", "template": "genericList"}, "not a document library"),
        ({"displayName": "Archive", "webUrl": f"{ft.SITE_URL}/RestoreTarget", "template": "documentLibrary"}, "named 'Archive'"),
    ],
    ids=["a generic list of that name", "another library at that address"],
)
def test_a_list_that_takes_the_name_stops_it_before_any_grant(tmp_path, the_list, words):
    state = never_seen()
    state["sites"][0]["lists"].append({"id": "77777777-0000-4000-8000-000000000001", "driveId": "b!x", "permissions": [], **the_list})
    result = run_setup(tmp_path, state)
    assert result.code == "throw" and words in result.thrown
    assert [w for w in result.writes() if "permissions" in w["path"] or w["path"].startswith(("applications", "servicePrincipals"))] == []


def test_a_file_named_restoretarget_stops_it(tmp_path):
    state = never_seen()
    state["drives"][0]["items"].append({"id": "01FILE0000000000000000000000000000", "name": "RestoreTarget", "kind": "file", "parentPath": "/drive/root:", "permissions": []})
    result = run_setup(tmp_path, state)
    assert result.code == "throw" and "is not a folder" in result.thrown
    assert [w for w in result.writes() if w["path"].startswith(("drives", "applications", "servicePrincipals"))] == []


def test_an_address_that_names_two_recipients_stops_it(tmp_path):
    """Exchange's "matches multiple entries" is never read as no recipient (review finding 7)."""
    state = never_seen()
    for who in ("bob", "carol"):
        other = ft.mailbox(f"{who}@{ft.DOMAIN}")
        other["EmailAddresses"].append(f"smtp:{ADDRESS}")
        state["exchange"]["recipients"].append(other)
    result = run_setup(tmp_path, state)
    assert result.code == "throw" and "names more than one recipient: nothing was changed" in result.thrown
    assert result.writes() == [] and result.exchange_writes() == []


def test_a_failed_recipient_read_stops_it_and_makes_no_mailbox(tmp_path):
    state = never_seen()
    state["exchange"]["recipientErrors"] = {ADDRESS: "fake: the request was throttled"}
    result = run_setup(tmp_path, state)
    assert result.code == "throw" and "throttled" in result.thrown
    assert result.writes() == [] and result.exchange_writes() == []


def test_a_onedrive_the_admin_cant_open_says_how_and_stops(tmp_path):
    state = never_seen()
    state["drives"][0]["forbidden"] = True
    result = run_setup(tmp_path, state)
    assert result.code == "throw" and "site collection admin" in result.thrown
    assert [w for w in result.writes() if w["path"].startswith(("drives", "applications", "servicePrincipals"))] == []


# ---- the check never passes on what it couldn't read or what is too much ----------------


def test_a_permission_list_the_check_cant_read_is_a_problem_never_a_pass(tmp_path):
    first = set_up(tmp_path)
    state = first.state
    state["failures"] = {f"GET ^drives/{re.escape(DRIVE)}/root/permissions$": 503}
    result = run_setup(tmp_path, state, name="second")
    assert result.code == "1", result.out
    assert "the permissions can't be read (HTTP 503)" in result.out
    assert "grants: 1 problem(s)" in result.out and "grants: ok" not in result.out
    assert result.profile is None or result.profile == first.profile and "profile:" not in result.out


@pytest.mark.parametrize(
    ("label", "change", "words"),
    [
        ("a write grant on the site's other library",
         lambda s: s["sites"][0]["lists"][0]["permissions"].append(
             {"id": "pX", "roles": ["write"], "grantedToV2": {"application": {"id": app_of(s)["appId"]}}}),
         "the site's list 'Documents': the Worker app has a grant of its own here"),
        ("a grant on the user's OneDrive root",
         lambda s: s["drives"][0]["root"]["permissions"].append(
             {"id": "pY", "roles": ["read"], "grantedToV2": {"application": {"id": app_of(s)["appId"]}}}),
         "OneDrive root: the Worker app has a grant here"),
        ("a grant on the user's OneDrive site",
         lambda s: s["sites"][2]["permissions"].append(
             {"id": "pZ", "roles": ["read"], "grantedToIdentities": [{"application": {"id": app_of(s)["appId"]}}]}),
         "OneDrive site: the Worker app has a grant here"),
        ("a directory role",
         lambda s: s["memberOf"].update({sp_of(s)["id"]: [{"displayName": "Global Reader", "@odata.type": "#microsoft.graph.directoryRole"}]}),
         "member of 'Global Reader'"),
        ("a federated credential",
         lambda s: app_of(s).update({"federated": [{"id": "f1", "name": "github"}]}),
         "federated credential"),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_a_grant_beyond_its_own_that_the_script_never_removes_fails_the_check(tmp_path, label, change, words):
    state = set_up(tmp_path).state
    change(state)
    result = run_setup(tmp_path, state, name="second")
    assert result.code == "1", result.out
    assert words in result.out and "problem(s)" in result.out
    assert result.writes() == [] and result.exchange_writes() == []


def test_checkonly_without_an_exchange_pointer_lists_its_problems(tmp_path):
    """A failed Exchange read is a problem, never the end of the check (review finding 3)."""
    state = set_up(tmp_path).state
    state["exchange"]["pointers"] = []
    result = run_setup(tmp_path, state, "-CheckOnly", name="check")
    assert result.code == "1", result.out
    assert "problem: Exchange has no service principal pointer for the app" in result.lines
    assert "grants: 1 problem(s)" in result.lines
    assert result.exchange("Test-ServicePrincipalAuthorization") == []


def test_checkonly_lists_a_recipient_it_cant_read_as_a_problem(tmp_path):
    state = set_up(tmp_path).state
    state["exchange"]["recipientErrors"] = {ft.ADMIN: "fake: the request was throttled", ADDRESS: "fake: busy"}
    result = run_setup(tmp_path, state, "-CheckOnly", name="check")
    assert result.code == "1", result.out
    assert f"problem: {ADDRESS} can't be read in Exchange: fake: busy" in result.lines
    assert f"problem: {ft.ADMIN} can't be read in Exchange: fake: the request was throttled" in result.lines
    assert "grants: 2 problem(s)" in result.lines


def test_a_onedrive_user_that_is_the_restoretest_mailbox_passes(tmp_path):
    """The lab's restoretest is a licensed user: its OneDrive may be the folder's (review finding 2)."""
    state = never_seen()
    state["users"][0]["userPrincipalName"] = ADDRESS
    state["exchange"]["recipients"].append(ft.mailbox(ADDRESS, "UserMailbox"))
    result = run_setup(tmp_path, state, "-OneDriveUser", ADDRESS)
    assert result.code == "ok", result.out
    assert "grants: ok" in result.lines
    assert f"note: {ADDRESS} is the {ADDRESS} mailbox itself" in result.lines


def test_an_app_made_again_gets_its_mail_role_back(tmp_path):
    """The app deleted by the client and the script run again: the old app's assignment of that
    name goes and the new service principal gets its own (review finding 1)."""
    state = set_up(tmp_path).state
    old_sp = sp_of(state)["id"]
    state["applications"], state["servicePrincipals"], state["appRoleAssignments"] = [], [], []
    result = run_setup(tmp_path, state, name="again")
    assert result.code == "ok", result.out
    assert "grants: ok" in result.lines
    new_sp = sp_of(result.state)["id"]
    assert new_sp != old_sp
    assert [a["RoleAssigneeName"] for a in result.state["exchange"]["assignments"]] == [new_sp]
    again = run_setup(tmp_path, result.state, name="third")
    assert again.changes() == 0 and again.exchange_writes() == []


def test_a_service_principal_made_again_gets_a_new_pointer(tmp_path):
    state = set_up(tmp_path).state
    old_sp = sp_of(state)["id"]
    state["servicePrincipals"], state["appRoleAssignments"] = [], []
    result = run_setup(tmp_path, state, name="again")
    assert result.code == "ok", result.out
    assert "grants: ok" in result.lines
    new_sp = sp_of(result.state)["id"]
    cmdlets = [e["cmdlet"] for e in result.exchange_writes()]
    assert cmdlets == ["Remove-ManagementRoleAssignment", "Remove-ServicePrincipal", "New-ServicePrincipal", "New-ManagementRoleAssignment"]
    assert [p["ObjectId"] for p in result.state["exchange"]["pointers"]] == [new_sp]
    assert old_sp not in json.dumps(result.state["exchange"])


def test_reads_and_grants_right_after_the_app_is_made_wait_for_it(tmp_path):
    """A new service principal reaches every replica seconds later (review finding 5)."""
    state = never_seen()
    state["failures"] = {
        "GET ^servicePrincipals/[^/]+/appRoleAssignments$": {"status": 404, "times": 2},
        f"POST ^sites/{re.escape(SITE_ID)}/permissions$": {"status": 400, "times": 1},
        "POST ^drives/[^/]+/items/[^/]+/permissions$": {"status": 404, "times": 1},
    }
    result = run_setup(tmp_path, state)
    assert result.code == "ok", result.out
    assert "grants: ok" in result.lines
    assert [e["seconds"] for e in result.log if e["call"] == "sleep"] == [10] * 4
    assert result.out.count("not ready yet (attempt") == 4


def test_an_org_wide_mail_role_of_another_app_is_noted_not_touched(tmp_path):
    state = set_up(tmp_path).state
    state["exchange"]["assignments"].append({"Name": "Other app", "Role": "Application Mail.Read", "RoleAssigneeType": "ServicePrincipal",
                                             "RoleAssigneeName": "99999999-0000-4000-8000-000000000009", "CustomResourceScope": "", "Identity": "Other app"})
    result = run_setup(tmp_path, state, name="second")
    assert result.code == "ok", result.out
    assert result.exchange_writes() == []


# ---- a tenant that has never seen RestoreProof --------------------------------------------


@pytest.fixture
def first(tmp_path):
    return set_up(tmp_path)


def test_the_first_run_makes_everything_and_the_check_passes(first):
    assert "grants: ok" in first.out
    assert first.changes() == 14
    state = first.state
    app = app_of(state)
    assert app["signInAudience"] == "AzureADMyOrg"
    assert [k["displayName"] for k in app["keyCredentials"]] == [f"CN=RestoreProof Worker {ft.THUMB}"]
    assert app["passwordCredentials"] == []
    sp = sp_of(state)
    held = sorted(a["appRoleId"] for a in state["appRoleAssignments"] if a["principalId"] == sp["id"])
    assert held == sorted(ft.ROLES.values())
    site = state["sites"][0]
    assert [p["roles"] for p in site["permissions"]] == [["read"]]
    assert [p["roles"] for p in target_list(state)["permissions"]] == [["write"]]
    assert [p["roles"] for p in target_folder(state)["permissions"]] == [["write"]]
    assert target_folder(state)["parentPath"] == "/drive/root:"
    assert [r["RecipientTypeDetails"] for r in state["exchange"]["recipients"] if r["PrimarySmtpAddress"] == ADDRESS] == ["SharedMailbox"]
    assert state["exchange"]["scopes"] == [{"Name": "RestoreProof Worker - restoretest mailbox", "RecipientFilter": f"PrimarySmtpAddress -eq '{ADDRESS}'"}]
    assert [a["Role"] for a in state["exchange"]["assignments"]] == ["Application Mail.ReadWrite"]


def test_the_first_run_writes_nowhere_else(first):
    state = first.state
    app, sp, lst, folder = app_of(state), sp_of(state), target_list(state), target_folder(state)
    site, drive = re.escape(SITE_ID), re.escape(DRIVE)
    allowed = [
        rf"POST sites/{site}/lists",
        rf"POST drives/{drive}/root/children",
        r"POST applications",
        rf"(PATCH applications|POST applications/{app['id']}/removePassword)",
        r"POST servicePrincipals",
        rf"(POST|DELETE) servicePrincipals/{sp['id']}/appRoleAssignments(/[^/]+)?",
        rf"(POST|PATCH|DELETE) sites/{site}/permissions(/[^/]+)?",
        rf"(POST|PATCH|DELETE) sites/{site}/lists/{lst['id']}/permissions(/[^/]+)?",
        rf"(POST|PATCH|DELETE) drives/{drive}/items/{folder['id']}/permissions(/[^/]+)?",
    ]
    for write in first.writes():
        line = f"{write['method']} {write['path']}"
        assert any(re.fullmatch(pattern, line) for pattern in allowed), line
    exchange = [(e["cmdlet"], e["args"]) for e in first.exchange_writes()]
    assert exchange == [
        ("New-Mailbox", {"Shared": True, "Name": "RestoreTest", "Alias": "restoretest", "PrimarySmtpAddress": ADDRESS}),
        ("New-ServicePrincipal", {"AppId": app["appId"], "ObjectId": sp["id"]}),
        ("New-ManagementScope", {"Name": "RestoreProof Worker - restoretest mailbox", "RecipientRestrictionFilter": f"PrimarySmtpAddress -eq '{ADDRESS}'"}),
        ("New-ManagementRoleAssignment", {"Name": "RestoreProof Worker - Application Mail.ReadWrite - restoretest", "App": sp["id"],
                                          "Role": "Application Mail.ReadWrite", "CustomResourceScope": "RestoreProof Worker - restoretest mailbox"}),
    ]


def test_every_write_grant_is_sent_right_after_its_name_check(first):
    state = first.state
    lst, folder = target_list(state), target_folder(state)
    graph = first.graph()
    for i, entry in enumerate(graph):
        if entry["method"] != "GET" and entry["path"].endswith("/permissions") and "write" in json.dumps(entry["body"] or {}):
            before = graph[i - 1]
            assert before["method"] == "GET", entry
            assert before["path"].split("?")[0] in (
                f"sites/{SITE_ID}/lists/{lst['id']}", f"drives/{DRIVE}/items/{folder['id']}"), (before, entry)
            assert before["path"].split("?")[0] == entry["path"].rsplit("/permissions", 1)[0]


def test_the_grants_asked_for_are_never_more(first):
    bodies = json.dumps([w["body"] for w in first.writes()])
    for never in ("fullcontrol", "owner", "Sites.ReadWrite.All", "Mail.Read\"", "passwordCredentials\": [{"):
        assert never not in bodies
    asked = [w["body"]["requiredResourceAccess"] for w in first.writes() if w["path"] == "applications"]
    assert len(asked) == 1
    assert sorted(r["id"] for r in asked[0][0]["resourceAccess"]) == sorted(ft.ROLES.values())
    assert {r["type"] for r in asked[0][0]["resourceAccess"]} == {"Role"}


def test_the_profile_is_valid_and_names_what_the_run_made(first):
    profile = json.loads(first.profile)
    jsonschema.validate(profile, schema())
    state = first.state
    assert profile["graph_client_id"] == app_of(state)["appId"]
    assert profile["graph_tenant_id"] == ft.TENANT
    assert profile["test_mailbox"] == ADDRESS
    assert profile["test_site_id"] == SITE_ID
    assert profile["test_library_id"] == target_list(state)["driveId"]
    assert profile["test_onedrive_drive_id"] == DRIVE
    assert profile["test_onedrive_folder_id"] == target_folder(state)["id"]
    assert profile["veeam_org_name"] == ft.DOMAIN
    assert first.profile in first.out.replace("\r\n", "\n").split("profile:\n", 1)[1] + "\n"


def test_the_graph_session_asks_for_the_documented_scopes_alone(first):
    connect = [e for e in first.log if e["call"] == "Connect-MgGraph"]
    assert connect == [{"call": "Connect-MgGraph", "tenant": ft.TENANT, "scopes": [
        "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Sites.FullControl.All",
        "Files.ReadWrite.All", "User.Read.All", "Organization.Read.All"]}]
    assert [e["call"] for e in first.log if e["call"].startswith("Disconnect")] == ["Disconnect-ExchangeOnline", "Disconnect-MgGraph"]


def test_no_key_and_no_secret_reaches_any_output_or_request(first):
    everything = first.out + json.dumps(first.log) + json.dumps(first.state) + (first.profile or "")
    assert "PRIVATE KEY" not in everything
    # The one certificate material sent is the public certificate, byte for byte.
    der = "".join(ft.PEM.strip().splitlines()[1:-1])
    sent = [k["key"] for w in first.writes() for k in (w["body"] or {}).get("keyCredentials", [])]
    assert sent == [der]
    assert "passwordCredentials" not in json.dumps([w["body"] for w in first.writes()])


# ---- a second run changes nothing --------------------------------------------------------


def test_a_second_run_changes_nothing_and_prints_the_same_profile(tmp_path, first):
    second = run_setup(tmp_path, first.state, name="second")
    assert second.code == "ok", second.out
    assert second.changes() == 0
    assert "change:" not in second.out
    assert second.writes() == [] and second.exchange_writes() == []
    assert second.profile == first.profile
    assert second.state == {**first.state, "nextId": second.state["nextId"]}


def a_lab_like_mess(state):
    """What a tenant set up by hand may hold: everything this task removes or sets back."""
    app = app_of(state)
    sp = sp_of(state)
    app["signInAudience"] = "AzureADMultipleOrgs"
    app["passwordCredentials"] = [{"keyId": "s1", "displayName": "made by hand"}]
    app["keyCredentials"].append({"keyId": "k2", "displayName": "CN=old", "customKeyIdentifier": None})
    state["appRoleAssignments"].append({"id": "extra-mail", "principalId": sp["id"], "resourceId": ft.GRAPH_SP,
                                        "appRoleId": ft.MAIL_READ, "resourceDisplayName": "Microsoft Graph"})
    state["appRoleAssignments"].append({"id": "extra-spo", "principalId": sp["id"], "resourceId": "spo",
                                        "appRoleId": "678536fe-1083-478a-9c59-b99265e6b0d3", "resourceDisplayName": "Office 365 SharePoint Online"})
    state["oauth2PermissionGrants"].append({"id": "g1", "clientId": sp["id"], "scope": "User.Read"})
    state["sites"][0]["permissions"][0]["roles"] = ["write"]
    target_list(state)["permissions"][0]["roles"] = ["read"]
    target_folder(state)["permissions"].append({"id": "pf2", "roles": ["write"], "grantedToV2": {"application": {"id": app["appId"]}}})
    state["exchange"]["scopes"][0]["RecipientFilter"] = f"PrimarySmtpAddress -eq 'alice@{ft.DOMAIN}'"
    state["exchange"]["assignments"].append({"Name": "RestoreProof Worker - Application Mail.Read - restoretest", "Role": "Application Mail.Read",
                                             "RoleAssigneeType": "ServicePrincipal", "RoleAssigneeName": sp["id"],
                                             "CustomResourceScope": "", "Identity": "old mail read"})
    return state


def test_a_tenant_set_up_by_hand_is_set_back_and_then_left_alone(tmp_path, first):
    messy = a_lab_like_mess(copy_state(first.state))
    fixed = run_setup(tmp_path, messy, name="fix")
    assert fixed.code == "ok", fixed.out
    assert fixed.changes() == 11, fixed.out
    for words in ("set the app to single tenant", "make the Worker's certificate", "remove the client secret",
                  "remove the consent Microsoft Graph", "remove the consent Office 365 SharePoint Online",
                  "remove the delegated grant 'User.Read'", "from 'write' to 'read'", "from 'read' to 'write'",
                  "remove the Worker app's extra grant on the folder", "set the management scope's filter",
                  "remove the role assignment 'RestoreProof Worker - Application Mail.Read - restoretest'"):
        assert [line for line in fixed.lines if line.startswith("change: ") and words in line], words
    assert "grants: ok" in fixed.out
    assert fixed.profile == first.profile
    again = run_setup(tmp_path, fixed.state, name="again")
    assert again.changes() == 0 and again.writes() == [] and again.exchange_writes() == []


def test_exchange_not_yet_seeing_the_new_app_is_waited_for(tmp_path):
    """Exchange sees a new Entra service principal minutes after Graph made it: the pointer is
    asked again until it is made, so one run sets the tenant up (the second live run stopped)."""
    state = never_seen()
    state["exchange"]["pointerNotFound"] = 5
    result = run_setup(tmp_path, state)
    assert result.code == "ok", result.out
    assert "grants: ok" in result.lines
    assert len(result.exchange("New-ServicePrincipal")) == 6
    assert len(result.state["exchange"]["pointers"]) == 1
    waits = [e["seconds"] for e in result.log if e["call"] == "sleep"]
    assert waits == [30] * 5
    assert result.out.count("note: Exchange does not see the app yet (attempt") == 5


def test_exchange_that_never_sees_the_new_app_stops_it_before_the_scope(tmp_path):
    state = never_seen()
    state["exchange"]["pointerNotFound"] = 1000
    result = run_setup(tmp_path, state)
    assert result.code == "throw"
    assert "AADServicePrincipalNotFound" in result.thrown
    assert len(result.exchange("New-ServicePrincipal")) == 20
    assert not result.exchange("New-ManagementScope", "New-ManagementRoleAssignment")


def test_a_mailbox_that_is_there_is_taken(tmp_path):
    state = never_seen()
    state["exchange"]["recipients"].append(ft.mailbox(ADDRESS, "UserMailbox"))
    result = run_setup(tmp_path, state)
    assert result.code == "ok", result.out
    assert result.exchange("New-Mailbox") == []
    assert f"ok: the mailbox {ADDRESS}" in result.out


def test_a_dehydrated_exchange_with_the_switch_is_customised_once(tmp_path):
    state = never_seen()
    state["exchange"]["isDehydrated"] = True
    result = run_setup(tmp_path, state, "-AllowOrganizationCustomization")
    assert result.code == "ok", result.out
    assert [e["cmdlet"] for e in result.exchange("Enable-OrganizationCustomization")] == ["Enable-OrganizationCustomization"]
    again = run_setup(tmp_path, result.state, "-AllowOrganizationCustomization", name="again")
    assert again.exchange("Enable-OrganizationCustomization") == [] and again.changes() == 0


# ---- -WhatIf and -CheckOnly ------------------------------------------------------------------


def test_whatif_plans_the_first_runs_changes_and_writes_nothing(tmp_path):
    result = run_setup(tmp_path, never_seen(), "-WhatIf")
    assert result.code == "ok", result.out
    assert result.writes() == [] and result.exchange_writes() == []
    assert result.out.count("plan: ") == 14
    assert "changes: 14 (planned; nothing was changed)" in result.out
    assert result.profile is None


def test_checkonly_on_a_tenant_never_set_up_finds_problems_and_writes_nothing(tmp_path):
    result = run_setup(tmp_path, never_seen(), "-CheckOnly")
    assert result.code == "1", result.out
    assert result.writes() == [] and result.exchange_writes() == []
    assert "there is no app registration 'RestoreProof Worker'" in result.out
    assert "the site has no RestoreTarget library" in result.out


def test_checkonly_on_a_tenant_set_up_passes(tmp_path, first):
    result = run_setup(tmp_path, first.state, "-CheckOnly", name="check")
    assert result.code == "ok" and "grants: ok" in result.out
    assert result.writes() == [] and result.exchange_writes() == []
    assert result.profile == first.profile
