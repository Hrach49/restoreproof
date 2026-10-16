"""The rules on the lab tenant's real answers (W7.0, decision point 10): fixtures/lab/ was recorded
read-only from the lab tenant on 2026-10-16, while it held the Worker app and its three targets as
lab/entra/ made them (before W7.0's live Done-when re-made them: lab/tenant.md). Every plan on that
state is empty, the check finds no problem, the profile is the recorded lab's, and a fault planted
into a real answer is caught.

The fake tenant (FakeTenant.ps1) builds its answers from its own model; these hold the rules to
the shapes Microsoft actually sends: a thumbprint as 40 hex digits in customKeyIdentifier, a
site grant named twice (grantedToIdentities and grantedToIdentitiesV2), a folder grant naming
the app by ID with no displayName, Exchange's answers as text ("True", "False")."""

import base64
import copy
import json
import re

import pytest

from pwsh import FIXTURES, evaluate, ps

LAB = FIXTURES / "lab"
TENANT = "bcd6bd1a-ea42-489d-aa28-2c19a44ad146"
APP_ID = "737da5ef-baf2-4198-b009-e160d8ca77c9"
SP_ID = "f5a56ba3-1b8f-4d4c-8a0a-b2b579b7bd5f"
OTHER_SP = "0b0b0b0b-1111-4222-8333-444444444444"
SITE_ID = "restoreprooflab.sharepoint.com,fe08085d-eb70-42e8-95a6-470189bd98eb,4ecaf399-cc0e-4d95-b3fe-cd091a09e689"
LIST_ID = "ffec069d-65e4-4c3a-9da2-ac086cf9dafa"
DRIVE_ID = "b!wA9gbfhlEUitGAluxbfoNBr_z5gEtDhErm5pJ6bMwyXfZJ8a_dkCQ696RX0r7_U3"
LIBRARY_DRIVE_ID = "b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omdBuz_5GU6TJ2irAhs-dr6"
FOLDER_ID = "01ZK75LGDGB6QOO3MGNFGYOY6C6VBDG5OH"
MAILBOX = "restoretest@RestoreProofLab.onmicrosoft.com"
THUMB = "B56D2BD39945BAB1484A53F6C78C059A369EDBB3"  # lab/tenant.md, the Worker app's credential
RECORDED = "([datetime]'2026-10-16T00:00:00Z')"
# The test accounts a fixture may name (the W4.1 rule), and the recorder's word for the admin.
ACCOUNTS = {"alice", "bob", "restoretest", "admin"}


def answer(number: int) -> dict:
    found = list(LAB.glob(f"{number:03d}-*.json"))
    assert len(found) == 1, f"fixtures/lab has {len(found)} answer(s) numbered {number:03d}"
    return json.loads(found[0].read_text(encoding="utf-8"))


def reply(number: int):
    return answer(number)["reply"]


def values(number: int) -> list:
    return reply(number)["value"]


def rows(number: int) -> list:
    """An Exchange answer as rows: the recorder keeps one row as an object, none as null."""
    r = reply(number)
    return [] if r is None else r if isinstance(r, list) else [r]


ROLE_IDS = f"(Get-GraphRoleIds {ps(reply(34))})"
GRAPH_SP = reply(34)["id"]


def certificate_pem() -> str:
    """The lab app's certificate as Graph returned it (the public half; Graph never returns a key)."""
    key = values(27)[0]["keyCredentials"][0]["key"]
    lines = [key[i:i + 64] for i in range(0, len(key), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


CERT = f"(Read-WorkerCertificate {ps(certificate_pem())} {RECORDED})"


def authorizations(**in_scope) -> str:
    """The check's three Test-ServicePrincipalAuthorization answers, InScope changed as asked."""
    items = []
    for name, number, expected in (("mailbox", 43, True), ("alice", 44, False), ("admin", 45, False)):
        answers = copy.deepcopy(rows(number))
        if name in in_scope:
            for row in answers:
                row["InScope"] = in_scope[name]
        items.append(f"@{{ Mailbox = '{name}'; Expected = {ps(expected)}; Answers = {ps(answers)} }}")
    return "@(" + ", ".join(items) + ")"


def with_app_grant(permissions: list, roles: list) -> list:
    """A list's permissions with the Worker app's grant from the RestoreTarget list added."""
    grant = copy.deepcopy(next(p for p in values(15) if "application" in p.get("grantedToV2", {})))
    grant["roles"] = roles
    return copy.deepcopy(permissions) + [grant]


def permission_rule(permissions, rule: str) -> str:
    return f"(Test-PermissionRule -Permissions {ps(permissions)} -AppId '{APP_ID}' -Rule '{rule}')"


# ---- the answers themselves --------------------------------------------------------------------


def test_every_answer_says_where_it_came_from():
    files = sorted(LAB.glob("*.json"))
    assert len(files) == 45
    for f in files:
        doc = json.loads(f.read_text(encoding="utf-8"))
        assert set(doc) == {"source", "request", "status", "reply"}, f.name
        assert doc["source"].startswith("recorded read-only from the lab tenant on 2026-10-16"), f.name
        assert doc["request"].startswith(("GET /v1.0/", "Get-", "Test-ServicePrincipalAuthorization ")), f.name


def test_no_answer_names_a_person_in_a_base64_id():
    """SharePoint's permission IDs are a claim login name in base64url (i:0#.f|membership|<upn>):
    the recorder cleans them too, so the admin's own address is in none."""
    claims = []
    for f in sorted(LAB.glob("*.json")):
        for token in set(re.findall(r"[A-Za-z0-9_\-]{16,}", f.read_text(encoding="utf-8"))):
            try:
                text = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            for login in re.findall(r"\|membership\|([^@|]+)@", text):
                claims.append((f.name, login))
    assert claims, "no claim login found: the test reads nothing"
    assert {login.lower() for _, login in claims} <= ACCOUNTS, claims


# ---- the targets -------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def targets():
    return evaluate([
        f"Get-InitialDomain {ps(values(1)[0])}",
        f"Get-LibraryPlan {ps(values(4))}",
        f"(Find-RestoreTargetList {ps(values(4))})['id']",
        f"Test-RestoreTargetList {ps(reply(13))} '{LIST_ID}'",
        f"Test-RestoreTargetList {ps(reply(16))} '7eb0f08a-f57b-418c-8ca6-f2ab81297666'",
        f"Test-RestoreTargetFolder {ps(reply(23))} '{DRIVE_ID}' '{FOLDER_ID}'",
        f"Get-FolderPlan {ps(reply(23))} '{DRIVE_ID}'",
        f"(Get-FolderPlan {ps(reply(25))} '{DRIVE_ID}').Action",
        f"Get-MailboxPlan {ps(rows(35))} '{MAILBOX}'",
        f"Test-MailRecipient {ps(rows(36)[0])} 'alice@RestoreProofLab.onmicrosoft.com'",
        f"(Get-MailboxPlan {ps(rows(38))} '{MAILBOX}').Action",
    ])


def test_the_lab_targets_need_nothing(targets):
    domain, library, list_id, list_ok, canary, folder_ok, folder, missing, mailbox, alice, no_mailbox = targets
    assert domain == "RestoreProofLab.onmicrosoft.com"
    assert library is None and list_id == LIST_ID and list_ok == ""
    assert folder_ok == "" and folder is None
    assert mailbox is None and alice == ""
    # A 404 is a target to make, in the form Graph and Get-Recipient answer it.
    assert missing == "folder.create" and no_mailbox == "mailbox.create"
    # The canary library is no RestoreTarget library, by its name.
    assert canary == "is named 'RestoreTest', not RestoreTarget"


# ---- the app, its consents, its grants ---------------------------------------------------------


@pytest.fixture(scope="module")
def app():
    apps = values(27)
    return evaluate([
        f"{CERT}.Problem",
        f"{CERT}.Thumbprint",
        f"Get-KeyThumbprint {ps(apps[0]['keyCredentials'][0])}",
        f"{ROLE_IDS}.Values",
        f"Get-AppPlan {ps(apps)} {CERT} {ROLE_IDS}",
        f"Test-AppState {ps(apps[0])} {ps(values(29))} '{THUMB}' {ROLE_IDS}",
        f"Get-ConsentPlan {ps(values(31))} {ps(values(32))} '{GRAPH_SP}' {ROLE_IDS}",
        f"Test-ServicePrincipalState {ps(values(30)[0])} {ps(values(31))} {ps(values(32))} {ps(values(33))} '{GRAPH_SP}' {ROLE_IDS}",
        f"Get-AppPlan {ps(values(28))} {CERT} {ROLE_IDS} | ForEach-Object Action",
    ])


def test_the_lab_app_needs_nothing(app):
    problem, thumb, key_thumb, role_ids, plan, state, consents, sp_state, none = app
    assert problem == "" and thumb == THUMB
    # Graph names the certificate by its thumbprint in 40 hex digits, not in base64.
    assert key_thumb == THUMB
    wanted = [a["id"] for a in values(27)[0]["requiredResourceAccess"][0]["resourceAccess"]]
    assert sorted(role_ids) == sorted(wanted)
    assert plan is None and state is None and consents is None and sp_state is None
    assert none == "app.create"


@pytest.fixture(scope="module")
def grants():
    return evaluate([
        f"{permission_rule(values(5), 'site-read')} | Select-Object Problems, Notes, Worker, Others",
        f"{permission_rule(values(15), 'target-write')} | Select-Object Problems, Notes, Worker, Others",
        f"{permission_rule(values(24), 'target-write')} | Select-Object Problems, Notes, Worker, Others",
        *(f"{permission_rule(values(n), 'inherited-read-only')}.Problems" for n in (9, 12, 18)),
        *(f"{permission_rule(values(n), 'none')}.Problems" for n in (22, 26)),
        f"Get-GrantPlan {ps(values(5))} '{APP_ID}' 'read' 'site'",
        f"Get-GrantPlan {ps(values(15))} '{APP_ID}' 'write' 'list'",
        f"Get-GrantPlan {ps(values(24))} '{APP_ID}' 'write' 'folder'",
    ])


def test_the_lab_grants_hold_the_rules(grants):
    site, target_list, folder, wte, documents, canary, root, onedrive_site, *plans = grants
    for found in (site, target_list, folder):
        assert found["Problems"] == [] and found["Notes"] == [] and found["Worker"] == 1 and found["Others"] == 0
    assert [wte, documents, canary, root, onedrive_site] == [None] * 5
    assert plans == [None, None, None]


@pytest.fixture(scope="module")
def planted():
    site = copy.deepcopy(values(5))
    site[0]["roles"] = ["write"]
    target = copy.deepcopy(values(15))
    next(p for p in target if "application" in p.get("grantedToV2", {}))["roles"] = ["owner"]
    return evaluate([
        f"{permission_rule(site, 'site-read')}.Problems",
        f"(Get-GrantPlan {ps(site)} '{APP_ID}' 'read' 'site').Action",
        f"{permission_rule(target, 'target-write')}.Problems",
        f"{permission_rule(with_app_grant(values(18), ['write']), 'inherited-read-only')}.Problems",
        f"{permission_rule(with_app_grant(values(22), ['read']), 'none')}.Problems",
        f"{permission_rule([], 'target-write')}.Problems",
    ])


def test_a_fault_planted_into_a_real_answer_is_caught(planted):
    site, site_plan, target, canary, root, no_grant = planted
    assert site == "the Worker app's grant has roles 'write'; only 'read' is allowed"
    assert site_plan == "site.set"
    assert target == "the Worker app's grant has roles 'owner'; it needs exactly 'write'"
    # The canary library: a write grant there is the one thing the rules exist to refuse.
    assert canary == "the Worker app has a grant of its own here, roles 'write'; none is allowed"
    assert root == "the Worker app has a grant here, roles 'read'; none is allowed"
    assert no_grant == "the Worker app has no grant of its own here; it needs exactly one, write"


# ---- Exchange Online ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def exchange():
    dehydrated = rows(39)[0]["IsDehydrated"]
    plan = (f"Get-ExchangePlan {ps(rows(40)[0])} {ps(rows(41)[0])} {ps(rows(42))} "
            f"(ConvertFrom-ExchangeBool {ps(dehydrated)} 'IsDehydrated') $false '{SP_ID}' '{APP_ID}' '{MAILBOX}'")
    state = f"Test-ExchangeState {ps(rows(40)[0])} {ps(rows(41)[0])} {ps(rows(42))} '{SP_ID}' '{APP_ID}' '{MAILBOX}'"
    return evaluate([
        f"ConvertFrom-ExchangeBool {ps(dehydrated)} 'IsDehydrated'",
        plan,
        f"{state} {authorizations()}",
        f"{state} {authorizations(admin='True')}",
        f"{state} {authorizations(mailbox='False')}",
        f"Test-ExchangeState {ps(rows(40)[0])} {ps(rows(41)[0])} @() '{SP_ID}' '{APP_ID}' '{MAILBOX}' {authorizations()}",
        # The recorded assignment and pointer, read for a service principal made again since.
        f"Test-ExchangeState {ps(rows(40)[0])} {ps(rows(41)[0])} {ps(rows(42))} '{OTHER_SP}' '{APP_ID}' '{MAILBOX}' {authorizations()}",
        f"(Get-ExchangePlan {ps(rows(40)[0])} {ps(rows(41)[0])} {ps(rows(42))} $false $false '{OTHER_SP}' '{APP_ID}' '{MAILBOX}').Action",
    ])


def test_the_lab_exchange_needs_nothing(exchange):
    dehydrated, plan, state, *_ = exchange
    # Recorded as text, the form Exchange's answer takes in a string: "False" is no customisation.
    assert dehydrated is False
    assert plan is None and state is None


def test_a_real_assignment_of_another_service_principal_is_not_the_apps(exchange):
    """Exchange names the assignee by the service principal's object ID, as recorded: an
    assignment of RestoreProof's name to another object is a deleted one's (review finding 1)."""
    *_, stale_state, stale_plan = exchange
    assert any("pointer for the app names f5a56ba3-" in p for p in stale_state)
    assert any(p.startswith("the app has 1 Exchange role assignment(s)") for p in stale_state)
    assert stale_plan == ["exchange.assignment-remove", "exchange.pointer-remove", "exchange.pointer", "exchange.assignment"]


def test_exchange_faults_on_real_answers_are_caught(exchange):
    *_, admin, mailbox, no_assignment, _, _ = exchange
    assert admin == "Exchange says the app may reach admin (Application Mail.ReadWrite); only the restoretest mailbox is allowed"
    assert mailbox == "Exchange says the app may not reach mailbox (Application Mail.ReadWrite not in scope)"
    assert no_assignment.startswith("the app has 0 Exchange role assignment(s)")


@pytest.mark.parametrize("value, expected", [
    (True, False), (False, False), ("True", False), ("False", False), ("true", False), (None, True), ("", True), ("yes", True), (1, True),
])
def test_an_exchange_true_or_false_is_read_as_such_and_nothing_else(value, expected):
    literal = "1" if value == 1 and not isinstance(value, bool) else ps(value)
    [found] = evaluate([f"ConvertFrom-ExchangeBool {literal} 'IsDehydrated'"])
    if expected:
        assert found == {"throws": f"Exchange answered IsDehydrated with '{'' if value is None else value}', not True or False"}
    else:
        assert found is (str(value).lower() == "true")


# ---- the profile -------------------------------------------------------------------------------


def test_the_profile_from_the_real_answers_is_the_labs():
    [profile] = evaluate([
        f"ConvertTo-ProfileJson (New-ClientProfile 'RestoreProofLab.onmicrosoft.com' '{TENANT}' '{values(27)[0]['appId']}' "
        f"'{rows(35)[0]['PrimarySmtpAddress']}' '{reply(3)['id']}' '{reply(14)['id']}' '{reply(20)['id']}' '{reply(23)['id']}')"
    ])
    # The lab as it was recorded: lab/tenant.md has named the app and targets the W7.0 live
    # Done-when made since (its note says which IDs were the lab's before).
    assert json.loads(profile) == {
        "format": "restoreproof.client-profile.v1", "veeam_org_name": "RestoreProofLab.onmicrosoft.com",
        "graph_tenant_id": TENANT, "graph_client_id": APP_ID, "test_mailbox": MAILBOX, "test_site_id": SITE_ID,
        "test_library_id": LIBRARY_DRIVE_ID, "test_onedrive_drive_id": DRIVE_ID, "test_onedrive_folder_id": FOLDER_ID,
    }


@pytest.mark.parametrize("text, expected", [
    # Exchange's words on the second live run (2026-10-16), the IDs replaced.
    ("||Error: AADServicePrincipalNotFound. No ServicePrincipal with Object Id 'x' for Client Application Id 'y' is registered in this tenant.", True),
    ("||Error: The operation couldn't be performed because object 'x' couldn't be found.", False),
    ("aadserviceprincipalnotfound", False),
    ("", False),
])
def test_exchange_not_yet_seeing_a_service_principal_is_known_by_its_word(text, expected):
    [found] = evaluate([f"Test-ExchangeNotYetReplicated {ps(text)}"])
    assert found is expected
