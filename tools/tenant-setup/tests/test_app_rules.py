"""The rules that decide the app registration, its consents and its grants (W7.0, decision points
4 to 7), row by row, refusals first, and for each plan the state it leaves giving an empty plan."""

import base64
import json

import pytest

import certs
from pwsh import evaluate, ps

GRAPH_SP = "99999999-0000-0000-0000-000000000001"
APP_ID = "aaaaaaaa-1111-2222-3333-444444444444"
SP_ID = "bbbbbbbb-1111-2222-3333-444444444444"
OTHER_APP = "cccccccc-1111-2222-3333-444444444444"
ROLES = {
    "Sites.Selected": "883ea226-0bf2-4a8f-9f9d-92c9162a727d",
    "Files.SelectedOperations.Selected": "bd61925e-3bf4-4d62-bc0b-06b06c96d95c",
    "Lists.SelectedOperations.Selected": "23c5a9bd-d900-4ecf-be26-a0689755d9e5",
}
MAIL_READ = "810c84a8-4a9e-49e6-bf7d-12d183f40d01"
GRAPH = {
    "id": GRAPH_SP,
    "appRoles": [{"id": i, "value": n, "allowedMemberTypes": ["Application"]} for n, i in ROLES.items()]
    + [{"id": MAIL_READ, "value": "Mail.Read", "allowedMemberTypes": ["Application"]}],
}
ROLE_IDS = f"(Get-GraphRoleIds {ps(GRAPH)})"

_, CERT = certs.make()
THUMB = certs.thumbprint(CERT)
_, OTHER_CERT = certs.make()
CERT_EXPR = f"(Read-WorkerCertificate {ps(certs.pem(CERT))} ([datetime]::UtcNow))"


def custom_key(thumb: str) -> str:
    return base64.b64encode(bytes.fromhex(thumb)).decode("ascii")


def an_app(**changes):
    app = {
        "id": "dddddddd-1111-2222-3333-444444444444",
        "appId": APP_ID,
        "displayName": "RestoreProof Worker",
        "signInAudience": "AzureADMyOrg",
        "requiredResourceAccess": [
            {"resourceAppId": "00000003-0000-0000-c000-000000000000", "resourceAccess": [{"id": i, "type": "Role"} for i in ROLES.values()]}
        ],
        "keyCredentials": [{"keyId": "k1", "customKeyIdentifier": custom_key(THUMB), "displayName": f"CN=RestoreProof Worker {THUMB}", "key": None}],
        "passwordCredentials": [],
    }
    app.update(changes)
    return app


# ---- the certificate ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def cert_results():
    key, cert = certs.make()
    _, small = certs.make(bits=1024)
    _, soon = certs.make(days=10)
    _, ec_cert = certs.make(ec_key=True)
    pems = [
        certs.pem(cert) + certs.key_pem(key),
        certs.pem(cert) + certs.pem(small),
        "",
        "-----BEGIN CERTIFICATE-----\nnot base64 of a certificate\n-----END CERTIFICATE-----\n",
        certs.pem(small),
        certs.pem(soon),
        certs.pem(ec_cert),
        certs.pem(cert),
    ]
    rows = [f"Read-WorkerCertificate {ps(p)} ([datetime]::UtcNow) | ForEach-Object {{ @{{ p = $_.Problem; t = $_.Thumbprint }} }}" for p in pems]
    return evaluate(rows), certs.thumbprint(cert)


@pytest.mark.parametrize(
    ("index", "words"),
    [
        (0, "private key"),
        (1, "2 certificates"),
        (2, "0 certificates"),
        (3, "not a certificate"),
        (4, "1024 bits"),
        (5, "within 30 days"),
        (6, "no RSA key"),
    ],
    ids=["a private key", "two certificates", "none", "garbage", "rsa 1024", "expires soon", "an EC key"],
)
def test_a_certificate_the_worker_cant_use_is_refused(cert_results, index, words):
    results, _ = cert_results
    assert words in results[index]["p"], results[index]


def test_the_workers_certificate_is_read(cert_results):
    results, thumb = cert_results
    assert results[-1] == {"p": "", "t": thumb}


def test_the_key_credentials_thumbprint():
    rows = [
        f"Get-KeyThumbprint {ps({'customKeyIdentifier': custom_key(THUMB)})}",
        f"Get-KeyThumbprint {ps({'customKeyIdentifier': THUMB.lower()})}",
        f"Get-KeyThumbprint {ps({'displayName': f'CN=RestoreProof Worker (lab) {THUMB.lower()}'})}",
        f"Get-KeyThumbprint {ps({'displayName': 'a certificate'})}",
        f"Get-KeyThumbprint {ps({})}",
    ]
    assert evaluate(rows) == [THUMB, THUMB, THUMB, "", ""]


# ---- the app -----------------------------------------------------------------------------------

APP_ROWS = [
    ("two apps of that name", [an_app(), an_app(id="e")], "throws"),
    ("none", [], ["app.create"]),
    ("multi-tenant", [an_app(signInAudience="AzureADMultipleOrgs")], ["app.update"]),
    ("Mail.Read asked for", [an_app(requiredResourceAccess=[{"resourceAppId": "00000003-0000-0000-c000-000000000000", "resourceAccess": [{"id": i, "type": "Role"} for i in [*ROLES.values(), MAIL_READ]]}])], ["app.update"]),
    ("a role missing", [an_app(requiredResourceAccess=[{"resourceAppId": "00000003-0000-0000-c000-000000000000", "resourceAccess": [{"id": i, "type": "Role"} for i in list(ROLES.values())[:2]]}])], ["app.update"]),
    ("another API asked for", [an_app(requiredResourceAccess=an_app()["requiredResourceAccess"] + [{"resourceAppId": "00000002-0000-0ff1-ce00-000000000000", "resourceAccess": [{"id": "x", "type": "Role"}]}])], ["app.update"]),
    ("a delegated scope asked for", [an_app(requiredResourceAccess=[{"resourceAppId": "00000003-0000-0000-c000-000000000000", "resourceAccess": [{"id": i, "type": "Scope"} for i in ROLES.values()]}])], ["app.update"]),
    ("no certificate", [an_app(keyCredentials=[])], ["app.certificate"]),
    ("another certificate", [an_app(keyCredentials=[{"customKeyIdentifier": custom_key(certs.thumbprint(OTHER_CERT))}])], ["app.certificate"]),
    ("two certificates", [an_app(keyCredentials=an_app()["keyCredentials"] * 2)], ["app.certificate"]),
    ("a client secret", [an_app(passwordCredentials=[{"keyId": "s1", "displayName": "old"}])], ["app.remove-secret"]),
    ("as it must be", [an_app()], []),
]


@pytest.fixture(scope="module")
def app_results():
    return evaluate([f"Get-AppPlan {ps(apps)} {CERT_EXPR} {ROLE_IDS} | ForEach-Object Action" for _, apps, _ in APP_ROWS])


@pytest.mark.parametrize("index", range(len(APP_ROWS)), ids=[r[0] for r in APP_ROWS])
def test_the_app_plan(app_results, index):
    got, expected = app_results[index], APP_ROWS[index][2]
    if expected == "throws":
        assert "nothing was changed" in got["throws"]
        return
    got = [] if got is None else [got] if isinstance(got, str) else got
    assert got == expected


def test_the_required_access_and_the_key_credential():
    rows = [
        f"ConvertTo-Json -InputObject @(Get-RequiredAccess {ROLE_IDS}) -Depth 5 -Compress",
        f"Get-KeyCredential {CERT_EXPR} | ForEach-Object {{ @{{ type = $_.type; usage = $_.usage; name = $_.displayName; has = [bool]$_.key }} }}",
        f"Test-RequiredAccess {ps(an_app())} {ROLE_IDS}",
    ]
    access, key, held = evaluate(rows)
    access = json.loads(access)
    assert access[0]["resourceAppId"] == "00000003-0000-0000-c000-000000000000"
    assert sorted(r["id"] for r in access[0]["resourceAccess"]) == sorted(ROLES.values())
    assert {r["type"] for r in access[0]["resourceAccess"]} == {"Role"}
    assert key == {"type": "AsymmetricX509Cert", "usage": "Verify", "name": f"CN=RestoreProof Worker {THUMB}", "has": True}
    assert held is True


def test_graph_without_one_of_the_roles_is_refused():
    graph = {"id": GRAPH_SP, "appRoles": GRAPH["appRoles"][1:]}
    (got,) = evaluate([f"Get-GraphRoleIds {ps(graph)}"])
    assert "no application permission 'Sites.Selected'" in got["throws"]


# ---- the consents ------------------------------------------------------------------------------


def consent(role_id, resource=GRAPH_SP, name="Microsoft Graph", consent_id=None):
    return {"id": consent_id or f"c-{role_id}", "resourceId": resource, "appRoleId": role_id, "resourceDisplayName": name}


ALL = [consent(i) for i in ROLES.values()]
CONSENT_ROWS = [
    ("Mail.Read consented", ALL + [consent(MAIL_READ)], [], ["consent.remove"]),
    ("full_access_as_app on Exchange", ALL + [consent("dc890d15-9560-4a4c-9b7f-a736ec74ec40", "exo", "Office 365 Exchange Online")], [], ["consent.remove"]),
    ("SharePoint's Sites.FullControl.All", ALL + [consent("678536fe-1083-478a-9c59-b99265e6b0d3", "spo", "Office 365 SharePoint Online")], [], ["consent.remove"]),
    ("a delegated grant", ALL, [{"id": "g1", "scope": "User.Read"}], ["delegated.remove"]),
    ("none", [], [], ["consent.grant"] * 3),
    ("one missing", ALL[:2], [], ["consent.grant"]),
    ("as it must be", ALL, [], []),
]


@pytest.fixture(scope="module")
def consent_results():
    return evaluate([f"Get-ConsentPlan {ps(a)} {ps(d)} {ps(GRAPH_SP)} {ROLE_IDS} | ForEach-Object Action" for _, a, d, _ in CONSENT_ROWS])


@pytest.mark.parametrize("index", range(len(CONSENT_ROWS)), ids=[r[0] for r in CONSENT_ROWS])
def test_the_consent_plan(consent_results, index):
    got = consent_results[index]
    got = [] if got is None else [got] if isinstance(got, str) else got
    assert got == CONSENT_ROWS[index][3]


# ---- the SharePoint grants ---------------------------------------------------------------------


def grant(roles, app=APP_ID, inherited=False, form="grantedToIdentitiesV2", grant_id=None):
    p = {"id": grant_id or f"p-{app}-{'-'.join(roles)}", "roles": roles}
    if form == "siteUser":
        p["grantedToV2"] = {"siteUser": {"loginName": f"i:0i.t|ms.sp.ext|{app}@tenant"}}
    elif form in ("grantedToV2", "grantedTo"):
        p[form] = {"application": {"id": app, "displayName": ""}}
    else:
        p[form] = [{"application": {"id": app, "displayName": "RestoreProof Worker"}}]
    if inherited:
        p["inheritedFrom"] = {"id": "parent"}
    return p


GRANT_ROWS = [
    ("the site: write", [grant(["write"])], "read", ["site.set"]),
    ("the site: fullcontrol", [grant(["fullcontrol"])], "read", ["site.set"]),
    ("the site: two grants", [grant(["read"]), grant(["write"], grant_id="p2")], "read", ["site.remove"]),
    ("the site: none", [], "read", ["site.grant"]),
    ("the site: another app's grant only", [grant(["read"], app=OTHER_APP)], "read", ["site.grant"]),
    ("the site: read", [grant(["read"]), grant(["write"], app=OTHER_APP)], "read", []),
    ("the list: read", [grant(["read"], form="grantedToV2")], "write", ["list.set"]),
    ("the list: inherited only", [grant(["read"], inherited=True)], "write", ["list.grant"]),
    ("the list: SharePoint's form, write", [grant(["write"], form="siteUser")], "write", []),
    ("the list: write", [grant(["write"], form="grantedToV2"), grant(["read"], inherited=True)], "write", []),
]


@pytest.fixture(scope="module")
def grant_results():
    rows = []
    for label, perms, role, _ in GRANT_ROWS:
        where = "site" if label.startswith("the site") else "list"
        rows.append(f"Get-GrantPlan {ps(perms)} {ps(APP_ID)} {ps(role)} {ps(where)} | ForEach-Object Action")
    rows.append(f"Get-GrantPlan @() {ps(APP_ID)} 'owner' 'site'")
    return evaluate(rows)


@pytest.mark.parametrize("index", range(len(GRANT_ROWS)), ids=[r[0] for r in GRANT_ROWS])
def test_the_grant_plan(grant_results, index):
    got = grant_results[index]
    got = [] if got is None else [got] if isinstance(got, str) else got
    assert got == GRANT_ROWS[index][3]


def test_a_grant_plan_never_asks_for_another_role(grant_results):
    assert "unknown role 'owner'" in grant_results[-1]["throws"]


RULE_ROWS = [
    # failure rows first
    ("site-read: write", [grant(["write"])], "site-read", 1),
    ("site-read: two", [grant(["read"]), grant(["read"], grant_id="x")], "site-read", 1),
    ("site-read: none", [], "site-read", 1),
    ("target-write: read", [grant(["read"], form="grantedToV2")], "target-write", 1),
    ("target-write: inherited write", [grant(["write"], form="grantedToV2"), grant(["write"], inherited=True)], "target-write", 1),
    ("target-write: none", [grant(["read"], inherited=True)], "target-write", 1),
    ("inherited-read-only: a grant of its own", [grant(["read"], form="grantedToV2")], "inherited-read-only", 1),
    ("inherited-read-only: inherited write", [grant(["write"], inherited=True)], "inherited-read-only", 1),
    ("none: SharePoint's form", [grant(["read"], form="siteUser")], "none", 1),
    ("none: inherited", [grant(["read"], inherited=True)], "none", 1),
    ("site-read: read", [grant(["read"])], "site-read", 0),
    ("target-write: write", [grant(["write"], form="grantedToV2"), grant(["read"], inherited=True)], "target-write", 0),
    ("inherited-read-only: inherited read", [grant(["read"], inherited=True)], "inherited-read-only", 0),
    ("none: another app", [grant(["write"], app=OTHER_APP)], "none", 0),
]


@pytest.fixture(scope="module")
def rule_results():
    rows = [f"Test-PermissionRule -Permissions {ps(p)} -AppId {ps(APP_ID)} -Rule {ps(rule)} | ForEach-Object {{ @{{ n = $_.Problems.Count; o = $_.Others }} }}" for _, p, rule, _ in RULE_ROWS]
    rows.append(f"Test-PermissionRule -Permissions @() -AppId {ps(APP_ID)} -Rule 'read'")
    return evaluate(rows)


@pytest.mark.parametrize("index", range(len(RULE_ROWS)), ids=[r[0] for r in RULE_ROWS])
def test_the_permission_rules(rule_results, index):
    assert rule_results[index]["n"] == RULE_ROWS[index][3], rule_results[index]


def test_an_unknown_rule_throws(rule_results):
    assert "unknown rule" in rule_results[-1]["throws"]


def test_another_apps_grant_is_counted_as_a_note(rule_results):
    assert rule_results[-2]["o"] == 1


# ---- Exchange ----------------------------------------------------------------------------------

ADDRESS = "restoretest@contoso.onmicrosoft.com"
FILTER = f"PrimarySmtpAddress -eq '{ADDRESS}'"
SCOPE = {"Name": "RestoreProof Worker - restoretest mailbox", "RecipientFilter": FILTER}
POINTER = {"AppId": APP_ID, "ObjectId": SP_ID}
OLD_SP = "eeeeeeee-1111-2222-3333-444444444444"
OLD_POINTER = {"AppId": APP_ID, "ObjectId": OLD_SP}


def assignment(name="RestoreProof Worker - Application Mail.ReadWrite - restoretest", role="Application Mail.ReadWrite",
               scope="RestoreProof Worker - restoretest mailbox", assignee=SP_ID):
    return {"Name": name, "Role": role, "RoleAssigneeType": "ServicePrincipal", "RoleAssigneeName": assignee,
            "CustomResourceScope": scope, "Identity": name}


EXCHANGE_ROWS = [
    ("dehydrated, not allowed", None, None, [], True, False, "throws"),
    ("an extra role", POINTER, SCOPE, [assignment(), assignment("x", "Application Mail.Read")], False, False, ["exchange.assignment-remove"]),
    ("the name, another role", POINTER, SCOPE, [assignment(role="Application Mail.Read")], False, False, ["exchange.assignment-remove", "exchange.assignment"]),
    ("the name, another scope", POINTER, SCOPE, [assignment(scope="Everyone")], False, False, ["exchange.assignment-remove", "exchange.assignment"]),
    ("the filter changed", POINTER, {**SCOPE, "RecipientFilter": "PrimarySmtpAddress -eq 'alice@contoso.onmicrosoft.com'"}, [assignment()], False, False, ["exchange.scope-filter"]),
    ("dehydrated, allowed", None, None, [], True, True, ["exchange.pointer", "exchange.customize", "exchange.scope", "exchange.assignment"]),
    ("nothing yet", None, None, [], False, False, ["exchange.pointer", "exchange.scope", "exchange.assignment"]),
    ("another app's assignment", POINTER, SCOPE, [assignment(), assignment("y", assignee=OTHER_APP)], False, False, []),
    ("as it must be, dehydrated says nothing", POINTER, SCOPE, [assignment()], True, False, []),
    # The app was made again: its new pointer is missing, the old app's assignment keeps the name.
    ("the name, a deleted app's assignee", None, SCOPE, [assignment(assignee=OLD_SP)], False, False,
     ["exchange.assignment-remove", "exchange.pointer", "exchange.assignment"]),
    # Its service principal alone was made again: the pointer and its assignments name the old one.
    ("a pointer to a deleted service principal", OLD_POINTER, SCOPE, [assignment(assignee=OLD_SP), assignment("z", "Application Mail.Read", assignee=OLD_SP)], False, False,
     ["exchange.assignment-remove", "exchange.assignment-remove", "exchange.pointer-remove", "exchange.pointer", "exchange.assignment"]),
]


def test_a_stale_pointer_goes_after_its_assignments_and_by_its_own_id():
    plan = evaluate([
        f"Get-ExchangePlan {ps(OLD_POINTER)} {ps(SCOPE)} {ps([assignment(assignee=OLD_SP)])} $false $false {ps(SP_ID)} {ps(APP_ID)} {ps(ADDRESS)} | ForEach-Object {{ \"$($_.Action)|$(if ($_.Data) {{ $_.Data.Identity }})\" }}"
    ])[0]
    assert plan[:2] == ["exchange.assignment-remove|RestoreProof Worker - Application Mail.ReadWrite - restoretest", f"exchange.pointer-remove|{OLD_SP}"]


def test_an_exchange_lookup_failure_is_read_by_its_words():
    rows = [
        "|Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException|The operation couldn't be performed because object 'x@contoso.com' couldn't be found on 'AM0PR01A001.PROD.OUTLOOK.COM'.",
        "|Microsoft.Exchange.Configuration.Tasks.ManagementObjectAmbiguousException|The operation couldn't be performed because 'x@contoso.com' matches multiple entries.",
        "The request was throttled. Try again in 30 seconds.",
        "",
    ]
    assert evaluate([f"Get-ExchangeLookupFailure {ps(text)}" for text in rows]) == ["not-found", "ambiguous", "", ""]


@pytest.fixture(scope="module")
def exchange_results():
    return evaluate([
        f"Get-ExchangePlan {ps(p)} {ps(s)} {ps(a)} {ps(d)} {ps(allow)} {ps(SP_ID)} {ps(APP_ID)} {ps(ADDRESS)} | ForEach-Object Action"
        for _, p, s, a, d, allow, _ in EXCHANGE_ROWS
    ])


@pytest.mark.parametrize("index", range(len(EXCHANGE_ROWS)), ids=[r[0] for r in EXCHANGE_ROWS])
def test_the_exchange_plan(exchange_results, index):
    got, expected = exchange_results[index], EXCHANGE_ROWS[index][-1]
    if expected == "throws":
        assert "-AllowOrganizationCustomization" in got["throws"] and "nothing was changed" in got["throws"]
        return
    got = [] if got is None else [got] if isinstance(got, str) else got
    assert got == expected


# ---- the check ---------------------------------------------------------------------------------


def problems(value):
    return [] if value is None else [value] if isinstance(value, str) else value


def test_the_app_state():
    rows = [
        f"Test-AppState {ps(an_app(passwordCredentials=[{'keyId': 's'}]))} @() {ps(THUMB)} {ROLE_IDS}",
        f"Test-AppState {ps(an_app(keyCredentials=[]))} @() {ps(THUMB)} {ROLE_IDS}",
        f"Test-AppState {ps(an_app())} {ps([{'id': 'f'}])} {ps(THUMB)} {ROLE_IDS}",
        f"Test-AppState {ps(an_app(signInAudience='AzureADMultipleOrgs'))} @() {ps(THUMB)} {ROLE_IDS}",
        f"Test-AppState {ps(an_app())} @() {ps(certs.thumbprint(OTHER_CERT))} {ROLE_IDS}",
        f"Test-AppState $null @() {ps(THUMB)} {ROLE_IDS}",
        f"Test-AppState {ps(an_app())} @() {ps(THUMB)} {ROLE_IDS}",
    ]
    secret, no_key, federated, multi, other, none, good = [problems(v) for v in evaluate(rows)]
    assert "client secret" in secret[0]
    assert "0 certificates" in no_key[0]
    assert "federated" in federated[0]
    assert "single tenant" in multi[0]
    assert "not the Worker's" in other[0]
    assert "no app registration" in none[0]
    assert good == []


def test_the_service_principal_state():
    sp = {"id": SP_ID}
    rows = [
        f"Test-ServicePrincipalState {ps(sp)} {ps(ALL + [consent(MAIL_READ)])} @() @() {ps(GRAPH_SP)} {ROLE_IDS}",
        f"Test-ServicePrincipalState {ps(sp)} {ps(ALL[:2])} @() @() {ps(GRAPH_SP)} {ROLE_IDS}",
        f"Test-ServicePrincipalState {ps(sp)} {ps(ALL)} {ps([{'id': 'g'}])} @() {ps(GRAPH_SP)} {ROLE_IDS}",
        f"Test-ServicePrincipalState {ps(sp)} {ps(ALL)} @() {ps([{'displayName': 'Global Administrator', '@odata.type': '#microsoft.graph.directoryRole'}])} {ps(GRAPH_SP)} {ROLE_IDS}",
        f"Test-ServicePrincipalState $null @() @() @() {ps(GRAPH_SP)} {ROLE_IDS}",
        f"Test-ServicePrincipalState {ps(sp)} {ps(ALL + ALL[:1])} @() @() {ps(GRAPH_SP)} {ROLE_IDS}",
        f"Test-ServicePrincipalState {ps(sp)} {ps(ALL)} @() @() {ps(GRAPH_SP)} {ROLE_IDS}",
    ]
    extra, missing, delegated, role, none, twice, good = [problems(v) for v in evaluate(rows)]
    assert "another consent" in extra[0]
    assert "Lists.SelectedOperations.Selected is held 0 time(s)" in missing[0]
    assert "delegated" in delegated[0]
    assert "Global Administrator" in role[0]
    assert "no service principal" in none[0]
    assert "held 2 time(s)" in twice[0]
    assert good == []


def authorization(mailbox, expected, *in_scope_roles):
    answers = [{"RoleName": r, "InScope": "True"} for r in in_scope_roles] or [{"RoleName": "Application Mail.ReadWrite", "InScope": "False"}]
    return {"Mailbox": mailbox, "Answers": answers, "Expected": expected}


def test_the_exchange_state():
    good_auth = [authorization(ADDRESS, True, "Application Mail.ReadWrite"), authorization("admin@contoso.onmicrosoft.com", False)]

    def row(scope, assignments, auth, pointer=POINTER):
        return f"Test-ExchangeState {ps(pointer)} {ps(scope)} {ps(assignments)} {ps(SP_ID)} {ps(APP_ID)} {ps(ADDRESS)} {ps(auth)}"

    later = [
        row(SCOPE, [assignment()], [], pointer=None),
        row(SCOPE, [assignment(assignee=OLD_SP)], good_auth, pointer=OLD_POINTER),
        row(SCOPE, [assignment(assignee=OLD_SP)], good_auth),
        row(SCOPE, [assignment()], [good_auth[0], {"Mailbox": "admin@contoso.onmicrosoft.com", "Failed": "throttled"}]),
    ]
    no_pointer, stale_pointer, stale_assignee, failed = [problems(v) for v in evaluate(later)]
    assert no_pointer == ["Exchange has no service principal pointer for the app"]
    assert any(f"names {OLD_SP}, not the app's service principal" in p for p in stale_pointer)
    assert any("1 Exchange role assignment(s)" in p for p in stale_pointer)
    assert len(stale_assignee) == 1 and f"assigned to '{SP_ID}'" in stale_assignee[0]
    assert failed == ["Exchange can't say whether the app may reach admin@contoso.onmicrosoft.com: throttled"]

    rows = [
        row(SCOPE, [assignment()], [authorization(ADDRESS, True), good_auth[1]]),
        row(SCOPE, [assignment()], [good_auth[0], authorization("admin@contoso.onmicrosoft.com", False, "Application Mail.ReadWrite")]),
        row(SCOPE, [assignment()], [good_auth[0], authorization("bob@contoso.onmicrosoft.com", False, "Application Mail.Read")]),
        row(SCOPE, [assignment(), assignment("x", "Application Mail.Read")], good_auth),
        row({**SCOPE, "RecipientFilter": "x"}, [assignment()], good_auth),
        row(None, [assignment()], good_auth),
        row(SCOPE, [], good_auth),
        row(SCOPE, [assignment()], good_auth),
    ]
    not_in, reaches, reaches_read, two, filt, no_scope, none, good = [problems(v) for v in evaluate(rows)]
    assert "may not reach restoretest@" in not_in[0]
    assert "may reach admin@" in reaches[0]
    assert "may reach bob@" in reaches_read[0]
    assert "2 Exchange role assignment(s)" in two[0]
    assert "filter is 'x'" in filt[0]
    assert "no management scope" in no_scope[0]
    assert "0 Exchange role assignment(s)" in none[0]
    assert good == []
