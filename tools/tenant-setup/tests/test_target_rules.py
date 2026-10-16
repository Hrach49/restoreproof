"""The rules that decide the three restore targets (W7.0, decision points 2, 5 and 6), row by row,
refusals first: the site address, the mailbox address and recipient, the RestoreTarget library and
folder name checks that stand before every write grant, and the plans each step makes."""

import pytest

from pwsh import evaluate, ps

DRIVE = "b!aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OTHER_DRIVE = "b!bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
FOLDER = "01AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
SITE = "https://contoso.sharepoint.com/sites/RestoreProof"
LIST_ID = "11111111-2222-3333-4444-555555555555"


def table(rows):
    """Evaluates every row's expression in one pwsh; the parametrize ids are the rows' labels."""
    return evaluate([expression for _, expression, _ in rows])


def refused(value) -> bool:
    return isinstance(value, str) and value != ""


# ---- the site ----------------------------------------------------------------------------------

SITE_ROWS = [
    ("http", "http://contoso.sharepoint.com/sites/RestoreProof", True),
    ("root site", "https://contoso.sharepoint.com", True),
    ("root site with slash", "https://contoso.sharepoint.com/", True),
    ("onedrive host", "https://contoso-my.sharepoint.com/personal/alice_contoso_com", True),
    ("another host", "https://contoso.example.com/sites/RestoreProof", True),
    ("a subsite", "https://contoso.sharepoint.com/sites/RestoreProof/sub", True),
    ("a library address", "https://contoso.sharepoint.com/Shared%20Documents", True),
    ("a query", "https://contoso.sharepoint.com/sites/RestoreProof?x=1", True),
    ("a port", "https://contoso.sharepoint.com:444/sites/RestoreProof", True),
    ("a user", "https://u@contoso.sharepoint.com/sites/RestoreProof", True),
    ("relative", "sites/RestoreProof", True),
    ("a site", "https://contoso.sharepoint.com/sites/RestoreProof", False),
    ("a team site", "https://contoso.sharepoint.com/teams/RestoreProof", False),
    ("trailing slash", "https://Contoso.SharePoint.com/sites/RestoreProof/", False),
]


@pytest.fixture(scope="module")
def site_results():
    return evaluate([f"Test-SiteUrl {ps(url)}" for _, url, _ in SITE_ROWS] + [f"Get-SitePath {ps(SITE + '/')}"])


@pytest.mark.parametrize("index", range(len(SITE_ROWS)), ids=[r[0] for r in SITE_ROWS])
def test_the_site_address(site_results, index):
    assert refused(site_results[index]) == SITE_ROWS[index][2], site_results[index]


def test_the_sites_graph_path(site_results):
    assert site_results[-1] == "contoso.sharepoint.com:/sites/RestoreProof"


# ---- the mailbox -------------------------------------------------------------------------------

ADDRESS_ROWS = [
    ("another user", "alice@contoso.com", True),
    ("a longer name", "restoretest2@contoso.com", True),
    ("a prefix", "xrestoretest@contoso.com", True),
    ("no dot in the domain", "restoretest@contoso", True),
    ("a line break", "restoretest@contoso.com\n", True),
    ("empty", "", True),
    ("the address", "restoretest@contoso.onmicrosoft.com", False),
    ("any case", "RestoreTest@Contoso.com", False),
]


@pytest.fixture(scope="module")
def address_results():
    return evaluate([f"Test-MailboxAddress {ps(a)}" for _, a, _ in ADDRESS_ROWS])


@pytest.mark.parametrize("index", range(len(ADDRESS_ROWS)), ids=[r[0] for r in ADDRESS_ROWS])
def test_the_mailbox_address(address_results, index):
    assert refused(address_results[index]) == ADDRESS_ROWS[index][2], address_results[index]


ADDRESS = "restoretest@contoso.onmicrosoft.com"


def recipient(kind, primary=ADDRESS):
    return {"RecipientTypeDetails": kind, "PrimarySmtpAddress": primary, "Name": "x"}


MAILBOX_ROWS = [
    ("a group", [recipient("GroupMailbox")], "throws"),
    ("a mail user", [recipient("MailUser")], "throws"),
    ("a distribution list", [recipient("MailUniversalDistributionGroup")], "throws"),
    ("another mailbox's secondary address", [recipient("UserMailbox", "bob@contoso.onmicrosoft.com")], "throws"),
    ("two recipients", [recipient("UserMailbox"), recipient("SharedMailbox")], "throws"),
    ("none", [], "create"),
    ("a user mailbox", [recipient("UserMailbox")], "none"),
    ("a shared mailbox, primary in another case", [recipient("SharedMailbox", ADDRESS.upper())], "none"),
]


@pytest.fixture(scope="module")
def mailbox_results():
    return evaluate([f"Get-MailboxPlan {ps(r)} {ps(ADDRESS)} | ForEach-Object Action" for _, r, _ in MAILBOX_ROWS])


@pytest.mark.parametrize("index", range(len(MAILBOX_ROWS)), ids=[r[0] for r in MAILBOX_ROWS])
def test_the_mailbox_plan(mailbox_results, index):
    got, expected = mailbox_results[index], MAILBOX_ROWS[index][2]
    if expected == "throws":
        assert isinstance(got, dict) and "Nothing was changed" in got["throws"] or "nothing was changed" in got["throws"], got
    elif expected == "create":
        assert got == "mailbox.create"
    else:
        assert got is None


# ---- the library -------------------------------------------------------------------------------


def a_list(name="RestoreTarget", url=f"{SITE}/RestoreTarget", template="documentLibrary", list_id=LIST_ID):
    return {"id": list_id, "displayName": name, "webUrl": url, "list": {"template": template}}


LIST_ROWS = [
    ("the canary library", a_list("RestoreTest", f"{SITE}/RestoreTest"), True),
    ("renamed", a_list("RestoreTarget", f"{SITE}/RestoreTest"), True),
    ("another list's name", a_list("RestoreTest", f"{SITE}/RestoreTarget"), True),
    ("the name in another case", a_list("restoretarget"), True),
    ("another address", a_list(url=f"{SITE}/Lists/RestoreTarget2"), True),
    ("no address", {"id": LIST_ID, "displayName": "RestoreTarget", "list": {"template": "documentLibrary"}}, True),
    ("a generic list", a_list(template="genericList"), True),
    ("no template", {"id": LIST_ID, "displayName": "RestoreTarget", "webUrl": f"{SITE}/RestoreTarget"}, True),
    ("another id", a_list(list_id="99999999-2222-3333-4444-555555555555"), True),
    ("nothing", {"id": LIST_ID}, True),
    ("the library", a_list(), False),
    ("the address in another case, a slash", a_list(url=f"{SITE}/restoretarget/"), False),
]


@pytest.fixture(scope="module")
def list_results():
    return evaluate([f"Test-RestoreTargetList {ps(reply)} {ps(LIST_ID)}" for _, reply, _ in LIST_ROWS])


@pytest.mark.parametrize("index", range(len(LIST_ROWS)), ids=[r[0] for r in LIST_ROWS])
def test_the_list_name_check(list_results, index):
    assert refused(list_results[index]) == LIST_ROWS[index][2], list_results[index]


DOCUMENTS = a_list("Documents", f"{SITE}/Shared%20Documents", list_id="22222222-2222-3333-4444-555555555555")
LIBRARY_ROWS = [
    ("a generic list of that name", [DOCUMENTS, a_list(template="genericList")], "throws"),
    ("another list at that address", [DOCUMENTS, a_list("Other")], "throws"),
    ("the name in another case", [a_list("restoretarget")], "throws"),
    ("two", [a_list(), a_list(list_id="33333333-2222-3333-4444-555555555555")], "throws"),
    ("none", [DOCUMENTS], "library.create"),
    ("no lists", [], "library.create"),
    ("the library", [DOCUMENTS, a_list()], None),
]


@pytest.fixture(scope="module")
def library_results():
    return evaluate([f"Get-LibraryPlan {ps(lists)} | ForEach-Object Action" for _, lists, _ in LIBRARY_ROWS])


@pytest.mark.parametrize("index", range(len(LIBRARY_ROWS)), ids=[r[0] for r in LIBRARY_ROWS])
def test_the_library_plan(library_results, index):
    got, expected = library_results[index], LIBRARY_ROWS[index][2]
    if expected == "throws":
        assert isinstance(got, dict) and "othing was changed" in got["throws"], got
    else:
        assert got == expected


# ---- the folder --------------------------------------------------------------------------------


def a_folder(name="RestoreTarget", path="/drive/root:", drive=DRIVE, folder=True, file=False, item_id=FOLDER):
    item = {"id": item_id, "name": name, "parentReference": {"driveId": drive, "path": path}}
    if folder:
        item["folder"] = {"childCount": 0}
    if file:
        item["file"] = {"mimeType": "text/plain"}
    return item


FOLDER_ROWS = [
    ("the canary folder", a_folder("RestoreTest"), True),
    ("the name in another case", a_folder("restoretarget"), True),
    ("a file", a_folder(folder=False, file=True), True),
    ("in a subfolder", a_folder(path="/drive/root:/Documents"), True),
    ("in another drive", a_folder(drive=OTHER_DRIVE), True),
    ("in another drive's root", a_folder(path=f"/drives/{OTHER_DRIVE}/root:"), True),
    ("another id", a_folder(item_id="01BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"), True),
    ("no parent", {"id": FOLDER, "name": "RestoreTarget", "folder": {}}, True),
    ("the folder", a_folder(), False),
    ("the folder, the drive's own root form", a_folder(path=f"/drives/{DRIVE}/root:"), False),
]


@pytest.fixture(scope="module")
def folder_results():
    rows = [f"Test-RestoreTargetFolder {ps(item)} {ps(DRIVE)} {ps(FOLDER)}" for _, item, _ in FOLDER_ROWS]
    rows += [
        f"Get-FolderPlan $null {ps(DRIVE)} | ForEach-Object Action",
        f"Get-FolderPlan {ps(a_folder())} {ps(DRIVE)} | ForEach-Object Action",
        f"Get-FolderPlan {ps(a_folder(folder=False, file=True))} {ps(DRIVE)} | ForEach-Object Action",
        f"Get-FolderPlan {ps(a_folder(path='/drive/root:/x'))} {ps(DRIVE)} | ForEach-Object Action",
    ]
    return evaluate(rows)


@pytest.mark.parametrize("index", range(len(FOLDER_ROWS)), ids=[r[0] for r in FOLDER_ROWS])
def test_the_folder_name_check(folder_results, index):
    assert refused(folder_results[index]) == FOLDER_ROWS[index][2], folder_results[index]


def test_the_folder_plan(folder_results):
    missing, there, a_file, nested = folder_results[len(FOLDER_ROWS):]
    assert "othing was changed" in a_file["throws"]
    assert "othing was changed" in nested["throws"]
    assert missing == "folder.create"
    assert there is None


def test_the_initial_domain():
    org = {"id": "x", "verifiedDomains": [
        {"name": "contoso.com", "isInitial": False, "isDefault": True},
        {"name": "contoso.onmicrosoft.com", "isInitial": True, "isDefault": False},
    ]}
    assert evaluate([f"Get-InitialDomain {ps(org)}", f"Get-InitialDomain {ps({'id': 'x'})}"]) == ["contoso.onmicrosoft.com", ""]
