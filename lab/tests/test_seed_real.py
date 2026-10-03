"""Tests for `python -m seeder seed-real` (L1.8): real, non-canary files and mails for the sampler's
random half. Against the fake tenant only; nothing here touches the network."""

import io
import re
import zipfile

import pytest

from seeder import LAB_DIR, MANIFEST_PATH, cli, tenant
from seeder.catalog import canary_files
from seeder.generate import generate_file
from seeder.graph import GraphError
from seeder.http import TransportError
from seeder.manifest import ManifestError, load_manifest
from seeder.seed_real import (
    MAX_FILE_BYTES,
    RealFile,
    RealMail,
    canary_names,
    name_key,
    plan_problems,
    real_file_bytes,
    real_files,
    real_mails,
    run_seed_real,
)
from tests.fake_graph import (
    ONEDRIVE_ROOT_ID,
    SITE_DOCUMENTS_DRIVE_ID,
    SITE_DOCUMENTS_ROOT_ID,
    FakeSignIn,
    FakeTenant,
)
from tests.fake_transport import graph_error

ALICE, BOB, ADMIN = tenant.ALICE_UPN, tenant.BOB_UPN, tenant.ADMIN_UPN
FILES = real_files()
MAILS = real_mails()
SP_FILES = [f for f in FILES if f.kind == "sharepoint_file"]
OD_FILES = [f for f in FILES if f.kind == "onedrive_file"]
CANARY = canary_names(load_manifest(MANIFEST_PATH))


class Run:
    def __init__(self, fake: FakeTenant, tmp_path) -> None:
        self.fake = fake
        self.lines: list[str] = []
        self.signin = FakeSignIn()
        self.manifest_path = MANIFEST_PATH

    def __call__(self, **kwargs) -> int:
        self.lines.clear()
        self.signin = FakeSignIn(out=self.lines.append)
        return run_seed_real(
            signin=self.signin,
            transport=self.fake,
            manifest_path=self.manifest_path,
            sleep=lambda _: None,
            out=self.lines.append,
            **kwargs,
        )

    @property
    def output(self) -> str:
        return "\n".join(self.lines)

    def nothing_written(self) -> bool:
        return self.fake.calls["upload"] == 0 and self.fake.calls["send_mail"] == 0


@pytest.fixture
def run(tmp_path):
    return Run(FakeTenant(), tmp_path)


def _uploaded(fake: FakeTenant, drive_id: str, parent: str) -> list[str]:
    return sorted(i["name"] for i in fake.drives[drive_id].items.values() if i["parent"] == parent)


# --- failure paths: the places it refuses ---------------------------------------------------
# Every refusal comes before any upload or send, in both places, whatever step found it.

FORBIDDEN_DRIVES = [
    pytest.param(tenant.RESTORE_TARGET_DRIVE_ID, "RestoreTarget", id="restore-target-library"),
    pytest.param(tenant.SHAREPOINT_DRIVE_ID, "RestoreTest", id="canary-library"),
]


@pytest.mark.parametrize("drive_id, word", FORBIDDEN_DRIVES)
def test_a_site_default_drive_that_is_a_forbidden_library_is_refused(run, drive_id, word):
    run.fake.site_drive[tenant.SHAREPOINT_SITE_ID] = drive_id
    assert run() == 1
    assert run.nothing_written()
    assert f"refused: the RestoreTest site's default drive is the {word} library" in run.output
    assert "nothing was uploaded or sent" in run.output


@pytest.mark.parametrize("drive_id, word", FORBIDDEN_DRIVES)
def test_alices_drive_that_is_a_forbidden_library_is_refused(run, drive_id, word):
    run.fake.my_drive[ALICE.lower()] = drive_id
    assert run() == 1
    assert run.nothing_written()
    assert f"refused: alice's OneDrive is the {word} library" in run.output


FORBIDDEN_FOLDERS = [
    pytest.param(tenant.ONEDRIVE_TARGET_FOLDER_ID, "RestoreTarget", id="restore-target-folder"),
    pytest.param(tenant.ONEDRIVE_FOLDER_ID, "RestoreTest", id="canary-folder"),
]


@pytest.mark.parametrize("folder_id, word", FORBIDDEN_FOLDERS)
def test_alices_root_that_is_a_forbidden_folder_is_refused(run, folder_id, word):
    run.fake.drive_roots[tenant.ONEDRIVE_DRIVE_ID] = folder_id
    assert run() == 1
    assert run.nothing_written()
    assert f"refused: alice's OneDrive root is the {word} folder" in run.output


@pytest.mark.parametrize("folder_id, word", FORBIDDEN_FOLDERS)
def test_a_site_root_that_is_a_forbidden_folder_is_refused(run, folder_id, word):
    run.fake.drive_roots[SITE_DOCUMENTS_DRIVE_ID] = folder_id
    run.fake.drives[SITE_DOCUMENTS_DRIVE_ID].folders[folder_id] = folder_id
    assert run() == 1
    assert run.nothing_written()
    assert f"refused: the RestoreTest site's default drive root is the {word} folder" in run.output


@pytest.mark.parametrize("drive_id", [SITE_DOCUMENTS_DRIVE_ID, tenant.ONEDRIVE_DRIVE_ID])
def test_a_root_without_the_root_facet_is_refused(run, drive_id):
    run.fake.not_root.add(run.fake.drive_roots[drive_id])
    assert run() == 1
    assert run.nothing_written()
    assert "is not a drive's root folder" in run.output


@pytest.mark.parametrize("drive_id", [SITE_DOCUMENTS_DRIVE_ID, tenant.ONEDRIVE_DRIVE_ID])
@pytest.mark.parametrize("name", ["RestoreTarget", "restoretest"])
def test_a_drive_named_like_a_target_or_the_canary_library_is_refused(run, drive_id, name):
    # Alice's drive reaches the name check only because its id matches lab/tenant.md.
    run.fake.drive_names[drive_id] = name
    assert run() == 1
    assert run.nothing_written()
    assert f"is named {name!r}" in run.output


def test_a_drive_id_compared_ignoring_case(run):
    # Drive ids are case-sensitive to Graph; refusing more is the safe side.
    run.fake.site_drive[tenant.SHAREPOINT_SITE_ID] = tenant.RESTORE_TARGET_DRIVE_ID.lower()
    run.fake.drive_names[tenant.RESTORE_TARGET_DRIVE_ID.lower()] = "Documents"
    assert run() == 1
    assert run.nothing_written()
    assert "RestoreTarget library" in run.output


def test_alices_drive_that_is_not_the_one_in_tenant_md_is_refused(run):
    run.fake.my_drive[ALICE.lower()] = "b!FAKESOMEONEELSESONEDRIVE"
    assert run() == 1
    assert run.nothing_written()
    assert "not alice's OneDrive as lab/tenant.md records it" in run.output


def test_a_refusal_found_by_alices_step_still_stops_the_admins_uploads(run):
    run.fake.drive_roots[tenant.ONEDRIVE_DRIVE_ID] = tenant.ONEDRIVE_TARGET_FOLDER_ID
    assert run() == 1
    # The admin's step ran first and found its place fine, but nothing was written there.
    assert _uploaded(run.fake, SITE_DOCUMENTS_DRIVE_ID, SITE_DOCUMENTS_ROOT_ID) == []
    assert run.fake.uploads == []


# --- failure paths: the plan's rules -------------------------------------------------------
# A plan that breaks a rule stops the run before any sign-in.

def _sp(name: str, number: int = 90) -> RealFile:
    return RealFile(number, name, "sharepoint_file", "A sentence.")


def _mail(subject: str, sender: str = ALICE, recipient: str = BOB) -> RealMail:
    return RealMail(subject, "A sentence.", sender, recipient)


@pytest.mark.parametrize(
    "files, mails, expected",
    [
        pytest.param([_sp("Notes.txt"), _sp("NOTES.TXT", 91)], [], "share one name key", id="file-case-twin"),
        pytest.param([], [_mail("Lunch"), _mail("lunch", BOB, ALICE)], "share one name key", id="subject-case-twin"),
        pytest.param([_sp("Rp-Canary-99.txt")], [], "starts with rp-canary-", id="file-canary-prefix"),
        pytest.param([], [_mail("rp-canary-0099")], "starts with rp-canary-", id="subject-canary-prefix"),
        pytest.param([_sp("plan/a.txt")], [], "'/'", id="slash"),
        pytest.param([_sp("plan\\a.txt")], [], "'\\\\'", id="backslash"),
        pytest.param([], [_mail("Re: lunch")], "':'", id="colon"),
        pytest.param([_sp("café.txt")], [], "printable ASCII", id="non-ascii"),
        pytest.param([_sp(" notes.txt")], [], "printable ASCII", id="leading-space"),
        pytest.param([_sp("notes.txt ")], [], "printable ASCII", id="trailing-space"),
        pytest.param([_sp("")], [], "printable ASCII", id="empty"),
        pytest.param([_sp("notes.exe")], [], "type", id="unknown-type"),
        pytest.param([], [_mail("Lunch", ALICE, tenant.RESTORETEST_UPN)], "only to alice or bob", id="to-restoretest"),
        pytest.param([], [_mail("Lunch", ALICE, ADMIN)], "only to alice or bob", id="to-admin"),
        pytest.param([], [_mail("Lunch", ADMIN, BOB)], "only from alice or bob", id="from-admin"),
        pytest.param([], [_mail("Lunch", ALICE, ALICE)], "to its own sender", id="to-self"),
    ],
)
def test_plan_problems(files, mails, expected):
    problems = plan_problems(files, mails, CANARY)
    assert any(expected in p for p in problems), problems


def test_a_name_equal_to_a_canary_name_in_the_manifest_is_refused():
    # The canary names all start with rp-canary- today; a manifest with any other name still counts.
    manifest = {
        "entries": [
            {"id": "Budget.pdf", "kind": "sharepoint_file", "name": "Budget.pdf"},
            {"id": "Weekly sync", "kind": "mail", "subject": "Weekly sync"},
        ]
    }
    canary = canary_names(manifest)
    problems = plan_problems([_sp("BUDGET.PDF")], [_mail("weekly SYNC")], canary)
    assert any("BUDGET.PDF" in p and "a canary" in p for p in problems), problems
    assert any("weekly SYNC" in p and "a canary" in p for p in problems), problems


def test_the_same_name_in_two_types_is_allowed():
    # The sampler's name key is per type: a SharePoint file and a OneDrive file never meet.
    od = RealFile(91, "notes.txt", "onedrive_file", "A sentence.")
    assert plan_problems([_sp("Notes.txt"), od], [], CANARY) == []


def test_a_file_too_large_is_refused(monkeypatch):
    from seeder import seed_real

    monkeypatch.setattr(seed_real, "MAX_FILE_BYTES", 10)
    problems = plan_problems([_sp("notes.txt")], [], CANARY)
    assert any("bytes, more than 10" in p for p in problems), problems


@pytest.mark.parametrize(
    "files, mails",
    [
        pytest.param([_sp("rp-canary-99.txt")], [], id="bad-file"),
        pytest.param([], [_mail("Lunch", ALICE, tenant.RESTORETEST_UPN)], id="mail-to-restoretest"),
    ],
)
def test_a_bad_plan_stops_before_any_sign_in(run, files, mails):
    assert run(files=files, mails=mails) == 1
    assert run.signin.providers == []
    assert run.fake.calls == {}
    assert "nothing was uploaded or sent" in run.output


def test_a_missing_manifest_stops_before_any_sign_in(run, tmp_path):
    # Raised, as for hash and verify: the CLI prints it on stderr and exits 2.
    run.manifest_path = tmp_path / "nope.json"
    with pytest.raises(ManifestError):
        run()
    assert run.signin.providers == []
    assert run.fake.calls == {}


# --- never replace ----------------------------------------------------------------------------

def test_a_file_already_in_place_is_not_uploaded_again(run):
    first = SP_FILES[0]
    run.fake.put_item(SITE_DOCUMENTS_DRIVE_ID, first.name, b"an older copy", parent=SITE_DOCUMENTS_ROOT_ID)
    assert run() == 0
    assert first.name not in [name for _, name, _ in run.fake.uploads]
    assert f"{first.name}: already there, not replaced" in run.output
    stored = next(i for i in run.fake.drives[SITE_DOCUMENTS_DRIVE_ID].items.values() if i["name"] == first.name)
    assert stored["data"] == b"an older copy"


def test_every_upload_fails_on_a_conflict_rather_than_replacing(run):
    assert run() == 0
    assert run.fake.uploads
    assert all(behavior == "fail" for _, _, behavior in run.fake.uploads)


def test_a_conflict_at_upload_time_is_reported_not_replaced(run, monkeypatch):
    # The file appears between the lookup and the upload: Graph answers 409 and nothing is replaced.
    from seeder import seed_real

    first = OD_FILES[0]
    run.fake.put_item(tenant.ONEDRIVE_DRIVE_ID, first.name, b"appeared meanwhile", parent=ONEDRIVE_ROOT_ID)
    real_lookup = seed_real.graph.get_item_by_path
    lookups: list[str] = []

    def lookup(g, d, f, name, owner):
        lookups.append(name)
        if name == first.name and lookups.count(name) == 1:
            return None  # not there yet at the first look; there when the 409 is checked
        return real_lookup(g, d, f, name, owner)

    monkeypatch.setattr(seed_real.graph, "get_item_by_path", lookup)
    assert run() == 0
    assert lookups.count(first.name) == 2
    assert f"{first.name}: already there, not replaced" in run.output
    stored = next(i for i in run.fake.drives[tenant.ONEDRIVE_DRIVE_ID].items.values() if i["name"] == first.name)
    assert stored["data"] == b"appeared meanwhile"


def test_a_conflict_with_no_file_there_is_an_error_not_already_there(run, monkeypatch):
    # A 409 for another reason (a lock, say): the file isn't there, so it isn't counted as there.
    from seeder import seed_real

    first = SP_FILES[0]
    real_upload = seed_real.graph.upload_file

    def upload(g, drive_id, folder_id, name, data, **kwargs):
        if name == first.name:
            raise GraphError("locked", status=409, method="PUT", path="/drives/x")
        return real_upload(g, drive_id, folder_id, name, data, **kwargs)

    monkeypatch.setattr(seed_real.graph, "upload_file", upload)
    with pytest.raises(GraphError) as info:
        run()
    assert info.value.status == 409
    assert f"{first.name}: Graph answered 409 Conflict" in str(info.value)
    assert "--force" not in str(info.value)
    assert f"{first.name}: already there" not in run.output
    assert run.fake.calls["send_mail"] == 0


# --- mails ------------------------------------------------------------------------------------

def test_mails_go_only_between_alice_and_bob_each_sent_by_its_sender(run):
    assert run() == 0
    assert len(run.fake.sent) == len(MAILS)
    for payload in run.fake.sent:
        recipients = [r["emailAddress"]["address"] for r in payload["message"]["toRecipients"]]
        assert len(recipients) == 1
        assert {payload["sender"], recipients[0]} == {ALICE, BOB}
        assert tenant.RESTORETEST_UPN.lower() not in recipients[0].lower()
        assert "ccRecipients" not in payload["message"] and "bccRecipients" not in payload["message"]
    assert run.fake.messages(tenant.RESTORETEST_UPN) == []


def test_a_mail_whose_subject_is_in_either_mailbox_is_not_sent_again(run):
    to_bob = next(m for m in MAILS if m.recipient == BOB)
    to_alice = next(m for m in MAILS if m.recipient == ALICE)
    run.fake.add_message(BOB, to_bob.subject, to_bob.body, sender=ALICE)  # bob has it, alice deleted hers
    run.fake.add_message(BOB, to_alice.subject, to_alice.body, sender=BOB, folder="Sent Items")
    assert run() == 0
    sent = [p["message"]["subject"] for p in run.fake.sent]
    assert to_bob.subject not in sent and to_alice.subject not in sent
    assert len(sent) == len(MAILS) - 2
    assert f"{to_bob.subject}: already in a mailbox, not sent" in run.output


def test_a_copy_only_in_deleted_items_does_not_count(run):
    mail = MAILS[0]
    run.fake.add_message(mail.recipient, mail.subject, mail.body, sender=mail.sender, folder="Deleted Items")
    assert run() == 0
    assert mail.subject in [p["message"]["subject"] for p in run.fake.sent]


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(_mail("Lunch", ALICE, tenant.RESTORETEST_UPN), id="alice-to-restoretest"),
        pytest.param(_mail("Lunch", BOB, tenant.ADMIN_UPN), id="bob-to-admin"),
        pytest.param(_mail("Lunch", ALICE, ALICE), id="to-self"),
        pytest.param(_mail("Lunch", ADMIN, BOB), id="from-admin"),
    ],
)
def test_the_send_check_runs_again_before_any_write_even_past_the_plan_check(run, monkeypatch, bad):
    # Belt and braces: every mail is checked again before the first upload, not only at its send.
    from seeder import seed_real

    monkeypatch.setattr(seed_real, "plan_problems", lambda files, mails, canary: [])
    with pytest.raises(seed_real.RefusedError) as info:
        run(mails=[*MAILS, bad])
    assert run.nothing_written()
    assert "seed-real sends only between alice and bob" in str(info.value)
    assert "nothing was uploaded or sent" in str(info.value)


def test_the_send_itself_still_refuses_a_bad_recipient():
    # The last check, at the send: reached only if the one before the writes were skipped.
    from seeder import seed_real

    fake = FakeTenant()
    s = seed_real._SeedReal(signin=FakeSignIn(), transport=fake, sleep=lambda _: None, out=lambda _: None)
    with pytest.raises(seed_real.RefusedError):
        s.send(s.client(ALICE, "send"), ALICE, [_mail("Lunch", ALICE, tenant.RESTORETEST_UPN)])
    assert fake.calls["send_mail"] == 0


# --- the whole run --------------------------------------------------------------------------

def test_happy_run_puts_files_in_the_two_roots_and_sends_every_mail(run):
    assert run() == 0
    assert _uploaded(run.fake, SITE_DOCUMENTS_DRIVE_ID, SITE_DOCUMENTS_ROOT_ID) == sorted(f.name for f in SP_FILES)
    assert _uploaded(run.fake, tenant.ONEDRIVE_DRIVE_ID, ONEDRIVE_ROOT_ID) == sorted(f.name for f in OD_FILES)
    # Nothing in the canary library or folder, nothing in a restore target.
    assert run.fake.drives[tenant.SHAREPOINT_DRIVE_ID].items == {}
    assert _uploaded(run.fake, tenant.ONEDRIVE_DRIVE_ID, tenant.ONEDRIVE_FOLDER_ID) == []
    assert run.fake.app_items == {}
    uploaders = {name: account for account, name, _ in run.fake.uploads}
    assert all(uploaders[f.name] == ADMIN for f in SP_FILES)
    assert all(uploaders[f.name] == ALICE for f in OD_FILES)
    for f in FILES:
        drive = SITE_DOCUMENTS_DRIVE_ID if f.kind == "sharepoint_file" else tenant.ONEDRIVE_DRIVE_ID
        stored = next(i for i in run.fake.drives[drive].items.values() if i["name"] == f.name)
        assert stored["data"] == real_file_bytes(f)
    assert run.lines[-1].startswith("Next: run the Veeam backup")


def test_three_sign_ins_admin_alice_bob_then_cached(run):
    assert run() == 0
    assert [u for u, _ in run.signin.interactive] == [ADMIN, ALICE, BOB]
    assert [u for u, _ in run.signin.providers] == [ADMIN, ALICE, BOB, ADMIN, ALICE, BOB]


def test_rerun_uploads_and_sends_nothing(run):
    assert run() == 0
    uploads, sends = run.fake.calls["upload"], run.fake.calls["send_mail"]
    assert run() == 0
    assert run.fake.calls["upload"] == uploads
    assert run.fake.calls["send_mail"] == sends
    assert "0 uploaded" in run.output and "0 sent" in run.output


def test_no_token_in_output(run):
    run()
    assert "token:" not in run.output
    assert "Bearer" not in run.output


# --- the plan itself ------------------------------------------------------------------------

def test_the_plan_passes_its_own_rules_against_the_committed_manifest():
    assert plan_problems(FILES, MAILS, CANARY) == []


def test_six_to_eight_files_per_place_and_about_six_mails_each_way():
    assert 6 <= len(SP_FILES) <= 8
    assert 6 <= len(OD_FILES) <= 8
    assert len([m for m in MAILS if (m.sender, m.recipient) == (ALICE, BOB)]) == 6
    assert len([m for m in MAILS if (m.sender, m.recipient) == (BOB, ALICE)]) == 6


def test_mostly_txt_pdf_png_and_at_most_two_office_files():
    office = [f for f in FILES if f.file_type in ("docx", "xlsx")]
    assert 1 <= len(office) <= 2
    for files in (SP_FILES, OD_FILES):
        assert {f.file_type for f in files} >= {"txt", "pdf", "png"}


def test_files_are_small_deterministic_and_unlike_any_canary_file():
    canary_bytes = {generate_file(f) for f in canary_files()}
    for f in FILES:
        data = real_file_bytes(f)
        assert data == real_file_bytes(f), f.name
        assert 0 < len(data) <= MAX_FILE_BYTES, f.name
        assert data not in canary_bytes, f.name


def test_each_file_opens_in_its_reader():
    from docx import Document
    from openpyxl import load_workbook
    from PIL import Image
    from pypdf import PdfReader

    for f in FILES:
        data = real_file_bytes(f)
        if f.file_type == "txt":
            assert f.sentence in data.decode("ascii")
        elif f.file_type == "pdf":
            assert f.sentence in PdfReader(io.BytesIO(data)).pages[0].extract_text()
        elif f.file_type == "png":
            assert Image.open(io.BytesIO(data)).size == (64, 64)
        elif f.file_type == "docx":
            assert f.sentence in [p.text for p in Document(io.BytesIO(data)).paragraphs]
        else:
            workbook = load_workbook(io.BytesIO(data))
            assert workbook.active["A2"].value == f.sentence
            assert workbook.sheetnames == ["Sheet1"]
        if f.file_type in ("docx", "xlsx"):
            assert zipfile.ZipFile(io.BytesIO(data)).testzip() is None


def test_no_file_calls_itself_a_canary():
    for f in FILES:
        data = real_file_bytes(f)
        if f.file_type in ("docx", "xlsx"):
            package = zipfile.ZipFile(io.BytesIO(data))
            data = b"".join(package.read(name) for name in package.namelist())
        assert b"canary" not in data.lower(), f.name


def test_mail_bodies_are_ascii_crlf_and_short_lines():
    for mail in MAILS:
        assert mail.body.isascii()
        assert "\n" not in mail.body.replace("\r\n", "")
        assert all(len(line) < 76 for line in mail.body.split("\r\n"))
        assert "canary" not in mail.body.lower()


def test_name_key_is_upper_case():
    assert name_key("Budget-Summary.pdf") == name_key("BUDGET-summary.PDF")
    assert name_key("a.txt") != name_key("b.txt")


def _tenant_md_section() -> str:
    text = (LAB_DIR / "tenant.md").read_text(encoding="utf-8")
    parts = text.split("## Real data for the random sample", 1)
    assert len(parts) == 2, "lab/tenant.md has no 'Real data for the random sample' section"
    return parts[1].split("\n## ", 1)[0]


def _ticked(text: str) -> list[str]:
    return re.findall(r"`([^`]+)`", text)


def _paragraph(section: str, heading: str) -> str:
    parts = section.split(f"**{heading}**", 1)
    assert len(parts) == 2, f"lab/tenant.md's section has no **{heading}** paragraph"
    return parts[1].split("\n\n", 1)[0]


def test_tenant_md_lists_exactly_the_files_in_their_places():
    section = _tenant_md_section()
    # The SharePoint paragraph also names the library, `Shared Documents`.
    assert set(_ticked(_paragraph(section, "SharePoint"))) - {"Shared Documents"} == {f.name for f in SP_FILES}
    assert set(_ticked(_paragraph(section, "OneDrive"))) == {f.name for f in OD_FILES}


def test_tenant_md_lists_exactly_the_mails_in_their_directions():
    rows = [_ticked(line) for line in _tenant_md_section().splitlines() if line.startswith("| `")]
    assert all(len(row) == 2 for row in rows), rows
    assert [row[0] for row in rows] == [m.subject for m in MAILS if (m.sender, m.recipient) == (ALICE, BOB)]
    assert [row[1] for row in rows] == [m.subject for m in MAILS if (m.sender, m.recipient) == (BOB, ALICE)]


# --- the CLI ----------------------------------------------------------------------------------

def test_seed_real_through_main(monkeypatch, capsys):
    fake = FakeTenant()
    monkeypatch.setattr(cli, "SignIn", lambda client_id, tenant_id, *, mode, out: FakeSignIn(out=out))
    monkeypatch.setattr(cli, "RequestsTransport", lambda: fake)
    assert cli.main(["seed-real", "--client-id", "cid", "--auth", "device"]) == 0
    assert fake.calls["upload"] == len(FILES)
    assert "Seeded real data" in capsys.readouterr().out


def test_seed_real_without_a_client_id_is_one_line_exit_2(monkeypatch, capsys):
    from seeder import auth

    monkeypatch.delenv(auth.CLIENT_ID_ENV, raising=False)
    monkeypatch.setattr(tenant, "SEEDER_CLIENT_ID", "")
    assert cli.main(["seed-real"]) == 2
    assert capsys.readouterr().err.startswith("error: No client ID")


def _through_main(monkeypatch, transport) -> None:
    monkeypatch.setattr(cli, "SignIn", lambda client_id, tenant_id, *, mode, out: FakeSignIn(out=out))
    monkeypatch.setattr(cli, "RequestsTransport", lambda: transport)


def test_seed_real_with_a_missing_manifest_is_one_line_exit_2(monkeypatch, capsys, tmp_path):
    fake = FakeTenant()
    _through_main(monkeypatch, fake)
    assert cli.main(["seed-real", "--client-id", "cid", "--manifest", str(tmp_path / "nope.json")]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "nope.json" in err and err.count("\n") == 1
    assert fake.calls == {}


def test_a_refused_send_through_main_is_one_line_exit_2_and_nothing_written(monkeypatch, capsys):
    from seeder import seed_real

    fake = FakeTenant()
    _through_main(monkeypatch, fake)
    monkeypatch.setattr(seed_real, "plan_problems", lambda files, mails, canary: [])
    monkeypatch.setattr(seed_real, "real_mails", lambda: (*MAILS, _mail("Lunch", ALICE, tenant.RESTORETEST_UPN)))
    assert cli.main(["seed-real", "--client-id", "cid", "--auth", "device"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: refused to send 'Lunch'") and err.count("\n") == 1
    assert fake.calls["send_mail"] == 0 and fake.calls["upload"] == 0


class _Unknown:
    """The fake tenant, but every matching write gets no answer or a 503."""

    def __init__(self, fake: FakeTenant, method: str, path_part: str, failure: str) -> None:
        self.fake, self.method, self.path_part, self.failure = fake, method, path_part, failure
        self.hits = 0

    def request(self, method, url, headers, body=None):
        if method == self.method and self.path_part in url:
            self.hits += 1
            if self.failure == "no response":
                raise TransportError(f"{method} https://graph.microsoft.com/...: ConnectionError: reset")
            return graph_error(503, "serviceNotAvailable", "busy")
        return self.fake.request(method, url, headers, body)


@pytest.mark.parametrize("failure", ["no response", "503"])
@pytest.mark.parametrize(
    "method, path_part, what",
    [
        pytest.param("PUT", f"/{SP_FILES[0].name}:/content", "may have been uploaded", id="upload"),
        pytest.param("POST", "/me/sendMail", "may have been sent", id="send"),
    ],
)
def test_an_unknown_outcome_tells_the_owner_to_run_seed_real_again(monkeypatch, capsys, method, path_part, what, failure):
    transport = _Unknown(FakeTenant(), method, path_part, failure)
    _through_main(monkeypatch, transport)
    assert cli.main(["seed-real", "--client-id", "cid", "--auth", "device"]) == 2
    err = capsys.readouterr().err
    assert what in err and "run seed-real again" in err
    assert "run seed again" not in err
    assert transport.hits == 1  # never sent twice: it may have happened


def test_help_lists_seed_real(capsys):
    assert cli.main(["--help"]) == 0
    assert "seed-real" in capsys.readouterr().out
