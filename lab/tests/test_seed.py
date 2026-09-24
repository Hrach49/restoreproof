import json

import pytest

from seeder import CANARY_DIR, tenant
from seeder.catalog import canary_files, canary_mails
from seeder.graph import GraphForbidden
from seeder.manifest import load_manifest, run_hash, validate_manifest
from seeder.seed import run_seed
from tests.fake_graph import FakeSignIn, FakeTenant

ALICE, BOB, ADMIN = tenant.ALICE_UPN, tenant.BOB_UPN, tenant.ADMIN_UPN
MAILS = {m.subject: m for m in canary_mails()}
FILES = {f.name: f for f in canary_files()}


class Clock:
    def __init__(self) -> None:
        self.t = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


class Run:
    def __init__(self, fake: FakeTenant, tmp_path, *, canary_dir=CANARY_DIR) -> None:
        self.fake = fake
        self.signin = FakeSignIn()
        self.clock = Clock()
        self.lines: list[str] = []
        self.manifest_path = tmp_path / "seed-manifest.json"
        self.canary_dir = canary_dir

    def __call__(self, **kwargs) -> int:
        self.lines.clear()
        kwargs.setdefault("now", self.fake.now)
        self.signin = FakeSignIn(out=self.lines.append)
        return run_seed(
            signin=self.signin,
            transport=self.fake,
            canary_dir=self.canary_dir,
            manifest_path=self.manifest_path,
            clock=self.clock,
            sleep=self.clock.sleep,
            out=self.lines.append,
            **kwargs,
        )

    @property
    def output(self) -> str:
        return "\n".join(self.lines)


@pytest.fixture
def run(tmp_path):
    return Run(FakeTenant(), tmp_path)


def _populate(fake: FakeTenant) -> None:
    """Every canary item already in the tenant, as a previous seed left it."""
    for mail in canary_mails():
        fake.add_message(mail.recipient, mail.subject, mail.body)
    for file in canary_files():
        fake.put_item(file.drive_id, file.name, (CANARY_DIR / file.name).read_bytes())


# --- failure paths ----------------------------------------------------------------------

def test_missing_canary_file_fails_before_any_sign_in(tmp_path):
    canary = tmp_path / "canary"
    canary.mkdir()
    for f in canary_files()[1:]:
        (canary / f.name).write_bytes((CANARY_DIR / f.name).read_bytes())
    r = Run(FakeTenant(), tmp_path, canary_dir=canary)
    assert r() == 1
    assert "rp-canary-01.pdf" in r.output
    assert "python -m seeder generate" in r.output
    assert r.signin.providers == []
    assert not r.manifest_path.exists()


def test_duplicate_subject_fails_naming_subject_and_mailbox_without_manifest(run):
    run.fake.add_message(ALICE, "RP-CANARY-0003", MAILS["RP-CANARY-0003"].body)
    run.fake.add_message(ALICE, "RP-CANARY-0003", MAILS["RP-CANARY-0003"].body)
    assert run() == 1
    assert "RP-CANARY-0003" in run.output
    assert ALICE in run.output
    assert "delete" in run.output.lower()
    assert run.fake.calls["send_mail"] == 0
    assert not run.manifest_path.exists()


def test_two_copies_in_inbox_are_a_duplicate_even_with_a_third_in_deleted_items(run):
    for folder in ("Inbox", "Inbox", "Deleted Items"):
        run.fake.add_message(BOB, "RP-CANARY-0017", MAILS["RP-CANARY-0017"].body, folder=folder)
    assert run() == 1
    assert f"RP-CANARY-0017 is in {BOB}'s mailbox 2 times" in run.output
    assert "Deleted Items" in run.output  # the advice says a deleted copy no longer counts
    assert run.fake.calls["send_mail"] == 0
    assert not run.manifest_path.exists()


def test_mail_poll_timeout_names_missing_subjects_and_mailbox_and_writes_no_manifest(tmp_path):
    fake = FakeTenant(delivery_delay=None)  # sent mails never arrive
    # Bob already has his mails; only alice's are missing.
    for n in range(11, 21):
        mail = MAILS[f"RP-CANARY-{n:04d}"]
        fake.add_message(BOB, mail.subject, mail.body)
    r = Run(fake, tmp_path)
    code = r(mail_timeout=60, poll_interval=10)
    assert code != 0
    assert not r.manifest_path.exists()
    missing = [line for line in r.lines if "RP-CANARY-0001" in line and ALICE in line]
    assert missing, r.output
    assert "RP-CANARY-0010" in r.output
    assert "RP-CANARY-0011" not in "\n".join(line for line in r.lines if "missing" in line.lower())
    assert sum(r.clock.sleeps) >= 60
    assert set(r.clock.sleeps) == {10}


def test_forbidden_drive_names_the_signed_in_account(run):
    run.fake.drive_access[tenant.ONEDRIVE_DRIVE_ID] = BOB  # alice's OneDrive refuses alice
    with pytest.raises(GraphForbidden) as info:
        run()
    assert ALICE in str(info.value)
    assert "token:" not in str(info.value)
    assert not run.manifest_path.exists()


def test_manifest_missing_before_run_is_not_created_on_failure(run):
    run.fake.drive_access[tenant.SHAREPOINT_DRIVE_ID] = BOB
    with pytest.raises(GraphForbidden):
        run()
    assert not run.manifest_path.exists()


# --- sign-in order ------------------------------------------------------------------------

def test_three_interactive_sign_ins_in_order_alice_bob_admin(run):
    assert run() == 0
    assert [u for u, _ in run.signin.interactive] == [ALICE, BOB, ADMIN]
    purposes = [p for _, p in run.signin.interactive]
    assert "RP-CANARY-0001..0010" in purposes[0] and "OneDrive" in purposes[0]
    assert "RP-CANARY-0011..0020" in purposes[1]
    assert "send" in purposes[2] and "SharePoint" in purposes[2]
    # Later steps reuse alice and bob (silent in the real SignIn).
    assert [u for u, _ in run.signin.providers] == [ALICE, BOB, ADMIN, ALICE, BOB]


def test_step_headers_name_the_account(run):
    run()
    headers = [line for line in run.lines if line.startswith("Step ")]
    assert len(headers) == 5
    assert headers[0].startswith(f"Step 1/5: {ALICE}")
    assert headers[1].startswith(f"Step 2/5: {BOB}")
    assert headers[2].startswith(f"Step 3/5: {ADMIN}")
    assert headers[3].startswith(f"Step 4/5: {ALICE}")
    assert headers[4].startswith(f"Step 5/5: {BOB}")


# --- mails --------------------------------------------------------------------------------

def test_existing_subject_is_not_sent_again_others_are(run):
    run.fake.add_message(ALICE, "RP-CANARY-0002", MAILS["RP-CANARY-0002"].body)
    run.fake.add_message(BOB, "RP-CANARY-0015", MAILS["RP-CANARY-0015"].body)
    assert run() == 0
    sent = [p["message"]["subject"] for p in run.fake.sent]
    assert len(sent) == 18
    assert "RP-CANARY-0002" not in sent and "RP-CANARY-0015" not in sent
    assert all(p["sender"] == ADMIN for p in run.fake.sent)
    assert "RP-CANARY-0002" in run.output and "already in mailbox, not sent" in run.output
    assert len(run.fake.messages(ALICE, "RP-CANARY-0002")) == 1


# Bug found in review: the subject lookup searched every folder, so a copy the user deleted
# (it moves to Deleted Items) still counted: the duplicate error never went away, and a lone
# deleted canary was not re-sent and was recorded in folder "Deleted Items".

def test_copy_in_deleted_items_is_not_a_duplicate(run):
    kept = run.fake.add_message(ALICE, "RP-CANARY-0003", MAILS["RP-CANARY-0003"].body)
    run.fake.add_message(ALICE, "RP-CANARY-0003", MAILS["RP-CANARY-0003"].body, folder="Deleted Items")
    assert run() == 0
    assert "RP-CANARY-0003" not in [p["message"]["subject"] for p in run.fake.sent]
    entry = load_manifest(run.manifest_path)["entries"][2]
    assert entry["graph_message_id"] == kept["id"]
    assert entry["location"]["folder"] == "Inbox"
    assert "Deleted Items" not in run.output
    assert run.fake.calls["deleted_items"] == 2  # looked up once per mailbox


def test_canary_only_in_deleted_items_is_sent_again_and_the_new_copy_read_back(run):
    deleted = run.fake.add_message(BOB, "RP-CANARY-0014", MAILS["RP-CANARY-0014"].body, folder="Deleted Items")
    assert run() == 0
    assert "RP-CANARY-0014" in [p["message"]["subject"] for p in run.fake.sent]
    assert "RP-CANARY-0014: sent to" in run.output
    entry = load_manifest(run.manifest_path)["entries"][13]
    assert entry["graph_message_id"] != deleted["id"]
    assert entry["graph_message_id"] == run.fake.messages(BOB, "RP-CANARY-0014")[-1]["id"]
    assert entry["location"]["folder"] == "Inbox"


def test_force_reads_back_the_new_copy_not_the_deleted_one(run):
    _populate(run.fake)
    deleted = run.fake.add_message(ALICE, "RP-CANARY-0001", MAILS["RP-CANARY-0001"].body, folder="Deleted Items")
    assert run(force=True) == 0
    assert "RP-CANARY-0001: 1 already in mailbox, sending again (--force)" in run.output
    entry = load_manifest(run.manifest_path)["entries"][0]
    assert entry["graph_message_id"] != deleted["id"]
    assert entry["graph_message_id"] == run.fake.messages(ALICE, "RP-CANARY-0001")[-1]["id"]
    assert entry["location"]["folder"] == "Inbox"


def test_mails_are_sent_with_the_catalog_body_to_the_catalog_recipient(run):
    run()
    by_subject = {p["message"]["subject"]: p["message"] for p in run.fake.sent}
    for subject, mail in MAILS.items():
        assert by_subject[subject]["body"] == {"contentType": "text", "content": mail.body}
        assert by_subject[subject]["toRecipients"][0]["emailAddress"]["address"] == mail.recipient


def test_force_resends_and_reads_back_the_newest_copy(run):
    _populate(run.fake)
    old_ids = {m["subject"]: m["id"] for upn in (ALICE, BOB) for m in run.fake.messages(upn)}
    assert run(force=True) == 0
    assert run.fake.calls["send_mail"] == 20
    manifest = load_manifest(run.manifest_path)
    for entry in manifest["entries"][:20]:
        assert entry["graph_message_id"] != old_ids[entry["id"]]
        newest = run.fake.messages(entry["recipient"], entry["id"])[-1]
        assert entry["graph_message_id"] == newest["id"]
    assert all(behavior == "replace" for _, _, behavior in run.fake.uploads)
    assert len(run.fake.uploads) == 20


def test_force_finds_the_new_copy_when_the_local_clock_runs_ahead(run):
    # Bug found in review: --force picked the copy received at/after the local send time,
    # so a PC clock ahead of Exchange made the new copies invisible and the run timed out.
    _populate(run.fake)
    old_ids = {m["subject"]: m["id"] for upn in (ALICE, BOB) for m in run.fake.messages(upn)}
    assert run(force=True, now=lambda: "2099-01-01T00:00:00Z") == 0
    manifest = load_manifest(run.manifest_path)
    for entry in manifest["entries"][:20]:
        assert entry["graph_message_id"] != old_ids[entry["id"]]


def test_force_with_duplicates_does_not_stop(run):
    run.fake.add_message(ALICE, "RP-CANARY-0001", MAILS["RP-CANARY-0001"].body)
    run.fake.add_message(ALICE, "RP-CANARY-0001", MAILS["RP-CANARY-0001"].body)
    assert run(force=True) == 0


def test_polls_until_delivered(tmp_path):
    r = Run(FakeTenant(delivery_delay=3), tmp_path)
    assert r(poll_interval=10) == 0
    assert r.clock.sleeps and set(r.clock.sleeps) == {10}


def test_exchange_body_change_is_recorded_and_reported(tmp_path):
    r = Run(FakeTenant(body_transform=lambda s: s.replace("\r\n", "\n") + "\n"), tmp_path)
    assert r() == 0
    entry = load_manifest(r.manifest_path)["entries"][0]
    assert entry["body_readback_exact"] is False
    assert entry["body_sha256"] == entry["sent_body_sha256"]
    report = r.output
    assert "RP-CANARY-0001" in report
    assert "same after text-v1" in report
    assert repr("\r\n")[1:-1] in report  # the first difference is shown escaped


def test_body_changed_beyond_normalisation_is_reported(tmp_path):
    r = Run(FakeTenant(body_transform=lambda s: "Hello " + s), tmp_path)
    assert r() == 0
    entry = load_manifest(r.manifest_path)["entries"][5]
    assert entry["body_sha256"] != entry["sent_body_sha256"]
    assert "differs after text-v1" in r.output


def test_mail_outside_inbox_is_reported(run):
    run.fake.add_message(BOB, "RP-CANARY-0012", MAILS["RP-CANARY-0012"].body, folder="Archive")
    assert run() == 0
    entry = load_manifest(run.manifest_path)["entries"][11]
    assert entry["location"]["folder"] == "Archive"
    assert any("RP-CANARY-0012" in line and "Archive" in line for line in run.lines)


# --- files --------------------------------------------------------------------------------

def test_upload_and_readback_record_both_hashes_with_sharepoint_rewrite(tmp_path):
    r = Run(FakeTenant(rewrite_types={"docx", "xlsx"}), tmp_path)
    assert r() == 0
    entries = {e["id"]: e for e in load_manifest(r.manifest_path)["entries"]}
    docx = entries["rp-canary-02.docx"]
    assert docx["stored_matches_local"] is False
    assert docx["stored_size"] > docx["local_size"]
    assert docx["location"]["folder_id"] != "root"
    assert entries["rp-canary-01.pdf"]["stored_matches_local"] is True
    assert entries["rp-canary-12.docx"]["stored_matches_local"] is True  # OneDrive: no rewrite
    size_line = f"{docx['local_size']} -> {docx['stored_size']}"
    assert any("rp-canary-02.docx" in line and size_line in line for line in r.lines), r.output
    assert all(b == "fail" for _, _, b in r.fake.uploads)
    uploaders = {name: acct for acct, name, _ in r.fake.uploads}
    assert uploaders["rp-canary-01.pdf"] == ADMIN and uploaders["rp-canary-11.pdf"] == ALICE


def test_existing_file_is_not_uploaded_but_is_downloaded(run):
    run.fake.put_item(tenant.ONEDRIVE_DRIVE_ID, "rp-canary-14.txt", b"stale copy\n")
    assert run() == 0
    assert "rp-canary-14.txt" not in [name for _, name, _ in run.fake.uploads]
    assert len(run.fake.uploads) == 19
    entry = {e["id"]: e for e in load_manifest(run.manifest_path)["entries"]}["rp-canary-14.txt"]
    assert entry["stored_sha256"] != entry["local_sha256"]
    assert entry["stored_size"] == len(b"stale copy\n")
    line = next(line for line in run.lines if "rp-canary-14.txt" in line and "already uploaded" in line)
    assert "not replaced" in line
    assert "--force" in run.output and "stale" in run.output


# --- the whole run ------------------------------------------------------------------------

def test_happy_run_writes_a_valid_manifest_that_hash_accepts(run):
    assert run() == 0
    manifest = load_manifest(run.manifest_path)
    validate_manifest(manifest)
    assert len(manifest["entries"]) == 40
    assert manifest["seeded_at"].endswith("Z")
    first = manifest["entries"][0]
    assert first["sender"] == ADMIN and first["location"] == {"mailbox": ALICE, "folder": "Inbox"}
    assert first["body_readback_exact"] is True
    lines: list[str] = []
    assert run_hash(run.manifest_path, CANARY_DIR, out=lines.append) == 0
    assert lines[-1] == "40/40 entries reproduce the manifest hashes"
    assert str(run.manifest_path) in run.output
    assert "uv run python -m seeder hash" in run.output
    assert "uv run python -m seeder verify" in run.output
    assert run.lines[-1] == (
        "Run the Veeam backup (L1.3) only after this seed: every canary item must be in the restore points."
    )


def test_rerun_on_populated_tenant_sends_and_uploads_nothing(run):
    assert run() == 0
    first = run.manifest_path.read_text(encoding="utf-8")
    sends, uploads = run.fake.calls["send_mail"], run.fake.calls["upload"]
    assert run() == 0
    assert run.fake.calls["send_mail"] == sends
    assert run.fake.calls["upload"] == uploads
    assert "overwritten" in run.output or "overwrite" in run.output
    second = json.loads(run.manifest_path.read_text(encoding="utf-8"))
    first_json = json.loads(first)
    assert second["entries"] == first_json["entries"]


def test_no_token_in_output(run):
    run()
    assert "token:" not in run.output
    assert "Bearer" not in run.output
    assert "token:" not in run.manifest_path.read_text(encoding="utf-8")
