import pytest

from seeder import CANARY_DIR, tenant
from seeder.manifest import dumps_manifest, load_manifest
from seeder.seed import run_seed
from seeder.verify import run_verify
from tests.fake_graph import FakeSignIn, FakeTenant

ALICE, BOB, ADMIN = tenant.ALICE_UPN, tenant.BOB_UPN, tenant.ADMIN_UPN


@pytest.fixture
def seeded(tmp_path):
    """A fake tenant seeded by run_seed, and its manifest."""
    fake = FakeTenant(rewrite_types={"docx", "xlsx"})
    manifest_path = tmp_path / "seed-manifest.json"
    code = run_seed(
        signin=FakeSignIn(),
        transport=fake,
        canary_dir=CANARY_DIR,
        manifest_path=manifest_path,
        sleep=lambda s: None,
        now=fake.now,
        out=lambda line: None,
    )
    assert code == 0
    return fake, manifest_path


def _verify(fake, manifest_path):
    lines: list[str] = []
    signin = FakeSignIn(out=lines.append)
    code = run_verify(signin=signin, transport=fake, manifest_path=manifest_path, out=lines.append)
    return code, lines, signin


# --- failure paths ----------------------------------------------------------------------

def test_missing_manifest_exits_2_without_signing_in(tmp_path):
    code, lines, signin = _verify(FakeTenant(), tmp_path / "seed-manifest.json")
    assert code == 2
    assert "python -m seeder seed" in "\n".join(lines)
    assert signin.providers == []


def test_invalid_manifest_exits_2(seeded, tmp_path):
    fake, manifest_path = seeded
    manifest = load_manifest(manifest_path)
    manifest["entries"].pop()
    manifest_path.write_text(dumps_manifest(manifest), encoding="utf-8")
    code, lines, signin = _verify(fake, manifest_path)
    assert code == 2
    assert signin.providers == []


def test_changed_body_is_a_body_sha256_diff(seeded):
    fake, manifest_path = seeded
    fake.messages(ALICE, "RP-CANARY-0004")[0]["body"]["content"] = "edited"
    code, lines, _ = _verify(fake, manifest_path)
    assert code == 1
    line = next(line for line in lines if "RP-CANARY-0004" in line)
    assert line.startswith("DIFF")
    assert "body_sha256: manifest " in line and ", tenant " in line
    assert lines[-1].startswith("39/40 entries in the tenant match the manifest")


def test_second_sharepoint_rewrite_with_the_same_content_is_ok(seeded):
    # The live run: SharePoint rewrote the Office files again after the seed (+3073 bytes,
    # same lastModifiedDateTime). Their content parts did not change, so they still match.
    from tests.office_fakes import sharepoint_rewrite

    fake, manifest_path = seeded
    item_id, _ = fake.item(tenant.SHAREPOINT_DRIVE_ID, "rp-canary-02.docx")
    item = fake.drives[tenant.SHAREPOINT_DRIVE_ID].items[item_id]
    item["data"] = sharepoint_rewrite(item["data"], round_=2)
    code, lines, _ = _verify(fake, manifest_path)
    assert code == 0, lines
    line = next(line for line in lines if "rp-canary-02.docx" in line)
    assert line.startswith("ok") and "office-v1" in line and "bytes changed" in line


def test_changed_office_content_is_a_content_sha256_diff(seeded):
    from tests.office_fakes import change_content

    fake, manifest_path = seeded
    item_id, _ = fake.item(tenant.SHAREPOINT_DRIVE_ID, "rp-canary-08.xlsx")
    item = fake.drives[tenant.SHAREPOINT_DRIVE_ID].items[item_id]
    item["data"] = change_content(item["data"], "xlsx")
    code, lines, _ = _verify(fake, manifest_path)
    assert code == 1
    line = next(line for line in lines if "rp-canary-08.xlsx" in line)
    assert line.startswith("DIFF") and "content_sha256" in line


def test_changed_pdf_bytes_are_a_content_sha256_diff(seeded):
    fake, manifest_path = seeded
    item_id, _ = fake.item(tenant.SHAREPOINT_DRIVE_ID, "rp-canary-06.pdf")
    fake.drives[tenant.SHAREPOINT_DRIVE_ID].items[item_id]["data"] += b"%%extra"
    code, lines, _ = _verify(fake, manifest_path)
    assert code == 1
    mine = [line for line in lines if "rp-canary-06.pdf" in line]
    assert all(line.startswith("DIFF") for line in mine)
    assert any("content_sha256 (bytes)" in line for line in mine)


def test_deleted_file_is_missing(seeded):
    fake, manifest_path = seeded
    item_id, _ = fake.item(tenant.SHAREPOINT_DRIVE_ID, "rp-canary-07.docx")
    del fake.drives[tenant.SHAREPOINT_DRIVE_ID].items[item_id]
    code, lines, _ = _verify(fake, manifest_path)
    assert code == 1
    assert next(line for line in lines if "rp-canary-07.docx" in line).startswith("MISSING")


def test_deleted_mail_is_missing(seeded):
    fake, manifest_path = seeded
    box = fake.mailboxes[BOB.lower()]
    box.remove(fake.messages(BOB, "RP-CANARY-0020")[0])
    code, lines, _ = _verify(fake, manifest_path)
    assert code == 1
    assert next(line for line in lines if "RP-CANARY-0020" in line).startswith("MISSING")


def test_changed_stored_bytes_are_a_diff(seeded):
    fake, manifest_path = seeded
    _, item = fake.item(tenant.ONEDRIVE_DRIVE_ID, "rp-canary-14.txt")
    item["data"] = item["data"] + b"x"
    code, lines, _ = _verify(fake, manifest_path)
    assert code == 1
    diffs = [line for line in lines if "rp-canary-14.txt" in line]
    assert all(line.startswith("DIFF") for line in diffs)
    text = "\n".join(diffs)
    assert "content_sha256 (bytes): manifest" in text and "size: manifest" in text


@pytest.mark.parametrize(
    "field, value, name",
    [
        ("subject", "RP-CANARY-9999", "subject"),
        ("internetMessageId", "<other@example.com>", "internet_message_id"),
        ("sentDateTime", "2020-01-01T00:00:00Z", "sent_at"),
        ("receivedDateTime", "2020-01-01T00:00:00Z", "received_at"),
    ],
)
def test_changed_mail_field_is_a_diff(seeded, field, value, name):
    fake, manifest_path = seeded
    fake.messages(ALICE, "RP-CANARY-0001")[0][field] = value
    code, lines, _ = _verify(fake, manifest_path)
    assert code == 1
    assert any(line.startswith("DIFF") and f"{name}: manifest" in line for line in lines)


# --- happy paths ------------------------------------------------------------------------

def test_happy_verify_is_40_of_40(seeded):
    fake, manifest_path = seeded
    code, lines, signin = _verify(fake, manifest_path)
    assert code == 0, "\n".join(lines)
    assert lines[-1] == "40/40 entries in the tenant match the manifest"
    assert sum(line.startswith("ok") for line in lines) == 40
    assert [u for u, _ in signin.interactive] == [ALICE, BOB, ADMIN]
    assert fake.calls["send_mail"] == 20 and fake.calls["upload"] == 20  # only the seed's


def test_sender_case_difference_is_ok(seeded):
    fake, manifest_path = seeded
    fake.messages(BOB, "RP-CANARY-0015")[0]["from"]["emailAddress"]["address"] = ADMIN.upper()
    code, lines, _ = _verify(fake, manifest_path)
    assert code == 0, "\n".join(lines)


def test_fractional_graph_dates_match(seeded):
    fake, manifest_path = seeded
    msg = fake.messages(ALICE, "RP-CANARY-0002")[0]
    msg["sentDateTime"] = msg["sentDateTime"].replace("Z", ".9999999Z")
    code, _, _ = _verify(fake, manifest_path)
    assert code == 0


def test_no_token_in_output(seeded):
    fake, manifest_path = seeded
    fake.messages(ALICE, "RP-CANARY-0004")[0]["body"]["content"] = "edited"
    _, lines, _ = _verify(fake, manifest_path)
    assert "token:" not in "\n".join(lines)
