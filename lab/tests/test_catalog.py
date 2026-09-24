import re

import pytest

from seeder import LAB_DIR, tenant
from seeder.catalog import (
    FILE_TYPE_CYCLE,
    MAIL_FOOTER,
    canary_files,
    canary_mails,
)

MAILS = canary_mails()
FILES = canary_files()


def test_tenant_ids_match_tenant_md():
    text = (LAB_DIR / "tenant.md").read_text(encoding="utf-8")
    values = [
        tenant.TENANT_DOMAIN,
        tenant.TENANT_ID,
        tenant.ADMIN_UPN,
        tenant.ALICE_UPN,
        tenant.BOB_UPN,
        tenant.SHAREPOINT_SITE_ID,
        tenant.SHAREPOINT_LIST_ID,
        tenant.SHAREPOINT_DRIVE_ID,
        tenant.ONEDRIVE_DRIVE_ID,
        tenant.ONEDRIVE_FOLDER_ID,
    ]
    missing = [v for v in values if f"`{v}`" not in text]
    assert not missing, f"seeder/tenant.py values not in lab/tenant.md: {missing}"


def test_seeder_client_id_is_recorded_in_tenant_md_once_set():
    if not tenant.SEEDER_CLIENT_ID:
        pytest.skip("seeder app not registered yet")
    text = (LAB_DIR / "tenant.md").read_text(encoding="utf-8")
    assert f"`{tenant.SEEDER_CLIENT_ID}`" in text


def test_twenty_mails_with_unique_subjects_and_sentences():
    assert len(MAILS) == 20
    assert len({m.subject for m in MAILS}) == 20
    assert len({m.sentence for m in MAILS}) == 20
    assert [m.subject for m in MAILS] == [f"RP-CANARY-{n:04d}" for n in range(1, 21)]


@pytest.mark.parametrize(
    "number, recipient",
    [(1, tenant.ALICE_UPN), (10, tenant.ALICE_UPN), (11, tenant.BOB_UPN), (20, tenant.BOB_UPN)],
)
def test_mail_recipient_split(number, recipient):
    mail = MAILS[number - 1]
    assert mail.recipient == recipient
    assert mail.sender == tenant.ADMIN_UPN


def test_mail_bodies_are_ascii_crlf_short_lines_ending_with_the_footer():
    for mail in MAILS:
        assert mail.body.isascii()
        assert mail.body.endswith(MAIL_FOOTER)
        assert "\n" not in mail.body.replace("\r\n", "")
        assert all(len(line) < 76 for line in mail.body.split("\r\n"))
        assert all(line == line.rstrip(" \t") for line in mail.body.split("\r\n"))


def test_twenty_files_named_in_order():
    assert [f.name for f in FILES] == [
        f"rp-canary-{n:02d}.{FILE_TYPE_CYCLE[(n - 1) % 5]}" for n in range(1, 21)
    ]
    assert len({f.sentence for f in FILES}) == 20


@pytest.mark.parametrize(
    "number, name, kind, uploader",
    [
        (1, "rp-canary-01.pdf", "sharepoint_file", tenant.ADMIN_UPN),
        (2, "rp-canary-02.docx", "sharepoint_file", tenant.ADMIN_UPN),
        (3, "rp-canary-03.xlsx", "sharepoint_file", tenant.ADMIN_UPN),
        (4, "rp-canary-04.txt", "sharepoint_file", tenant.ADMIN_UPN),
        (5, "rp-canary-05.png", "sharepoint_file", tenant.ADMIN_UPN),
        (10, "rp-canary-10.png", "sharepoint_file", tenant.ADMIN_UPN),
        (11, "rp-canary-11.pdf", "onedrive_file", tenant.ALICE_UPN),
        (20, "rp-canary-20.png", "onedrive_file", tenant.ALICE_UPN),
    ],
)
def test_file_type_and_location(number, name, kind, uploader):
    f = FILES[number - 1]
    assert (f.name, f.kind, f.uploader) == (name, kind, uploader)
    if kind == "sharepoint_file":
        assert (f.drive_id, f.folder_id) == (tenant.SHAREPOINT_DRIVE_ID, "root")
    else:
        assert (f.drive_id, f.folder_id) == (tenant.ONEDRIVE_DRIVE_ID, tenant.ONEDRIVE_FOLDER_ID)


def test_each_location_holds_two_files_of_every_type():
    for kind in ("sharepoint_file", "onedrive_file"):
        types = sorted(f.file_type for f in FILES if f.kind == kind)
        assert types == sorted(FILE_TYPE_CYCLE * 2)


def test_names_are_safe_in_a_graph_path():
    for f in FILES:
        assert re.fullmatch(r"rp-canary-\d\d\.(pdf|docx|xlsx|txt|png)", f.name)
