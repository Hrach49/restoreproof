"""The W7.0 lab harnesses (docs/api/veeam-lab/w7.0-harness/, decision point 11 (A)): they parse,
the teardown deletes only the lab's Worker app, its grants on the site, its Exchange objects and
the two empty RestoreTarget targets, each found by its lab ID and checked by name first, never a
canary, and it asks before it deletes."""

import re

import pytest

from pwsh import REPO_DIR, ps_string, run_json

HARNESS = REPO_DIR / "docs" / "api" / "veeam-lab" / "w7.0-harness"
TEARDOWN = HARNESS / "w70-teardown.ps1"
LIVE = HARNESS / "w70-live.ps1"
CANARIES = (
    "7eb0f08a-f57b-418c-8ca6-f2ab81297666",  # the RestoreTest (canary) library
    "b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omK8LB-e_WMQYym8quBKXZm",  # its drive
    "01ZK75LGF7FPAIWTU5MFGIMX6YUFEV7ZC4",  # alice's /RestoreTest folder
)


@pytest.mark.parametrize("path", [TEARDOWN, LIVE], ids=lambda p: p.name)
def test_it_parses(path):
    errors = run_json(f"""
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile({ps_string(path)}, [ref]$null, [ref]$errors)
        ,@($errors | ForEach-Object {{ "$_" }})
    """)
    assert errors == []


def test_the_teardown_deletes_only_what_it_names():
    text = TEARDOWN.read_text(encoding="utf-8")
    deletes = re.findall(r"Remove-Graph \"(.*?)\"; Say", text)
    assert deletes == [
        "sites/$SiteId/permissions/$([Uri]::EscapeDataString(\"$($grant.id)\"))",
        "sites/$SiteId/lists/$RestoreTargetListId",
        "drives/$OneDriveDriveId/items/$OneDriveTargetFolderId",
        "applications/$($app.id)",
        "directory/deletedItems/$($app.id)",
    ]
    assert re.findall(r"\b(Remove-\w+)", text).count("Remove-Graph") == 6  # the function and its five uses
    exchange = set(re.findall(r"\b(Remove-(?:Management\w+|ServicePrincipal))\b", text))
    assert exchange == {"Remove-ManagementRoleAssignment", "Remove-ManagementScope", "Remove-ServicePrincipal"}
    assert "-Method DELETE" in text and text.count("-Method DELETE") == 1
    assert not re.search(r"-Method (POST|PATCH|PUT)", text)
    for canary in CANARIES:
        assert canary not in text


def test_the_teardown_checks_each_target_by_name_and_asks_first():
    text = TEARDOWN.read_text(encoding="utf-8")
    first_delete = text.index("Remove-ManagementRoleAssignment -Identity")
    for check in ("-cne 'RestoreProof Worker'", "is not the $Name library", "is not empty", "is not alice's /$Name folder",
                  "Read-Host 'type remove to remove them'", "if ($WhatIf)"):
        assert check in text and text.index(check) < first_delete, check


def test_the_live_harness_copies_evidence_only_when_every_step_held():
    text = LIVE.read_text(encoding="utf-8")
    assert text.index("if (-not $ok)") < text.index("Save-W48Evidence 'w7.0-done-when.txt'")
    assert "-NoCopy" in text  # the W5.1 harness never overwrites its own evidence here
    assert "(?m)^changes: 0$" in text and "byte for byte" in text


def test_the_teardown_takes_the_labs_ids_from_its_profile_not_its_text():
    """The setup script makes new IDs at every run on a torn-down lab: the teardown reads them
    from the lab profile w70-live.ps1 wrote, and still checks each one by name before it goes."""
    text = TEARDOWN.read_text(encoding="utf-8")
    assert "lab-profile.json" in text
    for key in ("graph_client_id", "test_library_id", "test_onedrive_drive_id", "test_onedrive_folder_id", "test_site_id", "graph_tenant_id"):
        assert f"'{key}'" in text, key
    assert 'Get-Graph "drives/$LibraryDriveId/list' in text
    # The first lab app's IDs, removed on 2026-10-16, are in it no more.
    for old in ("737da5ef-baf2-4198-b009-e160d8ca77c9", "ffec069d-65e4-4c3a-9da2-ac086cf9dafa", "01ZK75LGDGB6QOO3MGNFGYOY6C6VBDG5OH"):
        assert old not in text, old


def test_the_live_harness_waits_for_the_mail_role_before_the_run():
    """Exchange applies a new mail role in 30 minutes to 2 hours: the W5.1 harness starts only
    once the Worker's graph list reads all three targets, asked every 5 minutes for 2 hours."""
    text = LIVE.read_text(encoding="utf-8")
    wait = text.index("graph list --config $script:LabConfig")
    assert wait < text.index("& pwsh -NoProfile -File $W51 -NoCopy")
    assert "Start-Sleep -Seconds 300" in text and "$attempt -le 24" in text
