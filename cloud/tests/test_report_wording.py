"""The reviewed wording of the report (C6.5, C6.7; docs/decisions.md
2026-10-13, "C6.6, C6.5 and C6.7", points 4 and 5). The fixed sentences of
the Summary, the Method and the Framework mapping are listed here verbatim
and held to the template and to `app/report/frameworks.py`, so a reviewed
sentence cannot change without this list changing in the same commit. The
C6.5 reviewer's and the C6.7 reader's comments, and what changed for them,
are the entries "C6.5 review" and "C6.7 reading" in docs/decisions.md.
"""

from __future__ import annotations

import pytest

from app.report import frameworks, render

# --- The Summary (C6.5): the three meanings, the recovery-times sentence, the disaster-recovery sentence ---

SUMMARY = (
    "A <span class=\"state pass\">pass</span> means every sampled item was restored from the backup and matched what was expected.",
    "A <span class=\"state fail\">fail</span> means an item was missing or did not match.",
    "An <span class=\"state error\">error</span> means the test itself could not run (the backup product, the tenant or the Worker was not available); it says nothing about the backup.",
    "The recovery times and the restore points above are those of the tests that passed or failed.",
    # The C6.4 review's finding 6 left the issue's "were restored and verified" (untrue of a month with a failure); C6.5's reviewer may say otherwise.
    "This report does not test full disaster recovery. It records what each test listed here found for the items it sampled, on the dates shown.",
    "The period is not over: this interim report covers the tests that have ended by",
    "The month's final report replaces nothing; it is made when the month has ended.",
    # The C6.6 review's finding 1: a result that reached the Cloud after its month had its report.
    "Tests that ended before this period and whose results arrived after that period had closed, counted here:",
)

# --- The Method (C6.5): the sampling, the targets, the comparison, the cleanup line, the levels line ---

METHOD = (
    "from one restore point of the backup.",
    # The W6.3 review's finding 3: canaries are an opt-in (W6.2) and a random file is compared with the
    # backup's own copy when the backup gave one (W6.3).
    "The items of a test are a sample chosen at random from the backup's own listing; a test set up with canary items, seeded in the tenant for this purpose and whose content is known in advance, samples some of those too.",
    "A test restores each item into a restore target set aside for testing (the <code>restoretest</code> mailbox, the <code>RestoreTarget</code> library or the <code>RestoreTarget</code> OneDrive folder), reads it back through Microsoft Graph, compares it, and removes it from the target afterwards.",
    "A canary is compared by the SHA-256 of its content. A random file is compared by the SHA-256 of the copy the backup gave of it before the restore (for a Word or Excel document, of the document's content, since the restore rewrites the rest of the file), or, when the backup gave no copy, by its name and, unless it is an Office document, its size. A random mail is compared by its subject and received time, and by its sender's name when the backup lists one.",
    "of this period the removal from the restore target did not complete.",
    "Verification levels covered: 1, 2, 3",
    "; level 4 partially (files opened and read via Microsoft Graph)",
    "No test of this period reached the comparison, so no verification level was covered.",
    "No test of a plan has a result in this period.",
)

# --- The cap's line and the Integrity sentence ---

OTHER = (
    "more tests of this period are not listed here; the Cloud's pages hold every one.",
    "A file cannot contain its own hash. The content hash above is the SHA-256 of this report rendered without it; the file hash, which the Cloud stores beside this report and which you can check yourself, is the SHA-256 of the file you are reading.",
)

# --- The Framework mapping (C6.7): the sentence above the table and the eight sentences, by control ---

ABOUT = (
    "For each control, the left sentence says what a test marked pass in this report shows, and the right sentence "
    "what this report does not look at. A test marked fail or error shows nothing for the control; it is listed under "
    "Failures. The table describes this evidence; it is not an assessment of the control."
)

# The C6.6 review's finding 3: in place of a control's first sentence when no test of the report passed.
NO_PASS = "No test in this report is marked pass, so it shows nothing for this control."

MAPPING = {
    "ISO/IEC 27001:2022 A.8.13": (
        "Information backup",
        "On the dates listed, a sample of items was restored from the backup copy into a test location, read back and compared with what was expected, and the outcome of each test is recorded here.",
        "Whether every item in the backup can be restored, whether the backup policy is followed, how often backups are taken, or where and for how long the copies are kept.",
    ),
    "SOC 2 (2017 TSC) Availability A1.2 and A1.3": (
        "A1.2: … data back-up processes, and recovery infrastructure to meet its objectives; A1.3: the entity tests recovery plan procedures supporting system recovery",
        "On the dates listed, the restore of a sample of backed-up items was tested and what each test found is recorded here; this is a record of restore testing of items, not of a recovery plan exercise.",
        "Recovery of a system or a service, the recovery plan and its exercise, recovery time or recovery point objectives, and whether the backup process meets the entity's objectives.",
    ),
    "HIPAA 45 CFR 164.308(a)(7)(ii)(D)": (
        "Testing and revision procedures",
        "On the dates listed, the restore of a sample of items from the backup was tested and the outcome recorded, which is one input to the periodic testing of a contingency plan.",
        "The contingency plan itself, its revision, its other parts (data backup plan, disaster recovery plan, emergency mode operation plan, criticality analysis), and whether the sampled items hold protected health information.",
    ),
    "DORA, Regulation (EU) 2022/2554, Article 12": (
        "Backup policies and procedures, restoration and recovery procedures and methods",
        "On the dates listed, the restoration of a sample of items from the backup was tested, with each test's outcome and the time the restore took recorded here.",
        "The backup policy, the restoration and recovery procedures and methods as a whole, the recovery of ICT systems, the testing of those procedures beyond the sampled items, and any register, report or notification the regulation asks for.",
    ),
}

# Words that claim more than a restore test shows: never in a reviewed sentence.
OVERCLAIMS = ("compliant", "complies", "compliance", "meets the control", "satisf", "audit passed", "passes the audit", "verified", "proves", "proof", "guarantee", "certif", "fully recoverable", "accepted by insurers")


def template() -> str:
    return (render.REPORT_DIR / render.TEMPLATE).read_text(encoding="utf-8")


@pytest.mark.parametrize("sentence", SUMMARY + METHOD + OTHER)
def test_each_reviewed_sentence_of_the_template_is_in_it_verbatim(sentence):
    assert sentence in template()


def test_the_mapping_is_the_reviewed_text_verbatim_control_by_control():
    assert [c.identifier for c in frameworks.CONTROLS] == list(MAPPING)
    for control in frameworks.CONTROLS:
        assert (control.name, control.demonstrates, control.not_covered) == MAPPING[control.identifier], control.identifier
    assert frameworks.ABOUT == ABOUT
    assert frameworks.NO_PASS == NO_PASS
    assert "control.demonstrates if data.passed else data.no_pass" in template()


@pytest.mark.parametrize("sentence", SUMMARY + METHOD + OTHER + (ABOUT, NO_PASS) + tuple(s for triple in MAPPING.values() for s in triple))
def test_no_reviewed_sentence_claims_more_than_a_restore_test_shows(sentence):
    lowered = sentence.lower()
    for word in OVERCLAIMS:
        assert word not in lowered, (word, sentence)


def test_every_mapping_sentence_names_the_dates_and_the_sample_and_nothing_met():
    """Each "demonstrates" sentence is of the form the issue asks for: on the
    dates listed, sampled items were restored and what was found recorded."""
    for control in frameworks.CONTROLS:
        assert control.demonstrates.startswith("On the dates listed, ")
        assert "sample" in control.demonstrates and "recorded" in control.demonstrates
        assert control.not_covered[0].isupper() and control.not_covered.endswith(".")
        assert control.demonstrates.endswith(".")
