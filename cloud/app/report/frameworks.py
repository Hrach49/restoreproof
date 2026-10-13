"""The Framework mapping section's rows (C6.4, docs/decisions.md 2026-10-12,
"C6.4", point 3; C6.7, docs/decisions.md 2026-10-13, "C6.6, C6.5 and C6.7",
point 4): the four controls by identifier and name, which are the controls'
own words and claim nothing (the SOC 2 points of focus have no title, so
their row is named by the criteria's own words shortened with an ellipsis,
never a gloss), and for each the two sentences the issue asks for: what a
test marked pass in a report shows, and what the report does not look at.
Each claims only what a `pass` run shows (sampled items restored into a test
location, read back and compared, on dates, with the outcome recorded), never
a control met, an audit passed or a regulation complied with.

The sentences are held verbatim by tests/test_report_wording.py, the
reviewed wording (C6.5, C6.7): a change here is a change there in the same
commit, and the outside reader's comments are recorded in docs/decisions.md.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    identifier: str
    name: str
    demonstrates: str
    not_covered: str


CONTROLS: tuple[Control, ...] = (
    Control(
        "ISO/IEC 27001:2022 A.8.13",
        "Information backup",
        "On the dates listed, a sample of items was restored from the backup copy into a test location, read back and "
        "compared with what was expected, and the outcome of each test is recorded here.",
        "Whether every item in the backup can be restored, whether the backup policy is followed, how often backups are "
        "taken, or where and for how long the copies are kept.",
    ),
    Control(
        "SOC 2 (2017 TSC) Availability A1.2 and A1.3",
        "A1.2: … data back-up processes, and recovery infrastructure to meet its objectives; "
        "A1.3: the entity tests recovery plan procedures supporting system recovery",
        "On the dates listed, the restore of a sample of backed-up items was tested and what each test found is recorded "
        "here; this is a record of restore testing of items, not of a recovery plan exercise.",
        "Recovery of a system or a service, the recovery plan and its exercise, recovery time or recovery point "
        "objectives, and whether the backup process meets the entity's objectives.",
    ),
    Control(
        "HIPAA 45 CFR 164.308(a)(7)(ii)(D)",
        "Testing and revision procedures",
        "On the dates listed, the restore of a sample of items from the backup was tested and the outcome recorded, "
        "which is one input to the periodic testing of a contingency plan.",
        "The contingency plan itself, its revision, its other parts (data backup plan, disaster recovery plan, emergency "
        "mode operation plan, criticality analysis), and whether the sampled items hold protected health information.",
    ),
    Control(
        "DORA, Regulation (EU) 2022/2554, Article 12",
        "Backup policies and procedures, restoration and recovery procedures and methods",
        "On the dates listed, the restoration of a sample of items from the backup was tested, with each test's outcome "
        "and the time the restore took recorded here.",
        "The backup policy, the restoration and recovery procedures and methods as a whole, the recovery of ICT systems, "
        "the testing of those procedures beyond the sampled items, and any register, report or notification the "
        "regulation asks for.",
    ),
)

# Above the table: what the table is, and what a fail or error means for it.
ABOUT = (
    "For each control, the left sentence says what a test marked pass in this report shows, and the right sentence "
    "what this report does not look at. A test marked fail or error shows nothing for the control; it is listed under "
    "Failures. The table describes this evidence; it is not an assessment of the control."
)
