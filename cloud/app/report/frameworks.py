"""The Framework mapping section's rows (C6.4, docs/decisions.md 2026-10-12,
"C6.4", point 3): the four controls by identifier and name, which are the
controls' own words and claim nothing. The two sentences per control, what
this evidence demonstrates and what it does not cover, are C6.7's, written
and reviewed by an outside reader; until then both are `None` and the report
says so in `PENDING`."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    identifier: str
    name: str
    demonstrates: str | None
    not_covered: str | None


CONTROLS: tuple[Control, ...] = (
    Control("ISO/IEC 27001:2022 A.8.13", "Information backup", None, None),
    Control("SOC 2 Availability A1.2, A1.3", "Recovery procedures tested", None, None),
    Control("HIPAA 45 CFR 164.308(a)(7)(ii)(D)", "Testing and revision procedures", None, None),
    Control(
        "DORA Regulation (EU) 2022/2554 Article 12",
        "Backup policies and procedures, restoration and recovery procedures and methods",
        None,
        None,
    ),
)

PENDING = (
    "The sentences relating this evidence to each control are being written and reviewed by an "
    "outside reader (C6.7) and are not part of this report yet."
)
