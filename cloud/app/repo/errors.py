"""A repo's own refusal: the key it is about and a fixed reason, never a value.

`constraint_refusal` (C5.10; docs/decisions.md 2026-10-11, "C5.10 and C5.9",
point 2) words the database's own refusals the same way: an `IntegrityError`
whose driver error names a constraint of `CONSTRAINT_WORDS` becomes a
`RepoError` from that table alone (the name asyncpg gives as
`constraint_name`, never read out of the message, whose DETAIL quotes the row), so a CLI line and a future admin route's 409 are one
text and neither quotes the row. A name the table lacks answers `None`, for
the caller to re-raise.
"""

from __future__ import annotations

from sqlalchemy.exc import IntegrityError


class RepoError(Exception):
    def __init__(self, key: str, reason: str) -> None:
        super().__init__(f"{key}: {reason}")
        self.key = key
        self.reason = reason


# By constraint name, as the models and migration 0001 name them: the key
# the refusal is about and a fixed reason. Registration's words for the key
# are repeated here so the two agree (app/auth/registration.py).
CONSTRAINT_WORDS: dict[str, tuple[str, str]] = {
    "uq_client_msp_id_tenant_id": ("tenant_id", "already a client of this MSP"),
    "uq_connector_worker_id_client_id": ("client_id", "already a connector of this Worker"),
    "uq_worker_key_id": ("public_key_pem", "already registered"),
    "ck_test_plan_sample_mail_range": ("sample_mail", "not 0 to 100"),
    "ck_test_plan_sample_sp_range": ("sample_sp", "not 0 to 100"),
    "ck_test_plan_sample_od_range": ("sample_od", "not 0 to 100"),
    "ck_test_plan_sample_not_empty": ("sample sizes", "all 0"),
    # C6.8: the canary cursor, the Worker's job rule (PlanRepo.create holds it first).
    "ck_test_plan_canary_cursor": ("canary_cursor", "not 0 to 999999"),
    "fk_test_plan_msp_id_connector_id_client_id_connector": ("connector_id", "not the client's connector"),
    "fk_test_plan_msp_id_client_id_client": ("client_id", "no such client"),
    "ck_msp_retention_days_positive": ("retention_days", "not positive"),
    "uq_test_run_msp_id_plan_id_scheduled_for": ("scheduled_for", "a run exists for the period"),
    # C6.1: one address across the Cloud, whatever its case; the role's list.
    "uq_user_email_lower": ("email", "already a user of this Cloud"),
    "ck_user_role": ("role", "not admin or member"),
    # C6.4: one final report per client and period; a key written once.
    "uq_report_final_period": ("period", "already reported"),
    "uq_report_storage_key": ("storage_key", "already used"),
    # The MSP's own key, on every row a command inserts.
    "fk_user_msp_id_msp": ("msp_id", "no such MSP"),
    "fk_client_msp_id_msp": ("msp_id", "no such MSP"),
    "fk_install_token_msp_id_msp": ("msp_id", "no such MSP"),
    "fk_worker_msp_id_msp": ("msp_id", "no such MSP"),
    "fk_connector_msp_id_msp": ("msp_id", "no such MSP"),
    "fk_test_plan_msp_id_msp": ("msp_id", "no such MSP"),
    "fk_test_run_msp_id_msp": ("msp_id", "no such MSP"),
}

def constraint_refusal(error: IntegrityError) -> RepoError | None:
    """The `RepoError` for the constraint the error names, or `None`."""
    # SQLAlchemy raises its own error from asyncpg's, which holds the name.
    name = getattr(error.orig.__cause__, "constraint_name", None)
    words = CONSTRAINT_WORDS.get(name) if isinstance(name, str) else None
    return None if words is None else RepoError(*words)
