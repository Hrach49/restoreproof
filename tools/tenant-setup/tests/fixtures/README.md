# The tenant setup's test fixtures (W7.0)

- `lab/`: the lab tenant's answers to Graph and Exchange Online, recorded read-only by
  `../record/Record-TenantAnswers.ps1` on 2026-10-16 (each file says when, in its `source`),
  while the lab held the Worker app and its three targets. The admin's address and name are
  replaced by "admin", in plain text and inside base64 IDs (SharePoint's permission IDs are a
  claim login name in base64url). No secret: a certificate credential comes back without its key.
  Held by `../test_recorded_lab.py`.

The tests' other tenants are built in code (`../fake_tenant.py`), not kept here. This folder is
in `worker/tools/fixture_secret_scan.py`'s trees.