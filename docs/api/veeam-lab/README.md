# Veeam REST evidence (L1.6, W1.0, W1.4)

Raw, scrubbed request/response pairs from the lab Veeam server (VB365 8.6, REST v8), recorded
on 2026-09-25/26: L1.6 and W1.0 for `docs/api/veeam-feasibility.md`, W1.4 for
`docs/api/veeam-notes.md` (made by the scripts in `docs/api/veeam-m365/`). W1.5 turns them into
`worker/tests/fixtures/veeam/` fixtures (the list is in `veeam-notes.md` §9).

## Format

One JSON file per call:

```jsonc
{
  "note": "who called what, and why",
  "captured_utc": "2026-09-26T14:24:04.014Z",
  "duration_ms": 1204,
  "request":  { "method": "POST", "path": "/v8/token", "body": { … } | "form=…" | null },
  "response": { "status": 200, "content_type": "…", "headers": { … }, "body": { … } | "text" | null }
}
```

`response.body` is `"<N bytes written to file>"` for downloads (MSG, PDF, DOCX); the files
themselves are not kept. `l1.6-operator-admin-sweep.json` and
`w1.0-b-operator-orphan-session-probe.json` are summaries of several calls.

## Scrubbing

Replaced with `"[REDACTED]"` before writing:

- the values of `access_token`, `refresh_token`, `id_token`, `password`, `userPassword`,
  `assertion`, `applicationCertificate`, `applicationCertificatePassword`, `client_secret`,
  `token`, `device_code`, in JSON and in form bodies;
- anything shaped like a JWT, and bearer values.

`Set-Cookie` and `Authorization` headers are dropped. W1.0's bearer rule also caught the
`WWW-Authenticate: Bearer error="invalid_token"` header (it reads `Bearer [REDACTED]"invalid_token"`
in `w1.0-a-restart-admin-access`); W1.4's rule only replaces token-length values, so the header
is intact in the `w1.4-auth-*` files. Every file was then checked against the
literal values of every secret used in the session (passwords, tokens, the certificate), and
for JWT and PFX patterns: no matches. Account names, object IDs and item names of the lab
tenant are not secret (`lab/tenant.md`) and are kept.

## Names

`<task>-<check>-<what>.json`: `l1.6-…` for the two accounts, `w1.0-a-…` refresh tokens,
`w1.0-b-…` operator scope, `w1.0-c-<mail|sp|od>-<cert|user|none>-…` admin restore bodies
(`-explore`, `-restore`, `-session`, `-statistics`, `-events`; `none` = no credentials,
refused with 400), `w1.0-d-…` export. Some
first attempts are kept under a suffix that names the outcome
(`-no-folder-400`, `-no-casserver-400`, `-antiforgery-500`, `-after-restart`).

Two operator grants show why a flag matters:

- `w1.0-a-operator-token` (14:20) was made without `disable_antiforgery_token`, and its
  refresh failed;
- `w1.0-a-operator-token-no-antiforgery` (14:24) is chain A, whose t0 refresh is
  `w1.0-a-operator-refresh-t0`.

The 48 h and 7-day refreshes will add `w1.0-a-operator-refresh-48h` and `-7d`.

W1.4 files are `w1.4-<area>-<what>.json`, with `<area>` one of `auth`, `org`, `rp` (restore
points), `session`, `mail`, `sp`, `od` and `sweep`. A suffix names an error case
(`-401`, `-404`, `-409`, `-400`, `-unknown`, `-bad-…`), and `w1.4-session-explore-<case>` is one
`dateTime` case of `veeam-notes.md` §4.2. They are written with `System.Text.Json`, so values
(timestamps especially) are byte-for-byte what Veeam sent. Before commit they were audited with
`docs/api/veeam-m365/audit-evidence.ps1` against every password and token value used, and for
JWT, bearer, PFX and PEM patterns: no hits. The W1.4 run left no explore session open
(`w1.4-sweep-list`).
