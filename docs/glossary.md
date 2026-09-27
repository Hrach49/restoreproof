# Glossary

The words RestoreProof uses, and what they mean here. Where a word is also a Veeam or
Microsoft term, this file says what *we* mean by it.

## Backup and restore

**Restore point.** One Veeam backup session's worth of data for an organisation: the state of
the backed-up mailboxes, sites and OneDrives as of the moment that backup ran. A test always
names the restore point it used, because "the data restores" is only true of a point in time.

**Restore target.** The place a restored item is written. In RestoreProof it is always the
`restoretest` mailbox, or the `RestoreTarget` SharePoint library or OneDrive folder — never the
original location, and never any other. Enforced per item by `TargetGuard`. (The `RestoreTest`
library and OneDrive folder hold the canary files and are not restore targets.)

**Canary item.** An item we seeded ourselves and whose expected content we recorded in
`lab/seed-manifest.json` (mails `RP-CANARY-0001`…`0020`, files `rp-canary-01.pdf`…
`rp-canary-20.png`, whose types cycle pdf, docx, xlsx, txt, png; see `lab/README.md`). Because the manifest holds the expected subject, sender, date and
SHA-256, a canary can be checked against a known-correct answer rather than against the live
tenant. Half of every sample is canaries, rotated so all of them get tested over a few runs.

**Random item.** An item picked from the customer's real backed-up data, not seeded by us.
Its expected values come from reading the live item through Microsoft Graph. Random items
prove the test covers real content and not just our own planted evidence.

**Sample.** The set of items one run selects and tests — canaries plus random items, chosen
from a seed so the selection is reproducible.

**Client.** One of an MSP's customers: one Microsoft 365 tenant, which Veeam backs up as one
organisation. One Veeam server may back up many clients; one Worker talks to it with one set
of credentials and names the client in each call.

**Client reference (`client_ref`).** How a connector call names the client: the name the
backup product knows it by. For Veeam, the organisation's name as in `veeam_org_name` (e.g.
`RestoreProofLab.onmicrosoft.com`), matched ASCII case-insensitively; the connector looks up
Veeam's organisation ID itself.

**Connector.** The Worker's adapter to one backup product (`rp::connector::IConnector`,
W1.7): it lists a client's restore points and restores a sample into the restore targets.
Registered by name; the only one is `veeam_m365` (Veeam Backup for Microsoft 365). Nothing
past the interface sees the product's own types or errors.

**Restore status.** A connector's report of how the restore itself went: `succeeded`,
`partial`, `failed` or `not_run` (`rp::connector::RestoreStatus`). Not a run outcome: `pass`,
`fail` and `error` are decided afterwards from it and the Graph comparison (W3.3).

## Verification levels

How deeply a backup has been verified. RestoreProof's own ladder, used in reports so the
claim is never bigger than the test. Stage 1 covers levels 1, 2 and 3, and level 4 partially
(files are opened and read through Microsoft Graph).

| Level | Name | What it proves |
|---|---|---|
| 0 | Job success | The backup job reported success. Nothing about the data. |
| 1 | Catalogue presence | The restore point exists and the expected items are listed in it. |
| 2 | Restorability | An item can actually be restored out of the backup to a location. |
| 3 | Content integrity | The restored item matches its expected content (hashes and fields). |
| 4 | Usability | The restored item opens and is readable in its application. |
| 5 | Service recovery | A whole mailbox, site or drive is restored and the service works. |
| 6 | Business continuity | People do real work against the restored data; RTO/RPO measured. |

These level numbers are ours. If a customer's framework uses a different ladder, map to it in
the report rather than renumbering this table.

## Run outcomes

The three statuses, and the line between them. The full decision table lives in
[verification.md](verification.md).

**`pass`.** The restore ran and 100% of sampled items match their expected values. Nothing
less is a pass: no "passed with warnings".

**`fail`.** The backup did not deliver the data. The restore failed, or an item was missing,
or an item's content did not match. A `fail` is a statement about the customer's backup — it
is the product working, not the product broken.

**`error`.** The test itself could not run, so nothing was learned about the backup: Veeam
unreachable, Graph authentication or permission refused, a `TargetGuard` violation, the
Cloud unreachable at dispatch. **Infrastructure problems are never reported as `fail`**,
because a `fail` accuses the customer's backup of losing data.

## Evidence

**Evidence bundle.** What one run leaves behind and uploads: the result JSON, plus
`veeam-session.log` and `items.csv` (the per-item comparison with hashes). Canonicalised
(sorted keys, no whitespace, UTF-8, ISO-8601 UTC), hashed as `bundle_sha256` with
`signature` and `tsa_token` removed, Ed25519-signed and RFC 3161-timestamped. It is the
artefact an auditor can verify offline with `shared/tools/verify_bundle.py`, without
trusting us. Failed runs are never edited or re-signed.

**Signing key.** The Ed25519 key pair generated on the Worker at setup. The private key never
leaves the DPAPI vault; the public key is registered with the Cloud so bundles from that
worker can be verified. Signing proves *which worker* produced a bundle; the RFC 3161
timestamp proves *when* it existed.

**RFC 3161 timestamp token (`tsa_token`).** A third-party Time Stamping Authority's signature
over the bundle hash, proving the bundle existed at that time — not merely that our server
says so.

## Tokens

Three different secrets, often confused:

**Install token.** A one-time, 7-day, single-use enrolment secret (32 random bytes,
base64url) created by `manage.py create-worker-token` and printed once. The MSP types it into
the Worker's setup wizard; the Worker calls `register`, receives its API token, and then
deletes the install token. The Cloud stores only its SHA-256 hash.

**API token.** The Worker's long-lived credential for calling the Cloud (32 random bytes),
issued at registration and kept in the vault. The Cloud stores only its SHA-256 hash and
compares in constant time; setting `revoked_at` blocks the worker immediately. Never logged.

**Veeam / Graph tokens.** Access and refresh tokens for the systems under test, also vault-
only. Distinct from both of the above: they let the Worker read and restore; the API token
lets it report.
