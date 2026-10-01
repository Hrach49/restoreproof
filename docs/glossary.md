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
Its expected values come from the backup's own listing (Veeam's browse of the restore point),
not from Graph: the Worker app may read only the restore targets (`docs/decisions.md`
2026-10-01, W3.1). A random mail is expected by its header fields (expected kind `fields`), a
random file by its name and listed size (`metadata`); neither has a content hash before the
restore. Random items prove the test covers real content and not just our own planted
evidence.

**Expected kind.** How one sampled item's expectation was obtained, recorded with it before
anything is compared (`rp::verification::ExpectedKind`, `docs/verification.md`): `manifest`
for a canary (the manifest's values and content hash), `fields` for a random mail (subject,
sender name, sent and received time as the backup lists them), `metadata` for a random file
(its name, and the backup's size unless it is an Office package). Every item has exactly one;
the result records it per item and counts each, and the report (W3.3/W4.1) shows them, so it
never claims more than was checked.

**Sample.** The set of items one run selects and tests — canaries plus random items, chosen
from a seed and a rotation cursor so the selection is reproducible. Per type, half the sample
size (rounded up) are canaries, taken in manifest order from the cursor on so each is tested in
turn; the other half are drawn from real data in the restore point with a seed derived from
the run ID (`docs/decisions.md` 2026-09-30, W2.6).

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

**Explore session.** A Veeam session that opens one restore point for browsing
(`POST /v8/Organizations/{id}/explore` with the point's exact `backupTime`, one per item
type; `docs/api/veeam-notes.md`): the Worker lists mailboxes,
sites, OneDrives and items in it and sends restores from it. It writes nothing and is stopped
when the run is done.

**Restore session.** The Veeam session a restore POST starts, whose ID comes back as
`sessionId`. The restore runs in it asynchronously; its state, result, statistics and events
say how the restore went (`docs/api/veeam-restore-flow.md`). Not the explore session it was
started from.

**Veeam says restored.** A restore session that stopped with result `Success` and reported
every sent item as restored. Veeam's word only: it maps to restore status `succeeded`, and
whether the item is really there and matches is decided by reading it back through Graph.

**Duplicate-restore check.** After a restore POST whose answer is lost (transport error,
5xx, no `sessionId`), looking in `GET /v8/RestoreSessions` for the session it may have
started, instead of sending it again. Exactly one match is adopted; none or several gives no
verdict (`error`), and the POST is not resent (`docs/decisions.md` 2026-09-28, W2.4).

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

Three different secrets, often confused, then the words for the Worker's Graph sign-in:

**Install token.** A one-time, 7-day, single-use enrolment secret (32 random bytes,
base64url) created by `manage.py create-worker-token` and printed once. The MSP types it into
the Worker's setup wizard; the Worker calls `register`, receives its API token, and then
deletes the install token. The Cloud stores only its SHA-256 hash.

**API token.** The Worker's long-lived credential for calling the Cloud (32 random bytes),
issued at registration and kept in the vault. The Cloud stores only its SHA-256 hash and
compares in constant time; setting `revoked_at` blocks the worker immediately. Never logged.

**Veeam / Graph tokens.** Access tokens (and, for Veeam, refresh tokens) for the systems
under test. Distinct from both of the above: they let the Worker read and restore; the API
token lets it report. They are never stored: the Worker keeps them in memory and gets new
ones by signing in again. What they are got with is a secret: Veeam's account password, and
for Graph the Worker app's certificate.

**Client assertion.** How the Worker signs in to Entra for its Graph token without a client
secret (W2.1): a short-lived JWT (5 minutes) that says "I am the Worker app, asking this
tenant's token endpoint", signed with the private key of the app's certificate. Entra checks
the signature against the public certificate uploaded to the app. A new one, with a new
`jti`, goes with every token request and is never reused; while valid it is a credential, so
it is never logged. Signed with PS256 (RSA-PSS, SHA-256). See `docs/decisions.md`,
2026-09-28.

**`x5t#S256`.** The client assertion's header field naming the certificate that signed it:
the base64url SHA-256 of the certificate's DER encoding. Entra finds the app's key by it.
Not the thumbprint Windows and the Entra portal show, which is the SHA-1 in hex (`x5t` is its
base64url form); the Worker's error messages name the certificate by that SHA-1.

**Grant (in Worker messages).** A permission a Graph call relies on, in words a customer can
act on, such as `Sites.Selected read on the test site`. Graph's 403 doesn't say what is
missing, so every call the Worker makes names its grant, and a refusal's message quotes it
(`docs/security/graph-permissions.md`, "What a refusal says"). Not a Graph term.
