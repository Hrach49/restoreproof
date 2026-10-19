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

**Document export.** Veeam's REST call that hands out a backed-up SharePoint or OneDrive
document's bytes straight from the backup repository, inside an explore session
(`POST …/Documents/{documentId}/save {"asZip": false}`, `application/octet-stream`). It names
no Microsoft 365 credential and writes nothing in the tenant. W6.1 (`docs/decisions.md`
2026-10-14) showed what it gives in admin mode against a restored copy. Since W6.3 every run
asks for it: the connector exports each random file with a content rule inside its own explore
session, after every item is found and before the first restore request, one attempt each and
never resent, and the Worker keeps the bytes' hash alone (the `backup_content` expected kind). A
file the export can't give is checked by name and size as before, with the export's word.

**Cleaner.** The Worker code that empties the three restore targets before and after each run
(`rp::graph::Cleaner`, W3.4; the clean after is skipped while the run's restore may still be
running in Veeam, W4.8): every mail in the `restoretest` Inbox (permanently deleted, never
through Deleted Items) and every plain file in the RestoreTarget library and alice's
`/RestoreTarget` folder (to the site recycle bin). It is the only Worker code that deletes in
the tenant: it checks each target with the guard's own checks, deletes only what it has just
listed there, and leaves folders and anything else that isn't a plain file for the owner
(*skipped*). Its result never changes a run's status, except that a guard refusal before the
run stops it (`error` `target_guard`). Only one run at a time uses the targets: `rpworker
restore` holds a machine-wide mutex while it runs, so one run's cleanup can't delete another's
copies before they are checked.

**Canary item.** An item we seeded ourselves and whose expected content we recorded in
`lab/seed-manifest.json` (mails `RP-CANARY-0001`…`0020`, files `rp-canary-01.pdf`…
`rp-canary-20.png`, whose types cycle pdf, docx, xlsx, txt, png; see `lab/README.md`). Because the manifest holds the expected subject, sender, date and
SHA-256, a canary can be checked against a known-correct answer rather than against the live
tenant. Canaries are an opt-in since W6.2 (`docs/decisions.md` 2026-10-14): a job
with a `canary_cursor` (or a command line with `--canary-cursor` or `--manifest`) has them, and
the manifest is then the Worker's `canaries\<tenant>.json`; a run with them takes half of each
type's sample from them, rotated so all of them get tested over a few runs. A run without them
plants nothing and tests the client's own data alone. On the Cloud the opt-in is a **plan's**
(C6.8, `docs/decisions.md` 2026-10-15: `manage.py create-plan --canaries`), and the report
names canaries only in a month whose tests sampled one and never counts them among the
client's own files.

**Canary cursor.** Where a run starts in each type's list of canaries: three numbers (mail,
SharePoint, OneDrive), each below that type's canary count in the tenant's manifest. The Cloud
keeps one per plan opted in (`test_plan.canary_cursor_mail`, `_sp`, `_od`; none for a plan
without canaries), starts it at `0,0,0`, sends it as the job's `canary_cursor`, and after each
`pass` or `fail` with canaries moves it to the run's signed `cursor_next`, which the Worker
computes as `(cursor + canaries taken) mod count`; only while it is still the cursor the run was
sent with, so two runs sent with one cursor move it once. An `error` leaves it, so the next run
takes the same canaries.

**Random item.** An item picked from the customer's real backed-up data, not seeded by us.
Its expected values come from the backup's own listing (Veeam's browse of the restore point),
not from Graph: the Worker app may read only the restore targets (`docs/decisions.md`
2026-10-01, W3.1). A random mail is expected by its header fields (expected kind `fields`). A
random file is expected by its content when the backup exported it before the restore
(`backup_content`, W6.3: the bytes' SHA-256, or `office-v1` for a docx or xlsx), else by its
name and listed size (`metadata`). Random items prove the test covers real content and not just
our own planted evidence.

**Expected kind.** How one sampled item's expectation was obtained, recorded with it before
anything is compared (`rp::verification::ExpectedKind`, `docs/verification.md`): `manifest`
for a canary (the manifest's values and content hash), `fields` for a random mail (subject,
sender name, sent and received time as the backup lists them), `backup_content` for a random
file the backup exported before the restore (W6.3: its name and the hash of the exported bytes
by its rule, `bytes` or `office-v1`), `metadata` for any other random file (its name, and the
backup's size unless it is an Office package). Every item has exactly one;
the result records it per item and counts each, and the report (W3.3/W4.1) shows them, so it
never claims more than was checked.

**Sample.** The set of items one run selects and tests, chosen from a seed (and, with canaries,
a rotation cursor) so the selection is reproducible. Without canaries, the default since W6.2
(`docs/decisions.md` 2026-10-14), the whole sample of each type is drawn from real data in the
restore point with a seed derived from the run ID. With canaries, half of each type's size
(rounded up) are canaries, taken in manifest order from the cursor on so each is tested in turn,
and the other half are random items (`docs/decisions.md` 2026-09-30, W2.6).

**Client.** One of an MSP's customers: one Microsoft 365 tenant, which Veeam backs up as one
organisation. One Veeam server may back up many clients; one Worker talks to it with one set
of credentials and names the client in each call.

**Client reference (`client_ref`).** How a connector call names the client: the name the
backup product knows it by. For Veeam, the organisation's name as in `veeam_org_name` (e.g.
`RestoreProofLab.onmicrosoft.com`), matched ASCII case-insensitively; the connector looks up
Veeam's organisation ID itself.

**Client profile (`restoreproof.client-profile.v1`).** One client as a job carries it and a
profile file holds it (W4.10, `rp::ClientProfile`, `shared/schemas/client-profile.v1.json`):
a closed object of nine required keys, `format` and the eight client keys of `config.json`
under the same names and rules (`veeam_org_name`, `graph_tenant_id`, `graph_client_id`,
`test_mailbox`, the four target IDs). IDs, a name and an address: no URL and no secret. The
service's runs, its record and its recovery clean take the client from the job's profile and
never from the config; `rpworker client check --profile-file` lists a profile's three restore
targets; `restore` and `test` take `--profile-file` too. The config's eight keys, set
together or not at all, are its **local client profile**, what the commands at a prompt run
on without a file. What the profile claims about the tenant is checked by the client check
(W4.11).

**Client check (W4.11).** The step of every run, right after the run line and before the
clean before, that holds the run's client profile to facts Veeam and Graph report: the
organisation named by `veeam_org_name` is of type `Office365`, its `msid` is the profile's
`graph_tenant_id` and its region is `Worldwide` (`rp::check_client`, else
`error client_mismatch`); the canary manifest is that tenant's (`error config`); and the
three restore targets resolve in that tenant through the guard's own checks (Graph's codes).
Nothing is cleaned, sampled or restored before it passes, and a run that stops in it is
reported under its run ID. `docs/verification.md`, "The client check".

**Scope (`client.scope`).** The one claim a signed result makes about where the restore went:
`same_tenant` when the client check passed, so the Veeam organisation's tenant is the
profile's and the targets resolved in it; `null` when the run stopped in or before the check,
and in every result written afterwards. `client.resolved` beside it holds what the check
resolved (the organisation's facts, the Inbox's ID, the library's list ID and site URL, the
OneDrive's site URL).

**Connector.** The Worker's adapter to one backup product (`rp::connector::IConnector`,
W1.7): it lists a client's restore points and restores a sample into the restore targets.
Registered by name; the only one is `veeam_m365` (Veeam Backup for Microsoft 365). Nothing
past the interface sees the product's own types or errors.

**Restore status.** A connector's report of how the restore itself went: `succeeded`,
`partial`, `failed` or `not_run` (`rp::connector::RestoreStatus`). Not a run outcome: `pass`,
`fail` and `error` are decided afterwards from it and the Graph comparison (W3.3,
[verification.md](verification.md), "The status decision table"), and the comparison wins: a
`partial` restore whose items all verify is a `pass` with a warning, and a "restored" item
that isn't there is a `fail`.

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

**Tenant setup script.** `tools/tenant-setup/Initialize-RestoreProofTenant.ps1` (W7.0): what a
client's Global Administrator runs once to prepare the tenant. It finds or makes the three
restore targets and the "RestoreProof Worker" app with exactly its grants, checks them read-only,
and prints the client's profile. A second run changes nothing (`changes: 0`). `docs/tenant-setup.md`.

**The Worker's Graph certificate.** The one certificate a Worker signs in to Microsoft Graph with,
in every client's tenant: its key only in the vault (`graph_cert_pfx_base64`,
`graph_cert_password`), its public half on each client's app registration (`rpworker graph
certificate`). Made once per Worker by `tools/tenant-setup/New-WorkerGraphCertificate.ps1`.

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

The report claims level 3 only for a month in which an item was compared by the SHA-256 of its
content (a canary, or a file of the client's compared with the backup's copy), and level 4
partially only when such an item was a file; a month whose items were checked by their fields,
names and sizes alone says "1, 2" and that level 3 is not covered (C6.8, `docs/decisions.md`
2026-10-15, point 3: a subject or a size is what the backup listed, not the content).

## Run outcomes

The three statuses, and the line between them. The full decision table lives in
[verification.md](verification.md).

**`pass`.** The restore ran and 100% of sampled items match their expected values. Nothing
less is a pass: no "passed with warnings". The status is never qualified; the *warnings*
recorded beside a pass (a restore session Veeam didn't call `Success`, a duplicate copy, a
sample shortfall, earlier runs' copies ignored) are evidence, and a pass with warnings still
means every sampled item verified.

**`fail`.** The backup did not deliver the data: an item was missing, or its content did not
match, while its target was read fine and Veeam didn't blame infrastructure for it (a *failed*
item). A `fail` is a statement about the customer's backup — it is the product working, not
the product broken. A restore Veeam reports as failed counts only through its missing items:
one whose items all turn up anyway is not a `fail` (it is `error` `restore_contradiction`).

**`error`.** The test itself could not run, or couldn't tell, so nothing certain was learned
about the backup: Veeam unreachable, Graph authentication or permission refused, a
`TargetGuard` violation, the Cloud unreachable at dispatch, an empty sample, a restore that
sent nothing (`not_run`), an item that couldn't be checked (its target unreadable, only an
earlier run's copy there: `stale_target`, or an item Veeam failed for an infrastructure
reason: `backup_infrastructure`), a restore Veeam called failed whose items all matched
(`restore_contradiction`), a result the Worker built that isn't valid
`restoreproof.result.v1` (`result_invalid`, the Worker's own fault), a run the Worker was
stopped during or its process ended during (`interrupted`), or a job that is no valid job
(`job_invalid`). Each `error` carries one `error_code` (the list of twenty is in
[verification.md](verification.md)). **Infrastructure problems are never reported as
`fail`**, because a `fail` accuses the customer's backup of losing data.

**`interrupted`.** The `error_code` of a run the Worker itself was stopped during (W4.8). No
service's fault, exit code 4. Three ways to it: a stop found during the run, which ends it as
a stop does (`the run stopped before the restore: the run was interrupted (interrupted);
nothing was restored`, and so on by phase); an `error` decided after a stop was asked for,
since a wait the stop cut short reads as the failure of whichever service was being waited
for (`the Worker was stopped during the run; the run itself ended error <code>`; a `pass`, a
`fail` and a `target_guard` stay what they are); and a result written afterwards for a run
the process ended during. It never says what the run found.

**`job_invalid`.** One word in two places (W4.8). As a result's `error_code`: the job the
service was handed has a usable `run_id` and breaks another rule of the jobs document, so
nothing was run and the Cloud gets a signed `error` under the job's own ID, `the job isn't a
valid job (<key>); nothing was done`; exit code 1 in the code table, never a stop's code nor
an item's. As a heartbeat's `last_error`: the loop met a job it couldn't run, one without a
usable `run_id` included, for which no result can be written.

**Item verdict.** What W3.3 makes of one sampled item: *verified* (the check found it
matching), *failed* (missing or mismatched, evidence against the backup) or *unchecked* (it
couldn't be checked, with a code). A `fail` names its failed items; an `error` its unchecked
ones.

**Warning (of a run).** A note beside the status, with a code (`backup_session`,
`backup_item`, `duplicate`, `shortfall`, `stale_copies`), a one-line message and the items it
concerns. Never changes the status, never names a tenant value.

**`cleanup_ok`.** Whether a run left the restore targets clean, in the result's `cleanup`
object beside `status` (W3.4): the clean after's verdict when it ran, else the clean before's;
false when a restore was sent and no clean after could run, or when the restore may still be
running in Veeam (`restore_may_still_run`): the clean after is then skipped (W4.8), `after`
is `null`, and the next run's clean before, or in the service the clean after the hold, takes
up what is left. A target is clean when nothing stopped its
cleanup and nothing was left or skipped. Housekeeping, not a result: a `pass` with
`cleanup_ok: false` is still a `pass`.

**Span.** One named, timed step of a run (W3.5, `rp::timing::StepTimer`): eleven fixed names,
from `restore_point_lookup` to `total`, printed as the table that ends `rpworker restore` and
kept as the result's `timings` object. Measured on a steady clock, never a wall clock. Spans
overlap and don't add up to `total`. A span without a duration says why: not run, stopped
(the run stopped during it), not reported (the connector didn't measure it) or clock went
back; no duration is ever made up. Timings never change a status or an exit code.

**Recovery time.** The span `recovery`: from the start of the restore to the last sampled
item's verdict, i.e. the restore plus reading the items back and checking them (W3.2 point 7,
W3.5). It is how long getting the sampled items back took, not the whole run (`total`), and
it says nothing about restoring anything beyond the sample.

## Evidence

**Result (`restoreproof.result.v1`).** The one JSON document a run with a run line leaves
(W4.1): seventeen keys, from `format` and `run_id` to `status`, `cleanup`, `timings`,
`attachments` and `screenshot` (W4.2), `null`
where a step didn't run. Built by `rp::ResultBuilder`, validated in the Worker against
`shared/schemas/result.v1.json` before any status line is printed, and written by `rpworker
test --json` as its canonical bytes, or as `result.json` in a run folder. The `--json` file is
never signed; a run folder's `result.json` always is, by the `signature.json` beside it (W4.3).
The result itself has no signature field. See [verification.md](verification.md), "The result".

**Canonical form (`canonical-json-v1`).** The one byte sequence of a result, the same from C++
and Python: keys sorted by byte, no whitespace, UTF-8, integers only. A float, an integer
outside ±(2^53 − 1), a non-ASCII key or invalid UTF-8 is refused, not written some way.
`rp::canonical_json`; vectors in `shared/testdata/canonical-json-v1.json`.

**Run folder.** `<runs root>\<run_id>\` (W4.2, `rpworker test --evidence <dir>`): `items.csv`,
`veeam-session.log`, `screenshot.png` when one was captured (none is, today), `signature.json`
(W4.3), `timestamp.tst` when the TSA gave a token (W4.4) and `result.json`, written last. The
result lists each of the first three with its SHA-256 and size in `attachments`; it lists
neither itself nor `signature.json` nor `timestamp.tst`. A folder without `result.json` is a
run with no result; one with it is complete: signed, and timestamped or not. The service
gives the folder its record names a result written afterwards (W4.8); a folder a command left
stays as it is. See
[verification.md](verification.md), "The run folder".

**Outbox.** Where a complete, signed run folder waits to be uploaded (W4.6):
`<root>\outbox\<run_id>\`, by default under `%ProgramData%\RestoreProof`, put there by one
rename (`rpworker test --evidence <dir> --outbox <root>`) and moved to `<root>\sent\<run_id>\`
once the Cloud has answered 202 (`rpworker outbox flush`, or the same pass made by the
service's loop, W4.8). A failed upload is tried again after
1 minute, doubled each time up to 1 hour. Nothing in a queued folder is ever changed but its
`manifest.json`.

**Outbox manifest (`manifest.json`).** The Worker's own record of a queued run
(`restoreproof.outbox-manifest.v1`): when it was queued, the upload attempts, the last error,
when it is tried next, and whether the run was timestamped (with the TSA's code when it
wasn't). Never uploaded, never listed in `attachments`, not covered by the signature; a
verifier notes it as a file the result doesn't list. See [verification.md](verification.md),
"The outbox".

**Evidence bundle.** What one run leaves behind and uploads: the run folder. The result JSON,
`veeam-session.log` and `items.csv` (the per-item comparison, with the canaries' expected and
found hashes), a screenshot when there is one, and `signature.json`. The result is written in
its canonical form (sorted keys, no whitespace, UTF-8, ISO-8601 UTC), those bytes are hashed
as `bundle_sha256`, and the hash is Ed25519-signed (W4.3) and timestamped by an RFC 3161
authority (W4.4, `timestamp.tst`). The other files are under the signature through the
result's `attachments`. It is the artefact an auditor can check offline with
`shared/tools/verify_bundle.py` and the Worker's public key, without trusting us: the script
says `verified` or `not verified: <word>`. Failed runs are never edited or re-signed. The
guide also says "bundle" for the result JSON alone; no zip is ever made.

**Signature (`signature.json`).** The file beside `result.json` that holds the result's
signature (W4.3), format `restoreproof.signature.v1`: five keys, `algorithm` (`ed25519`),
`bundle_sha256`, `format`, `key_id` and `signature` (64 bytes as standard Base64, 88
characters), written in canonical form; schema `shared/schemas/signature.v1.json`. The
signature is never a field of the result, and nothing is removed from the result before it is
hashed. The file is not itself signed, so a verifier takes the public key from its caller,
never from the folder. See [verification.md](verification.md), "The signature".

**Report.** A client's PDF of one period (C6.4): A4, six sections in a fixed order (Summary,
Test log, Failures, Method, Integrity, Framework mapping), rendered with WeasyPrint from one
template, stored under `msp/{msp_id}/reports/{client_id}/{period}.pdf` with a `report` row that
holds its two hashes. Made by the scheduler's report job on the 1st for the previous month
(C6.6), by "Generate now" on a client's reports page for the current month, and by `manage.py
generate-report` by hand. It never claims more than was tested; four phrases are banned by a
test, and the reviewed sentences are held verbatim by another (C6.5). The Test log, the
Failures and the Integrity run list show at most 200 runs and say how many more there were; the
Summary counts every run. See [verification.md](verification.md), "The Cloud's report".

**Period.** One UTC calendar month, named `YYYY-MM`, the span a report covers. A `pass`, `fail`
or `error` run is the month's by the time it ended (a result written afterwards: the time it was
stamped, else handed out); an `expired` run by its creation, counted as a scheduled test that did
not run; a `queued` or `dispatched` run by its creation, counted as one with no result yet.

**Content hash and file hash.** A report's two SHA-256s (C6.4). The report is rendered twice:
the first pass prints no hash and its SHA-256 is the *content hash*, printed by the second pass
in the Integrity section; the second pass's SHA-256 is the *file hash*, stored beside the report
and equal to the SHA-256 of the file a reader downloads. Two, because a file cannot contain its
own hash. `report.content_sha256`, `report.file_sha256`.

**Report check.** What a stored report is held to (Q6.1, `app/report/check.py`, run by the
tests and by `manage.py check-report`): the object under its key hashes to its file hash; every
run the Summary counts is as its row says, a stamped run's `timestamp.tst` read back from the
bucket beside its `result.json`, verified under the Cloud's TSA root, its time the row's and
within the stamp budget of the test's end; a late result the period's by its arrival; for a
final report every result received before it. A finding is one `<run id>: <word>` line. See
`docs/verification.md`, "The report checks".

**Stamp budget.** The Worker's whole timestamp budget after a run's end, 120 s
(`STAMP_BUDGET`: three attempts of ten seconds plus waits of thirty and sixty,
`worker/include/rp/timestamper.hpp`). A token's time is not before the second the test ended
and not more than the budget after it; no clock allowance beyond that, so a Worker whose clock
disagrees with the TSA by more is a finding, not noise.

**Interim report.** A report of a period that is not over (C6.4): its last day is not before
the day it was generated. Its title says so, its key carries its generation time, and a client
may have any number of them for a month beside the one final report (`uq_report_final_period`).
"Generate now" on a client's reports page makes one (C6.6), at most one per client every ten
minutes and one render at a time per process.

**Late result.** A result the Cloud received (`test_run.received_at`, the Cloud's clock at the
upload) at 02:00 UTC on the 1st after the month its run ended in, or later (`RESULTS_CLOSE`). It
is a test of the month it arrived in, since the month it ended in may have its final report; the
report prints it with its own date and counts it on a Summary line of its own.

**Closed month.** A month whose final report may be made: from 03:00 UTC on the 1st after it
(`FINAL_AFTER`, an hour after it stopped taking results). `generate` refuses a final report
earlier (`period: not closed until 03:00 UTC on the 1st`).

**Report job.** The scheduler's third job (C6.6, `tick_reports`): on the 1st at 03:00 UTC and
once at the process's start, the newest closed month's final report for every client with a run
in it, one transaction per client, a month that has its report skipped and never a failure, a
client's failure logged by type while the next is made. A final report is never re-made.

**Reports page.** `/reports` (the nav's "Reports", C6.6): every report of the MSP newest first,
with the client, the period, the kind, the generation time, both hashes and a Download link;
`/clients/{id}/reports` is one client's with "Generate now". The download,
`GET /reports/{id}/file`, writes one `report.download` audit row (user, time, IP) and answers
302 to a link pre-signed for ten minutes, as the bundle's download does.

**Framework mapping.** The report's sixth section (C6.4, C6.7): the four controls (ISO/IEC
27001:2022 A.8.13, SOC 2 Availability A1.2 and A1.3, HIPAA 45 CFR 164.308(a)(7)(ii)(D), DORA
Article 12) by identifier and their own name, each with one sentence saying what a test marked
pass shows ("On the dates listed, a sample of items was restored …") and one saying what the
report does not look at; above the table, that it describes this evidence and is not an
assessment of the control. `app/report/frameworks.py`, held verbatim by
`tests/test_report_wording.py`; the outside reader's comments in `docs/decisions.md`.

**Timestamp (`timestamp.tst`).** The file beside `result.json` that holds an RFC 3161
TimeStampToken (W4.4): a timestamp authority's signed statement that the SHA-256 of
`result.json`'s bytes existed at the token's time. The bare DER token as the TSA sent it, no
wrapper; `openssl ts -verify -data result.json -in timestamp.tst -token_in -CAfile <root>`
checks it. By default from DigiCert's public TSA, trusted through the one root in
`shared/tsa/tsa-ca.pem`. A folder without it is "not timestamped": a TSA failure is a warning,
never a status. Both verifiers check it against the caller's `--tsa-ca` and print its time as
the third field of their `verified` line (`none`, `unchecked`). See
[verification.md](verification.md), "The timestamp".

**TSA.** Timestamp authority: a service that signs "this hash existed at this time" (RFC
3161). Config's `tsa_url` and `tsa_ca_file`; `rp::Timestamper` asks it, `rp::Rfc3161` reads
and verifies its tokens.

**`bundle_sha256`.** The SHA-256 of `result.json`'s bytes, 64 lower-case hex: for a folder the
Worker wrote, what `Get-FileHash result.json` prints. The Ed25519 signature is over its 32 raw
bytes, not the hex text. In `signature.json`, in `rpworker test --evidence`'s `signed
<bundle_sha256> key <key_id>` line and in both verifiers' `verified` line.

**`key_id`.** The name of a signing key: the SHA-256 of its public half as SubjectPublicKeyInfo
DER (44 bytes), 64 lower-case hex. In `signature.json`; a verifier answers `wrong_key` when it
isn't the ID of the key it was given. `rpworker signer public-key` prints it as `key <key_id>`
on stderr.

**Signing key.** The Worker's Ed25519 key pair. The private key signs each run folder's result;
the public key, as a PEM file, is what a verifier is given and what is registered with the
Cloud so bundles from that Worker can be verified (C5.5). Since W4.5 the private key is the
vault's `signing_key_base64`, one line of Base64, and in the lab it is made by `python -m
seeder new-signing-key`, kept in Windows Credential Manager and moved into the vault by
`fill-worker-vault.ps1`; only from W7.1 is it generated on the Worker at setup. It is never
logged, printed or written to a file in the clear by the Worker. Signing proves *which Worker*
produced a bundle; the RFC 3161 timestamp proves *when* it existed.

**Vault.** The Worker's one store of secrets (W4.5): `%ProgramData%\RestoreProof\vault.bin`,
a DPAPI blob under machine scope whose plaintext is a canonical JSON object of five names,
`veeam_username`, `veeam_password`, `graph_cert_pfx_base64`, `graph_cert_password` and
`signing_key_base64`. Machine scope means any process on the machine can decrypt it and none
on another machine can, so the file's ACL is the access control: SYSTEM, Administrators and
the file's owner, plus one Read entry per `rpworker vault grant <account>` (the service
account's). `rpworker vault set <name>` fills it from the console without echo or from stdin;
`--vault <file>` on a command names another file. No secret is read from the environment or
`config.json`.

**Service (the Worker's).** The Windows service `RestoreProof` (display name `RestoreProof
Worker`, W4.7): `rpworker service run`, started by Windows at boot under the virtual account
`NT SERVICE\RestoreProof`, restarted a minute after a failure up to three times, and stopped
within 30 s of being asked. Installed and removed by `rpworker service install` and
`uninstall`. Its body is the scheduler loop (W4.8).

**Doctor (`rpworker doctor`, W7.2).** The read-only check of an installed Worker, run elevated
on the Veeam server: one line per check, `ok:`, `warning:`, `problem: ... (fix: <the line to
run>)` or `skip: ... (needs <check>)`, exit 5 when a line is a problem. What the service account
may do is computed by Windows' access check for the service's SID, never by running as it. A
**skip** is a check whose input a failed check was to give: it is never a problem of its own, so
one missing grant is one problem line. `--json` is the support file: ids, results and codes,
never a text, a path or a tenant value (`docs/worker-config.md` "`rpworker doctor`").

**Upgrade (`Install-RestoreProofWorker.ps1 -Upgrade`, W7.4).** The installer run from a newer
package over an installed Worker: it waits for a run in progress to end (`state\running.json`
gone, up to `-WaitMinutes`), stops the service, moves the installed files to **`previous\`**
(`%ProgramFiles%\RestoreProof\previous\`, the version before this one, emptied at every
upgrade) and copies the package's in, then starts the service; the config, the vault, the
grants and the registration are not touched. The **rollback** is the same switch with
`-Package "<ProgramDir>\previous"`. The version is the one number in `worker/CMakeLists.txt`,
bumped by the PR that ships a package (`docs/upgrade.md`).

**Uninstall (`Uninstall-RestoreProofWorker.ps1`, W7.3).** Takes away what the installer put on
the machine and what the service made: after the same wait for a run in progress, one
`outbox flush`, `rpworker cloud revoke`, the service account's entries off Veeam's key files
and `service uninstall`, then `vault.bin` and the run folders (each file **overwritten once,
then deleted**: it defeats an undelete tool and guarantees no erasure on an SSD or inside a
snapshot; the secrets are worthless once revoked), the config, the exe folder and the Apps &
features entry; `logs\` and the data folder stay unless **`-Full`**. Nothing is removed before
the service is uninstalled.

**`rpworker cloud revoke`.** The Worker revoking itself (W7.3): one `POST
/v1/workers/self/revoke` with its API token; on 204 (or a 401: the Cloud no longer knows the
token) the token leaves the vault; `state\worker.json` stays. Run by the uninstall; by hand
when a Worker is retired without it.

**Service log (`worker.log`).** The running service's log,
`%ProgramData%\RestoreProof\logs\worker.log`: five files of 10 MiB at most, every line
through `redact()`, `SECURITY: ` lines written at every `log_level`. The commands log to
stderr, not to it. Since W4.8 it holds the loop's own lines and, as `[<run_id>] <line>`, every
line a job's run would have printed at a prompt: stdout's at `info`, stderr's at `warning`,
tenant names included, as `veeam-session.log` and `items.csv` hold them.

**Scheduler loop (service loop).** The body of the service (W4.8, `rp::ServiceLoop`): one
thread, one timeline, three things due. A poll every `poll_interval_s` (300 s by default):
first the record's business when there is a record, then, only when there is none, the jobs,
one at a time, then a flush of the outbox. A heartbeat every `heartbeat_interval_s` (900 s).
And, while the hold lasts, a look at Veeam's sessions at least every 30 s. A job that takes
longer than the interval makes the next poll late, never a second run. After a stop nothing
new is started.

**Job.** One test the service is to run: a closed object with `run_id`, `client_id`, `client`
(the client's profile, W4.10), `connector` (`{type}`, the connector's registry name, W4.11; a
name this Worker's registry lacks is reported as `error connector_unknown`), `sample_mail`,
`sample_sp`, `sample_od`, `restore_point` (`latest` or a restore point ID),
`screenshots_enabled` and, optionally, `canary_cursor`. It is run through `rpworker test`'s
pipeline, in process, into a run folder and the outbox. A job whose run is already queued or
sent, or whose run folder is already there, is skipped; the run ID is what makes a job run
once.

**Jobs file.** Where the service gets its jobs until the Cloud hands them out (W5.1): the
file the optional config key `jobs_file` names, an absolute path, read whole at every poll.
One `restoreproof.jobs.v1` document, `{"format": "restoreproof.jobs.v1", "jobs": [...]}`, at
most 1 MiB and five jobs. Whoever can write it commands the Worker, so it is read only when
its owner is SYSTEM, Administrators or the service's account. A stub: its jobs are taken out
by hand.

**State folder.** `%ProgramData%\RestoreProof\state` (`rp::default_state_dir()`), the
service's own folder, made by the loop when it isn't there. It holds the record,
`running.json`, and `running.json.unread` when a record that couldn't be trusted or read was
moved aside.

**Record (`running.json`).** The service's written-ahead note of the one run it has taken
(W4.8, `restoreproof.running.v1`, `canonical-json-v1`, in the state folder, never in a run
folder): the run ID, when it was taken, the client (the job's profile, W4.10), then the start time, the restore point
and the connector once the run line is out, the ID of every explore session the run opens,
and `restore_requested`, set before every restore request. False is a promise that no restore
request went out; true means one may have. It holds IDs, times and fixed words, never a
secret or an item's name. It stays until the run's folder is in the outbox and no restore of
the run may still be running, and no other job starts while it is there. A record found at
start is of a run the process didn't finish.

**Result written afterwards.** The result the service writes for the record's run when its
folder was left without a `result.json` (W4.8): a valid `restoreproof.result.v1` that says
`error` with `interrupted`, `result_invalid`, `internal` or `job_invalid`, holds what the
record knows and `null` for every step, lists the `items.csv` and `veeam-session.log` the
folder has (or their empty forms), and is signed, timestamped and queued by the same path as
any run. It doesn't say what the run found: the attachments are evidence of what was done,
not a second verdict. See [verification.md](verification.md), "A result written afterwards".

**Hold.** What the loop does while a restore of the record's run may still be running in
Veeam (W4.8): no job is started and nothing is cleaned. It looks at the Veeam account's
running sessions under the run mutex. Without a restore request on record it ends the explore
sessions the record lists, at once. With one it ends nothing while any session the record
doesn't list is running (it might be the restore), and ends the recorded ones only when none
is and 120 s have passed. It never ends a session it didn't write down. When nothing of the
run is running any more and a restore was requested, the restore targets are cleaned once,
the clean the run never made, and the record goes.

**Heartbeat.** The service's sign of life to the Cloud (W4.8): `POST <cloud_url>/v1/heartbeat`
every `heartbeat_interval_s`, a canonical JSON body of `version`, `uptime_s`, `outbox_depth`
(the runs under `outbox\`, the ones that can't be sent included), `last_error` and
`last_error_at`. `last_error` is the latest of the loop's own troubles since the service
started, one fixed word (`jobs_unreadable`, `run_not_closed`, `veeam_sessions_working`, an
upload word, ...), never a run's `error_code`; it is not cleared by a later success. Sent
once, no credential until W5.1; one that falls due during a run is sent once after it, and a
failed one is a log line, never the last error it reports. The Cloud's side (C5.8) writes the
five fields as sent into the token's Worker's row (`worker.version`, `last_error`,
`last_error_at`, `outbox_depth`, `uptime_s`) and `last_seen_at` from its own clock, in one
`UPDATE`, answering 204 with no body; a revoked or unknown Worker is the one 401 and nothing is
written; a body outside the five keys is 422. `docs/verification.md` "The Cloud receives a
heartbeat".

**Last seen (`worker.last_seen_at`).** When the Cloud last took a heartbeat from a Worker: the
Cloud's clock at that request, never a time the Worker sent. Null until the first heartbeat;
stops moving at a revoke. C6.2's `/workers` page shows it, red when older than 24 h.

**RFC 3161 timestamp token (`tsa_token`).** A third-party Time Stamping Authority's signature
over the bundle hash, proving the bundle existed at that time — not merely that our server
says so. Not built yet (W4.4). It will be a file of its own in the run folder, not a field of
the result or a sixth key of `signature.json`: it arrives after the signature and touches no
signed byte. `tsa_token` is the guide's name for it; W4.4 names the file.

## Tokens

Three different secrets, often confused, then the words for the Worker's Graph sign-in:

**Install token.** A one-time, 7-day, single-use enrolment secret (32 random bytes,
base64url) created by `manage.py create-worker-token` and printed once. The operator puts it in
the Worker's vault (`rpworker vault set cloud_install_token`); `rpworker cloud register` (or the
first `rpworker service start`, W5.1) calls `register`, stores the API token and removes the
install token in one write of the vault. The Cloud stores only its SHA-256 hash, with a label (what the admin
typed), when and by whom it was made; it names no client (a Worker is an MSP's; connectors bind
clients later). A registration that fails (a bad key, a key already registered) leaves the token
unused: the whole of it is one transaction (C5.5).

**API token.** The Worker's long-lived credential for calling the Cloud (32 random bytes),
issued once by `POST /v1/workers/register` (C5.5) and kept in the vault as `cloud_api_token`
(W5.1). The Worker sends it as `Authorization: Bearer` on the poll, the upload and the heartbeat,
and nowhere else; a 401 stops the poll and the upload with that token until the vault holds
another. The Cloud stores only its SHA-256 hash and compares in constant time; setting
`revoked_at` blocks the worker immediately. Never logged.

**`failed\` (W5.1).** The third folder of the Worker's outbox root, beside `outbox\` and
`sent\`: a run the Cloud refused for good (400, 404, 409, 415, 422), moved whole for the
operator's `rpworker signer verify`; never sent, pruned or deleted by the Worker.

**Kept jobs document (W5.1).** `state\jobs.json`: the Cloud's last answer to `GET /v1/jobs`,
kept and read by the jobs file's reader until every job in it is settled or it is six hours old,
since the Cloud hands a run out once. `jobs_file`, set, replaces it (a lab without a Cloud).

**`state\worker.json` (W5.1).** The Worker's registration as `rpworker cloud register` wrote
it: its `worker_id`, `key_id`, `cloud_url` and time. No secret.

**Contract header.** `X-RestoreProof-API: 1`, on every answer the Cloud's app sends (C5.11). The
Worker counts a 2xx as the Cloud's only with it (W5.1): an upload's is otherwise
`upload_not_cloud`, a jobs document isn't read, a registration stores nothing.

**Key id.** The SHA-256 of a Worker's public key as SubjectPublicKeyInfo DER, 64 lower-case
hex: the `key_id` of every `signature.json` the key makes, what `rpworker signer public-key`
prints on stderr, and `worker.key_id` in the Cloud, unique across all MSPs since C5.5, so a
public key is registered once. The Cloud accepts a key file by the verifiers' one rule, stores
the key in the library's three-line PEM whatever layout it was sent in, and refuses a
small-order or non-canonical point, under which a verifier would accept forgeries.

**Dispatch.** The Cloud handing a queued run to its Worker: `GET /v1/jobs` (C5.6) moves the
Worker's oldest queued runs, at most five, to `dispatched` with `dispatched_at` and one more
`attempt`, in one locked statement, and answers them as a `restoreproof.jobs.v1` document whose
`run_id` is the run's own id. A run whose bundle hasn't arrived (C5.7) within six hours goes
back to `queued` by the scheduler's sweep (C5.9, over `RunRepo.requeue_stale`), and after three
attempts to `expired`; its bundle is still taken when it comes.

**Period.** The span between two occurrences of a plan's cadence (`cadence_cron`: five cron
fields, UTC, at most every five minutes and at least monthly), named by its start. The scheduler (C5.9, `cloud/app/scheduler.py`,
the Compose `scheduler` service) makes one queued run per enabled plan and current period,
`test_run.scheduled_for` being the period's start under a unique on `(msp_id, plan_id,
scheduled_for)`, so two ticks or two processes make one; a period that began before the plan was
made is not the plan's, and only the current period is ever made up. A run made by hand
(`RunRepo.create`, `create-plan --run-now`) has no period. See `docs/verification.md`, "The Cloud
makes a run".

**API version header.** `X-RestoreProof-API: 1` on every response the Cloud's app sends (C5.11,
`cloud/app/contract.py`): a route's answer, a refusal, a 404, the log middleware's 500,
`/healthz`, the OpenAPI document; not on the server's own 400 for a request it can't parse or
its 503 when it is full, which never reach the app, so only a 2xx is held to it. The value is the contract's number, the `1` of `/v1`, never
the Cloud's version (that is `GET /v1/version`'s `{"api": 1, "version": "0.0.0"}`, answered
without a token or a statement). It tells a Worker or an operator that the thing at `cloud_url`
is a RestoreProof Cloud speaking contract 1; W5.1 holds a 2xx of the upload to it. See
`docs/verification.md`, "The contract".

**Body cap.** C5.11's 64 KiB limit on every request body but the upload's
(`cloud/app/contract.py`, `MAX_BODY_BYTES`): 413 `body: too large` on a `Content-Length` over it
before the app runs, and from the first byte over it as the bytes arrive, whatever the header
said. `POST /v1/results` keeps its own 96 MiB cap (C5.7). The token still comes before the body:
the header check reads nothing, and a request without a token pulls nothing.

**Contract test.** C5.11's Done-when: `shared/testdata/signing-v1/dispatched-run.json`, a run
folder the C++ Worker's service made and sent for a job of the Cloud's shape (a uuid `run_id`, a
`client_id`), posted byte for byte by `cloud/tests/test_contract.py` under the part list the
Worker's outbox built, to 202 `pass`. Nothing is re-signed; it is the one shared folder that
reaches 202. Written by `rptests "[.write_shared_dispatched]"`.

**Onboarding CLI.** `cloud/manage.py` (C5.10, `docs/onboarding.md`): `create-msp`,
`create-client --tenant-id`, `create-worker-token --label` (the install token, once),
`create-connector --profile-file`, `create-plan` and `revoke-worker`, each one committed
transaction through the repos, each refusal one `<key>: <reason>` line by constraint name and
never a value. Since C6.1 also `create-user --email --role` and `reset-password --email`, the
password asked for on the console or read from standard input, never an argument.

**Session cookie (`rp_session`).** C6.1's one session: itsdangerous's URL-safe serializer under
`SECRET_KEY` (its one use) and the salt `restoreproof.session.v1` over the user's id, the MSP's
id, the issue time and the stamp of the password it was issued for, good for 12 hours; `HttpOnly`, `SameSite=Lax`, `Secure` unless
`SESSION_COOKIE_SECURE=false` (the http stack). `current_user` reads the user's row every time;
a cookie whose stamp is not `user.password_changed_at`'s is no session, so `reset-password` ends every
session. No session sends a browser to `/login` and answers an htmx request 401 with
`HX-Redirect`. See `docs/verification.md`, "The Cloud's pages".

**Login limiter.** C6.1's five attempts a minute per address and per IP
(`cloud/app/auth/login_limiter.py`): a sliding window in the api process's memory, every
`POST /login` counted right or wrong, the sixth 429 with `Retry-After` before any password work;
an attempt on a known user is an `audit_log` row (`login.success`, `login.failure`,
`login.blocked`), an unknown address has no MSP and no row. Not slowapi (it cannot key by the
form's address); a shared store is C7.2's.

**Role (`user.role`).** `admin` or `member` (`ck_user_role`). A member reads every page and
downloads a bundle's files; an admin also revokes a Worker and reads `/audit`. A member on an
admin route is 403; a row of another MSP is 404 on every page.

**Pre-signed link.** C6.2's download: `GET /runs/{id}/files/{name}` writes one `bundle.download`
audit row (user, time, IP) and answers 302 to a URL that SigV4-signs a GET of the one object for
ten minutes against `S3_PUBLIC_ENDPOINT`, the S3 endpoint a browser reaches (the signature
covers the host, so a URL signed for the stack's `minio:9000` doesn't open elsewhere; the
stack sets `http://127.0.0.1:9000`). The page links the route, never the bucket.

**Recovery time (`test_run.recovery_ms`).** The result's `timings.spans.recovery.ms` (W3.2:
restore start to last item verified), filed by `POST /v1/results` since C6.2 as `total_ms` is,
null for a span without a duration; the "recovery time" of `/clients`, `/clients/{id}`,
`/runs/{id}` and C6.4's report. A run filed before the column has null.

**Audit page (`/audit`).** C6.3: an admin's view of the MSP's `audit_log` newest first, the last
30 days by default (`?days=`), paged by keyset, each row with its user's address, the action,
the target and the IP; every row of the MSP, the Worker's and the CLI's included. Nothing
deletes an audit row; `cloud/app/audit.py` holds the pages' words (`ACTIONS`) and the one
reading of the caller's address.

**Bundle upload (`POST /v1/results`).** The Worker's multipart upload of a run folder (C5.7):
the parts `result`, `signature`, `timestamp` when there, and one per listed attachment under its
name. The Cloud verifies it with the auditor's own `verify_bundle.py` under the token's Worker's
registered key and the pinned TSA root, refuses anything that doesn't verify with the verifier's
one word (400; `result_unstorable`, the Cloud's own, for a verified result whose item index or
text a column can't hold), names the run only after that, by the very text the job gave (one 404
for a run that isn't this Worker's; 409
for one never handed out, for a bundle whose client isn't the run's, `client_mismatch`, and for a
second bundle of one run, `bundle_conflict`), and files the run as its bundle's `pass`, `fail`
or `error` with its items in one transaction, the files under `msp/<msp_id>/runs/<run_id>/`;
202 `{"run_id", "state"}`, and the same bundle again 202 with no change. There is no `received`
state: the bundle's status is known in the request that receives it. A missing token is
`tsa_ok` null ("not timestamped"); a bad one is refused as the two verifiers refuse it.

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

**Sentinel audit.** W4.9's test (`worker/tests/secret_audit_test.cpp`, `[secret_audit]`): every
path of the pipeline, the commands that read the vault and the service's loop run on fixtures
with five known values in place of the vault's secrets (`Sentinel-Audit-...`, a PFX made for
the audit, RFC 8032's test key 2), and everything each path wrote (both streams, the log, every
file, every request to the fake Cloud and the fake TSA) is searched for every value, every value
derived from one (the PFX's bytes and hex, the signing seed, the tokens the fakes hand out, the
exported credential, the client assertion) and every secret shape. A hit names the output and
the value's label, never the bytes. `veeam_username` is no secret value and is only counted. See
`docs/testing.md`, "The secret audit (W4.9)".

**Fixture scan.** W4.9's other half (`worker/tools/fixture_secret_scan.py`, a ctest test and the
`fixture-scan` CI job): the committed fixture, vector and evidence trees searched for secret
shapes, never values (CI has no lab secret), against an allowlist that names, per file, the shape,
the reason and the exact values or prefixes allowed (the published RFC 8032 and test-TSA keys, the
scrub placeholder JWT). A stale allowance fails the scan.

**Secret shape.** What a secret looks like without knowing its value: a JWT (`eyJ` and 37 or more
base64url characters), a `Bearer` token, a PEM private key block, the Base64 opening of a private
key's DER (Ed25519 `MC4CAQAwBQYDK2VwBCIEI`, RSA and EC in PKCS#8, RSA PKCS#1, EC SEC1) or of a PFX
(`MII..[AQgw]IBAzCC`), or a keyed secret (`"password": "..."`) with a value that isn't a
placeholder. A bare `MII...` run is a certificate or a signed token, public, and no shape. One
table for both halves of the audit in `docs/testing.md`.

**Grant (in Worker messages).** A permission a Graph call relies on, in words a customer can
act on, such as `Sites.Selected read on the test site`. Graph's 403 doesn't say what is
missing, so every call the Worker makes names its grant, and a refusal's message quotes it
(`docs/security/graph-permissions.md`, "What a refusal says"). Not a Graph term.
