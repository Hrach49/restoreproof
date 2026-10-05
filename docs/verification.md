# Verification

How a run decides what each restored item should look like, how it compares it, and how the
comparisons become `pass`, `fail` or `error` (the statuses are defined in
[glossary.md](glossary.md), "Run outcomes"). Built in Sprint 3: the expected set (W3.1), the
checker (W3.2), the status table (W3.3).

## The expected set (W3.1)

Before anything is compared, every item the sampler chose gets one expected record: what its
restored copy should look like, and how that expectation was obtained, its **expected kind**.
`rp::verification::build_expected_set(selection, manifest)` (`worker/include/rp/expected_set.hpp`)
builds it, pure, from the sampler's `Selection` and the canary manifest; the decisions are
`docs/decisions.md` 2026-10-01, W3.1.

There are three kinds, one per item, never mixed, and no "unknown" kind:

| Kind | Items | Expected values | Content hash |
|---|---|---|---|
| `manifest` | canaries | from `lab/seed-manifest.json`. Mail: subject, sender address, sent and received time, internet message ID. File: name, and `stored_size` for a `bytes` file | yes: a mail's `body_sha256` by `text-v1`; a file's `content_sha256` by its `content_rule`, `bytes` or `office-v1` |
| `fields` | random mails | from the backup's own listing (Veeam's browse): subject, received time, and the sender's display name and sent time when Veeam lists them | no: nothing knows the body before the restore |
| `metadata` | random files | from the backup's own listing: the name, and the size Veeam lists unless the file is an Office package | no |

- **Random items are expected from the backup, not from Graph.** The Worker app may read only
  the restore targets, never a source, so the backup's listing is the only place a random
  item's expectation can come from. A random file's content isn't expected in Stage 1 (a fourth
  kind, `backup_content`, from Veeam's document export, is a follow-up task after W3.2).
- **The sender.** A canary's sender is an address (the manifest's `sender`); a random mail's is
  a display name (`sender_name`), because Veeam's browse lists only that. W3.2 compares each
  with the matching Graph field.
- **Times** are `YYYY-MM-DDTHH:MM:SSZ`, cut (not rounded) to whole seconds. Tolerances are
  W3.2's.
- **What the backup didn't say is not an expectation.** A random mail without `from`, or whose
  `sent` isn't a time, is still offered and gets `fields` with what is known; a random file
  whose size is below 0 (a connector's "not known", `size_bytes` -1) gets `metadata` by name
  only. A display name is the sender's own text, so each control character in it
  (`worker/src/control_chars.hpp`) becomes a space as it is read.
- **A canary's rule is the one its file can be checked by.** The manifest loader refuses
  `bytes` for a docx or xlsx, `office-v1` for a pdf, txt or png, and a name that is an Office
  package's for any type but docx and xlsx (or isn't one for those), as `python -m seeder`'s
  validator does.
- **Order.** The items are in `RestoreSpec` order (mail canaries, mail randoms, SharePoint
  canaries, SharePoint randoms, OneDrive canaries, OneDrive randoms), each with its `index`, so
  the n-th expected item lines up with the n-th `RestoreResult::items` entry. A canary is named
  by its manifest `id`, a random item by the sampler's key (`record.<kind>.random_keys`).

### The rule for the Office files SharePoint rewrites

One rule, `rp::is_rewritten_office_file(name)` (`worker/src/office_files.hpp`): the name ends,
ASCII case-insensitive, in `.docx`, `.docm`, `.dotx`, `.dotm`, `.xlsx`, `.xlsm`, `.xltx`,
`.xltm`, `.xlsb`, `.pptx`, `.pptm`, `.potx`, `.potm`, `.ppsx`, `.ppsm`, `.doc`, `.xls` or
`.ppt`, with something before the dot (`.docx` alone is not one). SharePoint rewrites these
files, so their stored size is no expectation: such a random file is `metadata` by name only.
The list is what the W3.1 review's live check saw (`docs/decisions.md` 2026-10-01, "W3.1 code
review"; evidence `docs/api/veeam-lab/w3.1-rewrite-check/`): SharePoint's RestoreTarget
library rewrote docx, docm, xlsx, xlsm, pptx, pptm, xlsb, doc, xls and ppt on upload, and left
Visio (vsdx, vsdm, vssx, vstx), the add-ins (xlam, ppam), ODF, pdf, rtf and txt as uploaded;
the templates and shows (dotx, xltx, potx, ppsx and their macro types) weren't tried and stay
on the list as the Office Open XML family. OneDrive rewrote none, but the rule doesn't depend
on where a file is. The Graph reader uses the same rule
to read them up to the download limit instead of exactly Graph's size. Canaries keep the
manifest's `content_rule` (`office-v1` for docx and xlsx, wherever they are). `office-v1`
hashes only the `word/` and `xl/` parts, so it covers docx and xlsx, not pptx.

### The result's `expected` object

`to_json(ExpectedSet)`, snake_case like the `sample` object; a value that isn't known is left
out, never `null`; `counts` always has all three kinds, so a report can say "n of m items
checked against a known hash" without recounting (W4.1 adopts it into `result.v1.json`). It
writes nothing for an item whose fields don't back its kind (`manifest` without a canary ID, a
lower-case hex hash and its type's rule; `fields` or `metadata` with a hash, a canary ID or no
key, or for the other type; an item out of its index), so an item built elsewhere (W3.2, W4.1)
can't read as checked against a hash it hasn't. `build_expected_set` also refuses a record
whose `random_taken` or `canary_wanted` isn't what the selection holds.

```json
{
  "manifest_sha256": "<64 hex>",
  "counts": {"manifest": 3, "fields": 2, "metadata": 1},
  "items": [
    {"index": 0, "kind": "mail", "source": "canary", "expected_kind": "manifest",
     "canary_id": "RP-CANARY-0008", "subject": "RP-CANARY-0008",
     "sender_address": "...@RestoreProofLab.onmicrosoft.com",
     "sent_at": "...Z", "received_at": "...Z", "internet_message_id": "<...>",
     "sha256": "<64 hex>", "sha256_rule": "text-v1"},
    {"index": 3, "kind": "mail", "source": "random", "expected_kind": "fields",
     "key": ["alice@restoreprooflab.onmicrosoft.com", "Inbox", "Lunch", "...Z"],
     "subject": "Lunch", "sender_name": "Bob Test", "sent_at": "...Z", "received_at": "...Z"},
    {"index": 5, "kind": "sharepoint", "source": "random", "expected_kind": "metadata",
     "key": ["<site id>", "<list guid>", "/", "Plan.docx"], "name": "Plan.docx"}
  ]
}
```

## Comparing (W3.2)

`rp::verification::check(expected, before, after)` in `worker/include/rp/checker.hpp` decides,
for each expected item, what became of it in the restore targets. It is pure: `rpworker
restore` does the Graph reads around it (`docs/decisions.md` 2026-10-01, W3.2).

**Two reads, one check.** Just before the restore the command lists the targets the sample has
items for, without hashing: the *before snapshot*, each mail's Graph ID and each file's ID and
`cTag`. After the restore it lists them again, hashing every mail body (`text-v1`) and every
file that is this run's copy of an expected file (`bytes`, and `office-v1` for a docx or
xlsx): the *after read*. A file that was there before with the same `cTag` (an earlier run's
copy), or whose name has no `name_key` of an expected file that carries a hash or a size (a
random Office file carries neither), is listed but never downloaded
(`rp::verification::hash_filter`), so a leftover that is gone, has changed size or is too large
by now can't turn a target's items into `error`. Both go through
`rp::graph::TargetReader`, so every read runs the target guard's checks first (the mailbox's
Inbox, the RestoreTarget library, the OneDrive RestoreTarget folder) and nothing outside the
targets is read. A failure in the before snapshot stops the run before anything is restored.

**This run's copies.** Restored copies look like their originals: a mail keeps its
`receivedDateTime` and `internetMessageId`, a file its name and `createdDateTime`, and all
land flat in the target. So a copy counts as this run's only if:

- a mail: its Graph ID wasn't in the before snapshot (every restore gives a new ID);
- a file: its ID wasn't there, or its `cTag` changed (a restore over a same-named file merges
  a new version into the same item).

Everything else is an earlier run's copy: never compared, counted in `stale_copies`, and
named in one warning line on stderr (since W3.3 the status's `stale_copies` warning:
`warning: stale_copies: <n> copies from earlier runs in the restore targets were ignored
(mail <x>, sharepoint <y>, onedrive <z>)`).

**Finding an item.**

| Item | Looked for among this run's copies |
|---|---|
| canary mail | `internetMessageId` equal to the manifest's; if none, the subject exactly (then `internet_message_id` doesn't match) |
| random mail | the subject exactly |
| file | its own target, a name with the same `name_key` (case-insensitive as SharePoint and OneDrive are) |

**A copy counts for one item only.** Canary mails are looked up first, then every other item
in index order, and each item claims the copies it matched; a later item never sees them. Two
expected items that would find the same copy (two random mails of one subject, two files of
one `name_key`) can't both pass on it: the second finds only claimed copies and is `missing`
(or `stale_target` when an earlier run's copy it would match is there).

An item that only matches an earlier run's copy is `error`, code `stale_target`: the checker
can't tell whether this restore wrote anything, so it is neither found nor missing. For a
file this is a name whose copy's `cTag` didn't move. For a mail it is any earlier copy with
its `internetMessageId` (a canary) or subject: Veeam leaves a mail that is already in the
target as it is, gives no new copy and still reports it "restored successfully" (W3.2's live
run 2 on 2026-10-01 restored five mails over run 1's copies: the Inbox kept run 1's five,
same Graph IDs). So a mail sampled again while an earlier copy is still there is `error`,
never a `fail`. Since W3.4 the clean before empties the targets first ("Cleaning the restore
targets (W3.4)" below), so this happens only when it couldn't delete that copy. When
more than one of this run's copies match, the newest is compared (mail `createdDateTime`, file
`lastModifiedDateTime`, then the greater ID), and the item says `duplicate` with its `copies`;
a duplicate doesn't change the outcome (W3.3 decides what it means for the run).

**Comparing.** Only what the expectation carries is compared; a value the expectation doesn't
have is never a mismatch.

| Field | Rule |
|---|---|
| `subject` | byte-equal |
| `sender_address` (canary) | Graph's `from.emailAddress.address`, ASCII case-insensitive |
| `sender_name` (random mail) | Graph's `from.emailAddress.name`, control characters as spaces (the expectation's rule), byte-equal |
| `sent_at`, `received_at` | within 120 seconds either way, inclusive; a missing or unreadable Graph time is a mismatch |
| `internet_message_id` (canary) | byte-equal |
| `size_bytes` | the downloaded byte count |
| `sha256` | by the expectation's rule: `text-v1` of the body, `bytes` of the file, `office-v1` of the package; a restored docx or xlsx that isn't a valid package is a mismatch on `sha256`, since the restored file is broken, not the test |

A file's name is how it is found, so it is not compared again.

**Outcomes.**

| Outcome | When |
|---|---|
| `match` | this run's copy found, every carried field agrees |
| `mismatch` | this run's copy found, at least one field disagrees (named in `mismatches`) |
| `missing` | no copy of this run's that no other item claimed, and no earlier run's copy the item would match |
| `error` | the item couldn't be checked: its target couldn't be read back (`graph_auth`, `graph_permission`, `graph_transient`, `target_guard`, `graph`), or `stale_target` |

An infrastructure failure is always `error`, for every item of the type whose target couldn't
be read, never `missing` or `mismatch`; the other types are still checked.

**The `check` object.** Lined up with `expected` and `RestoreResult::items` by `index`:

```json
{
  "counts": {"match": 3, "mismatch": 0, "missing": 1, "error": 0},
  "stale_copies": {"mail": 2, "sharepoint": 0, "onedrive": 1},
  "items": [
    {"index": 0, "outcome": "match", "found": true, "ms": 4},
    {"index": 1, "outcome": "missing", "found": false, "reason": "no restored copy found"}
  ]
}
```

`mismatches`, `reason`, `duplicate` with `copies`, `error_code` and `ms` appear only when they
apply. Values found in the tenant (subjects, names, senders, IDs) are never written: the
`expected` object already holds what was checked. `ms` is the item's own cost: its file's
download, hash and `office-v1` time, plus its comparison. The run's step timings are W3.5's (`docs/decisions.md` 2026-10-03, W3.5;
`rp/step_timer.hpp`): W3.2 point 7's "restore start → last item verified" is the span
`recovery`, and its cleanup is the two spans `cleanup_before` and `cleanup_after`.

**Not checked in Stage 1.** A random file's content (no expectation, W3.1 decision 3). A pptx,
or any Office type but docx and xlsx: `office-v1` reads only `word/` and `xl/` parts, so
these are checked by name only; a `ppt/` rule would be a new rule, `office-v2`.

## The status decision table (W3.3)

`rp::verification::decide_status(RunFacts)` in `worker/include/rp/run_status.hpp` turns what a
run produced into one status, `pass`, `fail` or `error` (the statuses are defined in
[glossary.md](glossary.md), "Run outcomes"). It is pure: it never calls Veeam or Graph. The
decisions are `docs/decisions.md` 2026-10-01, W3.3, approved as written. The unit test
`worker/tests/run_status_test.cpp` encodes every row below as a Catch2 `GENERATE` table, each
row named by its ID here (`R5c`, `I3a`, ...), and `run_status` is held to 100% line coverage
like `target_guard` (`worker/tools/coverage_gate.py`).

**The check is the evidence.** The backup's own account (its `RestoreStatus`, its sessions'
results, each item's outcome) is only a warning or an infrastructure excuse: a "restored
successfully" that wrote nothing can't become `pass` (W3.2 live run 2), and neither an unclean
target nor an unreachable service becomes `fail`.

**Inputs** (`RunFacts`): the expected set; the sample's shortfalls (`shortfalls_of`, per type,
canaries and random items, wanted and taken); at most one `RunStop` (a phase, an `error_code`
and, in the restore phase, `nothing_restored`: the error's message ends with the connector's
`; nothing was restored` promise; never the exception's `what()`); the `RestoreResult` and the
`CheckResult` when they exist. `stop_reason(exception, phase)` makes the stop from an
exception's type. The phases are
`before_restore` (sampling, the expected set, the before snapshot), `restore`
(`restore_sample` threw) and `check` (the read-back or the check threw something that isn't
Graph's). A Graph failure in the read-back is not a stop: its type's items are already
`error` in the check.

### Item verdicts

Each item gets one verdict; the first rule that fits wins.

| Rule | When | Verdict |
|---|---|---|
| I1 | the check says `error` | *unchecked*, with the check's code |
| I2 | the check says `match` | *verified*, whatever the backup said about the item |
| I3 | `missing` or `mismatch`, and the backup marked the item not restored with `infrastructure` | *unchecked*, `backup_infrastructure` |
| I4 | `missing` or `mismatch`, the backup said the restore point doesn't hold the item (`not_in_backup`), and the point isn't shown to hold it: the point lacks the item's whole container (`container_missing`: its mailbox, site or OneDrive), or it is a random item, or a canary whose restore point wasn't taken strictly after the manifest's `seeded_at` (or either time doesn't read) | *unchecked*, `not_in_backup` |
| I5 | `missing` or `mismatch` | *failed* |

**An item the restore point doesn't hold (Q3.1, `docs/decisions.md` 2026-10-03).** The
connector reports it per item, `ItemOutcome::not_in_backup`, never sends it, and restores the
others. The manifest's `seeded_at` is when every canary was in place, so a restore point taken
later must hold each one: a canary missing from it is *failed* (I5), and the run `fail`s
naming it in its row (`rpworker test`'s REASON `not_in_backup`). A canary missing from an
older point, or a random item (drawn from this very point's listing, so its absence is the
backup product contradicting itself), is *unchecked* `not_in_backup` (I4): the test can't say
the backup lost it. The same holds when the point holds no backup of the item's whole mailbox,
site or OneDrive (`container_missing`; PR #155 review, `docs/decisions.md` 2026-10-04): the
point doesn't cover the item, a job or configuration matter, never a `fail`. A folder or a
library missing inside a container the point does hold is still the item's own miss.

A restored item's `infrastructure` flag counts for nothing (I5c): only an item the backup says
it didn't restore can be excused.

### The run

The first row that fits wins.

| Row | When | Status | `error_code` |
|---|---|---|---|
| R1 | the facts don't add up | error | `internal` |
| R2 | a stop, in any phase | error | the stop's (error codes below) |
| R3 | the sample is empty | error | `empty_sample` |
| R4 | the restore returned `not_run` | error | `not_run` |
| R5 | any item *failed* | **fail**, the failed items listed (and the unchecked beside them) | — |
| R6 | the restore is `failed` (the backup restored nothing) and every item *verified* | error | `restore_contradiction` |
| R7 | any item *unchecked* | error | the most severe item code |
| R8 | every item *verified* | **pass** | — |

One more `error` is decided after the table, never by it: `result_invalid` (W4.1). Once a row
has given the verdict, the pipeline builds the result from it and validates it; a result that
isn't valid `restoreproof.result.v1` replaces the verdict through
`verification::result_invalid(verdict)`: status `error`, code `result_invalid`, whatever the row
said. It keeps `restore_sent` (the clean after still runs), the item count and the warnings, and
clears the verified, failed and unchecked items, as R1 to R4 leave them. See "The result"
below. The test rows are V1 to V7.

R1, the facts that don't add up: no expected set and no stop; a restore result without an
expected set, or a check without a restore result; an expected item not at its index; a
restore of an empty sample, or a sample of items with neither a restore result nor a stop; a
restore (not `not_run`) whose items aren't the expected items in number and kind; a check
whose items aren't (in number, index and kind), or an item `error` with a code the checker
doesn't give; a restore result without a check and no stop; a stop whose code isn't one below,
or whose phase contradicts what is there (a stop before or in the restore beside a restore
result or a check, in the restore without an expected set, in the check without a restore
result or beside a check); a value outside its enum (a stop's phase, an expected kind, the
restore's status, a restore item's outcome, a check outcome); a check item whose `found`
contradicts its outcome (a `match` or `mismatch` without a copy found, a `missing` or `error`
with one). R1 carries no warnings, since its facts can't be trusted.

**Precedence.** A stop or an unusable run always wins. Then a confirmed *failed* item wins over
unchecked ones (R5 before R7): a missing or mismatched item counts only when its own target was
read fine and the backup didn't blame infrastructure for it, so it is evidence about the
backup, and an unrelated unchecked item can't hide it. The unchecked items are still listed
beside the `fail`. One item that couldn't be checked beside items that all match is `error`,
never a partial pass: `pass` means every sampled item verified.

How the backup's own status reads (decision point 4):

| Restore | Items | Status |
|---|---|---|
| `partial` (a `Warning` session, a `Failed` one beside restored items, a short count) | every item verified | **pass**, a `backup_session` warning per session that wasn't `Success` (R8b) |
| `partial` | an item missing or mismatched, not infrastructure | **fail** (R5d) |
| `partial` | an infrastructure item the check didn't find matching | error `backup_infrastructure` (R7c) |
| `failed` (0 restored, not infrastructure) | items missing | **fail** (R5e) |
| `failed` | every item matched | error `restore_contradiction` (R6) |
| `failed` | every item `stale_target` | error `stale_target` (R7d) |
| `succeeded` | items missing (the backup said restored; W3.2 live run 2 with mails gone) | **fail** (R5g) |

### Error codes

One flat vocabulary, the same in every phase, with `rpworker`'s exit code. In the code it is
one table (`kCodes` in `src/run_status.cpp`: each code's stop text, whether the checker gives
it, its severity rank and its exit code). Every code a status can carry has a row there,
eighteen since W4.1: `restore_contradiction`, R6's own code, was outside the table before (exit
4 then as now), and `result_invalid` is new. Neither can be a stop's code or a check item's:
given as one, it is R1's `internal`. Three public lists give the vocabulary to the result's
schema, and a test holds the schema's enums to them: `error_codes()` (the table's order),
`unchecked_item_codes()` (most severe first) and `warning_codes()`. A Graph exception's code is the checker's
`read_error_code` wherever it is thrown, the restore-target guard's layer 1 inside
`restore_sample` included, which lets Graph's errors out as Graph's.

| Code | From | Exit |
|---|---|---|
| `config` | `rp::ConfigError` (`graph::CertificateError` too), `sampling::ManifestError`, `connector::UnknownConnectorError`, in any phase (in the read-back too: a stop, never an item error) | 1 |
| `internal` | any other exception (its `what()` is never shown); facts that don't add up (R1) | 1 |
| `backup_auth` | `connector::AuthError` | 2 |
| `backup_transient` | `connector::TransientError` (unreachable, a timeout, a gateway error) | 3 |
| `not_in_backup` | `connector::NotFoundError`: the organisation; an item the restore point doesn't hold that it isn't shown to hold (I4) | 4 |
| `no_restore_point` | no restore points, or `--point` not among them (the command says these before its run line, so no status yet) | 4 |
| `target_guard` | `connector::SafetyViolation`; `graph::WrongTargetError` | 4 |
| `backup` | any other `connector::Error` | 4 |
| `backup_infrastructure` | an item the backup marked not restored with `infrastructure` that the check didn't find matching (I3) | 4 |
| `empty_sample` | R3 | 4 |
| `not_run` | R4 | 4 |
| `restore_contradiction` | R6 | 4 |
| `result_invalid` | the result built from the run isn't valid `restoreproof.result.v1`, or couldn't be built (`result_invalid()`, after the table); the Worker's own fault, as `internal` | 1 |
| `graph_auth` / `graph_permission` | `graph::AuthError` / `graph::PermissionError` | 2 |
| `graph_transient` | `graph::TransientError` | 3 |
| `graph` | any other `graph::GraphError` | 4 |
| `stale_target` | the checker's: only an earlier run's copy is there | 4 |

`pass` exits 0 and `fail` 5 (`exit_code::restore`, `exit_code_of`). With several unchecked
items, the run's code is the first of these present (the severity order, `S1`–`S7` in the
test): `target_guard`, `graph_auth`, `graph_permission`, `backup_infrastructure`,
`not_in_backup`, `graph`, `graph_transient`, `stale_target`. A misconfiguration or a safety problem outranks a
retry-later one, and an unclean target comes last. The message counts each code.

**Messages** are one line of counts and fixed words, never a tenant value (no subject, name,
address or Graph ID) and never an exception's `what()`, which goes to stderr only:

| Row | Message |
|---|---|
| R1 | `the run's results don't add up: <why>` |
| R2 | `the run stopped before the restore: <reason> (<code>); nothing was restored`; in the restore, `the restore didn't start: <reason> (<code>); nothing was restored` when the error promised it, else `the restore didn't complete: <reason> (<code>); items may be in the restore targets`; or `the restored items couldn't be checked: <reason> (<code>)`, by phase |
| R3 | `the sample is empty: nothing to restore` |
| R4 | `the restore didn't run: nothing was sent` |
| R5 | `<f> of <n> item(s) didn't verify (<x> missing, <y> mismatch)[; <u> couldn't be checked]` |
| R6 | `the backup reported nothing restored, yet every item verified: the evidence contradicts itself` |
| R7 | `<u> of <n> item(s) couldn't be checked (<code> <k>, ...)[; <v> verified]` |
| R8 | `<n> of <n> item(s) verified: manifest <a>, fields <b>, metadata <c>` |
| `result_invalid` | `the result isn't valid restoreproof.result.v1; the run itself ended <pass\|fail\|error <code>>`: the replaced verdict's status and code, never its message (a code outside the table isn't repeated: `... ended error`) |

### Warnings

Evidence beside the status, never a status of their own: the status is never qualified, and a
`pass` with warnings is still 100% verified. Each has a `code`, a one-line `message` and the
item `indexes` it concerns, in this order:

| Code | When | Message |
|---|---|---|
| `backup_session` | per restore session whose result isn't exactly `Success`; its indexes are the items sent in that session (an empty session ID matches none) | `<kind> session <id>: <result>[ (<details>)]` (the ID and result with control characters as spaces; the details only when they read as the backup's counts, `<n> item(s) processed[ (<n> <word>, ...)]` with words of Veeam's own (`success`/`successes`, `warning(s)`, `failure(s)`, `error(s)`, `skipped`), since any other text, inside the parenthesis too, may name an item or an address) |
| `backup_item` | verified items the backup didn't report restored | `<n> verified item(s) the backup didn't report restored` |
| `duplicate` | items more than one of this run's copies matched (the newest was compared) | `<n> item(s) had more than one restored copy; the newest was checked` |
| `shortfall` | per type and half that took fewer than it wanted | `<kind> <canary\|random>: <taken> of <wanted>` |
| `stale_copies` | earlier runs' copies the check ignored | `<n> copies from earlier runs in the restore targets were ignored (mail <x>, sharepoint <y>, onedrive <z>)` |

A duplicate is a warning, never a status: the newest copy matched, so the backup delivered the
data, and a second copy points at a double write, not at lost data. A shortfall never changes
the status either; the counts by expected kind keep the claim to what was checked. An item's
own message (which may hold a name) stays in the restore result, never in a warning.

### The result's `status` object

`to_json(RunVerdict)`, by index like `expected` and `check`; every key but `error_code` (error
only) is always there. `counts.items` is always the expected set's size (0 without one). The
other counts, `verified` and the item lists are the item verdicts of rows R5 to R8; for R1 to
R4 nothing got as far as a verdict, so they are 0 and the lists empty. `restore_sent` is whether
a restore may have been sent, so items may be in the restore targets (W3.4's cleanup): a restore
result that isn't `not_run`, or a stop in the restore without `nothing_restored`. It is the
result's `status` key ("The result" below), the one section that is never `null`.

```json
{
  "status": "error", "error_code": "stale_target", "restore_sent": true,
  "message": "1 of 3 item(s) couldn't be checked (stale_target 1); 2 verified",
  "counts": {"items": 3, "verified": 2, "failed": 0, "unchecked": 1},
  "verified": {"manifest": 1, "fields": 1, "metadata": 0},
  "failed_items": [],
  "unchecked_items": [{"index": 1, "error_code": "stale_target"}],
  "warnings": [{"code": "stale_copies", "indexes": [],
                "message": "1 copies from earlier runs in the restore targets were ignored (mail 1, sharepoint 0, onedrive 0)"}]
}
```

### A listing SharePoint trimmed (Q3.2)

SharePoint doesn't always refuse a read the app lacks the grant for: it can answer 200 and leave
the files out of a listing (live, 2026-10-04, Q3.2 scenario 6). An empty listing taken at face
value would make a restored item `missing`, a `fail`. So every listing of the RestoreTarget
library and of the OneDrive folder is held to the container's own `folder.childCount`, read
first (`check_listing_whole`, `src/graph_paging.hpp`): fewer entries than counted is a
`PermissionError`, code `graph_permission`, like any refused read: a stop before the restore,
or the type's items `error` after it (I1, R7). `docs/decisions.md` 2026-10-04, Q3.2. A short
listing isn't refused at once: the count may trail a delete, so count and listing are read
again after 2 s, up to three times (`list_whole`; the PR #155 review entry).

### In `rpworker restore`

Once its run line is out, every ending prints `status <pass|fail|error>[ <code>]: <message>` on
stdout, then each warning as `warning: <code>: <message>` on stderr, and exits with the
status's code (`docs/worker-config.md`, "`rpworker restore`"). The error lines that carry an
exception's `what()` (`restore error: ...`, `check error: ...`, the "the restore had started"
note) stay on stderr as before. `rpworker test` (W3.6) runs the same pipeline and ends the
same way; its table after the check shows each item's verdict (`docs/worker-config.md`,
"`rpworker test`").

**Open** (decision W3.3): a client with no restore points is `no_restore_point`, not `fail`,
until restore point freshness is decided; finer `backup` codes need connector error
subclasses. (A canary missing from a restore point dated after it is `fail` since Q3.1, I4
and I5 above.)

## Cleaning the restore targets (W3.4)

Every run empties the three restore targets before it samples and after its status is
decided, so an earlier run's copy can't pass for this run's (or turn a mail sampled again into
`stale_target`, or an earlier Office file rewritten between this run's two reads into a false
match), and Veeam's nightly backup doesn't take the copies into the next restore point. The
decisions are `docs/decisions.md` 2026-10-02, W3.4, approved as written.

**The Cleaner.** `rp::graph::Cleaner` in `worker/include/rp/cleaner.hpp` is the only Worker
code that deletes in the tenant, and the only code that reaches `GraphClient::remove`, its one
write member: a source scan in `tests/graph_client_test.cpp` fails the build if `ListedItem`
or a `remove(` call on the client appears under `src/`, `include/` or `app/` outside
`graph_client.*` and `cleaner.*`. A `ListedItem` (a mail: mailbox and ID; a file: drive, ID
and eTag) has a private constructor and only the Cleaner's listing makes one, so only an item
just listed in a target can be deleted. `clean(before_run | after_run)` cleans all three
targets, always, whatever the run sampled, one after the other; one target's failure never
stops the others, and it never throws. It cleans everything in them: every mail in the
`restoretest` Inbox (delivered mail too: the mailbox exists only for restores) and every plain
file in the RestoreTarget library's root and alice's `/RestoreTarget` folder. Nothing it does
names or reads the canaries' RestoreTest library or `/RestoreTest` folder. It is held to 100%
line coverage like `target_guard` (`cleaner` in `worker/tools/coverage_gate.py`).

**Per target, each round:**

1. **Resolve** the target with the guard's own Graph checks (`rp/target_guard_graph.hpp`):
   `check_restore_mailbox`, `check_restore_library`, `check_restore_onedrive_folder`, worded
   "deletes only in ...; nothing was deleted". A refusal (`WrongTargetError`) is one critical
   `SECURITY: cleanup: <message>` log line through `redact()`, and the target's code is
   `target_guard`: nothing is listed or deleted in it.
2. **List** under the resolved IDs only, never a body or a download: the Inbox's messages
   (`$select=id`, `$top=100`, with `kMailPrefer`, whose `IdType` is ImmutableId), the library's root children and
   the folder's children (`$select=id,name,eTag,file,folder,package,remoteItem,root,parentReference`,
   `$top=200`). Each `@odata.nextLink` must stay on the same resource
   (`src/graph_paging.hpp`, the rules `TargetReader` uses too), and pages are bounded by
   `kMaxListPages`; a delete path never comes from a nextLink.
3. **Keep only what may be deleted.** A mail whose ID passes `is_listed_id`. A file whose
   `parentReference.driveId` is the resolved drive, whose `parentReference.id` is the folder
   (OneDrive) or whose `parentReference.path` is the drive's root (library), whose ID passes
   `is_graph_item_id` and isn't its parent's, with an eTag of 1 to 512 printable ASCII
   characters, a `file` object and no `folder`, `package`, `remoteItem` or `root` facet.
   Anything else is counted `skipped`, logged as a warning ("never deleted; left for the
   owner") and never deleted: a folder's or package's delete would take contents never listed.
   Restores never make folders.
4. **Delete** each kept item with `GraphClient::remove`: a mail by a bodiless
   `POST /users/{mailbox}/messages/{id}/permanentDelete` (straight to Recoverable Items, never
   Deleted Items, where copies would pile up and be backed up), a file by
   `DELETE /drives/{drive}/items/{id}` with `If-Match: <eTag>` (to the site recycle bin, so a
   guard bug costs a recoverable delete). 204 counts `deleted`; a 404 Graph names as
   `itemNotFound`/`ErrorItemNotFound` counts `gone`; a 412 on a file (it changed since it was
   listed, as SharePoint's Office rewrite does) leaves it for the next round. Any other
   refusal of one delete (a locked or checked-out file, a labelled mail: a 403, 409, 423 or
   any other answer that isn't transient or a refused token) is that item's: it is logged
   with its code and the other listed items are still deleted. A transient error ends the
   round and a 401 after a fresh token stops the target, as on a listing. Writes are
   retried like reads (5 attempts, a 401 gets one fresh token); a resent delete of one listed
   ID can only answer 204, 404 or 412.
5. **List again**: what is still there is `left`, the entries kept out `skipped`.

A second round runs only when the first ended with something left (a 412 included) or in a
transient error; no other error gets one, a refused delete with something left after it
included, and there is never a third. A listing reads at most
`kMaxListPages` pages (`list_pages`' bounded mode, the link past the last page checked but
never fetched): a target that holds more is cleaned up to that, logs that it lists more, and
ends with `left > 0` (the count of the last listing, so at most that many pages' worth), for
the next round or the next run's clean before; never an error, which would stop every later
clean at the same listing.

**A target's code**, when it stopped, or when a delete Graph refused in its last round left it
not emptied (the first such delete's code): `target_guard`; `graph_auth`, `graph_permission`,
`graph_transient` (in both rounds) or `graph`, as the checker's `read_error_code`; `config`
for an `rp::ConfigError` (a `CertificateError` on the token); `internal` for anything else,
whose text is never copied. A 403 on a delete names the write grant it relies on
(`docs/security/graph-permissions.md`).

**In `rpworker restore`** (`docs/worker-config.md`, "`rpworker restore`"):

- **One run at a time.** Before its first Veeam call the command takes the machine-wide named
  mutex `Global\RestoreProof-restore-targets` without waiting (`rp/run_lock.hpp`) and holds it
  until it exits; a second run is refused with exit 4 and no run line. Without it, one run's
  cleanup could delete another's copies between that run's restore and its read-back: a false
  `fail`.
- **Before**: right after the run line and before the sample is chosen, every run cleans all
  three targets. A `target_guard` on any target stops the run as `RunStop{target_guard}` in
  phase `before_restore` (row R2: `error target_guard`, exit 4, no explore session opened);
  layer 1 alone wouldn't do, since it sees only the sampled types and runs after Veeam is
  browsed. Any other failure, or leftovers, lets the run go on: the before snapshot is still
  the second guard (leftovers are `stale_copies`, a sampled mail already there is
  `stale_target`).
- **After**: in the run's ending, the status is decided and its line and warnings printed
  first, then, only when `restore_sent`, the clean after, then its line. On the normal path it
  runs after the check, so nothing is deleted before it is read; after a check that threw it
  runs too (the restore's own rows are the evidence). When the run stopped in the restore
  without `nothing_restored`, Veeam may still be writing: it runs anyway and the run's
  `restore_may_still_run` is true.
- **The cleanup never changes the status**, but through the guard refusal above: `RunFacts`,
  `decide_status`, the codes, the warnings and the exit codes are W3.3's, and
  `rp/run_status.hpp` doesn't include `rp/cleaner.hpp`. A cleanup failure is housekeeping,
  shown in the cleanup lines and `warning: cleanup: ...` lines on stderr (outside the status's
  warning vocabulary); a `pass` with `cleanup_ok: false` still exits 0.

**The result's `cleanup` object.** `to_json(RunCleanup)` in `rp/restore_command.hpp`, handed
to `RestoreCommandEnv::on_cleanup` once the run's last line is out (no result file exists yet;
W4.1 adopts it into `result.v1.json` beside `status`). Counts and codes only, never a name or
an ID; `error_code` only when set; `after` is `null` when the clean after didn't run (and
`before` when the run stopped before it):

```json
{
  "cleanup_ok": false, "restore_may_still_run": false,
  "before": {"mail": {"found": 5, "deleted": 5, "gone": 0, "left": 0, "skipped": 0, "rounds": 1},
             "sharepoint": {"found": 3, "deleted": 3, "gone": 0, "left": 0, "skipped": 0, "rounds": 1},
             "onedrive": {"found": 3, "deleted": 3, "gone": 0, "left": 0, "skipped": 0, "rounds": 1}},
  "after": {"mail": {"found": 2, "deleted": 2, "gone": 0, "left": 0, "skipped": 0, "rounds": 1},
            "sharepoint": {"found": 1, "deleted": 0, "gone": 0, "left": 1, "skipped": 0, "rounds": 1,
                           "error_code": "graph_permission"},
            "onedrive": {"found": 0, "deleted": 0, "gone": 0, "left": 0, "skipped": 0, "rounds": 1}}
}
```

`found` is the first listing's count of mails and plain files; `deleted` Graph's 204s; `gone`
its 404s for an item this call listed; `left` and `skipped` the last listing's; `rounds` 1
or 2. A target is ok with no `error_code`, nothing left and nothing skipped. **`cleanup_ok`**
is the state the run leaves the targets in: false while `restore_may_still_run`; else the
clean after's ok when it ran; else false if a restore was sent; else the clean before's ok.

**Not done by the Cleaner.** Deleted Items in `restoretest` (copies from the hand cleanups
before W3.4) is emptied once by hand; the Cleaner never reads it. Stopping our own Veeam
sessions still `Working` is W3.6's, with the same Cleaner and placements in `rpworker test`;
W3.5 times the two cleans as the spans `cleanup_before` and `cleanup_after` (`docs/decisions.md`
2026-10-03, W3.5; `cleanup_after` stays `not run` when the clean after is skipped).

## The result (`restoreproof.result.v1`, W4.1)

Every run that printed its run line has one result: one JSON document, built by
`rp::ResultBuilder` (`worker/include/rp/result_builder.hpp`) from what the run produced and
validated by `rp::validate_result` (`rp/result_schema.hpp`) against
`shared/schemas/result.v1.json`. `rpworker test --json <file>` writes it
(`docs/worker-config.md`, "`--json <file>`"), and `--evidence <dir>` writes it into the run's folder (W4.2, "The run folder" below); W4.3 to W4.6 sign, timestamp and upload it. It
replaces W3.6's `rp.run-summary.v0`. The decisions are `docs/decisions.md` 2026-10-04, W4.1,
approved as written, and its build notes.

### The seventeen keys

All seventeen are always there, and every object is closed: a key the schema doesn't name makes
the result invalid.

| Key | From | `null` when |
|---|---|---|
| `format` | `"restoreproof.result.v1"` (`rp::kResultFormat`) | never |
| `worker_version` | `rp::version()` | never |
| `run_id` | the run ID (`--run-id`, or the one the run made) | never |
| `started_at`, `ended_at` | the wall clock where the `total` span starts and ends, `YYYY-MM-DDTHH:MM:SS.mmmZ`, UTC | the wall clock failed at that reading; `ended_at` also in the result as it is first validated (below) |
| `connector` | `{type, api}` from `IConnector::describe()`, read once when the connector is made: `type` is its name (`veeam_m365`, the only one the schema knows), `api` its version | never |
| `client` | the config: `client_id` (`null` until jobs carry one, W4.10), `tenant_id` (`graph_tenant_id`), `veeam_org_name`, and `targets` `{mailbox, site_id, library_id, onedrive_drive_id, onedrive_folder_id}` (`test_mailbox`, `test_site_id`, `test_library_id`, `test_onedrive_drive_id`, `test_onedrive_folder_id`) | never (`client_id` always, today) |
| `restore_point` | `{id, backup_time_raw, backup_time}`: the chosen point's ID, Veeam's time text as it is (what an explore session needs), and that time cut to whole seconds, `YYYY-MM-DDTHH:MM:SSZ` (`to_whole_seconds`, `src/veeam_time.hpp`) | never; `backup_time` when Veeam's text doesn't parse |
| `sample` | `sampling::to_json(SampleRecord)` (W2.6) | the run stopped before the sample was chosen |
| `expected` | `verification::to_json(ExpectedSet)` (W3.1, above) | the run stopped before the expected set was built |
| `restore` | `verification::to_json(RestoreResult)` in `rp/run_status.hpp`: status, items sent and restored, sessions (ID, kind, result, `details` only when `is_backup_counts`, else `null`, `started_at_raw`/`ended_at_raw`), items `{index, kind, outcome, infrastructure, container_missing, session_id}`; no item name, no Veeam message | there is no restore result (nothing was sent, or `restore_sample` threw) |
| `check` | `verification::to_json(CheckResult)` (W3.2, above) | the check didn't run |
| `status` | `verification::to_json(RunVerdict)` (W3.3, above) | never: a run without a verdict has no result |
| `cleanup` | `to_json(RunCleanup)` (W3.4, above) | the run stopped before the clean before; `cleanup.after` when no clean after ran |
| `timings` | `timing::to_json(RunTimings)` (W3.5): `{"spans": {...}}`, all eleven | never; a span that didn't run is `null` |
| `attachments` | `to_json(std::vector<Attachment>)` (W4.2, "The run folder" below): the run folder's files beside `result.json`, `[{name, sha256, size_bytes}]`, sorted by name | no run folder is written (`restore`, `test` without `--evidence`), and in the result as it is first validated |
| `screenshot` | `to_json(Screenshot)` (W4.2): `{"state": "captured"}` or `{"state": "unavailable", "reason": <code>}` | as `attachments` |

The item rows are `expected.items[i]`, `restore.items[i]` and `check.items[i]`, joined by
`index`. Nothing is written twice: the status is `status.status`, the error code
`status.error_code`, the seed `sample.seed`, `cleanup_ok` is `cleanup.cleanup_ok`, the recovery
time `timings.spans.recovery`. There is no `command` and no `exit_code` (v0 had both): they
are facts of one process, not of the run, so a lost stdout or an incomplete `--record`
recording shows in the exit code and on stderr only. There is no `signature`, `tsa_token`,
`bundle_sha256` or `worker_id` yet; W4.3 to W4.6 and W5.1 add theirs to the schema.

### The canonical form (`canonical-json-v1`)

`rp::canonical_json` (`worker/include/rp/canonical_json.hpp`) gives the result's bytes, and the
`--json` file is exactly those bytes:

- object keys sorted by byte, `,` and `:` with no whitespace, no trailing newline;
- strings as UTF-8, with JSON's short escapes and lower-case `\u00xx` for the other control
  characters; nothing else is escaped;
- integers only, within ±(2^53 − 1);
- refused, by throwing `CanonicalJsonError` with fixed words: a floating-point number, an
  integer outside that range, an object key that isn't ASCII, a string that isn't valid UTF-8
  (never replaced by U+FFFD), a value that isn't JSON.

With those rules Python's `json.dumps(value, sort_keys=True, separators=(",", ":"),
ensure_ascii=False)` gives the same bytes. The vectors are
`shared/testdata/canonical-json-v1.json` (33 accepted cases with their text and SHA-256, 9
refusals), run by `worker/tests/canonical_json_test.cpp` and, the accepted ones, by
`cloud/tests/test_canonical_json.py`.

### The schema

`shared/schemas/result.v1.json` is the only copy. The Worker's build embeds its bytes
(`worker/cmake/embed_bytes.cmake` writes a byte array into the build folder), so the Worker
never reads a schema from disk; a test compares the embedded bytes with the file. The Cloud
reads the file by path. It says draft 2020-12 and uses only keywords draft 7 and 2020-12 read
alike, because the Worker's validator (`json-schema-validator` 2.4.0) is draft 7 and Python's
is 2020-12; a Worker test walks the schema and fails on any other keyword. No `format`
keyword: times are `pattern`s, and a time with an offset or without `Z` doesn't validate.
Patterns are only on strings the Worker makes; Veeam's words and tenant text get a `maxLength`
and nothing else, so an unknown Veeam word can't make a result invalid. The schema's enums are
held to the code by a test (`run_status`'s three lists, the kinds, outcomes, span names and
cleanup codes).

What the schema can't say, and so doesn't check: any rule across objects (counts against array
lengths, `index` equal to position, `status` against `check`), and the order of the fields in a
mismatch `reason`.

`shared/testdata/result-v1/` holds the documents both validators must judge alike: `valid.json`
(a whole pipeline run of the Worker's tests, the lab's names replaced; since W4.2 the
`result.json` of an `--evidence` run, so it lists two attachments) and `cases.json` (180
small changes to it, 45 valid and 135 invalid). `worker/tests/result_schema_test.cpp` and
`cloud/tests/test_result_schema.py` run the same file (`docs/testing.md`, "The shared vectors
and result documents").

### Validation, and `result_invalid`

**When.** Twice at most.

1. In every run of `restore` and `test`, with or without `--json`, right after the status is
   decided and before the check's table and the status line. The clean after hasn't run then:
   `ended_at` and `cleanup.after` are `null`, `cleanup_ok` and `restore_may_still_run` hold
   their defaults and the open spans read `open`, all of which the schema allows.
   `attachments` and `screenshot` are `null` too: no file of the run folder is written yet.
2. Only when a file is to be written (`test --json`, or `test --evidence`'s `result.json`):
   after the clean after and the timings, the finished result is built and validated again,
   and that text is the file. With `--evidence` the run folder's other files are written
   first, so the result that is validated lists them.

What is validated is the canonical text parsed back, so it is the written text that validated.
`validate_result` refuses one thing itself, before the schema's validator is asked: an unsigned
integer too large for a signed 64-bit value, one violation at its place. The validator library
would read it as a negative number and could find it inside a range; every integer of the
schema ends at 2^53 - 1, so the schema refuses it too (`docs/decisions.md`, build notes
point 11).

**The first time fails:** the result can't be built (a part's `to_json` throws), has no
canonical form, or the schema refuses it. The verdict becomes `error result_invalid`, exit 1
(the status table's "Error codes" above). stderr gets one of these lines, before anything on
stdout says `pass`:

```
result error: <n> schema violation(s), first at <JSON pointer>
result error: <n> schema violation(s)
result error: the result has no canonical form
result error: the result couldn't be built
```

The pointer is there only when each of its parts is a property name of the schema or an array
index; never the validator's message, never a value. The run goes on: the check's table (in
`test`, VERDICT `-` in every row), one status line, for a run that would have passed

```
status error result_invalid: the result isn't valid restoreproof.result.v1; the run itself ended pass
```

then the warnings, the clean after when a restore was sent, and the timings.

**The second time fails** (the first passed): new since then are only `cleanup.after` with its
two flags, the closed spans and `ended_at`, all Worker-made, so this is a Worker bug (or a
wall clock past the year 9999, which is how the test reaches it). The status line is already
out and stays. stderr gets the `result error` line, and exit 0 becomes 1; any other exit code
is kept.

**No file.** An invalid result is never written under this format, and no cut-down one is
made up. With `--json`, in both cases, after the timings:

```
json error: <file>: the result isn't valid restoreproof.result.v1; no file was written
```

The same line stands for a run with no verdict at all (the status table itself threw: `error:
unexpected failure`, exit 1).

### A check item's `reason`

Fixed words, held by the schema to four forms. A `match` has no `reason`.

| Outcome | `reason` |
|---|---|
| `error`, the target's read failed | `the <mail\|sharepoint\|onedrive> restore target couldn't be read (<code>)`, the code one of `graph_auth`, `graph_permission`, `graph_transient`, `target_guard`, `graph` |
| `error` `stale_target` | `only an earlier run's copy is in the target` |
| `missing` | `no restored copy found` |
| `mismatch` | `fields did not match: <field>, ...` (the fields of `mismatches`, in its order), ending `; the restored package isn't valid office-v1 input` when office-v1 refused the copy |

Until W4.1 the office-v1 tail carried the zip reader's own text in a parenthesis, which names
a part inside a tenant file: the one place an exception's text reached the file. It doesn't
any more; the check reads `OfficeHash::error` only as set or not. The reader's text goes to
stderr alone, one line per refused file after the read back (`check note: <sharepoint|onedrive>
<name>: not valid office-v1 input: <text>`, through `redact()`), so one of the reader's own
limits can be told from a broken file (`docs/decisions.md` 2026-10-05, "W4.1 code review").

### What of the tenant the result holds

No secret, and no exception's text. But more tenant data than stdout:

- `client`: the tenant ID, the organisation's name, the test mailbox's address and the four
  target IDs;
- `expected.items`: subjects, sender addresses and names, Internet message IDs, sent and
  received times, and file names;
- `sample.*.random.keys`: mailbox addresses, folder names and paths, mail subjects and
  received times, site and list IDs, file names and OneDrive UPNs (`random_key`);
- `sample.*.random.containers_listed`: the mailboxes, sites and OneDrives the draw looked
  into, sampled or not (for an unresolved OneDrive, its URL).

W4.1 keeps them: the Cloud's item rows and the report's Failures section need the item names,
and the keys are what lets a draw be repeated. Today the file stays where the owner put it:
keep it out of the repository. That ends with W4.6, which uploads the result; whether the
random keys and `containers_listed` leave the network as they are, or are cut to counts and
`pool_sha256` first, is still open (`docs/decisions.md` 2026-10-04, W4.1, Open). It must be
settled before W4.3 signs the first result, not before W4.6 uploads it: a signed result is
never edited (`docs/decisions.md` 2026-10-05, W4.2 point 10).

## The run folder (W4.2)

`rpworker test --evidence <dir>` leaves one folder per run, `<dir>\<run_id>\`, made by
`rp::EvidenceBuilder` (`worker/include/rp/evidence_builder.hpp`). The decisions are
`docs/decisions.md` 2026-10-05, W4.2, approved as written; the command's lines and exit codes
are in `docs/worker-config.md`, "`--evidence <dir>`". Nothing here changes a run's status.

| File | From | Listed in `attachments` |
|---|---|---|
| `items.csv` | `EvidenceBuilder::items_csv`: the expected set, the restore result, the check and the verdict | always |
| `veeam-session.log` | `EvidenceBuilder::session_log`: `connector::RestoreResult::log` | always |
| `screenshot.png` | a capturer (`RestoreCommandEnv::capture_screenshot`), when it captured one | when it is there |
| `result.json` | the finished result's canonical text | never: a file can't hold its own hash |

### The order, and what a folder without `result.json` means

1. The folder is made when the run ID is known, before the run line: one call that makes it
   or finds something there, so a folder is never taken over from another run. Every run with
   a run line has had its folder from the start. Until that line is out the folder is
   `rp::RunFolder`'s, which takes it away again whichever way the run ends, and with it each
   level of the runs root that was made for it (only while empty): a run refused here, or one
   whose run line can't be printed, leaves nothing.
2. At the end, after the clean after and the timings: `items.csv` and `veeam-session.log` are
   written (both always; each is tried even when the other failed).
3. When both are written, the screenshot is asked for (below).
4. Each attachment's SHA-256 and size are taken from the bytes that were written (the
   screenshot's from the bytes read back), and the finished result is built with
   `attachments` and `screenshot` and validated.
5. The result's strings are looked through for the run's secret values ("No secret in the
   folder" below). One that holds one stops here: `the result holds a secret value`, no
   `result.json`.
6. Each attachment is read back and compared with its hash and size. One that is gone or
   differs stops here: `changed after it was hashed`, no `result.json`.
7. `result.json` is written, exactly the canonical text that validated.

So `result.json` is there only when the folder is complete, and a folder without it is a run
with no result: `error result_invalid`, a finished result that isn't valid or holds a secret
value, no verdict, a file that couldn't be written, or a process that ended in between. No
cut-down result is written
for any of these (W4.1 point 5 stands). What the service reports to the Cloud for such a run
is W4.8's question.

W4.3 signs the result. Through `attachments` its signature then covers the other files; until
then nothing but the read back in step 6 holds them.

### `attachments` and `screenshot`

`attachments` is `null` without a run folder, else two or three `{name, sha256, size_bytes}`,
sorted by `name`; `name` is one of `items.csv`, `screenshot.png`, `veeam-session.log`. The
schema's keyword subset can't say "each name once" or "in this order"; the builder's tests do.

`screenshot` is `null` without a run folder, else one of:

| `screenshot` | Meaning |
|---|---|
| `{"state": "captured"}` | `screenshot.png` is among the attachments |
| `{"state": "unavailable", "reason": "disabled"}` | `screenshots_enabled` is off; the capturer wasn't asked |
| `... "reason": "no_page"` | no page shows the restore session without an interactive sign-in; also a run with no restore session (it stopped before the restore, or the restore sent nothing), for which the capturer isn't asked |
| `... "reason": "no_browser"`, `"login_required"`, `"timeout"` | a capturer's own answer |
| `... "reason": "failed"` | the capturer threw, or said it captured and left no file, a file over 10 MiB, one that can't be read whole (a read that stops short, or a file still growing), or one that doesn't start with the PNG signature; what it left is removed |

**No screenshot is taken today.** The default capturer (`rp::no_screenshot_page`) answers
`no_page` and starts no browser. Veeam's only page with restore sessions is the Restore
Portal: it signs in through Microsoft's interactive page, and the REST service's certificate
is self-signed with no host name, which a browser shows as an error unless certificate checks
are turned off, and they never are. The other reasons and `captured` are reached only by the
tests' capturers. A picture drawn from the session's JSON was rejected: it would be the
Worker's own rendering under Veeam's name.

### `items.csv`

UTF-8 without a BOM, LF, a header row, one row per expected item in `index` order:

| Column | What it holds |
|---|---|
| `index` | the item's index: `expected.items[i]`, `restore.items[i]` and `check.items[i]` in the result |
| `type`, `source` | `mail`, `sharepoint` or `onedrive`; `canary` or `random` |
| `canary_id` | a canary's ID in the manifest; empty for a random item |
| `name` | the expected subject or file name |
| `expected_kind` | `manifest`, `fields` or `metadata` |
| `sha256_rule`, `expected_sha256` | a `manifest` item's rule (`text-v1`, `bytes`, `office-v1`) and hash; empty otherwise |
| `found_sha256` | the compared copy's hash by that rule, for an item that carries an expected hash only; empty otherwise, and when the copy has no hash by that rule |
| `restore_outcome` | the backup's word for the item: `restored`, `failed`, `unknown`, `not_in_backup` |
| `found`, `outcome`, `mismatches` | the check: `yes`/`no`; `match`, `mismatch`, `missing`, `error`; the mismatched fields joined by commas |
| `verdict`, `code` | `verified`, `failed` or `unchecked` with its code, when the item verdicts decided the run; `-` otherwise (as `rpworker test`'s VERDICT) |
| `ms` | the item's milliseconds when found |

`index` and `ms` are bare numbers. Every other cell is in double quotes, a `"` inside doubled,
each control character a space, so a row is one line whatever a subject holds. A cell of a
step that didn't run is empty; a run that stopped before its sample has the header alone.

- **A found hash only for a canary.** A canary's content is ours, so its hash says nothing of
  the tenant. The SHA-256 of a real mail's body is never written, though the read back
  computes it: a short body can be confirmed from its hash. A random item is checked by its
  fields or its metadata, not by a hash, so there is none to show. `ItemCheck::found_sha256`
  carries it; `check`'s `to_json` never writes it, and the result still holds no found value.
- **A name can't run as a formula.** A `name` that starts with `=`, `+`, `-` or `@` is
  written with a `'` before it. The CSV's `name` is for reading; the exact one is the
  result's, joined by `index`.
- No found subject, sender, time or Graph ID, no random key, no container, no Veeam message.

### `veeam-session.log`

`RestoreResult::log` as the connector made it, each line ending in LF: per restore session
`session <id> (<kind>): <result>, <details>`, then one line per restore event and per event
that isn't a success, `<status> <item name>: <Veeam's message>`. Each line was cut to one line
of at most 500 bytes and passed through `redact()` by the connector. It is the one file of the
folder in Veeam's own words, and it holds tenant names the result doesn't: Veeam's message
names the item's source folder or path, a mailbox's display name and the target's address or
URL, and a failure's message is free text. Empty when there is no restore result, also when
`restore_sample` threw after a session ran.

### No secret in the folder

`redact()` masks keyed secrets, JWTs and `Bearer` tokens, not a bare secret in prose. So the
builder is also given the run's secret values (the Veeam password, the Graph PFX and its
password): a log line that holds one is written as `[withheld: held a secret value]`, a CSV
row that holds one keeps its `index`, has those words as its `name` and nothing else, and one
`SECURITY: evidence: <n> line(s) held a secret value and were withheld` line is logged. The
restore's per-run PFX password never leaves the connector. W4.9's sentinel test is still to
come.

The result names every sampled item, so a subject or a file name that a CSV row was withheld
for is in `expected.items` too, and the result can't be cut: it is validated, hashed and, from
W4.3, signed as it is. So before `result.json` is written, every string of the finished result
is looked through for the same values, as JSON reads them (in the text an escaped `"` or `\`
would hide one). A result that holds one is not written: `evidence error: <folder>: the result
holds a secret value; no result.json was written` on stderr, one `SECURITY: evidence: the
result held a secret value; no result.json was written` log line, the status unchanged, exit 0
becoming 1. The two text files stay, with their withheld lines.

The match is on the whole value, anywhere in a string. A secret that is also a word of the
result (a Veeam password of `pass` or `mail`) would therefore stop every run's `result.json`;
a real password isn't one. Not covered: stdout, where `rpworker test`'s table shows each
item's name as it is, and `--json`, which writes the result to a file the operator names.
