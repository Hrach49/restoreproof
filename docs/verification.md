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

There are four kinds, one per item, never mixed, and no "unknown" kind:

| Kind | Items | Expected values | Content hash |
|---|---|---|---|
| `manifest` | canaries | from `lab/seed-manifest.json`. Mail: subject, sender address, sent and received time, internet message ID. File: name, and `stored_size` for a `bytes` file | yes: a mail's `body_sha256` by `text-v1`; a file's `content_sha256` by its `content_rule`, `bytes` or `office-v1` |
| `fields` | random mails | from the backup's own listing (Veeam's browse): subject, received time, and the sender's display name and sent time when Veeam lists them | no: nothing knows the body before the restore |
| `metadata` | random files the backup didn't export (W6.3: no content rule, or the export gave nothing) | from the backup's own listing: the name, and the size Veeam lists unless the file is an Office package | no |
| `backup_content` | random files the backup exported before the restore (W6.3) | the name, and the hash of the exported bytes by the file's rule: `bytes` (with the export's size) or `office-v1` (no size: SharePoint rewrites the package) | yes: from the backup's own copy, known before the restore |

- **Random items are expected from the backup, not from Graph.** The Worker app may read only
  the restore targets, never a source, so the backup's listing is the only place a random
  item's expectation can come from. W6.1 (2026-10-14, `docs/api/veeam-notes.md` §12) showed
  that Veeam's document export works in admin mode for SharePoint and OneDrive and gives the
  restored copy's bytes; W6.3 builds the fourth kind from it (below, "A random file's content
  against the backup's copy").
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

### A random file's content against the backup's copy (W6.3)

`docs/decisions.md` 2026-10-14, "W6.3 (#183) and W6.2 (#182)", approved as written; the code is
`rp/backup_content.hpp`.

- **Which files ask.** Every random file whose name has a content rule
  (`verification::content_rule`): `office-v1` for a name ending, in any ASCII case, in `.docx` or
  `.xlsx`; none for every other name of the rewritten Office family below (pptx, legacy Office,
  the macro and template types), which stay `metadata` with the word `no_rule` until a rule
  exists; `bytes` for every other name. Canaries never ask (the manifest's hash is the
  expectation) and mails never do (no body check: a spike of its own if wanted).
  `verification::mark_wanted` sets `want_content` on those selectors of the spec.
- **The export.** The connector exports each of them inside its own explore session of the
  type, after every item is found and before the first restore request, one attempt and never
  resent (`POST …/Documents/{id}/save` with `{"asZip":false}`, `Accept: */*`, 60 s per file, 15
  minutes for all of a run's exports, the bytes at most 64 MiB, the read back's own cap). The
  answer must be 200 `application/octet-stream` with as many bytes as Veeam listed. The bytes go
  to the pipeline's `ContentHasher`, which keeps their SHA-256 (and `office-v1` for a docx or
  xlsx) and drops them; nothing of a file's bytes is written anywhere: `--record` keeps an
  export's answer as its size and SHA-256 alone (`veeam_recorded_body`, the W6.3 review's finding
  1), never as content. An empty 401 is not resent, but the token it was sent with is dropped, so
  the next request signs in afresh rather than carry a token a Veeam REST restart killed to every
  export left (finding 5).
- **The words.** Each random file's expectation carries `export`: `exported`, `no_rule`,
  `refused` (any other answer, a 401 too), `no_answer` (a transport failure or the timeout),
  `size_mismatch`, `over_cap`, `invalid_package` (an exported docx or xlsx `office-v1` refused),
  `not_in_backup` (the restore point doesn't hold the item: never asked), `budget` (the run's 15
  minutes were spent: never asked). Only an `exported` file with its digest is `backup_content`,
  and a `metadata` file is never `exported`: the C++ consistency check and the schema both refuse
  it (finding 6).
- **The raise.** Once `restore_sample` returns, and before anything is read back,
  `verification::add_backup_content` raises each exported file with its digest to
  `backup_content`; every other random file stays `metadata` with its word, checked by its name
  and listed size as before. The expectation still comes from the backup, never from what the
  read back finds, and it is on record in the result's `expected` before the check runs. Facts
  that don't add up (an export for a file that isn't a random one of the set, a file with a rule
  and no export) are the Worker's fault, a stop in the check phase, `error internal`.
- **An export's own fault is never a `fail` and never an `error`.** The status table has no new
  row and no new code: a `backup_content` item is `match`, `mismatch`, `missing` or `error` like
  any other, so a restored copy whose bytes differ is a `mismatch` on `sha256` and the run is
  `fail`. When an export gives nothing, the file is `metadata`, and the `content_export` warning
  names it; when every export failed, a run whose names and sizes are right is `pass` with
  `verified.backup_content` 0 and the warning, so the result never claims the content was
  checked. The warning counts the files whose size was compared apart from those checked by name
  alone (a docx or xlsx carries no size), and names an `invalid_package` file by that word: its
  export worked, its package didn't (finding 4).
- **The time.** The exports run inside `restore_sample` but restore nothing: their time
  (`RestoreResult::content_time`) is the span `content_export`, and is left out of `restore`,
  `recovery` and the restore line's elapsed time (`StepTimer::delay_start`, held to the restore's
  own span), so the recovery time a report prints never holds them (finding 2). A run that asked
  for no export has `content_export` not run (`null`); one that asked and has no time from the
  connector, or that stopped after its restore began, has it not reported.

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
out, never `null`; `manifest_sha256` is there exactly when the run had canaries (W6.2: the
schema refuses an item of kind `manifest` without it); `counts` always has all four kinds, so a report can say "n of m items
checked against a known hash" without recounting (W4.1 adopts it into `result.v1.json`). It
writes nothing for an item whose fields don't back its kind (`manifest` without a canary ID, a
lower-case hex hash and its type's rule; `fields` or `metadata` with a hash, a canary ID or no
key, or for the other type; an item out of its index), so an item built elsewhere (W3.2, W4.1)
can't read as checked against a hash it hasn't. `build_expected_set` also refuses a record
whose `random_taken` or `canary_wanted` isn't what the selection holds.

```json
{
  "manifest_sha256": "<64 hex>",
  "counts": {"manifest": 3, "fields": 2, "metadata": 1, "backup_content": 1},
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
     "key": ["<site id>", "<list guid>", "/", "Deck.pptx"], "name": "Deck.pptx", "export": "no_rule"},
    {"index": 6, "kind": "sharepoint", "source": "random", "expected_kind": "backup_content",
     "key": ["<site id>", "<list guid>", "/", "Plan.pdf"], "name": "Plan.pdf", "size_bytes": 899,
     "sha256": "<64 hex>", "sha256_rule": "bytes", "export": "exported"}
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

**Not checked in Stage 1.** The content of a random file the backup didn't export (W6.3: it is
`metadata`, by name and size). A pptx,
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

Since W4.8 a verdict can be replaced once more, before the result is built: by `interrupted`.
When the Worker was asked to stop before the table decided, and the row gave an `error` whose
code is none of `interrupted`, `target_guard` and `result_invalid`
(`verification::interrupt_replaces`), the verdict becomes `verification::interrupted(verdict)`:
status `error`, code `interrupted`, keeping and clearing what `result_invalid()` keeps and
clears. A `pass` or a `fail` reached in spite of the stop stays what it is, and so does every
verdict decided before the stop came. See "A stop during a run" under "A result written
afterwards" below. The test rows are N1 to N8.

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
twenty-two since W4.11, which added `client_mismatch` and `connector_unknown` at the table's
end (`docs/decisions.md` 2026-10-09, W4.11 point 4); twenty since W4.8. W4.1 made it eighteen: `restore_contradiction`, R6's own code, was outside
the table before (exit 4 then as now), and `result_invalid` was new. Neither can be a stop's
code or a check item's: given as one, it is R1's `internal`. W4.8 added two at the table's
end, in this order (`docs/decisions.md` 2026-10-08, W4.8 point 14): `interrupted`, a stop's
code (stop text `the run was interrupted`) and never a check item's, and `job_invalid`, which
is neither a stop's code nor an item's and, given as a stop's, is R1's `internal` too. The
schema's enum only grew at its end, so every result signed before stays valid; a verifier
that holds the older schema answers `result_schema` for a result with a new code, which is why
the schema travels with the verifier (`--schemas`). Three public lists give the vocabulary to the result's
schema, and a test holds the schema's enums to them: `error_codes()` (the table's order),
`unchecked_item_codes()` (most severe first) and `warning_codes()`. A Graph exception's code is the checker's
`read_error_code` wherever it is thrown, the restore-target guard's layer 1 inside
`restore_sample` included, which lets Graph's errors out as Graph's.

| Code | From | Exit |
|---|---|---|
| `config` | `rp::ConfigError` (`graph::CertificateError` too), `sampling::ManifestError` (the manifest's tenant, since W4.11 in the client check), in any phase (in the read-back too: a stop, never an item error) | 1 |
| `internal` | any other exception (its `what()` is never shown); facts that don't add up (R1); a result written afterwards for a run that returned and left its folder without one (`ended_without_result()`, W4.8) | 1 |
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
| `interrupted` | `connector::Interrupted`, in any phase: a stop asked of the Worker during the run (a stop found at a step's boundary, a restore request withdrawn, the restore's poll left), or a run that couldn't be put on record as started; an `error` decided after a stop (`interrupted()`, after the table); a result written afterwards for a run the process ended during (`interrupted_before_result()`). No service's fault (W4.8) | 4 |
| `job_invalid` | a job the service was handed that is no valid job (`job_invalid()`, W4.8): never decided by the table, only ever in a result written afterwards | 1 |
| `client_mismatch` | `rp::ClientMismatchError` (W4.11): the client check found the backup's organisation isn't the profile's (its type isn't `Office365`, its tenant ID is missing or isn't `graph_tenant_id`, or its region isn't `Worldwide`); a stop before the restore, never an item's; a stop pending while it was decided doesn't replace it | 4 |
| `connector_unknown` | `connector::UnknownConnectorError` (W4.11; `config` before): a connector type the registry doesn't have. The pipeline meets it before its run line, so as a status it only ever comes from a result written afterwards, for a job asking for a connector this Worker lacks (`connector_unknown()`, the service's J3b) | 1 |
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
| R8 | `<n> of <n> item(s) verified: manifest <a>, fields <b>, metadata <c>, backup_content <d>` |
| `result_invalid` | `the result isn't valid restoreproof.result.v1; the run itself ended <pass\|fail\|error <code>>`: the replaced verdict's status and code, never its message (a code outside the table isn't repeated: `... ended error`) |
| `interrupted`, a stop (R2) | R2's messages with the reason `the run was interrupted`: `the run stopped before the restore: the run was interrupted (interrupted); nothing was restored`, and so on by phase |
| `interrupted`, replacing an `error` | `the Worker was stopped during the run; the run itself ended error <code>` (`interrupted(verdict)`: the words as `result_invalid` writes them, so `pass`, `fail` or `error <code>` of whatever verdict it is handed, a code outside the table not repeated; the pipeline hands it an `error` only) |
| `interrupted`, written afterwards | `the run was interrupted before its result was written; no restore request had been sent`, or `the run was interrupted before its result was written; a restore request may have been sent, so items may be in the restore targets` (`interrupted_before_result(restore_requested)`) |
| `internal`, written afterwards | `the run ended without a result the Worker could write; this result was written afterwards` (`ended_without_result(restore_requested)`) |
| `result_invalid`, written afterwards | `result_invalid`'s own message, naming how the run had ended (`result_invalid_afterwards(status, code, restore_requested)`; an ending that isn't known is `... ended error`) |
| `job_invalid` | `the job isn't a valid job (<key>); nothing was done` (`job_invalid(key)`): `<key>` is the jobs reader's word for the first key at fault, a key of the job's format or `unknown key`, never text taken from the job |
| `client_mismatch`, a stop (R2) | R2's message with the reason `the backup's organisation doesn't match the client's profile`: `the run stopped before the restore: the backup's organisation doesn't match the client's profile (client_mismatch); nothing was restored`. Which of the three facts was wrong is on stderr and in the log (`client error: client mismatch: ...`), never in the message |
| `connector_unknown`, written afterwards | `the job's connector type isn't one this Worker has; nothing was done` (`connector_unknown()`); as a stop's code (never reached today) R2's message with the reason `the connector type isn't one this Worker has` |

The makers of those rows are in `rp/run_status.hpp` beside `result_invalid()`, so the words
live with the codes. The four that make a result written afterwards
(`interrupted_before_result`, `ended_without_result`, `result_invalid_afterwards`,
`job_invalid`) give a verdict that says nothing of items: every count 0, no failed or
unchecked item, no warning; `restore_sent` is the run record's `restore_requested`, and always
false for `job_invalid`. The test rows are E19 (`Interrupted` in each phase), X21 and X22 (the
exit codes) and A1 to A10 (the makers).

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
| `content_export` | W6.3: random files whose export from the backup was asked for and that couldn't be compared with the backup's copy (`refused`, `no_answer`, `size_mismatch`, `over_cap`, `budget`, and `invalid_package`, an exported docx or xlsx `office-v1` refused; never `no_rule` or `not_in_backup`), its indexes those files | `<n> of <m> file(s) couldn't be compared with the backup's own copy (<word> <k>, ...): <s> checked by name and size alone, <t> by name alone` |

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
  "verified": {"manifest": 1, "fields": 1, "metadata": 0, "backup_content": 0},
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

## The client check (W4.11)

Before anything is cleaned, sampled or restored, the Worker holds the run's client profile
(`rp::ClientProfile`: a job's `client`, `--profile-file`'s, or the config's eight client keys)
to facts Veeam and Graph report. The decisions are `docs/decisions.md` 2026-10-09, W4.11; the
rule is `rp::check_client` in `worker/include/rp/client_check.hpp` (strict, 100% line), the
step is `check_client_step` in `src/run_pipeline.cpp`, right after the run line and its
record (W4.8's `on_run_started`) and before the clean before. In order, the first failure
ending the run as a `before_restore` stop with its code, nothing cleaned, no explore session,
nothing restored, the result signed and queued as any run's:

| Step | What is checked | Failure |
|---|---|---|
| (a) the organisation | `IConnector::client_facts(veeam_org_name)` (Veeam: the organisation found by name, its `type`, `msid` and `region` as sent) against the profile: `type` is `Office365`, `msid` is there and is `graph_tenant_id` (ASCII case-insensitive), `region` is `Worldwide`, in that order | `error client_mismatch` (exit 4); stderr `client error: client mismatch: <reason>; nothing was restored` with the reason `the backup's organisation isn't of type Office365 (<type>)`, `the backup's organisation reports no tenant ID`, `the backup's organisation's tenant ID isn't the profile's graph_tenant_id` or `the backup's organisation's region isn't Worldwide (<region>)`; `<type>` and `<region>` Veeam's words, printable ASCII only, at most 64 bytes, `none` when empty; never a tenant ID. The connector's own failure to say the facts is the backup's code (`backup_transient`, `backup_auth`, `not_in_backup` for a client Veeam doesn't know) |
| (b) the manifest | the canary manifest's `tenant_id` is the profile's `graph_tenant_id` (`sampling::check_manifest_tenant`); until W4.11 checked before the run line, so a job of another tenant was never reported | `error config` (exit 1); stderr `client error: canary manifest: /tenant_id: isn't the client's tenant (graph_tenant_id); nothing was restored` |
| (c) the targets | the three identity checks of `rp/target_guard_graph.hpp` (`check_restore_mailbox`, `check_restore_library`, `check_restore_onedrive_folder`) on the run's own Graph client, which signed in as the profile's tenant and app, with the guard's wording | the Graph codes: `target_guard` for a `WrongTargetError` (one `SECURITY: client check: ...` log line), else `graph_auth`, `graph_permission`, `graph_transient` or `graph` by `read_error_code`; stderr `client error: <Graph's message>; nothing was restored` |

On success one stdout line between the run line and the clean before's:
`client ok: tenant <tenant ID>, Office365, Worldwide; mailbox, library and folder resolved`.
The guard still resolves every target per item inside `restore_sample` (W2.7) and the clean
before still resolves each target before it deletes (W3.4): the step adds one organisation
list (the one `list_restore_points` already made, kept by the connector) and three GETs, and
makes every failure of a target to resolve a stop before any delete. The Graph token has been
the profile's tenant's since W4.10, for the guard's client and the run's own alike. The result
of a run that got past the step says `client.scope` `same_tenant` and `client.resolved`
(below); a run that stopped in or before it says `null` for both (the schema refuses one
without the other), and so does every result
written afterwards. A job whose connector type this Worker lacks never reaches the step: the
service reports it as `error connector_unknown` (`docs/worker-config.md`, "The jobs file",
J3b).

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
  until its clean after is over (what follows, the wait for a TSA included, needs no target);
  a second run is refused with exit 4 and no run line. Without it, one run's
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
  without `nothing_restored`, Veeam may still be writing: the clean after is skipped, the
  line is `cleanup after skipped: the restore may still be running; the next run cleans
  before`, and the run's `restore_may_still_run` is true. Nothing is cleaned under a restore
  that may still be writing. This amends W3.4, under which the clean after ran anyway
  (`docs/decisions.md` 2026-10-08, W4.8 point 9), for `rpworker restore` and `test` at a
  prompt too. The next run's clean before takes up what is left; in the service the hold
  waits for Veeam first and then makes the clean the run never made (below).
- **The cleanup never changes the status**, but through the guard refusal above: `RunFacts`,
  `decide_status`, the codes, the warnings and the exit codes are W3.3's, and
  `rp/run_status.hpp` doesn't include `rp/cleaner.hpp`. A cleanup failure is housekeeping,
  shown in the cleanup lines and `warning: cleanup: ...` lines on stderr (outside the status's
  warning vocabulary); a `pass` with `cleanup_ok: false` still exits 0.

**The result's `cleanup` object.** `to_json(RunCleanup)` in `rp/restore_command.hpp`, handed
to `RestoreCommandEnv::on_cleanup` once the run's last line is out (no result file exists yet;
W4.1 adopts it into `result.v1.json` beside `status`). Counts and codes only, never a name or
an ID; `error_code` only when set; `after` is `null` when the clean after didn't run: nothing
was restored, or, since W4.8, the restore may still be running (`restore_may_still_run` true,
`cleanup_ok` false); `before` is `null` when the run stopped before it:

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

**The clean a run never made (W4.8).** In the service, a run whose restore may still be
running keeps its record (`running.json`), and no job starts while it does. The loop looks at
Veeam's sessions until nothing of that run is running any more (the hold) and then cleans the
restore targets once: `rp::clean_restore_targets` beside `run_pipeline`, under the run mutex,
with the vault's Graph certificate, the same Cleaner over the targets of the record's own
profile (W4.10; never the config's client keys). It is the
Cleaner's `before_run` clean, unchanged, and its line is the clean before's (`cleanup before
ok|incomplete: ...`), logged after `recovery clean for <run_id>:`. It is made only when a
restore request is on record (W4.8 also compared the config's client with the record's and
wrote `the config's client is not the run's; the restore targets were not cleaned`; since
W4.10 the record's profile names the targets and that line is gone). Whatever it answers, the
record goes and jobs run again: every run cleans before anyway. This clean is in no result:
the run's own result was written before it, with `cleanup.after` `null`. The hold, its lines
and the operator's way out are in `docs/worker-config.md`.

## The result (`restoreproof.result.v1`, W4.1)

Every run that printed its run line has one result: one JSON document, built by
`rp::ResultBuilder` (`worker/include/rp/result_builder.hpp`) from what the run produced and
validated by `rp::validate_result` (`rp/result_schema.hpp`) against
`shared/schemas/result.v1.json`. `rpworker test --json <file>` writes it
(`docs/worker-config.md`, "`--json <file>`"), and `--evidence <dir>` writes it into the run's
folder (W4.2, "The run folder" below) and signs it there (W4.3, "The signature" below); W4.4
to W4.6 timestamp and upload it. It
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
| `connector` | `{type, api}` from `IConnector::describe()`, read once when the connector is made: `type` is its name (`veeam_m365`; since W4.11 the schema holds `type` to the registry's name rule, 1 to 64 of `a-z`, `0-9` and `_`, not to one word, since a result written afterwards for a job asking for a connector this Worker lacks names the type the job asked for), `api` its version | never |
| `client` | the run's client profile (W4.10, `rp::ClientProfile`: a job's `client`, `--profile-file`'s, or the config's eight client keys), as `rp::result_client` cuts it: `client_id` (the job's, the Cloud's label for the client; `null` at a prompt), `tenant_id` (`graph_tenant_id`), `veeam_org_name`, and `targets` `{mailbox, site_id, library_id, onedrive_drive_id, onedrive_folder_id}` (`test_mailbox`, `test_site_id`, `test_library_id`, `test_onedrive_drive_id`, `test_onedrive_folder_id`); not the app's ID, which the profile holds and the result doesn't. Since W4.11 also `scope` and `resolved`: `scope` is `"same_tenant"` exactly when the client check passed ("The client check" above), and `resolved` is then `{organization {name, tenant_id, type, region} (Veeam's four texts as sent), mailbox {inbox_id}, library {name, list_id, site_url}, onedrive_folder {name, site_url}}`, the names and URLs the targets resolved to at run time (the two `name`s are `RestoreTarget` by the checks' own rule); both `null` when the run stopped in or before the check, and in every result written afterwards. The claim and what earned it, together or neither | never (`client_id` at a prompt; `scope` and `resolved` when the check didn't pass) |
| `restore_point` | `{id, backup_time_raw, backup_time}`: the chosen point's ID, Veeam's time text as it is (what an explore session needs), and that time cut to whole seconds, `YYYY-MM-DDTHH:MM:SSZ` (`to_whole_seconds`, `src/veeam_time.hpp`) | never; `backup_time` when Veeam's text doesn't parse |
| `sample` | `sampling::to_json(SampleRecord)` (W2.6) | the run stopped before the sample was chosen |
| `expected` | `verification::to_json(ExpectedSet)` (W3.1, above) | the run stopped before the expected set was built |
| `restore` | `verification::to_json(RestoreResult)` in `rp/run_status.hpp`: status, items sent and restored, sessions (ID, kind, result, `details` only when `is_backup_counts`, else `null`, `started_at_raw`/`ended_at_raw`), items `{index, kind, outcome, infrastructure, container_missing, session_id}`; no item name, no Veeam message | there is no restore result (nothing was sent, or `restore_sample` threw) |
| `check` | `verification::to_json(CheckResult)` (W3.2, above) | the check didn't run |
| `status` | `verification::to_json(RunVerdict)` (W3.3, above) | never: a run without a verdict has no result |
| `cleanup` | `to_json(RunCleanup)` (W3.4, above) | the run stopped before the clean before; `cleanup.after` when no clean after ran |
| `timings` | `timing::to_json(RunTimings)` (W3.5): `{"spans": {...}}`, all twelve (W6.3's `content_export`, the exports' time, left out of `restore` and `recovery`; `null` when none was asked, `{"note": "not_reported"}` when asked and not measured) | never; a span that didn't run is `null` |
| `attachments` | `to_json(std::vector<Attachment>)` (W4.2, "The run folder" below): the run folder's files that the result covers (never `result.json` or `signature.json`), `[{name, sha256, size_bytes}]`, sorted by name | no run folder is written (`restore`, `test` without `--evidence`), and in the result as it is first validated |
| `screenshot` | `to_json(Screenshot)` (W4.2): `{"state": "captured"}` or `{"state": "unavailable", "reason": <code>}` | as `attachments` |

The item rows are `expected.items[i]`, `restore.items[i]` and `check.items[i]`, joined by
`index`. Nothing is written twice: the status is `status.status`, the error code
`status.error_code`, the seed `sample.seed`, `cleanup_ok` is `cleanup.cleanup_ok`, the recovery
time `timings.spans.recovery`. There is no `command` and no `exit_code` (v0 had both): they
are facts of one process, not of the run, so a lost stdout or an incomplete `--record`
recording shows in the exit code and on stderr only. There is no `signature`, `tsa_token`,
`bundle_sha256` or `worker_id`, and no signature field will come: the signature is a file
beside the result, and nothing is removed from the result before it is hashed (W4.3, "The
signature" below; the shared case `signature-not-in-the-schema-yet` stays invalid). The
timestamp will be a file of its own too (W4.4). `worker_id`, if W5.1 wants it signed, would be
one more nullable key.

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
refusals), run by `worker/tests/canonical_json_test.cpp` and by
`cloud/tests/test_canonical_json.py`, which since W4.3 runs them on the Python canonicaliser in
`shared/tools/verify_bundle.py` (`parse_strict`, `canonical_json`): the accepted cases byte for
byte, the refusals by their reason.

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
`result.json` of an `--evidence` run, so it lists two attachments) and `cases.json` (185
small changes to it, 47 valid and 138 invalid; the last two, valid, are results written
afterwards, W4.8). `worker/tests/result_schema_test.cpp` and
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

- `client`: the job's `client_id`, the tenant ID, the organisation's name, the test mailbox's
  address and the four target IDs (the profile's, W4.10; not the app's ID); and, when the
  client check passed (W4.11), `client.resolved`: the organisation's name, tenant ID, type and
  region as Veeam sent them, the mailbox's Inbox ID, the library's list ID and site URL
  (`https://<tenant>.sharepoint.com/sites/...`) and the OneDrive's site URL
  (`https://<tenant>-my.sharepoint.com/personal/<user>`), as Graph wrote them;
- since W6.3, a `backup_content` file's SHA-256 (or `office-v1`) of its exported bytes, and in
  `items.csv` the restored copy's hash beside it: a hash, never a byte of the file;
- `expected.items`: subjects, sender addresses and names, Internet message IDs, sent and
  received times, and file names;
- `sample.*.random.keys`: mailbox addresses, folder names and paths, mail subjects and
  received times, site and list IDs, file names and OneDrive UPNs (`random_key`). Each random
  item's key is there a second time, as `expected.items[].key`.

The Cloud's item rows and the report's Failures section need the item names, and a random
item's key is the one record of where it came from (mailbox, folder, site, path) when a
failure has to be traced. Today the file stays where the owner put it: keep it out of the
repository. That ends with W4.6, which uploads the result.

**No container the run didn't sample is named.** Until W4.3 the result also held
`sample.*.random.containers_listed`: up to eight mailboxes, sites and OneDrives per type that
the draw looked into, sampled or not (for a OneDrive whose owner didn't resolve, its URL).
W4.3 cut it to a count before the first signature, since a signed result is never edited:
`sample.<kind>.random.containers_drawn` is how many containers the draw looked into, an
integer, never their names. Nothing read the names, and they aren't what repeats a draw (the
seed and the restore point give the same containers again, and `pool_sha256` shows the pool
was the same). `containers_unresolved` still counts the OneDrives whose owner didn't resolve.
The keys stay, both copies. This closes W4.1's Open point on the random keys and
`containers_listed` (`docs/decisions.md` 2026-10-05, W4.3 point 1). The format changed in
place, as it did for W4.2's two keys: no v1 result had been signed or uploaded, and the
unsigned lab results of W4.1's and W4.2's Done-when runs no longer validate.

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
| `signature.json` | `rp::Signer::sign` over the result's canonical text (W4.3, "The signature" below) | never: it depends on the result's hash |
| `timestamp.tst` | `rp::Timestamper`: a TSA's RFC 3161 token over the same hash (W4.4, "The timestamp" below), when the TSA gave one | never: it depends on the result's hash |
| `result.json` | the finished result's canonical text | never: a file can't hold its own hash |

`attachments` has one entry per file the result covers; `result.json`, `signature.json` and
`timestamp.tst` are never listed.

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
7. The canonical text is signed with the run's key (W4.3). No signature stops here: `the
   result couldn't be signed`, no `signature.json`, no `result.json`.
8. The TSA is asked for a token over the SHA-256 of that text (W4.4), at most three times.
   No token stops nothing: it is a warning, and the folder is complete without one.
9. `signature.json` is written. If it can't be: `could not be written`, no `result.json`.
10. `timestamp.tst` is written when there is a token. One that can't be written is a warning
    too (`timestamp_not_written`).
11. `result.json` is written last, exactly the canonical text that validated and was signed. If
    it can't be, `signature.json` and `timestamp.tst` are removed again.

So `result.json` is there only when the folder is complete: signed, and the timestamp attempt
over, with a token beside it or without one. A folder without it
is a run with no result: `error result_invalid`, a finished result that isn't valid or holds a
secret value, no verdict, a result that couldn't be signed, a file that couldn't be written, or
a process that ended in between (between steps 9 and 11 that leaves a `signature.json`, and
perhaps a `timestamp.tst`, beside no result). No cut-down result is written
for any of these (W4.1 point 5 stands). A command leaves such a folder as it is. The service
closes the one its record names with a result written afterwards, a valid one that says
`error` and why ("A result written afterwards" below).

Through `attachments` the signature covers the other files: their names, hashes and sizes are
inside the signed bytes. That `result.json` means complete is a statement about the Worker's
order of writing, not a protection: until W4.5 sets the folder's ACL another local user can
remove or add a file, so W4.6 and the Cloud require both files and run the verifier.

### `attachments` and `screenshot`

`attachments` is `null` without a run folder, else two or three `{name, sha256, size_bytes}`,
sorted by `name`; `name` is one of `items.csv`, `screenshot.png`, `veeam-session.log`. The
schema's keyword subset can't say "each name once" or "in this order"; the builder's tests do,
and a verifier answers `attachment_twice` for a name listed twice and `screenshot_missing` for
`captured` without `screenshot.png` listed ("The signature" below).

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
| `expected_kind` | `manifest`, `fields`, `metadata` or `backup_content` |
| `sha256_rule`, `expected_sha256` | a `manifest` item's rule (`text-v1`, `bytes`, `office-v1`) and hash; empty otherwise |
| `found_sha256` | the compared copy's hash by that rule, for an item that carries an expected hash only; empty otherwise, and when the copy has no hash by that rule |
| `restore_outcome` | the backup's word for the item: `restored`, `failed`, `unknown`, `not_in_backup` |
| `found`, `outcome`, `mismatches` | the check: `yes`/`no`; `match`, `mismatch`, `missing`, `error`; the mismatched fields joined by commas |
| `verdict`, `code` | `verified`, `failed` or `unchecked` with its code, when the item verdicts decided the run; `-` otherwise (as `rpworker test`'s VERDICT) |
| `ms` | the item's milliseconds when found |

`index` and `ms` are bare numbers. Every other cell is in double quotes, a `"` inside doubled,
each control character a space, so a row is one line whatever a subject holds. A cell of a
step that didn't run is empty; a run that stopped before its sample has the header alone.

- **A found hash for an item that carries an expected hash**: a canary, or since W6.3 a
  `backup_content` file, whose expected and found hash are both in the row (the owner's decision
  of 2026-10-14: a real file's hash is what shows the match). Before W6.3 that was a canary
  alone. A canary's content is ours, so its hash says nothing of
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
password, and since W4.3 the signing key's text with the two other shapes its seed could leak
in, Base64 and hex; `rp::secret_values` in `rp/secrets.hpp` is the one list of the first four,
which a `--record` recorder checks its fixtures against too): a log line that holds one is written as `[withheld: held a secret value]`, a CSV
row that holds one keeps its `index`, has those words as its `name` and nothing else, and one
`SECURITY: evidence: <n> line(s) held a secret value and were withheld` line is logged. The
restore's per-run PFX password never leaves the connector. The builder wipes its copy of the
values when it goes. A test puts the signing key into Veeam's words and a Graph answer and
finds it in no file of the folder, no fixture, no log line and neither stream; W4.9's sentinel
test for every secret is still to come.

The result names every sampled item, so a subject or a file name that a CSV row was withheld
for is in `expected.items` too, and the result can't be cut: it is validated, hashed and
signed as it is. So before `result.json` is written, every string of the finished result
is looked through for the same values, as JSON reads them (in the text an escaped `"` or `\`
would hide one). A result that holds one is not written: `evidence error: <folder>: the result
holds a secret value; no result.json was written` on stderr, one `SECURITY: evidence: the
result held a secret value; no result.json was written` log line, the status unchanged, exit 0
becoming 1. The two text files stay, with their withheld lines.

The match is on the whole value, anywhere in a string. A secret that is also a word of the
result (a Veeam password of `pass` or `mail`) would therefore stop every run's `result.json`;
a real password isn't one. Not covered: stdout, where `rpworker test`'s table shows each
item's name as it is, and `--json`, which writes the result to a file the operator names
(one reason `--json` is never signed).

## The signature (W4.3)

`rpworker test --evidence <dir>` signs the result: an Ed25519 signature over the SHA-256 of
`result.json`'s bytes, kept in `signature.json` beside it, never in the result. `rp::Signer`
(`worker/include/rp/signer.hpp`, `src/signer.cpp`) signs and verifies over the primitive
`rp::Ed25519` (`rp/ed25519.hpp`; the calls into OpenSSL are `src/ed25519.cpp`). The two
verifiers are `rpworker signer verify <folder> --public-key <pem file>` and
`shared/tools/verify_bundle.py`, and `shared/testdata/signing-v1/` holds them to one answer
(`docs/testing.md`, "The shared signing vectors"). The decisions are `docs/decisions.md`
2026-10-05, W4.3, approved as written, and its build notes; the commands' lines and exit codes
are in `docs/worker-config.md`, "`--evidence <dir>`" and "`rpworker signer`". Signing never
changes a run's status. `--json` is never signed: it is one file with no folder to hold a
signature beside it, and its bytes aren't covered by the result's secret check.

### What is hashed and signed

- **`bundle_sha256`** is the SHA-256 of `result.json`'s bytes, 64 lower-case hex. Those bytes
  are the result's `canonical-json-v1` form, and nothing is removed before hashing: the result
  has no signature field. For a folder the Worker wrote it is the file's own SHA-256
  (`Get-FileHash result.json`, or `sha256sum` in Git Bash).
- **The Ed25519 message** is the 32 raw digest bytes: the bytes `bundle_sha256` shows as hex,
  not the hex text.
- **`signature`** is standard Base64 with padding: 64 bytes, 88 characters.
- **`Signer::sign(canonical, key)`** takes the text `write_result` is about to write, and
  answers the signature file's text with its `bundle_sha256` and `key_id`, or nothing. It
  refuses text that isn't its own canonical form, and verifies its new signature with the
  key's public half before it answers. It never throws.

### `signature.json`

Written as its own canonical bytes (322 of them): five keys, all always there, never a sixth.

```
{"algorithm":"ed25519","bundle_sha256":"<64 hex>","format":"restoreproof.signature.v1","key_id":"<64 hex>","signature":"<88 Base64>"}
```

| Key | What it holds |
|---|---|
| `algorithm` | `"ed25519"` |
| `bundle_sha256` | the SHA-256 of `result.json`'s bytes, 64 lower-case hex |
| `format` | `"restoreproof.signature.v1"` |
| `key_id` | the SHA-256 of the signing key's public half as SubjectPublicKeyInfo DER (44 bytes), 64 lower-case hex: `openssl pkey -pubin -outform DER \| sha256sum` (Git Bash) gives it from the public PEM |
| `signature` | the Ed25519 signature over the digest's 32 raw bytes, standard Base64 |

**Its schema is a second file, `shared/schemas/signature.v1.json`:** closed, five required
keys, in the same keyword subset as the result's: `const` for `format` and `algorithm`, the
64-hex definition twice, and for `signature` `minLength` = `maxLength` = 88 with
`^[A-Za-z0-9+/]{85}[AQgw]==$`, which takes every 64-byte value's Base64 and nothing with a
non-zero pad bit, a URL-safe character or no padding. `result.v1.json` gained no key. Python
validates a signature file against the schema file. The Worker has no second embedded
validator: it checks the same rules in code (`parse_signature_file` in `signer.cpp`), a Worker
test validates a Worker-made file against the schema file and runs the keyword walker over it,
and the shared cases hold the two to one answer.

There is no timestamp in it. A closed five-key format can't take a `tsa_token` later, so W4.4's
token will be a file of its own; it is over `bundle_sha256` and touches no signed byte.

### The trust rule

`signature.json` is not itself signed, and anyone can sign a result with a key of their own.
So a verifier takes the public key from its caller (the Cloud's registered key, an auditor's
PEM file), never from the folder, and answers `wrong_key` when `key_id` isn't that key's. A
verifier is only as good as the key it is given: OpenSSL takes a small-order public key and
then accepts forgeries under it, so refusing such a key is the job of whoever registers one
(C5.5).

### A file on disk must be canonical

Both verifiers require `result.json`'s bytes to equal the canonical form of what they parse
to, and refuse otherwise: `result_not_canonical`. A file with its keys re-ordered is refused,
not re-serialised: a verifier that re-serialises would accept bytes nobody signed, a key
written twice among them (both JSON parsers keep the last of two equal keys, silently). What
the Worker shows instead is that a document built in two key orders has one canonical text
and so one hash.

One word covers everything that keeps the bytes from being the canonical form of a document,
whichever parser notices it first and however: not UTF-8, a BOM, not JSON, `NaN`, a float, a
number too large, a lone surrogate, a duplicate key, another key order, a trailing newline.
The two parsers draw their lines in different places (`nlohmann::json` skips a BOM and refuses
`NaN` at the parse; Python's `json` does the reverse), so two words would let the verifiers
disagree. `result_unreadable` means only that the file isn't there, can't be read whole or is
over the size limit. `signature.json` has the same rule under the one word `signature_file`.

**The limits.** Before either parser sees the bytes, both verifiers count the nesting outside
strings and refuse more than 32 levels (`kMaxJsonNesting`, `MAX_NESTING`; a result has far
fewer), which is also what keeps the C++ verifier from a stack overflow. `result.json` is read
up to 16 MiB (`kMaxResultFileBytes`) and `signature.json` up to 4096 bytes
(`kMaxSignatureFileBytes`); a larger one isn't read and is `result_unreadable` or
`signature_file`. An attachment is read up to its listed size; a longer one isn't read and is
`attachment_size`. The caller's key file is read up to 64 KiB.

### The order of writing, and what a signed folder is

In `EvidenceBuilder::write_result`: the secret scan, each attachment read back against its
hash, the signature made, `signature.json` written, `result.json` written last ("The run
folder" above, steps 5 to 9). A signed folder is `items.csv`, `veeam-session.log`,
`screenshot.png` if one was taken, `signature.json` and `result.json`. The Worker writes
`result.json` only after `signature.json`, so in a folder only the Worker has written,
`result.json` means complete and signed.

**What a failed signing leaves.** The attachments (the two text files, and a screenshot if one
was taken), no `signature.json`, no `result.json`: the folder of a run with no result, as for
`result_invalid`. stderr has `evidence error: <folder>: the result couldn't be signed; no
result.json was written` (`EvidenceFailure::not_signed`: the signer answered nothing, threw, or
there was none), or `evidence error: <folder>\signature.json: could not be written`. Neither
changes the status; exit 0 becomes 1. If `signature.json` was written and `result.json` then
can't be, the Worker removes `signature.json` again; a crash between the two writes can still
leave it.

**What is signed, and what never is.** A run that ended `fail` or `error` with a valid result
is signed exactly as a `pass` is. The invalid result is never signed: a run that ended
`result_invalid` has no `result.json` when it ends. In the service the result written
afterwards for such a run is signed, and it is a valid one that says `result_invalid` (W4.8
point 7, which amends W4.3's "a `result_invalid` run is never signed"). Nothing is ever
re-signed: the folder of a run ID can't be made twice, the writer replaces nothing, and a
folder that has its `result.json` is only ever queued.

### The key

The private key is the secret `RP_SIGNING_KEY_BASE64` until the vault (W4.5): one line of
standard Base64 of the key's PKCS#8 DER, 64 characters (`docs/worker-config.md`, "Secrets").
`rp::SigningKey::from_base64` takes strict Base64 of exactly 48 bytes that start with
Ed25519's 16 bytes of PKCS#8 header (`302e020100300506032b657004220420`) and hands the 32
after them, the seed, to the primitive; anything else is refused (47 or 49 bytes, another
header, an RSA key, other Base64). No ASN.1 reader is used, so the library makes no copy of
the seed that can't be wiped. The decoded bytes are wiped before it returns.

With `--evidence` the key is parsed right after the Graph certificate is checked, before the
schema check, the manifest, the run mutex and any Veeam call; the only other command that
parses it is `rpworker signer public-key`. The pipeline takes the key's text out of the run's `Secrets` (wiped there) before
the connector is made, so the connector's copy of the secrets never holds it, and keeps it
with the parsed key in one holder that wipes both on every way out of the run. What stays: a
`--record` recorder keeps its copy of the text until its last check, as for every secret, and
the process's own environment holds the variable until the process ends. The list of secret
values a recorder is made with is taken by it: each value is moved in or wiped, on a refused
folder too, which a test sees. No test observes the other wipes.

### The checks, and the thirteen words

(Sixteen since W4.4: the timestamp's three come after these, "The timestamp" below.)

Both verifiers run the same checks in the same order; the first that fails gives the answer,
one word. `Signer::verify_folder` and `verify_bundle.py`'s `verify_folder`; the list is
`rp::verify_words()` and `WORDS` with `VERIFIED`, which tests hold equal to the words the
shared cases expect.

| # | Word | When |
|---|---|---|
| 1 | `result_unreadable` | `result.json` isn't there, can't be read whole, or is over 16 MiB |
| 2 | `result_not_canonical` | anything else that keeps its bytes from being the canonical form of a document (above), more than 32 levels of nesting included |
| 3 | `result_schema` | canonical, and not a `restoreproof.result.v1` |
| 4 | `attachment_twice` | one name is listed twice in `attachments` |
| 5 | `screenshot_missing` | `screenshot` says `captured` and `screenshot.png` isn't listed |
| 6 | `signature_file` | `signature.json` isn't there, can't be read, is over 4096 bytes, isn't canonical, or isn't its five keys and their shapes: every length, case and Base64 fault of `bundle_sha256`, `key_id` and `signature` is this word |
| 7 | `hash_mismatch` | its `bundle_sha256` isn't the SHA-256 of `result.json`'s bytes |
| 8 | `wrong_key` | its `key_id` isn't the caller's key's |
| 9 | `signature_invalid` | 64 well-formed bytes that Ed25519 refuses under the caller's key |
| 10 | `attachment_missing` | a listed file isn't there or can't be read |
| 11 | `attachment_size` | a listed file isn't the listed size (a longer one isn't read) |
| 12 | `attachment_hash` | a listed file's SHA-256 isn't the listed one |
| 13 | `verified` | none of the above |

Checks 10 to 12 run per listed attachment, in the result's order, after the signature is
known to be good. The canonical form comes before the schema because Python's `integer` takes
`1.0`. Checks 4 and 5 are the two things the schema can't say. `Signer::verify` runs checks 2
to 9 on a result's and a signature file's bytes and reads no attachment.

**A file is there under its own name, or it isn't there** (the code review of 2026-10-06).
Both verifiers list the folder once and read a file only when the listing has its name byte
for byte; any other name isn't asked for. NTFS opens `ITEMS.CSV` when `items.csv` is asked
for, and a file system that tells the two apart has no `items.csv`: with the listing deciding,
such a folder is `attachment_missing` on both (`result_unreadable` for `RESULT.JSON`,
`signature_file` for `Signature.json`), never `verified` beside a note that the same file
isn't listed. A listed name that is a folder is `attachment_missing` in both tools whatever
the folder holds: each asks whether it is a file before it asks for its size.

**However long the folder's path is.** Both read the folder through one absolute path in
Windows' extended-length form (`\\?\C:\...`, `\\?\UNC\server\share\...`), which has no limit
of 260 characters: `rp::extended_folder` in `src/file_read.hpp`, `_extended` in the script. A
file that is there opens, with or without the system's long-path setting; before, the Worker
called an intact folder at a long path `attachment_missing`, `signature_file` or
`result_unreadable`.

The line both print on stdout is `verified <bundle_sha256> key <key_id> timestamp <time |
none | unchecked>` (the third field since W4.4, "The timestamp" below) or `not verified:
<word>`. That line is the contract between the two; the exit codes are each tool's own (the
Worker's 0 and 5, the script's 0 and 1).

**Notes.** A name in the folder that the result doesn't list (W4.6's `manifest.json`, W4.4's
token, a subfolder) is never a failure. With `verified` only, each is one line on stderr before
the verdict's line, sorted by code point: `note: not listed in the result: <name>`. The name
is printable ASCII as it is but for the backslash; anything else is its code point in
lower-case hex, `\xNN` below U+0100, `\uNNNN` below U+10000, `\UNNNNNNNN` above, so no name
can end a line or start another. A Windows name holding a surrogate without its pair is
listed too, the surrogate as `\udXXX`.

**A failure of the verifier is never a verdict.** A folder that can't be opened, a key file
that can't be read or isn't a key, a schema that can't be loaded, and anything unexpected end
with an error line and the tool's error exit code (the Worker's 1, the script's 2), and
nothing on stdout. Since the code review of 2026-10-06 that holds for these too:

- **The Worker's embedded validator.** `rp::validate_result` answers "not valid" when it
  couldn't check at all (the schema not loaded, no memory), and sets
  `ResultValidation::not_checked`. The Signer throws `rp::VerifierFailure` for it instead of
  answering `result_schema`, and `signer verify` prints `signer error: the result couldn't be
  checked against its schema`, exit 1.
- **A folder nobody named.** Windows drops blanks and dots at the end of a path, so ` `, `...`
  or `.. ` would be the working folder or the one above it. The Worker names the folder as a
  file inside it would, where such a name stays what it is; the script refuses a last part of
  blanks and dots only (other than `.` and `..`). Both: the folder can't be opened.
- **An option given twice** to the script is a usage error, exit 2, as in the Worker (64):
  argparse would have kept the last `--public-key` or `--schemas`.
- **The script without its packages** (plain `python`, not `uv run`) prints one `error:` line
  and exits 2, not Python's 1 for a traceback, which is the "not verified" code.
- **A verdict that can't be written** (the reader of a pipe gone) is exit 2 from the script as
  a program too; the interpreter's own flush at exit made it 120.

### The public key file (W4.3)

One rule, the same in `rp::PublicKey::from_pem` and in the script's `public_key_from_pem`;
neither uses a PEM or DER reader of its library, since each library's takes more and they
differ. A key file is, in this order:

1. optional white space (space, tab, CR, LF);
2. the line `-----BEGIN PUBLIC KEY-----`;
3. one or more body lines, each of one or more standard Base64 characters (`A-Z`, `a-z`, `0-9`,
   `+`, `/`, `=`) and nothing else;
4. the line `-----END PUBLIC KEY-----`;
5. optional white space, and nothing more.

Inside the block a line ends with LF or CRLF only; a lone CR is refused. No header line, no
blank line, no space or tab, no text on the BEGIN or END line. The body lines joined must be
strict standard Base64 (padded, `=` only at the end, the unused bits zero) of exactly the 44
bytes of an Ed25519 SubjectPublicKeyInfo as the library itself writes it: the twelve bytes
`302a300506032b6570032100`, then the 32-byte key. No byte after it, no other length form, no
other algorithm. Those 44 bytes are the key's DER, never a re-encoding, and `key_id` is their
SHA-256. Where the body is wrapped doesn't matter. A file with a BOM, in UTF-16, with two
blocks or with a `key <key_id>` line after the block is refused. A small-order key is a
well-formed key and is accepted ("The trust rule" above).

`shared/testdata/signing-v1/key-files.json` holds the rule as 46 files, 11 accepted and 35
refused, run by both builds. `rpworker signer public-key` prints such a file on stdout.

## The timestamp (W4.4)

`rpworker test --evidence <dir>` asks a timestamp authority (TSA) for an RFC 3161 token over
the result's hash and keeps it as `timestamp.tst` beside `result.json`. The decisions are
`docs/decisions.md` 2026-10-06, W4.4, approved as written, and its build notes; the config
keys, the command's lines and `--tsa-ca` are in `docs/worker-config.md`. A timestamp never
changes a run's status or exit code, and nothing that is signed is rewritten for it.

### What is stamped

`timestamp.tst` is the bare DER TimeStampToken as the TSA sent it: a CMS SignedData whose
content is the TSTInfo. No wrapper, no JSON, no schema. Its message imprint is SHA-256 with,
as the hashed message, the 32 raw bytes `bundle_sha256` shows as hex: the SHA-256 of
`result.json`'s bytes, the same 32 bytes the Ed25519 signature signs. So the stamped datum is
`result.json` itself, and an auditor needs nothing of ours to check it:

```
openssl ts -verify -data result.json -in timestamp.tst -token_in -CAfile tsa-ca.pem
openssl ts -verify -digest <bundle_sha256> -in timestamp.tst -token_in -CAfile tsa-ca.pem
```

(`-token_in` because the file is the token, not the TSA's whole response. `openssl ts
-verify` checks the certificates at today's date; after the TSA's certificate has expired, add
`-attime <the token's time as seconds since 1970>`.) The token's time, policy, serial number
and the TSA's name are inside it, under the TSA's signature; nothing about the timestamp is
written anywhere else. The token is at most 64 KiB (`rp::kMaxTimestampFileBytes`; real ones
are 4 to 8 KB).

### The TSA, and how it is trusted

By default the Worker asks DigiCert's public TSA, `http://timestamp.digicert.com`
(`rp::kDefaultTsaUrl`), and holds its tokens to one root, DigiCert Trusted Root G4, which it
carries: `shared/tsa/tsa-ca.pem` (SHA-256 of the certificate
`552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988`, valid to 2038-01-15),
embedded at build time like the result's schema. The config's `tsa_url` and `tsa_ca_file`
name another TSA and the PEM certificates its tokens must chain to; a `tsa_url` needs its
`tsa_ca_file`, so another TSA never borrows the default's root. The anchor never comes from the
Windows store (hundreds of CAs, different per machine) and never from the token.

**Plain HTTP.** DigiCert's TSA has no HTTPS endpoint. The TLS rule is untouched: an `https`
`tsa_url` is verified like every other call, and with `http` there is no TLS to verify, so
nothing is switched off. A token's integrity never comes from the transport: its signature,
its chain to the pinned root, the nonce and the imprint are all checked before the file is
written. The request holds a hash and a nonce and no secret. Someone on the path can only deny
service, which is "not timestamped".

**The request** (`rp::Rfc3161::request`): version 1, a SHA-256 imprint, `certReq` true, a new
random 64-bit nonce for each attempt, no policy asked for. It is a POST with `Content-Type:
application/timestamp-query`, a 10 s timeout.

**The answer is taken only when**, in this order (`rp::Timestamper::stamp`): HTTP 200; at most
64 KiB; exactly one TimeStampResp; status granted (0), never `grantedWithMods`; a token that is
exactly one TimeStampToken; the nonce that was sent; a SHA-256 imprint equal to the result's
hash; and the token verifies under the CA at the token's own time (`rp::Rfc3161::verify_token`,
the same check the verifiers make). Three attempts in all, with waits of 30 s and 60 s, about
two minutes at worst; every kind of failure is tried again and the last one's code is the
answer.

**What "verifies" means** (`Rfc3161::verify_token` over OpenSSL's `TS_RESP_verify_token`, and
the script's `_token_verifies`): the signer's certificate is among the token's own
certificates and is named by the token's ESSCertID (v1 or v2); its extended key usage is
critical and `timeStamping` alone; the signature is over the signed attributes, whose
`messageDigest` is the TSTInfo's hash; and the signer chains, each certificate issued by the
next and each valid at the token's time, to a certificate of the caller's CA file (a
certificate of that file ends the chain wherever it is met). Revocation isn't checked, and the
policy OID and an accuracy aren't required. Long-term validation (the TSA's certificate
expiring in 2037, archive timestamps) is out of scope.

### No token

A TSA failure is a warning on stderr and nothing else:

```
timestamp warning: <folder>: not timestamped: <code> after <n> attempt(s)
```

| Code | When |
|---|---|
| `tsa_unreachable` | no HTTP answer (connect, timeout, a dropped connection) |
| `tsa_http_status` | an answer whose status isn't 200 |
| `tsa_token_too_large` | a body over 64 KiB |
| `tsa_response_malformed` | not one TimeStampResp, or granted with no token, or a token that isn't one |
| `tsa_rejected` | a status other than granted |
| `tsa_nonce_mismatch` | not the nonce that was sent |
| `tsa_imprint_mismatch` | not a SHA-256 imprint of the result's hash |
| `tsa_untrusted` | the token doesn't verify under the CA |
| `timestamp_internal` | the request couldn't be made, or the primitive or the HTTP client failed in a way that is neither's answer; or, since W4.8, the Worker was asked to stop before the first attempt (`after 0 attempt(s)`) |
| `timestamp_not_written` | there was a token and the file couldn't be written |

(`rp::timestamp_codes()`.) The status line, the exit code, the result and the signature are
those of the same run with a TSA: the folder is complete without `timestamp.tst`, and both
verifiers call it `verified ... timestamp none`. There is no error file in the folder: nothing
there but `result.json` is signed, so a file saying "the TSA failed" could be added or removed
by whoever removes a token. `EvidenceBuilder::write_result` hands the outcome on to its caller
(W4.6 puts it into the outbox manifest as `tsa_error`).

**After a stop (W4.8).** The Timestamper is handed the service's stop check
(`TimestamperOptions::stop_requested`; null, as for a command, means never). It is asked
before each attempt and before the wait that precedes it: after a yes no wait is begun and no
further attempt is made. The outcome is then the last attempt's code with the attempts made,
or `timestamp_internal` with no attempt at all when the stop came before the first, never
`tsa_unreachable` for a TSA that wasn't asked. So `<n>` in the warning may be 0:

```
timestamp warning: <folder>: not timestamped: timestamp_internal after 0 attempt(s)
```

An answer already taken stays taken. This amends W4.4's build note 3 ("the next attempt is
still made") for a stop. A run the stop itself ended is therefore not timestamped as a rule:
the stop check still says yes when its folder is written, so it is signed, complete and
without a token ("A stop during a run" below).

A clock that disagrees with the TSA's is said and changes nothing either: `timestamp warning:
the TSA's time and this machine's clock differ by <n> s` when they are more than 120 s apart.
The token is the better clock; no verifier compares the token's time with the result's own
times.

### What the verifiers check, and the three words

After the last attachment, when the folder's listing has `timestamp.tst` (byte for byte:
`TIMESTAMP.TST` is one more unlisted file and no timestamp):

| # | Word | When |
|---|---|---|
| 14 | `timestamp_file` | the file can't be read whole, is over 64 KiB, or isn't exactly one TimeStampToken: bytes after it, the TSA's whole response, not one signer, no TSTInfo, a version other than 1 |
| 15 | `timestamp_mismatch` | its imprint isn't SHA-256 or isn't `result.json`'s hash |
| 16 | `timestamp_invalid` | it doesn't verify under the caller's CA (above): the signature, the signer, or its chain at the token's time |

Checks 14 and 15 are made whoever asks; check 16 needs `--tsa-ca <pem file>`, the PEM
certificates a token must chain to, which like the public key come from the caller and never
from the folder. One word covers everything cryptographic, because OpenSSL reports the
signature and the chain as one step and two words would have the two libraries draw the line
in different places.

The third field of the `verified` line says what was established:

| Field | Meaning | stderr |
|---|---|---|
| the token's time, `YYYY-MM-DDTHH:MM:SSZ` | the token verifies under `--tsa-ca` | nothing |
| `none` | the folder has no `timestamp.tst`: the run wasn't timestamped | `note: not timestamped` |
| `unchecked` | there is a token, its form and imprint hold, and no `--tsa-ca` was given | `note: timestamp.tst was not checked: no --tsa-ca` |

A `--tsa-ca` file that can't be read or holds no certificate is the tool's own error (the
Worker's exit 1, the script's 2), never a word. Both tools hold the file to one rule: every PEM
block in it is a `CERTIFICATE` that reads as one; a block of another label (a key, a CRL) or one
that is cut off makes it no CA file, and text outside the blocks is a comment. `timestamp.tst` is never a `not listed` note.

**Where the two verifiers may differ.** The Worker checks through OpenSSL; the script reads the
token with `asn1crypto` and checks the signature and walks the chain with `cryptography`, with
no name constraints, path length or policy processing. `shared/testdata/timestamp-v1/` holds
them to one word on its 23 cases and to one list of the single-bit changes of a token that
still verify (12 of 897 bytes, none covered by a signature: two version numbers, two
algorithms' NULL parameters, and the signer info's signature algorithm, which neither reads).
For the other changes both say "not verified", and on 17 of them (measured on one token) not
with the same word: the script's readers refuse a few bytes of a certificate as no token
(`timestamp_file`) that OpenSSL reads and then fails to verify (`timestamp_invalid`). No
vector holds a signer without the timestamping key usage: OpenSSL's own responder refuses to
make one; the script's rule for it has tests of its own.

## The outbox (W4.6)

A complete, signed run folder is queued in a local outbox and uploaded later, oldest first,
with retries. Nothing signed is ever lost or changed on the way. The decisions are
`docs/decisions.md` 2026-10-07, W4.6, and its build notes; the commands, their lines and exit
codes are in `docs/worker-config.md` ("`--outbox <root>`", "`rpworker outbox`"). The code is
`rp::Outbox` (`rp/outbox.hpp`, strict) and `rp::CloudUploader` (`rp/uploader.hpp`). Since W5.1
the Worker posts to `<cloud_url>/v1/results` with its API token (`Authorization: Bearer`), and a
run the Cloud refuses for good goes to `failed\` ("What the Worker does with each answer").

### The layout

Two sibling folders under one root, by default `%ProgramData%\RestoreProof`:

| Folder | What is in it |
|---|---|
| `outbox\<run_id>\` | a queued run: the run folder as the run wrote it, plus `manifest.json` |
| `sent\<run_id>\` | an uploaded run: the same folder, its manifest with `sent_at` |

`rpworker test --evidence <dir> --outbox <root>` writes `<dir>\<run_id>` exactly as without
`--outbox` and then, once `result.json` is written and the `signed`, `timestamped` and
`evidence` lines are out, renames the folder to `<root>\outbox\<run_id>` with one
`MoveFileExW` and writes `manifest.json` there. A rename, never a copy: the folder is in the
runs root or in the outbox, whole, and never half in both, so `<dir>` and `<root>` must be on
one volume. The folder's name stays the run ID, and a flush holds `result.json`'s `run_id` to
it. A folder that can't be queued (already queued, already sent, another volume, the rename
refused) stays in `<dir>` as it is, with one `outbox error:` line. What can be known before the
run is checked before it, once the config is read and before the secrets, the mutex and any
Veeam call (the W4.6 code review, finding 1): with a `--run-id`, that no run of that ID is
queued or sent; that `<root>\outbox` can be made (it is made then, and left); that `<dir>` and
`<root>\outbox` are on one volume. A run refused there does nothing: `outbox error: ...;
nothing was done`, exit 1, no run line.

A run folder without `result.json` is a run that didn't finish (`result.json` is written
last, after the TSA was asked). The outbox never queues one and never deletes one, in the
runs root or under `outbox\`. The service gives the one its record names a result written
afterwards and queues it then ("A result written afterwards" below); any other is left.

### `manifest.json`

The Worker's own record of a queued run: never uploaded, never in `attachments`, not covered
by the signature, no shared schema. `canonical-json-v1`, exactly these keys:

| Key | Value |
|---|---|
| `format` | `restoreproof.outbox-manifest.v1` |
| `run_id` | the run ID, the folder's name |
| `queued_at` | when it was queued |
| `attempts` | uploads tried so far, the one that succeeded included |
| `last_attempt_at` | when the last one was tried, or `null` |
| `last_error` | why it failed, or `null`: `upload_http_<status>`, `upload_unreachable`, `upload_timeout`, `upload_internal`, or `folder_changed` |
| `next_attempt_at` | when it is tried again, or `null` (at the next flush) |
| `timestamp` | `{"state": "timestamped" \| "not_timestamped", "code": <the W4.4 code> \| null}`: whether the run got a token, and why not. This is where `tsa_error` lives |
| `files` | the folder's names when it was queued, sorted, without `manifest.json` |
| `sent_at` | only once the Cloud has answered 202 |

Times are UTC to the second, `YYYY-MM-DDTHH:MM:SSZ`. The file is written whole (a temp file
beside it, flushed, moved over it): it is the one file the outbox ever rewrites. A reader is
strict: text that isn't its own canonical form with exactly these keys and kinds is no
manifest. A queued folder without a readable manifest (a stop between the rename and the
manifest, or a damaged file) gets a new one at the next flush, with that flush's time as
`queued_at`, and is uploaded like any other; only the attempt count and the TSA's code are
lost.

### What is never changed

- **Nothing in a queued folder but `manifest.json` is written after it is queued.**
  `result.json`, `signature.json`, `timestamp.tst` and the attachments stay the bytes the run
  wrote, through every failed attempt and into `sent\`.
- **A flush never asks the TSA again.** A run that got no token is uploaded without a
  `timestamp` part and stays "not timestamped".
- **The queue is never pruned.** Only runs the Cloud has answered 202 for are ever deleted.
- **A run is never re-signed or edited**, whatever its status: a `fail` or `error` run with a
  valid result is queued and sent as a `pass` is.

### A flush

`rpworker outbox flush` is one pass and never waits. The service's loop (W4.8) makes the same
pass itself, `Outbox::flush` under the flush mutex, after each run that queued something and
at the end of every poll, and hands it a stop check that is asked before each queued run:
after a stop no further upload is started. After the caps
below, it takes every queued run whose `next_attempt_at` is `null` or not after now, oldest
`queued_at` first. For each run, in this order:

1. **Every file that would be sent is read whole and checked against what the run signed.**
   `result.json` parses and names this run; `signature.json` names the SHA-256 of
   `result.json`'s bytes; `timestamp.tst` is there exactly when the manifest says
   `timestamped` and is one token over that same hash; each attachment the result lists is
   there with its size and SHA-256. A file that fails is `outbox error: <folder>: <file>
   changed since it was signed`: nothing is sent, no attempt is counted, `last_error` becomes
   `folder_changed` (written once: a manifest that says so already isn't rewritten) and the
   run stays queued for the operator; every file is read and checked again at every flush it
   is due, so a folder the operator puts right is sent at the next one with no manifest edit.
   A file that is there and couldn't be opened at that moment (another process holds it) is
   not a change: `outbox error: <folder>: <file> couldn't be read`, `kept <run_id>: not_read`,
   nothing written, the next flush tries again. This catches every change short
   of forging both the result and its signature; the signature itself is verified under the
   public key by the Cloud and by `rpworker signer verify`, not here (the outbox reads no key).
2. **One request:** `POST <cloud_url>/v1/results`, multipart/form-data, the parts `result`
   (`result.json`), `signature` (`signature.json`), `timestamp` (`timestamp.tst`, only when
   there), then one part per listed attachment under its own name (`items.csv`,
   `veeam-session.log`, `screenshot.png`). Sent once, 120 s at most. `manifest.json` is never a
   part.
3. **202:** the manifest gets `sent_at`, then the folder is renamed to `sent\<run_id>`.
4. **Anything else** (another status, no connection, a connection lost mid-request, a
   timeout): `attempts` + 1, `last_error`, and `next_attempt_at` by the schedule. The folder
   is otherwise untouched.

A Worker stopped in the middle of a request has written nothing; the run is tried again at
the next flush.

### The retry schedule

`next_attempt_at` = the failed attempt's time + min(60 s × 2^(attempts − 1), 3600 s):

| After failed attempt | 1 | 2 | 3 | 4 | 5 | 6 | 7 and later |
|---|---|---|---|---|---|---|---|
| Wait | 1 min | 2 min | 4 min | 8 min | 16 min | 32 min | 1 h |

There is no last attempt: a queued run is tried hourly until it is sent.

### The caps

At every flush, before any upload:

1. `sent\` runs whose `sent_at` is more than 30 days ago are deleted.
2. While `outbox\` and `sent\` together hold more than 500 MB (500 × 1024 × 1024 bytes), the
   oldest `sent\` run goes too.

A `sent\` folder without a readable manifest has no `sent_at` and is never deleted. When the
queue alone is over 500 MB nothing is deleted: `outbox warning: the outbox holds <n> MB, over
the 500 MB cap` on stderr at every flush, and `rpworker outbox list` shows what is waiting.

### `signer verify` on a queued or sent folder

Both verifiers still say `verified` for a queued or a sent folder, with one more line on
stderr, `note: not listed in the result: manifest.json`: the manifest is a file the result
doesn't list, as W4.3 foresaw, and it is not evidence.

## A result written afterwards (W4.8)

The service runs one job at a time through `rpworker test`'s pipeline, in process, and writes
a record of the run it has taken, `%ProgramData%\RestoreProof\state\running.json`, before the
run does anything. A run whose folder was left without a `result.json` is closed by the
service: it writes a result for it afterwards, signs it and queues the folder, so the Cloud
gets a signed answer under the job's own run ID. The decisions are `docs/decisions.md`
2026-10-08, W4.8 (points 6, 7, 13 and 14), and its build notes; the loop, the jobs file, the
record's keys, the log lines and the operator's ways out are in `docs/worker-config.md`. The
code is `plan_close`, `build_close_result` and `close_run` in `rp/service_recovery.hpp`
(strict), `EvidenceBuilder::adopt_attachments` and `remove_unfinished`, and the run folder's
shared tail `rp::finish_run_folder` in `src/run_folder_tail.hpp`, which the pipeline and the
close both end in.

Only the service does this, and only for the one folder its record names,
`<runs root>\<run_id>`. It lists nothing under the runs root and adopts nothing it finds
there: a folder a command left (`rpworker test --evidence`) stays as it is.

### When one is written

| The record | The run | Code |
|---|---|---|
| found at start, `close_as` `null` | the process ended during the run (a kill, a crash, the 25 s after a stop) | `interrupted` |
| `close_as` `result_invalid` | the pipeline returned and its own result wasn't valid | `result_invalid` |
| `close_as` `internal` | the pipeline returned and the folder couldn't be completed; `close_detail` is the run folder's word: `not_written`, `changed`, `holds_secret`, `not_signed` or `invalid` | `internal` |
| `kind` `job_invalid` | a job that has a usable `run_id` and breaks another rule of the jobs document; no pipeline run, nothing asked of Veeam or Graph | `job_invalid` |
| `kind` `job_invalid`, `close_as` `connector_unknown` | a valid job asking for a connector this Worker's registry doesn't have (W4.11, J3b); no pipeline run, nothing asked of Veeam or Graph; the record's `connector` is `{type: the job's, api: ""}` from its first write | `connector_unknown` |

When the pipeline returns and leaves the folder incomplete, the loop first writes `close_as`
and `close_detail` into the record and then closes, so a close that is itself cut short keeps
its word: a record found at start with `close_as` set is closed with that code (`unfinished
run <run_id> found: to be closed as <code>` in the log; a record without one is `interrupted
run <run_id> found: taken <time>, restore requested <yes|no>`). A job that is no job has
`close_as` `job_invalid` and the key at fault from the record's first write. After a stop no
step is started for a record: a run that returned with an incomplete folder just as the
service was asked to stop has no `close_as` on record, and the next start closes it as
`interrupted`.

A run that ended before its run line has no folder and gets no result, in the service as for
the command; its record is deleted. A job without a usable `run_id` gets none either: nothing
can be signed under a name the Cloud knows.

### What the result holds

A valid `restoreproof.result.v1` with what the record knows and `null` for the rest, built by
`rp::ResultBuilder` like any other and validated before it is signed:

| Key | Value |
|---|---|
| `run_id` | the record's |
| `worker_version` | the Worker's that writes the result |
| `started_at` | the record's, written right after the run line; `null` when the run line was never reached |
| `ended_at` | `null` |
| `connector`, `restore_point` | the record's, written right after the run line (for a `connector_unknown` record, at its first write: the type the job asked for, `api` empty); else `{"api": "", "type": "veeam_m365"}` and the empty restore point the pipeline writes when none was chosen (`id` and `backup_time_raw` empty, `backup_time` `null`) |
| `client` | the record's profile (the job's, W4.10) with the job's `client_id`; for a `job_invalid` record of a job whose profile couldn't be read, empty strings beside the job's `client_id` (the schema holds the strings to a length alone); `scope` and `resolved` `null` (W4.11: no result written afterwards passed the client check) |
| `sample`, `expected`, `restore`, `check`, `cleanup` | `null` |
| `timings` | every one of the twelve spans `null` |
| `attachments` | `items.csv` and `veeam-session.log`, with their hashes and sizes (below) |
| `screenshot` | `{"state": "unavailable", "reason": "disabled"}`, or `no_page` when the config's `screenshots_enabled` is true: W4.2's rule for a run without a restore session to show. The capturer isn't asked, and it is the config's setting, not the job's: the record doesn't keep the job's flag |
| `status` | `error` with the code; `restore_sent` the record's `restore_requested` (false for `job_invalid`); every count 0; `failed_items`, `unchecked_items` and `warnings` empty; the fixed message of the status table's "Messages" above |

`restore_sent` false is the record's promise that no restore request went out. True means one
may have, whether or not Veeam took it: the record is written before every restore request,
and a kill between that write and the request looks the same as one after it. For
`result_invalid` the message names how the run itself had ended, which the record keeps in
`close_detail` (`pass`, `fail`, `error <code>`, or `error` alone when it isn't known).

### The attachments

In this order:

1. **A folder that isn't there is made** (a kill before the pipeline made it, or a job that is
   no job).
2. **What a signing that didn't finish can leave is taken away**
   (`EvidenceBuilder::remove_unfinished`): `signature.json` and `timestamp.tst` (a signature
   without its result signs bytes that exist nowhere any more), `screenshot.png` (its writer
   is the one that isn't atomic), each under any ASCII case of its name, and every `<name>.<16
   lower-case hex>.tmp`, the atomic writer's temp file. Nothing else in the folder is touched,
   and nothing below it.
3. **`items.csv` and `veeam-session.log`** (`EvidenceBuilder::adopt_attachments`). One that is
   there is kept and listed as it is, its bytes hashed and never rewritten: the run only ever
   wrote each whole. One that isn't there is written in its empty form: the CSV's header row
   alone, an empty log. Both are replaced by their empty forms, whatever they hold, in three
   cases:
   - **changed.** The run found one of them altered after it hashed it (`close_as` `internal`
     with `changed`), or an earlier try of this close did (the loop then writes `changed` into
     the record's `close_detail`, `<ending>; changed` for `result_invalid`, before the next
     try). The Worker doesn't list as its evidence a file it knows was changed.
   - **another owner.** One of them is owned by neither SYSTEM, Administrators nor the
     service's account (the vault's owner rule, `rp::check_trusted_owner`): where the installer's
     ACLs (W7.1) are not in force a local user can put a file there. One `SECURITY:
     service: run <run_id>: items.csv or veeam-session.log is owned by neither SYSTEM,
     Administrators nor this account; neither is kept: the close replaces both by their empty
     forms` line.
   - **a job that is no job.** Nothing in its folder is a run's evidence.

   The files are decided by the folder's listing, the name byte for byte, as the verifiers
   read it. A file under another case of the name (`ITEMS.CSV`) is not the run's file under
   the name the result lists: it is deleted, never adopted or renamed, and the empty form is
   written under the right name. A text file that is there and can't be read whole (a folder
   of that name, a file over 64 MiB) or can't be taken away fails the close (`not_written`).
4. **Anything else found in the folder is left**, and is the verifiers' `note: not listed in
   the result: <name>`.

### Signed and timestamped by the same path

From there the close ends in the same tail as every run, `rp::finish_run_folder`, so there is
one signing path: the result built and validated, its strings looked through for the secret
values (the vault's, the signing key's text and its other shapes), each attachment read back
against its hash and size, the signature under the vault's key, the TSA asked, then
`signature.json`, `timestamp.tst` when there is a token and `result.json` last, then the
folder queued by one rename with its `manifest.json` ("The run folder" steps 4 to 11, "The
outbox"). The log has the tail's own lines under the run's ID: `signed <bundle_sha256> key
<key_id>`, `timestamped <time>`, `evidence <folder>: ...`, `queued <outbox folder>`. The
signing key is read from the vault for this and held as the pipeline holds it (wiped on every
way out), which makes the close the key's third reader beside `rpworker test --evidence` and
`signer public-key`.

A closed folder is a signed folder like any other: `rpworker signer verify` and
`verify_bundle.py` say `verified` for it, and a flush checks and uploads it as it does any
run's. No token is never a failure here either: the folder is complete and queued without
`timestamp.tst`. A `tsa_ca_file` that can't be used doesn't fail a close: `timestamp warning:
the TSA's CA file can't be used; not timestamped`, and no TSA is asked.

This amends two sentences (W4.8 point 7). W4.3's "a `result_invalid` run is never signed" is
now "the invalid result is never signed": what the close signs for such a run is a valid
result that says `result_invalid`. And "nothing in a run folder is written after the run"
holds for a folder that has its `result.json`; one without was never signed, and the close is
its one writer.

**When it fails.** The record stays, so no other job runs, and the close is tried again at a
poll, not sooner than 15 minutes after the last try (each try asks the TSA). The log has `run
<run_id>: couldn't be closed (<word>)`, once per word and again every hour: `vault` (the vault
can't be read, or holds no signing key), `not_signed`, `not_written`, `holds_secret`,
`changed`, `invalid` (the result written afterwards isn't valid itself), or `untrusted`
(below). When the key is the reason, nothing can be signed, so nothing is sent: the
heartbeat's `last_error` (`run_not_closed`) is the Cloud's only word of it.

### A folder that already has its `result.json`

It is complete and is only queued: nothing is signed twice. That is the folder of a run whose
queueing failed (`run <run_id>: couldn't be queued (<the outbox's word>)`, tried again at every
poll), or of a run the process ended between `result.json` and the rename. Its manifest says
`timestamped` when `timestamp.tst` is in the folder and else `not_timestamped` with `code`
`null`: why the run got no token was only ever in memory.

What is queued is uploaded as the Worker's own word. So a complete folder whose `result.json`,
`signature.json` or `timestamp.tst` is owned by neither SYSTEM, Administrators nor the
service's account is not queued: `couldn't be closed (untrusted)` and one `SECURITY: service:
run <run_id>: result.json, signature.json or timestamp.tst is owned by neither SYSTEM,
Administrators nor this account; the folder is not queued` line. The record stays, as for any
close that fails. The owners of the text files of a complete folder are not asked: a flush
holds them to the hashes the result lists.

A run that reached the outbox while the service ran is never closed again, whatever the outbox
answers later: `sent\` is pruned, and a run that is gone from there was sent, not lost.

### It doesn't say what the run found

A result written afterwards is `error`, whatever the run had found. A run killed during the
TSA's wait had its verdict, its clean after and its two text files; the result written for it
is still `error interrupted`, because the verdict was only ever in memory. The `items.csv`
kept beside it shows the rows that run wrote, and `veeam-session.log` what Veeam said.

Here `error` is "the test didn't reach a result". The attachments are evidence of what was
done, not a second verdict: no reader and no report takes a `pass` or a `fail` from an
`items.csv` beside an `error`. The interrupted job is not run again under its run ID either:
the first attempt may have restored, and a second run couldn't tell its items from the
first's.

### A stop during a run

The pipeline is handed the service's stop check (`RestoreCommandEnv::stop_requested`; null, as
for a command, means never), its sleep is the stop signal's wait, and the connector learns of
a stop through `ConnectorOptions::stop_requested` and `before_restore_request`. The common
case is then a signed `error interrupted` written by the run itself; the record covers the
rest.

| Where the stop is found | What the run does |
|---|---|
| before the run mutex and the first Veeam call | no run line: `restore error: the Worker was asked to stop; nothing was done` on stderr, exit 4, no result; the record is deleted and the job is offered again |
| after the run line, before each of the clean before, the sample, the read before and the restore | `restore error: the Worker was asked to stop; nothing was restored`, then `status error interrupted: the run stopped before the restore: the run was interrupted (interrupted); nothing was restored`; the clean after skipped; the folder signed and queued, when the 25 s allow |
| before the first restore request | the request is not sent (no certificate exported, no POST): `connector::Interrupted` ending `; nothing was restored`; `the restore didn't start: the run was interrupted (interrupted); nothing was restored`, `restore_sent` false |
| before a later restore request | not sent either; the earlier ones of the call were: `the restore didn't complete: the run was interrupted (interrupted); items may be in the restore targets`, `restore_sent` true |
| in the restore's poll, after a wait | the poll ends with `connector::Interrupted`, no verdict, the explore sessions left open as at the 20 min deadline: the restore goes on in Veeam; `restore_sent` true |

`connector::Interrupted` is a type of its own, not a `connector::Error`, so no handler written
for Veeam's failures takes it; `stop_reason` gives it the code `interrupted` and reads `;
nothing was restored` from its text as for the others. A run that couldn't be put on record
as started (the record's write right after the run line failed) ends the same way as the
second row, with `restore error: the run couldn't be recorded as started; nothing was
restored`; a restore request the record couldn't be written for is withdrawn like one after a
stop.

In the last two rows a restore may still be running: the clean after is skipped ("Cleaning the
restore targets" above, `cleanup.after` `null`, `restore_may_still_run` true), the record
stays, and no job starts until nothing of the run is running in Veeam and the targets were
cleaned once.

**The code is `interrupted`, not the service that was waiting.** After a stop every other
wait (the HTTP retries, the statistics' tries, the duplicate check's looks, Graph's waits and
rechecks, the download client's) returns at once, and its loop gives up as it does at its own
limit. That reads as the failure of whichever service was being waited for: `graph_transient`,
`backup_transient`. So the stop is read right before the status is decided, and when it was
asked for by then and the table gives an `error`, the verdict is replaced by
`verification::interrupted(verdict)`: `the Worker was stopped during the run; the run itself
ended error <code>`, keeping the item count, `restore_sent` and the warnings. The exceptions:

- a `pass` or a `fail` reached in spite of the stop stays what it is;
- `target_guard` stays: a guard refusal is never renamed;
- `interrupted` is already the stop's own;
- every verdict decided before the stop came stays, and `result_invalid`, decided after this
  rule from the result that was built, replaces whatever it left.

**The timestamp after a stop.** The Timestamper makes no further attempt once a stop was asked
for ("No token" above). The stop check still says yes when an interrupted run's folder is
written, so such a run is signed and complete with `timestamp warning: <folder>: not
timestamped: timestamp_internal after 0 attempt(s)`, and its manifest says `not_timestamped`,
`timestamp_internal`. A result written afterwards at the next start asks the TSA like any run.

**What isn't promised.** A request in flight ends only by its own timeout, and 25 s after the
stop the process is ended whatever it is doing. That run is the record's: the next start
finds it and writes its result afterwards.

### The shared cases and the closed-folder vector

`shared/testdata/result-v1/cases.json` has 185 cases, 47 valid and 138 invalid. The two W4.8
added, both valid, are results written afterwards:
`written-afterwards-error-interrupted-every-step-null` (a record that reached its run line,
`restore_sent` true) and `written-afterwards-error-job-invalid-nothing-known` (`started_at`
`null`, an empty `api`, the empty restore point). The made-up code of the case
`status-unknown-error-code` is now `teapot`, since `job_invalid` became a real one. Both
builds run the file and pin the three counts (`worker/tests/result_schema_test.cpp`,
`cloud/tests/test_result_schema.py`).

`shared/testdata/signing-v1/closed-folder.json` is one folder the service closed, as texts, in
`bundle.json`'s shape (`description`, `key`, `bundle_sha256`, `key_id`, `files`): a run whose
process ended after a restore request and before its result, closed as `error interrupted`
with `restore_sent` true, its `items.csv` the header row alone and its `veeam-session.log`
empty, signed with RFC 8032's test key 1 and without a token (the stop is asked for before
the close, so no TSA is asked). It is a file of its own, not a
case of `cases.json` or a change to `bundle.json`, which are held byte for byte to what the
code makes. The hidden `rptests "[.write_shared_closed]"` writes it. A Worker test
(`tests/worker_body_test.cpp`) closes the same folder and compares it with the file, but for
`worker_version`, and `Signer::verify_folder` says `verified`;
`cloud/tests/test_verify_bundle_closed.py` runs `verify_bundle.py` over it and gets the same
word.

## The Cloud receives a bundle (C5.7)

`POST /v1/results` is the Cloud's side of the upload "The outbox" describes: the Worker's parts
`result`, `signature`, `timestamp` (when there) and one per listed attachment under its own
name, posted under the Worker's API token. The decisions are `docs/decisions.md` 2026-10-10,
"C5.7"; the code is `cloud/app/results.py` (every decision, strict at 100% line and branch) and
`cloud/app/routers/results.py` (the request and the statements). What the Worker does with
each answer is W5.1's (below).

### The third verifier is the second one

The Cloud imports `shared/tools/verify_bundle.py` from the image (`cloud/Dockerfile` copies
`shared/tools` and `shared/tsa` beside `shared/schemas`) and runs the script's own `verify`,
`check_attachment` and `check_timestamp` over the parts. So the three verifiers, `rpworker
signer verify`, the script and the Cloud, give one word for every case of
`shared/testdata/signing-v1/` and `shared/testdata/timestamp-v1/`;
`cloud/tests/test_results_vectors.py` posts each of the 61 cases through the route. Two cases
differ from a folder by design: a token under another case of its name (`TIMESTAMP.TST`) is a
file the verifiers note and a part the upload refuses, and a token with no CA, unchecked to the
script, is checked under the root here, since the Cloud always has one. A third difference is
also by design and has no shared case (the C5.7 review's finding 12, left as it is): the upload
holds every part's size before it reads any, in the sender's order, so a folder with two faults
at once, one of them an oversized `signature`, `timestamp` or attachment, may get the size's
word here and the other fault's word from the two verifiers. No bundle the Worker's flush sends
is affected (it holds the sizes before it sends), and a part is never read past its limit to
find a better word. The key is always the
token's Worker's `public_key_pem` and `key_id` as registered (C5.5); nothing in the body names a
key, an MSP or a Worker.

### The checks, in one order, and what each answers

| Step | Refusal | Status |
|---|---|---|
| no valid token | `not authenticated` | 401, before any byte of the body is parsed |
| `Content-Type` not `multipart/form-data` | `body: not multipart/form-data` | 415 |
| no `Content-Length` | `body: no Content-Length` | 411 |
| `Content-Length` no ASCII number | `body: no Content-Length` | 411 |
| `Content-Length` over 96 MiB | `body: too large` | 413, before the body is read |
| the body itself passes 96 MiB, whatever `Content-Length` said | `body: too large` | 413, the reading stopped there |
| the parser refuses the body (a bad boundary, a seventh file part, a part without a file name, a charset nothing decodes under), or the sender went away mid-body | `body: malformed` | 400 |
| a part name twice | `part_twice` | 400 |
| `result` missing or over 16 MiB; `signature` missing or over 4096 bytes; `timestamp` over 64 KiB | `result_unreadable`; `signature_file`; `timestamp_file` | 400, the part unread |
| the result and the signature, in the verifiers' order | `result_not_canonical`, `result_schema`, `attachment_twice`, `screenshot_missing`, `signature_file`, `hash_mismatch`, `wrong_key`, `signature_invalid` | 400 |
| a listed attachment's `size_bytes` over 25 MiB | `body: too large` | 413 |
| each listed attachment, in the result's order | `attachment_missing`, `attachment_size`, `attachment_hash` | 400 |
| a part the result doesn't list (`manifest.json`) | `part_unexpected` | 400 |
| the token, when there, under `shared/tsa/tsa-ca.pem` | `timestamp_file`, `timestamp_mismatch`, `timestamp_invalid` | 400 |
| a verified result the tables can't hold: an item `index` over 2^31-1, or a U+0000 in a text a row takes (an item's `subject` or `name`, an `error`'s `status.message`) | `result_unstorable` | 400 |
| `run_id` not the text the Cloud dispatched (no uuid, or a uuid in another spelling), no such run, another MSP's, another Worker's | `run_id: no such run` | 404 |
| a run never handed out (`dispatched_at` null) | `run_id: not dispatched` | 409 |
| a run that holds a bundle of another hash | `bundle_conflict` | 409 |
| the bundle's client isn't the run's | `client_mismatch` | 409 |
| accepted | `{"run_id": "<uuid>", "state": "pass" \| "fail" \| "error"}` | 202 |

Every answer the app gives, the 202 and each refusal, carries `X-RestoreProof-API: 1` (C5.11,
below, "The contract"). The upload is the one request the body cap of C5.11 leaves to its own 96 MiB.

The media type is read without regard to case, as HTTP has it. The 96 MiB cap is held twice: on
the header before a byte is read, and on the bytes as they arrive, since a server that frames a
body by its chunks (`Transfer-Encoding: chunked` beside a small `Content-Length`) hands the
route more than the header said; `tests/test_results_server.py` holds it through uvicorn on
loopback. A listed name under another case (`ITEMS.CSV` for `items.csv`) is not the listed part:
the attachments are checked first, so the answer is `attachment_missing`. `result_unstorable` is
the Cloud's own word, not a verifier's: the schema takes an index to 2^53-1 and any text, the
`position` column is an int4 and PostgreSQL's `text` holds no U+0000, and a 500 would leave the
Worker retrying for good. The run is named by `str(test_run.id)`, the text the job gave: capitals,
no hyphens or `urn:uuid:` name no run, so the stored `result.json` and its row agree byte for
byte. The verification runs in a thread (it is CPU work of up to seconds for a large plan and
would otherwise hold every other request).

Every 400 comes before the run is named, so a bundle that doesn't verify tells a caller nothing
about what runs exist. A refusal after authentication writes one `audit_log` row,
`result.rejected`, whose target is `worker:<id> <word>` or, once the run is known,
`run:<id> <word>`, and nothing else; it is answered as a response rather than raised, so that
one row commits. No refusal's text ever quotes the document, and no string of the body reaches
a log line.

**The client** (the entry's point 9): `client.client_id` must be the job's, `str(client.id)`
(null is a mismatch: a run made at a prompt is not the Cloud's job); `client.tenant_id`, parsed
as a uuid, must be the client row's; with `scope` `same_tenant`,
`resolved.organization.tenant_id`, what the backup product said the organisation is, must be
that tenant too; and a `pass` or `fail` without `scope` `same_tenant` is refused, since the
Worker never writes a verdict without the client check (W4.11) and the Cloud files no verdict it
wasn't shown to be about. An `error` without the check is filed, and it alone may leave the
tenant unsaid (`tenant_id` `""`): the Worker's `error job_invalid` for a job whose client profile
it couldn't read knows no tenant and signs the empty strings beside the job's `client_id` ("A
result written afterwards"). A tenant that is said must be the client's, in every result.

**The run's state.** A bundle is taken for a run that is `dispatched`, `queued` again by the
sweep and not yet polled, or `expired` after three attempts: all three were handed out, and a
late upload (the service's `error interrupted` written at its next start, "A result written
afterwards") is signed evidence of the job the Cloud dispatched, however late. The run goes to
the bundle's own `pass`, `fail` or `error` in one `UPDATE` whose `WHERE` holds that rule
(`RunRepo.receive`), so a second upload at the same moment is settled by the rowcount (the
sweep and the poll leave a run one that takes a bundle, so only another upload's commit makes
the `UPDATE` miss; the row read again then answers 202 or `bundle_conflict`); `dispatched_at`
and `attempt` are kept. There is no `received` state, and every state either takes a bundle or
holds one (a test holds the two lists to `RUN_STATES`). A run that
already holds this very bundle answers 202 with its stored state and nothing is written, not
even an audit row; a different bundle for one run is `bundle_conflict`.

**The timestamp.** No `timestamp` part is "not timestamped": `tsa_ok` null, never a refusal
(W4.4). A token that is there is held to the one root the image carries, exactly as the
verifiers hold it, and a bad one is refused: the three verifiers must agree, an honest Worker
never sends one (the run verified the chain before it wrote the file and the flush holds the
imprint before every upload), and a Worker configured for a TSA the Cloud doesn't trust should
hear so at its first bundle rather than have months of runs quietly flagged. `tsa_ok` is true
or null after this task, and `tsa_time` is the token's `genTime`.

### What is filed

Rows first, then the objects, in the request's one transaction, committed before the 202
leaves (so the Worker's move to `sent\` never outruns the row):

- **`test_run`:** `state` from `status.status`; `error_code` and `error_message` from `status`
  when `error`; `started_at`, `finished_at` from `started_at`, `ended_at`; `total_ms` from
  `timings.spans.total.ms`; `restore_point_at` from `restore_point.backup_time`; `bundle_key`
  the prefix `msp/<msp_id>/runs/<run_id>/`; `bundle_sha256` the signature's (the SHA-256 of
  `result.json`'s bytes); `signature_ok` true; `tsa_ok` and `tsa_time`; `cleanup_ok` from
  `cleanup.cleanup_ok`. A time the pattern takes and the calendar refuses, a negative duration
  and a span without `ms` are null, never a refusal. Everything else of the result stays in the
  stored `result.json`.
- **`test_item`:** one row per `expected.items[]` entry, joined to `check.items[]` by `index`,
  in one `INSERT`: `position` the index, `type` the kind, `name` the subject or the file name,
  `expected_kind` as the result names it (`manifest`, `fields`, `metadata` or W6.3's
  `backup_content`; text, never checked against a list here: the verifier holds it to the
  schema), `expected_sha256` for an item that carries one (a `manifest` item, and a
  `backup_content` file: the hash of the copy the backup gave, by its rule), `found_sha256` always
  null (no found value is ever in the result, W3.2; the compared copies' are in `items.csv` for a
  person), `found`, `match` (`match` true, `mismatch` and `missing` false, `error` not known),
  `reason`, `ms`. A `backup_content` file whose restored copy differs is `match` false with the
  Worker's reason (`fields did not match: sha256`) like any other mismatch (C6.8, held by
  `tests/test_results.py`). A result that never sampled files no items.
- **One audit row** `result.received`, target `run:<id>`.
- **The plan's canary cursor** (C6.8, `docs/decisions.md` 2026-10-15, point 11): for a `pass` or
  `fail` that carries the three `sample.<type>.canary` objects, `PlanRepo.advance_canary_cursor`
  moves the plan's cursor to the Worker's own signed `cursor_next`, in one `UPDATE` whose `WHERE`
  holds the cursor the run was sent with (`results.cursor_advance`). So the Cloud never computes a
  cursor (the Worker alone knows each type's canary count); a second run sent with the same cursor,
  a cursor another result already moved and a plan without canaries touch nothing (0 rows is never
  an error); an `error` moves nothing (its canaries may never have been compared, so the next run
  takes them again); a value outside the Worker's rule (0 to 999999) moves nothing rather than fail
  the upload. It is one statement more for such a result, no audit row (the stored `result.json`
  records both cursors), and it commits or rolls back with the rest; the same bundle again writes
  nothing. It is the route's last statement, after the objects are put (the C6.8 code review's
  finding 5), so the plan's row is locked from it to the commit alone. A second run of the plan
  dispatched before this result arrived was sent the old cursor and samples the same canaries
  (finding 4, open: the dispatch's rule).
- **The objects:** `result.json` and `signature.json` as `application/json`, `timestamp.tst`
  when there and each attachment under its own name as `application/octet-stream`, each the
  part's bytes under the prefix. A put that fails rolls the rows back (the app's 500; the Worker
  retries); an object already written is overwritten by the next upload of the same bundle.

### What the Worker does with each answer (W5.1)

Built by W5.1 (`docs/decisions.md` 2026-10-15, point 8; `rp::Outbox::flush`, strict). The status
alone decides; the body is never read. 202 with `X-RestoreProof-API: 1`, first or repeated:
`sent`. Any 2xx without the header (or with another value): `upload_not_cloud`, retried by the
schedule, never `sent`. 401: the attempt counted and scheduled, the pass stops, and the service
sends nothing more with that token (but the heartbeat) until the vault holds another, when the
runs a 401 kept are due at once. 400 (any word), 404, 409, 415, 422: refused for good, the
manifest written with no next attempt and the folder moved whole to `failed\<run_id>` for the
operator's `rpworker signer verify`; never sent, pruned or deleted by the Worker. 411, 413, 5xx,
a timeout, no connection: retried by the schedule. **The wire bytes** of one Worker upload (the
shared vector's bundle, as cpr and curl framed it) are `shared/testdata/signing-v1/
dispatched-run.wire`, posted unchanged by `cloud/tests/test_contract.py` to 202 `pass` (C5.11's
finding 3, closed).

## The contract (C5.11)

`docs/decisions.md` 2026-10-12, "C5.11"; the code is `cloud/app/contract.py` (strict at 100%
line and branch) and `cloud/app/routers/version.py`; the tests `cloud/tests/test_contract.py`
and `cloud/tests/test_openapi.py`.

**The header.** Every response the app sends carries `X-RestoreProof-API: 1`: a route's
answer, a refusal, FastAPI's 404, 405 and 422, the log middleware's own 500, `/healthz` and the
OpenAPI document. Not the answers the server makes without calling the app: uvicorn's `400
Invalid HTTP request received.` for a request it can't parse and its 503 under
`--limit-concurrency` carry no header, and neither does a proxy's own page. So the header's
absence means something on a 2xx alone; a 4xx or a 5xx without it may still be this Cloud's
server. The value is the contract's number, the `1` of `/v1`: it changes when `/v2`
exists and the document breaks, not when a field is added. It says one thing, *this answer came
from a RestoreProof Cloud speaking contract 1*, which a Worker pointed at a wrong host, a captive
portal or a proxy's error page cannot otherwise tell from a 202.

**`GET /v1/version`.** No token, no statement, a closed body `{"api": 1, "version": "<the
Cloud's>"}` (`app/__init__.py`'s `__version__`, the document's `info.version`), `Cache-Control:
no-store`. It answers before a Worker has a token, which is what W7.2's `rpworker doctor` needs,
and says nothing the anonymous `/v1/openapi.json` doesn't.

**The body cap.** Every request but `POST /v1/results` is held to 64 KiB: a `Content-Length` over
it is 413 `{"detail": "body: too large"}` before the app runs, and a body whose bytes pass it
(chunked beside any `Content-Length`, as h11 frames it) is the same 413 from the first byte over,
the read ended there. A `Content-Length` of more digits than the cap's is over it as it stands
and is never converted to a number (Python refuses a text past 4300 digits). The upload keeps
its own 96 MiB cap on the header and on the bytes; it is known by the path the router matches,
without the server's `root_path`, so it stays exempt behind `uvicorn --root-path`. The
header check reads no byte and the counter counts only what the app pulls, so a heartbeat without
a token is still the one 401 with nothing of its body read (C5.8); a 413 on the header before the
401 tells a caller nothing of any token. The two routes that take a body, registration and the
heartbeat, name the 413 in the document, and so does the Worker's revoke (W7.3), a `POST` a
caller may put a body on; a `GET` with a body gets it as the server's answer, like
the 404. Nothing else in the stack bounds a JSON body, and the Compose stack has no proxy; a
deployment's proxy (C5.12) is the second line, not the first.

**The security scheme.** The document's `components.securitySchemes.workerToken` (`http`,
`bearer`) and the `security` entry on `GET /v1/jobs`, `POST /v1/results`, `POST /v1/heartbeat` and
`POST /v1/workers/self/revoke` (W7.3)
come from `current_worker` itself, which depends on FastAPI's `HTTPBearer(auto_error=False)` for
the document alone: a route that depends on `current_worker` is documented as taking the token
with no second edit, and a test holds the document's secured operations equal to the routes
whose dependency tree holds `current_worker`. The dependency's result is never read and the
library never answers: `_presented_token`'s strict parse (one space, nothing else) and the one
401 are as C5.4 made them. `POST /v1/workers/register` takes the install token in its body and
gets no bearer scheme.

**The contract test.** `shared/testdata/signing-v1/dispatched-run.json` is a run folder the C++
Worker's service made and sent for a job of the Cloud's shape (`run_id`
`c5110000-0000-4000-8000-000000000001`, `client_id` `c5110000-…-0002`), signed with RFC 8032's
test key 1 and timestamped by the published test TSA, with the job it came from and the part
list the Worker's outbox built (`upload`: name, file name, content type, in order). The Cloud's
test makes a client and a queued run that carry the vector's ids, with the job's profile on the
connector and its three sizes on the plan, and polls `GET /v1/jobs` under the Worker's token:
the answer's one job is the vector's `job`, key for key, so a change to what the Cloud writes
into a job fails there until the Worker has run the new job and written the vector again. The
Done-when then posts the vector's bytes unchanged under that part list to the run that poll
dispatched: 202 `pass` with the header, the row, the items, the audit row and the objects;
nothing is re-signed. The request is built by the test's HTTP client from the part list, not
replayed from the Worker's wire bytes. The vector's client is the lab's test tenant, not a
made-up one: its `job` and result carry the identifiers of `lab/tenant.md` (none a secret, no
person), and its `description` says so. It is the one shared folder that reaches 202; every other shared case is
404 after the whole verification, as before.

**What the Worker does with the header (W5.1 built; W7.2's `doctor` not yet).** One rule,
`rp::cloud_answer_kind` (`worker/include/rp/cloud_api.hpp`, strict): the name in any case (Caddy
hands it on as `X-Restoreproof-Api`), the value exactly `1`. A 2xx of the upload without it is
not the Cloud's answer: the run is not moved to `sent\`, the attempt is `upload_not_cloud`
(retried by the schedule like `upload_unreachable`), one warning once. A jobs document from an
answer without the header is not kept or read. The heartbeat takes any 2xx and warns once of a
missing header. A registration's 201 without it stores nothing. A header with another value is
treated as absent, its warning naming the number (when it is 1 to 9 digits). `rpworker doctor`
(W7.2) will ask `GET <cloud_url>/v1/version`
without a token and prints `cloud: RestoreProof Cloud <version>, API 1`, or `cloud: not a
RestoreProof Cloud` for a 2xx without the header. Every one of these rules reads the header on
a 2xx alone: an answer that is no 2xx is handled by its status as before (the upload's table
above; `doctor` prints the status), with or without the header, since an overloaded or
confused server of this Cloud answers a 503 or a 400 without it.

## The Cloud receives a heartbeat (C5.8)

`POST /v1/heartbeat` is the Cloud's side of "The heartbeat" in `docs/worker-config.md`: the
service's five-key body, posted every `heartbeat_interval_s` under the Worker's API token
(W5.1). The decisions are
`docs/decisions.md` 2026-10-11, "C5.8"; the code is `cloud/app/routers/heartbeat.py` (the body
model and the route) and `WorkerRepo.heartbeat` (`cloud/app/repo/workers.py`, strict at 100%
line and branch). The Worker is not changed by it.

**The body is the Worker's, as W4.8 built it:** `version`, `last_error`, `last_error_at`,
`outbox_depth`, `uptime_s`, every key required, nothing else taken (`extra="forbid"`). Each is
held to the Worker's own form and nothing looser: `version` 1 to 64 printable ASCII;
`last_error` a word's shape `^[a-z0-9_]{1,64}$` or `null` (never the Worker's list, which grows
with the Worker); `last_error_at` exactly `YYYY-MM-DDTHH:MM:SS.mmmZ` on a real calendar day or
`null`, and the error and its time come both or neither; the two counts strict integers from 0
to 2^53 − 1, the canonical form's own bound, so every body that passes fits the `bigint`
columns. Anything else is FastAPI's 422, which quotes the sender's own input to the sender and
nowhere else.

**The token before the body** (the C5.8 review's findings 1 and 2). The body is not a parameter
of the route, which FastAPI would read and parse before any dependency ran: `heartbeat_body`
depends on `current_worker` and reads the request itself. A caller without a valid token is
answered the 401 with nothing of its body read, whatever the body is. For the Worker, a body
whose media type is not `application/json` (in any case, a parameter allowed), that is not
JSON or not UTF-8, that is nested past the parser's depth, that carries a number past the
interpreter's digits or **a key twice** (the parser alone would keep the last, so a closed body
would not be closed) is the same 422 as a body outside the model, with nothing of the body in
it; FastAPI's own 400 for a body it can't parse is never answered. `last_error_at` is parsed
once, into the aware UTC time that is stored, and its digits are 0 to 9 alone. `version` is
registration's own type (`app.routers.workers.Version`), so a version one route takes the other
takes. Nothing bounds the body's size yet (C5.11, with registration's).

**What is written** is one `UPDATE` of the token's Worker's row, `WHERE msp_id AND id AND
revoked_at IS NULL`: `last_seen_at` is the Cloud's clock at the request, never a time from the
body (C6.2's "red if older than 24 h" compares with the Cloud's clock); `version`,
`last_error`, `last_error_at`, `outbox_depth` and `uptime_s` are stored as sent, a `null`
replacing a value, so a restarted service's `null` clears the row's error and the row is
always the Worker's latest word, never a mix of two heartbeats or of a heartbeat and the
registration's `version`. A heartbeat is two statements, the token's lookup and the `UPDATE`
(which keeps the session's own copy of the row in step without a third); no row is read back and no audit row is written (the row is its own record, ninety-six times a
day per Worker).

**What is answered:** 204 with no body and no `Content-Type` (the Worker takes any 2xx and
reads nothing). No header, another scheme, an unknown token and a revoked Worker are
`current_worker`'s one 401 `{"detail": "not authenticated"}` with `WWW-Authenticate: Bearer`
after its one lookup, before the body is read or anything is written; a revoke that landed between the lookup and the `UPDATE` makes the
`UPDATE` touch nothing and is the same 401, nothing written. A revoked Worker's `last_seen_at`
therefore stops at the revoke: the Cloud's record of when its word was last taken. The log
holds the request line (method, path, status, duration, request ID) and nothing of the body or
the token.

**What the Worker does with each answer (W5.1):** 204 taken; 401 one
warning once and the heartbeat keeps going (it is the Cloud's only word of a Worker whose token
was revoked); 422 the Worker's `http_422` word (the two sides disagree on the body, which an
upgrade fixes); 5xx, a timeout, no connection: the next interval is the retry, as today.

## The Cloud revokes a Worker at its own word (W7.3)

`POST /v1/workers/self/revoke` is the Cloud's side of `rpworker cloud revoke`, which the
uninstall runs (`docs/upgrade.md`). The decision is `docs/decisions.md` 2026-10-19, "W7.3 (#82)
and W7.4 (#83)", point 5; the code is the route in `cloud/app/routers/workers.py` over
`onboarding.revoke_worker`, the CLI's (`manage.py revoke-worker`) and the `/workers` page's one
function; the tests `cloud/tests/test_workers_self_revoke.py`.

**What is written** is what the admin's revoke writes: `revoked_at` set once on the token's
Worker's row (`WorkerRepo.revoke`, `WHERE msp_id AND id AND revoked_at IS NULL`) and one
`audit_log` row `worker.revoke` `worker:<id>` with the Worker's address as the server saw it and
no user, in the request's one transaction. No body is read, whatever is sent, and nothing of the
request but the token decides anything.

**What is answered:** 204 with no body and no `Content-Type`, with the contract header. No
header, another scheme, an unknown token and a revoked Worker are `current_worker`'s one 401
`{"detail": "not authenticated"}` with `WWW-Authenticate: Bearer` after its one lookup, before
anything is written; so a Worker revoked already, by the admin or by itself, gets the 401 and
not a second answer, and from the commit on its heartbeat, its poll, its upload and a second
revoke are that 401. The Worker reads the 204 as `revoked worker <id>` and the 401 as "the
Cloud doesn't know this token"; both end with the API token out of the vault. The log holds
the request line and nothing of the token.

## The Worker reaches the Cloud (W5.1)

`docs/decisions.md` 2026-10-15, "W5.1 (#66)"; the Worker's guide is `docs/worker-config.md`
("`rpworker cloud register`", "The Cloud as the job source", "`rpworker outbox`").

- **Over HTTPS, always.** On this laptop the Cloud is the Compose stack behind Caddy
  (`cloud/docker/Caddyfile`, the `proxy` service) at `https://localhost:8443`, by Caddy's own CA;
  the Worker trusts its root through `cloud_ca_file` and checks the host name `localhost` as for
  any host. `cloud_url` is never `http`.
- **Registration** (`rpworker cloud register`, or the first `rpworker service start`): the
  install token from the vault, the signing key's public half, the Worker's name and version to
  `POST /v1/workers/register`; a 201 with the header and this key's `key_id` puts the API token in
  the vault in the same write that removes the install token, and writes `state\worker.json`.
  The vault is written only at the operator's console; the service reads it.
- **The token** is `Authorization: Bearer <cloud_api_token>` on `GET /v1/jobs`, `POST
  /v1/results` and `POST /v1/heartbeat`, and nowhere else: no line, file, recording or message
  holds it (the secret audit's two sentinels, J8 the poll).
- **The poll** replaces `jobs_file` when none is set: the Cloud's 200 is kept in
  `state\jobs.json` and read by the jobs file's reader until its jobs are settled or it is six
  hours old.
- **A 401** of the poll or an upload stops both for that token until the vault holds another;
  the heartbeat goes on.

## The Cloud makes a run (C5.9)

The job dispatcher, `cloud/app/scheduler.py`, the Compose `scheduler` service: the decisions are
`docs/decisions.md` 2026-10-11, "C5.10 and C5.9", points 6 to 9; the cadence's rules are
`cloud/app/cadence.py` (strict at 100% line and branch) and the statement `RunRepo.create_scheduled`.

**A plan's cadence** (`test_plan.cadence_cron`) is exactly five space-separated cron fields, read in
UTC and nothing else, parsed by croniter (`L`, ranges, steps and lists as croniter takes them;
its six-field seconds form, `@daily` and its random `R` field refused, so there is one form and
every reader of it agrees on a period's start), **at most every five minutes** (the scheduler's
tick: no two minutes of an hour less than five apart, nor the last of one hour and the first of
the next when the hours can follow each other; the day fields aren't read) and **at least monthly**:
from the start of every day in the 400 days after the plan is made, the next occurrence is within
31 days. So `0 2 * * *` (the default: daily at 02:00 UTC), `*/5 * * * *`, `0 2 1 * *`, `0 2 L * *`
and `0 2 * * 1` pass, and `0 2 31 * *` (58 days from February), `0 2 1 */2 *` and `0 2 1 1 *` are
refused where the plan is made, as `cadence_cron: not a cron expression` or `less than monthly`;
`* * * * *` is `more often than every 5 minutes` and `0 0 31 2 *`, which no date meets, `never occurs`
(`PlanRepo.create`, so every writer of a plan is held). C6.4's monthly report wants a run in every
period it covers; a plan that can't give one is not a plan.

**A period** is `[due, next)` between two occurrences of the cadence, named by its start. Every
five minutes (`TICK_S`), for each MSP (`MspRepo.list`, the one read across MSPs) in a transaction
of its own, for each enabled plan: `due` is the latest occurrence at or before now (`due_at`);
a period that began before the plan was made is not the plan's (`test_plan.created_at`), so a
plan's first run is at its first cron time after it was made (`create-plan --run-now` queues one
by hand for a first test today); otherwise one queued run for the period through
`RunRepo.create_scheduled`, one `INSERT ... ON CONFLICT DO NOTHING` under
`uq_test_run_msp_id_plan_id_scheduled_for`, which answers the row or nothing when the period has
its run. **The unique and the statement decide together**, so two ticks or two scheduler
processes make one run, with no lock, no read before the write and no error; a run made by hand
has no period (`scheduled_for` null; nulls are distinct) and never collides. **Only the current
period is made:** a scheduler that was down for a day makes today's run when it comes back,
never yesterday's. A plan re-enabled after a month gets its current period's run at the next
tick. A plan whose Worker is revoked still gets its runs: they sit `queued` with `dispatched_at`
null, the truth of a plan nobody moved, for C6.2's page to show.

**What can go wrong, and what it does to the tick.** A plan whose text the parser refuses or whose
cron never occurs (a row written past the repo) is skipped with one `plan skipped` line (`msp_id`,
`plan_id`, `reason cadence_cron`, never the text) and the loop goes on: a bad cron stops no other
plan. Each plan's run is made under a savepoint: a plan that raises (a connector the keys say
exists but is gone, a statement the database refuses) is rolled back alone and logged as
`plan failed` with its ids and the exception's type, and the MSP's other plans keep their runs.
An MSP whose transaction raises (its plans can't be listed, the commit fails) is rolled
back and logged as `tick failed` with the exception's type and frames, and the next MSP runs. A
run is counted and its `run created` line written only after its MSP's commit. A
tick that can't list the MSPs is `tick failed` with no MSP, and the next tick runs in five
minutes; the process never exits on a tick's failure. **The sweep**, the second job, calls
`RunRepo.requeue_stale` per MSP (six hours, three attempts, C5.6) in its own transaction and logs
`runs swept` when anything moved.

**What is logged:** `scheduler started` with the interval, one `tick` line per job with counts
(`msps`, `plans`, `created`, `skipped`, `failed`, `duration_ms`; the sweep's `requeued` and
`expired`), one `run created` per run with `msp_id`, `plan_id`, `run_id` and `scheduled_for`.
The scheduler reads nothing of a profile, a credential or a tenant value, so none can reach a
line.

## The Cloud's pages (C6.1, C6.2, C6.3)

`docs/decisions.md` 2026-10-12, "C6.1, C6.2 and C6.3"; the code `cloud/app/auth/{passwords,
sessions,login_limiter}.py`, `cloud/app/audit.py`, `cloud/app/ui.py`, `cloud/app/routers/ui/`,
`cloud/app/templates/`, `cloud/app/static/`. The pages live at the root (`/login`, `/clients`,
`/clients/{id}`, `/runs/{id}`, `/runs/{id}/files/{name}`, `/workers`, `/workers/{id}/revoke`,
`/audit`, `/static/`), outside `/v1` and outside the OpenAPI document; every one still carries
`X-RestoreProof-API: 1` and is under the 64 KiB body cap. Every template autoescapes, and no page
repeats a secret.

### Login and sessions (C6.1)

**The user.** `manage.py create-user --msp-id --email --role` and `reset-password --email`
(`docs/onboarding.md`): the password is read from the console twice without echo, or from
standard input as one line, never from an argument or the environment, 12 to 1024 characters,
hashed as **Argon2id** under argon2-cffi's defaults (64 MiB, 3 passes, 4 lanes;
`user.password_hash`); the address is trimmed, must hold one `@` with something on each side and
no space, is stored as typed and is one across the Cloud whatever its case
(`uq_user_email_lower`); `user.role` is `admin` or `member` (`ck_user_role`). A reset sets
`user.password_changed_at`, which ends every session of the user (the cookie carries that
time's stamp; "The session" below).

**`POST /login`** (`email` and `password` as a form): a field that is missing, over its limit
(254 and 1024 characters) or that no UTF-8 can hold (a multipart form may name a charset that
decodes to a lone surrogate) is 422 with the login page and neither field in it, before the
limiter and any work; the route holds the two fields itself, since FastAPI's own 422 repeats
the refused value in `detail[].input`. Then the limiter (below);
then one lookup by address and one Argon2 verification, against the user's hash or against one
fixed hash made for an address nobody has, so a known and an unknown address cost the same
(the lookup lowers both sides in PostgreSQL, as `uq_user_email_lower` does: Python's
`str.lower()` maps a dotted capital I or a final sigma otherwise; an address `create-user`
would refuse, such as one with a U+0000, a space or no `@`, is nobody's and is not looked
up, with the same answer, the same hash work and its count on the limiter); a
wrong password is 401 with the form again and one line, `wrong email or password`, and one
`audit_log` row `login.failure` in the user's MSP with the user and the caller's address; an
unknown address is the same answer with no row (it belongs to no MSP) and one log line
`login refused` with nothing of the form in it; the right password is 303 to `/` with the cookie
and one `login.success` row. A hash made under older parameters is replaced at that login (the
sessions kept). The page repeats the address escaped and never the password. `POST /logout`
clears the cookie, writes `logout` for a session and sends the browser to `/login`.

**The limiter** (`app/auth/login_limiter.py`): five attempts a minute per address (lower-cased)
and per caller's IP, a sliding window in the process's memory, every `POST /login` counted right
or wrong; the sixth inside the window under either key is 429 with `Retry-After` and
`too many attempts, try again in a minute`, before any password work (the lookup by address still
runs, so a `login.blocked` row names the user when there is one); a refused attempt counts under
no key and adds none (the 429 path can neither grow the table nor push a block out of it; it
touches the keys it already has, and a key whose attempts all fell out of the window is
dropped), so the window clears a minute after the fifth. The count is per process and lost at a
restart; the IP behind a proxy is the proxy's (C5.12).

**The session** is one cookie, `rp_session`: itsdangerous's URL-safe serializer under
`SECRET_KEY` (its one use) and the salt `restoreproof.session.v1` over `{"u": <user_id>,
"m": <msp_id>, "t": <issued, whole seconds>, "p": <the password's stamp>}`, good for 12 hours
from `t` by the Cloud's clock; `p` is `user.password_changed_at` in whole microseconds, of the
row the login verified the password against;
`HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age` 43200, `Secure` unless `SESSION_COOKIE_SECURE`
is `false` (the http stack). A cookie that is missing, tampered, expired, from the future, of
another shape, of a user who is gone or whose `password_changed_at` is not the cookie's `p`, is
no session (the two are compared for equality and never as times: the API host's clock, the
database's and the CLI host's needn't agree, and `t` has no fraction),
all alike: a browser is sent to `/login` (303), an htmx request told to go there (401 with
`HX-Redirect`). `current_user` reads the user's row on every request; a page reads the MSP's
too. The cookie is not renewed while in use. A `POST` to a page whose `Sec-Fetch-Site` is
`cross-site` or `same-site` is 403, and so is the download, the one `GET` that writes a row
(`SameSite=Lax` sends the cookie on a link from another site); no CSRF token.

**Roles.** A member reads every page and downloads; an admin also revokes a Worker and reads
`/audit`. A member on an admin route is 403 (the route exists and is the user's own MSP's); a
row of another MSP is 404 on every page, never 403, and a list never holds another MSP's row.

### The four pages (C6.2)

Every read is a repo method with `msp_id` first; a page runs a fixed number of statements
whatever its rows (held by a test). `test_run.recovery_ms` (new) is `timings.spans.recovery.ms`
of the result, filed by `POST /v1/results` as `total_ms` is (null for a span without `ms`); a
run that landed before the column has null, shown as "—".

- **`/clients`:** one row per client: its last finished run (`pass`, `fail`, `error` or
  `expired`, the latest by `(created_at, id)`), that run's `finished_at` (or `created_at` for an
  `expired` one), its state coloured, its recovery time as `m:ss`; and **next scheduled run**:
  the client's oldest `queued` or `dispatched` run ("queued since …", "running since …") first,
  else the earliest next occurrence over its enabled plans (`app/cadence.py`, the scheduler's
  own arithmetic), else **"no Worker"** when every enabled plan's Worker is revoked (the
  scheduler keeps queuing; the page says why nothing will run), else "none".
- **`/clients/{id}`:** 404 for a client not this MSP's; the run history newest first (date,
  restore point, items tested as the count of `test_item` rows, result, recovery time, cleanup
  ok, timestamped, scheduled: the period's start or "manual"; a `queued` or `dispatched` run
  shows its state and dashes), in pages of 50 by keyset (`?before=<run id>`: a "more" row with
  `hx-get` for htmx and the same URL as a plain link, which answers the rows alone to an htmx
  request and the whole page from there otherwise); and **the 90-day strip**, one cell per UTC
  day ending today, coloured by the day's worst test (`fail`, then `error`, then `pass`;
  `expired`, `queued` and `dispatched` are no test), its `title` the date and the counts.
- **`/runs/{id}`:** 404 for a run not this MSP's; the run's columns (the client, the Worker, the
  times, the restore point, total and recovery time, cleanup ok, timestamped with `tsa_time`,
  the bundle's SHA-256, the period, the attempts, `error_code` and `error_message` for an
  `error`); the items from `test_item`; and **the files** as the bucket lists them under the
  run's prefix (one `list_objects_v2` in a thread), grouped as the bundle (`result.json`,
  `signature.json`, `timestamp.tst`) and the attachments, each a link to the download route,
  never to the bucket. A run without a bundle lists no file.
- **The download, `GET /runs/{id}/files/{name}`:** the name held to
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` and to the bucket's list (404 otherwise; a bare `..`
  never reaches the route, a browser folds it into the path); one audit row `bundle.download`,
  target `run:<id> <name>`, with the user and the address, committed before the answer; then 302
  with `Cache-Control: no-store` to a URL pre-signed for **ten minutes** against
  `S3_PUBLIC_ENDPOINT` (the endpoint a browser reaches; SigV4 signs the host, so a URL signed for
  the stack's `minio:9000` doesn't open; unset, `S3_ENDPOINT`). The row records the link being
  handed out; the fetch goes to the bucket and may be repeated within the ten minutes unrecorded.
- **`/workers`:** one row per Worker: name, version, **last seen** (`last_seen_at`; red when
  more than 24 hours old by the Cloud's clock, or never), the last error with its time, the
  outbox depth, the uptime as `h:mm:ss`, and for an unrevoked Worker the admin's **Revoke** form
  (`POST /workers/{id}/revoke`, `hx-confirm` under htmx; without it the form posts without a
  dialog). The route is `onboarding.revoke_worker` with the user and the address, the CLI's
  function and its one `worker.revoke` row; 404 for a Worker not this MSP's; already revoked is
  409 with the CLI's words `worker_id: no such Worker or already revoked`; a member is 403. The
  Worker's next poll is `current_worker`'s 401.

### The audit page and the words (C6.3)

`app/audit.py` is the pages' one writer: `record(session, request, msp_id, action, target,
user_id=)` writes `AuditRepo.write` with `client_ip(request)` (the one reading of
`request.client.host` for the pages; C5.12 edits it for a proxy), and `ACTIONS` is the closed
list of what a page writes: `login.success`, `login.failure`, `login.blocked`, `logout`,
`bundle.download`, `worker.revoke`. The CLI's words are `app/onboarding.py`'s (`msp.create`,
`client.create`, `install_token.create`, `plan.create`, `run.create`, `worker.revoke`,
`user.create`, `user.reset_password`), the Worker's the routes' own (`worker.register`,
`result.received`, `result.rejected`) and the connector's the repo's (`connector.create`,
`connector.update`, `connector.delete`), and the report generator's is `report.create` (C6.4,
below) and the reports pages' `report.download` (C6.6, the seventh word of `ACTIONS`).
`settings.change` is C7.3's.

**`/audit`** (an admin; a member 403): the MSP's rows newest first by `(at, id)`, the last 30
days by default (`?days=`, 1 to 3650), in pages of 100 by keyset (`?before=<row id>`, with and
without htmx as the history), each with its time (UTC, seconds), its user's address (a dash for
the CLI's and the Worker's rows), the action, the target and the IP; every row of the MSP, the
Worker's and the CLI's included. **Nothing deletes an audit row**; a retention rule for them is
C7.3's to give.

## The Cloud's report (C6.4)

`docs/decisions.md` 2026-10-12, "C6.4"; the code `cloud/app/report/` (`data.py`, `render.py`,
`generate.py`, `frameworks.py`, `template.html`, `report.css`; guarded at 100% line and branch),
`cloud/app/repo/{reports,runs,items}.py`, `cloud/manage.py generate-report`. A report is one
client's PDF of one UTC calendar month, `YYYY-MM`, A4, six sections in this order: Summary, Test
log, Failures, Method, Integrity, Framework mapping. Made by the scheduler's job on the 1st
(C6.6, below), by "Generate now" on a client's reports page (an interim one), and by
`manage.py generate-report` by hand.

**Which runs are the month's** (`app/repo/runs.py` `period_time`; changed by the C6.4 review,
`docs/decisions.md` 2026-10-13, findings 2 and 3). A `pass`, `fail` or `error` run belongs to
the month of the time it ended: `finished_at`, and for a result written afterwards, which has no
`ended_at` (the Worker's `interrupted`, `result_invalid`, `internal`, `job_invalid`,
`connector_unknown`), the time it was stamped (`tsa_time`), else the time it was last handed out
(`dispatched_at`), and `created_at` only when nothing later is known. So a run queued on the
last night of a month and finished or closed on the 1st is the new month's (Q6.1's check holds
each run's token to its end and to the period: "The report checks" below). Every other run belongs to the month of `created_at` and
**is not a test**: an `expired` run is counted in the Summary ("Scheduled tests that did not
run: N") and shown in the Test log as "did not run"; a `queued` or `dispatched` run is counted
as "Scheduled tests with no result when this report was made: N" and shown as "no result yet",
so a month whose Worker was off never reads as a month of passes.

**A result that arrives late** (the C6.6 review's finding 1; `period_time`, `RESULTS_CLOSE`,
`test_run.received_at`). `POST /v1/results` stamps the run with the Cloud's clock when it files
the bundle (`received_at`; never a time of the bundle). A month takes results until **02:00 UTC
on the 1st after it** (`RESULTS_CLOSE`, two hours); a tested run whose result the Cloud received
at that time or later is **the month's it was received in**, not the month it ended in, because
that month may have its final report by then: a run that ended on 30 September 23:50 and whose
Worker reached the Cloud on 1 October 03:05 is October's test, and one received on 10 November
is November's. So every result is in exactly one month as a test, and none is lost to a report
that was already made. A run with no result when its month's final report is made stays in that
report as "no result yet"; when its bundle lands it is a test of the month it lands in. In the
report such a run keeps its own date (the Test log and the Failures print when it ended, and the
month's order is by the tests' ends, so it stands first and "a later test of the same plan" is
one that ended later), and the Summary counts it on a line of its own: "Tests that ended before
this period and whose results arrived after that period had closed, counted here: N". A row no
bundle wrote (`received_at` null) goes by its end. Q6.1's check of each run's token against
the period allows for these: a run counted on that line is stamped before the period began, and
the check accepts it by its arrival and counts it ("The report checks" below).
**No final report is made before 03:00 UTC on the 1st** (`FINAL_AFTER`, three hours: the job's
hour, and `generate`'s refusal `period: not closed until 03:00 UTC on the 1st` for whoever asks
earlier, the job's start run and the CLI included), so the hour between the two is the room an
upload stamped just inside the close has to commit before the month is read; a test holds the
order of the two constants.

`period_filter` is the one condition, and the four reads of a month (`RunRepo.period`,
`ItemRepo.counts_by_type_in_period`, `ItemRepo.unmatched_in_period`,
`RunRepo.clients_in_period`) share it; `app/report/data.py`'s `run_date` is `_run_time`, the
date and the order, on a row. A month that has not begun is `period: has not begun`; a month with no run of the client
at all is `period: no run in the period`; nothing is written for either.

**What each section reads.**

| Section | What | From |
|---|---|---|
| Summary | the client and MSP names, the period, the overall line (in the pass colour only when a test ran and none failed or errored; a month without a test is grey), tests run, C6.8's two rows "Client's own files tested" (the `sharepoint` and `onedrive` items of kind `metadata` or `backup_content` of the tests that passed or failed: canaries are never counted) and "Of those, compared by content" (`n of m`, the `backup_content` ones found with `match` known: a file the restore never brought back or nobody checked is tested, never compared, the C6.8 code review's finding 1; a dash when there is none), the sentence that says what the two rows count, only in a month that tested a file (finding 3), and, only in a month with a canary, "Canary items are not counted in these two rows.", average and maximum recovery time and C6.8's sentence that a recovery time is one test's sample's and not the time it would take to restore the tenant, scheduled tests that did not run, scheduled tests with no result, the backup source, restore points covered, the meaning of the three words, C6.5's sentence ("It records what each test listed here found for the items it sampled, on the dates shown.") | `client.name`, `msp.name`; the month's runs; `recovery_ms` and the distinct `restore_point_at` values over the `pass` and `fail` runs alone (an `error` is a test that could not run: its stopped span and its restore point are no part of either, and the Summary says so); `connector.type` worded (`veeam_m365` is "Veeam Backup for Microsoft 365") |
| Test log | one row per run, oldest first: date, restore point, items as `mail / SP / OD`, result (`pass`, `fail`, `error`, "did not run", "no result yet"), recovery time, the run id's first eight hex digits | the run's date as above, `restore_point_at`, `test_item` rows grouped by `type` (and, since C6.8, `expected_kind`, summed back here), `state`, `recovery_ms`, `id` |
| Failures | one block per `fail` or `error` run: the date, the result, for an `error` its code and message, the items that did not match (type, name, `missing` / `mismatch` / `not checked`, the `reason` word), "Every item that was checked matched." for a run with items and none unmatched, "No item was checked." for a run with none, and "A later test of the same plan passed on <date>." (the nearest later `pass` of the run's own plan in the month), else "No later test of the same plan passed in this period." | `error_code`, `error_message`; `test_item` rows with `match` not true: `match` false is `missing` when `found` is false and `mismatch` otherwise; `match` unknown is `not checked` whatever `found` says (the Worker stores an item whose target it could not read as not found). **The name is printed whole** (a mail's subject, a file's name; never shortened, masked or hashed: the owner's decision of 2026-10-14, held by a test with a 400-character name in both passes, the PDF's text and inside the page), so a subject or a file name the client's users chose is in the PDF: the report is the MSP's to give its client, who owns those names |
| Method | **what the month's tests that passed or failed did** (C6.8, `docs/decisions.md` 2026-10-15, points 2 and 3), from the kinds of their items: the sizes of the plans that have a result in the period; the sample, "a sample of the client's own items, chosen at random from the backup's own listing" when every test that passed or failed sampled an item of the client's own (a kind other than `manifest`), "In <n> of the tests that passed or failed, the sample included the client's own items, …" when some did, nothing when none did (a canary plan of one item per type samples none: the C6.8 code review's finding 2), and only when a test sampled a canary (an item of kind `manifest`) "In <k> of the tests that passed or failed, the sample also included canary items, …" ("also" only after the first sentence) (a month without one has no "canary" anywhere in the report); the three restore targets by name; one comparison sentence per kind the month used and none for a kind it did not: a canary by the SHA-256 of its content (`manifest`), a file compared by content against the backup's copy (`backup_content`; `office-v1` for a Word or Excel document), a file the backup gave no copy of by its name and, unless an Office document, its size (`metadata`), a mail by its subject, received time and sender's name when listed (`fields`); in how many tests the removal from the target did not complete (`cleanup_ok` false; nothing when none); and the levels: "Verification levels covered: 1, 2, 3" only when an item was compared by the SHA-256 of its content (`manifest` or `backup_content`, found with `match` known: a mismatch is a comparison, a missing or unchecked item is not), with "; level 4 partially (files opened and read via Microsoft Graph)" only when such an item was a file; with a test that passed or failed and nothing compared by content, "Verification levels covered: 1, 2. No item of this period was compared by its content, so level 3 is not covered."; a month in which no test passed or failed says no level was covered. An `error`'s items count for none of it | `test_plan` sizes of the runs' plans; the month's runs; the kinds from `ItemRepo.counts_by_type_in_period`; fixed text |
| Integrity | the content hash, the file-hash sentence, the generation time, the Workers of the month's runs (name, id, `key_id` as the public key's fingerprint), every run's id with its `bundle_sha256` and "timestamped <tsa_time>" or "not timestamped" | `worker`, `test_run` |
| Framework mapping | the sentence above the table (what the table is: a description of this evidence, not an assessment of the control; a fail or error shows nothing for it), then the four controls by identifier and their own name (the SOC 2 row by the criteria's own words, never a gloss), each with what a test marked pass shows and what the report does not look at (C6.7, "The framework mapping" below) | `app/report/frameworks.py` |

**The overall line** keeps `fail` and `error` apart (the status vocabulary above): "All N tests
passed", or "N of M tests failed" with "K of M tests could not run (error)" on its own line, or
"N of M tests passed" when only errors kept it from all; an infrastructure problem is never a
`fail`, and the Summary says in one line each what the three words mean. The four banned phrases
("fully recoverable", "guarantee", "certified", "accepted by insurers") are held out of the
template, the stylesheet, the controls and every rendered report by a test.

**Two passes, two hashes.** The template is rendered twice from one `ReportData`. Pass 1 prints
"computed after this report was rendered; see the note below" in the Integrity section's content
hash cell; the SHA-256 of that PDF is the **content hash**. Pass 2 prints the content hash; the
SHA-256 of that file is the **file hash**. Both are the `report` row's (`content_sha256`,
`file_sha256`); the PDF says, in one sentence, why there are two: a file cannot contain its own
hash. WeasyPrint's defaults embed no creation date and no identifier, so one HTML is one byte
sequence by one WeasyPrint version and the hash cell is the one difference between the passes
(the file names its producer, `WeasyPrint <version>`, so the bytes are the version's `uv.lock`
pins; a stored report is never rendered again, and the test reads the Info dictionary through
pypdf, since it lies in a compressed stream); where WeasyPrint
subsets fonts with fontTools (no HarfBuzz-Subset, as on the dev laptop) the fonts' `head` table
would carry the time of the render, so `render_pdf` pins fontTools' `SOURCE_DATE_EPOCH` when
nothing set it. The same HTML renders to the same bytes again in a test; rendering runs in a
thread, never on the loop.

**The row and the object.** `report`: `period_start` and `period_end` (the month's first and
last day), `storage_key`, `content_sha256`, `file_sha256`, `interim`, `generated_at` (the
generator's clock, given). A report is **interim** while its period is not over (its last day is
not before the generation day); the title says "Interim report" and the Summary says the period
is not over. A month has **one final report** per client (`uq_report_final_period`, a partial
unique on `(msp_id, client_id, period_start) WHERE NOT interim`; the generator asks
`ReportRepo.final` before it renders and answers `period: already reported`, the index being the
line for two at once: the loser's insert is refused by the key's unique or the period's, and
since a final report's key is its period's the generator words either as `period: already
reported`, which the job counts as `existing`; the C6.6 review's finding 7) and as many interim
ones as were asked for; a key is written once
(`uq_report_storage_key`). The object: `msp/{msp_id}/reports/{client_id}/{YYYY-MM}.pdf` for a
final report, `…/{YYYY-MM}-interim-{YYYYMMDDTHHMMSSZ}.pdf` for an interim one, `application/pdf`,
through `Storage.put` in a thread **after** the row and one audit row `report.create`
`report:<id>` (the user and the address from a page's caller; null from the CLI and the job), so
a refused row writes no object and a failed put rolls the row back with the caller's
transaction. Nothing edits, replaces or deletes a report; **a final report is never re-made**
(C6.6): it says what the Cloud knew on the day it was made, a run with no result that day is in
it as such, and that run's bundle, when it lands, is a test of the month it lands in ("A result
that arrives late", above).
The read for a final report the month already has comes first, before the month is read, so a
month that has its report costs one statement (the C6.6 job asks for every client).

**No secret, no link, no tenant identifier.** The PDF holds no token, no key PEM (the `key_id`
alone), no pre-signed URL, no bucket name, no `http`, no tenant id and no person's address; the
client, the MSP and the Worker are named by their names; a mail item by its subject and a file
by its name, as the run page shows them. Every value goes through the pages' autoescaping
environment (`ui.make_environment`), a planted `<script>` is escaped in both passes, and a test
scans both passes and the PDF's text.

**The reads.** `gather` is eight statements whatever the rows, each a repo method with `msp_id`
first (`MspRepo.get`, `ClientRepo.get`, `ConnectorRepo.list`, `PlanRepo.list`, `WorkerRepo.list`,
`RunRepo.period`, `ItemRepo.counts_by_type_in_period`, `ItemRepo.unmatched_in_period`); no list
of run ids travels to the database (the item reads join `test_item` to `test_run` under the
period's condition). `generate` adds `ReportRepo.final` (first), the row, the audit row, then
the put: eleven statements for a month of three runs and for a month of sixty. Another MSP's
client is `client_id: no such client`, never a report.

**The cap on a month of thousands of runs** (C6.6; `app/report/data.py` `MAX_LOG_ROWS` 200). The
Test log, the Failures and the Integrity run list show the first 200 runs of the month in the
month's order (the same 200 in the log and the run list, so a run's hash is there when its row
is), and under each capped table one line says "N more tests of this period are not listed here;
the Cloud's pages hold every one." The Summary's numbers (tests, passed, failed, errored, did not
run, no result, the recovery times, the restore points, the Workers, the plans) count every run:
the month is read whole, one statement, and capped in Python. A `*/5` plan is 8,928 runs a
month; uncapped that was hundreds of pages and a two-pass render of minutes. 200 runs are about
23 pages: the entry said 500, and the build measured 500 at 112 s in the image on the dev
laptop's Docker, past the Done-when's minute, so the cap is 200 (its build notes).

**The monthly job** (C6.6; `app/scheduler.py` `tick_reports`; `docs/decisions.md` 2026-10-13,
"C6.6, C6.5 and C6.7", point 1). The scheduler's third job, `CronTrigger(day=1, hour=3,
minute=0)` in UTC with an hour's misfire grace, and once at the process's start like the other
two: for every MSP, the clients with a run of **the newest closed month**
(`app.report.data.closed_month`: the previous month from 03:00 UTC on the 1st, the month before
it until then, so a scheduler started at 00:00:30 on the 1st makes nothing of the month that
just ended and the 03:00 run makes it; the C6.6 review's finding 2) (`RunRepo.clients_in_period`:
any state, so a client whose only run expired or has no result gets a report that says so; one
read in its own transaction), then **one transaction per client** calling `generate` for that
month's final report with no user and no address, committed as soon as it is made; a month that
has its report is counted as `existing` (one read, no render), never a failure; a client whose
report fails (a render, a put, the database) is rolled back alone and logged by type (`report
failed`, the ids, the type, never a message), and the next client is made; a report is counted
and named (`report created`: the ids and the report's id) after its commit; the tick line is
`tick job=reports msps clients created existing failed duration_ms`. The start run makes a
scheduler restarted after a 1st it missed catch up, and costs a restart on any other day one
read per client with a run last month. The scheduler's process reads `DATABASE_URL`, `LOG_LEVEL`
and the five `S3_*` variables at start (`storage_settings_from_environment`, `Storage.for_writing`;
a missing one stops it naming the variable), never `SECRET_KEY`; the Compose `scheduler` service
has them through the one environment anchor. A month whose report failed on the 1st is one
`report failed` line and one `manage.py generate-report --period` by hand.

**The reports pages** (C6.6; `app/routers/ui/reports.py`, the templates `reports.html`,
`client_reports.html`, `_reports.html`; `docs/decisions.md` 2026-10-13, point 2). Both roles
read, download and generate: a report is the client's own evidence, made in the user's name on
one audit row (C6.1's line between the roles is at taking something away and at seeing other
users' actions).

- **`/reports`** (the "Reports" nav entry, every role): every report of the MSP, newest period
  first then newest generation (`ReportRepo.page`, one statement joined to the client on the
  key that starts with `msp_id`), in pages of 50 by keyset (`?before=<report id>`; the rows alone
  for an htmx request; the read asks for one row more than a page, so "more" is offered only
  when a row follows, and a continuation with no row says nothing), each row the client (a link to its reports), the period `YYYY-MM`, the
  kind ("interim" or "final"), the generation time, the content hash, the file hash and a
  **Download** link to the route below. Three statements (the user, the MSP, the page).
- **`/clients/{id}/reports`:** 404 for a client not this MSP's; the same rows without the client
  column; above them the **Generate now** form and what it makes; the client page links it.
  Four statements.
- **The download, `GET /reports/{id}/file`:** `SameOrigin` (the one GET that writes, as the
  bundle's); 404 for a report not this MSP's; one audit row **`report.download`** `report:<id>`
  with the user and the address, committed before the answer; then 302 with `Cache-Control:
  no-store` to a URL pre-signed for ten minutes against `S3_PUBLIC_ENDPOINT`, as the bundle's
  download. No bucket list (the key is the row's): three statements and one `INSERT`. The
  browser's file name is the key's last part (`2026-09.pdf`,
  `2026-10-interim-20261013T101500Z.pdf`).
- **Generate now, `POST /clients/{id}/reports/generate`:** `SameOrigin`; 404 for another MSP's
  client; **the client's row**: `ClientRepo.hold` takes it first (`FOR NO KEY UPDATE SKIP
  LOCKED`: nothing waits, and a run or a report made for the client meanwhile is not kept
  waiting) and keeps it until the request's transaction has committed, in whatever process, so
  a second click while one is being made is the page with "A report is being made; try again in
  a minute." and 429 at once, and a click after it reads the cap with the first's row there (two
  clicks at once used to pass the cap together; the C6.6 review's finding 6); **the cap**: the
  client's newest report read once under that hold, and if it is an interim one of the
  current month made less than ten minutes ago (`GENERATE_EVERY` 600 s) the answer is the
  client's reports page with "An interim report of this month was made at <time>; the next can
  be made from <time>." and 429 with `Retry-After`, no render, no row (two reports a minute apart
  render the same rows to the same bytes, and a render is CPU seconds); the time named is the
  next whole minute at which the cap lets a click through and `Retry-After` the seconds rounded
  up, never a time it still refuses at (finding 12); **the render slot**: one
  render at a time per process (`app.state.render_slot`, a semaphore of one), a click while one
  runs waits five seconds (`RENDER_WAIT_S`) for the slot and is then the page with "A report is
  being made; try again in a minute." and 429; then `generate` for the current month with the
  user and the address under a savepoint (`session.begin_nested()`), and 303 to the client's
  reports page, where the new row is first. A `RepoError` (`period: no run in the period` for a
  client with nothing this month) is the page with the error's own line and 409; a `ReportFailed` (`report: not rendered (<type>)`,
  `storage: put failed (<type>)`) the page with that line and 503, the type logged with the ids
  and never the message; the savepoint rolls the report's rows back alone and the request's
  transaction commits nothing of it; **never a 500**. On success: the user, the MSP, the client,
  its row's hold, the cap's read, the month's eight reads, the row and the audit row, then the put, the same for
  a month of one run and of thirty. The form is a plain POST (no htmx: the render takes seconds
  and a 303 keeps a refresh from posting again). The request's transaction is held across the
  render and the put (the C6.4 review's finding 13, kept and bounded: one render at a time, a
  waiter answered in five seconds, six renders an hour per client).

**The framework mapping** (C6.7; `app/report/frameworks.py`, held verbatim by
`tests/test_report_wording.py`). Above the table: *"For each control, the left sentence says
what a test marked pass in this report shows, and the right sentence what this report does not
look at. A test marked fail or error shows nothing for the control; it is listed under Failures.
The table describes this evidence; it is not an assessment of the control."* The rows:

| Control | Name (the control's own) | What a test marked pass shows | What this report does not look at |
|---|---|---|---|
| ISO/IEC 27001:2022 A.8.13 | Information backup | On the dates listed, a sample of items was restored from the backup copy into a test location, read back and compared with what was expected, and the outcome of each test is recorded here. | Whether every item in the backup can be restored, whether the backup policy is followed, how often backups are taken, or where and for how long the copies are kept. |
| SOC 2 (2017 TSC) Availability A1.2 and A1.3 | A1.2: … data back-up processes, and recovery infrastructure to meet its objectives; A1.3: the entity tests recovery plan procedures supporting system recovery | On the dates listed, the restore of a sample of backed-up items was tested and what each test found is recorded here; this is a record of restore testing of items, not of a recovery plan exercise. | Recovery of a system or a service, the recovery plan and its exercise, recovery time or recovery point objectives, and whether the backup process meets the entity's objectives. |
| HIPAA 45 CFR 164.308(a)(7)(ii)(D) | Testing and revision procedures | On the dates listed, the restore of a sample of items from the backup was tested and the outcome recorded, which is one input to the periodic testing of a contingency plan. | The contingency plan itself, its revision, its other parts (data backup plan, disaster recovery plan, emergency mode operation plan, criticality analysis), and whether the sampled items hold protected health information. |
| DORA, Regulation (EU) 2022/2554, Article 12 | Backup policies and procedures, restoration and recovery procedures and methods | On the dates listed, the restoration of a sample of items from the backup was tested, with each test's outcome and the time the restore took recorded here. | The backup policy, the restoration and recovery procedures and methods as a whole, the recovery of ICT systems, the testing of those procedures beyond the sampled items, and any register, report or notification the regulation asks for. |

Each "shows" sentence begins "On the dates listed", names the sample and says the outcome is
recorded; none names a control met, an audit passed or a regulation complied with, and a test
holds a list of such words out of every reviewed sentence. **The reviewed wording** (C6.5): the
fixed sentences of the Summary (the three meanings, the recovery-times sentence, the
disaster-recovery sentence as the C6.4 review's finding 6 left it), the Method (the sampling,
the targets, the comparison, the clean-up line, the levels line), the cap's line, the Integrity
sentence, and the mapping above are listed verbatim in `tests/test_report_wording.py`; a change
to one of them changes the list in the same commit. The C6.5 reviewer's and the C6.7 reader's
comments are the entries "C6.5 review" and "C6.7 reading" in `docs/decisions.md`, each closing
its issue by its own commit.

**The report checks (Q6.1)** (`docs/decisions.md` 2026-10-13, "Q6.1"; `app/report/check.py`,
guarded at 100% line and branch; `manage.py check-report --msp-id <id> --report-id <id>`;
`tests/test_report_checks.py`). One function, `check_report`, run by the tests on reports they
made and by the command on any stored report, so a report an MSP has already handed over can be
checked on the day someone doubts it. It reads the report's row and the month's runs by the
report's own read (`RunRepo.period` with the row's period: the same `period_filter` the report
was made from, every run the Summary counts, not the 200 the Test log lists), then the bucket,
in a thread: the report's object, and per run one list of its `bundle_key` and at most two gets.
Two statements whatever the runs. Another MSP's report is `report_id: no such report` before
anything is read.

- **The file.** The object under the row's `storage_key`, read back whole, hashes to
  `file_sha256`, else `file_sha256: differs`; none there is `storage: no object`. The content
  hash is not re-read (it is inside the PDF's text, which the app has no reader for;
  `tests/test_report.py` holds it printed from the row and pass 1 re-rendered to it).
- **Which runs.** A `pass`, `fail` or `error` run with `tsa_ok` true is *stamped* and checked
  in full; a tested run with `tsa_ok` null ("not timestamped" in the Integrity section) is *not
  stamped*: no `timestamp.tst` may be under its key (`storage: timestamp.tst unexpected`) and
  its `tsa_time` must be null (`tsa_time: unexpected`); an `expired`, `queued` or `dispatched`
  run ("did not run", "no result yet") has *no bundle*: nothing is read, it is counted, and its
  `bundle_key`, `tsa_ok` and `tsa_time` must be null (`state: no bundle expected`). A tested run
  without a `bundle_key` is `bundle_key: missing` (a row made by hand, as the harnesses make
  them). The three counts and the late count are printed; a test holds them equal to the
  Summary's lines.
- **A stamped run**, in this order, the first miss its word: `storage: no result.json` or
  `storage: no timestamp.tst`; `bundle_sha256: differs` (the stored `result.json` is not the
  result the row names); the verifier's `check_timestamp` under the Cloud's root
  (`timestamp_file`, `timestamp_mismatch`, `timestamp_invalid`, the same words as the upload);
  `tsa_time: differs` (the token's time is not the row's, second for second); then the time
  rule. **The allowance**: the report dates a run by `finished_at`, the Worker's clock read after
  the clean after and before the evidence is written (the secret scan, the attachments'
  read-back and the signature are milliseconds, then the TSA is asked), so the token's time
  must be not before the second the test ended (`stamp_before_end`; a token's time is read in
  whole seconds) and not more than **`STAMP_BUDGET`, 120 s**, after it (`stamp_after_budget`):
  the Worker's whole timestamp budget, three attempts of ten seconds plus waits of thirty and
  sixty (`worker/include/rp/timestamper.hpp`, held equal by a test that reads the header). A
  test that ended at 23:59:58 on the last day and was stamped at 00:00:40 passes; at 00:01:59 it
  does not. No clock allowance beyond that: the report prints the Worker's time as the test's
  date and the token is the trusted time, and a Worker whose clock disagrees with the TSA by
  more than its own budget is the one fault this check can catch that nothing else does.
  A result written afterwards (`finished_at` null) is dated by its token's time, the only end it
  has: no budget applies, only the period.
- **Within the period.** A run that is not late is in the period by its date (`run_date`) and
  its stamp follows the rule above, so the stamp is in the period or within the budget past its
  end. A **late** result (`is_late`: `received_at` at or after `RESULTS_CLOSE` past the last day
  of the month its end falls in, `period_time`'s arithmetic on the row) is the period's by its
  arrival: accepted exactly when `received_at` is in the period, and counted; its end and its
  stamp are before the period. A tested run that is neither is `period: not the run's` (the
  filter makes it impossible; the word is for a row checked against another month).
- **Received before generated** (the C6.6 review's finding 9). For a **final** report every
  result (`received_at` not null) arrived before `generated_at`, else `received_after_report`:
  by the rules (results close at 02:00, no final report before 03:00) a miss is a report made
  against them or a row moved afterwards. For an **interim** report it is not held:
  `generated_at` is the clock read before the month is read, and a result committed between the
  two is honestly in the report with `received_at` after it by milliseconds. Finding 9 stays
  open.
- **What the check proves.** A token that does not verify is refused at the upload, so every
  stored token verified once, under the same root, over the same digest. The check shows that
  the object in the bucket is the token that was verified at the upload, over the result the row
  names, that the row's `tsa_time` is that token's time, and that the test's date and that time
  agree; a finding means the bucket or the row was changed after the upload, the Cloud filed the
  wrong object, or the Worker's clock disagrees with the TSA.

The command prints `report_id`, `final`, `file_sha256` (`ok` or `failed`), `runs`, `stamped`,
`not_stamped`, `no_bundle`, `late` and `findings`, then one `<run id>: <word>` line per finding
on stderr (`file: <word>` for the file) and `report: N check(s) failed`, exit 1; exit 0 with no
finding. A month made by hand with SQL (the harnesses' Septembers) has rows with no bundle
behind them, and the command says so (`bundle_key: missing` per row): it checks what is stored,
never what a row claims.

**The 30-second check** (Q6.1's third step) is a person's, not the code's: `docs/report-usability.md`
holds the method (page 1 of the sample report alone, one question, the clock from the page in
the reader's hands to the first answer, the expected answer "not all passed") and the result once
the owner has run it.
