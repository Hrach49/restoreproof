# Decision log

One entry per architectural choice. Newest first. Add an entry whenever a new choice is
made; never rewrite an old one — supersede it with a new entry that links back.

Format: date, decision, reason, alternatives rejected.

---

## 2026-10-01 — W3.2 live run: a file's cTag moves on a restore over it; a mail already there isn't restored at all (proposed)

Amends the W3.2 entry below (point 1 and its Open check) with what the live run showed
(`docs/api/veeam-lab/README.md`, "W3.2 live run"):

1. **The cTag check is answered: yes.** Restoring the same 6 canary files over run 1's copies
   (run 2b) moved every file's `cTag`, the OneDrive pdf, docx and xlsx included, whose bytes
   didn't change. So point 1's rule holds: a file whose `cTag` moved is this run's copy, and
   all 6 were `match`.
2. **A mail that is already in the target is not restored, and Veeam says it was.** Run 2b's
   five mails were each "restored successfully" in a `Success` session, but the Inbox kept run
   1's copies, same Graph IDs, and gained nothing (`changedItems: true` restores only what
   differs). Point 1 had assumed every mail restore gives a new Graph ID, from W2.5 and W2.8,
   which both started on empty targets. The build reported the five as `missing`, a `fail`
   for what is an unclean target: the infrastructure-as-fail the status rules forbid. Fixed
   (commit 6fd89e9, a test first): a mail with no copy of this run's but an earlier one it
   would match (its `internetMessageId`, or its subject) is `error` `stale_target`, as a file
   with only an unmoved earlier copy already was. A mail sampled again is therefore always
   `error` until the targets are emptied before each run.
3. **The check doesn't trust "restored successfully".** Run 2b is the case the product exists
   for: Veeam reported 11 of 11, and 5 had not been written by this run. The check said so.

**Reason.** Live evidence over the assumption it replaces; and `stale_target` keeps an unclean
target out of `fail`, where `missing` would have put it.

**Alternatives rejected.** *Ask Veeam to restore mails as copies, or turn `changedItems` off*:
the restore bodies are fixed by W2.4/W2.7's guard on the exact key set, and a second copy beside
an old one still can't say which run wrote it. *Count an earlier mail copy as found*: a restore
that wrote nothing would pass.

**Open.**
- W3.4 must empty the targets **before** each run, not only after: with leftovers, every mail
  sampled again is `error`. The before snapshot stays as the second guard.
- A residual risk to note for W3.4: SharePoint rewrites an uploaded Office file again some
  minutes later (`lab/README.md`, office-v1), which also moves its `cTag`. An earlier run's docx
  or xlsx in the RestoreTarget library, restored minutes before, could be rewritten between this
  run's two reads and look like this run's copy. Cleaning before each run removes it; until
  then, leave a few minutes between runs that sample the same Office canaries.
- The Graph fields W3.2 reads are now tested on live bodies: runs 1 and 2b's `--record`
  folders are replayed whole by `worker/tests/restore_replay_test.cpp`
  (`worker/tests/fixtures/recordings/w32-live-run{1,2}/`, the owner's two real mails' bodies
  and one invoice number replaced, each edit in the folder's README). Re-recording W2.2's
  target-state fixtures (the W3.2 entry's Open item) is no longer needed for coverage; do it
  when those states are next recorded.
- Veeam's explore-session Stop timed out once (run 2, 30 s twice, before any restore; the
  command refused to go on, exit 4, as designed). Watch for it; no change now.

---

## 2026-10-01 — W3.2 review: only this run's files are read back, a copy counts once, office-v1 no stricter than the seeder (proposed)

Amends the W3.2 entry below (points 1, 4 and 6). Two reviews of the build (the checker and
the command; office-v1, the rules and CI) found no false pass on the normal paths and these
defects, each fixed with a test that failed first:

1. **The after read downloads only this run's files with an expected name**
   (`TargetReaderOptions::hash_file`, `verification::hash_filter`). Before, it hashed every
   file in a target, earlier runs' leftovers included, so one leftover that couldn't be read
   (deleted during the read, a size Graph and SharePoint disagree on, over 64 MiB) made every
   item of its type `error`, and the leftovers, piling up until W3.4, were downloaded on every
   run. Other files are listed, not downloaded.
2. **Times are compared without subtracting them.** `want - got` in nanoseconds overflowed for
   years far apart (1700 against 2026) and wrapped to a match; now `got` is checked against
   `want ± 120 s`.
3. **A failure in the check that isn't Graph's keeps the restore's exit code.** An unexpected
   exception after the restore (out of memory, a broken expectation) ended as "unexpected
   failure", exit 1, without the note that the restore ran. Now `check error: unexpected
   failure`, the note, and the restore's own code, or 4 when that was 0.
4. **A copy counts for one item only.** Random mails now claim the copies they match, as
   canaries do, and so do files: two expected items of one subject (or one file name) and one
   copy give one `match` and one `missing`, never two matches. The sampler already prevents
   it; `check` is a general function and a Cloud job's sample might not.
5. **The earlier-copies line is a warning on stderr**, as point 1 said.
6. **office-v1 is no stricter than `lab/seeder/office.py` where a valid file could fail.**
   libzip's `ZIP_CHECKCONS` refused a package whose local header disagrees with its directory
   on a part the rule never reads, and trailing bytes after the end record; Python hashes both,
   so a restored file Word opens would have been a `sha256` mismatch, a false `fail`. It is
   dropped (`refuse_doubled` still refuses a name stored twice), and a deflated part declaring
   more bytes than it holds is accepted as Python accepts it. The entry-count limit is now read
   from the end record before libzip allocates the directory. The C++-only refusals
   (methods other than stored and deflate, encryption, a stored part whose sizes differ, the
   limits, names taken as stored) are written in `lab/README.md`'s office-v1 section: hostile
   input only, no Office writer produces them.
7. **Docs** follow: `docs/worker-config.md` (the check's exit-code rows, `graph list`'s Inbox
   check first, a 403 there now the guard's refusal, exit 4, where it was a permission error,
   exit 2), `docs/security/graph-permissions.md`, and the Graph fixtures README (seven request
   lines widened over the 2026-09-28 bodies until re-recorded: an Open item of the W3.2 entry).

**Reason.** Each was a way for the check to report something other than what the restore did:
an outage of a file nobody asked about, a time a century off, a lost exit code, one copy
proving two items, a valid document failing. The product's claim is only as good as the
check's.

**Alternatives rejected.** *Keep `ZIP_CHECKCONS` and document it*: a stricter rule than the
seeder's turns a writer's harmless quirk into a `fail`. *Refuse two expected items of one
name in `check`*: a logic error after the restore has run loses the run's result; claiming
reports the truth (one copy, one item). *Download every file but ignore errors on stale ones*:
still a download per leftover per run, and an error swallowed is an error hidden.

---

## 2026-10-01 — W3.2: the checker (proposed; recorded before the build)

Recorded before any of it was built, from W3.1's "Open" items (the W3.1 entry below) and issue
#37. Where the issue text predates W3.1, W3.1 wins: a random mail's sender is Veeam's display
name, a random Office file has no size, and a value missing from the expectation is not
checked. The owner confirmed the before/after snapshot (1), libzip (4), the exit codes until
W3.3 (6) and the timing split (7) on 2026-10-01; the rest is proposed until the W3.2 review.

**Decision.**

1. **One read of each target, before and after; this run's copies are the new ones.** The
   checker never searches per item. `rpworker restore` lists the three targets without hashing
   just before `restore_sample` (the *before* snapshot: each mail's Graph ID, each file's ID and
   `cTag`), and lists them again, hashing, after it (the *after* listing), through
   `TargetReader`, so every read keeps W2.2's guards and paging rules; the mail listing gains
   the `check_restore_mailbox` check the file listings already run. Matching is in memory:
   - **Canary mail:** among the mails not in the before snapshot (a restore gives every copy a
     new Graph ID: W2.5 and W2.8 restored `RP-CANARY-0001` under two IDs), the ones whose
     `internetMessageId` equals the manifest's; if none, the ones whose subject is the
     expected subject exactly (then `internet_message_id` is reported as the field that didn't
     match).
   - **Random mail:** the new mails whose subject is the expected subject exactly, not already
     claimed by a canary.
   - **File:** the files of its own target whose name has the expected name's `name_key`
     (`src/name_key.hpp`, the sampler's Unicode case key: SharePoint and OneDrive names are
     case-insensitive). A file that was in the before snapshot counts as this run's only if its
     `cTag` changed (a restore over a same-named file merges a new version into it,
     `documentLastVersionAction: Merge`, same item ID); one whose `cTag` didn't change is an
     earlier run's copy, and the item is `error` (`stale_target`), neither found nor missing:
     the checker can't tell whether this restore wrote it.
   - **Duplicate:** more than one new copy matches. The checker compares the newest (mail:
     `createdDateTime`, file: `lastModifiedDateTime`, then the higher ID), sets
     `duplicate: true` and `copies: n`, and does not change `match` because of it; W3.3 decides
     whether a duplicate fails a run. With the at-most-once POST and the same-name refusals of
     W2.5/W2.6, a duplicate means Veeam wrote twice, which W3.3 should see.
   - Leftovers from earlier runs are ignored, not checked, and counted (`stale_copies` per
     target in the check's JSON, and one warning line), so a run on unclean targets still
     verifies honestly. An earlier mail copy can't pass for this run's (new Graph IDs only);
     an earlier file copy can't either (`stale_target` unless its `cTag` moved).

2. **Comparisons and tolerances, per field present in the expectation; a field the
   expectation doesn't carry is not compared.**

   | Field | Rule |
   |---|---|
   | subject | byte-equal |
   | `sender_address` (canary) | `from.emailAddress.address`, ASCII case-insensitive |
   | `sender_name` (random) | `from.emailAddress.name` after `rp::without_controls` (the expectation's own rule), byte-equal |
   | `received_at` | Graph `receivedDateTime` within ±120 s (the issue's 2 minutes; every live restore so far kept it to the second) |
   | `sent_at` | Graph `sentDateTime` within ±120 s, for the same reason |
   | `internet_message_id` (canary) | byte-equal |
   | mail `sha256` (`text-v1`) | `text_v1_sha256(body.content)` equal |
   | file name | found by `name_key`, so equal after normalisation by construction; not a separate field |
   | file `size_bytes` | the downloaded byte count equal (only `bytes` canaries and non-Office random files carry one) |
   | file `sha256` `bytes` | SHA-256 of the downloaded bytes equal |
   | file `sha256` `office-v1` | `office_v1_sha256(bytes, file_type)` equal; a restored docx/xlsx that is no valid package (not a ZIP, no content part, a part twice, a bad CRC, a limit hit) is a mismatch on `sha256` with that reason: the restored file is broken, not the test |

   Times are parsed as UTC from Graph's `YYYY-MM-DDTHH:MM:SS[.f]Z` and the expectation's
   whole-second form. A Graph value that is missing or unparseable where the expectation has
   one is a mismatch on that field.

3. **`FoundItem` gains** `sender_name` (`from.emailAddress.name`, already in the reply),
   `sent_at` (`sentDateTime`), `created_at` (mail and file `createdDateTime`), `modified_at`
   (file `lastModifiedDateTime`), `ctag` (file `cTag`) and `listed_size` (Graph's size, kept
   beside the downloaded count). The `$select` strings become
   `id,subject,from,sentDateTime,receivedDateTime,createdDateTime,internetMessageId[,body]`
   and `id,name,size,cTag,createdDateTime,lastModifiedDateTime,file,folder`. All are plain
   message and driveItem properties under the three existing read grants
   (`docs/security/graph-permissions.md`: no new permission). The fixtures that carry these
   URLs, `tests/graph_lab.hpp` and the lab recorder's `MAIL_SELECT`/`CHILDREN_QUERY` change
   together, and the new fields are re-recorded live (W2.1's `record-graph-fixtures`) rather
   than written by hand.

4. **office-v1 in C++: libzip from vcpkg, `default-features: false`** (zlib only; BSD-3;
   1.11.4 at the pinned baseline; zlib is already in the build through curl and goes into
   `vcpkg.json` explicitly). `rp::office_v1_sha256(std::string_view bytes, file_type)` in
   `rp/office_v1.hpp` follows `lab/seeder/office.py` exactly: docx `word/`, xlsx `xl/`, any
   other type refused; every part from the central directory, a name twice refused; parts
   under the folder, not containing `_rels/`, not ending in `/`, case-sensitive; sorted by
   UTF-8 bytes; one line `sha256  name\n` each; the SHA-256 of the lines. Read from memory
   (`zip_source_buffer_create`), stored and deflate only, encrypted entries refused, CRC
   checked, each part read by `zip_fread` under a cap (64 MiB per part and in all, 10 000
   entries), so a zip bomb is a refusal. It passes `shared/testdata/office-content-v1/`; since
   every counted part there is stored, the C++ tests add their own deflated packages (as
   `lab/tests/test_office.py` does). **A pptx** (and every other Office type but docx and xlsx)
   has no office-v1 rule: the manifest loader already refuses office-v1 on anything but docx
   and xlsx, so no canary is a pptx, and a random pptx is `metadata` by name only (W3.1). Its
   content is never checked in Stage 1; a `ppt/` rule would be a new rule, `office-v2`.

5. **The result type.** `rp::verification::check(ExpectedSet, before, after)` (pure: the
   Graph reads happen outside it) returns a `CheckResult` with one `ItemCheck` per expected
   item, in the same order and with the same `index`, so `expected.items[i]`,
   `RestoreResult::items[i]` and `check.items[i]` describe one item. `ItemCheck`: `index`,
   `outcome` (`match`, `mismatch`, `missing`, `error`), `found`, `mismatches` (the field
   names: `subject`, `sender_address`, `sender_name`, `sent_at`, `received_at`,
   `internet_message_id`, `size_bytes`, `sha256`), `reason` (one line, no tenant values),
   `duplicate`, `copies`, `graph_id`, `ms`, and `error_code` for `error`. An infrastructure
   failure (a Graph `AuthError`, `PermissionError`, `TransientError`, `WrongTargetError` or
   other `GraphError` while listing or downloading a target) makes every item of that type
   `error` with `graph_auth`, `graph_permission`, `graph_transient`, `target_guard` or `graph`,
   never `missing` or `mismatch`; the other types are still checked. JSON, the result's `check`
   object (W4.1 adopts it into `result.v1.json`, which doesn't exist yet): `counts` per
   outcome, `stale_copies` per target, `items[]` with `index`, `outcome`, `found`, then
   `mismatches`, `reason`, `duplicate`, `copies`, `error_code` and `ms` only when set. Found
   values (subjects, names, senders) are never written: the expectation already holds what was
   checked, and the result shouldn't hold more tenant data than it. `ms` is the item's own
   cost: its file's download, hash and office-v1 time, measured inside `TargetReader` per file,
   plus its comparison; for a mail, only the comparison (its body comes with the listing).

6. **`rpworker restore` checks after it restores.** It builds the expected set
   (`build_expected_set`), takes the before snapshot, restores, reads the after listing,
   checks, and prints one row per item (KIND SOURCE NAME OUTCOME FIELDS DUPLICATE MS) and a
   `check` line with the counts. Until W3.3 the exit code is the restore's, then 5
   (`exit_code::restore`) if any item is `missing` or `mismatch`, then 4 if any is `error`;
   W3.3's table replaces this. A Graph failure on the before snapshot stops the run before any
   Veeam restore (exit 2, 3 or 4, as `graph list`). No `--no-check`: a restore that isn't read
   back proves nothing.

7. **Timings: W3.2 owns per-item `ms` and nothing else.** W3.5 owns the timer, the run's spans
   (`restore_point_lookup`, `sample_select`, `restore_submit`, `restore_wait`, `verify`,
   `cleanup`, `total`) and the issue's "total recovery time = restore start → last item
   verified", which becomes a W3.5 span. The issue's step-timings line moves to W3.5.

**Reason.** One listing per target before and after is the only isolation the evidence
supports: restored mails keep their `receivedDateTime` and `internetMessageId`, files keep
their name and `createdDateTime` and land flat in the target root (L1.4, W2.5, W2.8), so no
property of a copy says which run wrote it, except a mail's new Graph ID and, for a file, a
`cTag` that moved. Matching in memory needs no new Graph URL shape (`$filter` on
`internetMessageId` would be a new path for the guards and fixtures) and reuses TargetReader's
guards. Infrastructure failures stay `error` by type, so a Graph outage can never look like a
missing item. libzip is mature, reads from memory, streams each part under a cap, and needs
only zlib, which the build already ships.

**Alternatives rejected.**
- *Search per item* (`$filter=internetMessageId eq …`, a file by path): a new URL per item for
  the guards to vet, a 404-or-empty meaning to define, and no way to tell this run's copies
  from leftovers.
- *Require empty targets* (`error` if anything is there before the restore): honest, but every
  run would stop until W3.4 and the owner would empty the targets by hand each time; the
  snapshot gives the same safety and lets W3.4's Cleaner come later.
- *Take the newest and pass* on a file whose `cTag` didn't move: an earlier run's copy would
  pass for a restore that wrote nothing, the false pass the product exists to prevent.
- *A hand-written ZIP reader on zlib*: full control, but 200–300 lines of format parsing that
  libzip already does and is tested for; *minizip-ng* (defaults pull bzip2, lzma, zstd),
  *zlib's minizip* (memory I/O through a custom filefunc, a CVE history), *miniz*/*kubazip* (a
  second inflate beside zlib, weaker limits).
- *Found values in the JSON*: more tenant data in the bundle than the expectation holds.
- *Building W3.5's timer here*: two tasks owning one thing.

**Open.**
- A live check early in the build: after a restore over a same-named file in a target, does
  its `cTag` change? If not, every such item is `stale_target` (`error`) until the targets are
  emptied, which is safe; the check only settles what can be detected.
- W3.3: whether `duplicate` fails a run, and how `stale_target` maps (proposed: `error`).
- W3.4: the Cleaner empties the targets; the before snapshot stays as a second guard.
- The guide's `rpworker test` exit codes (0/1/3, W3.6) clash with `rp::exit_code`; W3.6 decides.
- Re-record the Graph target fixtures (`record-graph-fixtures --state empty|one-item|paged`) so
  their bodies carry the new fields; until then 7 fixtures have widened request lines over
  2026-09-28 bodies.

---

## 2026-10-01 — W3.1 code review: what SharePoint rewrites, and expectations no item can over-claim (proposed)

The `/code-review` of PR #145 found 13 issues; the owner chose six to fix and one to check
live. Amends the W3.1 entry below (points 5, 9 and 10).

1. **SharePoint's rewritten files, checked live.** The review doubted point 5's list: if
   SharePoint rewrites a format the list leaves out, a random file of it gets Veeam's size as
   its expectation and reads as `fail` after a good restore, and `graph list --hash` refuses
   it as larger than Graph's size. Checked on 2026-10-01 (evidence
   `docs/api/veeam-lab/w3.1-rewrite-check/`: the script, how the 23 test files were made, the
   results): each file uploaded through Graph into a scratch folder of the RestoreTarget
   library (as the admin; alice can't write it) and of alice's OneDrive `/RestoreTarget`, read
   back at once and after 15 minutes, both folders deleted. SharePoint rewrote docx, docm,
   xlsx, xlsm, pptx, pptm, **xlsb, doc, xls and ppt** (bigger at once, the same 15 minutes
   later; for the packages `docProps/`, `customXml/`, `[trash]/`, `[Content_Types].xml` and
   relationship parts, never `word/`, `xl/` or `ppt/` content). It left vsdx, vsdm, vssx, vstx,
   xlam, ppam, odt, ods, odp, pdf, rtf and txt byte-identical. OneDrive rewrote nothing, docx
   included. So the rule becomes `rp::is_rewritten_office_file` with `.xlsb`, `.doc`, `.xls`
   and `.ppt` added; the untried templates and shows stay. It doesn't depend on the location:
   a rule per location would trust that OneDrive never starts rewriting, and a random file
   then only loses its size check. Limits: the doc, xls, ppt and ODF files came from
   LibreOffice, not Office; vsdm, vssx, vstx, xlam and ppam were real packages with only their
   main content type changed (SharePoint picks its parser by extension); one library with its
   default columns.
2. **No size expectation from a size not known.** A random file whose `size_bytes` is below 0
   (a connector's "not known", -1) gets `metadata` by name only, as point 7 does for a mail's
   missing fields. Refusing it in the sampler was rejected: the connector is backend-neutral,
   and a missing fact was never a reason to drop an item.
3. **A canary's rule must be one its file can be checked by.** The manifest loader refuses
   `bytes` for a docx or xlsx, `office-v1` for a pdf, txt or png, and a name the Office rule
   matches for any other type (or doesn't match for those two), as `python -m seeder`'s
   validator already does for `content_rule`.
4. **No item can read as checked against a hash it hasn't.** `ExpectedItem`'s defaults are a
   canary's, so `to_json` now refuses (`std::logic_error`) an item whose fields don't back its
   kind: `manifest` needs a canary source and ID, no key, a lower-case hex SHA-256 and its
   type's rule; `fields` and `metadata` need a random source, a key, no canary ID or hash, and
   a mail or a file respectively; and each item must be at its index. `to_string` of a kind or
   source outside the enum is `"unknown"`, never `"manifest"`. Making the kind a required
   constructor argument was rejected: every builder would change for a check `to_json` makes
   once, where the result is written.
5. **The record's counts must be the selection's.** `build_expected_set` also refuses a record
   whose `random_taken` or `canary_wanted` isn't what the selection holds, so the `sample` and
   `expected` objects can't disagree on how many items were tested.
6. **A sender's display name is text a third party chose.** Each control character in it
   (`control_chars.hpp`) becomes a space as Veeam's `from` is read, through
   `rp::without_controls`, which `one_line` now uses too.
7. **`expected_set_test.cpp` puts its failure paths first**, as the TDD rule says.

Left as review comments, not done here: the duplicate random selector in `Selection`, the
tie-break that keeps the copy with fewer facts, the narrower `internet_message_id` control
check, the doubled comparisons in the sort, and the third `kind_name` copy. The 5-byte
extension assumption went with point 1.

---

## 2026-10-01 — W3.1: the expected set (proposed; recorded before the build)

Recorded before any of it was built. The owner confirmed decision 3 on 2026-10-01 (a random
file's content is not expected in Stage 1; Veeam's document export is a follow-up task after
W3.2). The rest is proposed: the owner confirms it in the W3.1 review, or supersedes it.

**Decision.**

1. **Every sampled item gets one expected record with one explicit expected kind.**
   `rp::verification::build_expected_set(selection, manifest)` (`rp/expected_set.hpp`, a new
   namespace W3.2 and W3.3 will share) is pure and returns one `ExpectedItem` per selector of
   the selection. There are three kinds, never mixed, and no "unknown" kind or default path:
   - `manifest`: a canary. The expected values are the manifest's, with a content hash: a
     mail's `body_sha256` by `text-v1`, a file's `content_sha256` by its `content_rule`
     (`bytes` or `office-v1`). A `bytes` file also expects its `stored_size`; an `office-v1`
     file expects no size (SharePoint rewrites it). The strongest kind.
   - `fields`: a random mail. The header fields as the backup lists them (Veeam's browse):
     subject, sender display name, sent time, received time. No body hash: nothing knows the
     body before the restore.
   - `metadata`: a random file. Its name, and the size the backup lists, except for an Office
     package (point 5), whose size is no expectation, so its name only.
   The result shows each item's kind and counts the three (`counts`, all three keys always
   there), so a report never claims more than was checked (W3.3, W4.1).
2. **Random items are expected from the backup's own listing, not from Graph.** The Worker app
   may read only the restore targets through Graph (L1.5, W2.6), so it can't read a random
   item's source. This supersedes the glossary's sentence that a random item's expected values
   come from a live Graph read (`docs/glossary.md`, "Random item", updated).
3. **A random file's content is not expected in Stage 1** (owner confirmed 2026-10-01): no
   Veeam export in W3.1. See Alternatives and Open.
4. **A random mail's sender is a display name** (`sender_name`), because that is all Veeam's
   browse lists (`from`, e.g. "Hrachya Harutyunyan"); a canary's sender is an address
   (`sender_address`, the manifest's `sender`). W3.2 compares each with the matching Graph
   field (`from.emailAddress.name` or `.address`).
5. **One Office package rule.** `rp::is_office_package(name)` (`src/office_files.hpp`): the
   name ends, ASCII case-insensitive, in `.docx`, `.docm`, `.dotx`, `.dotm`, `.xlsx`, `.xlsm`,
   `.xltx`, `.xltm`, `.pptx`, `.pptm`, `.potx`, `.potm`, `.ppsx` or `.ppsm` (the Office Open XML
   family SharePoint may rewrite), with something before the dot: a name that is only an
   extension (`.docx`) isn't a package's. It decides a random file's "size is not an
   expectation" and replaces the inline docx/xlsx check in `graph_targets.cpp`, so `graph list
   --hash` now reads a pptx and the macro and template types up to the download limit too
   (`SizeCheck::up_to_limit`), like docx and xlsx. Canaries keep the manifest's
   `content_rule`. `office-v1` hashes only the `word/` and `xl/` parts, so it covers docx and
   xlsx and not pptx: W3.2's concern (a random pptx is `metadata`, name only).
6. **Times are `YYYY-MM-DDTHH:MM:SSZ`**, cut (not rounded) to whole seconds by the rule the
   selector's `received_at` already uses (`veeam_restore::to_whole_seconds`). Tolerances (the
   guide: received within 2 minutes) belong to W3.2.
7. **A missing backup field doesn't drop a candidate.** A random mail without `from`, or whose
   `sent` isn't a time, is still offered and gets `fields` with what is known (its subject and
   received time are always there: the lister requires them). A random file always has a size
   (the lister requires `sizeBytes`).
8. **Order and identity.** The expected set is in `RestoreSpec` order (mail canaries, mail
   randoms, SharePoint canaries, SharePoint randoms, OneDrive canaries, OneDrive randoms), each
   item carrying its `index`, so it lines up with `RestoreResult::items`. A canary is named by
   its manifest `id`, a random item by the sampler's key (the strings of
   `record.<kind>.random_keys`).
9. **The candidates carry their facts beside the key.** `connector::MailCandidate{selector,
   sender_name, sent_at}` (empty: Veeam didn't say) makes `CandidatePool::mail` like the two
   file candidate types, and `Selection` gains `mail_random`, `sharepoint_random` and
   `onedrive_random`: the random candidates taken, in their selectors' order, each selector's
   size -1 as before and the backup's `size_bytes` kept. The sampler's keys, deduplication,
   draw, `pool_sha256` and `to_json(SampleRecord)` don't change, so the W2.8 run's recorded
   sample still replays to the same pool hash. Candidates of one key and equal fields but
   different facts are sorted by those facts too, so which one survives deduplication doesn't
   depend on the listing's order.
10. **The manifest's comparison fields become required in the loader.** `CanaryMail` gains
    `sender`, `sent_at`, `internet_message_id`, `body_sha256` and `body_normalization`;
    `CanaryFile` gains `content_sha256`. The schema requires them already, so the lab manifest
    passes; a pilot's manifest without them is refused as it loads, before any Veeam call,
    rather than giving items that can't be verified. Refused: a `sender` that isn't exactly one
    `@` with no whitespace or control character; a `sent_at` that isn't a real whole-second
    UTC time; an empty `internet_message_id` or one with a control character; a `body_sha256`
    or `content_sha256` that isn't 64 lower-case hex digits; a `body_normalization` other than
    `text-v1`.
11. **Privacy.** The new customer data in the result is a random mail's sender display name
    and sent time; its subject, mailbox and received time are in the sample record already.
    Nothing else.

**Reason.** W3.2 needs, per item, what to compare against and how strong that expectation is;
recording it before anything is compared keeps the checker from taking its expectations from
what it finds. The kinds keep the report's claims to what was tested (the report wording
rule). The backup's own listing is the only source the Worker app may read for a random item,
and it is what the restore restored from.

**Alternatives rejected.**

- *A fourth kind, `backup_content`, from Veeam's document export* (`…/Documents/{id}/save`
  during `restore_sample`, the file's hash then expected): deferred, not rejected for good. An
  Office file needs `office-v1` in C++, which needs the zip reader W3.2 brings; it doubles each
  random file's traffic (export and read-back, up to 64 MiB each); it makes the builder depend
  on `restore_sample`; the lab has no real files yet, so the path couldn't be run live. The
  `expected_kind` field makes adding it later non-breaking.
- *Expected values for random items from a Graph read of the source:* the Worker app has no
  grant on any source (point 2).
- *The facts inside the sampler's key:* every key and `pool_sha256` would change, and the W2.8
  run's recorded sample would no longer replay.
- *Two Office rules (the reader's docx/xlsx and the expected set's list):* two lists drift.

**Open.**

- A follow-up task after W3.2: the `backup_content` kind for random files from Veeam's
  document export, once `office-v1` exists in C++ (point 3).
- For W3.2: `FoundItem` needs the sender display name (`from.emailAddress.name`; Graph's
  `$select` returns `from` already) to check `sender_name`; a canary mail is best found by
  `internet_message_id` first (the manifest has it, and the W1.0 export kept it), then by
  subject; `office-v1` in C++ needs a zip reader (none in `vcpkg.json` today) and must pass
  `shared/testdata/office-content-v1/`.

---

## 2026-10-01 — Q2.1 review: the restore credential never kept, recording off the lock, and the refusal rules (proposed)

Amends the 2026-10-01 Q2.1 entry (points 2, 3 and 5) after the Q2.1 code review.

**Decision.**

1. **The restore credential is checked in its own exchange's file only.** What the recorder
   learns (`rp::secrets_in`, now `rp::LearnedSecrets`) comes in two lists. `kept` holds the
   `Authorization` value, tokens, form and query secrets, and a response body's secret values;
   these are checked in every later file. `one_time` holds the secret values of a JSON request
   body, which is a restore POST's `applicationCertificate` and its password. That credential
   is exported for one call (2026-09-30 W2.5 point 1), so it is checked against its own file
   and then wiped. The recorder's copies are wiped too (`secure_wipe`): both lists when they
   go, every kept secret in `~FixtureRecorder` (held in a deque, so adding one never leaves a
   moved copy behind), a parsed JSON body's strings and its text before redaction, the
   JSON-escaped copy of each secret the check makes, and a refused file's text. A later file
   that held a past restore's credential would no longer be refused by the known-secret
   check; `redact()` still replaces it under its own keys.
2. **Recording no longer holds up the command.** Secrets are learned before any lock. The
   kept list sits under a shared mutex, locked exclusively only to add to it and shared while
   files are scrubbed. The numbering and the counts have their own short lock. The scrub and
   the disk write run outside both, so one exchange's write never delays another's send. A
   `digest` body (a download) is not converted or scanned: nothing is learned from it, since
   it is never written.
3. **The refusal rules.** The JWT rule uses `redact()`'s `rp::kJwtStart` and
   `rp::is_base64url` (now in `rp/redact.hpp`), and keeps its own length threshold (37) on
   purpose: it catches a dotless run `redact()` would miss. `client_assertion` is now refused
   the way `tempauth` is, and no longer as a mere mention. A value of it (the name in any case,
   then `=`, `%3D` or `:`) other than a placeholder is refused. Entra's AADSTS7000218 text,
   which only names the parameter, can be recorded.
4. **Small fixes.** The `--record` folder is checked with `is_directory` after
   `create_directories`, whose MSVC result is false for a path ending in a separator even when
   it made the folder. `restore` opens its recording only after its pre-Veeam checks (sample
   sizes, manifest, cursor), so a run they stop makes no folder and prints no `recorded` line.
   `FakeHttpClient::serve_recording` orders files by their number, so file 1000 comes after 999,
   and matches requests by `rp::request_path`, the recorder's own rule. The commands' option
   loops are one parser, `parse_options` in `src/command_config.hpp`.

**Reason.** The code review of the Q2.1 PR found these. Point 1 restores W2.5's rule that the
exported PFX outlives its call nowhere, which `--record` had broken.

**Alternatives rejected.** Keeping the credential and wiping it only when the recorder goes
(the recorder lives for the whole restore); keeping a hash of it instead (a hash can't be
searched for in a file); widening the file number to four digits (every committed recording's
names would change, and 10 000 exchanges would still break it).

---

## 2026-10-01 — Q2.1: `--record <dir>`, what a recorded fixture keeps, and the unit tests' network guard (proposed)

With the owner's answers of 2026-10-01: `restore` may record, and `--record` takes a folder
that must be new or empty. Proposed: the owner confirms it in the Q2.1 review, or supersedes it.

**Decision.**

1. **`--record <dir>` on `veeam list`, `graph list [--hash]` and `restore`.** Each wraps the
   HTTP clients it makes in `rp::RecordingHttpClient` (`rp/recording_http_client.hpp`), which
   passes every request to the real client unchanged and hands each response it returns to
   one `rp::FixtureRecorder`. A request that throws (no connection, a timeout) isn't recorded
   and its exception goes on unchanged. Recording never changes what a command sends or sees;
   a file refused or not written is a line on stderr, never an exception inside the command,
   so a restore's at-most-once POST can't be mistaken for a POST that got no answer.
2. **Where it goes.** `<dir>` must not exist or be an empty folder (otherwise exit 1,
   `config error: <dir>: the --record folder is not empty`, before any request), so a
   recording never overwrites committed fixtures: the developer looks the files over and copies
   the ones wanted into `worker/tests/fixtures/<service>/`. One subfolder per service: `veeam`
   (the Veeam client and the connector), `graph` (Entra's token endpoint and Graph, the target
   guard's included) and `download` (`graph list --hash`'s downloads). One file per exchange,
   `<nnn>-<method>-<path slug>.json`, numbered per service from 001 in the order sent; a
   refused exchange keeps its number, so the gap shows. After the command:
   `recorded <n> exchange(s) in <dir>` on stdout, one `record error: <service>/<file>: <why>` per
   exchange not written on stderr, and exit 1 if the command had succeeded (a command that
   failed keeps its code).
3. **The file format is the fixtures' own** (`worker/tests/fixtures/veeam/README.md`):
   `source` (`rpworker <version> <command> --record`), `request` (`<METHOD> <path>?<query>`, no
   scheme or host), `status`, `headers`, `body`; `FakeHttpClient::serve_recording(dir)` serves
   a service folder by method and path, the files of one request in number order, the last
   repeating, whatever the host. Key order is kept as received.
4. **What a fixture keeps, and never keeps.**
   - Request headers: none, ever. Response headers: only `Content-Type`, `Retry-After`,
     `WWW-Authenticate` and `Location`, the last with every query value `SCRUBBED`.
   - Request bodies: only a JSON one (a restore's), as `request_body`. A form body (the Veeam
     password grant, Entra's client assertion) and a multipart one are never written.
   - Response bodies: JSON as JSON, with every `@microsoft.graph.downloadUrl` and
     `@content.downloadUrl` dropped; other UTF-8 text as a string; a body that isn't UTF-8,
     and every `download` body (file contents), only as `body_size` and `body_sha256`, never a
     byte. A download's request line has every query value `SCRUBBED` (the link is a
     credential).
   - All of it goes through `rp::redact()`, so tokens, the client assertion, passwords, the
     PFX, `applicationCertificate*` and `Authorization` read `[REDACTED]`; a token reply's
     `access_token` and `refresh_token` become that placeholder, which the Veeam and Graph
     clients accept on replay.
5. **Refused if a secret survives** (mirroring `Save-Evidence`, the PowerShell collection's
   evidence writer): the recorder is given the Veeam password, the Graph PFX and its password,
   and learns, before scrubbing, every secret an exchange carries (the `Authorization` value
   and its bearer token, the values of the keys `redact()` treats as secret in a form, JSON
   body or query, a `Location`'s included); values under 6 characters and the placeholders are
   left out. A file whose text still holds one (as written or JSON-escaped), anything
   JWT-shaped (`eyJ` and 37 or more base64url characters), a `tempauth` value other than a
   placeholder, or the word `client_assertion` is not written.
6. **The unit tests' network guard.** `rptests` has its own `main` (`tests/test_main.cpp`):
   unless `RP_LIVE=1`, it turns on `rp::detail::set_loopback_only`, under which `rp::HttpClient`
   refuses any URL whose host isn't `localhost`, `127.x.x.x` or `[::1]` before any lookup, and
   any socket curl would open to an address outside 127.0.0.0/8 and ::1 (a
   `CURLOPT_OPENSOCKETFUNCTION` callback, the TLS scan's one new reviewed statement). A
   listener counts the refusals per test case; a case with any is named on stderr and the run
   exits 1 even if the test passed. `rpworker.exe`'s ctest runs all stop before any request
   (their comments in `worker/CMakeLists.txt` say so). The manual proof is one `ctest --preset
   dev` with the network adapter disabled (`docs/testing.md`, "The network-off run").

**Reason.** Sprint 3 needs new fixtures (W3.2's deleted messages, W3.4's empty folders after
cleanup), and recording them from the Worker's own C++ calls is safer than writing them by hand
or from the PowerShell collection. A folder that must be empty keeps a recording from ever
landing on committed fixtures unreviewed. Refusing, rather than scrubbing harder, keeps the
rule simple: a file with a secret in it is never written at all. The guard turns "the unit
suite never touches the network" from a convention into something every CI run checks.

**Alternatives rejected.** Recording straight into `worker/tests/fixtures/` (overwrites
hand-edited fixtures); recording only the read-only commands (W3.x needs whole restore runs,
and recording only watches); keeping request headers or form bodies with their secrets
redacted (nothing needs them, and redaction is the only thing between them and the repo);
recording download bytes (canary files are in `lab/canary/` already, and a restored file could
be anything); a proxy variable pointing curl at a dead address (a test expecting a connection
error would still pass, and nothing would name it); a firewall rule or container in CI (heavy,
and not what runs on a developer's machine).

---

## 2026-10-01 — W2.8 second review: the certificate and the manifest checked before Veeam, and what a restore that failed partway says (proposed)

Amends the 2026-09-30 W2.8 entry (points 3, 4 and 5) after the second W2.8 review (PR #142).
Proposed: the owner confirms it in the review, or supersedes it.

**Decision.**

1. **The Graph certificate is opened and checked before any Veeam call**, by the same
   `graph::certificate_from_secrets` the connector uses (not only checked as set). A wrong
   password, a PFX that isn't Base64 or a certificate that isn't valid now is exit 1 before the
   sampler browses Veeam. `RP_GRAPH_CERT_PASSWORD` unset is no password, as for `graph list`:
   the W2.8 amendment that required it set refused a PFX without a password that `graph list`
   accepts. The check logs nothing; the connector's own load still warns of a certificate about
   to expire.
2. **The manifest is checked in full before the connector is made**: its tenant and that no
   canary is in a restore target, through `sampling::check_manifest`, which `choose_sample` also
   runs, and the cursor through `sampling::cursor_problem`, which the sampler's own check also
   uses. One rule and one message each; an unreachable Veeam can no longer turn a manifest that
   names a restore target into exit 3.
3. **A restore that fails after it started says items may be in the targets.** An error from
   `restore_sample` is followed by `restore error: the restore had started: items may be in the
   restore targets (run <id>)`, unless its message ends with `; nothing was restored`
   (`connector::kNothingRestored`), which `IConnector::restore_sample` now documents as the
   connector's promise that nothing was sent. The tables aren't printed: the error carries no
   partial result (a later task may add one).
4. **stdout failing after the restore ran** keeps the restore's exit code (5, or 4 with its
   line) and says the status in its line; a restore that succeeded is exit 1 then, since its
   output was lost.
5. `rp::require_veeam_secrets` (`rp/secrets.hpp`) is the one "is not set" rule for the Veeam
   secrets, used by `veeam list`, `restore` and the `veeam_m365` connector.

**Reason.** The review found the certificate and manifest problems surfacing only after Veeam
had been browsed (or hidden behind a Veeam error), a PFX `graph list` accepts refused by
`restore`, and an operator left without a hint that items were restored when a later session
failed.

**Alternatives rejected.** Keeping only the presence checks (a bad certificate still wastes a
browse per type); matching every connector message for "sent" or "not sent" (only "nothing was
restored" is a promise about the whole call; the others speak of one POST); passing the loaded
certificate into the connector (it makes its Graph client itself, on the first restore).

---

## 2026-09-30 — W2.8: `rpworker restore`, its flags and output, and exit code 5 (proposed; recorded before the build)

Recorded before any of it was built, with the owner's answers of 2026-09-30 (exit code 5, the
manifest beside the config, a random-half shortfall is not a failure). Proposed: the owner confirms
it in the W2.8 review, or supersedes it. *Amended after the W2.8 review* (2026-09-30), in place,
where marked: an empty sample and an infrastructure failure are errors (4), 5 is partial or
failed only, the run ID is printed before the sample is chosen, `--point` takes `latest` in
any case, and the Graph certificate's variables are checked before any Veeam call.

**Decision.**

1. **The command line.** `rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point
   latest|<id>] [--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config
   <path>]`, the options in any order, each at most once. `<n>` is 1 to 3 ASCII digits, 0 to 100;
   an absent flag takes config's `sample_mail`, `sample_sp` or `sample_od`, and at least one of the
   three sizes must then be above 0 (exit 64, once the config is read). `--point` defaults to
   `latest` (*amended after the W2.8 review:* in any ASCII case), the newest restore point of
   `veeam_org_name` (`list_restore_points` returns newest first); `<id>` must be 1 to 128 ASCII
   letters, digits and hyphens (safe to echo in a message) and is matched ASCII
   case-insensitively against the points' IDs. *Changed in the build:* this entry first said a
   GUID, but Veeam's restore point IDs are two GUIDs run together (72 characters, e.g.
   `c2f0f2e7-…-93a50cf702e3` `71ac3d9c-…-ae81fcc4681c` in `restore-points-200.json`), and the
   connector's IDs are opaque, so a GUID rule would refuse every real ID. Anything else on the
   command line (a size above 100, a sign, a point that is neither, a bad run ID or cursor, a
   flag twice) is a usage error, exit 64, before the config is read. A well-formed ID that isn't
   one of the organisation's restore points is exit 4.
2. **Run ID and cursor, until the Cloud sends them** (W2.6 point 3 and its open point). Each
   invocation makes a run ID, `rp-<YYYYMMDDTHHMMSSZ>-<8 random hex digits>` (UTC, in
   `check_run_id`'s alphabet); `--run-id` reuses a recorded one to repeat a sample. The canary
   cursor is `--canary-cursor m,s,o` (default `0,0,0`); nothing is stored on the Worker. The
   command prints the run ID, the seed, the cursor and the next cursor before it restores, so an
   operator can repeat the run or carry the rotation on by hand. A cursor at or above the
   manifest's canaries of its type is a usage error (exit 64, once the config and the manifest
   are read; and one above 0 for a type the manifest has no canaries of); each of its three
   numbers is 1 to 6 digits, so none can overflow.
3. **The manifest** is `--manifest <path>`, default `seed-manifest.json` in the config file's
   folder (`%ProgramData%\RestoreProof\`, or the `--config` file's folder). No config key: the
   manifest is a client's, and the Cloud job will carry it (2026-09-29, "Clients live in the
   Cloud"). A manifest that doesn't load, or whose tenant isn't `graph_tenant_id`, is a
   configuration error (exit 1); the command checks the tenant as soon as the manifest is read,
   with `choose_sample`'s words, so it fails before any Veeam call.
4. **The order.** Arguments; config and the Veeam secrets (as `veeam list`); the manifest; the
   `veeam_m365` connector from the default registry; the organisation's restore points and the
   chosen one; `choose_sample`; the header printed; `restore_sample`, whose first step is still the
   target guard's layer 1 (the command adds no restore path of its own, and has no way around the
   guard); the tables. The Graph certificate is read by the connector on the restore, so a bad one
   is still exit 1. *Amended after the W2.8 review:* `RP_GRAPH_CERT_PFX_BASE64` and
   `RP_GRAPH_CERT_PASSWORD` are checked as set right after the Veeam secrets (`config error:
   <name> is not set`, exit 1), before any Veeam call, since the certificate is otherwise read
   only after the sample has been chosen; the run ID is made, and its two lines printed, before
   `choose_sample` (point 5).
5. **The output.** The header (restore point, run ID and seed, cursor and next cursor, per type
   the canaries and random items wanted and taken, with a shortfall named) goes to stdout and is
   flushed before the restore starts, which takes minutes: a run that then fails still shows its
   run ID. *Amended after the W2.8 review:* the restore point line and `run <id>  seed <hex>`
   are printed and flushed as soon as the run ID exists, before `choose_sample`, which browses
   Veeam and can fail; the cursor line (`canary cursor <m>,<s>,<o> -> <m>,<s>,<o>`, on its own
   line now, since it needs the sample's next cursor), the per-type table and `restoring <k>
   item(s) ...` follow once the sample is chosen, still flushed before `restore_sample`. A
   stdout that fails after the restore ran is `error: writing the output failed after the
   restore ran (run <id>)`, exit 1, so the operator knows items may be in the targets. After the restore: one row per item (kind, canary or random, name, outcome, session,
   the session's elapsed time, the connector's message), one row per restore session (ID, kind,
   Veeam's result, items restored of sent, start, end, elapsed), and a status line with the
   restore's status, items restored of sent and the total elapsed time. An item's elapsed time is
   its session's (end − start as the connector reports them, `-` when either doesn't read); the
   total is the `restore_sample` call's, by the steady clock. Warnings go to stderr only.
6. **Exit codes.** The existing codes keep their meaning for every command: 1 config (a manifest
   error and an unknown connector included), 2 auth, 3 transient, 4 service (a `SafetyViolation`,
   a restore point or item not found, any other connector error), 64 usage. New: **5
   (`exit_code::restore`): the restore ran and its status is `partial` or `failed`**; the
   status line says which. 0 only for `succeeded`. A random-half shortfall with every sampled
   item restored is `succeeded`, exit 0; the header shows it. Infrastructure problems never
   reach 5. *Amended after the W2.8 review* (this point first said 5 for `not_run` too, and
   that `restore_sample` throws for every infrastructure problem; it throws only when a session
   restored nothing for one, so an item can come back `failed` or `unknown` marked
   `infrastructure` in a partial restore):
   - an **empty sample** (every type asked for fell short entirely) prints the header, calls no
     `restore_sample`, and is exit 4: `restore error: the sample is empty: nothing to restore
     (<kind>: <shortfall>; ...)`;
   - a restore that returns **`not_run`** is exit 4 (`restore error: the restore did not run:
     nothing was sent (status not_run)`);
   - a restore in which **any item not restored is marked `infrastructure`** (Veeam couldn't
     reach Microsoft 365, lacked permissions or was throttled) prints the tables and the status
     line as usual, then is exit 4: `restore error: <n> item(s) failed for an infrastructure
     reason (...); this is an error, not a restore failure`. A run reports all of these as
     `error`, never `fail`.

**Reason.** The issue's "exit 0/1/3 for success/failure/error" collides with codes every command
already uses (1 is config, 3 transient); a restore that ran and failed is a result, not an error,
and needs its own code. Printing the run ID before the restore makes every run repeatable, even
one that fails. A manifest beside the config needs no new key and no new rule.

**Alternatives rejected.** *Reusing 1 or 3 for a failed restore:* a script couldn't tell a
failed restore from a broken config or an unreachable Veeam. *Two codes, partial and failed:* the
status line already says which, and W3.3's pass/fail/error replaces this code's meaning for
`rpworker test`. *A cursor file:* see W2.6. *A required `--manifest`:* every lab run would repeat
the path. *A `canary_manifest` config key:* per client, so the Cloud's.

---

## 2026-09-30 — W2.7 second review: a restore target is never a source, by what Veeam lists

Supersedes parts of the 2026-09-30 W2.7 review entry below (point 1's layer-1 mail rule and
point 2's `siteUrl` rule), after a `/code-review high` of PR #138 run on 2026-09-30, once W2.5
and W2.6 were merged.

**Decision.**

1. **Layer 2 checks the source as browsing found it.** Veeam's OneDrive document IDs don't name
   their folder and a mail restore's body doesn't name its source mailbox, so layer 2 could
   only trust layer 1's reading of the sample. `restore_sample` now passes what Veeam listed:
   `GuardedItem::top_folder` (the top-level folder walked to a OneDrive item) and
   `RestoreRequestContext::source_mailbox` (the source mailbox's `email`). Layer 2 refuses an
   item whose top folder is a RestoreTarget folder (any OneDrive) and a source mailbox that is a
   restoretest mailbox or the test mailbox, so an alias, an object ID or a stray space in the
   sample can't hide the test mailbox. `source_mailbox` is required for mail (`bad context`).
2. **One path rule, stricter.** `src/folder_path.hpp`'s `first_folder` (the guard's layer 1,
   the sampler and the manifest loader) also refuses a path holding a backslash or a colon: no
   SharePoint or OneDrive name holds either, so such a path is another spelling of a folder
   (`\RestoreTarget`, Graph's `/drive/root:/RestoreTarget`), never one of the backup. The lister
   skips folders so named. A `/Documents/RestoreTarget` subfolder stays a source, as before.
3. **Layer 1 refuses a mailbox with whitespace or a control character** (and the manifest
   loader such a canary mailbox), and **a SharePoint item on the test OneDrive's drive**
   (`test_onedrive_drive_id`; the sampler already refused it, and now its canary check too).
4. **`siteUrl` is checked where Graph gives it.** The library's must be https on
   `test_site_id`'s host, the OneDrive folder's https on that tenant's `-my` host, neither with
   a query, fragment or whitespace; before, any string (even an empty one) passed layer 1 and
   became layer 2's only reference for `siteURL`.
5. **One derivation of the OneDrive host**: `rp::onedrive_host` (`rp/config.hpp`), used by the
   download allow-list, `veeam_restore::onedrive_url`, layer 2 and point 4.
6. The lab's fixture recorder requires alice's OneDrive `siteUrl` exactly, host included.

**Kept as they were.** (a) Exchange's 403 on the mailbox check stays a `SafetyViolation` (the
W2.7 review's point 1): the guard can't tell another mailbox from a missing scope, and treating
an unverified target as a refusal fails safe; the message names both causes. (b) A bad Worker
certificate still leaves `restore_sample` as `rp::ConfigError` (exit code 1, as documented on
`VeeamM365ConnectorOptions::make_graph`); `connector.hpp` now says connectors may let it out.

**Reason.** Each layer should refuse on data it can check itself: the sample's text is the
input under suspicion, and Veeam's listing and Graph's reply are what the restore acts on.

**Alternatives rejected.** Refusing every path with a RestoreTarget segment anywhere (would
refuse real data such as `/Documents/RestoreTarget`, and the lister and sampler would have to
follow); mapping the mailbox 403 to `PermissionError` (reports a possibly wrong target as a
grant problem); converting `ConfigError` to `connector::Error` (a broken certificate would exit 4
instead of 1).

## 2026-09-30 — W2.6: how the sample is chosen (proposed; recorded before the build)

Recorded before any of it was built. Proposed: the owner confirms it in the W2.6 review, or
supersedes it.

**Decision.**

1. **The selector is pure; one new connector call lists the candidates.**
   `rp::sampling::SampleSelector::select(plan, manifest, cursor, targets, pool, run_id)`
   (`rp/sample_selector.hpp`) does no I/O and reads no clock. The random half's pool comes from
   a new `IConnector::list_candidates(CandidateQuery)` (`rp/connector.hpp`, no Veeam name in it;
   read-only for Microsoft 365; its default throws `NotImplementedError`, so another connector
   needn't have it), and `choose_sample` calls it only when a random half is above 0.
   `restore_sample` and both guard layers are unchanged: the guard still checks every item the
   sampler chose.
2. **Halves.** Per type, with N = `sample_mail`/`sample_sp`/`sample_od` and M the manifest's
   canaries of that type (today 20 mails, 10 SharePoint files, 10 OneDrive files, not 20 of each):
   c = min(ceil(N/2), M) canaries and floor(N/2) random items. Canaries left over when
   ceil(N/2) > M are not moved to the random half.
3. **Canaries rotate by a cursor, and the cursor is the rotation's only state.** A type's
   canaries, in manifest order, are taken from positions cursor … cursor+c−1 (mod M), and the next
   cursor is (cursor+c) mod M. Windows follow each other without a gap, so every canary is taken
   within ceil(M/c) ≤ ceil(20/(N/2)) runs. The Worker keeps no state: the cursor is an input and
   the result carries it and the next one. It belongs with the client in the Cloud (the
   `client-profile.v1` job of 2026-09-29, W4.10/C5.13), which hands the next run the last run's
   `cursor_next`; until then tests and the CLI pass it (`0,0,0` by default).
4. **The seed comes from the run ID; the draws are portable.** seed = the first 4 bytes,
   big-endian, of SHA-256("restoreproof/sample-v1\n" + run_id). Each type has two streams, browse
   and items, seeded the same way from the seed, the type and the stream, so changing
   `sample_mail` never moves a OneDrive pick. The generator is `std::mt19937` seeded with one
   value; `below(n)` rejects outputs at or above 2^32 − (2^32 mod n); a pick is a lazy
   Fisher–Yates over a sorted list. No `<random>` distribution, `std::shuffle` or `std::sample` is
   used: their algorithms differ between standard libraries, and an auditor must be able to
   repeat a draw anywhere.
5. **Reproducible from the seed and the manifest, with the cursor and the restore point.** The
   seed and the manifest alone don't fix a selection: the cursor says where the rotation is, and
   the random half depends on what the restore point holds. The result records all four (run ID
   and seed, the manifest's SHA-256, the cursor, the restore point's ID and `backupTime`), plus
   each pool's size and SHA-256, so a replay can show it drew from the same pool. A restore point
   doesn't change while retention keeps it. One input isn't the restore point's: a OneDrive's
   owner (`restore_sample` finds a OneDrive by its owner's UPN) comes from
   `GET /v8/Organizations/{org}/Users`, Veeam's cache of the tenant's users today. So which
   OneDrives are eligible, and the order they are drawn in, come from the restore point alone
   (every OneDrive with a well-formed ID and a `url` no other shares); a drawn OneDrive that no
   single user owns now (deleted, renamed, not yet in the cache) is walked and its folders drawn
   as usual, so the draw goes on unchanged, but nothing in it is listed. The result counts those
   (`containers_unresolved`) and lists them by `url`, so a replay after a user change shows why
   its OneDrive pool differs.
6. **The random half is drawn in two levels, from real data only.** Eligible containers
   (mailboxes, sites, OneDrives) are sorted and drawn one at a time; in each, up to 3 folders are
   drawn and listed, until 2 containers have given a candidate or 8 have been tried (a few dozen
   Veeam calls, whatever the tenant's size). Every listing is the one `restore_sample` makes later,
   and an item is a candidate only if that call will find it exactly once: its subject, file name
   or folder name is unique in the whole listing, not only among candidates. Never a candidate:
   - a restore target: a `restoretest` mailbox, the RestoreTarget library (by its derived drive ID,
     point 8, and by its `url`), a top-level `RestoreTarget` folder in any OneDrive;
   - a canary location or copy: the canary libraries (by list ID), a top-level `RestoreTest` folder
     in any OneDrive and any other top-level folder the manifest's OneDrive canaries are in
     (`CandidateExclusions::onedrive_folders`, by name in any OneDrive, as `RestoreTest`), a
     subject or name starting with `rp-canary-` or equal to a canary's (ASCII case-insensitive;
     this catches the Sent Items copies);
   - an archive, public or `DiscoverySearchMailbox` mailbox; a personal or other-host site; the
     `SitePages`, `SiteAssets`, `Style Library` and `FormServerTemplates` libraries; a non-mail
     folder (`type` other than `None`) or the Deleted, PermanentlyDeletedItems, Drafts and Outbox
     folders; an item class other than `IPM.Note`; a file above the 64 MiB download cap.
   Mail comes from top-level folders only (whether `folders?name=`, which `restore_sample` uses,
   finds nested folders is unrecorded). `select` checks the pool again and refuses all of it
   (`std::logic_error`, nothing sampled) if a forbidden candidate gets through: on the selectors'
   own fields, so for SharePoint the RestoreTarget library and the test OneDrive (alice's
   OneDrive is a SharePoint site too) by drive ID and by the drive ID the site, web and list
   GUIDs give, and a site on a host other than `test_site_id`'s (a personal site, another
   tenant). What selectors don't carry (a mailbox's kind, a library's url, an item class, a
   size) only the lister can check.
7. **Same names and duplicates are skipped, deterministically.** Candidates are sorted by key and
   deduplicated. Canary names and subjects are unique (the loader checks) and never in the pool. A
   random pick whose subject or name is already taken for its type, the case of any letter aside
   (case-insensitive, Unicode, invariant upper case: `src/name_key.hpp`, which `restore_sample`'s
   same-name refusal uses too; SharePoint and OneDrive fold more than A-Z), is skipped and the
   next draw is used; the skipped draw still counts, so the sequence stays fixed.
   So `restore_sample`'s refusals (two SharePoint or two OneDrive files of one name, one item
   twice) can't fire, and no two mails of one subject are restored (the read-back couldn't tell
   them apart).
8. **The SharePoint drive ID is derived, not read.** A random SharePoint item's `drive_id` is
   "b!" plus the base64url, without padding, of the site, web and list GUIDs' little-endian bytes.
   This reproduces the canary library's, the RestoreTarget library's (`test_library_id`) and
   alice's OneDrive's drive IDs from `lab/tenant.md`, so guard layer 1 needs no change and still
   refuses the target. The Worker app can't read a source through Graph.
9. **Office files may be picked.** A canary's `size` is its `stored_size` for `bytes` files and −1
   for `office-v1` files (SharePoint rewrites docx and xlsx, so their stored size is evidence only;
   W3.2 compares their content with office-v1). A random item's `size` is −1; Veeam's `sizeBytes`
   stays in the pool for W3.
10. **A small pool is a shortfall, recorded, not filled.** With fewer eligible candidates than
    floor(N/2), all of them are taken and the result says how many were wanted and taken, and
    whether fewer than 2 containers gave any. W3.3 decides what a shortfall does to the status;
    the proposal is that it never turns `pass` into `fail`, and the report says how many real
    items were tested. The lab has almost no real data today, so its random half is mostly empty
    until some is seeded (open point).
11. **Explore sessions.** `list_candidates` opens one explore session per type and stops each one
    before it returns; one it can't stop is `connector::Error`, since `restore_sample`'s preflight
    would then refuse. The session bookkeeping moves out of `restore_sample` into
    `src/veeam_explore.*`, with no change in behaviour. Veeam lists explore sessions in
    `/v8/RestoreSessions` with the restore's type (restore-flow §12), so a lister's session,
    stopped seconds before the restore POST, would pass `restore_sample`'s duplicate check (ours,
    that type, new since the POST less 5 s) and leave the run without a verdict. The connector
    remembers every explore session `list_candidates` opened or adopted, also when it throws, and
    they join the duplicate check's known set. A Stop that fails as transient (timeout, dropped
    connection, a 5xx Veeam calls transient) is followed by a re-read and, if the session is still
    `Working`, one more Stop, at most 2 per session; auth errors and 4xx aren't retried (2026-09-30:
    the live dry run's Stop of explore session e251a437 timed out after 30 s with the session still
    `Working`, and a second Stop minutes later returned 204 at once).

**Reason.** Canaries rotate so each one is tested within the bound the task sets; a seeded offset
couldn't promise that. The random half must be real data outside the targets and the canary
locations (2026-09-25), and a restore target is in every backup (W2.4). Listing a whole tenant is
too slow, while a two-level draw costs a few dozen calls. Portable draws let an auditor repeat a
selection on any platform. Deriving the drive ID avoids a Graph read the Worker app isn't granted
and a change to the strict guard.

**Alternatives rejected.** *`std::uniform_int_distribution` or `std::shuffle`:* their output
depends on the standard library. *Random or date-based rotation:* no coverage bound. *A cursor
file on the Worker:* one Worker serves many clients (2026-09-29, "Clients live in the Cloud"), and
a lost file would silently restart the rotation. *Deriving the rotation from a run counter:* it is
the same state under another name. *Listing every container:* too costly. *Veeam's search:* not
uniform, and veeam-notes §5.4 keeps it for later. *Filling a shortfall with canaries:* the report
would overstate the real-data share. *Relaxing guard layer 1 to accept an empty `drive_id`:* it
weakens a strict check. *A Graph read of each source:* the Worker app reads the targets only.

**Open.** Where the run ID and cursor come from before the Cloud (proposed: `--run-id` and
`--canary-cursor` on S2's `rpworker restore`); real data in the lab for the random half (a new L
task: a few non-canary mails in alice's and bob's mailboxes, files in another library of the
RestoreTest site and in bob's OneDrive, then a backup); what a random item is verified against
(W3.1: the glossary says a live Graph read, which the grants rule out, so the proposal is Veeam's
own listing: presence, name or subject, received time, size for non-Office files); whether group
mailboxes such as `allcompany` are sampled (proposed: yes).

---

## 2026-09-30 — W2.5 second review: restore point, errors, infrastructure, paging

Amends points 2, 4, 6, 8, 9 and 10 of the W2.5 entry below and point 5 of its first review,
after the second review of the W2.5 branch (14 findings on PR #139). Proposed with them: the
owner confirms in the W2.5 review, or supersedes.

**Decision.**

1. **The restore point is checked.** After the organisation, `restore_sample` lists its restore
   points (`list_restore_points`); the spec's `restore_point.id` must be one of them and its
   `backup_time` equal byte for byte, else `connector::Error` before any explore session.
   Veeam explores the newest data at or before an explore's `dateTime` (veeam-notes §4.2), so
   a stale or another client's time would restore other data than the result names.
2. **`connector::NotFoundError` means one thing in `restore_sample`:** a sampled item (or its
   source mailbox, folder, site, library or OneDrive) isn't in the restore point, the case
   W3.3 may call `fail`. Everything else that is "not found" is `connector::Error`: a client
   Veeam doesn't know, the test OneDrive missing from the point, a restore target Graph can't
   find (the guard's `graph::NotFoundError`), and Veeam's own 404 `ResourceNotFound` mid-run
   (an expired session). `list_restore_points` keeps its W1.7 mapping.
3. **Mailboxes are the primary ones.** An entry with `isArchive` true (a user's in-place
   archive, listed with the same email) is never a sample's source mailbox.
4. **What reads as infrastructure (amends point 9 and review point 6).** The marker list grows
   from W1.0's four texts to the usual words of a failed service call ("Failed to access
   mailbox", connect / connection, access denied, unauthorized, forbidden, (401), (403), (429),
   too many requests, throttl-, (503), service unavailable, server busy, timed out, timeout,
   proxy, could not be resolved, certificate, token): broad on purpose, since a doubt must be
   `error`, never `fail`. They are matched in Veeam's own words only (`veeam_words`): every
   item name, the run's tenant texts (the source containers' names and addresses, folder
   names, the targets' names and URLs), Veeam's `source: …;` and `target: …)` fields, quoted
   parts and every word holding `@`, `/` or `\` are cut out first. And a session that
   restored nothing and whose events name no item (Veeam never reached them) is infrastructure
   whatever its words: nothing is known about the backup.
5. **An unpinned restore keeps the explore sessions open (amends point 8).** When the POST was
   accepted but the duplicate check didn't list its session alone (or failed), our session is
   still polled and read, but the explore sessions stay open and are named in the error: the
   other candidate may be running under them. In the no-answer branch a failed duplicate check
   is `connector::Error` (no verdict), never the lookup's own `TransientError` or
   `NotFoundError`.
6. **An orphaned explore session is adopted only when it is certainly ours (amends review
   point 5).** After a failed explore POST, the duplicate check's filter also requires the
   session `Working` and of this organisation (`organization`), and exactly one must match; with
   several, none is stopped and the sweep script is named. The duplicate check after a restore
   POST also filters by organisation (an entry without the field is kept, so it can only add a
   candidate).
7. **Smaller ones.** Events are read through `VeeamClient::get_all` (paged, each ID once, a page
   Veeam caps below the limit asked for isn't taken for the last). `open_explore_session`
   returns the ID in lower case, as `post_restore_once` does. One organisation's settings of an
   unexpected shape no longer fail `list_organizations` for all: `Organization::settings_problem`
   says why its app is unset, and `restore_sample` refuses that organisation with it.
   `parse_veeam_time` (`src/veeam_time.*`) is the one reader of Veeam's time form, for
   `VeeamClient` too.
8. **The registry's factory makes the Graph client on the first `restore_sample` (amends point
   10),** through `VeeamM365ConnectorOptions::make_graph`: listing restore points needs neither
   `RP_GRAPH_CERT_*` nor the Graph IDs. Their `CertificateError` / `ConfigError` now pass out
   of `restore_sample`, before any HTTP client and any request, and are tried again next time.

**Reason.** Each closes a case the review found: an explore session stopped under a restore that
may still run, a result attributed to a point it didn't restore from, every mail of a user with
an archive an error, a retryable error while a restore may run, infrastructure failures (and
tenant text) turning into `fail`, a config problem read as a missing item, events cut short, a
case mismatch refusing every restore, one odd organisation breaking `veeam list`, another
process's session stopped, and listing restore points needing a certificate it never uses.

**Alternatives rejected.** An allow-list of item-level failures instead of the marker list
(Veeam's texts for a bad item are not documented; the no-item rule and the markers err towards
`error`); matching the restore point by time alone (two points can share a second); keeping
the explore sessions open only when the check listed another candidate (a failed check can't
rule one out either).

## 2026-09-30 — W2.5 review: what `restore_sample` refuses, closes and wipes

Amends points 1, 3, 5, 6, 7, 8 and 9 of the W2.5 entry below (proposed), after the review of
the W2.5 branch. Proposed with it: the owner confirms both in the W2.5 review, or supersedes
them.

**Decision.**

1. **Point 1, how the credential is exported and which copies are wiped.** The exporter adds a
   *link* to the certificate to a memory store (`CertAddCertificateLinkToStore`), not a copy: a
   copy loses a key that is held only in memory, which the tests' imported PFX is. The source
   store and certificate context outlive the memory store (both are held across the export).
   After `PFXExportCertStoreEx`, the PFX is re-imported in memory (`PFXImportCertStore` with
   `CRYPT_EXPORTABLE | PKCS12_NO_PERSIST_KEY`), and one exported without its key is refused.
   Wiped with `SecureZeroMemory`: the `ExportedPfx` (PFX and password), the body's text (spliced
   into one buffer reserved up front, so growing it frees no partial copy; the JSON body itself
   never holds the credential, and a value that would need JSON escaping is refused), the target
   guard's parsed copy of the two values, and `VeeamClient`'s request body after the send. **Not
   wiped, out of reach:** the copy `HttpClient` hands to cpr (`cpr::Body`, freed with the
   session), libcurl's and Schannel's send buffers, and the JSON parser's token buffer while the
   guard reads the text. They live only in the Worker's memory, never in a log, a file or a
   message; anyone who can read that memory can export the same key from `LocalMachine\My`
   anyway (the exporter needs it exportable). "Buffers are wiped once the body is sent" means the
   list above.
2. **Point 3, two files of one name are refused.** `restoreTo` and `copyTo` drop the source
   path, so two SharePoint files, or two OneDrive files, of one name (case-insensitive, Unicode,
   invariant upper case, as the W2.6 review made it; from two folders or two sources) land on one
   target file, the second a new version of the first,
   and the read-back would fail the first although its backup was fine. `restore_sample` refuses
   such a spec with `connector::Error` before any Veeam request; the sampler (W2.6) must not pick
   them. Two selectors that resolve to one backup item (same container and ID) are refused after
   browsing, before any restore POST (they would restore it twice, in two calls). Point 5's split
   of same-named items stays for mail.
3. **Point 6, a POST that never went out.** A connection or TLS handshake failure on the restore
   POST is `RestorePostOutcome::not_sent`: nothing went out, so `connector::TransientError`, no
   duplicate check, and the explore sessions are closed. Only a dropped connection, a timeout, a
   5xx or a 2xx without `sessionId` are "no answer". A refused POST with `errorCode`
   `ResourceAccessDenied` is `connector::AuthError` whatever its status (restore-flow §15). An
   accepted `sessionId` is kept in lower case, as the duplicate check lists it.
4. **Point 7, statistics and events after the stop.** Any failure reading them other than a 409
   (or a lost sign-in, `AuthError`) is `connector::Error` "... stopped, but its statistics / events
   couldn't be read ...; no verdict": never `NotFoundError` (a missing item) or `TransientError`
   (try again), since the restore ran.
5. **Point 8, an explore POST that failed.** One that fails once it may have gone out (a
   timeout, a dropped connection, a 5xx, a 2xx without an `id`; not a refused sign-in) may still
   have opened a session (veeam-notes §4.4). The duplicate check's query and filter run from the
   POST's time; every new `Working` session of ours of that type is recorded and closed with the
   others, so the next run's preflight isn't blocked. A failed lookup is logged with the sweep
   script.
6. **Point 9, what reads as infrastructure.** Only Veeam's own words: session-level events,
   statistics errors, and failing item events with the item's name cut out. A sampled mail's
   subject or a file's name is the tenant's text ("AADSTS50076 sign-in error" is a plausible
   subject) and never turns a `failed` into an error; a restored item is never flagged.
7. `parse_veeam_time` accepts years 1678-2261 only, what a time in nanoseconds holds.

**Reason.** Each closes a case the review found: a leaked explore session blocking every later
run, a restore sent twice or onto one file, user data flipping `failed` to an error, a
post-restore failure read as a missing item, and a decision that claimed more wiping than the
code did.

**Alternatives rejected.** Restoring same-named files in separate runs with cleanup between
(W3.4's cleanup doesn't exist yet; the sampler avoiding them is simpler); wiping cpr's copy by
passing the body to curl without one (cpr has no non-owning body, and libcurl and Schannel keep
their own buffers anyway); leaving an orphaned explore session to the sweep (the Worker runs
unattended).

## 2026-09-30 — W2.5: how `restore_sample` restores (proposed; recorded before the build)

Recorded before any of it was built, as #30 asks for the credential export. Proposed: the owner
confirms it in the W2.5 review, or supersedes it.

**Decision.**

1. **The restore credential is exported in memory through CryptoAPI** (the 2026-09-28 W2.4
   entry: Veeam's own organisation app; the 2026-09-29 "The Worker runs on the Veeam server"
   entry). A neutral interface, `rp::CertificateExporter` (`rp/cert_export.hpp`: export by
   SHA-1 thumbprint, returning a Base64 PFX and its one-time password), keeps `rpcore`'s restore
   logic testable without a certificate store. The Windows one, `LocalMachineCertExporter`:
   `CertOpenStore` on `LocalMachine\My` (read-only), `CertFindCertificateInStore` by
   `CERT_FIND_SHA1_HASH` with the thumbprint Veeam reports in `GET /v8/Organizations`; refuses a
   certificate that has expired or has no private key (`CryptAcquireCertificatePrivateKey`,
   silent, no UI); copies it into a memory store and exports it with `PFXExportCertStoreEx`
   (`EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | REPORT_NO_PRIVATE_KEY`)
   under a password of 32 random bytes from `BCryptGenRandom`, in Base64. No file is written at
   any point (the PowerShell script's `%TEMP%` file goes away). Buffers are wiped with
   `SecureZeroMemory` once the body is sent. It needs what the script needed: an elevated
   process (or LocalSystem) and an exportable key; W4.12 (#135) decides the service account. A
   failure is `connector::Error` ("the Veeam organisation app's certificate ...: run elevated
   ..."), before any restore POST.
2. **The organisation app is cross-checked first.** `rp::Organization` also parses
   `exchangeOnlineSettings` and `sharePointOnlineSettings` (`applicationId`,
   `applicationCertificateThumbprint`); both must be present and equal, or `connector::Error`
   before any explore session. The body's `applicationId` and the exported thumbprint are that
   pair; `officeRegion` is the organisation's `region`, `organizationName` /
   `officeOrganizationName` its `officeName`.
3. **Selectors gain what the manifest already has**, so no source needs a Graph read the Worker
   app isn't granted (it reads the targets only): `MailSelector::received_at` (optional; when
   set, Veeam's `received` truncated to the second must equal it), `SharePointSelector::list_id`
   (required: Veeam's library ID is the site's two GUIDs, from `site_id`, followed by it; never a
   name, which is localised) and `size` (optional, the manifest's `stored_size`, checked on the
   re-read), `OneDriveSelector::size` (the same). The source OneDrive is Veeam's `OneDrives`
   entry whose `url` is `https://<tenant>-my.sharepoint.com/personal/<user, lower case, '@' and
   '.' as '_'>` (ASCII case-insensitive, exactly one), `<tenant>` from `test_site_id`'s host; a
   folder path is walked segment by segment through `Folders?parentId=` (`root` first).
   SharePoint folder paths other than `/` are walked the same way from the library.
4. **Browsing as 10-restore.ps1 does**, one explore session per type (`dateTime` the restore
   point's `backup_time` byte for byte), every list with `limit=1000` and paged; exactly one
   match per item, re-read by ID; the re-read document goes into the body minus `_links` and
   `_actions`. Zero or several matches, or a container not found, is `connector::NotFoundError`
   or `connector::Error` (`error`): the zero-match `fail` for a canary is W3.3's to settle, so
   W2.5 doesn't guess it.
5. **One restore call per source container; same-named items in one container go into separate
   calls** (events name items only by `itemName`). The explore session is reused for the next
   container of the same type (untried, restore-flow §18; the first live run shows it).
6. **The POST goes out at most once.** A preflight first (`GET /v8/RestoreSessions?limit=200`: no
   session of ours `Working`, else `connector::Error` before any explore). The POST is sent with
   one attempt, no retry of any kind, a 60 s timeout, and the exact text layer 2 checked. A 4xx:
   nothing started, `connector::Error` (401/403 `connector::AuthError`). No session ID (a
   transport error, a timeout, a 5xx, a 2xx without `sessionId`): the duplicate check of
   restore-flow §8, up to 3 more looks 10 s apart; exactly one candidate is adopted, else
   `connector::Error`, never a resend. With a session ID, the check must list exactly it, or the
   session is still polled but the call ends in `connector::Error` (no verdict).
7. **Waiting and reading** as restore-flow §9-§12: poll every 5 s; `Stopped` ends it; a 404 or 6
   failed polls in a row is `connector::Error`; still `Working` after 20 minutes is
   `connector::TransientError`. Statistics (409 retried, 6 attempts 5 s apart) and events are
   required, of the expected JSON kinds, else `connector::Error`. Start and end times are the
   session's `creationTime` and `endTime` as Veeam wrote them.
8. **Sessions are closed in a finally path, except under a restore that may still run.** Every
   explore session the call opened is read and, while `Working`, stopped (`POST .../Stop`, best
   effort). After a timeout, a 404 or failing polls, or a POST whose session couldn't be pinned
   down, the explore sessions are left open and named in the error (the 2026-09-29 W2.4 review:
   what Stop does under a running restore is untested). This narrows #30's "close sessions in a
   finally path even on error" by that one case.
9. **Status and per-item results.** `RestoreResult` gains `items_sent`, one
   `RestoreSessionResult` per restore session (ID, kind, Veeam's `result` and `details`, start
   and end, items sent and restored) and one `ItemRestoreResult` per item (kind, name,
   `restored` / `failed` / `unknown`, Veeam's message, and whether that message reads as
   infrastructure). The status is the W1.7 order with restore-flow §12's stricter `succeeded`
   (every session `Success`, its `restoredItemsCount` equal to the items sent, a
   `Restore`/`Success` event per item name, and for files a `Statistics.items[]` `Success` entry
   per ID). A session that restored nothing and whose events or errors read as infrastructure
   ("Cannot connect to Microsoft 365", "Failed to open mailbox", "missing the required
   application permissions", `AADSTS`) is `connector::Error`, never `failed`. `log` is the
   events' `status itemName: message` lines per session, through `rp::redact`. Veeam's own log
   file on disk is not read (the evidence bundle decides that, W3.x).
10. **The registry's factory makes the Graph client**, from `RP_GRAPH_CERT_PFX_BASE64` and
    `RP_GRAPH_CERT_PASSWORD` through `graph::certificate_from_secrets` (`ConfigError` if unset),
    with `Config::graph_tenant_id` and `graph_client_id`, on `graph::make_graph_http_client`
    (or `ConnectorOptions::make_graph_http`). Every logger it hands out (Veeam, Graph, the
    guard) is `ConnectorOptions::logger` or else the command logger (stderr), never spdlog's
    default. `ConnectorOptions` gains `now`, `wall_now`, `make_graph_http` and `cert_exporter`.
    `rp::redact` also masks `applicationCertificate` and `applicationCertificatePassword`.

**Reason.** It is 10-restore.ps1's proven flow (W2.4, mail r1) in C++, with the W2.4, W2.4
review and W2.7 decisions as they stand. The in-memory export removes the script's one file on
disk. Selectors carrying the manifest's IDs keep the Worker app's grants as they are.

**Alternatives rejected.** Exporting through a temporary file as the script does (a PFX on
disk, however briefly); `NCryptExportKey` of the key alone (Veeam wants a PFX); a vault copy of
the PFX (W4.12 decides; the 2026-09-28 entry keeps "never stored"); Graph reads of the source
site, drive or user (not granted); decoding Graph's `b!` drive IDs into GUIDs (works in the lab,
undocumented); resending a POST with no answer (could restore twice); stopping an explore
session under a running restore (untested).

**Live run.** #30's Done-when, 2026-09-30 07:35:12Z–07:37:39Z, run with the owner's go-ahead
from an elevated shell: `rptests.exe "[live][writes]"` (`veeam_m365_restore_live_test.cpp`,
`RP_LIVE=1`, `RP_LIVE_RESTORE=1`) restored RP-CANARY-0001 to 0005 (alice's Inbox) into
restoretest's Inbox, rp-canary-01.pdf, 04.txt and 06.pdf into the RestoreTarget library and
rp-canary-11.pdf and 14.txt into alice's `/RestoreTarget`, from the newest restore point
(`backupTime` 2026-09-29T22:00:45.6603083Z), into targets `rpworker graph list` had shown empty.
Status `succeeded`, 10 of 10, in three restore sessions, all `Success` (mail `6cd07acf-…`, 5 of
5; SharePoint `2ab2e15d-…`, 3 of 3; OneDrive `0819da9f-…`, 2 of 2). Point 1's in-memory export
(Windows' default PFX encryption) was accepted for all three types; point 5's one call per type
in a run of three types, point 6's duplicate-check query and point 9's per-item events matched
by `itemName` worked live. `rpworker graph list --hash` then found exactly the 10 items, all 10
SHA-256 values equal to `lab/seed-manifest.json`'s, and `08-sweep-sessions.ps1 -WhatIf` found
none of the 96 sessions `Working` (point 8's finally path stopped the three explore sessions).
Point 5's reuse of an explore session for a second container is still untried (one container
per type). The 10 copies stay in the targets until the owner removes them by hand (W3.4).
Details in restore-flow §19; evidence `docs/api/veeam-lab/w2.5-live-*`.

## 2026-09-30 — W2.7 review: the guard resolves the mailbox and the OneDrive's address, and runs first in `restore_sample`

Supersedes parts of the 2026-09-29 W2.7 entry below (points 1, 2 and 3, and its opening
paragraph), after the max-effort review of PR #138.

**Decision.**

1. **The mail target is resolved through Graph too.** Layer 1 reads
   `GET /users/{test_mailbox}/mailFolders/inbox?$select=id` once when the spec has mail items
   (`rp::graph::check_restore_mailbox`, `ResolvedMailbox`, `CheckedTargets::mailbox()` now an
   optional that is set only then). The Worker app reads mail only through Exchange RBAC
   `Application Mail.Read` in a management scope of the restoretest mailbox's primary address
   (`docs/security/graph-permissions.md`, #3), so a 200 shows the configured
   `restoretest@<domain>` reaches that mailbox and not a live mailbox holding the name as an
   alias (or a group). Exchange's 403 is a refusal (`SafetyViolation`: another mailbox, or the
   scope is missing); a 404 stays Graph's `NotFoundError`. No new permission. Layer 2 now
   requires the mailbox resolved for a mail request (`bad context: the test mailbox was not
   checked`), and a `restoretest` address there.
2. **Layer 2 ties `onedrive.url` and `onedrive.id` to the RestoreTarget folder's OneDrive.**
   The folder GET now selects `sharepointIds` (`$select=id,name,folder,parentReference,
   sharepointIds`, read through the existing folder grant): its `siteUrl` is exactly the URL
   Veeam's copyTo names (recorded live 2026-09-29), and its `siteId` and `webId` run together
   are Veeam's OneDrive ID. `onedrive.url` must equal that `siteUrl` and `onedrive.id` those two
   GUIDs (ASCII case-insensitive), besides equalling W2.5's context; before, a URL on the
   tenant's `-my` host that the context agreed with passed, so another user's OneDrive could
   too. `ResolvedOneDriveFolder` gains `web_id` and `site_url`; the shared check (also
   `TargetReader`'s) requires `sharepointIds` with the folder's `siteId`, a GUID `webId` and a
   string `siteUrl`.
3. **`restore_sample` runs layer 1 first.** `VeeamM365Connector` takes an optional Graph
   client and `TargetGuardOptions`; `restore_sample` refuses without a Graph client
   (`connector::Error`, no request), runs `TargetGuard::check_spec` before any Veeam request,
   maps Graph's errors to connector ones (`AuthError` and `PermissionError` to `AuthError`,
   `TransientError`, `NotFoundError`, the rest `connector::Error`), and only then throws
   `NotImplementedError` until W2.5. `veeam_m365_restore_guard_test.cpp` pins that a refusal
   and a passing guard both leave Veeam without a request. The registry's factory makes no
   Graph client yet; W2.5 adds it. Layer 2 stays W2.5's to call before each POST (the TODO in
   `restore_sample`).

**Reason.** A configured value proves nothing by itself, the mailbox included (the W2.4
review's rule, which the first W2.7 cut applied to the file targets only), and W2.5's context is
built by the same code the guard is meant to check, so agreeing with it proves nothing either.
#32's Done-when is "the guard is the first line of every restore call".

**Alternatives rejected.** `GET /users/{mailbox}?$select=id,mail` (needs `User.Read.All`, which
the app deliberately lacks); the OneDrive drive's `webUrl` (a drive-level read the folder grant
may not cover, and it ends in `/Documents`); keeping #32 open until W2.5 (the wiring and its test
cost little now, and W2.5 then can't skip the guard without breaking a test).

## 2026-09-29 — W2.7: the restore-target guard in two layers; `SafetyViolation`, exit code 4

**Decision.** `TargetGuard` exists as two standalone units with the API W2.5 will call;
`VeeamM365Connector::restore_sample` still throws `NotImplementedError` and carries a TODO
naming the calls. It builds what the 2026-09-29 W2.4 review entry decided: the guard trusts no
configured ID, runs per item inside `restore_sample` before any Veeam call, and checks the
exact body again before the POST.

1. **Layer 1, `rp::TargetGuard::check_spec(const RestoreSpec&)`** (`rp/target_guard.hpp`), before
   any call to the backup product. First every item, in the spec's order, with no call: a mail
   item may not come from a `restoretest` mailbox (`is_restore_mailbox`, any case, the test
   mailbox included), a SharePoint item not from `test_library_id` (ASCII case-insensitive), a
   OneDrive item not from a path whose first folder is `RestoreTarget` (any case; empty and `.`
   segments skipped, a `..` segment refused); an item naming no source is refused too. Then,
   once per type the spec uses, the targets through Graph (GETs only; mail needs none): the
   library and the OneDrive folder must be the dedicated `RestoreTarget`s. The canary
   locations are kept out by those exact names (the canary library and folder are both
   `RestoreTest`) and the `webUrl` rule; no list ID is compared with the canary library's, since
   the config carries no canary ID (restore-flow §16's "the library's list ID isn't the canary
   library's", and the W2.4 review's "not a canary location", are met this way). An empty spec
   calls nothing. It returns `CheckedTargets`, which only `TargetGuard` can make.
2. **The Graph checks are one unit, shared with W2.2's reader** (`rp/target_guard_graph.hpp`:
   `check_restore_library`, `check_restore_onedrive_folder`, `ResolvedLibrary`,
   `ResolvedOneDriveFolder`). `TargetReader` calls them; its messages and `WrongTargetError`
   are unchanged (the ending comes from `TargetCheckWording`). Two checks are new, for both
   callers: `sharePointIds.listId` must be a GUID and `.siteUrl` a string, and the folder's
   `parentReference.siteId` a GUID, since layer 2 compares the body with them. The names stay
   exact (`Dokumenty`, `Documents`, `RestoreTest`, `restoretarget` and look-alikes with U+00AD
   or U+200B are all refused by the name rule); the forbidden-name list is only layer 2's extra
   check.
3. **Layer 2, `rp::veeam::check_restore_request(const CheckedTargets&, const
   RestoreRequestContext&, path, body)`** (`rp/target_guard_veeam.hpp`), immediately before the
   restore POST, on the exact path and text. It ports `Assert-RestoreTarget` of `10-restore.ps1`:
   the path is exactly the kind's restore-to-another-location call with an explore session this
   run opened and no query, fragment, `%`, `\`, `//` or dot segment; the body is valid UTF-8
   JSON, an object, every key at any depth printable ASCII, with no key twice in any object and
   no two keys of one object that differ only in ASCII case (a parser callback; nlohmann would
   keep the last, and Veeam's .NET binder may match names ignoring case, so an `Id` beside the
   checked `id` of a document could be what it restores), and exactly the kind's key set;
   documents may carry Veeam's other browse fields; values are checked by JSON kind; every value
   compared with a target or fixed name must be printable ASCII; comparisons are ordinal
   (`std::string` `==`) except the OneDrive host and first GUID and the RestoreTarget-library
   prefix of SharePoint document IDs (ignoring case there only refuses more); the item set is exactly the context's, none
   missing, added or twice. It takes `CheckedTargets`, so it can't run without layer 1. Not
   ported (restore-flow §6, "Lab-only rules"): `onedrive.id` equal to the source OneDrive, and
   the canary list-ID prefix on SharePoint document IDs. Added: a SharePoint document whose ID
   starts with the RestoreTarget library's site, web and list GUIDs is refused (a restore target
   is never a source; the targets are in every restore point), and `onedrive.url` must be on
   `https://<tenant>-my.sharepoint.com/` for `test_site_id`'s tenant.
4. **The error is `rp::connector::SafetyViolation`** (a `connector::Error`, `rp/connector.hpp`):
   status `error`, never `fail`; rpworker's exit code 4 (`exit_code::service`, documented in
   `rp/cli.hpp`; no command restores yet, so nothing maps it in code). Its message starts with
   `target guard: `, ends with `nothing was restored` (layer 1) or `the restore was not sent`
   (layer 2), names the field or the item by type and index, and never quotes a credential:
   the two credential fields are checked for kind only, and nlohmann's parse message, which
   quotes the text, is never passed on. A layer-1 refusal from Graph is the `WrongTargetError`'s
   text with the prefix. Graph's other errors pass through with their own types. Each refusal
   logs exactly one line, `SECURITY: <message>`, at critical level through `rp::redact`, on the
   options' logger or spdlog's default one.
5. **Fixtures.** W2.4's five restore POSTs are `worker/tests/fixtures/veeam/restore-{mail,sp,od,
   mail-x5,mail-r1}-200.json` (restore-flow §17 names, plus r1), with `request_body` holding the
   body as sent. The tests run restore-flow §6's 12 mutations on each type and accept all five
   recorded requests unchanged.

**Reason.** The guard is what keeps a restore out of live data when a configured ID, a Cloud
job or a bug names the wrong place; W2.5 must only have to call it. Splitting it by what each
layer knows (the spec before any call; the exact request after browsing) keeps layer 1 free of
Veeam, as `connector.hpp` is.

**Deviations from the W2.7 design notes.**
- *The path's container is not required to be the target site* (the design had SharePoint's
  `container_id` equal to the RestoreTarget library's site). The path names the **source**
  site; W2.6 samples real data from other sites too, which that rule would refuse on every run.
  The target is fixed by `siteURL` and `list`, which are checked; the "never from the target
  library" rule covers the lab's shared site.
- *A mail source is refused if it is any `restoretest` mailbox*, not only the configured one.
- *Item IDs and names, and `onedrive.name`, may be any UTF-8*: they are compared byte for byte
  with the context and name no target; a real file name with an accent would otherwise be a
  guard violation.

**Alternatives rejected.**
- *One guard class that also parses Veeam bodies:* it would put Veeam in the neutral layer.
- *Parsing the body into a DOM and checking keys afterwards:* the DOM has already dropped the
  duplicate.
- *Quoting the refused value in the message:* useful, but a value next to a credential field
  could leak through a mistake; the field name is enough to find it in the evidence.

---

## 2026-09-29 — The Worker runs on the Veeam server (proposed)

**Status: proposed.** The owner accepted the recommendation; spike #135 (W4.12) confirms or
supersedes it before W4.5.

**Decision.** In Stage 1 the Worker is installed on the Veeam Backup for Microsoft 365 server,
next to its REST API. The restore credential is Veeam's own organisation app (as in W2.4
decision 1): for each run the Worker reads the app ID and certificate thumbprint from
`GET /v8/Organizations`, finds that certificate in `Cert:\LocalMachine\My`, checks the app ID,
and exports it in memory only. No copy of the PFX is stored, in the vault or anywhere else.
This picks the second option of the W2.4 entry's open point ("a run-time export by the
thumbprint Veeam reports, when the Worker runs on the Veeam server"). The 2026-09-26 rule
stands: it is tested (#135) before the Worker relies on it. That spike also picks the service
account: LocalSystem, or a virtual account with read access to the certificate's private key.

Follow-ups, as comments on the issues: W4.5 (#48) holds no restore PFX; W7.1 (#80) installs on
the Veeam server; W7.2 (#81) checks the REST API is local and each organisation's certificate
exists, is exportable and isn't within 30 days of expiry; Q7.2 (#85) and Q7.3 (#86) state the
requirement and that the Worker has Veeam admin rights over every organisation on that server.

**Reason.**

- Veeam's certificate never leaves the server it already lives on, and no file outlives a run.
- Nothing to rotate on our side: when Veeam renews its app certificate, the next run finds the
  new thumbprint.
- It is the path W1.0, L1.4 and W2.4 already proved in the lab.

**Cost.** Stage 1 can't serve customers whose Veeam REST API runs on a separate machine, who
won't install software on their backup server, or who use Veeam Data Cloud (Veeam's SaaS, no
self-hosted REST API). Sales material says so.

**Alternatives rejected.**

- *A vault copy of Veeam's organisation PFX:* a long-lived copy of a broad credential, and it
  must be renewed by hand when Veeam renews the certificate. Kept as the fallback if #135
  fails, or for a Worker on another machine (Stage 2).
- *A dedicated, narrower restore app:* Veeam's SharePoint restore needed
  `Group.ReadWrite.All` on the app (L1.4), so it may not be narrower, and it adds consent and
  roles in every client tenant.

---

## 2026-09-29 — Clients live in the Cloud; the Worker checks every job (proposed)

**Status: proposed.** The owner accepted the recommendation; tasks W4.10 (#133), W4.11 (#134)
and C5.13 (#136) build it.

**Decision.**

1. **A client is one Microsoft 365 tenant, which is one Veeam organisation.** A Worker serves
   one Veeam server and runs jobs for any number of clients on it, one at a time. In-house IT
   is the one-client case, not a separate mode.
2. **The Cloud is where clients' details live.** `connector.config_json` (C5.2) holds a
   `client-profile.v1`: `veeam_org_name`, `graph_tenant_id`, `graph_client_id`,
   `test_mailbox` and the four target IDs, with today's key names. IDs only: no names, URLs
   or secrets (W2.4 decision 3 stands). Each job (`job.v1`, C5.6) carries it.
3. **`RestoreTargets::from_profile` is the only factory;** `from_config` wraps it.
   `config.json`'s client keys become an optional local profile, all or nothing, read only by
   the CLI diagnostics. The service loop (W4.8) never reads it.
4. **Before any restore call, the Worker checks the job** (W4.11): the job and profile are
   valid (`job_invalid`), the connector is registered (`connector_unknown`), and the Veeam
   organisation named by `veeam_org_name` has `type == Office365`,
   `msid == graph_tenant_id` and `region == Worldwide` (`client_mismatch`). The Graph token is
   requested for the job's tenant, `TargetReader`'s checks pass, and only then does
   `TargetGuard` run per item. Every failure is `error`, never `fail`.
5. **The Cloud refuses mix-ups** (C5.13): a tenant is unique per MSP, a connector is unique
   per (worker, client), a profile must name its client's tenant, every connector change is an
   `audit_log` row, and a bundle for a different client or tenant than dispatched gets 409.
6. **The signed result names the client** (W4.1): tenant, Veeam organisation, target IDs,
   the names and URLs they resolved to at run time, and `scope: "same_tenant"`.
7. **Jobs run one at a time per Veeam server,** because the W2.4 duplicate check matches
   restore sessions by `initiatedBy`, not by organisation.

**Reason.**

- An MSP has many clients, and the job format already carries per-client locations; one
  `config.json` per client on the Worker would drift from the Cloud.
- The Worker doesn't trust the Cloud blindly: Veeam (`msid`) and Microsoft (a token bound to
  the tenant, grants on the test locations only) must agree with the job. A bug or a typo in
  the Cloud ends as `error` with nothing restored, so no approval step is needed on the
  Worker host, which locked-down MSP servers would struggle with.
- The same model serves an MSP with many organisations on one Veeam server, a Veeam server per
  customer, and in-house IT.

**Alternatives rejected.**

- *A client file per client on the Worker:* a second copy that drifts, and it repeats the
  W1.7 entry's reasoning against a `connector` key in `config.json` ("the wrong place once
  jobs carry the type").
- *Trusting a job's targets as sent:* see the 2026-09-29 W2.4 review entry, decision 1.
- *A person approving each client's targets on the Worker:* deferred; the checks above rest on
  facts Veeam and Microsoft report.
- *Finding the Veeam organisation by `msid` instead of by name:* deferred; the name plus the
  `msid` cross-check is enough for Stage 1.

**Deferred to Stage 2.** An organisation inventory in the heartbeat, bulk import of clients,
more than one Worker per Veeam server or more than one server per Worker, restores into
another tenant.

---

## 2026-09-29 — W2.4 review: the target guard trusts no configured ID; the restore script's no-verdict paths

**Decision.** A code review of W2.4 (`/code-review`, max) found fifteen problems plus ten
smaller ones. This entry records what changed. It supersedes the parts of the W2.4 entry below
that it names; the rest stands. `docs/api/veeam-restore-flow.md` and
`docs/api/veeam-m365/10-restore.ps1` carry the details.

1. **`TargetGuard` doesn't trust the configured IDs** (supersedes "`TargetGuard` checks the body
   against both the names derived from the configured IDs and what Veeam returned" in decision
   3). The W2.4 spec had the guard check only that Veeam's body names what the configured IDs
   resolve to. A `test_library_id` naming a live library (this tenant's default `Dokumenty`)
   would have passed and restored into live data. That is the "trusting configuration" the
   2026-09-22 entry rejects, and it ignored the 2026-09-24 rule that `TargetGuard` resolves the
   IDs and checks they are the restore targets. Now there are two checks (restore-flow §16):
   the resolved targets must be the fixed `RestoreTarget` library and folder and
   `restoretest`'s Inbox, as W2.2's `TargetReader` already requires, and not a canary location;
   then Veeam's body must name exactly those.
2. **The guard still runs per item inside `RestoreSample`, before any Veeam call.** The W2.4
   spec had moved the per-item check after browsing. The rule stands as CLAUDE.md and the
   2026-09-22 entry state it. The exact-body check before the POST is a second layer on top.
3. **The duplicate check excludes every session the run already knows** (supersedes "the ID is
   not one of our explore sessions" in the at-most-once paragraph). The Worker sends one POST per
   source container, so several of one type per run. Excluding only explore sessions would let
   a later POST that got no answer adopt an earlier POST's session. With a session ID from the
   POST, the check must list exactly that session; otherwise, or if the check itself fails, the
   returned session is still polled, but the run ends with no verdict.
4. **A restore that may still be running is left alone, and so is its explore session.** On a
   timeout, a 404 or six failed polls, the script used to stop the explore session under the
   running restore, and `08-sweep-sessions.ps1` would then stop the restore session itself. What
   Stop does to either is untested. Now the script leaves both and says to wait until the
   restore session reads `Stopped`. The sweep stops nothing while two of ours of one type are
   `Working`, unless given `-Force`.
5. **File results are matched by ID, not name.** `Statistics.items[].id` is the OneDrive
   document ID, or the list item GUID that ends the SharePoint document ID. Events carry only a
   name, so no two items of one call may share one, and W2.5 splits them into separate calls.
6. **The result-to-status mapping follows W1.7's contract.** 0 restored is `failed` whatever
   `result` says. A session that restored nothing because of infrastructure is an exception
   (`error`), so `failed` → `fail` stays true. Two changes remain proposals for W3.3: a
   `partial` item that failed for infrastructure makes the run `error`, and a canary missing
   from a point dated after it is `fail` (restore-flow §15).
7. **The script.** The guard's self-test counts only the guard's own refusals. Its array case
   never reached the guard (a generic `JsonArray.Add<T>` node can't be serialised, and the
   catch-all counted that as a refusal). A duplicate-key case is added, and the guard reads
   every object, because `JsonNode.Parse` doesn't refuse a duplicate key. Any 2xx from the POST
   counts; a status that is neither 2xx nor 4xx means looking for the session. The POST's
   evidence is written only after its session ID is parsed. A field the verdict reads that is
   missing or of the wrong kind is no verdict (exit 3), not "NOT restored". Arguments bind by
   name only. `-TimeoutMinutes` is 1 to 45, below the token's life. `-WhatIf` is documented as
   what it is: no POST, but a sign-in and an explore session. `initiatedBy` matches ignoring
   case. The source mailbox may not be the target. `-SaveEvidence` refuses to mix with an
   earlier run's files.
8. **The recordings came from an earlier, uncommitted revision of the script.** They stay the
   W2.4 evidence: the calls and bodies are unchanged. The committed revision was replayed
   offline against all four recordings, run live with `-WhatIf`, and made one real restore on
   2026-09-29 (`RP-CANARY-0011`, exit 0, read back by `graph list --hash` with the manifest's
   hash; `w2.4-mail-r1-*.json`). Veeam's log shows no late flush (supersedes the W2.4 open
   point on it): that run also printed 0 bytes, yet the file was complete 47 ms before the
   session's `endTime`. The size in a directory listing lags for a file Veeam holds open, so the
   Worker reads the file itself after `Stopped`.

**Reason.** A guard that only compares the body with the configuration protects against Veeam
changing the body, not against the configuration naming live data, which is the failure the
guard exists for. Every other change turns something that could report a result it didn't
establish, or stop what it didn't know was safe to stop, into "no verdict".

**Alternatives rejected.**

- *A longer forbidden-name list* (`Dokumenty`, `Documenti`, …): can't be complete in every
  language, and a library of any other name is live data too.
- *Stopping the restore session on a timeout:* untested, and it may leave a partial, unrecorded
  set of copies in a target that the nightly backup captures.
- *Treating a failed duplicate check as fatal once a session ID is known:* the session would go
  unmonitored, which is worse than polling it and withholding the verdict.

**Open.** What Stop does to a running restore (restore-flow §18).

---

## 2026-09-28 — W2.4: the Veeam restore flow

**Decision.** W2.4 restored canaries into the three restore targets through the REST API
with [`10-restore.ps1`](api/veeam-m365/10-restore.ps1): one mail, one SharePoint file, one
OneDrive file, then five mails in one call, all from the restore point of
2026-09-27T22:00:48Z. Veeam reported each one restored, and `rpworker graph list --hash`
found all 8 items in the targets with the manifest's SHA-256. The flow, the bodies and the
evidence are in `docs/api/veeam-restore-flow.md`; the exchanges are
`docs/api/veeam-lab/w2.4-*.json`. The owner decided:

1. **The restore credential is Veeam's own organisation app, per run, in the lab.** The script
   exports its certificate (`Cert:\LocalMachine\My`, so an elevated shell) to a temporary PFX
   in `%TEMP%` with a random 32-byte one-time password, reads it into memory and deletes the
   file at once in a `finally`. The PFX is not stored. With `RP_LAB_SECRET_DIR` set, as in the
   documented run, the one-time password (not the PFX) also gets a DPAPI copy in that folder,
   outside the repo, for `audit-evidence.ps1`; the folder is deleted after the audit. Before that it checks the app ID and
   thumbprint against what `GET /v8/Organizations` reports
   (`exchangeOnlineSettings`, `sharePointOnlineSettings`;
   [`w2.4-mail-x1-org`](api/veeam-lab/w2.4-mail-x1-org.json)). The body carries
   `applicationId`, `applicationCertificate` and `applicationCertificatePassword`.
2. **One restore call per source container** (a mailbox, a site, a OneDrive) with every
   sampled item from it. Tested with five mails in one call
   ([`w2.4-mail-x5-restore`](api/veeam-lab/w2.4-mail-x5-restore.json)): statistics `5/5`, one
   `Restore` event per item named by subject, not in the order sent
   ([`w2.4-mail-x5-events`](api/veeam-lab/w2.4-mail-x5-events.json)).
3. **The configured target IDs are mapped to Veeam's names at run time through Graph**, with
   the Worker's read-only app: the site's `webUrl` from `test_site_id`; the library's display
   name from `GET /drives/{test_library_id}` `name`; the OneDrive's URL from the drive's
   `webUrl`; the folder name from `GET /drives/{d}/items/{test_onedrive_folder_id}`; the
   mailbox is `test_mailbox` and the folder is always `Inbox`. The OneDrive object in the body
   is Veeam's, matched by that URL in the explore session. `TargetGuard` checks the body
   against both the names derived from the configured IDs and what Veeam returned. No new
   config keys. W2.5 and W2.7 build this. *(The guard also checks the resolved targets are the
   restore targets, and doesn't trust the configured IDs: see the 2026-09-29 W2.4 review entry.)*

**The restore POST is sent at most once.** It is never resent by the HTTP layer (the open
point of the 2026-09-24 HTTP client entry and of the 2026-09-26 VeeamClient review entry).
After a transport error, a 5xx or a 200 without `sessionId`, the script looks for the session
it may have started: `GET /v8/RestoreSessions?startTimeFrom=<POST time − 60 s>&orderBy=CreationTime&orderAsc=false&limit=50`,
kept only if `initiatedBy` is `rp-veeam`, the type is `Vex`/`Vesp`/`Veod` for the item type,
the ID is not one of our explore sessions and `creationTime` is no earlier than 5 s before
the POST. Exactly one match is adopted. While it finds none, it looks up to three more times,
10 s apart; still none, or several at any look, is "no verdict, not resent" (exit 3). The same check ran after every successful POST and found
exactly one new session, the one returned
([`w2.4-sp-x1-sessions-after-post`](api/veeam-lab/w2.4-sp-x1-sessions-after-post.json)).
`VeeamClient` (W2.5) does the same. *(It excludes every session the run knows, not only the
explore sessions, and a session ID from the POST must be the one the check lists: see the
2026-09-29 W2.4 review entry.)*

**The restore targets are in the backup.** The 2026-09-27T22:00:48Z restore point holds the
RestoreTarget library and alice's `/RestoreTarget` folder
([`w2.4-sp-x1-libraries`](api/veeam-lab/w2.4-sp-x1-libraries.json),
[`w2.4-od-x1-folders-root`](api/veeam-lab/w2.4-od-x1-folders-root.json)). W1.4 recorded them as
absent (`docs/api/veeam-notes.md` §5.2, §5.3) because they were made on 2026-09-25, after the
first two points. A restore not cleaned up before the nightly backup would put its copies in
the next point. So sampling (W2.6) takes items only from the canary sources (the RestoreTest
library by list ID, `/RestoreTest` by folder, the source mailboxes' Inbox) and the real data,
never from a target. The script prints a note when it sees a target in the point; it doesn't
refuse.

**Veeam's result maps to a restore status** as proposed in `docs/api/veeam-restore-flow.md`,
for W2.5's `RestoreStatus` and W3.3's table in `docs/verification.md`. "Veeam says restored"
(stopped, `Success`, every item reported) is `succeeded`; Graph read-back then decides `pass`
or `fail` per item. Anything infrastructure (auth, certificate, app permissions, a session
not found, statistics or events unreadable, still running after 20 minutes, a guard refusal)
is `error`; when unsure, `error`.

**Reason.**

- **Credential.** Veeam's app already holds the certificate Veeam trusts for this
  organisation and is the one W1.0 and L1.4 restored with. A dedicated app would need its own
  consent and roles, and a narrow one may not be possible: Veeam's SharePoint restore
  demanded `Group.ReadWrite.All` on the app (L1.4, `docs/manual-restore-reference.md`).
  Exporting per run keeps the PFX out of any file that outlives the run.
- **One call per container.** Fewer sessions to wait for, and the per-item result is still
  there: SharePoint and OneDrive statistics list items by name, mail events name each item.
- **Graph for the names.** The IDs are stable and the Worker already reads them; a display
  name or URL in config would be a second copy that can drift, and a renamed target would be
  found by the guard, not missed.
- **At most once.** A resent restore can write a second copy, which the checker would count
  and the Cleaner would have to find. A missing verdict costs one run; a duplicate costs trust
  in every later one.

**Alternatives rejected.**

- *The Worker's own app in the body:* read-only (L1.5), and Veeam writes the items.
- *A PFX of Veeam's app copied to disk for the lab:* one more copy of a broad credential.
- *One call per item:* N sessions of 30 to 50 s each (one item each here) for the same result.
- *New config keys for the site URL, library name and OneDrive URL:* see above.
- *Resending after a timeout when no session is found:* the session list may lag; "no verdict"
  is safe, a second restore is not.

**Open.**

- **The Worker's long-term restore credential** stays open for a spike before W4.5: a vault
  copy of Veeam's app PFX; a run-time export by the thumbprint Veeam reports, when the Worker
  runs on the Veeam server; or a dedicated, narrower app. The 2026-09-26 rule stands: it is to
  be tested before the Worker stores any certificate.
- **Veeam's per-restore log** (`C:\ProgramData\Veeam\Backup365\Logs\RestoreREST\restore_<local time>_<session ID without dashes>_<org ID without dashes>.log`)
  was 0 bytes when listed right after the sp, od and mail x5 sessions stopped (the mail x1 run
  printed no log line); 18–22 KB when listed later, and last written before each session's
  `endTime`. When Veeam flushes it is not established; its contents weren't read. Not committed.
  *(Superseded: those readings came from an earlier revision of the script, and each log was
  complete before its session ended; see the 2026-09-29 W2.4 review entry.)*
- **Cleanup** is the owner's, by hand, until the Cleaner (W3.4). The owner removed the eight
  restored items; `rpworker graph list` then found 0 items in each target (about 21:38Z).
- **The OneDrive drive read.** Decision 3 reads `GET /drives/{test_onedrive_drive_id}` for the
  OneDrive's `webUrl`. The Worker app's grant (`Files.SelectedOperations.Selected`) is on the
  `/RestoreTarget` folder only, so that read may answer 403, and a drive's `webUrl` may end in
  `/Documents`. W2.5 checks both. If the drive can't be read, the fallback is the folder's
  `parentReference.siteId` (the first GUID of Veeam's OneDrive `id`), with no new permission
  (`docs/api/veeam-restore-flow.md` §16, `docs/security/graph-permissions.md`).
- **A canary missing from the restore point** is proposed as `fail`, not `error`
  (`docs/api/veeam-restore-flow.md` §15); W3.3 settles it.

---

## 2026-09-28 — W2.3: `rpworker graph list`; a hash-less listing; service-neutral exit codes

**Decision.**

1. **`rpworker graph list [--hash] [--config <path>]`** prints what is in the three restore
   targets now, through W2.2's `TargetReader`: the test mailbox's Inbox, the RestoreTarget
   library, the test OneDrive's RestoreTarget folder, in that order, each a heading with its
   count and, if it holds anything, a table (mail: received, sender, subject, ID; files: name,
   size, ID), then a summary line (`docs/worker-config.md`). It follows `veeam list` in shape:
   `rp/graph_command.hpp` with a `GraphCommandEnv` (config path, secrets, the two HTTP client
   factories, `GraphClientOptions`), dispatched by `rp::run_cli`. The flags come in either
   order, each once. Everything is read before anything is printed. The table layout moved
   from `veeam_command.cpp` into `src/text_table.{hpp,cpp}` (`table_cell`, `display_width`,
   `format_table`), which both commands use; `veeam list`'s output is unchanged.
2. **Without `--hash`, nothing is downloaded or hashed**: `TargetReaderOptions::hash_items`
   (default `true`, W2.2's behaviour). When it is `false`, the file listings skip `/content` and
   the download client entirely, `size_bytes` is Graph's `size` and `on_file` is never called;
   the mail listing leaves `body` out of `$select` and never checks a body. Every `sha256` and
   `sha256_rule` stays empty (documented on `FoundItem`, not an `optional`, so W2.2's callers
   are untouched). The guards run the same either way. (First named `hash_files`, with mail
   hashed either way; the review found that fetched every body for a hash never printed, and
   that one body Graph sent as html failed the whole hash-less listing with exit 4.)
3. **The exit codes are service-neutral** (supersedes the wording of the 2026-09-27 W1.6
   entry, not its numbers): `exit_code::veeam` is renamed `exit_code::service`, and the
   comments in `rp/cli.hpp` and the table in `docs/worker-config.md` speak of "the service".
   For Graph: 1 for a `ConfigError`, a `graph::CertificateError` among them (an unset
   `RP_GRAPH_CERT_PFX_BASE64`, a PFX that doesn't open, a certificate not valid now: all found
   before any request), and any unexpected failure; 2 for `graph::AuthError` and
   `PermissionError` (whose message names the grant); 3 for `graph::TransientError`; 4 for any
   other `GraphError`: `NotFoundError`, `WrongTargetError`, a failed download, an unexpected
   answer. One line on stderr, `graph error: <what()>`; nothing on stdout.
4. **The command's logger writes warnings and worse to stderr only** (`make_command_logger()`
   in `src/command_config.cpp`, now shared with `veeam list`); a `GraphCommandEnv` without a
   logger gets that one too, never spdlog's default logger, which writes to stdout. Downloads go through
   `make_download_http_client()`, whose logger is a null sink, so no download link is logged.
5. **A failed write to stdout is a failure**: after printing, the command flushes `out` and
   checks its state; a full disk or a closed pipe gives `error: unexpected failure`, exit 1,
   never exit 0 with a short listing (exceptions are off on `std::cout`, so nothing throws).
6. **The download client is made only with `--hash`**: without it the reader gets a stand-in
   that throws if ever sent through, so a download client that can't be made never fails a
   listing that downloads nothing. A malformed Graph reply stays exit 4: the reader checks
   Graph's JSON itself and throws `GraphError`, so no JSON library exception reaches the
   command's exit-1 catch-all (a command test pins this).

**Reason.** The operator needs to see the targets before and after a restore (W2.8, W3.4)
without waiting for every file to download; `--hash` is there when the content matters. An
empty target is the normal state, so it prints `0 item(s)` rather than nothing. Graph's
failures map onto the same four meanings as Veeam's, so a script reading exit codes needs no
per-service table.

**Alternatives rejected.**
- *Always hashing:* a slow check that downloads every file, and SharePoint's download host
  becomes a dependency of a listing.
- *`std::optional<std::string>` for `sha256`:* stricter, but it changes every W2.2 caller and
  test for a state only this command produces.
- *Graph-only exit codes (5, 6, ...):* two numbers for the same meaning.
- *A `--json` output:* not needed yet; W2.8/W3.6 decide its shape.

---

## 2026-09-28 — W2.2 review: fixes to reading the restore targets

**Decision.** A code review of W2.2 (`/code-review`, xhigh) found thirteen problems; this entry
records what changed. It supersedes the parts of the W2.2 entry below that it names (§2, §4,
§6, §10, §11, §13); the rest stands.

1. **The OneDrive guard also requires `parentReference.driveType` `business`** (supersedes part
   of §2). Without it, `test_onedrive_drive_id` set to a site library's drive (the canaries'
   RestoreTest library) with a `RestoreTarget` folder at its root passed every check. Missing,
   not a string, or any other value (`documentLibrary`, `personal`, another case) is a
   `WrongTargetError`. The recorded `onedrive-folder-200.json` shows Graph returns it.
2. **Only a 2xx body is held to `max_body_bytes`** (supersedes part of §4). The cap is the
   file's size, so a SharePoint 503 whose error page was longer than a small file was cut,
   returned at once and never retried: whether it counted as transient depended on the file's
   size. Any other status's body is now held to `kMaxErrorBodyBytes` (64 KiB) and handled as
   its status says; a 5xx is retried as without a cap. A 5xx the download client returns all
   the same is a `TransientError`, like one retried to the end.
3. **A docx or xlsx is read up to the download limit, whatever its size** (`SizeCheck`,
   supersedes part of §4). SharePoint rewrites Office files (`lab/README.md`, `office-v1`), so
   their bytes may differ from the `size` Graph lists; one such file failed the whole listing.
   `FoundItem::size_bytes` is what came. Every other file must still be exactly Graph's size.
   Not seen live yet: the one-item recording has no Office file.
4. **A 200 straight from Graph's `/content` is held to the same cap** (supersedes part of §6):
   `GraphClient::get` takes an optional `max_body_bytes`, which goes with every attempt.
5. **Download errors are classified by `is_retryable()`**, not a copy of it, and their
   messages no longer blame a refused connection (that is `connect`, retried) for a `tls` or
   `other` failure.
6. **Mail bodies come in the Inbox listing** (supersedes part of §10): `body` is in the
   listing's `$select` under the same `Prefer`, instead of one GET per mail (N+1 calls).
   `mail-body-200.json` is gone; the recorder checks every listed body is text.
7. **A nextLink is checked by a rule per target, not an exact path** (supersedes part of §11).
   Graph documents `@odata.nextLink` as opaque, so a link naming the mailbox by object ID, or
   the library's root by item ID, was refused. The rules, on `resource_path()`'s segments:
   the Inbox `users/{mailbox or a GUID}/mailfolders/inbox/messages`; the library
   `drives/{test_library_id}/root/children` or `drives/{test_library_id}/items/{an item ID}/children`;
   the OneDrive folder `drives/{test_onedrive_drive_id}/items/{test_onedrive_folder_id}/children`
   only, never another item of that drive, since alice's canary folder shares it. A link to
   another mailbox by GUID would be refused by Exchange RBAC (a `PermissionError`, status
   `error`). The absolute-v1.0, no-refetch and page-cap rules stand. The `paged` recording
   (2026-09-28) confirms the mail rule: Exchange's links name `mailFolders('inbox')`, which
   the rule reads as the same resource.
8. **The ID shapes are config rules** (supersedes part of §13): `parse_config` applies
   `kGraphSiteIdRule`, `kGraphDriveIdRule` and `kGraphItemIdRule` (`rp/config.hpp`), so
   `rpworker config check` refuses a list GUID in `test_library_id` instead of the first run;
   `RestoreTargets::from_config` applies them again for a `Config` built in code, as it does
   the mailbox rule. `TargetReader` only splits the site ID.
9. **ASCII-only folding** (`ascii_lower`, `ascii_iequals`, `ascii_ends_with_i` in
   `src/text_util.hpp`) replaces the locale-dependent copies in the Graph code;
   `kSharePointSuffix` is declared once, in `rp/config.hpp`.
10. **The recorder scrubs a download link anywhere in a body**, an HTML "Object moved" page
    included, as it scrubs a `Location`, and reads `&amp;` as a separator in the scrub and the
    safety check alike. Before, such a 302 made the one-item state unrecordable.
11. **The live test prints Graph's text through `one_line()`** (`tests/found_item_line.hpp`),
    so a restored subject or name can't forge or reorder the lines it prints.

**Reason.** Each was a way to report an infrastructure problem as something else, to read
outside the restore targets, or to fail on replies Graph may really send.

**Alternatives rejected.**
- *Accepting any nextLink under v1.0* (Graph's advice): a link could then list alice's
  canary folder with the token. *Checking each page's items instead of the link* (their
  `parentReference`): more calls and fields, and it still can't tell the mailbox.
- *An exact size for Office files with a retry:* the rewrite is SharePoint's, not a race.
- *Dropping a 200 from `/content`:* Graph may serve one; it is capped instead.

**Consequences.**
- The empty state was recorded again (2026-09-28) with the new `$select`; the recorded
  `onedrive-folder-200.json` has `parentReference.driveType` `business`. The one-item and paged states were recorded the same day, after one mail and
  two files (then a second mail) were put in the targets by hand, and confirm items 3 and 7
  against real replies. Exchange puts an `@odata.nextLink` on every full page, the last one
  included: with two mails and `$top=1`, page 2 has a link and page 3 is empty, so the
  recorder takes three pages and the listing ends on an empty one.
- W3.2 hashes docx and xlsx with `office-v1` through `on_file`, so their byte counts no longer
  matter for verification.

---

## 2026-09-28 — W2.2: reading the three restore targets through Graph

**Decision.** `rp::graph::TargetReader` (`worker/include/rp/graph_targets.hpp`) lists what is
in the three restore targets (the test mailbox's Inbox, the RestoreTarget library's root, the
test OneDrive's `/RestoreTarget` folder) and hashes each item, through W2.1's `GraphClient`.
It returns `std::vector<FoundItem>` in Graph's order; an empty location is an empty vector,
never an error. It only reads. Downloads go through `rp/graph_download.hpp`, mail bodies are
hashed with `rp/text_v1.hpp`, bytes with `rp/sha256.hpp`. This resolves the open point in
`lab/tenant.md` on `test_library_id`.

1. **`test_library_id` is the RestoreTarget library's drive ID** (`b!…`), because Graph reads
   files by drive and the list ID would cost an extra call (`docs/worker-config.md`,
   `lab/tenant.md`).
2. **Wrong-location guard.** Before listing a file target, one GET checks it; a refusal is a
   `WrongTargetError` (a `GraphError`, so run status `error`) and nothing is listed.
   - The library's drive (`$select=id,name,driveType,webUrl,sharePointIds`): display name
     `RestoreTarget`; URL name (the last `webUrl` segment, which a UI rename doesn't change;
     compared ignoring case, query, fragment and percent-encoding) `RestoreTarget`;
     `driveType` `documentLibrary`; `sharePointIds.siteId` and `.webId` equal to the GUIDs in
     `test_site_id`.
   - The OneDrive folder (`$select=id,name,folder,parentReference`): name `RestoreTarget`
     (exact case), a `folder` facet, `parentReference.driveId` equal to
     `test_onedrive_drive_id`, and directly in the drive's root by **`parentReference.path`**,
     which Graph does return (the empty-state recording, 2026-09-28). Two forms are accepted:
     `/drive/root:`, and `/drives/{test_onedrive_drive_id}/root:`, the one Graph actually
     returned. A nested path in either form, another drive's root, or a path that is missing
     or not a string is refused. The root-ID fallback was not needed.
   - Every missing field fails closed. `Sites.Selected` can read the canary library, so the
     permissions can't be the guard. No canary ID appears under `worker/`: the guard's tests
     refuse edited recorded fixtures by shape (named `RestoreTest`, nested, in another site).
3. **Caller headers on GraphClient: an allow-list of `Prefer` only** (`kCallerHeaders`; an
   optional trailing `headers` on `get`, `get_json`, `find`, `find_json`). Any other name,
   `Authorization` included, or an empty value or one with a control character, is refused before the token
   request, so a caller can't swap or add credentials. The headers go on every attempt, the
   401 resend and retries included. The refusal reads `refused the header "<name>" since a
   caller may add only Prefer; …` rather than the drafted `…"<name>": a caller…`, because
   `GraphError` runs its message through `redact()`, which took `"Authorization": ` for a JSON
   secret key.
4. **In memory with a hard cap, no streaming.** `kMaxDownloadBytes` = 64 MiB is checked
   against Graph's `size` before downloading. The download carries
   `HttpRequest::max_body_bytes = size`, so `HttpClient` keeps at most one byte more (a curl
   write callback that stops the transfer) and never retries a cut body; the byte count is
   checked after. Memory is bounded whatever SharePoint sends. A larger file is an `error` in
   Stage 1; the canaries are under 30 KB.
5. **Office files:** `FoundItem::sha256` is the bytes hash (`sha256_rule` `bytes`). W3.2
   computes `office-v1` from the same bytes through `TargetReaderOptions::on_file`, called
   once per file after its size check and hash, in the same pass.
6. **The download follows Graph's `/content` redirect without the token**, through
   `make_download_http_client()`: the Windows store like `make_graph_http_client()`, but its
   logger has only a null sink, so the credential-bearing URL is never logged.
   `download_item` logs only the host and status and never puts the `Location` in a message.
   Only `https://` on the test tenant's hosts (`<t>.sharepoint.com` from `test_site_id`, and
   `<t>-my.sharepoint.com`), port 443, one hop. A 401 or 403 from SharePoint is an error with
   no retry; 5xx and lost connections are retried by `HttpClient`, then a `TransientError`; a
   429 is a `TransientError` at once. A 200 straight from Graph is taken as the content.
7. **Folders inside a location are skipped and logged** (info), not recursed: restores land in
   the root. Other non-file items too (warn).
8. **`FoundItem`** is the brief's `{type, id, name, subject, sender, receivedAt, sha256,
   sizeBytes}` in C++ naming (`received_at`, `size_bytes`; `std::optional` where a type has
   none), plus `internet_message_id` (the canary manifest carries it, and W3.1 matches mail
   on it) and `sha256_rule` (`text-v1` or `bytes`).
9. **The OneDrive grant** `kOneDriveReadGrant` = `"Files.SelectedOperations.Selected read on
   the test OneDrive folder"`. SharePoint answers 404, not 403, for an item the app may not
   read, so the folder's `NotFoundError` adds that the grant may be missing. The
   `PermissionError` path is tested on the hand-written `onedrive-folder-403-accessdenied.json`.
10. **Mail:** `Prefer: outlook.body-content-type="text", IdType="ImmutableId"` (`kMailPrefer`,
    the seeder's `MAIL_PREFER`) on the list and on every `$select=body`. The body is hashed
    with `text-v1`, byte-wise with no ICU, which passes every vector in
    `shared/testdata/body-normalization-text-v1.json`. A body Graph returns as HTML despite
    `Prefer` is an error, since its hash would mean nothing.
11. **Paging:** `@odata.nextLink` is followed for at most `kMaxListPages` (100) pages. A link
    fetched before (any cycle), empty or not a string, or naming another resource than the
    first request (`resource_path`: the path after `/v1.0`, percent-decoded, `seg('x')` as
    `seg/x`, lower-cased) is a `GraphError`, never a silently shortened listing. So is any
    link that doesn't start with `https://graph.microsoft.com/v1.0/`, a relative one too:
    Graph sends absolute links, and `GraphClient` would put its v1.0 root in front of a
    relative path and send it with the token, so leaving it to `GraphClient` would let a
    reply point the listing at another drive (review of W2.2). The mail rule did not have to be widened: the `paged` recording follows two real links.
12. **Fixture states:** `record-graph-fixtures --state {auth,empty,one-item,paged}`
    (`lab/README.md`). Hand-written stand-ins are committed until a state is recorded (the lab
    plan test skips them; a README test keeps rows and files in step). The paged state is
    recorded with two mails and `$top=1`: three pages, the last one empty. The OneDrive 403 is hand-written: the lab can't
    provoke it read-only. The `Location` query is scrubbed to `UniqueId`, `Translate` and
    `ApiVersion`, `@microsoft.graph.downloadUrl` is dropped, and the recorder never follows the
    redirect.
13. **IDs are checked against a charset before they go into a URL path**, since `graph_url()`
    doesn't police `?` or `/` inside an ID. From config, in the constructor, as an
    `rp::ConfigError` naming the key: drive IDs `b!` then 1..200 of `[A-Za-z0-9_-]`, the folder
    ID 1..200 of `[A-Za-z0-9!_-]`, `test_site_id` exactly `<label>.sharepoint.com,<GUID>,<GUID>`.
    From Graph (message and item IDs): 1..512 of `[A-Za-z0-9!_=-]`, else a `GraphError` before
    the ID is used. `test_mailbox` stays with `load_config`, which allows only
    `restoretest@<domain>`.

**Reason.** W3's checker needs what a restore actually put in each target, hashed the way the
canary manifest was, and it must never read the canaries themselves: that would make every
verification pass. Every infrastructure problem (a missing drive or folder, a refused grant, a
bad redirect, a size mismatch, a guard refusal) is an error type, so it becomes run status
`error`, never `fail`, and never an item quietly dropped.

**Alternatives rejected.**
- *The list ID for `test_library_id`, resolved through `/sites/{site}/lists/{list}/drive`:*
  an extra call for nothing.
- *Comparing against a list of canary IDs:* it only knows the lab's, and would put canary IDs
  in `worker/`. *The display name alone:* a site owner can rename it.
- *Free caller headers with `Authorization` filtered* (a deny-list).
- *A body sink in the HTTP layer:* Stage 2 if large files are sampled; it changes
  `IHttpClient` and every fake. *Checking Graph's size only:* not a hard cap.
- *Returning the bytes in `FoundItem`* (memory); *computing office-v1 now* (it needs a
  ZIP/inflate dependency W3.2 will pick).
- *Letting cpr follow the redirect* (it would carry the Authorization header); *any
  `*.sharepoint.com` host* (another tenant's bytes); *relying on `redact()` for the URL* (it
  masks by key name only).
- *Recursing into subfolders:* restores land in the root.

**Consequences.**
- W2.3's `rpworker graph list` prints `list_all()`. W3.1/W3.2 compare its items with
  `lab/seed-manifest.json`: mail on `internet_message_id` and the `text-v1` hash, files on the
  bytes hash, Office files on `office-v1` through `on_file`.
- The Done-when (issue #27) is shown by `worker/tests/graph_targets_live_test.cpp`
  (`docs/testing.md`, "Live tests"), run with the targets empty and again with one item in
  each.
- `docs/worker-config.md` documents the ID forms; `docs/security/graph-permissions.md` has the
  OneDrive grant's text and how its refusal is verified.

---

## 2026-09-28 — W2.1: Graph sign-in with a certificate client assertion; Graph errors, retries and where the token goes

**Decision.** `rp::graph::GraphClient` (`worker/include/rp/graph_client.hpp`) gets app-only
tokens from Entra with a signed client assertion and makes Graph GETs with them. Supersedes,
in the L1.5 entry below ("The Worker's Graph app"), the future-tense secret names of point 1
and the "reconsider CNG in W2.1" alternative, and, in the 2026-09-24 config entry, the
secret `RP_GRAPH_CLIENT_SECRET` and its list of secret-key markers.

1. **Signing with OpenSSL** (`rp/client_assertion.hpp`; no OpenSSL type in the header):
   `PKCS12_parse` once, then `EVP_DigestSign`. Only the key and certificate objects are
   kept; the decoded PFX bytes and the password copy are cleansed on every path.
   - The assertion is always **PS256** (SHA-256, MGF1-SHA-256, salt 32) with an
     **`x5t#S256`** header (base64url SHA-256 of the certificate's DER). A live probe on
     2026-09-28 showed Entra accepts PS256/RS256 with `x5t`, `x5t#S256` or both; one form is
     hard-wired.
   - Claims: `aud` the exact token URL
     `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, `iss` = `sub` = the
     client ID, a fresh `jti` (UUID v4 from `RAND_bytes`) on every token attempt, `nbf` =
     `iat` = wall-clock now, `exp` = `nbf` + 300 s. An assertion is never reused.
2. **Secrets.** `RP_GRAPH_CERT_PFX_BASE64` (the PFX, one line of Base64) and
   `RP_GRAPH_CERT_PASSWORD` replace `RP_GRAPH_CLIENT_SECRET` (`rp/secrets.hpp`,
   `docs/worker-config.md`, "Microsoft Graph app"). `certificate_from_secrets` checks the
   PFX before any network call and throws `rp::graph::CertificateError` naming the
   variable, never its value: unset, not strict Base64, not a PFX, no MAC, wrong password,
   a legacy cipher (re-export with AES256_SHA256), no key or no certificate, a key that
   doesn't match, not RSA of at least 2048 bits, expired or not yet valid. A certificate
   expiring within 30 days logs a warning. An empty password is accepted only if the PFX
   really has none. `config check` stays offline and does not open the PFX. `config.json`'s
   secret-key markers gain `pfx` and `passphrase` (`cert` deliberately not: it would reject
   `veeam_cert_sha256`).
   - **Known gap until the vault (W4.5):** the PFX and its password sit in environment
     variables, and the key lives in process memory for the Worker's lifetime.
3. **Errors** (`rp/graph_errors.hpp`): `GraphError` (base; `what()` always through
   `rp::redact`), `AuthError`, `PermissionError`, `NotFoundError`, `TransientError` (with
   Retry-After). They keep Graph's code, inner code, request ID and a short redacted
   message, never the body. `CertificateError` (an unusable certificate, found when it is
   loaded) is an `rp::ConfigError`, not a `GraphError` (review of W2.1): a command's
   `catch (const GraphError&)` can't take it for a failed call. OpenSSL failing to make a
   jti or to sign at run time is a plain `GraphError`.
   - Entra's refusals map on the AADSTS code (first of `error_codes`, else the number in
     `error_description`), then on `error`, never on the status alone; each `AuthError` says
     what to check (the table is `token_failure` in `worker/src/graph_client.cpp`):
     700016 the client and tenant IDs; 90002, 900023, 50059 the tenant ID; 700027, 7000274,
     50012, 700030 "is the certificate with SHA-1 thumbprint <X> uploaded to app <client
     ID>?"; 700024, 50027 clock skew, with this machine's UTC time; 53003 Conditional Access;
     70001, 7000112, 500014, 1000031 the app is disabled, deleted or not in the tenant; any
     other 4xx an `AuthError` with its code. 5xx, 429, `temporarily_unavailable` and 90006,
     90033, 90090, 50033, 90055 are `TransientError`s and retried.
   - A reply that isn't JSON is a `TransientError` on 5xx, else a `GraphError`.
     `NotFoundError` is only a 404 Graph explains in its JSON error; a mailbox Graph can't
     read (`MailboxNotEnabledForRESTAPI`, `MailboxNotSupportedForRESTAPI`) and a 404 without
     Graph's JSON (a proxy, a wrong path) are plain `GraphError`s.
   - Every Graph error means run status `error`, never `fail`. So `get` is for what must
     be there (the test mailbox, site or drive): its 404 is a `NotFoundError`. An item a
     restore should have put there is looked up with `find`/`find_json`, which answer a 404
     Graph explains with `nullopt` (the item is missing: W3's `fail`), except the codes that
     say the mailbox or user doesn't exist (`ErrorInvalidUser`, `ErrorNonExistentMailbox`,
     `Request_ResourceNotFound`), still a `NotFoundError`. SharePoint and OneDrive answer
     `itemNotFound` for a missing drive as for a missing item, so W2.2 checks the drive with
     `get` first (review of W2.1: one `NotFoundError` for both would have made either a
     misconfigured mailbox a `fail` or a failed restore an `error`).
   - **Exit codes are unchanged in W2.1**: no command calls Graph yet. `rpworker graph list`
     (W2.3) is the first to map these errors. Recommended there: `AuthError` and
     `PermissionError` 2, `TransientError` 3, other `GraphError`s 4; a `CertificateError`
     exits 1 with the other `ConfigError`s.
4. **Permissions.** Every call names a `Grant` (W2.1: Mail through Exchange RBAC, Sites
   through `Sites.Selected`). A 403 with Graph's JSON error is a `PermissionError` "Graph
   denied GET <path without query> (403 <code>): the Worker app relies on <grant>; see
   docs/security/graph-permissions.md"; a 401 that persists after a fresh token names it too.
   A 403 without Graph's JSON (a TLS-inspecting proxy's block page) is a plain `GraphError`
   pointing at the network, as a 404 without it is (review of W2.1).
5. **Retries.** GraphClient makes every attempt itself (`max_attempts` 1, status retries
   off, as VeeamClient): 5 attempts per call, shared by transport failures, 5xx and 429.
   A Retry-After (delta-seconds or IMF-fixdate) on 429 or 503 raises the wait to it; each
   wait is capped at 120 s and one call's waits at 300 s **in all, the waits of a token
   renewal made inside that call included**; over a cap is a `TransientError` at once.
   - The **token POST is resent after any transport failure** (connect, handshake, dropped,
     timeout) with a new assertion, unlike VeeamClient's token request: a client-credentials
     request changes nothing on Entra's side. Also on 5xx, 429 and Entra's retryable codes;
     never on another 400/401; every retry waits at least 5 s.
   - A 401 from Graph: one fresh token and a resend; another 401 is an `AuthError` (at most
     3 resends when other calls keep replacing the token). A 401 asking for
     `insufficient_claims` is an `AuthError` at once.
   - Tokens: `token_type` Bearer, a non-empty `access_token`, integer `expires_in` above 0
     (a day at most counts); renewed 60 s before expiry, or at half a lifetime of 120 s or
     less; single-flight under a renewal lock with a generation counter, and callers waiting
     behind a failed renewal share its failure. The token itself sits under a second, brief
     lock: a call whose token is still good never waits for a renewal in flight, and a call
     that does wait for one has that time counted toward its 300 s (review of W2.1).
6. **Where the token goes.** Only to a URL that starts with exactly
   `https://graph.microsoft.com/v1.0/` (a text compare, plus no whitespace, control
   character (the UTF-8 ones of `control_chars.hpp` included), backslash, `#`, dot segment,
   encoded `/` or `\` or double-encoded dot or separator); a path starting with `/` is
   taken relative to it, any other absolute URL is a `GraphError` before anything is sent. Redirects are never
   followed (`HttpClient` turns them off): `get` returns a 3xx to its caller, and the token
   request treats one as a `GraphError` without sending anything to its `Location`. The
   download that must follow Graph's redirect, without the token, is W2.2's. Every request carries `User-Agent: ISV|RestoreProof|RestoreProofWorker/<version>`.
   `rp::redact` also masks a raw JWT and `Bearer <token>`.
7. **TLS.** The Graph and Entra HTTP client (`make_graph_http_client`) trusts the Windows
   certificate store alone: no CA file, no pin.
8. `graph_tenant_id` and `graph_client_id` must be GUIDs (`rp::is_uuid`), in `config.json`
   and in the GraphClient constructor: both go into URLs and the assertion, and a domain
   name, `common` or `organizations` would sign in somewhere else than meant.

**Reason.**

- **OpenSSL, not CNG.** W2.4 has to put the PFX bytes in Veeam's restore body anyway
  (`docs/api/veeam-feasibility.md` §5.4), so a non-exportable CNG key would not remove the
  PFX from the machine, and OpenSSL is already linked into rpcore.
- **PS256 and `x5t#S256`:** SHA-256 throughout rather than SHA-1 thumbprints and PKCS#1
  v1.5; the probe showed Entra takes it on the lab tenant.
- **One budget per call:** a caller (W2.2's verification) must be able to bound how long one
  GET can block; a separate budget for a token renewal made inside it would double that.
- **Resending the token POST after a lost reply** is safe where VeeamClient's is not:
  Entra's client-credentials grant has no side effect a duplicate could repeat.
- **A grant in every 403 message:** Graph's 403 doesn't say which permission is missing,
  and the Worker's are split across Entra, SharePoint, OneDrive and Exchange RBAC. The
  wording is generic, so a customer never sees lab names.
- **A text compare for the token's URL:** parsing the URL could read it differently from
  curl; an exact prefix leaves no room for that, and makes `@odata.nextLink` safe to follow.

**Alternatives rejected.**

- *CNG with a key in `Cert:\CurrentUser\My`:* see above; reconsider with the vault (W4.5)
  if Veeam's restore body stops needing the PFX.
- *A client secret:* rejected in L1.5.
- *Following Graph's redirects with the token:* the token would reach whatever host the
  redirect names. W2.2's downloads follow theirs without it.
- *A separate retry budget for token renewals:* see "One budget per call".

---

## 2026-09-27 — W1.7: the connector interface; clients by name, neutral types and errors, targets only from Config

**Decision.**

- **`rp::connector::IConnector`** (`worker/include/rp/connector.hpp`) has `describe()`,
  `list_restore_points(client_ref)` and `restore_sample(spec)`. These are the guide's
  `Describe`, `ListRestorePoints` and `RestoreSample`, in the Worker's snake_case. One instance
  talks to one backup server with one set of credentials.
- **`client_ref` is the client's name in the backup product.** For Veeam that is the
  organisation name, as in `veeam_org_name`. A *client* is one MSP customer: one Microsoft 365
  tenant, one Veeam organisation.
  - An MSP whose Veeam server backs up many tenants uses one connector, and each call names
    its client.
  - The connector resolves the name to Veeam's organisation ID on every call, ASCII
    case-insensitively, as `veeam list` marks it.
  - No match is `NotFoundError`; two matches are a plain `Error`; an empty `client_ref` is
    `std::invalid_argument` before any request. A matched organisation whose ID isn't a UUID
    is an `Error`, checked before the restore points are asked for; any other
    `std::invalid_argument` passes through as it is.
  - Error messages show `client_ref` with each control character (`control_chars.hpp`) made
    a space, as `veeam list` shows Veeam's text: it will come from a Cloud job (C5.6), and
    a CR/LF or bidi override in it must not forge, hide or reorder a log line.
- **Neutral types, in namespace `rp::connector`.**
  - `RestorePoint` holds:
    - `id`: opaque, only meaningful to the connector that returned it.
    - `backup_time`: byte for byte as the product sent it, since Veeam opens explore sessions
      by that exact string.
    - `has_mail`, `has_sharepoint`, `has_onedrive`.
    - `is_archive`: Veeam's long-term copy, whose restore needs a retrieval first.
  - Veeam's organisation, repository and job IDs, `isCopy`, `isDeleted` and Teams stay behind
    the interface.
  - Errors: `connector::Error` (a `runtime_error`; `what()` is safe to print), with subclasses
    `AuthError`, `TransientError`, `NotFoundError` and `NotImplementedError`.
  - `VeeamM365Connector` catches the `VeeamError` family and rethrows the matching class with
    the same, already redacted, message: `AuthError`, `TransientError` and `NotFoundError` map
    to their namesakes, and any other `VeeamError` becomes `Error`.
  - The classes line up with `rp::exit_code`: 2 auth, 3 transient, 4 the rest. A command
    that runs a connector (W2.8) maps them as `veeam list` maps the Veeam ones.
- **`RestoreStatus` is the restore's own outcome**, not pass/fail/error, which W3.3 decides
  from it and the Graph comparison. How W2.5 will map Veeam's session `result` and
  `restoredItemsCount` onto it, one session per item type:

  | Status | Meaning | Veeam |
  |---|---|---|
  | `succeeded` | every session succeeded and restored every item sent | every session `Success`, each `restoredItemsCount` equal to the items it was sent |
  | `partial` | something restored, but not cleanly | any `Warning`; a `Failed` session beside sessions that restored items; `Success` with a short `restoredItemsCount` |
  | `failed` | nothing restored | every session `Failed`, or 0 restored; this covers the OneDrive trap in `docs/api/veeam-feasibility.md` §3 (`Failed`, 0 restored, no `errors`) |
  | `not_run` | nothing was sent | the default; what an empty spec returns |

  - The rows are tried in this order, and the first that fits wins: `not_run` (nothing
    sent), `failed` (0 restored in total, whatever the results say), `succeeded`, then
    `partial` for everything else. So `Warning` with 0 restored and `Success` with 0
    restored are `failed`, never `partial`.

  - W3.3 then reads: `failed` → fail; `partial` → fail unless every item verifies.
  - Infrastructure failures and guard violations are exceptions, never a status.
  - `RestoreResult` also carries:
    - `session_ids`: a vector, one per session (the guide's `sessionId`).
    - `log`: the sessions' logs, as text.
    - `items_restored`.
- **Restore targets come only from Config.** `RestoreTargets::from_config` is the only way
  to build one (the default constructor is private). It rejects an empty value and, as
  `parse_config` does, a `test_mailbox` that isn't `restoretest@<domain>`
  (`rp::is_restore_mailbox`), since a `Config` built in code skips `parse_config`.
  - It holds `test_mailbox`, `test_site_id`, `test_library_id`, `test_onedrive_drive_id` and
    `test_onedrive_folder_id`.
  - `RestoreSpec` holds a copy, so a spec can't be made without the configured targets and
    nothing dangles.
  - W2.7's `TargetGuard` compares each item's target with these, inside `restore_sample`.
    Resolving the Graph IDs to the names and URLs Veeam's restore bodies take (§5.5) is W2.4
    and W2.7's job.
  - `RestoreSpec` also holds the `client_ref`, the whole `RestorePoint` (for its
    `backup_time`), and mail, SharePoint and OneDrive selectors shaped like
    `lab/seed-manifest.json` entries. W2.5 and W2.6 may add fields.
- **`rpworker veeam list` stays on `VeeamClient`.** It lists every organisation, with Teams
  and raw Veeam IDs: a Veeam diagnostic, not a per-client connector operation. Its output and
  exit codes don't change.
  - The Done-when is shown in `worker/tests/connector_test.cpp` instead: scheduler-like code
    drives a fake connector through `IConnector&`, and a scan checks that nothing the file
    includes reaches a Veeam header.
  - `veeam_m365_connector_test.cpp` drives the registry's `veeam_m365` through `IConnector&`
    on recorded fixtures, and a `[live]` test does the same against the lab.
  - W2.8 `rpworker restore` will be the first command to go through the registry.
- **No config key picks the connector.** The name stays hard-wired as
  `rp::connector::kVeeamM365` until there is a second connector.
  - C5.2/C5.6 already give each client's connector a `type` in the job, which is where the
    name will come from.
  - `ConnectorRegistry` (`rp/connector_registry.hpp`) is an explicit name → factory map:
    - `add` rejects an empty name, a null factory and a duplicate.
    - `create` matches names exactly.
    - `default_connector_registry()` registers `veeam_m365`.
  - An unknown name is `UnknownConnectorError` (`std::invalid_argument`), listing the known
    names. The asked-for name is quoted only when it is 1–64 printable ASCII characters. It
    is a configuration error: exit 1 where a command meets it, `error` for a run.
  - The Veeam factory throws `ConfigError` "RP_VEEAM_USERNAME is not set" (then
    `RP_VEEAM_PASSWORD`), as `veeam list` reports them.
- **The connector owns its HTTP client and `VeeamClient`,** made from `ConnectorOptions`
  (HTTP factory, logger, sleep, jitter) with `veeam_ca_file` and `veeam_cert_sha256` from
  the config (TLS never off). It logs out in its destructor, and does nothing if it never
  signed in. `describe()` is offline: `{"veeam_m365", "v8"}`, the REST API version it
  speaks. `restore_sample` throws `NotImplementedError` before any request until W2.5.

**Reason.** The Done-when asks that the scheduler hold an `IConnector&` without knowing
Veeam. That rules out Veeam types and exceptions crossing the interface, and a scan makes it
checkable. C5.6's job carries the Veeam org name, not an ID, so the name is the reference
that will arrive. A targets type that can only come from a validated Config gives TargetGuard
one source of truth, and leaves no code path that builds free-form targets.

**Alternatives rejected.**

- *Veeam's organisation ID as `client_ref`:* a Veeam concept in the neutral interface, and
  not what the job sends.
- *Reusing `rp::RestorePoint` and the Veeam exceptions:* the scheduler would include
  `veeam_client.hpp`.
- *Veeam exceptions that also derive from the connector ones:* multiple inheritance, and
  `VeeamClient` would depend on the connector layer.
- *pass/fail/error as the connector's status:* the connector can't see the Graph comparison.
- *A spec holding a reference to one `RestoreTargets`:* it could dangle once runs go to a
  worker thread.
- *Moving `veeam list` onto the connector:* it would need a `ListClients` and Veeam-only
  fields on the interface.
- *A `connector` key in `config.json`:* the wrong place once jobs carry the type.
- *Self-registering factories:* the linker drops unreferenced objects from the static
  `rpcore`, and their registration with them.

---

## 2026-09-27 — The Worker's Graph app: a certificate, `*.Selected` grants, Exchange RBAC for mail, read-only for now (L1.5)

**Decision.** The Worker reads the restore targets through its own app registration,
"RestoreProof Worker" (single tenant, app-only). Details and the per-permission reasons:
`docs/security/graph-permissions.md`.

1. **Credential: a certificate, not a client secret.**
   - Until the vault, the private key exists only in a PFX outside the repo
     (`%LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx`). Its random password is in
     Credential Manager (`RestoreProof Lab - Worker Graph app PFX`).
   - When the Worker's Graph code lands (W2.1), `RP_GRAPH_CLIENT_SECRET` is replaced by
     `RP_GRAPH_CERT_PFX_BASE64` (the PFX, Base64) and `RP_GRAPH_CERT_PASSWORD`. That is the
     same form Veeam's restore body takes, and the vault (W4.5) will hold it.
     *(Done in W2.1: see the 2026-09-28 entry.)*
2. **No `Files.Read.All`.** SharePoint access is `Sites.Selected` `read` on the RestoreTest
   site. OneDrive access is `Files.SelectedOperations.Selected` `read` on alice's
   `/RestoreTarget` folder: not `Sites.Selected` on her OneDrive.
3. **Mail through Exchange Online RBAC for Applications.** The role is `Application
   Mail.Read`, with a management scope of `PrimarySmtpAddress -eq 'restoretest@…'`. The Entra
   `Mail.Read` consent is not granted, and the setup script removes it if present.
   A management scope needs the tenant "hydrated", so the lab tenant ran
   `Enable-OrganizationCustomization` on 2026-09-27. That is once per tenant, tenant-wide and
   irreversible, and was chosen over scoping by an Entra administrative unit, which would add
   an Entra object and a Graph scope for the same result.
4. **Read-only in L1.5.** The write needs of cleanup (W3.x) are an open item, with a proposal:
   `Lists.SelectedOperations.Selected` `write` on the RestoreTarget list only, the folder
   grant raised to `write`, and `Application Mail.ReadWrite` on the same scope.
5. The setup is a script the admin runs, `lab/entra/new-worker-app.ps1` (idempotent). It is
   checked by `python -m seeder check-worker-app`: 200 on the three targets (and on the
   metadata of alice's OneDrive site and root folder, which a folder grant opens), 403 on
   alice's mailbox, the tenant root site and its drives, and the OneDrive host site, 404 on the
   canary folder (SharePoint masks items the app may not see; a sign-in as alice first confirms
   the folder exists), alice's OneDrive root listing only `RestoreTarget` by that name, exactly
   two roles in the Graph token and none in the Exchange Online and SharePoint tokens. The
   RestoreTest site's canary library stays readable: `Sites.Selected` covers the whole site.
   The script leaves the certificate as the app's only credential (no client secret).

**Reason.**

- **Certificate.** A secret is a password sent with every token request; a certificate signs
  a short-lived assertion, so the key never leaves the machine. W1.0 showed Veeam's restore
  body needs an app certificate as a PFX anyway (`docs/api/veeam-feasibility.md` §5.4), so one
  credential kind and one storage path cover both. A non-exportable key in the certificate
  store would be stronger at rest, but the lab's Python checker can't sign with it, and
  Veeam needs the PFX bytes regardless.
- **`Files.Read.All`** reads every drive in the tenant through `/drives/{id}`, so "403 on any
  other site" (the Done-when) could never hold.
- **`Sites.Selected` on alice's OneDrive** would open her whole OneDrive, the canary folder
  included. Graph's `*.Selected` scopes now reach a single folder, and every `*.Selected`
  scope works app-only (Microsoft, "Overview of Selected permissions in OneDrive and
  SharePoint").
- **Mail.** An Entra `Mail.Read` consent covers every mailbox. Exchange adds RBAC grants to it
  as a union, so a scoped grant only means something if the consent is gone (Microsoft,
  "Role Based Access Control for Applications in Exchange Online", FAQ). RBAC for
  Applications replaces Application Access Policies.
- **Read-only.** `Sites.Selected` roles apply to the whole site, and the canary `RestoreTest`
  library shares the site with `RestoreTarget`. A site-wide `write` would put the canaries in
  reach of the Cleaner. Nothing in L1.5 writes, so nothing is granted to write.

**Alternatives rejected.**

- *A client secret (the issue's wording):* weaker, and a second kind of credential next to
  the PFX Veeam needs.
- *A non-exportable key in `Cert:\CurrentUser\My`:* see above. Reconsider when the Worker
  signs its own assertions in C++ (W2.1): CNG can sign with a key it never exports. Veeam's
  PFX would still be needed. *(Reconsidered in W2.1 and kept rejected: see the 2026-09-28
  entry.)*
- *`Files.Read.All` or `Sites.Read.All`:* tenant-wide.
- *`Sites.Selected` on alice's OneDrive:* her whole OneDrive for one folder.
- *An Application Access Policy on top of Entra `Mail.Read`:* legacy, replaced by RBAC for
  Applications.
- *Granting `write` now:* no L1.5 need, and the only site-level form reaches the canaries.

**Open.**

- The write grants for W3.x (above).
- Which app's certificate goes in Veeam's restore body (W2.4). Not this one: it can't write.
  *(W2.4 used Veeam's own organisation app, exported per run, in the lab; the Worker's restore
  credential is open until a spike before W4.5: see the 2026-09-28 W2.4 entry.)*
- Per-customer onboarding of these grants, and certificate renewal (a one-year lab cert).

---

## 2026-09-27 — W1.6: rpworker veeam list, exit codes and output

Changes the usage exit code from 2 to 64. The 2 was set with W1.1/W1.2 in the `cli.hpp` and
`config_check.hpp` comments and `docs/worker-config.md`, never recorded in this log; the
2026-09-24 entry "`rpworker`'s command line lives in rpcore" only says where exit codes live.

**Decision.**

- **One set of exit codes for the whole `rpworker` CLI**, in `rp::exit_code`
  (`worker/include/rp/cli.hpp`): `0` success; `1` config error (`config.json` missing or
  invalid, a `--config` path that isn't UTF-8, `RP_VEEAM_USERNAME` or `RP_VEEAM_PASSWORD`
  unset or empty, or any unexpected exception that isn't a Veeam one, whose message is never
  shown); `2` `AuthError` (Veeam refused the credentials, the role or the token); `3`
  `TransientError` (unreachable, timeout, TLS handshake failure, 502/503/504); `4` any other
  `VeeamError`, `NotFoundError` included, and `veeam_org_name` not among Veeam's
  organisations. A certificate that fails verification (`TransportError::tls`: a
  `veeam_ca_file` that doesn't hold Veeam's certificate or its CA, or a `veeam_cert_sha256`
  that no longer matches after Veeam's certificate was renewed) is a plain `VeeamError`, so
  exit 4, not 3: it won't fix itself on a retry. `64` usage (sysexits' `EX_USAGE`): a command line `rpworker` doesn't
  understand, an argument that isn't valid UTF-16 included. The usage line is one string,
  `rp::kCliUsage`, listing all three forms.
- **Messages on stderr, one line each:** `config error: <ConfigError what()>` as in `config
  check`; `config error: RP_VEEAM_USERNAME is not set` (checked first), then the same for
  `RP_VEEAM_PASSWORD`; `veeam error: <what()>` (already redacted by `VeeamError`);
  `error: unexpected failure` for an unexpected exception after the config loaded.
- **No exception leaves `rpworker`.** `rp::run_cli` and `rp::run_main` are `noexcept` and
  catch anything a command lets out: `error: unexpected failure`, exit 1. Uncaught, it would
  end in `abort()`, whose exit code with the MSVC runtime is 3, the code for "Veeam
  unreachable, try again later". `veeam list` catches everything itself too, formatting and
  writing the table included.
- **`veeam list` lists every organisation Veeam returns**, sorted by name (ASCII
  case-insensitive), then ID, and marks the one `veeam_org_name` names (ASCII
  case-insensitive) with `*` in a leading marker column. When none matches, the table is
  still printed, then `veeam error: organisation <name> (veeam_org_name) not found in
  Veeam`, exit 4; with no organisations at all it prints `no organisations in Veeam` and the
  summary, exit 4.
- **Every list is read before anything is printed.** A restore-point list that fails for
  any organisation (a `NotFoundError` if it vanished between the two calls included) fails
  the whole command with that error's code, and stdout stays empty: no partial table.
  `logout()` runs after any sign-in, on success and on failure, and after the table is
  printed, so a slow logout doesn't hold the table back.
- **The table** (stdout, UTF-8 bytes): columns `ORGANIZATION`, `BACKUP TIME`, `EX`, `SP`,
  `OD`, `TM`, `LONG-TERM`, `RESTORE POINT ID`, after the two-character marker column
  (`* ` or two spaces); left-aligned, padded to the widest cell counted in code points, two
  spaces apart, no trailing spaces. `backupTime` exactly as Veeam sent it; points newest
  first; the flags `x`/`-`, `LONG-TERM` `yes`/`no`; the organisation name on every row; an
  organisation without points gets one row with `(no restore points)`. Control characters
  in text from Veeam become spaces. Then a blank line and `<n> organisation(s), <m> restore
  point(s); * = veeam_org_name`. `rpworker` never changes the console code page, and
  PowerShell 7 doesn't either: non-ASCII names show correctly on a console only once its
  output code page is UTF-8 (`chcp 65001`, or `[Console]::OutputEncoding` set to UTF-8 in
  PowerShell). On code page 437 `Zürich` shows as `Z├╝rich`.
- **Testability.** `rp::run_veeam_command` (`worker/include/rp/veeam_command.hpp`) takes a
  `VeeamCommandEnv` (default config path, secrets loader, HTTP client factory, client
  options); `run_cli` passes `default_veeam_command_env()`, whose logger writes warnings and
  worse to stderr, never to stdout where the table is. The HTTP client gets `ca_file` and
  `pinned_cert_sha256` from the config (TLS never off). The `[--config <path>]` handling
  `config check` had moved to `worker/src/command_config.{hpp,cpp}`, shared by both
  commands. `run_exe_test.cmake` takes an optional `UNSET_ENV` list, so an exe test can
  remove variables the developer's shell has set.

**Reason.** The issue asks for exit code 2 on an authentication failure, which usage held.
Distinct codes let a script or the future service tell a wrong password from a server that
is down from a missing organisation without parsing text. Listing every organisation, rather
than only the configured one, is what an operator needs when `veeam_org_name` is wrong: the
right name is on screen. Building the whole table first keeps a failure from looking like a
short, successful list.

**Alternatives rejected.** *Keeping usage at 2 and giving auth another code:* the issue fixes
auth at 2. *Printing only `veeam_org_name`'s restore points:* a typo would show nothing
useful. *Printing organisations as they are read:* a later failure would leave a partial
table that looks complete. *Setting the console to UTF-8 from `rpworker`:* it changes the
shell's state for everything run after it; the bytes are UTF-8 either way. *CLI11:* the
hand-rolled parser still has three forms; not worth a dependency. *A code of its own for an
exception no command caught (70, sysexits' `EX_SOFTWARE`):* exit 1 already means "something
unexpected failed" and says nothing more; what matters is that it isn't 3.

---

## 2026-09-26 — VeeamClient after review: one retry budget, token requests at most once, renewal failures shared only while no token works (W1.5)

Supersedes parts of the entry below ("VeeamClient: status retries off per request ...") and
of "Veeam TLS" (how the CA file is read), after the review of PR #124.

**Decision.**

- **VeeamClient makes every attempt itself: five per request in all.** A new
  `HttpRequest::max_attempts` (1 to 5, default 5) caps `HttpClient`'s attempts; every
  Veeam request goes out with 1, so `HttpClient` never retries under the client (one GET had
  made up to 25 requests, 50 through the 401 path). With 1, `HttpError`'s message carries no
  attempt count; the client adds its own ("... (5 attempts)", "HTTP 503 after 5 attempts").
- **A new `TransportError::dropped`** for a connection that broke after the request may have
  gone out (curl's `SEND_ERROR`, `RECV_ERROR`, `GOT_NOTHING`, `PARTIAL_FILE`, formerly
  `connect`). `connect` now means the request never went out. `HttpClient` retries both, as
  before.
- **Which failures are retried.** A GET: `connect`, `dropped`, `timeout`, `handshake`, and a
  transient 5xx, with `rp::retry_delay`'s backoff. A token request (`/v8/token`): only
  `connect` and `handshake`, which never reached Veeam. After a timeout or a dropped
  connection it is not resent: a second password grant is a second logon (towards an
  account lockout, or another token chain nobody holds), a second refresh presents a used
  token. A logout: one attempt, never retried.
- **`/v8/token`'s 5xx.** Only a 500 is a refusal (`AuthError`, whatever its body). A 502,
  503 or 504 is a gateway or a service starting up (`TransientError`); any other 5xx maps
  as on any call. None is retried: the next call signs in again.
- **A refresh that fails with a `TransientError` is thrown as it is**, not followed by a
  password sign-in, which would meet the same unreachable server while every other caller
  waits on the lock. A refresh Veeam refuses (401 "Refresh token is not valid", an empty
  500) or garbles still falls back to the password.
- **Renewal failures are shared only while no token works.** A caller that waited for the
  lock while a sign-in or refresh failed gets that failure only if it still has to renew
  when it gets the lock and no renewal has succeeded since (a stored token clears the kept
  failure). A waiter was handed an earlier failure after a later sign-in had succeeded.
- **An empty 401 for a newer token** another caller brought is followed by the one fresh
  sign-in if that token is dead too (a REST restart kills every token), then one more
  resend; at most three resends per call. It used to end in `AuthError`.
- **`logout()` refreshes an access token within 60 s of expiry first** (one try, no password
  sign-in): Veeam refuses a logout with an expired one, and the refresh token it would end
  outlives it (veeam-notes §1.5). It sends outside the lock.
- **Paging** gives up after 3 full pages in a row that bring nothing new, not 1: with a small
  page size, points added in front between two reads repeat the last page.
- **List entries are moved out of the parsed page**, never copied: copying a JSON value
  recurses once per level, and a deeply nested value overflowed the stack.
- **Text from a response** (`message`, `errorCode`, `WWW-Authenticate`'s
  `error_description`, a bad `backupTime`) has every control character replaced, including
  the multi-byte ones config values refuse (C1, U+2028/U+2029, bidi marks, embeddings,
  overrides and isolates, U+061C); one list in `worker/src/control_chars.hpp` serves both.
- **`expires_in`** of 2^63 or more is capped at a day like any other large value, not refused.
- **The CA file is read as curl's Schannel backend reads it** (`rp::public_key_pin`, so
  `config check` too): each exact `-----BEGIN CERTIFICATE-----` line through the next
  `\n-----END CERTIFICATE-----`, decoded by the same `CryptQueryObject` call, stopping at
  the first BEGIN marker with anything after it on its line, and failing on a block without
  its END line or one Windows can't decode. OpenSSL's PEM reader accepted files curl then
  loaded as empty (a trailing space after the marker, the old `X509 CERTIFICATE` label) or
  refused, and asked for a pass phrase on the console for a block with PEM encryption
  headers. rpcore links `crypt32`.

**Reason.** The review found each of these as a failing scenario (retries multiplied to
11-23 minutes per GET; a stale sign-in error with a valid token stored; an `AuthError` after
a REST restart; 330 s instead of 165 s behind a hung server; a refused logout; a CA file
that passed `config check` and failed every connection). Each has a test that reproduced it
before the fix.

**Alternatives rejected.** *A retry predicate on `HttpRequest` so `HttpClient` keeps the only
loop:* `FakeHttpClient` doesn't retry, so every Veeam retry test would move to the local
server; a cap is simpler. *A single-flight future per renewal:* also correct, but a larger
change than clearing the kept failure on success. *Never resending a token request:* a
connection refused while Veeam restarts would fail the run at once. *Our own base64 decoder
for the CA file:* the only way to agree with curl exactly is to call what curl calls.

**Open.** A restore POST (W2.x) gets the same at-most-once rule as a token request from
`send_with_retries`; whether a timed-out restore started is still to be found in
`GET /v8/RestoreSessions` before any resend (veeam-notes §6).
*(W2.4, 2026-09-28: the restore POST is sent at most once, with a duplicate check in
`GET /v8/RestoreSessions` instead of a resend; see the 2026-09-28 W2.4 entry. `VeeamClient`
implements it in W2.5.)*

---

## 2026-09-26 — VeeamClient: status retries off per request, Veeam's 5xx classified by the client; token and paging rules (W1.5)

**Decision.** `rp::VeeamClient` (`worker/include/rp/veeam_client.hpp`) follows
`docs/api/veeam-notes.md` §1.7 and §8, with these choices:

- **`retry_on_status`** is a new per-request flag (`HttpRequest`, `RequestOptions`, default
  on). Off, every response, 5xx included, comes back after one attempt; transport errors
  (connect, timeout, dropped handshake) are still retried. Every Veeam request goes out
  with it off.
- **The client classifies Veeam's 5xx itself.** Any 5xx on `/v8/token` → `AuthError`, never
  retried. A 500 whose body is a JSON object with a string `message` → `VeeamError` with
  that message, not retried. 502/503/504, and any other 5xx without such a body →
  `TransientError`; on a GET, the client retries it first with `rp::retry_delay`'s backoff (five
  attempts in all). 401/403 and `errorCode: ResourceAccessDenied` → `AuthError`; 404 with
  `ResourceNotFound` → `NotFoundError`; everything else → `VeeamError`. All four derive
  from `VeeamError`, which keeps the status, Veeam's `errorCode` and the error body (never
  for `/v8/token`: a proxy could echo the posted password).
- **Tokens.** Refresh 60 s before expiry, counted on the local steady clock from receipt;
  `expires_in` capped at a day, and a lifetime of 120 s or less refreshed at its half. One
  mutex covers sign-in, refresh and the swap of both tokens. Any refresh failure falls back
  to the password. An empty 401 on an API call: resend with the current token if another
  caller has replaced it, otherwise sign in once and resend; a second 401 → `AuthError`. A
  401 with a message (the account's role) → `AuthError` at once. Callers that waited on the
  lock while a sign-in failed get that failure rather than each trying in turn.
- **Lists page until a page is shorter than the limit Veeam echoes** (1000 asked). An `id`
  seen on an earlier page is dropped (a backup finishing mid-read shifts the pages); a full
  page with nothing new stops with an error instead of looping.
- **Restore points are sorted newest first by `backupTime`'s value**, and `backupTime` is
  kept as the raw string. A point whose `backupTime` isn't Veeam's UTC form
  (`YYYY-MM-DDTHH:MM:SS[.1-7 digits]Z`) fails the whole list: explore sessions are opened by
  that string, and Veeam answers 500 to any other form.
- **Names are snake_case** (`list_restore_points`, `ensure_token`), like the rest of rpcore,
  not the guide's camelCase. `RestorePoint` has no `isModified`: v8 has no such field
  (veeam-notes §3, §10).
- **Tests run on recorded fixtures** (`worker/tests/fixtures/veeam/`, from the W1.4/L1.6
  evidence) served by a minimal `FakeHttpClient` (`worker/tests/fake_http_client.hpp`);
  Q2.1 extends it and adds `--record`. The live test runs only with `RP_LIVE=1` and is
  read-only.

**Reason.** Veeam answers 500 to many requests that will never succeed (an explore before
the first point, a stopped session, a bad search, a `dateTime` without `Z`). With W1.3's
rule each cost about 15 s of retries and then lost the body that said why. A refused
sign-in has been an empty 500, so retrying `/v8/token` only delays an `AuthError`. The token
rules follow what the lab showed: refresh tokens rotate and are single-use, a refresh
revokes the old access token at once, and a REST service restart kills every token.

**Alternatives rejected.** *A retry predicate on the request instead of a flag:* more
general, but a callback in every request for one caller's rule. *Letting `HttpClient` retry
GETs' 5xx and classifying afterwards:* a deterministic 500 would still cost 15 s. *Sorting
`backupTime` as text:* Veeam drops trailing zeros of the fraction, so `…15Z` would sort
after `…15.2Z`. *Skipping points with an odd `backupTime`:* hides a format change that
would break every explore anyway. *Parsing `backupTime` into a date type:* drops digits;
W2.x must send it unchanged. *Trusting `.expires`:* it is the server's clock.

**Open.** W1.3's open point is half closed: the 5xx half is settled here, but a timeout or
a connection dropped after a POST went out is still retried by `HttpClient`, so a restore
POST could still run twice. W2.x must add an at-most-once mode (no retry once the request
may have been sent) or find its own session in `GET /v8/RestoreSessions` before resending
(veeam-notes §6). *(W2.4, 2026-09-28: the restore POST is sent at most once, with a duplicate check in
`GET /v8/RestoreSessions` instead of a resend; see the 2026-09-28 W2.4 entry. `VeeamClient`
implements it in W2.5.)* `logout()` holds the lock while it sends, so a hanging logout delays
other calls; it runs at the end of a job. Veeam's "cannot manage selected object" 500
(an operator outside its scope, veeam-notes §8) maps to `VeeamError`, not `AuthError`;
operator mode is out of Stage 1.

---

## 2026-09-26 — Veeam TLS: the CA file plus a pinned certificate; only the host-name check is skipped (W1.5)

**Decision.** This settles the TLS point left open by "Veeam: admin mode is the default"
(2026-09-26). A new optional config key, `veeam_cert_sha256`, names Veeam's REST
certificate by its SHA-256, as Windows shows it (`GetCertHashString('SHA256')`, the value
the W1.4 scripts pin). It requires `veeam_ca_file`, which must hold that certificate in
PEM. With both set, the Veeam connection:

- keeps peer verification on, with the CA file as the only trust anchor (curl's Schannel
  backend validates the chain against it alone, dates included);
- pins the certificate's public key (`CURLOPT_PINNEDPUBLICKEY`, `sha256//` + the base64
  SHA-256 of its SubjectPublicKeyInfo, worked out by `rp::public_key_pin` from the CA file);
- skips only the host-name check.

Without a pin nothing is relaxed: a CA file alone, or no setting at all, keeps full
verification. `load_config` checks that the CA file holds the named certificate. If the pin
can't be worked out when the client is built, every request is refused before sending.
The TLS source scan gets narrow reviewed exceptions, each allowed once and only in
`src/http_client.cpp`: the statement that writes the pin, and
`options.verify_host = options.pinned_public_key.empty();`. Any other mention of the pinned key in
Worker code fails the build.

**Reason.** Veeam's default REST certificate is self-signed, `CN=Veeam Software`, with no
extensions at all, so no subject alternative name: no host name can ever verify against it,
and `veeam_ca_file` alone fails on every default install (feasibility §5.1). A probe on
127.0.0.1 with a certificate built the same way (curl 8.22, Schannel) showed:

- Schannel honours the pinned key whether or not peer verification is on;
- the host check can be turned off on its own;
- with CA file + pin + host check off, the right pin passes, while a wrong pin, another
  server key, a CA file without the certificate, no pin, a CA file alone and an expired
  certificate all fail;
- with peer verification off as well, an expired certificate passed.

So keeping the chain check costs nothing and keeps the dates. The TLS tests
(`worker/tests/http_client_tls_test.cpp`) repeat each case with a certificate made at run
time.

**Alternatives rejected.** *Pin only, with peer and host verification off:* one setting
fewer, but the config would have to hold the public-key hash (not what Windows shows), the
expiry would go unchecked, and the scan exception would be two switched-off checks. *A
certificate with the server's DNS name (`Set-VBORestAPISettings`):* still supported, through
`veeam_ca_file` alone, but it asks every MSP to replace Veeam's certificate before a first
test. *Importing Veeam's certificate into the Worker machine's Windows root store:* it
would let a key on the Veeam server sign certificates the whole machine trusts. *Checking the certificate's hash
after the handshake (`CURLOPT_CERTINFO`):* the request, password included, would already
be sent.

---

## 2026-09-26 — Bruno collection replaced by PowerShell scripts (W1.4)

**Decision.** The guide's W1.4 asks for a Bruno collection exported to
`docs/api/veeam-m365.bru`. Instead, the Veeam REST calls are small PowerShell 7 scripts in
`docs/api/veeam-m365/`:

- one script per step (`01-auth.ps1` … `09-token-expiry.ps1`);
- a shared, dot-sourced helper (`VeeamLab.ps1`);
- an evidence audit (`audit-evidence.ps1`);
- a README.

They record their responses, scrubbed, as `docs/api/veeam-lab/w1.4-*.json`, the format W1.0
started. `docs/api/veeam-notes.md` is written from those files. Later API exploration (W2.4's
restore flow) extends the same collection.

**Reason.**

- **TLS without switching verification off.** Veeam's default REST certificate has no SAN, so
  no host name verifies (`docs/api/veeam-feasibility.md` §5.1). Bruno can trust a CA file or
  turn verification off, and it can't pin one leaf certificate. The helper pins the leaf's
  SHA-256 in a compiled .NET callback, which is the same trust the Worker will need (W1.5).
- **No secrets on disk.** rp-veeam's password is read from Windows Credential Manager at run
  time, and tokens live only in the process. A Bruno environment keeps variables in files next
  to the collection, easy to commit by mistake.
- **Evidence comes out scrubbed and audited.** Every call can write its exchange straight into
  the repo's evidence format. The writer replaces known secret values, token-shaped values and
  JWTs, and refuses to write a file in which a secret survived. The audit script re-checks
  everything before a commit. W1.0 did this by hand-run helpers; now it is in the repo.
- **Session hygiene in code.** Every explore session is stopped in a `finally`, and a sweep
  script stops leftovers. A request collection can't express "stop what you opened, even on
  failure", and a leaked session stays `Working` for a long time (W1.0 saw 36 minutes).
- **Already proven.** W1.0 ran entirely on PowerShell and raw REST.
- **Nothing new to install.** PowerShell 7 is already on every machine that runs Veeam's own
  cmdlets (`docs/environment.md`), including an MSP's Veeam server.

**Alternatives rejected.**

- *Bruno (the guide's choice):* no leaf pinning (above), and its variables sit next to the
  collection.
- *Postman:* the same TLS options, plus a cloud account and sync.
- *curl scripts:* `--cacert` fails the host-name check on the SAN-less certificate. `--pinnedpubkey`
  pins the public key but still needs `-k` to skip the name check, which is off-limits.
- *A Python (httpx) collection in `lab/`:* would work, but it would add a second HTTP stack for
  the same job. PowerShell already has the working pinned client, and the Credential Manager
  and DPAPI calls, from W1.0.
- *Writing it in C++ straight away:* that is W1.5. W1.4 is exploration, and a C++ program
  would be tested against a moving target.

---

## 2026-09-26 — Veeam: admin mode is the default and the only mode in Stage 1; restores send an application certificate

**Decision.** This settles the 2026-09-22 entry "Veeam authentication supports two modes;
W1.0 picks the default". The evidence is in `docs/api/veeam-feasibility.md`.

- **`VeeamClient` uses admin mode.** A dedicated local Windows account (L1.6: `rp-veeam`, a
  standard user in the Veeam Backup Administrator role, interactive and RDP logon denied)
  signs in with `grant_type=password` and `disable_antiforgery_token=true`.
- **Operator mode is not built in Stage 1.** Plan section 9 and the security one-pager (Q7.3)
  must not claim "never a Veeam administrator".
- **Restores to another location send restore credentials in the body.** The only kind that
  works unattended is an Entra application ID with its certificate (PFX, Base64, and its
  password). Veeam refuses a body without credentials (400), and user credentials fail on MFA.
- **Tokens.** Refresh tokens are single-use and die with every restart of Veeam's REST service,
  so on any refresh failure the client signs in again with the password.
- **The Sprint 1 gate's fallback** (Veeam's PowerShell module run on the Veeam server) is not
  needed. It stays the answer for an MSP that refuses admin mode.

**Reason.**

- **Operator restores can't reach our targets.** The operator endpoints can only restore mail
  into the original mailbox and OneDrive files to their original place. The schema has no
  target field, and Veeam's docs say the same. So two of the three restore targets are out of
  reach, and CLAUDE.md forbids original locations.
- **Operator sessions can't be kept alive unattended.** A REST service restart (a reboot, a
  Veeam update) ends every session. Starting one again needs an interactive browser sign-in:
  - security defaults block the documented device-code flow (AADSTS530035);
  - the Restore Portal app must be multi-tenant (Veeam's on-behalf-of call uses `/common`);
  - each operator explore session stops after one restore.
- **Admin mode passed every check.** It restored mail, SharePoint and OneDrive into the three
  targets, and it can sign in again without a person.

**Alternatives rejected.**

- *Operator mode for SharePoint only:* two modes to build and support, for one of three item
  types.
- *Restoring into the original mailbox or OneDrive in a marked folder:* breaks the restore
  target rule (2026-09-22, 2026-09-25) and puts test copies in production mailboxes.
- *User credentials in the restore body:* need an account without MFA, which no MSP should
  have.
- *Device codes (`userCode`):* blocked by security defaults, and interactive.
- *The PowerShell module now:* admin mode works, and a second connector isn't needed yet.

**Open.**

- **Which Entra app's certificate the Worker holds** (L1.5, W2.4, W4.5). The lab used Veeam's
  own backup app, which has broad application permissions. A dedicated restore app with
  narrower permissions (Exchange application RBAC scoped to `restoretest`, SharePoint
  `Sites.Selected`) is to be tested before the Worker stores any certificate. Either way the
  PFX and its password are vault secrets, and `worker/include/rp/secrets.hpp` changes with W1.5.
  *(W2.4, 2026-09-28: the lab restores used Veeam's organisation app, its certificate exported
  per run, the PFX never stored. Which certificate the Worker holds stays open until a spike before
  W4.5; see the 2026-09-28 W2.4 entry.)*
- **TLS** (W1.5): Veeam's default REST certificate has no SAN, so no host name verifies and
  `veeam_ca_file` alone can't reach a default install. The options are to require a
  certificate with the server's DNS name (`Set-VBORestAPISettings`) or to add a pinned-leaf
  option. Verification stays on either way.
- **The operator refresh-token lifetime** (48 h and 7 days) is still being measured, due
  2026-09-28 and 2026-10-03. It is recorded for completeness and does not change this decision.

---

## 2026-09-25 — Restored files go to `RestoreTarget`, not to the `RestoreTest` library/folder that holds the canaries

**Decision.** Supersedes the file part of "Restores only ever target `restoretest` /
`RestoreTest`" (2026-09-22). SharePoint items are restored into a new library
**`RestoreTarget`** in the RestoreTest site, and OneDrive items into a new folder
**`/RestoreTarget`** in alice's OneDrive (IDs in `lab/tenant.md`). The `restoretest` mailbox
stays the mail target. The canary files stay where L1.2 seeded them: `rp-canary-01…10` in
the `RestoreTest` library, `11…20` in alice's `/RestoreTest`. Both new targets were created
on 2026-09-25, before any restore. The rest of the 2026-09-22 rule (one guarded code path,
checked per item, a violation is `error`) is unchanged.

**Reason.** The guide uses the RestoreTest library and alice's RestoreTest folder both as
L1.2's canary source and as the restore target. With one place for both:
- a restore of `rp-canary-01.pdf` lands on top of the original, which Veeam overwrites,
  skips or renames, and L1.4's "delete the restored items" can then delete the canary;
- the checker (W3.2) finds the original by name, so a restore that wrote nothing still passes:
  the false pass the product exists to prevent;
- the Cleaner (W3.4) empties the target after every run, and so would delete the canaries.

The mail side never had the problem: the canaries are in alice's and bob's mailboxes, the
target is `restoretest`.

**Alternatives rejected.** A `Restored` subfolder inside the current library and folder: less
setup, but the Cleaner would then have to spare the parent, and one scoping bug deletes the
canaries. Moving the canaries and keeping `RestoreTest` as the target: a new seed run, a new
manifest and a new Veeam backup for the same result. A target in `restoretest`'s own
OneDrive: not provisioned, and it would add a second user's drive to Graph permissions (L1.5).

**Consequences.** `TargetGuard` (W2.7) checks against `RestoreTarget`'s IDs, and the random
sample (W2.6) must exclude both `RestoreTarget` and the canary locations it already
handles. Both are in the same site and drive as before, so `Sites.Selected` on the
RestoreTest site (L1.5) still covers the SharePoint target. Veeam's backup job covers all
sites and OneDrives, so it will also back up whatever is left in `RestoreTarget`. The
Cleaner keeps it empty.

---

## 2026-09-25 — Veeam Backup for Microsoft 365 runs directly on the dev laptop, not in a VM

**Decision.** Supersedes "The Veeam lab VM runs on the dev laptop, with reduced resources"
(2026-09-22). L1.3 installs Veeam Backup for Microsoft 365 v8 (Community Edition) on the
laptop's own Windows 10 Pro 22H2, with no Hyper-V VM. The Worker will reach its REST API on
the same machine (port 4443). A spare PC or a cloud VM stays the fallback, now also for when
a separate host is needed to test the Worker across a network and a certificate name.

**Reason.** Veeam's v8 system requirements (8.6) list Windows 10 21H2/22H2 as a supported
backup server OS and ask for at least 8 cores and 16 GB RAM. The laptop has 2 cores / 4
threads and 16 GB, so the planned 2 vCPU / 6 GB VM would give Veeam well under half its
minimum, plus the overhead of a second Windows. On the host it gets the whole machine, and
L1.3 skips installing and updating Windows Server. The 2026-09-22 entry rejected a host
install because it mixes the product under test with the dev toolchain and doesn't resemble
an MSP's server. Both still hold, but a starved VM is the bigger risk for the Sprint 1
feasibility work. An MSP may also run the Worker on its Veeam server, so a local REST API is
not unrealistic.

**Alternatives rejected.** The 6 GB VM as planned: far below Veeam's minimum, with no gain
beyond isolation. A bigger VM: the laptop has no RAM or cores to spare. A cloud VM now: a
monthly cost and firewall rules before we know the laptop is too slow; kept as the fallback.

**Costs we accept.** Veeam's services and their database run on the dev laptop and start
with Windows. There are no checkpoints to roll back to. The Cloud's local Postgres (Docker,
later) must not clash with a database port Veeam uses. Check the ports when C-work starts.

---

## 2026-09-25 — Office files are compared by content (`office-v1`); the Worker compares `content_sha256`

**Decision.** Supersedes the file-hash part of the 2026-09-24 canary seeder entry below. Every
file entry in `lab/seed-manifest.json` gets a `content_rule` and a `content_sha256`, and the
Worker compares a restored file with `content_sha256` by that rule:

- `bytes` (pdf, txt, png): SHA-256 of the whole file; equal to `stored_sha256`.
- `office-v1` (docx, xlsx, wherever stored): SHA-256 of a listing of the document's content
  parts: every part under `word/` or `xl/` except `_rels/` folders, sorted by name, one line
  per part with its SHA-256 and name. Metadata, `customXml/`, `[trash]/`, content types and
  relationship files don't count. Rule and vectors: `lab/README.md`, `lab/seeder/office.py`,
  `shared/testdata/office-content-v1/` (including real files SharePoint rewrote), which
  W3.2's C++ checker must pass.

`seed` stops, writing no manifest, if the stored document content of an Office file differs
from `lab/canary/`; `hash` checks offline that the committed file reproduces its
`content_sha256`. The type mix stays as it was (option 1 of the two the owner was offered),
so SharePoint Office restores stay under test.

**Reason.** The live run (2026-09-24/25, findings in `lab/README.md`) showed the SharePoint
`RestoreTest` library rewriting every docx and xlsx on upload (3263 → 12617 bytes) and again
some minutes later (+3073 bytes), with `lastModifiedDateTime` unchanged. The first `verify`
therefore reported 4 DIFFs on files nobody had touched. No whole-file hash of an Office file
in a SharePoint library is a stable expected value, and a restore there would be rewritten
too: comparing bytes would report a good restore as `fail`. Part-by-part comparison showed
that SharePoint changes only packaging and metadata; the content parts stayed byte-identical.
OneDrive stored all its files unchanged, and pdf/txt/png were unchanged everywhere. The rule
applies by type, not location, because a Veeam restore may rewrite an Office file wherever it
lands.

**Alternatives rejected.** Keeping `stored_sha256` as the expected value: it was already wrong
minutes after the seed. Dropping Office files from SharePoint (option 2): simpler hashes, but
the most common customer files in a library would go untested. Comparing only size for Office
files: SharePoint changes the size too, and size misses real changes. Parsing the XML and
comparing text: more code on both sides, and a byte comparison of the untouched parts is
already exact. Hashing every part except a known list of SharePoint parts: breaks as soon as
SharePoint adds a new kind of part.

---

## 2026-09-24 — Lab CI: canary files checked offline, the manifest hash check only once it is committed

**Decision.** The `lab` workflow gets two checks after the tests, replacing the single
`python -m seeder hash` step of the canary seeder entry below:

- **Canary files match the generators.** `python -m seeder generate` writes into a temp dir,
  and `diff -r` compares it with the committed `lab/canary/`. It fails on a changed, missing
  or extra file, and needs no manifest.
- **Canary hashes reproduce the manifest.** If `lab/seed-manifest.json` is committed,
  `python -m seeder hash` runs and must pass, as before. If it is not, the step emits a
  GitHub `::warning::` saying the check was skipped and that L1.2's Done when is not met until
  a live `seed` run's manifest is committed, and succeeds.

**Reason.** The manifest is written only by a live `seed` run, which needs three interactive
tenant sign-ins and cannot run in CI. Until that run happens the hash step could only fail,
so the lab job was always red and hid real test failures. The generator check covers the part
that needs no tenant. Once the manifest is committed the hash check is a hard gate with no
change to the workflow. The catch: a PR that deletes `lab/seed-manifest.json` silently turns
it back into a warning, so a reviewer must treat deleting the manifest as a red flag.

**Alternatives rejected.** Leaving the job red until the live run: a permanently red job
trains everyone to ignore it. `continue-on-error` on the hash step: it would also hide a real
mismatch once the manifest exists. A placeholder manifest: it would be a fake expected set,
and `hash` would still have to fail on it. Failing when the manifest is missing only on
`main`: the same always-red problem, one merge later.

---

## 2026-09-24 — Canary seeder: a uv lab tool, a delegated public-client app, text-v1 mail hashes, hashes of what Graph returns

**Decision.** L1.2 (#10) seeds the 40 canary items and writes `lab/seed-manifest.json`. How
to use it: `lab/README.md`.

- **Tool layout.** `lab/` is its own uv project (Python 3.12, `uv.lock` committed) with a
  `seeder` package run as `python -m seeder generate|hash|seed|verify` and a pytest suite in
  `lab/tests/`. The tests run against a fake in-memory Graph tenant, never the network. A new
  CI workflow, `lab` (`.github/workflows/lab.yml`), runs the tests and `python -m seeder hash`.
- **Its own app registration.** The seeder signs in through "RestoreProof Lab Seeder", a
  single-tenant public client (redirect URI `http://localhost`, public client flows allowed)
  with delegated Microsoft Graph permissions only: `Mail.Send`, `Mail.Read`, `Files.ReadWrite`,
  `Sites.ReadWrite.All` and `User.Read`, admin-consented. It has no client secret or
  certificate. MSAL's token cache stays in memory, so no token is written to disk.
- **Three sign-ins.** Delegated Graph reaches only the signed-in user's own mailbox and
  OneDrive: a global admin gets 403 on alice's OneDrive. So a run signs in as alice (her
  mailbox, her OneDrive files), bob (his mailbox) and the admin (sends all 20 mails, uploads
  the SharePoint files), and re-uses alice's and bob's cached tokens to read the mails back.
  After each sign-in the tool checks the signed-in account and stops if it is the wrong one.
- **Hashes are of what Graph returns.** Each file is downloaded back after upload, and each
  mail is read back from the recipient's mailbox. A file entry records both `local_sha256`
  (the committed file) and `stored_sha256` (the bytes Graph returns), plus
  `stored_matches_local`; the Worker compares a restored file with `stored_sha256`. A mail
  entry records `body_sha256` (the read-back body) and `sent_body_sha256` (the sent body);
  the Worker compares with `body_sha256`.
- **Mail body rule `text-v1`.** Bodies are read with `Prefer: outlook.body-content-type="text"`
  and normalised before hashing: drop one leading U+FEFF; CRLF, then lone CR, to LF; strip
  trailing spaces and tabs from each line; strip trailing LFs; UTF-8; SHA-256. Nothing else is
  changed. The rule is named in each entry (`body_normalization`), and a change gets a new name,
  never an edit to `text-v1`. `shared/testdata/body-normalization-text-v1.json` holds test
  vectors that the Python tests use now and W3.2's C++ checker must also pass. The manifest's
  schema is `shared/schemas/seed-manifest.v1.json`.
- **Mail recipients.** `RP-CANARY-0001`–`0010` go to alice, `0011`–`0020` to bob, all sent by
  the admin. W1.0 restores `RP-CANARY-0001` from alice.
- **File types.** The type cycles by number: pdf, docx, xlsx, txt, png (01 pdf … 20 png), so
  each location gets two of each. 01–10 go to the SharePoint `RestoreTest` library root,
  11–20 to alice's OneDrive `RestoreTest` folder. The guide's `rp-canary-20.docx` was an
  illustration; W1.0 needs `rp-canary-01.pdf` in the library, which the cycle gives.
- **Deterministic files.** The generators use the standard library only and no compression
  (ZIP entries stored, PNG pixel data in stored deflate blocks), with fixed dates and metadata.
  A test generates twice and compares with the committed `lab/canary/`, and `.gitattributes`
  marks `lab/canary/**` binary.

Live-run result: SharePoint rewrites Office files, twice, so files are now compared by
`content_sha256` under a `content_rule`, superseding the `stored_sha256` comparison above. See
the 2026-09-25 entry.

**Reason.** The Worker only ever sees an item through Graph, so the expected value has to be
what Graph returns. SharePoint can rewrite Office files on upload (it writes library
properties into them), and a hash of the local file would then report every restore of that file as
a mismatch, a false `fail`. Recording both hashes shows whether that happened. Mail bodies
can pick up line-ending and trailing-whitespace changes on the way through Exchange; the rule
removes exactly those differences and nothing that could hide a real change of content. It
has to be written down precisely because a second implementation, in C++, must give the same
hash. The seeder has several modules (catalog, generators, Graph client, sign-in, manifest)
and its own tests, which a uv project holds naturally. A dedicated app is needed because the
Worker's app (L1.5) doesn't exist yet and will be app-only and read-only, while seeding needs
to send mail and write files. Stdlib-only generators without compression keep the committed
bytes, and therefore the manifest, reproducible regardless of library or zlib versions.

**Alternatives rejected.** A single PEP 723 script: fine for one file, awkward for eight
modules and a test suite. Putting the seeder in `cloud/`: it is lab tooling, not product
code, and would bring its dependencies and coverage rules into the Cloud build. Using the
Worker's app registration with application permissions: it doesn't exist yet, and giving it
`Mail.Send` and write access to files to seed a lab would break its read-only scope. Making
the admin a site collection admin of alice's OneDrive so one sign-in is enough: it changes
tenant permissions to save two sign-ins. Hashing the raw body: a CRLF or trailing-space change
by Exchange would read as a mismatch. Hashing the HTML body: Exchange rewrites HTML freely.
Office and image libraries to write the files: their output changes between versions. Hashing
only the local file: see the reason above.

---

## 2026-09-24 — Worker HTTP client: one fakeable interface, five attempts, redacted logs, TLS always verified

**Decision.** W1.3 (#18) adds the HTTP layer every Worker connector will use.

- **Interface and fake split.** `rp::IHttpClient` (`worker/include/rp/http_client.hpp`) has
  exactly one virtual, `send(const HttpRequest&)`. `get`, `post`, `post_multipart` and `del`
  are non-virtual shorthands that build an `HttpRequest` and call `send`. `rp::HttpClient` is
  the cpr/libcurl implementation. `VeeamClient` (W1.5), `GraphClient` (W2.1) and the Cloud
  uploader take an `IHttpClient&`. Q2.1's `FakeHttpClient` and its `--record` wrapper
  implement or wrap `send` only. No cpr type appears in the header: cpr stays private to rpcore.
- **Five attempts in total.** The guide's steps say "up to 5 attempts"; its Done when says
  "retries five times". We read both as **5 attempts: 1 initial + 4 retries**
  (`rp::kMaxHttpAttempts`). The waits are 1, 2, 4 and 8 s. `rp::retry_delay` caps a wait at
  16 s, but with 5 attempts a request never reaches the cap. The Done-when test asserts
  exactly 5 attempts.
- **What is retried.** Connect errors (resolve, connect, send/receive, empty reply),
  timeouts and TLS handshakes that break off (`TransportError::handshake`) are retried, and
  so is HTTP 500-599. Nothing else is: no 4xx (408 and 429 included), no certificate
  failure, no malformed URL. curl's Schannel backend reports a connection dropped
  mid-handshake as `SSL_CONNECT_ERROR`, the same code it uses for a protocol or cipher the
  two sides can't agree on. Certificate verdicts have codes of their own
  (`PEER_FAILED_VERIFICATION`, `SSL_CACERT_BADFILE`, ...) and stay `tls`, not retried. So
  a restarting Veeam REST service is retried over HTTPS as it is over HTTP, and a lasting
  negotiation failure takes five attempts to report. A 2xx, 3xx or 4xx is returned to the caller.
  An `rp::HttpError` is thrown when the attempts run out, and immediately for a failure that
  isn't retried. The policy is a pure unit (`rp/retry_policy.hpp`). The worst case for one
  call is 5 × its timeout + about 15 s of waiting, about 165 s at the 30 s default.
  `GraphClient` handles Graph's 429/`Retry-After` throttling itself.
- **Jitter** only shortens a wait, by up to 25%, so no wait exceeds its nominal value or the
  16 s cap. `retry_delay` works in whole milliseconds: `nominal - round(nominal * 0.25 *
  jitter)`, with jitter clamped to [0, 1] and NaN counting as 0. The client takes the sleeper,
  the jitter source and the clock as `HttpClientOptions`, so tests never sleep.
- **Only `http://` and `https://` URLs are sent** (scheme in any case). curl here is built
  with FILE, FTP, SMB, LDAP and more, and guesses a scheme for a URL without one. Any other
  URL throws `HttpError` (`other`, 0 attempts) before anything is sent. The check matters
  because URLs from server responses (Graph `nextLink`, the download `Location`, Veeam
  `_links`) will reach `send()`. A review showed a `file:///` URL returning the file's bytes
  as a status-0 response.
- **No method falls through to DELETE.** `perform()` and `to_string()` have a case for each
  `HttpMethod` and no `default`. An out-of-range value throws `std::invalid_argument` before
  anything is sent. rpcore builds with `/we4062`, so a new method without its case is a
  compile error. Before this, anything other than GET or POST (a future PATCH included) was
  sent as DELETE. The same goes for `config.cpp`'s `StringRule`: its check and its error
  message were two switches whose `default` gave the log-level message, and they are now one
  exhaustive switch. The two switches left with a `default` are over curl's error codes in
  `http_client.cpp`, where naming each of about 100 codes would add nothing.
- **Redirects are never followed.** A 3xx is returned, so an `Authorization` header or a
  token body can't be sent to another host. The Graph download 302 will be followed
  explicitly by `GraphClient`, without the header.
- **Timeout.** A per-request timeout covers the whole attempt, and each retry gets it again.
  It defaults to 30 s (`kDefaultHttpTimeout`); a long poll raises it with
  `RequestOptions::timeout`.
- **Logging.** One debug line per attempt: method, URL, `attempt n/5`, then the status or
  the error kind with curl's message, the duration, and the wait before the next attempt.
  Nothing is logged above debug, and request/response headers and bodies are never logged.
  Every logged string, and every `HttpError::what()`, goes through `rp::redact()`.
- **Redaction** (`rp/redact.hpp`) is one pure function, a hand-written linear scan (no
  `std::regex`). The exact rules are in the header comment. It redacts:
  - the value of an `Authorization` or `Proxy-Authorization` header, whatever the scheme, up
    to `\r\n`, `\n` or the end of the text;
  - `client_secret`, `password`, `refresh_token`, `access_token`, `authorization`,
    `tempauth` (Graph's pre-authenticated download URLs), `sig` (Azure SAS),
    `client_assertion` and `id_token` as `key=value` (query strings, fragments, form bodies)
    and as JSON keys at any nesting depth;
  - the first four also in the form `name: value`;
  - a quoted value up to its matching quote;
  - URL userinfo (`https://user:password@host`).

  Only an odd run of backslashes before a quote escapes it; an even run is escaped
  backslashes before a real quote (a review found `{\\"password\\":\\"x\\"}` leaking).

  Names match in any case. It over-redacts on purpose:
  - a key that ends in a name after a non-alphanumeric character counts (`new_password`,
    `db.password`);
  - a JSON value of any type becomes `"[REDACTED]"`;
  - an unterminated value is redacted to the end of the text.

  `code` is not on the list: Graph's error JSON (`"code":"ErrorItemNotFound"`) must stay
  readable. It does not recognise URL-encoded key names (`client%5Fsecret`), hyphenated
  spellings (`client-secret`), JSON keys written with `\u` escapes, or Python-style
  single-quoted keys. The HTTP client never logs bodies or headers, and the W4.9 sentinel
  audit is the backstop for the rest.
- **TLS.** Peer and host verification are set on for every request, and nothing can turn
  them off: no option, no config key, no revocation opt-out. With `veeam_ca_file`, curl
  checks every certificate in the chain for revocation, and a strict check fails on "the
  revocation status is unknown" for an internal CA that publishes no CRL, or one the Worker
  can't reach. So with a CA file (only then) the check is **best effort**
  (`CURLSSLOPT_REVOKE_BEST_EFFORT`): a certificate on its CA's CRL is still rejected, an
  unknown or offline status is let through. cpr 1.14 has no setting for it, so it is one
  `curl_easy_setopt` call after `SetSslOptions`; the source scan allows that exact
  statement, and only in `src/http_client.cpp`. A TLS test serves a CRL from 127.0.0.1 and
  shows a leaf from a private CA accepted with no CDP, an unreachable CDP, or a CRL that
  doesn't list it, and rejected when the CRL lists it. The optional config key
  `veeam_ca_file` names a PEM file trusted for `veeam_url` only. It is an absolute local or
  UNC path; `load_config` checks the file can be read. The path goes to curl as raw UTF-8
  bytes. `cpr::ssl::CaInfo` would convert it to the ANSI code page. With Schannel, curl builds
  the chain against that file alone (its exclusive-root engine), so the file **replaces** the
  Windows store. An HTTPS test against a certificate generated at run time shows four things:
  the server is trusted through a CA file at a Cyrillic path; it is rejected without one; it
  is rejected with a different CA; and a missing file is a TLS failure. Graph and the Cloud
  never set it. Two tests guard this: one checks the `cpr::SslOptions` the client builds, and a
  source scan over `worker/src`, `worker/include` and `worker/app` fails on any TLS switch
  name (`VerifySsl`, `CURLOPT_SSL_*`, `CURLSSLOPT_*`, `curl_easy_setopt`, `verify_status`,
  ...) and on any `verify_peer`/`verify_host` not set to exactly `true`. `verify_status`
  (OCSP stapling) stays off because a self-signed Veeam server doesn't staple. The scan is a
  tripwire, not a proof: review still applies. The known config keys are now 17. `veeam_ca_file` is checked after
  `log_level`, and its readability after the whole parse. It is left out of
  `config.example.json` because it has to name a real file.
- **Test server: cpp-httplib**, with the `openssl` feature and without brotli, linked only to
  `rptests` (`worker/tests/local_http_server.hpp`). The tests serve HTTP and HTTPS on
  127.0.0.1 with an ephemeral port, and generate their certificate with OpenSSL at run time,
  so they need no network and commit no private key.

**Reason.** One virtual function is the smallest seam a fake and a recorder can implement,
and it keeps every connector's tests on fixtures (CLAUDE.md). Taking the Done when's
"retries five times" as five retries would make six attempts and about 31 s of waiting.
Five attempts keep a dead Veeam server's wait to about 15 s, and they are what the guide's
steps say. A 4xx won't change on retry, and TLS failures and bad URLs are configuration
errors; retrying them only delays the `error` status. A redirect that carries credentials to
another host is how bearer tokens leak. Redacting the text itself, rather than trusting
callers to leave secrets out, means a secret that gets into a URL or an error message is
still caught. The redaction errs towards removing too much, because a log that says too
little costs a rerun and a leaked secret can't be taken back. Veeam ships with a self-signed
certificate, so an MSP must be able to trust it without turning verification off.
cpp-httplib is one header, runs in-process, and can serve TLS for the tests.

**Alternatives rejected.** Four virtual methods on the interface: every fake would implement
four. Telling a dropped handshake from a failed negotiation by curl's message text: it
changes between curl versions. `ssl_no_revoke` for a CA file: it would also accept a
certificate the CA has revoked. Best-effort revocation for Graph, the TSA and the Cloud
too: their public CAs publish reachable CRLs, so nothing needs relaxing there. Patching cpr
in a vcpkg overlay to add the option: a fork to maintain for one flag. Six attempts: see above. Retrying 429 honouring `Retry-After`: neither Veeam nor Graph
throttling has been seen yet, so it waits for evidence. Following redirects and relying on
curl to drop `Authorization` on a cross-host hop: the rule would live in curl's defaults,
not in our code. `std::regex` for redaction: slow, and MSVC's implementation recurses deeply
on long input. A `verify_tls: false` escape hatch: one support call away from being set
everywhere. Adding the CA to the Windows store on the MSP's server: it changes machine-wide
trust for one Worker connection. A mock HTTP library or a Python test server: the first
wouldn't exercise cpr and curl, and the second needs a runtime in CI and a process to manage.

**Open.** POSTs are retried on 5xx and timeouts like any other request. A "start restore" or
bundle-upload POST that timed out after the server accepted it could run twice. Before
`VeeamClient` starts restores (W2.x) or the uploader lands, add a per-request opt-out or
idempotency keys. Until then, a timeout, dropped connection or 5xx after the server
accepted a POST can repeat it. A code review reproduced this with a server that read the
POST and closed the connection without answering: the POST arrived five times. curl also
honours the `HTTP(S)_PROXY` environment variables, which is untested on MSP servers. The
`HttpError` for a final 5xx carries the status but not the response body, so `VeeamClient`
may want the body kept (never logged) to say why.

---

## 2026-09-24 — Worker config: strict `config.json`, secrets from environment variables until the vault

**Decision.** W1.2 loads the Worker's settings from `config.json` (default
`%ProgramData%\RestoreProof\config.json`) through `rp::load_config`, and checks them with
`rpworker config check`. Keys and rules are in [worker-config.md](worker-config.md).

- Secrets never go in `config.json`. Until the DPAPI vault arrives in W4.5 (#48), they come
  from `RP_VEEAM_USERNAME`, `RP_VEEAM_PASSWORD` and `RP_GRAPH_CLIENT_SECRET`, whose names are
  defined once in `worker/include/rp/secrets.hpp`. *(W2.1 replaced `RP_GRAPH_CLIENT_SECRET`
  with `RP_GRAPH_CERT_PFX_BASE64` and `RP_GRAPH_CERT_PASSWORD`, and added `pfx` and
  `passphrase` to the markers below: see the 2026-09-28 entry.)* An unset one is not an error, because
  which ones a run needs depends on the Veeam auth mode W1.0 picks.
- A top-level key whose lowercased name contains `password`, `passwd`, `pwd`, `secret`,
  `token`, `api_key`, `apikey`, `credential`, `private_key`, `access_key`, `signing_key` or
  `connection_string` is rejected, before any other key check.
- A key name from the file is echoed only if it is 1-64 of `[A-Za-z0-9_.-]`; otherwise the
  message describes the key without naming it.
- `cloud_url` and `veeam_url` must be printable ASCII and reject userinfo (`@` before the
  path), queries and fragments; every string setting rejects control characters: ASCII, C1,
  U+2028/U+2029 and bidi controls.
- `test_mailbox` must be `restoretest@<domain>` (local part in any case; the domain two or
  more `.`-separated labels of ASCII letters, digits and `-`). Only the domain comes from
  configuration, which applies the 2026-09-22 rule "Restores only ever target `restoretest` /
  `RestoreTest`" at load time. `TargetGuard` still checks every item. The SharePoint and
  OneDrive targets are opaque Graph IDs whose names the loader can't see, so `TargetGuard`
  must resolve them and check they are the `RestoreTest` library or folder.
- The environment and the command line are read as UTF-16 (`GetEnvironmentVariableW`,
  `wmain`) and converted to UTF-8 exactly. Text that isn't valid UTF-16 is an error, never
  replaced.
- Unknown keys are rejected (exact, case-sensitive match against the 16 known keys).
- Validation stops at the first error, in a fixed order: unreadable file, invalid JSON, root
  not an object, secret-looking key, unknown key, each field in declaration order, all sample
  sizes 0.
- Error messages name the key and never echo a value. A JSON parse error reports only the
  byte offset, because nlohmann's message quotes the last token it read; a number out of the
  parser's range (`1e400`) is reported without the number, for the same reason.
- `poll_interval_s` and `heartbeat_interval_s` are bounded 1..86400; `sample_mail`,
  `sample_sp` and `sample_od` 0..100, with at least one above 0.
- No CLI library yet: `run_cli` parses `--version` and `config check [--config <path>]` by
  hand. W1.6 (#21) decides between CLI11 and hand-rolled parsing once there are more
  subcommands.
- `%ProgramData%` is resolved with `SHGetKnownFolderPath(FOLDERID_ProgramData)`, not the
  environment variable.

**Reason.** A misspelt optional key would silently fall back to its default, and a secret
pasted into `config.json` would sit in a plain file that gets copied into tickets; rejecting
both turns a quiet mistake into a named error. Stopping at the first error is simpler,
deterministic and easy to test one rule at a time; the user fixes one thing and reruns
`config check`, and a config has few enough keys that this costs little. The bounds catch
values that are clearly wrong (0 seconds, a thousand items per run) without guessing at
tuning, and a run that restores nothing must not be able to report `pass`. Environment
variables are the least code that keeps secrets out of the file until the vault exists.
The `%ProgramData%` variable can be changed by whoever starts the process; the known-folder
API returns the machine's real location. `config check` prints the URLs and the error
messages name keys, so anything the file controls that reaches the terminal is limited to
what can't be a secret or forge output: a password in a URL's userinfo or a token in its
query would be printed, a key name can be a 200 KB string, and a control character in a
value or key can fake or hide lines. The key-name rule limits length and characters only: a
pasted token that is itself a short identifier-like key is still echoed as an unknown key.
A mailbox address that merely looked like an email let a typo or a look-alike name a live
mailbox as the restore target. The CRT's narrow environment and `argv` are in the ANSI code
page, so a password or path with a character outside it was silently changed.

**Alternatives rejected.** Collecting every error in one pass: more code and more test
combinations, and later errors are often caused by the first. Ignoring unknown keys: typos
go unnoticed. Secrets in `config.json` protected by file ACLs: one careless copy of the file
leaks them, and W4.5 replaces the mechanism anyway. Reading `%ProgramData%` from the
environment variable: a process can override it. Accepting any address for `test_mailbox`
and leaving it all to `TargetGuard`: a mistake would only surface mid-run, as `error` on
every test. An `activeCodePage` UTF-8 manifest instead of the wide APIs: older Windows
Server releases ignore it, and `rptests.exe` would need the same manifest for the tests to
mean anything. Pulling in CLI11 now: a dependency for two
commands, before W1.6 has looked at what the rest of the CLI needs.

---

## 2026-09-24 — `rpworker`'s command line lives in rpcore; `worker/app/` is guarded and measured

**Decision.** Supersedes the part of the 2026-09-22 entry "Every rpcore `.cpp` must reach the
coverage report; `main()` lives outside `src/`" that left `main()` untested. Argument parsing,
output and exit codes live in `rp::run_cli(args, out, err)` in rpcore and are tested in
`rptests`; `worker/app/main.cpp` only turns argv into a list and calls it. `worker/app/` is
also Worker source for the "No test, no merge" guard and for the coverage gate, which measures
it through ctest's runs of `rpworker.exe` (OpenCppCoverage `--cover_children`). Those runs go
through `worker/tests/run_exe_test.cmake`, which checks the exit code, stdout and stderr
exactly.

**Reason.** A code review of W1.1 found that `main()` held the parsing, sat outside both the
guard and coverage, and was tested only by ctest properties that ignore the exit code
(`PASS_REGULAR_EXPRESSION`) or accept any non-zero one, a crash included (`WILL_FAIL`). The
next subcommands (`veeam list`, `restore`, `test`, `doctor`) would have landed in that
untested file. With the logic in rpcore, `main()` is four lines that one exe test runs in
full, so measuring it costs nothing and catches it if it grows.

**Alternatives rejected.** Keeping `app/` out of coverage and relying on review to keep
`main()` thin: the guard would still let a PR change it with no test. Linking `main()` into a
test executable: two `main`s in one binary, or preprocessor tricks to rename one. A future
Windows service entry point that tests can't run will get its own entry if it has to be
excluded.

---

## 2026-09-23 — `main` is not branch-protected; merging only on green is a manual rule

**Decision.** L0.1's "Protect main: require CI green before merge" is replaced by a manual
rule: a PR is merged only by the repo owner, and only when every check on it is green (worker,
cloud and the "No test, no merge" guard). The CI gates in `docs/testing.md` still run on every
PR; they turn the PR red but cannot block the merge button.

**Reason.** Branch protection and rulesets are not available on a free private repository
(the API returns 403, "Upgrade to GitHub Pro or make this repository public"). With one
developer who reviews and merges every PR, a manual rule costs nothing and keeps the code
private.

**Alternatives rejected.** GitHub Pro: enforces the checks, but is a monthly cost for a guard
that only protects the developer from themselves. Making the repository public: exposes the
code before there is a product. Revisit when a second person gets write access or the repo
moves to an organisation (L0.1), at which point required checks become worth paying for.

---

## 2026-09-23 — Test tenant on `onmicrosoft.com` with 4 licences; domain deferred to C5.12

**Decision.** The L0.3 test tenant is `RestoreProofLab.onmicrosoft.com`, on its default
domain, and needs **4 licences** instead of the guide's 3. No domain is bought in Sprint 0. It
is bought before C5.12 (Sprint 5), which needs `api.<domain>` and `app.<domain>`, and C7.1
(Sprint 7) then uses it as the verified alert sender. The tenant must stay licensed for all
16 weeks.

**What was actually bought (2026-09-23).** The sign-up gave a **Microsoft 365 Business
Standard EEA (no Teams)** trial on an annual term, not the Business Basic trial the guide
names. The trial has 25 licences and **ends on 2026-10-23, in Sprint 2**. It then converts to
paid with only **1** licence. Before that date the renewal must be changed to 4 licences,
preferably on monthly billing. Whether to stay on Standard or move to Business Basic ×4 is
still open; this entry gets a follow-up once it is decided. Business Basic covers everything
the lab uses (Exchange mailboxes, SharePoint, OneDrive). The global admin has a personal-name
UPN rather than `admin@`; it is the fourth licensed user L1.1 calls "admin".

**Reason.** The Worker, Veeam and Graph work the same on an `onmicrosoft.com` domain, so
Sprints 1–4 don't need a custom domain. Only the Cloud deployment and email alerts do, and the
week-4 go/no-go (S2.1) could make both unnecessary. The guide contradicts itself on licences:
L0.3 says 3 users, but L1.1 needs four licensed mailboxes (admin, alice, bob, `restoretest`,
the mail restore target). `rpoperator` (W1.0) needs no licence. The tenant must outlive the
30-day trial because Veeam backs it up, `lab/seed-manifest.json` describes its data and the
recorded fixtures point at it. If it expires, or converts with 1 licence, alice, bob and
`restoretest` lose their mailboxes and the tenant is later disabled and deleted.

**Alternatives rejected.** Buying the domain now and adding it to the tenant: costs money
before the go/no-go, and a custom domain can be added to the tenant later without changing the
`onmicrosoft.com` addresses the fixtures use. It is only worth buying early if the name itself
matters and might be taken. A tenant from the Microsoft 365 Developer Program: its E5 sandbox
is now limited to qualifying subscribers, and it can be removed at any time. Letting the trial
lapse and creating a fresh tenant each month: every tenant ID, site ID and fixture would change.

---

## 2026-09-22 — Every rpcore `.cpp` must reach the coverage report; `main()` lives outside `src/`

**Decision.** `worker/tools/coverage_gate.py` lists the `.cpp` files under `worker/src/` and
`worker/include/` on disk and fails when one is missing from the OpenCppCoverage report.
`rpworker`'s entry point (`main()`) will live outside `src/` (e.g. `worker/app/main.cpp`) and
stay a thin call into `rpcore`.

**Reason.** OpenCppCoverage only sees code linked into `rptests.exe`. `rpcore` is a static
library, so the linker drops any object no test references, and an untested file would never
appear in the report: it would count neither against the 80% floor nor, for vault, signer or
target_guard, against the 100% floor. Listing files from disk is what the Cloud gate
(`cloud/tools/check_coverage.py`) already does. `main()` can't be linked into a test
executable, so it has to sit outside the checked folders.

**Alternatives rejected.** Linking `rpcore` with `/WHOLEARCHIVE` into `rptests` — keeps every
object, but the report would then show untested files at 0% and the gate would still need the
disk list to tell a file with no executable lines from a missing one. An allowlist of files
exempt from the check — easy to grow quietly.

---

## 2026-09-22 — Worker coverage via OpenCppCoverage; branch coverage deferred

**Decision.** The Worker's coverage is measured with OpenCppCoverage 0.9.9.0 on an unoptimised
Debug build (`coverage` preset), and `worker/tools/coverage_gate.py` enforces 80% line coverage
on `rpcore`. CLAUDE.md asks for 100% *branch* coverage on vault, signer and target_guard;
OpenCppCoverage measures lines only, so for now those files are held to 100% *line* coverage
instead. This is a known gap, not the target.

**Reason.** OpenCppCoverage works with the MSVC toolchain we already build with, needs only
PDBs, is free, and installs on the GitHub Windows runner in seconds. It is enough for L0.5's
"coverage numbers appear in the workflow summary". None of the three strict files exists
yet, so the missing branch data costs nothing today.

**Alternatives rejected.** clang-cl with `-fprofile-instr-generate -fcoverage-mapping` and
llvm-cov — gives branch coverage, but means a second compiler, a separate vcpkg triplet and
build, and possible MSVC/clang behaviour differences in the code we ship. Microsoft.CodeCoverage
(`vstest` / `dotnet-coverage` for native code) — needs Visual Studio Enterprise, which we do
not have.

**Revisit** before vault, signer or target_guard land, i.e. in the W sprint that creates the
first of them: either adopt a branch-capable tool for those files or record here why 100%
line coverage plus the manual mutation pass (`docs/testing.md`) is accepted.

---

## 2026-09-22 — The Veeam lab VM runs on the dev laptop, with reduced resources

**Decision.** Veeam Backup for Microsoft 365 runs in a local Hyper-V VM on the dev laptop, as
the plan says, but sized **2 vCPU and 6 GB RAM** with a dynamically expanding disk instead of
the plan's 4 vCPU, 8 GB and 100 GB. The VM and a C++ build do not run at the same time. If
W1.0 or the Sprint 3 end-to-end runs prove it too slow, the host moves to a spare PC or a
cloud VM, recorded here in a follow-up entry.

**Reason.** The laptop has 2 cores / 4 threads and 16 GB RAM shared with Visual Studio and
Docker, so the plan's sizing would leave nothing for the host. Reduced sizing is enough for a
4-user test tenant, costs nothing, has no cloud credit clock, and keeps the Worker and Veeam
on one internal network with no firewall rules to open. Disk is no longer a constraint: C:
has 78 GB free and a dynamic VHDX only claims what it uses (realistically 35-50 GB). See
[environment.md](environment.md).

**Alternatives rejected.** Cloud VM (AWS or Azure) — about $15-30 a month once the sign-up
credits run out, plus firewall rules for the REST API; kept as the fallback. Spare PC — none
free today; also a fallback. Veeam installed directly on the laptop — mixes the product under
test with the dev toolchain and does not resemble an MSP's server.

---

## 2026-09-22 — Veeam authentication supports two modes; W1.0 picks the default

**Decision.** `VeeamClient` implements both admin mode (a dedicated local Windows account in
the Veeam Backup Administrator role, `grant_type=password`) and operator mode (a Microsoft
365 user with a Restore Operator Role scoped to the tested users and sites, one device-code
sign-in, then refresh tokens). Admin mode is built first; operator mode becomes the default
if W1.0 proves it. Refresh tokens live in the DPAPI vault.

**Reason.** Veeam's documentation does not settle whether the Worker can run unattended with
less than administrator rights. Committing to one mode before the spike would risk either an
unsellable privilege level or a connector that cannot run unattended.

**Alternatives rejected.** Admin-only — "never a Veeam administrator" is a sales argument we
would lose. Operator-only — unproven, and an MSP may not run the Restore Portal. The
fallback, if operator mode fails all four W1.0 checks and an MSP refuses admin mode, is the
Veeam PowerShell module run locally on the Veeam server; that choice gets its own entry.

**Status.** Open until W1.0 closes.

---

## 2026-09-22 — Cloud tenant isolation through repository classes

**Decision.** All database access goes through repo classes in `cloud/app/repo/`, each taking
`msp_id` as its first argument. A lint test fails any `select(` outside `app/repo/`.

**Reason.** One MSP seeing another's results would end the product. A single enforced
choke-point is testable; a rule that every query must be filtered is not.

**Alternatives rejected.** Postgres row-level security — stronger, but harder to test and to
debug in Stage 1, and it moves the rule out of the code that CI checks. Filtering by hand in
each route — one forgotten `where` is a breach.

---

## 2026-09-22 — Evidence bundles are Ed25519-signed and RFC 3161-timestamped

**Decision.** Each run produces a result JSON canonicalised as sorted keys, no whitespace,
UTF-8, ISO-8601 UTC. `bundle_sha256` is computed over that JSON with `signature` and
`tsa_token` removed; the Worker signs the hash with Ed25519 and obtains an RFC 3161
timestamp token. `shared/schemas/result.v1.json` is the single schema for both the C++ and
Python sides, and `shared/tools/verify_bundle.py` is the auditor-facing verifier. Failed runs
are never edited or re-signed.

**Reason.** The product's claim is evidence, not a dashboard. An auditor must be able to
check, offline and without us, that a result came from this worker and existed at that time.
RFC 3161 is what auditors already accept.

**Alternatives rejected.** RSA signatures — larger, slower, more ways to hold wrong. Signing
the non-canonical JSON — whitespace or key order would break verification across languages.
Trusting our own server clock — proves nothing to a third party. A blockchain anchor — same
guarantee, far more explaining.

---

## 2026-09-22 — Worker secrets in a Windows DPAPI vault

**Decision.** Veeam and Graph credentials, refresh tokens, the Cloud API token and the
signing key live in `%ProgramData%\RestoreProof\vault.bin`, encrypted with DPAPI under the
service account. Nothing else, apart from a gitignored `.env` in development. HTTP logging
redacts `Authorization`, `client_secret` and `password`; a sentinel-grep test (W4.9) enforces
it.

**Reason.** The Worker runs as a Windows service on an MSP's server. DPAPI machine/user
protection is built into the OS, needs no extra infrastructure, and ties the secrets to the
host the MSP already trusts.

**Alternatives rejected.** A cloud key vault — an outbound dependency at the exact moment a
credential is needed, and it moves custody of MSP credentials to us. Config file with a
passphrase — the passphrase then needs storing. Windows Credential Manager — awkward for
non-string blobs like the signing key.

---

## 2026-09-22 — Worker in C++20 (MSVC, CMake + vcpkg)

**Decision.** The on-prem Worker is C++20 built with MSVC via CMake presets, dependencies
pinned by vcpkg (`builtin-baseline` in `worker/vcpkg.json`): cpr, nlohmann-json, spdlog,
openssl, catch2. `rpcore` holds all logic as a static library; `rpworker` is a thin exe;
`rptests` is the Catch2 suite.

**Reason.** It ships as a single native Windows service with no runtime for the MSP to
install, patch or explain, and it is straightforward to sign. Keeping the logic in `rpcore`
keeps it testable without the service.

**Alternatives rejected.** .NET — a runtime dependency and a much easier binary to decompile
for an on-prem agent. Go — fine binaries, weaker Windows service and DPAPI story. Python —
packaging an interpreter onto a customer's backup server is a support burden.

---

## 2026-09-22 — Cloud in FastAPI (Python 3.12, uv) with Jinja2 + HTMX

**Decision.** The Cloud backend is FastAPI on Python 3.12, managed with uv and a committed
`uv.lock`. The dashboard is server-rendered Jinja2 templates with HTMX for partial updates.
Local stack: Postgres 16 and MinIO through `docker compose`.

**Reason.** The API and the dashboard share one codebase, one test suite and one deployment.
The same Python that verifies bundles also renders them. HTMX gives the interactivity a
dashboard needs without a separate frontend build, which one developer would otherwise have
to maintain.

**Alternatives rejected.** React or another SPA — a second toolchain, build and deploy for a
handful of pages. Django — more framework than the API needs, and OpenAPI generation is the
point here. Node — would split the stack from the Python verifier.

---

## 2026-09-22 — Restores only ever target `restoretest` / `RestoreTest`

**Decision.** Every restore goes to the `restoretest` mailbox or the `RestoreTest`
library/OneDrive folder. `TargetGuard` is checked per item inside `RestoreSample`, before any
Veeam call, and is the only code path that may name a restore target. A guard violation is
`error`, never `fail`.

**Reason.** The one catastrophic failure mode is overwriting a customer's live data with a
restore. A single guarded code path can be tested exhaustively; scattered checks cannot.

**Alternatives rejected.** Checking the target once per run — a sample is built per item, so
per-item is the only place the check is complete. Trusting configuration — a typo in an MSP's
config would be a data-loss incident.
