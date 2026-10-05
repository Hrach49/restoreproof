#pragma once

// `rpworker test` (W3.6, #41): the whole test of a restore point, clean
// before, restore point, sample, guard, restore, verify, status, clean after
// and timings, as one run of the pipeline `rpworker restore` runs
// (src/run_pipeline.hpp). It WRITES to the tenant as `restore` does: into the
// restore targets only, through restore_sample, and deletes there through
// the Cleaner only. What differs from `restore` is its table and its --json
// file. The choices are the 2026-10-03 W3.6 entry in docs/decisions.md and,
// for the file, the 2026-10-04 W4.1 one; usage and an example are in
// docs/worker-config.md ("rpworker test").

#include <rp/restore_command.hpp>

#include <iosfwd>
#include <span>
#include <string_view>

namespace rp {

// `rpworker test ...`. `args` is what follows "test" on the command line, in
// UTF-8:
//   [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>]
//   [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>]
//   [--record <dir>] [--json <file> | --evidence <dir>]
// in any order, each at most once, each with its value, by
// run_restore_command's rules (an absent size is the config's sample_mail,
// sample_sp or sample_od). There is no --seed: the run ID gives the seed, so
// --run-id repeats a sample (W3.6 point 3).
//
// The run, its order, its lines on `err`, its status line and its exit codes
// are run_restore_command's (rp/restore_command.hpp): 0 pass, 5 fail, 1 to 4
// error by its code, 64 usage; a failure before the run line exits as there.
// What `out` shows differs only here:
//  - no per-item rows after the restore: the session rows and the `restore
//    <status>: ...` line follow the header;
//  - after the check, one table, one row per expected item:
//      TYPE  NAME  EXPECTED  FOUND  MATCH  VERDICT  REASON  MS
//    TYPE mail, sharepoint or onedrive; NAME the expected subject or file
//    name; EXPECTED manifest, fields or metadata; FOUND yes or no; MATCH the
//    check's outcome (match, mismatch, missing, error); VERDICT verified,
//    failed or "unchecked <code>" (an item the backup blamed on
//    infrastructure reads "unchecked backup_infrastructure", never a
//    failure), "-" when the status table's rows 1 to 4 decided the run;
//    REASON fixed words only: a mismatch's field names joined by commas,
//    "missing", an error's code, "-" for a match (never the check's reason,
//    which can name a part of a tenant file); MS the item's ms when found,
//    else "-";
//  - with --json <file>, after the step timings' table, "wrote <file>" on
//    success, before --record's "recorded ..." line.
//
// --json <file> (W3.6 point 5, W4.1) writes the run's unsigned result,
// restoreproof.result.v1 (rp/result_builder.hpp; the schema is
// shared/schemas/result.v1.json), for every run that printed its run line,
// whatever its status: exactly its canonical text (rp::canonical_json: one
// line, no whitespace, no trailing newline), seventeen keys, every one always
// there, null where a step didn't run (`attachments` and `screenshot` always:
// there is no run folder). The pipeline builds and validates it
// once the clean after and the timings are done. Nothing of the process is in
// it: a pass whose output was lost or whose --record recording isn't complete
// shows only in the exit code and on `err`. No secret; it holds more tenant
// data than stdout (docs/verification.md). The path is checked once the config is
// read, before the secrets, the manifest, the mutex, --record and any Veeam
// call; each refusal is exit 1:
//   config error: --json <file>: not a UTF-8 path
//   config error: --json <file>: not a file name
//   config error: --json <file>: the file already exists
//   config error: --json <file>: the folder doesn't exist
//   config error: --json <file>: a file can't be written there
// rp::check_new_file decides: "not a file name" is not rp::is_plain_file_name
// (a ':' names an NTFS stream; a trailing '.' or ' '; a DOS device's name
// such as PRN or aux.json); "already exists" is anything but a clean "not
// found"; "can't be written there" is the writer's own temp file not made
// (a folder it may not write to, a name or path too long with the temp's 21
// characters). An empty --json value is a usage error, as a missing one. The file is written through env.write_summary (by default never over a
// file that appeared since). When it isn't written: "json error: <file>:
// could not be written" on `err`; the status never changes, an exit code of
// 0 becomes 1 and any other is kept. A result that isn't valid is never
// written, and no cut-down one is made up: "json error: <file>: the result
// isn't valid restoreproof.result.v1; no file was written", by the same exit
// code rule, for a run that ended `error result_invalid`
// (rp/restore_command.hpp), for a finished result that isn't valid though
// the one before the status line was (after its own "result error: ..."
// line; the status line is out and stays), and for a run that has no status.
// <file> is the --json value as given, its control characters as spaces.
//
// --evidence <dir> (W4.2, docs/decisions.md 2026-10-05) writes the run folder
// <dir>\<run_id>\ instead (rp::EvidenceBuilder; never with --json, a usage
// error, as an empty value is): items.csv, veeam-session.log, screenshot.png
// when one was captured, and result.json, the same result with each of
// those files in `attachments` (name, SHA-256, size) and `screenshot` saying
// captured or why not. It always signs (W4.3): the key in
// RP_SIGNING_KEY_BASE64 is parsed before anything is done, and
// signature.json (rp/signer.hpp), an Ed25519 signature over the SHA-256 of
// result.json's bytes, is written just before result.json and never listed
// in it. --json stays unsigned and needs no key, as `restore` and a `test`
// without either. What it checks, when the folder is made, its lines
// and its exit codes are on run_pipeline (src/run_pipeline.hpp). <dir> is
// made if it isn't there; a folder for the run ID that is already there
// stops the run before its run line. No exception escapes.
int run_test_command(std::span<const std::string_view> args, std::ostream& out,
                     std::ostream& err, const RestoreCommandEnv& env);

} // namespace rp
