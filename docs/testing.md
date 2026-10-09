# Testing

How we test, what CI enforces, and the once-per-sprint mutation run. Set up in L0.5.
`CLAUDE.md` has the short version; this file has the detail.

## The rules

- **Test first.** Start from the task's "Done when" line: write it as an acceptance test,
  watch it fail, then go red → green → refactor one step at a time. Commit the test and the
  code together after each green.
- **Failure paths first.** Write the tests for what goes wrong before the happy path:
  missing item, hash mismatch, tampered signature, wrong target, unreachable service.
- **Decision tables are parametrised.** One row per case, in Catch2 `GENERATE` or
  `pytest.mark.parametrize`. The status table (`pass` / `fail` / `error`) is the main one;
  it will live in `docs/verification.md` (to be written in W3.x).
- **Fixtures before live calls.** Anything that talks to Veeam, Graph, the TSA or the Cloud is
  first written against recorded responses in `worker/tests/fixtures/<service>/`, recorded with
  `--record`, secrets scrubbed, and served by `FakeHttpClient`. Live tests run only when
  `RP_LIVE=1` is set.
- **Every bug becomes a test.** Write a test that reproduces the bug, see it fail, then fix.
- **End-to-end scenarios** are run by hand and tracked in `tests/e2e/scenarios.md`.

## What CI enforces

| Guard | Where | Rule |
|---|---|---|
| Worker coverage | `.github/workflows/worker.yml`, OpenCppCoverage + `worker/tools/coverage_gate.py` | 80% line on `rpcore` (`worker/src/`, `worker/include/`) plus `rpworker`'s `main()` (`worker/app/`); 100% **line** on vault, signer, target_guard, run_status, cleaner, timestamper, outbox and service (the vault once it exists), meaning any file with a path part named or prefixed `vault`, `signer`, `target_guard`, `run_status`, `cleaner`, `timestamper`, `outbox` or `service` (W4.8's five by the `service` prefix: `src/service_loop.cpp`, the scheduler loop, which decides what is due, which job runs, what is skipped and what becomes of a run's record, `src/service_jobs.cpp`, the jobs document's reader, `src/service_recovery.cpp`, `running.json`, the plan for a run folder without a result and the rule for Veeam's sessions after one, `src/service_log_stream.cpp`, the streams that turn a run's lines into log lines, and `src/service_errors.cpp`, the words a heartbeat's `last_error` may be, with their headers, while `src/worker_body.cpp`, the real calls the loop is handed, `src/heartbeat.cpp`, the one POST, `src/run_folder_tail.cpp`, the end of a run folder that the pipeline and the close share, and `src/job_rules.cpp`, the rules a command line and a job are both held to, are outside; W4.7's `src/service.cpp`, the running service's state machine, `src/service_command.cpp`, the `rpworker service` commands, and `src/service_log.cpp`, which decides what reaches the log file, while `src/scm.cpp`, the calls into the Service Control Manager, and `src/stop_signal.cpp` are outside; W4.6's `src/outbox.cpp`, which decides what is queued, sent, kept and pruned, and `src/outbox_command.cpp`, while `src/uploader.cpp`, the one HTTP call, and `src/folder_ops.cpp`, the file-system calls under it, are outside; W4.4's `src/timestamper.cpp`, which decides which RFC 3161 token is written, while `src/rfc3161.cpp`, the calls into OpenSSL under it, is outside like `src/ed25519.cpp`; `src/vault_dpapi.cpp`; W4.3's `src/signer.cpp`, the Signer, and `src/signer_command.cpp`, the two `rpworker signer` commands, with their headers, while `src/ed25519.cpp`, the calls into OpenSSL under the Signer, is deliberately outside: the library's failure lines for a valid key can't be reached by a test, and folding them onto their calls' own lines would hide them, `docs/decisions.md` 2026-10-05 W4.3 point 4; W2.7's `src/target_guard.cpp`, `src/target_guard_graph.cpp`, `src/target_guard_veeam.cpp` and their headers; W3.3's `src/run_status.cpp`, the status decision table; W3.4's `src/cleaner.cpp` and `include/rp/cleaner.hpp`, the only Worker code that deletes in the tenant); every `.cpp` on disk under `src/`, `include/` and `app/` must appear in the report, so a file no test links into `rptests` (or, for `app/`, that ctest's runs of `rpworker.exe` don't reach) fails (headers of declarations may be absent) |
| Cloud coverage | `.github/workflows/cloud.yml`, pytest-cov | 80% on `app/`, measured as coverage's combined line + branch figure; 100% line + branch on `app/auth`, `app/results.py` and `app/repo` (skipped while absent), checked by `cloud/tools/check_coverage.py` |
| Lab tests and canary hashes | `.github/workflows/lab.yml` | `lab/`'s pytest suite passes (offline, fake Graph tenant), and `python -m seeder hash` reproduces every hash in `lab/seed-manifest.json` from the committed `lab/canary/` files and the catalog (L1.2's Done when). No coverage floor |
| Secret audit | `worker/tests/secret_audit_test.cpp` (ctest, `[secret_audit]`); `worker/tools/fixture_secret_scan.py` (ctest `fixture secret scan` and the `fixture-scan` job of `.github/workflows/worker.yml`) | W4.9: every path of the pipeline, the commands and the service's loop run on fixtures with five sentinel secrets, and every output (both streams, the log, every file, every request to the fake Cloud and TSA) holds no sentinel, no value derived from one and no secret shape; the committed fixture, vector and evidence trees hold no secret shape but what `worker/tools/fixture_secret_scan_allowlist.json` allows by file, shape and value. See "The secret audit (W4.9)" |
| No test, no merge | `.github/workflows/pr-guards.yml`, `.github/scripts/tests_touched.py` | Each side needs its own tests: a PR that changes `worker/src/`, `worker/include/` or `worker/app/` must add or change a C++ file (`.cpp`, `.hpp`, `.h`) under `worker/tests/`, and one that changes `cloud/app/` must add or change a `.py` under `cloud/tests/`. Deleting a test, editing fixtures or editing `tests/e2e/scenarios.md` doesn't count |
| PR checklist | `.github/PULL_REQUEST_TEMPLATE.md` | Failing test written first, suite green locally, "Done when" observed |

`main` has no branch protection (not available on a free private repo), so a red check does
not disable the merge button. The rule is manual: merge only when every check is green. See
`docs/decisions.md`.

Both coverage jobs write their numbers to the workflow run's summary page; the Worker job
also uploads the Cobertura XML as the `worker-coverage-cobertura` artifact.

**Known gap:** OpenCppCoverage reports line coverage only, not branch coverage. CLAUDE.md asks
for 100% branch on vault, signer, target_guard, run_status and cleaner; until the Worker has a branch-capable tool,
those files are held to 100% line instead. See `docs/decisions.md`.

**Two rules for a strict file, which the gate taught (W4.8).** OpenCppCoverage counts a
closing brace as a line of its own when the only thing it carries is a destructor, and such a
line is unreached when every path has already returned. No test can reach it, so the code is
written without it:

- No `return` inside a catch handler: the handler's closing line is never reached. The handler
  notes what happened (a flag, a word) and the function returns once, after the handlers.
- No function that ends in a braced `return`, or in a `switch` whose every case returns, while
  a local of its own or a by-value parameter with a destructor is alive: the function's closing
  line only destroys it and is never reached. The value is taken by reference, given a scope of
  its own, or the function is one expression over helpers that hold no local.

Both leave the behaviour as it is. W4.8's review met six such lines in `src/service_loop.cpp`,
`src/service_recovery.cpp` and `src/service_jobs.cpp` (commit 5a3052c), and `src/outbox.cpp`
had one from W4.6 (`docs/decisions.md` 2026-10-08, W4.7 build notes point 3).

### Live tests

Tests tagged `[live]` call the lab's real services and are skipped unless `RP_LIVE=1` is set;
they are read-only, except the two tagged `[live][writes]`, which also need `RP_LIVE_RESTORE=1`
("Live restore" below). `RP_LIVE=1 ctest --preset dev` runs them with the rest, or run them alone
with `build\dev\rptests.exe "[live]"` (which also prints what they found). Three are Veeam's,
four Graph's and one the sampler's dry run, which uses both (below); once `RP_LIVE=1` is set,
each needs its variables below and fails, rather than skips, without them.

**The secrets come from the vault (W4.5).** Every `[live]` test reads the Worker's five
secrets as the Worker does, through `worker/tests/live_secrets.hpp`: `rp::read_vault` of the
file `RP_LIVE_VAULT` names (a path, a switch like `RP_LIVE`, not a secret) or, without it, the
default vault `%ProgramData%\RestoreProof\vault.bin`. No test reads a secret from the
environment. The lab's vault is filled once with `lab\entra\fill-worker-vault.ps1` from an
elevated shell ("The vault" in `lab/README.md`); its ACL admits SYSTEM, Administrators and the
file's owner, so a read-only live test in an unelevated shell needs one `Read` entry for the
developer's account, granted once from an elevated shell:

```powershell
.\worker\build\dev\rpworker.exe vault grant "$env:USERDOMAIN\$env:USERNAME"
.\worker\build\dev\rpworker.exe vault test     # as the developer, unelevated: `vault ...: ok` and the five names
```

Chosen over elevating every read-only test because the grant is the mechanism the service
itself uses and the lab should exercise it, an elevated shell is more privilege than a
read-only test needs, and the lab's developer already holds every one of these values (in
Credential Manager and the PFX file). Without the grant an unelevated test fails with
`<file>: the vault file can't be read`. The two `[live][writes]` tests still need an elevated
shell for the certificate export, as before.

The three Veeam ones
(`worker/tests/veeam_client_live_test.cpp`) each sign in, list organisations and restore
points, and log out: W1.5's through `VeeamClient`, W1.6's through `rpworker veeam list`
(`rp::run_veeam_command` with a temp config written from these variables, expecting the lab
organisation's two L1.3 restore points, found by `backupTime` among any later nightly ones), and W1.7's through the `veeam_m365` connector from
`rp::connector::default_connector_registry()`, held as an `IConnector&` and asked for the lab
organisation by name (since W2.5 the factory also loads the Worker app's certificate for the
target guard, so that one needs the Graph certificate variables below too; it makes no Graph
call). They read:

| Variable | Value |
|---|---|
| `RP_LIVE_VAULT` | the vault file holding `veeam_username` and `veeam_password` (`MACHINE\user`); default: the Worker's default vault |
| `RP_LIVE_VEEAM_CA_FILE` | PEM of Veeam's REST certificate (required) |
| `RP_LIVE_VEEAM_CERT_SHA256` | its SHA-256; default: the lab's |
| `RP_LIVE_VEEAM_URL` | default `https://localhost:4443` |

The two Graph ones (W2.1, `worker/tests/graph_client_live_test.cpp`) sign in to the lab
tenant's Entra with the Worker app's certificate through `GraphClient`, then make GETs only:
one reads the first message ID in the `restoretest` inbox and expects a `PermissionError`
naming the Mail grant for a mailbox outside the Exchange management scope; the other expects
one naming `Sites.Selected` for a site the app has no grant on. They read:

| Variable | Value |
|---|---|
| `RP_LIVE_VAULT` | the vault file holding the Worker app's certificate, `graph_cert_pfx_base64` and `graph_cert_password` (`rp/secrets.hpp`), filled with `lab\entra\fill-worker-vault.ps1` (`docs/worker-config.md`, "Microsoft Graph app"); default: the Worker's default vault |
| `RP_LIVE_GRAPH_TENANT_ID` | default: the lab tenant |
| `RP_LIVE_GRAPH_CLIENT_ID` | default: "RestoreProof Worker" |
| `RP_LIVE_GRAPH_MAILBOX` | default: `restoretest@`, inside the Mail scope |
| `RP_LIVE_GRAPH_DENIED_MAILBOX` | default: `alice@`, outside it |
| `RP_LIVE_GRAPH_DENIED_SITE` | default: the tenant's root site (no `Sites.Selected` grant) |

The third Graph one (W2.2, `worker/tests/graph_targets_live_test.cpp`, tag
`[graph][targets][live]`) is the Done-when of issue #27: `rp::graph::TargetReader::list_all()`
lists the three restore targets (the `restoretest` Inbox, the RestoreTarget library's root,
alice's OneDrive `/RestoreTarget`), downloading each file through
`make_download_http_client()` without the token, and prints one line per item
(`type  id  name|subject  size  sha256 (rule)`) and a `total` line per type. It asserts only that
nothing was thrown; whoever runs it compares the output with what the tenant shows. It never
names or reads the canary locations. Besides the certificate, tenant and client variables above,
it reads (defaults: the lab's restore targets in `lab/tenant.md`):

| Variable | Value |
|---|---|
| `RP_LIVE_TARGET_MAILBOX` | default: `restoretest@` |
| `RP_LIVE_TARGET_SITE_ID` | default: the RestoreTest site (`<host>,<site GUID>,<web GUID>`) |
| `RP_LIVE_TARGET_LIBRARY_ID` | default: the RestoreTarget library's **drive** ID |
| `RP_LIVE_TARGET_ONEDRIVE_DRIVE_ID` | default: alice's OneDrive drive |
| `RP_LIVE_TARGET_ONEDRIVE_FOLDER_ID` | default: its `RestoreTarget` folder |

Run it alone, with its output shown (ctest names tests by case and hides output without `-V`):

```powershell
.\worker\build\dev\rptests.exe "[targets][live]"
```

The fourth Graph one (W2.3, `worker/tests/graph_command_live_test.cpp`, tag
`[graph][graph_command][live]`) is the Done-when of issue #28: it runs `rpworker graph list`
(`rp::run_graph_command` with `default_graph_command_env()`, the real clocks and the Worker's
secrets from the environment, on a temp config written from the variables above), once without
and once with `--hash`, prints each run's tables, and checks exit code 0, an empty stderr, the
three headings and the summary line. Whoever runs it compares the tables with the tenant. Run it
alone:

```powershell
.\worker\build\dev\rptests.exe "[graph_command][live]"
```

Set the passwords for one shell only, and never on a command line that ends up in history or
a transcript: read them from Windows Credential Manager or `Read-Host -AsSecureString`.

To run the four Graph ones on the dev laptop (the PFX and its Credential Manager entry come from
`lab/entra/new-worker-app.ps1`, `lab/README.md`):

1. Open a VS 2022 Developer PowerShell: Start menu, type `Developer PowerShell for VS 2022`,
   press Enter (or run `Launch-VsDevShell.ps1` as in `docs/environment.md`, "Terminal
   setup"). Only a build needs it; to build first, also set `$env:VCPKG_ROOT = 'C:\vcpkg'`
   and run `cmake --build --preset dev` from `C:\restoreproof\worker`.
2. Go to the repo root:

   ```powershell
   cd C:\restoreproof
   ```

3. Make sure the vault is filled and this account can read it (once; W4.5, "Live tests"
   above): from an elevated shell `.\lab\entra\fill-worker-vault.ps1` (it ends with `vault
   list` naming the five secrets, or four and a `skipped signing_key_base64:` line while the lab
   has no signing key; the live tests need none) and `.\worker\build\dev\rpworker.exe vault
   grant "$env:USERDOMAIN\$env:USERNAME"`. Then, in this shell, `.\worker\build\dev\rpworker.exe
   vault test` must print `vault C:\ProgramData\RestoreProof\vault.bin: ok` and the names.
4. Turn the live tests on for this session and run the Graph ones:

   ```powershell
   $env:RP_LIVE = '1'
   .\worker\build\dev\rptests.exe "[graph][live]"
   ```

   Expected: a line `inbox of restoretest@…: N message(s) on the first page`, two lines
   `denied as expected: Graph denied GET …` (the Mail grant, then `Sites.Selected`), the
   restore targets' listing (one line per item, then `mail total: N`, `onedrive total: N`,
   `sharepoint total: N`), the same targets twice as `rpworker graph list` tables (without and
   with `--hash`), and `All tests passed` for 4 test cases. To run them with everything else instead, run
   `ctest --preset dev` from `C:\restoreproof\worker` (the Veeam live tests then need their
   variables too).
5. Remove the switch again, or close the window:

   ```powershell
   Remove-Item Env:RP_LIVE
   ```

No secret is in the session: the tests read the vault, and PowerShell's history holds only the
commands above.

### Live sample (dry run, read-only)

`worker/tests/sample_selector_live_test.cpp` (W2.6, tag `[live][sample]`, not `[writes]`) runs
the sampler against the lab: it makes the `veeam_m365` connector through
`default_connector_registry()`, takes the lab organisation's newest restore point, loads
`lab/seed-manifest.json` and calls `rp::sampling::choose_sample` **twice** with the same run ID
and canary cursor (`SamplePlan::from_config`'s defaults, 5 of each type). It restores nothing:
`list_candidates` opens one explore session per type with a random half and stops it again,
as `docs/api/veeam-m365/10-restore.ps1 -WhatIf` does, and the target guard reads the restore
targets through Graph. It checks that:

- both calls chose the same items and recorded the same `sample` object;
- `TargetGuard::check_spec` (layer 1, Graph GETs only) accepts the selection;
- every POST was a sign-in (`/v8/token`, `/v8/token/logout`), an explore session (`/explore`)
  or its `/Stop` (the Veeam HTTP client is wrapped in a counting forwarder through
  `ConnectorOptions::make_http`, which records methods and URLs only);
- afterwards `GET /v8/RestoreSessions?limit=200` lists no Working session of the account;
- the expected set (W3.1, `rp::verification::build_expected_set`) has one record per item,
  the same for both calls.

It prints the restore point, the selection, `to_json(record)` (the result's `sample` object:
seed, manifest SHA-256, cursors, canary IDs, pool sizes and hashes, the containers looked
into), the expected set (`to_json(ExpectedSet)`, the result's `expected` object; the lab has
no real files yet, so expect a file shortfall), how many entries each OneDrive's `Documents?parentId=root` listing held, and the number
of GETs and POSTs. It needs the vault (the Veeam account and the Worker app's certificate in
it) and `RP_LIVE_VEEAM_CA_FILE` above, no elevation, plus two optional ones:

| Variable | Value |
|---|---|
| `RP_LIVE_RUN_ID` | the run ID the seed comes from; default `live-dry-run` (seed `49b39f4c`) |
| `RP_LIVE_SAMPLE_CURSOR` | the canary cursor per type, `m,s,o`; default `0,0,0` |

Run it alone, with its output shown:

```powershell
$env:RP_LIVE = '1'
.\worker\build\dev\rptests.exe "[sample][live]"
```

Until the lab holds real (non-canary) data the random half is mostly a recorded shortfall
(`docs/decisions.md` 2026-09-30, W2.6, "Open"); the canary half is always full.

### Live restore (writes to the lab tenant)

**These two tests write.** They are the only live tests that change anything: one restores
real items into the three restore targets and deletes them again, the other only deletes
(W3.4's Cleaner). Each is skipped unless **both** `RP_LIVE=1` and `RP_LIVE_RESTORE=1` are set,
so a normal `RP_LIVE=1` run stays read-only. Each takes the run mutex
`Global\RestoreProof-restore-targets` first, as `rpworker restore` does
(`worker/include/rp/run_lock.hpp`), and fails at once (`REQUIRE(lock != nullptr)`) while another
RestoreProof run holds it, so a test never deletes a running restore's copies.

`worker/tests/veeam_m365_restore_live_test.cpp` (W2.5, tag `[live][writes]`, ctest name
`live restore: restore_sample restores 10 canaries into the lab's restore targets`) makes the
`veeam_m365` connector through `default_connector_registry()` with the vault's secrets and
`make_local_machine_cert_exporter()`. It lists the lab organisation's restore points and takes
the newest. It then builds one spec from `lab/seed-manifest.json`:

- 5 mails from one source mailbox's Inbox, by subject and `received_at`;
- 3 SharePoint files and 2 OneDrive files, by name and `stored_size`. pdf and txt files are
  chosen first, never docx or xlsx, and each type is taken in ID order.

It calls `restore_sample` once and prints the status, each restore session (start, end, result,
details), each item's outcome and the log. It passes only with status `succeeded` and 10 items
restored. Since W3.4 it then runs `Cleaner::clean(after_run)` on the three targets and prints
its counts (`cleanup after {...}`), so it leaves no copies; it checks that the clean was ok too.
It needs the variables of the Veeam and Graph live tests above, plus:

| Variable | Value |
|---|---|
| `RP_LIVE_RESTORE` | `1` (required, besides `RP_LIVE=1`) |
| `RP_LIVE_EVIDENCE_FILE` | optional: a path where the `RestoreResult` is written as JSON (no secrets in it) |

Before running it:

1. **Use an elevated shell.** The restore credential is Veeam's organisation app certificate,
   exported from `LocalMachine\My` in memory for each restore call, and reading its private key
   needs administrator rights (or, as the Worker's service will have, a Read ACE on the key
   file: W4.12, `docs/decisions.md` 2026-10-07). Start `Developer PowerShell for VS 2022` with
   right-click, **Run as administrator**. Without elevation the test fails at the first restore
   call with a certificate export error, before anything is restored.
2. **Make sure the restore targets are empty.** Run the live cleanup test (below), then
   `rpworker graph list` (above, and `docs/worker-config.md`) and check that the `restoretest`
   Inbox, the RestoreTarget library and alice's `/RestoreTarget` folder show `0 item(s)` and no
   `(... not listed)` line.
3. **Make sure no restore session of the Veeam account is still running.** The connector refuses
   to start if one is (`docs/api/veeam-m365/08-sweep-sessions.ps1` stops them).

Run it from `C:\restoreproof\worker`, with the vault filled as in the Graph steps above:

```powershell
$env:RP_LIVE = '1'
$env:RP_LIVE_RESTORE = '1'
$env:RP_LIVE_EVIDENCE_FILE = "$env:TEMP\w2.5-live-restore.json"   # optional
ctest --preset dev -R "live restore" -V
```

(`.\build\dev\rptests.exe "[live][writes]"` runs both writing tests). The restored copies are
deleted at the test's end, so `rpworker graph list --hash` afterwards shows empty targets; to
read a restore's copies back and compare them with the manifest, use `rpworker restore` (below),
whose check does it before its clean after.

**The live cleanup test.** `worker/tests/cleaner_live_test.cpp` (W3.4, tag `[live][writes]`,
ctest name `live cleanup: the Cleaner empties the three restore targets with folders and all`;
no comma in it, since Catch2 splits a test name given on its command line at a comma) first
seeds one item of its own in each restore target, because the targets are usually empty now
(every `rpworker restore` cleans before and after): a small `rp-probe-<uuid>.txt` `PUT` into
the RestoreTarget library's root, one into alice's `/RestoreTarget` folder (both with
`@microsoft.graph.conflictBehavior=fail`), and a message with subject `rp-probe-<uuid>` created
in the `restoretest` Inbox (`POST /users/{mailbox}/mailFolders/inbox/messages`). The seeds are
sent by the test itself, with a token of its own and cpr, not through `GraphClient`, whose only
write is the Cleaner's `remove()`. Before anything is sent, the config's restore-target IDs are
checked against `lab/seed-manifest.json` (`sampling::check_manifest`, then every canary's
mailbox, SharePoint drive and folder ID), then for shape (`RestoreTargets::from_config`, the
`parse_config` rules), and each target is resolved through the target guard's own Graph checks
(`check_restore_mailbox`, `check_restore_library`, `check_restore_onedrive_folder`, as the
Cleaner's `resolve()` runs them, on a Graph client of their own so the recording holds only the
Cleaner's exchanges); the three seed paths are built only from what those checks established
(`worker/tests/live_seed.hpp`, unit-tested in `live_seed_test.cpp`), and any refusal stops the
test before the first write. Then it signs in to Graph as the Worker app, runs
`Cleaner::clean(after_run)` on the three restore targets of `graph_live_lab.hpp`'s config (the
`RP_LIVE_TARGET_*` variables above, defaulting to the lab's), prints its counts, and requires no
error, an ok clean, and each seed found and deleted (`deleted` or `gone` at least 1 per target).
Its first file `DELETE` and first mail `permanentDelete` are each sent twice; with the seeds
there both happen, so it requires two doubled sends, the second answer of each counted `gone`:
the file's is Graph's 404 `itemNotFound`, the mail's 403 `ErrorCannotDeleteObject` (seen live
on 2026-10-02), which `GraphClient::remove` follows with one check, is the message gone: its
`parentFolderId` (live, the purged message still answered 200, from Recoverable Items) against
the `id` of the mailbox's `recoverableitemspurges` folder, then the Inbox's; only a 404 or a
byte-for-byte match with Purges makes it `gone`, the Inbox leaves the 403's `PermissionError`,
and any other folder is an error, never `gone` (`docs/decisions.md`, W3.4 build notes, point
15). Last, it lists each target again with `$top=1` and no type filter, folders
included, and requires zero entries: the W3.4 Done-when's "zero items and no entries left
unlisted". Set `RP_LIVE_RECORD_DIR` to a new or empty folder to record the Cleaner's and the
last listings' Graph exchanges there (under `graph/`; the seeds are not recorded), the second
answer of each doubled send included (the first is not: the wrapper sits inside the recorder).
The folder is opened before the first seed, so one that isn't new or empty fails the test with
nothing written. Only a first delete Graph answers 204 is doubled: a 429 or 503 GraphClient
retries, or a 412, leaves the doubling to the next attempt.
The 2026-10-02 run gave `w34-file-delete-404-itemnotfound.json` and
`w34-mail-permanentdelete-403-cannotdeleteobject-repeat.json`; its 21:05 rerun the message
GET's 200 behind the hand-shaped `w34-mail-get-200-purged-parentfolder.json`, whose
`parentFolderId` and `w34-mail-purges-200-id.json`'s `id` come from a read-only probe of the same
day. It needs the vault (the Worker app's certificate in it, readable by this account),
`RP_LIVE=1` and `RP_LIVE_RESTORE=1`, and no elevation. It deletes everything in the three
targets, delivered mail in `restoretest` too. From a VS 2022 Developer PowerShell:

```powershell
$env:RP_LIVE = '1'
$env:RP_LIVE_RESTORE = '1'
$env:RP_LIVE_RECORD_DIR = "$env:TEMP\rp-w34-cleaner-rec-$(Get-Date -Format yyyyMMddTHHmmss)"   # optional, new or empty
ctest --preset dev -R "live cleanup" -V
```

or, from any shell in `C:\restoreproof\worker` with the same variables,
`.\build\dev\rptests.exe "live cleanup*" -s`.

**When something is left.** A folder, a package or another entry the Cleaner skips (it deletes
only mails and plain files) is never deleted: it fails the cleanup test's last check, and the
restore test's `cleanup after` shows it as `skipped`. Remove it by hand in the Microsoft 365
web apps, then run the cleanup test again. A delete refused with 403 means a write grant is
missing or not yet active (`docs/security/graph-permissions.md`; Exchange may take up to two
hours to apply a role change). The `restoretest` mailbox's Deleted Items, which may still hold
copies from the hand cleanups before W3.4, is emptied once by hand; the Cleaner never reads it.
Remove the switches when done:

```powershell
Remove-Item Env:RP_LIVE, Env:RP_LIVE_RESTORE, Env:RP_LIVE_EVIDENCE_FILE, Env:RP_LIVE_RECORD_DIR -ErrorAction SilentlyContinue
```

### The restore credential under a service account (W4.12's probe)

`rpworker` exports Veeam's organisation app certificate from `LocalMachine\My` in memory for
each restore call (`rp::make_local_machine_cert_exporter`). Spike W4.12 (#135,
`docs/decisions.md` 2026-10-07) ran that export from a Windows service as LocalSystem and as a
virtual account, `NT SERVICE\<service name>`, which needs one Read ACE on the certificate's key
file and nothing else. The hidden test case `rptests "[spike_cert_export]"`
(`worker/tests/cert_export_test.cpp`) is what the spike ran under each account: with
`RP_SPIKE_THUMBPRINT` set to a thumbprint of the real `LocalMachine\My`, it prints one line with
what the Worker's exporter says of that certificate (`exported in memory: PFX <n> Base64
characters, password 44 characters; nothing written`, or `refused: <the exporter's message>`),
never a byte of the export. Without the variable it does nothing. It runs only when named;
`ctest --preset dev` never runs it. The spike's evidence, with the three refusals `rpworker
doctor` will have to name (a thumbprint no certificate has, a key that isn't exportable, an
expired certificate) and the denied-ACL case, is `docs/api/veeam-lab/w4.12-*`.

### Restore by hand (`rpworker restore`, writes to the lab tenant)

**This writes too.** `rpworker restore` (W2.8, `docs/worker-config.md`) chooses a sample and
restores it into the three restore targets, like the live test above, but from the command
line. ctest's `rpworker restore` exe tests all stop before any request (the arguments, the
config, the secrets), so nothing writes unless you run it by hand. Since W3.4 it also
deletes: it empties the three targets before it samples and again after its status line
(`docs/worker-config.md`, "`rpworker restore`"). Before running it, check: an elevated shell
(or an account with read access to Veeam's certificate's key file, as the service has: W4.12),
no restore session still `Working`, and no other RestoreProof run on this machine (the run
mutex refuses a second one: `restore error: another RestoreProof run is using the restore
targets; nothing was done`, exit 4). The targets needn't be empty first.

1. Open `Developer PowerShell for VS 2022` (or PowerShell) with **Run as administrator**, and
   go to `C:\restoreproof\worker`.
2. Make sure the vault holds the Veeam account and the Graph certificate
   (`..\lab\entra\fill-worker-vault.ps1` once, from this elevated shell; `.\build\dev\rpworker.exe
   vault list` shows the names). The command reads the vault and checks all four are there
   before it calls Veeam; no variable is read.
3. Optionally, see what is in the targets now (the clean before deletes it):

   ```powershell
   .\build\dev\rpworker.exe graph list --config <your config.json>
   ```

4. Restore, with the lab manifest (or leave `--manifest` out when a `seed-manifest.json` is
   beside the config):

   ```powershell
   .\build\dev\rpworker.exe restore --mail 5 --sp 5 --od 5 --config <your config.json> --manifest ..\lab\seed-manifest.json
   ```

   Note the printed run ID (`--run-id` repeats the sample) and the next canary cursor
   (`--canary-cursor` carries the rotation on). The line after `run ...` is the clean
   before's (`cleanup before ok: deleted ...`). The run's status line (W3.3) comes next to
   last: exit 0 is `pass` (every sampled item read back and verified), 5 `fail` (an item
   missing or not matching), 1 to 4 an `error` by its code, such as `target_guard` (the guard
   refusing, the clean before's included), `stale_target` (an earlier run's copy the clean
   before couldn't delete) or `backup_infrastructure` (an item Veeam failed for an
   infrastructure reason); warnings go to stderr (`docs/verification.md`, "The status decision
   table"). Then comes the clean after's line: `cleanup after ok: ...` when all three targets
   were left empty; `incomplete` names what was left, skipped or refused, and never changes the
   exit code. The step timings' table (W3.5, `STEP TIME NOTE`, eleven rows) ends the output.
5. Check with `rpworker graph list` that the targets are empty again (`0 item(s)` each and no
   `(... not listed)` line: the W3.4 Done-when). If not, see "When something is left" above.
   Nothing to remove: the secrets stayed in the vault.

### Test by hand (`rpworker test`, writes to the lab tenant)

**This writes and deletes too.** `rpworker test` (W3.6, `docs/worker-config.md`, "`rpworker
test`") runs the same pipeline as `rpworker restore`, with its own table after the check and an
optional `--json` file, the run's result (`restoreproof.result.v1`, W4.1), or with `--evidence
<dir>` the run's folder (W4.2), signed (W4.3). Its ctest exe tests all stop before any request. Check the same
things first as for "Restore by hand": an elevated shell, no restore session still `Working`,
no other RestoreProof run.

The W3.6 Done-when is a live run that prints `status pass` with 30 of 30 items: 30 sent, 30
verified (`manifest 15, fields 5, metadata 10`), and no `shortfall` warning
(`docs/decisions.md` 2026-10-03, W3.6 point 2). The random SharePoint and OneDrive halves need
real, non-canary files in the lab, so this comes after L1.8:

1. Seed the real data: `python -m seeder seed-real` (L1.8, `lab/README.md`) puts files in the
   root of the RestoreTest site's `Shared Documents` and of alice's OneDrive, and mails between
   alice and bob. It never writes into a restore target or a canary location.
2. Let a backup run: the nightly `RP-Lab-Full` job, or start it by hand in the Veeam console.
   The new restore point must hold the seeded items.
3. Run the read-only dry run ("Live sample" above) against that restore point with a run ID you
   choose, and keep it:

   ```powershell
   $env:RP_LIVE = '1'
   $env:RP_LIVE_RUN_ID = 'w36-done-when-1'
   .\build\dev\rptests.exe "[sample][live]"
   ```

   Per type, `sample.<type>.random.pool_size` must be at least 5 distinct names or subjects, and
   `containers_eligible` as expected. Note the restore point ID it printed. The pool depends on
   the run ID (the folders it draws) and the restore point, so the run below reuses both.
4. With the vault filled as in "Restore by hand" step 2, run the test with that run ID and
   restore point, and a `--json` file in a folder that exists:

   ```powershell
   .\build\dev\rpworker.exe test --mail 10 --sp 10 --od 10 --run-id w36-done-when-1 --point <the dry run's restore point ID> --config <your config.json> --manifest ..\lab\seed-manifest.json --json C:\restoreproof-runs\w36-done-when-1.json
   ```

   `--json` refuses a file that is already there (exit 1, before any Veeam call): pick a new
   name each run. The output ends with the status line, the clean after's line, the step
   timings' table and `wrote <file>`. Exit 0 is `pass`, 5 `fail`, 1 to 4 an `error` by its code,
   as for `restore`. In the table after the check, `VERDICT` is `verified` for every row and
   `REASON` `-`.
5. Check with `rpworker graph list` that the targets are empty again, and keep the `--json`
   file with the evidence. It holds tenant data (`docs/verification.md`, "What of the tenant
   the result holds"): keep it out of the repository.

**The W4.1 Done-when run.** W4.1's Done-when is "`rpworker test --json` writes a file that
validates against the schema" (`docs/decisions.md` 2026-10-04, W4.1). The unit tests show it
on the recorded lab; this is the same thing once against the live lab. Check the same things
first as above (an elevated shell, no restore session still `Working`, no other RestoreProof
run, the vault of "Restore by hand" step 2), then, from `worker\`:

```powershell
.\build\dev\rpworker.exe test --mail 10 --sp 10 --od 10 --run-id w41-done-when-1 --config <your config.json> --manifest ..\lab\seed-manifest.json --json C:\restoreproof-runs\w41-done-when-1.json
```

The folder must exist, must be outside the repository, and the file must be new. The run ends
`status pass: ...`, the clean after's line, the timings' table and `wrote
C:\restoreproof-runs\w41-done-when-1.json`, exit 0 (`$LASTEXITCODE`). stderr must hold no
`result error:` and no `json error:` line. Then validate the written file offline, with
Python's validator against the repository's schema, and check that it is its own canonical
form. From `cloud\` (its dev group has `jsonschema`):

```powershell
uv run python -c "import json,sys,pathlib; from jsonschema import Draft202012Validator; b=pathlib.Path(sys.argv[1]).read_bytes(); d=json.loads(b); s=json.loads(pathlib.Path('../shared/schemas/result.v1.json').read_bytes()); errs=sorted(Draft202012Validator(s).iter_errors(d), key=lambda e: e.json_path); print('schema:', 'valid' if not errs else [e.json_path for e in errs]); print('canonical:', json.dumps(d, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8') == b)" C:\restoreproof-runs\w41-done-when-1.json
```

It must print `schema: valid` and `canonical: True`. (On an invalid file it prints where, as
JSON paths, never the values.) To read the file, `python -m json.tool
C:\restoreproof-runs\w41-done-when-1.json`; don't save a reformatted copy over it. Check
with `rpworker graph list` that the targets are empty again. The file holds tenant data: it
stays outside the repository, and only the output and the two lines above go into the evidence.

**The W4.2 Done-when run.** W4.2's Done-when is "a run folder contains result.json, the log,
items.csv and (optionally) a PNG, each hashed in the result" (`docs/decisions.md` 2026-10-05,
W4.2). The unit tests show it on the recorded lab (`rptests "[evidence]"`); this is the same
once against the live lab. It was run on 2026-10-05, before W4.3: since then `--evidence` also
needs the signing key and signs (the W4.3 run below), and the lines here are as a run prints
them now. Check the same things first as above, then, from `worker\`, in an
elevated shell:

```powershell
.\build\dev\rpworker.exe test --mail 10 --sp 10 --od 10 --run-id w42-done-when-1 --config <your config.json> --manifest ..\lab\seed-manifest.json --evidence C:\restoreproof-runs\evidence
```

**A hand run's `--evidence` root is a folder of its own, not
`%ProgramData%\RestoreProof\runs`.** Since W4.8 that root is the service's
(`docs/worker-config.md`, "The service's loop"). The service never closes, signs, queues or
uploads a folder it finds there, but it skips a job whose run ID names one (`skipped <run_id>:
a run folder is already there`), and a hand run there under a run ID the service is using is
refused (`the run folder already exists`). The runs of 2026-10-05 to 2026-10-07 below were
made into `%ProgramData%\RestoreProof\runs`, before the service had a body; their folders are
still there on the lab machine and the service leaves them alone. Any folder outside the
repository does, here `C:\restoreproof-runs\evidence`; `--evidence` makes it when it isn't
there.

The run ID must be new: a folder `evidence\w42-done-when-1` that is already there stops the run
before its run line (`evidence error: ...: the run folder already exists; nothing was done`).
`--evidence` can't be combined with `--json`. The run ends `status pass: ...`, the clean
after's line, the timings' table, `signed <bundle_sha256> key <key_id>` and `evidence
C:\restoreproof-runs\evidence\w42-done-when-1: result.json, signature.json, items.csv,
veeam-session.log`, exit 0, stderr empty. Then check the folder
offline: `result.json` valid by the repository's schema and its own canonical form, the files
beside it and `signature.json` exactly the ones `attachments` lists, and each with the size and
SHA-256 listed. From `cloud\`:

```powershell
uv run python -c "import hashlib,json,sys,pathlib; from jsonschema import Draft202012Validator; f=pathlib.Path(sys.argv[1]); b=(f/'result.json').read_bytes(); d=json.loads(b); s=json.loads(pathlib.Path('../shared/schemas/result.v1.json').read_bytes()); errs=sorted(Draft202012Validator(s).iter_errors(d), key=lambda e: e.json_path); print('schema:', 'valid' if not errs else [e.json_path for e in errs]); print('canonical:', json.dumps(d, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8') == b); print('files:', {a['name'] for a in d['attachments']} == {p.name for p in f.iterdir()} - {'result.json', 'signature.json'}); [print(a['name'], len(x) == a['size_bytes'], hashlib.sha256(x).hexdigest() == a['sha256']) for a in d['attachments'] for x in [(f/a['name']).read_bytes()]]" C:\restoreproof-runs\evidence\w42-done-when-1
```

It must print `schema: valid`, `canonical: True`, `files: True` and `True True` after each
attachment's name. With the default config `screenshot` is `{"state": "unavailable", "reason":
"disabled"}` and there is no PNG: no screenshot is taken today, whatever the setting
(`docs/verification.md`, "The run folder"). Check with `rpworker graph list` that the targets
are empty again. The folder holds tenant names (`items.csv`, `veeam-session.log`,
`result.json`): it stays where it is, outside the repository, and only the run's output, the
`graph list` afterwards and the check's lines go into the evidence.

**The W4.3 Done-when run.** W4.3's Done-when is "the C++ and the Python verifier
agree on a real bundle" (`docs/decisions.md` 2026-10-05, W4.3 point 6). The shared vectors show
it offline for 38 folders ("The shared signing vectors" below); this is the same on a live
run's folder. Run on 2026-10-05 (`w43-done-when-1`: `status pass`, both tools printing the same
line for the folder and for each of the five changed copies; evidence
`docs/api/veeam-lab/w4.3-live-*`, build notes point 22). It needs an elevated shell and the
lab's signing key:

1. Make the lab's key once, from `lab\`, with the public PEM in a folder outside the
   repository (`lab/README.md`, "The signing key"), and note its `key <key_id>` line:

   ```powershell
   uv run python -m seeder new-signing-key --public-key-out C:\restoreproof-runs\worker-signing.pub.pem
   ```

2. In the elevated shell, from the repository's root, `.\lab\entra\fill-worker-vault.ps1` must
   end with `vault list` naming all five secrets, `signing_key_base64` among them (W4.5). Then
   from `worker\`:

   ```powershell
   .\build\dev\rpworker.exe test --mail 10 --sp 10 --od 10 --run-id w43-done-when-1 --point <restore point ID> --config <your config.json> --manifest ..\lab\seed-manifest.json --evidence C:\restoreproof-runs\evidence
   ```

   It must end `status pass: ...`, the clean after's line, the timings' table, `signed
   <bundle_sha256> key <key_id>` with step 1's key ID, and `evidence ...: result.json,
   signature.json, items.csv, veeam-session.log`, exit 0, stderr empty.
3. Verify the folder with both tools ("Verify a run folder by hand" below): both must print
   the same `verified <bundle_sha256> key <key_id>` line, with the hash `Get-FileHash` gives
   for `result.json`.
4. Copy the folder five times, outside the repository, and change one thing in each; both
   tools must print the same line each time:

   | Change | Both print |
   |---|---|
   | one digit of an item's hash in `result.json` | `not verified: hash_mismatch` |
   | one Base64 character of `signature` in `signature.json`, its length and its last three characters kept | `not verified: signature_invalid` |
   | one byte of `items.csv` | `not verified: attachment_hash` |
   | `veeam-session.log` removed | `not verified: attachment_missing` |
   | nothing; RFC 8032's test key given as `--public-key` (the `public_key_pem` of `rfc8032-test-1` in `shared/testdata/signing-v1/keys.json`, written to a file with LF line ends) | `not verified: wrong_key` |

   Change the two JSON files with an editor that adds no newline at the end and no BOM: either
   makes the file `result_not_canonical` or `signature_file` instead.
5. Check with `rpworker graph list` that the targets are empty again. Evidence
   `docs/api/veeam-lab/w4.3-live-*`: the run's output, both tools' lines for the six folders
   and the `graph list` afterwards. The folders and the lab's public key stay outside the
   repository.

**The W4.4 Done-when run.** W4.4's Done-when is "openssl ts -verify on the extracted token
succeeds against the bundle hash" (`docs/decisions.md` 2026-10-06, W4.4); the token is the
folder's `timestamp.tst`, so there is nothing to extract. Run on 2026-10-06 (`w44-done-when-1`:
`status pass`, `timestamped 2026-10-06T21:19:24Z`; evidence `docs/api/veeam-lab/w4.4-live-*`,
build notes point 15). The same command as W4.3's run above with a new run ID (and `--record
<a new folder outside the repository>` to keep the TSA's exchange): it must end `signed ...`,
`timestamped <time>` and an `evidence` line that lists `timestamp.tst`, exit 0, stderr empty.
Then steps 3 to 5 of "Verify a run folder by hand" below, with `--tsa-ca
shared\tsa\tsa-ca.pem` for both tools: `Verification: OK` from OpenSSL for `-digest` and for
`-data`, and one line from both verifiers whose third field is the token's time. To see a run
without a TSA, copy the config, set `tsa_url` to `http://127.0.0.1:9/` and `tsa_ca_file` to the
full path of `shared\tsa\tsa-ca.pem`, and run again with another run ID: the same status and
exit code, one `timestamp warning: ... tsa_unreachable after 3 attempt(s)` on stderr, a folder
without `timestamp.tst`, about 90 s later than usual.

**The W4.5 Done-when run.** W4.5's Done-when is "no secret is read from the environment or a
config file anywhere in the code" (`docs/decisions.md` 2026-10-07, W4.5): the unit tests inject
secrets through each command's seam and the vault's own tests use files of their own; the live
part is one run from the vault alone. Run on 2026-10-07 (`w45-done-when-1`: `status pass`, 30
of 30, signed and `timestamped 2026-10-07T01:01:31Z`; evidence `docs/api/veeam-lab/w4.5-*`).
From an elevated shell with no `RP_*` secret variable set: `.\lab\entra\fill-worker-vault.ps1`
from the repository's root (five `set <name> in C:\ProgramData\RestoreProof\vault.bin` lines
and `vault list`), `rpworker config check --config <config>` showing the five names from the
vault, then the same command as W4.4's run above with a new run ID: it must end `signed ...`,
`timestamped <time>` and the `evidence` line, exit 0, stderr empty, and `graph list` 0 in all
three targets. Then the service account reads the same vault: the W4.12 harness once more
(`docs/api/veeam-lab/w4.5-harness/w45-service-run.ps1`, the host serving nothing over its pipe)
with `rpworker vault grant "NT SERVICE\RpSpikeProbe"` and the key file's ACE: `rpworker restore
--mail 1 --sp 0 --od 0` as the virtual account, 1 of 1, `status pass`, exit 0; without the grant
`config error: C:\ProgramData\RestoreProof\vault.bin: the vault file can't be read`, exit 1,
before any Veeam call. Everything temporary is taken away by the harness's `Remove-W45Harness`;
`vault.bin` stays.

### Verify a run folder by hand (W4.3)

Read-only, offline, no config and no secret. The two tools must agree on the stdout line
(`docs/verification.md`, "The checks, and the thirteen words"); their exit codes are their
own. `<run folder>` below is the run's folder wherever it is: `<--evidence root>\<run_id>` for
a hand run, `%ProgramData%\RestoreProof\outbox\<run_id>` or `sent\<run_id>` for a queued or a
sent one, the service's runs included.

1. **The public key.** The file the Worker's key was exported to: `new-signing-key
   --public-key-out <file>` in the lab, or, from the vault (from `worker\`, PowerShell 7; an
   account the vault's ACL admits):

   ```powershell
   .\build\dev\rpworker.exe signer public-key > C:\restoreproof-runs\worker-signing.pub.pem
   ```

   stdout is the PEM alone, three lines; the `key <key_id>` line goes to the console (stderr).
   In Windows PowerShell 5.1 `>` writes UTF-16, which is no key file: use `| Set-Content
   -Encoding ascii <file>` there. Take the key from where you trust it, never from the run
   folder.
2. **The hash.** `bundle_sha256` is `result.json`'s own SHA-256:

   ```powershell
   (Get-FileHash <run folder>\result.json -Algorithm SHA256).Hash.ToLower()
   ```

3. **The Worker's verifier**, from `worker\`:

   ```powershell
   .\build\dev\rpworker.exe signer verify <run folder> --public-key C:\restoreproof-runs\worker-signing.pub.pem
   $LASTEXITCODE
   ```

   `verified <bundle_sha256> key <key_id> timestamp <time | none | unchecked>` and 0, or `not
   verified: <word>` and 5. Exit 1 with a `signer error: ...` line means the folder, the key
   file or the `--tsa-ca` file couldn't be read: no verdict. Add `--tsa-ca
   ..\shared\tsa\tsa-ca.pem` (the default TSA's root) to have the timestamp checked: the third
   field is then the token's own time; without it a folder that has a token says `unchecked`.
4. **The auditor's verifier**, from the repository's root. It is one file; `uv` reads its
   dependencies from the file's own header (`asn1crypto`, `cryptography`, `jsonschema`, Python
   3.12 or later) and downloads them on the first run. It takes `--tsa-ca <pem file>` too
   (`--tsa-ca shared/tsa/tsa-ca.pem`):

   ```powershell
   uv run shared/tools/verify_bundle.py <run folder> --public-key C:\restoreproof-runs\worker-signing.pub.pem
   $LASTEXITCODE
   ```

   The same line, and 0, or `not verified: <word>` and 1. Exit 2 with an `error: ...` line
   means the folder, the key or a schema couldn't be read, the command line was wrong (an
   option given twice included), a package is missing (run with plain `python` instead of `uv
   run`) or the verdict couldn't be written to stdout: no verdict. It finds the two schemas in `shared/schemas/` beside itself; `--schemas <dir>`
   names another folder holding `result.v1.json` and `signature.v1.json`. Away from the
   repository an auditor needs the script, the two schema files, the Worker's public PEM and
   the folder with every listed attachment.
5. **The timestamp, with OpenSSL alone** (W4.4; Git for Windows has `openssl` in
   `C:\Program Files\Git\mingw64\bin`). `timestamp.tst` is the TSA's token over `result.json`'s
   own hash, so no tool of ours is needed, from the run folder:

   ```powershell
   openssl ts -verify -data result.json -in timestamp.tst -token_in -CAfile C:\restoreproof\shared\tsa\tsa-ca.pem
   openssl ts -verify -digest <bundle_sha256> -in timestamp.tst -token_in -CAfile C:\restoreproof\shared\tsa\tsa-ca.pem
   openssl ts -reply -in timestamp.tst -token_in -text
   ```

   `Verification: OK` twice; the third prints the token's time, policy and serial number.
   OpenSSL checks the TSA's certificates at today's date: once they have expired, add `-attime
   <seconds since 1970 of the token's time>`. Both of our verifiers check them at the token's
   own time.
6. **The key's ID** is the SHA-256 of the 44 bytes the PEM's Base64 line decodes to; it must
   be the `key_id` in `signature.json` and in both `verified` lines:

   ```powershell
   $der = [Convert]::FromBase64String(((Get-Content C:\restoreproof-runs\worker-signing.pub.pem | Where-Object { $_ -notmatch '^-----' }) -join ''))
   -join ([Security.Cryptography.SHA256]::Create().ComputeHash($der) | ForEach-Object { $_.ToString('x2') })
   ```

A name in the folder that the result doesn't list is a `note: not listed in the result:
<name>` line on stderr from both, and still `verified`. A relative folder whose name starts
with `-` is an option to the script: give it as `.\-name` or by its full path. To try the
tools without a live run, write the four files of `shared/testdata/signing-v1/bundle.json`
(`files`, each string's UTF-8 with nothing added) into an empty folder and give the
`public_key_pem` of `rfc8032-test-1` from `keys.json`: both print `verified 572bf1f9...81bf key
06e3fd8f...2fa9 timestamp none`, and `note: not timestamped` on stderr.

### The outbox by hand (W4.6)

`rpworker test --evidence <dir> --outbox <root>` queues the run's folder and `rpworker outbox
flush` uploads it (`docs/worker-config.md`, "`--outbox <root>`" and "`rpworker outbox`";
`docs/verification.md`, "The outbox"). The unit tests cover both on temp folders with a fake
uploader and a fake Cloud (`tests/outbox_test.cpp`, `tests/uploader_test.cpp`,
`tests/outbox_command_test.cpp`, `tests/test_command_test.cpp` `[outbox]`); none sends
anything. `rpworker outbox list` and `outbox flush` on an empty root are safe to run anywhere.

**The Cloud is a stub until W5.1.** There is no `/v1/results` yet, so the W4.6 Done-when run
uploads to a stub kept as text, `docs/api/veeam-lab/w4.6-harness/stub-cloud.py`: Python's
`http.server` over TLS on `https://localhost:8443`, which answers 202 once it has read the
whole body and prints each part's name, size and SHA-256, never a body; `--slow` makes it
sleep 20 s after the body's first 1024 bytes, so it can be killed in the middle of an upload.
`w46-run.ps1` beside it makes the stub's certificate (self-signed, `CN=localhost`, with Git's
`openssl`), a copy of the lab config with `cloud_url` and `cloud_ca_file` pointing at the stub,
starts and kills the stub, and saves evidence under the W4.5 harness's rule (refused if a
secret, a token or a key survives). Everything it makes is under `%TEMP%\rp-w46`.

The Done-when ("killing the network mid-upload leaves the run in the outbox and it uploads
later"), from an elevated PowerShell 7, the vault the only source of secrets:

```powershell
. docs\api\veeam-lab\w4.6-harness\w46-run.ps1
Initialize-W46Harness
# (a) a run, queued
worker\build\dev\rpworker.exe test --mail 10 --sp 10 --od 10 --run-id <run id> --point <restore point ID> `
    --config $W46Config --manifest lab\seed-manifest.json `
    --evidence C:\restoreproof-runs\evidence --outbox $env:ProgramData\RestoreProof
worker\build\dev\rpworker.exe outbox list
# (b) the Cloud down: kept, attempt 1, exit 3
worker\build\dev\rpworker.exe outbox flush --config $W46Config
# (c) the Cloud lost in the middle of the upload: kept, attempt 2, the folder unchanged
Start-W46Stub -Slow     # then, once the wait of (b) is over, the flush in a second shell,
Stop-W46Stub            # and this while the stub sleeps
# (d) the Cloud up: sent, exit 0
Start-W46Stub
worker\build\dev\rpworker.exe outbox flush --config $W46Config
Get-W46StubLog          # every part, with the sizes result.json lists
# (e) the sent folder still verifies
worker\build\dev\rpworker.exe signer verify $env:ProgramData\RestoreProof\sent\<run id> `
    --public-key <pem file> --tsa-ca shared\tsa\tsa-ca.pem
Remove-W46Harness
```

Between (b) and (c) the run isn't due for a minute, and between (c) and (d) for two: a flush
before then prints `waiting <run id>: next at <time>` and sends nothing. Compare the queued
folder before and after (c) with `Get-W46Hashes <folder>`: only `manifest.json` differs.
`rpworker graph list` must show 0 in all three targets afterwards, as after any run. The sent
folder stays outside the repository; the 2026-10-07 run's evidence is
`docs/api/veeam-lab/w4.6-*`. That run's `--evidence` root was `%ProgramData%\RestoreProof\runs`;
since W4.8 it is a folder of its own on the outbox root's volume ("Test by hand" above). Run
this with the service stopped or not installed: a running service flushes the same outbox
(`%ProgramData%\RestoreProof`) at every poll, with its own config's `cloud_url`.

### The service by hand (W4.7)

`rpworker service install|uninstall|start|stop` act on the machine's real service, so no
automated test runs them (`docs/worker-config.md`, "`rpworker service`"). What the tests cover:

- `tests/service_command_test.cpp`: the five commands on a fake Service Control Manager
  (`tests/service_lab.hpp`), every refusal with its exact line and exit code, the waits on a
  fake clock.
- `tests/service_test.cpp`: the running service on a fake host: every status it reports, in
  order, for each way it can start, stop and fail.
- `tests/service_log_test.cpp`: the log file: redaction, the `SECURITY: ` rule at every
  level, one message one line, rotation at a small limit.
- `tests/scm_test.cpp`: the real calls. Unelevated they only ask about a name that isn't
  installed. Elevated, one test creates a service named `RestoreProofScmTest` (disabled, its
  executable a file that doesn't exist, so it can never run), reads it back and deletes it; it
  first deletes one a cut-off run left. The same file holds the source scan: only
  `src/scm.cpp` may name a Windows service function or a call that ends the process, and no
  Worker source may name a call that starts one. The scan reads comments too.
- The exe tests: `service` alone, an unknown subcommand, a word too many, `--config` without
  a value, and `service run` from a console. **None names `install`, `uninstall`, `start` or
  `stop`**, and none may.

The Done-when ("installs, starts on boot, stops cleanly within 30 s, logs rotate") is run by
hand from an elevated PowerShell 7 with `docs/api/veeam-lab/w4.7-harness/w47-run.ps1`:

```powershell
. docs\api\veeam-lab\w4.7-harness\w47-run.ps1
Initialize-W47Harness                 # a copy of the lab config the service's account can read
# (a) install; what Windows holds
Invoke-W47 @('service','install','--config',$W47Config)
Get-W47Setup                          # sc qc, sc qfailure, sc qdescription, FailureActions
# (b) start; whose process it is
Invoke-W47 @('service','start'); Get-W47Process; Get-W47Log
# (c) a crash: Windows starts it again after a minute
$since = Get-Date; Stop-W47Process; Start-Sleep 75; Get-W47Process; Get-W47Events $since
# (d) restart the machine, sign in, open an elevated PowerShell 7 again
Get-W47Process                        # running, its start right after the boot
# (e) stop
Invoke-W47 @('service','stop'); Get-W47Log
# (f) rotation with the real limit, blocked by a reader and then made, and the search for secrets
Add-W47Filler; Invoke-W47StartWhileHeld; Invoke-W47 @('service','stop'); Get-W47Log; Test-W47LogSecrets
# (g) a restart queued, and the uninstall inside its minute; nothing installed
Invoke-W47 @('service','start'); Stop-W47Process; Invoke-W47 @('service','uninstall'); Start-Sleep 70; Get-W47Process
Remove-W47Harness
```

`sc qc RestoreProof` answers 1060 afterwards. The 2026-10-08 run's evidence is
`docs/api/veeam-lab/w4.7-*`. `services.msc` held open on the service keeps it "marked for
deletion" after an uninstall until it is closed.

### The service's loop by hand (W4.8)

The loop is the body of `rpworker service run` (`docs/worker-config.md`, "The service's loop";
`docs/decisions.md` 2026-10-08, W4.8). It has no command of its own, so no exe test starts it,
and no automated test waits, starts the service or touches `%ProgramData%`. What the tests
cover:

- `tests/service_loop_test.cpp` (`[service_loop]`): the loop on `ServiceLoopEnv` fakes
  (`tests/service_loop_lab.hpp`: `LoopLab`, a fake clock whose `wait` advances it and answers
  a stop at a scripted step, the log's lines, every call in order). What is due and in which
  order, each job's rule and its line, the record's writes, the close and its retries, the
  hold's table, the heartbeat, the flush, a step that throws, a stop at every point.
- `tests/service_recovery_test.cpp` (`[service_recovery]`): `running.json`'s text after each
  write and its strict reader, the plan for a folder at every point a kill can leave it, the
  close on fakes, the result written afterwards for each code, the hold's rule, when the
  record goes.
- `tests/service_jobs_test.cpp` (`[service_jobs]`): the jobs document, one `GENERATE` row per
  document and per job against the exact `jobs error` line or the key at fault.
- `tests/service_log_stream_test.cpp` (`[service_log_stream]`): a run's lines as log lines.
  `tests/service_errors_test.cpp` (`[service_errors]`): the heartbeat's `last_error` words.
  `tests/heartbeat_test.cpp` (`[heartbeat]`): the body's exact bytes and each failure word, on
  the local HTTP server.
- `tests/worker_body_test.cpp` (`[worker_body]`): the real body over a temp folder, the
  command tests' Harness, a fake Cloud and a fake lock: one job from the stub file to `sent\`
  with every line, a killed run's folder closed, signed and queued at every point a kill can
  leave it, the hold and the recovery clean, the abandoned run mutex, and `service run` on the
  fake host with the real body. Its `[owner]` tests give a file to another account and skip
  unless elevated ("Running the gates locally" below). The hidden `[.write_shared_closed]`
  writes the shared closed folder ("The shared signing vectors" below).
- The pipeline's side, in the files that were there: `tests/test_command_test.cpp` `[report]`
  (`PipelineReport` at every way out of `run_pipeline`) and `[stop]`;
  `tests/restore_command_test.cpp` `[stop]` (a stop at each step boundary), `[job_rules]` (the
  rules a command line and a job share, `src/job_rules.hpp`) and `[recovery_clean]`
  (`clean_restore_targets`); `tests/evidence_builder_test.cpp` `[adopt]` (the text files a
  close keeps or replaces); `tests/timestamper_test.cpp` `[stop]`; `tests/outbox_test.cpp`
  `[stop]`, `[holds]` and `[lock]`; `tests/vault_test.cpp` `[owner]` (the owner rule as a
  function of its own); `tests/veeam_m365_restore_test.cpp`,
  `tests/veeam_m365_connector_test.cpp`, `tests/veeam_m365_candidates_test.cpp` and
  `tests/connector_test.cpp` `[w4.8]` (the record's seams, no POST after a stop, the poll
  ended by a stop, `own_sessions`, `end_session`); `tests/config_test.cpp` and
  `tests/config_check_test.cpp` `[jobs]` (`jobs_file`); `tests/run_status_test.cpp` (the two
  codes).
- One exe test: `rpworker config check refuses a jobs_file that isn't an absolute path`.

`rptests.exe "[service_loop],[service_recovery],[service_jobs],[service_log_stream],[service_errors],[heartbeat],[worker_body]"`
runs the new files alone.

**By hand.** The Done-when ("dropping a job into the stub file produces a signed bundle in the
outbox within one poll interval") is run on the lab machine with the harness
`docs/api/veeam-lab/w4.8-harness/`: `w48-run.ps1`, which is W4.7's `w47-run.ps1` grown by the
grants, the config copy, the jobs file and the reads of `running.json` and the folders, and
`stub-cloud.py`, W4.6's stub Cloud with `POST /v1/heartbeat` answering 204 and printing the
body. `w48-done-when.ps1` beside them runs steps (a) to (g) in one go and saves each step's
text as evidence when the step has ended (`docs/api/veeam-lab/w4.8-1` to `w4.8-7`). The steps
below are the commands they wrap. The live run of 2026-10-09: `docs/decisions.md`, "W4.8 build
notes", point 5.

This writes into the lab tenant and deletes there, as every run does. Before the first step:

- **An elevated PowerShell 7**, no restore session of the Veeam account still `Working`, no
  other RestoreProof run, the vault filled with all five secrets (`rpworker vault test`), the
  signing key among them: every run of the service signs.
- **The stub Cloud** on `https://localhost:8443` with its own certificate, as for "The outbox
  by hand".
- **A config copy** in a work folder of its own outside the repository (`<work>` below, which
  also holds the stub's CA file and the jobs file): the lab's config with `jobs_file` (an
  absolute path, `<work>\jobs.json`; the file needn't exist yet), `cloud_url` and
  `cloud_ca_file` of the stub, `poll_interval_s` 30 and `heartbeat_interval_s` 60, and
  **`seed-manifest.json` copied beside it**: the service finds the manifest beside its config
  and has no `--manifest`. The service reads the config once, at its start.
- **The jobs file's owner** must be SYSTEM, Administrators or the service's account, or the
  loop reads nothing from it (`jobs error: <file>: owned by neither SYSTEM, Administrators nor
  this account`). A file written from the elevated shell is owned by Administrators;
  `(Get-Acl <jobs file>).Owner` shows it.
- **W7.1 isn't built**, so nothing grants the account `NT SERVICE\RestoreProof` what the loop
  needs: step 2 makes the grants by hand and step 12 takes them away.
- The folders of earlier hand runs under `%ProgramData%\RestoreProof\runs` stay where they
  are. List them before and after: they must be untouched.

1. **Install.** The account exists only once the service is installed.

   ```powershell
   worker\build\dev\rpworker.exe service install --config <config copy>
   ```

2. **Grant**, and keep `icacls` of the vault and of the key file from before and after:

   ```powershell
   $acct = 'NT SERVICE\RestoreProof'
   $root = "$env:ProgramData\RestoreProof"
   worker\build\dev\rpworker.exe vault grant $acct
   icacls "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\<UniqueKeyContainerName>" /grant "${acct}:(R)"
   foreach ($d in 'state','runs','outbox','sent') {
       New-Item -ItemType Directory -Force "$root\$d" | Out-Null
       icacls "$root\$d" /grant "${acct}:(OI)(CI)M"
   }
   icacls '<work>' /grant "${acct}:(OI)(CI)R"
   ```

   The key file is the private key of Veeam's organisation app certificate (W4.12; "The restore
   credential under a service account" above). Read on `<work>` is inherited by the config
   copy, the manifest, the stub's CA file and every jobs file written or renamed there. Modify
   on the four folders and Read on `<work>` is all the account gets; a `veeam_ca_file` or
   `tsa_ca_file` kept elsewhere needs Read too.
3. **Start.** Start the stub, then `rpworker service start`. `worker.log`
   (`%ProgramData%\RestoreProof\logs\worker.log`) must hold `scheduler started: poll 30 s,
   heartbeat 60 s, jobs <jobs file>, runs C:\ProgramData\RestoreProof\runs, outbox
   C:\ProgramData\RestoreProof`, and the stub shows a heartbeat at once and one a minute:
   `{"last_error":null,"last_error_at":null,"outbox_depth":0,"uptime_s":<n>,"version":"<rpworker's>"}`.
4. **Drop a job.** From the elevated shell, write the document under another name in `<work>`
   and rename it to `jobs.json`, so the loop never reads half a file, and note the time:

   ```json
   {"format": "restoreproof.jobs.v1",
    "jobs": [
      {"run_id": "w48-job-1", "client_id": null,
       "sample_mail": 5, "sample_sp": 5, "sample_od": 5,
       "restore_point": "latest", "screenshots_enabled": false}
    ]}
   ```

5. **Watch `worker.log`** (`Get-Content <worker.log> -Wait -Tail 20`). No later than one poll
   interval after the file's time: `run w48-job-1: starting (mail 5, sharepoint 5, onedrive 5,
   point latest)`. Then the run's own lines, each as `[w48-job-1] <line>`, what `rpworker test
   --evidence --outbox` prints at a prompt: the restore point, the run line, the sample, the
   check's table, `status pass: ...`, `cleanup after ok: ...`, the timings, `signed
   <bundle_sha256> key <key_id>`, `timestamped <time>`, the `evidence` line and `queued
   C:\ProgramData\RestoreProof\outbox\w48-job-1`. Then `run w48-job-1: ended pass; queued` and,
   from the flush the loop makes right after the run, `sent w48-job-1`. The job is taken within
   one poll interval; its folder is in the outbox when the run has ended, some minutes later.
6. **The folders.** `runs\w48-job-1` and `outbox\w48-job-1` are gone and `sent\w48-job-1` holds
   `result.json`, `signature.json`, `timestamp.tst`, `items.csv`, `veeam-session.log` and
   `manifest.json`; the loop flushes at once, so the folder may only ever be seen under
   `sent\`. `state\running.json` is gone. `rpworker outbox list` counts no queued run and one
   sent. The stub printed every part with the sizes and hashes `result.json` lists. `rpworker
   graph list` shows 0 in all three targets.
7. **The verifiers**, both on `sent\w48-job-1` with the Worker's public key and `--tsa-ca
   shared\tsa\tsa-ca.pem` ("Verify a run folder by hand" above): the same `verified
   <bundle_sha256> key <key_id> timestamp <time>` line from both, with `note: not listed in the
   result: manifest.json` on stderr.
8. **The same job is skipped.** Leave the jobs file as it is for two more polls: one line,
   `skipped w48-job-1: already sent`, and no second `starting` line.
9. **A kill in the middle of a run.** Put a second job (`w48-job-2`) in the file. Read
   `state\running.json` until it says `"restore_requested":true`, then end the process:

   ```powershell
   Stop-Process -Id (Get-CimInstance Win32_Service -Filter "Name='RestoreProof'").ProcessId -Force
   ```

   `runs\w48-job-2` is empty and `running.json` is still there. Windows starts the service
   again after 60 s. **What the next start does**, from the record alone: `scheduler started:
   ...`, then `interrupted run w48-job-2 found: taken <time>, restore requested yes`; the
   folder is closed by the run's own signing path (`[w48-job-2] signed ...`, `[w48-job-2]
   timestamped <time>`, `[w48-job-2] queued <outbox folder>`, then `run w48-job-2: queued`)
   and sent. Its `result.json` says `error` `interrupted` with `restore_sent` `true`, every
   step `null`, and the message `the run was interrupted before its result was written; a
   restore request may have been sent, so items may be in the restore targets`; `items.csv` is
   its header row alone and `veeam-session.log` is empty. Then the hold: while a session of the
   Veeam account that the record doesn't list is running, nothing is ended and no job starts
   (`waiting for Veeam: <n> session(s) of <account> still Working since <time>`, once and again
   every hour); when none is, and 120 s have passed, the explore sessions the record lists are
   ended. Then `recovery clean for w48-job-2:` and `[w48-job-2] cleanup before ok: deleted
   ...`, and the record is deleted. `graph list` shows 0 in all three targets, and both
   verifiers say `verified` for `sent\w48-job-2`. No other job starts before the record is
   gone.
10. **A stop during a run.** A third job; during its restore:

    ```powershell
    worker\build\dev\rpworker.exe service stop        # stopped RestoreProof in <s.s> s, under 30
    Get-Content $env:ProgramData\RestoreProof\state\running.json
    worker\build\dev\rpworker.exe service start
    ```

    The record of a run that reached its run line is kept across a stop, so the start writes
    `interrupted run <run_id> found: ...` in both of the two cases. When the stop check ended
    the run inside the 25 s, the run signed and queued itself as `error interrupted` (`status
    error interrupted: ...` among its lines, and no token: the TSA isn't asked after a stop)
    and nothing is closed again. When
    the process was cut off first, the folder is closed at the start as step 9's was. Either
    way: sent, the hold, the clean when a restore was requested, the record gone, `graph list`
    0. The table of what a stop leaves is in `docs/worker-config.md`, "A stop during a run".
11. **An invalid job, and a file that is no document.** A job with all three sizes 0: `job
    <run_id>: not a valid job (sample_mail)`, then a folder closed, signed, queued and sent
    whose result says `error` `job_invalid`, `the job isn't a valid job (sample_mail); nothing
    was done`. Nothing is asked of Veeam or Graph for it, and from then on the job is skipped
    as `already sent`. Then a jobs file that isn't JSON: `jobs error: <file>: not JSON`, once,
    and `"last_error":"jobs_unreadable"` in the next heartbeat. A job without a usable `run_id`
    is not reported at all: `job <n> of <file>: no usable run_id; not run`.
12. **Revoke, before the uninstall.** `rpworker service stop`, then take away everything step 2
    gave while the account's name still resolves; after the uninstall `NT SERVICE\RestoreProof`
    names nothing and the entries could only be removed by their SID:

    ```powershell
    icacls "$root\vault.bin" /remove $acct
    icacls "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\<UniqueKeyContainerName>" /remove $acct
    foreach ($p in "$root\state","$root\runs","$root\outbox","$root\sent",'<work>') {
        icacls $p /remove $acct
    }
    ```

    `icacls` of the vault and of the key file must show what they showed before step 2.
13. **Uninstall.** `rpworker service uninstall`; `sc query RestoreProof` answers 1060. Take
    away `<work>` and the stub; keep the `sent\` folders of these runs, outside the repository.
    `vault.bin` stays.

If a step leaves the loop held (a session that stays `Working`, a folder that can't be closed
or queued), the two ways out are in `docs/worker-config.md`, "The operator's two ways out".
Evidence goes under `docs/api/veeam-lab/w4.8-*` as text, by the W4.5 harness's rule: refused if
a secret, a token or a key survives.

### Recording fixtures (`--record <dir>`)

Q2.1: `rpworker veeam list`, `graph list [--hash]`, `restore` and `test` take `--record <dir>`, which
writes every exchange the command has with a service, scrubbed, as a fixture
`FakeHttpClient` can serve (the format and rules: `docs/decisions.md` 2026-10-01, "Q2.1").
Recording only watches: the command sends and prints what it would without it, then one more
line, `recorded <n> exchange(s) in <dir>`. `restore --record` still writes into the tenant,
and records the cleanup's listings, `permanentDelete`s and `DELETE`s under `graph` too.

The W3.4 Cleaner's listings and 204s are recorded (`worker/tests/fixtures/recordings/w34-live-run1/`),
and so are the answers to a delete sent twice: the live cleanup test sends its first file
`DELETE` and first mail `permanentDelete` twice (the test-side wrapper `SendFirstDeleteTwice`)
and, with `RP_LIVE_RECORD_DIR` set to a new or empty folder, records every Graph exchange there
under `graph/`, the second answers included; its 2026-10-02 run gave the file's 404 and the
mail's 403 `ErrorCannotDeleteObject` (`worker/tests/fixtures/graph/README.md`). The 412, the
refusing 403s and Exchange's 404 stay hand-written; no Worker code ever sends a write at a
canary location to record a refusal.

1. Pick a folder that doesn't exist yet, outside the repo (for example
   `$env:TEMP\rp-rec-<what>`). The command refuses a folder with anything in it, so a
   recording never lands on committed fixtures.
2. With the vault filled as for the live tests (`..\lab\entra\fill-worker-vault.ps1`), run
   the command with `--record`:

   ```powershell
   .\build\dev\rpworker.exe veeam list --config <your config.json> --record $env:TEMP\rp-rec-veeam-list
   ```

3. Read what came out: `<dir>\veeam\`, `<dir>\graph\` and `<dir>\download\`, one file per
   exchange, `001-post-v8-token.json` and so on. A `record error: <file>: refused: ...` line
   means that exchange still held a secret after scrubbing and was not written (exit 1 if the
   command had succeeded); the rest were. Nothing in a file may be secret: no request header,
   no form body, no token (`[REDACTED]`), no download link's credential (`SCRUBBED`), no
   downloaded bytes (`body_size` and `body_sha256` only).
4. Copy the files you want into `worker/tests/fixtures/<service>/` (a subfolder per recording
   keeps a run's files together), and replay them in a test:

   ```cpp
   rp::test::FakeHttpClient veeam;
   veeam.serve_recording(std::filesystem::path{RP_FIXTURE_DIR} / "veeam" / "<recording>");
   ```

   `serve_recording` routes each file by its method and path (the request line; any host), and
   serves the files of one request in number order, the last one repeating. `on_path(method,
   "/v8/RestoreSessions/*", ...)` adds a route by pattern (`*` within one path segment), for a
   query a test's clock changes. A `download` file has no bytes to serve and throws if asked;
   give the test its own bytes.
5. Delete the recording folder when done.

### The network guard and the network-off run

Unless `RP_LIVE=1`, `rptests` runs with the network guard on (`tests/test_main.cpp`): the HTTP
client refuses any host outside `localhost`, `127.x.x.x` and `[::1]` before looking it up, and
any socket to an address outside 127.0.0.0/8 and ::1. A test case during which it refused
anything is named on stderr (`NETWORK GUARD: "<test>" tried to connect ...`) and fails the run,
even if its own checks passed. CI runs every test this way.

The Q2.1 "Done when" is also checked once by hand, with no network at all:

1. Build as usual (`cmake --build --preset dev`), with the network on: vcpkg may need it.
2. Turn the network off. Settings → Network & Internet → Advanced network settings (on
   Windows 10: Change adapter options), right-click each adapter (Wi-Fi, Ethernet) →
   **Disable**. Or unplug the cable and turn Wi-Fi off.
3. Make sure `RP_LIVE` isn't set (`Remove-Item Env:RP_LIVE -ErrorAction SilentlyContinue`), and
   run `ctest --preset dev` from `worker/`. Every test passes and the `[live]` ones show as
   skipped.
4. Turn the adapters back on (right-click → **Enable**).

### The shared vectors and result documents (W4.1)

Three sets of files under `shared/` are read by both builds, so C++ and Python are shown to
agree. All are LF on every checkout (`.gitattributes`); the schema's bytes are what the Worker
embeds.

| File | What | C++ test | Python test |
|---|---|---|---|
| `shared/schemas/result.v1.json` | the result's schema, the only copy | `worker/tests/result_schema_test.cpp` (`[result_schema]`): the embedded bytes are the file's, only the allowed keywords, the seventeen keys, the enums against the code | `cloud/tests/test_result_schema.py`: `check_schema`, `$schema` is draft 2020-12 |
| `shared/testdata/canonical-json-v1.json` | `canonical-json-v1`: 33 `cases` (`input`, `canonical`, `sha256`) and 9 `rejects` (`input_text`, `reason`: `float`, `integer_out_of_range` or `non_ascii_key`) | `worker/tests/canonical_json_test.cpp` (`[canonical_json]`): every case and every reject; invalid UTF-8, which a JSON file can't hold, on bytes | `cloud/tests/test_canonical_json.py`, since W4.3 on the Python canonicaliser in `shared/tools/verify_bundle.py` (`parse_strict`, `canonical_json`), loaded by path: the 33 cases byte for byte, the 9 rejects by their reason, and what a vector's JSON text can't hold built in the test (a duplicate key, a BOM, `NaN`, invalid UTF-8, a lone surrogate, 33 levels of nesting) |
| `shared/testdata/result-v1/valid.json` | a valid result, as canonical bytes | `worker/tests/test_command_test.cpp`: the pipeline's run reproduces it byte for byte | `test_result_schema.py`: valid, and equal to its own canonical dump |
| `shared/testdata/result-v1/cases.json` | 185 documents, each `valid.json` with an RFC 6902 `patch` (add, remove, replace) and whether the schema accepts it (`valid`): 47 valid, 138 invalid (three hold W4.3's cut of `containers_listed` to the count `containers_drawn`; the two newest, both valid, are W4.8's results written afterwards, `written-afterwards-error-interrupted-every-step-null` and `written-afterwards-error-job-invalid-nothing-known`, and the made-up code of `status-unknown-error-code` is now `teapot`, since `job_invalid` is a real one). Both sides pin the counts | `result_schema_test.cpp`, one `GENERATE` row per case | `test_result_schema.py`, one parametrised test per case |

The Python tests find `shared/` by walking up from their own file, so they also run from
mutmut's copy. The Worker tests read it through `RP_SHARED_DIR`. No case holds a float:
Python's validator reads `1.0` as an integer and the C++ one doesn't, so the canonical form
refuses floats before the schema is asked, and the float rows are C++-only tests. An integer
too large for a signed 64-bit value (`2^64 - 1`) is in the file: the C++ validator library would
read it as a negative number, so `rp::validate_result` refuses it itself, and both sides call
it invalid.

**`valid.json` is made by the Worker's own tests.** It is the `--json` file of one
`rpworker test` run through the whole pipeline on the test Harness (`--mail 2 --sp 2 --od 2`,
a fixed run ID and fixed clocks: a canary and a random item of each type, all verified), with
the lab tenant's names, and the lab Veeam server's repository ID that starts a restore point's
ID, replaced by placeholders (`shared_names()` in `test_command_test.cpp`) and `worker_version`
pinned to `0.0.0`. What stays of the lab: the canaries' hashes, the manifest's, and the restore
point's time (`2026-09-29T22:00:45.6603083Z`, a real point's, kept for its seven-digit
fraction). A test fails when the pipeline no longer gives exactly that text, and when any lab
name or that repository ID is left in it. After a deliberate change to the result,
write it again with the hidden test case, from `worker\`:

```powershell
.\build\dev\rptests.exe "[.write_shared_result]"
```

Then read the diff, and run both sides: `ctest --preset dev -R "result"` and, from `cloud\`,
`uv run pytest tests/test_result_schema.py`. The patches in `cases.json` point into `valid.json`
by position (`/expected/items/1` is the random mail, `/check/items/3` the item restored twice):
if the run's layout changed, the patches must follow, and the two counts pinned in
`result_schema_test.cpp` and `test_result_schema.py` (185 cases, 47 valid, 138 invalid) with them. Then
write the signing vectors again too (below): their `result.json` is made from `valid.json`. It also changes when
`lab/seed-manifest.json` is re-seeded, since the canaries' hashes and the manifest's are in it.
A change to the schema alone needs no C++ change to be tested: both suites run `cases.json`
against it.

### The TSA fixtures and the shared timestamp vectors (W4.4)

**Fixtures, `worker/tests/fixtures/tsa/`** (its `README.md` lists them). A TSA's exchange is
binary both ways, so a fixture has `"body": null`, the answer's bytes in `"body_base64"` and
the query in `"request_body_base64"` (a hash and a nonce, no secret); `FakeHttpClient` decodes
the first on replay and `rp::test::request_body_of` gives back the second. `rpworker test
--evidence <dir> --record <dir>` writes that format into the recording's `tsa/` folder
(`RecordedBody::base64`): the two Base64 fields skip `redact()` and the JWT-shape rule, which
Base64 of DER would break by chance, and the bytes themselves are checked against the known
secrets instead. `digicert-granted.json` is a real answer of DigiCert's TSA; a test replays it
through the Timestamper with the nonce and the digest of the recorded request and verifies the
token under `shared/tsa/tsa-ca.pem`. It never expires: a chain is checked at the token's own
time.

**The test-only TSA, `worker/tests/tsa_lab.hpp`.** `rp::test::TestTsa` is a root, a TSA
certificate under it and OpenSSL's own responder with a fixed time; `FakeRfc3161` is the
primitive with a fault switched on. The Harness of the command tests
(`tests/restore_command_lab.hpp`) has one behind `http://tsa.test/stamp`, with its root in a
`tsa-ca.pem` beside the config, so every `test --evidence` run in the tests is timestamped and
none asks DigiCert; `lab.tsa_answer` puts another answer in its place.

**Vectors, `shared/testdata/timestamp-v1/`.** `keys.json` is the published test TSA (a root, a
TSA certificate with its private key, a second root): made for these vectors, never a secret,
trusted by nothing but a test. `cases.json` has 23 cases over `signing-v1`'s signed folder,
each with the files to add (`timestamp.tst` as Base64), which CA the verifier is given
(`tsa_ca`, or none) and the word, and for `verified` the line's third field; and
`one_bit_changes`, the offsets at which the token still verifies with one bit flipped (bytes no
signature covers), which both verifiers must find exactly. Both builds run them: the Worker in
`tests/timestamp_verify_test.cpp` (`Signer::verify_folder` on disk and in memory) and
`tests/signer_command_test.cpp` (`rpworker signer verify --tsa-ca`: the line, the note, the
exit code), the Cloud in `cloud/tests/test_verify_bundle_timestamp.py` (`verify_folder`, the
command, and DigiCert's recorded token). The two files are written once by the hidden `rptests
"[.write_shared_timestamp]"` with a new TSA; ECDSA makes every run's tokens different, so
unlike `signing-v1` no test regenerates them: they are verified, never compared with a new run.

### The shared signing vectors (W4.3)

`shared/testdata/signing-v1/` holds what the Worker's Signer and `shared/tools/verify_bundle.py`
must answer alike (`docs/decisions.md` 2026-10-05, W4.3 point 6 and its build notes;
`docs/verification.md`, "The signature"). JSON only, so the LF rule of `.gitattributes` covers
the folder: a signed folder kept as files would change its hashes with a line-ending
conversion, texts inside JSON don't. Every key in it is one of RFC 8032's published test keys,
known to everyone: never a secret, and never to sign anything real.

| File | What | Written by |
|---|---|---|
| `keys.json` | two key pairs, RFC 8032 section 7.1's tests 1 and 2 (`rfc8032-test-1`, `rfc8032-test-2`): `seed_hex`, `private_pkcs8_base64` (as `RP_SIGNING_KEY_BASE64` carries a key), `public_key_pem`, `key_id` | `rptests "[.write_shared_signing]"` |
| `ed25519.json` | RFC 8032 section 7.1's tests 1 to 3 for the primitive: seed, public key, message, signature, all hex. Ed25519 is deterministic, so a build must reproduce each signature byte for byte, not only accept it | by hand, from the RFC |
| `bundle.json` | one signed run folder as texts: `result.json` (`result-v1/valid.json` with its `attachments` replaced by two small made-up files), `signature.json`, `items.csv`, `veeam-session.log`, with the `bundle_sha256` and `key_id` both verifiers must print | `rptests "[.write_shared_signing]"` |
| `cases.json` | 38 changes to that folder, each with the one word expected: a file's bytes replaced (as text, or as Base64 for bytes that aren't UTF-8 or start with a BOM), a file removed, or another public key given. 37 fail, one is the untouched folder, `verified` | `rptests "[.write_shared_signing]"` |
| `key-files.json` | 46 public key files, 11 accepted and 35 refused, with the one rule both verifiers hold for a key file (`docs/verification.md`, "The public key file") | a one-off script that isn't committed (the W4.3 review); changed by hand |
| `closed-folder.json` | one run folder the service closed afterwards (W4.8), as texts in `bundle.json`'s shape: `key` (`rfc8032-test-1`), `bundle_sha256`, `key_id` and `files`. The run's process ended after a restore request and before its result was written, so `result.json` says `error interrupted` with `restore_sent` true and every step `null`, `items.csv` is its header row alone, `veeam-session.log` is empty, and there is no `timestamp.tst` | `rptests "[.write_shared_closed]"` |

The 38 cases by word, pinned on both sides: `result_unreadable` 1, `result_not_canonical` 12,
`result_schema` 1, `attachment_twice` 1, `screenshot_missing` 1, `signature_file` 10,
`hash_mismatch` 2, `wrong_key` 2, `signature_invalid` 4, `attachment_missing` 1,
`attachment_size` 1, `attachment_hash` 1, `verified` 1. A check item holds no hash, so
`result-check-item-one-digit` changes one digit of an item's `ms`.

**Both builds run every case.** Each writes the folder into a temp directory per case and
compares the word.

- Worker: `worker/tests/signer_test.cpp` (`Signer::verify_folder` over a folder in memory;
  the key files through `PublicKey::from_pem`; `bundle.json`, `keys.json` and `cases.json`
  compared byte for byte with what the code makes), `worker/tests/signer_command_test.cpp`
  (the same 38 cases and 46 key files through `rpworker signer verify` on disk, with the
  stdout line and the exit code), `worker/tests/ed25519_test.cpp` (`ed25519.json` on the real
  primitive, `is_public_key` on the 44 bytes, and more key files through `PublicKey::from_pem`,
  whose rule for the file's text is in the strict `signer.cpp`).
- Cloud: `cloud/tests/test_verify_bundle.py` loads the script by path, walking up to `shared/`
  as the schema tests do, and runs the 38 cases through `verify_folder`, the command's stdout
  line and exit code through `main`, the 46 key files through `public_key_from_pem` and
  through `main`, `ed25519.json` and `keys.json` on `cryptography`. It holds the set of words
  the cases expect equal to the set the script can answer.

**The closed folder (W4.8).** `closed-folder.json` shows that a result the service wrote
afterwards is signed by the same path as a run's own and read alike by both verifiers
(`docs/verification.md`, "A result written afterwards (W4.8)"). It is made by the service's
real close over a temp folder: a record of a run with a restore request, no folder, the vault's
key RFC 8032's test key 1, the stop already asked for, so the TSA isn't asked.

- Worker: `worker/tests/worker_body_test.cpp`, "worker body: a folder closed after a stop has
  no token, and is what the shared vector holds" (`[worker_body][close][signer]`). It makes the
  folder again and compares it with the file: `items.csv` byte for byte, `result.json` as JSON
  without `worker_version`, the whole `status` object; then `Signer::verify_folder` over the
  file's four texts must say `verified` with the file's `bundle_sha256` and `key_id` and no
  timestamp.
- Cloud: `cloud/tests/test_verify_bundle_closed.py` writes the four files into a temp folder:
  `verify_folder` says `verified`, `main` prints `verified <bundle_sha256> key <key_id>
  timestamp none` with `note: not timestamped` on stderr and exit 0, the hash is
  `result.json`'s own, and `restore_sent` changed to `false` is `hash_mismatch`.

The result names the Worker's version of the day it was written, so unlike `bundle.json` the
file is not held to the code byte for byte: both tests verify it as it is, and a version bump
needs no rewrite. After a deliberate change to the result, to a result written afterwards or to
the signature file, write it again from `worker\`, read the diff and run both sides:

```powershell
.\build\dev\rptests.exe "[.write_shared_closed]"
.\build\dev\rptests.exe "[worker_body]"
```

and, from `cloud\`, `uv run pytest tests/test_verify_bundle_closed.py`.

The script is outside `--cov=app` and mutmut, so no gate holds its coverage; `cryptography` is
in Cloud's dev group for these tests.

After a deliberate change to the result, the signature file or the cases, write the three
Worker-made files again with the hidden test case, from `worker\`, after `valid.json` if that
changed too:

```powershell
.\build\dev\rptests.exe "[.write_shared_result]"
.\build\dev\rptests.exe "[.write_shared_signing]"
```

It fails if the bundle's signature has neither `+` nor `/` (the URL-safe case needs one of
them to change). Then read the diff and run both sides: `.\build\dev\rptests.exe
"[signer],[signer_command],[ed25519]"` and, from `cloud\`, `uv run pytest tests/test_verify_bundle.py tests/test_canonical_json.py`. A new case
moves the pinned counts in `signer_test.cpp`, `signer_command_test.cpp` and
`test_verify_bundle.py`; a new key file moves the 46 and its two parts there too.

### The secret audit (W4.9)

Two tests make CLAUDE.md's "Secrets" rule true (`docs/decisions.md` 2026-10-09, W4.9). Neither
needs a lab secret, the network, the real vault, the service or `%ProgramData%`.

**The sentinel audit**, `worker/tests/secret_audit_test.cpp` on `tests/secret_audit_lab.hpp`,
tag `[secret_audit]`, part of `rptests` and so of `ctest --preset dev`:

```powershell
.\build\dev\rptests.exe "[secret_audit]"
ctest --preset dev -R "secret audit"
```

Every case runs one path of the Worker with five sentinel secrets in place of the vault's
values (`rp::test::secret_audit::secrets()`: `veeam_password`
`Sentinel-Audit-Veeam-Password-2d7f`, a PFX made for the audit under
`Sentinel-Audit-PFX-Password-2d7f`, RFC 8032's test key 2 as the signing key, and the user
name `AUDIT-HOST\rp-veeam-audit-2d7f`, which is no secret value), the fakes handing out
sentinel tokens (`Sentinel-Audit-Veeam-Access-Token-...`, `...-Graph-Access-Token-...`) and a
sentinel exported credential, then collects everything the path wrote and searches it. The
search set (`searched()`) is every secret value as it is, the Base64 ones also as their bytes
and their hex and in 32-character pieces (a leak of 63 or more consecutive characters is
found), the signing seed in the two shapes `SigningKey::secret_shapes()` gives, the tokens, the
exported PFX and its password, and the client assertion the run signed, read from the fake
token endpoint's requests after the run; and beside the values, every secret shape of the table
below. A hit fails the case with the output's name, the secret's label and the byte offset,
never the bytes.

| Case | Path | Outputs searched |
|---|---|---|
| A | `rpworker restore`, a pass | stdout, stderr, the command logger, every file under the temp folder, the TSA's requests |
| B | `rpworker test --json` | the same, the `--json` file among the files |
| C | `test --evidence --outbox --record`, a pass; `outbox flush --record` with the Cloud answering 500 and then 202; `outbox list`; `graph list --hash --record` | the same, the run folder, the queued and sent folder with its `manifest.json`, the four recordings (the run's, each flush's `cloud/`, `graph list`'s), every request the fake Cloud received (URL, headers, body, every multipart part's name, file name, content type and bytes) |
| D | a `fail` (an item missing from its target) | the same, `items.csv`'s failed rows |
| E | an `error` before the restore (Graph refusing the token: `check error`, `graph_auth`) | the same, a signed result with `null` steps |
| F | an `error` in the restore phase (the connector throwing `AuthError`) | the same |
| G | a run that ends `result_invalid`, closed afterwards by the service as `error result_invalid` | the service's log (below) and the folders |
| H | the TSA failing (503): `timestamp warning`, a folder without a token | the same as A |
| I | the real `veeam_m365` connector over `recordings/w34-live-run1/` (`tests/replay_lab.hpp`), the fake Veeam's token answer and the exporter's credential replaced by the audit's, with `--record`: the sign-in, the Bearer header, four restore POSTs carrying the exported PFX and its password, Veeam's own words | stdout, stderr, the logger, the temp folder with the recording (the test requires the four restore POSTs' fixtures with their `request_body` and the credential's two keys in it); the test also counts the four POSTs that carried the credential to Veeam, where it belongs |
| J1 to J7 | the service's loop on `tests/worker_body_lab.hpp`'s `BodyLab` with a real `worker.log` (`rp::make_service_logger` into the temp folder, level `trace`): one job to `sent\` and the same job skipped (J1, with `running.json` as it stood before and at the restore request), a jobs file that isn't JSON (J3), an invalid job (J4), a killed run's record held for while another session of the account is `Working` (J5: the `waiting for Veeam` line names the account, which the test counts and allows), the hold over and the recovery clean (J6), a close that fails for a vault that can't be read (J7) | the log files, every file under the temp folder (`runs\`, `box\`, `state\`, the jobs file, the config), the fake Cloud's requests (the heartbeat's body, the uploaded parts), the TSA's |
| K | `config check`, `vault list`, `vault test`, `signer public-key` through `rp::run_cli` on a DPAPI vault of the sentinels in the temp folder; `vault set` and `vault remove` through their Env; `veeam list --record` on the recorded organisations | the same as A, the vault file (DPAPI's blob holds no plaintext) and the recording |

Not a path: `vault grant` (an ACL, no value), `service install|uninstall|start|stop` (the SCM),
`signer verify` (reads a folder and a public key). Requests to the fake Veeam and Graph are not
outputs: the token request to Veeam carries the password by design, the restore POST the
exported PFX, Graph's token request the client assertion; what comes back and is written is.

**To add a writer or a path.** A new kind of output (a new file a run writes, a new third party
it posts to) goes into the collector: `Outputs::add`, `add_folder` (every regular file under a
root) or `add_requests` (every request a `FakeHttpClient` received). A new path is a new
`TEST_CASE` that REQUIREs its own expected line or file first (`status pass`, `result.json`
there, `sent <run>`), then `collect`s its streams and `finish`es; an audit that searches
nothing fails on `REQUIRE_FALSE(outputs.items.empty())`. A new secret goes into `secrets()`
and `searched()`, long values through `add_base64` or `add_with_pieces`.

**The fixture scan**, `worker/tools/fixture_secret_scan.py` (stdlib only), searches the
committed data trees for the shapes alone, since CI has no lab secret and must never be given
one: `worker/tests/fixtures/`, `shared/testdata/`, `docs/api/`, `tests/e2e/`, `lab/canary/`,
`lab/seed-manifest.json` and `lab/tenant.md`, every file whatever its name (UTF-8 where it is,
Latin-1 otherwise, so no byte is skipped), never a `.venv`, `__pycache__`, `build` or `.git`
folder, nor a symbolic link or junction. Not the rest of `docs/`: `decisions.md` and this file
describe the shapes themselves and quote a PEM header in prose with no body to pin, so a value
allowlist can't hold them (W4.9 build notes). Source trees are not scanned: a secret in code is
caught by review and by the vault rule. A file that can't be read is never a pass: exit 2, as a
tree that isn't there. It runs as the
ctest test `fixture secret scan` (label `scan`, registered when CMake finds a Python 3; the
script and its tests run on 3.9 and later, without `Path.is_junction()` where there is none) and in
CI as the `fixture-scan` job of `.github/workflows/worker.yml`, on Ubuntu, without a compiler,
beside the Windows build job. Its self-tests run with the gate's:

```powershell
python tools/fixture_secret_scan.py --root ..          # from worker/: exit 0 clean, 1 a finding or a stale entry, 2 unusable (the allowlist, a tree or a file can't be read)
python -m unittest discover -s tools -p "test_*.py"
```

A finding is `<path>:<line>: <shape> (<n> characters)`, never the text. **The allowlist**,
`worker/tools/fixture_secret_scan_allowlist.json`, names per file the shape it may hold, why,
and either the exact `values` or the `prefixes` of what is allowed; never a file-wide pass, so
a new secret-shaped text in an allowed file still fails, and an entry whose file is gone or
whose values match nothing is stale and fails the scan. Today it holds: the scrub placeholder
JWT (`alg` `none`, the claim `{"scrubbed":true}`) in `graph/token-200.json` and the Graph
fixtures' README; Base64 of a result document in `signing-v1/cases.json` (Base64 of `{"` is
`eyJ`, whatever follows); RFC 8032's test keys 1 and 2 in `signing-v1/keys.json` and
`key-files.json`; the test TSA's EC key in `timestamp-v1/keys.json`; the stub Cloud's own word
`present` under `authorization` in `w4.8-harness/stub-cloud.py`. To allow a new file, add an
entry with its path, the shape, a reason sentence and the value (for a PEM block, its Base64
body without line breaks; for a Base64 opening, the Base64 run from the opening on; for a JWT,
the token) or a prefix.

**The shapes**, one table for both halves (the sentinel audit searches for them in every output
beside the values; the fixture scan in every data file), and one list of examples both are held
to: `worker/tools/secret_shapes_cases.json` (`shaped`, each with its shape; `clean`), read by
`test_fixture_secret_scan.py` and by the audit's case "the shapes are the fixture scan's". A new
rule, or a text one half gets wrong, goes there first:

| Shape | Rule | Allowed to be |
|---|---|---|
| `jwt` | `eyJ` not run into a preceding base64url character, then 37 or more base64url characters and dots (the recorder's `kMinJwtTail`) | the scrub placeholder; Base64 of a JSON document |
| `bearer` | `Bearer` not run into a word character, blanks, 20 or more of `A-Z a-z 0-9 . _ ~ + / -` and up to two `=`, not followed by a letter, a digit or `=` (`Bearer realm=` is an auth-param; `Bearer [REDACTED]` doesn't match) | nothing |
| `pem_private_key` | `-----BEGIN <label>-----` whose label is upper-case words ending in `PRIVATE KEY` (`redact()`'s rule: `PRIVATE KEY`, `RSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`; not `XPRIVATE KEY`); a `PUBLIC KEY` or `CERTIFICATE` block is no shape; the value compared is the block's Base64 body | the published test keys |
| `ed25519_pkcs8` | `MC4CAQAwBQYDK2VwBCIEI` and 43 Base64 characters: an Ed25519 PKCS#8 key whole | RFC 8032's test keys |
| `rsa_pkcs8` | `MII..[AQgw]IBADANBgkqhkiG9w0BAQEFAASC` | nothing |
| `rsa_pkcs1` | `MII..[AQgw]IBAAKCA` | nothing |
| `ec_pkcs8` | `MIG.AgEAMBMGByqGSM49` | the test TSA's key |
| `ec_sec1` | `MHcCAQEEI`, `MIGkAgEBBDA` or `MIHcAgEBBEIB` (P-256, P-384, P-521) | nothing |
| `pkcs12` | `MII..[AQgw]IBAzCC`, or `MIM....CAQMwgg` over 64 KiB: a PFX | nothing |
| `keyed_secret` (the fixture scan only; in the audit the values are searched as bytes) | `"<key>": "<value>"`, its JSON-escaped form inside a string (`\"<key>\":\"<value>\"`) or `<key>=<value>` with a bare, `"quoted"` or `'quoted'` value, or, for the keys `redact()` takes in that form (all but `client_assertion`, `id_token`, `tempauth`, `pfx`, `sig` and `authorization`) `<key>: <value>` when the rest of the line is one word or one quoted string (`Password : Hunter2!`; words after a key are prose), or an `Authorization:` / `Proxy-Authorization:` header (the name exact, not `X-Authorization`) with its scheme and the word after it, for the keys `redact()` masks: `password`, `client_secret`, `client_assertion`, `refresh_token`, `access_token`, `id_token`, `tempauth`, `applicationCertificate`, `applicationCertificatePassword`, `signing_key`, `signing_key_base64`, `signing_private_key`, `pfx_base64`, `pfx`, `sig`, `authorization`; the key in any case, ending a longer name after a separator as `redact()` takes it (`veeam_password`, `db.password`) but never run into a letter or digit (`xpassword`) nor followed by one or `_` (`password_hash`); the value not `[REDACTED]`, `SCRUBBED`, `null`, empty, an ellipsis, a closed `[...]`, `<...>` or backtick form that is the whole value, or a script's variable (the whole value, or calling a method: `$pw`, `$env:NAME`, `$cert.Export(`), subexpression `$(`, call in parentheses `(Get-Thing`, or a type's static call or cast `[Convert]::`, `[string]$x`; a value that only starts with one of those characters (`$tr0ng-Pa55`, `(Xy7!`) is a value | the placeholder JWT under `access_token`; the stub's `present` |

A bare `MII...` run is a certificate or a CMS token, public, and no shape: the fixture trees hold
hundreds (`rest-certificate.pem`, the TSA fixtures, the timestamp vectors). A TimeStampResp
reads `MII..` then `ADAgEAMII`, whose sixth character isn't `IB`.

### Running the gates locally

Cloud, from `cloud/` (the same commands as CI; `make cov` runs both in WSL or Linux):

```bash
uv run --locked pytest --cov=app --cov-branch --cov-report=term-missing --cov-report=json:coverage.json --cov-fail-under=80
uv run --locked python tools/check_coverage.py coverage.json
```

Worker, from `worker/` in a VS 2022 Developer PowerShell with OpenCppCoverage on PATH:

```powershell
cmake --preset coverage
cmake --build --preset coverage
pwsh tools/run_coverage.ps1
python tools/coverage_gate.py build/coverage/coverage.xml --min-line 80
```

`tools/run_coverage.ps1` is what CI runs too. It runs `rptests.exe` once under OpenCppCoverage,
every test case in one process, then the `rpworker.exe` tests through ctest (`ctest --preset
coverage -L exe`), and merges the two into `build/coverage/coverage.xml`. Running each test case
in its own process under OpenCppCoverage, as plain `ctest --preset coverage` would, took about an
hour; this takes about 13 minutes on the dev laptop. `ctest --preset dev` and CI's Release
`ctest --preset ci` still run each test case in its own process, so a test that only passes
because of an earlier one shows up there (`docs/decisions.md`, 2026-10-01 "Worker coverage in
one process").

**One exe test fails on a console in code page 437.** `rpworker config check keeps a --config
path outside the ANSI code page` gives `rpworker.exe` a Cyrillic file name and compares stderr
exactly. Run from a console whose code page is 437 (PowerShell started through another shell,
for one) it fails; after `chcp 65001`, or from a PowerShell window opened directly, it passes.
It is the console's doing, not the Worker's, and it is older than W4.8, whose build met it in
every step.

**Tests that skip unless elevated.** Changing a file's owner needs `SeRestorePrivilege`, so
the tests that give a file to another account (`tests/owner_lab.hpp`: `elevated()`,
`give_to()`; the other account is LocalService, `S-1-5-19`) skip themselves in an unelevated
shell with `changing a file's owner needs SeRestorePrivilege: run elevated`: the `[owner]`
tests of `tests/vault_test.cpp` and `tests/worker_body_test.cpp`. So does the one `scm_test`
that creates a service (W4.7). In an unelevated run what the W4.8 ones decide is still covered,
by the same rules on fakes (`[service_recovery]`, `[service_loop]`). Run `rptests.exe
"[owner]"` once from an elevated shell after a change to the owner rule.

Lab, from `lab/` (the same commands as CI; see `lab/README.md`):

```bash
uv run --locked pytest -q
uv run --locked python -m seeder hash
```

The guard scripts' own tests (from the repo root):

```bash
python -m pytest .github/scripts          # CI: uvx --python 3.12 pytest .github/scripts
python -m unittest discover -s worker/tools -p "test_*.py"
```

## Once-per-sprint mutation run

Coverage says a line ran. It does not say a test would notice if the line were wrong. Once a
sprint, we change the code on purpose and check that a test goes red. Nothing in CI runs this.

### Python: mutmut

mutmut needs `fork()`, so it does not run on Windows. Run it in WSL (installed on the dev
laptop, see [environment.md](environment.md)) or on Linux. `make` is also only available
there.

One-time setup in WSL:

```bash
sudo apt install make
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Each run:

```bash
cd /mnt/c/restoreproof/cloud
make mutate        # uv run mutmut run, then uv run mutmut results
```

The first `uv run` in WSL creates a Linux virtualenv. Sharing `.venv` with Windows breaks
both, so set `export UV_PROJECT_ENVIRONMENT=.venv-wsl` in the WSL shell first (`.venv-wsl/` is
gitignored). mutmut writes its mutated copy of the code to `cloud/mutants/` (also gitignored).

**Current state:** `app/` has no functions yet, so `make mutate` exits 1 with "could not find
any test case for any mutant". That is expected until real code lands in `app/`.

Reading the result:

- `uv run mutmut results` lists the mutants that survived: the code was changed and every
  test still passed.
- `uv run mutmut show <id>` prints the diff for one mutant.

Rule: **every surviving mutant gets a new test, or a written reason why it is equivalent**
(the change cannot alter behaviour, for example `x >= 0` vs `x > -1` on an integer). Add the
test, re-run `make mutate`, and confirm the mutant is now killed.

### C++: a manual pass

There is no mutation tool on the Worker side. Instead, by hand:

1. In the checker (the item comparison) and the status table, flip one comparison operator at
   a time: `==` ↔ `!=`, `<` ↔ `<=`, `>` ↔ `>=`, `&&` ↔ `||`.
2. Build and run `ctest --preset dev`.
3. The flip must turn at least one test red. If the suite stays green, write the missing test.
4. Revert the flip before trying the next one. Never commit a flip.

### Recording the outcome

Add one line per run to the log below, newest first: date, sprint, what was mutated, how many
mutants survived, and what was done about each (test added, or reason it is equivalent).

## Mutation log

| Date | Sprint | Scope | Survivors | Action |
|---|---|---|---|---|
| | | | | |
