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
| Worker coverage | `.github/workflows/worker.yml`, OpenCppCoverage + `worker/tools/coverage_gate.py` | 80% line on `rpcore` (`worker/src/`, `worker/include/`) plus `rpworker`'s `main()` (`worker/app/`); 100% **line** on vault, signer, target_guard, run_status and cleaner (the vault and signer once they exist), meaning any file with a path part named or prefixed `vault`, `signer`, `target_guard`, `run_status` or `cleaner` (`src/signer/ed25519.cpp`, `src/vault_dpapi.cpp`; W2.7's `src/target_guard.cpp`, `src/target_guard_graph.cpp`, `src/target_guard_veeam.cpp` and their headers; W3.3's `src/run_status.cpp`, the status decision table; W3.4's `src/cleaner.cpp` and `include/rp/cleaner.hpp`, the only Worker code that deletes in the tenant); every `.cpp` on disk under `src/`, `include/` and `app/` must appear in the report, so a file no test links into `rptests` (or, for `app/`, that ctest's runs of `rpworker.exe` don't reach) fails (headers of declarations may be absent) |
| Cloud coverage | `.github/workflows/cloud.yml`, pytest-cov | 80% on `app/`, measured as coverage's combined line + branch figure; 100% line + branch on `app/auth`, `app/results.py` and `app/repo` (skipped while absent), checked by `cloud/tools/check_coverage.py` |
| Lab tests and canary hashes | `.github/workflows/lab.yml` | `lab/`'s pytest suite passes (offline, fake Graph tenant), and `python -m seeder hash` reproduces every hash in `lab/seed-manifest.json` from the committed `lab/canary/` files and the catalog (L1.2's Done when). No coverage floor |
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

### Live tests

Tests tagged `[live]` call the lab's real services and are skipped unless `RP_LIVE=1` is set;
they are read-only, except the two tagged `[live][writes]`, which also need `RP_LIVE_RESTORE=1`
("Live restore" below). `RP_LIVE=1 ctest --preset dev` runs them with the rest, or run them alone
with `build\dev\rptests.exe "[live]"` (which also prints what they found). Three are Veeam's,
four Graph's and one the sampler's dry run, which uses both (below); once `RP_LIVE=1` is set,
each needs its variables below and fails, rather than skips, without them.

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
| `RP_VEEAM_USERNAME`, `RP_VEEAM_PASSWORD` | the Veeam account (`MACHINE\user`), as the Worker reads them |
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
| `RP_GRAPH_CERT_PFX_BASE64`, `RP_GRAPH_CERT_PASSWORD` | the Worker app's certificate, as the Worker reads them (`rp/secrets.hpp`); set them for one session with `. .\lab\entra\set-worker-env.ps1` (`docs/worker-config.md`, "Microsoft Graph app") (required) |
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

3. Put the certificate into this session. Type the leading dot and space:

   ```powershell
   . .\lab\entra\set-worker-env.ps1
   ```

   It prints `set RP_GRAPH_CERT_PFX_BASE64 and RP_GRAPH_CERT_PASSWORD for this session` and
   nothing else. A red error names what is missing (the PFX file or the Credential Manager
   entry) and sets nothing.
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
5. Remove the variables again, or close the window:

   ```powershell
   Remove-Item Env:RP_LIVE
   . .\lab\entra\set-worker-env.ps1 -Clear
   ```

Nothing is written to disk, and PowerShell's history holds only the commands above, never a
value: the script reads the PFX and the password itself.

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
of GETs and POSTs. It needs the Veeam and Graph variables above (`RP_VEEAM_*`,
`RP_LIVE_VEEAM_CA_FILE`, the Worker app's certificate), no elevation, plus two optional ones:

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
`veeam_m365` connector through `default_connector_registry()` with the real secrets and
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
   needs administrator rights. Start `Developer PowerShell for VS 2022` with right-click, **Run
   as administrator**. Without elevation the test fails at the first restore call with a
   certificate export error, before anything is restored.
2. **Make sure the restore targets are empty.** Run the live cleanup test (below), then
   `rpworker graph list` (above, and `docs/worker-config.md`) and check that the `restoretest`
   Inbox, the RestoreTarget library and alice's `/RestoreTarget` folder show `0 item(s)` and no
   `(... not listed)` line.
3. **Make sure no restore session of the Veeam account is still running.** The connector refuses
   to start if one is (`docs/api/veeam-m365/08-sweep-sessions.ps1` stops them).

Run it from `C:\restoreproof\worker`, with the certificate variables set as in the Graph steps
above:

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
day. It needs the Graph certificate variables,
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
Remove the variables when done:

```powershell
Remove-Item Env:RP_LIVE, Env:RP_LIVE_RESTORE, Env:RP_LIVE_EVIDENCE_FILE, Env:RP_LIVE_RECORD_DIR -ErrorAction SilentlyContinue
. ..\lab\entra\set-worker-env.ps1 -Clear
```

### Restore by hand (`rpworker restore`, writes to the lab tenant)

**This writes too.** `rpworker restore` (W2.8, `docs/worker-config.md`) chooses a sample and
restores it into the three restore targets, like the live test above, but from the command
line. ctest's `rpworker restore` exe tests all stop before any request (the arguments, the
config, the secrets), so nothing writes unless you run it by hand. Since W3.4 it also
deletes: it empties the three targets before it samples and again after its status line
(`docs/worker-config.md`, "`rpworker restore`"). Before running it, check: an elevated shell,
no restore session still `Working`, and no other RestoreProof run on this machine (the run
mutex refuses a second one: `restore error: another RestoreProof run is using the restore
targets; nothing was done`, exit 4). The targets needn't be empty first.

1. Open `Developer PowerShell for VS 2022` (or PowerShell) with **Run as administrator**, and
   go to `C:\restoreproof\worker`.
2. Set `RP_VEEAM_USERNAME` and `RP_VEEAM_PASSWORD` (the Veeam account, as for the Veeam live
   tests), and the Graph certificate variables with `. ..\lab\entra\set-worker-env.ps1`.
   The command checks all four are set before it calls Veeam.
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
   Remove the variables when done (`. ..\lab\entra\set-worker-env.ps1 -Clear`, and the two
   Veeam ones).

### Test by hand (`rpworker test`, writes to the lab tenant)

**This writes and deletes too.** `rpworker test` (W3.6, `docs/worker-config.md`, "`rpworker
test`") runs the same pipeline as `rpworker restore`, with its own table after the check and an
optional `--json` file, the run's result (`restoreproof.result.v1`, W4.1). Its ctest exe tests all stop before any request. Check the same
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
4. With the variables set as in "Restore by hand" step 2, run the test with that run ID and
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
run, the variables of "Restore by hand" step 2), then, from `worker\`:

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
2. Set the variables as for the live tests (the two Veeam ones, and for Graph
   `. ..\lab\entra\set-worker-env.ps1`), then run the command with `--record`:

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
| `shared/schemas/result.v1.json` | the result's schema, the only copy | `worker/tests/result_schema_test.cpp` (`[result_schema]`): the embedded bytes are the file's, only the allowed keywords, the fifteen keys, the enums against the code | `cloud/tests/test_result_schema.py`: `check_schema`, `$schema` is draft 2020-12 |
| `shared/testdata/canonical-json-v1.json` | `canonical-json-v1`: 33 `cases` (`input`, `canonical`, `sha256`) and 9 `rejects` (`input_text`, `reason`: `float`, `integer_out_of_range` or `non_ascii_key`) | `worker/tests/canonical_json_test.cpp` (`[canonical_json]`): every case and every reject; invalid UTF-8, which a JSON file can't hold, on bytes | `cloud/tests/test_canonical_json.py`: the accepted cases against `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`; the rejects' shape only, until W4.3 brings a Python canonicaliser |
| `shared/testdata/result-v1/valid.json` | a valid result, as canonical bytes | `worker/tests/test_command_test.cpp`: the pipeline's run reproduces it byte for byte | `test_result_schema.py`: valid, and equal to its own canonical dump |
| `shared/testdata/result-v1/cases.json` | 158 documents, each `valid.json` with an RFC 6902 `patch` (add, remove, replace) and whether the schema accepts it (`valid`): 39 valid, 119 invalid | `result_schema_test.cpp`, one `GENERATE` row per case | `test_result_schema.py`, one parametrised test per case |

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
`result_schema_test.cpp` (158 cases, 39 valid) with them. It also changes when
`lab/seed-manifest.json` is re-seeded, since the canaries' hashes and the manifest's are in it.
A change to the schema alone needs no C++ change to be tested: both suites run `cases.json`
against it.

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
