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
| Worker coverage | `.github/workflows/worker.yml`, OpenCppCoverage + `worker/tools/coverage_gate.py` | 80% line on `rpcore` (`worker/src/`, `worker/include/`) plus `rpworker`'s `main()` (`worker/app/`); 100% **line** on vault, signer and target_guard (the vault and signer once they exist), meaning any file with a path part named or prefixed `vault`, `signer` or `target_guard` (`src/signer/ed25519.cpp`, `src/vault_dpapi.cpp`; W2.7's `src/target_guard.cpp`, `src/target_guard_graph.cpp`, `src/target_guard_veeam.cpp` and their headers); every `.cpp` on disk under `src/`, `include/` and `app/` must appear in the report, so a file no test links into `rptests` (or, for `app/`, that ctest's runs of `rpworker.exe` don't reach) fails (headers of declarations may be absent) |
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
for 100% branch on vault, signer and target_guard; until the Worker has a branch-capable tool,
those files are held to 100% line instead. See `docs/decisions.md`.

### Live tests

Tests tagged `[live]` call the lab's real services and are skipped unless `RP_LIVE=1` is set;
they are read-only. `RP_LIVE=1 ctest --preset dev` runs them with the rest, or run them alone
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
- afterwards `GET /v8/RestoreSessions?limit=200` lists no Working session of the account.

It prints the restore point, the selection, `to_json(record)` (the result's `sample` object:
seed, manifest SHA-256, cursors, canary IDs, pool sizes and hashes, the containers looked
into), how many entries each OneDrive's `Documents?parentId=root` listing held, and the number
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

**This test writes.** It is the only live test that changes anything: it restores real items
into the three restore targets. It is skipped unless **both** `RP_LIVE=1` and
`RP_LIVE_RESTORE=1` are set, so a normal `RP_LIVE=1` run stays read-only.

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
restored. It needs the variables of the Veeam and Graph live tests above, plus:

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
2. **Make sure the restore targets are empty.** Run `rpworker graph list` (above, and
   `docs/worker-config.md`) and check that the `restoretest` Inbox, the RestoreTarget library and
   alice's `/RestoreTarget` folder show no items. The verification that W3.2 adds compares what
   is there with the manifest, and leftovers from an earlier run would get in the way.
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

(or `.\build\dev\rptests.exe "[live][writes]"`). Then read the targets back with their hashes
and compare them with the manifest:

```powershell
.\build\dev\rpworker.exe graph list --hash --config <your config.json>
```

(`--config` can be left out when the config is in its default place, `docs/worker-config.md`.)

**Clean up by hand afterwards.** Until W3.4's cleanup exists, delete the restored mails from the
`restoretest` Inbox and the files from the RestoreTarget library and alice's `/RestoreTarget`
folder in the Microsoft 365 web apps, then run `rpworker graph list` again to check that they
are empty. Remove the variables when done:

```powershell
Remove-Item Env:RP_LIVE, Env:RP_LIVE_RESTORE, Env:RP_LIVE_EVIDENCE_FILE -ErrorAction SilentlyContinue
. ..\lab\entra\set-worker-env.ps1 -Clear
```

### Restore by hand (`rpworker restore`, writes to the lab tenant)

**This writes too.** `rpworker restore` (W2.8, `docs/worker-config.md`) chooses a sample and
restores it into the three restore targets, like the live test above, but from the command
line. ctest's `rpworker restore` exe tests all stop before any request (the arguments, the
config, the secrets), so nothing writes unless you run it by hand. Before running it, check
the same three points as for the live restore: an elevated shell, empty targets, no restore
session still `Working`.

1. Open `Developer PowerShell for VS 2022` (or PowerShell) with **Run as administrator**, and
   go to `C:\restoreproof\worker`.
2. Set `RP_VEEAM_USERNAME` and `RP_VEEAM_PASSWORD` (the Veeam account, as for the Veeam live
   tests), and the Graph certificate variables with `. ..\lab\entra\set-worker-env.ps1`.
   The command checks all four are set before it calls Veeam.
3. Check the targets are empty:

   ```powershell
   .\build\dev\rpworker.exe graph list --config <your config.json>
   ```

4. Restore, with the lab manifest (or leave `--manifest` out when a `seed-manifest.json` is
   beside the config):

   ```powershell
   .\build\dev\rpworker.exe restore --mail 5 --sp 5 --od 5 --config <your config.json> --manifest ..\lab\seed-manifest.json
   ```

   Note the printed run ID (`--run-id` repeats the sample) and the next canary cursor
   (`--canary-cursor` carries the rotation on). Exit 0 is `succeeded`, 5 `partial` or `failed`,
   4 an error such as the guard refusing or an item failed for an infrastructure reason.
5. Read the targets back with their hashes:

   ```powershell
   .\build\dev\rpworker.exe graph list --hash --config <your config.json>
   ```

6. Clean up by hand, as after the live restore, until W3.4's cleanup exists, and check with
   `rpworker graph list` that the targets are empty again. Remove the variables when done
   (`. ..\lab\entra\set-worker-env.ps1 -Clear`, and the two Veeam ones).

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
OpenCppCoverage --quiet --cover_children --sources "$PWD\src" --sources "$PWD\include" `
  --sources "$PWD\app" --export_type "cobertura:$PWD\build\coverage\coverage.xml" -- ctest --preset coverage
python tools/coverage_gate.py build/coverage/coverage.xml --min-line 80
```

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
