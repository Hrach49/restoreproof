# End-to-end scenarios (Q3.1 #42, Q3.2 #43)

These are manual checks of the whole `rpworker test` run as one unit, against the real lab:
the real Veeam server, the real test tenant and real backups. The unit tests cover each piece
on recorded data. These scenarios show that the assembled run reports the honest status when
something really goes wrong: `pass` only when every item restored and matched, `fail` only for
a real backup problem, and `error` when the test itself couldn't run. Infrastructure problems
must never be reported as `fail` (CLAUDE.md, "Status vocabulary").

- **Q3.1 Done when:** scenarios 1, 2, 3, 4 and 7 each have an "Actual" that equals "Expected".
- **Q3.2 Done when:** scenarios 5 and 6 are logged here with the exact error message, and
  neither is reported as `fail`.

## Results

One row per scenario. Fill in "Actual" (status line, exit code, the item rows that matter),
the date (UTC) and the tester after each run. Where Actual differs from Expected, write what
happened and link the follow-up issue.

| # | Scenario | Setup (summary) | Command (summary) | Expected status | Expected named items | Actual | Date | Tester |
|---|---|---|---|---|---|---|---|---|
| 1 | Normal run | none | `test --mail 10 --sp 10 --od 10` | `status pass: 30 of 30 item(s) verified: manifest 15, fields 5, metadata 10`, exit 0 | none: 30 of 30 `verified` | As expected. Run `rp-20261003T201232Z-1bc4f6b0` on the 2026-10-03T16:16:54.0154727Z point: 30 of 30 restored in five `Success` sessions, `check: 30 match, 0 mismatch, 0 missing, 0 error`, `status pass: 30 of 30 item(s) verified: manifest 15, fields 5, metadata 10`, `cleanup after ok: deleted 10 mail, 10 sharepoint, 10 onedrive`, no shortfall, stderr empty, exit 0; `graph list` 0 in all three targets | 2026-10-03 20:12Z | owner (run by Claude Code) |
| 2 | Canary mail deleted before a backup | RP-CANARY-0003 deleted permanently from alice's Inbox, new backup | `test --mail 1 --sp 0 --od 0 --canary-cursor '2,0,0'` on the new point | `status fail: 1 of 1 item(s) didn't verify (1 missing, 0 mismatch)`, exit 5 (since the Q3.1 fix, `docs/decisions.md` 2026-10-03) | RP-CANARY-0003: FOUND `no`, MATCH `missing`, VERDICT `failed`, REASON `not_in_backup` | As expected (with the Q3.1 fix, commit 5ea507f). RP-CANARY-0003 permanently deleted from alice's Inbox (not in Deleted Items), then RP-Lab-Full started through Veeam's REST API: `Success`, new point 2026-10-04T14:04:19.5424301Z. Run `rp-20261004T140513Z-b9629069`: `canary cursor 2,0,0 -> 3,0,0`, mail `1 of 1`; no session table, `restore failed: 0 of 0 item(s) restored in 0:00:03`; row `mail  RP-CANARY-0003  manifest  no  missing  failed  not_in_backup  -`; `check: 0 match, 0 mismatch, 1 missing, 0 error`; `status fail: 1 of 1 item(s) didn't verify (1 missing, 0 mismatch)`; `cleanup after ok: deleted 0 mail, 0 sharepoint, 0 onedrive`; stderr empty; exit 5; `--json`: `status.failed_items` `[0]`, `restore.items[0].outcome` `not_in_backup`, `restore.items_sent` 0; timings `restore_submit`/`restore_wait` `not reported` (no session); `graph list` 0. Lab put back: RP-CANARY-0003 restored into alice's Inbox from the 2026-10-04T00:14:55.447798Z point through Veeam's REST API (`restoreTo` alice's Inbox, 1 item, session `Success`, "1 item processed (1 success)"), RP-Lab-Full run again (point 2026-10-04T14:38:15.6089519Z), then the same command on that point: run `rp-20261004T143904Z-dfd41758`, `status pass: 1 of 1 item(s) verified: manifest 1, fields 0, metadata 0`, exit 0: the restored mail matches the manifest (message ID, times, body hash); `graph list` 0 | 2026-10-04 14:05Z | owner (run by Claude Code) |
| 3 | Live file changed after the backup | rp-canary-04.txt edited in SharePoint after the backup | `test --mail 0 --sp 1 --od 0 --canary-cursor '0,3,0' --point <older point>` | `status pass: 1 of 1 item(s) verified: manifest 1, fields 0, metadata 0`, exit 0 | rp-canary-04.txt `verified`; note: the live source differs | As expected. rp-canary-04.txt edited in the RestoreTest library at about 20:30Z (a line added). Run `rp-20261003T203602Z-d9d09a49` with `--point` the 2026-10-03T16:16:54.0154727Z point (before the edit): one `Success` session, 1 of 1 restored; row `sharepoint  rp-canary-04.txt  manifest  yes  match  verified  -`; `check: 1 match, 0 mismatch, 0 missing, 0 error`; `status pass: 1 of 1 item(s) verified: manifest 1, fields 0, metadata 0`; `cleanup after ok: deleted 0 mail, 1 sharepoint, 0 onedrive`; stderr empty; exit 0; `graph list` 0. Note: the live source differs: a read-only GET of the live file through the Worker app gave 191 bytes, SHA-256 `db157854...5276ca`, against the manifest's 164 bytes, `f2d6976a...b392d8`; the Worker prints nothing about the live file | 2026-10-03 20:36Z | owner (run by Claude Code) |
| 4 | Wrong hash in the manifest | a copy of the manifest with a wrong `content_sha256` for rp-canary-07.docx | `test --mail 0 --sp 1 --od 0 --canary-cursor '0,6,0' --manifest <copy>` | `status fail: 1 of 1 item(s) didn't verify (0 missing, 1 mismatch)`, exit 5 | rp-canary-07.docx: MATCH `mismatch`, VERDICT `failed`, REASON `sha256` | As expected. Run `rp-20261003T201721Z-b9070514`, 2026-10-03T16:16:54.0154727Z point, manifest copy with 64 zeros as rp-canary-07.docx's `content_sha256`: one `Success` session, 1 of 1 restored; row `sharepoint  rp-canary-07.docx  manifest  yes  mismatch  failed  sha256`; `check: 0 match, 1 mismatch, 0 missing, 0 error`; `status fail: 1 of 1 item(s) didn't verify (0 missing, 1 mismatch)`; `--json` `check.items[0].mismatches` `["sha256"]`, `status.failed_items` `[0]`; `cleanup after ok: deleted 0 mail, 1 sharepoint, 0 onedrive`; stderr empty; exit 5; `graph list` 0. (A first attempt with the cursor unquoted got exit 64: PowerShell splits `0,6,0`; the commands now quote it.) | 2026-10-03 20:17Z | owner (run by Claude Code) |
| 7 | Wrong restore mailbox in config | a copy of the config with another `test_mailbox` | `test ... --config <copy>` | 7a: `config error: ...: config key "test_mailbox" must be restoretest@<domain>: ...`, exit 1, no run line; 7b: `status error graph: the run stopped before the restore: Microsoft Graph reported an error (graph); nothing was restored`, exit 4 (a 403 instead of Graph's 404 would give `target_guard`, exit 4) | none | As expected. 7a: stderr `config error: C:\restoreproof-runs\q31-s7a-config.json: config key "test_mailbox" must be restoretest@<domain>: restores only ever go to the restoretest mailbox`, stdout empty, exit 1. 7b: run `rp-20261003T201828Z-f798bac6`: `cleanup before incomplete: deleted 0 mail, 0 sharepoint, 0 onedrive; mail graph`; stderr Graph's `HTTP 404 (ErrorInvalidUser): The requested user 'restoretest@example.onmicrosoft.com' is invalid.` in the clean before and in `check error: ...; nothing was restored`; `status error graph: the run stopped before the restore: Microsoft Graph reported an error (graph); nothing was restored`; `cleanup after skipped: nothing was restored`; no Veeam restore session; exit 4; `graph list` 0 | 2026-10-03 20:18Z | owner (run by Claude Code) |
| 5 | Veeam REST service stopped (Q3.2) | Veeam's REST API service stopped | `test --mail 1 --sp 0 --od 0` | no run line, no status line: `restore error: Veeam POST https://localhost:4443/v8/token: could not connect: <curl's text> (5 attempts)`, exit 3 (`backup_transient`), nothing restored | none | As expected. Service `Veeam.Archiver.REST.Service` stopped with `Stop-Service`. stdout empty (no run line, no status line); stderr, exactly: `restore error: Veeam POST https://localhost:4443/v8/token: could not connect: Failed to connect to localhost:4443 after 4 ms: Could not connect to server (5 attempts)`; exit 3; no `--json` file written; nothing restored, no clean ran. Service started again, `veeam list` answered (10 restore points), `graph list` 0 | 2026-10-03 20:41Z | owner (run by Claude Code) |
| 6 | A Graph permission removed (Q3.2) | one of the Worker app's grants removed | `test --mail 0 --sp 1 --od 0` | Way A: `status error graph_permission: the run stopped before the restore: Microsoft Graph refused a permission the Worker relies on (graph_permission); nothing was restored`, exit 2; `check error:` naming `Sites.Selected read on the test site` | none | **Differs (Way A).** `Sites.Selected` revoked in Entra (Enterprise applications, Permissions); a fresh Worker token's roles were `Files.SelectedOperations.Selected`, `Lists.SelectedOperations.Selected` only. Run `rp-20261004T145435Z-22a2fc1e`: `cleanup before ok`, rp-canary-01.pdf restored (one `Success` session) and `match verified`, `status pass: 1 of 1 item(s) verified: manifest 1, fields 0, metadata 0`, `cleanup after ok: deleted 0 mail, 1 sharepoint, 0 onedrive`, exit 0. Not a status bug: the list-level `Lists.SelectedOperations.Selected` `write` grant (W3.4) alone lets the app read, list and delete in the RestoreTarget library, so nothing the Worker uses was missing. Finding: `Sites.Selected` read on the RestoreTest site looks unneeded since W3.4 (docs/security/graph-permissions.md #4's "#1 stays read: listing the library relies on it" doesn't hold). **Way A2 differs too:** `Lists.SelectedOperations.Selected` revoked as well; after about 4 minutes a fresh token's roles were `Files.SelectedOperations.Selected` alone (no SharePoint role). Run `rp-20261004T145929Z-62bfad56` (`--sp 1`): rp-canary-01.pdf restored, read back and `match verified`, `status pass: 1 of 1 item(s) verified: manifest 1, fields 0, metadata 0`, `cleanup after ok: deleted 0 mail, 1 sharepoint, 0 onedrive`, exit 0. SharePoint still let the app list, download and delete in the RestoreTarget library with neither `Sites.Selected` nor `Lists.SelectedOperations.Selected` in its token: either SharePoint caches app permissions, or its resource-specific grants are honoured under any `*.Selected` role; to be found out, #154 | 2026-10-04 14:54Z and 14:59Z | owner (run by Claude Code) |

## Before any scenario

Do these once per session. They are the steps of `docs/testing.md`, "Test by hand".

1. Open **Developer PowerShell for VS 2022** with **Run as administrator**, then:

   ```powershell
   cd C:\restoreproof\worker
   ```

2. Build: `cmake --build --preset dev`. The build must succeed.
3. Set the secrets for this window only:

   ```powershell
   $env:RP_VEEAM_USERNAME = 'rp-veeam'
   $env:RP_VEEAM_PASSWORD = '<the rp-veeam password from Credential Manager>'
   . ..\lab\entra\set-worker-env.ps1
   ```

4. Make a folder for run summaries, outside the repository (they hold tenant data):

   ```powershell
   New-Item -ItemType Directory -Force C:\restoreproof-runs
   ```

5. Check that the restore points are reachable and note the newest restore point's ID:

   ```powershell
   .\build\dev\rpworker.exe veeam list --config <your config.json>
   ```

6. Check that no Veeam restore session is still `Working` (Veeam console, **History**) and that
   no other RestoreProof run is going on.

In every command below, `<config>` is your `config.json` and `<manifest>` is
`..\lab\seed-manifest.json`. Each `--json` file name must be new: the command refuses an
existing file before it does anything.

**After every scenario,** check that the three restore targets are empty again:

```powershell
.\build\dev\rpworker.exe graph list --config <config>
```

Each target should show `0 item(s)` and no `(... not listed)` line. If something was left,
see `docs/testing.md`, "When something is left".

**Reading a run.** The status line `status <pass|fail|error>[ <code>]: <message>` is the
verdict. The exit code follows it: 0 `pass`, 5 `fail`, 1 to 4 `error` by its code
(`docs/worker-config.md`, exit codes). After the check, the table has one row per item:
`TYPE NAME EXPECTED FOUND MATCH VERDICT REASON MS`. Use `$LASTEXITCODE` right after the
command to see the exit code.

---

## Scenario 1: normal run (Q3.1)

**Purpose:** with nothing wrong, the whole run passes.

**Setup:** none. The lab is as seeded (L1.2 canaries and L1.8 real data), with a restore point
taken after both.

**Run:**

```powershell
.\build\dev\rpworker.exe test --mail 10 --sp 10 --od 10 --config <config> --manifest <manifest> --json C:\restoreproof-runs\q31-s1.json
$LASTEXITCODE
```

**Expected** (confirmed against the code 2026-10-03: `decide_status` row R8, `run_pipeline`'s
`finish`):
- stdout in this order: the restore point and `run <id>  seed <hex>` lines;
  `cleanup before ok: deleted 0 mail, 0 sharepoint, 0 onedrive`; `canary cursor 0,0,0 -> 5,5,5`
  and the KIND table (`5 of 5` canaries and random per type); `restoring 30 item(s) ...`; the
  session table; `restore succeeded: 30 of 30 item(s) restored in H:MM:SS`; the
  `TYPE NAME EXPECTED FOUND MATCH VERDICT REASON MS` table, every row FOUND `yes`, MATCH `match`,
  VERDICT `verified`, REASON `-`; `check: 30 match, 0 mismatch, 0 missing, 0 error`;
- the status line, exactly:
  `status pass: 30 of 30 item(s) verified: manifest 15, fields 5, metadata 10`
  (if a random pool comes up short, fewer items and a `warning: shortfall: <kind> random: <taken>
  of <wanted>` on stderr, but still `pass`; `fields` counts random mails, `metadata` random
  files);
- `cleanup after ok: deleted 10 mail, 10 sharepoint, 10 onedrive`, then the eleven-row
  `STEP TIME NOTE` table (NOTE empty in every row) and `wrote C:\restoreproof-runs\q31-s1.json`;
- exit code 0; nothing on stderr but log lines;
- `graph list` shows 0 in all three targets.

**Restore afterwards:** nothing.

---

## Scenario 2: canary mail deleted before a backup (Q3.1)

**Purpose:** an item that is missing from the backup is reported, and named.

**Setup:**
1. Sign in to Outlook on the web as alice (`alice@RestoreProofLab.onmicrosoft.com`).
2. In the **Inbox**, find the mail with subject **RP-CANARY-0003**.
3. Select it and press **Shift+Delete** (delete permanently), then confirm. It must not stay in
   Deleted Items, because Veeam backs that folder up too.
4. In the Veeam console, start the backup job **RP-Lab-Full** by hand (right-click,
   **Start**). Wait for it to finish with **Success**.
5. Run `veeam list` again and note the **new** restore point's ID (the newest one).

**Run:** the cursor `2,0,0` makes the mail rotation start at the third mail canary,
RP-CANARY-0003. `--mail 1` takes exactly one canary and no random mail.

```powershell
.\build\dev\rpworker.exe test --mail 1 --sp 0 --od 0 --canary-cursor '2,0,0' --point <new point ID> --config <config> --manifest <manifest> --json C:\restoreproof-runs\q31-s2.json
$LASTEXITCODE
```

Check that the header lists RP-CANARY-0003 as the canary taken.

**Expected** (the build with the Q3.1 fix, `docs/decisions.md` 2026-10-03, "Q3.1: an item the
restore point doesn't hold is reported per item"; confirmed against the code and its tests): the
connector finds no RP-CANARY-0003 in the new point's Inbox, reports it `not_in_backup` and sends
nothing; the point was taken after the manifest's `seeded_at` (2026-09-24T22:38:54Z), so item
rule I5 makes it *failed*:
- header: `canary cursor 2,0,0 -> 3,0,0`, mail `1 of 1` canaries, `restoring 1 item(s) ...`;
- no session table; `restore failed: 0 of 0 item(s) restored in H:MM:SS`;
- the row `mail  RP-CANARY-0003  manifest  no  missing  failed  not_in_backup  -`;
- `check: 0 match, 0 mismatch, 1 missing, 0 error`;
- `status fail: 1 of 1 item(s) didn't verify (1 missing, 0 mismatch)`, exit 5;
- `cleanup after ok: deleted 0 mail, 0 sharepoint, 0 onedrive`; stderr empty (no "the restore
  had started" note);
- the `--json` file: `status.failed_items` `[0]`, `restore.items[0].outcome` `not_in_backup`,
  `restore.items_sent` 0;
- `graph list` shows 0.

Before the fix the same run ended `status error not_in_backup: the restore didn't complete: ...;
items may be in the restore targets`, exit 4, naming no item (W3.3's open point).

If Veeam still lists the mail in the new point (it shouldn't once the mail is permanently
deleted), the run passes. Record that as the actual result and find out why.

**Restore afterwards:** put the original mail back. Re-sending it would give it a new message
ID, and the manifest would no longer match.
1. In the Veeam console, open **Explore** on an **older** restore point that still holds the
   mail (any point before step 4).
2. In Veeam Explorer for Exchange, open alice's mailbox, then **Inbox**, and find
   RP-CANARY-0003.
3. Right-click it, choose **Restore to original location**, and confirm.
4. Check that it is back in alice's Inbox.
5. Start **RP-Lab-Full** again so the newest restore point holds it again.

---

## Scenario 3: live file changed after the backup (Q3.1)

**Purpose:** RestoreProof checks what the backup holds, not what the live source holds today.
A restore from a point taken before an edit still matches the manifest.

The issue names `rp-canary-05.txt`, but canary 05 is a `.png`. The plain-text SharePoint
canaries are `rp-canary-04.txt` and `rp-canary-09.txt`. This scenario uses
**rp-canary-04.txt** (in the **RestoreTest library**, not RestoreTarget).

**Setup:**
1. Run `veeam list` and note the newest restore point's ID: that is the **older point**. Don't
   run a backup between this step and the run.
2. In a browser, open `https://restoreprooflab.sharepoint.com/sites/RestoreTest`, then the
   **RestoreTest** library.
3. Open `rp-canary-04.txt`, add a line such as `edited for Q3.1 scenario 3`, and save.

**Run:** the cursor `0,3,0` makes the SharePoint rotation start at its fourth canary,
rp-canary-04.txt.

```powershell
.\build\dev\rpworker.exe test --mail 0 --sp 1 --od 0 --canary-cursor '0,3,0' --point <older point ID> --config <config> --manifest <manifest> --json C:\restoreproof-runs\q31-s3.json
$LASTEXITCODE
```

**Expected** (confirmed against the code 2026-10-03: the manifest's `bytes` rule compares the
restored copy's SHA-256 and size with the manifest, never with the live file):
- header: `canary cursor 0,3,0 -> 0,4,0`, sharepoint `1 of 1` canaries, `0 of 0` random;
- `check: 1 match, 0 mismatch, 0 missing, 0 error`;
- `status pass: 1 of 1 item(s) verified: manifest 1, fields 0, metadata 0`, exit 0;
- rp-canary-04.txt: EXPECTED `manifest`, FOUND `yes`, MATCH `match`, VERDICT `verified`,
  REASON `-`;
- `cleanup after ok: deleted 0 mail, 1 sharepoint, 0 onedrive`;
- the Worker doesn't compare against the live source, so it prints no note that the live file
  differs. Write that note in the Actual column yourself.

**Restore afterwards:** upload the original over the edited one.
1. In the RestoreTest library, upload `C:\restoreproof\lab\canary\rp-canary-04.txt` and choose
   **Replace**.
2. Check the hash offline: `cd C:\restoreproof\lab; uv run python -m seeder hash` should still
   pass. That checks the local file. To check the live file, download it and compare its
   SHA-256 with the manifest's `content_sha256`, `f2d6976a...b392d8`.

---

## Scenario 4: wrong hash in the manifest (Q3.1)

**Purpose:** content that doesn't match the expectation is a `fail` that names the item and the
field.

**Setup:** never edit `lab/seed-manifest.json` itself. Use a copy outside the repository:
1. Copy it:

   ```powershell
   Copy-Item ..\lab\seed-manifest.json C:\restoreproof-runs\q31-s4-manifest.json
   ```

2. Open the copy in an editor and find the entry whose `id` is `rp-canary-07.docx`.
3. Change its `content_sha256` to 64 zeros (`0000...0000`, exactly 64 characters). Save.

**Run:** the cursor `0,6,0` makes the SharePoint rotation start at its seventh canary,
rp-canary-07.docx.

```powershell
.\build\dev\rpworker.exe test --mail 0 --sp 1 --od 0 --canary-cursor '0,6,0' --config <config> --manifest C:\restoreproof-runs\q31-s4-manifest.json --json C:\restoreproof-runs\q31-s4.json
$LASTEXITCODE
```

**Expected** (confirmed against the code 2026-10-03: the checker's `office-v1` comparison adds
`sha256` to `mismatches`; item rule I4, run row R5):
- header: `canary cursor 0,6,0 -> 0,7,0`, sharepoint `1 of 1` canaries;
- rp-canary-07.docx: EXPECTED `manifest`, FOUND `yes`, MATCH `mismatch`, VERDICT `failed`,
  REASON `sha256`;
- `check: 0 match, 1 mismatch, 0 missing, 0 error`;
- `status fail: 1 of 1 item(s) didn't verify (0 missing, 1 mismatch)`, exit 5;
- the `--json` file's `check.items[0].mismatches` is `["sha256"]` and `status.failed_items` is
  `[0]`;
- `cleanup after ok: deleted 0 mail, 1 sharepoint, 0 onedrive`, and `graph list` shows 0.

**Restore afterwards:** delete `C:\restoreproof-runs\q31-s4-manifest.json`. The repository's
manifest was never changed (`git status` shows it clean).

---

## Scenario 7: wrong restore mailbox in config (Q3.1)

**Purpose:** a config that points the Worker at the wrong mailbox never ends as `pass` and never
writes anywhere else.

The issue's setup (Veeam restores to `restoretest` while the reader looks at another mailbox)
can't happen in this build. The restore and the read-back both take the mailbox from the same
`test_mailbox` key, and two safety layers stop any other mailbox before anything is restored.
Both layers are tested here. The expected result is therefore stricter than the issue's
`fail`: an `error` before any restore.

**7a: another mailbox in `test_mailbox`.**
1. Copy your config to `C:\restoreproof-runs\q31-s7a-config.json`. Put `seed-manifest.json` next
   to it, or pass `--manifest`.
2. In the copy, set `"test_mailbox": "bob@RestoreProofLab.onmicrosoft.com"`.
3. Run:

   ```powershell
   .\build\dev\rpworker.exe test --mail 1 --sp 0 --od 0 --config C:\restoreproof-runs\q31-s7a-config.json --manifest <manifest>
   $LASTEXITCODE
   ```

**Expected 7a** (confirmed against `src/config.cpp`, `StringRule::restore_mailbox`): one line on
stderr, exactly

```text
config error: C:\restoreproof-runs\q31-s7a-config.json: config key "test_mailbox" must be restoretest@<domain>: restores only ever go to the restoretest mailbox
```

exit 1, before any Veeam or Graph call. Nothing on stdout: no run line and no status line. The
rule checks only the local part and the domain's shape; the domain itself is not compared with
the tenant's.

**7b: a `restoretest@` mailbox in another domain**, which passes the config rule:
1. Copy your config to `C:\restoreproof-runs\q31-s7b-config.json` and set
   `"test_mailbox": "restoretest@example.onmicrosoft.com"`.
2. Run the same command with that config, adding
   `--json C:\restoreproof-runs\q31-s7b.json`.

**Expected 7b** (confirmed against the code 2026-10-03; this corrects the first draft's
`target_guard`): `check_restore_mailbox` (`src/target_guard_graph.cpp`) turns only a **403** on the
Inbox into the guard's refusal. A mailbox that doesn't exist in the tenant answers **404
`ErrorInvalidUser`** (recorded live 2026-09-28, `worker/tests/fixtures/graph/messages-404-unknown-user.json`),
which `GraphClient` makes a `graph::NotFoundError` on purpose ("a wrong test_mailbox, never an
item missing from a restore"), code `graph`. So:
- stdout: the restore point and run lines, then
  `cleanup before incomplete: deleted 0 mail, <b> sharepoint, <c> onedrive; mail graph` (the
  library and folder are still cleaned; `<b>`/`<c>` 0 when they were empty);
- stderr: the Cleaner's log line `... cleanup before: the test mailbox's Inbox: stopped (graph):
  Graph GET /v1.0/users/restoretest@example.onmicrosoft.com/mailFolders/inbox: HTTP 404
  (ErrorInvalidUser): ...`, then `cleanup error: mail: Microsoft Graph gave an answer the
  cleanup can't use (graph)` and `warning: cleanup: mail not emptied before the run (left 0,
  skipped 0, graph)`;
- a `graph` error in the clean before doesn't stop the run (only `target_guard` does), so the
  header follows (`canary cursor 0,0,0 -> 1,0,0`, mail `1 of 1`, `restoring 1 item(s) ...`; no
  Veeam session is opened, since a 1-item sample has no random half), then the before snapshot
  runs the same mailbox check and stops: stderr `check error: Graph GET ...: HTTP 404
  (ErrorInvalidUser): ...; nothing was restored`;
- stdout, exactly:
  `status error graph: the run stopped before the restore: Microsoft Graph reported an error (graph); nothing was restored`,
  then `cleanup after skipped: nothing was restored`, the timings table and
  `wrote C:\restoreproof-runs\q31-s7b.json`;
- exit 4. Nothing restored, no Veeam restore session.

If Graph answers **403** instead (Exchange's RBAC scope check before the user lookup), the clean
before is refused by the guard and the run stops there:
`cleanup before incomplete: ...; mail target_guard`, a `SECURITY: cleanup: ...` log line, then
`status error target_guard: the run stopped before the restore: the restore-target guard refused (target_guard); nothing was restored`,
exit 4. Record which one happened; both are `error`, exit 4, nothing restored, never `pass` or
`fail`, but only the first equals "Expected".

**Restore afterwards:** delete both config copies. Your real config was never changed.

---

## Scenario 5: Veeam REST service stopped (Q3.2)

**Purpose:** an unreachable Veeam is an `error`, never a `fail`, and nothing is restored.

The issue's code `veeam_unreachable` is now `backup_transient`, because the status codes are
product-neutral (`docs/decisions.md`, W3.3).

**Setup:**
1. Press Win+R, type `services.msc` and press Enter.
2. Find **Veeam Backup for Microsoft 365 REST API Service** (the RESTful API service of
   Veeam Backup for Microsoft 365). Right-click it and choose **Stop**.

**Run:**

```powershell
.\build\dev\rpworker.exe test --mail 1 --sp 0 --od 0 --config <config> --manifest <manifest> --json C:\restoreproof-runs\q32-s5.json
$LASTEXITCODE
```

The client retries 5 times with waits, so this can take a few minutes.

**Expected** (confirmed against the code 2026-10-03: `VeeamClient`'s `throw_transport_error`,
`VeeamM365Connector::list_restore_points`, `run_pipeline`'s `restore_failed` before `phase` is
set, `exit_code_of("backup_transient")`):
- the first Veeam call (the sign-in for listing the restore points) fails before the run line,
  so nothing on stdout: no run line, no status line, no timings and no `--json` file (the
  summary is written only by a run that has a run line);
- stderr has exactly one line:
  `restore error: Veeam POST https://localhost:4443/v8/token: could not connect: <curl's text> (5 attempts)`;
  copy it into the Actual column exactly;
- exit 3 (transient; the code `backup_transient`);
- nothing restored, `graph list` shows 0. The clean before didn't run either, because it comes
  after the run line.

**Restore afterwards:** in `services.msc`, **Start** the service again. Restarting Veeam's REST
service invalidates every token, which is harmless here. Run `veeam list` to check that it
answers.

---

## Scenario 6: a Graph permission removed (Q3.2)

**Purpose:** a missing permission is an `error` naming the grant, never a `fail`.

The issue's `Mail.Read` no longer exists. Since W3.4 the Worker app's mail access is the
Exchange RBAC role **Application Mail.ReadWrite**, scoped to `restoretest`. A 403 on that
mailbox's Inbox counts as the guard's refusal (`target_guard`, exit 4), not as
`graph_permission`. A removed Graph app role gives `graph_permission`, exit 2. Pick one way
below and write the exact expected line in "Expected" **before** running. To get it, read
`docs/security/graph-permissions.md` and the code paths (`rp/graph_errors.hpp`,
`rp/run_status.hpp`'s `stop_reason`, the cleaner's codes).

**Way A (recommended): revoke the `Sites.Selected` app role.**
1. Open the Entra admin center: **Enterprise applications**, then **RestoreProof Worker**,
   then **Permissions**.
2. On **Sites.Selected**, choose **Revoke permission** and confirm.
3. Wait about 10 minutes so that new tokens no longer carry the role. To check, run
   `cd C:\restoreproof\lab; uv run python -m seeder check-worker-app`: the SharePoint read
   should now be denied.

**Run:**

```powershell
.\build\dev\rpworker.exe test --mail 0 --sp 1 --od 0 --config <config> --manifest <manifest> --json C:\restoreproof-runs\q32-s6.json
$LASTEXITCODE
```

**Expected** (confirmed against the code 2026-10-03: `check_restore_library` reads
`GET /drives/{test_library_id}` under `kSitesReadGrant`; `GraphClient` makes a 403 Graph explains
a `PermissionError` naming the grant; the Cleaner and `stop_reason` both map it through
`read_error_code` to `graph_permission`; only `target_guard` in the clean before stops a run):
- stdout: the restore point and run lines, then
  `cleanup before incomplete: deleted <a> mail, 0 sharepoint, <c> onedrive; sharepoint graph_permission`;
- stderr: the Cleaner's log line `... cleanup before: the RestoreTarget library: stopped
  (graph_permission): Graph denied GET /v1.0/drives/<test_library_id> (403 accessDenied): the
  Worker app relies on Sites.Selected read on the test site; see
  docs/security/graph-permissions.md ...`, then `cleanup error: sharepoint: Microsoft Graph
  refused a permission the cleanup relies on (graph_permission)` and `warning: cleanup:
  sharepoint not emptied before the run (left 0, skipped 0, graph_permission)`;
- the header (`canary cursor 0,0,0 -> 0,1,0`, sharepoint `1 of 1`, `restoring 1 item(s) ...`),
  then the before snapshot hits the same refusal: stderr `check error: Graph denied GET
  /v1.0/drives/<test_library_id> (403 accessDenied): the Worker app relies on Sites.Selected read
  on the test site; see docs/security/graph-permissions.md[ (request-id ...)]; nothing was
  restored`;
- stdout, exactly:
  `status error graph_permission: the run stopped before the restore: Microsoft Graph refused a permission the Worker relies on (graph_permission); nothing was restored`,
  then `cleanup after skipped: nothing was restored`, the timings table and
  `wrote C:\restoreproof-runs\q32-s6.json`;
- exit 2, nothing restored, never `fail`.

**Not yet proven live:** that listing the RestoreTarget library needs `Sites.Selected` at all.
Since W3.4 the app also holds `Lists.SelectedOperations.Selected` `write` on that very list
(`docs/security/graph-permissions.md` #4 says "#1 stays `read`: listing the library relies on
it", but no run has tried without #1). If the list grant alone is enough, this run **passes**:
that is Actual ≠ Expected, and a finding (`Sites.Selected` could be dropped), not a bug in the
status. If SharePoint masks the refusal as 404 `itemNotFound` instead of 403, the code is
`graph`, exit 4. Either way, record the exact lines.

**Restore afterwards:**
1. On the app's **API permissions** page (App registrations, then RestoreProof Worker), choose
   **Grant admin consent for RestoreProofLab** so that `Sites.Selected` is granted again. The
   per-site grants on the RestoreTest site are kept.
2. Run `..\lab\entra\check-worker-grants.ps1` and
   `cd C:\restoreproof\lab; uv run python -m seeder check-worker-app`. Both must pass.
3. Rerun scenario 1 if in doubt.

**Way A2 (run on 2026-10-04 after Way A passed): revoke both SharePoint roles.** Way A showed
that the list-level `Lists.SelectedOperations.Selected` `write` grant alone lets the app read the
RestoreTarget library (a pass; finding recorded in the Results table). So `Lists.SelectedOperations.Selected`
is revoked too, the same way, leaving the app no SharePoint role (the token keeps
`Files.SelectedOperations.Selected`, so it still has a `roles` claim). Same command, `--json
C:\restoreproof-runs\q32-s6b.json`.

**Expected A2** (written before the run): the same lines as Way A's Expected above:
`cleanup before incomplete: deleted 0 mail, 0 sharepoint, 0 onedrive; sharepoint graph_permission`,
`check error: Graph denied GET /v1.0/drives/<test_library_id> (403 accessDenied): the Worker app
relies on Sites.Selected read on the test site; ...; nothing was restored`, then
`status error graph_permission: the run stopped before the restore: Microsoft Graph refused a permission the Worker relies on (graph_permission); nothing was restored`,
`cleanup after skipped: nothing was restored`, exit 2. If SharePoint masks the refusal as 404
`itemNotFound`, the code is `graph`, exit 4 (`... (graph); nothing was restored`). Never `fail`.

**Restore afterwards (A2):** on the app's **API permissions** page, **Grant admin consent for
RestoreProofLab** brings back both roles; the site and list grants themselves were never removed.
Then `check-worker-grants.ps1` and `check-worker-app` must pass.

**Way B (mail): remove the Exchange role assignment**
`RestoreProof Worker - Application Mail.ReadWrite - restoretest`
(`Remove-ManagementRoleAssignment` in Exchange Online PowerShell), run with
`--mail 1 --sp 0 --od 0`, and expect `error target_guard`, exit 4. Restore it with
`lab\entra\new-worker-app.ps1`, then `check-worker-grants.ps1`. This takes longer to undo, so
use Way A unless the owner wants both.
