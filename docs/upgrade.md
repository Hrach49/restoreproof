# The Worker after the install: versions, upgrades, rollback, uninstall

W7.3 and W7.4 (`docs/decisions.md` 2026-10-19, "W7.3 (#82) and W7.4 (#83)"). The install
itself is W7.1's (`docs/testing.md` "The Worker installer (W7.1)"; `docs/onboarding.md` step 3).
Everything here runs from an elevated PowerShell 7 on the Veeam server.

## The version

One number, `major.minor.patch`, in one place: `project(... VERSION x.y.z)` in
`worker/CMakeLists.txt`. The build embeds it (`rp::version()`), and it is what `rpworker
--version` prints, what every result bundle carries, what the Worker sends when it registers
and in every heartbeat (so the Cloud's `worker.version` and the `/workers` page show the
version the service runs, from its first heartbeat after a start), and what the Apps & features
entry shows as `DisplayVersion`. Three ways to read it on a machine:

```
rpworker --version                     # the exe
Settings > Apps > RestoreProof Worker   # the entry the installer writes (or `Get-Package`)
```

and, for every Worker, the Cloud's `/workers` page.

**The rule.** The PR that ships a package bumps the number: the patch for a fix or a small
change of the Worker or its scripts, the minor for a new command or a changed contract
(`result.v1`, the jobs, the config), the major for `/v2`. A version shipped once is never built
again with other bytes: `worker\tools\package.ps1` refuses to overwrite a zip of the same
version under its output folder unless `-Force`; bump the number instead. The owner may tag
the commit that shipped a package `worker-v<version>`. The package is
`RestoreProof-Worker-<version>.zip`: the exe, its DLLs, the five scripts
(`Install-RestoreProofWorker.ps1`, `Uninstall-RestoreProofWorker.ps1`, `RestoreProofWorker.psm1`,
`WorkerMachine.psm1`, `New-WorkerGraphCertificate.ps1`) and `config.example.json`.

The installer copies the scripts into `%ProgramFiles%\RestoreProof\` beside the exe, so the
uninstall and the rollback are there once the package folder is gone, and writes the Apps &
features entry (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RestoreProofWorker`:
the name, the version, the folder, the uninstall line; the one registry key of RestoreProof's).

## The upgrade

Unpack the new package anywhere, then from an elevated PowerShell 7:

```
pwsh -File <unpacked package>\Install-RestoreProofWorker.ps1 -Upgrade
```

It is the installer with one switch. In order, each step one `ok:`/`change:` line as every
step of the installer's:

1. The checks of the install. The service must be the one the installer made (its command line
   `"<ProgramDir>\rpworker.exe" service run`); a service installed from another exe stops it.
   The package's version and the installed exe's are printed: `upgrade: 0.1.0 -> 0.1.1`
   (`(the files differ)` for the same version with other bytes; `(a downgrade: a rollback)`
   for a lower one). The same files already installed: `ok: rpworker 0.1.1 is installed
   already`, and nothing is stopped.
2. **The wait for a run in progress.** While `state\running.json` is there (the record the
   service writes ahead of every step of a run and deletes after the run and its hold), the
   script waits, reading it every 10 s and printing one line a minute (`waiting: run <id> in
   progress for <m> min`), for `-WaitMinutes` (30 by default; `0` stops at once). Past the
   budget it stops with nothing changed: `rpworker doctor` shows the run, and
   `docs/worker-config.md` "The operator's two ways out" says what to do. A restore is never
   cut in half by an upgrade.
3. `rpworker service stop`. A run taken between the wait's last read and the stop (a job taken
   at a poll in that window) is said in one line and left to the new version's first start,
   whose recovery closes it, waits for Veeam and cleans the restore targets (W4.8).
4. The installed files (the exe, the DLLs, the scripts) are moved to
   `%ProgramFiles%\RestoreProof\previous\` (emptied first: one level, the version before this
   one) and the package's copied in, so the folder holds exactly the package's files.
5. The Apps entry's version; `rpworker config check` on the kept config (a config the new
   version refuses stops here, with the rollback line); then the installer's own steps find
   nothing to change: the folders' ACLs, the vault's names, the signing key, the Graph
   certificate, the key-file grants, the service's definition and the registration are **not
   touched** (`vault list` and `state\worker.json` are the same before and after).
6. `rpworker service start`. The summary ends `upgraded 0.1.0 -> 0.1.1; the previous version is
   in <ProgramDir>\previous (rollback: ...)`. The service's first heartbeat (seconds after the
   start) carries the new version; `/workers` shows it.

`-WhatIf` prints the whole plan, the versions included, and writes nothing. An upgrade needs
no new install token and no Cloud change: the Worker keeps its key, its token and its row.
`-Upgrade` given with no service installed is a plain install and says so.

### Windows and the running exe

Windows refuses to overwrite a running exe or a loaded DLL (a sharing violation), which is why
the service is stopped first and why the swap is a move and a copy, not a copy over.

## The rollback

Every upgrade keeps the version before it as `%ProgramFiles%\RestoreProof\previous\`. To go
back:

```
pwsh -File "C:\Program Files\RestoreProof\Install-RestoreProofWorker.ps1" -Upgrade -Package "C:\Program Files\RestoreProof\previous"
```

The same path as an upgrade, printed as `upgrade: 0.1.1 -> 0.1.0 (a downgrade: a rollback)`:
the wait, the stop, the swap, the start. After it `previous\` holds the version rolled back
from, so a second rollback (two versions back) needs that version's zip: keep the previous
package's zip beside the new one until the new version has run for a while. The config, the
vault, the grants and the registration are the ones the upgrade kept, so nothing else moves.
One thing a rollback can't undo: a `config.json` the old version can't read (a key it doesn't
know), which the old version's `config check` names at step 5; the fix is the config, not the
exe.

## The uninstall

```
pwsh -File "C:\Program Files\RestoreProof\Uninstall-RestoreProofWorker.ps1" [-Full] [-WaitMinutes <n>] [-WhatIf]
```

Also from Settings > Apps > RestoreProof Worker > Uninstall (which runs that line), or from the
unpacked package. It asks nothing. **Nothing is removed before the service is uninstalled
(step 8)**: every stop before it leaves the Worker installed (stopped from step 3 on;
`rpworker service start` brings it back). In order:

1. The checks. A service installed from another exe is refused: this script takes away what
   the installer put there and nothing else (`rpworker service stop`, then `rpworker service
   uninstall` by hand first).
2. The wait for a run in progress, as the upgrade's (`-WaitMinutes`, 30).
3. `rpworker service stop`.
4. A record still there after the stop (a job taken in the window): `rpworker service start`
   once more, the wait again, `rpworker service stop` again, so the service's own recovery
   closes the run, holds for Veeam's sessions and cleans the restore targets. A record that
   doesn't go within the budget stops the uninstall with the service stopped and nothing
   removed: the targets may hold that run's restore, and the record says which.
5. **The outbox, once**: `rpworker outbox flush` when the vault holds the API token, so what
   the Worker tested and signed reaches the Cloud before its folder goes (`<n> queued, <m>
   sent, <k> failed` printed). The runs that still never reached the Cloud are named: `note:
   <n> run(s) never reached the Cloud and go with the folder: <ids>`. A run folder that
   outlives the Worker is nobody's: nothing is edited or re-signed, and no other Worker can
   send it.
6. **The Cloud told**: `rpworker cloud revoke` (`docs/worker-config.md`). `revoked worker <id>`
   is a change; a Cloud that no longer knows the token (revoked already) is `ok:`; a Cloud not
   reached is `note: the Cloud wasn't reached (...): revoke this Worker in the Cloud:
   manage.py revoke-worker --worker-id <id>, or the Workers page`, and the uninstall goes on.
7. **The key files**: for every organisation `rpworker veeam list` names, the service account's
   entry is taken off its certificate's private key file (`icacls "<key file>" /remove:g
   *S-1-5-80-...`, through .NET by SID as the installer grants it).
8. `rpworker service uninstall`.
9. **The data**: `vault.bin` and every file under `state\`, `runs\`, `outbox\`, `sent\` and
   `failed\` are each **overwritten once in place with random bytes, flushed to the disk, then
   deleted**, and those five folders removed; `config.json`, `veeam-rest.pem` and
   `cloud-ca.pem` deleted. Anything else under `%ProgramData%\RestoreProof` (a lab's folder,
   `canaries\`, a copy someone kept) is left and named: `note: <path> left: not the
   installer's`. A file that can't be opened (held by another program) is one `problem:` line,
   the rest goes on, and the script ends with `problems: <n>` and exit 1.
10. `%ProgramFiles%\RestoreProof\` whole (`previous\` included) and the Apps & features entry.
11. `logs\` and the data folder itself stay, with the folder's protected ACL (the log is for a
    post-mortem and holds no secret: every line went through `redact()`), unless **`-Full`**:
    then `logs\` goes and the folder with everything still in it, what step 9 named included.

The summary: `changes: <n>`, `left: <root>\logs (...)` when it stayed, and what the overwrite
is and isn't.

### What "overwritten once, then deleted" is, and isn't

`vault.bin` is DPAPI under the machine's key (W4.5): its bytes are useless off this machine,
and on it any SYSTEM or administrator process could decrypt them while the file was there.
Overwriting the file before deleting it defeats an undelete tool, and costs one write. **It
guarantees no erasure:** an SSD's wear levelling may keep the old bytes in cells the overwrite
never reached, and a volume shadow copy keeps a file's old contents whatever is written over
it. The secrets are made worthless by revoking them, which is what the uninstall does and says:

- the Cloud's API token: revoked at step 6 (or by hand in the Cloud);
- the Worker's Graph certificate: its private key went with the vault; the public half stays as
  a credential of each client's "RestoreProof Worker" app, which the client's admin may remove
  (`docs/tenant-setup.md`);
- the Veeam account's password: Veeam's console; change it if the machine is not being wiped.

The run folders hold no secret (tenant item names and subjects, the signed results): the same
one write is spent on them because it is cheap, not because it is needed.

### After the uninstall

The Worker's row in the Cloud is revoked and keeps its runs as evidence; its plans keep making
queued runs that nothing dispatches until they are disabled or moved to another Worker
(`docs/onboarding.md` step 6). The Veeam account and its role are Veeam's. The virtual account
`NT SERVICE\RestoreProof` exists only while the service does.
