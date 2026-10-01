# W3.2 live run 2: `rpworker restore --record` over run 1's copies, 2026-10-01

Every exchange of the second live restore, recorded as `../w32-live-run1/` was (Q2.1's
recorder; format in `../../veeam/README.md`, "Recorded by the Worker"): `veeam/` (144 files),
`graph/` (23) and `download/` (6). Same command line as run 1, so the same canaries:

```
rpworker restore --mail 5 --sp 5 --od 5 --canary-cursor 0,0,0 --manifest ..\lab\seed-manifest.json
                 --config %LOCALAPPDATA%\RestoreProof\lab\config.json --record <dir>
```

- Run `rp-20261001T172815Z-6285c4a6` (seed `be2461b7`), restore point
  `2026-09-30T22:00:43.4764524Z`, the targets still holding run 1's 11 copies. (An attempt
  before it, `rp-20261001T172434Z-999c6dea`, stopped before any restore when Veeam's explore
  session Stop timed out; it is not here.)
- The same 3 canaries of each type and the same 2 random mails, drawn in another order.
- Veeam reported 11 of 11 restored in four `Success` sessions. Every file's `cTag` moved; the
  Inbox gained no mail (Veeam's `changedItems` restore writes nothing that is already there).
- Live, the build of the day reported the five mails `missing` (exit 5). Since commit 6fd89e9
  they are `error` `stale_target`, with one warning about 5 earlier mail copies; the files
  `match`; exit 4 (`docs/decisions.md` 2026-10-01, "W3.2 live run").

`worker/tests/restore_replay_test.cpp` replays the whole command from these files through the
real `veeam_m365` connector and checks that output line for line, but for the total time and
each item's ms, which are the replay's clock's: the regression test for that fix.

## Downloads

As in run 1: `download/` keeps sizes and SHA-256s only, and the replay serves the canaries' own
bytes from `lab/canary/`, which are what was downloaded but for the SharePoint docx and xlsx
(`002`, `003`), SharePoint's rewrite of them (their office-v1 hash is the manifest's either
way). The rewritten files' digests differ from run 1's: SharePoint rewrote them again.

## Secrets: what was checked before copying

The same search as run 1 (`../w32-live-run1/README.md`): no password, PFX, certificate, JWT,
`Authorization` or `Bearer` value, client assertion or secret, unscrubbed `tempauth`, or long
Base64 run. Tokens and the restore POSTs' credential are `[REDACTED]`, download link query
values `SCRUBBED`.

## Edited (privacy)

As in run 1, for the two real mails of the owner's mailbox ("Weekly digest: Microsoft service
updates", "Veeam website registration"), which carry no body expectation:

- `graph/013-get-v1-0-users-restoretest-...-mailf.json` (the after-restore listing with bodies):
  both mails' `body.content` (104584 and 677 characters) replaced with
  `Placeholder text: this real mail's body was removed from the fixture (see README.md).`
  `graph/003` (the before listing) asks for no body and is unchanged.
- `veeam/021-...` and `veeam/069-...` (Veeam's listing of the owner's Inbox): the invoice number
  in the subject "Twoja faktura Microsoft G186548938 jest gotowa", a mail the run didn't sample,
  replaced with `G000000000`.

Nothing else was changed.
