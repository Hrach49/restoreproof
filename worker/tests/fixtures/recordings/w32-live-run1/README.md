# W3.2 live run 1: `rpworker restore --record`, 2026-10-01

Every exchange of one live restore against the lab, recorded by the Worker itself
(Q2.1's recorder, `rp/recording_http_client.hpp`; format in `../../veeam/README.md`,
"Recorded by the Worker"): `veeam/` (139 files), `graph/` (23) and `download/` (6).

```
rpworker restore --mail 5 --sp 5 --od 5 --canary-cursor 0,0,0 --manifest ..\lab\seed-manifest.json
                 --config %LOCALAPPDATA%\RestoreProof\lab\config.json --record <dir>
```

- Run `rp-20261001T172150Z-b029c118` (seed `311f1eea`), restore point
  `2026-09-30T22:00:43.4764524Z`; the three restore targets were empty before.
- Sample: 3 canaries of each type and 2 random mails from the owner's mailbox; the SharePoint
  and OneDrive random halves were short (no real files in the lab).
- 11 of 11 restored in four `Success` sessions; check: 11 match; exit 0.

`worker/tests/restore_replay_test.cpp` replays the whole command from these files through the
real `veeam_m365` connector (with the run's ID, so the sample is the one the live run drew) and
checks the console output line for line, but for the total time and each item's ms, which are
the replay's clock's. `graph_targets_test.cpp` reads `graph/013`, `015` and `020` to show that
Graph lists the fields W3.2 checks (`sentDateTime`, `createdDateTime`, `cTag`,
`lastModifiedDateTime`).

## Downloads

`download/` holds each download's size and SHA-256 only (the recorder never keeps a download's
bytes). The replay serves each file the canary's own bytes from `lab/canary/`. They are the
bytes the live run downloaded for the four pdf and OneDrive files; the SharePoint docx and xlsx
(`002`, `003`) are SharePoint's rewrite of them (15563 and 19993 bytes), whose office-v1 hash is
the manifest's as the original's is. The test checks both.

## Secrets: what was checked before copying

Every file was searched for `password`, `pfx`, `eyJ` (JWTs), `MII` and `BEGIN ` (certificates),
`Authorization`, `Bearer <token>`, `client_assertion`, `client_secret`, `x5t`, `sig=`,
`SharedAccessSignature`, `token=`, a `tempauth` value other than `SCRUBBED`, and any run of 200
or more Base64 characters. Nothing was found: `access_token` and `refresh_token` are
`[REDACTED]`, each restore POST's `applicationCertificate` and
`applicationCertificatePassword` are `[REDACTED]`, and every download link's query values are
`SCRUBBED`.

## Edited (privacy)

The two random mails, "Weekly digest: Microsoft service updates" and "Veeam website
registration", are real mails of the lab owner's mailbox. Random mails carry no body
expectation (only subject, sender and times are compared), so the check is unchanged:

- `graph/013-get-v1-0-users-restoretest-...-mailf.json` (the after-restore listing with bodies):
  both mails' `body.content` (104584 and 677 characters) replaced with
  `Placeholder text: this real mail's body was removed from the fixture (see README.md).`
  Their subject, sender, times and IDs are as recorded; the canaries' bodies are untouched.
  Graph listed no recipients (`$select` doesn't ask for them).
- `veeam/018-...` and `veeam/069-...` (Veeam's listing of the owner's Inbox): the invoice number
  in the subject "Twoja faktura Microsoft G186548938 jest gotowa", a mail the run didn't sample,
  replaced with `G000000000`. Veeam's listings hold no bodies or previews, only subject, sender,
  recipients' names and times.

Nothing else was changed.
