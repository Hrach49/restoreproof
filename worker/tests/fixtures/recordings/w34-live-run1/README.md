# W3.4 live run 1: `rpworker restore --record` with the Cleaner, 2026-10-02

Every exchange of the first live restore with W3.4's clean before and after, recorded by the
Worker itself (Q2.1's recorder, `rp/recording_http_client.hpp`; format in
`../../veeam/README.md`, "Recorded by the Worker"): `veeam/` (142 files), `graph/` (52) and
`download/` (6), 200 in all, as the run printed (`recorded 200 exchange(s)`). The owner ran it
in an elevated shell:

```
rpworker restore --mail 5 --sp 5 --od 5 --manifest ..\lab\seed-manifest.json
                 --config %LOCALAPPDATA%\RestoreProof\lab\config.json --record <dir>
```

- Run `rp-20261002T180310Z-6661beff` (seed `6933ea77`), restore point
  `2026-10-01T22:01:38.761857Z`; no `--canary-cursor`, so `0,0,0`.
- The clean before found the three targets empty: `cleanup before ok: deleted 0 mail,
  0 sharepoint, 0 onedrive`.
- Sample: 3 canaries of each type and 2 random mails from the owner's Sent Items ("sub" and
  "RestoreProof W2.2 second mail 3n5w", both lab test mails); the SharePoint and OneDrive
  random halves were short (no real files in the lab).
- 11 of 11 restored in four `Success` sessions; check: 11 match; `status pass: 11 of 11
  item(s) verified: manifest 9, fields 2, metadata 0`; two shortfall warnings.
- The clean after: `cleanup after ok: deleted 5 mail, 3 sharepoint, 3 onedrive`; exit 0.
  `rpworker graph list` showed 0 items in all three targets before and after the run
  (`docs/api/veeam-lab/w3.4-live-*`).

The console output is `docs/api/veeam-lab/w3.4-live-3-restore.txt`.

## What `graph/` holds

| Files | Step |
|---|---|
| `001` | the token |
| `002`–`010` | the clean before: per target the guard's check, then the Cleaner's listing and its listing again, all empty |
| `011`–`016` | the before snapshot (the guard's checks and the reader's listings, empty) |
| `017` | a second token |
| `018`–`020` | the target guard's layer 1 in `restore_sample`, before any Veeam call |
| `021`–`032` | the after read: the guard's checks, the mails with bodies, the files and their six `/content` 302s |
| `033`–`040` | the clean after, mail: the Inbox check, the listing of 5 (`034`), 5 `permanentDelete`s answered 204 (`035`–`039`), the listing again, empty (`040`) |
| `041`–`046` | the clean after, library: the drive check, the listing of 3 (`042`), 3 `DELETE`s answered 204 (`043`–`045`), the listing again, empty |
| `047`–`052` | the clean after, OneDrive: the folder check, the listing of 3 (`048`), 3 `DELETE`s answered 204 (`049`–`051`), the listing again, empty |

The targets were empty before the run, so the clean before deleted nothing, and nothing was
deleted twice: the recording holds no 404 (nor 403 or 412). Those stay hand-written in
`../../graph/` (its README.md, "The Cleaner's fixtures").

## Who reads it

- `worker/tests/restore_replay_test.cpp` replays the whole command from these files through
  the real `veeam_m365` connector and the real Cleaner, with the run's ID, so the sample is the
  one the live run drew. It checks the console output line for line (but for the total time,
  which is the replay's clock's: 0:02:30 against the live 0:02:38, and each item's ms), that
  every recorded exchange was asked for and nothing else (route by route: each request line
  as often as the recording holds it), that the canaries downloaded have the recorded digests
  (but the rewritten SharePoint docx and xlsx), and that each `DELETE` and
  `permanentDelete` names an item the latest listing of its own target held (a file with that
  listing's `eTag` as `If-Match`), 5 mails and 3 + 3 files, each once, all after the after read.
- `worker/tests/cleaner_test.cpp` uses `034`, `042` and `048` as its listings (edited in the
  test for the refusal rows) and `035` and `043` as its 204s; `restore_command_test.cpp` uses
  `035`.

## Downloads

As in W3.2's runs: `download/` keeps sizes and SHA-256s only, and the replay serves each file
the canary's own bytes from `lab/canary/`, which are what was downloaded but for the SharePoint
docx and xlsx (`002`, `003`), SharePoint's rewrite of them (their office-v1 hash is the
manifest's either way).

## Secrets: what was checked before copying

Every file was searched for JWTs (`eyJ` followed by Base64), `client_assertion`,
`client_secret`, `password`/`pfx`/`applicationCertificate` keys and their values, `tempauth`
values, `Bearer <token>`, `Authorization`, `MII` and `BEGIN ` (certificates), `x5t`, `sig=`,
`SharedAccessSignature`, `token=`, and runs of 200 or more Base64 characters. Nothing secret was
found:

- `access_token` (Graph's two tokens, Veeam's) and Veeam's `refresh_token` are `[REDACTED]`;
- each of the four restore POSTs' `applicationCertificate` and `applicationCertificatePassword`
  is `[REDACTED]`; the only other such key is `applicationCertificateThumbprint` in Veeam's
  organisation listing, the certificate's public SHA-1 thumbprint (as in W3.2's recordings);
- every `tempauth` (the six `/content` 302s and the six downloads) is `SCRUBBED`;
- the long runs are Veeam's item IDs and their `href`/`uri` links, as in W3.2's recordings.

## Edited

Nothing. The two random mails are lab test mails the owner sent while building W2.2 (their
bodies are `Su b` and `RestoreProof W2.2 second body 8d6r`), and Veeam's listings hold no real
mail of the owner's that W3.2's recordings had to edit.
