# Decision log

One entry per architectural choice. Newest first. Add an entry whenever a new choice is
made; never rewrite an old one — supersede it with a new entry that links back.

Format: date, decision, reason, alternatives rejected.

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
  defined once in `worker/include/rp/secrets.hpp`. An unset one is not an error, because
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
