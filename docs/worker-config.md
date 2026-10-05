# Worker configuration

How the Worker is configured: the settings file, the secrets, and how to check both with
`rpworker config check`, then how `rpworker veeam list`, `rpworker graph list` and `rpworker
restore` use them, and the exit codes of every `rpworker` command. The contract is in `worker/include/rp/config.hpp` and
`worker/include/rp/secrets.hpp`; where this page and the code disagree, the code wins.

## Where the file lives

By default the Worker reads `%ProgramData%\RestoreProof\config.json` (usually
`C:\ProgramData\RestoreProof\config.json`). `%ProgramData%` is resolved through Windows
(`FOLDERID_ProgramData`), not from the environment variable. `rpworker config check --config
<path>` reads another file instead; the path may contain any character, including ones
outside the machine's ANSI code page.

The file is JSON with one flat object of settings. A UTF-8 byte order mark, as Notepad writes,
is accepted. `worker/config.example.json` has every key with placeholder values, except
`veeam_ca_file` and `veeam_cert_sha256`: `veeam_ca_file` must name a file that exists, so a
placeholder would make the example fail to load, and `veeam_cert_sha256` needs it. Copy the
example, fill in your own values, and add those two keys if you need them.

## Settings

Ten keys are required; the other nine are optional. Seven of those have defaults; without
`veeam_ca_file` the Worker trusts the Windows certificate store, and without
`veeam_cert_sha256` it checks the Veeam server's host name.

| Key | Required | Default | Valid values | What it is for |
|---|---|---|---|---|
| `cloud_url` | yes | | `https://` URL, printable ASCII only, no user name, password, query or fragment | The RestoreProof Cloud the Worker gets jobs from and uploads results to. |
| `veeam_url` | yes | | `https://` URL, printable ASCII only, no user name, password, query or fragment | The Veeam Backup for Microsoft 365 REST API, e.g. `https://veeam.example.invalid:4443`. |
| `veeam_org_name` | yes | | non-empty string | The Microsoft 365 organisation as Veeam names it, e.g. `example.onmicrosoft.com`. |
| `graph_tenant_id` | yes | | a GUID: see below | The Microsoft 365 tenant ID, for Microsoft Graph sign-in: see "Microsoft Graph app" below. Not the tenant's domain name. |
| `graph_client_id` | yes | | a GUID: see below | The application (client) ID of the Worker's own app registration, "RestoreProof Worker": see "Microsoft Graph app" below. |
| `test_mailbox` | yes | | `restoretest@<domain>`: see below | The `restoretest` mailbox: the only restore target for mail. |
| `test_site_id` | yes | | Graph's site ID `<tenant>.sharepoint.com,<site GUID>,<web GUID>`: see below | The SharePoint site holding the `RestoreTarget` library (the RestoreTest site in the lab). |
| `test_library_id` | yes | | a Graph **drive ID** (`b!…`): see below | Graph **drive ID** (`b!…`) of the `RestoreTarget` library; not the list ID. The only restore target for SharePoint items. Not the `RestoreTest` library, which holds the canary files. |
| `test_onedrive_drive_id` | yes | | a Graph drive ID (`b!…`): see below | The OneDrive drive holding the `RestoreTarget` folder. |
| `test_onedrive_folder_id` | yes | | a Graph item ID: see below | The `RestoreTarget` folder's item ID: the only restore target for OneDrive items. Not `/RestoreTest`, which holds the canary files. |
| `poll_interval_s` | no | `300` | integer, 1 to 86400 | Seconds between the Worker's requests to the Cloud for new jobs. |
| `heartbeat_interval_s` | no | `900` | integer, 1 to 86400 | Seconds between the Worker's reports to the Cloud that it is alive. |
| `sample_mail` | no | `5` | integer, 0 to 100 | Mail items restored per test run. |
| `sample_sp` | no | `5` | integer, 0 to 100 | SharePoint items restored per test run. |
| `sample_od` | no | `5` | integer, 0 to 100 | OneDrive items restored per test run. |
| `log_level` | no | `"info"` | `trace`, `debug`, `info`, `warn`, `error`, `critical`, `off` | How much the Worker logs. Lowercase only. |
| `veeam_ca_file` | no | (not set) | absolute path of a readable file: see below | PEM file with the CA certificate(s), or Veeam's self-signed certificate itself, that the Worker trusts for `veeam_url` instead of the Windows certificate store. TLS verification can't be turned off. |
| `veeam_cert_sha256` | no | (not set) | 64 hexadecimal digits in any case, no separators; needs `veeam_ca_file`: see below | The SHA-256 of Veeam's REST certificate, as Windows shows it (`GetCertHashString('SHA256')`). `veeam_ca_file` must hold that certificate. With both set, the Worker trusts exactly that certificate's key and skips only the host-name check, which Veeam's default certificate can never pass. Not a secret. |
| `screenshots_enabled` | no | `false` | `true` or `false`: see below | The client's screenshot setting: whether a run that writes a run folder asks for a picture of Veeam's restore session. Off by default. |

At least one of `sample_mail`, `sample_sp` and `sample_od` must be above 0.

No string setting may contain a control character: an ASCII one (below 0x20, such as a
newline or tab, or 0x7F), a C1 control (U+0080 to U+009F), the line or paragraph separator
(U+2028, U+2029), or a bidirectional-text control (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066
to U+2069), which can reorder how a line displays. Other non-ASCII text, such as `Zürich` or
`東京`, is fine.

## Validation

The Worker checks the file when it loads it and stops at the first problem, in a fixed order:
the file can't be read; it isn't valid JSON; it isn't a JSON object; a key looks like a secret;
a key is unknown; then each setting in the order of the table above (for `veeam_cert_sha256`,
its form first, then that `veeam_ca_file` is set; `screenshots_enabled` last); then the sample
sizes together; then that
the `veeam_ca_file` named can be opened for reading; last, when `veeam_cert_sha256` is set,
that `veeam_ca_file` holds a certificate with that SHA-256, read the way the Worker's TLS
connection reads it. Fix the reported problem and run
`rpworker config check` again.

- **Messages name the key and never repeat a value from the file.** A JSON syntax error
  reports only the byte offset where parsing failed, because the parser's own message can
  quote whatever it read last, which might be a password. A number too large for the parser
  (such as `1e400`) is reported as `config is not valid JSON (a number is out of range)`,
  without the number.
- **A key name from the file is printed only if it is safe:** 1 to 64 characters, each a
  letter, digit, `_`, `.` or `-`. Any other unknown or secret-looking key is reported as
  `config has a key that ...` without its name, since the name could be a huge string or
  contain control characters that forge lines of output. This limits length and characters
  only; it can't recognise a pasted token that happens to look like a key name. Known keys
  are always named.
- **URLs can't carry credentials.** `cloud_url` and `veeam_url` reject an `@` before the path
  (a user name or password, as in `https://user:password@host`) and any `?` or `#` (a query or
  fragment, where tokens often hide), because `config check` prints both URLs. They must be
  printable ASCII (no spaces), so a look-alike such as a fullwidth `＠` can't hide userinfo;
  write an internationalised host name in its `xn--` form.
- **`test_mailbox` must be the `restoretest` mailbox.** Restores only ever go there, so the
  file can't name any other mailbox: a typo that named a live one would overwrite its mail.
  The value is `restoretest@` (in any case) followed by the tenant's domain, two or more
  `.`-separated labels of ASCII letters, digits and `-`, such as
  `restoretest@contoso.onmicrosoft.com`. Spaces, look-alike letters and invisible characters
  are rejected; write an internationalised domain in its `xn--` form. The Worker's
  `TargetGuard` still checks every restore; this rule stops a wrong mailbox before any run.
- **The four target IDs are Graph's IDs, checked for form by `rpworker config check`.**
  Each goes into a Graph URL path, so a value of another form is a config error naming the
  key (`docs/decisions.md` 2026-09-28, W2.2 review):
  - `test_site_id` is exactly `<tenant>.sharepoint.com,<site GUID>,<web GUID>`, as
    `GET /sites/{hostname}:/sites/{name}` returns it in `id`. The host is one DNS label then
    `.sharepoint.com`; downloads are only accepted from that tenant's SharePoint hosts.
  - `test_library_id` and `test_onedrive_drive_id` are drive IDs: `b!` then 1 to 200 letters,
    digits, `-` and `_` (`GET /sites/{site}/drives`, or the library's `drive` in Graph
    Explorer). `test_library_id` is the drive ID, not the SharePoint list ID
    (`docs/decisions.md` 2026-09-28, W2.2).
  - `test_onedrive_folder_id` is a drive item ID: 1 to 200 letters, digits, `!`, `-` and `_`.
  Before listing, the Worker also checks with one GET that the drive or folder really is a
  `RestoreTarget` in that site or directly in the root of that OneDrive (a drive Graph calls
  `business`, never a site library), and refuses to list anything else, the canaries'
  `RestoreTest` included.
- **`graph_tenant_id` and `graph_client_id` are GUIDs.** Exactly 8-4-4-4-12 hexadecimal
  digits in any case, such as `bcd6bd1a-ea42-489d-aa28-2c19a44ad146`, with nothing around
  them: no braces, no spaces. Both go into Entra and Graph URLs, so nothing else is accepted.
  A tenant's domain name (`contoso.onmicrosoft.com`), `common` or `organizations` would also
  sign in, but is refused: copy the Tenant ID from the tenant's Overview page and the
  Application (client) ID from the app's Overview page in the Entra admin center.
- **`veeam_ca_file` only chooses what to trust.** The Veeam REST API often has a self-signed
  certificate; point `veeam_ca_file` at a PEM file holding that certificate, or the CA
  certificate(s) that issued it, and the Worker trusts it for `veeam_url` instead of the
  Windows certificate store. Veeam's default certificate names no host, so it also needs
  `veeam_cert_sha256` (see "Veeam's default certificate"). It is used for the Veeam connection only: Microsoft Graph and the
  Cloud always use the Windows store. Certificate verification is always on, and no setting
  turns it off: a key such as `veeam_verify_tls` or `insecure` is rejected as unknown.
  With `veeam_ca_file`, revocation is checked on a best-effort basis: a certificate on its
  CA's revocation list is rejected, but one whose status can't be learned (an internal CA
  that publishes no revocation list, or one the Worker can't reach) is accepted.
- **`veeam_ca_file` must be an absolute path**, with a drive and a root
  (`C:\ProgramData\RestoreProof\veeam-ca.pem`, `/` works too) or a UNC share
  (`\\server\share\veeam-ca.pem`). The Worker runs as a Windows service whose working
  directory is `System32`, so relative paths (`ca.pem`, `..\ca.pem`), paths rooted without a
  drive (`\ca.pem`) and drive-relative paths (`C:ca.pem`) are rejected. Any character is
  allowed apart from control characters, including ones outside the ANSI code page. The file
  must exist and be readable by the account the Worker runs as; a missing file or a directory
  is reported as `config key "veeam_ca_file" names a file that can't be read`. Without
  `veeam_cert_sha256`, its contents aren't checked until the Worker connects to Veeam; with
  it, the Worker reads the file when it loads the config (see the next item). In a JSON
  string each `\` is written `\\`: `"C:\\ProgramData\\RestoreProof\\veeam-ca.pem"`.
- **`veeam_cert_sha256` must be a SHA-256 and needs `veeam_ca_file`.** The value is 64
  hexadecimal digits, upper or lower case, with nothing between them: no colons, spaces or
  `0x`. A 40-digit SHA-1 thumbprint, which the Veeam console shows, is rejected with
  `config key "veeam_cert_sha256" must be the certificate's SHA-256: 64 hexadecimal digits, as
  Windows shows it`. Without `veeam_ca_file` it is rejected with `config key
  "veeam_cert_sha256" needs veeam_ca_file: set it to a PEM file holding that certificate`. When
  the Worker loads the file it also reads `veeam_ca_file` and reports `config key
  "veeam_cert_sha256": veeam_ca_file holds no certificate whose SHA-256 is veeam_cert_sha256`
  when no PEM certificate in it matches. It reads the file exactly as the TLS connection
  does (curl's Windows backend, with the same Windows decoder): at most 1 MiB; each
  certificate starts with a line that is exactly `-----BEGIN CERTIFICATE-----`, with nothing
  after it, not even a space, and ends with `-----END CERTIFICATE-----`; reading stops at the
  first BEGIN line with anything after the marker (certificates below it are never loaded);
  a block without its END line, or one that doesn't decode (such as one with
  `Proc-Type`/`DEK-Info` encryption headers), makes the whole file unusable. The messages are
  `veeam_ca_file is larger than 1 MiB`, `veeam_ca_file holds no certificate curl can read:
  each must begin with a line that is exactly -----BEGIN CERTIFICATE-----`, `veeam_ca_file
  has a BEGIN CERTIFICATE line without its END CERTIFICATE line` and `veeam_ca_file holds a
  certificate block that can't be read`, each after `config key "veeam_cert_sha256": `. See
  "Veeam's default certificate" below.
- **`screenshots_enabled` is `true` or `false`, and nothing else.** It is the file's only
  boolean. JSON's own `true` and `false` are accepted; a string (`"true"`), a number (`1`) or
  `null` is rejected with `config key "screenshots_enabled" must be true or false`. It is a
  per-client setting, off by default, since a picture can't be passed through the redaction
  that every logged string goes through. Until jobs exist (W4.8) the CLI reads it from
  `config.json`; a job's value replaces it then. In W4.2 it changes only the reason the result
  gives: the default capturer starts no browser and answers `unavailable` either way, with the
  reason `disabled` when the key is `false` and `no_page` when it is `true`, because no Veeam
  page shows a restore session without an interactive sign-in (`docs/decisions.md` 2026-10-05,
  W4.2, points 2 to 4). A screenshot never changes a run's status, a warning or the exit code.
- **Control characters are rejected** in every string setting, for the same reason: a newline,
  escape sequence or bidi override in a value could forge, hide or reorder lines of
  `config check` output.
- **Unknown keys are rejected.** A misspelt optional key (`poll_intervall_s`) would otherwise
  be ignored and its default used without anyone noticing. Keys are case-sensitive.
- **All sample sizes 0 is rejected.** A run that restores nothing has nothing to compare, and
  must not be able to report `pass`.
- Numbers must be JSON integers: `"300"`, `300.0`, `true` and `null` are wrong types.
- Duplicate keys are not detected; the last one wins.

## Veeam's default certificate

Veeam Backup for Microsoft 365 installs its REST API with a self-signed certificate,
`CN=Veeam Software`, that has no subject alternative name. TLS clients match the server's host
name against the subject alternative names, so no host name can ever match this certificate,
and `veeam_ca_file` alone always fails with a host-name error (`docs/api/veeam-feasibility.md`
§5.1). If the MSP has replaced it with a certificate that names the Veeam server, set only
`veeam_ca_file` (or nothing, if a CA in the Windows store issued it) and leave
`veeam_cert_sha256` out.

For the default certificate, set both keys: `veeam_ca_file` to a PEM file holding the
certificate, and `veeam_cert_sha256` to its SHA-256. The Worker then still checks the
certificate chain against `veeam_ca_file`, the validity dates, and that the server's public key
is the pinned certificate's key. Only the host-name check is skipped, and only when both keys
are set; `veeam_ca_file` on its own keeps the host-name check.

On the Veeam server, in PowerShell 7 run as administrator:

1. Find the REST certificate's SHA-1 thumbprint: in the Veeam console, ☰ → General Options →
   REST API, or with `Get-VBORestAPISettings`.
2. Run the following, replacing `895C6325` with the start of your thumbprint:

   ```powershell
   New-Item -ItemType Directory -Force C:\ProgramData\RestoreProof | Out-Null
   $c = Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -like '895C6325*'
   $c.Subject; $c.GetCertHashString('SHA256')        # the value for veeam_cert_sha256
   Set-Content -Encoding ascii -Path C:\ProgramData\RestoreProof\veeam-rest.pem -Value $c.ExportCertificatePem()
   ```

   For the default certificate, `$c.Subject` includes `CN=Veeam Software`. If it prints
   nothing, or more than one subject, the thumbprint prefix matched no certificate or several:
   use more of the thumbprint.
3. Put the 64-digit value in `veeam_cert_sha256` and the file's path in `veeam_ca_file`:

   ```json
   "veeam_ca_file": "C:\\ProgramData\\RestoreProof\\veeam-rest.pem",
   "veeam_cert_sha256": "9FB19E0E604C9BE49F83D8E508EFA8EA0986A952377C783E5035CEA2D772A213"
   ```

   If the Worker runs on another machine, copy the `.pem` file there. It holds only the public
   certificate, no private key.
4. Run `rpworker config check`.

Windows PowerShell 5.1 has no `ExportCertificatePem()`. To write the `.pem` file there, open
`certlm.msc`, go to Personal → Certificates, right-click the certificate, choose All Tasks →
Export, and export it as "Base-64 encoded X.509 (.CER)", which is PEM. Save it as
`C:\ProgramData\RestoreProof\veeam-rest.pem` (the name doesn't matter; the path in
`veeam_ca_file` must match it).

If Veeam's certificate is renewed or replaced, both values change and the Worker stops
connecting until they are updated: `rpworker veeam list` then fails with exit code 4 and
`veeam error: Veeam POST /v8/token: TLS failure: ...`.

The trust comes from `config.json`: the SHA-256 there decides which certificate the Worker
accepts, so replacing the `.pem` file alone gets nobody past the pin. Keep `config.json`
writable by administrators only, as a file an administrator creates under `%ProgramData%` is
by default.

## Secrets

`config.json` must not contain secrets. Any top-level key whose name, in any case, contains
`password`, `passwd`, `pwd`, `secret`, `token`, `api_key`, `apikey`, `credential`,
`private_key`, `access_key`, `signing_key`, `connection_string`, `pfx` or `passphrase` is
rejected, and checked before anything else so that the secret is removed first. None of the
18 settings matches. `cert` is not on the list: a certificate's hash or path is public, and
`veeam_cert_sha256` is a setting. A key such as `graph_cert_thumbprint` is refused only as
unknown.

Until the DPAPI vault (`%ProgramData%\RestoreProof\vault.bin`) arrives in W4.5 (issue #48),
secrets are read from these environment variables, whose names are defined once in
`worker/include/rp/secrets.hpp`:

| Variable | What it is for |
|---|---|
| `RP_VEEAM_USERNAME` | The account the Worker signs in to the Veeam REST API with. |
| `RP_VEEAM_PASSWORD` | That account's password. |
| `RP_GRAPH_CERT_PFX_BASE64` | The Worker app's certificate with its private key: the PFX file as one line of standard Base64. See "Microsoft Graph app" below. |
| `RP_GRAPH_CERT_PASSWORD` | The PFX's password. Unset only if the PFX has none. |

Any of them may be unset for now. W1.0 chose admin mode (`docs/decisions.md`, 2026-09-26):

- `RP_VEEAM_USERNAME` and `RP_VEEAM_PASSWORD` are the local Veeam account (`rp-veeam` in the
  lab);
- `RP_GRAPH_CERT_PFX_BASE64` and `RP_GRAPH_CERT_PASSWORD` are the certificate of the
  Worker's own Graph app (W2.1);
- the Entra application certificate that restore requests must carry has no variable yet. W2.4
  used Veeam's own organisation app in the lab, exporting its certificate per run; which
  credential the Worker carries, and how it is stored, is open until a spike before W4.5
  (`docs/decisions.md` 2026-09-28, W2.4). Nothing is to be stored before that spike.

A variable set to an empty string counts as unset.

Values are read from Windows' own Unicode environment, so any character works, including
ones outside the machine's ANSI code page (such as `€` or `Ж` on a Western-European
machine). A value that isn't valid Unicode, which only a program can create, is rejected with
`config error: environment variable <name> is not valid Unicode` rather than changed.

To set them for the current PowerShell session:

```powershell
$env:RP_VEEAM_USERNAME = '...'
$env:RP_VEEAM_PASSWORD = '...'
$env:RP_GRAPH_CERT_PFX_BASE64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\path\to\worker-graph.pfx'))
$env:RP_GRAPH_CERT_PASSWORD = '...'
```

In the lab, dot-source `lab/entra/set-worker-env.ps1` (`. .\lab\entra\set-worker-env.ps1`)
instead: it sets the two Graph variables from the lab's PFX and Credential Manager without
printing either, and `-Clear` removes them.

A Windows service does not see a user's session variables. Until the vault lands, a Worker
running as a service would need them set at machine level, where any local administrator can
read them.

## Microsoft Graph app

The Worker reads the restore targets through Microsoft Graph, app-only, as its own app
registration, **RestoreProof Worker** (L1.5). What it may read and why is in
`docs/security/graph-permissions.md`.

- **`graph_tenant_id`** is the tenant's ID, a GUID: in the lab
  `bcd6bd1a-ea42-489d-aa28-2c19a44ad146` (`lab/tenant.md`). In the Entra admin center it is
  on the tenant's Overview page.
- **`graph_client_id`** is the Application (client) ID of "RestoreProof Worker" (the lab's
  value is in `lab/tenant.md`, "RestoreProof Worker app"). It is printed at the end of
  `lab/entra/new-worker-app.ps1`. Not the seeder's app, nor Veeam's.
- **The credential is a certificate, not a client secret** (`docs/decisions.md`,
  2026-09-27). Until the vault arrives it comes from two variables (W2.1):

  | Variable | What it is for |
  |---|---|
  | `RP_GRAPH_CERT_PFX_BASE64` | The app's certificate with its private key: the PFX file as one line of standard Base64 (`A-Z`, `a-z`, `0-9`, `+`, `/`, padded with `=`; no line breaks, no base64url). |
  | `RP_GRAPH_CERT_PASSWORD` | The PFX's password. Leave it unset only for a PFX that has none. |

  Before its first Graph call the Worker opens the PFX once and checks it, stopping with a
  message that names the variable, never its value: the PFX variable is not set; it isn't
  strict Base64; it doesn't hold a PFX; the PFX has no integrity check (MAC), so its password
  can't be checked; the password doesn't open it (`RP_GRAPH_CERT_PASSWORD is not set, and the
  PFX in RP_GRAPH_CERT_PFX_BASE64 needs a password` when it is unset); it uses a legacy cipher
  that OpenSSL 3 no longer reads (RC2, RC4, DES), or the password is right and it still can't
  be read (a damaged file), in both cases re-export it with `AES256_SHA256`, as
  `lab/entra/new-worker-app.ps1` does; it holds no private key, no certificate, or a key
  that matches no certificate in it; the key isn't RSA of at least 2048 bits; the certificate
  has expired or isn't valid yet. A certificate that expires within 30 days still loads, with
  a warning in the log. `rpworker config check` doesn't do any of this: it stays offline and
  only says whether each variable is set.

  The Worker then signs every token request with a new client assertion made with the key
  (`docs/glossary.md`); the key itself is never sent. How it signs in and what a refusal says
  are in `docs/security/graph-permissions.md`, "How the Worker signs in".

  In the lab the PFX is `%LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx` and its password
  is the Credential Manager generic credential `RestoreProof Lab - Worker Graph app PFX`.
  Neither ever goes into `config.json`, which rejects key names containing `pfx`,
  `passphrase`, `password` or `private_key`.

## `rpworker config check`

```
rpworker config check [--config <path>]
```

Loads the config file and the secrets and prints what it found. It changes nothing. Without
`--config` it reads the default path; with `--config`, or when the arguments are wrong, it
doesn't look up `%ProgramData%` at all.

| Exit code | Meaning |
|---|---|
| 0 | The config is valid. Unset secrets are not an error. |
| 1 | The config failed to load or validate; stderr has `config error: <path>: <message>`. If `%ProgramData%` can't be resolved, `config error: cannot find the ProgramData folder`; if a secret variable isn't valid Unicode, `config error: environment variable <name> is not valid Unicode`; any other failure prints `config error: unexpected failure`, never the underlying message. |
| 64 | Arguments not understood; stderr has the usage line. |

Sample output (placeholder values):

```
config file: C:\ProgramData\RestoreProof\config.json
cloud_url                 https://cloud.example.invalid
veeam_url                 https://veeam.example.invalid:4443
veeam_org_name            example.onmicrosoft.com
graph_tenant_id           00000000-0000-0000-0000-000000000000
graph_client_id           00000000-0000-0000-0000-000000000000
test_mailbox              restoretest@example.onmicrosoft.com
test_site_id              ...
test_library_id           ...
test_onedrive_drive_id    ...
test_onedrive_folder_id   ...
poll_interval_s           300
heartbeat_interval_s      900
sample_mail               5
sample_sp                 5
sample_od                 5
log_level                 info
veeam_ca_file             C:\ProgramData\RestoreProof\veeam-rest.pem
veeam_cert_sha256         9FB19E0E604C9BE49F83D8E508EFA8EA0986A952377C783E5035CEA2D772A213
screenshots_enabled       false
secrets (environment variables; values are never shown):
RP_VEEAM_USERNAME         **** (set)
RP_VEEAM_PASSWORD         **** (set)
RP_GRAPH_CERT_PFX_BASE64  **** (set)
RP_GRAPH_CERT_PASSWORD    **** (set)
```

Without `veeam_ca_file` its line reads `veeam_ca_file             (not set)`, and likewise
`veeam_cert_sha256         (not set)` without a pin. `screenshots_enabled` always has a line:
`false` when the file doesn't set it.

A secret prints only as `**** (set)` or `(not set)`: never any character of its value, nor its
length.

An error looks like this:

```
config error: C:\ProgramData\RestoreProof\config.json: config key "poll_interval_s" must be an integer from 1 to 86400 (seconds)
```

## `rpworker veeam list`

```
rpworker veeam list [--config <path>] [--record <dir>]
```

Signs in to the Veeam REST API (`veeam_url`, with `veeam_ca_file` and `veeam_cert_sha256` as
in the config), lists every Microsoft 365 organisation Veeam backs up and each one's restore
points, logs out, and prints them as a table. It reads nothing else and changes nothing. The
config is read as `rpworker config check` reads it; `RP_VEEAM_USERNAME` and
`RP_VEEAM_PASSWORD` must be set (see "Secrets"). The code is `rp::run_veeam_command` in
`worker/include/rp/veeam_command.hpp`.

With the lab's organisation (the recorded responses in `worker/tests/fixtures/veeam/`):

```
  ORGANIZATION                     BACKUP TIME                   EX  SP  OD  TM  LONG-TERM  RESTORE POINT ID
* RestoreProofLab.onmicrosoft.com  2026-09-25T19:37:15.2145203Z  x   x   x   -   no         c2f0f2e7-177f-48ac-992b-93a50cf702e371ac3d9c-eb29-42b6-a391-ae81fcc4681c
* RestoreProofLab.onmicrosoft.com  2026-09-25T19:24:31.0936821Z  x   x   x   -   no         c2f0f2e7-177f-48ac-992b-93a50cf702e32fb3c7e0-ff6e-4949-8b2d-ae32ecf9e9a7

1 organisation(s), 2 restore point(s); * = veeam_org_name
```

- **Every organisation** Veeam returns is listed, sorted by name (ignoring ASCII case), then
  by ID. The one `veeam_org_name` names (ignoring ASCII case) is marked `*`. If none is, the
  table is still printed, so the right name can be copied from it, and the command fails
  with exit code 4.
- **Restore points** are newest first. `BACKUP TIME` is exactly what Veeam sent, the form
  the Worker opens explore sessions with. `EX`, `SP`, `OD` and `TM` are `x` when the point
  holds Exchange, SharePoint, OneDrive or Teams data, `-` when not. `LONG-TERM` is `yes` for
  a copy in archive storage, which needs a retrieval before a restore.
- An organisation with no restore points gets one row, with `(no restore points)` under
  `BACKUP TIME`. With no organisations at all, the command prints `no organisations in Veeam`
  and the summary line, and fails with exit code 4.
- **Everything is read before anything is printed.** If any call fails, stdout stays empty:
  a partial table never looks like a complete one. The command logs out of Veeam whether it
  succeeded or not.
- **The output is UTF-8.** Columns are padded by character, so a name such as `Zürich` lines
  up. `rpworker` doesn't change the console's code page, and neither does PowerShell 7: on a
  console still on code page 437 or 850, `Zürich` shows as `Z├╝rich` and its row is out of
  line. To see non-ASCII names correctly, switch the console to UTF-8 first: in PowerShell
  run `[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()`, in `cmd.exe` run
  `chcp 65001`. The same PowerShell setting also matters when PowerShell captures the output
  or pipes it to a cmdlet, since it decodes a program's output with it; `> file` in `cmd.exe`
  writes the UTF-8 bytes as they are. Control characters in names from Veeam are shown as
  spaces.

An error is one line on stderr, and nothing is printed on stdout:

```
veeam error: Veeam POST /v8/token: HTTP 401: The server has rejected the client credentials.
```

Veeam's messages never contain the password or a token: they are redacted before they are
shown. Debug lines are not shown.

## `rpworker graph list`

```
rpworker graph list [--hash] [--config <path>] [--record <dir>]
```

Shows what is in the three restore targets right now: the test mailbox's Inbox
(`test_mailbox`), the RestoreTarget library (`test_library_id`) and the test OneDrive's
RestoreTarget folder (`test_onedrive_drive_id`, `test_onedrive_folder_id`). It is the check to
run before and after a restore. It signs in to Graph as the Worker's app (`graph_tenant_id`,
`graph_client_id`, and the certificate in `RP_GRAPH_CERT_PFX_BASE64` and
`RP_GRAPH_CERT_PASSWORD`, see "Secrets"), reads, and changes nothing. Before listing each file
target it checks that the drive or folder really is a RestoreTarget where the config says (the
guard, `docs/decisions.md` 2026-09-28, W2.2); the canaries' RestoreTest library and folder are
never read. Since W3.2 the mail listing runs the guard's mailbox check first too: one GET of
the test mailbox's Inbox, which the Worker app's Exchange scope lets it read only for the
`restoretest` mailbox. A 403 there is the guard's refusal, not a permission error: `graph
error: Graph refused the Worker app the Inbox of the mailbox test_mailbox names (403): ...;
the Worker reads only the restoretest mailbox; nothing was listed`, exit 4 (the address is
another mailbox, or the Exchange grant is missing; `docs/security/graph-permissions.md`). The
flags may come in either order. The code is `rp::run_graph_command` in
`worker/include/rp/graph_command.hpp`.

With one item in each target (the recorded responses in `worker/tests/fixtures/graph/`):

```
Mail (restoretest@RestoreProofLab.onmicrosoft.com, Inbox): 1 item(s)
  RECEIVED              SENDER                                              SUBJECT                          ID
  2026-09-28T18:06:26Z  HrachyaHarutyunyan@RestoreProofLab.onmicrosoft.com  RestoreProof W2.2 one-item 7f3k  AAkALgAAAAAAHYQDEapmEc2byACqAC-EWg0Apy-rvAUfAU_pqKwuzmFBWgAAAqwo8wAA

SharePoint (RestoreTarget library): 1 item(s)
  NAME                            SIZE  ID
  rp-w22-sharepoint-4h8x.txt.txt  26    01BLWRTHOARNGB63IOOBG3RYUK4JVLHRQL

OneDrive (RestoreTarget folder): 1 item(s)
  NAME                          SIZE  ID
  rp-w22-onedrive-6k1p.txt.txt  24    01ZK75LGGUS62ZZ5SJURBKYYUXNGNUDVT2

3 item(s) in the three restore targets
```

- **Three tables, always in this order.** An empty target prints its heading with
  `0 item(s)` and no rows; with all three empty the summary reads
  `0 item(s) in the three restore targets`. Items are in Graph's order.
- **Mail:** `RECEIVED` is Graph's `receivedDateTime`, `SENDER` the sender's address, `ID` the
  message's immutable ID. A missing or empty field shows as `-`, a missing or empty
  subject as `(no subject)`.
- **Files:** `SIZE` is in bytes, `ID` the driveItem ID. Subfolders and items that aren't files
  are skipped (restores land files in the root) and don't count. Since W3.4, when a file
  target's listing skipped any, a line under its table (or under its heading, with no rows)
  says how many: `  (<n> folder(s) or other entries not listed)`. A target showing `0 item(s)`
  and no such line holds nothing at all.
- **`--hash`** downloads each file (without the Graph token, from the test tenant's SharePoint
  only) and adds `SHA256` and `RULE` to every table: `text-v1` for mail (the hash of the
  body's text, `lab/README.md`), `bytes` for files. `SIZE` is then the bytes downloaded, which
  for an Office file SharePoint rewrote (docx, xlsx, pptx and their macro and template
  types, xlsb, doc, xls and ppt, `worker/src/office_files.hpp`) may differ from Graph's size. Without `--hash` nothing
  is downloaded, no mail body is read, and `SIZE` is Graph's.
- **Everything is read before anything is printed.** If any call fails, stdout stays empty. If
  writing to stdout fails (a full disk, a closed pipe), the command exits 1 with
  `error: unexpected failure`.
- **The output is UTF-8**, padded by character, as for `rpworker veeam list` (see there for
  the console's code page). Control characters in subjects, senders, names and IDs from Graph
  are shown as spaces, so a restored item can't forge or hide a line.

An error is one line on stderr, and nothing is printed on stdout:

```
graph error: Graph denied GET /v1.0/drives/b!XQgI_nDr6EKVpkcBib2Y65nzyk4OzJVNs_7NCRoJ5omdBuz_5GU6TJ2irAhs-dr6 (403 accessDenied): the Worker app relies on Sites.Selected read on the test site; see docs/security/graph-permissions.md (request ID fc57d2c2-4ef3-48fe-ac0b-bd0c465230fa)
```

Graph's messages never contain a token, the certificate or a download link. Debug lines are
not shown.

## `rpworker restore`

```
rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>]
                 [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>]
                 [--record <dir>]
```

**It writes to the tenant.** It picks a restore point of `veeam_org_name`, chooses a sample
(W2.6: per type half canaries from the manifest, half random items from the restore point),
and restores it through Veeam into the three restore targets: the test mailbox's Inbox, the
RestoreTarget library and the test OneDrive's RestoreTarget folder, and nowhere else. The
restore goes through the connector's `restore_sample`, whose first step is the restore-target
guard (W2.7); the command has no restore path of its own. Since W3.2 it reads the restored
items back through Graph and checks them (`docs/verification.md`, "Comparing"): it lists the
targets the sample has items for just before the restore and again after it, hashing every
mail body and this run's copies of the sampled files.
Since W3.4 it also **deletes**, in the three restore targets only: it empties all three
before choosing the sample, and again after the run's status line once a restore may have
been sent (the Cleaner, `docs/verification.md`, "Cleaning the restore targets (W3.4)").
Everything in them goes: every mail in the `restoretest` Inbox, delivered mail too, and
every plain file in the RestoreTarget library's root and alice's `/RestoreTarget` folder.
Mails are permanently deleted (never through Deleted Items); files go to the site's recycle
bin. Folders and other entries that aren't plain files are never deleted: they are counted
as skipped and left for the owner. Copies an earlier run left that the clean before couldn't
delete are still ignored and counted by the check. The code is `rp::run_restore_command` in
`worker/include/rp/restore_command.hpp`; the choices are `docs/decisions.md` 2026-09-30
(W2.8), 2026-10-01 (W3.2) and 2026-10-02 (W3.4).

It needs:

- **an elevated shell** (Run as administrator): the restore credential, Veeam's organisation
  app certificate, is exported in memory per restore call from `LocalMachine\My`, which needs
  the machine's private key (`docs/decisions.md` 2026-09-30, W2.5, point 1). Without
  elevation the export fails after the guard has passed and the explore sessions are open,
  before anything is sent: `restore error: veeam_m365: <why the export failed>; the restore
  was not sent`, exit 4;
- `RP_VEEAM_USERNAME` and `RP_VEEAM_PASSWORD` (`config error: <name> is not set`, exit 1),
  then the Worker app's certificate for the guard's Graph reads: `RP_GRAPH_CERT_PFX_BASE64`
  and, unless the PFX has none, `RP_GRAPH_CERT_PASSWORD`. The certificate is opened and
  checked before any Veeam call, as `graph list` does: unset, not Base64, a password that
  doesn't open it, or not valid now is exit 1 with the same messages. See "Secrets";
- the canary manifest (`lab/seed-manifest.json`, schema `seed-manifest.v1`), whose
  `tenant_id` must be `graph_tenant_id` and which must name no restore target (`config error:
  canary manifest: ...`, exit 1, before any Veeam call);
- no restore session of the Veeam account still `Working`: the restore checks, after the
  guard and before any explore session, and refuses with `restore error: veeam_m365: Veeam has restore sessions of <account> still
  Working (<IDs>); stop them first (docs/api/veeam-m365/08-sweep-sessions.ps1); nothing was
  restored`, exit 4;
- **no other RestoreProof run on this machine** (W3.4). After the config, the secrets, the
  manifest and the cursor are checked, and before the `--record` folder is made or Veeam is
  called, the command takes the machine-wide named mutex `Global\RestoreProof-restore-targets`
  without waiting, and holds it until it exits (`worker/include/rp/run_lock.hpp`). If another
  run holds it, or Windows refuses to open it (another user's run made it): `restore error:
  another RestoreProof run is using the restore targets; nothing was done`, exit 4, with no
  run line and no status. If its last holder ended without releasing it (a crashed run), this
  run is refused once with `restore error: the last RestoreProof run ended without releasing
  the restore targets; nothing was done; the next run cleans them before it restores`, exit 4,
  and the mutex is let go, so the next run takes it. One run's cleanup
  could otherwise delete another run's copies before they are read back, which would read as
  `missing`, a false `fail`. `graph list` only reads and doesn't take it; the two
  `[live][writes]` tests do (`docs/testing.md`);
- the Worker app's write grants on the three restore targets
  (`docs/security/graph-permissions.md`). Without them the cleanup's deletes are refused
  (`graph_permission` on that target, below) and the run goes on; the copies stay.

The flags come in any order, each at most once:

| Flag | Default | Meaning |
|---|---|---|
| `--mail <n>`, `--sp <n>`, `--od <n>` | `sample_mail`, `sample_sp`, `sample_od` | Items to restore per type: 1 to 3 ASCII digits, 0 to 100. At least one of the three must be above 0. |
| `--point latest\|<id>` | `latest` | The newest restore point (`latest` in any case), or the one with this ID (1 to 128 ASCII letters, digits and hyphens, ignoring case), as `rpworker veeam list` shows it. |
| `--run-id <id>` | a new one | The run ID the random draw is seeded from: 1 to 128 of `A-Z a-z 0-9 . _ : -`. Without it each run makes `rp-<YYYYMMDDTHHMMSSZ>-<8 random hex digits>` (UTC). Give a recorded one to repeat a sample. |
| `--canary-cursor <m>,<s>,<o>` | `0,0,0` | Where each type's canary rotation starts: three numbers of 1 to 6 digits, no spaces, each below that type's canaries in the manifest (0 for a type it has none of). Nothing is stored on the Worker: carry the printed next cursor to the next run by hand. |
| `--manifest <path>` | `seed-manifest.json` beside the config file | The canary manifest: `%ProgramData%\RestoreProof\seed-manifest.json`, or in the `--config` file's folder. |
| `--config <path>` | `%ProgramData%\RestoreProof\config.json` | As for every command. |

With W2.4's recorded single-mail restore (`worker/tests/restore_command_test.cpp`, through the
real connector; the restore point ID is the fixtures' made-up one, and the times there are the
test's clock, which moves only while the restore is polled):

```
restore point 2026-09-27T22:00:48.1447833Z  c2f0f2e7-177f-48ac-992b-93a50cf702e35e1c0a24-0000-4000-8000-000000000924  (veeam_org_name RestoreProofLab.onmicrosoft.com)
run run-0001  seed 8b26e36a
cleanup before ok: deleted 0 mail, 0 sharepoint, 0 onedrive
canary cursor 10,0,0 -> 11,0,0
  KIND        REQUESTED  CANARIES  RANDOM  NOTE
  mail        1          1 of 1    0 of 0
  sharepoint  0          0 of 0    0 of 0
  onedrive    0          0 of 0    0 of 0
restoring 1 item(s) ...

  KIND  SOURCE  NAME            OUTCOME   SESSION                               ELAPSED  MESSAGE
  mail  canary  RP-CANARY-0011  restored  b6fe35ef-9633-481d-9756-3496a717d8a9  0:00:32  Item RP-CANARY-0011 was restored successfully (type: IPM.Note; source: Bob Test\Inbox; target: restoretest@RestoreProofLab.onmicrosoft.com\<null>\Inbox)

  SESSION                               KIND  RESULT   RESTORED  STARTED                       ENDED                         ELAPSED
  b6fe35ef-9633-481d-9756-3496a717d8a9  mail  Success  1 of 1    2026-09-28T21:27:28.3281642Z  2026-09-28T21:28:00.6973119Z  0:00:32

restore succeeded: 1 of 1 item(s) restored in 0:00:05

  KIND  SOURCE  NAME            OUTCOME  FIELDS  DUP  MS
  mail  canary  RP-CANARY-0011  match    -       -    0

check: 1 match, 0 mismatch, 0 missing, 0 error

status pass: 1 of 1 item(s) verified: manifest 1, fields 0, metadata 0
cleanup after ok: deleted 1 mail, 0 sharepoint, 0 onedrive

STEP                  TIME         NOTE
restore_point_lookup  0:00:00.000
cleanup_before        0:00:00.000
sample_select         0:00:00.000
target_snapshot       0:00:00.000
restore               0:00:05.000
restore_submit        0:00:00.000
restore_wait          0:00:05.000
verify                0:00:00.000
recovery              0:00:05.000
cleanup_after         0:00:00.000
total                 0:00:05.000
```

- **The header.** Its first two lines (the restore point, the run ID and seed) are printed as
  soon as the run ID exists, before the sample is chosen, which browses Veeam: a run that fails
  from then on still shows its run ID. The clean before's line follows (below). The rest (the
  canary cursor and the next one, the per-type table, `restoring ...`) is printed before the
  restore starts, which takes minutes.
  `CANARIES` is taken of half the size rounded up, `RANDOM` taken of half rounded down; fewer
  taken is a shortfall, named in `NOTE` (`canary shortfall`, `random shortfall` or both) and
  never filled. A shortfall never changes the run's status: with every sampled item verified
  it is still `pass`, exit 0, with one `warning: shortfall: <kind> <canary|random>: <taken> of
  <wanted>` per half that fell short. A sample with no item at all (every type asked for fell
  short entirely) restores nothing: no `restoring ...` line, `status error empty_sample: the
  sample is empty: nothing to restore` and the shortfall warnings, exit 4.
- **One row per item**, mail first, then SharePoint, then OneDrive, each type's canaries
  first: `SOURCE` is `canary` or `random`; `OUTCOME` is `restored`, `failed` or `unknown`
  (Veeam said nothing about it), with ` (infrastructure)` when Veeam's message reads as Veeam
  failing to reach Microsoft 365, lacking permissions or being throttled rather than the item
  being wrong; `ELAPSED` is the item's restore session's; `MESSAGE` is Veeam's, `-` if none.
  What Veeam says of an item is only its account: the check decides (below). An item Veeam
  failed for an infrastructure reason that the check doesn't find is *unchecked* (`error
  backup_infrastructure`), never a restore failure; one the check finds matching anyway is
  verified, with a `backup_item` warning.
- **One row per restore session**: Veeam's result, items restored of sent, start and end as
  Veeam wrote them, and the time between (`-` when either doesn't read).
- **The restore's line**: `restore <restore status>: ...` (`status ...` until W3.3, renamed so
  that only the run's status line starts with `status`), the restore's own status
  (`succeeded`, `partial`, `failed` or `not_run`, `worker/include/rp/connector.hpp`), items
  restored of sent, and the time the restore took. Times are `H:MM:SS`, cut to whole seconds.
  It is Veeam's account, not the run's status, which comes after the check.
- **The check (W3.2)**: one row per sampled item, in the same order. `OUTCOME` is `match`,
  `mismatch`, `missing` or `error`; `FIELDS` names the fields that didn't match
  (`subject`, `sender_address`, `sender_name`, `sent_at`, `received_at`,
  `internet_message_id`, `size_bytes`, `sha256`) or an error's code (`graph_auth`,
  `graph_permission`, `graph_transient`, `target_guard`, `graph` when the target couldn't be
  read back; `stale_target` when only an earlier run's copy of the item is there); `DUP` says
  `<n> copies` when the restore wrote more than one; `MS` is the item's own read and
  comparison time, `-` when no copy was found (`missing`, `error`). Then `check: <a> match,
  <b> mismatch, <c> missing, <d> error`. Only this run's copies of the sampled files are
  downloaded: a file that was in the target before the restore with the same `cTag`, or whose
  name no sampled file has, is listed but never read, so an earlier run's leftover can't fail
  the check. Copies earlier runs left are ignored and counted in one warning on stderr:
  `warning: stale_copies: <n> copies from earlier runs in the restore targets were ignored
  (mail <x>, sharepoint <y>, onedrive <z>)`. A target that couldn't be read back is one
  `check error: <message>` line on stderr, and its items are `error`. A restored docx or xlsx
  that office-v1 refuses is a `sha256` mismatch, and why it was refused is one line on stderr
  only, never in the table or the result: `check note: <sharepoint|onedrive> <name>: not valid
  office-v1 input: <the reader's text>`. So one of the reader's own limits (an encrypted part,
  a part past 64 MiB, more than 10,000 entries) can be told from a broken file.
- **The result's validator is checked first (W4.1).** After the config, the secrets and the
  sample sizes, and before the manifest, the mutex and any Veeam call, the command loads the
  validator from the embedded schema. If that fails: `error: the result schema couldn't be
  loaded; nothing was done`, exit 1, with no run line and no status.
- **The run's status (W3.3)** comes in every run once its first two lines are out, however
  it ended: `status <pass|fail|error>[ <code>]: <message>`, its own paragraph, then each warning
  as `warning: <code>: <message>` on stderr. The exit code is the status's: `pass` 0 (every
  sampled item verified), `fail` 5 (an item missing or a mismatch, its target read fine, not
  blamed on infrastructure), `error` 1 to 4 by its code (table below). The message is counts
  and fixed words, never a subject, a name, an address or an exception's message. Veeam's
  own status never decides: a `partial` restore whose items all verify is `pass` (with a
  `backup_session` warning per session that wasn't `Success`); a `failed` one whose items all
  match anyway is `error restore_contradiction`; an item only an earlier run's copy matches is
  `error stale_target`; one item that couldn't be checked beside matches is `error`, never a
  partial pass; a missing item beside one that couldn't be checked is `fail`. The decision
  table, the codes and the warnings: `docs/verification.md`, "The status decision table".
  Since W3.4 the status line is no longer the last stdout line: the clean after's line follows
  it, and since W3.5 the step timings' table follows that (below).
- **The cleanup (W3.4).** Two lines on stdout, counts and codes only, never a name or an ID:
  the clean before's, right after the run line, and the clean after's, right after the status
  line and its warnings, so the decided status never waits on it:

  ```
  cleanup <before|after> ok: deleted <a> mail, <b> sharepoint, <c> onedrive
  cleanup <before|after> incomplete: deleted <a> mail, <b> sharepoint, <c> onedrive[; left <x> mail, <y> sharepoint, <z> onedrive][; skipped <n>][; <target> <code>]...[; the restore may still be running; the next run cleans before]
  cleanup after skipped: nothing was restored
  cleanup after skipped: no Graph client
  ```

  `deleted` counts Graph's 204s; `left` what the last listing still showed; `skipped` the
  entries never deleted (a folder, a package, a file not proving its place); `<target>` is
  `mail`, `sharepoint` or `onedrive`, and `<code>` what stopped it: `target_guard`,
  `graph_auth`, `graph_permission`, `graph_transient` (in both rounds), `graph`, `config` or
  `internal`. For example `cleanup after incomplete: deleted 2 mail, 0 sharepoint, 0 onedrive;
  left 0 mail, 1 sharepoint, 0 onedrive; sharepoint graph_permission`. On stderr, each target
  that stopped on an error gets `cleanup error: <target>: <fixed text> (<code>)`, and each
  target not left empty `warning: cleanup: <target> not emptied <before|after> the run (left
  <x>, skipped <n>[, <code>])`; the Cleaner's own warning and error lines, with Graph's message
  or a skipped entry's ID, go to stderr too, through `redact()`.
  - The clean after runs only when the status says a restore may have been sent
    (`restore_sent`); otherwise its line is `cleanup after skipped: nothing was restored`, so
    every run that prints a status line has a `cleanup after` line right before the step
    timings' table, which ends the run (W3.5, below). It runs after the
    check, so nothing is deleted before it is read back, and also after a check that threw.
    When the restore stopped with an error that doesn't promise `nothing was restored` (a POST
    with no answer, a poll that gave up), it still runs, and its line ends `the restore may
    still be running; the next run cleans before`: Veeam may still be writing.
  - **The cleanup never changes the status or the exit code**, but in one case: when the clean
    before's guard check refuses a target (it isn't the RestoreTarget the config says), the run
    stops there, before the sample is chosen and before any Veeam explore session: `cleanup
    error: <target>: the restore-target guard refused the target; nothing was deleted in it
    (target_guard)`, one `SECURITY: cleanup: ...` line in the log, then `status error
    target_guard: the run stopped before the restore: the restore-target guard refused
    (target_guard); nothing was restored`, exit 4. The other targets are cleaned all the same.
    Any other cleanup failure, or leftovers, only shows in these lines: a `pass` whose clean
    after left something still exits 0. A failure of the clean after itself prints `cleanup
    error: unexpected failure` and keeps the exit code.
- **Step timings (W3.5).** Every run that printed its run line ends stdout with one more
  paragraph, after the `cleanup after` line: a table of eleven named spans, always all eleven,
  in this order (`rp/step_timer.hpp`; `docs/decisions.md` 2026-10-03, W3.5):
  - `restore_point_lookup`: listing the restore points and picking one;
  - `cleanup_before`: the clean before;
  - `sample_select`: choosing the sample, Veeam's browsing for the random half included;
  - `target_snapshot`: reading the targets before the restore (W3.2);
  - `restore`: the whole restore, the same time the `restore <status>: ...` line prints;
  - `restore_submit` and `restore_wait`: the connector's own account, summed over its restore
    sessions: exporting the credential, the guard's last check, the one POST and the duplicate
    check; then Veeam running the restore, polled until it ended. The rest of `restore` is the
    connector's preparation (explore sessions, browsing) and reading the results;
  - `verify`: the restore's tables, the read back with hashing and the check;
  - `recovery`: `restore` and `verify` together, from the restore's start to the last item's
    verdict;
  - `cleanup_after`: the clean after;
  - `total`: from listing the restore points to the end of the clean after. What comes
    before (arguments, config, secrets, manifest, the run mutex) is local and not timed.

  The spans overlap and don't add up to `total`. `TIME` is `H:MM:SS.mmm`, cut to the
  millisecond, on the same steady clock as the restore's line, never a wall clock. A span
  with no time reads `-`, and `NOTE` says why: `not run` (the run stopped before it, or the
  clean after was skipped), `stopped` (the run stopped during it; its time runs to the
  stop, read as the stop is handled, before the status line and the clean after), `not reported` (the connector didn't
  measure it, or the restore threw and its sessions' account was lost), `clock went back` (no
  time is ever made up). `NOTE` is empty for a span measured in full; `not closed` appears
  only through a bug or a clock that failed at the span's end: a clock reading taken for the
  timings alone that fails leaves its span `not run` (at its start) or `not closed` (at its
  end) and changes nothing else. A run that stops before its run
  line prints no table. When stdout is lost the table isn't printed, on stdout or stderr. The
  timings never change the status, a warning or the exit code, and a table that fails to write
  changes nothing either. The same spans are the result's `timings` object
  (`{"spans": {"<span>": {"ms": <n>[, "note": "stopped"]} | {"note": "<state>"} | null}}`,
  whole milliseconds, `null` for a span that didn't run).
- **The result (W4.1).** Every run with a run line builds its result,
  `restoreproof.result.v1`, right after the status is decided, and validates it against the
  schema built into the Worker (`docs/verification.md`, "The result"). `restore` writes no
  file, but a result that isn't valid is the Worker's own fault and is said before anything
  says `pass`: one line on stderr, `result error: <n> schema violation(s), first at <JSON
  pointer>` (or `result error: the result has no canonical form`, `result error: the result
  couldn't be built`), then the check's table and `status error result_invalid: the result
  isn't valid restoreproof.result.v1; the run itself ended <pass|fail|error <code>>`, exit 1.
  The warnings, the clean after and the timings follow as for any run. The line never holds
  a value or the validator's message, only a count and a place in the document.
- **If reading back or checking fails for a reason that isn't Graph's** (out of memory, a bug),
  the check's table isn't printed: `check error: unexpected failure`, then `restore error:
  the restore had started: items may be in the restore targets (run <run ID>)`, and `status
  error internal: the restored items couldn't be checked: an unexpected failure (internal)`,
  exit 1. The clean after then deletes the copies; the restore's own rows are the evidence.
- **Before the restore**, the targets are read for the check: a failure there stops the run
  and nothing is restored: `check error: <message>; nothing was restored`, then `status error
  <code>: the run stopped before the restore: ...; nothing was restored`, exit 1 (`config`:
  the Graph certificate failing as Graph signs in), 2 (`graph_auth`, `graph_permission`), 3
  (`graph_transient`) or 4 (`graph`; `target_guard`, a target its guard refuses).
- If stdout can't be written after the restore ran, the error says so, since items may now be
  in the targets, with the run and how the restore went: `error: writing the output failed
  after the restore ran (run <run ID>, restore <restore status>: <restored> of <sent> item(s)
  restored); run status <pass|fail|error>[ <code>]`, so the run's status is still on record.
  The check still runs and the warnings still go to stderr; the exit code is the
  status's, but 1 for a `pass`, since its output was lost. Before the restore, a stdout that
  can't be written stops the command (`error: unexpected failure`, exit 1); once the run line
  is out, its lost status line is said too: `error: writing the output failed (run <run ID>);
  run status <pass|fail|error>[ <code>]`.
- If choosing the sample or the restore itself fails with an error, the error is one line on
  stderr (`restore error: <message>`) and the status line names its code (`backup_auth`,
  `backup_transient`, `not_in_backup`, `target_guard`, `backup`; `config` for the restore
  credential's certificate; `graph_auth`, `graph_permission`, `graph_transient` or `graph` when
  the guard couldn't read a restore target through Graph, never a backup code). After the
  restore started the tables can't be printed and items may already be in the targets: unless
  Veeam's or the guard's message ends with `nothing was restored`, a second line says so,
  `restore error: the restore had started: items may be in the restore targets (run <run
  ID>)`, and the status reads `the restore didn't complete: ...; items may be in the restore
  targets`; with that promise it reads `the restore didn't start: ...; nothing was restored`.
  The "had started" line (`restore_note` in the code) says what the restore did; the clean
  after's line, after the status, says what is left (`the restore may still be running` when
  Veeam may still be writing). Check with `rpworker graph list`.
- The output is UTF-8; control characters in Veeam's text are shown as spaces. Warnings go to
  stderr only.

An error's line goes to stderr, after whatever stdout shows by then. For example, with
`test_library_id` naming a library that isn't the RestoreTarget library (a drive named
`Dokumenty`), the clean before refuses it, cleans the other two targets and stops the run:

```
run run-0001  seed 8b26e36a
cleanup before incomplete: deleted 0 mail, 0 sharepoint, 0 onedrive; sharepoint target_guard

status error target_guard: the run stopped before the restore: the restore-target guard refused (target_guard); nothing was restored
cleanup after skipped: nothing was restored
```

then the step timings' table, with `restore_point_lookup`, `cleanup_before` and `total` timed
and every other span `-`, `not run`,
and, on stderr, the log's `SECURITY: cleanup: the drive test_library_id names is
"Dokumenty", ...` line and

```
cleanup error: sharepoint: the restore-target guard refused the target; nothing was deleted in it (target_guard)
warning: cleanup: sharepoint not emptied before the run (left 0, skipped 0, target_guard)
```

exit 4. Veeam saw only the sign-in, the restore points and the sign-out. (The clean before
resolves all three targets through the same guard checks the check's before snapshot and the
restore use, so it refuses first; the snapshot's refusal reads `check error: ...; nothing was
restored`, the restore's own `restore error: target guard: ...`.)

Veeam's and the guard's messages never contain a password, a token or a certificate. Debug
lines are not shown.

## `rpworker test`

```
rpworker test [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>]
              [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>]
              [--record <dir>] [--json <file>]
```

**It writes to the tenant and deletes there, as `restore` does.** It is the whole test of a
restore point in one run (W3.6): clean before, restore point, sample, guard, restore, verify,
status, clean after and the step timings. It runs the same pipeline as `rpworker restore`
(`worker/src/run_pipeline.hpp`), so everything in "`rpworker restore`" holds for it: what it
needs (an elevated shell, the secrets, the manifest, the run mutex), the order of the steps,
the run line, the header, the guard, the cleanup lines, the status line and its warnings, the
timings' table, `--record`, and the exit codes. The code is `rp::run_test_command` in
`worker/include/rp/test_command.hpp`; the choices are `docs/decisions.md` 2026-10-03 (W3.6).

- **Flags.** `restore`'s flags with `restore`'s rules, plus `--json <file>`. An absent size is
  the config's `sample_mail`, `sample_sp` or `sample_od`. There is no `--seed`: the run ID
  gives the seed (`run <id>  seed <hex>`), so `--run-id` repeats a sample, with the same
  manifest, cursor and restore point (`--point`).
- **Exit codes.** `restore`'s: 0 pass, 5 fail, 1 to 4 an error by its code (`result_invalid`
  is 1), 64 usage (see
  "Exit codes"). Not the guide's "0 pass, 1 fail, 3 error": 1 and 3 already mean config and
  transient.

What stdout shows differs from `restore` in two places only:

- **After the restore**, no per-item rows: the session rows and the `restore <status>: ...`
  line follow the header. Veeam's per-item messages aren't printed.
- **After the check**, one table, one row per sampled item, in place of `restore`'s check
  rows:

  | Column | What it holds |
  |---|---|
  | TYPE | `mail`, `sharepoint` or `onedrive` |
  | NAME | the expected subject or file name |
  | EXPECTED | `manifest` (a canary), `fields` (a random mail) or `metadata` (a random file) |
  | FOUND | `yes` when a copy of this run's was compared, else `no` |
  | MATCH | the check's outcome: `match`, `mismatch`, `missing` or `error` |
  | VERDICT | `verified`, `failed` or `unchecked <code>`; `-` when the status table's rows 1 to 4 decided the run, or the run is `error result_invalid`. An item Veeam failed for an infrastructure reason that the check doesn't find reads `unchecked backup_infrastructure`, never `failed` |
  | REASON | fixed words only: a mismatch's field names joined by commas, `missing` (`not_in_backup` when the backup said the restore point doesn't hold the item, Q3.1), an error's code, `-` for a match. Shorter than the result's `check.items[].reason`, which since W4.1 is fixed words too |
  | MS | the item's milliseconds when found, else `-` |

For example, `rpworker test --mail 2 --sp 1 --od 0 --run-id run-0001 --json C:\runs\run-0001.json`
on a restore point with one random mail ends:

```
  SESSION          KIND        RESULT   RESTORED  STARTED               ENDED                    ELAPSED
  sess-mail        mail        Success  2 of 2    2026-09-30T10:00:00Z  2026-09-30T10:01:05Z     0:01:05
  sess-sharepoint  sharepoint  Success  1 of 1    2026-09-30T10:01:10Z  2026-09-30T10:01:52.25Z  0:00:42

restore succeeded: 3 of 3 item(s) restored in 0:02:03

  TYPE        NAME              EXPECTED  FOUND  MATCH  VERDICT   REASON  MS
  mail        RP-CANARY-0001    manifest  yes    match  verified  -       123000
  mail        real mail 01      fields    yes    match  verified  -       123000
  sharepoint  rp-canary-01.pdf  manifest  yes    match  verified  -       246000

check: 3 match, 0 mismatch, 0 missing, 0 error

status pass: 3 of 3 item(s) verified: manifest 2, fields 1, metadata 0
cleanup after ok: deleted 2 mail, 1 sharepoint, 0 onedrive

STEP                  TIME         NOTE
...                                         (the eleven spans, as for restore)
wrote C:\runs\run-0001.json
```

With `--json`, the last lines are the timings' table, then `wrote <file>`, then `--record`'s
`recorded ...` line. (For `restore` the timings' table stays last but for `recorded ...`.)

### `--json <file>`

Writes the run's result, `restoreproof.result.v1` (W4.1; `docs/verification.md`, "The
result"), for every run that printed its run line, whatever its status (`error` and stops
included). A run that stops before its run line (the mutex, no restore point, Veeam
unreachable listing them, a config or manifest problem) writes no file, as it prints no status
line. The file is unsigned (W4.3 signs it).

**The file is the result's canonical bytes** (`canonical-json-v1`): one line of UTF-8, keys
sorted, no whitespace, no trailing newline, no BOM. Those are the bytes W4.3 hashes, so don't
reformat the file in place. To read it:

```powershell
python -m json.tool C:\runs\run-0001.json
python -m json.tool --no-ensure-ascii C:\runs\run-0001.json C:\runs\run-0001.pretty.json
```

Its fifteen top-level keys are always all there, `null` where a step didn't run:

| Key | What it holds |
|---|---|
| `format` | `"restoreproof.result.v1"` |
| `worker_version` | the Worker's version |
| `run_id` | the run ID |
| `started_at`, `ended_at` | `YYYY-MM-DDTHH:MM:SS.mmmZ`, UTC, read where the `total` span starts and ends; `null` when the wall clock failed there |
| `connector` | `{"type", "api"}`: `veeam_m365` and its API version |
| `client` | `{"client_id", "tenant_id", "veeam_org_name", "targets"}` from the config: `client_id` is `null` until jobs carry one (W4.10); `targets` is `{"mailbox", "site_id", "library_id", "onedrive_drive_id", "onedrive_folder_id"}` |
| `restore_point` | `{"id", "backup_time_raw", "backup_time"}`: Veeam's time text unparsed, and the same time cut to whole seconds (`YYYY-MM-DDTHH:MM:SSZ`, `null` when the text doesn't parse) |
| `sample`, `expected`, `check`, `status`, `cleanup`, `timings` | the result objects as W2.6, W3.1, W3.2, W3.3, W3.4 and W3.5 write them (`docs/verification.md`). `sample` and `expected` are `null` when the run stopped before the sample was chosen, `check` when the check didn't run, `cleanup` when no clean ran (the run stopped before the clean before). `status` and `timings` are always objects |
| `restore` | the restore's status, items sent and restored; its sessions (ID, kind, result, `details` only when they read as Veeam's counts, else `null`, items sent and restored, `started_at_raw`/`ended_at_raw` as Veeam wrote them); its items in order, `{index, kind, outcome, infrastructure, container_missing, session_id}`, with no item name and no Veeam message. `null` when there is no restore result |

There is no `command` and no `exit_code` (W3.6's `rp.run-summary.v0` had both): the file
describes the run, not the process. A pass whose stdout was lost, or whose `--record`
recording isn't complete, still exits 1, and the file says `pass`. There is no top-level
`veeam_org_name` either: it is in `client`. There is no `signature`, `tsa_token` or
`bundle_sha256` yet. The file holds no secret, but more tenant data than stdout: the list is in
`docs/verification.md`, "What of the tenant the result holds". Keep it out of the repository.

**A result that isn't valid is never written.** The Worker validates the result against its
built-in schema twice: when the status is decided (then the run is `error result_invalid`,
exit 1; "`rpworker restore`" above), and again at the end, on the finished result, which is the
text of the file. Either way stderr gets, after the run's other lines,

```
json error: <file>: the result isn't valid restoreproof.result.v1; no file was written
```

and no file is made. When only the second validation fails, the status line is already out and
stays, a `result error: ...` line comes before the `json error` one, and exit 0 becomes 1; any
other exit code is kept.

The path is checked once the config is read and before the secrets, the manifest, the mutex,
`--record` and any Veeam call. Each refusal is exit 1:

```
config error: --json <file>: not a UTF-8 path
config error: --json <file>: not a file name
config error: --json <file>: the file already exists
config error: --json <file>: the folder doesn't exist
config error: --json <file>: a file can't be written there
```

`not a file name` is a file name that is empty, `.` or `..`, ends in `.` or a space, holds a
control character or any of `< > : " / \ | ? *`, or is a DOS device's name: `CON`, `PRN`,
`AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM0`–`COM9`, `LPT0`–`LPT9` (and `COM¹`–`COM³`,
`LPT¹`–`LPT³`), in any case, alone or before an extension (`prn.json`, `LPT1.json`). A `:`
would name an NTFS stream of another file, Windows refuses the other characters, strips a
trailing `.` or space (`run.json.` would be written as `run.json`), and on Windows 10 opens a
device for its name, saying "not found" when there is none. Anything but a clean "not found" at
the path counts as a file already there (a file the Worker may not read). Last, the check makes
the writer's own temp file (below) and drops it at once: when that fails, `a file can't be
written there` (a folder the Worker may not write to, a read-only volume, a name or path too
long once the temp name's 21 characters are added), before the run rather than after it. A missing, empty or repeated `--json`
value is exit 64 with the usage line. An existing file is never
overwritten, by this check or later: the result goes into a temp file in the same folder,
`<file>.<16 random hex digits>.tmp`, is flushed to disk, and is then moved onto `<file>` in a
way that fails if a file appeared there since (`worker/src/atomic_file.hpp`). The temp file is
deleted on any failure. When a valid result's file can't be written:

```
json error: <file>: could not be written
```

on stderr, after the run's other lines. The status never changes. Exit 0 becomes 1; any other
exit code is kept. `<file>` is the value as given, control characters shown as spaces.

## `--record <dir>`

`rpworker veeam list`, `graph list`, `restore` and `test` take `--record <dir>` (Q2.1), in any place
among their other flags, once. It writes every exchange the command has with a service as a
test fixture, scrubbed, and changes nothing else: the same requests go out and the same output
comes back, then one more line on stdout, `recorded <n> exchange(s) in <dir>`. `restore
--record` still writes into the tenant, and records the cleanup's listings, `permanentDelete`s
and `DELETE`s under `graph` (W3.4). How to record and replay: `docs/testing.md`,
"Recording fixtures"; what a fixture keeps and never keeps: `docs/decisions.md` 2026-10-01,
"Q2.1".

- `<dir>` must not exist yet (it is made) or be an empty folder. Anything in it, or a file
  there, is exit 1 before any request: `config error: <dir>: the --record folder is not empty`
  (`... the --record path is not a folder`, `... the --record folder can't be made`,
  `config error: the --record path is not valid UTF-8`).
- One subfolder per service, `veeam`, `graph` and `download`, and one file per exchange,
  `<nnn>-<method>-<path>.json`, numbered in the order sent.
- An exchange that still holds a secret after scrubbing is not written: `record error:
  <service>/<file>: refused: <which rule>` on stderr, one line each (`... could not be
  written` for a write that failed). The command's own result stands, but a command that
  succeeded exits 1 then, since its recording isn't complete.

## Exit codes

The same for every `rpworker` command (`rp::exit_code` in `worker/include/rp/cli.hpp`):

| Exit code | Meaning | stderr |
|---|---|---|
| 0 | Success. | (nothing) |
| 1 | The config or a secret is missing or invalid, or something unexpected failed (an error no command handles ends here too, never in an `abort()`, whose exit code would be 3). For `graph list` this includes the certificate: `RP_GRAPH_CERT_PFX_BASE64` unset, a PFX that doesn't open with `RP_GRAPH_CERT_PASSWORD`, or a certificate that isn't valid now, all found before any request. For `restore`, also the same certificate problems as `graph list` (before any Veeam call; `RP_GRAPH_CERT_PASSWORD` unset is fine for a PFX without a password), the certificate failing as the check's reads before the restore sign in (nothing restored), a manifest that doesn't load, whose `tenant_id` isn't `graph_tenant_id` or that names a restore target (before any Veeam call), an unknown connector, a run whose status is `error config`, `error internal` (the facts not adding up, or the check failing for a reason that isn't Graph's) or `error result_invalid` (the result the Worker built isn't valid `restoreproof.result.v1`, W4.1), and stdout failing after a restore whose run passed. `test` exits as `restore` does; for `test` also a `--json` path that isn't UTF-8, isn't a plain file name, names a file already there or a folder that doesn't exist, or where a file can't be written (before the secrets), and a passing run whose `--json` file couldn't be written or whose finished result isn't valid (no file). With `--record`, a folder that isn't new or empty, and a command that succeeded but whose recording isn't complete. | `config error: <path>: <message>`, `config error: the --config path is not valid UTF-8`, `config error: the --manifest path is not valid UTF-8`, `config error: canary manifest: <message>`, `config error: cannot find the ProgramData folder`, `config error: environment variable <name> is not valid Unicode`, `config error: RP_VEEAM_USERNAME is not set` (then `RP_VEEAM_PASSWORD`), `config error: RP_GRAPH_CERT_PFX_BASE64 is not set` (or another message naming the certificate's variables), for `restore` `config error: unknown connector "<name>" (known: <names>)`, `check error: <message>; nothing was restored`, `check error: unexpected failure` and `error: writing the output failed after the restore ran (run <run ID>, restore ...); run status ...`, with `--record` `config error: <dir>: the --record folder is not empty` and `record error: <service>/<file>: refused: ...`, for `test` `config error: --json <file>: not a UTF-8 path` (`... not a file name`, `... the file already exists`, `... the folder doesn't exist`, `... a file can't be written there`) `json error: <file>: could not be written` and `json error: <file>: the result isn't valid restoreproof.result.v1; no file was written`, for `restore` and `test` `result error: <n> schema violation(s), first at <JSON pointer>` (`result error: the result has no canonical form`, `result error: the result couldn't be built`), `config error: unexpected failure` or `error: unexpected failure`; an unexpected failure's own message is never shown |
| 2 | The service refused the sign-in, the account's role, the token or a permission: Veeam's credentials or role; Entra refusing the Worker app's sign-in; Graph refusing the token, or denying a call for want of a grant (the message names the grant, see `docs/security/graph-permissions.md`); for `restore` and `test`, a run whose status is `error backup_auth`, `graph_auth` or `graph_permission`: on the check's reads before the restore (nothing restored) or after it (the item couldn't be checked). | `veeam error: <message>`, `graph error: <message>`, `restore error: <message>` or `check error: <message>; nothing was restored` |
| 3 | The service couldn't be reached or asked to try later: no connection, a timeout, a TLS handshake that broke off, or a 502, 503 or 504 (for Graph also a 429 or another 5xx) after the retries; for `restore` and `test`, a run whose status is `error backup_transient` or `graph_transient`, before the restore or after it. | `veeam error: <message>`, `graph error: <message>`, `restore error: <message>` or `check error: <message>; nothing was restored` |
| 4 | Any other error from the service. Veeam: an unknown organisation, a bad request, an unexpected answer, or no organisation named `veeam_org_name`; also Veeam's certificate failing verification, which a retry won't fix: `veeam_ca_file` doesn't hold Veeam's certificate or its CA, or Veeam's certificate was renewed and no longer matches `veeam_cert_sha256` (see "Veeam's default certificate"). Graph: the mailbox, drive or folder not found, a mailbox, drive or folder the guard refuses (not the RestoreTarget the config says; a 403 on the test mailbox's Inbox included), a download that failed, an unexpected answer. `restore` and `test`: another RestoreProof run holding the run mutex, no restore points or a `--point` ID that isn't one of them (before the run line), and a run whose status is `error` with any other code: `target_guard` (the restore-target guard refusing, in the clean before or later, nothing restored), `not_in_backup` (the organisation not in Veeam, or an item not in the restore point that it can't be shown to hold: a random item, or a canary in a point taken before the manifest's `seeded_at`; a canary missing from a later point is `fail`, Q3.1), `backup` (a restore session of the Veeam account still `Working`, the restore credential's export failing when not elevated, any other error of the restore), `empty_sample`, `not_run`, `restore_contradiction`, `backup_infrastructure` (an item Veeam failed for an infrastructure reason that the check didn't find), `graph` (any other Graph error, before the restore or reading an item back), `stale_target` (only an earlier run's copy of an item is there). | `veeam error: <message>` (`... TLS failure: ...` for a certificate), `veeam error: organisation <name> (veeam_org_name) not found in Veeam`, `graph error: <message>`, `restore error: <message>` (`restore error: target guard: ...` for the guard), `restore error: another RestoreProof run is using the restore targets; nothing was done`, `restore error: no restore points for veeam_org_name`, `restore error: restore point <id> not found for veeam_org_name`, `cleanup error: <target>: the restore-target guard refused the target; nothing was deleted in it (target_guard)`, `check error: <message>; nothing was restored`, or a `check error: <message>` per target that couldn't be read back; after an error of a restore that had started, also `restore error: the restore had started: items may be in the restore targets (run <run ID>)`; for a run, the status line is on stdout and its warnings follow on stderr |
| 5 | `restore` and `test` only: the run's status is `fail` (W3.3): an item is missing or doesn't match, its target read fine and Veeam didn't blame infrastructure for it, whatever Veeam's own status says (`status fail: ...` on stdout). A result about the backup, not an error: a run that couldn't run at all or couldn't tell is `error`, 1 to 4. | (nothing but the run's warnings) |
| 64 | The command line isn't understood (for `test` also `--seed`, which it doesn't take). For `restore` and `test` also, once the config or the manifest is read: every sample size 0, or a `--canary-cursor` out of the manifest's range. | the usage line; for `restore`, `usage error: every sample size is 0 (--mail, --sp, --od, or config's sample_mail, sample_sp, sample_od): nothing to restore` or `usage error: --canary-cursor: the <kind> cursor must be below <n>, the manifest's <kind> canaries` (`... must be 0: the manifest has no <kind> canaries`) |

The usage line is:

```
usage: rpworker --version | rpworker config check [--config <path>] | rpworker veeam list [--config <path>] [--record <dir>] | rpworker graph list [--hash] [--config <path>] [--record <dir>] | rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--record <dir>] | rpworker test [--mail <n>] [--sp <n>] [--od <n>] [--point latest|<id>] [--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config <path>] [--record <dir>] [--json <file>]
```
