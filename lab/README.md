# Lab tools: the canary set (L1.2) and the Worker app (L1.5)

`lab/` holds the test tenant's notes (`tenant.md`) and the seeder, a small Python tool that
puts 40 known items into the tenant and records what they look like in
`lab/seed-manifest.json`.

## What the canary set is

40 items we create ourselves, so their expected content is known before any backup runs:

- 20 mails, subjects `RP-CANARY-0001` … `RP-CANARY-0020`, plain text;
- 20 files, `rp-canary-01.pdf` … `rp-canary-20.png`.

Veeam backs them up (L1.3). From Sprint 3 the Worker restores a sample of them and compares
what Microsoft Graph reads back from the restore target with the manifest. W3.1 (the C++
expected-set builder) reads the manifest; W3.2 (the C++ checker) re-implements the mail body
rule below.

The hashes in the manifest are of **what Graph returns when the item is read back**, not of
what was on disk or what was sent. The Worker will only ever see an item through Graph, so
that is the value it can compare with. If SharePoint rewrites a file on upload, or Exchange
changes a mail body, the manifest records the changed bytes and also says that they changed.

## Layout

| Path | What |
|---|---|
| `pyproject.toml`, `uv.lock`, `.python-version` | Its own uv project (Python 3.12). Runtime: msal, requests, jsonschema. Dev only: pytest and the readers the tests use to open the files (python-docx, openpyxl, pypdf, pillow) |
| `seeder/` | The tool: `catalog.py` (the 40 items and where they go), `tenant.py` (tenant IDs, copied from `tenant.md`), `generate.py`, `normalize.py`, `manifest.py`, `auth.py`, `graph.py`, `transport.py`, `seed.py`, `verify.py`, `cli.py`; `worker_app.py` is `check-worker-app` (L1.5) |
| `tests/` | pytest, one file per module, against a fake in-memory Graph tenant. No network |
| `entra/new-worker-app.ps1` | Creates or updates the RestoreProof Worker app registration and its grants (L1.5), below |
| `canary/` | The 20 generated files, committed |
| `seed-manifest.json` | Written by a live `seed` run only; not committed yet, so CI skips the `hash` check with a warning until it is |
| `tenant.md` | Tenant, user and restore-target IDs |

Shared with the Worker, outside `lab/`:

- `shared/schemas/seed-manifest.v1.json`: the manifest's JSON Schema (draft 2020-12,
  `additionalProperties: false` everywhere, exactly 40 entries).
- `shared/testdata/body-normalization-text-v1.json`: input/output test vectors for the mail
  body rule, used by the Python tests now and by W3.2's C++ tests later.

## One-time setup: create the seeder app registration

The seeder signs in with a dedicated app registration, "RestoreProof Lab Seeder". It is a
public client with delegated permissions only: it acts as whoever signs in, and has no client
secret or certificate. This is not the Worker's app (L1.5); see `docs/decisions.md`.

Do this once, in the Microsoft Entra admin center, signed in as the global admin
(`HrachyaHarutyunyan@RestoreProofLab.onmicrosoft.com`).

> **Turn off browser translation for this site first.** Automatic page translation has broken
> the Microsoft 365 admin centre before. In Chrome, click the translate icon in the address bar
> and choose "Never translate this site". Or use Edge (or an InPrivate window) with English as
> the display language. The steps below use the English labels.

1. Open https://entra.microsoft.com.
2. Go to **Entra ID** > **App registrations** (older menus: **Identity** > **Applications** >
   **App registrations**) and click **New registration**.
3. **Name:** `RestoreProof Lab Seeder`.
4. **Supported account types:** "Accounts in this organizational directory only
   (RestoreProofLab only - Single tenant)".
5. **Redirect URI:** platform "Public client/native (mobile & desktop)", value
   `http://localhost`.
6. Click **Register**.
7. Open **Authentication**. Under **Advanced settings**, set **"Allow public client flows"** to
   **Yes**, then click **Save**.
8. Open **API permissions** > **Add a permission** > **Microsoft Graph** > **Delegated
   permissions**. Tick `Mail.Send`, `Mail.Read`, `Files.ReadWrite` and `Sites.ReadWrite.All`
   (`User.Read` is already there). Click **Add permissions**.
9. Click **"Grant admin consent for RestoreProofLab"** and confirm with **Yes**. Check that every
   row's status says "Granted for RestoreProofLab".
10. Open **Overview** and copy the **Application (client) ID**. Send it on so it is recorded in
    `lab/tenant.md` ("Seeder app") and in `SEEDER_CLIENT_ID` in `seeder/tenant.py`.

A client ID is not a secret. No client secret or certificate is created: a public client has
none. Until the ID is committed, pass it with `--client-id` or the `RP_LAB_CLIENT_ID`
environment variable.

### Or with PowerShell

The same registration from the Microsoft Graph PowerShell modules. This is how the lab's app
was created (2026-09-25); its client ID is in `tenant.md`. Run as the global admin:

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns -Scope CurrentUser

$tenantId = 'bcd6bd1a-ea42-489d-aa28-2c19a44ad146'
$appName  = 'RestoreProof Lab Seeder'
$scopes   = 'Mail.Send','Mail.Read','Files.ReadWrite','Sites.ReadWrite.All','User.Read'

Connect-MgGraph -TenantId $tenantId -Scopes 'Application.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All' -NoWelcome

$existing = Get-MgApplication -Filter "displayName eq '$appName'"
if ($existing) { "Already exists. Client ID: $($existing.AppId)"; return }

# Delegated scope IDs looked up by name from Microsoft Graph's service principal.
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$access  = $graphSp.Oauth2PermissionScopes | Where-Object { $scopes -contains $_.Value } |
           ForEach-Object { @{ Id = $_.Id; Type = 'Scope' } }

$app = New-MgApplication -DisplayName $appName -SignInAudience 'AzureADMyOrg' `
         -IsFallbackPublicClient:$true `
         -PublicClient @{ RedirectUris = @('http://localhost') } `
         -RequiredResourceAccess @(@{ ResourceAppId = $graphSp.AppId; ResourceAccess = $access })

# Service principal, then tenant-wide admin consent for the five delegated scopes.
$sp = New-MgServicePrincipal -AppId $app.AppId
New-MgOauth2PermissionGrant -ClientId $sp.Id -ConsentType 'AllPrincipals' `
    -ResourceId $graphSp.Id -Scope ($scopes -join ' ') | Out-Null

"Client ID: $($app.AppId)"
Disconnect-MgGraph | Out-Null
```

## One-time setup: the RestoreProof Worker app (L1.5)

The Worker's own app registration: single tenant, app-only, with a certificate. It can read
the three restore targets and nothing else. What is granted and why:
`docs/security/graph-permissions.md`. `entra/new-worker-app.ps1` does everything below the
first two steps, and is safe to run again.

1. **Install the modules** (once), in PowerShell 7 (Start, type `pwsh`, open "PowerShell 7"):

   ```powershell
   Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement -Scope CurrentUser
   ```

   On a machine with Veeam Backup for Microsoft 365, Install-Module finds Veeam's own
   ExchangeOnlineManagement and installs nothing, but PowerShell 7 can't load that copy. Install
   yours next to it: `-Force` for a second version, `-AllowClobber` because Veeam's copy already
   has the same commands:
   `Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber`.
   The script needs version 3.7.2 or later (for `Connect-ExchangeOnline -DisableWAM`); the same
   command upgrades an older copy.

2. **Make the admin a site collection admin of alice's OneDrive.** Even a global admin can't
   grant access to another user's OneDrive otherwise.
   1. Open https://admin.microsoft.com, signed in as the global admin.
   2. **Users** > **Active users** > click **alice**.
   3. On the **OneDrive** tab, under **Get access to files**, click **Create link to files**.
      A link to her OneDrive appears. You don't need to open it: creating it made the admin a
      site collection admin.
3. **Run the script** from the repo root:

   ```powershell
   pwsh -NoProfile -File lab\entra\new-worker-app.ps1
   ```

   It signs in twice, both times as the global admin: first Microsoft Graph, then Exchange
   Online. If the account picker offers another account, choose **"Use another account"**.
   The first time, Microsoft Graph PowerShell asks to consent to "Read and write all
   applications", "Manage app permission grants and app role assignments" and "Have full
   control of all site collections". Leave "Consent on behalf of your organization"
   **unticked**, so only the admin's own sessions get these, then click **Accept**.
4. **Wait, then check.** Exchange applies permission changes after 30 minutes to 2 hours. The
   script's `Test-ServicePrincipalAuthorization` lines show the new state at once. Then, from
   `lab/`:

   ```powershell
   uv run python -m seeder check-worker-app --client-id <the client ID the script printed>
   ```

5. **Optional: remove the admin from alice's OneDrive.** Open her OneDrive with the link from
   step 2, then gear icon > **OneDrive settings** > **More settings** > **Site collection
   administrators**, and remove the admin. The Worker's grant stays. Running the script again
   needs step 2 again.

The certificate's private key exists only in `%LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx`
(outside the repo). Its password exists only in Credential Manager, as the generic credential
`RestoreProof Lab - Worker Graph app PFX`. The script never prints either. To renew the
certificate, delete the PFX and run the script again.

## Commands

Run from `lab/`:

```bash
uv sync                               # create .venv from uv.lock
uv run pytest                         # all tests, offline
uv run python -m seeder generate      # write the 20 files into canary/
uv run python -m seeder hash          # offline check: canary/ and the manifest agree (L1.2's Done when)
uv run python -m seeder seed          # live: put the 40 items in the tenant, write seed-manifest.json
uv run python -m seeder verify        # live: re-read the 40 items and compare with the manifest
uv run python -m seeder check-worker-app  # live: what the Worker app can and can't read (L1.5)
```

| Command | Network | What it does | Exit code |
|---|---|---|---|
| `generate` | no | Writes the 20 canary files into `canary/`. The output is byte-identical on every run, so after a clean checkout it changes nothing | 0 |
| `hash` | no | Checks that `seed-manifest.json` exists, is valid JSON and matches the schema; has exactly 40 entries whose ids, kinds and order match the catalog; that each file in `canary/` has the recorded `local_sha256` and `local_size` and that `stored_matches_local` is consistent; that each mail's `sent_body_sha256` equals the text-v1 hash of the catalog body and its subject and recipient match the catalog. Prints one line per entry and a summary (`40/40 entries reproduce the manifest hashes`) | 0 all reproduce; 1 any difference (each message names the entry, expected and actual); 2 manifest missing, unreadable or invalid (wrong count, order or schema) |
| `seed` | yes | Signs in three times, sends the missing mails, uploads the missing files, reads all 40 back and writes the manifest. Step by step below | 0 manifest written; 1 a problem the output explains (missing canary file, duplicate subject, mail timeout); 2 sign-in or Graph error. No manifest is written unless it exits 0 |
| `verify` | yes | Re-reads every item by its Graph id as the account that owns it (alice: mails 0001–0010 and the OneDrive files; bob: mails 0011–0020; admin: the SharePoint files). Compares subject, sender (case-insensitive), sent and received dates, `internet_message_id` and `body_sha256`; for files name and `content_sha256` by `content_rule` (and size for `bytes` files); an Office file whose bytes changed but whose content didn't is `ok`, with a note. Prints `ok`, `DIFF` or `MISSING` per entry and a summary (`40/40 entries in the tenant match the manifest`) | 0 all ok; 1 any DIFF or MISSING; 2 manifest missing or invalid, or a sign-in or Graph error |
| `check-worker-app` | yes | Signs in as the RestoreProof Worker app with its certificate (PFX from `--pfx`, default `%LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx`; password from Credential Manager). Checks the token's roles are exactly `Files.SelectedOperations.Selected` and `Sites.Selected`, then sends one GET per probe and prints `ok` or `UNEXPECTED` per row with the expected and actual status (the probe table is in `docs/security/graph-permissions.md`). Only reads | 0 all as expected; 1 anything unexpected; 2 a missing or unusable credential, or a sign-in error |

A usage error (unknown command or option) exits 2. Ctrl+C exits 130; `seed` then says nothing was written.

Options:

| Option | Commands | Meaning |
|---|---|---|
| `--client-id <id>` | `seed`, `verify` | The seeder app's client ID. Order: this option, then `RP_LAB_CLIENT_ID`, then `SEEDER_CLIENT_ID` in `seeder/tenant.py`. If all are empty the tool stops and points here |
| `--client-id <id>` | `check-worker-app` | The Worker app's client ID. Order: this option, then `RP_LAB_WORKER_CLIENT_ID`, then `WORKER_CLIENT_ID` in `seeder/tenant.py` |
| `--pfx <path>` | `check-worker-app` | The Worker app's certificate, if not in the default place |
| `--auth browser\|device` | `seed`, `verify` | `browser` (default) opens a browser window for each sign-in. `device` prints a code to enter at https://microsoft.com/devicelogin instead |
| `--force` | `seed` | Send every mail again and replace every file, even if it is already there |
| `--mail-timeout <seconds>` | `seed` | How long to wait for sent mails to arrive (default 600) |
| `--canary-dir`, `--manifest` | all that use them | Other paths than `canary/` and `seed-manifest.json` (tests use these) |

## The seed run, step by step

`seed` uses delegated permissions, so each step can only reach the signed-in user's own
mailbox and OneDrive. A global admin gets 403 on alice's OneDrive through delegated Graph.
That is why there are three sign-ins.

The run has five steps. Each starts with a header naming the account, and before each of the three sign-ins the tool also prints a banner:

```
Step 1/5: alice@RestoreProofLab.onmicrosoft.com - check her mailbox for RP-CANARY-0001..0010, upload rp-canary-11..20 to her OneDrive
==> Sign in as alice@RestoreProofLab.onmicrosoft.com  (check her mailbox for ...)
```

1. **alice.** Looks for `RP-CANARY-0001` … `0010` already in her mailbox. Uploads
   `rp-canary-11` … `20` to her OneDrive `RestoreTest` folder and downloads each back.
2. **bob.** Looks for `RP-CANARY-0011` … `0020` already in his mailbox.
3. **admin** (`HrachyaHarutyunyan@…`). Sends the mails that are missing, all 20 from the admin.
   Uploads `rp-canary-01` … `10` to the root of the SharePoint `RestoreTest` library and
   downloads each back.
4. and 5. **alice, then bob, silently.** Their tokens are still in the in-memory cache, so there is
   no fourth or fifth sign-in. The tool polls each mailbox until every expected mail can be
   read, and reads it back.

The token cache is in memory only. Nothing is written to disk, and the next run signs in
again.

**Picking the right account.** In `browser` mode a browser window opens with the account
already filled in (a login hint). If the browser is already signed in as someone else, choose
**"Use another account"** and sign in as the account in the banner. In `device` mode, open an
InPrivate window, go to https://microsoft.com/devicelogin, enter the code and sign in as the
account in the banner; the InPrivate window keeps other sessions from being picked up.

**Wrong account.** After each sign-in the tool checks who signed in. If it is not the account
in the banner it stops with "You signed in as X, but this step needs Y." Nothing further is
sent or uploaded. Run it again.

**Running it again.** `seed` can be re-run safely.

- A mail whose subject is already in the recipient's mailbox is not sent again ("already in
  mailbox, not sent"). If a subject is there more than once, the tool stops and names the
  subject and the mailbox: delete the extra copies and run again. Copies in Deleted Items are
  ignored (not its subfolders), so there is no need to empty it, and a canary that is only
  there counts as missing and is sent again.
- A file already in its folder is not uploaded again. It is still downloaded, so the manifest
  records what is stored. If the stored bytes differ from the file in `canary/`, the tool says
  so (a SharePoint rewrite, or an old copy).
- `--force` replaces every file and sends every mail again. Re-sending creates a **second copy**
  of each mail, and the tool reads back the newest one. Delete the old mails first, or the next
  run without `--force` will stop on the duplicates.

**Mail delivery.** Sending returns before the mail is delivered. The tool polls every 10
seconds, up to `--mail-timeout` (600 s by default). On timeout it stops, names the missing
subjects and the mailbox, and writes no manifest.

**The manifest is written only when all 40 items were read back.** The run ends with a report:
files whose stored bytes differ from the local file (with both sizes), mails whose read-back
body differs from what was sent (exactly, and after normalisation), mails in a folder other
than Inbox, and a reminder that the Veeam backup (L1.3) must run after the seed.

## Mail body hash: normalisation rule `text-v1`

Every mail is read through Graph with the header

```
Prefer: outlook.body-content-type="text", IdType="ImmutableId"
```

so `body.content` is the plain-text body, and message ids are ImmutableIds. The body is a JSON
string, so the rule works on Unicode code points:

1. If the text starts with U+FEFF, drop that one character.
2. Replace every CRLF with LF, then every remaining lone CR with LF.
3. Split on LF. From the end of each line, remove every U+0020 SPACE and U+0009 TAB, and only
   these two characters.
4. Join with LF. Remove all LF characters at the end of the text. Nothing else: no trimming at
   the start, no Unicode normalisation, no case change, no handling of non-breaking spaces.
5. Encode as UTF-8 without a BOM. `body_sha256` is the lower-case hex SHA-256 of those bytes.

The rule is versioned: each mail entry names it in `body_normalization`. A different rule gets
a new name (`text-v2`), never a change to `text-v1`. The C++ checker (W3.2) must implement
exactly this rule. `shared/testdata/body-normalization-text-v1.json` is the shared contract:
both the Python and the C++ tests must pass every vector in it.

## Office file content: rule `office-v1`

The SharePoint `RestoreTest` library rewrites docx and xlsx files: once on upload and again
some minutes later, without changing `lastModifiedDateTime` (see the findings below). No
whole-file hash of them stays valid, so Office files are compared on their content parts:

1. Open the file as a ZIP package.
2. Take every part whose name starts with the content folder, `word/` for docx and `xl/` for
   xlsx, except parts inside a `_rels/` folder.
3. Sort the part names by their UTF-8 bytes.
4. For each part write one line: lower-case hex SHA-256 of the uncompressed part bytes, two
   spaces, the part name, LF.
5. `content_sha256` is the lower-case hex SHA-256 of those lines (UTF-8).

Metadata (`docProps/`), `customXml/`, `[trash]/`, `[Content_Types].xml` and relationship files
don't count: that is exactly what SharePoint changes. Every piece of document text, sheet data,
style and embedded media does. The rule applies to every docx and xlsx, wherever it is stored,
because a restore may rewrite an Office file too. pdf, txt and png use `bytes`: the SHA-256 of
the whole file.

`shared/testdata/office-content-v1/` is the shared contract, as for `text-v1`: the committed
canaries and the same files as SharePoint rewrote them, which must give equal hashes, with the
expected values in `cases.json`. W3.2's C++ checker must pass them. A different rule gets a new
name (`office-v2`).

## The manifest

`lab/seed-manifest.json`, schema `shared/schemas/seed-manifest.v1.json`. Written as sorted-key
JSON with a 2-space indent, UTF-8, LF line endings. Dates are ISO-8601 UTC in whole seconds
(`2026-09-25T10:00:00Z`). Hashes are 64 lower-case hex characters. Exactly 40 entries: the mails
`RP-CANARY-0001` … `0020` in order, then the files `rp-canary-01` … `20` in order.

Top level:

| Field | Meaning |
|---|---|
| `schema` | `"seed-manifest.v1"` |
| `tenant` | `RestoreProofLab.onmicrosoft.com` |
| `tenant_id` | The tenant's ID |
| `seeded_at` | When the seed run finished |
| `rules` | The rules below as plain sentences, so the manifest can be read on its own |
| `entries` | The 40 entries |

Mail entry (`kind` `"mail"`):

| Field | Meaning |
|---|---|
| `id`, `subject` | `RP-CANARY-0001` … `0020` |
| `kind` | `"mail"` |
| `sender` | `from.emailAddress.address` as read back (the admin) |
| `recipient` | The recipient's UPN, from the catalog |
| `location` | `{"mailbox": <recipient UPN>, "folder": <display name of the folder it was found in, normally "Inbox">}` |
| `sent_at`, `received_at` | `sentDateTime`, `receivedDateTime` as read back |
| `internet_message_id` | The `Message-ID` header (`<…@…>`) |
| `graph_message_id` | The message's Graph id in the recipient's mailbox, as an **ImmutableId** (it survives moves between folders) |
| `body_content_type` | `"text"` |
| `body_normalization` | `"text-v1"` |
| `body_sha256` | text-v1 hash of the body **read back** from the recipient's mailbox. **The Worker compares with this** |
| `sent_body_sha256` | text-v1 hash of the body that was sent (the catalog body) |
| `body_readback_exact` | `true` if the read-back body string equals the sent string before normalisation |

File entry (`kind` `"sharepoint_file"` or `"onedrive_file"`):

| Field | Meaning |
|---|---|
| `id`, `name` | `rp-canary-01.pdf` … `rp-canary-20.png` |
| `kind` | `"sharepoint_file"` (01–10) or `"onedrive_file"` (11–20) |
| `file_type` | `pdf`, `docx`, `xlsx`, `txt` or `png` |
| `location` | SharePoint: `site_id`, `list_id`, `drive_id`, `folder_id`, `folder_path` (`"/"`). OneDrive: `user` (alice), `drive_id`, `folder_id`, `folder_path` (`"/RestoreTest"`). `folder_id` is the real id of the parent folder (`parentReference.id`), never the alias `root` |
| `drive_item_id` | The file's Graph driveItem id |
| `uploaded_by` | The UPN that uploaded it, from the catalog |
| `last_modified_at` | The driveItem's `lastModifiedDateTime` after the upload |
| `local_sha256`, `local_size` | The committed file in `canary/` |
| `stored_sha256`, `stored_size` | The bytes downloaded back through Graph at seed time. Evidence only: SharePoint may have rewritten an Office file since |
| `stored_matches_local` | `true` if the stored bytes equal the local file |
| `content_rule` | `"office-v1"` for docx and xlsx, `"bytes"` for pdf, txt and png |
| `content_sha256` | The expected value by `content_rule`, from the stored bytes. For `bytes` it equals `stored_sha256`; for `office-v1` it also equals the committed file's content hash, which `hash` checks. **The Worker compares with this** |

## Rules

- **Mail recipients.** `RP-CANARY-0001` … `0010` go to alice, `0011` … `0020` to bob. The admin
  sends all 20. W1.0 restores `RP-CANARY-0001` from alice's mailbox.
- **File types.** The type cycles by file number: 01 pdf, 02 docx, 03 xlsx, 04 txt, 05 png,
  06 pdf, … 20 png. Each location gets two files of each type. The guide's
  `rp-canary-20.docx` was only an illustration; file 20 is `rp-canary-20.png`.
- **File locations.** 01–10 go in the root of the SharePoint `RestoreTest` library, uploaded by
  the admin. 11–20 go in alice's OneDrive `RestoreTest` folder, uploaded by alice. 01 is a pdf
  because W1.0 restores `rp-canary-01.pdf` from the library.
- **Conflicts.** Uploads use `@microsoft.graph.conflictBehavior=fail`, so an existing file is
  never overwritten by accident; the tool checks first and skips it. With `--force` they use
  `replace`.

All of these are fixed in `seeder/catalog.py`. Changing a sentence, the mail footer, the cycle
or a location changes the expected set: it needs a new seed run, a new manifest and a new
backup.

## Deterministic files

`generate` writes the same bytes on every machine and every run:

- **Standard library only.** No third-party library writes the files, so their bytes never
  depend on a library version. The dev-only readers (python-docx, openpyxl, pypdf, pillow) are
  used by the tests to prove each file opens and holds its sentence.
- **No compression.** zlib's output can differ between zlib builds. docx and xlsx are ZIPs with
  every entry `ZIP_STORED`; the PNG's pixel data is written as stored (uncompressed) deflate
  blocks. Only the checksums (Adler-32, CRC-32) use zlib, and they are fixed maths.
- **Fixed dates and metadata.** ZIP entries are dated 1980-01-01 00:00:00 with fixed attributes
  and a fixed entry order; Office `docProps/core.xml` and the PDF's `/CreationDate` and `/ModDate`
  are 2026-01-01 00:00:00 UTC; the PDF has a fixed `/Producer` and no random `/ID`; the PNG has
  only `IHDR`, `IDAT` and `IEND` chunks.

`tests/test_generate.py` proves it: it generates twice into two temporary folders and compares
the bytes, and compares the output with the committed `canary/` files. The files are
committed, and `.gitattributes` marks `lab/canary/**` as binary so `core.autocrlf` can never
change their line endings (and with them their hashes).

## Findings from the live seed run

First live run, 2026-09-24 (seed) and 2026-09-25 (verify, then a diagnostic download):

- **Mail: Exchange changed nothing.** All 20 plain-text bodies read back through Graph were
  exactly the sent string (`body_readback_exact: true`), so `body_sha256 == sent_body_sha256`.
  All 20 arrived in the Inbox 3–6 s after sending.
- **pdf, txt, png: stored byte for byte**, in both the SharePoint library and OneDrive.
- **OneDrive: Office files stored byte for byte.** alice's `RestoreTest` folder kept the four
  docx/xlsx files unchanged.
- **SharePoint library: every docx and xlsx rewritten, twice.** On upload SharePoint wrote the
  library's content-type metadata into the package (docx 3263 → 12617 bytes, xlsx 5844 →
  17047). Some minutes later it rewrote them again (+3073 bytes each: 15690 and 20120), with
  `lastModifiedDateTime` unchanged, so the first `verify` reported 4 DIFFs. After that, three
  downloads 15 s apart gave identical bytes. Part by part, only packaging and metadata changed:
  `customXml/` (the content-type schema, 11 KB), `docProps/custom.xml` (`ContentTypeId`),
  `docProps/core.xml`, the `_rels` files, `[Content_Types].xml`, and `[trash]/` parts left by
  the rewrites. `word/document.xml`, `xl/workbook.xml`, `xl/worksheets/sheet1.xml` and
  `xl/styles.xml` were byte-identical to the committed files. Hence `office-v1`.
- **Checked in W1.0 (2026-09-26): a Veeam restore keeps the `office-v1` hash.**
  `rp-canary-02.docx`, restored from the backup into the `RestoreTarget` library, was
  rewritten again. It is 15 563 bytes, and its whole-file hash matches neither the canary
  nor the stored copy. Its `office-v1` hash equals the manifest's `content_sha256`, and was
  unchanged 16 minutes later. The Veeam export of the same file (the stored 15 690 bytes)
  gives the same `office-v1` hash (`docs/api/veeam-feasibility.md`, check d).

## Order with L1.3

The seed must finish before the Veeam backup job runs (L1.3), so every canary item is in the
restore points the Worker will test. Seeding again later (new or replaced items) needs a new
backup before those items can be restored.
