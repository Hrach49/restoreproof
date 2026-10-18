# Lab tools: the canary set (L1.2) and the Worker app (L1.5)

`lab/` holds the test tenant's notes (`tenant.md`) and the seeder, a small Python tool that
puts 40 known items into the tenant and records what they look like in
`lab/seed-manifest.json`. It also puts real, non-canary files and mails there for the
sampler's random half (`seed-real`, L1.8, below).

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
| `pyproject.toml`, `uv.lock`, `.python-version` | Its own uv project (Python 3.12). Runtime: msal, requests, jsonschema, cryptography. Dev only: pytest and the readers the tests use to open the files (python-docx, openpyxl, pypdf, pillow) |
| `seeder/` | The tool: `catalog.py` (the 40 items and where they go), `tenant.py` (tenant IDs, copied from `tenant.md`), `generate.py`, `normalize.py`, `manifest.py`, `auth.py`, `graph.py`, `transport.py`, `seed.py`, `verify.py`, `cli.py`; `seed_real.py` is `seed-real` (L1.8); `worker_app.py` is `check-worker-app` (L1.5); `graph_fixtures.py` is `record-graph-fixtures` (W2.1, and W2.2's restore-target states); `signing_key.py` is `new-signing-key` (W4.3) |
| `tests/` | pytest, one file per module, against a fake in-memory Graph tenant. No network |
| `entra/new-worker-app.ps1` | Creates or updates the RestoreProof Worker app registration and its grants (L1.5), below |
| `entra/check-worker-grants.ps1` | Read-only: lists the SharePoint and OneDrive grants and checks the Worker app holds none at a canary and its write grants on the two file restore targets (W3.4), below |
| `entra/fill-worker-vault.ps1` | Fills the Worker's DPAPI vault (W4.5) from Credential Manager and the PFX file: the Veeam account, the Worker app's certificate and its password, and, when the lab has one, the signing key, each piped to `rpworker vault set <name>`; below |
| `canary/` | The 20 generated files, committed |
| `seed-manifest.json` | Written by a live `seed` run; committed, so CI runs the `hash` check on it, and the Worker's sampler (W2.6) reads it (`worker/include/rp/canary_manifest.hpp`) |
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
the three restore targets and, since W3.4, delete in them (the Cleaner): write on the
RestoreTarget list, write on alice's `/RestoreTarget` folder, and `Application Mail.ReadWrite`
on the `restoretest` mailbox. It can also read two things it doesn't use: the rest of the
RestoreTest site (the canary library included, since a site grant covers the whole site) and
the metadata of alice's OneDrive site and root folder. Nothing else, and no write outside the
restore targets. What is granted and why: `docs/security/graph-permissions.md`.
`entra/new-worker-app.ps1` does everything below the first two steps, and is safe to run again:
on an app set up before W3.4 it adds the `Lists.SelectedOperations.Selected` consent and the
list grant, raises the folder grant to `write`, and replaces the `Application Mail.Read`
assignment with `Application Mail.ReadWrite`. Before each write grant it reads the list or
folder and stops, granting nothing, unless it is the RestoreTarget one. After the grants it runs
`entra/check-worker-grants.ps1` in the same session, a read-only listing of the grants (below),
and stops before the Exchange step if that finds a problem.

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
4. **Wait, then check.** Exchange applies permission changes after 30 minutes to 2 hours (until
   then the mail write probe may get 403). The script's `Test-ServicePrincipalAuthorization`
   lines show the new state at once. Then, from `lab/`:

   ```powershell
   uv run python -m seeder check-worker-app --client-id <the client ID the script printed>
   ```

   A browser window opens once: sign in as alice. The check reads her canary folder with the
   seeder app to confirm it exists and holds files (the Worker app gets 404 on it either way).
   It then creates and deletes one `rp-probe-<uuid>` item in each restore target (below). It
   sends nothing but GETs anywhere near a canary: that the app can't write there is proven by
   the grant check, next.
5. **Check the grants, read-only.** From the repo root (the setup script has already run it
   once; run it alone any time):

   ```powershell
   pwsh -NoProfile -File lab\entra\check-worker-grants.ps1 | Tee-Object docs\security\w3.4-worker-grants-check.txt
   ```

   It signs in as the admin (Microsoft Graph, `Sites.FullControl.All` only, the one scope that
   can read grants), sends GETs only, and signs out. It needs the admin to be a site
   collection admin of alice's OneDrive (step 2), so run it before step 6. Rows below.
6. **Optional: remove the admin from alice's OneDrive.** Open her OneDrive with the link from
   step 2, then gear icon > **OneDrive settings** > **More settings** > **Site collection
   administrators**, and remove the admin. The Worker's grant stays. Running the script or the
   grant check again needs step 2 again.

The certificate's private key exists only in `%LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx`
(outside the repo). Its password exists only in Credential Manager, as the generic credential
`RestoreProof Lab - Worker Graph app PFX`. The script never prints either. To renew the
certificate, delete the PFX and run the script again.

### The vault: the Worker's secrets (W4.5)

Since W4.5 `rpworker` reads its five secrets from the DPAPI vault
`%ProgramData%\RestoreProof\vault.bin` and from nowhere else (`docs/worker-config.md`,
"Secrets"): `veeam_username`, `veeam_password`, `graph_cert_pfx_base64`, `graph_cert_password`
and `signing_key_base64`. `entra/fill-worker-vault.ps1` fills it from what the lab already
keeps: the Veeam account `<COMPUTERNAME>\rp-veeam` and its password (the Credential Manager
entry `RestoreProof Lab - rp-veeam (local Veeam REST)`, `docs/api/veeam-m365/README.md`), the
PFX file and its Credential Manager entry above (after checking the password opens the PFX),
and the signing key's own entry (below). It feeds each value to `rpworker vault set <name>` on
stdin, one process per value, so no value is ever on a command line, in an environment variable
or in a file, and ends with `rpworker vault list`. Run it from an elevated shell (the default
vault's ACL is SYSTEM, Administrators and the file's owner), from the repo root, PowerShell 7:

```powershell
.\lab\entra\fill-worker-vault.ps1
.\lab\entra\fill-worker-vault.ps1 -VaultPath C:\restoreproof-runs\lab-vault.bin   # another vault file (--vault)
```

It prints rpworker's own lines, `set <name> in C:\ProgramData\RestoreProof\vault.bin` five
times and then the five names. Without a signing key it does not fail, since only `rpworker
test --evidence` signs: it sets the other four and prints `skipped signing_key_base64:` naming
the missing entry and `new-signing-key`. An entry that is there but isn't a signing key stops
it before anything is set; the message never shows the entry's value. A `vault set` that fails
stops it with that command's exit code, the values before it set.

The script writes nothing itself (rpworker writes the vault) and keeps no value in the session.
`-Worker`, `-VaultPath`, `-VeeamUser`, `-VeeamCredentialTarget`, `-PfxPath`, `-CredentialTarget`
and `-SigningKeyTarget` point it at another Worker, vault, account, PFX or credential (the tests
use them, with a stub Worker, so no test reads the lab's own entries or writes the lab's vault).

To read the vault from an unelevated shell (the read-only live tests, `rpworker vault test`),
grant your own account once, from an elevated shell:
`.\worker\build\dev\rpworker.exe vault grant "$env:USERDOMAIN\$env:USERNAME"`
(`docs/testing.md`, "Live tests").

### The signing key (W4.3)

`rpworker test --evidence <dir>` signs the result with an Ed25519 key (`signature.json` beside
`result.json`; `docs/decisions.md` 2026-10-05 W4.3). A deployment's key is made by the installer
with `rpworker signer new-key` (W7.1); the lab's key was made here, once, from `lab/`, and
`fill-worker-vault.ps1` puts it into the vault as `signing_key_base64` (W4.5):

```bash
uv run python -m seeder new-signing-key
uv run python -m seeder new-signing-key --public-key-out C:\path\outside\the\repo\worker-signing.pub.pem
```

It makes the key pair with `cryptography` and keeps the private key in Windows Credential
Manager, as the generic credential `RestoreProof Lab - Worker signing key`: one line of standard
Base64 of the key's PKCS#8 DER, 64 characters, which is the body line of the PEM OpenSSL writes
and exactly what the vault's `signing_key_base64` holds. Then it prints, on stdout and nothing else there:

```
-----BEGIN PUBLIC KEY-----
<one line of 60 Base64 characters>
-----END PUBLIC KEY-----
key <key_id>
```

The PEM is the public key's SubjectPublicKeyInfo, what a verifier is given
(`rpworker signer verify <folder> --public-key <pem file>`, `shared/tools/verify_bundle.py`).
`key_id` is the SHA-256 of that key's DER in lower-case hex, the `key_id` of every
`signature.json` the key makes. stderr gets
`stored the private key in Credential Manager ('RestoreProof Lab - Worker signing key')` and,
with `--public-key-out`, `wrote <file>`.

- **The private key is never printed, logged or written to a file in the clear.** It exists in
  Credential Manager and, after `fill-worker-vault.ps1`, in the Worker's vault. The public key
  can be shown again at any time with `rpworker signer public-key`.
- **An existing key is not replaced** unless `--replace` is given. A replaced key orphans every
  signature made with the old one: no run folder signed with it verifies against the new public
  key, and the old private key can't be brought back. The refusal says so and makes no key.
- **`--public-key-out <file>` must be outside the repository** (the lab's public key isn't
  committed; the rule follows `..` and symbolic links), in a folder that exists, and not a file
  that is already there unless `--replace` is given. Each is refused before a key is made. If
  the file can't be written after the key is stored, the PEM on stdout is the copy to keep.
- After storing, the command reads the entry back and prints the public key only if it is the
  key it made.

The published test keys in `shared/testdata/signing-v1/keys.json` (RFC 8032's) are not the lab's
key and sign nothing real.

## Commands

Run from `lab/`:

```bash
uv sync                               # create .venv from uv.lock
uv run pytest                         # all tests, offline
uv run python -m seeder generate      # write the 20 files into canary/
uv run python -m seeder hash          # offline check: canary/ and the manifest agree (L1.2's Done when)
uv run python -m seeder seed          # live: put the 40 items in the tenant, write seed-manifest.json
uv run python -m seeder verify        # live: re-read the 40 items and compare with the manifest
uv run python -m seeder seed-real     # live: put real, non-canary files and mails in the tenant (L1.8)
uv run python -m seeder check-worker-app  # live: what the Worker app can and can't reach (L1.5, W3.4)
uv run python -m seeder record-graph-fixtures  # live: re-record worker/tests/fixtures/graph/ (W2.1)
uv run python -m seeder record-graph-fixtures --state empty  # live: the restore targets, empty (W2.2)
uv run python -m seeder new-signing-key   # offline: the lab's signing key into Credential Manager (W4.3)
```

| Command | Network | What it does | Exit code |
|---|---|---|---|
| `generate` | no | Writes the 20 canary files into `canary/`. The output is byte-identical on every run, so after a clean checkout it changes nothing | 0 |
| `hash` | no | Checks that `seed-manifest.json` exists, is valid JSON and matches the schema; has exactly 40 entries whose ids, kinds and order match the catalog; that each file in `canary/` has the recorded `local_sha256` and `local_size` and that `stored_matches_local` is consistent; that each mail's `sent_body_sha256` equals the text-v1 hash of the catalog body and its subject and recipient match the catalog. Prints one line per entry and a summary (`40/40 entries reproduce the manifest hashes`) | 0 all reproduce; 1 any difference (each message names the entry, expected and actual); 2 manifest missing, unreadable or invalid (wrong count, order or schema) |
| `seed` | yes | Signs in three times, sends the missing mails, uploads the missing files, reads all 40 back and writes the manifest. Step by step below | 0 manifest written; 1 a problem the output explains (missing canary file, duplicate subject, mail timeout); 2 sign-in or Graph error. No manifest is written unless it exits 0 |
| `verify` | yes | Re-reads every item by its Graph id as the account that owns it (alice: mails 0001–0010 and the OneDrive files; bob: mails 0011–0020; admin: the SharePoint files). Compares subject, sender (case-insensitive), sent and received dates, `internet_message_id` and `body_sha256`; for files name and `content_sha256` by `content_rule` (and size for `bytes` files); an Office file whose bytes changed but whose content didn't is `ok`, with a note. Prints `ok`, `DIFF` or `MISSING` per entry and a summary (`40/40 entries in the tenant match the manifest`) | 0 all ok; 1 any DIFF or MISSING; 2 manifest missing or invalid, or a sign-in or Graph error |
| `seed-real` | yes | Signs in three times (admin, alice, bob), finds and checks its two places, then uploads 7 files to the root of the RestoreTest site's default drive and 7 to the root of alice's OneDrive, and sends 6 mails each way between alice and bob. Never replaces a file or sends a subject twice. Details in "Real data for the random sample" below | 0 done; 1 a rule or a place refused (the output says which), nothing uploaded or sent; 2 manifest missing or invalid, a send refused (nothing uploaded or sent), or a sign-in or Graph error |
| `check-worker-app` | yes | Signs in as the RestoreProof Worker app with its certificate (PFX from `--pfx`, default `%LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx`; password from Credential Manager). Checks the Graph token's roles are exactly `Files.SelectedOperations.Selected`, `Lists.SelectedOperations.Selected` and `Sites.Selected` and that its Exchange Online and SharePoint tokens carry none, signs in as alice (the seeder app) to confirm her canary folder exists, then sends one request per probe and prints `ok` or `UNEXPECTED` per row with the expected and actual status (the probe table is in `docs/security/graph-permissions.md`). Writes only W3.4's probes in the three restore targets, below; at a canary it sends nothing but GETs (the write refusal there is `entra/check-worker-grants.ps1`'s) | 0 all as expected; 1 anything unexpected; 2 a missing or unusable credential, or a sign-in error (the app's or alice's) |
| `record-graph-fixtures` | yes | Records the Graph and Entra replies the Worker's GraphClient tests replay (W2.1) into `--out`, default `worker/tests/fixtures/graph/`. Signs in as the RestoreProof Worker app the way the Worker does: its own client assertion (PS256, header `x5t#S256`), certificate and password as for `check-worker-app`. Then sends six more token requests that must fail (an assertion signed by an unknown key, an unknown certificate, app and tenant, one expired and one not yet valid by an hour) and seven GETs (the restoretest inbox, alice's inbox, the tenant root site, `/users`, a bad and a missing token, an unknown user). Prints one line per file with the status and error code. With `--state empty\|one-item\|paged` (W2.2) it records the three restore targets instead, read the way the Worker's `TargetReader` reads them. Only reads. Details below | 0 all of the state's files written; 1 a reply had another status than its file name says, or not the content its state needs, nothing written; 2 a missing or unusable credential, a failed sign-in, a network error, a reply that holds something secret-looking, or a request that needs an item or link an earlier reply didn't give, nothing written |
| `new-signing-key` | no | Makes the lab's Ed25519 signing key pair, stores the private key in Credential Manager (`RestoreProof Lab - Worker signing key`) and prints the public key's PEM and `key <key_id>`. Never prints or writes the private key. Windows only. Details in "The signing key" above | 0 key stored and public key printed; 2 an entry is already there and no `--replace`, a `--public-key-out` path that is refused or couldn't be written, or Credential Manager couldn't be read or written |

A usage error (unknown command or option) exits 2. Ctrl+C exits 130; `seed` then says nothing was written.

Options:

| Option | Commands | Meaning |
|---|---|---|
| `--client-id <id>` | `seed`, `seed-real`, `verify` | The seeder app's client ID. Order: this option, then `RP_LAB_CLIENT_ID`, then `SEEDER_CLIENT_ID` in `seeder/tenant.py`. If all are empty the tool stops and points here |
| `--client-id <id>` | `check-worker-app` | The Worker app's client ID. Order: this option, then `RP_LAB_WORKER_CLIENT_ID`, then `WORKER_CLIENT_ID` in `seeder/tenant.py` |
| `--client-id <id>` | `record-graph-fixtures` | As for `check-worker-app` |
| `--pfx <path>` | `check-worker-app`, `record-graph-fixtures` | The Worker app's certificate, if not in the default place |
| `--out <dir>` | `record-graph-fixtures` | Where to write the fixtures (default `worker/tests/fixtures/graph/` in the repo). Existing files of the same names are replaced; other files are left alone |
| `--state auth\|empty\|one-item\|paged` | `record-graph-fixtures` | Which fixtures: `auth` (default) the 14 of W2.1; the others the restore targets in that state (W2.2), see below |
| `--seeder-client-id <id>` | `check-worker-app` | The seeder app's client ID, for alice's sign-in. Same order as `--client-id` for `seed` |
| `--auth browser\|device` | `seed`, `seed-real`, `verify`, `check-worker-app` | `browser` (default) opens a browser window for each sign-in. `device` prints a code to enter at https://microsoft.com/devicelogin instead |
| `--force` | `seed` | Send every mail again and replace every file, even if it is already there |
| `--replace` | `new-signing-key` | Replace the key that is in Credential Manager (and the `--public-key-out` file, if it exists). Every signature made with the old key is orphaned |
| `--public-key-out <file>` | `new-signing-key` | Also write the public PEM to `<file>`, which must be outside the repository |
| `--mail-timeout <seconds>` | `seed` | How long to wait for sent mails to arrive (default 600) |
| `--canary-dir`, `--manifest` | all that use them | Other paths than `canary/` and `seed-manifest.json` (tests use these) |

### `check-worker-app`'s write probes (W3.4)

W3.4's Cleaner deletes what a run restored, so the check proves the app can delete in the
three restore targets (`docs/decisions.md` 2026-10-02, point 9). After the read probes it
sends, in this order:

| Rows | Requests | Expected |
|---|---|---|
| RestoreTarget library: create a file, delete it | `PUT /drives/{RestoreTarget drive}/items/root:/rp-probe-<uuid>.txt:/content` (fail on a name conflict), then `DELETE /drives/{RestoreTarget drive}/items/{id}` with the `If-Match` ETag the upload returned | 201, then 204 |
| alice's OneDrive: RestoreTarget folder: create a file, delete it | the same, under `/drives/{alice's drive}/items/{RestoreTarget}:` | 201, then 204 |
| restoretest's mailbox: create a draft, permanently delete it | `POST /users/restoretest@…/messages` (a draft with subject `rp-probe-<uuid>` and no recipient), then `POST …/messages/{id}/permanentDelete`, both with `Prefer: IdType="ImmutableId"` | 201, then 204 |

Rules the code keeps, each with a test in `tests/test_worker_app.py`:

- **Writes go to the restore targets only.** Every create and delete path is checked against
  the three targets before it is sent, and one naming the canary library, list or folder is
  refused without a request. No folder is ever created, anywhere.
- **Nothing but a GET reaches a canary.** No request of another method goes to the canary
  library, list or folder, and no request names a canary file's ID (a test runs the check
  against a fake tenant with and without misgrants and looks at every request).
- **A probe deletes only its own item.** The delete is built from the create's reply only when
  that reply shows the probe's name, the target's drive and (in OneDrive) the
  `/RestoreTarget` folder. Otherwise nothing is deleted and the row says to check by hand.
- **A create is never sent twice.** After no answer or a 502/503/504 the item may exist; the
  row says so (a file is removed by the Worker's next clean, a draft in `restoretest`'s Drafts
  by hand).
- **An interrupted delete is sent once more on the way out**, for that same item only.

Save the output as the W3.4 evidence (from `lab/`; it holds no secret):

```powershell
uv run python -m seeder check-worker-app | Tee-Object -FilePath ..\docs\security\w3.4-worker-app-check.txt
```

### The canary grant check: `entra/check-worker-grants.ps1` (W3.4)

No write probe can prove the app is refused at a canary without risking a real write there.
Live on 2026-10-02 two were tried and neither could tell: a `PATCH` with a made-up `If-Match`
on a canary file the app can read got 412 (SharePoint checks the ETag before write
permission), and a folder create with an invalid name (`rp-probe-invalid:name`) got 400 at both
canary locations, alice's `/RestoreTest` folder included, which the app can't even read (404 on
a GET): Graph checks the name before any permission, so a 400 says nothing. So the proof is the
grants themselves. In Microsoft's selected-permissions model an app reaches a site, list,
folder or file only through an application grant on it or on a parent it inherits from
([Overview of Selected permissions](https://learn.microsoft.com/graph/permissions-selected-overview),
"How access is calculated"). `docs/decisions.md` 2026-10-02, W3.4 build notes, points 13 and 14.

The grants are half the proof. The other half is the app's tenant-wide roles: an application
role such as `Sites.ReadWrite.All` or `Files.ReadWrite.All` would reach every canary without
any grant this script lists. `check-worker-app`'s token-roles rows check those (only the three
`*.Selected` roles in the Graph token, none for SharePoint or Exchange); the script says so on
its second line (`scope: …`). Both runs together are the evidence.

The script lists the grants read-only, as the admin, and matches the Worker app by its client
ID (`$WorkerAppId`, `737da5ef-…`), never by its name: the live listing showed the RestoreTarget
list's application grant with an empty name. The ID is read from `grantedToV2`, `grantedTo`,
`grantedToIdentitiesV2` and `grantedToIdentities`, whichever Graph gives, and, failing closed,
a permission that names the ID anywhere else (SharePoint can show an app principal as a
`siteUser` whose login name holds it, with no `application` facet) counts as the Worker app's
too. Every parent of each canary is read, up to its site: alice's OneDrive site is found by its
URL (`GET /sites/restoreprooflab-my.sharepoint.com:/personal/alice_…`), checked to hold her
OneDrive drive (`GET /sites/{her site}/drive`), and her Documents list through the drive
(`GET /drives/{alice's drive}/list`); if any of that fails, her site and list are one problem
and their grants aren't read.

| Location | Request (GET) | Must hold |
|---|---|---|
| RestoreTest site | `/sites/{site}/permissions`, then each Worker app grant by its ID (the list may leave roles out) | exactly one Worker app grant, roles exactly `read` |
| canary library RestoreTest (list) | `/sites/{site}/lists/{canary list}/permissions` | no Worker app grant of its own; an inherited one only with roles `read` |
| canary library root folder | `/drives/{RestoreTest drive}/root/permissions` (the library canaries sit in its root) | as the canary list |
| alice's OneDrive site | `/sites/{her site}/permissions` | no Worker app grant at all |
| alice's OneDrive Documents list | `/sites/{her site}/lists/{her Documents list}/permissions` | no Worker app grant at all |
| alice's OneDrive root | `/drives/{alice's drive}/root/permissions` | no Worker app grant at all |
| alice's RestoreTest canary folder | `/drives/{alice's drive}/items/{RestoreTest}/permissions` | no Worker app grant at all |
| each of the 10 library canary files | `/drives/{RestoreTest drive}/items/{id}/permissions`, IDs from `seed-manifest.json` | as the canary list |
| each of the 10 OneDrive canary files | `/drives/{alice's drive}/items/{id}/permissions` | no Worker app grant at all |
| RestoreTarget list | `/sites/{site}/lists/{RestoreTarget list}/permissions` | exactly one Worker app grant of its own, roles exactly `write` |
| alice's RestoreTarget folder | `/drives/{alice's drive}/items/{RestoreTarget}/permissions` | the same |

It follows `@odata.nextLink` (only within Graph v1.0). Any other application's grant is printed
as a `note:` line, not a problem (in SharePoint's claim form too). A GET that fails, or a reply
without a permission list (`value`), is a problem, never a pass. It refuses to run, reading
nothing, if `seed-manifest.json` can't be read, lists fewer than 20 canary files, or puts one
outside its canary drive, a library file outside the canary list's root folder, or a OneDrive
file outside alice's canary folder (the parents it reads). It prints one line per location (label, `ok` or
`PROBLEM`, the counts), each problem and note under it, then `canary grants: ok` (exit 0) or
`canary grants: N problem(s)` (exit 1). Nothing it prints is secret. Save it as the W3.4
evidence, from the repo root:

```powershell
pwsh -NoProfile -File lab\entra\check-worker-grants.ps1 | Tee-Object docs\security\w3.4-worker-grants-check.txt
```

`new-worker-app.ps1` runs the same script at its end, in its own Graph session
(`-UseCurrentSession`, with the client ID it set up). The rules are a pure function,
`Test-PermissionRule`, which `tests/test_entra_script.py` runs through `pwsh` row by row,
failure rows first, and the whole script with `Invoke-MgGraphRequest` stubbed; the same file
checks that the script sends only GETs, asks only for `Sites.FullControl.All` and names no
write verb.

## Recording the Worker's Graph fixtures (W2.1)

`record-graph-fixtures` writes the 14 live fixtures in `worker/tests/fixtures/graph/`, in the
format of `worker/tests/fixtures/veeam/README.md`: `source` (`live <date>: <what was sent>`),
`request` (method and path with query; the random tenant ID shows as `<random GUID>` and the
random unknown user as `nobody-…`), `status`, `headers` (only `Content-Type`,
`WWW-Authenticate`, `Retry-After`, `Location`, `request-id`, `client-request-id` and
`x-ms-request-id`) and `body` (JSON as sent, a string if it isn't JSON, `null` if empty).
The hand-written fixtures in that folder are not touched.

Safety, all checked before anything is written:

- The access token in `token-200.json` becomes a fake unsigned JWT
  (`eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzY3J1YmJlZCI6dHJ1ZX0.`, `alg: none`).
- A file is refused (exit 2, nothing written) if it holds anything that looks like a real JWT
  (`eyJ` and 37 or more base64url characters), the text `client_assertion`, the PFX password,
  the real token, one of the assertions sent, or a line of the private key.
- Every reply must have the status in its file name; if Graph or Entra answers differently
  (a permission changed, say), nothing is written and the line says `UNEXPECTED`.
- It never prints the password, the token or an assertion: only file name, status and error
  code. Graph is only read (GET); the only POSTs are the token requests to Entra.

Run it from `lab/` after a permission change or to refresh the recordings, then look at the
diff in `worker/tests/fixtures/graph/` before committing: request IDs, dates and trace IDs
always change.

### The restore-target states (W2.2)

`--state` records what the Worker's `TargetReader` reads in the three restore targets: the
`restoretest` Inbox, the RestoreTarget library's root and alice's OneDrive `/RestoreTarget`
folder (never the RestoreTest library or alice's `/RestoreTest` folder, which hold the
canaries). It signs in as above but writes no `token-200.json`. Each state needs the targets to
be in that state first; the recorder checks, and if they aren't, the line says
`UNEXPECTED (<what differs>)`, it writes nothing and exits 1 (for example
`mail-list-200-empty.json  200  -  UNEXPECTED (expected 0 item(s), got 1)`).

| State | The targets must hold | Files (in the order sent) |
|---|---|---|
| `empty` | nothing: no mail in the Inbox, no file or folder in either root (after L1.4's cleanup) | `mail-list-200-empty.json`, `restoretarget-drive-200.json`, `restoretarget-children-200-empty.json`, `onedrive-folder-200.json`, `onedrive-children-200-empty.json`, `onedrive-folder-404-itemnotfound.json`, `drive-404-itemnotfound.json` |
| `one-item` | exactly one mail in the Inbox, one file in the RestoreTarget library's root and one in alice's `/RestoreTarget` | `mail-list-200-one-item.json`, `restoretarget-children-200-one-item.json`, `restoretarget-content-302.json`, `onedrive-children-200-one-item.json`, `onedrive-content-302.json` |
| `paged` | exactly two mails in the Inbox (the files don't matter) | `mail-list-200-page1.json` (`$top=1`), `mail-list-200-page2.json` (page 1's `@odata.nextLink`), `mail-list-200-page3.json` (page 2's). Exchange puts a link on every full page, the last one included, so page 2 has one and page 3 is empty without one |

What each request is and what is checked:

- The mail requests carry `Prefer: outlook.body-content-type="text", IdType="ImmutableId"`, as
  the seeder's and the Worker's do (`MAIL_PREFER` in `seeder/graph.py`); no other request
  carries anything but `Authorization`. The list is the Worker's
  (`$select=id,subject,from,sentDateTime,receivedDateTime,createdDateTime,internetMessageId,body&$top=100`,
  W3.2): the bodies come in the listing, and each must come back as `text`.
- `restoretarget-drive-200.json` is the Worker's guard read of the library's drive
  (`$select=id,name,driveType,webUrl,sharePointIds`): it must be named `RestoreTarget`, its
  `webUrl` must end `/RestoreTarget`, and it must have `sharePointIds.siteId` and `.webId`.
  `onedrive-folder-200.json` (`$select=id,name,folder,parentReference,sharepointIds`) must be
  named `RestoreTarget`, be a folder, sit in alice's OneDrive and have her OneDrive's
  `sharepointIds.siteUrl` (W2.7). `mailbox-inbox-200.json` is the guard's read of the restoretest
  Inbox (`$select=id`), which must have an `id`; `mailbox-inbox-403-exchange.json` is alice's,
  outside the Exchange scope. The drive and folder lines also print the facts the
  Worker's guard depends on: `webUrl last segment=… sharePointIds=present|absent` and
  `parentReference.path=<value or (absent)> parentReference.id=present|absent`.
- The children lists use
  `$select=id,name,size,cTag,createdDateTime,lastModifiedDateTime,file,folder&$top=200` (W3.2:
  the checker tells this run's copies from an earlier run's by `cTag` and the times). In `one-item` the one
  child must be a file (a `file` facet).
- The not-found cases use random IDs of the right shape, never a canary's: `01` and 32 base32
  letters for the OneDrive item, and the RestoreTarget drive ID with its last 16 bytes (the
  list GUID) random for the drive. Both must answer 404 `itemNotFound`.
- IDs taken from a reply (the mail, the files) go in the next URL only if they are made of
  letters, digits, `!`, `_`, `=` and `-`; a nextLink is followed only if it is on
  `https://graph.microsoft.com/v1.0/`. Anything else, or a missing item or link, stops the run
  with an error (exit 2) before the request is sent.
- The two `/content` requests are sent **without following the redirect**, so the 302 is
  recorded and nothing is downloaded. Request lines show the IDs a reply gave as
  `<item id>` and `<@odata.nextLink of mail-list-200-page1.json>` (or `page2`), and the
  random ones as `<random item ID>` and `<random drive ID>`.

Download links are scrubbed before the safety check: a `Location` keeps its scheme, host and
path and only the values of `UniqueId`, `Translate` and `ApiVersion`; every other query value
(`tempauth`, the pre-authenticated credential, and anything new) becomes `SCRUBBED`, and a
fragment is dropped. `@microsoft.graph.downloadUrl` is removed from every body, a
`tempauth=` value in any body string becomes `SCRUBBED`, and a `download.aspx` link in any body
string (a 302's HTML "Object moved" page too, whose `&` is written `&amp;`) has its query
scrubbed as a `Location`'s is. The safety check then also refuses a
file holding a `tempauth` whose value isn't `SCRUBBED` (as `tempauth=`, `tempauth%3D` or a JSON
key) or a `download.aspx` URL with another query value that isn't `SCRUBBED`.

Until a state is recorded, `worker/tests/fixtures/graph/` holds hand-written stand-ins under
the same names (`source` starting `hand-written: stand-in`); the plan test skips them, and a
test keeps the README's file table and the folder in step. To record a state:

1. **empty**: with the three targets empty, run
   `uv run python -m seeder record-graph-fixtures --state empty`.
2. **one-item**: send one mail to `restoretest@RestoreProofLab.onmicrosoft.com` and wait until
   it is in the Inbox; upload one small file to the root of the RestoreTarget library (site
   RestoreTest, library RestoreTarget) and one to alice's OneDrive `/RestoreTarget`. Give the
   mail's subject, its body and both file names distinctive text of at least 12 characters,
   e.g. `RestoreProof W2.2 one-item 7f3k`: the Worker's log sentinel test checks none of them
   reaches the log, and fails on an empty or short value, which could match by chance. Then
   `--state one-item`.
3. **paged**: send a second mail to restoretest and wait for it. Then `--state paged`.
4. Delete the two mails and the two files by hand (L1.4's cleanup), so the targets are empty
   again.

Each run replaces only its own files. Switch their rows in
`worker/tests/fixtures/graph/README.md` from the stand-in text to `live: …`, and read the diff
before committing.

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

## Real data for the random sample (L1.8)

The Worker's sampler takes half of each type from the canaries and half at random from real
data (W2.6). The lab had no real files, so a run of 10 per type got 20 of 30 items: the random
SharePoint and OneDrive halves were empty, and the random mail half depended on the folders
drawn. `seed-real` fills that gap (`docs/decisions.md` 2026-10-03, W3.6 point 2; issue #152).
It writes no manifest: the Worker takes a random item's expected values from Veeam.

What it puts where (the names are in `lab/tenant.md`, "Real data for the random sample"):

- **SharePoint:** 7 files in the root of the RestoreTest site's default drive (its
  "Documents" library, `Shared Documents`), uploaded by the admin. No subfolders, so the
  sampler sees the site as one unit holding all 7.
- **OneDrive:** 7 files in the root of alice's OneDrive, in no folder, uploaded by alice.
- **Mail:** 6 mails from alice to bob and 6 from bob to alice, each sent by its sender. Each
  is then in the backup twice under one subject (Sent Items and Inbox). The sampler skips a
  subject it has already taken, so 12 sends give 12 subjects.

The run has six steps. Steps 1 to 3 only read; steps 4 to 6 write, with the sign-ins of
steps 1 to 3 still cached:

1. **admin.** Reads the RestoreTest site's default drive and its root folder, and checks them.
2. **alice.** Reads her OneDrive and its root folder, and checks them. Looks for the 12
   subjects in her mailbox.
3. **bob.** Looks for the 12 subjects in his mailbox.
4. **admin.** Uploads the SharePoint files.
5. **alice.** Uploads the OneDrive files and sends her 6 mails to bob.
6. **bob.** Sends his 6 mails to alice.

**Where it refuses to write.** The seeder app's delegated scopes include
`Sites.ReadWrite.All`, and `graph.upload_file` writes wherever it is pointed. So `seed-real`
finds its places itself and checks them before any upload or send. It stops with
`refused: ...` and exit 1, nothing written, when:

- a drive is the RestoreTarget library's or the RestoreTest (canary) library's, by the drive
  IDs in `lab/tenant.md` (compared ignoring case);
- a drive is named `RestoreTarget` or `RestoreTest`, in any case;
- a root folder is the OneDrive `RestoreTarget` or `RestoreTest` folder, by the item IDs in
  `lab/tenant.md`;
- a root folder has no `root` facet, so it is not a drive's root;
- `/me/drive` signed in as alice is not her OneDrive's drive ID in `lab/tenant.md`.

The sends are checked again, whatever the plan said: a mail goes only from alice to bob or
from bob to alice, never to `restoretest@` or anyone else. Every mail is checked after step 3,
before the first upload, and each again at its send. A mail that breaks this stops the run
(`error: refused to send ...`, exit 2), nothing uploaded or sent.

**The plan's rules.** Checked against `lab/seed-manifest.json` before any sign-in; a plan
that breaks one stops with exit 1:

- every name and subject is printable ASCII, with no space at either end, and not empty;
- none contains `/`, `\` or `:`;
- none starts with `rp-canary-`, in any case (the Worker's lister skips those);
- none has the same name key as a canary file name or mail subject in the manifest;
- names and subjects are distinct by name key within their type. The key is upper case: the
  Worker's `name_key` for ASCII, the same rule SharePoint and OneDrive use for "the same
  name";
- files are txt, pdf, png, docx or xlsx, each under 1 MiB;
- mails go from alice or bob, to the other one.

**The files.** Made at run time, deterministically, through the canary generators
(`generate.py`, standard library only, nothing compressed), so their bytes never differ from
run to run. Mostly txt, pdf and png: the Worker compares their size with Veeam's. One xlsx in
SharePoint and one docx in OneDrive, whose names alone are compared (SharePoint rewrites
Office files). The xlsx's sheet is named `Sheet1`, not `Canary`, and the txt files carry no
canary footer: no file calls itself a canary. Nothing is written to disk.

**Running it again.** Safe. A file already in its place is not uploaded again ("already
there, not replaced"), and uploads use `@microsoft.graph.conflictBehavior=fail`, so a file
that appears meanwhile is never replaced either. A mail whose subject is already in alice's
or bob's mailbox is not sent again. Copies in Deleted Items don't count. There is no
`--force`. To change a file, delete it in the tenant first. A 409 counts as "already there"
only when a re-read finds the file; otherwise it is an error (exit 2).

**When the outcome is unknown.** An upload or a send that got no answer, or a 502, 503 or 504,
is never sent again: Graph may have done it. The run stops (exit 2) and says to run `seed-real`
again, which finds the file uploaded or the mail in Sent Items and doesn't write it twice.

**Mail delivery** is not waited for: Exchange delivers within minutes, and the dry run below
shows what the backup holds.

**After seeding.**

1. Run a Veeam backup: the nightly `RP-Lab-Full` job, or start it by hand.
2. Run the read-only `[live][sample]` dry run (`docs/testing.md`, "Live sample") with a chosen
   `RP_LIVE_RUN_ID` against the new restore point. Per type, `sample.<type>.random.pool_size`
   must be at least 5 distinct names or subjects, and `containers_eligible` as expected.
3. W3.6's Done-when run reuses both, since the pool depends on the run ID and the restore
   point: `rpworker test --mail 10 --sp 10 --od 10 --run-id <the dry run's RP_LIVE_RUN_ID>
   --point <its restore point ID>`.

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

1. Open the file as a ZIP package, reading its central directory. A part name stored twice is
   refused (the package is not valid input).
2. Take every part whose name starts with the content folder, `word/` for docx and `xl/` for
   xlsx (case-sensitive), except parts inside a `_rels/` folder and names ending in `/`
   (folder entries).
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

**The C++ checker also refuses** (`worker/src/office_v1.cpp`, over libzip), where
`seeder/office.py` (Python's `zipfile`) may not: a counted part compressed by any method but
stored or deflate; an encrypted counted part; a stored counted part whose compressed and
uncompressed sizes differ; a counted part larger than 64 MiB uncompressed, or counted parts
larger than 64 MiB together; a package of more than 10,000 entries (read from the end record
before the directory is, so a ZIP64 package is refused too). Names are taken as stored: a
backslash is not turned into `/`, as Python's `zipfile` does on Windows. These are
hostile-input differences only: no Office writer produces them. Where Python is lenient on
something a valid file could carry, the C++ checker is too: a local header that disagrees with
its central directory entry, bytes after the end record, and a deflated part that declares
more bytes than it holds all hash as in Python (one local header difference is even read where
Python refuses: a counted part whose local header names it otherwise is read by its directory
name). A counted part that holds more than it declares is refused by both.

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
| `stored_sha256`, `stored_size` | The bytes downloaded back through Graph at seed time. Evidence only: SharePoint may have rewritten an Office file since, so the Worker checks `stored_size` for `bytes` files only and leaves an `office-v1` canary's size unchecked |
| `stored_matches_local` | `true` if the stored bytes equal the local file |
| `content_rule` | `"office-v1"` for docx and xlsx, `"bytes"` for pdf, txt and png |
| `content_sha256` | The expected value by `content_rule`, from the stored bytes. For `bytes` it equals `stored_sha256`; for `office-v1` it also equals the committed file's content hash, which `hash` checks. **The Worker compares with this** |

The Worker's sampler (W2.6, `rp::sampling::load_canary_manifest`) reads the manifest to take
its canary half: per type, in manifest order, a window that starts at a rotation cursor
(`docs/decisions.md` 2026-09-30, W2.6). It uses `tenant_id`, each entry's `id`, `kind`,
`location`, a mail's `subject` and `received_at`, and a file's `name`, `file_type`,
`content_rule` and `stored_size`; it ignores the other fields and refuses a manifest that
breaks one of its rules (a canary in a restore target among them). It records the manifest
file's SHA-256 in the result.

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
