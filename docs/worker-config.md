# Worker configuration

How the Worker is configured: the settings file, the secrets, and how to check both with
`rpworker config check`. The contract is in `worker/include/rp/config.hpp` and
`worker/include/rp/secrets.hpp`; where this page and the code disagree, the code wins.

## Where the file lives

By default the Worker reads `%ProgramData%\RestoreProof\config.json` (usually
`C:\ProgramData\RestoreProof\config.json`). `%ProgramData%` is resolved through Windows
(`FOLDERID_ProgramData`), not from the environment variable. `rpworker config check --config
<path>` reads another file instead.

The file is JSON with one flat object of settings. A UTF-8 byte order mark, as Notepad writes,
is accepted. `worker/config.example.json` has every key with placeholder values; copy it and
fill in your own.

## Settings

Ten keys are required; the other six have defaults.

| Key | Required | Default | Valid values | What it is for |
|---|---|---|---|---|
| `cloud_url` | yes | | `https://` URL | The RestoreProof Cloud the Worker gets jobs from and uploads results to. |
| `veeam_url` | yes | | `https://` URL | The Veeam Backup for Microsoft 365 REST API, e.g. `https://veeam.example.invalid:4443`. |
| `veeam_org_name` | yes | | non-empty string | The Microsoft 365 organisation as Veeam names it, e.g. `example.onmicrosoft.com`. |
| `graph_tenant_id` | yes | | non-empty string | The Microsoft 365 tenant ID, for Microsoft Graph sign-in. |
| `graph_client_id` | yes | | non-empty string | The app registration's client ID, for Microsoft Graph sign-in. |
| `test_mailbox` | yes | | email address (`@` with text both sides) | The `restoretest` mailbox: the only restore target for mail. |
| `test_site_id` | yes | | non-empty string | The SharePoint site holding the `RestoreTest` library. |
| `test_library_id` | yes | | non-empty string | The `RestoreTest` library: the only restore target for SharePoint items. |
| `test_onedrive_drive_id` | yes | | non-empty string | The OneDrive drive holding the `RestoreTest` folder. |
| `test_onedrive_folder_id` | yes | | non-empty string | The `RestoreTest` folder: the only restore target for OneDrive items. |
| `poll_interval_s` | no | `300` | integer, 1 to 86400 | Seconds between the Worker's requests to the Cloud for new jobs. |
| `heartbeat_interval_s` | no | `900` | integer, 1 to 86400 | Seconds between the Worker's reports to the Cloud that it is alive. |
| `sample_mail` | no | `5` | integer, 0 to 100 | Mail items restored per test run. |
| `sample_sp` | no | `5` | integer, 0 to 100 | SharePoint items restored per test run. |
| `sample_od` | no | `5` | integer, 0 to 100 | OneDrive items restored per test run. |
| `log_level` | no | `"info"` | `trace`, `debug`, `info`, `warn`, `error`, `critical`, `off` | How much the Worker logs. Lowercase only. |

At least one of `sample_mail`, `sample_sp` and `sample_od` must be above 0.

## Validation

The Worker checks the file when it loads it and stops at the first problem, in a fixed order:
the file can't be read; it isn't valid JSON; it isn't a JSON object; a key looks like a secret;
a key is unknown; then each setting in the order of the table above; then the sample sizes
together. Fix the reported problem and run `rpworker config check` again.

- **Messages name the key and never repeat a value from the file.** A JSON syntax error
  reports only the byte offset where parsing failed, because the parser's own message can
  quote whatever it read last, which might be a password.
- **Unknown keys are rejected.** A misspelt optional key (`poll_intervall_s`) would otherwise
  be ignored and its default used without anyone noticing. Keys are case-sensitive.
- **All sample sizes 0 is rejected.** A run that restores nothing has nothing to compare, and
  must not be able to report `pass`.
- Numbers must be JSON integers: `"300"`, `300.0`, `true` and `null` are wrong types.
- Duplicate keys are not detected; the last one wins.

## Secrets

`config.json` must not contain secrets. Any top-level key whose name, in any case, contains
`password`, `passwd`, `secret`, `token`, `api_key` or `apikey` is rejected, and checked before
anything else so that the secret is removed first.

Until the DPAPI vault (`%ProgramData%\RestoreProof\vault.bin`) arrives in W4.5 (issue #48),
secrets are read from these environment variables, whose names are defined once in
`worker/include/rp/secrets.hpp`:

| Variable | What it is for |
|---|---|
| `RP_VEEAM_USERNAME` | The account the Worker signs in to the Veeam REST API with. |
| `RP_VEEAM_PASSWORD` | That account's password. |
| `RP_GRAPH_CLIENT_SECRET` | The client secret of the app registration named by `graph_client_id`. |

Any of them may be unset for now: which ones a run needs depends on the Veeam authentication
mode, which W1.0 decides. A variable set to an empty string counts as unset.

To set them for the current PowerShell session:

```powershell
$env:RP_VEEAM_USERNAME = '...'
$env:RP_VEEAM_PASSWORD = '...'
$env:RP_GRAPH_CLIENT_SECRET = '...'
```

A Windows service does not see a user's session variables. Until the vault lands, a Worker
running as a service would need them set at machine level, where any local administrator can
read them.

## `rpworker config check`

```
rpworker config check [--config <path>]
```

Loads the config file and the secrets and prints what it found. It changes nothing.

| Exit code | Meaning |
|---|---|
| 0 | The config is valid. Unset secrets are not an error. |
| 1 | The config failed to load or validate; stderr has `config error: <path>: <message>`. |
| 2 | Arguments not understood; stderr has the usage line. |

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
secrets (environment variables; values are never shown):
RP_VEEAM_USERNAME         **** (set)
RP_VEEAM_PASSWORD         **** (set)
RP_GRAPH_CLIENT_SECRET    (not set)
```

A secret prints only as `**** (set)` or `(not set)`: never any character of its value, nor its
length.

An error looks like this:

```
config error: C:\ProgramData\RestoreProof\config.json: config key "poll_interval_s" must be an integer from 1 to 86400 (seconds)
```
