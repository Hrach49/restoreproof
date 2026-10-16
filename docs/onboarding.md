# Onboarding an MSP by hand (C5.10)

How an operator with the Cloud's database makes an MSP, its first client, a Worker's install
token, the client's connector, a test plan and, since C6.1, the MSP's users, with
`cloud/manage.py`; what each command prints; what it refuses. The decisions are
`docs/decisions.md` 2026-10-11, "C5.10 and C5.9" (and 2026-10-12, "C6.1, C6.2 and C6.3", point
12, for the users); the code
is `cloud/manage.py` (the Typer layer) over `cloud/app/onboarding.py` (the logic, through the
repos) and `cloud/app/repo/errors.py` (the database's refusals worded). The Done-when, an MSP
with one client and plan in under five minutes, is `cloud/tests/test_manage.py` and the by-hand
run `docs/api/cloud-lab/c5.9-c5.10-done-when.txt` (the six steps took seconds).

## Where to run it

The CLI reads **`DATABASE_URL` alone** from the environment, as a migration does: no bucket, no
`SECRET_KEY`. Two places:

- **Inside the local stack**, where the api container has the database's address and the
  image's own copy of `manage.py`:

  ```powershell
  cd cloud
  docker compose up -d --wait
  docker compose exec api python manage.py create-msp --name "Contoso MSP"
  ```

  A file the CLI must read (`--profile-file`) has to be in the container:
  `docker compose cp .\profile.json api:/tmp/profile.json`, then `--profile-file /tmp/profile.json`,
  then `docker compose exec api rm /tmp/profile.json`.

- **From the host**, with the stack's Postgres on 127.0.0.1:55432 (every value local only):

  ```powershell
  cd cloud
  $env:DATABASE_URL = "postgresql+asyncpg://restoreproof:local-only-postgres@127.0.0.1:55432/restoreproof"
  uv run python manage.py create-msp --name "Contoso MSP"
  ```

A deployment runs it the same way on a host that has `DATABASE_URL` (C5.12). The CLI logs
nothing and prints no secret but the one token it exists to print.

## What every command has in common

- **One transaction per command**, committed when the command returns, rolled back when it
  refuses: exit 0 means every row of the command is in the database; exit 1 means none is.
- **Stdout is one `<name> <value>` line per thing made**, in a fixed order, nothing else; a
  script takes it with `split(' ')`. Notes go to stderr.
- **A refusal is one line on stderr, `<key>: <reason>`, exit 1**, from fixed words and never a
  value of yours: the repos' own (`graph_tenant_id: not the client's tenant`), the database's by
  constraint name (`tenant_id: already a client of this MSP`), or the CLI's (`profile_file: not
  JSON`). A usage fault (an option missing, a uuid that isn't one) is Typer's own message, exit
  2, before any database is touched. A database that can't be reached is `database: unreachable`,
  exit 1; a missing or malformed `DATABASE_URL` is `settings error: DATABASE_URL is missing|is not
  valid`.
- **One audit row per command that changed a row** (`msp.create`, `client.create`,
  `install_token.create`, `connector.create` by the repo, `plan.create`, `run.create` with
  `--run-now`, `worker.revoke`, `user.create`, `user.reset_password`), `user_id` and `ip` null:
  the CLI has no user and no address.
- **A password is never an option.** `create-user` and `reset-password` ask for it on the
  console, twice, without echo (`password: the two entries differ`, exit 1), or read one line
  from standard input when that is no console (`docker compose exec -T api python manage.py
  create-user ... < nothing`; a script pipes it). It is 12 to 1024 characters, reaches no row
  but as its Argon2id hash, no line and no file.
- Every uuid option is parsed as a uuid; every name or label is 1 to 128 characters without a
  control character.

## The sequence

1. **The MSP.**

   ```
   manage.py create-msp --name "Contoso MSP" [--retention-days 1095]
   msp_id 7d1e…
   ```

2. **The client**, one per Microsoft 365 tenant of the MSP. The tenant id is the GUID of the
   client's tenant (`graph_tenant_id` in its profile; `lab/tenant.md` for the lab's). The same
   tenant twice in one MSP is refused; the same tenant in another MSP is another client.

   ```
   manage.py create-client --msp-id <msp_id> --name Fabrikam --tenant-id <guid> [--screenshots-enabled]
   client_id 3b9c…
   ```

3. **The Worker's install token.** Printed once; the Cloud stores its SHA-256 alone. It lasts
   seven days and is used once, by the Worker's registration. The label is what you'll see
   beside the Worker. The token names no client: a Worker is the MSP's, and connectors bind
   clients to it next.

   ```
   manage.py create-worker-token --msp-id <msp_id> --label veeam-vm
   install_token_id 5a2f…
   expires_at 2026-10-18T12:00:30Z
   install_token <43 characters>
   the install token is shown once; the Cloud stores its hash alone      (stderr)
   ```

   Give the token to the Worker's operator by a channel of yours. On the Worker's machine, from
   an elevated prompt (W5.1; `docs/worker-config.md` "`rpworker cloud register`"):

   ```
   rpworker vault set cloud_install_token          (the token at the console, or one line on stdin)
   rpworker service install --config <path>
   rpworker service start                          (the first start registers, then starts)
   registered worker 65fd… key 06e3…
   started RestoreProof
   ```

   `rpworker cloud register` does the registration alone, for a service started another way.
   The token is spent there (`POST /v1/workers/register`, C5.5) and removed from the vault in
   the write that stores the API token; it is never typed on a command line. The **`worker_id`**
   the next step needs is on that line (and in `state\worker.json`; C6.2's `/workers` page lists
   the Worker). A Cloud reached over a private CA (the laptop's Compose stack behind Caddy,
   `https://localhost:8443`) is trusted through the Worker's `cloud_ca_file`.

4. **The connector**: the client on that Worker, with the client's profile. The profile file is
   the same `restoreproof.client-profile.v1` document `rpworker client check --profile-file`
   reads (`docs/worker-config.md`): the Veeam organisation's name, the tenant, the Worker app's
   id, the `restoretest` mailbox and the four restore-target ids; IDs only, no secret. The
   repo holds it to the schema and its `graph_tenant_id` to the client's tenant; a client twice
   on one Worker is refused.

   ```
   manage.py create-connector --msp-id <msp_id> --client-id <client_id> --worker-id <worker_id> --profile-file profile.json [--type veeam_m365]
   connector_id 9e0d…
   ```

5. **The plan**: the sample sizes (0 to 100 each, not all 0: the Worker's own rule) and the
   cadence, five cron fields in UTC, at most every five minutes and at least monthly (`docs/verification.md`, "The Cloud makes a
   run"). The default is the guide's `0 2 * * *`, daily at 02:00 UTC. The scheduler makes the
   plan's first run at its first cron time after the plan was made; `--run-now` queues one run
   at once for a first test today.

   **Canaries are an opt-in, per plan** (C6.8, `docs/decisions.md` 2026-10-15). By default a
   plan's runs sample the client's own items alone (W6.2). `--canaries` opts the plan in: its
   jobs carry `canary_cursor`, starting at `0,0,0`, and each test then takes half of each type's
   sample from the canaries seeded in that tenant. **The Worker must hold the tenant's manifest**,
   `canaries\<graph_tenant_id>.json` beside its config (`docs/worker-config.md`), and the canaries
   must be seeded in the tenant (`lab/README.md`); without it every run of the plan ends before
   it starts, sends no result and expires after three attempts. The Cloud moves the cursor on
   after each `pass` or `fail` with canaries, from the Worker's own signed `cursor_next`. No
   command turns canaries on or off for an existing plan yet: make a new plan.

   ```
   manage.py create-plan --msp-id <msp_id> --client-id <client_id> --connector-id <connector_id> --mail 10 --sp 10 --od 10 [--cron "0 2 * * *"] [--disabled] [--run-now] [--canaries]
   plan_id c4a1…
   canary_cursor 0,0,0     (with --canaries)
   run_id 61f2…            (with --run-now)
   ```

   From here the scheduler (`cloud/app/scheduler.py`, the Compose `scheduler` service) makes one
   queued run per period, the Worker polls them (`GET /v1/jobs`), runs them and uploads each
   bundle (`POST /v1/results`).

6. **Revoking a Worker**, when its machine is retired or its token may have leaked. From the
   commit on, every request under its token is 401 (the poll, the upload, the heartbeat); its
   runs stay as evidence, its plans keep making queued runs that nothing dispatches until they
   are disabled (the admin pages, C6.x) or moved to a new Worker (a new token, a new
   registration, a new connector, a new plan).

   ```
   manage.py revoke-worker --msp-id <msp_id> --worker-id <worker_id>
   revoked_at 2026-10-11T12:00:30Z
   ```

7. **The users** (C6.1), who sign in at `/login` (`docs/verification.md` "The Cloud's pages").
   The address is trimmed, must hold one `@` with something on each side and no space, is
   stored as typed and is one across the whole Cloud whatever its case. The role is `admin`
   (reads every page, downloads, revokes a Worker, reads `/audit`) or `member` (reads every
   page and downloads). The password is asked for (above).

   ```
   manage.py create-user --msp-id <msp_id> --email admin@example.test --role admin
   Password:                                                              (console only)
   Again:
   user_id 8c3e…
   ```

   A reset (an admin-driven one; there is no self-service in Stage 1) gives a new password and
   ends every session the user had:

   ```
   manage.py reset-password --email admin@example.test
   user_id 8c3e…
   password_changed_at 2026-10-12T15:00:00Z
   ```

   The onboarding above needs no user: the install token's `created_by` and every audit row's
   `user_id` are null for the CLI.

8. **A client's monthly report** (C6.4, C6.6; `docs/verification.md` "The Cloud's report").
   The scheduler makes every client's final report of the previous month on the 1st at 03:00
   UTC (and at its start, for a 1st it missed), and the users make an interim report of the
   current month from the client's reports page ("Generate now") and download any report from
   `/reports`; the command is for a month the job did not make (its `report failed` line names
   the client) and for a run without the pages. The period is a UTC calendar month, `YYYY-MM`,
   the previous month when not given; the current month gives an interim report (as many as
   asked for, each its own object), a month that is over the final one, made once and never
   re-made, and not before 03:00 UTC on the 1st (`period: not closed until 03:00 UTC on the
   1st`: the month still takes its last results until then). A result that reaches the Cloud
   after its month closed is counted in the report of the month it arrived in. The command writes the PDF to the bucket, so it needs the five `S3_*` variables
   beside `DATABASE_URL` (the api container has them); never `SECRET_KEY`.

   ```
   manage.py generate-report --msp-id <msp_id> --client-id <client_id> --period 2026-09
   report_id 3f1a…
   period 2026-09
   interim false
   storage_key msp/<msp_id>/reports/<client_id>/2026-09.pdf
   content_sha256 <64 hex>
   file_sha256 <64 hex>
   ```

   The file hash is the SHA-256 of the object; the content hash is printed inside the PDF (the
   file cannot hold its own hash). One audit row `report.create`.

   **Checking a report** (Q6.1): any stored report, by its id (the pages list it), against what
   the bucket holds: its object's hash, and every run's token read back and verified, its time
   the row's and within two minutes of the test's end. Exit 0 with no finding; each finding one
   `<run id>: <word>` line on stderr and exit 1. The same five `S3_*` variables.

   ```
   manage.py check-report --msp-id <msp_id> --report-id <report_id>
   report_id 3f1a…
   final true
   file_sha256 ok
   runs 5
   stamped 4
   not_stamped 1
   no_bundle 0
   late 0
   findings 0
   ```

## The refusals, by command

| Command | Line | Why |
|---|---|---|
| any | `name: not 1 to 128 characters without a control character` | the name's rule (`label:` for the token) |
| any but `create-msp` | `msp_id: no such MSP` | the id names no MSP |
| `create-msp` | `retention_days: not positive` | the database's CHECK |
| `create-client` | `tenant_id: already a client of this MSP` | one client per tenant and MSP (C5.13) |
| `create-connector` | `profile_file: not readable` / `not UTF-8` / `not JSON` | the file |
| `create-connector` | `config_json: not a client-profile.v1` | the schema |
| `create-connector` | `client_id: no such client` / `worker_id: no such worker` | not this MSP's |
| `create-connector` | `graph_tenant_id: not the client's tenant` | the profile names another tenant (C5.13) |
| `create-connector` | `client_id: already a connector of this Worker` | one connector per Worker and client |
| `create-plan` | `cadence_cron: not a cron expression` / `never occurs` / `more often than every 5 minutes` / `less than monthly` | five fields, UTC, no `R`, a date that exists, at most every five minutes, at least monthly |
| `create-plan` | `sample_mail: not 0 to 100` (`_sp`, `_od`) / `sample sizes: all 0` | the Worker's J3 rule |
| `create-plan` | `connector_id: not the client's connector` | the connector is another client's or absent |
| `create-plan` | `client_id: no such client` | not this MSP's |
| `create-plan` | `canary_cursor: not 0 to 999999` | the Worker's cursor rule (`--canaries` always sets `0,0,0`; met only by a cursor written another way) |
| `revoke-worker` | `worker_id: no such Worker or already revoked` | one line for both |
| `create-user`, `reset-password` | `email: not an address` | the address's rule |
| `create-user` | `email: already a user of this Cloud` | one address across the Cloud, in any case |
| `create-user` | `role: not admin or member` | the two roles |
| `create-user`, `reset-password` | `password: not 12 to 1024 characters` / `password: the two entries differ` | the password's rule; the console's two entries |
| `reset-password` | `email: no such user` | the address names nobody |
| `generate-report` | `period: not YYYY-MM` / `has not begun` / `no run in the period` / `not closed until 03:00 UTC on the 1st` / `already reported` | the month's rule; a month not yet begun; no run of the client ended in it (and no expired one of it); a month that ended less than three hours ago; its final report exists (also when another process made it meanwhile) |
| `generate-report` | `client_id: no such client` | not this MSP's |
| `generate-report` | `settings error: S3_ENDPOINT is missing; …` | the five S3 variables, named at once, before the database |
| `check-report` | `report_id: no such report` | not this MSP's, or no report of that id |
| `check-report` | `settings error: S3_ENDPOINT is missing; …` | the five S3 variables, named at once, before the database |
| `check-report` | `report: N check(s) failed`, after one `<run id>: <word>` line per finding (`file: <word>` for the object) | a check missed: the object's hash, a token, a time, a row's bundle columns (`docs/verification.md` "The report checks" lists the words) |
| any | `database: unreachable` / `settings error: DATABASE_URL …` / `internal: <type>` | the environment, or an error nobody foresaw (its type alone) |
