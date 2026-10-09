# CLAUDE.md

Guidance for Claude Code in this repository. Where this file and the code differ, trust the code and update this file. The per-task build history that used to live here is `docs/build-log.md` (archive, verbatim); the decision log is `docs/decisions.md` (one dated entry per task, its build notes, its code review).

## Project overview

RestoreProof proves that Microsoft 365 backups in Veeam Backup for Microsoft 365 actually restore.

- **Worker** (`worker/`, C++20, Windows service): samples items from a Veeam restore point, restores them through Veeam's REST API v8 into three dedicated restore targets, reads them back through Microsoft Graph, compares, cleans up, signs and RFC 3161-timestamps the result, queues it in a local outbox and uploads it to the Cloud.
- **Cloud** (`cloud/`, FastAPI, Python 3.12): dispatches jobs, verifies and stores bundles, dashboard, monthly PDF reports for MSPs. Mostly unbuilt: `cloud/app` is empty; `cloud/tests` runs the shared vectors, the schemas and `shared/tools/verify_bundle.py`.
- **Lab** (`lab/`, Python 3.12): the test tenant's canary seeder and Entra scripts. IDs in `lab/tenant.md`, the 40 canary items in `lab/seed-manifest.json`.
- **Shared** (`shared/`): the schemas, the test vectors and `verify_bundle.py`, the contract between C++ and Python.

Plan: `RestoreProof Stage 1 — Sprint Task Guide.docx`, 16 weeks, task IDs `L` lab, `W` Worker, `C` Cloud, `Q` quality, `S` sales, `P` pilots. One GitHub issue per task (#3–#95, plus #133 W4.10, #134 W4.11, #135 W4.12, #136 C5.13) on the "RestoreProof Stage 1" project; PRs say `Closes #N`. `main` is not branch-protected; the owner merges on green.

### The pipeline (`rpworker test`, as built through W4.11)

restore point → client check (the organisation `Office365`, `Worldwide`, `msid` = the profile's tenant; the manifest's tenant; the three targets resolved in that tenant) → clean before → sample (canaries + random) → target guard → restore (Veeam) → read back (Graph) → check → status → result built and validated (`restoreproof.result.v1`, invalid = `error result_invalid`) → clean after → timings → `--json <file>` (canonical bytes, never signed) **or** `--evidence <dir>` (`items.csv`, `veeam-session.log`, Ed25519 `signature.json`, RFC 3161 `timestamp.tst`, `result.json` last) → `--outbox <root>` renames the folder to `outbox\<run_id>` + `manifest.json` → `rpworker outbox flush` POSTs it to `<cloud_url>/v1/results`, 202 moves it to `sent\`.

The service (`rpworker service run`) runs that pipeline in process, one job at a time from `jobs_file`, writes `state\running.json` ahead of every step that matters, closes a run the process died in afterwards as `error interrupted|result_invalid|internal|job_invalid` (signed and queued like any run), holds while a restore of it may still run, flushes the outbox and POSTs a heartbeat to `/v1/heartbeat`.

## Status (2026-10-10)

Done: L0, L1.1–L1.8, W1–W4 (W4.1–W4.12), Q2.1, Q3.1, Q3.2, Q4.1. Milestone demos: S1 `veeam list`, S2 `restore`, S3 `test`, S4 outbox done; S5 pass row in DB, S6 PDF, S7 green `doctor` planned. No Worker CI run has started since 2026-10-03 (GitHub billing); every gate is run locally and its figures go into the task's build notes.

## Active goals and open items

- **W5.1**: `GET <cloud_url>/v1/jobs` replacing `jobs_file`; the API token on upload and heartbeat (none is sent today); what a 4xx that will never succeed and a `folder_changed` run do in the outbox.
- **W7.1**: the service account `NT SERVICE\RestoreProof`: `vault grant`, a Read ACE on Veeam's certificate key file (re-granted when Veeam renews it), ACLs on `state\`, `runs\`, `outbox\`, `sent\` and the run folders.
- **W7.2** `rpworker doctor` (S7): `vault test`, the certificate export and its `icacls` line, the record and a held loop.
- **Cloud**: C5.5 refuse a small-order key; C5.6/C5.8 the jobs document and heartbeat body as the Worker proposes them; C5.7 `/v1/results` verifying signature and timestamp and holding `resolved.organization.tenant_id` to `client.tenant_id`; C5.13 clients and connectors per tenant (#136).
- **Open review findings** are listed per entry in `docs/decisions.md` (W4.3 10–15 partly, W4.4 1–3 and 7–10, W4.5 4–10, W4.6 4–9, W4.9 5–8 and 10, W4.10 5–8 and 12–15, W4.11 8–9). Also #154 (which SharePoint grant the library needs; a revoke is cached for minutes), the W3.2 Graph fixtures' re-recording, and the screenshot (no Veeam page a browser can be given the pin for, so `no_page` always).

## Tech stack

- Worker: CMake + vcpkg (baseline pinned in `worker/vcpkg.json`; bump it to upgrade ports), Ninja + MSVC `cl`, C++20. Deps: cpr, nlohmann-json, json-schema-validator (draft 7, PRIVATE, a DLL beside the exes), spdlog, OpenSSL, libzip (zlib only), zlib, Catch2, cpp-httplib (tests only).
- Targets: `rpcore` (static lib, all logic; nlohmann-json and spdlog PUBLIC), `rpworker` (`app/main.cpp`: a `wmain` that forwards UTF-16 argv to `rp::run_main`; nothing else lives there), `rptests` (Catch2 with its own `main`, `tests/test_main.cpp`: the loopback-only network guard unless `RP_LIVE=1`).
- Cloud and lab: uv projects; `cloud/` pytest + `jsonschema`, `cryptography`, `asn1crypto` in the dev group.
- Veeam lab: Veeam Backup for Microsoft 365 13.6 (REST `v8`) on the dev laptop with a nightly backup job; `docs/environment.md`. Admin mode only (local account `rp-veeam`, password grant); restores are asynchronous and carry Veeam's own organisation app certificate, exported in memory per run from `LocalMachine\My` (`rp/cert_export.hpp`); every Veeam REST restart invalidates all tokens; Veeam's default certificate has no SAN. The Worker runs on the Veeam server (`docs/decisions.md` 2026-09-29, confirmed by W4.12).

## Core commands

Worker (from a VS 2022 Developer PowerShell; the dev shell overwrites `VCPKG_ROOT` with VS's bundled vcpkg, so set it back to the real clone, e.g. `C:\vcpkg`):

```
cmake --preset dev && cmake --build --preset dev && ctest --preset dev
ctest --preset dev -R <regex>                  # one test; exe tests are labelled "exe"
RP_LIVE=1 ctest --preset dev                   # live tests (RP_LIVE_RESTORE=1 for the two that write; elevated)
build/dev/rpworker --version
worker/tools/run_coverage.ps1                  # coverage preset under OpenCppCoverage: rptests once, then the exe tests
python tools/coverage_gate.py build/coverage/coverage.xml --min-line 80   # from worker/
python tools/fixture_secret_scan.py            # ctest "fixture secret scan"
```

Cloud (`cloud/`): `uv run pytest`; CI gate `uv run --locked pytest --cov=app --cov-branch --cov-report=term-missing --cov-report=json:coverage.json --cov-fail-under=80` then `uv run --locked python tools/check_coverage.py coverage.json`; `uv run mutmut run` once per sprint (Linux/WSL). Planned: `docker compose up` (postgres:16, minio, api, scheduler), `uv run python manage.py <command>` (Typer: create-msp, create-client, create-worker-token). Commit `uv.lock` with dependency changes.

Lab (`lab/`): `uv run pytest`; `python -m seeder hash|generate|seed|seed-real|verify|check-worker-app|record-graph-fixtures|new-signing-key`; `lab/entra/new-worker-app.ps1`, `check-worker-grants.ps1`, `fill-worker-vault.ps1`. See `lab/README.md`.

`rpworker` commands (details `docs/worker-config.md`): `--version`; `config check`; `vault set|remove <name> | list | test | grant <account>`; `veeam list`; `graph list [--hash]`; `client check --profile-file <file>`; `restore [--mail n] [--sp n] [--od n] [--point latest|<id>] [--run-id id] [--canary-cursor m,s,o] [--manifest path] [--profile-file file]`; `test [restore's flags] [--json <file> | --evidence <dir> [--outbox <root>]]`; `outbox flush|list`; `signer public-key`, `signer verify <folder> --public-key <pem> [--tsa-ca <pem>]`; `service install|uninstall|start|stop|run`. Most take `--config <path>`, `--vault <file>`, `--record <dir>`. In PowerShell quote `--canary-cursor '0,6,0'`.

Exit codes (`rp/cli.hpp`): 0 ok, 1 config or any unexpected failure, 2 auth, 3 transient, 4 any other Veeam/Graph error, a guard refusal or a stop, 5 the thing tested failed (status `fail`; `signer verify` not verified), 64 usage; `outbox flush` 3 while runs stay queued. A status `error` exits by its code's row in `kCodes`.

## Where the code lives (`worker/include/rp/` unless `src/`)

- CLI: `cli.hpp` (`run_main`, `run_cli`, exit codes); commands `veeam_command`, `graph_command`, `client_command`, `restore_command`, `test_command`, `outbox_command`, `signer_command`, `vault_command`, `service_command`; `restore` and `test` share `src/run_pipeline.{hpp,cpp}` (`rp::run_pipeline(PipelineArgs, out, err, env, recorder, Presentation, PipelineReport*)`); tables `src/text_table.hpp`.
- Config and secrets: `config.hpp` (`load_config`), `secrets.hpp` (five names, `secret_values`), `vault.hpp` (DPAPI, the owner rule, `read_trusted_file`), `client_profile.hpp`, `src/strict_json.hpp`, `src/job_rules.hpp`.
- HTTP: `http_client.hpp` (cpr), `retry_policy.hpp`, `redact.hpp`, `cert_pin.hpp`, `recording_http_client.hpp` (`--record`, `FixtureRecorder`).
- Veeam: `veeam_client.hpp`; neutral connector `connector.hpp` (no Veeam header; a test scans for it), `veeam_m365_connector.hpp` over `src/veeam_restore.*`, `veeam_explore.*`, `veeam_browse.*`, `veeam_candidates.cpp`; `connector_registry.hpp` (`veeam_m365`); `cert_export.hpp`.
- Graph: `graph_client.hpp` (`remove(ListedItem)` is the one write), `graph_targets.hpp` (`TargetReader`), `graph_download.hpp`, `cleaner.hpp`, `src/graph_paging.hpp`; the guard `target_guard.hpp` (layer 1), `target_guard_graph.hpp`, `target_guard_veeam.hpp` (layer 2 on the exact POST body).
- Verification: `sample_selector.hpp`, `canary_manifest.hpp`, `expected_set.hpp`, `checker.hpp`, `office_v1.hpp`, `text_v1.hpp`, `run_status.hpp` (`decide_status`, `kCodes`, the makers), `client_check.hpp`, `step_timer.hpp`.
- Result and evidence: `canonical_json.hpp`, `result_schema.hpp` (the embedded `shared/schemas/result.v1.json`), `result_builder.hpp`, `evidence_builder.hpp`, `signer.hpp` over `ed25519.hpp`, `timestamper.hpp` over `rfc3161.hpp`, `sha256.hpp`, `src/atomic_file.hpp`, `src/file_read.*`, `src/run_folder_tail.*` (the end of a run folder, shared by the pipeline and the close).
- Outbox and Cloud: `outbox.hpp`, `uploader.hpp` (`cloud_endpoint`, `CloudUploader`), `src/heartbeat.*`, `src/folder_ops.*`.
- Service: `service.hpp`, `service_command.hpp`, `service_log.hpp`, `service_loop.hpp` (`ServiceLoopEnv`), `service_jobs.hpp`, `service_recovery.hpp` (`running.json`, `close_run`, the hold), `service_errors.hpp`, `stop_signal.hpp`, `run_lock.hpp`; real calls only in `src/scm.*`, `src/worker_body.*`, `src/service_log_stream.*`.
- Tests: `worker/tests/`, Catch2; `fake_http_client.hpp` (`serve_recording`, `on_path`), `local_http_server.hpp`, `*_lab.hpp` harnesses, fixtures `worker/tests/fixtures/<service>/` and `fixtures/recordings/`, exe tests through `tests/run_exe_test.cmake`, the secret audit `secret_audit_test.cpp`, live tests `*_live_test.cpp` reading the vault via `live_secrets.hpp`.
- Defaults: `%ProgramData%\RestoreProof\` holds `vault.bin`, `runs\`, `outbox\`, `sent\`, `state\running.json`, `state\done\`, `logs\worker.log`. Named mutexes `Global\RestoreProof-restore-targets` and `Global\RestoreProof-outbox`.

## Non-negotiable rules

- **Restore targets.** Every restore goes to the `restoretest` mailbox, the `RestoreTarget` library in the RestoreTest site or alice's OneDrive `/RestoreTarget` folder (IDs in `lab/tenant.md`). Never the `RestoreTest` library or alice's `/RestoreTest` folder: those hold the canaries. `TargetGuard` runs per item inside `restore_sample` before any Veeam call, and again on the exact POST body; never trust configured IDs alone. The Cleaner is the only Worker code that deletes in the tenant: only in those three targets, each resolved through the guard's own checks first, only mails and plain files it has just listed there (`GraphClient::remove` takes a `ListedItem` only the Cleaner can make; a source scan enforces it); folders and anything else are never deleted. The app's write grants stay that narrow: `write` on the RestoreTarget list and the `/RestoreTarget` folder, `Application Mail.ReadWrite` scoped to `restoretest`; never `Sites.Selected` `write`, a `*.All` role or an Entra `Mail.ReadWrite` (`docs/security/graph-permissions.md`). Every run holds its client to the backup before anything is cleaned or restored (the client check; `error client_mismatch`); a job naming a connector this Worker lacks is `error connector_unknown` and never runs. The service's recovery adds no second deleter: its clean is the Cleaner's `before_run` clean by the record's own profile, never while a restore of ours may still run; in Veeam the hold ends only the sessions `running.json` lists as the run's own, and none of them while a restore request may have gone out and any other session of the account is running.
- **Status vocabulary.** `pass` = restore ran and 100% of items match; `fail` = an item missing or mismatched, its target read fine, Veeam not blaming infrastructure; `error` = the test itself couldn't run. Infrastructure problems are never `fail`. Veeam's own status never decides. The table is `docs/verification.md` and `rp/run_status.hpp`.
- **Secrets.** Only in the DPAPI vault (`vault.bin`; five names `veeam_username`, `veeam_password`, `graph_cert_pfx_base64`, `graph_cert_password`, `signing_key_base64`; filled by `rpworker vault set <name>` from the console or stdin, never an argument) or a gitignored `.env`. Never from an environment variable or `config.json` (which rejects secret-looking keys). Tests inject `Secrets` through each command's `load_secrets(vault)` seam. Never logged: `rp::redact()` masks the secret keys, JWTs, `Bearer` tokens and PEM private key blocks; headers and bodies are never logged. `veeam_username` is a name, not a secret value. The secret audit (`[secret_audit]`, and `fixture_secret_scan.py` with its allowlist) enforces this; `docs/testing.md` "The secret audit".
- **TLS.** Verification is never turned off. Veeam's self-signed certificate is trusted through `veeam_ca_file`, pinned through `veeam_cert_sha256` with only the host-name check skipped; a source scan fails the build on code that disables verification (reviewed exceptions all in `src/http_client.cpp`). `tsa_url` is the one URL that may be `http://`; a token is trusted for its signature, chain to `shared/tsa/tsa-ca.pem`, nonce and imprint, never for how it arrived. `cloud_ca_file` trusts a private CA for `cloud_url` (still https, host name checked).
- **Cloud tenant isolation.** All DB access through repo classes in `cloud/app/repo/` taking `msp_id` first; `select(` outside `app/repo/` fails a lint test.
- **Signing contract** (C++ and Python agree, held by `shared/testdata/`): `canonical-json-v1` (`rp::canonical_json`; keys sorted by byte, `,` and `:` only, no trailing newline, refuses floats, integers outside ±(2^53−1), non-ASCII keys, invalid UTF-8; Python's `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)` gives the same bytes). `result.json` is the result's canonical bytes with nothing removed; `bundle_sha256` is its SHA-256; the signature is Ed25519 over the 32 raw digest bytes, in `signature.json` beside the result (`restoreproof.signature.v1`, five keys), never in it; `timestamp.tst` is the bare RFC 3161 token over the same digest, absent when the TSA gave none (never a status). A verifier takes the public key and the TSA CA from its caller, never the folder, and refuses a `result.json` that isn't its own canonical form (`result_not_canonical`). `rpworker signer verify` and `shared/tools/verify_bundle.py` run the same checks in the same order and print the same word; the schemas in `shared/schemas/` are the only copies (the result schema embedded into rpcore at build time, read by the Cloud by path) in the subset draft 7 and 2020-12 read alike; whoever validates in Python checks the canonical form first. The run folder's other files are covered only through the result's `attachments`; `result.json`, `signature.json`, `timestamp.tst` and `manifest.json` are never listed there.
- **API contract.** All Cloud routes under `/v1`; `docs/api/openapi-v1.json` committed and diffed in CI.
- **Report wording.** Never claim more than was tested; "fully recoverable", "guarantee", "certified", "accepted by insurers" are banned by a test.
- **Nothing is edited or re-signed.** A failed run is never edited. In a queued or sent folder only `manifest.json` is ever written after the run; the Worker deletes only `sent\` runs (over 30 days, or the oldest while `outbox\` + `sent\` exceed 500 MB), never a queued one. Under `runs\` a folder with its `result.json` is only queued; a folder without one was never signed and the service's `close_run` is its one writer, for the one folder its record names: it writes one `error` result afterwards that never says what the run found. The service lists nothing under `runs\` and adopts no folder it finds there.

## TDD workflow (enforced by CI)

- Test first: an acceptance test from the task's "Done when", then red → green → refactor per step; commit test and code together.
- Anything talking to Veeam, Graph, the TSA or the Cloud is written against recorded fixtures first (`--record`, secrets scrubbed, served by `FakeHttpClient`). Live calls are gated by `RP_LIVE=1` (`docs/testing.md`). Catch2 assertions aren't thread-safe: never in code a fake handler runs on the client's threads.
- Failure-path tests before happy paths; decision tables as Catch2 `GENERATE` / `pytest.mark.parametrize`; every bug gets a reproducing test before its fix; end-to-end scenarios tracked by hand in `tests/e2e/scenarios.md`.
- Exe tests check exit code, stdout and stderr exactly (no `PASS_REGULAR_EXPRESSION` or `WILL_FAIL`); none starts the service loop or names `service install|uninstall|start|stop`; no test touches `%ProgramData%`.
- Coverage: 80% line on `rpcore` and `cloud/app` (Cloud gate on line+branch combined); 100% on the strict files, held as 100% **line** in the Worker since OpenCppCoverage has no branch data. A Worker file is strict when a part of its path is, or starts with, one of `vault`, `signer`, `target_guard`, `run_status`, `cleaner`, `timestamper`, `outbox`, `service`, `client_profile`, `strict_json`, `client_check` (`worker/tools/coverage_gate.py`); strict files are decided logic over seams, no `catch (...)` of their own, and the real calls under them (`ed25519.cpp`, `rfc3161.cpp`, `uploader.cpp`, `folder_ops.cpp`, `scm.cpp`, `stop_signal.cpp`, `worker_body.cpp`, `heartbeat.cpp`, `run_folder_tail.cpp`) are outside. Cloud: 100% on `app/auth`, `app/results.py`, `app/repo`. Every `.cpp` under `worker/src`, `include` and `app` must appear in the report.
- "No test, no merge": a PR changing `worker/src|include|app` without C++ test changes under `worker/tests/`, or `cloud/app/` without a `.py` under `cloud/tests/`, fails CI.

## Coding conventions

- rpcore works in UTF-8 and reads Windows text through the wide APIs only. Messages are one line of fixed words and counts; never `what()`, a tenant value, a path or a secret in a status, a code or a log line that could leave the machine. Every logged string goes through `redact()`; `SECURITY:` lines mark a guard or owner-rule refusal.
- A new architectural choice gets a dated entry in `docs/decisions.md` (recorded before the build; "approved as written" when the owner approved it), its build notes say where the build left the entry, and the code review gets its own entry listing fixed and open findings. Update `docs/verification.md`, `docs/worker-config.md`, `docs/testing.md`, `docs/glossary.md` and this file with the task.
- Shared documents (`shared/testdata/result-v1`, `signing-v1`, `timestamp-v1`, `canonical-json-v1.json`, `client-profile-v1`, `jobs-v1`) are written by hidden `rptests "[.write_shared_*]"` cases and run by both builds; `.gitattributes` keeps `shared/schemas/*.json` and `shared/testdata/**/*.json` LF. Keys in vectors are RFC 8032's published test keys, never a secret.
- Live evidence goes under `docs/api/veeam-lab/<task>-*` with its harness; run folders, profile files and config copies stay outside the repo (`%LOCALAPPDATA%\RestoreProof\lab\`). A live harness uninstalls the service whatever happens and never replaces committed evidence with a failed run's.

## Key docs

`docs/decisions.md` (decision log), `docs/build-log.md` (archived task history), `docs/verification.md` (expected set, checker, status table, cleanup, result, run folder, signature, timestamp, outbox, results written afterwards, client check), `docs/worker-config.md` (config keys, vault, every command, the service's loop, `jobs_file`, `running.json`), `docs/testing.md` (local gates, live tests, fixtures, shared vectors, the secret audit, by-hand checks), `docs/glossary.md`, `docs/environment.md`, `docs/security/graph-permissions.md`, `docs/api/veeam-feasibility.md`, `docs/api/veeam-notes.md`, `docs/api/veeam-restore-flow.md`, `docs/api/veeam-m365/` (the PowerShell collection; `10-restore.ps1` is the only script that writes), `docs/manual-restore-reference.md`, `lab/README.md`, `lab/tenant.md`, `tests/e2e/scenarios.md`.
