# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

Early Stage 1. The plan is `RestoreProof Stage 1 — Sprint Task Guide.docx`, which breaks a 16-week plan into tasks with IDs (e.g. `L0.1`, `W2.7`, `C5.7`). L0.1–L0.5, W1.1, W1.2 and W1.3 are done: CI builds and tests `worker/` (`rpcore` with `include/rp/` and `src/`, linking cpr, nlohmann-json, spdlog and OpenSSL; `rpworker` from `app/main.cpp`, whose `wmain` hands the UTF-16 command line to `rp::run_main` (UTF-8, then `rp::run_cli`) in rpcore and answers `--version` and `config check [--config <path>]` so far; the config loader `rp::load_config` with its env var secret names in `rp/secrets.hpp`, see `docs/worker-config.md`; the HTTP layer `rp::IHttpClient` (one virtual, `send`) and its cpr-backed `rp::HttpClient` in `rp/http_client.hpp`, with the pure units `rp/retry_policy.hpp` (5 attempts in total) and `rp/redact.hpp` (every logged string), see the W1.3 entry in `docs/decisions.md`; Catch2 tests) and `cloud/` (pytest), with coverage gates and the "No test, no merge" PR guard (see `docs/testing.md`). L1.2 (in progress) adds `lab/` (uv project: `python -m seeder generate|hash|seed|verify`, see `lab/README.md`), tested by the `lab` CI workflow. `main` is not branch-protected (free private repo), so the gates don't block merges; the owner merges only on green (`docs/decisions.md`). Tasks are tracked as issues #3–#95 on the "RestoreProof Stage 1" GitHub Project (columns Backlog, Sprint 1–8, In progress, Done), one per guide task, labelled with its prefix; use `Closes #N` in PRs. Much of what follows describes the **planned** design from the guide; where code exists, trust the code over this file, and update this file.

Task ID prefixes: `L` lab/env (`lab/`, `docs/`), `W` Worker C++ (`worker/`), `C` Cloud Python (`cloud/`), `Q` quality (`tests/`, `docs/`), `S` sales (`sales/`), `P` pilots (`docs/pilots/`). Each task is one GitHub issue; its "Done when" line is the acceptance criterion.

## What the product does

RestoreProof proves that Microsoft 365 backups in Veeam Backup for Microsoft 365 actually restore. An on-prem **Worker** (C++, Windows service) samples items from a Veeam restore point, restores them through the Veeam REST API (v8) into dedicated test locations, reads them back through Microsoft Graph, compares them, cleans up, and uploads a signed, RFC 3161-timestamped result bundle. A **Cloud** backend (FastAPI) dispatches jobs, verifies and stores bundles, shows a dashboard, and generates monthly PDF reports for MSPs.

Worker pipeline (`rpworker test`): cleanup → pick restore point → sample select → target guard → restore → verify → cleanup → result JSON → sign → timestamp → outbox → upload.

## Planned commands

Worker (`worker/`, CMake + vcpkg, C++20, MSVC; deps in `vcpkg.json`: cpr, nlohmann-json, spdlog, openssl, catch2, and cpp-httplib, which is test-only and linked only into `rptests`). Targets: `rpcore` (static lib holding all logic; nlohmann-json and spdlog linked PUBLIC, cpr and OpenSSL::Crypto PRIVATE), `rpworker` (exe, `app/main.cpp`, a `wmain` that only forwards its UTF-16 argv to `rp::run_main`; conversion, parsing and exit codes live in rpcore. rpcore works in UTF-8 and reads Windows text (environment, command line) through the wide APIs, never the ANSI ones), `rptests` (Catch2; `tests/deps_test.cpp` checks each dependency links; HTTP tests run a cpp-httplib server on 127.0.0.1 through `tests/local_http_server.hpp`, never the network; a source scan over `src/`, `include/` and `app/` fails on any code that turns TLS verification off). ctest also runs `rpworker.exe` through `tests/run_exe_test.cmake`, which checks the exit code, stdout and stderr exactly (don't use `PASS_REGULAR_EXPRESSION` or `WILL_FAIL` for exe tests: they ignore the exit code).
```
cmake --preset dev && cmake --build --preset dev && ctest --preset dev
ctest --preset dev -R <test-name-regex>        # single test
build/dev/rpworker --version                   # prints project(VERSION)
RP_LIVE=1 ctest --preset dev                   # also run live tests against the Veeam VM / test tenant
```
Presets use Ninja + `cl`, so run CMake from a VS 2022 Developer PowerShell (or `Enter-VsDevShell`). The dev shell overwrites `VCPKG_ROOT` with VS's bundled vcpkg; set it back to the real clone (e.g. `C:\vcpkg`) after entering the shell. vcpkg is pinned by `builtin-baseline` in `worker/vcpkg.json`; CI checks out vcpkg at exactly that commit, so bump the baseline to upgrade ports. CI (`.github/workflows/worker.yml`) runs `cmake --preset ci` on windows-latest, then the `coverage` preset (Debug + PDBs) under OpenCppCoverage and `python tools/coverage_gate.py build/coverage/coverage.xml --min-line 80`. Local commands are in `docs/testing.md`.

Cloud (`cloud/`, uv, Python 3.12):
```
uv run pytest                                  # commit uv.lock with dependency changes
uv run pytest tests/test_x.py::test_name       # single test
uv run --locked pytest --cov=app --cov-branch --cov-report=term-missing --cov-report=json:coverage.json --cov-fail-under=80   # CI gate
uv run --locked python tools/check_coverage.py coverage.json                                                                 # CI: 100% on guarded paths
uv run mutmut run                              # once per sprint, WSL/Linux only (see docs/testing.md)
docker compose up                              # postgres:16, minio, api, scheduler
uv run python manage.py <command>              # Typer admin CLI: create-msp, create-client, create-worker-token, ...
```

Lab (`lab/`, uv, Python 3.12; the canary seeder, see `lab/README.md`):
```
cd lab; uv run pytest
uv run python -m seeder hash                   # offline: canary files and manifest hashes reproduce (L1.2 Done when)
uv run python -m seeder seed                   # live: seed the 40 canary items, write lab/seed-manifest.json
```

Milestone demo commands: `rpworker veeam list` (S1), `rpworker restore` (S2), `rpworker test` (S3), signed bundle in outbox (S4), pass row in DB (S5), PDF download (S6), green `rpworker doctor` (S7).

## Non-negotiable rules

- **Restore targets:** every restore goes to the `restoretest` mailbox or the `RestoreTest` library/OneDrive folder. `TargetGuard` must be checked per item, inside `RestoreSample`, before any Veeam call. Any code path that could target something else is a bug.
- **Status vocabulary:** `pass` = restore ran and 100% of items match; `fail` = restore failed or any item missing/mismatched; `error` = the test itself couldn't run (Veeam unreachable, Graph auth/permission error, guard violation). Infrastructure problems must never be reported as `fail`. The decision table lives in `docs/verification.md`.
- **Secrets:** only in the Worker DPAPI vault (`%ProgramData%\RestoreProof\vault.bin`) or gitignored `.env`. Until the vault lands (W4.5), the Worker reads them from `RP_*` environment variables (names in `worker/include/rp/secrets.hpp`), never from `config.json`, which rejects secret-looking keys. Never logged; HTTP logging redacts `Authorization`, `client_secret`, `password`, `refresh_token`, `access_token` through `rp::redact()`, and never logs headers or bodies. A sentinel-grep test (W4.9) enforces this.
- **TLS:** verification is never turned off. A self-signed Veeam certificate is trusted through the `veeam_ca_file` config key, never by skipping verification. A source-scan test fails the build if code that disables verification appears.
- **Cloud tenant isolation:** all DB access goes through repo classes in `cloud/app/repo/` that take `msp_id` first. `select(` outside `app/repo/` fails a lint test.
- **Signing contract (shared by C++ and Python):** canonical JSON = sorted keys, no whitespace, UTF-8, ISO-8601 UTC; `bundle_sha256` is computed with `signature` and `tsa_token` removed; Ed25519 over the hash. Schema is one file, `shared/schemas/result.v1.json`, used by both builds. (`shared/schemas/` also holds `seed-manifest.v1.json`, the canary manifest's schema, and `shared/testdata/` the test vectors W3.2's C++ checker must pass: `text-v1` for mail bodies and `office-v1` for docx/xlsx content, which SharePoint rewrites; see `lab/README.md`.) `shared/tools/verify_bundle.py` is the auditor-facing verifier and must agree with the C++ `Signer`.
- **API contract:** all Cloud routes under `/v1`; `docs/api/openapi-v1.json` is committed and diffed in CI.
- **Report wording:** never claim more than was tested. Phrases like "fully recoverable", "guarantee", "certified", "accepted by insurers" are banned by a test.
- Failed runs are never edited or re-signed.

## TDD workflow (enforced by CI)

- Test first: acceptance test from "Done when", then red → green → refactor per step; commit test and code together after each green.
- Anything talking to Veeam, Graph, the TSA or the Cloud is written against recorded fixtures first (`worker/tests/fixtures/<service>/`, recorded with `--record`, secrets scrubbed, served by `FakeHttpClient`). Live calls are gated behind `RP_LIVE=1`.
- Write failure-path tests before happy paths (missing item, hash mismatch, tampered signature, wrong target, unreachable service).
- Use parameterised tables (Catch2 `GENERATE`, `pytest.mark.parametrize`) for decision tables.
- Coverage floors: 80% line on `rpcore` and `cloud/app` (cloud gate is on the combined line+branch figure); 100% branch on vault, signer, target_guard, `app/auth`, `app/results.py`, `app/repo`. OpenCppCoverage has no branch data, so the Worker per-file floor is currently enforced as 100% line (`docs/decisions.md`). Any Worker file whose path has a part named or prefixed `vault`, `signer` or `target_guard` (e.g. `src/signer/ed25519.cpp`, `src/vault_dpapi.cpp`) is strict. Every `.cpp` under `worker/src/`, `worker/include/` and `worker/app/` must show up in the coverage report, so a file no test reaches fails; `app/` is measured through ctest's runs of `rpworker.exe`.
- A PR changing `worker/src/`, `worker/include/` or `worker/app/` without adding or changing C++ test code under `worker/tests/`, or changing `cloud/app/` without adding or changing a `.py` under `cloud/tests/`, fails CI ("No test, no merge"). Deleted tests, fixtures and `tests/e2e/` don't count.
- Every bug gets a reproducing test before its fix.
- End-to-end scenarios are tracked manually in `tests/e2e/scenarios.md`.

## Key docs (some still to be created)

`docs/decisions.md` (decision log, update on any new architectural choice), `docs/glossary.md`, `docs/verification.md`, `docs/api/veeam-feasibility.md` (admin vs operator Veeam auth mode; W1.0 must close before `VeeamClient` work), `docs/api/veeam-restore-flow.md`, `docs/security/graph-permissions.md`, `lab/tenant.md` and `lab/seed-manifest.json` (the 40 canary items: the expected set for verification). Already exist: `docs/decisions.md`, `docs/glossary.md`, `docs/testing.md`, `docs/environment.md`, `docs/worker-config.md` (Worker `config.json` keys, secret env vars, `rpworker config check`), `lab/tenant.md`, `lab/README.md` (the canary seeder, the `text-v1` mail body rule, the manifest fields) and `lab/canary/` (the 20 generated canary files). `lab/seed-manifest.json` is written by the live `seed` run and is not committed yet; until it is, the `lab` CI workflow only warns instead of running `python -m seeder hash` (`docs/decisions.md`).
