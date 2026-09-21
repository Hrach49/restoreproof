# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

Early Stage 1. The plan is `RestoreProof Stage 1 — Sprint Task Guide.docx`, which breaks a 16-week plan into tasks with IDs (e.g. `L0.1`, `W2.7`, `C5.7`). The CI skeleton (L0.1) exists: `worker/` builds a Catch2 smoke test, `cloud/` runs a pytest smoke test. Much of what follows describes the **planned** design from the guide; where code exists, trust the code over this file, and update this file.

Task ID prefixes: `L` lab/env (`lab/`, `docs/`), `W` Worker C++ (`worker/`), `C` Cloud Python (`cloud/`), `Q` quality (`tests/`, `docs/`), `S` sales (`sales/`), `P` pilots (`docs/pilots/`). Each task is one GitHub issue; its "Done when" line is the acceptance criterion.

## What the product does

RestoreProof proves that Microsoft 365 backups in Veeam Backup for Microsoft 365 actually restore. An on-prem **Worker** (C++, Windows service) samples items from a Veeam restore point, restores them through the Veeam REST API (v8) into dedicated test locations, reads them back through Microsoft Graph, compares them, cleans up, and uploads a signed, RFC 3161-timestamped result bundle. A **Cloud** backend (FastAPI) dispatches jobs, verifies and stores bundles, shows a dashboard, and generates monthly PDF reports for MSPs.

Worker pipeline (`rpworker test`): cleanup → pick restore point → sample select → target guard → restore → verify → cleanup → result JSON → sign → timestamp → outbox → upload.

## Planned commands

Worker (`worker/`, CMake + vcpkg, C++20, MSVC; deps: cpr, nlohmann-json, spdlog, openssl, catch2). Targets: `rpcore` (static lib holding all logic), `rpworker` (exe), `rptests` (Catch2).
```
cmake --preset dev && cmake --build --preset dev && ctest --preset dev
ctest --preset dev -R <test-name-regex>        # single test
RP_LIVE=1 ctest --preset dev                   # also run live tests against the Veeam VM / test tenant
```
Presets use Ninja + `cl`, so run CMake from a VS 2022 Developer PowerShell (or `Enter-VsDevShell`). The dev shell overwrites `VCPKG_ROOT` with VS's bundled vcpkg; set it back to the real clone (e.g. `C:\vcpkg`) after entering the shell. vcpkg is pinned by `builtin-baseline` in `worker/vcpkg.json`; CI checks out vcpkg at exactly that commit, so bump the baseline to upgrade ports. CI (`.github/workflows/worker.yml`) runs `cmake --preset ci` on windows-latest; OpenCppCoverage arrives in L0.5.

Cloud (`cloud/`, uv, Python 3.12):
```
uv run pytest                                  # CI runs `uv run --locked pytest`; commit uv.lock with dependency changes
uv run pytest tests/test_x.py::test_name       # single test
docker compose up                              # postgres:16, minio, api, scheduler
uv run python manage.py <command>              # Typer admin CLI: create-msp, create-client, create-worker-token, ...
```

Milestone demo commands: `rpworker veeam list` (S1), `rpworker restore` (S2), `rpworker test` (S3), signed bundle in outbox (S4), pass row in DB (S5), PDF download (S6), green `rpworker doctor` (S7).

## Non-negotiable rules

- **Restore targets:** every restore goes to the `restoretest` mailbox or the `RestoreTest` library/OneDrive folder. `TargetGuard` must be checked per item, inside `RestoreSample`, before any Veeam call. Any code path that could target something else is a bug.
- **Status vocabulary:** `pass` = restore ran and 100% of items match; `fail` = restore failed or any item missing/mismatched; `error` = the test itself couldn't run (Veeam unreachable, Graph auth/permission error, guard violation). Infrastructure problems must never be reported as `fail`. The decision table lives in `docs/verification.md`.
- **Secrets:** only in the Worker DPAPI vault (`%ProgramData%\RestoreProof\vault.bin`) or gitignored `.env`. Never logged; HTTP logging redacts `Authorization`, `client_secret`, `password`. A sentinel-grep test (W4.9) enforces this.
- **Cloud tenant isolation:** all DB access goes through repo classes in `cloud/app/repo/` that take `msp_id` first. `select(` outside `app/repo/` fails a lint test.
- **Signing contract (shared by C++ and Python):** canonical JSON = sorted keys, no whitespace, UTF-8, ISO-8601 UTC; `bundle_sha256` is computed with `signature` and `tsa_token` removed; Ed25519 over the hash. Schema is one file, `shared/schemas/result.v1.json`, used by both builds. `shared/tools/verify_bundle.py` is the auditor-facing verifier and must agree with the C++ `Signer`.
- **API contract:** all Cloud routes under `/v1`; `docs/api/openapi-v1.json` is committed and diffed in CI.
- **Report wording:** never claim more than was tested. Phrases like "fully recoverable", "guarantee", "certified", "accepted by insurers" are banned by a test.
- Failed runs are never edited or re-signed.

## TDD workflow (enforced by CI)

- Test first: acceptance test from "Done when", then red → green → refactor per step; commit test and code together after each green.
- Anything talking to Veeam, Graph, the TSA or the Cloud is written against recorded fixtures first (`worker/tests/fixtures/<service>/`, recorded with `--record`, secrets scrubbed, served by `FakeHttpClient`). Live calls are gated behind `RP_LIVE=1`.
- Write failure-path tests before happy paths (missing item, hash mismatch, tampered signature, wrong target, unreachable service).
- Use parameterised tables (Catch2 `GENERATE`, `pytest.mark.parametrize`) for decision tables.
- Coverage floors: 80% line on `rpcore` and `cloud/app`; 100% branch on vault, signer, target_guard, `app/auth`, `app/results.py`, `app/repo`.
- A PR changing `worker/src/` or `cloud/app/` without changes under a tests directory fails CI ("No test, no merge").
- Every bug gets a reproducing test before its fix.
- End-to-end scenarios are tracked manually in `tests/e2e/scenarios.md`.

## Key docs (to be created)

`docs/decisions.md` (decision log, update on any new architectural choice), `docs/glossary.md`, `docs/verification.md`, `docs/api/veeam-feasibility.md` (admin vs operator Veeam auth mode; W1.0 must close before `VeeamClient` work), `docs/api/veeam-restore-flow.md`, `docs/security/graph-permissions.md`, `lab/tenant.md` and `lab/seed-manifest.json` (the 40 canary items: the expected set for verification).
