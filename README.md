# RestoreProof

Proves that Microsoft 365 backups in Veeam Backup for Microsoft 365 actually restore.

An on-prem **Worker** (C++, Windows service) samples items from a Veeam restore point,
restores them through the Veeam REST API into dedicated test locations, reads them back
through Microsoft Graph, compares them, cleans up, and uploads a signed, RFC 3161-timestamped
evidence bundle. A **Cloud** backend (FastAPI) dispatches jobs, verifies and stores bundles,
shows a dashboard, and generates monthly PDF reports for MSPs.

Status: Stage 1, Sprint 1. See `CLAUDE.md` for the working agreements.

## Layout

| Path | What |
|---|---|
| `worker/` | C++20 Worker: `rpcore` (logic), `rpworker` (exe), `rptests` (Catch2) |
| `cloud/` | FastAPI backend, dashboard and reports (Python 3.12, uv) |
| `shared/schemas/` | `result.v1.json` — the one bundle schema, used by both builds; `seed-manifest.v1.json` — the canary manifest's schema |
| `lab/` | Test tenant notes, the canary seeder (`python -m seeder`, a uv project) and the canary seed manifest |
| `docs/` | Decisions, glossary, API and security notes |
| `tests/e2e/` | Manually tracked end-to-end scenarios |
| `sales/` | Pricing, pitch and pilot material |

## Docs

- [Decision log](docs/decisions.md) — every architectural choice, why, and what was rejected.
- [Glossary](docs/glossary.md) — restore point, canary item, verification levels, pass /
  fail / error, evidence bundle, tokens, signing key.
- [Environment](docs/environment.md) — the dev toolchain and its versions.
- [Worker configuration](docs/worker-config.md) — `config.json` settings, secrets from
  environment variables, and `rpworker config check`.
- [Lab tools](lab/README.md) — the 40 canary items, the seeder app registration, and how to
  seed and check them.
- [Testing](docs/testing.md) — test rules, the CI coverage and "No test, no merge" gates, and
  the once-per-sprint mutation run.

## Build

Worker (from a VS 2022 Developer PowerShell, with `VCPKG_ROOT` pointing at your vcpkg clone):

```powershell
cd worker
cmake --preset dev && cmake --build --preset dev && ctest --preset dev
```

Cloud:

```bash
cd cloud
uv run pytest
```
