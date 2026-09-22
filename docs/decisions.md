# Decision log

One entry per architectural choice. Newest first. Add an entry whenever a new choice is
made; never rewrite an old one — supersede it with a new entry that links back.

Format: date, decision, reason, alternatives rejected.

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
