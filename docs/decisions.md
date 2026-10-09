# Decision log

One entry per architectural choice. Newest first. Add an entry whenever a new choice is
made; never rewrite an old one — supersede it with a new entry that links back.

Format: date, decision, reason, alternatives rejected.

---

## 2026-10-10 — Q4.1 (#53) closed: the four signing and schema steps are covered by tests that exist; a re-ordered `result.json` is refused, not verified (W4.3); green locally, not in CI

Q4.1 asks for four unit tests. Each was written with the task that built the thing (W4.1, W4.3, W4.5), so nothing was built here: the tests were found, run and listed. Worker paths are under `worker/`.

1. **A tampered bundle (a changed item hash) fails verify.** The shared vectors `shared/testdata/signing-v1/cases.json`: `result-expected-item-hash-one-digit` (one digit of `expected.items[0].sha256` changed, the file still canonical and valid: `hash_mismatch`), `result-check-item-one-digit` (`hash_mismatch`), `forgery-result-changed-hash-computed-again` (the result changed and `bundle_sha256` computed again under the old signature: `signature_invalid`), `signature-one-bit-changed` (`signature_invalid`) and `attachment-one-byte-changed` (`attachment_hash`). Run by `tests/signer_test.cpp` "the folder verifier answers every shared case with its word", by `tests/signer_command_test.cpp` "signer verify answers every shared case with its line and exit code" (`not verified: <word>`, exit 5) and by `cloud/tests/test_verify_bundle.py` `test_each_failing_case_gets_its_word`. Beside the vectors: `tests/signer_test.cpp` "after the signature file: the hash, then the key, then the signature" and "each listed attachment: there, its size, its hash, in the result's order".
2. **Re-ordered keys in `result.json`: superseded by W4.3.** The guide says a re-ordered file still verifies. W4.3 (2026-10-05, point 2) decided the opposite: `bundle_sha256` is the SHA-256 of the file's own bytes, and a `result.json` that isn't its own `canonical-json-v1` form is refused as `result_not_canonical`, so the two JSON parsers can never differ on what was signed. The tests hold that: the vector `result-keys-reordered` expects `result_not_canonical`, in the three tests of step 1; `tests/signer_test.cpp` "the result's own checks come before the signature's, whatever the signature says" holds the same word for a file with a trailing newline, the signature not even asked. What is left of the guide's intent is tested too: the order in which a document is built doesn't change what is signed (`tests/signer_test.cpp` "a document built in two key orders has one canonical text and one hash", `cloud/tests/test_canonical_json.py` `test_two_key_orders_one_canonical_text`, and the `key-order` cases of `shared/testdata/canonical-json-v1.json`). Q4.1's second step is read as "a re-ordered file is refused"; the issue's wording is not met and is not meant to be.
3. **The schema rejects an unknown status.** `shared/testdata/result-v1/cases.json`: `status-passed` (`status.status` `passed`), `status-unknown-error-code` (`error_code` `teapot`) and `restore-unknown-status` (`restore.status` `Success`), all `valid: false`, run by `tests/result_schema_test.cpp` "the shared result documents validate as they say" and by `cloud/tests/test_result_schema.py` `test_each_case_validates_as_it_says`. Also `tests/result_schema_test.cpp` "a validator that can't be loaded checks nothing, and says so" (`status.status` `maybe` is invalid) and "the result schema's enums are the code's words", and through the verifiers the signing vector `result-unknown-status` (`result_schema`).
4. **DPAPI round trip.** `tests/vault_test.cpp` "a vault round-trips the five secrets through DPAPI" (written by `write_vault`, read back by `read_vault`, nothing of a value in the file's bytes), with "a value outside the ANSI code page round-trips as UTF-8". The Worker builds on Windows only, so there is no non-Windows runner to skip it on.

The runs, on `main` at 5794beb, 2026-10-10, on the dev laptop:

- `ctest --preset dev -R "signer|result_schema|vault|canonical"`: 139 of 139 passed, none skipped. The regex matches test names, and several of the tests above have none of its words in their names, so the same build was also run by tag: `rptests "[signer],[signer_command],[result_schema],[vault],[canonical_json]"`, 146 test cases, 7817 assertions, all passed.
- `uv run pytest tests/test_verify_bundle.py tests/test_result_schema.py tests/test_canonical_json.py` in `cloud/`: 639 passed.

**"Green in CI" is not shown.** The Done-when says all four are green in CI. No Worker CI run has started since 2026-10-03 (GitHub billing, W4.1 build notes point 16), so the Worker's half is shown by the local runs above alone. When the workflows run again, the first green `worker` run is the Done-when's own evidence; nothing in this entry stands in for it.

---

## 2026-10-10 — W4.11 code review: findings 1 to 7 of nine fixed, 8 and 9 open

The review of the branch `w4.11-client-check` gave nine findings. 1 to 7 are fixed, each with its test; 8 and 9 stay open.

1. **A stop is asked for again right before the clean before.** The client check stands between W4.8's stop check and the Cleaner, and its Graph reads can wait minutes. `run_pipeline` now asks once more after the `client ok` line: `error interrupted`, nothing cleaned. Test: the stop table of `tests/restore_command_test.cpp` has the row "the clean before" (a stop that came during the check).
2. **A run's record naming a connector this Worker lacks is no record.** `ServiceLoop::find_record` treats it as one that doesn't parse: moved aside as `running.json.unread` with that line, nothing ended, closed or cleaned on its word, as before W4.11, when the reader refused such a name. A `connector_unknown` record names such a type on purpose and is unchanged. Rejected: holding with one log line, since nothing would ever end the hold.
3. **The connector's refusal of a spec that isn't its profile's is a `SafetyViolation`.** It was `std::invalid_argument`, which `stop_reason` reads as `internal` with a restore that may have started. Now `target guard: the restore spec isn't the connector's client's; nothing was restored` through `rp::refusal` (one `SECURITY:` line): `error target_guard`, exit 4, nothing restored, no hold.
4. **`parse_record` holds a `connector_unknown` record's `connector.type` to its `close_detail`.** A record with another type, or no connector, is no record, so `close_run` can't sign `connector.type: veeam_m365` beside `error connector_unknown`.
5. **`ServiceLoopEnv::connector_names` became the required function `has_connector`.** An empty list read as "no connectors" and turned every job into a signed `connector_unknown` with its `done` mark. An env without the function now fails the step (`scheduler: a step failed unexpectedly; the loop goes on`): no record, no mark, no result.
6. **The schema holds `client.scope` and `client.resolved` to each other.** `result.v1.json`'s `client` has a `oneOf`: both null, or `scope` `same_tenant` beside a `resolved` that isn't null. `result-v1/cases.json` has 201 patches, 52 valid (the two one-sided cases now invalid, both null a new valid one). No verifier word was added; both verifiers refuse such a result as `result_schema`. Open: nothing holds `resolved.organization.tenant_id` to `client.tenant_id`, which a schema can't say; C5.7 should compare them.
7. **The live harnesses' `finally`.** In `w410-live.ps1` and `w411-live.ps1` step (c), the uninstall runs whatever the revoke does, and a run that failed writes `...-service-run.failed.txt` and never replaces the committed evidence. Parsed, not run live.

Open: 8 (the three targets are resolved by the client check and again by the Cleaner, the before snapshot and layer 1; handing them on changes the Cleaner's interface) and 9 (`shown_word` in `client_check.cpp` beside `one_line` in `src/text_util.hpp`).

---

## 2026-10-09 — W4.11 build notes: the client check built as the entry says, the organisation kept by the connector, the vectors rewritten, two tests moved by the step; the runs; the live Done-when waiting for the owner's go-ahead (proposed)

W4.11 (#134) was built as the entry below says, test-first, on the branch `w4.11-client-check` (nothing committed until the owner asks). This records where the build left the entry, what it settled beyond it, the runs, and what is open. `docs/verification.md` ("The client check (W4.11)", the two codes' rows), `docs/worker-config.md` ("`rpworker restore`" the client check, "The jobs file" `connector` and J3b, "`running.json`"), `docs/testing.md`, `docs/glossary.md` and `tests/e2e/scenarios.md` (scenario 8) say the rest.

**Where the build left the entry.**

1. **The step (point 1): as written**, `check_client_step` in `src/run_pipeline.cpp`, between the run line's record and the clean before, with one thing the entry didn't say: the run's Graph client (`make_graph_and_cleaner`) is now made before the step instead of after it, since the step's three identity checks run on it; the clean before, the snapshot and the check use the same client as before. A `WrongTargetError` in the step is logged as one critical `SECURITY: client check: <what()>` line through `rp::log_security`, as the Cleaner's and layer 1's refusals are (the entry had no line for it; the "Restore targets" rule wants one). The stderr prefix is `client error: `; `; nothing was restored` is added only when the message doesn't already end with it (the guard's wording does).
2. **The facts (point 2): as written**, `IConnector::client_facts`, `connector::ClientFacts`, `rp::Organization::type`. The Veeam connector keeps the organisation `list_restore_points` found (`found_`, by client reference, ASCII case-insensitive) and answers the facts from it, so a run asks Veeam for the organisation list once, as before, and the W3.4 recording replays route by route; a `client_facts` without a listing before it lists.
3. **The rule (point 3): as written**, `rp/client_check.hpp` / `src/client_check.cpp`, strict (`client_check` in `STRICT_NAMES` and `BRANCH_NOTE`, with the gate's own tests). The product's words in a text are printable ASCII only, cut to 64 bytes, `none` when empty.
4. **The codes (point 4): as written**, `kCodes` of twenty-two; `interrupt_replaces` leaves both alone. `connector_unknown` as a stop's code is reachable by no test through the pipeline (the registry refuses before the run line), so its stop text is held by `run_status_test.cpp`'s E4 and N10 alone.
5. **The job's `connector` (point 5): as written.** The W4.8 harness's `New-W48Job` writes `connector = @{ type = 'veeam_m365' }`, and the two jobs-file examples in the docs carry the key. The shared case `connector-type-fake` of `result-v1/cases.json` became `connector-type-other` (valid); the tests that made a result invalid through an unregistered connector name (`fake`, `other`, `not_a_connector_the_schema_knows`) now use a name the rule refuses (`Fake Connector`, `Other Backup`, `Not A Connector The Schema Takes`).
6. **J3b (point 6): as written**, `ServiceLoopEnv::connector_names` and `hold_connector_type` (a function the loop calls before each look with the record's `connector.type`, else `veeam_m365`; the body drops a hold connector of another type), `CloseAs::connector_unknown`, `new_connector_unknown_record`. The heartbeat's `last_error` stays `job_invalid` for it.
7. **The result (point 7): as written**, `ResultClient::resolved` (`rp::ResolvedClient`, one field: `scope` is `same_tenant` exactly when it is set), the schema's two required keys, `connector.type` by the name rule. The four shared documents were rewritten in the entry's order: `result-v1/valid.json`, `signing-v1/bundle.json` and `cases.json` (the bundle's `bundle_sha256` is now `d89376890c804d4e4040e4dd51fc43520a29ce4659700cf7b10b4e36ef27df8b`; `tests/signer_command_test.cpp` pins it), `timestamp-v1/cases.json` with `keys.json` (the writer makes a new test TSA each time, so the scan's allowlist names the new key), `signing-v1/closed-folder.json`. `result-v1/cases.json` has 200 patches, 53 valid; `jobs-v1/cases.json` 84, 18 valid, 3 `code_refuses`; both sides pin the counts. `test_command_test.cpp`'s shared-names table gained the site and OneDrive URLs, the Inbox's ID and the list's, so `valid.json` names nothing of the lab tenant.
8. **Finding 8 (point 8): as written**, `VeeamM365ConnectorOptions::profile`, set by the factory from `ConnectorOptions::client`; `RestoreTargets` gained `operator==` for the comparison.
9. **Findings 6, 7, 11 (points 9 to 11): as written.** The W4.10 harness script has `$LabProfile` and its service step a `try`/`finally`.
10. **Secrets (point 12): as written**, the audit's cases L and J8. Case E (Graph refusing the token) now sees the refusal in the client check, so its stderr line is `client error: ` and not `check error: `; case G's connector name is one the rule refuses.

**Where the step moved what a test saw.** The identity checks now run before the clean before, so every test that served a wrong target to make the *clean* refuse serves the recorded answer first (the check passes) and the wrong one second (`FakeHttpClient`'s list of answers): `restore: a clean before the guard refuses` (which also lost its old premise: with one wrong answer it is now the client check that refuses, `restore: the client check: a target that doesn't resolve ...`), the step timings' case of the same name, the per-ending `--json` case of the same name (and a new case, `the client check's guard refuses`, with `cleanup` null), and `restore: a failure reading the targets before the restore` (three answers: the check's, the clean's, the snapshot's). The RealRig's `a wrong target is refused` is now the client check's refusal with nothing cleaned. The manifest-of-another-tenant row of `a manifest that doesn't load or isn't the tenant's` moved to `the client check: a manifest of another tenant`, after the run line. The replay tests count the three identity GETs the recordings predate (`graph_files + ... + 3`, and three routes `sent 6, recorded 5` in the W3.4 replay). Every test that spells out a run's first lines has `client_ok_line()` after the run line (`expected_intro()` carries it).

**The runs** (2026-10-09, this branch): `ctest --preset dev` 2183 of 2186 passed, the three failures none of W4.11's (the pre-existing `[owner]` test, the exe test that needs a console in code page 65001, and `fixture secret scan` on the regenerated test TSA key, fixed in the allowlist, after which the scan reads 1157 files in 7 trees, 12 allowed matches, 0 findings); `rptests.exe` in one process under OpenCppCoverage 2082 of 2093 passed, 11 skipped (the live tests), 124,463 assertions; the exe tests 93 of 94 (the code-page one); the coverage gate passed at 96.7% line (15,362 of 15,888), every strict file at 100% (`client_check.cpp` 31 of 31, `run_status.cpp` 454 of 454, `service_jobs.cpp` 185 of 185, `service_loop.cpp` 464 of 464, `service_recovery.cpp` 443 of 443, `client_profile.cpp` 118 of 118), `run_pipeline.cpp` 851 of 901, `veeam_m365_connector.cpp` 754 of 800, `worker_body.cpp` 353 of 367; Cloud's pytest 947 passed; the lab's 980 passed, 1 skipped; the gate's own tests and the scan's passed.

**The live Done-when** (2026-10-09, the lab machine, elevated, the real vault, commit 01b88dd plus this branch's working tree; `docs/api/veeam-lab/w4.11-harness/w411-live.ps1` over the W4.8 and W4.10 harnesses, the config copy without client keys and the profile files under `%LOCALAPPDATA%\RestoreProof\lab\`, outside the repository; evidence `docs/api/veeam-lab/w4.11-1` to `w4.11-4`):
- (a) `w4.11-1-client-mismatch.txt`: `rpworker test --mail 2 --sp 1 --od 1 --run-id w411-1 --config config-no-client.json --profile-file lab-profile-other-tenant.json --evidence --outbox` (the lab's profile with `graph_tenant_id` `11111111-2222-3333-4444-555555555555`): the run line, then `client error: client mismatch: the backup's organisation's tenant ID isn't the profile's graph_tenant_id; nothing was restored` on stderr, `status error client_mismatch: the run stopped before the restore: the backup's organisation doesn't match the client's profile (client_mismatch); nothing was restored`, `cleanup after skipped: nothing was restored`, every span but `restore_point_lookup` and `total` `not run`, exit 4; `signed`, `timestamped 2026-10-09T20:19:28Z` by DigiCert, `queued`; no session of `rp-veeam` Working before or after; both verifiers `verified`; the result's `scope` and `resolved` `null`.
- (b) `w4.11-2-client-ok.txt`: the same on `lab-profile.json`, run `w411-2`: `client ok: tenant bcd6bd1a-ea42-489d-aa28-2c19a44ad146, Office365, Worldwide; mailbox, library and folder resolved`, `cleanup before ok`, 4 of 4 restored and `status pass: 4 of 4 item(s) verified: manifest 3, fields 1, metadata 0`, cleaned after, signed, `timestamped 2026-10-09T20:25:37Z`, queued, both verifiers `verified`; the result's `scope` `same_tenant` and `resolved` the lab's organisation (`Office365`, `Worldwide`, the tenant ID), the Inbox's ID, the library's list ID and `https://restoreprooflab.sharepoint.com/sites/RestoreTest`, and the OneDrive folder's site URL. (A first attempt of (b) ended the same way, `pass` and queued; the harness threw after it in its own evidence helper, on a pass result having no `error_code` under strict mode; the helper was fixed, the queued folder set aside as `w411\w411-2-first-attempt`, and (b) run again.)
- (c) `w4.11-3-service-run.txt`: the service installed on the config copy without client keys, started, three jobs in one stub file: `w411-3` of connector type `other_backup` (`warning job w411-3: connector type other_backup isn't one this Worker has`, `run w411-3: queued`, `sent w411-3`, its result `error connector_unknown` with `connector` `{"type": "other_backup", "api": ""}`), `w411-4` on the other-tenant profile (`client error: client mismatch: ...` in the log, `run w411-4: ended error client_mismatch; queued`, `sent w411-4`), `w411-5` on the lab's (`run w411-5: ended pass; queued`, `sent w411-5`, 3 of 3 verified), then `skipped w411-3|4|5: already sent`; all three sent folders `verified` by both verifiers and timestamped; no session Working; the grants taken away, the service uninstalled.
- (d) `w4.11-4-teardown.txt`: nothing installed, `runs\` holding only the earlier tasks' hand-made folders, no session Working, `graph list` 0 in all three targets; the sent folders kept under `%ProgramData%\RestoreProof\w411`.

**Open.**
- The entry's Open list stands: W5.1 (the manifest with the job, `GET /v1/jobs` with `connector`), C5.6/C5.7/C5.13 (the mismatch's reason beside the code), finding 8's struct split, findings 12 to 14, a `client check` by hand against Veeam, the mail `permanentDelete` rule for another cloud.
- One failure in every local run is the pre-existing `[owner]` test `worker body: a run folder that can't be listed is not closed` (`owner_lab.hpp`'s `give_to` answering 2), which the W4.9 build notes record as the pre-existing `set_dacl` failure on this machine; it is not W4.11's.
- A run of the `[restore_command]` group in one `rptests` process with every other group hung once during the build, before the step's tests were settled; under ctest (one process per test) and in the full one-process run below nothing hangs. Not reproduced since; noted in case it is a test-order dependence.
- No Worker CI run has started since 2026-10-03 (GitHub billing).

---

## 2026-10-09 — W4.11 (#134): the per-job client check before any restore. Once the run line is out and before anything is cleaned, sampled or restored, the Worker holds the job's client to facts Veeam and Graph report: the organisation named by `veeam_org_name` is an `Office365` organisation of the `Worldwide` region whose `msid` is the profile's `graph_tenant_id` (`client_mismatch`), the manifest is that tenant's, and the three restore targets resolve in that tenant; a job names its connector type and one this Worker lacks is reported as `connector_unknown`; the signed result then says `scope: "same_tenant"` and what the targets resolved to (recorded before the build)

W4.11 (#134) is the second half of the 2026-09-29 entry "Clients live in the Cloud" (its point 4); W4.10 (#133, PR #167, merged as 01b88dd) was the first. Done when: "A fixture test where the job's `graph_tenant_id` differs from the organisation's `msid` ends as `error` / `client_mismatch` and the fake HTTP client records no restore POST." This entry works from issue #134 (no comments; #133 has none either), the 2026-09-29 entry, the W4.10 entry with its build notes and its code review (findings 5 to 8 and 12 to 15 open), the W4.8 entry (points 3 to 7, 9 and 14 and its Open list), the W3.3 and W4.1 entries, `docs/verification.md`, `docs/worker-config.md`, the code and the Veeam fixtures. The issue was written before W4.8 to W4.10; where it and the code disagree, the code wins, and each such place is named below. No code is written yet; the build notes will record what the build finds. Out of scope and not built here: `GET /v1/jobs`, the API token, a job that ends before its run line and whether `jobs_file` stays (W5.1); the Cloud's side, a tenant unique per MSP, the 409 for a bundle of another client (C5.2, C5.6, C5.7, C5.13); the installer's grants and ACLs (W7.1); doctor (W7.2); a second Veeam server or tenant per Worker and a restore into another tenant (Stage 2).

**What the investigation found, since the points below rest on it.**

- **The job carries no connector type, and `veeam_m365` is hard-wired in three places**: `run_pipeline` makes the run's connector by `connector::kVeeamM365` (`src/run_pipeline.cpp`, before the restore points are listed), `worker_body.cpp` makes the hold's connector the same way, and the record's reader refuses a `connector.type` that isn't that name (`src/service_recovery.cpp`). `ConnectorRegistry` exists with one name and `UnknownConnectorError`, which `stop_reason` maps to `config`. The result's `connector.type` is an `enum` of one word in `result.v1.json`, and the shared case `connector-type-fake` is invalid today.
- **Veeam reports what the check needs, and the client parses most of it.** `GET /v8/Organizations` answers `type` (`Office365`), `region` (`Worldwide`), `msid` (the Entra tenant ID), `name` and `officeName` (`docs/api/veeam-notes.md` §2, the fixture `organizations-200.json`, whose one organisation is the lab's, `msid` `bcd6bd1a-…`). `rp::Organization` holds `msid`, `region` and `office_name` but **not `type`**: the issue's "`VeeamClient` already parses `msid`, `region`, `office_name`" is right as far as it goes, and `type` must be added. The connector's `restore_sample` already refuses an organisation without a region, with different apps for Exchange and SharePoint, or with odd settings (`RestoreRun::organization()`), and `find_organization` matches `veeam_org_name` against `name` ASCII case-insensitively and refuses two matches. Nothing compares `msid` with anything, and the organisation found by `list_restore_points` is dropped once the points are listed: the pipeline never sees it.
- **The Graph token is already the job's tenant's (W4.10).** The guard's Graph client signs in with `ConnectorOptions::client`'s `graph_tenant_id` and `graph_client_id` (`make_veeam_m365_connector`'s `make_graph`), and the run's own client for the clean and the check with the profile's through `make_graph_and_cleaner`; `rpworker client check`'s with the file's. The only Graph client made from `config.json`'s keys is `graph list`'s, the local profile, and the service never reads it. The issue's fourth step is therefore done and only confirmed here.
- **The identity checks exist and run twice already, after the run line.** `check_restore_mailbox`, `check_restore_library` and `check_restore_onedrive_folder` (`rp/target_guard_graph.hpp`) are what `TargetReader` runs before it lists a file target, what the Cleaner's `resolve` runs at the start of the clean before, and what the guard's layer 1 runs inside `restore_sample`. Each answers the resolved facts (`ResolvedLibrary` with `name`, `list_id`, `site_url`, `ResolvedOneDriveFolder` with `name`, `site_url`, `ResolvedMailbox` with `inbox_id`), and the pipeline keeps none of them. In the clean before only a `WrongTargetError` stops the run (`error target_guard`); any other Graph failure "lets the run go on" to the before snapshot, which stops it then. So today the first failure of a target to resolve is found inside the clean, after the run has started deleting in the other targets.
- **A result for a run with no connector can't come from the pipeline.** The run line needs a restore point, which needs a connector. A job whose connector type this Worker lacks can only be reported the way J3 reports a job that is no job: a record, a folder made and closed by `close_run`, a result written afterwards (W4.8 point 7), signed and queued. The close's result takes `connector` from the record, `{"type": "veeam_m365", "api": ""}` when the record has none.
- **The canary manifest is one file and is held to the profile's tenant before the run line.** `sampling::check_manifest(manifest, targets, graph_tenant_id)` throws `ManifestError` (`canary manifest: /tenant_id: isn't the client's tenant (graph_tenant_id)`) before the mutex, the connector and any Veeam call, so a job for a tenant whose manifest the Worker doesn't have ends `config error`, exit 1, with no run line, no folder and no result, and the stub file offers it again at every poll (the W4.10 review's finding 5).
- **Adding a key to the result rewrites four shared vectors in a fixed order.** `tests/test_command_test.cpp` holds `shared/testdata/result-v1/valid.json` to the whole pipeline's run; `signing-v1/bundle.json` is that file with its `attachments` replaced, signed, and a Worker test holds it to what the code makes byte for byte; `timestamp-v1/cases.json` is 23 cases over that signed folder with the twelve `one_bit_changes` offsets of a token over its digest; `signing-v1/closed-folder.json` is a closed folder of the body's own run. Each has a hidden writer (`[.write_shared_result]`, `[.write_shared_signing]`, `[.write_shared_timestamp]`, `[.write_shared_closed]`), and the Cloud's tests read the files. So whatever the schema says, a Worker that writes two new keys into `client` rewrites all four; the schema's choice between required and optional keys decides only what an older result is worth under the new schema.
- **`timings.spans` has eleven required keys** and `attachments`' names are fixed words. A twelfth span would make every result signed so far invalid for nothing: the check is three GETs and one organisation list.
- **The jobs reader's fault order is `client_id`, `client`, `sample_mail`, …, `unknown key`** (`src/service_jobs.cpp`, `fault_of`); `is_job_key` takes a `.`; the loop's env has no view of the registry. `ServiceLoopEnv` is a struct of functions and values the body fills (`make_worker_loop_env`), so a list of connector names joins it as one more member.
- **`interrupt_replaces` turns an `error` decided after a stop into `interrupted`** unless its code is `interrupted`, `target_guard` or `result_invalid`: a fact about the client, found while a stop was pending, must stay what it is as a guard refusal does.
- **The secret audit's cases** are A to K and J1 to J7 (`tests/secret_audit_test.cpp`); a new path joins by one case. A profile holds no secret value (W4.10 point 10) and neither do Veeam's `type`, `region` and `msid` or a resolved name or URL; the fixture scan already walks `shared/testdata`.

**Decision.**

1. **One new step of the run, the client check, between the run line and the clean before.** In `run_pipeline`, for `restore` and `test` alike (a job's, a file's or the config's profile), right after `on_run_started` and its stop check, before the Graph client for the clean is used for anything and before `cleanup_before` starts, in this order, the first failure ending the run through `finish` as a `before_restore` stop with its code, `nothing was restored`, no clean, no explore session, nothing deleted, `cleanup` `null`:
   - (a) **The organisation against the profile** (`client_mismatch`): the connector is asked for the client's facts (point 2), and the pure rule of point 3 holds them to the profile: `type` is `Office365`, `msid` is `graph_tenant_id` (ASCII case-insensitive, as the GUID rules compare), `region` is `Worldwide`, checked in that order, the 2026-09-29 entry's. A failure is `rp::ClientMismatchError`, which `stop_reason` maps to `client_mismatch`.
   - (b) **The manifest against the profile** (`config`): `check_manifest`'s tenant comparison moves here from before the run line (the W4.10 review's finding 5, below); the manifest is still loaded, and held to "no canary in a restore target" and the cursor's bounds, before the run line as today, since those need no run to be reported and the cursor's fault is a usage error. A `ManifestError` here is a `config` stop as everywhere.
   - (c) **The targets in the tenant** (the Graph codes): `check_restore_mailbox`, `check_restore_library` and `check_restore_onedrive_folder` on the run's own Graph client, which signed in as the profile's tenant and app, with the wording `restores only into …; nothing was restored`; a `WrongTargetError` is `target_guard`, any other Graph error its code by `read_error_code` (`graph_auth`, `graph_permission`, `graph_transient`, `graph`), as a Graph failure of the before snapshot is today. What they resolve is kept for the result (point 6). The issue's "as a step of the run with its own code" is read as the step's own place in the run: the three failures have their codes already, and no code is added for them.
   - Then the clean before, `choose_sample`, the before snapshot, `restore_sample` with the guard's layer 1 per item and layer 2 per request (W2.7), unchanged. So the guard still resolves every target per item, and the clean before still resolves each target before it deletes: the step adds one organisation list and three GETs per run and makes every failure of a target to resolve a stop before any delete, where today a non-guard Graph failure in the clean is found by the snapshot after the other targets were emptied.
   - **What a failure costs.** The run line is out, so the folder exists, the record has its (b) write, and `finish` builds the result (`error`, the code, `started_at` set, `restore_sent` false, `sample`, `expected`, `restore`, `check`, `cleanup` and every span but `total` and `restore_point_lookup` `null`, `scope` and `resolved` `null`), validates it, signs it, asks the TSA (so with the TSA down the run ends about 90 s later, as any run), writes the folder and queues it; the service flushes it and the Cloud learns the code under the job's own run ID, and J2 skips the job from then on. At a prompt the exit code is the code's: `client_mismatch` 4, `config` 1, the Graph codes 2, 3 or 4. The stderr line is `client error: <the exception's text>` (`client mismatch: the backup's organisation isn't of type Office365 (<type>)`, `… 's tenant ID isn't the profile's graph_tenant_id`, `… reports no tenant ID`, `… 's region isn't Worldwide (<region>)`, with `<type>` and `<region>` Veeam's words cut to 64 printable ASCII characters and never a tenant ID; the manifest's text; Graph's text through `redact()`), then the status line. On success one stdout line after the run line, `client ok: tenant <tenant ID>, Office365, Worldwide; mailbox, library and folder resolved`, before `cleanup before …`.
   - A stop asked during the step ends it as a stop ends any call (the sleep is the service's, the connector's `stop_requested` its own); a `client_mismatch` decided while a stop was pending stays what it is: `interrupt_replaces` excludes it as it excludes `target_guard`.
   - *Rejected:* the check before the run line, "before the first Veeam call" as the W4.10 entry's Open point says it (then a mismatched job has no run line, no folder and no result, and the stub offers it again at every poll: the finding 5 pattern, and the Done-when needs a status); inside `restore_sample` as a fourth layer of the guard (then the clean before and the sample run for a client that isn't the organisation's); a twelfth timing span (the schema's eleven are required, and the step is four reads); a `client check` by hand against Veeam (`rpworker client check` reads no config and no Veeam secret, W4.10 point 6; the check by hand is `rpworker test --profile-file`, which reports it under a run ID, and doctor's is W7.2; listed under Open as an option).

2. **The connector reports the client's facts: `IConnector::client_facts(client_ref)`.** A new neutral member of `rp/connector.hpp`, `connector::ClientFacts client_facts(const std::string& client_ref)`, `ClientFacts{name, tenant_id, organization_type, region}`, each the backup product's own text or empty when it sent none; the default throws `NotImplementedError` as `own_sessions`' does, the Harness's fake answers what the test set (facts matching its profile by default). `VeeamM365Connector::client_facts` is `find_organization` (one `GET /v8/Organizations`, the errors mapped as `list_restore_points` maps them: a client Veeam doesn't know is `not_in_backup`, as it is there) and the organisation's `name`, `msid`, `type` and `region`; `rp::Organization` gains `type`. `connector.hpp` gains no Veeam name (the scan). The build may keep the organisation `list_restore_points` found instead of listing again; the entry doesn't require it.
   - *Rejected:* the check inside the connector (`check_client(profile)` throwing): the rule is the 2026-09-29 entry's and belongs with the status table's vocabulary, not with one product's client, and a pure rule gets its `GENERATE` table; returning the facts from `list_restore_points` (a second meaning for one call, and thirty fakes to change).

3. **The rule is pure and strict: `rp::check_client` in `rp/client_check.hpp` / `src/client_check.cpp`.** `std::optional<ClientMismatch> check_client(const ClientProfile&, const connector::ClientFacts&)`, `ClientMismatch{reason}` with `reason` one of `organization_type`, `tenant_id_missing`, `tenant_id`, `region` (first fit, in that order), the constants `kClientOrganizationType` = `Office365` and `kClientRegion` = `Worldwide`, `to_string(reason)`, and `rp::ClientMismatchError` (a `std::runtime_error` carrying the reason, its `what()` the texts of point 1). `client_check` joins `STRICT_NAMES` in `worker/tools/coverage_gate.py` (it decides which client may be restored for, as `client_profile` decides which is a profile). The two product words live there, not in the connector, as `is_backup_counts` holds Veeam's words in `run_status`: a second connector gets its own facts and, if its words differ, the rule's table grows by a row.

4. **Two new codes, twenty-two: `client_mismatch` and `connector_unknown`**, at the end of `kCodes`, `error_codes()` and the schema's `status.error_code` enum, in this order (the enum only grows at its end, W4.8 point 14).
   - `client_mismatch`: a stop's code (stop text `the backup's organisation doesn't match the client's profile`, so R2 reads `the run stopped before the restore: the backup's organisation doesn't match the client's profile (client_mismatch); nothing was restored`), never a check item's, no severity, exit 4 (`exit_code::service`: the job's claim and Veeam's facts disagree, the thing tested couldn't start, no service refused the Worker).
   - `connector_unknown`: a stop's code too (stop text `the connector type isn't one this Worker has`; `stop_reason` maps `connector::UnknownConnectorError` to it instead of `config`, one type, one code, though the pipeline can't reach it after a run line today), never an item's, exit 1 (`exit_code::config`, with `job_invalid`: the job asks for what this installation doesn't have). Its maker `verification::connector_unknown()` beside `job_invalid()`: `error connector_unknown`, message `the job's connector type isn't one this Worker has; nothing was done`, `restore_sent` false, every count 0.
   - Both join `docs/verification.md` "Error codes" and "Messages"; `connector_unknown` the "When one is written" table of "A result written afterwards". `interrupt_replaces` leaves both alone. `shared/testdata/result-v1/cases.json` gains a valid case for each.
   - *Rejected:* three codes for the three mismatches (the issue names one; the reason is on stderr and in the log, and the result's message is fixed words: the Cloud sees `client_mismatch`, the operator sees which); `client_mismatch` for the manifest's tenant (the manifest is the Worker's configuration, so `config`, as `ManifestError` is everywhere); exit 2 for `client_mismatch` (nobody refused a credential).

5. **A job names its connector: the required key `connector` of `restoreproof.jobs.v1`, a closed object `{"type": "<name>"}`.** The name rule `rp::connector::is_connector_name`: 1 to 64 of `a-z`, `0-9` and `_`, which `ConnectorRegistry::add` now holds a name to as well (`veeam_m365` passes; the quoting rule of `UnknownConnectorError` stays). `Job` gains `connector_type`; in J3's order the key comes right after `client`: `client_id`, `client`, `connector` (the fault word `connector` when the key is missing, not an object or has another key, `connector.type` when `type` is missing, no string or fails the rule), `sample_mail`, …; the shape is the reader's, not the registry's. `shared/schemas/jobs.v1.json` gains it (`type` `pattern` `^[a-z0-9_]{1,64}$` with `not: {pattern: "\n"}`, `additionalProperties` false), `jobs-v1/valid.json` gains `"connector": {"type": "veeam_m365"}`, and `cases.json` gains the key missing, not an object, `type` missing, not a string, empty, with a space, 65 characters, another key beside `type` (invalid) and `type` `other_backup` (valid: a schema can't know a registry). The record's `connector` reader takes any name by the rule, so a record of another connector parses; `result.v1.json`'s `connector.type` becomes the same pattern in place of the one-word enum (a superset: every result so far stays valid), the shared case `connector-type-fake` becomes valid under the name `connector-type-other`, and `connector-type-empty` and `connector-type-bad-characters` are added, invalid.
   - **The pipeline makes the connector by the job's type**: `PipelineArgs::connector_type` (the loop's from the job; at a prompt `kVeeamM365`, no new flag), `default_connector_registry().create(type, …)`; an unknown type there ends before the run line as today (`restore error: …`, exit 1), unreachable from the loop (point 6) and kept for a flag a later task may add. The hold's connector in `worker_body.cpp` is made by the record's `connector.type`; a record without one has no session and no restore request on record and needs no hold.
   - *Rejected:* a flat `connector_type` key (the result and the record say `connector.type`; one spelling); the profile moved under `connector` as the Cloud's `connector.config_json` has it (W4.10 chose `client` a week ago for what Veeam and Microsoft can confirm, and nothing reads the format but this Worker: the Cloud's row can map to either); `connector` optional with `veeam_m365` as the default (a job that doesn't say what it is for is a job the Cloud didn't write).

6. **The loop refuses a job whose connector this Worker lacks and reports it: J3b, `connector_unknown`.** After J3 and before J4, a valid job whose `connector_type` isn't in `ServiceLoopEnv::connector_names` (a vector the body fills from `default_connector_registry().names()`): `warning` `job <run_id>: connector type <type> isn't one this Worker has` (the type passed the name rule, so it may be echoed), last error `job_invalid` (the heartbeat's sixteen words don't grow; the result carries the code), and the job is reported as J3 is: a record of `kind` `job_invalid` with `close_as` `connector_unknown` and `close_detail` the type, and `connector` `{type: the job's, api: ""}` written at (a) already, so the close's result can name it; the folder made and closed with the result of point 4, `client` the job's profile with its `client_id`, `scope` and `resolved` `null`; signed, the TSA asked, queued; J2 skips the job from then on. `CloseAs` gains `connector_unknown`; a `job_invalid` record's `close_as` is `job_invalid` or `connector_unknown`; `plan_close` and `build_close_result` take the new word; `docs/worker-config.md`'s J table and `running.json` tables change with it. Nothing is asked of Veeam or Graph.
   - *Rejected:* J3 `job_invalid (connector.type)` for a registered-looking name (the issue wants the Cloud to tell a malformed job from a Worker that lacks a connector, and C5.13 will dispatch types from its own table); the pipeline deciding it (no connector, no run line, no result).

7. **The result says what was checked: `client.scope` and `client.resolved`, two new required keys of `client`, changed in place.** `scope` is `"same_tenant"` exactly when the step of point 1 passed (the organisation's tenant is the profile's and the targets resolved in it), else `null` (a run that stopped in or before the step, every result written afterwards); the claim is about the client, so a run that later `fail`s keeps it. `resolved` is `null` then too, else the closed object `{"organization": {"name", "tenant_id", "type", "region"} (Veeam's four texts as sent), "mailbox": {"inbox_id"}, "library": {"name", "list_id", "site_url"}, "onedrive_folder": {"name", "site_url"}}`: the names and URLs the targets resolved to at run time, which the 2026-09-29 entry's point 6 asked of W4.1 and W4.1 put off until the check that earns them. The two `name`s are `const` `RestoreTarget` (the checks require it exactly); the rest tenant text or the product's words, `maxLength` alone; `tenant_id` is Veeam's `msid` as sent (it equalled the profile's GUID case-insensitively). Not written: the organisation's Veeam ID and `officeName` (server-local, says nothing to a verifier, W4.1's reasoning on the repository ID), the app's ID (not in the result since W4.1). `ResultClient` gains the two; `ResultBuilder::document` writes them; `result_client(profile, client_id)` leaves both null and the pipeline fills them after the step; `close_run`'s results have both null.
   - **The schema change and the vectors.** `result.v1.json`: `client.scope` `oneOf` null and `enum ["same_tenant"]`, `client.resolved` `oneOf` null and the closed object above, both in `client`'s `required`; the subset draft 7 and 2020-12 read alike, no pattern on tenant text. The four vectors are rewritten by their hidden writers in this order: `result-v1/valid.json` (now with `scope` `same_tenant` and `resolved` holding the made-up names), then `signing-v1/bundle.json` and `cases.json` (`keys.json` unchanged), then `timestamp-v1/cases.json` (a new token over the new digest, the twelve `one_bit_changes` offsets found again by both builds), then `signing-v1/closed-folder.json`; `result-v1/cases.json` changes: `client-scope` goes (the base has it), and `client-no-scope`, `client-no-resolved`, `client-scope-other`, `client-resolved-unknown-key`, `client-resolved-library-name-other` (invalid), `client-scope-null`, `client-resolved-null` (valid), `status-error-client-mismatch`, `status-error-connector-unknown`, `written-afterwards-error-connector-unknown` (valid) come. The Cloud's tests read the rewritten files. **Every result signed before this change no longer validates under the new schema**: none was uploaded anywhere but the lab's stub, and the lab's folders are verified with the schema of their commit (`verify_bundle.py --schemas`). This is the format changed in place for the last time it is cheap, as W4.2's two keys and W4.3's `containers_drawn` were.
   - *Rejected:* the two keys optional in the schema (the vectors are rewritten either way, since the Worker writes the keys; a schema that lets them be missing can't hold the Worker to writing them, and the shared cases couldn't say that a result without `scope` is invalid); `scope` absent rather than `null` when the check didn't pass (every key always there, W4.1 point 1); the resolved names as an attachment file (`client.json`, signed through its hash: it splits the client's identity from the result that claims it, and `attachments`' names are fixed words too).

8. **In the connector, the spec is held to the profile it was made with (finding 8, the part that matters).** `restore_sample` refuses, before layer 1, a spec whose `client_ref` isn't `ConnectorOptions::client`'s `veeam_org_name` (ASCII case-insensitive) or whose targets aren't `RestoreTargets::from_profile` of it, with `std::invalid_argument` ending `; nothing was restored` (`internal`: the Worker's own inconsistency, as an empty `client_ref` is). The split itself (organisation and targets in `RestoreSpec`, tenant and app in the options) stays: making `RestoreSpec` carry the profile touches every test of the guard, the sampler and the restore for no behaviour, and the hold's connector, which never restores, has no profile by design. Open.

9. **The record goes whatever the recovery clean answers: kept, with its reason corrected (finding 6).** "Every run cleans before" holds per client: a leftover of client A's interrupted run sits in A's own `RestoreTarget`s, where nothing but the Cleaner ever deletes and where A's next run's clean before takes it away, and the warning `recovery clean for <run_id>: not completed (<word>)` with `recovery_clean_incomplete` says so. Holding the record until A's targets are clean would hold every other client's jobs for one client's Graph trouble. `docs/worker-config.md` "The hold" says it per client.

10. **A job without a profile can't reach the config's local profile (finding 7).** `make_worker_loop_env`'s `run_job` takes `job.client.value()`: a job the reader passed always has one, and one without throws before the pipeline is called, which `job_run_after_throw` reports as a run that ended before its run line. `PipelineArgs::client` stays a pointer for the commands. A test holds it.

11. **Findings 12 to 15.** 12 and 13 (`read_key` and `shape_problem` beside `config.cpp`'s own, `run_check` beside `run_list`) and 14 (`clean_restore_targets`' unused `Config`, W7.1's) stay out: no behaviour, and this task's diff is wide enough. 15 is in: the W4.10 harness script's `$Profile` (a PowerShell automatic variable) is renamed and its steps get `try`/`finally`, since the W4.11 live run extends that script.

12. **Secrets.** Nothing new is a secret value: `rp::secret_values` is unchanged. The step's stderr line never holds a tenant ID (the facts' `type` and `region` only, cut and printable); `client ok:` prints the tenant ID, which `client check`'s heading prints today. Two cases join the audit: **L**, `test --evidence --outbox --profile-file` on the Harness's fake connector whose facts' tenant isn't the profile's, ending `error client_mismatch`, signed and queued, its streams, folder and recording searched; **J8**, a job of connector type `other_backup` through the service's loop, closed as `error connector_unknown` and sent, the log, the folder and the Cloud's requests searched. The fixture scan covers the rewritten vectors.

**Where the issue and the code disagree, the code wins.** `job.v1` is `restoreproof.jobs.v1` with the job as its element (W4.8 point 3, W4.10 point 2); `job_invalid` for a job that doesn't match it or whose profile doesn't parse is W4.8's J3 and W4.10's `client.<key>`, and gains only the `connector` shape here; the issue's "`VeeamClient` already parses … " lacks `type` (above); "`TargetReader`'s identity checks" are `rp/target_guard_graph.hpp`'s three, which `TargetReader`, the Cleaner and the guard share, and the step runs those; "before the first Veeam restore call" is kept as the issue says it, and the W4.10 Open point's "before the first Veeam call" is not (point 1); the check sits after the run line so that it is reported, and before the clean, the sample and any session (W4.8 made the run line the point after which everything is reported); the Done-when's fixture test runs the real connector over the W3.4 recording (the replay lab), with the Harness's fake beside it.

**Tests, written first, failure paths before the happy path.** `tests/client_check_test.cpp` (`[client_check]`): one `GENERATE` table over the facts (type `Office365`, another word, empty; `msid` equal, equal in another case, different, empty; region `Worldwide`, another word, empty; several at fault at once, the first in order wins; the error's text per reason, never the tenant ID). `tests/run_status_test.cpp`: the two codes in `kCodes` (E20 a `ClientMismatchError` and an `UnknownConnectorError` stop in each phase, X23 and X24 the exit codes, N9 a `client_mismatch` not replaced by a stop, A11 the maker), the schema's enum held to `error_codes()`. `tests/result_schema_test.cpp`, `tests/result_builder_test.cpp` (`scope`, `resolved`, the rewritten `valid.json` and the new cases, the `connector.type` pattern, the schema walk). `tests/restore_command_test.cpp` and `tests/test_command_test.cpp` (`[client_check]`, on the Harness: a mismatched tenant ends `error client_mismatch` after the run line with no clean, no `list_candidates` and no `restore_sample` call, `cleanup` null, the result's `scope` and `resolved` null, exit 4, the folder signed and queued; a manifest of another tenant `error config` after the run line; a library that resolves to another name `error target_guard` before the clean, a 403 `graph_permission`, a 503 `graph_transient`; a pass with `scope` `same_tenant` and `resolved` the fake's names; a stop pending during the step). `tests/veeam_m365_connector_test.cpp` (`client_facts` on `organizations-200.json`, a missing `type` or `msid` as empty, an unknown client `not_in_backup`, two matches an error; `restore_sample` refusing a spec of another client, finding 8). **The Done-when:** `tests/restore_replay_test.cpp` on `tests/replay_lab.hpp`, the real connector over `recordings/w34-live-run1/` with the lab's profile copied and its `graph_tenant_id` replaced by a made-up GUID: the run line, `status error client_mismatch: …`, and the fake Veeam client's requests hold no restore POST, no explore session and no browse (`restore_posts()` 0). `tests/service_jobs_test.cpp` (`connector`, the fault words, the counts, the schema walk), `tests/service_loop_test.cpp` (J3b on a names list of one, its record, its close, J2 afterwards, the log line, the last error), `tests/service_recovery_test.cpp` (`close_as` `connector_unknown`: the record's text and reader, `plan_close`, `build_close_result` with the record's `connector`, a W4.10 record still read), `tests/worker_body_test.cpp` (an unknown-type job to `sent\` and `verified` by `Signer::verify_folder`; a job without a profile never runs on the config; the hold's connector by the record's type), `tests/connector_test.cpp` (the name rule, the default `client_facts`, the scan), the audit's L and J8, the closed-folder vector through `verify_bundle.py`; the Cloud's `test_jobs_schema.py` and `test_result_schema.py` with the new counts, `test_verify_bundle*.py` on the rewritten vectors.

**Docs with the build.** `docs/verification.md` ("The status decision table": the two rows in "Error codes" and "Messages"; a new "The client check (W4.11)" section before "Cleaning the restore targets": the three checks, their order and codes, what `scope` claims; "The result": `client`'s two keys, "What of the tenant the result holds" gains the resolved names and URLs; "A result written afterwards": the `connector_unknown` row), `docs/worker-config.md` ("`rpworker restore`" and "`rpworker test`": the step's lines and the exit code; "The jobs file": `connector`, J3b; "`running.json`": the word and the (a) write; "A run without a result"; "The hold": per client; "Exit codes"), `docs/testing.md` (the four writers and their order, the counts, the audit's L and J8, "Test by hand" with a mismatched profile), `docs/glossary.md` (client check, scope, connector type), `tests/e2e/scenarios.md` (scenario 8: a profile of another tenant), `CLAUDE.md` (the status paragraph, the pipeline line, the "Restore targets" rule: every job's client is held to the backup's organisation before anything is cleaned or restored), and this log's build notes after the build.

**Open.**
- W5.1: `GET /v1/jobs` with `connector` and `client`; the token; a job that ends before its run line (the stub offers it again); whether the Cloud serves each client's canary manifest with the job, which is where finding 5 points (the manifest is the seeder's per-tenant output and the Cloud holds the cursor; until then a Worker holds one tenant's manifest beside its config, and a job of another tenant is reported `error config` by point 1(b) and never retried).
- C5.6, C5.7, C5.13: `connector.type` in the job as the Worker's proposal; the 409 for a bundle whose `client_id`, tenant or connector isn't what was dispatched; whether the Cloud wants the mismatch's reason beside the code (today stderr and the log alone have it).
- Finding 8's split of the run's client between `RestoreSpec` and `ConnectorOptions::client` (point 8), 12 to 14 (point 11).
- A `client check` against Veeam by hand (`--config` and the Veeam secrets, the organisation's facts printed and held to the profile) if the owner wants one before W7.2's doctor.
- The mail `permanentDelete` rule for a cloud other than the global one (W3.4 build notes) stays open; `region` `Worldwide` is now required, so no such cloud is restored into.
- Every result signed before this change is invalid under the new schema (point 7); nothing was uploaded.
- No Worker CI run has started since 2026-10-03 (GitHub billing).

**Done-when, as it will be run** (live and writing: only with the owner's go-ahead, after the fixture tests are green). With `RP_LIVE=1` and the real vault, elevated, over the W4.10 harness extended (`docs/api/veeam-lab/w4.11-harness/w411-live.ps1`), the config copy without client keys and `lab-profile.json` of W4.10, outside the repository: (a) `rpworker test --evidence --outbox --profile-file lab-profile-other-tenant.json` (the lab's profile with a made-up `graph_tenant_id`): the run line, `client error: client mismatch: the backup's organisation's tenant ID isn't the profile's graph_tenant_id`, `status error client_mismatch: …`, exit 4, no `cleanup before` line, no session of `rp-veeam` opened in Veeam, the folder signed, timestamped and queued, both verifiers `verified`, the result's `scope` and `resolved` `null`; (b) the same on `lab-profile.json`: `client ok: tenant bcd6bd1a-…, Office365, Worldwide; mailbox, library and folder resolved`, `pass`, the result's `scope` `same_tenant` and `resolved` holding the lab's organisation and the three `RestoreTarget`s' names and URLs, verified; (c) the service on the config copy with a jobs file of three jobs, in order one of connector type `other_backup`, one with the other-tenant profile and one with the lab's: the first closed as `error connector_unknown`, the second `error client_mismatch`, the third `pass`, all three to `sent\` and `verified`, the stub Cloud showing three results; (d) nothing installed, `graph list` 0 in all three targets, no session Working. Evidence `docs/api/veeam-lab/w4.11-*`, the folders kept outside the repository.

**Code, tests and docs with the build.** New: `rp/client_check.hpp`, `src/client_check.cpp`; `tests/client_check_test.cpp`; `docs/api/veeam-lab/w4.11-harness/`. Changed: `rp/connector.hpp` and `src/connector.cpp` (`ClientFacts`, `client_facts`, `is_connector_name`), `rp/connector_registry.hpp` and `src/connector_registry.cpp` (the name rule), `rp/veeam_client.hpp` and `src/veeam_client.cpp` (`Organization::type`), `rp/veeam_m365_connector.hpp` and `src/veeam_m365_connector.cpp` (`client_facts`, the spec held to the profile), `rp/run_status.hpp` and `src/run_status.cpp` (the two codes, the maker, `stop_reason`, `interrupt_replaces`), `rp/result_builder.hpp` and `src/result_builder.cpp` (`scope`, `resolved`), `src/run_pipeline.{hpp,cpp}` (the step, `PipelineArgs::connector_type`, the manifest's tenant check moved), `rp/sample_selector.hpp` and `src/sample_selector.cpp` (`check_manifest` split), `rp/service_jobs.hpp` and `src/service_jobs.cpp` (`connector`), `rp/service_loop.hpp` and `src/service_loop.cpp` (J3b, `connector_names`), `rp/service_recovery.hpp` and `src/service_recovery.cpp` (`CloseAs::connector_unknown`, the record's `connector` at (a), the reader's name rule), `src/worker_body.cpp` (`connector_names`, the hold's type, `job.client.value()`), `shared/schemas/result.v1.json`, `shared/schemas/jobs.v1.json`, `shared/testdata/result-v1/`, `shared/testdata/jobs-v1/`, `shared/testdata/signing-v1/`, `shared/testdata/timestamp-v1/`, `worker/tools/coverage_gate.py`, the tests named above, `tests/secret_audit_test.cpp`, `tests/restore_command_lab.hpp` (the fake's facts), `tests/replay_lab.hpp`, `cloud/tests/test_jobs_schema.py`, `cloud/tests/test_result_schema.py`; `docs/verification.md`, `docs/worker-config.md`, `docs/testing.md`, `docs/glossary.md`, `tests/e2e/scenarios.md`, `CLAUDE.md`, `docs/api/veeam-lab/w4.10-harness/w410-live.ps1`.

---

## 2026-10-09 — W4.10 code review: findings 1 to 4 and 9 to 11 of fifteen fixed (the schemas' line-break guard, the organisation name's limit in characters, the jobs schema walked, the live restore test's profile, two strict names, the audit's case A, the stale docs); 5 to 8 and 12 to 15 open (proposed)

A review of the branch `w4.10-client-profile` gave fifteen findings. The owner asked for 1 to 4 and 9 to 11; each was fixed test-first where a test can show it. The numbers are the review's order as reported to the owner.

**Fixed.**

1. **The live restore test had no client.** `tests/veeam_m365_restore_live_test.cpp` made its connector without `ConnectorOptions::client`, so since W4.10 `restore_sample` refused it (`the connector has no client profile; nothing was restored`). It now gives the config's local profile and requires that there is one. Compiled, **not run live**: it writes to the lab tenant and needs an elevated shell.
2. **A value ending in a line break.** Python's `$` matches before a final `\n`, so `client-profile.v1.json` and `jobs.v1.json` accepted `"b!abc\n"`, a mailbox, a site ID, a folder ID, a `run_id`, a `client_id` and a `restore_point` with one, each of which the Worker's readers refuse. Every variable-length pattern of both schemas now carries W4.1's `not: {pattern: "\n"}`; `client_id`, which may be `null`, carries `not: {type: string, pattern: "\n"}`, since a bare `not: {pattern}` refuses `null`. The GUIDs need none (`minLength` = `maxLength`). `veeam_org_name` has no pattern and stays `code_refuses`. Eight new shared cases, seen failing in Python before the schemas changed.
3. **`veeam_org_name`'s 1024 was counted in bytes.** The schema's `maxLength` counts code points; `client_profile.cpp` counted `size()`. It now counts every byte that isn't a UTF-8 continuation. Two new shared cases, 1024 two-byte letters (valid) and 1025 (not). `test_mailbox` is ASCII by its rule, so nothing changes for it.
4. **`jobs.v1.json` was never walked.** `tests/service_jobs_test.cpp` now runs the shared-subset walk over it, as the entry's point 8 says, and holds `client` to the one `$ref` and the three strings to their guard. The walk found what the review said: the `not` of the sample sizes named `type: object` without closing it. The `type` is gone from the `not` (the job itself is an object already), which changes nothing it accepts.
9. **Docs behind the code.** CLAUDE.md's "Restore targets" rule and its W4.8 paragraph still said the recovery clean is made only when the config's client is the record's; `docs/verification.md` said the same, and `docs/worker-config.md` that `client_id` is `null` until jobs carry one. All four now say what W4.10 built: the clean runs by the record's own profile, and the result's `client_id` is the job's.
10. **Deciding code outside the strict gate.** `src/client_profile.cpp` (is a job's or a record's client a profile) and `src/strict_json.hpp` (a key twice, a document nested too deep) hold what the strict `service_jobs.cpp` and `service_recovery.cpp` decided before W4.10. `client_profile` and `strict_json` are now strict names in `worker/tools/coverage_gate.py`; both files were at 100% on the last report (114 of 114, 23 of 23). `src/client_command.cpp` is not matched and stays outside.
11. **The audit's case A.** The entry's point 10 puts `restore --profile-file` into case A; only case C had gained `client check`. Case A now runs with a profile file, and then once more with a file that is no profile (`config error: --profile-file ...`, exit 1), both searched.

The counts: `shared/testdata/client-profile-v1/cases.json` 104 cases (18 valid, 86 invalid, 2 `code_refuses`), `shared/testdata/jobs-v1/cases.json` 72 (17 valid, 55 invalid, 3 `code_refuses`). The runs: `ctest --preset dev` passed, 2160 tests (the live ones skipped); Cloud's pytest 920 passed; the gate's own tests 22; the gate on the last coverage report passes with the two new names. No new coverage run was made.

**Open.**

- 5: the canary manifest is one `seed-manifest.json` beside the config, and `check_manifest` holds its tenant to the profile's. A job for a second tenant ends before its run line as a `config error`, with no folder and no result, and the stub offers it again at every poll. Whether a job carries or names its manifest is undecided (W4.11 or W5.1).
- 6: the record goes whatever the recovery clean answers, on "every run cleans before", which holds only while the next job is the same client's.
- 7: `worker_body.cpp` maps a job without a profile to `args.client = nullptr`, which `run_pipeline` reads as "at a prompt"; only the loop's own check keeps such a job from the config's local profile.
- 8: the run's client is split between `RestoreSpec` (organisation, targets) and the optional `ConnectorOptions::client` (tenant, app), with a refusal at run time in place of a required argument. Finding 1 was an instance.
- 12 to 15: `read_key` and `shape_problem` beside `config.cpp`'s own, `run_check` beside `run_list`, `clean_restore_targets`' unused `Config`, and the harness script's `$Profile` and missing `try`/`finally`.

## 2026-10-09 — W4.10 build notes and the live Done-when: the profile in one schema and one type, the job's `client`, the run and the record on it, `rpworker client check`; the lab's three targets listed from a file with no client keys in the config, and the service's run on a job's profile sent and verified (proposed)

W4.10 (#133) was built as the entry of 2026-10-09 says, test-first, in six commits of test and code together. This records where the build left the entry, what it settled beyond it, the runs, and what is open. `docs/worker-config.md` ("`rpworker client check`", "The jobs file", "`running.json`"), `docs/verification.md`, `docs/testing.md` and `docs/glossary.md` say the rest.

**Where the build left the entry.**

1. **The profile (point 1): as written.** `rp::ClientProfile`, `parse_client_profile`, `to_json`, `local_profile`, `read_client_profile_file` in `rp/client_profile.hpp` / `src/client_profile.cpp`; `shared/schemas/client-profile.v1.json`. Two things the entry didn't say: the GUID and mailbox rule texts left `config.cpp`'s switch for the constants `rp::kGuidRule` and `rp::kRestoreMailboxRule` beside the three Graph ID texts, and `has_control_character` and `is_printable_key` became public, so the profile's reader and the config's say one text each and refuse the same characters; and the jobs reader's strict parser (a key twice refused, nesting past 32 levels never parsed) moved to `src/strict_json.hpp` for both readers. `veeam_org_name` and `test_mailbox` get the 1024-character limit the result's schema has (`must be at most 1024 characters`); the config's own reader has no such limit, which is left as it is (a config value that long gives a `result_invalid` run already).
2. **The job's `client` (point 2): as written**, in place, required; the fault words `client` and `client.<key>` right after `client_id`; `is_job_key` takes a `.`. `shared/schemas/jobs.v1.json` refers to the profile schema by the relative name `client-profile.v1.json`, which Python's validator resolves through the two schemas' `$id` with the `referencing` registry (`cloud/tests/test_jobs_schema.py`); the Worker never validates a job with the schema. A J3 job whose profile could be read keeps it in its record.
3. **W4.10 carries, W4.11 checks (point 3): as written**, `client_id` in the result included. Nothing of `client_mismatch`, `connector_unknown` or `scope` was built.
4. **The run's path (point 4): as written, with one more seam.** `PipelineArgs::client`, `client_id` and `profile_file`; the profile read right after the config and before `after_config`, the secrets, the schema check, the manifest and the mutex; `ConnectorOptions::client`; `make_graph_and_cleaner` and `clean_restore_targets` on the profile (`clean_restore_targets` still takes the `Config`, unused, so the signature says where the clean's settings come from when W7.1 adds any); the record's `client` the profile or `null`; `is_records_client` and its warning line gone; `close_run`'s result from the record's profile with the job's `client_id`, empty strings for a profile that couldn't be read. The one thing beyond the entry: the listing `graph list` prints moved to `src/target_listing.hpp` / `rp::list_restore_targets`, which `client check` calls with its heading, so the two commands are one listing with two sources of the profile, as point 6 wanted, and `graph list`'s code changed by a few lines.
5. **The config's eight keys (point 5): as written.** `config key "<first missing>" is missing: the eight client keys (...) are set together or not at all`, said before any rule of the present ones.
6. **`rpworker client check` (point 6): as written.** No `--config`; `--profile-file` required; `client profile: veeam_org_name <org>, tenant <guid>, app <guid>`, a blank line, the three tables; `graph list`'s exit codes. The exe tests run on three committed profile files under `worker/tests/fixtures/client-profile/` (the shared vector's values, no lab value).
7. **`--profile-file` on `restore` and `test` (point 7): as written.** An empty value is a missing one (usage, 64), as `--json`'s.
8. **The vectors (point 8): as written, with the counts** 97 profile cases (17 valid, 80 invalid, 2 `code_refuses`) and 69 jobs cases (17 valid, 52 invalid, 3 `code_refuses`: `PRN`, `job.`, `..`), both pinned on both sides. The profile schema has `minLength`s the C++ rules imply (a site ID is at least 90 characters, a drive ID at least 3), so a schema reader sees the bounds without running the pattern.
9. **The result, the vectors and the record (point 9): as written.** `result.v1.json`, `result-v1/`, `signing-v1/` and `closed-folder.json` unchanged; a W4.8 record is `isn't a restoreproof.running.v1 record; moved aside`, which the recovery tests now hold.
10. **Secrets (point 10): as written.** The audit's case C runs `client check --profile-file --record` and searches its streams, the recording and the profile file; `secret_values` unchanged; the fixture scan passes over the new vectors, fixtures and evidence.

**The runs** (2026-10-09, this branch): `rptests.exe` in one process 2055 of 2055 passed, 11 skipped (the live tests), 122,001 assertions; the `rpworker.exe` exe tests 94 of 94 (`ctest --preset dev -L exe`); the fixture secret scan passed; Cloud's pytest 910 passed (176 of them the two new schema tests); the lab's pytest 980 passed, 1 skipped, and `python -m seeder hash` 40 of 40; the local coverage gate passed, 96.7% line (15,208 of 15,724), every strict file at 100% (`service_jobs.cpp` 172 of 172, `service_recovery.cpp` 427 of 427, `service_loop.cpp` 456 of 456), `client_profile.cpp` 114 of 114, `client_command.cpp` 46 of 49.

**The live Done-when** (2026-10-09, the lab machine, elevated, the real vault; `docs/api/veeam-lab/w4.10-harness/w410-live.ps1` over the W4.8 harness; the profile files and the config copy under `%LOCALAPPDATA%\RestoreProof\lab\`, outside the repository):
- (a) `w4.10-1-client-check.txt`: `config check` on a config copy holding the two URLs and Veeam's certificate alone prints `(not set)` for the eight; `graph list` on it exits 1 with `config error: the config has no client keys; set the eight client keys, or use rpworker client check --profile-file <file>`; `rpworker client check --profile-file lab-profile.json` prints `client profile: veeam_org_name RestoreProofLab.onmicrosoft.com, tenant bcd6bd1a-..., app 737da5ef-...` and the lab's three targets (0 items each, as `graph list` on the lab config showed beside it), exit 0, having read no config; a copy with `test_mailbox` set to alice exits 1 with `key "test_mailbox" must be restoretest@<domain>: ...`, one with `graph_tenant_id` in braces names `graph_tenant_id`, a file that isn't there `can't be read`; `veeam list` on the copy lists the organisation unmarked, exit 0. The live test `[client_command][live]` passed the same way.
- (b) `w4.10-2-test-profile-file.txt`: `rpworker test --mail 2 --sp 1 --od 1 --run-id w410-1 --config config-no-client.json --profile-file lab-profile.json --evidence --outbox` on the 2026-10-08T23:43:58.1565721Z restore point: 4 of 4 restored in four `Success` sessions, `status pass: 4 of 4 item(s) verified: manifest 3, fields 1, metadata 0`, cleaned after (2 mail, 1 sharepoint, 1 onedrive), signed, `timestamped 2026-10-09T14:04:38Z`, queued; `rpworker signer verify` and `verify_bundle.py` both `verified`, the result's `client` the file's with `client_id` `null`; `graph list` 0 in all three targets after. (A first attempt of the same run ended the same way and its folder was set aside unrecorded: the harness threw after the run, before saving, on the W4.8 folder it keeps the public key in not being there yet, which the harness now makes first.)
- (c) `w4.10-3-service-run.txt`: the service installed on a config copy whose eight client keys were taken out (`config check` printing `(not set)` for each), started as `NT SERVICE\RestoreProof`, one job `w410-2` (`client_id` `lab-client`, `client` the lab's profile, 1 of each) taken at 14:07:03Z, `ended pass; queued` at 14:09:01Z, `sent w410-2` a second later, `skipped w410-2: already sent` at the next poll, stopped, uninstalled; the sent folder `verified` by both verifiers, its `result.json`'s `client` the job's profile cut to the result's object with `client_id` `lab-client`.
- (d) `w4.10-4-teardown.txt`: nothing installed, `runs\` empty, no session Working, 0 in all three targets; the sent folder and the run's kept under `%ProgramData%\RestoreProof\w410`.

**Open.**
- W4.11 (#134): `client_mismatch`, `connector_unknown` and the connector type in the job; `scope: "same_tenant"` and the resolved names in the result; the rows in `docs/verification.md`; a `GENERATE` table over the codes. Until then a job's profile is checked against nothing but its own shape and the guard's resolution of each target.
- W5.1: the job with its profile from `GET /v1/jobs`; whether `jobs_file` stays.
- The profile's `graph_client_id` per client is the MSP's choice (one multi-tenant app or one registration per tenant); the Worker takes the ID as given. The Worker app's grants in a client tenant (L1.5) are the operator's to make; `client check` is what shows they are there.
- `clean_restore_targets` keeps its `Config` parameter unused: W7.1 decides whether anything of the config reaches the recovery clean.
- No CI run has started since 2026-10-03 (GitHub billing); the Windows job, the `fixture-scan` job and the `lab` and `cloud` workflows are untried on this branch.

---

## 2026-10-09 — W4.10 (#133): the client profile from the job. A job carries its client as a `restoreproof.client-profile.v1` object, the service's runs and records take the client from it and never from `config.json`, whose eight client keys become an optional local profile for the commands at a prompt; `rpworker client check --profile-file <f>` reads a profile's three restore targets as `graph list` does (recorded before the build)

W4.10 (#133) is the first half of the 2026-09-29 entry "Clients live in the Cloud": the Worker takes a client's details from the job, so one Worker can serve many clients. Done when: "`rpworker client check --profile-file lab-profile.json` prints the lab's three targets with no client keys in `config.json`, and a profile that breaks the schema exits 1 naming the bad key." This entry works from issue #133, issue #134 (W4.11, the second half, which needs this one), the 2026-09-29 entry, the W4.8 entry (point 3, its build notes and its Open list, which name W4.10 and W4.11), the W4.1 entry (point 6) and the code. The issue was written before W4.5 to W4.9; where it and the code disagree, the code wins, and each such place is named below. No code is written yet; the build notes will record what the build finds. Out of scope and not built here: the per-job check against Veeam (`client_mismatch`, `connector_unknown`, the Graph token held to the organisation's `msid`, W4.11), `GET /v1/jobs` and the token (W5.1), the Cloud's side (C5.2, C5.6, C5.13).

**What the investigation found, since the points below rest on it.**

- **The config's client keys are read in eleven places.** `rp::result_client(config)` (the result's `client` object and the record's), `RestoreTargets::from_config` (every restore target in the Worker), `run_pipeline` (the targets, the manifest's tenant check, `list_restore_points(veeam_org_name)`, the run line, `choose_sample`, the `RestoreSpec`, the run's Graph client for the clean and the check through `make_graph_and_cleaner(config)`), the connector's factory `make_veeam_m365_connector` (the guard's Graph client signs in with `config.graph_tenant_id` and `config.graph_client_id`), `clean_restore_targets(config, ...)` (the recovery clean), the hold's `is_records_client(config, record)` (the record's `client` compared with the config's before that clean), `new_run_record(..., config, ...)` and `new_job_invalid_record` (the record's `client`), `graph list` (the Graph client and the targets), `config check` (prints the eight), `veeam list` (marks the configured organisation and errors when it isn't there), and the live tests through the lab config. Every one of them but `config check` and `veeam list` wants the client as one thing: a tenant, an app, an organisation name, a mailbox and four IDs.
- **The record's `client` is the result's `client` object, which has no `graph_client_id`.** A recovery clean by the record's profile needs the app's ID to sign in to Graph, so the record must carry the whole profile, not the result's cut of it.
- **The jobs reader is closed and hand-written** (`src/service_jobs.cpp`, strict): a job with a key it doesn't know is `job_invalid` with `unknown key`, so a stub file that names a profile today runs nothing, which is what W4.8 point 3 intended ("a new key, which this reader refuses until then"). The fault word of a J3 job is one key name of `a-z`, `_` and space, at most 32 characters (`is_job_key`), kept in the record's `close_detail` and in the result's message.
- **Nothing of the Cloud's side exists**: no `job.v1` schema, no `client-profile.v1` schema, `cloud/app` empty. The jobs document `restoreproof.jobs.v1` is the Worker's proposal for C5.6 and has been written by hand only; no job has ever been dispatched. The result's `client.client_id` is `string | null` in `result.v1.json` already, with a valid shared case for a string.
- **The config's shape rules are private to `config.cpp`** (a `StringRule` switch), but the checks behind them are public: `is_restore_mailbox`, `parse_graph_site_id`, `is_graph_drive_id`, `is_graph_item_id` (`rp/config.hpp`) and `is_uuid` (`src/uuid.hpp`). The texts of the GUID and mailbox rules are in the switch alone; the three Graph ID texts are constants.
- **`screenshots_enabled` is already the job's** (W4.8 point 3, `PipelineArgs::screenshots`) and the config's for a command at a prompt. Nothing else per client is in the config: `sample_mail/sp/od` are per job too.
- **`graph list` is `client check` without the file**: it loads the config, opens the certificate from the vault, makes the Graph client with the config's tenant and app, and lists the three targets through `TargetReader` with the guard's checks first. Nothing of the config but the eight client keys reaches a Graph call: Graph is trusted through the Windows store, the download client has no setting, and the certificate is the vault's.
- **The test lab's `graph_lab::lab_config()` builds a `Config` with the five target keys alone** (no tenant, app or organisation) and hands it to `RestoreTargets::from_config` in the reader's and the Cleaner's tests; `from_config` requires the five and no more.
- **The secret audit searches every output of a path for the sentinels and the shapes** (W4.9); a new command's outputs join it by one `lab.collect`. A profile holds a tenant ID, an app ID, an organisation name, a mailbox and four Graph IDs: none is a secret value, `graph_client_id` is public by Entra's own definition, and `redact()`'s keyed rule doesn't name any of the eight keys.

**Decision.**

1. **The profile is one closed object, `restoreproof.client-profile.v1`, with nine keys, in one schema and one C++ type.** `shared/schemas/client-profile.v1.json`, in the subset draft 7 and 2020-12 read alike (W4.1 point 3), every key required, no other key: `format` (`const` `restoreproof.client-profile.v1`), `veeam_org_name` (1 to 1024 characters, tenant text: `maxLength` alone in the schema), `graph_tenant_id` and `graph_client_id` (a GUID: a fixed-length pattern, `minLength` = `maxLength` 36), `test_mailbox` (`restoretest@<domain>`), `test_site_id` (`<tenant>.sharepoint.com,<site GUID>,<web GUID>`), `test_library_id` and `test_onedrive_drive_id` (`b!` then letters, digits, `-` and `_`), `test_onedrive_folder_id` (letters, digits, `!`, `-` and `_`), each with the pattern of the config's rule, which is the shape the Worker makes URLs from. Today's key names, as the issue asks; IDs only, no names, URLs or secrets (W2.4 decision 3 stands). In rpcore `rp::ClientProfile` in `rp/client_profile.hpp` (the eight values; `format` is read and never stored) with `rp::parse_client_profile(const nlohmann::json&)`, pure, answering the profile or a `ProfileFault{key, problem}` whose `problem` is the config's own text for that key (`is missing (required)`, `must be a string`, `must not be empty`, `must not contain control characters`, `must be a GUID (...)`, `must be restoretest@<domain>: ...`, `must be a Graph site ID (...)`, the drive and item rules) or, for the object, `not a restoreproof.client-profile.v1 document` (not an object, `format` wrong or missing) and `has a key that isn't the profile's` (named when it passes the config's `is_printable_key` rule, unnamed otherwise); `to_json(profile)` the closed object with `format`; `rp::read_client_profile_file(path)` (UTF-8 JSON, at most 64 KiB, strict: a key twice is refused as the jobs reader refuses it) throwing `ConfigError`. The Worker checks the rules in code, as it does the signature file's (W4.3 point 4): there is no second embedded validator. The two sets of rules are held together by shared vectors (point 8). The GUID and mailbox rule texts move out of `config.cpp`'s switch into constants beside the three Graph ID texts, so the profile's and the config's messages are one text each.
   - *Rejected:* a profile without `format` (every other document of ours says what it is, and a profile file given to `client check` by mistake, say a jobs file, is then refused by one word, not by whichever key is missing first); `client_id` inside the profile (it is the job's key since W4.8 and the Cloud's label for the client, not a fact of the tenant; the profile is what Veeam and Microsoft can confirm, W4.11); `screenshots_enabled` in the profile (it is the job's key, W4.8 point 3; moving it changes the jobs format for nothing); a second validator embedded for the profile (one hand-written reader held to one schema by vectors is the signature file's way, and the profile is nine strings).

2. **The profile enters a job as the required key `client` of `restoreproof.jobs.v1`, in place; a job without one is no job.** The jobs document keeps its name and gains the key: no job has ever been dispatched, the Worker's reader is the only reader, and the stub file is written by hand, so there is nothing to keep compatible (as W4.1's result changed in place before the first signature). `Job` gains `ClientProfile client`. In J3's order the key comes right after `client_id`: `client_id`, `client`, `sample_mail`, `sample_sp`, `sample_od`, `restore_point`, `screenshots_enabled`, `canary_cursor`, then `unknown key`. The fault word is `client` when the key is missing, not an object, not the format or has a key that isn't the profile's, and `client.<key>` when one of its eight keys is at fault (`client.test_mailbox`), so J3's line, the record's `close_detail` and the result's message name the key, as the Done-when wants of the command; `is_job_key` takes a `.` and the words stay under 32 characters. A job whose profile can't be read is still reported (a `job_invalid` record, folder and result, W4.8 J3): the Cloud must learn that its profile is wrong, which is W4.11's `job_invalid` ("the job doesn't match `job.v1` or its profile doesn't parse") taken in here as far as the shape goes. Its record then has `client` `null` (point 4). `shared/schemas/jobs.v1.json` is added for the Cloud's side: the whole document, the job's keys under their W4.8 rules as far as a schema can say them, and `client` a `$ref` to `client-profile.v1.json` by relative name, so the profile schema has one copy. The Worker never validates a job with it (the reader stays hand-written and strict); the vectors hold the two together (point 8).
   - *Rejected:* a new format `restoreproof.jobs.v2` (nothing reads v1 but this Worker, and two names for one stub); an optional `client` falling back to the config's (the 2026-09-29 entry: the service loop never reads the config's client keys, and a job that silently ran against another client's targets is the mix-up the whole design exists to refuse); `job.v1.json` for one job alone (the document is what a Cloud answers and a file holds; the job is its element); inlining the profile schema into `jobs.v1.json` (two copies drift; the `$ref` keeps one, and the shared keyword list has `$ref` already).

3. **What W4.10 carries and what W4.11 checks.** W4.10: the profile in the job, the run on the job's profile (targets, tenant, app, organisation name, `client_ref`), the record's `client` as the profile and the recovery clean by it, `client.client_id` in the result, `RestoreTargets::from_profile`, the config's client keys as an optional local profile, `--profile-file` on the commands at a prompt, and `rpworker client check`. W4.11: `client_mismatch` (the organisation named by `veeam_org_name` has `type == Office365`, `msid == graph_tenant_id`, `region == Worldwide`), `connector_unknown`, the connector type in the job, `TargetReader`'s identity checks before the first Veeam call as a step of the run with its own code, `scope: "same_tenant"` and the resolved names in the result, the rows in `docs/verification.md`. **`client_id` goes into the result now**, which W4.8 point 3 put off: W4.8's reason was that the job's `client_id` and the config's tenant were two sources nothing tied together; now the `client` object is the job's profile whole, and `client_id` is the Cloud's own label for that job, which the Cloud needs to match the bundle to what it dispatched (C5.13's 409). It claims nothing about the tenant: the claim is `scope`, and that waits for the check that earns it.
   - *Why the run may use an unchecked profile:* the profile comes from the jobs file, which is read only under the vault's owner rule (W4.8 point 3), the same trust `config.json` has, and the guard still resolves every target per item through Graph before any Veeam call and refuses anything that isn't a `RestoreTarget` (W2.7, W2.4 review decision 1): a profile is a configured set of IDs the guard verifies, as the config's keys were. What W4.11 adds is the cross-check with Veeam, which no config-keyed run had either.
   - *Rejected:* building W4.11's `msid` check here (its own task, with its own Done-when and `GENERATE` table); carrying the profile but running on the config's keys until W4.11 (then the config's client keys couldn't be optional, which the issue's Done-when needs).

4. **The run's path, reader by reader.** `rp::result_client(const ClientProfile&, std::optional<std::string> client_id)` replaces `result_client(config)`; `ResultClient` gains `client_id`. `RestoreTargets::from_profile(const ClientProfile&)` is the factory, with `from_config`'s checks on the five target values (an empty one, the mailbox rule, the four shapes; `std::invalid_argument` with the same texts); `from_config(config)` copies the config's eight keys into a profile and calls it, requiring the five target keys and no more, as today (the test lab's five-key `Config` keeps working). `PipelineArgs` gains `client` (the run's profile, borrowed; null: `--profile-file`'s, else the config's local profile, else `config error: the config has no client keys; set the eight client keys or give --profile-file <file>`, exit 1), `client_id` (the job's; nullopt at a prompt) and `profile_file`; `run_pipeline` reads the profile once after the config and before the secrets and uses it everywhere the config's keys were. `ConnectorOptions` gains `client` (`std::optional<ClientProfile>`): the registry's factory makes the guard's Graph client with its tenant and app; the pipeline always sets it; a connector made without one (the hold's, which lists and ends sessions and never restores) refuses the first `restore_sample` with a `ConfigError`. `make_graph_and_cleaner` and `clean_restore_targets` take the profile; the Cleaner is unchanged (strict, W3.4). The record (`running.json`, still fourteen keys): `client` becomes the profile's object (`to_json`, nine keys) or `null` for a `job_invalid` record of a job whose profile couldn't be read; a `run` record's is never null. `new_run_record(run_id, client_id, profile, taken_at)`, `new_job_invalid_record(run_id, client_id, optional profile, taken_at, key)`. The hold's clean runs by the record's profile: `is_records_client` and its line `the config's client is not the run's; the restore targets were not cleaned` go, `clean_restore_targets(config, record.client, ...)`, which closes that Open point of W4.8. `close_run`'s result takes `client` from the record (`result_client(profile, client_id)`, or, with a null profile, the empty strings the schema allows beside the job's `client_id`). `ServiceLoopEnv::config` keeps the intervals and nothing of a client. `graph list`: the config's local profile, as today, with the new error when there is none. `veeam list`: marks the configured organisation and reports a missing one only when the config has a local profile; without one every organisation is listed and nothing is marked. `config check`: each of the eight keys, or `(not set)`. The live tests read the lab config, which keeps its client keys.
   - *Rejected:* filling the config's client keys from the profile and leaving every reader on `Config` (the least change, but then `Config` would carry "the client of this run" and `from_config` would stay the factory, the opposite of the issue's step; and a struct that is sometimes the file and sometimes the job hides which one a reader got); a new `ConnectorFactory` signature with the profile (the same thing through thirty call sites, most of them tests); a `client` object in the record that is the result's (no `graph_client_id`, so no clean by it).

5. **The config's eight client keys are an optional local profile, all or nothing.** `parse_config` takes the eight together or none: with some set and some missing, `config key "<the first missing>" is missing: the eight client keys (veeam_org_name, graph_tenant_id, graph_client_id, test_mailbox, test_site_id, test_library_id, test_onedrive_drive_id, test_onedrive_folder_id) are set together or not at all`, before any other check of them; each present one keeps its rule and its text. `rp::local_profile(const Config&)` answers the profile or nothing. Who needs it: `restore` and `test` without `--profile-file`, `graph list`, each with the error of point 4; `veeam list` uses it when there; `service run` and the loop never read it (point 4); `client check` reads no config at all. The service's config may now hold no client key, which is what an MSP's Worker will have.
   - *Rejected:* keeping the keys required (the Done-when says "with no client keys in `config.json`", and the service doesn't use them); a `client` object in `config.json` (a second shape for the same eight values; the flat keys are what every installation has today).

6. **`rpworker client check --profile-file <file> [--vault <file>] [--record <dir>]`.** `--profile-file` is required (the usage line otherwise, exit 64; an empty value is a missing one). No `--config`: nothing of the config reaches a Graph call, so the command reads none (point 5's reason, and the Done-when's "no client keys in `config.json`" holds trivially). In this order: the profile file (`config error: --profile-file <file>: <problem>`, with the file's problems `can't be read`, `over 64 KiB`, `not JSON` (a key twice too), `not a restoreproof.client-profile.v1 document`, `key "<key>" <the key's problem>` and `has a key that isn't the profile's[: "<key>"]`, exit 1); the vault and the certificate as `graph list` opens them (`config error: ...`, exit 1); `--record` (as `graph list`'s); then the three targets listed as `graph list` lists them without `--hash` (the guard's checks first, nothing downloaded), printed as `client profile: veeam_org_name <org>, tenant <guid>, app <guid>`, a blank line, then `graph list`'s three tables and summary line. Exit codes are `graph list`'s: 2 for `graph error: ...` naming the grant the call relies on (a `PermissionError`, which is how "a target it can't reach names the missing grant" is already said, `docs/security/graph-permissions.md`) or an `AuthError`, 3 transient, 4 any other `GraphError` (the guard's `WrongTargetError`, a `NotFoundError`), 1 unexpected. The code: `rp::run_client_command` in `rp/client_command.hpp` / `src/client_command.cpp`, on `GraphCommandEnv` (its `default_config_path` never called), over the listing moved out of `graph_command.cpp` into one internal function both commands call, so `graph list` and `client check` are one listing with two sources of the profile.
   - *Rejected:* `--hash` (a check of reachability and identity, not of content); `--config` (nothing to read); a `profile error:` prefix (a profile file is a configuration, and every command says `config error:` for one that doesn't load).

7. **`restore` and `test` take `--profile-file <file>` too.** Optional; without it the config's local profile. The service hands a job's profile to the same `PipelineArgs::client`, so a run from a file at a prompt is a run as the service makes it, and W4.11's live Done-when (a job whose tenant isn't the organisation's) can be made from a file. The profile is read right after the config, before the secrets, by the one reader `client check` uses, with the same messages.
   - *Rejected:* the commands at a prompt on the config alone (then the lab can't run a job's profile by hand, and `client check` would be the only reader of a file).

8. **Shared vectors, run by Catch2 and by pytest.** `shared/testdata/client-profile-v1/valid.json` (one profile with the result vectors' placeholder names) and `cases.json` (RFC 6902 patches as `result-v1/cases.json` has them, each with `valid` as the schema's verdict and, where the code refuses what the schema can't say, `code_refuses` true): every key missing, of another kind, empty, with a control character (the schema can say it for the patterned keys and not for `veeam_org_name`: that one is `code_refuses`), a GUID with braces, a mailbox that isn't `restoretest`, a look-alike, a site ID with a list GUID, a drive ID without `b!`, a list ID for a drive, an unknown key, a wrong `format`, a profile that is an array; the valid ones: the base, upper-case GUIDs and `RESTORETEST@`, a `.SharePoint.COM` host. The Worker runs them through `parse_client_profile` (`valid` and not `code_refuses` is a profile; `tests/client_profile_test.cpp`) and through the validator library against the schema in a test (as `signer_test.cpp` validates the signature file), so the rules in code are the schema's; the Cloud runs them with `jsonschema` (`cloud/tests/test_client_profile_schema.py`), and both pin the counts. `shared/testdata/jobs-v1/valid.json` and `cases.json` do the same for the jobs document (a job without `client`, with a profile at fault, an unknown key, six jobs, every size 0; `valid` the schema's verdict, `code_refuses` where the reader is stricter than a schema can be): the Worker through `parse_jobs` (`tests/service_jobs_test.cpp`), the Cloud through `jsonschema` with the profile schema registered for the `$ref` (`cloud/tests/test_jobs_schema.py`). The schema walk (`tests/schema_walk.hpp`) runs over both new schemas.

9. **The result, the vectors and the record.** `result.v1.json` gains no key and loses none; `client.client_id` is now the job's (or null at a prompt). `shared/testdata/result-v1/valid.json` is unchanged (the Harness's run has no job); `cases.json` gains nothing (`client-id-string` is there). The signing vectors are unchanged. The closed-folder vector (`signing-v1/closed-folder.json`) is unchanged: its record has no `client_id`. `running.json` changes in place (point 4): a record W4.8's build wrote no longer parses, which the loop handles as any record it can't read (`isn't a restoreproof.running.v1 record; moved aside`, W4.8 point 6): nothing is closed, ended or cleaned on its word, and no such record exists outside the lab. `docs/worker-config.md`'s `running.json` table and "The hold" change with it.

10. **Secrets.** A profile is IDs, a name and an address: no value in it is a secret, and `rp::secret_values` is unchanged. The profile's errors name keys and never values, the unknown-key name only under the config's printable rule, and a value is never echoed (`client check`'s header prints the organisation name, the tenant and the app ID, which `config check` prints today). `client check --profile-file --record` joins the secret audit (a new case beside case C's `graph list`, its stdout, stderr and recording searched), `restore --profile-file` the audit's case A. The fixture scan already covers `shared/testdata`.

**Open, left to W4.11 and W5.1.**

- W4.11 (#134): `client_mismatch` and `connector_unknown` in `kCodes`, `error_codes()` and the schema's enum; the connector type in the job (`connector.type`, the registry's name; today `veeam_m365` is hard-wired in the pipeline); the organisation looked up by `veeam_org_name` and held to `type == Office365`, `msid == graph_tenant_id`, `region == Worldwide` before any explore session; `scope: "same_tenant"` and the resolved names and URLs in the result (W4.1 point 6); the rows in `docs/verification.md`; the mail `permanentDelete` rule for a cloud other than the global one (W3.4 build notes).
- W5.1: the job from `GET /v1/jobs` with its profile; the token; whether `jobs_file` stays; a job whose profile is refused by the Cloud's own check (C5.13) never reaching the Worker.
- C5.2, C5.6, C5.13: `client-profile.v1.json` and `jobs.v1.json` as the Worker's proposal for `connector.config_json` and the jobs answer; a tenant unique per MSP; the profile's `graph_client_id` per client (one multi-tenant app or one registration per tenant is the MSP's choice; the Worker takes the ID as given).
- W7.1: `lab-profile.json` and a profile file at a prompt are the operator's own files, under no owner rule (the jobs file has one): a profile the Worker is handed by the person at the keyboard needs none.

**Done-when, as it will be run.** With `RP_LIVE=1` and the real vault, from an elevated shell: a copy of the lab config without its eight client keys and a `lab-profile.json` written from `lab/tenant.md` outside the repository; `rpworker client check --profile-file lab-profile.json` prints the lab's three targets (the same tables `graph list` printed with the keys) and exits 0, having read no config; `rpworker config check` on the copy prints `(not set)` for the eight; `rpworker graph list` on the copy exits 1 with the no-client-keys error; a copy of the profile with `test_mailbox` set to `alice@...` exits 1 with `config error: --profile-file <file>: key "test_mailbox" must be restoretest@<domain>: ...`, and one with `graph_tenant_id` in braces names `graph_tenant_id`; `rpworker test --evidence --outbox --profile-file lab-profile.json` on the copy restores and verifies as before (the profile the run's, the result's `client` the file's, `client_id` null), and a jobs file with the profile in its one job runs through the service's loop to `sent\` with the result's `client_id` the job's, both verifiers `verified`. Evidence `docs/api/veeam-lab/w4.10-*`, the profile and the config copy kept outside the repository.

**Code, tests and docs with the build.** New: `rp/client_profile.hpp`, `src/client_profile.cpp`; `rp/client_command.hpp`, `src/client_command.cpp`; `shared/schemas/client-profile.v1.json`, `shared/schemas/jobs.v1.json`; `shared/testdata/client-profile-v1/`, `shared/testdata/jobs-v1/`; `tests/client_profile_test.cpp`, `tests/client_command_test.cpp`; `cloud/tests/test_client_profile_schema.py`, `cloud/tests/test_jobs_schema.py`. Changed: `rp/config.hpp` and `src/config.cpp` (the optional eight, the rule texts as constants), `rp/connector.hpp` and `src/connector.cpp` (`from_profile`), `rp/connector_registry.hpp` and `src/veeam_m365_connector.cpp` (`ConnectorOptions::client`), `rp/result_builder.hpp` and `src/result_builder.cpp` (`result_client`), `src/run_pipeline.{hpp,cpp}` (`PipelineArgs::client`, `client_id`, `profile_file`; the profile through the run; `clean_restore_targets`), `src/restore_command.cpp` and `src/test_command.cpp` (`--profile-file`), `rp/service_jobs.hpp` and `src/service_jobs.cpp` (`client`), `rp/service_recovery.hpp` and `src/service_recovery.cpp` (the record's `client`, the makers, `is_records_client` gone), `src/service_loop.cpp` (the clean by the record), `src/worker_body.cpp`, `src/graph_command.cpp` (the listing shared), `src/config_check.cpp`, `src/veeam_command.cpp`, `src/cli.cpp` and `rp/cli.hpp` (usage), `CMakeLists.txt` (the exe tests), the tests of each, `tests/secret_audit_test.cpp`; `docs/worker-config.md`, `docs/verification.md`, `docs/testing.md`, `docs/glossary.md`, `CLAUDE.md`.

---

## 2026-10-09 — W4.9 code review (the second), findings 1 to 4 and 9: the scan's tests import off Windows and the scan runs on a Python before 3.12; `name: value` and the two headers are keyed secrets; a placeholder is a closed form, not a first character; the recorder runs over a real restore POST (proposed)

A second review of the branch (`/code-review high`, 2026-10-09) gave ten findings. Five are fixed here, test-first; 5 to 8 and 10 are open (below). Amends the build notes below where they describe the keyed rule and cases C and I.

1. **The scan's tests import where there is no `_winapi`.** The junction test's `skipUnless` asked `__import__("_winapi")` when the class was defined, so the module couldn't be imported on Ubuntu and CI's `fixture-scan` job would have failed at its first step. The condition is `sys.platform == "win32"` and the import is inside the test. A test imports the module in a child process with `_winapi` taken away.
2. **The scan runs on a Python before 3.12.** `Path.is_junction()` is 3.12's and CMake registers the ctest test with any Python 3. `is_junction(entry)` asks the method where there is one and the entry's reparse tag otherwise. The tests run on 3.9 too (their helper no longer uses `write_text(newline=)`), with the junction test once more under a `Path` without the method.
3. **`name: value` and the two headers.** `redact()` masks `password: x` for its colon-form keys and the whole value of `Authorization:` and `Proxy-Authorization:`; the scan had neither form. It can't take `redact()`'s "the rest of the line": over-redacting prose is harmless, reporting prose would get the scan switched off (`# ... a one-time password: bytes only, never a file.` in a committed script). So a key's value is the rest of the line only when that is one word or one quoted string, and a header's is its scheme and the word after it. Not caught, knowingly: an unquoted value of several words after a colon.
4. **A placeholder is a closed form.** Any keyed value starting with `[`, `<`, `$`, `(` or a backtick passed, a real password starting with one of them included. Now: `[...]`, `<...>` or a backtick form that is the whole value, or a script's variable (whole, or calling a method), `$(`, `(Verb-Noun`, `($x`, `([Type]`, `[Type]::`, `[type]$x`. Not told apart, knowingly: a password that reads as a variable name (`$ecret1`). The committed trees needed no new allowlist entry under either change.
5. **(Finding 9.) The recorder over a real restore POST.** No audit case recorded the one exchange whose request carries the exported credential: case I ran without `--record`, case C's `--record` is on the fake connector. Case I now records (`Replay::run`'s `more` arguments) and requires the four restore POSTs' fixtures, each with its `request_body` and the credential's two keys in it, before the search; case C's two flushes run with `--record` and their `cloud/` folders are searched. Both were green on their first run: no leak found, and the recorder was not broken on purpose to see the case fail.

**Open from this review:** a UTF-16 file is read but not decoded (5); the PFX and RSA openings miss a DER of 16 to 64 KiB (6) and `ec_pkcs8` is P-256 only (7), in both halves; staleness is per allowlist entry, not per value (8); no case asserts that the sentinel tokens were handed out and used (10).

**Runs:** the scan's 32 tests on Python 3.12 and 3.9; the scan over the seven trees, 1143 files, 12 allowed, 0 findings; `rptests "[secret_audit]"` 17 cases; `ctest --preset dev` 2119 tests, 0 failed (the live tests skipped).

## 2026-10-09 — W4.9 build notes, the planted leaks and the live check: no secret reaches anything the Worker writes; every planted one was caught; the committed trees are clean (proposed)

Amends the W4.9 entry below where it says so; nothing here reopens a point. The build was made test-first in two steps (the fixture scan, red on its 23 unit tests before the script existed; the sentinel audit, its sixteen cases green on their first full run), then the audit was shown to fail on planted leaks, then run live.

1. **What the entry didn't say, now decided.**
   - **A script's variable or call is no value** (point 5's placeholder rule): the first scan over the trees reported eight `keyed_secret` findings in `docs/api/veeam-m365/*.ps1`, every one `password = $pw`, `refresh_token = $old` or `refresh_token = (Get-VeeamRefreshToken)`: where a value comes from, not a value. A value starting with `$` or `(` is a placeholder too. The ninth finding was the scrub placeholder JWT under `"access_token"` in `graph/token-200.json`, which the keyed rule reports beside the JWT rule, so that file has two allowlist entries, one per shape, and the unit test expects both.
   - **The claims challenge needs no entry**: `eyJhY2Nlc3NfdG9rZW4iOnt9fQ==` has 23 base64url characters after `eyJ`, under the rule's 37, so it isn't a shape; the entry's point 7 listed it from a looser pre-scan. Nor do the two docs with `<Base64 PFX>` and `…`: the placeholder rule covers them. The allowlist holds nine entries over six files; the scan over the repository reads 1,135 files in the five trees, 11 allowed matches, 0 findings, 0 stale entries.
   - **`pem_private_key`'s value is the block's body**: the Base64 between the BEGIN and END lines without white space and without the `\n` a JSON string escapes a line break as, so an allowlist entry can name a key once for the PEM and the Base64-opening shapes alike (`key-files.json`'s RFC 8032 key 1). `signing-v1/cases.json`'s second Base64 document (`eyJleHBlY3RlZF9raW5kIjoi`) is run into a preceding base64url character and is no shape; one prefix is allowed, not two.
   - **The audit's own secrets never meet the Harness's**: the Harness's defaults stay (`Sentinel-Veeam-Password-9c2e`, the shared PFX, key 1); the audit's are `Sentinel-Audit-...`, a PFX with a fresh key and key 2, so a hit names a run of the audit and nothing else.
   - **The exported credential is Base64 of its own words** (`exported_pfx()`), since a restore body carries a Base64 PFX and the connector refuses one that isn't Base64.
   - **Two labs moved into headers unchanged**, so the audit runs on them: `restore_replay_test.cpp`'s `Replay` and its helpers into `tests/replay_lab.hpp` (`rp::test::replay_lab`, one seam added, `load_secrets`), `worker_body_test.cpp`'s `BodyLab`, `HoldConnector` and helpers into `tests/worker_body_lab.hpp` (`rp::test::worker_body_lab`). `FakeExporter` (`tests/veeam_restore_lab.hpp`) gained a `password` member beside `pfx`, its default the constant it returned before.
   - **Case I keeps the recording's account**, `AUDIT-HOST\rp-veeam`: the duplicate check looks for sessions `rp-veeam` started, and the recording holds those. Its REQUIRE counts the four restore POSTs that carried the exported credential to Veeam, where it belongs, and the audit finds it nowhere else.
   - **Case D is a missing item**, not a mismatch: an after listing without the SharePoint copy makes the `fail` the entry wanted with the fewest moving parts; the `fail` path's writers are the same.
   - **`vault set` runs through its Env** (`VaultCommandEnv::read_secret`), as the entry's correction said; its new value is a sentinel of its own, added to the search set.
   - **The scan is a ctest test when CMake finds a Python 3** (`find_package(Python3 COMPONENTS Interpreter)`, a warning otherwise), label `scan`, so `tools/run_coverage.ps1`'s `ctest -L exe` leaves it out.

2. **The audit proves it can fail (point 8).** One scratch change planted a sentinel into eleven writers at once, each a literal the audit knows, and `rptests "[secret_audit]"` was run: 16 of 16 cases failed, 116 assertions, each hit naming the output and the label and never the bytes. Caught: `run_pipeline.cpp`'s run line (every case's stdout: `restore stdout holds veeam_password`, `test --json stdout ...`, ...); its `restore error:` line (`test, the connector refused stderr`); `service_loop.cpp`'s `scheduler started` line, bare prose the redacting sink doesn't know (`temp/logs/worker.log`, 7 times over the J cases); `evidence_builder.cpp`'s CSV header (`temp/runs/audit-d/items.csv` and the others, and again as `cloud request 2 part 4 content`, the uploaded `items.csv`); its session log, planted with the exported PFX's password, which the builder's withholding doesn't know (`temp/runs/audit-h/veeam-session.log`, `cloud request 2 part 5 content`); `heartbeat.cpp`'s body (`cloud request 1 body`); `uploader.cpp`, a sixth part (`cloud request 2 part 6 content`); `recording_http_client.cpp`, every fixture written (`temp/rec/graph/001-...` to `035-...`, `temp/rec/tsa/001-post-stamp.json`, `temp/rec-graph/...`, `temp/rec-veeam/veeam/001-post-v8-token.json` to `004-...`: planted with the exported PFX's password, since the recorder itself refuses a file holding the Veeam password); `service_recovery.cpp`'s `client_id` (`temp/state/running.json`, and `running.json at write 1` and `2`); `test_command.cpp`'s `--json` writer (`temp/run.json`); and `vault_command.cpp`'s `vault list`, planted with a JWT-shaped literal (`vault list stdout holds shape: jwt`). Not planted: `result.json` and `signature.json` (a planted string breaks the validation or the signature before the audit runs, and the result's own `holds_secret` refusal has its tests since W4.2), the outbox's `manifest.json` (its `last_error` is held to the upload codes; the file is read by the same folder walk that caught `running.json` and `items.csv` beside it) and the TSA's request (DER the fake TSA must parse; the Cloud's parts cover "sent to a third party"). The scratch change was removed and the audit is green again; nothing of it is committed.

3. **A bug in the audit's own first version, found by the audit.** `--evidence <root>` was handed a `std::string_view` of a temporary `std::string`, so four cases ran with a dangling argument: three ended `config error: --evidence` and one wrote its run folder under the working directory, in a folder named by the bytes the freed memory then held (the lab's library ID, `b!XQgI...`), complete and signed. The views now point at members that outlive them. The lesson for the Harness's callers is in the test's comment; the stray folder was removed.

4. **The audit found no leak.** Sixteen cases, 6,578 assertions, clean on the first full run (before the planting) and after it; seventeen, 7,150, after the review. Beside the layers the entry listed, nothing had to change in `rpcore`: the task's one code change outside `tests/`, `tools/` and the workflow is none.

5. **The runs.** `ctest --preset dev` 2,117 of 2,118, the one failure the pre-existing `set_dacl` test of the Open list below; the coverage gate passing at **96.7% line (14,975 of 15,485)** with every strict file at 100% (`run_coverage.ps1`'s one-process `rptests` run, the 87 exe tests), on commit cb471f6; the scan's 29 unit tests and the repository scan (1,143 files in seven trees, 12 allowed matches) in under three seconds; the seventeen audit cases in under four seconds together (case I, the replay, 1.6 s). No Worker CI run has started since 2026-10-03 (GitHub billing): the Ubuntu `fixture-scan` job is written and untried there.

6. **The live check, 2026-10-09, elevated, on the lab machine; evidence `docs/api/veeam-lab/w4.9-1` to `w4.9-4`, the harness `w4.9-harness/w49-live.ps1` over the W4.8 harness.** With the real vault and the lab's config, commit cb471f6:
   - (a) `rpworker test --mail 2 --sp 1 --od 1 --run-id w49-1 --evidence <w49>\runs --outbox <w49>\box --record <w49>\rec-w49-1`: no session Working before, the targets empty; 4 of 4 restored in three `Success` sessions, `status pass: 4 of 4 item(s) verified: manifest 3, fields 1, metadata 0`, exit 0; `signed`, `timestamped 2026-10-09T10:19:39Z` by DigiCert, `queued`, `recorded 144 exchange(s)`; both verifiers `verified ... timestamp 2026-10-09T10:19:39Z` for the queued folder; cleaned after.
   - (b) The service through the W4.8 harness: installed with the config copy (the stub Cloud on 8443, the stub jobs file), the grants by hand, started; a job of 1, 1, 1 taken 30 s after the drop, `pass`, 3 of 3, signed, timestamped, queued and sent by the loop's own flush in the same second (`run w49-2: ended pass; queued`, `sent w49-2`, then `skipped w49-2: already sent`); two heartbeats at the stub, no `Authorization`; `stopped RestoreProof in 0.2 s`; the grants taken away and the service uninstalled.
   - (c) The search, `Search-W49`: every file under `<w49>` (the run folder in `box\outbox\w49-1`, the recording's 144 fixtures), `sent\w49-2`, `logs\worker.log` (the whole service run), `state\` (the `done\w49-2` mark), the config copy's folder and the harness's temp folder (the stub's log), **171 files, 1,207,952 bytes**, searched for 123 values: the vault's four, the PFX's DER as hex and its Base64 in 32-character pieces, the signing seed in Base64 and hex, each read from Credential Manager and the PFX file and never printed: **0 hits**. The shape scan (the fixture scan with an empty allowlist) over the same roots: clean, but for `stub-key.pem` in the harness's temp folder, the stub Cloud's own TLS private key that `Initialize-W48Harness` writes with OpenSSL: the harness's file, not the Worker's, and the scan telling a private key from the rest as it should. The account's name appeared nowhere (no hold ran).
   - (d) `sent\w49-2` moved beside the run's folder under `<w49>\sent-by-service`; the config copy, `state\` and `logs\` taken away; `sc query` 1060; the five `runs\` and two `sent\` folders of earlier tasks as they were; no session Working; `graph list` 0 in all three targets. **Nothing is installed.** `<w49>` is kept outside the repo (`C:\ProgramData\RestoreProof\w49`), as is `w49-attempt1`, a first attempt whose run went through alike but whose step (a) evidence wasn't saved: `Test-W48Folder` writes the public key file under the W4.8 harness's folder, which the harness makes in step (b); the script now makes it first.

7. **The code review (eight angles, nine findings; 1 to 7 and 9 confirmed and fixed test-first in commit 102ec26; 8 is this entry).**
   - 1 and 2: the fixture scan's keyed rule was narrower than `redact()`'s, though it claimed the same list: a name joined by a separator (`veeam_password`, `graph_cert_password`, `db.password`), the JSON-escaped form inside a string (`{\"password\":\"...\"}`) and the keys `pfx`, `sig` and `authorization` were never matched, and a `"quoted"` or `'quoted'` form value was read as empty and so as a placeholder. All four are matched now; a value that starts with `[`, `<`, `$`, `(` or a backtick is a placeholder (a bracketed placeholder, a script's variable, call or expression, Markdown's code), which is what the wider rule met in the harnesses' PowerShell and Python (`RP_VEEAM_PASSWORD = [RpSpikeCred]::Read(...)`, `$pfx = [Convert]::...`, `` `sig=` ``) and one more allowlist entry covers the stub Cloud's own word `present` under `authorization`.
   - 3: `Outputs::add_folder` opened each file without checking the stream, so a file held open would have been searched as zero bytes and passed; it REQUIREs the open, a clean read and the file's size now.
   - 4 and 5: an unreadable file or an absolute `--tree` escaped as a traceback with Python's exit 1; an unreadable file is now `fixture secret scan: a file can't be read: <path>`, exit 2, never a pass, an absolute tree is named from the root, and no symbolic link or junction is entered (a junction up the tree looped). Each has its unit test, the junction's through `_winapi.CreateJunction`.
   - 6: the trees gained `tests/e2e` and `lab/tenant.md`, both clean. Not the rest of `docs/`: a scan over it finds this log and `docs/testing.md` describing the shapes (the placeholder JWT quoted, `MHcCAQEEI`, `"password": "..."`) and the W4.3 entry quoting `-----BEGIN PRIVATE KEY-----` in prose, a block with no END line whose "body" is the rest of the file, which no value allowlist can pin. The reason stands in `docs/testing.md`.
   - 7: the C++ shapes and the Python regexes differed in two places (a PEM label of any text ending in `PRIVATE KEY`, a `Bearer` run into `_`) and no test held one to the other. One list of examples, `tools/secret_shapes_cases.json` (38 shaped texts, 32 clean), is read by the scan's unit test and by a new audit case, and the two rules are the regexes' now (`is_private_key_label`, `is_word_char`).
   - 9: a no-op path conversion and a constant inside a loop condition, removed.

**Open**, beside the entry's own.
- `worker body: a run folder that can't be listed is not closed` fails in this session's shells, elevated, on `SetNamedSecurityInfoW` answering 2 (`tests/owner_lab.hpp`'s `set_dacl`), with `main`'s own test source as with the moved lab, and passed in the same session's coverage run under OpenCppCoverage; it is not the audit's and is left as found for its own look.
- The `fixture-scan` CI job and the Windows job are untried in CI (billing), as every job since 2026-10-03.
- The scan's keyed rule is `redact()`'s list by hand in two places (`SECRET_KEYS`, `redact.hpp`'s comment); a shared vector of the keys would hold them together.

---

## 2026-10-09 — W4.9 (#52): the secret-redaction audit. One ctest test runs every path of the pipeline, the commands and the service's loop on fixtures with five sentinel secrets and searches everything they wrote for every sentinel, every value derived from one and every secret shape; one stdlib Python script, run by ctest and by CI, searches the committed fixture, vector and evidence trees for the shapes alone, against an allowlist by file, shape and value (recorded before the build; the owner left the open points to the build)

W4.9 (#52) is the audit CLAUDE.md's "Secrets" rule has promised since W1.3: "a sentinel-grep test (W4.9) enforces this". Done when: "The audit test passes and is part of ctest." This entry works from issue #52, the owner's scope for the task (2026-10-09), every sentence of this log that names W4.9 (W4.2's point 6, W4.3's Open, W4.4's Open, W4.5's Open, W4.7's point 7 and Open, W4.8's Open and the W4.8 build notes' Open), CLAUDE.md "Secrets", and the code: `rp/redact.hpp`, `rp/secrets.hpp`, `rp/recording_http_client.hpp`, `rp/evidence_builder.hpp`, `rp/service_log.hpp`, `src/service_log_stream.cpp`, `src/worker_body.cpp`, `src/run_folder_tail.cpp` and every writer under `src/`. No code is written yet; the build notes will record what the build finds, and the owner's two stops hold: a non-negotiable rule that would have to change, or a real leak, which is shown first.

**What the investigation found, since the points below rest on it.**

- **Three layers already stand between a secret and a file, each a convention or a rule at one place, and no test today walks every output of every path for every secret.** (1) `rp::redact()` masks keyed secrets, JWTs, `Bearer` tokens, URL userinfo and PEM private key blocks in every logged string, and the service log's one sink (`rp::ServiceLogSink`) applies it to every line by construction (W4.7). (2) The `--record` recorder (`rp::FixtureRecorder`, Q2.1) learns every secret an exchange carries and refuses a fixture that still holds one, a JWT shape or an unscrubbed `tempauth`/`client_assertion` value. (3) The run folder's builder (W4.2, W4.3) is handed `rp::secret_values(secrets)` plus the signing key's text and `SigningKey::secret_shapes()` (the seed in Base64 and hex), withholds a log line or CSV row that holds one and refuses a result that does; `run_folder_tail.cpp` is its one caller. Neither stdout, stderr, `--json`'s file, `running.json`, the outbox's `manifest.json`, the heartbeat's body nor the uploaded parts pass any of the three; they are clean by what is put in them, which is what an audit is for.
- **The secret values.** `rp::secret_values` lists four of the five: the Veeam password, the Graph PFX's Base64, its password and the signing key's text. **`veeam_username` is not a secret value**: the W4.5 entry's own comment in `rp/secrets.hpp` ("The user name is no secret"), `redact()` (no `username` key) and the recorder (which never learns it) agree, and the W4.12 entry calls the vault's five "the user name among them" only as a list of names. The account's bare name reaches Veeam's `initiatedBy`, the restore's duplicate check and, since W4.8, the `waiting for Veeam: <n> session(s) of <account> still Working since <time>` line of the log. Three more values exist only at run time: the Veeam access and refresh tokens, the Graph client assertion (a JWT the Worker signs with the PFX's key) and the access token it gets for it, and the restore credential Veeam's organisation app certificate is exported as per restore POST (`rp::ExportedPfx`: a Base64 PFX and a 32-byte random password, W2.5), which never leaves `restore_sample` and is wiped.
- **The tests already run every path on fakes with sentinel-shaped secrets, and can read a real `worker.log`.** The restore tests' Harness (`tests/restore_command_lab.hpp`) runs `rpworker restore`, `test`, `test --json`, `test --evidence [--outbox] [--record]` through `run_pipeline` with a fake connector, Graph and the downloads on `FakeHttpClient`s, the test-only TSA, a fake run mutex and `load_secrets` the test chooses (today `Sentinel-Veeam-Password-9c2e`, the lab's generated PFX under `Sentinel-Targets-PFX-Password-3b9d`, RFC 8032's test key 1). `tests/worker_body_test.cpp`'s `BodyLab` runs the service's loop (`rp::make_worker_loop_env`) on that Harness with a fake Cloud and fake locks: one job to `sent\`, a killed run's record closed, an invalid job, the hold. `tests/restore_replay_test.cpp`'s `Replay` runs the whole command on the **real** `veeam_m365` connector over the recorded live runs, with `tests/veeam_restore_lab.hpp`'s `FakeExporter` handing out `Sentinel-Fake-PFX-Base64-5e1c` and `Sentinel-Fake-PFX-Password-5e1c` as the exported credential. `rp::make_service_logger(folder, level, LogLimits)` writes a real, rotating, redacting `worker.log` into any folder, which W4.7's point 7 put there for this task. Every `FakeHttpClient` keeps every request it was sent (`requests()`, multipart `parts` included), so what went to the fake Cloud and the fake TSA can be searched too. `config check`, `vault list`, `vault test` and `signer public-key` run through `rp::run_cli` with `--vault <file>` on a real DPAPI vault in a temp folder (as `tests/vault_test.cpp` and `tests/config_check_test.cpp` do). Nothing in this needs the network, a sleep, the real vault, the service or `%ProgramData%`.
- **The writers.** Everything the Worker writes goes through one of: the two streams a command is handed (`std::cout`/`std::cerr` only in `app/main.cpp`; in the service `rp::LogLineStream`s into the log); a logger (the commands' stderr logger, the service's file logger); `rp::write_file_atomically` (`--json`, every file of a run folder, `manifest.json`, `running.json`, the `state\done\` marks); the recorder's `std::ofstream` (fixtures); `vault.cpp`'s `WriteFile` (the vault blob, DPAPI-encrypted); `console_input.cpp`'s `WriteFile` (the prompt text of `vault set`); and two HTTP clients that send to a third party, the Cloud's (`src/uploader.cpp`, `src/heartbeat.cpp`) and the TSA's. Veeam and Graph are not third parties in this sense: the token request to Veeam carries the password by design, the restore POST the exported PFX, Graph's token request the client assertion; what is sent to them is not an output of the audit, what comes back and is written is.
- **`what()` reaches stderr in several places** (`run_pipeline.cpp`'s `say`, `check error:`, `restore error:`, the commands' `config error:`/`veeam error:`/`graph error:`) and the log in others. Those texts are built from fixed words, Veeam's and Graph's error bodies cut to a length, paths and names, never from a secret the Worker holds; a server that echoed a credential in prose would reach stderr unredacted (redact() masks keyed forms, not bare prose). No recorded answer does, and the audit searches what the recorded failure answers produce.
- **The committed data trees hold five kinds of secret-shaped text, every one explainable.** `worker/tests/fixtures/graph/token-200.json` (and the lab's README and `graph_fixtures.py` that write it) holds the scrub placeholder `eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzY3J1YmJlZCI6dHJ1ZX0.` (a JWT with `alg` `none` and the claim `{"scrubbed":true}`); `graph/api-insufficient-claims-401.json` holds a claims challenge, `eyJhY2Nlc3NfdG9rZW4iOnt9fQ==`, Base64 of `{"access_token":{}}`; `shared/testdata/signing-v1/cases.json` holds Base64 of result documents and items (`eyJhdHRhY2htZW50cyI6...`, `eyJleHBlY3RlZF9raW5kIjoi...`: Base64 of `{"` is `eyJ` whatever follows); `shared/testdata/signing-v1/keys.json` and `key-files.json` hold RFC 8032's published test keys 1 and 2 as PKCS#8 Base64 and PEM; `shared/testdata/timestamp-v1/keys.json` holds the test-only TSA's EC private key, made for the vectors and trusted by no build but through a CA file a test writes. `docs/api/veeam-feasibility.md` and `veeam-restore-flow.md` show `"applicationCertificate": "<Base64 PFX>"` and `"…"`: placeholders. A pre-scan for `password=`/`"password":` and the other keyed forms with a value other than `[REDACTED]`/`SCRUBBED`, for `Bearer <token>`, and for the Base64 signatures of a PKCS#12 file and of RSA, EC and Ed25519 private keys found nothing else. Source code (`worker/tests/*.cpp`, `lab/tests/*.py`) holds the same RFC keys as literals; it is read in review and is not a recorded fixture.
- **Coverage.** The gate (`tools/coverage_gate.py`) measures `src/`, `include/` and `app/` through `rptests.exe` and the exe tests; test code under `tests/` and tools under `tools/` are outside it. Python is not yet asked for by `CMakeLists.txt`; CI's Windows job has it (the gate's self-tests), and the dev machine has it.

**Decision.**

1. **Two audits, one list of shapes.** (a) **The sentinel audit**, `tests/secret_audit_test.cpp` over `tests/secret_audit_lab.hpp`, a Catch2 test case per path with the tag `[secret_audit]`, part of `rptests` and so of ctest: it runs each path of point 3 with the five secrets of point 2, collects every output of point 4 and searches each for every value of point 2, as written, JSON-escaped and, for the Base64 values, in 32-character pieces, and for every shape of point 5. (b) **The fixture scan**, `worker/tools/fixture_secret_scan.py`, stdlib only (`docs/decisions.md` 2026-09-24's rule for the gate): it reads the data trees of point 6 as bytes, decodes them as UTF-8 where they are (a file that isn't is searched as Latin-1 text, so no byte is skipped), reports every match of a shape of point 5 that the allowlist of point 7 doesn't name, and exits 1 on any. It runs as a ctest test (`fixture secret scan`, label `scan`, `${Python3_EXECUTABLE} tools/fixture_secret_scan.py --root ..`, registered when `find_package(Python3 COMPONENTS Interpreter)` finds one and a CMake warning when not) and in CI as a job of its own in `worker.yml`, `fixture-scan` on `ubuntu-latest`, needing no compiler, beside the Windows build job that hasn't started since 2026-10-03; its self-tests, `tools/test_fixture_secret_scan.py`, run with the gate's (`python -m unittest discover -s tools`) in both jobs. Neither audit is in the coverage gate: both are test code, and the gate's rules measure `rpcore`. *Rejected:* one implementation of the shapes called from both sides (rptests would need Python, or the script a C++ build; the two lists are small, named alike in `docs/testing.md`'s one table, and each side's self-test holds it to the same examples); a C++ scan of the fixture trees inside rptests (CI without a Worker build would never run it); the scan in `pr-guards.yml` (`pull_request` only; a push to `main` must run it too).

2. **The five sentinels, and the values derived from them.** The audit's `load_secrets` answers:
   - `veeam_username` `AUDIT-HOST\rp-veeam-audit-2d7f` — **not a secret value**, by the finding above. The audit counts where it appears (the `waiting for Veeam` line, Veeam's `initiatedBy` in a fixture) and fails on none of them; the line stays as W4.8 built it. This closes the W4.8 build notes' Open point.
   - `veeam_password` `Sentinel-Audit-Veeam-Password-2d7f`.
   - `graph_cert_pfx_base64`: a PFX made for the audit by `tests/test_certs.hpp`'s `make_pfx` (`make_client_cert`, a fresh RSA key, valid at `graph_lab::kNow`) under `graph_cert_password` `Sentinel-Audit-PFX-Password-2d7f`. The PFX must open, since the pipeline builds a client assertion from it; what is searched is its Base64 text, its DER bytes and the DER's hex.
   - `signing_key_base64`: RFC 8032's published test key 2 (`tests/signing_lab.hpp`'s `signing_key2_base64()`), never key 1, which the Harness uses by default, so the audit's hits can't be the Harness's values; searched as its text and as `SigningKey::secret_shapes()` gives the seed, Base64 and hex, which is what the run folder's builder is handed (W4.3 point 3).
   - **Derived at run time**, each a sentinel the fakes hand out or a value read back from them: the Veeam access and refresh tokens the fake Veeam's `/v8/token` answers (`Sentinel-Audit-Veeam-Access-Token-2d7f-…`, 40+ characters, and the refresh token alike), the Graph access token the fake token endpoint answers (`Sentinel-Audit-Graph-Access-Token-2d7f`), the exported restore credential (`FakeExporter`'s `pfx` and `password`, set to `Sentinel-Audit-Exported-PFX-2d7f` and `Sentinel-Audit-Exported-PFX-Password-2d7f`), and the client assertion, which the audit takes from the fake token endpoint's requests after the run (`client_assertion=` in the form body) and searches as a value, beside the JWT shape that would catch any other.
   - The searched set is one list of `{label, bytes}`; a hit names the output and the label, never the bytes. Every value is at least `kMinRecordedSecret` long. *Rejected:* the Harness's own sentinels (shared with two hundred tests, so a hit couldn't say which run wrote it); a PFX without a key (the pipeline would stop at the certificate check); searching the hex of the PFX's private key (it is inside the PFX, encrypted under the password; the PFX's bytes and Base64 are what a leak would carry).

3. **The paths.** Each is a test case, failures first, and each is needed to reach a writer or a layer no other reaches:
   - **A: `restore`** on the Harness: a pass with the fake connector, stdout, stderr and the command logger (W2.8's per-item rows, the check table, the clean lines, the timings).
   - **B: `test --json`**: the `--json` file (the result's canonical bytes, unsigned).
   - **C: `test --evidence --outbox --record`, a pass**, the TSA answering: the run folder (`items.csv`, `veeam-session.log`, `signature.json`, `timestamp.tst`, `result.json`), the queued folder and its `manifest.json`, the recording (`graph/`, `download/`, `tsa/`), then `rpworker outbox flush` twice through `rp::run_outbox_command` on a fake Cloud: 500 (kept, `upload_http_500`) and then 202 (sent): the flush's lines, the moved folder, the manifest with `sent_at`, and every part of the upload the fake Cloud received.
   - **D: a fail**: one item's copy changed in the after read (W3.2's mismatch), so the `fail` status, VERDICT `failed` rows and `items.csv`'s mismatch cells are written.
   - **E: an error before the restore**, Graph refusing the before snapshot's token (the recorded `token-bad-signature-401` answer): `check error: ...; nothing was restored`, exit 2, a result with `null` steps, signed.
   - **F: an error in the restore phase**, the fake connector throwing `connector::AuthError`: `restore error:`, the `restore_sent` text, the clean after skipped.
   - **G: `result_invalid`**: the fake connector's `describe()` naming a type the schema doesn't know, so the result is refused, the folder left with the two text files, exit 1; then the service's `close_run` (`BodyLab`) closes that folder as `error result_invalid`, signed and queued: a result written afterwards (W4.8 point 7).
   - **H: the TSA failing** (a 503 three times, no wait): `timestamp warning: ...`, a folder without a token.
   - **I: the real connector's restore POST**, `Replay` over `recordings/w34-live-run1/` (the W3.4 live run: the clean before and after, four restore sessions, eleven items), the fake Veeam's token answer replaced by the audit's sentinel tokens and the exporter's values replaced by the audit's: the one path on which the Veeam sign-in, the Bearer header, the exported PFX and its password, Veeam's own words and `GET /v8/RestoreSessions` are real code over recorded answers. `Replay` moves from `restore_replay_test.cpp` to `tests/replay_lab.hpp` with one seam added, `load_secrets` (today's values its default), and `FakeExporter` gets a `password` member beside `pfx` (today's constant its default); both files use them.
   - **J: the service's loop** on `BodyLab` (which moves, with `HoldConnector` and its helpers, from `worker_body_test.cpp` to `tests/worker_body_lab.hpp`, unchanged) with the service's own log, `rp::make_service_logger(<temp>\logs, trace, LogLimits{1 MiB, 5})`, as `context->logger`, so every line of the loop and of the runs goes through the redacting sink into a real `worker.log`: one job to `sent\` (the heartbeat, the record at each of its writes, the flush, the `done` mark), the same job skipped, a jobs file that isn't JSON (`jobs error: <file>: not JSON`), a job that is no job (`error job_invalid`), a record left by a killed run closed as `error interrupted` after a restore request with the hold's `waiting for Veeam` line and the recovery clean (the account's name appears here and is counted, point 2), and a close that fails because the vault can't be read (`couldn't be closed (vault)`). The log is flushed and closed before it is read; every `worker*.log` is searched.
   - **K: the commands that read the vault**, through `rp::run_cli` on a real DPAPI vault of the five sentinels in the temp folder: `config check --config <file> --vault <file>` (the masked names), `vault list`, `vault test`, `vault set` and `vault remove` through `rp::run_vault_command` with `VaultCommandEnv::read_secret` handing the value in (the test process has no console to type at and no stdin to give; `console_input.cpp`'s own two paths have their tests), `signer public-key` (the public PEM and `key <id>`), and `veeam list --record` and `graph list --hash --record` on their fixtures through `VeeamCommandEnv` and `GraphCommandEnv` with sentinel tokens. The vault file itself is searched too: DPAPI's blob must hold none of the plaintext.
   - Not a path: `vault grant` (changes an ACL, writes nothing of a value), `service install|uninstall|start|stop` (the SCM, no secret), `signer verify` (reads a folder and a public key), `outbox list` (covered by C's folders).

4. **What counts as an output.** For every path, all of: the two streams; the command logger's text (the Harness's stream sink) and, for J, the log files; every regular file under the test's temp folder, read recursively after the run (run folders, `outbox\`, `sent\`, `state\`, the recording, the `--json` file, the vault, the jobs file, the config: the last two the audit wrote itself and are searched anyway); every request the fake Cloud and the fake TSA received (URL, headers, body, every multipart part's name, filename, content type and bytes). Requests to the fake Veeam and Graph are not outputs (the finding above); their *answers* only matter through what the Worker writes of them. An output that is empty when it should hold something is a failure too: each path REQUIREs its own expected line or file first (the `status` line, `result.json` there, `sent <run>`), so an audit over nothing can't pass. *Rejected:* excluding the vault file (DPAPI encrypts, so the plaintext mustn't be there, and a vault written in clear would be the leak); searching only the files the issue names (every writer found above is a file the issue didn't know).

5. **The shapes**, searched in every output by the sentinel audit and in every data file by the fixture scan, one table in `docs/testing.md`:
   - **JWT**: `eyJ` not run into a preceding base64url character, then 37 or more base64url characters and dots (the recorder's `kMinJwtTail`; redact's `kJwtStart`).
   - **Bearer**: `Bearer`, blanks, then 20 or more of `A-Z a-z 0-9 . _ ~ + / = -`, unless `=` follows the run (an auth-param, `Bearer realm=`). `Bearer [REDACTED]` doesn't match.
   - **PEM private key**: `-----BEGIN <label>-----` whose label ends in `PRIVATE KEY`, redact's rule; a `PUBLIC KEY` or `CERTIFICATE` block is no shape.
   - **Private key DER in Base64**, by the Base64 of each format's fixed opening bytes, which a certificate or a signed token never has: Ed25519 PKCS#8 `MC4CAQAwBQYDK2VwBCIEI` plus its 43 characters (the whole key: `SigningKey::from_base64`'s 48 bytes); RSA PKCS#8 `MII..[AQgw]IBADANBgkqhkiG9w0BAQEFAASC`; RSA PKCS#1 `MII..[AQgw]IBAAKCA`; EC PKCS#8 `MIG.AgEAMBMGByqGSM49` and SEC1 `MHcCAQEEI`; and a **PKCS#12 file**, `MII..[AQgw]IBAzCC` (a PFX's `SEQUENCE, INTEGER 3, SEQUENCE`). A bare `MII...` run is a certificate or a CMS token, public, and is no shape: the fixture trees hold hundreds (`rest-certificate.pem`, the TSA fixtures, the timestamp vectors).
   - **A keyed secret with a value**, the fixture scan only: `"<key>": "<value>"` or `<key>=<value>` for the keys `redact()` masks (`password`, `client_secret`, `client_assertion`, `refresh_token`, `access_token`, `id_token`, `tempauth`, `applicationCertificate`, `applicationCertificatePassword`, `signing_key`, `signing_key_base64`, `signing_private_key`, `pfx_base64`), where the value is not `[REDACTED]`, `SCRUBBED`, empty, `null`, or a placeholder in brackets or angle brackets or starting with an ellipsis. A match with a fixed-word value (`grant_type=password`) has the key `grant_type`, not `password`, so it isn't one. In the sentinel audit this rule is the values' own: a sentinel in any form is found by its bytes.
   - What a shape finds in an output of the sentinel audit is a failure unless it is one of: the audit's own public key PEM (`PUBLIC KEY`, no shape anyway), `signature.json`'s 88-character signature (no shape), the `timestamp.tst` bytes and the recording's `body_base64` of a TSA exchange (a TimeStampResp, `MII..` then `ADAgEAMII` and the CMS `GCSqGSIb3DQEHAq`: not a shape, since position 6 isn't `IB`). No allowlist is needed on this side; a shape hit is a leak until shown otherwise.

6. **The fixture scan's trees**: `worker/tests/fixtures/`, `shared/testdata/`, `docs/api/` (the lab evidence and the recording scripts), `lab/canary/` and `lab/seed-manifest.json`, every file whatever its extension, nothing under a `.venv`, `__pycache__`, `build` or `.git`. Not the source trees (`worker/src`, `worker/tests/*.cpp`, `lab/seeder`, `lab/tests`, `cloud/`): a secret in code is caught by review and by the vault rule (no secret is read from an environment variable or a file but the vault), and their RFC 8032 literals would need the allowlist to say the same thing three more times. *Rejected:* the whole repository (the `.venv` of `lab/` alone holds `cacert.pem` and the libraries' own test keys); only `worker/tests/fixtures/` (the issue's wording; the vectors and the evidence are recorded fixtures by another name).

7. **The allowlist**, `worker/tools/fixture_secret_scan_allowlist.json`, one entry per file, each with the file's repo-relative path, the shape it may hold, a `reason` sentence, and either `values` (the exact texts allowed) or `prefixes` (what an allowed text starts with) — never a file-wide pass for a shape without one of the two, so a new secret-shaped text in an allowed file still fails:
   - `worker/tests/fixtures/graph/token-200.json`, JWT, value `eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzY3J1YmJlZCI6dHJ1ZX0.`: the scrub placeholder the lab's `record-graph-fixtures` writes, an unsigned token with `alg` `none` and the claim `scrubbed`.
   - `worker/tests/fixtures/graph/api-insufficient-claims-401.json`, JWT, value `eyJhY2Nlc3NfdG9rZW4iOnt9fQ==`: Graph's claims challenge, Base64 of `{"access_token":{}}`, a public value the server asks the client to echo.
   - `shared/testdata/signing-v1/cases.json`, JWT, prefixes `eyJhdHRhY2htZW50cyI6` and `eyJleHBlY3RlZF9raW5kIjoi`: Base64 of a result document and of an item, which W4.3's cases give as text that isn't UTF-8.
   - `shared/testdata/signing-v1/keys.json` and `key-files.json`, Ed25519 PKCS#8 and PEM private key, values: RFC 8032's test keys 1 and 2 (`MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/...`, `MC4CAQAwBQYDK2VwBCIEIEzNCJso/...`) and the PEM blocks `key-files.json` makes of them: published, known to everyone, never signing anything real (W4.3 point 6).
   - `shared/testdata/timestamp-v1/keys.json`, PEM private key and EC PKCS#8, value: the test TSA's key as the file holds it: made once for the vectors (W4.4), trusted by no Worker build and by no verifier without a CA file a test writes.
   - `docs/api/veeam-feasibility.md`, `docs/api/veeam-restore-flow.md`: nothing to allow once the placeholder rule of point 5 holds (`<Base64 PFX>`, `…`); the build checks and adds an entry only if the rule doesn't cover a line.
   The build measures the trees once more and the list holds exactly what is there; an entry whose file no longer exists, or whose value or prefix matches nothing, fails the scan (a stale allowance is a hole). The self-tests plant each shape in a temp tree and see it caught, and each allowed value and see it pass, and a value that is almost the allowed one fail.

8. **The audit proves it can fail, by hand, once.** Before the audit is committed as passing, a scratch change writes one sentinel into each kind of output in turn (a stream, a log line through the redacting sink in a form `redact()` doesn't know, a run folder's file, the manifest, the heartbeat's body, an uploaded part, a fixture, `running.json`, the `--json` file) and the audit is seen to fail each time, naming the output and the label; the scratch change is then removed. The build notes record the list. The fixture scan's self-tests do the same for every shape, permanently.

9. **What a hit is.** A sentinel found in any output is a leak and the test fails naming the path, the output and the label; the owner is shown the leak first (the owner's second stop), the reproducing test is the audit's own case, and the fix is made under it. A shape found is a leak until explained; if the explanation is a public value (a certificate, a CMS token, a signature), the shape's rule is wrong and is tightened, never the output excluded. Nothing is excluded by file name on the sentinel side.

10. **Docs.** `docs/testing.md`: a section "The secret audit (W4.9)": the two halves, how to run each (`rptests "[secret_audit]"`, `ctest -R "secret"`, `python tools/fixture_secret_scan.py --root ..`), the one table of shapes, the allowlist's format and how to extend it (a new allowed file needs a value or prefix and a reason), how to add a new writer or path to the sentinel audit (a new output kind goes into the lab's collector; a new path is a new case that REQUIREs its own line first), and the point 8 list in the build notes; "What CI enforces" gains the row. `docs/worker-config.md` "Secrets": one sentence naming the audit and that `veeam_username` is no secret value. `docs/glossary.md`: "Sentinel audit", "Fixture scan", "Secret shape". CLAUDE.md: the status paragraph and the "Secrets" rule's last sentence, which becomes true: `tests/secret_audit_test.cpp` runs every path with sentinel secrets and searches every output, and `tools/fixture_secret_scan.py` searches the committed data trees for secret shapes in ctest and CI.

**Reason.** The rule CLAUDE.md has carried since W1.3 says a test enforces it, and until now none did: redaction, the recorder's refusals and the folder's withholding are each tested at their own seam, and a secret that reached an output none of them guards (stdout, `--json`, `manifest.json`, the heartbeat, a part) would be found by nobody. One test that puts a known value into every secret, runs every path and reads every output is the only way to say "no secret reaches anything the Worker writes" about the whole and not about a layer, and it is also the one test that will fail when a later task adds a writer and forgets. The fixture scan is the same promise for what is already committed: a recorded fixture is a file anyone can read on GitHub, and the three scrubbing layers (the lab's scripts, the recorder, the evidence's hand-scrubbing) are each a convention until a grep over the result holds them. Shapes, not values, because CI has no lab secret and must never be given one; an allowlist by value, not by file, because the files that legitimately hold a key shape hold exactly the published keys and nothing else may join them unseen.

**Alternatives rejected.** A sentinel audit that only greps the existing tests' outputs (two hundred tests with shared sentinels: a hit couldn't say which run wrote it, and no test collects the uploaded parts or a real `worker.log`). A single "run everything" test case (one failure hides the others; a case per path says which path leaked). Giving CI the lab's values as GitHub secrets to grep for (a secret in CI is a secret in one more place, and the scan must run on a fork and a laptop alike). Scanning values in the fixture trees from a local vault (the trees are committed; a developer's vault isn't the one the fixtures were recorded with). Marking the audit strict in the coverage gate (test code is outside the gate; what the audit covers is measured as the code it runs). Scanning source trees (point 6). A C++ reimplementation of the scan inside rptests (point 1).

**Open.**
- A server that echoes a credential in prose (the finding above) reaches stderr through `what()` unredacted; `redact()` over every `say` would over-redact fixed messages and is not done here. A W5.x hardening or the Cloud's own view of a Worker's lines may want it.
- `console_input.cpp`'s two input paths (`ReadConsoleW` without echo, stdin's first line) aren't run by the audit, which hands `vault set` its value through the Env; their own tests cover them, and neither writes a value anywhere.
- The screenshot capturer (W4.2) writes a PNG the audit never sees captured (the default answers `no_page`); a real capturer is a new output kind for its own task.
- The Cloud's side of the uploaded parts (C5.7): what the Cloud stores of a bundle, and whether its logs redact what a Worker sent, is C5.x's.
- W7.2's doctor: its lines are a new output kind for W7.2 to add to the audit.
- The fixture scan runs on CI's Ubuntu job; whether GitHub's billing lets any job start is outside this task (the dev machine runs both halves through ctest).

**Code, tests and docs with the build.** New: `tests/secret_audit_test.cpp`, `tests/secret_audit_lab.hpp`, `tests/replay_lab.hpp` (moved out of `tests/restore_replay_test.cpp`), `tests/worker_body_lab.hpp` (moved out of `tests/worker_body_test.cpp`), `tests/veeam_restore_lab.hpp`'s `FakeExporter::password`, `tools/fixture_secret_scan.py`, `tools/fixture_secret_scan_allowlist.json`, `tools/test_fixture_secret_scan.py`; `CMakeLists.txt` (the test source, `find_package(Python3)`, the `scan` test); `.github/workflows/worker.yml` (the `fixture-scan` job). Changed only if the audit finds a leak: whatever it names. Docs: `docs/testing.md`, `docs/worker-config.md`, `docs/glossary.md`, CLAUDE.md, this entry's build notes.

---

## 2026-10-09 — W4.8 code review (the second), findings 1 to 4 and 6: a run is marked as run before its record goes; no restore request after a session the record couldn't take; what escapes the pipeline keeps its report; a run folder that can't be listed whole is not closed

Amends points 4, 6, 7 and 9 of the W4.8 entry below. Each was seen failing first. Ten findings, ranked by the review; 1 to 4 fixed here, 6 settled in favour of the entry, 5 and 7 to 10 open.

1. **A run is marked as run before its record goes** (point 4, J2). J2 skipped a job whose run was queued, sent or had a folder under `runs\`; the outbox prunes `sent\` (30 days, the 500 MB cap), so a stub file that still named the job ran it again under the same run ID, and a second result was signed for it. The loop now writes an empty file `state\done\<run_id>` right before it deletes a record whose run had its run line (`ServiceLoopEnv::run_done` and `mark_run_done`, `Body::done_mark` in `src/worker_body.cpp`), and J2 skips a marked run: `skipped <run_id>: already run`. A run that ended before its run line made nothing and is not marked, so its job is offered again as before. A mark that can't be written keeps the record, so no job runs: `run <run_id>: couldn't be marked as run; running.json is kept`, once and hourly, `last_error` `record_not_removed` (no seventeenth word). The marks are never deleted; each is an empty file. *Rejected:* keeping a pruned run's `manifest.json` under `sent\` as a tombstone (changes what the outbox prunes and its caps, W4.6); the marks in one file (a rewrite per run). Until W7.1 tightens `state\`, a local user can plant a mark and so keep a job from running, as a planted folder under `runs\` already does.
2. **No restore request after a session the record couldn't take** (point 6 (c), point 9). The entry priced a failed write (c) at "one session nobody ends". After a restore request it cost more: Veeam lists an explore session and a restore session alike (`type` `Vex` for both, restore-flow §9), so the hold counted that session among the others and waited on it for ever, and no job ran again. Every explore session of a run is opened before its first restore request (`restore_sample` resolves every type, `list_candidates` before it), so the loop now remembers a failed write (c) for the run of this process and answers `before_restore_request` false: `run <run_id>: a session the run opened is not on record; the restore request is not sent`, the run ending `error interrupted` as for a failed (d). The record then says no request went out, and the hold ends the recorded sessions and leaves the others, as point 9 says. A process that ends between Veeam opening a session and write (c) sends no later request either.
3. **What escapes the pipeline keeps its report** (point 5). `Body::run_job` declared the `PipelineReport` inside its `try`, and its `catch (...)` reported every throw as a run that ended before its run line: the record was deleted with no close and no hold, the run's folder under `runs\` was left without a result, and J2 skipped its job for good. The report is now declared before the `try` (`run_pipeline` fills it as the run goes), and `rp::job_run_after_throw` (in `src/worker_body.hpp`, beside `job_run_of`, which `run_job` now uses for every run) keeps what it knew; once the run line was out it also says a restore may still be running, since nothing says it isn't, so the loop holds when the record says a request went out. Before the run line it is a run that did nothing, as before.
4. **A run folder that can't be listed whole is not closed** (point 7). `look_at` stopped at the first listing error and returned the part it had read as the whole folder; with `result.json` left out, the close planned the folder as unfinished, took its `signature.json` away and signed again, `result.json` couldn't be written over, and the folder was left signed by nothing and stuck. Seen failing first in a second way too: `path_kind` answers "nothing there" for a folder the account may not ask about, so the close made it, wrote into it and queued it. `FolderContents::list_failed` (a listing that failed or stopped short, a status that can't be read, something there that is no folder) makes `close_run` answer `not_closed` `not_read` before it plans anything; nothing is made, removed, written or queued, and the loop tries again no sooner than 15 minutes later, as for any close that failed.
6. **The hold without a restore request: the entry stands, CLAUDE.md is mended.** The review read CLAUDE.md's "none of them while another session of the account might be a restore" against `decide_hold`, which ends the recorded sessions at once when `restore_requested` is false whatever else runs. That is point 9's rule as approved: with no request sent, no session of the run is a restore. CLAUDE.md now says that, and the rule of point 2 here.

**Tests.** `tests/service_loop_test.cpp`: a session the run opened that couldn't be put on record withholds every later request of that run and of that run only; a run sent and pruned is never run again, in this life of the service and the next; a run that ended before its run line is not marked; a mark that can't be written keeps the record and is said once; the record-write table reordered so the plain (d) failure keeps its line; three call orders now hold `mark job-1`. `tests/service_recovery_test.cpp`: a folder that couldn't be listed whole isn't closed, made, cleared or queued. `tests/worker_body_test.cpp`: a run folder whose listing is denied (`rp::test::set_dacl` in `tests/owner_lab.hpp`, no privilege needed) is not closed and keeps its `signature.json`; `job_run_after_throw` after and before the run line; `job_run_of`; the marks through the real env, and a mark that can't be written.

**Open from the same review.** 5: the owner rule for the two text files is asked by path in `look_at` and their read in `adopt_attachments` is another open, so a file put there between the two is adopted (W7.1's ACL closes the window; one handle for both is the code's fix). 7: a record found at start is settled twice in a row, once before the loop and once at the first poll. 8 to 10: the temp-name rule and the folder words copied in two places, three takes on the abandoned-mutex rule, "a restore may still run" written twice (`hold_needed`, `record_may_go`).

---

## 2026-10-09 — W4.8 build notes, the code review and the live Done-when: a job taken, signed, queued and sent by the service; a killed run and a stopped run each reported as `error interrupted`, held for and cleaned after; nothing left installed (proposed)

Amends the W4.8 entry below where it says so. The build was made in eight steps, one builder at a time (the codes; the seams; the connector; the pipeline; the jobs reader, the log stream and the heartbeat; the record, the close and the hold; the loop; the wiring), then reviewed by six reviewers, each finding checked by a second.

1. **How it was built, said plainly.** The steps were not red, green, commit per behaviour. Most builders wrote a step's tests and code together and built once, to save rebuilds on this machine (a change to `connector.hpp` or `run_status.hpp` recompiles most of the Worker), saw red only through deliberate mutations afterwards, and committed a step as one commit. The connector step and every review fix were seen failing first. The tests are there and the gate holds them to the lines; the order they were written in is not what `docs/testing.md` asks for.

2. **Where the code went beyond the entry or left it.**
   - **The clean after is skipped while a restore may still run, for the commands too.** The entry asked for it in the service (points 9 and 13). `finish` is one function, so `rpworker restore` and `test` at a prompt now print `cleanup after skipped: the restore may still be running; the next run cleans before` where W3.4 had the clean run and say `incomplete`. **This supersedes W3.4's "the clean-after still runs".** Nothing is deleted under a restore that is still writing; the price is that a command's leftovers wait for the next run's clean before, which was already where the last of them went.
   - **A run that ends after a stop is not timestamped.** The stop check the Timestamper is handed is still true when the folder is written, so the outcome is `timestamp_internal after 0 attempt(s)` and the folder is complete without a token. It follows from point 13's "no further attempt after a stop"; seen live in step (e).
   - **The loop's env.** No `queue_run`: queueing is the last step of `close_run`, which only queues a folder that has its `result.json`. Added: `stop_requested`, `outbox_holds`, `run_folder_exists`, `outbox_depth`, `release_hold`.
   - **Nothing a step throws leaves the loop** (`scheduler: a step failed unexpectedly; the loop goes on`, `error`). The entry let what the body "didn't foresee" leave it and restart the service; a loop that goes on is the same promise kept more often.
   - **The record.** A J3 record has `close_as` and `close_detail` from its first write. `close_detail` for `result_invalid` is the run's own ending (`pass`, `fail`, `error <code>`, or `error` when it isn't known), so a close after a restart can name it. Times are in milliseconds. The reader holds it to 64 KiB and 32 levels of nesting. A fifth answer beside the entry's four: a `running.json` that is there and can't be read (`running.json can't be read; no job runs`, hourly, no move tried).
   - **The jobs document** is not held to canonical form: white space, key order and a BOM are taken; a key twice and nesting past 32 levels are `not JSON`. A non-object entry is J1. The first fault is reported by a fixed key order, `unknown key` last; all three sizes 0 is reported as `sample_mail`.
   - **`client_id`** goes into the record only, not into the log (the entry said both).
   - **The heartbeat** is also sent between two jobs of one poll when it is due; `last_error_at` is in milliseconds; the cloud client is made at the first flush or heartbeat.
   - **A result written afterwards takes its screenshot reason from the config**, not from the job: the record doesn't keep the job's `screenshots_enabled`, and its format was approved without it. No screenshot is taken either way today.
   - **Names.** `rp/service_errors.hpp` / `src/service_errors.cpp` (strict) hold the last-error words; `src/run_folder_tail.{hpp,cpp}` is the shared tail of point 7; `src/job_rules.hpp` the job's rules both parsers call; `rp::json_nesting_depth` and `kMaxJsonNesting` moved from the Signer to `rp/canonical_json.hpp`; `RecordStore`'s delete is `erase` (the scan that keeps `remove(` to the Graph client and the Cleaner met it: the full suite's one failure, fixed in 3a80e09).
   - **Log lines the entry doesn't quote** are in `docs/worker-config.md`, "The service's loop".

3. **The code review: fifteen confirmed, none high; fixed test-first in 9c8394c to ef2c1c8.**
   - **After a stop no step is started for a record** (the hold's ends, its second look, the clean and the record's erase went on after one). A run queued normally while a stop came therefore keeps its record; the next start says `interrupted run <id> found`, closes nothing, makes one look and one clean and lets the record go. The wording of that line is wrong for such a run and is left.
   - **A run that reached the outbox is never closed again**, even when its `sent\` folder has been pruned while its record lasted. The memory is the process's: the record's format has no word for it. **Still open:** after a restart, a record that outlived its pruned `sent\` folder (30 days, or the 500 MB cap) would be closed a second time under the same run ID.
   - **A flush that throws no longer skips the record's business** after it.
   - **What the loop has said once is the record's or the document's, and bounded.** This weakens two sentences of the entry: J2's and "ended before its run line"'s "once per run ID and service life" is "once for as long as the jobs document names the run ID", and point 10's "once per run and reason per service life" is "once for as long as every flush pass names it". The hourly lines' memory goes with the record.
   - **A close that itself finds a text file changed marks the record** (`close_detail` `changed`, with `close_as` left `null` so the code stays `interrupted`; `<ending>; changed` for `result_invalid`), so the retry replaces both text files.
   - **`adopt_attachments` decides by the folder's listing**, the name byte for byte: `ITEMS.CSV` is taken away and the empty form written, where it was signed and then refused by both verifiers.
   - **The owner rule holds in the close** as it does for the jobs file and the record (`runs\` has the same inherited ACL until W7.1). A text file of another owner: both replaced by their empty forms, one `SECURITY:` line. A `result.json`, `signature.json` or `timestamp.tst` of another owner in a complete folder: not queued, `couldn't be closed (untrusted)`, one `SECURITY:` line. The owner is asked at the look and the files are read later by path; what catches a swap in between is the read back against the hash.
   - **A record or a jobs document nested past 32 levels is never parsed** (a 64 KiB record nested 50,000 deep ended the test process with a stack overflow).
   - **Tests the strict loop lacked** for its stop guards, the flush's stop, and that the pipeline's and the download client's sleeps are the service's wait.
   - **The gate's six lines** in the three new strict files were closing braces that carry only a local's clean-up; restructured, behaviour unchanged.

4. **The runs, 2026-10-09, one at a time.** `ctest --preset dev`: 2,091 of 2,091 (ten live tests skipped), on the final code. The coverage gate: PASS, 96.7% line (14,922 of 15,430); every strict file 100%, among them `service_loop.cpp` 445 of 445, `service_recovery.cpp` 419 of 419, `service_jobs.cpp` 181 of 181, `service_log_stream.cpp` 59 of 59, `service_errors.cpp` 6 of 6, `outbox.cpp` 444 of 444, `run_status.cpp` 449 of 449, `timestamper.cpp` 87 of 87, `vault.cpp` 306 of 306; `worker_body.cpp` 311 of 319, `run_folder_tail.cpp` 142 of 157, `heartbeat.cpp` 46 of 47. Cloud's `tests/test_result_schema.py` 191 passed with the two new shared cases (185 cases, 47 valid). No Worker CI run has started since 2026-10-03 (GitHub billing), so "No test, no merge" and CI's gates are unchecked for this branch. The exe test `rpworker config check keeps a --config path outside the ANSI code page` fails from a console on code page 437 and passes on 65001; it is not W4.8's.

5. **The live Done-when, 2026-10-09, elevated, on this machine, commit 995c4ba; evidence `docs/api/veeam-lab/w4.8-1` to `w4.8-7`, harness `w4.8-harness/` (`w48-run.ps1`, `w48-done-when.ps1`, `stub-cloud.py`).** It was run twice. The first pass went through every step as below; its collected texts were lost when the harness's teardown deleted the temp folder they were in (my mistake: the texts are now saved as each step ends), so the evidence is the second pass's, with run IDs `w48-live-1` to `w48-live-4`. The first pass's four sent folders and its log are kept outside the repository with the second's.
   - (a) `service install --config <the copy>`, the grants by hand, `service start`: `scheduler started: poll 30 s, heartbeat 60 s, ...`; the stub got a heartbeat at start and every minute, `outbox_depth` 0, no `Authorization`. **The account creates `running.json` and renames a folder from `runs\` to `outbox\` and on to `sent\` under Modify on the four folders.**
   - (b) A job of 5, 5, 5 written into the stub file was **taken 10 s later** (poll interval 30 s), ended `pass`, 15 of 15, about three minutes after, and was signed, timestamped by DigiCert, queued and, by the loop's own flush in the same second, sent: the stub shows the five parts with the sizes and hashes the result lists; both verifiers print the same `verified` line; `running.json` gone. This is the owner's reading of "within one poll interval": taken within one, in the outbox when the run has ended.
   - (c) The same file for two more polls: `skipped w48-live-1: already sent`, once; no run started.
   - (d) A second job; the process killed 12 s after `restore_requested` turned true, with three explore sessions and one restore session of ours `Working`. Event 7031; started again by Windows 60 s later: `interrupted run w48-live-2 found: taken ..., restore requested yes`; the empty folder closed, signed, timestamped, queued and sent as `error interrupted`, `restore_sent` true, `items.csv` its header alone; no job run meanwhile. Two minutes after the start nothing of ours was `Working` any more: **Veeam took the end of the three explore sessions as it takes the run's own stop, and the restore session had stopped by itself.** Then `recovery clean for w48-live-2:` deleted 3 mails, the record went, `graph list` 0 in all three targets, both verifiers `verified`.
   - (e) A third job; `service stop` 12 s into its restore: `stopped RestoreProof in 0.2 s`. Inside that the run ended itself: `restore session ... was still Working when the Worker was asked to stop; no verdict`, `status error interrupted`, `cleanup after skipped: the restore may still be running; the next run cleans before`, signed, not timestamped, queued. `running.json` was still there and says what was in flight (the run, its restore point, `restore_requested` true with its time, the three explore sessions). After `service start`: found, sent, held two minutes, 4 mails cleaned, the record gone, `graph list` 0, `verified ... timestamp none` from both verifiers.
   - (f) A job with all three sizes 0: `job w48-live-4: not a valid job (sample_mail)`, sent as `error job_invalid`, `restore_sent` false, no session in Veeam. A stub file cut off in the middle: `jobs error: <file>: not JSON` once in four polls, `jobs_unreadable` in the next heartbeats.
   - (g) `service stop`; `worker.log`'s 165 lines searched for the vault's four values, a JWT shape, a PEM header and an `MII` run: 0 each; the account's entries taken off the vault, Veeam's key file and the four folders before `service uninstall`; `sc query` 1060; the config copy, `state\` and `logs\` taken away; the five folders under `runs\` and the two under `sent\` that were there before are as they were; no session `Working` in Veeam. **Nothing is installed.**
   - Seen beside it: the TSA's time is about 80 s behind this machine's clock in every token (`timestamped 00:56:57Z` in a line logged at 00:58:17Z), under the 120 s at which the Worker warns. The lab machine's clock is ahead.
   - Not shown live: a hold that waits for a session that stays `Working`; a close that fails; a record of another owner; the hold with the run mutex held by a command. The loop's tables hold them on fakes.

**Open**, beside the entry's own.
- For the owner, from the build: whether a stop right after a run should still write `close_as` (today the next start closes that run as `interrupted`, not `internal` or `result_invalid`); whether a failing close or queue should block the hold (today it doesn't); whether the 120 s should also gate "the hold is over" when nothing is running after a restore request (today: over, and cleaned, at once); whether a `tsa_ca_file` that can't be used should fail a close (today: signed, not timestamped, one warning); whether the jobs file should be held to canonical form; whether the record should keep the job's `screenshots_enabled` and a word for "reached the outbox" (both change `restoreproof.running.v1`).
- A folder queued by a later poll, after a queue that failed, has a manifest that says `not_timestamped` with no code: the W4.4 code of why isn't kept.
- The `interrupted run <id> found` line for a record whose run had ended and was queued.
- The hold's ends write no line of their own; the log shows them only by the clean that follows.
- The Worker's account name appears in the `waiting for Veeam` line; it is no secret value, and W4.9's grep has to know that.
- The steps' order of work (point 1): the next task is built red first, one behaviour at a time, or says here why not.

---

## 2026-10-08 — W4.8 (#51): the scheduler loop, the service's body. Jobs from a stub file run one at a time through `rpworker test`'s pipeline into the run folder and the outbox; `running.json` is written ahead, a run the process didn't finish becomes `error interrupted`, signed and queued, and no job starts while a restore of ours may still run (recorded before the build; the owner approved it as written)

W4.8 (#51) fills the seam W4.7 left: the body of the service. Done when: "Dropping a job into the stub file produces a signed bundle in the outbox within one poll interval." This entry works from issue #51 and its comment, the owner's scope for the task (2026-10-08), the W4.7 entry (points 5 and 6 and its Open list), the Open points of the W4.6, W4.4, W4.3, W4.2 and W4.1 entries that name W4.8, the 2026-09-29 entry "Clients live in the Cloud", the guide's C5.6 and C5.8, and the code. No code is written yet; the build notes will record what the build finds. Out of scope and not built here: the client profile from the job (W4.10), the per-job client check (W4.11), the real Cloud and its token (W5.1), the installer, the account's grants and the folders' ACLs (W7.1), doctor (W7.2), the sentinel grep (W4.9).

**What the investigation found, since the points below rest on it.**

- **The body is handed four things and returns nothing.** `ServiceBody` takes a `ServiceContext` (the `StopSignal`, the logger, the `Config` loaded at start, the config's path). A body that returns or throws while no stop was asked for is a failure that Windows restarts (three times a day); 25 s after a stop the process is ended with `TerminateProcess`: no destructor runs, so no explore session is stopped and the run mutex is abandoned. `run_service` never sets a body today, and `ServiceCommandEnv` has no member for one.
- **A run leaves nothing on disk until its very end.** The run folder is made before the run line and stays empty through the sample, the restore, the check and the clean after; `items.csv` and `veeam-session.log` are written after the timings, then the signature and the token are held in memory through the TSA's wait (up to about 90 s) and `signature.json`, `timestamp.tst` and `result.json` are written last. A process killed during a restore leaves an empty folder named after the run and nothing else: no restore point, no sample, no start time. A kill between the last three writes leaves `signature.json` (and `timestamp.tst`) without `result.json`; the atomic writer's `<name>.<16 hex>.tmp` can be left by any kill during a write.
- **Nothing tells the pipeline to stop, and its sleep can't say why it returned.** Every wait but the download client's goes through `ConnectorOptions::sleep`, a function returning nothing. Handed `StopSignal::wait_for`, the counted loops (the HTTP retries, the statistics' six tries, the duplicate check's three looks, the TSA's three attempts) would run through their remaining attempts without waiting, which is giving up early; **the restore poll would not**: it is bounded by its 20 min deadline alone and would ask Veeam in a tight loop until the process is ended. A request in flight ends only by its own timeout (30 s, the restore POST 60 s, a download and an upload 120 s), all longer than 25 s.
- **The restore POST is sent in one place**, `RestoreRun::restore_call`, once per source container (five sessions in the lab's 30-item runs), and nothing tells the caller before it goes. The pipeline only knows that `restore_sample` was entered, which is some ten seconds of exploring and browsing earlier.
- **A restore session and an explore session are two sessions of one type.** The POST answers with a restore session's ID; that session reads `Working` and stops by itself when the restore has ended. The explore session it was made from never stops by itself in useful time (one was seen `Working` for 36 min) and is stopped by the run's own finally path, or left open on purpose while a restore may still run. In `GET /v8/RestoreSessions` both carry the same `type` (`Vex`, `Vesp`, `Veod`) and the same `initiatedBy`: the list can't tell them apart, which is why `08-sweep-sessions.ps1` stops nothing while two of ours of one type are `Working`. What a Stop does to a restore that is running is untested (restore-flow §18). The preflight reads one page of 200 sessions, unordered, and refuses (`error backup`) while any session of ours is `Working`; it runs after the run line and after the clean before, so the run it refuses is signed, queued and has used up its run ID.
- **An abandoned run mutex refuses the next run once** (W3.4 build note 6: counted as taken "for that one try", so that somebody looks, and "the next run's clean-before takes up what the crashed run left"), with exit 4 and no run line, so nothing is reported for that job. The flush's mutex has the other policy already: abandoned is taken again at once.
- **The outbox already knows a run ID it holds**, but only inside `prepare` and `queue`, which answer with a line and make folders. `flush` is one pass with no way to end between two runs; a `folder_changed` run and a `not_read` run are reported at every flush for ever and count as queued. `take_flush_lock` is local to `outbox_command.cpp`. `make_cloud_http_client` fixes its logger to stderr, which a service doesn't have.
- **`poll_interval_s` (300) and `heartbeat_interval_s` (900) are config keys nothing reads.** The pipeline loads the config from its path at every run; sample sizes fall back to the config; all three at 0 is a usage error with no result. `check_run_id` allows a `:`, which can't name a folder (W4.2: "W4.8 needs the same rule for a job's `run_id`"). The Worker keeps no cursor: W2.6 put the canary cursor with the client in the Cloud.
- **A result with every step `null` is valid `result.v1` today.** `sample`, `expected`, `restore`, `check`, `cleanup`, `ended_at` and each of the eleven spans may be `null`; `restore_point` must be an object but takes empty strings (the pipeline writes them when no point was chosen); `client` and `connector` must be there. `interrupted` and `job_invalid` are in neither `kCodes` nor the schema's enum, though the W4.1 entry names both as "added to the enum by W4.8/W4.11"; the shared cases and one builder test use `job_invalid` as their made-up, must-be-refused word. `status.restore_sent` already means "a restore may have been sent, so items may be in the restore targets".
- **`%ProgramData%\RestoreProof\runs` is not empty and not the service's alone.** `docs/testing.md` names it as the `--evidence` root for runs made by hand, and five such folders are there on the lab machine, one of them (W4.2's) with a `result.json` and no signature. `%ProgramData%\RestoreProof` still has the inherited ACL under which any local user can create a file or a folder (W4.5, W4.7 Open; W7.1 tightens it).
- **Nothing of the Cloud's side exists** (`cloud/app` is empty, there is no `job.v1` schema). The guide's C5.6 gives a job `run_id`, `client_id`, the connector's config, `sample_mail/sp/od`, `screenshots_enabled` and `restore_point: "latest"`, at most five a poll; C5.8 gives a heartbeat `version`, `last_error`, `outbox_depth`, `uptime_s` and answers 204. The W4.6 stub Cloud answers `POST /v1/results` only.

**Decision.**

1. **The units, and what is strict.** Four new strict files, each by the `service` prefix the gate already has: `rp/service_loop.hpp` / `src/service_loop.cpp` (`rp::ServiceLoop`: what is due, which job runs, what is skipped or put off, what happens to a run's record afterwards, every log line of the loop), `rp/service_jobs.hpp` / `src/service_jobs.cpp` (the jobs document's reader and what makes a job invalid), `rp/service_recovery.hpp` / `src/service_recovery.cpp` (`running.json`'s format, reader and writer; the plan for a run that has no result: which files go, which code and message; the rule for Veeam's sessions after one), and `src/service_log_stream.{hpp,cpp}` (the streams that turn the pipeline's lines into log lines). They decide and reach everything else through `ServiceLoopEnv`, a struct of functions (the `OutboxFiles` pattern): `wait(ms)` answering true for a stop, a steady `now` and a wall `wall_now`, `read_jobs`, `run_job`, `close_run`, `queue_run`, `take_run_lock`, `own_sessions`, `end_session`, `clean_targets`, `flush`, `heartbeat`, and the file calls for the record. Not strict, because they make the real calls and decide nothing: `src/worker_body.{hpp,cpp}` and `src/heartbeat.{hpp,cpp}` (one POST, as `uploader.cpp` is). `rp::make_worker_body(WorkerBodyOptions)` builds the real env; its options hold the three paths of point 2 and the factories (the cloud client, the pipeline's env, the run lock, the vault's path), null meaning the real one. `ServiceCommandEnv` gains `body`; `default_service_command_env()` sets the real one, and an env that leaves it null keeps W4.7's body, so W4.7's tests are untouched and no test meets the real paths by leaving a member out. The loop runs on the body's thread and starts no other: a run's mutex is taken and released on one thread (W4.7 point 5).

2. **The loop.** One timeline, one thread, three things due.
   - **At start**, in this order: the log line `scheduler started: poll <n> s, heartbeat <n> s, jobs <file|none>, runs <dir>, outbox <root>`; a record found (point 8); the first heartbeat; the first poll.
   - **A poll** (every `poll_interval_s`, counted from the start of the last one): unless a stop was asked for, first the record's business when there is a record (points 8 and 9); then, only when there is none, the jobs (point 3), each decided (point 4) and run (point 5) in the document's order, one at a time, a flush (point 10) after each run that queued something; and a flush at the poll's end in every case. A job that takes longer than the interval makes the next poll late, never a second run.
   - **A heartbeat** (point 11) every `heartbeat_interval_s`. The loop has one thread, so a heartbeat that falls due during a run is sent when the run has ended, once, not once per interval missed.
   - **Between them** the loop waits in `wait` for whichever is due first; a stop ends the wait and the loop returns. After a stop nothing new is started: no job, no flush, no heartbeat, no step for a record. The body catches what a step throws (logged as `error`, a fixed line, never `what()`) and goes on with the next step; only what it didn't foresee leaves it, which is W4.7's unexpected failure.
   - **The paths** are fixed, each a default the body's options can replace for a test: runs under `%ProgramData%\RestoreProof\runs` (`rp::default_runs_root()`, new), the outbox under `rp::default_outbox_root()`, and the record in a folder of the service's own, `%ProgramData%\RestoreProof\state\running.json` (`rp::default_state_dir()`, made by the loop when it isn't there), whatever `--config` names: one machine has one runs root, one outbox and one run mutex, so it has one record. The account then needs Modify on `state\`, `runs\`, `outbox\` and `sent\` and only Read where the config, the manifest and the vault are.
   - **The service touches one folder under `runs\`: the one its record names.** It lists nothing there and adopts nothing it finds: the folders of runs made by hand with `--evidence` (five are there on the lab machine, and `docs/testing.md` names that root) are never queued, signed or uploaded by it.
   - **The config** is the one the service loaded at start. The pipeline is handed it (`PipelineArgs::loaded`) and doesn't read the file again, so an edit takes effect at the next service start, for the loop and the runs alike. The vault is read per run, as the commands do.
   - *Rejected:* a heartbeat thread (a second thread beside a run for one POST; the Cloud's "offline" threshold has to be longer than a run anyway, and C5.8 sets it); a flush timer of its own (the manifest's `next_attempt_at` already paces each run); catching up missed polls; a sweep of `runs\` at start that closes or queues whatever is there (it would sign a folder anyone made, and upload the lab's hand-made runs as if they were jobs).

3. **The job source is a stub file; its shape is the Cloud's coming answer.** A new optional config key, `jobs_file`: an absolute path, held to that by `parse_config` and printed by `config check`; the file needn't exist. Without the key the loop gets no jobs (it still flushes, deals with a record and sends heartbeats); W5.1 puts `GET <cloud_url>/v1/jobs` in its place and decides whether the key stays for the lab.
   - **Whoever can write that file commands the Worker** (restores into the test targets, signed results under run IDs of their choice). So the file is read only when its owner is SYSTEM, Administrators or the service's own account, the vault's owner rule through the same function; otherwise `jobs error: <file>: owned by neither SYSTEM, Administrators nor this account` and nothing is run.
   - **The document**, `restoreproof.jobs.v1`: `{"format":"restoreproof.jobs.v1","jobs":[<job>, ...]}`, read whole at every poll, at most 1 MiB and **five jobs** (C5.6's "max 5"), strict JSON (a key twice is refused, as the vault's reader does), any other top-level key refused. A file that isn't there is no jobs and no error. A file that can't be read, isn't JSON, isn't this shape or is over a limit runs nothing: one `warning` line `jobs error: <file>: <can't be read|over 1 MiB|not JSON|not a restoreproof.jobs.v1 document|more than 5 jobs|owned by ...>`, written again only when the reason changes, and `jobs_unreadable` as the heartbeat's last error.
   - **A job** is a closed object: `run_id` (required; `check_run_id`'s rule **and** a plain file name, `rp::is_plain_file_name`, so no `:`), `client_id` (required; a string of 1 to 128 printable ASCII characters, or `null`), `sample_mail`, `sample_sp`, `sample_od` (required integers 0 to 100, not all 0), `restore_point` (required; `latest` or a restore point ID by `--point`'s rule), `screenshots_enabled` (required boolean), and `canary_cursor` (optional; three integers 0 to 999999, the command's own bounds, default `0,0,0`: the cursor is the Cloud's to keep and hand on, W2.6). These are C5.6's fields under C5.6's names, less the connector's config, plus the cursor. The rules are the ones `parse_pipeline_args` holds a command line to, as pure functions both call, not a copy.
   - **The client is `config.json`'s until W4.10, and the result doesn't name the job's `client_id` yet.** The 2026-09-29 entry and the owner's comment on #51 say the loop takes the client from the job and never from the config, and that a mismatch ends `client_mismatch` with no restore POST; both need the profile (W4.10) and its check (W4.11), which the owner's scope for this task leaves out. So for now a job names no targets and the run uses the config's client keys as every command does. Since nothing checks that the job's `client_id` belongs to that tenant, it is **not** written into the signed result (`client.client_id` stays `null`, as today): it goes into `running.json` and the log only. W4.10 adds the profile to the job (a new key, which this reader refuses until then), W4.11 the check and the `client_id` in the result. **The #51 comment's added Done-when line (`client_mismatch`) therefore moves to #134; closing #51 without it is the owner's call in approving this entry.**
   - **`screenshots_enabled`** is the job's, replacing the config's value for that run (W4.2: "a job's value replaces it when jobs exist"), through `PipelineArgs::screenshots`. No screenshot is taken either way today.
   - *Rejected:* a fixed file name with no key (the live run and the tests point the service at a file of their own, and "no job source" needs a way to be said); a URL in W4.8 (an unauthenticated GET that W5.1 replaces whole); a bare array (no place for the format's name); an open job object that ignores keys it doesn't know (a job that names a profile would run against the config's client without saying so).

4. **Which job runs.** Only while there is no record (point 6: one run at a time, and a run isn't over until its folder is in the outbox). For each job of the document, first fit:
   - **J1, no usable `run_id`** (missing, not a string, or failing its rule): `warning` `job <n> of <file>: no usable run_id; not run` (`<n>` its position, from 1), written again only when the file's content changes; last error `job_invalid`. Nothing can be signed under a name the Cloud knows.
   - **J2, already there.** `outbox\<run_id>` exists: `skipped <run_id>: already queued`; `sent\<run_id>`: `skipped <run_id>: already sent`; `runs\<run_id>`: `skipped <run_id>: a run folder is already there` (a hand-made run's, or one an operator took out of the loop's hands, point 7). Each at `info`, once per run ID and service life. The first two are the issue's idempotency rule, asked of the outbox through a new pure `Outbox::holds(run_id)` (the rule `prepare` and `queue` already apply: anything at that path counts). Until W7.1 sets the folders' ACLs a local user can make such a folder and so keep a job from running; that is W7.1's Open already.
   - **J3, invalid** (any other rule of point 3 broken): `warning` `job <run_id>: not a valid job (<key>)`, `<key>` the first key at fault or `unknown key`, and the job is **reported**: a record is written with `kind` `job_invalid` (point 6), a run folder is made and closed (point 7) with status `error`, code `job_invalid`, and queued, so the Cloud gets a signed answer under the job's own ID and J2 skips it from then on. Nothing is asked of Veeam or Graph.
   - **J4, run it** (point 5).
   - A stop between two jobs ends the poll. `sent\` is pruned after 30 days or over 500 MB (W4.6), after which a stub file that still holds an old job would run it again; the stub is a lab tool and its jobs are taken out by hand, and the Cloud never offers a received run again (C5.6, C5.7).

5. **Running a job: `rpworker test`'s pipeline, in process.** `run_job` calls `rp::run_pipeline` with `test`'s presentation, the job's `run_id`, sizes, point, cursor and screenshots flag, `--evidence <runs root>` and `--outbox <outbox root>`, the loaded config, and an env whose logger is the service's (W4.7 point 7), whose sleep is `StopSignal::wait_for`, and which carries the new seams of points 6 and 13. No process is started (W4.7's source scan forbids it).
   - **`PipelineReport`**, a new out-parameter of `run_pipeline`, filled on every way out: the run ID, whether the run line was written, the verdict's status and code when one was decided (and the verdict `result_invalid` replaced, when it did), what became of the run folder (`none`, `incomplete`, `complete`, `queued`) with the evidence failure's word when incomplete, and `restore_may_still_run`. The loop decides from it and never from the exit code, which can't tell a config error from a `pass` whose folder couldn't be queued.
   - **What the loop logs:** `run <run_id>: starting (mail <m>, sharepoint <s>, onedrive <o>, point <p>)`, then the pipeline's own lines (point 12), then one of `run <run_id>: ended <pass|fail|error <code>>; queued`, `...; not queued` (the pipeline's `outbox error` line is above it; point 7 queues it), `run <run_id>: ended without a result` (then closed, point 7), or `run <run_id>: ended before its run line; nothing was done` (`warning`, written once per run ID and exit code, not at every poll).
   - **A run that ends before its run line** (the vault, the signing key, the manifest, a cursor past the manifest's canaries, a restore point ID the organisation doesn't have, a mutex held by a command, Veeam not answering when the restore points are listed) leaves no folder and no result, as for the command; the record is deleted. The stub offers the job again at the next poll, which is the retry, at the cost of a vault read and a Veeam sign-in per poll; last error `job_not_started`. What a job the Cloud hands out once gets in that case, and whether the lasting ones of these become a reported `error`, is W5.1's (Open).
   - **The abandoned mutex.** The service's `take_run_lock` takes the mutex again at once when the first try answers `AbandonedRunLock`, as the flush does for its own. The refusal existed so that a person looks and the next run cleans first; in the service the record and the hold of point 9 carry both, and a refusal there would cost a job its run with no result. `rpworker restore` and `test` at a prompt keep W3.4's refusal.

6. **`running.json`, written ahead: one record, one run.** `%ProgramData%\RestoreProof\state\running.json`, in `canonical-json-v1`, written with the atomic writer (`replace`), never inside a run folder. `{"client": {<the result's client object, as the config gives it>}, "client_id", "close_as": null | "result_invalid" | "internal" | "job_invalid", "close_detail": <word> | null, "connector": {"type", "api"} | null, "format": "restoreproof.running.v1", "kind": "run" | "job_invalid", "restore_point": {"id", "backup_time_raw"} | null, "restore_requested": <bool>, "restore_requested_at": <time> | null, "run_id", "sessions": [<id>, ...], "started_at": <time> | null, "taken_at": <time>}`. It holds IDs, times and fixed words, never a secret or an item's name.
   - **Its writes.** (a) By the loop **before `run_pipeline` is called** (and before a J3 folder is made): the run ID, `kind`, `client_id`, the client and `taken_at`; everything else `null`, empty or false. If it can't be written the job isn't run (`error` `run <run_id>: running.json couldn't be written; not run`, last error `record_not_written`). (b) By the pipeline's new seam `RestoreCommandEnv::on_run_started`, right after the run line: `started_at`, the restore point, the connector. A failure here ends the run before any clean and any explore session, as point 13's stop does. (c) **At every session the run opens in Veeam and is to close itself** (the explore sessions, `list_candidates`' included): the session's ID is added to `sessions`, through `ConnectorOptions::on_session_opened(id)`. A write that fails here is a `warning` and the run goes on: the price is one session nobody ends (below), never a safety rule. (d) **Before every restore POST**: `restore_requested` true and `restore_requested_at` the time of this one. The seam is `ConnectorOptions::before_restore_request`, a function answering whether the request may go, which the Veeam connector calls in `restore_call` before it exports the certificate (so outside the stretch in which the credential is in memory); `posted` is still read right before the POST. Answered false (the record couldn't be written, or a stop, point 13), **the POST is not sent**: `restore_sample` ends with `connector::Interrupted`, ending `; nothing was restored` when no POST of this call had gone out. `connector.hpp` gains no Veeam name; a fake connector in the tests calls the functions itself. (e) By the loop after a run that left its folder without a result: `close_as` and `close_detail` (point 7).
   - **What it means.** A record is "this run was taken and isn't in the outbox yet, or a restore of it may still be running". `restore_requested` false is a promise that no restore POST went out; true means one **may** have, whether or not Veeam took it (a kill between the write and the POST looks the same as one after it).
   - **When it goes.** The loop deletes the record when both hold: the run's folder is under `outbox\` or `sent\`, or the run ended before its run line and has none; and no restore of it may still be running, which is `restore_requested` false, or the report's `restore_may_still_run` false, or the hold of point 9 done. Until then no other job is started. A record that can't be deleted: `error` `running.json couldn't be removed`, written once and again every hour, last error `record_not_removed`, tried again at every poll.
   - **A record the service can't trust or read.** It is read only when its owner is SYSTEM, Administrators or the service's account (the vault's rule); one that isn't, and one that isn't its own canonical form or not a `restoreproof.running.v1` record, is moved aside as `running.json.unread` (replacing an older one), with one line (`SECURITY: service: running.json is owned by neither SYSTEM, Administrators nor this account; moved aside`, or `error` `running.json isn't a restoreproof.running.v1 record; moved aside as running.json.unread`), last error `record_unreadable`. Then nothing is known: nothing is closed, signed, ended or cleaned on its word, and the loop goes on as before W4.8 (the next run cleans before, and the preflight refuses it while a session of ours is `Working`). If it can't be moved aside either, no job runs and the line is repeated hourly.
   - *Rejected:* the record inside the run folder (the folder doesn't exist before the pipeline makes it, the file would travel into the outbox and be uploaded as an unlisted part); a record that goes when the pipeline returns (a folder that couldn't be closed or queued would then be nobody's, and only a sweep of `runs\` could find it); recording the restore sessions' IDs (a POST that got no answer has none).

7. **Closing the record's run when its folder has no `result.json`.** One operation, `close_run`; it is the answer to W4.2's, W4.3's and W4.6's Open points. It acts only on the folder the record names.
   - **With which code.** `interrupted`: a record found at start whose `close_as` is `null` (the process ended during the run). `result_invalid` or `internal`: the pipeline returned and left the folder incomplete; the loop first writes `close_as` (`result_invalid` when that was the verdict; else `internal`, with the evidence failure's word as `close_detail`: `not_written`, `changed`, `holds_secret`, `not_signed`), then closes. `job_invalid`: a J3 record, `close_detail` the key. A record found at start with `close_as` set is closed with that code, so a close that was itself cut short keeps its word.
   - **What it does, in order.** A folder that has a `result.json` is complete and is only queued: nothing is signed twice. A folder that isn't there (a kill before the pipeline made it, or a J3 job) is made. Otherwise: remove `signature.json`, `timestamp.tst`, `screenshot.png` and every `<name>.<16 hex>.tmp` (a signature without its result signs bytes that exist nowhere any more, and the screenshot's writer is the one that isn't atomic); keep `items.csv` and `veeam-session.log` when they are there (each is only ever written whole) and write the empty form of one that isn't (the CSV's header alone, an empty log), **except** when `close_detail` is `changed`, where the pipeline has just found one of them altered after it hashed it: both are then replaced by their empty forms, since the Worker doesn't list as its evidence a file it knows was changed. Then the result is built (below), and then the same tail as every run, one internal function the pipeline and `close_run` share so that there is one signing path: the secret scan (over `secret_values(secrets)`, the key's text and its shapes), the attachments read back, the signature under the vault's key, the TSA asked, `signature.json`, `timestamp.tst`, `result.json` last, the folder queued. Anything else found in the folder is left and becomes the verifiers' "not listed" note. The key is read from the vault for this and held as the pipeline holds it (`RunSigningKey`: taken out of `Secrets`, wiped on every way out), which makes `close_run` the third reader W4.3 names beside `rpworker test --evidence` and `signer public-key`.
   - **The result** is valid `restoreproof.result.v1` with what is known and `null` for the rest: `run_id`; `started_at` from the record (`null` when the run line was never reached); `ended_at` `null`; `connector` and `restore_point` from the record, else `veeam_m365` with an empty `api` and the empty point the pipeline writes when none was chosen; `client` from the record, `client_id` `null` (point 3); `sample`, `expected`, `restore`, `check`, `cleanup` `null`; every span `null`; `attachments` the two files; `screenshot` `unavailable`, `disabled` or `no_page` by W4.2's rule for a run without a restore session. `status` is `error` with the code, `restore_sent` the record's `restore_requested`, every count 0, `failed_items`, `unchecked_items` and `warnings` empty, and a fixed message: `the run was interrupted before its result was written; no restore request had been sent` or `...; a restore request may have been sent, so items may be in the restore targets` for `interrupted`; `the run ended without a result the Worker could write; this result was written afterwards` for `internal`; W4.1's own text for `result_invalid`, naming the verdict the run had (the report carries it); `the job isn't a valid job (<key>); nothing was done` for `job_invalid`. Each comes from a maker in `run_status` beside `result_invalid()`, so the words live with the codes.
   - **It doesn't say what the run found.** A run killed during the TSA's wait had its verdict, its clean after and its two text files; the result written for it is still `error interrupted`, because the verdict was only ever in memory. The `items.csv` kept beside it shows the rows that run wrote. `docs/verification.md` says so: `error` is "the test didn't reach a result", and the attachments are evidence of what was done, not a second verdict.
   - **When it fails, or the queue does** (the vault can't be read, there is no signing key, the folder can't be written, the rename is refused because something holds a file): one `error` line `run <run_id>: couldn't be closed (<vault|not_signed|not_written|holds_secret|changed|invalid>)` or `run <run_id>: couldn't be queued (<the outbox's word>)`, written once per reason and again every hour, last error `run_not_closed` or `run_not_queued`. The record stays, so no other job runs; the queue is tried again at every poll, a close at every poll but not more often than every 15 min (each try asks the TSA). When the key itself is the reason nothing can be signed, so nothing is sent, and no job could be signed either: the heartbeat is the Cloud's only word of it.
   - **The operator's way out**, in `docs/worker-config.md`: stop the service, move the run's folder out of `runs\` or leave it, delete `state\running.json`, start the service. The folder is then nobody's: J2 skips its job while it is there, and nothing is uploaded for it.
   - **This amends two sentences.** W4.3's "a `result_invalid` run is never signed" becomes "the invalid result is never signed": the result `close_run` signs for it is a valid one that says `result_invalid`. And "nothing in a run folder is written after the run" keeps holding for a folder that has its `result.json`; one without was never signed, and `close_run` is its one writer.

8. **A record found: at start, and at every poll while it lasts.** At start: `warning` `interrupted run <run_id> found: taken <time>, restore requested <yes|no>` (for a record whose `close_as` is `null`). Then, at start and at each poll until the record is gone, in this order and each only if still needed: (a) the run's folder closed and queued (point 7), unless `outbox\` or `sent\` already holds the run; (b) the hold of point 9, unless `restore_requested` is false and `sessions` is empty; (c) the record deleted (point 6). A stop ends the sequence between two steps; a kill at any point of it leaves a record from which the next start does the same again, and no step is one that can't be done twice: a closed folder is only queued, a queued run is skipped, an ended session isn't `Working`, a clean of empty targets deletes nothing.

9. **The hold: no job, and no clean, while a restore of ours may still run.**
   - **The look** is two new connector members, neutral: `IConnector::own_sessions(since)` answers every session the connector's account started at or after `since` that is still running, as `{id, created_at}`, reading every page from `startTimeFrom`, newest first, for the whole account (not one organisation: the preflight isn't limited to one either); `IConnector::end_session(id)` is the stop the run's own finally path sends (`stop_if_working`'s read, Stop, read, Stop, as a function both use). Their defaults throw `NotImplementedError`. `since` is the record's `taken_at`. One connector is made when the hold begins and kept until it ends; a look that fails drops it and the next look makes a new one (a vault read and a sign-in).
   - **Each look-and-end is made under the run mutex**, taken without waiting; held by a command, the look is "not yet". So no `rpworker restore` or `test` at a prompt has a session open while the service ends any. Looks are made at every poll and at least every 30 s.
   - **The rule.** The sessions still running are split in two: the **recorded** ones, whose IDs `sessions` holds (explore sessions this run opened), and the **others** (not in the record: a restore session a POST made, or a session whose ID never reached the record). **`restore_requested` false**: no POST went out, so nothing of this run is restoring: each recorded session still running is ended at once, which is what the run's finally path would have done; the others are not touched. **`restore_requested` true**: while any other session is running, a restore may be: nothing is ended, the loop waits. When none is, and 120 s have passed since the later of `restore_requested_at` and the moment this process began the hold (twice the POST's timeout: a restore session Veeam hadn't listed yet), each recorded session still running is ended. **The hold is over** when no recorded session is running and, with `restore_requested` true, no other is.
   - **It ends only sessions it wrote down as the run's own explore sessions, and never one of them while another session of ours might be a restore.** A session it didn't write down is never ended by it. What a Stop does to a running restore is still untested (restore-flow §18) and isn't relied on.
   - **What can last.** A look or an end that fails (Veeam restarting after a reboot, a changed password, a Stop refused) is "not yet": `warning` `the look at Veeam's sessions failed: <auth|transient|other>` or `ending session <id> failed`, written once per reason and again every hour, last error `veeam_look_failed`. Another session that stays `Working` holds the loop for as long as it does (a hung restore; an explore session whose ID was never recorded, until Veeam ends it, 36 min seen): `warning` `waiting for Veeam: <n> session(s) of <account> still Working since <time>`, once and again every hour, last error `veeam_sessions_working`. There is no deadline after which sessions are ended anyway. **The operator's way out**, in `docs/worker-config.md`: look at the sessions in Veeam; when none of them is a restore that still runs, stop the service, delete `state\running.json` and start it. Without the record there is no clean by the hold: the next run's clean before and the preflight take over, as before W4.8. (`08-sweep-sessions.ps1` doesn't help here: it stops nothing while two of ours of one type are `Working`.)
   - **The Veeam account is the service's alone while it is installed.** A person signing in as `rp-veeam` (the lab's `10-restore.ps1`, a restore in Veeam's console under that account) holds no run mutex, and their session is an "other" one: the hold waits for it and never ends it, but the preflight of a run would refuse over it as today.
   - **Then the clean, then the record goes.** When the hold is over and `restore_requested` is true, the restore targets are cleaned once, the clean after the run never made: under the run mutex, with the vault's Graph certificate, the Cleaner over the config's targets, the pipeline's own construction through a new internal `rp::clean_restore_targets` beside `run_pipeline`. It is the Cleaner's `before_run` clean, unchanged (`cleanup before ok|incomplete: ...`, logged after `recovery clean for <run_id>:`), so the strict Cleaner and W3.4's texts aren't touched. It is made only when the config's client equals the record's (`warning` `the config's client is not the run's; the restore targets were not cleaned` otherwise). Whatever it answers (last error `recovery_clean_incomplete` when not ok), the record goes and jobs run again: every run cleans before anyway. With `restore_requested` false nothing was restored and nothing is cleaned.
   - **This is W4.7's known weakness closed for the service**: the clean before of the next run no longer runs under a restore that is still writing, and no job is spent on the preflight's refusal after an unfinished run. It holds for a record kept by a run that ended in this process too (the 20 min poll deadline, a POST without an answer, a stop during the poll: every restore-phase end whose text doesn't end `; nothing was restored`): that run skips its clean after, as W3.4 has it for a restore that may still run, and the hold begins at once.
   - *Rejected:* judging by the session list alone, "two of a type running is a restore, one is an explore session" (a lone session can be the restore, once its explore session has gone, and would be ended); ending everything of ours at start (it might cancel a restore, with unknown results); a deadline after which the sessions are ended anyway (the same, later); the hold before every job, record or not (a GET per job for a state only an unfinished run creates).

10. **The flush in the loop.** The loop calls `Outbox::flush` itself, with one cloud client and one `CloudUploader` for the service's life, under the flush mutex (`rp::take_outbox_flush_lock`, moved out of `outbox_command.cpp` and shared with the command; held elsewhere: this pass is skipped, a `debug` line).
    - **A stop between two runs.** `flush` gains an optional `stop` function, asked before each queued run: after a stop no further upload is started. One in flight goes on for as long as the 25 s last; a flush cut off there changes nothing on disk before the Cloud's answer (W4.6), so the run is sent again.
    - **The lines.** The report's stdout lines go to the log at `info` (`waiting <run>: next at <time>` at `debug`), its `outbox error` lines at `warning`.
    - **`folder_changed` and `not_read`** stay as W4.6 left them on disk: never sent, never deleted, counted as queued. In the service their line is written **once per run and reason per service life**, not at every pass; the last error is `folder_changed` or `not_read`; the other runs are flushed as ever. A `folder_changed` run is evidence that something wrote in a signed folder: sending it as genuine and deleting it are both wrong, and a second result under the same run ID can't be queued while the folder is there. What takes it out of the queue is W5.1's `failed\` (Open).
    - *Rejected:* `run_outbox_command` called with streams (it reads the config again at every pass, builds a client each time, and answers with an exit code where the heartbeat needs the counts).

11. **The heartbeat.** `POST <cloud_url>/v1/heartbeat`, `Content-Type: application/json`, the body `canonical-json-v1`: `{"last_error": <word> | null, "last_error_at": <time> | null, "outbox_depth": <n>, "uptime_s": <n>, "version": "<rpworker's>"}`. That is C5.8's body plus the time. Under `/v1` like every Cloud route (the issue's `/heartbeat` is the guide's shorthand). Sent once, 10 s timeout, the cloud client of point 10 (so `cloud_ca_file` holds and TLS is verified as for an upload), no `Authorization` and no credential until W5.1. Any 2xx is taken. Anything else: `warning` `heartbeat failed: <http_<status>|unreachable|timeout|internal>`, written again only when the word changes; nothing is retried before the next interval, and a failed heartbeat is never the last error it reports.
    - **`outbox_depth`** is the number of runs under `outbox\`, the ones that can't be sent included.
    - **`last_error`** is the latest of the loop's own troubles since the service started, one word from a fixed list (`rp::service_error_codes()`): `jobs_unreadable`, `job_invalid`, `job_not_started`, `record_not_written`, `record_not_removed`, `record_unreadable`, `run_not_closed`, `run_not_queued`, `folder_changed`, `not_read`, `veeam_look_failed`, `veeam_sessions_working`, `recovery_clean_incomplete`, and the outbox's upload words (`upload_unreachable`, `upload_timeout`, `upload_internal`, `upload_http_<status>`). Never a run's own `error` code (the result carries that), never `what()`, never a path or a name. It is not cleared by a later success; `last_error_at` says how old it is.
    - *Rejected:* an object for `last_error` (C5.8 stores a text); the queue's size in bytes.

12. **Where the lines go.** The pipeline writes to two streams as ever; in the service they are `rp::LogLineStream`s: each completed line becomes one log line `[<run_id>] <line>`, stdout's at `info`, stderr's at `warning`, a last line without its line break written when the run ends. The stream never fails, so "stdout was lost" can't happen there. Every line passes the log's sink, which redacts it (W4.7 point 7). **The log therefore holds what a console would have shown, tenant names included** (the sample's rows, a `check note`'s file name, Veeam's messages): the same text `veeam-session.log` and `items.csv` hold in the run folder, on the same machine, under the folder ACL W7.1 sets; a 30-item run is about 120 lines of the log's 50 MiB. With `log_level` at `warn` only the stderr lines and the loop's warnings are kept. The cloud client's logger is the service's: `make_cloud_http_client(config, logger)`, null meaning the command's stderr logger as today.
    - *Rejected:* only the status line in the log (the log is the one place an operator can read why a run ended as it did); a file per run (the run folder is that, for a run that reached its end).

13. **A stop during a run.** `RestoreCommandEnv::stop_requested` (null: never) is the stop check; the sleep is `StopSignal::wait_for`; the connector learns of a stop through `before_restore_request` answering false and through `ConnectorOptions::stop_requested`.
    - **Step boundaries in `run_pipeline`:** before the mutex and the first Veeam call (no run line yet: the run ends there, nothing was done, the record is deleted, the stub offers the job again), and after the run line before each of the clean before, `choose_sample`, the read before and `restore_sample`: the run ends through `finish` as a stop in phase `before_restore` with code `interrupted` (W3.3's row 2: `the run stopped before the restore: the run was interrupted (interrupted); nothing was restored`), the clean after skipped, the explore sessions stopped by their own finally path, the folder signed and queued if the 25 s allow.
    - **In the connector:** `connector::Interrupted` is a type of its own, not a `connector::Error`, so no handler written for Veeam's failures takes it; `run_pipeline` catches it where it catches the connector's errors and `stop_reason` gives it the code `interrupted`, reading `; nothing was restored` from its text as for the others. **No new POST after a stop:** before the first it ends `; nothing was restored` (`restore_sent` false, the record goes, no hold); before a later one it doesn't (the sessions already made have stopped; `restore_sent` true). In the restore poll a stop after a wait ends it with `Interrupted`, no verdict, the explore sessions left open as at the 20 min deadline: the restore goes on in Veeam, the run skips its clean after, the record stays and the hold of point 9 follows, in this process if it lives or at the next start.
    - **Every other wait** (the HTTP retries, the statistics' tries, the duplicate check's looks, Graph's waits and rechecks) returns at once and its loop gives up as it does at its own limit, as W4.7 point 6 says. The download client gets the pipeline's sleep (`make_download_http` is handed it). The Timestamper gets `stop_requested` and makes **no further attempt** after a stop: the outcome is the last attempt's code with the attempts made, or `timestamp_internal after 0 attempt(s)` when the stop came before the first (never `tsa_unreachable` for a TSA that wasn't asked; `attempts` may now be 0). This amends W4.4 build note 2's "the next attempt is still made" for a stop.
    - **The code is `interrupted`, not the service that happened to be waiting.** When the stop was asked for **before** the verdict is decided and the verdict is `error` with a code other than `interrupted`, `target_guard` or `result_invalid`, it is replaced by `verification::interrupted(verdict)` (as `result_invalid(verdict)` replaces one: the counts, `restore_sent` and the warnings kept): `the Worker was stopped during the run; the run itself ended error <code>`. A `pass` or a `fail` reached in spite of the stop stays what it is, and so does every verdict decided before the stop came.
    - **What isn't promised.** A request in flight ends only by its timeout, and the 25 s end the process whatever it is doing: that run is the record's (point 8). The stop check makes the common case a signed `error interrupted` written by the run itself; the record covers the rest.

14. **Two new codes: twenty.** `interrupted`: a stop's code (stop text `the run was interrupted`), never a check item's, no severity, exit 4. `job_invalid`: never a stop's code nor an item's, exit 1. Both join `kCodes`, `error_codes()` and the schema's `status.error_code` enum in table order; the made-up word of the shared case `status-unknown-error-code` and of the builder's test becomes one no task plans. The enum only grows, so every result signed so far stays valid; a verifier holding the older schema answers `result_schema` for a result with a new code, which is why the schema travels with the verifier (`--schemas`). `shared/testdata/result-v1/cases.json` gains valid cases for both. `client_mismatch` and `connector_unknown` stay W4.11's.

15. **Tests, failures before the happy path.** No test waits, starts the service or touches `%ProgramData%`: the loop runs on `ServiceLoopEnv` fakes with a fake clock whose `wait` advances it and answers a stop at a scripted step (`tests/service_loop_lab.hpp`).
    - **The jobs reader** (`tests/service_jobs_test.cpp`): a `GENERATE` table of documents against the exact line and outcome: missing file, unreadable, a foreign owner, over the limit, not JSON, a key twice, wrong format, a sixth job; per job every key missing, of the wrong kind, out of range, all sizes 0, a cursor of 1000000, a `run_id` with a `:`, a device name, an unknown key, a `client_id` of 129 characters; then a valid document.
    - **The loop** (`tests/service_loop_test.cpp`): a stop before the first poll, between two jobs, during a wait; a job already queued, sent, with a run folder; J1 (its line once, again after the file changed) and J3 (the record's `kind`, the close, then skipped); a record that can't be written (no run); a run that ends before its run line (the record gone, the line once, offered again); one that leaves an incomplete folder with each evidence word (`close_as` written before the close; the text files kept, and replaced for `changed`); a close that fails and is tried again no sooner than 15 min while no job runs; a queue that fails and succeeds at the next poll; a record that can't be deleted; a foreign-owned and an unparseable record (moved aside, the line, nothing closed, ended or cleaned), one that can't be moved aside; the hold's table (`restore_requested` false with three recorded sessions running and one other: three ends, the other untouched, the hold over; true with another session running: nothing ended, the warning once and again after an hour; true with none other before and after the 120 s, counted from the hold's start when that is later than the last POST's time; a recorded session no longer listed; the mutex held by a command; a look that throws, once and hourly; an end that fails; the clean made, refused for a changed client, incomplete); a heartbeat due during a run sent once after it; a failed heartbeat's line once; a `folder_changed` line once; the flush skipped while its mutex is held; a step that throws; then one job from poll to `queued` and `sent` with every line in order and the record gone.
    - **The record and the close** (`tests/service_recovery_test.cpp`): the record's canonical text after each write and its strict reader; a folder at every point of the finding's list (not there, empty, the two text files, a `.tmp`, `signature.json` alone, with `timestamp.tst`, complete, already queued), each against the files afterwards and the result's status object for each code; the same folder closed twice (a close cut short); no key in the vault; the result holding a secret value. A closed folder is `verified` by `Signer::verify_folder`, and one closed folder joins the shared signing vectors so that `verify_bundle.py` says the same in the Cloud's tests.
    - **The pipeline** (`tests/test_command_test.cpp`, `tests/restore_command_test.cpp`, the Harness gaining the new seams): `PipelineReport` at every way out of `run_pipeline` (a table: each refusal before the run line, each stop phase, `result_invalid`, each evidence failure, a refused queue, queued); a stop at each boundary of point 13 with the status line, the result's code and what was called after it (no explore session, no POST); `on_run_started` failing; `before_restore_request` answering false before the first and before the second POST on the recorded restore (`tests/veeam_m365_restore_test.cpp`: the POST count, the certificate not exported, `restore_sent`); `on_session_opened` called for every session opened, a failing one not stopping the run; the poll ended by a stop after one wait, not a tight loop (the fake clock counts the GETs), its run skipping the clean after; a `pass` reached in spite of a stop; an `error graph_transient` after a stop reported as `interrupted`, a `target_guard` not, a verdict decided before the stop not; the status table's E rows for `Interrupted` in each phase; the Timestamper stopped before the first, the second and the third attempt; `flush` stopped between two runs; `Outbox::holds`; `own_sessions` over recorded session lists (two pages, another account's sessions, older than `since`) and `end_session`; `clean_restore_targets` on the W3.4 recording.
    - **The small files:** `tests/service_log_stream_test.cpp` (a line over two writes, a last line without its break, an empty line, CR LF, the prefix, a write that never fails, a sentinel redacted in the file); `tests/heartbeat_test.cpp` (the body's exact bytes, each failure word, on the local HTTP server); the service's `take_run_lock` over an abandoned mutex; `take_outbox_flush_lock` after its move.
    - **The codes:** X rows for both codes' exit codes, the schema's enum held to `error_codes()`, the makers' messages, the shared cases run by both builds.
    - **Wiring:** `service run` on the fake host with the real body over a temp folder, a fake cloud client and a fake lock (the stop given before the body is let go, so only the `scheduler started` line and a clean stop are asserted); `config check` printing `jobs_file`. Exe tests through `run_exe_test.cmake`: `config check` with a relative `jobs_file` (the exact `config error` line, exit 1). No exe test starts the loop.

16. **The live Done-when**, on the lab machine, elevated, evidence as text under `docs/api/veeam-lab/w4.8-*`, the harness `w4.8-harness/` beside it (W4.7's `w47-run.ps1` and W4.6's stub Cloud, which gains `POST /v1/heartbeat` answering 204 and printing the body). Since W7.1 isn't built, the harness makes by hand what the account needs, after `service install` (the account exists only then) and takes it away **before** `service uninstall`: `rpworker vault grant "NT SERVICE\RestoreProof"`; the Read ACE on Veeam's key file (W4.12's `icacls` line); Read on the config copy, the manifest copy beside it, the jobs file and the two CA files; `runs\`, `outbox\`, `sent\` and `state\` made by the administrator with Modify for the account. `icacls` of the vault and the key file before and after are part of the evidence. The five hand-made folders under `runs\` stay where they are and must be untouched at the end.
    - (a) `service install --config <a copy of the lab's config with jobs_file, the stub's cloud_url and cloud_ca_file, poll_interval_s 30, heartbeat_interval_s 60; seed-manifest.json copied beside it>`, `service start`; the `scheduler started` line; the stub shows heartbeats with `outbox_depth` 0.
    - (b) A job (`sample_mail`/`sp`/`od` 5, `latest`) is written into the stub file. **The reading of "within one poll interval" put to the owner here:** the job is *taken* within one poll interval (its `starting` line no later than 30 s after the file's write time), and its signed folder is in the outbox when the run has ended, some minutes later; a 30-item restore can't be inside 30 s. The evidence is the log's `queued <folder>` line and the flush's `sent` line with their times (the loop flushes right after the run, so the folder may only ever be seen under `sent\`), the stub's parts, both verifiers' `verified`, and `running.json` gone.
    - (c) The same file is left as it is for two more polls: `skipped <run_id>: already sent`, once, and no second run.
    - (d) A second job; the process is killed while `running.json` reads `restore_requested` true. Windows starts the service again after 60 s: `interrupted run <id> found`, the folder closed, signed, queued and sent as `error interrupted` with `restore_sent` true; the loop holds while the restore's session is `Working`, ends the recorded explore sessions afterwards, cleans, deletes the record; `graph list` shows 0 in all three targets; both verifiers say `verified` for the sent folder.
    - (e) A third job; `service stop` during its restore: `stopped RestoreProof in <s.s> s`, under 30; `running.json` is read and shown (what was in flight); after `service start` the run is found as (d)'s was, or, when the stop check ended it inside the 25 s, is already queued as `error interrupted` with the record kept for the hold. Either way: sent, held, cleaned, `graph list` 0.
    - (f) A job with all three sizes 0: sent as `error job_invalid`, nothing asked of Veeam. A stub file that isn't JSON: the `jobs error` line once, `jobs_unreadable` in the next heartbeat.
    - (g) `service stop`; the grants and ACEs removed and shown gone; `service uninstall`; the config copy and the folders the run made taken away; `sc query` answers 1060. The sent folders are kept outside the repo.

**Reason.** A service that restarts by itself meets every half-finished state a person at a prompt would have noticed and cleared, so each of them gets one written rule instead of an operator: a run is on record before it does anything, the record says whether a restore may be out before one is sent, the record stays until the run is in the outbox and nothing of it can still be running, and what the next start does follows from the record alone. The service acts on nothing it didn't write down itself: it closes only the folder its record names and ends only the sessions its record lists. The Cloud gets a signed answer for every job the Worker took whenever one can be signed, and that answer never says more than is known: `interrupted` and `job_invalid` are `error`, never `fail`, and a result written afterwards carries no verdict the Worker didn't keep. Nothing is ended in Veeam while a restore might be running, and nothing is cleaned under one. The loop itself is plain code over functions it is handed, so every branch of "which job, what skipped, what next" is a row in a table that a fake drives.

**Alternatives rejected.**
- *Starting `rpworker test` as a child process per job:* a console to read and an exit code to interpret where the pipeline can be called and asked; W4.7's scan forbids starting a process.
- *Running the interrupted job again under its run ID:* the first attempt may have restored; a second run can't tell its items from the first's, and the Cloud would get a verdict for a run that was two.
- *A result for an interrupted run that lists nothing and deletes what the folder held:* the two text files of a run that reached them are the only evidence of what it did.
- *A new status beside `pass`, `fail` and `error`:* `error` is "the test itself couldn't run"; the code says why.
- *A sleep that throws on a stop:* it would be caught by handlers written for Veeam's and Graph's failures (the duplicate check's, the Timestamper's, the Cleaner's) and read as theirs.
- *Going on with the next job while a run can't be closed or queued:* a second record, or a run nobody owns; one run at a time is the rule everything else here rests on.
- *A cursor file on the Worker* (W2.6 rejected it), *and the hold before every job* (point 9).

**Supersedes and closes, from earlier entries.** W4.7's Open "W4.8" line, each part: the body (points 1, 2), `wait_for` and the stop check (13), `running.json` and `interrupted` (6, 7, 8), the abandoned mutex (5), the look for a Working session (9), the download client's sleep (13), the streams and the cloud client's logger (12). W4.6's Open "the flush loop, both roots, a runs-root folder without `result.json`, a `folder_changed` run" (2, 10, 7; a folder under `runs\` that the record doesn't name is left alone). W4.4's "(the sleep must be interruptible)" and its build note on a wait that ends early (13). W4.3's "whatever result W4.8 writes for such a run must be signed too, a leftover `signature.json` removed first; and what is uploaded when the key itself is why nothing could be signed" and its "parsed only by" (7). W4.2's "what the service tells the Cloud for such a run" and "the same rule for a job's `run_id`" (7, 3), and `screenshots_enabled` as the job's (3). W4.1's `interrupted` and `job_invalid` (14). W3.4 build note 6's refusal of an abandoned mutex: kept for the commands, replaced in the service (5). The 2026-09-29 entry's "the service loop never reads" the config's client keys, and the #51 comment's `client_mismatch` line: not yet, W4.10 and W4.11 (3). CLAUDE.md's rule "nothing in a queued or sent run folder is written after the run" is unchanged; the runs root's rule is point 7's.

**Open.**
- W4.10, W4.11 (#133, #134): the profile in the job and the config's client keys out of the loop; `client_id` in the result; `client_mismatch`, `connector_unknown`; the recovery clean by the record's profile instead of a comparison with the config.
- W5.1: `GET /v1/jobs` and the token; a job handed out once that ends before its run line, and whether a refusal that can't pass (a cursor past the manifest, an unknown restore point) becomes a reported `error` (point 5: today the stub offers it again); a `folder_changed` run and a 4xx that will never succeed (`failed\`); whether `jobs_file` stays.
- C5.6, C5.8: the jobs document and the heartbeat body as built here are the Worker's proposal for both contracts; the Cloud's "offline" threshold against a heartbeat that waits for a run.
- W7.1: the account's Modify on `state\`, `runs\`, `outbox\`, `sent\` and nothing more than Read beside the config; until then a local user can make a folder or a file there first (the owner rule keeps a planted record and jobs file from being believed, not from being in the way). W7.2: doctor reading the record, a held loop, and that the Veeam account is used by nobody else.
- W4.9: the log now holds a run's lines; the sentinel grep reads it.
- A session the run's own finally path couldn't stop after a run that ended cleanly isn't held for (the record goes with the run); the preflight refuses the next run over it, as today.
- Not tried before the build, and the live run's to show: that ending the explore sessions a killed run left is taken by Veeam as the run's own stop is; how long after a kill the restore's session reads `Stopped`; what Veeam's session list shows after Veeam itself restarted; the account's rename from `runs\` to `outbox\` under the ACLs the harness sets. Still untested and not relied on: what a Stop does to a running restore.

**Code, tests and docs with the build.** New: `rp/service_loop.hpp`, `src/service_loop.cpp`; `rp/service_jobs.hpp`, `src/service_jobs.cpp`; `rp/service_recovery.hpp`, `src/service_recovery.cpp`; `src/service_log_stream.{hpp,cpp}`; `src/worker_body.{hpp,cpp}`; `src/heartbeat.{hpp,cpp}`; the shared tail of the run folder beside `run_pipeline`. Changed: `src/run_pipeline.{hpp,cpp}` (`PipelineArgs::loaded` and `screenshots`, `PipelineReport`, the stop checks, `on_run_started`, the `Interrupted` catch, `clean_restore_targets`, the job's rules as shared functions), `rp/restore_command.hpp`, `rp/connector.hpp` and `rp/connector_registry.hpp` (`Interrupted`, `own_sessions`, `end_session`, `before_restore_request`, `on_session_opened`, `stop_requested`), `src/veeam_m365_connector.cpp`, `src/veeam_explore.*`, `src/veeam_candidates.cpp`, `rp/run_status.hpp` and `src/run_status.cpp` (the two codes, the makers, `stop_reason`), `shared/schemas/result.v1.json`, `shared/testdata/result-v1/cases.json` and `shared/testdata/signing-v1/`, `rp/evidence_builder.hpp` (keeping the text files that are there), `rp/timestamper.hpp`, `rp/outbox.hpp` (`holds`, `flush`'s stop, the shared flush lock), `rp/vault.hpp` (the owner rule as a function of its own), `src/uploader.cpp` (the logger), `src/graph_download.*` (the sleep), `rp/config.hpp` and `src/config.cpp` (`jobs_file`), `src/config_check.cpp`, `rp/service_command.hpp` and `src/service_command.cpp` (`body`). Tests as point 15. Docs: `docs/worker-config.md` (the service's loop, `jobs_file` and the jobs document, `running.json`, the heartbeat, the two codes, the operator's two ways out), `docs/testing.md` (the loop by hand, the strict names, a hand-run's `--evidence` root), `docs/verification.md` (`interrupted`, `job_invalid`, a result written afterwards, twenty codes), `docs/glossary.md`, CLAUDE.md. The PR closes #51.

---

## 2026-10-08 — W4.7 build notes and the live Done-when: installed, started by Windows after a crash and after a reboot, stopped in 0.2 s, the log rotated with a reader holding it, nothing left installed

Amends the W4.7 entry below where it says so. The build was made test-first in four steps (the stop signal and the log; the SCM seam; `rp::Service`; the commands), then reviewed twice: findings A to D below from the first review, and the second's own entry above ("W4.7 code review, findings 1 to 3").

1. **What the entry didn't say, now decided.**
   - `make_service_logger` answers `std::variant<std::shared_ptr<rp::ServiceLog>, rp::ServiceLogFailure>` (`code_page`, `folder`, `file`); `rp::ServiceLog` holds the logger beside `set_level`, `write_failures`, `flush`, `close` and `file`, and takes any inner sink, so the service's tests need no file. The code page is checked before the folder is made. A line ends in CR LF.
   - The sink's level is its own (`ServiceLogSink::set_threshold`), not spdlog's `sink::set_level`, which the logger would ask before the sink's SECURITY rule ever saw the line.
   - `rp::ScmCalls`' members answer `rp::ScmResult{error, step}`, the step (`manager`, `service`, `call`) naming which call of the sequence Windows refused, so a line can say what was tried. `create_service` creates only; the description and the failure actions are `set_description` and `set_recovery`, install's steps (d) and (e). `rp::scm::read_setup` reads a service back into a `ServiceSetup`. A start type or action `service.hpp` has no word for is error 13.
   - `rp::ServiceReport` has no Windows code: `scm.cpp` reports 1066 with the service's own code when it isn't 0.
   - `rp::Service::run` answers `ServiceRun{exit_code, dispatcher_error}`; the command prints the 1063 line, and any other dispatcher error as `opening the service control manager failed (error <n>)`. Three events: the stop (the context's), the work's end, and the wake the main function waits on.
   - A handler that can't be registered ends the process with 1 (nothing can be reported without its handle). An exception from the service's own steps that the entry gives no code for is `the service ended on an unexpected failure` in the log, `stopped` with code 3 only when a stop was asked for, and `exit_process(1)` always. A second stop or shutdown control is answered and does nothing.
   - `ServiceCommandEnv`: every member null means the real one. A failed log folder is always `making the log folder failed (error <n>)`, 5 included. A roll-back whose delete answers 1060 ends `; the service was not installed`. A `--config` that isn't UTF-8 is `service error: the --config path is not valid UTF-8`, exit 1; one holding a quote is refused as not absolute. In the command line, backslashes before the closing quote of `--config` are doubled. A lost stdout is `service error: the answer couldn't be written`, exit 1.
   - The real dispatcher answers 1063 to the first call of a process and 1056 to every later one; the three tests that call it ask `rp::test::next_real_dispatcher_answer()` which to expect, so `rptests` passes in one process (the coverage run) as in many (ctest).
   - The source scan of point 8 bans more than the entry lists (`_Exit`, `exit` and `terminate` when called, `WinExec`, `popen`, `_wpopen`, the `_spawn` and `_exec` families) and reads comments: three comments of `main` were reworded rather than exempted.
   - `redact(redact(x)) == redact(x)`, which the entry's sink test needs, failed for a `name: value` whose PEM block ended with text on its END line; `through_private_key` takes such a value to the end of that line (one row's expectation changed; only ever more is redacted). The second review then made that rest of the line read before it goes (its point 2).
2. **The first code review (five reviewers, each finding checked by a second): three confirmed, all low, fixed test-first in commit ad2d4d4, plus one answer of Windows made safe.**
   - A. A stop the work asked for itself left the handler's state free, so a control a few milliseconds later could report `stop pending` after `stopped`. The main function now takes the handler's state when it takes the stop path.
   - B. `service start` refused with 5 by the start call itself (the caller already opened the service, so it is elevated) told an administrator to elevate. It is now `NT SERVICE\RestoreProof was denied access when starting (error 5); it must be able to read and run the service's executable`. This amends point 2's "access denied from any call".
   - C. The elevated `scm_test` built its command line in the ANSI code page; it is UTF-8 now.
   - D. Microsoft's documentation gives 1061 for a service that is still starting as well as for one that is stopping; the entry read 1061 as "a stop under way". `service stop` now reads the state while it waits and sends the stop again while the service reads `start pending` and no stop was taken; at the deadline that is `still starting after 35 s; the stop was not sent`. Not seen live: the service starts in under a second.
3. **The gate's one failure was from `main`.** `src/outbox.cpp` was 427 of 428 since the W4.6 review: the closing line of the `folder_changed` branch carried only its local's clean-up. The local has its own scope now (commit 9e9816f); behaviour unchanged.
4. **The live Done-when, 2026-10-08, elevated, on this machine; evidence `docs/api/veeam-lab/w4.7-*`, harness `w4.7-harness/w47-run.ps1`.** Steps (a) to (e) and (g) ran on commit 9e9816f; step (f) ran again on ccd8def, the second review's rotation, which changed nothing else the run touched.
   - (a) `install --config <a copy of the lab config under %ProgramData%\RestoreProof\w47>`: exit 0. `sc qc` `AUTO_START`, `NT SERVICE\RestoreProof`, the display name, the quoted command line; `sc qfailure` three restarts after 60,000 ms and 86,400 s. The registry's `FailureActions` holds four actions, the fourth `none`, as written: **Windows takes the list.** The owner saw it in services.msc.
   - (b) `start`: `started RestoreProof`; the process's owner `NT SERVICE\RestoreProof`; the start line in `worker.log`, the file owned by the account: **the account creates and writes its log under the inherited ACL.** A second start: `RestoreProof is already running`.
   - (c) The process killed at 15:12:50Z: event 7031, started again at 15:13:50Z.
   - (d) The owner restarted the machine. The log shows `stop requested (shutdown)` and `service stopped after 0 ms` at 15:56:30Z; after the boot at 15:56:51Z the service was running from 15:57:01Z with nobody starting it.
   - (e) `stop`: `stopped RestoreProof in 0.2 s`, the two stop lines, no event; a second stop `RestoreProof is already stopped`.
   - (f) The service's own `worker.log` filled to 60 bytes under 10 MiB, then the service started while a reader held `worker.log` open without delete sharing: no rotation, the start line appended, nothing emptied. The reader let go; the stop's line rotated it, `worker.1.log` keeping all 52,428 filler lines and the start line: **the account renames its own files.** The five values the lab's vault was filled from, a JWT shape, a PEM header and an `MII` run: 0 in every file. (The idle service writes three kinds of line, so the search says little beyond them; the redaction itself is the unit tests'.)
   - (g) The process killed (a restart queued for 60 s later) and `uninstall` run 4 s after: `uninstalled RestoreProof` at once, and nothing came back after the minute. **A queued restart doesn't hold an uninstall.**
   - The teardown: `sc query` 1060 for `RestoreProof` and `RestoreProofScmTest`, the config copy and `logs\` taken away. **Nothing is installed.**
   - Not shown live: the refusal without elevation (UAC's Admin Approval Mode is off here); the fake SCM's table holds it.
5. **The runs.** `ctest --preset dev` 1,842 of 1,842 before the second review's commit; the coverage gate's results are in the PR. Two background runs of the full suite and of the coverage script were stopped by Claude Code for low memory on this 16 GB machine while other work ran; run one at a time they finish.

**Open**, beside the entry's own: the second review's listed findings it didn't fix (its entry's Open); `service stop`'s 1061 rule (point 2 D) seen only on the fake SCM.

---

## 2026-10-08 — W4.7 code review, findings 1 to 3: the log's rotation is our own and loses no line to a rename that fails; `redact()` reads the rest of a private key block's last line before it takes it

Amends point 7 of the W4.7 entry below ("Rotation" and "The path"). Each was seen failing first.

1. **The rotation is ours; the live file is still spdlog's.** spdlog's `rotating_file_sink` answers a rename that fails by reopening the live file truncated and throwing: every line in `worker.log` is gone, `SECURITY:` ones included, with the line being written, and one write failure is counted. Windows refuses such a rename whenever somebody holds one of the files open without sharing its deletion, which is what a CRT, Python or .NET reader tailing the log does, and a copy or a hash under way. So the "rotating sink of our own" that point 7 rejected is built after all, as small as it can be: `LogFileSink` in `src/service_log.cpp` (strict) keeps spdlog's `file_helper` for the live file, under the same ANSI name, and makes the renames itself (`rp::detail::make_log_file_sink`, `rename_log_file`: one `MoveFileExW` that replaces; a seam in `src/service_log_detail.hpp` for the tests).
   - A line that would take `worker.log` past its limit first moves the files one number up, the oldest first and `worker.log` last, **as far up as the first number no file has**. Only when every number is taken is the oldest file replaced, which is the rotation's one intended loss.
   - It **stops at the first rename that fails**. No file is put over one that stayed, nothing is emptied, the line is appended to `worker.log`, and the next line tries again. That try ends at the number the failed one left free, so it replaces nothing: a blocked rotation costs at most the one oldest file a finished one would have cost.
   - **The price: `worker.log` is over 10 MiB, and the set over 50 MiB, for as long as the reader holds its file.** Such a line is written, so it is no write failure and nothing counts it; the file's size is the only sign. *Rejected:* emptying the live file to keep the cap (what spdlog does: the lines an incident is read from are the ones lost); a second live file under another name (a reader of `worker.log` would miss the newest lines); a `warn` line of the log's own about the stuck rotation (a line from inside the sink, at every line while it lasts; W7.2's doctor can read the size instead).
   - A `worker.log` that can't be opened again after a rotation fails that line **and every line after it, each counted**, until it opens, which every line tries. spdlog dropped those lines without counting them.
2. **`redact()`: the rest of the block's last line is read before it goes.** W4.7 made a value that ran to its line's end take the rest of its private key block's last line too, so that a second redaction changes nothing. It took that rest unread: a second secret that opened there (another block, a quoted value over two lines) lost its opening and its later lines came out in clear, which `main` had redacted. `through_private_key` now scans that rest as the main pass would have; a secret that starts in it and ends behind the line's end goes whole, and the replacement with it to the end of that secret's last line, where the same holds again. One level of calls however many blocks follow one another.
3. **`redact()` is linear again.** Whether a value ran to its line's end was asked by reading on to the line's end, for every secret: a megabyte that is one line of secrets took 24 s (6 ms on `main`). It is now asked of the byte behind the value (`at_line_end`).

**Tests.** `tests/redact_test.cpp`: the table "redact reads what follows a private key block's END line before it goes", a megabyte of blocks chained on their END lines, a megabyte that is one line of secrets (with a wide time bound, the one timing assertion there). `tests/service_log_test.cpp`, "A rotation that can't be made": a real reader holding `worker.log`, one holding an old file, the full set of five with a reader on `worker.1.log`, a rename refused half-way through the seam, and a `worker.log` that can't be opened after its rotation. `service_log.cpp` 160 of 160 lines, `redact.cpp` 329 of 329.

**Open.** The other findings of that review (the service's stop paths, `service stop` and `install`, the harness's step (f), the stale header and build notes); `redact(redact(x)) == redact(x)` still fails for a value cut short of its rule's own end (over-redaction only).

---

## 2026-10-08 — W4.7 (#50): the Windows service wrapper. `rpworker service install|uninstall|start|stop` through the SCM API, the service `RestoreProof` under `NT SERVICE\RestoreProof`, a rotating `worker.log` that redacts every line and always holds the SECURITY ones, and a stop that ends within 30 s (recorded before the build; the owner approved it as written)

W4.7 (#50) makes the Worker a Windows service. Done when: "The service starts at boot, appears in services.msc, and stops cleanly." This entry works from issue #50, the owner's scope for the task (2026-10-08), the W4.12, W4.5, W4.6 and W4.4 entries and their Open points, Microsoft's pages for the service functions, and the code. No code is written yet; the build notes below record what the build found. The service's body is a seam: in W4.7 it waits for the stop and does nothing else. The poll and heartbeat loop, `running.json` and the interrupted-run rule are W4.8's; the installer, the vault grant, the folders' ACLs and the Read ACE on Veeam's key are W7.1's; doctor is W7.2's.

**What the investigation found, since the points below rest on it.**

- **Nothing of a service exists.** No SCM call, no `ServiceMain`, no file log, no stop flag anywhere in `src/`, `include/` or `app/`. Every line a command writes goes to the two streams `wmain` hands in, and `make_command_logger()` writes warnings to stderr; a service has neither.
- **`log_level` is already a config key** (W1.2: optional, default `info`, one of `trace`, `debug`, `info`, `warn`, `error`, `critical`, `off`), validated, printed by `config check` and read by nothing. So the level needs no new key, only its first reader. `off` is a legal value, which "SECURITY lines always written" has to hold against.
- **Redaction is a convention at each call site, with one exception already** (`timestamper.cpp`'s debug line, which holds two numbers and a fixed word). The one emitter of a SECURITY line is `rp::log_security`: level `critical`, payload starting `SECURITY: `; nothing else logs at `critical`, and tests pin both.
- **spdlog as built opens files through the narrow CRT calls** (`_fsopen`, `std::rename`; `SPDLOG_WCHAR_FILENAMES` is off and can only be turned on in a triplet), so a path reaches it in the machine's ANSI code page, not as UTF-8. Its `rotating_file_sink(name, max_size, max_files)` keeps `max_files` old files beside the live one (`worker.1.log` is the newest old one), makes the folder when it opens the file, and by default never flushes.
- **A virtual account exists only while its service is installed** (seen here: `NT SERVICE\Spooler` resolves, the name of a service that isn't installed doesn't), so `vault grant` and `icacls` by name work only after `service install`. Its SID follows from the service's name (W4.5), so the name chosen here is the name every later ACE carries.
- **What the SCM does, from Microsoft's pages.** A virtual account is `lpServiceStartName` `NT SERVICE\<service name>` with `lpPassword` null. Only an administrator gets an SCM handle that can create a service, and the service object's default DACL lets only administrators start, stop and delete it; anyone may query it. A service has failed "when it terminates without reporting a status of SERVICE_STOPPED"; the N-th failure since the count was last reset runs action N of the list, and past the list's end the last action is repeated, so three restarts and then none is a list of four. A restart action needs the handle that sets it to hold `SERVICE_START`. `StartServiceCtrlDispatcherW` fails with 1063 in a process the SCM didn't start. The handler must return at once and never block; after `SERVICE_STOPPED` is reported the process may be ended at any moment, so nothing is done after it. `StartServiceW` returns before the service says it runs, and `DeleteService` only marks a service whose handles are open elsewhere (an open services.msc holds one). A queued restart "cannot be canceled": once a failure has queued one it fires after its delay whatever was started or stopped in between. At system shutdown a service has `WaitToKillServiceTimeout` (20 s on this machine, less on others), not 30 s.
- **No wait in the run pipeline can be cut short today, and several are longer than 30 s** (the restore poll up to 20 min, a Graph retry wait up to 120 s, the TSA's 30 s and 60 s, an upload's 120 s). All the sleeps but one go through one function, `ConnectorOptions::sleep` (the download client leaves `HttpClient`'s own retries on, and those wait on its default `sleep_for`); an HTTP request in flight ends only by its own timeout (the restore POST's is 60 s). A process killed after a restore POST leaves Veeam restoring into the targets, the restore's explore session Working (it is left open on purpose after a POST) and the run mutex abandoned. The next run is refused once for the mutex; the one after cleans before, first and without any look at Veeam, and is then refused by the Working-session preflight (`error backup`, exit 4, "stop them first") for as long as a session of ours reads Working: the preflight refuses, it never waits, and nothing in the Worker stops such a session today.

**Decision.**

1. **The names.** The service's name is `RestoreProof`, its display name `RestoreProof Worker`, its description `Tests that Microsoft 365 backups in Veeam Backup for Microsoft 365 restore: restores a sample into test locations and checks it.` Its account is therefore `NT SERVICE\RestoreProof`. They are constants in `rp/service.hpp` (`kServiceName`, `kServiceDisplayName`, `kServiceDescription`, `kServiceAccount`), not options: one Worker serves one Veeam server (2026-09-29), so one machine has one such service, and a second name would be a second SID that no ACE names. This is the issue's own name and the one `docs/worker-config.md` already uses as its example.

2. **`rpworker service`: five subcommands, one of them the SCM's.** `install [--config <path>]`, `uninstall`, `start`, `stop`, and `run [--config <path>]`, which is what the service's command line names and what nobody types. Any other word, a word too many, an option twice, without its value or with an empty one is the usage line and exit 64, before any call. None of them reads the vault, and only `run` reads the config. Each prints its answer on stdout and its one `service error: ...` line on stderr. Exit codes: 0 done; 3 not yet, and trying again may do it: the lines marked exit 3 below (still starting, still stopping, stopping when asked to start, and both `marked for deletion` lines); 1 every other `service error`, and an answer that didn't reach stdout; 64 usage. (3 is `exit_code::transient`'s number; `exit_code::service`, 4, which means a Veeam or Graph error, is not used here.) The texts below are the whole list; `<n>` is Windows' error code in decimal, as `sc` and `net helpmsg` take it.
   - **Shared refusals.** Access denied (error 5) from any call: `service error: access denied; run this from an elevated prompt (Administrators)`. The service not there (1060) for `uninstall`, `start`, `stop`: `service error: the service RestoreProof is not installed`. Marked for deletion (1072): `service error: the service RestoreProof is marked for deletion; close services.msc and any other tool that has it open, then try again`, exit 3 from every subcommand. Anything else: `service error: <what was tried> failed (error <n>)`, the first part one of `opening the service control manager`, `creating the service`, `setting the description`, `setting the recovery actions`, `opening the service`, `starting the service`, `stopping the service`, `deleting the service`, `reading the service's state`, `making the log folder`.
   - **`install`** needs an elevated administrator and does exactly this: (a) with `--config`, holds the path to an absolute one (`service error: --config must be an absolute path; a service's working directory is System32`) without reading the file; (b) creates the service: own process, automatic start (not delayed), error control normal, account `NT SERVICE\RestoreProof` with no password, command line `"<this rpworker.exe's full path>" service run`, with ` --config "<path>"` after it when given (the path quoted; a path can't hold a quote); access denied, a service already there and a display name in use end here, with nothing made; (c) makes `%ProgramData%\RestoreProof\logs` when it isn't there (one `create_directories`, the inherited ACL, an existing folder's ACL never changed); (d) sets the description; (e) sets the recovery actions, point 4. If (c), (d) or (e) fails the service is deleted again and the line ends `; the service was not installed` (or, if that delete fails too, `; the service was left installed: run rpworker service uninstall`). The folder is thus only ever made by a caller the SCM took for an administrator, and one made in (c) stays, as `uninstall` leaves it. stdout, two lines: `installed RestoreProof: <command line>` and `account NT SERVICE\RestoreProof, automatic start, restart after 60 s up to 3 times; not started: run rpworker service start`. A service of that name already there (1073): `service error: the service RestoreProof is already installed; uninstall it first`, nothing changed. The display name taken by another service (1078): `service error: the display name RestoreProof Worker is in use by another service`. **It does not** start the service, read or check the config or the vault, grant the account anything (the vault's Read entry, the key file's ACE, a folder's ACL: W7.1, which runs this command first because the account doesn't exist before it), register an event source, or copy the executable: the service runs the file `install` was run from, which the account must be able to read and run.
   - **`uninstall`** reads the state first. Anything but stopped: `service error: the service RestoreProof is running; stop it first (rpworker service stop)`, nothing changed. Then one delete, then the state read every 250 ms for up to 10 s until the service is gone: `uninstalled RestoreProof`, exit 0; still there: `service error: the service RestoreProof is marked for deletion; it goes when services.msc and any other tool that has it open are closed`, exit 3. It deletes the service and nothing else: the logs, the config, the vault, the runs and the outbox stay.
   - **`start`** sends the start, then reads the state every 250 ms for up to 30 s. Running: `started RestoreProof`, exit 0. "Already running" (1056) is Windows' one answer for a service that isn't stopped, so it is a reason to read the state and never the answer: running at that read, `RestoreProof is already running`, exit 0; starting, the same wait as after a start that was sent; stopping, `service error: the service RestoreProof is stopping; start it again when it has stopped`, exit 3 (the stop was someone's, and `start` doesn't wait it out to undo it); stopped by then, the start is sent once more and a second 1056 is the "anything else" line. Stopped again: `service error: the service RestoreProof stopped while starting (<reason>); see <log file>`, exit 1, `<reason>` being `the config couldn't be loaded` for the service's own code 1, `the log couldn't be opened` for 2, else `service error <n>` or `Windows error <n>`. Still starting: `service error: the service RestoreProof is still starting after 30 s`, exit 3. Disabled (1058): `service error: the service RestoreProof is disabled`. The account refused (1069): `service error: NT SERVICE\RestoreProof couldn't log on (error 1069); it needs the "Log on as a service" right`. The executable gone (2, 3): `service error: the service's executable isn't where it was installed from; uninstall and install again`.
   - **`stop`** sends the stop, then reads the state every 250 ms for up to 35 s (the service's own 30 s and a margin). Stopped: `stopped RestoreProof in <s.s> s`, exit 0. Already stopped (1062): `RestoreProof is already stopped`, exit 0. A stop already under way (1061) is waited for the same way. A service still starting (1052) was not sent the stop, since it accepts no control while starting (point 5), so the stop is sent again every 250 ms inside the same 35 s until it is taken (then the wait), the service has stopped by itself (1062, above) or the time is up: `service error: the service RestoreProof is still starting after 35 s; the stop was not sent`, exit 3. Still not stopped: `service error: the service RestoreProof is still stopping after 35 s`, exit 3. **Within 60 s of a failure a stopped service doesn't stay stopped:** the restart point 4 queued can't be cancelled or even seen, so `already stopped` and `stopped ... in` are both followed by the SCM's own start when the minute is up; whoever needs it down stops it again after that, or disables it (`sc config RestoreProof start= disabled`, Microsoft's remedy). `stop` doesn't disable: that is a change to the service nobody asked for.
   - **`run`** calls the dispatcher and nothing before it (the SCM gives a process 30 s to do so; everything else happens in the service's main function, point 5). In a process the SCM didn't start (1063): `service error: service run is what the Service Control Manager starts; use rpworker service start`, exit 1, nothing logged and no log file touched. Under the SCM the process's exit code is 0 after a clean stop and 1 otherwise; nobody reads it (the SCM reads the status the service reported, where its own codes 1, 2 and 3 are).
   - *Rejected:* a `--name` option (point 1); `install` over an existing service changing it in place (a repointed executable or account without anyone having asked for it; `uninstall` then `install` says what happens); `uninstall` stopping the service itself (one command, one change; a stop that takes its 30 s is `stop`'s to report); `start` and `stop` refusing the state they were asked for (they ask for a state, and a script that runs `stop` twice shouldn't fail; `install` and `uninstall` change the machine, so they refuse); `stop` refusing a service that is still starting (a start lasts milliseconds; sending the stop again is what the caller would do).

3. **`app/main.cpp` stays the forwarder, and nothing is excluded from coverage.** `service` is one more word in `dispatch`. `run` reaches the dispatcher through the same `run_main` every command goes through; the service's main function and its control handler are two small static functions in `src/scm.cpp` that call back into `rp::Service`. This closes the 2026-09-24 entry's "a future Windows service entry point that tests can't run will get its own entry if it has to be excluded": it isn't excluded.

4. **Recovery: restart after 1 min, three times, then nothing.** The failure actions are four: restart after 60,000 ms, three times, then none; the count resets after 86,400 s without a failure. The fourth entry is what makes "three times" true: with three, Windows would repeat the last one and restart for ever. The failure-actions flag is left at its default (a failure is a process that ended without reporting `SERVICE_STOPPED`), so what restarts the service is a crash, a kill or the unexpected failure of point 5 while no stop was asked for; a stop that was asked for, however it ends, and a start that ended with one of the service's own codes (a config that doesn't load, a log that can't be opened) never do: restarting wouldn't change either, and both say what is wrong. `sc qfailure` shows the three restarts and not the fourth entry, and services.msc shows First, Second and Subsequent failures as "Restart the Service"; whoever saves the Recovery tab there writes three actions and loses the fourth. *Rejected:* the flag set, so that a non-zero exit restarts too (a broken config restarted three times a day for nothing); a reboot or a command as an action.

5. **`rp::Service`: the state machine, over a host it is handed.** `rp/service.hpp` and `src/service.cpp` hold every decision: what is reported when, what a control does, the stop's budget, the exit codes, every log line. They reach Windows only through `ServiceHost` (four functions, each null = the real one in `src/scm.cpp`: run the dispatcher with a main function, register a control handler, report a status, and `exit_process(code)`, which ends the process at once without the C++ runtime's shutdown and, for real, doesn't return), and they wait and read the time through two more seams, `wait_done(ms)` and a steady `now`, so the tests run the whole life of a service on a fake host, never touch the SCM and never really wait.
   - **Start.** The main function registers the handler, reports `START_PENDING` (checkpoint 1, wait hint 10 s, no control accepted: Microsoft's rule while starting), opens the log at `info` (point 7), loads the config (`--config`, else `default_config_path()`), sets the log's level from `log_level`, starts the body on a thread of its own, reports `RUNNING` accepting stop and shutdown, and logs `service running: rpworker <version>, config <path>, log_level <level>` at `info`. A log that can't be opened: `STOPPED` with the service's own code 2 (`ERROR_SERVICE_SPECIFIC_ERROR`), nothing else possible. A config that doesn't load: one `error` line `config error: <the ConfigError's text>` (the text `config check` prints, which never holds a value), then `STOPPED` with code 1. In W4.7 the config is read for `log_level` alone, but the whole file must be valid, as for every command; the vault isn't read (W4.8 reads it per run, as the commands do).
   - **The body is the seam W4.8 fills.** `ServiceBody` is a function taking a `ServiceContext` (the `StopSignal`, the logger, the config and its path) and returning when it is done. W4.7's body is `stop.wait()`. The thread it runs on is its own from start to end, so a run's mutex, which Windows ties to a thread, is taken and released on one thread. That thread runs the body inside a catch-all, notes how it ended (returned or threw), sets a second signal, `done`, and ends; it never logs the end, reports a status or ends the process. All of that is the main function's, so nothing races. The context and `done` are shared (`shared_ptr`) between the two threads.
   - **The wait while running.** After `RUNNING` the main function waits for whichever comes first, the stop or the body's end: `request()` and the body's last act set one wake event, and the main function then reads which it was. The four endings: a stop first and the body back inside the budget is point 6's clean stop; a stop first and the body not back is point 6's cut-off; the body ending with no stop asked for, by a throw or by simply returning, is the unexpected failure below; a body that throws after a stop is below too.
   - **`rp::StopSignal`** (`rp/stop_signal.hpp`, `src/stop_signal.cpp`) is a manual-reset event: `request()` (the handler's one call: no lock, never blocks), `requested()`, `wait()`, and `wait_for(ms)`, which returns true at once when a stop was asked for. It is the stop source W4.4 and W4.6 left open: W4.8's interruptible sleep is `wait_for` handed in as `ConnectorOptions::sleep`.
   - **The handler.** Stop and shutdown are one path: the handler reports `STOP_PENDING` (checkpoint 1, wait hint 5 s, no control accepted), calls `request()` and returns `NO_ERROR`. Interrogate returns `NO_ERROR`; anything else `ERROR_CALL_NOT_IMPLEMENTED`. It logs nothing itself (a log write takes a lock); the main function logs `stop requested (stop|shutdown)`.
   - **An unexpected failure.** A body that ends while no stop was asked for is logged as `error`, `the service's work ended on an unexpected failure` for an exception (never its text) or `the service's work ended without a stop` for a return, the log is flushed, and the main function ends the process with `exit_process(1)` without reporting `STOPPED`: to the SCM that is a failure, and point 4 restarts the service after a minute, three times at most. The body W4.8 writes catches what a job throws; this is for what it didn't foresee, and for a loop that fell out. **After a stop was asked for** an exception leaving the body gets the same `error` line, but then `STOPPED` is reported with the service's own code 3, the last thing done: the SCM counts no failure and nothing restarts a service someone stopped, and the System log still shows the stop wasn't clean. `stop` prints `stopped RestoreProof ...` for it; the `error` line is in the log.
   - **No thread returns into the runtime while the body lives.** `exit_process` is always the last thing its caller does. When the body was cut off or the failure path was taken, `Service::run`, on the thread that called the dispatcher, calls `exit_process` too when the dispatcher returns, instead of returning to `run_main`: reporting `STOPPED` is what lets the dispatcher return, so whichever of the two threads gets there first ends the process, and neither runs static destructors under a thread that is still working. `run` returns through `wmain` only when the body's thread has ended: a clean stop, a start that failed with code 1 or 2, a throw after a stop, or the 1063 refusal.

6. **The stop: 25 s for the body, 30 s in all, and what "finish the current step" means.**
   - **The mechanics.** After a stop the main function waits for `done` (through `wait_done`) in slices of 2.5 s, at most ten of them, and after each slice in which the body hasn't ended reports `STOP_PENDING` with the next checkpoint (2, 3, ...) and the same 5 s hint, so the SCM and any tool watching see the stop moving and the hint is never outrun. When the body has returned its thread is joined: `service stopped after <n> ms` at `info`, the log flushed and closed, then `STOPPED` with exit code 0 as the last thing done. When it hasn't after 25 s its thread is detached: `error` `the service's work didn't end within 25 s of the stop; ending the process`, the log flushed, `STOPPED` with exit code 0 (the stop was asked for, so it is no failure and nothing restarts it), then `exit_process(0)` at once, because a thread is still running and must not meet the runtime's shutdown (point 5's last rule). The 5 s left are for the flush and the exit. With W4.7's body the first wait returns in milliseconds.
   - **What it promises for a run, which W4.8 builds and this entry fixes.** A step is finished when nothing it started in the tenant or in Veeam is half done. After a stop the body starts nothing it couldn't leave: no new job, no new restore POST, no wait (a retry's, the poll's, the TSA's: `wait_for` returns at once and the waiting code gives up as it does at its own deadline). What is already in flight goes on for as long as the 25 s last. A run that reaches its end inside them (the status, the clean after, the signed folder queued) is a normal run. One that doesn't is left where it is, on purpose and on record. The record can't depend on anything done after the stop: the body's thread may be inside a request that only its own timeout ends (the restore POST itself has 60 s), and a kill or a system shutdown gives no warning at all. So the state W4.8 defines is written ahead: which run, before its first step, and that a restore POST may have gone out, before the first one is sent; a record found at the next start is an interrupted run, and one that names a POST is a restore that may still be running, whether or not Veeam took it. W4.7 itself persists nothing (its body holds no state; its log is flushed line by line) and guarantees one thing: the process is gone within 30 s of the stop. The file, its format and what the next start does with it are W4.8's.
   - **A stop during a restore.** Before the first restore POST the run ends through `finish` as a stop with nothing restored: no POST is sent, the explore sessions are stopped if the 25 s allow (each stop is a request of up to 30 s; one left Working refuses the next run, as the finding above says), the clean after is skipped because there is nothing to clean. After a POST the two rules can't both hold inside 30 s (the poll alone may take 20 min, and a clean after while Veeam is still restoring would delete under it), so the 30 s win and neither rule is broken: the POST is never sent again, by this process or the next, and the clean after for that restore is the clean before of the first run that starts once Veeam's session has ended. That is the rule a restore-phase stop has had since W3.4 (`the restore may still be running; the next run cleans before`), with its known weakness, which a service that restarts by itself meets more often than a person at a prompt: a run started while the session is still Working cleans first all the same (nothing looks at Veeam before the clean before, so it may delete under the running restore; no verdict is read from the targets then, but nothing is emptied for good either) and is then refused by the preflight as `error backup`, nothing restored. So W4.8 must look for a Working session of ours before it starts a job after an interrupted run, and wait or put the job off; W4.7's idle body starts no run, so nothing here can meet it. A stop that arrives when the restore has ended (the read back, the check, the clean after, the run folder) lets the run go on to its end if the 25 s allow, and a run cut off there is an incomplete folder, never a cut-down result: `result.json` is still written last, and nothing is signed twice.
   - **At system shutdown** Windows gives less than 30 s (20 s here) and then ends the process whatever it is doing. That is the same outcome as the 25 s running out, without the last log line; the next start treats both alike. *Rejected:* `SERVICE_ACCEPT_PRESHUTDOWN` with a long timeout, to finish a run before the machine goes down (it holds up the shutdown of a customer's Veeam server for minutes, which Microsoft's page reserves for "special circumstances"); staying in `STOP_PENDING` with moving checkpoints until a restore has ended (a stop that takes 20 min is not a stop, and at shutdown it is cut anyway); killing the body's thread.

7. **The log.** `%ProgramData%\RestoreProof\logs\worker.log` (`rp::default_log_dir()`, from the known folder as the config and the vault are), written by the service alone: no command logs there, and the commands' loggers stay as they are (stderr, warnings and worse).
   - **Rotation.** spdlog's rotating sink at 10 MiB a file and five files in all: `worker.log` and `worker.1.log` to `worker.4.log`, 50 MiB at most. Every line is flushed when it is written, so a kill loses none.
   - **One line per message**, UTC: `2026-10-08T12:00:00.123Z <level> <message>`, the level in spdlog's words (`info`, `warning`, `error`, `critical`). A control character in a message (a line break above all) is written as a space, so no message can forge a second line.
   - **Everything through `redact()`, in one place.** The logger's only sink is `rp::ServiceLogSink`, which wraps the rotating sink: it decides whether the line is written, passes the message through `rp::redact`, then the control-character rule, and hands the result on. So a line is redacted whether or not its call site did it (the Timestamper's is covered from now on), and a new call site can't forget. Most lines are redacted twice, which changes nothing (a test holds `redact(redact(x)) == redact(x)` over the redaction tests' inputs).
   - **The level, and the SECURITY lines.** `log_level` is the existing config key; this is its first reader, through a table of the seven words, not spdlog's parser. A line is written when its level is at or above the configured one, **or** when its message starts with `SECURITY: `, whatever `log_level` is. `off` therefore means "the SECURITY lines only". The logger's own level is `log_level`, or `critical` when that is `off`, and the sink then applies the rule; so a SECURITY line, which `log_security` always writes at `critical` (a test pins it), reaches the sink under every `log_level`, and the HTTP layer's `should_log(debug)` guards go on saving their work. The rule is on the prefix, not on the level `critical`, so it stays right if another critical line is ever added.
   - **The path** goes to spdlog in the machine's ANSI code page (the finding above). A folder whose path that code page can't hold is "the log can't be opened"; `%ProgramData%` is ASCII on every installation seen. *Rejected:* a triplet that turns `SPDLOG_WCHAR_FILENAMES` on (a second build of spdlog for CI and every developer, for a path that is `C:\ProgramData\...`); a rotating sink of our own over the wide calls (rotation's rename-and-truncate failure paths, written again).
   - **A write that fails** (a full disk), or anything thrown inside the sink (an allocation failing in `redact`), is counted by the logger's error handler and the line is not written, never written unredacted; nothing else changes: the service doesn't stop over its log. What doctor shows of it is W7.2's.
   - **The logger is handed on, never global**: not registered with spdlog and not its default logger, since `rptests` is one process and the units' "null means the default logger" paths are pinned by tests. `make_service_logger(folder, level, LogLimits)` takes the folder and the sizes, so a test logs into a temp folder with a 1 KiB limit and W4.9's sentinel grep can read the file. W4.8 hands the same logger to the pipeline as `connector_options.logger`.
   - **What W4.7 writes there:** the `service running`, `stop requested` and `service stopped` lines at `info`, and the `error` lines of points 5 and 6. With `log_level` at `warn` or above a clean start and stop leave no line; that is what the level asks for.

8. **Files, seams, and what is strict.** `service` joins `STRICT_NAMES`: `rp/service.hpp` / `src/service.cpp` (the state machine), `rp/service_command.hpp` / `src/service_command.cpp` (the five subcommands, every message and exit code; no `catch (...)` of its own, as the vault's and the outbox's) and `rp/service_log.hpp` / `src/service_log.cpp` (the sink's rule, the level table, the logger's making) are held to 100% line, because they decide whether a SECURITY line is written, whether a line is redacted and when a process holding a run is ended. Not strict, like `folder_ops.cpp` and `console_input.cpp` under their strict callers: `src/scm.{hpp,cpp}`, one SCM call sequence per function and nothing decided (each takes the service's name as an argument, opens and closes its own handles, and returns Windows' error code, never "it worked" for a call that failed: `create_service(ServiceSetup)`, `delete_service`, `start_service`, `stop_service`, `query_service` returning a neutral `ServiceStatus`, and the host's four functions with the two static callbacks; the real `exit_process` is one call that no test can run, which counts against this file's share of the 80% and never against a strict one), and `src/stop_signal.cpp` (one event). `ServiceSetup` carries everything a create passes (name, display name, description, account, start type, command line, the actions and the reset period) and one function, `service_setup(name, command_line)`, fills it, the display name and `NT SERVICE\<name>` following from the name; the product calls it with `kServiceName` only, and a test holds its result to point 1's four constants. The commands take them as `ScmCalls` and the service as `ServiceHost`, both structs of functions with null meaning the real one (the `OutboxFiles` pattern), in `ServiceCommandEnv` beside `own_path`, `default_log_dir`, `default_config_path`, `make_folder`, `sleep` and a steady `now`. No header under `include/rp/` names a Windows type. A source scan, in the manner of the TLS and `ListedItem` scans, fails on a service function of Windows named outside `src/scm.cpp`, on a call that ends the process (`ExitProcess`, `TerminateProcess`, `_exit`, `quick_exit`, `abort`) named outside it, and on any call that starts a process (`CreateProcess`, `ShellExecute`, `system`, `_popen`) anywhere under `src/`, `include/` and `app/`: the SCM is reached through its API and never through `sc.exe`.

9. **Tests, failures before the happy path.** On the fake SCM (`tests/service_lab.hpp`): every refusal of point 2 as a `GENERATE` table of Windows' code against the exact line and exit code, with the calls made counted (a usage error and a bad `--config` make none; access denied, 1073 and 1078 make no folder; a failed step (c), (d) or (e) deletes what (b) made); `start` and `stop` over state sequences with a fake clock, the calls counted (stopped while starting with each code, still pending at the deadline, already there; 1056 with the service running, starting, stopping and stopped; 1052 twice and then taken, 1052 then 1062, 1052 until the deadline); then the four happy paths and the exact command line, quoted, with and without `--config`. On the fake host: the handler never blocking and reporting before it requests; a log that can't be opened, a config that doesn't load, a body that throws and one that returns with no stop asked for (the `error` line, `exit_process(1)`, no `STOPPED`), a body that throws after a stop (`STOPPED` with code 3, no `exit_process`), a body that doesn't return (ten checkpoints through a `wait_done` that answers false at no cost, the `error` line, `exit_process(0)` as the last host call after `STOPPED`, and again when the dispatcher returns; the test then lets its body go and waits for it), a body that returns in the k-th slice, then the clean start and stop with every status in order; no assertion is made on the handler's or the body's thread, which only record; shutdown as stop; interrogate and an unknown control. The log: a sentinel written through a raw `logger->info` is redacted in the file; all seven levels as a table, each with a SECURITY line that is in the file and a `critical` line without the prefix that follows the level; a message with a line break is one line; rotation at a 1 KiB limit leaves five files and not six; a folder that can't be made. The real calls: `query_service` for a made-up name answers 1060 unelevated; elevated (`SKIP` otherwise, as the vault's owner tests; the coverage run is elevated), a service is created from `service_setup` under one fixed test name (`RestoreProofScmTest`, so its own display name and its own account, `NT SERVICE\RestoreProofScmTest`) with two fields changed so that a leftover can never run, the start type disabled and a command line naming a file that doesn't exist; it is read back (the four actions, 86,400 s, the description, the account), never started, and deleted. The test's first step deletes a service of that name left by a run that was cut off, and "marked for deletion" there is a `SKIP` that says so. The automatic start type is asserted where it is decided, on the fake, and seen in the live run's `sc qc`. Exe tests through `run_exe_test.cmake`: `service` alone, an unknown subcommand, a word too many, `--config` without a value, and `service run` from ctest's console (the 1063 line, exit 1), which is also what brings `src/scm.cpp`'s dispatcher call into the coverage report. **No exe test names `install`, `uninstall`, `start` or `stop` with valid arguments**: they would act on the machine's real service, which during the live run exists.

10. **The live Done-when**, on the lab machine, elevated, evidence as text under `docs/api/veeam-lab/w4.7-*` and the harness beside it. (a) `rpworker service install --config <a copy of the lab's config>`; `sc qc`, `sc qfailure`, `sc qdescription` and the registry's `FailureActions` decoded (four entries); the owner sees it in services.msc. (b) `rpworker service start`; the process's account is `NT SERVICE\RestoreProof`; `worker.log` holds the start line. (c) The process is killed: the SCM starts it again after a minute (System event 7031), which is point 4 seen once. (d) The owner restarts the machine; afterwards the service is running without anyone having started it, its start line later than the boot time. (e) `rpworker service stop`: `stopped RestoreProof in <s.s> s`, under 30, the stop lines in the log, no failure event. (f) Rotation with the real limits: the stopped service's own `worker.log` is filled to just under 10 MiB with filler lines and the service started; `worker.1.log` then holds the filler and `worker.log` the new lines. The secret check: every `worker*.log` is searched for the vault's five values (read elevated, compared in memory, only counts printed), a JWT shape and a PEM or `MII` block; all zero. (g) The process is killed once more and `rpworker service uninstall` run inside the minute, to see what a queued restart does to it (gone at once, or exit 3 and gone when the restart has failed); then, if the service is still there, stop and uninstall. `sc qc` answers 1060; the `logs` folder and the config copy are taken away; nothing stays installed. Not shown live: the refusal without elevation (UAC's Admin Approval Mode is off on this machine, W4.5 build note (e)); the fake SCM's table holds it.

**Reason.** A service is the one place where the Worker has no console, no operator and no second chance to say what went wrong, so the three things that are only true by convention today are made true by construction: every logged line is redacted by the sink and not by its author, a SECURITY line can't be configured away, and a stop ends in a bounded time whatever the body is doing. The SCM is reached through one small file that decides nothing, so the rules (what `install` leaves behind when a step fails, which exit restarts the service, what is reported in what order) are plain code that a fake drives through every branch. And the stop's promise is stated at its real size: 30 s is kept always, and what it costs a run in flight is said here, with the rules that already cover it, before W4.8 has to build on it.

**Alternatives rejected.**
- *LocalSystem, or a local account the installer creates* (the issue's second option): W4.12 decided the virtual account and why; a created account needs a password kept somewhere.
- *`sc.exe` or PowerShell from code:* the issue rules it out; a child process's text output would be parsed for what the API returns as a number.
- *The service's main function in `app/main.cpp`:* code no test runs, and the entry point excluded from the gate.
- *Delayed automatic start:* nothing the idle body waits for; W4.8 can ask for it if the first poll at boot proves too early for Veeam's own services.
- *Redaction left to each call site, checked by a source scan:* a scan can't see what a format argument holds; the sink can.
- *SECURITY lines to a second file, or to the Windows event log:* one more place with its own ACL and rotation; an event source is the installer's to register (W7.1) and can be added beside the file.
- *A named pipe or a custom control code to ask the service for its state:* nothing in W4.7 needs it; `sc query` and the log answer.

**Supersedes and closes, from earlier entries.** W4.12 (2026-10-07) and W4.5's Open left the service's name to W7.1: it is `RestoreProof`, fixed here. W4.12 said W7.1 "creates the service as a virtual account": W7.1's installer runs `rpworker service install` and then makes the grants. W4.4's Open "W4.7 and W4.8: ... (the sleep must be interruptible)": the stop source is `StopSignal::wait_for` and the rule is point 6; handing it to the pipeline is W4.8's. The 2026-09-24 entry on `app/main.cpp`: point 3.

**Open.**
- W4.8: the body (poll, heartbeat, the flush loop); `wait_for` as the pipeline's sleep and a stop check at the step boundaries of point 6, the Timestamper's and the poll loop's handling of a wait that ends early; `running.json`, the `interrupted` code and what the next start does with a run left behind; the abandoned run mutex after a process that was ended (the next run is refused once today); a look for a Working session of ours before a job is started after an interrupted run (point 6); the download client taking the pipeline's sleep; the streams the pipeline writes its lines to when there is no console; the cloud client's logger, which `make_cloud_http_client` fixes to stderr today.
- W7.1: the vault grant and the key file's ACE for `NT SERVICE\RestoreProof`, run after `service install`; the ACL of `logs\` (the account `Modify`; today the inherited ACL lets any local user create a file there before the service does, as it does for the vault; a `logs` folder that is already there when `install` runs keeps whatever owner and ACL it has); an event source; whether the installer copies `rpworker.exe` to a folder of its own before installing.
- W7.2: doctor reading the service's state, its account and recovery actions against point 4, the log's write failures, and a "Log on as a service" right a domain policy has taken from `NT SERVICE\ALL SERVICES`.
- W4.9: `worker.log` joins the files the sentinel grep reads.
- Not tried before the build, and the live run's to show: that Windows takes a fourth failure action of "none" as written (stock services carry such lists); that the account can create, write and rotate `worker.log` under today's inherited ACL without a grant; whether a stopped service with a restart still queued is deleted at once or stays marked until the restart has fired (step (g)).

**Code, tests and docs with the build.** `rp/service.hpp`, `src/service.cpp`; `rp/service_command.hpp`, `src/service_command.cpp`; `rp/service_log.hpp`, `src/service_log.cpp`; `rp/stop_signal.hpp`, `src/stop_signal.cpp`; `src/scm.{hpp,cpp}`; `rp/cli.hpp`, `cli.cpp` (the `service` word, the usage line, the exit codes' comments); `CMakeLists.txt`; `tools/coverage_gate.py` and its tests; `tests/service_test.cpp`, `tests/service_command_test.cpp`, `tests/service_log_test.cpp`, `tests/stop_signal_test.cpp`, `tests/scm_test.cpp`, `tests/service_lab.hpp`, `tests/redact_test.cpp` (redacting twice), the usage line's tests, the `rpworker service` exe tests; `docs/worker-config.md` "`rpworker service`", "The service's log" and the `log_level` row, `docs/testing.md` "The service by hand (W4.7)" and the strict names, `docs/glossary.md`, CLAUDE.md. `docs/verification.md` is not touched: nothing about a run or its result changes. The PR closes #50.

---

## 2026-10-07 — W4.6 code review (PR #163), findings 1 to 3: `--outbox` checked before the run, `cloud_ca_file` held to a certificate, a kept run's manifest written once and an unreadable file never "changed"

A `/code-review high` of the W4.6 branch (PR #163) found nine issues, none in what is signed or sent. The owner asked for the first three to be fixed and the branch merged (2026-10-07); findings 4 to 9 stay open below. Nothing here reopens a point of the W4.6 entry: the layout, the manifest, what a flush sends and never sends, the schedule and the caps stand.

**Decision.**

1. **Finding 1: what would stop the folder from being queued is found before the run.** With `--outbox`, once the config is read and before the secrets, the mutex and any Veeam call, `rp::Outbox::prepare(runs root, --run-id)` (strict, `src/outbox.cpp`) runs: with a `--run-id`, a run of that ID already under `outbox\` or `sent\` is refused; then `<root>\outbox` is made when it isn't there (and left: an empty folder the flush reads as an empty queue, the one side effect before "nothing was done"); then the runs root and `<root>\outbox` are held to one volume. Each is the W4.6 entry's line with `; nothing was done` after it (`outbox error: <root>\outbox\<run_id>: already queued; nothing was done`, `...\sent\<run_id>: already sent; nothing was done`, `outbox error: <root>\outbox: the folder couldn't be made; nothing was done`) or, for the volume, `outbox error: <dir>: not on the same volume as <root>\outbox; nothing was done`, exit 1, no run line, no secrets read. The volume check is a new seam, `OutboxFiles::same_volume`, whose real call is `rp::same_volume` in the not-strict `src/folder_ops.cpp`: `GetVolumePathNameW` on each path made absolute (neither need exist yet), the mount points compared without regard to case or to the `\\?\` prefix; a volume Windows can't name (a drive that isn't there) is nullopt and never a refusal, since the run folder's own check and the rename at the end say what is wrong. The end-of-run checks stay as they were, for a run without `--run-id` (its ID is made after the mutex and the restore point lookup) and for anything that changes during a run. *Rejected:* checking at `make_run_folder`, when every ID is known: that is after the mutex and one Veeam call, and the volume and the folder can be checked before the secrets with no ID at all; the two "already" checks for a made-up ID guard against nothing that can happen.

2. **Finding 2: `cloud_ca_file` is held to at least one certificate.** `load_config` reads the file whole (at most 1 MiB) and holds it to `openssl_rfc3161().certificates_in` ≥ 1, the count the TSA's CA file is held to by `rpworker test --evidence` and `signer verify`'s `--tsa-ca`; so a file that is empty, DER, cut off or a key block alone is `config error: <config>: config key "cloud_ca_file" names a file that holds no certificate (PEM)`, exit 1, from `config check` and every command that reads the config, instead of `upload_unreachable` at every flush for good with the cause in a log line. The three "names a file that can't be read" blocks for `veeam_ca_file`, `tsa_ca_file` and `cloud_ca_file` became one helper (finding 8 fell out of it); `veeam_ca_file` keeps the pin's check and `tsa_ca_file` its check at the run (the W4.4 entry: only `--evidence` needs it), both unchanged.

3. **Finding 3: a `folder_changed` manifest is written once, and a file that can't be opened is never "changed".** The flush builds the manifest's text before and after setting `last_error` and writes only when they differ, so a run kept for the operator costs no write per flush (under W4.8's loop that was a rewrite a minute). A file that is there, is a file and couldn't be read whole at that moment (another process holding it without sharing, a file still being written) is this flush's failure, not a change: `outbox error: <folder>: <file> couldn't be read` on stderr, `kept <run_id>: not_read` on stdout (`rp::kFlushNotRead`, never a manifest code), nothing written, the next flush tries again. Missing, too large and a folder in a file's place stay "changed". *Kept from the entry, on purpose:* every file is still read and checked at every flush a changed run is due, since point 3's rule is that nothing is sent unchecked and a folder the operator puts right is then sent with no manifest edit; `folder_changed` still counts no attempt and sets no `next_attempt_at`.

**Open, from the same review (findings 4 to 9).** The "moved" path for a manifest with `sent_at` doesn't run the "already sent" check, so an existing `sent\<run_id>` is "couldn't be moved to sent (error 183)" at every flush; a manifest that no longer parses is replaced with `queued_at` = now, which drops the run to the back of the queue and loses its attempt count and TSA code (the folder's creation time or `result.json`'s `started_at` would keep the order); `checked_parts` hashes `result.json` twice; `is_time` repeats `canary_manifest.cpp`'s `is_whole_second_utc` and takes an impossible date; `flush` rebuilds `not_a_run()`'s text by hand, and a `--outbox` value that isn't UTF-8 gets two different messages from `test` and `outbox flush`.

**Tests** (written with the code in one pass and seen green on the first build; not seen failing first, a departure from the rule, since the three fixes and their tests went in together). `tests/outbox_test.cpp`: `prepare` (nothing in the way, with and without an ID; already queued and already sent, with the ID only; the folder not makeable; the volume seam answering false, nullopt and true, and what it is asked); the changed table's new row (a folder in an attachment's place is "changed"); a changed run flushed twice writes its manifest once; each of `result.json`, `signature.json`, `timestamp.tst` and `items.csv` held open by another handle is "couldn't be read", `kept ...: not_read`, no write, the manifest byte for byte, and sent at the next flush. `tests/test_command_test.cpp` `[outbox]`: with `--run-id`, already queued or sent refused before the secrets and the mutex, nothing made; the root a file, and the volume seam false, likewise; the end-of-run refusal kept for a made-up ID. `tests/folder_ops_test.cpp`: `same_volume` true for two paths under one folder, one not there yet, and for the `\\?\` form, nullopt for a drive letter nothing is mounted at. `tests/config_test.cpp`: five files that hold no certificate refused, one that does taken; `config_check_test.cpp` and `outbox_command_test.cpp` now write a real certificate (`rp::default_tsa_ca_pem()`). Docs: `docs/worker-config.md` ("`--outbox <root>`" split into before and after the run, the flush's two new lines, `cloud_ca_file`), `docs/verification.md` "The outbox", CLAUDE.md.

## 2026-10-07 — W4.6 (#49): the local outbox. A signed run folder is queued under `outbox\`, uploaded later oldest first with retries, and moved to `sent\`; only `manifest.json` is ever rewritten (recorded before the build)

W4.6 (#49) queues a complete, signed run folder and uploads it later. Done when: "Killing the network mid-upload leaves the run in the outbox and it uploads later." This entry works from issue #49, the owner's seven decisions for the task (2026-10-07), the W4.2 to W4.5 entries and their Open points, and the code. No code is written yet; the build notes below record what the build found. The upload's endpoint is a stub until W5.1: the Cloud has no `/v1/results` and no API token exists, so the Worker posts to `cloud_url` with no credential, and W5.1 adds the token from the vault as the sixth name.

**What the code has that the points below rest on.**

- `HttpRequest::parts` already sends a multipart/form-data body (W1.3: curl writes the boundary, a part with a file name is sent byte for byte). The task expected the body to be built by hand; it isn't, and no dependency is added. The recorder never writes a multipart request body, so a recording of an upload holds the answer only.
- `HttpClientOptions::ca_file` (Veeam's) replaces the Windows store by one PEM file and keeps the host-name check. `cloud_url` is `https://` only and the loader refuses anything else.
- `write_file_atomically` never replaces a file; `read_whole_file` reads under a limit or is no file; `list_folder` lists a folder's names; `try_take_named_lock` is the run mutex's maker; `timestamp_time_text` writes `YYYY-MM-DDTHH:MM:SSZ`, a text whose byte order is its time order.
- `write_result` writes `result.json` last and hands back the `TimestampOutcome` (the W4.4 code when there is no token). `finish` releases the run mutex before the run folder's files are written.

**Decision.**

1. **Layout.** Two sibling folders under one root, by default `%ProgramData%\RestoreProof` (`rp::default_outbox_root()`): `outbox\<run_id>\` (queued) and `sent\<run_id>\` (uploaded). `rpworker test --evidence <dir>` writes `<dir>\<run_id>` exactly as today. A new `--outbox <root>` (only with `--evidence`, else the usage line and exit 64; an empty value too; a path that isn't UTF-8 is `config error: --outbox <root>: not a UTF-8 path`, exit 1, before the secrets) queues the finished folder: after `result.json` is written and the `signed`, `timestamped` and `evidence` lines are out, the folder is moved to `<root>\outbox\<run_id>` with one `MoveFileExW` without `MOVEFILE_COPY_ALLOWED` (a rename, never a copy, so both must be on one volume), then `manifest.json` is written there, then one more stdout line, `queued <outbox folder>`. The folder's name stays the run ID. Nothing is queued for a run whose folder has no `result.json` (a `result_invalid` run, any `evidence error`). On stderr, the status unchanged and an exit code of 0 becoming 1, the run folder left in `<dir>` as it is: `outbox error: <outbox folder>: already queued`, `outbox error: <sent folder>: already sent`, `outbox error: <run folder>: couldn't be moved to <outbox folder>: not on the same volume` (Windows' error 17) or `...: couldn't be moved to <outbox folder> (error <n>)`, and `outbox error: <root>\outbox: the folder couldn't be made`. A moved folder whose manifest can't be written is queued all the same (`queued ...` is printed) with `outbox error: <outbox folder>\manifest.json: could not be written; the next flush makes it`, 0 becoming 1. W4.8's service passes both roots.

2. **The manifest.** `manifest.json` is the Worker's own: never uploaded, never in `attachments`, no shared schema. In `canonical-json-v1`, exactly these keys: `{"attempts":n,"files":[names],"format":"restoreproof.outbox-manifest.v1","last_attempt_at":<time|null>,"last_error":<code|null>,"next_attempt_at":<time|null>,"queued_at":<time>,"run_id":<id>,"timestamp":{"code":<the W4.4 code|null>,"state":"timestamped"|"not_timestamped"}}`, and a tenth, `"sent_at":<time>`, once the run is uploaded. Times are UTC, whole seconds, `YYYY-MM-DDTHH:MM:SSZ`. `files` is the folder's names when it was queued, sorted by byte, without `manifest.json`. It is written whole (a temp file beside it, flushed, `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`): the one file the outbox rewrites. **That is where `tsa_error` goes:** `timestamp.code`. **Nothing else in a queued folder is ever written after it is queued:** the signed bytes, the signature and the token stay as the run made them. **`flush` never asks the TSA again:** a run that got no token is uploaded as "not timestamped" and stays so (a later token would be over the same hash and rewrite nothing signed, but it would be a second writer in a queued folder and a second time for one run; `rpworker signer timestamp <folder>` stays out of scope as in W4.4).
   - **A reader is strict:** the text must be its own canonical form with exactly those keys and kinds, a `run_id` that is the folder's name, `attempts` 0 to 1,000,000, times of that shape, `last_error` one of point 3's codes, `timestamp.code` null or printable ASCII of at most 64 characters. Anything else is no manifest.
   - **A queued folder without a readable manifest gets a new one at the next flush** (`queued_at` that flush's time, `attempts` 0, `timestamp.state` by whether `timestamp.tst` is there, `code` null), made with the writer that never replaces, so a manifest the queueing run writes at that moment wins. This is what covers the moment between the move and the manifest (a stop there, or a manifest that couldn't be written), and a manifest damaged later: the signed result is uploaded either way, and only the attempt count and the TSA's code are lost. One line on stderr says so: `outbox warning: <folder>: manifest.json was made again`.
   - **A folder under `outbox\` without `result.json` is not a queued run:** `outbox error: <folder>: no result.json; not a queued run` at every flush, never uploaded, never deleted, never counted as queued. So is one whose name isn't a plain file name. A file directly under `outbox\` or `sent\` is ignored.

3. **The uploader.** `rp::Outbox` (strict: `rp/outbox.hpp`, `src/outbox.cpp`) has `queue(run folder, run ID, now, timestamp outcome)`, `flush(IUploader&, now)` and `list()`. `flush` is one pass and never sleeps (the loop is W4.8's): first the caps (point 4), then every queued run whose `next_attempt_at` is null or not after `now`, oldest `queued_at` first (the run ID by byte for a tie). For each:
   - **Everything sent is read whole and checked first.** `result.json` (at most 16 MiB) must parse as a JSON object whose `run_id` is the folder's name; `signature.json` (at most 4096 bytes) must be a JSON object whose `bundle_sha256` is the SHA-256 of `result.json`'s bytes; `timestamp.tst`, there exactly when the manifest says `timestamped`, must be at most 64 KiB and one token whose imprint is SHA-256 and that same hash (`rp::Rfc3161::parse_token`; the chain isn't checked again, the run did that before it wrote the token); each attachment the result lists must be there with its size and SHA-256. A file that fails is `outbox error: <folder>: <file> changed since it was signed`: no request is built, no attempt is counted, the manifest gets `last_error` `folder_changed` and nothing else changes, the run stays queued and the operator decides (the Worker never deletes it). This is a check that nothing was altered since the run, not a verification: the signature is checked under the public key by the Cloud (C5.7) and by `signer verify`; the outbox reads no key and no vault.
   - **The request** (the real `IUploader`, `rp::CloudUploader` in `rp/uploader.hpp` / `src/uploader.cpp`, not strict, over `IHttpClient`): `POST <cloud_url>/v1/results`, multipart/form-data, the parts in this order: `result` (`result.json`, `application/json`), `signature` (`signature.json`, `application/json`), `timestamp` (`timestamp.tst`, only when there), then one part per listed attachment under its own name (`items.csv`, `veeam-session.log`, `screenshot.png`), each `application/octet-stream` with its file name. No `Authorization` header and no other credential until W5.1. Sent once (`max_attempts` 1, no retry on a status: the outbox owns the schedule), a 120 s timeout, at most 64 KiB of the answer read, redirects never followed.
   - **202 is sent.** `manifest.json` gets `sent_at`, `attempts` + 1, `last_attempt_at`, `last_error` and `next_attempt_at` null, written in place; then the folder moves to `sent\<run_id>` with the same one rename. The manifest first, so a move that fails (`outbox error: <folder>: uploaded, but couldn't be moved to sent (error <n>)`) leaves a folder the next flush only moves and never uploads again. A manifest that can't be written after a 202 (`outbox error: <folder>: uploaded, but manifest.json couldn't be written`) leaves the run queued, and the next flush uploads it again: W5.1's endpoint must take the same bundle twice. A `sent\<run_id>` that is already there stops the run before anything is sent: `outbox error: <sent folder>: already sent`, the run left queued.
   - **Anything else is a failed attempt:** `attempts` + 1, `last_attempt_at` = now, `last_error` one of `upload_http_<status>` (any answer but 202, a 2xx or a 3xx included), `upload_unreachable` (no connection, a TLS failure, a connection dropped mid-request), `upload_timeout`, `upload_internal` (an uploader that throws or answers a word that is none of these), and `next_attempt_at` = now + min(60 s × 2^(attempts − 1), 3600 s): 1, 2, 4, 8, 16, 32 minutes, then one hour for good. The folder is untouched but for `manifest.json`. A Worker stopped mid-request has written nothing: the attempt isn't counted and the next flush tries at once. **The upload sends nothing it didn't check and writes nothing before the answer.**
   - **One flush at a time:** `outbox flush` takes the named mutex `Global\RestoreProof-outbox` without waiting; held elsewhere it is `outbox error: another flush is running; nothing was done`, exit 3. The run mutex isn't taken: nothing here touches a restore target, and a run queues its folder after it has released the run mutex.
   - **With `--record <dir>`** the exchanges go under `cloud/` as content fixtures; the multipart request is never written, by the recorder's standing rule.

4. **The caps.** At every flush, first `sent\` runs whose `sent_at` is more than 30 days before `now` are deleted; then, while `outbox\` and `sent\` together hold more than 500 MB (500 × 1024 × 1024 bytes, each folder the sum of its files' sizes), the oldest `sent\` run by `sent_at` goes too. Each is `pruned <run_id>` on stdout. A `sent\` folder without a readable manifest has no `sent_at`: it is never deleted, by age or by size, and is `outbox warning: <folder>: no readable manifest.json; not pruned` at every flush; one that can't be removed is `outbox warning: <folder>: couldn't be removed`. **The queue is never pruned:** a signed result is never thrown away by the Worker. When the queue alone is over the cap: `outbox warning: the outbox holds <n> MB, over the 500 MB cap` on stderr, every flush (whole MB, rounded down), and the operator sees `outbox list`.

5. **The commands** (`rp::run_outbox_command` in `rp/outbox_command.hpp` / `src/outbox_command.cpp`, strict). Neither reads the vault.
   - **`rpworker outbox flush [--config <path>] [--outbox <root>] [--record <dir>]`** reads the config for `cloud_url` and `cloud_ca_file`. stdout: `pruned <run_id>` per deleted sent run; per queued run `sent <run_id>`, `kept <run_id>: <code>; attempt <n>, next at <time>`, `waiting <run_id>: next at <time>` (not due), `kept <run_id>: folder_changed` or `moved <run_id>` (uploaded by an earlier flush, moved now); then `<n> queued, <m> sent`. Exit 0 when nothing is left under `outbox\` that is a run, 3 when a run stays there (kept, waiting, changed, or another flush holding the mutex), 1 for a config error, a root that can't be read (`outbox error: <root>: the outbox can't be read`), an incomplete recording, or, when nothing stays queued, any other `outbox error` line; 64 usage.
   - **`rpworker outbox list [--outbox <root>]`** reads no config and changes nothing: one row per queued run, `RUN QUEUED ATTEMPTS NEXT LAST_ERROR TIMESTAMP` (`-` for null; TIMESTAMP `timestamped`, `not_timestamped` or `not_timestamped <code>`; a folder with `result.json` and no readable manifest is a row of `-` with LAST_ERROR `no_manifest`), then `<n> queued, <m> sent`. A root, or an `outbox\` or `sent\` under it, that isn't there is empty: `0 queued, 0 sent`, exit 0. Exit 1 only for a root that can't be read.

6. **Incomplete folders.** A folder under `<dir>` (the runs root) without `result.json` is a run that didn't finish (W4.4's review, finding 4: a stop during the TSA wait leaves a signed run's two text files). W4.6 never queues one and never deletes one; what the service does with it is W4.8's. The write order stays: `result.json` last, the move after it. So "is there a `result.json`" stays the one test for a complete folder, in the runs root and in the outbox alike.

7. **`cloud_ca_file`, a new optional config key.** An absolute path of a readable PEM file, read like `tsa_ca_file` (the form by `parse_config`, that it opens by `load_config`; `config check` prints it), handed to the Cloud's HTTP client as its CA file in place of the Windows store. The TLS rule is untouched: `cloud_url` stays `https://` only, verification is never off, the host name is still checked. It exists because the Done-when needs a Cloud that isn't there yet: the lab's stub answers on `https://localhost` with a self-signed certificate, and the only other ways to reach it would be an `http` `cloud_url` or switching verification off, both refused. A private Cloud behind an internal CA is the same case in production.

8. **Files, seams, and what is strict.** `rp/outbox.hpp` and `src/outbox.cpp` (every decision: what is queued, due, checked, sent, kept, pruned, and every message) and `rp/outbox_command.hpp` / `src/outbox_command.cpp` are strict; `outbox` joins `STRICT_NAMES`. Not strict, like `ed25519.cpp` and `console_input.cpp` under their strict callers: `src/uploader.cpp` (one HTTP call and its mapping to a code) and `src/folder_ops.{hpp,cpp}` (one Win32 or `std::filesystem` call each: `move_folder` returning Windows' error code, `folder_bytes`, `remove_folder`), with `AtomicWriteOptions::replace` in `src/atomic_file.cpp` for the manifest's writer. The outbox takes them as `OutboxFiles` (each null = the real one), so the strict file's failure branches are reached with a fake and the real calls through temp folders. `RestoreCommandEnv::outbox_files` is the pipeline's seam.

9. **Tests, fixtures first, failures before the happy path.** The uploader on `FakeHttpClient` (500 then 202, a dropped connection, a timeout, a TLS failure, a 200, a 301, a client that throws something else; the parts, their order, names and bytes; no `Authorization`); the manifest's every field and every refusal of the reader; the schedule table (1, 2, 4, 8, 16, 32 min, 1 h, 1 h); `queue` (not complete, already queued, already sent, not the same volume, another error, the manifest not written); `flush` (not due, due, oldest first, a changed result, signature, token and attachment each, a token without a manifest that says so, a folder without `result.json`, a manifest made again, 202 with the move refused and the next flush, the uploader throwing); the pruning table (30 days to the second, the 500 MB cap with the oldest first, a sent folder with no manifest, the queue alone over the cap); a run folder built by the test Harness (`test --evidence --outbox`) queued, flushed and still `verified`; `--record` under `cloud/`; the commands' lines and exit codes; `cloud_ca_file`'s rules. The exe tests check `outbox list` on an empty root and the usage lines exactly.

10. **The Done-when, live, from the vault.** A stub Cloud, `docs/api/veeam-lab/w4.6-harness/stub-cloud.py` (Python's `http.server` over TLS with a certificate made for the run: 202 after reading the whole body, `--slow` sleeping 20 s while reading so it can be killed mid-upload, printing each request's parts and sizes and never a body), and a copy of the lab's config with `cloud_url` and `cloud_ca_file` pointing at it. (a) `rpworker test --mail 10 --sp 10 --od 10 --run-id w46-done-when-1 --point <the 2026-10-03T16:16:54 point> --evidence %ProgramData%\RestoreProof\runs --outbox %ProgramData%\RestoreProof`: `status pass`, `queued ...`, the folder under `outbox\` with its manifest; (b) the stub stopped, `outbox flush`: kept, attempts 1, exit 3; (c) the stub `--slow`, the flush started, the stub killed mid-body: kept, attempts 2, the folder byte for byte as before but `manifest.json`; (d) the stub normal, flush: `sent`, moved to `sent\`, exit 0, the stub's log showing every part with the sizes `result.json` lists; (e) `rpworker signer verify` on the sent folder still `verified`. `graph list` 0 in all three targets. Evidence `docs/api/veeam-lab/w4.6-*`; the sent folder stays outside the repository.

**Reason.** A signed result is the product; the outbox's one job is not to lose or alter one. So the queue is a rename (whole or not at all), the only file ever rewritten is one the signature doesn't cover and the Cloud never sees, the upload re-reads and checks every byte it sends against what was signed, and nothing the Worker does on a failure touches the folder. What can be lost is only the Worker's own bookkeeping (an attempt count, a TSA code), and a lost manifest is made again rather than stranding the run. The caps delete only what the Cloud already has.

**Alternatives rejected.**
- *Copying the folder into the outbox:* a copy can stop half way and leaves two folders to tell apart; a rename can't.
- *The manifest written before the move:* a failed move would leave a `manifest.json` in the runs root, and the owner's order is the move first; the flush's "made again" covers the moment between.
- *`tsa_error` in a file of its own, or in the upload:* W4.4 point 2's reasons; the manifest is the Worker's record and the Cloud learns "not timestamped" from the missing part.
- *Asking the TSA again at flush:* above.
- *Pruning the queue at the cap, or refusing to queue over it:* either loses a signed result.
- *Counting an attempt for a changed folder, or deleting it:* nothing was tried, and the evidence of what changed is the folder.
- *A fifth code for a TLS failure:* the owner's four stand; a certificate the Cloud's client refuses is `upload_unreachable`, and the HTTP client's own log line names the cause.
- *Full signature verification before each upload:* needs the public key, so the vault; the hash checks catch every change short of forging both files, and the Cloud verifies.
- *`manifest.json` as a fourth name the verifiers never note:* a change to both verifiers and the shared vectors for a file that is never uploaded; `signer verify` on a sent folder says `note: not listed in the result: manifest.json` on stderr and `verified`, as W4.3 point 4 foresaw.
- *An `http://` `cloud_url` for the stub:* point 7.

**Closes, from earlier entries.** W4.3's Open points for W4.6: the folder's name is the run ID and the outbox holds `result.json`'s `run_id` to it; `tsa_error` is the manifest's `timestamp.code`; flush never asks the TSA again. W4.4's: the same two, and the upload's `timestamp` part (sent when there; C5.7 reads it). W4.4's review finding 4, the part left to W4.6: `result.json` stays last and after the TSA wait, and point 6 says what an unfinished folder is.

**Open.**
- W5.1: the API token (the vault's sixth name) and the `Authorization` header; the endpoint taking one bundle twice; what a 4xx that will never succeed (a 400, a 413) should do, since today every answer but 202 is retried hourly for good.
- W4.8: the flush loop and its interruptible wait, both roots passed to the run, what the service reports for a runs-root folder without `result.json`, and for a `folder_changed` run.
- W7.1: the ACL of `outbox\` and `sent\` (the service account `Modify`), as for `runs\`.
- C5.7: the parts' names are the contract; nothing but this entry fixes them yet.
- Two processes at once: a run that queues while a flush lists (the flush may make the manifest and the run then replace it; nothing signed is involved). The service is one process.

**Code, tests and docs with the build.** `rp/outbox.hpp`, `src/outbox.cpp`; `rp/outbox_command.hpp`, `src/outbox_command.cpp`; `rp/uploader.hpp`, `src/uploader.cpp`; `src/folder_ops.{hpp,cpp}`; `src/atomic_file.{hpp,cpp}` (`replace`); `rp/config.hpp`, `config.cpp`, `config_check.cpp` (`cloud_ca_file`); `run_pipeline.{hpp,cpp}`, `test_command.cpp`, `rp/restore_command.hpp` (`--outbox`, `outbox_files`); `rp/cli.hpp`, `cli.cpp`; `CMakeLists.txt`; `tools/coverage_gate.py`; `tests/outbox_test.cpp`, `tests/outbox_command_test.cpp`, `tests/uploader_test.cpp`, `tests/folder_ops_test.cpp`, `tests/atomic_file_test.cpp`, `tests/test_command_test.cpp` (`[outbox]`), `tests/config_test.cpp`, `tests/config_check_test.cpp`, the usage line's tests; `docs/verification.md` "The outbox", `docs/worker-config.md`, `docs/testing.md`, CLAUDE.md. The PR closes #49.

**W4.6 build notes: what the build and the live run settled beyond the entry (written after, 2026-10-07).** Nothing here reopens a point above.

1. **Built as written, with these particulars.** `rp::Outbox::queue(run folder, run ID, now, timestamped, code)`, `list()` and `flush(IUploader&, now)`; `flush` returns its lines whole (`FlushReport{readable, out, err, errors, queued, sent}`), so the command only prints them and decides the exit code. `rp::Outbox::queue_error` is the one text of every `outbox error` a run can end with. `IUploader::upload(run_id, parts)` answers `{accepted, error}`; an error that is none of the codes is `upload_internal` in the manifest. `rp::make_cloud_http_client(config)` (in the not-strict `uploader.cpp`) is the real client: the Windows store, or `cloud_ca_file` in its place. One clock reading per flush: every run of one pass has the same `last_attempt_at`. A flush counts under "queued" every run folder left under `outbox\` (kept, waiting, changed, uploaded and not yet moved), which is what exit 3 goes by.
2. **Where the build differs from the entry.**
   - *Point 2, the manifest made again:* it is written with the one replacing writer, not with the writer that never replaces. A damaged `manifest.json` must be replaced, and two writers for one file bought only the two-process case that the entry's Open list already leaves to the single service process.
   - *Point 3, the answer's status:* an HTTP status outside 100 to 999 from the client is `upload_internal`, so `last_error` is always one of the fixed words or `upload_http_` and three digits.
   - *Point 5, `outbox list`:* a `--outbox` path that isn't UTF-8 is `config error: the --outbox path is not valid UTF-8`, exit 1, as for the other path options.
   - *Point 8:* `src/folder_ops` also has `make_folder` and `path_kind`, used directly (a root that is a file, a folder in a file's place are real folders in the tests); only the four calls whose failure a test can't provoke on a real folder are seams (`OutboxFiles::move_folder`, `write_manifest`, `remove_folder`, `folder_bytes`).
3. **The multipart body isn't built by hand.** The task expected `HttpRequest` to lack one; W1.3's `parts` already sends multipart/form-data byte for byte (curl writes the boundary). The uploader uses it; a test sends parts with NUL bytes, `\r\n--` and 0xFF over a real local server and compares what arrived.
4. **`cloud_ca_file` with a self-signed certificate works as `veeam_ca_file` does:** the stub's certificate (`CN=localhost`, a `DNS:localhost` subject alternative name, made with Git's `openssl req -x509`) given as the CA file, the host name checked. Seen in the lab, not in a unit test: the unit tests reach no TLS server for the Cloud.
5. **What was seen failing first, and what wasn't.** `outbox.cpp`'s 33 test cases against a stub of the file that answers nothing: 31 failed (the two that passed expect "no manifest" and "an empty root"). The uploader's, the commands', the pipeline's and `cloud_ca_file`'s tests were written beside their code and then seen failing with the code taken out again in one build (the upload answering nothing, the two subcommands unreachable, the pipeline's queue step skipped, the key not read): 28 of 34 failed, the six that passed being the usage and default-path cases. Not seen failing: the folder-ops and replacing-writer tests, the exe tests, the docs. Three test mistakes of mine were found by the first green run (a fake's handler that kept its call count by value, a check that the result's text never says "manifest", an expected line missing a warning) and fixed in the tests, not the code. The first coverage run found one strict line no test ran (`queue_error`'s `case queued: break;`, which the compiler folded away); the function now returns early for `queued` and the `break` belongs to `not_complete`.
6. **The live Done-when, 2026-10-07, evidence `docs/api/veeam-lab/w4.6-1` to `-7`,** from the vault alone, the config a copy of the lab's with `cloud_url` `https://localhost:8443` and `cloud_ca_file` the stub's certificate.
   - **A run I didn't plan (`w4.6-1`).** The first `rpworker test ... --run-id w46-done-when-1 --evidence ... --outbox ...` ran while the coverage build was loading the machine: Veeam's explore POST timed out after 30 s, `status error backup_transient`, exit 3, nothing restored. It has a valid result, so it was signed, timestamped and queued like any run. It was left in the queue and went through every later step: the outbox had two runs, which showed "oldest first".
   - **(a) `w4.6-2`:** `--run-id w46-done-when-2` on the 2026-10-03T16:16:54.0154727Z restore point, the machine idle: 30 of 30 in four `Success` sessions, `status pass: 30 of 30 item(s) verified: manifest 15, fields 5, metadata 10`, `cleanup after ok`, exit 0, stderr empty, `signed 33436406... key 9dfab6ea...`, `timestamped 2026-10-07T12:14:38Z`, `evidence C:\ProgramData\RestoreProof\runs\w46-done-when-2: ...`, `queued C:\ProgramData\RestoreProof\outbox\w46-done-when-2`; the folder gone from `runs\`, six files under `outbox\`, the manifest with `attempts` 0 and `timestamp.state` `timestamped`; `outbox list` two rows.
   - **(b) `w4.6-3`:** nothing listening on 8443: `kept ...: upload_unreachable; attempt 1, next at ...` for both, `2 queued, 0 sent`, exit 3, in one second.
   - **(c) `w4.6-4`:** the stub with `--slow`, the flush once both were due. The older run went first and the stub answered it 202 after its 20 s (`sent w46-done-when-1`); the stub was killed 2 s after it had read 1024 of the pass run's 42,279 bytes: `kept w46-done-when-2: upload_unreachable; attempt 2, next at` two minutes on. The queued folder's five signed files have the sizes and SHA-256 they had when queued; only `manifest.json` differs. This flush's exit code wasn't captured (a mistake in my harness call lost the process handle); its last line is `1 queued, 1 sent`, and the next flush, 20 s later, printed `waiting w46-done-when-2: next at ...` and exited 3.
   - **(d) `w4.6-5`:** the stub up, the run due: `sent w46-done-when-2`, `0 queued, 2 sent`, exit 0; the stub's lines show `result` 21,971 bytes with the SHA-256 the run printed as `signed`, `signature` 322, `timestamp` 5,997, `items.csv` 5,739 and `veeam-session.log` 7,360 with the sizes and hashes `result.json` lists, `Authorization absent`; the folder under `sent\` byte for byte as queued but for the manifest, which has `attempts` 3 and `sent_at`.
   - **(e) `w4.6-6`:** `rpworker signer verify` with the public key from the vault and `--tsa-ca shared/tsa/tsa-ca.pem` on both sent folders: `verified <hash> key <id> timestamp <time>`, exit 0, with `note: not listed in the result: manifest.json` on stderr; `verify_bundle.py` printed the same line for the pass run. `graph list`: 0 in all three targets.
   - **Taken away (`w4.6-7`):** the stub, its certificate and key, the config copy, the exported public key (`%TEMP%\rp-w46`). `runs\` holds the earlier tasks' five folders, `outbox\` is empty, `sent\` holds `w46-done-when-1` and `w46-done-when-2`, outside the repository.
7. **The runs of 2026-10-07.** `ctest --preset dev`: 1699 of 1699 before the live run (ten live tests skipped, 80 exe tests, ten of them the outbox's), and exit 0 again on the final code after the `queue_error` change (the same 1699 tests; the summary line of that second run wasn't kept). The Worker's coverage run and gate, from the elevated shell: the first run failed the gate on the one line of note 5 (`outbox.cpp` 389 of 390); the second, on the final code: exit 0, 96.9% line (12,094 of 12,478), the strict files all 100%: `outbox.cpp` 390 of 390, `outbox_command.cpp` 124 of 124, `vault.cpp`, `vault_command.cpp`, `signer.cpp`, `signer_command.cpp`, `timestamper.cpp`, `cleaner.cpp`, `run_status.cpp` and the three `target_guard` files; not strict, `uploader.cpp` 45 of 46, `folder_ops.cpp` 39 of 52 (the `catch` blocks and the error returns of `std::filesystem` calls that didn't fail), `atomic_file.cpp` 104 of 110, `run_pipeline.cpp` 812 of 861. `python -m unittest discover -s worker/tools`: 22 passed. Cloud's and the lab's pytest weren't run: nothing under `cloud/`, `shared/` or `lab/` changed. No Worker CI run has started since 2026-10-03 (GitHub billing), so the gate on the two strict outbox files is shown by the local run only.
8. **Still open**, beyond the entry's list: the `manifest.json` note on every queued or sent folder in both verifiers (accepted above; if C5.7 or an auditor finds it noisy, it becomes a fourth name of the folder's own in both tools and the shared vectors); the stub's parts are the only reader of the upload so far, so the parts' names and content types are fixed by this entry and nothing else until C5.7; `outbox\` and `sent\` under `%ProgramData%\RestoreProof` inherit the folder's ACL, which still lets `Users` create files (W7.1); a queued folder whose attachment is larger than memory allows is read whole (a screenshot is at most 10 MiB today).

---

## 2026-10-07 — W4.5 (#48): the DPAPI vault. The five secrets live in `vault.bin`, machine-scope DPAPI under a protected ACL; the environment variables go (recorded before the build)

W4.5 (#48) moves the Worker's secrets out of the `RP_*` environment variables into a vault the Worker's service account reads. Done when: "No secret is read from the environment or config file anywhere in the code." This entry works from issue #48, its two comments, the Sprint Task Guide (W4.5, W4.6, W4.8, W4.9, W7.1, W7.2), the 2026-09-22 entry "Worker secrets in a Windows DPAPI vault", the 2026-09-29 entry "The Worker runs on the Veeam server", the W4.3 entry's point 3 (how the signing key is held and wiped) and the W4.12 entry's point 3 (what the vault holds, who reads it, the ACL recommendation), and the code. No code is written yet; the build notes below record what the build found.

**The issue's key list is the guide's old one.** It names `veeam_username`, `veeam_password`, `graph_client_secret`, `api_token` and `signing_private_key`. W2.1 replaced the client secret with a certificate (its PFX and the PFX's password), the Cloud API token is W5.1's and doesn't exist yet, and W4.12 settled that no restore PFX is ever stored. So the vault holds exactly the five secrets of `rp/secrets.hpp` today, the Veeam user name among them: `veeam_username`, `veeam_password`, `graph_cert_pfx_base64`, `graph_cert_password`, `signing_key_base64`. The names are the `Secrets` fields' names, so a message, `config check`'s line and `vault list`'s line all say the same word; `signing_key_base64` rather than the guide's `signing_private_key` because the name says what shape the value is (Base64 of the PKCS#8 DER, as `graph_cert_pfx_base64` does), and `redact()` masks both names already. W5.1 adds `api_token` as a sixth name when there is a Cloud to talk to.

**What the investigation found, since the points below rest on it:**

- **The reader has no profile.** The service account is a virtual account, `NT SERVICE\<service name>` (W4.12 point 2). Its DPAPI user master key would be made on first use under a profile the spike's service never got (`w4.12-10`); machine-scope DPAPI (`CRYPTPROTECT_LOCAL_MACHINE`) uses the machine's master key, which every process on the machine can use. So with machine scope the file's ACL is the whole of the access control, and DPAPI only keeps the bytes from being read on another machine.
- **`%ProgramData%\RestoreProof` lets ordinary users create files in it.** Its ACL is inherited from `%ProgramData%`: `Users: (CI)(WD,AD,WEA,WA)` and `CREATOR OWNER: (OI)(CI)(IO)(F)`. A non-administrator can't read or replace a file an administrator made there, but can create a file that isn't there yet and then owns it with full access. That is what the ownership rule in point 3 is for; the folder's own ACL is W7.1's (below).
- **A service SID is derived from the service's name** (`S-1-5-80-<SHA-1 of the upper-cased name>`), so entropy derived from it hides nothing from anyone who knows the name, and doctor (W7.2) and an administrator's `vault test` would have to derive the same SID to read the same file.
- **A vault written under a user's own DPAPI scope can't be read by another account** (`CryptUnprotectData` fails), which is the issue's "reading under a different user context fails". Under machine scope it can, by any account the ACL lets read the file: the manual test changes meaning (point 9).
- **The repository has** `read_whole_file` (`src/file_read.hpp`), the atomic writer (`src/atomic_file.hpp`, which never replaces a file), `rp::canonical_json`, `rp::secure_wipe`, the `load_secrets` seam on every command's `Env` (`std::function<Secrets()>`, set by 35 test sites), and `make_local_machine_cert_exporter`'s pattern for a Win32 call with its error code in the message. `load_secrets_from_env` is called by `config check`, `veeam list`, `graph list`, the pipeline (`restore` and `test`), `signer public-key` and six `[live]` tests. Any Worker path part named or prefixed `vault` is strict (`coverage_gate.py`): 100% line.

**Decision.**

1. **One file, `%ProgramData%\RestoreProof\vault.bin`, and `--vault <file>` on every command that reads a secret.** `rp::default_vault_path()` is `program_data_dir() / "RestoreProof" / "vault.bin"` (the known folder, never the variable, as for `config.json`). `config check`, `veeam list`, `graph list`, `restore`, `test`, `signer public-key` and the new `vault` commands take `--vault <file>` (a path, not a secret), the exe tests and the lab use it, and without it the default is read. The default path is looked up only when `--vault` isn't given and only once the arguments parsed, as `--config` is. `load_secrets_from_env` and the five `RP_*` names are removed from rpcore: no command, connector, client or test helper reads a secret from the environment, and `config.json` keeps refusing secret-looking keys, its message now naming `rpworker vault set <name>`.

2. **What is in the file.** `vault.bin` is the bytes `CryptProtectData` returned, nothing before or after them: no header of our own, since the blob carries a description (`szDataDescr`, `restoreproof.vault.v1`) that `CryptUnprotectData` gives back and the reader checks, and a file that isn't a DPAPI blob at all is refused by DPAPI itself. The plaintext is one JSON object in `canonical-json-v1` (`rp::canonical_json`): its keys a subset of the five names, each value a non-empty string of at most 64 KiB, a name that isn't set absent (never `null`, never `""`). The reader parses strictly and requires the bytes to be their own canonical form, as the verifiers do for `result.json`, so a duplicate key or a value that isn't UTF-8 (which no JSON string can hold) is "not a RestoreProof vault", never read differently by two parsers. The file is read whole under a limit of 1 MiB.
   - **Scope: `CRYPTPROTECT_LOCAL_MACHINE`,** with `CRYPTPROTECT_UI_FORBIDDEN` (a service has no desktop). The reader is a virtual account without a profile; machine scope needs none, and lets an administrator's `vault set` write what the service reads and `vault test` and doctor read what the service reads, which user scope under any one account can't.
   - **Entropy: a fixed application constant,** the bytes of `restoreproof.vault.v1`, not a SID. The issue's "optional entropy derived from the service SID" is weighed and not taken: the service SID is derivable from the service's name, so it adds no secret, and it would bind the file to one service name that W7.1 hasn't chosen and that doctor and an administrator's commands would each have to derive. The constant is a label, not a secret: it keeps another program's DPAPI blob from being taken for a vault and ours from being decrypted by a generic tool without naming it, and nothing more. The protection is the machine's master key (another machine can't decrypt the file) and the file's ACL (another account on this machine can't read it). The entry says so plainly so nobody reads the entropy as a second lock.

3. **The ACL, and who sets it.** W7.1's installer isn't built, so `rpworker vault set` makes what it needs:
   - **A new vault file gets a protected DACL** (no inheritance) of three entries: `SYSTEM: Full`, `BUILTIN\Administrators: Full`, `OWNER RIGHTS: Full` (SDDL `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)`). The owner is the creator (Administrators for an elevated administrator). `OWNER RIGHTS` names the file's owner, whoever that is: in the lab's temp vaults it is the developer's account, so the unit tests run unelevated; in production it is Administrators, already Full. `Users` get nothing, so a non-administrator can't read, replace or delete the file.
   - **`rpworker vault grant <account>` adds one `Read` entry** (`FILE_GENERIC_READ`, `(A;;FR;;;<SID>)`) for the account on the file's DACL, merged into any entry it has, and nothing else. W7.1 runs it for `NT SERVICE\<service name>` at install, as it grants the certificate key file's ACE (W4.12 point 4); W7.2's doctor can read whether the service has it. The account is looked up on this machine (`LookupAccountNameW`); one that isn't known is refused with its name through `table_cell`.
   - **`set` and `remove` keep the file's DACL.** They write whole or not at all (a temp file beside the vault made with the old file's DACL, `FlushFileBuffers`, `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`), so a grant survives a password rotation and a crash leaves the old vault.
   - **The ownership rule.** Both reading and writing refuse a vault file whose owner is neither `SYSTEM`, `BUILTIN\Administrators` nor the calling process's own user: `<file>: the vault file is owned by neither SYSTEM, Administrators nor this account`. This closes the finding above: a non-administrator who plants a `vault.bin` before the first `vault set` owns it, and without the rule the administrator's `set` would read it, keep its DACL (the planter with Full, `Users` reading) and the service would read it; with the rule the administrator's `set` and the service's read both refuse it, and the fix is to remove the file and set the secrets again. The rule is the same for every reader, so the developer's own temp vaults (owner: the developer) and the lab's (owner: Administrators, read by the developer after a grant) read as before.
   - **The folder.** `vault set` makes `<file>`'s folder when it isn't there (one `create_directories`, the inherited ACL), and never changes an existing folder's ACL: `runs\` under it is written by whoever runs the Worker, and the lab's folder is in use. The `Users` create rights on `%ProgramData%\RestoreProof` and the run folders' ACL (open since W4.2) are W7.1's, which knows the service's name: `Users: RX` on the folder, the service account `Modify` on `runs\`. Until then the ownership rule is what refuses a planted vault.

4. **The commands.** All under `rpworker vault`, each with `[--vault <file>]`:
   - **`vault set <name>`** reads the value from the console without echo (a prompt `value for <name> (not shown): ` on stderr, `ReadConsoleW` with echo off, the line's `\r\n` stripped), or, when stdin isn't a console, the first line of stdin as UTF-8 bytes (a trailing `\n` or `\r\n` stripped; nothing after the first line is read). Never from an argument: a value on a command line is in the shell's history, the process list and any transcript. Then it reads the vault (none: an empty one), puts the value under the name, writes, and prints `set <name> in <file>`. Refused before anything is written, exit 1, one line on stderr: `vault error: the value is empty`, `vault error: the value is longer than 65536 bytes`, `vault error: the value isn't valid Unicode` (a console line with a lone surrogate) / `isn't valid UTF-8` (a piped line), `vault error: the value couldn't be read`. The value is wiped from every buffer of the command when it ends.
   - **`vault remove <name>`** takes the name out and writes: `removed <name> from <file>`, or, when it wasn't there, `<name> was not in <file>; nothing changed`, exit 0 both.
   - **`vault list`** decrypts and prints the names that are in the vault, one per line, in the fixed order of the five, and nothing else: never a value or a length; an empty vault prints nothing, exit 0.
   - **`vault test`** decrypts as the calling account and prints `vault <file>: ok` and then the five names each with `mask_secret`'s word (`**** (set)` / `(not set)`), in `config check`'s layout. It is what doctor runs and what an operator runs after a grant.
   - **`vault grant <account>`** (point 3): `granted read on <file> to <account>`.
   - **Exit codes:** 0; 1 for every vault error (`vault error: <what>`) and every refused value; 64 with the usage line for no subcommand, a word too many, a missing name or account, `--vault` without a file or twice; and `usage error: the name must be one of veeam_username, veeam_password, graph_cert_pfx_base64, graph_cert_password, signing_key_base64`, exit 64, for a name that isn't one of the five (the word given is never echoed).
   - **What every command says for a vault it can't use,** `vault error: ` from the `vault` commands and `config error: ` from the others (a `VaultError` is a `ConfigError`, key `vault`, so `run_status` still calls such a stop `config`), each naming the file as given and never a value: `<file>: vault file not found`; `<file>: the vault file can't be read` (no access, a folder, over 1 MiB, a read that stops short); `<file>: the vault file is owned by neither SYSTEM, Administrators nor this account`; `<file>: the vault can't be decrypted on this machine by this account (error 0x<8 hex>)` (DPAPI's refusal: a file written on another machine, under a user's scope by another account, or damaged; DPAPI doesn't tell these apart and the Worker doesn't guess, the hex is `GetLastError`'s); `<file>: not a RestoreProof vault` (decrypts, but another description, or the plaintext isn't a canonical JSON object of non-empty strings under 64 KiB each); `<file>: the vault holds a name that isn't one of the five secrets` (a sixth name, or a misspelt one, from a build that knew other names; the name is never echoed); for writes `<file>: the vault's folder couldn't be made`, `<file>: the vault file couldn't be written` and `<file>: the vault couldn't be encrypted (error 0x…)`; for `grant` `<file>: the account <account> isn't known on this machine` and `<file>: read on the vault file couldn't be granted (error <n>)`. A value that isn't valid Unicode never reaches the file (`set` refuses it) and, were one written by another program, is "not a RestoreProof vault" by the canonical rule; the issue's "a value that isn't valid Unicode" has no message of its own in the reader.

5. **The switch: every command reads the vault once, into `Secrets`, and nothing after that changes.** Each command's `Env` keeps `load_secrets`, now `std::function<Secrets(const std::filesystem::path& vault)>`, with `rp::read_vault` as the default and a new `default_vault_path` beside `default_config_path`; the unit tests keep injecting `Secrets` through it and none touches DPAPI or a real vault file but the vault's own tests and the exe tests. `Secrets`, `secret_values`, `require_veeam_secrets` and `mask_secret` stay as they are. The vault is read where the variables were read: after the config (and, for `test`, after `--json`'s and `--evidence`'s checks), before the Veeam secrets are required, the Graph certificate opened, the signing key parsed, the schema checked, the manifest read, the run mutex taken and any Veeam call. The messages that named a variable name the vault's name: `veeam_username is not in the vault` (then `veeam_password`); `graph_cert_pfx_base64 is not in the vault`, `graph_cert_password is not in the vault, and the PFX in graph_cert_pfx_base64 needs a password`, `graph_cert_password does not open the PFX in graph_cert_pfx_base64`, `graph_cert_pfx_base64 is not valid Base64 (…)` and the certificate's other messages; `signing_key_base64 is not in the vault; --evidence signs the result`, `signing_key_base64 is not an Ed25519 private key (Base64 of PKCS#8 DER)`, and `signer public-key`'s `signing_key_base64 is not in the vault`. `config check` prints its settings, then `secrets (vault <file>; values are never shown):` and the five names masked; a vault it can't use is `config error: <file>: …` on stderr after the settings, exit 1, so a fresh installation's `config check` still shows its config and names what is missing. What is wiped: the file's bytes and DPAPI's plaintext buffer (`SecureZeroMemory` before `LocalFree`), the JSON text; what isn't: the parsed value's own copies, as before for the three secrets the run holds anyway (W4.3 point 3). `redact()` already masks every one of the five names; nothing is added.

6. **The live tests read the vault through one helper, as the Worker does,** `rp::test::live_secrets()` in `tests/live_secrets.hpp`: `read_vault` of `RP_LIVE_VAULT` (a path, a switch like `RP_LIVE`, not a secret) or the default file. No `[live]` test and no lab helper reads `RP_VEEAM_*`, `RP_GRAPH_CERT_*` or `RP_SIGNING_KEY_BASE64` any more. **The read-only live tests run unelevated after one grant to the developer's account:** `rpworker vault grant <DOMAIN\user>` once, from an elevated shell, which `docs/testing.md` says. Chosen over "the read-only ones now need an elevated shell too" because a grant is the mechanism the service itself uses, so the lab exercises it; because an elevated shell for a read-only test is more privilege than the test needs; and because the lab's developer already holds every one of these values (in Credential Manager and the PFX file), so the grant widens nothing. The two `[live][writes]` tests still need elevation for the certificate export, as before.

7. **The lab: `lab/entra/set-worker-env.ps1` becomes `lab/entra/fill-worker-vault.ps1`.** It reads the same two Credential Manager entries and the PFX file (and checks the password opens the PFX, as today), the Veeam account's password from the entry `RestoreProof Lab - rp-veeam (local Veeam REST)` (the one W4.12's harness read) with the user name `<COMPUTERNAME>\rp-veeam` (`-VeeamUser`), and feeds each value to `rpworker vault set <name>` on stdin, one process per value, `--vault` passed through when `-VaultPath` is given; the signing key is skipped with a notice when there is no entry, and an entry that isn't a key stops the script before anything is set, as today. No value is on a command line, in an environment variable or in a file; the script isn't dot-sourced (nothing stays in the session) and ends with `rpworker vault list`. It needs an elevated shell for the default file (the folder's ACL) and `-Worker <exe>` names the Worker (default `worker\build\dev\rpworker.exe`). Its tests (`lab/tests/test_fill_worker_vault.py`) check the script's text as today's do and run it under pwsh against a stub Worker that records what reached it and how. `python -m seeder new-signing-key`'s text and `lab/README.md` name the vault instead of the variable.

8. **Files, and what is strict.** `rp/vault.hpp` and `src/vault.cpp` (strict): the names' fields, `default_vault_path`, `read_vault`, `write_vault`, `grant_vault_read`, the ownership rule, the DACL, the DPAPI calls, every message. `rp/vault_command.hpp` and `src/vault_command.cpp` (strict): the five subcommands, their lines and exit codes, the value's checks. `src/console_input.{hpp,cpp}` (not strict, like `ed25519.cpp` under the Signer): `read_secret_line`, the console and the pipe, one `ReadConsoleW` or `ReadFile` each; the command takes it as a seam (`VaultCommandEnv::read_secret`), so the strict file is tested with a fake and the real reader through the exe tests' piped stdin (`run_exe_test.cmake` gains `STDIN <file>`). The Win32 failures no test can provoke (`WriteFile`, `FlushFileBuffers`, `CryptProtectData` on a valid buffer, `SetNamedSecurityInfoW` after a successful lookup) are each one expression on the line of their call, as the other strict files do; the entry says so rather than hiding it. The ownership refusal needs a file owned by another account, which only a process with `SeRestorePrivilege` can make: that test `SKIP`s unelevated, and the local coverage run is from an elevated shell.

9. **The Done-when, live, and the manual test.** (a) Fill the lab's vault with `fill-worker-vault.ps1` from an elevated shell; `vault list` shows the five names; `icacls` shows the three entries. (b) `rpworker test --mail 10 --sp 10 --od 10 --run-id w45-done-when-1 --point <id> --evidence %ProgramData%\RestoreProof\runs` as the current user from the vault alone (no `RP_*` variable set; a `config check` first shows the five names from the vault), `status pass`, exit 0, signed and timestamped, `graph list` 0 in all three targets after. (c) The W4.12 harness once more, the host serving no variable over its pipe, the temporary service `RpSpikeProbe` as `NT SERVICE\RpSpikeProbe` with the certificate key file's ACE and `rpworker vault grant "NT SERVICE\RpSpikeProbe"`: `rpworker restore --mail 1 --sp 0 --od 0`, `status pass`, exit 0, cleaned after; then the same without the grant: `config error: …: the vault file can't be read`, exit 1, before any Veeam call. (d) The issue's manual test, with its meaning under machine scope: a temporary local non-administrator, `rp-vault-probe`, runs `rpworker vault test` and `vault list` on the lab's file (`the vault file can't be read`, the ACL's refusal), then, with a `Read` entry granted for the test, reads it (`ok`: machine scope decrypts for any account the ACL admits, which is why the ACL is the lock), then `vault set` as that account (refused: `can't be written`, no access), and a vault the probe wrote in its own temp folder read by the administrator (the ownership rule's refusal). A copy of the blob on another machine isn't tried: the lab has one machine; what is recorded instead is DPAPI's refusal of a blob made under another entropy and of a damaged one, and the documented behaviour of `CRYPTPROTECT_LOCAL_MACHINE`. (e) Everything temporary taken away: the service, its ACEs on the key file and the vault, the probe account and its folder, the spike folder; the lab's `vault.bin` stays, with the five names in it and the developer's `Read` entry. Evidence `docs/api/veeam-lab/w4.5-*`, each file refused by the saver if it holds a known secret value, a JWT or a PFX/PEM-shaped run of Base64; no blob and no key.

**Reason.** The reader is a profile-less virtual account, so machine scope is the one scope it can use, and then the file's ACL is the access control: the design spends its effort there (the protected DACL, the ownership rule, `grant` as the one way to widen it, the DACL kept across writes) and not on entropy that hides nothing. The value never touches a command line, a variable or a file in the clear, in the lab too. One seam stays, so the pipeline, the connector and 35 test sites change nothing but a signature. The commands say one fixed thing for each way a vault can't be used, with the Win32 code where only that tells two failures apart, so doctor can print them as they are.

**Alternatives rejected.**
- *Entropy from the service SID:* above. *A random entropy kept in the registry or a second file:* a second secret to protect with the same ACL, which protects the first just as well.
- *User-scope DPAPI under the service account:* needs the service's profile loaded, which a virtual account doesn't get (`w4.12-10`), and an administrator could neither write nor test the file without running as the service.
- *Windows Credential Manager:* the 2026-09-22 entry's reasons stand, and a virtual account's credential store is as profile-bound as its DPAPI user key.
- *A header or magic of our own before the blob:* DPAPI's description does the same, and a header would be one more thing an auditor's tool must know.
- *`vault set <name> <value>`, or a `--value` option:* the value would be in the shell's history and the process list. *An environment variable read by `set`:* the thing this task removes.
- *`set` resetting the DACL to the default on every write:* a password rotation would silently take the service's read away. *`set` copying the old DACL without the ownership rule:* the planted-file hole above.
- *`config check` failing before it prints anything when the vault is missing:* on a fresh installation it would show nothing of the config.
- *Keeping `std::function<Secrets()>` and a second seam for the path:* two seams for one thing. *`run_cli` pre-scanning the arguments for `--vault`:* a second parser.
- *The read-only live tests under an elevated shell:* point 6. *A `--vault` under the developer's own folder for the live tests:* two vaults to keep in step, and the lab would never exercise `grant`.
- *A `vault.bin` whose plaintext is lines of `name=value`:* a second format beside canonical JSON, with its own escaping rules for a password with `=` or a newline.
- *Printing the account name in `vault test`'s first line:* `GetUserNameExW` with its own failure path in a strict file, for a line `whoami` gives.

**Open.**
- W7.1: the service's name, `vault grant` at install, the folder's ACL (`Users` without create rights) and `runs\`'s, and whether the installer makes the signing key into the vault directly (no `rpworker` command prints or makes a private key; the lab's `new-signing-key` still keeps it in Credential Manager and the fill script moves it).
- W7.2: `rpworker doctor` runs `vault test` as the service's account would, prints the DACL's entries and names the `vault grant` line that is missing.
- W5.1: `api_token` as the sixth name.
- A copy of the blob on another machine, not tried in the lab (point 9).
- The parsed values' copies in memory, as before (W4.3 point 3).
- W4.9's sentinel grep must know the names of the five secrets as words that may appear in messages, and that no `RP_*` secret variable exists any more.

**Code, tests and docs with the build.** `rp/secrets.hpp` (the five names, `load_secrets_from_env` removed) and `secrets.cpp`; `rp/vault.hpp`, `src/vault.cpp`; `rp/vault_command.hpp`, `src/vault_command.cpp`; `src/console_input.{hpp,cpp}`; the `Env` of `config check`, `veeam list`, `graph list`, the pipeline and `signer` (`--vault`, `default_vault_path`, `load_secrets(path)`); `rp/cli.hpp` (`kCliUsage`), `cli.cpp`; `client_assertion.hpp`'s `CertificateSecretNames`, `run_pipeline.cpp`'s `RunSigningKey`, `signer_command.cpp`, `config.cpp`'s secret-key message; `CMakeLists.txt` (sources, `rptests` linking crypt32, the exe tests on a vault of their own, `run_exe_test.cmake`'s `STDIN`); `tests/vault_test.cpp`, `tests/vault_command_test.cpp`, `tests/secrets_test.cpp`, `tests/config_check_test.cpp`, `tests/config_test.cpp`, `tests/cli_test.cpp`, `tests/veeam_command_test.cpp`, `tests/graph_command_test.cpp`, `tests/restore_command_test.cpp`, `tests/restore_command_lab.hpp`, `tests/test_command_test.cpp`, `tests/signer_command_test.cpp`, `tests/restore_replay_test.cpp`, `tests/live_secrets.hpp` and the six `[live]` tests; `lab/entra/fill-worker-vault.ps1`, `lab/tests/test_fill_worker_vault.py`, `lab/seeder/signing_key.py`; `docs/worker-config.md` ("Secrets", "`rpworker vault`", `--vault` on each command, the exit codes), `docs/testing.md` ("Live tests", "Restore by hand", "Test by hand"), `lab/README.md`, `docs/glossary.md`, CLAUDE.md (the status line, "Secrets"). The PR closes #48.

**W4.5 build notes: what the build and the live runs settled beyond the entry (written after, 2026-10-07).** Nothing here reopens a point above.

1. **Built as written, with these particulars.** `rp::VaultError` is a `ConfigError` keyed `vault`; `rp::secret_field(Secrets&, name)` is the one map from a name to its field, which the vault, `config check`, `vault list` and `vault test` share; `rp::not_in_vault(name)` is the one sentence. `grant` takes a SID string as well as a name (`S-1-5-80-...`), since the installer will know the service's SID before its name resolves; `""` is refused (LookupAccountName maps it to the machine). `SetEntriesInAcl` puts the new entry first and marks the DACL auto-inherited (`D:PAI(...)`), which changes nothing of what it grants; a later write copies the entries in the order it finds them. Windows marks an `OWNER RIGHTS` entry inherit-only when a file's owner changes (`(A;IO;FA;;;OW)`), so a planted file's new owner doesn't get it either. DPAPI's codes, measured: bytes too short to be a blob are `ERROR_INVALID_PARAMETER` (`0x57`), a blob that doesn't decrypt (another entropy, a changed byte, a 1 MiB file of `x`) is `ERROR_INVALID_DATA` (`0x0d`); the message carries whichever it was. The Windows PowerShell tool pipes a value as UTF-8 only in PowerShell 7, so `fill-worker-vault.ps1` refuses 5.1 and sets `$OutputEncoding` itself.
2. **The refusal of a vault whose security can't be asked for is reached by a test after all.** The entry's point 8 expected it couldn't be: a file whose DACL denies `READ_CONTROL` to Everyone and whose `OWNER RIGHTS` entry grants `FILE_READ_DATA` alone makes `GetNamedSecurityInfoW` fail for the elevated test process too, so `inspect`'s "can't be read" is a normal two-line `if`, not a folded one. Found on the way, by a test that passed in its own process and failed in the coverage run's one process: once `SeRestorePrivilege` (or `SeBackupPrivilege`) is enabled in the process token, Windows reads any file's security for it whatever the DACL says, and the ownership tests had enabled it for `SetNamedSecurityInfoW` and left it on. The tests now enable it for that one call and turn it off again, and the refusal test turns both off first; `vault.cpp` itself never touches a privilege, so a Worker process has neither enabled. What stays folded on one line: `CryptProtectData`'s failure, `WriteFile`/`FlushFileBuffers`'s, `ConvertStringSecurityDescriptorToSecurityDescriptorW`'s, `SetEntriesInAclW`/`SetNamedSecurityInfoW`'s after a successful lookup, the token-user reads, and a `std::filesystem::status` that fails with anything but "not found" (a folder that denies everything to Everyone doesn't stop a lookup by path: traverse checking is a privilege every token has enabled, so the test that tried it was dropped). The command's `catch` no longer returns from inside the handler, for the same reason as `signer_command.cpp` (W4.4 build notes point 13). The ownership-rule test needs `SeRestorePrivilege` and `SKIP`s unelevated, as said.
3. **What was seen failing first.** The vault's tests against the header alone (no `vault.cpp`), the command's against the declarations, every exe test against the old usage line, `config_check_test` against the old output, the 35 seam sites against the new signature (compile errors), the lab script's tests against a script that wasn't there. Found by the tests, not by design: a move-only `Local` holder (the first `Local` was copyable and freed a descriptor twice: `STATUS_HEAP_CORRUPTION` in `vault grant`), the `0x57`/`0x0d` split, the `""` account, and, once the privilege of point 2 was put back, that a vault owned by SYSTEM or Administrators couldn't be written over by an administrator: the temp file was made with the old file's whole descriptor, owner included, which only a restore privilege lets a process assign (`ERROR_INVALID_OWNER`, "couldn't be written"). The writer now carries over the old file's DACL alone (protected) and the temp file gets its creator's owner, so an installer's vault (owner SYSTEM) can be rotated by an administrator; the test "a vault owned by SYSTEM or Administrators is read" writes and grants on such a file.
4. **The runs of 2026-10-07.** `ctest --preset dev`: 1607 of 1607 (ten live tests skipped, 70 exe tests, the four exe vaults filled by `vault set` from stdin). `rptests.exe` alone, every case in one process as the coverage run has it: 1528 passed, 10 skipped, 90,044 assertions. The lab's pytest: 980 passed, 1 skipped (`test_fill_worker_vault.py`'s 26 among them, 16 of them end to end under pwsh against a stub Worker). Cloud's pytest wasn't run: nothing under `cloud/` or `shared/` changed. The Worker's coverage run and gate (from the elevated shell, so the ownership tests ran): exit 0, 96.9% line (11,400 of 11,768), the strict files all 100%: `vault.cpp` 218 of 218, `vault_command.cpp` 151 of 151, `cleaner.cpp` 202 of 202, `run_status.cpp`, `signer.cpp`, `signer_command.cpp`, `timestamper.cpp` and the three `target_guard` files; not strict, `console_input.cpp`'s console path unrun, as said. No Worker CI run has started since 2026-10-03 (GitHub billing).
5. **The live Done-when, 2026-10-07, evidence `docs/api/veeam-lab/w4.5-*`.** (a) `fill-worker-vault.ps1` from an elevated shell: five `set <name> in C:\ProgramData\RestoreProof\vault.bin` lines, `vault list` the five names, `vault test` `ok`, the file 4272 bytes, owner `BUILTIN\Administrators`, ACL `SYSTEM:(F)`, `BUILTIN\Administrators:(F)`, `OWNER RIGHTS:(F)` and nothing else, `config check` printing the five from the vault, no `RP_*` variable in the shell. (b) `rpworker test --mail 10 --sp 10 --od 10 --run-id w45-done-when-1 --point <the 2026-10-03T16:16:54 point> --evidence %ProgramData%\RestoreProof\runs` as the current user, the vault the only source: 30 of 30 in four `Success` sessions, `status pass: 30 of 30 item(s) verified: manifest 15, fields 5, metadata 10`, `cleanup after ok`, exit 0, stderr empty, `signed e1868c59… key 9dfab6ea…` (the lab's key of W4.3), `timestamped 2026-10-07T01:01:31Z`, `rpworker signer verify` with the PEM `signer public-key` printed from the vault and `--tsa-ca` `verified … timestamp 2026-10-07T01:01:31Z`, `graph list` 0 in all three targets; the folder stays outside the repository. (c) The W4.12 harness once more, the host serving 0 variables over its pipe: `rpworker vault grant "NT SERVICE\RpSpikeProbe"` and the key file's ACE, then `rpworker restore --mail 1 --sp 0 --od 0 --run-id w45-service-1` as the virtual account: RP-CANARY-0001 restored in 29 s, `check: 1 match`, `status pass`, `cleanup after ok: deleted 1 mail`, exit 0, stderr empty; the vault's entry taken away again (`icacls /remove`) and the same command: `config error: C:\ProgramData\RestoreProof\vault.bin: the vault file can't be read`, exit 1, in 3 s, before any Veeam call. (d) The issue's manual test under machine scope, a temporary local non-administrator `rp-vault-probe` (random password, never shown): `vault test` and `vault list` on the lab's file `the vault file can't be read` (the ACL's refusal); after `rpworker vault grant` for it, `vault test` `ok` with the five names (machine-scope DPAPI decrypts for any account the ACL admits: the ACL is the lock); `vault set veeam_username` with Read alone `the vault file couldn't be written` (the temp file is made, the move over the vault refused, the temp taken away; the vault unchanged) ; a vault the probe wrote under `C:\Users\Public` (owner the probe) read and written by the administrator: `owned by neither SYSTEM, Administrators nor this account`, both. A copy of the blob on another machine wasn't tried: the lab has one machine. (e) The developer's own account was granted `Read` too and the read-only `[live]` tests (8 cases, 392 assertions) passed from the vault with only `RP_LIVE` and `RP_LIVE_VEEAM_CA_FILE` set; but on the lab machine UAC's Admin Approval Mode is off (`EnableLUA=0`), so every process of that account is a full administrator and no unelevated read could be shown there (`w4.5-4`'s note): the grant is what a UAC-on machine or a non-administrator developer needs, and the probe of (d) is the same mechanism shown. (f) Taken away again: the service, its ACEs on the key file (back to `SYSTEM:(F)`, `Administrators:(RX)`) and on the vault, the spike folder, the probe account and its folder, the temp files of the runs. **The lab's `vault.bin` stays**, with `veeam_username`, `veeam_password`, `graph_cert_pfx_base64`, `graph_cert_password` and `signing_key_base64` in it and the developer's `Read` entry; the Credential Manager entries and the PFX file stay as the lab's source of truth, and `fill-worker-vault.ps1` fills the vault again from them at any time.
6. **Still open**, beyond the entry's own list: the `%ProgramData%\RestoreProof` folder still lets `Users` create files (W7.1); a `grant` has no counterpart (`icacls /remove` takes an entry away; W7.1 or W7.2 may want `vault revoke`); the run folders' ACL; no Worker CI run has started since 2026-10-03 (GitHub billing), so the gate on the two strict vault files is shown by the local coverage run only.

**W4.5 code review (PR #162), findings 1 to 3 (2026-10-07).** Ten findings (`/code-review high`, posted on the PR); the three security ones are fixed here, 4 to 10 are open on the PR.

1. **`vault grant` took SDDL's aliases for SIDs.** `sid_of` tried `ConvertStringSidToSidW` on every account, and that call also takes the two-letter aliases: `grant WD` gave Everyone Read, and `grant ED` would have granted Enterprise Domain Controllers instead of a user called ED. Now only a string starting `S-1-` takes the SID path; anything else is a name for `LookupAccountNameW`. Seen failing first: nine aliases granted.
2. **The owner rule and the read were two opens by path.** `read_vault` asked for the owner by path and then read by path, so a file moved onto the path between the two (a valid vault, which machine-scope DPAPI with a fixed entropy lets any local account make) would have been decrypted without passing the rule; `grant` had the same shape. Now each of `read_vault`, `write_vault` and `grant_vault_read` opens the file once, with the access it needs (`GENERIC_READ`; `READ_CONTROL`, with `FILE_FLAG_BACKUP_SEMANTICS` so a folder in the vault's place still ends as "couldn't be written"; `READ_CONTROL | WRITE_DAC`), and the owner rule (`GetSecurityInfo`), the read (`ReadFile`) and the grant (`SetSecurityInfo`) work on that handle. Three tests swap the file at that moment through `rp::detail::set_vault_owner_checked_hook` (`src/vault_detail.hpp`, tests only); they were written with the fix and not run against the old code, which had no such moment to hook. What changed in the messages: a vault this account can't open is "can't be read" before the owner rule is asked (it was the owner's message when the security alone could be read); a device (`NUL`) is never a vault; a `grant` on a folder is refused; a `grant` whose file gives no `WRITE_DAC` is opened without it, so the owner rule still speaks first, and then says "couldn't be granted (error 5)", now reached by a test and no longer a folded line. `ReOpenFile` on a `READ_CONTROL` handle was tried first and refused `WRITE_DAC` with error 5 on a file that grants it, so it isn't used. Not closed by this: the folder `%ProgramData%\RestoreProof` still lets `Users` create files until W7.1, so a local user can still plant a vault before the first `vault set` (refused by the owner rule) or delete one.
3. **Copies of the secrets left unwiped.** The console line was copied into the command's value and went unwiped; `set`'s value went unwiped when the vault couldn't be read or written; the parsed `nlohmann::json` in `parse_vault` and `write_vault` held every secret and was freed as it was; a value `set` replaces was assigned over. Each is now wiped by a holder on every way out, values go on as copies of a string that is then wiped (never moved out of one), and `parse_vault` checks the whole document before it copies a value. No test observes a wipe (as for the Signer's, W4.3). Left: the JSON parser's own working buffer is nlohmann's and can't be reached.

---

## 2026-10-07 — W4.12 (#135): the restore credential under a service account. Confirmed: the Worker exports Veeam's certificate in memory from a service; the account is a virtual account with one Read ACE on the key file (proposed)

**Status: proposed.** Spike W4.12 ran on 2026-10-06/07 (evidence `docs/api/veeam-lab/w4.12-*`). It **confirms** the 2026-09-29 entry "The Worker runs on the Veeam server" and settles the point that entry left to the spike, the service account. W4.5 (#48) can go ahead.

**Decision.**

1. **Confirmed.** A process running as a Windows service account, with no elevated shell anywhere, reads `GET /v8/Organizations`, finds the organisation app's certificate in `Cert:\LocalMachine\My` by the thumbprint Veeam reports, checks the app ID, exports it in memory with `rp::make_local_machine_cert_exporter` and restores with it. No PFX and no key container was written by our process, in either of the two restores below. The 2026-09-29 entry stands as written, with point 2 added to it.
2. **The Worker's service account is a virtual account**, `NT SERVICE\<service name>` (the spike's was `NT SERVICE\RpSpikeProbe`; W7.1 names the real one), **not LocalSystem**. Beyond what every service has, it needs exactly one thing: a **Read ACE on the private key file** of Veeam's organisation app certificate. For the lab's certificate, a CAPI key (`Microsoft Enhanced RSA and AES Cryptographic Provider`), that is
   `icacls "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\76c3cba9ff326aabc15dd987a090ecaf_979c0e2f-70cd-4490-8214-782eeb81f138" /grant "NT SERVICE\<service name>:(R)"`.
   The file's name is the key's unique container name (`CspKeyContainerInfo.UniqueKeyContainerName`, or `CngKey.UniqueName` when the key is opened through CNG, as .NET does); a key of the Microsoft Software Key Storage Provider lives under `C:\ProgramData\Microsoft\Crypto\Keys\` instead, and the same ACE there let the account open such a key (the throwaway certificates of `w4.12-4`). The default ACL of a machine key file is `SYSTEM: Full`, `Administrators: RX` and nothing else, which is why until now only an elevated shell or LocalSystem could export. Nothing else was granted: the store itself is readable by everyone, and Veeam's REST API, Graph and the run mutex (`Global\...`) need no right the account doesn't have.
3. **What W4.5 holds.** No restore PFX, ever. The vault holds the Worker's own secrets only: the Veeam REST account's password, the Worker app's Graph PFX and its password, and the signing key (the five `RP_*` variables of `rp/secrets.hpp`, the user name among them). The vault's reader is the service account; the recommendation to W4.5 is machine-scope DPAPI (`CRYPTPROTECT_LOCAL_MACHINE`) with the vault file's ACL limited to the service account and Administrators, which needs no loaded profile (a virtual account's profile folder was not made by the spike's service: `w4.12-10`). W4.5 decides that.
4. **The cost of the virtual account, and who pays it.** When Veeam renews its organisation app certificate, the new key is a new file with the default ACL, and the next run's export fails: `restore error: veeam_m365: certificate <thumbprint> in LocalMachine\My: its private key can't be opened (error 0x80090016); run elevated or as LocalSystem, which a machine key needs; the restore was not sent`, status `error`, exit 4, nothing restored, the guard having passed and the explore sessions open (as `docs/worker-config.md` says of a missing right). With LocalSystem that cost does not exist, and the 2026-09-29 entry's "nothing to rotate on our side" was true without reservation only for LocalSystem. So: W7.1 (#80), the installer, creates the service as the virtual account and grants the ACE on the key file of every organisation's certificate, by the thumbprints `GET /v8/Organizations` reports; W7.2 (#81), `rpworker doctor`, doesn't only check that the certificate exists, is exportable and isn't near expiry: it runs the export in memory and discards it, and when it fails names the exact `icacls` line for the key file it resolved, so a renewal shows up as one red line with its fix. The exporter's hint "run elevated or as LocalSystem" is wrong for the service and is W7.2's to reword, test first (`src/cert_export.cpp`, untouched by this spike).

**What was seen.** The harness (`docs/api/veeam-lab/w4.12-harness/`, kept as text): a temporary service `RpSpikeProbe`, a hundred-line C# `ServiceBase` that runs one command line as its account and stops, created with `sc create ... obj= LocalSystem` and again with `obj= "NT SERVICE\RpSpikeProbe"`; the four secret variables (`RP_VEEAM_USERNAME`, `RP_VEEAM_PASSWORD`, `RP_GRAPH_CERT_PFX_BASE64`, `RP_GRAPH_CERT_PASSWORD`) read by the elevated shell from Credential Manager and the PFX file and handed to the service over a named pipe whose ACL named that one account (`GetImpersonationUserName` logged the client), so no secret touched disk, the registry or a command line; the hidden test `rptests "[spike_cert_export]"` (`worker/tests/cert_export_test.cpp`) as the one way to ask the Worker's own exporter about any thumbprint. In order:

- `w4.12-1`, **LocalSystem**: `GET /v8/Organizations` 200, both settings app `1fd2609d-…`, thumbprint `AC3220B5…F783A7`, equal; the certificate found, `CN=RestoreProof Lab Veeam`, valid to 2028-09-25; the key opened and made a 256-byte test signature; key file and ACL as in point 2; .NET's export 2631 bytes, re-imported ephemerally with its key; the Worker's exporter: `exported in memory: PFX 3508 Base64 characters, password 44 characters; nothing written`.
- `w4.12-2`, **the virtual account, default ACL**: everything up to the certificate alike (sign-in, the listing, the store), then `GetRSAPrivateKey`: "Keyset does not exist", and the Worker: `its private key can't be opened (error 0x80090016)` (`NTE_BAD_KEYSET`: CAPI reports a key the caller may not open as absent, not as denied). The token: `Everyone`, `BUILTIN\Users`, `NT AUTHORITY\SERVICE`, `Authenticated Users`, `NT SERVICE\ALL SERVICES`; not an administrator.
- `w4.12-3`, **the virtual account after the one ACE**: identical to LocalSystem's lines, the ACL now showing the third entry.
- `w4.12-4`, **the three refusals for `doctor`**, as the virtual account, the Worker's words: a thumbprint no certificate has, `certificate 0123…4567 in LocalMachine\My: not found`; a throwaway certificate made with `-KeyExportPolicy NonExportable` (its key file given the same ACE, so the refusal is the policy's), `its private key isn't exportable (error 0x8009000B)` (`NTE_BAD_KEY_STATE`; .NET: "Key not valid for use in specified state"); a throwaway certificate made with `-NotAfter` ten days ago, `expired at 2026-09-26T23:02:09Z`, refused before the key is touched (the exporter checks validity first; that key file had no ACE and .NET's export of it said "Keyset does not exist", the ACL's word). Veeam's own certificate was never changed, and both throwaway certificates went with their keys (`w4.12-10`).
- `w4.12-5` to `-7`, **one mail through `10-restore.ps1`** as the virtual account, the elevated shell holding the run mutex: RP-CANARY-0011 from bob's Inbox at the 2026-10-05T01:14:32Z point, the guard and its 12-mutation self-test passed, `certificate exported in memory (3508 Base64 chars); nothing written to disk`, POST 200, the duplicate check exactly that session, `Success`, `1 item processed (1 success)`, 22 s, exit 0; no file written under `C:\ProgramData\Microsoft\Crypto`, the spike folder or `C:\Windows\Temp`, no `.pfx`/`.p12` anywhere scanned; `rpworker graph list --hash` right after: the one mail, `text-v1` hash equal to the manifest's `body_sha256` (`dfef80f3…`); then the live cleanup test (it takes the mutex itself) emptied the targets and `graph list` read 0. The script now exports in memory (`X509Certificate2.Export`) and no temporary PFX exists any more; it needs a readable key, not elevation (checked up front, exit 64 with the account's name and the fix), and `VeeamLab.ps1` takes `RP_VEEAM_PASSWORD` when set.
- `w4.12-8` and `-9`, **the Done-when**: `rpworker restore --mail 1 --sp 0 --od 0 --run-id w412-done-when-1` as the virtual account, the Worker's whole pipeline: the run mutex taken by the process itself, `cleanup before ok`, RP-CANARY-0001 restored in 23 s in one `Success` session, `check: 1 match`, `status pass: 1 of 1 item(s) verified`, `cleanup after ok: deleted 1 mail`, exit 0, stderr empty; `graph list --hash` after: 0 in all three targets. During it two 1601-byte key files appeared in `C:\ProgramData\Microsoft\Crypto\SystemKeys`, owner `BUILTIN\Administrators`: that is LocalSystem's key store, which the virtual account can't write, and Veeam's REST service (LocalSystem) wrote six such files when it started on 2026-10-05T22:47:59Z; none appeared during the script's restore. So Veeam's own process persisted something while it ran our restore; whether it is the app's key from the PFX we sent, and whether Veeam removes it, is not established and is Veeam's behaviour, not ours. Noted for Q7.2/Q7.3 (#85/#86).
- `w4.12-10`, **taken away again**: the service deleted; the ACE purged from Veeam's key file (ACL back to `SYSTEM: Full`, `Administrators: RX`, verified); the two throwaway certificates removed with their keys, `LocalMachine\My` holding the five certificates it held before; no profile folder for the account was ever made; the spike folder under `%ProgramData%\RestoreProof` gone, that folder's own ACL untouched; no process of the spike left in session 0. Nothing of the spike stays on the machine.

**Reason.**

- **Least privilege, as the task set out.** The Worker parses what three remote services send it (Veeam, Graph, a TSA) and holds the Veeam admin password, the Graph certificate and the signing key. As LocalSystem a flaw in any of that owns the backup server; as a virtual account it owns one key file's read right and the Worker's own folders. Veeam's services run as LocalSystem, which is no reason for ours to.
- **The cost is one line, and a detectable one.** Point 4's renewal failure is a known message at a known step, with a fix the installer already knows how to apply.
- **Both candidates were tried, and both work;** the account was not chosen for working but for what it can't do.

**Alternatives rejected.**

- *LocalSystem:* works with nothing granted (`w4.12-1`) and survives a certificate renewal untouched; rejected for the reach it gives. Kept as the fallback if a customer's Veeam server can't take the ACE (a key stored where `icacls` doesn't reach, which the lab hasn't seen).
- *A vault copy of Veeam's organisation PFX* and *a dedicated restore app:* as in the 2026-09-29 entry; nothing in the spike spoke for either.
- *A scheduled task as the candidate account:* Task Scheduler runs a task as SYSTEM but not as a virtual account, so a service was made for both, which is also what the Worker will be.
- *Secrets to the service through its command line, the registry or a file:* a copy on disk or in a listing; the pipe left none.

**Open.**

- The `SystemKeys` observation above.
- The exporter's hint text (point 4), and `doctor`'s wording of the three refusals and the ACE, both W7.2's.
- A Veeam organisation certificate held in the Microsoft Software Key Storage Provider (`Crypto\Keys\`) hasn't been seen in the lab; the ACE's effect there was tried on the throwaway keys only.
- Changing the Worker's own `check_private_key` to report `0x80090016` as "no read access to the key file" rather than a missing key would need a denied key in a unit test; left with W7.2.

**Follow-ups, as comments on the issues:** W4.5 (#48) holds no restore PFX and reads the vault as the service account; W7.1 (#80) creates the service as a virtual account and grants the ACE; W7.2 (#81) tries the export and names the fix; Q7.2/Q7.3 (#85/#86) say the requirement: the Worker's service account needs read access to each organisation certificate's key file, granted by the installer.

---

## 2026-10-07 — W4.4 code review (PR #160), findings 4 to 6: the run mutex goes after the clean after, the run folder's list of secrets never grows, and a CA file is certificates only (proposed)

The review of PR #160 posted ten findings. These three are fixed here, test first; 1 to 3 (where the script's token check may differ from OpenSSL's) wait for a probe that confirms each, and 7 to 10 are open.

1. **Finding 4: the run mutex is released once the clean after is over, not when the command returns.** `finish` drops it right after `clean_after`, before the timings, the result and the run folder's files. With the TSA down, `rpworker test --evidence` waits about 90 s after its `cleanup after` line; it held `Global\RestoreProof-restore-targets` through that wait, so a second run was refused (`another RestoreProof run is using the restore targets`, exit 4) while the targets were idle. Nothing after the clean after touches a target. This amends W3.4 point 8 ("holds it until it exits") for a run that reaches `finish`; a run that ends before it still releases the mutex on its way out. A test reads the fake mutex at each delete of the clean after (held) and at each of the TSA's three requests (released).
   - **Not changed; the owner left it until W4.6 (2026-10-07):** the finding's two other parts. `result.json` is still written last, after the wait, so a process stopped during the wait leaves a signed `pass` run with only `items.csv` and `veeam-session.log`; writing it before the wait would end "`result.json` there means the timestamp attempt is over" (W4.4 point 3), which W4.6's outbox may go by. And the signing key stays in memory through the wait: the builder's list of secret values holds its text beside the Veeam and Graph secrets, which are there for the whole run anyway, and no test could observe a wipe.
2. **Finding 5: `secret_values(secrets, room)`.** The list reserved four places and said "no growth", but `write_evidence` added the key's text and its two shapes to it: past four, the vector moved, and a value short enough to live inside its string object (a password under 16 characters) stayed, unwiped, in the block it left. The caller now says how many values it adds and the list has that capacity from the start (`secret_values(secrets, 3)`). A test adds `room` values and holds the list's block and the first value's bytes to where they were. The finding's other half doesn't hold: `FixtureRecorder::secrets_` is a `std::deque`, which never moves its elements when one is added.
3. **Finding 6: a CA file is certificates only, in both verifiers.** `add_certificates` read through `PEM_read_bio_X509`, which skips a block of another label, so a `tsa_ca_file` or `--tsa-ca` file holding a certificate and a private key counted as one certificate. The script's `load_pem_x509_certificates` skips such a block too, and also a block that is cut off, which the Worker refused: the two tools differed there. One rule now, in `rfc3161.cpp` (the blocks read one by one with `PEM_read_bio`) and in the script's `_ca_certificates`: every PEM block is labelled `CERTIFICATE` and reads as exactly one certificate, and there is at least one; a block of another label (a key, a CRL, the old `X509 CERTIFICATE`), one with a header or one that is cut off makes the whole text no CA file (`certificates_in` 0, `verify_token` false; the config error, `signer error: ... no certificate in PEM`, the script's exit 2). Text outside the blocks stays a comment.

Runs of 2026-10-07: `ctest --preset dev` 1552 of 1552 (ten live tests skipped), Cloud's pytest 727. The coverage run was not repeated.

## 2026-10-06 — W4.4 build notes: what the build settled beyond the approved entry (proposed)

The W4.4 entry below was approved as written and built in the stages it lists. This records what the build found and decided beyond it, what was and wasn't seen failing, and the runs. Nothing here reopens a point of the entry.

1. **A token's bytes are the TSA's own, never a re-encoding.** The entry said the primitive would "compare its re-encoding for bytes after it". That would have refused DigiCert's tokens: OpenSSL sorts a SET OF when it writes one, and DigiCert's certificate set isn't in DER's order (the same fact that makes `rfc3161-client` refuse them). `rp::Rfc3161` asks instead that the library's reader ends at the text's last byte, and `parse_response` hands back the token as the response's own trailing bytes (the response is a SEQUENCE of the status and the token). A test holds the token to `response.ends_with(token)`, and the Timestamper's request is byte for byte what `openssl ts -query -cert` sent for the same digest and nonce.
2. **A tenth code, `timestamp_internal`.** The entry listed nine. A request that can't be built, no nonce, a primitive or an HTTP client that fails in a way that is neither's answer, and a timestamper that throws or answers nothing in the run folder's seam are none of the nine and are not the TSA's doing. Calling them `tsa_unreachable` would have blamed the TSA.
3. **The Timestamper has no sleep of its own.** `TimestamperOptions::sleep` is the caller's (the pipeline passes `connector_options.sleep`, else `std::this_thread::sleep_for`); null means the attempts follow at once. A default inside the strict file would have been a line no test runs without really waiting, and W4.8 needs to hand in an interruptible wait anyway. A wait that throws is that attempt's failure (`timestamp_internal`), and the next attempt is still made.
4. **`tsa_ca_file` is read, and must hold a certificate, before anything is done.** `load_config` checks that it opens, as for `veeam_ca_file`; `rpworker test --evidence` also reads it (at most 64 KiB) and asks the primitive for its certificates right after the signing key is parsed: `config error: config key "tsa_ca_file" names a file that can't be read` / `... names a file that holds no certificate (PEM)`, exit 1, no run line. No other command reads the file. `tsa_ca_file` without `tsa_url` is allowed and replaces the root for the default TSA; `config check` prints both keys.
5. **A certificate of the CA file ends the chain wherever it is met**, in both verifiers (OpenSSL's `X509_V_FLAG_PARTIAL_CHAIN`; the script's walk stops at a certificate byte-equal to one of the file's). So `--tsa-ca` may hold the TSA's own certificate or an intermediate, not only a root. Without it the two would have differed on such a file.
6. **Three alignments of the script with OpenSSL, found by measurement.** Both verifiers were run over one token with one bit of each of its 898 bytes flipped in turn. At first 163 changes got different answers, 16 of them a `verified` on one side only. The script now (a) reads the whole token up front, certificates included, so bytes that are no token are `timestamp_file` and not `timestamp_invalid` further on; (b) requires the signer's digest algorithm among the SignedData's own list, an unsigned field OpenSSL needs; (c) chooses RSA PKCS #1 v1.5 or ECDSA by the signer's key and digest algorithm and doesn't read the signer info's signature algorithm, which is unsigned and which OpenSSL doesn't read either. After that both verify the changed token at exactly the same 12 offsets (two version numbers, two algorithms' NULL parameters, the eight content bytes of that unread OID), none covered by a signature. `cases.json`'s `one_bit_changes` holds that list and both builds must find it.
7. **What still differs, measured.** On 17 of those 898 changes both say "not verified" with different words: the script's readers (`asn1crypto`, `cryptography`) refuse a few bytes of a certificate or of the certificates' tag as no token (`timestamp_file`) where OpenSSL reads them and fails to verify (`timestamp_invalid`), and twice the other way round. This is not held equal by a test; `docs/verification.md` says so. The point-5 risk of the entry stands as written: the script's chain walk is simpler than OpenSSL's.
8. **No vector for a signer without the timestamping key usage, or with a wrong ESSCertID.** OpenSSL's own responder refuses to sign with such a certificate, and the test-only TSA is that responder. The script's rule (`_is_timestamp_signer`: critical, `timeStamping` alone, and a key usage with digitalSignature or nonRepudiation when there is one) has eight cases of its own on certificates made with `cryptography`; the Worker's is OpenSSL's `X509_PURPOSE_TIMESTAMP_SIGN`, not tested by us.
9. **Library failures on a token's bytes are a word in the script, not exit 2.** `cryptography` raised `InvalidVersion` (not a `ValueError`) on a changed certificate. `_parse_token` and `_token_verifies` catch everything a library makes of the token's bytes: no token, or not verified. The rest of the script still ends anything unexpected with exit 2.
10. **The recorder's Base64 mode.** `RecordedBody::base64`: `"body": null`, `"body_base64"` and `"request_body_base64"`. The file without the two fields is held to every rule as always; the two bodies are checked against the known secrets as the bytes they are and skip `redact()` and the JWT-shape rule. A test builds bytes whose Base64 is JWT-shaped and shows the same characters refused as text and taken as a binary body.
11. **The test Harness has a TSA.** Every `test --evidence` run in the unit tests is timestamped by the test-only TSA behind `http://tsa.test/stamp`, its root in a `tsa-ca.pem` beside the config; none asks DigiCert, and the embedded root is never the tests' trust. `signing-v1`'s expected `verified` lines gained ` timestamp none` and a `note: not timestamped` on stderr.
12. **A slip in the tests, found by a stray folder.** Three new tests pushed a temporary string into the argument list, which holds views; one run wrote a run folder under `worker/` and it was committed for a moment (the commit was amended before any push). The tests now keep the text alive (`EvidenceRun`).
13. **What was seen failing, and what was not.** Seen failing before the code: the primitive's tests against a stub that answers nothing; the Timestamper's table against a stub; the recorder's Base64 tests against the enum value alone; the config tests against the two fields alone; the run folder's tests against a `write_result` that ignored the seam; the Signer's and the command's timestamp tests against the declarations alone; the script's 79 tests against the unchanged script. Seen failing only by taking the code out again, since the wiring was written first: the pipeline's nine tests, with `tsa = tsa_settings(config)` commented out (eight failed; the ninth is "only --evidence asks the TSA"). Not seen failing: the replay of the live recording (added after it passed by hand), the clock-skew rows that expect no line, the docs. One strict line had no test: the closing brace of a `catch` that returned, which the first coverage run showed; the handler no longer returns.
14. **The runs of 2026-10-06.** `ctest --preset dev`: 1549 of 1549 (ten live tests skipped). The Worker's coverage run and gate: exit 0, 97.1% line (10937 of 11259), the strict files all 100%: `timestamper.cpp` 84 of 84, `signer.cpp` 364 of 364, `signer_command.cpp` 140 of 140, `cleaner.cpp`, `run_status.cpp`, the three `target_guard` files; not strict, `rfc3161.cpp` 134 of 157 (the unreached lines are the library's failure returns and the `catch` blocks), `ed25519.cpp` 62 of 81, `evidence_builder.cpp` 274 of 294, `run_pipeline.cpp` 794 of 841. Cloud's pytest: 718 passed (76 new, `tests/test_verify_bundle_timestamp.py`). The lab's wasn't run again: nothing under `lab/` changed since the review branch below (982 passed). CI has still not run.
15. **The live Done-when, 2026-10-06.** Run `w44-done-when-1` on the 2026-10-03T16:16:54.0154727Z restore point, with `--record`: 30 of 30, `status pass`, exit 0, stderr empty, `signed 4a7e8cff... key 9dfab6ea...`, `timestamped 2026-10-06T21:19:24Z`, the folder holding `result.json`, `signature.json`, `timestamp.tst` (5998 bytes, DigiCert, policy 2.16.840.1.114412.7.1), `items.csv` and `veeam-session.log`; `graph list` 0 in all three targets. With Git's OpenSSL 3.5.5 and nothing of ours: `openssl ts -verify -digest <bundle_sha256> -in timestamp.tst -token_in -CAfile shared/tsa/tsa-ca.pem` and the same with `-data result.json` both `Verification: OK`, a wrong digest `FAILED`. `rpworker signer verify` and `verify_bundle.py`, with `--tsa-ca`, print the same line, `verified <hash> key <id> timestamp 2026-10-06T21:19:24Z`, the hash `Get-FileHash`'s; without it `timestamp unchecked`; and the same line for four changed copies: a DigiCert token over another hash (`timestamp_mismatch`), one bit of the signature changed (`timestamp_invalid`), the token removed (`verified ... timestamp none`), the test root given (`timestamp_invalid`). The recording's `tsa/001-post-root.json` is now the fixture `digicert-w44-live.json`, replayed by a test. A second run, `w44-tsa-down-1`, with `tsa_url` at a closed local port: the same `status pass` and exit 0, one line on stderr, `timestamp warning: ...: not timestamped: tsa_unreachable after 3 attempt(s)`, a complete folder without `timestamp.tst`, both verifiers `timestamp none`, and the process ending about 90 s after the timings' total (the waits of 30 s and 60 s). No clock warning in either run. Evidence `docs/api/veeam-lab/w4.4-live-*`; both folders and the recording stay outside the repository.
16. **Still open**, beyond the entry's own list: whether the 17 differing words of point 7 should be closed (it would mean a stricter or a looser reader on one side); `timestamp.tst` is not looked through for the run's secret values (a TSA is sent a hash and a nonce and can echo nothing else); the branch sits on `w4.3-review-open` (PR #159), whose commits it carries until that is merged.

## 2026-10-06 — W4.4: the timestamp is the bare RFC 3161 token in `timestamp.tst`, over the result's own hash, from a TSA trusted through one pinned root; a missing token is "not timestamped", never a status (recorded before the build; the owner approved it as written)

W4.4 (#47) timestamps the signed result. Done when: "Openssl ts -verify on the extracted token succeeds against the bundle hash." This entry works from issue #47, the Sprint Task Guide (W4.4, and W4.5 to W4.9, W7.2, C5.1, C5.7, C6.4, Q6.1 where they name the timestamp), the W4.3 entry's point 2 and its build notes, and the code. No code is written yet. One sub-agent investigated and measured; what it measured is marked as measured, and what nobody measured is listed at the end.

Fixed before this entry and not reopened: the timestamp is over `bundle_sha256` and comes after the signature; it is a file of its own beside `result.json`, never a key of `result.json` or of `signature.json` (five keys); nothing signed is rewritten or re-signed; TLS verification is never turned off; the TSA is built against recorded fixtures first, live calls behind `RP_LIVE=1`.

What the investigation found, since the points below rest on it:

- **The guide's steps 3 and 4 can't be built as written.** "Store the token base64 in `tsa_token`" and "set `tsa_token: null` and `tsa_error`" name keys of a document that is signed before the TSA is asked (W4.3 point 2). "The extracted token" of the Done-when has nothing to be extracted from when the file is the token; it is read as "`openssl ts -verify` on the folder's token file succeeds for `bundle_sha256`". The guide's "retry 3 times over 2 minutes" and "the run still uploads, the dashboard shows not timestamped" stand.
- **Six public TSAs, measured on 2026-10-06** (one query each for an arbitrary SHA-256 digest, certReq, an 8-byte nonce, Git's OpenSSL 3.5.5 and curl). All answered 200 `application/timestamp-reply`, status granted, the nonce echoed, a SHA-256 imprint, a signer whose extended key usage is critical `timeStamping`:

  | TSA | token bytes | time | policy OID | accuracy | certificates in the token | signer, notAfter | ESSCertID | `openssl ts -verify` |
  |---|---|---|---|---|---|---|---|---|
  | DigiCert `http://timestamp.digicert.com` | 5998 | 0.44 to 0.53 s | 2.16.840.1.114412.7.1 | none | 3, to Trusted Root G4 | RSA-4096, 2037-11-04 | v1 and v2 | OK with the G4 root alone |
  | Sectigo `http://timestamp.sectigo.com` | 6627 | 0.19 to 1.35 s | 1.3.6.1.4.1.6449.2.1.1 | none | 3, to USERTrust | RSA-4096, 2037-06-24 | v1 | OK with USERTrust alone |
  | FreeTSA `https://freetsa.org/tsr` | 4634 | 0.93 to 1.38 s | 1.2.3.4.1 | none | 2, its own root | EC P-384, 2040-02-02 | v1 | fails with a public CA bundle; OK only with FreeTSA's own `cacert.pem` |
  | GlobalSign `r6advanced1` | 7652 | 0.62 s | 1.3.6.1.4.1.4146.2.3.2.2 | 1 s | 4 | RSA-3072, 2037-01-10 | v2 | OK |
  | Certum `http://time.certum.pl` | 6156 | 0.26 s | 1.2.616.1.113527.2.5.1.11 | 1 s | 3 | RSA-4096, 2036-02-27 | v1 and v2 | OK |
  | SSL.com `http://ts.ssl.com` | 3853 | 0.43 s | 1.3.6.1.4.1.38064.1.3.6.1 | 1 s | 2 | EC P-256, 2034-11-12 | v2 | OK |

- **More from the probes (measured).** DigiCert has no HTTPS endpoint reachable from the lab: port 443 didn't connect in 18 s. A response is the token behind a 9-byte status wrapper for five of the six (SSL.com adds a status text). `openssl ts -verify` on a bare token needs `-token_in`; without it every bare token is `Verification: FAILED`. It works with `-digest <hex>` and equally with `-data result.json`. A wrong digest fails; a token checked against another TSA's root fails. With `-attime` in 2040 the answer is "certificate has expired", with `-attime` at the token's own time it is OK: plain `openssl ts -verify` validates at "now". The lab machine's clock is about 80 s ahead of every TSA (nine queries, three TSAs agreeing), so a token's time can be earlier than the result's own `ended_at`.
- **OpenSSL at the pinned baseline (3.6.4) has the TS API.** `openssl/ts.h` is in the vcpkg tree, `OPENSSL_NO_TS` and `OPENSSL_NO_CMS` aren't set, and `libcrypto` exports `TS_REQ_*`, `d2i_TS_RESP`, `TS_RESP_verify_token`, `TS_VERIFY_CTX_set0_imprint` / `set0_store`, `TS_TST_INFO_get_time`, `X509_VERIFY_PARAM_set_time` and `TS_RESP_CTX_set_time_cb` (measured: headers and exports; no program was compiled against them). vcpkg builds no `openssl.exe`; the only one on the machine is Git's.
- **A throwaway test TSA works (measured).** `openssl req`, `x509` and `ts -reply` made a P-256 root, a TSA certificate and a 1480-byte token that verifies, fails under a second root and fails at a time after its certificates. The command line can't set the token's time; `TS_RESP_CTX_set_time_cb` in code can.
- **Python (measured under `uv run --with`, `cryptography` 50.0.2).** `rfc3161-client` 1.0.9 refused to parse five of seven tokens (DigiCert, Sectigo, GlobalSign, Certum and OpenSSL's own) with `InvalidSetOrdering` at the certificates: not usable. `cryptography`'s own path validator refuses every TSA chain ("Neither EKU nor anyEKU could be found") and FreeTSA's root. `asn1crypto` 1.5.1 with `cryptography` parsed all seven, and a 60-line check verified the imprint, the one signer, `messageDigest`, ESSCertID v1 and v2, the signature over the signed attributes (RSA PKCS#1 v1.5 and ECDSA) and the key usage, and refused a wrong digest, a flipped signature bit and a trailing byte; a 25-line chain walk to a caller-given root accepted all seven and refused the wrong root. `rfc3161ng`, which C5.1 and C5.7 name, was last released in 2020-10 and wasn't run.
- **The code as it is.** `HttpClient` already sends `http://` URLs, with the TLS options applying to `https` only; request and response bodies are `std::string`, so binary works; redirects are never followed. The recorder keeps a non-UTF-8 response body as size and hash only, which can't be replayed, and writes a request body only when it is JSON. `result.v1.json`'s attachment names are a fixed set, so a token couldn't be listed even by mistake.

What is decided:

1. **The file is `timestamp.tst`: the bare DER TimeStampToken, as the TSA made it, with no wrapper and no schema.** A CMS SignedData whose content is the TSTInfo, at most 64 KiB (measured tokens are 3.9 to 7.7 KB). Its message imprint is SHA-256 with, as the hashed message, the 32 raw bytes that `bundle_sha256` shows as hex: the SHA-256 of `result.json`'s bytes, the same 32 bytes Ed25519 signs. The timestamped datum is therefore `result.json` itself, and an auditor checks it with nothing of ours: `openssl ts -verify -data result.json -in timestamp.tst -token_in -CAfile <root>`, or `-digest <bundle_sha256>`. Hashing the digest again would be wrong, not just needless: `-digest <bundle_sha256>` would fail and the Done-when couldn't be met. Reason: the token is the signed object, and its time, policy, serial and the TSA's name are inside it under the TSA's signature. *Rejected:* `timestamp.json` with the token in Base64 beside `tsa_url` and `gen_time` (unsigned copies that can disagree with the token, a schema and canonical rules for no gain, and the auditor must decode first); the whole TimeStampResp as `.tsr` (the status wrapper is unsigned and differs per TSA, and CMS tools want the token; a response found in the file is `timestamp_file`); the extension `.tsr` for a token (OpenSSL's name for a response).

2. **A TSA failure changes neither the status nor the exit code. `tsa_error` is a line on stderr and a value handed on to the caller, not a file; a folder without `timestamp.tst` is "not timestamped", whatever the reason.** The line is `timestamp warning: <folder>: not timestamped: <code> after <n> attempt(s)`, "warning" because the exit code stays. The codes: `tsa_unreachable`, `tsa_http_status`, `tsa_rejected`, `tsa_response_malformed`, `tsa_nonce_mismatch`, `tsa_imprint_mismatch`, `tsa_untrusted`, `tsa_token_too_large`, `timestamp_not_written`. `write_result` returns the outcome, so W4.6 can put `tsa_error` into its outbox manifest and the upload. Reason: nothing in the folder besides `result.json` is signed, so a `timestamp-error.json` could be added or removed by whoever strips a token and can't tell "the TSA failed" from "stripped"; only the Worker's own record can (manifest, log, heartbeat), and that is diagnosis, not evidence. A token obtained later is acceptable: it is over `bundle_sha256` and rewrites nothing signed; it proves existence at its own, later time, which every verifier prints, and whether that time is inside a report's period is C6.4's question. *Rejected:* `timestamp-error.json` (a second unsigned format, a schema, a rule in both verifiers, and what becomes of it when a later token arrives); exit 0 becoming 1 (a TSA outage would fail every scheduled run); any key in the result (it is signed).

3. **Three names are the folder's own.** `result.json`, `signature.json` and `timestamp.tst` are never listed in `attachments` and never a `note: not listed in the result`. Every other unlisted name keeps today's note. The byte-for-byte listing rule holds: `TIMESTAMP.TST` is a note and no timestamp. *Rejected:* listing the token (it depends on the result's hash); a note for it (noise on every good folder).

4. **The TSA is DigiCert's, over plain HTTP, trusted through one pinned root that comes neither from the folder nor from the Windows store.**
   - **Why DigiCert:** the fastest and steadiest measured, a WebTrust-audited CA, the whole chain in the token, verifiable against one 2 KB root, the signer valid to 2037-11.
   - **Two config keys.** `tsa_url`, optional, default `http://timestamp.digicert.com`; a new rule takes `http://` or `https://` and otherwise holds the URL rule the other keys have (printable ASCII, no user, password, query or fragment). `tsa_ca_file`, optional, an absolute readable PEM like `veeam_ca_file`; its default is the root embedded at build time from a new `shared/tsa/tsa-ca.pem` (DigiCert Trusted Root G4, 1988 bytes, notAfter 2038-01-15; one file for the Worker, the Cloud and an auditor, as the guide's "bundled `tsa-ca.pem`"). A `tsa_url` that is set requires `tsa_ca_file`, as `veeam_cert_sha256` requires `veeam_ca_file`: another TSA never borrows DigiCert's root.
   - **Plain HTTP, said outright.** The TLS rule is untouched: an `https` `tsa_url` is verified like every other call, and with `http` there is no TLS to verify, so nothing is switched off and the source scan needs no exception. Integrity doesn't come from the transport: the token's signature, its chain to the pinned root, the nonce and the imprint are all checked before the file is written. The request holds a hash and a nonce and no secret. Someone on the path can only deny service, which is "not timestamped".
   - **The request:** version 1, a SHA-256 imprint, `certReq` true, a random 64-bit nonce (injectable for tests), no policy asked for.
   - **The answer's checks, in this order:** HTTP 200; at most 64 KiB; parses as a TimeStampResp; status granted (0) only, `grantedWithMods` refused; a token is there; the nonce is ours; the imprint is SHA-256 and ours; the token verifies under the pinned root by point 5's rule, the same function the verifiers use.
   - **Not pinned, not required:** the policy OID (it is in the token and a TSA may change it); an accuracy (three of six send none).
   - **The TSA's time against the Worker's clock is a warning, never a refusal:** `timestamp warning: the TSA's time and this machine's clock differ by <n> s` when they differ by more than 120 s (W7.2's threshold). The token is the better clock, the lab machine is 80 s off today, and no verifier compares the token's time with the result's own times.
   - **The signer:** its ESSCertID, v1 or v2, must match (TSAs send either or both); its extended key usage must be critical and `timeStamping`.
   - **The chain is valid at the token's own time; revocation isn't checked.** Long-term validation (the TSA certificate expiring in 2037, archive timestamps, CRLs) is out of scope and the docs say so; an auditor using plain `openssl ts -verify` after the certificate has expired adds `-attime`.
   - *Rejected:* FreeTSA (one person's service, a root in no store whose basicConstraints a strict validator refuses, the slowest); Sectigo as the default (as sound, slower and less steady here; the documented alternative); the Windows store as the anchor (hundreds of CAs, different per machine, so the Worker and an auditor could disagree); an anchor from the token's own certificates (anyone can mint a chain); requiring `https` (DigiCert has none); a switch that turns timestamping off (a second kind of complete folder).

5. **Both verifiers check the token: three new words after the attachments' words, and a third field on the stdout line.**

   | Word | When |
   |---|---|
   | `timestamp_file` | `timestamp.tst` is in the listing and can't be read, is over 64 KiB, or isn't exactly one DER TimeStampToken (bytes after it, a whole response, not one signer, no TSTInfo, a version other than 1) |
   | `timestamp_mismatch` | its imprint isn't SHA-256 or isn't `bundle_sha256` |
   | `timestamp_invalid` | everything cryptographic: the signature, `messageDigest`, ESSCertID, the key usage, or no chain to the caller's CA valid at the token's time |

   - **Sixteen words; the first thirteen and their order are unchanged,** and the three come after `attachment_hash`: the timestamp is evidence about a result already known good.
   - **One word for all that is cryptographic,** because OpenSSL's `TS_RESP_verify_token` reports signature and chain as one step; two words would have the two libraries draw the line in different places, W4.3's lesson with `result_not_canonical`.
   - **The stdout line, the contract between the two tools, becomes** `verified <bundle_sha256> key <key_id> timestamp <time | none | unchecked>`. `<time>` is the token's, UTC, `YYYY-MM-DDTHH:MM:SSZ`, fractions cut. `none`: no `timestamp.tst`; still `verified`, exit 0, and `note: not timestamped` on stderr. `unchecked`: a token is there and the caller gave no CA; `note: timestamp.tst was not checked: no --tsa-ca` on stderr. `not verified: <word>` and the exit codes are as today.
   - **`--tsa-ca <pem file>`, new on both tools:** optional, from the caller only, no default, never from the folder. A file that can't be read or holds no certificate is the tool's own error (exit 1 / 2), never a word.
   - **The Worker:** `Signer::verify_folder` (strict) asks a small injected primitive `rp::Rfc3161` (`rp/rfc3161.hpp`, `src/rfc3161.cpp`): parse the token and compare its re-encoding for bytes after it, hand back the imprint for our own comparison, then `TS_RESP_verify_token` over an `X509_STORE` holding the caller's CA alone, at the token's time.
   - **The script:** `asn1crypto>=1.5,<2` joins `cryptography` in its PEP 723 block, and the CMS checks and the chain walk are written in the script (the signer by issuer and serial among the token's certificates; each certificate valid at the token's time; `verify_directly_issued_by`; the issuer a CA; at most 8 deep; ending at a certificate byte-equal to one in `--tsa-ca`; RSA PKCS#1 v1.5 and ECDSA with SHA-256, 384 or 512).
   - **A risk the owner should see:** the script's chain walk is hand-written and simpler than OpenSSL's (no name constraints, path length, key usage or policy processing), so the two could differ on an exotic chain. The shared vectors hold them on the cases listed, and the anchor is always the caller's.
   - **The vectors, `shared/testdata/timestamp-v1/`:** `keys.json` (a throwaway test root, a TSA certificate with its key, and a second root, published and named "not a secret" as RFC 8032's keys are) and `cases.json` (the `signing-v1` folder plus a `timestamp.tst` in Base64, which CA is given, and the expected line or word). Written once by a hidden `rptests "[.write_shared_timestamp]"` through a test-only TSA with a fixed time and 100-year certificates. ECDSA makes a token different every time, so unlike `bundle.json` there is no byte-for-byte regeneration test: the files are verified, not compared. Since the chain is checked at the token's own time, neither the vectors nor a recorded DigiCert answer ever expire. `signing-v1`'s expected `verified` lines gain ` timestamp none`.
   - *Rejected for the script:* `rfc3161-client` (measured: refuses DigiCert's tokens at the parse); `rfc3161ng` (unmaintained since 2020, pulls `requests`, builds no chain); `cryptography`'s path validator (measured: refuses TSA chains); calling `openssl` (not on the lab's PATH, nor on an auditor's Windows); not checking in Python (C5.7 and Q6.1 need it).

6. **`write_result`'s order: sign, ask the TSA, then write `signature.json`, `timestamp.tst` when there is a token, and `result.json` last.** `result.json` there still means complete: signed, and the timestamp attempt over, with a token beside it or without one.
   - **The budget is the guide's:** three attempts in all, 10 s each, waits of 30 s and 60 s through the injected sleep, about two minutes at worst. The HTTP layer sends each once (`max_attempts` 1) and the Timestamper owns the loop; every kind of failure is tried again and the last one's code is reported.
   - **No timing span:** `timings` is inside the signed bytes and closed before the signing, so it can't hold the TSA call. The duration goes to the log. The result keeps its seventeen keys.
   - **A token that can't be written** is `timestamp_not_written`, a warning; `result.json` is still written. **If `result.json` can't be written,** `timestamp.tst` and `signature.json` are both taken away again.
   - **Known cost:** with the TSA down, every run holds the run mutex for up to two more minutes.
   - *Rejected:* the token after `result.json` (the file would no longer mean complete, and W4.6 could move a folder in the middle of the request); the token before the signature (fixed otherwise); longer or unbounded retries inside the run (the service's work, W4.6).

7. **The shape, the seams, the recording, the lines.**
   - **`rp::Timestamper`** (`rp/timestamper.hpp`, `src/timestamper.cpp`): builds the request through the primitive, runs the attempts over an `IHttpClient`, applies point 4's checks and answers a token with its time, or a code with the number of attempts. Never throws. **`rp::Rfc3161`** (`src/rfc3161.cpp`): the calls into OpenSSL only.
   - **Coverage, the owner's choice:** `timestamper` joins the strict names (it decides which token is written), its 100% reached through a fake primitive and `FakeHttpClient`. `src/rfc3161.cpp` stays outside like `ed25519.cpp`, for the same reason (the library's allocation and failure lines), though much more of it is reachable since malformed input can be tested. The token's checks in `signer.cpp` stay strict.
   - **Seams:** `EvidenceOptions::timestamp` (null means none is asked, for the builder's own tests only), `RestoreCommandEnv::make_tsa_http` and `timestamp_nonce`; the sleep and the clock the pipeline already has.
   - **Recording:** `--record` wraps the TSA client as a third service, `tsa`, with a new body mode: `"body_base64"` for the answer and `"request_body_base64"` for the query (a hash and a nonce, no secret), which `FakeHttpClient` decodes on replay. A replay test takes the nonce and the imprint from the recorded request, so a recorded DigiCert answer verifies for good. The recorder's JWT-shape scan must not run over the two Base64 fields (Base64 of DER can hold `eyJ...` by chance; an estimate, about 1% of 8 KB bodies, not measured); they are checked as decoded bytes against the known secrets instead. Fixtures under `worker/tests/fixtures/tsa/`.
   - **Lines of `rpworker test --evidence`:** after `signed <hash> key <id>` comes `timestamped <time>`, and the `evidence` line lists `timestamp.tst` after `signature.json` when it is there; otherwise point 2's warning on stderr. No exit code changes in any case. A `tsa_ca_file` that can't be read is a config error at load, like `veeam_ca_file`. `--json` is never timestamped, as it is never signed.
   - **Out of scope:** a command that adds a missing token later (`rpworker signer timestamp <folder>`). The Timestamper takes only `bundle_sha256`, so W4.6's flush or a later command can call it, and adding the file rewrites nothing.

**Where this differs from the guide and the issue.** No `tsa_token` or `tsa_error` key anywhere (W4.3 point 2): the token is `timestamp.tst`, the error a stderr line and a value for W4.6. C5.7's upload gains a `timestamp` part beside W4.3's `signature` part; its "a failed or missing token does not reject the run, it is flagged" stands. C5.1 and C5.7's `rfc3161ng` is replaced by `asn1crypto` if the Cloud uses the script's verifier, which C5.7 decides. W7.2's doctor check "DNS + TLS to the TSA" becomes a real query over HTTP.

**The build, in stages, test first, failures before the happy path.** (0) the test-only TSA (`tests/tsa_lab.hpp`), the hidden writer and the vectors, `shared/tsa/tsa-ca.pem`; (1) `Rfc3161`: not DER, cut short, a byte after, a response for a token, another hash, another root, a flipped bit, no key usage, a non-critical one, a certificate not valid at the token's time, no certificates, then the good ones; (2) `Timestamper`, one row per code: unreachable, 503, HTML with 200, an empty body, a rejection, `grantedWithMods`, a wrong nonce, another imprint, an untrusted TSA, too large, each with three attempts and both waits, then failure-then-success; (3) the recorder's Base64 mode and the fixtures; (4) the two config keys; (5) the folder: TSA down (complete folder, the warning, the same status and exit code as with a TSA), the token's write refused, `result.json` refused after the token, the TSA never asked when signing failed, then the happy path; (6) the two verifiers on `timestamp-v1`; (7) the docs; (8) the live Done-when: `rpworker test --evidence` in the lab, `openssl ts -verify` with `-digest` and with `-data`, both verifiers printing one line, four changed copies (another run's token, a changed byte, the token removed, the test root given), one run against a closed port, evidence under `docs/api/veeam-lab/w4.4-live-*`.

**Open, for later tasks.** W4.5: the folder's ACL, which is what stops a local user removing a token. W4.6: `tsa_error` in the outbox manifest, whether `flush()` asks again for a missing token and for how long, the upload's `timestamp` part. W4.7 and W4.8: the two-minute wait against "stop within 30 s" (the sleep must be interruptible), the run mutex held meanwhile. W4.9: the sentinel grep must not flag the published test TSA key. C5.7: `tsa_ok`, and whether `timestamp unchecked` is a failure there. C6.4 and Q6.1: "its time is within the period" against a late token and an 80 s-fast Worker clock; the wording for "not timestamped". Not decided at all: long-term validation, a revoked TSA certificate, a second TSA as fallback, a customer with no route to the TSA (every run then waits two minutes).

**Not measured.** No program was compiled against the vcpkg OpenSSL's TS API (headers and exports only; the command-line checks ran Git's 3.5.5). `cpr` sending a request body with NUL bytes wasn't tried. `rfc3161ng` and `tsp-client` weren't run. The JWT false-refusal rate is an estimate. DigiCert's missing HTTPS was seen from this network only. No TSA's rate limits or terms of use were read.

## 2026-10-06 — W4.3 code review (PR #158), findings 10 to 15: the recorder takes its list of secrets, the key file's rule moves into the strict `signer.cpp`, and three lab fixes (proposed)

The six findings the entry below left open (its point 11), and the seven items the review's limit cut. PR #158 was merged before these; they are a branch of their own, `w4.3-review-open`. This amends that entry's point 11, the W4.3 build notes where they say the key file's framing is in `src/ed25519.cpp`, and nothing in the approved W4.3 entry: its point 4 ("each function one checked call into OpenSSL") is true again rather than amended.

1. **A `FixtureRecorder` takes its list of secret values (finding 10).** `open_recording` handed the recorder `secret_values(secrets)` as a temporary, the recorder copied each value, and the temporary went unwiped: with `--record` a copy of the Veeam password, the PFX and, since W4.3, the signing key's text stayed in freed memory. The fault is older than the key. The constructor's parameter is now `std::vector<std::string>&&`: each value is moved into the recorder or wiped where it is (`secure_wipe`), by a guard that also runs when the folder is refused. No call site changed. `secret_values` reserves its four places, so growing the list leaves no short value behind in a freed block. Rejected: a named vector and a wipe in `open_recording`, which is smaller but can't be seen failing. `rp/secrets.hpp` now says that a run which has taken the key out of `Secrets` adds its text and shapes for the run folder itself, and that the caller wipes the list or hands it to a recorder.
2. **The lab's PowerShell tests run without the caller's three variables (finding 11).** `run_pwsh` passed the caller's environment on, so in a shell where `set-worker-env.ps1` had been dot-sourced the refusal tests read `set: True`. It now passes `clean_env()`, the environment without `RP_GRAPH_CERT_PFX_BASE64`, `RP_GRAPH_CERT_PASSWORD` and `RP_SIGNING_KEY_BASE64` (names compared upper-cased).
3. **The stray guard removes only what the test made (finding 12).** `test_signing_key.py`'s `nothing_written` deleted `worker-signing.pub.pem` in the repository root, `lab/` and `docs/` whatever was there before, and its tests failed on a developer's own file and then deleted it. `stray_guard(paths)` snapshots the files that are there, lists the ones made or changed since, removes those it made and gives a changed one its bytes back.
4. **A malformed entry takes an earlier key out of the session (finding 13).** `set-worker-env.ps1` threw "Nothing was set" for a Credential Manager entry that isn't a signing key and left an `RP_SIGNING_KEY_BASE64` from an earlier call, which the next `rpworker test --evidence` would have signed with. It removes the variable before the throw, as the no-entry branch already did. The two certificate variables from an earlier call stay: the script states no rule for them and the finding didn't ask.
5. **The lost-stdout test can fail now (finding 14).** The buffer stopped storing before either line, and, as the build found, counting writes wouldn't help either: after the first short write the stream has `badbit` and nothing reaches the buffer again, so a regression would be invisible to any buffer and to a real stdout. The test now brings the stream back (`out.clear()`, the buffer's limit lifted) from inside the signing seam, which runs right before the two lines would be written, proves with a probe that the buffer stores again, and looks at stderr too, where the pipeline sends what it must still say. The `--json` twin (`wrote <file>`) got the stderr check only.
6. **The public key file's rule is in `signer.cpp` (finding 15), the first of the two options.** `pem_body`, `take_line_end`, `is_base64_char`, `is_space` and the Base64 and 44-byte checks moved from `src/ed25519.cpp` into `signer.cpp`'s `public_der_of`; `Ed25519::public_key_from_pem(pem)` is replaced by `Ed25519::is_public_key(der)`, one checked call. Reason: it is a rule on text that both verifiers must hold alike, which is what the strict gate is for, and after the move the approved point 4, `ed25519.cpp`'s header comment, CLAUDE.md and `docs/testing.md` are true as written. Rejected: correcting those four texts to bless the exemption, which point 4 justified only by library failures no test can provoke; the grammar has none. `signer.cpp` is 347 of 347 with it, every line of the grammar reached by the 46 rows of `key-files.json`; `ed25519.cpp` is 62 of 81, the same 19 lines as before. `verify_bundle.py` is unchanged.
7. **The seven cut items.** Fixed: the raw U+FEFF between two quotes in `verify_bundle.py` is now written as its escape, and a test holds the script's source to printable ASCII (`lab/seeder/normalize.py` had the same character and got the same fix and test); the comments in `rp/secrets.hpp` and `config_check.cpp`, and a sentence of `docs/verification.md`, that said only `test --evidence` parses the key (`signer public-key` does too); the hidden writer of the shared signing vectors builds all three texts before it writes the first. Left: both JSON files parsed twice in the script (one extra parse of at most 16 MiB, no behaviour, no test that could fail first); the schemas loaded before the key and the folder (recorded as chosen in the build notes, and it only decides which `error:` line shows, both exit 2); `signing_key.py`'s own copy of the credential read (lab-only, different error types, to be merged when W4.5's vault changes where secrets live); `signer.cpp`'s local hex check, which is not a duplicate: `rp::is_sha256_hex` takes either case and the signature file's rule is lower case only, so it was renamed `is_lower_sha256_hex` with a comment, and `to_hex` and `string_at` have no second copy to merge with.
8. **What was seen failing, and what was not.** Seen failing before its fix: the child shell seeing the caller's variables; the stale key after a malformed entry (Windows with `pwsh` only, so never on the lab's CI, which is Linux); the stray guard, against the old delete-everything body moved into the helper; the recorder's list, with the `&&` signature over the old copying body, on a good and on a refused folder; the key file's rule, under the old interface with a fake primitive that takes anything (33 rows accepted that must be refused); the two ASCII-source tests. Seen failing only by a temporary change to the product code, since the code was right: the lost-stdout test, once with the guard `if (!output_lost)` made `if (true)` and once with the lines sent to `(output_lost ? err : out)`, each reverted. Not seen failing: the stderr check added to the `--json` twin, the comment and doc corrections, the writer's new order (a hidden test), the rename, `secret_values`' `reserve`. Still true: no test observes the other wipes (`RunSigningKey`, the run folder's builder, `read_env`, `signer public-key`).
9. **The runs of 2026-10-06.** `ctest --preset dev`: 1473 of 1473 (ten live tests skipped). The Worker's coverage run and gate: exit 0, 97.3% line (10569 of 10863), the strict files all 100%: `signer.cpp` 347 of 347, `signer_command.cpp` 116 of 116, `cleaner.cpp` 202 of 202, `run_status.cpp` 415 of 415, the three `target_guard` files; `ed25519.cpp` 62 of 81, `recording_http_client.cpp` 386 of 401. Cloud's pytest: 642 passed. The lab's: 982 passed, 1 skipped. CI has still not run.

## 2026-10-06 — W4.3 code review (PR #158): findings 1 to 9 fixed; a file is there under its own name, the folder is read through its extended path, and a verifier's own failure no longer reads as a verdict (proposed)

A code review of the branch (2026-10-06, `/code-review max`, fifteen findings posted on PR #158) found no wrong `verified`, no leak of the key in today's code paths and no fault in the guard or the status. Its findings 1 and 3 to 9 are the two verifiers answering differently for one folder, or a failure of a verifier ending in a verdict's line or exit code; finding 2 is `redact()`. The owner asked for 1 to 9 to be fixed; 10 to 15 and the seven cut by the review's limit stay open (below). This entry amends the W4.3 build notes' points 6, 13, 16, 17 and 18.

1. **The folder is listed and read through one extended-length path (finding 1).** `rpworker.exe` has no long-path manifest, so a file whose full path is past 260 characters didn't open: an intact signed folder at a path of 242 to 257 characters was `not verified: attachment_missing`, `signature_file` or `result_unreadable`, where `verify_bundle.py` said `verified`. `rp::extended_folder` (`src/file_read.hpp`) makes the folder absolute and puts `\\?\` (for a share `\\?\UNC\`) in front; `signer verify` lists and reads through that one path. The folder is made absolute as a file inside it would be (`absolute(folder\x)`, then the name taken off), so Windows reads its name as on every open of `folder\name`: a name of blanks or dots, or with a space after it, stays no folder. The script does the same for its own reason: where Windows' long-path setting is off, Python opens no such file either, and with the Worker fixed the two would differ the other way; `_open_folder` resolves `\\?\` + the absolute path. Rejected: a `longPathAware` manifest (it works only where the registry setting is on, and the answer mustn't depend on the machine); telling "not there" from "couldn't be opened" by the error code (Windows gives "path not found" for both); reading `unreadable` as a failure of the verifier whenever the listing has the name (a folder and a file without read access are `attachment_missing` by the build notes' point 6).
2. **A file is there under its own name, byte for byte (finding 9).** NTFS opens `ITEMS.CSV` for `items.csv`: both tools said `verified` and, beside it, `note: not listed in the result: ITEMS.CSV`, and the same four files on a file system that tells the names apart were `attachment_missing`. Now a file is read only when the folder's listing has its name; any other name isn't asked for. `Signer::verify_folder`'s `files` are no longer for the notes alone (a caller must hand it the listing; `rp::list_folder`), and the script's `verify_folder` reads through the same rule. `RESULT.JSON` is `result_unreadable`, `Signature.json` is `signature_file`. No shared case holds it: a case's `files` map has no order, and on a file system that ignores case "remove `items.csv`, write `ITEMS.CSV`" in the other order leaves neither. Each side has its own test on a real folder. Rejected: comparing names without case in both tools (the verdict would still differ from a reader's on Linux, and "which case folding" is a rule of its own).
3. **A folder as a listed attachment is `attachment_missing` in both (finding 5).** `read_whole_file` asked `file_size` before it knew the path was a file; MSVC answers for a folder (on NTFS 4096 once it holds a few names), so a folder of five files was `too_large` and the word `attachment_size`. It asks `is_regular_file` first, as the script's `_read_file` asks `S_ISREG`. This makes the build notes' point 6 true of the Worker too.
4. **A result that couldn't be checked against its schema is the verifier's failure (finding 3).** `rp::validate_result` answers "not valid" when the embedded validator couldn't be loaded or threw, which `Signer` read as `result_schema`, exit 5. `ResultValidation` gains `not_checked`, set in exactly those two cases; the Signer throws `rp::VerifierFailure` for it (from `verify` and `verify_folder`), and `signer verify` prints `signer error: the result couldn't be checked against its schema`, exit 1, nothing on stdout. A folder refused before the schema is asked (`result_unreadable`, `result_not_canonical`) still gets its word. The pipeline is unchanged: it asks `result_schema_ready()` before a run, and an unchecked result there is `result_invalid`, an `error`. For the tests `rp::detail::set_result_validator_unavailable(bool)` (`src/result_schema_detail.hpp`) makes the validator count as not loaded; it can only make the Worker refuse, and nothing under `src/`, `include/` or `app/` calls it (as `set_loopback_only`). Rejected: asking `result_schema_ready()` in `signer verify` alone (a validator that throws in the middle would still be a verdict), and a validator handed into `Signer::verify` (nlohmann's types in `rp/signer.hpp` for one test's sake).
5. **A folder name Windows would drop is no folder, in the script too (finding 6).** `Path(" ").resolve()` is the working folder on Windows, and `...`, `. ` and `.. ` likewise (`.. ` the one above): with the working folder a signed one, the script printed `verified` for a folder nobody named. `_open_folder` refuses, on Windows, a last path part of blanks and dots only that is neither `.` nor `..`: `error: the folder can't be opened`, exit 2, as the Worker's exit 1. A name with a space after it (`run `) is still the folder `run` to the script and no folder to the Worker: the build notes' point 17 stands for it, and a Worker test now pins the Worker's side, with `run\ `, `run\...` and the four forms above.
6. **An option given twice is a usage error in the script (finding 4).** argparse keeps the last value: `--public-key other.pem --public-key trusted.pem` verified under the second, so a wrapper that puts its trusted key first and passes arguments on had it replaced; a second `--schemas` could name a schema that takes anything. Both options take the `_Once` action: `verify_bundle.py: error: argument --public-key: given more than once`, exit 2. The Worker already answers a second `--public-key` with its usage line, 64.
7. **The script without its packages is exit 2 (finding 7).** Run with plain `python`, the two imports failed at the module's top and Python's exit status for the traceback is 1, the script's "not verified". Run as a program, an `ImportError` there is `error: a package the script needs isn't installed (<package>); run it with `uv run``, exit 2; imported as a module it is still an `ImportError`.
8. **A verdict that can't be written is exit 2 from the program, not 120 (finding 8).** `main()` returned 2 when stdout couldn't be flushed, but the text stayed in the stream's buffer; the interpreter's own flush at exit failed again and made the status 120, with an `Exception ignored` line. As a program the script now ends through `_exit_code`: stdout is flushed once more and, when that fails, pointed at the null device, so nothing is left to fail. The build notes' point 16 ("a verdict that can't reach stdout is exit 2") is now true of the process, and a test runs the script with a pipe nobody reads. Not done inside `main()`: a caller's stream (pytest's capture) isn't the script's to redirect.
9. **`redact()`: a private key block that is the value of a secret name, and two kinds of label (finding 2).** A key rule ends an unquoted value at the first blank or at the line's end, which is inside `-----BEGIN PRIVATE KEY-----` or right after it; the scan went on behind the header, and the key's own lines came back as they were: `signing_private_key=[REDACTED] PRIVATE KEY-----`, then the Base64 body. (`main` did the same before the three names existed; nothing in the Worker logs that shape.) A bearer token's and a secret key's or header's replacement now goes on to the end of a private key block that starts inside it (`through_private_key`). And a block is a private key's when its label holds `PRIVATE KEY`, the label upper-case letters, digits and blanks: `ED25519 PRIVATE KEY` (a digit) and `PGP PRIVATE KEY BLOCK` (it doesn't end with the words) were left unmasked. This amends the build notes' point 13 ("ends in").
10. **What the fixes don't cover.** The `--public-key` file is still opened by its path as given (a file past 260 characters "can't be read", exit 1 or 2: no verdict). The script on a machine with Windows' long paths switched off wasn't run: the lab machine has them on, so the script's long-path test passes there with or without the change; what was seen failing is the path the listing and the reads go through. Not seen failing first, by their nature: the Worker's test of the blank and dotted folder names (it pins what the Worker already did), the script's tests that `.` and `..` still name their folders, that it runs as a program with exit 0 and 1, and that a missing package is an `ImportError` to an importer. `verify_bundle.py` under Linux is still not run by any test here.
11. **Still open from the review.** Findings 10 to 15, each posted on the PR: the recorder's unwiped temporary list of secret values (10), two lab tests that depend on the caller's environment or delete a file of the developer's (11, 12), `set-worker-env.ps1` leaving a stale key on a malformed entry (13), a test of the lost-stdout path that can't fail (14), and the public key file's grammar living in `src/ed25519.cpp`, outside the strict gate, with CLAUDE.md's description of that file no longer true (15). And the seven the review's limit cut: an invisible U+FEFF in a string of the script, both JSON files parsed twice, the schemas loaded before the key and the folder, `signing_key.py` reading a credential with its own copy of `read_generic_credential`, `signer.cpp`'s local `is_sha256_hex`, `to_hex` and `string_at`, two comments that say only `test --evidence` parses the key, and the hidden writer of the shared vectors leaving them half written if it fails.
12. **Tests and coverage, the runs of 2026-10-06.** Each new test was written first and seen failing, the Worker's against stubs (`extended_folder` returning its argument, a validator switch that did nothing) and then against the code as it stood, but for those point 10 names. `ctest --preset dev`: 1469 passed, none failed (ten live tests skipped); thirteen test cases are new. Cloud's `uv run --locked pytest`: 641 passed (36 new, all in `tests/test_verify_bundle.py`). The Worker's coverage run and gate: exit 0, 97.3% line overall (10567 of 10861), the strict files all 100%: `signer.cpp` 303 of 303, `signer_command.cpp` 116 of 116, `cleaner.cpp` 202 of 202, `run_status.cpp` 415 of 415, the three `target_guard` files; not strict, `file_read.cpp` 114 of 119, `redact.cpp` 311 of 311, `result_schema.cpp` 108 of 118. Both tools were then run by hand on one set of folders (the signed one, one 260 characters deep, `ITEMS.CSV`, `items.csv` as a folder of eight files, `--public-key` twice, the four blank and dotted names from inside a signed folder): the same stdout line each time, and no verdict where none is due. The lab's tests weren't run (nothing under `lab/` changed), and CI has still not run.

---

## 2026-10-05 — W4.3 build notes: what the build and its review settled beyond the approved entry (proposed)

The build follows the W4.3 entry below. A review of the branch (2026-10-05, five reviewers, each finding then checked by a sceptic) found no wrong verdict, no leak of the key and no fault in the guard or the status. What it found is the two verifiers answering differently around the verdict, for a key file, a file name and a folder argument (points 3, 4, 7 and 16), and two faults in the lab command's tests and checks (point 15). Point 3 amends the entry's point 4. Where the entry was silent or the build departs from its words:

1. **The second `hash_mismatch` case changes an item's `ms`, and there is one case beyond the list.** The entry asked for one digit of a hash in `check.items`; a check item holds no hash, so `result-check-item-one-digit` changes one digit of an item's `ms` (the file stays canonical and valid), and `cases.json`'s description says so. `untouched-the-second-key-given` (`wrong_key`) is added: the only case that gives another public key to an untouched folder. `cases.json` has 38 cases: `result_unreadable` 1, `result_not_canonical` 12, `result_schema` 1, `attachment_twice` 1, `screenshot_missing` 1, `signature_file` 10, `hash_mismatch` 2, `wrong_key` 2, `signature_invalid` 4, `attachment_missing`, `attachment_size` and `attachment_hash` 1 each, `verified` 1. The count and the count per word are pinned in `signer_test.cpp` and, since the review, in `cloud/tests/test_verify_bundle.py`. A case's `files` maps a name to `null` (remove), `{"text": s}` or `{"base64": b}`; a case may replace several files (the forgery replaces two); every case names its `public_key`.
2. **`containers_drawn` is the schema's `count`,** as `containers_eligible` and `containers_unresolved` are: 0 to 2^53 − 1, with no upper bound of 8, since the limit isn't in the result. The three shared cases are `sample-containers-listed-still-there` (mail; the array added beside the count, so it fails for one reason only), `sample-containers-drawn-an-array-of-names` (OneDrive) and `sample-no-containers-drawn` (SharePoint), so both schema definitions are touched. The in-memory `BrowseRecord::containers_listed` keeps its name and its names; only `kind_json` writes its size.
3. **`rpworker signer public-key` prints the PEM alone on stdout and `key <key_id>` on stderr (amends point 4).** The entry had both on stdout. Both verifiers refuse a key file with anything after the END line, so the command's own output, saved with `>`, was no key to either: the review reproduced it, and the test that claimed otherwise had cut the `key` line by hand. Now stdout is a key file as it is, and a test feeds the whole of it to `signer verify`. The `key` line is written only once the PEM is out; a lost stdout is `signer error: the answer couldn't be written`, exit 1, and no `key` line. Its unset text has no tail, `config error: RP_SIGNING_KEY_BASE64 is not set` (no run is asked for); the not-a-key text is the pipeline's. The two texts are written in `signer_command.cpp` and again in `RunSigningKey::parse`, not shared. The lab's `new-signing-key` still prints the `key` line on stdout after the PEM; its key file is `--public-key-out`'s. Rejected: loosening both readers to take a trailing line (two languages to keep equal), and an `--out <file>` flag (a second way to the same bytes).
4. **One strict rule for a public key file, held by both verifiers and by `shared/testdata/signing-v1/key-files.json`.** The first build read the file with each library's own PEM reader, and the two readers differ: OpenSSL's took DER with a byte after the key, a long-form length, a BIT STRING with one unused bit and Base64 with non-zero pad bits, and handed back the key re-encoded; `cryptography`'s took a block on one line, lone CR line ends, text on the armour lines and RFC 1421 header lines. Each tool then gave `verified` where the other gave no verdict. Now neither uses a PEM or DER reader of its library. The rule: white space (space, tab, CR, LF) around; the line `-----BEGIN PUBLIC KEY-----`; one or more body lines, each of one or more Base64 characters and nothing else; the line `-----END PUBLIC KEY-----`; inside the block a line ends with LF or CRLF only. The body lines joined must be strict standard Base64 (padded, `=` only at the end, the unused bits zero) of exactly the 44 bytes of an Ed25519 SubjectPublicKeyInfo as the library writes it (`302a300506032b6570032100`, then the key's 32 bytes). Those bytes are the key's DER, never a re-encoding; where the body is wrapped doesn't matter. The file has 46 rows, 11 accepted and 35 refused, each a file's text (one as Base64: UTF-16 with a BOM) and whether both readers must return a key; the counts are pinned on both sides. The small-order identity key is a well-formed key and is accepted, as the entry's trust rule leaves it to C5.5. In the Worker the framing is in `src/ed25519.cpp` (`pem_body`, not strict), reached through `PublicKey::from_pem`; in Python the library is handed the 32 key bytes only, and a test shows it isn't asked about a refused file.
5. **The size limits.** `result.json` 16 MiB (`kMaxResultFileBytes`, `MAX_RESULT_FILE_BYTES`): larger is `result_unreadable`, not read. `signature.json` 4096 bytes (a Worker-made one is 322): larger is `signature_file`. The caller's key file 64 KiB in both tools (`kMaxPublicKeyFileBytes`): larger is "can't be read". A schema file given to the script 16 MiB. A file is read whole or it is no file (`read_whole_file`, which the run folder's read back now shares; `src/file_read.{hpp,cpp}`, not strict).
6. **An attachment longer than listed is `attachment_size`, and isn't read.** The reader is given the listed size as its limit. In the script a listed name that is a folder is `attachment_missing` (not a regular file is unreadable). No shared case covers a longer attachment or a file over a limit.
7. **Notes: only with `verified`, on stderr, before the verdict's line.** `note: not listed in the result: <name>`, one line per name of the folder that isn't `result.json`, `signature.json` or a listed attachment (a subfolder's name too, never what is in it), sorted by code point. A name is written so that it can't end a line or start another: printable ASCII (0x20 to 0x7E) as it is but for the backslash; anything else by its code point in lower-case hex, `\xNN` below U+0100, `\uNNNN` below U+10000, `\UNNNNNNNN` above. NTFS takes a name that isn't valid UTF-16; the first build's `list_folder` threw for one, so one stray file made a correctly signed folder end `error: unexpected failure`, exit 1, in the Worker while the script said `verified`. `list_folder` now keeps each lone surrogate as the three bytes UTF-8's scheme gives its code point, `name_code_points` reads it back, and the note shows it as `\udXXX`, never joined with its neighbour. The script wrote a backslash, a tab and a line end in Python's short forms; it writes the Worker's now. Both tools on one folder with ten odd names gave the same stdout and stderr.
8. **`signer verify`'s other lines.** Exit 1, all on stderr with the prefix `signer error:`: `the --public-key path is not valid UTF-8`, `--public-key <file>: the file can't be read`, `--public-key <file>: not an Ed25519 public key in PEM`, `the folder's path is not valid UTF-8`, `<folder>: the folder can't be opened`, and `the answer couldn't be written` for a verdict that didn't reach stdout (never exit 0 or 5 without its line). The key file is checked before the folder. `<folder>` and `--public-key <file>` in either order; an empty value, either given twice or any other word is the usage line, exit 64. A stream that throws is `run_cli`'s `error: unexpected failure`.
9. **`Signer::verify` and `verify_folder` are not `noexcept`.** What the reader or the primitive throws passes through to `run_cli`: a failure of the verifier is never a verdict. `sign`, `SigningKey::from_base64` and `PublicKey::from_pem` never throw. In the strict files a function never returns from both a `try` block and its handler: OpenCppCoverage then marks the closing line unreached, so each assigns and returns once after.
10. **`write_result` has an out-parameter,** `SignedResult* signature = nullptr`, filled only when `result.json` is written, so the pipeline can print the `signed` line. `EvidenceFailure::not_signed` names `result.json` as its file; an `EvidenceOptions::sign` that is null is `not_signed` too. `EvidenceBuilder` is no longer copyable (its destructor wipes its copy of the secret values). The pipeline's seam for tests is `RestoreCommandEnv::sign_result` (null: `Signer::sign`).
11. **`rp::secret_values` leaves out a value that is empty.** The two loops it replaces passed a set-but-empty one on.
12. **A `--record` recorder knows the key's text, not the seed's other shapes.** The text stays in `Secrets` until `open_recording` has run and is taken out (`RunSigningKey::take`) before the connector is made; on an earlier return the holder wipes it where it is. The parsed key's `secret_shapes()` (the seed in Base64 and in hex) go to the run folder's list alone, as the entry says. So a Graph or Veeam answer that held the seed in one of those shapes would be written to a fixture; the test's fixture check is live for the key's text only.
13. **`redact()`.** All three names take every form the others do (`name=value`, `name: value`, a JSON key); `signing_key_id` is not a match. A PEM block is masked when its label ends in `PRIVATE KEY` (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `RSA PRIVATE KEY`); one without its END line is masked to the end of the text.
14. **Names the entry doesn't have.** `rp::sha256_bytes` joins `rp/sha256.hpp`; the primitive's interface is `rp::Ed25519` and `rp::Ed25519Key` in `rp/ed25519.hpp`, the real one `openssl_ed25519()`. The schema's keyword walker moved to `tests/schema_walk.hpp` and runs over both schema files. The `attachments` description in `result.v1.json` now reads "One entry per file of the run folder that the result covers … result.json and signature.json are never listed".
15. **The lab command.** The Credential Manager entry is the generic credential `RestoreProof Lab - Worker signing key` (user `rp-worker-signing-key`). Every refusal is exit 2, the seeder's own error code, and is made before a key is: an entry that is there without `--replace`, a `--public-key-out` file that is there without `--replace`, its folder missing, a path inside the repository. After storing, the entry is read back and the public key printed only if it is the key that was made. If the PEM file can't be written after the key is stored, stdout still has the PEM and the command exits 2. From the review: "inside the repository" is decided by file identity (each existing parent of the resolved path against the repository folder), so a `\\?\` path, the drive's admin share and a folder name with a trailing space are refused too; and the refusal tests can no longer write a file into the working tree or leave one there (a fixture replaces the writer and removes `worker-signing.pub.pem` from three places afterwards). `set-worker-env.ps1`: an entry that isn't key-shaped stops it before anything is set, its value never shown; with no entry a stale `RP_SIGNING_KEY_BASE64` is removed; `-SigningKeyTarget` is new, and every test passes a throwaway target.
16. **`verify_bundle.py` beyond the entry.** It sets up in the order schemas, key, folder (the Worker: key, folder). Exit 2, on stderr: `error: the folder can't be opened`, `error: --public-key: the file can't be read`, `error: --public-key: not an Ed25519 public key in PEM`, `error: --schemas: <file> can't be read`, `error: --schemas: <file> isn't a JSON Schema` (it must parse strictly, be an object and pass `check_schema`), `error: --schemas: the folder can't be opened`, `error: unexpected failure (<exception type>)`, and argparse's usage. From the review: an empty `<folder>`, `--public-key` or `--schemas` is such an error and never the working folder (`Path("")` is `.`, and the first build gave a verdict on it); and the folder is resolved once, strictly, and that one path is listed and read from (on Windows a name ending in a space could be listed as one place and read as another, which ended in `not verified: result_unreadable` for a complete folder). Flags can't be abbreviated. A verdict that can't reach stdout is exit 2. The canonicaliser's slugs where the entry left a choice: a BOM, `NaN` and `Infinity` are `not_json`; a lone surrogate is `invalid_utf8`, refused by `canonical_json` (the escaped form parses); a 5000-digit integer is `integer_out_of_range` at the parse; the nesting is counted before the bytes are decoded, so invalid bytes 33 levels deep are `too_deep`; `canonical_fault` answers `not_canonical`, which is no `Refusal` slug, for bytes that have a canonical form and aren't it. None of the slugs reaches the verdict: each is `result_not_canonical` or `signature_file`.
17. **Where the two tools still differ, by choice.** The exit codes (the entry). An empty `<folder>`: usage and 64 in the Worker, `error: the folder can't be opened` and 2 in the script. A folder path with a trailing space: Windows resolves it to the real folder, so the script verifies it, and the Worker says the folder can't be opened; refusing a name that resolves to another would be a further rule. A relative folder whose name starts with `-` is an option to argparse: give it as `.\-name` or by its full path. `--help` exits 0 in the script and prints no verdict line.
18. **Not reached by a test.** The wipes: no test observes that the holder, `EvidenceBuilder`'s destructor, `read_env`'s buffer or `signer public-key` wipes anything; the tests show only that the connector's `Secrets` never hold the key and that the key is in no file, fixture, log line or stream. `src/ed25519.cpp` is 111 of 130 lines (85.4%): unreached are the library failing for a valid key at four calls (the public key's DER, a signature, a key from 32 bytes, the PEM's bytes) and the five `catch (...)` blocks, which only an allocation failure enters; this is the file the entry's point 4 keeps outside the strict gate for that reason. `src/file_read.cpp` 99 of 101: `read_whole_file`'s closing line (the tool's artefact) and a listing that fails partway. No exe test runs a successful `rpworker.exe signer public-key` (the exe checker compares one line per stream; `run_cli` covers it in `rptests`). An attachment longer than listed and a file over a size limit have no shared vector, and two of the script's size-limit tests would pass without the limit (their files aren't canonical either). `verify_bundle.py` under Linux, and a folder holding a name that isn't UTF-8 there. The script has no coverage gate and mutmut wasn't run over it.
19. **Left as they are.** From the review, refuted and recorded: the primitive's `verify()` answers `false` for its own failures too (a null context, a failed init, anything caught), which the Signer reports as `signature_invalid`; the interface says "false for anything else", only an allocation or library failure gets there, and no test can; a stricter reading would throw for them. The recorder without the seed's shapes (point 12): handing them over would be a new decision. A `signature.json` whose removal fails after `result.json` couldn't be written stays, with no line of its own: it needs two faults at once, the run already ends with its `evidence error` and exit 1, the folder has no `result.json` and so isn't complete, and W4.8's Open point removes a leftover first. The Cloud side pinning no case counts was refuted as a fault and pinned all the same (38 and per word; 183 and 45). From W4.2's code review: findings 7 and 9 to 11, and stdout and `--json` outside the secret check. A comment in `signer_command.cpp` (`printable`) still says the script's notes differ for a backslash, a tab and a line end; they no longer do.
20. **How it was built.** In stages by sub-agents, each stage's tests written before its code and seen red against a stub or the code as it stood, then committed with it; the reports name the failing lines. Not seen red: the shared cases' runner in the Worker against a stub verifier with the vector files present (the files didn't exist yet when it failed); the two `config_test` messages for the key (built from `kSecretEnvVars`, which already had five names); the nine exe tests of the `signer` commands (written first, first run after the code); part of stage 4's reds, cut off by an output filter; three of the script's tests added afterwards; and, in the review's fixes, the Python count pins and the lone-surrogate note test, green from the start. The lab's first finding passes on the committed code, so its refusal was switched off for a moment to show the leak (a `lab/worker-signing.pub.pem` in the working tree), then restored. Stage 4 (the two commands) is one commit, test and code together; commit `8b958b8` doesn't build alone (its `CMakeLists.txt` names `signer.cpp`, added in the next). One stage's red run wrote three stray public PEM files of RFC 8032's key into the repository; they were deleted before any commit. The workflow: six sub-agents investigated, three proposed, six checked the entry, eight built in stages (four of the Worker, one for coverage, two of the script, one of the lab), five reviewed with a sceptic each (eighteen findings: twelve upheld, which are eight faults, some found twice, and six refuted), three fixed.
21. **Tests and coverage, the last runs of 2026-10-05.** `ctest --preset dev`: 1456 of 1456 passed (ten live tests skipped). Cloud's `uv run --locked pytest`: 605 passed; its coverage gate passes (100.00% of `app`, which doesn't hold the script). Lab's `uv run pytest`: 978 passed, 1 skipped. The Worker's coverage run (`worker/tools/run_coverage.ps1`, then the gate): exit 0, 97.3% line overall (10516 of 10808), every `.cpp` present; the strict files all 100%: `signer.cpp` 291 of 291, `signer_command.cpp` 108 of 108, `cleaner.cpp` 202 of 202, `run_status.cpp` 415 of 415, `target_guard.cpp` 73 of 73, `target_guard_graph.cpp` 117 of 117, `target_guard_veeam.cpp` 315 of 315; not strict, `ed25519.cpp` 111 of 130, `file_read.cpp` 99 of 101, `evidence_builder.cpp` 259 of 279, `run_pipeline.cpp` 744 of 787 (no unreached line of either is W4.3's, by `git blame`). CI has still not run: no Worker workflow has started since 2026-10-03 (GitHub billing).
22. **The Done-when run, live on 2026-10-05 (16:10Z).** The lab's key was made with `python -m seeder new-signing-key --public-key-out C:\restoreproof-runs\worker-signing.pub.pem` (key ID `9dfab6eadaa1d04a22dcc966aac7a53bcff8bbe0077232485f6143cd9c4d0ca5`; `rpworker signer public-key` printed the same PEM and ID). Then `rpworker test --mail 10 --sp 10 --od 10 --run-id w43-done-when-1 --point <id> --evidence %ProgramData%\RestoreProof\runs`, elevated, on the 2026-10-03T16:16:54.0154727Z restore point: 30 of 30 restored in five `Success` sessions, `status pass: 30 of 30 item(s) verified: manifest 15, fields 5, metadata 10`, `cleanup after ok`, the timings' table, `signed 2cd2cd0010b4d3bc02d6af1943beb80a5fef81c3a1c5a38db420c2e54559a8f4 key 9dfab6eadaa1d04a22dcc966aac7a53bcff8bbe0077232485f6143cd9c4d0ca5`, then `evidence C:\ProgramData\RestoreProof\runs\w43-done-when-1: result.json, signature.json, items.csv, veeam-session.log`, exit 0, stderr empty, `graph list` 0 in all three targets before and afterwards. On that folder `rpworker signer verify` and `uv run shared/tools/verify_bundle.py`, given the lab's public PEM, printed the same line, `verified 2cd2cd0010b4d3bc02d6af1943beb80a5fef81c3a1c5a38db420c2e54559a8f4 key 9dfab6eadaa1d04a22dcc966aac7a53bcff8bbe0077232485f6143cd9c4d0ca5`, and that hash is the SHA-256 of `result.json`'s 22,347 bytes. On five changed copies both printed the same line each time: one digit of an item's hash in `result.json` changed, `not verified: hash_mismatch`; one Base64 character of `signature` changed, its shape kept, `not verified: signature_invalid`; one byte of `items.csv` changed, `not verified: attachment_hash`; `veeam-session.log` removed, `not verified: attachment_missing`; RFC 8032's test key given, `not verified: wrong_key` (exit 5 from the Worker, 1 from the script, each time). Evidence `docs/api/veeam-lab/w4.3-live-*` (the run's output, `graph list` afterwards, both verifiers' lines for the six folders); the folder, its copies and the lab's public key stay outside the repository. One thing left on the laptop by a lab test of the build: a throwaway Credential Manager entry `RestoreProof Lab - test b2ae42de-...`, which `cmdkey /delete` wouldn't take for its spaces; it holds a test key and can be removed in Credential Manager.

---

## 2026-10-05 — W4.3: the signature is a file beside the result; what is hashed, where the key comes from, and the two verifiers (recorded before the build; the owner approved it as written)

W4.3 (#46) signs the result: an Ed25519 key, `Signer::sign` and `Signer::verify` in the Worker, and `shared/tools/verify_bundle.py` for an auditor. Done when the C++ and the Python verifier agree on a real bundle. This entry works from the Sprint Task Guide (W4.3 to W4.9, W5.1, W7.1, C5.2, C5.5, C5.7, C6.2, C6.4, Q4.1), the W4.1 and W4.2 entries below and their Open points, two of W4.1's and one of W4.2's falling due here. No code is written yet. Six sub-agents investigated, three proposed independently (all three put the signature in a file of its own), and six checked this entry against the code, the guide and, for the cryptography and the two JSON parsers, by experiment; what they measured is marked as measured.

What the investigation found, since the points below rest on it:

- **The guide's signing sentence can't be built as written.** "`bundle_sha256` over the canonical bytes of result.json with `signature` and `tsa_token` fields removed" names two removed fields, but `bundle_sha256` can't be inside the bytes it is the hash of, and `tsa_error` (W4.4) is known only after the signature. The guide never names `bundle_sha256` or `worker_id` as a key of `result.json` (C5.7 step 3 does read a `worker_id` from the upload); C5.2 has no column for the signature or the token; "bundle" means the result JSON in some places and the run folder in others, never a zip. The upload is multipart, "result (JSON file) + attachments by name" (C5.7).
- **Every key of the result is required, and the writer never replaces a file.** `result.v1.json` has `properties` equal to `required` (a test holds it), so "removed" would hash a document the schema refuses and no file ever holds; `rp::write_file_atomically` refuses a name that is there, so a `result.json` written with its signature couldn't take a TSA token afterwards.
- **The two JSON parsers differ on what they take, and agree where it hurts.** Both keep the last of two equal keys, silently, so a hash made from the parsed value agrees on both sides while ignoring bytes that are in the file. Measured: `nlohmann::json` skips a UTF-8 BOM and refuses `NaN`, an escaped lone surrogate and `1e400` at the parse; Python's `json` refuses the BOM and takes the other three; a 100,000-level `[[[...` kills the C++ process with a stack overflow and raises `RecursionError` in Python.
- **Each random item's key is in the result twice,** once in `sample.<kind>.random.keys` and once as `expected.items[].key`, which the schema requires for a random item. `containers_listed` holds up to eight containers per type (a mailbox address, a Graph site ID, a OneDrive owner, or the URL of a OneDrive whose owner didn't resolve), pushed when a container is drawn, whether or not it gave a candidate; it is the only field of the result that names a container the run didn't sample. Nothing in the Worker, the Cloud or the lab reads either field back from the JSON; `build_expected_set` works from the `Selection` in memory.
- **OpenSSL at the pinned baseline is 3.6.4** and declares the one-shot Ed25519 calls. Measured with Git's OpenSSL 3.5.5 and `cryptography` 50.0.2: the PEM of `openssl genpkey -algorithm ed25519` has one body line of 64 Base64 characters, 48 bytes of PKCS#8, always the 16 bytes `302e020100300506032b657004220420` and the 32-byte seed; the public key's SubjectPublicKeyInfo DER is 44 bytes; RFC 8032's tests 1 to 3 reproduce byte for byte; a signature whose S is S + L is refused by both; a small-order public key (the identity point) is accepted by both and then verifies a forged signature for any message. OpenSSL's PKCS#8 reader leaves a copy of the seed in freed memory the Worker can't reach (`ecx_backend.c`), and takes a key with bytes after it.
- **The repository has** `rp::sha256_hex` but no raw digest, strict Base64 in `rp/base64.hpp`, `rp::secure_wipe` for a `std::string` in `rp/cert_export.hpp`. `redact()` masks by key name, JWT and `Bearer` shape: a bare Base64 key or a `-----BEGIN PRIVATE KEY-----` block passes it unmasked today. `load_secrets_from_env()` reads every secret variable for every command, and the connector's Graph factory captures the whole `Secrets` by value.
- **`cryptography` is locked in `lab/` (50.0.1) and nowhere in `cloud/`;** PyNaCl is in neither. `shared/tools/` doesn't exist, no workflow runs anything inside `shared/`, and the "No test, no merge" guard doesn't look there. Neither `openssl` nor `sha256sum` is on PowerShell's `PATH` on the lab machine; both are in Git's folders.
- **Any Worker path part named `signer` or starting `signer_` is strict** (`coverage_gate.py`): `src/signer.cpp`, `src/signer_command.cpp` and `rp/signer.hpp` are, `src/ed25519.cpp` is not. OpenSSL's own failures for a valid Ed25519 key can't be provoked by a test, and no command file of the Worker is at 100% line today: each is short by its `catch (...)` "unexpected failure" block.

**Decision.**

1. **`containers_listed` is cut to a count before the first signature; the keys stay.** In `sample.<kind>.random` the array `containers_listed` becomes the integer `containers_drawn`: how many containers the draw looked into (the array's length; not the limit `CandidateLimits::containers_tried`, which isn't in the result). The names go because they are of mailboxes, sites and OneDrives the run did not test, a departed user's OneDrive URL among them; nothing reads them; and they are not what repeats a draw (the seed and the restore point give the same containers again, and `pool_sha256` shows the pool was the same). `containers_unresolved` already counts the OneDrives whose owner didn't resolve; the URL that explained such a pool difference is given up. The keys stay, both copies: they name only items the run sampled, they are the one record of where a random item came from (mailbox, folder, site, path) when a failure has to be traced, and cutting the `sample` copy alone would remove no tenant data, since `expected.items[].key` holds the same strings (W3.1 point 8 names a random item by its key). This closes W4.1's first Open point and W4.2's point 10.
   - **`restoreproof.result.v1` changes in place,** as it did when W4.2 added two keys: no v1 result has been signed or uploaded. The unsigned lab results of W4.1's and W4.2's Done-when runs, kept outside the repository, no longer validate.
   - **Cost.** The two schema definitions (`sample_kind_key4`, which mail and SharePoint share, and `sample_kind_key3`), a `required` entry and a property in each; one line of `kind_json` and the comments in `rp/sample_selector.hpp` and `rp/connector.hpp`; the goldens; `valid.json` written again. No shared case touches the field today, so three invalid ones are added to hold the cut on both sides (the old array still there; `containers_drawn` as an array of names; `containers_drawn` missing): 183 cases, 45 valid.

2. **The signature lives in `signature.json`, beside `result.json`. The result has no signature field and nothing is removed before hashing.** This amends the signing contract (CLAUDE.md, `docs/glossary.md`, the guide's W4.3 and C5.7 step 4): "`bundle_sha256` is computed with `signature` and `tsa_token` removed" becomes "`bundle_sha256` is the SHA-256 of `result.json`'s bytes, which are the result's `canonical-json-v1` form; the signature is in `signature.json`, never in the result". It closes W4.1's second Open point by its second branch ("or live outside the signed document") and supersedes W4.1 point 3's "W4.2 to W4.6 and W5.1 each add theirs" for the signature fields.
   - **What is hashed and signed.** `bundle_sha256` = SHA-256 of the canonical bytes, 64 lower-case hex; for a folder the Worker wrote it is the file's own SHA-256 (`Get-FileHash`, or `sha256sum` in Git Bash). The Ed25519 message is the 32 raw digest bytes (the bytes `bundle_sha256` shows as hex, not the hex text). `signature` is standard Base64 with padding: 64 bytes, 88 characters.
   - **`signature.json`,** written as its own canonical bytes, five keys, all always there, and never a sixth:
     `{"algorithm":"ed25519","bundle_sha256":"<64 hex>","format":"restoreproof.signature.v1","key_id":"<64 hex>","signature":"<88 Base64>"}`.
     `key_id` is the SHA-256 of the public key's SubjectPublicKeyInfo DER, so `openssl pkey -pubin -outform DER | sha256sum` (Git Bash) gives it from the registered PEM; it is also what C6.4's report can print as the "public key fingerprint".
   - **Its schema is a second file, `shared/schemas/signature.v1.json`,** closed, five required keys, in the same keyword subset: `const` for `format` and `algorithm`, the 64-hex definition twice, and for `signature` `minLength` = `maxLength` = 88 with `^[A-Za-z0-9+/]{85}[AQgw]==$` (measured: it takes every 64-byte value's Base64 and nothing with a non-zero pad bit, a URL-safe character or no padding). `result.v1.json` gains no key: seventeen stay, and the shared case `signature-not-in-the-schema-yet` stays invalid. Python validates a signature file against the schema; the Worker checks the same rules in code in the strict `signer.cpp` (no second embedded validator), a Worker test validates a Worker-made file against the schema file and runs the keyword walker over it, and the shared vectors of point 6 hold the two to one answer.
   - **The timestamp will be a file of its own (W4.4), not keys of `signature.json`.** A closed five-key format can't take `tsa_token` later without every W4.3 verifier, an auditor's copy included, refusing every W4.4 folder. The token is over `bundle_sha256` and arrives after the signature, so it touches no signed byte either way; W4.4 names its file and where `tsa_error` goes. This changes the guide's W4.4 step 3 ("store the token base64 in `tsa_token`").
   - **The trust rule.** `signature.json` is not itself signed, and anyone can sign a result with a key of their own. So a verifier takes the public key from its caller (the Cloud's registered key, the auditor's PEM file), never from the folder, and answers `wrong_key` when `key_id` isn't that key's. A verifier is only as good as the key it is given: OpenSSL takes a small-order public key and then accepts forgeries under it, so refusing such a key is the job of whoever registers one (C5.5).
   - **A file on disk must be canonical.** Both verifiers require `result.json`'s bytes to equal the canonical form of what they parse to, and refuse otherwise (`result_not_canonical`). This changes Q4.1's second bullet, "re-ordered keys in result.json still verify": a re-ordered file is refused, because a verifier that re-serialises would accept bytes nobody signed, the duplicate key among them. What the Worker shows instead: a document built in two key orders has one canonical text and so one hash.
   - **`Signer::sign` takes the bytes that are written.** `sign(std::string_view canonical, const SigningKey&) noexcept` returns the signature file's text with its `bundle_sha256` and `key_id`, or nothing. It hashes exactly the text `write_result` is about to write, refuses text that isn't its own canonical form, and verifies its new signature with the key's public half before it answers (the issue's "self-check"). The issue's `sign(canonicalJson)`, kept as it is.
   - **The order of writing.** In `EvidenceBuilder::write_result`: the secret scan, each attachment read back against its hash (both as today), sign, write `signature.json`, write `result.json` last. `attachments` doesn't list `signature.json`, which depends on the result's hash. That amends W4.2 point 1's "one entry per file beside `result.json`": one entry per file the result covers; `result.json` and `signature.json` are never listed.
   - **What a signed folder is.** `items.csv`, `veeam-session.log`, `screenshot.png` if one was taken, `signature.json`, `result.json`. The Worker writes `result.json` only after `signature.json`, so in a folder only the Worker has written, `result.json` still means complete, and now signed. That is a statement about the Worker's order, not a protection: until W4.5 sets the folder's ACL another local user can delete or add a file, so W4.6 and the Cloud require both files and run the verifier.
   - **What a failed signing leaves.** The attachments (the two text files, and a screenshot if one was taken), no `signature.json`, no `result.json`: the folder of a run with no result, as for `result_invalid`. If `signature.json` was written and `result.json` then can't be, the Worker removes `signature.json` again; a crash between the two writes can still leave it. A run that ended `result_invalid` is not signed. A run that ended `fail` or `error` with a valid result is signed exactly as a `pass` is. Nothing is ever re-signed: the folder of a run ID can't be made twice and the writer replaces nothing.
   - **`worker_id`** is issued by the Cloud at registration and isn't needed in the result: the Cloud knows the Worker from its API token, C5.5 refuses a public key registered twice, and `key_id` names the key. If W5.1 wants it signed, it is one more nullable key of `result.v1.json` then, known before the run.

3. **The private key comes from `RP_SIGNING_KEY_BASE64` through the existing `load_secrets` seam, and the Signer only ever sees a parsed key.**
   - **The value** is one line of standard Base64 of the key's PKCS#8 DER (64 characters): the body line of the PEM that OpenSSL writes, the same kind of carrier as `RP_GRAPH_CERT_PFX_BASE64`. `Secrets` gains a fifth field, `signing_key_base64`, last; `kSecretEnvVars` has five names; `config check` prints one more masked line. W4.5 fills the same field from the vault's `signing_private_key`, and nothing in the Signer changes. The issue's step 1 is met only in part and #46 closes so: storing the key in the vault is W4.5's, generating it at install is W7.1's (see point 4 for today).
   - **`rp::SigningKey`** (`rp/signer.hpp`): move-only, the key behind an `Impl` as `graph::ClientCertificate` keeps its own. `SigningKey::from_base64(text)` takes strict Base64 of exactly 48 bytes that start with Ed25519's PKCS#8 prefix and hands the 32 bytes after it to `EVP_PKEY_new_raw_private_key`; anything else is refused. No ASN.1 reader is used, so OpenSSL makes no copy of the seed that can't be wiped, a key with bytes after it is refused by its length, and every refusal is a plain comparison a test reaches. `public_key_pem()`, `key_id()`, and `secret_shapes()`: the seed's Base64 and hex, the other shapes the key could leak in.
   - **Checked before anything is done, and only when it is needed.** With `--evidence`, the key is parsed right after the Graph certificate is checked: before the schema check, the manifest, the run mutex and any Veeam call. Not set: `config error: RP_SIGNING_KEY_BASE64 is not set; --evidence signs the result`; not a key: `config error: RP_SIGNING_KEY_BASE64 is not an Ed25519 private key (Base64 of PKCS#8 DER)`; exit 1, no run line. Every other command reads the variable with the other secrets, as today, and never parses or requires it.
   - **Wiped, and what that does not mean.** The decoded bytes are wiped as soon as the key is made. The pipeline takes the text out of `Secrets` (wiped there) before the connector is made, so the connector's copy of the secrets never holds it, and keeps it with the parsed key in one holder that wipes both on every way out of the run, the returns before the run line included. `EvidenceBuilder` wipes its copy of the secret values when it goes; `read_env` zeroes the buffer it reads every variable into. What stays: a `--record` recorder keeps its copy until its last check, as for every secret; and the process's own environment holds the variable until the process ends, which only W4.5's vault changes. The other three secrets stay unwiped for the run as today.
   - **Never logged, and one list of the run's secret values.** `rp::secret_values(const Secrets&)` in `rp/secrets.hpp` replaces `open_recording`'s loop and its copy in `write_evidence` (finding 8 of the W4.2 code review; the only one of 7 to 11 touched here). It gives each set value as it is (the Veeam password, the Graph PFX, its password, the signing key's text), never decodes and never throws, since with `--record` it runs for commands that never check the key. The run folder's list also gets the parsed key's `secret_shapes()`. `redact()` gains the key names `signing_key`, `signing_key_base64` and `signing_private_key` and masks a `-----BEGIN ... PRIVATE KEY-----` block. A sentinel test shows the key in no file of the folder, no fixture, no log line and neither stream.

4. **`rpworker test --evidence <dir>` always signs; `--json` stays unsigned; two read-only `signer` commands.**
   - No flag: a run folder that is complete and unsigned would be a second kind of folder for W4.6 and the Cloud to tell apart. `--json` writes the unsigned canonical result as today and needs no key: it is one file with no folder to hold a signature beside it, and it isn't covered by the result's secret check.
   - **Lines.** stdout, both only after `result.json` is written, the folder's line still last: `signed <bundle_sha256> key <key_id>`, then `evidence <folder>: result.json, signature.json, items.csv, veeam-session.log[, screenshot.png]`. stderr: `evidence error: <folder>: the result couldn't be signed; no result.json was written` (`EvidenceFailure::not_signed`) and `evidence error: <folder>\signature.json: could not be written`. Neither changes the status; exit 0 becomes 1 (the W3.6 rule), through the same path as every other evidence error.
   - **`rpworker signer public-key`** prints the SubjectPublicKeyInfo PEM of the key in `RP_SIGNING_KEY_BASE64` and `key <key_id>`: the issue's "public key exported as PEM for registration" (C5.5's `public_key_pem`). It never prints the private key.
   - **`rpworker signer verify <folder> --public-key <pem file>`** is the C++ verifier over a run folder, and what the Done-when runs: `verified <bundle_sha256> key <key_id>`, exit 0, or `not verified: <word>`, exit 5. `exit_code::restore`'s meaning widens from "the run's status is `fail`" to "the thing tested failed: a run's status `fail`, or a folder not verified". Exit 1 only when `<folder>` isn't a folder that can be opened or the key file can't be read or isn't an Ed25519 public key in PEM; anything wrong inside the folder, a missing file included, is a word and exit 5. A missing argument is 64. It needs no config and no secret.
   - **Making a key pair today.** No `rpworker` command prints a private key: before the vault its only way out would be stdout. For the lab, `python -m seeder new-signing-key` (in `lab/`, where `cryptography`, which is OpenSSL underneath, is locked) makes the pair, keeps the Base64 line in Windows Credential Manager and prints the public PEM and its `key_id`; `lab/entra/set-worker-env.ps1` puts it into the variable for one session, skips it with a notice when there is none, and clears it with the other two. No C++ `generate()` now: nothing would call it before W7.1, and what it makes needs a way into the vault that W4.5 defines.
   - **Files, and what is strict.** `src/signer.cpp` and `rp/signer.hpp` (strict): the hash, the key's parsing rules, the signature file's text and rules, the folder's checks in their order, the answers. It works over a small injected interface of the primitive (make a key from 32 bytes, sign, verify, the public key's DER) and reads the folder's files through a reader handed in, so a fake reaches every failure line and the 100% is of lines a test ran. `src/ed25519.cpp` (not strict): the real primitive, each function one checked call into OpenSSL, tested against RFC 8032's vectors. `src/signer_command.cpp` (strict by its name): the two commands, with no `catch (...)` of its own (`run_cli` already turns any escape into exit 1) and every verdict made in `signer.cpp`. `rp::sha256_bytes` joins `rp/sha256.hpp`. No new Worker dependency: OpenSSL::Crypto is linked already. **This is a choice the owner should see:** CLAUDE.md gives `src/signer/ed25519.cpp` as its example of a strict file, and here the calls into OpenSSL are in a file the gate doesn't hold to 100%, because their failure lines can't be reached. The alternative is everything in `signer.cpp` with each unreachable failure folded onto its call's own line, which passes the gate and hides the unexecuted branch. The floor is 100% line, not branch, as for the other strict files (OpenCppCoverage has no branch data).

5. **`shared/tools/verify_bundle.py` is one file, and it uses `cryptography`.**
   - **One file with PEP 723 inline dependencies** (`cryptography>=50,<51`, `jsonschema>=4.26,<5`, Python 3.12 or later): `uv run verify_bundle.py <folder> --public-key <pem file> [--schemas <dir>]`, the schemas by default from `../schemas` beside it; a schema that can't be found is exit 2, never a skipped check. Exit 0 `verified <bundle_sha256> key <key_id>`, 1 `not verified: <word>`, 2 usage, an unreadable folder, key or schema, or anything unexpected (`main` is wrapped, so a crash never reads as a verdict). The contract between the two verifiers is the stdout line; the exit codes are each tool's own (0, 5, 1, 64 in the Worker). No banned word ("verified", never "certified"). What an auditor needs is the script, the two schema files, the Worker's public PEM and the folder with every listed attachment; the first run downloads the two libraries.
   - **The canonicaliser** is in that file. `parse_strict(raw: bytes)` decodes strict UTF-8 itself (bytes are never handed to `json.loads`, which would take a BOM and UTF-16) and refuses a float, `NaN`/`Infinity` and a duplicate key through the parse hooks. `canonical_json(value) -> bytes` refuses an integer outside ±(2^53 − 1) (by `type(v) is int`: `True` is an `int` to `isinstance`), a key that isn't ASCII and a string with a lone surrogate, and gives the bytes of W4.1's one-line `json.dumps`. A refusal carries a slug and never the value: the vector file's three (`float`, `integer_out_of_range`, `non_ascii_key`) and, for what a vector's JSON text can't hold, `duplicate_key`, `not_json`, `invalid_utf8`, `too_deep`. `cloud/tests/test_canonical_json.py` moves onto it: the 33 cases byte for byte, the 9 rejects by their reason, the others built in the test.
   - **One rule for a file that isn't canonical, so the parsers' differences can't show.** `result_unreadable` means only that the file isn't there, can't be read or is over the size limit. Everything else that keeps the bytes from being the canonical form of a document is `result_not_canonical`, whichever parser notices it first and however: not UTF-8, a BOM, not JSON, `NaN`, a float, a number too large, a lone surrogate, a duplicate key, another key order, a trailing newline. Before either parser sees the bytes, both verifiers count the nesting outside strings and refuse more than 32 levels the same way (a result has far fewer), which is also what keeps the C++ verifier from a stack overflow. In C++ every `nlohmann::json::exception` is caught, not `parse_error` alone; in Python `ValueError`, `UnicodeError` and `RecursionError`. `signature.json` has the same rule under the one word `signature_file`.
   - **The order, first failure wins, one word:** `result_unreadable` → `result_not_canonical` → `result_schema` → `attachment_twice`, `screenshot_missing` (the two things the schema can't say: a name twice, `captured` without `screenshot.png` listed) → `signature_file` (not there, not canonical, or not its five keys and their shapes: every length, case and Base64 fault of `bundle_sha256`, `key_id` and `signature` is this word) → `hash_mismatch` → `wrong_key` → `signature_invalid` (64 well-formed bytes the library refuses under the caller's key, and nothing else) → per listed attachment `attachment_missing`, `attachment_size`, `attachment_hash`. The canonical form comes before the schema because Python's `integer` takes `1.0`. A file in the folder that the result doesn't list (W4.6's `manifest.json`, W4.4's token) is a `note:` line, never a failure. `rpworker signer verify` runs the same checks in the same order with the same words.
   - **`cryptography`,** because it is the only Ed25519 library already locked in the repository, it is OpenSSL underneath like the Worker, and W4.4 and C5.7 will want it for the token and the PEM. It goes into Cloud's dev group now, with `uv.lock`; `jsonschema` is there already. C5.7 moves both to Cloud's runtime dependencies and decides whether the Cloud loads this file or keeps its own copy held equal by the shared vectors.
   - **Where it is tested.** `cloud/tests/test_verify_bundle.py` loads the script by path, walking up to `shared/` as the schema tests do. The script is outside `--cov=app` and mutmut, so no gate holds its coverage; the test holds the set of words the vectors expect equal to the set the script can answer.

6. **Shared vectors in `shared/testdata/signing-v1/`, run by both builds; the Done-when on a live run's folder.**
   - **`keys.json`:** two fixed test key pairs, RFC 8032's tests 1 and 2 (published keys, named as such in the file): the seed in hex, `private_pkcs8_base64`, `public_key_pem`, `key_id`. JSON only, so the LF rule of `.gitattributes` covers the folder.
   - **`ed25519.json`:** RFC 8032 section 7.1's tests 1 to 3 (seed, public key, message, signature) for the primitive. Ed25519 is deterministic, so both builds must reproduce each signature byte for byte, not only accept it.
   - **`bundle.json`:** one signed folder as texts: `result.json`, `signature.json`, and two small made-up attachments with the hashes and sizes the result lists (the result is `result-v1/valid.json` with its `attachments` replaced, since that file's hashes are of files the repository doesn't hold). Written by a hidden `rptests "[.write_shared_signing]"`, which fails if the signature has neither `+` nor `/` (the URL-safe case needs one), and compared byte for byte by a Worker test. **`cases.json`:** each a replacement of one file's bytes (text or Base64: bytes that aren't canonical are the point, so no JSON patch), a removed file or another public key, with the one word expected. Each build writes the folder into a temp directory per case.
   - **The cases, failures first, each with its word.** `result_unreadable`: `result.json` removed. `result_not_canonical`: keys re-ordered, a trailing newline, a duplicate key, a BOM, a `1.0`, `NaN`, `1e400`, an escaped lone surrogate, a 5000-digit integer, 33 levels of nesting, bytes that aren't UTF-8, a file that isn't JSON. `result_schema`: a canonical result with an unknown `status`. `attachment_twice`, `screenshot_missing`: one case each. `signature_file`: `signature.json` removed, not JSON, re-ordered, with a sixth key; `bundle_sha256` in upper case; `key_id` in upper case; a `signature` of 63 bytes, in URL-safe Base64, without padding, with a non-zero pad bit. `hash_mismatch`: one digit of a hash in `expected.items` changed, and one in `check.items` (the issue's "one flipped byte in items"; the file stays canonical and valid). `wrong_key`: the second key's own signature and `key_id`, the first key given. `signature_invalid`: one bit of the signature changed, its shape kept; S replaced by S + L; the second key's signature under the first key's `key_id`; and the plain forgery, the result changed and `bundle_sha256` computed again. `attachment_missing`, `attachment_size`, `attachment_hash`: a file removed, cut short, one byte changed. Then the untouched folder, `verified`. Both builds must give the same word for every case, which is what "agree" means offline.
   - **Unit tests in the Worker beside them:** the sign and verify round trip, a document built in two key orders giving one hash, `sign` refusing text that isn't canonical, every refusal of `SigningKey::from_base64` (47 and 49 bytes, another prefix, an RSA key, bad Base64), the fake primitive failing at each call (`couldn't be signed`), the `signature.json` write refused, `result.json` refused after it (no `signature.json` left), a key unset or malformed stopping the run before its run line, and the sentinel test of point 3. TDD as the task says: the acceptance test from the Done-when first, each failure row seen red before its code.
   - **The Done-when, live.** A lab key made as in point 4; `rpworker test --mail 10 --sp 10 --od 10 --run-id w43-done-when-1 --point <id> --evidence %ProgramData%\RestoreProof\runs`; then on that folder `rpworker signer verify` and `verify_bundle.py` with the exported public PEM must print the same `verified <hash> key <id>` line, and `Get-FileHash result.json` that hash. Then on five copies of the folder both must print the same line each time: one digit of an item's hash in `result.json` changed (`hash_mismatch`); one Base64 character of `signature` changed, its shape kept (`signature_invalid`, the one copy where Ed25519 itself says no); one byte of `items.csv` changed (`attachment_hash`); `veeam-session.log` removed (`attachment_missing`); the test key's PEM given (`wrong_key`). Evidence `docs/api/veeam-lab/w4.3-live-*`: the run's output, both verifiers' lines for the six folders, `graph list` afterwards; the folder and the lab's public key stay outside the repository. It needs the owner's elevated shell and the new Credential Manager entry.

**Alternatives rejected.**
- *The signature fields inside `result.json`, required and `null` until signed:* five or six more top-level keys in every result, signed or not; a removed set of four (`bundle_sha256`, `signature`, `tsa_token`, `tsa_error`) against the contract's two; a hash over a document no file holds, so the file's SHA-256 is never `bundle_sha256` and every verifier hashes its own re-serialisation, where a duplicate key goes unseen in both languages; and a `result.json` that must be held back or written again when the TSA answers.
- *The same with the fields set to `null` instead of removed before hashing:* the hashed bytes are then the unsigned document, which is this entry's rule with the signature written into the file afterwards; it keeps the rewrite and the re-serialisation.
- *`signature.json` written last, after `result.json`:* the mark of a complete folder would move to another file, and a crash between the two would leave a result that reads as complete and unsigned.
- *`tsa_token` and `tsa_error` as two more keys of `signature.json`, `null` until W4.4:* W4.4's words fixed here before its design, and a file that would be written only after a network call that may take two minutes.
- *`Signer::sign` taking a JSON value:* the signer would hash its own serialisation, not the text that is written.
- *Signing the 64 hex characters:* an auditor could pipe `sha256sum`'s output, but case and a trailing newline would then be part of the message.
- *A verifier that re-canonicalises a re-ordered file and accepts it (Q4.1 as written):* it accepts bytes that were never signed.
- *Two words for a broken file, one for "not JSON" and one for "not canonical":* the two parsers draw that line in different places (the BOM, `NaN`, a lone surrogate), so the verifiers would disagree on the word.
- *Cutting `sample.*.random.keys` and keeping `expected.items[].key`:* removes a duplicate and no data, for three shared cases and a schema block. *Cutting both copies of the key:* a random item would be named by its subject or file name alone, W3.1 point 8 and seven shared cases would go, and a failed random item couldn't be traced to its mailbox or folder. *Keeping `containers_listed`:* names of containers the run never tested, under a signature for good.
- *The key read with OpenSSL's PKCS#8 reader:* a copy of the seed left in freed memory, and trailing bytes taken. *As PEM text:* line breaks in an environment variable. *As the bare 32-byte seed:* not what OpenSSL writes, and it says nothing of its own algorithm. *A key file named in `config.json`:* a secret on disk before the vault exists, and `config.json` refuses secret-looking keys.
- *A config key pinning the public key:* a second place to keep in step with the Cloud's registered key, which is what refuses a wrong key (C5.7).
- *A `--sign` flag, or signing `--json`:* two kinds of complete folder; a signature over bytes no secret check has seen.
- *`rpworker signer new-key`, or `openssl genpkey` from a lab script:* a private key on stdout; a tool that isn't on the lab machine's `PATH`.
- *Verifiers that refuse small-order public keys themselves:* a list of encodings to keep equal in two languages for a key that only the registering side can vouch for; left to C5.5 (Open).
- *PyNaCl:* in no lock file, and libsodium refuses small-order keys that OpenSSL takes, so the two verifiers could differ on a malformed key. *A uv project of its own under `shared/tools/`:* a third lock file and a fourth workflow for one script. *The verifier's logic under `cloud/app/`:* the auditor's file would need the repository. *The schemas copied into the script:* a second copy of the one schema.
- *A hidden test case as the C++ verifier of the Done-when:* "the C++ verifier" would be a test binary no installed Worker has. *The command file under a name the gate doesn't know (`signature_command.cpp`):* strictness avoided by a name.
- *A signed run folder committed as files:* a line-ending conversion on checkout would change the hashes; texts inside JSON don't have that risk.

**Open.**
- W4.4: its token's file name, where `tsa_error` goes, and the guide's wording (W4.4 steps 3 and 4, Q6.1's "the TSA token in the bundle").
- W4.8: a folder without `result.json` now has two more ways to come about (the signing failed; a crash between the two writes). Whatever result W4.8 writes for such a run must be signed too, a leftover `signature.json` removed first; and what is uploaded when the key itself is why nothing could be signed.
- The Cloud: C5.7's upload gains a `signature` part and its step 7 stores it; C5.7's step 3 if `worker_id` isn't in the result ("the token's Worker's key verifies the signature"); the folder's name against `run_id` and the job (a whole signed folder of another run copied in still verifies); C5.5 refusing a small-order public key; whether the Cloud loads `verify_bundle.py` or keeps a copy; C5.11's fixture bundle (`signing-v1/bundle.json` can serve). Issues #53 and #60 carry the old wording.
- The hand-over to an auditor (Sprint 8): where the public PEM comes from (C6.2 offers no key, C6.4 prints only fingerprints), `signature.json` and the attachments offered together, and a verifier that can run without a download.
- That OpenSSL 3.6.4 and the OpenSSL inside `cryptography`'s wheel (4.0.3 in 50.0.2) agree on every malformed signature. Measured alike: a flipped bit, S + L, a small-order key. The script's dependency is bounded to one major version, not pinned.
- A coverage floor for `verify_bundle.py`.
- The run folder's ACL (W4.5): until then another local user can remove or add a file in a run folder, also during the run, which ends such a run with an evidence error.
- From W4.2's code review: findings 7 and 9 to 11, and stdout and `--json` outside the secret check, all left as they are.
- W4.9's sentinel grep must not take the published test keys in `shared/testdata/signing-v1/` for a leak.
- No Worker CI run has started since 2026-10-03 (GitHub billing), so the strict gate on the signer files will be shown by the local coverage run only.

**Code, tests and docs with the build.** `rp/signer.hpp`, `src/signer.cpp`, `src/signer_command.cpp`, `src/ed25519.cpp`, `rp::sha256_bytes`; `Secrets::signing_key_base64`, `rp::secret_values` and its two callers, `secrets.cpp`, `config.cpp`'s list of names, `config_check.cpp`; `redact()`; `EvidenceBuilder::write_result`, `EvidenceOptions` (the signer as a seam) and `EvidenceFailure::not_signed`, `run_pipeline.cpp`, `test_command.cpp`, `cli.cpp`, `rp/cli.hpp` (`kCliUsage`, exit 5's meaning) and CMake's `RP_USAGE`; `sample_selector.cpp` (`containers_drawn`); `shared/schemas/result.v1.json` (point 1, and the `attachments` description) and the new `shared/schemas/signature.v1.json`; `shared/testdata/result-v1/valid.json` and `cases.json`, `shared/testdata/signing-v1/`; `shared/tools/verify_bundle.py`, `cloud/tests/test_verify_bundle.py`, `cloud/tests/test_canonical_json.py`, `cryptography` in Cloud's dev group with `uv.lock`; `lab/seeder` (`new-signing-key`) with its test and `lab/entra/set-worker-env.ps1`. Tests: `tests/signer_test.cpp`, `tests/ed25519_test.cpp`, `tests/signer_command_test.cpp` and exe tests, `tests/secrets_test.cpp`, `tests/config_test.cpp`, `tests/config_check_test.cpp`, `tests/redact_test.cpp`, `tests/evidence_builder_test.cpp`, `tests/test_command_test.cpp` (`[evidence]`: the Harness's default key, the folder's file set and its two last lines), `tests/sample_selector_test.cpp`, `tests/result_lab.hpp`, `tests/result_schema_test.cpp`. Docs: `docs/verification.md` (a new "The signature"; "The result", "The run folder" and "What of the tenant the result holds" where they speak of the signature fields, the file list, the order of writing, the secret values and `containers_listed`), `docs/worker-config.md` (the variable, the two commands, the lines, exit 5, "`--json` is never signed"), `docs/testing.md` (the vectors, the folder's line, the Python canonical test, the live run), `docs/glossary.md` (evidence bundle, run folder, signing key, `tsa_token`), `lab/README.md`, CLAUDE.md (the signing contract, the redacted names, the commands, the pipeline line, W4.1's and W4.2's open points). The PR closes #46.

---

## 2026-10-05 — W4.2 code review: six fixes on the branch (proposed)

The code review of PR #157 (2026-10-05) gave eleven findings. The first six are fixed here, each with a test that was seen to fail on the branch as it stood; the other five are duplication and efficiency cleanups and are left. This entry supersedes the build notes below where they differ (points 5, 6 and 8).

1. **A result that holds a secret value is not written.** The secret layer withheld a CSV row or a log line, and `result.json` went into the same folder unchecked with the same subject or file name in `expected.items`: the test run showed the Veeam password in `result.json` beside a withheld row. The result can't be cut the way a row can (it is validated, hashed and, from W4.3, signed as it is, and a subject replaced by fixed words would be an expectation the run never had). So `EvidenceBuilder::write_result` first looks through every string of the canonical text, parsed back, for the run's secret values, and refuses one that holds any: `EvidenceFailure::holds_secret`, one `SECURITY: evidence: the result held a secret value; no result.json was written` log line, and `evidence error: <folder>: the result holds a secret value; no result.json was written` on stderr, the status unchanged, exit 0 becoming 1. The strings and not the text: a secret with a `"` or a `\` in it is escaped there. Keys and numbers are not looked at (the schema's own words, never tenant text). The two text files stay. Its limit is build note 8's, now with more weight: the match is on the whole value, so a secret that is a word of the result (`pass`, `mail`) would stop every run's `result.json`. Rejected: replacing the name in the result (a result that says something the run didn't expect, under a signature), and a minimum length for a secret (a short password would then pass unseen). (`evidence_builder_test.cpp`, "a result that holds a secret value is never written, and said once"; `test_command_test.cpp`, "a result that holds a secret value is never written".)
2. **The too-deep run folder test no longer depends on the temp folder's length.** It built a folder path of 215 to 239 characters and the probe only fails from 221 (the folder, `\veeam-session.log` and the temp's 21 characters over 259), so it failed for a `TEMP` of some lengths; the reviewer saw it fail three times of three with one of 128 characters. It now builds a folder of exactly 230 characters, and passes under temp folders of 7, 20, 128, 129, 150 and 170 characters.
3. **A screenshot is read whole or it is no screenshot.** `capture` checked the 10 MiB cap against the file's listed size and then hashed whatever a character-wise read returned, and the read's `bad()` check could never fire: a read that stopped short was taken for the whole file (the test, a PNG whose second half another handle holds locked, got `captured` with half a picture), and a file still growing could pass the cap. `read_file` now takes the size, reads exactly that many bytes in one call and requires the end of the file right after them, under a limit: `kMaxScreenshotBytes` for the capture, the listed size for `write_result`'s read back. Anything else is no file: `failed` for a screenshot, `changed after it was hashed` for an attachment. (`evidence_builder_test.cpp`, "a screenshot that can't be read whole".)
4. **A refused run folder leaves nothing, the root's new levels included.** `make_run_folder` made every missing level of the runs root, and on a refusal removed the run folder alone while the run said `nothing was done`. It now notes which levels weren't there before it makes them and takes them away again on anything but `ok`, deepest first, each only while empty.
5. **No capturer for a run with no restore session: `no_page`.** The capturer was asked whenever the run had a valid result, with an empty list of session IDs for a run that stopped before its restore; the test's capturer got `captured` and a listed `screenshot.png` for a run that restored nothing. `capture` now answers `no_page` itself when there is no restore result or it names no session: no page shows a session that doesn't exist. Rejected: a new reason `no_session`, a schema change for a case the existing word covers.
6. **The folder's lifetime is its own (`rp::RunFolder`).** "A run without its run line leaves no folder" rested on one special case in `stopped()`, and any later early return between the folder and the run line would have left an empty folder that refuses the next run with that ID. `make_run_folder` now fills an `rp::RunFolder`, which removes what was made (point 4's levels too) when it goes, unless `keep()` was called; the pipeline keeps it once the run line is out and only then has an `evidence_folder`. The special case is gone. (`evidence_builder_test.cpp`, "a run folder that isn't kept is taken away again"; `test_command_test.cpp`, "a run whose run line can't be printed leaves no folder", which now also finds no runs root.)

**Left as they are.** Findings 7 to 11: `verdict_cells` beside `test_command.cpp`'s `verdict_cell`, the list of secret values copied from `open_recording` (to be one function when W4.5's vault adds a secret), `write_evidence`'s copy of the finished-result block, the withheld row's two constants, and the screenshot hashed twice (point 3 made each read one call). Also not covered by point 1: stdout, where `rpworker test`'s table shows each item's name as it is, and `--json`, which writes the result to a file the operator names; neither is the folder that W4.6 uploads.

`ctest --preset dev` on 2026-10-05: 1351 of 1351 passed (ten live tests skipped); seven new test cases. The coverage run and the live Done-when run were not repeated.

---

## 2026-10-05 — W4.2 build notes: what the build and its two reviews settled beyond the approved entry (proposed)

The build follows the W4.2 entry below. Two reviews of the branch (2026-10-05, one of the code, one of the tests and of the code against the entry) found no fault in the guard or the status; what they found is in points 4 to 9. Where the entry was silent or the build departs from its words:

1. **The capturer is handed the path, and answers "captured" or a reason.** The entry said it answers a PNG's path. It is given `<run folder>\screenshot.png` and can name no other file. An answer of `disabled` (the builder's own word) or of a value outside the enum is `failed`. Whatever an unavailable screenshot left at the path, a folder with files in it included, is removed.
2. **Two messages the entry doesn't have.** `config error: --evidence <dir>: not a UTF-8 path`, and for a run ID the run made itself that can't name a folder, `evidence error: the run ID can't name a folder; nothing was done` (`make_run_id`'s always can; only a test's reaches it).
3. **"Nothing was done" means nothing restored, deleted or written.** The run ID is known only after the restore points are listed, so by then the run mutex is taken, a `--record` folder is open and Veeam has answered one read. Not checked earlier for a `--run-id` that is given: one message at one place.
4. **The folder is tried for the writer before the restore.** `make_run_folder` makes the atomic writer's own temp file for the longest name the folder will hold (`veeam-session.log`) and drops the folder if it can't: `couldn't be made`. A root so deep that the folder can be made (under 248 characters) but no file written in it (over 259 with the temp's 21) was otherwise found after the restore. (`evidence_builder_test.cpp`, "a run folder too deep for the writer's own temp name".)
5. **A run that ends before its run line leaves no folder.** The folder is made before the run line is printed; when that line can't be printed the run has no status and no evidence step, and its empty folder would have refused the next run with the same ID. It is removed (only an empty one can be). (`test_command_test.cpp`, "a run whose run line can't be printed leaves no folder".)
6. **No screenshot for a run with no valid result.** The capturer isn't asked when the run ended `result_invalid` or has no verdict: a PNG no result lists would stay in the folder. A finished result that turns out invalid after a capture can still leave one; no test reaches it but through the wall clock.
7. **A canary mail found by its subject alone gets no found hash.** The check falls back to the subject when no copy has the canary's Internet message ID; such a copy may be a real mail of that subject, and its body's hash is what point 5 keeps out. `found_sha256` is set for a mail only when the message ID agrees. (`checker_test.cpp`, "found_sha256 is the compared copy's hash".)
8. **The secret layer, and its limits.** A cell is looked at as given and as written (a control character becomes a space in the file). A withheld CSV row keeps its `index` and its sixteen columns, with the fixed words as `name`, every other cell empty, `verdict` too. The match is on the whole value, so three things it doesn't catch or overdoes: the connector cuts a line at 500 bytes before the builder sees it, so the Base64 PFX can never be there whole and a cut part isn't recognised; a secret Veeam re-encodes isn't; and a password of a few characters would withhold lines that merely hold those letters. The count is in the `SECURITY:` log line, not on stderr.
9. **The folder's line is in the entry's order** (`result.json, items.csv, veeam-session.log[, screenshot.png]`); `attachments` in the result is sorted by name. The first build printed the sorted order.
10. **What the schema can't say is pinned as such.** Two shared cases are valid on purpose: one name twice in `attachments`, and `captured` without `screenshot.png` among them. The builder makes neither (`evidence_builder_test.cpp`, "the attachments' names are in order and each is there once"); C5.7 must check both itself, with each attachment's hash. Also unsaid by the schema: `attachments` `null` with a `screenshot` object, and the reverse.
11. **`valid.json` is an `--evidence` run's `result.json`.** Its two attachment hashes are of the Harness run's own files and stay as they are when the lab's names are replaced in the document, as the canaries' hashes do. `cases.json` has 180 patches, 45 valid (22 new: 6 valid, 16 invalid). Python's validator agrees with the C++ one on all of them.
12. **The config's first boolean.** `screenshots_enabled` takes JSON's `true` or `false` only (`"true"`, `1` and `null` are refused: `config key "screenshots_enabled" must be true or false`), read after `veeam_cert_sha256`; `config check` prints it.
13. **Not reached by a test.** Through the pipeline: a run with no verdict under `--evidence` (as W4.1's build note 15), `write_evidence`'s `error: unexpected failure`, stdout lost at the folder's line or before it (the files are written, the line isn't), `--evidence` with `--record`, and `changed` for `screenshot.png` (the text files' is tested). In the builder: the catch blocks around `noexcept` functions, where the one in `write_attachments` would name `items.csv` whatever threw. `--record <dir>` and `--evidence <dir>` on one folder with a run ID of `veeam`, `graph` or `download` aren't refused.
14. **Left as they are.** A formula guard for the full-width `＝ ＋ － ＠` (the ASCII four are guarded); a minimum length for a secret (point 8); an early look for an existing folder when `--run-id` is given (point 3).
15. **How it was built.** The acceptance test and the failure-path tests were written with the builder, before its first build, not one red-green step at a time: the build was held by the config key's own work, done test-first by a sub-agent (red seen, then green). The review fixes of points 4 to 9 were each written with their test and built together. Five sub-agents investigated before the entry (the guide, the pipeline, the data, the schema, the screenshot), one built the config key, two reviewed.
16. **Coverage, run locally on 2026-10-05** (`worker/tools/run_coverage.ps1`, then the gate, PowerShell 7): the gate passes, exit 0. 97.3% line overall (9794 of 10065); the strict files all 100% (`cleaner.cpp` 202 of 202, `run_status.cpp` 415 of 415, `target_guard.cpp` 73 of 73, `target_guard_graph.cpp` 117 of 117, `target_guard_veeam.cpp` 315 of 315); `evidence_builder.cpp` 219 of 239 (91.6%, not strict: point 13's catch blocks), `run_pipeline.cpp` 710 of 753, `checker.cpp` 302 of 304; every `.cpp` present. `ctest --preset dev`: 1344 of 1344 passed (ten live tests skipped); Cloud's `uv run pytest`: 253 passed. CI has still not run: no Worker workflow has started since 2026-10-03 (GitHub billing).
17. **The Done-when run, live on 2026-10-05 (09:18Z).** `rpworker test --mail 10 --sp 10 --od 10 --run-id w42-done-when-1 --point <id> --evidence %ProgramData%\RestoreProof\runs`, elevated, on the 2026-10-03T16:16:54.0154727Z restore point: 30 of 30 restored in four `Success` sessions, `status pass: 30 of 30 item(s) verified: manifest 15, fields 5, metadata 10`, `cleanup after ok`, then `evidence C:\ProgramData\RestoreProof\runs\w42-done-when-1: result.json, items.csv, veeam-session.log`, exit 0, stderr empty, `graph list` 0 in all three targets afterwards. The folder: `result.json` 22,606 bytes, seventeen keys, valid by Python's `Draft202012Validator` against `shared/schemas/result.v1.json` and its own canonical form; `items.csv` 5,746 bytes, 30 rows, a found hash in the 15 canary rows and equal to the expected one in each; `veeam-session.log` 7,371 bytes, 34 lines, none withheld; both with the size and SHA-256 the result lists, and no other file. `screenshot` is `unavailable` / `disabled` (the lab config doesn't set the key): no PNG, and none could have been taken. Evidence `docs/api/veeam-lab/w4.2-live-*` (the run's output, `graph list` afterwards, the folder's check); the folder itself stays under `%ProgramData%`, outside the repository.

---

## 2026-10-05 — W4.2: the run folder, its attachments and the screenshot (recorded before the build; the owner approved it as written)

W4.2 (#45) makes the run folder: `result.json`, `veeam-session.log`, `items.csv` and, optionally, a PNG, each attachment hashed in the result. This entry works from the Sprint Task Guide (W4.2 to W4.9, C5.2, C5.6, C5.7, C7.2, C7.3, Q7.3), the W4.1 entry below and its Open points. Plan section 9, which the issue points at, is not in the repository.

What the investigation found, since the points below rest on it:

- `connector::RestoreResult::log` is one line per session (`session <id> (<kind>): <result>, <details>`) and one per restore event (`<status> <itemName>: <message>`), each through `one_line` (controls to spaces, 500 bytes) and `redact()`. Nothing reads it today. Veeam's message names the item, its source folder or path, the mailbox's display name and the target's address or URL (`... (type: IPM.Note; source: Alice Test\Inbox; target: restoretest@...\Inbox)`); a failure's message is free text.
- A found value doesn't outlive the check: `ItemCheck` keeps only the compared copy's Graph ID, and the read back (`TargetsRead after`) is gone before `finish`. A found SHA-256 exists for every mail in the target (its body, `text-v1`) and for the files `hash_filter` downloads.
- The only Veeam web page that shows a restore session is the Restore Portal, served by the REST service (`https://localhost:4443` in the lab). It signs in through Microsoft's interactive page (password, MFA), and the REST certificate is self-signed with no SAN, which Edge shows as a certificate error unless verification is turned off. `msedge.exe` 154 and the WebView2 runtime are on the dev laptop, and `msedge --headless=new --screenshot` of `about:blank` wrote a PNG in 3 s (interactive session; session 0 untried). Whether the portal would list a restore the admin account started through REST is unknown.
- A run ID may be `.`, `..`, `CON`, `a:b` or differ from another only in case (`check_run_id`); none of these can name a folder of its own on NTFS.

**Decision.**

1. **`attachments` is an array of `{name, sha256, size_bytes}`, and `result.json` is not in it.** One entry per file beside `result.json` in the run folder, sorted by `name`. `name` is an enum: `items.csv`, `screenshot.png`, `veeam-session.log`. `sha256` is the file's bytes (64 lower-case hex), `size_bytes` their count (C7.2 caps an attachment at 25 MB, and a size is the cheapest check before a hash). A file can't hold its own hash; `result.json` is covered by W4.3's `bundle_sha256`, and through `attachments` the signature then covers the other files. `attachments` is `null` when no run folder is written (`rpworker restore`, `test` without `--evidence`, and the result as it is first validated, point 5 of W4.1), an array of two or three otherwise. The two text files are always written, also for a run that restored nothing (the log is then empty, the CSV its header alone), so a folder has one shape. The keyword subset can't say "each name once"; a test does.

2. **`screenshot` is an object, `null` when no run folder is written.** Either `{"state": "captured"}`, and then `screenshot.png` is among the attachments, or `{"state": "unavailable", "reason": <code>}` with `reason` one of `disabled` (the flag is off), `no_page` (no page shows the session without an interactive sign-in), `no_browser`, `login_required`, `timeout`, `failed`. The guide's `screenshot: "unavailable"` is `state`; the reason is added because "the client switched it off" and "it couldn't be done" are different facts on a dashboard. That makes seventeen top-level keys, all always present.

3. **The screenshot is a seam now, and the default capturer answers `unavailable` / `no_page` without starting a browser.** The page needs an interactive sign-in, and Edge can't be given the Worker's CA file and pin, so a real attempt would end `unavailable` on every run, after starting the first child process the Worker ever starts. What is built: `screenshots_enabled`, the schema key, an injectable capturer (`std::function`, given the folder and the sessions' IDs, answering a PNG's path or a reason), and the builder's handling of its answer, all tested with fake capturers: off means the capturer isn't called (`disabled`); a capturer that throws, or names a file that isn't there, doesn't start with the PNG signature or is over 10 MiB, is `failed`; `timeout`, `no_browser` and `login_required` pass through. A screenshot never changes the status, a warning or the exit code. Bounding a real browser (a job object, a deadline) belongs to the capturer that starts one. Rejected: rendering the session's JSON to a local page and photographing it. That is the Worker's picture of its own data under Veeam's name, and proves nothing the log doesn't.

4. **`screenshots_enabled` is an optional boolean config key, default `false`.** It is a per-client setting (C5.2, C5.6, C7.3), and `config.json`'s client keys are the CLI's local profile (2026-09-29, "Clients live in the Cloud"); a job's value replaces it when jobs exist (W4.8). The config's first boolean: anything but `true` or `false` is `config key "screenshots_enabled" must be true or false`. Off by default, since a picture can't be passed through `redact()`.

5. **`items.csv`: one row per expected item, the hashes of canaries only, no Veeam message.** Columns: `index`, `type`, `source` (`canary`/`random`), `canary_id`, `name` (the expected subject or file name), `expected_kind`, `sha256_rule`, `expected_sha256`, `found_sha256`, `restore_outcome`, `found`, `outcome`, `mismatches`, `verdict` (`verified`/`failed`/`unchecked`/`-`), `code`, `ms`.
   - **Found hashes, for `manifest` items only.** `found_sha256` is filled where the expectation carries a hash and a copy of this run was compared, by that expectation's rule. A canary's content is ours, so its hash says nothing about the tenant, and it is what "with hashes" can honestly mean: a random mail is checked by its fields and a random file by its metadata, neither by a hash. The SHA-256 of a real mail's body is never written, though the read back computes it: a short body can be confirmed from its hash. `ItemCheck` gains `found_sha256` for this, set by the checker and never written by `to_json`; the result still holds no found value (W3.2 stands).
   - **Tenant names: the ones the result already holds.** `name` is `expected.items[].subject`/`name`. No found subject, sender, time or Graph ID, no key, no container.
   - **Format.** UTF-8 without a BOM, LF, a header row, every text cell in double quotes with `"` doubled, control characters as spaces. A `name` starting with `=`, `+`, `-` or `@` gets a leading `'`, so a subject can't run as a formula when an auditor opens the file. The CSV's `name` is therefore for reading; the exact one is the result's, joined by `index`.

6. **`veeam-session.log` is `RestoreResult::log` as the connector made it: Veeam's own words, tenant names included.** This is the one file of the bundle that says what Veeam said, and a failure's free text is what an MSP needs to see and what the result withholds. What it names concerns the sampled items and the restore targets only, the classes of data the result already carries (subjects and names in `expected.items`, mailboxes and folder paths in `sample.*.random.keys`, the target mailbox in `client`). The rule "no Veeam message in the result" stays: the result's strings feed the status line, the dashboard and the report; the log is an attachment someone downloads on purpose (C6.2, with an audit row). Q7.3's promise holds: no mail body, no file content. Empty when there is no restore result, also when `restore_sample` threw after a session ran (its lines are lost with it, as today).
   - **`redact()`, and a second layer.** Every line has been through `redact()` in the connector, which masks keyed secrets, JWTs and `Bearer` tokens but not a bare secret in prose. So the builder is also handed the run's secret values (the Veeam password, the Graph PFX and its password) and replaces any log line or CSV row holding one with fixed words (`[withheld: held a secret value]`), with one `SECURITY:` log line. The per-run PFX password never leaves the connector, which wipes it. W4.9's sentinel test then checks this layer too.

7. **`rpworker test --evidence <dir>` writes the folder `<dir>\<run_id>\`; nothing is written without it.** `<dir>` is the runs root, made if it isn't there. The CLI has no default: the service passes `%ProgramData%\RestoreProof\runs` (W4.8), and the live run names it. Not every run, because a `test` run by hand would then need write access to `%ProgramData%`, and `--json` alone keeps doing what W4.1 fixed. `--json` stays and can't be combined with `--evidence` (usage, exit 64): `result.json` is that file, and two flags would need a rule for one written and the other not. `restore` gets neither.

8. **A run ID that can't name a folder, and a folder that is already there, stop the run before anything is done.** With `--evidence`, a `--run-id` that isn't a plain file name (`rp::is_plain_file_name`: `:`, a trailing `.`, `.`/`..`, a DOS device's name) is `config error: --evidence: the run ID can't name a folder`, exit 1, checked with the config and before the secrets. It isn't encoded: the folder's name is the run ID, which W4.6 and W4.8 look up. `check_run_id` keeps `:` (run IDs seed the sample; existing IDs stay valid); W4.8 needs the same rule for a job's `run_id`. The folder is made with one `CreateDirectoryW` when the run ID is known, before the run line, the clean before and the restore. If it exists (another case of the same letters included) or can't be made: `evidence error: <folder>: the run folder already exists; nothing was done` (or `couldn't be made`), exit 1, no run line. Never written into, never replaced. So every run with a run line has its folder from the start.

9. **`result.json` is written last, and only a valid result.** At the end of the run (after the clean after and the timings, where W4.1 builds the finished result): write the two text files with the atomic writer, ask the capturer, hash what was written, build and validate the result with `attachments` and `screenshot`, read each attachment back and compare it with its hash, then write `result.json` as the canonical bytes. Then one stdout line, `evidence <folder>: result.json, items.csv, veeam-session.log[, screenshot.png]`.
   - **A file that can't be written, or an attachment missing or changed between its hash and `result.json`:** `evidence error: <file>: could not be written` (or `changed after it was hashed`), no `result.json`, the status unchanged, exit 0 becomes 1 (the W3.6 rule).
   - **`result_invalid`, and a run with no verdict:** the folder holds the log and the CSV as far as they could be written, and no `result.json`; stderr gets `evidence error: <folder>: the result isn't valid restoreproof.result.v1; no result.json was written`. W4.1's rule stands: no invalid result under this format, no cut-down one.
   - So `result.json` there means the folder is complete, and a folder without it is a run with no result: `result_invalid`, no verdict, a failed write or a crash. What the service tells the Cloud for such a run is W4.8's, with `interrupted`: both need a result for a run that has none, and so does the run that ends before its run line (W3.3 build note 8).

10. **The W4.1 Open point on `random.keys` and `containers_listed` stays open, but its deadline moves to W4.3.** W4.2 uploads nothing and adds nothing to it: neither new file names a key or a container. But a signed result is never edited or re-signed, so what W4.3 signs is what W4.6 uploads; the cut, if there is one, must be made before the first signature, not before the first upload. My lean, not decided here: cut `containers_listed` to a count (it names containers the run looked into and didn't test), keep the keys (they are the sampled items, and what lets a draw be repeated).

**Alternatives rejected.**
- *The log cut to Veeam's words (`veeam_words`: item names, addresses, paths and quoted parts removed):* nothing of the tenant beyond the result would leave, but the lines read `Success : Item  was restored successfully (type: File; )`, and a failure's text loses the part that says what failed. If the owner prefers it, the uncut log could stay in the folder under a name `attachments` doesn't list and W4.6 doesn't upload.
- *Found hashes for every hashed item:* a confirmation oracle for real mail bodies.
- *`found_sha256` in the result:* against W3.2 and W4.1 ("found values are never written"); C5.2's `test_item.found_sha256` can be read from `items.csv` or left empty (W4.1's third Open point, C5.7).
- *`result.json` listed in `attachments` with a hash of itself less that field:* a second hashing rule beside `bundle_sha256`.
- *Encoding the run ID into a folder name:* two names for one run, and `.`, `CON` and case still need a rule.
- *Writing into, or replacing, a folder that exists:* a run's evidence mixed with another's.
- *Building the capture with `msedge --headless`:* a child process, a browser profile and a deadline to maintain, for an answer that is `unavailable` on every server until Veeam offers a page without an interactive sign-in. *WebView2 in the Worker's process:* a browser engine beside the secrets, and unsupported in session 0.
- *A `--screenshots` flag instead of the config key:* the setting is the client's, not the run's.

**Open.**
- The run folder's ACL. Until W4.5 and the installer set it, the folder has what its parent gives (under `%ProgramData%` any local user can add a file). The hashes in the result are what holds the attachments; nothing holds an unsigned `result.json` before W4.3.
- What the service reports for a folder without `result.json` (W4.8, point 9).
- `random.keys` and `containers_listed` (point 10), and W4.1's other two Open points, unchanged.
- A real capturer, when a page exists that can be captured without an interactive sign-in and without turning certificate checks off.

**Code, tests and docs with the build.** `rp/evidence_builder.hpp` and `src/evidence_builder.cpp` (`rp::EvidenceBuilder`: the pure `items_csv` and `session_log`, the folder, the attachments, the capturer's answer, `result.json`), `ItemCheck::found_sha256`, `ResultParts` and `ResultBuilder` (two keys), `shared/schemas/result.v1.json` with an enum test for the attachment names and the screenshot's states and reasons, `run_pipeline.cpp`, `test_command.cpp` (`--evidence`), `config.cpp` (`screenshots_enabled`). Tests first, failure paths before happy ones: the folder exists, the run ID can't name a folder, the root or a file can't be written, an attachment missing or changed after hashing, a capturer that throws, times out or hands back something that isn't a PNG, a secret value in a log line, a formula-shaped subject, `result_invalid` and no verdict; then the acceptance test: a whole Harness run whose folder holds the files, each with the hash and size the result lists. `shared/testdata/result-v1/valid.json` written again (an evidence run, so it holds real attachments) and new cases in `cases.json`; the counts follow. Docs: `docs/verification.md`, `docs/worker-config.md`, `docs/testing.md`, `docs/glossary.md`, CLAUDE.md. The live run's folder stays outside the repository; `docs/api/veeam-lab/w4.2-live-*` gets the run's output and the folder's listing with sizes and hashes.

---

## 2026-10-05 — W4.1 code review: four fixes on the branch (proposed)

The code review of the W4.1 branch (2026-10-05) gave fourteen findings. Four are fixed here, with tests; the other ten are left as they are (design and cleanup, two of them against points approved as written).

1. **`embed_bytes.cmake` wrote its back-references as `\1`.** That is no CMake escape. It worked only because a `-P` script that declares no minimum version runs under the old policy (CMP0010 unset: a warning on every regeneration); under the project's own minimum it is an error and no file is written. Now `\\1`, and the script declares `cmake_minimum_required(VERSION 3.25)` itself, so it is read as the project is. Run again with VS's CMake 3.30.5: no warning, and the generated file is byte for byte the one the build had. `result_schema_test.cpp`, "the embedded result schema is the file's bytes", is its test.
2. **Why office-v1 refused a package is said on stderr.** W4.1 point 7 took the reader's text out of `reason`, and it then reached nothing: a refusal by one of the reader's own limits read the same as a broken file. `read_after` now prints, per refused file, `check note: <sharepoint|onedrive> <name>: not valid office-v1 input: <text>` on stderr, through `redact()`. Point 7 stands: stdout and the result hold the fixed words only. (`test_command_test.cpp`, "an Office file that isn't a valid package".)
3. **A lost `wrote <file>` line changes nothing, for a stream that throws too.** W4.1 had made an end-of-run hook that throws turn exit 0 into 1 with nothing on stderr, and the only way there was the hook's own `wrote` line on a stream set to throw. `std::cout` doesn't throw, so the same lost line exited 0 in production: against the W3.6 review's point 4 on one kind of stream and with it on the other. The hook now catches what that write throws, and both exit as before the hook ran. A hook that throws for another reason gets `error: unexpected failure` on stderr before 0 becomes 1; no test reaches that. Rejected: making a lost `wrote` line exit 1, which would overturn point 4 and leave the timings' table as the one lost line that changes nothing. (`test_command_test.cpp`, "a `wrote` line that can't be written changes nothing".)
4. **The validator is loaded before anything is restored, and a failed load isn't kept.** It was first built inside `finish`, after the restore, and a failure was kept in a function static for the life of the process and reported as `1 schema violation(s)`. Now `rp::result_schema_ready()` is asked after the config, the secrets and the sample sizes and before the manifest, the mutex and any Veeam call (`RestoreCommandEnv::result_schema_ready`, null = the real one): false is `error: the result schema couldn't be loaded; nothing was done`, exit 1, no run line. A loaded validator is kept; a failed load is tried again on the next call. `validate_result` still answers a schema it can't load with one violation and no place (build notes point 5), which a run now reaches only if the load fails between the two calls. (`restore_command_test.cpp`, "a result schema that can't be loaded"; `result_schema_test.cpp`, "the embedded result schema loads into a validator". The failing load itself still has no test: build notes point 15.)

---

## 2026-10-04 — W4.1 build notes: what the build settled beyond the approved entry (proposed)

The build follows the W4.1 entry below: the fifteen keys, the embedded schema and its keyword subset, `canonical-json-v1` and its refusals, `result_invalid` and when it is decided, the `client` object, the fixed `reason`. What it adds or settles where the entry was silent:

1. **The canonical form refuses one thing more, and its messages are fixed.** A `nlohmann::json` value that is binary or discarded is `canonical-json-v1: a value that isn't JSON`. The other four refusals read `... a floating-point number`, `... an integer outside +-(2^53 - 1)`, `... an object key that isn't ASCII` and `... a string that isn't valid UTF-8`; none carries the value, the key or a position. A key with invalid UTF-8 is refused by the key rule. `rp::canonical_sha256` is there too. (`tests/canonical_json_test.cpp`, "a refusal never carries the value or the key".)
2. **The vector file's refusals carry a slug, not the C++ text.** `rejects[].reason` is `float`, `integer_out_of_range` or `non_ascii_key`, so W4.3's Python canonicaliser can use the same words; the C++ test maps each to its message. The file has 33 cases and 9 rejects, pinned by name on both sides. One case the vectors can't hold: an integer too large for 64 bits (`1e20` written as digits) is a float to `nlohmann::json` and refused as one, where Python would call it out of range. Both refuse. (`canonical_json_test.cpp`, "the canonical-json-v1 vector file names every required case and reject"; `cloud/tests/test_canonical_json.py`.)
3. **What a violation count counts, and where the first one is.** `ResultValidation::violations` is the validator's top-level errors. When a `oneOf` fails, the library (2.4.0) also says why each branch failed, on lines starting `[combination: `; those aren't counted, but they are read for one thing: without them every violation inside a nullable section would be reported at `/expected` or `/check`, so the first violation's pointer is refined to the deepest place its branch lines name. One wrong value can still count twice (a number as `run_id`: its `type` and its `not`). Only that prefix of a message is ever read; no message and no instance is kept. (`tests/result_schema_test.cpp`, "validate_result names where, never what".)
4. **The pointer rule is stricter than point 5's.** A pointer is printed only when every part is a property name that occurs in the embedded schema, or digits; otherwise the line is `result error: <n> schema violation(s)` with no place. The library reports an unknown key at its parent object, so a key the schema doesn't know never reaches a pointer. (`result_schema_test.cpp`, "a pointer is kept only when the schema knows each of its parts".)
5. **Three causes, three stderr lines.** `ResultBuilder::build` returns a `ResultError` with `cause` `build_failed` (a part's `to_json` threw, or no verdict), `not_canonical` (the canonical form refused: a string that isn't UTF-8 from Veeam or the tenant) or `schema`. The lines are `result error: the result couldn't be built`, `result error: the result has no canonical form` and `result error: <n> schema violation(s)[, first at <pointer>]`. A validator that can't load its embedded schema, or throws, is one violation with no place. (`tests/result_builder_test.cpp`; `tests/test_command_test.cpp`, the `result_invalid` table's non-UTF-8 row.)
6. **`result_invalid()` repeats a code only when the table holds it.** `... the run itself ended error <code>` for a code in `error_codes()`, else `... ended error`. `decide_status` only gives table codes, so this guards a hand-built verdict; no text from outside the table reaches the status line. Neither `result_invalid` nor `restore_contradiction` can be a stop's code or a check item's: as one, it is row 1's `internal`. (`tests/run_status_test.cpp`, V1 to V7 and "result_invalid's message holds only the status's own words".)
7. **A third public list.** Beside `error_codes()` and `warning_codes()`, `unchecked_item_codes()` gives the codes an unchecked item can carry, most severe first; row 7's message uses it, and the schema's `unchecked_items[].error_code` enum is held to it. (`run_status_test.cpp`, "the public lists of error, unchecked-item and warning codes"; `result_schema_test.cpp`, "the result schema's enums are the code's words".)
8. **The second validation says why, too.** When the finished result fails at the end, stderr gets the `result error: ...` line and then the `json error: ... no file was written` line; the entry named only the second. (`test_command_test.cpp`, "a result that is valid when the status is decided and isn't at the end".)
9. **The schema holds `expected.items` to what `build_expected_set` makes,** which is stricter than `to_json`'s own check: a manifest mail carries `sender_address`, `sent_at` and `internet_message_id` and no `sender_name`; a random item carries no `sender_address` or `internet_message_id`; `bytes` requires `size_bytes` and `office-v1` forbids it. `sample.algorithm` is the constant `sample-v1`; the two `manifest_sha256` and each `pool_sha256` are 64 lower-case hex. `worker_version` is `^[0-9A-Za-z.+-]+$`, 1 to 64 characters. `tenant_id` is a string with a `maxLength`, like the other tenant values, not a GUID pattern. `check.items[].ms` has no minimum (a clock that went back). `$id` is `https://restoreproof.local/schemas/result.v1.json`, the seed manifest's convention. (`shared/testdata/result-v1/cases.json`.)
10. **What the keyword subset can't say is not checked.** Any rule across objects (counts against array lengths, `index` equal to position, `status` against `check`, `sample.run_id` equal to `run_id`), the per-position types of a random `key`, and "each mismatch field once, in order" in `reason`: the pattern takes the listed fields in any order. C5.7 must not read the schema as checking these.
11. **The shared documents are patches of one base.** `shared/testdata/result-v1/cases.json` holds 158 cases (39 valid, 119 invalid), each `valid.json` with an RFC 6902 patch of add, remove and replace, and no float (point 3 of the entry: the two validators differ on `1.0`; the float rows are C++-only tests). The counts are pinned in `result_schema_test.cpp`; Python's validator agrees with the C++ one on all 158 (`cloud/tests/test_result_schema.py`). A second difference was found in review (2026-10-05) and closed in the Worker: the library reads an unsigned integer into a signed 64-bit value before `minimum` and `maximum`, so `2^64 - 1` at `check.items[].ms` was `-1` to it and valid, where Python refuses it. `validate_result` now refuses any unsigned integer past the signed 64-bit range itself, as one violation at its place, before the library is asked; every integer of the schema ends at `2^53 - 1` and every object is closed, so such a number is valid nowhere. The pipeline never got that far (the canonical form refuses it first); a direct caller did. The case is in the shared file (`check-ms-past-signed-64-bit`), with two valid reasons no shared case held (`check-error-mail-target-graph-transient`, `check-mismatch-size-bytes`). The `reason` pattern's own copies of the item kinds, `read_error_code`'s codes and the mismatch fields are held to the code by a test that builds every reason the checker can write from the kinds and the two enums beside the pattern (`result_schema_test.cpp`, "the result schema's reason pattern takes every reason the checker can write").
12. **`valid.json` is the Harness's run with the lab's names replaced.** The test Harness runs on the lab tenant's recorded values, and `shared/` holds no tenant's. So the test renames them by a fixed table (`shared_names()`), pins `worker_version` to `0.0.0`, writes the manifest with LF so `manifest_sha256` doesn't depend on the checkout, and compares the canonical text with the file, byte for byte; it also fails if a lab name is left. The table also renames the lab Veeam server's repository ID, which starts the Harness's restore point IDs as it starts every real one of the lab (missed at first; found in review, 2026-10-05). The hashes in it are the lab run's own, and so is the restore point's time, a real point's. A hidden test case, `rptests "[.write_shared_result]"`, writes the file again after a deliberate change; `connector.api` in it is the fake connector's `1`, not `v8`. (`test_command_test.cpp`, "the whole pipeline's result is shared/testdata/result-v1/valid.json".)
13. **The builder's shape.** `ResultBuilder` has two static functions, `document(ResultParts)` (throws without a verdict, lets a part's `to_json` throw) and `build(ResultParts) noexcept` (a `BuiltResult{document, canonical}` or a `ResultError`); `document` is the canonical text parsed back. A missing timings part gives `timings.spans` with all eleven keys `null`, since the schema requires the object; the pipeline always hands one in. `RunSummary` is now `{run_id, result}`, `result` the finished result's canonical text or null.
14. **The validator is a DLL.** Under the `x64-windows` triplet vcpkg builds `json-schema-validator` as `nlohmann_json_schema_validator.dll`, copied beside `rpworker.exe` and `rptests.exe` like cpr's and OpenSSL's. The installer must ship it. `reason` and `run_id` patterns run on MSVC's `std::regex`, with `maxLength` checked beside them, not before.
15. **Not reached by a test.** Through the pipeline: `result error: the result couldn't be built` (no part's `to_json` throws on anything the Harness can make; `ResultBuilder`'s own tests cover `build_failed`) and a run with no verdict (`decide_status` never throws on what the Harness feeds it; it shares the no-result path the `result_invalid` rows test). In `result_schema.cpp`: the schema failing to load and the validator throwing. In `canonical_json.cpp`: nothing but the closing line of the UTF-8 rethrow. Looked at again on 2026-10-05, line by line, and left: no test reaches them without a seam made for the purpose. `result_builder.cpp` 80 and 88 are the closing lines of two `catch` blocks whose `return` is reached, and 95 to 98 the outer `catch` for a failed allocation; `result_schema.cpp` 71 and 72 (the embedded schema not loading), 195 (no validator) and 206 to 209 (the validator throwing); `canonical_json.cpp` 69; `run_pipeline.cpp` 392 (the `couldn't be built` line) and 846 to 848 (the `catch` around a `noexcept` build).
16. **Coverage, run locally on 2026-10-05** (`worker/tools/run_coverage.ps1`, then the gate): the gate passes, exit 0. 97.6% line overall (9462 of 9695); the strict files all 100%: `cleaner.cpp` 202 of 202, `run_status.cpp` 415 of 415, `target_guard.cpp` 73 of 73, `target_guard_graph.cpp` 117 of 117, `target_guard_veeam.cpp` 315 of 315; the new files `canonical_json.cpp` 31 of 32, `result_builder.cpp` 46 of 51, `result_schema.cpp` 97 of 103, none strict (point 15 names their lines); every `.cpp` present. The first run of that day failed the gate on a file W4.1 hadn't touched: `src/cleaner.cpp` was 198 of 200, the two closing lines of `Cleaner::resolve`'s SharePoint and OneDrive branches, unreached since Q3.2 added the child counts there (commit 1c55019, on `main`). No test could reach them: OpenCppCoverage counts the closing line of a block that returns past a local with a destructor as code, and a throw through it doesn't run it either (a new test, the library's own count refused or failing, showed that). So this branch fixes the gap from `main`: `resolve` holds no local now, each file target's `Resolved` built in one expression (`Resolved::library`, `Resolved::onedrive_folder`, in `cleaner.cpp`). No behaviour changed: the same guard checks with the same wording, in the same order, the count read after the library's check as before; the existing cleaner tests pass unchanged. CI still hasn't said any of this: no Worker workflow run has started since 2026-10-03T13:11Z (GitHub reports the jobs "not started because recent account payments have failed or your spending limit needs to be increased"). That stays open, outside W4.1. One thing about running it: start `run_coverage.ps1` and `ctest` from PowerShell 7 itself; started through Git Bash, the console's code page makes the exe test "rpworker config check keeps a --config path outside the ANSI code page" fail.
17. **The Done-when run, live on 2026-10-04 (23:52Z).** `rpworker test --mail 10 --sp 10 --od 10 --run-id w41-done-when-1 --point <id> --json <file>`, elevated, on the 2026-10-03T16:16:54.0154727Z restore point (the one W3.6 passed on; the 2026-10-04 points were taken during Q3.1's scenarios): 30 of 30 restored in five `Success` sessions, `status pass: 30 of 30 item(s) verified: manifest 15, fields 5, metadata 10`, `cleanup after ok`, exit 0, stderr empty, `graph list` 0 in all three targets afterwards. The written file (22,692 bytes, fifteen keys, `connector` `veeam_m365`/`v8`) validated in the Worker before it was written and again with Python's `Draft202012Validator` against `shared/schemas/result.v1.json`, and is its own canonical form (`schema: valid`, `canonical: True`). Evidence `docs/api/veeam-lab/w4.1-live-*`; the `--json` file is kept outside the repository.

---

## 2026-10-04 — W4.1: `restoreproof.result.v1`, its schema, the canonical form, and what an invalid result does (recorded before the build; the owner approved it as written)

W4.1 (#44) fixes the result's schema, builds the result from the run, validates it in the Worker and makes `rpworker test --json` write it. Plan section 6, which the issue points at, is not in the repository; this entry works from the Sprint Task Guide (W4.1 to W4.6, C5.2, C5.6, C5.7, C6.x), the issue's comment and the entries below. Where the guide and a later entry disagree, the later entry wins, as in W3.6.

**Decision.**

1. **`result.v1` replaces `rp.run-summary.v0` in `--json`. One file, one shape.** v0 was written as "close to what W4.1 signs"; nothing reads it but the tests and the owner. The sixteen keys:

   | v0 key | in `result.v1` |
   |---|---|
   | `format` | kept; its value is `"restoreproof.result.v1"` |
   | `worker_version`, `run_id`, `started_at`, `ended_at` | kept as they are (`started_at`/`ended_at` `null` when the clock failed) |
   | `restore_point` `{id, backup_time_raw}` | kept, always an object (a run with a run line has chosen its point), plus `backup_time`: the same time cut to whole seconds, `null` when Veeam's text doesn't parse (`to_whole_seconds`, moved from `src/veeam_restore.hpp` to `src/veeam_time.hpp`). The Cloud's `restore_point_at` reads it; `backup_time_raw` stays the exact text an explore session needs |
   | `veeam_org_name` | moves into the new `client` object (point 6) |
   | `sample`, `expected`, `restore`, `check`, `status`, `cleanup`, `timings` | kept, each the existing `to_json`, with one change to `check` (point 7). `null` where the step didn't run, except `status`, which is always an object (point 5) |
   | `command`, `exit_code` | dropped (amends W3.6 point 5 and the PR #153 review point 4). They are facts of one process (`test`, a lost stdout, an incomplete `--record`), not of the run, and a service run has neither. A lost stdout or an incomplete recording then shows only in the exit code and on stderr, not in the file |

   New: `connector` `{type, api}` from `IConnector::describe()`, read once when the connector is made (`type` an enum, today `veeam_m365` only; the tests' fake connector takes that name), and `client` (point 6). That makes fifteen top-level keys, all always present. The guide's flat names map onto the built objects and are not duplicated: `status` is `status.status`, `error_code` and the message are `status.error_code`/`status.message`, `cleanup_ok` is `cleanup.cleanup_ok`, `sample_seed` is `sample.seed`, `expected_kind` is `expected.items[].expected_kind`, the item rows are `expected.items[i]`, `restore.items[i]` and `check.items[i]` joined by `index`, recovery time is `timings.spans.recovery`. Two of them are absent on some `error` runs: `sample` is `null` when the run stopped before the sample was chosen, and `cleanup` is `null` when it stopped before the clean before. The Cloud stores no seed and no `cleanup_ok` for those.

2. **The schema is embedded at build time.** `shared/schemas/result.v1.json` is the only copy. A CMake custom command reads it as bytes and writes a generated source holding a byte array into the build folder (`DEPENDS` on the file, so an edit rebuilds; never one string literal, which MSVC cuts at about 16 KB), linked into `rpcore`; the Worker never reads a schema from disk, so an installed Worker can't run with a different one. A test compares the embedded bytes with the file; `.gitattributes` gets `eol=lf` for `shared/schemas/*.json` and the JSON under `shared/testdata/`, so a Windows checkout embeds the bytes the Cloud reads. The Cloud side reads the same file by path, as `lab` reads `seed-manifest.v1.json`; W4.1 adds only a Cloud test for it, no copy. The test finds `shared/schemas` by walking up from its own folder, so it also runs from mutmut's copy. A later PR that changes only the schema passes the "No test, no merge" guard; the shared documents below are what checks it.

3. **The schema says draft 2020-12 and uses only what draft 7 and 2020-12 read alike.** The vcpkg port at the pinned baseline is `json-schema-validator` 2.4.0, which implements draft 7 only: it never looks at `$schema` and silently ignores `unevaluatedProperties`, `prefixItems`, `dependentRequired` and any keyword beside a `$ref`. Python's `Draft202012Validator` enforces those. So:
   - Allowed: `type`, `enum`, `const`, `properties`, `required`, `additionalProperties`, `items` (one schema), `minItems`/`maxItems`, `minLength`/`maxLength`, `pattern`, `minimum`/`maximum`, `allOf`/`anyOf`/`oneOf`/`not`, `if`/`then`/`else`, `$defs`, a `$ref` alone in its object, and `$schema`, `$id`, `title`, `description`. A Worker test walks the schema's subschemas (not its property names: the result has keys called `format`, `items`, `type` and `status`) and fails on any other keyword.
   - No `format`: the C++ checker accepts `+02:00`, Python doesn't check it at all, and the C++ message quotes the value. Timestamps are `pattern`s: `YYYY-MM-DDTHH:MM:SS.mmmZ` for `started_at`/`ended_at`, `YYYY-MM-DDTHH:MM:SSZ` for the items' times and `restore_point.backup_time`. A time with an offset, or without `Z`, doesn't validate.
   - Patterns use ASCII classes only (`[0-9]`, never `\d`). The two engines also disagree on line ends: MSVC's `^` and `$` match at any line, Python's `$` before a final newline. So a fixed-length pattern (a timestamp, a 64-hex hash) carries `minLength` = `maxLength`, and a variable-length one (`run_id`, `reason`) also carries `not: {pattern: "\n"}`.
   - Patterns only on strings the Worker makes. Veeam's text (`restore.sessions[].result`, the `*_raw` times, session IDs, the tail of a `backup_session` warning) and tenant text get a `maxLength` and nothing else: an unknown Veeam word must not turn a run into `result_invalid`.
   - A nullable object is `oneOf` of `null` and the object. The random `key` arrays are held to their length and to strings only (per-position rules need a keyword the two drafts read differently).
   - `integer` differs for `1.0`: Python accepts it, the C++ validator doesn't. The Worker never meets it (point 4 refuses floats before validation); C5.7 and `verify_bundle.py` must check the canonical form before the schema.
   - Every object is closed (`additionalProperties: false`). `signature`, `tsa_token`, `tsa_error`, `attachments`, `worker_id` and `bundle_sha256` are not in the schema yet; W4.2 to W4.6 and W5.1 each add theirs (see Open for the ones written after the hash). Until the C5.11 contract test the file is not frozen.
   - One set of documents, `shared/testdata/result-v1/` (a valid result made by the Worker's own test run, and invalid ones as small changes to it), is checked by the C++ validator and by Python's, so the two are shown to agree.
   - A test holds the schema's enums to the code. `kCodes` gains a `restore_contradiction` row (it was row 6's own code outside the table; exit 4 as before) and `run_status` a public, tested list of the run's error codes and of the warning codes. The span names, kinds, outcomes and the cleanup and check codes have no table; the test lists them by hand beside the `to_string` functions.

4. **The canonical form is its own unit, `rp::canonical_json` (`rp/canonical_json.hpp`), `canonical-json-v1`.** `nlohmann::json`'s compact dump: keys sorted by byte, `,` and `:` only, no trailing newline, strings as UTF-8 with JSON's short escapes and lower-case `\u00xx` for the other control characters. It refuses, by throwing, what the two languages would write differently: a floating-point number (no result field is one), an integer outside ±(2^53 − 1), a key that isn't ASCII (only RFC 8785 orders those differently), and invalid UTF-8 (strict, never replaced by U+FFFD as v0's dump did; point 7 is its precondition, since the office-v1 note was the one result string not read from JSON). With those rules Python's `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)` gives the same bytes, and so does RFC 8785. Vectors in `shared/testdata/canonical-json-v1.json` (the text-v1 layout: input, canonical text, SHA-256, and refusals: a float, an integer out of range, a non-ASCII key) are run by a C++ test; a Python test runs the accepted ones against that one line. A Python canonicaliser with the same refusals comes with `verify_bundle.py` (W4.3). Invalid UTF-8 can't be written in a JSON file, so that refusal is a C++ test on bytes. The `--json` file is exactly the canonical bytes, no longer pretty-printed. `verify_bundle.py` and the removal of `signature`/`tsa_token` before hashing are W4.3's.

5. **An invalid result is `error result_invalid`, exit 1.** A new row in `kCodes` (never a stop's code, not a check code, `exit_code::config`: the Worker's own fault, as `internal`). The message is fixed: `the result isn't valid restoreproof.result.v1; the run itself ended <pass|fail|error <code>>`.
   - **When.** The pipeline builds and validates the result in `finish`, right after `decide_status` and before the check table and the status line, for `restore` and `test` alike, with or without `--json` (so the wall clock is read for every run with a run line, not only under `--json`). At that point the clean after hasn't run: `ended_at` and `cleanup.after` are `null`, `cleanup_ok` and `restore_may_still_run` hold their defaults and the open spans read `open`, all of which the schema allows. If it doesn't validate (or can't be built: `to_json` throws, the canonical form refuses, the validator throws), a public `verification::result_invalid(verdict)` in `run_status` gives the error verdict. It keeps `restore_sent`, the item count and the warnings and clears the verified, failed and unchecked items, so `test`'s VERDICT column reads `-` as for rows 1 to 4, the one status line says `error result_invalid` and the clean after still runs.
   - **`status` is required.** If `decide_status` itself threw there is no verdict (v0 wrote `"status": null`). `result.v1` has no such document: no file, the `json error` line below, exit 1 as today.
   - **What is validated.** The canonical bytes parsed back, so it is the written text that validated.
   - **No file.** An invalid document is never written under this format, and no cut-down one is made up: `json error: <file>: the result isn't valid restoreproof.result.v1; no file was written` on stderr.
   - **At the end.** Only when a file is to be written: after the clean after and the timings the finished result is built and validated again. New since the first time are `cleanup.after` with its two flags, the closed spans and `ended_at`, all fixed-shape and Worker-made, so a failure here is a Worker bug (or a wall clock past the year 9999, which is the test for it). The status line is already out and stays; the same `json error` line is printed, no file is written, and exit 0 becomes 1 (the W3.6 write-failure rule). A throw while building counts the same, and `finish` no longer keeps exit 0 when the end-of-run hook throws. Without `--json` only the first validation runs.
   - **What is printed.** stderr gets `result error: <n> schema violation(s), first at <JSON pointer>`: the pointer only when each part is a schema key or an index, never the validator's message or the value.

6. **The `client` object holds what the config knows today.** `tenant_id`, `veeam_org_name`, `targets` `{mailbox, site_id, library_id, onedrive_drive_id, onedrive_folder_id}`, and `client_id: null` until jobs carry one (W4.10). The 2026-09-29 entry and the issue's comment also name three things that wait:
   - `scope: "same_tenant"`: nothing compares the Veeam organisation's `msid` with `graph_tenant_id` yet (W4.11's `client_mismatch`), so the result would claim what wasn't tested. It comes with that check.
   - The organisation's ID and the names and URLs the targets resolved to: the pipeline doesn't hand them out today (the guard resolves them inside `restore_sample`). W4.10/W4.11.

7. **`check.items[].reason` becomes fixed words.** Today an invalid office-v1 package puts the zip reader's text, which names a part inside a tenant file, into `reason`: the one place an exception's text reaches the file (W3.6, Open). The result is what gets signed and uploaded, so `to_json` writes `...; the restored package isn't valid office-v1 input` without the parenthesis, and the schema holds `reason` to its four forms: `the <kind> restore target couldn't be read (<code>)`, `only an earlier run's copy is in the target`, `no restored copy found`, and `fields did not match: <field>, ...` with or without that office-v1 tail.

8. **What of the tenant the result holds.** As v0 (`docs/verification.md`): `expected.items` (subjects, sender names and addresses, Internet message IDs, times, file names), `sample.*.random.keys` (mailbox addresses, folder names and paths, subjects, site and list IDs, file names, UPNs), `sample.*.random.containers_listed` (the mailboxes, sites and OneDrives the draw looked into, sampled or not), and now `client`'s IDs and mailbox address. W4.1 keeps them: the Cloud's item rows and the report's Failures section need the item names, and the keys are what lets a draw be repeated. v0's reason, "the file is local", ends when W4.6 uploads the result; see Open.

**Not produced today, and left out.**
- `worker_id`: issued at registration (W5.1).
- A found hash (`test_item.found_sha256` in C5.2): found values are never written (W3.2); `expected.items[].sha256` exists for `manifest` items only.
- A per-item `match` boolean and one `name`: the result has the four-valued `outcome`, and `subject` for a mail, `name` for a file. The per-item verdict is `status.failed_items`/`unchecked_items`. C5.7 maps these to its rows.
- A result for a run that ends before its run line (W3.3 build note 8, still open).
- `job_invalid`, `connector_unknown`, `client_mismatch`, `interrupted`: added to the enum by W4.8/W4.11.

**Alternatives rejected.**
- *Writing v0 beside `result.v1`:* two shapes of one run to keep in step, and nothing needs v0.
- *Lifting `status`, `cleanup_ok` and `sample_seed` to the top level:* a second copy that can disagree with the object beside it.
- *Reading the schema from disk:* an installed Worker could validate against an edited file.
- *Reusing `internal`:* its messages speak of a stop before, in or after the restore, and the Cloud couldn't tell a schema failure from any other.
- *Validating only at the end:* stdout would already say `pass`.
- *A cut-down result for `result_invalid`:* it would have to say steps didn't run that did. What the service uploads for such a run is W4.2's question.
- *`format: date-time`:* the two validators disagree on it.

**Open.**
- Whether `sample.*.random.keys` and `containers_listed` leave the network as they are or are cut to counts and `pool_sha256` before the first upload (W4.6). Nothing in C5.2, C5.7 or C6.x reads them.
- Fields written after the hash: `bundle_sha256` if it is in the document (W4.3), and `tsa_error` (W4.4), which is known only after the signature. Each must join `signature` and `tsa_token` in the removed set, which amends the signing contract, or live outside the signed document.
- The Cloud's `test_item` columns against the three item arrays (C5.2/C5.7).

**Code, tests and docs with the build.** `shared/schemas/result.v1.json`, `shared/testdata/result-v1/`, `shared/testdata/canonical-json-v1.json`; `rp/canonical_json.hpp`, `rp/result_builder.hpp` (`ResultBuilder`), `rp/result_schema.hpp` (the embedded schema and `validate_result`), the `result_invalid` and `restore_contradiction` rows, `result_invalid()` and the code lists in `run_status` (100% line), `run_pipeline.cpp`, `test_command.cpp` and `checker.cpp`; the v0 golden-shape test and its pretty-print check rewritten for v1; `.gitattributes`; `json-schema-validator` in `worker/vcpkg.json` and `tests/deps_test.cpp`; `cloud/tests/` with `jsonschema` in Cloud's dev group. Docs: `docs/verification.md`, `docs/worker-config.md`, `docs/testing.md`, CLAUDE.md.

---

## 2026-10-04 — PR #155 review: a missing container is never `fail`; a short listing is read again before it is refused (proposed)

Amends the two entries below (Q3.1 points 1 and 2, Q3.2 point 1 and its Risk) after the review of PR #155.

1. **A canary whose whole container isn't in the restore point is *unchecked*, never *failed*.** Q3.1 made every canary missing from a later point `fail`. But when the point holds no backup of the canary's mailbox, site or OneDrive at all (the job doesn't cover it, or it was taken out of the job), the point says nothing about the item: a job or configuration matter, which the status vocabulary forbids as `fail`. `connector::ItemRestoreResult` gains `container_missing`, set by `restore_sample` when it is the item's mailbox, site or OneDrive that has no match (`ContainerNotInPoint` in `src/veeam_m365_connector.cpp`); item rule I4 now also takes a `not_in_backup` item with `container_missing`, whatever its source and the point's date, so the run is `error not_in_backup`, exit 4. A folder or a library missing inside a container the point does hold stays an item-level miss (I5 for a canary in a later point): Veeam's jobs select mailboxes, sites and OneDrives, not folders, so that is data the backup should have. The result's `restore.items[]` carries `container_missing`.
2. **A SharePoint site Veeam answers 404 for is a missing container, per item.** Until now that 404 ended the whole run as `error backup`, though the header listed the site among the per-item cases. The site is asked for once however many items it has. What Veeam answers for a site the point doesn't hold wasn't recorded live: the test's 404 is hand-written in the shape of the recorded `ResourceNotFound` replies. Any other answer (a 400, a 500) still ends the run as before. An explore session that expired answers 404 too and would read as a missing site; either way the items are *unchecked*, never *failed*.
3. **A listing shorter than its container's count is read again before it is refused.** Q3.2's Risk: a `childCount` that trails a delete (the clean before the snapshot, a Cleaner round before the next), or an entry removed between the two reads, would read as a trimmed listing. `list_whole` in `src/graph_paging.hpp` now waits `kListingRecheckWait` (2 s, on the Graph client's own sleep, `GraphClient::wait`), reads the count again (the library's root; the OneDrive folder through the guard's check) and lists again, at most `kListingRechecks` (3) times. A listing still short after 6 s is the `PermissionError` as before, so a real trimmed listing costs 6 s and six requests more per reader. Whether SharePoint's count lags at all, and for how long, is still unmeasured; a lag past 6 s would still end `error graph_permission` (never `fail` or `pass`).
4. **Smaller.** The browse caches of `restore_sample` keep an empty listing (`cached`), so the items missing under it don't each ask Veeam again; the guard's OneDrive check reads the folder's count with `child_count_of`, the one rule for it.

**Alternatives rejected.**
- *Keep a missing container `fail`:* a mailbox dropped from the job does leave it unprotected, but the run still ends non-zero (`error not_in_backup`) and says why; `fail` is kept for "the backup holds the container and lost the item".
- *List the sites (`Sites?parentId=root`) instead of reading the 404:* independent of Veeam's error shape, but the listing leaves subsites out, and it changes the recorded request sequence of every SharePoint restore.
- *Drop the count check after the Worker's own deletes:* that is exactly the clean after the trimmed read-back of scenario 6.

Tests: `run_status_test.cpp` (I4g, I4h, `[restore_json]`), `veeam_m365_restore_test.cpp` (`[q3.1]`: `container_missing` per kind of missing item, the 404 site, the site asked for once, an empty listing fetched once), `graph_targets_test.cpp` and `cleaner_test.cpp` (`[q3.2]`: a trailing count read again; the trimmed listing refused after three rechecks), `graph_client_test.cpp` (`wait`).

---

## 2026-10-04 — Q3.2: a listing shorter than its container's count is a permission error, never an empty target (proposed)

Found by Q3.2's scenario 6 (#43, `tests/e2e/scenarios.md`): with the Worker app's `Sites.Selected` and `Lists.SelectedOperations.Selected` roles revoked, `rpworker test --sp 1` ended **`status fail`** (run `rp-20261004T185609Z-6af4a76d`). SharePoint did not refuse anything. `GET /drives/{library}` and `GET /drives/{library}/root` answered 200, the root's `folder.childCount` counting the file Veeam had just restored, and `GET .../root/children` answered 200 with an empty `value`: security trimming. The Worker took the empty listing for a missing item (a `fail`, which the status vocabulary forbids for a permission problem), the clean after said `ok: deleted 0` with the file still there, and `graph list` said 0. (Minutes after the revoke the same run still passed: SharePoint serves cached permissions for a while. #154 tracks which grants the library really needs.)

1. **A file listing is held to its container's own count.** `check_listing_whole` in `src/graph_paging.hpp`: when the container says it holds more children than Graph listed, the read throws a `PermissionError` naming the grant (`Graph listed <n> of the <m> entries in <target>: SharePoint leaves out what the app may not read instead of refusing the listing; ...`), so the code is `graph_permission`: `error`, exit 2, never `fail`. A container reply without a count is a `GraphError`: the listing can't be shown to be whole.
2. **The count is read before the listing.** For the library: one new request, `GET /drives/{drive}/root?$select=id,folder` (`library_child_count`). For the OneDrive folder: the guard's own read already asks for the `folder` facet, so `ResolvedOneDriveFolder::child_count` costs nothing. Read first, a file added in between makes the listing longer than the count, which is fine; only fewer entries than counted is refused.
3. **Both readers.** `TargetReader::list_sharepoint`/`list_onedrive` (the before snapshot, the after read, `graph list`) and the Cleaner's first listing of each round. The Cleaner's second listing of a round isn't checked: the count was read before that round's deletes. A listing cut at `kMaxListPages` is short by design and isn't checked either.
4. **What the run says.** Before the restore the snapshot stops the run: `status error graph_permission: the run stopped before the restore: ...; nothing was restored`. After it, the type's items are `error` `graph_permission` (row 7), and the clean after reports `sharepoint graph_permission` instead of `ok`. Mail isn't affected: Exchange refuses with a 403.

**Alternatives rejected.**
- *Check the token's `roles` claim:* it says what Entra granted, not what SharePoint enforces (the cached passes above had no SharePoint role), and it wouldn't catch a grant removed on the list or folder itself.
- *Treat an empty listing after a successful restore as `error`:* that is exactly the real `fail` (Veeam said restored, nothing arrived; W3.2 live run 2) and must stay one.
- *`$expand=root` on the guard's drive read:* no extra request, but it changes a recorded guard request for every fixture and recording.

**Risk.** If SharePoint's `childCount` ever lags behind a delete, a listing right after a clean would look short and the run would end `error graph_permission` wrongly (never `fail` or `pass`). The recordings show count and listing equal at every recorded moment, and the live reruns after this change are the check.

Tests: `graph_targets_test.cpp` and `cleaner_test.cpp` (`[q3.2]`, on the two live replies recorded at the failure, `restoretarget-root-200-one-child.json` and `restoretarget-children-200-trimmed.json`), `test_command_test.cpp` (the whole run: restored, read-back trimmed, `error graph_permission`, never `fail`). The w34 live recording replays unchanged but for the one new library-root request.

---

## 2026-10-03 — Q3.1: an item the restore point doesn't hold is reported per item; a canary missing from a later point is `fail` (proposed)

Closes the first "Open" point of W3.3. Q3.1's scenario 2 (#42: a canary mail permanently deleted, then backed up) wants `fail` naming the item; until now `restore_sample` threw one `NotFoundError` for the whole sample, so the run ended `error not_in_backup` with no item, and its message ("the restore didn't complete ... items may be in the restore targets") overstated it, since browsing fails before any restore is sent. The owner chose to fix it within Q3.1.

1. **The connector reports it per item.** `connector::ItemOutcome` gains `not_in_backup`. `VeeamM365Connector::restore_sample` catches browsing's `connector::NotFoundError` per item (`resolve_item` in `src/veeam_m365_connector.cpp`: the item, or its mailbox, folder, site, library or OneDrive, has no match in the restore point), records that outcome with browsing's message, never sends the item, and restores the others. `restore_sample` no longer throws `connector::NotFoundError`; any other browsing error (several matches, a re-read that differs, the test OneDrive missing) still ends the run as before. `items_sent` counts what was sent. `veeam_restore::overall_status` gains `not_in_point`: nothing sent because nothing was in the point is `failed` (not `not_run`, which row 4 would make an `error`), and a run that missed some items is at best `partial`.
2. **The status decides whether the backup should have held it.** New item rule I4 (the old I4 is now I5): `missing` or `mismatch` with the backup's `not_in_backup` is *unchecked* `not_in_backup` unless the item is a canary and the restore point was taken strictly after the manifest's `seeded_at`; then I5 makes it *failed* and the run `fail`. `seeded_at` is the seeder's time after the last canary was written (required by `seed-manifest.v1`; the loader now reads and checks it, `CanaryManifest::seeded_at`), carried as `ExpectedSet::canaries_seeded_at`; `RunFacts::restore_point_time` is the chosen point's `backupTime`. Both are read with `parse_veeam_time`; a time that doesn't read says "not shown to hold", never `fail`.
3. **A random item missing is never `fail`.** Its pool was listed from the same restore point, so its absence is the backup product contradicting itself, not lost data: `error not_in_backup`.
4. **`not_in_backup` ranks after `backup_infrastructure`** among the unchecked items' codes (`target_guard`, `graph_auth`, `graph_permission`, `backup_infrastructure`, `not_in_backup`, `graph`, `graph_transient`, `stale_target`): a backup-side reason, more specific than a Graph error.
5. **Naming the item.** The status message still names nothing (counts only); the item is named by its row: `rpworker test`'s REASON reads `not_in_backup` (the check table now gets the restore result), `rpworker restore`'s OUTCOME `not_in_backup` with Veeam's lookup message, and the `--json` summary's `status.failed_items` and `restore.items[].outcome`.

**Alternatives rejected.**
- *Every missing canary is `fail`:* a restore point taken before the canaries were seeded can't hold them; that is a test-setup problem, not the backup's.
- *Per-canary dates (`received_at`, `last_modified_at`):* finer, but the manifest's single `seeded_at` is later than all of them and needs no per-kind rule; it is the conservative bound.
- *Keep throwing and parse the item from the message:* the status would depend on a message's wording.

Tests: `run_status_test.cpp` (I1c, I2c, I4a–I4f, I5e–I5f, S1–S7), `veeam_m365_restore_test.cpp` (`[q3.1]`: each kind of missing item, and one missing beside one restored on W2.4's recorded single-mail restore), `veeam_restore_test.cpp` (`overall_status`), `canary_manifest_test.cpp` (`seeded_at`), `expected_set_test.cpp`, `restore_command_test.cpp` and `test_command_test.cpp` (the run's status line and the REASON cell, for a point after and before `seeded_at`). The live proof is Q3.1's scenario 2 (`tests/e2e/scenarios.md`).

---

## 2026-10-03 — PR #153 review: the `--json` check makes the writer's temp file; device names refused; the summary's `exit_code` is the process's (proposed)

The review of PR #153 found more `--json` paths that passed the check and failed only after the whole run, and two places where the summary said less than the truth. Fixed on the branch, with tests (`tests/atomic_file_test.cpp`, `tests/test_command_test.cpp`):

1. **One check, the writer's own: `rp::check_new_file` in `src/atomic_file.hpp`.** In order: a plain name, nothing there, the folder there, then the writer's first step done for real: `CreateFileW` `CREATE_NEW` on a `<file>.<16 hex>.tmp` name, with `FILE_FLAG_DELETE_ON_CLOSE`, so nothing is left. `check_json_path` maps its answer to the texts and no longer re-derives the writer's rules. New text, exit 1: `config error: --json <file>: a file can't be written there`, for a folder the Worker may not write to, a read-only volume, or a name or path too long once the temp's 21 characters are added (a 240-character name fits 255, its temp name doesn't; there is no long-path manifest).
2. **DOS device names aren't plain file names.** `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`, `CONOUT$`, `COM0`–`COM9`, `LPT0`–`LPT9`, and COM/LPT with a superscript 1–3, in any ASCII case, alone or before the first `.` (spaces before it ignored). On Windows 10 Win32 answers "not found" for `PRN` or `aux.json` with no such device, so they passed as "no file yet"; with a printer or a COM port the summary could have gone to it. `NUL` now reads `not a file name`, not `the file already exists` (amends the W3.6 review point 3's example).
3. **A name ending in `.` or a space isn't plain.** Win32 strips it: `--json run.json.` wrote `run.json` and printed `wrote run.json.`.
4. **The summary's `exit_code` is the process's as known when the file is written.** It was the status's alone, so a pass whose stdout was lost, or whose `--record` recording was incomplete, said 0 for a process that exits 1. Now both are in it (`recorded_exit_code` in `src/command_config.hpp`, the rule `finish_recording` applies). Only the file's own failed write comes later, and then there is no file. `RunSummary::exit_code` is gone; the hook already gets the code. Amends W3.6 point 5's "`exit_code`: the status's code, before any change below".
5. **`cleanup` is `null` when no clean ran.** It was always an object; now `null` when the run stopped after its run line but before the clean before (the clean after only runs after it), as the v0 rule says.

Rejected: keeping the name rules and adding a length rule and an ACL check one by one; each is a guess at what `CreateFileW` will do, and making the temp file is the answer.

---

## 2026-10-03 — W3.6 review: a `--json` path the writer can't use is refused before the run (proposed)

The reviews of the W3.6 branch found `--json` values that passed the up-front check and so cost a whole run, the restore into the tenant and the clean after included, before the write failed at the end. Fixed on the branch, with tests (`tests/test_command_test.cpp`, `tests/atomic_file_test.cpp`, `tests/cli_test.cpp`, and one exe test):

1. **An empty `--json` value is a missing one: exit 64 with the usage line.** `parse_options` accepts an empty value, and the check took the empty path for "no file yet" in the working folder. Point 5 already makes a missing value 64, so there is no new text.
2. **A new refusal, exit 1: `config error: --json <path>: not a file name` (amends point 5's list of three).** The file name must not be empty, `.` or `..`, and must hold no control character and none of `< > : " / \ | ? *`.
   - A `:` names an NTFS stream. With `out.json:x` the writer's `CreateFileW` made an empty `out.json` to hold the stream and left it behind when the move failed. With `existing.json:x` it added a stream to a file already there and changed its time. Point 5 keeps the run ID out of the temp name for this reason, but the user's own name wasn't checked.
   - The others are names Windows refuses. `std::filesystem` reports them as not found (MSVC maps `ERROR_INVALID_NAME` to `no_such_file_or_directory`), so they passed as "no file yet".
   - A drive's `C:` is in the root name, not the file name, so it isn't affected.
   - The rule is one function, `rp::is_plain_file_name` in `src/atomic_file.hpp`. The writer applies it too and refuses before it opens anything.
3. **Anything but a clean "not found" counts as a file already there.** The check read `exists()` of `symlink_status`, which is false on any error. It now refuses unless the type is `not_found`, with `the file already exists`. That covers a device such as `NUL` and a file the Worker may not read. No new text.
4. **A lost `wrote <file>` line still changes nothing.** Checked, no change: as with W3.5's timings table, a stdout that breaks at that line keeps the run's exit code.

The tests the reviews asked for besides: the summary's table gains the rows restore's `[step_timer]` table has (a restore stopped with nothing restored, row 1, row 4, row 6, `stale_target`), and the stdout-lost case checks every key. The early stops before the run line gain the secrets, the cursor, no connector, an unknown `--point` and a `--record` folder that isn't new or empty. `started_at` and `ended_at` are tested on a clock that moves by a fraction of a millisecond (the cut, not a rounding) and on one that fails for those two readings (both `null`, nothing else changed). `restore --json` and `restore --seed` are usage errors in `restore`'s table and `cli_test.cpp`. CLAUDE.md's list of commands now ends with `test`.

---

## 2026-10-03 — W3.6: `rpworker test` runs the same pipeline as `restore`, with its own table and a `--json` file; its exit codes are `restore`'s, `--seed` is dropped, and the lab gets real files for 30 of 30 (approved as written)

W3.6 (#41) adds `rpworker test --mail 10 --sp 10 --od 10 [--point latest] [--seed N]`. The issue lists clean before, restore point, sample, guard, restore, verify and clean after. It asks for a per-item table, the timing breakdown and the overall status, and `--json <file>` writes the run summary. The issue's Done when is "a live run against the tenant prints pass with 30/30 items".

`rpworker restore` (W2.8, W3.1–W3.5) already runs that whole pipeline in `run_restore` (`src/restore_command.cpp`). It runs the steps in its own order: the restore point is looked up, the run line printed, then the clean before. W3.5's spans follow that order (`restore_point_lookup` before `cleanup_before`). `test` keeps `restore`'s order, whatever order the issue lists. The issue text is older than W2.6, W2.8 and W3.3, so this log wins on two points: the exit codes (point 1) and `--seed` (point 3).

**Decision.**

1. **`rpworker test` uses W3.3's `exit_code_of`: 0 pass, 5 fail, 1 to 4 error by its code, 64 usage. This replaces the guide's "0 pass, 1 fail, 3 error".** It is the mapping proposed in W3.3 point 6. Every code keeps the meaning it has in every other command:
   - 1: config or internal.
   - 2: auth (`backup_auth`, `graph_auth`, `graph_permission`).
   - 3: transient.
   - 4: any other `error`.

   A failure before the run line exits with the same codes as `restore`: a mutex held by another run is 4, a config error is 1.

2. **30 of 30 needs real, non-canary data in the lab. Seed it (a new L task, W2.6's open point), and keep the Done when as written.** With `--mail 10 --sp 10 --od 10`, each type takes ceil(10/2) = 5 canaries and floor(10/2) = 5 random items (W2.6 point 2). The manifest covers the canaries (20 mails, 10 SharePoint files, 10 OneDrive files). The random halves can't fill on today's restore points:
   - **Mail:** 5 canaries plus up to 5 random. The pool size isn't recorded. The W2.8 and W3.4 live runs took 2 of 2 only because floor(5/2) = 2 were wanted. The draw looks into at most 3 folders in each of at most 2 productive mailboxes (`include/rp/connector.hpp:277-282`), and the folders drawn change with the seed.
   - **SharePoint:** 5 plus 0. The backup holds no real files. SharePoint's containers are every site on the tenant host (`src/veeam_candidates.cpp:431-441`). In the RestoreTest site, `Shared Documents` is the only eligible library (`kSkippedLibraries` and the manifest's `list_id`).
   - **OneDrive:** 5 plus 0. In alice's OneDrive the root holds only `RestoreTarget` and `RestoreTest`, and both are excluded. Whether any other OneDrive is in the restore point is an assumption. `RP-Lab-Full` backs up "all users, all SharePoint sites and OneDrives" (`docs/environment.md`), but a OneDrive that was never provisioned isn't there. The dry run below checks it (`containers_eligible`).

   So today's best case is 20 of 30. A shortfall is a warning, never a status (W3.3 point 4), so that run would still print `pass`.

   To seed:
   - **SharePoint:** 6 to 8 files in the root of `Shared Documents` in the RestoreTest site, with no subfolders. That gives the site one unit, so every draw that tries the site sees all of them. Every draw tries it only while the backup holds 8 sites or fewer (`containers_tried = 8`) and no other site gives a candidate first. The dry run checks this.
   - **OneDrive:** 6 to 8 files in the root of alice's OneDrive, in no folder. W2.6's open point proposed bob's OneDrive. Alice's is chosen because the evidence shows it in the backup (W2.5, W2.8) and its sign-in is already in `seed.py`. Bob's OneDrive is fine too if the dry run lists it. Root files work end to end: the root is a unit (`src/veeam_candidates.cpp:540-543`), guard layer 1's `first_folder` is empty for them, and an empty `top_folder` passes guard layer 2 (`src/target_guard_veeam.cpp:465`).
   - **Mail:** about 6 messages from alice to bob and 6 from bob to alice, so both users' Inbox and Sent Items fill. Each sent mail is in the backup twice under one subject: once in the sender's Sent Items, once in the recipient's Inbox. The sampler skips a pick whose `name_key` it has already taken, so 12 sends give 12 usable subjects, not 24.
   - **Names:** every name and subject distinct by `name_key` within its type. None starts with `rp-canary-` in any case: the lister's check is ASCII case-insensitive (`starts_with_i`, `src/veeam_candidates.cpp:67-81`), and the canary subjects are `RP-CANARY-…`. None equals a canary's name or subject in any case, and none contains `/`, `\` or `:`.
   - **File types:** mostly txt, pdf and png, whose `metadata` check compares Veeam's size with the downloaded size. One or two docx or xlsx files are allowed (name only, `is_rewritten_office_file`). Every file stays under 64 MiB.
   - **Tooling:** a `python -m seeder seed-real` command reusing `seed.py`'s delegated sign-in and upload helpers. It is written up in `lab/README.md`, the names are listed in `lab/tenant.md`, and no manifest is needed. `graph.upload_file` writes wherever it is pointed, and the delegated scopes include `Sites.ReadWrite.All` (`lab/seeder/auth.py:10`). So `seed-real` finds its places itself and checks them before any upload:
     - SharePoint: the RestoreTest site's default drive (`/sites/{id}/drive`), its root only.
     - OneDrive: `/me/drive/root`, signed in as alice.
     - It refuses the RestoreTarget drive, the RestoreTest (canary) drive and the `RestoreTarget`/`RestoreTest` folder IDs listed in `lab/tenant.md`.
     - It never replaces an existing file (`replace=False`).
     - Mail goes only to alice and bob, never to `restoretest@`.
     - A lab test covers each refusal.
   - **After seeding:** a backup must run, either the nightly `RP-Lab-Full` job or one started by hand. Then run the read-only `[live][sample]` dry run with a chosen `RP_LIVE_RUN_ID` against the new restore point. It must show, per type, `sample.<type>.random.pool_size` of at least 5 distinct names or subjects, and `containers_eligible` as expected. The pool depends on the run ID (the folders drawn) and on the restore point. A run without `--run-id` makes a new ID and may draw other mailboxes or folders. So the Done-when run reuses both: `rpworker test --mail 10 --sp 10 --od 10 --run-id <the dry run's RP_LIVE_RUN_ID> --point <the dry run's restore point ID>`.
   - **Worker grants:** no change. Candidates and their expected values come from Veeam, and guard layer 1 already allows these sources.

   The Done when is read as: `status pass`, 30 items sent, 30 verified (`manifest` 15, `fields` 5, `metadata` 10), and no `shortfall` warning, on the command above.

   **Fallback, only if the owner declines the seeding:** restate it as "pass, every canary verified, every random item taken verified, shortfalls named as warnings". That restatement leaves the random SharePoint and OneDrive restore and the `metadata` check unproven live.

3. **Drop `--seed N`, and use `--run-id <id>` to repeat a sample.**
   - **Where the seed comes from:** the first 4 bytes, big-endian, of SHA-256("restoreproof/sample-v1\n" + run_id) (`rp/sample_rng.hpp`).
   - **Why no caller can pass one:** `SampleSelector::select` derives the seed from the run ID itself, "so no caller can pass one the run ID didn't give" (`rp/sample_selector.hpp:96`).
   - **What repeats a draw:** the run ID, the manifest's SHA-256, the cursor and the restore point. The result records all four (W2.6 points 4 and 5).
   - **Why `--seed` is dropped:** it would be a second input the result doesn't record. A seed can't be turned back into a run ID, and `--run-id` already fixes the seed.
   - **What `test` takes instead:** `--run-id` and `--canary-cursor`, with `restore`'s rules. It prints `run <id>  seed <hex>` as `restore` does.

4. **Keep both commands, over one shared pipeline.** `run_restore` becomes an internal `run_pipeline(PipelineArgs, out, err, env, recorder, Presentation)`. Each command keeps its own parser.

   | | `restore` | `test` |
   |---|---|---|
   | Per-item table | restore rows (KIND SOURCE NAME OUTCOME SESSION ELAPSED MESSAGE), then check rows (KIND SOURCE NAME OUTCOME FIELDS DUP MS) | one table after the check, columns below. Veeam's per-item MESSAGE is not printed |
   | Session rows and the `restore <status>: ...` line | printed | printed (Veeam's per-session view, no `details`, no tenant values) |
   | `--json <file>` | no | yes (point 5) |
   | Command label in the recording's source (`rpworker <ver> <label> --record`) | `restore` | `test` |

   **`test`'s table columns:**
   - **TYPE:** `kind`.
   - **NAME:** the subject or file name, as stdout shows today.
   - **EXPECTED:** `expected_kind`.
   - **FOUND:** `yes` or `no`.
   - **MATCH:** the checker's `outcome`.
   - **VERDICT:** from `RunVerdict`: `verified`, `failed`, or `unchecked <code>`; `-` when rows 1 to 4 decided the run. An item the backup blamed on infrastructure then reads `unchecked backup_infrastructure`, never as a failure.
   - **REASON:** fixed words only:
     - a mismatch: its mismatched field names, joined;
     - missing: `missing`;
     - an error: its `error_code`;
     - a match: `-`.

     REASON never prints `ItemCheck::reason`. For an office-v1 file, that text carries the zip reader's error, which names a part inside the tenant file (`src/checker.cpp:153-154`, `src/office_v1.cpp:172-205`).
   - **MS:** `ms` when found, else `-`.

   These stay identical in both commands:
   - the run line and header, the mutex and its refusal, and guard layers 1 and 2;
   - the `cleanup before` and `cleanup after` lines, the `check: ...` count line, and the status line and its warnings;
   - the eleven-row timings table and `on_cleanup`/`on_timings`;
   - absent `--mail`/`--sp`/`--od` falling back to the config's `sample_*` ("items restored per test run", `docs/worker-config.md`; 5 each in `config.example.json`), so the Done-when run passes 10/10/10 on the command line, as the issue writes it;
   - `--record`, `--point`, `--run-id`, `--canary-cursor`, `--manifest` and `--config`;
   - the exit codes.

   No `--seed` in either (point 3).

5. **`--json <file>` writes an unsigned run summary, close to what W4.1 signs, for every run that printed its run line.**
   - **Shape:** fixed top-level keys, with `null` for whatever didn't run:
     - `format` (`"rp.run-summary.v0"`), `worker_version`, `command` (`"test"`), `run_id`.
     - `started_at` and `ended_at`: `YYYY-MM-DDTHH:MM:SS.mmmZ` from `wall_now`, read where `total` starts and ends.
     - `restore_point` `{id, backup_time_raw}` (Veeam's text, unparsed) and `veeam_org_name`.
     - `sample`, `expected`, `check`, `status` (with `restore_sent`), `cleanup` and `timings`: each the existing `to_json`, unchanged.
     - `restore`: a new `to_json(RestoreResult)`. It holds the status and the items sent and restored. It holds the sessions: ID, kind, result, `details`, items, and `started_at_raw`/`ended_at_raw` (the product's text, unparsed, the `0001-01-01T00:00:00Z` sentinel included). `details` appears only in the form of W3.3 build note 7 as amended by the W3.3 second review point 5, through the same filter `run_status.cpp` applies for `backup_session`, not a second copy. `items` is an array in index order, each `{index, kind, outcome, infrastructure, session_id}`, with no item name and no Veeam message.
     - `exit_code`: the status's code, before any change below.

     There is no `signature`, `tsa_token` or `bundle_sha256`. Until W4.1 the file is written pretty-printed; W4.1 brings the canonical form. A golden-shape test in `tests/test_command_test.cpp` on the Harness pins v0. It has one `GENERATE` row per way a run ends, and in each row every top-level key is present, with `null` where a step didn't run.
   - **When:** after the timings table and `on_timings`, whatever the status (`error` and stops included). A run that ends before its run line writes no file, as it prints no status line today (W3.3 build note 8 stays open).
   - **Last stdout lines:** on success `wrote <path>` is printed on stdout. This amends W3.5 point 4 for `test`: the timings table is no longer last. The last lines are now the table, then `wrote <path>`, then `recorded ...` with `--record`.
   - **Refused before anything runs:** the path is checked after the config is read and before the Veeam secrets, so an exe test needs no env. That is before the manifest, the mutex, `--record` and any Veeam call. These are exit 1:
     - `config error: --json <path>: not a UTF-8 path`
     - `config error: --json <path>: the file already exists`
     - `config error: --json <path>: the folder doesn't exist`

     A missing or repeated value is 64 with the usage line. Only the `config error:` form, the UTF-8 check (`path_from_utf8`) and exit 1 are shared with `--record`. Its other rules are new and stricter than `--record`'s. `--record` takes an existing empty folder, creates missing folders (`create_directories`, Q2.1 point 2), and is opened after the mutex.
   - **Atomic write:**
     - The JSON is built first and dumped with `error_handler_t::replace`.
     - It goes into a temp file in the same folder, `<file>.<16 random hex>.tmp`, opened with `CreateFileW` `CREATE_NEW`. The run ID is never part of that name: `check_run_id` allows `:`, which on NTFS would name an alternate data stream. A test covers a run ID that holds `:`.
     - Then `FlushFileBuffers`, then `MoveFileExW` with `MOVEFILE_WRITE_THROUGH` and without `REPLACE_EXISTING`, so a file that appeared since the check is never overwritten.
     - The temp file is deleted on any failure. `std::filesystem::rename` is not used because it replaces.
   - **Testing the write:** the writer sits behind a `RestoreCommandEnv` hook, `write_summary`, which defaults to the atomic writer.
     - The writer is tested on its own in a temp folder: a target that exists, a temp name that exists, a folder that doesn't exist, and a file that appears between the check and the move.
     - The command's rules are tested through the hook in a `GENERATE` table: 0 becomes 1, any other code is kept, and the status never changes.
   - **Content rules:** no secret. The file holds more tenant data than stdout, and `docs/verification.md` records this list:
     - `expected.items` carries sender addresses and names, Internet message IDs, sent and received times, and random mails' subjects and file names.
     - `sample.*.random.keys` carry mailbox addresses, folder names, mail subjects and received times, site and list IDs, folder paths, file names and OneDrive UPNs (`random_key`).
     - `sample.*.random.containers_listed` carries mailbox addresses and, for an unresolved OneDrive, its URL.
     - A `check` item's `reason` can carry the office-v1 reader's error text, which names a part of a tenant file. This is the one place `what()` text reaches the file. It is accepted here because it is W3.2's `check` object as approved (see Open).

     These are written as designed: they are the objects W4.1 signs, the file is local, and the owner chose its path.
   - **Write failure:** `json error: <path>: could not be written` on stderr. The status never changes. Exit 0 becomes 1, and any other code is kept. That is the same rule as `finish_recording` (Q2.1) and lost stdout (W2.8 second review point 4).

**Reason.**
- **One pipeline** means one guard, one mutex and one status table to trust and test. A second copy would drift.
- **Shared exit codes** let a script read `test` and `restore` alike. In the guide's mapping, 1 and 3 already mean config and transient.
- **A seed derived from the run ID** keeps a draw provable from what the result records.
- **Seeding real files** is the only way to run the random SharePoint and OneDrive restore and the `metadata` check live for the first time. Restating the Done when would hide that, and a short run already says `pass`.
- **The table's VERDICT and fixed REASON words** keep infrastructure from reading as a failure, and keep tenant file content off stdout.
- **The `--json` file** follows the existing output-loss rule, so nothing new decides an exit code.

**Alternatives rejected.**
- *The guide's 0/1/3:* fail would collide with config, and auth and service errors would collapse into 3 (W2.8 point 6, W3.3 point 6).
- *`--seed N` mapped to a run ID `seed-N`:* the printed seed would then be a hash and not N, and it couldn't be combined with `--run-id`.
- *`--seed` fed into the sampler:* it undoes the rule in `sample_selector.hpp` that only the run ID gives the seed, and the result wouldn't record it.
- *Restating the Done when only:* it leaves two paths untested.
- *`test` defaulting to 10/10/10:* the config's `sample_*` are documented as a test run's sizes, and the command named for the service pipeline would ignore them.
- *REASON printing `ItemCheck::reason`:* it would put a tenant file's part names on stdout.
- *Holding the JSON to stdout's data (no `random.keys`, no sender or IMID):* W4.1 would need a second shape.
- *Overwriting an existing `--json` file:* a scheduled script could lose an earlier run's summary.
- *A temp name from the run ID:* `:` is allowed in a run ID and names an NTFS stream.
- *`--json` on `restore` too:* nothing needs it yet.

**Open.**
- The Veeam session sweep (stopping our own `Working` sessions) that W3.4 handed to W3.6 is not settled here. A short entry comes before it is built.
- W3.3 build note 8: a status and a JSON file for failures before the run line (`no_restore_point`).
- `--keep`.
- The seeding is L1.8 (#152), built in W3.6's PR.
- W3.2's `to_json(ItemCheck)` keeps the office-v1 note in `reason` as approved (owner, 2026-10-03, approving this entry as written); a fixed word there is a later change if wanted.

**Docs and code to change with the build:**
- **Code:**
  - `src/run_pipeline.{hpp,cpp}` (from `run_restore`), keeping the selection record, the restore point and `RunVerdict` for an end-of-run `on_run(RunSummary)` hook.
  - `include/rp/test_command.hpp` and `src/test_command.cpp` (parser, table, `--json`).
  - A `to_json(RestoreResult)`, and an atomic file writer in `src/` behind the `write_summary` env hook.
  - The `test` branch in `src/cli.cpp`, and `kCliUsage` with its copies (`tests/restore_command_test.cpp` `kUsage`, `worker/CMakeLists.txt` `RP_USAGE`).
- **Tests:**
  - `tests/test_command_test.cpp` on the existing `Harness`: the golden shape, the table's VERDICT/REASON rows (an infrastructure item, an office-v1 mismatch), and the write-failure `GENERATE` table.
  - Writer tests, including a run ID that holds `:`.
  - Exe tests mirroring `restore`'s, plus the three `--json` refusals.
- **Docs:** `docs/worker-config.md` ("`rpworker test`" and the exit-code table), `docs/testing.md` (the Done-when command with the dry run's run ID and restore point), `docs/verification.md` (the file's tenant data), the W3.5 output order for `test`, and CLAUDE.md.
- **Lab:** `seed-real` with its refusals and tests, and `lab/README.md` and `lab/tenant.md`.

## 2026-10-03 — W3.5 review: a clock that fails changes nothing, and a stop ends its spans where it happens (proposed)

The `/code-review` of the W3.5 branch found readings for the timings that could change a run, and stopped spans that ran on past their stop. Fixed on the branch, with tests (`tests/step_timer_test.cpp`, and in `tests/restore_command_test.cpp` "a clock that throws at a reading for the timings alone changes nothing but that span" and "without env.now they run on the connector's clock"):

1. **A clock that throws at a reading for the timings alone changes nothing (amends build note 5).** Before, the readings at the boundaries of `restore_point_lookup`, `cleanup_before`, `sample_select`, `target_snapshot`'s start, `verify`/`recovery`'s end and `cleanup_after` used the throwing `StepTimer::now()` inside the run's `try`. A throw made the run `error internal`, or, around the clean after, skipped it and left the copies in the targets. Those readings now go through `StepTimer::try_now()` (`nullopt` when the clock throws). `start(span, nullopt)` leaves the span `not run`, and `end(span, nullopt)` leaves it open for good, `not closed`: no later end or stop gives it a duration it never had. The restore's own two readings (its line's time) and the check's stay on `now()`, as before W3.5: the run needs them.
2. **A stop ends what it interrupted at its own reading (amends the approved entry's point 4 table).** Before, a span a stop left open ended with `total`, after the status line and the whole clean after, so a stopped `restore` or `verify` included the cleanup. `finish` now ends every open span but `total` `stopped` on one reading as soon as it handles a stop (`StepTimer::stop_open(at, keep)`); `total` still ends after the clean after. `target_snapshot` no longer has its own stop reading: the same rule ends it.
3. **Submit and wait are `not reported` whenever the restore started and they weren't reported (amends build note 5).** The rule was "`restore` still open at the end". They are now reported from the sessions in place (`sum_session_durations(sessions, &RestoreSessionResult::submit_time)`, a template, no vectors built) before `restore` ends, nothing between that can throw, and `finish` marks them `not reported` on any stop once `restore` is no longer `not run`. The vector overload is gone.
4. **One clock for `restore` and for submit and wait.** `RestoreCommandEnv::now` null now falls back to `connector_options.now`, the clock the connector measures each session on, then `steady_clock::now`. A caller that sets both must set one clock. In production both are null.
5. **Smaller.** `StepTimer::state(Span)` reads one span (no copy of the table); the command's restore and check readings all go through the timer; `format_span` and the restore line's `H:MM:SS` share `format_hms` in `src/duration_text.hpp`.
6. **Docs.** `docs/testing.md` "Restore by hand" no longer calls the clean after's line the last; `on_cleanup`'s comment says the table and `on_timings` come after it.

---

## 2026-10-03 — W3.5 build notes: what the build settled beyond the approved entry (proposed)

The build follows the W3.5 entry below: its span names and boundaries, states, NOTE words, `H:MM:SS.mmm`, the `timings` JSON, `on_timings`, and submit and wait measured per session and summed. What it adds or settles where the entry was silent:

1. **Three more free functions in `rp/step_timer.hpp`.** `note(SpanState)` (the table's NOTE words), `format_timings(RunTimings)` (the table, through `src/text_table.hpp`) and `sum_session_durations(...)` (point 3's sum). The command and the tests share them, so the words and the sum rule live in one place.
2. **The sum's order of rules.** No sessions, or any session without a duration: `not_reported`, checked first. Then any negative session: `clock_backwards`. Otherwise the sum, held at `nanoseconds::max()` rather than wrapping (unreachable in practice).
3. **A hand-built `RunTimings`.** `format_timings` and `to_json` show a `measured` or `stopped` span whose duration is missing or negative as `clock_backwards`, and ignore a duration beside any other state. A `StepTimer` never makes either. A `Span` outside the enum is refused by every call (`false`).
4. **The TIME column is as wide as its widest cell.** `text_table` pads by content, so when no span has a duration (every reading went back), the header reads `STEP                  TIME  NOTE`, not the entry's example width. The values and words are as approved.
5. **Failures inside `finish`'s timing step.** An `on_timings` that throws is ignored. A clock that throws while `total` ends leaves what is still open as `open` (`not closed`). Neither changes a line, a status or an exit code. The submit and wait spans are marked `not reported` when `restore` is still open at the end, which is exactly when `restore_sample` threw.
6. **Coverage (point 6).** `step_timer` is not on `STRICT_NAMES`. `tests/step_timer_test.cpp` is written to reach every line of `src/step_timer.cpp`; CI's coverage run is where that is checked.

---

## 2026-10-03 — W3.5: step timings, one timer and named spans for `rpworker restore` (recorded before the build; the owner approved it as written, the four points of choice included)

W3.5 (#40) adds a timer that records named spans of one run. `rpworker restore` prints them as a table at the end of the run and hands them to the env as the result's `timings` object, which W4.1 adopts into `result.v1.json` as it adopts `status` and `cleanup`.

- New files: `rp/step_timer.hpp` and `src/step_timer.cpp`, namespace `rp::timing`.
- `connector::RestoreSessionResult` gains two optional durations.
- `RestoreCommandEnv` gains one hook.

The issue lists seven spans. Two later entries change that list, and this entry follows them; where it differs from the issue, it wins:
- W3.2 point 7's "total recovery time = restore start → last item verified" becomes its own span, `recovery`. `total` stays the whole run.
- W3.4 split the cleanup into two cleans, so `cleanup` becomes `cleanup_before` and `cleanup_after` (point 2).

**Decision.**

1. **The timer: `rp::timing::StepTimer`, a fixed set of spans on one injected steady clock. It never throws.**

   ```cpp
   namespace rp::timing {
   enum class Span { restore_point_lookup, cleanup_before, sample_select, target_snapshot,
                     restore, restore_submit, restore_wait, verify, recovery,
                     cleanup_after, total };            // the table's and the JSON's order
   inline constexpr std::size_t kSpanCount = 11;
   std::string_view to_string(Span) noexcept;          // "restore_point_lookup", ...

   enum class SpanState { not_run, open, measured, stopped, not_reported, clock_backwards };
   std::string_view to_string(SpanState) noexcept;     // "not_run", "open", ...

   struct SpanTiming {
       SpanState state = SpanState::not_run;
       std::optional<std::chrono::nanoseconds> duration; // only when measured or stopped; never negative
   };
   struct RunTimings { std::array<SpanTiming, kSpanCount> spans; };

   class StepTimer {
   public:
       using Clock = std::function<std::chrono::steady_clock::time_point()>;
       explicit StepTimer(Clock now);                                         // null: steady_clock::now
       std::chrono::steady_clock::time_point now() const;                     // one clock reading
       bool start(Span, std::chrono::steady_clock::time_point at) noexcept;   // false unless not_run
       bool end(Span, std::chrono::steady_clock::time_point at,
                bool stopped = false) noexcept;                               // false unless open
       bool report(Span, std::optional<std::chrono::nanoseconds>) noexcept;   // a connector's duration; false unless not_run
       void stop_open(std::chrono::steady_clock::time_point at) noexcept;     // every open span ends `stopped`
       RunTimings timings() const noexcept;                                   // reads no clock
   };
   std::string format_span(std::chrono::nanoseconds);  // "H:MM:SS.mmm", cut to the ms; negative: "-"
   nlohmann::json to_json(const RunTimings&);
   }
   ```

   - **Time points are passed in.** One clock reading can end one span and start the next. That lets spans share an instant exactly: `recovery` starts with `restore`, and it ends with `verify`.
   - **A misused span is ignored, and the first call holds.** That covers a second `start`, an `end` or `report` on a span that isn't in the right state, and a second `end`. The call returns `false` and never throws. These are bugs in the caller, and they must not throw inside `finish`, which is `noexcept`, or turn a run into `error internal`.
   - **A clock that goes backwards never yields a duration.** That means an end earlier than its start, or a negative reported duration. The state is `clock_backwards` and `duration` is unset. No zero, absolute value or negative number is ever made up.
   - **A span never closed:** `timings()` shows it as `open`, with no duration, and reads no clock. In the command, `finish` calls `stop_open` before it reads the timings, so `open` only ever appears through a bug, and a test pins that.
   - **The clock is `RestoreCommandEnv::now`,** which already times the restore and each item's `ms`. It falls back to `steady_clock::now`. No wall clock is used. The command's existing `now` lambda (`restore_command.cpp`, defined after `build_expected_set` today) moves up beside the state that outlives the try block, so `finish` and `clean_after` can use it.

2. **What each span covers in `rpworker restore`.** Each boundary is one reading of `now()`. Spans that share a boundary share the reading.

   | Span | Starts | Ends |
   |---|---|---|
   | `total` | Just before `source->list_restore_points(...)`, the run's first call to a service. | After `clean_after` returns (its line, `report_cleanup`, `on_cleanup`), just before the table. |
   | `restore_point_lookup` | Same reading as `total`'s start. | Just after `pick_point` returns a point. |
   | `cleanup_before` | Just before `cleaner->clean(before_run)`. | Just after it returns, before its line. `clean` is `noexcept`, so the span always ends `measured`. |
   | `sample_select` | Just before `sampling::choose_sample(...)`. | Just after it returns. Its `list_candidates` browse falls inside. |
   | `target_snapshot` | Just before `read_before(...)`. | On success, the existing `started` reading. On a returned failure, a new reading with `stopped`. |
   | `restore` | The existing `started` reading. | The existing reading after `restore_sample`. This is the same measurement the `restore <status>: … in H:MM:SS` line prints, and that line doesn't change. |
   | `restore_submit`, `restore_wait` | Reported by the connector (point 3). | |
   | `verify` | Same reading as `restore`'s end. | A new reading just after `verification::check(...)` returns. It covers writing the restore tables, the reads back with hashing, and the comparison. |
   | `recovery` | Same reading as `restore`'s start. | Same reading as `verify`'s end. This is W3.2's "restore start → last item verified": `check` gives every item's verdict in one call, after the reads. |
   | `cleanup_after` | Just before `cleaner->clean(after_run)` inside `clean_after`. | Just after it returns. It stays `not_run` when the clean after is skipped (nothing restored, or no Graph client). |

   - **Two cleanup spans, not one.** The two cleans run minutes apart, on either side of the restore, and they do different jobs: the first removes an earlier run's leftovers, the second removes this run's copies and is skipped when nothing was sent. A sum wouldn't be an interval. It would hide which clean was slow, and it would read the same whether or not the clean after ran. The issue's `cleanup`, and W3.2 point 7's, is these two names.
   - **`target_snapshot` and `restore` go beyond the issue's list.**
     - `target_snapshot` is W3.2's Graph read before the restore. Without a span, that time would be unattributed.
     - `restore` is the whole `restore_sample` call, already printed since W2.8. On one clock, `restore − restore_submit − restore_wait` is the connector's own preparation and result reading: guard layer 1, the restore-point recheck, the preflight, the explore sessions and browsing, then statistics and events. That remainder gets no span of its own.
   - **The spans overlap and don't add up to `total`.** `restore` contains submit and wait, and `recovery` contains `restore` and `verify`. Some time sits in no span except `total`: the run ID, the intro, making the Graph clients, the sample header, `build_expected_set`, the status line and its warnings. Everything before `total`'s start is local and service-free and is untimed: arguments, config, secrets, certificate, manifest, run lock, `--record` folder, and making the connector.
   - **The fake clock stays put.** No new reading falls between `started` and the restore's end reading, or between `read_after`'s clock calls and `check`'s. So the Harness's `restored in 0:02:03` and the per-item `123000`/`246000` ms don't change. RealRig's `rig.clock` only moves on `sleep`, so its `0:00:05` doesn't change either.

3. **How the connector reports submit and wait: two optional durations per session, summed by the command.**

   `RestoreSessionResult` gains the following. `rp/connector.hpp` gains `<chrono>` and `<optional>` and no Veeam type. The include scan in `tests/connector_test.cpp` checks file names only, and it still passes.

   ```cpp
   // This session's submit and wait, on the connector's own steady clock;
   // nullopt when the connector didn't measure it.
   std::optional<std::chrono::nanoseconds> submit_time;
   std::optional<std::chrono::nanoseconds> wait_time;
   ```

   In `RestoreRun::restore_call` both are measured with `c_.now`, the steady clock that the 20-minute poll deadline uses:
   - **Submit** runs from just before `c_.exporter->export_pfx(...)` to just after `sessions_.know(id)`. It covers the export, guard layer 2, the one POST, and the duplicate check, including `no_answer`'s three 10 s re-looks. Building the body comes before it and is pure.
   - **Wait** is the `poll(id, kind)` call, from its first GET to its return. Statistics (with their 409 waits), events and `judge` are result reading, not waiting, so they count only in `restore`.

   The command reports `restore_submit` and `restore_wait` to the timer as the **sum** over `result->sessions`. Sessions alternate submit, wait, submit, wait, so the sum is the time spent in each phase, while "first start to last end" would overlap the other phase. The sum is replaced by a state, never shown as a partial number:
   - a session without the duration, or a result with no sessions (the fake connectors): `not_reported`;
   - any negative session duration: `clock_backwards`.

   The command's and the connector's clocks are the same `steady_clock` in production and the same `rig.clock` in RealRig. Only durations cross the boundary, never time points.

   **When `restore_sample` throws,** its local `RestoreResult` is lost, as it is today. `restore` and `recovery` end `stopped` at `finish`'s reading. `restore_submit` and `restore_wait` are `not_reported`, not `not_run`, because a POST may have gone out. Nothing partial is carried out of the connector (see Alternatives and the owner's choice).

4. **Output: one table, last, after the `cleanup after` line.** `cleanup_after` and `total` are only known once the clean after is done.
   - At the end of `finish`, after `clean_after`, the command ends `total`, calls `stop_open`, then prints the table.
   - It does this for every run that printed its run line, the same rule as the status line.
   - With `--record`, `recorded <n> exchange(s) in <dir>` still comes after it.

   ```

   STEP                  TIME         NOTE
   restore_point_lookup  0:00:00.412
   cleanup_before        0:00:03.106
   sample_select         0:00:21.870
   target_snapshot       0:00:01.204
   restore               0:08:10.004
   restore_submit        0:00:04.120
   restore_wait          0:07:31.000
   verify                0:02:00.551
   recovery              0:10:10.555
   cleanup_after         0:00:05.200
   total                 0:12:41.880
   ```

   - All eleven rows always print, in `Span` order, laid out by `src/text_table.hpp`. TIME is `format_span`: `H:MM:SS.mmm`, cut to the millisecond, hours not capped. Whole seconds would read `0:00:00` for most steps. The existing `H:MM:SS` columns and the restore line don't change.
   - A span without a duration prints `-`. NOTE is empty for `measured`. Otherwise it is one fixed phrase: `stopped`, `not run`, `not reported`, `clock went back`, or `not closed` (the last only through a bug). It never holds a tenant value or `what()`.
   - **Stdout lost** (`output_lost`): no table, and nothing goes to `err`, which already carries the status. `on_timings` is still called.
   - **A table that fails to write** changes nothing. That includes the exit code, as with the `cleanup after` line.
   - Timings never change a status, a warning or an exit code.
   - The order of the last lines becomes: status line, its warnings on `err`, `cleanup after …`, the table.

   **Each early stop** (one row of the command test's `GENERATE` table):

   | Stop | Spans |
   |---|---|
   | Before the run line: usage, config, manifest, cursor, run lock, `--record` folder, connector, `list_restore_points` error, no point or an unknown point, bad run ID | No table and no `on_timings`. Stdout stays empty, as today, so no ctest exe test changes (all eight `restore` ones stop before any request). |
   | Clean-before `target_guard` | lookup, `cleanup_before` and `total` measured. The rest `not run`. |
   | `choose_sample` throws | `sample_select` `stopped`. Later spans `not run`, except `total`. |
   | Empty sample | Measured through `sample_select`. Later spans `not run`, except `total`. |
   | Reads before fail | `target_snapshot` `stopped`. Later spans `not run`, except `total`. |
   | `restore_sample` throws (with or without `kNothingRestored`) | `restore` and `recovery` `stopped`. Submit and wait `not reported`. `verify` `not run`. `cleanup_after` measured if the clean after ran, else `not run`. |
   | Reads back or the check throws | `verify` and `recovery` `stopped`. Submit and wait as reported. `cleanup_after` measured. |
   | A target's read-back Graph error | Not a stop. The spans are as on a normal run. |
   | Normal run, pass or fail | All measured. Submit and wait as reported. |

   `total` is always measured, or `clock_backwards`, once the run line is out. It ends after the clean after, so it is never `stopped`.

5. **JSON for W4.1: the result's `timings` object.** It is handed to the new `RestoreCommandEnv::on_timings(const timing::RunTimings&)`, called once, after the table (or where the table would have been), for every run that printed its run line. W3.4 point 7 has the same form: fixed keys, `null` for what didn't run, an optional key left out when unset.

   ```
   {"spans": {"<span>": {"ms": <int >= 0>, "note"?: "stopped"}
                      | {"note": "not_reported" | "clock_backwards" | "open"}
                      | null}}
   ```

   - All eleven span names are always keys. `null` means `not_run`.
   - `ms` is whole milliseconds, cut toward zero, from the steady clock only. It is the unit W3.2's `check.items[].ms` uses. No wall times and no tenant values.
   - `to_json` lives in `src/step_timer.cpp`. W4.1 adopts it into `result.v1.json`, which doesn't exist yet.

6. **Coverage.** `step_timer` is not on `STRICT_NAMES`. Its tests still reach every line of `src/step_timer.cpp`, and the build notes will say so. rpcore's 80% floor is unchanged.

**Reason.**
- Fixed span names keep the table, the JSON keys and the tests stable. A string API would let a typo add a span.
- Passing time points in and sharing readings makes `recovery` exactly `restore` + `verify`. It also puts no new reading where the tests' fake clock is already measured.
- Never making up a duration follows "never claim more than was tested". Not run, stopped, not reported and clock-backwards each read differently, both in the table and in the JSON.
- Per-session durations keep the connector neutral, sit beside Veeam's own per-session start and end strings, and are testable on `FakeClock` with the recorded fixtures.

**Alternatives rejected.**
- *One `cleanup` span, or `cleanup` with `before`/`after` parts:* it hides which clean took the time, and it is a second JSON shape kept only to keep a name.
- *`total` = restore start → last item verified:* that is `recovery`. Folding it in loses the run's own time.
- *A timer pointer or sink on `RestoreSpec`, or `IConnector::last_timings()`, to keep the submit and wait of a restore that threw:* it adds a second way for results to leave the connector, and puts a non-data member on the spec the guard checks. `restore` (`stopped`) already gives that run's time. Revisit if W4.1 needs it.
- *Timings carried on the connector's exceptions:* every throw site and error type would change.
- *Statistics' 409 waits and events counted as `restore_wait`:* they read results, bounded at 30 s. "Wait" means Veeam still running.
- *A span for explore and browsing:* it is `restore − submit − wait` on one clock.
- *Printing the table before the status line:* `cleanup_after` and `total` aren't known then.
- *Moving the table to `err` when stdout is lost:* `err` already carries the status and the cleanup. Timings decide nothing.
- *Absent keys for spans that didn't run:* W3.4's `before`/`after` are `null` when they didn't run. This entry follows that.
- *Throwing on a misused span:* it would stop a run over a timing bug, inside `noexcept` code.

**Open.**
- W3.6 (`rpworker test`) uses the same timer and the same placements. W4.1 writes `timings` into `result.v1.json` through `on_timings`.
- Docs to change with the build:
  - `docs/worker-config.md`, "`rpworker restore`": the sample run block gains the table; a new **Step timings (W3.5).** bullet; the status bullet's and the cleanup bullet's claims about which line comes last.
  - `docs/verification.md`, lines ~197 and ~520: point to this entry and to `cleanup_before`/`cleanup_after`.
  - `include/rp/restore_command.hpp`: the comments on `now` and `on_timings`, and the comment at ~249 ("The total is restore_sample's own time").
  - `docs/glossary.md`: **span**, **recovery time**.
  - CLAUDE.md's status paragraph: W3.4 ran live on 2026-10-02 (evidence `docs/api/veeam-lab/w3.4-live-*`, commits 28ea8ee and 4327fa6) and merged as PR #149, with its review fixes in 1e2f12e. Add W3.5.

---

## 2026-10-03 — W3.4 PR review: one refused delete no longer stops its target (proposed)

**Decision.** In the Cleaner's delete loop, a `GraphError` on one item that is neither a
`TransientError` nor an `AuthError` (a locked or checked-out file's 423/409, a labelled mail's
403, any answer `remove()` can't use) is that item's: it is logged with its code, the other
listed items are still deleted, and the target is listed again. If something is left after
that, the target's `error_code` is the first refused delete's code and there is no second
round (Graph would refuse it again); if nothing is left, there is no error. A `TransientError`
still ends the round and an `AuthError` (a 401 after a fresh token) still stops the target.
The live cleanup test now doubles only a first delete Graph answered 204, and opens its
`RP_LIVE_RECORD_DIR` before it seeds anything.

**Reason.** The PR #149 review: Graph lists in a stable order, so one undeletable item stopped
every later clean at the same place and copies piled up behind it (and went into the nightly
backup). The live test's doubling was used up by a transient first answer, and a reused
recording folder threw after the seeds were written, leaving them in the targets.

**Alternatives rejected.** A second round for a refused delete — doubles the writes when a
grant is missing, for an answer that won't change in seconds. Counting refused items in a new
`TargetCleanup` field — the result's `cleanup` object would change shape for what `left` and
the code already say.

---

## 2026-10-02 — W3.4 build notes: what the build and its review settled beyond the approved entry (proposed)

The W3.4 entry below was approved as written. These are the points where the build differs from its letter, or settles what it left open, after the build and its review. None widens a grant or changes a status, an exit code of a decided run, or what may be deleted.

1. **A target past the page limit (point 2).** `list_pages` gains a bounded mode (`past_limit`), used only by the Cleaner: a listing stops at `kMaxListPages` pages without an error, the link past the last page still checked by the target's rule but never fetched, and a warning says the target lists more. The Cleaner deletes what it listed, so such a target ends with `left > 0` as point 2 says. Before the review it threw (`graph`, nothing deleted), which would have stopped every later clean at the same listing. `TargetReader` keeps the throw. `left` is the count of the last listing, so it never exceeds that many pages' worth.
2. **The root's ID (point 4.4).** The Cleaner never reads the library root's ID. It refuses an entry whose ID is its own `parentReference.id`; in the library the parent must be the root (`parentReference.path` is the drive's root), so that is the root's ID, and an entry with a `root` facet is never deleted either. In OneDrive the parent must be the folder, which covers "not the folder's own ID".
3. **`rounds` is 1 or 2** once `clean()` has run, never 0 (point 2's comment).
4. **Round 2 after other errors (point 6).** Only something left (a 412 included) or a `TransientError` starts round 2; `graph` and `internal` get none either, besides the four the entry names. Each round runs the guard's checks again.
5. **The stderr lines (points 7 and 8).** A failing target's line is `cleanup error: <target>: <fixed text per code> (<code>)`, and a not-ok target's warning `warning: cleanup: <target> not emptied <before|after> the run (left n, skipped m[, code])`. The stdout lines are as decided, counts and codes only. The Cleaner's own log lines go to the command logger (stderr, warn and worse) and, like `TargetReader`'s, may carry Graph's message and a skipped entry's ID through `redact()`, so the owner can find what to remove by hand (`docs/worker-config.md`).
6. **An abandoned mutex (point 8).** "Counts as taken" for that one try: the run is refused, exit 4, with no run line, and the mutex is released at once so the next run takes it; keeping it would lock the Worker out until a reboot, and the next run's clean-before takes up what the crashed run left. Since no run holds it, the refusal says so: `restore error: the last RestoreProof run ended without releasing the restore targets; nothing was done; the next run cleans them before it restores` (`rp::AbandonedRunLock`). `ERROR_ACCESS_DENIED` (another user's run made it) counts as taken.
7. **`restore_may_still_run`** is set for any stop in the restore phase without `nothing_restored`, a `config` or `internal` stop there included, since `RunStop` doesn't tell them apart.
8. **`remove()`'s own last check.** The Cleaner's rules are stricter, so no test can drive `GraphClient::remove` into its refusal through the Cleaner. The rule is a pure function, `is_sendable_item` in `src/graph_write_rule.hpp`, used only by `graph_client.cpp` and tested on its own (`tests/graph_write_rule_test.cpp`), not through a test-only way to make a `ListedItem`, which would undo point 3. `send()`'s separate check of its own header values went with it: its only caller's values are the checked eTag and a constant.
9. **The live tests (point 9).** The live cleanup test sends the Cleaner's first file `DELETE` and first mail `permanentDelete` twice through a test-side wrapper, checks the second answer was counted `gone`, and with `RP_LIVE_RECORD_DIR` records its Graph exchanges through `rp::RecordingHttpClient`. The live restore test makes its Cleaner before `restore_sample` and cleans on every way out, a throw or a failed `REQUIRE` included.
10. **The lab probes (points 1 and 9).** The OneDrive refusal canary is confirmed as its owner, alice, and the library one as the admin: each canary file is readable by its uploader, so `check-worker-app` signs in twice. `_check_write` is now a second layer of its own: a create goes only into a target itself (the library's root, alice's `/RestoreTarget` folder, `restoretest`'s messages), and a delete must name exactly the item the create's reply proved, never a target folder or a canary file of `lab/seed-manifest.json`. The list grant's POST uses `grantedToV2.application.id` like the folder grant; if the live run rejects it, the key becomes `grantedTo`.
11. **`kMailPrefer`** moved to `rp/graph_client.hpp`, and `remove()` sends all of it as the mail's Prefer (its `IdType` is what matters). The bodiless POST relies on curl's own `Content-Length: 0`; the live probe settles whether Graph wants it.
12. **The canary refusal probe, redesigned after a live run (amends point 9 of the approved entry; superseded by point 13, kept as history).** On 2026-10-02 `check-worker-app`'s refusal probe at `rp-canary-01.pdf` in the RestoreTest library, `PATCH {}` with `If-Match: "rp-probe-no-such-etag"`, got 412, not 403 or 404, and the check failed (412 was already UNEXPECTED). alice's OneDrive canary got 404, as expected: the app can't read that folder. The owner then listed the grants read-only (as the admin, `Sites.FullControl.All`): the RestoreTest site has `read` for RestoreProof Worker; the canary library's list (`7eb0f08a-…`) has only the inherited site groups and the owner, nothing for the app; `rp-canary-01.pdf` has only inherited grants; the RestoreTarget list has unique permissions with `write` for one application, but the listing printed that application's name empty, so it didn't show the grant is RestoreProof Worker's: the controls' 400 in the live re-run, or a listing that prints `grantedToV2.application.id`, settles that. So the canary side of the grants is right, and SharePoint checks `If-Match` before write permission on an item the app may read: on a readable location the `PATCH` can't tell "refused" from "allowed but stopped by the ETag". The probe at each canary location is now a folder create with a name SharePoint never accepts, in the canary file's own folder: `POST /drives/{canary drive}/items/{root or canary folder}/children` with `{"name": "rp-probe-invalid:name", "folder": {}, "@microsoft.graph.conflictBehavior": "fail"}` (`INVALID_NAME`, `INVALID_FOLDER_BODY` in `seeder/worker_app.py`). 403 or 404 passes (404 only after the canary file's uploader has confirmed it, as before); 400 (past the permission check, stopped only by the name: the app may write there), any 2xx (the row says to remove it by hand), 409, 412 or anything else fails. Nothing can be created, and no request names a canary file's ID any more, only the folder. A **control** is added in each file restore target, the RestoreTarget library's root and alice's `/RestoreTarget` folder: the same create, expected 400, to show what "allowed" looks like, so a canary's 403 is a refusal and not a request SharePoint rejects for everyone; anything but 400 there fails the check (403 or 404: no write in the target; a 2xx: created something, remove it by hand). `_check_write` allows exactly that create in those two folders and nothing else new, and `run_refusal_probe` refuses to send a canary anything but that exact request. The fake tenant now answers a wrong `If-Match` 412 wherever the app may read (as seen live) and the invalid-name create 403/404 where it may not write and 400 where it may, so the earlier misgrant test (write on the canary library) now shows 400. If a live run ever shows a canary answering 400 (SharePoint validating the name before permission), the check fails, as it must, and telling a refusal apart would need yet another design, never a pass. Point 9's rule stands: at a canary, one request that is refused and could change nothing even if a grant were wrong. But what the probe covers narrowed: the `PATCH` named the canary file, the create names only its folder, so a write grant on one canary file alone (`Files.SelectedOperations.Selected` allows one on a single driveItem) leaves the folder's 403 or 404 and the check passes (`test_a_write_grant_on_one_canary_file_is_not_seen_by_the_folder_probe` pins it). The probe catches a write grant on the canary library's list, the site or alice's canary folder; a grant on a single canary file shows only in a read-only listing of its permissions like the owner's. Automating that listing in `check-worker-app` (the admin's and alice's delegated sign-ins, failing on any application grant on a canary file, folder or list) is left open: the seeder app's delegated scopes have not been tried live for it, and the owner's listing used `Sites.FullControl.All`. `lab/README.md` and `docs/security/graph-permissions.md` ("How each refusal is verified") have the details.
13. **No write probe at a canary: the refusal is proven by reading the grants (supersedes point 12's probe and controls; the owner chose this, "option 1", on 2026-10-02).** The live re-run with point 12's probe (2026-10-02; 24 of 26 rows as expected, its output saved as `docs/security/w3.4-worker-app-check.txt` until the re-run replaces it) got 400 from the invalid-name folder create at **both** canary locations: the RestoreTest library's root, and alice's `/RestoreTest` folder, which the same app gets 404 on for a plain `GET` (it can't even see it). The two controls in the restore targets got 400 too, and the three create/delete pairs passed. So Graph validates the name before any permission check, and a 400 says nothing about access: point 12's probe can't tell a refusal either, and the case its last sentences foresaw has happened. With the 412 of the `PATCH` (point 12) that is two designs a live run defeated; any request that could get past Graph's other checks to the permission check would risk a real write at a canary, which point 9 forbids. So no write probe is sent at a canary at all, and the proof is the grants: in Microsoft's selected-permissions model access comes only from an application grant on the resource or on a securable parent it inherits from ([Overview of Selected permissions](https://learn.microsoft.com/graph/permissions-selected-overview), "How access is calculated"), so no Worker app grant on a canary or above it means no access through a grant (and, point 14, with no tenant-wide role, no access at all). **A.** A new read-only script, `lab/entra/check-worker-grants.ps1`: `Connect-MgGraph` as the admin with only `Sites.FullControl.All` (the scope the owner's listing used; reading grants needs it), GETs only, `Disconnect-MgGraph` in a `finally`; the Worker app matched by its client ID (`737da5ef-…`, the script's `$WorkerAppId`) from `grantedToV2`, `grantedTo`, `grantedToIdentitiesV2` or `grantedToIdentities`, never by name (the live listing printed an empty name on the RestoreTarget list's grant). Required: on the RestoreTest site exactly one Worker app grant, roles exactly `read` (each of its grants read by ID, since a site's list may leave roles out); on the canary library's list and each of its 10 canary files no Worker app grant of its own, an inherited one only with roles `read`; on alice's OneDrive root, her `/RestoreTest` folder and its 10 canary files no Worker app grant at all; on the RestoreTarget list and alice's `/RestoreTarget` folder exactly one non-inherited Worker app grant, roles exactly `write`. The 20 canary files come from `lab/seed-manifest.json` (fewer, one outside its canary drive or a manifest that can't be read: it refuses to run and reads nothing); `@odata.nextLink` is followed within Graph v1.0 only; a failed GET is a problem, never a pass; another application's grant is a note. One line per location, then `canary grants: ok` (exit 0) or `canary grants: N problem(s)` (exit 1). The constants are its own, pinned to `seeder/tenant.py` and to `new-worker-app.ps1`'s by `lab/tests/test_entra_script.py` (the style of the existing scripts); the rules are a pure function, `Test-PermissionRule`, tested row by row through `pwsh`, failure rows first, and the whole script with `Invoke-MgGraphRequest` stubbed. `new-worker-app.ps1` runs it at its end, after the grants and in its own Graph session (`-UseCurrentSession -AppId $appId`), and stops before the Exchange step on a problem. It also sees what point 12's folder probe couldn't: a write grant on a single canary file. **B.** `check-worker-app` drops the canary write probes, the controls, the canary file confirmations and the admin sign-in that existed only for them (`INVALID_NAME`, `INVALID_FOLDER_BODY`, the refusal and control code, the fake tenant's folder-create and `PATCH` routes and its single-item grant); alice's sign-in stays, for the L1.5 canary folder confirmation. It keeps the GET probes (the read refusals included: alice's canary folder 404, alice's mailbox 403) and the create/delete pairs in the three restore targets; `_check_write` allows only those creates and proven deletes. A test runs it against the fake tenant, with the grants as set up and with a write grant on the canary library or alice's canary folder, and checks that no request but a GET goes to a canary location, none names a canary file and no folder create is sent anywhere. Its header says the canary write refusal is checked by `lab/entra/check-worker-grants.ps1`. **C.** `lab/README.md` and `docs/security/graph-permissions.md` describe the grant check and why no write probe can do its job; the evidence is `docs/security/w3.4-worker-grants-check.txt` next to `w3.4-worker-app-check.txt`. Point 9's rule stands, more strictly: no write at a canary at all. The failed run (24/26, both canaries 400) is kept as evidence in `docs/security/w3.4-worker-app-check-invalid-name-400.txt`.
14. **The grant check's review (2026-10-02, amends point 13).** Five gaps, each fixed test-first in `lab/tests/test_entra_script.py`. (a) **Every parent is read.** Point 13 read alice's OneDrive root, canary folder and files, but not her OneDrive site or its Documents list, both securable parents: a `Sites.Selected` or `Lists.SelectedOperations.Selected` grant there would reach her canary folder, and nothing says Graph would show it as an inherited driveItem entry. The script now resolves them read-only (her site by its URL, `$OneDriveHost` and `$AliceSitePath`, pinned to `seeder/tenant.py`; the site's drive must be her OneDrive drive; the list through `GET /drives/{her drive}/list`) and requires no Worker app entry on either; a resolve that fails is one problem and their grants aren't read. Likewise the canary library's root folder, the driveItem its 10 canaries sit in, is read with the canary list's rule, and the manifest must put each library canary in the canary list's root (`list_id`, `folder_path` `/`) and each OneDrive canary in alice's canary folder (`folder_id`), so the parents read are the files' own. (b) **Matched failing closed.** A permission that names the client ID anywhere, not only as `application.id` (SharePoint can show an app principal as a `siteUser` with `i:0i.t|ms.sp.ext|<app id>@<tenant>`), is the Worker app's; another application in that form is a note. (c) **A reply without a `value` list is a problem**, never an empty, passing listing. (d) **The tenant-wide roles are the other half of the proof.** A role such as `Sites.ReadWrite.All` would reach every canary with no grant listed; `check-worker-app`'s token-roles rows check those, so the evidence is both runs, and the script prints that on its second line (`scope: …`). (e) `docs/security/graph-permissions.md`'s open item 1 said "Closed" with evidence not yet recorded: it is "Decided; live proof pending" until both runs are saved. Also, the fake tenant's `DELETE` answers a wrong `If-Match` 412 wherever the app may read, before the write check, as the live `PATCH` did (point 12); point 13's rewrite had reversed that. Still assumed, not seen live: that a list's `/permissions` gives `roles` (if not, the check reports roles `''` and fails rather than passes).
15. **A repeated `permanentDelete` answers 403 `ErrorCannotDeleteObject`, not 404, and the purged message still answers by its ID (amends point 3's `RemoveOutcome` rule of the approved entry; found live, two runs).** *First run.* On 2026-10-02 the live cleanup test (`cleaner_live_test`, by the owner's request; output `docs/api/veeam-lab/w3.4-live-1-cleaner-test.txt`, recorded with `RP_LIVE_RECORD_DIR`, `rp-w34-rec-cleaner-20261002T204648`) sent the Cleaner's first file `DELETE` and first mail `permanentDelete` twice. The library's second `DELETE` got 404 `itemNotFound` and counted `gone`, as designed. The mail's second `POST /users/{mailbox}/messages/{id}/permanentDelete` got **403 `ErrorCannotDeleteObject`** ("Object cannot be deleted."), so `GraphClient::remove` threw a `PermissionError` naming the mail grant and the mail target ended `graph_permission`, left 1; yet the final `$top=1` Inbox listing was empty, so the first `permanentDelete` (204) had purged the mail. Exchange answers a `permanentDelete` of a message already purged with that 403. The same happens in production whenever `GraphClient` resends a `permanentDelete` whose first answer was lost (writes are retried like GETs, point 3), so a successful clean would end `graph_permission`. A first fix followed the 403 with `GET /users/{mailbox}/messages/{id}?$select=id` and took a 404 as gone, a 200 as the refusal standing. *Second run.* The rerun at 21:05 (`rp-w34-rec-cleaner-20261002T210555`) got the same 403 (`graph/004`), and that GET answered **200** (`graph/005`) although the test's final Inbox listing was again empty. A read-only probe right after showed why: `GET /users/{mailbox}/messages/{id}?$select=id,parentFolderId,subject` with `Prefer: IdType="ImmutableId"` answered 200 with `parentFolderId` `AAMk...AAAAAAFiAAA=`, while `GET /users/{mailbox}/mailFolders/inbox?$select=id` (same Prefer) answered `AAMk...AAAAAAEMAAA=`: a purged message lives on in Recoverable Items (Purges) and still resolves by its ID; `GET /users/{mailbox}/mailFolders/inbox/messages/{id}` answered 200 too (Graph ignores the folder in that path, so it can't be the check). Both folder IDs come back in the same form with that Prefer. **The rule:** in `remove()`, for a mail only, a 403 whose Graph code is `ErrorCannotDeleteObject` is followed by one check, is the message gone (`GraphClient::purged_or_gone`), at most three GETs, all with `Prefer: kMailPrefer` and every path built by `remove()` from the `ListedItem`'s mailbox and ID alone, never from a response: `GET /users/{mailbox}/messages/{id}?$select=id,parentFolderId`; only after its 200, `GET /users/{mailbox}/mailFolders/recoverableitemspurges?$select=id`; only if that doesn't match, `GET /users/{mailbox}/mailFolders/inbox?$select=id`. `gone` is a positive answer only: the message GET's 404 `itemNotFound`/`ErrorItemNotFound` is `RemoveOutcome::gone`, with no folder GET; a non-empty string `parentFolderId` equal, byte for byte, to the Purges folder's non-empty string `id` is `gone` (the message is where `permanentDelete` puts it), with no Inbox GET. Equal to the Inbox's `id`, byte for byte, the original `PermissionError` stands (naming the mail grant, its message the POST's with the 403 code). Equal to neither (a message moved to another folder, an ID in another form, one differing in case only) fails closed: a `GraphError` saying the message is in another folder of the mailbox and isn't counted gone, never `gone`. Everything else fails closed too, an error and never `gone`: any GET's own error (its 403, a 5xx after the retries, a 404 of a folder or naming a missing mailbox), any other status a `GraphError` ("where 200 or 404 was expected" for the message, "where 200 was expected" for a folder), a reply that isn't a JSON object or whose `parentFolderId` or `id` is missing, empty or not a string a `GraphError` saying it can't be read. At most these three GETs per 403, no loop. Any other 403, and every 403 on a file `DELETE`, is unchanged: a `PermissionError` with no GET. The GETs only read; they need nothing beyond the mail grant the Cleaner already uses (the guard reads the same Inbox, and the Purges GET answered under the Worker app's Exchange scope, below). Tests first in `tests/cleaner_test.cpp`: the message in the Inbox (`PermissionError` naming the mail grant, three GETs); a `parentFolderId` missing, empty, not a string or a reply not a JSON object (no folder GET); the message GET's errors (403, 503s, a missing mailbox, 412, 302); the Purges GET's errors (403, 503s, a missing mailbox, a 404 for the folder, 302) and an unreadable Purges reply or `id` (no Inbox GET); the Inbox GET's errors and an unreadable Inbox `id`; a `parentFolderId` equal to neither folder (Purges's or the Inbox's ID in lower case, another folder) an error, never `gone`; a file's 403 with that code and a mail's other 403 sending no GET; the message's 404 counted `gone` with no folder GET; the live case, the `parentFolderId` equal to the Purges folder's ID, counted `gone` with no Inbox GET and the round's listing again empty; and a `permanentDelete` resent after a dropped connection. The recorded 403 is `tests/fixtures/graph/w34-mail-permanentdelete-403-cannotdeleteobject-repeat.json` (first run), the recorded 404 replaces the hand-written `w34-file-delete-404-itemnotfound.json`, `w34-mail-get-200-purged-parentfolder.json` is hand-shaped from the second run's `graph/005` with its `parentFolderId` exact from the read-only probe of 2026-10-02 (below), and `w34-mail-purges-200-id.json` is that probe's Purges folder reply, narrowed to `$select=id`; the Inbox's ID is `mailbox-inbox-200.json`'s, the same as that run's `graph/002`. The hand-written Exchange 404 `w34-mail-permanentdelete-404-erroritemnotfound.json` was never seen live; it stays for a message someone else deleted between the listing and the delete, and as a message GET's 404. **Review: the first rule failed open; a positive Purges match answers it (owner-directed, 2026-10-02).** The rule as first built counted a mail `gone` when its `parentFolderId` differed from the Inbox's ID. The review found that this fails open: a message that sits in some other folder of the `restoretest` mailbox when the 403 comes, or two GETs returning folder IDs in different forms (Graph honouring the ImmutableId Prefer for one and not the other), would count a mail `gone` that is still in the mailbox, and the Cleaner's Inbox-only listing would never see it again. That "out of the Inbox" rule is rejected. The answer is a positive match: `gone` only when `parentFolderId` equals, byte for byte, the ID of the mailbox's well-known `recoverableitemspurges` folder, and an error when it equals neither that nor the Inbox's. The one doubt about that alternative, whether the well-known folder's GET answers under the Worker app's Exchange scope, was settled by a read-only probe on 2026-10-02: `GET /users/restoretest@RestoreProofLab.onmicrosoft.com/mailFolders/recoverableitemspurges?$select=id,displayName` with `Prefer: IdType="ImmutableId"` answered 200, `displayName` `Purges`, `id` `AAMkADYyNGRlZDhkLTM1MmEtNGI1NS05Y2I5LTM4OTliNzZhMTRjOAAuAAAAAADjrcyzRbMCTbaiTPZo3n0vAQCnL_u8BR8BT6morC7OYUFaAAAAAAFiAAA=`, byte for byte the purged probe message's `parentFolderId`; the Inbox's `id` is `...AAAAAAEMAAA=`. A purged message in Purges is the one case that counts; anything else stays a leftover the target stops on, never a mail counted gone. The live test should now pass its mail checks; rerunning it is left to the owner.

**Done live on 2026-10-02:** the grants, `check-worker-app` 22/22 and `check-worker-grants.ps1` "canary grants: ok" (`docs/security/w3.4-worker-app-check.txt`, `docs/security/w3.4-worker-grants-check.txt`); they settle the entry's first three live probes (list `write` allows a `DELETE`, folder `write` a child's, `permanentDelete` takes the ImmutableId). Also done live on 2026-10-02: the first `rpworker restore --record` (status pass, 11 of 11, cleaned before and after; its recording is `worker/tests/fixtures/recordings/w34-live-run1/`, replayed by a test, and replaced the hand-written listing and 204 fixtures), the Done-when (`rpworker graph list` 0 in all three targets, `docs/api/veeam-lab/w3.4-live-2..4-*`) and `cleaner_live_test` (35 of 35, `docs/api/veeam-lab/w3.4-live-1-cleaner-test.txt`, after point 15). **Still open:** emptying restoretest's Deleted Items by hand once (the Cleaner never reads it); the 403 and 412 fixtures stay hand-written.

---

## 2026-10-02 — W3.4: cleaning the restore targets before and after each run (recorded before the build; the owner approved it as written, the run mutex, the status line before the clean-after, the clean-before guard stop and the by-hand emptying of Deleted Items included)

W3.4 (#39) adds the code that empties the three restore targets: the `restoretest` mailbox's Inbox, the **RestoreTarget** library in the RestoreTest site, and alice's OneDrive **/RestoreTarget** folder. The new class is `rp::graph::Cleaner`, in `rp/cleaner.hpp` and `src/cleaner.cpp`, and `GraphClient` gains one narrow write member. Nothing here deletes in, or names, the RestoreTest library or alice's /RestoreTest folder, which hold the canaries (2026-09-25). This builds on the W3.2 live run's Open items and the W3.3 second review's `restore_sent`. The issue text is older than 2026-09-25 and L1.5, so CLAUDE.md and this log win on three points:
- the targets are RestoreTarget, not RestoreTest;
- there is no `Sites.Selected` write, no `Files.ReadWrite.All` and no application access policy;
- the issue's `Cleaner::clear()` and `DELETE /users/{u}/messages/{id}` become points 2 and 5 below.

Copies from W2.5, W2.8 and W3.2 are still in the targets: 5 mails, 3 SharePoint files and 3 OneDrive files (`w3.2-live-6`). The first live clean removes them.

**Decision.**

1. **Permissions: the narrow write grants of `docs/security/graph-permissions.md` "Open items" 1, and nothing wider.**

   | # | Grant | Change | How |
   |---|---|---|---|
   | 1 | `Sites.Selected` `read` on the RestoreTest site | unchanged; listing the library still relies on it | `POST /sites/{site}/permissions` |
   | 2 | `Files.SelectedOperations.Selected` on alice's `/RestoreTarget` folder | `read` becomes `write` | the existing POST/PATCH in `new-worker-app.ps1` |
   | 3 | Exchange RBAC on the scope `RestoreProof Worker - restoretest mailbox` | `Application Mail.Read` becomes `Application Mail.ReadWrite`; the assignment is renamed `RestoreProof Worker - Application Mail.ReadWrite - restoretest`, and the script's extra-assignment loop removes the old one | `New-ManagementRoleAssignment` |
   | 4 | **new** `Lists.SelectedOperations.Selected` `write` on the RestoreTarget list only | a new Entra application permission, with admin consent | `POST /sites/{site}/lists/{list}/permissions`, `roles: ["write"]` |

   - The token's `roles` claim goes from two roles to three: `Files.SelectedOperations.Selected`, `Lists.SelectedOperations.Selected` and `Sites.Selected`. `$GraphRoles` and `EXPECTED_ROLES` change together; `check-worker-app` still fails on any `Mail.*`, `*.All` or Exchange/SharePoint-audience role.
   - **The script checks what it is about to make writable.** A new lab constant `$RestoreTargetListId` joins `$SiteId`, `$OneDriveDriveId` and `$OneDriveTargetFolderId`. Before the POST or PATCH that gives `write`:
     - the script GETs the list (`$select=id,displayName,webUrl`) and refuses unless `displayName` is `RestoreTarget` and so is the webUrl's last segment;
     - it GETs the folder (`name`, `parentReference.path`) and refuses unless it is `RestoreTarget` directly under the drive root.

     This mirrors `check_restore_library` and `check_restore_onedrive_folder`.
   - **`lab/tests/test_entra_script.py`:**
     - `test_the_canary_locations_are_never_named` stays.
     - A new test requires `$RestoreTargetListId` to equal `tenant.RESTORE_TARGET_LIST_ID` and the list-permissions POST to use only that variable.
     - A new test requires each `write` grant to sit behind its name check.
     - `test_grants_are_read_only` (lines 60-64) becomes "the only `write` grants are the RestoreTarget list and folder, and the only mail role is `Application Mail.ReadWrite`". Its assert that `Application Mail.ReadWrite` is absent is dropped.
   - **What Microsoft documents.** Microsoft's selected-permissions overview (learn.microsoft.com/graph/permissions-selected-overview, checked 2026-10-02) says three things. A list, folder or file grant breaks inheritance on that resource. The result doesn't depend on the path (`/drives/{d}/items/{i}` or `/sites/{s}/lists/{l}/items/{i}`). `write` means "read and modify the metadata and contents". It also notes a service limit on unique permissions. Only two points are left implicit there: whether `write` allows a DELETE, and whether folder `write` allows deleting a child. Probes settle both (Open).
   - **Residual risks:**
     - `Mail.ReadWrite` lets the app change or delete any item in `restoretest`. That mailbox exists only for this.
     - List `write` covers every item in the RestoreTarget library. Folder `write` covers the `/RestoreTarget` folder itself, and deleting that folder would drop the grant (point 4 never deletes a folder). Neither grant reaches a sibling list or folder.
     - `Sites.Selected` `read` still lets the app read the canary library, as today.
     - A wrong ID in a grant call would give write elsewhere. The name checks above refuse that before the grant, and the refusal probes (point 9) confirm it afterwards.
     - Exchange caches role changes for 30 minutes to 2 hours. `Test-ServicePrincipalAuthorization` shows the new role at once, but a delete may still get 403 for that long. Probe again after the delay before trusting a failure.
     - Falling back to `Sites.Selected` `write` is never an option. If a probe fails, this entry is amended.

2. **The API.**

   ```cpp
   namespace rp::graph {
   enum class CleanupWhen { before_run, after_run };
   struct TargetCleanup {
       std::string error_code;   // "" or target_guard, graph_auth, graph_permission,
                                 // graph_transient, graph, config, internal
       std::size_t found = 0;    // items listed in the first round
       std::size_t deleted = 0;  // 204
       std::size_t gone = 0;     // 404 on an item this call listed
       std::size_t left = 0;     // still listed after the last round
       std::size_t skipped = 0;  // entries that are not plain files or mails; never deleted
       unsigned rounds = 0;      // 0, 1 or 2
       bool ok() const;          // error_code empty, left == 0, skipped == 0
   };
   struct CleanupResult {
       CleanupWhen when;
       TargetCleanup mail, sharepoint, onedrive;
       bool ok() const;          // all three ok
   };
   struct CleanerOptions { std::shared_ptr<spdlog::logger> logger; };
   class Cleaner {
   public:
       Cleaner(GraphClient&, connector::RestoreTargets, CleanerOptions = {});
       CleanupResult clean(CleanupWhen) noexcept;   // all three targets, always
   };
   nlohmann::json to_json(const CleanupResult&);
   }
   ```

   - **`clean` never throws.** A failure goes into its target's `error_code`:
     - Graph's errors map as in `verification::read_error_code` (`rp/checker.hpp`).
     - A `ConfigError`, such as `CertificateError` on the token, becomes `config`.
     - Anything else becomes `internal`, and `what()` is never copied.

     One target's failure never stops the others.
   - **`clean` always cleans all three targets, whatever the run sampled.** That includes everything in the `restoretest` Inbox, delivered mail too, because the mailbox exists only for restores. Mail that arrives after the clean-after is a leftover for the next clean-before, not a W3.4 failure.
   - It is not thread-safe, like `TargetReader`.
   - **Its listings are its own**, in `src/cleaner.cpp`, because `TargetReader` drops folders and keeps no parent reference. `list_pages` and the `is_inbox_path`/`is_library_root_path`/`is_folder_path` rules move from `src/graph_targets.cpp`'s anonymous namespace into `src/graph_paging.hpp`, so both readers keep one paging rule. `NextLinkRule` and `kMaxListPages` stay public in `rp/graph_targets.hpp`.
   - **Nothing is downloaded and no body is read:**
     - mail: `$select=id`, with `kMailPrefer`;
     - files: `$select=id,name,eTag,file,folder,package,remoteItem,root,parentReference`.
   - **There is no delete cap.** `kMaxListPages` already bounds a round. A target that holds more than that ends with `left > 0`.

3. **`GraphClient` gains one write member, and only the Cleaner can call it.**
   - **`ListedItem`.** `rp/graph_client.hpp` declares `class ListedItem`, a mail (mailbox and ID) or a file (drive, ID and eTag). Its constructor is private, with `friend class Cleaner`. Only the Cleaner's listing can make one.
   - **`remove`.** `RemoveOutcome GraphClient::remove(const ListedItem&)` builds the path itself, and there are only two shapes:
     - `POST /users/{mailbox}/messages/{id}/permanentDelete`, bodiless, with `kMailPrefer`'s IdType;
     - `DELETE /drives/{drive}/items/{id}` with `If-Match: <eTag>`.

     `RemoveOutcome` is `removed` (204), `gone` (404 with `itemNotFound`/`ErrorItemNotFound`) or `changed` (412). A 404 naming a missing container (`names_missing_container`) stays a `NotFoundError`.
   - **A source scan**, like the TLS scan, fails the build if `ListedItem` or `remove(` appears under `src/`, `include/` or `app/` outside `graph_client.*` and `cleaner.*`. Tests reach `remove` only through the Cleaner.
   - **One send path.** `send_get` becomes a private `send(HttpMethod, ...)`. `graph_url`'s v1.0 prefix and path checks, the caller-header check and the 401/403/404 rules stay the same for every method. Every message names the method ("Graph DELETE …", "Graph denied POST …"). `kCallerHeaders` stays `{"Prefer"}`.
   - **Retries: a write is retried like a GET.** That means 5 attempts, 429/503 waited out within the per-wait and per-call caps, a transport failure resent, and one fresh token on a 401. A resent permanentDelete or If-Match DELETE of the same listed ID can only answer 204, 404 or 412, so it never deletes anything else. The round's re-list (point 6) settles what is left.
   - **New grant texts** in `graph_client.hpp`. They name no lab value, and the table "every grant's text is generic" in `graph_client_test.cpp` gains rows:
     - `kMailGrant` = `Exchange RBAC "Application Mail.ReadWrite" in a management scope covering the test mailbox`. It replaces `kMailReadGrant`.
     - `kOneDriveGrant` = `Files.SelectedOperations.Selected write on the test OneDrive folder`. It replaces `kOneDriveReadGrant`.
     - `kListWriteGrant` = `Lists.SelectedOperations.Selected write on the test library`.
     - `kSitesReadGrant` stays.

     The refusal table in `graph-permissions.md` changes to match.

4. **How every delete is guarded.** Per target and per round, in this order. A refusal stops that target before its first DELETE.
   1. **Resolve the target** with the existing checks, called directly: `check_restore_mailbox`, `check_restore_library` and `check_restore_onedrive_folder`, worded `{"deletes only in", "nothing was deleted"}`.
      - They are not called through `TargetGuard::check_spec`, which resolves only the types in a spec (`src/target_guard.cpp:118-128`).
      - A `WrongTargetError` is logged once at critical as `SECURITY: cleanup: <message>` through `redact()`, using a helper beside `rp::refusal` in `src/target_guard_refuse.hpp`. The target's `error_code` becomes `target_guard`. What the run does with that is point 8.
   2. **List under the resolved IDs only**, paged by the shared rules:
      - `/users/{ResolvedMailbox::address}/mailFolders/inbox/messages`;
      - `/drives/{ResolvedLibrary::drive_id}/root/children`;
      - `/drives/{ResolvedOneDriveFolder::drive_id}/items/{folder_id}/children`.

      `is_inbox_path` and the other path rules pin each nextLink. A delete path comes only from the `ListedItem`, never from a nextLink.
   3. **A file proves its place:**
      - its `parentReference.driveId` is the resolved drive;
      - in OneDrive, its `parentReference.id` is `folder_id`;
      - in the library, its `parentReference.path` is the drive's root.

      A mail's place is proved by the resolved mailbox, the Inbox-scoped listing path and the paging rule. There is no `parentFolderId` check: `check_restore_mailbox` reads the Inbox ID without Prefer (`src/target_guard_graph.cpp:214`), so it is in another form than the listing's ImmutableIds.
   4. **The ID passes its rule:**
      - files: `is_graph_item_id` (`src/config.cpp:407`), and the ID is not the folder's own ID or the library root's;
      - mail: the predicate `graph_id` applies today (`is_id` with `"!-_="`, at most 512), shared from `graph_paging.hpp` as a `bool`.

      An entry that fails is logged and counted `skipped`. It doesn't throw.
   5. **Only plain files are deleted.** A file entry is deleted only if it has a `file` object and no `folder`, `package`, `remoteItem` or `root` facet. Everything else counts as `skipped`, is logged as what it is, and stays for the owner. Restores never make folders: mail lands in the Inbox, files in the target root (W2.4, W2.5, W2.8). A folder's or package's DELETE would take contents this call never listed.
   6. **Only a listed item can be deleted.** A `ListedItem` exists only from this call's listing under that target (point 3).

   The checks are GETs that run before the DELETEs. A rename between check and delete is a window Graph can't close. Accepted.

5. **Delete semantics.**
   - **Mail: `permanentDelete`.** A plain DELETE moves the mail to Deleted Items, where copies would pile up run after run and go into every nightly backup. `permanentDelete` puts it straight into Recoverable Items/Purges, which retention empties (later under a hold). Neither the checker nor Veeam's restore into the Inbox sees Purges.
   - **Files: `DELETE` with `If-Match: <eTag>` from this call's listing.** The item goes to the site recycle bin, where SharePoint keeps it for 93 days from the delete (first and second stage together). A guard bug then costs a recoverable delete, not a lost file. A 412 means the item changed since it was listed (SharePoint's Office rewrite moves the eTag). It counts as `changed`, and the next round lists it again.

6. **"One retry" is one more round.**
   - Round 1 lists, deletes each listed item, and lists again.
   - Round 2 does the same once more if anything is left, or if round 1 ended in a transient error or a 412.
   - A `target_guard`, `graph_auth`, `graph_permission` or `config` error gets no second round, since a second round can't change it.
   - The final listing sets `left`. A 404 on a listed item counts as `gone`. The re-list is what confirms it, since SharePoint also answers 404 for an item the app may not see.
   - There is no loop beyond two rounds. A target left non-empty ends not ok, and the next run's clean-before takes it up.

7. **The cleanup never changes the status, except through the guard (point 8).**
   - `RunFacts`, `decide_status`, `kCodes`, the warning vocabulary and every exit code stay as W3.3 left them. `rp/run_status.hpp` doesn't include `rp/cleaner.hpp`.
   - **The `cleanup` object.** The result gets it beside `status`:

     ```
     {"cleanup_ok": bool, "restore_may_still_run": bool, "before": {...}, "after": {...} | null}
     ```

     Each target in `before` and `after` has `found`, `deleted`, `gone`, `left`, `skipped`, `rounds`, and `error_code` only when it is set. It holds counts and codes only.
   - **`cleanup_ok` is the state the run leaves behind:** `after.ok` when the clean-after ran, else `before.ok`. It is false whenever `restore_may_still_run` is true, or a restore was sent and no clean-after could run.
   - **A not-ok target is visible.** Each one gets a stderr line `warning: cleanup: <mail|sharepoint|onedrive> <fixed text>`. This is the existing warning format, but outside `run_status`'s vocabulary. A run that passes with `cleanup_ok: false` still exits 0.
   - W4.1 adopts the object into `result.v1.json`, and the dashboard flags repeated `cleanup_ok: false` (C-tasks).

8. **Placement in `rpworker restore`.**
   - **One run at a time.** Before its first Veeam call, the command takes a machine-wide named mutex, `Global\RestoreProof-restore-targets`, with no wait. It holds the mutex until it exits.
     - An abandoned mutex (a crashed holder) counts as taken.
     - A second run that can't take it prints `restore error: another RestoreProof run is using the restore targets; nothing was done` and exits 4 (`service`), with no run line and no status.
     - The mutex is injected through the command's environment, so tests use a fake.
     - The two `[live][writes]` tests take it too. `graph list` doesn't.

     Without the mutex, one run's cleanup could delete another run's copies between that run's restore and its read-back, and its items would read `missing`: a false `fail`.
   - **Where the Graph client lives.** `graph_http`, `download_http` and an `std::optional<graph::GraphClient>` are declared before `finish`, in the same scope as `result`/`expected`, in the order that destroys the client first. They are built right after the run line. Today they are locals inside the `try` (`src/restore_command.cpp:796-814`), destroyed before the outer catches reach `finish` through `stopped()`/`restore_failed()`. The certificate is still checked before any Veeam call.
   - **Before.** Right after `run <id>  seed <hex>` and before `choose_sample`, every run that prints a run line cleans all three targets. That includes a run whose sample turns out empty.
     - **A `target_guard` on any target stops the run.** It goes through `stop_reason`'s existing `WrongTargetError` mapping as `RunStop{target_guard}` in phase `before_restore`: status `error target_guard`, exit 4, nothing restored, and no Veeam explore session opened. The guard decides here, as layer 1 would. Layer 1 alone isn't enough, because it checks only sampled types and runs after `choose_sample`'s Veeam calls.
     - Any other failure, or leftovers, lets the run go on. The before snapshot stays the second guard: leftovers are `stale_copies`, a sampled mail already there is `error stale_target`, and a Graph failure is `read_before`'s `check error: ...; nothing was restored` stop, as today.
     - Cleaning first also removes the W3.2 residual risk, where an earlier run's Office file is rewritten between this run's two reads.
   - **After.** In `finish()`, in this order:
     1. `decide_status`;
     2. the status line and its warnings, printed at once, so the decided verdict never waits on housekeeping;
     3. the clean-after, only when `verdict.restore_sent`;
     4. the cleanup line and its warnings.

     The status line is no longer the last stdout line after a restore.
     - On the normal path the clean-after comes after `read_after` and the check, so evidence is never deleted before it is read.
     - After a check that threw, the copies are deleted too. The restore's own rows are the evidence.
     - **A restore that may still run.** When the run stopped in phase `restore` without `nothing_restored` (a POST with no answer, a poll that gave up, a session that may still be `Working`), the clean-after still runs. `restore_may_still_run` is then true and `cleanup_ok` is false, since Veeam may still be writing. A `restore_sample` that returns has polled its sessions to the end.
     - With no Graph client (a stop before it was built), the clean-after doesn't run, and `cleanup_ok` is false if `restore_sent` is true.
   - **Output.** These lines go on stdout, with counts and codes only, never a name or an ID:
     - `cleanup before ok: deleted 5 mail, 3 sharepoint, 3 onedrive`
     - `cleanup after incomplete: deleted 2 mail, 3 sharepoint, 0 onedrive; left 0 mail, 0 sharepoint, 3 onedrive; skipped 1; onedrive graph_permission`
     - `cleanup after incomplete: deleted 3 mail, 0 sharepoint, 0 onedrive; the restore may still be running; the next run cleans before`
     - `cleanup after skipped: nothing was restored`
     - `cleanup after skipped: no Graph client`

     Each failing target also gets one stderr line, `cleanup error: <mail|sharepoint|onedrive>: <what>`.
   - **`restore_note` stays.** The line `the restore had started: items may be in the restore targets (run <id>)` reports what the restore did, and the cleanup line after it says what remains. `docs/worker-config.md` lists both.
   - **`rpworker test` (W3.6)** uses the same Cleaner, mutex and placements. The Veeam half of the pipeline's cleanup step (stopping our own `Working` sessions, `veeam-notes` §4.4) is W3.6's.
   - **`rpworker graph list`** prints, under each table, `(<n> folder(s) or other entries not listed)` when there are any. A target showing zero then really holds nothing, which the Done-when needs.
   - **Build notes.**
     - Every `tests/restore_command_test.cpp` case past the run line gets cleanup routes on its `FakeHttpClient` (empty listings by default), plus a fake mutex.
     - New rows cover each ending: a normal end, a check that throws, `restore_sample` throwing `connector::Error` after the POST (the clean-after still runs, and `restore_may_still_run` is set), a clean-before `target_guard`, and a mutex already held.
     - `veeam_m365_restore_live_test.cpp` ends with `Cleaner::clean(after_run)`, so no live test leaves copies.

9. **Probes, fixtures and the live check.**
   - **`check-worker-app`'s write probes.** `Probe` gains `method`, a body and headers. Creates use `idempotent=False` and `rp-probe-<uuid>` names.
     - **Must succeed** (create, then delete; `finally` deletes only on the RestoreTarget paths):
       - a PUT of a small file into the RestoreTarget library root and into alice's `/RestoreTarget` folder, then a DELETE, expecting 201 then 204;
       - a draft mail in `restoretest`, then `permanentDelete`, expecting 201 then 204.
     - **Must be refused, and can change nothing even when granted.** The probe sends `PATCH {}` with `If-Match: "rp-probe-no-such-etag"` to one canary file in the library and one in alice's `/RestoreTest` folder.
       - The seeder's admin credentials first confirm that each file exists, so a 404 means masked, not missing.
       - 403 or 404 is refused. 412 or any 2xx fails the check.
       - No `finally` ever touches a canary path.
       - For alice's mailbox, the existing read refusal is the proof, since read and write share the RBAC scope. No draft is created there.
     - The token's three roles are checked as in point 1. Evidence goes to `docs/security/w3.4-worker-app-check.txt`.
   - **Fixtures** go in `worker/tests/fixtures/graph/w34-*`.
     - `rpworker restore --record` on the first live run records the clean-before listings, the DELETEs and `permanentDelete`s (the 11 leftovers), and the clean-after.
     - The 404 on an item already gone comes from the live test: a test-side `IHttpClient` wrapper sends the Cleaner's first DELETE twice, inside `rp::RecordingHttpClient`. The write still goes only through the Cleaner, on an item it listed.
     - The 403 on a canary location is hand-written from the Python probe's recorded body, as for `onedrive-folder-403-accessdenied`. No Worker code ever sends a write at a canary.
     - A 412 is hand-written.
   - **The live test.** `worker/tests/cleaner_live_test.cpp`, tagged `[live][writes]` and gated like the restore test (`RP_LIVE=1` and `RP_LIVE_RESTORE=1`). It takes the mutex, cleans, then lists every entry of the three targets (folders included) and requires zero.
   - **Done when:** right after `rpworker restore`, `rpworker graph list` shows zero items and no entries left unlisted in all three locations. Evidence goes to `docs/api/veeam-lab/w3.4-live-*`.

10. **Coverage.** `cleaner` joins `STRICT_NAMES` in `worker/tools/coverage_gate.py` (line 37; 100% line), so `src/cleaner.cpp` and `include/rp/cleaner.hpp` are strict. This changes:
    - `BRANCH_NOTE` (line 41) and the docstring;
    - the two lists in `worker/tools/test_coverage_gate.py`;
    - `docs/testing.md`;
    - CLAUDE.md's "Coverage floors".

    It is the only Worker code that deletes in the tenant, so it is held to the guard's floor. `src/graph_client.cpp`'s write path stays under the 80% gate, but it is tested by failure paths first:
    - a 403 naming the write grant;
    - a 404 for a missing container;
    - a 412;
    - a resent DELETE answered 404;
    - a 401 resend;
    - the source scan.

**Reason.**
- Without a clean before each run, every mail sampled again is `error stale_target`, and an earlier run's Office file can pass for this run's copy after SharePoint rewrites it. Without a clean after, Veeam backs up whatever the targets hold.
- The narrow grants keep the canaries out of reach of any write. The library is protected by a list-scoped grant that the script checks by name, the OneDrive canaries because the grant sits on another folder, and other mailboxes by the RBAC scope.
- To delete outside a target, the Cleaner would need a misconfigured grant, a wrong config and a guard bug all at once. It checks each target with the guard's own Graph checks, deletes only a `ListedItem` it just listed there, and has the only path to the write member. Even then, a file can be recovered.
- The mutex keeps one run's cleanup from turning another run's restore into a false `fail`.
- The cleanup stays out of `decide_status`, so a failed cleanup is housekeeping, never `fail` or `error`. A guard refusal stops the run, as the guard always does.

**Alternatives rejected.**
- *`Sites.Selected` `write` on the site* (the issue): it covers the canary library in the same site.
- *`Files.ReadWrite.All`, or an Entra `Mail.ReadWrite` with an application access policy* (the issue): these are tenant-wide roles that L1.5 rejected, and RBAC already scopes mail.
- *A public `GraphClient::remove(path, ...)`:* any later caller could delete outside the targets.
- *Plain `DELETE` for mail:* copies pile up in Deleted Items and in every backup.
- *`permanentDelete` for files:* irreversible, and it documents no `If-Match`.
- *Deleting folders or packages:* a recursive delete of content never listed.
- *A `parentFolderId` check for mail:* the guard's Inbox ID and the listing's ImmutableIds are different forms, and the listing path already pins the Inbox.
- *`TargetGuard::check_spec` with a made-up spec:* it resolves only the sampled types and would blur what layer 1 vouches for.
- *A cleanup failure as a status stop or a `kCodes` entry, or a `run_status` warning:* it would turn housekeeping into `error` and change exit codes.
- *Letting a clean-before guard refusal run on to layer 1:* it opens Veeam sessions for nothing, and layer 1 misses unsampled types.
- *Refusing to resend a write after `dropped`/`timeout`:* a resend of one listed ID can't delete anything else.
- *A per-target delete cap:* the page limit already bounds a round.
- *Cleaning only after the run, or only the sampled types:* leftovers from a crashed run, or in an unsampled target, would spoil a later run and be backed up.
- *Any Worker-side write at a canary for a fixture or probe:* the 403 comes from the Python probe, which can change nothing.

**Open.**
- Live probes before the build:
  - whether list `write` allows a DELETE;
  - whether folder `write` allows deleting a child;
  - whether `permanentDelete` takes the ImmutableId with `kMailPrefer`;
  - whether a bodiless POST needs `Content-Length: 0`.
- Deleted Items in `restoretest` may still hold copies from the hand cleanups. The owner empties it once by hand before the live check; the Cleaner never reads it.
- Recycle-bin growth (it counts against site storage) and Purges under a hold. Revisit if the lab or a pilot runs into quota.
- Mail `permanentDelete` exists in the global cloud only. A customer in US Gov or China needs another rule (W4.11/C5.13).
- The mutex is per machine. Two Workers on two machines against one tenant aren't covered; Stage 1 has one Worker per Veeam server.
- A `--keep` flag that skips the clean-after, for debugging.
- W3.5 times the `cleanup` span. W3.6 adds the Veeam session sweep (and with it, an end to `restore_may_still_run`) and the same placements to `rpworker test`. W4.1 puts the `cleanup` object in `result.v1.json`, and the dashboard flags runs with `cleanup_ok: false` in a row.
- Docs to change with the build:
  - `docs/security/graph-permissions.md`: the granted table, the "not granted" row for write roles, the probes, and Open item 1 closed;
  - `docs/verification.md`: a new section "Cleaning the restore targets (W3.4)", and lines 147-148;
  - `docs/worker-config.md`: the `rpworker restore` output, the mutex, the "Nothing is cleaned up" lines, and `restore_note`;
  - `docs/testing.md`: the "clean up by hand" lines, the overlap sentence (replaced by the mutex) and the live test;
  - `docs/glossary.md`: **Cleaner**, `cleanup_ok`;
  - `docs/api/veeam-restore-flow.md`'s hand-cleanup notes;
  - CLAUDE.md.

---

## 2026-10-02 — W3.3 second review: Graph is blamed as Graph, one code table, "nothing restored" kept (proposed)

Amends the W3.3 build notes below (points 1 and 7) after the PR #147 review's eight findings.

1. **The guard's Graph errors stay Graph's.** `restore_sample`'s target guard (layer 1) used to
   turn Graph's errors into connector ones, so a Graph 429 read `error backup_transient` and a
   Graph 403 "the backup product refused the credentials". It now rethrows each as its own
   Graph type with `; nothing was restored` appended (it runs before any Veeam call), so the
   status is `graph_transient`, `graph_permission`, `graph_auth` or `graph`, and no "the
   restore had started" note follows. A target Graph can't find is a `graph::NotFoundError`
   (`graph`), still never `connector::NotFoundError`. `IConnector::restore_sample` documents
   that a connector reading targets through Graph lets Graph's errors out.
2. **`RunStop` carries `nothing_restored`, not `what()`.** The copied `message` was never
   read (point 1 of the build notes said it was kept "for the evidence"; it wasn't). In the
   restore phase the stop records whether the error promised `connector::kNothingRestored`,
   and the status line says which: `the restore didn't start: ...; nothing was restored` or
   `the restore didn't complete: ...; items may be in the restore targets`. The verdict and
   the `status` object gain `restore_sent`, whether items may be in the targets, for W3.4's
   cleanup, which can't read stderr.
3. **One code table.** The stop texts, check codes, severity order and exit codes were four
   parallel lists; a check code missing from the severity list made row 7 read past its end.
   They are now one `kCodes` table with a `static_assert` that every check code ranks, each
   rank once. `exit_code_of(code)` is exposed, and `rpworker restore` uses it with
   `stop_reason` for an exception before its run line too, so the catch clauses no longer
   carry exit codes of their own (no exit code changed).
4. **Graph's errors map once.** `stop_reason` uses the checker's `read_error_code` for every
   `graph::GraphError`. `read_error_code` no longer turns a `ConfigError` into `graph`: a
   configuration problem is a `config` stop in every phase (the read-back included, where it
   now stops the run, exit 1, instead of making its items `error graph`, exit 4).
5. **`backup_session` details: counts only, inside the parenthesis too.** The pattern
   `<n> item(s) processed[ (<no parentheses>)]` let `(alice@contoso.com: mailbox not found)`
   through. The parenthesis now holds only `<n> <word>` pairs of Veeam's own words
   (`success`/`successes`, `warning(s)`, `failure(s)`, `error(s)`, `skipped`).
6. **A lost status line is always said.** When stdout fails after the run line but no
   restore ran (an empty sample, a stop before the restore), stderr now reads `error: writing
   the output failed (run <id>); run status <status>[ <code>]`; before, only a lost output
   after a restore was said.

**Reason.** The review's findings: the status must name the service that failed, never a
tenant value, and the evidence must say whether the targets may hold this run's copies.

---

## 2026-10-01 — W3.3 build notes: what the build settled beyond the approved table (proposed)

Amends nothing in the approved W3.3 entry below; it records what building it settled where that
entry was silent, and what its review changed. Code: `rp/run_status.hpp`,
`src/restore_command.cpp`; tables: `docs/verification.md`, "The status decision table".

1. **The status line never quotes an exception.** Its message is fixed text per code and phase
   ("the run stopped before the restore: the backup product couldn't be reached or asked to
   try later (backup_transient); nothing was restored"), counts for rows 5 to 8, never a
   tenant value. A connector's or Graph's `what()` can name the client or an item, so it stays
   on stderr in the existing `restore error: ...` and `check error: ...` lines, and in
   `RunStop::message` for the evidence.
2. **Exit codes against the interim (W2.8/W3.2) code.** The decision's three: a `partial`
   restore whose items all verify is 0 (was 5); a `failed` restore with stale items is 4 (was
   5); an infrastructure item beside a missing item is 5 (was 4). Also, by the code table: an
   after-read Graph auth or permission failure is 2 and a transient one 3 (both were 4); an
   unexpected (non-Graph) failure in the check is `error internal`, 1 (was the restore's code
   or 4); a restore result that doesn't line up with the sample (another number or kind of
   items) is `error internal`, 1.
3. **Output lost after the restore doesn't stop the check.** The check still runs, the
   warnings still go to stderr, the status decides the exit code, and a `pass` becomes 1 (its
   output was lost). The stderr line names the restore's account and the run's status:
   `error: writing the output failed after the restore ran (run <id>, restore <status>: <n>
   of <m> item(s) restored); run status <pass|fail|error>[ <code>]`.
4. **The not_run and empty-sample stderr lines are gone**, as are the interim `check: ...`
   lines and the infrastructure line: the status line says each (`status error not_run`,
   `status error empty_sample`, its shortfalls as warnings). Earlier runs' copies are the
   `stale_copies` warning.
5. **Only the run's line starts with `status`.** The restore's own line is now `restore
   <not_run|succeeded|partial|failed>: <n> of <m> item(s) restored in H:MM:SS` (was `status
   ...`; `status failed` began with `status fail`). The run's status line is the last line of
   stdout but for `--record`'s `recorded ...` line.
6. **Row 1 checks more than the approved list:** a sample of items with neither a restore
   result nor a stop; a stop whose code isn't in the vocabulary, or whose phase contradicts
   what is there (before or in the restore beside a restore result or a check, in the restore
   without an expected set, in the check without a restore result or beside a check); a restore
   or check item of another kind than its expected item; an item `error` with a code the
   checker doesn't give; a value outside its enum (`RunPhase`, `ExpectedKind`,
   `RestoreStatus`, `ItemOutcome`, `CheckOutcome`); a check item whose `found` contradicts its
   outcome. Row 1 carries no warnings.
7. **`backup_session` keeps Veeam's `details` only when they read as its counts**, `<n>
   item(s) processed[ (<no parentheses>)]` in printable ASCII; anything else may name an item
   or an address and is left out. An empty session ID matches no item.
8. **`no_restore_point` is in the vocabulary but not yet used.** A failure before the run line
   (no restore points, an unknown `--point`, Veeam unreachable or refusing while listing
   restore points, a config or manifest problem) keeps its stderr line and exit code and
   prints no status line. **Open for W3.6:** `rpworker test` and the result JSON need a status
   for these too, so the run line (or a status) should come before listing restore points.
9. **R5 before R7 stays as approved**, so a `target_guard` unchecked item sits below a failed
   item (the run is `fail`, the guard's item listed as unchecked). Noted as a possible
   revisit: a guard refusal is a safety signal one might want to outrank everything.

**Reason.** Each point keeps the approved table's rule (the check is the evidence, never a
tenant value in the status, infrastructure never `fail`) where the entry didn't say how.

---

## 2026-10-01 — W3.3: the status decision table (recorded before the build; the owner approved it as written)

W3.3 (#38) turns what a run produced into one status, `pass`, `fail` or `error`. One pure
function, `rp::verification::decide_status`, in new files `rp/run_status.hpp` and
`src/run_status.cpp`. It never calls Veeam or Graph. Where the issue text predates W3.1/W3.2,
the checker wins: item outcomes are `match`/`mismatch`/`missing`/`error`, not "found/match".

1. **Inputs.** A `RunFacts` holds four things:
   - the `ExpectedSet`;
   - the sample's shortfalls (per type, canaries and random items, how many were wanted and
     how many taken);
   - at most one `RunStop` (a phase plus an `error_code` and a message) for whatever stopped
     the run;
   - the `RestoreResult` and the `CheckResult` when they exist.

   A separate pure helper, `stop_reason(std::exception_ptr, RunPhase)`, maps an exception
   to a `RunStop` by its type. The phases are `before_restore` (config, manifest, restore
   points, sampling, the before snapshot), `restore` (`restore_sample` threw) and `check`
   (the read-back or the check threw something that isn't Graph's). Per-type Graph failures
   in the read-back are not stops: they are already item `error`s in the `CheckResult`.

   **Each item gets one verdict, in this order, first fit wins:**
   1. check `error` → *unchecked*, with the check's code;
   2. check `match` → *verified*, whatever Veeam said about the item;
   3. check `missing`/`mismatch` while Veeam marked the item not restored with
      `infrastructure` → *unchecked*, `backup_infrastructure`;
   4. check `missing`/`mismatch` → *failed*.

   **The run, first fit wins:**

   | # | When | Status | `error_code` |
   |---|---|---|---|
   | 1 | inputs that don't add up (check items ≠ expected items, indexes out of order, a restore result without a check and no stop) | error | `internal` |
   | 2 | a stop in any phase | error | by the exception (point 2) |
   | 3 | the sample is empty | error | `empty_sample` |
   | 4 | the restore returned `not_run` | error | `not_run` |
   | 5 | any item *failed* | **fail**, the failed items named | — |
   | 6 | the restore is `failed` (Veeam: 0 restored) and every item matched | error | `restore_contradiction` |
   | 7 | any item *unchecked* | error | the most severe item code (point 2) |
   | 8 | every item *verified* | **pass**, with warnings (point 4) | — |

   **Precedence.** A stop or an unusable run always wins. Then a confirmed *failed* item wins
   over unchecked ones (row 5 before row 7). A missing or mismatched item counts only when
   its own target was read fine and Veeam didn't blame infrastructure for it, so it is
   evidence about the backup, and an unrelated unchecked item can't hide it. The unchecked
   items are still listed beside the `fail`.

   The interim code already put 5 before 4. One case changes: today an infrastructure item
   anywhere makes the run 4 even when another item is missing.

2. **Error codes.** One flat vocabulary, the same in every phase. The `rpworker` exit code is
   in brackets (point 6).

   | Code | From | Exit |
   |---|---|---|
   | `config` | `rp::ConfigError` (`graph::CertificateError` too), `sampling::ManifestError`, `connector::UnknownConnectorError` | 1 |
   | `internal` | any other exception; inconsistent inputs (row 1) | 1 |
   | `backup_auth` | `connector::AuthError` (also Graph auth inside `restore_sample`'s guard layer 1, as the connector maps it today) | 2 |
   | `backup_transient` | `connector::TransientError` (unreachable, a timeout, a gateway error) | 3 |
   | `not_in_backup` | `connector::NotFoundError`: unknown organisation, or (in `restore_sample`) a sampled item not in the restore point | 4 |
   | `no_restore_point` | no restore points, or `--point` not among them (the command's own stop, not an exception) | 4 |
   | `target_guard` | `connector::SafetyViolation`; `graph::WrongTargetError` (before snapshot or read-back) | 4 |
   | `backup` | any other `connector::Error`: Veeam errors, an ambiguous match, a `Working` session of ours at preflight, a restore with no verdict (still `Working` after 20 min, session not found), a session that restored nothing for an infrastructure reason | 4 |
   | `backup_infrastructure` | an item Veeam marked not restored with `infrastructure` that the check didn't find matching | 4 |
   | `empty_sample` | row 3 | 4 |
   | `not_run` | row 4 | 4 |
   | `restore_contradiction` | row 6 | 4 |
   | `graph_auth` / `graph_permission` | `graph::AuthError` / `PermissionError` (before snapshot or read-back) | 2 |
   | `graph_transient` | `graph::TransientError` | 3 |
   | `graph` | any other `graph::GraphError` | 4 |
   | `stale_target` | the checker's: only an earlier run's copy is there | 4 |

   With several unchecked items, the run's code is the first of these present: `target_guard`,
   `graph_auth`, `graph_permission`, `backup_infrastructure`, `graph`, `graph_transient`,
   `stale_target`. A misconfiguration or a safety problem outranks a retry-later one, and an
   unclean target comes last. The message counts each code.

   `backup` carries every other connector error. Splitting it (a `Working` session, no verdict)
   needs new connector error classes, which is left open.

3. **`duplicate`, and unchecked items beside matches.**
   - **A duplicate is a warning, never a status.** The newest copy was compared and matched, so
     the backup delivered the data. A second copy points at Veeam or the Worker writing twice,
     not at the backup losing data, so `fail` would accuse the backup wrongly. It is a
     `duplicate` warning naming the items, on a `pass` or a `fail`.
   - **One item `error` with every other item matching is `error` for the run.** `pass` means
     every sampled item verified, and a partial pass would claim more than was checked. The
     result is finer than the status: per-item verdicts and the counts (point 5), so a report
     can say "n of m verified, k couldn't be checked (code)" under an `error` without calling
     it a pass. `stale_target` is `error` as the checker already decided (W3.2 live run).

4. **Partial and Warning.** Veeam's word never decides the status. W3.2 live run 2b showed
   that "restored" proves nothing, and a failure Veeam reports has to show up in the check to
   become `fail`.
   - `partial` (a `Warning` session, a `Failed` session beside restored items, a short
     `restoredItemsCount`) with every item verified → `pass` with warnings. This is the issue's
     rule.
   - `partial` with an item missing or mismatched, not infrastructure → `fail`.
   - `partial` with an infrastructure item that didn't match → `error` `backup_infrastructure`
     (the W2.4 review's proposal, now settled).
   - `failed` (0 restored, not infrastructure) → `fail` through its missing items. If every
     item matched anyway → `error` `restore_contradiction`: when Veeam and Graph disagree that
     completely, "when unsure, error".

   **"The warning text attached"** means a `warnings` list on the status. Each warning has a
   `code`, a one-line `message` and the item `indexes` it concerns. The codes:
   - `backup_session`: per session whose result isn't `Success`, with Veeam's `result` and
     `details` (Veeam's counts, never a tenant value);
   - `backup_item`: verified items Veeam didn't report restored;
   - `duplicate`;
   - `shortfall`: per type and half, wanted and taken;
   - `stale_copies`: earlier runs' copies ignored.

   Item messages (which may hold a name) stay in the restore result, never in a warning.

   **Where this disagrees with earlier entries:**
   - W1.7 "`failed` → fail": now fail only through the check. A stale item gives `error`, and a
     full contradiction gives `error`.
   - W1.7 "`partial` → fail unless every item verifies": kept, except that an infrastructure
     item makes it `error`.
   - Restore-flow §15 row 810 ("0 restored → `fail`"): narrowed the same way as W1.7's
     `failed` rule.
   - The glossary's "no 'passed with warnings'": the status is never qualified. A pass still
     means 100% verified, and the warnings are evidence beside it, so the glossary gets one
     clarifying sentence.

   **A shortfall never changes the status** (W2.6's proposal). It is a `shortfall` warning, and
   the counts by expected kind keep the claim to what was checked.

5. **The result type.**

   ```cpp
   enum class RunStatus { pass, fail, error };
   struct StatusWarning { std::string code; std::string message; std::vector<std::size_t> indexes; };
   struct RunVerdict {
       RunStatus status;
       std::string error_code;  // error only
       std::string message;     // one line, never a tenant value
       std::vector<std::size_t> failed;    // indexes, fail only
       std::vector<std::size_t> unchecked; // indexes, with their codes in JSON
       std::vector<StatusWarning> warnings;
   };
   ```

   `to_json` gives the result's `status` object, by index like `expected` and `check`:

   ```
   {"status", "error_code"?, "message",
    "counts": {"items", "verified", "failed", "unchecked"},
    "verified": {"manifest", "fields", "metadata"},
    "failed_items": [...],
    "unchecked_items": [{"index", "error_code"}],
    "warnings": [{"code", "message", "indexes"}]}
   ```

   W4.1 adopts it into `result.v1.json`.

6. **`rpworker restore` once the status decides.**
   - Once the run line is out, every ending prints `status <pass|fail|error>[ <code>]:
     <message>` on stdout, then each warning as `warning: <code>: <message>` on stderr.
   - The interim `check: n item(s) didn't verify` / `couldn't be checked` lines and the
     restore's own infrastructure line are replaced by the status line.
   - The exit code comes from the status: pass 0, fail 5 (`exit_code::restore`, now meaning
     "the run's status is `fail`"), error by its code (point 2's column: 1, 2, 3 or 4).
   - Usage errors stay 64 and are outside a run. Errors before the run line (arguments,
     config, manifest) keep today's stderr lines and codes.
   - **Changes from the interim:**
     - a `partial` restore whose items all verify is 0, not 5;
     - a `failed` restore with stale items is 4, not 5;
     - an infrastructure item beside a missing item is 5, not 4.
   - **W3.6 must decide** `rpworker test`'s codes. The guide's 0 pass / 1 fail / 3 error clash
     with 1 config and 3 transient. The proposal for W3.6 is the same mapping as `restore` (0,
     5, 1–4), so a script reads both commands the same way.

7. **Coverage.** `run_status` matches no strict name (`vault`, `signer`, `target_guard`).
   Proposed: add `run_status` to `tools/coverage_gate.py`'s `STRICT_NAMES` (100% line). It is
   the Worker's counterpart of the Cloud's `app/results.py`, which is held to 100% branch.

**Reason.** The check is the evidence. Veeam's account is only a warning or an infrastructure
excuse, so neither an unclean target nor an unreachable service becomes `fail`, and a
"restored successfully" that wrote nothing can't become `pass`.

**Alternatives rejected.**
- *An unchecked item outranks a failed one:* a real data loss would hide behind an unrelated
  Graph hiccup.
- *A duplicate fails the run:* it accuses the backup of the Worker's or Veeam's double write.
- *Pass on the checked subset:* claims more than was tested.
- *`partial` is always `fail`:* contradicts the issue and the evidence, since every item
  verified.
- *Backup codes named `veeam_*`:* the connector layer is product-neutral (W1.7). The run names
  its connector.

**Open.**
- **A canary missing from a restore point dated after it** (W2.4's proposed `fail`) stays
  `error` `not_in_backup` for now. `restore_sample` throws one `NotFoundError` for the whole
  sample, with no item and no date, so the status can't name the item or know whether the
  backup should hold it. Making it `fail` needs a per-item "not in restore point" outcome from
  the connector and the manifest's date against `backupTime`: a later task.
- A client with no restore points at all is `error` `no_restore_point`, not `fail`. Whether a
  missing or too-old backup is a `fail` (restore point freshness) is a later product decision.
- Finer `backup` codes need connector error subclasses.

---

## 2026-10-01 — Worker coverage in one process; the vcpkg cache key names the runner image (proposed)

Amends "Worker coverage via OpenCppCoverage" (2026-09-22): the tool and the gate stay, how the
tests run under it changes.

**Decision.**

1. **The coverage run starts `rptests.exe` once.** `worker/tools/run_coverage.ps1`, which CI and
   `docs/testing.md` both use, makes two OpenCppCoverage runs and merges them: `rptests.exe`
   with every Catch2 test case in one process (exported as OpenCppCoverage's binary format),
   then the `rpworker.exe` tests through `ctest --preset coverage -L exe` with
   `--cover_children` and `--input_coverage`, exported as the Cobertura file the gate reads.
   `rp_add_exe_test` gives each exe test the ctest label `exe`. `--modules` names the one exe
   of each run, so the vcpkg DLLs' PDBs aren't read.
2. **Test cases are still isolated where it is cheap.** `ctest --preset dev` and CI's Release
   `ctest --preset ci` run each test case in its own process, as before. Only the coverage run
   shares one.
3. **CI's vcpkg cache key is `vcpkg-<os>-<image OS>-<image version>-<hash of vcpkg.json>`**,
   with the restore keys falling back to the same image, then to any older cache.

**Reason.** On 2026-10-01 the Worker job took 96 minutes on `main`. 48 of them were "Test under
OpenCppCoverage": `catch_discover_tests` registers each of the 1,038 test cases as a ctest test,
and OpenCppCoverage reads rptests' PDB (229 MB) and sets its breakpoints again for each
process. On the dev laptop the per-test-case run's ctest times summed to 58 minutes; the
script took 12.6 minutes (the 26 exe tests 24 s of it), and its report passed
`coverage_gate.py` (97.8% line, the strict files at 100%, `app/main.cpp` present). Another 24
minutes were vcpkg rebuilding every dependency (OpenSSL alone 12 to 17 minutes) in three of
that day's four runs: the cache key held only `vcpkg.json`'s hash, a runner image update had
changed the compiler, so no cached package matched ("Restored 0 package(s)"), and
`actions/cache` never saves under a key that already exists, so the stale cache was never
replaced.

**Alternatives rejected.** *`ctest -j` under OpenCppCoverage*: still a thousand PDB loads, on a
4-core runner. *Coverage only on `main`, not on pull requests*: the gate is the point of the
PR check. *The compiler version in the cache key instead of the image*: vcpkg's hashes also
take in CMake and PowerShell, which change with the image too. *A cache saved on every run
under a per-run key*: a few hundred megabytes per run against the repository's cache quota.

**Open.**
- One of three single-process runs without OpenCppCoverage exited -1 after 150 s without
  Catch2's summary and wasn't reproduced; another coverage run may have been using the build
  folder at the time. If the coverage step fails where the Release ctest passes, suspect a
  test that depends on another's state and fix the test.
- The cache folder carries packages of older images forward until GitHub evicts the cache.
  Small today; delete the caches by hand if it grows.
- The Release build (11 to 16 minutes) and the coverage build (5 to 6.5) are the next largest
  steps; precompiled headers for Catch2 and nlohmann-json in `rptests` are untried.

---

## 2026-10-01 — W3.2 live run: a file's cTag moves on a restore over it; a mail already there isn't restored at all (proposed)

Amends the W3.2 entry below (point 1 and its Open check) with what the live run showed
(`docs/api/veeam-lab/README.md`, "W3.2 live run"):

1. **The cTag check is answered: yes.** Restoring the same 6 canary files over run 1's copies
   (run 2b) moved every file's `cTag`, the OneDrive pdf, docx and xlsx included, whose bytes
   didn't change. So point 1's rule holds: a file whose `cTag` moved is this run's copy, and
   all 6 were `match`.
2. **A mail that is already in the target is not restored, and Veeam says it was.** Run 2b's
   five mails were each "restored successfully" in a `Success` session, but the Inbox kept run
   1's copies, same Graph IDs, and gained nothing (`changedItems: true` restores only what
   differs). Point 1 had assumed every mail restore gives a new Graph ID, from W2.5 and W2.8,
   which both started on empty targets. The build reported the five as `missing`, a `fail`
   for what is an unclean target: the infrastructure-as-fail the status rules forbid. Fixed
   (commit 6fd89e9, a test first): a mail with no copy of this run's but an earlier one it
   would match (its `internetMessageId`, or its subject) is `error` `stale_target`, as a file
   with only an unmoved earlier copy already was. A mail sampled again is therefore always
   `error` until the targets are emptied before each run.
3. **The check doesn't trust "restored successfully".** Run 2b is the case the product exists
   for: Veeam reported 11 of 11, and 5 had not been written by this run. The check said so.

**Reason.** Live evidence over the assumption it replaces; and `stale_target` keeps an unclean
target out of `fail`, where `missing` would have put it.

**Alternatives rejected.** *Ask Veeam to restore mails as copies, or turn `changedItems` off*:
the restore bodies are fixed by W2.4/W2.7's guard on the exact key set, and a second copy beside
an old one still can't say which run wrote it. *Count an earlier mail copy as found*: a restore
that wrote nothing would pass.

**Open.**
- W3.4 must empty the targets **before** each run, not only after: with leftovers, every mail
  sampled again is `error`. The before snapshot stays as the second guard.
- A residual risk to note for W3.4: SharePoint rewrites an uploaded Office file again some
  minutes later (`lab/README.md`, office-v1), which also moves its `cTag`. An earlier run's docx
  or xlsx in the RestoreTarget library, restored minutes before, could be rewritten between this
  run's two reads and look like this run's copy. Cleaning before each run removes it; until
  then, leave a few minutes between runs that sample the same Office canaries.
- The Graph fields W3.2 reads are now tested on live bodies: runs 1 and 2b's `--record`
  folders are replayed whole by `worker/tests/restore_replay_test.cpp`
  (`worker/tests/fixtures/recordings/w32-live-run{1,2}/`, the owner's two real mails' bodies
  and one invoice number replaced, each edit in the folder's README). Re-recording W2.2's
  target-state fixtures (the W3.2 entry's Open item) is no longer needed for coverage; do it
  when those states are next recorded.
- Veeam's explore-session Stop timed out once (run 2, 30 s twice, before any restore; the
  command refused to go on, exit 4, as designed). Watch for it; no change now.

---

## 2026-10-01 — W3.2 review: only this run's files are read back, a copy counts once, office-v1 no stricter than the seeder (proposed)

Amends the W3.2 entry below (points 1, 4 and 6). Two reviews of the build (the checker and
the command; office-v1, the rules and CI) found no false pass on the normal paths and these
defects, each fixed with a test that failed first:

1. **The after read downloads only this run's files with an expected name**
   (`TargetReaderOptions::hash_file`, `verification::hash_filter`). Before, it hashed every
   file in a target, earlier runs' leftovers included, so one leftover that couldn't be read
   (deleted during the read, a size Graph and SharePoint disagree on, over 64 MiB) made every
   item of its type `error`, and the leftovers, piling up until W3.4, were downloaded on every
   run. Other files are listed, not downloaded.
2. **Times are compared without subtracting them.** `want - got` in nanoseconds overflowed for
   years far apart (1700 against 2026) and wrapped to a match; now `got` is checked against
   `want ± 120 s`.
3. **A failure in the check that isn't Graph's keeps the restore's exit code.** An unexpected
   exception after the restore (out of memory, a broken expectation) ended as "unexpected
   failure", exit 1, without the note that the restore ran. Now `check error: unexpected
   failure`, the note, and the restore's own code, or 4 when that was 0.
4. **A copy counts for one item only.** Random mails now claim the copies they match, as
   canaries do, and so do files: two expected items of one subject (or one file name) and one
   copy give one `match` and one `missing`, never two matches. The sampler already prevents
   it; `check` is a general function and a Cloud job's sample might not.
5. **The earlier-copies line is a warning on stderr**, as point 1 said.
6. **office-v1 is no stricter than `lab/seeder/office.py` where a valid file could fail.**
   libzip's `ZIP_CHECKCONS` refused a package whose local header disagrees with its directory
   on a part the rule never reads, and trailing bytes after the end record; Python hashes both,
   so a restored file Word opens would have been a `sha256` mismatch, a false `fail`. It is
   dropped (`refuse_doubled` still refuses a name stored twice), and a deflated part declaring
   more bytes than it holds is accepted as Python accepts it. The entry-count limit is now read
   from the end record before libzip allocates the directory. The C++-only refusals
   (methods other than stored and deflate, encryption, a stored part whose sizes differ, the
   limits, names taken as stored) are written in `lab/README.md`'s office-v1 section: hostile
   input only, no Office writer produces them.
7. **Docs** follow: `docs/worker-config.md` (the check's exit-code rows, `graph list`'s Inbox
   check first, a 403 there now the guard's refusal, exit 4, where it was a permission error,
   exit 2), `docs/security/graph-permissions.md`, and the Graph fixtures README (seven request
   lines widened over the 2026-09-28 bodies until re-recorded: an Open item of the W3.2 entry).

**Reason.** Each was a way for the check to report something other than what the restore did:
an outage of a file nobody asked about, a time a century off, a lost exit code, one copy
proving two items, a valid document failing. The product's claim is only as good as the
check's.

**Alternatives rejected.** *Keep `ZIP_CHECKCONS` and document it*: a stricter rule than the
seeder's turns a writer's harmless quirk into a `fail`. *Refuse two expected items of one
name in `check`*: a logic error after the restore has run loses the run's result; claiming
reports the truth (one copy, one item). *Download every file but ignore errors on stale ones*:
still a download per leftover per run, and an error swallowed is an error hidden.

---

## 2026-10-01 — W3.2: the checker (proposed; recorded before the build)

Recorded before any of it was built, from W3.1's "Open" items (the W3.1 entry below) and issue
#37. Where the issue text predates W3.1, W3.1 wins: a random mail's sender is Veeam's display
name, a random Office file has no size, and a value missing from the expectation is not
checked. The owner confirmed the before/after snapshot (1), libzip (4), the exit codes until
W3.3 (6) and the timing split (7) on 2026-10-01; the rest is proposed until the W3.2 review.

**Decision.**

1. **One read of each target, before and after; this run's copies are the new ones.** The
   checker never searches per item. `rpworker restore` lists the three targets without hashing
   just before `restore_sample` (the *before* snapshot: each mail's Graph ID, each file's ID and
   `cTag`), and lists them again, hashing, after it (the *after* listing), through
   `TargetReader`, so every read keeps W2.2's guards and paging rules; the mail listing gains
   the `check_restore_mailbox` check the file listings already run. Matching is in memory:
   - **Canary mail:** among the mails not in the before snapshot (a restore gives every copy a
     new Graph ID: W2.5 and W2.8 restored `RP-CANARY-0001` under two IDs), the ones whose
     `internetMessageId` equals the manifest's; if none, the ones whose subject is the
     expected subject exactly (then `internet_message_id` is reported as the field that didn't
     match).
   - **Random mail:** the new mails whose subject is the expected subject exactly, not already
     claimed by a canary.
   - **File:** the files of its own target whose name has the expected name's `name_key`
     (`src/name_key.hpp`, the sampler's Unicode case key: SharePoint and OneDrive names are
     case-insensitive). A file that was in the before snapshot counts as this run's only if its
     `cTag` changed (a restore over a same-named file merges a new version into it,
     `documentLastVersionAction: Merge`, same item ID); one whose `cTag` didn't change is an
     earlier run's copy, and the item is `error` (`stale_target`), neither found nor missing:
     the checker can't tell whether this restore wrote it.
   - **Duplicate:** more than one new copy matches. The checker compares the newest (mail:
     `createdDateTime`, file: `lastModifiedDateTime`, then the higher ID), sets
     `duplicate: true` and `copies: n`, and does not change `match` because of it; W3.3 decides
     whether a duplicate fails a run. With the at-most-once POST and the same-name refusals of
     W2.5/W2.6, a duplicate means Veeam wrote twice, which W3.3 should see.
   - Leftovers from earlier runs are ignored, not checked, and counted (`stale_copies` per
     target in the check's JSON, and one warning line), so a run on unclean targets still
     verifies honestly. An earlier mail copy can't pass for this run's (new Graph IDs only);
     an earlier file copy can't either (`stale_target` unless its `cTag` moved).

2. **Comparisons and tolerances, per field present in the expectation; a field the
   expectation doesn't carry is not compared.**

   | Field | Rule |
   |---|---|
   | subject | byte-equal |
   | `sender_address` (canary) | `from.emailAddress.address`, ASCII case-insensitive |
   | `sender_name` (random) | `from.emailAddress.name` after `rp::without_controls` (the expectation's own rule), byte-equal |
   | `received_at` | Graph `receivedDateTime` within ±120 s (the issue's 2 minutes; every live restore so far kept it to the second) |
   | `sent_at` | Graph `sentDateTime` within ±120 s, for the same reason |
   | `internet_message_id` (canary) | byte-equal |
   | mail `sha256` (`text-v1`) | `text_v1_sha256(body.content)` equal |
   | file name | found by `name_key`, so equal after normalisation by construction; not a separate field |
   | file `size_bytes` | the downloaded byte count equal (only `bytes` canaries and non-Office random files carry one) |
   | file `sha256` `bytes` | SHA-256 of the downloaded bytes equal |
   | file `sha256` `office-v1` | `office_v1_sha256(bytes, file_type)` equal; a restored docx/xlsx that is no valid package (not a ZIP, no content part, a part twice, a bad CRC, a limit hit) is a mismatch on `sha256` with that reason: the restored file is broken, not the test |

   Times are parsed as UTC from Graph's `YYYY-MM-DDTHH:MM:SS[.f]Z` and the expectation's
   whole-second form. A Graph value that is missing or unparseable where the expectation has
   one is a mismatch on that field.

3. **`FoundItem` gains** `sender_name` (`from.emailAddress.name`, already in the reply),
   `sent_at` (`sentDateTime`), `created_at` (mail and file `createdDateTime`), `modified_at`
   (file `lastModifiedDateTime`), `ctag` (file `cTag`) and `listed_size` (Graph's size, kept
   beside the downloaded count). The `$select` strings become
   `id,subject,from,sentDateTime,receivedDateTime,createdDateTime,internetMessageId[,body]`
   and `id,name,size,cTag,createdDateTime,lastModifiedDateTime,file,folder`. All are plain
   message and driveItem properties under the three existing read grants
   (`docs/security/graph-permissions.md`: no new permission). The fixtures that carry these
   URLs, `tests/graph_lab.hpp` and the lab recorder's `MAIL_SELECT`/`CHILDREN_QUERY` change
   together, and the new fields are re-recorded live (W2.1's `record-graph-fixtures`) rather
   than written by hand.

4. **office-v1 in C++: libzip from vcpkg, `default-features: false`** (zlib only; BSD-3;
   1.11.4 at the pinned baseline; zlib is already in the build through curl and goes into
   `vcpkg.json` explicitly). `rp::office_v1_sha256(std::string_view bytes, file_type)` in
   `rp/office_v1.hpp` follows `lab/seeder/office.py` exactly: docx `word/`, xlsx `xl/`, any
   other type refused; every part from the central directory, a name twice refused; parts
   under the folder, not containing `_rels/`, not ending in `/`, case-sensitive; sorted by
   UTF-8 bytes; one line `sha256  name\n` each; the SHA-256 of the lines. Read from memory
   (`zip_source_buffer_create`), stored and deflate only, encrypted entries refused, CRC
   checked, each part read by `zip_fread` under a cap (64 MiB per part and in all, 10 000
   entries), so a zip bomb is a refusal. It passes `shared/testdata/office-content-v1/`; since
   every counted part there is stored, the C++ tests add their own deflated packages (as
   `lab/tests/test_office.py` does). **A pptx** (and every other Office type but docx and xlsx)
   has no office-v1 rule: the manifest loader already refuses office-v1 on anything but docx
   and xlsx, so no canary is a pptx, and a random pptx is `metadata` by name only (W3.1). Its
   content is never checked in Stage 1; a `ppt/` rule would be a new rule, `office-v2`.

5. **The result type.** `rp::verification::check(ExpectedSet, before, after)` (pure: the
   Graph reads happen outside it) returns a `CheckResult` with one `ItemCheck` per expected
   item, in the same order and with the same `index`, so `expected.items[i]`,
   `RestoreResult::items[i]` and `check.items[i]` describe one item. `ItemCheck`: `index`,
   `outcome` (`match`, `mismatch`, `missing`, `error`), `found`, `mismatches` (the field
   names: `subject`, `sender_address`, `sender_name`, `sent_at`, `received_at`,
   `internet_message_id`, `size_bytes`, `sha256`), `reason` (one line, no tenant values),
   `duplicate`, `copies`, `graph_id`, `ms`, and `error_code` for `error`. An infrastructure
   failure (a Graph `AuthError`, `PermissionError`, `TransientError`, `WrongTargetError` or
   other `GraphError` while listing or downloading a target) makes every item of that type
   `error` with `graph_auth`, `graph_permission`, `graph_transient`, `target_guard` or `graph`,
   never `missing` or `mismatch`; the other types are still checked. JSON, the result's `check`
   object (W4.1 adopts it into `result.v1.json`, which doesn't exist yet): `counts` per
   outcome, `stale_copies` per target, `items[]` with `index`, `outcome`, `found`, then
   `mismatches`, `reason`, `duplicate`, `copies`, `error_code` and `ms` only when set. Found
   values (subjects, names, senders) are never written: the expectation already holds what was
   checked, and the result shouldn't hold more tenant data than it. `ms` is the item's own
   cost: its file's download, hash and office-v1 time, measured inside `TargetReader` per file,
   plus its comparison; for a mail, only the comparison (its body comes with the listing).

6. **`rpworker restore` checks after it restores.** It builds the expected set
   (`build_expected_set`), takes the before snapshot, restores, reads the after listing,
   checks, and prints one row per item (KIND SOURCE NAME OUTCOME FIELDS DUPLICATE MS) and a
   `check` line with the counts. Until W3.3 the exit code is the restore's, then 5
   (`exit_code::restore`) if any item is `missing` or `mismatch`, then 4 if any is `error`;
   W3.3's table replaces this. A Graph failure on the before snapshot stops the run before any
   Veeam restore (exit 2, 3 or 4, as `graph list`). No `--no-check`: a restore that isn't read
   back proves nothing.

7. **Timings: W3.2 owns per-item `ms` and nothing else.** W3.5 owns the timer, the run's spans
   (`restore_point_lookup`, `sample_select`, `restore_submit`, `restore_wait`, `verify`,
   `cleanup`, `total`) and the issue's "total recovery time = restore start → last item
   verified", which becomes a W3.5 span. The issue's step-timings line moves to W3.5.

**Reason.** One listing per target before and after is the only isolation the evidence
supports: restored mails keep their `receivedDateTime` and `internetMessageId`, files keep
their name and `createdDateTime` and land flat in the target root (L1.4, W2.5, W2.8), so no
property of a copy says which run wrote it, except a mail's new Graph ID and, for a file, a
`cTag` that moved. Matching in memory needs no new Graph URL shape (`$filter` on
`internetMessageId` would be a new path for the guards and fixtures) and reuses TargetReader's
guards. Infrastructure failures stay `error` by type, so a Graph outage can never look like a
missing item. libzip is mature, reads from memory, streams each part under a cap, and needs
only zlib, which the build already ships.

**Alternatives rejected.**
- *Search per item* (`$filter=internetMessageId eq …`, a file by path): a new URL per item for
  the guards to vet, a 404-or-empty meaning to define, and no way to tell this run's copies
  from leftovers.
- *Require empty targets* (`error` if anything is there before the restore): honest, but every
  run would stop until W3.4 and the owner would empty the targets by hand each time; the
  snapshot gives the same safety and lets W3.4's Cleaner come later.
- *Take the newest and pass* on a file whose `cTag` didn't move: an earlier run's copy would
  pass for a restore that wrote nothing, the false pass the product exists to prevent.
- *A hand-written ZIP reader on zlib*: full control, but 200–300 lines of format parsing that
  libzip already does and is tested for; *minizip-ng* (defaults pull bzip2, lzma, zstd),
  *zlib's minizip* (memory I/O through a custom filefunc, a CVE history), *miniz*/*kubazip* (a
  second inflate beside zlib, weaker limits).
- *Found values in the JSON*: more tenant data in the bundle than the expectation holds.
- *Building W3.5's timer here*: two tasks owning one thing.

**Open.**
- A live check early in the build: after a restore over a same-named file in a target, does
  its `cTag` change? If not, every such item is `stale_target` (`error`) until the targets are
  emptied, which is safe; the check only settles what can be detected.
- W3.3: whether `duplicate` fails a run, and how `stale_target` maps (proposed: `error`).
- W3.4: the Cleaner empties the targets; the before snapshot stays as a second guard.
- The guide's `rpworker test` exit codes (0/1/3, W3.6) clash with `rp::exit_code`; W3.6 decides.
- Re-record the Graph target fixtures (`record-graph-fixtures --state empty|one-item|paged`) so
  their bodies carry the new fields; until then 7 fixtures have widened request lines over
  2026-09-28 bodies.

---

## 2026-10-01 — W3.1 code review: what SharePoint rewrites, and expectations no item can over-claim (proposed)

The `/code-review` of PR #145 found 13 issues; the owner chose six to fix and one to check
live. Amends the W3.1 entry below (points 5, 9 and 10).

1. **SharePoint's rewritten files, checked live.** The review doubted point 5's list: if
   SharePoint rewrites a format the list leaves out, a random file of it gets Veeam's size as
   its expectation and reads as `fail` after a good restore, and `graph list --hash` refuses
   it as larger than Graph's size. Checked on 2026-10-01 (evidence
   `docs/api/veeam-lab/w3.1-rewrite-check/`: the script, how the 23 test files were made, the
   results): each file uploaded through Graph into a scratch folder of the RestoreTarget
   library (as the admin; alice can't write it) and of alice's OneDrive `/RestoreTarget`, read
   back at once and after 15 minutes, both folders deleted. SharePoint rewrote docx, docm,
   xlsx, xlsm, pptx, pptm, **xlsb, doc, xls and ppt** (bigger at once, the same 15 minutes
   later; for the packages `docProps/`, `customXml/`, `[trash]/`, `[Content_Types].xml` and
   relationship parts, never `word/`, `xl/` or `ppt/` content). It left vsdx, vsdm, vssx, vstx,
   xlam, ppam, odt, ods, odp, pdf, rtf and txt byte-identical. OneDrive rewrote nothing, docx
   included. So the rule becomes `rp::is_rewritten_office_file` with `.xlsb`, `.doc`, `.xls`
   and `.ppt` added; the untried templates and shows stay. It doesn't depend on the location:
   a rule per location would trust that OneDrive never starts rewriting, and a random file
   then only loses its size check. Limits: the doc, xls, ppt and ODF files came from
   LibreOffice, not Office; vsdm, vssx, vstx, xlam and ppam were real packages with only their
   main content type changed (SharePoint picks its parser by extension); one library with its
   default columns.
2. **No size expectation from a size not known.** A random file whose `size_bytes` is below 0
   (a connector's "not known", -1) gets `metadata` by name only, as point 7 does for a mail's
   missing fields. Refusing it in the sampler was rejected: the connector is backend-neutral,
   and a missing fact was never a reason to drop an item.
3. **A canary's rule must be one its file can be checked by.** The manifest loader refuses
   `bytes` for a docx or xlsx, `office-v1` for a pdf, txt or png, and a name the Office rule
   matches for any other type (or doesn't match for those two), as `python -m seeder`'s
   validator already does for `content_rule`.
4. **No item can read as checked against a hash it hasn't.** `ExpectedItem`'s defaults are a
   canary's, so `to_json` now refuses (`std::logic_error`) an item whose fields don't back its
   kind: `manifest` needs a canary source and ID, no key, a lower-case hex SHA-256 and its
   type's rule; `fields` and `metadata` need a random source, a key, no canary ID or hash, and
   a mail or a file respectively; and each item must be at its index. `to_string` of a kind or
   source outside the enum is `"unknown"`, never `"manifest"`. Making the kind a required
   constructor argument was rejected: every builder would change for a check `to_json` makes
   once, where the result is written.
5. **The record's counts must be the selection's.** `build_expected_set` also refuses a record
   whose `random_taken` or `canary_wanted` isn't what the selection holds, so the `sample` and
   `expected` objects can't disagree on how many items were tested.
6. **A sender's display name is text a third party chose.** Each control character in it
   (`control_chars.hpp`) becomes a space as Veeam's `from` is read, through
   `rp::without_controls`, which `one_line` now uses too.
7. **`expected_set_test.cpp` puts its failure paths first**, as the TDD rule says.

Left as review comments, not done here: the duplicate random selector in `Selection`, the
tie-break that keeps the copy with fewer facts, the narrower `internet_message_id` control
check, the doubled comparisons in the sort, and the third `kind_name` copy. The 5-byte
extension assumption went with point 1.

---

## 2026-10-01 — W3.1: the expected set (proposed; recorded before the build)

Recorded before any of it was built. The owner confirmed decision 3 on 2026-10-01 (a random
file's content is not expected in Stage 1; Veeam's document export is a follow-up task after
W3.2). The rest is proposed: the owner confirms it in the W3.1 review, or supersedes it.

**Decision.**

1. **Every sampled item gets one expected record with one explicit expected kind.**
   `rp::verification::build_expected_set(selection, manifest)` (`rp/expected_set.hpp`, a new
   namespace W3.2 and W3.3 will share) is pure and returns one `ExpectedItem` per selector of
   the selection. There are three kinds, never mixed, and no "unknown" kind or default path:
   - `manifest`: a canary. The expected values are the manifest's, with a content hash: a
     mail's `body_sha256` by `text-v1`, a file's `content_sha256` by its `content_rule`
     (`bytes` or `office-v1`). A `bytes` file also expects its `stored_size`; an `office-v1`
     file expects no size (SharePoint rewrites it). The strongest kind.
   - `fields`: a random mail. The header fields as the backup lists them (Veeam's browse):
     subject, sender display name, sent time, received time. No body hash: nothing knows the
     body before the restore.
   - `metadata`: a random file. Its name, and the size the backup lists, except for an Office
     package (point 5), whose size is no expectation, so its name only.
   The result shows each item's kind and counts the three (`counts`, all three keys always
   there), so a report never claims more than was checked (W3.3, W4.1).
2. **Random items are expected from the backup's own listing, not from Graph.** The Worker app
   may read only the restore targets through Graph (L1.5, W2.6), so it can't read a random
   item's source. This supersedes the glossary's sentence that a random item's expected values
   come from a live Graph read (`docs/glossary.md`, "Random item", updated).
3. **A random file's content is not expected in Stage 1** (owner confirmed 2026-10-01): no
   Veeam export in W3.1. See Alternatives and Open.
4. **A random mail's sender is a display name** (`sender_name`), because that is all Veeam's
   browse lists (`from`, e.g. "Hrachya Harutyunyan"); a canary's sender is an address
   (`sender_address`, the manifest's `sender`). W3.2 compares each with the matching Graph
   field (`from.emailAddress.name` or `.address`).
5. **One Office package rule.** `rp::is_office_package(name)` (`src/office_files.hpp`): the
   name ends, ASCII case-insensitive, in `.docx`, `.docm`, `.dotx`, `.dotm`, `.xlsx`, `.xlsm`,
   `.xltx`, `.xltm`, `.pptx`, `.pptm`, `.potx`, `.potm`, `.ppsx` or `.ppsm` (the Office Open XML
   family SharePoint may rewrite), with something before the dot: a name that is only an
   extension (`.docx`) isn't a package's. It decides a random file's "size is not an
   expectation" and replaces the inline docx/xlsx check in `graph_targets.cpp`, so `graph list
   --hash` now reads a pptx and the macro and template types up to the download limit too
   (`SizeCheck::up_to_limit`), like docx and xlsx. Canaries keep the manifest's
   `content_rule`. `office-v1` hashes only the `word/` and `xl/` parts, so it covers docx and
   xlsx and not pptx: W3.2's concern (a random pptx is `metadata`, name only).
6. **Times are `YYYY-MM-DDTHH:MM:SSZ`**, cut (not rounded) to whole seconds by the rule the
   selector's `received_at` already uses (`veeam_restore::to_whole_seconds`). Tolerances (the
   guide: received within 2 minutes) belong to W3.2.
7. **A missing backup field doesn't drop a candidate.** A random mail without `from`, or whose
   `sent` isn't a time, is still offered and gets `fields` with what is known (its subject and
   received time are always there: the lister requires them). A random file always has a size
   (the lister requires `sizeBytes`).
8. **Order and identity.** The expected set is in `RestoreSpec` order (mail canaries, mail
   randoms, SharePoint canaries, SharePoint randoms, OneDrive canaries, OneDrive randoms), each
   item carrying its `index`, so it lines up with `RestoreResult::items`. A canary is named by
   its manifest `id`, a random item by the sampler's key (the strings of
   `record.<kind>.random_keys`).
9. **The candidates carry their facts beside the key.** `connector::MailCandidate{selector,
   sender_name, sent_at}` (empty: Veeam didn't say) makes `CandidatePool::mail` like the two
   file candidate types, and `Selection` gains `mail_random`, `sharepoint_random` and
   `onedrive_random`: the random candidates taken, in their selectors' order, each selector's
   size -1 as before and the backup's `size_bytes` kept. The sampler's keys, deduplication,
   draw, `pool_sha256` and `to_json(SampleRecord)` don't change, so the W2.8 run's recorded
   sample still replays to the same pool hash. Candidates of one key and equal fields but
   different facts are sorted by those facts too, so which one survives deduplication doesn't
   depend on the listing's order.
10. **The manifest's comparison fields become required in the loader.** `CanaryMail` gains
    `sender`, `sent_at`, `internet_message_id`, `body_sha256` and `body_normalization`;
    `CanaryFile` gains `content_sha256`. The schema requires them already, so the lab manifest
    passes; a pilot's manifest without them is refused as it loads, before any Veeam call,
    rather than giving items that can't be verified. Refused: a `sender` that isn't exactly one
    `@` with no whitespace or control character; a `sent_at` that isn't a real whole-second
    UTC time; an empty `internet_message_id` or one with a control character; a `body_sha256`
    or `content_sha256` that isn't 64 lower-case hex digits; a `body_normalization` other than
    `text-v1`.
11. **Privacy.** The new customer data in the result is a random mail's sender display name
    and sent time; its subject, mailbox and received time are in the sample record already.
    Nothing else.

**Reason.** W3.2 needs, per item, what to compare against and how strong that expectation is;
recording it before anything is compared keeps the checker from taking its expectations from
what it finds. The kinds keep the report's claims to what was tested (the report wording
rule). The backup's own listing is the only source the Worker app may read for a random item,
and it is what the restore restored from.

**Alternatives rejected.**

- *A fourth kind, `backup_content`, from Veeam's document export* (`…/Documents/{id}/save`
  during `restore_sample`, the file's hash then expected): deferred, not rejected for good. An
  Office file needs `office-v1` in C++, which needs the zip reader W3.2 brings; it doubles each
  random file's traffic (export and read-back, up to 64 MiB each); it makes the builder depend
  on `restore_sample`; the lab has no real files yet, so the path couldn't be run live. The
  `expected_kind` field makes adding it later non-breaking.
- *Expected values for random items from a Graph read of the source:* the Worker app has no
  grant on any source (point 2).
- *The facts inside the sampler's key:* every key and `pool_sha256` would change, and the W2.8
  run's recorded sample would no longer replay.
- *Two Office rules (the reader's docx/xlsx and the expected set's list):* two lists drift.

**Open.**

- A follow-up task after W3.2: the `backup_content` kind for random files from Veeam's
  document export, once `office-v1` exists in C++ (point 3).
- For W3.2: `FoundItem` needs the sender display name (`from.emailAddress.name`; Graph's
  `$select` returns `from` already) to check `sender_name`; a canary mail is best found by
  `internet_message_id` first (the manifest has it, and the W1.0 export kept it), then by
  subject; `office-v1` in C++ needs a zip reader (none in `vcpkg.json` today) and must pass
  `shared/testdata/office-content-v1/`.

---

## 2026-10-01 — Q2.1 review: the restore credential never kept, recording off the lock, and the refusal rules (proposed)

Amends the 2026-10-01 Q2.1 entry (points 2, 3 and 5) after the Q2.1 code review.

**Decision.**

1. **The restore credential is checked in its own exchange's file only.** What the recorder
   learns (`rp::secrets_in`, now `rp::LearnedSecrets`) comes in two lists. `kept` holds the
   `Authorization` value, tokens, form and query secrets, and a response body's secret values;
   these are checked in every later file. `one_time` holds the secret values of a JSON request
   body, which is a restore POST's `applicationCertificate` and its password. That credential
   is exported for one call (2026-09-30 W2.5 point 1), so it is checked against its own file
   and then wiped. The recorder's copies are wiped too (`secure_wipe`): both lists when they
   go, every kept secret in `~FixtureRecorder` (held in a deque, so adding one never leaves a
   moved copy behind), a parsed JSON body's strings and its text before redaction, the
   JSON-escaped copy of each secret the check makes, and a refused file's text. A later file
   that held a past restore's credential would no longer be refused by the known-secret
   check; `redact()` still replaces it under its own keys.
2. **Recording no longer holds up the command.** Secrets are learned before any lock. The
   kept list sits under a shared mutex, locked exclusively only to add to it and shared while
   files are scrubbed. The numbering and the counts have their own short lock. The scrub and
   the disk write run outside both, so one exchange's write never delays another's send. A
   `digest` body (a download) is not converted or scanned: nothing is learned from it, since
   it is never written.
3. **The refusal rules.** The JWT rule uses `redact()`'s `rp::kJwtStart` and
   `rp::is_base64url` (now in `rp/redact.hpp`), and keeps its own length threshold (37) on
   purpose: it catches a dotless run `redact()` would miss. `client_assertion` is now refused
   the way `tempauth` is, and no longer as a mere mention. A value of it (the name in any case,
   then `=`, `%3D` or `:`) other than a placeholder is refused. Entra's AADSTS7000218 text,
   which only names the parameter, can be recorded.
4. **Small fixes.** The `--record` folder is checked with `is_directory` after
   `create_directories`, whose MSVC result is false for a path ending in a separator even when
   it made the folder. `restore` opens its recording only after its pre-Veeam checks (sample
   sizes, manifest, cursor), so a run they stop makes no folder and prints no `recorded` line.
   `FakeHttpClient::serve_recording` orders files by their number, so file 1000 comes after 999,
   and matches requests by `rp::request_path`, the recorder's own rule. The commands' option
   loops are one parser, `parse_options` in `src/command_config.hpp`.

**Reason.** The code review of the Q2.1 PR found these. Point 1 restores W2.5's rule that the
exported PFX outlives its call nowhere, which `--record` had broken.

**Alternatives rejected.** Keeping the credential and wiping it only when the recorder goes
(the recorder lives for the whole restore); keeping a hash of it instead (a hash can't be
searched for in a file); widening the file number to four digits (every committed recording's
names would change, and 10 000 exchanges would still break it).

---

## 2026-10-01 — Q2.1: `--record <dir>`, what a recorded fixture keeps, and the unit tests' network guard (proposed)

With the owner's answers of 2026-10-01: `restore` may record, and `--record` takes a folder
that must be new or empty. Proposed: the owner confirms it in the Q2.1 review, or supersedes it.

**Decision.**

1. **`--record <dir>` on `veeam list`, `graph list [--hash]` and `restore`.** Each wraps the
   HTTP clients it makes in `rp::RecordingHttpClient` (`rp/recording_http_client.hpp`), which
   passes every request to the real client unchanged and hands each response it returns to
   one `rp::FixtureRecorder`. A request that throws (no connection, a timeout) isn't recorded
   and its exception goes on unchanged. Recording never changes what a command sends or sees;
   a file refused or not written is a line on stderr, never an exception inside the command,
   so a restore's at-most-once POST can't be mistaken for a POST that got no answer.
2. **Where it goes.** `<dir>` must not exist or be an empty folder (otherwise exit 1,
   `config error: <dir>: the --record folder is not empty`, before any request), so a
   recording never overwrites committed fixtures: the developer looks the files over and copies
   the ones wanted into `worker/tests/fixtures/<service>/`. One subfolder per service: `veeam`
   (the Veeam client and the connector), `graph` (Entra's token endpoint and Graph, the target
   guard's included) and `download` (`graph list --hash`'s downloads). One file per exchange,
   `<nnn>-<method>-<path slug>.json`, numbered per service from 001 in the order sent; a
   refused exchange keeps its number, so the gap shows. After the command:
   `recorded <n> exchange(s) in <dir>` on stdout, one `record error: <service>/<file>: <why>` per
   exchange not written on stderr, and exit 1 if the command had succeeded (a command that
   failed keeps its code).
3. **The file format is the fixtures' own** (`worker/tests/fixtures/veeam/README.md`):
   `source` (`rpworker <version> <command> --record`), `request` (`<METHOD> <path>?<query>`, no
   scheme or host), `status`, `headers`, `body`; `FakeHttpClient::serve_recording(dir)` serves
   a service folder by method and path, the files of one request in number order, the last
   repeating, whatever the host. Key order is kept as received.
4. **What a fixture keeps, and never keeps.**
   - Request headers: none, ever. Response headers: only `Content-Type`, `Retry-After`,
     `WWW-Authenticate` and `Location`, the last with every query value `SCRUBBED`.
   - Request bodies: only a JSON one (a restore's), as `request_body`. A form body (the Veeam
     password grant, Entra's client assertion) and a multipart one are never written.
   - Response bodies: JSON as JSON, with every `@microsoft.graph.downloadUrl` and
     `@content.downloadUrl` dropped; other UTF-8 text as a string; a body that isn't UTF-8,
     and every `download` body (file contents), only as `body_size` and `body_sha256`, never a
     byte. A download's request line has every query value `SCRUBBED` (the link is a
     credential).
   - All of it goes through `rp::redact()`, so tokens, the client assertion, passwords, the
     PFX, `applicationCertificate*` and `Authorization` read `[REDACTED]`; a token reply's
     `access_token` and `refresh_token` become that placeholder, which the Veeam and Graph
     clients accept on replay.
5. **Refused if a secret survives** (mirroring `Save-Evidence`, the PowerShell collection's
   evidence writer): the recorder is given the Veeam password, the Graph PFX and its password,
   and learns, before scrubbing, every secret an exchange carries (the `Authorization` value
   and its bearer token, the values of the keys `redact()` treats as secret in a form, JSON
   body or query, a `Location`'s included); values under 6 characters and the placeholders are
   left out. A file whose text still holds one (as written or JSON-escaped), anything
   JWT-shaped (`eyJ` and 37 or more base64url characters), a `tempauth` value other than a
   placeholder, or the word `client_assertion` is not written.
6. **The unit tests' network guard.** `rptests` has its own `main` (`tests/test_main.cpp`):
   unless `RP_LIVE=1`, it turns on `rp::detail::set_loopback_only`, under which `rp::HttpClient`
   refuses any URL whose host isn't `localhost`, `127.x.x.x` or `[::1]` before any lookup, and
   any socket curl would open to an address outside 127.0.0.0/8 and ::1 (a
   `CURLOPT_OPENSOCKETFUNCTION` callback, the TLS scan's one new reviewed statement). A
   listener counts the refusals per test case; a case with any is named on stderr and the run
   exits 1 even if the test passed. `rpworker.exe`'s ctest runs all stop before any request
   (their comments in `worker/CMakeLists.txt` say so). The manual proof is one `ctest --preset
   dev` with the network adapter disabled (`docs/testing.md`, "The network-off run").

**Reason.** Sprint 3 needs new fixtures (W3.2's deleted messages, W3.4's empty folders after
cleanup), and recording them from the Worker's own C++ calls is safer than writing them by hand
or from the PowerShell collection. A folder that must be empty keeps a recording from ever
landing on committed fixtures unreviewed. Refusing, rather than scrubbing harder, keeps the
rule simple: a file with a secret in it is never written at all. The guard turns "the unit
suite never touches the network" from a convention into something every CI run checks.

**Alternatives rejected.** Recording straight into `worker/tests/fixtures/` (overwrites
hand-edited fixtures); recording only the read-only commands (W3.x needs whole restore runs,
and recording only watches); keeping request headers or form bodies with their secrets
redacted (nothing needs them, and redaction is the only thing between them and the repo);
recording download bytes (canary files are in `lab/canary/` already, and a restored file could
be anything); a proxy variable pointing curl at a dead address (a test expecting a connection
error would still pass, and nothing would name it); a firewall rule or container in CI (heavy,
and not what runs on a developer's machine).

---

## 2026-10-01 — W2.8 second review: the certificate and the manifest checked before Veeam, and what a restore that failed partway says (proposed)

Amends the 2026-09-30 W2.8 entry (points 3, 4 and 5) after the second W2.8 review (PR #142).
Proposed: the owner confirms it in the review, or supersedes it.

**Decision.**

1. **The Graph certificate is opened and checked before any Veeam call**, by the same
   `graph::certificate_from_secrets` the connector uses (not only checked as set). A wrong
   password, a PFX that isn't Base64 or a certificate that isn't valid now is exit 1 before the
   sampler browses Veeam. `RP_GRAPH_CERT_PASSWORD` unset is no password, as for `graph list`:
   the W2.8 amendment that required it set refused a PFX without a password that `graph list`
   accepts. The check logs nothing; the connector's own load still warns of a certificate about
   to expire.
2. **The manifest is checked in full before the connector is made**: its tenant and that no
   canary is in a restore target, through `sampling::check_manifest`, which `choose_sample` also
   runs, and the cursor through `sampling::cursor_problem`, which the sampler's own check also
   uses. One rule and one message each; an unreachable Veeam can no longer turn a manifest that
   names a restore target into exit 3.
3. **A restore that fails after it started says items may be in the targets.** An error from
   `restore_sample` is followed by `restore error: the restore had started: items may be in the
   restore targets (run <id>)`, unless its message ends with `; nothing was restored`
   (`connector::kNothingRestored`), which `IConnector::restore_sample` now documents as the
   connector's promise that nothing was sent. The tables aren't printed: the error carries no
   partial result (a later task may add one).
4. **stdout failing after the restore ran** keeps the restore's exit code (5, or 4 with its
   line) and says the status in its line; a restore that succeeded is exit 1 then, since its
   output was lost.
5. `rp::require_veeam_secrets` (`rp/secrets.hpp`) is the one "is not set" rule for the Veeam
   secrets, used by `veeam list`, `restore` and the `veeam_m365` connector.

**Reason.** The review found the certificate and manifest problems surfacing only after Veeam
had been browsed (or hidden behind a Veeam error), a PFX `graph list` accepts refused by
`restore`, and an operator left without a hint that items were restored when a later session
failed.

**Alternatives rejected.** Keeping only the presence checks (a bad certificate still wastes a
browse per type); matching every connector message for "sent" or "not sent" (only "nothing was
restored" is a promise about the whole call; the others speak of one POST); passing the loaded
certificate into the connector (it makes its Graph client itself, on the first restore).

---

## 2026-09-30 — W2.8: `rpworker restore`, its flags and output, and exit code 5 (proposed; recorded before the build)

Recorded before any of it was built, with the owner's answers of 2026-09-30 (exit code 5, the
manifest beside the config, a random-half shortfall is not a failure). Proposed: the owner confirms
it in the W2.8 review, or supersedes it. *Amended after the W2.8 review* (2026-09-30), in place,
where marked: an empty sample and an infrastructure failure are errors (4), 5 is partial or
failed only, the run ID is printed before the sample is chosen, `--point` takes `latest` in
any case, and the Graph certificate's variables are checked before any Veeam call.

**Decision.**

1. **The command line.** `rpworker restore [--mail <n>] [--sp <n>] [--od <n>] [--point
   latest|<id>] [--run-id <id>] [--canary-cursor <m>,<s>,<o>] [--manifest <path>] [--config
   <path>]`, the options in any order, each at most once. `<n>` is 1 to 3 ASCII digits, 0 to 100;
   an absent flag takes config's `sample_mail`, `sample_sp` or `sample_od`, and at least one of the
   three sizes must then be above 0 (exit 64, once the config is read). `--point` defaults to
   `latest` (*amended after the W2.8 review:* in any ASCII case), the newest restore point of
   `veeam_org_name` (`list_restore_points` returns newest first); `<id>` must be 1 to 128 ASCII
   letters, digits and hyphens (safe to echo in a message) and is matched ASCII
   case-insensitively against the points' IDs. *Changed in the build:* this entry first said a
   GUID, but Veeam's restore point IDs are two GUIDs run together (72 characters, e.g.
   `c2f0f2e7-…-93a50cf702e3` `71ac3d9c-…-ae81fcc4681c` in `restore-points-200.json`), and the
   connector's IDs are opaque, so a GUID rule would refuse every real ID. Anything else on the
   command line (a size above 100, a sign, a point that is neither, a bad run ID or cursor, a
   flag twice) is a usage error, exit 64, before the config is read. A well-formed ID that isn't
   one of the organisation's restore points is exit 4.
2. **Run ID and cursor, until the Cloud sends them** (W2.6 point 3 and its open point). Each
   invocation makes a run ID, `rp-<YYYYMMDDTHHMMSSZ>-<8 random hex digits>` (UTC, in
   `check_run_id`'s alphabet); `--run-id` reuses a recorded one to repeat a sample. The canary
   cursor is `--canary-cursor m,s,o` (default `0,0,0`); nothing is stored on the Worker. The
   command prints the run ID, the seed, the cursor and the next cursor before it restores, so an
   operator can repeat the run or carry the rotation on by hand. A cursor at or above the
   manifest's canaries of its type is a usage error (exit 64, once the config and the manifest
   are read; and one above 0 for a type the manifest has no canaries of); each of its three
   numbers is 1 to 6 digits, so none can overflow.
3. **The manifest** is `--manifest <path>`, default `seed-manifest.json` in the config file's
   folder (`%ProgramData%\RestoreProof\`, or the `--config` file's folder). No config key: the
   manifest is a client's, and the Cloud job will carry it (2026-09-29, "Clients live in the
   Cloud"). A manifest that doesn't load, or whose tenant isn't `graph_tenant_id`, is a
   configuration error (exit 1); the command checks the tenant as soon as the manifest is read,
   with `choose_sample`'s words, so it fails before any Veeam call.
4. **The order.** Arguments; config and the Veeam secrets (as `veeam list`); the manifest; the
   `veeam_m365` connector from the default registry; the organisation's restore points and the
   chosen one; `choose_sample`; the header printed; `restore_sample`, whose first step is still the
   target guard's layer 1 (the command adds no restore path of its own, and has no way around the
   guard); the tables. The Graph certificate is read by the connector on the restore, so a bad one
   is still exit 1. *Amended after the W2.8 review:* `RP_GRAPH_CERT_PFX_BASE64` and
   `RP_GRAPH_CERT_PASSWORD` are checked as set right after the Veeam secrets (`config error:
   <name> is not set`, exit 1), before any Veeam call, since the certificate is otherwise read
   only after the sample has been chosen; the run ID is made, and its two lines printed, before
   `choose_sample` (point 5).
5. **The output.** The header (restore point, run ID and seed, cursor and next cursor, per type
   the canaries and random items wanted and taken, with a shortfall named) goes to stdout and is
   flushed before the restore starts, which takes minutes: a run that then fails still shows its
   run ID. *Amended after the W2.8 review:* the restore point line and `run <id>  seed <hex>`
   are printed and flushed as soon as the run ID exists, before `choose_sample`, which browses
   Veeam and can fail; the cursor line (`canary cursor <m>,<s>,<o> -> <m>,<s>,<o>`, on its own
   line now, since it needs the sample's next cursor), the per-type table and `restoring <k>
   item(s) ...` follow once the sample is chosen, still flushed before `restore_sample`. A
   stdout that fails after the restore ran is `error: writing the output failed after the
   restore ran (run <id>)`, exit 1, so the operator knows items may be in the targets. After the restore: one row per item (kind, canary or random, name, outcome, session,
   the session's elapsed time, the connector's message), one row per restore session (ID, kind,
   Veeam's result, items restored of sent, start, end, elapsed), and a status line with the
   restore's status, items restored of sent and the total elapsed time. An item's elapsed time is
   its session's (end − start as the connector reports them, `-` when either doesn't read); the
   total is the `restore_sample` call's, by the steady clock. Warnings go to stderr only.
6. **Exit codes.** The existing codes keep their meaning for every command: 1 config (a manifest
   error and an unknown connector included), 2 auth, 3 transient, 4 service (a `SafetyViolation`,
   a restore point or item not found, any other connector error), 64 usage. New: **5
   (`exit_code::restore`): the restore ran and its status is `partial` or `failed`**; the
   status line says which. 0 only for `succeeded`. A random-half shortfall with every sampled
   item restored is `succeeded`, exit 0; the header shows it. Infrastructure problems never
   reach 5. *Amended after the W2.8 review* (this point first said 5 for `not_run` too, and
   that `restore_sample` throws for every infrastructure problem; it throws only when a session
   restored nothing for one, so an item can come back `failed` or `unknown` marked
   `infrastructure` in a partial restore):
   - an **empty sample** (every type asked for fell short entirely) prints the header, calls no
     `restore_sample`, and is exit 4: `restore error: the sample is empty: nothing to restore
     (<kind>: <shortfall>; ...)`;
   - a restore that returns **`not_run`** is exit 4 (`restore error: the restore did not run:
     nothing was sent (status not_run)`);
   - a restore in which **any item not restored is marked `infrastructure`** (Veeam couldn't
     reach Microsoft 365, lacked permissions or was throttled) prints the tables and the status
     line as usual, then is exit 4: `restore error: <n> item(s) failed for an infrastructure
     reason (...); this is an error, not a restore failure`. A run reports all of these as
     `error`, never `fail`.

**Reason.** The issue's "exit 0/1/3 for success/failure/error" collides with codes every command
already uses (1 is config, 3 transient); a restore that ran and failed is a result, not an error,
and needs its own code. Printing the run ID before the restore makes every run repeatable, even
one that fails. A manifest beside the config needs no new key and no new rule.

**Alternatives rejected.** *Reusing 1 or 3 for a failed restore:* a script couldn't tell a
failed restore from a broken config or an unreachable Veeam. *Two codes, partial and failed:* the
status line already says which, and W3.3's pass/fail/error replaces this code's meaning for
`rpworker test`. *A cursor file:* see W2.6. *A required `--manifest`:* every lab run would repeat
the path. *A `canary_manifest` config key:* per client, so the Cloud's.

---

## 2026-09-30 — W2.7 second review: a restore target is never a source, by what Veeam lists

Supersedes parts of the 2026-09-30 W2.7 review entry below (point 1's layer-1 mail rule and
point 2's `siteUrl` rule), after a `/code-review high` of PR #138 run on 2026-09-30, once W2.5
and W2.6 were merged.

**Decision.**

1. **Layer 2 checks the source as browsing found it.** Veeam's OneDrive document IDs don't name
   their folder and a mail restore's body doesn't name its source mailbox, so layer 2 could
   only trust layer 1's reading of the sample. `restore_sample` now passes what Veeam listed:
   `GuardedItem::top_folder` (the top-level folder walked to a OneDrive item) and
   `RestoreRequestContext::source_mailbox` (the source mailbox's `email`). Layer 2 refuses an
   item whose top folder is a RestoreTarget folder (any OneDrive) and a source mailbox that is a
   restoretest mailbox or the test mailbox, so an alias, an object ID or a stray space in the
   sample can't hide the test mailbox. `source_mailbox` is required for mail (`bad context`).
2. **One path rule, stricter.** `src/folder_path.hpp`'s `first_folder` (the guard's layer 1,
   the sampler and the manifest loader) also refuses a path holding a backslash or a colon: no
   SharePoint or OneDrive name holds either, so such a path is another spelling of a folder
   (`\RestoreTarget`, Graph's `/drive/root:/RestoreTarget`), never one of the backup. The lister
   skips folders so named. A `/Documents/RestoreTarget` subfolder stays a source, as before.
3. **Layer 1 refuses a mailbox with whitespace or a control character** (and the manifest
   loader such a canary mailbox), and **a SharePoint item on the test OneDrive's drive**
   (`test_onedrive_drive_id`; the sampler already refused it, and now its canary check too).
4. **`siteUrl` is checked where Graph gives it.** The library's must be https on
   `test_site_id`'s host, the OneDrive folder's https on that tenant's `-my` host, neither with
   a query, fragment or whitespace; before, any string (even an empty one) passed layer 1 and
   became layer 2's only reference for `siteURL`.
5. **One derivation of the OneDrive host**: `rp::onedrive_host` (`rp/config.hpp`), used by the
   download allow-list, `veeam_restore::onedrive_url`, layer 2 and point 4.
6. The lab's fixture recorder requires alice's OneDrive `siteUrl` exactly, host included.

**Kept as they were.** (a) Exchange's 403 on the mailbox check stays a `SafetyViolation` (the
W2.7 review's point 1): the guard can't tell another mailbox from a missing scope, and treating
an unverified target as a refusal fails safe; the message names both causes. (b) A bad Worker
certificate still leaves `restore_sample` as `rp::ConfigError` (exit code 1, as documented on
`VeeamM365ConnectorOptions::make_graph`); `connector.hpp` now says connectors may let it out.

**Reason.** Each layer should refuse on data it can check itself: the sample's text is the
input under suspicion, and Veeam's listing and Graph's reply are what the restore acts on.

**Alternatives rejected.** Refusing every path with a RestoreTarget segment anywhere (would
refuse real data such as `/Documents/RestoreTarget`, and the lister and sampler would have to
follow); mapping the mailbox 403 to `PermissionError` (reports a possibly wrong target as a
grant problem); converting `ConfigError` to `connector::Error` (a broken certificate would exit 4
instead of 1).

## 2026-09-30 — W2.6: how the sample is chosen (proposed; recorded before the build)

Recorded before any of it was built. Proposed: the owner confirms it in the W2.6 review, or
supersedes it.

**Decision.**

1. **The selector is pure; one new connector call lists the candidates.**
   `rp::sampling::SampleSelector::select(plan, manifest, cursor, targets, pool, run_id)`
   (`rp/sample_selector.hpp`) does no I/O and reads no clock. The random half's pool comes from
   a new `IConnector::list_candidates(CandidateQuery)` (`rp/connector.hpp`, no Veeam name in it;
   read-only for Microsoft 365; its default throws `NotImplementedError`, so another connector
   needn't have it), and `choose_sample` calls it only when a random half is above 0.
   `restore_sample` and both guard layers are unchanged: the guard still checks every item the
   sampler chose.
2. **Halves.** Per type, with N = `sample_mail`/`sample_sp`/`sample_od` and M the manifest's
   canaries of that type (today 20 mails, 10 SharePoint files, 10 OneDrive files, not 20 of each):
   c = min(ceil(N/2), M) canaries and floor(N/2) random items. Canaries left over when
   ceil(N/2) > M are not moved to the random half.
3. **Canaries rotate by a cursor, and the cursor is the rotation's only state.** A type's
   canaries, in manifest order, are taken from positions cursor … cursor+c−1 (mod M), and the next
   cursor is (cursor+c) mod M. Windows follow each other without a gap, so every canary is taken
   within ceil(M/c) ≤ ceil(20/(N/2)) runs. The Worker keeps no state: the cursor is an input and
   the result carries it and the next one. It belongs with the client in the Cloud (the
   `client-profile.v1` job of 2026-09-29, W4.10/C5.13), which hands the next run the last run's
   `cursor_next`; until then tests and the CLI pass it (`0,0,0` by default).
4. **The seed comes from the run ID; the draws are portable.** seed = the first 4 bytes,
   big-endian, of SHA-256("restoreproof/sample-v1\n" + run_id). Each type has two streams, browse
   and items, seeded the same way from the seed, the type and the stream, so changing
   `sample_mail` never moves a OneDrive pick. The generator is `std::mt19937` seeded with one
   value; `below(n)` rejects outputs at or above 2^32 − (2^32 mod n); a pick is a lazy
   Fisher–Yates over a sorted list. No `<random>` distribution, `std::shuffle` or `std::sample` is
   used: their algorithms differ between standard libraries, and an auditor must be able to
   repeat a draw anywhere.
5. **Reproducible from the seed and the manifest, with the cursor and the restore point.** The
   seed and the manifest alone don't fix a selection: the cursor says where the rotation is, and
   the random half depends on what the restore point holds. The result records all four (run ID
   and seed, the manifest's SHA-256, the cursor, the restore point's ID and `backupTime`), plus
   each pool's size and SHA-256, so a replay can show it drew from the same pool. A restore point
   doesn't change while retention keeps it. One input isn't the restore point's: a OneDrive's
   owner (`restore_sample` finds a OneDrive by its owner's UPN) comes from
   `GET /v8/Organizations/{org}/Users`, Veeam's cache of the tenant's users today. So which
   OneDrives are eligible, and the order they are drawn in, come from the restore point alone
   (every OneDrive with a well-formed ID and a `url` no other shares); a drawn OneDrive that no
   single user owns now (deleted, renamed, not yet in the cache) is walked and its folders drawn
   as usual, so the draw goes on unchanged, but nothing in it is listed. The result counts those
   (`containers_unresolved`) and lists them by `url`, so a replay after a user change shows why
   its OneDrive pool differs.
6. **The random half is drawn in two levels, from real data only.** Eligible containers
   (mailboxes, sites, OneDrives) are sorted and drawn one at a time; in each, up to 3 folders are
   drawn and listed, until 2 containers have given a candidate or 8 have been tried (a few dozen
   Veeam calls, whatever the tenant's size). Every listing is the one `restore_sample` makes later,
   and an item is a candidate only if that call will find it exactly once: its subject, file name
   or folder name is unique in the whole listing, not only among candidates. Never a candidate:
   - a restore target: a `restoretest` mailbox, the RestoreTarget library (by its derived drive ID,
     point 8, and by its `url`), a top-level `RestoreTarget` folder in any OneDrive;
   - a canary location or copy: the canary libraries (by list ID), a top-level `RestoreTest` folder
     in any OneDrive and any other top-level folder the manifest's OneDrive canaries are in
     (`CandidateExclusions::onedrive_folders`, by name in any OneDrive, as `RestoreTest`), a
     subject or name starting with `rp-canary-` or equal to a canary's (ASCII case-insensitive;
     this catches the Sent Items copies);
   - an archive, public or `DiscoverySearchMailbox` mailbox; a personal or other-host site; the
     `SitePages`, `SiteAssets`, `Style Library` and `FormServerTemplates` libraries; a non-mail
     folder (`type` other than `None`) or the Deleted, PermanentlyDeletedItems, Drafts and Outbox
     folders; an item class other than `IPM.Note`; a file above the 64 MiB download cap.
   Mail comes from top-level folders only (whether `folders?name=`, which `restore_sample` uses,
   finds nested folders is unrecorded). `select` checks the pool again and refuses all of it
   (`std::logic_error`, nothing sampled) if a forbidden candidate gets through: on the selectors'
   own fields, so for SharePoint the RestoreTarget library and the test OneDrive (alice's
   OneDrive is a SharePoint site too) by drive ID and by the drive ID the site, web and list
   GUIDs give, and a site on a host other than `test_site_id`'s (a personal site, another
   tenant). What selectors don't carry (a mailbox's kind, a library's url, an item class, a
   size) only the lister can check.
7. **Same names and duplicates are skipped, deterministically.** Candidates are sorted by key and
   deduplicated. Canary names and subjects are unique (the loader checks) and never in the pool. A
   random pick whose subject or name is already taken for its type, the case of any letter aside
   (case-insensitive, Unicode, invariant upper case: `src/name_key.hpp`, which `restore_sample`'s
   same-name refusal uses too; SharePoint and OneDrive fold more than A-Z), is skipped and the
   next draw is used; the skipped draw still counts, so the sequence stays fixed.
   So `restore_sample`'s refusals (two SharePoint or two OneDrive files of one name, one item
   twice) can't fire, and no two mails of one subject are restored (the read-back couldn't tell
   them apart).
8. **The SharePoint drive ID is derived, not read.** A random SharePoint item's `drive_id` is
   "b!" plus the base64url, without padding, of the site, web and list GUIDs' little-endian bytes.
   This reproduces the canary library's, the RestoreTarget library's (`test_library_id`) and
   alice's OneDrive's drive IDs from `lab/tenant.md`, so guard layer 1 needs no change and still
   refuses the target. The Worker app can't read a source through Graph.
9. **Office files may be picked.** A canary's `size` is its `stored_size` for `bytes` files and −1
   for `office-v1` files (SharePoint rewrites docx and xlsx, so their stored size is evidence only;
   W3.2 compares their content with office-v1). A random item's `size` is −1; Veeam's `sizeBytes`
   stays in the pool for W3.
10. **A small pool is a shortfall, recorded, not filled.** With fewer eligible candidates than
    floor(N/2), all of them are taken and the result says how many were wanted and taken, and
    whether fewer than 2 containers gave any. W3.3 decides what a shortfall does to the status;
    the proposal is that it never turns `pass` into `fail`, and the report says how many real
    items were tested. The lab has almost no real data today, so its random half is mostly empty
    until some is seeded (open point).
11. **Explore sessions.** `list_candidates` opens one explore session per type and stops each one
    before it returns; one it can't stop is `connector::Error`, since `restore_sample`'s preflight
    would then refuse. The session bookkeeping moves out of `restore_sample` into
    `src/veeam_explore.*`, with no change in behaviour. Veeam lists explore sessions in
    `/v8/RestoreSessions` with the restore's type (restore-flow §12), so a lister's session,
    stopped seconds before the restore POST, would pass `restore_sample`'s duplicate check (ours,
    that type, new since the POST less 5 s) and leave the run without a verdict. The connector
    remembers every explore session `list_candidates` opened or adopted, also when it throws, and
    they join the duplicate check's known set. A Stop that fails as transient (timeout, dropped
    connection, a 5xx Veeam calls transient) is followed by a re-read and, if the session is still
    `Working`, one more Stop, at most 2 per session; auth errors and 4xx aren't retried (2026-09-30:
    the live dry run's Stop of explore session e251a437 timed out after 30 s with the session still
    `Working`, and a second Stop minutes later returned 204 at once).

**Reason.** Canaries rotate so each one is tested within the bound the task sets; a seeded offset
couldn't promise that. The random half must be real data outside the targets and the canary
locations (2026-09-25), and a restore target is in every backup (W2.4). Listing a whole tenant is
too slow, while a two-level draw costs a few dozen calls. Portable draws let an auditor repeat a
selection on any platform. Deriving the drive ID avoids a Graph read the Worker app isn't granted
and a change to the strict guard.

**Alternatives rejected.** *`std::uniform_int_distribution` or `std::shuffle`:* their output
depends on the standard library. *Random or date-based rotation:* no coverage bound. *A cursor
file on the Worker:* one Worker serves many clients (2026-09-29, "Clients live in the Cloud"), and
a lost file would silently restart the rotation. *Deriving the rotation from a run counter:* it is
the same state under another name. *Listing every container:* too costly. *Veeam's search:* not
uniform, and veeam-notes §5.4 keeps it for later. *Filling a shortfall with canaries:* the report
would overstate the real-data share. *Relaxing guard layer 1 to accept an empty `drive_id`:* it
weakens a strict check. *A Graph read of each source:* the Worker app reads the targets only.

**Open.** Where the run ID and cursor come from before the Cloud (proposed: `--run-id` and
`--canary-cursor` on S2's `rpworker restore`); real data in the lab for the random half (a new L
task: a few non-canary mails in alice's and bob's mailboxes, files in another library of the
RestoreTest site and in bob's OneDrive, then a backup); what a random item is verified against
(W3.1: the glossary says a live Graph read, which the grants rule out, so the proposal is Veeam's
own listing: presence, name or subject, received time, size for non-Office files); whether group
mailboxes such as `allcompany` are sampled (proposed: yes).

---

## 2026-09-30 — W2.5 second review: restore point, errors, infrastructure, paging

Amends points 2, 4, 6, 8, 9 and 10 of the W2.5 entry below and point 5 of its first review,
after the second review of the W2.5 branch (14 findings on PR #139). Proposed with them: the
owner confirms in the W2.5 review, or supersedes.

**Decision.**

1. **The restore point is checked.** After the organisation, `restore_sample` lists its restore
   points (`list_restore_points`); the spec's `restore_point.id` must be one of them and its
   `backup_time` equal byte for byte, else `connector::Error` before any explore session.
   Veeam explores the newest data at or before an explore's `dateTime` (veeam-notes §4.2), so
   a stale or another client's time would restore other data than the result names.
2. **`connector::NotFoundError` means one thing in `restore_sample`:** a sampled item (or its
   source mailbox, folder, site, library or OneDrive) isn't in the restore point, the case
   W3.3 may call `fail`. Everything else that is "not found" is `connector::Error`: a client
   Veeam doesn't know, the test OneDrive missing from the point, a restore target Graph can't
   find (the guard's `graph::NotFoundError`), and Veeam's own 404 `ResourceNotFound` mid-run
   (an expired session). `list_restore_points` keeps its W1.7 mapping.
3. **Mailboxes are the primary ones.** An entry with `isArchive` true (a user's in-place
   archive, listed with the same email) is never a sample's source mailbox.
4. **What reads as infrastructure (amends point 9 and review point 6).** The marker list grows
   from W1.0's four texts to the usual words of a failed service call ("Failed to access
   mailbox", connect / connection, access denied, unauthorized, forbidden, (401), (403), (429),
   too many requests, throttl-, (503), service unavailable, server busy, timed out, timeout,
   proxy, could not be resolved, certificate, token): broad on purpose, since a doubt must be
   `error`, never `fail`. They are matched in Veeam's own words only (`veeam_words`): every
   item name, the run's tenant texts (the source containers' names and addresses, folder
   names, the targets' names and URLs), Veeam's `source: …;` and `target: …)` fields, quoted
   parts and every word holding `@`, `/` or `\` are cut out first. And a session that
   restored nothing and whose events name no item (Veeam never reached them) is infrastructure
   whatever its words: nothing is known about the backup.
5. **An unpinned restore keeps the explore sessions open (amends point 8).** When the POST was
   accepted but the duplicate check didn't list its session alone (or failed), our session is
   still polled and read, but the explore sessions stay open and are named in the error: the
   other candidate may be running under them. In the no-answer branch a failed duplicate check
   is `connector::Error` (no verdict), never the lookup's own `TransientError` or
   `NotFoundError`.
6. **An orphaned explore session is adopted only when it is certainly ours (amends review
   point 5).** After a failed explore POST, the duplicate check's filter also requires the
   session `Working` and of this organisation (`organization`), and exactly one must match; with
   several, none is stopped and the sweep script is named. The duplicate check after a restore
   POST also filters by organisation (an entry without the field is kept, so it can only add a
   candidate).
7. **Smaller ones.** Events are read through `VeeamClient::get_all` (paged, each ID once, a page
   Veeam caps below the limit asked for isn't taken for the last). `open_explore_session`
   returns the ID in lower case, as `post_restore_once` does. One organisation's settings of an
   unexpected shape no longer fail `list_organizations` for all: `Organization::settings_problem`
   says why its app is unset, and `restore_sample` refuses that organisation with it.
   `parse_veeam_time` (`src/veeam_time.*`) is the one reader of Veeam's time form, for
   `VeeamClient` too.
8. **The registry's factory makes the Graph client on the first `restore_sample` (amends point
   10),** through `VeeamM365ConnectorOptions::make_graph`: listing restore points needs neither
   `RP_GRAPH_CERT_*` nor the Graph IDs. Their `CertificateError` / `ConfigError` now pass out
   of `restore_sample`, before any HTTP client and any request, and are tried again next time.

**Reason.** Each closes a case the review found: an explore session stopped under a restore that
may still run, a result attributed to a point it didn't restore from, every mail of a user with
an archive an error, a retryable error while a restore may run, infrastructure failures (and
tenant text) turning into `fail`, a config problem read as a missing item, events cut short, a
case mismatch refusing every restore, one odd organisation breaking `veeam list`, another
process's session stopped, and listing restore points needing a certificate it never uses.

**Alternatives rejected.** An allow-list of item-level failures instead of the marker list
(Veeam's texts for a bad item are not documented; the no-item rule and the markers err towards
`error`); matching the restore point by time alone (two points can share a second); keeping
the explore sessions open only when the check listed another candidate (a failed check can't
rule one out either).

## 2026-09-30 — W2.5 review: what `restore_sample` refuses, closes and wipes

Amends points 1, 3, 5, 6, 7, 8 and 9 of the W2.5 entry below (proposed), after the review of
the W2.5 branch. Proposed with it: the owner confirms both in the W2.5 review, or supersedes
them.

**Decision.**

1. **Point 1, how the credential is exported and which copies are wiped.** The exporter adds a
   *link* to the certificate to a memory store (`CertAddCertificateLinkToStore`), not a copy: a
   copy loses a key that is held only in memory, which the tests' imported PFX is. The source
   store and certificate context outlive the memory store (both are held across the export).
   After `PFXExportCertStoreEx`, the PFX is re-imported in memory (`PFXImportCertStore` with
   `CRYPT_EXPORTABLE | PKCS12_NO_PERSIST_KEY`), and one exported without its key is refused.
   Wiped with `SecureZeroMemory`: the `ExportedPfx` (PFX and password), the body's text (spliced
   into one buffer reserved up front, so growing it frees no partial copy; the JSON body itself
   never holds the credential, and a value that would need JSON escaping is refused), the target
   guard's parsed copy of the two values, and `VeeamClient`'s request body after the send. **Not
   wiped, out of reach:** the copy `HttpClient` hands to cpr (`cpr::Body`, freed with the
   session), libcurl's and Schannel's send buffers, and the JSON parser's token buffer while the
   guard reads the text. They live only in the Worker's memory, never in a log, a file or a
   message; anyone who can read that memory can export the same key from `LocalMachine\My`
   anyway (the exporter needs it exportable). "Buffers are wiped once the body is sent" means the
   list above.
2. **Point 3, two files of one name are refused.** `restoreTo` and `copyTo` drop the source
   path, so two SharePoint files, or two OneDrive files, of one name (case-insensitive, Unicode,
   invariant upper case, as the W2.6 review made it; from two folders or two sources) land on one
   target file, the second a new version of the first,
   and the read-back would fail the first although its backup was fine. `restore_sample` refuses
   such a spec with `connector::Error` before any Veeam request; the sampler (W2.6) must not pick
   them. Two selectors that resolve to one backup item (same container and ID) are refused after
   browsing, before any restore POST (they would restore it twice, in two calls). Point 5's split
   of same-named items stays for mail.
3. **Point 6, a POST that never went out.** A connection or TLS handshake failure on the restore
   POST is `RestorePostOutcome::not_sent`: nothing went out, so `connector::TransientError`, no
   duplicate check, and the explore sessions are closed. Only a dropped connection, a timeout, a
   5xx or a 2xx without `sessionId` are "no answer". A refused POST with `errorCode`
   `ResourceAccessDenied` is `connector::AuthError` whatever its status (restore-flow §15). An
   accepted `sessionId` is kept in lower case, as the duplicate check lists it.
4. **Point 7, statistics and events after the stop.** Any failure reading them other than a 409
   (or a lost sign-in, `AuthError`) is `connector::Error` "... stopped, but its statistics / events
   couldn't be read ...; no verdict": never `NotFoundError` (a missing item) or `TransientError`
   (try again), since the restore ran.
5. **Point 8, an explore POST that failed.** One that fails once it may have gone out (a
   timeout, a dropped connection, a 5xx, a 2xx without an `id`; not a refused sign-in) may still
   have opened a session (veeam-notes §4.4). The duplicate check's query and filter run from the
   POST's time; every new `Working` session of ours of that type is recorded and closed with the
   others, so the next run's preflight isn't blocked. A failed lookup is logged with the sweep
   script.
6. **Point 9, what reads as infrastructure.** Only Veeam's own words: session-level events,
   statistics errors, and failing item events with the item's name cut out. A sampled mail's
   subject or a file's name is the tenant's text ("AADSTS50076 sign-in error" is a plausible
   subject) and never turns a `failed` into an error; a restored item is never flagged.
7. `parse_veeam_time` accepts years 1678-2261 only, what a time in nanoseconds holds.

**Reason.** Each closes a case the review found: a leaked explore session blocking every later
run, a restore sent twice or onto one file, user data flipping `failed` to an error, a
post-restore failure read as a missing item, and a decision that claimed more wiping than the
code did.

**Alternatives rejected.** Restoring same-named files in separate runs with cleanup between
(W3.4's cleanup doesn't exist yet; the sampler avoiding them is simpler); wiping cpr's copy by
passing the body to curl without one (cpr has no non-owning body, and libcurl and Schannel keep
their own buffers anyway); leaving an orphaned explore session to the sweep (the Worker runs
unattended).

## 2026-09-30 — W2.5: how `restore_sample` restores (proposed; recorded before the build)

Recorded before any of it was built, as #30 asks for the credential export. Proposed: the owner
confirms it in the W2.5 review, or supersedes it.

**Decision.**

1. **The restore credential is exported in memory through CryptoAPI** (the 2026-09-28 W2.4
   entry: Veeam's own organisation app; the 2026-09-29 "The Worker runs on the Veeam server"
   entry). A neutral interface, `rp::CertificateExporter` (`rp/cert_export.hpp`: export by
   SHA-1 thumbprint, returning a Base64 PFX and its one-time password), keeps `rpcore`'s restore
   logic testable without a certificate store. The Windows one, `LocalMachineCertExporter`:
   `CertOpenStore` on `LocalMachine\My` (read-only), `CertFindCertificateInStore` by
   `CERT_FIND_SHA1_HASH` with the thumbprint Veeam reports in `GET /v8/Organizations`; refuses a
   certificate that has expired or has no private key (`CryptAcquireCertificatePrivateKey`,
   silent, no UI); copies it into a memory store and exports it with `PFXExportCertStoreEx`
   (`EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | REPORT_NO_PRIVATE_KEY`)
   under a password of 32 random bytes from `BCryptGenRandom`, in Base64. No file is written at
   any point (the PowerShell script's `%TEMP%` file goes away). Buffers are wiped with
   `SecureZeroMemory` once the body is sent. It needs what the script needed: an elevated
   process (or LocalSystem) and an exportable key; W4.12 (#135) decides the service account. A
   failure is `connector::Error` ("the Veeam organisation app's certificate ...: run elevated
   ..."), before any restore POST.
2. **The organisation app is cross-checked first.** `rp::Organization` also parses
   `exchangeOnlineSettings` and `sharePointOnlineSettings` (`applicationId`,
   `applicationCertificateThumbprint`); both must be present and equal, or `connector::Error`
   before any explore session. The body's `applicationId` and the exported thumbprint are that
   pair; `officeRegion` is the organisation's `region`, `organizationName` /
   `officeOrganizationName` its `officeName`.
3. **Selectors gain what the manifest already has**, so no source needs a Graph read the Worker
   app isn't granted (it reads the targets only): `MailSelector::received_at` (optional; when
   set, Veeam's `received` truncated to the second must equal it), `SharePointSelector::list_id`
   (required: Veeam's library ID is the site's two GUIDs, from `site_id`, followed by it; never a
   name, which is localised) and `size` (optional, the manifest's `stored_size`, checked on the
   re-read), `OneDriveSelector::size` (the same). The source OneDrive is Veeam's `OneDrives`
   entry whose `url` is `https://<tenant>-my.sharepoint.com/personal/<user, lower case, '@' and
   '.' as '_'>` (ASCII case-insensitive, exactly one), `<tenant>` from `test_site_id`'s host; a
   folder path is walked segment by segment through `Folders?parentId=` (`root` first).
   SharePoint folder paths other than `/` are walked the same way from the library.
4. **Browsing as 10-restore.ps1 does**, one explore session per type (`dateTime` the restore
   point's `backup_time` byte for byte), every list with `limit=1000` and paged; exactly one
   match per item, re-read by ID; the re-read document goes into the body minus `_links` and
   `_actions`. Zero or several matches, or a container not found, is `connector::NotFoundError`
   or `connector::Error` (`error`): the zero-match `fail` for a canary is W3.3's to settle, so
   W2.5 doesn't guess it.
5. **One restore call per source container; same-named items in one container go into separate
   calls** (events name items only by `itemName`). The explore session is reused for the next
   container of the same type (untried, restore-flow §18; the first live run shows it).
6. **The POST goes out at most once.** A preflight first (`GET /v8/RestoreSessions?limit=200`: no
   session of ours `Working`, else `connector::Error` before any explore). The POST is sent with
   one attempt, no retry of any kind, a 60 s timeout, and the exact text layer 2 checked. A 4xx:
   nothing started, `connector::Error` (401/403 `connector::AuthError`). No session ID (a
   transport error, a timeout, a 5xx, a 2xx without `sessionId`): the duplicate check of
   restore-flow §8, up to 3 more looks 10 s apart; exactly one candidate is adopted, else
   `connector::Error`, never a resend. With a session ID, the check must list exactly it, or the
   session is still polled but the call ends in `connector::Error` (no verdict).
7. **Waiting and reading** as restore-flow §9-§12: poll every 5 s; `Stopped` ends it; a 404 or 6
   failed polls in a row is `connector::Error`; still `Working` after 20 minutes is
   `connector::TransientError`. Statistics (409 retried, 6 attempts 5 s apart) and events are
   required, of the expected JSON kinds, else `connector::Error`. Start and end times are the
   session's `creationTime` and `endTime` as Veeam wrote them.
8. **Sessions are closed in a finally path, except under a restore that may still run.** Every
   explore session the call opened is read and, while `Working`, stopped (`POST .../Stop`, best
   effort). After a timeout, a 404 or failing polls, or a POST whose session couldn't be pinned
   down, the explore sessions are left open and named in the error (the 2026-09-29 W2.4 review:
   what Stop does under a running restore is untested). This narrows #30's "close sessions in a
   finally path even on error" by that one case.
9. **Status and per-item results.** `RestoreResult` gains `items_sent`, one
   `RestoreSessionResult` per restore session (ID, kind, Veeam's `result` and `details`, start
   and end, items sent and restored) and one `ItemRestoreResult` per item (kind, name,
   `restored` / `failed` / `unknown`, Veeam's message, and whether that message reads as
   infrastructure). The status is the W1.7 order with restore-flow §12's stricter `succeeded`
   (every session `Success`, its `restoredItemsCount` equal to the items sent, a
   `Restore`/`Success` event per item name, and for files a `Statistics.items[]` `Success` entry
   per ID). A session that restored nothing and whose events or errors read as infrastructure
   ("Cannot connect to Microsoft 365", "Failed to open mailbox", "missing the required
   application permissions", `AADSTS`) is `connector::Error`, never `failed`. `log` is the
   events' `status itemName: message` lines per session, through `rp::redact`. Veeam's own log
   file on disk is not read (the evidence bundle decides that, W3.x).
10. **The registry's factory makes the Graph client**, from `RP_GRAPH_CERT_PFX_BASE64` and
    `RP_GRAPH_CERT_PASSWORD` through `graph::certificate_from_secrets` (`ConfigError` if unset),
    with `Config::graph_tenant_id` and `graph_client_id`, on `graph::make_graph_http_client`
    (or `ConnectorOptions::make_graph_http`). Every logger it hands out (Veeam, Graph, the
    guard) is `ConnectorOptions::logger` or else the command logger (stderr), never spdlog's
    default. `ConnectorOptions` gains `now`, `wall_now`, `make_graph_http` and `cert_exporter`.
    `rp::redact` also masks `applicationCertificate` and `applicationCertificatePassword`.

**Reason.** It is 10-restore.ps1's proven flow (W2.4, mail r1) in C++, with the W2.4, W2.4
review and W2.7 decisions as they stand. The in-memory export removes the script's one file on
disk. Selectors carrying the manifest's IDs keep the Worker app's grants as they are.

**Alternatives rejected.** Exporting through a temporary file as the script does (a PFX on
disk, however briefly); `NCryptExportKey` of the key alone (Veeam wants a PFX); a vault copy of
the PFX (W4.12 decides; the 2026-09-28 entry keeps "never stored"); Graph reads of the source
site, drive or user (not granted); decoding Graph's `b!` drive IDs into GUIDs (works in the lab,
undocumented); resending a POST with no answer (could restore twice); stopping an explore
session under a running restore (untested).

**Live run.** #30's Done-when, 2026-09-30 07:35:12Z–07:37:39Z, run with the owner's go-ahead
from an elevated shell: `rptests.exe "[live][writes]"` (`veeam_m365_restore_live_test.cpp`,
`RP_LIVE=1`, `RP_LIVE_RESTORE=1`) restored RP-CANARY-0001 to 0005 (alice's Inbox) into
restoretest's Inbox, rp-canary-01.pdf, 04.txt and 06.pdf into the RestoreTarget library and
rp-canary-11.pdf and 14.txt into alice's `/RestoreTarget`, from the newest restore point
(`backupTime` 2026-09-29T22:00:45.6603083Z), into targets `rpworker graph list` had shown empty.
Status `succeeded`, 10 of 10, in three restore sessions, all `Success` (mail `6cd07acf-…`, 5 of
5; SharePoint `2ab2e15d-…`, 3 of 3; OneDrive `0819da9f-…`, 2 of 2). Point 1's in-memory export
(Windows' default PFX encryption) was accepted for all three types; point 5's one call per type
in a run of three types, point 6's duplicate-check query and point 9's per-item events matched
by `itemName` worked live. `rpworker graph list --hash` then found exactly the 10 items, all 10
SHA-256 values equal to `lab/seed-manifest.json`'s, and `08-sweep-sessions.ps1 -WhatIf` found
none of the 96 sessions `Working` (point 8's finally path stopped the three explore sessions).
Point 5's reuse of an explore session for a second container is still untried (one container
per type). The 10 copies stay in the targets until the owner removes them by hand (W3.4).
Details in restore-flow §19; evidence `docs/api/veeam-lab/w2.5-live-*`.

## 2026-09-30 — W2.7 review: the guard resolves the mailbox and the OneDrive's address, and runs first in `restore_sample`

Supersedes parts of the 2026-09-29 W2.7 entry below (points 1, 2 and 3, and its opening
paragraph), after the max-effort review of PR #138.

**Decision.**

1. **The mail target is resolved through Graph too.** Layer 1 reads
   `GET /users/{test_mailbox}/mailFolders/inbox?$select=id` once when the spec has mail items
   (`rp::graph::check_restore_mailbox`, `ResolvedMailbox`, `CheckedTargets::mailbox()` now an
   optional that is set only then). The Worker app reads mail only through Exchange RBAC
   `Application Mail.Read` in a management scope of the restoretest mailbox's primary address
   (`docs/security/graph-permissions.md`, #3), so a 200 shows the configured
   `restoretest@<domain>` reaches that mailbox and not a live mailbox holding the name as an
   alias (or a group). Exchange's 403 is a refusal (`SafetyViolation`: another mailbox, or the
   scope is missing); a 404 stays Graph's `NotFoundError`. No new permission. Layer 2 now
   requires the mailbox resolved for a mail request (`bad context: the test mailbox was not
   checked`), and a `restoretest` address there.
2. **Layer 2 ties `onedrive.url` and `onedrive.id` to the RestoreTarget folder's OneDrive.**
   The folder GET now selects `sharepointIds` (`$select=id,name,folder,parentReference,
   sharepointIds`, read through the existing folder grant): its `siteUrl` is exactly the URL
   Veeam's copyTo names (recorded live 2026-09-29), and its `siteId` and `webId` run together
   are Veeam's OneDrive ID. `onedrive.url` must equal that `siteUrl` and `onedrive.id` those two
   GUIDs (ASCII case-insensitive), besides equalling W2.5's context; before, a URL on the
   tenant's `-my` host that the context agreed with passed, so another user's OneDrive could
   too. `ResolvedOneDriveFolder` gains `web_id` and `site_url`; the shared check (also
   `TargetReader`'s) requires `sharepointIds` with the folder's `siteId`, a GUID `webId` and a
   string `siteUrl`.
3. **`restore_sample` runs layer 1 first.** `VeeamM365Connector` takes an optional Graph
   client and `TargetGuardOptions`; `restore_sample` refuses without a Graph client
   (`connector::Error`, no request), runs `TargetGuard::check_spec` before any Veeam request,
   maps Graph's errors to connector ones (`AuthError` and `PermissionError` to `AuthError`,
   `TransientError`, `NotFoundError`, the rest `connector::Error`), and only then throws
   `NotImplementedError` until W2.5. `veeam_m365_restore_guard_test.cpp` pins that a refusal
   and a passing guard both leave Veeam without a request. The registry's factory makes no
   Graph client yet; W2.5 adds it. Layer 2 stays W2.5's to call before each POST (the TODO in
   `restore_sample`).

**Reason.** A configured value proves nothing by itself, the mailbox included (the W2.4
review's rule, which the first W2.7 cut applied to the file targets only), and W2.5's context is
built by the same code the guard is meant to check, so agreeing with it proves nothing either.
#32's Done-when is "the guard is the first line of every restore call".

**Alternatives rejected.** `GET /users/{mailbox}?$select=id,mail` (needs `User.Read.All`, which
the app deliberately lacks); the OneDrive drive's `webUrl` (a drive-level read the folder grant
may not cover, and it ends in `/Documents`); keeping #32 open until W2.5 (the wiring and its test
cost little now, and W2.5 then can't skip the guard without breaking a test).

## 2026-09-29 — W2.7: the restore-target guard in two layers; `SafetyViolation`, exit code 4

**Decision.** `TargetGuard` exists as two standalone units with the API W2.5 will call;
`VeeamM365Connector::restore_sample` still throws `NotImplementedError` and carries a TODO
naming the calls. It builds what the 2026-09-29 W2.4 review entry decided: the guard trusts no
configured ID, runs per item inside `restore_sample` before any Veeam call, and checks the
exact body again before the POST.

1. **Layer 1, `rp::TargetGuard::check_spec(const RestoreSpec&)`** (`rp/target_guard.hpp`), before
   any call to the backup product. First every item, in the spec's order, with no call: a mail
   item may not come from a `restoretest` mailbox (`is_restore_mailbox`, any case, the test
   mailbox included), a SharePoint item not from `test_library_id` (ASCII case-insensitive), a
   OneDrive item not from a path whose first folder is `RestoreTarget` (any case; empty and `.`
   segments skipped, a `..` segment refused); an item naming no source is refused too. Then,
   once per type the spec uses, the targets through Graph (GETs only; mail needs none): the
   library and the OneDrive folder must be the dedicated `RestoreTarget`s. The canary
   locations are kept out by those exact names (the canary library and folder are both
   `RestoreTest`) and the `webUrl` rule; no list ID is compared with the canary library's, since
   the config carries no canary ID (restore-flow §16's "the library's list ID isn't the canary
   library's", and the W2.4 review's "not a canary location", are met this way). An empty spec
   calls nothing. It returns `CheckedTargets`, which only `TargetGuard` can make.
2. **The Graph checks are one unit, shared with W2.2's reader** (`rp/target_guard_graph.hpp`:
   `check_restore_library`, `check_restore_onedrive_folder`, `ResolvedLibrary`,
   `ResolvedOneDriveFolder`). `TargetReader` calls them; its messages and `WrongTargetError`
   are unchanged (the ending comes from `TargetCheckWording`). Two checks are new, for both
   callers: `sharePointIds.listId` must be a GUID and `.siteUrl` a string, and the folder's
   `parentReference.siteId` a GUID, since layer 2 compares the body with them. The names stay
   exact (`Dokumenty`, `Documents`, `RestoreTest`, `restoretarget` and look-alikes with U+00AD
   or U+200B are all refused by the name rule); the forbidden-name list is only layer 2's extra
   check.
3. **Layer 2, `rp::veeam::check_restore_request(const CheckedTargets&, const
   RestoreRequestContext&, path, body)`** (`rp/target_guard_veeam.hpp`), immediately before the
   restore POST, on the exact path and text. It ports `Assert-RestoreTarget` of `10-restore.ps1`:
   the path is exactly the kind's restore-to-another-location call with an explore session this
   run opened and no query, fragment, `%`, `\`, `//` or dot segment; the body is valid UTF-8
   JSON, an object, every key at any depth printable ASCII, with no key twice in any object and
   no two keys of one object that differ only in ASCII case (a parser callback; nlohmann would
   keep the last, and Veeam's .NET binder may match names ignoring case, so an `Id` beside the
   checked `id` of a document could be what it restores), and exactly the kind's key set;
   documents may carry Veeam's other browse fields; values are checked by JSON kind; every value
   compared with a target or fixed name must be printable ASCII; comparisons are ordinal
   (`std::string` `==`) except the OneDrive host and first GUID and the RestoreTarget-library
   prefix of SharePoint document IDs (ignoring case there only refuses more); the item set is exactly the context's, none
   missing, added or twice. It takes `CheckedTargets`, so it can't run without layer 1. Not
   ported (restore-flow §6, "Lab-only rules"): `onedrive.id` equal to the source OneDrive, and
   the canary list-ID prefix on SharePoint document IDs. Added: a SharePoint document whose ID
   starts with the RestoreTarget library's site, web and list GUIDs is refused (a restore target
   is never a source; the targets are in every restore point), and `onedrive.url` must be on
   `https://<tenant>-my.sharepoint.com/` for `test_site_id`'s tenant.
4. **The error is `rp::connector::SafetyViolation`** (a `connector::Error`, `rp/connector.hpp`):
   status `error`, never `fail`; rpworker's exit code 4 (`exit_code::service`, documented in
   `rp/cli.hpp`; no command restores yet, so nothing maps it in code). Its message starts with
   `target guard: `, ends with `nothing was restored` (layer 1) or `the restore was not sent`
   (layer 2), names the field or the item by type and index, and never quotes a credential:
   the two credential fields are checked for kind only, and nlohmann's parse message, which
   quotes the text, is never passed on. A layer-1 refusal from Graph is the `WrongTargetError`'s
   text with the prefix. Graph's other errors pass through with their own types. Each refusal
   logs exactly one line, `SECURITY: <message>`, at critical level through `rp::redact`, on the
   options' logger or spdlog's default one.
5. **Fixtures.** W2.4's five restore POSTs are `worker/tests/fixtures/veeam/restore-{mail,sp,od,
   mail-x5,mail-r1}-200.json` (restore-flow §17 names, plus r1), with `request_body` holding the
   body as sent. The tests run restore-flow §6's 12 mutations on each type and accept all five
   recorded requests unchanged.

**Reason.** The guard is what keeps a restore out of live data when a configured ID, a Cloud
job or a bug names the wrong place; W2.5 must only have to call it. Splitting it by what each
layer knows (the spec before any call; the exact request after browsing) keeps layer 1 free of
Veeam, as `connector.hpp` is.

**Deviations from the W2.7 design notes.**
- *The path's container is not required to be the target site* (the design had SharePoint's
  `container_id` equal to the RestoreTarget library's site). The path names the **source**
  site; W2.6 samples real data from other sites too, which that rule would refuse on every run.
  The target is fixed by `siteURL` and `list`, which are checked; the "never from the target
  library" rule covers the lab's shared site.
- *A mail source is refused if it is any `restoretest` mailbox*, not only the configured one.
- *Item IDs and names, and `onedrive.name`, may be any UTF-8*: they are compared byte for byte
  with the context and name no target; a real file name with an accent would otherwise be a
  guard violation.

**Alternatives rejected.**
- *One guard class that also parses Veeam bodies:* it would put Veeam in the neutral layer.
- *Parsing the body into a DOM and checking keys afterwards:* the DOM has already dropped the
  duplicate.
- *Quoting the refused value in the message:* useful, but a value next to a credential field
  could leak through a mistake; the field name is enough to find it in the evidence.

---

## 2026-09-29 — The Worker runs on the Veeam server (proposed)

**Status: proposed.** The owner accepted the recommendation; spike #135 (W4.12) confirms or
supersedes it before W4.5.

**Decision.** In Stage 1 the Worker is installed on the Veeam Backup for Microsoft 365 server,
next to its REST API. The restore credential is Veeam's own organisation app (as in W2.4
decision 1): for each run the Worker reads the app ID and certificate thumbprint from
`GET /v8/Organizations`, finds that certificate in `Cert:\LocalMachine\My`, checks the app ID,
and exports it in memory only. No copy of the PFX is stored, in the vault or anywhere else.
This picks the second option of the W2.4 entry's open point ("a run-time export by the
thumbprint Veeam reports, when the Worker runs on the Veeam server"). The 2026-09-26 rule
stands: it is tested (#135) before the Worker relies on it. That spike also picks the service
account: LocalSystem, or a virtual account with read access to the certificate's private key.

Follow-ups, as comments on the issues: W4.5 (#48) holds no restore PFX; W7.1 (#80) installs on
the Veeam server; W7.2 (#81) checks the REST API is local and each organisation's certificate
exists, is exportable and isn't within 30 days of expiry; Q7.2 (#85) and Q7.3 (#86) state the
requirement and that the Worker has Veeam admin rights over every organisation on that server.

**Reason.**

- Veeam's certificate never leaves the server it already lives on, and no file outlives a run.
- Nothing to rotate on our side: when Veeam renews its app certificate, the next run finds the
  new thumbprint.
- It is the path W1.0, L1.4 and W2.4 already proved in the lab.

**Cost.** Stage 1 can't serve customers whose Veeam REST API runs on a separate machine, who
won't install software on their backup server, or who use Veeam Data Cloud (Veeam's SaaS, no
self-hosted REST API). Sales material says so.

**Alternatives rejected.**

- *A vault copy of Veeam's organisation PFX:* a long-lived copy of a broad credential, and it
  must be renewed by hand when Veeam renews the certificate. Kept as the fallback if #135
  fails, or for a Worker on another machine (Stage 2).
- *A dedicated, narrower restore app:* Veeam's SharePoint restore needed
  `Group.ReadWrite.All` on the app (L1.4), so it may not be narrower, and it adds consent and
  roles in every client tenant.

---

## 2026-09-29 — Clients live in the Cloud; the Worker checks every job (proposed)

**Status: proposed.** The owner accepted the recommendation; tasks W4.10 (#133), W4.11 (#134)
and C5.13 (#136) build it.

**Decision.**

1. **A client is one Microsoft 365 tenant, which is one Veeam organisation.** A Worker serves
   one Veeam server and runs jobs for any number of clients on it, one at a time. In-house IT
   is the one-client case, not a separate mode.
2. **The Cloud is where clients' details live.** `connector.config_json` (C5.2) holds a
   `client-profile.v1`: `veeam_org_name`, `graph_tenant_id`, `graph_client_id`,
   `test_mailbox` and the four target IDs, with today's key names. IDs only: no names, URLs
   or secrets (W2.4 decision 3 stands). Each job (`job.v1`, C5.6) carries it.
3. **`RestoreTargets::from_profile` is the only factory;** `from_config` wraps it.
   `config.json`'s client keys become an optional local profile, all or nothing, read only by
   the CLI diagnostics. The service loop (W4.8) never reads it.
4. **Before any restore call, the Worker checks the job** (W4.11): the job and profile are
   valid (`job_invalid`), the connector is registered (`connector_unknown`), and the Veeam
   organisation named by `veeam_org_name` has `type == Office365`,
   `msid == graph_tenant_id` and `region == Worldwide` (`client_mismatch`). The Graph token is
   requested for the job's tenant, `TargetReader`'s checks pass, and only then does
   `TargetGuard` run per item. Every failure is `error`, never `fail`.
5. **The Cloud refuses mix-ups** (C5.13): a tenant is unique per MSP, a connector is unique
   per (worker, client), a profile must name its client's tenant, every connector change is an
   `audit_log` row, and a bundle for a different client or tenant than dispatched gets 409.
6. **The signed result names the client** (W4.1): tenant, Veeam organisation, target IDs,
   the names and URLs they resolved to at run time, and `scope: "same_tenant"`.
7. **Jobs run one at a time per Veeam server,** because the W2.4 duplicate check matches
   restore sessions by `initiatedBy`, not by organisation.

**Reason.**

- An MSP has many clients, and the job format already carries per-client locations; one
  `config.json` per client on the Worker would drift from the Cloud.
- The Worker doesn't trust the Cloud blindly: Veeam (`msid`) and Microsoft (a token bound to
  the tenant, grants on the test locations only) must agree with the job. A bug or a typo in
  the Cloud ends as `error` with nothing restored, so no approval step is needed on the
  Worker host, which locked-down MSP servers would struggle with.
- The same model serves an MSP with many organisations on one Veeam server, a Veeam server per
  customer, and in-house IT.

**Alternatives rejected.**

- *A client file per client on the Worker:* a second copy that drifts, and it repeats the
  W1.7 entry's reasoning against a `connector` key in `config.json` ("the wrong place once
  jobs carry the type").
- *Trusting a job's targets as sent:* see the 2026-09-29 W2.4 review entry, decision 1.
- *A person approving each client's targets on the Worker:* deferred; the checks above rest on
  facts Veeam and Microsoft report.
- *Finding the Veeam organisation by `msid` instead of by name:* deferred; the name plus the
  `msid` cross-check is enough for Stage 1.

**Deferred to Stage 2.** An organisation inventory in the heartbeat, bulk import of clients,
more than one Worker per Veeam server or more than one server per Worker, restores into
another tenant.

---

## 2026-09-29 — W2.4 review: the target guard trusts no configured ID; the restore script's no-verdict paths

**Decision.** A code review of W2.4 (`/code-review`, max) found fifteen problems plus ten
smaller ones. This entry records what changed. It supersedes the parts of the W2.4 entry below
that it names; the rest stands. `docs/api/veeam-restore-flow.md` and
`docs/api/veeam-m365/10-restore.ps1` carry the details.

1. **`TargetGuard` doesn't trust the configured IDs** (supersedes "`TargetGuard` checks the body
   against both the names derived from the configured IDs and what Veeam returned" in decision
   3). The W2.4 spec had the guard check only that Veeam's body names what the configured IDs
   resolve to. A `test_library_id` naming a live library (this tenant's default `Dokumenty`)
   would have passed and restored into live data. That is the "trusting configuration" the
   2026-09-22 entry rejects, and it ignored the 2026-09-24 rule that `TargetGuard` resolves the
   IDs and checks they are the restore targets. Now there are two checks (restore-flow §16):
   the resolved targets must be the fixed `RestoreTarget` library and folder and
   `restoretest`'s Inbox, as W2.2's `TargetReader` already requires, and not a canary location;
   then Veeam's body must name exactly those.
2. **The guard still runs per item inside `RestoreSample`, before any Veeam call.** The W2.4
   spec had moved the per-item check after browsing. The rule stands as CLAUDE.md and the
   2026-09-22 entry state it. The exact-body check before the POST is a second layer on top.
3. **The duplicate check excludes every session the run already knows** (supersedes "the ID is
   not one of our explore sessions" in the at-most-once paragraph). The Worker sends one POST per
   source container, so several of one type per run. Excluding only explore sessions would let
   a later POST that got no answer adopt an earlier POST's session. With a session ID from the
   POST, the check must list exactly that session; otherwise, or if the check itself fails, the
   returned session is still polled, but the run ends with no verdict.
4. **A restore that may still be running is left alone, and so is its explore session.** On a
   timeout, a 404 or six failed polls, the script used to stop the explore session under the
   running restore, and `08-sweep-sessions.ps1` would then stop the restore session itself. What
   Stop does to either is untested. Now the script leaves both and says to wait until the
   restore session reads `Stopped`. The sweep stops nothing while two of ours of one type are
   `Working`, unless given `-Force`.
5. **File results are matched by ID, not name.** `Statistics.items[].id` is the OneDrive
   document ID, or the list item GUID that ends the SharePoint document ID. Events carry only a
   name, so no two items of one call may share one, and W2.5 splits them into separate calls.
6. **The result-to-status mapping follows W1.7's contract.** 0 restored is `failed` whatever
   `result` says. A session that restored nothing because of infrastructure is an exception
   (`error`), so `failed` → `fail` stays true. Two changes remain proposals for W3.3: a
   `partial` item that failed for infrastructure makes the run `error`, and a canary missing
   from a point dated after it is `fail` (restore-flow §15).
7. **The script.** The guard's self-test counts only the guard's own refusals. Its array case
   never reached the guard (a generic `JsonArray.Add<T>` node can't be serialised, and the
   catch-all counted that as a refusal). A duplicate-key case is added, and the guard reads
   every object, because `JsonNode.Parse` doesn't refuse a duplicate key. Any 2xx from the POST
   counts; a status that is neither 2xx nor 4xx means looking for the session. The POST's
   evidence is written only after its session ID is parsed. A field the verdict reads that is
   missing or of the wrong kind is no verdict (exit 3), not "NOT restored". Arguments bind by
   name only. `-TimeoutMinutes` is 1 to 45, below the token's life. `-WhatIf` is documented as
   what it is: no POST, but a sign-in and an explore session. `initiatedBy` matches ignoring
   case. The source mailbox may not be the target. `-SaveEvidence` refuses to mix with an
   earlier run's files.
8. **The recordings came from an earlier, uncommitted revision of the script.** They stay the
   W2.4 evidence: the calls and bodies are unchanged. The committed revision was replayed
   offline against all four recordings, run live with `-WhatIf`, and made one real restore on
   2026-09-29 (`RP-CANARY-0011`, exit 0, read back by `graph list --hash` with the manifest's
   hash; `w2.4-mail-r1-*.json`). Veeam's log shows no late flush (supersedes the W2.4 open
   point on it): that run also printed 0 bytes, yet the file was complete 47 ms before the
   session's `endTime`. The size in a directory listing lags for a file Veeam holds open, so the
   Worker reads the file itself after `Stopped`.

**Reason.** A guard that only compares the body with the configuration protects against Veeam
changing the body, not against the configuration naming live data, which is the failure the
guard exists for. Every other change turns something that could report a result it didn't
establish, or stop what it didn't know was safe to stop, into "no verdict".

**Alternatives rejected.**

- *A longer forbidden-name list* (`Dokumenty`, `Documenti`, …): can't be complete in every
  language, and a library of any other name is live data too.
- *Stopping the restore session on a timeout:* untested, and it may leave a partial, unrecorded
  set of copies in a target that the nightly backup captures.
- *Treating a failed duplicate check as fatal once a session ID is known:* the session would go
  unmonitored, which is worse than polling it and withholding the verdict.

**Open.** What Stop does to a running restore (restore-flow §18).

---

## 2026-09-28 — W2.4: the Veeam restore flow

**Decision.** W2.4 restored canaries into the three restore targets through the REST API
with [`10-restore.ps1`](api/veeam-m365/10-restore.ps1): one mail, one SharePoint file, one
OneDrive file, then five mails in one call, all from the restore point of
2026-09-27T22:00:48Z. Veeam reported each one restored, and `rpworker graph list --hash`
found all 8 items in the targets with the manifest's SHA-256. The flow, the bodies and the
evidence are in `docs/api/veeam-restore-flow.md`; the exchanges are
`docs/api/veeam-lab/w2.4-*.json`. The owner decided:

1. **The restore credential is Veeam's own organisation app, per run, in the lab.** The script
   exports its certificate (`Cert:\LocalMachine\My`, so an elevated shell) to a temporary PFX
   in `%TEMP%` with a random 32-byte one-time password, reads it into memory and deletes the
   file at once in a `finally`. The PFX is not stored. With `RP_LAB_SECRET_DIR` set, as in the
   documented run, the one-time password (not the PFX) also gets a DPAPI copy in that folder,
   outside the repo, for `audit-evidence.ps1`; the folder is deleted after the audit. Before that it checks the app ID and
   thumbprint against what `GET /v8/Organizations` reports
   (`exchangeOnlineSettings`, `sharePointOnlineSettings`;
   [`w2.4-mail-x1-org`](api/veeam-lab/w2.4-mail-x1-org.json)). The body carries
   `applicationId`, `applicationCertificate` and `applicationCertificatePassword`.
2. **One restore call per source container** (a mailbox, a site, a OneDrive) with every
   sampled item from it. Tested with five mails in one call
   ([`w2.4-mail-x5-restore`](api/veeam-lab/w2.4-mail-x5-restore.json)): statistics `5/5`, one
   `Restore` event per item named by subject, not in the order sent
   ([`w2.4-mail-x5-events`](api/veeam-lab/w2.4-mail-x5-events.json)).
3. **The configured target IDs are mapped to Veeam's names at run time through Graph**, with
   the Worker's read-only app: the site's `webUrl` from `test_site_id`; the library's display
   name from `GET /drives/{test_library_id}` `name`; the OneDrive's URL from the drive's
   `webUrl`; the folder name from `GET /drives/{d}/items/{test_onedrive_folder_id}`; the
   mailbox is `test_mailbox` and the folder is always `Inbox`. The OneDrive object in the body
   is Veeam's, matched by that URL in the explore session. `TargetGuard` checks the body
   against both the names derived from the configured IDs and what Veeam returned. No new
   config keys. W2.5 and W2.7 build this. *(The guard also checks the resolved targets are the
   restore targets, and doesn't trust the configured IDs: see the 2026-09-29 W2.4 review entry.)*

**The restore POST is sent at most once.** It is never resent by the HTTP layer (the open
point of the 2026-09-24 HTTP client entry and of the 2026-09-26 VeeamClient review entry).
After a transport error, a 5xx or a 200 without `sessionId`, the script looks for the session
it may have started: `GET /v8/RestoreSessions?startTimeFrom=<POST time − 60 s>&orderBy=CreationTime&orderAsc=false&limit=50`,
kept only if `initiatedBy` is `rp-veeam`, the type is `Vex`/`Vesp`/`Veod` for the item type,
the ID is not one of our explore sessions and `creationTime` is no earlier than 5 s before
the POST. Exactly one match is adopted. While it finds none, it looks up to three more times,
10 s apart; still none, or several at any look, is "no verdict, not resent" (exit 3). The same check ran after every successful POST and found
exactly one new session, the one returned
([`w2.4-sp-x1-sessions-after-post`](api/veeam-lab/w2.4-sp-x1-sessions-after-post.json)).
`VeeamClient` (W2.5) does the same. *(It excludes every session the run knows, not only the
explore sessions, and a session ID from the POST must be the one the check lists: see the
2026-09-29 W2.4 review entry.)*

**The restore targets are in the backup.** The 2026-09-27T22:00:48Z restore point holds the
RestoreTarget library and alice's `/RestoreTarget` folder
([`w2.4-sp-x1-libraries`](api/veeam-lab/w2.4-sp-x1-libraries.json),
[`w2.4-od-x1-folders-root`](api/veeam-lab/w2.4-od-x1-folders-root.json)). W1.4 recorded them as
absent (`docs/api/veeam-notes.md` §5.2, §5.3) because they were made on 2026-09-25, after the
first two points. A restore not cleaned up before the nightly backup would put its copies in
the next point. So sampling (W2.6) takes items only from the canary sources (the RestoreTest
library by list ID, `/RestoreTest` by folder, the source mailboxes' Inbox) and the real data,
never from a target. The script prints a note when it sees a target in the point; it doesn't
refuse.

**Veeam's result maps to a restore status** as proposed in `docs/api/veeam-restore-flow.md`,
for W2.5's `RestoreStatus` and W3.3's table in `docs/verification.md`. "Veeam says restored"
(stopped, `Success`, every item reported) is `succeeded`; Graph read-back then decides `pass`
or `fail` per item. Anything infrastructure (auth, certificate, app permissions, a session
not found, statistics or events unreadable, still running after 20 minutes, a guard refusal)
is `error`; when unsure, `error`.

**Reason.**

- **Credential.** Veeam's app already holds the certificate Veeam trusts for this
  organisation and is the one W1.0 and L1.4 restored with. A dedicated app would need its own
  consent and roles, and a narrow one may not be possible: Veeam's SharePoint restore
  demanded `Group.ReadWrite.All` on the app (L1.4, `docs/manual-restore-reference.md`).
  Exporting per run keeps the PFX out of any file that outlives the run.
- **One call per container.** Fewer sessions to wait for, and the per-item result is still
  there: SharePoint and OneDrive statistics list items by name, mail events name each item.
- **Graph for the names.** The IDs are stable and the Worker already reads them; a display
  name or URL in config would be a second copy that can drift, and a renamed target would be
  found by the guard, not missed.
- **At most once.** A resent restore can write a second copy, which the checker would count
  and the Cleaner would have to find. A missing verdict costs one run; a duplicate costs trust
  in every later one.

**Alternatives rejected.**

- *The Worker's own app in the body:* read-only (L1.5), and Veeam writes the items.
- *A PFX of Veeam's app copied to disk for the lab:* one more copy of a broad credential.
- *One call per item:* N sessions of 30 to 50 s each (one item each here) for the same result.
- *New config keys for the site URL, library name and OneDrive URL:* see above.
- *Resending after a timeout when no session is found:* the session list may lag; "no verdict"
  is safe, a second restore is not.

**Open.**

- **The Worker's long-term restore credential** stays open for a spike before W4.5: a vault
  copy of Veeam's app PFX; a run-time export by the thumbprint Veeam reports, when the Worker
  runs on the Veeam server; or a dedicated, narrower app. The 2026-09-26 rule stands: it is to
  be tested before the Worker stores any certificate.
- **Veeam's per-restore log** (`C:\ProgramData\Veeam\Backup365\Logs\RestoreREST\restore_<local time>_<session ID without dashes>_<org ID without dashes>.log`)
  was 0 bytes when listed right after the sp, od and mail x5 sessions stopped (the mail x1 run
  printed no log line); 18–22 KB when listed later, and last written before each session's
  `endTime`. When Veeam flushes it is not established; its contents weren't read. Not committed.
  *(Superseded: those readings came from an earlier revision of the script, and each log was
  complete before its session ended; see the 2026-09-29 W2.4 review entry.)*
- **Cleanup** is the owner's, by hand, until the Cleaner (W3.4). The owner removed the eight
  restored items; `rpworker graph list` then found 0 items in each target (about 21:38Z).
- **The OneDrive drive read.** Decision 3 reads `GET /drives/{test_onedrive_drive_id}` for the
  OneDrive's `webUrl`. The Worker app's grant (`Files.SelectedOperations.Selected`) is on the
  `/RestoreTarget` folder only, so that read may answer 403, and a drive's `webUrl` may end in
  `/Documents`. W2.5 checks both. If the drive can't be read, the fallback is the folder's
  `parentReference.siteId` (the first GUID of Veeam's OneDrive `id`), with no new permission
  (`docs/api/veeam-restore-flow.md` §16, `docs/security/graph-permissions.md`).
- **A canary missing from the restore point** is proposed as `fail`, not `error`
  (`docs/api/veeam-restore-flow.md` §15); W3.3 settles it.

---

## 2026-09-28 — W2.3: `rpworker graph list`; a hash-less listing; service-neutral exit codes

**Decision.**

1. **`rpworker graph list [--hash] [--config <path>]`** prints what is in the three restore
   targets now, through W2.2's `TargetReader`: the test mailbox's Inbox, the RestoreTarget
   library, the test OneDrive's RestoreTarget folder, in that order, each a heading with its
   count and, if it holds anything, a table (mail: received, sender, subject, ID; files: name,
   size, ID), then a summary line (`docs/worker-config.md`). It follows `veeam list` in shape:
   `rp/graph_command.hpp` with a `GraphCommandEnv` (config path, secrets, the two HTTP client
   factories, `GraphClientOptions`), dispatched by `rp::run_cli`. The flags come in either
   order, each once. Everything is read before anything is printed. The table layout moved
   from `veeam_command.cpp` into `src/text_table.{hpp,cpp}` (`table_cell`, `display_width`,
   `format_table`), which both commands use; `veeam list`'s output is unchanged.
2. **Without `--hash`, nothing is downloaded or hashed**: `TargetReaderOptions::hash_items`
   (default `true`, W2.2's behaviour). When it is `false`, the file listings skip `/content` and
   the download client entirely, `size_bytes` is Graph's `size` and `on_file` is never called;
   the mail listing leaves `body` out of `$select` and never checks a body. Every `sha256` and
   `sha256_rule` stays empty (documented on `FoundItem`, not an `optional`, so W2.2's callers
   are untouched). The guards run the same either way. (First named `hash_files`, with mail
   hashed either way; the review found that fetched every body for a hash never printed, and
   that one body Graph sent as html failed the whole hash-less listing with exit 4.)
3. **The exit codes are service-neutral** (supersedes the wording of the 2026-09-27 W1.6
   entry, not its numbers): `exit_code::veeam` is renamed `exit_code::service`, and the
   comments in `rp/cli.hpp` and the table in `docs/worker-config.md` speak of "the service".
   For Graph: 1 for a `ConfigError`, a `graph::CertificateError` among them (an unset
   `RP_GRAPH_CERT_PFX_BASE64`, a PFX that doesn't open, a certificate not valid now: all found
   before any request), and any unexpected failure; 2 for `graph::AuthError` and
   `PermissionError` (whose message names the grant); 3 for `graph::TransientError`; 4 for any
   other `GraphError`: `NotFoundError`, `WrongTargetError`, a failed download, an unexpected
   answer. One line on stderr, `graph error: <what()>`; nothing on stdout.
4. **The command's logger writes warnings and worse to stderr only** (`make_command_logger()`
   in `src/command_config.cpp`, now shared with `veeam list`); a `GraphCommandEnv` without a
   logger gets that one too, never spdlog's default logger, which writes to stdout. Downloads go through
   `make_download_http_client()`, whose logger is a null sink, so no download link is logged.
5. **A failed write to stdout is a failure**: after printing, the command flushes `out` and
   checks its state; a full disk or a closed pipe gives `error: unexpected failure`, exit 1,
   never exit 0 with a short listing (exceptions are off on `std::cout`, so nothing throws).
6. **The download client is made only with `--hash`**: without it the reader gets a stand-in
   that throws if ever sent through, so a download client that can't be made never fails a
   listing that downloads nothing. A malformed Graph reply stays exit 4: the reader checks
   Graph's JSON itself and throws `GraphError`, so no JSON library exception reaches the
   command's exit-1 catch-all (a command test pins this).

**Reason.** The operator needs to see the targets before and after a restore (W2.8, W3.4)
without waiting for every file to download; `--hash` is there when the content matters. An
empty target is the normal state, so it prints `0 item(s)` rather than nothing. Graph's
failures map onto the same four meanings as Veeam's, so a script reading exit codes needs no
per-service table.

**Alternatives rejected.**
- *Always hashing:* a slow check that downloads every file, and SharePoint's download host
  becomes a dependency of a listing.
- *`std::optional<std::string>` for `sha256`:* stricter, but it changes every W2.2 caller and
  test for a state only this command produces.
- *Graph-only exit codes (5, 6, ...):* two numbers for the same meaning.
- *A `--json` output:* not needed yet; W2.8/W3.6 decide its shape.

---

## 2026-09-28 — W2.2 review: fixes to reading the restore targets

**Decision.** A code review of W2.2 (`/code-review`, xhigh) found thirteen problems; this entry
records what changed. It supersedes the parts of the W2.2 entry below that it names (§2, §4,
§6, §10, §11, §13); the rest stands.

1. **The OneDrive guard also requires `parentReference.driveType` `business`** (supersedes part
   of §2). Without it, `test_onedrive_drive_id` set to a site library's drive (the canaries'
   RestoreTest library) with a `RestoreTarget` folder at its root passed every check. Missing,
   not a string, or any other value (`documentLibrary`, `personal`, another case) is a
   `WrongTargetError`. The recorded `onedrive-folder-200.json` shows Graph returns it.
2. **Only a 2xx body is held to `max_body_bytes`** (supersedes part of §4). The cap is the
   file's size, so a SharePoint 503 whose error page was longer than a small file was cut,
   returned at once and never retried: whether it counted as transient depended on the file's
   size. Any other status's body is now held to `kMaxErrorBodyBytes` (64 KiB) and handled as
   its status says; a 5xx is retried as without a cap. A 5xx the download client returns all
   the same is a `TransientError`, like one retried to the end.
3. **A docx or xlsx is read up to the download limit, whatever its size** (`SizeCheck`,
   supersedes part of §4). SharePoint rewrites Office files (`lab/README.md`, `office-v1`), so
   their bytes may differ from the `size` Graph lists; one such file failed the whole listing.
   `FoundItem::size_bytes` is what came. Every other file must still be exactly Graph's size.
   Not seen live yet: the one-item recording has no Office file.
4. **A 200 straight from Graph's `/content` is held to the same cap** (supersedes part of §6):
   `GraphClient::get` takes an optional `max_body_bytes`, which goes with every attempt.
5. **Download errors are classified by `is_retryable()`**, not a copy of it, and their
   messages no longer blame a refused connection (that is `connect`, retried) for a `tls` or
   `other` failure.
6. **Mail bodies come in the Inbox listing** (supersedes part of §10): `body` is in the
   listing's `$select` under the same `Prefer`, instead of one GET per mail (N+1 calls).
   `mail-body-200.json` is gone; the recorder checks every listed body is text.
7. **A nextLink is checked by a rule per target, not an exact path** (supersedes part of §11).
   Graph documents `@odata.nextLink` as opaque, so a link naming the mailbox by object ID, or
   the library's root by item ID, was refused. The rules, on `resource_path()`'s segments:
   the Inbox `users/{mailbox or a GUID}/mailfolders/inbox/messages`; the library
   `drives/{test_library_id}/root/children` or `drives/{test_library_id}/items/{an item ID}/children`;
   the OneDrive folder `drives/{test_onedrive_drive_id}/items/{test_onedrive_folder_id}/children`
   only, never another item of that drive, since alice's canary folder shares it. A link to
   another mailbox by GUID would be refused by Exchange RBAC (a `PermissionError`, status
   `error`). The absolute-v1.0, no-refetch and page-cap rules stand. The `paged` recording
   (2026-09-28) confirms the mail rule: Exchange's links name `mailFolders('inbox')`, which
   the rule reads as the same resource.
8. **The ID shapes are config rules** (supersedes part of §13): `parse_config` applies
   `kGraphSiteIdRule`, `kGraphDriveIdRule` and `kGraphItemIdRule` (`rp/config.hpp`), so
   `rpworker config check` refuses a list GUID in `test_library_id` instead of the first run;
   `RestoreTargets::from_config` applies them again for a `Config` built in code, as it does
   the mailbox rule. `TargetReader` only splits the site ID.
9. **ASCII-only folding** (`ascii_lower`, `ascii_iequals`, `ascii_ends_with_i` in
   `src/text_util.hpp`) replaces the locale-dependent copies in the Graph code;
   `kSharePointSuffix` is declared once, in `rp/config.hpp`.
10. **The recorder scrubs a download link anywhere in a body**, an HTML "Object moved" page
    included, as it scrubs a `Location`, and reads `&amp;` as a separator in the scrub and the
    safety check alike. Before, such a 302 made the one-item state unrecordable.
11. **The live test prints Graph's text through `one_line()`** (`tests/found_item_line.hpp`),
    so a restored subject or name can't forge or reorder the lines it prints.

**Reason.** Each was a way to report an infrastructure problem as something else, to read
outside the restore targets, or to fail on replies Graph may really send.

**Alternatives rejected.**
- *Accepting any nextLink under v1.0* (Graph's advice): a link could then list alice's
  canary folder with the token. *Checking each page's items instead of the link* (their
  `parentReference`): more calls and fields, and it still can't tell the mailbox.
- *An exact size for Office files with a retry:* the rewrite is SharePoint's, not a race.
- *Dropping a 200 from `/content`:* Graph may serve one; it is capped instead.

**Consequences.**
- The empty state was recorded again (2026-09-28) with the new `$select`; the recorded
  `onedrive-folder-200.json` has `parentReference.driveType` `business`. The one-item and paged states were recorded the same day, after one mail and
  two files (then a second mail) were put in the targets by hand, and confirm items 3 and 7
  against real replies. Exchange puts an `@odata.nextLink` on every full page, the last one
  included: with two mails and `$top=1`, page 2 has a link and page 3 is empty, so the
  recorder takes three pages and the listing ends on an empty one.
- W3.2 hashes docx and xlsx with `office-v1` through `on_file`, so their byte counts no longer
  matter for verification.

---

## 2026-09-28 — W2.2: reading the three restore targets through Graph

**Decision.** `rp::graph::TargetReader` (`worker/include/rp/graph_targets.hpp`) lists what is
in the three restore targets (the test mailbox's Inbox, the RestoreTarget library's root, the
test OneDrive's `/RestoreTarget` folder) and hashes each item, through W2.1's `GraphClient`.
It returns `std::vector<FoundItem>` in Graph's order; an empty location is an empty vector,
never an error. It only reads. Downloads go through `rp/graph_download.hpp`, mail bodies are
hashed with `rp/text_v1.hpp`, bytes with `rp/sha256.hpp`. This resolves the open point in
`lab/tenant.md` on `test_library_id`.

1. **`test_library_id` is the RestoreTarget library's drive ID** (`b!…`), because Graph reads
   files by drive and the list ID would cost an extra call (`docs/worker-config.md`,
   `lab/tenant.md`).
2. **Wrong-location guard.** Before listing a file target, one GET checks it; a refusal is a
   `WrongTargetError` (a `GraphError`, so run status `error`) and nothing is listed.
   - The library's drive (`$select=id,name,driveType,webUrl,sharePointIds`): display name
     `RestoreTarget`; URL name (the last `webUrl` segment, which a UI rename doesn't change;
     compared ignoring case, query, fragment and percent-encoding) `RestoreTarget`;
     `driveType` `documentLibrary`; `sharePointIds.siteId` and `.webId` equal to the GUIDs in
     `test_site_id`.
   - The OneDrive folder (`$select=id,name,folder,parentReference`): name `RestoreTarget`
     (exact case), a `folder` facet, `parentReference.driveId` equal to
     `test_onedrive_drive_id`, and directly in the drive's root by **`parentReference.path`**,
     which Graph does return (the empty-state recording, 2026-09-28). Two forms are accepted:
     `/drive/root:`, and `/drives/{test_onedrive_drive_id}/root:`, the one Graph actually
     returned. A nested path in either form, another drive's root, or a path that is missing
     or not a string is refused. The root-ID fallback was not needed.
   - Every missing field fails closed. `Sites.Selected` can read the canary library, so the
     permissions can't be the guard. No canary ID appears under `worker/`: the guard's tests
     refuse edited recorded fixtures by shape (named `RestoreTest`, nested, in another site).
3. **Caller headers on GraphClient: an allow-list of `Prefer` only** (`kCallerHeaders`; an
   optional trailing `headers` on `get`, `get_json`, `find`, `find_json`). Any other name,
   `Authorization` included, or an empty value or one with a control character, is refused before the token
   request, so a caller can't swap or add credentials. The headers go on every attempt, the
   401 resend and retries included. The refusal reads `refused the header "<name>" since a
   caller may add only Prefer; …` rather than the drafted `…"<name>": a caller…`, because
   `GraphError` runs its message through `redact()`, which took `"Authorization": ` for a JSON
   secret key.
4. **In memory with a hard cap, no streaming.** `kMaxDownloadBytes` = 64 MiB is checked
   against Graph's `size` before downloading. The download carries
   `HttpRequest::max_body_bytes = size`, so `HttpClient` keeps at most one byte more (a curl
   write callback that stops the transfer) and never retries a cut body; the byte count is
   checked after. Memory is bounded whatever SharePoint sends. A larger file is an `error` in
   Stage 1; the canaries are under 30 KB.
5. **Office files:** `FoundItem::sha256` is the bytes hash (`sha256_rule` `bytes`). W3.2
   computes `office-v1` from the same bytes through `TargetReaderOptions::on_file`, called
   once per file after its size check and hash, in the same pass.
6. **The download follows Graph's `/content` redirect without the token**, through
   `make_download_http_client()`: the Windows store like `make_graph_http_client()`, but its
   logger has only a null sink, so the credential-bearing URL is never logged.
   `download_item` logs only the host and status and never puts the `Location` in a message.
   Only `https://` on the test tenant's hosts (`<t>.sharepoint.com` from `test_site_id`, and
   `<t>-my.sharepoint.com`), port 443, one hop. A 401 or 403 from SharePoint is an error with
   no retry; 5xx and lost connections are retried by `HttpClient`, then a `TransientError`; a
   429 is a `TransientError` at once. A 200 straight from Graph is taken as the content.
7. **Folders inside a location are skipped and logged** (info), not recursed: restores land in
   the root. Other non-file items too (warn).
8. **`FoundItem`** is the brief's `{type, id, name, subject, sender, receivedAt, sha256,
   sizeBytes}` in C++ naming (`received_at`, `size_bytes`; `std::optional` where a type has
   none), plus `internet_message_id` (the canary manifest carries it, and W3.1 matches mail
   on it) and `sha256_rule` (`text-v1` or `bytes`).
9. **The OneDrive grant** `kOneDriveReadGrant` = `"Files.SelectedOperations.Selected read on
   the test OneDrive folder"`. SharePoint answers 404, not 403, for an item the app may not
   read, so the folder's `NotFoundError` adds that the grant may be missing. The
   `PermissionError` path is tested on the hand-written `onedrive-folder-403-accessdenied.json`.
10. **Mail:** `Prefer: outlook.body-content-type="text", IdType="ImmutableId"` (`kMailPrefer`,
    the seeder's `MAIL_PREFER`) on the list and on every `$select=body`. The body is hashed
    with `text-v1`, byte-wise with no ICU, which passes every vector in
    `shared/testdata/body-normalization-text-v1.json`. A body Graph returns as HTML despite
    `Prefer` is an error, since its hash would mean nothing.
11. **Paging:** `@odata.nextLink` is followed for at most `kMaxListPages` (100) pages. A link
    fetched before (any cycle), empty or not a string, or naming another resource than the
    first request (`resource_path`: the path after `/v1.0`, percent-decoded, `seg('x')` as
    `seg/x`, lower-cased) is a `GraphError`, never a silently shortened listing. So is any
    link that doesn't start with `https://graph.microsoft.com/v1.0/`, a relative one too:
    Graph sends absolute links, and `GraphClient` would put its v1.0 root in front of a
    relative path and send it with the token, so leaving it to `GraphClient` would let a
    reply point the listing at another drive (review of W2.2). The mail rule did not have to be widened: the `paged` recording follows two real links.
12. **Fixture states:** `record-graph-fixtures --state {auth,empty,one-item,paged}`
    (`lab/README.md`). Hand-written stand-ins are committed until a state is recorded (the lab
    plan test skips them; a README test keeps rows and files in step). The paged state is
    recorded with two mails and `$top=1`: three pages, the last one empty. The OneDrive 403 is hand-written: the lab can't
    provoke it read-only. The `Location` query is scrubbed to `UniqueId`, `Translate` and
    `ApiVersion`, `@microsoft.graph.downloadUrl` is dropped, and the recorder never follows the
    redirect.
13. **IDs are checked against a charset before they go into a URL path**, since `graph_url()`
    doesn't police `?` or `/` inside an ID. From config, in the constructor, as an
    `rp::ConfigError` naming the key: drive IDs `b!` then 1..200 of `[A-Za-z0-9_-]`, the folder
    ID 1..200 of `[A-Za-z0-9!_-]`, `test_site_id` exactly `<label>.sharepoint.com,<GUID>,<GUID>`.
    From Graph (message and item IDs): 1..512 of `[A-Za-z0-9!_=-]`, else a `GraphError` before
    the ID is used. `test_mailbox` stays with `load_config`, which allows only
    `restoretest@<domain>`.

**Reason.** W3's checker needs what a restore actually put in each target, hashed the way the
canary manifest was, and it must never read the canaries themselves: that would make every
verification pass. Every infrastructure problem (a missing drive or folder, a refused grant, a
bad redirect, a size mismatch, a guard refusal) is an error type, so it becomes run status
`error`, never `fail`, and never an item quietly dropped.

**Alternatives rejected.**
- *The list ID for `test_library_id`, resolved through `/sites/{site}/lists/{list}/drive`:*
  an extra call for nothing.
- *Comparing against a list of canary IDs:* it only knows the lab's, and would put canary IDs
  in `worker/`. *The display name alone:* a site owner can rename it.
- *Free caller headers with `Authorization` filtered* (a deny-list).
- *A body sink in the HTTP layer:* Stage 2 if large files are sampled; it changes
  `IHttpClient` and every fake. *Checking Graph's size only:* not a hard cap.
- *Returning the bytes in `FoundItem`* (memory); *computing office-v1 now* (it needs a
  ZIP/inflate dependency W3.2 will pick).
- *Letting cpr follow the redirect* (it would carry the Authorization header); *any
  `*.sharepoint.com` host* (another tenant's bytes); *relying on `redact()` for the URL* (it
  masks by key name only).
- *Recursing into subfolders:* restores land in the root.

**Consequences.**
- W2.3's `rpworker graph list` prints `list_all()`. W3.1/W3.2 compare its items with
  `lab/seed-manifest.json`: mail on `internet_message_id` and the `text-v1` hash, files on the
  bytes hash, Office files on `office-v1` through `on_file`.
- The Done-when (issue #27) is shown by `worker/tests/graph_targets_live_test.cpp`
  (`docs/testing.md`, "Live tests"), run with the targets empty and again with one item in
  each.
- `docs/worker-config.md` documents the ID forms; `docs/security/graph-permissions.md` has the
  OneDrive grant's text and how its refusal is verified.

---

## 2026-09-28 — W2.1: Graph sign-in with a certificate client assertion; Graph errors, retries and where the token goes

**Decision.** `rp::graph::GraphClient` (`worker/include/rp/graph_client.hpp`) gets app-only
tokens from Entra with a signed client assertion and makes Graph GETs with them. Supersedes,
in the L1.5 entry below ("The Worker's Graph app"), the future-tense secret names of point 1
and the "reconsider CNG in W2.1" alternative, and, in the 2026-09-24 config entry, the
secret `RP_GRAPH_CLIENT_SECRET` and its list of secret-key markers.

1. **Signing with OpenSSL** (`rp/client_assertion.hpp`; no OpenSSL type in the header):
   `PKCS12_parse` once, then `EVP_DigestSign`. Only the key and certificate objects are
   kept; the decoded PFX bytes and the password copy are cleansed on every path.
   - The assertion is always **PS256** (SHA-256, MGF1-SHA-256, salt 32) with an
     **`x5t#S256`** header (base64url SHA-256 of the certificate's DER). A live probe on
     2026-09-28 showed Entra accepts PS256/RS256 with `x5t`, `x5t#S256` or both; one form is
     hard-wired.
   - Claims: `aud` the exact token URL
     `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, `iss` = `sub` = the
     client ID, a fresh `jti` (UUID v4 from `RAND_bytes`) on every token attempt, `nbf` =
     `iat` = wall-clock now, `exp` = `nbf` + 300 s. An assertion is never reused.
2. **Secrets.** `RP_GRAPH_CERT_PFX_BASE64` (the PFX, one line of Base64) and
   `RP_GRAPH_CERT_PASSWORD` replace `RP_GRAPH_CLIENT_SECRET` (`rp/secrets.hpp`,
   `docs/worker-config.md`, "Microsoft Graph app"). `certificate_from_secrets` checks the
   PFX before any network call and throws `rp::graph::CertificateError` naming the
   variable, never its value: unset, not strict Base64, not a PFX, no MAC, wrong password,
   a legacy cipher (re-export with AES256_SHA256), no key or no certificate, a key that
   doesn't match, not RSA of at least 2048 bits, expired or not yet valid. A certificate
   expiring within 30 days logs a warning. An empty password is accepted only if the PFX
   really has none. `config check` stays offline and does not open the PFX. `config.json`'s
   secret-key markers gain `pfx` and `passphrase` (`cert` deliberately not: it would reject
   `veeam_cert_sha256`).
   - **Known gap until the vault (W4.5):** the PFX and its password sit in environment
     variables, and the key lives in process memory for the Worker's lifetime.
3. **Errors** (`rp/graph_errors.hpp`): `GraphError` (base; `what()` always through
   `rp::redact`), `AuthError`, `PermissionError`, `NotFoundError`, `TransientError` (with
   Retry-After). They keep Graph's code, inner code, request ID and a short redacted
   message, never the body. `CertificateError` (an unusable certificate, found when it is
   loaded) is an `rp::ConfigError`, not a `GraphError` (review of W2.1): a command's
   `catch (const GraphError&)` can't take it for a failed call. OpenSSL failing to make a
   jti or to sign at run time is a plain `GraphError`.
   - Entra's refusals map on the AADSTS code (first of `error_codes`, else the number in
     `error_description`), then on `error`, never on the status alone; each `AuthError` says
     what to check (the table is `token_failure` in `worker/src/graph_client.cpp`):
     700016 the client and tenant IDs; 90002, 900023, 50059 the tenant ID; 700027, 7000274,
     50012, 700030 "is the certificate with SHA-1 thumbprint <X> uploaded to app <client
     ID>?"; 700024, 50027 clock skew, with this machine's UTC time; 53003 Conditional Access;
     70001, 7000112, 500014, 1000031 the app is disabled, deleted or not in the tenant; any
     other 4xx an `AuthError` with its code. 5xx, 429, `temporarily_unavailable` and 90006,
     90033, 90090, 50033, 90055 are `TransientError`s and retried.
   - A reply that isn't JSON is a `TransientError` on 5xx, else a `GraphError`.
     `NotFoundError` is only a 404 Graph explains in its JSON error; a mailbox Graph can't
     read (`MailboxNotEnabledForRESTAPI`, `MailboxNotSupportedForRESTAPI`) and a 404 without
     Graph's JSON (a proxy, a wrong path) are plain `GraphError`s.
   - Every Graph error means run status `error`, never `fail`. So `get` is for what must
     be there (the test mailbox, site or drive): its 404 is a `NotFoundError`. An item a
     restore should have put there is looked up with `find`/`find_json`, which answer a 404
     Graph explains with `nullopt` (the item is missing: W3's `fail`), except the codes that
     say the mailbox or user doesn't exist (`ErrorInvalidUser`, `ErrorNonExistentMailbox`,
     `Request_ResourceNotFound`), still a `NotFoundError`. SharePoint and OneDrive answer
     `itemNotFound` for a missing drive as for a missing item, so W2.2 checks the drive with
     `get` first (review of W2.1: one `NotFoundError` for both would have made either a
     misconfigured mailbox a `fail` or a failed restore an `error`).
   - **Exit codes are unchanged in W2.1**: no command calls Graph yet. `rpworker graph list`
     (W2.3) is the first to map these errors. Recommended there: `AuthError` and
     `PermissionError` 2, `TransientError` 3, other `GraphError`s 4; a `CertificateError`
     exits 1 with the other `ConfigError`s.
4. **Permissions.** Every call names a `Grant` (W2.1: Mail through Exchange RBAC, Sites
   through `Sites.Selected`). A 403 with Graph's JSON error is a `PermissionError` "Graph
   denied GET <path without query> (403 <code>): the Worker app relies on <grant>; see
   docs/security/graph-permissions.md"; a 401 that persists after a fresh token names it too.
   A 403 without Graph's JSON (a TLS-inspecting proxy's block page) is a plain `GraphError`
   pointing at the network, as a 404 without it is (review of W2.1).
5. **Retries.** GraphClient makes every attempt itself (`max_attempts` 1, status retries
   off, as VeeamClient): 5 attempts per call, shared by transport failures, 5xx and 429.
   A Retry-After (delta-seconds or IMF-fixdate) on 429 or 503 raises the wait to it; each
   wait is capped at 120 s and one call's waits at 300 s **in all, the waits of a token
   renewal made inside that call included**; over a cap is a `TransientError` at once.
   - The **token POST is resent after any transport failure** (connect, handshake, dropped,
     timeout) with a new assertion, unlike VeeamClient's token request: a client-credentials
     request changes nothing on Entra's side. Also on 5xx, 429 and Entra's retryable codes;
     never on another 400/401; every retry waits at least 5 s.
   - A 401 from Graph: one fresh token and a resend; another 401 is an `AuthError` (at most
     3 resends when other calls keep replacing the token). A 401 asking for
     `insufficient_claims` is an `AuthError` at once.
   - Tokens: `token_type` Bearer, a non-empty `access_token`, integer `expires_in` above 0
     (a day at most counts); renewed 60 s before expiry, or at half a lifetime of 120 s or
     less; single-flight under a renewal lock with a generation counter, and callers waiting
     behind a failed renewal share its failure. The token itself sits under a second, brief
     lock: a call whose token is still good never waits for a renewal in flight, and a call
     that does wait for one has that time counted toward its 300 s (review of W2.1).
6. **Where the token goes.** Only to a URL that starts with exactly
   `https://graph.microsoft.com/v1.0/` (a text compare, plus no whitespace, control
   character (the UTF-8 ones of `control_chars.hpp` included), backslash, `#`, dot segment,
   encoded `/` or `\` or double-encoded dot or separator); a path starting with `/` is
   taken relative to it, any other absolute URL is a `GraphError` before anything is sent. Redirects are never
   followed (`HttpClient` turns them off): `get` returns a 3xx to its caller, and the token
   request treats one as a `GraphError` without sending anything to its `Location`. The
   download that must follow Graph's redirect, without the token, is W2.2's. Every request carries `User-Agent: ISV|RestoreProof|RestoreProofWorker/<version>`.
   `rp::redact` also masks a raw JWT and `Bearer <token>`.
7. **TLS.** The Graph and Entra HTTP client (`make_graph_http_client`) trusts the Windows
   certificate store alone: no CA file, no pin.
8. `graph_tenant_id` and `graph_client_id` must be GUIDs (`rp::is_uuid`), in `config.json`
   and in the GraphClient constructor: both go into URLs and the assertion, and a domain
   name, `common` or `organizations` would sign in somewhere else than meant.

**Reason.**

- **OpenSSL, not CNG.** W2.4 has to put the PFX bytes in Veeam's restore body anyway
  (`docs/api/veeam-feasibility.md` §5.4), so a non-exportable CNG key would not remove the
  PFX from the machine, and OpenSSL is already linked into rpcore.
- **PS256 and `x5t#S256`:** SHA-256 throughout rather than SHA-1 thumbprints and PKCS#1
  v1.5; the probe showed Entra takes it on the lab tenant.
- **One budget per call:** a caller (W2.2's verification) must be able to bound how long one
  GET can block; a separate budget for a token renewal made inside it would double that.
- **Resending the token POST after a lost reply** is safe where VeeamClient's is not:
  Entra's client-credentials grant has no side effect a duplicate could repeat.
- **A grant in every 403 message:** Graph's 403 doesn't say which permission is missing,
  and the Worker's are split across Entra, SharePoint, OneDrive and Exchange RBAC. The
  wording is generic, so a customer never sees lab names.
- **A text compare for the token's URL:** parsing the URL could read it differently from
  curl; an exact prefix leaves no room for that, and makes `@odata.nextLink` safe to follow.

**Alternatives rejected.**

- *CNG with a key in `Cert:\CurrentUser\My`:* see above; reconsider with the vault (W4.5)
  if Veeam's restore body stops needing the PFX.
- *A client secret:* rejected in L1.5.
- *Following Graph's redirects with the token:* the token would reach whatever host the
  redirect names. W2.2's downloads follow theirs without it.
- *A separate retry budget for token renewals:* see "One budget per call".

---

## 2026-09-27 — W1.7: the connector interface; clients by name, neutral types and errors, targets only from Config

**Decision.**

- **`rp::connector::IConnector`** (`worker/include/rp/connector.hpp`) has `describe()`,
  `list_restore_points(client_ref)` and `restore_sample(spec)`. These are the guide's
  `Describe`, `ListRestorePoints` and `RestoreSample`, in the Worker's snake_case. One instance
  talks to one backup server with one set of credentials.
- **`client_ref` is the client's name in the backup product.** For Veeam that is the
  organisation name, as in `veeam_org_name`. A *client* is one MSP customer: one Microsoft 365
  tenant, one Veeam organisation.
  - An MSP whose Veeam server backs up many tenants uses one connector, and each call names
    its client.
  - The connector resolves the name to Veeam's organisation ID on every call, ASCII
    case-insensitively, as `veeam list` marks it.
  - No match is `NotFoundError`; two matches are a plain `Error`; an empty `client_ref` is
    `std::invalid_argument` before any request. A matched organisation whose ID isn't a UUID
    is an `Error`, checked before the restore points are asked for; any other
    `std::invalid_argument` passes through as it is.
  - Error messages show `client_ref` with each control character (`control_chars.hpp`) made
    a space, as `veeam list` shows Veeam's text: it will come from a Cloud job (C5.6), and
    a CR/LF or bidi override in it must not forge, hide or reorder a log line.
- **Neutral types, in namespace `rp::connector`.**
  - `RestorePoint` holds:
    - `id`: opaque, only meaningful to the connector that returned it.
    - `backup_time`: byte for byte as the product sent it, since Veeam opens explore sessions
      by that exact string.
    - `has_mail`, `has_sharepoint`, `has_onedrive`.
    - `is_archive`: Veeam's long-term copy, whose restore needs a retrieval first.
  - Veeam's organisation, repository and job IDs, `isCopy`, `isDeleted` and Teams stay behind
    the interface.
  - Errors: `connector::Error` (a `runtime_error`; `what()` is safe to print), with subclasses
    `AuthError`, `TransientError`, `NotFoundError` and `NotImplementedError`.
  - `VeeamM365Connector` catches the `VeeamError` family and rethrows the matching class with
    the same, already redacted, message: `AuthError`, `TransientError` and `NotFoundError` map
    to their namesakes, and any other `VeeamError` becomes `Error`.
  - The classes line up with `rp::exit_code`: 2 auth, 3 transient, 4 the rest. A command
    that runs a connector (W2.8) maps them as `veeam list` maps the Veeam ones.
- **`RestoreStatus` is the restore's own outcome**, not pass/fail/error, which W3.3 decides
  from it and the Graph comparison. How W2.5 will map Veeam's session `result` and
  `restoredItemsCount` onto it, one session per item type:

  | Status | Meaning | Veeam |
  |---|---|---|
  | `succeeded` | every session succeeded and restored every item sent | every session `Success`, each `restoredItemsCount` equal to the items it was sent |
  | `partial` | something restored, but not cleanly | any `Warning`; a `Failed` session beside sessions that restored items; `Success` with a short `restoredItemsCount` |
  | `failed` | nothing restored | every session `Failed`, or 0 restored; this covers the OneDrive trap in `docs/api/veeam-feasibility.md` §3 (`Failed`, 0 restored, no `errors`) |
  | `not_run` | nothing was sent | the default; what an empty spec returns |

  - The rows are tried in this order, and the first that fits wins: `not_run` (nothing
    sent), `failed` (0 restored in total, whatever the results say), `succeeded`, then
    `partial` for everything else. So `Warning` with 0 restored and `Success` with 0
    restored are `failed`, never `partial`.

  - W3.3 then reads: `failed` → fail; `partial` → fail unless every item verifies.
  - Infrastructure failures and guard violations are exceptions, never a status.
  - `RestoreResult` also carries:
    - `session_ids`: a vector, one per session (the guide's `sessionId`).
    - `log`: the sessions' logs, as text.
    - `items_restored`.
- **Restore targets come only from Config.** `RestoreTargets::from_config` is the only way
  to build one (the default constructor is private). It rejects an empty value and, as
  `parse_config` does, a `test_mailbox` that isn't `restoretest@<domain>`
  (`rp::is_restore_mailbox`), since a `Config` built in code skips `parse_config`.
  - It holds `test_mailbox`, `test_site_id`, `test_library_id`, `test_onedrive_drive_id` and
    `test_onedrive_folder_id`.
  - `RestoreSpec` holds a copy, so a spec can't be made without the configured targets and
    nothing dangles.
  - W2.7's `TargetGuard` compares each item's target with these, inside `restore_sample`.
    Resolving the Graph IDs to the names and URLs Veeam's restore bodies take (§5.5) is W2.4
    and W2.7's job.
  - `RestoreSpec` also holds the `client_ref`, the whole `RestorePoint` (for its
    `backup_time`), and mail, SharePoint and OneDrive selectors shaped like
    `lab/seed-manifest.json` entries. W2.5 and W2.6 may add fields.
- **`rpworker veeam list` stays on `VeeamClient`.** It lists every organisation, with Teams
  and raw Veeam IDs: a Veeam diagnostic, not a per-client connector operation. Its output and
  exit codes don't change.
  - The Done-when is shown in `worker/tests/connector_test.cpp` instead: scheduler-like code
    drives a fake connector through `IConnector&`, and a scan checks that nothing the file
    includes reaches a Veeam header.
  - `veeam_m365_connector_test.cpp` drives the registry's `veeam_m365` through `IConnector&`
    on recorded fixtures, and a `[live]` test does the same against the lab.
  - W2.8 `rpworker restore` will be the first command to go through the registry.
- **No config key picks the connector.** The name stays hard-wired as
  `rp::connector::kVeeamM365` until there is a second connector.
  - C5.2/C5.6 already give each client's connector a `type` in the job, which is where the
    name will come from.
  - `ConnectorRegistry` (`rp/connector_registry.hpp`) is an explicit name → factory map:
    - `add` rejects an empty name, a null factory and a duplicate.
    - `create` matches names exactly.
    - `default_connector_registry()` registers `veeam_m365`.
  - An unknown name is `UnknownConnectorError` (`std::invalid_argument`), listing the known
    names. The asked-for name is quoted only when it is 1–64 printable ASCII characters. It
    is a configuration error: exit 1 where a command meets it, `error` for a run.
  - The Veeam factory throws `ConfigError` "RP_VEEAM_USERNAME is not set" (then
    `RP_VEEAM_PASSWORD`), as `veeam list` reports them.
- **The connector owns its HTTP client and `VeeamClient`,** made from `ConnectorOptions`
  (HTTP factory, logger, sleep, jitter) with `veeam_ca_file` and `veeam_cert_sha256` from
  the config (TLS never off). It logs out in its destructor, and does nothing if it never
  signed in. `describe()` is offline: `{"veeam_m365", "v8"}`, the REST API version it
  speaks. `restore_sample` throws `NotImplementedError` before any request until W2.5.

**Reason.** The Done-when asks that the scheduler hold an `IConnector&` without knowing
Veeam. That rules out Veeam types and exceptions crossing the interface, and a scan makes it
checkable. C5.6's job carries the Veeam org name, not an ID, so the name is the reference
that will arrive. A targets type that can only come from a validated Config gives TargetGuard
one source of truth, and leaves no code path that builds free-form targets.

**Alternatives rejected.**

- *Veeam's organisation ID as `client_ref`:* a Veeam concept in the neutral interface, and
  not what the job sends.
- *Reusing `rp::RestorePoint` and the Veeam exceptions:* the scheduler would include
  `veeam_client.hpp`.
- *Veeam exceptions that also derive from the connector ones:* multiple inheritance, and
  `VeeamClient` would depend on the connector layer.
- *pass/fail/error as the connector's status:* the connector can't see the Graph comparison.
- *A spec holding a reference to one `RestoreTargets`:* it could dangle once runs go to a
  worker thread.
- *Moving `veeam list` onto the connector:* it would need a `ListClients` and Veeam-only
  fields on the interface.
- *A `connector` key in `config.json`:* the wrong place once jobs carry the type.
- *Self-registering factories:* the linker drops unreferenced objects from the static
  `rpcore`, and their registration with them.

---

## 2026-09-27 — The Worker's Graph app: a certificate, `*.Selected` grants, Exchange RBAC for mail, read-only for now (L1.5)

**Decision.** The Worker reads the restore targets through its own app registration,
"RestoreProof Worker" (single tenant, app-only). Details and the per-permission reasons:
`docs/security/graph-permissions.md`.

1. **Credential: a certificate, not a client secret.**
   - Until the vault, the private key exists only in a PFX outside the repo
     (`%LOCALAPPDATA%\RestoreProof\lab\worker-graph.pfx`). Its random password is in
     Credential Manager (`RestoreProof Lab - Worker Graph app PFX`).
   - When the Worker's Graph code lands (W2.1), `RP_GRAPH_CLIENT_SECRET` is replaced by
     `RP_GRAPH_CERT_PFX_BASE64` (the PFX, Base64) and `RP_GRAPH_CERT_PASSWORD`. That is the
     same form Veeam's restore body takes, and the vault (W4.5) will hold it.
     *(Done in W2.1: see the 2026-09-28 entry.)*
2. **No `Files.Read.All`.** SharePoint access is `Sites.Selected` `read` on the RestoreTest
   site. OneDrive access is `Files.SelectedOperations.Selected` `read` on alice's
   `/RestoreTarget` folder: not `Sites.Selected` on her OneDrive.
3. **Mail through Exchange Online RBAC for Applications.** The role is `Application
   Mail.Read`, with a management scope of `PrimarySmtpAddress -eq 'restoretest@…'`. The Entra
   `Mail.Read` consent is not granted, and the setup script removes it if present.
   A management scope needs the tenant "hydrated", so the lab tenant ran
   `Enable-OrganizationCustomization` on 2026-09-27. That is once per tenant, tenant-wide and
   irreversible, and was chosen over scoping by an Entra administrative unit, which would add
   an Entra object and a Graph scope for the same result.
4. **Read-only in L1.5.** The write needs of cleanup (W3.x) are an open item, with a proposal:
   `Lists.SelectedOperations.Selected` `write` on the RestoreTarget list only, the folder
   grant raised to `write`, and `Application Mail.ReadWrite` on the same scope.
5. The setup is a script the admin runs, `lab/entra/new-worker-app.ps1` (idempotent). It is
   checked by `python -m seeder check-worker-app`: 200 on the three targets (and on the
   metadata of alice's OneDrive site and root folder, which a folder grant opens), 403 on
   alice's mailbox, the tenant root site and its drives, and the OneDrive host site, 404 on the
   canary folder (SharePoint masks items the app may not see; a sign-in as alice first confirms
   the folder exists), alice's OneDrive root listing only `RestoreTarget` by that name, exactly
   two roles in the Graph token and none in the Exchange Online and SharePoint tokens. The
   RestoreTest site's canary library stays readable: `Sites.Selected` covers the whole site.
   The script leaves the certificate as the app's only credential (no client secret).

**Reason.**

- **Certificate.** A secret is a password sent with every token request; a certificate signs
  a short-lived assertion, so the key never leaves the machine. W1.0 showed Veeam's restore
  body needs an app certificate as a PFX anyway (`docs/api/veeam-feasibility.md` §5.4), so one
  credential kind and one storage path cover both. A non-exportable key in the certificate
  store would be stronger at rest, but the lab's Python checker can't sign with it, and
  Veeam needs the PFX bytes regardless.
- **`Files.Read.All`** reads every drive in the tenant through `/drives/{id}`, so "403 on any
  other site" (the Done-when) could never hold.
- **`Sites.Selected` on alice's OneDrive** would open her whole OneDrive, the canary folder
  included. Graph's `*.Selected` scopes now reach a single folder, and every `*.Selected`
  scope works app-only (Microsoft, "Overview of Selected permissions in OneDrive and
  SharePoint").
- **Mail.** An Entra `Mail.Read` consent covers every mailbox. Exchange adds RBAC grants to it
  as a union, so a scoped grant only means something if the consent is gone (Microsoft,
  "Role Based Access Control for Applications in Exchange Online", FAQ). RBAC for
  Applications replaces Application Access Policies.
- **Read-only.** `Sites.Selected` roles apply to the whole site, and the canary `RestoreTest`
  library shares the site with `RestoreTarget`. A site-wide `write` would put the canaries in
  reach of the Cleaner. Nothing in L1.5 writes, so nothing is granted to write.

**Alternatives rejected.**

- *A client secret (the issue's wording):* weaker, and a second kind of credential next to
  the PFX Veeam needs.
- *A non-exportable key in `Cert:\CurrentUser\My`:* see above. Reconsider when the Worker
  signs its own assertions in C++ (W2.1): CNG can sign with a key it never exports. Veeam's
  PFX would still be needed. *(Reconsidered in W2.1 and kept rejected: see the 2026-09-28
  entry.)*
- *`Files.Read.All` or `Sites.Read.All`:* tenant-wide.
- *`Sites.Selected` on alice's OneDrive:* her whole OneDrive for one folder.
- *An Application Access Policy on top of Entra `Mail.Read`:* legacy, replaced by RBAC for
  Applications.
- *Granting `write` now:* no L1.5 need, and the only site-level form reaches the canaries.

**Open.**

- The write grants for W3.x (above).
- Which app's certificate goes in Veeam's restore body (W2.4). Not this one: it can't write.
  *(W2.4 used Veeam's own organisation app, exported per run, in the lab; the Worker's restore
  credential is open until a spike before W4.5: see the 2026-09-28 W2.4 entry.)*
- Per-customer onboarding of these grants, and certificate renewal (a one-year lab cert).

---

## 2026-09-27 — W1.6: rpworker veeam list, exit codes and output

Changes the usage exit code from 2 to 64. The 2 was set with W1.1/W1.2 in the `cli.hpp` and
`config_check.hpp` comments and `docs/worker-config.md`, never recorded in this log; the
2026-09-24 entry "`rpworker`'s command line lives in rpcore" only says where exit codes live.

**Decision.**

- **One set of exit codes for the whole `rpworker` CLI**, in `rp::exit_code`
  (`worker/include/rp/cli.hpp`): `0` success; `1` config error (`config.json` missing or
  invalid, a `--config` path that isn't UTF-8, `RP_VEEAM_USERNAME` or `RP_VEEAM_PASSWORD`
  unset or empty, or any unexpected exception that isn't a Veeam one, whose message is never
  shown); `2` `AuthError` (Veeam refused the credentials, the role or the token); `3`
  `TransientError` (unreachable, timeout, TLS handshake failure, 502/503/504); `4` any other
  `VeeamError`, `NotFoundError` included, and `veeam_org_name` not among Veeam's
  organisations. A certificate that fails verification (`TransportError::tls`: a
  `veeam_ca_file` that doesn't hold Veeam's certificate or its CA, or a `veeam_cert_sha256`
  that no longer matches after Veeam's certificate was renewed) is a plain `VeeamError`, so
  exit 4, not 3: it won't fix itself on a retry. `64` usage (sysexits' `EX_USAGE`): a command line `rpworker` doesn't
  understand, an argument that isn't valid UTF-16 included. The usage line is one string,
  `rp::kCliUsage`, listing all three forms.
- **Messages on stderr, one line each:** `config error: <ConfigError what()>` as in `config
  check`; `config error: RP_VEEAM_USERNAME is not set` (checked first), then the same for
  `RP_VEEAM_PASSWORD`; `veeam error: <what()>` (already redacted by `VeeamError`);
  `error: unexpected failure` for an unexpected exception after the config loaded.
- **No exception leaves `rpworker`.** `rp::run_cli` and `rp::run_main` are `noexcept` and
  catch anything a command lets out: `error: unexpected failure`, exit 1. Uncaught, it would
  end in `abort()`, whose exit code with the MSVC runtime is 3, the code for "Veeam
  unreachable, try again later". `veeam list` catches everything itself too, formatting and
  writing the table included.
- **`veeam list` lists every organisation Veeam returns**, sorted by name (ASCII
  case-insensitive), then ID, and marks the one `veeam_org_name` names (ASCII
  case-insensitive) with `*` in a leading marker column. When none matches, the table is
  still printed, then `veeam error: organisation <name> (veeam_org_name) not found in
  Veeam`, exit 4; with no organisations at all it prints `no organisations in Veeam` and the
  summary, exit 4.
- **Every list is read before anything is printed.** A restore-point list that fails for
  any organisation (a `NotFoundError` if it vanished between the two calls included) fails
  the whole command with that error's code, and stdout stays empty: no partial table.
  `logout()` runs after any sign-in, on success and on failure, and after the table is
  printed, so a slow logout doesn't hold the table back.
- **The table** (stdout, UTF-8 bytes): columns `ORGANIZATION`, `BACKUP TIME`, `EX`, `SP`,
  `OD`, `TM`, `LONG-TERM`, `RESTORE POINT ID`, after the two-character marker column
  (`* ` or two spaces); left-aligned, padded to the widest cell counted in code points, two
  spaces apart, no trailing spaces. `backupTime` exactly as Veeam sent it; points newest
  first; the flags `x`/`-`, `LONG-TERM` `yes`/`no`; the organisation name on every row; an
  organisation without points gets one row with `(no restore points)`. Control characters
  in text from Veeam become spaces. Then a blank line and `<n> organisation(s), <m> restore
  point(s); * = veeam_org_name`. `rpworker` never changes the console code page, and
  PowerShell 7 doesn't either: non-ASCII names show correctly on a console only once its
  output code page is UTF-8 (`chcp 65001`, or `[Console]::OutputEncoding` set to UTF-8 in
  PowerShell). On code page 437 `Zürich` shows as `Z├╝rich`.
- **Testability.** `rp::run_veeam_command` (`worker/include/rp/veeam_command.hpp`) takes a
  `VeeamCommandEnv` (default config path, secrets loader, HTTP client factory, client
  options); `run_cli` passes `default_veeam_command_env()`, whose logger writes warnings and
  worse to stderr, never to stdout where the table is. The HTTP client gets `ca_file` and
  `pinned_cert_sha256` from the config (TLS never off). The `[--config <path>]` handling
  `config check` had moved to `worker/src/command_config.{hpp,cpp}`, shared by both
  commands. `run_exe_test.cmake` takes an optional `UNSET_ENV` list, so an exe test can
  remove variables the developer's shell has set.

**Reason.** The issue asks for exit code 2 on an authentication failure, which usage held.
Distinct codes let a script or the future service tell a wrong password from a server that
is down from a missing organisation without parsing text. Listing every organisation, rather
than only the configured one, is what an operator needs when `veeam_org_name` is wrong: the
right name is on screen. Building the whole table first keeps a failure from looking like a
short, successful list.

**Alternatives rejected.** *Keeping usage at 2 and giving auth another code:* the issue fixes
auth at 2. *Printing only `veeam_org_name`'s restore points:* a typo would show nothing
useful. *Printing organisations as they are read:* a later failure would leave a partial
table that looks complete. *Setting the console to UTF-8 from `rpworker`:* it changes the
shell's state for everything run after it; the bytes are UTF-8 either way. *CLI11:* the
hand-rolled parser still has three forms; not worth a dependency. *A code of its own for an
exception no command caught (70, sysexits' `EX_SOFTWARE`):* exit 1 already means "something
unexpected failed" and says nothing more; what matters is that it isn't 3.

---

## 2026-09-26 — VeeamClient after review: one retry budget, token requests at most once, renewal failures shared only while no token works (W1.5)

Supersedes parts of the entry below ("VeeamClient: status retries off per request ...") and
of "Veeam TLS" (how the CA file is read), after the review of PR #124.

**Decision.**

- **VeeamClient makes every attempt itself: five per request in all.** A new
  `HttpRequest::max_attempts` (1 to 5, default 5) caps `HttpClient`'s attempts; every
  Veeam request goes out with 1, so `HttpClient` never retries under the client (one GET had
  made up to 25 requests, 50 through the 401 path). With 1, `HttpError`'s message carries no
  attempt count; the client adds its own ("... (5 attempts)", "HTTP 503 after 5 attempts").
- **A new `TransportError::dropped`** for a connection that broke after the request may have
  gone out (curl's `SEND_ERROR`, `RECV_ERROR`, `GOT_NOTHING`, `PARTIAL_FILE`, formerly
  `connect`). `connect` now means the request never went out. `HttpClient` retries both, as
  before.
- **Which failures are retried.** A GET: `connect`, `dropped`, `timeout`, `handshake`, and a
  transient 5xx, with `rp::retry_delay`'s backoff. A token request (`/v8/token`): only
  `connect` and `handshake`, which never reached Veeam. After a timeout or a dropped
  connection it is not resent: a second password grant is a second logon (towards an
  account lockout, or another token chain nobody holds), a second refresh presents a used
  token. A logout: one attempt, never retried.
- **`/v8/token`'s 5xx.** Only a 500 is a refusal (`AuthError`, whatever its body). A 502,
  503 or 504 is a gateway or a service starting up (`TransientError`); any other 5xx maps
  as on any call. None is retried: the next call signs in again.
- **A refresh that fails with a `TransientError` is thrown as it is**, not followed by a
  password sign-in, which would meet the same unreachable server while every other caller
  waits on the lock. A refresh Veeam refuses (401 "Refresh token is not valid", an empty
  500) or garbles still falls back to the password.
- **Renewal failures are shared only while no token works.** A caller that waited for the
  lock while a sign-in or refresh failed gets that failure only if it still has to renew
  when it gets the lock and no renewal has succeeded since (a stored token clears the kept
  failure). A waiter was handed an earlier failure after a later sign-in had succeeded.
- **An empty 401 for a newer token** another caller brought is followed by the one fresh
  sign-in if that token is dead too (a REST restart kills every token), then one more
  resend; at most three resends per call. It used to end in `AuthError`.
- **`logout()` refreshes an access token within 60 s of expiry first** (one try, no password
  sign-in): Veeam refuses a logout with an expired one, and the refresh token it would end
  outlives it (veeam-notes §1.5). It sends outside the lock.
- **Paging** gives up after 3 full pages in a row that bring nothing new, not 1: with a small
  page size, points added in front between two reads repeat the last page.
- **List entries are moved out of the parsed page**, never copied: copying a JSON value
  recurses once per level, and a deeply nested value overflowed the stack.
- **Text from a response** (`message`, `errorCode`, `WWW-Authenticate`'s
  `error_description`, a bad `backupTime`) has every control character replaced, including
  the multi-byte ones config values refuse (C1, U+2028/U+2029, bidi marks, embeddings,
  overrides and isolates, U+061C); one list in `worker/src/control_chars.hpp` serves both.
- **`expires_in`** of 2^63 or more is capped at a day like any other large value, not refused.
- **The CA file is read as curl's Schannel backend reads it** (`rp::public_key_pin`, so
  `config check` too): each exact `-----BEGIN CERTIFICATE-----` line through the next
  `\n-----END CERTIFICATE-----`, decoded by the same `CryptQueryObject` call, stopping at
  the first BEGIN marker with anything after it on its line, and failing on a block without
  its END line or one Windows can't decode. OpenSSL's PEM reader accepted files curl then
  loaded as empty (a trailing space after the marker, the old `X509 CERTIFICATE` label) or
  refused, and asked for a pass phrase on the console for a block with PEM encryption
  headers. rpcore links `crypt32`.

**Reason.** The review found each of these as a failing scenario (retries multiplied to
11-23 minutes per GET; a stale sign-in error with a valid token stored; an `AuthError` after
a REST restart; 330 s instead of 165 s behind a hung server; a refused logout; a CA file
that passed `config check` and failed every connection). Each has a test that reproduced it
before the fix.

**Alternatives rejected.** *A retry predicate on `HttpRequest` so `HttpClient` keeps the only
loop:* `FakeHttpClient` doesn't retry, so every Veeam retry test would move to the local
server; a cap is simpler. *A single-flight future per renewal:* also correct, but a larger
change than clearing the kept failure on success. *Never resending a token request:* a
connection refused while Veeam restarts would fail the run at once. *Our own base64 decoder
for the CA file:* the only way to agree with curl exactly is to call what curl calls.

**Open.** A restore POST (W2.x) gets the same at-most-once rule as a token request from
`send_with_retries`; whether a timed-out restore started is still to be found in
`GET /v8/RestoreSessions` before any resend (veeam-notes §6).
*(W2.4, 2026-09-28: the restore POST is sent at most once, with a duplicate check in
`GET /v8/RestoreSessions` instead of a resend; see the 2026-09-28 W2.4 entry. `VeeamClient`
implements it in W2.5.)*

---

## 2026-09-26 — VeeamClient: status retries off per request, Veeam's 5xx classified by the client; token and paging rules (W1.5)

**Decision.** `rp::VeeamClient` (`worker/include/rp/veeam_client.hpp`) follows
`docs/api/veeam-notes.md` §1.7 and §8, with these choices:

- **`retry_on_status`** is a new per-request flag (`HttpRequest`, `RequestOptions`, default
  on). Off, every response, 5xx included, comes back after one attempt; transport errors
  (connect, timeout, dropped handshake) are still retried. Every Veeam request goes out
  with it off.
- **The client classifies Veeam's 5xx itself.** Any 5xx on `/v8/token` → `AuthError`, never
  retried. A 500 whose body is a JSON object with a string `message` → `VeeamError` with
  that message, not retried. 502/503/504, and any other 5xx without such a body →
  `TransientError`; on a GET, the client retries it first with `rp::retry_delay`'s backoff (five
  attempts in all). 401/403 and `errorCode: ResourceAccessDenied` → `AuthError`; 404 with
  `ResourceNotFound` → `NotFoundError`; everything else → `VeeamError`. All four derive
  from `VeeamError`, which keeps the status, Veeam's `errorCode` and the error body (never
  for `/v8/token`: a proxy could echo the posted password).
- **Tokens.** Refresh 60 s before expiry, counted on the local steady clock from receipt;
  `expires_in` capped at a day, and a lifetime of 120 s or less refreshed at its half. One
  mutex covers sign-in, refresh and the swap of both tokens. Any refresh failure falls back
  to the password. An empty 401 on an API call: resend with the current token if another
  caller has replaced it, otherwise sign in once and resend; a second 401 → `AuthError`. A
  401 with a message (the account's role) → `AuthError` at once. Callers that waited on the
  lock while a sign-in failed get that failure rather than each trying in turn.
- **Lists page until a page is shorter than the limit Veeam echoes** (1000 asked). An `id`
  seen on an earlier page is dropped (a backup finishing mid-read shifts the pages); a full
  page with nothing new stops with an error instead of looping.
- **Restore points are sorted newest first by `backupTime`'s value**, and `backupTime` is
  kept as the raw string. A point whose `backupTime` isn't Veeam's UTC form
  (`YYYY-MM-DDTHH:MM:SS[.1-7 digits]Z`) fails the whole list: explore sessions are opened by
  that string, and Veeam answers 500 to any other form.
- **Names are snake_case** (`list_restore_points`, `ensure_token`), like the rest of rpcore,
  not the guide's camelCase. `RestorePoint` has no `isModified`: v8 has no such field
  (veeam-notes §3, §10).
- **Tests run on recorded fixtures** (`worker/tests/fixtures/veeam/`, from the W1.4/L1.6
  evidence) served by a minimal `FakeHttpClient` (`worker/tests/fake_http_client.hpp`);
  Q2.1 extends it and adds `--record`. The live test runs only with `RP_LIVE=1` and is
  read-only.

**Reason.** Veeam answers 500 to many requests that will never succeed (an explore before
the first point, a stopped session, a bad search, a `dateTime` without `Z`). With W1.3's
rule each cost about 15 s of retries and then lost the body that said why. A refused
sign-in has been an empty 500, so retrying `/v8/token` only delays an `AuthError`. The token
rules follow what the lab showed: refresh tokens rotate and are single-use, a refresh
revokes the old access token at once, and a REST service restart kills every token.

**Alternatives rejected.** *A retry predicate on the request instead of a flag:* more
general, but a callback in every request for one caller's rule. *Letting `HttpClient` retry
GETs' 5xx and classifying afterwards:* a deterministic 500 would still cost 15 s. *Sorting
`backupTime` as text:* Veeam drops trailing zeros of the fraction, so `…15Z` would sort
after `…15.2Z`. *Skipping points with an odd `backupTime`:* hides a format change that
would break every explore anyway. *Parsing `backupTime` into a date type:* drops digits;
W2.x must send it unchanged. *Trusting `.expires`:* it is the server's clock.

**Open.** W1.3's open point is half closed: the 5xx half is settled here, but a timeout or
a connection dropped after a POST went out is still retried by `HttpClient`, so a restore
POST could still run twice. W2.x must add an at-most-once mode (no retry once the request
may have been sent) or find its own session in `GET /v8/RestoreSessions` before resending
(veeam-notes §6). *(W2.4, 2026-09-28: the restore POST is sent at most once, with a duplicate check in
`GET /v8/RestoreSessions` instead of a resend; see the 2026-09-28 W2.4 entry. `VeeamClient`
implements it in W2.5.)* `logout()` holds the lock while it sends, so a hanging logout delays
other calls; it runs at the end of a job. Veeam's "cannot manage selected object" 500
(an operator outside its scope, veeam-notes §8) maps to `VeeamError`, not `AuthError`;
operator mode is out of Stage 1.

---

## 2026-09-26 — Veeam TLS: the CA file plus a pinned certificate; only the host-name check is skipped (W1.5)

**Decision.** This settles the TLS point left open by "Veeam: admin mode is the default"
(2026-09-26). A new optional config key, `veeam_cert_sha256`, names Veeam's REST
certificate by its SHA-256, as Windows shows it (`GetCertHashString('SHA256')`, the value
the W1.4 scripts pin). It requires `veeam_ca_file`, which must hold that certificate in
PEM. With both set, the Veeam connection:

- keeps peer verification on, with the CA file as the only trust anchor (curl's Schannel
  backend validates the chain against it alone, dates included);
- pins the certificate's public key (`CURLOPT_PINNEDPUBLICKEY`, `sha256//` + the base64
  SHA-256 of its SubjectPublicKeyInfo, worked out by `rp::public_key_pin` from the CA file);
- skips only the host-name check.

Without a pin nothing is relaxed: a CA file alone, or no setting at all, keeps full
verification. `load_config` checks that the CA file holds the named certificate. If the pin
can't be worked out when the client is built, every request is refused before sending.
The TLS source scan gets narrow reviewed exceptions, each allowed once and only in
`src/http_client.cpp`: the statement that writes the pin, and
`options.verify_host = options.pinned_public_key.empty();`. Any other mention of the pinned key in
Worker code fails the build.

**Reason.** Veeam's default REST certificate is self-signed, `CN=Veeam Software`, with no
extensions at all, so no subject alternative name: no host name can ever verify against it,
and `veeam_ca_file` alone fails on every default install (feasibility §5.1). A probe on
127.0.0.1 with a certificate built the same way (curl 8.22, Schannel) showed:

- Schannel honours the pinned key whether or not peer verification is on;
- the host check can be turned off on its own;
- with CA file + pin + host check off, the right pin passes, while a wrong pin, another
  server key, a CA file without the certificate, no pin, a CA file alone and an expired
  certificate all fail;
- with peer verification off as well, an expired certificate passed.

So keeping the chain check costs nothing and keeps the dates. The TLS tests
(`worker/tests/http_client_tls_test.cpp`) repeat each case with a certificate made at run
time.

**Alternatives rejected.** *Pin only, with peer and host verification off:* one setting
fewer, but the config would have to hold the public-key hash (not what Windows shows), the
expiry would go unchecked, and the scan exception would be two switched-off checks. *A
certificate with the server's DNS name (`Set-VBORestAPISettings`):* still supported, through
`veeam_ca_file` alone, but it asks every MSP to replace Veeam's certificate before a first
test. *Importing Veeam's certificate into the Worker machine's Windows root store:* it
would let a key on the Veeam server sign certificates the whole machine trusts. *Checking the certificate's hash
after the handshake (`CURLOPT_CERTINFO`):* the request, password included, would already
be sent.

---

## 2026-09-26 — Bruno collection replaced by PowerShell scripts (W1.4)

**Decision.** The guide's W1.4 asks for a Bruno collection exported to
`docs/api/veeam-m365.bru`. Instead, the Veeam REST calls are small PowerShell 7 scripts in
`docs/api/veeam-m365/`:

- one script per step (`01-auth.ps1` … `09-token-expiry.ps1`);
- a shared, dot-sourced helper (`VeeamLab.ps1`);
- an evidence audit (`audit-evidence.ps1`);
- a README.

They record their responses, scrubbed, as `docs/api/veeam-lab/w1.4-*.json`, the format W1.0
started. `docs/api/veeam-notes.md` is written from those files. Later API exploration (W2.4's
restore flow) extends the same collection.

**Reason.**

- **TLS without switching verification off.** Veeam's default REST certificate has no SAN, so
  no host name verifies (`docs/api/veeam-feasibility.md` §5.1). Bruno can trust a CA file or
  turn verification off, and it can't pin one leaf certificate. The helper pins the leaf's
  SHA-256 in a compiled .NET callback, which is the same trust the Worker will need (W1.5).
- **No secrets on disk.** rp-veeam's password is read from Windows Credential Manager at run
  time, and tokens live only in the process. A Bruno environment keeps variables in files next
  to the collection, easy to commit by mistake.
- **Evidence comes out scrubbed and audited.** Every call can write its exchange straight into
  the repo's evidence format. The writer replaces known secret values, token-shaped values and
  JWTs, and refuses to write a file in which a secret survived. The audit script re-checks
  everything before a commit. W1.0 did this by hand-run helpers; now it is in the repo.
- **Session hygiene in code.** Every explore session is stopped in a `finally`, and a sweep
  script stops leftovers. A request collection can't express "stop what you opened, even on
  failure", and a leaked session stays `Working` for a long time (W1.0 saw 36 minutes).
- **Already proven.** W1.0 ran entirely on PowerShell and raw REST.
- **Nothing new to install.** PowerShell 7 is already on every machine that runs Veeam's own
  cmdlets (`docs/environment.md`), including an MSP's Veeam server.

**Alternatives rejected.**

- *Bruno (the guide's choice):* no leaf pinning (above), and its variables sit next to the
  collection.
- *Postman:* the same TLS options, plus a cloud account and sync.
- *curl scripts:* `--cacert` fails the host-name check on the SAN-less certificate. `--pinnedpubkey`
  pins the public key but still needs `-k` to skip the name check, which is off-limits.
- *A Python (httpx) collection in `lab/`:* would work, but it would add a second HTTP stack for
  the same job. PowerShell already has the working pinned client, and the Credential Manager
  and DPAPI calls, from W1.0.
- *Writing it in C++ straight away:* that is W1.5. W1.4 is exploration, and a C++ program
  would be tested against a moving target.

---

## 2026-09-26 — Veeam: admin mode is the default and the only mode in Stage 1; restores send an application certificate

**Decision.** This settles the 2026-09-22 entry "Veeam authentication supports two modes;
W1.0 picks the default". The evidence is in `docs/api/veeam-feasibility.md`.

- **`VeeamClient` uses admin mode.** A dedicated local Windows account (L1.6: `rp-veeam`, a
  standard user in the Veeam Backup Administrator role, interactive and RDP logon denied)
  signs in with `grant_type=password` and `disable_antiforgery_token=true`.
- **Operator mode is not built in Stage 1.** Plan section 9 and the security one-pager (Q7.3)
  must not claim "never a Veeam administrator".
- **Restores to another location send restore credentials in the body.** The only kind that
  works unattended is an Entra application ID with its certificate (PFX, Base64, and its
  password). Veeam refuses a body without credentials (400), and user credentials fail on MFA.
- **Tokens.** Refresh tokens are single-use and die with every restart of Veeam's REST service,
  so on any refresh failure the client signs in again with the password.
- **The Sprint 1 gate's fallback** (Veeam's PowerShell module run on the Veeam server) is not
  needed. It stays the answer for an MSP that refuses admin mode.

**Reason.**

- **Operator restores can't reach our targets.** The operator endpoints can only restore mail
  into the original mailbox and OneDrive files to their original place. The schema has no
  target field, and Veeam's docs say the same. So two of the three restore targets are out of
  reach, and CLAUDE.md forbids original locations.
- **Operator sessions can't be kept alive unattended.** A REST service restart (a reboot, a
  Veeam update) ends every session. Starting one again needs an interactive browser sign-in:
  - security defaults block the documented device-code flow (AADSTS530035);
  - the Restore Portal app must be multi-tenant (Veeam's on-behalf-of call uses `/common`);
  - each operator explore session stops after one restore.
- **Admin mode passed every check.** It restored mail, SharePoint and OneDrive into the three
  targets, and it can sign in again without a person.

**Alternatives rejected.**

- *Operator mode for SharePoint only:* two modes to build and support, for one of three item
  types.
- *Restoring into the original mailbox or OneDrive in a marked folder:* breaks the restore
  target rule (2026-09-22, 2026-09-25) and puts test copies in production mailboxes.
- *User credentials in the restore body:* need an account without MFA, which no MSP should
  have.
- *Device codes (`userCode`):* blocked by security defaults, and interactive.
- *The PowerShell module now:* admin mode works, and a second connector isn't needed yet.

**Open.**

- **Which Entra app's certificate the Worker holds** (L1.5, W2.4, W4.5). The lab used Veeam's
  own backup app, which has broad application permissions. A dedicated restore app with
  narrower permissions (Exchange application RBAC scoped to `restoretest`, SharePoint
  `Sites.Selected`) is to be tested before the Worker stores any certificate. Either way the
  PFX and its password are vault secrets, and `worker/include/rp/secrets.hpp` changes with W1.5.
  *(W2.4, 2026-09-28: the lab restores used Veeam's organisation app, its certificate exported
  per run, the PFX never stored. Which certificate the Worker holds stays open until a spike before
  W4.5; see the 2026-09-28 W2.4 entry.)*
- **TLS** (W1.5): Veeam's default REST certificate has no SAN, so no host name verifies and
  `veeam_ca_file` alone can't reach a default install. The options are to require a
  certificate with the server's DNS name (`Set-VBORestAPISettings`) or to add a pinned-leaf
  option. Verification stays on either way.
- **The operator refresh-token lifetime** (48 h and 7 days) is still being measured, due
  2026-09-28 and 2026-10-03. It is recorded for completeness and does not change this decision.

---

## 2026-09-25 — Restored files go to `RestoreTarget`, not to the `RestoreTest` library/folder that holds the canaries

**Decision.** Supersedes the file part of "Restores only ever target `restoretest` /
`RestoreTest`" (2026-09-22). SharePoint items are restored into a new library
**`RestoreTarget`** in the RestoreTest site, and OneDrive items into a new folder
**`/RestoreTarget`** in alice's OneDrive (IDs in `lab/tenant.md`). The `restoretest` mailbox
stays the mail target. The canary files stay where L1.2 seeded them: `rp-canary-01…10` in
the `RestoreTest` library, `11…20` in alice's `/RestoreTest`. Both new targets were created
on 2026-09-25, before any restore. The rest of the 2026-09-22 rule (one guarded code path,
checked per item, a violation is `error`) is unchanged.

**Reason.** The guide uses the RestoreTest library and alice's RestoreTest folder both as
L1.2's canary source and as the restore target. With one place for both:
- a restore of `rp-canary-01.pdf` lands on top of the original, which Veeam overwrites,
  skips or renames, and L1.4's "delete the restored items" can then delete the canary;
- the checker (W3.2) finds the original by name, so a restore that wrote nothing still passes:
  the false pass the product exists to prevent;
- the Cleaner (W3.4) empties the target after every run, and so would delete the canaries.

The mail side never had the problem: the canaries are in alice's and bob's mailboxes, the
target is `restoretest`.

**Alternatives rejected.** A `Restored` subfolder inside the current library and folder: less
setup, but the Cleaner would then have to spare the parent, and one scoping bug deletes the
canaries. Moving the canaries and keeping `RestoreTest` as the target: a new seed run, a new
manifest and a new Veeam backup for the same result. A target in `restoretest`'s own
OneDrive: not provisioned, and it would add a second user's drive to Graph permissions (L1.5).

**Consequences.** `TargetGuard` (W2.7) checks against `RestoreTarget`'s IDs, and the random
sample (W2.6) must exclude both `RestoreTarget` and the canary locations it already
handles. Both are in the same site and drive as before, so `Sites.Selected` on the
RestoreTest site (L1.5) still covers the SharePoint target. Veeam's backup job covers all
sites and OneDrives, so it will also back up whatever is left in `RestoreTarget`. The
Cleaner keeps it empty.

---

## 2026-09-25 — Veeam Backup for Microsoft 365 runs directly on the dev laptop, not in a VM

**Decision.** Supersedes "The Veeam lab VM runs on the dev laptop, with reduced resources"
(2026-09-22). L1.3 installs Veeam Backup for Microsoft 365 v8 (Community Edition) on the
laptop's own Windows 10 Pro 22H2, with no Hyper-V VM. The Worker will reach its REST API on
the same machine (port 4443). A spare PC or a cloud VM stays the fallback, now also for when
a separate host is needed to test the Worker across a network and a certificate name.

**Reason.** Veeam's v8 system requirements (8.6) list Windows 10 21H2/22H2 as a supported
backup server OS and ask for at least 8 cores and 16 GB RAM. The laptop has 2 cores / 4
threads and 16 GB, so the planned 2 vCPU / 6 GB VM would give Veeam well under half its
minimum, plus the overhead of a second Windows. On the host it gets the whole machine, and
L1.3 skips installing and updating Windows Server. The 2026-09-22 entry rejected a host
install because it mixes the product under test with the dev toolchain and doesn't resemble
an MSP's server. Both still hold, but a starved VM is the bigger risk for the Sprint 1
feasibility work. An MSP may also run the Worker on its Veeam server, so a local REST API is
not unrealistic.

**Alternatives rejected.** The 6 GB VM as planned: far below Veeam's minimum, with no gain
beyond isolation. A bigger VM: the laptop has no RAM or cores to spare. A cloud VM now: a
monthly cost and firewall rules before we know the laptop is too slow; kept as the fallback.

**Costs we accept.** Veeam's services and their database run on the dev laptop and start
with Windows. There are no checkpoints to roll back to. The Cloud's local Postgres (Docker,
later) must not clash with a database port Veeam uses. Check the ports when C-work starts.

---

## 2026-09-25 — Office files are compared by content (`office-v1`); the Worker compares `content_sha256`

**Decision.** Supersedes the file-hash part of the 2026-09-24 canary seeder entry below. Every
file entry in `lab/seed-manifest.json` gets a `content_rule` and a `content_sha256`, and the
Worker compares a restored file with `content_sha256` by that rule:

- `bytes` (pdf, txt, png): SHA-256 of the whole file; equal to `stored_sha256`.
- `office-v1` (docx, xlsx, wherever stored): SHA-256 of a listing of the document's content
  parts: every part under `word/` or `xl/` except `_rels/` folders, sorted by name, one line
  per part with its SHA-256 and name. Metadata, `customXml/`, `[trash]/`, content types and
  relationship files don't count. Rule and vectors: `lab/README.md`, `lab/seeder/office.py`,
  `shared/testdata/office-content-v1/` (including real files SharePoint rewrote), which
  W3.2's C++ checker must pass.

`seed` stops, writing no manifest, if the stored document content of an Office file differs
from `lab/canary/`; `hash` checks offline that the committed file reproduces its
`content_sha256`. The type mix stays as it was (option 1 of the two the owner was offered),
so SharePoint Office restores stay under test.

**Reason.** The live run (2026-09-24/25, findings in `lab/README.md`) showed the SharePoint
`RestoreTest` library rewriting every docx and xlsx on upload (3263 → 12617 bytes) and again
some minutes later (+3073 bytes), with `lastModifiedDateTime` unchanged. The first `verify`
therefore reported 4 DIFFs on files nobody had touched. No whole-file hash of an Office file
in a SharePoint library is a stable expected value, and a restore there would be rewritten
too: comparing bytes would report a good restore as `fail`. Part-by-part comparison showed
that SharePoint changes only packaging and metadata; the content parts stayed byte-identical.
OneDrive stored all its files unchanged, and pdf/txt/png were unchanged everywhere. The rule
applies by type, not location, because a Veeam restore may rewrite an Office file wherever it
lands.

**Alternatives rejected.** Keeping `stored_sha256` as the expected value: it was already wrong
minutes after the seed. Dropping Office files from SharePoint (option 2): simpler hashes, but
the most common customer files in a library would go untested. Comparing only size for Office
files: SharePoint changes the size too, and size misses real changes. Parsing the XML and
comparing text: more code on both sides, and a byte comparison of the untouched parts is
already exact. Hashing every part except a known list of SharePoint parts: breaks as soon as
SharePoint adds a new kind of part.

---

## 2026-09-24 — Lab CI: canary files checked offline, the manifest hash check only once it is committed

**Decision.** The `lab` workflow gets two checks after the tests, replacing the single
`python -m seeder hash` step of the canary seeder entry below:

- **Canary files match the generators.** `python -m seeder generate` writes into a temp dir,
  and `diff -r` compares it with the committed `lab/canary/`. It fails on a changed, missing
  or extra file, and needs no manifest.
- **Canary hashes reproduce the manifest.** If `lab/seed-manifest.json` is committed,
  `python -m seeder hash` runs and must pass, as before. If it is not, the step emits a
  GitHub `::warning::` saying the check was skipped and that L1.2's Done when is not met until
  a live `seed` run's manifest is committed, and succeeds.

**Reason.** The manifest is written only by a live `seed` run, which needs three interactive
tenant sign-ins and cannot run in CI. Until that run happens the hash step could only fail,
so the lab job was always red and hid real test failures. The generator check covers the part
that needs no tenant. Once the manifest is committed the hash check is a hard gate with no
change to the workflow. The catch: a PR that deletes `lab/seed-manifest.json` silently turns
it back into a warning, so a reviewer must treat deleting the manifest as a red flag.

**Alternatives rejected.** Leaving the job red until the live run: a permanently red job
trains everyone to ignore it. `continue-on-error` on the hash step: it would also hide a real
mismatch once the manifest exists. A placeholder manifest: it would be a fake expected set,
and `hash` would still have to fail on it. Failing when the manifest is missing only on
`main`: the same always-red problem, one merge later.

---

## 2026-09-24 — Canary seeder: a uv lab tool, a delegated public-client app, text-v1 mail hashes, hashes of what Graph returns

**Decision.** L1.2 (#10) seeds the 40 canary items and writes `lab/seed-manifest.json`. How
to use it: `lab/README.md`.

- **Tool layout.** `lab/` is its own uv project (Python 3.12, `uv.lock` committed) with a
  `seeder` package run as `python -m seeder generate|hash|seed|verify` and a pytest suite in
  `lab/tests/`. The tests run against a fake in-memory Graph tenant, never the network. A new
  CI workflow, `lab` (`.github/workflows/lab.yml`), runs the tests and `python -m seeder hash`.
- **Its own app registration.** The seeder signs in through "RestoreProof Lab Seeder", a
  single-tenant public client (redirect URI `http://localhost`, public client flows allowed)
  with delegated Microsoft Graph permissions only: `Mail.Send`, `Mail.Read`, `Files.ReadWrite`,
  `Sites.ReadWrite.All` and `User.Read`, admin-consented. It has no client secret or
  certificate. MSAL's token cache stays in memory, so no token is written to disk.
- **Three sign-ins.** Delegated Graph reaches only the signed-in user's own mailbox and
  OneDrive: a global admin gets 403 on alice's OneDrive. So a run signs in as alice (her
  mailbox, her OneDrive files), bob (his mailbox) and the admin (sends all 20 mails, uploads
  the SharePoint files), and re-uses alice's and bob's cached tokens to read the mails back.
  After each sign-in the tool checks the signed-in account and stops if it is the wrong one.
- **Hashes are of what Graph returns.** Each file is downloaded back after upload, and each
  mail is read back from the recipient's mailbox. A file entry records both `local_sha256`
  (the committed file) and `stored_sha256` (the bytes Graph returns), plus
  `stored_matches_local`; the Worker compares a restored file with `stored_sha256`. A mail
  entry records `body_sha256` (the read-back body) and `sent_body_sha256` (the sent body);
  the Worker compares with `body_sha256`.
- **Mail body rule `text-v1`.** Bodies are read with `Prefer: outlook.body-content-type="text"`
  and normalised before hashing: drop one leading U+FEFF; CRLF, then lone CR, to LF; strip
  trailing spaces and tabs from each line; strip trailing LFs; UTF-8; SHA-256. Nothing else is
  changed. The rule is named in each entry (`body_normalization`), and a change gets a new name,
  never an edit to `text-v1`. `shared/testdata/body-normalization-text-v1.json` holds test
  vectors that the Python tests use now and W3.2's C++ checker must also pass. The manifest's
  schema is `shared/schemas/seed-manifest.v1.json`.
- **Mail recipients.** `RP-CANARY-0001`–`0010` go to alice, `0011`–`0020` to bob, all sent by
  the admin. W1.0 restores `RP-CANARY-0001` from alice.
- **File types.** The type cycles by number: pdf, docx, xlsx, txt, png (01 pdf … 20 png), so
  each location gets two of each. 01–10 go to the SharePoint `RestoreTest` library root,
  11–20 to alice's OneDrive `RestoreTest` folder. The guide's `rp-canary-20.docx` was an
  illustration; W1.0 needs `rp-canary-01.pdf` in the library, which the cycle gives.
- **Deterministic files.** The generators use the standard library only and no compression
  (ZIP entries stored, PNG pixel data in stored deflate blocks), with fixed dates and metadata.
  A test generates twice and compares with the committed `lab/canary/`, and `.gitattributes`
  marks `lab/canary/**` binary.

Live-run result: SharePoint rewrites Office files, twice, so files are now compared by
`content_sha256` under a `content_rule`, superseding the `stored_sha256` comparison above. See
the 2026-09-25 entry.

**Reason.** The Worker only ever sees an item through Graph, so the expected value has to be
what Graph returns. SharePoint can rewrite Office files on upload (it writes library
properties into them), and a hash of the local file would then report every restore of that file as
a mismatch, a false `fail`. Recording both hashes shows whether that happened. Mail bodies
can pick up line-ending and trailing-whitespace changes on the way through Exchange; the rule
removes exactly those differences and nothing that could hide a real change of content. It
has to be written down precisely because a second implementation, in C++, must give the same
hash. The seeder has several modules (catalog, generators, Graph client, sign-in, manifest)
and its own tests, which a uv project holds naturally. A dedicated app is needed because the
Worker's app (L1.5) doesn't exist yet and will be app-only and read-only, while seeding needs
to send mail and write files. Stdlib-only generators without compression keep the committed
bytes, and therefore the manifest, reproducible regardless of library or zlib versions.

**Alternatives rejected.** A single PEP 723 script: fine for one file, awkward for eight
modules and a test suite. Putting the seeder in `cloud/`: it is lab tooling, not product
code, and would bring its dependencies and coverage rules into the Cloud build. Using the
Worker's app registration with application permissions: it doesn't exist yet, and giving it
`Mail.Send` and write access to files to seed a lab would break its read-only scope. Making
the admin a site collection admin of alice's OneDrive so one sign-in is enough: it changes
tenant permissions to save two sign-ins. Hashing the raw body: a CRLF or trailing-space change
by Exchange would read as a mismatch. Hashing the HTML body: Exchange rewrites HTML freely.
Office and image libraries to write the files: their output changes between versions. Hashing
only the local file: see the reason above.

---

## 2026-09-24 — Worker HTTP client: one fakeable interface, five attempts, redacted logs, TLS always verified

**Decision.** W1.3 (#18) adds the HTTP layer every Worker connector will use.

- **Interface and fake split.** `rp::IHttpClient` (`worker/include/rp/http_client.hpp`) has
  exactly one virtual, `send(const HttpRequest&)`. `get`, `post`, `post_multipart` and `del`
  are non-virtual shorthands that build an `HttpRequest` and call `send`. `rp::HttpClient` is
  the cpr/libcurl implementation. `VeeamClient` (W1.5), `GraphClient` (W2.1) and the Cloud
  uploader take an `IHttpClient&`. Q2.1's `FakeHttpClient` and its `--record` wrapper
  implement or wrap `send` only. No cpr type appears in the header: cpr stays private to rpcore.
- **Five attempts in total.** The guide's steps say "up to 5 attempts"; its Done when says
  "retries five times". We read both as **5 attempts: 1 initial + 4 retries**
  (`rp::kMaxHttpAttempts`). The waits are 1, 2, 4 and 8 s. `rp::retry_delay` caps a wait at
  16 s, but with 5 attempts a request never reaches the cap. The Done-when test asserts
  exactly 5 attempts.
- **What is retried.** Connect errors (resolve, connect, send/receive, empty reply),
  timeouts and TLS handshakes that break off (`TransportError::handshake`) are retried, and
  so is HTTP 500-599. Nothing else is: no 4xx (408 and 429 included), no certificate
  failure, no malformed URL. curl's Schannel backend reports a connection dropped
  mid-handshake as `SSL_CONNECT_ERROR`, the same code it uses for a protocol or cipher the
  two sides can't agree on. Certificate verdicts have codes of their own
  (`PEER_FAILED_VERIFICATION`, `SSL_CACERT_BADFILE`, ...) and stay `tls`, not retried. So
  a restarting Veeam REST service is retried over HTTPS as it is over HTTP, and a lasting
  negotiation failure takes five attempts to report. A 2xx, 3xx or 4xx is returned to the caller.
  An `rp::HttpError` is thrown when the attempts run out, and immediately for a failure that
  isn't retried. The policy is a pure unit (`rp/retry_policy.hpp`). The worst case for one
  call is 5 × its timeout + about 15 s of waiting, about 165 s at the 30 s default.
  `GraphClient` handles Graph's 429/`Retry-After` throttling itself.
- **Jitter** only shortens a wait, by up to 25%, so no wait exceeds its nominal value or the
  16 s cap. `retry_delay` works in whole milliseconds: `nominal - round(nominal * 0.25 *
  jitter)`, with jitter clamped to [0, 1] and NaN counting as 0. The client takes the sleeper,
  the jitter source and the clock as `HttpClientOptions`, so tests never sleep.
- **Only `http://` and `https://` URLs are sent** (scheme in any case). curl here is built
  with FILE, FTP, SMB, LDAP and more, and guesses a scheme for a URL without one. Any other
  URL throws `HttpError` (`other`, 0 attempts) before anything is sent. The check matters
  because URLs from server responses (Graph `nextLink`, the download `Location`, Veeam
  `_links`) will reach `send()`. A review showed a `file:///` URL returning the file's bytes
  as a status-0 response.
- **No method falls through to DELETE.** `perform()` and `to_string()` have a case for each
  `HttpMethod` and no `default`. An out-of-range value throws `std::invalid_argument` before
  anything is sent. rpcore builds with `/we4062`, so a new method without its case is a
  compile error. Before this, anything other than GET or POST (a future PATCH included) was
  sent as DELETE. The same goes for `config.cpp`'s `StringRule`: its check and its error
  message were two switches whose `default` gave the log-level message, and they are now one
  exhaustive switch. The two switches left with a `default` are over curl's error codes in
  `http_client.cpp`, where naming each of about 100 codes would add nothing.
- **Redirects are never followed.** A 3xx is returned, so an `Authorization` header or a
  token body can't be sent to another host. The Graph download 302 will be followed
  explicitly by `GraphClient`, without the header.
- **Timeout.** A per-request timeout covers the whole attempt, and each retry gets it again.
  It defaults to 30 s (`kDefaultHttpTimeout`); a long poll raises it with
  `RequestOptions::timeout`.
- **Logging.** One debug line per attempt: method, URL, `attempt n/5`, then the status or
  the error kind with curl's message, the duration, and the wait before the next attempt.
  Nothing is logged above debug, and request/response headers and bodies are never logged.
  Every logged string, and every `HttpError::what()`, goes through `rp::redact()`.
- **Redaction** (`rp/redact.hpp`) is one pure function, a hand-written linear scan (no
  `std::regex`). The exact rules are in the header comment. It redacts:
  - the value of an `Authorization` or `Proxy-Authorization` header, whatever the scheme, up
    to `\r\n`, `\n` or the end of the text;
  - `client_secret`, `password`, `refresh_token`, `access_token`, `authorization`,
    `tempauth` (Graph's pre-authenticated download URLs), `sig` (Azure SAS),
    `client_assertion` and `id_token` as `key=value` (query strings, fragments, form bodies)
    and as JSON keys at any nesting depth;
  - the first four also in the form `name: value`;
  - a quoted value up to its matching quote;
  - URL userinfo (`https://user:password@host`).

  Only an odd run of backslashes before a quote escapes it; an even run is escaped
  backslashes before a real quote (a review found `{\\"password\\":\\"x\\"}` leaking).

  Names match in any case. It over-redacts on purpose:
  - a key that ends in a name after a non-alphanumeric character counts (`new_password`,
    `db.password`);
  - a JSON value of any type becomes `"[REDACTED]"`;
  - an unterminated value is redacted to the end of the text.

  `code` is not on the list: Graph's error JSON (`"code":"ErrorItemNotFound"`) must stay
  readable. It does not recognise URL-encoded key names (`client%5Fsecret`), hyphenated
  spellings (`client-secret`), JSON keys written with `\u` escapes, or Python-style
  single-quoted keys. The HTTP client never logs bodies or headers, and the W4.9 sentinel
  audit is the backstop for the rest.
- **TLS.** Peer and host verification are set on for every request, and nothing can turn
  them off: no option, no config key, no revocation opt-out. With `veeam_ca_file`, curl
  checks every certificate in the chain for revocation, and a strict check fails on "the
  revocation status is unknown" for an internal CA that publishes no CRL, or one the Worker
  can't reach. So with a CA file (only then) the check is **best effort**
  (`CURLSSLOPT_REVOKE_BEST_EFFORT`): a certificate on its CA's CRL is still rejected, an
  unknown or offline status is let through. cpr 1.14 has no setting for it, so it is one
  `curl_easy_setopt` call after `SetSslOptions`; the source scan allows that exact
  statement, and only in `src/http_client.cpp`. A TLS test serves a CRL from 127.0.0.1 and
  shows a leaf from a private CA accepted with no CDP, an unreachable CDP, or a CRL that
  doesn't list it, and rejected when the CRL lists it. The optional config key
  `veeam_ca_file` names a PEM file trusted for `veeam_url` only. It is an absolute local or
  UNC path; `load_config` checks the file can be read. The path goes to curl as raw UTF-8
  bytes. `cpr::ssl::CaInfo` would convert it to the ANSI code page. With Schannel, curl builds
  the chain against that file alone (its exclusive-root engine), so the file **replaces** the
  Windows store. An HTTPS test against a certificate generated at run time shows four things:
  the server is trusted through a CA file at a Cyrillic path; it is rejected without one; it
  is rejected with a different CA; and a missing file is a TLS failure. Graph and the Cloud
  never set it. Two tests guard this: one checks the `cpr::SslOptions` the client builds, and a
  source scan over `worker/src`, `worker/include` and `worker/app` fails on any TLS switch
  name (`VerifySsl`, `CURLOPT_SSL_*`, `CURLSSLOPT_*`, `curl_easy_setopt`, `verify_status`,
  ...) and on any `verify_peer`/`verify_host` not set to exactly `true`. `verify_status`
  (OCSP stapling) stays off because a self-signed Veeam server doesn't staple. The scan is a
  tripwire, not a proof: review still applies. The known config keys are now 17. `veeam_ca_file` is checked after
  `log_level`, and its readability after the whole parse. It is left out of
  `config.example.json` because it has to name a real file.
- **Test server: cpp-httplib**, with the `openssl` feature and without brotli, linked only to
  `rptests` (`worker/tests/local_http_server.hpp`). The tests serve HTTP and HTTPS on
  127.0.0.1 with an ephemeral port, and generate their certificate with OpenSSL at run time,
  so they need no network and commit no private key.

**Reason.** One virtual function is the smallest seam a fake and a recorder can implement,
and it keeps every connector's tests on fixtures (CLAUDE.md). Taking the Done when's
"retries five times" as five retries would make six attempts and about 31 s of waiting.
Five attempts keep a dead Veeam server's wait to about 15 s, and they are what the guide's
steps say. A 4xx won't change on retry, and TLS failures and bad URLs are configuration
errors; retrying them only delays the `error` status. A redirect that carries credentials to
another host is how bearer tokens leak. Redacting the text itself, rather than trusting
callers to leave secrets out, means a secret that gets into a URL or an error message is
still caught. The redaction errs towards removing too much, because a log that says too
little costs a rerun and a leaked secret can't be taken back. Veeam ships with a self-signed
certificate, so an MSP must be able to trust it without turning verification off.
cpp-httplib is one header, runs in-process, and can serve TLS for the tests.

**Alternatives rejected.** Four virtual methods on the interface: every fake would implement
four. Telling a dropped handshake from a failed negotiation by curl's message text: it
changes between curl versions. `ssl_no_revoke` for a CA file: it would also accept a
certificate the CA has revoked. Best-effort revocation for Graph, the TSA and the Cloud
too: their public CAs publish reachable CRLs, so nothing needs relaxing there. Patching cpr
in a vcpkg overlay to add the option: a fork to maintain for one flag. Six attempts: see above. Retrying 429 honouring `Retry-After`: neither Veeam nor Graph
throttling has been seen yet, so it waits for evidence. Following redirects and relying on
curl to drop `Authorization` on a cross-host hop: the rule would live in curl's defaults,
not in our code. `std::regex` for redaction: slow, and MSVC's implementation recurses deeply
on long input. A `verify_tls: false` escape hatch: one support call away from being set
everywhere. Adding the CA to the Windows store on the MSP's server: it changes machine-wide
trust for one Worker connection. A mock HTTP library or a Python test server: the first
wouldn't exercise cpr and curl, and the second needs a runtime in CI and a process to manage.

**Open.** POSTs are retried on 5xx and timeouts like any other request. A "start restore" or
bundle-upload POST that timed out after the server accepted it could run twice. Before
`VeeamClient` starts restores (W2.x) or the uploader lands, add a per-request opt-out or
idempotency keys. Until then, a timeout, dropped connection or 5xx after the server
accepted a POST can repeat it. A code review reproduced this with a server that read the
POST and closed the connection without answering: the POST arrived five times. curl also
honours the `HTTP(S)_PROXY` environment variables, which is untested on MSP servers. The
`HttpError` for a final 5xx carries the status but not the response body, so `VeeamClient`
may want the body kept (never logged) to say why.

---

## 2026-09-24 — Worker config: strict `config.json`, secrets from environment variables until the vault

**Decision.** W1.2 loads the Worker's settings from `config.json` (default
`%ProgramData%\RestoreProof\config.json`) through `rp::load_config`, and checks them with
`rpworker config check`. Keys and rules are in [worker-config.md](worker-config.md).

- Secrets never go in `config.json`. Until the DPAPI vault arrives in W4.5 (#48), they come
  from `RP_VEEAM_USERNAME`, `RP_VEEAM_PASSWORD` and `RP_GRAPH_CLIENT_SECRET`, whose names are
  defined once in `worker/include/rp/secrets.hpp`. *(W2.1 replaced `RP_GRAPH_CLIENT_SECRET`
  with `RP_GRAPH_CERT_PFX_BASE64` and `RP_GRAPH_CERT_PASSWORD`, and added `pfx` and
  `passphrase` to the markers below: see the 2026-09-28 entry.)* An unset one is not an error, because
  which ones a run needs depends on the Veeam auth mode W1.0 picks.
- A top-level key whose lowercased name contains `password`, `passwd`, `pwd`, `secret`,
  `token`, `api_key`, `apikey`, `credential`, `private_key`, `access_key`, `signing_key` or
  `connection_string` is rejected, before any other key check.
- A key name from the file is echoed only if it is 1-64 of `[A-Za-z0-9_.-]`; otherwise the
  message describes the key without naming it.
- `cloud_url` and `veeam_url` must be printable ASCII and reject userinfo (`@` before the
  path), queries and fragments; every string setting rejects control characters: ASCII, C1,
  U+2028/U+2029 and bidi controls.
- `test_mailbox` must be `restoretest@<domain>` (local part in any case; the domain two or
  more `.`-separated labels of ASCII letters, digits and `-`). Only the domain comes from
  configuration, which applies the 2026-09-22 rule "Restores only ever target `restoretest` /
  `RestoreTest`" at load time. `TargetGuard` still checks every item. The SharePoint and
  OneDrive targets are opaque Graph IDs whose names the loader can't see, so `TargetGuard`
  must resolve them and check they are the `RestoreTest` library or folder.
- The environment and the command line are read as UTF-16 (`GetEnvironmentVariableW`,
  `wmain`) and converted to UTF-8 exactly. Text that isn't valid UTF-16 is an error, never
  replaced.
- Unknown keys are rejected (exact, case-sensitive match against the 16 known keys).
- Validation stops at the first error, in a fixed order: unreadable file, invalid JSON, root
  not an object, secret-looking key, unknown key, each field in declaration order, all sample
  sizes 0.
- Error messages name the key and never echo a value. A JSON parse error reports only the
  byte offset, because nlohmann's message quotes the last token it read; a number out of the
  parser's range (`1e400`) is reported without the number, for the same reason.
- `poll_interval_s` and `heartbeat_interval_s` are bounded 1..86400; `sample_mail`,
  `sample_sp` and `sample_od` 0..100, with at least one above 0.
- No CLI library yet: `run_cli` parses `--version` and `config check [--config <path>]` by
  hand. W1.6 (#21) decides between CLI11 and hand-rolled parsing once there are more
  subcommands.
- `%ProgramData%` is resolved with `SHGetKnownFolderPath(FOLDERID_ProgramData)`, not the
  environment variable.

**Reason.** A misspelt optional key would silently fall back to its default, and a secret
pasted into `config.json` would sit in a plain file that gets copied into tickets; rejecting
both turns a quiet mistake into a named error. Stopping at the first error is simpler,
deterministic and easy to test one rule at a time; the user fixes one thing and reruns
`config check`, and a config has few enough keys that this costs little. The bounds catch
values that are clearly wrong (0 seconds, a thousand items per run) without guessing at
tuning, and a run that restores nothing must not be able to report `pass`. Environment
variables are the least code that keeps secrets out of the file until the vault exists.
The `%ProgramData%` variable can be changed by whoever starts the process; the known-folder
API returns the machine's real location. `config check` prints the URLs and the error
messages name keys, so anything the file controls that reaches the terminal is limited to
what can't be a secret or forge output: a password in a URL's userinfo or a token in its
query would be printed, a key name can be a 200 KB string, and a control character in a
value or key can fake or hide lines. The key-name rule limits length and characters only: a
pasted token that is itself a short identifier-like key is still echoed as an unknown key.
A mailbox address that merely looked like an email let a typo or a look-alike name a live
mailbox as the restore target. The CRT's narrow environment and `argv` are in the ANSI code
page, so a password or path with a character outside it was silently changed.

**Alternatives rejected.** Collecting every error in one pass: more code and more test
combinations, and later errors are often caused by the first. Ignoring unknown keys: typos
go unnoticed. Secrets in `config.json` protected by file ACLs: one careless copy of the file
leaks them, and W4.5 replaces the mechanism anyway. Reading `%ProgramData%` from the
environment variable: a process can override it. Accepting any address for `test_mailbox`
and leaving it all to `TargetGuard`: a mistake would only surface mid-run, as `error` on
every test. An `activeCodePage` UTF-8 manifest instead of the wide APIs: older Windows
Server releases ignore it, and `rptests.exe` would need the same manifest for the tests to
mean anything. Pulling in CLI11 now: a dependency for two
commands, before W1.6 has looked at what the rest of the CLI needs.

---

## 2026-09-24 — `rpworker`'s command line lives in rpcore; `worker/app/` is guarded and measured

**Decision.** Supersedes the part of the 2026-09-22 entry "Every rpcore `.cpp` must reach the
coverage report; `main()` lives outside `src/`" that left `main()` untested. Argument parsing,
output and exit codes live in `rp::run_cli(args, out, err)` in rpcore and are tested in
`rptests`; `worker/app/main.cpp` only turns argv into a list and calls it. `worker/app/` is
also Worker source for the "No test, no merge" guard and for the coverage gate, which measures
it through ctest's runs of `rpworker.exe` (OpenCppCoverage `--cover_children`). Those runs go
through `worker/tests/run_exe_test.cmake`, which checks the exit code, stdout and stderr
exactly.

**Reason.** A code review of W1.1 found that `main()` held the parsing, sat outside both the
guard and coverage, and was tested only by ctest properties that ignore the exit code
(`PASS_REGULAR_EXPRESSION`) or accept any non-zero one, a crash included (`WILL_FAIL`). The
next subcommands (`veeam list`, `restore`, `test`, `doctor`) would have landed in that
untested file. With the logic in rpcore, `main()` is four lines that one exe test runs in
full, so measuring it costs nothing and catches it if it grows.

**Alternatives rejected.** Keeping `app/` out of coverage and relying on review to keep
`main()` thin: the guard would still let a PR change it with no test. Linking `main()` into a
test executable: two `main`s in one binary, or preprocessor tricks to rename one. A future
Windows service entry point that tests can't run will get its own entry if it has to be
excluded.

---

## 2026-09-23 — `main` is not branch-protected; merging only on green is a manual rule

**Decision.** L0.1's "Protect main: require CI green before merge" is replaced by a manual
rule: a PR is merged only by the repo owner, and only when every check on it is green (worker,
cloud and the "No test, no merge" guard). The CI gates in `docs/testing.md` still run on every
PR; they turn the PR red but cannot block the merge button.

**Reason.** Branch protection and rulesets are not available on a free private repository
(the API returns 403, "Upgrade to GitHub Pro or make this repository public"). With one
developer who reviews and merges every PR, a manual rule costs nothing and keeps the code
private.

**Alternatives rejected.** GitHub Pro: enforces the checks, but is a monthly cost for a guard
that only protects the developer from themselves. Making the repository public: exposes the
code before there is a product. Revisit when a second person gets write access or the repo
moves to an organisation (L0.1), at which point required checks become worth paying for.

---

## 2026-09-23 — Test tenant on `onmicrosoft.com` with 4 licences; domain deferred to C5.12

**Decision.** The L0.3 test tenant is `RestoreProofLab.onmicrosoft.com`, on its default
domain, and needs **4 licences** instead of the guide's 3. No domain is bought in Sprint 0. It
is bought before C5.12 (Sprint 5), which needs `api.<domain>` and `app.<domain>`, and C7.1
(Sprint 7) then uses it as the verified alert sender. The tenant must stay licensed for all
16 weeks.

**What was actually bought (2026-09-23).** The sign-up gave a **Microsoft 365 Business
Standard EEA (no Teams)** trial on an annual term, not the Business Basic trial the guide
names. The trial has 25 licences and **ends on 2026-10-23, in Sprint 2**. It then converts to
paid with only **1** licence. Before that date the renewal must be changed to 4 licences,
preferably on monthly billing. Whether to stay on Standard or move to Business Basic ×4 is
still open; this entry gets a follow-up once it is decided. Business Basic covers everything
the lab uses (Exchange mailboxes, SharePoint, OneDrive). The global admin has a personal-name
UPN rather than `admin@`; it is the fourth licensed user L1.1 calls "admin".

**Reason.** The Worker, Veeam and Graph work the same on an `onmicrosoft.com` domain, so
Sprints 1–4 don't need a custom domain. Only the Cloud deployment and email alerts do, and the
week-4 go/no-go (S2.1) could make both unnecessary. The guide contradicts itself on licences:
L0.3 says 3 users, but L1.1 needs four licensed mailboxes (admin, alice, bob, `restoretest`,
the mail restore target). `rpoperator` (W1.0) needs no licence. The tenant must outlive the
30-day trial because Veeam backs it up, `lab/seed-manifest.json` describes its data and the
recorded fixtures point at it. If it expires, or converts with 1 licence, alice, bob and
`restoretest` lose their mailboxes and the tenant is later disabled and deleted.

**Alternatives rejected.** Buying the domain now and adding it to the tenant: costs money
before the go/no-go, and a custom domain can be added to the tenant later without changing the
`onmicrosoft.com` addresses the fixtures use. It is only worth buying early if the name itself
matters and might be taken. A tenant from the Microsoft 365 Developer Program: its E5 sandbox
is now limited to qualifying subscribers, and it can be removed at any time. Letting the trial
lapse and creating a fresh tenant each month: every tenant ID, site ID and fixture would change.

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
