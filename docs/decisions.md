# Decision log

One entry per architectural choice. Newest first. Add an entry whenever a new choice is
made; never rewrite an old one — supersede it with a new entry that links back.

Format: date, decision, reason, alternatives rejected.

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
2. **Without `--hash`, nothing is downloaded**: `TargetReaderOptions::hash_files` (default
   `true`, W2.2's behaviour). When it is `false`, the file listings skip `/content` and the
   download client entirely; a file's `sha256` and `sha256_rule` stay empty (documented on
   `FoundItem`, not an `optional`, so W2.2's callers are untouched) and `size_bytes` is Graph's
   `size`; `on_file` is never called. The guards run the same either way. Mail is still hashed
   (its body comes in the listing, so it costs nothing), but the command shows hashes only with
   `--hash`, so every table has the same columns for a given command line.
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
(veeam-notes §6). `logout()` holds the lock while it sends, so a hanging logout delays
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
