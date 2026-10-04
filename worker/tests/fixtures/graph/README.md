# Graph and Entra fixtures

Recorded replies from Microsoft Entra's token endpoint and Microsoft Graph, served by
`FakeHttpClient` in the GraphClient tests (`worker/tests/graph_client_test.cpp`, W2.1 and
later). The live ones were recorded on 2026-09-28 against the lab tenant by
`uv run python -m seeder record-graph-fixtures` (`lab/README.md`), signed in as the
"RestoreProof Worker" app the way the Worker does: PS256, header `x5t#S256`. The rest are
hand-written, for replies the lab can't provoke; their `source` says so.

## Format

One JSON object per file, as in `../veeam/README.md`:

```json
{
  "source": "live 2026-09-28: token request, PS256 header ['x5t#S256']",
  "request": "POST /bcd6bd1a-ea42-489d-aa28-2c19a44ad146/oauth2/v2.0/token",
  "status": 200,
  "headers": { "Content-Type": "application/json; charset=utf-8", "x-ms-request-id": "..." },
  "body": { "...": "the recorded response body" }
}
```

- `source`: `live <date>: <what was sent>`, or `hand-written: <what it stands for and why>`.
- `request`: method and path (with query string) of the call. Documentation only: tests
  route by the URL they build themselves.
- `status`: the HTTP status.
- `headers`: only `Content-Type`, `WWW-Authenticate`, `Retry-After`, `Location`,
  `request-id`, `client-request-id` and `x-ms-request-id`, when the reply had them. The
  request IDs are what `GraphError::request_id()` reports.
- `body`: `null` means an empty body. A string is raw text. An object or array is JSON; the
  fake sends it compactly serialised.

No secret is kept. The token reply's `access_token` is a fake unsigned JWT
(`eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzY3J1YmJlZCI6dHJ1ZX0.`); tests put their own token
in its place. No file holds a client assertion or anything JWT-shaped beyond that: the
recorder refuses to write one, and `lab/tests/test_graph_fixtures.py` checks every file here
the same way, hand-written ones included. Tenant and app IDs, UPNs, request and trace IDs are
real lab values.

## The restore-target states (W2.2)

The `TargetReader` tests (`graph_targets_test.cpp`, `graph_download_test.cpp`) replay the three
restore targets in three states, recorded with `record-graph-fixtures --state
empty|one-item|paged` (`lab/README.md`, "The restore-target states"): `empty` after L1.4's
cleanup, `one-item` with one mail and one file in each file target, `paged` with two mails and
`$top=1`. Until a state is recorded, its files are hand-written **stand-ins** under the same
names, shaped as the recorder writes them; their `source` starts `hand-written: stand-in until
the <state> state is recorded (W2.2)`, the lab's plan test skips them, and a lab test keeps the
table below and the files here in step. Recording a state overwrites its stand-ins; switch their
rows to `live: …`. `onedrive-folder-403-accessdenied.json` stays hand-written: SharePoint
answers 404 for an item the app may not read, so the lab can't provoke that 403 read-only.

- **Request lines** are documentation. IDs a reply gave are written as placeholders
  (`<message id>`, `<item id>`, `<@odata.nextLink of mail-list-200-page1.json>`, …), and the
  not-found cases' random IDs as `<random item ID>` and `<random drive ID>`. No canary ID
  appears in any file here, nor anywhere under `worker/`.
- **Download links are scrubbed.** A `/content` 302's `Location` carries a pre-authenticated
  `tempauth` credential. The recorder never follows it, keeps the scheme, host, path and the
  values of `UniqueId`, `Translate` and `ApiVersion`, and writes every other query value as
  `SCRUBBED`; `@microsoft.graph.downloadUrl` is dropped from bodies. The tests serve the
  download from a second fake client and put their own sentinel in the link, which the
  sentinel test then looks for in the logs.
- **W3.2's fields are not in the replies yet.** W3.2 widened the two `$select`s (mail:
  `sentDateTime` and `createdDateTime`; files: `cTag`, `createdDateTime` and
  `lastModifiedDateTime`) and the request lines of the `mail-list-*` and `*-children-*` files
  were changed with them, to keep `lab`'s request-line check in step, but their bodies are
  still the 2026-09-28 recordings without those fields, until the states are recorded again.
  The tests read the new fields from a reply when it has them and put them into edited copies
  where they need them; nothing here was given a field by hand.
- **Tests read lab values from the files**, never spell them: a re-recording changes request
  IDs, and the scan in `graph_client_test.cpp` fails on any recorded GUID a test source spells
  other than its `stable` ones.

## Files

| Fixture | Source | For |
|---|---|---|
| `token-200.json` | live: a token request | the token reply: `token_type` Bearer, `expires_in` 3599 |
| `token-bad-signature-401.json` | live: an assertion signed by a key Entra doesn't know | 401 `invalid_client` AADSTS700027 → `AuthError`, the certificate hint, not retried |
| `token-unknown-thumbprint-401.json` | live: an `x5t#S256` of no uploaded certificate | 401 `invalid_client` AADSTS700027 → `AuthError`, the certificate hint |
| `token-unknown-app-400.json` | live: a client ID of no app | 400 `unauthorized_client` AADSTS700016 → `AuthError`, "check graph_client_id and graph_tenant_id" |
| `token-unknown-tenant-400.json` | live: a tenant ID of no tenant | 400 `invalid_request` AADSTS90002 → `AuthError`, "check graph_tenant_id" |
| `token-expired-assertion-401.json` | live: an assertion that expired an hour ago | 401 `invalid_client` AADSTS700024 → `AuthError`, the clock hint |
| `token-future-assertion-401.json` | live: an assertion valid only from an hour ahead | 401 `invalid_client` AADSTS700024 → `AuthError`, the clock hint |
| `token-429-retry-after.json` | hand-written: Entra throttling, as documented (empty body, `Retry-After: 60`) | 429 → `TransientError`, retried after the Retry-After |
| `token-503-temporarily-unavailable.json` | hand-written: Entra's reply shape with the transient AADSTS90033 | 503 `temporarily_unavailable` → `TransientError`, retried |
| `token-500-html.json` | hand-written: a proxy's HTML error page | a 5xx that isn't JSON → `TransientError`; the body is never quoted |
| `token-302-redirect.json` | hand-written: a redirect from the token endpoint | 3xx → `GraphError`, nothing sent to its `Location` |
| `messages-200.json` | live: the restoretest inbox, `$top=1&$select=id` | a GET that works (`value: []`): `get()`, `get_json()`, the token's reuse and renewal |
| `messages-403-exchange.json` | live: alice's inbox, outside the Exchange RBAC scope | 403 `ErrorAccessDenied` → `PermissionError` naming the Mail grant; no innerError: the request ID comes from the headers |
| `messages-404-unknown-user.json` | live: the inbox of a user who doesn't exist | 404 `ErrorInvalidUser` → `NotFoundError` |
| `site-403-accessdenied.json` | live: the tenant root site, no Sites.Selected grant on it | 403 `accessDenied` → `PermissionError` naming the Sites grant; innerError: the request ID comes from the body |
| `users-403-requestdenied.json` | live: `GET /users`, no directory role | 403 `Authorization_RequestDenied` → `PermissionError` naming the grant |
| `api-invalid-token-401.json` | live: a GET with a malformed bearer token | 401 `InvalidAuthenticationToken` with WWW-Authenticate → one new token, then `AuthError` |
| `api-no-token-401.json` | live: a GET without Authorization | 401 `InvalidAuthenticationToken` with WWW-Authenticate → one new token, then `AuthError` |
| `api-insufficient-claims-401.json` | hand-written: a claims challenge (`error="insufficient_claims"` in WWW-Authenticate), as Conditional Access or continuous access evaluation sends it | 401 → `AuthError` at once, no new token |
| `messages-404-mailbox-not-enabled.json` | hand-written: `MailboxNotEnabledForRESTAPI`, what Graph says for a mailbox without an Exchange Online licence, inactive or on-premises | 404 → a plain `GraphError`, not `NotFoundError` |
| `messages-429-throttled.json` | hand-written: Graph throttling a mailbox (`ApplicationThrottled`, `Retry-After: 3`) | 429 → retried after the Retry-After, then `TransientError` |
| `messages-503-unavailable.json` | hand-written: Graph briefly unavailable (`serviceNotAvailable`, `Retry-After: 10`) | 503 → retried after the Retry-After, then `TransientError` |
| `onedrive-folder-403-accessdenied.json` | hand-written: a 403 on the OneDrive folder in the recorded `site-403-accessdenied.json` shape; SharePoint masks an ungranted item as 404 (L1.5), so the lab can't provoke one read-only | 403 `accessDenied` → `PermissionError` naming the OneDrive grant (W2.2) |
| `mail-list-200-empty.json` | live: the restoretest inbox as the Worker lists it, empty; request line widened for W3.2, body still the 2026-09-28 recording | an empty Inbox lists as an empty vector; the tests read the mailbox from its request line (W2.2) |
| `mail-list-200-one-item.json` | live: the restoretest inbox as the Worker lists it, one mail, its body as text (`Prefer`); request line widened for W3.2, body still the 2026-09-28 recording | one mail lists as one `FoundItem` (subject, sender, received, internetMessageId and the text-v1 hash of `body.content` read from it); its edits are the not-text refusals (W2.2) |
| `mail-list-200-page1.json` | live: the restoretest inbox with `$top=1`, two mails: page 1, with `@odata.nextLink`; request line widened for W3.2, body still the 2026-09-28 recording | mail follows `@odata.nextLink`; the link's shape is what the Inbox's nextLink rule must take (W2.2 review) |
| `mail-list-200-page2.json` | live: page 1's `@odata.nextLink`: the second mail, and a link again, since Exchange links every full page | the second page (W2.2) |
| `mail-list-200-page3.json` | live: page 2's `@odata.nextLink`: empty, no link | the last page is an empty one: the listing ends on it with two mails (W2.2) |
| `restoretarget-drive-200.json` | live: the RestoreTarget library's drive, as the guard reads it | the SharePoint guard: name, `webUrl`, `driveType` and `sharePointIds` of the RestoreTarget library; its edits are the refusals (W2.2) |
| `restoretarget-root-200-one-child.json` | live 2026-10-04 (Q3.2 scenario 6, the app's SharePoint roles revoked): `GET /drives/{RestoreTarget}/root?$select=id,folder` while the library held one restored file | 200, `folder.childCount` 1: the count a listing is held to; the tests edit the count |
| `restoretarget-children-200-trimmed.json` | live, the same moment: the library's listing, 200 and empty although the root counted one child (SharePoint's security trimming) | fewer entries than the root's count → `PermissionError` naming the grant, `graph_permission`, never an empty target (Q3.2) |
| `restoretarget-children-200-empty.json` | live: the RestoreTarget library's root children, empty; request line widened for W3.2, body still the 2026-09-28 recording | an empty library lists as an empty vector (W2.2) |
| `restoretarget-children-200-one-item.json` | live: the RestoreTarget library's root children, one file; request line widened for W3.2, body still the 2026-09-28 recording | one file lists as one `FoundItem` (name, size and the bytes' SHA-256); its edits are the bad-driveItem, folder and package rows (W2.2) |
| `onedrive-folder-200.json` | live: alice's OneDrive `/RestoreTarget` folder, as the guard reads it | the OneDrive guard: name, folder facet, `parentReference.driveId`, `.driveType`, `.path` and `.siteId`, and `sharepointIds` (`$select` has it since W2.7: `.siteUrl` is the OneDrive a restore names); its edits are the refusals (W2.2) |
| `mailbox-inbox-200.json` | live: the restoretest Inbox folder, as the guard reads it | the mailbox guard (W2.7): a 200 means the Worker app's Exchange RBAC scope, restoretest's alone, covers the address |
| `mailbox-inbox-403-exchange.json` | live: alice's Inbox folder, outside the Exchange RBAC scope | 403 `ErrorAccessDenied`: the guard refuses the address as not the test mailbox (W2.7) |
| `onedrive-children-200-empty.json` | live: the children of alice's `/RestoreTarget`, empty; request line widened for W3.2, body still the 2026-09-28 recording | an empty folder lists as an empty vector (W2.2) |
| `onedrive-children-200-one-item.json` | live: the children of alice's `/RestoreTarget`, one file; request line widened for W3.2, body still the 2026-09-28 recording | one file lists as one `FoundItem`, downloaded from the `-my` host (W2.2) |
| `drive-404-itemnotfound.json` | live: a drive ID of no drive | 404 `itemNotFound` on the drive → `NotFoundError`, never an empty listing (W2.2) |
| `onedrive-folder-404-itemnotfound.json` | live: an item ID of no item in alice's OneDrive | 404 `itemNotFound` → `NotFoundError` (W2.2) |
| `restoretarget-content-302.json` | live: a file's `/content` in the RestoreTarget library, redirect not followed, `Location` scrubbed | 302 → the download follows `Location` without the token (W2.2) |
| `onedrive-content-302.json` | live: a file's `/content` in alice's `/RestoreTarget`, redirect not followed, `Location` scrubbed | 302 on the `-my` host → the download follows `Location` without the token (W2.2) |
| `w34-mail-permanentdelete-404-erroritemnotfound.json` | hand-written, in the shape of `messages-404-unknown-user.json`: Exchange's 404 for a message no longer there. **Never seen live**: a repeated `permanentDelete` answers 403 `ErrorCannotDeleteObject` instead (next row). Kept for a message someone else deleted between the Cleaner's listing and its `permanentDelete`, and as a 404 of the message GET that follows that 403 (below), though live that GET answered 200 | 404 `ErrorItemNotFound` → `gone`, on the `permanentDelete` or on the message GET after a 403 `ErrorCannotDeleteObject`, with no Inbox GET (W3.4, build notes point 15) |
| `w34-mail-permanentdelete-403-cannotdeleteobject-repeat.json` | live: the live cleaner test of 2026-10-02 (`rp-w34-rec-cleaner-20261002T204648`, `graph/004`), unedited but its `source`: the second of two `permanentDelete`s of one seeded draft, the first already answered 204 | 403 `ErrorCannotDeleteObject` on a mail → one check, is the message gone: its `parentFolderId`, then the Purges folder's `id`, then the Inbox's; 404 or Purges, byte for byte → `gone`, the Inbox → `PermissionError` naming the mail grant, another folder, anything unreadable or any other error an error, never `gone`; for a file a plain `PermissionError` (W3.4, build notes point 15) |
| `w34-mail-get-200-purged-parentfolder.json` | hand-shaped from live answers: the live cleaner test of 2026-10-02 21:05 (`rp-w34-rec-cleaner-20261002T210555`, `graph/005`: the message GET after the repeated `permanentDelete`'s 403 answered **200**, though the final Inbox listing was empty) and read-only probes after it (`$select=id,parentFolderId,subject`, ImmutableId: 200). Request, ID and eTag are `graph/005`'s; the `parentFolderId` is exact, from the read-only probe of 2026-10-02: byte for byte the Purges folder's `id` (next row), not the Inbox's `...AAAAAAEMAAA=` | 200 with the Purges folder's ID as `parentFolderId`: the purged message → `gone` (W3.4, build notes point 15); the tests edit its `parentFolderId` for the Inbox's ID, another folder's, one differing in case only, a missing, empty or non-string one |
| `w34-mail-purges-200-id.json` | live read-only probe, 2026-10-02: `GET /users/{restoretest}/mailFolders/recoverableitemspurges?$select=id,displayName`, ImmutableId: 200, `displayName` `Purges`; shaped like `mailbox-inbox-200.json` (request narrowed to `$select=id`, `displayName` and request IDs left out), the `id` exact | the Purges folder's `id` the purged message's `parentFolderId` must equal, byte for byte, to count `gone` (W3.4, build notes point 15); the tests edit it for a missing, empty, non-string `id` or a non-JSON reply (an error, never `gone`) |
| `w34-mail-permanentdelete-403-exchange.json` | hand-written, in the shape of `mailbox-inbox-403-exchange.json`: a `permanentDelete` while the Exchange role is still read-only; the lab, granted, can't be refused (below) | 403 → `PermissionError` naming the mail grant; the mail target ends `graph_permission` (W3.4) |
| `w34-file-delete-404-itemnotfound.json` | live: the live cleaner test of 2026-10-02 (`rp-w34-rec-cleaner-20261002T204648`, `graph/007`), unedited but its `source`: the second of two `DELETE`s of one seeded file in the RestoreTarget library, the first already answered 204; replaced the hand-written stand-in | 404 `itemNotFound` → `gone`; a resent `DELETE` answered so too; also SharePoint's code on the message GET after a mail's 403 `ErrorCannotDeleteObject` (W3.4) |
| `w34-file-delete-412-resourcemodified.json` | hand-written, in the shape of `drive-404-itemnotfound.json`: a `DELETE` whose `If-Match` no longer matches; no live run has met one (below) | 412 → `changed`: the next round lists the file again (W3.4) |
| `w34-file-delete-403-accessdenied.json` | hand-written, in the shape of `onedrive-folder-403-accessdenied.json`: a `DELETE` without the write grant; the lab, granted, can't be refused (below) | 403 → `PermissionError` naming the list or folder write grant (W3.4) |

## The Cleaner's fixtures (W3.4): recorded and hand-written

The Cleaner's listings and 204s are **recorded**, from the W3.4 live run of 2026-10-02
(`rpworker restore --record`, run `rp-20261002T180310Z-6661beff`;
`../recordings/w34-live-run1/README.md`). `cleaner_test.cpp` and `restore_command_test.cpp`
load them from there, unedited, in place of the hand-written stand-ins they replaced
(`w34-mail-list-200-two.json`, `w34-restoretarget-children-200-two.json`,
`w34-onedrive-children-200-two.json`, `w34-mail-permanentdelete-204.json`,
`w34-file-delete-204.json`, removed):

| Recording file (`../recordings/w34-live-run1/graph/`) | What it is | For |
|---|---|---|
| `034-get-...-mailf.json` | the clean after's first listing of the restoretest Inbox (`$select=id`, `Prefer`): the run's 5 mails | the Cleaner's mail listing; its edits are the bad-ID rows |
| `042-get-...-7ncroj5omdbu.json` | the clean after's first listing of the RestoreTarget library's root (`eTag`, facets, `parentReference`): the run's 3 files | the Cleaner's library listing; its edits are the place, facet, ID and eTag rows |
| `048-get-...-z5getdherm5pj6bmwyxfzj.json` | the clean after's first listing of alice's `/RestoreTarget`: the run's 3 files | the Cleaner's OneDrive listing, as the library's |
| `035-post-...-messa.json` | the first mail's bodiless `permanentDelete`, 204 | `RemoveOutcome::removed` for a mail |
| `043-delete-...-7ncroj5omdbu.json` | the first library file's `DELETE` with `If-Match`, 204 | `RemoveOutcome::removed` for a file (OneDrive's 204, `049`, is the same reply) |

Two `w34-*` files here are **recorded** by the live cleanup test of 2026-10-02
(`cleaner_live_test.cpp` with `RP_LIVE_RECORD_DIR`; console output
`docs/api/veeam-lab/w3.4-live-1-cleaner-test.txt`), which sends the Cleaner's first file
`DELETE` and first mail `permanentDelete` twice: `w34-file-delete-404-itemnotfound.json`
(`graph/007`, the second `DELETE`'s 404) and
`w34-mail-permanentdelete-403-cannotdeleteobject-repeat.json` (`graph/004`, the second
`permanentDelete`'s 403). The recording holds only the second answer of each doubled send (the
test's wrapper sits inside the recorder). That run is how the 403 was found: Exchange answers
a repeated `permanentDelete` of a purged message 403 `ErrorCannotDeleteObject`, not 404, so
`GraphClient::remove` now checks such a 403: is the message gone
(`docs/decisions.md`, 2026-10-02 W3.4 build notes, point 15). A rerun at 21:05
(`rp-w34-rec-cleaner-20261002T210555`) showed the purged message still answers a GET by its ID
(200), from Recoverable Items: hence the check compares its `parentFolderId`, byte for byte,
with the `id` of the mailbox's `recoverableitemspurges` folder (`gone` only on that match), then
with the Inbox's (the 403 stands), any other folder an error
(`w34-mail-get-200-purged-parentfolder.json`, hand-shaped from that run with its
`parentFolderId` exact from a read-only probe; `w34-mail-purges-200-id.json`, that probe's
Purges folder; the Inbox's ID is `mailbox-inbox-200.json`'s, the same as that run's
`graph/002`). An earlier rule, `gone` whenever the folder wasn't the Inbox, failed open and was
replaced. The rest of that recording (the
token, the guard's checks, the listings) adds nothing the W3.4 restore run's recording doesn't
have, so it isn't committed.

The other `w34-*` files stay **hand-written**, because no live run has given those answers:
the refusing 403s can't be provoked while the lab holds the W3.4 write grants (every live
delete was allowed); Exchange's 404 `ErrorItemNotFound` was never seen (a repeated
`permanentDelete` gets the 403 above) and stays for a message deleted by someone else between
the listing and the delete, for a 404 of the message GET after that 403, and for a 404 of the Purges folder GET (an error); and a 412 needs a file changed
between its listing and its `DELETE`, which no live run has met. Each one's `source` says so.

Entra's refusals that the lab can't provoke (Conditional Access, a disabled app, the other
transient codes) are built in `graph_client_test.cpp` from `entra_error()`, in the recorded
shape, rather than kept as files.

Graph replies that only vary a recorded one (another status, Retry-After or WWW-Authenticate
value, a redirect, a body that isn't JSON, a page with `@odata.nextLink`) are built in the
test from `make_response()` or an edited fixture, rather than kept as files.
