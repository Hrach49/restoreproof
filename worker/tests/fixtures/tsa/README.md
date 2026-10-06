# TSA fixtures (W4.4)

Answers of an RFC 3161 timestamp authority, in the fixtures' own format
(`../veeam/README.md`) with the two keys a binary exchange has:

- `"body": null` and `"body_base64"`: the response's bytes, standard Base64;
- `"request_body_base64"`: the TimeStampReq that was sent. It holds a hash and a
  nonce and no secret.

`rpworker test --evidence <dir> --record <dir>` writes this format into the
recording's `tsa/` folder (`RecordedBody::base64`); `FakeHttpClient` decodes
`body_base64` on replay, and `rp::test::request_body_of` gives the request back.

| File | What | From |
|---|---|---|
| `digicert-granted.json` | a granted answer of DigiCert's public TSA with its token | recorded by hand on 2026-10-06 with `openssl ts -query` and curl, before `--record` knew the format |
| `digicert-w44-live.json` | the W4.4 live Done-when run's own exchange with DigiCert's TSA (run `w44-done-when-1`, 2026-10-06): the query holds the SHA-256 of that run's `result.json` and a nonce | `rpworker test --evidence --record`, its `tsa/001-post-root.json` as written |
| `rejection.json` | PKIStatus 2, no token: `30 05 30 03 02 01 02` | hand-written |
| `html-200.json` | a maintenance page with status 200 | hand-written |
| `503.json` | 503 | hand-written |
| `empty-200.json` | 200 and no body | hand-written |

A test that replays `digicert-granted.json` takes the nonce and the digest out
of the recorded request, so the recorded answer is the right one for the
request the Timestamper sends. The token verifies for good: its chain is checked
at the token's own time, never at "now", against `shared/tsa/tsa-ca.pem`.
