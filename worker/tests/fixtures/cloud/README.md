# The Cloud's answers (W5.1)

Recorded once from the local Compose stack through its HTTPS front (Caddy,
`https://localhost:8443`) by `docs/api/cloud-lab/w5.1-record/record_cloud.py`
(docs/decisions.md 2026-10-15, "W5.1 (#66)", point 10), in the recorder's
format: the request line, the status, the kept headers as the wire spelled them
(Caddy hands the contract header on as `X-Restoreproof-Api`), the body. Every
token is `SCRUBBED`; a test that needs one puts its own in its place. The ids
are the shared vector `shared/testdata/signing-v1/dispatched-run.json`'s and
the Cloud's own; the key is RFC 8032's test key 1, never a secret.

- `register/`: 201, 400 (a key that is none), 401 (an unknown and a used
  install token), 409 (the key registered already), 422 (a body without its keys).
- `jobs/`: 200 with the vector's job, with a canary plan's `canary_cursor`, and
  with none; 401; 502 (Caddy's own, the api stopped: no contract header).
- `results/`: 202 and 202 again, 400 (a signature that fails), 401, 409 (`run_id:
  not dispatched`), 415, 502 (Caddy's own).
- `heartbeat/`: 204, 401, 422. `version/`: 200.
