# Client profile fixtures

Hand-written `restoreproof.client-profile.v1` files for the `rpworker client check` exe
tests (W4.10, `worker/CMakeLists.txt`): `valid.json` is the shared vector
`shared/testdata/client-profile-v1/valid.json` (made-up names, no lab value, no secret),
`alice-mailbox.json` names another mailbox (refused: `key "test_mailbox" ...`) and
`missing-site.json` has no `test_site_id` (refused: `key "test_site_id" is missing`).
