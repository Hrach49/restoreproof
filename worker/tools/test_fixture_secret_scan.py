"""Tests for fixture_secret_scan.py (W4.9). Stdlib only:

    python -m unittest discover -s worker/tools -p "test_*.py"

Failures first: every shape planted in a temp tree is reported; an allowed
value passes only in its file and only exactly; a stale allowlist entry fails.
The last test runs the scan over this repository's own trees with the
committed allowlist, which is what ctest and CI run.
"""

import io
import json
import tempfile
import unittest
from pathlib import Path

import fixture_secret_scan as scan

REPO = Path(__file__).resolve().parents[2]

# RFC 8032's test key 1 as PKCS#8 Base64: published, never a secret.
RFC_KEY_1 = "MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g"
PLACEHOLDER_JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzY3J1YmJlZCI6dHJ1ZX0."

# One text per shape that must be found, as a (shape, text) pair.
PLANTED = [
    ("jwt", "token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij"),
    ("jwt", "a token without dots eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0 here"),
    ("bearer", "Authorization: Bearer AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"),
    ("bearer", "Bearer   dGhpcyBpcyBhIHRva2VuIHRoYXQgaXM=="),
    ("pem_private_key", "-----BEGIN PRIVATE KEY-----\nMC4C\n-----END PRIVATE KEY-----"),
    ("pem_private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"),
    ("pem_private_key", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF"),
    ("pem_private_key", "-----BEGIN EC PRIVATE KEY-----"),
    ("ed25519_pkcs8", RFC_KEY_1),
    ("rsa_pkcs8", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC"),
    ("rsa_pkcs8", "MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQD"),
    ("rsa_pkcs1", "MIIEpAIBAAKCAQEAx4UbaDzY5xjW6hc9jwO0BkK3gUkTjqWXMd"),
    ("ec_pkcs8", "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg"),
    ("ec_sec1", "MHcCAQEEIFZyB1234567890abcdefghijklmnopqrstuvwxyzAB"),
    ("ec_sec1", "MIGkAgEBBDAabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"),
    ("pkcs12", "MIIKsQIBAzCCCncGCSqGSIb3DQEHAaCCCmgEggpkMIIKYDCCBh"),
    ("pkcs12", "MIMBAgQCAQMwggQAAgEDMIIEGAYJKoZIhvcNAQcBoIIECQSCBAUw"),
    ("keyed_secret", '"access_token": "AQABAAAAAAD-3b7f-very-real-looking"'),
    ("keyed_secret", "grant_type=password&username=x&password=hunter2hunter2&client_id=y"),
    ("keyed_secret", '"applicationCertificatePassword": "P@ssw0rd!"'),
    ("keyed_secret", '"Password": "upper-case-key-counts"'),
    ("keyed_secret", "client_assertion=eyJ"),
    ("keyed_secret", '"signing_key_base64": "x"'),
    ("keyed_secret", '"pfx_base64": "MIIK"'),
]

# Texts no shape may match.
CLEAN = [
    "a certificate MIIBmTCCAT6gAwIBAgIBATAKBggqhkjOPQQDAjBCMUAwPgYDVQQD is public",
    "a TimeStampResp MIIXczADAgEAMIIXagYJKoZIhvcNAQcCoIIXWzCCF1cCAQMxDTALBglghkgBZQMEAgEw",
    "a request MEQCAQEwMTANBglghkgBZQMEAgEFAAQglZJ85mJS",
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----",
    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
    'WWW-Authenticate: Bearer error="invalid_token", error_description="The token expired"',
    'WWW-Authenticate: Bearer realm="https://login.microsoftonline.com/"',
    'Bearer [REDACTED]"invalid_token"',
    "Authorization: Bearer [REDACTED]",
    "Bearer short",
    '"access_token": "[REDACTED]"',
    '"refresh_token": ""',
    '"password": null',
    '"applicationCertificate": "<Base64 PFX>"',
    '"applicationCertificatePassword": "…"',
    '"applicationCertificate": "[not exported yet]"',
    "grant_type=password&username=rp-veeam&password=[REDACTED]",
    "tempauth=SCRUBBED&x=1",
    "password = $pw; refresh_token = (Get-VeeamRefreshToken)",  # a script's variable, a call
    "password_hash=abc",  # the key is password_hash, not password
    "xpassword=abc",
    "a hash 9fb19e0e604c9be49f83d8e508efa8ea0986a952377c783e5035cea2d772a213 is no shape",
    "a signature sTOWRl9yH1gX4Ugf5m1z2k5HS9lVt1gOGoXwdWmiXCg5Nq9S5c0YCe+N3xMuMrx1dS/CZ5lP3zkTvY+9dK8eDw==",
    "base64url run into a jwt start: AAeyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIn0",
    "a short tail eyJhbGciOiJSUzI1NiJ9.e30.",
    PLACEHOLDER_JWT,  # is a shape; it passes only through the allowlist (tested below)
]
CLEAN_SHAPED = {PLACEHOLDER_JWT}


class Tree:
    """A temp repository root with a tree to scan and an allowlist."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "fixtures").mkdir()

    def close(self):
        self.tmp.cleanup()

    def write(self, rel, text, encoding="utf-8"):
        file = self.root / rel
        file.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            file.write_bytes(text)
        else:
            file.write_text(text, encoding=encoding, newline="\n")
        return file

    def allowlist(self, entries):
        return scan.Allowlist.from_json({"entries": entries})

    def run(self, entries=(), trees=("fixtures",)):
        return scan.scan_trees(self.root, list(trees), self.allowlist(list(entries)))


class ShapeTests(unittest.TestCase):
    def test_every_planted_text_is_found_as_its_shape(self):
        for shape, text in PLANTED:
            with self.subTest(shape=shape, text=text[:24]):
                found = {f.shape for f in scan.find_shapes(text)}
                self.assertIn(shape, found)

    def test_clean_texts_match_no_shape(self):
        for text in CLEAN:
            if text in CLEAN_SHAPED:
                continue
            with self.subTest(text=text[:40]):
                self.assertEqual([], scan.find_shapes(text))

    def test_a_finding_carries_the_value_for_the_allowlist_only(self):
        found = scan.find_shapes("x " + RFC_KEY_1 + " y")
        self.assertEqual(1, len(found))
        self.assertEqual(RFC_KEY_1, found[0].value)
        self.assertEqual("ed25519_pkcs8", found[0].shape)

    def test_shape_names_are_the_documented_ones(self):
        self.assertEqual(
            ["jwt", "bearer", "pem_private_key", "ed25519_pkcs8", "rsa_pkcs8", "rsa_pkcs1",
             "ec_pkcs8", "ec_sec1", "pkcs12", "keyed_secret"],
            list(scan.SHAPES),
        )


class TreeTests(unittest.TestCase):
    def setUp(self):
        self.tree = Tree()
        self.addCleanup(self.tree.close)

    def test_a_planted_shape_in_the_tree_is_reported_with_its_line_and_no_value(self):
        self.tree.write("fixtures/a.json", '{"a": 1,\n "b": "' + RFC_KEY_1 + '"}\n')
        result = self.tree.run()
        self.assertEqual(1, len(result.findings))
        finding = result.findings[0]
        self.assertEqual("fixtures/a.json", finding.path)
        self.assertEqual(2, finding.line)
        self.assertEqual("ed25519_pkcs8", finding.shape)
        text = finding.text()
        self.assertNotIn(RFC_KEY_1, text)
        self.assertNotIn(RFC_KEY_1[21:30], text)
        self.assertIn("fixtures/a.json:2: ed25519_pkcs8", text)

    def test_a_clean_tree_has_no_findings(self):
        self.tree.write("fixtures/a.json", json.dumps({"access_token": "[REDACTED]"}))
        self.tree.write("fixtures/b.txt", "\n".join(t for t in CLEAN if t not in CLEAN_SHAPED))
        result = self.tree.run()
        self.assertEqual([], result.findings)
        self.assertEqual(2, result.files)

    def test_every_file_is_read_whatever_its_name_and_encoding(self):
        self.tree.write("fixtures/no-extension", "Bearer AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
        self.tree.write("fixtures/latin1.txt", ("caf\xe9 " + RFC_KEY_1).encode("latin-1"))
        self.tree.write("fixtures/utf16.txt", ("x " + RFC_KEY_1).encode("utf-16"))
        self.tree.write("fixtures/binary.bin", b"\x00\xff" + RFC_KEY_1.encode() + b"\x00")
        result = self.tree.run()
        self.assertEqual(
            {"fixtures/no-extension", "fixtures/latin1.txt", "fixtures/binary.bin"},
            {f.path for f in result.findings},
        )
        # UTF-16 isn't decoded (no committed data file is); it is still read.
        self.assertEqual(4, result.files)

    def test_venv_pycache_build_and_git_are_not_entered(self):
        for folder in (".venv", "__pycache__", "build", ".git"):
            self.tree.write(f"fixtures/{folder}/x.txt", RFC_KEY_1)
        self.tree.write("fixtures/kept/x.txt", RFC_KEY_1)
        result = self.tree.run()
        self.assertEqual(["fixtures/kept/x.txt"], [f.path for f in result.findings])

    def test_a_tree_may_be_one_file(self):
        self.tree.write("one.json", RFC_KEY_1)
        result = self.tree.run(trees=("one.json",))
        self.assertEqual(["one.json"], [f.path for f in result.findings])

    def test_a_tree_that_is_not_there_is_an_error(self):
        result = self.tree.run(trees=("nowhere",))
        self.assertEqual(["nowhere"], result.missing_trees)
        self.assertFalse(result.ok())


class AllowlistTests(unittest.TestCase):
    def setUp(self):
        self.tree = Tree()
        self.addCleanup(self.tree.close)
        self.tree.write("fixtures/keys.json", json.dumps({"key": RFC_KEY_1}))

    def entry(self, **changes):
        entry = {
            "path": "fixtures/keys.json",
            "shape": "ed25519_pkcs8",
            "reason": "RFC 8032's test key 1",
            "values": [RFC_KEY_1],
        }
        entry.update(changes)
        return entry

    def test_an_allowed_value_in_its_file_passes(self):
        result = self.tree.run([self.entry()])
        self.assertEqual([], result.findings)
        self.assertTrue(result.ok())
        self.assertEqual(1, result.allowed)

    def test_the_same_value_in_another_file_fails(self):
        self.tree.write("fixtures/other.json", RFC_KEY_1)
        result = self.tree.run([self.entry()])
        self.assertEqual(["fixtures/other.json"], [f.path for f in result.findings])

    def test_a_value_that_is_almost_the_allowed_one_fails(self):
        almost = RFC_KEY_1[:-4] + "AAAA"
        self.tree.write("fixtures/keys.json", json.dumps({"key": almost}))
        result = self.tree.run([self.entry()])
        self.assertEqual(1, len(result.findings))

    def test_an_allowed_value_of_another_shape_fails(self):
        result = self.tree.run([self.entry(shape="jwt")])
        self.assertEqual(1, len(result.findings))

    def test_a_prefix_entry_allows_every_text_that_starts_with_it(self):
        self.tree.write("fixtures/cases.json", "eyJhdHRhY2htZW50cyI6W3sibmFtZSI6Iml0ZW1zLmNzdiIsInNoYTI1NiI6Ij")
        result = self.tree.run([
            self.entry(),
            {"path": "fixtures/cases.json", "shape": "jwt", "reason": "Base64 of a result",
             "prefixes": ["eyJhdHRhY2htZW50cyI6"]},
        ])
        self.assertEqual([], result.findings)

    def test_an_entry_needs_values_or_prefixes_and_a_reason(self):
        for bad in (self.entry(values=None), self.entry(values=[]), self.entry(reason="")):
            bad = {k: v for k, v in bad.items() if v is not None}
            with self.subTest(bad=bad):
                with self.assertRaises(scan.AllowlistError):
                    self.tree.allowlist([bad])
        with self.assertRaises(scan.AllowlistError):
            self.tree.allowlist([self.entry(shape="not-a-shape")])
        with self.assertRaises(scan.AllowlistError):
            self.tree.allowlist([{**self.entry(), "extra": 1}])

    def test_a_stale_entry_fails_the_scan(self):
        gone = self.entry(path="fixtures/gone.json")
        unmatched = self.entry(values=[RFC_KEY_1[:-4] + "AAAA"])
        result = self.tree.run([self.entry(), gone, unmatched])
        self.assertEqual([], result.findings)
        self.assertEqual(2, len(result.stale))
        self.assertFalse(result.ok())
        text = "\n".join(s.text() for s in result.stale)
        self.assertIn("fixtures/gone.json", text)
        self.assertNotIn(RFC_KEY_1[:20], text)

    def test_the_placeholder_jwt_passes_only_where_allowed(self):
        self.tree.write("fixtures/token.json", json.dumps({"access_token": PLACEHOLDER_JWT}))
        # Under its key it is two shapes, a JWT and a keyed secret's value.
        refused = self.tree.run([self.entry()])
        self.assertEqual([("fixtures/token.json", "jwt"), ("fixtures/token.json", "keyed_secret")],
                         sorted((f.path, f.shape) for f in refused.findings))
        one_shape = self.tree.run([
            self.entry(),
            {"path": "fixtures/token.json", "shape": "jwt", "reason": "the scrub placeholder",
             "values": [PLACEHOLDER_JWT]},
        ])
        self.assertEqual(["keyed_secret"], [f.shape for f in one_shape.findings])
        allowed = self.tree.run([
            self.entry(),
            {"path": "fixtures/token.json", "shape": "jwt", "reason": "the scrub placeholder",
             "values": [PLACEHOLDER_JWT]},
            {"path": "fixtures/token.json", "shape": "keyed_secret", "reason": "the same",
             "values": [PLACEHOLDER_JWT]},
        ])
        self.assertEqual([], allowed.findings)


class MainTests(unittest.TestCase):
    def setUp(self):
        self.tree = Tree()
        self.addCleanup(self.tree.close)

    def run_main(self, *args):
        out = io.StringIO()
        code = scan.main(["--root", str(self.tree.root), *args], out)
        return code, out.getvalue()

    def test_clean_is_0_and_says_what_was_read(self):
        self.tree.write("fixtures/a.json", "{}")
        allowlist = self.tree.write("allow.json", json.dumps({"entries": []}))
        code, out = self.run_main("--allowlist", str(allowlist), "--tree", "fixtures")
        self.assertEqual(0, code, out)
        self.assertIn("1 file(s)", out)
        self.assertIn("no secret shape", out)

    def test_a_finding_is_1_and_names_the_file_and_shape_only(self):
        self.tree.write("fixtures/a.json", RFC_KEY_1)
        allowlist = self.tree.write("allow.json", json.dumps({"entries": []}))
        code, out = self.run_main("--allowlist", str(allowlist), "--tree", "fixtures")
        self.assertEqual(1, code)
        self.assertIn("fixtures/a.json:1: ed25519_pkcs8", out)
        self.assertNotIn(RFC_KEY_1[21:], out)

    def test_an_unreadable_allowlist_or_missing_tree_is_2(self):
        self.tree.write("fixtures/a.json", "{}")
        bad = self.tree.write("allow.json", "{not json")
        code, out = self.run_main("--allowlist", str(bad), "--tree", "fixtures")
        self.assertEqual(2, code)
        good = self.tree.write("allow2.json", json.dumps({"entries": []}))
        code, out = self.run_main("--allowlist", str(good), "--tree", "nowhere")
        self.assertEqual(2, code)
        self.assertIn("nowhere", out)


class RepositoryTest(unittest.TestCase):
    """What ctest and CI run: this repository's trees under the committed allowlist."""

    def test_the_committed_trees_hold_no_secret_shape(self):
        allowlist = scan.load_allowlist(scan.DEFAULT_ALLOWLIST)
        result = scan.scan_trees(REPO, scan.DEFAULT_TREES, allowlist)
        self.assertEqual([], result.missing_trees)
        self.assertEqual([], [f.text() for f in result.findings])
        self.assertEqual([], [s.text() for s in result.stale])
        self.assertTrue(result.ok())
        self.assertGreater(result.files, 300)
        self.assertGreater(result.allowed, 0)

    def test_the_default_trees_are_the_documented_ones(self):
        self.assertEqual(
            ["worker/tests/fixtures", "shared/testdata", "docs/api", "lab/canary",
             "lab/seed-manifest.json"],
            scan.DEFAULT_TREES,
        )


if __name__ == "__main__":
    unittest.main()
