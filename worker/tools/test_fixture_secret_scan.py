"""Tests for fixture_secret_scan.py (W4.9). Stdlib only:

    python -m unittest discover -s worker/tools -p "test_*.py"

Failures first: every shape planted in a temp tree is reported; an allowed
value passes only in its file and only exactly; a stale allowlist entry fails.
The last test runs the scan over this repository's own trees with the
committed allowlist, which is what ctest and CI run.
"""

import io
import json
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import fixture_secret_scan as scan

REPO = Path(__file__).resolve().parents[2]

# RFC 8032's test key 1 as PKCS#8 Base64: published, never a secret.
RFC_KEY_1 = "MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g"
PLACEHOLDER_JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzY3J1YmJlZCI6dHJ1ZX0."

# The shapes' examples, shared with the Worker's secret_audit_lab.hpp, which the
# C++ side is held to as well (secret_audit_test.cpp).
CASES = json.loads((Path(__file__).with_name("secret_shapes_cases.json")).read_text(encoding="utf-8"))
PLANTED = [(case["shape"], case["text"]) for case in CASES["shaped"]]
CLEAN = CASES["clean"]


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
            file.write_bytes(text.encode(encoding))
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
            with self.subTest(text=text[:40]):
                self.assertEqual([], scan.find_shapes(text))

    def test_the_shared_cases_hold_every_shape_and_only_known_ones(self):
        self.assertEqual(set(scan.SHAPES), {shape for shape, _ in PLANTED})
        self.assertGreater(len(CLEAN), 20)

    def test_a_keyed_value_is_the_text_the_allowlist_compares(self):
        for text, value in [
            ('"veeam_password": "hunter2"', "hunter2"),
            ('{\\"password\\":\\"hunter2\\"}', "hunter2"),
            ('password="Hunter2!"', "Hunter2!"),
            ("password='Hunter2!'", "Hunter2!"),
            ("db.password=hunter2", "hunter2"),
            ("Password : Hunter2! \r\nnext", "Hunter2!"),
            ("password: 'two words'", "two words"),
            ("Authorization: Basic dXNlcjpwYXNz", "Basic dXNlcjpwYXNz"),
        ]:
            with self.subTest(text=text):
                found = scan.find_shapes(text)
                self.assertEqual(["keyed_secret"], [f.shape for f in found])
                self.assertEqual(value, found[0].value)

    def test_the_cloud_s_tokens_are_keyed_secrets_and_a_placeholder_is_none(self):
        """W5.1 (docs/decisions.md 2026-10-15, point 10): registration's
        install_token and api_token and the vault's names ending in them."""
        token = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9"
        for text in [
            '{"api_token": "%s"}' % token,
            '{"install_token":"%s","version":"0.0.0"}' % token,
            "cloud_api_token=%s" % token,
            "cloud_install_token = %s" % token,
        ]:
            with self.subTest(text=text):
                found = scan.find_shapes(text)
                self.assertEqual(["keyed_secret"], [f.shape for f in found])
                self.assertEqual(token, found[0].value)
        for text in ['{"api_token": "SCRUBBED"}', '"install_token": "<token>"', '{"api_tokens_left": 3}',
                     "install_token.create install_token:b2e92b1d-c49a-4934-be83-ad9002ca6fa1"]:
            with self.subTest(text=text):
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
        self.tree.write("fixtures/b.txt", "\n".join(CLEAN))
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

    def test_a_tree_given_as_an_absolute_path_is_scanned_and_named_from_the_root(self):
        self.tree.write("fixtures/a.json", RFC_KEY_1)
        result = self.tree.run(trees=(str(self.tree.root / "fixtures"),))
        self.assertEqual(["fixtures/a.json"], [f.path for f in result.findings])

    def test_a_file_that_cannot_be_read_is_no_pass(self):
        self.tree.write("fixtures/a.json", "{}")
        self.tree.write("fixtures/b.json", "{}")
        original = Path.read_bytes

        def failing(self_path):
            if self_path.name == "b.json":
                raise PermissionError(13, "Permission denied")
            return original(self_path)

        with unittest.mock.patch.object(Path, "read_bytes", failing):
            result = self.tree.run()
        self.assertEqual([], result.findings)
        self.assertEqual(1, result.files)
        self.assertEqual(["fixtures/b.json: Permission denied"], result.unreadable)
        self.assertFalse(result.ok())

    def junction_loop(self):
        import _winapi

        self.tree.write("fixtures/kept/x.txt", RFC_KEY_1)
        # A junction inside the tree pointing at the tree's parent: a loop.
        _winapi.CreateJunction(str(self.tree.root), str(self.tree.root / "fixtures" / "loop"))

    @unittest.skipUnless(sys.platform == "win32", "a junction needs Windows")
    def test_a_junction_or_link_is_not_entered(self):
        self.junction_loop()
        result = self.tree.run()
        self.assertEqual(["fixtures/kept/x.txt"], [f.path for f in result.findings])
        self.assertEqual(1, result.files)

    @unittest.skipUnless(sys.platform == "win32", "a junction needs Windows")
    def test_a_junction_is_not_entered_by_a_python_without_is_junction(self):
        # Path.is_junction() came with Python 3.12; CMake takes any Python 3.
        self.junction_loop()
        with unittest.mock.patch.object(Path, "is_junction", None, create=True):
            result = self.tree.run()
        self.assertEqual(["fixtures/kept/x.txt"], [f.path for f in result.findings])
        self.assertEqual(1, result.files)

    def test_a_plain_folder_is_entered_by_a_python_without_is_junction(self):
        self.tree.write("fixtures/kept/x.txt", RFC_KEY_1)
        with unittest.mock.patch.object(Path, "is_junction", None, create=True):
            result = self.tree.run()
        self.assertEqual(["fixtures/kept/x.txt"], [f.path for f in result.findings])


class ImportTests(unittest.TestCase):
    def test_this_module_imports_where_there_is_no_winapi(self):
        # CI's fixture-scan job runs on Ubuntu, which has no _winapi: the
        # standard library is loaded first, then _winapi is taken away.
        code = ("import io, json, subprocess, sys, tempfile, unittest, unittest.mock, pathlib\n"
                "import argparse, dataclasses, re, stat, typing\n"
                "sys.modules['_winapi'] = None\n"
                "import test_fixture_secret_scan\n")
        done = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).parent,
                              capture_output=True, text=True)
        self.assertEqual("", done.stderr)
        self.assertEqual(0, done.returncode)


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

    def test_an_unreadable_file_is_2(self):
        self.tree.write("fixtures/a.json", "{}")
        allowlist = self.tree.write("allow.json", json.dumps({"entries": []}))
        with unittest.mock.patch.object(Path, "read_bytes", side_effect=PermissionError(13, "Permission denied")):
            code, out = self.run_main("--allowlist", str(allowlist), "--tree", "fixtures")
        self.assertEqual(2, code)
        self.assertIn("a file can't be read: fixtures/a.json", out)

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
            ["worker/tests/fixtures", "shared/testdata", "docs/api", "tests/e2e", "lab/canary",
             "lab/seed-manifest.json", "lab/tenant.md", "tools/tenant-setup/tests/fixtures"],
            scan.DEFAULT_TREES,
        )


if __name__ == "__main__":
    unittest.main()
