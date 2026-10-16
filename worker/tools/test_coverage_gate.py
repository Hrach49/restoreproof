"""Tests for coverage_gate.py. Stdlib only: python -m unittest discover -s worker/tools"""

import io
import re
import tempfile
import unittest
from pathlib import Path

import coverage_gate


def cobertura(*classes):
    """Build a minimal OpenCppCoverage-style Cobertura document.

    Each class is (filename, [(line_number, hits), ...]).
    """
    parts = []
    for filename, lines in classes:
        body = "".join(f'<line number="{n}" hits="{h}"/>' for n, h in lines)
        parts.append(
            f'<class name="{Path(filename).name}" filename="{filename}" '
            f'line-rate="0" branch-rate="0" complexity="0">'
            f"<methods/><lines>{body}</lines></class>"
        )
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<coverage line-rate="0" branch-rate="0" version="1.9" timestamp="0">'
        "<sources><source>C:</source></sources><packages>"
        r'<package name="C:\build\rptests.exe" line-rate="0" branch-rate="0" complexity="0">'
        f"<classes>{''.join(parts)}</classes></package></packages></coverage>"
    )


def covered(n):
    return [(i, 1) for i in range(1, n + 1)]


def mixed(hit, miss):
    return [(i, 1) for i in range(1, hit + 1)] + [(hit + i, 0) for i in range(1, miss + 1)]


class GateTest(unittest.TestCase):
    def run_gate(self, xml, *extra, disk=None):
        """Run the gate against a fake worker/ root holding the `disk` files.

        By default the root holds exactly the files the report names, so only
        tests about files missing from the report need to pass `disk`.
        """
        if disk is None:
            disk = [n.replace("\\", "/") for n in re.findall(r'filename="([^"]+)"', xml)]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "worker"
            for rel in disk:
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text("", encoding="utf-8")
            report = Path(tmp) / "coverage.xml"
            report.write_text(xml, encoding="utf-8")
            summary = Path(tmp) / "summary.md"
            out = io.StringIO()
            code = coverage_gate.main(
                [str(report), "--root", str(root), "--summary", str(summary), *extra], out=out
            )
            text = summary.read_text(encoding="utf-8") if summary.exists() else ""
            return code, out.getvalue(), text

    # Failure paths first.

    def test_below_line_threshold_fails(self):
        code, out, _ = self.run_gate(cobertura((r"src\a.cpp", mixed(79, 21))))
        self.assertEqual(code, 1)
        self.assertIn("79.0%", out)

    def test_missing_report_is_an_error(self):
        out = io.StringIO()
        code = coverage_gate.main(["does-not-exist.xml"], out=out)
        self.assertEqual(code, 2)

    def test_malformed_xml_is_an_error(self):
        code, _, _ = self.run_gate("<coverage><packages>")
        self.assertEqual(code, 2)

    def test_non_numeric_line_data_is_an_error(self):
        for attrs in ('number="1" hits=""', 'number="x" hits="1"'):
            with self.subTest(attrs=attrs):
                xml = cobertura((r"src\a.cpp", covered(1))).replace('number="1" hits="1"', attrs)
                code, out, _ = self.run_gate(xml)
                self.assertEqual(code, 2)
                self.assertIn("ERROR", out)

    def test_root_without_src_is_an_error(self):
        # Run from the wrong folder, the on-disk check would see no files and
        # pass vacuously.
        code, out, _ = self.run_gate(cobertura((r"src\a.cpp", covered(1))), disk=["other/a.cpp"])
        self.assertEqual(code, 2)
        self.assertIn("no src/ folder", out)

    def test_report_without_lines_is_an_error(self):
        # An empty report must not pass vacuously (e.g. --sources filter wrong).
        code, out, _ = self.run_gate(cobertura())
        self.assertEqual(code, 2)
        self.assertIn("no source lines", out)

    def test_source_file_missing_from_report_fails(self):
        # A .cpp no test references is never linked into rptests.exe, so
        # OpenCppCoverage never sees it. It must fail, not vanish.
        code, out, summary = self.run_gate(
            cobertura((r"src\a.cpp", covered(10))),
            disk=["src/a.cpp", "src/untested.cpp"],
        )
        self.assertEqual(code, 1)
        self.assertIn("src/untested.cpp", out)
        self.assertIn("not in coverage report", out)
        self.assertIn("| `src/untested.cpp` | not in report |", summary)

    def test_app_file_missing_from_report_fails(self):
        # rpworker's main() in app/ is measured through ctest's runs of
        # rpworker.exe, so it must not vanish from the report either.
        code, out, summary = self.run_gate(
            cobertura((r"src\a.cpp", covered(10))),
            disk=["src/a.cpp", "app/main.cpp"],
        )
        self.assertEqual(code, 1)
        self.assertIn("app/main.cpp", out)
        self.assertIn("| `app/main.cpp` | not in report |", summary)

    def test_app_file_counts_towards_the_total(self):
        xml = cobertura(
            (r"D:\a\restoreproof\worker\src\a.cpp", covered(8)),
            (r"D:\a\restoreproof\worker\app\main.cpp", mixed(0, 2)),
        )
        code, out, summary = self.run_gate(
            xml, "--min-line", "90", disk=["src/a.cpp", "app/main.cpp"]
        )
        self.assertEqual(code, 1, out)
        self.assertIn("| `app/main.cpp` | 0/2 | 0.0% |", summary)
        self.assertIn("80.0% lines, needs 90%", out)

    def test_strict_file_missing_from_report_fails(self):
        for rel, name in (
            ("src/vault.cpp", "vault"),
            ("src/signer/ed25519.cpp", "signer"),
            ("src/service_log.cpp", "service"),
            ("src/client_profile.cpp", "client_profile"),
            ("src/client_check.cpp", "client_check"),
            ("src/cloud_command.cpp", "cloud"),
        ):
            with self.subTest(rel=rel):
                code, out, summary = self.run_gate(
                    cobertura((r"src\a.cpp", covered(10))),
                    disk=["src/a.cpp", rel],
                )
                self.assertEqual(code, 1)
                self.assertIn(rel, out)
                self.assertNotIn(f"`{name}`: not present yet", summary)

    def test_strict_file_below_100_fails_even_if_total_passes(self):
        xml = cobertura(
            (r"src\big.cpp", covered(1000)),
            (r"src\vault.cpp", mixed(99, 1)),
        )
        code, out, summary = self.run_gate(xml)
        self.assertEqual(code, 1)
        self.assertIn("vault.cpp", out)
        self.assertIn("FAIL", summary)

    def test_strict_names_match_headers_and_target_guard(self):
        for name in (
            r"include\rp\signer.hpp",
            r"src\target_guard.cpp",
            r"src\run_status.cpp",
            r"include\rp\run_status.hpp",
            r"src\cleaner.cpp",
            r"include\rp\cleaner.hpp",
            r"src\timestamper.cpp",
            r"include\rp\timestamper.hpp",
            r"src\outbox.cpp",
            r"src\service.cpp",
            r"include\rp\service.hpp",
            # W4.10: the profile reader and the strict JSON reader.
            r"src\client_profile.cpp",
            r"include\rp\client_profile.hpp",
            r"src\strict_json.hpp",
            # W4.11: the client check's rule.
            r"src\client_check.cpp",
            r"include\rp\client_check.hpp",
            # W5.1: the Cloud's answers and the registration.
            r"src\cloud_api.cpp",
            r"src\cloud_command.cpp",
            r"include\rp\cloud_api.hpp",
        ):
            with self.subTest(name=name):
                xml = cobertura((r"src\big.cpp", covered(1000)), (name, mixed(1, 1)))
                code, _, _ = self.run_gate(xml)
                self.assertEqual(code, 1)

    def test_strict_code_split_into_other_files_is_still_strict(self):
        for name in (
            r"src\signer\ed25519.cpp",
            r"include\rp\signer\keys.hpp",
            r"src\vault_dpapi.cpp",
            r"src\target_guard_rules.cpp",
            r"src\vault\detail\blob.cpp",
            # W4.7: the service's subcommands and its log.
            r"src\service_command.cpp",
            r"include\rp\service_command.hpp",
            r"src\service_log.cpp",
            r"include\rp\service_log.hpp",
            r"src\service_log_detail.hpp",
        ):
            with self.subTest(name=name):
                xml = cobertura((r"src\big.cpp", covered(1000)), (name, mixed(1, 1)))
                code, out, _ = self.run_gate(xml)
                self.assertEqual(code, 1)
                self.assertIn("strict", out)

    def test_strict_name_does_not_match_unrelated_file(self):
        # "vaulted.cpp" is not the vault: a strict name must be a whole path
        # part, or a prefix followed by "_".
        # Nor are the calls into Windows under the service (W4.7): src/scm.cpp
        # and src/stop_signal.cpp count toward the total only.
        for name in (
            r"src\vaulted.cpp",
            r"src\signers.cpp",
            r"src\my_vault.cpp",
            r"src\cleaners.cpp",
            r"src\services.cpp",
            r"src\run_service.cpp",
            r"src\scm.cpp",
            r"src\stop_signal.cpp",
            # W4.10: the command over the profile is not the profile reader.
            r"src\client_command.cpp",
        ):
            with self.subTest(name=name):
                xml = cobertura((r"src\big.cpp", covered(1000)), (name, mixed(1, 1)))
                code, _, _ = self.run_gate(xml)
                self.assertEqual(code, 0)

    # Happy paths.

    def test_exactly_at_threshold_passes(self):
        code, _, _ = self.run_gate(cobertura((r"src\a.cpp", mixed(80, 20))))
        self.assertEqual(code, 0)

    def test_lines_merge_across_packages(self):
        # ctest runs rptests once per test case; a line counts as covered if
        # any run hit it.
        xml = cobertura((r"src\a.cpp", [(1, 1), (2, 0)]), (r"src\a.cpp", [(1, 0), (2, 1)]))
        code, out, _ = self.run_gate(xml)
        self.assertEqual(code, 0)
        self.assertIn("100.0%", out)

    def test_headers_without_executable_lines_may_be_absent(self):
        # A header of declarations has no lines to cover, so OpenCppCoverage
        # leaves it out of the report. That is not an untested file.
        code, _, _ = self.run_gate(
            cobertura((r"src\a.cpp", covered(10))),
            disk=["src/a.cpp", "include/rp/a.hpp", "include/rp/vault.hpp", "src/notes.md"],
        )
        self.assertEqual(code, 0)

    def test_absolute_report_paths_match_files_on_disk(self):
        # OpenCppCoverage writes full paths, and Windows paths ignore case.
        xml = cobertura(
            (r"D:\a\restoreproof\restoreproof\worker\src\a.cpp", covered(10)),
            (r"d:\A\RESTOREPROOF\restoreproof\worker\SRC\Vault.cpp", covered(5)),
        )
        code, out, summary = self.run_gate(xml, disk=["src/a.cpp", "src/Vault.cpp"])
        self.assertEqual(code, 0, out)
        self.assertIn("| `src/a.cpp` | 10/10 | 100.0% |", summary)
        self.assertIn("| `src/Vault.cpp` | 5/5 | 100.0% | PASS |", summary)

    def test_absent_strict_files_are_skipped_with_a_note(self):
        code, _, summary = self.run_gate(cobertura((r"src\a.cpp", covered(10))))
        self.assertEqual(code, 0)
        for name in (
            "vault",
            "signer",
            "target_guard",
            "run_status",
            "cleaner",
            "timestamper",
            "outbox",
            "service",
            "client_profile",
            "strict_json",
            "client_check",
            "cloud",
        ):
            self.assertIn(f"`{name}`: not present yet", summary)

    def test_strict_file_on_disk_is_not_reported_as_absent(self):
        code, _, summary = self.run_gate(
            cobertura((r"src\a.cpp", covered(10)), (r"src\signer\ed25519.cpp", covered(3)))
        )
        self.assertEqual(code, 0)
        self.assertNotIn("`signer`: not present yet", summary)
        self.assertIn("`vault`: not present yet", summary)

    def test_summary_has_table_and_branch_limitation(self):
        code, _, summary = self.run_gate(
            cobertura((r"src\a.cpp", covered(3)), (r"src\signer.cpp", covered(4)))
        )
        self.assertEqual(code, 0)
        self.assertIn("| File | Lines covered | Line % |", summary)
        self.assertIn("| `src/a.cpp` | 3/3 | 100.0% |", summary)
        self.assertIn("branch coverage is not measured", summary.lower())
        # The note names every strict name, so the summary says what is held.
        for name in coverage_gate.STRICT_NAMES:
            self.assertIn(f"`{name}`", coverage_gate.BRANCH_NOTE)

    def test_threshold_is_configurable(self):
        code, _, _ = self.run_gate(cobertura((r"src\a.cpp", mixed(50, 50))), "--min-line", "50")
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
