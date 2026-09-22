"""Tests for coverage_gate.py. Stdlib only: python -m unittest discover -s worker/tools"""

import io
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
    def run_gate(self, xml, *extra):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "coverage.xml"
            report.write_text(xml, encoding="utf-8")
            summary = Path(tmp) / "summary.md"
            out = io.StringIO()
            code = coverage_gate.main(
                [str(report), "--summary", str(summary), *extra], out=out
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

    def test_report_without_lines_is_an_error(self):
        # An empty report must not pass vacuously (e.g. --sources filter wrong).
        code, out, _ = self.run_gate(cobertura())
        self.assertEqual(code, 2)
        self.assertIn("no source lines", out)

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
        for name in (r"include\rp\signer.hpp", r"src\target_guard.cpp"):
            with self.subTest(name=name):
                xml = cobertura((r"src\big.cpp", covered(1000)), (name, mixed(1, 1)))
                code, _, _ = self.run_gate(xml)
                self.assertEqual(code, 1)

    def test_strict_name_does_not_match_unrelated_file(self):
        # "vaulted.cpp" is not the vault; only the exact stem counts.
        xml = cobertura((r"src\big.cpp", covered(1000)), (r"src\vaulted.cpp", mixed(1, 1)))
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

    def test_absent_strict_files_are_skipped_with_a_note(self):
        code, _, summary = self.run_gate(cobertura((r"src\a.cpp", covered(10))))
        self.assertEqual(code, 0)
        for name in ("vault", "signer", "target_guard"):
            self.assertIn(f"`{name}`", summary)
        self.assertIn("not present yet", summary)

    def test_summary_has_table_and_branch_limitation(self):
        code, _, summary = self.run_gate(
            cobertura((r"src\a.cpp", covered(3)), (r"src\signer.cpp", covered(4)))
        )
        self.assertEqual(code, 0)
        self.assertIn("| File | Lines covered | Line % |", summary)
        self.assertIn("| `src/a.cpp` | 3/3 | 100.0% |", summary)
        self.assertIn("branch coverage is not measured", summary.lower())

    def test_threshold_is_configurable(self):
        code, _, _ = self.run_gate(cobertura((r"src\a.cpp", mixed(50, 50))), "--min-line", "50")
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
