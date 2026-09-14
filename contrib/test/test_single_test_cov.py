#!/usr/bin/env python3
"""Check coverage helper status and argument handling with real LLVM profiles."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


HELPER = Path(__file__).with_name("single_test_cov.sh")


@unittest.skipUnless(
    all(shutil.which(tool) for tool in ("clang", "llvm-profdata", "llvm-cov")),
    "requires Clang and LLVM coverage tools",
)
class CoverageHelperTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="firedancer-coverage-test-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.binary = self.work / "test with spaces"
        source = self.work / "test.c"
        source.write_text(
            '#include <stdlib.h>\n#include <string.h>\n'
            'int main(int argc, char **argv) {\n'
            '  if(argc != 3 || strcmp(argv[2], "literal ; argument")) return 91;\n'
            '  return atoi(argv[1]);\n}\n'
        )
        subprocess.run(
            ["clang", "-fprofile-instr-generate", "-fcoverage-mapping",
             str(source), "-o", str(self.binary)], check=True
        )

    def run_helper(self, *args, clanker="1"):
        return subprocess.run(
            [str(HELPER), *args], cwd=self.work,
            env={**os.environ, "CLANKER": clanker}, capture_output=True, text=True
        )

    def test_status_and_literal_arguments(self):
        for status in (0, 7):
            with self.subTest(status=status):
                result = self.run_helper(str(self.binary), str(status), "literal ; argument")
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                report = subprocess.run(
                    ["llvm-cov", "report", str(self.binary),
                     "-instr-profile=" + str(self.work / "default.profdata")],
                    capture_output=True, text=True
                )
                self.assertEqual(report.returncode, 0, report.stderr)
                self.assertIn("test.c", report.stdout)

    def test_no_arguments(self):
        self.assertEqual(self.run_helper().returncode, 2)

    @unittest.skipUnless(shutil.which("genhtml"), "requires Lcov genhtml")
    def test_html_report_preserves_failure(self):
        result = self.run_helper(
            str(self.binary), "7", "literal ; argument", clanker="0"
        )
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertTrue((self.work / "report" / "index.html").exists())

    def test_missing_profile(self):
        first = self.run_helper(str(self.binary), "0", "literal ; argument")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertTrue((self.work / "default.profdata").exists())
        result = self.run_helper("/bin/true")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "default.profdata").exists())


if __name__ == "__main__":
    unittest.main()
