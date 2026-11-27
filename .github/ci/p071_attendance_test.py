"""Positive and negative source controls for the P-071 attendance gate."""

from pathlib import Path
import tempfile
import unittest

from p071_attendance import CASES, MAX_REPORT_BYTES, PREFIX, check_attendance, check_output

SUMMARY = "test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 274 filtered out; finished in 0.00s"
NAMES = sorted(CASES)
OUTCOMES = [f"test {name} ... ok" for name in NAMES]


def report(outcomes=OUTCOMES, summary=SUMMARY, footer=()):
    return "\n".join(("running 8 tests", *outcomes, *footer, summary, "")).encode()


class P071Attendance(unittest.TestCase):
    def test_accepts_exact_cases_with_libtest_success_output(self):
        footer = ("", "successes:", "", f"---- {NAMES[0]} stdout ----",
                  "allocation fixture diagnostic", "", "successes:", f"    {NAMES[0]}", "")
        self.assertEqual(check_output(report(outcomes=reversed(OUTCOMES), footer=footer)), NAMES)

    def test_refuses_same_count_with_replaced_or_duplicate_case(self):
        for row, error in (
            (f"test {PREFIX}different_case ... ok", "unexpected P-071 testcase"),
            (OUTCOMES[1], "duplicate P-071 testcase"),
        ):
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, error):
                check_output(report([row, *OUTCOMES[1:]]))

    def test_a_passing_summary_does_not_substitute_for_a_passed_outcome(self):
        with self.assertRaisesRegex(ValueError, "missing P-071 testcases"):
            check_output(report(OUTCOMES[1:]))
        for status in ("ignored", "FAILED", "ok trailing text"):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "unsuccessful"):
                check_output(report([f"test {NAMES[0]} ... {status}", *OUTCOMES[1:]]))
        with self.assertRaisesRegex(ValueError, "misplaced outcome"):
            check_output(report(OUTCOMES[1:], footer=("successes:", OUTCOMES[0])))

    def test_refuses_missing_duplicate_or_incompatible_execution_boundaries(self):
        complete = report()
        for invalid in (
            complete.replace(b"running 8 tests\n", b"", 1),
            b"running 8 tests\n" + complete,
            complete.replace(b"8 passed", b"5 passed", 1),
            complete.replace(b"0 ignored", b"1 ignored", 1),
            complete + (SUMMARY + "\n").encode(),
            (SUMMARY + "\n").encode() + complete.replace((SUMMARY + "\n").encode(), b"", 1),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                check_output(invalid)

    def test_refuses_oversized_or_invalid_utf8_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tests.log"
            path.write_bytes(report().ljust(MAX_REPORT_BYTES + 1, b" "))
            with self.assertRaisesRegex(ValueError, "exceeds 1 MiB"):
                check_attendance(path)
        with self.assertRaises(UnicodeError):
            check_output(report() + b"\xff")


if __name__ == "__main__":
    unittest.main()
