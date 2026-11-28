"""Controls for the ManagedAction transcript verifier, with no TLC launch."""

from pathlib import Path
import runpy
import unittest

CHECKER = runpy.run_path(str(Path(__file__).with_name("check-managed-action.py")))
check_healthy = CHECKER["check_healthy"]
check_mutant = CHECKER["check_mutant"]
GateFailure = CHECKER["GateFailure"]

HEALTHY = (
    "Model checking completed. No error has been found.\n"
    "257 states generated, 61 distinct states found, 0 states left on queue.\n"
    "The depth of the complete state graph search is 17.\n"
    + "".join(
        f"<{name} line 10, col 1 to line 10, col 3 of module ManagedAction>: 1:2\n"
        for name in CHECKER["HEALTHY_ACTIONS"]
    )
)
TRACE = (
    "Error: Invariant AtMostOneActivation is violated.\n"
    "Error: The behavior up to this point is:\n"
    "State 1: <Initial predicate>\n"
    "State 2: <Claim line 12, col 1 to line 12, col 5 of module ManagedAction>\n"
    "State 3: <SubmitIntent line 20, col 1 to line 20, col 5 of module ManagedAction>\n"
    "State 4: <InterruptIntent line 30, col 1 to line 30, col 5 of module ManagedAction>\n"
    "State 5: <Crash line 40, col 1 to line 40, col 5 of module ManagedAction>\n"
    "State 6: <Reopen line 50, col 1 to line 50, col 5 of module ManagedAction>\n"
    "State 7: <Claim line 12, col 1 to line 12, col 5 of module ManagedAction>\n"
)
TRUST_PRISTINE = next(case[1:] for case in CHECKER["MUTANTS"] if case[0] == "ManagedActionTrustPristine")


class TranscriptControls(unittest.TestCase):
    def test_exhausted_healthy_trace_requires_attendance(self):
        result = check_healthy(0, HEALTHY)
        self.assertEqual(result["distinct"], 61)
        self.assertEqual(result["actions"]["RefuseSpentActivation"]["total"], 2)
        for transcript in (
            HEALTHY.replace("0 states left on queue", "1 states left on queue"),
            HEALTHY.replace("RefuseSpentActivation line", "OtherAction line"),
            HEALTHY.replace(": 1:2", ": 0:0"),
            HEALTHY + "Error: Search stopped.\n",
        ):
            with self.subTest(transcript=transcript[-160:]), self.assertRaises(GateFailure):
                check_healthy(0, transcript)

    def test_selected_mutant_requires_real_failure_and_complete_ordered_trace(self):
        result = check_mutant(12, TRACE, *TRUST_PRISTINE)
        self.assertEqual(result["actions"][0::5], ["Claim", "Claim"])
        for status, transcript in (
            (124, TRACE),
            (12, TRACE.replace("AtMostOneActivation", "AtMostOneChildCreation")),
            (12, TRACE + "Error: Failed to complete trace.\n"),
            (12, TRACE.replace("State 6:", "State 16:")),
            (12, TRACE.replace("State 4: <InterruptIntent", "State 4: <PersistIntent")),
            (12, TRACE.replace("State 6: <Reopen", "State 6: <Claim").replace("State 7: <Claim", "State 7: <Reopen")),
            (12, TRACE + "State 8: <incomplete\n"),
        ):
            with self.subTest(status=status, transcript=transcript[-160:]), self.assertRaises(GateFailure):
                check_mutant(status, transcript, *TRUST_PRISTINE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
