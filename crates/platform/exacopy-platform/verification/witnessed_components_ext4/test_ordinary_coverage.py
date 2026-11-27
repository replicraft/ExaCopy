"""Portable controls for the ordinary witness coverage admission boundary."""

from copy import deepcopy
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import ordinary_coverage as ordinary


class OrdinaryCoverageControls(unittest.TestCase):
    def test_same_denominator_admits_only_monotone_same_file_inventories(self):
        before = {"src/left.rs": (20, 10), "src/right.rs": (30, 29)}
        ordinary.same_denominator(before, {"src/left.rs": (20, 12), "src/right.rs": (30, 30)})
        invalid = (
            {"src/left.rs": (20, 10), "src/right.rs": (30, 29), "src/extra.rs": (2, 2)},
            {"src/left.rs": (20, 10)},
            {"src/left.rs": (21, 10), "src/right.rs": (29, 29)},
            {"src/left.rs": (20, 9), "src/right.rs": (30, 30)},
        )
        for altered in invalid:
            with self.subTest(altered=altered), self.assertRaisesRegex(ValueError, "denominator"):
                ordinary.same_denominator(before, altered)

    def test_admission_refuses_wrong_workflow_job_run_or_attempt(self):
        revision = "b" * 40
        good = {
            "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "replicraft/ExaCopy",
            "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": revision, "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64", "GITHUB_WORKFLOW_SHA": revision,
            "GITHUB_WORKFLOW_REF": ordinary.WORKFLOW, "GITHUB_JOB": "coverage",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_TEMP": str(Path.cwd().resolve()),
        }
        with patch.dict(os.environ, good, clear=True):
            self.assertEqual(ordinary.admission()[1]["revision"], revision)
        cases = (
            ("GITHUB_WORKFLOW_REF", "replicraft/ExaCopy/.github/workflows/ci.yml@refs/heads/main"),
            ("GITHUB_WORKFLOW_SHA", "a" * 40),
            ("GITHUB_JOB", "other"),
            ("GITHUB_RUN_ID", "0"),
            ("GITHUB_RUN_ATTEMPT", "wrong"),
        )
        for name, value in cases:
            with self.subTest(name=name), patch.dict(os.environ, {**good, name: value}, clear=True):
                with self.assertRaises(ValueError):
                    ordinary.admission()

    def test_only_exact_measured_slots_from_the_same_image_enter_merge(self):
        image = "a" * 64
        measured, discarded = [], []
        for index, selector in enumerate(ordinary.run.CASES, 1):
            common = {"selector": selector, "executable_sha256": image}
            measured.append({**common, "launch": f"case-{index}-run",
                             "retained": f"case-{index}-run.profraw"})
            discarded.extend({**common, "launch": f"case-{index}-{kind}"} for kind in ("listed", "ignored"))
        valid = {"admitted_profiles": measured, "discarded_listing_profiles": discarded}
        self.assertEqual(ordinary.admitted_runs(valid, image), measured)
        changed = (
            ("admitted_profiles", 0, {"launch": "case-1-listed"}),
            ("admitted_profiles", 0, {"retained": "case-1-listed.profraw"}),
            ("discarded_listing_profiles", 0, {"retained": "case-1-listed.profraw"}),
            ("discarded_listing_profiles", 1, {"executable_sha256": "b" * 64}),
        )
        for group, slot, change in changed:
            specimen = deepcopy(valid)
            specimen[group][slot].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "attendance"):
                ordinary.admitted_runs(specimen, image)
        for group in valid:
            specimen = deepcopy(valid)
            specimen[group].pop()
            with self.subTest(group=group), self.assertRaisesRegex(ValueError, "attendance"):
                ordinary.admitted_runs(specimen, image)


if __name__ == "__main__":
    unittest.main()
