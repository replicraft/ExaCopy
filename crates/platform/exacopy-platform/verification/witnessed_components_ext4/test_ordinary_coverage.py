"""Portable controls for the ordinary witness coverage admission boundary."""

from copy import deepcopy
import errno
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
        self.assertEqual(ordinary.admitted_runs(valid, ordinary.run.CASES, image), measured)
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
                ordinary.admitted_runs(specimen, ordinary.run.CASES, image)
        for group in valid:
            specimen = deepcopy(valid)
            specimen[group].pop()
            with self.subTest(group=group), self.assertRaisesRegex(ValueError, "attendance"):
                ordinary.admitted_runs(specimen, ordinary.run.CASES, image)


    def test_campaign_rejects_forged_cohort_membership_or_incomplete_cleanup(self):
        image = "a" * 64
        reports = []
        for name, cases in ordinary.cohorts.COHORTS:
            measured = []
            discarded = []
            for index, selector in enumerate(cases, 1):
                prefix = f"case-{index}"
                common = {"selector": selector, "executable_sha256": image}
                measured.append({**common, "launch": f"{prefix}-run",
                                 "retained": f"{prefix}-run.profraw"})
                discarded.extend({**common, "launch": f"{prefix}-{kind}"}
                                 for kind in ("listed", "ignored"))
            reports.append({
                "id": name, "cases": dict.fromkeys(cases, "pass"),
                "cleanup": "verified_absent", "outcome": "pass", "executable_sha256": image,
                "coverage": {"admitted_profiles": measured, "discarded_listing_profiles": discarded},
            })
        self.assertEqual([len(entries) for _, entries in ordinary.admitted_cohorts(reports, image)], [7, 6, 4])
        for forgery in (reports[:2], [reports[0], reports[0], reports[2]], list(reversed(reports))):
            with self.assertRaisesRegex(ValueError, "inventory"):
                ordinary.admitted_cohorts(forgery, image)

        for field, value in (("cleanup", "pending"), ("outcome", "blocked"), ("executable_sha256", "b" * 64),
                             ("cases", reports[0]["cases"])):
            altered = deepcopy(reports)
            altered[2][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "lacks exact tests"):
                ordinary.admitted_cohorts(altered, image)

        altered = deepcopy(reports)
        altered[1]["coverage"]["admitted_profiles"][0] = reports[0]["coverage"]["admitted_profiles"][0]
        with self.assertRaisesRegex(ValueError, "attendance"):
            ordinary.admitted_cohorts(altered, image)

        altered = deepcopy(reports)
        altered[2]["coverage"]["admitted_profiles"][0] = reports[2]["coverage"]["discarded_listing_profiles"][0]
        with self.assertRaisesRegex(ValueError, "attendance"):
            ordinary.admitted_cohorts(altered, image)

    def test_held_image_capability_must_be_known_absent(self):
        with patch.object(ordinary.cohorts.os, "getxattr", side_effect=OSError(errno.ENODATA, "absent")) as probe:
            ordinary.cohorts.check_unprivileged_image(91)
            probe.assert_called_once_with(91, "security.capability")
        with patch.object(ordinary.cohorts.os, "getxattr", return_value=b"present"):
            with self.assertRaisesRegex(ordinary.ext4.Blocked, "has file capabilities"):
                ordinary.cohorts.check_unprivileged_image(91)
        with patch.object(ordinary.cohorts.os, "getxattr", side_effect=OSError(errno.EACCES, "unavailable")):
            with self.assertRaisesRegex(ordinary.ext4.Blocked, "could not be excluded"):
                ordinary.cohorts.check_unprivileged_image(91)


if __name__ == "__main__":
    unittest.main()
