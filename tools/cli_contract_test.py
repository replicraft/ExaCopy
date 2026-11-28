"""Regression controls for selection of CLI JSON report contracts."""

import copy
from pathlib import Path
import tomllib
import unittest

from contracts.check_cli import JSON_REPORTS, OPT_IN_JSON_REPORTS, VERSION_DIAGNOSTIC, report_versions


class ReportInventoryTests(unittest.TestCase):
    def setUp(self):
        self.inventory = tomllib.loads(
            (Path(__file__).resolve().parents[1] / "specs/contracts/versions.toml").read_text()
        )

    def test_text_version_diagnostic_does_not_require_a_json_schema_version(self):
        versions = report_versions(self.inventory)
        self.assertNotIn(VERSION_DIAGNOSTIC, versions)
        self.assertEqual(set(versions), JSON_REPORTS | OPT_IN_JSON_REPORTS)
        for identity in JSON_REPORTS:
            self.assertEqual(versions[identity], "1.0")

    def test_feature_enabled_json_reports_are_separate_from_the_local_probe(self):
        expected = {
            "exacopy.public_stage_inspection": "1.0",
            "exacopy.cli.remote_download": "1.0",
            "exacopy.cli.witnessed_remote_download": "1.1",
            "exacopy.cli.witnessed_remote_inspection": "1.0",
            "exacopy.cli.apfs_recovery_inspection": "1.1",
            "exacopy.cli.managed_sync_recreate_plan": "1.0",
            "exacopy.cli.windows_bootstrap_inspection": "1.0",
        }
        self.assertEqual(OPT_IN_JSON_REPORTS, set(expected))
        self.assertTrue(JSON_REPORTS.isdisjoint(expected))
        versions = report_versions(self.inventory)
        self.assertEqual({identity: versions[identity] for identity in expected}, expected)

    def test_each_json_report_requires_its_version(self):
        for identity in JSON_REPORTS | OPT_IN_JSON_REPORTS:
            with self.subTest(identity=identity):
                inventory = copy.deepcopy(self.inventory)
                selected = next(c for c in inventory["contract"] if c["id"] == identity)
                del selected["version"]
                with self.assertRaises(KeyError):
                    report_versions(inventory)

    def test_missing_or_duplicate_json_reports_are_rejected(self):
        for identity in JSON_REPORTS | OPT_IN_JSON_REPORTS:
            with self.subTest(identity=identity):
                missing = copy.deepcopy(self.inventory)
                missing["contract"] = [c for c in missing["contract"] if c["id"] != identity]
                duplicate = copy.deepcopy(self.inventory)
                selected = next(c for c in duplicate["contract"] if c["id"] == identity)
                duplicate["contract"].append(selected)
                for inventory in (missing, duplicate):
                    with self.assertRaises(ValueError):
                        report_versions(inventory)

    def test_unknown_json_report_is_rejected(self):
        unknown = copy.deepcopy(self.inventory)
        selected = next(c for c in unknown["contract"] if c["id"] in JSON_REPORTS)
        unknown["contract"].append(selected | {"id": "unregistered.json"})
        with self.assertRaises(ValueError):
            report_versions(unknown)
