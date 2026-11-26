"""Regression controls for selection of CLI JSON report contracts."""

import copy
from pathlib import Path
import tomllib
import unittest

from contracts.check_cli import JSON_REPORTS, report_versions


class ReportInventoryTests(unittest.TestCase):
    def setUp(self):
        self.inventory = tomllib.loads(
            (Path(__file__).resolve().parents[1] / "specs/contracts/versions.toml").read_text()
        )

    def test_text_version_diagnostic_does_not_require_a_json_schema_version(self):
        versions = report_versions(self.inventory)
        self.assertEqual(set(versions), JSON_REPORTS)
        self.assertTrue(all(value == "1.0" for value in versions.values()))

    def test_each_json_report_requires_its_version(self):
        for identity in JSON_REPORTS:
            with self.subTest(identity=identity):
                inventory = copy.deepcopy(self.inventory)
                selected = next(c for c in inventory["contract"] if c["id"] == identity)
                del selected["version"]
                with self.assertRaises(KeyError):
                    report_versions(inventory)

    def test_missing_duplicate_or_unknown_reports_are_rejected(self):
        selected = next(c for c in self.inventory["contract"] if c["id"] in JSON_REPORTS)
        missing = copy.deepcopy(self.inventory)
        missing["contract"] = [c for c in missing["contract"] if c["id"] != selected["id"]]
        duplicate = copy.deepcopy(self.inventory)
        duplicate["contract"].append(selected)
        unknown = copy.deepcopy(self.inventory)
        unknown["contract"].append(selected | {"id": "unregistered.json"})
        for inventory in (missing, duplicate, unknown):
            with self.assertRaises(ValueError):
                report_versions(inventory)
