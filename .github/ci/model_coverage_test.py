"""Exercise the model coverage gate against synthetic LLVM export summaries."""

from copy import deepcopy
import json
from pathlib import Path
import unittest

import model_coverage as coverage


WORKSPACE = Path("/checkout/ExaCopy")


def metric(dimension, count, covered):
    result = {
        "count": count,
        "covered": covered,
        "percent": 100 * covered / count if count else 0,
    }
    if dimension == "branches":
        result["notcovered"] = count - covered
    return result


def retotal(dataset):
    for dimension in coverage.MINIMUM:
        values = [item["summary"][dimension] for item in dataset["files"]]
        dataset["totals"][dimension] = metric(
            dimension,
            sum(item["count"] for item in values),
            sum(item["covered"] for item in values),
        )


def export():
    dataset = {
        "files": [
            {
                "filename": str(WORKSPACE / source),
                "branches": [[1, 1, 1, 2, 1, 0, 0, 0, 4]],
                "segments": [[1, 1, 1, True, True, False]],
                "summary": {
                    "lines": metric("lines", 100, 95),
                    "branches": metric("branches", 100, 90),
                },
            }
            for source in sorted(coverage.SOURCES)
        ],
        "functions": [{"name": "synthetic"}],
        "totals": {},
    }
    dataset["files"][1]["summary"]["branches"] = metric("branches", 0, 0)
    dataset["files"][1]["branches"] = []
    retotal(dataset)
    return {
        "type": "llvm.coverage.json.export",
        "version": "3.1.0",
        "cargo_llvm_cov": {
            "version": "0.9.1",
            "manifest_path": str(WORKSPACE / "Cargo.toml"),
        },
        "data": [dataset],
    }


class ModelCoverageControls(unittest.TestCase):
    def test_full_and_summary_exports_accept_exact_thresholds(self):
        report = coverage.parse_report(json.dumps(export()))
        totals = coverage.validate(report, WORKSPACE)
        self.assertEqual(totals, {"lines": (1500, 1425), "branches": (1400, 1260)})
        self.assertEqual(coverage.shortfalls(totals), [])
        dataset = report["data"][0]
        del dataset["functions"]
        for item in dataset["files"]:
            del item["branches"], item["segments"]
        self.assertEqual(coverage.validate(report, WORKSPACE), totals)

    def test_one_count_below_either_threshold_fails(self):
        for dimension, covered in (("lines", 94), ("branches", 89)):
            with self.subTest(dimension=dimension):
                report = export()
                dataset = report["data"][0]
                dataset["files"][0]["summary"][dimension] = metric(dimension, 100, covered)
                retotal(dataset)
                self.assertEqual(coverage.shortfalls(coverage.validate(report, WORKSPACE)), [dimension])

    def test_wrong_or_ambiguous_export_envelope_is_rejected(self):
        report = export()
        for bad in (
            {**report, "type": "other"},
            {**report, "version": "0.0.0"},
            {**report, "data": []},
            {**report, "data": [*report["data"], *report["data"]]},
            {**report, "cargo_llvm_cov": {**report["cargo_llvm_cov"], "manifest_path": "/foreign/Cargo.toml"}},
            {**report, "cargo_llvm_cov": {**report["cargo_llvm_cov"], "version": False}},
            {**report, "data": [None]},
            {**report, "data": [{**report["data"][0], "functions": []}]},
            {**report, "data": [{**report["data"][0], "functions": [None]}]},
        ):
            with self.subTest(bad_type=type(bad)), self.assertRaises(ValueError):
                coverage.validate(bad, WORKSPACE)
        for malformed in ('{"data": [}', '{"data": [], "data": []}', '{"value": NaN}'):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                coverage.parse_report(malformed)
        report["data"][0]["files"][0]["segments"] = [None]
        with self.assertRaisesRegex(ValueError, "location array"):
            coverage.validate(report, WORKSPACE)

    def test_inventory_refuses_empty_missing_extra_duplicate_and_foreign_sources(self):
        report = export()
        files = report["data"][0]["files"]
        first = files[0]
        name = Path(first["filename"]).name
        for rejected in (
            [],
            files[1:],
            [*files, {**first, "filename": str(WORKSPACE / "extra.rs")}],
            [first, *files[:-1]],
            [{**first, "filename": "/foreign" + first["filename"]}, *files[1:]],
            [{**first, "filename": str(WORKSPACE / "other" / name)}, *files[1:]],
            [{**first, "filename": first["filename"].replace("/src/", "/src/../src/")}, *files[1:]],
            [{**first, "filename": first["filename"].removeprefix(f"{WORKSPACE}/")}, *files[1:]],
        ):
            with self.subTest(filenames=[item["filename"] for item in rejected]):
                bad = deepcopy(report)
                bad["data"][0]["files"] = rejected
                with self.assertRaises(ValueError):
                    coverage.validate(bad, WORKSPACE)

    def test_counts_refuse_wrong_types_mismatches_and_zero_denominators(self):
        for dimension, change in (
            ("lines", {"count": True}),
            ("lines", {"count": 100.0}),
            ("lines", {"covered": False}),
            ("lines", {"covered": -1}),
            ("lines", {"covered": 101}),
            ("lines", {"percent": True}),
            ("lines", {"percent": 100}),
            ("lines", metric("lines", 0, 0)),
            ("branches", {"notcovered": False}),
            ("branches", {"notcovered": 9}),
        ):
            with self.subTest(dimension=dimension, change=change):
                report = export()
                report["data"][0]["files"][0]["summary"][dimension].update(change)
                with self.assertRaises(ValueError):
                    coverage.validate(report, WORKSPACE)

        report = export()
        dataset = report["data"][0]
        dataset["totals"]["lines"] = metric("lines", 1401, 1330)
        with self.assertRaisesRegex(ValueError, "totals disagree"):
            coverage.validate(report, WORKSPACE)
        for item in dataset["files"]:
            item["summary"]["branches"] = metric("branches", 0, 0)
        retotal(dataset)
        with self.assertRaisesRegex(ValueError, "zero total coverage count"):
            coverage.validate(report, WORKSPACE)


if __name__ == "__main__":
    unittest.main()
