import copy
import json
import unittest

from dependency_review.check import CRATES_IO, REVIEW_FIELDS, compact_graph, registry_inputs, review_gaps, tree_inputs


class CargoTreeTests(unittest.TestCase):
    def test_preserves_exact_versions_features_and_deduplicated_edges(self):
        parents, features = tree_inputs(
            "0|application v0.1.0 (/root with spaces)\t\n"
            "1|bridge v1.0.0\t\n"
            "2|shared v1.1.0 (proc-macro)\tcli (*)\n"
            "1|shared v1.2.0\tbuild\n"
            "1|shared v1.1.0\tcore\n"
        )
        self.assertEqual(parents["shared@1.1.0"], {"bridge@1.0.0", "application@0.1.0"})
        self.assertEqual(features["shared@1.1.0"], {"cli", "core"})
        self.assertEqual(features["shared@1.2.0"], {"build"})

    def test_rejects_missing_parent(self):
        with self.assertRaisesRegex(ValueError, "no parent"):
            tree_inputs("1|bridge v1.0.0\t")

    def test_registry_input_requires_checksum_and_exact_source(self):
        package = {
            "name": "bridge", "version": "1.0.0", "source": CRATES_IO,
            "license": "MIT", "repository": "https://example.com",
            "targets": [{"kind": ["proc-macro"]}, {"kind": ["custom-build"]}],
        }
        sha = "a" * 64
        checksums = {("bridge@1.0.0", CRATES_IO): sha}
        record = registry_inputs(package, checksums)
        self.assertEqual(record["archive_sha256"], sha)
        self.assertTrue(record["build_script"])
        self.assertTrue(record["proc_macro"])
        with self.assertRaisesRegex(ValueError, "archive SHA-256"):
            registry_inputs(package, {})
        with self.assertRaisesRegex(ValueError, "archive SHA-256"):
            registry_inputs(package | {"source": "git+https://example.com"}, checksums)


class ReviewInventoryTests(unittest.TestCase):
    def setUp(self):
        self.graph = {
            "schema_version": 1,
            "packages": {
                "bridge@1.0.0": {"archive_sha256": "a" * 64},
                "shared@1.0.0": {"archive_sha256": "b" * 64},
            },
            "resolutions": {
                "test-target": [{
                    "profiles": ["default"],
                    "inputs": {
                        "bridge@1.0.0": {"parents": ["application@0.1.0"], "features": []},
                        "shared@1.0.0": {"parents": ["bridge@1.0.0"], "features": ["parser"]},
                    },
                }],
            },
        }
        self.reviews = {
            "schema_version": 1,
            "purpose": {"bridge": "Bridge purpose.", "shared": "Shared purpose."},
            "assessment": {
                "bridge@1.0.0": dict.fromkeys(REVIEW_FIELDS, "Scoped assessment.") | {
                    "archive_sha256": "a" * 64, "review_gaps": ["Independent review."]
                },
            },
        }

    def test_valid_inventory_keeps_missing_transitive_assessment_visible(self):
        snapshot = json.loads(compact_graph(self.graph))
        self.assertEqual(review_gaps(self.graph, snapshot, self.reviews), ({"bridge@1.0.0"}, ["shared@1.0.0"]))

    def test_rejects_changed_checksum_or_feature(self):
        for changes in ("checksum", "features"):
            with self.subTest(changes=changes):
                updated = copy.deepcopy(self.graph)
                if changes == "checksum":
                    updated["packages"]["bridge@1.0.0"]["archive_sha256"] = "c" * 64
                else:
                    updated["resolutions"]["test-target"][0]["inputs"]["shared@1.0.0"]["features"] = []
                with self.assertRaisesRegex(ValueError, "locked production graph differs"):
                    review_gaps(updated, self.graph, self.reviews)

    def test_rejects_stale_or_missing_direct_assessment(self):
        self.reviews["assessment"]["bridge@1.0.0"]["archive_sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "does not identify the locked archive"):
            review_gaps(self.graph, self.graph, self.reviews)
        self.reviews["assessment"].clear()
        with self.assertRaisesRegex(ValueError, "missing direct dependency assessments"):
            review_gaps(self.graph, self.graph, self.reviews)
