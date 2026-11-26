import unittest

import record_evidence


class RustGateFeatureTests(unittest.TestCase):
    def setUp(self):
        self.package = {"name": "example", "features": {"protocol": [], "strict": []}}
        self.obligation = {"id": "P-123", "rust": {"test": "tests::round_trip"}}

    def test_omitted_or_empty_features_preserve_the_legacy_command(self):
        expected = [
            "cargo", "nextest", "run", "--locked", "-p", "example",
            "--no-tests", "fail", "--", "--exact", "tests::round_trip",
        ]
        for features in ({}, {"features": []}):
            link = self.obligation["rust"] | features
            with self.subTest(features=features):
                self.assertEqual(record_evidence.gate_command("example", None, "rust", link), expected)

    def test_explicit_features_are_selected_before_the_exact_test_filter(self):
        link = self.obligation["rust"]
        link["features"] = ["protocol", "strict"]
        self.assertEqual(record_evidence.rust_features(self.package, self.obligation), ["protocol", "strict"])
        self.assertEqual(record_evidence.gate_command("example", None, "rust", link), [
            "cargo", "nextest", "run", "--locked", "-p", "example",
            "--no-default-features", "--features", "protocol,strict",
            "--no-tests", "fail", "--", "--exact", "tests::round_trip",
        ])

    def test_feature_list_refuses_duplicates_unknown_names_and_other_shapes(self):
        link = self.obligation["rust"]
        for features, error in (
            (["protocol", "protocol"], "duplicate Rust gate"),
            (["unknown"], "undeclared Rust gate"),
            (["protocol,strict"], "undeclared Rust gate"),
            (["--all-features"], "undeclared Rust gate"),
            ("protocol", "list of names"),
            ([7], "list of names"),
        ):
            with self.subTest(features=features), self.assertRaisesRegex(ValueError, error):
                link["features"] = features
                record_evidence.rust_features(self.package, self.obligation)


if __name__ == "__main__":
    unittest.main()
