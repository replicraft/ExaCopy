"""Portable controls for the independent native frame oracle."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import oracle
from oracle_sign import Signer


class FrameControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform == "darwin":
            # Local-only control. Production preflight has a fixed native procfd launcher.
            binary = Path("/opt/homebrew/opt/openssl@3/bin/openssl").resolve(strict=True)
            signer = Signer(binary, "/dev/fd", trust_owner=False, exec_by_fd=False)
        else:
            signer = Signer()
        cls.addClassCleanup(signer.close)
        cls.checker = oracle.checked_preflight(Path.cwd(), signer)
        fixture = Path(__file__).with_name("positive-frame.json")
        capsule = json.loads(fixture.read_bytes())
        cls.frame, cls.expected, cls.result = (capsule[key] for key in ("frame", "expected", "result"))
        # This is fixed synthetic Linux dev_t, including when portable controls run on Darwin.
        devices = patch.multiple(oracle.os, major=lambda raw: (raw >> 8) & 0xfff,
                                 minor=lambda raw: raw & 255)
        devices.start()
        cls.addClassCleanup(devices.stop)

    def test_pinned_oracle_and_exact_frame_positive(self):
        result = self.checker.verify_frame(oracle.parse_frame(json.dumps(self.frame).encode()), self.expected)
        self.assertEqual(set(result), {"schema_version", "outcome", "member_count", "root_digest",
                                      "root_sha256", "intent_sha256"})
        self.assertEqual((result["schema_version"], result["outcome"], result["member_count"]), (1, "pass", 4))
        self.assertEqual(result, self.result)

    def test_only_missing_fixed_tool_is_blocked(self):
        with patch.object(oracle, "Signer", side_effect=FileNotFoundError):
            with self.assertRaises(oracle.OracleUnavailable):
                oracle.preflight()
        with patch.object(oracle, "Signer") as supplier:
            with patch.object(oracle, "checked_preflight", side_effect=ValueError("wrong known answer")):
                with self.assertRaisesRegex(ValueError, "wrong known answer"):
                    oracle.preflight()
            supplier.return_value.close.assert_called_once_with()

    def test_exact_json_schema_bounds_duplicate_and_number_types(self):
        exact = json.dumps(self.frame).encode()
        cases = {
            "oversize": b" " * (oracle.FRAME_BYTES + 1), "empty": b"", "trailing": exact + b"{}",
            "duplicate": b'{"version":1,' + exact[1:], "wrong_float": exact.replace(b'"version": 1', b'"version": 1.0'),
            "nan": exact.replace(b'"version": 1', b'"version": NaN'), "invalid_utf8": exact + b"\xff",
            "negative_zero": exact.replace(b'"version": 1', b'"version": -0'),
            "extra": b'{"unknown":1,' + exact[1:], "missing": b"{}",
        }
        for case, value in cases.items():
            with self.subTest(case=case), self.assertRaises(ValueError):
                oracle.parse_frame(value)

    def test_external_scope_and_exact_raw_paths_are_required(self):
        for key, wrong in (("pid", 1235), ("boot", "01234567-89ab-4cde-8f01-23456789abce"),
                           ("actor", [1001, 1003]), ("mount", 32), ("unique_mount", 0x1_0000_0002),
                           ("mount_namespace", "4:6"), ("user_namespace", "4:5"),
                           ("anchors", list(reversed(self.expected["anchors"]))),
                           ("fixture_parent", Path("/other/fixture"))):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.checker.verify_frame(self.frame, self.expected | {key: wrong})
        mutations = {"version": True, "fixture": "../outside", "owner": "00" * 32,
                     "owner_profile": "11" * 16, "scan": 30, "creation": [12, 20],
                     "subject_hex": "616263", "records": self.frame["records"][::-1],
                     "paths_hex": ["2f2e2e"] * 3, "participants": self.frame["participants"][::-1]}
        for key, wrong in mutations.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.checker.verify_frame(self.frame | {key: wrong}, self.expected)

    def test_same_size_member_mutation_stamp_or_intent_refuses(self):
        mutations = (
            ("signature", ("members", 0, 4), lambda raw: raw[:-10] + ("00" if raw[-10:-8] != "00" else "01") + raw[-8:]),
            ("commitment", ("members", 1, 3), lambda _: "aa" * 32),
            ("swap_endpoints", ("members",), lambda rows: [rows[0], rows[2], rows[1], rows[3]]),
            ("unsafe_mode", ("source_stamps", 0, 2), lambda mode: mode | 0o100),
            ("nlink", ("source_stamps", 1, 6), lambda _: 2),
            ("stamp_time", ("source_stamps", 0, 7, 0), lambda seconds: seconds + 1),
            ("overflow_native_time", ("source_stamps", 1, 8, 1), lambda _: 1_000_000_000),
            ("source_alias", ("source_stamps", 1, 1), lambda _: self.frame["source_stamps"][0][1]),
            ("stage_inode", ("intent_hex",), lambda raw: raw[:104] + "ff" + raw[106:]),
            ("raw_digest", ("intent_hex",), lambda raw: raw[:256] + "ff" + raw[258:]),
            ("enrollment", ("enrollment", 1), lambda _: "ff" * 32),
        )
        for label, path, change in mutations:
            frame = deepcopy(self.frame)
            node = frame
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = change(node[path[-1]])
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.checker.verify_frame(frame, self.expected)


if __name__ == "__main__":
    unittest.main()
