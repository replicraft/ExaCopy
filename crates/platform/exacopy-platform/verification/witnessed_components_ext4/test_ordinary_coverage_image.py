import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import ordinary_coverage_image as image


class OrdinaryCoverageImage(unittest.TestCase):
    def setUp(self):
        self.target = Path("/checked/repository/target/llvm-cov-target")
        layout = "debug/build/exacopy-platform/{tag}/out/exacopy_platform-{tag}"
        self.expected = {"path": str(self.target / layout.format(tag="975b089c24cb6b2e"))}
        self.other = {"path": str(self.target / layout.format(tag="015b089c24cb6b2e"))}
        self.integration = {"path": self.expected["path"].replace("exacopy_platform-", "linux_stage-")}

    def test_selects_only_unique_exact_library_layout(self):
        self.assertEqual(image.platform_unit([self.integration, self.expected], self.target), self.expected)
        for objects in ([self.integration], [self.expected, self.other], [self.expected, {"path": "/other"}]):
            with self.subTest(objects=objects), self.assertRaises(ValueError):
                image.platform_unit(objects, self.target)

    def test_receipts_require_same_bytes_and_exact_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            first, second = (root / name for name in image.CAPTURES)
            first.write_bytes(b"capture")
            second.write_bytes(b"capture")
            with image.held_capture_pair(root) as read_pair:
                self.assertEqual(read_pair(), b"capture")
            second.write_bytes(b"other")
            with image.held_capture_pair(root) as read_pair, self.assertRaisesRegex(ValueError, "receipts differ"):
                read_pair()
            second.unlink()
            second.symlink_to(first)
            with self.assertRaises(OSError), image.held_capture_pair(root):
                self.fail("opened a symlinked receipt")
            second.unlink()
            second.write_bytes(b"capture")
            (root / "unexpected").touch()
            with self.assertRaisesRegex(ValueError, "directory or inventory changed"), image.held_capture_pair(root):
                self.fail("opened an unexpected inventory")

    def test_replacing_held_directory_or_receipt_with_same_bytes_refuses(self):
        for replaced in ("directory", "receipt"):
            with self.subTest(replaced=replaced), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory).resolve()
                root = parent / "receipts"
                root.mkdir(mode=0o700)
                for name in image.CAPTURES:
                    (root / name).write_bytes(b"same bytes")
                with image.held_capture_pair(root) as read_pair:
                    self.assertEqual(read_pair(), b"same bytes")
                    if replaced == "directory":
                        root.rename(parent / "original")
                        root.mkdir(mode=0o700)
                        for name in image.CAPTURES:
                            (root / name).write_bytes(b"same bytes")
                    else:
                        first = root / image.CAPTURES[0]
                        first.rename(parent / "original")
                        first.write_bytes(b"same bytes")
                    with self.assertRaisesRegex(ValueError, "changed"):
                        read_pair()

    def test_replay_rejects_changed_objects_tool_and_target(self):
        value = {"argv": ["export"], "objects": [self.expected], "tool": {"sha256": "original"},
                 "campaign_target": str(self.target)}
        raw = (json.dumps(value, sort_keys=True) + "\n").encode("ascii")
        replay = Mock(return_value=value)
        collector = SimpleNamespace(__file__=str(image.COLLECTOR), capture=replay)
        tool = Path("/trusted/llvm-cov")
        self.assertEqual(image.verify_capture(collector, raw, tool, self.target), self.expected)
        replay.assert_called_once_with(value["argv"], tool, image.run.ROOT, self.target)
        for changed in ({"objects": [self.other]}, {"tool": {"sha256": "changed"}},
                        {"campaign_target": "/different"}, {"schema": True}):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "binding changed"):
                replay.return_value = value | changed
                image.verify_capture(collector, raw, tool, self.target)


if __name__ == "__main__":
    unittest.main()
