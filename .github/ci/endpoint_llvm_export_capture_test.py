import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import endpoint_llvm_export_capture as delegate


class CaptureTest(unittest.TestCase):
    def test_capture_records_exact_input_order_and_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            tool, profile, first, second = [
                root / name for name in ("llvm-cov", "test.profdata", "lib-first", "lib-second")
            ]
            for path in (tool, profile, first, second):
                path.write_bytes(path.name.encode("ascii"))
            args = ["export", "-format=text", "-instr-profile=test.profdata", "-object", "lib-second",
                    "-object", "lib-first", "-ignore-filename-regex", "(^|/)tests/"]
            result = delegate.capture(args, tool, root, root)
            self.assertEqual(result["argv"], args)
            self.assertEqual([row["path"] for row in result["objects"]], [str(second), str(first)])
            self.assertEqual(result["tool"]["sha256"], hashlib.sha256(b"llvm-cov").hexdigest())
            self.assertEqual(result["indexed_profile"]["sha256"],
                             hashlib.sha256(b"test.profdata").hexdigest())
            self.assertEqual(result["ignore_filename_regex"], "(^|/)tests/")
            (root / "alias").symlink_to(first)
            for invalid in ("../lib-first", "alias", str(root.parent / "lib-first")):
                candidate = [*args[:6], invalid, *args[7:]]
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    delegate.capture(candidate, tool, root, root)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                delegate.capture([*args[:7], "-object", "lib-first", *args[7:]], tool, root, root)

    def test_capture_failure_does_not_change_forwarded_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            tool = root / "llvm-cov"
            inputs = {"EXACOPY_ENDPOINT_LLVM_EVIDENCE": str(root),
                      "EXACOPY_ENDPOINT_LLVM_TARGET": str(root)}
            args = ["export", "-object", "unknown"]
            with patch.object(delegate.os, "execv") as execute:
                delegate.forward(args, tool, inputs)
                execute.assert_called_once_with(tool, [str(tool), *args])
            self.assertTrue((root / "endpoint-llvm-export-failure-1.json").is_file())
            self.assertFalse((root / "endpoint-llvm-export-capture-1.json").exists())

    def test_pathlib_symlink_loop_still_forwards_original_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            tool = root / "llvm-cov"
            obj = root / "loop"
            obj.symlink_to(obj)
            inputs = {"EXACOPY_ENDPOINT_LLVM_EVIDENCE": str(root),
                      "EXACOPY_ENDPOINT_LLVM_TARGET": str(root)}
            args = ["export", "-format=text", "-instr-profile=test.profdata", "-object", str(obj),
                    "-ignore-filename-regex", "(^|/)tests/"]
            original_resolve = Path.resolve

            def resolve(path, *, strict):
                if path == obj:
                    raise RuntimeError("Symlink loop")
                return original_resolve(path, strict=strict)

            with patch.object(Path, "resolve", autospec=True, side_effect=resolve), \
                    patch.object(delegate.os, "execv") as execute:
                delegate.forward(args, tool, inputs)
                execute.assert_called_once_with(tool, [str(tool), *args])
            failure = root / "endpoint-llvm-export-failure-1.json"
            self.assertIn("coverage path could not be resolved", failure.read_text())
            self.assertFalse((root / "endpoint-llvm-export-capture-1.json").exists())

    def test_unsupported_object_shapes_never_emit_an_incomplete_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            tool = root / "llvm-cov"
            inputs = {"EXACOPY_ENDPOINT_LLVM_EVIDENCE": str(root),
                      "EXACOPY_ENDPOINT_LLVM_TARGET": str(root)}
            args = ["export", "-format=text", "-instr-profile=test.profdata", "-object", "other"]
            shapes = ([*args[:3], "positional-bin", *args[3:]],
                      [*args, "-summary-only"], [*args, "@response-file"])
            for index, candidate in enumerate(shapes, 1):
                with self.subTest(argv=candidate), patch.object(delegate.os, "execv") as execute:
                    delegate.forward(candidate, tool, inputs)
                    execute.assert_called_once_with(tool, [str(tool), *candidate])
                failure = root / f"endpoint-llvm-export-failure-{index}.json"
                self.assertIn("unsupported LLVM export arguments", failure.read_text())
            self.assertFalse((root / "endpoint-llvm-export-capture-1.json").exists())

    def test_unsafe_evidence_directories_do_not_receive_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            safe = root / "safe"
            safe.mkdir(mode=0o700)
            link = root / "link"
            link.symlink_to(safe, target_is_directory=True)
            shared = root / "shared"
            shared.mkdir(mode=0o755)
            shared.chmod(0o755)
            for path in (link, shared):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    delegate.record(path, {"phase": "test"}, "capture")
            with patch.object(delegate, "resolve_path", return_value=link), self.assertRaises(OSError):
                delegate.record(link, {"phase": "test"}, "capture")
            self.assertEqual(list(safe.iterdir()), [])
            self.assertEqual(list(shared.iterdir()), [])

    def test_tool_probe_passes_through_with_no_capture(self):
        tool = Path("/usr/bin/llvm-cov")
        with patch.object(delegate, "capture") as capture, patch.object(delegate.os, "execv") as execute:
            delegate.forward(["--version"], tool, {})
            capture.assert_not_called()
            execute.assert_called_once_with(tool, [str(tool), "--version"])


if __name__ == "__main__":
    unittest.main()
