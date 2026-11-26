"""Portable source, closure, admission and submission controls for provider B."""
from copy import deepcopy
import io
import json
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import remote_commissioning_wireguard as fixture
from remote_commissioning_wireguard import provider_b as azure
from native_supervision import CleanupUnconfirmed, ProcessResult
from remote_commissioning_peer import Blocked


BOOT = {
    "release": azure.RELEASE, "build": azure.BUILD, "architecture": "x86_64",
    "boot_id": "2ca9d1d8-9ffc-4b88-b5a8-3c6e6f7c8a90",
}


def observed():
    facts = {
        "booted_kernel_package": azure.package_record(azure.IMAGE),
        "module_listing_before": {"status": "absent"},
        "module_listing_after": {"status": "absent"},
        "module_initstate": {"status": "missing"},
    }
    for name, path, token in (
        ("config", azure.CONFIG, "module"),
        ("builtin_inventory", azure.BUILTIN, "absent"),
        ("module_file", azure.MODULES["wireguard"], "packaged"),
    ):
        facts[name] = azure.package_record(azure.PACKAGE) | {"status": token, "sha256": azure.EXPECTED[path]}
    return {
        "schema": "exacopy.hosted-wireguard-provider-observation.v2", "kernel": BOOT.copy(),
        "provider": "packaged-but-unloaded", "observations": facts,
    }


def module(name, *depends, signer="Ubuntu"):
    return azure.Module(name, "1" * 64, depends, azure.RELEASE + " SMP", signer)


def plan(*names):
    return "".join(f"insmod {azure.MODULES[name]}\n" for name in names).encode()


class AzureProviderTests(unittest.TestCase):
    def test_exact_unloaded_boot_and_package_hashes_are_required(self):
        accepted = observed()
        self.assertEqual(azure.admit(accepted), BOOT)
        for scope, key, value in (
            ((), "provider", "unknown"), ((), "provider", "already-live"),
            (("kernel",), "release", "7.0.0-1014-aws"),
            (("kernel",), "build", "a different build"),
            (("observations", "booted_kernel_package"), "package", "unknown"),
            (("observations", "module_initstate"), "status", "live"),
            (("observations", "config"), "sha256", "0" * 64),
            (("observations", "builtin_inventory"), "status", "present"),
            (("observations", "module_file"), "version", "same ABI, different bits"),
        ):
            with self.subTest(scope=scope, key=key):
                changed = deepcopy(accepted)
                selected = changed
                for item in scope:
                    selected = selected[item]
                selected[key] = value
                with self.assertRaises(Blocked):
                    azure.admit(changed)

    def test_default_and_unbound_push_never_enter_provider_b(self):
        for event, workflow in (("workflow_dispatch", azure.WORKFLOW_REF), ("push", "foreign")):
            with (
                patch.dict(fixture.os.environ, {
                    "GITHUB_EVENT_NAME": event, "GITHUB_WORKFLOW_REF": workflow,
                    "GITHUB_WORKFLOW_SHA": "a" * 40, "GITHUB_SHA": "a" * 40,
                }),
                patch.object(azure, "prepare") as prepare,
                patch.object(fixture.provider, "report") as report,
            ):
                with self.assertRaises(Blocked):
                    fixture.execute(Path("/invalid"), Path("/invalid"), Path("/invalid"), {}, fixture.ProviderChoice.HOSTED_AZURE_B)
                prepare.assert_not_called()
                report.assert_not_called()
        with (
            patch.dict(fixture.os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF_PROTECTED": "true"}),
            patch.object(fixture.provider, "report", return_value=observed()),
            patch.object(azure, "prepare") as prepare,
        ):
            with self.assertRaises(Blocked):
                fixture.execute(Path("/invalid"), Path("/invalid"), Path("/invalid"), {})
            prepare.assert_not_called()

    def test_verified_kmod_order_matches_exact_elf_closure(self):
        good = {
            "wireguard": module("wireguard", "ip6_udp_tunnel", "libcurve25519"),
            "ip6_udp_tunnel": module("ip6_udp_tunnel", "udp_tunnel"),
            "udp_tunnel": module("udp_tunnel"),
            "libcurve25519": module("libcurve25519"),
        }
        exact = plan("udp_tunnel", "libcurve25519", "ip6_udp_tunnel", "wireguard")
        self.assertEqual(azure.closure_order(good, exact), ["udp_tunnel", "libcurve25519", "ip6_udp_tunnel", "wireguard"])
        for graph, proposed in (
            (good, plan("ip6_udp_tunnel", "udp_tunnel", "libcurve25519", "wireguard")),
            (good, plan("udp_tunnel", "ip6_udp_tunnel", "wireguard")),
            (good, exact.replace(b"insmod", b"install", 1)),
            (good, exact.replace(b"/lib/modules", b"/tmp/modules", 1)),
            (good, exact.replace(b".ko.zst\n", b".ko.zst foo=1\n", 1)),
            (good, exact + plan("wireguard")),
            (good | {"udp_tunnel": module("udp_tunnel", "wireguard")}, exact),
            (good | {"udp_tunnel": module("udp_tunnel", signer="other")}, exact),
        ):
            with self.subTest(plan=proposed):
                with self.assertRaises(Blocked):
                    azure.closure_order(graph, proposed)

    def test_only_exact_regular_archive_members_are_selected(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)
            member = azure.MODULES["wireguard"]
            for label, types in (("good", (tarfile.REGTYPE,)), ("duplicate", (tarfile.REGTYPE,) * 2),
                                 ("usrmerge", (tarfile.REGTYPE,)), ("both-spellings", (tarfile.REGTYPE,) * 2),
                                 ("alias", (tarfile.SYMTYPE,))):
                archive = root / f"{label}.tar"
                stage = root / label
                stage.mkdir()
                with tarfile.open(archive, "w") as output:
                    for index, kind in enumerate(types):
                        merged = label == "usrmerge" or label == "both-spellings" and index == 1
                        header = tarfile.TarInfo(f"./usr{member}" if merged else f".{member}")
                        header.type = kind
                        if kind == tarfile.REGTYPE:
                            header.size = 4
                        output.addfile(header, io.BytesIO(b"test"))
                if label in {"good", "usrmerge"}:
                    actual = azure.extract_selected(archive, stage, [member])
                    self.assertEqual(actual[member].read_bytes(), b"test")
                else:
                    with self.assertRaises(Blocked):
                        azure.extract_selected(archive, stage, [member])

    def test_pinned_archive_mismatch_never_opens_package_or_tar_process(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)
            candidate = root / azure.ARCHIVE
            candidate.write_bytes(b"different")
            with patch.object(azure, "read_command") as query, patch.object(azure, "logged_command") as unpack:
                with self.assertRaisesRegex(Blocked, "archive differs"):
                    azure.archived_sources(candidate, root)
                query.assert_not_called()
                unpack.assert_not_called()

    def test_module_metadata_requires_exact_abi_signer_and_closed_dependency(self):
        sample = [b"wireguard\n", b"udp_tunnel\n", (azure.RELEASE + " SMP\n").encode(), b"Ubuntu\n", b"PKCS#7\n"]
        with patch.object(azure, "read_command", side_effect=sample):
            self.assertEqual(azure.module_metadata(Path("/fixture"), "wireguard", Path("/candidate"), "a"), azure.Module(
                "wireguard", "a", ("udp_tunnel",), azure.RELEASE + " SMP", "Ubuntu",
            ))
        for index, replacement in ((1, b"foreign\n"), (2, b"foreign ABI\n"), (3, b"\n"), (4, b"none\n")):
            changed = sample[:]
            changed[index] = replacement
            with patch.object(azure, "read_command", side_effect=changed):
                with self.assertRaises(Blocked):
                    azure.module_metadata(Path("/fixture"), "wireguard", Path("/candidate"), "a")

    def test_unconfirmed_read_only_child_keeps_its_private_scratch(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)

            def unresolved(_argv, log, _seconds, **_options):
                log.write_bytes(b"partial bounded result")
                raise CleanupUnconfirmed("injected child uncertainty")

            with patch.object(azure, "logged_command", side_effect=unresolved):
                with self.assertRaises(CleanupUnconfirmed):
                    azure.read_command(root, "bounded package query", [azure.DPKG_DEB])
            (log,) = root.glob("provider-b-read-*/output")
            self.assertEqual(log.read_bytes(), b"partial bounded result")

    def test_attempt_is_sticky_before_fixed_command_and_result_preserved(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)
            selected = root / "pinned.ko.zst"

            def refused(argv, path, seconds, *, env, output_limit):
                marker = json.loads((root / "provider-b-0-attempt.json").read_text())
                self.assertEqual(marker, {"name": "wireguard", "sha256": "a", "effect": "submitted-or-uncertain"})
                self.assertEqual(argv[-2:], [azure.INSMOD, selected])
                self.assertEqual(seconds, 15)
                self.assertEqual(output_limit, 64 * 1024)
                self.assertNotIn("--force", argv)
                return ProcessResult("exited", 1)

            with (
                patch.object(azure, "hosted_scope"),
                patch.object(azure, "logged_command", side_effect=refused) as runner,
            ):
                with self.assertRaises(Blocked):
                    azure.load_once(selected, root, 0, "wireguard", "a", 15)
                with self.assertRaises(FileExistsError):
                    azure.load_once(selected, root, 0, "wireguard", "a", 15)
                runner.assert_called_once()
            self.assertEqual(json.loads((root / "provider-b-0-result.json").read_text())["exit_status"], 1)

    def test_closed_execution_checks_all_custody_then_stops_after_first_uncertainty(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)
            modules = {"wireguard": module("wireguard", "udp_tunnel"), "udp_tunnel": module("udp_tunnel")}
            order = ["udp_tunnel", "wireguard"]
            selected = {azure.MODULES[name]: root / f"{name}.input" for name in order}
            for mode in ("success", "load-failure", "wrong-boot"):
                with self.subTest(mode=mode):
                    current = {name: "absent" for name in order}
                    evidence = {"tools_sha256": {path: "1" * 64 for path in (azure.SUDO, azure.SET_PRIV, azure.INSMOD)}}
                    _boot = observed() if mode != "wrong-boot" else {}
                    run = []

                    def load(_path, _report, _number, name, _sha, _budget):
                        run.append(name)
                        if mode == "load-failure":
                            raise CleanupUnconfirmed("injected child uncertainty")
                        current[name] = "live"

                    with (
                        patch.object(azure, "command"),
                        patch.object(azure, "directory_identity", return_value=(5, 10)),
                        patch.object(azure, "checked_hash", return_value="1" * 64),
                        patch.object(Path, "resolve", return_value=Path("/synthetic/tool")),
                        patch.object(azure, "checkpoint"),
                        patch.object(azure, "recheck_boot"),
                        patch.object(azure.provider, "report", return_value=_boot),
                        patch.object(azure, "live_state", side_effect=current.__getitem__),
                        patch.object(azure, "load_once", side_effect=load),
                    ):
                        invoke = lambda: azure.stage_load(root, root, root, (5, 10), selected, modules, order, BOOT, evidence)
                        if mode == "success":
                            invoke()
                            self.assertEqual(run, order)
                            self.assertTrue(evidence["loaded"])
                        elif mode == "load-failure":
                            with self.assertRaises(CleanupUnconfirmed):
                                invoke()
                            self.assertEqual(run, ["udp_tunnel"])
                            self.assertEqual(evidence["disposition"], {"udp_tunnel": "submitted-or-uncertain"})
                            self.assertEqual(evidence["last_observed_after_failure"], {"module": "udp_tunnel", "state": "absent"})
                        else:
                            with self.assertRaises(Blocked):
                                invoke()
                            self.assertFalse(run)


if __name__ == "__main__":
    unittest.main()
