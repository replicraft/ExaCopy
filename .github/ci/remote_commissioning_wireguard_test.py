from contextlib import nullcontext
from pathlib import Path
import hashlib
import json
import os
import stat
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

import remote_commissioning_wireguard as fixture
import remote_commissioning_wireguard_client as client
import campaign
import native_supervision as supervision
import remote_commissioning_peer as peer
from remote_retry_commissioning import COMMAND, RetryFixture
import remote_commissioning_wireguard_net as network
import remote_commissioning_wireguard_lane as lane
import remote_commissioning_wireguard_observations as observations
from remote_commissioning_peer import Blocked, Fixture
from native_supervision import CleanupUnconfirmed


class KernelFixtureTests(unittest.TestCase):
    def test_inactive_provider_stops_before_privileged_preflight(self):
        evidence = {}
        for status in ("packaged-but-unloaded", "absent", "unknown"):
            with (
                self.subTest(status=status),
                patch.dict(fixture.os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF_PROTECTED": "true"}),
                patch.object(fixture.provider, "report", return_value={"provider": status, "kernel": {}}),
                patch.object(fixture.direct, "preflight") as preflight,
            ):
                with self.assertRaisesRegex(Blocked, "no pre-existing active"):
                    fixture.execute(Path("/invalid"), Path("/invalid"), Path("/invalid"), evidence)
                preflight.assert_not_called()
                self.assertEqual(evidence["provider"]["provider"], status)

    def test_direct_retry_and_embedded_peer_keep_their_distinct_service_admission(self):
        for kind in ("direct", "retry", "embedded"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                selected = (RetryFixture if kind == "retry" else Fixture)("0" * 20, 1)
                private = root / f"exacopy-direct-{selected.nonce}/private"
                private.mkdir(parents=True)
                port = 2222
                namespace = root / "owned-network"
                route = {"kind": "embedded-wireguard"}
                embedded = kind == "embedded"
                listen = network.SERVER if embedded else "127.0.0.1"
                source = network.CLIENT if embedded else "127.0.0.1"
                start = RuntimeError("stop at service submission")
                argv = []

                def command(command_argv, **_options):
                    if command_argv[0] == peer.SSHD_KEYGEN:
                        Path(command_argv[-1]).touch()
                    elif command_argv[0] == peer.SYSTEMD_RUN:
                        argv.extend(command_argv)
                        raise start

                with (
                    patch.object(peer, "BASE", root),
                    patch.object(peer, "run", side_effect=command),
                    patch.object(peer, "checkpoint"),
                    patch.object(selected, "make_runtime"),
                    patch.object(peer, "public_key", return_value=(b"ssh-ed25519 AAAA", "hash")),
                    patch.object(peer, "select_port", return_value=port),
                    self.assertRaisesRegex(RuntimeError, str(start)),
                ):
                    if embedded:
                        selected.make_selected_peer(listen, port, source, namespace, route)
                    else:
                        Fixture.make_peer(selected)
                config = (private / "sshd_config").read_text()
                profile = json.loads((private / "ssh.json").read_text())
                self.assertIn(f"ListenAddress {listen}:{port}\n", config)
                self.assertIn(f"AllowUsers {selected.account}@{source}\n", config)
                self.assertTrue((private / "known_hosts").read_bytes().startswith(f"[{listen}]:{port} ".encode()))
                self.assertEqual(profile["route"], route if embedded else {
                    "kind": "direct", "endpoint": f"{listen}:{port}",
                })
                self.assertEqual([arg for arg in argv if isinstance(arg, str) and "NetworkNamespacePath=" in arg],
                                 [f"--property=NetworkNamespacePath={namespace}"] if embedded else [])
                self.assertIn("--property=CapabilityBoundingSet=" + (
                    "~CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_RAW" if embedded else "~CAP_SYS_ADMIN"
                ), argv)
                if kind == "retry":
                    self.assertIn(f"ForceCommand {COMMAND}\n", config)
                    self.assertTrue(any("/retry-input:norbind" in str(arg) for arg in argv))
                else:
                    self.assertIn("ForceCommand internal-sftp -R -d /\n", config)

    def test_mismatched_route_namespace_or_nonloopback_direct_refuses_before_effects(self):
        selected = Fixture("0" * 20, 1)
        with patch.object(peer, "run") as command, patch.object(selected, "make_runtime") as runtime:
            for listen, namespace, route in (
                (network.SERVER, None, {"kind": "embedded-wireguard"}),
                (network.SERVER, Path("/owned-network"), None),
                (network.SERVER, None, None),
            ):
                with self.subTest(listen=listen, namespace=namespace, route=route), self.assertRaises(Blocked):
                    selected.make_selected_peer(listen, 2222, "127.0.0.1", namespace, route)
            command.assert_not_called()
            runtime.assert_not_called()

    def test_each_wireguard_entrypoint_selects_only_its_hosted_event(self):
        for choice, program, events in (
            (fixture.ProviderChoice.EXISTING, "remote_commissioning_wireguard.py", ("workflow_dispatch",)),
            (fixture.ProviderChoice.HOSTED_AZURE_B, "remote_commissioning_wireguard_azure.py", ("push",)),
            (fixture.ProviderChoice.HOSTED_AWS_B, "remote_commissioning_wireguard_aws.py", ("push",)),
        ):
            with (
                self.subTest(choice=choice),
                patch.object(fixture.direct, "hosted_parent", side_effect=Blocked("host refusal")) as parent,
                patch.object(fixture, "execute") as execute,
            ):
                self.assertEqual(fixture.main(choice), 77)
                parent.assert_called_once_with(program, events)
                execute.assert_not_called()

    def test_provider_identity_must_match_exact_earlier_boot(self):
        with patch.object(fixture.provider, "report", return_value={"provider": "built-in", "kernel": {"boot": "second"}}):
            with self.assertRaisesRegex(Blocked, "changed"):
                fixture.check_provider({}, ({"boot": "first"}, "built-in"))

    def test_link_selection_refuses_same_name_with_foreign_identity(self):
        row = {"ifname": "owned", "ifalias": "anchor", "linkinfo": {"info_kind": "wireguard"}, "ifindex": 42}
        self.assertEqual(network.exact_link([row], "owned", "anchor"), 42)
        for rows in (
            [row | {"ifalias": "foreign"}], [row | {"linkinfo": {"info_kind": "dummy"}}], [row, row],
            [row | {"ifindex": True}], [],
        ):
            with self.assertRaises(CleanupUnconfirmed):
                network.exact_link(rows, "owned", "anchor")

    def test_pin_drift_refuses_net_enter_before_dispatch(self):
        keeper = network.Keeper(Fixture("0" * 20, 1), "client", Path("/invalid"))
        keeper.identity, keeper.mount_id = (1, 2), 30
        with patch.object(keeper, "measure_pin", return_value=((1, 2), 31)), patch.object(network, "unit_status") as status:
            with self.assertRaises(CleanupUnconfirmed):
                keeper.enter(network.IP, "link", "show")
            status.assert_not_called()

    def test_retained_exact_pin_produces_network_only_enter(self):
        keeper = network.Keeper(Fixture("0" * 20, 1), "client", Path("/invalid"))
        keeper.identity, keeper.mount_id, keeper.invocation = (1, 2), 30, "ab" * 16
        with (
            patch.object(keeper, "measure_pin", return_value=((1, 2), 30)),
            patch.object(network, "cgroup_present", return_value=True),
            patch.object(network, "unit_status", return_value={"InvocationID": keeper.invocation, "ActiveState": "active"}),
        ):
            self.assertEqual(
                keeper.enter(network.IP, "link", "show"),
                [network.NSENTER, f"--net={keeper.pin}", "--", network.IP, "link", "show"],
            )

    def test_missing_link_identity_prevents_all_cleanup_mutations(self):
        kernel = network.KernelPeer(Fixture("0" * 20, 1), Path("/invalid"), Path("/invalid"))
        kernel.link_attempted = True  # Ownership could not be established after an attempted syscall.
        with patch.object(kernel, "call") as command, patch.object(kernel.peer, "stop") as stop:
            with self.assertRaises(CleanupUnconfirmed):
                kernel.stop()
            command.assert_not_called()
            stop.assert_not_called()

    def test_keeper_command_failure_retains_primary_and_secondary_without_raw_output(self):
        self.check_keeper_report(uncertain=False)

    def test_keeper_ownership_uncertainty_retains_marker_and_skips_cleanup(self):
        self.check_keeper_report(uncertain=True)

    def check_keeper_report(self, *, uncertain):
        with tempfile.TemporaryDirectory() as scratch:
            parent = Path(scratch)
            root = parent / "synthetic-private-path"
            owned = Mock(root=root, nonce="0" * 20, account="synthetic-account", unit="synthetic-unit")
            original_lstat = Path.lstat
            injected_output = b"synthetic-secret-from-command"

            def fixture_stat(path):
                if path == root / "wg":
                    return SimpleNamespace(st_uid=0, st_nlink=1, st_mode=stat.S_IFREG)
                return original_lstat(path)

            def refuse(_argv, transcript, _deadline, **_options):
                transcript.write_bytes(injected_output)
                if uncertain:
                    raise CleanupUnconfirmed(injected_output.decode())
                return supervision.ProcessResult("exited", 19)

            with (
                patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF_PROTECTED": "true",
                                        "GITHUB_SHA": "a" * 40}),
                patch.object(fixture.direct, "hosted_parent", return_value=parent),
                patch.object(fixture.signal, "signal"),
                patch.object(fixture, "check_provider", return_value=({}, "built-in")),
                patch.object(fixture.direct, "preflight", return_value=1),
                patch.object(fixture, "Fixture", return_value=owned),
                patch.object(fixture, "staged_tool", side_effect=lambda _parent, name: root / name),
                patch.object(fixture, "file_digest", return_value="b" * 64),
                patch.object(fixture.native, "source_identity", return_value={"revision": "a" * 40}),
                patch.object(fixture.native, "build_environment", return_value={}),
                patch.object(fixture.native, "fresh_target", return_value=nullcontext()),
                patch.object(fixture.native, "build_cli", return_value=(root / "binary", root / "manifest")),
                patch.object(fixture.direct, "read_build_manifest", return_value=({}, "c" * 64)),
                patch.object(fixture.direct, "verify_build_custody"),
                patch.object(fixture, "command"),
                patch.object(network, "unit_known", return_value=False),
                patch.object(network, "logged_command", side_effect=refuse),
                patch.object(Path, "lstat", fixture_stat),
            ):
                self.assertEqual(fixture.main(), 77)

            job = parent / fixture.JOB
            report = job / "report"
            self.assertTrue((report / "cleanup-unconfirmed.json").is_file())
            self.assertTrue((job / "private").is_dir())
            self.assertEqual(list((job / "private").glob("kernel-peer-*")), [])
            if uncertain:
                owned.stop_peer.assert_not_called()
            else:
                owned.stop_peer.assert_called_once()
            owned.stop.assert_not_called()
            raw = (report / "provider.json").read_bytes()
            for protected in (injected_output, os.fsencode(root), b"/usr/bin/sleep", b"synthetic-account"):
                self.assertNotIn(protected, raw)
            evidence = json.loads(raw)
            self.assertTrue(evidence["cleanup_unconfirmed"])
            primary = ({"kind": "ownership-unconfirmed"} if uncertain else
                       {"kind": "command", "status": "exited", "exit_status": 19})
            cleanup = ({"disposition": "held-uncertain"} if uncertain else {
                "disposition": "failed", "step": {"code": "keeper-stop", "role": "client"},
                "last_completed": {"code": "ssh-stop"}, "failure": {"kind": "ownership-unconfirmed"},
            })
            self.assertEqual(evidence["fixture_progress"], {
                "setup": {"disposition": "failed", "step": {"code": "keeper-start", "role": "client"},
                          "last_completed": {"code": "keeper-admission", "role": "client"},
                          "failure": primary},
                "cleanup": cleanup,
            })

    def test_peer_pin_query_refusal_records_only_bounded_status(self):
        with tempfile.TemporaryDirectory() as scratch:
            keeper = network.Keeper(Fixture("0" * 20, 1), "peer", Path(scratch))

            def supervise(argv, transcript, _deadline, **_options):
                if network.STAT in argv:
                    transcript.write_bytes(b"20:42\n")
                    return supervision.ProcessResult("exited", 0)
                transcript.write_bytes(b"synthetic-protected-stdout")
                return supervision.ProcessResult("output-limit", -15)

            with patch.object(network, "logged_command", side_effect=supervise):
                with self.assertRaises(Blocked) as failed:
                    keeper.measure_pin(setup_trace=True)
            keeper.setup.failed(failed.exception)
            self.assertEqual(keeper.setup.evidence, {
                "disposition": "failed", "step": {"code": "pin-mount-query", "role": "peer"},
                "last_completed": {"code": "pin-stat", "role": "peer"},
                "failure": {"kind": "command", "status": "output-limit", "exit_status": -15,
                            "operation": "pin-mount-query"},
            })
            self.assertEqual(list(Path(scratch).iterdir()), [])

    def test_client_group_ambiguity_does_not_stop_a_replacement(self):
        client = lane.ClientLane("owned.service", Path("/invalid"), 20, attempted=True, invocation="original", group=(1, 2))
        with (
            patch.object(lane, "cgroup_present", return_value=True),
            patch.object(lane, "unit_known", return_value=True),
            patch.object(lane, "unit_status", return_value={"InvocationID": "replacement"}),
            patch.object(lane, "run") as run,
        ):
            with self.assertRaises(CleanupUnconfirmed):
                client.stop()
            run.assert_not_called()

    def test_client_group_requires_a_confirmed_drain(self):
        client = lane.ClientLane("owned.service", Path("/invalid"), 20, attempted=True, invocation="original", group=(1, 2))
        with (
            patch.object(lane, "cgroup_present", return_value=True),
            patch.object(lane, "unit_known", return_value=True),
            patch.object(lane, "unit_status", return_value={
                "InvocationID": "original", "ControlGroup": "/system.slice/owned.service",
            }),
            patch.object(lane, "run") as stop,
            patch.object(lane, "cgroup_drained", return_value=False),
        ):
            with self.assertRaises(CleanupUnconfirmed):
                client.stop()
            self.assertEqual(stop.call_args.args[0], [lane.SYSTEMCTL, "stop", "--", "owned.service"])

    def test_per_case_traffic_needs_matching_bidirectional_progress(self):
        initial = observations.Counters(0, 0, 0, None)
        exchange = observations.Counters(96, 112, 1760000000, "127.0.0.1:49152")
        observations.check_delta(initial, initial, 0)
        observations.check_delta(initial, exchange, 1)
        for before, after, expected in (
            (initial, exchange, 0), (exchange, exchange, 1), (initial, observations.Counters(96, 0, 1, None), 1),
            (initial, exchange, 2),
        ):
            with self.assertRaises(Blocked):
                observations.check_delta(before, after, expected)

    def test_public_telemetry_rejects_wrong_peer_and_non_loopback_endpoint(self):
        key = "01" * 32
        import base64
        selected = base64.b64encode(bytes.fromhex(key))
        fields = {
            "transfer": selected + b"\t32\t48\n",
            "latest-handshakes": selected + b"\t12\n",
            "endpoints": selected + b"\t127.0.0.1:2223\n",
        }
        peer = SimpleNamespace(client_public=key, field=fields.__getitem__)
        self.assertEqual(observations.snapshot(peer), observations.Counters(32, 48, 12, "127.0.0.1:2223"))
        fields["endpoints"] = selected + b"\t192.0.2.1:2223\n"
        with self.assertRaises(Blocked):
            observations.snapshot(peer)
        fields["transfer"] = fields["transfer"] * 2
        with self.assertRaises(Blocked):
            observations.snapshot(peer)

    def test_observer_refuses_unexpected_case_before_creating_file(self):
        with tempfile.TemporaryDirectory() as scratch:
            mailbox = Path(scratch)
            record = observations.observe_case(mailbox)
            with self.assertRaises(Blocked):
                record("resume", 1)
            self.assertFalse(list(mailbox.iterdir()))

    def test_latched_cancellation_stops_new_work_but_runs_bounded_cleanup(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            with patch.object(supervision, "CANCELLATION_REQUESTED", True):
                effect = [sys.executable, "-c", "print('owned teardown')"]
                cancelled = supervision.logged_command(effect, root / "setup.log", 3)
                self.assertEqual(cancelled.status, "interrupted")
                self.assertEqual((root / "setup.log").read_bytes(), b"")
                cleanup = supervision.logged_cleanup_command(effect, root / "teardown.log", 3, output_limit=32)
                self.assertTrue(cleanup.passed())
                self.assertEqual((root / "teardown.log").read_bytes(), b"owned teardown\n")
                too_large = supervision.logged_cleanup_command(effect, root / "capped.log", 3, output_limit=4)
                self.assertEqual(too_large.status, "output-limit")
                self.assertEqual((root / "capped.log").read_bytes(), b"owne")
                self.assertTrue(supervision.CANCELLATION_REQUESTED)

    def test_torn_down_link_probes_and_deletion_use_only_cleanup_lane(self):
        kernel = network.KernelPeer(Fixture("0" * 20, 1), Path("/invalid"), Path("/invalid"))
        kernel.link_attempted, kernel.location, kernel.ifindex, kernel.port = True, kernel.peer, 42, 51820
        with (
            patch.object(kernel, "recheck_link") as recheck,
            patch.object(kernel, "links", return_value=[]) as links,
            patch.object(kernel, "call", side_effect=(b"", b"[]", b"")) as call,
            patch.object(kernel.peer, "stop") as stop_peer,
            patch.object(kernel.client, "stop") as stop_client,
        ):
            kernel.stop()
            recheck.assert_called_once_with(cleanup=True)
            self.assertTrue(all(c.kwargs == {"cleanup": True} for c in links.call_args_list))
            self.assertTrue(all(c.kwargs == {"cleanup": True} for c in call.call_args_list))
            self.assertEqual(call.call_args_list[0].args[-4:], ("link", "delete", "dev", kernel.name))
            stop_peer.assert_called_once()
            stop_client.assert_called_once()

    def test_carrier_down_enters_actual_protected_preflight_with_retained_objects(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            destination = root / "destination"
            destination.mkdir(mode=0o700)
            for name in ("complete", "incumbent", "interrupted"):
                (destination / name).write_bytes(b"keep")
            for name in ("first-job", "resumed-job"):
                folder = destination / name / "journal"
                folder.mkdir(parents=True)
                (folder / "segment").write_bytes(b"retained journal")
            owner = root / "owner"
            owner.mkdir(mode=0o700)
            binary = root / "exacopy"
            binary.write_bytes(b"\x7fELFsample")
            binary.chmod(0o700)
            inputs = {
                "destination": destination, "owner-profile": owner, "binary": binary,
                **{name: root / name for name in (
                    "qualification", "trust", "ssh-profile", "source-small", "source-interrupt", "sshd-log",
                )},
            }
            for name in ("qualification", "source-small", "source-interrupt", "sshd-log"):
                inputs[name].write_bytes(b"bounded fixture")
                inputs[name].chmod(0o600)
            inputs["trust"].write_text(json.dumps({"route": fixture.native.EMBEDDED, "build": "one-build"}))
            inputs["ssh-profile"].write_text(json.dumps({
                "host": network.SERVER, "port": network.SSH_PORT, "account": "fixture", "maximum_extent": 512,
                "route": {"kind": "embedded-wireguard", "outer": "127.0.0.1:51820",
                          "local_inner": network.CLIENT, "remote_inner": f"{network.SERVER}:{network.SSH_PORT}"},
            }))
            boot_file = root / "boot"
            boot_file.write_text("fixture-boot")
            evidence = root / "retained.json"
            evidence.write_text(json.dumps(client.retained_namespace(campaign, destination)))
            real_path = Path

            def paths(value):
                if value == "/proc/self/ns/mnt":
                    return root
                if value == "/proc/sys/kernel/random/boot_id":
                    return boot_file
                return real_path(value)

            with (
                patch.object(campaign.sys, "platform", "linux"),
                patch.object(campaign.platform, "machine", return_value="x86_64"),
                patch.object(campaign, "git", return_value=""),
                patch.object(campaign.shutil, "which", side_effect=lambda name: name),
                patch.object(campaign.subprocess, "run", return_value=SimpleNamespace(
                    stdout=b'{"filesystems":[{"fstype":"ext4","fsroot":"/","options":"rw"}]}',
                )),
                patch.object(campaign, "Path", side_effect=paths),
                patch.object(campaign, "digest_executable", return_value=("one-build", "elf")),
                patch.object(campaign, "b3", return_value="record-digest"),
                patch.object(campaign, "run_case", return_value={
                    "publication": "not_published", "error": {"code": "E_IO"},
                }) as get,
            ):
                with self.assertRaises(campaign.Blocked):
                    campaign.empty_destination(destination)
                self.assertEqual(client.carrier_down(campaign, inputs, root / "observed", evidence), 0)
                get.assert_called_once()
                self.assertEqual(get.call_args.args[2:], (
                    ("get",), (f"fixture@{network.SERVER}:{inputs['source-small']}", destination / "carrier-down"), 4,
                ))
                get.reset_mock()
                (destination / "first-job" / "journal" / "segment").write_bytes(b"replaced same kind")
                with self.assertRaisesRegex(campaign.Failed, "exact retained namespace changed"):
                    client.carrier_down(campaign, inputs, root / "changed", evidence)
                get.assert_not_called()

    def test_kernel_evidence_exports_only_exact_bounded_paths(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            work, report = root / "work", root / "report"
            work.mkdir()
            report.mkdir()
            data = b"independent fixture output"
            for relative in (
                *fixture.EXTRA_EVIDENCE, "carrier-down/carrier-down.stderr", "lane-campaign/private-key",
            ):
                path = work / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            hashes = fixture.export(work, report)
            self.assertEqual(hashes, {relative: hashlib.sha256(data).hexdigest() for relative in fixture.EXTRA_EVIDENCE})
            self.assertFalse((report / "carrier-down/carrier-down.stderr").exists())
            self.assertFalse((report / "lane-campaign/private-key").exists())

    def test_passing_outcome_requires_each_exact_kernel_artifact(self):
        required = list(fixture.EXTRA_EVIDENCE)
        self.assertEqual(len(required), 7)

        def report_for(outcome, missing=None):
            with tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch).resolve()

                def complete(parent, work, report, evidence):
                    for relative in required:
                        if relative == missing:
                            continue
                        path = work / relative
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(b"fixture evidence")
                    return outcome

                with (
                    patch.object(fixture.direct, "hosted_parent", return_value=root),
                    patch.object(fixture, "execute", side_effect=complete),
                    patch.object(fixture.signal, "signal"),
                ):
                    status = fixture.main()
                path = root / fixture.JOB / "report/provider.json"
                return status, json.loads(path.read_text())

        status, report = report_for(0)
        self.assertEqual((status, report["status"]), (0, "pass"))
        self.assertEqual(set(report["artifacts_sha256"]), set(required))
        for missing in required:
            with self.subTest(missing=missing):
                status, report = report_for(0, missing)
                self.assertEqual((status, report["status"], report["exit_status"]), (77, "blocked", 77))
                self.assertEqual(report["missing_artifacts"], [missing])
                self.assertEqual(set(report["artifacts_sha256"]), set(required) - {missing})

        for outcome, label in ((1, "fail"), (77, "blocked")):
            status, report = report_for(outcome, required[0])
            self.assertEqual((status, report["status"]), (outcome, label))
            self.assertNotIn("missing_artifacts", report)
            self.assertEqual(len(report["artifacts_sha256"]), 6)

    def test_client_stop_io_failure_preserves_identity_and_uncertainty(self):
        with tempfile.TemporaryDirectory() as scratch:
            unit = SimpleNamespace(unit="test.service", invocation="one", group=(9, 10), attempted=True)
            work = Path(scratch)
            with (
                patch.object(fixture, "ClientLane", return_value=unit),
                patch.object(fixture, "wait_file", return_value=True),
                patch.object(fixture, "file_signal"),
                patch.object(unit, "start", create=True),
                patch.object(unit, "wait", create=True),
                patch.object(unit, "stop", create=True, side_effect=OSError("stop failed")),
            ):
                with self.assertRaisesRegex(CleanupUnconfirmed, "lane cleanup is unconfirmed"):
                    fixture.run_client(Fixture("0" * 20, 1), work, "campaign", [], 10)
            facts = json.loads((work / "lane-campaign/identity.json").read_text())
            self.assertEqual(facts, {"unit": "test.service", "invocation": "one", "cgroup": [9, 10]})
            disposition = json.loads((work / "lane-campaign/disposition.json").read_text())
            self.assertEqual(disposition, facts | {"cleanup": "unconfirmed"})

    def test_exact_independent_route_revision_bytes(self):
        route = {
            "outer": "127.0.0.1:51820", "remote_inner": "198.18.0.1:2222",
            "local_inner": "198.18.0.2", "outer_mtu": 1500,
            "local_public_key": "01" * 32, "peer_public_key": "02" * 32,
        }
        domain = b"ExaCopy/ssh-profile/embedded-route/v2\0"
        suffix = bytes.fromhex("047f000001 ca6c 05dc 04c6120002 04c6120001 08ae")
        with patch.object(fixture, "run", return_value=b"a" * 64 + b"\n") as b3:
            self.assertEqual(fixture.route_revision(route, Path("/fixture/b3sum")), "a" * 64)
            self.assertEqual(b3.call_args.kwargs["data"], domain + bytes([1] * 32 + [2] * 32) + suffix)


if __name__ == "__main__":
    unittest.main()
