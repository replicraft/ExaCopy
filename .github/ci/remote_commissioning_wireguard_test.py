from contextlib import nullcontext
from dataclasses import asdict
import errno
from pathlib import Path
import hashlib
import json
import os
import socket
import stat
import struct
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
import remote_commissioning_wireguard_orphan as orphan
import remote_commissioning_wireguard_tcp as tcp
from remote_commissioning_wireguard_progress import failure
from remote_commissioning_peer import Blocked, Fixture
from native_supervision import CleanupUnconfirmed, ProcessResult


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
        network.exact_link([row], "owned", 42, "anchor")
        for rows, predicate in (
            ([row | {"ifalias": "foreign"}], "link-alias-match"),
            ([row | {"linkinfo": {"info_kind": "dummy"}}], "link-kind"),
            ([row, row], "link-name"), ([row | {"ifindex": True}], "link-index"), ([], "link-name"),
            ([row, row | {"ifname": "duplicate-index"}], "link-index"),
        ):
            with self.assertRaises(CleanupUnconfirmed) as error:
                network.exact_link(rows, "owned", 42, "anchor")
            self.assertEqual(failure(error.exception)["predicate"], predicate)

    def test_link_birth_proves_exclusive_index_before_alias_and_never_removes_ambiguity(self):
        for condition, predicate, create, alias in (
            ("created", None, True, True),
            ("occupied", "namespace-vacancy", False, False),
            ("wrong-name", "link-name", True, False),
            ("wrong-kind", "link-kind", True, False),
            ("wrong-index", "link-index", True, False),
            ("foreign-alias", "link-alias-unset", True, False),
            ("keeper-lost", "namespace-keeper", True, False),
            ("alias-error", "link-effect-unconfirmed", True, True),
            ("alias-missing", "link-alias-match", True, True),
        ):
            with self.subTest(condition=condition):
                self.check_birth(condition, predicate, create, alias)

    def check_birth(self, condition, predicate, create, alias):
        kernel = network.KernelPeer(Fixture("0" * 20, 1), Path("/invalid"), Path("/invalid"))
        kernel.client.identity, kernel.client.mount_id = (1, 2), 30
        kernel.client.group, kernel.client.invocation = (4, 5), "a" * 32
        loopback = {"ifname": "lo", "ifindex": 1, "link_type": "loopback"}
        birth = {"ifname": kernel.name, "ifindex": network.LINK_IFINDEX, "linkinfo": {"info_kind": "wireguard"}}
        altered = {
            "wrong-name": {"ifname": "foreign"}, "wrong-kind": {"linkinfo": {"info_kind": "dummy"}},
            "wrong-index": {"ifindex": 43}, "foreign-alias": {"ifalias": "foreign"},
        }
        first = [loopback, birth] if condition == "occupied" else [loopback]
        full = birth if condition == "alias-missing" else birth | {"ifalias": kernel.alias}
        inventories = iter((first, [loopback, birth | altered.get(condition, {})], [loopback, full]))
        effects = []

        def command(_work, operation, argv, **_options):
            self.assertEqual(argv[:3], [network.NSENTER, f"--net={kernel.client.pin}", "--"])
            if operation == "private link inventory":
                return json.dumps(next(inventories)).encode()
            effects.append((operation, argv[3:]))
            if operation is network.Step.LINK_ALIAS and condition == "alias-error":
                raise network.CommandRefused(operation, supervision.ProcessResult("exited", 2))
            return b""

        current = {"InvocationID": kernel.client.invocation, "ActiveState": "active"}
        checks = [current] * 3 + [{"InvocationID": "replacement", "ActiveState": "active"}]
        with (
            patch.object(network, "command", side_effect=command),
            patch.object(network, "cgroup_present", return_value=True),
            patch.object(network, "unit_status", side_effect=checks if condition == "keeper-lost" else None,
                         return_value=current),
            patch.object(kernel.client, "measure_pin", return_value=((1, 2), 30)),
        ):
            if condition == "created":
                kernel.create_link()
                self.assertIs(kernel.location, kernel.client)
                self.assertEqual(kernel.ifindex, network.LINK_IFINDEX)
            else:
                with self.assertRaises(CleanupUnconfirmed) as error:
                    kernel.create_link()
                observed = failure(error.exception)
                self.assertEqual(observed["predicate"], predicate)
                if condition == "alias-error":
                    self.assertEqual(observed["command"], {
                        "kind": "command", "operation": "link-alias", "status": "exited", "exit_status": 2,
                    })
                self.assertIsNone(kernel.location)
                self.assertIsNone(kernel.ifindex)
                if create:
                    with patch.object(kernel, "call") as remove, patch.object(kernel.peer, "stop") as stop_peer:
                        with self.assertRaises(CleanupUnconfirmed):
                            kernel.stop()
                        remove.assert_not_called()
                        stop_peer.assert_not_called()
        expected = []
        if create:
            expected.append((network.Step.LINK_CREATE, [network.IP, "link", "add", "name", kernel.name,
                                                       "index", str(network.LINK_IFINDEX), "type", "wireguard"]))
        if alias:
            expected.append((network.Step.LINK_ALIAS, [network.IP, "link", "set", "dev", kernel.name, "alias", kernel.alias]))
        self.assertEqual(effects, expected)

    def test_namespace_move_requires_full_identity_and_same_pinned_destination_index(self):
        for fault in (None, "source-alias", "destination-index"):
            with self.subTest(fault=fault):
                kernel = network.KernelPeer(Fixture("0" * 20, 1), Path("/invalid"), Path("/invalid"))
                kernel.location, kernel.ifindex = kernel.client, network.LINK_IFINDEX
                loopback = {"ifname": "lo", "ifindex": 1, "link_type": "loopback"}
                full = {"ifname": kernel.name, "ifindex": kernel.ifindex, "ifalias": kernel.alias,
                        "linkinfo": {"info_kind": "wireguard"}}
                original = full | {"ifalias": "different"} if fault == "source-alias" else full
                moved = full | {"ifindex": 43} if fault == "destination-index" else full
                with (
                    patch.object(kernel.peer, "recheck"),
                    patch.object(kernel, "links", side_effect=([loopback], [loopback, original], [loopback, moved])),
                    patch.object(kernel, "call") as effect,
                ):
                    if fault is None:
                        kernel.move_link()
                        self.assertIs(kernel.location, kernel.peer)
                        self.assertEqual(kernel.ifindex, network.LINK_IFINDEX)
                    else:
                        with self.assertRaises(CleanupUnconfirmed):
                            kernel.move_link()
                        self.assertIs(kernel.location, kernel.client if fault == "source-alias" else None)
                    if fault == "source-alias":
                        effect.assert_not_called()
                    else:
                        effect.assert_called_once_with(kernel.client, network.Step.LINK_MOVE, network.IP, "link", "set",
                                                       "dev", kernel.name, "netns", kernel.peer.pin, "index", str(kernel.ifindex))

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

    def test_failed_post_intent_observation_is_retained_without_acknowledgement(self):
        initial = observations.Counters(0, 0, 0, None)
        get = observations.Counters(96, 112, 1, "127.0.0.1:49152")
        interrupted = observations.Counters(192, 224, 2, "127.0.0.1:49153")
        resumed = observations.Counters(288, 336, 3, "127.0.0.1:49154")
        unexpected = observations.Counters(320, 336, 3, "127.0.0.1:49154")
        for last, phase, after in (
            (unexpected, "case-delta", asdict(unexpected)),
            (Blocked("synthetic private failure details"), "case-sample", None),
        ):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                mailbox = work / "telemetry"
                report = {}

                def complete_cases(_seconds, *, signal, stop):
                    for index, _ in enumerate(observations.CASES):
                        observations.file_signal(mailbox / f"case-{index}.done")
                    self.assertTrue(observations.wait_file(mailbox / "blocked", timeout=5))
                    self.assertTrue(stop())
                    return ProcessResult("observer-stopped")

                with (
                    patch.object(observations, "snapshot", side_effect=[
                        initial, initial, initial, get, get, interrupted, resumed, last,
                    ]),
                    patch.object(observations, "settle_peer", side_effect=lambda _peer, after, *_: after),
                    patch.object(orphan, "identify", return_value=None),
                    patch.object(orphan, "retire"),
                ):
                    with self.assertRaises(fixture.direct.EvidenceFailed):
                        fixture.execute_campaign(
                            Mock(), SimpleNamespace(wait=complete_cases), work, work,
                            work / "unused", report, {}, Mock(time_for=Mock(return_value=10)),
                        )
                self.assertEqual([row["case"] for row in report["kernel_cases"]], [
                    name for name, _ in observations.CASES[:-1]
                ])
                self.assertEqual(report["kernel_case_failure"], {
                    "case": "post-intent", "phase": phase,
                    "before": asdict(resumed), "after": after, "failure": {"kind": "refused"},
                })
                self.assertFalse((mailbox / "case-6.observed").exists())

    def test_local_case_uses_quiet_baseline_after_prior_connection(self):
        initial = observations.Counters(0, 0, 0, None)
        connected = observations.Counters(3490, 4780, 1, "127.0.0.1:44497")
        late_transmit = observations.Counters(3490, 4940, 1, "127.0.0.1:44497")
        closing = tcp.parse_tcp(b"FIN-WAIT-1 0 1 198.18.0.1:2222 198.18.0.2:61899 timer:(on,20ms,0)\n")
        cases = (("get", 1), ("incumbent", 0))
        rows, failures = [], []
        with tempfile.TemporaryDirectory() as scratch:
            mailbox = Path(scratch)
            now = 0

            def wait(seconds):
                nonlocal now
                self.assertFalse((mailbox / "case-0.observed").exists())
                now += seconds
                return False

            kernel = Mock()
            halted = SimpleNamespace(is_set=lambda: False, wait=wait)
            for index in range(len(cases)):
                observations.file_signal(mailbox / f"case-{index}.done")
            with (
                patch.object(observations, "CASES", cases),
                patch.object(observations, "time", SimpleNamespace(monotonic=lambda: now)),
                patch.object(observations, "snapshot", side_effect=[
                    initial, connected, late_transmit,
                    *([late_transmit] * (observations.PEER_QUIET_SECONDS + 1)), late_transmit,
                ]),
                patch.object(observations, "observe_tcp", side_effect=[
                    closing, *([[]] * (observations.PEER_QUIET_SECONDS + 1)),
                ]),
            ):
                observations.observe_cases(kernel, mailbox, halted, rows, failures)
            self.assertEqual(failures, [])
            self.assertEqual(rows[0]["after"], asdict(connected))
            settling = rows[0]["settling"]
            self.assertEqual(settling["before_case"], "incumbent")
            self.assertEqual(settling["latest"], asdict(late_transmit))
            self.assertEqual(settling["required_quiet_ms"], 22000)
            self.assertEqual(settling["observed_quiet_ms"], 22000)
            self.assertEqual(settling["elapsed_ms"], 24000)
            self.assertEqual(settling["tcp_first"]["sockets"][0]["state"], "FIN-WAIT-1")
            self.assertEqual(settling["tcp_latest"]["sockets"], [])
            self.assertEqual(rows[1]["before"], asdict(late_transmit))
            self.assertEqual(rows[1]["after"], asdict(late_transmit))
            self.assertTrue((mailbox / "case-1.observed").exists())

    def test_peer_settling_rejects_drift_and_unbounded_activity(self):
        initial = observations.Counters(96, 112, 1, "127.0.0.1:49152")
        changed_peer = observations.Counters(96, 128, 1, "127.0.0.1:49153")
        regressed = observations.Counters(95, 128, 1, "127.0.0.1:49152")
        active = [observations.Counters(96, i, 1, initial.endpoint) for i in range(113, 173)]
        for samples, reason in (
            ([changed_peer], "changed peer"), ([regressed], "regressed counters"), (active, "did not settle"),
        ):
            with self.subTest(reason=reason):
                now = 0

                def wait(seconds):
                    nonlocal now
                    now += seconds
                    return False

                with (
                    patch.object(observations, "time", SimpleNamespace(monotonic=lambda: now)),
                    patch.object(observations, "snapshot", side_effect=samples),
                    patch.object(observations, "observe_tcp", return_value=[]),
                    self.assertRaisesRegex(Blocked, reason),
                ):
                    observations.settle_peer(Mock(), initial, SimpleNamespace(wait=wait), {})

    def test_exact_peer_tcp_inventory_keeps_only_bounded_retransmit_evidence(self):
        active = (b"FIN-WAIT-1 0 192 198.18.0.1:2222 198.18.0.2:61899 "
                  b"timer:(on,208ms,5) cubic bytes_retrans:960 segs_out:24 retrans:1/5\n")
        closed = b"TIME-WAIT 0 0 198.18.0.1:2222 198.18.0.2:60950 timer:(timewait,59sec,0)\n"
        kernel = Mock()
        kernel.call.return_value = active + closed
        flows = tcp.observe_tcp(kernel)
        kernel.call.assert_called_once_with(kernel.peer, "observe exact inner OpenSSH sockets", network.SS,
                                            "-H4ntoieO", "state", "connected", "src", "198.18.0.1:2222",
                                            "dst", "198.18.0.2")
        terminal, pending = flows
        self.assertTrue(terminal.drained())
        self.assertFalse(pending.drained())
        self.assertEqual((pending.client_port, pending.timer, pending.send_queue, pending.timer_retransmissions,
                          pending.retransmissions, pending.bytes_retransmitted, pending.segments_sent),
                         (61899, "on", 192, 5, 5, 960, 24))
        self.assertEqual(tcp.parse_tcp(active.replace(b"208ms", b"")), [pending])
        for invalid in (
            active + active, active.replace(b"198.18.0.2", b"192.0.2.2"),
            active.replace(b"retrans:1/5", b"retrans:6/5"), active.replace(b"61899", b"65536"),
            active.replace(b",208ms,5", b",5"), active.replace(b",208ms,5", b",,"),
        ):
            with self.assertRaises(Blocked):
                tcp.parse_tcp(invalid)

    def test_settling_identifies_the_refused_sample_without_raw_details(self):
        carrier = observations.Counters(3490, 5420, 1, "127.0.0.1:51314")
        for function, phase in (("snapshot", "peer-carrier-sample"), ("observe_tcp", "peer-tcp-sample")):
            with self.subTest(phase=phase):
                evidence = {}
                with (
                    patch.object(observations, "snapshot", return_value=carrier),
                    patch.object(observations, "observe_tcp", return_value=[]),
                    patch.object(observations, function, side_effect=Blocked("unretained observation text")),
                    self.assertRaises(Blocked),
                ):
                    observations.settle_peer(Mock(), carrier, Mock(wait=Mock(return_value=False)), evidence)
                self.assertEqual(evidence, {"sample_phase": phase})

    def test_crash_retirement_refuses_rebinding_and_live_resumption(self):
        def transcript(port, *, closed=False):
            lines = [f"Connection from 198.18.0.2 port {port} on 198.18.0.1 port 2222",
                     f"Accepted publickey for fixture from 198.18.0.2 port {port} ssh2"]
            if closed:
                lines += [f"Received disconnect from 198.18.0.2 port {port}:11: ",
                          f"Disconnected from user fixture 198.18.0.2 port {port}"]
            return "\n".join(lines) + "\n"

        old = b"ESTAB 0 0 198.18.0.1:2222 198.18.0.2:60313 timer:(keepalive,75sec,0) sk:123456789\n"
        original, = tcp.parse_tcp(old)
        replacement, = tcp.parse_tcp(old.replace(b"sk:123456789", b"sk:12345678a"))
        resumed, = tcp.parse_tcp(old.replace(b"60313", b"53023").replace(b"sk:123456789", b"sk:12345678b"))
        with tempfile.TemporaryDirectory() as scratch:
            evidence = Path(scratch).resolve()
            (evidence / "process-kill.journal").touch()
            (evidence / "process-kill.openssh.log").write_text(transcript(60313))
            resume_log = evidence / "resume.openssh.log"
            resume_log.write_text(transcript(53023, closed=True))
            kernel = Mock(peer=SimpleNamespace(identity=(14, 42)), fixture=SimpleNamespace(account="fixture"))
            with patch.object(orphan, "observe_tcp", return_value=[original]):
                self.assertEqual(orphan.identify(kernel, evidence), original)
                (evidence / orphan.CLEANUP_MARKER).touch()
                with self.assertRaisesRegex(Blocked, "not confirmed drained"):
                    orphan.identify(kernel, evidence)
                (evidence / orphan.CLEANUP_MARKER).unlink()
            for flows in ([replacement], [original, resumed], [resumed]):
                with patch.object(orphan, "observe_tcp", return_value=flows), self.assertRaises(Blocked):
                    orphan.retire(kernel, evidence, original, {})
            resume_log.write_text(transcript(53023))
            with self.assertRaisesRegex(Blocked, "disconnect was not observed"):
                orphan.retire(kernel, evidence, original, {})
            kernel.call.assert_not_called()
            resume_log.write_text(transcript(53023, closed=True))
            kernel.call.return_value = b"removed\n"
            report = {}
            with patch.object(orphan, "observe_tcp", side_effect=[[original], []]):
                orphan.retire(kernel, evidence, original, report)
            kernel.call.assert_called_once_with(
                kernel.peer, "retire exact socket left by fixture SIGKILL", "/usr/bin/python3",
                "-I", "-S", "-B", "-c", orphan.DESTROY, "14", "42", "60313", str(original.cookie),
            )
            self.assertEqual(report["state"], "removed")
            self.assertEqual(report["before"]["cookie"], original.cookie)
            self.assertEqual(report["after"], [])
            kernel.call.reset_mock()
            kernel.call.return_value = b"not-found\n"
            report = {}
            with patch.object(orphan, "observe_tcp", side_effect=[[original], [replacement]]):
                with self.assertRaisesRegex(Blocked, "did not confirm absence"):
                    orphan.retire(kernel, evidence, original, report)
            self.assertEqual(report["state"], "submission-uncertain")
            kernel.call.assert_called_once()

    def test_socket_destroy_frame_binds_exact_cookie_and_kernel_ack(self):
        code = compile(orphan.DESTROY, "<fixture-netlink-helper>", "exec")
        cookie = 0x1234567887654321
        for sender, status, corrupt_echo, accepted in (
            ((0, 0), 0, False, "removed"),
            ((0, 0), -errno.ENOENT, False, "not-found"),
            ((0, 0), -errno.ENOENT, True, None),
            ((0, 0), -errno.EOPNOTSUPP, False, None),
            ((7, 0), 0, False, None),
        ):
            with self.subTest(sender=sender, status=status, corrupt_echo=corrupt_echo):
                diag = Mock()
                diag.getsockname.return_value = (1234, 0)
                header = struct.Struct("=IHHII")

                def sendto(packet, address):
                    self.assertEqual(address, (0, 0))
                    self.assertEqual(header.unpack_from(packet), (72, 21, 5, 1, 1234))
                    self.assertEqual(struct.unpack_from("!HH", packet, 24), (2222, 60313))
                    self.assertEqual(packet[28:32], socket.inet_aton("198.18.0.1"))
                    self.assertEqual(packet[44:48], socket.inet_aton("198.18.0.2"))
                    self.assertEqual(struct.unpack_from("=III", packet, 60), (0, 0x87654321, 0x12345678))
                    echo = packet[:16] if status == 0 else packet
                    if corrupt_echo:
                        echo = echo[:-1] + bytes([echo[-1] ^ 1])
                    reply = header.pack(20 + len(echo), 2, 0x100 if status == 0 else 0, 1, 1234)
                    diag.recvmsg.return_value = (reply + struct.pack("=i", status) + echo, [], 0, sender)
                    return len(packet)

                diag.sendto.side_effect = sendto
                argv = ["helper", "14", "42", "60313", str(cookie)]
                with (
                    patch.object(sys, "argv", argv),
                    patch.object(os, "stat", return_value=SimpleNamespace(st_dev=14, st_ino=42)),
                    patch.object(socket, "AF_NETLINK", 16, create=True),
                    patch.object(socket, "socket", return_value=nullcontext(diag)),
                    patch("builtins.print") as output,
                ):
                    if accepted is not None:
                        exec(code, {})
                        output.assert_called_once_with(accepted)
                    else:
                        with self.assertRaises(SystemExit) as error:
                            exec(code, {})
                        self.assertEqual(error.exception.code, 2)
                        output.assert_not_called()
                diag.sendto.assert_called_once()

    def test_socket_destroy_refuses_namespace_replacement_before_netlink(self):
        code = compile(orphan.DESTROY, "<fixture-netlink-helper>", "exec")
        with (
            patch.object(sys, "argv", ["helper", "14", "42", "60313", "1"]),
            patch.object(os, "stat", return_value=SimpleNamespace(st_dev=14, st_ino=43)),
            patch.object(socket, "socket") as open_diag,
            self.assertRaises(SystemExit) as error,
        ):
            exec(code, {})
        self.assertEqual(error.exception.code, 2)
        open_diag.assert_not_called()

    def test_stable_wireguard_counters_do_not_hide_active_tcp_retransmission(self):
        carrier = observations.Counters(3490, 7552, 1, "127.0.0.1:44497")
        active = (b"FIN-WAIT-1 0 192 198.18.0.1:2222 198.18.0.2:61899 "
                  b"timer:(on,15sec,5) bytes_retrans:960 segs_out:24 retrans:1/5\n")
        first, last = tcp.parse_tcp(active), tcp.parse_tcp(active.replace(b"960", b"1152"))
        now = 0

        def wait(seconds):
            nonlocal now
            now += seconds
            return False

        evidence = {}
        with (
            patch.object(observations, "time", SimpleNamespace(monotonic=lambda: now)),
            patch.object(observations, "snapshot", return_value=carrier),
            patch.object(observations, "observe_tcp", side_effect=[first, *([last] * 59)]),
            self.assertRaisesRegex(Blocked, "did not settle"),
        ):
            observations.settle_peer(Mock(), carrier, SimpleNamespace(wait=wait), evidence)
        self.assertEqual(evidence["tcp_first"]["sockets"][0]["bytes_retransmitted"], 960)
        self.assertEqual(evidence["tcp_latest_active"]["sockets"][0]["bytes_retransmitted"], 1152)
        self.assertEqual(evidence["tcp_latest"]["elapsed_ms"], 60000)
        self.assertNotIn("observed_quiet_ms", evidence)

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
        self.assertEqual(len(required), 6)

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
            self.assertEqual(len(report["artifacts_sha256"]), len(required) - 1)

    def test_client_stop_io_failure_preserves_identity_and_uncertainty(self):
        with tempfile.TemporaryDirectory() as scratch:
            unit = SimpleNamespace(unit="test.service", invocation="one", group=(9, 10), attempted=True)
            work = Path(scratch)
            with (
                patch.object(fixture, "ClientLane", return_value=unit),
                patch.object(unit, "start", create=True),
                patch.object(unit, "stop", create=True, side_effect=OSError("stop failed")),
            ):
                with self.assertRaisesRegex(CleanupUnconfirmed, "lane cleanup is unconfirmed"):
                    with fixture.owned_client(Fixture("0" * 20, 1), work, [], lane.ClientBudget.before_keepers()):
                        pass
            facts = json.loads((work / "lane-campaign/identity.json").read_text())
            self.assertEqual(facts, {"unit": "test.service", "invocation": "one", "cgroup": [9, 10]})
            disposition = json.loads((work / "lane-campaign/disposition.json").read_text())
            self.assertEqual(disposition, facts | {"cleanup": "unconfirmed"})

    def test_protected_client_admits_its_private_mount_and_rejects_the_old_host_mount(self):
        nonce = "0" * 20
        net = {"device": 5, "inode": 100}
        host = {"device": 5, "inode": 200}
        private = {"device": 5, "inode": 300}
        requirements = {
            "/proc/self/status": "CapInh: 0\nCapPrm: 0\nCapEff: 0\nCapBnd: 0\nCapAmb: 0\nNoNewPrivs: 1\n",
            "/proc/self/cgroup": f"0::/system.slice/exacopy-wg-{nonce}-campaign.service\n",
        }
        with (
            patch.object(client.os, "geteuid", return_value=1001),
            patch.object(client.os, "getuid", return_value=1001),
            patch.object(client.os, "getgroups", return_value=[]),
            patch.object(client.os, "statvfs", return_value=SimpleNamespace(f_flag=os.ST_RDONLY)) as cgroup,
            patch.object(client, "Path", side_effect=lambda path: SimpleNamespace(
                read_text=lambda **_kw: requirements[path],
            )),
            patch.object(client.provider, "namespace_identity", side_effect=[net, private, net, host, net, private]),
        ):
            self.assertEqual(client.isolated_client("5:100", "5:200", "1001", nonce), private)
            with self.assertRaisesRegex(Blocked, "private mount namespace"):
                client.isolated_client("5:100", "5:200", "1001", nonce)
            cgroup.return_value = SimpleNamespace(f_flag=0)
            with self.assertRaisesRegex(Blocked, "protected cgroup"):
                client.isolated_client("5:100", "5:200", "1001", nonce)

    def test_client_observation_requires_same_held_mount_before_facts_authority(self):
        host = {"device": 5, "inode": 200}
        mounted = (5, 300)
        for problem in ("none", "host-mount", "measurement-drift", "leader-drift", "early-exit"):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                handoff = work / "lane-campaign"
                handoff.mkdir()
                unit = Mock()
                unit.mount_namespace.side_effect = [
                    (5, 200) if problem == "host-mount" else mounted,
                    (5, 301) if problem == "leader-drift" else mounted,
                ]
                unit.wait.side_effect = [
                    ProcessResult("rendezvous"),
                    ProcessResult("exited", 77) if problem == "early-exit" else ProcessResult("rendezvous"),
                ]
                facts = {"destination": {"mount_namespace": "200" if problem == "measurement-drift" else "300"}}
                for name in ("native-facts", "native-facts-recheck"):
                    (work / name).mkdir()
                    (work / name / "facts.json").write_text(json.dumps(facts))
                evidence = {}
                with patch.object(fixture.provider, "namespace_identity", return_value=host):
                    if problem == "none":
                        self.assertEqual(fixture.observe_client(unit, handoff, work, host, evidence, lane.ClientBudget.before_keepers()), mounted)
                        self.assertEqual(json.loads((handoff / "mount.json").read_text()), {
                            "host": host, "client": list(mounted),
                        })
                    else:
                        refusal = CleanupUnconfirmed if problem == "leader-drift" else Blocked
                        with self.assertRaises(refusal):
                            fixture.observe_client(unit, handoff, work, host, evidence, lane.ClientBudget.before_keepers())
                        self.assertFalse((handoff / "mount.json").exists())
                signal = handoff / lane.ClientStep.OBSERVE.value
                self.assertEqual(signal.exists(), problem != "host-mount")
                self.assertFalse((handoff / lane.ClientStep.CAMPAIGN.value).exists())
                if problem == "early-exit":
                    self.assertEqual(evidence["client_observations"], {"status": "exited", "exit_status": 77})

    def test_client_phases_share_one_deadline_before_network_keeper_expiry(self):
        with patch.object(lane.time, "monotonic", side_effect=[100, 110, 200, 1570, 1600]):
            budget = lane.ClientBudget.before_keepers()
            self.assertEqual(budget.deadline, 100 + network.KEEPER_SECONDS - lane.NAMESPACE_CLEANUP_RESERVE)
            self.assertEqual(budget.time_for(120), 120)
            self.assertEqual(budget.time_for(), 1400)
            self.assertEqual(budget.time_for(55), 30)
            with self.assertRaisesRegex(Blocked, "supervision budget is exhausted") as expired:
                budget.time_for()
            self.assertEqual(failure(expired.exception), {"kind": "client-supervision-budget-exhausted"})

    def test_observations_cleanup_uncertainty_retains_lane_after_drain(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            unit = Mock(unit="test.service", invocation="one", group=(9, 10), attempted=True)
            with patch.object(fixture, "ClientLane", return_value=unit):
                with self.assertRaisesRegex(CleanupUnconfirmed, "lane cleanup is unconfirmed"):
                    with fixture.owned_client(Fixture("0" * 20, 1), work, [], lane.ClientBudget.before_keepers()) as (_, handoff):
                        (handoff / "observations-cleanup-pending").touch()
                unit.stop.assert_called_once()
            retained = json.loads((work / "lane-campaign/disposition.json").read_text())
            self.assertEqual(retained["cleanup"], "unconfirmed")

    def test_one_client_carries_observations_campaign_and_carrier_down_in_order(self):
        with tempfile.TemporaryDirectory() as scratch:
            runner = Path(scratch)
            work = runner / fixture.JOB / "private"
            handoff = work / "lane-campaign"
            handoff.mkdir(parents=True)
            mount = {"device": 5, "inode": 300}
            sequence = []
            env = {}

            def wait_for(path, **_options):
                sequence.append(path.name)
                return True

            def observe(_fixture, _manifest, _binary, selected_env, evidence, verify):
                self.assertEqual(evidence, work)
                self.assertEqual(selected_env["CARGO_BUILD_JOBS"], "2")
                self.assertTrue((handoff / "observations-cleanup-pending").exists())
                verify()
                sequence.append("facts")

            def campaign_main(_observer, _retained):
                self.assertTrue((handoff / lane.ClientStep.OBSERVED.value).exists())
                self.assertFalse((handoff / "observations-cleanup-pending").exists())
                sequence.append("transfer")
                return 0

            def carrier(_campaign, _paths, _evidence, _retained):
                self.assertTrue((handoff / lane.ClientStep.CAMPAIGN_COMPLETE.value).exists())
                sequence.append("carrier-work")
                return 0

            with (
                patch.dict(os.environ, {"RUNNER_TEMP": str(runner), "PATH": "/scoped/bin:/usr/bin"}),
                patch.object(client, "wait_file", side_effect=wait_for),
                patch.object(client, "no_direct_route", return_value=True) as no_direct,
                patch.object(client.direct, "read_build_manifest", return_value=({"source_after": "same-order"}, "digest")),
                patch.object(client.direct, "verify_build_custody") as verify,
                patch.object(client.direct, "observations", side_effect=observe),
                patch.object(client.native, "source_identity", return_value="same-order"),
                patch.object(client.native, "build_environment", return_value=env),
                patch.object(campaign, "main", side_effect=campaign_main),
                patch.object(client, "carrier_down", side_effect=carrier),
                patch.object(sys, "argv", []),
            ):
                self.assertEqual(client.run_client("0" * 20, mount, lambda: mount), 0)
            self.assertEqual(sequence, ["observe", "facts", "campaign", "transfer", "carrier-down", "carrier-work"])
            self.assertEqual(verify.call_count, 3)
            self.assertEqual(no_direct.call_count, 3)

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
