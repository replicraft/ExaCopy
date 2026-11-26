"""Portable commissioning scope, authority, cleanup, and evidence controls."""

import contextlib
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import remote_commissioning as commission
import remote_commissioning_authority as authority
import remote_commissioning_peer as peer
from native_supervision import CleanupUnconfirmed

NONCE = "4601714801c0e1a535bf"


class PortableCommissioningControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="exacopy-direct-controls-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.fixture = peer.Fixture(NONCE, 65534)

    def test_non_hosted_job_stops_before_files_or_effects(self):
        errors = io.StringIO()
        with (
            patch.object(commission.sys, "platform", "darwin"),
            patch.object(commission.sys, "argv", ["remote_commissioning.py"]),
            patch.object(commission, "execute") as execute,
            patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}, clear=True),
            contextlib.redirect_stderr(errors),
        ):
            self.assertEqual(commission.main(), 77)
        execute.assert_not_called()
        self.assertIn("closed GitHub-hosted", errors.getvalue())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_only_canonical_hosted_main_events_are_admitted_without_protection(self):
        admitted = {
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
            "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "replicraft/ExaCopy",
            "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF_PROTECTED": "false", "RUNNER_TEMP": str(self.root),
        }
        directory = SimpleNamespace(st_mode=0o40700, st_uid=1234)
        with (
            patch.object(commission.sys, "platform", "linux"),
            patch.object(commission.sys, "argv", ["remote_commissioning.py"]),
            patch.object(commission.os, "geteuid", return_value=1234),
            patch.object(commission.os, "getuid", return_value=1234),
            patch.object(Path, "cwd", return_value=commission.native.REPO),
            patch.object(Path, "read_text", return_value='ID=ubuntu\nVERSION_ID="24.04"\n'),
            patch.object(Path, "lstat", return_value=directory),
            patch.object(Path, "resolve", return_value=self.root),
        ):
            for event in ("push", "workflow_dispatch"):
                with patch.dict(os.environ, admitted | {"GITHUB_EVENT_NAME": event}, clear=True):
                    self.assertEqual(commission.hosted_parent(), self.root)
            for name, value in (
                ("GITHUB_EVENT_NAME", "pull_request_target"),
                ("GITHUB_EVENT_NAME", "schedule"),
                ("GITHUB_REF", "refs/heads/feature"),
                ("GITHUB_REF", "refs/tags/v0.1.0"),
                ("GITHUB_SERVER_URL", "https://example.test"),
                ("GITHUB_REPOSITORY", "fork/ExaCopy"),
                ("GITHUB_REPOSITORY", ""),
                ("RUNNER_ENVIRONMENT", "self-hosted"),
                ("EXACOPY_REMOTE_DEPLOYMENT", ""),
            ):
                with self.subTest(name=name, value=value), patch.dict(
                    os.environ, admitted | {name: value}, clear=True,
                ), self.assertRaisesRegex(peer.Blocked, "closed GitHub-hosted"):
                    commission.hosted_parent()

    def test_scope_is_generated_and_peer_authentication_is_read_only_and_loopback(self):
        for invalid in ("../caller-root", "00", "AA" * 10):
            with self.subTest(invalid=invalid), self.assertRaises(peer.Blocked):
                peer.Fixture(invalid, 65534)
        config = peer.sshd_configuration(self.fixture, 21234)
        for line in (
            "ListenAddress 127.0.0.1:21234", f"HostKey {self.fixture.root / 'host-key'}", f"AllowUsers {self.fixture.account}@127.0.0.1",
            f"ChrootDirectory {self.fixture.chroot}", "AuthenticationMethods publickey",
            "PasswordAuthentication no", "KbdInteractiveAuthentication no", "UsePAM no",
            "ForceCommand internal-sftp -R -d /", "DisableForwarding yes",
        ):
            self.assertIn(line, config.splitlines())
        self.assertEqual(sum(line.startswith("ListenAddress ") for line in config.splitlines()), 1)
        self.assertTrue(self.fixture.root.is_relative_to(peer.BASE))
        unit = peer.unit_properties(self.fixture)
        self.assertEqual(unit["KillMode"], "control-group")
        self.assertEqual(unit["Delegate"], "no")
        self.assertEqual(unit["ProtectControlGroups"], "yes")
        self.assertEqual(unit["CapabilityBoundingSet"], "~CAP_SYS_ADMIN")
        self.assertEqual(unit["Restart"], "no")
        self.assertLessEqual(peer.UNIT_SECONDS, 1800)
        self.assertEqual(unit["BindReadOnlyPaths"].split(), [
            f"{self.fixture.source}:{self.fixture.chroot / self.fixture.source.relative_to('/')}:" "norbind",
            f"{self.fixture.runtime}:/run:norbind",
        ])

    def test_host_privsep_absence_is_observed_and_required_host_path_refuses(self):
        cgroup_root = self.root / "cgroup"
        cgroup = cgroup_root / "system.slice"
        cgroup.mkdir(parents=True)
        systemd_runtime = self.root / "systemd"
        systemd_runtime.mkdir()
        host_privsep = self.root / "unused-host-sshd"
        with (
            patch.object(peer, "CGROUP_ROOT", cgroup_root),
            patch.object(peer, "CGROUP", cgroup),
            patch.object(peer, "SYSTEMD_RUNTIME", systemd_runtime),
            patch.object(peer, "PRIVSEP", host_privsep),
        ):
            observed = {}
            peer.observe_host_paths(observed)
            self.assertEqual(observed[str(host_privsep)], "absent")
            systemd_runtime.rmdir()
            systemd_runtime.symlink_to(cgroup)
            with self.assertRaisesRegex(peer.Blocked, "/systemd: symlink"):
                peer.observe_host_paths(observed)
            self.assertEqual(observed[str(cgroup)], "canonical-directory")

    def test_runtime_creation_uses_only_the_owned_root(self):
        with patch.object(peer, "BASE", self.root):
            owned_privsep = self.fixture.runtime / "sshd"
            owned_privsep.mkdir(parents=True)
            with (
                patch.object(peer, "run") as command,
                patch.object(peer, "directory_identity", side_effect=[(3, 7), (3, 8)]) as identity,
            ):
                self.fixture.make_runtime()
            self.assertEqual(command.call_args.args[0], [peer.INSTALL, "-d", "-m", "0755", "--", owned_privsep])
            self.assertEqual([call.args for call in identity.call_args_list], [
                (self.fixture.runtime, 0, 0o755), (owned_privsep, 0, 0o755),
            ])
            self.assertNotIn(peer.PRIVSEP, command.call_args.args[0])

    def test_registered_process_requires_the_exact_read_only_owned_runtime(self):
        leader = Path("/proc/1234")
        for identity, options, allowed in (
            (b"17:18:0:755\n17:19:0:755", "ro,nosuid", True),
            (b"17:18:0:755\n17:20:0:755", "ro,nosuid", False),
            (b"17:20:0:755\n17:19:0:755", "ro,nosuid", False),
            (b"17:18:0:755\n17:19:0:755", "rw,nosuid", False),
        ):
            mount = ('{"filesystems":[{"target":"/run","options":"' + options + '"}]}').encode()
            with (
                self.subTest(identity=identity, options=options),
                patch.object(peer, "directory_identity", side_effect=[(17, 18), (17, 19)]),
                patch.object(peer, "run", side_effect=[identity, mount]) as command,
            ):
                if allowed:
                    peer.verify_privsep_runtime(leader, self.fixture)
                    self.assertEqual(command.call_args.args[0][1:3], ["--task", "1234"])
                else:
                    with self.assertRaises(peer.Blocked):
                        peer.verify_privsep_runtime(leader, self.fixture)
                self.assertEqual(command.call_args_list[0].args[0][-2:], [
                    leader / "root/run", leader / "root/run/sshd",
                ])

    def test_listener_log_requires_a_current_daemon_and_exact_cgroup(self):
        leader = self.root / "1234"
        leader.mkdir()
        registered = self.registered_fixture() | {"MainPID": leader.name, "ActiveState": "active"}
        for state, group, membership, allowed in (
            (registered, True, True, True),
            (registered | {"MainPID": "5678"}, True, True, False),
            (registered | {"InvocationID": "b" * 32}, True, True, False),
            (registered | {"ActiveState": "inactive"}, True, True, False),
            (registered, False, True, False),
            (registered, True, False, False),
        ):
            line = f"0::/system.slice/{self.fixture.unit}" if membership else "0::/unowned"
            (leader / "cgroup").write_text(line + "\n", encoding="ascii")
            with (
                self.subTest(state=state, cgroup=group, membership=membership),
                patch.object(peer, "unit_status", return_value=state) as status,
                patch.object(peer, "cgroup_present", return_value=group) as cgroup,
            ):
                if allowed:
                    self.fixture.recheck_listening_leader(registered, leader)
                    cgroup.assert_called_once_with(self.fixture.cgroup, self.fixture.cgroup_identity)
                else:
                    with self.assertRaises(peer.Blocked):
                        self.fixture.recheck_listening_leader(registered, leader)
                status.assert_called_once_with(self.fixture.unit)

    def test_password_is_not_a_command_argument_and_account_is_exact(self):
        current = SimpleNamespace(
            pw_gecos=f"ExaCopy direct fixture {NONCE}", pw_gid=65534, pw_shell=peer.NOLOGIN,
            pw_dir="/", pw_uid=996,
        )
        hash_value = b"$6$testSalt$privateFixtureHash\n"
        responses = [b"", hash_value, b""]
        with (
            patch.object(peer, "local_account", side_effect=[None, current]),
            patch.object(peer, "local_group", return_value=None),
            patch.object(peer, "run", side_effect=responses) as command,
        ):
            self.fixture.make_account()
        self.assertEqual(self.fixture.account_identity, (996, 65534))
        create, hash_command, set_password = command.call_args_list
        self.assertNotIn("--password", create.args[0])
        self.assertIn("-stdin", hash_command.args[0])
        self.assertEqual(set_password.args[0], [peer.CHPASSWD, "--encrypted"])
        self.assertEqual(set_password.kwargs["data"], self.fixture.account.encode() + b":" + hash_value)
        self.assertNotIn(hash_value, set_password.args[0])

    def test_cancelled_account_creation_skips_new_provisioning_but_can_clean_up(self):
        current = SimpleNamespace(
            pw_gecos=f"ExaCopy direct fixture {NONCE}", pw_gid=65534, pw_shell=peer.NOLOGIN,
            pw_dir="/", pw_uid=996,
        )
        effects = []

        def command(argv, **_kwargs):
            effects.append(argv[0])
            if argv[0] == peer.USERADD:
                peer.native_supervision.CANCELLATION_REQUESTED = True

        with (
            patch.object(peer.native_supervision, "CANCELLATION_REQUESTED", False),
            patch.object(peer, "local_account", side_effect=[None, current, current, None]),
            patch.object(peer, "local_group", return_value=None),
            patch.object(peer, "run", side_effect=command),
        ):
            with self.assertRaisesRegex(peer.Blocked, "cancelled"):
                self.fixture.make_account()
            self.fixture.stop()
        self.assertEqual(effects, [peer.USERADD, peer.USERDEL])

    def registered_fixture(self):
        self.fixture.root_attempted = self.fixture.account_attempted = self.fixture.unit_attempted = True
        self.fixture.root_identity = (11, 13)
        self.fixture.account_identity = (996, 65534)
        self.fixture.cgroup_identity = (17, 19)
        self.fixture.invocation = "a" * 32
        return {
            "InvocationID": self.fixture.invocation,
            "ControlGroup": f"/system.slice/{self.fixture.unit}",
        }

    def test_occupied_cgroup_keeps_account_and_scratch(self):
        status = self.registered_fixture()
        with (
            patch.object(peer, "unit_known", return_value=True),
            patch.object(peer, "unit_status", return_value=status),
            patch.object(peer, "run") as command,
            patch.object(peer, "cgroup_present", return_value=True),
            patch.object(peer, "cgroup_drained", return_value=False) as drained,
            patch.object(self.fixture, "observe_account") as account,
        ):
            with self.assertRaises(CleanupUnconfirmed):
                self.fixture.stop()
        account.assert_not_called()
        command.assert_called_once()
        self.assertEqual(command.call_args.args[0], [peer.SYSTEMCTL, "stop", "--", self.fixture.unit])
        drained.assert_called_once_with(self.fixture.cgroup, self.fixture.cgroup_identity)

    def test_rebound_invocation_refuses_to_stop_unowned_service(self):
        status = self.registered_fixture() | {"InvocationID": "b" * 32}
        with (
            patch.object(peer, "unit_known", return_value=True),
            patch.object(peer, "unit_status", return_value=status),
            patch.object(peer, "cgroup_present", return_value=True),
            patch.object(peer, "run") as command,
        ):
            with self.assertRaisesRegex(CleanupUnconfirmed, "ownership changed"):
                self.fixture.stop()
        command.assert_not_called()

    def test_verified_cleanup_drains_service_before_removing_account_and_root(self):
        status = self.registered_fixture()
        order = []

        def command(argv, **_kwargs):
            order.append(argv[0])

        def drain(path, identity):
            self.assertEqual((path, identity), (self.fixture.cgroup, (17, 19)))
            order.append("cgroup-drained")
            return True

        with (
            patch.object(peer, "unit_known", return_value=True),
            patch.object(peer, "unit_status", return_value=status),
            patch.object(peer, "run", side_effect=command),
            patch.object(peer, "cgroup_present", return_value=True),
            patch.object(peer, "cgroup_drained", side_effect=drain),
            patch.object(self.fixture, "observe_account", return_value=(996, 65534)),
            patch.object(peer, "local_account", return_value=None),
            patch.object(peer, "local_group", return_value=None),
            patch.object(peer, "directory_identity", return_value=(11, 13)),
            patch.object(peer.os.path, "lexists", return_value=False),
        ):
            self.fixture.stop()
        self.assertEqual(order, [peer.SYSTEMCTL, "cgroup-drained", peer.USERDEL, peer.REMOVE])

    def test_rebound_cgroup_refuses_before_stop(self):
        self.registered_fixture()
        with (
            patch.object(peer, "cgroup_present", side_effect=CleanupUnconfirmed("replaced cgroup")),
            patch.object(peer, "run") as command,
            self.assertRaisesRegex(CleanupUnconfirmed, "replaced cgroup"),
        ):
            self.fixture.stop()
        command.assert_not_called()

    def test_same_name_group_refuses_account_removal(self):
        self.fixture.account_attempted = True
        self.fixture.account_identity = (996, 65534)
        with (
            patch.object(self.fixture, "observe_account", return_value=(996, 65534)),
            patch.object(peer, "local_group", return_value=object()),
            patch.object(peer, "run") as command,
            self.assertRaisesRegex(CleanupUnconfirmed, "same-name group"),
        ):
            self.fixture.stop()
        command.assert_not_called()

    def test_nested_cleanup_failure_fences_known_peer_without_removing_fixture(self):
        parent = self.root / "commissioning"
        report, work = parent / "report", parent / "private"
        report.mkdir(parents=True)
        work.mkdir()
        tool_root = self.root / "exacopy-commissioning-tools"
        tool_root.mkdir(mode=0o700)
        tool = tool_root / "unpacked/usr/bin/b3sum"
        tool.parent.mkdir(parents=True)
        tool.touch()
        manifest = work / "build.json"
        manifest.write_text('{"build_sha256":"digest","compiled_features":["experimental-ssh-capture"]}')
        self.registered_fixture()
        evidence = {"fixture_id": self.fixture.nonce}
        stop = Mock()
        stop_peer = Mock()
        with (
            patch.dict(os.environ, {"GITHUB_SHA": "selected"}),
            patch.object(commission, "preflight", return_value=65534),
            patch.object(commission.shutil, "which", return_value=str(tool)),
            patch.object(commission, "run", return_value=b"1:9.6p1-3ubuntu13.14"),
            patch.object(commission.native, "source_identity", return_value={"revision": "selected"}),
            patch.object(commission.native, "build_environment", return_value={}),
            patch.object(commission.native, "build_cli", return_value=(work / "exacopy", manifest)) as build,
            patch.object(commission, "file_digest", return_value="digest"),
            patch.object(commission, "Fixture", return_value=self.fixture),
            patch.object(self.fixture, "stop", stop),
            patch.object(self.fixture, "stop_peer", stop_peer),
            patch.object(commission, "run_fixture", side_effect=CleanupUnconfirmed("nested child retained")),
            self.assertRaisesRegex(CleanupUnconfirmed, "nested child retained"),
        ):
            commission.execute(parent, report, work, evidence)
        self.assertEqual(build.call_args.args[-1]["CARGO_BUILD_JOBS"], "2")
        stop_peer.assert_called_once_with()
        stop.assert_not_called()
        self.assertEqual(evidence["peer_cleanup"], "confirmed-drained")
        self.assertTrue((report / "cleanup-unconfirmed.json").is_file())
        self.assertTrue((parent / "private-build").is_dir())

    def test_cgroup_inode_and_population_are_independent_of_process_sessions(self):
        group = self.root / "group"
        group.mkdir()
        info = group.stat()
        kind = info.st_dev, info.st_ino
        events = group / "cgroup.events"
        events.write_text("populated 1\nfrozen 0\n")
        self.assertFalse(peer.cgroup_drained(group, kind))
        events.write_text("populated 0\nfrozen 0\n")
        self.assertTrue(peer.cgroup_drained(group, kind))
        with self.assertRaises(CleanupUnconfirmed):
            peer.cgroup_drained(group, (info.st_dev, info.st_ino + 1))
        events.write_text("frozen 0\n")
        with self.assertRaises(CleanupUnconfirmed):
            peer.cgroup_drained(group, kind)

    def test_privileged_timeout_is_unconfirmed_and_uses_private_stdin(self):
        with patch.object(peer.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 15)) as spawn:
            with self.assertRaises(CleanupUnconfirmed):
                peer.run([peer.CHPASSWD, "--encrypted"], privileged=True, data=b"private\n", operation="fixture")
        self.assertEqual(spawn.call_args.args[0], [peer.SUDO, "-n", "--", peer.CHPASSWD, "--encrypted"])
        self.assertEqual(spawn.call_args.kwargs["input"], b"private\n")

    def test_only_allowlisted_report_files_are_exported(self):
        internal, output = self.root / "internal", self.root / "report"
        (internal / "campaign").mkdir(parents=True)
        output.mkdir()
        (internal / "campaign" / "summary.json").write_bytes(b"case outcomes")
        (internal / "campaign" / "get.openssh.log").write_bytes(b"observed peer")
        for secret in ("client-key", "sshd.log", "synthetic-record", "synthetic-trust.json", "owner-init.log"):
            (internal / secret).write_bytes(b"private sentinel")
        (internal / "campaign" / "get.stderr").write_bytes(b"private sentinel")
        exported = commission.export(internal, output)
        self.assertEqual(exported, {
            "campaign/summary.json": hashlib.sha256(b"case outcomes").hexdigest(),
            "campaign/get.openssh.log": hashlib.sha256(b"observed peer").hexdigest(),
        })
        self.assertEqual(
            sorted(path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()),
            sorted(exported),
        )
        (internal / "campaign" / "resume.openssh.log").symlink_to(internal / "client-key")
        with self.assertRaises(peer.Blocked):
            commission.capture_file(internal, output, "campaign/resume.openssh.log", 65536)

    def test_v1_body_uses_explicit_assumed_scope_digests_and_real_native_projection(self):
        class Reference:
            def identity(self, device, inode):
                return [device, inode]

            def encode(self, value):
                return value

        measured = {
            "device": "11", "inode": "13", "effective_uid": 1000, "effective_gid": 1000,
            "boot_id_hex": "16" * 16, "mount_namespace": "17", "mount_id": "19", "unique_mount": "21",
            "architecture": "x86_64", "kernel_release_hex": "37", "kernel_build_hex": "38",
            "mount_record_hex": "39",
        }
        build = "cd" * 32
        with patch.object(authority.secrets, "token_bytes", return_value=b"\x10" * 16):
            body, trust = authority.fixture_payload(
                Reference(), measured, build, NONCE, {"revision": "a" * 40}, {"facts_sha256": "bc" * 32},
            )
        self.assertEqual(authority.V1_DOMAIN, b"ExaCopy/linux-remote-destination-qualification/v1\0")
        self.assertEqual(body[1], bytes.fromhex(build))
        self.assertEqual(body[2], 1)
        self.assertEqual(body[5], [[11, 13], 1000, 1000, b"\x16" * 16, 17, 19, 21, 1, b"7", b"8", b"9"])
        self.assertEqual(trust["campaign_scope"], body[3].hex())
        self.assertEqual(trust["campaign_evidence"], body[4].hex())
        self.assertNotEqual(trust["campaign_evidence"], "bc" * 32)
        self.assertEqual(trust["schema"], "exacopy-remote-qualification-trust-v1")
        self.assertEqual(trust["route"], "direct-pinned-tcp-v1")


if __name__ == "__main__":
    unittest.main()
