"""Portable controls for native qualification evidence and subprocess ownership."""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import remote_qualification as ci

import linux_remote_substrate as substrate
import native_supervision as supervisor

ROOT = Path(__file__).resolve().parents[2]


class ImmutableEvidenceControls(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="exacopy-native-control-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve()
        self.evidence = self.root / "facts"
        self.binary = self.root / "exacopy"
        self.binary.write_bytes(b"\x7fELFcontrolled input")
        self.binary.chmod(0o700)
        self.identity = {"revision": "a" * 40, "git_tree": "b" * 40, "lock_sha256": "c" * 64}

    def git(self, *args):
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.check_output(
            ["git", "-C", str(self.root), *args], env=env, timeout=10, text=True,
        ).strip()

    def test_source_identity_binds_tree_lock_and_refuses_all_dirty_kinds(self):
        self.git("init", "-q")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "fixture")
        lock = self.root / "Cargo.lock"
        ignored = self.root / ".gitignore"
        ignored.write_text("ignored-source\n")
        lock.write_text("locked\n")
        self.git("add", "--", ".gitignore", "Cargo.lock", "exacopy")
        self.git("commit", "-qm", "fixture")
        facts = ci.source_identity(self.root)
        self.assertEqual(facts, {
            "revision": self.git("rev-parse", "HEAD"), "git_tree": self.git("rev-parse", "HEAD^{tree}"),
            "lock_sha256": ci.file_digest(lock),
        })
        for leaf in ("tracked", "untracked-source", "ignored-source"):
            with self.subTest(leaf=leaf):
                if leaf == "tracked":
                    lock.write_text("changed\n")
                else:
                    (self.root / leaf).touch()
                with self.assertRaisesRegex(ValueError, "pristine checkout"):
                    ci.source_identity(self.root)
                if leaf == "tracked":
                    lock.write_text("locked\n")
                else:
                    (self.root / leaf).unlink()

    def test_facts_refuse_drift_and_label_manual_elf(self):
        observation = b'{"status":"observed","facts":{"build_blake3_derive_key":"abc","destination":{}}}\n'

        def fake(_command, log, _timeout, **_kwargs):
            log.write_bytes(ci.FACTS_MARKER + observation)
            return supervisor.ProcessResult("exited", 0)

        with patch.object(ci, "logged_command", side_effect=fake):
            with patch.object(ci, "source_identity", side_effect=[self.identity, self.identity]):
                self.assertEqual(ci.collect_facts(self.root, self.binary, self.evidence, env={}, manifest=None), 0)
            result = json.loads((self.evidence / "facts.json").read_bytes())
            self.assertEqual(result["repository_attribution"], "measured-selected-elf")
            self.assertNotIn("build_manifest_sha256", result)
            with patch.object(ci, "source_identity", side_effect=[
                self.identity, dict(self.identity, git_tree="d" * 40),
            ]):
                other = self.evidence.with_name("drift")
                self.assertEqual(ci.collect_facts(self.root, self.binary, other, env={}, manifest=None), 77)
                self.assertEqual(json.loads((other / "facts.json").read_bytes())["status"], "blocked")

    def test_facts_reject_different_locked_binary_before_invocation(self):
        manifest = self.root / "build.json"
        manifest.write_text(json.dumps({
            "status": "built", "source_before": self.identity, "source_after": self.identity,
            "build_size": 4, "build_sha256": "0" * 64,
        }))
        with patch.object(ci, "logged_command") as invoked:
            with patch.object(ci, "source_identity", return_value=self.identity):
                with patch.object(ci, "verified_pins"):
                    self.assertEqual(ci.collect_facts(self.root, self.binary, self.evidence,
                                                      env={}, manifest=manifest), 77)
            invoked.assert_not_called()

    def test_candidate_facts_require_exact_custody_before_and_after_observation(self):
        manifest = self.root / "candidate-result.json"
        binding = ci.CandidateFactsBinding("1" * 64, ci.DIRECT)
        size, digest = ci.binary_observation(self.binary)
        verified = {"binary": {"size": size, "sha256": digest}}
        observation = b'{"status":"observed","facts":{"build_blake3_derive_key":"abc","destination":{}}}\n'

        def fake(_command, log, _timeout, **_kwargs):
            log.write_bytes(ci.FACTS_MARKER + observation)
            return supervisor.ProcessResult("exited", 0)

        for mode, proof, status, invoked in (
            ("valid", [verified, verified], 0, True),
            ("changed-before", [ValueError("replaced manifest")], 77, False),
            ("another-elf", [{"binary": {"size": size, "sha256": "2" * 64}}], 77, False),
            ("changed-after", [verified, ValueError("replaced manifest")], 77, True),
        ):
            with (
                self.subTest(mode=mode),
                patch.object(ci, "source_identity", return_value=self.identity),
                patch.object(ci, "verified_pins"),
                patch.object(type(binding), "verify", side_effect=proof) as verify,
                patch.object(ci, "logged_command", side_effect=fake) as command,
            ):
                evidence = self.evidence.with_name(mode)
                self.assertEqual(ci.collect_facts(self.root, self.binary, evidence,
                                                  env={}, manifest=manifest, candidate=binding), status)
                self.assertEqual(command.called, invoked)
                self.assertEqual(verify.call_args.args, (manifest, self.binary, self.identity))
                report = json.loads((evidence / "facts.json").read_bytes())
                self.assertEqual(report["repository_attribution"], ci.CANDIDATE_ATTRIBUTION)
                if status == 0:
                    self.assertEqual(report["build_manifest_sha256"], binding.manifest_sha256)
                    self.assertEqual(report["elf_sha256"], digest)
                    self.assertEqual(report["campaign_route"], ci.DIRECT)
                    self.assertTrue(self.identity.items() <= report.items())

    def test_build_requires_exact_cargo_features_and_new_executable(self):
        log = self.root / "build.log"
        unit = {
            "reason": "compiler-artifact", "target": {"kind": ["bin"], "name": "exacopy"},
            "executable": os.fspath(self.binary), "features": list(ci.FEATURES.values()), "fresh": False,
        }
        log.write_text(json.dumps(unit))
        ci.verify_cargo_artifact(log, self.binary, ci.FEATURES[ci.EMBEDDED])
        with self.assertRaises(ValueError):
            ci.verify_cargo_artifact(log, self.binary, ci.FEATURES[ci.DIRECT])
        unit["fresh"] = True
        log.write_text(json.dumps(unit))
        with self.assertRaises(ValueError):
            ci.verify_cargo_artifact(log, self.binary, ci.FEATURES[ci.EMBEDDED])

    def test_staged_executable_preserves_bytes_but_not_cargo_link_identity(self):
        alias = self.root / "cargo-artifact-alias"
        selected = self.root / "selected"
        os.link(self.binary, alias)
        original = ci.executable_observation(self.binary)
        copy = ci.stage_built_executable(self.binary, selected, original)
        self.assertEqual(original["link_count"], 2)
        self.assertEqual(copy["link_count"], 1)
        self.assertEqual(copy["sha256"], original["sha256"])
        self.assertEqual(copy["size"], original["size"])
        self.assertEqual(copy["mode"], 0o700)
        self.assertNotEqual((copy["device"], copy["inode"]), (original["device"], original["inode"]))
        custody = {"compiler_reported_executable": original, "checked_executable_copy": copy}
        ci.verify_executable_custody(self.binary, selected, custody)
        os.link(selected, self.root / "unexpected-copy-alias")
        with self.assertRaisesRegex(ValueError, "custody|changed"):
            ci.verify_executable_custody(self.binary, selected, custody)

    def test_staging_refuses_occupied_copy_and_replaced_original(self):
        selected = self.root / "selected"
        selected.write_bytes(b"retain incumbent")
        original = ci.executable_observation(self.binary)
        with self.assertRaises(FileExistsError):
            ci.stage_built_executable(self.binary, selected, original)
        self.assertEqual(selected.read_bytes(), b"retain incumbent")
        replacement = self.root / "replacement"
        replacement.write_bytes(self.binary.read_bytes())
        replacement.chmod(0o700)
        replacement.replace(self.binary)
        pending = self.root / "pending"
        with self.assertRaisesRegex(ValueError, "compiler-reported executable changed"):
            ci.stage_built_executable(self.binary, pending, original)
        self.assertEqual(pending.stat().st_mode & 0o111, 0)

    def test_held_original_is_rechecked_during_copy(self):
        replacement = self.root / "replacement"
        replacement.write_bytes(self.binary.read_bytes())
        replacement.chmod(0o700)

        class ReplaceDuringWrite:
            def write(_self, data):
                replacement.replace(self.binary)
                return len(data)

        with self.assertRaisesRegex(ValueError, "selected ELF changed while measured"):
            ci.executable_observation(self.binary, ReplaceDuringWrite())

    def test_staging_follows_no_source_symlink(self):
        report = ci.executable_observation(self.binary)
        source_alias = self.root / "source-alias"
        source_alias.symlink_to(self.binary)
        with self.assertRaises(OSError):
            ci.stage_built_executable(source_alias, self.root / "unused", report)
        selected = self.root / "foreign"
        with self.assertRaisesRegex(ValueError, "fixture owner scope"):
            ci.stage_built_executable(self.binary, selected, report | {"uid": os.geteuid() + 1})
        self.assertFalse(selected.exists())

    def test_timeout_reaps_owned_group_and_preserves_log(self):
        log = self.root / "process.log"
        command = [
            sys.executable, "-c",
            "import signal,subprocess,sys,time;"
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);"
            "print(p.pid,flush=True);"
            "signal.signal(signal.SIGTERM, lambda *_: (p.wait(timeout=3),sys.exit(1)));"
            "time.sleep(60)",
        ]
        result = ci.logged_command(command, log, 0.75)
        self.assertEqual(result.status, "timeout")
        child = int(log.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)
        record = ci.process_record(result, log)
        self.assertEqual(record["log_sha256"], ci.file_digest(log))

    def test_wrapper_sigterm_interrupts_owned_process_and_retains_status(self):
        log = self.root / "interrupted.log"
        process_json = self.root / "interrupted.json"
        helper = ROOT / ".github/ci"
        script = """
from pathlib import Path
import signal
import sys
sys.path.insert(0, sys.argv[1])
import remote_qualification as ci
signal.signal(signal.SIGTERM, ci.interrupted)
log, report = map(Path, sys.argv[2:])
command = [sys.executable, "-c", "import os,time; print(os.getpid(),flush=True); time.sleep(60)"]
result = ci.logged_command(command, log, 30)
ci.write_json(report, ci.process_record(result, log))
"""
        with subprocess.Popen([sys.executable, "-B", "-c", script,
                               os.fspath(helper), os.fspath(log), os.fspath(process_json)]) as runner:
            try:
                deadline = time.monotonic() + 5
                while (not log.is_file() or not log.stat().st_size) and time.monotonic() < deadline:
                    time.sleep(0.025)
                self.assertTrue(log.is_file() and log.stat().st_size)
                child = int(log.read_text())
                runner.send_signal(signal.SIGTERM)
                self.assertEqual(runner.wait(timeout=5), 0)
                self.assertEqual(json.loads(process_json.read_bytes())["status"], "interrupted")
                with self.assertRaises(ProcessLookupError):
                    os.kill(child, 0)
            finally:
                if runner.poll() is None:
                    runner.send_signal(signal.SIGTERM)
                    runner.wait(timeout=5)

    def test_output_overflow_caps_retained_bytes_and_returns_nonpass(self):
        log = self.root / "flood.log"
        producer = [
            sys.executable, "-c",
            "import os, signal; os.write(1, b'X' * 65536); signal.pause()",
        ]
        result = supervisor.logged_command(producer, log, 5, output_limit=512)
        self.assertEqual(result.status, "output-limit")
        self.assertEqual(log.read_bytes(), b"X" * 512)

    def test_normal_leader_exit_still_checks_group_and_refuses_descendant(self):
        log = self.root / "stray.log"
        leader = """
import os
import subprocess
import sys

read_fd, write_fd = os.pipe()
child = subprocess.Popen(
    [sys.executable, "-c",
     "import os, signal, sys; os.write(int(sys.argv[1]), b'1'); signal.pause()",
     str(write_fd)],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    pass_fds=(write_fd,),
)
os.close(write_fd)
assert os.read(read_fd, 1) == b"1"
os.close(read_fd)
print(child.pid, flush=True)
"""
        observe_drain = supervisor.group_drained
        send = supervisor.group_signal
        observed_live = []

        def signal_registered_group(group, event):
            descendant = int(log.read_text())
            self.assertEqual(os.getpgid(descendant), group)
            observed_live.append(descendant)
            send(group, event)

        def observe_residue(group, budget):
            # Force the first lookup to model residue after the already-observed live
            # descendant is signalled. The retry still checks the actual kernel group.
            return bool(budget) and observe_drain(group, budget)

        with (
            patch.object(supervisor, "group_signal", side_effect=signal_registered_group),
            patch.object(supervisor, "group_drained", side_effect=observe_residue) as drain,
        ):
            result = supervisor.logged_command([sys.executable, "-c", leader], log, 5)
        self.assertEqual(result.status, "stray-descendant")
        self.assertEqual(drain.call_count, 2)
        self.assertEqual(len(observed_live), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(observed_live[0], 0)

    def test_latched_cancellation_at_stream_handoff_still_fences_and_reaps(self):
        log = self.root / "handoff.log"
        original = supervisor.stream

        def latch_after_stream(*args):
            outcome = original(*args)
            supervisor.interrupted(signal.SIGTERM, None)
            return outcome

        with patch.object(supervisor, "CANCELLATION_REQUESTED", False):
            with patch.object(supervisor, "stream", side_effect=latch_after_stream):
                result = supervisor.logged_command([sys.executable, "-c", "print('observed')"], log, 5)
        self.assertEqual(result.status, "interrupted")
        self.assertEqual(log.read_bytes(), b"observed\n")

    def test_destructive_signal_happens_only_while_leader_is_unreaped(self):
        order = []
        class Leader:
            pid = 47

            def wait(self, *, timeout):
                order.append("reap")
                return 0

        def signal_group(pid, sig):
            self.assertNotIn("reap", order)
            order.append(f"signal:{sig}")

        def drained(pid, budget):
            self.assertEqual(order[-1], "reap")
            order.append("observe-drain")
            return True

        with patch.object(supervisor, "leader_exited", return_value=True):
            with patch.object(supervisor, "group_signal", side_effect=signal_group):
                with patch.object(supervisor, "group_drained", side_effect=drained):
                    self.assertTrue(supervisor.stop_group(Leader(), signal.SIGKILL))
        self.assertEqual(order, [f"signal:{signal.SIGKILL}", "reap", "observe-drain"])

    def test_unconfirmed_group_drain_preserves_target_and_partial_status(self):
        target = self.root / "owned"
        log = self.root / "unconfirmed.log"
        real_drain = supervisor.group_drained

        def refuse_fallback(process, budget):
            real_drain(process, budget)
            return False

        with patch.object(supervisor, "group_exists", return_value=True):
            with patch.object(supervisor, "TERM_GRACE", 0.05):
                with patch.object(supervisor, "group_drained", side_effect=refuse_fallback):
                    with self.assertRaises(supervisor.CleanupUnconfirmed):
                        with ci.fresh_target(target):
                            supervisor.logged_command([sys.executable, "-c", "print('partial')"], log, 5)
        self.assertTrue(target.is_dir())
        self.assertEqual(log.read_text(), "partial\n")
        self.assertEqual(json.loads(log.with_suffix(".cleanup.json").read_bytes())["status"], "cleanup-unconfirmed")

    def test_failed_campaign_preserves_partial_log_status_and_refuses_missing_summary(self):
        for code, expected in ((1, 1), (77, 77), (0, None)):
            with self.subTest(code=code):
                evidence = self.root / f"case{code}"
                evidence.mkdir()
                def fail(command, log, _timeout):
                    self.assertIn("--trust", command)
                    self.assertIn("--qualification", command)
                    log.write_bytes(b"partial fixture transcript")
                    return supervisor.ProcessResult("exited", code)
                with patch.object(ci, "logged_command", side_effect=fail):
                    paths = {item: self.root / item for item in ci.DEPLOYMENT_PATHS}
                    if expected is None:
                        with self.assertRaisesRegex(ValueError, "outcome"):
                            ci.run_campaign(paths, ci.DIRECT, self.binary, evidence)
                    else:
                        self.assertEqual(ci.run_campaign(paths, ci.DIRECT, self.binary, evidence), expected)
                self.assertEqual(json.loads((evidence / "campaign-process.json").read_bytes())["exit_status"], code)

    def test_nested_cleanup_marker_preserves_outer_build_target_on_nonpass(self):
        self.evidence.mkdir()
        (self.evidence / "campaign").mkdir()
        (self.evidence / "campaign" / "cleanup-unconfirmed.json").touch()
        target = self.root / "retained"

        def fail(command, log, timeout):
            log.write_bytes(b"nested unresolved")
            return supervisor.ProcessResult("exited", 77)

        with patch.object(ci, "logged_command", side_effect=fail):
            with self.assertRaises(supervisor.CleanupUnconfirmed):
                with ci.fresh_target(target):
                    paths = {item: self.root / item for item in ci.DEPLOYMENT_PATHS}
                    ci.run_campaign(paths, ci.DIRECT, self.binary, self.evidence)
        self.assertTrue(target.is_dir())
        record = json.loads((self.evidence / "campaign-process.json").read_bytes())
        self.assertEqual(record["exit_status"], 77)

    def test_evidence_write_failure_cannot_discard_unresolved_scratch(self):
        target = self.root / "retained"
        log = self.root / "cleanup.log"
        unresolved = supervisor.CleanupUnconfirmed("unresolved")
        original_cleanup = supervisor.stop_group

        def stop_and_refuse(*args):
            original_cleanup(*args)
            raise unresolved

        with patch.object(supervisor, "stop_group", side_effect=stop_and_refuse):
            with patch.object(supervisor, "write_json", side_effect=OSError("evidence unavailable")):
                with self.assertRaises(supervisor.CleanupUnconfirmed) as reported:
                    with ci.fresh_target(target):
                        supervisor.logged_command([sys.executable, "-c", "print('retained')"], log, 5)
        self.assertIs(reported.exception, unresolved)
        self.assertTrue(target.is_dir())
        self.assertEqual(log.read_text(), "retained\n")

    def test_unreadable_nested_ownership_marker_preserves_build(self):
        self.evidence.mkdir()
        marker = self.evidence / "campaign" / "cleanup-unconfirmed.json"
        target = self.root / "retained"
        original_lstat = Path.lstat

        def inaccessible(path):
            if path == marker:
                raise PermissionError("fixture simulated inaccessible marker")
            return original_lstat(path)

        def returned(command, log, timeout):
            log.write_bytes(b"nested outcome")
            return supervisor.ProcessResult("exited", 77)

        with patch.object(Path, "lstat", new=inaccessible):
            with patch.object(ci, "logged_command", side_effect=returned):
                with self.assertRaisesRegex(supervisor.CleanupUnconfirmed, "could not be inspected"):
                    with ci.fresh_target(target):
                        paths = {item: self.root / item for item in ci.DEPLOYMENT_PATHS}
                        ci.run_campaign(paths, ci.DIRECT, self.binary, self.evidence)
        self.assertTrue(target.is_dir())

    def test_substrate_cleanup_uncertainty_survives_failed_log_hash(self):
        fixture = self.root / "fixture"
        fixture.mkdir()
        output = self.root / "substrate"
        unresolved = supervisor.CleanupUnconfirmed("unresolved")
        seen = []

        def cargo(command, log, timeout, *, cwd, env, output_limit):
            seen.append(Path(env["TMPDIR"]))
            log.write_bytes(b"retained")
            raise unresolved

        with patch.object(substrate.sys, "platform", "linux"):
            with patch.object(substrate, "source_identity", return_value=self.identity):
                with patch.object(substrate, "SOURCE_INPUTS", []):
                    with patch.object(substrate.shutil, "which", return_value="/fixture/cargo"):
                        with patch.object(substrate, "logged_command", side_effect=cargo):
                            with patch.object(substrate, "file_digest", side_effect=OSError("log inaccessible")):
                                with self.assertRaises(supervisor.CleanupUnconfirmed) as failure:
                                    substrate.run(fixture, output, environment={})
        self.assertIs(failure.exception, unresolved)
        self.assertTrue(seen[0].is_dir())
        self.assertEqual((output / "native.log").read_bytes(), b"retained")

    def test_substrate_shares_supervisor_without_an_intermediate_group(self):
        fixture = self.root / "fixture"
        fixture.mkdir()
        output = self.root / "substrate"
        seen = []

        def cargo(command, log, timeout, *, cwd, env, output_limit):
            self.assertEqual(command[:3], ["cargo", "+1.100.0", "test"])
            self.assertEqual(cwd, substrate.REPO)
            self.assertEqual(output_limit, substrate.MAX_LOG_BYTES)
            self.assertEqual(Path(env["EXACOPY_REMOTE_SUBSTRATE_PARENT"]), fixture)
            scratch = Path(env["TMPDIR"])
            self.assertEqual(Path(env["CARGO_TARGET_DIR"]), scratch / "cargo-target")
            self.assertEqual(scratch.parent, fixture)
            seen.append(scratch)
            log.write_bytes(b"".join(b"EXACOPY_REMOTE_SUBSTRATE_PASS " + cut.encode() + b"\n"
                                     for cut in substrate.EXPECTED)
                            + b"EXACOPY_REMOTE_SUBSTRATE_PARENT 195 5 0123456789abcdef0123456789abcdef 819 17 22\n")
            return supervisor.ProcessResult("exited", 0)

        with patch.object(substrate.sys, "platform", "linux"):
            with patch.object(substrate, "source_identity", return_value=self.identity):
                with patch.object(substrate, "SOURCE_INPUTS", []):
                    with patch.object(substrate.shutil, "which", return_value="/fixture/cargo"):
                        with patch.object(substrate, "logged_command", side_effect=cargo):
                            self.assertEqual(substrate.run(fixture, output, environment={"PATH": "/fixture"}), 0)
                        refused = self.root / "refused"
                        with patch.object(substrate, "logged_command") as called:
                            self.assertEqual(substrate.run(fixture, refused, environment={"CARGO_TARGET_DIR": "target"}), 77)
                        called.assert_not_called()
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0].exists())
        record = json.loads((output / "result.json").read_bytes())
        self.assertFalse(record["qualifies_remote_download"])
        self.assertEqual(record["outcome"], "passed_native_substrate")
        self.assertEqual(record["process_status"], "exited")
        self.assertEqual(record["destination_parent"]["inode"], "5")

    def test_substrate_requires_unique_bounded_native_parent(self):
        log = self.root / "native.log"
        marker = b"EXACOPY_REMOTE_SUBSTRATE_PARENT 195 5 0123456789abcdef0123456789abcdef 819 17 22\n"
        cases = b"".join(b"EXACOPY_REMOTE_SUBSTRATE_PASS " + name.encode() + b"\n" for name in substrate.EXPECTED)
        log.write_bytes(cases + marker)
        observed, parent = substrate.read_markers(log)
        self.assertEqual(observed, substrate.EXPECTED)
        self.assertEqual(parent["inode"], "5")
        log.write_bytes(cases + marker + marker)
        self.assertIsNone(substrate.read_markers(log)[1])
        log.write_bytes(cases + marker.replace(b" 195 ", b" 18446744073709551616 "))
        self.assertIsNone(substrate.read_markers(log)[1])
        with patch.object(substrate, "MAX_LOG_BYTES", 8):
            with self.assertRaisesRegex(ValueError, "input bound"):
                substrate.read_markers(log)



class HostedLauncherControls(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="exacopy-hosted-control-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve()
        self.runner = self.root / "runner-temp"
        self.runner.mkdir()
        self.evidence = self.runner / "exacopy-hosted-native-remote"
        self.marker = self.evidence / "cleanup-unconfirmed.txt"
        capture = self.root / ".github" / "ci" / "capture.sh"
        capture.parent.mkdir(parents=True)
        capture.write_text("""#!/usr/bin/env bash
set -euo pipefail
marker="$RUNNER_TEMP/exacopy-hosted-native-remote/cleanup-unconfirmed.txt"
test -s "$marker"
case "$1" in
  hosted-fixture-filesystem)
    test "$2" = findmnt && test "$3" = -T
    if [[ "$OUTCOME" == filesystem-failed ]]; then exit 1; fi
    ;;
  native-hosted)
    shift
    test "$#" = 10
    test "$1" = python3 && test "$2" = -B && test "$3" = .github/ci/remote_qualification.py
    test "$4" = hosted && test "$5" = --route && test "$6" = direct-pinned-tcp-v1
    test "$7" = --destination && test "$9" = --evidence
    test "${10}" = "$RUNNER_TEMP/exacopy-hosted-native-remote/diagnostic"
    work="$8"
    test -d "$work"
    printf '%s\n' "$work" > "$RUNNER_TEMP/fixture-argument"
    mkdir -- "${10}"
    printf 'synthetic wrapper evidence\n' > "${10}/result.txt"
    case "$OUTCOME" in
      pass) exit 0 ;;
      failed) exit 1 ;;
      blocked) exit 77 ;;
      retained-build)
        mkdir -- "$RUNNER_TEMP/exacopy-hosted-native-remote/exacopy-remote-build-target"
        exit 77 ;;
      retained-child)
        touch -- "$work/child"
        exit 0 ;;
      replaced-fixture)
        mv -- "$work" "$work.original"
        mkdir -- "$work"
        exit 0 ;;
      interrupted)
        kill -TERM "$PPID"
        exit 0 ;;
      *) exit 2 ;;
    esac
    ;;
  *) exit 2 ;;
esac
""")

    def launch(self, outcome):
        return subprocess.run(
            ["bash", str(ROOT / ".github" / "ci" / "hosted_remote_substrate.sh")],
            cwd=self.root,
            env=dict(os.environ, RUNNER_TEMP=os.fspath(self.runner), OUTCOME=outcome),
            capture_output=True, text=True, timeout=10, check=False,
        )

    def owned_path(self):
        return Path((self.runner / "fixture-argument").read_text().strip())

    def test_confirmed_cleanup_preserves_native_exit_and_evidence(self):
        for outcome, expected in (("pass", 0), ("failed", 1), ("blocked", 77)):
            with self.subTest(outcome=outcome):
                if self.evidence.exists():
                    self.evidence.rename(self.runner / f"retained-{outcome}")
                result = self.launch(outcome)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertFalse(self.owned_path().exists())
                self.assertFalse(self.marker.exists())
                self.assertTrue((self.evidence / "diagnostic" / "result.txt").is_file())

    def test_filesystem_probe_failure_cleans_without_starting_wrapper(self):
        result = self.launch("filesystem-failed")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((self.runner / "fixture-argument").exists())
        self.assertFalse(list(self.evidence.glob("fixture.*")))
        self.assertFalse(self.marker.exists())

    def test_retained_build_defers_even_empty_fixture_cleanup(self):
        result = self.launch("retained-build")
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertTrue(self.owned_path().is_dir())
        self.assertTrue((self.evidence / "exacopy-remote-build-target").is_dir())
        self.assertIn("cleanup=unconfirmed", self.marker.read_text())

    def test_nonempty_or_rebound_fixture_is_never_removed(self):
        for outcome in ("retained-child", "replaced-fixture"):
            with self.subTest(outcome=outcome):
                if self.evidence.exists():
                    self.evidence.rename(self.runner / f"retained-{outcome}")
                result = self.launch(outcome)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertTrue(self.marker.exists())
                work = self.owned_path()
                self.assertTrue(work.is_dir())
                if outcome == "retained-child":
                    self.assertTrue((work / "child").is_file())
                else:
                    self.assertTrue(Path(f"{work}.original").is_dir())

    def test_interruption_retains_empty_fixture_without_build_target(self):
        result = self.launch("interrupted")
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assertTrue(self.marker.exists())
        self.assertTrue(self.owned_path().is_dir())
        self.assertFalse((self.evidence / "exacopy-remote-build-target").exists())

    def test_preamble_interruption_preserves_fixture_before_assignment(self):
        tools = self.root / "interposed-tools"
        tools.mkdir()
        mktemp = tools / "mktemp"
        mktemp.write_text("""#!/usr/bin/env bash
set -euo pipefail
test -s "$RUNNER_TEMP/exacopy-hosted-native-remote/cleanup-unconfirmed.txt"
work=$("$ACTUAL_MKTEMP" "$@")
printf '%s\n' "$work" > "$RUNNER_TEMP/preamble-fixture"
for ((attempt=0; attempt<300; attempt++)); do
  if [[ -e "$RUNNER_TEMP/release-preamble" ]]; then
    printf '%s\n' "$work"
    exit 0
  fi
  sleep 0.01
done
exit 1
""")
        mktemp.chmod(0o700)
        observed = self.runner / "preamble-fixture"
        release = self.runner / "release-preamble"
        with subprocess.Popen(
            ["bash", str(ROOT / ".github" / "ci" / "hosted_remote_substrate.sh")],
            cwd=self.root,
            env=dict(
                os.environ, RUNNER_TEMP=os.fspath(self.runner), OUTCOME="pass",
                PATH=os.pathsep.join((os.fspath(tools), os.environ["PATH"])),
                ACTUAL_MKTEMP=shutil.which("mktemp"),
            ),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) as process:
            try:
                deadline = time.monotonic() + 2
                while not observed.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(observed.is_file())
                process.send_signal(signal.SIGTERM)
                release.touch()
                _, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 143, stderr)
            finally:
                release.touch()
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
        work = Path(observed.read_text().strip())
        self.assertEqual(work.parent, self.evidence)
        self.assertTrue(work.is_dir())
        retained = self.marker.read_text()
        self.assertIn(f"fixture_parent={self.evidence}", retained)
        self.assertNotIn("\nfixture=", retained)
        self.assertFalse((self.runner / "fixture-argument").exists())
        self.assertFalse((self.evidence / "exacopy-remote-build-target").exists())

    def test_existing_evidence_root_is_refused_without_removing_its_contents(self):
        self.evidence.mkdir()
        self.marker.write_text("incumbent cleanup marker")
        result = self.launch("pass")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.runner / "fixture-argument").exists())
        self.assertEqual(self.marker.read_text(), "incumbent cleanup marker")

if __name__ == "__main__":
    unittest.main(verbosity=2)
