#!/usr/bin/env python3
"""Run the ordinary direct CLI inside a disposable hosted commissioning fixture."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import signal
import stat
import subprocess
import sys

import remote_qualification as native
from native_supervision import CleanupUnconfirmed, file_digest, interrupted, logged_command, write_json

sys.path.insert(0, str(native.REPO / native.FIXTURES))
from fixture import Blocked as EvidenceBlocked, Failed as EvidenceFailed
from remote_commissioning_authority import make_authority, read_json
from remote_commissioning_peer import Blocked, DPKG_QUERY, Fixture, SSHD, checkpoint, directory_identity, preflight, run

SCHEMA = "exacopy.linux-remote-commissioning.v1"
MAX_SUMMARY = 64 * 1024
BASE_FILES = {
    "build/result.json": MAX_SUMMARY,
    "native-facts/facts.json": MAX_SUMMARY,
    "native-facts/process.json": MAX_SUMMARY,
    "native-facts-recheck/facts.json": MAX_SUMMARY,
    "substrate/result.json": MAX_SUMMARY,
    "substrate/native.log": 8 * 1024 * 1024,
    "campaign-process.json": MAX_SUMMARY,
    "campaign/summary.json": MAX_SUMMARY,
}
CASES = (
    "qualification-path-control", "qualification-refusal", "get", "incumbent",
    "process-kill", "resume", "post-intent",
)
PEER_FILES = {f"campaign/{case}.openssh.log": MAX_SUMMARY for case in CASES}


def hosted_parent():
    if (
        sys.platform != "linux" or os.geteuid() == 0 or os.getuid() != os.geteuid()
        or os.getenv("GITHUB_ACTIONS") != "true" or os.getenv("RUNNER_ENVIRONMENT") != "github-hosted"
        or os.getenv("RUNNER_OS") != "Linux" or os.getenv("RUNNER_ARCH") != "X64"
        or os.getenv("GITHUB_SERVER_URL") != "https://github.com"
        or os.getenv("GITHUB_REPOSITORY", "").lower() != "replicraft/exacopy"
        or os.getenv("GITHUB_REF") != "refs/heads/main"
        or os.getenv("GITHUB_EVENT_NAME") not in {"push", "workflow_dispatch"}
        or "EXACOPY_REMOTE_DEPLOYMENT" in os.environ
        or len(sys.argv) != 1
    ):
        raise Blocked("commissioning requires the closed GitHub-hosted Ubuntu job")
    # The workflow intentionally provisions no named deployment or authority input.
    if not sys.argv[0].endswith("remote_commissioning.py") or Path.cwd() != native.REPO:
        raise Blocked("commissioning must run from the selected source checkout")
    os_release = Path("/etc/os-release").read_text(encoding="ascii").splitlines()
    if not {'ID=ubuntu', 'VERSION_ID="24.04"'} <= set(os_release):
        raise Blocked("commissioning requires Ubuntu 24.04")
    parent = Path(os.environ["RUNNER_TEMP"])
    if not parent.is_absolute() or parent.resolve(strict=True) != parent or parent.is_relative_to(native.REPO):
        raise Blocked("runner temporary storage is outside the selected scope")
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise Blocked("runner temporary storage is not an owned directory")
    return parent


def capture_file(work, output, relative, maximum):
    original = work / relative
    try:
        selected = original.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(selected.st_mode) or selected.st_nlink != 1
        or selected.st_uid != os.geteuid() or selected.st_size > maximum
        or original.resolve(strict=True) != original
    ):
        raise Blocked("commissioning evidence file is outside its allowed type or extent")
    descriptor = os.open(original, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        observed = os.fstat(stream.fileno())
        if native.file_observation(observed) != native.file_observation(selected):
            raise Blocked("commissioning evidence changed before capture")
        data = stream.read(maximum + 1)
        if (
            len(data) != selected.st_size
            or native.file_observation(os.fstat(stream.fileno())) != native.file_observation(selected)
        ):
            raise Blocked("commissioning evidence changed during capture")
    target = output / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as destination:
        destination.write(data)
    return hashlib.sha256(data).hexdigest()


def export(work, output):
    hashes = {}
    for relative, maximum in (BASE_FILES | PEER_FILES).items():
        digest = capture_file(work, output, relative, maximum)
        if digest is not None:
            hashes[relative] = digest
    return hashes


def observations(fixture, build, binary, env, work):
    first = native.collect_facts(fixture.destination, binary, work / "native-facts", env=env, manifest=build)
    if first != 0:
        raise Blocked("exact fixture native facts were unavailable")
    result = native.linux_remote_substrate.run(fixture.destination, work / "substrate", environment=env)
    if result != 0:
        raise Blocked("exact-root substrate diagnostics did not pass")
    second = native.collect_facts(fixture.destination, binary, work / "native-facts-recheck", env=env, manifest=build)
    if second != 0 or (
        work.joinpath("native-facts/facts.json").read_bytes()
        != work.joinpath("native-facts-recheck/facts.json").read_bytes()
    ):
        raise Blocked("commissioning native facts changed")


def run_fixture(fixture, work, binary, manifest, env, b3sum, evidence):
    fixture.make_root()
    observations(fixture, manifest, binary, env, work)
    checkpoint()
    record, trust, authority = make_authority(fixture, work, manifest, b3sum)
    evidence["authority"] = authority
    evidence["inputs"] = {
        "native_facts_sha256": file_digest(work / "native-facts/facts.json"),
        "substrate_result_sha256": file_digest(work / "substrate/result.json"),
        "campaign_definition_sha256": {
            name: file_digest(native.REPO / native.FIXTURES / name)
            for name in ("campaign.py", "fixture.py", "process.py")
        },
    }
    facts = read_json(work / "native-facts/facts.json")
    evidence["build"]["build_blake3_derive_key"] = facts["build_blake3_derive_key"]
    owner = fixture.private / "owner"
    checkpoint()
    init = logged_command([binary, "profile", "init", owner], work / "owner-init.log", 10, env=env, output_limit=8192)
    if not init.passed():
        raise Blocked("fixture owner profile was not created by the ordinary CLI")
    directory_identity(owner, os.geteuid(), 0o700)
    small, large = fixture.make_sources()
    fixture.make_account()
    profile, peer_log, peer = fixture.make_peer()
    evidence["peer"] = peer
    checkpoint()
    result = native.run_campaign({
        "destination": fixture.destination, "owner_profile": owner, "ssh_profile": profile,
        "qualification": record, "trust": trust, "source_small": small,
        "source_interrupt": large, "sshd_log": peer_log,
    }, native.DIRECT, binary, work)
    summary_file = work / "campaign/summary.json"
    if summary_file.exists():
        summary = read_json(summary_file, MAX_SUMMARY)
        if summary.get("qualification_digest") != authority["record_digest"] and result == 0:
            raise EvidenceFailed("campaign result lost the exact synthetic authority binding")
        evidence["observations"] = {
            "campaign_summary_sha256": file_digest(summary_file), "outer_route_evidence_sha256": None,
        }
    if result == 0:
        if evidence["observations"] is None:
            raise EvidenceFailed("native campaign pass is missing its observations")
        build = read_json(manifest, MAX_SUMMARY)
        native.verified_pins("campaign-post", work, env)
        if (
            native.source_identity(native.REPO) != build["source_after"]
            or native.binary_observation(binary) != (build["build_size"], build["build_sha256"])
        ):
            raise EvidenceFailed("source or executable changed during commissioning")
    return result


def execute(parent, report, work, evidence):
    evidence["host_preflight"] = {}
    gid = preflight(evidence["host_preflight"])
    b3sum = shutil.which("b3sum")
    tool_root = parent.parent / "exacopy-commissioning-tools"
    directory_identity(tool_root, os.geteuid(), 0o700)
    selected_b3sum = tool_root / "unpacked/usr/bin/b3sum"
    if not b3sum or Path(b3sum) != selected_b3sum or selected_b3sum.resolve(strict=True) != selected_b3sum:
        raise Blocked("the job-local independent Ubuntu b3sum is unavailable")
    tool = selected_b3sum.stat()
    if not stat.S_ISREG(tool.st_mode) or tool.st_uid != os.geteuid() or tool.st_mode & 0o022:
        raise Blocked("the job-local digest binary is outside the admitted owner scope")
    version = run(
        [DPKG_QUERY, "--show", "--showformat=${Version}\n", "openssh-server"],
        operation="exact independent OpenSSH package version",
    ).decode("ascii").strip()
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+:~\-]{1,120}", version):
        raise Blocked("unexpected OpenSSH tool identity")
    source = native.source_identity(native.REPO)
    if source["revision"] != os.environ["GITHUB_SHA"]:
        raise Blocked("fixture checkout differs from the selected workflow source revision")
    evidence["source"] = source
    sshd_digest = file_digest(Path(SSHD))
    evidence["b3sum_sha256"] = file_digest(Path(b3sum))
    fixture = Fixture(evidence["fixture_id"], gid)
    target = parent / "private-build"
    env = native.build_environment(target)
    env["CARGO_BUILD_JOBS"] = "2"
    marker = report / "cleanup-unconfirmed.json"
    write_json(marker, {"fixture_id": fixture.nonce, "root": str(fixture.root), "unit": fixture.unit,
                        "account": fixture.account})
    outcome = 77
    with native.fresh_target(target):
        unresolved_child = False
        try:
            binary, manifest = native.build_cli(native.DIRECT, work / "build", target, env)
            build = read_json(manifest, MAX_SUMMARY)
            evidence["build"] = {
                "elf_sha256": build["build_sha256"], "compiled_features": build["compiled_features"],
                "build_manifest_sha256": file_digest(manifest), "build_blake3_derive_key": None,
            }
            outcome = run_fixture(fixture, work, binary, manifest, env, b3sum, evidence)
            if evidence["peer"] is not None:
                if file_digest(Path(SSHD)) != sshd_digest:
                    raise EvidenceFailed("independent OpenSSH executable changed during commissioning")
                evidence["peer"]["package_version"] = version
                evidence["peer"]["executable_sha256"] = sshd_digest
        except CleanupUnconfirmed:
            unresolved_child = True
            # The independent listening service has its own already held
            # identity. An unresolved CLI group still prevents file/account
            # removal even when the listener can be confirmed stopped.
            if fixture.invocation is not None:
                try:
                    fixture.stop_peer()
                except (OSError, ValueError, CleanupUnconfirmed):
                    evidence["peer_cleanup"] = "unconfirmed"
                else:
                    evidence["peer_cleanup"] = "confirmed-drained"
            raise
        except (Blocked, EvidenceBlocked, EvidenceFailed, OSError, ValueError, KeyError,
                TypeError, subprocess.SubprocessError) as error:
            outcome = 1 if isinstance(error, EvidenceFailed) else 77
            evidence["reason"] = str(error) if isinstance(error, (Blocked, EvidenceBlocked, EvidenceFailed)) else type(error).__name__
        except Exception as error:
            outcome = 1
            evidence["reason"] = f"unexpected fixture failure: {type(error).__name__}"
        finally:
            if not unresolved_child:
                try:
                    fixture.stop()
                except (OSError, ValueError, CleanupUnconfirmed) as error:
                    raise CleanupUnconfirmed("direct commissioning cleanup is unconfirmed") from error
                evidence["cleanup"] = {
                    "owned_groups": "confirmed-drained",
                    "fixture_state": "removed" if fixture.root_attempted else "not-created",
                }
    marker.unlink()
    return outcome


def main():
    if len(sys.argv) != 1:
        print("The hosted commissioning job accepts no arguments.", file=sys.stderr)
        return 77
    try:
        fixed_parent = hosted_parent()
    except (Blocked, OSError, KeyError) as error:
        print(f"Direct commissioning blocked: {error}", file=sys.stderr)
        return 77
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parent = fixed_parent / "exacopy-direct-commissioning"
    try:
        parent.mkdir(mode=0o700)
    except OSError:
        print("Direct commissioning requires fresh owned report storage.", file=sys.stderr)
        return 77
    report = parent / "report"
    work = parent / "private"
    report.mkdir(mode=0o700)
    work.mkdir(mode=0o700)
    evidence = {
        "schema": SCHEMA, "status": "blocked", "exit_status": 77, "route": native.DIRECT,
        "fixture_id": secrets.token_hex(10), "production_qualification_issued": False,
        "source": None, "build": None, "b3sum_sha256": None, "host_preflight": None,
        "authority": None, "inputs": None, "observations": None,
        "peer": None, "peer_cleanup": None, "cleanup": {"owned_groups": "not-started", "fixture_state": "not-created"},
        "artifacts_sha256": {},
    }
    result = 77
    try:
        result = execute(parent, report, work, evidence)
    except CleanupUnconfirmed:
        evidence["reason"] = "owned fixture cleanup is unconfirmed"
        evidence["cleanup"] = {"owned_groups": "unconfirmed", "fixture_state": "retained-uncertain"}
    except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        evidence["reason"] = str(error) if isinstance(error, Blocked) else type(error).__name__
    finally:
        try:
            evidence["artifacts_sha256"] = export(work, report)
            if evidence["cleanup"]["fixture_state"] != "retained-uncertain":
                shutil.rmtree(work)
        except (OSError, Blocked):
            if result == 0:
                result = 77
            evidence["reason"] = "allowlisted evidence export or private scratch removal failed"
        evidence["exit_status"] = result
        evidence["status"] = {0: "pass", 1: "fail", 77: "blocked"}[result]
        write_json(report / "commissioning.json", evidence)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
