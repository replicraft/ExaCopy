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
from remote_commissioning_authority import make_authority, read_evidence, read_json
from remote_commissioning_candidate import CandidateRequest, import_candidate
from remote_commissioning_peer import Blocked, DPKG_QUERY, Fixture, SSHD, checkpoint, directory_identity, preflight, run

SCHEMA = "exacopy.linux-remote-commissioning.v1"
CAMPAIGN_SCHEMA = "exacopy.linux-remote-cli-campaign.v1"
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


def hosted_parent(program="remote_commissioning.py", events=("push", "workflow_dispatch")):
    if (
        sys.platform != "linux" or os.geteuid() == 0 or os.getuid() != os.geteuid()
        or os.getenv("GITHUB_ACTIONS") != "true" or os.getenv("RUNNER_ENVIRONMENT") != "github-hosted"
        or os.getenv("RUNNER_OS") != "Linux" or os.getenv("RUNNER_ARCH") != "X64"
        or os.getenv("GITHUB_SERVER_URL") != "https://github.com"
        or os.getenv("GITHUB_REPOSITORY", "").lower() != "replicraft/exacopy"
        or os.getenv("GITHUB_REF") != "refs/heads/main"
        or os.getenv("GITHUB_EVENT_NAME") not in events
        or "EXACOPY_REMOTE_DEPLOYMENT" in os.environ
        or len(sys.argv) != 1
    ):
        raise Blocked("commissioning requires the closed GitHub-hosted Ubuntu job")
    # The workflow intentionally provisions no named deployment or authority input.
    if Path(sys.argv[0]).name != program or Path.cwd() != native.REPO:
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


def export(work, output, case_files=PEER_FILES):
    hashes = {}
    for relative, maximum in (BASE_FILES | case_files).items():
        digest = capture_file(work, output, relative, maximum)
        if digest is not None:
            hashes[relative] = digest
    return hashes


def check_case_exports(report, hashes, case_files, *, expected_summary_sha256=None):
    summary_bytes = read_evidence(report / "campaign/summary.json", MAX_SUMMARY)
    if expected_summary_sha256 is not None and hashlib.sha256(summary_bytes).hexdigest() != expected_summary_sha256:
        raise EvidenceFailed("the exported campaign summary differs from the checked candidate summary")
    summary = json.loads(summary_bytes)
    declared = summary.get("artifacts_sha256") if isinstance(summary, dict) else None
    if not isinstance(declared, dict) or any(
        relative not in hashes or hashes[relative] != declared.get(Path(relative).name)
        for relative in case_files
    ):
        raise EvidenceFailed("successful campaign lacks its complete exact exported transcripts")


def check_candidate_summary(summary, candidate, authority, inputs):
    if not isinstance(summary, dict):
        raise EvidenceFailed("campaign result is not a structured candidate observation")
    cases = summary.get("cases")
    if (
        summary.get("schema") != CAMPAIGN_SCHEMA or summary.get("status") != "pass"
        or type(summary.get("exit_status")) is not int or summary["exit_status"] != 0
        or summary.get("route") != candidate["campaign_route"]
        or summary.get("binary_sha256") != candidate["binary"]["sha256"]
        or summary.get("binary_build_digest") != candidate["build_blake3_derive_key"]
        or summary.get("qualification_digest") != authority["record_digest"]
        or any(summary.get(name) != digest for name, digest in inputs.items())
        or summary.get("issues_new_qualification") is not False
        or not isinstance(cases, list) or len(cases) != len(CASES)
        or any(not isinstance(row, dict) or row.get("name") != name or row.get("outcome") != "pass"
               for row, name in zip(cases, CASES))
    ):
        raise EvidenceFailed("campaign result does not bind the checked frozen candidate and ordered cases")


def check_candidate_exports(report, evidence):
    hashes = evidence["artifacts_sha256"]
    if BASE_FILES.keys() - hashes.keys():
        raise EvidenceFailed("exported commissioning evidence lacks required candidate observations")
    inputs = evidence["authority"]["inputs_sha256"]
    expected = {
        "build/result.json": evidence["candidate"]["manifest_sha256"],
        "campaign/summary.json": evidence["observations"]["campaign_summary_sha256"],
        "native-facts/facts.json": inputs["native_facts_sha256"],
        "native-facts-recheck/facts.json": inputs["native_facts_sha256"],
        "substrate/result.json": inputs["substrate_result_sha256"],
        "substrate/native.log": inputs["substrate_log_sha256"],
    }
    if any(hashes.get(name) != digest for name, digest in expected.items()):
        raise EvidenceFailed("exported commissioning evidence lost the frozen candidate binding")
    candidate = evidence["candidate"]
    campaign_process = ("rendezvous", None) if candidate["campaign_route"] == native.EMBEDDED else ("exited", 0)
    for relative, (status, exit_status) in (
        ("native-facts/process.json", ("exited", 0)),
        ("campaign-process.json", campaign_process),
    ):
        data = read_evidence(report / relative)
        details = json.loads(data)
        if (
            hashlib.sha256(data).hexdigest() != hashes[relative]
            or not isinstance(details, dict) or details.get("status") != status or "exit_status" not in details
            or type(details["exit_status"]) is not type(exit_status) or details["exit_status"] != exit_status
        ):
            raise EvidenceFailed("exported commissioning process evidence does not cover the successful candidate run")
    if candidate.get("post_campaign_custody") != candidate_custody(candidate):
        raise EvidenceFailed("candidate archive and ELF custody were not confirmed after the campaign")
    check_case_exports(report, hashes, PEER_FILES, expected_summary_sha256=expected["campaign/summary.json"])


def import_preview_candidate(request, work, target, route, source, evidence):
    frozen = import_candidate(request, work / "build", target / "exacopy", route, source)
    evidence["candidate"] = {
        name: frozen.report[name]
        for name in ("campaign_route", "producer_route", "source", "transport", "archive", "binary", "compiled_features")
    }
    evidence["candidate"].update(manifest_sha256=frozen.digest, build_blake3_derive_key=None)
    return frozen, native.CandidateFactsBinding(frozen.digest, route)


def check_candidate_custody(verify, outcome, evidence):
    try:
        verify()
    except (EvidenceFailed, OSError, ValueError):
        evidence["candidate"]["post_campaign_custody"] = {"status": "failed"}
        if outcome == 0:
            raise


def candidate_custody(candidate):
    return {"status": "confirmed", "archive_sha256": candidate["archive"]["sha256"],
            "elf_sha256": candidate["binary"]["sha256"]}


def confirm_candidate_archive(frozen, outcome, evidence):
    check_candidate_custody(frozen.verify_archive, outcome, evidence)
    candidate = evidence["candidate"]
    if "post_campaign_custody" not in candidate:
        candidate["post_campaign_custody"] = candidate_custody(candidate)


def read_build_manifest(manifest):
    with manifest.open("rb") as stream:
        contents = stream.read(MAX_SUMMARY + 1)
    if not 0 < len(contents) <= MAX_SUMMARY:
        raise Blocked("the generated build manifest exceeds its input bound")
    return json.loads(contents), hashlib.sha256(contents).hexdigest()


def verify_build_custody(manifest, binary, build, digest):
    if read_build_manifest(manifest) != (build, digest):
        raise EvidenceFailed("build evidence changed during commissioning")
    native.verify_executable_custody(binary.parent / "release/exacopy", binary, build)


def observations(fixture, build, binary, env, work, verify_build, *, candidate=None):
    verify_build()
    first = native.collect_facts(
        fixture.destination, binary, work / "native-facts", env=env, manifest=build, candidate=candidate,
    )
    if first != 0:
        raise Blocked("exact fixture native facts were unavailable")
    if candidate is not None:
        verify_build()
    result = native.linux_remote_substrate.run(fixture.destination, work / "substrate", environment=env)
    if result != 0:
        raise Blocked("exact-root substrate diagnostics did not pass")
    verify_build()
    second = native.collect_facts(
        fixture.destination, binary, work / "native-facts-recheck", env=env, manifest=build, candidate=candidate,
    )
    if second != 0 or (
        work.joinpath("native-facts/facts.json").read_bytes()
        != work.joinpath("native-facts-recheck/facts.json").read_bytes()
    ):
        raise Blocked("commissioning native facts changed")
    verify_build()


def direct_campaign(fixture, paths, binary, work):
    return native.run_campaign(paths, native.DIRECT, binary, work)


def run_fixture(fixture, work, binary, manifest, env, b3sum, evidence, verify_build, campaign, *, candidate=None):
    verify_build()
    fixture.make_root()
    observations(fixture, manifest, binary, env, work, verify_build, candidate=candidate)
    checkpoint()
    record, trust, authority = make_authority(fixture, work, manifest, b3sum, candidate=candidate, binary=binary)
    verify_build()
    evidence["authority"] = authority
    evidence["inputs"] = {
        "native_facts_sha256": file_digest(work / "native-facts/facts.json"),
        "substrate_result_sha256": file_digest(work / "substrate/result.json"),
        "campaign_definition_sha256": {
            name: file_digest(native.REPO / native.FIXTURES / name)
            for name in ("campaign.py", "fixture.py", "process.py")
        },
    }
    if candidate is None:
        facts = read_json(work / "native-facts/facts.json")
        evidence["build"]["build_blake3_derive_key"] = facts["build_blake3_derive_key"]
    else:
        evidence["candidate"]["build_blake3_derive_key"] = authority["build_blake3_derive_key"]
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
    verify_build()
    if candidate is not None:
        inputs = {"ssh_profile_sha256": profile, "trust_sha256": trust, "qualification_sha256": record}
        input_digests = {name: file_digest(path) for name, path in inputs.items()}
    result = campaign(fixture, {
        "destination": fixture.destination, "owner_profile": owner, "ssh_profile": profile,
        "qualification": record, "trust": trust, "source_small": small,
        "source_interrupt": large, "sshd_log": peer_log,
    }, binary, work)
    if candidate is not None:
        check_candidate_custody(verify_build, result, evidence)
    summary_file = work / "campaign/summary.json"
    if summary_file.exists():
        summary_bytes = read_evidence(summary_file, MAX_SUMMARY)
        summary = json.loads(summary_bytes)
        if summary.get("qualification_digest") != authority["record_digest"] and result == 0:
            raise EvidenceFailed("campaign result lost the exact synthetic authority binding")
        if candidate is not None and result == 0:
            check_candidate_summary(summary, evidence["candidate"], authority, input_digests)
            if any(file_digest(path) != input_digests[name] for name, path in inputs.items()):
                raise EvidenceFailed("protected route or authority inputs changed")
        evidence["observations"] = {
            "campaign_summary_sha256": hashlib.sha256(summary_bytes).hexdigest(), "outer_route_evidence_sha256": None,
        }
    if result == 0:
        if evidence["observations"] is None:
            raise EvidenceFailed("native campaign pass is missing its observations")
        native.verified_pins("campaign-post", work, env)
        try:
            verify_build()
        except (OSError, ValueError) as error:
            raise EvidenceFailed("executable custody changed during commissioning") from error
    return result


def execute(parent, report, work, evidence, fixture_kind=None, campaign=direct_campaign):
    source = native.source_identity(native.REPO)
    if source["revision"] != os.environ["GITHUB_SHA"]:
        raise Blocked("fixture checkout differs from the selected workflow source revision")
    evidence["source"] = source
    request = CandidateRequest.from_hosted_environment(parent.parent, route=native.DIRECT)
    if request is not None and (fixture_kind is not None or campaign is not direct_campaign):
        raise Blocked("the frozen candidate requires the ordinary direct commissioning campaign")
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
    sshd_digest = file_digest(Path(SSHD))
    evidence["b3sum_sha256"] = file_digest(Path(b3sum))
    fixture = (fixture_kind or Fixture)(evidence["fixture_id"], gid)
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
            frozen = candidate = None
            if request is None:
                binary, manifest = native.build_cli(
                    native.DIRECT, work / "build", target, env, staged_executable=target / "exacopy",
                )
                build, digest = read_build_manifest(manifest)
                evidence["build"] = {
                    "elf_sha256": build["build_sha256"], "compiled_features": build["compiled_features"],
                    "build_manifest_sha256": digest, "build_blake3_derive_key": None,
                }
            else:
                frozen, candidate = import_preview_candidate(request, work, target, native.DIRECT, source, evidence)
                binary, manifest = frozen.binary, frozen.manifest

            def verify_build():
                expected_source = source if frozen is not None else build["source_after"]
                if native.source_identity(native.REPO) != expected_source:
                    raise EvidenceFailed("source changed during commissioning")
                if frozen is not None:
                    frozen.verify()
                else:
                    verify_build_custody(manifest, binary, build, digest)

            outcome = run_fixture(fixture, work, binary, manifest, env, b3sum, evidence, verify_build, campaign,
                                  candidate=candidate)
            if frozen is not None:
                confirm_candidate_archive(frozen, outcome, evidence)
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


def main(*, fixture_kind=None, campaign=direct_campaign, program="remote_commissioning.py",
         report_name="exacopy-direct-commissioning", case_files=PEER_FILES, require_case_exports=False,
         events=("push", "workflow_dispatch")):
    if len(sys.argv) != 1:
        print("The hosted commissioning job accepts no arguments.", file=sys.stderr)
        return 77
    try:
        fixed_parent = hosted_parent(program, events)
    except (Blocked, OSError, KeyError) as error:
        print(f"Direct commissioning blocked: {error}", file=sys.stderr)
        return 77
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parent = fixed_parent / report_name
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
        result = execute(parent, report, work, evidence, fixture_kind, campaign)
    except CleanupUnconfirmed:
        evidence["reason"] = "owned fixture cleanup is unconfirmed"
        evidence["cleanup"] = {"owned_groups": "unconfirmed", "fixture_state": "retained-uncertain"}
    except (Blocked, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        evidence["reason"] = str(error) if isinstance(error, Blocked) else type(error).__name__
    finally:
        try:
            evidence["artifacts_sha256"] = export(work, report, case_files)
            if evidence["cleanup"]["fixture_state"] != "retained-uncertain":
                shutil.rmtree(work)
        except (OSError, Blocked):
            if result == 0:
                result = 77
            evidence["reason"] = "allowlisted evidence export or private scratch removal failed"
        if result == 0 and require_case_exports:
            try:
                check_case_exports(report, evidence["artifacts_sha256"], case_files)
            except (Blocked, EvidenceFailed, OSError, KeyError, ValueError, TypeError) as error:
                result = 1
                evidence["reason"] = (
                    str(error) if isinstance(error, EvidenceFailed) else "successful campaign summary cannot be read"
                )
        if result == 0 and "candidate" in evidence:
            try:
                check_candidate_exports(report, evidence)
            except (Blocked, EvidenceFailed, OSError, KeyError, ValueError, TypeError) as error:
                result = 1
                evidence["reason"] = str(error) if isinstance(error, EvidenceFailed) else "frozen candidate evidence is unavailable"
        evidence["exit_status"] = result
        evidence["status"] = {0: "pass", 1: "fail", 77: "blocked"}[result]
        write_json(report / "commissioning.json", evidence)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
