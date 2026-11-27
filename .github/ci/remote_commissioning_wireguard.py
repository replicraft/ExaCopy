#!/usr/bin/env python3
"""Commission the ordinary embedded CLI against an isolated hosted kernel peer."""
from contextlib import contextmanager
from dataclasses import asdict
from enum import Enum
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import struct
import sys
import threading

import remote_commissioning as direct
from remote_commissioning import native
from native_supervision import CleanupUnconfirmed, file_digest, interrupted, logged_command, write_json
from remote_commissioning_authority import make_authority, read_evidence, read_json
from remote_commissioning_peer import Blocked, Fixture, INSTALL, SSHD, checkpoint, directory_identity, run, unit_status
from remote_commissioning_wireguard_lane import ClientBudget, ClientLane, ClientStep
from remote_commissioning_wireguard_net import CLIENT, SERVER, SSH_PORT, SET_PRIV, SS, KernelPeer, command
from remote_commissioning_wireguard_observations import CASES, file_signal, observe_cases, snapshot, wait_file
import remote_commissioning_wireguard_provider as provider
import remote_commissioning_wireguard_provider_b as provider_b
from remote_commissioning_wireguard_provider_profiles import DispatchMode
from remote_commissioning_wireguard_progress import Progress, Step

SCHEMA = "exacopy.linux-kernel-wireguard-commissioning.v1"
JOB = "exacopy-wireguard-commissioning"
ROUTE_REVISION = b"ExaCopy/ssh-profile/embedded-route/v2\0"
CAMPAIGN_SECONDS = 1500
EXTRA_EVIDENCE = {
    "retained-destination.json": 16 * 1024,
    "carrier-down/carrier-down.stdout": 16 * 1024,
    "carrier-down/carrier-down.openssh.log": 64 * 1024,
    **{f"lane-campaign/{name}.json": 4096 for name in ("identity", "mount", "disposition")},
}


def export(work, report):
    hashes = direct.export(work, report)
    for relative, bound in EXTRA_EVIDENCE.items():
        value = direct.capture_file(work, report, relative, bound)
        if value is not None:
            hashes[relative] = value
    return hashes


def staged_tool(parent, name):
    folder = parent / "exacopy-commissioning-tools"
    directory_identity(folder, os.geteuid(), 0o700)
    path = folder / "unpacked/usr/bin" / name
    actual = path.lstat()
    if (
        path.resolve(strict=True) != path or actual.st_uid != os.geteuid()
        or not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1
        or actual.st_mode & 0o022 or not os.access(path, os.X_OK)
    ):
        raise Blocked("the selected commissioning executable is outside private custody")
    return path


def route_revision(route, b3sum):
    remote, remote_port = route["remote_inner"].split(":")
    outer, outer_port = route["outer"].split(":")
    def v4(value):
        return b"\x04" + ipaddress.IPv4Address(value).packed

    body = ROUTE_REVISION + bytes.fromhex(route["local_public_key"]) + bytes.fromhex(route["peer_public_key"])
    body += v4(outer) + struct.pack("!HH", int(outer_port), route["outer_mtu"])
    body += v4(route["local_inner"]) + v4(remote) + struct.pack("!H", int(remote_port))
    digest = run([b3sum, "--no-names"], data=body, operation="independent embedded route revision").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise Blocked("embedded route revision unavailable")
    return digest


def check_provider(evidence, expected=None):
    observed = provider.report()
    evidence["provider"] = observed
    if observed["provider"] not in {"built-in", "already-live"}:
        raise Blocked("no pre-existing active WireGuard provider on this runner")
    if expected is not None and (observed["kernel"], observed["provider"]) != expected:
        raise Blocked("the positively admitted provider changed before link creation")
    return observed["kernel"], observed["provider"]


def validate_listener(fixture, kernel):
    registered = unit_status(fixture.unit)
    if registered["InvocationID"] != fixture.invocation:
        raise CleanupUnconfirmed("the OpenSSH invocation changed")
    peer = command(kernel.work, "OpenSSH network namespace", [
        "/usr/bin/stat", "-Lc", "%d:%i", "--", Path("/proc") / registered["MainPID"] / "ns/net",
    ])
    status = (Path("/proc") / registered["MainPID"] / "status").read_text(encoding="ascii")
    mask = re.findall(r"^CapBnd:\s+([0-9a-f]{16})$", status, re.M)
    if len(mask) != 1 or int(mask[0], 16) & sum(1 << bit for bit in (12, 13, 21)):
        raise Blocked("OpenSSH retained namespace administration or raw socket capabilities")
    if peer.decode().strip() != ":".join(map(str, kernel.peer.identity)):
        raise Blocked("OpenSSH is outside the owned peer namespace")
    sockets = kernel.call(kernel.peer, "exact OpenSSH listener", SS, "-H", "-lntp").splitlines()
    expected = f"{SERVER}:{SSH_PORT}".encode()
    ownership = f"pid={registered['MainPID']},".encode()
    if len(sockets) != 1 or expected not in sockets[0].split() or ownership not in sockets[0]:
        raise Blocked("the exact OpenSSH listener could not be attributed")
    if kernel.call(kernel.client, "no kernel TCP fallback listener", SS, "-H", "-lnt").strip():
        raise Blocked("the isolated client unexpectedly owns a TCP listener")


def client_command(fixture, kernel, work, b3sum, env, host_mount, *, candidate=None):
    return kernel.client.enter(
        SET_PRIV, f"--reuid={os.geteuid()}", f"--regid={os.getegid()}", "--clear-groups",
        "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
        "/usr/bin/env", "-i", f"RUNNER_TEMP={work.parent.parent}",
        f"PATH={b3sum.parent}:{env['PATH']}", "LC_ALL=C",
        *(f"{name}={env[name]}" for name in ("HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR") if name in env),
        "/usr/bin/python3", "-B", native.REPO / ".github/ci/remote_commissioning_wireguard_client.py",
        fixture.nonce, ":".join(map(str, kernel.client.identity)),
        f"{host_mount['device']}:{host_mount['inode']}", str(os.geteuid()),
        *((candidate.manifest_sha256,) if candidate is not None else ()),
    )


def process_evidence(result):
    return {"status": result.status, "exit_status": result.exit_status}


def execute_campaign(kernel, lane, handoff, work, binary, report, input_digests, budget):
    mailbox = work / "telemetry"
    mailbox.mkdir(mode=0o700)
    rows, failures = [], []
    halted = threading.Event()
    observer = threading.Thread(target=observe_cases, args=(kernel, mailbox, halted, rows, failures), daemon=True)
    observer.start()
    try:
        if not wait_file(mailbox / "start", lambda: bool(failures), timeout=budget.time_for(120)):
            raise failures[0].error
        seconds = budget.time_for(CAMPAIGN_SECONDS)
        file_signal(handoff / ClientStep.CAMPAIGN.value)
        result = lane.wait(seconds, signal=handoff / ClientStep.CAMPAIGN_COMPLETE.value,
                           stop=lambda: bool(failures))
        write_json(work / "campaign-process.json", process_evidence(result))
    finally:
        halted.set()
        observer.join(timeout=75)
        if observer.is_alive():
            raise CleanupUnconfirmed("kernel telemetry observer cleanup is unconfirmed")
        report["kernel_cases"] = rows
        if failures:
            report["kernel_case_failure"] = failures[0].evidence()
    if failures:
        error = failures[0].error
        if isinstance(error, CleanupUnconfirmed):
            raise error
        raise direct.EvidenceFailed("kernel peer observations differ from the executed campaign") from error
    if result.status != "rendezvous":
        return 1 if result.exit_status == 1 else 77
    summary_bytes = read_evidence(work / "campaign/summary.json")
    summary = json.loads(summary_bytes)
    if (
        [row["case"] for row in rows] != [case[0] for case in CASES]
        or summary["status"] != "pass" or summary["exit_status"] != 0 or summary["route"] != native.EMBEDDED
        or summary["binary_sha256"] != file_digest(binary)
        or summary["qualification_digest"] != report["authority"]["record_digest"]
        or any(summary.get(name) != value for name, value in input_digests.items())
        or summary["issues_new_qualification"] is not False
    ):
        raise Blocked("kernel or CLI campaign evidence does not cover the exact requested run")
    if asdict(snapshot(kernel)) != rows[-1]["after"]:
        raise direct.EvidenceFailed("unexpected carrier traffic after the last owned campaign case")
    if "candidate" in report:
        direct.check_candidate_summary(summary, report["candidate"], report["authority"], input_digests)
        report["observations"] = {"campaign_summary_sha256": hashlib.sha256(summary_bytes).hexdigest()}
    return 0


def client_unit_name(fixture):
    return f"exacopy-wg-{fixture.nonce}-campaign.service"


def lane_evidence(handoff, lane, disposition):
    write_json(handoff / "disposition.json", {
        "unit": lane.unit, "invocation": lane.invocation, "cgroup": lane.group, "cleanup": disposition,
    })


@contextmanager
def owned_client(fixture, work, args, budget):
    handoff = work / "lane-campaign"
    handoff.mkdir(mode=0o700)
    lane = ClientLane(client_unit_name(fixture), work, budget.time_for())
    try:
        lane.start(args)
        write_json(handoff / "identity.json", {"unit": lane.unit, "invocation": lane.invocation, "cgroup": lane.group})
        yield lane, handoff
    finally:
        try:
            lane.stop()
            for marker in (handoff / "observations-cleanup-pending",
                           work / "campaign/cleanup-unconfirmed.json",
                           work / "carrier-down/cleanup-unconfirmed.json"):
                try:
                    marker.lstat()
                except FileNotFoundError:
                    continue
                raise CleanupUnconfirmed("nested client cleanup is unconfirmed")
        except Exception as error:
            try:
                lane_evidence(handoff, lane, "unconfirmed")
            finally:
                # Missing evidence cannot erase unresolved process ownership.
                raise CleanupUnconfirmed("isolated client lane cleanup is unconfirmed") from error
        else:
            lane_evidence(handoff, lane, "confirmed-drained" if lane.attempted else "not-started")


def observe_client(lane, handoff, work, host_mount, evidence, budget):
    result = lane.wait(budget.time_for(120), signal=handoff / ClientStep.READY.value)
    evidence["client_start"] = process_evidence(result)
    if result.status != "rendezvous":
        raise Blocked("protected client did not enter")
    mount = lane.mount_namespace()
    if mount == (host_mount["device"], host_mount["inode"]):
        raise Blocked("client did not establish the protected mount namespace")
    seconds = budget.time_for()
    file_signal(handoff / ClientStep.OBSERVE.value)
    result = lane.wait(seconds, signal=handoff / ClientStep.OBSERVED.value)
    evidence["client_observations"] = process_evidence(result)
    if result.status != "rendezvous":
        raise Blocked("protected native observations did not complete")
    require_client_mount(lane, mount)
    first = read_json(work / "native-facts/facts.json")
    second = read_json(work / "native-facts-recheck/facts.json")
    if first != second or first["destination"]["mount_namespace"] != str(mount[1]):
        raise Blocked("native facts do not match the held client mount namespace")
    if provider.namespace_identity("mnt") != host_mount:
        raise Blocked("host mount namespace changed during client observations")
    write_json(handoff / "mount.json", {"host": host_mount, "client": mount})
    return mount


def require_client_mount(lane, mount):
    if lane.mount_namespace() != mount:
        raise CleanupUnconfirmed("protected client mount namespace changed")


def carrier_down(kernel, lane, handoff, evidence, budget):
    kernel.recheck_link()
    kernel.call(kernel.peer, "lower owned carrier", "/usr/sbin/ip", "link", "set", "dev", kernel.name, "down")
    sockets = kernel.call(kernel.client, "confirm lowered carrier", SS, "-H", "-lun")
    if re.search(rb":" + str(kernel.port).encode() + rb"\s", sockets):
        raise Blocked("lowered carrier still has an outer UDP socket")
    seconds = budget.time_for(55)
    file_signal(handoff / ClientStep.CARRIER_DOWN.value)
    result = lane.wait(seconds)
    evidence["carrier_down"] = process_evidence(result)
    if not result.passed():
        raise direct.EvidenceFailed("ordinary CLI did not confirm no publication after carrier shutdown")


class ProviderChoice(Enum):
    EXISTING = "existing"
    HOSTED_AZURE_B = "hosted-azure-b"
    HOSTED_AWS_B = "hosted-aws-b"


def execute(parent, work, report, evidence, choice=ProviderChoice.EXISTING):
    boot = None
    provider_profile = None
    if choice is ProviderChoice.EXISTING:
        if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or os.environ.get("GITHUB_REF_PROTECTED") != "true":
            raise Blocked("embedded fixture requires manual commissioning")
        expected_provider = check_provider(evidence)
    elif choice in (ProviderChoice.HOSTED_AZURE_B, ProviderChoice.HOSTED_AWS_B):
        provider_b.hosted_scope()
        observed = provider.report()
        evidence["provider_before"] = observed
        provider_profile = provider_b.known_profile(observed.get("kernel", {}))
        boot = provider_b.admit(observed, provider_profile)
        aws_profile = provider_profile.mode in (DispatchMode.AWS_1014, DispatchMode.AWS_1018)
        if (choice is ProviderChoice.HOSTED_AWS_B) != aws_profile:
            raise Blocked("provider B entrypoint differs from the selected profile")
        evidence["dispatch"] = provider_b.verify_dispatch(parent.parent, provider_profile, boot)
    else:
        raise ValueError("unexpected provider choice")
    evidence["provider_choice"] = choice.value
    identity = native.source_identity(native.REPO)
    if identity["revision"] != os.environ["GITHUB_SHA"]:
        raise Blocked("source differs from the selected hosted revision")
    request = direct.CandidateRequest.from_hosted_environment(parent.parent, route=native.EMBEDDED)
    if request is not None and choice is ProviderChoice.EXISTING:
        raise Blocked("the frozen candidate requires hosted provider B")
    evidence["preflight"] = {}
    fixture = Fixture(secrets.token_hex(10), direct.preflight(evidence["preflight"]))
    b3sum = staged_tool(parent.parent, "b3sum")
    wg = staged_tool(parent.parent, "wg")
    staged_wg_sha = file_digest(wg)
    sshd_sha = file_digest(Path(SSHD))
    target = parent / "private-build"
    env = native.build_environment(target)
    kernel = None
    unresolved = False
    marker = report / "cleanup-unconfirmed.json"
    write_json(marker, {
        "root": str(fixture.root), "account": fixture.account, "unit": fixture.unit,
        "keepers": [f"exacopy-wg-{fixture.nonce}-{role}.service" for role in ("client", "peer")],
        "client_lanes": [client_unit_name(fixture)],
    })
    setup, cleanup = Progress(), Progress()
    evidence["fixture_progress"] = {"setup": setup.evidence, "cleanup": cleanup.evidence}
    with native.fresh_target(target):
        try:
            setup.advance(Step.BUILD)
            frozen = candidate = None
            if request is None:
                binary, manifest = native.build_cli(native.EMBEDDED, work / "build", target, env, staged_executable=target / "exacopy")
                build, digest = direct.read_build_manifest(manifest)
            else:
                frozen, candidate = direct.import_preview_candidate(request, work, target, native.EMBEDDED, identity, evidence)
                binary, manifest = frozen.binary, frozen.manifest

            def verify():
                if native.source_identity(native.REPO) != identity:
                    raise Blocked("source changed during kernel commissioning")
                if frozen is not None:
                    frozen.verify()
                else:
                    direct.verify_build_custody(manifest, binary, build, digest)

            verify()
            setup.advance(Step.FIXTURE_ROOT)
            fixture.make_root()
            setup.advance(Step.PEER_TOOL)
            protected_wg = fixture.root / "wg"
            command(work, "stage exact root-owned WireGuard tool", [INSTALL, "-m", "0755", "--", wg, protected_wg])
            info = protected_wg.lstat()
            if info.st_uid or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode) or file_digest(protected_wg) != staged_wg_sha:
                raise Blocked("kernel peer tool custody changed")
            if boot is not None:
                setup.advance(Step.PROVIDER)
                details = evidence["provider_b"] = {}
                provider_b.prepare(
                    parent.parent / "exacopy-commissioning-tools", work, report, fixture, provider_profile, boot, details,
                )
                expected_provider = check_provider(evidence)
                if expected_provider != (boot, "already-live"):
                    raise Blocked("provider B did not establish WireGuard Live on the same boot")
            kernel = KernelPeer(fixture, work, protected_wg, setup=setup, cleanup=cleanup)
            budget = ClientBudget.before_keepers()
            kernel.prepare(lambda: check_provider(evidence, expected_provider))
            evidence["topology"] = {
                "namespaces": {"client": kernel.client.identity, "peer": kernel.peer.identity},
                "kernel_ifindex": kernel.ifindex, "outer_port": kernel.port, "wg_sha256": staged_wg_sha,
                "client_inner": CLIENT, "server_inner": SERVER, "sshd_sha256": sshd_sha,
            }
            host_mount = provider.namespace_identity("mnt")
            if host_mount is None:
                raise Blocked("caller mount namespace identity unavailable")
            setup.advance(Step.CLIENT_OBSERVATIONS)
            args = client_command(fixture, kernel, work, b3sum, env, host_mount, candidate=candidate)
            with owned_client(fixture, work, args, budget) as (lane, handoff):
                mount = observe_client(lane, handoff, work, host_mount, evidence, budget)
                verify()
                setup.advance(Step.SSH_SETUP)
                route = kernel.profile()
                revision = route_revision(route, b3sum)
                evidence["topology"]["route_revision"] = revision
                require_client_mount(lane, mount)
                _, _, evidence["authority"] = make_authority(
                    fixture, work, manifest, b3sum, route=native.EMBEDDED, route_revision=revision,
                    candidate=candidate, binary=binary,
                )
                if candidate is not None:
                    verify()
                    evidence["candidate"]["build_blake3_derive_key"] = evidence["authority"]["build_blake3_derive_key"]
                owner = fixture.private / "owner"
                init = logged_command([binary, "profile", "init", owner], work / "owner-init.log", 10, env=env, output_limit=8192)
                if not init.passed():
                    raise Blocked("ordinary CLI failed to initialize fixture owner")
                directory_identity(owner, os.geteuid(), 0o700)
                fixture.make_sources()
                fixture.make_account()
                kernel.peer.recheck()
                profile, _, evidence["peer"] = fixture.make_selected_peer(SERVER, SSH_PORT, CLIENT, kernel.peer.pin, route)
                inputs = {
                    "ssh_profile_sha256": profile,
                    "trust_sha256": fixture.private / "synthetic-trust.json",
                    "qualification_sha256": fixture.private / "synthetic-record",
                }
                input_digests = {name: file_digest(path) for name, path in inputs.items()}
                validate_listener(fixture, kernel)
                verify()
                require_client_mount(lane, mount)
                setup.advance(Step.CAMPAIGN)
                try:
                    result = execute_campaign(kernel, lane, handoff, work, binary, evidence, input_digests, budget)
                except (direct.EvidenceFailed, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
                    if candidate is not None:
                        direct.check_candidate_custody(verify, 1, evidence)
                    raise
                if candidate is not None:
                    direct.check_candidate_custody(verify, result, evidence)
                if result == 0:
                    setup.advance(Step.CARRIER_DOWN)
                    require_client_mount(lane, mount)
                    kernel.check_geometry()
                    validate_listener(fixture, kernel)
                    verify()
                    if file_digest(Path(SSHD)) != sshd_sha or file_digest(protected_wg) != staged_wg_sha:
                        raise Blocked("kernel or OpenSSH tool custody changed")
                    carrier_down(kernel, lane, handoff, evidence, budget)
                    verify()
                    if any(file_digest(path) != input_digests[name] for name, path in inputs.items()):
                        raise direct.EvidenceFailed("protected route or authority inputs changed")
            if candidate is not None:
                direct.check_candidate_custody(verify, result, evidence)
                direct.confirm_candidate_archive(frozen, result, evidence)
            setup.completed()
        except Exception as error:
            unresolved = isinstance(error, CleanupUnconfirmed)
            setup.failed(error)
            raise
        finally:
            if unresolved:
                cleanup.held()
            else:
                try:
                    cleanup.advance(Step.SSH_STOP)
                    fixture.stop_peer()
                    fixture.unit_attempted = False
                    if kernel is not None:
                        kernel.stop()
                    cleanup.advance(Step.FIXTURE_REMOVE)
                    fixture.stop()
                    cleanup.advance(Step.MARKER_REMOVE)
                    marker.unlink()
                    cleanup.completed()
                except Exception as error:
                    cleanup.failed(error)
                    raise CleanupUnconfirmed("kernel commissioning cleanup is unconfirmed") from error
    checkpoint()
    return result


def main(choice=ProviderChoice.EXISTING):
    program = {
        ProviderChoice.EXISTING: "remote_commissioning_wireguard.py",
        ProviderChoice.HOSTED_AZURE_B: "remote_commissioning_wireguard_azure.py",
        ProviderChoice.HOSTED_AWS_B: "remote_commissioning_wireguard_aws.py",
    }[choice]
    try:
        events = ("workflow_dispatch",) if choice is ProviderChoice.EXISTING else ("push",)
        fixed = direct.hosted_parent(program, events)
    except (Blocked, OSError, KeyError):
        return 77
    parent = fixed / JOB
    parent.mkdir(mode=0o700)
    work, report = parent / "private", parent / "report"
    work.mkdir(mode=0o700)
    report.mkdir(mode=0o700)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    evidence = {"schema": SCHEMA, "route": native.EMBEDDED, "production_qualification_issued": False}
    status = 77
    uncertain = False
    try:
        status = (
            execute(parent, work, report, evidence)
            if choice is ProviderChoice.EXISTING
            else execute(parent, work, report, evidence, choice)
        )
    except CleanupUnconfirmed:
        uncertain = True
        evidence["reason"] = "owned fixture cleanup remains unconfirmed"
    except direct.EvidenceFailed as error:
        status = 1
        evidence["reason"] = "kernel commissioning fixture checks failed" if "fixture_progress" in evidence else str(error)
    except (Blocked, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        if evidence.get("fixture_progress", {}).get("setup", {}).get("disposition") == "failed":
            evidence["reason"] = "kernel commissioning fixture step failed"
        else:
            evidence["reason"] = str(error) if isinstance(error, Blocked) else type(error).__name__
    finally:
        evidence["cleanup_unconfirmed"] = uncertain
        try:
            evidence["artifacts_sha256"] = export(work, report)
            if status == 0 and (missing := EXTRA_EVIDENCE.keys() - evidence["artifacts_sha256"].keys()):
                status = 77
                evidence["reason"] = "mandatory kernel commissioning evidence unavailable"
                evidence["missing_artifacts"] = sorted(missing)
            if not uncertain:
                shutil.rmtree(work)
        except (Blocked, OSError):
            status = 77
        if status == 0 and "candidate" in evidence:
            try:
                direct.check_candidate_exports(report, evidence)
            except (direct.EvidenceFailed, OSError, KeyError, TypeError, ValueError) as error:
                status = 1
                evidence["reason"] = str(error) if isinstance(error, direct.EvidenceFailed) else "frozen candidate evidence is unavailable"
        evidence["status"] = {0: "pass", 1: "fail", 77: "blocked"}[status]
        evidence["exit_status"] = status
        provider.write_report(report, evidence)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
