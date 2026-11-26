#!/usr/bin/env python3
"""Commission the ordinary embedded CLI against an isolated hosted kernel peer."""
from dataclasses import asdict
from enum import Enum
import ipaddress
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
from remote_commissioning_authority import make_authority, read_json
from remote_commissioning_peer import Blocked, Fixture, INSTALL, SSHD, checkpoint, directory_identity, run, unit_status
from remote_commissioning_wireguard_lane import ClientLane
from remote_commissioning_wireguard_net import CLIENT, SERVER, SSH_PORT, SET_PRIV, SS, KernelPeer, command
from remote_commissioning_wireguard_observations import CASES, Counters, check_delta, file_signal, snapshot, wait_file
import remote_commissioning_wireguard_provider as provider
import remote_commissioning_wireguard_provider_b as provider_b

SCHEMA = "exacopy.linux-kernel-wireguard-commissioning.v1"
JOB = "exacopy-wireguard-commissioning"
ROUTE_REVISION = b"ExaCopy/ssh-profile/embedded-route/v2\0"
CLIENT_MODES = ("campaign", "carrier-down")
EXTRA_EVIDENCE = {
    "retained-destination.json": 16 * 1024,
    "carrier-down/carrier-down.stdout": 16 * 1024,
    "carrier-down/carrier-down.openssh.log": 64 * 1024,
    **{f"lane-{mode}/{name}.json": 4096 for mode in CLIENT_MODES for name in ("identity", "disposition")},
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


def observe_cases(kernel, mailbox, halted, rows, failures):
    try:
        before = snapshot(kernel)
        if before != Counters(0, 0, 0, None):
            raise Blocked("kernel peer lacks a fresh quiet initial baseline")
        file_signal(mailbox / "start")
        for index, (name, count) in enumerate(CASES):
            if not wait_file(mailbox / f"case-{index}.done", halted.is_set):
                return
            kernel.recheck_link()
            after = snapshot(kernel)
            check_delta(before, after, count)
            rows.append({"case": name, "before": asdict(before), "after": asdict(after)})
            before = after
            file_signal(mailbox / f"case-{index}.observed")
    except Exception as error:
        failures.append(error)
        file_signal(mailbox / "blocked")


def client_command(fixture, kernel, work, b3sum, mode):
    observed_mount = provider.namespace_identity("mnt")
    if observed_mount is None:
        raise Blocked("caller mount namespace identity unavailable")
    return kernel.client.enter(
        SET_PRIV, f"--reuid={os.geteuid()}", f"--regid={os.getegid()}", "--clear-groups",
        "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
        "/usr/bin/env", "-i", f"RUNNER_TEMP={work.parent.parent}",
        f"PATH={b3sum.parent}:/usr/bin:/usr/sbin", "LC_ALL=C",
        "/usr/bin/python3", "-B", native.REPO / ".github/ci/remote_commissioning_wireguard_client.py",
        fixture.nonce, ":".join(map(str, kernel.client.identity)),
        f"{observed_mount['device']}:{observed_mount['inode']}", str(os.geteuid()), mode,
    )


def execute_campaign(fixture, kernel, work, b3sum, binary, report, input_digests):
    mailbox = work / "telemetry"
    mailbox.mkdir(mode=0o700)
    args = client_command(fixture, kernel, work, b3sum, "campaign")
    rows, failures = [], []
    halted = threading.Event()
    observer = threading.Thread(target=observe_cases, args=(kernel, mailbox, halted, rows, failures), daemon=True)
    observer.start()
    try:
        if not wait_file(mailbox / "start", lambda: bool(failures)):
            raise failures[0]
        result = run_client(fixture, work, "campaign", args, 1500)
        write_json(work / "campaign-process.json", {"status": result.status, "exit_status": result.exit_status})
    finally:
        halted.set()
        observer.join(timeout=75)
        if observer.is_alive():
            raise CleanupUnconfirmed("kernel telemetry observer cleanup is unconfirmed")
        report["kernel_cases"] = rows
        try:
            (work / "campaign/cleanup-unconfirmed.json").lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise CleanupUnconfirmed("campaign cleanup state could not be confirmed") from error
        else:
            raise CleanupUnconfirmed("nested campaign cleanup is unconfirmed")
    if failures:
        if isinstance(failures[0], CleanupUnconfirmed):
            raise failures[0]
        raise direct.EvidenceFailed("kernel peer observations differ from the executed campaign") from failures[0]
    if not result.passed():
        return 1 if result.exit_status == 1 else 77
    summary = read_json(work / "campaign/summary.json")
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
    return 0


def client_unit_name(fixture, mode):
    if mode not in CLIENT_MODES:
        raise ValueError("unknown fixture client lane")
    return f"exacopy-wg-{fixture.nonce}-{mode}.service"


def lane_evidence(handoff, lane, disposition):
    write_json(handoff / "disposition.json", {
        "unit": lane.unit, "invocation": lane.invocation, "cgroup": lane.group, "cleanup": disposition,
    })


def run_client(fixture, work, mode, args, budget):
    handoff = work / f"lane-{mode}"
    handoff.mkdir(mode=0o700)
    lane = ClientLane(client_unit_name(fixture, mode), work, budget)
    try:
        lane.start(args)
        write_json(handoff / "identity.json", {"unit": lane.unit, "invocation": lane.invocation, "cgroup": lane.group})
        if not wait_file(handoff / "ready"):
            raise Blocked("isolated client lane did not enter")
        file_signal(handoff / "go")
        return lane.wait()
    finally:
        try:
            lane.stop()
        except Exception as error:
            try:
                lane_evidence(handoff, lane, "unconfirmed")
            finally:
                # Missing evidence cannot erase unresolved process ownership.
                raise CleanupUnconfirmed("isolated client lane cleanup is unconfirmed") from error
        else:
            lane_evidence(handoff, lane, "confirmed-drained" if lane.attempted else "not-started")


def carrier_down(fixture, kernel, work, b3sum, evidence):
    kernel.recheck_link()
    kernel.call(kernel.peer, "lower owned carrier", "/usr/sbin/ip", "link", "set", "dev", kernel.name, "down")
    sockets = kernel.call(kernel.client, "confirm lowered carrier", SS, "-H", "-lun")
    if re.search(rb":" + str(kernel.port).encode() + rb"\s", sockets):
        raise Blocked("lowered carrier still has an outer UDP socket")
    try:
        result = run_client(fixture, work, "carrier-down", client_command(fixture, kernel, work, b3sum, "carrier-down"), 55)
    finally:
        if os.path.lexists(work / "carrier-down/cleanup-unconfirmed.json"):
            raise CleanupUnconfirmed("carrier-down command cleanup is unconfirmed")
    evidence["carrier_down"] = {"status": result.status, "exit_status": result.exit_status}
    if not result.passed():
        raise direct.EvidenceFailed("ordinary CLI did not confirm no publication after carrier shutdown")


class ProviderChoice(Enum):
    EXISTING = "existing"
    HOSTED_AZURE_B = "hosted-azure-b"


def execute(parent, work, report, evidence, choice=ProviderChoice.EXISTING):
    boot = None
    if choice is ProviderChoice.EXISTING:
        if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or os.environ.get("GITHUB_REF_PROTECTED") != "true":
            raise Blocked("embedded fixture requires manual commissioning")
        expected_provider = check_provider(evidence)
    elif choice is ProviderChoice.HOSTED_AZURE_B:
        provider_b.hosted_scope()
        observed = provider.report()
        evidence["provider_before"] = observed
        boot = provider_b.admit(observed)
        evidence["dispatch"] = provider_b.verify_dispatch(parent.parent, boot)
    else:
        raise ValueError("unexpected provider choice")
    evidence["provider_choice"] = choice.value
    evidence["preflight"] = {}
    fixture = Fixture(secrets.token_hex(10), direct.preflight(evidence["preflight"]))
    b3sum = staged_tool(parent.parent, "b3sum")
    wg = staged_tool(parent.parent, "wg")
    staged_wg_sha = file_digest(wg)
    sshd_sha = file_digest(Path(SSHD))
    identity = native.source_identity(native.REPO)
    if identity["revision"] != os.environ["GITHUB_SHA"]:
        raise Blocked("source differs from the selected hosted revision")
    target = parent / "private-build"
    env = native.build_environment(target)
    kernel = None
    unresolved = False
    marker = report / "cleanup-unconfirmed.json"
    write_json(marker, {
        "root": str(fixture.root), "account": fixture.account, "unit": fixture.unit,
        "keepers": [f"exacopy-wg-{fixture.nonce}-{role}.service" for role in ("client", "peer")],
        "client_lanes": [client_unit_name(fixture, mode) for mode in CLIENT_MODES],
    })
    with native.fresh_target(target):
        try:
            binary, manifest = native.build_cli(native.EMBEDDED, work / "build", target, env, staged_executable=target / "exacopy")
            build, digest = direct.read_build_manifest(manifest)

            def verify():
                if native.source_identity(native.REPO) != identity:
                    raise Blocked("source changed during kernel commissioning")
                direct.verify_build_custody(manifest, binary, build, digest)

            verify()
            fixture.make_root()
            protected_wg = fixture.root / "wg"
            command(work, "stage exact root-owned WireGuard tool", [INSTALL, "-m", "0755", "--", wg, protected_wg])
            info = protected_wg.lstat()
            if info.st_uid or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode) or file_digest(protected_wg) != staged_wg_sha:
                raise Blocked("kernel peer tool custody changed")
            if boot is not None:
                details = evidence["provider_b"] = {}
                provider_b.prepare(
                    parent.parent / "exacopy-commissioning-tools", work, report, fixture, boot, details,
                )
                expected_provider = check_provider(evidence)
                if expected_provider != (boot, "already-live"):
                    raise Blocked("provider B did not establish WireGuard Live on the same boot")
            kernel = KernelPeer(fixture, work, protected_wg)
            kernel.prepare(lambda: check_provider(evidence, expected_provider))
            evidence["topology"] = {
                "namespaces": {"client": kernel.client.identity, "peer": kernel.peer.identity},
                "kernel_ifindex": kernel.ifindex, "outer_port": kernel.port, "wg_sha256": staged_wg_sha,
                "client_inner": CLIENT, "server_inner": SERVER, "sshd_sha256": sshd_sha,
            }
            route = kernel.profile()
            revision = route_revision(route, b3sum)
            evidence["topology"]["route_revision"] = revision
            direct.observations(fixture, manifest, binary, env, work, verify)
            _, _, evidence["authority"] = make_authority(fixture, work, manifest, b3sum, route=native.EMBEDDED, route_revision=revision)
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
            result = execute_campaign(fixture, kernel, work, b3sum, binary, evidence, input_digests)
            if result == 0:
                kernel.check_geometry()
                validate_listener(fixture, kernel)
                verify()
                if file_digest(Path(SSHD)) != sshd_sha or file_digest(protected_wg) != staged_wg_sha:
                    raise Blocked("kernel or OpenSSH tool custody changed")
                carrier_down(fixture, kernel, work, b3sum, evidence)
                verify()
                if any(file_digest(path) != input_digests[name] for name, path in inputs.items()):
                    raise direct.EvidenceFailed("protected route or authority inputs changed")
        except CleanupUnconfirmed:
            unresolved = True
            raise
        finally:
            if not unresolved:
                try:
                    fixture.stop_peer()
                    fixture.unit_attempted = False
                    if kernel is not None:
                        kernel.stop()
                    fixture.stop()
                    marker.unlink()
                except Exception as error:
                    raise CleanupUnconfirmed("kernel commissioning cleanup is unconfirmed") from error
    checkpoint()
    return result


def main(choice=ProviderChoice.EXISTING):
    program = {
        ProviderChoice.EXISTING: "remote_commissioning_wireguard.py",
        ProviderChoice.HOSTED_AZURE_B: "remote_commissioning_wireguard_azure.py",
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
        evidence["reason"] = str(error)
    except (Blocked, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
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
        evidence["status"] = {0: "pass", 1: "fail", 77: "blocked"}[status]
        evidence["exit_status"] = status
        provider.write_report(report, evidence)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
