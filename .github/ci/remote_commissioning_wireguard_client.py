"""Enter the ordinary CLI campaign from the one supervised unprivileged lane."""
from contextlib import ExitStack
import errno
import os
import signal
import socket
from types import SimpleNamespace
import json
import stat
from pathlib import Path
import sys

import remote_commissioning as direct
from remote_commissioning import native
from remote_commissioning_peer import Blocked, FIXTURE_ID, Fixture
from remote_commissioning_wireguard_lane import ClientStep
from remote_commissioning_wireguard_net import SERVER, SSH_PORT
from remote_commissioning_wireguard_observations import file_signal, observe_case, wait_file
from native_supervision import CleanupUnconfirmed, interrupted, write_json
import remote_commissioning_wireguard_provider as provider


def isolated_client(net, host_mount, owner, nonce):
    if os.geteuid() == 0 or str(os.geteuid()) != owner or os.geteuid() != os.getuid() or os.getgroups():
        raise Blocked("fixture client retained ambient credentials")
    observed_net = provider.namespace_identity("net")
    if observed_net is None or net != f"{observed_net['device']}:{observed_net['inode']}":
        raise Blocked("fixture client is outside the selected network namespace")
    selected_mount = provider.namespace_identity("mnt")
    if selected_mount is None or host_mount == f"{selected_mount['device']}:{selected_mount['inode']}":
        raise Blocked("fixture client requires a private mount namespace")
    cgroup = Path("/sys/fs/cgroup")
    if (
        not os.statvfs(cgroup).f_flag & os.ST_RDONLY
        or Path("/proc/self/cgroup").read_text(encoding="ascii") != f"0::/system.slice/exacopy-wg-{nonce}-campaign.service\n"
    ):
        raise Blocked("fixture client is outside the protected cgroup")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    if any(int(status[name], 16) for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
        raise Blocked("fixture client retained capabilities")
    if status.get("NoNewPrivs", "").strip() != "1":
        raise Blocked("fixture client may acquire additional privileges")
    return selected_mount


def main():
    if len(sys.argv) != 5 or not FIXTURE_ID.fullmatch(sys.argv[1]):
        return 77
    nonce, net, host_mount, owner = sys.argv[1:]
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        mount = isolated_client(net, host_mount, owner, nonce)
        os.chdir(native.REPO)
        return run_client(nonce, mount, lambda: isolated_client(net, host_mount, owner, nonce))
    except (Blocked, OSError, KeyError, TypeError, ValueError):
        return 77


def no_direct_route():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
        check.settimeout(1)
        return check.connect_ex((SERVER, SSH_PORT)) in {errno.ENETUNREACH, errno.EHOSTUNREACH}


def run_client(nonce, mount, recheck):
    # File operands are selected by the admitted parent and derived inside the
    # exclusive fixture. This stage has no transport setup or sudo authority.
    work = Path(os.environ["RUNNER_TEMP"]) / "exacopy-wireguard-commissioning"
    root = Path("/var/lib") / f"exacopy-direct-{nonce}"
    private = root / "private"
    paths = {
        "binary": work / "private-build/exacopy",
        "destination": root / "destination",
        "owner-profile": private / "owner",
        "ssh-profile": private / "ssh.json",
        "qualification": private / "synthetic-record",
        "trust": private / "synthetic-trust.json",
        "source-small": private / "sources/empty",
        "source-interrupt": private / "sources/interrupt",
        "sshd-log": root / "peer.log",
        "evidence": work / "private/campaign",
    }

    import campaign

    handoff = work / "private/lane-campaign"

    def await_step(step, budget=120):
        wait_file(handoff / step.value, timeout=budget)
        if recheck() != mount:
            raise Blocked("fixture mount namespace changed between client stages")

    file_signal(handoff / ClientStep.READY.value)
    await_step(ClientStep.OBSERVE)
    if not no_direct_route():
        return 1
    fixture = Fixture(nonce, os.getegid())
    manifest = work / "private/build/result.json"
    build, digest = direct.read_build_manifest(manifest)

    def verify_build():
        if native.source_identity(native.REPO) != build["source_after"]:
            raise Blocked("source changed during isolated native observations")
        direct.verify_build_custody(manifest, paths["binary"], build, digest)

    pending = handoff / "observations-cleanup-pending"
    file_signal(pending)
    try:
        env = native.build_environment(paths["binary"].parent)
        env["CARGO_BUILD_JOBS"] = "2"
        direct.observations(fixture, manifest, paths["binary"], env, work / "private", verify_build)
    except CleanupUnconfirmed:
        # Preserve the pre-existing marker even if subsequent writes fail.
        return 77
    except (Blocked, OSError, KeyError, TypeError, ValueError):
        pending.unlink()
        raise
    pending.unlink()
    file_signal(handoff / ClientStep.OBSERVED.value)
    await_step(ClientStep.CAMPAIGN)
    verify_build()
    os.environ["PATH"] = os.environ["PATH"].split(":", 1)[0] + ":/usr/bin:/usr/sbin"
    if not no_direct_route():
        return 1

    retained = work / "private/retained-destination.json"
    sys.argv = ["campaign", "--route", native.EMBEDDED]
    for flag, path in paths.items():
        sys.argv.extend((f"--{flag}", str(path)))

    def observe_destination(root, expected):
        campaign.namespace(root, expected)
        write_json(retained, retained_namespace(campaign, root))

    result = campaign.main(observe_case(work / "private/telemetry"), observe_destination)
    if result != 0:
        return result
    file_signal(handoff / ClientStep.CAMPAIGN_COMPLETE.value)
    await_step(ClientStep.CARRIER_DOWN)
    verify_build()
    if not no_direct_route():
        return 1
    return carrier_down(campaign, paths, work / "private/carrier-down", retained)


def retained_namespace(campaign, root):
    rows = {}

    def visit(path, depth):
        if depth > 4 or len(rows) >= 32:
            raise campaign.Failed("retained fixture exceeds its namespace observation bound")
        initial = path.lstat()
        relative = path.relative_to(root).as_posix()
        rows[relative] = list(campaign.fingerprint(initial))
        if stat.S_ISDIR(initial.st_mode):
            for child in path.iterdir():
                visit(child, depth + 1)
        elif not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
            raise campaign.Failed("retained fixture contains an unsafe object")
        if rows[relative] != list(campaign.fingerprint(path.lstat())):
            raise campaign.Failed("retained fixture changed during observation")

    visit(root, 0)
    return rows


def carrier_down(campaign, paths, evidence, retained):
    target = paths["destination"] / "carrier-down"
    args = SimpleNamespace(**{name.replace("-", "_"): path for name, path in paths.items()})
    args.evidence = evidence
    args.route = native.EMBEDDED
    evidence.mkdir(mode=0o700)
    with ExitStack() as scope:
        args.inputs = campaign.HeldInputs(scope)
        expected = json.loads(args.inputs.read(retained, campaign.MAX_REPORT))

        def unchanged(root):
            if retained_namespace(campaign, root) != expected or not campaign.absent(target):
                raise campaign.Failed("the completed campaign's exact retained namespace changed")

        _, _, _, account, host, peer = campaign.protected_preflight(args, {}, unchanged)
        unchanged(args.destination)
        operand = campaign.fixture_operand(account, host, args.source_small)
        result = campaign.run_case(args, "carrier-down", ("get",), (operand, target), 4)
        peer.check(0, evidence / "carrier-down.openssh.log")
        unchanged(args.destination)
    return 0 if result["publication"] == "not_published" and result["error"]["code"] == "E_IO" else 1


if __name__ == "__main__":
    raise SystemExit(main())
