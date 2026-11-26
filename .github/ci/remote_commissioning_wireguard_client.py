"""Enter the ordinary CLI campaign from the one supervised unprivileged lane."""
from contextlib import ExitStack
import errno
import os
import socket
from types import SimpleNamespace
import json
import stat
from pathlib import Path
import sys

from remote_commissioning import native
from remote_commissioning_peer import FIXTURE_ID
from remote_commissioning_wireguard_net import SERVER, SSH_PORT
from remote_commissioning_wireguard_observations import file_signal, observe_case, wait_file
from native_supervision import write_json
import remote_commissioning_wireguard_provider as provider


def main():
    if len(sys.argv) != 6 or not FIXTURE_ID.fullmatch(sys.argv[1]):
        return 77
    nonce, net, mnt, owner, mode = sys.argv[1:]
    if mode not in {"campaign", "carrier-down"}:
        return 77
    if os.geteuid() == 0 or str(os.geteuid()) != owner or os.geteuid() != os.getuid() or os.getgroups():
        return 77
    for name, selected in (("net", net), ("mnt", mnt)):
        actual = provider.namespace_identity(name)
        if actual is None or selected != f"{actual['device']}:{actual['inode']}":
            return 77
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    if any(int(status[name], 16) for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
        return 77
    if status.get("NoNewPrivs", "").strip() != "1":
        return 77

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

    handoff = work / "private" / f"lane-{mode}"
    file_signal(handoff / "ready")
    if not wait_file(handoff / "go"):
        return 77

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
        check.settimeout(1)
        if check.connect_ex((SERVER, SSH_PORT)) not in {errno.ENETUNREACH, errno.EHOSTUNREACH}:
            return 1
    retained = work / "private/retained-destination.json"
    if mode == "carrier-down":
        return carrier_down(campaign, paths, work / "private/carrier-down", retained)

    sys.argv = ["campaign", "--route", native.EMBEDDED]
    for flag, path in paths.items():
        sys.argv.extend((f"--{flag}", str(path)))
    def observe_destination(root, expected):
        campaign.namespace(root, expected)
        write_json(retained, retained_namespace(campaign, root))

    return campaign.main(observe_case(work / "private/telemetry"), observe_destination)


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
