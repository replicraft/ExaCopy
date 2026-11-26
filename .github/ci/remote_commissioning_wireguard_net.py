"""Own two disposable network namespaces and exactly one kernel WireGuard peer."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import tempfile

from native_supervision import CleanupUnconfirmed, logged_cleanup_command, logged_command
from remote_commissioning_peer import (
    Blocked, CGROUP, INSTALL, STAT, SUDO, SYSTEMCTL, SYSTEMD_RUN, cgroup_drained,
    cgroup_present, checkpoint, directory_identity, unit_known, unit_status,
)
from remote_commissioning_wireguard_progress import CommandRefused, Progress, Role, Step

NSENTER = "/usr/bin/nsenter"
IP = "/usr/sbin/ip"
SS = "/usr/bin/ss"
SET_PRIV = "/usr/bin/setpriv"
MOUNT = "/usr/bin/mount"
UNMOUNT = "/usr/bin/umount"
FINDMNT = "/usr/bin/findmnt"
SERVER = "198.18.0.1"
CLIENT = "198.18.0.2"
SSH_PORT = 2222
OUTER_MTU = 1500


def command(work, operation, args, *, elevated=True, cleanup=False):
    argv = [SUDO, "-n", "--", *args] if elevated else args
    # Output may contain protected fixture values. The upload never selects this path.
    with tempfile.TemporaryDirectory(prefix="kernel-peer-", dir=work) as scratch:
        log = Path(scratch) / "command"
        supervise = logged_cleanup_command if cleanup else logged_command
        result = supervise(argv, log, 15, output_limit=64 * 1024)
        if not result.passed():
            raise CommandRefused(operation, result)
        return log.read_bytes()


def stable_pair(raw):
    if not re.fullmatch(rb"[0-9]+:[1-9][0-9]*\n", raw):
        raise Blocked("namespace identity unavailable")
    return tuple(map(int, raw.strip().split(b":")))


@dataclass
class Keeper:
    fixture: object
    role: str
    work: Path
    invocation: str | None = None
    group: tuple[int, int] | None = None
    identity: tuple[int, int] | None = None
    mount_id: int | None = None
    original: tuple[int, int] | None = None
    attempted: bool = False
    mount_attempted: bool = False
    setup: Progress = field(default_factory=Progress)
    cleanup: Progress = field(default_factory=Progress)

    @property
    def unit(self):
        return f"exacopy-wg-{self.fixture.nonce}-{self.role}.service"

    @property
    def cgroup(self):
        return CGROUP / self.unit

    @property
    def pin(self):
        return self.fixture.root / f"network-{self.role}"

    def measure_pin(self, *, cleanup=False, setup_trace=False):
        if setup_trace:
            self.setup.advance(Step.PIN_STAT, Role(self.role))
        raw = command(self.work, Step.PIN_STAT, [STAT, "-Lc", "%d:%i", "--", self.pin], cleanup=cleanup)
        if setup_trace:
            self.setup.advance(Step.PIN_MOUNT_QUERY, Role(self.role))
        data = command(self.work, Step.PIN_MOUNT_QUERY, [
            FINDMNT, "--json", "--mountpoint", self.pin, "--output", "TARGET,FSTYPE,ID",
        ], cleanup=cleanup)
        if setup_trace:
            self.setup.advance(Step.PIN_VERIFY, Role(self.role))
        rows = json.loads(data)["filesystems"]
        if len(rows) != 1 or rows[0]["target"] != str(self.pin) or rows[0]["fstype"] != "nsfs":
            raise CleanupUnconfirmed("network namespace pin is not an exact nsfs mount")
        mount_id = int(rows[0]["id"])
        if mount_id <= 0:
            raise CleanupUnconfirmed("network namespace mount identity unavailable")
        return stable_pair(raw), mount_id

    def start(self):
        role = Role(self.role)
        self.setup.advance(Step.KEEPER_ADMISSION, role)
        checkpoint()
        if unit_known(self.unit) or os.path.lexists(self.cgroup) or os.path.lexists(self.pin):
            raise Blocked("generated network resources are occupied")
        self.attempted = True
        properties = [
            "Type=exec", "KillMode=control-group", "Delegate=no", "ProtectControlGroups=yes",
            "PrivateNetwork=yes", "RuntimeMaxSec=1800s", "Restart=no", "TimeoutStopSec=10s",
            "StandardOutput=null", "StandardError=null",
        ]
        self.setup.advance(Step.KEEPER_START, role)
        command(self.work, "isolated namespace keeper", [
            SYSTEMD_RUN, "--quiet", "--unit", self.unit,
            *(f"--property={item}" for item in properties), "--", "/usr/bin/sleep", "1800",
        ])
        self.setup.advance(Step.KEEPER_STATUS, role)
        current = unit_status(self.unit)
        pid = current["MainPID"]
        if (
            current["LoadState"] != "loaded" or current["ActiveState"] != "active"
            or current["ControlGroup"] != f"/system.slice/{self.unit}"
            or not re.fullmatch(r"[0-9a-f]{32}", current["InvocationID"])
            or not re.fullmatch(r"[1-9][0-9]{0,9}", pid)
        ):
            raise CleanupUnconfirmed("keeper ownership unavailable")
        self.setup.advance(Step.KEEPER_PROPERTIES, role)
        if (
            current["KillMode"] != "control-group" or current["Delegate"] != "no"
            or current["Transient"] != "yes" or current["ProtectControlGroups"] != "yes"
        ):
            raise CleanupUnconfirmed("keeper ownership unavailable")
        self.setup.advance(Step.KEEPER_LEADER, role)
        leader = Path("/proc") / pid
        if (leader / "cgroup").read_text(encoding="ascii") != f"0::/system.slice/{self.unit}\n":
            raise CleanupUnconfirmed("keeper escaped its exact group")
        self.setup.advance(Step.KEEPER_CGROUP, role)
        group = self.cgroup.lstat()
        if group.st_uid != 0 or not cgroup_present(self.cgroup, (group.st_dev, group.st_ino)):
            raise CleanupUnconfirmed("keeper group ownership unavailable")
        self.group = group.st_dev, group.st_ino
        self.invocation = current["InvocationID"]
        source = leader / "ns/net"
        self.setup.advance(Step.KEEPER_NETWORK, role)
        raw = command(self.work, "keeper network identity", [STAT, "-Lc", "%d:%i", "--", source])
        identity = stable_pair(raw)
        host = Path("/proc/self/ns/net").stat()
        if identity == (host.st_dev, host.st_ino) or unit_status(self.unit) != current:
            raise CleanupUnconfirmed("keeper network is not independent")
        self.setup.advance(Step.PIN_CREATE, role)
        if directory_identity(self.fixture.root, 0, 0o755) != self.fixture.root_identity:
            raise CleanupUnconfirmed("protected fixture root changed")
        command(self.work, "fresh protected namespace pin", [INSTALL, "-m", "0600", "--", "/dev/null", self.pin])
        original = self.pin.lstat()
        if original.st_uid != 0 or original.st_mode & 0o777 != 0o600 or original.st_nlink != 1:
            raise CleanupUnconfirmed("protected network pin file differs")
        self.original = original.st_dev, original.st_ino
        self.mount_attempted = True
        # The pin is checked before it can authorize any network mutation. If
        # a leader exits or rebinds during mount, the setup stops without attach.
        self.setup.advance(Step.PIN_BIND, role)
        command(self.work, "pin isolated network namespace", [MOUNT, "--bind", "--no-canonicalize", source, self.pin])
        pinned, mount_id = self.measure_pin(setup_trace=True)
        if pinned != identity or unit_status(self.unit) != current:
            raise CleanupUnconfirmed("keeper changed while its namespace was pinned")
        self.identity, self.mount_id = pinned, mount_id

    def recheck(self, *, cleanup=False):
        if self.identity is None or self.measure_pin(cleanup=cleanup) != (self.identity, self.mount_id):
            raise CleanupUnconfirmed("network namespace ownership changed")

    def enter(self, *argv, cleanup=False):
        self.recheck(cleanup=cleanup)
        if cleanup:
            return [NSENTER, f"--net={self.pin}", "--", *argv]
        if not cgroup_present(self.cgroup, self.group):
            raise CleanupUnconfirmed("keeper group disappeared")
        current = unit_status(self.unit)
        if current["InvocationID"] != self.invocation or current["ActiveState"] != "active":
            raise CleanupUnconfirmed("network namespace keeper is no longer current")
        return [NSENTER, f"--net={self.pin}", "--", *argv]

    def stop(self):
        if not self.attempted:
            return
        role = Role(self.role)
        self.cleanup.advance(Step.KEEPER_STOP, role)
        if self.invocation is None:
            raise CleanupUnconfirmed("keeper invocation was not established")
        if self.mount_attempted:
            self.recheck(cleanup=True)
        cgroup_present(self.cgroup, self.group)
        if unit_known(self.unit):
            current = unit_status(self.unit)
            if current["InvocationID"] != self.invocation:
                raise CleanupUnconfirmed("keeper was replaced")
            command(self.work, "owned keeper stop", [SYSTEMCTL, "stop", "--", self.unit], cleanup=True)
        self.cleanup.advance(Step.KEEPER_DRAIN, role)
        if not cgroup_drained(self.cgroup, self.group):
            raise CleanupUnconfirmed("owned keeper group did not drain")
        if self.mount_attempted:
            self.cleanup.advance(Step.PIN_RELEASE, role)
            self.recheck(cleanup=True)
            command(self.work, Step.PIN_UNMOUNT, [UNMOUNT, "--no-canonicalize", "--", self.pin], cleanup=True)
            # The empty original pin file is removed with the owned fixture tree.
            raw = command(self.work, Step.PIN_RELEASED_IDENTITY, [STAT, "-Lc", "%d:%i", "--", self.pin], cleanup=True)
            if stable_pair(raw) != self.original:
                raise CleanupUnconfirmed("network pin still refers to the isolated namespace")


def public_key(raw):
    if not re.fullmatch(rb"[A-Za-z0-9+/]{43}=\n", raw):
        raise Blocked("WireGuard key encoding is unavailable")
    key = base64.b64decode(raw.strip(), validate=True)
    if not any(key) or base64.b64encode(key) + b"\n" != raw:
        raise Blocked("WireGuard key is not canonical")
    return key.hex()


def exact_link(rows, name, alias):
    matches = [row for row in rows if row.get("ifname") == name]
    if (
        len(matches) != 1 or matches[0].get("ifalias") != alias
        or matches[0].get("linkinfo", {}).get("info_kind") != "wireguard"
        or type(matches[0].get("ifindex")) is not int or matches[0]["ifindex"] <= 0
    ):
        raise CleanupUnconfirmed("WireGuard link ownership unavailable")
    return matches[0]["ifindex"]


class KernelPeer:
    def __init__(self, fixture, work, wg, *, setup=None, cleanup=None):
        self.fixture = fixture
        self.work = work
        self.wg = wg
        self.setup = setup if setup is not None else Progress()
        self.cleanup = cleanup if cleanup is not None else Progress()
        self.client = Keeper(fixture, "client", work, setup=self.setup, cleanup=self.cleanup)
        self.peer = Keeper(fixture, "peer", work, setup=self.setup, cleanup=self.cleanup)
        self.name = f"exw{fixture.nonce[:10]}"
        self.alias = f"exacopy-kernel-{fixture.nonce}"
        self.location = None
        self.port = None
        self.ifindex = None
        self.link_attempted = False

    def call(self, keeper, operation, *argv, cleanup=False):
        return command(self.work, operation, keeper.enter(*argv, cleanup=cleanup), cleanup=cleanup)

    def links(self, keeper, *, cleanup=False):
        return json.loads(self.call(keeper, "private link inventory", IP, "-j", "-d", "link", "show", cleanup=cleanup))

    def recheck_link(self, *, cleanup=False):
        if exact_link(self.links(self.location, cleanup=cleanup), self.name, self.alias) != self.ifindex:
            raise CleanupUnconfirmed("WireGuard interface identity changed")

    def prepare(self, admit_provider):
        self.client.start()
        self.peer.start()
        self.setup.advance(Step.NAMESPACE_SEPARATION)
        if self.client.identity == self.peer.identity:
            raise CleanupUnconfirmed("fixture network namespaces are aliased")
        for keeper in (self.client, self.peer):
            role = Role(keeper.role)
            self.setup.advance(Step.LOOPBACK_INVENTORY, role)
            if [row["ifname"] for row in self.links(keeper)] != ["lo"]:
                raise Blocked("isolated network has an unexpected link")
            self.setup.advance(Step.LOOPBACK_UP, role)
            self.call(keeper, "bring up isolated loopback", IP, "link", "set", "dev", "lo", "up")
        for role in ("client", "peer"):
            self.setup.advance(Step.SYNTHETIC_KEYS, Role(role))
            checkpoint()
            key = self.fixture.private / f"wireguard-{role}.key"
            # The fixed tool writes one generated key. No key output is retained.
            secret = command(self.work, "synthetic private key generation", [self.wg, "genkey"], elevated=False)
            public_key(secret)
            fd = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(secret)
        client_key = self.fixture.private / "wireguard-client.key"
        peer_key = self.fixture.private / "wireguard-peer.key"
        # Public key derivation uses shell-free stdin in the orchestrator.
        self.setup.advance(Step.SYNTHETIC_KEYS)
        self.client_public = self.derive_public(client_key)
        self.peer_public = self.derive_public(peer_key)
        if self.client_public == self.peer_public:
            raise Blocked("the synthetic key pair is aliased")
        checkpoint()
        self.setup.advance(Step.PROVIDER_RECHECK)
        admit_provider()
        self.setup.advance(Step.LINK_CREATE, Role.CLIENT)
        self.link_attempted = True
        self.call(self.client, "create exact WireGuard link", IP, "link", "add", self.name, "alias", self.alias, "type", "wireguard")
        self.location = self.client
        self.setup.advance(Step.LINK_BIRTH_IDENTITY, Role.CLIENT)
        self.ifindex = exact_link(self.links(self.client), self.name, self.alias)
        self.setup.advance(Step.LINK_MOVE, Role.CLIENT)
        self.peer.recheck()
        self.call(self.client, "move exact WireGuard link", IP, "link", "set", "dev", self.name, "netns", self.peer.pin)
        self.location = self.peer
        self.setup.advance(Step.LINK_PEER_IDENTITY, Role.PEER)
        self.ifindex = exact_link(self.links(self.peer), self.name, self.alias)
        self.setup.advance(Step.LINK_CONFIGURE, Role.PEER)
        self.call(
            self.peer, "configure closed synthetic peer", self.wg, "set", self.name,
            "listen-port", "0", "private-key", peer_key,
            "peer", base64.b64encode(bytes.fromhex(self.client_public)).decode(),
            "allowed-ips", f"{CLIENT}/32", "persistent-keepalive", "0",
        )
        self.setup.advance(Step.LINK_ADDRESS, Role.PEER)
        self.call(self.peer, "assign exact peer inner address", IP, "address", "add", f"{SERVER}/32", "dev", self.name)
        self.setup.advance(Step.LINK_UP, Role.PEER)
        self.call(self.peer, "bring up private WireGuard link", IP, "link", "set", "dev", self.name, "up")
        self.setup.advance(Step.LINK_ROUTE, Role.PEER)
        self.call(self.peer, "add private return host route", IP, "route", "add", f"{CLIENT}/32", "dev", self.name)
        self.setup.advance(Step.LINK_LISTEN, Role.PEER)
        raw = self.field("listen-port").strip()
        if not raw.isdigit() or not 1 <= int(raw) <= 65535:
            raise Blocked("kernel WireGuard listen port is unavailable")
        self.port = int(raw)
        self.setup.advance(Step.TOPOLOGY_VERIFY)
        self.check_geometry()

    def derive_public(self, key):
        import subprocess
        # The official tool consumes exactly one locally generated key.
        with key.open("rb") as source:
            result = subprocess.run(
                [self.wg, "pubkey"], stdin=source, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=5, check=True,
            )
        return public_key(result.stdout)

    def field(self, name):
        if name not in {"listen-port", "public-key", "allowed-ips", "endpoints", "transfer", "latest-handshakes"}:
            raise ValueError("unexpected WireGuard observation")
        return self.call(self.peer, "selected WireGuard public field", self.wg, "show", self.name, name)

    def check_geometry(self):
        self.recheck_link()
        if [row["ifname"] for row in self.links(self.client)] != ["lo"]:
            raise Blocked("client acquired a kernel inner path")
        if {row["ifname"] for row in self.links(self.peer)} != {"lo", self.name}:
            raise Blocked("peer network changed")
        for keeper in (self.client, self.peer):
            rows = json.loads(self.call(keeper, "private IPv4 routes", IP, "-j", "-4", "route", "show"))
            if keeper is self.client:
                valid = not rows
            else:
                valid = len(rows) == 1 and rows[0].get("dst") in {CLIENT, f"{CLIENT}/32"} and rows[0].get("dev") == self.name
            if not valid:
                raise Blocked("isolated kernel route geometry differs")
            if json.loads(self.call(keeper, "private IPv6 routes", IP, "-j", "-6", "route", "show")):
                raise Blocked("unexpected IPv6 forwarding route")
        expected = base64.b64encode(bytes.fromhex(self.client_public))
        if self.field("allowed-ips").split() != [expected, f"{CLIENT}/32".encode()]:
            raise Blocked("kernel WireGuard peer allowlist changed")
        if public_key(self.field("public-key")) != self.peer_public:
            raise Blocked("WireGuard server public key changed")
        listeners = self.call(self.client, "kernel WireGuard birth socket", SS, "-H", "-lun").splitlines()
        if not any(
            re.search(rb" (?:0\.0\.0\.0|\*|\[::\]):" + str(self.port).encode() + rb"\s", line)
            for line in listeners
        ):
            raise Blocked("kernel WireGuard outer socket is absent from its birth namespace")

    def profile(self):
        return {
            "kind": "embedded-wireguard", "outer": f"127.0.0.1:{self.port}", "outer_mtu": OUTER_MTU,
            "local_inner": CLIENT, "remote_inner": f"{SERVER}:{SSH_PORT}",
            "local_public_key": self.client_public, "peer_public_key": self.peer_public,
            "private_key_file": str(self.fixture.private / "wireguard-client.key"),
        }

    def stop(self):
        if self.link_attempted:
            role = Role(self.location.role) if self.location is not None else None
            self.cleanup.advance(Step.LINK_RECHECK, role)
            if self.location is None:
                raise CleanupUnconfirmed("no exact WireGuard link to remove")
            self.recheck_link(cleanup=True)
            self.cleanup.advance(Step.LINK_REMOVE, role)
            self.call(self.location, "remove exact owned WireGuard link", IP, "link", "delete", "dev", self.name, cleanup=True)
            self.cleanup.advance(Step.LINK_ABSENCE)
            if any(row.get("ifname") == self.name for keeper in (self.client, self.peer) for row in self.links(keeper, cleanup=True)):
                raise CleanupUnconfirmed("WireGuard link remains after teardown")
            self.cleanup.advance(Step.ROUTE_ABSENCE, Role.PEER)
            routes = json.loads(self.call(self.peer, "confirm return route absence", IP, "-j", "-4", "route", "show", cleanup=True))
            if routes:
                raise CleanupUnconfirmed("unexpected route remains in the isolated peer")
            if self.port is not None:
                self.cleanup.advance(Step.SOCKET_ABSENCE, Role.CLIENT)
                listeners = self.call(self.client, "confirm kernel outer socket absence", SS, "-H", "-lun", cleanup=True)
                if re.search(rb":" + str(self.port).encode() + rb"\s", listeners):
                    raise CleanupUnconfirmed("kernel WireGuard UDP listener still exists")
        self.peer.stop()
        self.client.stop()
