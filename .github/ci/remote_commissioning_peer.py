"""Own the direct commissioning fixture and its OpenSSH cgroup."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import stat
import subprocess
import time

import native_supervision
from native_supervision import CleanupUnconfirmed, write_json

BASE = Path("/var/lib")
CGROUP_ROOT = Path("/sys/fs/cgroup")
CGROUP = CGROUP_ROOT / "system.slice"
SYSTEMD_RUNTIME = Path("/run/systemd/system")
PRIVSEP = Path("/run/sshd")
SSHD = "/usr/sbin/sshd"
SUDO = "/usr/bin/sudo"
OPENSSL = "/usr/bin/openssl"
SSHD_KEYGEN = "/usr/bin/ssh-keygen"
NOLOGIN = "/usr/sbin/nologin"
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_RUN = "/usr/bin/systemd-run"
USERADD = "/usr/sbin/useradd"
USERDEL = "/usr/sbin/userdel"
CHPASSWD = "/usr/sbin/chpasswd"
MKDIR = "/usr/bin/mkdir"
INSTALL = "/usr/bin/install"
REMOVE = "/usr/bin/rm"
FINDMNT = "/usr/bin/findmnt"
STAT = "/usr/bin/stat"
DPKG_QUERY = "/usr/bin/dpkg-query"
SOURCE_BYTES = 128 * 1024 * 1024
UNIT_SECONDS = 1800
PEER_LOG_LIMIT = 4 * 1024 * 1024
CAP_SYS_ADMIN = 21
FIXTURE_ID = re.compile(r"[0-9a-f]{20}")


class Blocked(ValueError):
    """Required fixture admission or evidence was unavailable."""


def run(argv, *, privileged=False, data=None, budget=15, operation):
    if privileged:
        argv = [SUDO, "-n", "--", *argv]
    try:
        result = subprocess.run(
            argv, input=data, stdin=subprocess.DEVNULL if data is None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=budget,
            env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"}, check=False,
        )
    except subprocess.TimeoutExpired as error:
        if privileged:
            raise CleanupUnconfirmed(f"privileged fixture operation timed out: {operation}") from error
        raise Blocked(f"fixture prerequisite timed out: {operation}") from error
    except OSError as error:
        raise Blocked(f"fixture command unavailable: {operation}") from error
    if result.returncode != 0:
        raise Blocked(f"fixture command refused: {operation}")
    output = result.stdout
    if len(output) > 64 * 1024:
        raise Blocked(f"fixture command returned overlong output: {operation}")
    return output


def checkpoint():
    if native_supervision.CANCELLATION_REQUESTED:
        raise Blocked("commissioning cancelled")


def local_account(name):
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def local_group(name):
    try:
        return grp.getgrnam(name)
    except KeyError:
        return None


def directory_identity(path, uid, mode):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode:
        raise Blocked("fixture directory owner, type or mode differs")
    return info.st_dev, info.st_ino


def host_directory_status(path):
    try:
        detail = path.lstat()
        if stat.S_ISLNK(detail.st_mode):
            return "symlink"
        if not stat.S_ISDIR(detail.st_mode):
            return "not-directory"
        return "canonical-directory" if path.resolve(strict=True) == path else "noncanonical"
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unavailable"


def observe_host_paths(observations):
    required_paths = (CGROUP_ROOT, CGROUP, SYSTEMD_RUNTIME)
    for selected in (*required_paths, PRIVSEP):
        observations[str(selected)] = host_directory_status(selected)
    for selected in required_paths:
        status = observations[str(selected)]
        if status != "canonical-directory":
            raise Blocked(f"required hosted directory {selected}: {status}")


def preflight(observations):
    observe_host_paths(observations)
    commands = (SSHD, SSHD_KEYGEN, OPENSSL, SUDO, SYSTEMCTL, SYSTEMD_RUN,
                USERADD, USERDEL, CHPASSWD, NOLOGIN, MKDIR, INSTALL, REMOVE, FINDMNT, STAT, DPKG_QUERY)
    if any(not Path(command).is_file() or not os.access(command, os.X_OK) for command in commands):
        raise Blocked("the admitted runner lacks required OpenSSH or system tools")
    if BASE.resolve(strict=True) != BASE or BASE.stat().st_uid != 0:
        raise Blocked("the fixed fixture parent must be a root-owned directory")
    if any(ancestor.stat().st_uid != 0 or ancestor.stat().st_mode & 0o022
           for ancestor in (BASE, *BASE.parents)):
        raise Blocked("the fixture parent has unsafe chroot ancestry")
    controllers_path = CGROUP / "cgroup.controllers"
    if not (CGROUP_ROOT / "cgroup.controllers").is_file():
        raise Blocked("cgroup v2 control file is absent at the hosted cgroup root")
    try:
        controllers = controllers_path.read_text(encoding="ascii").split()
    except (OSError, UnicodeError) as error:
        raise Blocked("hosted system.slice controllers are unavailable") from error
    if "cpu" not in controllers:
        raise Blocked("hosted system.slice does not expose the CPU controller")
    run(["/usr/bin/true"], privileged=True, operation="noninteractive hosted privilege")
    run([SYSTEMCTL, "show", "--property=Version", "--value"], operation="systemd manager")
    mounted = json.loads(run(
        [FINDMNT, "--json", "--target", os.fspath(BASE), "--output", "FSTYPE,FSROOT,OPTIONS"],
        operation="fixture mount preflight",
    ))["filesystems"]
    if len(mounted) != 1 or (
        mounted[0]["fstype"] != "ext4" or mounted[0]["fsroot"] != "/"
        or mounted[0]["options"].split(",")[0] != "rw"
    ):
        raise Blocked("the fixed fixture parent is outside whole writable ext4")
    return grp.getgrnam("nogroup").gr_gid


def select_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def sshd_configuration(fixture, port, listen="127.0.0.1", source="127.0.0.1"):
    return (
        "AddressFamily inet\n"
        f"ListenAddress {listen}:{port}\n"
        f"PidFile {fixture.root / 'daemon.pid'}\n"
        f"HostKey {fixture.root / 'host-key'}\n"
        f"AuthorizedKeysFile {fixture.root / 'authorized_keys'}\n"
        f"AllowUsers {fixture.account}@{source}\n"
        f"ChrootDirectory {fixture.chroot}\n"
        "AuthenticationMethods publickey\nPubkeyAuthentication yes\n"
        "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
        "PermitEmptyPasswords no\nPermitRootLogin no\n"
        "UsePAM no\nStrictModes yes\n"
        "AuthorizedKeysCommand none\nTrustedUserCAKeys none\nAuthorizedPrincipalsFile none\n"
        "PermitUserEnvironment no\nPermitUserRC no\nPermitTTY no\nDisableForwarding yes\n"
        "Subsystem sftp internal-sftp -R -d /\nForceCommand internal-sftp -R -d /\n"
        "HostKeyAlgorithms ssh-ed25519\nPubkeyAcceptedAlgorithms ssh-ed25519\n"
        "MaxSessions 1\nLoginGraceTime 20\nLogLevel VERBOSE\n"
    )


def public_key(path):
    raw = path.read_bytes()
    pieces = raw.split(None, 2)
    if len(raw) > 512 or len(pieces) < 2 or pieces[0] != b"ssh-ed25519":
        raise Blocked("fixture key generator did not produce a bounded Ed25519 key")
    digest = hashlib.sha256(base64.b64decode(pieces[1], validate=True)).hexdigest()
    return b" ".join(pieces[:2]), digest


def unit_properties(fixture):
    mirror = fixture.chroot / fixture.source.relative_to("/")
    return {
        "Type": "exec",
        "KillMode": "control-group",
        "Delegate": "no",
        "ProtectControlGroups": "yes",
        "CapabilityBoundingSet": "~CAP_SYS_ADMIN",
        "ProtectHome": "yes",
        "PrivateTmp": "yes",
        "NoNewPrivileges": "yes",
        "Restart": "no",
        "TimeoutStopSec": "10s",
        "RuntimeMaxSec": f"{UNIT_SECONDS}s",
        "SendSIGKILL": "yes",
        "CPUQuota": "25%",
        "BindReadOnlyPaths": f"{fixture.source}:{mirror}:norbind {fixture.runtime}:/run:norbind",
        "StandardOutput": "null",
        "StandardError": "null",
    }


def verify_privsep_runtime(leader, fixture):
    # Only inspect the process after its exact invocation and cgroup are held.
    # A host-wide /run/sshd cannot satisfy the owned inode checks.
    runtime = directory_identity(fixture.runtime, 0, 0o755)
    privsep = directory_identity(fixture.runtime / "sshd", 0, 0o755)
    view = leader / "root" / PRIVSEP.relative_to("/")
    observed = run(
        [STAT, "--dereference", "--format=%d:%i:%u:%a", "--", view.parent, view],
        privileged=True, operation="namespace runtime and privilege separation inodes",
    ).decode("ascii").splitlines()
    if observed != [f"{device}:{inode}:0:755" for device, inode in (runtime, privsep)]:
        raise Blocked("OpenSSH privilege separation is outside the owned runtime")
    mounts = json.loads(run(
        [FINDMNT, "--task", leader.name, "--uniq", "--json", "--mountpoint", "/run",
         "--output", "TARGET,OPTIONS"],
        privileged=True, operation="namespace runtime mount",
    ))["filesystems"]
    if len(mounts) != 1 or (
        mounts[0]["target"] != "/run" or "ro" not in mounts[0]["options"].split(",")
    ):
        raise Blocked("the OpenSSH namespace runtime is not read-only")


def unit_known(name):
    result = run(
        [SYSTEMCTL, "list-units", "--all", "--plain", "--no-legend", "--full", "--", name],
        operation="fixture unit presence",
    ).decode("ascii")
    rows = [line.split() for line in result.splitlines() if line.strip()]
    if not rows:
        return False
    if len(rows) != 1 or rows[0][0] != name:
        raise CleanupUnconfirmed("generated unit presence is ambiguous")
    return True


def unit_status(name):
    keys = ("LoadState", "ActiveState", "ControlGroup", "InvocationID", "KillMode", "Delegate",
            "MainPID", "Transient", "ProtectControlGroups")
    output = run(
        [SYSTEMCTL, "show", f"--property={','.join(keys)}", "--", name],
        operation="fixture unit observation",
    ).decode("ascii")
    rows = dict(line.split("=", 1) for line in output.splitlines())
    if rows.keys() != set(keys):
        raise Blocked("fixture unit state is ambiguous")
    return rows


def cgroup_present(cgroup, expected_identity):
    try:
        detail = cgroup.lstat()
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISDIR(detail.st_mode) or cgroup.resolve(strict=True) != cgroup
        or (detail.st_dev, detail.st_ino) != expected_identity
    ):
        raise CleanupUnconfirmed("fixture cgroup identity changed")
    return True


def cgroup_drained(cgroup, expected_identity):
    if not cgroup_present(cgroup, expected_identity):
        return True
    fields = (cgroup / "cgroup.events").read_text(encoding="ascii").splitlines()
    populated = [line for line in fields if line.startswith("populated ")]
    if populated not in (["populated 0"], ["populated 1"]):
        raise CleanupUnconfirmed("fixture cgroup population could not be established")
    return populated == ["populated 0"]


@dataclass
class Fixture:
    nonce: str
    gid: int
    root_identity: tuple[int, int] | None = None
    account_identity: tuple[int, int] | None = None
    root_attempted: bool = False
    account_attempted: bool = False
    unit_attempted: bool = False
    invocation: str | None = None
    cgroup_identity: tuple[int, int] | None = None

    def __post_init__(self):
        if not FIXTURE_ID.fullmatch(self.nonce):
            raise Blocked("invalid generated commissioning identifier")

    @property
    def root(self):
        return BASE / f"exacopy-direct-{self.nonce}"

    @property
    def account(self):
        return f"exacopy-d-{self.nonce}"

    @property
    def unit(self):
        return f"exacopy-direct-{self.nonce}.service"

    @property
    def cgroup(self):
        return CGROUP / self.unit

    @property
    def private(self):
        return self.root / "private"

    @property
    def runtime(self):
        return self.root / "runtime"

    @property
    def chroot(self):
        return self.root / "chroot"

    @property
    def destination(self):
        return self.root / "destination"

    @property
    def source(self):
        return self.private / "sources"

    def make_root(self):
        checkpoint()
        if os.path.lexists(self.root) or local_account(self.account) is not None:
            raise Blocked("generated commissioning fixture is already occupied")
        if unit_known(self.unit) or os.path.lexists(self.cgroup):
            raise Blocked("generated commissioning service is already occupied")
        self.root_attempted = True
        run([MKDIR, "--mode=0755", "--", self.root], privileged=True, operation="private root creation")
        self.root_identity = directory_identity(self.root, 0, 0o755)
        checkpoint()
        run(
            [INSTALL, "-d", "-m", "0700", "-o", str(os.geteuid()), "-g", str(os.getegid()),
             "--", self.private, self.destination],
            privileged=True, operation="owner private fixture directories",
        )
        directory_identity(self.private, os.geteuid(), 0o700)
        directory_identity(self.destination, os.geteuid(), 0o700)
        checkpoint()
        self.source.mkdir(mode=0o755)
        self.source.chmod(0o755)
        mirror = self.chroot / self.source.relative_to("/")
        checkpoint()
        run([INSTALL, "-d", "-m", "0755", "--", mirror], privileged=True, operation="private chroot mirror")
        for ancestor in (mirror, *mirror.parents):
            if ancestor == self.root:
                break
            directory_identity(ancestor, 0, 0o755)

    def make_runtime(self):
        checkpoint()
        privsep = self.runtime / "sshd"
        run([INSTALL, "-d", "-m", "0755", "--", privsep],
            privileged=True, operation="owned privilege separation runtime")
        directory_identity(self.runtime, 0, 0o755)
        directory_identity(privsep, 0, 0o755)
        if any(privsep.iterdir()):
            raise Blocked("the owned privilege separation directory is not empty")

    def make_sources(self):
        checkpoint()
        small, large = self.source / "empty", self.source / "interrupt"
        for path in (small, large):
            checkpoint()
            with path.open("xb") as output:
                if path == large:
                    for index in range(SOURCE_BYTES // (1024 * 1024)):
                        checkpoint()
                        seed = self.nonce.encode() + index.to_bytes(4, "little")
                        output.write(hashlib.shake_256(seed).digest(1024 * 1024))
                os.fchmod(output.fileno(), 0o444)
        return small, large

    def sshd_config(self, port):
        return sshd_configuration(self, port)

    def sshd_properties(self):
        return unit_properties(self)

    def observe_account(self):
        current = local_account(self.account)
        if current is None:
            return None
        if (
            current.pw_gecos != f"ExaCopy direct fixture {self.nonce}"
            or current.pw_gid != self.gid or current.pw_shell != NOLOGIN
            or current.pw_dir != "/" or current.pw_uid in (0, os.geteuid())
        ):
            raise CleanupUnconfirmed("fixture account identity differs")
        return current.pw_uid, current.pw_gid

    def make_account(self):
        checkpoint()
        if local_account(self.account) is not None or local_group(self.account) is not None:
            raise Blocked("fixture account or group is occupied")
        self.account_attempted = True
        run(
            [USERADD, "--system", "--no-create-home", "--no-user-group", "--no-log-init", "--gid", str(self.gid),
             "--shell", NOLOGIN, "--home-dir", "/", "--comment", f"ExaCopy direct fixture {self.nonce}",
             "--", self.account],
            privileged=True, operation="dedicated fixture account creation",
        )
        self.account_identity = self.observe_account()
        if self.account_identity is None:
            raise CleanupUnconfirmed("fixture account creation was not observed")
        # PAM-free sshd needs a nonlocked account. The random password is
        # discarded and its hash only crosses this private stdin channel.
        checkpoint()
        secret = secrets.token_hex(48).encode("ascii") + b"\n"
        password_hash = run([OPENSSL, "passwd", "-6", "-stdin"], data=secret, operation="account password hash")
        if not re.fullmatch(rb"\$6\$[./0-9A-Za-z]+\$[./0-9A-Za-z]+\n", password_hash):
            raise Blocked("invalid private account hash format")
        checkpoint()
        run([CHPASSWD, "--encrypted"], privileged=True,
            data=self.account.encode("ascii") + b":" + password_hash, operation="nonlocked fixture account setup")

    def make_peer(self):
        return self.make_selected_peer("127.0.0.1", select_port(), "127.0.0.1", None, None)

    def make_selected_peer(self, listen, port, source, protected_namespace, embedded_route):
        if (protected_namespace is None) != (embedded_route is None):
            raise Blocked("fixture namespace and embedded route must be selected together")
        if protected_namespace is None and (listen, source) != ("127.0.0.1", "127.0.0.1"):
            raise Blocked("direct fixture requires loopback listener and source")

        self.make_runtime()
        host, client = self.private / "host-key", self.private / "client-key"
        for key in (host, client):
            checkpoint()
            run([SSHD_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", key], operation="fixture key generation")
        allowed, client_hash = public_key(client.with_suffix(".pub"))
        host_key, host_hash = public_key(host.with_suffix(".pub"))
        checkpoint()
        run([INSTALL, "-m", "0600", "--", host, self.root / "host-key"],
            privileged=True, operation="root-owned fixture host key installation")
        host.unlink()
        authorized = self.root / "authorized_keys"
        public_file = self.private / "authorized_keys"
        public_file.write_bytes(b"restrict " + allowed + b"\n")
        checkpoint()
        run([INSTALL, "-m", "0644", "--", public_file, authorized],
            privileged=True, operation="fixture account public key installation")
        log = self.root / "peer.log"
        checkpoint()
        run(
            [INSTALL, "-m", "0600", "-o", str(os.geteuid()), "-g", str(os.getegid()),
             "--", "/dev/null", log],
            privileged=True, operation="fixture-only daemon log in the owned root",
        )
        known = self.private / "known_hosts"
        known.write_bytes(f"[{listen}]:{port} ".encode("ascii") + host_key + b"\n")
        known.chmod(0o600)
        config_source = self.private / "sshd_config"
        config = self.root / "sshd_config"
        configuration = (
            self.sshd_config(port)
            if protected_namespace is None
            else sshd_configuration(self, port, listen, source)
        )
        config_source.write_text(configuration, encoding="ascii")
        checkpoint()
        run([INSTALL, "-m", "0600", "--", config_source, config],
            privileged=True, operation="root-owned fixture OpenSSH configuration")
        profile = self.private / "ssh.json"
        route = {"kind": "direct", "endpoint": f"{listen}:{port}"} if embedded_route is None else embedded_route
        write_json(profile, {
            "schema": "exacopy-ssh-profile-v1", "host": listen,
            "port": port, "account": self.account,
            "host_key_sha256": host_hash, "known_hosts": str(known),
            "credential": {"kind": "openssh-ed25519", "private_key_file": str(client),
                           "public_key_sha256": client_hash},
            "route": route,
            "maximum_extent": SOURCE_BYTES, "grant_seconds": 300,
        })
        profile.chmod(0o600)
        checkpoint()
        self.unit_attempted = True
        if protected_namespace is None:
            properties = self.sshd_properties()
        else:
            properties = unit_properties(self)
            properties["NetworkNamespacePath"] = str(protected_namespace)
            properties["CapabilityBoundingSet"] = "~CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_RAW"
        run(
            [SYSTEMD_RUN, "--quiet", "--unit", self.unit,
             *(f"--property={key}={value}" for key, value in properties.items()),
             "--", SSHD, "-D", "-E", log, "-f", config],
            privileged=True, budget=30, operation="dedicated OpenSSH service start",
        )
        current = unit_status(self.unit)
        if (
            current["LoadState"] != "loaded" or current["ActiveState"] != "active"
            or current["ControlGroup"] != f"/system.slice/{self.unit}"
            or not re.fullmatch(r"[0-9a-f]{32}", current["InvocationID"])
            or current["KillMode"] != "control-group" or current["Delegate"] != "no"
            or current["Transient"] != "yes" or current["ProtectControlGroups"] != "yes"
            or not re.fullmatch(r"[1-9][0-9]{0,9}", current["MainPID"])
        ):
            raise CleanupUnconfirmed("OpenSSH ownership could not be established")
        leader = Path(f"/proc/{current['MainPID']}")
        actual = (leader / "cgroup").read_text(encoding="ascii").splitlines()
        if actual != [f"0::/system.slice/{self.unit}"]:
            raise CleanupUnconfirmed("OpenSSH leader is outside the owned cgroup")
        detail = self.cgroup.lstat()
        if not stat.S_ISDIR(detail.st_mode) or self.cgroup.resolve(strict=True) != self.cgroup:
            raise CleanupUnconfirmed("OpenSSH unit lacks an exact cgroup directory")
        self.cgroup_identity = detail.st_dev, detail.st_ino
        self.invocation = current["InvocationID"]
        lines = (leader / "status").read_text(encoding="ascii").splitlines()
        bounding = [line.split()[1] for line in lines if re.fullmatch(r"CapBnd:\s+[0-9a-f]{16}", line)]
        if len(bounding) != 1 or int(bounding[0], 16) & (1 << CAP_SYS_ADMIN):
            raise Blocked("OpenSSH leader retained a mount administration capability")
        verify_privsep_runtime(leader, self)
        deadline = time.monotonic() + 12
        expected = f"Server listening on {listen} port {port}.".encode("ascii")
        while time.monotonic() < deadline:
            checkpoint()
            with log.open("rb") as source:
                raw = source.read(PEER_LOG_LIMIT + 1)
            if len(raw) > PEER_LOG_LIMIT:
                raise Blocked("fixture daemon log exceeds its startup bound")
            if expected in raw:
                self.recheck_listening_leader(current, leader)
                return profile, log, {
                    "implementation": "OpenSSH", "listener": f"{listen}:{port}",
                    "host_key_sha256": host_hash, "client_key_sha256": client_hash,
                    "invocation_id": self.invocation,
                    "privsep_runtime": "owned-read-only-mount",
                }
            time.sleep(0.05)
        raise Blocked("dedicated OpenSSH listener was not observed")

    def recheck_listening_leader(self, registered, leader):
        if unit_status(self.unit) != registered:
            raise Blocked("the registered OpenSSH invocation or leader changed before readiness")
        if not cgroup_present(self.cgroup, self.cgroup_identity):
            raise Blocked("the OpenSSH cgroup disappeared before readiness")
        actual = (leader / "cgroup").read_text(encoding="ascii").splitlines()
        if actual != [f"0::/system.slice/{self.unit}"]:
            raise Blocked("the registered OpenSSH leader left the owned cgroup before readiness")

    def stop_peer(self):
        if self.unit_attempted:
            if self.invocation is None:
                raise CleanupUnconfirmed("no exact OpenSSH unit invocation to stop")
            cgroup_present(self.cgroup, self.cgroup_identity)
            if unit_known(self.unit):
                current = unit_status(self.unit)
                if current["InvocationID"] != self.invocation or current["ControlGroup"] not in (
                    f"/system.slice/{self.unit}", "",
                ):
                    raise CleanupUnconfirmed("OpenSSH invocation ownership changed")
                run([SYSTEMCTL, "stop", "--", self.unit],
                    privileged=True, budget=25, operation="dedicated OpenSSH group stop")
            if not cgroup_drained(self.cgroup, self.cgroup_identity):
                raise CleanupUnconfirmed("OpenSSH cgroup still contains processes")

    def stop(self):
        self.stop_peer()
        if self.account_attempted:
            current = self.observe_account()
            if current is not None:
                if self.account_identity is None or current != self.account_identity:
                    raise CleanupUnconfirmed("fixture account ownership remains unconfirmed")
                if local_group(self.account) is not None:
                    raise CleanupUnconfirmed("unexpected same-name group blocks fixture account removal")
                run([USERDEL, "--", self.account], privileged=True, operation="dedicated fixture account removal")
                if local_account(self.account) is not None:
                    raise CleanupUnconfirmed("fixture account removal remains unconfirmed")
        if self.root_attempted:
            if self.root_identity is None or directory_identity(self.root, 0, 0o755) != self.root_identity:
                raise CleanupUnconfirmed("fixture directory ownership remains unconfirmed")
            run([REMOVE, "-r", "--one-file-system", "--", self.root],
                privileged=True, budget=30, operation="owned fixture tree removal")
            if os.path.lexists(self.root):
                raise CleanupUnconfirmed("fixture tree removal remains unconfirmed")
