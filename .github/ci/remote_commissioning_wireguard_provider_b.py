"""Explicitly load the fixed verified Azure WireGuard provider in a disposable hosted job."""
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile
import time

import remote_commissioning_wireguard_provider as provider
from native_supervision import CleanupUnconfirmed, file_digest, logged_command, write_json
from remote_commissioning_peer import Blocked, INSTALL, SUDO, checkpoint, directory_identity
from remote_commissioning_wireguard_net import SET_PRIV, command

WORKFLOW_REF = "replicraft/ExaCopy/.github/workflows/linux-remote-wireguard-provider-b.yml@refs/heads/main"
RELEASE = "7.0.0-1017-azure"
BUILD = "#17~24.04.1-Ubuntu SMP PREEMPT Thu Sep 24 18:46:57 UTC 2026"
VERSION = "7.0.0-1017.17~24.04.1"
IMAGE = f"linux-image-{RELEASE}"
PACKAGE = f"linux-modules-{RELEASE}"
ARCHIVE = f"{PACKAGE}_{VERSION}_amd64.deb"
ARCHIVE_BYTES = 148377792
ARCHIVE_SHA256 = "19ad1d32c0138b6ef90257f211e80490d3aaf322ba5c3c2910fdfbfb1f20da6d"
TREE = Path(f"/lib/modules/{RELEASE}")
CONFIG = Path(f"/boot/config-{RELEASE}")
BUILTIN = TREE / "modules.builtin"
MODULES = {
    "wireguard": TREE / "kernel/drivers/net/wireguard/wireguard.ko.zst",
    "udp_tunnel": TREE / "kernel/net/ipv4/udp_tunnel.ko.zst",
    "ip6_udp_tunnel": TREE / "kernel/net/ipv6/ip6_udp_tunnel.ko.zst",
    "libcurve25519": TREE / "kernel/lib/crypto/libcurve25519.ko.zst",
}
EXPECTED = {
    CONFIG: "59b49d17af9e7049b5d1c0de5451d8afbeac39420b5086bfaa39f16cd1dec10b",
    BUILTIN: "bd1052b0290f2968662c89a9d1576f273084d51eeda8ca717b3403ad0a159654",
    MODULES["wireguard"]: "f4f7849240810f17ba54b6cb080195a5d640e090bc76b71f07903383f2d69c96",
}
DPKG_DEB = "/usr/bin/dpkg-deb"
MODINFO = "/usr/sbin/modinfo"
MODPROBE = "/usr/sbin/modprobe"
INSMOD = "/usr/sbin/insmod"
MODULE_BYTES = 4 * 1024 * 1024
TAR_BYTES = 256 * 1024 * 1024
TOOL_ENV = {"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"}


def hosted_scope():
    env = os.environ
    uid = os.geteuid()
    revision = env.get("GITHUB_SHA", "")
    if (
        sys.platform != "linux" or uid == 0 or os.getuid() != uid or os.getegid() != os.getgid()
        or env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or env.get("RUNNER_OS") != "Linux" or env.get("RUNNER_ARCH") != "X64"
        or env.get("GITHUB_SERVER_URL") != "https://github.com"
        or env.get("GITHUB_REPOSITORY", "").lower() != "replicraft/exacopy"
        or env.get("GITHUB_REF") != "refs/heads/main" or env.get("GITHUB_EVENT_NAME") != "push"
        or env.get("GITHUB_WORKFLOW_REF") != WORKFLOW_REF or env.get("GITHUB_WORKFLOW_SHA") != revision
        or not re.fullmatch(r"[0-9a-f]{40}", revision) or "EXACOPY_REMOTE_DEPLOYMENT" in env
    ):
        raise Blocked("fixed Azure B requires its exact canonical main push workflow")


def package_record(name):
    return {"package": name, "version": VERSION, "architecture": "amd64"}


def admit(observed):
    kernel = observed.get("kernel", {})
    boot = kernel.get("boot_id")
    facts = observed.get("observations", {})
    if (
        observed.get("schema") != "exacopy.hosted-wireguard-provider-observation.v2"
        or observed.get("provider") != "packaged-but-unloaded"
        or not isinstance(boot, str)
        or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot)
        or kernel != {"release": RELEASE, "build": BUILD, "architecture": "x86_64", "boot_id": boot}
        or facts.get("booted_kernel_package") != package_record(IMAGE)
        or facts.get("module_listing_before", {}).get("status") != "absent"
        or facts.get("module_listing_after", {}).get("status") != "absent"
        or facts.get("module_initstate", {}).get("status") != "missing"
    ):
        raise Blocked("fixed Azure provider B did not match the exact unloaded boot")
    for field, path, selection in (
        ("config", CONFIG, "module"),
        ("builtin_inventory", BUILTIN, "absent"),
        ("module_file", MODULES["wireguard"], "packaged"),
    ):
        fact = facts.get(field, {})
        if fact.get("status") != selection or fact.get("sha256") != EXPECTED[path] or any(
            fact.get(key) != value for key, value in package_record(PACKAGE).items()
        ):
            raise Blocked("fixed Azure provider B source observation differs")
    return kernel


def recheck_boot(expected):
    actual = os.uname()
    if (
        provider.boot_id() != expected["boot_id"] or actual.release != RELEASE
        or actual.version != BUILD or actual.machine != "x86_64" or actual.sysname != "Linux"
    ):
        raise Blocked("provider B boot changed")


def regular(path, uid, length):
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
        or info.st_mode & 0o022 or not 0 < info.st_size <= length
    ):
        raise Blocked("provider B input is outside exact file custody")
    return (info.st_dev, info.st_ino, info.st_size, info.st_ctime_ns, info.st_mtime_ns)


def checked_hash(path, uid, maximum):
    before = regular(path, uid, maximum)
    result = file_digest(path)
    if regular(path, uid, maximum) != before:
        raise Blocked("provider B input changed during hashing")
    return result


def extract_selected(source, staging, selected):
    required = {path.relative_to("/").as_posix(): path for path in selected}
    required.update({f"usr/{name}": path for name, path in tuple(required.items()) if name.startswith("lib/")})
    output = {}
    with tarfile.open(source, mode="r:") as archive:
        for member in archive:
            normalized = member.name.removeprefix("./")
            if normalized not in required:
                continue
            path = required[normalized]
            if path in output or not member.isreg() or not 0 < member.size <= MODULE_BYTES:
                raise Blocked("provider B selected archive members are ambiguous")
            payload = archive.extractfile(member)
            if payload is None:
                raise Blocked("provider B archive member is unreadable")
            with payload:
                data = payload.read(member.size + 1)
            if len(data) != member.size:
                raise Blocked("provider B archive member is incomplete")
            target = staging / path.name
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            output[path] = target
    if set(output) != set(selected):
        raise Blocked("provider B archive omits a required selected member")
    return output


def archived_sources(archive, work):
    owner = os.geteuid()
    archive_identity = regular(archive, owner, ARCHIVE_BYTES)
    if archive_identity[2] != ARCHIVE_BYTES or checked_hash(archive, owner, ARCHIVE_BYTES) != ARCHIVE_SHA256:
        raise Blocked("provider B archive differs from the pinned Canonical bytes")
    fields = read_command(work, "package control identity", [
        DPKG_DEB, "--show", "--showformat=${Package}\t${Version}\t${Architecture}\n", archive,
    ])
    if fields != f"{PACKAGE}\t{VERSION}\tamd64\n".encode():
        raise Blocked("provider B archive package identity differs")
    tar = work / "selected-package.tar"
    result = logged_command([DPKG_DEB, "--fsys-tarfile", archive], tar, 45, env=TOOL_ENV, output_limit=TAR_BYTES)
    if not result.passed() or regular(archive, owner, ARCHIVE_BYTES) != archive_identity:
        raise Blocked("provider B authenticated archive extraction did not complete")
    staging = work / "members"
    staging.mkdir(mode=0o700)
    try:
        return extract_selected(tar, staging, (*EXPECTED, *(p for p in MODULES.values() if p not in EXPECTED)))
    except tarfile.TarError as error:
        raise Blocked("provider B authenticated archive is malformed") from error
    finally:
        tar.unlink()


def read_command(work, label, argv):
    # The whole private work tree is retained if a reader's group did not drain.
    scratch = Path(tempfile.mkdtemp(prefix="provider-b-read-", dir=work))
    log = scratch / "output"
    result = logged_command(argv, log, 8, env=TOOL_ENV, output_limit=16 * 1024)
    if not result.passed():
        raise Blocked(f"provider B could not observe {label}")
    return log.read_bytes()


def installed_hash(path):
    actual = provider.from_kernel_package(path, RELEASE, VERSION, MODULE_BYTES, lambda _: "packaged")
    if actual["status"] != "packaged" or any(
        actual.get(key) != value for key, value in package_record(PACKAGE).items()
    ):
        raise Blocked("provider B installed source does not match the exact kernel package")
    return actual["sha256"]


@dataclass(frozen=True)
class Module:
    name: str
    sha256: str
    depends: tuple[str, ...]
    vermagic: str
    signer: str


def module_metadata(work, name, path, sha):
    fields = {}
    for field in ("name", "depends", "vermagic", "signer", "sig_id"):
        raw = read_command(work, "ELF module metadata", [MODINFO, "-F", field, "--", path])
        if not re.fullmatch(rb"[\x20-\x7e]{0,200}\n?", raw):
            raise Blocked("provider B module metadata is malformed")
        fields[field] = raw.decode("ascii").rstrip("\n")
    depends = tuple(fields["depends"].split(",")) if fields["depends"] else ()
    if (
        fields["name"] != name or not fields["vermagic"].startswith(RELEASE + " ")
        or not fields["signer"] or fields["sig_id"] != "PKCS#7"
        or len(depends) != len(set(depends)) or any(dependency not in MODULES for dependency in depends)
    ):
        raise Blocked("provider B module ABI, signature metadata or dependency is outside the pin")
    return Module(name, sha, depends, fields["vermagic"], fields["signer"])


def closure_order(modules, plan):
    closure = set()

    def visit(name, stack):
        if name in stack or name not in modules:
            raise Blocked("provider B dependency closure is cyclic or incomplete")
        if name not in closure:
            for dep in modules[name].depends:
                visit(dep, stack | {name})
            closure.add(name)

    visit("wireguard", set())
    expected_paths = {str(path): name for name, path in MODULES.items()} | {
        f"/usr{path}": name for name, path in MODULES.items()
    }
    ordered = []
    for line in plan.decode("ascii").splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] != "insmod" or fields[1] not in expected_paths:
            raise Blocked("provider B kmod plan has unexpected command, option or path")
        name = expected_paths[fields[1]]
        if name not in closure or name in ordered or any(dep not in ordered for dep in modules[name].depends):
            raise Blocked("provider B native kmod ordering differs from ELF dependency closure")
        ordered.append(name)
    if set(ordered) != closure or ordered[-1] != "wireguard":
        raise Blocked("provider B kmod plan is incomplete")
    if len({modules[name].signer for name in ordered}) != 1 or len({modules[name].vermagic for name in ordered}) != 1:
        raise Blocked("provider B staged closure disagrees on signer or vermagic")
    return ordered


def live_state(name):
    if name not in MODULES:
        raise ValueError("unselected module observation")
    def listing():
        raw = provider.read_root_file(Path("/proc/modules"), provider.MAX_METADATA)
        return [fields for line in raw.splitlines() if (fields := line.split()) and fields[0] == name.encode()]

    rows = listing()
    try:
        init = provider.read_root_file(Path("/sys/module") / name / "initstate", 64)
    except FileNotFoundError:
        init = None
    later = listing()
    if [row[4] for row in rows if len(row) >= 6] != [row[4] for row in later if len(row) >= 6] or len(rows) != len(later):
        raise Blocked("provider B module state changed during observation")
    if not rows and init is None:
        return "absent"
    if len(rows) == 1 and len(rows[0]) >= 6 and rows[0][4] == b"Live" and init == b"live\n":
        return "live"
    raise Blocked("provider B module is transitional or its state could not be paired")


def load_once(path, report, number, name, sha, budget):
    hosted_scope()
    marker = report / f"provider-b-{number}-attempt.json"
    write_json(marker, {"name": name, "sha256": sha, "effect": "submitted-or-uncertain"})
    argv = [
        SUDO, "-n", "--", SET_PRIV, "--bounding-set=-all,+sys_module",
        "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", INSMOD, path,
    ]
    result = logged_command(argv, report / f"provider-b-{number}.log", budget, env=TOOL_ENV, output_limit=64 * 1024)
    write_json(report / f"provider-b-{number}-result.json", {"status": result.status, "exit_status": result.exit_status})
    if not result.passed():
        raise Blocked("provider B fixed load failed or remains uncertain")


def stage_load(work, report, root, root_identity, selected, modules, order, expected, evidence):
    if directory_identity(root, 0, 0o755) != root_identity:
        raise CleanupUnconfirmed("provider B fixture root changed before module staging")
    destination = root / "provider-b"
    if os.path.lexists(destination):
        raise Blocked("provider B root staging is occupied")
    command(work, "fixed root module staging", ["/usr/bin/mkdir", "--mode=0755", "--", destination])
    identity = directory_identity(destination, 0, 0o755)
    paths = {}
    for name in order:
        path = destination / MODULES[name].name
        command(work, "verified module copy to root custody", [INSTALL, "-m", "0644", "--", selected[MODULES[name]], path])
        if checked_hash(path, 0, MODULE_BYTES) != modules[name].sha256:
            raise Blocked("provider B root staging bytes differ")
        paths[name] = path

    # All archive, metadata and ordering checks precede the first load.
    if admit(provider.report()) != expected:
        raise Blocked("provider B unloaded observations changed before submission")
    observed = {name: live_state(name) for name in order}
    if observed["wireguard"] != "absent":
        raise Blocked("provider B origin is no longer unloaded")
    evidence["initial"] = observed
    updated = evidence["disposition"] = {}
    deadline = time.monotonic() + 120
    for number, name in enumerate(order):
        checkpoint()
        recheck_boot(expected)
        if (
            directory_identity(root, 0, 0o755) != root_identity
            or directory_identity(destination, 0, 0o755) != identity
            or checked_hash(paths[name], 0, MODULE_BYTES) != modules[name].sha256
        ):
            raise CleanupUnconfirmed("provider B protected staging identity changed")
        if any(live_state(dep) != "live" for dep in modules[name].depends) or live_state(name) != observed[name]:
            raise Blocked("provider B exact module custody changed before submission")
        if observed[name] == "live":
            updated[name] = "previously-live-name-only"
            continue
        budget = min(15, deadline - time.monotonic())
        if budget <= 0:
            raise Blocked("provider B exhausted its bounded deadline")
        for executable in (SUDO, SET_PRIV, INSMOD):
            if checked_hash(Path(executable).resolve(strict=True), 0, 4 * 1024 * 1024) != evidence["tools_sha256"][executable]:
                raise CleanupUnconfirmed("provider B loader custody changed at submission")
        updated[name] = "submitted-or-uncertain"
        try:
            load_once(paths[name], report, number, name, modules[name].sha256, budget)
            recheck_boot(expected)
            if live_state(name) != "live":
                raise Blocked("provider B submitted module could not be observed Live")
        except (Blocked, CleanupUnconfirmed, OSError, ValueError):
            try:
                recheck_boot(expected)
                state = live_state(name)
            except (Blocked, OSError, ValueError):
                state = "unknown"
            evidence["last_observed_after_failure"] = {"module": name, "state": state}
            raise
        updated[name] = "loaded-live"
    if any(live_state(name) != "live" for name in order):
        raise Blocked("provider B did not establish the complete Live closure")
    evidence["loaded"] = True


def prepare(archive_dir, work, report, fixture, expected, evidence):
    hosted_scope()
    recheck_boot(expected)
    directory_identity(archive_dir, os.geteuid(), 0o700)
    stage = work / "provider-b-private"
    stage.mkdir(mode=0o700)
    evidence["module_archive_sha256"] = ARCHIVE_SHA256
    evidence["loaded"] = False
    evidence["module_lifetime"] = "disposable-runner-vm"
    evidence["tools_sha256"] = {path: checked_hash(Path(path).resolve(strict=True), 0, 4 * 1024 * 1024)
                                 for path in (DPKG_DEB, MODINFO, MODPROBE, SUDO, SET_PRIV, INSMOD)}
    selected = archived_sources(archive_dir / ARCHIVE, stage)
    modules = {}
    for path, source in selected.items():
        sha = checked_hash(source, os.geteuid(), MODULE_BYTES)
        if installed_hash(path) != sha or (path in EXPECTED and EXPECTED[path] != sha):
            raise Blocked("provider B package members differ from the exact installed files")
        name = next((name for name, filed in MODULES.items() if filed == path), None)
        if name is not None:
            modules[name] = module_metadata(stage, name, source, sha)
    config = stage / "kmod-empty.conf"
    config.touch(mode=0o600, exist_ok=False)
    plan = read_command(stage, "read-only kmod dependency plan", [
        MODPROBE, "--show-depends", f"--config={config}", f"--set-version={RELEASE}", "--", "wireguard",
    ])
    order = closure_order(modules, plan)
    evidence["plan_sha256"] = provider.digest(plan)
    evidence["order"] = order
    evidence["closure"] = [{
        "name": m.name, "sha256": m.sha256, "depends": m.depends, "vermagic": m.vermagic, "signer": m.signer,
    } for m in (modules[name] for name in order)]
    if any(checked_hash(Path(path).resolve(strict=True), 0, 4 * 1024 * 1024) != sha
           for path, sha in evidence["tools_sha256"].items()):
        raise Blocked("provider B tool identity changed before staging")
    stage_load(stage, report, fixture.root, fixture.root_identity, selected, modules, order, expected, evidence)
