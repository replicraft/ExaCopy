"""Qualify one held historical-location and member fixture on a native Linux host."""

import argparse
from contextlib import ExitStack
from dataclasses import dataclass
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import stat
import struct
import sys
import subprocess
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "tools/qualification"))
import native_supervision as supervision

PACKAGE = ROOT / "crates/platform/exacopy-platform"
CLI_PACKAGE = ROOT / "apps/exacopy-cli"
TARGET = "x86_64-unknown-linux-gnu"
TOOLCHAIN = "1.100.0"
TEST = "linux_sync_history_ext4"
CASE = "held_ext4_history_scope_and_named_members_refuse_aliases_and_swaps"
FIXTURE = Path(__file__).with_name("fixture.toml")
PROFILE = "linux-unprivileged-whole-ext4-sync-history-v1"
MARKER = "EXACOPY_SYNC_HISTORY_EXT4_RESULT "
OUTPUT_LIMIT = 8 * 1024 * 1024
MANAGED_CLI_LIMIT = 128 * 1024 * 1024
FD_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
DIR_FLAGS = FD_FLAGS | os.O_DIRECTORY
UNAVAILABLE = {errno.ENOENT, errno.ENODEV, errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP,
               errno.ELOOP, errno.EXDEV, errno.EACCES, errno.EPERM}


@dataclass(frozen=True)
class FixtureProfile:
    id: str
    profile: str
    definition: Path
    test: str
    case: str
    parent_variable: str
    workflow: str
    required_feature: str | None = None
    package_root: Path = PACKAGE


HISTORY = FixtureProfile(
    "linux-sync-history-ext4", PROFILE, FIXTURE, TEST, CASE,
    "EXACOPY_SYNC_HISTORY_EXT4_PARENT", ".github/workflows/linux-sync-history-ext4-qualification.yml",
)
STATMOUNT = FixtureProfile(
    "linux-sync-history-ext4-statmount", "linux-unprivileged-whole-ext4-sync-statmount-v1",
    FIXTURE.parent.parent / "sync_history_ext4_statmount" / "fixture.toml", "linux_sync_history_ext4_statmount",
    "held_ext4_history_mount_admits_unmapped_attributes", "EXACOPY_SYNC_HISTORY_STATMOUNT_PARENT",
    ".github/workflows/linux-sync-history-ext4-statmount-qualification.yml",
    "experimental-linux-managed-sync",
)
MANAGED = FixtureProfile(
    "linux-managed-sync-production", "linux-unprivileged-whole-ext4-managed-sync-production-v1",
    CLI_PACKAGE / "verification/managed_sync_production/fixture.toml", "linux_managed_sync_production",
    "production_managed_init_then_preview_exact_p063_history", "EXACOPY_MANAGED_SYNC_FIXTURE_PARENT",
    ".github/workflows/linux-managed-sync-production-qualification.yml",
    "experimental-linux-managed-sync", CLI_PACKAGE,
)
MANAGED_MARKER = "managed_sync_production="
STATMOUNT_MARKER = "EXACOPY_SYNC_HISTORY_STATMOUNT_RESULT "
SIDES = ("left", "right")


class Blocked(RuntimeError):
    """An independently observed host prerequisite is unavailable."""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(evidence, label, args, *, env=None, held=(), executable=None, timeout=20, observe_exit=False):
    args = list(map(os.fspath, args))
    marker = evidence / f"{label}.drain"
    with marker.open("x", encoding="ascii") as state:
        state.write("pending\n")
    (evidence / f"{label}.argv.json").write_text(json.dumps(args) + "\n")
    output = [bytearray(), bytearray()]
    code = 127
    drain = "not_started"
    try:
        require(not supervision.CANCELLATION_REQUESTED, f"{label} cancelled before launch")
        drain = "unconfirmed"
        try:
            process = subprocess.Popen(
                args, executable=executable, cwd=ROOT, env=env, pass_fds=held,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError:
            drain = "not_started"
            raise
        try:
            try:
                capture(process, output, label, timeout)
            except supervision.CleanupUnconfirmed:
                raise
            except BaseException:
                supervision.stop_group(process, signal.SIGTERM)
                code = process.returncode
                drain = "verified_absent_after_failure"
                raise
            # The shared supervisor pins the leader with WNOWAIT before its last real signal.
            immediately_drained = supervision.stop_group(process, signal.SIGKILL)
            code = process.returncode
            drain = "verified_absent"
            require(immediately_drained, f"{label} required late descendant drain")
            require(not supervision.CANCELLATION_REQUESTED, f"{label} cancelled")
        finally:
            process.stdout.close()
            process.stderr.close()
    finally:
        (evidence / f"{label}.stdout").write_bytes(output[0])
        (evidence / f"{label}.stderr").write_bytes(output[1])
        (evidence / f"{label}.exit").write_text(f"{code}\n")
        marker.write_text(f"{drain}\n")
    if observe_exit:
        return bytes(output[0]).decode("utf-8", errors="strict"), code
    require(code == 0, f"{label} exited {code}")
    return bytes(output[0]).decode("utf-8", errors="strict")


def capture(process, output, label, timeout):
    limit = time.monotonic() + timeout
    with selectors.DefaultSelector() as readers:
        readers.register(process.stdout, selectors.EVENT_READ, 0)
        readers.register(process.stderr, selectors.EVENT_READ, 1)
        while True:
            require(not supervision.CANCELLATION_REQUESTED, f"{label} cancelled")
            budget = min(supervision.POLL_INTERVAL, limit - time.monotonic())
            if budget <= 0:
                raise TimeoutError(f"{label} timed out")
            if not readers.get_map():
                if supervision.leader_exited(process):
                    return
                time.sleep(budget)
                continue
            for key, _ in readers.select(budget):
                data = os.read(key.fd, supervision.READ_CHUNK)
                if not data:
                    readers.unregister(key.fileobj)
                    continue
                stream = output[key.data]
                room = OUTPUT_LIMIT - len(stream)
                stream.extend(data[:room])
                require(len(data) <= room, f"{label} exceeded the evidence bound")


def read_bounded(fd, limit):
    data = bytearray()
    while len(data) <= limit:
        chunk = os.read(fd, min(65536, limit + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
    raise Blocked("native proc evidence exceeds the supported bound")


def proc_open(stack, name, parent, flags, *, resolve=0x0D):
    if parent is None or not resolve:
        try:
            fd = os.open(name, flags, dir_fd=parent)
        except OSError as error:
            if error.errno in UNAVAILABLE:
                raise Blocked("fixed procfs observation is unavailable") from error
            raise
    else:
        # Linux x86-64 SYS_openat2 and struct open_how. Default resolution uses
        # RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH.
        how = (ctypes.c_uint64 * 3)(flags, 0, resolve)
        syscall = ctypes.CDLL(None, use_errno=True).syscall
        syscall.restype = ctypes.c_long
        fd = syscall(437, parent, os.fsencode(name), ctypes.byref(how), ctypes.sizeof(how))
        if fd < 0:
            status = ctypes.get_errno()
            if status in UNAVAILABLE:
                raise Blocked("kernel refused a held procfs observation")
            raise OSError(status, "held procfs open failed")

    stack.callback(os.close, fd)
    return fd


def filesystem_magic(fd):
    # The native x86-64 struct statfs starts with signed long f_type.
    raw = (ctypes.c_long * 32)()
    call = ctypes.CDLL(None, use_errno=True).fstatfs
    call.argtypes = [ctypes.c_int, ctypes.c_void_p]
    call.restype = ctypes.c_int
    if call(fd, ctypes.byref(raw)) != 0:
        raise OSError(ctypes.get_errno(), "held filesystem observation failed")
    return raw[0]


def fd_mount(stack, fd, fdinfo, device):
    info = proc_open(stack, str(fd), fdinfo, FD_FLAGS)
    if os.fstat(info).st_dev != device:
        raise Blocked("proc fdinfo is outside the verified procfs")
    ids = re.findall(rb"(?m)^mnt_id:\s*([1-9][0-9]*)$", read_bounded(info, 8192))
    if len(ids) != 1:
        raise Blocked("missing held descriptor mount ID")
    return int(ids[0])


def proc_bytes(stack, parent, name, limit, fdinfo, proc_device, proc_mount):
    fd = proc_open(stack, name, parent, FD_FLAGS | os.O_NONBLOCK)
    node = os.fstat(fd)
    if (not stat.S_ISREG(node.st_mode) or node.st_dev != proc_device
            or fd_mount(stack, fd, fdinfo, proc_device) != proc_mount):
        raise Blocked("proc observation crossed the verified held mount")
    return read_bounded(fd, limit)


def inode(path):
    node = path.stat()
    return f"{node.st_dev}:{node.st_ino}"


def mount_row(mountinfo, mount, device):
    rows = [row.split(b" ") for row in mountinfo.splitlines()
            if row.split(b" ", 1)[0] == str(mount).encode()]
    if len(rows) != 1:
        raise Blocked("selected mount ID lacks a unique current mountinfo record")
    row = rows[0]
    try:
        separator = row.index(b"-")
        expected_device = f"{os.major(device)}:{os.minor(device)}".encode()
        valid = (row[2] == expected_device and row[3] == b"/" and b"rw" in row[5].split(b",")
                 and row[separator + 1] == b"ext4" and b"rw" in row[separator + 3].split(b","))
    except (ValueError, IndexError):
        valid = False
    if not valid:
        raise Blocked("RUNNER_TEMP is outside a writable whole local ext4 mount")
    return b" ".join(row)


def unique_mount(fd):
    # Linux x86-64 UAPI struct statx: 256 bytes, stx_mask at 0, stx_mnt_id at 144.
    mask = 0x4000
    try:
        probe = ctypes.CDLL(None, use_errno=True).statx
    except AttributeError as error:
        raise Blocked("statx is unavailable in the native runtime") from error
    probe.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p]
    probe.restype = ctypes.c_int
    raw = ctypes.create_string_buffer(256)
    if probe(fd, b"", 0x1000, mask, raw) != 0:  # AT_EMPTY_PATH; only the held descriptor.
        status = ctypes.get_errno()
        if status in UNAVAILABLE:
            raise Blocked("kernel unique mount ID is unavailable")
        raise OSError(status, "kernel held mount observation failed")
    returned = struct.unpack_from("=I", raw, 0)[0]
    identity = struct.unpack_from("=Q", raw, 144)[0]
    if not returned & mask or not identity:
        raise Blocked("kernel did not return an exact unique mount ID")
    return identity


def observe(parent, parent_fd, evidence, phase, profile=HISTORY):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise Blocked("native Linux x86-64 is required")
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise Blocked("an ordinary non-root invocation is required")
    with ExitStack() as stack:
        proc = proc_open(stack, "/proc", None, DIR_FLAGS)
        proc_node = os.fstat(proc)
        if filesystem_magic(proc) != 0x9FA0 or proc_node.st_ino != 1:
            raise Blocked("the fixed procfs root could not be verified")
        # The kernel's fixed thread-self symlink stays beneath the held procfs and
        # may cross neither mounts nor magic links (NO_XDEV | NO_MAGICLINKS | BENEATH).
        thread = proc_open(stack, "thread-self", proc, DIR_FLAGS & ~os.O_NOFOLLOW, resolve=0x0B)
        fdinfo = proc_open(stack, "fdinfo", thread, DIR_FLAGS)
        if any(os.fstat(fd).st_dev != proc_node.st_dev for fd in (thread, fdinfo)):
            raise Blocked("thread proc descriptors crossed the verified procfs")
        proc_mount = fd_mount(stack, proc, fdinfo, proc_node.st_dev)
        if any(fd_mount(stack, fd, fdinfo, proc_node.st_dev) != proc_mount
               for fd in (thread, fdinfo)):
            raise Blocked("thread proc descriptors crossed the verified proc mount")
        read = lambda scope, name, limit: proc_bytes(
            stack, scope, name, limit, fdinfo, proc_node.st_dev, proc_mount
        )
        status = read(thread, "status", 64 * 1024)
        (evidence / f"{phase}.status").write_bytes(status)
        for field in (b"CapInh", b"CapPrm", b"CapEff", b"CapAmb"):
            values = re.findall(rb"(?m)^" + field + rb":\s*([0-9a-f]+)$", status)
            if len(values) != 1 or int(values[0], 16) != 0:
                raise Blocked("fixture requires zero live inheritable, permitted, effective and ambient capabilities")
        actor = managed_actor(status, read, thread, proc, evidence, phase) if profile is MANAGED else {}
        mount = fd_mount(stack, parent_fd, fdinfo, proc_node.st_dev)
        mountinfo = read(thread, "mountinfo", 1024 * 1024)
        (evidence / f"{phase}.mountinfo").write_bytes(mountinfo)
        boot = read(proc, "sys/kernel/random/boot_id", 37).decode().strip()
        namespace_dir = proc_open(stack, "ns", thread, DIR_FLAGS)
        if fd_mount(stack, namespace_dir, fdinfo, proc_node.st_dev) != proc_mount:
            raise Blocked("namespace directory crossed the verified proc mount")
        namespaces = []
        for kind in ("mnt", "user"):
            # The two fixed proc namespace links are deliberately followed to held nsfs.
            namespace = proc_open(stack, kind, namespace_dir, FD_FLAGS & ~os.O_NOFOLLOW, resolve=0)
            if filesystem_magic(namespace) != 0x6E736673:
                raise Blocked("held namespace is outside nsfs")
            node = os.fstat(namespace)
            namespaces.append(f"{node.st_dev}:{node.st_ino}")
    held = os.fstat(parent_fd)
    named = parent.stat(follow_symlinks=False)
    require((held.st_dev, held.st_ino) == (named.st_dev, named.st_ino),
            "fixture parent identity changed")
    if filesystem_magic(parent_fd) != 0xEF53 or os.fstatvfs(parent_fd).f_flag & os.ST_RDONLY:
        raise Blocked("selected held filesystem is outside the writable ext4 family")
    row = mount_row(mountinfo, mount, held.st_dev)
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot) is not None,
            "invalid boot ID")
    unique = unique_mount(parent_fd)
    if profile is MANAGED:
        root_fd = os.open("/", DIR_FLAGS)
        try:
            if row.split(b" ")[4] != b"/" or unique_mount(root_fd) != unique:
                raise Blocked("managed fixture requires the current whole ext4 root mount")
        finally:
            os.close(root_fd)
    return {
        "boot": boot, "kernel": platform.release(), "mount": mount,
        "mount_record": row.decode("utf-8", errors="replace"),
        "mount_namespace": namespaces[0], "user_namespace": namespaces[1],
        "real_uid": os.getuid(), "effective_uid": os.geteuid(), "unique_mount": unique,
        "parent": f"{held.st_dev}:{held.st_ino}", "filesystem": "ext4", **actor,
    }


def managed_actor(status, read, thread, proc, evidence, phase):
    uid, gid = os.geteuid(), os.getegid()
    for label, real, effective in (("uid", os.getuid(), uid), ("gid", os.getgid(), gid)):
        field = re.findall(rb"(?m)^" + label.title().encode() + rb":([^\n]*)$", status)
        columns = [str(effective).encode()] * 4
        if not 0 < effective < 2**32 - 1 or real != effective or len(field) != 1 or field[0].split() != columns:
            raise Blocked("managed fixture requires one ordinary real/effective/saved/filesystem actor")
        mapping = read(thread, f"{label}_map", 4096)
        (evidence / f"{phase}.{label}_map").write_bytes(mapping)
        if (not mapping.endswith(b"\n") or mapping.count(b"\n") != 1
                or mapping.split() != [b"0", b"0", b"4294967295"]):
            raise Blocked("managed fixture requires exact full identity maps")
        sentinel = read(proc, f"sys/kernel/overflow{label}", 16)
        (evidence / f"{phase}.overflow{label}").write_bytes(sentinel)
        if re.fullmatch(rb"(0|[1-9][0-9]{0,9})\n", sentinel) is None or not int(sentinel) < 2**32:
            raise Blocked("managed fixture cannot confirm a native overflow identity")
        if int(sentinel) == effective:
            raise Blocked("managed actor aliases a native overflow identity")
    return {"real_gid": os.getgid(), "effective_gid": gid, "identity_maps": "full"}


def digest_file(file):
    file.seek(0)
    return hashlib.file_digest(file, "sha256").hexdigest()


def check_revision(revision, evidence, phase):
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "expected an exact selected revision")
    head = command(evidence, f"revision-{phase}", ["git", "rev-parse", "HEAD"]).strip()
    dirt = command(evidence, f"status-{phase}", ["git", "status", "--porcelain"])
    require(head == revision and not dirt, "qualification requires an exact clean revision")


def artifact(output, target_root, profile=HISTORY):
    paths = []
    for row in output.splitlines():
        event = json.loads(row)
        target = event.get("target", {})
        if (event.get("reason") == "compiler-artifact" and target.get("name") == profile.test
                and target.get("kind") == ["test"] and event.get("profile", {}).get("test") is True
                and event.get("manifest_path") == str(profile.package_root / "Cargo.toml")
                and target.get("src_path") == str(profile.package_root / "tests" / f"{profile.test}.rs")
                and (profile.required_feature is None
                     or event.get("features") == [profile.required_feature])
                and event.get("executable")):
            paths.append(Path(event["executable"]))
    require(len(paths) == 1, "expected exactly one matching native Cargo integration test artifact")
    path = paths[0]
    require(path.is_absolute() and path.resolve(strict=True) == path and path.is_relative_to(target_root),
            "native binary escaped private target custody")
    return path


def managed_cli_artifact(output, target_root):
    candidates = []
    for row in output.splitlines():
        event = json.loads(row)
        if (event.get("reason") == "compiler-artifact"
                and event.get("target", {}).get("name") == "exacopy"):
            candidates.append(event)
    require(len(candidates) == 1, "expected exactly one managed Cargo CLI artifact")
    event, = candidates
    target = event["target"]
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    package_id = f"path+{CLI_PACKAGE.as_uri()}#{version}"
    path = target_root / TARGET / "debug" / "exacopy"
    require(event.get("package_id") == package_id
            and event.get("manifest_path") == str(CLI_PACKAGE / "Cargo.toml")
            and target.get("src_path") == str(CLI_PACKAGE / "src/main.rs")
            and target.get("kind") == ["bin"] and target.get("crate_types") == ["bin"]
            and target.get("edition") == "2024"
            and event.get("profile", {}).get("test") is False
            and event.get("features") == [MANAGED.required_feature]
            and event.get("fresh") is False and event.get("executable") == str(path)
            and path.is_absolute() and path.resolve(strict=True) == path,
            "managed Cargo CLI artifact differs from the exact private bin target")
    return path


def executable_stamp(node):
    return (node.st_dev, node.st_ino, node.st_mode, node.st_uid, node.st_gid,
            node.st_nlink, node.st_size, node.st_mtime_ns, node.st_ctime_ns)


def held_managed_image(path, fd, limit=256 * 1024 * 1024):
    node = os.fstat(fd)
    stamp = executable_stamp(node)
    require(stat.S_ISREG(node.st_mode) and node.st_uid == os.geteuid()
            and (node.st_mode & 0o500) == 0o500 and not (node.st_mode & 0o7022)
            and node.st_nlink > 0 and 20 <= node.st_size <= limit
            and executable_stamp(path.stat(follow_symlinks=False)) == stamp,
            "managed executable identity or size differs")
    header = os.pread(fd, 20, 0)
    require(header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00",
            "expected a Linux x86-64 ELF managed image")
    digest = hashlib.sha256()
    offset = 0
    while offset < node.st_size:
        chunk = os.pread(fd, min(65536, node.st_size - offset), offset)
        require(chunk, "managed executable ended during hashed observation")
        digest.update(chunk)
        offset += len(chunk)
    require(not os.pread(fd, 1, offset)
            and executable_stamp(os.fstat(fd)) == stamp
            and executable_stamp(path.stat(follow_symlinks=False)) == stamp,
            "managed executable changed during hashed observation")
    return stamp, digest.hexdigest()


def managed_cli_environment(fd, observation):
    (device, inode, mode, _, _, _, size, _, _), digest = observation
    facts = {"dev": device, "ino": inode, "mode": stat.S_IMODE(mode), "size": size, "sha256": digest}
    environment = {f"EXACOPY_MANAGED_SYNC_CLI_{key.upper()}": str(value)
                   for key, value in {**facts, "fd": fd}.items()}
    return environment, facts


def checked_result(output, facts):
    lines = output.splitlines()
    markers = [line.removeprefix(MARKER) for line in lines if line.startswith(MARKER)]
    require(len(markers) == 1, "required one fixture result marker")
    require(sum(line.strip() == f"test {CASE} ..." for line in lines) == 1 and lines.count("ok") == 1,
            "fixture did not report exact executed case")
    require(sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                for line in lines) == 1, "fixture did not pass exactly once")
    pairs = [token.split("=", 1) for token in markers[0].split()]
    require(all(len(pair) == 2 for pair in pairs), "invalid fixture marker")
    result = dict(pairs)
    expected = {"schema_version", "boot", "mount_namespace", "user_namespace", "mount",
                "unique_mount", "parent", "left", "right", "cleanup"}
    require(len(pairs) == len(expected) and result.keys() == expected,
            "invalid fixture marker field inventory")
    require(result["schema_version"] == "1" and result["cleanup"] == "verified_absent"
            and re.fullmatch("[1-9][0-9]*", result["unique_mount"])
            and int(result["unique_mount"]) < 2**64,
            "fixture did not establish a clean unique-mount scope")
    for key in ("boot", "mount_namespace", "user_namespace", "mount", "unique_mount"):
        require(result[key] == str(facts[key]), f"fixture {key} differs from independent observation")
    directories = [result[key] for key in ("parent", "left", "right")]
    require(len(set(directories)) == 3 and all(re.fullmatch("[0-9]+:[1-9][0-9]*", value)
                                              for value in directories),
            "fixture parent and ordered siblings are not distinct")
    require(all(value.split(":")[0] == facts["parent"].split(":")[0] for value in directories),
            "fixture identities escaped the independently observed device")
    return result


def checked_statmount_result(output, code, facts, sides):
    lines = output.splitlines()
    markers = [line.removeprefix(STATMOUNT_MARKER) for line in lines if line.startswith(STATMOUNT_MARKER)]
    require(len(markers) == 1, "required one statmount result marker")
    require(sum(line.strip() == f"test {STATMOUNT.case} ..." for line in lines) == 1,
            "statmount fixture did not report its exact executed case")
    pairs = [token.split("=", 1) for token in markers[0].split()]
    require(all(len(pair) == 2 for pair in pairs), "invalid statmount result")
    status = dict(pairs)
    require(len(status) == len(pairs) and status.get("schema_version") == "1"
            and status.get("feature") == STATMOUNT.required_feature, "invalid statmount feature or schema")
    if status.get("outcome") == "blocked":
        require(code == 101 and status.keys() == {"schema_version", "outcome", "feature", "reason"}
                and status["reason"] in {"unsupported_mount_attributes", "idmapped_mount", "permission_denied"}
                and lines.count("FAILED") == 1
                and sum(line.startswith("test result: FAILED. 0 passed; 1 failed; 0 ignored;")
                        for line in lines) == 1, "invalid typed statmount blockage")
        return status
    keys = {"schema_version", "outcome", "feature", "boot", "mount_namespace", "user_namespace",
            "mount", "unique_mount", "parent", "left", "right", "idmap"}
    require(code == 0 and status.keys() == keys and status["outcome"] == "passed"
            and status["idmap"] == "clear" and lines.count("ok") == 1
            and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                    for line in lines) == 1, "statmount fixture did not pass exactly once")
    for key in ("boot", "mount_namespace", "user_namespace", "mount", "unique_mount", "parent"):
        require(status[key] == str(facts[key]), f"statmount {key} differs from independent observation")
    for side in SIDES:
        require(status[side] == sides[side], "statmount fixture sibling identity differs")
    return status


def native_object(identity):
    device, inode = map(int, identity.split(":"))
    return f"{os.major(device)}:{os.minor(device)}:{inode}"


def checked_managed_result(output, code, facts, anchors, cli_sha256):
    lines = output.splitlines()
    markers = [line.removeprefix(MANAGED_MARKER) for line in lines if line.startswith(MANAGED_MARKER)]
    require(len(markers) == 1, "required one managed production result marker")
    require(lines.count("running 1 test") == 1
            and sum(line.strip() == f"test {MANAGED.case} ..." for line in lines) == 1,
            "managed production fixture did not report its exact executed case")
    if markers[0].startswith("blocked reason="):
        reason = markers[0].removeprefix("blocked reason=")
        require(reason in {"statmount-attributes-unavailable", "idmapped-history-mount"}
                and code == 101 and lines.count("FAILED") == 1 and not lines.count("ok")
                and sum(line.startswith("test result: FAILED. 0 passed; 1 failed; 0 ignored;")
                        for line in lines) == 1, "invalid typed managed production blockage")
        return {"schema_version": 1, "outcome": "blocked", "feature": MANAGED.required_feature,
                "reason": reason}
    fields = {
        "boot": facts["boot"], "mnt_ns": native_object(facts["mount_namespace"]),
        "user_ns": native_object(facts["user_namespace"]), "mount": str(facts["mount"]),
        "unique_mount": str(facts["unique_mount"]), "anchor": native_object(facts["parent"]),
        "anchor_left": native_object(anchors["left"]), "anchor_right": native_object(anchors["right"]),
    }
    prefix = "passed " + " ".join(f"{key}={value}" for key, value in fields.items()) + " "
    device = fields["anchor"].rsplit(":", 1)[0]
    identity = rf"({re.escape(device)}:[1-9][0-9]{{0,19}})"
    require(re.fullmatch(r"[0-9a-f]{64}", cli_sha256), "invalid selected managed CLI digest")
    suffix = re.fullmatch(
        rf"live={identity} live_left={identity} live_right={identity} "
        rf"controls=8 cli_controls=15 cli_sha256={cli_sha256} cleanup=verified",
        markers[0].removeprefix(prefix),
    )
    require(markers[0].startswith(prefix) and suffix is not None and code == 0
            and lines.count("ok") == 1 and not lines.count("FAILED")
            and sum(line.startswith("test result: ok. 1 passed; 0 failed; 0 ignored;")
                    for line in lines) == 1, "managed production identity or exact passing result differs")
    live = suffix.groups()
    require(all(int(value.rsplit(":", 1)[1]) < 2**64 for value in live)
            and len({fields["anchor"], fields["anchor_left"], fields["anchor_right"], *live}) == 6,
            "reported managed live directories must be distinct on the independent anchor device")
    return {"schema_version": 1, "outcome": "passed", "feature": MANAGED.required_feature, **fields,
            **dict(zip(("live", "live_left", "live_right"), live)), "controls": 8,
            "cli_controls": 15, "cli_sha256": cli_sha256, "cleanup": "verified"}


def execute(evidence, binary, env, facts, report, profile=HISTORY, sides=None, cli=None):
    with os.fdopen(os.open(binary, FD_FLAGS | os.O_NONBLOCK), "rb", buffering=0) as held:
        node = os.fstat(held.fileno())
        require(stat.S_ISREG(node.st_mode) and node.st_mode & 0o111
                and 20 <= node.st_size <= 256 * 1024 * 1024, "invalid bounded executable")
        header = held.read(20)
        require(header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00",
                "expected a Linux x86-64 ELF test image")
        pinned = f"/proc/self/fd/{held.fileno()}"
        before_managed = held_managed_image(binary, held.fileno()) if profile is MANAGED else None
        report["executable_sha256"] = before_managed[1] if before_managed else digest_file(held)
        for label, options in (("listed", []), ("ignored", ["--ignored"])):
            listed = command(evidence, label, [binary, "--list", "--format=terse", *options],
                             env=env, executable=pinned, held=(held.fileno(),))
            require(listed.strip() == f"{profile.case}: test", "unexpected test inventory")
        args = [binary, "--ignored", "--exact", "--nocapture", "--test-threads=1",
                "--color", "never", profile.case]
        options = {"env": env, "executable": pinned, "held": (held.fileno(),), "timeout": 45}
        if profile is MANAGED:
            require(cli is not None, "managed fixture requires the exact CLI companion")
            require(held_managed_image(binary, held.fileno()) == before_managed,
                    "held managed harness changed before execution")
            with ExitStack() as stack:
                cli_fd = os.open(cli, FD_FLAGS | os.O_NONBLOCK)
                stack.callback(os.close, cli_fd)
                before_cli = held_managed_image(cli, cli_fd, MANAGED_CLI_LIMIT)
                require(before_cli[0][:2] != before_managed[0][:2],
                        "managed CLI aliases the test harness")
                cli_env, cli_facts = managed_cli_environment(cli_fd, before_cli)
                options.update(env={**env, **cli_env}, held=(held.fileno(), cli_fd))
                try:
                    output, code = command(evidence, "run", args, observe_exit=True, **options)
                finally:
                    require(held_managed_image(cli, cli_fd, MANAGED_CLI_LIMIT) == before_cli
                            and held_managed_image(binary, held.fileno()) == before_managed,
                            "held managed executable changed after execution")
                report["cli_executable"] = cli_facts
                report["case"] = checked_managed_result(output, code, facts, sides, cli_facts["sha256"])
        elif profile is STATMOUNT:
            output, code = command(evidence, "run", args, observe_exit=True, **options)
            report["case"] = checked_statmount_result(output, code, facts, sides)
        else:
            result = command(evidence, "run", args, **options)
            report["case"] = checked_result(result, facts)
        if profile is not MANAGED:
            after = binary.stat(follow_symlinks=False)
            require((node.st_dev, node.st_ino) == (after.st_dev, after.st_ino)
                    and report["executable_sha256"] == digest_file(held),
                    "held executable or exact name changed")


def manifest_digest(profile=HISTORY):
    raw = profile.definition.read_bytes()
    actual = tomllib.loads(raw.decode())
    expected = {
        "schema_version": 1, "id": profile.id, "target": TARGET,
        "profile": profile.profile, "rust_toolchain": TOOLCHAIN,
        "runner": profile.definition.with_name("run.py").relative_to(profile.package_root).as_posix(),
        "controls": profile.definition.with_name("test_runner.py").relative_to(profile.package_root).as_posix(),
        "workflow": profile.workflow, "result": "result.json",
        "case": [{"kind": "rust-integration", "test_target": profile.test, "selector": profile.case,
                  "source": f"tests/{profile.test}.rs", "ignored": True}],
    }
    if profile.required_feature is not None:
        expected["case"][0]["required_feature"] = profile.required_feature
    require(actual == expected and type(actual["schema_version"]) is int
            and actual["case"][0]["ignored"] is True, "exact native fixture manifest drift")
    return hashlib.sha256(raw).hexdigest()


def sibling_facts(parent_fd, held, parent_facts, profile=STATMOUNT):
    result = {}
    for side, fd in held.items():
        node = os.fstat(fd)
        named = os.stat(side, dir_fd=parent_fd, follow_symlinks=False)
        identity = f"{node.st_dev}:{node.st_ino}"
        require((node.st_dev, node.st_ino) == (named.st_dev, named.st_ino)
                and stat.S_ISDIR(node.st_mode) and stat.S_IMODE(node.st_mode) == 0o700
                and node.st_uid == os.geteuid() and not os.listdir(fd)
                and (profile is not MANAGED or node.st_gid == os.getegid())
                and unique_mount(fd) == parent_facts["unique_mount"],
                "held managed admission anchor changed" if profile is MANAGED else "held statmount sibling changed")
        result[side] = identity
    require(len({parent_facts["parent"], *result.values()}) == len(result) + 1,
            "managed admission anchors must have distinct identities" if profile is MANAGED
            else "statmount siblings must have distinct identities")
    return result


def qualify(revision, temp, evidence, report, profile=HISTORY):
    check_revision(revision, evidence, "before")
    report["fixture_manifest_sha256"] = manifest_digest(profile)
    parent_fd = os.open(temp, DIR_FLAGS)
    try:
        node = os.fstat(parent_fd)
        if node.st_uid != os.geteuid() or node.st_mode & 0o022:
            raise Blocked("RUNNER_TEMP must be held, owned and protected")
        report["substrate"] = observe(temp, parent_fd, evidence, "before", profile)
    finally:
        os.close(parent_fd)
    rustc = command(evidence, "rustc", ["rustc", f"+{TOOLCHAIN}", "-vV"]).splitlines()
    require(f"host: {TARGET}" in rustc and f"release: {TOOLCHAIN}" in rustc,
            "unexpected native Rust compiler")
    lock = ROOT / "Cargo.lock"
    report["lockfile_sha256"] = hashlib.sha256(lock.read_bytes()).hexdigest()
    require(not supervision.CANCELLATION_REQUESTED, "cancelled before work allocation")
    work_prefix = "exacopy-managed-sync-work-" if profile is MANAGED else "exacopy-sync-ext4-work-"
    work = Path(tempfile.mkdtemp(prefix=work_prefix, dir=temp))
    work_identity = inode(work)
    report["cleanup"] = "pending"
    parent = work / "fixture"
    parent_identity = None
    held_sides = {}
    report["owned_work_basename"] = work.name
    try:
        require(not supervision.CANCELLATION_REQUESTED, "cancelled before fixture allocation")
        parent.mkdir(mode=0o700)
        parent_fd = os.open(parent, DIR_FLAGS)
        try:
            parent_identity = inode(parent)
            before = observe(parent, parent_fd, evidence, "fixture-before", profile)
            require(stat.S_IMODE(os.fstat(parent_fd).st_mode) == 0o700 and not any(parent.iterdir()),
                    "private fixture parent is unavailable or occupied")
            anchored = profile is STATMOUNT or profile is MANAGED
            if profile is MANAGED:
                fixture = os.fstat(parent_fd)
                require(fixture.st_uid == os.geteuid() and fixture.st_gid == os.getegid(),
                        "fixture parent ownership differs from the managed actor")
            if anchored:
                for side in SIDES:
                    os.mkdir(side, mode=0o700, dir_fd=parent_fd)
                    held_sides[side] = os.open(side, DIR_FLAGS, dir_fd=parent_fd)
            before_sides = sibling_facts(parent_fd, held_sides, before, profile) if anchored else None
            target_root = work / "target"
            overrides = {"RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
                         "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTFLAGS",
                         "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
                         "LD_PRELOAD", "LD_LIBRARY_PATH"}
            require(not any(os.environ.get(name) for name in overrides), "compiler override present")
            env = {
                **os.environ, "CARGO_TARGET_DIR": str(target_root), "CARGO_BUILD_BUILD_DIR": str(target_root),
                "CARGO_INCREMENTAL": "0", "CARGO_PROFILE_TEST_DEBUG": "0", "LC_ALL": "C",
                "TMPDIR": str(work),
            }
            args = ["cargo", f"+{TOOLCHAIN}", "test", "--locked", "--offline", "--jobs", "2",
                    "--target", TARGET, "-p", profile.package_root.name, "--test", profile.test,
                    "--no-run", "--message-format=json"]
            if profile is MANAGED:
                args.append("--no-default-features")
            if profile.required_feature is not None:
                args.extend(("--features", profile.required_feature))
            output = command(evidence, "cargo", args, env=env, timeout=900)
            child_env = {
                "PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(work),
                profile.parent_variable: str(parent),
            }
            cli = managed_cli_artifact(output, target_root) if profile is MANAGED else None
            execute(evidence, artifact(output, target_root, profile), child_env, before, report,
                    profile, before_sides, cli)
            try:
                after = observe(parent, parent_fd, evidence, "fixture-after", profile)
            except Blocked as error:
                raise ValueError("native fixture substrate unavailable after execution") from error
            require(after == before, "native fixture substrate changed")
            report["fixture_substrate"] = before
            if anchored:
                managed = profile is MANAGED
                require(before_sides == sibling_facts(parent_fd, held_sides, after, profile),
                        "managed admission anchor custody changed" if managed
                        else "native statmount sibling custody changed")
                report["fixture_anchors" if managed else "fixture_siblings"] = before_sides
            check_revision(revision, evidence, "after")
            require(manifest_digest(profile) == report["fixture_manifest_sha256"], "fixture manifest changed")
            require(hashlib.sha256(lock.read_bytes()).hexdigest() == report["lockfile_sha256"],
                    "lockfile changed")
            if anchored and report["case"].get("outcome") == "blocked":
                raise Blocked(report["case"]["reason"])
        finally:
            os.close(parent_fd)
    finally:
        try:
            terminal = {"not_started", "verified_absent", "verified_absent_after_failure"}
            require(all(path.read_text().strip() in terminal for path in evidence.glob("*.drain")),
                    "owned process drain is unconfirmed; retain private tree")
            require(work.resolve() == work and inode(work) == work_identity,
                    "private work identity changed; retain all entries")
            require(parent_identity is not None and parent.is_dir() and parent.resolve() == parent
                    and inode(parent) == parent_identity, "fixture cleanup unconfirmed; retain private tree")
            cleanup_siblings(parent, held_sides, parent_identity)
            require(not any(parent.iterdir()), "fixture is occupied; retain private tree")
            parent.rmdir()
            shutil.rmtree(work)
            require(not os.path.lexists(work), "private build cleanup unconfirmed")
            report["cleanup"] = "verified_absent"
        finally:
            for fd in held_sides.values():
                os.close(fd)


def cleanup_siblings(parent, held, parent_identity):
    if not held:
        return
    directory = os.open(parent, DIR_FLAGS)
    try:
        original = os.fstat(directory)
        require(f"{original.st_dev}:{original.st_ino}" == parent_identity,
                "cleanup parent is outside held custody")
        require(set(os.listdir(directory)) == set(held), "unexpected names; retain fixture")
        for side, fd in held.items():
            node = os.fstat(fd)
            named = os.stat(side, dir_fd=directory, follow_symlinks=False)
            require((node.st_dev, node.st_ino) == (named.st_dev, named.st_ino)
                    and stat.S_ISDIR(named.st_mode) and not os.listdir(fd),
                    "sibling cleanup custody changed")
        for side in held:
            os.rmdir(side, dir_fd=directory)
    finally:
        os.close(directory)


def main(profile=HISTORY):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    raw = Path(os.environ["RUNNER_TEMP"])
    require(raw.is_absolute() and raw.resolve(strict=True) == raw, "invalid exact RUNNER_TEMP")
    prefixes = {
        MANAGED: "exacopy-managed-sync-production-evidence-",
        STATMOUNT: "exacopy-sync-ext4-statmount-evidence-",
        HISTORY: "exacopy-sync-ext4-evidence-",
    }
    prefix = prefixes[profile]
    evidence = Path(tempfile.mkdtemp(prefix=prefix, dir=raw))
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path is not None:
        require("\n" not in str(evidence) and "\r" not in str(evidence), "invalid evidence output path")
        with open(output_path, "a", encoding="utf-8") as output:
            output.write(f"evidence_path={evidence}\n")
    report = {"revision": args.revision, "profile": profile.profile, "outcome": "failed", "cleanup": "not_created"}
    code = 1
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, supervision.interrupted)
    try:
        qualify(args.revision, raw, evidence, report, profile)
    except Blocked as error:
        report.update(outcome="blocked", reason=str(error))
        code = 77
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["reason"] = str(error)
    else:
        if supervision.CANCELLATION_REQUESTED:
            report["reason"] = "native runner cancelled"
        else:
            report["outcome"] = "pass"
            code = 0
    finally:
        with (evidence / "result.json").open("x", encoding="utf-8") as result:
            result.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
