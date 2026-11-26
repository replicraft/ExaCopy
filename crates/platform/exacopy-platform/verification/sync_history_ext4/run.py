"""Qualify one held historical-location and member fixture on a native Linux host."""

import argparse
from contextlib import ExitStack
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
TARGET = "x86_64-unknown-linux-gnu"
TOOLCHAIN = "1.100.0"
TEST = "linux_sync_history_ext4"
CASE = "held_ext4_history_scope_and_named_members_refuse_aliases_and_swaps"
FIXTURE = Path(__file__).with_name("fixture.toml")
PROFILE = "linux-unprivileged-whole-ext4-sync-history-v1"
MARKER = "EXACOPY_SYNC_HISTORY_EXT4_RESULT "
OUTPUT_LIMIT = 8 * 1024 * 1024
FD_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
DIR_FLAGS = FD_FLAGS | os.O_DIRECTORY
UNAVAILABLE = {errno.ENOENT, errno.ENODEV, errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP,
               errno.ELOOP, errno.EXDEV, errno.EACCES, errno.EPERM}


class Blocked(RuntimeError):
    """An independently observed host prerequisite is unavailable."""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(evidence, label, args, *, env=None, held=(), executable=None, timeout=20):
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


def observe(parent, parent_fd, evidence, phase):
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
    return {
        "boot": boot, "kernel": platform.release(), "mount": mount,
        "mount_record": row.decode("utf-8", errors="replace"),
        "mount_namespace": namespaces[0], "user_namespace": namespaces[1],
        "real_uid": os.getuid(), "effective_uid": os.geteuid(), "unique_mount": unique_mount(parent_fd),
        "parent": f"{held.st_dev}:{held.st_ino}", "filesystem": "ext4",
    }


def digest_file(file):
    file.seek(0)
    return hashlib.file_digest(file, "sha256").hexdigest()


def check_revision(revision, evidence, phase):
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "expected an exact selected revision")
    head = command(evidence, f"revision-{phase}", ["git", "rev-parse", "HEAD"]).strip()
    dirt = command(evidence, f"status-{phase}", ["git", "status", "--porcelain"])
    require(head == revision and not dirt, "qualification requires an exact clean revision")


def artifact(output, target_root):
    paths = []
    for row in output.splitlines():
        event = json.loads(row)
        target = event.get("target", {})
        if (event.get("reason") == "compiler-artifact" and target.get("name") == TEST
                and target.get("kind") == ["test"] and event.get("profile", {}).get("test") is True
                and event.get("manifest_path") == str(PACKAGE / "Cargo.toml")
                and target.get("src_path") == str(PACKAGE / "tests" / f"{TEST}.rs")
                and event.get("executable")):
            paths.append(Path(event["executable"]))
    require(len(paths) == 1, "expected exactly one matching native Cargo integration test artifact")
    path = paths[0]
    require(path.is_absolute() and path.resolve(strict=True) == path and path.is_relative_to(target_root),
            "native binary escaped private target custody")
    return path


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


def execute(evidence, binary, env, facts, report):
    with os.fdopen(os.open(binary, FD_FLAGS | os.O_NONBLOCK), "rb", buffering=0) as held:
        node = os.fstat(held.fileno())
        require(stat.S_ISREG(node.st_mode) and node.st_mode & 0o111
                and 20 <= node.st_size <= 256 * 1024 * 1024, "invalid bounded executable")
        header = held.read(20)
        require(header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00",
                "expected a Linux x86-64 ELF test image")
        pinned = f"/proc/self/fd/{held.fileno()}"
        report["executable_sha256"] = digest_file(held)
        for label, options in (("listed", []), ("ignored", ["--ignored"])):
            listed = command(evidence, label, [binary, "--list", "--format=terse", *options],
                             env=env, executable=pinned, held=(held.fileno(),))
            require(listed.strip() == f"{CASE}: test", "unexpected test inventory")
        result = command(evidence, "run", [
            binary, "--ignored", "--exact", "--nocapture", "--test-threads=1", "--color", "never", CASE,
        ], env=env, executable=pinned, held=(held.fileno(),), timeout=45)
        report["case"] = checked_result(result, facts)
        after = binary.stat(follow_symlinks=False)
        require((node.st_dev, node.st_ino) == (after.st_dev, after.st_ino)
                and report["executable_sha256"] == digest_file(held),
                "held executable or exact name changed")


def manifest_digest():
    raw = FIXTURE.read_bytes()
    actual = tomllib.loads(raw.decode())
    expected = {
        "schema_version": 1, "id": "linux-sync-history-ext4", "target": TARGET,
        "profile": PROFILE, "rust_toolchain": TOOLCHAIN,
        "runner": "verification/sync_history_ext4/run.py",
        "controls": "verification/sync_history_ext4/test_runner.py",
        "workflow": ".github/workflows/linux-sync-history-ext4-qualification.yml",
        "result": "result.json",
        "case": [{"kind": "rust-integration", "test_target": TEST, "selector": CASE,
                  "source": f"tests/{TEST}.rs", "ignored": True}],
    }
    require(actual == expected and type(actual["schema_version"]) is int
            and actual["case"][0]["ignored"] is True, "exact native fixture manifest drift")
    return hashlib.sha256(raw).hexdigest()


def qualify(revision, temp, evidence, report):
    check_revision(revision, evidence, "before")
    report["fixture_manifest_sha256"] = manifest_digest()
    parent_fd = os.open(temp, DIR_FLAGS)
    try:
        node = os.fstat(parent_fd)
        if node.st_uid != os.geteuid() or node.st_mode & 0o022:
            raise Blocked("RUNNER_TEMP must be held, owned and protected")
        report["substrate"] = observe(temp, parent_fd, evidence, "before")
    finally:
        os.close(parent_fd)
    rustc = command(evidence, "rustc", ["rustc", f"+{TOOLCHAIN}", "-vV"]).splitlines()
    require(f"host: {TARGET}" in rustc and f"release: {TOOLCHAIN}" in rustc,
            "unexpected native Rust compiler")
    lock = ROOT / "Cargo.lock"
    report["lockfile_sha256"] = hashlib.sha256(lock.read_bytes()).hexdigest()
    require(not supervision.CANCELLATION_REQUESTED, "cancelled before work allocation")
    work = Path(tempfile.mkdtemp(prefix="exacopy-sync-ext4-work-", dir=temp))
    work_identity = inode(work)
    report["cleanup"] = "pending"
    parent = work / "fixture"
    parent_identity = None
    report["owned_work_basename"] = work.name
    try:
        require(not supervision.CANCELLATION_REQUESTED, "cancelled before fixture allocation")
        parent.mkdir(mode=0o700)
        parent_fd = os.open(parent, DIR_FLAGS)
        try:
            parent_identity = inode(parent)
            before = observe(parent, parent_fd, evidence, "fixture-before")
            require(stat.S_IMODE(os.fstat(parent_fd).st_mode) == 0o700 and not any(parent.iterdir()),
                    "private fixture parent is unavailable or occupied")
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
            output = command(evidence, "cargo", [
                "cargo", f"+{TOOLCHAIN}", "test", "--locked", "--offline", "--jobs", "2",
                "--target", TARGET, "-p", "exacopy-platform", "--test", TEST,
                "--no-run", "--message-format=json",
            ], env=env, timeout=900)
            child_env = {
                "PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(work),
                "EXACOPY_SYNC_HISTORY_EXT4_PARENT": str(parent),
            }
            execute(evidence, artifact(output, target_root), child_env, before, report)
            try:
                after = observe(parent, parent_fd, evidence, "fixture-after")
            except Blocked as error:
                raise ValueError("native fixture substrate unavailable after execution") from error
            require(after == before, "native fixture substrate changed")
            report["fixture_substrate"] = before
            check_revision(revision, evidence, "after")
            require(manifest_digest() == report["fixture_manifest_sha256"], "fixture manifest changed")
            require(hashlib.sha256(lock.read_bytes()).hexdigest() == report["lockfile_sha256"],
                    "lockfile changed")
        finally:
            os.close(parent_fd)
    finally:
        terminal = {"not_started", "verified_absent", "verified_absent_after_failure"}
        require(all(path.read_text().strip() in terminal for path in evidence.glob("*.drain")),
                "owned process drain is unconfirmed; retain private tree")
        require(work.resolve() == work and inode(work) == work_identity,
                "private work identity changed; retain all entries")
        require(parent_identity is not None and parent.is_dir() and parent.resolve() == parent
                and inode(parent) == parent_identity and not any(parent.iterdir()),
                "fixture cleanup unconfirmed; retain private tree")
        parent.rmdir()
        shutil.rmtree(work)
        require(not os.path.lexists(work), "private build cleanup unconfirmed")
        report["cleanup"] = "verified_absent"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    raw = Path(os.environ["RUNNER_TEMP"])
    require(raw.is_absolute() and raw.resolve(strict=True) == raw, "invalid exact RUNNER_TEMP")
    evidence = Path(tempfile.mkdtemp(prefix="exacopy-sync-ext4-evidence-", dir=raw))
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path is not None:
        require("\n" not in str(evidence) and "\r" not in str(evidence), "invalid evidence output path")
        with open(output_path, "a", encoding="utf-8") as output:
            output.write(f"evidence_path={evidence}\n")
    report = {"revision": args.revision, "profile": PROFILE, "outcome": "failed", "cleanup": "not_created"}
    code = 1
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, supervision.interrupted)
    try:
        qualify(args.revision, raw, evidence, report)
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
