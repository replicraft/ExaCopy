"""Closed privileged half of the hosted protected-slot fixture."""

import ctypes
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import sys

ROOT = Path("/run/exacopy-protected-root-v1")
TREE = ROOT / "fixture"
INBOX = ROOT / "inbox"
OBSERVER_ID = 1001
CGROUP = "0::/system.slice/exacopy-protected-root-v1.service"
SELECTOR = "linux::protected_slot::tests::mount::refuses_same_device_bind_mount_at_the_selected_name"
MAX_BINARY = 256 * 1024 * 1024
CLONE_NEWNS = 0x00020000
MS_BIND, MS_REC, MS_PRIVATE = 4096, 16384, 1 << 18
PR_CAPBSET_DROP, PR_SET_NO_NEW_PRIVS, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 24, 38, 47, 4
LIBC = ctypes.CDLL(None, use_errno=True)


class CapabilityHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class CapabilityWord(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in ("effective", "permitted", "inheritable")]


def checked(result, label):
    if result != 0:
        raise OSError(ctypes.get_errno(), label)


def fixed_directory(path, uid, mode):
    node = path.lstat()
    if (not stat.S_ISDIR(node.st_mode) or node.st_uid != uid
            or node.st_gid != uid or stat.S_IMODE(node.st_mode) != mode):
        raise RuntimeError(f"unexpected directory custody: {path}")


def namespace():
    return os.readlink("/proc/self/ns/mnt")


def custody():
    cgroup = Path("/proc/self/cgroup").read_text().splitlines()
    invocation = os.environ.get("INVOCATION_ID", "")
    if cgroup != [CGROUP] or re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
        raise RuntimeError("unexpected systemd invocation or cgroup")
    return {"cgroup": CGROUP, "invocation": invocation}


def mount(source, target, flags):
    source = None if source is None else os.fsencode(source)
    checked(LIBC.mount(source, os.fsencode(target), None, ctypes.c_ulong(flags), None), "fixed mount")


def output(role, **facts):
    print(json.dumps({"role": role, **facts}, sort_keys=True), flush=True)


def drop_observer():
    os.setgroups([])
    last_cap = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
    if not 0 <= last_cap < 64:
        raise RuntimeError("unexpected capability ABI")
    for cap in range(last_cap + 1):
        checked(LIBC.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0), "drop bounding capability")
    checked(LIBC.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0), "clear ambient capabilities")
    os.setresgid(OBSERVER_ID, OBSERVER_ID, OBSERVER_ID)
    os.setresuid(OBSERVER_ID, OBSERVER_ID, OBSERVER_ID)
    header = CapabilityHeader(0x20080522, 0)  # Linux capability ABI v3, current thread.
    zero = (CapabilityWord * 2)()
    checked(LIBC.capset(ctypes.byref(header), ctypes.byref(zero)), "clear all capability sets")
    checked(LIBC.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "set no-new-privileges")
    fields = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    ids = [OBSERVER_ID] * 4
    caps = {key: int(fields[key], 16) for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
    uids = list(map(int, fields["Uid"].split()))
    gids = list(map(int, fields["Gid"].split()))
    groups = list(map(int, fields["Groups"].split()))
    nnp = int(fields["NoNewPrivs"])
    if uids != ids or gids != ids or groups or any(caps.values()) or nnp != 1:
        raise RuntimeError("observer retained privilege")
    return {"uids": uids, "gids": gids, "groups": groups, "caps": caps, "no_new_privs": nnp}


def exec_observer():
    credentials = drop_observer()
    fixed_directory(INBOX, OBSERVER_ID, 0o700)
    source = os.open(INBOX / "observer", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    pinned = os.memfd_create("protected-slot-observer", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    with os.fdopen(source, "rb") as input_file, os.fdopen(os.dup(pinned), "wb") as output_file:
        node = os.fstat(input_file.fileno())
        if (not stat.S_ISREG(node.st_mode) or node.st_uid != OBSERVER_ID
                or node.st_nlink != 1 or not 0 < node.st_size <= MAX_BINARY):
            raise RuntimeError("invalid observer input")
        remaining = node.st_size
        while remaining:
            chunk = input_file.read(min(remaining, 65536))
            if not chunk:
                raise RuntimeError("observer changed length")
            output_file.write(chunk)
            remaining -= len(chunk)
        if input_file.read(1):
            raise RuntimeError("observer changed length")
    os.fchmod(pinned, 0o500)
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    fcntl.fcntl(pinned, fcntl.F_ADD_SEALS, seals)
    if fcntl.fcntl(pinned, fcntl.F_GET_SEALS) != seals:
        raise RuntimeError("observer executable was not sealed")
    os.lseek(pinned, 0, os.SEEK_SET)
    with os.fdopen(os.dup(pinned), "rb") as frozen:
        digest = hashlib.file_digest(frozen, "sha256").hexdigest()
    output("observer", namespace=namespace(), sha256=digest, **credentials, **custody())
    args = ["protected-slot-observer", SELECTOR, "--exact", "--ignored", "--color", "never", "--test-threads=1"]
    os.execve(pinned, args, {"LANG": "C", "EXACOPY_PROTECTED_SLOT_MOUNT_FIXTURE": str(TREE)})


def run():
    if len(sys.argv) != 1 or os.getresuid() != (0, 0, 0) or os.getcwd() != "/":
        raise RuntimeError("root fixture requires the installed closed service")
    fixed_directory(Path("/run"), 0, 0o755)
    fixed_directory(ROOT, 0, 0o755)
    trusted_service = custody()
    previous = namespace()
    checked(LIBC.unshare(CLONE_NEWNS), "create private mount namespace")
    current = namespace()
    if previous == current:
        raise RuntimeError("mount namespace did not change")
    mount(None, "/", MS_REC | MS_PRIVATE)
    output("setup", uid=0, prior_namespace=previous, namespace=current, **trusted_service)
    TREE.mkdir(mode=0o755)
    parent = TREE / "parent"
    source = TREE / "source"
    target = parent / "selected"
    parent.mkdir(mode=0o755)
    sentinels = ((source, b"source"), (target, b"underlying"))
    held = {}
    for path, payload in sentinels:
        with path.open("xb") as file:
            file.write(payload)
            initial = os.fstat(file.fileno())
            held[path] = (initial.st_dev, initial.st_ino)
        path.chmod(0o444)
    mount(source, target, MS_BIND)
    try:
        child = os.fork()
        if child == 0:
            try:
                exec_observer()
            except BaseException as error:
                print(f"observer: {error}", file=sys.stderr, flush=True)
            os._exit(125)
        _, status = os.waitpid(child, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError("observer did not exit successfully")
    finally:
        checked(LIBC.umount2(os.fsencode(target), 0), "unmount sentinel")
        fixed_directory(TREE, 0, 0o755)
        fixed_directory(parent, 0, 0o755)
        for path, expected in sentinels:
            node = path.lstat()
            if (not stat.S_ISREG(node.st_mode) or (node.st_dev, node.st_ino) != held[path]
                    or node.st_uid != 0 or node.st_gid != 0 or node.st_nlink != 1
                    or node.st_size != len(expected) or path.read_bytes() != expected):
                raise RuntimeError("sentinel or covered inode changed; retain fixture")
        output("unmount", covered_inode_preserved=True, sentinels_preserved=True)
        for path, _ in sentinels:
            path.unlink()
        parent.rmdir()
        TREE.rmdir()
        output("fixture_cleanup", absent=not os.path.lexists(TREE))


if __name__ == "__main__":
    run()
