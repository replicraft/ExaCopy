#!/usr/bin/env python3
"""Record the hosted kernel WireGuard provider without activating it."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
from typing import NamedTuple
from uuid import UUID


SCHEMA = "exacopy.hosted-wireguard-provider-observation.v1"
REPORT = "exacopy-kernel-wireguard-provider"
DPKG_QUERY = "/usr/bin/dpkg-query"
MODULE = Path("kernel/drivers/net/wireguard/wireguard.ko")
KERNEL_RELEASE = re.compile(r"(?P<base>[0-9]+\.[0-9]+\.[0-9]+-[0-9]+)-(?:azure|aws)")
KERNEL_BUILD = re.compile(r"#(?P<build>[0-9]+(?:~[0-9]+\.[0-9]+\.[0-9]+)?)-Ubuntu .{1,180}")
MAX_METADATA = 2 * 1024 * 1024
MAX_MODULE = 4 * 1024 * 1024
PACKAGE_QUERY_BYTES = 4096
PACKAGE_QUERY_SECONDS = 5
PACKAGE_REAP_SECONDS = 2
TOOLS = {
    "ip": ("/usr/sbin/ip",),
    "ss": ("/usr/bin/ss", "/usr/sbin/ss"),
    "nsenter": ("/usr/bin/nsenter",),
    "unshare": ("/usr/bin/unshare",),
    "setpriv": ("/usr/bin/setpriv",),
    "findmnt": ("/usr/bin/findmnt",),
    "systemctl": ("/usr/bin/systemctl",),
    "systemd-run": ("/usr/bin/systemd-run",),
    "mount": ("/usr/bin/mount",),
    "umount": ("/usr/bin/umount",),
    "wg": ("/usr/bin/wg",),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def kernel_package_version(release, build):
    base = KERNEL_RELEASE.fullmatch(release)
    stamp = KERNEL_BUILD.fullmatch(build)
    if base is None or stamp is None:
        return None
    return f"{base['base']}.{stamp['build']}"


def config_selection(data):
    candidates = [
        line for line in data.splitlines()
        if line == b"# CONFIG_WIREGUARD is not set" or line.startswith(b"CONFIG_WIREGUARD=")
    ]
    return {
        (b"CONFIG_WIREGUARD=y",): "built-in",
        (b"CONFIG_WIREGUARD=m",): "module",
        (b"# CONFIG_WIREGUARD is not set",): "disabled",
    }.get(tuple(candidates), "unknown")


def builtin_selection(data, release):
    accepted = {bytes(MODULE), bytes(Path("/lib/modules") / release / MODULE)}
    count = sum(line in accepted for line in data.splitlines())
    return {0: "absent", 1: "present"}.get(count, "unknown")


def module_listing(data):
    rows = [parts for line in data.splitlines() if (parts := line.split()) and parts[0] == b"wireguard"]
    if not rows:
        return "absent"
    if len(rows) != 1 or len(rows[0]) < 6 or not rows[0][1].isdigit() or not rows[0][2].isdigit():
        return "unknown"
    return {b"Live": "live", b"Loading": "transitional", b"Unloading": "transitional"}.get(
        rows[0][4], "unknown",
    )


class ProviderFacts(NamedTuple):
    config: str
    builtin: str
    module: str
    initstate: str
    installed: str


def classify(facts):
    if facts.module == facts.initstate == "live":
        consistent = facts.config not in {"built-in", "disabled"} and facts.builtin != "present"
        return "already-live" if consistent else "unknown"
    if facts.module != "absent" or facts.initstate != "absent":
        return "unknown"
    if facts.config == "built-in" and facts.builtin == "present" and facts.installed == "absent":
        return "built-in"
    if facts.config == "module" and facts.builtin == "absent" and facts.installed == "packaged":
        return "packaged-but-unloaded"
    if facts.config in {"disabled", "module"} and facts.builtin == facts.installed == "absent":
        return "absent"
    return "unknown"


def read_root_file(path, maximum):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("untrusted file ownership")
        data = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        if len(data) > maximum or (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns
        ) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise ValueError("observation exceeded its bound or changed")
        return data


def read_observation(path, maximum, parse):
    try:
        data = read_root_file(path, maximum)
    except FileNotFoundError:
        return {"status": "missing"}
    except (OSError, ValueError):
        return {"status": "unknown"}
    return {"status": parse(data), "sha256": digest(data)}


def dpkg_query(*arguments):
    command = [DPKG_QUERY, *arguments]
    deadline = time.monotonic() + PACKAGE_QUERY_SECONDS
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"},
    )
    try:
        data = bytearray()
        with selectors.DefaultSelector() as readiness:
            readiness.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not readiness.select(remaining):
                    raise subprocess.TimeoutExpired(command, PACKAGE_QUERY_SECONDS)
                chunk = os.read(process.stdout.fileno(), PACKAGE_QUERY_BYTES + 1 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > PACKAGE_QUERY_BYTES:
                    raise ValueError("package query output exceeds its bound")
        result = process.wait(timeout=max(0, deadline - time.monotonic()))
        if result != 0:
            raise subprocess.CalledProcessError(result, command)
        if not data:
            raise ValueError("unavailable package record")
        return data.decode("ascii").splitlines()
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=PACKAGE_REAP_SECONDS)
            except subprocess.TimeoutExpired as error:
                # An unconfirmed child stops the report rather than causing
                # another package query from the classifier.
                raise RuntimeError("cannot confirm package query exit") from error


def package_owner(path, release, version):
    if version is None:
        return None
    try:
        lines = dpkg_query("--search", "--", str(path))
        if len(lines) != 1:
            return None
        package, separator, named = lines[0].partition(": ")
        if not separator or named != str(path):
            return None
        allowed = {
            f"{prefix}-{release}" for prefix in (
                "linux-image", "linux-image-unsigned", "linux-modules", "linux-modules-extra",
            )
        }
        if package not in allowed and package not in {f"{name}:amd64" for name in allowed}:
            return None
        installed = dpkg_query("--show", "--showformat=${Status}\\t${Version}\\t${Architecture}\\n", "--", package)
        if installed != [f"install ok installed\t{version}\tamd64"]:
            return None
        return {"package": package, "version": version, "architecture": "amd64"}
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def from_kernel_package(path, release, version, maximum, parse):
    observed = read_observation(path, maximum, parse)
    if observed["status"] in {"missing", "unknown"}:
        return observed
    # Ubuntu's usrmerge can store package paths with either original spelling.
    package = package_owner(path, release, version)
    if package is None and path.is_relative_to("/lib"):
        package = package_owner(Path("/usr") / path.relative_to("/"), release, version)
    if package is None:
        return {"status": "unknown", "sha256": observed["sha256"]}
    return observed | package


def installed_module(root, release, version):
    paths = []
    for ext in ("", ".zst", ".xz", ".gz"):
        path = root / (str(MODULE) + ext)
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return {"status": "unknown"}
        paths.append(path)
    if not paths:
        return {"status": "absent"}
    if len(paths) != 1:
        return {"status": "unknown"}
    return from_kernel_package(paths[0], release, version, MAX_MODULE, lambda _: "packaged")


def observe_provider(release, build):
    version = kernel_package_version(release, build)
    root = Path("/lib/modules") / release
    first = read_observation(Path("/proc/modules"), MAX_METADATA, module_listing)
    image = package_owner(Path("/boot") / f"vmlinuz-{release}", release, version)
    # Exact package owners must match the booted Ubuntu build independently.
    if image is None:
        version = None
    config = from_kernel_package(Path("/boot") / f"config-{release}", release, version, MAX_METADATA, config_selection)
    builtin = from_kernel_package(root / "modules.builtin", release, version, MAX_METADATA, lambda data: builtin_selection(data, release))
    installed = installed_module(root, release, version)
    initstate = read_observation(
        Path("/sys/module/wireguard/initstate"), 64,
        lambda data: {b"live\n": "live", b"coming\n": "transitional", b"going\n": "transitional"}.get(data, "unknown"),
    )
    final = read_observation(Path("/proc/modules"), MAX_METADATA, module_listing)
    module_status = final["status"] if first["status"] == final["status"] else "unknown"
    facts = ProviderFacts(
        config["status"], builtin["status"], module_status,
        "absent" if initstate["status"] == "missing" else initstate["status"], installed["status"],
    )
    return classify(facts), {
        "booted_kernel_package": image,
        "config": config, "builtin_inventory": builtin, "module_file": installed,
        "module_listing_before": first, "module_listing_after": final, "module_initstate": initstate,
    }


def namespace_identity(kind):
    try:
        path = Path(f"/proc/self/ns/{kind}")
        before = path.stat()
        target = os.readlink(path)
        after = path.stat()
        if target == f"{kind}:[{before.st_ino}]" and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino):
            return {"device": before.st_dev, "inode": before.st_ino}
    except OSError:
        pass
    return None


def tool_status(paths):
    for path in map(Path, paths):
        try:
            details = path.stat()
            if (
                stat.S_ISREG(details.st_mode) and details.st_uid == 0
                and not details.st_mode & 0o022 and os.access(path, os.X_OK)
            ):
                return {"path": str(path), "status": "observed"}
        except OSError:
            continue
    return {"status": "unavailable"}


def boot_id():
    try:
        value = UUID(read_root_file("/proc/sys/kernel/random/boot_id", 64).decode("ascii").strip())
        return str(value) if value.int else None
    except (OSError, ValueError):
        return None


def hosted_admission():
    env = os.environ
    uid = os.geteuid()
    if (
        sys.platform != "linux" or uid == 0 or os.getuid() != uid or os.getegid() != os.getgid()
        or env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or env.get("RUNNER_OS") != "Linux" or env.get("RUNNER_ARCH") != "X64"
        or env.get("GITHUB_SERVER_URL") != "https://github.com"
        or env.get("GITHUB_REPOSITORY", "").lower() != "replicraft/exacopy"
        or env.get("GITHUB_REF") != "refs/heads/main" or env.get("GITHUB_EVENT_NAME") != "push"
        or "EXACOPY_REMOTE_DEPLOYMENT" in env or len(sys.argv) != 1
        or not re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", ""))
    ):
        raise ValueError("provider observation requires the canonical Ubuntu main push job")
    release = read_root_file("/usr/lib/os-release", 8192)
    if not {b"ID=ubuntu", b'VERSION_ID="24.04"'} <= set(release.splitlines()):
        raise ValueError("the hosted provider observation requires Ubuntu 24.04")
    parent = Path(env["RUNNER_TEMP"])
    if not parent.is_absolute() or parent.resolve(strict=True) != parent or parent.is_relative_to(Path.cwd()):
        raise ValueError("runner evidence parent is outside its expected scope")
    mode = parent.lstat()
    if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != uid or mode.st_mode & 0o022:
        raise ValueError("runner evidence parent is not owner controlled")
    return parent


def report():
    native = os.uname()
    first_boot = boot_id()
    if (
        native.sysname == "Linux" and native.machine == "x86_64" and first_boot
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}", native.release)
    ):
        status, evidence = observe_provider(native.release, native.version)
    else:
        status, evidence = "unknown", {}
    if boot_id() != first_boot or native != os.uname():
        status = "unknown"
    image = {
        name: value if re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value) else None
        for name in ("ImageOS", "ImageVersion")
        if (value := os.environ.get(name))
    }
    return {
        "schema": SCHEMA,
        "revision": os.environ["GITHUB_SHA"],
        "image": image,
        "kernel": {"release": native.release, "build": native.version, "architecture": native.machine, "boot_id": first_boot},
        "provider": status,
        "observations": evidence,
        "prerequisites": {
            "tools": {name: tool_status(paths) for name, paths in TOOLS.items()},
            "namespaces": {kind: namespace_identity(kind) for kind in ("net", "mnt", "user")},
            "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
            "namespace_operations_exercised": False,
        },
        "commissioned": False,
        "qualified": False,
    }


def write_report(directory, value):
    data = json.dumps(value, indent=2, sort_keys=True) + "\n"
    pending = directory / ".provider.json.pending"
    file = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(file, "w", encoding="utf-8") as output:
            output.write(data)
        pending.replace(directory / "provider.json")
    finally:
        pending.unlink(missing_ok=True)


def main():
    parent = hosted_admission()
    directory = parent / REPORT
    directory.mkdir(mode=0o700)
    write_report(directory, report())


if __name__ == "__main__":
    main()
