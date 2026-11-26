"""Bounded independent observations for the Linux remote CLI campaign."""

import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess

MIB = 1024 * 1024
MAX_REPORT = 16 * 1024
MAX_SOURCE = 128 * MIB
MAX_PEER_LOG = 8 * MIB
MAX_RECEIPT = 5120
MAX_QUALIFICATION = 3072
RECEIPT_DOMAIN = b"ExaCopy/linux-remote-download-receipt/v1\0"
QUALIFICATION_DOMAIN = b"ExaCopy/linux-remote-destination-qualification-record/v1\0"
BUILD_DOMAIN = "ExaCopy remote running executable v1"
JOB_NAME = re.compile(r"\.exacopy-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
CONNECTION = re.compile(r"^Connection from (\S+) port (\d+) on (\S+) port (\d+)(?: |$)")
AUTHENTICATION = re.compile(r"^Accepted (?:publickey|password) for (\S+) from (\S+) port (\d+)(?: |$)")

OMISSIONS = (
    "additional_content_streams_unenumerated", "source_unix_mode", "source_ownership",
    "source_timestamps", "source_acl", "source_xattrs_and_security_labels",
    "source_file_flags", "source_link_topology", "source_sparse_layout",
    "source_storage_representation",
)


class Blocked(Exception):
    """The fixture could not establish a required antecedent."""


class Failed(Exception):
    """The observed result differed from the test oracle."""


def require(condition, description):
    if not condition:
        raise Failed(description)


def canonical(path):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise Blocked("fixture paths must be absolute and free of symlinks")
    return path


def owned_directory(path, *, private=False):
    current = canonical(path).stat()
    if (
        not stat.S_ISDIR(current.st_mode)
        or current.st_uid != os.geteuid()
        or (private and stat.S_IMODE(current.st_mode) != 0o700)
    ):
        raise Blocked("fixture directory ownership or mode is outside the campaign scope")
    return current


def fingerprint(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def opened(path, maximum, *, buffering=-1):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    file = os.fdopen(descriptor, "rb", buffering=buffering)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum or info.st_nlink != 1:
        file.close()
        raise Blocked("a selected fixture file exceeds its bound or is not a single regular file")
    return file, info


def checked_read(path, maximum):
    with_open, info = opened(path, maximum)
    with with_open as file:
        data = file.read(maximum + 1)
        require(len(data) == info.st_size, "bounded evidence file length changed")
        check_held(path, file, info)
    return data


def check_held(path, file, info):
    require(
        fingerprint(info) == fingerprint(os.fstat(file.fileno()))
        == fingerprint(path.stat(follow_symlinks=False)),
        "independently observed fixture file changed",
    )


def b3(b3sum, data, context=None, *, file=None):
    argv = [str(b3sum), "--no-names"]
    if context is not None:
        argv += ["--derive-key", context]
    if file is not None:
        require(isinstance(file, io.FileIO), "a child digest requires an unbuffered held descriptor")
    kwargs = {"input": data} if file is None else {"stdin": file}
    output = subprocess.run(argv, **kwargs, capture_output=True, check=True, timeout=20).stdout
    digest = output.strip().decode("ascii")
    require(re.fullmatch(r"[0-9a-f]{64}", digest), "b3sum returned an unexpected digest")
    return digest


def digest_executable(binary, b3sum):
    # The child's stdin and the parent share a kernel file offset. A buffered
    # reader can rewind only its own cache after the ELF header check.
    binary.seek(0)
    build_digest = b3(b3sum, None, BUILD_DOMAIN, file=binary)
    binary.seek(0)
    return build_digest, hashlib.file_digest(binary, "sha256").hexdigest()


def hash_source(path, b3sum, lower, upper):
    with_open, info = opened(path, upper, buffering=0)
    with with_open as file:
        if info.st_uid != os.geteuid() or not lower <= info.st_size <= upper:
            raise Blocked("source fixture must be owned and within its audited extent")
        digest = b3(b3sum, None, file=file)
        check_held(path, file, info)
    return info, digest


def compare_files(source, target, expected):
    source_open, source_info = opened(source, expected.st_size)
    with source_open as left:
        target_open, target_info = opened(target, expected.st_size)
        with target_open as right:
            require(fingerprint(source_info) == fingerprint(expected), "source fixture changed")
            require(
                target_info.st_size == expected.st_size
                and stat.S_IMODE(target_info.st_mode) == 0o600
                and target_info.st_uid == os.geteuid(),
                "published target extent, owner or restrictive mode differed",
            )
            for offset in range(0, expected.st_size, MIB):
                count = min(MIB, expected.st_size - offset)
                require(left.read(count) == right.read(count), "independent bytes differed")
            require(left.read(1) == right.read(1) == b"", "independent EOF differed")
            check_held(source, left, source_info)
            check_held(target, right, target_info)
    return target_info


def socket_address(raw):
    host, separator, port = raw.rpartition(":")
    if not separator:
        raise Blocked("fixture listener must be a literal socket address")
    address = ipaddress.ip_address(host.removeprefix("[").removesuffix("]"))
    port = int(port)
    if not 1 <= port <= 65535:
        raise Blocked("fixture listener port is invalid")
    return address, port


def peer_profile(data, route_class):
    document = json.loads(data)
    route = document["route"]
    expected_port = document["port"]
    if route_class == "direct-pinned-tcp-v1" and route["kind"] == "direct":
        listener, port = socket_address(route["endpoint"])
        if not listener.is_loopback:
            raise Blocked("direct fixture listener must be loopback")
        local = None
    elif route_class == "embedded-wireguard-tcp-v1" and route["kind"] == "embedded-wireguard":
        listener, port = socket_address(route["remote_inner"])
        outer, _ = socket_address(route["outer"])
        if not outer.is_loopback:
            raise Blocked("embedded fixture outer peer must be loopback")
        local = ipaddress.ip_address(route["local_inner"])
    else:
        raise Blocked("fixture uses the wrong explicitly selected route class")
    if port != expected_port or document["maximum_extent"] > MAX_SOURCE:
        raise Blocked("fixture profile exceeds the admitted listener or transfer bounds")
    return document["account"], document["host"], listener, port, local


def match_records(data, pattern):
    return [
        match.groups()
        for line in data.decode("utf-8", errors="strict").splitlines()
        if (match := pattern.match(line))
    ]


class PeerLog:
    def __init__(self, path, account, listener, port, local):
        self.path = canonical(path)
        info = self.path.stat()
        if (
            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid()
            or info.st_size > MAX_PEER_LOG
        ):
            raise Blocked("provide the dedicated private fixture-only OpenSSH log")
        self.identity = (info.st_dev, info.st_ino)
        self.offset = info.st_size
        self.account = account
        self.listener = listener
        self.port = port
        self.local = local

    def check(self, count, output):
        with_open, info = opened(self.path, MAX_PEER_LOG)
        with with_open as file:
            require(
                self.identity == (info.st_dev, info.st_ino) and info.st_size >= self.offset,
                "dedicated OpenSSH log was reset or replaced",
            )
            file.seek(self.offset)
            data = file.read(info.st_size - self.offset)
            require(len(data) == info.st_size - self.offset, "short OpenSSH log read")
            self.offset += len(data)
        with output.open("xb") as record:
            record.write(data)
        connections = match_records(data, CONNECTION)
        accepted = match_records(data, AUTHENTICATION)
        require(len(connections) == count, "unexpected number of OpenSSH connections")
        require(
            accepted == [(self.account, peer, port) for peer, port, _, _ in connections],
            "OpenSSH authentication did not match the observed connection and account",
        )
        for peer, _, destination, port in connections:
            require(
                ipaddress.ip_address(destination) == self.listener and int(port) == self.port,
                "OpenSSH observed a different listener",
            )
            ip = ipaddress.ip_address(peer)
            require(
                ip.is_loopback if self.local is None else ip == self.local,
                "OpenSSH observed a different route peer",
            )


def file_sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()
