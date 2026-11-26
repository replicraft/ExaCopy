"""Verify the exact Canonical Noble archive records used for read-only enrollment."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import lzma
import os
from pathlib import Path
import re

from remote_commissioning_peer import Blocked
from native_supervision import logged_command
from remote_commissioning_wireguard_provider_b import checked_hash, regular

ORIGIN = "https://security.ubuntu.com/ubuntu"
SUITE = "noble-security"
INDEX = "main/binary-amd64/Packages.xz"
KEYRING = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
CURL = "/usr/bin/curl"
GPGV = "/usr/bin/gpgv"
RELEASE_MAX = 256 * 1024
SIGNATURE_MAX = 16 * 1024
INDEX_MAX = 16 * 1024 * 1024
INDEX_PLAIN_MAX = 128 * 1024 * 1024
ARCHIVE_MAX = 224 * 1024 * 1024
ENV = {"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"}


@dataclass(frozen=True)
class Extent:
    size: int
    sha256: str


def extent(size, digest, ceiling):
    if not re.fullmatch(r"[1-9][0-9]{0,8}", size) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise Blocked("signed archive extent is malformed")
    value = int(size)
    if value > ceiling:
        raise Blocked("signed archive extent is outside its bounded budget")
    return Extent(value, digest)


def fields(lines):
    result = {}
    last = None
    for line in lines:
        if line.startswith((b" ", b"\t")) and last:
            result[last].append(line.strip())
            continue
        key, delimiter, value = line.partition(b":")
        if not delimiter or not re.fullmatch(rb"[A-Za-z0-9][A-Za-z0-9-]*", key) or key in result:
            raise Blocked("signed archive contains an ambiguous control record")
        last = key
        result[key] = [value.strip()]
    return result


def scalar(record, name):
    entries = record.get(name, [])
    if len(entries) != 1 or not entries[0] or any(char < 32 or char > 126 for char in entries[0]):
        raise Blocked("required signed archive field is missing or malformed")
    return entries[0].decode("ascii")


def release_index(release, now):
    record = fields(release.splitlines())
    if (
        scalar(record, b"Origin") != "Ubuntu" or scalar(record, b"Label") != "Ubuntu"
        or scalar(record, b"Codename") != "noble" or scalar(record, b"Suite") != SUITE
        or "amd64" not in scalar(record, b"Architectures").split()
        or "main" not in scalar(record, b"Components").split()
        or scalar(record, b"Acquire-By-Hash") != "yes"
    ):
        raise Blocked("signed Release origin, suite or index geometry differs")
    try:
        issued = parsedate_to_datetime(scalar(record, b"Date"))
        expires = (
            parsedate_to_datetime(scalar(record, b"Valid-Until"))
            if b"Valid-Until" in record else issued + timedelta(days=7)
        )
        if not now - timedelta(days=7) <= issued <= now + timedelta(minutes=10) or now >= expires or expires <= issued:
            raise Blocked("signed Release date or validity is outside the admission window")
    except (TypeError, ValueError, OverflowError) as error:
        raise Blocked("signed Release date or validity is malformed") from error
    matches = []
    for row in record.get(b"SHA256", []):
        values = row.decode("ascii").split()
        if len(values) == 3 and values[2] == INDEX:
            matches.append(extent(values[1], values[0], INDEX_MAX))
    if len(matches) != 1:
        raise Blocked("signed Release lacks one exact AMD64 index hash")
    return matches[0]


def package_rows(path, expected):
    records = {}
    consumed = 0
    stanza = []
    stanza_bytes = 0
    with lzma.open(path, "rb") as index:
        while True:
            line = index.readline(64 * 1024 + 1)
            consumed += len(line)
            stanza_bytes += len(line)
            if consumed > INDEX_PLAIN_MAX or stanza_bytes > 256 * 1024 or len(line) > 64 * 1024:
                raise Blocked("expanded package index exceeds its bounded budget")
            if line and not line.endswith(b"\n"):
                raise Blocked("signed package index ends with an incomplete line")
            if line not in (b"\n", b""):
                stanza.append(line.rstrip(b"\n"))
                continue
            if stanza:
                find_package(stanza, expected, records)
            if not line:
                break
            stanza = []
            stanza_bytes = 0
    if set(records) != set(expected):
        raise Blocked("signed index lacks the exact kernel image or module package")
    return records


def find_package(stanza, expected, records):
    names = [line.removeprefix(b"Package: ") for line in stanza if line.startswith(b"Package: ")]
    selected = [name for name in expected if name.encode("ascii") in names]
    if not selected:
        return
    record = fields(stanza)
    name = scalar(record, b"Package")
    version, filename = expected[name]
    if scalar(record, b"Version") != version:
        return
    if name in records or scalar(record, b"Architecture") != "amd64" or scalar(record, b"Filename") != filename:
        raise Blocked("signed kernel package identity or filename is ambiguous")
    binding = extent(scalar(record, b"Size"), scalar(record, b"SHA256"), ARCHIVE_MAX)
    records[name] = {
        "package": name, "version": version, "architecture": "amd64",
        "filename": filename, "size": binding.size, "sha256": binding.sha256,
    }


def bounded(argv, path, seconds, maximum):
    if not logged_command(argv, path, seconds, env=ENV, output_limit=maximum).passed():
        raise Blocked("bounded Canonical archive command did not complete")


def fetch(url, path, seconds, maximum):
    bounded([
        CURL, "--disable", "--fail", "--silent", "--show-error", "--proto", "=https", "--tlsv1.2",
        "--connect-timeout", "10", "--max-time", str(seconds), "--max-filesize", str(maximum), "--", url,
    ], path, seconds + 5, maximum)
    return regular(path, os.geteuid(), maximum)


def verify_blob(path, expected):
    owner = os.geteuid()
    original = regular(path, owner, expected.size)
    if original[2] != expected.size or checked_hash(path, owner, expected.size) != expected.sha256:
        raise Blocked("Canonical bytes differ from the signed archive extent")
    return original


def signed_index(work, evidence, expected):
    release = work / "Release"
    signature = work / "Release.gpg"
    release_url = f"{ORIGIN}/dists/{SUITE}/Release"
    release_identity = fetch(release_url, release, 25, RELEASE_MAX)
    signature_identity = fetch(release_url + ".gpg", signature, 25, SIGNATURE_MAX)
    gpg_home = work / "gpg"
    gpg_home.mkdir(mode=0o700)
    key_digest = checked_hash(KEYRING, 0, RELEASE_MAX)
    bounded([
        GPGV, "--homedir", gpg_home, "--keyring", KEYRING, "--status-fd", "1", "--", signature, release,
    ], work / "gpg-status", 15, RELEASE_MAX)
    if checked_hash(KEYRING, 0, RELEASE_MAX) != key_digest:
        raise Blocked("Ubuntu archive keyring custody changed")
    owner = os.geteuid()
    if regular(release, owner, RELEASE_MAX) != release_identity or regular(signature, owner, SIGNATURE_MAX) != signature_identity:
        raise Blocked("Canonical Release or signature changed during verification")
    index = release_index(release.read_bytes(), datetime.now(timezone.utc))
    url = f"{ORIGIN}/dists/{SUITE}/main/binary-amd64/by-hash/SHA256/{index.sha256}"
    download = work / "Packages.xz"
    fetch(url, download, 90, index.size)
    before = verify_blob(download, index)
    packages = package_rows(download, expected)
    if regular(download, os.geteuid(), index.size) != before:
        raise Blocked("Canonical index changed while reading package records")
    evidence["canonical"] = {
        "url": ORIGIN, "suite": SUITE, "archive_keyring_sha256": key_digest,
        "index_url": url, "index_size": index.size, "index_sha256": index.sha256,
        "release_sha256": checked_hash(release, os.geteuid(), RELEASE_MAX),
        "signature_sha256": checked_hash(signature, os.geteuid(), SIGNATURE_MAX),
        "packages": packages,
    }
    return packages, {
        release: Extent(release_identity[2], evidence["canonical"]["release_sha256"]),
        signature: Extent(signature_identity[2], evidence["canonical"]["signature_sha256"]),
        download: index,
    }
