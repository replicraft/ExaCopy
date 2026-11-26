"""Verify the exact Canonical Noble archive records used for read-only enrollment."""

from base64 import b64decode
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from hashlib import sha256
import lzma
import os
from pathlib import Path
import re
import stat

from remote_commissioning_peer import Blocked
from native_supervision import logged_command
from remote_commissioning_wireguard_provider_b import checked_hash, regular

ORIGIN = "https://security.ubuntu.com/ubuntu"
SUITE = "noble-security"
INDEX = "main/binary-amd64/Packages.xz"
# Canonical Chisel's Noble configuration selects this one public archive key.
# https://ubuntu.com/chisel/docs/v1.3.0/reference/chisel-releases/chisel.yaml/
ARCHIVE_KEY_FINGERPRINT = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
ARCHIVE_KEY_BYTES = 1167
ARCHIVE_KEY_SHA256 = "5ebbeeb474034b1fa7e50abbe6f136e177fc826219e01f314b3623f7b3097e96"
ARCHIVE_KEY_BASE64 = (
    b"mQINBFufwdoBEADv/Gxytx/LcSXYuM0MwKojbBye81s0G1nEx+lz6VAUpIUZnbkq"
    b"dXBHC+dwrGS/CeeLuAjPRLU8AoxE/jjvZVp8xFGEWHYdklqXGZ/gJfP5d3fIUBtZ"
    b"HZEJl8B8m9pMHf/AQQdsC+YzizSG5t5Mhnotw044LXtdEEkx2t6Jz0OGrh+5Ioxq"
    b"X7pZiq6Cv19BohaUioKMdp7ES6RYfN7ol6HSLFlrMXtVfh/ijpN9j3ZhVGVeRC8k"
    b"KHQsJ5PkIbmvxBiUh7SJmfZUx0IQhNMaDHXfdZAGNtnhzzNReb1FqNLSVkrS/Pns"
    b"AQzMhG1BDm2VOSF64jebKXffFqM5LXRQTeqTLsjUbbrqR6s/GCO8UF7jfUj6I7ta"
    b"LygmsHO/JD4jpKRC0gbpUBfaiJyLvuepx3kWoqL3sN0LhlMI80+fA7GTvoOx4tpq"
    b"VlzlE6TajYu+jfW3QpOFS5ewEMdL26hzxsZg/geZvTbArcP+OsJKRmhv4kNo6Ayd"
    b"yHQ/3ZV/f3X9mT3/SPLbJaumkgp3Yzd6t5PeBu+ZQk/mN5WNNuaihNEV7llb1Zhv"
    b"Y0Fxu9BVd/BNl0rzuxp3rIinB2TX2SCg7wE5xXkwXuQ/2eTDE0v0HlGntkuZjGow"
    b"DZkxHZQSxZVOzdZCRVaX/WEFLpKa2AQpw5RJrQ4oZ/OfifXyJzP27o03wQARAQAB"
    b"tEJVYnVudHUgQXJjaGl2ZSBBdXRvbWF0aWMgU2lnbmluZyBLZXkgKDIwMTgpIDxm"
    b"dHBtYXN0ZXJAdWJ1bnR1LmNvbT6JAjgEEwEKACIFAlufwdoCGwMGCwkIBwMCBhUI"
    b"AgkKCwQWAgMBAh4BAheAAAoJEIcZINGZG8k8LHMQAKS2cnxz/5WaoCOWArf5g6UH"
    b"beOCgc5DBm0hCuFDZWWv427aGei3CPuLw0DGLCXZdyc5dqE8mvjMlOmmAKKlj1uG"
    b"g3TYCbQWjWPeMnBPZbkFgkZoXJ7/6CB7bWRht1sHzpt1LTZ+SYDwOwJ68QRp7DRa"
    b"Zl9Y6QiUbeuhq2DUcTofVbBxbhrckN4ZteLvm+/nG9m/ciopc66LwRdkxqfJ32Cy"
    b"q+1TS5VaIJDG7DWziG+Kbu6qCDM4QNlg3LH7p14CrRxAbc4lvohRgsV4eQqsIcdF"
    b"kuVY5HPPj2K8TqpY6STe8Gh0aprG1RV8ZKay3KSMpnyV1fAKn4fM9byiLzQAovC0"
    b"LZ9MMMsrAS/45AvC3IEKSShjLFn1X1dRCiO6/7jmZEoZtAp53hkf8SMBsi78hVNr"
    b"BumZwfIdBA1v22+LY4xQK8q4XCoRcA9G+pvzU9YVW7cRnDZZGl0uwOw7z9PkQBF5"
    b"KFKjWDz4fCk+K6+YtGpovGKekGBb8I7EA6UpvPgqA/QdI0t1IBP0N06RQcs1fUaA"
    b"QEtz6DGy5zkRhR4pGSZn+dFET7PdAjEK84y7BdY4t+U1jcSIvBj0F2B7LwRL7xGp"
    b"SpIKi/ekAXLs117bvFHaCvmUYN7JVp1GMmVFxhIdx6CFm3fxG8QjNb5tere/YqK+"
    b"uOgcXny1UlwtCUzlrSaP"
)
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


@contextmanager
def custody_step(evidence, stage, path, owner, maximum):
    steps = evidence.setdefault("canonical_steps", {})
    result = steps[stage] = {"status": "started", "limit_bytes": maximum}
    try:
        yield
    except (Blocked, OSError, ValueError, lzma.LZMAError) as error:
        result["status"] = "blocked"
        result["failure"] = str(error) if isinstance(error, Blocked) else type(error).__name__
        try:
            info = path.lstat()
            result["file"] = {
                "regular": stat.S_ISREG(info.st_mode), "owner_matches": info.st_uid == owner,
                "links": info.st_nlink, "mode": f"{stat.S_IMODE(info.st_mode):04o}", "bytes": info.st_size,
            }
        except FileNotFoundError:
            result["file"] = {"status": "missing"}
        except OSError:
            result["file"] = {"status": "inspection-unavailable"}
        raise
    else:
        result["status"] = "observed"


def stage_archive_key(keyring):
    public_key = b64decode(ARCHIVE_KEY_BASE64, validate=True)
    if len(public_key) != ARCHIVE_KEY_BYTES or sha256(public_key).hexdigest() != ARCHIVE_KEY_SHA256:
        raise Blocked("the reviewed Ubuntu archive key bytes differ")
    fd = os.open(keyring, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(public_key)
    return verify_archive_key(keyring)


def verify_archive_key(keyring):
    identity = verify_blob(keyring, Extent(ARCHIVE_KEY_BYTES, ARCHIVE_KEY_SHA256))
    if stat.S_IMODE(keyring.lstat().st_mode) != 0o600:
        raise Blocked("private Ubuntu archive key mode differs")
    return identity


def verify_archive_signer(status):
    # VALIDSIG has a signing fingerprint and optionally the primary fingerprint.
    # The pinned key packet has no subkey. Treat other signatures as a refusal.
    authenticated = []
    rejected = {b"BADSIG", b"ERRSIG", b"EXPSIG", b"EXPKEYSIG", b"REVKEYSIG", b"NO_PUBKEY", b"KEYEXPIRED", b"SIGEXPIRED"}
    fingerprint = ARCHIVE_KEY_FINGERPRINT.encode("ascii")
    for line in status.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0] != b"[GNUPG:]":
            continue
        if fields[1] in rejected:
            raise Blocked("GnuPG refused an Ubuntu Release signature")
        if fields[1] == b"VALIDSIG":
            if (
                len(fields) not in {11, 12} or fields[2] != fingerprint
                or (len(fields) == 12 and fields[11] != fingerprint)
                or fields[8] != b"1" or fields[9] not in {b"8", b"9", b"10"}
            ):
                raise Blocked("Ubuntu Release signature is outside its pinned signer or digest")
            authenticated.append(fields[2])
    if authenticated != [fingerprint]:
        raise Blocked("Ubuntu Release lacks one exact pinned signer")


def signed_index(work, evidence, expected):
    release = work / "Release"
    signature = work / "Release.gpg"
    release_url = f"{ORIGIN}/dists/{SUITE}/Release"
    owner = os.geteuid()
    with custody_step(evidence, "release-download", release, owner, RELEASE_MAX):
        release_identity = fetch(release_url, release, 25, RELEASE_MAX)
    with custody_step(evidence, "release-signature-download", signature, owner, SIGNATURE_MAX):
        signature_identity = fetch(release_url + ".gpg", signature, 25, SIGNATURE_MAX)
    gpg_home = work / "gpg"
    gpg_home.mkdir(mode=0o700)
    keyring = gpg_home / "ubuntu-archive-2018.gpg"
    with custody_step(evidence, "pinned-ubuntu-archive-key", keyring, owner, ARCHIVE_KEY_BYTES):
        key_identity = stage_archive_key(keyring)
    evidence["archive_anchor"] = {"sha256": ARCHIVE_KEY_SHA256, "fingerprint": ARCHIVE_KEY_FINGERPRINT}
    with custody_step(evidence, "release-signature-verification", signature, owner, SIGNATURE_MAX):
        verification_status = work / "gpg-status"
        bounded([
            GPGV, "--homedir", gpg_home, "--keyring", keyring, "--status-fd", "1", "--", signature, release,
        ], verification_status, 15, RELEASE_MAX)
        verify_archive_signer(verification_status.read_bytes())
    with custody_step(evidence, "pinned-ubuntu-archive-key-recheck", keyring, owner, ARCHIVE_KEY_BYTES):
        if verify_archive_key(keyring) != key_identity:
            raise Blocked("private Ubuntu archive key changed during verification")
    with custody_step(evidence, "release-signature-recheck", signature, owner, SIGNATURE_MAX):
        if regular(signature, owner, SIGNATURE_MAX) != signature_identity:
            raise Blocked("Canonical Release signature changed during verification")
    with custody_step(evidence, "release-parse", release, owner, RELEASE_MAX):
        if regular(release, owner, RELEASE_MAX) != release_identity:
            raise Blocked("Canonical Release changed during verification")
        index = release_index(release.read_bytes(), datetime.now(timezone.utc))
    url = f"{ORIGIN}/dists/{SUITE}/main/binary-amd64/by-hash/SHA256/{index.sha256}"
    download = work / "Packages.xz"
    with custody_step(evidence, "index-download", download, owner, index.size):
        fetch(url, download, 90, index.size)
    with custody_step(evidence, "index-verification", download, owner, index.size):
        before = verify_blob(download, index)
        packages = package_rows(download, expected)
        if regular(download, owner, index.size) != before:
            raise Blocked("Canonical index changed while reading package records")
    with custody_step(evidence, "release-retention-digest", release, owner, RELEASE_MAX):
        release_digest = checked_hash(release, owner, RELEASE_MAX)
    with custody_step(evidence, "signature-retention-digest", signature, owner, SIGNATURE_MAX):
        signature_digest = checked_hash(signature, owner, SIGNATURE_MAX)
    evidence["canonical"] = {
        "url": ORIGIN, "suite": SUITE, "archive_keyring_sha256": ARCHIVE_KEY_SHA256,
        "archive_signer_fingerprint": ARCHIVE_KEY_FINGERPRINT,
        "index_url": url, "index_size": index.size, "index_sha256": index.sha256,
        "release_sha256": release_digest,
        "signature_sha256": signature_digest,
        "packages": packages,
    }
    return packages, {
        release: Extent(release_identity[2], evidence["canonical"]["release_sha256"]),
        signature: Extent(signature_identity[2], evidence["canonical"]["signature_sha256"]),
        download: index,
    }
