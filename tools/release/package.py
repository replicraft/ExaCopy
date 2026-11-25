#!/usr/bin/env python3
"""Package and validate exact ExaCopy CLI release bundles for CI."""

import argparse
from contextlib import contextmanager, nullcontext
import gzip
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[2]
TARGETS = (
    "aarch64-apple-darwin", "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu",
    "aarch64-pc-windows-msvc", "x86_64-pc-windows-msvc",
)
RELEASE_TARGETS = (
    "aarch64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
)
MANIFEST = "release.manifest"
SIGNATURE = "release.sig"
CHECKSUMS = "SHA256SUMS.txt"
MAX_ARCHIVE = 257 * 1024 * 1024
MAX_EXECUTABLE = 256 * 1024 * 1024
MAX_CERTIFICATE = 16384
COPY_BLOCK = 128 * 1024
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){2}")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
NUMERIC_FLOOR = re.compile(r"(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){1,3}")
MANIFEST_TIMESTAMP = re.compile(r"[1-9][0-9]{9}")
MANIFEST_SEQUENCE = re.compile(r"[1-9][0-9]{0,9}")
MANIFEST_FIELDS = (
    "schema", "version", "channel", "created", "expires", "sequence", "target", "variant",
    "format", "artifact", "size", "sha256", "publisher_sha256", "min_os", "min_abi",
    "sbom_sha256", "provenance_sha256",
)
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIP_END = struct.Struct("<4s4H2LH")
ZIP_LOCAL = struct.Struct("<4s5H3L2H")
ZIP_CENTRAL_SIZE = 46


def windows(target):
    return target.endswith("-pc-windows-msvc")


def archive_name(target):
    extension = "zip" if windows(target) else "tar.gz"
    return f"exacopy-cli-{target}.{extension}"


def members(target):
    executable = "exacopy.exe" if windows(target) else "exacopy"
    return {MANIFEST: (4096, 0o644), SIGNATURE: (1024, 0o644), executable: (MAX_EXECUTABLE, 0o755)}


def workspace_version(requested):
    with (ROOT / "Cargo.toml").open("rb") as stream:
        version = tomllib.load(stream)["workspace"]["package"]["version"]
    if not VERSION.fullmatch(version) or requested not in (None, version):
        raise ValueError(f"expected canonical workspace version {version}, received {requested}")
    return version


def ordinary(info):
    return not stat.S_ISLNK(info.st_mode) and not (
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def directory(path):
    info = path.lstat()
    if not ordinary(info) or not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"expected an ordinary directory: {path}")


@contextmanager
def regular_input(path, maximum):
    prior = path.lstat()
    if not ordinary(prior) or not stat.S_ISREG(prior.st_mode) or not 0 < prior.st_size <= maximum:
        raise ValueError(f"expected a bounded regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not ordinary(opened) or not stat.S_ISREG(opened.st_mode) or not os.path.samestat(prior, opened):
            raise ValueError(f"file identity changed while opening: {path}")
        if prior.st_size != opened.st_size:
            raise ValueError(f"file size changed while opening: {path}")
        yield stream, opened.st_size
        after = path.lstat()
        if (not ordinary(after) or not os.path.samestat(opened, after)
                or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            raise ValueError(f"input changed while reading: {path}")


def bounded_digest(source, size, destination=None):
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        block = source.read(min(COPY_BLOCK, remaining))
        if not block:
            raise ValueError("truncated release file")
        digest.update(block)
        if destination is not None:
            destination.write(block)
        remaining -= len(block)
    return digest.hexdigest()


def digest_input(path, maximum):
    with regular_input(path, maximum) as (source, size):
        digest = bounded_digest(source, size)
        if source.read(1):
            raise ValueError(f"input grew while reading: {path}")
        return size, digest


def require_entries(path, names):
    directory(path)
    actual = set()
    with os.scandir(path) as entries:
        for entry in entries:
            if entry.name not in names:
                raise ValueError(f"unexpected release entry: {entry.name}")
            actual.add(entry.name)
    if actual != names:
        raise ValueError(f"missing release entries: {', '.join(sorted(names - actual))}")


def check_manifest(data, info, target, version):
    expected_keys = b"\n".join(
        field.encode("ascii") + b"=([A-Za-z0-9._-]+)" for field in MANIFEST_FIELDS
    )
    match = re.fullmatch(expected_keys + b"\n", data)
    if not match:
        raise ValueError("invalid raw release descriptor")
    fields = dict(zip(MANIFEST_FIELDS, (value.decode("ascii") for value in match.groups())))
    executable = next(name for name in info if name not in (MANIFEST, SIGNATURE))
    size, digest = info[executable]
    expected = {
        "schema": "exacopy-release-v1", "version": version, "channel": "stable",
        "target": target, "variant": "cli", "format": "raw", "artifact": executable,
        "size": str(size), "sha256": digest,
    }
    for key, value in expected.items():
        if fields[key] != value:
            raise ValueError(f"release descriptor disagrees with expected {key}")
    for key in ("publisher_sha256", "sbom_sha256", "provenance_sha256"):
        if not HEX_SHA256.fullmatch(fields[key]):
            raise ValueError(f"invalid digest in release descriptor: {key}")
    for key in ("created", "expires"):
        if not MANIFEST_TIMESTAMP.fullmatch(fields[key]):
            raise ValueError(f"invalid timestamp in release descriptor: {key}")
    if fields["expires"] <= fields["created"]:
        raise ValueError("release descriptor validity interval is empty")
    if not MANIFEST_SEQUENCE.fullmatch(fields["sequence"]) or int(fields["sequence"]) > 2147483647:
        raise ValueError("invalid release sequence")
    if not 384 <= info[SIGNATURE][0] <= 1024:
        raise ValueError("detached signature length is outside the offline release profile")
    if windows(target):
        check_floor(fields["min_os"], (10, 0, 20348, 0))
    elif target.endswith("-apple-darwin"):
        check_floor(fields["min_os"], (14, 0, 0, 0))
    else:
        check_floor(fields["min_os"], (5, 15, 0, 0))
        check_floor(fields["min_abi"], (2, 35, 0, 0))
        return fields
    if fields["min_abi"] != "native":
        raise ValueError("non-Linux releases require the native ABI")
    return fields


def check_floor(value, baseline):
    if not NUMERIC_FLOOR.fullmatch(value):
        raise ValueError(f"invalid release platform floor: {value}")
    numbers = tuple(map(int, value.split(".")))
    if numbers + (0,) * (len(baseline) - len(numbers)) < baseline:
        raise ValueError(f"release platform floor is below the offline profile: {value}")


def openssl(*arguments):
    result = subprocess.run(["openssl", *map(os.fspath, arguments)], capture_output=True, timeout=30)
    if result.returncode != 0:
        raise ValueError(f"OpenSSL rejected release {arguments[0]} verification")
    return result.stdout


def verify_signature(bundle, scratch, certificate, expected_pin, signature_size):
    if not HEX_SHA256.fullmatch(expected_pin):
        raise ValueError("publisher pin must be a canonical SHA-256 digest")
    staged_certificate = scratch / "publisher.der"
    with regular_input(certificate, MAX_CERTIFICATE) as (source, size):
        with staged_certificate.open("xb") as destination:
            pin = bounded_digest(source, size, destination)
    if pin != expected_pin:
        raise ValueError("publisher certificate does not match the independently approved pin")
    public_key = scratch / "publisher.pem"
    public_key.write_bytes(openssl("x509", "-inform", "DER", "-in", staged_certificate, "-pubkey", "-noout"))
    modulus = openssl("rsa", "-pubin", "-in", public_key, "-modulus", "-noout")
    match = re.fullmatch(rb"Modulus=([0-9A-Fa-f]+)\r?\n", modulus)
    if not match or len(match[1]) > 2048:
        raise ValueError("publisher certificate must contain an RSA key of 3072–8192 bits")
    key_bits = int(match[1], 16).bit_length()
    if not 3072 <= key_bits <= 8192 or signature_size != (key_bits + 7) // 8:
        raise ValueError("invalid publisher RSA key or detached signature length")
    openssl("dgst", "-sha256", "-sigopt", "rsa_padding_mode:pkcs1", "-verify", public_key,
            "-signature", bundle / SIGNATURE, bundle / MANIFEST)


def tar_member(name, mode, size):
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.size = size
    return info


def write_tar(output, bundle, expected):
    with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
            for name, (limit, mode) in expected.items():
                with regular_input(bundle / name, limit) as (source, size):
                    archive.addfile(tar_member(name, mode, size), source)


def write_zip(output, bundle, expected):
    with zipfile.ZipFile(output, "w", allowZip64=False) as archive:
        for name, (limit, mode) in expected.items():
            entry = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
            entry.create_system = 3  # Unix regular-file mode in the external attributes.
            entry.external_attr = (stat.S_IFREG | mode) << 16
            with regular_input(bundle / name, limit) as (source, size):
                entry.file_size = size
                with archive.open(entry, "w") as zipped:
                    bounded_digest(source, size, zipped)


def payload(source, size, name, mode, destination):
    manifest = source.read(size) if name == MANIFEST else None
    context = nullcontext() if destination is None else (destination / name).open("xb")
    with context as target:
        if manifest is None:
            digest = bounded_digest(source, size, target)
        else:
            if len(manifest) != size:
                raise ValueError("truncated release descriptor")
            digest = hashlib.sha256(manifest).hexdigest()
            if target is not None:
                target.write(manifest)
        if target is not None:
            os.chmod(target.name, mode)
    return (size, digest), manifest


def read_tar(source, expected, destination):
    block = tarfile.BLOCKSIZE
    total = 0
    info = {}
    with gzip.GzipFile(fileobj=source, mode="rb") as archive:
        for name, (limit, mode) in expected.items():
            header = archive.read(block)
            entry = tarfile.TarInfo.frombuf(header, "ascii", "strict")
            if (not 0 < entry.size <= limit
                    or header != tar_member(name, mode, entry.size).tobuf(tarfile.USTAR_FORMAT)):
                raise ValueError(f"invalid USTAR entry for {name}")
            info[name], descriptor = payload(archive, entry.size, name, mode, destination)
            if name == MANIFEST:
                manifest = descriptor
            padding = (-entry.size) % block
            if archive.read(padding) != bytes(padding):
                raise ValueError("invalid USTAR member padding")
            total += block + entry.size + padding
        # tarfile writes two end blocks followed by padding to a full record.
        end_size = 2 * block + (-(total + 2 * block)) % tarfile.RECORDSIZE
        if archive.read(end_size + 1) != bytes(end_size):
            raise ValueError("invalid USTAR end marker or unexpected archive member")
    return info, manifest


def check_zip_end(source, size, expected):
    if size < ZIP_END.size:
        raise ValueError("truncated ZIP archive")
    source.seek(size - ZIP_END.size)
    marker, disk, start_disk, disk_count, count, central_size, central, comment = ZIP_END.unpack(
        source.read(ZIP_END.size)
    )
    exact_central_size = ZIP_CENTRAL_SIZE * len(expected) + sum(map(len, expected))
    if (marker != b"PK\x05\x06" or disk != 0 or start_disk != 0 or comment != 0
            or disk_count != len(expected) or count != len(expected)
            or central_size != exact_central_size or central + central_size + ZIP_END.size != size):
        raise ValueError("invalid classic ZIP central directory")
    return central


def check_zip_local(source, entry, name, offset, central):
    if entry.header_offset != offset or offset + ZIP_LOCAL.size + len(name) + entry.file_size > central:
        raise ValueError(f"invalid ZIP member extent for {name}")
    source.seek(offset)
    header = ZIP_LOCAL.unpack(source.read(ZIP_LOCAL.size))
    marker, _, flags, method, _, _, crc, compressed, size, name_size, extra = header
    if (marker != b"PK\x03\x04" or flags != 0 or method != zipfile.ZIP_STORED or crc != entry.CRC
            or size != entry.file_size or compressed != size or name_size != len(name) or extra != 0
            or source.read(name_size) != name.encode("ascii")):
        raise ValueError(f"invalid ZIP local header for {name}")
    return offset + ZIP_LOCAL.size + name_size + size


def read_zip(source, size, expected, destination):
    central = check_zip_end(source, size, expected)
    info = {}
    offset = 0
    with zipfile.ZipFile(source, "r") as archive:
        entries = archive.infolist()
        if len(entries) != len(expected):
            raise ValueError("unexpected ZIP member count")
        for entry, (name, (limit, mode)) in zip(entries, expected.items()):
            if (entry.orig_filename != name or entry.create_system != 3 or entry.flag_bits != 0
                    or entry.external_attr != (stat.S_IFREG | mode) << 16 or entry.extra or entry.comment
                    or entry.compress_type != zipfile.ZIP_STORED or entry.compress_size != entry.file_size
                    or not 0 < entry.file_size <= limit):
                raise ValueError(f"invalid ZIP entry for {name}")
            offset = check_zip_local(source, entry, name, offset, central)
            with archive.open(entry) as unzipped:
                info[name], descriptor = payload(unzipped, entry.file_size, name, mode, destination)
            if name == MANIFEST:
                manifest = descriptor
        if offset != central:
            raise ValueError("unexpected bytes between ZIP entries and central directory")
    return info, manifest


def read_archive(source, size, target, destination=None):
    expected = members(target)
    if windows(target):
        return read_zip(source, size, expected, destination)
    return read_tar(source, expected, destination)


def make_archive(target, version, bundle, output_dir, certificate, pin, sbom, provenance):
    expected = members(target)
    require_entries(bundle, set(expected))
    original = {name: digest_input(bundle / name, limit) for name, (limit, _) in expected.items()}
    output_dir.mkdir(parents=True, exist_ok=True)
    directory(output_dir)
    name = archive_name(target)
    with tempfile.TemporaryDirectory(prefix=".exacopy-package-", dir=output_dir) as scratch:
        directory_path = Path(scratch)
        stage = directory_path / name
        readback = directory_path / "readback"
        readback.mkdir(mode=0o700)
        with stage.open("xb") as output:
            writer = write_zip if windows(target) else write_tar
            writer(output, bundle, expected)
        with regular_input(stage, MAX_ARCHIVE) as (source, size):
            info, manifest = read_archive(source, size, target, readback)
        if info != original:
            raise ValueError("archive read-back differs from the bundle inputs")
        verify_signature(readback, directory_path, certificate, pin, info[SIGNATURE][0])
        fields = check_manifest(manifest, info, target, version)
        if fields["publisher_sha256"] != pin:
            raise ValueError("release descriptor publisher digest disagrees with the approved pin")
        for field, evidence in (("sbom_sha256", sbom), ("provenance_sha256", provenance)):
            if fields[field] != digest_input(evidence, MAX_EXECUTABLE)[1]:
                raise ValueError(f"release descriptor disagrees with {field}")
        os.link(stage, output_dir / name)
    return output_dir / name


def extract_archive(target, version, archive, bundle):
    if archive.name != archive_name(target):
        raise ValueError("archive filename does not match the selected target")
    directory(bundle.parent)
    with tempfile.TemporaryDirectory(prefix=".exacopy-extract-", dir=bundle.parent) as scratch:
        stage = Path(scratch)
        with regular_input(archive, MAX_ARCHIVE) as (source, size):
            info, manifest = read_archive(source, size, target, stage)
        check_manifest(manifest, info, target, version)
        bundle.mkdir(mode=0o700)
        linked = []
        try:
            for name in members(target):
                os.link(stage / name, bundle / name)
                linked.append(bundle / name)
        except OSError:
            for path in linked:
                path.unlink()
            bundle.rmdir()
            raise
    return bundle


def write_checksums(artifact_dir, version):
    archives = {archive_name(target): target for target in RELEASE_TARGETS}
    require_entries(artifact_dir, set(archives))
    lines = []
    for name, target in sorted(archives.items()):
        with regular_input(artifact_dir / name, MAX_ARCHIVE) as (source, size):
            info, manifest = read_archive(source, size, target)
            check_manifest(manifest, info, target, version)
            source.seek(0)
            lines.append(f"{bounded_digest(source, size)}  {name}\n")
    with tempfile.TemporaryDirectory(prefix=".exacopy-checksums-", dir=artifact_dir) as scratch:
        stage = Path(scratch) / CHECKSUMS
        stage.write_bytes("".join(lines).encode("ascii"))
        os.link(stage, artifact_dir / CHECKSUMS)
    return artifact_dir / CHECKSUMS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    archive = commands.add_parser("archive", help="Create a deterministic archive from a signed raw bundle.")
    extract = commands.add_parser("extract", help="Read back an archive into a new CI staging directory.")
    checksums = commands.add_parser("checksums", help="Hash the complete, validated release archive matrix.")
    for command in (archive, extract, checksums):
        command.add_argument("--version", help="Expected workspace version without a v prefix.")
    for command in (archive, extract):
        command.add_argument("--target", choices=TARGETS, required=True)
        command.add_argument("--bundle", type=Path, required=True)
    archive.add_argument("--output-dir", type=Path, required=True)
    archive.add_argument("--publisher-cert", type=Path, required=True)
    archive.add_argument("--publisher-sha256", required=True)
    archive.add_argument("--sbom", type=Path, required=True)
    archive.add_argument("--provenance", type=Path, required=True)
    extract.add_argument("--archive", type=Path, required=True)
    checksums.add_argument("--artifact-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        version = workspace_version(args.version)
        if args.command == "archive":
            result = make_archive(args.target, version, args.bundle, args.output_dir,
                                  args.publisher_cert, args.publisher_sha256, args.sbom, args.provenance)
        elif args.command == "extract":
            result = extract_archive(args.target, version, args.archive, args.bundle)
        else:
            result = write_checksums(args.artifact_dir, version)
        print(result)
    except (OSError, ValueError, EOFError, tarfile.TarError, zipfile.BadZipFile, zlib.error,
            struct.error, subprocess.SubprocessError) as error:
        parser.exit(1, f"release packaging: {error}\n")


if __name__ == "__main__":
    main()
