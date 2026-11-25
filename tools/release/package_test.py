#!/usr/bin/env python3
"""Exercise the package CLI with throwaway publisher keys and inert fixture bytes."""

import gzip
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
import zipfile


SCRIPT = Path(__file__).with_name("package.py")
VERSION = tomllib.loads((SCRIPT.parents[2] / "Cargo.toml").read_text())["workspace"]["package"]["version"]
TARGETS = {
    "aarch64-apple-darwin": ("tar.gz", "exacopy", "14.0", "native"),
    "x86_64-unknown-linux-gnu": ("tar.gz", "exacopy", "5.15", "2.35"),
    "x86_64-pc-windows-msvc": ("zip", "exacopy.exe", "10.0.20348", "native"),
}
LINUX = "x86_64-unknown-linux-gnu"
WINDOWS = "x86_64-pc-windows-msvc"
PAYLOAD = b"ExaCopy synthetic inert packaging test.\0" + bytes(range(256)) * 600


def sha(data):
    return hashlib.sha256(data).hexdigest()


def openssl(*arguments):
    subprocess.run(["openssl", *map(os.fspath, arguments)], check=True, capture_output=True, timeout=30)


def filename(target):
    return f"exacopy-cli-{target}.{TARGETS[target][0]}"


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("openssl") is None:
            raise RuntimeError("OpenSSL is required to generate the synthetic test publisher")
        scratch = tempfile.TemporaryDirectory(prefix="exacopy-synthetic-publisher-")
        cls.addClassCleanup(scratch.cleanup)
        root = Path(scratch.name)
        cls.key = root / "test-only.key"
        cls.cert = root / "test-only.der"
        pem = root / "test-only.pem"
        openssl("req", "-new", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1",
                "-subj", "/CN=Synthetic ExaCopy archive fixture/", "-keyout", cls.key, "-out", pem)
        openssl("x509", "-in", pem, "-outform", "DER", "-out", cls.cert)
        cls.pin = sha(cls.cert.read_bytes())

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="exacopy-release-package-test-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.archive_dir = self.root / "archives"
        self.sbom = self.root / "test-only.cdx.json"
        self.provenance = self.root / "test-only.provenance.json"
        self.sbom.write_bytes(b'{"label":"synthetic SBOM fixture"}\n')
        self.provenance.write_bytes(b'{"label":"synthetic provenance fixture"}\n')

    def fixture(self, runner_target, **overrides):
        directory = self.root / runner_target
        directory.mkdir(exist_ok=True)
        _, executable, min_os, min_abi = TARGETS[runner_target]
        (directory / executable).write_bytes(PAYLOAD)
        fields = {
            "schema": "exacopy-release-v1", "version": VERSION, "channel": "stable",
            "created": "2000000000", "expires": "2000003600", "sequence": "9", "target": runner_target,
            "variant": "cli", "format": "raw", "artifact": executable, "size": len(PAYLOAD),
            "sha256": sha(PAYLOAD), "publisher_sha256": self.pin, "min_os": min_os, "min_abi": min_abi,
            "sbom_sha256": sha(self.sbom.read_bytes()), "provenance_sha256": sha(self.provenance.read_bytes()),
        }
        manifest = directory / "release.manifest"
        manifest.write_bytes("".join(f"{key}={value}\n" for key, value in (fields | overrides).items()).encode("ascii"))
        openssl("dgst", "-sha256", "-sign", self.key, "-out", directory / "release.sig", manifest)
        return directory

    def invoke(self, *arguments, refuses=None):
        process = subprocess.run([sys.executable, "-B", str(SCRIPT), *map(os.fspath, arguments)],
                                 capture_output=True, text=True, timeout=45)
        if refuses is None:
            self.assertEqual(process.returncode, 0, process.stderr)
            return Path(process.stdout.strip())
        self.assertNotEqual(process.returncode, 0, process.stdout)
        self.assertIn(refuses, process.stderr)
        self.assertNotIn("Traceback", process.stderr)

    def package(self, target, bundle, *, output=None, pin=None, version=VERSION, refuses=None):
        return self.invoke("archive", "--target", target, "--version", version, "--bundle", bundle,
                           "--output-dir", output or self.archive_dir, "--publisher-cert", self.cert,
                           "--publisher-sha256", pin or self.pin, "--sbom", self.sbom,
                           "--provenance", self.provenance, refuses=refuses)

    def extract(self, target, package, *, refuses=None):
        return self.invoke("extract", "--target", target, "--archive", package,
                           "--bundle", self.root / "staged", refuses=refuses)

    def checksums(self, *, refuses=None):
        return self.invoke("checksums", "--artifact-dir", self.archive_dir, refuses=refuses)

    def assert_tar(self, package, expected):
        self.assertEqual(package.read_bytes()[:8], b"\x1f\x8b\x08\x00\x00\x00\x00\x00")
        with tarfile.open(package, "r:gz") as archive:
            entries = archive.getmembers()
            self.assertEqual({entry.name for entry in entries}, set(expected))
            self.assertEqual(len(entries), len(expected))
            for entry in entries:
                self.assertTrue(entry.isfile())
                self.assertEqual((entry.uid, entry.gid, entry.mtime, entry.uname, entry.gname), (0, 0, 0, "", ""))
                self.assertEqual(entry.mode, 0o755 if entry.name == "exacopy" else 0o644)
                self.assertEqual(archive.extractfile(entry).read(), expected[entry.name])

    def assert_zip(self, package, expected):
        with zipfile.ZipFile(package) as archive:
            self.assertEqual(archive.comment, b"")
            entries = archive.infolist()
            self.assertEqual({entry.filename for entry in entries}, set(expected))
            self.assertEqual(len(entries), len(expected))
            for entry in entries:
                self.assertEqual(entry.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual((entry.flag_bits, entry.extra, entry.comment), (0, b"", b""))
                self.assertTrue(stat.S_ISREG(entry.external_attr >> 16))
                self.assertEqual(stat.S_IMODE(entry.external_attr >> 16), 0o755 if entry.filename == "exacopy.exe" else 0o644)
                self.assertEqual(archive.read(entry), expected[entry.filename])

    def test_three_targets_deterministic_and_standard_checksum_rows(self):
        expected_rows = []
        for target in TARGETS:
            with self.subTest(target=target):
                bundle = self.fixture(target)
                expected = {entry.name: entry.read_bytes() for entry in bundle.iterdir()}
                first = self.package(target, bundle)
                self.assertEqual(first.name, filename(target))
                for entry in bundle.iterdir():
                    os.utime(entry, (123456789, 123456789))
                second = self.package(target, bundle, output=self.root / "another-directory")
                self.assertEqual(first.read_bytes(), second.read_bytes())
                if first.suffix == ".zip":
                    self.assert_zip(first, expected)
                else:
                    self.assert_tar(first, expected)
                expected_rows.append((first.name, sha(first.read_bytes())))
        checksum_path = self.checksums()
        self.assertEqual(checksum_path.name, "SHA256SUMS.txt")
        self.assertEqual(checksum_path.read_bytes(), "".join(
            f"{checksum}  {name}\n" for name, checksum in sorted(expected_rows)
        ).encode("ascii"))
        self.assertEqual({entry.name for entry in self.archive_dir.iterdir()},
                         {filename(target) for target in TARGETS} | {"SHA256SUMS.txt"})

    def test_extract_preserves_exact_member_bytes_and_refuses_existing_directory(self):
        for target in (LINUX, WINDOWS):
            with self.subTest(target=target):
                bundle = self.fixture(target)
                archive = self.package(target, bundle)
                staged = self.extract(target, archive)
                for entry in bundle.iterdir():
                    copy = staged / entry.name
                    self.assertEqual(copy.read_bytes(), entry.read_bytes())
                    if os.name != "nt":
                        self.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o755 if entry.name.startswith("exacopy") else 0o644)
                self.extract(target, archive, refuses="File exists" if os.name != "nt" else "already exists")
                shutil.rmtree(staged)

    def test_refuses_wrong_version_and_preserves_output_incumbent(self):
        bundle = self.fixture(LINUX)
        self.package(LINUX, bundle, version="v" + VERSION, refuses="expected canonical workspace version")
        self.archive_dir.mkdir()
        output = self.archive_dir / filename(LINUX)
        output.write_bytes(b"incumbent release artifact")
        self.package(LINUX, bundle, refuses="File exists" if os.name != "nt" else "already exists")
        self.assertEqual(output.read_bytes(), b"incumbent release artifact")
        self.assertEqual(list(self.archive_dir.iterdir()), [output])

    def test_refuses_untrusted_publishers_and_unauthenticated_manifest(self):
        bundle = self.fixture(LINUX)
        self.package(LINUX, bundle, pin="1" * 64, refuses="independently approved pin")
        manifest = bundle / "release.manifest"
        manifest.write_bytes(manifest.read_bytes().replace(b"sequence=9", b"sequence=8"))
        self.package(LINUX, bundle, refuses="OpenSSL rejected release dgst verification")
        self.assertEqual(list(self.archive_dir.iterdir()), [])

    def test_refuses_mismatched_signed_target_binary_size_and_evidence(self):
        mutations = (
            ({"target": WINDOWS}, "expected target"),
            ({"sha256": "1" * 64}, "expected sha256"),
            ({"size": 5}, "expected size"),
            ({"publisher_sha256": "1" * 64}, "approved pin"),
            ({"min_abi": "2.34"}, "below the offline profile"),
            ({"sbom_sha256": "1" * 64}, "sbom_sha256"),
            ({"provenance_sha256": "1" * 64}, "provenance_sha256"),
        )
        for fields, diagnostic in mutations:
            with self.subTest(fields=fields):
                self.package(LINUX, self.fixture(LINUX, **fields), refuses=diagnostic)
        self.assertEqual(list(self.archive_dir.iterdir()), [])

    def test_refuses_unexpected_bundle_members_links_and_oversized_executable(self):
        bundle = self.fixture(LINUX)
        foreign = bundle / "reference.txt"
        foreign.write_bytes(b"foreign")
        self.package(LINUX, bundle, refuses="unexpected release entry")
        foreign.unlink()
        artifact = bundle / "exacopy"
        artifact.unlink()
        if os.name != "nt":
            artifact.symlink_to(self.cert)
            self.package(LINUX, bundle, refuses="bounded regular file")
            artifact.unlink()
        with artifact.open("wb") as output:
            output.truncate(256 * 1024 * 1024 + 1)
        self.package(LINUX, bundle, refuses="bounded regular file")
        self.assertFalse(self.archive_dir.exists())

    def test_refuses_tar_traversal_symlink_and_extra_member(self):
        bundle = self.fixture(LINUX)
        archive_path = self.package(LINUX, bundle)
        source = gzip.decompress(archive_path.read_bytes())
        for name, entry_type in (("../release.manifest", tarfile.REGTYPE), ("release.manifest", tarfile.SYMTYPE)):
            with self.subTest(name=name, entry_type=entry_type):
                entry = tarfile.TarInfo(name)
                entry.type = entry_type
                entry.size = len((bundle / "release.manifest").read_bytes())
                archive_path.write_bytes(gzip.compress(entry.tobuf(tarfile.USTAR_FORMAT) + source[512:], mtime=0))
                self.extract(LINUX, archive_path, refuses="invalid USTAR entry")
                self.assertFalse((self.root / "staged").exists())
        last = ((len((bundle / "release.manifest").read_bytes()) + 511) // 512 + 1
                + (len((bundle / "release.sig").read_bytes()) + 511) // 512 + 1
                + (len(PAYLOAD) + 511) // 512 + 1) * 512
        entry = tarfile.TarInfo("fourth")
        archive_path.write_bytes(gzip.compress(source[:last] + entry.tobuf(tarfile.USTAR_FORMAT) + source[last + 512:], mtime=0))
        self.extract(LINUX, archive_path, refuses="unexpected archive member")
        self.assertFalse((self.root / "staged").exists())

    def test_refuses_zip_local_name_crc_and_archive_comment(self):
        archive_path = self.package(WINDOWS, self.fixture(WINDOWS))
        original = archive_path.read_bytes()
        wrong_name = original[:30] + b"invalid.manifest" + original[46:]
        corrupted_bytes = original[:46] + bytes([original[46] ^ 1]) + original[47:]
        archive_comment = original[:-2] + b"\x01\x00x"
        for mutated, diagnostic in ((wrong_name, "invalid ZIP local header"),
                                    (corrupted_bytes, "Bad CRC-32"),
                                    (archive_comment, "invalid classic ZIP central directory")):
            with self.subTest(diagnostic=diagnostic):
                archive_path.write_bytes(mutated)
                self.extract(WINDOWS, archive_path, refuses=diagnostic)
                self.assertFalse((self.root / "staged").exists())

    def test_checksum_refuses_partial_unknown_and_malformed_inputs(self):
        for target in TARGETS:
            self.package(target, self.fixture(target))
        missing = self.archive_dir / filename(WINDOWS)
        original = missing.read_bytes()
        missing.unlink()
        self.checksums(refuses="missing release entries")
        self.assertFalse((self.archive_dir / "SHA256SUMS.txt").exists())
        missing.write_bytes(original)
        foreign = self.archive_dir / "unknown-release.tar.gz"
        foreign.write_bytes(b"foreign")
        self.checksums(refuses="unexpected release entry")
        foreign.unlink()
        missing.write_bytes(b"PK broken ZIP")
        self.checksums(refuses="truncated ZIP archive")
        self.assertFalse((self.archive_dir / "SHA256SUMS.txt").exists())


if __name__ == "__main__":
    unittest.main()
