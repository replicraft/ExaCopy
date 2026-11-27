#!/usr/bin/env python3
"""Build the separate unsigned Linux SSH and WireGuard user-testing archive."""

import argparse
from contextlib import contextmanager
import gzip
import hashlib
import io
import json
import shutil
import os
from pathlib import Path
import subprocess
import stat
import sys
import tarfile
import tempfile
import zlib

import release_candidate
import remote_qualification as native

TARGET = "x86_64-unknown-linux-gnu"
PREVIEW_TAG = "v0.1.0-preview.2"
PREVIEW_BASE = "0.1.0"
PREVIEW_REF = f"refs/tags/{PREVIEW_TAG}"
ROUTE_FEATURE = "experimental-ssh-wireguard"
SBOM_NAME = "exacopy-experimental-ssh-wireguard.cdx.json"
PROVENANCE_NAME = "build-provenance-experimental-ssh-wireguard.json"
NOTICES_NAME = "THIRD-PARTY-NOTICES.txt"


def check_source(ref, commit):
    if ref == PREVIEW_REF:
        return release_candidate.check_source_version(ref, commit, PREVIEW_BASE), PREVIEW_TAG
    version = release_candidate.check_source(ref, commit)
    return version, f"v{version}"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_archive(path, binary, license_text):
    with path.open("xb") as output, gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data, mode in (("exacopy", binary, 0o755), ("LICENSE", license_text, 0o644)):
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode = len(data), mode
                archive.addfile(entry, io.BytesIO(data))


def read_archive(path, elf_size, license_text):
    if type(elf_size) is not int or not 0 < elf_size <= 256 * 1024 * 1024 or not 0 < len(license_text) <= 64 * 1024:
        raise ValueError("preview contents exceed the archive bounds")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        details = os.fstat(stream.fileno())
        size = details.st_size
        if not stat.S_ISREG(details.st_mode) or not 0 < size <= elf_size + len(license_text) + 1024 * 1024:
            raise ValueError("preview compressed archive exceeds the expected bounds")
        data = stream.read(size + 1)
    if len(data) != size:
        raise ValueError("preview archive changed while reading its bytes")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        plain = decoder.decompress(data, elf_size + len(license_text) + 16 * 1024)
    except zlib.error as error:
        raise ValueError("invalid preview gzip stream") from error
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("expected one complete preview gzip stream")

    expected = (("exacopy", elf_size, 0o755), ("LICENSE", len(license_text), 0o644))
    offset = 0
    elf = None
    for name, length, mode in expected:
        entry = tarfile.TarInfo(name)
        entry.size, entry.mode = length, mode
        header = entry.tobuf(format=tarfile.USTAR_FORMAT)
        body_start = offset + len(header)
        body_end = body_start + length
        next_header = (body_end + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE * tarfile.BLOCKSIZE
        if (
            len(plain) < next_header or plain[offset:body_start] != header
            or plain[body_end:next_header] != bytes(next_header - body_end)
        ):
            raise ValueError("preview archive member differs from the expected bytes or metadata")
        content = plain[body_start:body_end]
        if name == "exacopy":
            elf = content
        elif content != license_text:
            raise ValueError("preview archive member differs from the expected bytes or metadata")
        offset = next_header

    end = offset + 2 * tarfile.BLOCKSIZE
    padded_end = (end + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE * tarfile.RECORDSIZE
    if plain[offset:] != bytes(padded_end - offset):
        raise ValueError("unexpected preview archive end or padding")
    return {"name": path.name, "sha256": hashlib.sha256(data).hexdigest(), "size": size}, elf


def verify_archive(path, binary, license_text):
    record, payload = read_archive(path, len(binary), license_text)
    if payload != binary:
        raise ValueError("preview archive member differs from the expected bytes or metadata")
    return record


def smoke(binary, version):
    for args, expected in ((["--version"], f"exacopy {version}"), (["get", "--help"], "exacopy get"),
                           (["recover", "remote-resume", "--help"], "exacopy recover remote-resume")):
        done = subprocess.run([binary, *args], check=True, capture_output=True, text=True, timeout=30)
        required = done.stdout.splitlines()[0:1] == [expected] if args == ["--version"] else (
            any(line.startswith(f"Usage: {expected} ") for line in done.stdout.splitlines())
        )
        if not required:
            raise ValueError(f"experimental CLI did not expose expected output for {' '.join(args)}")
        print(done.stdout, end="")


def write_preview_receipts(output, evidence, archive, binary, observed, manifest, env, floors, candidate=None):
    sbom_release = release_candidate.sbom_release
    repo = release_candidate.ROOT
    log = evidence / "build.log"
    if digest(log) != observed["build_log_sha256"]:
        raise ValueError("Cargo build transcript changed after executable verification")
    with log.open(encoding="utf-8") as stream:
        units, (root, executable), origins = sbom_release.build_inputs(line for line in stream if line.startswith("{"))
    required = {"experimental-ssh-capture", ROUTE_FEATURE}
    if executable != binary.parent / "release/exacopy" or set(observed["compiled_features"]) != required:
        raise ValueError("preview executable or compiled features differ from the recorded build")
    if digest(executable) != observed["build_sha256"]:
        raise ValueError("Cargo-produced ELF changed before the build receipt")
    sbom = output / SBOM_NAME
    apfs = release_candidate.apfs_source
    pin = apfs.read_pin((repo / apfs.PIN).read_text(encoding="utf-8"))
    transports = release_candidate.transport_source.read_pins(repo)
    source = observed["source_after"]
    sbom_release.write_sbom(
        repo, env, sbom, TARGET, source["revision"], observed["build_sha256"],
        units, root, pin, transports, origins=origins,
        selected_features=(f"exacopy-cli/{ROUTE_FEATURE}",),
    )
    receipt = {
        "schema": "exacopy-testing-preview-build-v1",
        "scope": "unsigned Linux x86-64 user-testing archive",
        "tag": PREVIEW_TAG,
        "workspace_version": PREVIEW_BASE,
        "rust_toolchain": "1.100.0",
        "target": TARGET,
        "source": source,
        "workflow": {
            key: os.environ[key] for key in ("GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")
        },
        "cargo_args": observed["argv"],
        "compiled_features": observed["compiled_features"],
        "apfs_source": pin,
        "transport_sources": transports,
        "build_receipt_sha256": digest(manifest),
        "cargo_messages_sha256": digest(log),
        "binary": {"name": "exacopy", "sha256": observed["build_sha256"], "size": observed["build_size"]},
        "archive": archive,
        "sbom_sha256": digest(sbom),
        "abi": floors,
        "exact_elf_campaigns": "pending",
    }
    if candidate is not None:
        from preview_release_notices import write_notices

        if source != candidate["source"]:
            raise ValueError("candidate build source differs from the admitted main request")
        del receipt["tag"]
        notices = output / NOTICES_NAME
        write_notices(notices, sbom, repo, Path(env.get("CARGO_HOME", Path.home() / ".cargo")), source, transports)
        receipt.update(
            schema="exacopy-main-preview-build-v1", intended_tag=PREVIEW_TAG,
            workflow=candidate["workflow"], request_sha256=candidate["request_sha256"],
            notices_sha256=digest(notices),
        )
    sbom_release.write_json(output / PROVENANCE_NAME, receipt)


@contextmanager
def build_target(evidence, candidate):
    if candidate is None:
        with tempfile.TemporaryDirectory(prefix="exacopy-remote-test-") as work:
            yield Path(work).resolve()
        return

    target = Path(tempfile.mkdtemp(prefix="exacopy-main-preview-build-", dir=evidence.parent)).resolve()
    try:
        yield target
    except native.CleanupUnconfirmed:
        evidence.mkdir(mode=0o700, exist_ok=True)
        with (evidence / "cleanup-unconfirmed.json").open("x", encoding="utf-8") as marker:
            json.dump({"target": os.fspath(target), "status": "cleanup-unconfirmed"}, marker)
            marker.write("\n")
        raise
    except BaseException:
        shutil.rmtree(target)
        raise
    else:
        shutil.rmtree(target)


def build(output, evidence, version, tag, commit, *, candidate=None):
    with build_target(evidence, candidate) as target:
        env = native.build_environment(target)
        selected = target / "verified-exacopy"
        binary, manifest = native.build_cli(native.EMBEDDED, evidence, target, env, staged_executable=selected)
        observed = json.loads(manifest.read_text(encoding="utf-8"))
        if observed["source_before"]["revision"] != commit:
            raise ValueError("experimental CLI build source differs from the release commit")
        floors = release_candidate.inspect_artifact_floors(TARGET, binary, evidence)
        smoke(binary, version)
        payload = binary.read_bytes()
        asset_digest = hashlib.sha256(payload).hexdigest()
        if asset_digest != observed["build_sha256"]:
            raise ValueError("experimental CLI bytes differ from the verified build digest")
        license_bytes = subprocess.check_output(["git", "--no-replace-objects", "show", f"{commit}:LICENSE"])
        output.mkdir()
        asset = output / f"exacopy-cli-{tag}-{TARGET}-experimental-ssh-wireguard.tar.gz"
        write_archive(asset, payload, license_bytes)
        if tag == PREVIEW_TAG:
            archive = verify_archive(asset, payload, license_bytes)
            if candidate is not None:
                with (output / "LICENSE").open("xb") as license_file:
                    license_file.write(license_bytes)
            write_preview_receipts(output, evidence, archive, binary, observed, manifest, env, floors, candidate)
            files = [asset]
            if candidate is not None:
                files.extend(output / name for name in (SBOM_NAME, PROVENANCE_NAME, "LICENSE", NOTICES_NAME))
                if set(output.iterdir()) != set(files):
                    raise ValueError("unexpected main preview asset inventory")
            checksums = [
                f"{archive['sha256'] if file == asset else digest(file)}  {file.name}\n" for file in sorted(files)
            ]
            (output / "SHA256SUMS.txt").write_text("".join(checksums), encoding="ascii")
            if candidate is not None:
                native.verified_pins("candidate-post", evidence, env)
                if native.source_identity(release_candidate.ROOT) != candidate["source"]:
                    raise ValueError("candidate source changed during preview packaging")
                native.verify_executable_custody(target / "release/exacopy", binary, observed)
        else:
            asset.with_suffix(asset.suffix + ".sha256").write_text(f"{digest(asset)}  {asset.name}\n", encoding="ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-source", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if (args.check_source and (args.output or args.evidence)) or (
        not args.check_source and (not args.output or not args.evidence)
    ):
        parser.error("select --check-source alone or supply both --output and --evidence")
    try:
        commit = os.environ["GITHUB_SHA"]
        version, tag = check_source(os.environ["GITHUB_REF"], commit)
        if args.check_source:
            print(f"Admitted {tag} at {commit}, workspace version {version}")
            return
        release_candidate.check_toolchain(TARGET)
        build(args.output, args.evidence, version, tag, commit)
    except (ValueError, OSError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, f"remote testing asset: {error}\n")


if __name__ == "__main__":
    main()
