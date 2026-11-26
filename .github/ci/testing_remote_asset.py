#!/usr/bin/env python3
"""Build the separate unsigned Linux SSH and WireGuard user-testing archive."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

import release_candidate
import remote_qualification as native

TARGET = "x86_64-unknown-linux-gnu"


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


def smoke(binary, version):
    for args, expected in ((["--version"], f"exacopy {version}"), (["get", "--help"], "exacopy get"),
                           (["recover", "remote-resume", "--help"], "exacopy recover remote-resume")):
        done = subprocess.run([binary, *args], check=True, capture_output=True, text=True, timeout=30)
        if expected not in done.stdout:
            raise ValueError(f"experimental CLI did not expose expected output for {' '.join(args)}")
        print(done.stdout, end="")


def build(output, evidence, version, commit):
    with tempfile.TemporaryDirectory(prefix="exacopy-remote-test-") as work:
        target = Path(work).resolve()
        env = native.build_environment(target)
        selected = target / "verified-exacopy"
        binary, manifest = native.build_cli(native.EMBEDDED, evidence, target, env, staged_executable=selected)
        observed = json.loads(manifest.read_text(encoding="utf-8"))
        if observed["source_before"]["revision"] != commit:
            raise ValueError("experimental CLI build source differs from the release commit")
        release_candidate.inspect_artifact_floors(TARGET, binary, evidence)
        smoke(binary, version)
        payload = binary.read_bytes()
        asset_digest = hashlib.sha256(payload).hexdigest()
        if asset_digest != observed["build_sha256"]:
            raise ValueError("experimental CLI bytes differ from the verified build digest")
        license_bytes = subprocess.check_output(["git", "--no-replace-objects", "show", f"{commit}:LICENSE"])
        output.mkdir()
        asset = output / f"exacopy-cli-v{version}-{TARGET}-experimental-ssh-wireguard.tar.gz"
        write_archive(asset, payload, license_bytes)
        receipt = asset.with_suffix(asset.suffix + ".sha256")
        receipt.write_text(f"{digest(asset)}  {asset.name}\n", encoding="ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    try:
        commit = os.environ["GITHUB_SHA"]
        version = release_candidate.check_source(os.environ["GITHUB_REF"], commit)
        release_candidate.check_toolchain(TARGET)
        build(args.output, args.evidence, version, commit)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"remote testing asset: {error}\n")


if __name__ == "__main__":
    main()
