#!/usr/bin/env python3
"""Make ephemeral signed release bundles for installer tests. Never issue release trust."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

TARGETS = {
    "aarch64-apple-darwin": ("14.0", "native", "exacopy"),
    "x86_64-apple-darwin": ("14.0", "native", "exacopy"),
    "aarch64-unknown-linux-gnu": ("5.15", "2.35", "exacopy"),
    "x86_64-unknown-linux-gnu": ("5.15", "2.35", "exacopy"),
    "aarch64-pc-windows-msvc": ("10.0.20348", "native", "exacopy.exe"),
    "x86_64-pc-windows-msvc": ("10.0.20348", "native", "exacopy.exe"),
}


def openssl(*arguments):
    subprocess.run(["openssl", *map(os.fspath, arguments)], check=True, capture_output=True)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(fields):
    return "".join(f"{key}={value}\n" for key, value in fields.items()).encode("ascii")


def bundle(output, name, manifest, artifact, artifact_name, key):
    directory = output / name
    directory.mkdir(mode=0o700)
    manifest_path = directory / "release.manifest"
    signature = directory / "release.sig"
    manifest_path.write_bytes(manifest)
    openssl("dgst", "-sha256", "-sign", key, "-out", signature, manifest_path)
    if name == "bad-signature":
        data = signature.read_bytes()
        signature.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    shutil.copyfile(artifact, directory / artifact_name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New output directory")
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--artifact", type=Path, help="Exact local binary, never executed by this tool")
    parser.add_argument("--launcher-upgrade", action="store_true",
                        help="Issue a newer synthetic release with the same certificate")
    args = parser.parse_args()

    old_umask = os.umask(0o077)
    try:
        args.output.mkdir(mode=0o700)
        output = args.output.resolve()
        with tempfile.TemporaryDirectory(prefix="signing-fixture-", dir=output) as temporary:
            secret_dir = Path(temporary)
            key = secret_dir / "private.pem"
            pem = secret_dir / "certificate.pem"
            cert = output / "fixture-publisher.der"
            openssl("req", "-new", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1",
                    "-subj", "/CN=ExaCopy ephemeral test fixture/", "-keyout", key, "-out", pem)
            openssl("x509", "-in", pem, "-outform", "DER", "-out", cert)
            if args.artifact is None:
                artifact = secret_dir / "inert-artifact"
                artifact.write_bytes(b"ExaCopy installer verification fixture. Do not execute.\n")
            else:
                artifact = args.artifact.resolve(strict=True)
            if not artifact.is_file() or not 0 < artifact.stat().st_size <= 256 * 1024 * 1024:
                parser.error("artifact must be a regular file between 1 byte and 256 MiB")
            floor, abi, artifact_name = TARGETS[args.target]
            now = int(time.time())
            fields = {
                "schema": "exacopy-release-v1",
                "version": "0.1.0",
                "channel": "stable",
                "created": now - 60,
                "expires": now + 3600,
                "sequence": 2,
                "target": args.target,
                "variant": "cli",
                "format": "raw",
                "artifact": artifact_name,
                "size": artifact.stat().st_size,
                "sha256": digest(artifact),
                "publisher_sha256": digest(cert),
                "min_os": floor,
                "min_abi": abi,
                "sbom_sha256": hashlib.sha256(b"fixture SBOM reference, not an SBOM").hexdigest(),
                "provenance_sha256": hashlib.sha256(b"fixture provenance reference").hexdigest(),
            }
            valid = encoded(fields)
            mutations = {
                "bad-signature": valid,
                "wrong-target": encoded(fields | {"target": "unsupported-target"}),
                "wrong-hash": encoded(fields | {"sha256": "0" * 64}),
                "wrong-size": encoded(fields | {"size": fields["size"] + 1}),
                "wrong-publisher": encoded(fields | {"publisher_sha256": "0" * 64}),
                "wrong-version": encoded(fields | {"version": "0.1.1"}),
                "expired": encoded(fields | {"created": now - 500, "expires": now - 100}),
                "future": encoded(fields | {"created": now + 60, "expires": now + 500}),
                "lower-sequence": encoded(fields | {"sequence": 1}),
                "same-sequence-other-digest": encoded(fields | {"created": now - 59}),
                "duplicate-field": valid + b"version=0.1.0\n",
                "missing-final-lf": valid[:-1],
                "embedded-nul": valid.replace(b"version=0.1.0\n", b"version=0.1.0\x00\n"),
                "wrong-format": encoded(fields | {"format": "zip"}),
                "crlf": valid.replace(b"\n", b"\r\n"),
            }
            for name, candidate in ({"valid": valid} | mutations).items():
                bundle(output, name, candidate, artifact, artifact_name, key)
            if args.launcher_upgrade:
                upgrade = encoded(fields | {"version": "0.2.0", "sequence": 3})
                bundle(output, "launcher-upgrade", upgrade, artifact, artifact_name, key)
            print(json.dumps({"directory": str(output), "publisher_certificate": str(cert),
                              "publisher_sha256": fields["publisher_sha256"], "target": args.target,
                              "expires": fields["expires"], "version": fields["version"]}, indent=2))
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    main()
