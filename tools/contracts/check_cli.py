#!/usr/bin/env python3
"""Check the Linux CLI contract markers on an isolated, completed copy."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import uuid


ROOT = Path(__file__).resolve().parents[2]
DIFF = "exacopy.cli.diff"
COPY = "exacopy.cli.copy"
RECOVERY = "exacopy.local_recovery_inspection"
JSON_FLAGS = ("--format", "json")


def run(cli, directory, *args):
    result = subprocess.run(
        [cli, *args], cwd=directory, capture_output=True, check=False, timeout=30,
    )
    if result.returncode:
        diagnostic = result.stderr.decode(errors="replace").strip()
        raise ValueError(f"{' '.join(args)} exited {result.returncode}: {diagnostic}")
    return result.stdout


def read_report(cli, directory, versions, schema, *args):
    report = json.loads(run(cli, directory, *args, *JSON_FLAGS))
    if not isinstance(report, dict):
        raise ValueError(f"{schema}: expected a JSON object")
    actual = report.get("schema"), report.get("schema_version")
    expected = schema, versions[schema]
    if actual != expected:
        raise ValueError(f"expected CLI marker {expected!r}, got {actual!r}")
    return report


def probe(cli, versions):
    with tempfile.TemporaryDirectory(prefix="exacopy-contracts-") as fixture:
        directory = Path(fixture)
        source = b"synthetic CLI contract fixture\n"
        (directory / "source").write_bytes(source)
        (directory / "same").write_bytes(source)
        read_report(cli, directory, versions, DIFF, "diff", "source", "same")
        run(cli, directory, "profile", "init", "profile")
        report = read_report(
            cli, directory, versions, COPY, "copy", "source", "copy", "--profile", "profile",
        )
        receipt = report["receipt"]
        job_id = uuid.UUID(receipt["job_id"])
        job_directory = receipt["job_directory"]
        if job_directory != f".exacopy-{job_id}":
            raise ValueError("copy report does not identify its retained job directory")
        read_report(
            cli, directory, versions, RECOVERY,
            "recover", "inspect", job_directory, "--profile", "profile",
        )
        if (directory / "source").read_bytes() != source or (directory / "copy").read_bytes() != source:
            raise ValueError("source or copy bytes differ from the fixture")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("this contract probe requires the Linux CLI copy profile")
    try:
        with (ROOT / "docs/specs/contracts/versions.toml").open("rb") as stream:
            inventory = tomllib.load(stream)
        versions = {
            contract["id"]: contract["version"]
            for contract in inventory["contract"]
            if contract["kind"] == "cli_output" and contract["status"] == "implemented"
        }
        probe(args.binary.resolve(strict=True), versions)
    except (KeyError, OSError, TypeError, ValueError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"CLI contract probe failed: {error}\n")
    print("Emitted Linux diff, copy and recovery inspection markers match the contract inventory.")


if __name__ == "__main__":
    main()
