#!/usr/bin/env python3
"""Build the ABI-floor binary for the one frozen v0.1.0 testing prerelease."""

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

TAG = "refs/tags/v0.1.0"
COMMIT = "104451ebfeeb344418ece53ad020e7cbafa72054"
TARGET = "x86_64-unknown-linux-gnu"


def candidate_from_source(source):
    def git(*arguments):
        return subprocess.check_output(
            ["git", "--no-replace-objects", "-C", source, *arguments], text=True, timeout=30,
        ).strip()

    if git("rev-parse", "HEAD") != COMMIT or git("rev-parse", "--verify", f"{TAG}^{{commit}}") != COMMIT:
        raise ValueError("source must be the frozen v0.1.0 commit before importing its tools")
    if git("status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("source must be clean before importing its tools")
    sys.path.insert(0, str(source / ".github/ci"))
    import release_candidate as candidate

    if candidate.ROOT != source:
        raise ValueError("expected the archived release source checkout")
    return candidate


def build(candidate, version, output):
    output.mkdir(mode=0o700)
    evidence = output / "build"
    evidence.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="exacopy-v0.1.0-linux-") as temporary:
        work = Path(temporary)
        binary, sbom, provenance = candidate.create_build(TARGET, evidence, work, TAG, COMMIT, version)
        candidate.probe_cli(binary, version, work)
        bundle, certificate = candidate.sign_fixture(TARGET, version, binary, sbom, provenance, work)
        pin = candidate.sbom_release.sha256(certificate)
        archives = output / "fixture"
        archives.mkdir()
        subprocess.run([
            *candidate.PACKAGER, "archive", "--target", TARGET, "--version", version,
            "--bundle", bundle, "--output-dir", archives, "--publisher-cert", certificate,
            "--publisher-sha256", pin, "--sbom", sbom, "--provenance", provenance,
        ], check=True, timeout=90)
        candidate.verify_fixture_signature(bundle, certificate, work)
        trust = output / "fixture-trust"
        trust.mkdir()
        shutil.copy2(certificate, trust / certificate.name)
        (trust / "fixture-publisher.sha256").write_text(pin + "\n", encoding="ascii")
        unsigned = output / "unsigned-cli"
        unsigned.mkdir()
        shutil.copy2(binary, unsigned / binary.name)
        candidate.sbom_release.write_json(evidence / "testing-recovery.json", {
            "testing_only": True, "source_tag": TAG, "source_commit": COMMIT,
            "compatibility_lane": "Ubuntu 22.04 GNU ABI and the native CLI startup probe",
            "product_contract_lane": "Ubuntu 24.04 exact archive verification",
        })


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("command", choices=("check-source", "build-linux"))
    cli.add_argument("--source", required=True, type=Path)
    cli.add_argument("--output", type=Path)
    args = cli.parse_args()
    try:
        candidate = candidate_from_source(args.source.resolve(strict=True))
        version = candidate.check_source(TAG, COMMIT)
        print(f"Frozen testing source {TAG} @ {COMMIT}")
        if args.command == "build-linux":
            if args.output is None:
                cli.error("build-linux requires an output directory")
            build(candidate, version, args.output.resolve())
            candidate.check_source(TAG, COMMIT)
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        cli.exit(1, f"testing recovery refused: {error}\n")


if __name__ == "__main__":
    main()
