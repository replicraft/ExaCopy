#!/usr/bin/env python3
"""Build and exercise a tag-bound ExaCopy CLI candidate on a native CI runner."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import apfs_source
import installer_fixture
import sbom_release
import transport_source

ASSETS = {
    "x86_64-unknown-linux-gnu": "exacopy-cli-x86_64-unknown-linux-gnu.tar.gz",
    "aarch64-apple-darwin": "exacopy-cli-aarch64-apple-darwin.tar.gz",
    "x86_64-pc-windows-msvc": "exacopy-cli-x86_64-pc-windows-msvc.zip",
}
CARGO = ["cargo", "+1.100.0"]
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){2}")
COMMIT = re.compile(r"[0-9a-f]{40}")
PACKAGER = [sys.executable, "-B", ROOT / "tools/release/package.py"]
SCOPE = "GitHub Actions fixture signed by an ephemeral key"


def git(*args):
    return sbom_release.output("git", "--no-replace-objects", *args, cwd=ROOT)


def check_source(ref, commit):
    prefix = "refs/tags/v"
    if not ref.startswith(prefix) or not VERSION.fullmatch(ref[len(prefix):]):
        raise ValueError("select a canonical vMAJOR.MINOR.PATCH Git tag when dispatching this workflow")
    if not COMMIT.fullmatch(commit):
        raise ValueError("the workflow commit must be a complete lowercase hexadecimal object ID")
    if git("rev-parse", "HEAD") != commit or git("rev-parse", "--verify", f"{ref}^{{commit}}") != commit:
        raise ValueError("checkout HEAD and the tag must both resolve to the workflow commit")
    if git("status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("release candidates require a clean source checkout")
    version = ref[len(prefix):]
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    cli = tomllib.loads((ROOT / "apps/exacopy-cli/Cargo.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    locked = [item["version"] for item in lock["package"] if item["name"] == "exacopy-cli" and "source" not in item]
    if (
        workspace["workspace"]["package"]["version"] != version
        or cli["package"]["name"] != "exacopy-cli"
        or cli["package"]["version"] != {"workspace": True}
        or locked != [version]
    ):
        raise ValueError("Git tag, workspace version, inherited CLI version and locked package must agree")
    return version


def check_toolchain(target):
    rustc = sbom_release.output("rustc", "+1.100.0", "-vV")
    cargo = sbom_release.output(*CARGO, "-V", "--verbose")
    release = "release: 1.100.0"
    if release not in rustc.splitlines() or release not in cargo.splitlines() or f"host: {target}" not in rustc.splitlines():
        raise ValueError("the pinned Rust and Cargo toolchain must run natively on the selected target")
    return rustc, cargo


def inspect_artifact_floors(target, executable, evidence):
    if target == "x86_64-unknown-linux-gnu":
        host_abi = sbom_release.output("getconf", "GNU_LIBC_VERSION")
        imports = sbom_release.output("readelf", "--version-info", executable)
        versions = {tuple(map(int, match.split("."))) for match in re.findall(r"\bGLIBC_([0-9.]+)\b", imports)}
        (evidence / "elf-version-info.txt").write_text(imports + "\n", encoding="utf-8")
        if host_abi != "glibc 2.35" or not versions or max(versions) > (2, 35):
            raise ValueError("Linux CLI requires a runtime and imported glibc versions within the 2.35 ABI floor")
        return {"host_glibc": host_abi, "highest_imported_glibc": ".".join(map(str, max(versions)))}
    if target == "aarch64-apple-darwin":
        commands = sbom_release.output("otool", "-l", executable)
        (evidence / "macho-load-commands.txt").write_text(commands + "\n", encoding="utf-8")
        deployment = re.findall(r"^\s*minos (\S+)$", commands, re.MULTILINE)
        if deployment != ["14.0"]:
            raise ValueError("the Mach-O build deployment target differs from the expected macOS 14.0 baseline")
        return {"build_deployment_target": deployment[0], "host_macos": platform.mac_ver()[0]}
    return {"host_windows": platform.version()}


def create_build(target, evidence, work, ref, commit, version):
    rustc, cargo = check_toolchain(target)
    source_archive = work / "source.tar"
    apfs_archive = work / "apfs.tar"
    subprocess.run(
        ["git", "--no-replace-objects", "-c", "tar.umask=0002", "archive", "--format=tar",
         "--output", source_archive, commit], cwd=ROOT, check=True,
    )
    pin = apfs_source.read_pin((ROOT / apfs_source.PIN).read_text(encoding="utf-8"))
    apfs_source.archive_apfs(ROOT, pin, apfs_archive)
    source = sbom_release.extract_sources(work / "inputs", source_archive, apfs_archive, target=target)
    transport_pins = transport_source.read_pins(source)
    transport_source.verify_manifests(source)
    transport_archives = transport_source.archive_sources(ROOT, transport_pins, work)
    transport_source.extract_sources(source, transport_archives, transport_pins)
    apfs_source.verify_consumer(*(
        tomllib.loads((source / path).read_text(encoding="utf-8"))
        for path in ("Cargo.toml", apfs_source.CONSUMER_MANIFEST)
    ))
    epoch = git("show", "-s", "--format=%ct", commit)
    apfs_layout = sbom_release.project_release_sources(source, target, apfs_archive)
    env = sbom_release.build_environment(work, epoch, target)
    subprocess.run([*CARGO, "fetch", "--locked", "--target", target], cwd=source, env=env, check=True)
    if apfs_layout is not None:
        sbom_release.verify_projected_apfs_tree(source, apfs_archive)
    target_dir = work / "cargo-target"
    command = [
        *CARGO, "build", "--release", "--locked", "--offline", "--no-default-features",
        "-p", "exacopy-cli", "--bin", "exacopy", "--target", target,
        "--target-dir", str(target_dir), "--message-format=json-render-diagnostics",
    ]
    print(subprocess.list2cmdline(command), flush=True)
    messages = evidence / "cargo.jsonl"
    with messages.open("wb") as stream:
        subprocess.run(command, cwd=source, env=env, stdout=stream, check=True)
    with messages.open(encoding="utf-8") as stream:
        units, (root_id, executable), origins = sbom_release.build_inputs(stream)
    filename = installer_fixture.TARGETS[target][2]
    expected = target_dir / target / "release" / filename
    if executable.resolve() != expected.resolve() or executable.is_symlink() or not executable.is_file():
        raise ValueError("Cargo returned an unexpected executable path")
    if not 0 < executable.stat().st_size <= 256 * 1024 * 1024 or any(features for _, features in units[root_id]):
        raise ValueError("expected a bounded CLI executable built with no CLI features")
    if any(
        feature.startswith("experimental-")
        for package_units in units.values() for _, features in package_units for feature in features.split(",")
    ):
        raise ValueError("an experimental dependency feature entered the main CLI artifact")
    sbom = evidence / "exacopy.cdx.json"
    artifact_hash = sbom_release.sha256(executable)
    sbom_release.write_sbom(
        source, env, sbom, target, commit, artifact_hash, units, root_id, pin, transport_pins, apfs_layout,
        origins=origins,
    )
    provenance = evidence / "build-provenance.json"
    sbom_release.write_json(provenance, {
        "schema": "exacopy-ci-candidate-build-v1",
        "scope": "unsigned native artifact from a single CI build",
        "repository": os.environ["GITHUB_REPOSITORY"],
        "tag": ref.removeprefix("refs/tags/"),
        "commit": commit,
        "tree": git("rev-parse", "HEAD^{tree}"),
        "version": version,
        "dirty": False,
        "target": target,
        "profile": "release",
        "features": [],
        "source_date_epoch": int(epoch),
        "source_tar_sha256": sbom_release.sha256(source_archive),
        "lockfile_sha256": sbom_release.sha256(source / "Cargo.lock"),
        "apfs_source": {"repository": apfs_source.REPOSITORY, **pin},
        "transport_sources": transport_pins,
        "binary": {"name": filename, "sha256": artifact_hash, "size": executable.stat().st_size},
        "sbom_sha256": sbom_release.sha256(sbom),
        "cargo_messages_sha256": sbom_release.sha256(messages),
        "command": command,
        "rustflags": env["CARGO_ENCODED_RUSTFLAGS"],
        "artifact_floor_observations": inspect_artifact_floors(target, executable, evidence),
        "rustc": rustc,
        "cargo": cargo,
        "python": sys.version,
        "runner": {
            "os": platform.platform(),
            "machine": platform.machine(),
            "image_version": os.environ.get("ImageVersion"),
            "run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        },
    } | ({"apfs_build_layout": apfs_layout} if apfs_layout is not None else {}))
    return executable, sbom, provenance


def sign_fixture(target, version, executable, sbom, provenance, work):
    floor, abi, name = installer_fixture.TARGETS[target]
    now = int(time.time())
    certificate = work / "fixture-publisher.der"
    with tempfile.TemporaryDirectory(prefix="ephemeral-signing-", dir=work) as secret_dir:
        key = Path(secret_dir) / "private.pem"
        pem = Path(secret_dir) / "certificate.pem"
        installer_fixture.openssl(
            "req", "-new", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1",
            "-subj", "/CN=ExaCopy CI fixture only/", "-keyout", key, "-out", pem,
        )
        installer_fixture.openssl("x509", "-in", pem, "-outform", "DER", "-out", certificate)
        manifest = installer_fixture.encoded({
            "schema": "exacopy-release-v1",
            "version": version,
            "channel": "stable",
            "created": now - 60,
            "expires": now + 6 * 3600,
            "sequence": 1,
            "target": target,
            "variant": "cli",
            "format": "raw",
            "artifact": name,
            "size": executable.stat().st_size,
            "sha256": sbom_release.sha256(executable),
            "publisher_sha256": sbom_release.sha256(certificate),
            "min_os": floor,
            "min_abi": abi,
            "sbom_sha256": sbom_release.sha256(sbom),
            "provenance_sha256": sbom_release.sha256(provenance),
        })
        installer_fixture.bundle(work, "signed-fixture", manifest, executable, name, key)
    return work / "signed-fixture", certificate


def verify_fixture_signature(bundle, certificate, work):
    key = work / "public-key.pem"
    with key.open("wb") as stream:
        subprocess.run(
            ["openssl", "x509", "-in", certificate, "-inform", "DER", "-noout", "-pubkey"],
            stdout=stream, check=True, timeout=30,
        )
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", key, "-signature", bundle / "release.sig",
         bundle / "release.manifest"], check=True, timeout=30,
    )


def probe_cli(executable, version, work):
    help_text = subprocess.check_output([executable, "--help"], cwd=work, timeout=30, text=True)
    if "Usage: exacopy" not in help_text:
        raise ValueError("the executable did not emit the expected CLI usage")
    version_text = subprocess.check_output([executable, "--version"], cwd=work, timeout=30, text=True)
    if version_text.splitlines()[:1] != [f"exacopy {version}"]:
        raise ValueError("the executable's reported version differs from the release tag")
    print(help_text, version_text, flush=True)


def probe_package(target, version, executable, sbom, provenance, work, assets):
    bundle, certificate = sign_fixture(target, version, executable, sbom, provenance, work)
    extracted = work / "extracted-fixture"
    assets.mkdir()
    archive = assets / ASSETS[target]
    common = ["--target", target, "--version", version]
    subprocess.run([
        *PACKAGER, "archive", *common, "--bundle", bundle, "--output-dir", assets,
        "--publisher-cert", certificate, "--publisher-sha256", sbom_release.sha256(certificate),
        "--sbom", sbom, "--provenance", provenance,
    ], check=True)
    subprocess.run([*PACKAGER, "extract", *common, "--archive", archive, "--bundle", extracted], check=True)
    verify_fixture_signature(extracted, certificate, work)
    staged = extracted / executable.name
    if sbom_release.sha256(staged) != sbom_release.sha256(executable):
        raise ValueError("the extracted CLI differs from the Cargo executable")
    probe_cli(staged, version, work)
    if target.endswith("-linux-gnu"):
        subprocess.run([sys.executable, "-B", ROOT / "tools/contracts/check_cli.py", staged], check=True)
    if target.endswith("-windows-msvc"):
        subprocess.run([
            "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
            ROOT / "tools/install/windows/test.ps1", "-Artifact", staged,
        ], check=True)
    else:
        subprocess.run([
            sys.executable, "-B", ROOT / "tools/installer/test_posix.py", "--artifact", staged,
        ], check=True)
    return archive, certificate


def build_candidate(target, output, ref, commit, version, require_reproducible):
    output.mkdir()
    evidence = output / "build"
    evidence.mkdir()
    work_parent = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="exacopy-release-candidate-", dir=work_parent) as temporary:
        work = Path(temporary)
        executable, sbom, provenance = create_build(target, evidence, work, ref, commit, version)
        if require_reproducible:
            second_work = work / "rebuild"
            second_evidence = output / "rebuild"
            second_work.mkdir()
            second_evidence.mkdir()
            rebuilt, rebuilt_sbom, _ = create_build(target, second_evidence, second_work, ref, commit, version)
            if (
                sbom_release.sha256(executable) != sbom_release.sha256(rebuilt)
                or sbom_release.sha256(sbom) != sbom_release.sha256(rebuilt_sbom)
            ):
                raise ValueError(f"{target}: independent build directories produced different CLI or SBOM digests")
            print(f"{target}: matching CLI and SBOM digests from two independent build directories")
        archive, certificate = probe_package(target, version, executable, sbom, provenance, work, output / "fixture")
        trust = output / "fixture-trust"
        trust.mkdir()
        shutil.copy2(certificate, trust / certificate.name)
        (trust / "fixture-publisher.sha256").write_text(sbom_release.sha256(certificate) + "\n", encoding="ascii")
        binary = output / "unsigned-cli"
        binary.mkdir()
        shutil.copy2(executable, binary / executable.name)
        sbom_release.write_json(evidence / "fixture-package.json", {
            "scope": SCOPE,
            "target": target,
            "archive": archive.name,
            "archive_sha256": sbom_release.sha256(archive),
            "manifest_and_signature_verified": True,
            "same_executable_as_unsigned_cli": True,
            "native_help_and_offline_installer_tests": "pass",
            "release_authorization": "blocked",
            "open_release_gates": [
                "production publisher certificate and approved signing",
                "applicable native platform signatures",
                "release profile qualification and revision-bound assurance review",
            ],
        })
    check_source(ref, commit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check-source")
    build = commands.add_parser("build")
    build.add_argument("--target", choices=ASSETS, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--require-reproducible", action="store_true")
    options = parser.parse_args()
    try:
        ref = os.environ["GITHUB_REF"]
        commit = os.environ["GITHUB_SHA"]
        version = check_source(ref, commit)
        print(f"Candidate {ref} @ {commit} (version {version})", flush=True)
        if options.command == "build":
            build_candidate(options.target, options.output.resolve(), ref, commit, version, options.require_reproducible)
    except (
        OSError, KeyError, TypeError, ValueError, tarfile.TarError,
        subprocess.CalledProcessError, subprocess.TimeoutExpired,
    ) as error:
        parser.exit(1, f"release candidate: {error}\n")


if __name__ == "__main__":
    main()
