#!/usr/bin/env python3
"""Validate native signing inputs and assemble or publish a fully signed CLI release."""

import argparse
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

import release_candidate as candidate
import transport_source

from installer_fixture import TARGETS, bundle, encoded
from release.package import MAX_ARCHIVE, MAX_EXECUTABLE
from sbom_release import sha256, write_json

LINUX = "x86_64-unknown-linux-gnu"
APPLE = "aarch64-apple-darwin"
WINDOWS = "x86_64-pc-windows-msvc"
HEX = re.compile(r"[0-9a-f]{64}")


def bounded_release_setting(name, value, maximum):
    if not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) > maximum:
        raise ValueError(f"{name} must be a canonical positive decimal no greater than {maximum}")
    return int(value)


def checked(path, maximum=MAX_EXECUTABLE):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError(f"missing or invalid release input {path.name}")
    return path


def load_record(path):
    return json.loads(checked(path, 1024 * 1024).read_bytes())


def verified_build(directory, target, commit, tag, version):
    provenance = load_record(directory / "build/build-provenance.json")
    expected = {
        "schema": "exacopy-ci-candidate-build-v1",
        "repository": os.environ["GITHUB_REPOSITORY"],
        "tag": tag,
        "commit": commit,
        "version": version,
        "dirty": False,
        "target": target,
        "profile": "release",
        "features": [],
        "tree": candidate.git("rev-parse", "HEAD^{tree}"),
        "lockfile_sha256": sha256(candidate.ROOT / "Cargo.lock"),
        "transport_sources": transport_source.read_pins(candidate.ROOT),
    }
    if any(provenance.get(name) != value for name, value in expected.items()):
        raise ValueError(f"{target}: build record does not match the admitted release source")
    runner = provenance["runner"]
    if runner["run_id"] != os.environ["GITHUB_RUN_ID"] or runner["run_attempt"] != os.environ["GITHUB_RUN_ATTEMPT"]:
        raise ValueError(f"{target}: build record is from a different run or attempt")
    binary = checked(directory / "unsigned-cli" / TARGETS[target][2])
    sbom = checked(directory / "build/exacopy.cdx.json", 16 * 1024 * 1024)
    if (
        provenance["binary"] != {"name": binary.name, "size": binary.stat().st_size, "sha256": sha256(binary)}
        or provenance["sbom_sha256"] != sha256(sbom)
    ):
        raise ValueError(f"{target}: unsigned CLI or SBOM bytes differ from the build record")
    return binary, sbom, provenance


def prepare_native(directory, output, target, identity):
    binary, _, _ = verified_build(directory, target, *identity)
    output.mkdir()
    signed_path = output / binary.name
    shutil.copy2(binary, signed_path)
    if target == APPLE:
        signed_path.chmod(0o700)


def record_native(directory, output, target, identity):
    unsigned, _, _ = verified_build(directory, target, *identity)
    binary = checked(output / unsigned.name)
    if sha256(unsigned) == sha256(binary):
        raise ValueError(f"{target}: native signing did not change the CLI executable")
    candidate.probe_cli(binary, identity[2], output)
    report = checked(output / "native-signature.txt", 1024 * 1024)
    write_json(output / "native-signature.json", {
        "target": target,
        "original_sha256": sha256(unsigned),
        "signed_sha256": sha256(binary),
        "native_signer_report_sha256": sha256(report),
        "github_run_id": os.environ["GITHUB_RUN_ID"],
        "github_run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
    })


def verified_native(directory, target, unsigned):
    binary = checked(directory / unsigned.name)
    report = checked(directory / "native-signature.txt", 1024 * 1024)
    record = load_record(directory / "native-signature.json")
    expected = {
        "target": target,
        "original_sha256": sha256(unsigned),
        "signed_sha256": sha256(binary),
        "native_signer_report_sha256": sha256(report),
        "github_run_id": os.environ["GITHUB_RUN_ID"],
        "github_run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
    }
    if record != expected or record["original_sha256"] == record["signed_sha256"]:
        raise ValueError(f"{target}: the native signature evidence does not bind these CLI bytes")
    return binary, record


def production_key(work):
    pem = os.environ.pop("EXACOPY_RELEASE_PRIVATE_KEY_PEM", "")
    encoded_der = os.environ.pop("EXACOPY_RELEASE_PUBLISHER_CERT_DER_B64", "")
    pin = os.environ.pop("EXACOPY_RELEASE_PUBLISHER_SHA256", "")
    if not pem or not encoded_der or not HEX.fullmatch(pin):
        raise ValueError(
            "production signing requires EXACOPY_RELEASE_PRIVATE_KEY_PEM, "
            "EXACOPY_RELEASE_PUBLISHER_CERT_DER_B64 and EXACOPY_RELEASE_PUBLISHER_SHA256"
        )
    if len(pem) > 32768 or len(encoded_der) > 22000:
        raise ValueError("production signing material exceeds release profile limits")
    key = work / "private-key.pem"
    descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(pem.encode("ascii") + b"\n")
    certificate = work / "publisher.der"
    certificate.write_bytes(base64.b64decode(encoded_der, validate=True))
    if sha256(checked(certificate, 16384)) != pin:
        raise ValueError("configured publisher certificate differs from the independently approved pin")
    return key, certificate, pin


def sign(args, identity):
    commit, tag, version = identity
    sequence = bounded_release_setting("release sequence", args.sequence, 2147483647)
    now = int(time.time())
    days = bounded_release_setting(
        "EXACOPY_RELEASE_VALIDITY_DAYS", os.environ.get("EXACOPY_RELEASE_VALIDITY_DAYS", ""),
        (9_999_999_999 - now) // 86400,
    )
    args.output.mkdir()
    assets = args.output / "assets"
    evidence = args.output / "evidence"
    trust = args.output / "trust"
    assets.mkdir()
    evidence.mkdir()
    trust.mkdir()
    with tempfile.TemporaryDirectory(prefix="exacopy-production-signer-") as temporary:
        work = Path(temporary)
        key, certificate, pin = production_key(work)
        # Verifiers receive public material. Their pin comes from the protected environment.
        shutil.copyfile(certificate, trust / "publisher.der")
        for target in candidate.ASSETS:
            unsigned_dir = args.unsigned / f"release-unsigned-{target}-{os.environ['GITHUB_RUN_ATTEMPT']}"
            unsigned, sbom, build = verified_build(unsigned_dir, target, commit, tag, version)
            binary = unsigned
            native_signature = None
            if target != LINUX:
                native_dir = args.native / f"release-native-signed-{target}-{os.environ['GITHUB_RUN_ATTEMPT']}"
                binary, native_signature = verified_native(native_dir, target, unsigned)
            prefix = f"exacopy-cli-{target}"
            release_sbom = evidence / f"{prefix}.cdx.json"
            shutil.copyfile(sbom, release_sbom)
            provenance = evidence / f"{prefix}.provenance.json"
            write_json(provenance, {
                "schema": "exacopy-ci-signed-release-v1",
                "build": build,
                "distributed_binary_sha256": sha256(binary),
                "native_signature": native_signature,
                "publisher_sha256": pin,
            })
            floor, abi, name = TARGETS[target]
            manifest = encoded({
                "schema": "exacopy-release-v1",
                "version": version,
                "channel": "stable",
                "created": now - 60,
                "expires": now + days * 86400,
                "sequence": sequence,
                "target": target,
                "variant": "cli",
                "format": "raw",
                "artifact": name,
                "size": binary.stat().st_size,
                "sha256": sha256(binary),
                "publisher_sha256": pin,
                "min_os": floor,
                "min_abi": abi,
                "sbom_sha256": sha256(release_sbom),
                "provenance_sha256": sha256(provenance),
            })
            bundle(work, target, manifest, binary, name, key)
            subprocess.run([
                *candidate.PACKAGER, "archive", "--target", target, "--version", version,
                "--bundle", work / target, "--output-dir", assets, "--publisher-cert", certificate,
                "--publisher-sha256", pin, "--sbom", release_sbom, "--provenance", provenance,
            ], check=True)
        subprocess.run([*candidate.PACKAGER, "checksums", "--artifact-dir", assets, "--version", version], check=True)
    subprocess.run(["sha256sum", "--strict", "-c", "SHA256SUMS.txt"], cwd=assets, check=True)


def required_success(identity):
    commit, tag, _ = identity
    if os.environ.get("GITHUB_REF_PROTECTED") != "true":
        raise ValueError("publication requires a release tag protected by a GitHub ruleset")
    repository = os.environ["GITHUB_REPOSITORY"]
    for workflow in ("ci.yml", "installers.yml"):
        endpoint = f"repos/{repository}/actions/workflows/{workflow}/runs?head_sha={commit}&branch=main&event=push&per_page=100"
        runs = json.loads(subprocess.check_output(["gh", "api", endpoint], text=True, timeout=30))
        matching = [
            run for run in runs["workflow_runs"]
            if run["head_sha"] == commit and run["head_branch"] == "main" and run["event"] == "push"
        ]
        if not matching or matching[0]["status"] != "completed" or matching[0]["conclusion"] != "success":
            raise ValueError(f"{tag}: {workflow} must have a successful push-to-main run for {commit}")


def require_immutability(repository, token):
    if not token:
        raise ValueError("publication requires EXACOPY_IMMUTABILITY_READ_TOKEN with repository Administration read access")
    try:
        result = subprocess.check_output(
            ["gh", "api", f"repos/{repository}/immutable-releases", "-H", "X-GitHub-Api-Version: 2026-03-10"],
            env={**os.environ, "GH_TOKEN": token}, text=True, timeout=30,
        )
    except subprocess.CalledProcessError as error:
        raise ValueError("enable GitHub immutable releases and supply a valid Administration read token") from error
    if json.loads(result).get("enabled") is not True:
        raise ValueError("GitHub immutable releases must be enabled before publication")


def publish(output, identity):
    _, tag, version = identity
    repository = os.environ["GITHUB_REPOSITORY"]
    ref = os.environ["GITHUB_REF"]
    local_ref = candidate.git("rev-parse", ref)
    administration_read_token = os.environ.pop("EXACOPY_IMMUTABILITY_READ_TOKEN", "")
    require_immutability(repository, administration_read_token)
    releases = json.loads(subprocess.check_output(
        ["gh", "api", "--paginate", "--slurp", f"repos/{repository}/releases?per_page=100"],
        text=True, timeout=30,
    ))
    expected_version = tuple(map(int, version.split(".")))
    for page in releases:
        for item in page:
            if item["tag_name"] == tag:
                raise ValueError("a release or draft already exists for this tag; reconcile it before creating a release")
            name = item["tag_name"]
            if not item["draft"] and not item["prerelease"] and name.startswith("v") and candidate.VERSION.fullmatch(name[1:]):
                if tuple(map(int, name[1:].split("."))) >= expected_version:
                    raise ValueError("the selected version must advance beyond the existing stable releases")
    archives = [output / "assets" / asset for asset in candidate.ASSETS.values()]
    files = [*archives, output / "assets/SHA256SUMS.txt"]
    for target in candidate.ASSETS:
        files.extend(output / f"evidence/exacopy-cli-{target}.{kind}.json" for kind in ("cdx", "provenance"))
    expected = {}
    for path in files:
        limit = MAX_ARCHIVE if path in archives else MAX_EXECUTABLE
        expected[path.name] = f"sha256:{sha256(checked(path, limit))}"
    subprocess.run(["sha256sum", "--strict", "-c", "SHA256SUMS.txt"], cwd=output / "assets", check=True)
    ensure_tag = ["gh", "api", f"repos/{repository}/git/ref/tags/{tag}", "--jq", ".object.sha"]
    if subprocess.check_output(ensure_tag, text=True).strip() != local_ref:
        raise ValueError("remote release tag object changed")
    subprocess.run([
        "gh", "release", "create", tag, "--repo", repository, "--verify-tag", "--draft",
        "--title", f"ExaCopy CLI {version}", "--generate-notes",
    ], check=True)
    # gh release view can resolve drafts. The REST tag endpoint serves published releases.
    draft = json.loads(subprocess.check_output([
        "gh", "release", "view", tag, "--repo", repository,
        "--json", "databaseId,isDraft,isPrerelease,tagName",
    ], text=True, timeout=30))
    draft_id = draft.get("databaseId")
    if (
        type(draft_id) is not int or draft_id <= 0 or draft.get("tagName") != tag
        or draft.get("isDraft") is not True or draft.get("isPrerelease") is not False
    ):
        raise ValueError("could not identify the exact tagged draft; preserve it for maintainer reconciliation")
    draft_path = f"repos/{repository}/releases/{draft_id}"
    subprocess.run(["gh", "release", "upload", tag, "--repo", repository, *files], check=True)
    release = json.loads(subprocess.check_output(
        ["gh", "api", draft_path], text=True, timeout=30,
    ))
    actual = {item["name"]: item["digest"] for item in release["assets"] if item["state"] == "uploaded"}
    if (
        release["id"] != draft_id or release["tag_name"] != tag or not release["draft"] or release["prerelease"]
        or len(release["assets"]) != len(files) or actual != expected
        or subprocess.check_output(ensure_tag, text=True, timeout=30).strip() != local_ref
    ):
        raise ValueError("draft assets or tag changed; preserve the draft for maintainer reconciliation")
    require_immutability(repository, administration_read_token)
    subprocess.run([
        "gh", "api", "--method", "PATCH", draft_path, "-F", "draft=false", "-f", "make_latest=true",
    ], check=True, timeout=30, stdout=subprocess.DEVNULL)
    published = json.loads(subprocess.check_output(
        ["gh", "api", f"repos/{repository}/releases/latest"], text=True, timeout=30,
    ))
    published_assets = {item["name"]: item["digest"] for item in published["assets"] if item["state"] == "uploaded"}
    if (
        published["id"] != draft_id or published["tag_name"] != tag or published["draft"] or published["prerelease"]
        or not published["immutable"] or len(published["assets"]) != len(expected)
        or published_assets != expected
    ):
        raise ValueError("publication returned but latest release verification failed; reconcile the live release")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("require-ci")
    sign_args = commands.add_parser("sign")
    for name in ("unsigned", "native", "output"):
        sign_args.add_argument(f"--{name}", type=Path, required=True)
    sign_args.add_argument("--sequence", required=True)
    publish_args = commands.add_parser("publish")
    publish_args.add_argument("--output", type=Path, required=True)
    for command in ("prepare-native", "record-native"):
        native = commands.add_parser(command)
        native.add_argument("--target", choices=(APPLE, WINDOWS), required=True)
        native.add_argument("--unsigned", type=Path, required=True)
        native.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    try:
        ref, commit = os.environ["GITHUB_REF"], os.environ["GITHUB_SHA"]
        version = candidate.check_source(ref, commit)
        identity = commit, ref.removeprefix("refs/tags/"), version
        if options.command == "require-ci":
            required_success(identity)
        elif options.command == "prepare-native":
            prepare_native(options.unsigned, options.output, options.target, identity)
        elif options.command == "record-native":
            record_native(options.unsigned, options.output, options.target, identity)
        elif options.command == "sign":
            sign(options, identity)
        else:
            publish(options.output, identity)
    except (KeyError, OSError, TypeError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"signed release: {error}\n")


if __name__ == "__main__":
    main()
