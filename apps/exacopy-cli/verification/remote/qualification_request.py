#!/usr/bin/env python3
"""Assemble unsigned same-source Linux observations for independent campaign review."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from campaign import MAX_BINARY, ROUTES, ROOT, git
from fixture import (
    BUILD_DOMAIN, Blocked, Failed, MIB, b3, canonical, check_held, checked_read,
    file_sha256, opened, owned_directory, require,
)

sys.path.insert(0, str(ROOT / "tools" / "qualification"))
from linux_remote_substrate import (
    EXPECTED as SUBSTRATE_CASES, MAX_LOG_BYTES as MAX_NATIVE_LOG, PARENT_FIELDS, parse_markers,
)

BUILD_SCHEMA = "exacopy.linux-remote-cli-build.v1"
BUILD_FEATURES = {
    "direct-pinned-tcp-v1": "experimental-ssh-capture",
    "embedded-wireguard-tcp-v1": "experimental-ssh-wireguard",
}
PIN_INPUTS = ("specs/dependencies/apfs-source.toml", "specs/dependencies/transport-source.toml")
PIN_LOGS = ("pin-pre.apfs.log", "pin-pre.transport.log", "pin-post.apfs.log", "pin-post.transport.log")
FACTS_SCHEMA = "exacopy.linux-remote-native-facts.v1"
SUBSTRATE_SCHEMA = "ExaCopy/linux-remote-destination-substrate-diagnostic/v1"
MAX_MANIFEST = 32 * 1024
MAX_BUILD_LOG = 32 * MIB


def digest(data):
    return hashlib.sha256(data).hexdigest()


def retain(input_path, output_path, bound):
    data = checked_read(canonical(input_path), bound)
    with output_path.open("xb") as output:
        output.write(data)
    return data


def checked_hex(value, maximum, *, exact=None):
    return (
        isinstance(value, str)
        and len(value) % 2 == 0
        and 0 < len(value) <= 2 * maximum
        and (exact is None or len(value) == 2 * exact)
        and re.fullmatch("[0-9a-f]+", value) is not None
    )


def checked_native(destination):
    if not isinstance(destination, dict):
        return False
    return (
        all(
            isinstance(destination.get(key), str)
            and re.fullmatch("[1-9][0-9]{0,19}", destination[key]) is not None
            and int(destination[key]) < 2**64
            for key in ("device", "inode", "mount_namespace", "mount_id", "unique_mount")
        )
        and all(type(destination.get(key)) is int and 0 <= destination[key] < 2**32
                for key in ("effective_uid", "effective_gid"))
        and destination.get("architecture") in ("x86_64", "aarch64")
        and checked_hex(destination.get("boot_id_hex"), 16, exact=16)
        and checked_hex(destination.get("kernel_release_hex"), 256)
        and checked_hex(destination.get("kernel_build_hex"), 256)
        and checked_hex(destination.get("mount_record_hex"), 2048)
    )


def source_identity():
    if git("status", "--porcelain", "--untracked-files=normal"):
        raise Blocked("independent request source checkout must be clean")
    return {
        "revision": git("rev-parse", "HEAD"),
        "git_tree": git("rev-parse", "HEAD^{tree}"),
        "lock_sha256": file_sha256(ROOT / "Cargo.lock"),
    }


def exact_build(args, request, facts, source):
    if facts.get("repository_attribution") != "locked-cli-build":
        raise Blocked("native facts lack wrapper-owned locked CLI build provenance")
    manifest_bytes = retain(args.build_manifest, args.evidence / "build-result.json", MAX_MANIFEST)
    manifest_digest = digest(manifest_bytes)
    require(
        facts.get("build_manifest_sha256") == manifest_digest,
        "native facts and selected build manifest differ",
    )
    build = strict_json(manifest_bytes)
    feature = BUILD_FEATURES[args.route]
    argv = [
        "cargo", "+1.100.0", "build", "--release", "--offline", "--locked",
        "--no-default-features", "-p", "exacopy-cli", "--bin", "exacopy",
        "--features", feature, "--message-format=json-render-diagnostics",
    ]
    closure = ["experimental-ssh-capture"]
    if feature == "experimental-ssh-wireguard":
        closure.append(feature)
    require(
        build.get("schema") == BUILD_SCHEMA and build.get("status") == "built"
        and build.get("route") == args.route and build.get("features") == [feature]
        and build.get("argv") == argv and build.get("compiled_features") == closure,
        "build did not report the exact locked route-specific CLI command",
    )
    require(
        build.get("source_before") == build.get("source_after") == source,
        "the locked build does not bind clean exact source before and after compilation",
    )
    require(
        build.get("pin_inputs_sha256") == {item: file_sha256(ROOT / item) for item in PIN_INPUTS},
        "the locked build selected different pinned local source inputs",
    )
    build_directory = args.build_manifest.parent
    output = retain(build_directory / "build.log", args.evidence / "build.log", MAX_BUILD_LOG)
    output_digest = digest(output)
    require(
        build.get("build_log_sha256") == output_digest
        and build.get("process") == {"status": "exited", "exit_status": 0, "log_sha256": output_digest},
        "the locked build log or exit status differs",
    )
    pin_logs = {}
    for name in PIN_LOGS:
        pin_log = retain(build_directory / name, args.evidence / name, MAX_MANIFEST)
        pin_logs[name] = digest(pin_log)
    require(build.get("pin_logs_sha256") == pin_logs, "pinned local source verification logs differ")

    b3sum = shutil.which("b3sum")
    if not b3sum:
        raise Blocked("the independent b3sum executable is required")
    binary_path = canonical(args.binary)
    binary_open, info = opened(binary_path, MAX_BINARY)
    with binary_open as binary:
        require(
            os.access(binary_path, os.X_OK) and binary.read(4) == b"\x7fELF",
            "the selected compiled command is not executable ELF",
        )
        binary.seek(0)
        measured = b3(b3sum, None, BUILD_DOMAIN, file=binary)
        binary.seek(0)
        binary_sha256 = hashlib.file_digest(binary, "sha256").hexdigest()
        check_held(binary_path, binary, info)
    require(
        facts["build_blake3_derive_key"] == measured
        and build.get("build_sha256") == binary_sha256 and build.get("build_size") == info.st_size,
        "observed and selected builds differ",
    )
    request["build_manifest_sha256"] = manifest_digest
    return measured


def strict_json(data):
    def unique_fields(fields):
        document = {}
        for key, value in fields:
            if key in document:
                raise Failed("duplicate field in selected evidence document")
            document[key] = value
        return document

    document = json.loads(data, object_pairs_hook=unique_fields)
    require(isinstance(document, dict), "selected evidence document is not a JSON object")
    return document


def substrate_closure(manifest, facts, source, log):
    require(
        all(manifest.get(key) == source[key] for key in ("revision", "lock_sha256"))
        and manifest.get("source_before") == manifest.get("source_after") == source,
        "native substrate diagnostic lacks the exact clean source observations",
    )
    require(manifest["log_sha256"] == digest(log), "native substrate log hash differs")
    cuts, observed_parent = parse_markers(log)
    require(
        manifest["cases"] == list(SUBSTRATE_CASES) and manifest["process_exit"] == 0
        and cuts == SUBSTRATE_CASES,
        "native substrate process cuts do not match the expected campaign",
    )
    parent = {field: facts["destination"][field] for field in PARENT_FIELDS}
    if observed_parent != parent or manifest.get("destination_parent") != parent:
        raise Blocked("substrate process cuts are not associated with the exact observed native parent")


def assemble(args, request):
    source = source_identity()
    facts_bytes = retain(args.facts, args.evidence / "facts.json", MAX_MANIFEST)
    facts = strict_json(facts_bytes)
    require(facts["schema"] == FACTS_SCHEMA, "invalid native observation schema")
    require(facts["qualifies_remote_download"] is False, "native observations must be unsigned")
    if facts["status"] != "observed":
        raise Blocked("exact native facts could not be observed")
    require(checked_native(facts.get("destination")), "invalid observed native destination facts")
    require(
        all(facts.get(key) == value for key, value in source.items()),
        "native facts do not bind the current clean build source",
    )
    build = exact_build(args, request, facts, source)

    owned_directory(args.substrate)
    manifest_bytes = retain(
        args.substrate / "result.json", args.evidence / "substrate-result.json", MAX_MANIFEST,
    )
    manifest = strict_json(manifest_bytes)
    require(manifest["schema"] == SUBSTRATE_SCHEMA, "invalid native substrate schema")
    require(manifest["qualifies_remote_download"] is False, "substrate is diagnostic only")
    log = retain(args.substrate / "native.log", args.evidence / "substrate-native.log", MAX_NATIVE_LOG)
    if manifest["outcome"] != "passed_native_substrate":
        raise Blocked("the eligible native substrate diagnostic did not pass")
    substrate_closure(manifest, facts, source, log)
    require(source_identity() == source, "source changed while assembling the request")
    request.update(
        status="incomplete",
        **source,
        build_blake3_derive_key=build,
        destination_observation="exact_selected_root",
        substrate_observation="owned_disposable_descendants",
        reason="select independent evidence that the requested build exercised the exact route class",
        inputs_sha256={
            "facts.json": digest(facts_bytes),
            "substrate-result.json": digest(manifest_bytes),
            "substrate-native.log": digest(log),
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "build-manifest", "facts", "substrate", "evidence"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--route", choices=ROUTES, required=True)
    args = parser.parse_args()
    args.evidence = args.evidence.absolute()
    try:
        owned_directory(args.evidence.parent)
        args.evidence.mkdir(mode=0o700, exist_ok=False)
    except (Blocked, OSError) as error:
        parser.error(f"invalid or occupied evidence destination ({type(error).__name__})")
    request = {
        "schema": "exacopy.linux-remote-qualification-request.v1",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "blocked",
        "route": args.route,
        "route_evidence": "required",
        "independent_review": "required",
        "issues_new_qualification": False,
    }
    status = 77
    try:
        assemble(args, request)
    except Blocked as error:
        request["reason"] = str(error)
    except FileNotFoundError:
        request["reason"] = "a selected antecedent artifact is unavailable"
    except Failed as error:
        request.update(status="fail", reason=str(error))
        status = 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        request.update(status="fail", reason=type(error).__name__)
        status = 1
    request.update(finished_at=datetime.now(timezone.utc).isoformat(), exit_status=status)
    with (args.evidence / "request.json").open("x") as output:
        json.dump(request, output, indent=2, sort_keys=True)
        output.write("\n")
    return status


if __name__ == "__main__":
    sys.exit(main())
