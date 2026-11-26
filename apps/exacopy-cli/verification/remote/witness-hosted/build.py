"""Prepare one exact native witness libtest and a bound unsigned root observation."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys

REPO = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO / ".github/ci"))
sys.path.insert(0, str(REPO / "apps/exacopy-cli/verification/remote"))

import remote_qualification as native
from qualification_request import checked_native

SCHEMA = "exacopy.linux-remote-witness-libtest-build.v1"
SELECTOR = (
    "assembly::linux::remote_continued::tests::hosted_witness::"
    "witnesses_reviewed_held_remote_zero_tail"
)
ROUTES = {
    "direct_tcp_v1": native.DIRECT,
    "embedded_wireguard_tcp_v1": native.EMBEDDED,
}
IMAGE_DOMAIN = "ExaCopy remote running executable v1"
FACTS_MARKER = b"EXACOPY_HOSTED_WITNESS_FACTS "
DIGEST = re.compile(r"[0-9a-f]{64}")
TOOL_LIMIT = 32 * 1024 * 1024
CLI = Path("apps/exacopy-cli")


def cargo_libtest(log, root, target, route, triple):
    if triple not in native.RUST_HOSTS.values():
        raise ValueError("witness build requires a supported native Rust target")
    expected_features = sorted({native.FEATURES[native.DIRECT], native.FEATURES[route]})
    if log.stat().st_size > native.LOG_LIMIT:
        raise ValueError("witness compiler inventory exceeds its input bound")
    reports = []
    with log.open("rb") as inventory:
        for line in inventory:
            if line.startswith(b"{"):
                item = json.loads(line)
                if item.get("reason") == "compiler-artifact" and item.get("executable"):
                    reports.append(item)
                    if len(reports) != 1:
                        raise ValueError("witness build reported ambiguous executable targets")
    if len(reports) != 1:
        raise ValueError("witness build did not report a single test executable")
    unit = reports[0]
    description = unit["target"]
    package = (root / CLI).as_uri()
    package_id = re.fullmatch(
        re.escape(f"path+{package}#") + r"(?:exacopy-cli@)?[0-9]+\.[0-9]+\.[0-9]+",
        unit["package_id"],
    )
    compiler_path = native.absolute_path(unit["executable"])
    release = target / triple / "release"
    relative = compiler_path.relative_to(release) if compiler_path.is_relative_to(release) else None
    if relative is None:
        raise ValueError("witness test executable lies outside its native private release target")
    layout = relative.parent.parts
    supported_layout = layout == ("deps",) or (
        len(layout) == 4 and layout[:2] == ("build", "exacopy-cli") and layout[3] == "out"
        and re.fullmatch(r"[0-9a-f]{16}", layout[2]) is not None
    )
    if (
        not package_id or unit.get("manifest_path") != str(root / CLI / "Cargo.toml")
        or description.get("src_path") != str(root / CLI / "src/lib.rs")
        or description.get("name") != "exacopy_cli" or description.get("kind") != ["lib"]
        or unit.get("profile", {}).get("test") is not True or unit.get("fresh") is not False
        or sorted(unit["features"]) != expected_features
        or not supported_layout
        or not re.fullmatch(r"exacopy_cli-[0-9a-f]{16}", compiler_path.name)
        or unit["executable"] not in unit["filenames"]
    ):
        raise ValueError("compiler inventory did not select the exact witness library test target")
    return compiler_path, expected_features


def owned_directory(path):
    path = native.absolute_path(str(path))
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("witness intake requires an exact owned 0700 directory")
    return info.st_dev, info.st_ino


def derived_build(binary, b3sum, expected_tool, expected_image, evidence, env):
    if not isinstance(expected_tool, str) or not DIGEST.fullmatch(expected_tool):
        raise ValueError("witness build needs an independently approved digest-tool SHA-256")
    b3sum = native.absolute_path(str(b3sum))
    tool_root = native.absolute_path(os.environ.get("RUNNER_TEMP")) / "exacopy-commissioning-tools"
    owned_directory(tool_root)
    if b3sum != tool_root / "unpacked/usr/bin/b3sum":
        raise ValueError("unexpected witness digest-tool location")
    tool = native.executable_observation(b3sum)
    if (
        tool["sha256"] != expected_tool or tool["size"] > TOOL_LIMIT or tool["link_count"] != 1
        or tool["uid"] != os.geteuid() or tool["mode"] not in (0o500, 0o700)
    ):
        raise ValueError("digest tool differs from its approved owned ELF")
    if native.executable_observation(binary) != expected_image:
        raise ValueError("selected image changed before independent measurement")
    log = evidence / "build-domain.log"
    result = native.logged_command([
        b3sum, "--no-names", "--derive-key", IMAGE_DOMAIN, binary,
    ], log, 30, env=env, output_limit=128)
    contents = log.read_bytes()
    if (
        not result.passed() or not re.fullmatch(rb"[0-9a-f]{64}\n", contents)
        or native.executable_observation(binary) != expected_image
        or native.executable_observation(b3sum) != tool
    ):
        raise ValueError("exact independent witness image measurement failed")
    return contents.decode("ascii").strip()


def read_facts(log, destination_stamp, digest):
    matches = []
    if log.stat().st_size > native.CONFIG_LIMIT:
        raise ValueError("same-image witness facts log exceeds its bound")
    with log.open("rb") as transcript:
        for line in transcript:
            if line.startswith(FACTS_MARKER):
                matches.append(json.loads(line.removeprefix(FACTS_MARKER),
                                          object_pairs_hook=native.closed_object))
    if (
        len(matches) != 1 or not isinstance(matches[0], dict)
        or set(matches[0]) != {"build_blake3_derive_key", "destination"}
    ):
        raise ValueError("missing or ambiguous same-image witness facts")
    image = matches[0]
    destination = image["destination"]
    if (
        image["build_blake3_derive_key"] != digest or not checked_native(destination)
        or (int(destination["device"]), int(destination["inode"])) != destination_stamp
        or destination["effective_uid"] != os.geteuid()
        or destination["effective_gid"] != os.getegid()
        or destination["architecture"] != os.uname().machine
    ):
        raise ValueError("same-image facts do not bind the exact selected image and destination")
    return image


def write_owner_json(path, report):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")


def collect_same_image_facts(binary, destination, destination_stamp, evidence, env, manifest, report):
    facts = evidence / "native-facts"
    facts.mkdir(mode=0o700)
    artifact = {
        "schema": "exacopy.linux-remote-native-facts.v1",
        "status": "blocked", "qualifies_remote_download": False,
        "repository_attribution": "locked-cli-build",
        "observation_scope": "exact-witness-libtest-running-image",
        "build_manifest_sha256": native.file_digest(manifest),
    }
    log = facts / "facts.log"
    command = [binary, SELECTOR, "--exact", "--ignored", "--nocapture", "--test-threads=1"]
    try:
        result = native.logged_command(
            command, log, 60, env=dict(
                env, EXACOPY_HOSTED_WITNESS_FACTS_DESTINATION=str(destination),
                EXACOPY_HOSTED_WITNESS_FACTS_BINARY=str(binary),
            ),
            output_limit=native.CONFIG_LIMIT,
        )
        write_owner_json(facts / "process.json", native.process_record(result, log))
        if not result.passed():
            raise ValueError("same-image witness facts invocation did not pass")
        if not re.search(rb"(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored;", log.read_bytes()):
            raise ValueError("same-image facts invocation did not execute exactly one test")
        observed = read_facts(log, destination_stamp, report["build_blake3_derive_key"])
        if (
            owned_directory(destination) != destination_stamp
            or native.source_identity(REPO) != report["source_after"]
            or native.file_digest(manifest) != artifact["build_manifest_sha256"]
        ):
            raise ValueError("destination, source, or build evidence changed during facts collection")
        native.verify_executable_custody(
            Path(report["compiler_reported_executable"]["path"]), binary, report,
        )
        artifact.update(report["source_after"], **observed, status="observed")
    finally:
        write_owner_json(facts / "facts.json", artifact)


def build_fixture(route, evidence, target, destination, revision, b3sum):
    """Build once, freeze the exact image manifest, then observe the held root in that image."""
    route = ROUTES[route]
    owned_directory(evidence)
    destination_stamp = owned_directory(destination)
    parent = native.absolute_path(str(target.parent))
    owned_directory(parent)
    if not target.is_absolute() or target != parent / target.name or not target.name:
        raise ValueError("witness target requires a new canonical path")
    if any(path.is_relative_to(REPO) for path in (target, evidence, destination)):
        raise ValueError("witness fixture inputs and build output must stay outside the clean checkout")
    if len({target, evidence, destination}) != 3 or any(
        path.is_relative_to(destination) for path in (target, evidence)
    ):
        raise ValueError("witness build and evidence must stay outside the destination")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("expected exact reviewed witness revision")
    triple = native.RUST_HOSTS.get(os.uname().machine)
    if sys.platform != "linux" or triple is None:
        raise ValueError("witness facts require supported native Linux")
    before = native.source_identity(REPO)
    if before["revision"] != revision or Path.cwd() != REPO:
        raise ValueError("witness build requires the exact clean working root at the reviewed revision")
    evidence_build = evidence / "build"
    evidence_build.mkdir(mode=0o700)
    target.mkdir(mode=0o700)
    env = native.build_environment(target)
    env.update(CARGO_BUILD_BUILD_DIR=str(target))
    argv = [
        "cargo", native.RUST, "test", "--release", "--offline", "--locked", "--no-default-features",
        "--target", triple, "-p", "exacopy-cli", "--lib", "--no-run", "--features", native.FEATURES[route],
        "--message-format=json-render-diagnostics",
    ]
    report = {
        "schema": SCHEMA, "status": "blocked", "route": route, "selector": SELECTOR,
        "source_before": before, "argv": argv,
    }
    manifest = evidence_build / "result.json"
    binary = target / "witness-libtest"
    try:
        report["pin_inputs_sha256"] = {item: native.file_digest(REPO / item) for item in native.PIN_INPUTS}
        logs = native.verified_pins("pre", evidence_build, env)
        rustc_log = evidence_build / "rustc.log"
        rustc = native.logged_command(["rustc", native.RUST, "-vV"], rustc_log, 30, env=env)
        report["toolchain"] = native.process_record(rustc, rustc_log)
        if not rustc.passed() or not {
            "release: 1.100.0", f"host: {triple}",
        } <= set(rustc_log.read_text().splitlines()):
            raise ValueError("expected exact native Rust 1.100.0")
        build_log = evidence_build / "build.log"
        result = native.logged_command(argv, build_log, 1500, env=env)
        report["process"] = native.process_record(result, build_log)
        report["build_log_sha256"] = report["process"]["log_sha256"]
        logs.update(native.verified_pins("post", evidence_build, env))
        report["pin_logs_sha256"] = logs
        after = native.source_identity(REPO)
        if before != after or not result.passed():
            raise ValueError("exact pinned witness libtest build did not succeed")
        original, features = cargo_libtest(build_log, REPO, target, route, triple)
        measured = native.executable_observation(original)
        report["compiler_reported_executable"] = measured
        staged = native.stage_built_executable(original, binary, measured)
        report["checked_executable_copy"] = staged
        report["compiled_features"] = features
        listing = evidence_build / "ignored-selector.log"
        listed = native.logged_command(
            [binary, SELECTOR, "--exact", "--ignored", "--list", "--format", "terse"],
            listing, 30, env=env, output_limit=1024,
        )
        report["selector_log_sha256"] = native.file_digest(listing)
        if not listed.passed() or listing.read_text().splitlines() != [f"{SELECTOR}: test"]:
            raise ValueError("exact ignored witness selector was not uniquely wired")
        digest = derived_build(binary, b3sum, os.environ.get("EXACOPY_HOSTED_WITNESS_B3SUM_SHA256"),
                               staged, evidence_build, env)
        native.verify_executable_custody(original, binary, report)
        if native.source_identity(REPO) != after:
            raise ValueError("source changed after witness image selection")
        report.update(status="built", source_after=after, build_size=staged["size"],
                      build_sha256=staged["sha256"], build_blake3_derive_key=digest)
    finally:
        write_owner_json(manifest, report)
    collect_same_image_facts(binary, destination, destination_stamp, evidence, env, manifest, report)
    return binary, manifest
