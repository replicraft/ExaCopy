#!/usr/bin/env python3
"""Supervise the exact ignored Linux witnessed-continuation fixture."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
from contextlib import ExitStack, contextmanager

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "tools" / "qualification"))
from linux_remote_source import source_identity
from native_supervision import CleanupUnconfirmed, interrupted, logged_command, write_json

SELECTOR = "assembly::linux::remote_continued::tests::hosted_witness::witnesses_reviewed_held_remote_zero_tail"
MARKER = b"EXACOPY_HOSTED_WITNESS_RESULT "
REQUEST = "EXACOPY_HOSTED_WITNESS_REQUEST"
QUALIFICATION = "EXACOPY_HOSTED_WITNESS_QUALIFICATION_BLAKE3"
REQUEST_DIGEST = "EXACOPY_HOSTED_WITNESS_REQUEST_BLAKE3"
JOB_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
FIRST_SEGMENT = "00000000000000000001.exajnl"
MAX_REQUEST = 16 * 1024
MAX_BUILD_MANIFEST = 64 * 1024
MAX_TRANSCRIPT = 32 * 1024
MAX_BINARY = 512 * 1024 * 1024
BASE = "3861acc23877ad8af301f2c7df404a34e4e2d6aa"
OVERLAYS = ("f80db0f010f4794237e63fa298af07f2d0836b1efc61a651d9e7682cc0088623",)
ROUTES = ("direct_tcp_v1", "embedded_wireguard_tcp_v1")
BUILD_SCHEMA = "exacopy.linux-remote-witness-libtest-build.v1"
FEATURES = {
    "direct_tcp_v1": ("direct-pinned-tcp-v1", "experimental-ssh-capture"),
    "embedded_wireguard_tcp_v1": ("embedded-wireguard-tcp-v1", "experimental-ssh-wireguard"),
}
APP = "apps/exacopy-cli/src/assembly/linux/remote_continued"
WITNESS_SOURCES = (
    f"{APP}/tests.rs", f"{APP}/tests/hosted_witness.rs", f"{APP}/tests/hosted_witness/inputs.rs",
    f"{APP}/tests/hosted_witness/facts.rs", f"{APP}/witness.rs", f"{APP}/witness/zero_tail.rs",
)
PIN_INPUTS = ("specs/dependencies/apfs-source.toml", "specs/dependencies/transport-source.toml")
CASES = ("positive", "qualification-refusal")
REFUSALS = {"missing_authority", "op2_qualification_refused", "unsupported_substrate",
            "route_not_supported", "request_refused"}
HEX64 = re.compile(r"[0-9a-f]{64}")
NATIVE_TRIPLES = {"x86_64": "x86_64-unknown-linux-gnu", "aarch64": "aarch64-unknown-linux-gnu", "arm64": "aarch64-unknown-linux-gnu"}
HEX40 = re.compile(r"[0-9a-f]{40}")
DIGESTS = {
    "build_blake3", "qualification_blake3", "retention_approval_blake3",
    "source_blake3", "prior_head_blake3", "terminal_head_blake3",
}
PASS_FIELDS = {
    "journal_terminal_kind": 41, "same_inode_links": 2, "public_target_absent": True,
    "receipt_absent": True, "operation": 2, "coverage": 2,
}


class Blocked(Exception):
    """The selected fixture or a prerequisite is unavailable."""


class RefusalEvidenceChanged(ValueError):
    """The observed refusal fixture failed its bounded preservation check."""


def observation(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def path_for(value):
    if not value:
        raise Blocked("missing-external-fixture-input")
    path = Path(value)
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise Blocked("outside-canonical-path-custody")
    return path


@contextmanager
def held_input(path, maximum, *, executable=False):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as stream:
        found = os.fstat(stream.fileno())
        allowed = (0o500, 0o700) if executable else (0o600,)
        if (
            not stat.S_ISREG(found.st_mode) or found.st_nlink != 1
            or found.st_uid != os.geteuid() or stat.S_IMODE(found.st_mode) not in allowed
            or not 0 < found.st_size <= maximum
            or observation(path.lstat()) != observation(found)
        ):
            raise Blocked("invalid-protected-file")
        yield stream, found.st_size
        if observation(found) != observation(os.fstat(stream.fileno())) or observation(found) != observation(path.lstat()):
            raise Blocked("protected-file-changed")


def read_held_bytes(path, maximum):
    with held_input(path, maximum) as (held, length):
        data = held.read(maximum + 1)
        if len(data) != length:
            raise Blocked("protected-file-size-changed")
        return data


def stage_exact_binary(path, selected, expected, *, planned=None, maximum=MAX_BINARY):
    with held_input(path, maximum, executable=True) as (source, length):
        info = os.fstat(source.fileno())
        if planned is not None and (
            planned.get("path") != str(path) or planned.get("size") != length
            or planned.get("sha256") != expected
            or any(planned.get(field) != actual for field, actual in {
                "device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
                "link_count": info.st_nlink, "mode": stat.S_IMODE(info.st_mode),
                "modified_ns": info.st_mtime_ns, "changed_ns": info.st_ctime_ns,
            }.items())
        ):
            raise Blocked("build-executable-custody-mismatch")
        digest = hashlib.sha256()
        with selected.open("xb") as output:
            remaining = length
            while remaining:
                chunk = source.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise Blocked("short-executable")
                if remaining == length and not chunk.startswith(b"\x7fELF"):
                    raise Blocked("non-elf-fixture")
                if output.write(chunk) != len(chunk):
                    raise Blocked("short-private-executable-copy")
                remaining -= len(chunk)
                digest.update(chunk)
            if source.read(1) or digest.hexdigest() != expected:
                raise Blocked("executable-sha256-mismatch")
            output.flush()
            os.fchmod(output.fileno(), 0o500)


def expected_build_command(feature):
    triple = NATIVE_TRIPLES.get(os.uname().machine)
    if triple is None:
        raise Blocked("unsupported-fixture-build-architecture")
    return [
        "cargo", "+1.100.0", "test", "--release", "--offline", "--locked",
        "--no-default-features", "--target", triple, "-p", "exacopy-cli", "--lib", "--no-run",
        "--features", feature, "--message-format=json-render-diagnostics",
    ]


def validate_build(raw, current, pins, route, image_sha, image_blake3):
    try:
        build = json.loads(raw, object_pairs_hook=distinct_keys)
        route_name, feature = FEATURES[route]
        size = build["build_size"]
        original = build["compiler_reported_executable"]
        copy = build["checked_executable_copy"]
        compiled = build["compiled_features"]
        pin_logs = build["pin_logs_sha256"]
        toolchain = build["toolchain"]
        process = build["process"]
        if (
            build["schema"] != BUILD_SCHEMA or build["status"] != "built"
            or build["selector"] != SELECTOR or build["route"] != route_name
            or build["source_before"] != current or build["source_after"] != current
            or build["argv"] != expected_build_command(feature)
            or build["pin_inputs_sha256"] != pins
            or set(pin_logs) != {"pin-pre.apfs.log", "pin-pre.transport.log", "pin-post.apfs.log", "pin-post.transport.log"}
            or any(not HEX64.fullmatch(digest) for digest in pin_logs.values())
            or sorted(compiled) != sorted({"experimental-ssh-capture", feature})
            or any(item.get("status") != "exited" or type(item.get("exit_status")) is not int
                   or item["exit_status"] != 0 or not HEX64.fullmatch(item.get("log_sha256", ""))
                   for item in (toolchain, process))
            or build["build_log_sha256"] != process["log_sha256"]
            or not HEX64.fullmatch(build["selector_log_sha256"])
            or type(size) is not int or not 4 <= size <= MAX_BINARY
            or build["build_sha256"] != image_sha or build["build_blake3_derive_key"] != image_blake3
            or any((item.get("size"), item.get("sha256")) != (size, image_sha) for item in (original, copy))
            or (original.get("device"), original.get("inode")) == (copy.get("device"), copy.get("inode"))
        ):
            raise ValueError("build provenance mismatch")
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise Blocked("incomplete-or-mismatched-build-provenance") from error
    return copy


def stage_digest_tool(work):
    parent = path_for(os.environ.get("RUNNER_TEMP"))
    tools = path_for(str(parent / "exacopy-commissioning-tools"))
    info = tools.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Blocked("unprotected-digest-tool-directory")
    expected = os.environ.get("EXACOPY_HOSTED_WITNESS_B3SUM_SHA256", "")
    if not HEX64.fullmatch(expected):
        raise Blocked("missing-independent-digest-tool-selection")
    tool = path_for(str(tools / "unpacked/usr/bin/b3sum"))
    selected = work / "b3sum"
    stage_exact_binary(tool, selected, expected, maximum=32 * 1024 * 1024)
    return selected


def hash_request(tool, payload):
    try:
        output = subprocess.run(
            [tool, "--no-names"], input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=True, timeout=15, env={"LC_ALL": "C"},
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise Blocked("request-digest-unavailable") from error
    if not re.fullmatch(rb"[0-9a-f]{64}\n", output):
        raise Blocked("request-digest-unavailable")
    return output[:-1].decode("ascii")


def check_private_directory(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Blocked("unprotected-refusal-fixture-directory")


def observe_refusal_file(path, stream, limit, original, fail):
    def stamp():
        info = os.fstat(stream.fileno())
        if not 0 < info.st_size <= limit:
            raise fail("refusal-fixture-file-size-outside-bound")
        current = observation(info)
        try:
            named = path.lstat()
        except OSError as error:
            raise fail("refusal-fixture-file-name-unavailable") from error
        if current != original or current != observation(named):
            raise fail("refusal-fixture-file-identity-or-stamp-changed")
        return info

    current = stamp()
    stream.seek(0)
    digest = hashlib.sha256()
    remaining = current.st_size
    while remaining:
        count = min(remaining, 1024 * 1024)
        chunk = stream.read(count)
        if not chunk or len(chunk) > count:
            raise fail("short-or-overlong-refusal-fixture-read")
        remaining -= len(chunk)
        digest.update(chunk)
    if stream.read(1):
        raise fail("refusal-fixture-file-grew-during-read")
    stamp()
    return observation(current), digest.hexdigest()


@contextmanager
def refusal_observation(request, case, report):
    if case != "qualification-refusal":
        yield
        return
    root = path_for(os.environ.get("EXACOPY_HOSTED_WITNESS_REFUSAL_DESTINATION"))
    job = request.get("job_id")
    target = request.get("target")
    stage = request.get("stage")
    if (
        str(root) != request.get("destination_root")
        or not isinstance(job, str) or not JOB_ID.fullmatch(job)
        or not isinstance(target, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", target) is None
        or target in (".", "..")
        or not isinstance(stage, str) or not stage.startswith("capture-") or not JOB_ID.fullmatch(stage[8:])
    ):
        raise Blocked("invalid-refusal-fixture-selection")

    with ExitStack() as held:
        directories = {}
        files = {}
        job_dir = root / (".exacopy-" + job)
        receipts = job_dir / "receipts"
        selected_directories = [
            ("destination", root), ("job", job_dir), ("stage", job_dir / "stage"), ("journal", job_dir / "journal"),
        ]
        if os.path.lexists(receipts):
            selected_directories.append(("receipts", receipts))
        for label, path in selected_directories:
            canonical = path_for(str(path))
            fd = os.open(canonical, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            held.callback(os.close, fd)
            check_private_directory(os.fstat(fd))
            directories[label] = (canonical, fd)
        for label, path, limit in (
            ("owner", directories["job"][0] / "owner.cbor", 16 * 1024),
            ("segment", directories["journal"][0] / FIRST_SEGMENT, 64 * 1024 * 1024),
            ("stage", directories["stage"][0] / stage, MAX_BINARY),
        ):
            canonical = path_for(str(path))
            selected, _ = held.enter_context(held_input(canonical, limit))
            files[label] = (canonical, selected, limit, observation(os.fstat(selected.fileno())))

        def state(on_missing):
            result = {}
            if os.path.lexists(root / target) or os.path.lexists(receipts / "receipt.cbor"):
                raise on_missing("refusal-target-or-receipt-not-absent")
            for label, (path, fd) in directories.items():
                info = os.fstat(fd)
                check_private_directory(info)
                with os.scandir(fd) as entries:
                    names = []
                    for entry in entries:
                        if len(names) >= 128:
                            raise Blocked("refusal-fixture-inventory-exceeds-bound")
                        names.append(entry.name)
                if observation(path.lstat()) != observation(info):
                    raise ValueError("refusal-fixture-directory-changed")
                if label == "job" and any(
                    name.startswith(("witness.", "rw-receipt.pending.", "rw-receipt.final.")) for name in names
                ):
                    raise on_missing("refusal-witness-or-receipt-not-absent")
                result[label + "_directory"] = (observation(info), sorted(names))
            for label, (path, stream, limit, original) in files.items():
                result[label] = observe_refusal_file(path, stream, limit, original, on_missing)
            return result

        before = state(Blocked)
        yield
        if state(RefusalEvidenceChanged) != before:
            raise RefusalEvidenceChanged("refusal-fixture-state-changed")
    # The public report commits to this exact bounded scope without raw names.
    report["refusal_preservation"] = {
        "status": "unchanged", "scope": ["destination", "job", "stage", "journal", "owner", "target-absent", "witness-and-receipt-absent"],
        "inventory_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def observe_source():
    try:
        current = source_identity(ROOT)
        pins = {item: hashlib.sha256((ROOT / item).read_bytes()).hexdigest() for item in PIN_INPUTS}
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise Blocked("exact-clean-source-unavailable") from error
    return current, pins


def observe_witness_sources():
    try:
        files = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in WITNESS_SOURCES}
    except OSError as error:
        raise Blocked("reviewed-hosted-witness-source-unavailable") from error
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("ascii")
    return files, hashlib.sha256(encoded).hexdigest()


def stage_request(path, selected, route):
    raw = read_held_bytes(path, MAX_REQUEST)
    try:
        header = json.loads(raw, object_pairs_hook=distinct_keys)
    except ValueError as error:
        raise Blocked("invalid-request-envelope") from error
    if (
        not isinstance(header, dict)
        or type(header.get("schema_version")) is not int or header["schema_version"] != 1
        or header.get("route") != route
        or header.get("strategy") != "verified_prefix" or header.get("allow_witness_retention") is not True
        or not isinstance(header.get("op2"), dict)
        or not isinstance(header["op2"].get("record"), str)
        or not header["op2"]["record"]
    ):
        raise Blocked("missing-or-mismatched-operation-2-envelope")
    with selected.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        if output.write(raw) != len(raw):
            raise Blocked("short-private-request-copy")
    return raw, header


def distinct_keys(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON key")
    return result


def fixture_result(data, route, expected_build, request_header, expected_qualification, request_blake3):
    rows = [line[len(MARKER):] for line in data.splitlines() if line.startswith(MARKER)]
    if len(rows) != 1 or len(rows[0]) > 4096:
        raise ValueError("missing or ambiguous fixture report")
    value = json.loads(rows[0], object_pairs_hook=distinct_keys)
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValueError("fixture report version")
    outcome = value.get("outcome")
    phase = value.get("phase")
    if outcome not in ("passed", "failed", "blocked") or phase not in ("preflight", "held_prefix", "witness_closeout"):
        raise ValueError("fixture report disposition")
    common = {"schema_version": 1, "outcome": outcome, "phase": phase}
    if outcome != "passed":
        reason = value.get("reason")
        if isinstance(reason, str) and reason in REFUSALS:
            common["reason"] = reason
        if reason == "op2_qualification_refused":
            if (
                phase != "preflight" or value.get("qualification_blake3") != expected_qualification
                or value.get("request_blake3") != request_blake3
            ):
                raise ValueError("unbound operation-2 refusal")
            common.update(qualification_blake3=expected_qualification, request_blake3=request_blake3)
        return common
    if (
        phase != "witness_closeout" or value.get("route") != route
        or value.get("authority_scope") != "fixture_only"
        or value.get("request_blake3") != request_blake3
        or value.get("source_blake3") != request_header.get("source_blake3")
        or value.get("prior_head_blake3") != request_header.get("prior_head_blake3")
        or value.get("qualification_blake3") != expected_qualification
        or value.get("build_blake3") != expected_build
        or any(type(value.get(key)) is not str or not HEX64.fullmatch(value[key]) for key in DIGESTS)
        or any(type(value.get(key)) is not type(expected) or value[key] != expected for key, expected in PASS_FIELDS.items())
        or value["prior_head_blake3"] == value["terminal_head_blake3"]
    ):
        raise ValueError("incomplete witness evidence")
    return common | {"route": route, "authority_scope": "fixture_only", "request_blake3": request_blake3} | {key: value[key] for key in DIGESTS} | PASS_FIELDS


def run_selected(work, report, route, case):
    # Environment comes from the protected, route-selected workflow environment.
    request = path_for(os.environ.get(REQUEST))
    binary = path_for(os.environ.get("EXACOPY_HOSTED_WITNESS_BINARY"))
    selected_sha = os.environ.get("EXACOPY_HOSTED_WITNESS_BINARY_SHA256", "")
    build = os.environ.get("EXACOPY_HOSTED_WITNESS_BUILD_BLAKE3", "")
    revision = os.environ.get("EXACOPY_HOSTED_WITNESS_REVISION", "")
    if not HEX64.fullmatch(selected_sha) or not HEX64.fullmatch(build):
        raise Blocked("missing-exact-build-selection")
    if not HEX40.fullmatch(revision) or revision != os.environ.get("GITHUB_SHA"):
        raise Blocked("wrong-source-selection")
    if (
        sys.platform != "linux" or os.geteuid() == 0 or os.geteuid() != os.getuid()
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "self-hosted"
        or os.environ.get("GITHUB_REPOSITORY", "").lower() != "replicraft/exacopy"
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("GITHUB_REF_PROTECTED") != "true"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
    ):
        raise Blocked("unsupported-runner-identity")
    manifest = path_for(os.environ.get("EXACOPY_HOSTED_WITNESS_BUILD_MANIFEST"))
    manifest_sha = os.environ.get("EXACOPY_HOSTED_WITNESS_BUILD_MANIFEST_SHA256", "")
    if not HEX64.fullmatch(manifest_sha):
        raise Blocked("missing-build-manifest-approval")
    selected_manifest = read_held_bytes(manifest, MAX_BUILD_MANIFEST)
    if hashlib.sha256(selected_manifest).hexdigest() != manifest_sha:
        raise Blocked("build-manifest-sha256-mismatch")
    current, pins = observe_source()
    if current["revision"] != revision:
        raise Blocked("wrong-running-checkout")
    observed = validate_build(selected_manifest, current, pins, route, selected_sha, build)
    source_review = observe_witness_sources()
    expected_sources = os.environ.get("EXACOPY_HOSTED_WITNESS_SOURCE_SET_SHA256", "")
    if not HEX64.fullmatch(expected_sources) or source_review[1] != expected_sources:
        raise Blocked("reviewed-hosted-witness-source-mismatch")
    expected_qualification = os.environ.get(QUALIFICATION, "")
    if not HEX64.fullmatch(expected_qualification) or expected_qualification == "0" * 64:
        raise Blocked("missing-exact-operation-2-record-selection")

    request_copy = work / "request.json"
    payload, request_header = stage_request(request, request_copy, route)
    request_digest = hashlib.sha256(payload).hexdigest()
    request_blake3 = hash_request(stage_digest_tool(work), payload)
    selected = work / "fixture-elf"
    stage_exact_binary(binary, selected, selected_sha, planned=observed)
    if observe_source() != (current, pins) or observe_witness_sources() != source_review:
        raise Blocked("source-changed-during-selection")
    report.update(
        source=current, executable_sha256=selected_sha, build_manifest_sha256=manifest_sha,
        witness_source_sha256=source_review[0], witness_source_set_sha256=source_review[1],
    )
    log = work / "fixture.log"
    marker_path = work.parent / "cleanup-unconfirmed.json"
    with refusal_observation(request_header, case, report), held_input(request_copy, MAX_REQUEST) as (staged, length):
        if length != len(payload) or staged.read(MAX_REQUEST + 1) != payload:
            raise Blocked("staged-request-custody-mismatch")
        info = os.fstat(staged.fileno())
        request_evidence = {
            "sha256": request_digest, "blake3": request_blake3, "size": length,
            "device": info.st_dev, "inode": info.st_ino,
        }
        report["staged_request"] = request_evidence
        write_json(marker_path, {
            "selector": SELECTOR, "revision": revision, "executable_sha256": selected_sha,
            "staged_request": request_evidence,
        })
        result = logged_command(
            [selected, SELECTOR, "--exact", "--ignored", "--nocapture", "--test-threads=1"],
            log, 180, cwd=ROOT, env={
                "LC_ALL": "C", REQUEST: str(request_copy), QUALIFICATION: expected_qualification,
                REQUEST_DIGEST: request_blake3,
                "EXACOPY_HOSTED_WITNESS_ROUTE": route, "EXACOPY_HOSTED_WITNESS_CASE": case,
            },
            output_limit=MAX_TRANSCRIPT,
        )
        marker_path.unlink()
        staged.seek(0)
        if staged.read(MAX_REQUEST + 1) != payload:
            raise Blocked("staged-request-custody-mismatch")
    if observe_source() != (current, pins) or observe_witness_sources() != source_review:
        raise Blocked("source-changed-during-execution")
    report["process"] = {"status": result.status, "exit_status": result.exit_status}
    with log.open("rb") as transcript:
        data = transcript.read(MAX_TRANSCRIPT + 1)
    if len(data) > MAX_TRANSCRIPT:
        raise ValueError("oversized fixture transcript")
    report["transcript_sha256"] = hashlib.sha256(data).hexdigest()
    try:
        proof = fixture_result(data, route, build, request_header, expected_qualification, request_blake3)
    except ValueError:
        if result.passed():
            raise
    else:
        report["fixture"] = proof
    if not result.passed():
        return 1
    if case == "qualification-refusal":
        if proof["outcome"] == "passed":
            return 1
        if (proof["outcome"], proof["phase"], proof.get("reason")) == (
            "blocked", "preflight", "op2_qualification_refused",
        ):
            return 0
    return {"passed": 0, "failed": 1, "blocked": 77}[proof["outcome"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, choices=CASES)
    parser.add_argument("--route", required=True, choices=ROUTES)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    parent = path_for(str(args.evidence.parent))
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise Blocked("invalid-evidence-parent")
    os.umask(0o077)
    evidence = parent / args.evidence.name
    evidence.mkdir(mode=0o700)
    work = evidence / "private"
    work.mkdir(mode=0o700)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    report = {
        "schema": "exacopy.linux-witness-zero-tail-hosted.v1", "route": args.route, "case": args.case,
        "base": BASE, "overlay_sha256": OVERLAYS, "selector": SELECTOR,
        "qualifies_operation_2": False,
    }
    result = 77
    cleanup = "confirmed"
    try:
        result = run_selected(work, report, args.route, args.case)
    except CleanupUnconfirmed:
        cleanup = "unconfirmed"
        report["reason"] = "fixture-process-drain-unconfirmed"
    except Blocked as error:
        report["reason"] = str(error)
    except OSError:
        report["reason"] = "fixture-input-or-io-unavailable"
    except RefusalEvidenceChanged as error:
        result = 1
        report["reason"] = str(error)
    except (ValueError, TypeError):
        result = 1
        report["reason"] = "invalid-fixture-report"
    finally:
        if os.path.lexists(evidence / "cleanup-unconfirmed.json"):
            cleanup = "unconfirmed"
            result = 77
        if cleanup == "confirmed":
            try:
                shutil.rmtree(work)
            except OSError:
                cleanup = "unconfirmed"
                result = 77
        report.update(status={0: "pass", 1: "fail", 77: "blocked"}[result], cleanup=cleanup, exit_status=result)
        write_json(evidence / "report.json", report)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
