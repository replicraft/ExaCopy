#!/usr/bin/env python3
"""Exercise an exact built sync preview on an owned, unprivileged Linux tmpfs fixture."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile

from fixture import (
    CASES, ROOT, TARGET, TEST_NAMES, bind_fixture, unit_source_fingerprints,
)
from native import (
    PREFIX, build_cli, build_native_suite, build_oracle, check_toolchain,
    clean_revision, command, digest, private_build_environment, verify_listing,
)

REFERENCE_ROOT = (
    ROOT
    / "crates/formats/exacopy-manifest/verification/manifest"
)
sys.path.insert(0, str(REFERENCE_ROOT))
from reference import FILE_DIGESTS, encode  # independent fixture oracle

TMPFS = Path("/dev/shm")
LEFT = b"left-\xc3\xa9"
RIGHT = b"right-\xfe"
SUBJECT = b"subject-\xff"
DIFFERENT_SPELLING = b"Subject-\xff"
METADATA_DOMAIN = b"ExaCopy/sync-baseline/linux-owner-mode/v1\0"
FILE_LIMIT = 64 * 1024 * 1024
DIRECTORY_LIMIT = 4096
OUTPUT_LIMIT = 16 * 1024
MOUNTINFO_LIMIT = 1024 * 1024
FINGERPRINT_ENTRIES = 2 * DIRECTORY_LIMIT
EXECUTION_SECONDS = 15
BASIC = {"history": "none", "scope": "one_subject"}
COMPLETE = BASIC | {
    "scope_complete": True,
    "consistency": "live_observed",
    "comparison": "independent_blake3_unnamed_stream",
    "required_metadata": "linux_owner_and_mode_v1",
    "omitted_metadata": "all_other_metadata",
    "max_file_bytes": FILE_LIMIT,
}
ABSENT = {"state": "absent_observed"}
BLOCKED_EXIT = 77


class Blocked(RuntimeError):
    """Required native substrate cannot be admitted."""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate report key {key!r}")
        result[key] = value
    return result


def exact_report(stdout, expected):
    require(len(stdout) <= OUTPUT_LIMIT, "sync report exceeds fixture budget")
    actual = json.loads(stdout, object_pairs_hook=unique_object)
    require(canonical(actual) == canonical(expected), "sync report differs from the independent oracle")
    return actual


def mount_id(mountinfo, device):
    require(len(mountinfo) <= MOUNTINFO_LIMIT, "mountinfo exceeds fixture budget")
    expected = b"%d:%d" % (os.major(device), os.minor(device))
    matches = []
    for line in mountinfo.splitlines():
        before, separator, after = line.partition(b" - ")
        columns = before.split()
        if len(columns) >= 6 and columns[4] == b"/dev/shm":
            require(separator and columns[2] == expected and columns[3] == b"/"
                    and after.split()[:1] == [b"tmpfs"], "/dev/shm is not an exact whole tmpfs mount")
            require(columns[0].isdigit() and int(columns[0]) > 0, "invalid tmpfs mount ID")
            matches.append(columns[0].decode("ascii"))
    require(len(matches) == 1, "expected exactly one /dev/shm mountinfo record")
    return matches[0]


def admit():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise Blocked(f"expected native {TARGET}")
    if os.getuid() == 0 or os.geteuid() == 0:
        raise Blocked("qualification requires an unprivileged outer invocation")
    try:
        require(TMPFS.resolve(strict=True) == TMPFS and TMPFS.is_dir(), "refuse rebound fixture root")
        with Path("/proc/self/mountinfo").open("rb") as proc:
            return mount_id(proc.read(MOUNTINFO_LIMIT + 1), TMPFS.stat().st_dev)
    except (OSError, ValueError) as error:
        raise Blocked(f"whole unprivileged tmpfs fixture unavailable ({error})") from error


def fingerprint(root):
    """Hash the owned tree without following links or including access times."""
    values = []

    def walk(path):
        require(len(values) < FINGERPRINT_ENTRIES, "owned fixture exceeds fingerprint entry budget")
        observed = path.lstat()
        fields = [
            os.fsencode(str(path.relative_to(root))).hex(),
            observed.st_dev, observed.st_ino, observed.st_mode,
            observed.st_uid, observed.st_gid, observed.st_nlink, observed.st_size,
            observed.st_mtime_ns, observed.st_ctime_ns,
        ]
        values.append(fields)
        if stat.S_ISDIR(observed.st_mode):
            for child in sorted(path.iterdir(), key=lambda item: os.fsencode(item.name)):
                walk(child)
        elif stat.S_ISREG(observed.st_mode):
            require(observed.st_size <= FILE_LIMIT + 1, "unexpected fixture file size")
            fields.append(digest(path))
        elif stat.S_ISLNK(observed.st_mode):
            fields.append(os.fsencode(os.readlink(path)).hex())
        else:
            raise ValueError("unexpected object in owned qualification fixture")

    walk(root)
    return hashlib.sha256(canonical(values).encode("ascii")).hexdigest()


def blake3(oracle, data):
    result = subprocess.run(
        [oracle], input=data, capture_output=True, check=True, timeout=EXECUTION_SECONDS,
    )
    require(not result.stderr and re.fullmatch(b"[0-9a-f]{64}\n", result.stdout),
            "independent BLAKE3 did not emit a digest")
    return result.stdout.decode("ascii").strip()


def present(path, oracle):
    observed = path.stat()
    metadata = encode([stat.S_IMODE(observed.st_mode), observed.st_uid, observed.st_gid])
    return {
        "state": "present", "bytes": observed.st_size,
        "stream_digest": blake3(oracle, path.read_bytes()),
        "required_metadata_digest": blake3(oracle, METADATA_DOMAIN + metadata),
    }


def identity(path):
    observed = path.stat()
    return {"device": str(observed.st_dev), "inode": str(observed.st_ino)}


def selection(parent, left, right, mount):
    return {
        "parent": identity(parent), "left_root": identity(left), "right_root": identity(right),
        "mount_id": mount, "left_root_name_hex": LEFT.hex(),
        "right_root_name_hex": RIGHT.hex(), "subject_hex": SUBJECT.hex(),
    }


def write_file(path, data, permissions=0o600):
    path.write_bytes(data)
    path.chmod(permissions)


def blocked(reason, side=None):
    report = BASIC | {"scope_complete": False, "status": "blocked", "reason": reason}
    return 2, report | ({"side": side} if side is not None else {})


def prepare(case, parent, oracle, mount):
    left = parent / os.fsdecode(LEFT)
    right = parent / os.fsdecode(RIGHT)
    left.mkdir(mode=0o700)
    if case == "unavailable_root":
        return blocked("unknown_observation")
    right.mkdir(mode=0o700)
    left_item, right_item = (root / os.fsdecode(SUBJECT) for root in (left, right))

    if case == "explicit_no_history_required":
        return 2, None
    if case == "oversized":
        with right_item.open("wb") as stream:
            stream.truncate(FILE_LIMIT + 1)
        return blocked("resource_limit", "right")
    if case == "directory_cap":
        for index in range(DIRECTORY_LIMIT):
            (right / str(index)).touch()
        return blocked("resource_limit")

    base = COMPLETE | {"selection": selection(parent, left, right, mount)}
    if case == "both_absent":
        return 0, base | {"status": "no_change", "left": ABSENT, "right": ABSENT}

    write_file(left_item, b"abc")
    if case == "aliased_files":
        right_item.hardlink_to(left_item)
        return blocked("aliased_files")
    base["left"] = present(left_item, oracle)
    if case == "different_spelling":
        write_file(right / os.fsdecode(DIFFERENT_SPELLING), b"xyz")
    if case in {"one_sided", "different_spelling"}:
        return 0, base | {
            "status": "copy_candidate", "from": "left", "target": "absent_name", "right": ABSENT,
        }
    if case == "unsupported_link":
        right_item.symlink_to(os.path.relpath(left_item, right))
        return 3, base | {
            "status": "conflict", "reason": "unsupported_entry",
            "right": {"state": "unsupported_entry"},
        }

    require(case in {"equal", "same_extent_divergent", "metadata_divergent"}, "unknown case")
    write_file(
        right_item, b"xyz" if case == "same_extent_divergent" else b"abc",
        0o640 if case == "metadata_divergent" else 0o600,
    )
    base["right"] = present(right_item, oracle)
    if case == "equal":
        return 0, base | {"status": "matching_observations"}
    return 3, base | {"status": "conflict", "reason": "divergent_versions"}


def run_case(case, fixture, binary, oracle, mount, record):
    parent = fixture / case
    parent.mkdir(mode=0o700)
    expected_exit, expected_report = prepare(case, parent, oracle, mount)
    argv = [binary, "sync-preview", parent, LEFT, RIGHT, SUBJECT]
    if expected_report is not None:
        argv.append("--no-history")
    before = fingerprint(fixture)
    record["before_sha256"] = before
    try:
        completed = subprocess.run(
            argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=EXECUTION_SECONDS,
        )
    finally:
        record["after_sha256"] = fingerprint(fixture)
        require(record["after_sha256"] == before, "preview changed owned fixture content or metadata")
    record["exit"] = completed.returncode
    record["stdout"] = completed.stdout[:OUTPUT_LIMIT].decode("utf-8", errors="replace")
    record["stderr"] = completed.stderr[:OUTPUT_LIMIT].decode("utf-8", errors="replace")
    require(completed.returncode == expected_exit, f"{case} returned unexpected exit")
    if expected_report is None:
        require(not completed.stdout and b"required" in completed.stderr,
                "missing explicit no-history selection was not reported")
    else:
        require(not completed.stderr, "unexpected preview diagnostic on stderr")
        record["report"] = exact_report(completed.stdout, expected_report)
    record["status"] = "pass"


def verify_test_log(name, log):
    successes = [
        line[len("test "):-len(" ... ok")] for line in log.splitlines()
        if line.startswith("test ") and line.endswith(" ... ok")
    ]
    require(name in TEST_NAMES and sorted(successes) == sorted(TEST_NAMES[name]),
            f"{name} native runner did not pass every exact named test")
    count = len(TEST_NAMES[name])
    expected = f"test result: ok. {count} passed; 0 failed; 0 ignored;"
    require(sum(line.startswith(expected) for line in log.splitlines()) == 1,
            f"{name} native runner summary is missing or incomplete")


def campaign(binary, oracle, mount, record):
    record["binary_sha256"] = digest(binary)
    record["oracle_sha256"] = digest(oracle)
    for data, expected in FILE_DIGESTS.items():
        require(blake3(oracle, data) == expected, "independent BLAKE3 control failed")
    record["status"] = "failed"
    try:
        directory = tempfile.TemporaryDirectory(prefix="exacopy-sync-native-", dir=TMPFS)
    except OSError as error:
        record["status"] = "blocked"
        raise Blocked(f"owner-private tmpfs directory unavailable ({error})") from error
    fixture = Path(directory.name)
    try:
        with directory:
            owner = fixture.stat()
            require(owner.st_uid == os.geteuid() and stat.S_IMODE(owner.st_mode) == 0o700,
                    "fixture is not an owner-private scope")
            for case in CASES:
                item = {"name": case, "status": "failed"}
                record["cases"].append(item)
                run_case(case, fixture, binary, oracle, mount, item)
    finally:
        record["fixture_removed"] = not os.path.lexists(fixture)
        require(record["fixture_removed"], "owned tmpfs fixture was not removed")
    require(digest(binary) == record["binary_sha256"] and digest(oracle) == record["oracle_sha256"],
            "fixture executables changed during qualification")
    require(tuple(item["name"] for item in record["cases"] if item["status"] == "pass") == CASES,
            "not all named cases passed")
    record["status"] = "pass"


def qualify(revision, evidence, report):
    binding = bind_fixture()
    report.update(binding)
    mount = admit()
    report["mount"] = {"filesystem": "tmpfs", "mount_id": mount}
    report["kernel"] = platform.release()
    clean_revision(revision, evidence, "before")
    report["unit_source_sha256"] = unit_source_fingerprints()
    check_toolchain(evidence)
    lockfile = ROOT / "Cargo.lock"
    report["lockfile_sha256"] = digest(lockfile)
    directory = tempfile.TemporaryDirectory(prefix="exacopy-sync-native-build-", dir=evidence.parent)
    work = Path(directory.name)
    try:
        with directory:
            env = private_build_environment(work)
            binary = build_cli(work, evidence, env)
            oracle, archive = build_oracle(work, evidence, env)
            report["oracle_archive_sha256"] = archive
            admissible_binaries = (digest(binary), digest(oracle))

            for family, expected in TEST_NAMES.items():
                result = report["native_tests"][family]
                result["status"] = "failed"
                executable = build_native_suite(work, evidence, env, family)
                result["executable_sha256"] = digest(executable)
                listing = command(evidence, f"{family}-list", [
                    executable, PREFIX, "--list", "--format", "terse",
                ], env=env)
                verify_listing(listing, expected)
                output = command(evidence, f"{family}-run", [
                    executable, PREFIX, "--test-threads=1", "--color", "never",
                ], env=env)
                verify_test_log(family, output)
                require(digest(executable) == result["executable_sha256"],
                        "fixture suite executable changed during execution")
                result.update(status="pass", passed=list(expected))

            require((digest(binary), digest(oracle)) == admissible_binaries,
                    "built CLI or oracle changed before preview")
            require(admit() == mount, "native fixture mount changed during setup")
            campaign(binary, oracle, mount, report["preview"])
            require(admit() == mount, "native fixture mount changed during qualification")
            require(bind_fixture() == binding, "fixture or owner registry changed during the run")
            require(unit_source_fingerprints() == report["unit_source_sha256"],
                    "native unit test sources changed during the run")
            require(digest(lockfile) == report["lockfile_sha256"],
                    "Cargo.lock changed during qualification")
            clean_revision(revision, evidence, "after")
    finally:
        report["build_cleanup"] = "preserved" if os.path.lexists(work) else "verified_absent"
        require(report["build_cleanup"] == "verified_absent", "private build directory still exists")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(mode=0o700)
    report = {
        "revision": args.revision, "outcome": "failed", "native": platform.platform(),
        "build_cleanup": "not_created",
        "native_tests": {family: {"status": "not_run", "passed": []} for family in TEST_NAMES},
        "preview": {"status": "not_run", "cases": [], "fixture_removed": None},
        "ext4_casefold": {"status": "not_run", "reason": "no disposable casefold fixture"},
    }
    status = 1
    try:
        qualify(args.revision, evidence, report)
    except Blocked as error:
        report.update(outcome="blocked", reason=str(error))
        status = BLOCKED_EXIT
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        report["reason"] = str(error)
    else:
        report["outcome"] = "pass"
        status = 0
    finally:
        with (evidence / "result.json").open("x", encoding="utf-8") as output:
            output.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return status


if __name__ == "__main__":
    sys.exit(main())
