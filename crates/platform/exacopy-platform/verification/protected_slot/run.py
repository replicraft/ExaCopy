"""Qualify the metadata-only Linux protected-slot observer on disposable fixtures."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import tomllib
from contextlib import contextmanager

TOOLCHAIN = "1.100.0"
TARGET = "x86_64-unknown-linux-gnu"
PREFIX = "linux::protected_slot::tests::"
ORDINARY_SOURCE = "src/linux/protected_slot/tests.rs"
COVERAGE_SOURCE = "tests/unit/protected_slot.rs"
MOUNT_SOURCE = "src/linux/protected_slot/tests/mount.rs"
MOUNT_TEST = PREFIX + "mount::refuses_same_device_bind_mount_at_the_selected_name"
ORDINARY_SOURCES = {
    PREFIX + "distinguishes_lookup_absence_and_rebound_objects": ORDINARY_SOURCE,
    PREFIX + "reports_opaque_kind_without_following_or_opening_payload": ORDINARY_SOURCE,
    PREFIX + "refuses_non_directory_and_previously_unlinked_parent": ORDINARY_SOURCE,
    PREFIX + "distinguishes_hard_link_identity_from_distinct_slot_names": ORDINARY_SOURCE,
    PREFIX + "refuses_unknown_entry_kind": ORDINARY_SOURCE,
    PREFIX + "renamed_parent_survives_as_a_held_observation_only": ORDINARY_SOURCE,
    PREFIX + "coverage::observes_the_exact_unix_component_bytes": COVERAGE_SOURCE,
    PREFIX + "coverage::pinned_recheck_propagates_invalid_parent": COVERAGE_SOURCE,
    PREFIX + "coverage::observation_error_reports_keep_typed_causes": COVERAGE_SOURCE,
}
ORDINARY = tuple(ORDINARY_SOURCES)
BLOCKED_EXIT = 77
SETUP_DENIALS = ("operation not permitted", "permission denied", "function not implemented")


def fixture_cases():
    return [
        {"selector": name, "source": source, "ignored": False}
        for name, source in ORDINARY_SOURCES.items()
    ] + [{"selector": MOUNT_TEST, "source": MOUNT_SOURCE, "ignored": True}]


def fixture_source_fingerprints():
    crate = Path(__file__).resolve().parents[2]
    sources = {case["source"] for case in fixture_cases()}
    return {source: sha256(crate / source) for source in sorted(sources)}


def fixture_binding(path):
    raw = path.read_bytes()
    manifest = tomllib.loads(raw.decode("utf-8"))
    expected = {
        "schema_version": 1, "id": "linux-protected-slot-observation",
        "target": TARGET, "profile": "linux-unprivileged-same-device-bind-v1",
        "rust_toolchain": TOOLCHAIN, "runner": "verification/protected_slot/run.py",
        "controls": "verification/protected_slot/test_runner.py",
        "workflow": ".github/workflows/linux-protected-slot-qualification.yml",
        "result": "result.json",
        "case": fixture_cases(),
    }
    if manifest != expected or type(manifest.get("schema_version")) is not int or any(
        type(case.get("ignored")) is not bool for case in manifest.get("case", [])
    ):
        raise RuntimeError("native fixture manifest disagrees with the reviewed execution profile")
    return {
        "fixture_id": manifest["id"], "fixture_manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "profile": manifest["profile"], "target": TARGET, "rust_toolchain": TOOLCHAIN,
    }


class Blocked(RuntimeError):
    """The isolated mount fixture could not be provisioned."""


def collect(command, *, env=None, timeout=20, isolate=True):
    with subprocess.Popen(
        command, env=env, text=True, encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=isolate,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            stop_process(process, isolate)
            stdout, stderr = process.communicate()
            return subprocess.CompletedProcess(
                command, 124, stdout, stderr + f"\nprocess timed out after {timeout} seconds\n"
            )
        except BaseException:
            stop_process(process, isolate)
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def stop_process(process, isolate):
    try:
        if isolate:
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass


def record(evidence, label, result):
    (evidence / f"{label}.stdout").write_text(result.stdout, encoding="utf-8")
    (evidence / f"{label}.stderr").write_text(result.stderr, encoding="utf-8")
    (evidence / f"{label}.exit").write_text(f"{result.returncode}\n", encoding="utf-8")
    return result


def require_success(result, label):
    if result.returncode:
        raise RuntimeError(f"{label} failed with exit {result.returncode}")
    return result.stdout


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def executable_from_cargo(output, target_root):
    matches = []
    for line in output.splitlines():
        event = json.loads(line)
        target = event.get("target", {})
        if (
            event.get("reason") == "compiler-artifact"
            and target.get("name") == "exacopy_platform"
            and target.get("kind") == ["lib"]
            and event.get("profile", {}).get("test") is True
            and event.get("executable")
        ):
            matches.append(Path(event["executable"]))
    if len(matches) != 1:
        raise RuntimeError(f"expected one platform unit-test executable, got {len(matches)}")
    executable = matches[0]
    if executable.is_symlink() or not executable.resolve().is_relative_to(target_root.resolve()):
        raise RuntimeError("unit-test executable escaped the private target")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError("unit-test executable is unavailable")
    return executable


def check_listing(output, expected):
    observed = []
    for line in output.splitlines():
        if line.startswith(PREFIX):
            name, delimiter, kind = line.partition(": ")
            if delimiter != ": " or kind != "test":
                raise RuntimeError("malformed protected-slot test inventory")
            observed.append(name)
    if sorted(observed) != sorted(expected):
        raise RuntimeError(f"protected-slot inventory mismatch: {observed!r}")


def test_command(binary, name, *, ignored=False):
    args = [binary, name, "--exact", "--color", "never", "--test-threads=1"]
    if ignored:
        args.append("--ignored")
    return args


def check_exact_test(result, name):
    output = require_success(result, name)
    cases = [line for line in output.splitlines() if line.startswith("test ") and " ... " in line]
    if cases != [f"test {name} ... ok"] or not re.search(
        r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", output, re.MULTILINE
    ):
        raise RuntimeError(f"test did not establish exactly one successful control: {name}")


def write_report(evidence, report):
    (evidence / "result.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def clean_revision(revision):
    actual = require_success(collect(["git", "rev-parse", "HEAD"]), "git revision").strip()
    dirty = require_success(collect(["git", "status", "--porcelain"]), "git status")
    if revision != actual or dirty:
        raise RuntimeError("qualification requires the selected exact clean Git revision")


def mount_helper(work, binary, previous_namespace):
    if os.readlink("/proc/self/ns/mnt") == previous_namespace:
        raise RuntimeError("mount helper did not obtain a new mount namespace")
    print(json.dumps({"helper_uid": os.getuid(), "helper_euid": os.geteuid(),
                      "helper_mount_namespace": os.readlink("/proc/self/ns/mnt"),
                      "helper_user_namespace": os.readlink("/proc/self/ns/user"),
                      "helper_uid_map": Path("/proc/self/uid_map").read_text()}, sort_keys=True))
    fixture = Path(tempfile.mkdtemp(prefix="mount-", dir=work))
    parent = fixture / "parent"
    parent.mkdir(mode=0o700)
    underlying = parent / "selected"
    source = fixture / "source"
    underlying.write_bytes(b"underlying")
    source.write_bytes(b"source")
    before = underlying.stat()
    result = collect(["mount", "--bind", str(source), str(underlying)], isolate=False)
    if result.returncode:
        if any(denial in result.stderr.lower() for denial in SETUP_DENIALS):
            raise Blocked(f"private bind mount refused: {result.stderr.strip()}")
        require_success(result, "private bind mount")
    try:
        test = collect(
            test_command(binary, MOUNT_TEST, ignored=True),
            env={**os.environ, "EXACOPY_PROTECTED_SLOT_MOUNT_FIXTURE": str(fixture)},
            isolate=False,
        )
        sys.stdout.write(test.stdout)
        sys.stderr.write(test.stderr)
        check_exact_test(test, MOUNT_TEST)
    finally:
        require_success(collect(["umount", "--", str(underlying)], isolate=False), "private bind unmount")
        after = underlying.stat()
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or underlying.read_bytes() != b"underlying"
            or source.read_bytes() != b"source"
        ):
            raise RuntimeError("disposable source or covered entry changed")
        print("fixture: source and covered entry preserved after verified unmount")


def run_mount(evidence, work, binary):
    for tool in ("unshare", "mount", "umount"):
        if shutil.which(tool) is None:
            raise Blocked(f"missing private-namespace utility: {tool}")
    namespace = os.readlink("/proc/self/ns/mnt")
    args = [
        "unshare", "--user", "--map-root-user", "--mount", "--propagation", "private",
        "--fork", "--kill-child", "--", sys.executable, "-B", str(Path(__file__).resolve()),
        "--mount-helper", str(work), str(binary), namespace,
    ]
    result = record(evidence, "mount", collect(args, timeout=80))
    if result.returncode == BLOCKED_EXIT or (
        result.returncode == 1
        and not result.stdout
        and result.stderr.startswith("unshare:")
        and any(denial in result.stderr.lower() for denial in SETUP_DENIALS)
    ):
        raise Blocked("private user/mount namespace or bind mount unavailable; see mount.stderr")
    check_exact_test(result, MOUNT_TEST)
    if "fixture: source and covered entry preserved after verified unmount" not in result.stdout:
        raise RuntimeError("private mount cleanup evidence is missing")


@contextmanager
def private_work(parent, report):
    work = Path(tempfile.mkdtemp(prefix="exacopy-protected-slot-", dir=parent))
    report["cleanup"] = "pending"
    try:
        yield work
    finally:
        report["cleanup"] = "failed"
        shutil.rmtree(work)
        if os.path.lexists(work):
            raise RuntimeError("private fixture or build directory still exists")
        report["cleanup"] = "verified_absent"


def default_binding():
    return fixture_binding(Path(__file__).with_name("fixture.toml"))


def run(revision, evidence, report, *, binding, mount_runner):
    report.update(binding())
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise Blocked(f"expected native {TARGET}")
    report["outer_identity"] = {
        "uid": os.getuid(), "euid": os.geteuid(),
        "mount_namespace": os.readlink("/proc/self/ns/mnt"),
        "user_namespace": os.readlink("/proc/self/ns/user"),
        "uid_map": Path("/proc/self/uid_map").read_text(),
    }
    if os.getuid() == 0 or os.geteuid() == 0:
        raise Blocked("qualification requires an unprivileged outer invocation")
    clean_revision(revision)
    cargo_lock = Path("Cargo.lock")
    report["lockfile_sha256"] = sha256(cargo_lock)
    report["fixture_source_sha256"] = fixture_source_fingerprints()
    version = require_success(
        record(evidence, "rustc", collect(["rustc", f"+{TOOLCHAIN}", "-vV"])),
        "pinned compiler",
    )
    if f"host: {TARGET}" not in version.splitlines() or (
        f"release: {TOOLCHAIN}" not in version.splitlines()
    ):
        raise RuntimeError("unexpected compiler host or release")
    with private_work(evidence.parent, report) as work:
        target = work / "target"
        env = {**os.environ, "CARGO_TARGET_DIR": str(target),
               "CARGO_BUILD_BUILD_DIR": str(target), "TMPDIR": str(work)}
        command = [
            "cargo", f"+{TOOLCHAIN}", "test", "--locked", "--offline", "--jobs", "2",
            "--target", TARGET, "-p", "exacopy-platform", "--lib", "--no-run",
            "--message-format=json",
        ]
        report["build_command"] = command
        result = record(evidence, "build", collect(command, env=env, timeout=900))
        binary = executable_from_cargo(require_success(result, "platform build"), target)
        report["test_executable_sha256"] = sha256(binary)
        report["fixture_filesystem"] = require_success(
            record(evidence, "filesystem", collect(["stat", "-f", "-c", "%T", str(work)])),
            "fixture filesystem",
        ).strip()
        for label, options, expected in (
            ("test-list", [], (*ORDINARY, MOUNT_TEST)),
            ("ignored-list", ["--ignored"], (MOUNT_TEST,)),
        ):
            result = record(evidence, label, collect([binary, "--list", "--format", "terse", *options]))
            check_listing(require_success(result, label), expected)
        for index, name in enumerate(ORDINARY, start=1):
            result = record(evidence, f"ordinary-{index}", collect(test_command(binary, name), env=env))
            check_exact_test(result, name)
            report["ordinary_passed"].append(name)
        if sha256(binary) != report["test_executable_sha256"]:
            raise RuntimeError("unit-test executable changed before mount run")
        report["mount"] = "pending"
        try:
            mount_runner(evidence, work, binary)
        except Blocked:
            report["mount"] = "blocked"
            raise
        except (RuntimeError, OSError, subprocess.SubprocessError):
            report["mount"] = "failed"
            raise
        else:
            report["mount"] = "pass"
        finally:
            clean_revision(revision)
            if sha256(cargo_lock) != report["lockfile_sha256"]:
                raise RuntimeError("Cargo.lock changed during qualification")
            if fixture_source_fingerprints() != report["fixture_source_sha256"]:
                raise RuntimeError("fixture sources changed during qualification")
            if sha256(binary) != report["test_executable_sha256"]:
                raise RuntimeError("unit-test executable changed during qualification")


def main(*, binding=default_binding, mount_runner=run_mount, permit_helper=True):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--revision")
    if permit_helper:
        parser.add_argument("--mount-helper", nargs=3)
    args = parser.parse_args()
    os.environ["LC_ALL"] = "C"
    if permit_helper and args.mount_helper:
        work, binary, namespace = args.mount_helper
        try:
            mount_helper(Path(work), Path(binary), namespace)
        except Blocked as error:
            print(str(error), file=sys.stderr)
            return BLOCKED_EXIT
        return 0
    if args.evidence is None or args.revision is None:
        parser.error("--evidence and --revision are required")
    evidence = args.evidence.resolve()
    evidence.mkdir(mode=0o700)
    report = {
        "revision": args.revision, "native": platform.platform(),
        "outcome": "failed", "ordinary_passed": [], "mount": "not_run", "cleanup": "not_created",
    }
    status = 1
    try:
        run(args.revision, evidence, report, binding=binding, mount_runner=mount_runner)
    except Blocked as error:
        report.update(outcome="blocked", reason=str(error))
        status = BLOCKED_EXIT
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        report["reason"] = str(error)
    else:
        report["outcome"] = "pass"
        status = 0
    finally:
        write_report(evidence, report)
    return status


if __name__ == "__main__":
    sys.exit(main())
