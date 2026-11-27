"""Exercise exact native witness components on protected, unprivileged whole ext4."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import tomllib

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / "sync_history_ext4/run.py"
spec = importlib.util.spec_from_file_location("whole_ext4_history", SHARED)
ext4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ext4)

ROOT, PACKAGE = ext4.ROOT, ext4.PACKAGE
TARGET, TOOLCHAIN = ext4.TARGET, ext4.TOOLCHAIN
ID = "linux-witnessed-components-ext4"
PROFILE = "linux-unprivileged-whole-ext4-witnessed-components-v1"
WORKFLOW = f".github/workflows/{ID}-qualification.yml"
PREFIX = "linux::recovery::writer::"
CASES = (
    PREFIX + "prefix::tests::witness::actual_descriptor_link_keeps_both_names_and_held_exclusion",
    PREFIX + "prefix::tests::witness::occupied_slot_or_refused_later_barrier_never_removes_evidence",
    PREFIX + "prefix::tests::witness::witnessed_native_rename_observes_success_conflict_and_nonregular_incumbent",
    PREFIX + "witness_reservation::tests::native_allocation_preserves_the_named_segment_and_anonymous_eof",
    PREFIX + "witness_reservation::tests::only_a_submitted_journal_allocation_latches_the_lease_even_on_syscall_error",
    PREFIX + "witness_reservation::continuation::tests::original_reserved_descriptor_writes_and_rereads_only_the_exact_successor",
    PREFIX + "witness_reservation::continuation::witness::publication::receipt::tests::"
             "readonly_reopened_anonymous_receipt_links_and_promotes_original_inode",
)
COMPILER_OVERRIDES = (
    "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "LD_PRELOAD", "LD_LIBRARY_PATH",
)


def source(selector):
    return "src/" + selector.rsplit("::", 1)[0].replace("::", "/") + ".rs"


def binding(path):
    manifest = tomllib.loads(path.read_text())
    expected = {
        "schema_version": 1, "id": ID, "target": TARGET, "profile": PROFILE,
        "rust_toolchain": TOOLCHAIN, "runner": "verification/witnessed_components_ext4/run.py",
        "controls": "verification/witnessed_components_ext4/test_runner.py",
        "workflow": WORKFLOW, "result": "result.json",
        "case": [
            {"selector": case, "source": source(case), "ignored": True} for case in CASES
        ],
    }
    ext4.require(manifest == expected and type(manifest["schema_version"]) is int
                 and all(case["ignored"] is True for case in manifest["case"]),
                 "exact witnessed component manifest drift")


def inputs():
    manifest = HERE / "fixture.toml"
    binding(manifest)
    files = {
        ROOT / "Cargo.lock", ROOT / "rust-toolchain.toml", ROOT / WORKFLOW,
        ROOT / "tools/qualification/native_supervision.py",
        SHARED, manifest, HERE / "run.py", HERE / "test_runner.py",
        PACKAGE / "tests/common/scratch.rs", PACKAGE / "Cargo.toml",
        *(PACKAGE / source(case) for case in CASES),
    }
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(files)}


def artifact(output, target_root):
    candidates = []
    for row in output.splitlines():
        event = json.loads(row)
        target = event.get("target", {})
        if (event.get("reason") == "compiler-artifact" and target.get("name") == "exacopy_platform"
                and target.get("kind") == ["lib"] and event.get("profile", {}).get("test") is True
                and target.get("src_path") == str(PACKAGE / "src/lib.rs")
                and event.get("manifest_path") == str(PACKAGE / "Cargo.toml")
                and event.get("features") == [] and event.get("executable")):
            candidates.append(Path(event["executable"]))
    ext4.require(len(candidates) == 1, "expected one exact native platform unit artifact")
    path = candidates[0]
    ext4.require(path.is_absolute() and path.is_relative_to(target_root)
                 and path.resolve(strict=True) == path, "native binary escaped private build custody")
    return path


def check_listing(output, case):
    ext4.require(output.strip() == f"{case}: test", f"exact listing mismatch for {case}")


def check_test(output, case):
    lines = output.splitlines()
    outcomes = [line for line in lines if line.startswith("test ") and " ... " in line]
    summary = [line for line in lines if line.startswith("test result:")]
    ext4.require(outcomes == [f"test {case} ... ok"] and len(summary) == 1
                 and re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; "
                                  r"0 measured; [0-9]+ filtered out; finished in [0-9.]+s", summary[0]),
                 f"expected exactly one successful test for {case}")


def execute(evidence, binary, fixture, fixture_fd, report):
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(fixture)}
    fd = os.open(binary, ext4.FD_FLAGS | os.O_NONBLOCK)
    try:
        image = ext4.held_managed_image(binary, fd)
        report["executable_sha256"] = image[1]
        report["cases"] = {}
        options = {"env": env, "executable": f"/proc/self/fd/{fd}", "held": (fd,)}
        for index, case in enumerate(CASES, 1):
            for ending, flags in (("listed", []), ("ignored", ["--ignored"])):
                listed = ext4.command(
                    evidence, f"case-{index}-{ending}",
                    [binary, "--list", "--exact", "--format=terse", *flags, case], **options,
                )
                check_listing(listed, case)
            ext4.require(not os.listdir(fixture_fd), "component fixture occupied before execution")
            try:
                result = ext4.command(
                    evidence, f"case-{index}-run",
                    [binary, "--ignored", "--exact", "--test-threads=1", "--color", "never", case],
                    timeout=45, **options,
                )
            finally:
                ext4.require(ext4.held_managed_image(binary, fd) == image,
                             "held component executable changed during test")
                ext4.require(not os.listdir(fixture_fd),
                             "component fixture cleanup unconfirmed")
            check_test(result, case)
            report["cases"][case] = "pass"
    finally:
        os.close(fd)


def cleanup(evidence, work, work_id, fixture, fixture_fd):
    terminal = {"not_started", "verified_absent", "verified_absent_after_failure"}
    ext4.require(all(path.read_text().strip() in terminal for path in evidence.glob("*.drain")),
                 "owned process drain unconfirmed; private work retained")
    ext4.require(work.resolve() == work and ext4.inode(work) == work_id,
                 "owned work identity changed")
    if fixture_fd is not None:
        named = fixture.stat(follow_symlinks=False)
        held = os.fstat(fixture_fd)
        ext4.require((named.st_dev, named.st_ino) == (held.st_dev, held.st_ino)
                     and not os.listdir(fixture_fd), "owned fixture cleanup unconfirmed")
        fixture.rmdir()
    else:
        ext4.require(not os.path.lexists(fixture), "fixture ownership unconfirmed")
    shutil.rmtree(work)
    ext4.require(not os.path.lexists(work), "owned build cleanup unconfirmed")


def qualify(revision, temp, evidence, report):
    ext4.check_revision(revision, evidence, "before")
    report["inputs_sha256"] = inputs()
    fd = os.open(temp, ext4.DIR_FLAGS)
    try:
        owner = os.fstat(fd)
        if owner.st_uid != os.geteuid() or owner.st_mode & 0o022:
            raise ext4.Blocked("RUNNER_TEMP requires an owned protected directory")
        report["substrate"] = ext4.observe(temp, fd, evidence, "runner-before")
    finally:
        os.close(fd)
    ext4.require(not any(os.environ.get(key) for key in COMPILER_OVERRIDES),
                 "compiler or loader override present")
    compiler = ext4.command(evidence, "rustc", ["rustc", f"+{TOOLCHAIN}", "-vV"]).splitlines()
    ext4.require(f"host: {TARGET}" in compiler and f"release: {TOOLCHAIN}" in compiler,
                 "unexpected native Rust compiler")
    work = Path(tempfile.mkdtemp(prefix=f"{ID}-work-", dir=temp))
    report.update(cleanup="pending", owned_work_basename=work.name)
    work_id = ext4.inode(work)
    fixture = work / "fixture"
    fixture_fd = None
    try:
        fixture.mkdir(mode=0o700)
        fixture_fd = os.open(fixture, ext4.DIR_FLAGS)
        held = os.fstat(fixture_fd)
        ext4.require(held.st_uid == os.geteuid() and stat.S_IMODE(held.st_mode) == 0o700
                     and not os.listdir(fixture_fd), "fixture parent is not privately owned and empty")
        before = ext4.observe(fixture, fixture_fd, evidence, "fixture-before")
        ext4.require({key: value for key, value in before.items() if key != "parent"} ==
                     {key: value for key, value in report["substrate"].items() if key != "parent"},
                     "owned fixture escaped the observed runner mount or actor")
        target = work / "target"
        env = {
            **os.environ, "CARGO_TARGET_DIR": str(target), "CARGO_BUILD_BUILD_DIR": str(target),
            "CARGO_INCREMENTAL": "0", "CARGO_PROFILE_TEST_DEBUG": "0", "LC_ALL": "C",
            "TMPDIR": str(work),
        }
        output = ext4.command(
            evidence, "cargo", ["cargo", f"+{TOOLCHAIN}", "test", "--locked", "--offline",
                                "--jobs", "2", "--target", TARGET, "-p", "exacopy-platform",
                                "--no-default-features", "--lib", "--no-run", "--message-format=json"],
            env=env, timeout=900,
        )
        execute(evidence, artifact(output, target), fixture, fixture_fd, report)
        try:
            after = ext4.observe(fixture, fixture_fd, evidence, "fixture-after")
        except ext4.Blocked as error:
            raise ValueError("native substrate unavailable after execution") from error
        ext4.require(after == before, "native component substrate changed")
        report["fixture_substrate"] = before
        ext4.check_revision(revision, evidence, "after")
        ext4.require(inputs() == report["inputs_sha256"], "fixture inputs changed")
    finally:
        try:
            cleanup(evidence, work, work_id, fixture, fixture_fd)
            report["cleanup"] = "verified_absent"
        finally:
            if fixture_fd is not None:
                os.close(fixture_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    temp = Path(os.environ["RUNNER_TEMP"])
    ext4.require(temp.is_absolute() and temp.resolve(strict=True) == temp, "invalid RUNNER_TEMP")
    evidence = Path(tempfile.mkdtemp(prefix=f"{ID}-evidence-", dir=temp))
    if output_path := os.environ.get("GITHUB_OUTPUT"):
        ext4.require("\n" not in str(evidence) and "\r" not in str(evidence), "invalid evidence path")
        with open(output_path, "a", encoding="utf-8") as output:
            output.write(f"evidence_path={evidence}\n")
    report = {"revision": args.revision, "profile": PROFILE, "scope": "native-components",
              "outcome": "failed", "cleanup": "not_created"}
    code = 1
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, ext4.supervision.interrupted)
    try:
        qualify(args.revision, temp, evidence, report)
    except ext4.Blocked as error:
        report.update(outcome="blocked", reason=str(error))
        code = 77
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["reason"] = str(error)
    else:
        if ext4.supervision.CANCELLATION_REQUESTED:
            report["reason"] = "native runner cancelled"
        else:
            report["outcome"] = "pass"
            code = 0
    finally:
        with (evidence / "result.json").open("x", encoding="utf-8") as result:
            result.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
