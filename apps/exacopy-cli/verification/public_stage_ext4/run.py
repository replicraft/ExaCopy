"""Run the exact public-stage composition test on an unprivileged native ext4 host."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PACKAGE = HERE.parents[1]
COMPONENT_DIR = ROOT / "crates/platform/exacopy-platform/verification/witnessed_components_ext4"
spec = importlib.util.spec_from_file_location("witnessed_ext4_runner", COMPONENT_DIR / "run.py")
components = importlib.util.module_from_spec(spec)
spec.loader.exec_module(components)

ext4 = components.ext4
TARGET, TOOLCHAIN = ext4.TARGET, ext4.TOOLCHAIN
ID = "linux-public-stage-ext4"
PROFILE = "linux-unprivileged-whole-ext4-public-stage-v1"
SCOPE = "private-stage-and-checked-transfer-components-with-synthetic-authority"
WORKFLOW = f".github/workflows/{ID}-qualification.yml"
SOURCE = "src/assembly/linux/public_stage/tests.rs"
CASE = "assembly::linux::public_stage::tests::approved_stage_reopens_with_exact_owner_and_preserves_uncertain_evidence"
MARKER = "EXACOPY_PUBLIC_STAGE_EXT4_RESULT preserved_and_cleaned"
SOURCE_CHECKS = ("apfs_source", "transport_source")
CARGO_ENV = {"CARGO_HOME", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "CARGO_TERM_COLOR"}


def inputs():
    profile = HERE / "fixture.toml"
    expected = {
        "schema_version": 1, "id": ID, "target": TARGET, "profile": PROFILE,
        "rust_toolchain": TOOLCHAIN, "workflow": WORKFLOW, "result": "result.json",
        "runner": "verification/public_stage_ext4/run.py",
        "controls": "verification/public_stage_ext4/test_runner.py",
        "case": [{"kind": "rust-unit", "selector": CASE, "source": SOURCE, "ignored": True}],
    }
    declaration = tomllib.loads(profile.read_text())
    ext4.require(declaration == expected and type(declaration["schema_version"]) is int
                 and declaration["case"][0]["ignored"] is True, "exact fixture profile drift")
    files = (
        ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "rust-toolchain.toml",
        *(ROOT / "tools" / f"{name}.py" for name in SOURCE_CHECKS),
        ROOT / "specs/dependencies/apfs-source.toml",
        ROOT / "specs/dependencies/transport-source.toml",
        ROOT / "tools/qualification/native_supervision.py", ROOT / WORKFLOW,
        COMPONENT_DIR / "run.py", components.SHARED, components.COVERAGE_HELPER,
        profile, HERE / "run.py", HERE / "test_runner.py",
        PACKAGE / "Cargo.toml", PACKAGE / "src/lib.rs", PACKAGE / "src/assembly.rs",
        PACKAGE / "src/assembly/linux.rs", PACKAGE / "src/assembly/linux/public_stage.rs",
        PACKAGE / SOURCE, PACKAGE / Path(SOURCE).with_suffix("") / "fixture.rs",
        PACKAGE / Path(SOURCE).with_suffix("") / "late_journal.rs",
        PACKAGE / Path(SOURCE).with_suffix("") / "checked_apply.rs",
        PACKAGE / Path(SOURCE).with_suffix("") / "checked_apply" / "terminal.rs",
        HERE / "checked_component.rs",
    )
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


def artifact(output, target_root):
    candidates = []
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    package_id = f"path+{PACKAGE.as_uri()}#{version}"
    for row in output.splitlines():
        event = json.loads(row)
        target = event.get("target", {})
        if (event.get("reason") == "compiler-artifact" and target.get("name") == "exacopy_cli"
                and target.get("kind") == ["lib"] and target.get("crate_types") == ["lib"]
                and target.get("edition") == "2024" and event.get("profile", {}).get("test") is True
                and event.get("package_id") == package_id and event.get("fresh") is False
                and target.get("src_path") == str(PACKAGE / "src/lib.rs")
                and event.get("manifest_path") == str(PACKAGE / "Cargo.toml")
                and event.get("features") == [] and event.get("executable")):
            candidates.append(Path(event["executable"]))
    ext4.require(len(candidates) == 1, "expected one exact native CLI unit artifact")
    path = candidates[0]
    ext4.require(path.is_absolute() and path.is_relative_to(target_root)
                 and path.resolve(strict=True) == path, "native artifact escaped private build custody")
    return path


def check_run(output):
    ext4.require(output.splitlines().count(MARKER) == 1, "missing exact fixture cleanup marker")
    components.check_test(output, CASE)


def execute(evidence, binary, fixture, fixture_fd, report):
    fd = os.open(binary, ext4.FD_FLAGS | os.O_NONBLOCK)
    try:
        image = ext4.held_managed_image(binary, fd)
        report["executable_sha256"] = image[1]
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "EXACOPY_PUBLIC_STAGE_EXT4_PARENT": str(fixture)}
        options = {"env": env, "executable": f"/proc/self/fd/{fd}", "held": (fd,)}
        for name, extra in (("list", []), ("ignored", ["--ignored"])):
            output = ext4.command(
                evidence, name, [binary, "--list", "--exact", "--format=terse", *extra, CASE], **options
            )
            components.check_listing(output, CASE)
        ext4.require(not os.listdir(fixture_fd), "fixture parent occupied before test")
        try:
            output = ext4.command(
                evidence, "test",
                [binary, "--ignored", "--exact", "--test-threads=1", "--color=never", "--show-output", CASE],
                timeout=45, **options,
            )
        finally:
            ext4.require(ext4.held_managed_image(binary, fd) == image, "held CLI test changed during execution")
            ext4.require(not os.listdir(fixture_fd), "owned fixture cleanup unconfirmed")
        check_run(output)
        report["selector"] = CASE
    finally:
        os.close(fd)


def check_cargo_environment():
    conflicting = any(
        key.startswith("CARGO_") and key not in CARGO_ENV
        or key in components.COMPILER_OVERRIDES
        for key in os.environ
    )
    ext4.require(not conflicting, "additional Cargo, compiler or loader override present")
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    ext4.require(cargo_home.is_absolute(), "relative Cargo home")
    directories = {cargo_home, ROOT / ".cargo", *(parent / ".cargo" for parent in ROOT.parents)}
    for directory in directories:
        ext4.require(not any(os.path.lexists(directory / name) for name in ("config", "config.toml")),
                     "additional Cargo configuration present")


def source_checks(evidence, phase):
    return {
        name: ext4.command(
            evidence, f"{name}-{phase}", ["python3", "-B", ROOT / "tools" / f"{name}.py"], timeout=90
        )
        for name in SOURCE_CHECKS
    }


def qualify(revision, temp, evidence, report):
    ext4.check_revision(revision, evidence, "before")
    report["inputs_sha256"] = inputs()
    fd = os.open(temp, ext4.DIR_FLAGS)
    try:
        owner = os.fstat(fd)
        if owner.st_uid != os.geteuid() or owner.st_mode & 0o022:
            raise ext4.Blocked("temporary parent requires an owned protected directory")
        report["substrate"] = ext4.observe(temp, fd, evidence, "before", ext4.MANAGED)
    finally:
        os.close(fd)
    check_cargo_environment()
    sources = source_checks(evidence, "before")
    compiler = ext4.command(evidence, "rustc", ["rustc", f"+{TOOLCHAIN}", "-vV"]).splitlines()
    ext4.require(f"host: {TARGET}" in compiler and f"release: {TOOLCHAIN}" in compiler,
                 "unexpected native Rust compiler")
    work = Path(tempfile.mkdtemp(prefix=f"{ID}-work-", dir=temp))
    work_id = ext4.inode(work)
    report.update(cleanup="pending", owned_work_basename=work.name)
    fixture = work / "fixture"
    fixture_fd = None
    try:
        fixture.mkdir(mode=0o700)
        fixture_fd = os.open(fixture, ext4.DIR_FLAGS)
        held = os.fstat(fixture_fd)
        ext4.require(held.st_uid == os.geteuid() and stat.S_IMODE(held.st_mode) == 0o700
                     and not os.listdir(fixture_fd), "fixture parent is not privately owned and empty")
        before = ext4.observe(fixture, fixture_fd, evidence, "fixture-before", ext4.MANAGED)
        ext4.require({key: value for key, value in before.items() if key != "parent"} ==
                     {key: value for key, value in report["substrate"].items() if key != "parent"},
                     "fixture escaped the observed runner mount or actor")
        target = work / "target"
        env = {**os.environ, "CARGO_TARGET_DIR": str(target), "CARGO_BUILD_BUILD_DIR": str(target),
               "CARGO_INCREMENTAL": "0", "CARGO_PROFILE_TEST_DEBUG": "0", "LC_ALL": "C",
               "TMPDIR": str(work)}
        args = ["cargo", f"+{TOOLCHAIN}", "test", "--locked", "--offline", "--jobs", "2",
                "--target", TARGET, "-p", "exacopy-cli", "--no-default-features", "--lib",
                "--no-run", "--message-format=json"]
        output = ext4.command(evidence, "cargo", args, timeout=900, env=env)
        execute(evidence, artifact(output, target), fixture, fixture_fd, report)
        try:
            after = ext4.observe(fixture, fixture_fd, evidence, "fixture-after", ext4.MANAGED)
        except ext4.Blocked as error:
            raise ValueError("native substrate unavailable after test execution") from error
        ext4.require(after == before, "native fixture substrate changed")
        ext4.require(source_checks(evidence, "after") == sources, "pinned inputs changed")
        ext4.check_revision(revision, evidence, "after")
        ext4.require(inputs() == report["inputs_sha256"], "fixture inputs changed")
    finally:
        try:
            components.cleanup(evidence, work, work_id, fixture, fixture_fd)
            report["cleanup"] = "verified_absent"
        finally:
            if fixture_fd is not None:
                os.close(fixture_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--temporary-parent", required=True, type=Path)
    args = parser.parse_args()
    temp = args.temporary_parent
    ext4.require(temp.is_absolute() and temp.resolve(strict=True) == temp, "invalid temporary parent")
    evidence = Path(tempfile.mkdtemp(prefix=f"{ID}-evidence-", dir=temp))
    print(evidence)
    if output := os.environ.get("GITHUB_OUTPUT"):
        ext4.require("\n" not in str(evidence) and "\r" not in str(evidence), "invalid evidence path")
        with open(output, "a", encoding="utf-8") as stream:
            stream.write(f"evidence_path={evidence}\n")
    report = {"revision": args.revision, "profile": PROFILE, "scope": SCOPE,
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
