"""Bind the ordinary platform coverage ELF and verify exact case listings."""

from contextlib import ExitStack, contextmanager
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import stat

import run

COLLECTOR = run.ROOT / ".github/ci/endpoint_llvm_export_capture.py"
SOURCE_INPUTS = (".github/ci/assurance.sh", ".github/ci/endpoint_llvm_export_capture.py",
                 ".github/workflows/coverage.yml", ".config/nextest.toml")
CAPTURES = tuple(f"endpoint-llvm-export-capture-{index}.json" for index in (1, 2))
CAPTURE_LIMIT = 1024 * 1024
PLATFORM_UNIT = re.compile(r"debug/build/exacopy-platform/([0-9a-f]{16})/out/exacopy_platform-\1")


def source_snapshot(revision, evidence, phase):
    """Take the initial snapshot before the ordinary instrumented build."""
    run.ext4.check_revision(revision, evidence, phase)
    tree = run.ext4.command(evidence, f"ordinary-tree-{phase}", ["git", "rev-parse", "HEAD^{tree}"]).strip()
    run.ext4.require(re.fullmatch(r"[0-9a-f]{40}", tree), "invalid ordinary coverage source tree")
    inputs = run.inputs(coverage=True)
    for name in (*SOURCE_INPUTS, str(Path(__file__).relative_to(run.ROOT))):
        inputs[name] = hashlib.sha256((run.ROOT / name).read_bytes()).hexdigest()
    return {"revision": revision, "tree": tree, "inputs_sha256": inputs}


@contextmanager
def held_capture_pair(directory):
    require = run.ext4.require
    require(directory.is_absolute() and directory.resolve(strict=True) == directory,
            "ordinary capture directory is not canonical")
    with ExitStack() as stack:
        fd = os.open(directory, run.ext4.DIR_FLAGS)
        stack.callback(os.close, fd)
        held = os.fstat(fd)
        stamp = run.coverage_profile.stamp
        require(held.st_uid == os.geteuid() and stat.S_IMODE(held.st_mode) == 0o700,
                "ordinary capture directory is not held and private")

        def check_directory():
            require(set(os.listdir(fd)) == set(CAPTURES)
                    and stamp(os.fstat(fd)) == stamp(directory.stat(follow_symlinks=False)) == stamp(held),
                    "ordinary export receipt directory or inventory changed")

        check_directory()
        receipts = []
        for name in CAPTURES:
            source = os.open(name, run.ext4.FD_FLAGS | os.O_NONBLOCK, dir_fd=fd)
            stack.callback(os.close, source)
            receipts.append((directory / name, source, stamp(os.fstat(source))))

        def read_pair():
            check_directory()
            documents = []
            for path, source, original in receipts:
                require(stamp(os.fstat(source)) == original, "held ordinary export receipt changed")
                with BytesIO() as content:
                    run.coverage_profile.checked_file(path, source, CAPTURE_LIMIT, content)
                    documents.append(content.getvalue())
                require(stamp(os.fstat(source)) == original, "held ordinary export receipt changed")
            check_directory()
            require(documents[0] == documents[1], "ordinary export receipts differ")
            return documents[0]

        yield read_pair


def platform_unit(objects, target):
    candidates = []
    for entry in objects:
        path = Path(entry["path"])
        run.ext4.require(path.is_relative_to(target), "ordinary LLVM object escaped campaign target")
        if PLATFORM_UNIT.fullmatch(path.relative_to(target).as_posix()):
            candidates.append(entry)
    run.ext4.require(len(candidates) == 1, "expected one ordinary platform library test executable")
    return candidates[0]


def verify_capture(collector, raw, tool, target):
    require = run.ext4.require
    require(Path(collector.__file__) == COLLECTOR, "unexpected ordinary LLVM collector source")
    record = run.coverage_profile.parse_export(raw)
    argv = run.coverage_profile.field(record, "argv", list)
    require(all(type(arg) is str for arg in argv), "ordinary export arguments require strings")
    observed = collector.capture(argv, tool, run.ROOT, target)
    canonical = (json.dumps(observed, ensure_ascii=True, sort_keys=True) + "\n").encode("ascii")
    require(raw == canonical, "ordinary LLVM source, tool, object, or target binding changed")
    return platform_unit(observed["objects"], target)


@contextmanager
def held_listed_image(revision, before_build, collector, temp, evidence, fixture, fixture_fd, profiles):
    """Yield the same held image after all ordinary and ignored listings."""
    run.check_coverage_host(revision)
    require = run.ext4.require
    require(source_snapshot(revision, evidence, "ordinary-before-listing") == before_build,
            "ordinary coverage source changed since before build")
    compiler = run.ext4.command(evidence, "ordinary-rustc", ["rustc", f"+{run.TOOLCHAIN}", "-vV"]).splitlines()
    require(f"release: {run.TOOLCHAIN}" in compiler and f"host: {run.TARGET}" in compiler,
            "unexpected ordinary coverage compiler")
    tool = run.coverage_profile.pinned_tools(run.ext4, evidence, compiler, {})["llvm-cov"]
    target = run.ROOT / "target/llvm-cov-target"
    directory = temp / "exacopy-evidence/endpoint-llvm-export"
    with held_capture_pair(directory) as read_pair, ExitStack() as stack:
        raw = read_pair()
        selected = verify_capture(collector, raw, tool, target)
        path = Path(selected["path"])
        fd = os.open(path, run.ext4.FD_FLAGS | os.O_NONBLOCK)
        stack.callback(os.close, fd)
        image = run.ext4.held_managed_image(path, fd)
        require((image[0][6], image[1]) == (selected["size"], selected["sha256"]),
                "held platform ELF differs from original ordinary export")
        environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(fixture)}
        for index, case in enumerate(run.CASES, 1):
            for ending, flags in (("listed", []), ("ignored", ["--ignored"])):
                label = f"case-{index}-{ending}"
                require(not os.listdir(fixture_fd), "ordinary selector fixture occupied")
                output = run.ext4.command(
                    evidence, label, [path, "--list", "--exact", "--format=terse", *flags, case],
                    env=profiles.allocate(label, environment), executable=f"/proc/self/fd/{fd}", held=(fd,))
                run.check_listing(output, case)
                require(run.ext4.held_managed_image(path, fd) == image and not os.listdir(fixture_fd),
                        "ordinary listing changed held image or fixture")
                profiles.collect(label, case, image[1])
        require(source_snapshot(revision, evidence, "ordinary-after-listing") == before_build,
                "ordinary coverage source changed during listings")
        require(verify_capture(collector, raw, tool, target) == selected
                and run.ext4.held_managed_image(path, fd) == image and read_pair() == raw,
                "ordinary campaign binding changed during listings")
        profiles.check_cleanup()
        yield path, fd, image
