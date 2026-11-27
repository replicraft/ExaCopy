"""Collect coverage from the exact held native component image."""

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat

PROFILE = "linux-unprivileged-whole-ext4-witnessed-component-coverage-v1"
INSTRUMENTATION = "-Cinstrument-coverage"
RAW_NAME = "counters.profraw"
INDEX_SLOT = "merge"
INDEX_NAME = "measured.profdata"
RAW_LIMIT = 16 * 1024 * 1024
IMAGE_LIMIT = 256 * 1024 * 1024
EXPORT_LIMIT = 32 * 1024 * 1024
INDEXED_PROFILE_LIMIT = 32 * 1024 * 1024
EXPORT_TYPE = "llvm.coverage.json.export"
EXPORT_VERSION = "3.1.0"
CRATE_PREFIX = "crates/platform/exacopy-platform/"
SOURCE_PREFIX = CRATE_PREFIX + "src/"
TEST_PREFIX = CRATE_PREFIX + "tests/"
TOOL_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stamp(node):
    return (node.st_dev, node.st_ino, node.st_mode, node.st_nlink,
            node.st_uid, node.st_gid, node.st_size, node.st_mtime_ns, node.st_ctime_ns)


def checked_file(path, fd, limit, destination=None):
    node = os.fstat(fd)
    identity = stamp(node)
    require(stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and node.st_uid == os.geteuid()
            and not node.st_mode & 0o022 and 0 < node.st_size <= limit
            and stamp(path.stat(follow_symlinks=False)) == identity,
            "coverage file is not a bounded held private regular file")
    digest = hashlib.sha256()
    size = 0
    while size < node.st_size:
        data = os.pread(fd, min(65536, node.st_size - size), size)
        require(data, "coverage file ended during hashing")
        digest.update(data)
        if destination is not None:
            destination.write(data)
        size += len(data)
    require(not os.pread(fd, 1, size) and stamp(os.fstat(fd)) == identity
            and stamp(path.stat(follow_symlinks=False)) == identity,
            "coverage file changed during hashing")
    return {"device": node.st_dev, "inode": node.st_ino, "size": size,
            "sha256": digest.hexdigest()}


@dataclass(frozen=True)
class Slot:
    directory: Path
    fd: int

    def check(self):
        node = os.fstat(self.fd)
        require(stat.S_ISDIR(node.st_mode) and node.st_uid == os.geteuid()
                and stat.S_IMODE(node.st_mode) == 0o700
                and os.path.samestat(node, self.directory.stat(follow_symlinks=False)),
                "coverage sink ownership or identity changed")


class Profiles:
    def __init__(self, ext4, stack, work, evidence, report):
        self.ext4 = ext4
        self.stack = stack
        self.evidence = evidence
        self.report = report
        self.slots = {}
        self.collected = {}
        self.root_path = work / "profiles"
        self.root = None
        self.report.update(admitted_profiles=[], discarded_listing_profiles=[])

    def prepare(self):
        require(self.root is None and "%" not in str(self.root_path),
                "invalid or repeated coverage root preparation")
        self.root_path.mkdir(mode=0o700)
        self.root = self.open_directory(self.root_path)

    def open_directory(self, directory, parent_fd=None):
        name = directory if parent_fd is None else directory.name
        fd = os.open(name, self.ext4.DIR_FLAGS, dir_fd=parent_fd)
        self.stack.callback(os.close, fd)
        slot = Slot(directory, fd)
        slot.check()
        require(not os.listdir(fd), "coverage sink was not empty")
        return slot

    def create_slot(self, label):
        self.check_root()
        require(label not in self.slots, "repeated coverage sink")
        self.slots[label] = None
        os.mkdir(label, mode=0o700, dir_fd=self.root.fd)
        slot = self.open_directory(self.root.directory / label, self.root.fd)
        self.slots[label] = slot
        return slot

    def allocate(self, label, environment):
        require(re.fullmatch(r"case-[1-7]-(listed|ignored|run)", label),
                "unexpected coverage invocation")
        slot = self.create_slot(label)
        return {**environment, "LLVM_PROFILE_FILE": str(slot.directory / RAW_NAME)}

    def open_output(self, label, filename):
        self.check_root()
        slot = self.slots.get(label)
        require(slot is not None and label not in self.collected, "unconfirmed or repeated coverage output")
        slot.check()
        require(os.listdir(slot.fd) == [filename], "coverage invocation did not produce exactly one expected file")
        path = slot.directory / filename
        fd = os.open(filename, self.ext4.FD_FLAGS | os.O_NONBLOCK, dir_fd=slot.fd)
        return path, fd

    def collect(self, label, selector, image_sha256):
        path, fd = self.open_output(label, RAW_NAME)
        try:
            receipt = checked_file(path, fd, RAW_LIMIT)
            receipt.update(selector=selector, launch=label, executable_sha256=image_sha256)
            inode = (receipt["device"], receipt["inode"])
            require(all(inode != (entry[2]["device"], entry[2]["inode"])
                        for entry in self.collected.values()), "duplicate coverage profile inode")
            if label.endswith("-run"):
                retained = f"{label}.profraw"
                with (self.evidence / retained).open("xb") as dst:
                    copied = checked_file(path, fd, RAW_LIMIT, dst)
                require(all(receipt[key] == value for key, value in copied.items()),
                        "coverage profile changed before retention")
                receipt["retained"] = retained
                self.report["admitted_profiles"].append(receipt)
            else:
                self.report["discarded_listing_profiles"].append(receipt)
            self.collected[label] = (path, fd, receipt)
            self.stack.callback(os.close, fd)
            fd = None
        finally:
            if fd is not None:
                os.close(fd)

    def begin_merge(self):
        return self.create_slot(INDEX_SLOT).directory / INDEX_NAME

    def collect_index(self):
        path, fd = self.open_output(INDEX_SLOT, INDEX_NAME)
        try:
            with (self.evidence / INDEX_NAME).open("xb") as retained:
                receipt = checked_file(path, fd, INDEXED_PROFILE_LIMIT, retained)
            self.report["merged_profile"] = {**receipt, "retained": INDEX_NAME}
            self.collected[INDEX_SLOT] = (path, fd, receipt)
            self.stack.callback(os.close, fd)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def check_root(self):
        require(self.root is not None, "coverage root custody unconfirmed; private work retained")
        self.root.check()

    def check_cleanup(self):
        self.check_root()
        require(set(os.listdir(self.root.fd)) == set(self.slots), "unexpected coverage sink")
        for label, slot in self.slots.items():
            require(slot is not None, "coverage sink custody unconfirmed; private work retained")
            slot.check()
            names = os.listdir(slot.fd)
            if label not in self.collected:
                require(not names, "uncollected coverage output; private work retained")
                continue
            path, fd, receipt = self.collected[label]
            require(names == [path.name], "collected coverage output no longer uniquely named")
            limit = INDEXED_PROFILE_LIMIT if label == INDEX_SLOT else RAW_LIMIT
            observed = checked_file(path, fd, limit)
            require(all(receipt[key] == value for key, value in observed.items()),
                    "collected coverage profile changed")

    def export(self, image_path, image_fd, image_receipt, tools, cases):
        admitted = [entry for label, entry in self.collected.items() if label.endswith("-run")]
        require([entry[2]["selector"] for entry in admitted] == list(cases)
                and len(self.collected) == 3 * len(cases),
                "coverage collection lacks exact measured and discarded attendance")
        self.check_cleanup()
        packed = self.begin_merge()
        profile_fds = tuple(entry[1] for entry in admitted)
        command = self.ext4.command
        command(self.evidence, "coverage-merge",
                [tools["llvm-profdata"], "merge", "--failure-mode=any", "--sparse",
                 "-o", packed, *(fd_path(fd) for fd in profile_fds)],
                env=TOOL_ENV, held=profile_fds, timeout=60)
        require(not (self.evidence / "coverage-merge.stderr").stat().st_size,
                "LLVM profile merge reported diagnostics")
        packed_fd = self.collect_index()
        self.report.update(profile_admission="pass", phase="export", export="incomplete")
        output = command(self.evidence, "coverage-export",
                         [tools["llvm-cov"], "export", "--summary-only",
                          "-instr-profile", fd_path(packed_fd), fd_path(image_fd)],
                         env=TOOL_ENV, held=(packed_fd, image_fd), timeout=90,
                         output_limit=EXPORT_LIMIT)
        require(not (self.evidence / "coverage-export.stderr").stat().st_size,
                "LLVM coverage export reported diagnostics")
        require(checked_file(image_path, image_fd, IMAGE_LIMIT) == image_receipt,
                "instrumented executable changed during coverage export")
        self.check_cleanup()
        tracked = command(self.evidence, "coverage-sources",
                          ["git", "ls-files", "-z", "--", SOURCE_PREFIX, TEST_PREFIX])
        sources = sorted(path for path in tracked.split("\0") if path.endswith(".rs"))
        inventory = [path for path in sources if path.startswith(SOURCE_PREFIX)]
        test_inventory = [path for path in sources if path.startswith(TEST_PREFIX)]
        mapping = summarize(parse_export(output), self.ext4.ROOT, inventory, test_inventory)
        encoded = output.encode("utf-8")
        mapping["export_sha256"] = hashlib.sha256(encoded).hexdigest()
        mapping["export_size"] = len(encoded)
        return mapping


def fd_path(fd):
    return f"/proc/self/fd/{fd}"


def pinned_tools(ext4, evidence, compiler, report):
    llvm = [line.removeprefix("LLVM version: ") for line in compiler if line.startswith("LLVM version: ")]
    require(len(llvm) == 1 and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", llvm[0]),
            "could not bind the pinned compiler LLVM version")
    sysroot = Path(ext4.command(
        evidence, "coverage-sysroot", ["rustc", f"+{ext4.TOOLCHAIN}", "--print", "sysroot"],
    ).strip()).resolve(strict=True)
    tools = {}
    for name in ("llvm-profdata", "llvm-cov"):
        path = (sysroot / "lib/rustlib" / ext4.TARGET / "bin" / name).resolve(strict=True)
        require(path.is_relative_to(sysroot), "coverage tool escaped the pinned Rust sysroot")
        output = ext4.command(evidence, f"coverage-{name}-version", [path, "--version"], env=TOOL_ENV)
        require(re.search(rf"\bLLVM version {re.escape(llvm[0])}(?![0-9.])", output),
                "coverage tool LLVM version differs from the pinned compiler")
        tools[name] = path
        report[name] = {"path": str(path), "version": output.strip()}
    return tools


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, f"duplicate LLVM coverage JSON field {key!r}")
        result[key] = value
    return result


def finite_float(value):
    parsed = float(value)
    require(math.isfinite(parsed), "nonfinite LLVM coverage JSON number")
    return parsed


def parse_export(output):
    try:
        return json.loads(output, object_pairs_hook=unique_object, parse_float=finite_float,
                          parse_constant=finite_float)
    except RecursionError as error:
        raise ValueError("LLVM coverage JSON exceeds the supported nesting") from error


def field(record, name, kind):
    require(isinstance(record, dict) and type(record.get(name)) is kind,
            f"invalid LLVM coverage field {name!r}")
    return record[name]


def counts(summary, metric):
    item = field(summary, metric, dict)
    total, covered = field(item, "count", int), field(item, "covered", int)
    require(0 <= covered <= total, f"invalid LLVM coverage counters for {metric}")
    uncovered = total - covered
    if "notcovered" in item:
        require(field(item, "notcovered", int) == uncovered,
                f"inconsistent LLVM uncovered count for {metric}")
    percent = item.get("percent")
    expected = covered / total * 100 if total else 0
    require(type(percent) in (float, int) and 0 <= percent <= 100
            and math.isclose(percent, expected, abs_tol=1e-8),
            f"inconsistent LLVM coverage percentage for {metric}")
    return {"total": total, "covered": covered, "uncovered": uncovered}


def linked_test_source(filename, tracked_tests):
    # Interpret the LLVM label, without opening or resolving any filesystem path.
    parts = []
    for part in filename.relative_to(CRATE_PREFIX).parts:
        if part == "..":
            require(parts, "platform coverage alias leaves the owning crate")
            parts.pop()
        else:
            parts.append(part)
    name = PurePosixPath(CRATE_PREFIX, *parts).as_posix()
    require(name.startswith(TEST_PREFIX) and name in tracked_tests,
            "platform coverage alias does not name a tracked owning-crate test source")
    return name


def summarize(export, root, inventory, test_inventory):
    require(field(export, "type", str) == EXPORT_TYPE and field(export, "version", str) == EXPORT_VERSION,
            "wrong LLVM coverage export type or version")
    datasets = field(export, "data", list)
    require(len(datasets) == 1, "expected one LLVM coverage dataset")
    files = {}
    excluded = {}
    governed = set(inventory)
    tracked_tests = set(test_inventory)
    crate = root / CRATE_PREFIX
    for row in field(datasets[0], "files", list):
        label = field(row, "filename", str)
        filename = PurePosixPath(label)
        exact_spelling = filename.as_posix() == label
        if filename.is_absolute():
            if not filename.is_relative_to(root):
                require(not PurePosixPath(posixpath.normpath(filename)).is_relative_to(crate),
                        "noncanonical coverage path enters the owning crate")
                continue
            filename = filename.relative_to(root)
        name = filename.as_posix()
        if name.startswith(CRATE_PREFIX):
            require(exact_spelling, "noncanonical platform coverage path spelling")
        if ".." in filename.parts:
            if name.startswith(SOURCE_PREFIX):
                require(name not in excluded, "duplicate linked test coverage mapping")
                excluded[name] = linked_test_source(filename, tracked_tests)
                continue
            normalized = PurePosixPath(posixpath.normpath(root / filename))
            require(not name.startswith(CRATE_PREFIX) and not normalized.is_relative_to(crate),
                    "noncanonical coverage path enters or leaves the owning crate")
        if not name.startswith(SOURCE_PREFIX):
            continue
        require(name in governed and name not in files,
                "unexpected or duplicate platform source mapping")
        summary = field(row, "summary", dict)
        files[name] = {metric: counts(summary, metric) for metric in ("lines", "regions")}
    require(files and any(summary["lines"]["covered"] for summary in files.values()),
            "missing executed platform source mappings")
    totals = {metric: {field: sum(summary[metric][field] for summary in files.values())
                       for field in ("total", "covered", "uncovered")}
              for metric in ("lines", "regions")}
    return {"scope": "witnessed-component-coverage", "export": "coverage-export.stdout",
            "governed_source_inventory": inventory, "unmapped_sources": sorted(governed - files.keys()),
            "tracked_test_source_inventory": test_inventory, "excluded_linked_test_mappings": excluded,
            "files": files, "totals_for_mapped_sources": totals}
