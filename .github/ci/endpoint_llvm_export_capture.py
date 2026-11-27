#!/usr/bin/python3
"""Retain pre-execution provenance for the ordinary LLVM coverage export."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys

FILE_LIMIT = 256 * 1024 * 1024
TOTAL_LIMIT = 1024 * 1024 * 1024
ARG_LIMIT = 64 * 1024
OBJECT_LIMIT = 128
BLOCK = 1024 * 1024
CHILD_ARGV_LIMIT = 512


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stamp(node):
    return node.st_dev, node.st_ino, node.st_size, node.st_mtime_ns, node.st_ctime_ns


def receipt(path, budget):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= min(FILE_LIMIT, budget),
                "export input is not a bounded regular file")
        sha256 = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(BLOCK, remaining))
            require(block, "export input ended during capture")
            sha256.update(block)
            remaining -= len(block)
        require(not os.read(fd, 1) and stamp(os.fstat(fd)) == stamp(before)
                and stamp(path.stat(follow_symlinks=False)) == stamp(before),
                "export input changed during capture")
        return {"path": str(path), "size": before.st_size, "sha256": sha256.hexdigest()}
    finally:
        os.close(fd)


def resolve_path(path):
    try:
        return path.resolve(strict=True)
    except RuntimeError as error:
        # pathlib reports symlink loops as RuntimeError on Python 3.12.
        raise ValueError("coverage path could not be resolved") from error


def owned_path(raw, root, cwd):
    path = cwd / raw
    require(".." not in path.parts and path.is_relative_to(root)
            and resolve_path(path) == path, "export input escaped the coverage target")
    return path


def export_inputs(args):
    require(0 < len(args) <= CHILD_ARGV_LIMIT
            and sum(len(os.fsencode(arg)) + 1 for arg in args) <= ARG_LIMIT,
            "LLVM export arguments exceeded the capture bound")
    require(len(args) >= 5 and args[:2] == ["export", "-format=text"]
            and args[2].startswith("-instr-profile="), "unsupported LLVM export arguments")
    profile = args[2].removeprefix("-instr-profile=")
    require(profile and not profile.startswith(("-", "@")), "missing LLVM profile argument")
    objects = []
    index = 3
    while index + 1 < len(args) and args[index] == "-object":
        item = args[index + 1]
        require(item and not item.startswith(("-", "@")), "unsupported LLVM object argument")
        objects.append(item)
        index += 2
    require(0 < len(objects) <= OBJECT_LIMIT, "unsupported LLVM export arguments")
    options = args[index:]
    require(not options or (len(options) == 2 and options[0] == "-ignore-filename-regex"
                            and options[1] and not options[1].startswith(("-", "@"))),
            "unsupported LLVM export arguments")
    return profile, objects, options[1] if options else None


def capture(args, tool, cwd, root):
    require(root.is_absolute() and resolve_path(root) == root,
            "coverage target is not canonical")
    profile_input, object_inputs, ignore_regex = export_inputs(args)
    objects = [owned_path(raw, root, cwd) for raw in object_inputs]
    require(len(objects) == len(set(objects)), "duplicate LLVM export object")
    profile = owned_path(profile_input, root, cwd)
    require(profile.suffix == ".profdata", "unexpected export profile extension")
    budget = TOTAL_LIMIT
    receipts = []
    for path in [tool, profile, *objects]:
        item = receipt(path, budget)
        budget -= item["size"]
        receipts.append(item)
    return {"schema": 1, "phase": "before_llvm_export", "argv": args,
            "working_directory": str(cwd), "campaign_target": str(root),
            "tool": receipts[0], "indexed_profile": receipts[1], "objects": receipts[2:],
            "ignore_filename_regex": ignore_regex}


def record(directory, document, stem):
    require(directory.is_absolute() and resolve_path(directory) == directory,
            "coverage evidence directory is not canonical")
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        held = os.fstat(directory_fd)
        named = directory.stat(follow_symlinks=False)
        require(held.st_uid == os.geteuid() and stat.S_IMODE(held.st_mode) == 0o700
                and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino),
                "coverage evidence directory is not held and private")
        # Exclusive numbered files retain multiplicity without overwriting earlier receipts.
        data = (json.dumps(document, ensure_ascii=True, sort_keys=True) + "\n").encode("ascii")
        for index in range(1, 5):
            name = f"endpoint-llvm-export-{stem}-{index}.json"
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                             0o600, dir_fd=directory_fd)
            except FileExistsError:
                continue
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            return
        raise ValueError("LLVM export evidence slots exhausted")
    finally:
        os.close(directory_fd)


def forward(args, tool, environment):
    if args[:1] == ["export"]:
        try:
            directory = Path(environment["EXACOPY_ENDPOINT_LLVM_EVIDENCE"])
            root = Path(environment["EXACOPY_ENDPOINT_LLVM_TARGET"])
            record(directory, capture(args, tool, Path.cwd(), root), "capture")
        except (KeyError, OSError, ValueError) as error:
            try:
                directory = Path(environment["EXACOPY_ENDPOINT_LLVM_EVIDENCE"])
                record(directory, {"schema": 1, "phase": "capture_failed",
                                   "error": str(error)[:1024]}, "failure")
            except (KeyError, OSError, ValueError):
                pass
    os.execv(tool, [str(tool), *args])


if __name__ == "__main__":
    forward(sys.argv[1:], Path(os.environ["EXACOPY_ENDPOINT_LLVM_TOOL"]), os.environ)
