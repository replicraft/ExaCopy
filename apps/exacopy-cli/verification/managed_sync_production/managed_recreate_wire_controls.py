"""Collect five exact managed-recreate approval wire unit results."""

import hashlib
import json
import os
from pathlib import Path
import re
import tomllib

PACKAGE = "exacopy-cli"
LIBRARY = "exacopy_cli"
PREFIX = "assembly::linux::managed_sync::activation::wire::tests::"
CASES = tuple(PREFIX + name for name in (
    "approval_refuses_substituted_roles_and_stale_artifacts",
    "approval_refuses_wrong_signature_role_or_purpose",
    "approval_role_projections_match_independent_slot_and_segment_vectors",
    "approval_window_refuses_unavailable_or_exclusive_time",
    "host_grant_parent_and_activation_match_independent_vectors",
))
INPUTS = (
    "Cargo.toml",
    "src/lib.rs",
    "src/assembly.rs",
    "src/assembly/linux.rs",
    "src/assembly/linux/managed_sync.rs",
    "src/assembly/linux/managed_sync/activation.rs",
    "src/assembly/linux/managed_sync/activation/wire.rs",
    "src/assembly/linux/managed_sync/activation/wire/tests.rs",
    "verification/managed_approval_wire/vectors.hex",
    "src/assembly/linux/managed_sync/history.rs",
    "src/assembly/linux/managed_sync/activation/prepared.rs",
    "tests/linux_managed_sync_production.rs",
    "tests/managed_sync_production/cli_recreate.rs",
    "verification/managed_sync_production/approval.rs",
    "verification/managed_sync_production/approval_slot.rs",
    "verification/managed_sync_production/approval_slot_edges.rs",
    "verification/managed_sync_production/approval_host_refusals.rs",
    "verification/managed_sync_production/managed_recreate_wire_controls.py",
)
SUMMARY = re.compile(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
                     r"[0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s")
TRANSCRIPT_LIMIT = 64 * 1024
STEP_TIMEOUT = 15


def artifact(ext4, output, target_root):
    candidates = []
    for row in output.splitlines():
        event = json.loads(row)
        ext4.require(isinstance(event, dict) and isinstance(event.get("target", {}), dict),
                     "malformed compiler artifact row")
        if (event.get("reason") == "compiler-artifact"
                and event.get("target", {}).get("name") == LIBRARY and event.get("executable")):
            candidates.append(event)
    ext4.require(len(candidates) == 1, "expected one executable managed approval CLI library test artifact")
    event, = candidates
    version = tomllib.loads((ext4.ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    package = ext4.CLI_PACKAGE
    spec = event["target"]
    ext4.require(event.get("package_id") == f"path+{package.as_uri()}#{version}"
                 and event.get("manifest_path") == str(package / "Cargo.toml")
                 and event.get("features") == ext4.MANAGED_PREPARED.features()
                 and event.get("fresh") is False
                 and isinstance(event.get("profile"), dict) and event["profile"].get("test") is True
                 and isinstance(event["executable"], str) and event.get("filenames") == [event["executable"]]
                 and spec.get("kind") == ["lib"] and spec.get("crate_types") == ["lib"]
                 and spec.get("src_path") == str(package / "src/lib.rs") and spec.get("edition") == "2024",
                 "managed approval artifact differs from the exact CLI library test target")
    path = Path(event["executable"])
    native = target_root / ext4.TARGET / "debug"
    ext4.require(path.is_absolute() and path.is_relative_to(native) and path.resolve(strict=True) == path,
                 "managed approval artifact escaped private native build custody")
    parts = path.relative_to(native).parts
    suffix = re.fullmatch(rf"{LIBRARY}-([0-9a-f]{{16}})", path.name)
    ext4.require(suffix is not None and (parts[:-1] == ("deps",)
                 or (len(parts) == 5 and parts[:2] == ("build", PACKAGE)
                     and re.fullmatch(r"[0-9a-f]{16}", parts[2]) and parts[3] == "out")),
                 "unexpected managed approval Cargo library artifact layout")
    return path


def check_listing(ext4, output, ignored=False):
    expected = [] if ignored else [f"{case}: test" for case in CASES]
    ext4.require(output.splitlines() == expected, "unexpected managed approval test inventory")
    return list(CASES) if not ignored else []


def check_case(ext4, output, case):
    lines = [line for line in output.splitlines() if line]
    ext4.require(case in CASES and len(lines) == 3
                 and lines[0] == "running 1 test"
                 and lines[1] == f"test {case} ... ok"
                 and SUMMARY.fullmatch(lines[2]),
                 f"managed approval wire library did not pass the exact case {case}")


def inputs(ext4):
    return {name: hashlib.sha256((ext4.CLI_PACKAGE / name).read_bytes()).hexdigest() for name in INPUTS}


def run(ext4, evidence, binary, work, result):
    fd = os.open(binary, ext4.FD_FLAGS | os.O_NONBLOCK)
    try:
        image = ext4.held_managed_image(binary, fd)
        result["executable_sha256"] = image[1]
        options = {
            "env": {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(work)},
            "executable": f"/proc/self/fd/{fd}", "held": (fd,),
            "timeout": STEP_TIMEOUT, "output_limit": TRANSCRIPT_LIMIT,
        }

        def observe(label, args):
            ext4.require(ext4.held_managed_image(binary, fd) == image,
                         "managed approval library image changed before execution")
            try:
                return ext4.command(evidence, label, [binary, *args], **options)
            finally:
                ext4.require(ext4.held_managed_image(binary, fd) == image,
                             "managed approval library image changed after execution")

        for field, flags in (("listed", []), ("ignored", ["--ignored"])):
            listing = observe(f"wire-{field}", ["--list", "--format=terse", *flags, PREFIX])
            result[field] = check_listing(ext4, listing, ignored=bool(flags))
        for index, case in enumerate(CASES, 1):
            output = observe(f"wire-case-{index}", ["--exact", "--test-threads=1", "--color", "never", case])
            check_case(ext4, output, case)
            result["cases"][case] = "passed"
    finally:
        os.close(fd)
    ext4.require(inputs(ext4) == result["inputs_sha256"], "managed approval wire inputs changed")
    result["outcome"] = "passed"
