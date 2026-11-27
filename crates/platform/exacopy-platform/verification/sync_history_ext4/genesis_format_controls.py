"""Run only the four Linux managed-genesis intent codec libtests."""

import hashlib
import json
import os
from pathlib import Path
import re
import tomllib

PREFIX = "linux::sync_profile_store::genesis_output::intent::tests::"
CASES = tuple(PREFIX + name for name in (
    "exact_v1_extent_layout_and_endianness",
    "refuses_noncanonical_extent_shape_and_member_inventory",
    "structural_decode_does_not_adopt_swapped_same_kind_members_or_other_approval",
    "independent_v1_oracle_distinguishes_shape_from_exact_selection",
))
FEATURE = "experimental-linux-managed-sync"
PACKAGE_NAME = "exacopy-platform"
LIBRARY = "exacopy_platform"
SUMMARY = (r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
           r"[0-9]+ filtered out; finished in [0-9]+(?:\.[0-9]+)?s")
INPUTS = (
    "Cargo.toml", "src/lib.rs",
    "src/linux/sync_profile_store/genesis_output/intent.rs",
    "src/linux/sync_profile_store/genesis_output/intent/tests.rs",
    "verification/sync_genesis_publication/intent.tsv",
)


def artifact(ext4, output, target):
    candidates = []
    for row in output.splitlines():
        event = json.loads(row)
        if (event.get("reason") == "compiler-artifact"
                and event.get("target", {}).get("name") == LIBRARY
                and event.get("executable")):
            candidates.append(event)
    ext4.require(len(candidates) == 1, "expected one executable intent codec artifact")
    event, = candidates
    version = tomllib.loads((ext4.ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    package = ext4.PACKAGE
    spec = event["target"]
    path = Path(event["executable"])
    ext4.require(event.get("package_id") == f"path+{package.as_uri()}#{version}"
                 and event.get("manifest_path") == str(package / "Cargo.toml")
                 and event.get("features") == [FEATURE] and event.get("fresh") is False
                 and event.get("profile", {}).get("test") is True
                 and event.get("filenames") == [event["executable"]]
                 and spec.get("kind") == ["lib"] and spec.get("crate_types") == ["lib"]
                 and spec.get("src_path") == str(package / "src/lib.rs")
                 and spec.get("edition") == "2024",
                 "intent codec artifact differs from the exact platform test target")
    native = target / ext4.TARGET / "debug"
    ext4.require(path.is_absolute() and path.is_relative_to(native) and path.resolve(strict=True) == path,
                 "intent codec artifact escaped the private native build")
    parts = path.relative_to(native).parts
    suffix = re.fullmatch(rf"{LIBRARY}-([0-9a-f]{{16}})", path.name)
    ext4.require(suffix is not None and (parts[:-1] == ("deps",)
                 or parts[:-1] == ("build", PACKAGE_NAME, suffix[1], "out")),
                 "unexpected intent codec Cargo artifact layout")
    return path


def check_test(ext4, output, case):
    lines = output.splitlines()
    reported = [(i, line) for i, line in enumerate(lines) if line.startswith("test ") and " ... " in line]
    summaries = [(i, line) for i, line in enumerate(lines) if line.startswith("test result:")]
    ext4.require(lines.count("running 1 test") == 1 and len(reported) == len(summaries) == 1
                 and reported[0][1] == f"test {case} ... ok" and re.fullmatch(SUMMARY, summaries[0][1])
                 and lines.index("running 1 test") < reported[0][0] < summaries[0][0],
                 f"intent codec did not pass the exact case {case}")


def inputs(ext4):
    return {name: hashlib.sha256((ext4.PACKAGE / name).read_bytes()).hexdigest()
            for name in INPUTS}


def run(ext4, evidence, target, build_env, work, report):
    result = {"outcome": "failed", "package": PACKAGE_NAME, "target": ext4.TARGET,
              "feature": FEATURE, "inputs_sha256": inputs(ext4), "cases": {}}
    report["format_controls"] = result
    output = ext4.command(
        evidence, "format-cargo",
        ["cargo", f"+{ext4.TOOLCHAIN}", "test", "--locked", "--offline", "--jobs", "2",
         "--target", ext4.TARGET, "-p", PACKAGE_NAME, "--no-default-features",
         "--features", FEATURE, "--lib", "--no-run", "--message-format=json"],
        env=build_env, timeout=900,
    )
    binary = artifact(ext4, output, target)
    fd = os.open(binary, ext4.FD_FLAGS | os.O_NONBLOCK)
    try:
        image = ext4.held_managed_image(binary, fd)
        result["executable_sha256"] = image[1]
        options = {
            "env": {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(work)},
            "executable": f"/proc/self/fd/{fd}", "held": (fd,),
        }
        for index, case in enumerate(CASES, 1):
            prefix = f"format-case-{index}"
            for name, flags, expected in (("listed", [], f"{case}: test"), ("ignored", ["--ignored"], "")):
                output = ext4.command(
                    evidence, f"{prefix}-{name}",
                    [binary, "--list", "--exact", "--format=terse", *flags, case], **options,
                )
                ext4.require(output.strip() == expected, f"intent codec {name} inventory differs for {case}")
            ext4.require(ext4.held_managed_image(binary, fd) == image, "intent codec image changed before execution")
            try:
                output = ext4.command(
                    evidence, f"{prefix}-run",
                    [binary, "--exact", "--test-threads=1", "--color", "never", case],
                    timeout=45, **options,
                )
            finally:
                ext4.require(ext4.held_managed_image(binary, fd) == image, "intent codec image changed after execution")
            check_test(ext4, output, case)
            result["cases"][case] = "pass"
    finally:
        os.close(fd)
    ext4.require(inputs(ext4) == result["inputs_sha256"], "intent codec inputs changed")
    result["outcome"] = "passed"
