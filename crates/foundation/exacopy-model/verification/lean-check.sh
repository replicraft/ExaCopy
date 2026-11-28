#!/bin/sh
set -eu

verification_dir=$(cd "$(dirname "$0")" && pwd -P)
cd "$verification_dir"

python3 - "$@" <<'PY'
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tomllib


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def digest(path):
    with path.open("rb") as binary:
        return hashlib.file_digest(binary, "sha256").hexdigest()


def verify_file(path, expected):
    actual = digest(path)
    require(actual == expected, f"SHA-256 mismatch for {path}: {actual}")
    print(f"SHA-256 {actual}  {path}", flush=True)


def candidate_state():
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    require(commit == os.environ.get("GITHUB_SHA"), "Candidate checkout differs from the CI source")
    require(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"]),
            "Candidate requires a clean checkout")
    return commit, subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip()


def extract_candidate(scratch):
    scenario = config["scenario"]["grant_time"]
    output = scratch / "grant-time"
    require(scenario["output-dir"] == "verification/" + output.as_posix(),
            "Unexpected candidate scratch path")
    commit, tree = candidate_state()
    inputs = [
        "crates/foundation/exacopy-model/src/grant_time.rs",
        "apps/exacopy-cli/src/assembly/linux/public_stage/grant/clock.rs",
        "Cargo.lock",
        "crates/foundation/exacopy-model/hax.toml",
        "crates/foundation/exacopy-model/verification/toolchain.lock.json",
        "crates/foundation/exacopy-model/verification/lake-manifest.json",
        "crates/foundation/exacopy-model/verification/lean-toolchain",
    ]
    repo = Path("../../../..")
    source = {name: digest(repo / name) for name in inputs}
    command = [frontend, "hax", "extract", "--locked", "-v", "grant_time"]
    print(f"Extract grant_time source {commit} tree {tree}", flush=True)
    output.mkdir()  # Refuse a preexisting path and clean up only the directory we create.
    try:
        candidate_env = env | {
            "CARGO_TARGET_DIR": str((output / "target").resolve()),
            "RUSTC_WRAPPER": "",
            "RUSTC_WORKSPACE_WRAPPER": "",
            "CARGO_INCREMENTAL": "0",
        }
        with subprocess.Popen(command, cwd="..", env=candidate_env, start_new_session=True) as process:
            try:
                require(process.wait(timeout=360) == 0, "Candidate extraction failed")
            except (subprocess.TimeoutExpired, KeyboardInterrupt, SystemExit):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise
        required = {"Types.lean", "Funs.lean"}
        allowed = required | {"FunsExternal_Template.lean"}
        files = {}
        limit = 512 * 1024
        with ExitStack() as opened:
            directory_fd = None
            for directory in (output, "Generated", "GrantTime"):
                directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                       dir_fd=directory_fd)
                opened.callback(os.close, directory_fd)
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    name = entry.name
                    require(name in allowed and name not in files, f"Unexpected candidate output: {name}")
                    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                         dir_fd=directory_fd)
                    with os.fdopen(descriptor, "rb") as file:
                        info = os.fstat(file.fileno())
                        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit,
                                f"Expected bounded plain candidate file: {name}")
                        data = file.read(limit + 1)
                    require(len(data) == info.st_size, f"Candidate file length changed: {name}")
                    files[name] = data
        require(required <= files.keys(), f"Missing candidate files: {sorted(required - files.keys())}")
        require(sum(map(len, files.values())) <= 1024 * 1024, "Candidate artifact exceeds 1 MiB")
        require(candidate_state() == (commit, tree)
                and all(digest(repo / name) == value for name, value in source.items()),
                "Candidate source changed during extraction")
        receipt = {
            "kind": "generated-source-candidate",
            "commit": commit,
            "git_tree": tree,
            "scenario": "grant_time",
            "scenario_config": scenario,
            "verified_tool_binaries": {
                tool: {key: value for key, value in pins.items() if key != "archive_sha256"}
                for tool, pins in binaries.items()
            },
            "extraction_rust_revision": rust["revision"],
            "lean_revision": lock["lean"]["revision"],
            "input_sha256": source,
            "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                      for name, data in files.items()},
        }
        evidence = Path(os.environ["RUNNER_TEMP"]) / "exacopy-evidence" / "grant-time-generated"
        require(evidence.is_absolute(), "Candidate evidence requires an absolute runner temp path")
        evidence.mkdir()
        try:
            for name, data in files.items():
                (evidence / name).write_bytes(data)
            (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        except BaseException:
            shutil.rmtree(evidence)
            raise
    finally:
        shutil.rmtree(output)


def interrupt_candidate(_signal, _frame):
    raise KeyboardInterrupt


candidate = sys.argv[1:] == ["grant-time-candidate"]
require(candidate or len(sys.argv) == 1, "usage: lean-check.sh [grant-time-candidate]")
if candidate:
    signal.signal(signal.SIGTERM, interrupt_candidate)
lock = json.loads(Path("toolchain.lock.json").read_text())
platform_id = {("Darwin", "arm64"): "macos-aarch64", ("Linux", "x86_64"): "linux-x86_64"}.get(
    (platform.system(), platform.machine())
)
require(platform_id in lock["platforms"], "Unsupported host for the pinned extraction binaries")
binaries = lock["platforms"][platform_id]
config = tomllib.loads(Path("../hax.toml").read_text())
require(config["tools"] == {tool: lock[tool]["version"] for tool in ("charon", "aeneas")},
        "hax.toml extractor pins differ from toolchain.lock.json")
require(config["versions"] == {"lean": lock["lean"]["toolchain"], "hax-lean-lib": lock["hax_lean"]["version"]},
        "hax.toml Lean pins differ from toolchain.lock.json")
require(Path("lean-toolchain").read_text().strip() == lock["lean"]["toolchain"], "Unexpected Lean toolchain")
manifest = json.loads(Path("lake-manifest.json").read_text())
revisions = {package["name"]: package["rev"] for package in manifest["packages"]}
for package, pin in (("aeneas", "aeneas"), ("hax", "hax_lean"), ("mathlib", "mathlib")):
    require(revisions[package] == lock[pin]["revision"], f"Unexpected Lake revision for {package}")
cargo = tomllib.loads(Path("../../../../Cargo.lock").read_text())
hax_lib = [package for package in cargo["package"] if package["name"] == "hax-lib"]
require(len(hax_lib) == 1 and hax_lib[0]["version"] == lock["hax_lib"]["version"] and
        hax_lib[0]["checksum"] == lock["hax_lib"]["crate_sha256"], "Unexpected Cargo hax-lib lock entry")

frontend = shutil.which("cargo-hax")
require(frontend is not None, "Install the pinned official cargo-hax release and add it to PATH")
verify_file(Path(frontend), binaries["cargo-hax"]["binary_sha256"])
subprocess.run([frontend, "hax", "--version"], check=True)
subprocess.run([frontend, "hax", "tools", "install"], cwd="..", check=True)
cache = Path(os.environ.get("XDG_CACHE_HOME", ""))
if not cache.is_absolute():
    cache = Path.home() / ".cache"
cache = cache / "hax" / "tools"
for tool in ("charon", "aeneas"):
    installed = cache / tool / lock[tool]["version"]
    metadata = tomllib.loads((installed / "hax-metadata.toml").read_text())
    require(metadata.get("checksum_verified") is True, f"Unverified hax archive for {tool}")
    verify_file(installed / tool, binaries[tool]["binary_sha256"])
    if tool == "charon":
        verify_file(installed / "charon-driver", binaries[tool]["driver_sha256"])
        verify_file(installed / "rust-toolchain", lock[tool]["rust_toolchain_sha256"])

rust = lock["extraction_rust"]
components = subprocess.run(
    ["rustup", "component", "list", "--installed", "--toolchain", rust["toolchain"]],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
).stdout.splitlines()
if not all(any(item == name or item.startswith(f"{name}-") for item in components)
           for name in rust["components"]):
    subprocess.run([
        "rustup", "toolchain", "install", rust["toolchain"], "--profile", "minimal",
        "--component", ",".join(rust["components"]),
    ], check=True)
env = dict(os.environ)
# Charon invokes cargo by name when asking Miri for the full-MIR sysroot.
# Use the same selected Rust distribution even when the host installs cargo separately.
extract_cargo = subprocess.check_output(["rustup", "which", "--toolchain", rust["toolchain"], "cargo"], text=True).strip()
env["PATH"] = str(Path(extract_cargo).parent) + os.pathsep + env["PATH"]
env["RUSTUP_TOOLCHAIN"] = rust["toolchain"]
env.pop("CHARON_TOOLCHAIN_IS_IN_PATH", None)
env.pop("CHARON_MIRI_SYSROOTS", None)
compiler = subprocess.check_output(["rustup", "run", rust["toolchain"], "rustc", "-Vv"], text=True)
require(f"commit-hash: {rust['revision']}" in compiler.splitlines(), "Unexpected extraction compiler commit")
print(compiler, end="", flush=True)
lean = subprocess.check_output(["lean", "--version"], text=True)
require(f"commit {lock['lean']['revision']}," in lean, "Unexpected Lean kernel commit")
print(lean, end="", flush=True)

scratch = Path(".lake/hax")
if candidate:
    require(scratch.resolve() == scratch.absolute(), "Candidate scratch path contains a symlink")
scratch.mkdir(parents=True, exist_ok=True)
try:
    (scratch / "active").mkdir()
except FileExistsError:
    raise SystemExit(f"Another extraction owns {scratch / 'active'}") from None
try:
    if candidate:
        extract_candidate(scratch)
        raise SystemExit(0)
    generated = scratch / "Generated"
    if generated.exists():
        shutil.rmtree(generated)
    subprocess.run([frontend, "hax", "extract", "--locked", "-v", "range"], cwd="..", env=env, check=True)
    # Aeneas emits the external import template even though this crate has no external declarations.
    (generated / "FunsExternal_Template.lean").rename(generated / "FunsExternal.lean")
    subprocess.run(["diff", "-ru", "Generated", str(generated)], check=True)
    inputs = [Path("../src/range.rs"), Path("../../../../Cargo.lock"), Path("../hax.toml"),
              Path("toolchain.lock.json"), Path("lake-manifest.json"), Path("Proofs/Range.lean")]
    for path in inputs + sorted(Path("Generated").glob("*.lean")):
        print(f"SHA-256 {digest(path)}  {path}", flush=True)
finally:
    (scratch / "active").rmdir()
PY

[ "$#" -eq 0 ] || exit 0

lake exe cache get
lake build
lake env lean -DwarningAsError=true Proofs/Range.lean
