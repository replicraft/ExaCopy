#!/bin/sh
set -eu

verification_dir=$(cd "$(dirname "$0")" && pwd -P)
cd "$verification_dir"

python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
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
scratch.mkdir(parents=True, exist_ok=True)
try:
    (scratch / "active").mkdir()
except FileExistsError:
    raise SystemExit(f"Another extraction owns {scratch / 'active'}") from None
try:
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

lake exe cache get
lake build
lake env lean -DwarningAsError=true Proofs/Range.lean
