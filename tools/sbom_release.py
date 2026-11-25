#!/usr/bin/env python3
"""Build an unsigned native CLI twice from one Git revision and inventory the Cargo artifacts."""

import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import tomllib

from apfs_source import (
    CONSUMER_MANIFEST, PIN as APFS_PIN, REPOSITORY as APFS_REPOSITORY, archive_apfs,
    dependency_manifest_matches, read_pin, sibling, verify_consumer,
)


PRODUCT_PACKAGE = "exacopy-cli"
PRODUCT_BINARY = "exacopy"
NATIVE_FLAGS = ("CFLAGS", "CXXFLAGS", "CPPFLAGS", "ASFLAGS", "LDFLAGS")
NATIVE_CPU = re.compile(r"(?:target-cpu|march|mcpu|mtune)\s*(?:=|\s)\s*native\b")


def output(*command, cwd=None, env=None):
    return subprocess.check_output(command, cwd=cwd, env=env, text=True).strip()


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def build_inputs(stream):
    units = defaultdict(set)
    executable = None
    for line in stream:
        message = json.loads(line)
        if message["reason"] != "compiler-artifact":
            continue
        target = message["target"]
        unit = (",".join(sorted(target["kind"])), ",".join(sorted(message["features"])))
        units[message["package_id"]].add(unit)
        if target["name"] == PRODUCT_BINARY and message["executable"] is not None:
            if executable is not None:
                raise ValueError("multiple CLI executables reported by Cargo")
            executable = (message["package_id"], Path(message["executable"]))
    if executable is None:
        raise ValueError("no CLI executable reported by Cargo")
    return units, executable


def component(package, units, checksum, application, apfs_pin=None):
    name = package["name"]
    version = package["version"]
    source = package["source"]
    registry = source is not None
    if registry and (source != "registry+https://github.com/rust-lang/crates.io-index" or not checksum):
        raise ValueError(f"{name}@{version} requires a checked crates.io source")
    if registry:
        reference = f"pkg:cargo/{name}@{version}"
    elif apfs_pin is not None:
        reference = f"local-path:{name}@{version}#{apfs_pin['commit']}"
    else:
        reference = f"workspace:{name}@{version}"
    item = {
        "type": "application" if application else "library",
        "bom-ref": reference,
        "name": name,
        "version": version,
        "properties": [
            {"name": "exacopy:cargo-unit", "value": f"{kind}: {features or '(no features)'}"}
            for kind, features in sorted(units)
        ],
    }
    if registry:
        item["purl"] = reference
        item["hashes"] = [{"alg": "SHA-256", "content": checksum}]
    elif apfs_pin is not None:
        item["externalReferences"] = [{"type": "vcs", "url": APFS_REPOSITORY}]
        item["properties"].extend([
            {"name": "exacopy:source-commit", "value": apfs_pin["commit"]},
            {"name": "exacopy:source-tree", "value": apfs_pin["tree"]},
            {"name": "exacopy:source-archive-sha256", "value": apfs_pin["archive_sha256"]},
        ])
    if package["license"]:
        item["licenses"] = [{"expression": package["license"]}]
    return item


def write_sbom(source, env, evidence, target, commit, binary_sha256, units, root_id, apfs_pin):
    metadata = json.loads(output(
        "cargo", "metadata", "--format-version", "1", "--locked", "--offline",
        "--filter-platform", target, cwd=source, env=env,
    ))
    package_by_id = {package["id"]: package for package in metadata["packages"]}
    lock = tomllib.loads((source / "Cargo.lock").read_text(encoding="utf-8"))
    checksums = {
        (package["name"], package["version"], package["source"]): package["checksum"]
        for package in lock["package"] if "checksum" in package
    }
    workspace = set(metadata["workspace_members"])
    components = {}
    for package_id, package_units in units.items():
        package = package_by_id[package_id]
        identity = (package["name"], package["version"], package["source"])
        pin = None
        if package["source"] is None and package_id not in workspace:
            if target != "aarch64-apple-darwin" or not dependency_manifest_matches(package, source) or apfs_pin is None:
                raise ValueError(f"unexpected local Cargo artifact: {package['name']}@{package['version']}")
            pin = apfs_pin
        components[package_id] = component(
            package, package_units, checksums.get(identity), package_id == root_id, apfs_pin=pin,
        )
    root = components.pop(root_id)
    if root["name"] != PRODUCT_PACKAGE:
        raise ValueError("Cargo's executable does not belong to the expected package")
    provenance = {
        "binary-sha256": binary_sha256,
        "commit": commit,
        "profile": "release",
        "target": target,
    }
    write_json(evidence, {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "lifecycles": [{"phase": "build"}],
            "component": root,
            "properties": [
                {"name": f"exacopy:{name}", "value": value}
                for name, value in provenance.items()
            ],
        },
        "components": sorted(components.values(), key=lambda item: item["bom-ref"]),
    })


def build_environment(work, epoch):
    env = os.environ.copy()
    for key in list(env):
        if any(key == flag or key.startswith(flag + "_") or key in ("HOST_" + flag, "TARGET_" + flag)
               for flag in NATIVE_FLAGS):
            del env[key]
        elif key in ("CC", "CXX", "RUSTC") or key.startswith(("CC_", "CXX_")) or key in ("HOST_CC", "TARGET_CC", "HOST_CXX", "TARGET_CXX"):
            if NATIVE_CPU.search(env[key]):
                raise ValueError(f"{key} selects a host-native CPU for a distributed build")
    env.update({
        "CARGO_ENCODED_RUSTFLAGS": f"--remap-path-prefix={work}=/exacopy",
        "RUSTFLAGS": "",
        "CARGO_INCREMENTAL": "0",
        "RUSTC_WRAPPER": "",
        "RUSTC_WORKSPACE_WRAPPER": "",
        "SOURCE_DATE_EPOCH": epoch,
    })
    return env


def extract_sources(work, archive, apfs_archive):
    source = work / "source"
    with tarfile.open(archive, "r:") as files:
        files.extractall(source, filter="data")
    with tarfile.open(apfs_archive, "r:") as files:
        files.extractall(sibling(source), filter="data")
    return source


def build(work, archive, apfs_archive, evidence, attempt, target, record):
    source = extract_sources(work, archive, apfs_archive)
    env = build_environment(work, str(record["source_date_epoch"]))
    command = [
        "cargo", "build", "--release", "--locked", "--offline", "--no-default-features",
        "--package", PRODUCT_PACKAGE, "--bin", PRODUCT_BINARY, "--target", target,
        "--target-dir", str(work / "target"), "--message-format=json-render-diagnostics",
    ]
    print(subprocess.list2cmdline(command), flush=True)
    archive_hash = sha256(source / "Cargo.lock")
    messages = evidence / f"{attempt}-cargo.jsonl"
    with messages.open("w", encoding="utf-8") as stream:
        subprocess.run(command, cwd=source, env=env, stdout=stream, check=True)
    with messages.open(encoding="utf-8") as stream:
        units, (root_id, executable) = build_inputs(stream)
    binary_hash = sha256(executable)
    sbom = evidence / f"{attempt}.cdx.json"
    write_sbom(source, env, sbom, target, record["commit"], binary_hash, units, root_id, record["apfs_source"])
    return {
        "binary_sha256": binary_hash,
        "cargo_messages_sha256": sha256(messages),
        "command": command,
        "lockfile_sha256": archive_hash,
        "rustflags": env["CARGO_ENCODED_RUSTFLAGS"],
        "sbom_sha256": sha256(sbom),
    }


def reproduce(evidence, target, fetch):
    rustc = output("rustc", "-vV")
    cargo = output("cargo", "--version", "--verbose")
    rust_version = tomllib.loads(Path("rust-toolchain.toml").read_text(encoding="utf-8"))
    release = f"release: {rust_version['toolchain']['channel']}"
    if release not in rustc.splitlines() or release not in cargo.splitlines():
        raise ValueError("the active Rust and Cargo toolchain does not match rust-toolchain.toml")
    if f"host: {target}" not in rustc.splitlines():
        raise ValueError("release rebuild evidence requires a native compiler and linker")
    commit = output("git", "rev-parse", "HEAD")
    epoch = output("git", "show", "-s", "--format=%ct", commit)
    record = {
        "attempts": {},
        "cargo": cargo,
        "commit": commit,
        "native_cc": output("cc", "--version"),
        "rustc": rustc,
        "runner_sha256": sha256(Path(__file__)),
        "source_date_epoch": int(epoch),
        "target": target,
        "tree": output("git", "rev-parse", f"{commit}^{{tree}}"),
    }
    record_path = evidence / "rebuild.json"
    try:
        with tempfile.TemporaryDirectory(prefix="exacopy-release-") as temp:
            root = Path(temp).resolve()
            archive = root / "source.tar"
            subprocess.run(["git", "archive", "--output", str(archive), commit], check=True)
            record["source_archive_sha256"] = sha256(archive)
            with tarfile.open(archive, "r:") as files:
                apfs_pin = read_pin(files.extractfile(APFS_PIN.as_posix()).read().decode())
                verify_consumer(*(
                    tomllib.loads(files.extractfile(path).read().decode())
                    for path in ("Cargo.toml", CONSUMER_MANIFEST.as_posix())
                ))
            apfs_archive = root / "apfs.tar"
            record["apfs_source"] = {"repository": APFS_REPOSITORY, **apfs_pin}
            archive_apfs(Path.cwd(), apfs_pin, apfs_archive)
            if fetch:
                fetch_source = extract_sources(root / "fetch", archive, apfs_archive)
                subprocess.run(
                    ["cargo", "fetch", "--locked", "--target", target], cwd=fetch_source, check=True,
                )
            for attempt in ("first", "second"):
                record["attempts"][attempt] = {"result": "fail"}
                record["attempts"][attempt] = build(root / attempt, archive, apfs_archive, evidence, attempt, target, record)
                record["attempts"][attempt]["result"] = "pass"
        first, second = (record["attempts"][name] for name in ("first", "second"))
        for key in ("binary_sha256", "lockfile_sha256", "sbom_sha256"):
            if first[key] != second[key]:
                raise ValueError(f"release rebuilds differ in {key}: {first[key]} != {second[key]}")
        record["result"] = "pass"
        print(f"{target}: two unsigned CLI builds match SHA-256 {first['binary_sha256']}")
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        record["result"] = "fail"
        record["error"] = str(error)
        raise
    finally:
        write_json(record_path, record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True, type=Path, help="A new directory for rebuild evidence.")
    parser.add_argument("--fetch", action="store_true", help="Populate the locked dependency cache before building.")
    args = parser.parse_args()
    try:
        evidence = args.output.resolve()
        evidence.mkdir(parents=True)
        reproduce(evidence, args.target, args.fetch)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, f"release evidence: {error}\n")


if __name__ == "__main__":
    main()
