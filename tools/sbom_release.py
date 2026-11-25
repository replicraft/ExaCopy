#!/usr/bin/env python3
"""Build an unsigned native CLI twice from one Git revision and inventory the Cargo artifacts."""

import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib

PRODUCT_PACKAGE = "exacopy-cli"
PRODUCT_BINARY = "exacopy"


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


def component(package, units, checksum, application):
    name = package["name"]
    version = package["version"]
    source = package["source"]
    registry = source is not None
    if registry and (source != "registry+https://github.com/rust-lang/crates.io-index" or not checksum):
        raise ValueError(f"{name}@{version} requires a checked crates.io source")
    reference = f"pkg:cargo/{name}@{version}" if registry else f"workspace:{name}@{version}"
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
    if package["license"]:
        item["licenses"] = [{"expression": package["license"]}]
    return item


def write_sbom(source, env, evidence, target, commit, binary_sha256, units, root_id):
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
    components = {}
    for package_id, package_units in units.items():
        package = package_by_id[package_id]
        identity = (package["name"], package["version"], package["source"])
        components[package_id] = component(
            package, package_units, checksums.get(identity), package_id == root_id,
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


def build(work, archive, evidence, attempt, target, commit, epoch):
    source = work / "source"
    with tarfile.open(archive) as files:
        files.extractall(source, filter="data")
    env = os.environ | {
        "CARGO_ENCODED_RUSTFLAGS": f"--remap-path-prefix={work}=/exacopy",
        "CARGO_INCREMENTAL": "0",
        "RUSTC_WRAPPER": "",
        "RUSTC_WORKSPACE_WRAPPER": "",
        "SOURCE_DATE_EPOCH": epoch,
    }
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
    write_sbom(source, env, sbom, target, commit, binary_hash, units, root_id)
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
            if fetch:
                with tarfile.open(archive) as files:
                    files.extractall(root / "fetch", filter="data")
                subprocess.run(
                    ["cargo", "fetch", "--locked", "--target", target], cwd=root / "fetch", check=True,
                )
            for attempt in ("first", "second"):
                record["attempts"][attempt] = {"result": "fail"}
                record["attempts"][attempt] = build(root / attempt, archive, evidence, attempt, target, commit, epoch)
                record["attempts"][attempt]["result"] = "pass"
        first, second = (record["attempts"][name] for name in ("first", "second"))
        for key in ("binary_sha256", "lockfile_sha256", "sbom_sha256"):
            if first[key] != second[key]:
                raise ValueError(f"release rebuilds differ in {key}: {first[key]} != {second[key]}")
        record["result"] = "pass"
        print(f"{target}: two unsigned CLI builds match SHA-256 {first['binary_sha256']}")
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
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
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"release evidence: {error}\n")


if __name__ == "__main__":
    main()
