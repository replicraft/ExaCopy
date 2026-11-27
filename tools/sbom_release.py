#!/usr/bin/env python3
"""Build an unsigned native CLI twice from one Git revision and inventory the Cargo artifacts."""

import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import tomllib

from apfs_source import (
    CONSUMER_MANIFEST, MEMBER as APFS_MEMBER, NAME as APFS_NAME, PIN as APFS_PIN,
    REPOSITORY as APFS_REPOSITORY, WORKSPACE_PATH as APFS_WORKSPACE_PATH, archive_apfs,
    dependency_manifest_matches, read_pin, sibling, verify_consumer,
)


import transport_source


PRODUCT_PACKAGE = "exacopy-cli"
PRODUCT_BINARY = "exacopy"
DARWIN_TARGET = "aarch64-apple-darwin"
APFS_RELEASE_SOURCE = Path(".exacopy-release-inputs/pomologie/apfs")
APFS_RELEASE_MEMBER = APFS_RELEASE_SOURCE / APFS_MEMBER
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
    origins = defaultdict(set)
    executable = None
    for line in stream:
        message = json.loads(line)
        if message["reason"] != "compiler-artifact":
            continue
        target = message["target"]
        unit = (",".join(sorted(target["kind"])), ",".join(sorted(message["features"])))
        package_id = message["package_id"]
        units[package_id].add(unit)
        origins[package_id].add((
            message.get("manifest_path"), target.get("src_path"), target["name"], unit[0],
        ))
        if target["name"] == PRODUCT_BINARY and message["executable"] is not None:
            if executable is not None:
                raise ValueError("multiple CLI executables reported by Cargo")
            executable = (message["package_id"], Path(message["executable"]))
    if executable is None:
        raise ValueError("no CLI executable reported by Cargo")
    return units, executable, origins


def component(package, units, checksum, application, local_pin=None):
    name = package["name"]
    version = package["version"]
    source = package["source"]
    registry = source is not None
    if registry and (source != "registry+https://github.com/rust-lang/crates.io-index" or not checksum):
        raise ValueError(f"{name}@{version} requires a checked crates.io source")
    if registry:
        reference = f"pkg:cargo/{name}@{version}"
    elif local_pin is not None:
        reference = f"local-path:{name}@{version}#{local_pin['commit']}"
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
    elif local_pin is not None:
        if "upstream_commit" in local_pin:
            item["externalReferences"] = [{"type": "vcs", "url": local_pin["repository"],
                                            "comment": "Upstream repository for the separately pinned modified source"}]
            item["properties"].extend(
                {"name": f"exacopy:{name.replace('_', '-')}", "value": local_pin[name]}
                for name in ("upstream_commit", "registry_archive_sha256", "repair_patch_sha256", "attribution_patch_sha256")
            )
        else:
            item["externalReferences"] = [{"type": "vcs", "url": APFS_REPOSITORY}]
        item["properties"].extend([
            {"name": "exacopy:source-commit", "value": local_pin["commit"]},
            {"name": "exacopy:source-tree", "value": local_pin["tree"]},
            {"name": "exacopy:source-archive-sha256", "value": local_pin["archive_sha256"]},
        ])
    if package["license"]:
        item["licenses"] = [{"expression": package["license"]}]
    return item


def write_sbom(
    source, env, evidence, target, commit, binary_sha256, units, root_id, apfs_pin, transport_pins,
    apfs_layout=None, *, origins, selected_features=(),
):
    command = ["cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--filter-platform", target]
    if selected_features:
        command.extend(("--no-default-features", "--features", ",".join(selected_features)))
    metadata = json.loads(output(*command, cwd=source, env=env))
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
        if package["name"] in transport_pins:
            name = package["name"]
            if not transport_source.package_matches(package, source) or package_id in workspace:
                raise ValueError(f"unexpected {name} artifact source")
            repair = transport_pins[name]
            pin = repair["repair"] | {
                "repository": repair["upstream_repository"], "upstream_commit": repair["upstream_commit"],
                "registry_archive_sha256": repair["registry_archive_sha256"],
                "repair_patch_sha256": repair["repair_patch_sha256"],
                "attribution_patch_sha256": repair["attribution_patch_sha256"],
            }
        elif package["name"] == APFS_NAME or (package["source"] is None and package_id not in workspace):
            if (
                target != DARWIN_TARGET or apfs_layout is None or apfs_pin is None or package_id in workspace
                or not dependency_manifest_matches(package, source, member_path=APFS_RELEASE_MEMBER)
            ):
                raise ValueError(f"unexpected local Cargo artifact: {package['name']}@{package['version']}")
            member = source / APFS_RELEASE_MEMBER
            expected = (str(member / "Cargo.toml"), str(member / "src/lib.rs"), "apfs_mounted", "lib")
            if origins.get(package_id) != {expected}:
                raise ValueError("unexpected APFS compiler artifact origin")
            pin = apfs_pin
        components[package_id] = component(
            package, package_units, checksums.get(identity), package_id == root_id, local_pin=pin,
        )
    if apfs_layout is not None and not any(item["name"] == APFS_NAME for item in components.values()):
        raise ValueError("the Darwin build did not report its pinned APFS source")
    root = components.pop(root_id)
    if root["name"] != PRODUCT_PACKAGE:
        raise ValueError("Cargo's executable does not belong to the expected package")
    provenance = {
        "binary-sha256": binary_sha256,
        "commit": commit,
        "profile": "release",
        "target": target,
    }
    if apfs_layout is not None:
        provenance.update({f"apfs-layout-{key.replace('_', '-')}": value for key, value in apfs_layout.items()})
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


def build_environment(work, epoch, target=None):
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
    if target == DARWIN_TARGET:
        env["MACOSX_DEPLOYMENT_TARGET"] = "14.0"
    return env


def apfs_archive_member(member, destination):
    """Apply the safe archive mode explicitly, including directory modes."""
    relative = Path(member.name)
    if (
        relative.is_absolute() or ".." in relative.parts or not relative.parts
        or relative.as_posix() != member.name or not (member.isfile() or member.isdir())
    ):
        raise ValueError(f"unexpected APFS archive member: {member.name}")
    safe = tarfile.data_filter(member, destination)
    return safe.replace(mode=member.mode & 0o755) if member.isdir() else safe


def verify_projected_apfs_tree(source, archive):
    """Prove the private projected tree equals the pinned archive's safe extraction."""
    if not stat.S_ISDIR(source.lstat().st_mode):
        raise ValueError("expected a real application source directory")
    root = source
    for part in APFS_RELEASE_SOURCE.parts:
        root /= part
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise ValueError("expected a real directory on the projected APFS path")

    remaining = {}
    with tarfile.open(archive, "r:") as contents:
        for member in contents:
            safe = apfs_archive_member(member, root)
            if safe.name in remaining:
                raise ValueError(f"duplicate APFS archive member: {safe.name}")
            remaining[safe.name] = (
                safe.mode, safe.size,
                hashlib.file_digest(contents.extractfile(member), "sha256").hexdigest()
                if safe.isfile() else None,
            )
    if not remaining:
        raise ValueError("expected a nonempty APFS source archive")

    directories = [root]
    while directories:
        for path in directories.pop().iterdir():
            relative = path.relative_to(root).as_posix()
            expected = remaining.pop(relative, None)
            if expected is None:
                raise ValueError(f"unexpected projected APFS entry: {relative}")
            mode, size, digest = expected
            actual = path.lstat()
            if stat.S_IMODE(actual.st_mode) != mode:
                raise ValueError(f"projected APFS mode differs: {relative}")
            if digest is None and stat.S_ISDIR(actual.st_mode):
                directories.append(path)
            elif (
                digest is None or not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1
                or actual.st_size != size or sha256(path) != digest
            ):
                raise ValueError(f"projected APFS entry differs: {relative}")
    if remaining:
        raise ValueError(f"missing projected APFS entry: {min(remaining)}")


def extract_sources(work, archive, apfs_archive, transport_archives=None, *, target=None):
    source = work / "source"
    with tarfile.open(archive, "r:") as files:
        files.extractall(source, filter="data")
    with tarfile.open(apfs_archive, "r:") as files:
        files.extractall(sibling(source), filter=apfs_archive_member if target == DARWIN_TARGET else "data")
    if transport_archives is not None:
        transport_source.verify_manifests(source)
        transport_source.extract_sources(source, transport_archives, transport_source.read_pins(source))
    return source


def projected_apfs_manifest(original):
    """Project one verified local edge to a fixed workspace-relative build path."""
    workspace = tomllib.loads(original.decode("utf-8"))
    configuration = workspace["workspace"]
    dependency = configuration["dependencies"][APFS_NAME]
    old_path = f'path = "{APFS_WORKSPACE_PATH}"'.encode("ascii")
    new_path = APFS_RELEASE_MEMBER.as_posix()
    header = b"[workspace]\n"
    if (
        dependency["path"] != APFS_WORKSPACE_PATH or "exclude" in configuration
        or original.count(old_path) != 1 or original.count(header) != 1
    ):
        raise ValueError("release requires the exact original APFS workspace edge")
    configuration["exclude"] = [new_path]
    dependency["path"] = new_path
    projected = original.replace(old_path, f'path = "{new_path}"'.encode("ascii")).replace(
        header, header + f'exclude = ["{new_path}"]\n'.encode("ascii"),
    )
    if tomllib.loads(projected.decode("utf-8")) != workspace:
        raise ValueError("unexpected changes in the APFS release workspace projection")
    layout = {
        "schema": "exacopy-apfs-release-layout-v1",
        "member_path": new_path,
        "original_manifest_sha256": hashlib.sha256(original).hexdigest(),
        "projected_manifest_sha256": hashlib.sha256(projected).hexdigest(),
    }
    return projected, layout


def project_release_sources(source, target, apfs_archive):
    """Relocate the exact archived APFS bytes inside each independent Darwin build."""
    if target != DARWIN_TARGET:
        return None
    manifest = source / "Cargo.toml"
    original = manifest.read_bytes()
    verify_consumer(tomllib.loads(original.decode("utf-8")), tomllib.loads(
        (source / CONSUMER_MANIFEST).read_text(encoding="utf-8"),
    ))
    projected, layout = projected_apfs_manifest(original)
    # Never merge the pinned source into any path already present in the source archive.
    (source / APFS_RELEASE_SOURCE.parts[0]).mkdir(mode=0o700)
    destination = source / APFS_RELEASE_SOURCE
    destination.parent.mkdir()
    sibling(source).rename(destination)
    verify_projected_apfs_tree(source, apfs_archive)
    manifest.write_bytes(projected)
    return layout


def build(work, archive, apfs_archive, transport_archives, evidence, attempt, target, record):
    source = extract_sources(work, archive, apfs_archive, transport_archives, target=target)
    apfs_layout = project_release_sources(source, target, apfs_archive)
    env = build_environment(work, str(record["source_date_epoch"]), target)
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
        units, (root_id, executable), origins = build_inputs(stream)
    binary_hash = sha256(executable)
    sbom = evidence / f"{attempt}.cdx.json"
    write_sbom(
        source, env, sbom, target, record["commit"], binary_hash, units, root_id,
        record["apfs_source"], record["transport_sources"], apfs_layout, origins=origins,
    )
    return {
        "binary_sha256": binary_hash,
        "cargo_messages_sha256": sha256(messages),
        "command": command,
        "lockfile_sha256": archive_hash,
        "rustflags": env["CARGO_ENCODED_RUSTFLAGS"],
        "sbom_sha256": sha256(sbom),
    } | ({"apfs_build_layout": apfs_layout} if apfs_layout is not None else {})


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
            # Read these pins from the exact application archive, then verify the project siblings.
            committed_source = extract_sources(root / "pins", archive, apfs_archive)
            transport_pins = transport_source.read_pins(committed_source)
            transport_source.verify_manifests(committed_source)
            record["transport_sources"] = transport_pins
            transport_archives = transport_source.archive_sources(Path.cwd(), transport_pins, root)
            if fetch:
                fetch_source = extract_sources(
                    root / "fetch", archive, apfs_archive, transport_archives, target=target,
                )
                project_release_sources(fetch_source, target, apfs_archive)
                subprocess.run(
                    ["cargo", "fetch", "--locked", "--target", target], cwd=fetch_source,
                    env=build_environment(fetch_source.parent, epoch, target), check=True,
                )
            for attempt in ("first", "second"):
                record["attempts"][attempt] = {"result": "fail"}
                record["attempts"][attempt] = build(root / attempt, archive, apfs_archive, transport_archives, evidence, attempt, target, record)
                record["attempts"][attempt]["result"] = "pass"
        first, second = (record["attempts"][name] for name in ("first", "second"))
        if first.get("apfs_build_layout") != second.get("apfs_build_layout"):
            raise ValueError("release rebuilds differ in APFS build layout")
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
