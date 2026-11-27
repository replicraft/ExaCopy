#!/usr/bin/env python3
"""Materialize the default ExaCopy CLI and its libraries for registry review."""

import argparse
import copy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tomllib


ROOT = Path(__file__).resolve().parents[2]
POLICY = Path(__file__).with_name("registry_projection.toml")
APFS_PIN = "specs/dependencies/apfs-source.toml"
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
REPOSITORY = "https://github.com/replicraft/ExaCopy"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(manifest):
    return digest(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())


def toml(data):
    return tomllib.loads(data.decode("utf-8"))


def git(root, *args):
    return subprocess.run(
        ["git", "--no-replace-objects", "-C", root, *args],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout


def source_files(root, commit, wanted):
    if not COMMIT.fullmatch(commit) or git(root, "rev-parse", f"{commit}^{{commit}}").decode().strip() != commit:
        raise ValueError("source must be a full ExaCopy commit ID")
    listing = git(root, "ls-tree", "--full-tree", "-r", "-z", commit, "--", *wanted)
    entries = {}
    for line in listing.split(b"\0")[:-1]:
        metadata, raw_name = line.split(b"\t", 1)
        mode, kind, blob = metadata.decode("ascii").split()
        name = raw_name.decode("utf-8")
        path = PurePosixPath(name)
        if kind != "blob" or mode != "100644" or path.is_absolute() or ".." in path.parts:
            raise ValueError(f"unsupported tracked source entry in registry projection: {name}")
        entries[name] = blob
    archive = git(root, "archive", "--format=tar", commit, "--", *wanted)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
        for entry in stream:
            if entry.isdir():
                continue
            if entry.name not in entries or entry.name in files or not entry.isfile():
                raise ValueError(f"unexpected registry source archive entry: {entry.name}")
            data = stream.extractfile(entry).read()
            git_header = f"blob {len(data)}\0".encode("ascii")
            if hashlib.sha1(git_header + data, usedforsecurity=False).hexdigest() != entries[entry.name]:
                raise ValueError(f"source archive changed Git blob bytes: {entry.name}")
            files[entry.name] = data
    if set(files) != set(entries):
        raise ValueError("source archive omitted tracked registry package inputs")
    return files


def checked_manifest(data, expected, location):
    manifest = toml(data)
    if fingerprint(manifest) != expected:
        raise ValueError(f"registry projection policy needs review for changed {location}")
    return manifest


def dependency(name, member, inherited, packages, version, forks):
    if member.get("workspace") is not True or set(member) - {"workspace", "features", "optional"}:
        raise ValueError(f"unsupported registry dependency declaration: {name}")
    declaration = inherited[name]
    resolved = {"version": declaration} if isinstance(declaration, str) else declaration.copy()
    if "path" in resolved:
        path = resolved.pop("path")
        if name == "apfs-mounted":
            if path != "../pomologie/apfs/crates/platform/apfs-mounted" or not resolved["version"].startswith("="):
                raise ValueError("registry projection requires the exact external Pomologie crate")
        elif name in forks:
            fork = forks[name]
            if path != f"../local-deps/{name}" or resolved["version"] != f'={fork["upstream_version"]}':
                raise ValueError(f"unapproved transport source declaration: {name}")
            resolved.update(package=fork["name"], version=f'={fork["version"]}')
        elif name not in packages or path != packages[name]["path"] or resolved["version"] != f"={version}":
            raise ValueError(f"unapproved registry substitution for path dependency: {name}")
    if set(resolved) - {"version", "default-features", "features", "package"} or not isinstance(resolved.get("version"), str):
        raise ValueError(f"unsupported registry dependency: {name}")
    if "features" in member:
        resolved["features"] = sorted(set(resolved.get("features", ())) | set(member["features"]))
    if member.get("optional") is True:
        resolved["optional"] = True
    return resolved


def dependency_sections(manifest, inherited, packages, version, features, forks):
    optional = {value[4:] for selection in features.values() for value in selection if value.startswith("dep:")}
    sections = [("dependencies", manifest.get("dependencies", {}))]
    sections.extend(
        (f"target.{json.dumps(target)}.dependencies", target_section.get("dependencies", {}))
        for target, target_section in sorted(manifest.get("target", {}).items())
    )
    for header, dependencies in sections:
        selected = {
            name: dependency(name, declaration, inherited, packages, version, forks)
            for name, declaration in sorted(dependencies.items())
            if declaration.get("optional") is not True or name in optional
        }
        if selected:
            yield header, selected


def value(item):
    if isinstance(item, dict):
        return "{ " + ", ".join(f"{key} = {value(child)}" for key, child in sorted(item.items())) + " }"
    return json.dumps(item, ensure_ascii=False)


def table(header, fields):
    return "\n".join([f"[{header}]", *(f"{key} = {value(item)}" for key, item in fields.items())])


def standalone_manifest(manifest, workspace, profile, package, packages, forks):
    metadata = workspace["package"]
    cli = package["name"] == "exacopy"
    fields = {
        "name": package["name"], **metadata, "repository": REPOSITORY,
        "description": package["description"], "readme": "README.md", "resolver": workspace["resolver"],
        "autobins": False, "autolib": False, "autoexamples": False, "autotests": False, "autobenches": False,
        "include": ["Cargo.toml", "LICENSE", "README.md", "src/**"],
    }
    lib = {"path": "src/lib.rs", "test": False, "doctest": False}
    if cli:
        lib["name"] = manifest["package"]["name"].replace("-", "_")
    sections = [table("package", fields), table("lib", lib)]
    if cli:
        sections.append(table("[bin]", {**manifest["bin"][0], "test": False}))
        sections.append(table("profile.release", profile))
    selected = {name: manifest["features"][name] for name in package.get("features", ())}
    if selected:
        sections.append(table("features", selected))
    dependencies = list(dependency_sections(manifest, workspace["dependencies"], packages, metadata["version"], selected, forks))
    sections.extend(table(header, fields) for header, fields in dependencies)
    lints = copy.deepcopy(workspace["lints"])
    if omitted_features := sorted(manifest.get("features", {}).keys() - selected.keys()):
        names = ", ".join(map(json.dumps, omitted_features))
        lints["rust"]["unexpected_cfgs"]["check-cfg"].append(f"cfg(feature, values({names}))")
    sections.extend(table(f"lints.{name}", fields) for name, fields in sorted(lints.items()))
    return ("\n\n".join(sections) + "\n").encode(), sorted({item.get("package", name) for _, fields in dependencies for name, item in fields.items()})


def package_readme(name, description, commit):
    details = (
        "This package installs the default ExaCopy CLI. Linux provides local comparison,\n"
        "manifest creation and verification, plan export, preserve-mode copy and recovery.\n"
        "macOS provides exact comparison in documented owner-managed APFS directories.\n"
        "Windows retains the default CLI's structured unsupported-operation results.\n"
        "Experimental features require the source workspace. See the "
        f"[CLI guide]({REPOSITORY}/blob/{commit}/apps/exacopy-cli/README.md) "
        "for usage and managed APFS setup.\n\n"
        if name == "exacopy" else "This component is released with the ExaCopy CLI.\n\n"
    )
    return (
        f"# {name}\n\n{description}.\n\n{details}"
        f"[Release source and full verification suite]({REPOSITORY}/tree/{commit}).\n"
    ).encode()


def lock_baseline(lock, version):
    if lock.get("version") != 4:
        raise ValueError("unreviewed workspace lockfile format")
    cli = [row for row in lock["package"] if row["name"] == "exacopy-cli" and "source" not in row]
    if len(cli) != 1 or cli[0]["version"] != version:
        raise ValueError("workspace lockfile does not identify the selected CLI version")
    return sorted(
        (row["name"], row["version"], row["checksum"])
        for row in lock["package"] if row.get("source") == REGISTRY
    )


def render(source, commit, policy, forks=None):
    forks = forks or {}
    workspace_manifest = checked_manifest(source["Cargo.toml"], policy["workspace_sha256"], "Cargo.toml")
    workspace = workspace_manifest["workspace"]
    version = workspace["package"]["version"]
    profile = workspace_manifest["profile"]["release"]
    if workspace["resolver"] != "3" or workspace["package"]["rust-version"] != "1.100.0" or profile.get("overflow-checks") is not True:
        raise ValueError("registry policy requires resolver 3, Rust 1.100.0 and release overflow checks")
    archive = toml(source[APFS_PIN])
    if set(archive) != {"commit", "tree", "archive_sha256"} or not (
        COMMIT.fullmatch(archive["commit"]) and COMMIT.fullmatch(archive["tree"])
        and SHA256.fullmatch(archive["archive_sha256"])
    ):
        raise ValueError("unrecognized APFS source pin")
    packages = {item["source_name"]: item for item in policy["packages"]}
    record = {
        "schema": "exacopy-registry-projection-v1", "source_commit": commit, "version": version,
        "projection_policy_sha256": fingerprint(policy),
        "workspace_lock_sha256": digest(source["Cargo.lock"]), "packages": [],
        "workspace_registry_lock": lock_baseline(toml(source["Cargo.lock"]), version),
        "external_companion": {
            "name": "apfs-mounted", "version": workspace["dependencies"]["apfs-mounted"]["version"][1:], **archive,
        },
    }
    projected = {}
    earlier = set()
    for package in policy["packages"]:
        name, path = package["name"], package["path"]
        if path not in workspace["members"]:
            raise ValueError(f"registry package is not a canonical workspace member: {path}")
        manifest_path = f"{path}/Cargo.toml"
        manifest = checked_manifest(source[manifest_path], package["manifest_sha256"], manifest_path)
        if manifest["package"]["name"] != package["source_name"] or manifest["package"]["publish"] is not False:
            raise ValueError(f"unexpected canonical package identity at {manifest_path}")
        staged_manifest, dependencies = standalone_manifest(manifest, workspace, profile, package, packages, forks)
        if (set(dependencies) & packages.keys()) - earlier:
            raise ValueError(f"registry dependency order is invalid for {name}")
        earlier.add(name)
        prefix = f"{path}/src/"
        staged = {file.removeprefix(f"{path}/"): data for file, data in source.items() if file.startswith(prefix)}
        entries = {"src/lib.rs", "src/main.rs"} if name == "exacopy" else {"src/lib.rs"}
        if missing := entries - staged.keys():
            raise ValueError(f"registry package source entries missing in {path}: {', '.join(sorted(missing))}")
        readme = package_readme(name, package["description"], commit)
        if name == "exacopy" and forks:
            readme = readme.replace(
                b"Experimental features require the source workspace.",
                b"Linux SSH/WireGuard, Linux managed sync init/preview and Windows local NTFS comparison require explicit Cargo features and separate qualification.",
            )
        staged.update({"Cargo.toml": staged_manifest, "LICENSE": source["LICENSE"], "README.md": readme})
        record["packages"].append({
            "name": name, "source_path": path, "source_manifest_sha256": digest(source[manifest_path]),
            "dependencies": dependencies, "files_sha256": {file: digest(data) for file, data in sorted(staged.items())},
        })
        projected.update({f"{name}/{file}": data for file, data in staged.items()})
    projected["projection.json"] = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    return projected


def projection_inputs(root, commit, policy, extra=()):
    requested = ["Cargo.toml", "Cargo.lock", "LICENSE", APFS_PIN, *extra]
    for package in policy["packages"]:
        requested.extend(f"{package['path']}/{entry}" for entry in ("Cargo.toml", "src"))
    if not COMMIT.fullmatch(commit):
        raise ValueError("source must be a full ExaCopy commit ID")
    build_paths = [f"{package['path']}/build.rs" for package in policy["packages"]]
    if git(root, "ls-tree", "--full-tree", "-r", commit, "--", *build_paths):
        raise ValueError("registry projection requires review before packaging implicit build scripts")
    return source_files(root, commit, requested)


def write_projection(destination, projected):
    for file in projected:
        parts = file.split("/")
        if any(not part or part in (".", "..") or "\\" in part or ":" in part for part in parts):
            raise ValueError(f"registry projection output path is outside its staging directory: {file!r}")
    destination.mkdir()
    try:
        for file, data in sorted(projected.items()):
            target = destination / file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    except BaseException:
        shutil.rmtree(destination)
        raise


def project(root, commit, destination, policy):
    write_projection(destination, render(projection_inputs(root, commit, policy), commit, policy))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True, help="full immutable ExaCopy commit ID")
    parser.add_argument("--output", type=Path, required=True, help="absent destination for the registry staging files")
    parser.add_argument("--profile", choices=("default", "transports"), default="default")
    args = parser.parse_args()
    try:
        policy = toml(POLICY.read_bytes())
        if args.profile == "transports":
            import registry_transport_projection
            registry_transport_projection.project_transport(ROOT, args.commit, args.output, policy)
        else:
            project(ROOT, args.commit, args.output, policy)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"registry projection: {error}\n")


if __name__ == "__main__":
    main()
