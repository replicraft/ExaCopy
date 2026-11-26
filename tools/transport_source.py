#!/usr/bin/env python3
"""Provision and verify the two pinned, locally repaired transport packages."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request

PIN = Path("specs/dependencies/transport-source.toml")
INPUTS = PIN.with_suffix("")
SIBLINGS = Path("local-deps")
RUSSH_UTILITY = "russh-util"
POLICY = {
    "boringtun": ("0.7.1", "exacopy-wireguard", [], "BSD-3-Clause", "https://github.com/cloudflare/boringtun"),
    "russh": ("0.65.4", "exacopy-ssh", ["ring"], "Apache-2.0", "https://github.com/warp-tech/russh"),
    RUSSH_UTILITY: ("0.52.0", "russh", [], "Apache-2.0", "https://github.com/warp-tech/russh"),
}
GIT_ENV = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")} | {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "ExaCopy source fixture",
    "GIT_AUTHOR_EMAIL": "fixture@exacopy.invalid",
    "GIT_COMMITTER_NAME": "ExaCopy source fixture",
    "GIT_COMMITTER_EMAIL": "fixture@exacopy.invalid",
    "GIT_AUTHOR_DATE": "2026-11-25T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-11-25T00:00:00Z",
}
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024


def sibling(source, name):
    return source.resolve().parent / SIBLINGS / name


def dependency_edge_matches(dependency, source, consumer):
    name = dependency["name"]
    if name not in POLICY or name == RUSSH_UTILITY:
        return False
    version, expected, features, _, _ = POLICY[name]
    return (
        consumer == expected and dependency["req"] == f"={version}"
        and dependency["kind"] is None and dependency["target"] is None
        and dependency["source"] is None and dependency["rename"] is None
        and dependency["optional"] and not dependency["uses_default_features"]
        and sorted(dependency["features"]) == features
        and dependency.get("path") is not None and Path(dependency["path"]) == sibling(source, name)
    )


def package_matches(package, source):
    name = package["name"]
    if name not in POLICY:
        return False
    version, _, _, license_name, repository = POLICY[name]
    return (
        package["source"] is None and package["version"] == version
        and package["license"] == license_name and package["repository"] == repository
        and Path(package["manifest_path"]) == sibling(source, name) / "Cargo.toml"
    )


def hex_value(value, digits):
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{digits}}}", value)


def read_pins(source):
    entries = tomllib.loads((source / PIN).read_text(encoding="utf-8"))
    version = entries.pop("schema_version", None)
    if version != 1 or entries.keys() != POLICY.keys():
        raise ValueError("unexpected transport source pin inventory")
    digests = {"registry_archive_sha256", "license_sha256", "normalized_manifest_sha256",
               "repair_patch_sha256", "attribution_patch_sha256"}
    for name, pin in entries.items():
        version, _, _, license_name, repository = POLICY[name]
        package_digests = digests | {"repaired_manifest_sha256"} if name == RUSSH_UTILITY else digests
        if (
            not isinstance(pin, dict) or pin.keys() != package_digests | {"version", "upstream_repository", "upstream_commit", "license",
                                     "license_file", "repair_patch", "attribution_patch", "base", "repair"}
            or pin["version"] != version or pin["license"] != license_name
            or pin["upstream_repository"] != repository or not hex_value(pin["upstream_commit"], 40)
            or any(not hex_value(pin[entry], 64) for entry in package_digests)
            or any(not isinstance(pin[key], str) or not re.fullmatch(r"[-a-zA-Z0-9._]+", pin[key])
                   or pin[key] in (".", "..") for key in ("license_file", "repair_patch", "attribution_patch"))
        ):
            raise ValueError(f"invalid {name} source pin")
        for identity in (pin["base"], pin["repair"]):
            if not isinstance(identity, dict) or identity.keys() != {"commit", "tree", "archive_sha256"} or any(
                not hex_value(identity[field], digits)
                for field, digits in (("commit", 40), ("tree", 40), ("archive_sha256", 64))
            ):
                raise ValueError(f"invalid {name} Git identity")
    return entries


def verify_utility_patch(manifest, version):
    direct = manifest["workspace"]["dependencies"]
    patches = manifest.get("patch", {}).get("crates-io", {})
    expected = {"version": f"={version}", "path": f"../{SIBLINGS}/{RUSSH_UTILITY}"}
    if RUSSH_UTILITY in direct or patches.get(RUSSH_UTILITY) != expected:
        raise ValueError("russh-util must use the exact transitive crates.io source repair")


def verify_manifests(source):
    manifest = tomllib.loads((source / "Cargo.toml").read_text(encoding="utf-8"))
    deps = manifest["workspace"]["dependencies"]
    lock = tomllib.loads((source / "Cargo.lock").read_text(encoding="utf-8"))["package"]
    for name, (version, consumer, features, _, _) in POLICY.items():
        packages = [package for package in lock if package["name"] == name]
        if len(packages) != 1 or packages[0]["version"] != version or any(
            field in packages[0] for field in ("source", "checksum")
        ):
            raise ValueError(f"{name} lockfile must contain only its pinned local version")
        if name == RUSSH_UTILITY:
            verify_utility_patch(manifest, version)
            continue
        expected = {"version": f"={version}", "path": f"../{SIBLINGS}/{name}", "default-features": False}
        if deps.get(name) != expected:
            raise ValueError(f"{name} Cargo workspace declaration differs from its source pin")
        member = source / "crates/net" / consumer / "Cargo.toml"
        direct = tomllib.loads(member.read_text(encoding="utf-8"))["dependencies"].get(name)
        expected = {"workspace": True, "optional": True}
        if features:
            expected["features"] = features
        if direct != expected:
            raise ValueError(f"{consumer} declaration of {name} differs from its source pin")
    unix_fixtures = 'cfg(any(target_os = "linux", target_os = "macos"))'
    for fixture in ("apps/exacopy-cli", "crates/adapters/exacopy-sftp"):
        manifest = tomllib.loads((source / fixture / "Cargo.toml").read_text(encoding="utf-8"))
        fixture_dependencies = manifest.get("target", {}).get(unix_fixtures, {}).get("dev-dependencies", {})
        if fixture_dependencies.get("russh") != {"workspace": True, "features": ["ring"]}:
            raise ValueError(f"{fixture} Russh fixture differs from its source pin")


def checked(data, expected, field):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"unexpected SHA-256 for {field}")
    return data


def git(repository, *args, extra_env=None, content=None):
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-C", os.fspath(repository), *args],
        env=GIT_ENV | (extra_env or {}), input=content,
    )


def immutable_archive(repository, pin, revision="HEAD"):
    if git(repository, "rev-parse", revision).decode().strip() != pin["commit"]:
        raise ValueError(f"{repository.name} checkout commit differs from the source pin")
    if git(repository, "rev-parse", f"{revision}^{{tree}}").decode().strip() != pin["tree"]:
        raise ValueError(f"{repository.name} checkout tree differs from the source pin")
    return checked(
        git(repository, "-c", "tar.umask=0002", "archive", "--format=tar", pin["commit"]),
        pin["archive_sha256"], f"{repository.name} canonical Git archive",
    )


def source_files(contents, package=None):
    with tarfile.open(fileobj=io.BytesIO(contents), mode="r:*") as archive:
        for entry in archive:
            parts = PurePosixPath(entry.name).parts
            if package is not None:
                if not parts or parts[0] != package:
                    raise ValueError("unexpected prefix in published archive")
                parts = parts[1:]
            if any(part in ("/", ".", "..", ".git") or "\\" in part or ":" in part for part in parts):
                raise ValueError(f"invalid archive member {entry.name!r}")
            if entry.isdir():
                continue
            if not parts or not entry.isfile() or entry.size > MAX_ARCHIVE_BYTES:
                raise ValueError(f"invalid source archive member {entry.name!r}")
            yield Path(*parts), archive.extractfile(entry).read(), bool(entry.mode & 0o111)


def verify_files(path, contents):
    if path.resolve(strict=True) != path:
        raise ValueError(f"{path.name} must be at its exact sibling path")
    expected = {file for file, _, _ in source_files(contents)}
    observed = set()
    for directory, folders, files in os.walk(path, followlinks=False):
        parent = Path(directory)
        if parent == path and ".git" in folders:
            folders.remove(".git")
        for name in [*folders, *files]:
            child = parent / name
            if child.is_symlink() or (hasattr(child, "is_junction") and child.is_junction()):
                raise ValueError(f"unexpected link in {path.name} source")
        observed.update((parent / name).relative_to(path) for name in files)
    if observed != expected:
        raise ValueError(f"{path.name} checkout file set differs from its pinned source")
    for file, data, executable in source_files(contents):
        file = path / file
        mode = file.stat().st_mode
        if not stat.S_ISREG(mode) or file.read_bytes() != data:
            raise ValueError(f"{path.name} worktree bytes differ from the source pin")
        if os.name != "nt" and bool(mode & 0o111) != executable:
            raise ValueError(f"{path.name} worktree executable bit differs from the source pin")


def verified_inputs(source, name, pin):
    inputs = source / INPUTS
    patches = []
    for kind in ("repair_patch", "attribution_patch"):
        patch = inputs / pin[kind]
        checked(patch.read_bytes(), pin[f"{kind}_sha256"], f"{name} {kind}")
        patches.append(patch)
    license_text = checked(
        (inputs / f"{name}-{pin['license_file']}").read_bytes(), pin["license_sha256"], f"{name} notice",
    )
    return patches, license_text


def verify_package_metadata(manifest, vcs, name, pin):
    checked(manifest, pin["normalized_manifest_sha256"], f"{name} normalized manifest")
    package = tomllib.loads(manifest.decode())["package"]
    if (package["name"], package["version"], package["repository"], package["license"], vcs["git"]["sha1"]) != (
        name, pin["version"], pin["upstream_repository"], pin["license"], pin["upstream_commit"]
    ):
        raise ValueError(f"unexpected source identity in published {name} archive")


def verify_lineage(repository, name, pin, patches, license_text):
    parents = git(repository, "rev-list", "--parents", "-n1", "HEAD").decode().split()
    if parents != [pin["repair"]["commit"], pin["base"]["commit"]]:
        raise ValueError(f"{name} repair must have the pinned published archive commit as its only parent")
    base = immutable_archive(repository, pin["base"], pin["base"]["commit"])
    files = {file.name: data for file, data, _ in source_files(base) if len(file.parts) == 1}
    verify_package_metadata(files["Cargo.toml"], json.loads(files[".cargo_vcs_info.json"]), name, pin)

    # Reapply the reviewed change to the verified base tree without reading the
    # installed source's index or writing to its object store.
    objects = git(repository, "rev-parse", "--path-format=absolute", "--git-path", "objects").decode().strip()
    with tempfile.TemporaryDirectory(prefix="transport-lineage-") as temp:
        work = Path(temp).resolve()
        (work / "objects").mkdir()
        isolated = {
            "GIT_INDEX_FILE": str(work / "index"),
            "GIT_OBJECT_DIRECTORY": str(work / "objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": objects,
        }
        git(repository, "read-tree", pin["base"]["tree"], extra_env=isolated)
        for patch in patches:
            git(repository, "apply", "--cached", "--whitespace=error", str(patch), extra_env=isolated)
        license_id = git(repository, "hash-object", "-w", "--stdin", extra_env=isolated,
                         content=license_text).decode().strip()
        git(repository, "update-index", "--add", "--cacheinfo", f"100644,{license_id},{pin['license_file']}",
            extra_env=isolated)
        if git(repository, "write-tree", extra_env=isolated).decode().strip() != pin["repair"]["tree"]:
            raise ValueError(f"{name} repaired tree is not the exact reviewed patch and pinned notice")


def archive_sources(source, pins, output=None):
    archives = {}
    for name, pin in pins.items():
        repository = sibling(source, name)
        patches, license_text = verified_inputs(source, name, pin)
        private_git = repository / ".git"
        if (not private_git.is_dir() or private_git.is_symlink()
                or repository.resolve(strict=True) != repository
                or (hasattr(private_git, "is_junction") and private_git.is_junction())):
            raise ValueError(f"missing pinned {name} checkout at {repository}")
        archive = immutable_archive(repository, pin["repair"])
        verify_files(repository, archive)
        verify_lineage(repository, name, pin, patches, license_text)
        verify_repaired_manifest(repository, name, pin)
        if output is not None:
            destination = output / f"{name}.tar"
            with destination.open("xb") as stream:
                stream.write(archive)
            archives[name] = destination
    return archives


def extract_sources(source, archives, pins):
    if archives.keys() != pins.keys():
        raise ValueError("missing reviewed transport source archive")
    for name, archive in archives.items():
        data = checked(archive.read_bytes(), pins[name]["repair"]["archive_sha256"], name)
        path = sibling(source, name)
        path.mkdir(parents=True)
        for file, contents, executable in source_files(data):
            target = path / file
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(contents)
            target.chmod(0o755 if executable else 0o644)
        verify_files(path, data)


def registry_archive(name, pin, cache):
    filename = f"{name}-{pin['version']}.crate"
    if cache is None:
        url = f"https://static.crates.io/crates/{name}/{filename}"
        with urllib.request.urlopen(url, timeout=30) as response:
            if response.geturl() != url:
                raise ValueError(f"unexpected registry redirect for {name}")
            data = response.read(MAX_ARCHIVE_BYTES + 1)
    else:
        data = (cache / filename).read_bytes()
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError(f"{name} registry archive exceeds its bound")
    return checked(data, pin["registry_archive_sha256"], filename)


def verify_registry_preimages(source, pins, cache):
    for name, pin in pins.items():
        original = registry_archive(name, pin, cache)
        baseline = immutable_archive(sibling(source, name), pin["base"], pin["base"]["commit"])
        package = f"{name}-{pin['version']}"
        by_path = lambda entry: entry[0].as_posix()
        if sorted(source_files(original, package), key=by_path) != sorted(source_files(baseline), key=by_path):
            raise ValueError(f"{name} cached registry package does not reproduce its pinned base files")


def verify_repaired_manifest(repository, name, pin):
    expected = pin.get("repaired_manifest_sha256", pin["normalized_manifest_sha256"])
    checked((repository / "Cargo.toml").read_bytes(), expected, f"{name} repaired manifest")


def provision_one(source, name, pin, repository, cache):
    archive = registry_archive(name, pin, cache)
    repository.mkdir()
    git(repository, "init", "--quiet", "--template=", "--object-format=sha1", "--initial-branch=fixture")
    git(repository, "config", "core.autocrlf", "false")
    git(repository, "config", "core.filemode", "false")
    files = []
    executables = []
    for file, data, executable in source_files(archive, f"{name}-{pin['version']}"):
        target = repository / file
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(0o755 if executable else 0o644)
        files.append(file.as_posix())
        if executable:
            executables.append(file.as_posix())
    git(repository, "add", "--force", "--", *sorted(files))
    if executables:
        git(repository, "update-index", "--chmod=+x", "--", *sorted(executables))
    git(repository, "commit", "--quiet", "-m", f"Import published {name}-{pin['version']} archive")
    immutable_archive(repository, pin["base"])
    manifest = (repository / "Cargo.toml").read_bytes()
    vcs = json.loads((repository / ".cargo_vcs_info.json").read_text(encoding="utf-8"))
    verify_package_metadata(manifest, vcs, name, pin)
    patches, license_text = verified_inputs(source, name, pin)
    for patch in patches:
        git(repository, "apply", "--index", "--whitespace=error", str(patch))
    license_file = repository / pin["license_file"]
    with license_file.open("xb") as stream:
        stream.write(license_text)
    license_file.chmod(0o644)
    git(repository, "add", "--", license_file.name)
    repair = "Wasm clock repair" if name == RUSSH_UTILITY else "transport key API repair"
    git(repository, "commit", "--quiet", "-m", f"Apply reviewed {repair} and retain upstream license")
    verify_repaired_manifest(repository, name, pin)
    verify_files(repository, immutable_archive(repository, pin["repair"]))


def provision(source, pins, cache):
    parent = sibling(source, "boringtun").parent
    parent.mkdir(exist_ok=True)
    if parent.resolve(strict=True) != parent:
        raise ValueError("transport source parent must be the exact sibling directory")
    for name, pin in pins.items():
        target = sibling(source, name)
        if not target.exists() and not target.is_symlink():
            with tempfile.TemporaryDirectory(prefix="transport-source-", dir=parent) as temp:
                candidate = Path(temp).resolve() / name
                provision_one(source, name, pin, candidate, cache)
                target.mkdir()
                try:
                    shutil.copytree(candidate, target, dirs_exist_ok=True)
                except OSError:
                    shutil.rmtree(target)
                    raise
    archive_sources(source, pins)


def write_advisory_lock(path, pins):
    # Cargo's resolved lock continues to cover registry transitives. A
    # separate fixture retains advisory visibility for these upstream bases.
    rows = ["version = 4", ""]
    for name, pin in sorted(pins.items()):
        rows.extend([
            "[[package]]",
            f'name = "{name}"',
            f'version = "{pin["version"]}"',
            'source = "registry+https://github.com/rust-lang/crates.io-index"',
            f'checksum = "{pin["registry_archive_sha256"]}"',
            "",
        ])
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write("\n".join(rows))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="Provision absent sources from pinned crates.io archives.")
    parser.add_argument("--crate-cache", type=Path, help="Read published .crate inputs from this directory when provisioning.")
    parser.add_argument(
        "--advisory-lock", type=Path, help="Write a new registry ancestry lockfile for advisory scanning.",
    )
    args = parser.parse_args()
    try:
        source = Path.cwd()
        pins = read_pins(source)
        verify_manifests(source)
        if args.fetch:
            provision(source, pins, args.crate_cache)
        else:
            archive_sources(source, pins)
        if args.crate_cache is not None:
            verify_registry_preimages(source, pins, args.crate_cache)
        if args.advisory_lock is not None:
            write_advisory_lock(args.advisory_lock, pins)
        for name, pin in pins.items():
            print(f"{name} {pin['version']} verified local source {pin['repair']['commit']}")
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"transport source: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
