#!/usr/bin/env python3
"""Verify the pinned Pomologie source, optionally provisioning a clean checkout."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import tomllib

PIN = Path("docs/specs/dependencies/apfs-source.toml")
SIBLING = Path("pomologie/apfs")
MEMBER = Path("crates/platform/apfs-mounted")
WORKSPACE_PATH = (Path("..") / SIBLING / MEMBER).as_posix()
NAME = "apfs-mounted"
KEY = f"{NAME}@0.1.0"
REPOSITORY = "https://github.com/pomologie/apfs"
CONSUMER = "exacopy-platform"
CONSUMER_MANIFEST = Path("crates/endpoints/platform/Cargo.toml")
MACOS_CFG = 'cfg(target_os = "macos")'


def read_pin(contents):
    pin = tomllib.loads(contents)
    fields = {"commit": 40, "tree": 40, "archive_sha256": 64}
    if pin.keys() != fields.keys() or any(
        not isinstance(pin[key], str) or not re.fullmatch(f"[0-9a-f]{{{size}}}", pin[key])
        for key, size in fields.items()
    ):
        raise ValueError("invalid apfs-mounted source pin")
    return pin


def verify_consumer(root_manifest, platform_manifest):
    workspace_dep = root_manifest["workspace"]["dependencies"].get(NAME)
    platform_dep = platform_manifest.get("target", {}).get(MACOS_CFG, {}).get("dependencies", {}).get(NAME)
    if workspace_dep != {"path": WORKSPACE_PATH, "default-features": False} or platform_dep != {"workspace": True}:
        raise ValueError("apfs-mounted must be inherited without default features in the macOS dependency table")


def sibling(source):
    return source.resolve().parent / SIBLING


def git_output(repository, *arguments):
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-C", str(repository), *arguments], text=True,
    ).strip()


def verify_manifest(workspace, member):
    project = workspace["workspace"]
    package = member["package"]
    if (
        MEMBER.as_posix() not in project["members"]
        or project["package"]["repository"] != REPOSITORY
        or project["package"]["license"] != "Apache-2.0"
        or f'{package["name"]}@{package["version"]}' != KEY
        or package.get("repository") != {"workspace": True}
        or package.get("license") != {"workspace": True}
    ):
        raise ValueError("APFS archive manifests do not identify the pinned workspace member")


def archive_apfs(source, pin, archive):
    archive_checkout(sibling(source), pin, archive)


def archive_checkout(repository, pin, archive):
    if not (repository / ".git").exists():
        raise ValueError(f"missing APFS checkout at {repository}; supply the pinned revision {pin['commit']}")
    if repository.resolve(strict=True) != repository or Path(git_output(repository, "rev-parse", "--show-toplevel")).resolve() != repository:
        raise ValueError("APFS checkout must be a Git root at the expected sibling path")
    if git_output(repository, "rev-parse", "HEAD") != pin["commit"]:
        raise ValueError(f"APFS checkout is at the wrong revision; expected {pin['commit']}")
    if git_output(repository, "rev-parse", "HEAD^{tree}") != pin["tree"]:
        raise ValueError("APFS checkout tree differs from the source pin")
    if git_output(repository, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("APFS checkout has uncommitted changes")
    subprocess.run([
        "git", "--no-replace-objects", "-C", str(repository), "-c", "tar.umask=0002",
        "archive", "--format=tar", "--output", str(archive), pin["commit"],
    ], check=True)
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != pin["archive_sha256"]:
        raise ValueError("APFS source archive SHA-256 differs from the source pin")
    with tarfile.open(archive, "r:") as files:
        manifests = [tomllib.loads(files.extractfile(path).read().decode()) for path in
                     ("Cargo.toml", (MEMBER / "Cargo.toml").as_posix())]
        verify_manifest(*manifests)


def verify_checkout(source, pin):
    with tempfile.TemporaryDirectory(prefix="exacopy-apfs-check-") as temp:
        archive_apfs(source, pin, Path(temp) / "apfs.tar")


def dependency_manifest_matches(package, source):
    return (
        package["source"] is None
        and f'{package["name"]}@{package["version"]}' == KEY
        and Path(package["manifest_path"]).resolve() == sibling(source) / MEMBER / "Cargo.toml"
        and package["repository"] == REPOSITORY
        and package["license"] == "Apache-2.0"
    )


def provision(source, pin):
    repository = sibling(source)
    if repository.exists():
        verify_checkout(source, pin)
        return
    parent = repository.parent
    parent.mkdir(exist_ok=True)
    if parent.resolve() != parent:
        raise ValueError("APFS checkout parent must be at the expected sibling path")
    env = os.environ | {"GIT_TERMINAL_PROMPT": "0"}
    with tempfile.TemporaryDirectory(prefix="apfs-provision-", dir=parent) as temp:
        staging = Path(temp) / "checkout"
        subprocess.run(["git", "init", "--quiet", str(staging)], check=True)
        command = ["git", "-C", str(staging)]
        try:
            subprocess.run([*command, "fetch", "--quiet", "--depth=1", REPOSITORY, pin["commit"]], check=True, env=env)
        except subprocess.CalledProcessError as error:
            raise ValueError(f"pinned APFS revision {pin['commit']} could not be fetched from {REPOSITORY}") from error
        subprocess.run([*command, "config", "core.autocrlf", "false"], check=True)
        subprocess.run([*command, "checkout", "--quiet", "--detach", pin["commit"]], check=True)
        archive_checkout(staging, pin, Path(temp) / "apfs.tar")
        if repository.exists() or repository.is_symlink():
            raise ValueError(f"APFS checkout appeared during provisioning at {repository}")
        staging.rename(repository)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="Fetch the exact pinned revision if the sibling checkout is absent.")
    args = parser.parse_args()
    try:
        source = Path.cwd()
        pin = read_pin((source / PIN).read_text(encoding="utf-8"))
        verify_consumer(*(
            tomllib.loads((source / path).read_text(encoding="utf-8")) for path in
            ("Cargo.toml", CONSUMER_MANIFEST)
        ))
        if args.fetch:
            provision(source, pin)
        else:
            verify_checkout(source, pin)
        print(json.dumps({"repository": REPOSITORY, **pin}, sort_keys=True))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, f"APFS source: {error}\n")


if __name__ == "__main__":
    main()
