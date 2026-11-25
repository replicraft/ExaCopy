#!/usr/bin/env python3
"""Check the declared and resolved Cargo feature matrix for a native CI target."""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import subprocess

from apfs_source import CONSUMER, MACOS_CFG, NAME as APFS_NAME, WORKSPACE_PATH


MATRIX = Path("docs/specs/features/matrix.json")


def check_manifests(policy, packages):
    production = set(policy["production_packages"])
    engineering = set(policy["engineering_packages"])
    declared = {package["name"] for package in packages}
    if production & engineering or declared != production | engineering:
        raise ValueError(f"workspace package inventory differs: {declared ^ (production | engineering)}")

    rules = policy["production_dependencies"]
    seen = set()
    for package in packages:
        name = package["name"]
        entries = policy["features"].get(name, {})
        expected = {feature: sorted(entry["enables"]) for feature, entry in entries.items()}
        actual = {feature: sorted(enables) for feature, enables in package["features"].items()}
        if expected != actual:
            raise ValueError(f"{name}: Cargo features differ: expected {expected}, got {actual}")
        for dependency in package["dependencies"]:
            if name not in production or dependency["kind"] == "dev":
                continue
            dep_name = dependency["name"]
            if dependency["source"] is None:
                if dep_name in production:
                    continue
                if (
                    name != CONSUMER or dep_name != APFS_NAME or dependency["kind"] is not None
                    or dependency["target"] != MACOS_CFG
                    or Path(dependency["path"]).resolve() != (Path.cwd() / WORKSPACE_PATH).resolve()
                ):
                    raise ValueError(f"{name}: unreviewed production path dependency {dep_name}")
            if dep_name not in rules:
                raise ValueError(f"{name}: unreviewed production dependency {dep_name}")
            seen.add(dep_name)
            rule = rules[dep_name]
            additions = rule.get("feature_additions", {}).get(name, [])
            if isinstance(additions, dict):
                additions = additions.get(dependency["target"], [])
            expected = (
                rule["default_features"],
                sorted(rule["features"] + additions),
                rule.get("optional", False)
                or dependency["target"] in rule.get("optional_targets", {}).get(name, []),
            )
            actual = (
                dependency["uses_default_features"],
                sorted(dependency["features"]),
                dependency["optional"],
            )
            if expected != actual:
                raise ValueError(
                    f"{name}: {dep_name} feature selection differs on {dependency['target']}: "
                    f"expected {expected}, got {actual} (default, features, optional)"
                )
    if seen != set(rules):
        raise ValueError(f"production dependency inventory has unused entries: {sorted(set(rules) - seen)}")


def resolved_graph(cargo, roots, target, flags):
    root_flags = [argument for package in roots for argument in ("-p", package)]
    output = cargo(
        "tree", *root_flags, "--target", target, "--edges", "normal,build",
        "--prefix", "none", "--format", "{p}\t{f}", *flags, capture=True,
    )
    packages = defaultdict(set)
    for line in output.splitlines():
        if line in {"[build-dependencies]", ""}:
            continue
        package_with_version, features = line.removesuffix(" (*)").split("\t")
        name, version, *_ = package_with_version.split()
        if not version.startswith("v"):
            raise ValueError(f"unexpected cargo tree version: {line}")
        packages[f"{name}@{version[1:]}"].update(features.split(",") if features else ())
    return packages


def check_cli_graph(policy, target, graph):
    target_policy = policy["targets"][target]
    groups = policy["cli_graph_groups"]
    expected = {package for group in target_policy["cli_graph_groups"] for package in groups[group]}
    if set(graph) != expected:
        raise ValueError(
            f"{target}: CLI dependency graph drift: "
            f"unexpected {sorted(set(graph) - expected)}, missing {sorted(expected - set(graph))}"
        )
    controls = policy["production_dependencies"]
    for identity, features in graph.items():
        name, _, _ = identity.partition("@")
        if name == "rustix":
            allowed = set(target_policy["rustix_features"])
        elif name in controls and not controls[name]["default_features"]:
            allowed = set(controls[name]["features"])
        elif name in policy["production_packages"]:
            allowed = set()
        else:
            continue
        if features != allowed:
            raise ValueError(
                f"{target}: CLI dependency {identity} enables {sorted(features)}, expected {sorted(allowed)}"
            )


def profile_features(policy, profile, target):
    if "feature_packages" in profile:
        raise ValueError("unrecognized feature_packages selector; use exact_features")
    targets = set(profile.get("targets", policy["targets"]))
    if not targets or targets - policy["targets"].keys():
        raise ValueError("profile has missing or unknown targets")
    exact = profile.get("exact_features")
    if exact is not None:
        if profile["defaults"] or profile["feature_statuses"]:
            raise ValueError("exact_features requires an isolated profile with defaults and status selection off")
        if not exact:
            raise ValueError("exact_features requires at least one feature selector")
        if len(exact) != len(set(exact)):
            raise ValueError("duplicate exact feature selector")
        for selector in exact:
            package, _, feature = selector.partition("/")
            entry = policy["features"].get(package, {}).get(feature)
            if entry is None or entry["status"] != "experimental":
                raise ValueError(f"unknown or non-experimental exact feature selector {selector}")
            if targets - set(entry.get("targets", policy["targets"])):
                raise ValueError(f"exact feature selector {selector} is unavailable on a profile target")
        return sorted(exact) if target in targets else []
    return sorted(
        f"{package}/{name}"
        for package, features in policy["features"].items()
        for name, entry in features.items()
        if entry["status"] in profile["feature_statuses"]
        and target in entry.get("targets", policy["targets"])
    )


def profile_flags(policy, profile, target):
    flags = [] if profile["defaults"] else ["--no-default-features"]
    features = profile_features(policy, profile, target)
    if features:
        flags.extend(["--features", ",".join(features)])
    return flags


def check_isolated_features(policy, target, profile_name, profile, graph):
    expected = set(profile_features(policy, profile, target))
    production = set(policy["production_packages"])
    selected = set()
    for identity, features in graph.items():
        name, _, _ = identity.partition("@")
        if name in production:
            selected.update(f"{name}/{feature}" for feature in features)
    if selected != expected:
        raise ValueError(
            f"{target}/{profile_name}: isolated workspace features differ: "
            f"unexpected {sorted(selected - expected)}, missing {sorted(expected - selected)}"
        )


def check_optional_features(policy, target, cargo):
    for package, entries in policy["features"].items():
        for name, entry in entries.items():
            if target not in entry.get("targets", policy["targets"]):
                continue
            expected = set(entry["resolution_probe"])
            minimal = ["--no-default-features"]
            off = resolved_graph(cargo, [package], target, minimal)
            on = resolved_graph(cargo, [package], target, [*minimal, "--features", name])
            off_names = {identity.partition("@")[0] for identity in off}
            on_names = {identity.partition("@")[0] for identity in on}
            enabled = any(
                name in features for identity, features in on.items()
                if identity.startswith(f"{package}@")
            )
            if expected & off_names or expected - on_names or not enabled:
                raise ValueError(
                    f"{target}: {package}/{name} dependency probe differs: "
                    f"unexpected while off {sorted(expected & off_names)}, "
                    f"missing while on {sorted(expected - on_names)}"
                )


def check_matrix(policy, target, cargo, graph_only):
    manifest = cargo("metadata", "--format-version", "1", "--no-deps", capture=True)
    check_manifests(policy, json.loads(manifest)["packages"])
    root = policy["product_package"]
    for name, profile in policy["profiles"].items():
        flags = profile_flags(policy, profile, target)
        if target not in profile.get("targets", policy["targets"]):
            print(f"{target}: {name} not applicable", flush=True)
            continue
        if profile["check_cli"]:
            check_cli_graph(policy, target, resolved_graph(cargo, [root], target, flags))
        if "exact_features" in profile:
            graph = resolved_graph(cargo, policy["production_packages"], target, flags)
            check_isolated_features(policy, target, name, profile, graph)
        if not graph_only:
            cargo("check", "--workspace", "--all-targets", "--target", target, *flags)
            print(f"{target}: {name} build passed", flush=True)
    check_optional_features(policy, target, cargo)
    print(f"{target}: feature dependency probes passed", flush=True)


def main():
    policy = json.loads(MATRIX.read_text(encoding="utf-8"))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=policy["targets"])
    parser.add_argument("--offline", action="store_true", help="Use the existing Cargo cache.")
    parser.add_argument("--graph-only", action="store_true", help="Skip profile compilation.")
    args = parser.parse_args()
    if policy["schema_version"] != 1:
        parser.error("unsupported feature matrix schema version")

    def cargo(command, *flags, capture=False):
        arguments = ["cargo", command, "--locked", *flags]
        if args.offline:
            arguments.append("--offline")
        print(subprocess.list2cmdline(arguments), flush=True)
        return subprocess.run(
            arguments, check=True, text=True, stdout=subprocess.PIPE if capture else None,
        ).stdout

    try:
        check_matrix(policy, args.target, cargo, args.graph_only)
    except (ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"feature matrix: {error}\n")


if __name__ == "__main__":
    main()
