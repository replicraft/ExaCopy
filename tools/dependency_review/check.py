#!/usr/bin/env python3
"""Check the locked production dependency inventory and report review gaps."""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from apfs_source import (
    CONSUMER, CONSUMER_MANIFEST, KEY as APFS_KEY, PIN as APFS_PIN, dependency_manifest_matches,
    read_pin, verify_checkout, verify_consumer,
)
from feature_matrix import MATRIX, profile_features, profile_flags

SPEC = Path("docs/specs/dependencies")
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
TREE_ROW = re.compile(r"([0-9]+)\|([^ ]+) v([^ ]+)(?: [^\t]*)?\t(.*)")
REVIEW_FIELDS = {
    "archive_sha256", "release_observation", "security_history", "unsafe_exposure",
    "resource_limits", "adversarial_inputs", "verification", "replacement", "review_gaps",
}


def cargo(command, *flags, offline):
    arguments = ["cargo", command, "--locked", *flags]
    if offline:
        arguments.append("--offline")
    return subprocess.check_output(arguments, text=True)


def package_id(name, version):
    return f"{name}@{version}"


def tree_inputs(output):
    """Collect immediate parents and effective features for resolved normal and build units."""
    ancestors = []
    parents = defaultdict(set)
    features = defaultdict(set)
    for row in output.splitlines():
        if not row:
            continue
        match = TREE_ROW.fullmatch(row.removesuffix(" (*)"))
        if not match:
            raise ValueError(f"unexpected Cargo dependency row {row!r}")
        depth_text, name, version, feature_text = match.groups()
        depth = int(depth_text)
        if depth > len(ancestors):
            raise ValueError(f"Cargo dependency row has no parent: {row!r}")
        key = package_id(name, version)
        del ancestors[depth:]
        if depth:
            parents[key].add(ancestors[-1])
        ancestors.append(key)
        features[key].update(feature_text.split(",") if feature_text else ())
    if not features:
        raise ValueError("Cargo returned an empty dependency graph")
    return parents, features


def packages_by_identity(metadata, target):
    packages = defaultdict(list)
    for package in metadata["packages"]:
        packages[package_id(package["name"], package["version"])].append(package)
    for key, candidates in packages.items():
        if len(candidates) != 1:
            raise ValueError(f"{target}: ambiguous Cargo package identity {key}")
    return {key: candidates[0] for key, candidates in packages.items()}


def registry_inputs(package, checksums):
    key = package_id(package["name"], package["version"])
    source = package["source"]
    identity = (key, source)
    checksum = checksums.get(identity, "")
    if source != CRATES_IO or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError(f"{key} lacks an exact crates.io archive SHA-256 in Cargo.lock")
    if not package["license"] or not package["repository"]:
        raise ValueError(f"{key} must identify its license and upstream repository")
    return source_inputs(package, source, checksum)


def source_inputs(package, source, checksum):
    kinds = {kind for target in package["targets"] for kind in target["kind"]}
    return {
        "source": source,
        "archive_sha256": checksum,
        "license": package["license"],
        "repository": package["repository"],
        "build_script": "custom-build" in kinds,
        "proc_macro": "proc-macro" in kinds,
    }


def apfs_inputs(package, source, pin, target, parents, features):
    if (
        not dependency_manifest_matches(package, source)
        or target != "aarch64-apple-darwin"
        or parents != {f"{CONSUMER}@0.1.0"}
        or features
    ):
        raise ValueError(f"{target}: unexpected source, edges or features for {APFS_KEY}")
    return source_inputs(package, "local-path", pin["archive_sha256"]) | {
        "commit": pin["commit"], "tree": pin["tree"],
    }


def production_graph(policy, lock, offline, source, apfs_pin):
    checksums = {
        (package_id(entry["name"], entry["version"]), entry["source"]): entry["checksum"]
        for entry in lock["package"] if "checksum" in entry
    }
    roots = [argument for name in policy["production_packages"] for argument in ("-p", name)]
    inputs = {}
    resolutions = {}
    for target in policy["targets"]:
        production_profiles = {
            name: profile
            for name, profile in policy["profiles"].items()
            if target in profile.get("targets", policy["targets"])
            and "verification" not in profile["feature_statuses"]
        }
        selected_features = sorted({
            feature
            for profile in production_profiles.values()
            for feature in profile_features(policy, profile, target)
        })
        metadata_flags = ["--features", ",".join(selected_features)] if selected_features else []
        metadata = cargo(
            "metadata", "--format-version", "1", "--filter-platform", target, *metadata_flags,
            offline=offline,
        )
        metadata = json.loads(metadata)
        packages = packages_by_identity(metadata, target)
        workspace = set(metadata["workspace_members"])
        for profile_name, profile in production_profiles.items():
            parents, features = tree_inputs(cargo(
                "tree", *roots, "--target", target, "--edges", "normal,build", "--prefix", "depth",
                "--format", "|{p}\t{f}", *profile_flags(policy, profile, target), offline=offline,
            ))
            resolved = {}
            for key, selected in sorted(features.items()):
                package = packages[key]
                if package["id"] in workspace and package["name"] in policy["production_packages"]:
                    continue
                if package["source"] is None:
                    if key != APFS_KEY:
                        raise ValueError(f"{target}/{profile_name}: unexpected local dependency {key}")
                    record = apfs_inputs(package, source, apfs_pin, target, parents[key], selected)
                else:
                    record = registry_inputs(package, checksums)
                if inputs.setdefault(key, record) != record:
                    raise ValueError(f"{key}: inconsistent package metadata across targets")
                resolved[key] = {"parents": sorted(parents[key]), "features": sorted(selected)}
            if target == "aarch64-apple-darwin" and APFS_KEY not in resolved:
                raise ValueError(f"{target}/{profile_name}: missing {APFS_KEY}")
            # Store identical profiles for the same target once.
            target_resolutions = resolutions.setdefault(target, [])
            for group in target_resolutions:
                if group["inputs"] == resolved:
                    group["profiles"].append(profile_name)
                    break
            else:
                target_resolutions.append({"profiles": [profile_name], "inputs": resolved})
    return {"schema_version": 1, "packages": inputs, "resolutions": resolutions}


def compact_graph(graph):
    """Keep the generated snapshot diff readable at the package and edge level."""
    lines = ['{', f'  "schema_version": {graph["schema_version"]},', '  "packages": {']
    lines.append(",\n".join(
        f"    {json.dumps(key)}: {json.dumps(record)}" for key, record in sorted(graph["packages"].items())
    ))
    lines.extend(['  },', '  "resolutions": {'])
    targets = []
    for target, groups in sorted(graph["resolutions"].items()):
        group_lines = []
        for group in groups:
            edges = ",\n".join(
                f"          {json.dumps(key)}: {json.dumps(record)}"
                for key, record in sorted(group["inputs"].items())
            )
            group_lines.append(
                f'      {{\n        "profiles": {json.dumps(group["profiles"])},\n'
                f'        "inputs": {{\n{edges}\n        }}\n      }}'
            )
        targets.append(f"    {json.dumps(target)}: [\n" + ",\n".join(group_lines) + "\n    ]")
    lines.extend([",\n".join(targets), "  }", "}"])
    return "\n".join(lines)


def review_gaps(graph, expected, reviews):
    if expected != graph:
        old_packages = expected["packages"]
        new_packages = graph["packages"]
        changed_packages = sorted(
            key for key in old_packages.keys() | new_packages.keys()
            if old_packages.get(key) != new_packages.get(key)
        )
        old_resolutions = expected["resolutions"]
        new_resolutions = graph["resolutions"]
        changed_targets = sorted(
            target for target in old_resolutions.keys() | new_resolutions.keys()
            if old_resolutions.get(target) != new_resolutions.get(target)
        )
        raise ValueError(
            "locked production graph differs from graph.json "
            f"(package metadata {changed_packages}, target resolutions {changed_targets}). "
            "Inspect affected package and scope records with --emit-graph."
        )
    if reviews["schema_version"] != 1:
        raise ValueError("unsupported suitability schema version")
    inputs = graph["packages"]
    purposes = reviews["purpose"]
    names = {key.partition("@")[0] for key in inputs}
    if names != set(purposes) or not all(isinstance(purpose, str) and purpose.strip() for purpose in purposes.values()):
        raise ValueError(f"production purpose inventory differs: {sorted(names ^ set(purposes))}")
    direct = {
        key
        for groups in graph["resolutions"].values()
        for group in groups
        for key, selection in group["inputs"].items()
        if any(parent not in inputs for parent in selection["parents"])
    }
    assessments = reviews["assessment"]
    if direct - assessments.keys():
        raise ValueError(f"missing direct dependency assessments: {sorted(direct - assessments.keys())}")
    for key, record in assessments.items():
        if key not in inputs or record.keys() != REVIEW_FIELDS:
            raise ValueError(f"{key}: unexpected or incomplete suitability assessment")
        if record["archive_sha256"] != inputs[key]["archive_sha256"]:
            raise ValueError(f"{key}: suitability assessment does not identify the locked archive")
        for field in REVIEW_FIELDS - {"archive_sha256", "review_gaps"}:
            if not isinstance(record[field], str) or not record[field].strip():
                raise ValueError(f"{key}: empty {field}")
        gaps = record["review_gaps"]
        if not isinstance(gaps, list) or not all(isinstance(gap, str) and gap.strip() for gap in gaps):
            raise ValueError(f"{key}: invalid scoped review gaps")
    return direct, sorted(set(inputs) - assessments.keys())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Use the existing Cargo cache.")
    parser.add_argument("--emit-graph", action="store_true", help="Print the resolved graph for review.")
    args = parser.parse_args()
    try:
        policy = json.loads(MATRIX.read_text(encoding="utf-8"))
        lock = tomllib.loads(Path("Cargo.lock").read_text(encoding="utf-8"))
        source = Path.cwd()
        apfs_pin = read_pin((source / APFS_PIN).read_text(encoding="utf-8"))
        verify_consumer(*(
            tomllib.loads((source / path).read_text(encoding="utf-8")) for path in
            ("Cargo.toml", CONSUMER_MANIFEST)
        ))
        verify_checkout(source, apfs_pin)
        graph = production_graph(policy, lock, args.offline, source, apfs_pin)
        if args.emit_graph:
            print(compact_graph(graph))
            return
        expected = json.loads((SPEC / "graph.json").read_text(encoding="utf-8"))
        reviews = tomllib.loads((SPEC / "suitability.toml").read_text(encoding="utf-8"))
        direct, missing = review_gaps(graph, expected, reviews)
        count = len(graph["packages"])
        print(f"Locked production graph matches {count} registry and pinned source versions across {len(graph['resolutions'])} targets.")
        print(f"{len(reviews['assessment'])} suitability assessments cover {len(direct)} direct dependencies and reviewed transitive inputs.")
        if missing:
            print(f"{len(missing)} versions lack a suitability entry in this inventory: {', '.join(missing)}")
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"dependency review: {error}\n")


if __name__ == "__main__":
    main()
