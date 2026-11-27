"""Project exact reviewed transport repairs under downstream package identities."""

import copy
import json
from pathlib import Path
import sys
import tempfile

import registry_projection as projection

sys.path.insert(0, str(projection.ROOT / "tools"))
import transport_source

POLICY = Path(__file__).with_name("registry_transports.toml")
# A missing policy entry can remove a CLI flag or leave a dangling feature
# forward. Changes to this public runtime inventory require explicit review.
REQUIRED_EXISTING_FEATURES = {
    "exacopy": {
        "experimental-linux-managed-sync", "experimental-ssh-capture",
        "experimental-ssh-wireguard", "experimental-windows-diff",
    },
    "exacopy-platform": {"experimental-linux-managed-sync", "experimental-windows-read"},
}


def transport_policy(default, selected):
    policy = copy.deepcopy(default)
    cli = policy["packages"].pop()
    if cli["name"] != "exacopy":
        raise ValueError("unexpected default registry package order")
    policy["packages"].extend([*selected["packages"], cli])
    existing = {package["name"] for package in default["packages"]}
    feature_selections = selected.get("existing_features")
    required = REQUIRED_EXISTING_FEATURES.keys()
    if not isinstance(feature_selections, dict) or feature_selections.keys() != required or required - existing:
        raise ValueError("registry transport profile requires exactly the CLI and platform feature owners")
    for name, expected in REQUIRED_EXISTING_FEATURES.items():
        features = feature_selections[name]
        if (not isinstance(features, list) or len(features) != len(expected)
                or any(not isinstance(feature, str) for feature in features) or set(features) != expected):
            raise ValueError(f"registry transport profile requires the exact default-off runtime features for {name}")
    for package in policy["packages"]:
        if package["name"] in feature_selections:
            package["features"] = feature_selections[package["name"]]
        if "default" in package.get("features", ()):
            raise ValueError("registry transport profile must keep runtime features default-off")
    return policy


def fork_manifest(manifest, fork, forks):
    name = fork["source_name"]
    original = manifest["package"]
    if (original["name"], original["version"], manifest["lib"]["name"]) != (
        name, fork["upstream_version"], fork["library"]
    ) or original.get("build") is not False:
        raise ValueError(f"unexpected transport package or native build declaration: {name}")
    fields = {key: original[key] for key in ("edition", "license")}
    fields.update(
        name=fork["name"], version=fork["version"], **{"rust-version": "1.100.0"},
        description=f"ExaCopy-maintained {name} transport library",
        repository=projection.REPOSITORY, build=False,
        autobins=False, autoexamples=False, autotests=False, autobenches=False,
        include=["Cargo.toml", "LICENSE*", "COPYING*", "NOTICE*", "README.md", "src/**", "EXACOPY-MODIFICATIONS.patch"],
    )
    lib = {**manifest["lib"], "test": False, "doctest": False}
    sections = [projection.table("package", fields), projection.table("lib", lib)]
    selected = {key: manifest["features"][key] for key in fork["features"]}
    if selected:
        sections.append(projection.table("features", selected))
    optional = {dep[4:] for entries in selected.values() for dep in entries if dep.startswith("dep:")}
    dependencies = set()
    for target, container in [(None, manifest), *manifest.get("target", {}).items()]:
        for kind in ("dependencies", "build-dependencies"):
            kept = {}
            for key, value in container.get(kind, {}).items():
                options = {"version": value} if isinstance(value, str) else value.copy()
                if options.get("optional") is True and key not in optional:
                    continue
                if set(options) & {"path", "git", "registry", "registry-index"}:
                    raise ValueError(f"unexpected non-registry transport dependency: {name}/{key}")
                if key == "russh-util" and name == "russh":
                    utility = forks[key]
                    if options != {"version": utility["upstream_version"]}:
                        raise ValueError("unexpected direct Russh utility edge")
                    options.update(package=utility["name"], version=f'={utility["version"]}')
                kept[key] = options
                dependencies.add(options.get("package", key))
            if kept:
                header = kind if target is None else f"target.{json.dumps(target)}.{kind}"
                sections.append(projection.table(header, kept))
    if name == "russh" and forks["russh-util"]["name"] not in dependencies:
        raise ValueError("downstream Russh must bind to the repaired utility by package identity")
    return ("\n\n".join(sections) + "\n").encode(), sorted(dependencies)


def verified_archives(root, source, work):
    # Materialize policy and patch inputs from the requested Git revision. The
    # only data read from sibling checkouts are their exact verified sources.
    selected = work / "pinned"
    for name, data in source.items():
        if not (name.endswith("Cargo.toml") or name == "Cargo.lock" or name.startswith("specs/dependencies/transport-source")):
            continue
        file = selected / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
    pins = transport_source.read_pins(selected)
    transport_source.verify_manifests(selected)
    archives = {}
    for name, pin in pins.items():
        repo = transport_source.sibling(root, name)
        git_dir = repo / ".git"
        if (not git_dir.is_dir() or git_dir.is_symlink() or
                (hasattr(git_dir, "is_junction") and git_dir.is_junction()) or repo.resolve(strict=True) != repo):
            raise ValueError(f"missing exact repaired transport Git checkout: {name}")
        archive = transport_source.immutable_archive(repo, pin["repair"])
        transport_source.verify_files(repo, archive)
        patches, license_text = transport_source.verified_inputs(selected, name, pin)
        transport_source.verify_lineage(repo, name, pin, patches, license_text)
        transport_source.verify_repaired_manifest(repo, name, pin)
        archives[name] = archive
    return pins, archives


def fork_sources(archive, fork, forks, pin, notice, commit):
    material = {file.as_posix(): data for file, data, _ in transport_source.source_files(archive)}
    if "build.rs" in material or "src/lib.rs" not in material:
        raise ValueError("unexpected transport source target inventory")
    upstream_manifest = material["Cargo.toml"]
    manifest, dependencies = fork_manifest(projection.toml(upstream_manifest), fork, forks)
    files = {file: data for file, data in material.items() if file.startswith("src/") or
             Path(file).name.startswith(("LICENSE", "COPYING", "NOTICE"))}
    transport_source.checked(files[pin["license_file"]], pin["license_sha256"], "transport license")
    transport_source.checked(notice, pin["attribution_patch_sha256"], "transport modification notices")
    source_name = fork["source_name"]
    files.update({
        "Cargo.toml": manifest,
        "EXACOPY-MODIFICATIONS.patch": notice,
        "README.md": (
            f"# {fork['name']}\n\n"
            f"Downstream Cargo package for ExaCopy’s pinned {source_name} {pin['version']} repair.\n"
            f"Upstream source: {pin['upstream_repository']}/tree/{pin['upstream_commit']}\n"
            f"ExaCopy integration: {projection.REPOSITORY}/tree/{commit}\n"
        ).encode(),
    })
    return files, {
        "name": fork["name"], "version": fork["version"], "upstream_name": source_name,
        "source_manifest_sha256": projection.digest(upstream_manifest),
        "upstream_archive_sha256": pin["registry_archive_sha256"], "upstream_commit": pin["upstream_commit"],
        "repair": pin["repair"], "repair_patch_sha256": pin["repair_patch_sha256"],
        "attribution_patch_sha256": pin["attribution_patch_sha256"], "dependencies": dependencies,
        "files_sha256": {path: projection.digest(data) for path, data in sorted(files.items())},
    }


def render_transport(root, commit, default, selected):
    policy = transport_policy(default, selected)
    forks = {fork["source_name"]: fork for fork in selected["forks"]}
    if len(forks) != len(selected["forks"]) or forks.keys() != transport_source.POLICY.keys():
        raise ValueError("transport projection requires all three admitted repaired sources")
    occupied = {package["name"].casefold() for package in policy["packages"]} | {"apfs-mounted"}
    if any(fork["name"] != f"exacopy-{name}" or fork["name"] in occupied for name, fork in forks.items()):
        raise ValueError("unexpected downstream transport package identity")
    source = projection.projection_inputs(root, commit, policy, (str(transport_source.PIN), str(transport_source.INPUTS)))
    transport_source.checked(source[transport_source.PIN.as_posix()], selected["transport_pins_sha256"], "transport pin file")
    with tempfile.TemporaryDirectory(prefix="exacopy-registry-transports-") as scratch:
        pins, archives = verified_archives(root, source, Path(scratch))
    files = projection.render(source, commit, policy, forks)
    record = json.loads(files["projection.json"])
    receipts = []
    for fork in selected["forks"]:
        name, pin = fork["source_name"], pins[fork["source_name"]]
        notice = source[(transport_source.INPUTS / pin["attribution_patch"]).as_posix()]
        staged, receipt = fork_sources(archives[name], fork, forks, pin, notice, commit)
        receipts.append(receipt)
        files.update({f"{fork['name']}/{path}": data for path, data in staged.items()})
    record.update(
        profile="transports", transport_policy_sha256=projection.fingerprint(selected), transport_forks=receipts,
        registry_publication_verified=False,
    )
    record["external_companion"]["canonical_registry_archive_required"] = True
    files["projection.json"] = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    return files


def project_transport(root, commit, destination, default):
    files = render_transport(root, commit, default, projection.toml(POLICY.read_bytes()))
    projection.write_projection(destination, files)
