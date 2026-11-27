"""Collect unchanged legal notice bodies for exact compiled Cargo components."""

import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tomllib

import release_candidate

transport = release_candidate.transport_source
NOTICE = re.compile(
    r"^(?:licen[cs]es?|copying|copyrights?|notices?|unlicense|patents|authors|third[-_ ]party[-_ ](?:licen[cs]es?|notices?))(?:[._ -]|$)",
    re.IGNORECASE,
)
MAX_NOTICE = 4 * 1024 * 1024
MAX_ARCHIVE = 128 * 1024 * 1024
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
UPSTREAM = {
    ("delegate", "0.13.5"): ("kobzol/rust-delegate", "b129d4cbf4cc499eff7743365dcb0fe5d8d2e820", {
        "LICENSE-APACHE": "8dada3edaf50dbc082c9a125058f25def75e625a",
        "LICENSE-MIT": "688d43f92fad946c826ac49c4edf7ec280fdad66",
    }),
    ("russh-cryptovec", "0.62.0"): ("warp-tech/russh", "907c732562c5732aad6c140dba958eafddc41ba0", {
        "LICENSE.txt": "d645695673349e3947e8e5ae42332d0ac3164cd7",
    }),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def member_bytes(bundle, entry):
    if not entry.isfile() or not 0 < entry.size <= MAX_NOTICE:
        raise ValueError(f"expected bounded regular archive member: {entry.name}")
    data = bundle.extractfile(entry).read(MAX_NOTICE + 1)
    if len(data) != entry.size or b"\0" in data:
        raise ValueError(f"unexpected license member bytes: {entry.name}")
    return data


def notice_members(bundle, prefix, declared=None):
    notices = {}
    for entry in bundle:
        full = PurePosixPath(entry.name)
        if not full.is_relative_to(prefix) or full.is_absolute() or ".." in full.parts or entry.isdir():
            continue
        path = full.relative_to(prefix)
        named = path.as_posix()
        in_license_tree = any(part.casefold() in {"licenses", "licences"} for part in path.parts[:-1])
        text_file = path.suffix.casefold() in {".txt", ".md", ".rst", ""}
        if named == declared or NOTICE.match(path.name) or (in_license_tree and text_file):
            if named in notices or any(ord(character) < 32 for character in named):
                raise ValueError(f"invalid or duplicate notice path: {entry.name!r}")
            notices[named] = member_bytes(bundle, entry)
    if declared is not None and declared not in notices:
        raise ValueError(f"package omitted declared license file: {declared}")
    return notices


def registry_archive(cache, name, version, checksum):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?", version
    ):
        raise ValueError("unexpected Cargo package coordinate")
    for archive in sorted((cache / "registry/cache").glob(f"index.crates.io-*/{name}-{version}.crate")):
        if archive.is_symlink() or not archive.is_file():
            continue
        with archive.open("rb") as source:
            data = source.read(MAX_ARCHIVE + 1)
        if 0 < len(data) <= MAX_ARCHIVE and digest(data) == checksum:
            return data
    raise ValueError(f"missing exact cached registry archive for {name} {version}")


def upstream_notices(bundle, prefix, name, version):
    key = (name, version)
    if key not in UPSTREAM:
        raise ValueError(f"no embedded license or reviewed upstream notices for {name} {version}")
    repository, revision, blobs = UPSTREAM[key]
    vcs = json.loads(member_bytes(bundle, bundle.getmember(f"{prefix}/.cargo_vcs_info.json")))
    if vcs["git"].get("sha1") != revision or vcs["git"].get("dirty"):
        raise ValueError(f"upstream notice revision differs from the frozen archive: {name}")
    notices = {}
    for file, oid in sorted(blobs.items()):
        body = (Path(__file__).with_name("preview-notices") / f"{name}-{file}").read_bytes()
        header = f"blob {len(body)}\0".encode("ascii")
        if not 0 < len(body) <= MAX_NOTICE or hashlib.sha1(header + body, usedforsecurity=False).hexdigest() != oid:
            raise ValueError(f"upstream notice Git blob mismatch for {name}/{file}")
        notices[f"upstream/{file}"] = body
    return notices, f"https://github.com/{repository}/tree/{revision}"


def registry_notices(cache, name, version, checksum):
    archive = registry_archive(cache, name, version, checksum)
    prefix = f"{name}-{version}"
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        manifest = tomllib.loads(member_bytes(bundle, bundle.getmember(f"{prefix}/Cargo.toml")).decode())["package"]
        if (manifest["name"], manifest["version"]) != (name, version):
            raise ValueError("registry notice archive has unexpected package identity")
        texts = notice_members(bundle, PurePosixPath(prefix), manifest.get("license-file"))
        upstream = None
        if not texts:
            texts, upstream = upstream_notices(bundle, prefix, name, version)
    source = f"https://static.crates.io/crates/{name}/{prefix}.crate"
    return texts, source, upstream


def repair_notices(repo, name, pin):
    repair = pin["repair"]
    archive = transport.immutable_archive(transport.sibling(repo, name), repair)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        texts = notice_members(bundle, PurePosixPath("."), pin["license_file"])
    transport.checked(texts[pin["license_file"]], pin["license_sha256"], f"{name} license")
    notice = (repo / transport.INPUTS / pin["attribution_patch"]).read_bytes()
    transport.checked(notice, pin["attribution_patch_sha256"], f"{name} modification notice")
    lines = []
    source_file = None
    for line in notice.splitlines(keepends=True):
        if line.startswith(b"+++ b/"):
            source_file = line[6:]
        elif line.startswith((b"+// ", b"+# ")):
            if source_file is None:
                raise ValueError("transport notice lacks its source filename")
            lines.extend((source_file, line[1:]))
        elif line.startswith(b"+") and line.strip() != b"+":
            raise ValueError("transport attribution input contains unrelated changes")
    if not lines:
        raise ValueError(f"source change notices missing for {name}")
    texts["ExaCopy source change notices"] = b"".join(lines)
    return texts


def write_notices(output, sbom, repo, cache, source, pins):
    lock = (repo / "Cargo.lock").read_bytes()
    if digest(lock) != source["lock_sha256"]:
        raise ValueError("Cargo.lock changed before notice collection")
    packages = tomllib.loads(lock.decode())["package"]
    checksums = {(row["name"], row["version"]): row["checksum"] for row in packages if row.get("source") == REGISTRY}
    workspace = {(row["name"], row["version"]) for row in packages if "source" not in row} - {
        (name, pin["version"]) for name, pin in pins.items()
    }
    seen = set()
    with output.open("xb") as stream:
        stream.write((
            "ExaCopy Linux testing binary — third-party notices\n"
            f"Source revision: {source['revision']}\nCargo.lock SHA-256: {source['lock_sha256']}\n"
            "Inventory covers exact third-party Cargo compiler artifacts, including build inputs.\n"
            "License and notice bodies retain their original bytes.\n\n"
        ).encode())
        for component in sorted(json.loads(sbom.read_bytes())["components"], key=lambda row: row["bom-ref"]):
            name, version = component["name"], component["version"]
            ref = component["bom-ref"]
            if ref in seen:
                raise ValueError("duplicate compiled component in legal inventory")
            seen.add(ref)
            if ref == f"workspace:{name}@{version}" and (name, version) in workspace:
                continue
            if ref == f"pkg:cargo/{name}@{version}" and component.get("purl") == ref:
                checksum = checksums[name, version]
                if component["hashes"] != [{"alg": "SHA-256", "content": checksum}]:
                    raise ValueError("compiled legal inventory differs from Cargo.lock")
                bodies, url, supplement = registry_notices(cache, name, version, checksum)
            elif name in pins and ref == f"local-path:{name}@{version}#{pins[name]['repair']['commit']}":
                pin = pins[name]
                if version != pin["version"]:
                    raise ValueError("compiled repaired notice identifies a different version")
                checksum = pin["repair"]["archive_sha256"]
                url = f"{pin['upstream_repository']}/tree/{pin['upstream_commit']}"
                supplement = None
                bodies = repair_notices(repo, name, pin)
            else:
                raise ValueError(f"unrecognized third-party compiler artifact: {ref}")
            stream.write((f"{name} {version}\nSource: {url}\nSource archive SHA-256: {checksum}\n").encode())
            if supplement is not None:
                stream.write(f"Upstream notice revision: {supplement}\n".encode())
            for file, body in sorted(bodies.items()):
                stream.write(f"\n--- {file} ({len(body)} bytes, SHA-256 {digest(body)}) ---\n".encode())
                stream.write(body)
                stream.write(b"\n--- End of notice ---\n")
            stream.write(b"\n")
    for name, pin in pins.items():
        if f"local-path:{name}@{pin['version']}#{pin['repair']['commit']}" not in seen:
            raise ValueError(f"compiled legal inventory omitted repaired dependency {name}")
