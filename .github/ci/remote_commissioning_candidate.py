"""Import one exact main-push preview ELF for disposable commissioning."""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

import remote_qualification as native
from remote_commissioning_peer import Blocked
import testing_remote_asset as assets
import apfs_source
import transport_source

CANDIDATE_SCHEMA = "exacopy.linux-remote-preview-candidate.v1"
BUILD_SCHEMA = "exacopy-main-preview-build-v1"
REQUEST_SCHEMA = "exacopy-main-preview-request-v1"
WORKFLOW_REF = "replicraft/ExaCopy/.github/workflows/linux-remote-wireguard-provider-b.yml@refs/heads/main"
INPUT_ROOT = "exacopy-preview-candidate-input"
REQUEST_PATH = Path(".github/ci/remote-preview-candidate.json")
MANIFEST_NAME = "result.json"
TAG = assets.PREVIEW_TAG
VERSION = assets.PREVIEW_BASE
TARGET = assets.TARGET
FEATURES = (native.FEATURES[native.DIRECT], native.FEATURES[native.EMBEDDED])
JOBS = {native.DIRECT: "preview-direct", native.EMBEDDED: "embedded"}
ARCHIVE = f"exacopy-cli-{TAG}-{TARGET}-{FEATURES[-1]}.tar.gz"
RECEIPT = assets.PROVENANCE_NAME
SBOM = assets.SBOM_NAME
CHECKSUMS = "SHA256SUMS.txt"
LICENSE = "LICENSE"
NOTICES = assets.NOTICES_NAME
DOCUMENT_LIMIT = 128 * 1024
LICENSE_LIMIT = 64 * 1024
ELF_HEADER = 64
ELF_LIMIT = 256 * 1024 * 1024
INVENTORY = {
    ARCHIVE: ELF_LIMIT + LICENSE_LIMIT + 1024 * 1024,
    RECEIPT: DOCUMENT_LIMIT,
    SBOM: 8 * 1024 * 1024,
    CHECKSUMS: 4096,
    LICENSE: LICENSE_LIMIT,
    NOTICES: 8 * 1024 * 1024,
}
ENV_PREFIX = "EXACOPY_PREVIEW_CANDIDATE_"
ENV_MODE = ENV_PREFIX + "MODE"
ENV_FIELDS = {"ARTIFACT_ID", "ARTIFACT_DIGEST", "RECEIPT_SHA256", "ARCHIVE_SHA256", "REQUEST_SHA256"}
PREVIEW_CARGO_ARGS = (
    "cargo", native.RUST, "build", "--release", "--offline", "--locked", "--no-default-features",
    "-p", "exacopy-cli", "--bin", "exacopy", "--features", FEATURES[-1],
    "--message-format=json-render-diagnostics",
)
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


def hex_id(value, width=64):
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{width}}}", value) is not None


def decimal_id(value):
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_json(data):
    def invalid_constant(_):
        raise ValueError("nonfinite JSON constant")

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=native.closed_object,
                           parse_constant=invalid_constant)
    except (ValueError, RecursionError) as error:
        raise Blocked("candidate metadata is not a valid closed JSON object") from error
    if not isinstance(value, dict):
        raise Blocked("candidate metadata requires a JSON object")
    return value


def require_directory(path, *, private=False):
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise Blocked("candidate requires a canonical directory")
    details = path.lstat()
    if (
        not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid()
        or details.st_mode & 0o022 or (private and stat.S_IMODE(details.st_mode) != 0o700)
    ):
        raise Blocked("candidate directory is outside its owner scope")
    return native.file_observation(details)


def regular_observation(path, maximum, mode=None):
    details = path.lstat()
    if (
        not stat.S_ISREG(details.st_mode) or details.st_nlink != 1
        or details.st_uid != os.geteuid() or details.st_mode & 0o022
        or not 0 < details.st_size <= maximum
        or (mode is not None and stat.S_IMODE(details.st_mode) != mode)
    ):
        raise Blocked("candidate file is outside its allowed identity or extent")
    return native.file_observation(details)


@contextmanager
def held_reader(path, maximum, identity):
    descriptor = os.open(path, READ_FLAGS)
    with os.fdopen(descriptor, "rb") as stream:
        if native.file_observation(os.fstat(stream.fileno())) != identity:
            raise Blocked("candidate file changed before its bounded read")
        yield stream
        if (
            native.file_observation(os.fstat(stream.fileno())) != identity
            or regular_observation(path, maximum) != identity
        ):
            raise Blocked("candidate file changed during its bounded read")


def read_checked(path, maximum, identity, *, prefix=None):
    with held_reader(path, maximum, identity) as stream:
        opened_size = os.fstat(stream.fileno()).st_size
        size = opened_size if prefix is None else min(prefix, opened_size)
        data = stream.read(maximum + 1 if prefix is None else size)
        if len(data) != size:
            raise Blocked("candidate file changed during its bounded read")
    return data


def read_regular(path, maximum):
    return read_checked(path, maximum, regular_observation(path, maximum))


@dataclass(frozen=True)
class CandidateRequest:
    root: Path
    route: str
    revision: str
    run_id: str
    run_attempt: str
    artifact_id: str
    artifact_digest: str
    receipt_sha256: str
    archive_sha256: str
    request_sha256: str

    @classmethod
    def from_hosted_environment(cls, parent: Path, *, route: str):
        env = os.environ
        present = {name.removeprefix(ENV_PREFIX) for name in env if name.startswith(ENV_PREFIX)}
        job = env.get("GITHUB_JOB")
        if not present:
            if job == JOBS[native.DIRECT] or (
                env.get("GITHUB_WORKFLOW_REF") == WORKFLOW_REF and job == JOBS[native.EMBEDDED]
            ):
                raise Blocked("this hosted campaign has no admitted candidate mode")
            return None
        mode = env.get(ENV_MODE)
        if mode == "not-requested":
            if route != native.EMBEDDED or present != {"MODE"}:
                raise Blocked("the ordinary provider-B campaign requires its sole not-requested mode")
        elif mode != "requested" or present != ENV_FIELDS | {"MODE"}:
            raise Blocked("candidate import requires the complete exact artifact binding")
        revision = env.get("GITHUB_SHA")
        run_id, attempt = env.get("GITHUB_RUN_ID"), env.get("GITHUB_RUN_ATTEMPT")
        if (
            route not in JOBS or sys.platform != "linux" or os.geteuid() == 0
            or os.getuid() != os.geteuid() or os.getegid() != os.getgid()
            or env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or env.get("RUNNER_OS") != "Linux" or env.get("RUNNER_ARCH") != "X64"
            or env.get("GITHUB_SERVER_URL") != "https://github.com"
            or env.get("GITHUB_REPOSITORY", "").lower() != "replicraft/exacopy"
            or env.get("GITHUB_REF") != "refs/heads/main" or env.get("GITHUB_EVENT_NAME") != "push"
            or env.get("GITHUB_WORKFLOW_REF") != WORKFLOW_REF or env.get("GITHUB_WORKFLOW_SHA") != revision
            or job != JOBS[route] or "EXACOPY_REMOTE_DEPLOYMENT" in env
            or not hex_id(revision, 40) or not decimal_id(run_id) or not decimal_id(attempt)
            or env.get("RUNNER_TEMP") != os.fspath(parent) or parent.is_relative_to(native.REPO)
        ):
            raise Blocked("preview candidate requires its exact hosted main push job")
        require_directory(parent)
        if mode == "not-requested":
            return None
        if attempt != "1":
            raise Blocked("the preview candidate requires its first hosted run attempt")
        values = {field: env[ENV_PREFIX + field] for field in ENV_FIELDS}
        if not decimal_id(values["ARTIFACT_ID"]) or any(
            not hex_id(values[key]) for key in ENV_FIELDS - {"ARTIFACT_ID"}
        ):
            raise Blocked("candidate artifact identity is malformed")
        return cls(parent / INPUT_ROOT, route, revision, run_id, attempt,
                   **{key.lower(): value for key, value in values.items()})

    def workflow(self):
        return {
            "ref": WORKFLOW_REF, "sha": self.revision,
            "run_id": self.run_id, "run_attempt": self.run_attempt,
        }

    def transport(self):
        return {
            "artifact_id": self.artifact_id, "artifact_digest": self.artifact_digest,
            "receipt_sha256": self.receipt_sha256, "request_sha256": self.request_sha256,
            "workflow": self.workflow(),
        }


def observe_inputs(root):
    directory = require_directory(root, private=True)
    names = set()
    with os.scandir(root) as entries:
        for entry in entries:
            if entry.name not in INVENTORY:
                raise Blocked("candidate download contains an unexpected member")
            names.add(entry.name)
    if names != INVENTORY.keys():
        raise Blocked("candidate download has an incomplete file inventory")
    files = {name: regular_observation(root / name, bound) for name, bound in INVENTORY.items()}
    if require_directory(root, private=True) != directory:
        raise Blocked("candidate directory changed during observation")
    return directory, files


def validate_source(source):
    if (
        not isinstance(source, dict) or set(source) != {"revision", "git_tree", "lock_sha256"}
        or not hex_id(source["revision"], 40) or not hex_id(source["git_tree"], 40)
        or not hex_id(source["lock_sha256"])
    ):
        raise Blocked("candidate source identity is malformed")


def validate_intent(request, source):
    validate_source(source)
    raw = read_regular(native.REPO / REQUEST_PATH, 2048)
    intent = read_json(raw)
    expected = {
        "schema": REQUEST_SCHEMA, "intended_tag": TAG, "workspace_version": VERSION,
        "target": TARGET, "feature": FEATURES[-1],
    }
    if (
        source["revision"] != request.revision or request.run_attempt != "1"
        or sha256(raw) != request.request_sha256
        or intent != expected | {"nonce": intent.get("nonce")} or not hex_id(intent.get("nonce"), 32)
    ):
        raise Blocked("candidate intent differs from the committed exact preview request")


def validate_record(record, name, minimum, maximum):
    if (
        not isinstance(record, dict) or set(record) != {"name", "size", "sha256"}
        or record["name"] != name or not hex_id(record["sha256"])
        or type(record["size"]) is not int or not minimum <= record["size"] <= maximum
    ):
        raise Blocked("candidate binary or archive record is malformed")


def validate_receipt(receipt, request, source):
    fixed = {
        "schema": BUILD_SCHEMA, "intended_tag": TAG, "workspace_version": VERSION,
        "target": TARGET, "source": source, "workflow": request.workflow(),
        "scope": "unsigned Linux x86-64 user-testing archive", "rust_toolchain": native.RUST.removeprefix("+"),
        "cargo_args": list(PREVIEW_CARGO_ARGS),
        "request_sha256": request.request_sha256, "compiled_features": list(FEATURES),
        "apfs_source": apfs_source.read_pin((native.REPO / apfs_source.PIN).read_text(encoding="utf-8")),
        "transport_sources": transport_source.read_pins(native.REPO), "exact_elf_campaigns": "pending",
    }
    digests = {"build_receipt_sha256", "cargo_messages_sha256", "sbom_sha256", "notices_sha256"}
    if (
        set(receipt) != fixed.keys() | digests | {"binary", "archive", "abi"}
        or any(receipt[key] != value for key, value in fixed.items())
        or any(not hex_id(receipt[key]) for key in digests)
    ):
        raise Blocked("candidate producer provenance differs from the revision, tool inputs or run")
    abi = receipt["abi"]
    if (
        not isinstance(abi, dict) or set(abi) != {"host_glibc", "highest_imported_glibc"}
        or abi["host_glibc"] != "glibc 2.35" or not isinstance(abi["highest_imported_glibc"], str)
        or not re.fullmatch(r"2\.(?:[0-9]|[1-3][0-9])", abi["highest_imported_glibc"])
        or int(abi["highest_imported_glibc"].split(".")[1]) > 35
    ):
        raise Blocked("candidate producer ABI differs from the preview floor")
    validate_record(receipt["binary"], "exacopy", ELF_HEADER, ELF_LIMIT)
    validate_record(receipt["archive"], ARCHIVE, 1, INVENTORY[ARCHIVE])
    if receipt["archive"]["sha256"] != request.archive_sha256:
        raise Blocked("candidate archive digest differs from the admitted download")


def archive_observation(identity):
    device, inode, mode, links, uid, size, modified, changed = identity
    return {
        "device": device, "inode": inode, "mode": stat.S_IMODE(mode), "link_count": links,
        "uid": uid, "size": size, "modified_ns": modified, "changed_ns": changed,
    }


def validate_archive_observation(observed, size):
    fields = {"device", "inode", "mode", "link_count", "uid", "size", "modified_ns", "changed_ns"}
    if (
        not isinstance(observed, dict) or set(observed) != fields
        or any(type(observed[key]) is not int for key in fields)
        or observed["device"] < 0 or observed["inode"] <= 0
        or not 0 <= observed["mode"] <= 0o777 or observed["mode"] & 0o022
        or observed["link_count"] != 1 or observed["uid"] != os.geteuid() or observed["size"] != size
    ):
        raise Blocked("candidate manifest has an invalid archive observation")


def validate_elf(header):
    if (
        len(header) < ELF_HEADER or header[:7] != b"\x7fELF\x02\x01\x01" or header[7] not in (0, 3)
        or int.from_bytes(header[16:18], "little") not in (2, 3)
        or struct.unpack_from("<HI", header, 18) != (62, 1)
        or int.from_bytes(header[52:54], "little") != ELF_HEADER
    ):
        raise Blocked("candidate requires a Linux x86-64 little-endian ELF executable")


def check_auxiliary(read, receipt, request, license_bytes):
    sbom = read(SBOM)
    notices = read(NOTICES)
    if sha256(sbom) != receipt["sbom_sha256"] or sha256(notices) != receipt["notices_sha256"]:
        raise Blocked("candidate legal assets differ from the producer provenance")
    metadata = read_json(sbom)
    if metadata.get("bomFormat") != "CycloneDX" or metadata.get("specVersion") != "1.6":
        raise Blocked("candidate SBOM differs from the producer's CycloneDX format")
    expected = {
        ARCHIVE: request.archive_sha256,
        RECEIPT: request.receipt_sha256,
        SBOM: receipt["sbom_sha256"],
        LICENSE: sha256(license_bytes),
        NOTICES: receipt["notices_sha256"],
    }
    lines = read(CHECKSUMS).splitlines(keepends=True)
    if len(lines) != len(expected) or set(lines) != {
        f"{digest}  {name}\n".encode("ascii") for name, digest in expected.items()
    }:
        raise Blocked("candidate checksum inventory disagrees with the exact asset bytes")


def staged_observation(path):
    if path.name != "exacopy":
        raise Blocked("candidate executable is outside its fixed staged name")
    directory = require_directory(path.parent, private=True)
    identity = regular_observation(path, ELF_LIMIT, 0o500)
    validate_elf(read_checked(path, ELF_LIMIT, identity, prefix=ELF_HEADER))
    observed = native.executable_observation(path)
    if require_directory(path.parent, private=True) != directory or (
        regular_observation(path, ELF_LIMIT, 0o500) != identity
    ):
        raise Blocked("candidate executable changed during observation")
    return observed


def exclusive_write(path, data, mode):
    descriptor = os.open(path, CREATE_FLAGS, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        if stream.write(data) != len(data):
            raise Blocked("candidate stage write was incomplete")
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        created = native.file_observation(os.fstat(stream.fileno()))
    if regular_observation(path, len(data), mode) != created:
        raise Blocked("candidate stage lost its exclusive file identity")
    return created


def verify_staged_candidate(manifest, binary, expected_digest, route, source):
    validate_source(source)
    if route not in JOBS or not hex_id(expected_digest) or manifest.name != MANIFEST_NAME:
        raise Blocked("candidate manifest requires a fixed route, identity and staged name")
    directory = require_directory(manifest.parent, private=True)
    identity = regular_observation(manifest, DOCUMENT_LIMIT, 0o400)
    raw = read_checked(manifest, DOCUMENT_LIMIT, identity)
    if sha256(raw) != expected_digest:
        raise Blocked("candidate manifest differs from the parent-known digest")
    report = read_json(raw)
    fixed = {
        "schema": CANDIDATE_SCHEMA, "status": "imported", "campaign_route": route,
        "producer_route": native.EMBEDDED, "source": source, "compiled_features": list(FEATURES),
    }
    if (
        set(report) != fixed.keys() | {"transport", "archive", "archive_observation", "binary", "staged_executable"}
        or any(report[key] != value for key, value in fixed.items())
    ):
        raise Blocked("candidate manifest differs from the admitted route or source")
    validate_record(report["binary"], "exacopy", ELF_HEADER, ELF_LIMIT)
    validate_record(report["archive"], ARCHIVE, 1, INVENTORY[ARCHIVE])
    validate_archive_observation(report["archive_observation"], report["archive"]["size"])
    transport = report["transport"]
    if (
        not isinstance(transport, dict)
        or set(transport) != {"artifact_id", "artifact_digest", "receipt_sha256", "request_sha256", "workflow"}
        or not decimal_id(transport["artifact_id"])
        or any(not hex_id(transport[key]) for key in ("artifact_digest", "receipt_sha256", "request_sha256"))
    ):
        raise Blocked("candidate manifest has an invalid artifact transport binding")
    workflow = transport["workflow"]
    if (
        not isinstance(workflow, dict) or set(workflow) != {"ref", "sha", "run_id", "run_attempt"}
        or workflow["ref"] != WORKFLOW_REF or workflow["sha"] != source["revision"]
        or not decimal_id(workflow["run_id"]) or workflow["run_attempt"] != "1"
    ):
        raise Blocked("candidate manifest has an invalid workflow binding")
    observed = staged_observation(binary)
    if (
        observed != report["staged_executable"]
        or (observed["size"], observed["sha256"]) != (report["binary"]["size"], report["binary"]["sha256"])
        or require_directory(manifest.parent, private=True) != directory
        or regular_observation(manifest, DOCUMENT_LIMIT, 0o400) != identity
    ):
        raise Blocked("candidate executable or manifest custody changed")
    return report


@dataclass(frozen=True)
class FrozenCandidate:
    binary: Path
    manifest: Path
    report: dict
    digest: str
    _request: CandidateRequest
    _source: dict
    _inputs: tuple
    _manifest_identity: tuple

    def verify(self):
        if (
            observe_inputs(self._request.root) != self._inputs
            or regular_observation(self.manifest, DOCUMENT_LIMIT, 0o400) != self._manifest_identity
            or verify_staged_candidate(
                self.manifest, self.binary, self.digest, self._request.route, self._source,
            ) != self.report
            or observe_inputs(self._request.root) != self._inputs
        ):
            raise Blocked("candidate input or staged custody changed during commissioning")

    def verify_archive(self):
        """Rehash the held download after commissioning, along with recurring custody checks."""
        hasher = hashlib.sha256()
        path = self._request.root / ARCHIVE
        with held_reader(path, INVENTORY[ARCHIVE], self._inputs[1][ARCHIVE]) as stream:
            remaining = os.fstat(stream.fileno()).st_size
            while remaining:
                chunk = stream.read(min(remaining, 64 * 1024))
                if not chunk:
                    raise Blocked("candidate archive ended before its held extent")
                hasher.update(chunk)
                remaining -= len(chunk)
            if stream.read(1) or hasher.hexdigest() != self._request.archive_sha256:
                raise Blocked("candidate archive digest changed during commissioning")
        self.verify()


def import_candidate(request, evidence, staged, route, source):
    if route not in JOBS or route != request.route or request.root.name != INPUT_ROOT:
        raise Blocked("candidate transport was established for a different campaign route")
    validate_intent(request, source)
    observed = observe_inputs(request.root)
    _, files = observed

    def read(name):
        return read_checked(request.root / name, INVENTORY[name], files[name])

    raw_receipt = read(RECEIPT)
    if sha256(raw_receipt) != request.receipt_sha256:
        raise Blocked("candidate producer receipt differs from the admitted download")
    receipt = read_json(raw_receipt)
    validate_receipt(receipt, request, source)
    license_bytes = read(LICENSE)
    if license_bytes != read_regular(native.REPO / LICENSE, INVENTORY[LICENSE]):
        raise Blocked("candidate license differs from the committed license")
    check_auxiliary(read, receipt, request, license_bytes)
    path = request.root / ARCHIVE
    with held_reader(path, INVENTORY[ARCHIVE], files[ARCHIVE]):
        archive, elf = assets.read_archive(path, receipt["binary"]["size"], license_bytes)
    validate_elf(elf)
    if archive != receipt["archive"] or (
        len(elf), sha256(elf)
    ) != (receipt["binary"]["size"], receipt["binary"]["sha256"]):
        raise Blocked("candidate archive or ELF differs from the producer receipt")
    if observe_inputs(request.root) != observed:
        raise Blocked("candidate download changed during import")

    if staged.name != "exacopy":
        raise Blocked("candidate executable is outside its fixed staged name")
    require_directory(staged.parent, private=True)
    require_directory(evidence.parent, private=True)
    evidence.mkdir(mode=0o700)
    require_directory(evidence, private=True)
    created = exclusive_write(staged, elf, 0o500)
    selected = staged_observation(staged)
    if regular_observation(staged, ELF_LIMIT, 0o500) != created:
        raise Blocked("candidate executable changed after the private write")
    manifest = evidence / MANIFEST_NAME
    report = {
        "schema": CANDIDATE_SCHEMA, "status": "imported",
        "campaign_route": route, "producer_route": native.EMBEDDED, "source": source.copy(),
        "transport": request.transport(), "archive": archive,
        "archive_observation": archive_observation(files[ARCHIVE]), "binary": receipt["binary"],
        "compiled_features": list(FEATURES), "staged_executable": selected,
    }
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    manifest_identity = exclusive_write(manifest, raw, 0o400)
    result = FrozenCandidate(staged, manifest, report, sha256(raw), request, source.copy(), observed, manifest_identity)
    result.verify()
    return result
