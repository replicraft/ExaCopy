"""Create only the in-fixture synthetic V1 authority for the direct diagnostics."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

from native_supervision import file_digest
from remote_commissioning_peer import Blocked, OPENSSL, run
from remote_qualification import CANDIDATE_ATTRIBUTION, CandidateFactsBinding, DIRECT, EMBEDDED, REPO, source_identity

V1_DOMAIN = b"ExaCopy/linux-remote-destination-qualification/v1\0"
RECORD_DOMAIN = b"ExaCopy/linux-remote-destination-qualification-record/v1\0"
SPKI_ED25519 = bytes.fromhex("302a300506032b6570032100")
CLAIM_KIND = "synthetic-fixture-only-assumed-campaign"
HEX_DIGEST = re.compile(r"[0-9a-f]{64}")


def read_evidence(path, maximum=64 * 1024):
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    if not data or len(data) > maximum:
        raise Blocked("the internal fixture evidence exceeds its bound")
    return data


def read_json(path, maximum=64 * 1024):
    return json.loads(read_evidence(path, maximum))


def independent_encoder():
    source = REPO / "crates/storage/exacopy-journal/verification/remote_download/reference.py"
    spec = importlib.util.spec_from_file_location("commissioning_cbor_reference", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def protected_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def stable_claim_digest(label, value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(f"ExaCopy direct commissioning {label} v1\0".encode("ascii") + data).digest()


def observed_facts(fixture, facts, substrate, source, log, *, attribution="locked-cli-build"):
    from qualification_request import checked_native, substrate_closure

    value = facts["destination"]
    if (
        facts["status"] != "observed" or facts["qualifies_remote_download"] is not False
        or facts["repository_attribution"] != attribution
        or not checked_native(value)
        or not HEX_DIGEST.fullmatch(facts["build_blake3_derive_key"])
        or any(facts.get(name) != item for name, item in source.items())
        or substrate["schema"] != "ExaCopy/linux-remote-destination-substrate-diagnostic/v1"
        or substrate["outcome"] != "passed_native_substrate"
        or substrate["qualifies_remote_download"] is not False
    ):
        raise Blocked("commissioning requires unsigned exact-root component observations")
    current = fixture.destination.lstat()
    if (
        (int(value["device"]), int(value["inode"])) != (current.st_dev, current.st_ino)
        or value["effective_uid"] != os.geteuid() or value["effective_gid"] != os.getegid()
        or current.st_uid != os.geteuid()
    ):
        raise Blocked("measured root is not the created fixture destination")
    substrate_closure(substrate, facts, source, log)
    return value


def fixture_payload(reference, destination, build_digest, nonce, source, observed_hashes, *, route=DIRECT, route_revision=None):
    route_number = {DIRECT: 1, EMBEDDED: 2}[route]
    attestor = secrets.token_bytes(16)
    if not any(attestor):
        raise Blocked("empty fixture attestor identity")
    scope = stable_claim_digest("scope", {
        "fixture_id": nonce, "route": route, "source": source, "build": build_digest,
        **({"route_revision": route_revision} if route_revision is not None else {}),
        "claims_are_assumed": True, "kind": CLAIM_KIND, "destination": destination,
    })
    assumed = stable_claim_digest("antecedent", {
        "fixture_id": nonce, "kind": CLAIM_KIND,
        "compiled_cli_transfer_results_observed": False,
        "prior_authority_independently_reviewed": False,
        "component_observations": observed_hashes,
    })
    native = [
        reference.identity(int(destination["device"]), int(destination["inode"])),
        destination["effective_uid"], destination["effective_gid"], bytes.fromhex(destination["boot_id_hex"]),
        int(destination["mount_namespace"]), int(destination["mount_id"]), int(destination["unique_mount"]),
        {"x86_64": 1, "aarch64": 2}[destination["architecture"]],
        *(bytes.fromhex(destination[field]) for field in (
            "kernel_release_hex", "kernel_build_hex", "mount_record_hex",
        )),
    ]
    body = reference.encode({0: attestor, 1: bytes.fromhex(build_digest), 2: route_number, 3: scope, 4: assumed, 5: native})
    return body, {
        "schema": "exacopy-remote-qualification-trust-v1", "attestor": attestor.hex(),
        "build": build_digest, "route": route,
        "campaign_scope": scope.hex(), "campaign_evidence": assumed.hex(),
    }


def make_authority(fixture, evidence, manifest, b3sum, *, route=DIRECT, route_revision=None,
                   candidate: CandidateFactsBinding | None = None, binary: Path | None = None):
    facts_path = evidence / "native-facts/facts.json"
    substrate_path = evidence / "substrate/result.json"
    facts_bytes = read_evidence(facts_path)
    substrate_bytes = read_evidence(substrate_path)
    facts = json.loads(facts_bytes)
    substrate = json.loads(substrate_bytes)
    observed_hashes = {
        "native_facts_sha256": hashlib.sha256(facts_bytes).hexdigest(),
        "substrate_result_sha256": hashlib.sha256(substrate_bytes).hexdigest(),
    }
    if candidate is None:
        build = read_json(manifest)
        if (
            facts["repository_attribution"] != "locked-cli-build"
            or file_digest(manifest) != facts["build_manifest_sha256"] or build["route"] != route
        ):
            raise Blocked("native facts do not bind the exact fixture build")
        source = build["source_after"]
        attribution = "locked-cli-build"
    else:
        if not isinstance(candidate, CandidateFactsBinding) or candidate.route != route or binary is None:
            raise Blocked("synthetic authority requires the checked candidate binding for this campaign route")
        source = source_identity(REPO)
        imported = candidate.verify(manifest, binary, source)
        attribution = CANDIDATE_ATTRIBUTION
        if (
            facts.get("repository_attribution") != attribution or facts.get("campaign_route") != route
            or facts.get("build_manifest_sha256") != candidate.manifest_sha256
            or facts.get("elf_sha256") != imported["binary"]["sha256"]
        ):
            raise Blocked("native facts do not bind the exact frozen candidate")
        observed_hashes["candidate_manifest_sha256"] = candidate.manifest_sha256
    with (evidence / "substrate/native.log").open("rb") as stream:
        log = stream.read(8 * 1024 * 1024 + 1)
    if len(log) > 8 * 1024 * 1024:
        raise Blocked("substrate transcript exceeds its bound")
    destination = observed_facts(fixture, facts, substrate, source, log, attribution=attribution)
    reference = independent_encoder()
    body, trust = fixture_payload(
        reference, destination, facts["build_blake3_derive_key"], fixture.nonce, source, observed_hashes,
        route=route, route_revision=route_revision,
    )
    with tempfile.TemporaryDirectory(prefix="one-use-attestor-", dir=fixture.private) as scratch:
        key, message = Path(scratch) / "key.der", Path(scratch) / "message"
        protected_write(key, run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-outform", "DER"],
                                 operation="one-use attestor generation"))
        spki = run([OPENSSL, "pkey", "-inform", "DER", "-in", key, "-pubout", "-outform", "DER"],
                   operation="one-use attestor public key")
        if len(spki) != len(SPKI_ED25519) + 32 or not spki.startswith(SPKI_ED25519):
            raise Blocked("unexpected one-use attestor encoding")
        public = spki[len(SPKI_ED25519):]
        protected_write(message, V1_DOMAIN + reference.encode([1, 1, body, public]))
        signature = run(
            [OPENSSL, "pkeyutl", "-sign", "-rawin", "-inkey", key, "-keyform", "DER", "-in", message],
            operation="synthetic fixture signature",
        )
        if len(signature) != 64:
            raise Blocked("unexpected synthetic signature encoding")
        record = reference.encode({0: 1, 1: 1, 2: body, 3: public, 4: signature})

    if len(record) > 3072:
        raise Blocked("synthetic fixture record exceeds native V1 bound")
    record_path, trust_path = fixture.private / "synthetic-record", fixture.private / "synthetic-trust.json"
    protected_write(record_path, record)
    trust["attestor_key"] = public.hex()
    protected_write(trust_path, json.dumps(trust, sort_keys=True).encode("ascii"))
    digest = run([b3sum, "--no-names"], data=RECORD_DOMAIN + record,
                 operation="synthetic record digest").decode("ascii").strip()
    if not HEX_DIGEST.fullmatch(digest):
        raise Blocked("invalid synthetic record digest")
    authority = {
        "kind": CLAIM_KIND, "reviewed_attestor": False, "production_qualification_issued": False,
        "scope_digest": trust["campaign_scope"], "evidence_claim_digest": trust["campaign_evidence"],
        "record_digest": digest, "issuer_secret_removed": True,
    }
    if candidate is not None:
        authority["inputs_sha256"] = observed_hashes | {"substrate_log_sha256": substrate["log_sha256"]}
        authority["build_blake3_derive_key"] = facts["build_blake3_derive_key"]
    return record_path, trust_path, authority
