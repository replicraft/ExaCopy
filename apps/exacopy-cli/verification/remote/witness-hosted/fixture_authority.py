"""Issue only a one-use synthetic operation-2 record for an owned direct fixture."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from commission import BUILD_SCHEMA, HEX40, HEX64, MAX_BINARY, ROOT, held_input, path_for, read_held_bytes, stage_exact_binary, distinct_keys

sys.path.insert(0, str(ROOT / ".github" / "ci"))
sys.path.insert(0, str(ROOT / "apps" / "exacopy-cli" / "verification" / "remote"))
from remote_commissioning_authority import (
    SPKI_ED25519, independent_encoder, observed_facts, protected_write,
    stable_claim_digest,
)
from remote_commissioning_peer import Blocked, FIXTURE_ID, OPENSSL, Fixture, directory_identity, run
from remote_qualification import DIRECT, source_identity

MASK = 0x00ff_ffff
V2_DOMAIN = b"ExaCopy/linux-remote-destination-qualification/v2\0"
DIGEST_DOMAIN = b"ExaCopy/linux-remote-destination-qualification-record/v2\0"
FIXTURE_ONLY = "synthetic-witness-zero-tail-assumed-operation-2-coverage"
REPORT_LIMIT = 64 * 1024
SUBSTRATE_LIMIT = 8 * 1024 * 1024
IMAGE_DOMAIN = "ExaCopy remote running executable v1"


def parse_digest(value, pattern=HEX64):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise Blocked("invalid exact fixture selection")
    return bytes.fromhex(value)


def observed_payload(reference, destination, build, identity, scope, observed):
    native = [
        reference.identity(int(destination["device"]), int(destination["inode"])),
        destination["effective_uid"], destination["effective_gid"], bytes.fromhex(destination["boot_id_hex"]),
        int(destination["mount_namespace"]), int(destination["mount_id"]), int(destination["unique_mount"]),
        {"x86_64": 1, "aarch64": 2}[destination["architecture"]],
        *(bytes.fromhex(destination[field]) for field in (
            "kernel_release_hex", "kernel_build_hex", "mount_record_hex",
        )),
    ]
    return reference.encode({
        0: identity, 1: parse_digest(build), 2: 1, 3: scope, 4: observed, 5: native,
        6: 2, 7: 2, 8: MASK,
    })


def verify_fixture_directory(fixture):
    if (
        type(fixture) is not Fixture or not FIXTURE_ID.fullmatch(fixture.nonce)
        or fixture.root_identity != directory_identity(fixture.root, 0, 0o755)
    ):
        raise Blocked("issuer requires the closed, owned direct fixture")
    directory_identity(fixture.private, os.geteuid(), 0o700)
    directory_identity(fixture.destination, os.geteuid(), 0o700)


def make_operation_2_fixture_record(fixture, evidence, manifest, binary, b3sum, owner_key):
    """Only call from the separately reviewed fixture orchestrator after native facts."""
    verify_fixture_directory(fixture)
    parse_digest(owner_key)
    selected_tool = path_for(os.environ.get("RUNNER_TEMP")) / "exacopy-commissioning-tools"
    directory_identity(selected_tool, os.geteuid(), 0o700)
    b3sum = path_for(str(b3sum))
    if b3sum != selected_tool / "unpacked/usr/bin/b3sum":
        raise Blocked("unauthorized witness digest tool")
    tool_sha256 = os.environ.get("EXACOPY_HOSTED_WITNESS_B3SUM_SHA256")
    parse_digest(tool_sha256)
    with tempfile.TemporaryDirectory(prefix="witness-digest-tool-", dir=fixture.private) as scratch:
        exact_b3sum = Path(scratch) / "b3sum"
        stage_exact_binary(b3sum, exact_b3sum, tool_sha256, maximum=32 * 1024 * 1024)
        return issue_with_tool(fixture, evidence, manifest, binary, exact_b3sum, owner_key)


def issue_with_tool(fixture, evidence, manifest, binary, b3sum, owner_key):
    # Bind the bytes actually consumed to the facts and evidence digests.
    manifest_raw = read_held_bytes(path_for(str(manifest)), REPORT_LIMIT)
    facts_raw = read_held_bytes(path_for(str(evidence / "native-facts/facts.json")), REPORT_LIMIT)
    substrate_raw = read_held_bytes(path_for(str(evidence / "substrate/result.json")), REPORT_LIMIT)
    build, facts, substrate = [
        json.loads(raw, object_pairs_hook=distinct_keys) for raw in (manifest_raw, facts_raw, substrate_raw)
    ]
    current = source_identity(ROOT)
    if (
        build["schema"] != BUILD_SCHEMA or build["status"] != "built" or build["route"] != DIRECT
        or facts.get("observation_scope") != "exact-witness-libtest-running-image"
        or build.get("source_before") != current or build.get("source_after") != current
        or parse_digest(current["revision"], HEX40).hex() != os.environ.get("GITHUB_SHA")
        or hashlib.sha256(manifest_raw).hexdigest() != facts["build_manifest_sha256"]
        or binary.parent.resolve(strict=True) != binary.parent
        or not isinstance(build["build_size"], int) or not 0 < build["build_size"] <= MAX_BINARY
        or facts["build_blake3_derive_key"] != build["build_blake3_derive_key"]
    ):
        raise Blocked("fixture facts are outside the exact witnessed build")
    with held_input(binary, MAX_BINARY, executable=True) as (image, length):
        if length != build["build_size"] or hashlib.file_digest(image, "sha256").hexdigest() != build["build_sha256"]:
            raise Blocked("fixture executable differs from the selected build")
        image.seek(0)
        measured = subprocess.run(
            [b3sum, "--no-names", "--derive-key", IMAGE_DOMAIN], stdin=image,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20, check=True,
        ).stdout
        if not re.fullmatch(rb"[0-9a-f]{64}\n", measured) or measured.decode().strip() != facts["build_blake3_derive_key"]:
            raise Blocked("fixture executable differs from its independent build-domain observation")
    log = read_held_bytes(path_for(str(evidence / "substrate/native.log")), SUBSTRATE_LIMIT)
    destination = observed_facts(fixture, facts, substrate, current, log)
    scope = stable_claim_digest("witness-zero-tail-scope", {
        "fixture": fixture.nonce, "build": facts["build_blake3_derive_key"], "destination": destination,
        "kind": FIXTURE_ONLY, "route": DIRECT, "source": current,
    })
    antecedent = stable_claim_digest("witness-zero-tail-assumed-coverage", {
        "fixture": fixture.nonce, "kind": FIXTURE_ONLY, "production_qualification_issued": False,
        "native_facts_sha256": hashlib.sha256(facts_raw).hexdigest(),
        "substrate_result_sha256": hashlib.sha256(substrate_raw).hexdigest(),
    })
    identifier = os.urandom(16)
    if not any(identifier):
        raise Blocked("empty synthetic attestor identity")
    reference = independent_encoder()
    body = observed_payload(reference, destination, facts["build_blake3_derive_key"], identifier, scope, antecedent)

    with tempfile.TemporaryDirectory(prefix="one-use-witness-attestor-", dir=fixture.private) as scratch:
        key, message = Path(scratch) / "key.der", Path(scratch) / "message"
        protected_write(key, run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-outform", "DER"],
                                 operation="one-use witness fixture attestor generation"))
        spki = run([OPENSSL, "pkey", "-inform", "DER", "-in", key, "-pubout", "-outform", "DER"],
                   operation="one-use witness fixture public key")
        if len(spki) != len(SPKI_ED25519) + 32 or not spki.startswith(SPKI_ED25519):
            raise Blocked("invalid synthetic witness attestor encoding")
        public = spki[len(SPKI_ED25519):]
        if public == bytes.fromhex(owner_key):
            raise Blocked("synthetic attestor aliases the selected owner")
        protected_write(message, V2_DOMAIN + reference.encode([2, 1, body, public]))
        signature = run([OPENSSL, "pkeyutl", "-sign", "-rawin", "-inkey", key, "-keyform", "DER", "-in", message],
                        operation="one-use witnessed fixture signature")
        if len(signature) != 64:
            raise Blocked("invalid synthetic witness signature")
        record = reference.encode({0: 2, 1: 1, 2: body, 3: public, 4: signature})

    if not 0 < len(record) <= 3072 or source_identity(ROOT) != current:
        raise Blocked("synthetic witness record or source custody differs")
    verify_fixture_directory(fixture)
    record_path = fixture.private / "synthetic-witness-operation-2.cbor"
    record_digest = run([b3sum, "--no-names"], data=DIGEST_DOMAIN + record,
                        operation="synthetic witnessed fixture digest").decode("ascii").strip()
    parse_digest(record_digest)
    protected_write(record_path, record)
    return {
        "record": str(record_path), "attestor": identifier.hex(), "attestor_key": public.hex(),
        "campaign_scope": scope.hex(), "campaign_evidence": antecedent.hex(),
    }, {
        "kind": FIXTURE_ONLY, "coverage_assumed": True, "production_qualification_issued": False,
        "record_blake3": record_digest, "issuer_secret_removed": True,
    }
