"""Independently compare the exact post-cleanup P-063 native fixture frame."""

import csv
import hashlib
import json
import io
import os
from pathlib import Path
import re
import sys
import types
import stat
import struct
import uuid

from oracle_hash import derive, digest
from oracle_sign import OracleCleanupUnconfirmed as OracleCleanupUnconfirmed
from oracle_sign import OracleUnavailable, Signer

ROOT = Path(__file__).resolve().parents[4]
FRAME_BYTES = 65_536
REFERENCE = "crates/engines/exacopy-transfer/verification/sync_genesis/reference.py"
VECTORS = "crates/engines/exacopy-transfer/verification/sync_genesis/vectors.tsv"
PLAN_REFERENCE = "crates/formats/exacopy-plan/verification/plan_body/reference.py"
MANIFEST_REFERENCE = "crates/formats/exacopy-manifest/verification/manifest/reference.py"
PINS = {
    MANIFEST_REFERENCE: "ffb7e40b73138191a8f3fdaab1c088f86de25a0d21a2c2bb35f8c59484a1199e",
    REFERENCE: "293805803eec4c919553331c2e0dcb456e210e295a55f85f5494f7ab5f9f3d09",
    VECTORS: "86630c7b7e9504a10ffc2f511121fb88b5d6cacf9c5daf4460040689b7b2e631",
    PLAN_REFERENCE: "e75487ed8cf182f3ed7141dc77125c6670a0ef906ab233ed7300a895d250808d",
}
KEYS = frozenset((
    "version", "fixture", "anchors", "boot", "mount_namespace", "user_namespace", "ordinary_mount",
    "unique_mount", "native_live_parent", "native_profile", "native_output", "actor", "paths_hex",
    "owner", "owner_profile", "profile_revision", "operation", "enrollment", "participants",
    "subject_hex", "endpoints", "records", "creation", "scan", "live_stream_hex", "source_stamps",
    "final_stamp", "intent_stamp", "intent_hex", "members",
))
NAMES = (b"root.cbor", b"left.cbor", b"right.cbor", b"leaf.cbor")
KINDS = (6, 1, 1, 256)
SUBJECT = b"equal-subject-\xff"
ROOT_NAMES = (b"left-\xff", b"right-\xff")
STREAM = b"abc"
OPERATION, ENROLLMENT = (bytes([value]) * 16 for value in (0x61, 0x41))
PARTICIPANTS = tuple(bytes([value]) * 16 for value in (0x51, 0x52))
ENDPOINTS = tuple((bytes([endpoint]) * 16, bytes([root]) * 16, bytes([0x33]) * 16)
                  for endpoint, root in ((0x21, 0x31), (0x22, 0x32)))
TIME, SCAN, REVISION = [12, 19], 29, 3
RECORD = b"ExaCopy/workflow-record/v1\0"
PAGE = b"ExaCopy/workflow-page/v1\0"
DOMAIN = b"ExaCopy/sync-baseline/"
LOCAL = b"ExaCopy/local-sync-genesis-"
PUBLIC_ANSWER = "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a"
PROFILE_ANSWER = "56152790e0648628a21a1276965cad6a"
HASH_ANSWERS = (
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
    (3, "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"),
    (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"),
    (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"),
    (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
    (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
    (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
    (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"),
    (4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"),
)


def exact_closure(observed, expected):
    require(observed == expected, "fixture canonical genesis bytes or commitments differ")


def require(valid, message):
    if not valid:
        raise ValueError(message)


def exact_keys(obj):
    require(type(obj) is dict and obj.keys() == KEYS, "unexpected genesis frame fields")
    return obj


def object_pairs(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), "duplicate genesis JSON field")
    return result


def decimal(token):
    require(len(token) <= 21 and token != "-0", "invalid numeric field in genesis frame")
    return int(token)


def forbidden_number(_):
    raise ValueError("non-integer number in genesis frame")


def parse_frame(raw):
    require(type(raw) is bytes and 0 < len(raw) <= FRAME_BYTES,
            "genesis frame exceeds its byte bound")
    try:
        return exact_keys(json.loads(raw.decode("ascii"), object_pairs_hook=object_pairs,
                                     parse_int=decimal, parse_float=forbidden_number,
                                     parse_constant=forbidden_number))
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid genesis JSON frame") from error


def record_id(label):
    value = bytearray([label] * 16)
    value[6], value[8] = 0x70, 0x80
    return bytes(value)


RECORD_IDS = tuple(record_id(label) for label in (0x83, 0x81, 0x82))


def uint(value, bits, positive=False):
    require(type(value) is int and int(positive) <= value < 2**bits, "invalid unsigned genesis field")
    return value


def array(value, length):
    require(type(value) is list and len(value) == length, "invalid genesis array extent")
    return value


def unhex(value, extent=None, limit=4095):
    require(type(value) is str and len(value) % 2 == 0 and len(value) <= 2 * limit
            and (extent is None or len(value) == 2 * extent)
            and re.fullmatch(r"[0-9a-f]*", value) is not None, "invalid genesis hex field")
    return bytes.fromhex(value)


def object_id(raw):
    major, minor, inode = array(raw, 3)
    return [uint(major, 32), uint(minor, 32), uint(inode, 64, True)]


def native(raw):
    device, inode = array(raw, 2)
    return uint(device, 64), uint(inode, 64, True)


def tuple_id(value):
    device, inode = map(int, value.split(":"))
    return [os.major(device), os.minor(device), inode]


def checked_time(raw):
    seconds, ns = array(raw, 2)
    require(type(seconds) is int and -(1 << 63) <= seconds < 1 << 63,
            "invalid fixture native timestamp seconds")
    require(uint(ns, 32) < 1_000_000_000, "invalid fixture native timestamp fraction")
    return raw


def stamp(raw, device, actor, *, directory=False, length=None):
    dev, ino, mode, uid, gid, size, links, mtime, ctime = array(raw, 9)
    require(uint(dev, 64) == device and uint(ino, 64, True) > 0 and
            uint(mode, 32) == (stat.S_IFDIR | 0o700 if directory else stat.S_IFREG | 0o600) and
            [uint(uid, 32, True), uint(gid, 32, True)] == actor, "fixture held stamp differs")
    uint(size, 64)
    require(uint(links, 64, True) > 0 and (directory or links == 1)
            and (length is None or length == size), "fixture held stamp extent or links differ")
    checked_time(mtime)
    checked_time(ctime)
    return raw


def verify_scope(frame, expected, owner, profile):
    actor = [uint(value, 32, True) for value in array(frame["actor"], 2)]
    pid = uint(expected["pid"], 32, True)
    fixture = f"managed-sync-genesis-fixture-{pid}"
    require(frame["fixture"] == fixture and actor == list(expected["actor"]),
            "fixture basename, launch pid or actor differs")
    boot = uuid.UUID(expected["boot"]).bytes
    require(unhex(frame["boot"], 16) == boot, "managed genesis boot differs")
    for name in ("mount_namespace", "user_namespace"):
        require(object_id(frame[name]) == tuple_id(expected[name]), "genesis namespace differs")
    require(uint(frame["ordinary_mount"], 64, True) == expected["mount"]
            and uint(frame["unique_mount"], 64, True) == expected["unique_mount"], "genesis mount differs")
    require([object_id(raw) for raw in array(frame["anchors"], 2)] ==
            [tuple_id(value) for value in expected["anchors"]], "genesis ordered anchors differ")
    paths = [os.fsencode(expected["fixture_parent"]) + b"/" + fixture.encode() + b"/" + suffix
             for suffix in (b"profile", b"live", b"output")]
    require([unhex(value) for value in array(frame["paths_hex"], 3)] == paths,
            "genesis exact raw role paths differ")
    require(unhex(frame["owner"], 32) == owner and unhex(frame["owner_profile"], 16) == profile
            and unhex(frame["subject_hex"], limit=255) == SUBJECT
            and unhex(frame["operation"], 16) == OPERATION
            and unhex(frame["live_stream_hex"], len(STREAM)) == STREAM
            and uint(frame["profile_revision"], 64, True) == REVISION
            and uint(frame["scan"], 64, True) == SCAN and checked_time(frame["creation"]) == TIME
            and tuple(unhex(value, 16) for value in array(frame["records"], 3)) == RECORD_IDS,
            "genesis independently fixed fixture selection differs")
    enrollment, digest_claim = array(frame["enrollment"], 2)
    require(unhex(enrollment, 16) == ENROLLMENT and
            tuple(unhex(value, 16) for value in array(frame["participants"], 2)) == PARTICIPANTS,
            "genesis independent enrollment differs")
    return boot, paths, unhex(digest_claim, 32)


def observation_fields(frame, expected):
    actor = frame["actor"]
    native_profile = native(frame["native_profile"])
    native_output = native(frame["native_output"])
    device = native_profile[0]
    root_device = tuple_id(expected["parent"])[:2]
    require(device == int(expected["parent"].split(":", 1)[0]) and native_output[0] == device,
            "fixture profile/output are outside the exact native device")
    parent = object_id(frame["native_live_parent"])
    require(parent[:2] == root_device, "fixture live parent is outside the native device")
    roots = []
    for index, raw in enumerate(array(frame["endpoints"], 2)):
        endpoint, locator, parent_locator, name, root, ceiling = array(raw, 6)
        require(tuple(unhex(value, 16) for value in (endpoint, locator, parent_locator)) == ENDPOINTS[index]
                and unhex(name, limit=255) == ROOT_NAMES[index] and uint(ceiling, 64) == len(STREAM),
                "ordered fixture endpoint approval differs")
        root = object_id(root)
        require(root[:2] == root_device, "fixture root is outside the native device")
        roots.append(root)
    sources = [stamp(raw, device, actor, length=len(STREAM))
               for raw in array(frame["source_stamps"], 2)]
    final = stamp(frame["final_stamp"], device, actor, directory=True)
    intent = stamp(frame["intent_stamp"], device, actor, length=364)
    members, inodes = [], [parent[2], *[root[2] for root in roots], native_profile[1], native_output[1],
                           final[1], intent[1], *[entry[1] for entry in sources],
                           tuple_id(expected["parent"])[2], *[entry[2] for entry in frame["anchors"]]]
    for index, raw in enumerate(array(frame["members"], 4)):
        name, member_stamp, kind, commitment, payload = array(raw, 5)
        payload = unhex(payload, limit=2048)
        require(0 < len(payload) <= 2048 and unhex(name, limit=255) == NAMES[index]
                and uint(kind, 16) == KINDS[index], "invalid or reordered genesis member")
        inodes.append(stamp(member_stamp, device, actor, length=len(payload))[1])
        members.append((unhex(commitment, 32), payload))
    require(len(inodes) == len(set(inodes)), "fixture inode identities alias")
    require(sum(len(payload) for _, payload in members) <= 8192, "genesis closure exceeds bound")
    return native_profile, native_output, parent, roots, sources, final, members


def framed(family, role, value):
    return digest(LOCAL + family + b"/v1\0" + struct.pack("<BH", role, len(value)) + value)


def enrollment_and_approval(frame, scope, obs, root_digest):
    boot, paths, claimed = scope
    native_profile, native_output, parent, roots, _, _, _ = obs
    uid, gid = frame["actor"]
    owner = unhex(frame["owner"], 32)
    profile = unhex(frame["owner_profile"], 16)
    profile_path, live_path, output_path = [framed(b"path", index, path)
                                           for index, path in enumerate(paths, 1)]
    ns = lambda raw: struct.pack("<IIQ", *raw)
    common = (profile + owner + profile_path + struct.pack("<QQ", *native_profile) + live_path)
    output = output_path + struct.pack("<QQ", *native_output)
    enrollment = (ENROLLMENT + profile + owner + struct.pack("<Q", REVISION) + common[48:]
                  + struct.pack("<II", uid, gid) + boot + ns(frame["mount_namespace"])
                  + ns(frame["user_namespace"]) + struct.pack("<QQ", frame["ordinary_mount"], frame["unique_mount"])
                  + ns(parent) + framed(b"component", 1, SUBJECT))
    for index, root in enumerate(roots):
        enrollment += (b"".join(ENDPOINTS[index]) + framed(b"component", index + 2, ROOT_NAMES[index])
                       + ns(root) + struct.pack("<Q", len(STREAM)))
    enrollment += output + bytes([len(PARTICIPANTS)]) + b"".join(PARTICIPANTS)
    require(len(enrollment) == 529 + 16 * len(PARTICIPANTS), "independent enrollment width differs")
    enrollment_digest = digest(LOCAL + b"enrollment/v1\0" + enrollment)
    require(claimed == enrollment_digest, "fixture independently reconstructed enrollment differs")
    approval = (OPERATION + common + struct.pack("<QII", frame["ordinary_mount"], uid, gid)
                + ENROLLMENT + enrollment_digest + output + root_digest)
    require(len(approval) == 288, "independent approval width differs")
    return digest(LOCAL + b"approval/v1\0" + approval)


class Oracle:
    def __init__(self, reference, signer, prerequisites):
        self.reference = reference
        self.encode = reference["encode"]
        self.signer = signer
        self.keys = [(None, signer.public)]  # Existing independent corpus's public-key interface.
        self.hash = digest
        self.prerequisites = prerequisites
        profile = bytearray(derive(b"ExaCopy local CLI profile ID v1", signer.public)[:16])
        profile[6] = (profile[6] & 0x0F) | 0x80
        profile[8] = (profile[8] & 0x3F) | 0x80
        self.profile = bytes(profile)

    def close(self):
        self.signer.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def digest(self, suffix, value):
        return digest(DOMAIN + suffix + b"\0" + self.encode(value))

    def sign(self, kind, body, key=0, domain=RECORD):
        require(key == 0 and domain == RECORD, "unexpected independent fixture signing role")
        encoded = self.encode(body)
        message = domain + struct.pack("<H", kind) + encoded
        signature = self.signer.sign(message)
        envelope = self.encode({0: encoded, 1: self.signer.public, 2: signature, 3: 32})
        return digest(message), envelope

    def header(self, kind, identifier, body, features):
        return {0: {0: 1, 1: 0, 2: features}, 1: kind, 2: identifier,
                3: self.profile, 4: None, 5: body, 6: TIME, 7: 1}

    def closure(self, frame, boot, parent, roots, sources):
        component, reference = self.reference["component"], self.reference["reference"]
        native = lambda raw: [raw[:2], raw[2]]
        locations = [[boot, native(frame["mount_namespace"]), native(frame["user_namespace"]),
                      frame["unique_mount"], native(parent), native(root)] for root in roots]
        rooted = lambda raw: self.digest(b"linux-object/v1", [boot, *native(raw)])
        root_ids = [rooted(root) for root in roots]
        endpoint_resources = []
        for i, ((endpoint, locator, parent_locator), location) in enumerate(zip(ENDPOINTS, locations, strict=True)):
            body = {0: endpoint, 1: 0, 2: REVISION, 3: None,
                    4: self.digest(b"local-only/v1", None), 5: locator, 6: self.encode(location),
                    7: "linux-managed-local-sync-genesis-v1", 8: dict(self.reference["EVIDENCE"]),
                    9: {0: parent_locator, 1: [component(ROOT_NAMES[i])]},
                    10: {0: len(STREAM), 1: 1, 2: 1, 3: 1}, 11: None}
            endpoint_resources.append(self.sign(1, self.header(1, RECORD_IDS[i + 1], body, 1)))
        refs = [reference(1, commitment, len(member)) for commitment, member in endpoint_resources]
        filter_digest = self.digest(b"filter/v1", [component(SUBJECT)])
        policy = self.digest(b"policy/v1", [0, 0, 0, 0])
        pair = self.digest(b"pair/v1", [self.profile, REVISION, *[list(ep[:2]) for ep in ENDPOINTS],
                                        filter_digest, policy])
        scope = self.digest(b"scope/v1", [pair, self.signer.public, *[r[0] for r in refs], *root_ids, *locations])
        sides = []
        stream = digest(STREAM)
        for index, (dev, ino, mode, uid, gid, size, links, mtime, ctime) in enumerate(sources):
            file = rooted([os.major(dev), os.minor(dev), ino])
            stability = self.digest(b"linux-stability/v1", [file, size, mode, uid, gid, links, mtime, ctime])
            metadata = [mode & 0o777, uid, gid]
            identities = [root_ids[index], file]
            sides.append({0: 2, 1: identities, 2: size, 3: self.digest(b"linux-owner-mode/v1", metadata),
                          4: stream, 5: {0: index + 1, 1: stability, 2: 3, 3: identities,
                                         4: stability, 5: 0}, 6: [], 7: metadata})
        leaf = self.encode({0: [1, 0], 1: 256, 2: 0, 3: [{0: [component(SUBJECT)], 1: sides[0],
                            2: sides[1], 3: 0, 4: None, 5: {0: scope, 1: policy, 2: SCAN}}], 4: [], 5: 1})
        leaf_resource = digest(PAGE + struct.pack("<HQ", 256, len(leaf)) + leaf), leaf
        root = {0: pair, 1: 1, 2: None, 3: refs, 4: {0: filter_digest, 1: policy},
                5: {0: 0, 1: 0, 2: scope, 3: SCAN, 4: component(SUBJECT)},
                6: [reference(256, leaf_resource[0], len(leaf))], 7: 1, 8: [], 9: []}
        return [self.sign(6, self.header(6, RECORD_IDS[0], root, 69)), *endpoint_resources, leaf_resource]

    def verify_frame(self, frame, expected):
        exact_keys(frame)
        require(uint(frame["version"], 8) == 1, "unexpected genesis frame version")
        scope = verify_scope(frame, expected, self.signer.public, self.profile)
        observations = observation_fields(frame, expected)
        _, output, parent, roots, sources, final, members = observations
        closure = self.closure(frame, scope[0], parent, roots, sources)
        exact_closure(closure, members)
        root_digest, root = closure[0]
        approval = enrollment_and_approval(frame, scope, observations, root_digest)
        intent = (struct.pack("<8sHH16sQQQQ32s", b"EXSYNINT", 1, 0, OPERATION,
                              *output, *final[:2], approval)
                  + b"".join(struct.pack("<HH32s32s", kind, len(raw), commitment, digest(raw))
                             for kind, (commitment, raw) in zip(KINDS, closure, strict=True)))
        require(len(intent) == 364 and unhex(frame["intent_hex"], 364) == intent,
                "fixture independently reconstructed publication intent differs")
        return {"schema_version": 1, "outcome": "pass", "member_count": 4,
                "root_digest": root_digest.hex(), "root_sha256": hashlib.sha256(root).hexdigest(),
                "intent_sha256": hashlib.sha256(intent).hexdigest()}


def load_reference(root):
    checked = {}
    for path, expected in PINS.items():
        contents = (root / path).read_bytes()
        require(hashlib.sha256(contents).hexdigest() == expected,
                f"independent pinned genesis reference drifted: {path}")
        checked[path] = contents
    known = next(row for row in csv.DictReader(io.StringIO(checked[VECTORS].decode("ascii")),
                                               delimiter="\t") if row["case"] == "valid")
    module = types.ModuleType("reference")
    module.__file__ = str(root / MANIFEST_REFERENCE)
    exec(compile(checked[MANIFEST_REFERENCE], module.__file__, "exec"), module.__dict__)
    previous, search = sys.modules.get("reference"), sys.path[:]
    sys.modules["reference"] = module
    reference = {"__name__": "pinned_genesis_reference", "__file__": str(root / REFERENCE)}
    try:
        # The pinned historical reference loads its pinned Plan child by exact source path.
        # Only that child is reopened, under the caller's clean checkout custody.
        exec(compile(checked[REFERENCE], reference["__file__"], "exec"), reference)
        require((root / PLAN_REFERENCE).read_bytes() == checked[PLAN_REFERENCE]
                and reference["encode"].__code__.co_filename == str(root / PLAN_REFERENCE)
                and reference["encode"].__globals__.get("head") is module.head,
                "wrong deterministic CBOR reference import")
    finally:
        sys.path[:] = search
        if previous is None:
            sys.modules.pop("reference", None)
        else:
            sys.modules["reference"] = previous
    return reference, known


def checked_preflight(root, signer):
    reference, known = load_reference(root)
    oracle = Oracle(reference, signer, {"openssl_sha256": signer.sha256,
                    "openssl_version": signer.version, "reference_sha256": PINS[REFERENCE]})
    for length, expected in HASH_ANSWERS:
        data = b"abc" if length == 3 else bytes(index % 251 for index in range(length))
        require(digest(data).hex() == expected, "independent BLAKE3 known answer differs")
    require(signer.public.hex() == PUBLIC_ANSWER and oracle.profile.hex() == PROFILE_ANSWER,
            "independent fixture public key or derived profile differs")
    actual = reference["fixture"](oracle, "valid")[:5]
    frozen = [bytes.fromhex(known[key]) for key in ("root_digest", "root", "left", "right", "leaf")]
    exact_closure(actual, frozen)
    # The last byte of the fixed 64-byte signature precedes key 3 and marker 32.
    root = bytearray(frozen[1])
    require(root.endswith(b"\x03\x18\x20"), "known-answer signature location changed")
    root[-4] ^= 1
    try:
        exact_closure(actual, [frozen[0], bytes(root), *frozen[2:]])
    except ValueError:
        return oracle
    raise ValueError("independent oracle accepted the forged known-answer envelope")


def preflight():
    try:
        signer = Signer()
    except (FileNotFoundError, PermissionError) as error:
        raise OracleUnavailable("fixed independent OpenSSL executable is unavailable") from error
    try:
        return checked_preflight(ROOT, signer)
    except BaseException:
        signer.close()
        raise
