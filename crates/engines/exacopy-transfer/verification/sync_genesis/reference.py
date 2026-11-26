#!/usr/bin/env python3
"""Independently author bounded workflow genesis fixtures using C BLAKE3 and OpenSSL."""

import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile

verification = Path(__file__).resolve().parents[4] / "formats/exacopy-plan/verification"
spec = importlib.util.spec_from_file_location("plan_fixture_reference", verification / "plan_body/reference.py")
plan_reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan_reference)
encode = plan_reference.encode

DOMAIN = b"ExaCopy/sync-baseline/"
RECORD = b"ExaCopy/workflow-record/v1\0"
PAGE = b"ExaCopy/workflow-page/v1\0"
MAX = (1 << 63) - 1
PROFILE = bytes([0x44]) * 16
EVIDENCE = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 3, 6: 2, 7: None}


class Oracle:
    def __init__(self, directory, hash_program, openssl):
        self.directory = directory
        self.hash_program = hash_program
        self.openssl = openssl
        self.keys = []
        for label in (0x51, 0x67):
            private = directory / f"fixture-{label}.der"
            private.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + bytes([label]) * 32)
            public = self.run("pkey", "-inform", "DER", "-in", private, "-pubout", "-outform", "DER")
            assert public[:12] == bytes.fromhex("302a300506032b6570032100")
            self.keys.append((private, public[12:]))

    def hash(self, data):
        run = subprocess.run([self.hash_program], input=data, capture_output=True, timeout=10, check=True)
        return bytes.fromhex(run.stdout.decode("ascii"))

    def run(self, *arguments):
        return subprocess.run([self.openssl, *arguments], capture_output=True, timeout=10, check=True).stdout

    def sign(self, kind, body, key=0, domain=RECORD):
        encoded = body if isinstance(body, bytes) else encode(body)
        message = domain + kind.to_bytes(2, "little") + encoded
        path, public = self.keys[key]
        input_file = self.directory / "message"
        input_file.write_bytes(message)
        signature = self.run("pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", path, "-in", input_file)
        return self.hash(RECORD + kind.to_bytes(2, "little") + encoded), encode({
            0: encoded, 1: public, 2: signature, 3: 32,
        })

    def digest(self, suffix, value):
        return self.hash(DOMAIN + suffix + b"\0" + encode(value))


def id_bytes(value):
    return bytes([value]) * 16


def record_id(value):
    out = bytearray(id_bytes(value))
    out[6] = 0x70
    out[8] = 0x80
    return bytes(out)


def component(name):
    return {0: 1, 1: name}


def header(kind, identifier, data, features, wide=False):
    return {0: {0: 1, 1: 0, 2: features}, 1: kind, 2: record_id(identifier),
            3: PROFILE, 4: None, 5: data, 6: ([-(1 << 63), 999_999_999] if wide else [12, 19]), 7: 1}


def reference(kind, digest, size):
    return {0: digest, 1: kind, 2: size, 3: 1}


def location(side):
    return [id_bytes(0x71), [[0, 4], 23], [[0, 4], 24], 65_536,
            [[8, 1], 70], [[8, 1], 71 + side]]


def endpoint(oracle, side, root_name, max_bytes, wide):
    return header(1, 0x81 + side, {0: id_bytes(0x21 + side), 1: 0, 2: 3, 3: None,
                  4: oracle.digest(b"local-only/v1", None), 5: id_bytes(0x31 + side),
                  6: encode(location(side)), 7: "linux-managed-local-sync-genesis-v1",
                  8: dict(EVIDENCE), 9: {0: id_bytes(0x41), 1: [component(root_name)]},
                  10: {0: max_bytes, 1: 1, 2: 1, 3: 1}, 11: None}, 1, wide)


def rooted_id(oracle, object_location):
    return oracle.digest(b"linux-object/v1", [id_bytes(0x71), *object_location])


def leaf_body(oracle, name, scope, policy, scan, roots, length, reverse):
    sides = []
    for index, root in enumerate(roots):
        file = rooted_id(oracle, [[8, 1], 80 + index])
        metadata = [0o754, 0xFFFFFFFF, 1024]
        stamp = bytes([0x30 + index]) * 32
        position = (2 - index) if reverse else (1 + index)
        sides.append({0: 2, 1: [root, file], 2: length,
                      3: oracle.digest(b"linux-owner-mode/v1", metadata),
                      4: oracle.hash(b"" if not length else b"abc"),
                      5: {0: position, 1: stamp, 2: 3 + index, 3: [root, file],
                          4: stamp, 5: 0}, 6: [], 7: metadata})
    return {0: [1, 0], 1: 256, 2: 0, 3: [{0: [component(name)], 1: sides[0],
            2: sides[1], 3: 0, 4: None, 5: {0: scope, 1: policy, 2: scan}}], 4: [], 5: 1}


def fixture(oracle, case):
    wide = case == "wide"
    max_bytes = 2 if case == "limit" else MAX
    length = 0 if case in ("empty", "empty_hash") else MAX if wide else 3
    scan = 29
    name = b"f" * 254 + b"\xff" if wide else b"subject-\xff"
    names = [bytes([65 + side]) * 254 + b"\xff" if wide else bytes([65 + side, 255])
             for side in range(2)]
    locations = [location(side) for side in range(2)]
    roots = [rooted_id(oracle, loc[-1]) for loc in locations]
    left, right = [endpoint(oracle, side, names[side], max_bytes, wide) for side in range(2)]
    if case == "endpoint_parent":
        right[5][9][0] = id_bytes(0x42)
    elif case == "endpoint_scope":
        altered = location(1)
        altered[2] = [[0, 4], 25]
        right[5][6] = encode(altered)
    elif case == "endpoint_profile":
        right[3] = id_bytes(0x55)
    elif case == "endpoint_revision":
        right[5][2] = 4
    elif case == "endpoint_evidence":
        right[5][8][6] = 0
    elif case == "endpoint_id_duplicate":
        right[2] = left[2]
    elif case == "endpoint_wrong_kind":
        right[1] = 6
    if case == "endpoint_padded_key":
        raw = encode(right)
        right = raw[:1] + b"\x18\x00" + raw[2:]
    a, b = oracle.sign(1, left), oracle.sign(1, right, key=int(case == "endpoint_key"))
    if case == "swapped_endpoints":
        a, b = b, a
    refs = [reference(1, digest, len(data)) for digest, data in (a, b)]
    if case == "duplicate_ref":
        refs[1] = dict(refs[0])
    elif case == "wrong_length":
        refs[0][2] += 1
    elif case == "wrong_count":
        refs[0][3] = 2
    elif case == "oversize_ref":
        refs[0][2] = 2049
    elif case == "wrong_ref_kind":
        refs[0][1] = 256

    filter_digest = oracle.digest(b"filter/v1", [component(name)])
    policy = oracle.digest(b"policy/v1", [0, 0, 0, 0])
    pair = oracle.digest(b"pair/v1", [PROFILE, 3, [id_bytes(0x21), id_bytes(0x31)],
                        [id_bytes(0x22), id_bytes(0x32)], filter_digest, policy])
    observed_locations = list(map(encode, locations)) if case == "scope_bstr" else locations
    scope = oracle.digest(b"scope/v1", [pair, oracle.keys[0][1], refs[0][0], refs[1][0],
                          *roots, *observed_locations])
    leaf = leaf_body(oracle, name, scope, policy, scan, roots, length, length == 0)
    row = leaf[3][0]
    if case in ("root_alias", "other_root_alias", "parent_alias"):
        identity = (roots[0] if case == "root_alias" else roots[1] if case == "other_root_alias"
                    else rooted_id(oracle, locations[0][-2]))
        row[1][1][1] = identity
        row[1][5][3][1] = identity
    elif case == "empty_hash":
        row[1][4] = row[2][4] = bytes([9]) * 32
    elif case == "leaf_scope":
        row[5][0] = bytes([9]) * 32
    elif case == "leaf_recheck":
        row[1][5][2] = 1
    encoded_leaf = encode(leaf)
    leaf_digest = oracle.hash(PAGE + (256).to_bytes(2, "little")
                              + len(encoded_leaf).to_bytes(8, "little") + encoded_leaf)
    body = header(6, 0x83, {0: pair, 1: 1, 2: None, 3: refs, 4: {0: filter_digest, 1: policy},
                  5: {0: 0, 1: 0, 2: scope, 3: scan, 4: component(name)},
                  6: [reference(256, leaf_digest, len(encoded_leaf))], 7: 1, 8: [], 9: []}, 69, wide)
    if case == "wrong_subject":
        body[5][5][4] = component(b"other")
    elif case == "root_profile":
        body[3] = id_bytes(0x55)
    elif case == "root_scan":
        body[5][5][3] += 1
    elif case == "root_filter":
        body[5][4][0] = bytes([9]) * 32
    elif case == "root_policy":
        body[5][4][1] = bytes([9]) * 32
    elif case == "coverage":
        body[5][5][1] = 4
    elif case == "root_features":
        body[0][2] |= 128
    elif case == "root_version":
        body[0][1] = 1
    elif case == "prior_record":
        body[4] = bytes([4]) * 32
    elif case == "prior_baseline":
        body[5][2] = refs[0]
    elif case == "receipt":
        body[5][8] = [refs[0]]
    elif case == "tombstone":
        body[5][9] = [refs[0]]
    elif case == "wrong_root_kind":
        body[1] = 1
    elif case == "root_padded_map":
        body = b"\xb8\x08" + encode(body)[1:]
    root_digest, root = oracle.sign(6, body, key=int(case == "foreign_root"),
                                    domain=(b"wrong\0" if case == "wrong_domain" else RECORD))
    if case == "wrong_root_digest":
        root_digest = bytes([9]) * 32
    elif case == "root_trailing":
        root += b"\x00"
    members = [a[1], b[1], encoded_leaf]
    if case == "leaf_substitution":
        members[2] = encoded_leaf[:-1] + b"\x02"
    if case == "trailing_child":
        members[0] += b"\x00"
    return [root_digest, root, *members, name, *names, max_bytes, length, pair,
            filter_digest, policy, scope, *roots, leaf_digest]


CASES = {
    **dict.fromkeys(("valid", "empty", "wide"), ("ok", 3)),
    **dict.fromkeys(("wrong_subject", "root_profile", "root_scan", "root_filter", "root_policy",
                     "scope_bstr"), ("selection", 0)),
    **dict.fromkeys(("coverage", "root_features", "root_version", "prior_record", "prior_baseline",
                     "receipt", "tombstone", "wrong_root_kind", "root_padded_map", "root_trailing",
                     "wrong_count", "wrong_ref_kind", "oversize_ref"), ("wire", 0)),
    **dict.fromkeys(("foreign_root", "wrong_domain"), ("signature", 0)),
    **dict.fromkeys(("wrong_root_digest", "duplicate_ref"), ("closure", 0)),
    **dict.fromkeys(("endpoint_parent", "endpoint_scope", "endpoint_profile", "endpoint_revision"),
                    ("selection", 2)),
    "swapped_endpoints": ("selection", 1),
    "endpoint_key": ("signature", 2),
    "endpoint_id_duplicate": ("closure", 2),
    **dict.fromkeys(("endpoint_evidence", "endpoint_wrong_kind", "endpoint_padded_key"), ("wire", 2)),
    "wrong_length": ("read", 1),
    "trailing_child": ("closure", 1),
    **dict.fromkeys(("root_alias", "other_root_alias", "parent_alias", "empty_hash", "limit"),
                    ("closure", 3)),
    **dict.fromkeys(("leaf_scope", "leaf_recheck", "leaf_substitution"), ("leaf", 3)),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hash_program", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    header_row = ("case expected resolver_calls root_digest root left right leaf subject left_name "
                  "right_name max_bytes stream_length pair filter policy scope left_root right_root leaf_digest")
    rows = [header_row.replace(" ", "\t")]
    with tempfile.TemporaryDirectory(prefix="exacopy-genesis-vectors-") as directory:
        oracle = Oracle(Path(directory), args.hash_program.resolve(), args.openssl)
        for name, result in CASES.items():
            fields = (name, *result, *fixture(oracle, name))
            rows.append("\t".join(value.hex() if isinstance(value, bytes) else str(value) for value in fields))
    args.output.write_text("\n".join(rows) + "\n", encoding="ascii")
    print(f"Wrote {len(CASES)} independent synchronization closure fixtures")


if __name__ == "__main__":
    main()
