#!/usr/bin/env python3
"""Independent canonical public Plan body fixtures using portable BLAKE3 C."""

import argparse
from pathlib import Path
import subprocess
import sys
from uuid import UUID

BASE = Path(__file__).resolve().parent
MANIFEST_VERIFICATION = BASE.parents[2] / "exacopy-manifest/verification/manifest"
sys.path.insert(0, str(MANIFEST_VERIFICATION))
from reference import head, parse as parse_page_ref

PLAN_DOMAIN = b"ExaCopy/plan/v1\0"
PAGE_DOMAIN = b"ExaCopy/document-page/v1\0"
PLAN_ENTRIES = 1


def encode(value):
    if value is None:
        return b"\xf6"
    if type(value) is bool:
        return b"\xf5" if value else b"\xf4"
    if type(value) is int:
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if type(value) is bytes:
        return head(2, len(value)) + value
    if type(value) is str:
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if type(value) is list:
        return head(4, len(value)) + b"".join(map(encode, value))
    if type(value) is dict:
        entries = sorted((encode(key), encode(item)) for key, item in value.items())
        return head(5, len(entries)) + b"".join(key + item for key, item in entries)
    raise ValueError(type(value))


def decode(payload):
    def take(start, count):
        end = start + count
        assert end <= len(payload)
        return payload[start:end], end

    def item(offset):
        (marker,), offset = take(offset, 1)
        if marker in (0xf4, 0xf5, 0xf6):
            return {0xf4: False, 0xf5: True, 0xf6: None}[marker], offset
        kind, width = divmod(marker, 32)
        if width < 24:
            arg = width
        else:
            assert 24 <= width <= 27
            data, offset = take(offset, 1 << (width - 24))
            arg = int.from_bytes(data, "big")
            assert len(head(kind, arg)) == len(data) + 1
        if kind == 0:
            return arg, offset
        if kind == 1:
            return -1 - arg, offset
        if kind in (2, 3):
            data, offset = take(offset, arg)
            return (data if kind == 2 else data.decode("utf-8")), offset
        if kind == 4:
            values = []
            for _ in range(arg):
                value, offset = item(offset)
                values.append(value)
            return values, offset
        assert kind == 5
        result = {}
        previous = b""
        for _ in range(arg):
            key_start = offset
            key, offset = item(offset)
            raw_key = payload[key_start:offset]
            assert previous < raw_key
            previous = raw_key
            result[key], offset = item(offset)
        return result, offset

    decoded, end = item(0)
    assert end == len(payload)
    return decoded


def uid(s):
    return UUID(s).bytes


def bodies(refs):
    source = uid("ffeeddcc-bbaa-4988-8776-554433221100")
    destination = uid("18291f52-8015-48ff-af49-546767ec49cd")
    view = uid("e57d5e90-ad55-446e-a983-4cc60a94290a")
    view_two = uid("e57d5e90-ad55-446e-a983-4cc60a94290b")
    measurement = uid("00112233-4455-4677-8899-aabbccddeeff")
    plan = {
        0: [1, 0],
        1: uid("019a0000-0000-7000-8000-000000000002"),
        2: 1,
        3: [-(1 << 63), 999_999_999],
        4: [(1 << 63) - 1, 0],
        5: [source],
        6: destination,
        7: refs,
        8: {0: 2, 1: 3, 2: 1, 3: 1, 4: 1, 5: 4, 6: 1, 7: 2, 8: 1, 9: False},
        9: {0: (1 << 64) - 1, 1: 64},
        10: True,
        11: [
            {
                0: view, 1: source, 2: 3, 3: "observation-é-e\u0301",
                4: measurement, 5: {0: 2, 1: b"v\x00", 2: b"\xffobj", 3: b"g"},
                6: [-1, 42], 7: bytes(range(32)), 8: [1, 0],
            },
            {
                0: view_two, 1: source, 2: 0, 3: "live-observation",
                4: measurement, 5: None, 6: [0, 0], 7: None, 8: None,
            },
        ],
        12: ["read-content", "create-new", "prése\u0301rve"],
        13: 3,
        14: 0,
        15: 2,
        16: True,
        127: {
            "org.exacopy": {"z": [None, False, True, -(1 << 64), (1 << 64)-1], "long": "é"},
            "z.test": None,
        },
    }
    yield "complete-protected", plan
    yield "incomplete-empty", plan | {
        2: 6, 3: [0, 0], 4: None, 5: [], 7: [], 8: {i: 0 for i in range(9)} | {9: False},
        9: {0: 0, 1: 1}, 10: False, 11: [], 12: [], 13: 0, 14: 0, 15: 0, 16: False, 127: {},
    }



def digest(executable, payload):
    hashed = subprocess.run([executable], input=payload, capture_output=True, check=True)
    return bytes.fromhex(hashed.stdout.decode("ascii"))


def page_ref(executable, canonical_page):
    frame = PAGE_DOMAIN + PLAN_ENTRIES.to_bytes(2, "little")
    frame += len(canonical_page).to_bytes(8, "little") + canonical_page
    return {0: digest(executable, frame), 1: PLAN_ENTRIES, 2: len(canonical_page), 3: 1}


def coherent_fixture_bundle(executable):
    original = BASE.parent / "plan_entries/vectors"
    first_page = (original / "empty-file.page.cbor").read_bytes()
    first_ref = parse_page_ref((original / "empty-file.ref.cbor").read_bytes())
    assert page_ref(executable, first_page) == first_ref

    first_entry = decode(first_page)[3][0]
    second_entry = {
        0: uid("00112233-4455-4677-8899-aabbccddeefe"),
        1: {0: first_entry[1][0], 1: [{0: 1, 1: b"\xfe-alternate.bin"}]},
        2: {0: first_entry[2][0], 1: [{0: 1, 1: b"new-2.bin"}]},
        3: 0,
        4: uid("e57d5e90-ad55-446e-a983-4cc60a94290b"),
        5: None,
        6: None,
        7: [{
            0: b"", 1: 3, 2: 0,
            3: bytes.fromhex("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"),
        }],
        8: first_entry[8],
        9: 0,
        10: None,
        11: 3,
    }
    for key in (0, 1, 2, 4):
        assert first_entry[key] != second_entry[key]
    second_page = {0: [1, 0], 1: PLAN_ENTRIES, 2: 0, 3: [second_entry], 4: [], 5: 1}
    second_canonical = encode(second_page)
    assert decode(second_canonical) == second_page
    second_ref = page_ref(executable, second_canonical)
    return [first_entry, second_entry], [first_ref, second_ref], second_canonical


def emit(path, payload, write):
    if write:
        path.write_bytes(payload)
    assert path.read_bytes() == payload, path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash", required=True, type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    executable = args.hash.resolve()
    entries, references, second_page = coherent_fixture_bundle(executable)
    directory = BASE / "vectors"
    emit(directory / "coherent-second.page.cbor", second_page, args.write)
    emit(directory / "coherent-second.ref.cbor", encode(references[1]), args.write)
    for name, value in bodies(references):
        canonical = encode(value)
        assert decode(canonical) == value
        if value[16]:
            views = {view[0]: view for view in value[11]}
            for entry in entries:
                assert entry[1][0] in value[5] and entry[2][0] == value[6]
                assert views[entry[4]][1] == entry[1][0]
            assert sum(ref[3] for ref in references) == value[15]
            assert sum(entry[11] for entry in entries) == value[13]
            assert sum(entry[10] is not None for entry in entries) == value[14]
        plan_digest = digest(executable, PLAN_DOMAIN + canonical)
        for suffix, content in [
            ("body.cbor", canonical), ("digest", plan_digest), ("extensions.cbor", encode(value[127])),
        ]:
            emit(directory / f"{name}.{suffix}", content, args.write)
        print(name, len(canonical), plan_digest.hex())


if __name__ == "__main__":
    main()
