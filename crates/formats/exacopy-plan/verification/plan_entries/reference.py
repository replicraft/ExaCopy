#!/usr/bin/env python3
"""Generate independent PlanEntries CBOR vectors with the portable BLAKE3 C driver."""

import argparse
from pathlib import Path
import subprocess
import sys
from uuid import UUID

BASE = Path(__file__).resolve().parent
MANIFEST_VERIFICATION = BASE.parents[2] / "exacopy-manifest/verification/manifest"
sys.path.insert(0, str(MANIFEST_VERIFICATION))
from reference import encode, parse

PAGE_DOMAIN = b"ExaCopy/document-page/v1\0"
PLAN_ENTRIES = 1


def uid(value):
    return UUID(value).bytes


def digest(executable, payload):
    output = subprocess.run(
        [executable], input=payload, capture_output=True, check=True
    ).stdout
    return bytes.fromhex(output.decode("ascii"))


def vectors(executable):
    empty_stream_digest = bytes.fromhex(
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    )
    entry = {
        0: uid("00112233-4455-4677-8899-aabbccddeeff"),
        1: {0: uid("ffeeddcc-bbaa-4988-8776-554433221100"), 1: [{0: 1, 1: b"\xff.bin"}]},
        2: {0: uid("18291f52-8015-48ff-af49-546767ec49cd"), 1: [{0: 1, 1: b"new.bin"}]},
        3: 0,
        4: uid("e57d5e90-ad55-446e-a983-4cc60a94290a"),
        5: None,
        6: None,
        7: [{0: b"", 1: 0, 2: 0, 3: empty_stream_digest}],
        8: bytes(range(32)),
        9: 0,
        10: None,
        11: 0,
    }
    for name, overrides in [
        ("empty-file", {}),
        ("observed-identity", {5: {0: 0, 1: b"v\x00", 2: b"\x80file", 3: b"g"}, 11: 4294967297}),
    ]:
        page = {0: [1, 0], 1: PLAN_ENTRIES, 2: 0, 3: [entry | overrides], 4: [], 5: 1}
        page_wire = encode(page)
        assert parse(page_wire) == page
        address = PAGE_DOMAIN + PLAN_ENTRIES.to_bytes(2, "little")
        address += len(page_wire).to_bytes(8, "little") + page_wire
        reference = {0: digest(executable, address), 1: PLAN_ENTRIES, 2: len(page_wire), 3: 1}
        reference_wire = encode(reference)
        assert parse(reference_wire) == reference
        yield name + ".page.cbor", page_wire
        yield name + ".ref.cbor", reference_wire


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash", required=True, type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    for basename, payload in vectors(args.hash.resolve()):
        path = BASE / "vectors" / basename
        if args.write:
            path.write_bytes(payload)
        assert path.read_bytes() == payload, path
        print(basename, len(payload), payload.hex())


if __name__ == "__main__":
    main()
