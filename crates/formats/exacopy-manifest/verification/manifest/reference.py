#!/usr/bin/env python3
"""Independent restricted CBOR and public-manifest v1 golden-vector recipe."""

import argparse
import base64
import json
from pathlib import Path
import subprocess
import uuid

BASE = Path(__file__).resolve().parent
DOMAIN = b"ExaCopy/manifest/v1\0"
MANIFEST_ID = "00112233-4455-4677-8899-aabbccddeeff"
ROOT_ID = "ffeeddcc-bbaa-4988-8776-554433221100"
MAX_LENGTH = (1 << 63) - 1
FILE_DIGESTS = {
    b"": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    b"abc": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
}


def hash_bytes(data):
    return subprocess.run(
        [BASE / "hash"], input=data, capture_output=True, check=True
    ).stdout.decode("ascii").strip()


def head(major, argument):
    prefix = major << 5
    if argument < 24:
        return bytes([prefix | argument])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if argument < (1 << (width * 8)):
            return bytes([prefix | info]) + argument.to_bytes(width, "big")
    raise ValueError("outside CBOR uint64")


def encode(value):
    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if type(value) is int and value >= 0:
        return head(0, value)
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
    raise ValueError(f"unsupported vector value {value!r}")


def parse(data):
    """Independent byte reader for the known fixture CBOR value types."""
    position = 0

    def take(count):
        nonlocal position
        if position + count > len(data):
            raise ValueError("truncated CBOR")
        result = data[position : position + count]
        position += count
        return result

    def item(depth):
        if depth > 16:
            raise ValueError("unexpected nested value")
        first = take(1)[0]
        major, info = first >> 5, first & 31
        if first == 0xF5:
            return True
        if first == 0xF6:
            return None
        if info < 24:
            argument = info
        elif info in (24, 25, 26, 27):
            width = 1 << (info - 24)
            argument = int.from_bytes(take(width), "big")
            if argument < {1: 24, 2: 256, 4: 65536, 8: 4294967296}[width]:
                raise ValueError("non-shortest CBOR argument")
        else:
            raise ValueError("unexpected CBOR additional information")
        if major == 0:
            return argument
        if major in (2, 3):
            raw = take(argument)
            return raw if major == 2 else raw.decode("utf-8")
        if major == 4:
            return [item(depth + 1) for _ in range(argument)]
        if major == 5:
            result = {}
            previous = b""
            for _ in range(argument):
                start = position
                key = item(depth + 1)
                raw_key = data[start:position]
                if raw_key <= previous:
                    raise ValueError("duplicate or out-of-order CBOR key")
                previous = raw_key
                result[key] = item(depth + 1)
            return result
        raise ValueError(f"unexpected CBOR major type {major}")

    value = item(0)
    if position != len(data):
        raise ValueError("trailing bytes")
    return value


def envelope_body(name, length, file_digest):
    return {
        "schema_version": "1.0",
        "manifest_id": MANIFEST_ID,
        "algorithm": "blake3-256",
        "consistency": "live_observed",
        "complete": True,
        "entries": [
            {
                "path": {
                    "root_id": ROOT_ID,
                    "components": [
                        {"encoding": "unix_bytes", "raw_base64": base64.b64encode(name).decode("ascii")}
                    ],
                },
                "file_type": "regular",
                "streams": [
                    {
                        "name_raw_base64": "",
                        "length": str(length),
                        "algorithm": "blake3-256",
                        "digest": file_digest,
                    }
                ],
                "metadata_ref": None,
            }
        ],
        "continuation_pages": [],
        "errors": [],
        "extensions": {},
    }


def project(body):
    # This is the unsigned one-inline-regular-entry subset, including exact
    # schema-defined text keys where no numeric field IDs have been allocated.
    assert body["schema_version"] == "1.0"
    assert body["complete"] is True
    assert body["algorithm"] == "blake3-256"
    assert body["consistency"] == "live_observed"
    assert body["continuation_pages"] == body["errors"] == []
    assert body["extensions"] == {}
    (entry,) = body["entries"]
    assert entry["metadata_ref"] is None and entry["file_type"] == "regular"
    (component,) = entry["path"]["components"]
    (stream,) = entry["streams"]
    assert component["encoding"] == "unix_bytes"
    assert stream["name_raw_base64"] == "" and stream["algorithm"] == "blake3-256"
    length = int(stream["length"])
    assert 0 <= length <= MAX_LENGTH
    return {
        0: [1, 0],
        1: uuid.UUID(body["manifest_id"]).bytes,
        2: 0,
        3: 0,
        4: True,
        5: [
            {
                "path": {
                    0: uuid.UUID(entry["path"]["root_id"]).bytes,
                    1: [{0: 1, 1: base64.b64decode(component["raw_base64"], validate=True)}],
                },
                "file_type": 0,
                "streams": [{0: b"", 1: length, 2: 0, 3: bytes.fromhex(stream["digest"])}],
                "metadata_ref": None,
            }
        ],
        6: [],
        7: [],
        127: {},
    }


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--vectors", type=Path, default=BASE / "vectors")
    cli.add_argument("--check-cbor", type=Path, help="directory with .canonical.cbor output from another language")
    opts = cli.parse_args()
    opts.vectors.mkdir(exist_ok=True)
    for payload, known_digest in FILE_DIGESTS.items():
        assert hash_bytes(payload) == known_digest

    cases = (
        ("empty-nonutf8", b"\xff.bin", 0, FILE_DIGESTS[b""]),
        ("embedded-nonutf8", b"prefix-\xff-suffix.bin", 3, FILE_DIGESTS[b"abc"]),
        ("max-length", b"\xff.bin", MAX_LENGTH, bytes(range(32)).hex()),
    )
    for case, raw_name, length, file_digest in cases:
        body = envelope_body(raw_name, length, file_digest)
        expected = project(body)
        encoded = encode(expected)
        parsed = parse(encoded)
        assert parsed == expected
        assert list(parsed[5][0]) == ["path", "streams", "file_type", "metadata_ref"]
        assert parsed[5][0]["path"][1][0][1] == raw_name
        assert parsed[5][0]["streams"][0][1] == length
        digest = hash_bytes(DOMAIN + encoded)
        if opts.check_cbor:
            foreign = (opts.check_cbor / f"{case}.canonical.cbor").read_bytes()
            assert foreign == encoded and parse(foreign) == expected
        (opts.vectors / f"{case}.canonical.cbor").write_bytes(encoded)
        envelope = {"body": body, "digest": digest}
        (opts.vectors / f"{case}.json").write_text(json.dumps(envelope, indent=2) + "\n")
        print(f"{case}: {len(encoded)} bytes\n{encoded.hex()}\n{digest}")
        if case == "embedded-nonutf8":
            body["entries"][0]["path"]["display"] = "informational label"
            assert encode(project(body)) == encoded
            (opts.vectors / f"{case}.display-input.json").write_text(json.dumps(envelope, indent=2) + "\n")


if __name__ == "__main__":
    main()
