"""Reproduce bounded remote-download CBOR fixtures without the Rust codec."""

from argparse import ArgumentParser
from pathlib import Path
import subprocess
import tempfile
import textwrap

PREFIX = b"ExaCopy/owner/linux-remote-download/v1\0"
# Synthetic public fixture material, independent from any profile credential.
SEED = bytes([0x52]) * 32
PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
VERSION = [1, 0, 1]
JOB = bytes.fromhex("0123456789ab7cde8f0123456789abcd")
ENTRY = bytes([0x33]) * 16
NONCE = bytes([0x61]) * 16
CONTEXT = [bytes([0x44]) * 32, JOB, ENTRY]
EPOCHS = [2, 10]


def header(major, value):
    if value < 24:
        return bytes([major << 5 | value])
    for code, width in [(24, 1), (25, 2), (26, 4), (27, 8)]:
        if value < 256 ** width:
            return bytes([major << 5 | code]) + value.to_bytes(width, "big")
    raise ValueError("integer outside the selected CBOR profile")


def encode(value):
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return header(0, value) if value >= 0 else header(1, -1 - value)
    if isinstance(value, bytes):
        return header(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return header(3, len(raw)) + raw
    if isinstance(value, list):
        return header(4, len(value)) + b"".join(map(encode, value))
    if isinstance(value, dict):
        return header(5, len(value)) + b"".join(
            encode(key) + encode(value[key]) for key in sorted(value)
        )
    raise TypeError(type(value))


def identity(device, inode):
    return {
        0: 1,
        1: device.to_bytes(8, "little"),
        2: inode.to_bytes(8, "little"),
        3: None,
    }


def record(kind, preceding, fields):
    return encode({0: VERSION, 1: CONTEXT, 2: preceding, 3: kind, 4: fields})


def signed_owner(openssl, directory, scope):
    key = directory / "key.der"
    key.write_bytes(PKCS8_PREFIX + SEED)
    spki = subprocess.check_output(
        [openssl, "pkey", "-in", key, "-inform", "DER", "-pubout", "-outform", "DER"]
    )
    assert spki.startswith(SPKI_PREFIX) and len(spki) == len(SPKI_PREFIX) + 32
    public = spki[len(SPKI_PREFIX):]
    body = encode({
        0: VERSION,
        1: bytes([0x11]) * 16,
        2: JOB,
        3: bytes([0x22]) * 16,
        4: public,
        5: [-1, 999999999],
        6: identity(7, 11),
        7: scope,
    })
    message = directory / "message"
    message.write_bytes(PREFIX + body)
    signature = subprocess.check_output([
        openssl, "pkeyutl", "-sign", "-rawin", "-inkey", key,
        "-keyform", "DER", "-in", message,
    ])
    assert len(signature) == 64
    return encode({0: body, 1: public, 2: signature, 3: 4})


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    options = parser.parse_args()
    fixtures = Path(__file__).resolve().parents[2] / "tests" / "remote_download"
    scope = {
        0: ENTRY,
        1: [
            ["transfer.example.", 22, "Reader"],
            bytes([0x51]) * 32,
            [1, bytes([0x52]) * 32, bytes([0x53]) * 32, bytes([10, 15, 17, 19]), 22],
            b"inbox/raw-\xff",
        ],
        2: [bytes([0x54]) * 8 + bytes([0x94]) + bytes([0x54]) * 7, identity(7, 9), b"target-\xff"],
        3: [10**9, bytes([0x56]) * 32, 0],
    }
    head_1 = [1, bytes([0xA1]) * 32]
    head_2 = [2, bytes([0xA2]) * 32]
    head_3 = [3, bytes([0xA3]) * 32]
    head_4 = [4, bytes([0xA4]) * 32]
    with tempfile.TemporaryDirectory() as temporary:
        vectors = {
            "scope": encode(scope),
            "owner": signed_owner(options.openssl, Path(temporary), scope),
            "job": record(1, None, [bytes([0x55]) * 32]),
            "allocation": record(37, head_1, [[1, 9], EPOCHS, b"attempt-\xff", NONCE, [65536, 0o100644, 22]]),
            "prepared": record(2, head_2, [head_2, EPOCHS, NONCE, identity(7, 12), identity(7, 13)]),
            "checkpoint": record(3, head_3, [head_3, EPOCHS, 1, 0, 65536, bytes([0x62]) * 32]),
            "failure": record(15, head_4, [head_3, EPOCHS, 2]),
        }
        for label, vector in vectors.items():
            destination = fixtures / f"{label}.hex"
            if options.write:
                destination.write_text("\n".join(textwrap.wrap(vector.hex(), 76)) + "\n")
            assert bytes.fromhex(destination.read_text()) == vector, f"{label} vector differs"
            print(f"Independent {label} vector verified: {len(vector)} bytes")


if __name__ == "__main__":
    main()
