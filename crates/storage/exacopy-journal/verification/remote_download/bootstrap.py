"""Verify standalone CBOR and OpenSSL vectors for the signed bootstrap payload."""

from argparse import ArgumentParser
from pathlib import Path
import subprocess
import tempfile

from reference import ENTRY, JOB, PKCS8_PREFIX, SEED, encode, identity


DOMAIN = b"ExaCopy/linux-remote-bootstrap/v1\0"
# Frozen inputs measured from the P-043 owner and its canonical sequence-one job frame.
OWNER = bytes.fromhex("b882c2c67f3a13920dea9e3ffe1caef53d99faa0a9e463b3afca2a15e31e29ad")
JOB_HEAD = bytes.fromhex("15d48188b190bfac2f703add2fd72769991917b7f2de99a5a99003932c3e1b1f")
BODY = {
    0: OWNER,
    1: JOB,
    2: ENTRY,
    3: bytes([0x22]) * 16,
    4: [1, JOB_HEAD],
    5: identity(7, 12),
    6: 0,
}


def signed(openssl, directory, body, *, seed=SEED, domain=DOMAIN, version=1, profile=4):
    key = directory / "fixture-key.der"
    message = directory / "fixture-message"
    key.write_bytes(PKCS8_PREFIX + seed)
    message.write_bytes(domain + encode([version, profile, body]))
    signature = subprocess.check_output([
        openssl, "pkeyutl", "-sign", "-rawin", "-inkey", key,
        "-keyform", "DER", "-in", message,
    ])
    assert len(signature) == 64
    return encode({0: version, 1: profile, 2: body, 3: signature})


def vectors(openssl, directory):
    body = encode(BODY)
    valid = signed(openssl, directory, body)
    return {
        "valid": valid,
        "new-version": signed(openssl, directory, body, version=2),
        "foreign-domain": signed(openssl, directory, body, profile=3),
        "wrong-prefix": signed(openssl, directory, body, domain=b"ExaCopy/owner/linux-remote-download/v1\0"),
        "other-key": signed(openssl, directory, body, seed=bytes([0x53]) * 32),
        "changed-signature": valid[:-1] + bytes([valid[-1] ^ 1]),
        "other-owner": signed(openssl, directory, encode(BODY | {0: bytes([0x83]) * 32})),
        "other-job": signed(openssl, directory, encode(BODY | {1: JOB[:-1] + b"\xb7"})),
        "other-entry": signed(openssl, directory, encode(BODY | {2: bytes([0x81]) * 16})),
        "other-profile": signed(openssl, directory, encode(BODY | {3: bytes([0x82]) * 16})),
        "other-predecessor": signed(openssl, directory, encode(BODY | {4: [1, bytes([0x84]) * 32]})),
        "other-sequence": signed(openssl, directory, encode(BODY | {4: [2, JOB_HEAD]})),
        "foreign-device": signed(openssl, directory, encode(BODY | {5: identity(8, 12)})),
        "aliased-job": signed(openssl, directory, encode(BODY | {5: identity(7, 11)})),
        "aliased-destination": signed(openssl, directory, encode(BODY | {5: identity(7, 9)})),
        "other-role": signed(openssl, directory, encode(BODY | {6: 1})),
        "duplicate-field": signed(openssl, directory, b"\xa8" + body[1:] + b"\x06\x00"),
        "noncanonical-body": signed(openssl, directory, body[:-1] + b"\x18\x00"),
        "noncanonical-envelope": valid[:2] + b"\x18\x01" + valid[3:],
        "trailing-byte": valid + b"\x00",
    }


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    target = Path(__file__).resolve().parents[2] / "tests" / "remote_download" / "bootstrap.hex"
    with tempfile.TemporaryDirectory() as scratch:
        expected = vectors(args.openssl, Path(scratch))
    text = "".join(f"{name} {value.hex()}\n" for name, value in expected.items())
    if args.write:
        target.write_text(text, encoding="ascii")
    assert target.read_text(encoding="ascii") == text, "independent stage bootstrap vectors differ"
    print(f"Verified {len(expected)} independently encoded and signed bootstrap vectors")


if __name__ == "__main__":
    main()
