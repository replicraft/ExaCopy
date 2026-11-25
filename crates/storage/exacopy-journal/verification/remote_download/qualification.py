"""Generate synthetic qualification vectors using independent CBOR and OpenSSL."""

from argparse import ArgumentParser
from pathlib import Path
import subprocess
import tempfile

from reference import PKCS8_PREFIX, SPKI_PREFIX, encode, identity


DOMAIN = b"ExaCopy/linux-remote-destination-qualification/v1\0"
ATTESTOR_SEED = bytes([0x62]) * 32
OWNER_SEED = bytes([0x52]) * 32
DIRECT = 1
EMBEDDED = 2
FACTS = [
    identity(0x801, 11), 1001, 1002, bytes([0x15]) * 16, 4026533000, 36, 59426,
    1, b"6.8.0-fixture", b"#1 fixture SMP", b"36 25 8:1 / /fixture rw,nosuid - ext4 /dev/fixture rw",
]
CLAIMS = {
    0: bytes([0x31]) * 16, 1: bytes([0x61]) * 32, 2: DIRECT,
    3: bytes([0x63]) * 32, 4: bytes([0x64]) * 32, 5: FACTS,
}


class Signer:
    def __init__(self, openssl, directory, seed):
        self.openssl = openssl
        self.key = directory / f"synthetic-{seed[0]:02x}.der"
        self.key.write_bytes(PKCS8_PREFIX + seed)
        self.input = directory / "synthetic-input"
        key = subprocess.check_output(
            [openssl, "pkey", "-in", self.key, "-inform", "DER", "-pubout", "-outform", "DER"]
        )
        assert key.startswith(SPKI_PREFIX) and len(key) == len(SPKI_PREFIX) + 32
        self.public_key = key[len(SPKI_PREFIX):]

    def record(self, body, *, version=1, role=1, domain=DOMAIN):
        self.input.write_bytes(domain + encode([version, role, body, self.public_key]))
        signature = subprocess.check_output([
            self.openssl, "pkeyutl", "-sign", "-rawin", "-inkey", self.key,
            "-keyform", "DER", "-in", self.input,
        ])
        assert len(signature) == 64
        return encode({0: version, 1: role, 2: body, 3: self.public_key, 4: signature})


def with_fact(index, value):
    facts = FACTS.copy()
    facts[index] = value
    return encode(CLAIMS | {5: facts})


def vectors(openssl, directory):
    attestor = Signer(openssl, directory, ATTESTOR_SEED)
    owner = Signer(openssl, directory, OWNER_SEED)
    body = encode(CLAIMS)
    valid = attestor.record(body)
    values = {
        "direct": valid,
        "embedded": attestor.record(encode(CLAIMS | {2: EMBEDDED})),
        "at-field-caps": attestor.record(encode(CLAIMS | {
            2: EMBEDDED,
            5: FACTS[:7] + [2, b"r" * 256, b"b" * 256, b"m" * 2048],
        })),
        "version": attestor.record(body, version=2),
        "role": attestor.record(body, role=2),
        "owner-domain": attestor.record(body, domain=b"ExaCopy/owner/linux-remote-download/v1\0"),
        "owner-key": owner.record(body),
        "attestor-id": attestor.record(encode(CLAIMS | {0: bytes([0x35]) * 16})),
        "build": attestor.record(encode(CLAIMS | {1: bytes([0x65]) * 32})),
        "unknown-route-class": attestor.record(encode(CLAIMS | {2: 3})),
        "campaign-scope": attestor.record(encode(CLAIMS | {3: bytes([0x68]) * 32})),
        "campaign-evidence": attestor.record(encode(CLAIMS | {4: bytes([0x69]) * 32})),
        "noncanonical-claims": attestor.record(body[:1] + b"\x18\x00" + body[2:]),
        "noncanonical-envelope": valid[:2] + b"\x18\x01" + valid[3:],
        "extra-field": attestor.record(encode(CLAIMS | {6: 0})),
        "suffix": valid + b"\x00",
        "signature": valid[:-1] + bytes([valid[-1] ^ 1]),
    }
    for label, field, value in [
        ("device", 0, identity(0x802, 11)),
        ("inode", 0, identity(0x801, 12)),
        ("uid", 1, 1003), ("gid", 2, 1004),
        ("boot", 3, bytes([0x16]) * 16),
        ("namespace", 4, 4026533001),
        ("mount-id", 5, 37), ("unique-mount", 6, 59427),
        ("arch", 7, 2), ("kernel-release", 8, b"6.8.1-fixture"),
        ("kernel-build", 9, b"#2 fixture SMP"),
        ("mountinfo", 10, FACTS[10].replace(b"rw,nosuid", b"rw,nodev")),
        ("overlong-kernel", 8, b"r" * 257),
        ("overlong-mountinfo", 10, b"m" * 2049),
        ("mountinfo-newline", 10, FACTS[10] + b"\n"),
        ("nil-boot", 3, bytes(16)), ("unknown-arch", 7, 3),
    ]:
        values[label] = attestor.record(with_fact(field, value))
    return values


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parents[2] / "tests" / "remote_download" / "qualification.hex"
    with tempfile.TemporaryDirectory(prefix="synthetic-qualification-") as scratch:
        records = vectors(args.openssl, Path(scratch))
    expected = "".join(f"{label} {record.hex()}\n" for label, record in records.items())
    if args.write:
        fixture.write_text(expected, encoding="ascii")
    assert fixture.read_text(encoding="ascii") == expected
    print(f"Verified {len(records)} synthetically attested qualification vectors")


if __name__ == "__main__":
    main()
