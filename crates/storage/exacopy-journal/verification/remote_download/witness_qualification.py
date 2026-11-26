"""Reproduce synthetic witnessed qualification vectors with CBOR and OpenSSL."""

from argparse import ArgumentParser
from pathlib import Path
import tempfile

from continuation_qualification import V2_DOMAIN
from qualification import ATTESTOR_SEED, CLAIMS, EMBEDDED, FACTS, OWNER_SEED, Signer
from reference import encode

MASK = 0x00ff_ffff
CLAIMS_WITH_WITNESS = CLAIMS | {6: 2, 7: 2, 8: MASK}


def vectors(openssl, directory):
    attestor = Signer(openssl, directory, ATTESTOR_SEED)
    owner = Signer(openssl, directory, OWNER_SEED)

    def record(body):
        return attestor.record(body, version=2, domain=V2_DOMAIN)

    def signed(overrides=None):
        return record(encode(CLAIMS_WITH_WITNESS | (overrides or {})))

    body = encode(CLAIMS_WITH_WITNESS)
    assert body[-5:] == bytes.fromhex("1a00ffffff")
    u32 = (1 << 32) - 1
    u64 = (1 << 64) - 1
    maximum_claims = encode(CLAIMS_WITH_WITNESS | {
        2: EMBEDDED,
        5: [FACTS[0], u32, u32, FACTS[3], u64, u64, u64, 2, b"r" * 256, b"b" * 256, b"m" * 2048],
    })
    maximum = record(maximum_claims)
    assert (len(maximum_claims), len(maximum), len(attestor.input.read_bytes())) == (2787, 2898, 2877)
    results = {
        "direct": record(body),
        "embedded": signed({2: EMBEDDED}),
        "at-field-caps": maximum,
        "legacy-v1": attestor.record(encode(CLAIMS)),
        "wrong-role": attestor.record(body, version=2, role=2, domain=V2_DOMAIN),
        "wrong-domain": attestor.record(body, version=2, domain=b"witness-test\0"),
        "owner-key": owner.record(body, version=2, domain=V2_DOMAIN),
        "wrong-attestor": signed({0: bytes([0x35]) * 16}),
        "different-build": signed({1: bytes([0x65]) * 32}),
        "different-campaign": signed({3: bytes([0x65]) * 32}),
        "different-evidence": signed({4: bytes([0x65]) * 32}),
        "mixed-operation": signed({6: 1}),
        "mixed-coverage": signed({7: 1}),
        "unknown-operation": signed({6: 3}),
        "unknown-coverage": signed({7: 3}),
        "extra-bit": signed({8: MASK | (1 << 24)}),
        "overflow": signed({8: 1 << 32}),
        "overlong-mask": record(body[:-5] + bytes.fromhex("1b0000000000ffffff")),
        "trailing-body": record(body + b"\x00"),
    }
    for bit in range(24):
        results[f"missing-{bit}"] = signed({8: MASK ^ (1 << bit)})
    return results


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parents[2] / "tests/remote_download/witness_qualification.hex"
    with tempfile.TemporaryDirectory(prefix="synthetic-witness-qualification-") as scratch:
        records = vectors(args.openssl, Path(scratch))
    expected = "".join(f"{label} {record.hex()}\n" for label, record in records.items())
    if args.write:
        fixture.write_text(expected, encoding="ascii")
    assert fixture.read_text(encoding="ascii") == expected
    print(f"Verified {len(records)} independent witnessed qualification vectors")


if __name__ == "__main__":
    main()
