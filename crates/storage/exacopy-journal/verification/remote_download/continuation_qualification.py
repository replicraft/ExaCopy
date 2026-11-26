"""Reproduce synthetic V2 qualification vectors using independent CBOR and OpenSSL."""

from argparse import ArgumentParser
from pathlib import Path
import tempfile

from qualification import ATTESTOR_SEED, CLAIMS, DOMAIN as V1_DOMAIN, EMBEDDED, FACTS, OWNER_SEED, Signer
from reference import encode, identity

V2_DOMAIN = b"ExaCopy/linux-remote-destination-qualification/v2\0"
V2_CLAIMS = CLAIMS | {6: 1, 7: 1, 8: 0x0fff}


def vectors(openssl, directory):
    attestor = Signer(openssl, directory, ATTESTOR_SEED)
    owner = Signer(openssl, directory, OWNER_SEED)

    def signed(overrides=None):
        return attestor.record(encode(V2_CLAIMS | (overrides or {})), version=2, domain=V2_DOMAIN)

    body = encode(V2_CLAIMS)
    direct = signed()
    results = {
        "direct": direct,
        "embedded": signed({2: EMBEDDED}),
        "at-field-caps": signed({
            2: EMBEDDED,
            5: FACTS[:7] + [2, b"r" * 256, b"b" * 256, b"m" * 2048],
        }),
        "legacy-v1": attestor.record(encode(CLAIMS)),
        "unknown-version": attestor.record(body, version=3, domain=V2_DOMAIN),
        "wrong-role": attestor.record(body, version=2, role=2, domain=V2_DOMAIN),
        "v1-signature-domain": attestor.record(body, version=2, domain=V1_DOMAIN),
        "owner-key": owner.record(body, version=2, domain=V2_DOMAIN),
        "attestor-id": signed({0: bytes([0x35]) * 16}),
        "build": signed({1: bytes([0x65]) * 32}),
        "unknown-route": signed({2: 3}),
        "campaign-scope": signed({3: bytes([0x66]) * 32}),
        "campaign-evidence": signed({4: bytes([0x67]) * 32}),
        "unknown-operation": signed({6: 2}),
        "unknown-coverage": signed({7: 2}),
        "extra-coverage": signed({8: 0x1fff}),
        "changed-signed-root": signed({5: [identity(0x801, 12), *FACTS[1:]]}),
        "oversized-mountinfo": signed({5: [*FACTS[:10], b"m" * 2049]}),
        "noncanonical-body": attestor.record(
            body[:1] + b"\x18\x00" + body[2:], version=2, domain=V2_DOMAIN,
        ),
        "noncanonical-envelope": direct[:2] + b"\x18\x02" + direct[3:],
        "unknown-field": signed({9: 1}),
        "suffix": direct + b"\x00",
        "changed-signature": direct[:-1] + bytes([direct[-1] ^ 1]),
    }
    for index in range(12):
        results[f"missing-coverage-{index}"] = signed({8: 0x0fff ^ (1 << index)})
    return results


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parents[2] / "tests/remote_download/continuation_qualification.hex"
    with tempfile.TemporaryDirectory(prefix="synthetic-continuation-qualification-") as scratch:
        records = vectors(args.openssl, Path(scratch))
    expected = "".join(f"{label} {record.hex()}\n" for label, record in records.items())
    if args.write:
        fixture.write_text(expected, encoding="ascii")
    assert fixture.read_text(encoding="ascii") == expected
    print(f"Verified {len(records)} independently signed synthetic V2 qualification vectors")


if __name__ == "__main__":
    main()
