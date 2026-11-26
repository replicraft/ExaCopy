"""Check the independent op2 attestation fixtures for the signed replay owner."""

from argparse import ArgumentParser
from pathlib import Path
import tempfile

from continuation_qualification import V2_DOMAIN
from qualification import ATTESTOR_SEED, CLAIMS, DIRECT, EMBEDDED, FACTS, Signer
from reference import encode, identity


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parents[2] / "tests/remote_continuation/witness_replay_qualification.hex"
    with tempfile.TemporaryDirectory(prefix="exacopy-witness-replay-vectors-") as scratch:
        signer = Signer(args.openssl, Path(scratch), ATTESTOR_SEED)
        records = {}
        for label, route, inode in (
            ("embedded", EMBEDDED, 9),
            ("direct", DIRECT, 9),
            ("wrong-parent", EMBEDDED, 10),
        ):
            # Device/inode 7/9 is the destination parent of the frozen replay owner.
            body = encode(CLAIMS | {
                2: route,
                5: [identity(7, inode), *FACTS[1:]],
                6: 2,
                7: 2,
                8: 0x00ff_ffff,
            })
            records[label] = signer.record(body, version=2, domain=V2_DOMAIN)
    expected = "".join(f"{label} {record.hex()}\n" for label, record in records.items())
    if args.write:
        fixture.write_text(expected, encoding="ascii")
    assert fixture.read_text(encoding="ascii") == expected
    print(f"Verified {len(records)} independent witness replay attestation vectors")


if __name__ == "__main__":
    main()
