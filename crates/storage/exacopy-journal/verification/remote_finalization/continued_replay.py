"""Verify the independently signed and framed continuation replay fixtures."""

from argparse import ArgumentParser
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from remote_finalization.continuation import HEADER, fixture
from remote_download.continuation_qualification import V2_CLAIMS, V2_DOMAIN
from remote_download.qualification import ATTESTOR_SEED, EMBEDDED, FACTS, Signer
from remote_download.reference import ENTRY, JOB, encode, identity
from remote_finalization.reference import FRAME_DOMAIN, crc32c, vectors

QUALIFICATION_RECORD_DOMAIN = b"ExaCopy/linux-remote-destination-qualification-record/v2\0"


def fixtures(hasher, openssl, scratch):
    def digest(data):
        return bytes.fromhex(subprocess.check_output([hasher], input=data).decode("ascii"))

    def signed_qualification(root, route):
        return Signer(openssl, scratch, ATTESTOR_SEED).record(encode(V2_CLAIMS | {
            2: route,
            5: [root, *FACTS[1:]],
        }), version=2, domain=V2_DOMAIN)

    qualification = signed_qualification(identity(7, 9), EMBEDDED)
    wrong_parent = signed_qualification(identity(7, 10), EMBEDDED)
    wrong_route = signed_qualification(identity(7, 9), 1)
    owner = vectors(hasher, openssl)["owner"]
    bound = digest(QUALIFICATION_RECORD_DOMAIN + qualification)
    original = fixture(hasher, openssl, scratch, qualification=bound, fresh_length=7, replay_controls=True)
    no_tail = fixture(hasher, openssl, scratch, qualification=bound, fresh_length=4)
    journal = original["journal"]
    prepare = [6, journal[-32:]]
    predecessor = prepare
    for ordinal, offset, payload in [(1, 4, b"E"), (2, 5, b"FG")]:
        body = encode({
            0: [1, 0, 15],
            1: [digest(owner), JOB, ENTRY],
            2: predecessor,
            3: 3,
            4: [prepare, [2, 9], ordinal, offset, len(payload), digest(payload)],
        })
        next_sequence = predecessor[0] + 1
        header = HEADER.pack(b"EXAJNL01", 1, 3, len(body), next_sequence, predecessor[1])
        checksummed = header + body + crc32c(header + body)
        predecessor = [next_sequence, digest(FRAME_DOMAIN + checksummed)]
        journal += checksummed + predecessor[1]

    return {
        "replay_qualification": qualification,
        "replay_wrong_parent": wrong_parent,
        "replay_wrong_route": wrong_route,
        "replay_journal": journal,
        "replay_zero_tail": no_tail["journal"],
        "replay_wrong_stage": original["foreign_stage"],
        "replay_wrong_prepared": original["wrong_prepared"],
        "replay_wrong_coverage": original["wrong_coverage"],
        "replay_wrong_old_extent": original["wrong_old_extent"],
    }


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--blake3", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="synthetic-continuation-replay-") as scratch:
        expected = fixtures(args.blake3.resolve(), args.openssl, Path(scratch))
    directory = HERE.parents[1] / "tests" / "remote_continuation"
    for name, value in expected.items():
        path = directory / f"{name}.hex"
        if args.write:
            path.write_text("\n".join(textwrap.wrap(value.hex(), 64)) + "\n", encoding="ascii")
        assert bytes.fromhex(path.read_text(encoding="ascii")) == value, name
    print(f"Verified {len(expected)} independent continued replay fixtures")


if __name__ == "__main__":
    main()
