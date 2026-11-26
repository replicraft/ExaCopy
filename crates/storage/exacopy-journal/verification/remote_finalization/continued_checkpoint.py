"""Reproduce the canonical V2 checkpoint appended to the kind-40 fixture."""

from argparse import ArgumentParser
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from remote_finalization.continuation import HEADER, fixture
from remote_download.reference import ENTRY, JOB, encode
from remote_finalization.reference import FRAME_DOMAIN, crc32c, vectors


def transcript(hasher, openssl):
    def digest(data):
        return bytes.fromhex(subprocess.check_output([hasher], input=data).decode("ascii"))

    with tempfile.TemporaryDirectory(prefix="continued-checkpoint-") as scratch:
        original = fixture(hasher, openssl, Path(scratch))["journal"]
    baseline = HERE.parents[1] / "tests" / "remote_continuation" / "journal.hex"
    assert original == bytes.fromhex(baseline.read_text(encoding="ascii"))
    owner = vectors(hasher, openssl)["owner"]
    offset = 0
    while offset < len(original):
        magic, version, kind, length, sequence, _ = HEADER.unpack_from(original, offset)
        offset += HEADER.size + length + 4 + 32
    assert offset == len(original)
    assert (magic, version, kind, sequence) == (b"EXAJNL01", 1, 40, 6)
    continuation = [sequence, original[-32:]]
    payload = encode({
        0: [1, 0, 15],
        1: [digest(owner), JOB, ENTRY],
        2: continuation,
        3: 3,
        4: [continuation, [2, 9], 1, 4, 1, digest(b"E")],
    })
    header = HEADER.pack(magic, version, 3, len(payload), sequence + 1, continuation[1])
    checksummed = header + payload + crc32c(header + payload)
    return checksummed + digest(FRAME_DOMAIN + checksummed)


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--blake3", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    checkpoint = transcript(args.blake3.resolve(), args.openssl)
    path = HERE.parents[1] / "tests" / "remote_continuation" / "checkpoint.hex"
    if args.write:
        path.write_text("\n".join(textwrap.wrap(checkpoint.hex(), 64)) + "\n", encoding="ascii")
    assert bytes.fromhex(path.read_text(encoding="ascii")) == checkpoint
    print(f"Verified independently framed V2 continued checkpoint: {len(checkpoint)} bytes")


if __name__ == "__main__":
    main()
