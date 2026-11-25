"""Reproduce the kind-39 transcript using the independent journal wire helpers."""

from argparse import ArgumentParser
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import textwrap


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from remote_finalization.reference import FRAME_DOMAIN, NAME, OMISSIONS, crc32c, vectors
from remote_download.bootstrap import signed
from remote_download.reference import ENTRY, JOB, encode, identity


HEADER = struct.Struct("<8sHHIQ32s")
QUALIFICATION = bytes([0x71]) * 32
GRANT = bytes([0x72]) * 32


def timeline(hasher, openssl):
    def digest(data):
        return bytes.fromhex(subprocess.check_output([hasher], input=data).decode("ascii"))

    baseline = vectors(hasher, openssl)
    frozen_owner = HERE.parents[1] / "tests" / "remote_finalization" / "owner.hex"
    assert bytes.fromhex(frozen_owner.read_text(encoding="ascii")) == baseline["owner"]
    journal = baseline["journal"]
    magic, version, kind, size, sequence, previous = HEADER.unpack_from(journal)
    assert (magic, version, kind, sequence, previous) == (
        b"EXAJNL01", 1, 1, 1, bytes(32),
    )
    job_payload = journal[HEADER.size:HEADER.size + size]
    assert job_payload[-34:-32] == b"\x58\x20"
    scope = job_payload[-32:]
    first = journal[:HEADER.size + size + 4 + 32]
    head = [1, first[-32:]]
    frames = [first]

    def append(kind, payload):
        nonlocal head
        sequence = head[0] + 1
        header = HEADER.pack(b"EXAJNL01", 1, kind, len(payload), sequence, head[1])
        prefix = header + payload
        checksummed = prefix + crc32c(prefix)
        head = [sequence, digest(FRAME_DOMAIN + checksummed)]
        frames.append(checksummed + head[1])
        return head

    context = [digest(baseline["owner"]), JOB, ENTRY]
    parent, directory, stage = (identity(7, inode) for inode in (9, 12, 13))
    root = bytes([0x54]) * 8 + b"\x94" + bytes([0x54]) * 7
    bootstrap_body = encode({
        0: context[0], 1: JOB, 2: ENTRY, 3: bytes([0x22]) * 16,
        4: head, 5: directory, 6: 0,
    })
    with tempfile.TemporaryDirectory(prefix="synthetic-retirement-") as scratch:
        bootstrap = append(38, signed(openssl, Path(scratch), bootstrap_body))

    def capture(kind, detail):
        return append(kind, encode({
            0: [1, 0, 1], 1: context, 2: head, 3: kind, 4: detail,
        }))

    epochs = [1, 7]
    nonce = bytes([0x61]) * 16
    stream = b"AB"
    observed = [len(stream), 0o100644, 22]
    allocation = capture(37, [None, epochs, b"first-\xff", nonce, observed])
    prepared = capture(2, [allocation, epochs, nonce, directory, stage])
    stream_digest = digest(stream)
    capture(3, [prepared, epochs, 1, 0, len(stream), stream_digest])

    def phase(kind, detail):
        return append(kind, encode({
            0: [1, 0, 3], 1: context + [prepared, *epochs, stage],
            2: head, 3: kind, 4: detail,
        }))

    seal = phase(4, [directory, len(stream), 1, 1])
    phase(5, [len(stream), stream_digest, stream_digest, 1, 1, 1, 1])
    phase(6, [baseline["policy_digest"], 0o600, 1000, 1001, 1, 1, OMISSIONS])
    append(39, encode({
        0: [1, 0, 7],
        1: context + [scope],
        2: head,
        3: [bootstrap, allocation, prepared, seal, *epochs],
        4: [directory, stage],
        5: [root, parent, NAME],
        6: QUALIFICATION,
        7: [GRANT, 1, 1],
    }))
    capture(37, [epochs, [2, 8], b"fresh-\xff", bytes([0x62]) * 16, observed])
    return b"".join(frames)


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--blake3", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    fixture = HERE.parents[1] / "tests" / "remote_finalization" / "retirement_journal.hex"
    data = timeline(args.blake3.resolve(), args.openssl)
    if args.write:
        fixture.write_text("\n".join(textwrap.wrap(data.hex(), 64)) + "\n", encoding="ascii")
    assert bytes.fromhex(fixture.read_text(encoding="ascii")) == data
    print(f"Verified independently framed kind-39 retirement transcript: {len(data)} bytes")


if __name__ == "__main__":
    main()
