"""Reproduce the signed kind-40 positive transcript and refusal vectors."""

from argparse import ArgumentParser
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import textwrap


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "remote_download"))
from remote_download.bootstrap import PKCS8_PREFIX, SEED, signed as sign_bootstrap
from remote_download.reference import ENTRY, JOB, encode, identity
from remote_finalization.reference import FRAME_DOMAIN, crc32c, vectors


HEADER = struct.Struct("<8sHHIQ32s")
DOMAIN = b"ExaCopy/linux-remote-capture-continuation/v1\0"
NAME = b"s" * 254 + b"\xff"
GRANT = bytes([0x72]) * 32
QUALIFICATION = bytes([0x71]) * 32


def fixture(hasher, openssl, directory, *, qualification=QUALIFICATION, fresh_length=5, replay_controls=False):
    def digest(data):
        return bytes.fromhex(subprocess.check_output([hasher], input=data).decode("ascii"))

    def sign(body, domain=DOMAIN, seed=SEED):
        key = directory / "continuation-fixture-key.der"
        message = directory / "continuation-fixture-message"
        key.write_bytes(PKCS8_PREFIX + seed)
        message.write_bytes(domain + struct.pack("<HI", 40, len(body)) + body)
        signature = subprocess.check_output([
            openssl, "pkeyutl", "-sign", "-rawin", "-inkey", key,
            "-keyform", "DER", "-in", message,
        ])
        assert len(signature) == 64
        return encode({0: body, 1: signature})

    baseline = vectors(hasher, openssl)
    owner = baseline["owner"]
    assert bytes.fromhex((HERE.parents[1] / "tests" / "remote_finalization" / "owner.hex")
                         .read_text(encoding="ascii")) == owner
    original = baseline["journal"]
    magic, version, kind, size, sequence, previous = HEADER.unpack_from(original)
    assert (magic, version, kind, sequence, previous) == (b"EXAJNL01", 1, 1, 1, bytes(32))
    scope = original[HEADER.size + size - 32:HEADER.size + size]
    first = original[:HEADER.size + size + 4 + 32]
    head = [1, first[-32:]]
    frames = [first]

    def append(kind, payload):
        nonlocal head
        sequence = head[0] + 1
        header = HEADER.pack(b"EXAJNL01", 1, kind, len(payload), sequence, head[1])
        wire = header + payload
        checksummed = wire + crc32c(wire)
        head = [sequence, digest(FRAME_DOMAIN + checksummed)]
        frames.append(checksummed + head[1])
        return head

    context = [digest(owner), JOB, ENTRY]
    stage_directory, stage = (identity(7, inode) for inode in (12, 13))
    bootstrap = append(38, sign_bootstrap(openssl, directory, encode({
        0: context[0], 1: JOB, 2: ENTRY, 3: bytes([0x22]) * 16,
        4: head, 5: stage_directory, 6: 0,
    })))

    def capture(kind, fields):
        return append(kind, encode({0: [1, 0, 1], 1: context, 2: head, 3: kind, 4: fields}))

    epochs = [1, 7]
    nonce = bytes([0x61]) * 16
    stream = b"ABCD"
    allocation = capture(37, [None, epochs, NAME, nonce, [len(stream), 0o100644, 22]])
    prepared = capture(2, [allocation, epochs, nonce, stage_directory, stage])
    checkpoint = capture(3, [prepared, epochs, 1, 0, 2, digest(stream[:2])])
    body = {
        0: [1, 0, 15],
        1: context + [scope],
        2: [head, sum(map(len, frames))],
        3: [bootstrap, allocation, prepared, [2, prepared], *epochs, NAME, nonce],
        4: [stage_directory, stage],
        5: [3, checkpoint, 1, 2],
        6: [2, 9, fresh_length, 0o100600, 23],
        7: [len(stream), digest(stream), 1],
        8: [1, GRANT, qualification, 1],
    }
    valid = sign(encode(body))
    append(40, valid)
    results = {
        "journal": b"".join(frames),
        "future_features": sign(encode(body | {0: [1, 0, 31]})),
        "future_version": sign(encode(body | {0: [2, 0, 15]})),
        "wrong_domain": sign(encode(body), b"ExaCopy/linux-remote-capture-continuation/v2\0"),
        "other_key": sign(encode(body), seed=bytes([0x53]) * 32),
        "noncanonical_body": sign(encode(body)[:-1] + b"\x18\x01"),
        "foreign_stage": sign(encode(body | {4: [stage_directory, identity(7, 14)]})),
        "body_trailing": sign(encode(body) + b"\x00"),
    }
    if replay_controls:
        forged_head = [prepared[0], bytes([0x44]) * 32]
        results["wrong_prepared"] = sign(encode(body | {
            3: [bootstrap, allocation, forged_head, [2, forged_head], *epochs, NAME, nonce],
        }))
        results["wrong_coverage"] = sign(encode(body | {5: [3, checkpoint, 1, 3]}))
        results["wrong_old_extent"] = sign(encode(body | {7: [5, digest(b"ABCDE"), 1]}))
    return results


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--blake3", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    path = HERE.parents[1] / "tests" / "remote_continuation"
    with tempfile.TemporaryDirectory(prefix="synthetic-continuation-") as scratch:
        payloads = fixture(args.blake3.resolve(), args.openssl, Path(scratch))
    for label, data in payloads.items():
        output = path / f"{label}.hex"
        if args.write:
            output.write_text("\n".join(textwrap.wrap(data.hex(), 64)) + "\n", encoding="ascii")
        assert bytes.fromhex(output.read_text(encoding="ascii")) == data, label
    print(f"Verified {len(payloads)} independently signed kind-40 fixtures")


if __name__ == "__main__":
    main()
