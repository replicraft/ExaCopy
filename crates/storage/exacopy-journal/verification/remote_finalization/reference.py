"""Generate or verify the remote-finalization vectors independently of Rust."""

from argparse import ArgumentParser
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import textwrap

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "remote_download"))
from reference import ENTRY, JOB, encode, identity, signed_owner

POLICY_DOMAIN = b"ExaCopy/remote-download-metadata-policy/v1\0"
SCOPE_DOMAIN = b"ExaCopy/linux-remote-scope/v1\0"
FRAME_DOMAIN = b"ExaCopy/journal-record/v1\0"
RECEIPT_DOMAIN = b"ExaCopy/linux-remote-download-receipt/v1\0"
VERSION = [1, 0, 3]
OMISSIONS = list(range(1, 11))
NAME = b"t" * 254 + b"\xff"


def crc32c(data):
    residue = 0xFFFFFFFF
    for byte in data:
        residue ^= byte
        for _ in range(8):
            residue = (residue >> 1) ^ (0x82F63B78 if residue & 1 else 0)
    return (residue ^ 0xFFFFFFFF).to_bytes(4, "little")


def vectors(hasher, openssl):
    def digest(data):
        return bytes.fromhex(subprocess.check_output([hasher], input=data).decode())

    assert digest(b"").hex() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    assert crc32c(b"123456789").hex() == "839206e3"
    descriptor = bytes([1, 0]) + (0o600).to_bytes(2, "big") + bytes([1, 1] + OMISSIONS)
    policy = digest(POLICY_DOMAIN + descriptor)
    destination_root = bytes([0x54]) * 8 + bytes([0x94]) + bytes([0x54]) * 7
    parent, directory, stage = (identity(7, inode) for inode in (9, 12, 13))
    scope = {
        0: ENTRY,
        1: [["transfer.example.", 22, "Reader"], bytes([0x51])*32,
            [1, bytes([0x52])*32, bytes([0x53])*32, bytes([10, 15, 17, 19]), 22],
            b"incoming/data"],
        2: [destination_root, parent, NAME],
        3: [10**9, policy, 0],
    }
    with tempfile.TemporaryDirectory() as tmp:
        owner = signed_owner(openssl, Path(tmp), scope)
    context = [digest(owner), JOB, ENTRY]
    scope_digest = digest(SCOPE_DOMAIN + encode(scope))
    stream = b"\0SFTP\x00bytes"
    length = len(stream)
    stream_digest = digest(stream)
    head = [0, bytes(32)]
    frames = []

    def append(kind, payload):
        nonlocal head
        sequence = head[0] + 1
        header = struct.pack("<8sHHIQ32s", b"EXAJNL01", 1, kind,
                             len(payload), sequence, head[1])
        prefix = header + payload
        checksummed = prefix + crc32c(prefix)
        frame_digest = digest(FRAME_DOMAIN + checksummed)
        frames.append(checksummed + frame_digest)
        head = [sequence, frame_digest]
        return head

    def prefix(kind, fields):
        payload = encode({0: [1, 0, 1], 1: context,
                          2: None if head[0] == 0 else head, 3: kind, 4: fields})
        return append(kind, payload)

    nonce = bytes([0x61]) * 16
    run, source = (1, 7)
    prefix(1, [scope_digest])
    allocation = prefix(37, [None, [run, source], b"attempt", nonce, [length, 0o100644, 22]])
    prepared = prefix(2, [allocation, [run, source], nonce, directory, stage])
    binding = context + [prepared, run, source, stage]
    phases = []

    def record(kind, fields, receipt_phase=True):
        payload = encode({0: VERSION, 1: binding, 2: head, 3: kind, 4: fields})
        next_head = append(kind, payload)
        if receipt_phase:
            phases.append([next_head, payload])
        return next_head

    qualification = bytes([0x71]) * 32
    seal = record(4, [directory, length, 1, 1])
    verification = record(5, [length, stream_digest, stream_digest, 1, 1, 1, 1])
    metadata = record(6, [policy, 0o600, 1000, 1001, 1, 1, OMISSIONS])
    record(7, [seal, verification, directory, [destination_root, parent, NAME], qualification, 1, 1, 1])
    record(8, [1, stage])
    record(9, [metadata, directory, parent, qualification, 1, 1, 1])
    artifact = encode({0: VERSION, 1: scope_digest, 2: phases,
                       3: policy, 4: OMISSIONS, 5: 2, 6: allocation})
    receipt_digest = digest(RECEIPT_DOMAIN + artifact)
    record(18, [receipt_digest, 1], receipt_phase=False)
    return {
        "policy_descriptor": descriptor,
        "policy_digest": policy,
        "owner": owner,
        "journal": b"".join(frames),
        "receipt": artifact,
        "receipt_digest": receipt_digest,
    }


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--blake3", required=True, type=Path)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    fixture_dir = Path(__file__).resolve().parents[2] / "tests" / "remote_finalization"
    for name, data in vectors(args.blake3.resolve(), args.openssl).items():
        file = fixture_dir / (name + ".hex")
        if args.write:
            file.write_text("\n".join(textwrap.wrap(data.hex(), 64)) + "\n", encoding="ascii")
        else:
            assert bytes.fromhex(file.read_text(encoding="ascii")) == data, name
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()
