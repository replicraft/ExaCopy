"""Regenerate selector-2 declaration fixtures independently of the Rust codec."""

from argparse import ArgumentParser
from pathlib import Path

import cbor2

from reference import encode, identity
from witness_closeout import TESTS, common


def read_vectors(path):
    return {name: bytes.fromhex(raw) for name, raw in (
        row.split(" ", 1) for row in path.read_text(encoding="ascii").splitlines()
    )}


def frames(raw):
    index = 0
    found = {}
    while index < len(raw):
        kind = int.from_bytes(raw[index + 10:index + 12], "little")
        size = int.from_bytes(raw[index + 12:index + 16], "little")
        sequence = int.from_bytes(raw[index + 16:index + 24], "little")
        next_index = index + 92 + size
        payload = raw[index + 56:index + 56 + size]
        found[kind] = ([sequence, raw[next_index - 32:next_index]], cbor2.loads(payload))
        index = next_index
    assert index == len(raw)
    return found


def build():
    inherited = read_vectors(TESTS / "remote_continuation/witness_closeout.hex")
    chain = frames(inherited["zero-through-durability"])
    witness_head, envelope = chain[41]
    claims = cbor2.loads(envelope[0])
    stage_dir, job_dir, witness_name = claims[5][:3]
    binding = claims[1]
    target, qual, grant = chain[7][1][5][4:7]
    inode = identity(7, 14)
    def observation(fields):
        return encode(common(binding, chain[7][0], 8, fields))

    def retire(predecessor, reason, retained):
        return encode(common(binding, predecessor, 39, [
            stage_dir, target, qual, grant, reason, retained, 1, 1, 1,
        ]))

    return {
        "observation-conflict": observation([2]),
        "observation-uncertain": observation([3, [0], [1], [2, binding[9]]]),
        "observation-recovered": observation([4, binding[9], witness_head, 1, 1, 2]),
        "retire-unwitnessed": retire(chain[40][0], 1, [0]),
        "retire-absent-at-intent": retire(witness_head, 2, [1, witness_head]),
        "retire-preserved": retire(chain[6][0], 1, [2, witness_head, job_dir, witness_name]),
        "commit-fixture-head": encode(common(
            binding, [chain[9][0][0] + 1, bytes([0x9b]) * 32], 18,
            [inherited["receipt-digest"], inode, 1, 1],
        )),
    }


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    fixture = TESTS / "remote_continuation/witness_phase_records.hex"
    vectors = build()
    expected = "".join(f"{key} {value.hex()}\n" for key, value in vectors.items())
    if args.write:
        fixture.write_text(expected, encoding="ascii")
    assert fixture.read_text(encoding="ascii") == expected
    print(f"Verified {len(vectors)} independent selector-2 phase declarations")


if __name__ == "__main__":
    main()
