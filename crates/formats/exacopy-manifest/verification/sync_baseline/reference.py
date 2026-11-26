#!/usr/bin/env python3
"""Independently encode the paired baseline leaf and bound its profile negatives."""

import argparse
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "manifest"))
from reference import encode

KIND = 0x0100
PAGE = b"ExaCopy/workflow-page/v1\0"
META = b"ExaCopy/sync-baseline/linux-owner-mode/v1\0"
NAME = b"pair-\xff"


def fixture(hash_bytes, length=18, reverse=False):
    def side(root, inode, measured, rechecked, stamp):
        ident = [bytes([root]) * 32, bytes([inode]) * 32]
        metadata = [0o754, 0xFFFFFFFF, 1024]
        stability = bytes([stamp]) * 32
        return {0: 2, 1: ident, 2: length, 3: hash_bytes(META + encode(metadata)),
                4: hash_bytes(b"" if length == 0 else b"single-stream-data"),
                5: {0: measured, 1: stability, 2: rechecked, 3: ident.copy(),
                    4: stability, 5: 0}, 6: [], 7: metadata}

    left, right = (2, 1) if reverse else (1, 2)
    row = {0: [{0: 1, 1: NAME}], 1: side(1, 3, left, 4, 5),
           2: side(2, 4, right, 3, 6), 3: 0, 4: None,
           5: {0: b"\x07" * 32, 1: b"\x08" * 32, 2: 11}}
    return {0: [1, 0], 1: KIND, 2: 0, 3: [row], 4: [], 5: 1}


def cases(hash_bytes):
    base = fixture(hash_bytes)
    yield "valid", "ok", encode(base)
    yield "empty_stream_reverse_reads", "ok", encode(fixture(hash_bytes, 0, True))
    yield "signed_extent_max", "ok", encode(fixture(hash_bytes, (1 << 63) - 1))
    maximum_name = fixture(hash_bytes)
    maximum_name[3][0][0][0][1] = b"n" * 255
    yield "maximum_name", "ok", encode(maximum_name)

    def row(page):
        return page[3][0]

    def left(page):
        return row(page)[1]

    def left_read(page):
        return left(page)[5]

    def right(page):
        return row(page)[2]

    def context(page):
        return row(page)[5]

    def swap_sides(page):
        row(page)[1], row(page)[2] = row(page)[2], row(page)[1]

    def alias_roots(page):
        right(page)[1][0] = left(page)[1][0]
        right(page)[5][3][0] = left(page)[1][0]

    def alias_files(page):
        target = left(page)[1][1]
        right(page)[1][1] = target
        right(page)[5][3][1] = target

    def both(field, value, page):
        left(page)[field] = right(page)[field] = value

    def special_mode(page):
        metadata = [0o1754, 1, 2]
        both(7, metadata, page)
        both(3, hash_bytes(META + encode(metadata)), page)

    def different_verified_metadata(page):
        metadata = [0o754, 1023, 1024]
        left(page)[7] = metadata
        left(page)[3] = hash_bytes(META + encode(metadata))

    for name, expected, alter in (
        ("root_swap", "selection", swap_sides),
        ("aliased_roots", "aliased_roots", alias_roots),
        ("raw_name", "selection", lambda p: row(p)[0][0].update({1: b"pair-\xfe"})),
        ("scope", "selection", lambda p: context(p).update({0: b"x" * 32})),
        ("policy", "selection", lambda p: context(p).update({1: b"x" * 32})),
        ("scan", "selection", lambda p: context(p).update({2: 12})),
        ("zero_scan", "evidence", lambda p: context(p).update({2: 0})),
        ("aliased_files", "evidence", alias_files),
        ("reused_read_position", "evidence", lambda p: left_read(p).update({0: 2})),
        ("zero_read_position", "evidence", lambda p: left_read(p).update({0: 0})),
        ("early_final", "evidence", lambda p: left_read(p).update({2: 2})),
        ("changed_final_stamp", "evidence", lambda p: left_read(p).update({4: b"x" * 32})),
        ("foreign_final_root", "evidence", lambda p: left_read(p)[3].__setitem__(0, b"x" * 32)),
        ("foreign_final_file", "evidence", lambda p: left_read(p)[3].__setitem__(1, b"x" * 32)),
        ("foreign_right_final_root", "evidence", lambda p: right(p)[5][3].__setitem__(0, b"x" * 32)),
        ("foreign_right_final_file", "evidence", lambda p: right(p)[5][3].__setitem__(1, b"x" * 32)),
        ("changed_right_final_stamp", "evidence", lambda p: right(p)[5].update({4: b"x" * 32})),
        ("untested_consistency", "encoding", lambda p: left_read(p).update({5: 1})),
        ("stream_digest", "evidence", lambda p: left(p).update({4: b"x" * 32})),
        ("stream_length", "evidence", lambda p: left(p).update({2: 19})),
        ("above_signed_extent", "evidence", lambda p: both(2, 1 << 63, p)),
        ("uid", "evidence", lambda p: left(p)[7].__setitem__(1, 1023)),
        ("gid", "evidence", lambda p: left(p)[7].__setitem__(2, 1023)),
        ("special_mode", "evidence", special_mode),
        ("different_independently_digest_bound_metadata", "evidence", different_verified_metadata),
        ("mode_digest_mismatch", "evidence", lambda p: both(7, [0o154, 0xFFFFFFFF, 1024], p)),
        ("wrong_metadata_domain", "evidence",
         lambda p: both(3, hash_bytes(encode(left(p)[7])), p)),
        ("uid_overflow", "encoding", lambda p: left(p)[7].__setitem__(1, 1 << 32)),
        ("missing_final", "encoding", lambda p: left_read(p).pop(4)),
        ("unknown_observation", "encoding", lambda p: left(p).update({0: 0})),
        ("receipt", "encoding", lambda p: left(p).update({6: [b"x" * 32]})),
        ("tombstone", "encoding", lambda p: row(p).update({4: b"x" * 32})),
        ("unknown_key", "encoding", lambda p: context(p).update({3: 0})),
        ("nonleaf", "encoding", lambda p: p.update({2: 1})),
        ("wrong_version", "encoding", lambda p: p.update({0: [1, 1]})),
        ("wrong_inner_kind", "kind", lambda p: p.update({1: 6})),
        ("wrong_row_count", "encoding", lambda p: p.update({5: 2})),
        ("excess_rows", "encoding", lambda p: p[3].append(row(p))),
        ("external_page", "encoding", lambda p: p.update({4: [b"x" * 32]})),
        ("unsafe_name", "encoding", lambda p: row(p)[0][0].update({1: b"left/right"})),
        ("wrong_name_encoding", "encoding", lambda p: row(p)[0][0].update({0: 2})),
    ):
        entry = fixture(hash_bytes)
        alter(entry)
        yield name, expected, encode(entry)


    reverse = fixture(hash_bytes, reverse=True)
    # Right read completes at 1, its check is sampled at 2, then the left read
    # completes at 3. The later left check at 4 cannot make the right one fresh.
    left_read(reverse)[0] = 3
    right(reverse)[5][2] = 2
    yield "right_final_before_later_left", "evidence", encode(reverse)

    encoded = encode(base)
    yield "overlong_key", "canonical", encoded[:1] + b"\x18\x00" + encoded[2:]
    yield "duplicate_key", "encoding", encoded[:5] + b"\x00" + encoded[6:]
    yield "indefinite_map", "encoding", b"\xbf" + encoded[1:] + b"\xff"
    yield "trailing_value", "canonical", encoded + b"\x00"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hash_program", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()

    def hash_bytes(data):
        result = subprocess.run([arguments.hash_program.resolve()], input=data,
                                capture_output=True, check=True, timeout=10)
        return bytes.fromhex(result.stdout.decode("ascii"))

    rows = ["name\texpected\tworkflow_digest\tcanonical_or_mutated_cbor"]
    for name, expected, page in cases(hash_bytes):
        hashed = hash_bytes(PAGE + KIND.to_bytes(2, "little")
                            + len(page).to_bytes(8, "little") + page)
        rows.append(f"{name}\t{expected}\t{hashed.hex()}\t{page.hex()}")
    arguments.output.write_text("\n".join(rows) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
