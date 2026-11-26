"""Independent P-072 arithmetic, canonical widths, and existing fixture checks."""

import argparse
import csv
from hashlib import sha256
import io
import json
from pathlib import Path
import struct


PACKET = Path(__file__).resolve().parent
ROOT = next(parent for parent in PACKET.parents if (parent / "Cargo.lock").is_file())
U64_MAX = (1 << 64) - 1
MAX_SOURCE = (1 << 63) - 1
SEGMENT_CAP = 64 * 1024 * 1024
CHECKPOINT_DATA_CAP = 64 * 1024 * 1024
CHECKPOINT_COUNT_CAP = 4096
RUN_CAP = 64
RECEIPT_CAP = 6144
HEADER = struct.Struct("<8sHHIQ32s")
OVERHEAD = HEADER.size + 4 + 32


def uint_width(n):
    """Count the CBOR header octets for a nonnegative integer or length."""
    if not 0 <= n <= U64_MAX:
        raise ValueError(f"not unsigned 64-bit: {n}")
    if n <= 23:
        return 1
    data_bytes = (n.bit_length() + 7) // 8
    return 1 + next(size for size in (1, 2, 4, 8) if size >= data_bytes)


def byte_string(length):
    return uint_width(length) + length


def array(*widths):
    return uint_width(len(widths)) + sum(widths)


def map_of(*values):
    return uint_width(len(values)) + sum(uint_width(key) + val for key, val in enumerate(values))


def canonical_widths():
    """Symbolic size only. No canonical bytes or cryptographic operation."""
    u64 = uint_width(U64_MAX)
    u32 = uint_width((1 << 32) - 1)
    extent = uint_width(MAX_SOURCE)
    digest, locator = byte_string(32), byte_string(16)
    head = array(u64, digest)
    native_id = map_of(1, byte_string(8), byte_string(8), 1)
    coverage = array(1, head, uint_width(CHECKPOINT_COUNT_CAP), extent)
    common = array(digest, locator, locator, digest, head, head, head,
                   u64, u64, native_id, coverage)
    version = array(1, 1, 1)
    target = array(locator, native_id, byte_string(255))
    witness = byte_string(len("witness.") + 32)
    receipt_suffix = 32 + 1 + 16 + 1 + 32
    pending = byte_string(len("rw-receipt.pending.") + receipt_suffix)
    final = byte_string(len("rw-receipt.final.") + receipt_suffix)
    name_present = array(1, native_id)
    omissions = array(*(1,) * 10)
    witness_preserved = array(1, head, native_id, witness)

    def phase(kind, body):
        return map_of(version, common, head, uint_width(kind), 1, body)

    witness_claims = phase(41, array(native_id, native_id, witness, digest, u64, 1, 1, 1))
    stage_seal = phase(4, array(native_id, extent, head, native_id, witness, 1, 1, 1, 1))
    verification = phase(5, array(extent, digest, digest, 1, 1, 1, 1))
    metadata = phase(6, array(digest, uint_width(384), u32, u32, 1, 1, omissions))
    intent = phase(7, array(head, head, head, native_id, target, digest, digest, 1, 1, 1))
    durability = phase(9, array(head, native_id, native_id, native_id, digest, 1, 1, 1, 1))
    ready = phase(42, array(native_id, pending, final, native_id, uint_width(RECEIPT_CAP),
                            digest, 1, 1, 1))
    commit = phase(18, array(digest, native_id, 1, 1))
    observed = {
        "live": phase(8, array(1, native_id, 1)),
        "conflict": phase(8, array(1)),
        "uncertain": phase(8, array(1, name_present, name_present, name_present)),
        "recovered": phase(8, array(1, native_id, head, 1, 1, 1)),
    }
    retired = {
        "unwitnessed": phase(39, array(native_id, target, digest, digest, 1, array(1), 1, 1, 1)),
        "witness_absent": phase(39, array(native_id, target, digest, digest, 1,
                                          array(1, head), 1, 1, 1)),
        "witness_preserved": phase(39, array(native_id, target, digest, digest, 1,
                                             witness_preserved, 1, 1, 1)),
    }
    payload_caps = {
        2: 768, 3: 768, 4: stage_seal, 5: verification, 6: metadata, 7: intent,
        8: max(observed.values()), 9: durability, 15: 768, 18: commit, 37: 768,
        39: max(retired.values()), 40: 1024, 41: map_of(byte_string(witness_claims), byte_string(64)),
        42: ready,
    }
    successful_payloads = [payload_caps[k] for k in (41, 4, 5, 6, 7)]
    successful_payloads += [max(observed["live"], observed["recovered"]), durability]
    receipt_pairs = array(*(array(head, byte_string(payload)) for payload in successful_payloads))
    structural_receipt = map_of(version, digest, receipt_pairs, digest, omissions, 1,
                                array(head, head, head, coverage), 1)
    return payload_caps, observed, retired, structural_receipt


CAPS, OBSERVED, RETIRED, STRUCTURAL_RECEIPT = canonical_widths()


def phase_edges(phase, can_retire):
    """Record kind, selected payload cap, successor, and distinct outcomes."""
    success = max(OBSERVED["live"], OBSERVED["recovered"])
    terminal_observation = max(OBSERVED["conflict"], OBSERVED["uncertain"])
    advance = {
        "coverage": (41, CAPS[41], "witness_intent"),
        "witness_intent": (4, CAPS[4], "seal"),
        "seal": (5, CAPS[5], "verify"),
        "verify": (6, CAPS[6], "metadata"),
        "metadata": (7, CAPS[7], "publish_intent"),
        "publish_intent": (8, success, "published_observed"),
        "published_observed": (9, CAPS[9], "durable"),
        "durable": (42, CAPS[42], "receipt_ready"),
        "receipt_ready": (18, CAPS[18], "terminal"),
        "retired": (37, CAPS[37], "fresh_allocated"),
        "fresh_allocated": (2, CAPS[2], "fresh_prepared"),
    }
    if phase in advance:
        yield advance[phase]
    if phase in {"coverage", "witness_intent", "seal", "verify", "metadata",
                 "fresh_allocated", "fresh_prepared"}:
        yield 15, CAPS[15], "terminal"
    if phase == "publish_intent":
        yield 8, terminal_observation, "terminal"
    if can_retire and phase in {"coverage", "witness_intent", "seal", "verify", "metadata"}:
        witness_state = {
            "coverage": "unwitnessed",
            "witness_intent": "witness_preserved",
            "seal": "witness_preserved",
            "verify": "witness_preserved",
            "metadata": "witness_preserved",
        }[phase]
        yield 39, RETIRED[witness_state], "retired"


def all_paths(start, can_retire):
    """Enumerate complete paths iteratively, including every uncertain stop."""
    pending = [(start, (), 0)]
    complete = []
    while pending:
        phase, kinds, consumed_bytes = pending.pop()
        complete.append((kinds, consumed_bytes))
        for kind, frame_payload, next_phase in phase_edges(phase, can_retire):
            pending.append((next_phase, kinds + (kind,), consumed_bytes + OVERHEAD + frame_payload))
    return complete


def phase_bound(phase, can_retire):
    paths = all_paths(phase, can_retire)
    max_byte_path, byte_count = max(paths, key=lambda row: row[1])
    max_slot_path, _ = max(paths, key=lambda row: len(row[0]))
    return byte_count, len(max_slot_path), max_byte_path, max_slot_path


def plan(accepted_end, sequence, retained, source, consumed):
    if not 0 < accepted_end <= U64_MAX or not 0 < sequence <= U64_MAX:
        return ("Boundary",)
    if not 0 <= retained <= source <= MAX_SOURCE:
        return ("SourceExtent",)
    if not 0 < consumed < RUN_CAP:
        return ("RunLimit",)
    tail = source - retained
    full, extra = divmod(tail, CHECKPOINT_DATA_CAP)
    checkpoints = full + bool(extra)
    if checkpoints > CHECKPOINT_COUNT_CAP:
        return ("CheckpointLimit",)
    new_run = consumed + 1
    can_retire = new_run < RUN_CAP
    terminal_bytes, terminal_slots, _, _ = phase_bound("coverage", can_retire)
    byte_count = OVERHEAD + CAPS[40] + checkpoints * (OVERHEAD + CAPS[3]) + terminal_bytes
    slots = 1 + checkpoints + terminal_slots
    if accepted_end > SEGMENT_CAP - byte_count:
        return ("SegmentLimit",)
    if sequence > U64_MAX - slots:
        return ("SequenceLimit",)
    return ("Accept", checkpoints, new_run, str(can_retire).lower(),
            accepted_end + byte_count, slots, RECEIPT_CAP)


def observed_end(accepted_end, logical_eof):
    """External exact-EOF observation, separate from the pure producer."""
    return 0 < accepted_end <= SEGMENT_CAP and logical_eof == accepted_end


def plan_rows():
    cap = CHECKPOINT_DATA_CAP
    total = CHECKPOINT_COUNT_CAP * cap
    nominal_end = 4096
    fresh_full = 3_529_698
    last_full = 3_529_665
    cases = [
        ("zero_tail_empty_source", nominal_end, 1, 0, 0, 1),
        ("zero_tail_nonzero_prefix", nominal_end, 6, 17, 17, 1),
        ("one_byte_tail", nominal_end, 6, 17, 18, 1),
        ("one_exact_chunk", nominal_end, 6, 17, 17 + cap, 62),
        ("chunk_plus_one", nominal_end, 6, 17, 18 + cap, 62),
        ("latest_retire_eligible_zero_tail", nominal_end, 6, 17, 17, 62),
        ("last_run_zero_tail", nominal_end, 6, 17, 17, 63),
        ("last_run_one_byte", nominal_end, 6, 17, 18, 63),
        ("full_max", nominal_end, 6, 0, total, 1),
        ("max_ranges_with_short_final", nominal_end, 6, 97, 97 + total - cap + 1, 1),
        ("max_source_offset", nominal_end, 6, MAX_SOURCE - cap - 1, MAX_SOURCE, 62),
        ("max_source_exact_fit", SEGMENT_CAP - last_full, U64_MAX - 4106,
         MAX_SOURCE - total, MAX_SOURCE, 63),
        ("fresh_both_exact_fit", SEGMENT_CAP - fresh_full, U64_MAX - 4106, 0, total, 62),
        ("fresh_one_byte_short", SEGMENT_CAP - fresh_full + 1, U64_MAX - 4106, 0, total, 62),
        ("fresh_one_slot_short", SEGMENT_CAP - fresh_full, U64_MAX - 4106 + 1, 0, total, 62),
        ("last_run_same_eof_gains_33_bytes", SEGMENT_CAP - fresh_full + 33,
         U64_MAX - 4106, 0, total, 63),
        ("last_run_one_byte_short", SEGMENT_CAP - last_full + 1, U64_MAX - 4106, 0, total, 63),
        ("last_run_one_slot_short", SEGMENT_CAP - last_full, U64_MAX - 4106 + 1, 0, total, 63),
        ("zero_tail_fresh_exact_fit", SEGMENT_CAP - 7138, U64_MAX - 10, 17, 17, 62),
        ("zero_tail_last_exact_fit", SEGMENT_CAP - 7105, U64_MAX - 10, 17, 17, 63),
        ("no_capacity_at_segment_cap", SEGMENT_CAP, 6, 17, 17, 63),
        ("outside_segment", SEGMENT_CAP + 1, 6, 17, 17, 63),
        ("arithmetic_end_overflow_if_unchecked", U64_MAX, 6, 17, 17, 63),
        ("zero_accepted_end", 0, 6, 17, 17, 1),
        ("zero_accepted_sequence", nominal_end, 0, 17, 17, 1),
        ("no_sequence_positions", nominal_end, U64_MAX, 17, 17, 1),
        ("source_shorter_than_retained", nominal_end, 6, 18, 17, 1),
        ("checkpoint_4097", nominal_end, 6, 0, total + 1, 1),
        ("already_exhausted", nominal_end, 6, 17, 17, 64),
    ]
    for name, *arguments in cases:
        outcome = plan(*arguments)
        padding = ("",) * (7 - len(outcome))
        yield name, *arguments, *outcome, *padding


def range_rows():
    cap = CHECKPOINT_DATA_CAP
    cases = [
        ("zero_tail", 17, 17, 1),
        ("first_single_byte", 17, 18, 1),
        ("past_single_byte", 17, 18, 2),
        ("first_full_chunk", 17, 18 + cap, 1),
        ("short_final_chunk", 17, 18 + cap, 2),
        ("past_short_final", 17, 18 + cap, 3),
        ("maximum_final_chunk", MAX_SOURCE - CHECKPOINT_COUNT_CAP * cap, MAX_SOURCE, 4096),
        ("past_maximum", MAX_SOURCE - CHECKPOINT_COUNT_CAP * cap, MAX_SOURCE, 4097),
    ]
    for name, retained, source, ordinal in cases:
        start = retained + (ordinal - 1) * cap
        span = (start, min(source, start + cap)) if start < source else ("", "")
        yield name, retained, source, ordinal, *span


def phase_rows():
    phases = (
        "coverage", "witness_intent", "seal", "verify", "metadata", "publish_intent",
        "published_observed", "durable", "receipt_ready", "retired", "fresh_allocated",
        "fresh_prepared", "terminal",
    )
    for can_retire in (True, False):
        for phase in phases:
            if not can_retire and phase in {"retired", "fresh_allocated", "fresh_prepared"}:
                continue
            width, count, byte_path, slot_path = phase_bound(phase, can_retire)
            yield str(can_retire).lower(), phase, width, count, csv_kinds(byte_path), csv_kinds(slot_path)


def csv_kinds(path):
    return ",".join(map(str, path))


def fixture_payloads(data):
    """Read structural boundaries only. A trailing digest is not authenticated here."""
    offset = 0
    previous = bytes(32)
    sequence = 0
    while offset < len(data):
        magic, version, kind, payload, actual_sequence, prior = HEADER.unpack_from(data, offset)
        assert magic == b"EXAJNL01" and version == 1
        assert actual_sequence == sequence + 1 or offset == 0
        assert prior == previous or offset == 0
        end = offset + OVERHEAD + payload
        assert end <= len(data)
        yield (actual_sequence, kind, payload, end - offset)
        previous = data[end - 32:end]
        sequence = actual_sequence
        offset = end


def fixture_rows():
    fixtures = ROOT / "crates/storage/exacopy-journal/tests/remote_continuation"
    standalone = fixtures / "checkpoint.hex"
    rows = [
        ("checkpoint.hex", "", bytes.fromhex(standalone.read_text())),
    ]
    for filename, labels in (
        ("witness_closeout.hex", ("zero-through-durability", "tail-prefix", "tail-witness", "ready", "receipt")),
        ("witness_phase_records.hex", ("observation-conflict", "observation-uncertain",
                                      "observation-recovered", "retire-unwitnessed",
                                      "retire-absent-at-intent", "retire-preserved", "commit-fixture-head")),
        ("witnessed_replay.hex", ("published", "recovered-published", "retire-preserved",
                                 "fresh-unbound", "conflict", "uncertain",
                                 "receipt", "recovered-receipt")),
    ):
        data = dict(line.split() for line in (fixtures / filename).read_text().splitlines())
        rows.extend((filename, label, bytes.fromhex(data[label])) for label in labels)
    naked_payloads = {
        "ready": 42, "tail-witness": 41,
        "observation-conflict": 8, "observation-uncertain": 8, "observation-recovered": 8,
        "retire-unwitnessed": 39, "retire-absent-at-intent": 39, "retire-preserved": 39,
        "commit-fixture-head": 18,
    }
    by_kind = {}
    artifacts = []
    for file, label, blob in rows:
        if label in {"receipt", "recovered-receipt"}:
            assert len(blob) <= STRUCTURAL_RECEIPT
            artifacts.append({"file": file, "label": label, "length": len(blob)})
            continue
        if file in {"witness_closeout.hex", "witness_phase_records.hex"} and label in naked_payloads:
            kind = naked_payloads[label]
            assert len(blob) <= CAPS[kind]
            artifacts.append({"file": file, "label": label, "kind": kind, "payload_length": len(blob)})
            continue
        frames = list(fixture_payloads(blob))
        artifacts.append({"file": file, "label": label, "length": len(blob),
                          "sequence_kind_payload_framed": frames})
        for sequence, kind, payload, frame in frames:
            if kind in CAPS:
                assert payload <= CAPS[kind], (file, label, sequence, kind, payload)
            if kind in {3, 8, 39, 40, 41, 42}:
                by_kind[kind] = max(by_kind.get(kind, 0), frame)
    assert set(by_kind) == {3, 8, 39, 40, 41, 42}
    return artifacts, by_kind


def tsv(header, rows):
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter="\t", lineterminator="\n")
    writer.writerow(header.split())
    writer.writerows(tuple("-" if field == "" else field for field in row) for row in rows)
    return buf.getvalue()


def frozen():
    payload_caps = {41: 605, 4: 543, 5: 475, 6: 454, 7: 922, 8: 476, 9: 551,
                    42: 689, 18: 455, 39: 905, 40: 1024, 3: 768, 15: 768, 37: 768, 2: 768}
    assert CAPS == payload_caps
    assert OVERHEAD == 92 and STRUCTURAL_RECEIPT == 4639
    assert phase_bound("coverage", True) == (
        6022, 9, (41, 4, 5, 6, 39, 37, 2, 15), (41, 4, 5, 6, 7, 8, 9, 42, 18))
    assert phase_bound("coverage", False) == (
        5989, 9, (41, 4, 5, 6, 7, 8, 9, 42, 18), (41, 4, 5, 6, 7, 8, 9, 42, 18))
    assert plan(4096, 6, 0, 0, 1) == ("Accept", 0, 2, "true", 11234, 10, 6144)
    assert plan(4096, 6, 17, 18, 63) == ("Accept", 1, 64, "false", 12061, 11, 6144)
    assert plan(4096, 6, 17, 17, 0) == ("RunLimit",)
    assert plan(4096, 6, 17, 17, 64) == ("RunLimit",)
    assert plan(4096, 6, 18, 17, 1) == ("SourceExtent",)
    assert plan(4096, 6, 0, MAX_SOURCE + 1, 1) == ("SourceExtent",)
    full_tail = 4096 * CHECKPOINT_DATA_CAP
    final_slot = U64_MAX - 4106
    for consumed, total in ((62, 3_529_698), (63, 3_529_665)):
        exact_end = SEGMENT_CAP - total
        accepted = plan(exact_end, final_slot, 0, full_tail, consumed)
        assert accepted[-3:] == (SEGMENT_CAP, 4106, 6144)
        assert plan(exact_end + 1, final_slot, 0, full_tail, consumed) == ("SegmentLimit",)
        assert plan(exact_end, final_slot + 1, 0, full_tail, consumed) == ("SequenceLimit",)
    assert plan(4096, 6, 0, full_tail + 1, 1) == ("CheckpointLimit",)
    artifacts, observed_widths = fixture_rows()
    return {
        "plan_vectors.tsv": tsv(
            "name accepted_end accepted_sequence retained_end source_extent runs_before expected "
            "checkpoints new_run allows_fresh_retirement reserved_end reserved_frames receipt_bytes",
            plan_rows()),
        "phase_vectors.tsv": tsv(
            "fresh_available phase remaining_bytes remaining_frames max_byte_kinds max_slot_kinds",
            phase_rows()),
        "range_vectors.tsv": tsv("name retained_end source_extent ordinal start exclusive_end", range_rows()),
        "eof_vectors.tsv": tsv("accepted_end observed_eof matches",
            ((accepted, seen, str(observed_end(accepted, seen)).lower())
             for accepted, seen in ((1, 1), (4096, 4095), (4096, 4096), (4096, 4097),
                                    (0, 0), (SEGMENT_CAP, SEGMENT_CAP), (SEGMENT_CAP+1, SEGMENT_CAP+1)))),
        "widths.json": json.dumps({
            "header": HEADER.size, "crc32c": 4, "digest": 32, "frame_overhead": OVERHEAD,
            "payload_ceiling": CAPS, "framed_ceiling": {kind: cap + OVERHEAD for kind, cap in CAPS.items()},
            "kind_8_payload_by_channel": OBSERVED, "kind_39_payload_by_witness_state": RETIRED,
            "receipt_structural_ceiling": STRUCTURAL_RECEIPT, "receipt_reservation": RECEIPT_CAP,
            "observed_max_framed": observed_widths, "existing_fixture_observations": artifacts,
        }, indent=2, sort_keys=True) + "\n",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", action="store_true")
    args = parser.parse_args()
    for name, expected in frozen().items():
        path = PACKET / name
        if args.freeze:
            path.write_text(expected, encoding="utf-8")
        else:
            actual = path.read_text(encoding="utf-8")
            assert actual == expected, name
        digest = sha256(expected.encode()).hexdigest()
        print(f"{digest}  {name}")


if __name__ == "__main__":
    main()
