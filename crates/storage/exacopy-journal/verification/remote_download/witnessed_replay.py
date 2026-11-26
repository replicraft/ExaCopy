"""Reproduce mixed witnessed histories using Python CBOR, C BLAKE3, and OpenSSL."""

from argparse import ArgumentParser
from pathlib import Path
import subprocess
import tempfile

import cbor2

from reference import encode, identity
from qualification import OWNER_SEED, Signer
from witness_closeout import APPROVAL, TESTS, SEAL, WITNESS, RECEIPT, common, frame, signed
from witness_phase_records import read_vectors

FRESH_V1 = bytes([0x85]) * 32


class History:
    def __init__(self, digest, raw):
        self.digest = digest
        self.raw = raw
        self.head = [0, bytes(32)]
        self.rows = []
        offset = 0
        while offset < len(raw):
            kind = int.from_bytes(raw[offset + 10:offset + 12], "little")
            size = int.from_bytes(raw[offset + 12:offset + 16], "little")
            payload = raw[offset + 56:offset + 56 + size]
            self.head, expected = frame(digest, self.head, kind, payload)
            assert raw[offset:offset + len(expected)] == expected
            offset += len(expected)
            self.rows.append((kind, self.head, offset, payload))

    def get(self, kind):
        return next(row for row in reversed(self.rows) if row[0] == kind)

    def through(self, kind):
        return self.raw[:self.get(kind)[2]]

    def append(self, kind, payload):
        self.head, encoded = frame(self.digest, self.head, kind, payload)
        self.raw += encoded
        self.rows.append((kind, self.head, len(self.raw), payload))
        return self.head


def read_inputs(digest):
    old = bytes.fromhex((TESTS / "remote_continuation/journal.hex").read_text())
    inherited = History(digest, old).through(3)
    fixtures = read_vectors(TESTS / "remote_continuation/witness_closeout.hex")
    bodies = read_vectors(TESTS / "remote_continuation/witness_phase_records.hex")
    return inherited, fixtures, bodies


def record_raw(row):
    return cbor2.loads(row[3])


def kind40_claims(history):
    return cbor2.loads(record_raw(history.get(40))[0])


def close_receipt(digest, chain, original, inode):
    receipt = cbor2.loads(original)
    receipt[2] = [[head, payload] for kind in (41, 4, 5, 6, 7, 8, 9)
                  for _, head, _, payload in [chain.get(kind)]]
    artifact = encode(receipt)
    ready = record_raw(chain.get(9))
    original_ready = cbor2.loads(inode)
    ready_body = original_ready[5].copy()
    ready_body[4:6] = [len(artifact), digest(RECEIPT + artifact)]
    chain.append(42, encode(common(ready[1], chain.head, 42, ready_body)))
    chain.append(18, encode(common(ready[1], chain.head, 18, [
        ready_body[5], ready_body[3], 1, 1,
    ])))
    return artifact


def add_fresh(chain, context, epochs, name, nonce, stage):
    next_epochs = [epochs[0] + 1, epochs[1] + 1]
    source = [4, 0o100600, 41]
    allocation = chain.append(37, encode({
        0: [1, 0, 1], 1: context[:3], 2: chain.head, 3: 37,
        4: [epochs, next_epochs, name, nonce, source],
    }))
    return allocation, next_epochs, source, stage


def fresh_prepare(digest, chain, context, fresh, directory, nonce):
    allocation, epochs, _, stage = fresh
    prepared = chain.append(2, encode({
        0: [1, 0, 1], 1: context[:3], 2: chain.head, 3: 2,
        4: [allocation, epochs, nonce, directory, stage],
    }))
    checkpoint = chain.append(3, encode({
        0: [1, 0, 1], 1: context[:3], 2: chain.head, 3: 3,
        4: [prepared, epochs, 1, 0, 4, digest(b"ABCD")],
    }))
    return prepared, checkpoint


def last_record_failure(chain, context, active, epochs, boundary):
    chain.append(15, encode({
        0: [1, 0, 1], 1: context[:3], 2: chain.head, 3: 15,
        4: [active, epochs, boundary],
    }))


def fresh_v1(digest, chain, witness_chain, fresh, prepared, directory):
    allocation, epochs, source, stage = fresh
    del allocation
    binding = [*kind40_claims(witness_chain)[1][:3], prepared, *epochs, stage]
    def emit(kind, body):
        return chain.append(kind, encode({0: [1, 0, 3], 1: binding, 2: chain.head, 3: kind, 4: body}))
    seal = emit(4, [directory, source[0], 1, 1])
    stream = digest(b"ABCD")
    verify = emit(5, [source[0], stream, stream, 1, 1, 1, 1])
    emit(6, record_raw(witness_chain.get(6))[5])
    target = record_raw(witness_chain.get(7))[5][4]
    emit(7, [seal, verify, directory, target, FRESH_V1, 1, 1, 1])


def logical_limits(digest, signer, zero):
    current = History(digest, zero.through(40))
    stable = record_raw(zero.get(7))[5]
    results = {}
    for run in range(2, 65):
        prior = kind40_claims(current)
        assert prior[6][0] == run
        active = current.get(40)[1]
        source = prior[6][1]
        extent = prior[7][0]
        if run in (63, 64):
            branch = History(digest, current.raw)
            context = prior[1]
            binding = [*context, *prior[3][1:3], active, run, source, prior[4][1], [0, active, extent]]
            branch.append(39, encode(common(binding, branch.head, 39, [
                prior[4][0], *stable[4:7], 1, [0], 1, 1, 1,
            ])))
            results[f"retire-at-{run}"] = branch.raw
        if run < 64:
            next_claims = prior | {
                2: [active, len(current.raw)],
                3: [*prior[3][:3], [40, active], *prior[6][:2], *prior[3][6:]],
                5: [40, active, 0, extent],
                6: [run + 1, source + 1, *prior[6][2:]],
            }
            current.append(40, signed(signer, SEAL, 40, encode(next_claims)))
    return results

def vectors(digest, signer):
    inherited, fixtures, bodies = read_inputs(digest)
    zero = History(digest, inherited + fixtures["zero-through-durability"])
    full = History(digest, zero.raw)
    receipt = close_receipt(digest, full, fixtures["receipt"], fixtures["ready"])
    assert receipt == fixtures["receipt"]
    claims = kind40_claims(zero)
    stage_directory, stage = claims[4]
    result = {"published": full.raw, "receipt": receipt}
    expired = History(digest, zero.through(40))
    witness = cbor2.loads(record_raw(zero.get(41))[0])
    context = claims[1]
    body = witness[5].copy()
    body[4] = 1
    body[3] = digest(APPROVAL + encode({
        0: [1, 0, 1], 1: context[0], 2: context[1], 3: context[2], 4: context[3],
        5: claims[8][1], 6: 2, 7: body[4],
    }))
    expired.append(41, signed(signer, WITNESS, 41, encode(witness | {5: body})))
    result["archived-expired-consent"] = expired.raw
    result.update(logical_limits(digest, signer, zero))

    for status in ("conflict", "uncertain", "recovered"):
        alternative = History(digest, zero.through(7))
        alternative.append(8, bodies["observation-" + status])
        result[status] = alternative.raw
        if status == "recovered":
            durability = record_raw(zero.get(9))
            alternative.append(9, encode(durability | {2: alternative.head}))
            recovered_receipt = close_receipt(digest, alternative, fixtures["receipt"], fixtures["ready"])
            result["recovered-published"] = alternative.raw
            result["recovered-receipt"] = recovered_receipt
        else:
            durability = record_raw(zero.get(9))
            alternative.append(9, encode(durability | {2: alternative.head}))
            result[status + "-then-durability"] = alternative.raw

    failure = History(digest, zero.through(41))
    last_record_failure(failure, claims[1], zero.get(40)[1], claims[6][:2], 1)
    result["pre-intent-failure"] = failure.raw
    seal = record_raw(zero.get(4))
    failure.append(4, encode(seal | {2: failure.head}))
    result["failure-then-seal"] = failure.raw
    rejected = History(digest, zero.through(41))
    last_record_failure(rejected, claims[1], zero.get(40)[1], claims[6][:2], 3)
    result["false-terminal-source-after-witness"] = rejected.raw


    for label, end in (("retire-unwitnessed", 40), ("retire-absent-at-intent", 41), ("retire-preserved", 6)):
        retired = History(digest, zero.through(end))
        retired.append(39, bodies[label])
        result[label] = retired.raw
    retired = History(digest, result["retire-preserved"])
    fresh_name, nonce = b"fresh-attempt-3", bytes([0x8b]) * 16
    fresh = add_fresh(retired, claims[1], claims[6][:2], fresh_name, nonce, identity(7, 20))
    result["fresh-unbound"] = retired.raw
    second = History(digest, retired.raw)
    add_fresh(second, claims[1], fresh[1], b"second-fresh", bytes([0x8c]) * 16, identity(7, 21))
    result["fresh-unbound-then-allocation"] = second.raw
    prepared, checkpoint = fresh_prepare(digest, retired, claims[1], fresh, stage_directory, nonce)
    legacy = History(digest, retired.raw)
    fresh_v1(digest, legacy, zero, fresh, prepared, stage_directory)
    result["fresh-v1-intent"] = legacy.raw

    allocation, epochs, source, new_stage = fresh
    restarted = claims | {
        2: [retired.head, len(retired.raw)],
        3: [claims[3][0], allocation, prepared, [2, prepared], *epochs, fresh_name, nonce],
        4: [stage_directory, new_stage],
        5: [3, checkpoint, 1, 4],
        6: [epochs[0] + 1, epochs[1] + 1, *source],
    }
    retired.append(40, signed(signer, SEAL, 40, encode(restarted)))
    result["fresh-v1-then-v2"] = retired.raw

    tail = History(digest, inherited + fixtures["tail-prefix"])
    prior = kind40_claims(tail)
    older_head = tail.get(40)[1]
    reused = prior | {
        2: [tail.head, len(tail.raw)],
        3: [*prior[3][:3], [40, older_head], *prior[6][:2], *prior[3][6:]],
        5: [3, tail.head, 2, 6],
        6: [3, 10, *prior[6][2:]],
        7: [6, digest(b"ABCDEF"), 1],
    }
    new_head = tail.append(40, signed(signer, SEAL, 40, encode(reused)))
    witness = cbor2.loads(cbor2.loads(fixtures["tail-witness"])[0])
    binding = [*witness[1][:6], new_head, 3, 10, stage, [0, new_head, 6]]
    tail.append(41, signed(signer, WITNESS, 41, encode(common(binding, tail.head, 41, witness[5]))))
    result["repeated-v2"] = tail.raw

    ready = History(digest, full.through(42))
    bad_commit = record_raw(full.get(18))
    changed_body = [*bad_commit[5]]
    changed_body[1] = identity(7, 15)
    ready.append(18, encode(bad_commit | {5: changed_body}))
    result["wrong-committed-inode"] = ready.raw
    bad_ready = History(digest, zero.raw)
    changed = cbor2.loads(fixtures["ready"])
    changed[5][5] = bytes([0x33]) * 32
    bad_ready.append(42, encode(changed))
    result["wrong-ready-digest"] = bad_ready.raw
    return result


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--blake3", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    oracle = args.blake3.resolve()

    def digest(raw):
        return bytes.fromhex(subprocess.check_output([oracle], input=raw).decode("ascii"))

    with tempfile.TemporaryDirectory(prefix="separate-witnessed-replay-") as scratch:
        records = vectors(digest, Signer(args.openssl, Path(scratch), OWNER_SEED))
    expected = "".join(f"{name} {raw.hex()}\n" for name, raw in records.items())
    path = TESTS / "remote_continuation/witnessed_replay.hex"
    if args.write:
        path.write_text(expected, encoding="ascii")
    assert path.read_text(encoding="ascii") == expected
    print(f"Verified {len(records)} independent witnessed history/artifact vectors")


if __name__ == "__main__":
    main()
