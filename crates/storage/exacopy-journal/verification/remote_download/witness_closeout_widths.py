"""Encode conservative structural maxima and check reachable reservation paths."""
from functools import cache
from struct import pack


def header(major, n):
    if n <= 23:
        return bytes([major * 32 + n])
    widths = ((24, ">B", 8), (25, ">H", 16), (26, ">I", 32), (27, ">Q", 64))
    for flag, spelling, bits in widths:
        if n < 1 << bits:
            return bytes([major * 32 + flag]) + pack(spelling, n)
    raise ValueError(n)


def encode(value):
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return header(0, value)
    if isinstance(value, bytes):
        return header(2, len(value)) + value
    if isinstance(value, list):
        return header(4, len(value)) + b"".join(map(encode, value))
    if isinstance(value, dict):
        return header(5, len(value)) + b"".join(
            encode(k) + encode(v) for k, v in sorted(value.items())
        )
    raise TypeError(type(value))


u64 = (1 << 64) - 1
u32 = (1 << 32) - 1
extent = (1 << 63) - 1
head = [u64, b"d" * 32]
digest, locator = b"d" * 32, b"r" * 16
name = b"n" * 255
witness = b"witness." + b"0" * 32
suffix = b"e" * 32 + b"." + b"a" * 16 + b"." + b"0" * 32
pending = b"rw-receipt.pending." + suffix
final = b"rw-receipt.final." + suffix
assert (len(pending), len(final)) == (101, 99)
identity = {0: 1, 1: b"d" * 8, 2: b"i" * 8, 3: None}
version = [1, 0, 15]
coverage = [1, head, 4096, extent]
binding = [digest, locator, locator, digest, head, head, head, u64, u64, identity, coverage]
target = [locator, identity, name]
name_state = [2, identity]
witness_state = [2, head, identity, witness]
omissions = list(range(1, 11))

bodies = {
    41: [[identity, identity, witness, digest, u64, 1, 1, 1]],
    4: [[identity, extent, head, identity, witness, 1, 1, 1, 2]],
    5: [[extent, digest, digest, 1, 1, 1, 1]],
    6: [[digest, 384, u32, u32, 1, 1, omissions]],
    7: [[head, head, head, identity, target, digest, digest, 1, 1, 1]],
    8: [[1, identity, 1], [2], [3, name_state, name_state, name_state],
        [4, identity, head, 1, 1, 2]],
    9: [[head, identity, identity, identity, digest, 1, 1, 1, 1]],
    42: [[identity, pending, final, identity, 6144, digest, 1, 1, 1]],
    18: [[digest, identity, 1, 1]],
    39: [[identity, target, digest, digest, 2, witness_state, 1, 1, 1]],
}
def payload_bytes(kind, body):
    claims = encode({0: version, 1: binding, 2: head, 3: kind, 4: 2, 5: body})
    if kind == 41:
        return encode({0: claims, 1: b"s" * 64})
    return claims


payload = {
    kind: max((payload_bytes(kind, b) for b in alternatives), key=len)
    for kind, alternatives in bodies.items()
}
overhead = 92
frame = {kind: len(data) + overhead for kind, data in payload.items()}
phase_kinds = [41, 4, 5, 6, 7, 8, 9]
success = max((payload_bytes(8, bodies[8][index]) for index in [0, 3]), key=len)
receipt_payload = payload | {8: success}
retire_body_unwitnessed = [*bodies[39][0][:5], [0], *bodies[39][0][6:]]
retire_unwitnessed = len(payload_bytes(39, retire_body_unwitnessed)) + overhead
receipt = {
    0: version, 1: digest, 2: [[head, receipt_payload[kind]] for kind in phase_kinds],
    3: digest, 4: omissions, 5: 2, 6: [head, head, head, coverage], 7: 2,
}
receipt_bytes = len(encode(receipt))
assert receipt_bytes <= 6144
assert max(map(len, payload.values())) <= 1024
approval = encode({0: [1, 0, 1], 1: digest, 2: locator, 3: locator, 4: digest,
                   5: digest, 6: 2, 7: u64})
witness_claims = len(payload[41]) - 72
assert (witness_claims, len(approval)) == (533, 159)
print(f"witness claims {witness_claims} signed envelope {len(payload[41])} approval claims {len(approval)}")
for kind in bodies:
    print(f"kind {kind:2} payload {len(payload[kind]):4} framed {frame[kind]:4}")
print(f"receipt structural bytes <= {receipt_bytes}")
assert 522 + 567 + 546 + 3464 == 5099

# Edges carry bytes for the record written at the transition. Fresh capture
# checkpoints require a new reservation; this graph reaches fresh preparation
# plus one bounded failure. All unknown outcomes can stop without more bytes.
failure = 768 + overhead
fresh_stage = 768 + overhead
edges = {
    "coverage": [(41, "witness-intent"), ("retire-unwitnessed", "retired"), ("failure", "stop")],
    "witness-intent": [(4, "seal"), (39, "retired"), ("failure", "stop")],
    "seal": [(5, "verify"), (39, "retired"), ("failure", "stop")],
    "verify": [(6, "metadata"), (39, "retired"), ("failure", "stop")],
    "metadata": [(7, "intent"), (39, "retired"), ("failure", "stop")],
    "intent": [("publish-observed", "observed"), (8, "stop")],
    "observed": [(9, "durable")],
    "durable": [(42, "receipt-ready")],
    "receipt-ready": [(18, "stop")],
    "retired": [("allocate", "allocated")],
    "allocated": [("prepare", "fresh"), ("failure", "stop")],
    "fresh": [("failure", "stop")],
    "stop": [],
}
weights = frame | {
    "failure": failure,
    "allocate": fresh_stage,
    "prepare": fresh_stage,
    "retire-unwitnessed": retire_unwitnessed,
    "publish-observed": len(success) + overhead,
}


@cache
def longest(state, fresh_available):
    candidates = [(0, ())]
    for record, next_state in edges[state]:
        if next_state == "retired" and not fresh_available:
            continue
        suffix, path = longest(next_state, fresh_available)
        candidates.append((weights[record] + suffix, (record, *path)))
    return max(candidates, key=lambda candidate: candidate[0])


@cache
def max_slots(state, fresh_available):
    return max((1 + max_slots(next_state, fresh_available) for _, next_state in edges[state]
                if fresh_available or next_state != "retired"), default=0)


for state in edges:
    width, records = longest(state, True)
    print(f"{state:15} reserve {width:4} bytes / {max_slots(state, True)} slots: {records}")
clean = sum(len(receipt_payload[kind]) + overhead for kind in phase_kinds) + frame[42] + frame[18]
budget, _ = longest("coverage", True)
assert budget >= 5099 and budget >= clean
print(f"clean closeout {clean} bytes; longest reachable terminal branch {budget} bytes")
last_run, last_path = longest("coverage", False)
assert last_run == clean and last_path == (41, 4, 5, 6, 7, "publish-observed", 9, 42, 18)
print(f"no fresh slot: {last_run} bytes / {max_slots('coverage', False)} slots: {last_path}")
max_checkpoints = 4096
kind40_frame = 1024 + overhead
print(f"zero-tail total {kind40_frame + budget}")
print(f"4096-range total {kind40_frame + max_checkpoints * (768 + overhead) + budget}")
print(f"last run totals {kind40_frame + last_run} and "
      f"{kind40_frame + max_checkpoints * (768 + overhead) + last_run}")

facts = [
    identity, u32, u32, locator, u64, u64, u64, 2,
    b"k" * 256, b"r" * 256, b"m" * 2048,
]
signature_domain = b"ExaCopy/linux-remote-destination-qualification/v2\0"
for operation, mask in [(1, 0x0FFF), (2, 0x00FF_FFFF)]:
    selection = encode({0: locator, 1: digest, 2: 2, 3: digest, 4: digest,
                        5: facts, 6: operation, 7: operation, 8: mask})
    envelope = encode({0: 2, 1: 1, 2: selection, 3: digest, 4: b"s" * 64})
    signed = signature_domain + encode([2, 1, selection, digest])
    assert len(envelope) <= 3072 and len(signed) <= 3072
    print(f"qual op{operation} mask bytes {encode(mask).hex()} claims {len(selection)} "
          f"envelope {len(envelope)} signature input {len(signed)}")
