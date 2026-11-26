"""Reproduce witnessed closeout framing, canonical consent and signed fixture bytes.

The independent oracle uses cbor2 for inherited fixture input, the existing
Python canonical encoder, the portable C BLAKE3 oracle, and OpenSSL Ed25519.
"""
from argparse import ArgumentParser
from pathlib import Path
import struct
import sys
import subprocess
import tempfile

import cbor2

from continuation_qualification import V2_DOMAIN
from qualification import ATTESTOR_SEED, CLAIMS, EMBEDDED, FACTS, OWNER_SEED, Signer
from reference import encode, identity

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from remote_finalization.reference import FRAME_DOMAIN, crc32c

TESTS = Path(__file__).resolve().parents[2] / "tests"
VERSION = [1, 0, 15]
SELECTOR = 2
SEAL = b"ExaCopy/linux-remote-capture-continuation/v1\0"
WITNESS = b"ExaCopy/linux-remote-witness-intent/v1\0"
APPROVAL = b"ExaCopy/linux-remote-witness-retention-approval/v1\0"
QUALIFICATION = b"ExaCopy/linux-remote-destination-qualification-record/v2\0"
RECEIPT = b"ExaCopy/linux-remote-witnessed-continued-download-receipt/v1\0"
DEADLINE = (1 << 64) - 1


def frame(b3, predecessor, kind, payload):
    sequence = predecessor[0] + 1
    raw = b"EXAJNL01" + struct.pack("<HHIQ", 1, kind, len(payload), sequence)
    raw += predecessor[1] + payload
    raw += crc32c(raw)
    digest = b3(FRAME_DOMAIN + raw)
    return [sequence, digest], raw + digest


def signed(signer, domain, kind, claims):
    signer.input.write_bytes(domain + struct.pack("<HI", kind, len(claims)) + claims)
    signature = subprocess.check_output([
        signer.openssl, "pkeyutl", "-sign", "-rawin", "-inkey", signer.key,
        "-keyform", "DER", "-in", signer.input,
    ])
    return encode({0: claims, 1: signature})


def common(binding, previous, kind, body):
    return {0: VERSION, 1: binding, 2: previous, 3: kind, 4: SELECTOR, 5: body}


def inherited(b3):
    segment = bytes.fromhex((TESTS / "remote_continuation/journal.hex").read_text())
    prior = [0, bytes(32)]
    offset = 0
    for expected_kind in (1, 38, 37, 2, 3, 40):
        _, kind, size, _ = struct.unpack_from("<HHIQ", segment, offset + 8)
        assert kind == expected_kind
        payload = segment[offset + 56:offset + 56 + size]
        head, encoded = frame(b3, prior, kind, payload)
        assert encoded == segment[offset:offset + len(encoded)]
        if kind == 40:
            return prior, cbor2.loads(cbor2.loads(payload)[0])
        offset += len(encoded)
        prior = head
    raise AssertionError("required inherited continuation missing")


def closeout(b3, owner, prior, claims, qualification_digest, *, tail):
    context = claims[1]
    grant = claims[8][1]
    claims[8] = [1, grant, qualification_digest, 1]
    adopted = claims[7][0]
    # The nonzero case has two successive independently framed checkpoints.
    source = claims[6].copy()
    source[2] = adopted + (2 if tail else 0)
    claims[6] = source
    active, transcript = frame(b3, prior, 40, signed(owner, SEAL, 40, encode(claims)))
    head = active
    coverage = [0, active, adopted]
    if tail:
        for ordinal, data in enumerate((b"E", b"F"), 1):
            checkpoint = encode({
                0: VERSION, 1: context[:3], 2: head, 3: 3,
                4: [active, source[:2], ordinal, adopted + ordinal - 1, 1, b3(data)],
            })
            head, encoded = frame(b3, head, 3, checkpoint)
            transcript += encoded
        coverage = [1, head, 2, source[2]]

    allocation, prepared = claims[3][1:3]
    nonce = claims[3][7]
    stage_dir, stage = claims[4]
    job_dir, parent, receipt_inode = [identity(7, inode) for inode in (11, 9, 14)]
    name = b"witness." + nonce.hex().encode()
    binding = [*context, allocation, prepared, active, *source[:2], stage, coverage]
    approval = encode({0: [1, 0, 1], 1: context[0], 2: context[1], 3: context[2],
                       4: context[3], 5: grant, 6: SELECTOR, 7: DEADLINE})
    assert len(approval) == 159
    consent = b3(APPROVAL + approval)
    body = [stage_dir, job_dir, name, consent, DEADLINE, 1, 1, 1]
    record = common(binding, head, 41, body)
    canonical = encode(record)
    witness = signed(owner, WITNESS, 41, canonical)
    controls = {
        "wrong-domain": signed(owner, SEAL, 41, canonical),
        "wrong-profile": signed(owner, WITNESS, 41, encode(record | {4: 1})),
        "legacy-version": signed(owner, WITNESS, 41, encode(record | {0: [1, 0, 3]})),
        "wrong-witness-name": signed(owner, WITNESS, 41, encode(
            record | {5: [*body[:2], name.upper(), *body[3:]]})),
        "wrong-consent": signed(owner, WITNESS, 41, encode(
            record | {5: [*body[:3], b"?" * 32, *body[4:]]})),
        "trailing-claims": signed(owner, WITNESS, 41, canonical + b"\x00"),
        "noncanonical-map": signed(owner, WITNESS, 41, canonical[:1] + b"\x18\x00" + canonical[2:]),
    }
    if tail:
        return {"tail-prefix": transcript, "tail-witness": witness, **controls}

    witness_head, encoded = frame(b3, head, 41, witness)
    transcript += encoded
    phases = [[witness_head, witness]]
    head = witness_head

    def emit(kind, body):
        nonlocal head, transcript
        payload = encode(common(binding, head, kind, body))
        head, encoded_frame = frame(b3, head, kind, payload)
        transcript += encoded_frame
        phases.append([head, payload])
        return head

    seal_head = emit(4, [stage_dir, source[2], witness_head, job_dir, name, 1, 1, 1, 2])
    data_digest = b3(b"ABCD")
    verify_head = emit(5, [source[2], data_digest, data_digest, 1, 1, 1, 1])
    manifest = cbor2.loads(cbor2.loads(bytes.fromhex(
        (TESTS / "remote_finalization/owner.hex").read_text()))[0])
    scope = manifest[7]
    policy = scope[3][1]
    omissions = list(range(1, 11))
    metadata = emit(6, [policy, 384, 1001, 1002, 1, 1, omissions])
    emit(7, [seal_head, verify_head, witness_head, stage_dir, scope[2], qualification_digest,
             grant, 1, 1, 1])
    emit(8, [1, stage, 1])
    emit(9, [metadata, stage_dir, parent, job_dir, qualification_digest, 1, 1, 1, 1])

    receipt = encode({0: VERSION, 1: context[3], 2: phases, 3: policy, 4: omissions,
                      5: SELECTOR, 6: [allocation, prepared, active, coverage], 7: SELECTOR})
    digest = b3(RECEIPT + receipt)
    suffix = b"%s.%016x.%s" % (context[2].hex().encode(), source[0], nonce.hex().encode())
    pending = b"rw-receipt.pending." + suffix
    final = b"rw-receipt.final." + suffix
    assert (len(pending), len(final)) == (101, 99)
    receipt_body = [job_dir, pending, final, receipt_inode, len(receipt), digest, 1, 1, 1]
    ready_record = common(binding, head, 42, receipt_body)
    ready = encode(ready_record)
    return {
        "zero-through-durability": transcript, "receipt": receipt, "receipt-digest": digest,
        "ready": ready, "approval": consent,
        "wrong-receipt-name": encode(ready_record | {
            5: [job_dir, pending.upper(), *receipt_body[2:]]}),
        "aliased-receipt": encode(ready_record | {
            5: [*receipt_body[:3], stage, *receipt_body[4:]]}),
        "legacy-ready": encode(ready_record | {0: [1, 0, 3]}),
        "zero-length-ready": encode(ready_record | {
            5: [*receipt_body[:4], 0, *receipt_body[5:]]}),
    }


def test_maxima(owner):
    full_head = [DEADLINE, b"d" * 32]
    stage = identity(7, 13)
    held = identity(7, 11)
    binding = [b"d" * 32, b"i" * 16, b"e" * 16, b"s" * 32, full_head,
               full_head, full_head, DEADLINE, DEADLINE, stage,
               [1, full_head, 4096, (1 << 63) - 1]]
    claims = encode(common(binding, full_head, 41, [
        identity(7, 12), held, b"witness." + b"f" * 32, b"a" * 32, DEADLINE, 1, 1, 1,
    ]))
    assert (len(claims), len(signed(owner, WITNESS, 41, claims))) == (533, 605)
    ready = encode(common(binding, full_head, 42, [
        held, b"p" * 101, b"f" * 99, identity(7, 14), 6144, b"d" * 32, 1, 1, 1,
    ]))
    assert len(ready) == 689


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--blake3", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    hasher = args.blake3.resolve()

    def b3(data):
        return bytes.fromhex(subprocess.check_output([hasher], input=data).decode("ascii"))

    prior, claims = inherited(b3)
    with tempfile.TemporaryDirectory(prefix="synthetic-remote-witness-") as directory:
        owner = Signer(args.openssl, Path(directory), OWNER_SEED)
        attestor = Signer(args.openssl, Path(directory), ATTESTOR_SEED)
        qualification = attestor.record(encode(CLAIMS | {
            2: EMBEDDED, 5: [identity(7, 9), *FACTS[1:]], 6: 2, 7: 2, 8: 0x00ffffff,
        }), version=2, domain=V2_DOMAIN)
        digest = b3(QUALIFICATION + qualification)
        vectors = {"qualification": qualification, **closeout(b3, owner, prior, claims, digest, tail=False),
                   **closeout(b3, owner, prior, claims, digest, tail=True)}
        test_maxima(owner)
    expected = "".join(f"{key} {value.hex()}\n" for key, value in vectors.items())
    fixture = TESTS / "remote_continuation/witness_closeout.hex"
    if args.write:
        fixture.write_text(expected, encoding="ascii")
    assert fixture.read_text(encoding="ascii") == expected
    print(f"Verified {len(vectors)} independent witnessed closeout fixtures and structural maxima")


if __name__ == "__main__":
    main()
