"""Build a synthetic public apply owner fixture with canonical CBOR and OpenSSL."""
from argparse import ArgumentParser
from pathlib import Path
import subprocess
import tempfile

PREFIX = b"ExaCopy/owner/linux-public-apply/v1\0"
SEED = bytes([0x42]) * 32
PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

def header(major, value):
    if value < 24:
        return bytes([major << 5 | value])
    for code, size in [(24, 1), (25, 2), (26, 4), (27, 8)]:
        if value < 256 ** size:
            return bytes([major << 5 | code]) + value.to_bytes(size, 'big')
    raise ValueError("integer outside the CBOR profile")

def encode(value):
    if value is None:
        return b'\xf6'
    if isinstance(value, int):
        return header(0, value) if value >= 0 else header(1, -1 - value)
    if isinstance(value, bytes):
        return header(2, len(value)) + value
    if isinstance(value, str):
        return header(3, len(value)) + value.encode('ascii')
    if isinstance(value, list):
        return header(4, len(value)) + b''.join(map(encode, value))
    if isinstance(value, dict):
        return header(5, len(value)) + b''.join(
            encode(key) + encode(value[key]) for key in sorted(value)
        )
    raise TypeError(type(value))

parser = ArgumentParser(description=__doc__)
parser.add_argument('--openssl', default='openssl')
options = parser.parse_args()

with tempfile.TemporaryDirectory() as temporary:
    key = Path(temporary) / 'vector-key.der'
    key.write_bytes(PKCS8_PREFIX + SEED)
    public_spki = subprocess.check_output([
        options.openssl, 'pkey', '-in', key, '-inform', 'DER',
        '-pubout', '-outform', 'DER',
    ])
    assert public_spki.startswith(SPKI_PREFIX) and len(public_spki) == len(SPKI_PREFIX) + 32
    public = public_spki[len(SPKI_PREFIX):]
    owner = encode({
        0: {0: 1, 1: 0, 2: 0},
        1: bytes([0xA1]) * 16,
        2: bytes.fromhex("0123456789ab7cde8f0123456789abcd"),
        3: bytes([0xA2]) * 16,
        4: public,
        5: {0: -2, 1: 999999999},
        6: {0: 1, 1: (7).to_bytes(8, 'little')},
        7: {0: 1, 1: (7).to_bytes(8, 'little'), 2: (9).to_bytes(8, 'little'), 3: None},
        8: bytes([0xA3]) * 32,
        9: 0,
        10: ['checkpoints', 'journal', 'receipts', 'stage'],
    })
    approved = {
        0: bytes([0xB1]) * 32,
        1: bytes([0xB2]) * 16,
        2: bytes([0xB3]) * 16,
        3: 24,
        4: bytes.fromhex("0123456789ab4cde8f0123456789ab01"),
        5: bytes.fromhex("0123456789ab4cde8f0123456789ab02"),
        6: 65536,
        7: bytes([0xB7]) * 32,
        8: bytes([0xB8]) * 32,
        9: [-1, 123456789],
        10: 0,
    }
    body = encode({0: {0: 1, 1: 0, 2: 1}, 1: owner, 2: approved})
    message = Path(temporary) / 'message'
    message.write_bytes(PREFIX + body)
    signature = subprocess.check_output([
        options.openssl, 'pkeyutl', '-sign', '-rawin', '-inkey',
        key, '-keyform', 'DER', '-in', message,
    ])
    assert len(signature) == 64
    actual = encode({0: body, 1: public, 2: signature, 3: 3})
    fixture = Path(__file__).resolve().parents[2] / 'tests/public_apply_owner.hex'
    assert actual == bytes.fromhex(fixture.read_text()), 'independent signed vector differs'
    print(f'Independent public-apply owner vector verified: {len(actual)} bytes')
