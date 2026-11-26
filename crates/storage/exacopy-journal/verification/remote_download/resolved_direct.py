"""Independent deterministic CBOR and OpenSSL vectors for resolved direct SSH."""

from argparse import ArgumentParser
from ipaddress import ip_address
from pathlib import Path
from tempfile import TemporaryDirectory
import textwrap

from reference import ENTRY, VERSION, encode, identity, signed_owner


REQUIRED = [1, 1, 3]
SSH_PORT = 2222
PEER = ip_address("192.0.2.7").packed
LABEL = "transfer.example."


def scope(route, *, host=LABEL):
    return {
        0: ENTRY,
        1: [[host, SSH_PORT, "Reader"], bytes([0x51]) * 32, route, b"inbox/raw-\xff"],
        2: [
            bytes([0x54]) * 8 + bytes([0x94]) + bytes([0x54]) * 7,
            identity(7, 9),
            b"target-\xff",
        ],
        3: [10**9, bytes([0x56]) * 32, 0],
    }


def vectors(openssl, work):
    approved = scope([2, PEER, SSH_PORT])
    yield "scope", encode(approved)
    for label, projection, version in [
        ("owner", approved, REQUIRED),
        ("other-peer", scope([2, ip_address("192.0.2.8").packed, SSH_PORT]), REQUIRED),
        ("ipv6", scope([2, ip_address("2001:db8::7").packed, SSH_PORT]), REQUIRED),
        ("legacy-header", approved, VERSION),
        ("legacy-route", scope([0]), REQUIRED),
        ("legacy-direct", scope([0]), VERSION),
        ("missing-required-bit", approved, [1, 1, 1]),
        ("wrong-port", scope([2, PEER, SSH_PORT + 1]), REQUIRED),
        ("invalid-length", scope([2, PEER + bytes([1]), SSH_PORT]), REQUIRED),
        ("multicast", scope([2, ip_address("224.0.0.7").packed, SSH_PORT]), REQUIRED),
        ("mapped", scope([2, ip_address("::ffff:192.0.2.7").packed, SSH_PORT]), REQUIRED),
        ("link-local", scope([2, ip_address("fe80::7").packed, SSH_PORT]), REQUIRED),
        ("literal-mismatch", scope([2, PEER, SSH_PORT], host="192.0.2.8"), REQUIRED),
    ]:
        yield label, signed_owner(openssl, work, projection, version=version)


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    options = parser.parse_args()
    output = Path(__file__).resolve().parents[2] / "tests" / "remote_download" / "resolved-direct.hex"
    with TemporaryDirectory(prefix="exacopy-direct-vectors-") as work:
        result = []
        for name, data in vectors(options.openssl, Path(work)):
            result.extend([f"[{name}]", *textwrap.wrap(data.hex(), 76), ""])
        fixture = "\n".join(result)
    if options.write:
        output.write_text(fixture)
    assert output.read_text() == fixture
    print("Verified independently generated resolved-direct owner and scope vectors.")


if __name__ == "__main__":
    main()
