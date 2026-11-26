"""Independent OpenSSL Ed25519 and deterministic CBOR for absolute SFTP owners."""

from argparse import ArgumentParser
from pathlib import Path
from tempfile import TemporaryDirectory
import textwrap

from reference import VERSION, encode, signed_owner
from resolved_direct import PEER, REQUIRED, SSH_PORT, scope


ABSOLUTE = [1, 2, 7]
PATH = b"/inbox/raw-\xff"
DIRECT = [2, PEER, SSH_PORT]
EMBEDDED = [1, bytes([0x52]) * 32, bytes([0x53]) * 32, bytes([10, 15, 17, 19]), SSH_PORT]


def projection(route, path):
    value = scope(route)
    value[1][3] = path
    return value


def vectors(openssl, work):
    for label, route in [("direct", DIRECT), ("embedded", EMBEDDED)]:
        value = projection(route, PATH)
        yield f"{label}-scope", encode(value)
        yield label, signed_owner(openssl, work, value, version=ABSOLUTE)
    for label, route, name, version in [
        ("legacy-header", EMBEDDED, PATH, VERSION),
        ("resolved-relative-header", DIRECT, PATH, REQUIRED),
        ("missing-required-bit", DIRECT, PATH, [1, 2, 3]),
        ("relative", DIRECT, PATH[1:], ABSOLUTE),
        ("unbound", [0], PATH, ABSOLUTE),
        ("root-only", DIRECT, b"/", ABSOLUTE),
        ("double-slash", DIRECT, b"//inbox/file", ABSOLUTE),
        ("trailing", DIRECT, b"/inbox/file/", ABSOLUTE),
        ("parent", DIRECT, b"/inbox/../file", ABSOLUTE),
        ("dot", DIRECT, b"/inbox/./file", ABSOLUTE),
    ]:
        yield label, signed_owner(openssl, work, projection(route, name), version=version)


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--write", action="store_true")
    options = parser.parse_args()
    output = Path(__file__).resolve().parents[2] / "tests" / "remote_download" / "absolute-path.hex"
    with TemporaryDirectory(prefix="exacopy-absolute-vectors-") as work:
        result = []
        for name, data in vectors(options.openssl, Path(work)):
            result.extend([f"[{name}]", *textwrap.wrap(data.hex(), 76), ""])
    encoded = "\n".join(result)
    if options.write:
        output.write_text(encoded)
    assert output.read_text() == encoded
    print("Verified independently generated absolute-path owner and scope vectors.")


if __name__ == "__main__":
    main()
