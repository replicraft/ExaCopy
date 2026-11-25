"""Exercise latest-release admission in a disposable HOME with scripted HTTP."""

from argparse import ArgumentParser
from hashlib import sha256
from io import BytesIO
import gzip
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

from test_posix import REPO, release_target


GITHUB = "https://github.com/replicraft/ExaCopy/releases"
STORAGE = "https://release-assets.githubusercontent.com/github-production-release-asset"
ARCHIVE = f"exacopy-cli-{release_target()}.tar.gz"
MEMBERS = ("exacopy", "release.manifest", "release.sig")

# Stub curl only in the disposable copy. The root entrypoint, argument
# processing, request options, redirect policy and release verification run.
MOCK_CURL = """\
import json
import os
from pathlib import Path
import shutil
import sys

arguments = sys.argv[1:]
url = arguments[-1]
assert arguments[0] == "--disable"
assert "--location" not in arguments
assert arguments[arguments.index("--proto") + 1] == "=https"
assert arguments[arguments.index("--write-out") + 1] == "%{size_header} %{http_code} %{redirect_url}!"
method = "HEAD" if "--head" in arguments else "GET"
output = Path(arguments[arguments.index("--output") + 1])
with open(os.environ["FIXTURE_REQUESTS"], "a") as log:
    print(json.dumps([method, url, str(output.parent)]), file=log)
response, file, *header_size = json.loads(Path(os.environ["FIXTURE_ROUTES"]).read_text())[method + " " + url]
if file:
    shutil.copyfile(file, output)
sys.stdout.write(f"{header_size[0] if header_size else 123} {response}!")
"""


def make_tar(bundle, mutation=None):
    stream = BytesIO()
    format = tarfile.PAX_FORMAT if mutation == "pax" else tarfile.USTAR_FORMAT
    with tarfile.open(fileobj=stream, mode="w", format=format) as output:
        for name in MEMBERS:
            data = (bundle / name).read_bytes()
            member = tarfile.TarInfo(name)
            member.size = len(data)
            if name == "exacopy":
                member = change_artifact_member(member, mutation)
            output.addfile(member, BytesIO(data))
        if mutation in ("extra", "duplicate"):
            member = tarfile.TarInfo("foreign" if mutation == "extra" else "exacopy")
            member.size = 1
            output.addfile(member, BytesIO(b"x"))
    data = stream.getvalue()
    if mutation == "oversized":
        header = bytearray(data[:512])
        header[124:136] = b"02000000001\0"  # 256 MiB + 1, with valid header checksum.
        header[148:156] = b" " * 8
        header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
        data = header + data[512:]
    elif mutation == "header-checksum":
        data = data[:148] + b"000000\0 " + data[156:]
    elif mutation == "post-terminator":
        data += b"X" * 512
    elif mutation == "too-much-padding":
        data += b"\0" * 10240
    compressed = gzip.compress(data, mtime=0)
    if mutation == "gzip-crc":
        compressed = compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:]
    elif mutation == "gzip-truncated":
        compressed = compressed[:-1]
    elif mutation == "gzip-extra":
        compressed += b"a"
    elif mutation == "gzip-concatenated":
        compressed += gzip.compress(b"", mtime=0)
    return compressed


def change_artifact_member(member, mutation):
    if mutation == "traversal":
        member.name = "../escape"
    elif mutation == "nested":
        member.name = "bundle/exacopy"
    elif mutation == "absolute":
        member.name = "/exacopy"
    elif mutation in ("symbolic-link", "hard-link"):
        member.type = tarfile.SYMTYPE if mutation == "symbolic-link" else tarfile.LNKTYPE
        member.size = 0
        member.linkname = "../escape"
    elif mutation == "pax":
        member.pax_headers = {"comment": "hidden PAX extension member"}
    return member


def mock_source(base):
    source = base / "source"
    helpers = source / "tools" / "installer"
    helpers.mkdir(parents=True)
    for name in ("install.sh", "uninstall.sh"):
        shutil.copy2(REPO / name, source)
    for name in ("posix.sh", "download.sh", "manifest.sh", "store.sh", "unpack_release.pl"):
        shutil.copy2(REPO / "tools" / "installer" / name, helpers)
    curl_py = source / "curl.py"
    curl_py.write_text(MOCK_CURL)
    curl = source / "curl"
    curl.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(curl_py))} \"$@\"\n")
    curl.chmod(0o700)
    downloader = helpers / "download.sh"
    original = downloader.read_text()
    assert original.count("/usr/bin/curl") == 3
    downloader.write_text(original.replace("/usr/bin/curl", shlex.quote(str(curl))))
    return source


def exercise(base):
    source = mock_source(base)
    fixtures = base / "fixtures"
    metadata = json.loads(subprocess.check_output([
        sys.executable, str(REPO / "tools" / "installer_fixture.py"), str(fixtures),
        "--target", release_target(),
    ]))
    version = metadata["version"]
    tag_url = f"{GITHUB}/tag/v{version}"
    asset_url = f"{GITHUB}/download/v{version}"
    latest_request = f"HEAD {GITHUB}/latest"
    checksum_request = f"GET {asset_url}/SHA256SUMS.txt"
    archive_request = f"GET {asset_url}/{ARCHIVE}"
    checksum_storage = f"{STORAGE}/1234/checksums?filename=SHA256SUMS.txt&sig=A%2BB%2FC"
    archive_storage = f"{STORAGE}/1234/archive?filename={ARCHIVE}&sig=A%2BB%2FC"
    checksums, archive, routes, requests = (base / name for name in (
        "SHA256SUMS.txt", ARCHIVE, "routes.json", "requests.jsonl",
    ))
    allowed = {
        latest_request: [f"302 {tag_url}", None],
        checksum_request: [f"302 {checksum_storage}", None],
        f"GET {checksum_storage}": ["200 ", str(checksums)],
        archive_request: [f"302 {archive_storage}", None],
        f"GET {archive_storage}": ["200 ", str(archive)],
    }
    home = base / "home"
    home.mkdir(mode=0o700)
    root = home / "custom dir" / "install"
    default = (home / "Library" / "Application Support" / "ExaCopy" / "install"
               if platform.system() == "Darwin" else home / "xdg space" / "exacopy" / "install")
    credentials = ["--publisher-cert", metadata["publisher_certificate"],
                   "--publisher-sha256", metadata["publisher_sha256"]]
    environment = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(home / "xdg space"),
                       FIXTURE_ROUTES=str(routes), FIXTURE_REQUESTS=str(requests))
    foreign = home / "backup"
    foreign.write_bytes(b"preserve incumbent content\x00\xff")

    def prepare(bundle="valid", mutation=None):
        content = make_tar(fixtures / bundle, mutation)
        archive.write_bytes(content)
        row = sha256(content).hexdigest().encode("ascii") + b"  " + ARCHIVE.encode("ascii") + b"\n"
        checksums.write_bytes(row)
        return row

    def run(label, *flags, error=None, special_routes=None, expected_requests=None,
            install_root=root, auth=credentials, operation="install"):
        routes.write_text(json.dumps(allowed if special_routes is None else allowed | special_routes))
        requests.write_text("")
        executable = source / f"{operation}.sh"
        command = [str(executable), *auth, *flags]
        if install_root is not None:
            command += ["--install-root", str(install_root)]
        output = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=45)
        if error is None:
            assert output.returncode == 0, (label, output)
        else:
            assert output.returncode != 0 and error in output.stderr, (label, output)
        actual = [json.loads(line) for line in requests.read_text().splitlines()]
        assert all(not Path(parent).exists() for _, _, parent in actual), (label, actual)
        observed = [f"{method} {url}" for method, url, _ in actual]
        assert observed == (list(allowed) if expected_requests is None else expected_requests), (label, observed)
        assert foreign.read_bytes() == b"preserve incumbent content\x00\xff"
        print(f"pass {label}", flush=True)
        return output.stdout

    prepare()
    run("latest flags require out-of-band trust", "--latest", auth=[],
        error="independently trusted", expected_requests=[])
    run("wrong supplied publisher pin stops before HTTP", auth=[*credentials[:-1], "0" * 64],
        error="does not match supplied pin", expected_requests=[])
    run("reject contradictory latest and offline inputs", "--latest", "--version", version,
        "--offline-bundle", str(fixtures / "valid"), error="mutually exclusive", expected_requests=[])
    run("latest makes no network request during uninstall", "--latest", "--version", version,
        operation="uninstall", error="applies to install", expected_requests=[])
    run("exact version expectation checked before asset request", "--version", "0.1.1",
        error="does not match --version", expected_requests=[latest_request])
    for location in (
        tag_url.replace("https:", "http:"),
        tag_url.replace("github.com/", "github.com.example.com/"),
        tag_url.replace("/replicraft/", "/other/"),
        tag_url.replace("/tag/", "/download/"),
    ):
        run(f"refuse latest redirect {location}", error="did not redirect to an ExaCopy release tag",
            special_routes={latest_request: [f"302 {location}", None]}, expected_requests=[latest_request])
    for suffix in ("-alpha", "?x=1", "/y", "%2F", ".0"):
        run(f"refuse noncanonical tag suffix {suffix}", error="tag is not vN.N.N",
            special_routes={latest_request: [f"302 {tag_url}{suffix}", None]},
            expected_requests=[latest_request])

    run("refuse asset redirect outside GitHub CDN", error="outside GitHub release storage",
        special_routes={checksum_request: ["302 https://release-assets.githubusercontent.com.example.com/evil", None]},
        expected_requests=[latest_request, checksum_request])
    run("refuse excessive response headers", error="cannot download release asset",
        special_routes={checksum_request: [f"302 {checksum_storage}", None, 16385]},
        expected_requests=[latest_request, checksum_request])
    run("refuse a trailing URL control byte", error="cannot resolve latest GitHub release",
        special_routes={latest_request: [f"302 {tag_url}\n", None]}, expected_requests=[latest_request])
    run("refuse second asset redirect", error="unexpected response from GitHub release storage",
        special_routes={f"GET {checksum_storage}": [f"302 {archive_storage}", None]},
        expected_requests=[latest_request, checksum_request, f"GET {checksum_storage}"])

    row = prepare()
    for name, invalid in {
        "missing final LF": row[:-1],
        "duplicate row": row * 2,
        "CRLF": row[:-1] + b"\r\n",
        "ASCII NUL": row[:10] + b"\0" + row[11:],
        "uppercase hash": row[:64].upper() + row[64:],
        "extra path syntax": row[:66] + b"../" + row[66:],
        "missing target": row[:66] + b"exacopy-cli-x86_64-pc-windows-msvc.zip\n",
    }.items():
        checksums.write_bytes(invalid)
        run(f"refuse {name} checksum index", error="invalid release SHA256SUMS.txt",
            expected_requests=list(allowed)[:3])
    checksums.write_bytes(b"a" * 4097)
    run("refuse oversized checksum index", error="cannot download release asset from GitHub storage",
        expected_requests=list(allowed)[:3])

    prepare()
    archive.write_bytes(archive.read_bytes()[:-1] + b"X")
    run("refuse archive digest mismatch before unpack", error="archive SHA-256 mismatch")
    for name in (
        "extra", "duplicate", "traversal", "nested", "absolute", "symbolic-link", "hard-link", "pax",
        "oversized", "header-checksum", "post-terminator", "too-much-padding", "gzip-crc",
        "gzip-truncated", "gzip-extra", "gzip-concatenated",
    ):
        prepare(mutation=name)
        run(f"refuse hostile archive {name}", error="invalid ExaCopy release archive")
        assert not root.exists() and not default.exists()
    for name, error in (
        ("bad-signature", "signature verification failed"),
        ("wrong-target", "target mismatch"),
        ("wrong-version", "version mismatch"),
        ("wrong-hash", "artifact SHA-256 mismatch"),
    ):
        prepare(name)
        run(f"authenticated inner checks still reject {name}", error=error)
        assert not root.exists() and not default.exists()

    prepare()
    stdout = run("latest default install path dry run", "--dry-run", install_root=None)
    assert str(default / "versions" / version / "exacopy") in stdout
    assert not default.exists()
    stdout = run("latest override publishes authenticated bytes", "--latest", "--version", version)
    executable = root / "versions" / version / "exacopy"
    signed_bytes = (fixtures / "valid" / "exacopy").read_bytes()
    assert str(executable) in stdout and executable.read_bytes() == signed_bytes
    assert executable.stat().st_mode & 0o777 == 0o700
    identity = executable.stat().st_ino
    assert "Already installed" in run("latest repeat verifies owned version")
    assert executable.stat().st_ino == identity
    prepare("lower-sequence")
    run("latest refuses signed rollback", error="rollback refused")
    assert executable.stat().st_ino == identity and executable.read_bytes() == signed_bytes
    run("offline uninstall removes latest installed owned bytes", "--version", version, "--quiesced",
        operation="uninstall", expected_requests=[])
    assert not executable.exists()
    assert (root / ".high-water").is_file()


def exercise_release(base, release):
    source = mock_source(base)
    asset_url = f"{GITHUB}/download/v{release.version}"
    archive_storage = f"{STORAGE}/fixture/archive"
    checksum_storage = f"{STORAGE}/fixture/checksums"
    allowed = {
        f"HEAD {GITHUB}/latest": [f"302 {GITHUB}/tag/v{release.version}", None],
        f"GET {asset_url}/SHA256SUMS.txt": [f"302 {checksum_storage}", None],
        f"GET {checksum_storage}": ["200 ", str(release.checksum_index.resolve(strict=True))],
        f"GET {asset_url}/{ARCHIVE}": [f"302 {archive_storage}", None],
        f"GET {archive_storage}": ["200 ", str(release.archive.resolve(strict=True))],
    }
    routes = base / "routes.json"
    requests = base / "requests.jsonl"
    routes.write_text(json.dumps(allowed))
    home = base / "home"
    home.mkdir(mode=0o700)
    root = home / "install"
    environment = dict(os.environ, HOME=str(home), FIXTURE_ROUTES=str(routes),
                       FIXTURE_REQUESTS=str(requests))
    certificate = base / "fixture-publisher.der"
    shutil.copyfile(release.publisher_cert, certificate)
    certificate.chmod(0o600)
    credentials = ["--version", release.version, "--publisher-cert", str(certificate),
                   "--publisher-sha256", release.publisher_sha256, "--install-root", str(root)]
    run = subprocess.run([str(source / "install.sh"), *credentials], env=environment,
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run
    actual = [json.loads(line) for line in requests.read_text().splitlines()]
    assert [f"{method} {url}" for method, url, _ in actual] == list(allowed)
    assert all(not Path(scratch).exists() for _, _, scratch in actual)
    executable = root / "versions" / release.version / "exacopy"
    assert str(executable) in run.stdout and executable.stat().st_mode & 0o777 == 0o700
    with tarfile.open(release.archive, "r:gz") as archive, executable.open("rb") as installed:
        with archive.extractfile("exacopy") as packed:
            assert sha256_stream(installed) == sha256_stream(packed)
    run = subprocess.run([str(source / "uninstall.sh"), *credentials, "--quiesced"], env=environment,
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0 and not executable.exists(), run
    assert (root / ".high-water").is_file()
    print(f"pass release candidate install/reverify/uninstall for {ARCHIVE}")


def sha256_stream(stream):
    digest = sha256()
    while chunk := stream.read(65536):
        digest.update(chunk)
    return digest.digest()


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--checksum-index", type=Path)
    parser.add_argument("--publisher-cert", type=Path)
    parser.add_argument("--publisher-sha256")
    parser.add_argument("--version")
    release = parser.parse_args()
    supplied = vars(release).values()
    if any(supplied) and not all(supplied):
        parser.error("supply all five release fixture arguments together")
    if os.geteuid() == 0:
        parser.error("run as an unprivileged user")
    temporary_root = "/private/tmp" if platform.system() == "Darwin" else "/tmp"
    with TemporaryDirectory(prefix="exacopy-latest-test-", dir=temporary_root) as temp:
        if all(supplied):
            exercise_release(Path(temp), release)
        else:
            exercise(Path(temp))
