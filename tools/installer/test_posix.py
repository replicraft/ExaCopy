"""Exercise the offline installer in a disposable unprivileged HOME."""

from argparse import ArgumentParser
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory


REPO = Path(__file__).resolve().parents[2]


def release_target():
    architecture = {"aarch64": "aarch64", "arm64": "aarch64", "x86_64": "x86_64"}[platform.machine()]
    suffix = {"Darwin": "apple-darwin", "Linux": "unknown-linux-gnu"}[platform.system()]
    return f"{architecture}-{suffix}"


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-tool", type=Path,
                        default=Path(__file__).resolve().parents[1] / "installer_fixture.py")
    parser.add_argument("--artifact", type=Path, help="Optional real CLI fixture; never executed")
    options = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("run as an unprivileged user")

    temp_base = "/private/tmp" if platform.system() == "Darwin" else "/tmp"
    with TemporaryDirectory(prefix="exacopy-installer-test-", dir=temp_base) as temp:
        test_install(Path(temp), options)


def test_install(temporary, options):
    bundle_root = temporary / "bundles"
    command = [sys.executable, str(options.fixture_tool), str(bundle_root),
               "--target", release_target()]
    if options.artifact:
        command += ["--artifact", str(options.artifact)]
    fixture = json.loads(subprocess.check_output(command, text=True))
    home = temporary / "home"
    home.mkdir(mode=0o700)
    environment = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(home / "xdg data"))
    store = home / "Unicode Å space" / "install"
    version = fixture["version"]
    directory = store / "versions" / version
    executable = directory / "exacopy"
    pin = fixture["publisher_sha256"]
    auth = ["--version", version, "--publisher-cert", fixture["publisher_certificate"],
            "--publisher-sha256", pin]

    def run(action, label, *arguments, expected=None, root=store, credentials=auth):
        program = REPO / f"{action}.sh"
        command = [str(program), *credentials]
        if root is not None:
            command += ["--install-root", str(root)]
        command += list(map(str, arguments))
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30)
        combined = result.stdout + result.stderr
        if (expected is None and result.returncode != 0) or (
            expected is not None and (result.returncode == 0 or expected not in combined)
        ):
            raise AssertionError(f"{label}: status {result.returncode}\n{combined}")
        print(f"pass {label}")
        return result.stdout

    def install(label, bundle="valid", *arguments, **kwargs):
        return run("install", label, "--offline-bundle", bundle_root / bundle, *arguments, **kwargs)

    user_paths = {
        home / ".config" / "exacopy" / "credentials": b"owner credentials\x00dummy",
        home / ".local" / "share" / "exacopy" / "profile" / "journal": b"owner journal\xffdummy",
        home / "backup-repository" / "pack": b"backup content\x00\xff",
        home / ".exacopy" / "retained": b"retained incumbent",
        home / ".local" / "bin" / "exacopy": b"foreign launcher",
        home / ".profile": b"# existing PATH config\n",
    }
    for path, data in user_paths.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    install("dry run leaves selected store absent", "valid", "--dry-run")
    assert not store.exists()
    default_store = (home / "Library" / "Application Support" / "ExaCopy" / "install"
                     if platform.system() == "Darwin" else home / "xdg data" / "exacopy" / "install")
    assert str(default_store) in install("default path is scoped to fixture home", "valid",
                                         "--dry-run", root=None)
    assert not default_store.exists()

    for name, error in {
        "bad-signature": "signature verification failed",
        "wrong-target": "target mismatch",
        "wrong-hash": "SHA-256 mismatch",
        "wrong-size": "size mismatch",
        "wrong-publisher": "publisher pin mismatch",
        "wrong-version": "version mismatch",
        "expired": "validity interval",
        "future": "validity interval",
        "duplicate-field": "LF-terminated lines",
        "missing-final-lf": "LF-terminated lines",
        "wrong-format": "single raw CLI",
        "crlf": "manifest contains non-ASCII or control bytes",
        "embedded-nul": "manifest contains non-ASCII or control bytes",
    }.items():
        install(f"reject {name}", name, expected=error)
        assert not store.exists()

    install("reject invalid external certificate pin", expected="does not match supplied pin",
            credentials=[*auth[:-1], "0" * 64])
    assert not store.exists()

    extra_bundle = bundle_root / "extra"
    shutil.copytree(bundle_root / "valid", extra_bundle)
    (extra_bundle / "extra-file").write_bytes(b"foreign")
    install("reject extra bundle entries", "extra", expected="only the signed manifest")

    symlink_bundle = bundle_root / "symlink"
    shutil.copytree(bundle_root / "valid", symlink_bundle)
    (symlink_bundle / "exacopy").unlink()
    (symlink_bundle / "exacopy").symlink_to(bundle_root / "valid" / "exacopy")
    install("reject raw artifact symlink", "symlink", expected="single-link regular")

    foreign_root = home / "unowned" / "install"
    foreign_root.mkdir(mode=0o700, parents=True)
    foreign_file = foreign_root / "preexisting"
    foreign_file.write_bytes(b"foreign install data")
    install("reject unowned store", expected="ownership record", root=foreign_root)
    assert foreign_file.read_bytes() == b"foreign install data"

    linked_root = home / "link" / "install"
    linked_root.parent.mkdir()
    linked_root.symlink_to(foreign_root, target_is_directory=True)
    install("reject install-root symlink", expected="unsafe or missing directory", root=linked_root)
    assert foreign_file.read_bytes() == b"foreign install data"

    install("publish verified local CLI")
    signed_artifact = (bundle_root / "valid" / "exacopy").read_bytes()
    assert executable.read_bytes() == signed_artifact
    assert executable.stat().st_mode & 0o777 == 0o700
    identity = executable.stat().st_ino
    assert "Already installed" in install("idempotence checks the same installed inode")
    assert executable.stat().st_ino == identity

    install("refuse older release sequence", "lower-sequence", expected="rollback refused")
    install("refuse replacement at same sequence", "same-sequence-other-digest",
            expected="binds different signed metadata")
    run("uninstall", "refuse absent quiescence assertion", expected="requires --quiesced")
    run("uninstall", "dry uninstall preserves version", "--dry-run")
    assert executable.read_bytes() == signed_artifact

    lock = store / ".lifecycle-lock"
    lock.mkdir(mode=0o700)
    run("uninstall", "refuse concurrent or interrupted lifecycle", "--quiesced",
        expected="lifecycle lock is held")
    lock.rmdir()

    pending = store / "versions" / f".remove-{version}"
    pending.mkdir()
    run("uninstall", "refuse interrupted withdrawal", "--quiesced",
        expected="interrupted removal requires owner reconciliation")
    pending.rmdir()

    history = store / ".high-water"
    history_digest = sha256(history.read_bytes()).digest()
    absent_history = store / ".saved-high-water"
    history.rename(absent_history)
    install("refuse missing rollback history", expected="invalid release sequence record")
    absent_history.rename(history)

    extra = directory / ".extra"
    extra.write_bytes(b"foreign")
    run("uninstall", "preserve foreign version-directory entry", "--quiesced",
        expected="unexpected entries")
    assert extra.read_bytes() == b"foreign"
    extra.unlink()

    executable.write_bytes(bytes([signed_artifact[0] ^ 1]) + signed_artifact[1:])
    run("uninstall", "preserve tampered installation", "--quiesced", expected="SHA-256 mismatch")
    executable.write_bytes(signed_artifact)
    run("uninstall", "remove only exact owned version files", "--quiesced")
    assert not directory.exists()
    assert sha256(history.read_bytes()).digest() == history_digest
    install("refuse rollback after removing binaries", "lower-sequence", expected="rollback refused")
    install("reinstall exact verified version")
    assert executable.read_bytes() == signed_artifact
    assert all(path.read_bytes() == data for path, data in user_paths.items())
    print("pass preserved profile, credentials, journal, retained files, launcher and PATH")


if __name__ == "__main__":
    main()
