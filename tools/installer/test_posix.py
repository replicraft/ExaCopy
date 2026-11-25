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
    environment = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(home / "xdg data"),
                       PATH="/usr/bin:/bin:/usr/sbin:/sbin")
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
        home / "backup-repository" / "key": b"synthetic recovery key\x00",
        home / ".exacopy" / "stages" / "partial": b"partial transfer\xff",
        home / ".exacopy" / "retained": b"retained incumbent",
        home / ".local" / "bin" / "other-command": b"foreign executable",
        home / ".profile": b"# existing PATH config\n",
    }
    for path, data in user_paths.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    launcher = home / ".local" / "bin" / "exacopy"
    launcher.write_bytes(b"foreign launcher")
    for arguments in ((), ("--dry-run",)):
        install("refuse unowned launcher without changing it", "valid", *arguments,
                expected="unowned launcher path is occupied")
        assert launcher.read_bytes() == b"foreign launcher"
        assert not store.exists()
    launcher.unlink()

    dry_install = install("dry run leaves selected store absent", "valid", "--dry-run")
    assert f"Launcher: {launcher}" in dry_install and "to your PATH" in dry_install
    assert not launcher.is_symlink()
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
    if platform.system() == "Darwin":
        darwin_resource_fork = "com.apple.ResourceFork"
        fork_bytes = b"independently attached resource data\x00\xff"
        for component in ("exacopy", "release.manifest", "release.sig", "intent"):
            owned = directory / component
            data_bytes = owned.read_bytes()
            identity_before = owned.stat().st_ino
            subprocess.run(["/usr/bin/xattr", "-wx", darwin_resource_fork, fork_bytes.hex(), owned],
                           check=True, capture_output=True, timeout=10)
            for arguments in (("--dry-run",), ("--quiesced",)):
                run("uninstall", f"preserve resource fork on {component} during {arguments[0]}",
                    *arguments, expected="resource fork")
                assert owned.stat().st_ino == identity_before
                assert owned.read_bytes() == data_bytes
                raw_fork = subprocess.check_output(
                    ["/usr/bin/xattr", "-px", darwin_resource_fork, owned], text=True, timeout=10)
                assert bytes.fromhex(raw_fork) == fork_bytes
                assert sha256(history.read_bytes()).digest() == history_digest
            subprocess.run(["/usr/bin/xattr", "-d", darwin_resource_fork, owned],
                           check=True, capture_output=True, timeout=10)
    run("uninstall", "remove only exact owned version files", "--quiesced")
    assert not directory.exists() and not launcher.is_symlink()
    history_bytes = history.read_bytes()
    assert sha256(history_bytes).digest() == history_digest
    owner_marker = store / ".owner"
    owner_bytes = owner_marker.read_bytes()
    for arguments in (("--quiesced",), ("--dry-run",)):
        repeated = run("uninstall", f"repeat uninstall reports absence during {arguments[0]}",
                       *arguments)
        assert repeated == f"Already absent: {directory}\n"
        assert not directory.exists()
        assert history.read_bytes() == history_bytes
        assert owner_marker.read_bytes() == owner_bytes

    alternate_certificate = temporary / "different.der"
    original_certificate = Path(fixture["publisher_certificate"]).read_bytes()
    alternate_certificate.write_bytes(original_certificate[:-1] + bytes([original_certificate[-1] ^ 1]))
    run("uninstall", "refuse absent version with wrong certificate", "--quiesced",
        credentials=[*auth[:3], str(alternate_certificate), *auth[4:]],
        expected="certificate does not match supplied pin")
    run("uninstall", "refuse absent unknown version", "--quiesced",
        credentials=[auth[0], "999.0.0", *auth[2:]], expected="does not match retained release history")
    foreign_history = history_bytes.replace(f"\n{version}\n".encode(), b"\n999.0.0\n")
    assert foreign_history != history_bytes
    history.write_bytes(foreign_history)
    run("uninstall", "refuse absent version with different history", "--quiesced",
        expected="does not match retained release history")
    assert history.read_bytes() == foreign_history
    history.write_bytes(b"unrecognized or incomplete history")
    run("uninstall", "refuse absent version with invalid history", "--quiesced",
        expected="invalid release sequence record")
    assert history.read_bytes() == b"unrecognized or incomplete history"
    history.write_bytes(history_bytes)
    history.rename(absent_history)
    run("uninstall", "refuse absent version with missing history", "--quiesced",
        expected="invalid release sequence record")
    assert absent_history.read_bytes() == history_bytes
    assert not history.exists()
    absent_history.rename(history)

    absent_store = home / "absent-store" / "install"
    run("uninstall", "refuse absent store without ownership", "--quiesced", root=absent_store,
        expected="no owned install store")
    assert not absent_store.exists()
    run("uninstall", "refuse unowned store without removing an incumbent", "--quiesced",
        root=foreign_root, expected="ownership record")
    assert foreign_file.read_bytes() == b"foreign install data"

    dangling_target = temporary / "missing-version-target"
    directory.symlink_to(dangling_target, target_is_directory=True)
    run("uninstall", "refuse a dangling selected-version link", "--quiesced",
        expected="unsafe or missing directory")
    assert directory.readlink() == dangling_target
    directory.unlink()

    pending.mkdir(mode=0o700)
    pending_evidence = pending / "unknown-receipt"
    pending_evidence.write_bytes(b"retained withdrawal evidence\x00\xff")
    for arguments in (("--quiesced",), ("--dry-run",)):
        run("uninstall", f"refuse absent selected version with withdrawal during {arguments[0]}",
            *arguments, expected="interrupted removal requires owner reconciliation")
        assert pending_evidence.read_bytes() == b"retained withdrawal evidence\x00\xff"
    pending_evidence.unlink()
    pending.rmdir()
    assert history.read_bytes() == history_bytes
    assert owner_marker.read_bytes() == owner_bytes
    assert all(path.read_bytes() == data for path, data in user_paths.items())
    install("refuse rollback after removing binaries", "lower-sequence", expected="rollback refused")
    install("reinstall exact verified version")
    assert executable.read_bytes() == signed_artifact
    assert launcher.readlink() == executable
    assert all(path.read_bytes() == data for path, data in user_paths.items())
    print("pass preserved profile, credentials, journal, backup, recovery key, stage, retained files, launcher and PATH")


if __name__ == "__main__":
    main()
