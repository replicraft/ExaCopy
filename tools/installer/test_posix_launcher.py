"""Exercise the real POSIX launcher in synthetic homes and interrupt its signed upgrade."""

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic, sleep

from test_posix import REPO, release_target


SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


class Installation:
    def __init__(self, temporary, release, home_name):
        self.temporary = temporary
        self.release = release
        self.home = temporary / home_name
        self.home.mkdir(mode=0o700)
        self.bin = self.home / ".local" / "bin"
        self.launcher = self.bin / "exacopy"
        self.store = self.home / "store with space" / "install"
        self.record = self.store / ".launcher"
        self.paths = f"{self.bin}:{SYSTEM_PATH}"
        self.original_version = release["version"]
        self.next_version = "0.2.0"

    def executable(self, version):
        return self.store / "versions" / version / "exacopy"

    def environment(self):
        return {"HOME": str(self.home), "PATH": self.paths}

    def command(self, action, version, *options, source=REPO, root=None):
        arguments = [
            source / f"{action}.sh", "--version", version, "--install-root", root or self.store,
            "--publisher-cert", self.release["publisher_certificate"],
            "--publisher-sha256", self.release["publisher_sha256"], *options,
        ]
        if action == "install":
            bundle = "valid" if version == self.original_version else "launcher-upgrade"
            arguments += ["--offline-bundle", Path(self.release["directory"]) / bundle]
        return arguments

    def run(self, action, label, version, *options, error=None, root=None, cwd=None, source=REPO):
        result = subprocess.run(self.command(action, version, *options, root=root, source=source),
                                env=self.environment(), cwd=cwd, capture_output=True, text=True, timeout=45)
        if error is None:
            assert result.returncode == 0, (label, result)
        else:
            assert result.returncode != 0 and error in result.stderr, (label, result)
        print(f"pass {label}")
        return result.stdout

    def assert_selection(self, version):
        assert self.launcher.readlink() == self.executable(version)
        result = subprocess.check_output(["exacopy", "two words"], env=self.environment(),
                                         text=True, timeout=5)
        assert result == "synthetic execution: two words\n"

    def expect_crash(self, action, version, relative, anchor, *, options=()):
        # Copy the candidate and insert a fixture-only process stop at the named effect boundary.
        # The installer runs its real validation, filesystem tools and barriers before the stop.
        with TemporaryDirectory(prefix="fixture-stop-", dir=self.temporary) as source_dir:
            source = Path(source_dir)
            shutil.copytree(REPO / "tools" / "installer", source / "tools" / "installer")
            shutil.copy2(REPO / f"{action}.sh", source / f"{action}.sh")
            # A forced kill skips the installer's trap. Keep its scratch in this
            # fixture's removable tree while retaining the real install effects.
            installer_temp = source / "installer-scratch"
            installer_temp.mkdir(mode=0o700)
            environment = self.environment() | {"EXACOPY_FIXTURE_TEMP": str(installer_temp)}
            setup = source / "tools" / "installer" / "posix.sh"
            anchor_setup = "\thost_profile\n"
            native_setup = setup.read_text()
            assert native_setup.count(anchor_setup) == 1
            setup.write_text(native_setup.replace(
                anchor_setup, anchor_setup + '\ttemp_base="$EXACOPY_FIXTURE_TEMP"\n'))
            script = source / relative
            original = script.read_text()
            assert original.count(anchor) == 1
            script.write_text(original.replace(anchor, f'{anchor}\n\tkill -STOP "$$"'))
            with subprocess.Popen(self.command(action, version, *options, source=source),
                                  env=environment, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE) as process:
                deadline = monotonic() + 45
                try:
                    while monotonic() < deadline:
                        waited, status = os.waitpid(process.pid, os.WNOHANG | os.WUNTRACED)
                        if waited:
                            if os.WIFSTOPPED(status):
                                assert os.WSTOPSIG(status) == signal.SIGSTOP
                                break
                            process.returncode = os.waitstatus_to_exitcode(status)
                            output, error = process.communicate(timeout=5)
                            raise AssertionError((process.returncode, output, error))
                        sleep(0.05)
                    else:
                        raise TimeoutError("fixture did not reach launcher boundary")
                finally:
                    if process.returncode is None:
                        process.kill()
                assert process.wait(timeout=5) == -signal.SIGKILL

    def clear_fixture_locks(self):
        # Fixture-controlled reconciliation after the test verifies that both locks block.
        (self.store / ".lifecycle-lock").rmdir()
        (self.bin / ".exacopy-lifecycle-lock").rmdir()


def test_launcher(temporary, release):
    case = Installation(temporary, release, "synthetic home with ünicode")
    old = case.original_version
    new = case.next_version
    case.bin.mkdir(parents=True)
    foreign = case.home / "other executables"
    foreign.mkdir()
    foreign_command = foreign / "exacopy"
    foreign_command.write_bytes(b"foreign executable\n")
    foreign_command.chmod(0o700)
    case.paths = f"{case.bin}:{foreign}:{SYSTEM_PATH}"
    case.run("install", "refuse to shadow a foreign command later in PATH", old,
             error="would be shadowed")
    assert foreign_command.read_bytes() == b"foreign executable\n" and not case.store.exists()
    case.paths = f"{case.bin}:{SYSTEM_PATH}"

    foreign_directory = case.home / "foreign directory"
    foreign_directory.mkdir()
    case.launcher.symlink_to(foreign_directory, target_is_directory=True)
    case.run("install", "preserve a foreign launcher symlink to a directory", old,
             error="unowned launcher path is occupied")
    assert case.launcher.readlink() == foreign_directory and not list(foreign_directory.iterdir())
    case.launcher.unlink()
    case.launcher.mkdir()
    case.run("install", "preserve a foreign launcher directory", old,
             error="unowned launcher path is occupied")
    assert case.launcher.is_dir() and not list(case.launcher.iterdir())
    case.launcher.rmdir()
    case.bin.rmdir()
    case.run("install", "preview with no launcher directory leaves it absent", old, "--dry-run")
    assert not case.bin.exists() and not case.store.exists()

    output = case.run("install", "publish and invoke the stable launcher through PATH", old)
    assert f"Launcher: {case.launcher}\n" in output and "to your PATH" not in output
    case.assert_selection(old)
    initial_inode = case.launcher.lstat().st_ino
    initial_record = case.record.read_bytes()
    old_digest = sha256(case.executable(old).read_bytes()).digest()
    assert case.record.stat().st_mode & 0o777 == 0o600
    assert "Already installed" in case.run("install", "repeat keeps the exact launcher inode", old)
    assert case.launcher.lstat().st_ino == initial_inode
    assert case.record.read_bytes() == initial_record

    for equivalent in ("./bin", f"{case.bin}/"):
        case.paths = f"{equivalent}:{SYSTEM_PATH}"
        output = case.run("install", f"accept equivalent PATH entry {equivalent}", old, cwd=case.bin.parent)
        assert "Already installed" in output and "to your PATH" not in output
        assert case.launcher.lstat().st_ino == initial_inode
        assert case.record.read_bytes() == initial_record
    case.paths = f"{case.bin}:{SYSTEM_PATH}"

    alternate = case.home / "another store" / "install"
    case.run("install", "refuse another store's claim on the same bin entry", old,
             root=alternate, error="unowned launcher path is occupied")
    assert not alternate.exists()
    case.run("install", "preview an upgrade without touching either selector or store", new, "--dry-run")
    assert not case.executable(new).exists() and case.record.read_bytes() == initial_record
    assert case.launcher.lstat().st_ino == initial_inode

    pinned_link = case.bin / "known selector fixture"
    case.launcher.rename(pinned_link)
    case.launcher.symlink_to(case.executable(old))
    foreign_inode = case.launcher.lstat().st_ino
    case.run("install", "refuse a rebound selector even with matching text", new,
             error="does not match either recorded selector state")
    case.run("uninstall", "refuse to withdraw a rebound selector", old, "--quiesced",
             error="does not match either recorded selector state")
    assert case.launcher.lstat().st_ino == foreign_inode and case.executable(old).exists()
    case.launcher.unlink()
    pinned_link.rename(case.launcher)

    case.record.write_bytes(initial_record + b"future state\n")
    case.run("install", "refuse an unrecognized receipt without changes", new,
             error="invalid launcher transaction record")
    assert case.record.read_bytes() == initial_record + b"future state\n"
    assert case.launcher.lstat().st_ino == initial_inode
    case.record.write_bytes(initial_record)

    if platform.system() == "Darwin":
        attribute = "com.apple.ResourceFork"
        contents = "736570617261746520636f6e74656e74"
        subprocess.run(["/usr/bin/xattr", "-wx", attribute, contents, case.record],
                       check=True, capture_output=True, timeout=5)
        case.run("install", "preserve a resource fork attached to the selector record", new,
                 error="resource fork")
        actual = subprocess.check_output(["/usr/bin/xattr", "-px", attribute, case.record],
                                         timeout=5)
        assert bytes.fromhex(actual.decode()) == bytes.fromhex(contents)
        assert case.record.read_bytes() == initial_record and not case.executable(new).exists()
        subprocess.run(["/usr/bin/xattr", "-d", attribute, case.record],
                       check=True, capture_output=True, timeout=5)

        history = case.store / ".high-water"
        original_history = history.read_bytes()
        history_identity = history.stat().st_ino
        subprocess.run(["/usr/bin/xattr", "-wx", attribute, contents, history],
                       check=True, capture_output=True, timeout=5)
        for options in (("--dry-run",), ()):
            case.run("install", "preserve a resource fork attached to release history", new,
                     *options, error="resource fork")
            actual = subprocess.check_output(["/usr/bin/xattr", "-px", attribute, history],
                                             timeout=5)
            assert bytes.fromhex(actual.decode()) == bytes.fromhex(contents)
            assert history.stat().st_ino == history_identity
            assert history.read_bytes() == original_history
            assert case.record.read_bytes() == initial_record
            assert case.launcher.lstat().st_ino == initial_inode
            assert not case.executable(new).exists()
        subprocess.run(["/usr/bin/xattr", "-d", attribute, history],
                       check=True, capture_output=True, timeout=5)

    case.expect_crash("install", new, "tools/installer/launcher.sh",
                      '\tpublish_launcher_intent "$next_launcher"')
    case.assert_selection(old)
    assert case.launcher.lstat().st_ino == initial_inode
    assert case.executable(new).is_file()
    interrupted_record = case.record.read_bytes()
    assert interrupted_record != initial_record
    assert b"0.1.0|" in interrupted_record and b"0.2.0|" in interrupted_record
    case.run("install", "retain locks and launch the prior version after pre-switch kill", new,
             error="lifecycle lock is held")
    case.clear_fixture_locks()
    leftover = tuple(case.bin.glob(".exacopy-selector.*"))
    assert len(leftover) == 1 and (leftover[0] / "link").is_symlink()

    history = case.store / ".high-water"
    pending_history = history.read_bytes(), history.stat().st_ino
    pending_record_inode = case.record.stat().st_ino
    pending_new_digest = sha256(case.executable(new).read_bytes()).digest()
    case.paths = SYSTEM_PATH
    output = case.run("install", "preview pending launcher activation after pre-switch kill",
                      new, "--dry-run")
    case.paths = f"{case.bin}:{SYSTEM_PATH}"
    assert output.splitlines() == [
        f"Verified installed release: {case.executable(new)}",
        f"Would activate launcher: {case.launcher}",
    ]
    case.assert_selection(old)
    assert case.launcher.lstat().st_ino == initial_inode
    assert case.record.read_bytes() == interrupted_record
    assert case.record.stat().st_ino == pending_record_inode
    assert (history.read_bytes(), history.stat().st_ino) == pending_history
    assert sha256(case.executable(new).read_bytes()).digest() == pending_new_digest
    assert sha256(case.executable(old).read_bytes()).digest() == old_digest
    assert tuple(case.bin.glob(".exacopy-selector.*")) == leftover

    case.expect_crash("install", new, "tools/installer/launcher.sh", '\tlauncher_current=$next_launcher')
    case.assert_selection(new)
    assert sha256(case.executable(old).read_bytes()).digest() == old_digest
    case.clear_fixture_locks()
    selected_inode = case.launcher.lstat().st_ino
    selected_record = case.record.read_bytes()
    selected_record_inode = case.record.stat().st_ino
    selected_history = history.read_bytes()
    selected_history_inode = history.stat().st_ino
    new_digest = sha256(case.executable(new).read_bytes()).digest()
    with TemporaryDirectory(prefix="fixture-flush-failure-", dir=case.temporary) as source_dir:
        source = Path(source_dir)
        shutil.copytree(REPO / "tools" / "installer", source / "tools" / "installer")
        shutil.copy2(REPO / "install.sh", source / "install.sh")
        # Simulate an unavailable flush after the real process interruption.
        with (source / "tools" / "installer" / "posix.sh").open("a") as setup:
            setup.write("\nsync() { return 1; }\n")
        output = case.run("install", "refuse to complete pending activation when the retry cannot flush",
                          new, source=source, error="cannot flush the verified launcher selection")
        assert not output
    case.assert_selection(new)
    assert case.launcher.lstat().st_ino == selected_inode
    assert case.record.read_bytes() == selected_record
    assert case.record.stat().st_ino == selected_record_inode
    assert history.read_bytes() == selected_history
    assert history.stat().st_ino == selected_history_inode
    assert sha256(case.executable(new).read_bytes()).digest() == new_digest
    assert sha256(case.executable(old).read_bytes()).digest() == old_digest
    output = case.run("install", "complete the verified selection after post-switch kill", new)
    assert f"Already installed: {case.executable(new)}\n" in output
    assert case.launcher.lstat().st_ino == selected_inode
    assert (leftover[0] / "link").is_symlink()
    output = case.run("install", "preview the already selected release", new, "--dry-run")
    assert output.splitlines() == [
        f"Already installed: {case.executable(new)}",
        f"Launcher: {case.launcher}",
    ]
    assert case.launcher.lstat().st_ino == selected_inode

    case.expect_crash("uninstall", new, "tools/installer/store.sh", "\twithdraw_launcher",
                      options=("--quiesced",))
    assert not case.launcher.is_symlink() and case.executable(new).is_file()
    assert sha256(case.executable(old).read_bytes()).digest() == old_digest
    case.clear_fixture_locks()
    output = case.run("install", "preview activation when the selector was withdrawn", new, "--dry-run")
    assert output.splitlines() == [
        f"Verified installed release: {case.executable(new)}",
        f"Would activate launcher: {case.launcher}",
    ]
    assert not case.launcher.is_symlink() and not case.launcher.exists()
    assert sha256(case.executable(new).read_bytes()).digest() == new_digest
    case.run("uninstall", "complete verified withdrawal after selector removal", new, "--quiesced")
    assert not case.launcher.is_symlink() and not case.executable(new).exists()
    assert case.executable(old).is_file()
    case.run("uninstall", "repeat verified uninstall with absent selector", new, "--quiesced")
    case.run("install", "reactivate the same authenticated release", new)
    case.assert_selection(new)
    selected_inode = case.launcher.lstat().st_ino
    removed = case.run("uninstall", "remove an inactive release without touching the selector",
                       old, "--quiesced")
    assert "Removed launcher" not in removed
    assert case.launcher.lstat().st_ino == selected_inode and not case.executable(old).exists()
    case.assert_selection(new)


def main():
    if os.geteuid() == 0:
        raise SystemExit("run as an unprivileged user")
    temp_base = "/private/tmp" if platform.system() == "Darwin" else "/tmp"
    with TemporaryDirectory(prefix="exacopy-launcher-tests-", dir=temp_base) as base:
        temporary = Path(base)
        synthetic_artifact = temporary / "synthetic-executable"
        synthetic_artifact.write_bytes(b'#!/bin/sh\nprintf "synthetic execution: %s\\n" "$1"\n')
        release = json.loads(subprocess.check_output([
            sys.executable, REPO / "tools" / "installer_fixture.py", temporary / "bundles",
            "--target", release_target(), "--artifact", synthetic_artifact, "--launcher-upgrade",
        ], text=True, timeout=30))
        test_launcher(temporary, release)


if __name__ == "__main__":
    main()
