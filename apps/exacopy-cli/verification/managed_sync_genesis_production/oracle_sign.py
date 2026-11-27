"""Deterministic signing of independently reconstructed public fixture messages."""

import hashlib
import os
from pathlib import Path
import stat
import subprocess
from tempfile import TemporaryFile

SEED = bytes([0x51]) * 32  # Existing published test fixture, never a deployed key.
PRIVATE_DER = bytes.fromhex("302e020100300506032b657004220420") + SEED
PUBLIC_DER_HEADER = bytes.fromhex("302a300506032b6570032100")
OPENSSL = Path("/usr/bin/openssl")
OUTPUT_BOUND = 1024


class OracleUnavailable(RuntimeError):
    """A pinned prerequisite cannot be established before any fixture work."""


class OracleCleanupUnconfirmed(RuntimeError):
    """The independent verifier child could not be positively reaped."""


class Signer:
    def __init__(self, executable=OPENSSL, fd_root="/proc/self/fd", *, trust_owner=True, exec_by_fd=True):
        self.fd_root = fd_root
        self.exec_by_fd = exec_by_fd
        self.executable = executable
        self.node = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            node = os.fstat(self.node)
            if (not stat.S_ISREG(node.st_mode) or not 0 < node.st_size <= 32 * 1024 * 1024
                    or (trust_owner and (node.st_uid != 0 or node.st_mode & 0o7022))):
                raise ValueError("independent OpenSSL file failed owner or extent admission")
            self.stamp = self.metadata()
            with os.fdopen(os.dup(self.node), "rb") as reader:
                self.sha256 = hashlib.file_digest(reader, "sha256").hexdigest()
            self.check()
            version = self.command("version")
            if not version.startswith(b"OpenSSL 3."):
                raise ValueError("the fixed OpenSSL command is outside the version 3 profile")
            self.version = version.decode("ascii").strip()
            with TemporaryFile() as seed:
                seed.write(PRIVATE_DER)
                seed.seek(0)
                public = self.command("pkey", "-inform", "DER", "-in", self.name(seed),
                                      "-pubout", "-outform", "DER", held=(seed.fileno(),))
            if len(public) != len(PUBLIC_DER_HEADER) + 32 or not public.startswith(PUBLIC_DER_HEADER):
                raise ValueError("independent OpenSSL did not return canonical fixture public key")
            self.public = public[len(PUBLIC_DER_HEADER):]
        except BaseException:
            self.close()
            raise

    def close(self):
        os.close(self.node)

    def metadata(self):
        node = os.fstat(self.node)
        return node.st_dev, node.st_ino, node.st_mode, node.st_uid, node.st_size, node.st_mtime_ns, node.st_ctime_ns

    def check(self):
        named = self.executable.stat(follow_symlinks=False)
        if (self.metadata() != self.stamp
                or (named.st_dev, named.st_ino) != self.stamp[:2]):
            raise ValueError("independent held OpenSSL executable changed")

    def name(self, file):
        return f"{self.fd_root}/{file.fileno()}"

    def command(self, *args, held=()):
        self.check()
        child = subprocess.Popen(
            [str(self.executable), *args], executable=(f"{self.fd_root}/{self.node}" if self.exec_by_fd else str(self.executable)),
            pass_fds=(self.node, *held), env={"LC_ALL": "C", "OPENSSL_CONF": "/dev/null"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            try:
                status = child.wait(timeout=5)
            except BaseException as initial:
                try:
                    child.kill()
                except OSError:
                    pass
                try:
                    child.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired) as error:
                    raise OracleCleanupUnconfirmed("independent OpenSSL exit could not be confirmed") from error
                if isinstance(initial, subprocess.TimeoutExpired):
                    raise ValueError("independent OpenSSL exceeded its deadline") from None
                raise
            output = []
            for pipe in (child.stdout, child.stderr):
                os.set_blocking(pipe.fileno(), False)
                data = os.read(pipe.fileno(), OUTPUT_BOUND + 1)
                if len(data) > OUTPUT_BOUND or os.read(pipe.fileno(), 1):
                    raise ValueError("independent OpenSSL exceeded its output bound")
                output.append(data)
            if status != 0 or output[1]:
                raise ValueError("independent OpenSSL command failed")
            self.check()
            return output[0]
        finally:
            child.stdout.close()
            child.stderr.close()

    def sign(self, message):
        if not 0 < len(message) <= 2048:
            raise ValueError("fixture signing message outside supported extent")
        with TemporaryFile() as seed, TemporaryFile() as body:
            seed.write(PRIVATE_DER)
            body.write(message)
            seed.seek(0)
            body.seek(0)
            signature = self.command("pkeyutl", "-sign", "-rawin", "-keyform", "DER",
                                     "-inkey", self.name(seed), "-in", self.name(body),
                                     held=(seed.fileno(), body.fileno()))
        if len(signature) != 64:
            raise ValueError("independent OpenSSL's signature extent differs")
        return signature
