#!/usr/bin/env python3
"""Opt in to a bounded, disk-only sccache session for a Cargo development build."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time

VERSION = "0.18.0"
CACHE_BYTES = 1024**3
START_SECONDS = 10
STOP_SECONDS = 5


def cargo_command(arguments, ci):
    args = arguments[1:] if arguments[:1] == ["--"] else arguments
    if not args or args[0] not in ("build", "check"):
        raise ValueError("select Cargo build or check")
    if any(arg in ("--", "-r", "--release", "--profile", "--config")
           or arg.startswith(("--profile=", "--config=")) for arg in args[1:]):
        raise ValueError("this wrapper only accepts development compilation without Cargo config overrides")
    toolchain = ["+1.100.0"] if ci else []
    return ["cargo", *toolchain, args[0], "--profile", "dev", *args[1:]]


def cache_root(repo, ci, environ, system, machine):
    if ci:
        if system != "linux" or machine != "x86_64" or not environ.get("RUNNER_TEMP"):
            raise ValueError("the pinned CI cache supports Linux x86_64 with RUNNER_TEMP")
        return Path(environ["RUNNER_TEMP"]).resolve(strict=True) / "exacopy-sccache"
    if system not in ("darwin", "linux"):
        raise ValueError("isolated local sccache requires macOS or Linux")
    return repo / "target" / "sccache"


def scoped_environment(environ, executable, session):
    scoped = {name: value for name, value in environ.items() if not name.startswith("SCCACHE_")}
    scoped.update({
        "RUSTC_WRAPPER": str(executable),
        "RUSTC_WORKSPACE_WRAPPER": "",
        "CARGO_INCREMENTAL": "0",
        "SCCACHE_CONF": str(session / "config.toml"),
        "SCCACHE_SERVER_UDS": str(session / "s"),
        # Refuse to fall back to another daemon if a Unix socket cannot be used.
        "SCCACHE_SERVER_PORT": "0",
        "SCCACHE_IDLE_TIMEOUT": "60",
        "SCCACHE_CLIENT_SIDE": "1",
    })
    return scoped


@contextmanager
def locked_cache(root):
    import fcntl

    cache = root / VERSION
    if cache.resolve() != cache:
        raise ValueError("the sccache directory must be inside its designated root without symlinks")
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    if cache.resolve(strict=True) != cache:
        raise ValueError("the sccache directory changed while opening it")
    descriptor = os.open(cache / "session.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+") as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("another ExaCopy sccache session holds this cache") from error
        yield cache


def configure(config, cache):
    disk = cache / "objects"
    if disk.resolve() != disk:
        raise ValueError("the sccache object directory must not be a symlink")
    disk.mkdir(mode=0o700, exist_ok=True)
    config.write_text(f"[cache.disk]\ndir = {json.dumps(str(disk), ensure_ascii=False)}\nsize = {CACHE_BYTES}\n",
                      encoding="utf-8")


def wait_ready(server, socket):
    deadline = time.monotonic() + START_SECONDS
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise ValueError(f"the private sccache server exited with status {server.returncode}")
        if socket.is_socket():
            return
        time.sleep(0.05)
    raise ValueError("the private sccache server did not create its Unix socket")


def stop_server(server, executable, env, socket):
    try:
        if socket.is_socket():
            result = subprocess.run([executable, "--stop-server"], env=env, timeout=STOP_SECONDS, check=False)
            if result.returncode != 0:
                raise ValueError("the private sccache server did not acknowledge shutdown")
            server.wait(timeout=STOP_SECONDS)
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=STOP_SECONDS)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()



def run_cargo(command, repo, env):
    # Keep a cancelled build and any rustc children from restarting the server.
    with subprocess.Popen(command, cwd=repo, env=env, start_new_session=True) as cargo:
        try:
            return cargo.wait()
        except KeyboardInterrupt:
            try:
                os.killpg(cargo.pid, signal.SIGTERM)
                cargo.wait(timeout=STOP_SECONDS)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(cargo.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                cargo.wait()
            raise


def run(command, repo, root, executable):
    with locked_cache(root) as cache, tempfile.TemporaryDirectory(prefix="exa-sccache-", dir="/tmp") as private:
        session = Path(private)
        env = scoped_environment(os.environ, executable, session)
        if subprocess.check_output([executable, "--version"], env=env, text=True, timeout=START_SECONDS).strip() != f"sccache {VERSION}":
            raise ValueError(f"sccache {VERSION} is required")
        configure(session / "config.toml", cache)
        socket = session / "s"
        server = subprocess.Popen(
            [executable], env=env | {"SCCACHE_START_SERVER": "1", "SCCACHE_NO_DAEMON": "1"},
            stdin=subprocess.DEVNULL,
        )
        try:
            wait_ready(server, socket)
            return run_cargo(command, repo, env)
        finally:
            stop_server(server, executable, env, socket)


def on_terminate(_number, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ci", action="store_true", help="use the dedicated Linux CI cache directory")
    parser.add_argument("--binary", default="sccache", help="path to sccache 0.18.0")
    parser.add_argument("cargo_args", nargs=argparse.REMAINDER, help="Cargo build or check arguments after --")
    args = parser.parse_args()
    try:
        repo = Path.cwd().resolve()
        command = cargo_command(args.cargo_args, args.ci)
        root = cache_root(repo, args.ci, os.environ, sys.platform, platform.machine())
        located = shutil.which(args.binary)
        if located is None:
            raise ValueError(f"sccache {VERSION} executable not found")
        signal.signal(signal.SIGTERM, on_terminate)
        return run(command, repo, root, Path(located).resolve(strict=True))
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"sccache: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
