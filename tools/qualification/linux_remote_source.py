"""Observe the clean checkout for Linux remote fixture evidence."""

import hashlib
import os
from pathlib import Path
import re
import subprocess


def source_identity(root: Path) -> dict[str, str]:
    git_env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    git_env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0")

    def git(*args):
        return subprocess.check_output(
            ["git", "--no-replace-objects", *args], cwd=root, env=git_env, timeout=15, text=True,
        ).strip()

    result = git("rev-parse", "HEAD", "HEAD^{tree}").splitlines()
    if len(result) != 2 or any(not re.fullmatch(r"[0-9a-f]{40}", item) for item in result):
        raise ValueError("invalid source revision or tree")
    if git("status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"):
        raise ValueError("evidence requires a pristine checkout, including ignored paths")
    if Path(git("rev-parse", "--show-toplevel")).resolve() != root:
        raise ValueError("evidence must run from the observed checkout root")
    if any(not entry.startswith("H ") for entry in git("ls-files", "-v").splitlines()):
        raise ValueError("evidence refuses masked or unmerged checkout entries")
    with (root / "Cargo.lock").open("rb") as lock:
        lock_digest = hashlib.file_digest(lock, "sha256").hexdigest()
    return {
        "revision": result[0], "git_tree": result[1], "lock_sha256": lock_digest,
    }
