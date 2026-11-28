"""Source-bound foreground cohorts for the ordinary Linux coverage image."""

from contextlib import ExitStack
import errno
import os
from pathlib import Path
import stat
import struct
import tempfile

import run

SELECTED_STREAM_PREFIX = "linux::stage::selected_stream::publication::tests::"
PROTECTED_SNAPSHOT_PREFIX = "linux::protected_snapshot::tests::"
WITNESSED = "witnessed-components"
SELECTED_STREAM = "selected-stream-publication"
PROTECTED_SNAPSHOT = "protected-snapshot"
COHORTS = (
    (WITNESSED, run.CASES),
    (SELECTED_STREAM, tuple(SELECTED_STREAM_PREFIX + name for name in (
        "publish_confirms_original_inode_and_releases_gate_before_both_real_barriers",
        "qualification_binding_and_final_grant_refuse_before_rename",
        "grant_revoked_during_file_barrier_is_checked_at_the_effect",
        "retained_stage_conflict_keeps_both_inodes_and_never_syncs_directories",
        "barrier_and_post_rename_failures_preserve_effect_and_return_typed_error",
        "expired_prepublication_barrier_cannot_reach_the_rename_gate",
    ))),
    (PROTECTED_SNAPSHOT, tuple(PROTECTED_SNAPSHOT_PREFIX + name for name in (
        "selected_path_reads_bounded_nonempty_and_empty_fixtures",
        "selected_path_refuses_unsafe_parents_files_and_writer_contention",
        "selected_path_refuses_an_ancestor_acl_that_effectively_grants_write",
        "secret_buffers_enforce_the_selected_bound_and_native_mode",
    ))),
)
SOURCE_INPUTS = (
    str(Path(__file__).relative_to(run.ROOT)),
    *(str(path.relative_to(run.ROOT)) for path in run.CHECKPOINT_INPUTS),
    *(str((run.PACKAGE / source).relative_to(run.ROOT)) for source in sorted({
        run.source(case) for _, cases in COHORTS for case in cases
    })),
)


def check_unprivileged_image(fd):
    """The held executable may not acquire file capabilities on exec."""
    try:
        os.getxattr(fd, "security.capability")
    except OSError as error:
        if error.errno == errno.ENODATA:
            return
        raise run.ext4.Blocked("held ordinary ELF file capabilities could not be excluded") from error
    raise run.ext4.Blocked("held ordinary ELF has file capabilities")


def snapshot_substrate(fixture, fixture_fd, evidence, phase):
    """Check the root mount and protected ancestor contract for snapshot reads."""
    facts = run.ext4.observe(fixture, fixture_fd, evidence, phase, profile=run.ext4.MANAGED)
    owner = os.geteuid()
    chain = []
    with ExitStack() as stack:
        parent = os.open("/", run.ext4.DIR_FLAGS)
        stack.callback(os.close, parent)
        for part in ("/", *fixture.parts[1:]):
            if part != "/":
                parent = os.open(part, run.ext4.DIR_FLAGS, dir_fd=parent)
                stack.callback(os.close, parent)
            node = os.fstat(parent)
            if (node.st_uid not in (0, owner) or node.st_mode & 0o022
                    or run.ext4.unique_mount(parent) != facts["unique_mount"]):
                raise run.ext4.Blocked("snapshot fixture ancestry is outside the protected ext4 root")
            chain.append((node.st_dev, node.st_ino, node.st_uid, stat.S_IMODE(node.st_mode)))
        run.ext4.require(os.path.samestat(os.fstat(parent), os.fstat(fixture_fd)),
                         "snapshot ancestor walk did not resolve to the held fixture")
    return {"managed_substrate": facts, "ancestors": chain}


def check_snapshot_acl(fixture):
    """Confirm POSIX ACL recording without granting access to another actor."""
    # Linux POSIX access ACL v2. The named user write bit is masked out.
    no_id = 0xffffffff
    actor = 2 if os.geteuid() == 1 else 1
    entries = ((1, 7, no_id), (2, 2, actor), (4, 0, no_id), (16, 0, no_id), (32, 0, no_id))
    encoded = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)
    attribute = "system.posix_acl_access"
    with tempfile.TemporaryDirectory(prefix="snapshot-acl-", dir=fixture) as directory:
        fd = os.open(directory, run.ext4.DIR_FLAGS)
        try:
            try:
                os.setxattr(fd, attribute, encoded, flags=os.XATTR_CREATE)
                observed = os.getxattr(fd, attribute)
            except OSError as error:
                raise run.ext4.Blocked("snapshot fixture could not establish POSIX ACL support") from error
            run.ext4.require(observed == encoded and stat.S_IMODE(os.fstat(fd).st_mode) == 0o700,
                             "snapshot fixture ACL changed its private mode or recorded bytes")
        finally:
            os.close(fd)
