use std::fs::{self, File, OpenOptions, Permissions};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink};

use rustix::fs as native;

use super::{
	FlockOperation, HeldDirectory, MAX_PROTECTED_SNAPSHOT_BYTES, ProtectedSnapshotError,
	UnixComponent, check_file, current_owner, open_child, protected_length, read_twice,
	recheck_chain,
};
use crate::read_protected_snapshot;
use crate::scratch::Scratch;

const FILE: &str = "selected.fixture";

fn create_fixture(scratch: &Scratch) -> File {
	OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(scratch.path(FILE))
		.unwrap()
}

#[test]
#[ignore = "requires a nonroot native Linux account and TMPDIR on a protected whole ext4 or XFS root mount"]
fn selected_path_reads_bounded_nonempty_and_empty_fixtures() {
	use std::io::Write as _;

	let scratch = Scratch::new();
	let path = scratch.path(FILE);
	assert_eq!(
		read_protected_snapshot(&path),
		Err(ProtectedSnapshotError::Unavailable)
	);
	let mut writer = create_fixture(&scratch);
	assert_eq!(read_protected_snapshot(&path).unwrap(), b"");
	let expected = vec![0x79; MAX_PROTECTED_SNAPSHOT_BYTES];
	writer.write_all(&expected).unwrap();
	assert_eq!(read_protected_snapshot(&path).unwrap(), expected);
	writer.set_len(expected.len() as u64 + 1).unwrap();
	assert_eq!(
		read_protected_snapshot(&path),
		Err(ProtectedSnapshotError::TooLarge)
	);
}

#[test]
#[ignore = "requires a nonroot native Linux account and TMPDIR on a protected whole ext4 or XFS root mount"]
fn selected_path_refuses_unsafe_parents_files_and_writer_contention() {
	let scratch = Scratch::new();
	let path = scratch.path(FILE);
	create_fixture(&scratch);

	let writer = scratch.open();
	native::flock(&writer, FlockOperation::NonBlockingLockExclusive).unwrap();
	assert_eq!(
		read_protected_snapshot(&path),
		Err(ProtectedSnapshotError::Busy)
	);
	drop(writer);
	assert_eq!(read_protected_snapshot(&path).unwrap(), b"");

	fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
	assert_eq!(
		read_protected_snapshot(&path),
		Err(ProtectedSnapshotError::Unprotected)
	);
	fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
	fs::hard_link(&path, scratch.path("alias.fixture")).unwrap();
	assert_eq!(
		read_protected_snapshot(&path),
		Err(ProtectedSnapshotError::Unprotected)
	);
	symlink(&path, scratch.path("link.fixture")).unwrap();
	assert_eq!(
		read_protected_snapshot(&scratch.path("link.fixture")),
		Err(ProtectedSnapshotError::Unprotected)
	);
	let root = scratch.open();
	native::mknodat(
		&root,
		c"fifo.fixture",
		native::FileType::Fifo,
		native::Mode::RUSR | native::Mode::WUSR,
		0,
	)
	.unwrap();
	assert_eq!(
		read_protected_snapshot(&scratch.path("fifo.fixture")),
		Err(ProtectedSnapshotError::Unprotected)
	);
	fs::create_dir(scratch.path("directory.fixture")).unwrap();
	assert_eq!(
		read_protected_snapshot(&scratch.path("directory.fixture")),
		Err(ProtectedSnapshotError::Unprotected)
	);
	fs::set_permissions(scratch.path("."), Permissions::from_mode(0o770)).unwrap();
	assert_eq!(
		read_protected_snapshot(&path),
		Err(ProtectedSnapshotError::Unprotected)
	);
}

#[test]
#[ignore = "requires a nonroot native Linux account and TMPDIR on a protected whole ext4 or XFS root mount with POSIX ACLs"]
fn selected_path_refuses_an_ancestor_acl_that_effectively_grants_write() {
	let scratch = Scratch::new();
	let private = scratch.path("private");
	fs::DirBuilder::new().mode(0o700).create(&private).unwrap();

	let path = private.join(FILE);
	OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&path)
		.unwrap();

	// Linux POSIX access ACL xattr version 2. Entries hold a tag, permission
	// bits and a UID/GID, or u32::MAX when the tag has no associated ID.
	const ACL_VERSION: u32 = 2;
	const USER_OBJECT: u16 = 0x01;
	const NAMED_USER: u16 = 0x02;
	const GROUP_OBJECT: u16 = 0x04;
	const MASK: u16 = 0x10;
	const OTHER: u16 = 0x20;
	const WRITE: u16 = 0o2;
	const OWNER_ACCESS: u16 = 0o7;
	const NO_ID: u32 = u32::MAX;
	let unrelated_user = if current_owner().unwrap() == 1 { 2 } else { 1 };
	let ancestor = scratch.open();
	let set_acl = |mask| {
		let mut value = ACL_VERSION.to_le_bytes().to_vec();
		for (tag, permission, id) in [
			(USER_OBJECT, OWNER_ACCESS, NO_ID),
			(NAMED_USER, WRITE, unrelated_user),
			(GROUP_OBJECT, 0, NO_ID),
			(MASK, mask, NO_ID),
			(OTHER, 0, NO_ID),
		] {
			value.extend_from_slice(&tag.to_le_bytes());
			value.extend_from_slice(&permission.to_le_bytes());
			value.extend_from_slice(&id.to_le_bytes());
		}
		native::fsetxattr(
			&ancestor,
			c"system.posix_acl_access",
			&value,
			native::XattrFlags::empty(),
		)
		.unwrap();
	};
	set_acl(0);
	assert_eq!(read_protected_snapshot(&path).unwrap(), b"");

	set_acl(WRITE);
	assert_eq!(
		read_protected_snapshot(&path),
		Err(ProtectedSnapshotError::Unprotected)
	);
}

#[test]
fn a_shared_reader_lease_blocks_a_separately_opened_cooperating_writer() {
	let scratch = Scratch::new();
	let owner = rustix::process::geteuid().as_raw();
	let parent = HeldDirectory::new(scratch.open().into(), owner).unwrap();
	let first = parent.lock_private(owner).unwrap();
	let second = parent.lock_private(owner).unwrap();
	let writer = scratch.open();
	let try_writer = || native::flock(&writer, FlockOperation::NonBlockingLockExclusive);
	assert_eq!(try_writer(), Err(rustix::io::Errno::WOULDBLOCK));
	drop(first);
	assert_eq!(try_writer(), Err(rustix::io::Errno::WOULDBLOCK));
	drop(second);
	try_writer().unwrap();
}

#[test]
fn a_held_regular_file_rejects_growth_and_name_replacement() {
	let scratch = Scratch::new();
	let writer = create_fixture(&scratch);
	let owner = rustix::process::geteuid().as_raw();
	let parent = HeldDirectory::new(scratch.open().into(), owner).unwrap();
	let root = parent.lock_private(owner).unwrap();
	let name = UnixComponent::new(FILE.as_bytes()).unwrap();
	let file = root.open_regular(name).unwrap();
	let length = protected_length(&file, owner).unwrap();
	assert_eq!(read_twice(&root, name, &file, length).unwrap(), b"");

	writer.set_len(1).unwrap();
	assert_eq!(
		check_file(&root, name, &file),
		Err(ProtectedSnapshotError::Changed)
	);
	writer.set_len(0).unwrap();
	let file = root.open_regular(name).unwrap();
	fs::rename(scratch.path(FILE), scratch.path("old.fixture")).unwrap();
	create_fixture(&scratch);
	assert_eq!(
		check_file(&root, name, &file),
		Err(ProtectedSnapshotError::Changed)
	);
}

#[test]
fn an_ancestor_cannot_be_replaced_by_a_directory_or_symlink() {
	let scratch = Scratch::new();
	let owner = rustix::process::geteuid().as_raw();
	let name = UnixComponent::new(b"child").unwrap();
	let path = scratch.path("child");
	fs::create_dir(&path).unwrap();
	let root = HeldDirectory::new(scratch.open().into(), owner).unwrap();
	let child = open_child(&root.descriptor, name).unwrap();
	let child = HeldDirectory::new(child, owner).unwrap();
	let mount = root.observation.mount;
	fs::rename(&path, scratch.path("old")).unwrap();
	fs::create_dir(&path).unwrap();
	assert_eq!(
		recheck_chain(&[root, child], &[name], owner, mount),
		Err(ProtectedSnapshotError::Changed)
	);
	fs::remove_dir(&path).unwrap();
	symlink(scratch.path("old"), &path).unwrap();
	let root = HeldDirectory::new(scratch.open().into(), owner).unwrap();
	assert_eq!(
		open_child(&root.descriptor, name).unwrap_err(),
		ProtectedSnapshotError::Unprotected
	);
}

#[test]
fn invalid_paths_are_refused_even_when_the_platform_profile_is_unavailable() {
	use std::path::Path;

	assert_eq!(
		read_protected_snapshot(Path::new("relative")),
		Err(ProtectedSnapshotError::InvalidPath)
	);
	if current_owner().is_err() {
		assert_eq!(
			read_protected_snapshot(Path::new("/unused/fixture")),
			Err(ProtectedSnapshotError::Unsupported)
		);
	}
}
