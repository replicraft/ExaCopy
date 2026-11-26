use apfs_mounted::publication::{
	RenameAttempt, RenameEvidence, attempt_exclusive_rename, sync_directories,
};
use apfs_mounted::{Directory, EntryName, ObjectIdentity};
use std::ffi::CStr;
use std::fs::{self, File};
use std::io;
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt as _, symlink};
use std::path::Path;

use crate::scratch::Scratch;

fn rename_exclusively(stage: &File, from: &CStr, destination: &File, to: &CStr) -> io::Result<()> {
	let stage = Directory::from_file(stage.try_clone()?)?;
	let destination = Directory::from_file(destination.try_clone()?)?;
	let from = EntryName::new(from.to_bytes())
		.map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
	let to = EntryName::new(to.to_bytes()).map_err(io::Error::other)?;
	let held = stage.open_event(&from)?;
	let expected = ObjectIdentity::held(&held).map_err(io::Error::other)?;
	match attempt_exclusive_rename(&stage, &from, &destination, &to, &held, &expected) {
		RenameAttempt::Conflict => Err(io::Error::from_raw_os_error(libc::EEXIST)),
		RenameAttempt::Uncertain(error) => Err(error),
		RenameAttempt::Renamed(renamed) => {
			let barriers = sync_directories(&stage, &destination);
			barriers.source.map_err(io::Error::other)?;
			barriers.destination.map_err(io::Error::other)?;
			assert!(
				matches!(renamed.observe(), RenameEvidence::Confirmed { target } if target == expected)
			);
			Ok(())
		}
		result => panic!("unexpected companion rename result {result:?}"),
	}
}

const STAGE_BYTES: &[u8] = b"verified bytes\0\xff";
const INCUMBENT_BYTES: &[u8] = b"incumbent bytes";

fn identity(path: &Path) -> (u64, u64) {
	let metadata = fs::symlink_metadata(path).expect("inspect generated fixture entry");
	(metadata.dev(), metadata.ino())
}

fn write_new(path: &Path, bytes: &[u8]) {
	use std::io::Write as _;

	File::create_new(path)
		.expect("exclusively create generated fixture")
		.write_all(bytes)
		.expect("write fixture");
}

#[test]
fn native_exclusive_rename_moves_the_exact_stage() {
	let stage = Scratch::new();
	let destination = Scratch::new();
	let stage_dir = stage.open();
	let destination_dir = destination.open();
	let stage_path = stage.path("stage");
	let target = destination.path("target");
	write_new(&stage_path, STAGE_BYTES);
	let before = identity(&stage_path);

	rename_exclusively(&stage_dir, c"stage", &destination_dir, c"target")
		.expect("rename exclusive into absent name");

	assert!(
		matches!(stage_path.symlink_metadata(), Err(error) if error.kind() == ErrorKind::NotFound)
	);
	assert_eq!(identity(&target), before);
	assert_eq!(fs::read(target).expect("read published stage"), STAGE_BYTES);
}

#[test]
fn native_exclusive_rename_preserves_late_regular_and_symlink_incumbents() {
	for is_symlink in [false, true] {
		let stage = Scratch::new();
		let destination = Scratch::new();
		let stage_dir = stage.open();
		let destination_dir = destination.open();
		let stage_path = stage.path("stage");
		let target = destination.path("target");
		let referent = destination.path("referent");
		write_new(&stage_path, STAGE_BYTES);
		write_new(&referent, INCUMBENT_BYTES);
		let stage_before = identity(&stage_path);
		let referent_before = identity(&referent);
		assert!(
			matches!(target.symlink_metadata(), Err(error) if error.kind() == ErrorKind::NotFound)
		);
		std::thread::scope(|scope| {
			scope
				.spawn(|| {
					if is_symlink {
						symlink("referent", &target).expect("create generated late symbolic link");
					} else {
						write_new(&target, INCUMBENT_BYTES);
					}
				})
				.join()
				.expect("join late incumbent creator");
		});
		let target_before = identity(&target);

		let error = rename_exclusively(&stage_dir, c"stage", &destination_dir, c"target")
			.expect_err("refuse generated late incumbent");
		match error.raw_os_error() {
			Some(libc::EEXIST) => {}
			Some(libc::ELOOP) if is_symlink => {}
			errno => panic!("unexpected refused rename errno {errno:?}"),
		}

		assert_eq!(identity(&target), target_before);
		assert_eq!(identity(&stage_path), stage_before);
		assert_eq!(identity(&referent), referent_before);
		assert_eq!(
			fs::read(stage_path).expect("read retained stage"),
			STAGE_BYTES
		);
		assert_eq!(
			fs::read(referent).expect("read retained referent"),
			INCUMBENT_BYTES
		);
		if is_symlink {
			assert_eq!(
				fs::read_link(target).expect("read untouched link"),
				Path::new("referent")
			);
		} else {
			assert_eq!(
				fs::read(target).expect("read untouched incumbent"),
				INCUMBENT_BYTES
			);
		}
	}
}

#[test]
fn native_exclusive_rename_preserves_an_incumbent_addressed_through_an_alias() {
	let stage = Scratch::new();
	let destination = Scratch::new();
	let stage_dir = stage.open();
	let destination_dir = destination.open();
	let stage_path = stage.path("stage");
	let target = destination.path("target");
	let incumbent = destination.path("TARGET");
	let referent = destination.path("referent");
	write_new(&stage_path, STAGE_BYTES);
	write_new(&referent, INCUMBENT_BYTES);
	let stage_before = identity(&stage_path);
	let incumbent_before = identity(&referent);
	fs::hard_link(&referent, &incumbent).expect("install late fixture incumbent");
	match target.symlink_metadata() {
		Ok(_) => assert_eq!(identity(&target), incumbent_before),
		Err(error) if error.kind() == ErrorKind::NotFound => {
			fs::hard_link(&referent, &target).expect("reserve the distinct target spelling");
		}
		Err(error) => panic!("could not observe fixture target: {error}"),
	}
	let error = rename_exclusively(&stage_dir, c"stage", &destination_dir, c"target")
		.expect_err("refuse the existing alias");
	assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
	assert_eq!(identity(&stage_path), stage_before);
	assert_eq!(identity(&target), incumbent_before);
	assert_eq!(fs::read(stage_path).unwrap(), STAGE_BYTES);
	assert_eq!(identity(&incumbent), incumbent_before);
	assert_eq!(identity(&referent), incumbent_before);
	assert_eq!(fs::read(incumbent).unwrap(), INCUMBENT_BYTES);
	assert_eq!(fs::read(referent).unwrap(), INCUMBENT_BYTES);
}

#[test]
fn native_exclusive_rename_refuses_to_traverse_a_symbolic_link() {
	let fixture = Scratch::new();
	let destination = Scratch::new();
	let fixture_dir = fixture.open();
	let destination_dir = destination.open();
	let source_parent = fixture.path("source-parent");
	fs::create_dir(&source_parent).expect("create synthetic source parent");
	let source = source_parent.join("stage");
	write_new(&source, STAGE_BYTES);
	let alias = fixture.path("parent-link");
	symlink("source-parent", &alias).expect("install synthetic parent alias");
	let target = destination.path("target");
	let original_file = identity(&source);
	let original_link = identity(&alias);

	// The mounted boundary will never accept an intermediate component.
	let error = rename_exclusively(
		&fixture_dir,
		c"parent-link/stage",
		&destination_dir,
		c"target",
	)
	.expect_err("the native call must not traverse a source parent link");

	assert_eq!(error.kind(), ErrorKind::InvalidInput);
	assert_eq!(identity(&source), original_file);
	assert_eq!(fs::read(source).unwrap(), STAGE_BYTES);
	assert_eq!(identity(&alias), original_link);
	assert_eq!(fs::read_link(alias).unwrap(), Path::new("source-parent"));
	assert!(matches!(target.symlink_metadata(), Err(error) if error.kind() == ErrorKind::NotFound));
}
