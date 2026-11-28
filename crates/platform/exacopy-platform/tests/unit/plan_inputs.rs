use std::error::Error as _;
use std::fs::{self, DirBuilder, File, FileTimes, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use exacopy_endpoint::UnixComponent;
use rustix::fs::{OFlags, fcntl_getfl};
use rustix::io::{FdFlags, fcntl_getfd};

use crate::scratch::Scratch;

use super::{
	HeldOwnerSeed, KEY_NAME, OWNER_SEED_BYTES, PlanInputDirectory, PlanSeedError, StageError,
};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[test]
fn roots_remain_bound_after_the_selected_parent_is_replaced() {
	let scratch = Scratch::new();
	let selected = scratch.path("selected");
	let moved = scratch.path("moved");
	DirBuilder::new()
		.mode(PRIVATE_DIRECTORY_MODE)
		.create(&selected)
		.expect("create selected directory");
	let original = fs::metadata(&selected).expect("inspect original selected directory");
	let held = PlanInputDirectory::open(selected.as_os_str()).expect("hold selected directory");

	fs::rename(&selected, &moved).expect("move selected directory to another fixture name");
	fs::create_dir(&selected).expect("create replacement directory at the selected path");
	let replacement = fs::metadata(&selected).expect("inspect replacement directory");
	let original_identity = (original.dev(), original.ino());
	assert_ne!(
		original_identity,
		(replacement.dev(), replacement.ino()),
		"the fixture must contain two distinct directories"
	);

	let source = held
		.read_root()
		.expect("derive source root from held input");
	let target = held
		.destination_root()
		.expect("derive destination root from held input");
	drop(held);

	for identity in [source.identity(), target.identity()] {
		assert_eq!(
			(identity.device(), identity.inode()),
			original_identity,
			"derived root must identify the original directory"
		);
	}
}

#[test]
fn selected_directory_alias_keeps_a_path_only_close_on_exec_pin() {
	let scratch = Scratch::new();
	let directory = scratch.path("selected");
	let alias = scratch.path("alias");
	fs::create_dir(&directory).expect("create selected directory");
	symlink(&directory, &alias).expect("create selected directory alias");

	let actual = fs::metadata(&directory).expect("inspect selected directory");
	let held = PlanInputDirectory::open(alias.as_os_str()).expect("hold selected directory alias");
	let flags = fcntl_getfl(&held.0).expect("inspect held directory status flags");
	assert!(flags.contains(OFlags::PATH | OFlags::DIRECTORY));
	let flags = fcntl_getfd(&held.0).expect("inspect held directory descriptor flags");
	assert!(flags.contains(FdFlags::CLOEXEC));
	let identity = held.read_root().expect("bind selected input").identity();
	assert_eq!(
		(identity.device(), identity.inode()),
		(actual.dev(), actual.ino())
	);
}

#[test]
fn input_open_reports_missing_and_non_directory_paths() {
	let scratch = Scratch::new();
	let file = scratch.path("ordinary-file");
	fs::write(&file, b"ordinary fixture").expect("create ordinary file fixture");

	for (path, kind) in [
		(scratch.path("missing"), io::ErrorKind::NotFound),
		(file, io::ErrorKind::NotADirectory),
	] {
		let Err(error) = PlanInputDirectory::open(path.as_os_str()) else {
			panic!("accepted invalid Plan input path {path:?}");
		};
		assert_eq!(error.kind(), kind, "incorrect refusal for {path:?}");
	}
}

#[test]
fn destination_root_applies_the_managed_parent_contract() {
	let scratch = Scratch::new();
	let path = scratch.path("writable-parent");
	fs::create_dir(&path).expect("create ordinary directory in private fixture");
	fs::set_permissions(&path, Permissions::from_mode(0o770))
		.expect("make fixture group-writable without a sticky bit");
	let held = PlanInputDirectory::open(path.as_os_str()).expect("hold selected directory");

	held.read_root()
		.expect("the directory is a valid read root");
	assert!(
		matches!(held.destination_root(), Err(StageError::UnsafeDirectory)),
		"the group-writable directory must fail destination admission"
	);
}

#[test]
fn seed_observation_returns_native_stamps_for_the_accepted_identity() {
	let scratch = Scratch::new();
	let path = scratch.path(KEY_NAME.to_str().expect("seed name is ASCII"));
	let fixture = seed_fixture(&path);
	let native = fixture.metadata().expect("inspect synthetic seed metadata");
	let held = PlanInputDirectory::open(scratch.path(".").as_os_str())
		.expect("hold the synthetic profile directory");
	let accepts = |identity: super::FileIdentity| {
		(identity.device(), identity.inode()) == (native.dev(), native.ino())
	};

	let before = held
		.observe_seed(accepts)
		.expect("observe admitted seed name");
	assert_eq!(
		before.mtime,
		(i128::from(native.mtime()), i128::from(native.mtime_nsec()),),
		"modification timestamp must match the native observation"
	);
	assert_eq!(
		before.ctime,
		(i128::from(native.ctime()), i128::from(native.ctime_nsec()),),
		"change timestamp must match the native observation"
	);
	assert!(
		held.observe_seed(accepts)
			.expect("observe unchanged fixture")
			== before,
		"unchanged seed observations must compare equal"
	);

	fixture
		.set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(3600)))
		.expect("set a distinct modification time on synthetic fixture");
	let updated = fixture.metadata().expect("inspect updated seed metadata");
	assert_ne!(
		(updated.mtime(), updated.mtime_nsec()),
		(native.mtime(), native.mtime_nsec()),
		"the filesystem must record the fixture time change"
	);
	let after = held
		.observe_seed(accepts)
		.expect("observe changed seed stamp");
	assert!(
		after != before,
		"the seed stamp must distinguish an updated observation"
	);
}

#[test]
fn seed_observation_refuses_identity_mode_link_count_and_length_mismatches() {
	let scratch = Scratch::new();
	let path = scratch.path(KEY_NAME.to_str().expect("seed name is ASCII"));
	let fixture = seed_fixture(&path);
	let held = PlanInputDirectory::open(scratch.path(".").as_os_str())
		.expect("hold the synthetic profile directory");
	assert!(
		held.observe_seed(|_| true).is_ok(),
		"admit the control fixture"
	);
	let Err(error @ PlanSeedError::Unsafe) = held.observe_seed(|_| false) else {
		panic!("a rejected seed identity must return the contract error");
	};
	assert_eq!(error.to_string(), "plan seed observation refused");
	assert!(
		error.source().is_none(),
		"contract error has no native cause"
	);

	fixture
		.set_permissions(Permissions::from_mode(0o640))
		.expect("give the fixture group read permission");
	assert!(
		matches!(held.observe_seed(|_| true), Err(PlanSeedError::Unsafe)),
		"seed with group read permission must be refused"
	);
	fixture
		.set_permissions(Permissions::from_mode(PRIVATE_FILE_MODE))
		.expect("restore the admitted mode");

	let alias = scratch.path("alias");
	fs::hard_link(&path, &alias).expect("add a second name for the ordinary fixture");
	assert!(
		matches!(held.observe_seed(|_| true), Err(PlanSeedError::Unsafe)),
		"seed with two names must be refused"
	);
	fs::remove_file(alias).expect("remove the fixture alias");

	fixture.set_len(0).expect("shorten the ordinary fixture");
	assert!(
		matches!(held.observe_seed(|_| true), Err(PlanSeedError::Unsafe)),
		"seed with the wrong length must be refused"
	);
}

#[test]
fn seed_observation_distinguishes_a_missing_name_from_a_link() {
	let scratch = Scratch::new();
	let path = scratch.path(KEY_NAME.to_str().expect("seed name is ASCII"));
	let held = PlanInputDirectory::open(scratch.path(".").as_os_str())
		.expect("hold the synthetic profile directory");
	let Err(error @ PlanSeedError::Io(_)) =
		held.observe_seed(|_| panic!("missing name cannot reach identity policy"))
	else {
		panic!("a missing seed name must return a native observation error");
	};
	let native = error
		.source()
		.and_then(|source| source.downcast_ref::<io::Error>())
		.expect("preserve the underlying I/O error");
	assert_eq!(native.kind(), io::ErrorKind::NotFound);
	assert_eq!(error.to_string(), native.to_string());

	let target = scratch.path("ordinary-target");
	let _fixture = seed_fixture(&target);
	symlink(&target, path).expect("create a link to the synthetic regular file");
	assert!(
		matches!(held.observe_seed(|_| true), Err(PlanSeedError::Unsafe)),
		"the seed name itself must be a regular file"
	);
}

#[test]
fn bound_owner_seed_rejects_a_stamp_change_on_the_original_inode() {
	let scratch = Scratch::new();
	let (directory, held, seed, original) = bound_seed_fixture(&scratch);
	let binding = directory.bind_owner_seed(&held).unwrap();
	binding.recheck().unwrap();

	original
		.set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(3600)))
		.unwrap();
	let current = fs::symlink_metadata(seed).unwrap();
	assert_eq!(
		(current.dev(), current.ino()),
		(held.identity().device(), held.identity().inode())
	);
	assert_eq!((current.mtime(), current.mtime_nsec()), (3600, 0));
	assert!(matches!(binding.recheck(), Err(PlanSeedError::Unsafe)));
}

#[test]
fn bound_owner_seed_refuses_a_byte_identical_replacement_name() {
	let scratch = Scratch::new();
	let (directory, held, seed, original) = bound_seed_fixture(&scratch);
	let binding = directory.bind_owner_seed(&held).unwrap();
	binding.recheck().unwrap();

	let moved = seed.with_file_name("original-seed");
	fs::rename(&seed, &moved).unwrap();
	assert!(matches!(
		binding.recheck(),
		Err(PlanSeedError::Io(error)) if error.kind() == io::ErrorKind::NotFound
	));
	let _replacement = seed_fixture(&seed);
	let current = fs::symlink_metadata(&seed).unwrap();
	let retained = original.metadata().unwrap();
	assert_eq!(
		(retained.dev(), retained.ino()),
		(held.identity().device(), held.identity().inode())
	);
	assert_ne!(
		(current.dev(), current.ino()),
		(retained.dev(), retained.ino())
	);
	assert_eq!(fs::read(seed).unwrap(), fs::read(moved).unwrap());
	assert!(matches!(binding.recheck(), Err(PlanSeedError::Unsafe)));
	assert!(matches!(
		directory.bind_owner_seed(&held),
		Err(PlanSeedError::Unsafe)
	));
}

fn bound_seed_fixture(scratch: &Scratch) -> (PlanInputDirectory, HeldOwnerSeed, PathBuf, File) {
	const PROFILE: &str = "profile";
	let profile = scratch.path(PROFILE);
	DirBuilder::new()
		.mode(PRIVATE_DIRECTORY_MODE)
		.create(&profile)
		.unwrap();
	let seed = profile.join(KEY_NAME.to_str().unwrap());
	let original = seed_fixture(&seed);
	let directory = PlanInputDirectory::open(profile.as_os_str()).unwrap();
	let selected = UnixComponent::new(PROFILE.as_bytes()).unwrap();
	let mut bytes = [0; OWNER_SEED_BYTES];
	let held = HeldOwnerSeed::open(
		scratch.path(".").as_os_str(),
		selected,
		&mut bytes,
		&mut [0],
	)
	.unwrap();
	assert_eq!(bytes, [0; OWNER_SEED_BYTES]);
	(directory, held, seed, original)
}

fn seed_fixture(path: &Path) -> File {
	let file = File::options()
		.write(true)
		.create_new(true)
		.open(path)
		.expect("create synthetic ordinary file");
	file.set_permissions(Permissions::from_mode(PRIVATE_FILE_MODE))
		.expect("set the fixture's private mode");
	file.set_len(u64::try_from(OWNER_SEED_BYTES).expect("fixture length fits u64"))
		.expect("set the synthetic fixture size without writing seed data");
	file.set_times(FileTimes::new().set_modified(UNIX_EPOCH))
		.expect("set the initial synthetic modification time");
	file
}
