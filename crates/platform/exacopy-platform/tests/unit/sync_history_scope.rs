use std::fs::{self, File};
use std::num::NonZeroU64;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self as native_fs, AtFlags};
use rustix::io::Errno;

use super::{
	CASEFOLD_DIRECTORY, ENCRYPT_DIRECTORY, MOUNT_ID_UNIQUE, SyncPreviewError, SyncPreviewRoots,
	check_directory, file_identity, mount_id, unique_mount_id,
};

const SUBJECT: &[u8] = b"subject";
const LEFT_BYTES: &[u8] = b"left fixture content";
const RIGHT_BYTES: &[u8] = b"right fixture content";
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

#[test]
fn stable_live_pair_on_tmpfs_refuses_history_location_and_preserves_inputs() {
	let fixture = Fixture::new();
	let roots = fixture.roots();
	let pair = roots.observe(component(SUBJECT)).unwrap();

	pair.recheck()
		.expect("the ordinary live pair remains valid");
	assert!(matches!(
		pair.recheck_history_location(),
		Err(SyncPreviewError::UnsupportedMount)
	));
	assert_eq!(
		fs::read(fixture.0.join("left/subject")).unwrap(),
		LEFT_BYTES
	);
	assert_eq!(
		fs::read(fixture.0.join("right/subject")).unwrap(),
		RIGHT_BYTES
	);
}

#[test]
fn changed_subject_refuses_history_before_the_mount_check() {
	let fixture = Fixture::new();
	let roots = fixture.roots();
	let pair = roots.observe(component(SUBJECT)).unwrap();
	let selected = fixture.0.join("right/subject");
	let retained = fixture.0.join("right/retained");

	fs::rename(&selected, &retained).unwrap();
	fs::write(&selected, RIGHT_BYTES).unwrap();

	assert!(matches!(
		pair.recheck_history_location(),
		Err(SyncPreviewError::Changed)
	));
	assert_eq!(fs::read(&selected).unwrap(), RIGHT_BYTES);
	assert_eq!(fs::read(&retained).unwrap(), RIGHT_BYTES);
	assert_eq!(
		fs::read(fixture.0.join("left/subject")).unwrap(),
		LEFT_BYTES
	);
}

#[test]
fn changed_root_refuses_history_before_the_mount_check() {
	let fixture = Fixture::new();
	let roots = fixture.roots();
	let pair = roots.observe(component(SUBJECT)).unwrap();
	let selected = fixture.0.join("left");
	let retained = fixture.0.join("retained-left");

	fs::rename(&selected, &retained).unwrap();
	fs::create_dir(&selected).unwrap();
	fs::write(selected.join("subject"), LEFT_BYTES).unwrap();

	assert!(matches!(
		pair.recheck_history_location(),
		Err(SyncPreviewError::Changed)
	));
	assert_eq!(fs::read(selected.join("subject")).unwrap(), LEFT_BYTES);
	assert_eq!(fs::read(retained.join("subject")).unwrap(), LEFT_BYTES);
	assert_eq!(
		fs::read(fixture.0.join("right/subject")).unwrap(),
		RIGHT_BYTES
	);
}

#[test]
fn history_directory_requires_matching_live_identity_and_mounts() {
	let fixture = Fixture::new();
	let left = File::open(fixture.0.join("left")).unwrap();
	let right = File::open(fixture.0.join("right")).unwrap();
	let stat = native_fs::statx(&left, c"", AtFlags::EMPTY_PATH, MOUNT_ID_UNIQUE)
		.expect("read the native unique mount field and availability bit");
	let unique =
		NonZeroU64::new(stat.stx_mnt_id).filter(|_| stat.stx_mask & MOUNT_ID_UNIQUE.bits() != 0);
	let Some(unique) = unique else {
		assert!(matches!(
			unique_mount_id(&left),
			Err(SyncPreviewError::UnsupportedMount)
		));
		return;
	};

	assert_eq!(unique_mount_id(&left).unwrap(), unique);
	assert_eq!(unique_mount_id(&right).unwrap(), unique);
	let identity = file_identity(&left).unwrap();
	let other_identity = file_identity(&right).unwrap();
	let mount = mount_id(&left).unwrap();
	assert_ne!(
		other_identity, identity,
		"fixture directories must be distinct"
	);
	let different_unique = if unique == NonZeroU64::MIN {
		NonZeroU64::MAX
	} else {
		NonZeroU64::MIN
	};

	for (wrong_identity, wrong_mount, wrong_unique) in [
		(other_identity, mount, unique),
		(identity, mount ^ 1, unique),
		(identity, mount, different_unique),
	] {
		let result = check_directory(&left, wrong_identity, wrong_mount, wrong_unique);
		assert!(
			matches!(result, Err(SyncPreviewError::Changed)),
			"mismatched directory evidence returned {result:?}"
		);
	}

	let subject = File::open(fixture.0.join("left/subject")).unwrap();
	assert!(matches!(
		check_directory(&subject, identity, mount, unique),
		Err(SyncPreviewError::System(error))
			if error.raw_os_error() == Some(Errno::NOTDIR.raw_os_error())
	));

	let matched = check_directory(&left, identity, mount, unique);
	match native_fs::ioctl_getflags(&left) {
		Ok(flags) => {
			assert_eq!(
				flags.bits() & (ENCRYPT_DIRECTORY | CASEFOLD_DIRECTORY),
				0,
				"the ordinary fixture has no history-incompatible naming flags"
			);
			matched.expect("matching native facts and ordinary naming allow the directory check");
		}
		Err(errno) => assert!(matches!(
			matched,
			Err(SyncPreviewError::System(error))
				if error.raw_os_error() == Some(errno.raw_os_error())
		)),
	}
}

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
		let path = Path::new("/dev/shm").join(format!(
			"exacopy-history-scope-{}-{serial}",
			std::process::id()
		));
		fs::DirBuilder::new()
			.mode(0o700)
			.create(&path)
			.expect("create a private history scope test directory on Linux tmpfs");
		let fixture = Self(path);
		fs::create_dir(fixture.0.join("left")).unwrap();
		fs::create_dir(fixture.0.join("right")).unwrap();
		fs::write(fixture.0.join("left/subject"), LEFT_BYTES).unwrap();
		fs::write(fixture.0.join("right/subject"), RIGHT_BYTES).unwrap();
		fixture
	}

	fn roots(&self) -> SyncPreviewRoots<'_> {
		SyncPreviewRoots::open(&self.0, [component(b"left"), component(b"right")])
			.expect("hold a stable live pair on the fixture mount")
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).expect("remove the owned history scope fixture");
	}
}

fn component(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).expect("valid fixture basename")
}
