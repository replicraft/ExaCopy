use std::fs::{File, FileTimes, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::{Duration, SystemTime};

use super::super::native::{
	capture, confirm_transition, exact_receipt, pin_receipt_name, rename_pending, reopen_sealed,
	require_absent,
};
use super::NAMES;
use crate::linux::recovery::mount_id;
use crate::linux::source::reopen_regular_without_atime;
use crate::linux::{ReadError, StageError};
use crate::scratch::Scratch;

const RECEIPT_BYTES: &[u8] = b"expected receipt";
const OTHER_BYTES: &[u8] = b"replaced receipt";

#[test]
fn named_receipt_readback_refuses_mismatched_bytes_identity_and_metadata() {
	let scratch = Scratch::new();
	let job = scratch.open();
	let mount = mount_id(&job).expect("observe fixture mount");
	let receipt = create_fixture(&scratch.path("receipt"), RECEIPT_BYTES);
	let independent = create_fixture(&scratch.path("independent"), RECEIPT_BYTES);
	let expected = capture(&receipt).expect("capture original receipt inode");

	let readback = exact_receipt(&receipt, expected, RECEIPT_BYTES, 1, mount)
		.expect("confirm exact bytes, mode and single link");
	assert_eq!(readback, expected, "stable readback through O_NOATIME");
	assert!(matches!(
		exact_receipt(&receipt, expected, OTHER_BYTES, 1, mount),
		Err(StageError::IdentityChanged)
	));
	assert!(matches!(
		exact_receipt(&independent, expected, RECEIPT_BYTES, 1, mount),
		Err(StageError::IdentityChanged)
	));
	assert!(matches!(
		exact_receipt(&receipt, expected, RECEIPT_BYTES, 1, mount ^ 1),
		Err(StageError::IdentityChanged)
	));
	assert!(
		matches!(
			reopen_sealed(&receipt, expected, RECEIPT_BYTES, mount),
			Err(StageError::IdentityChanged)
		),
		"a named single-link receipt cannot be sealed as the anonymous reservation"
	);

	let changed_access = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
	receipt
		.set_times(FileTimes::new().set_accessed(changed_access))
		.expect("alter only the owned fixture's access time");
	let accessed = exact_receipt(&receipt, expected, RECEIPT_BYTES, 1, mount)
		.expect("read back the same content and identity");
	assert!(matches!(
		confirm_transition(expected, accessed),
		Err(StageError::IdentityChanged)
	));

	receipt
		.set_permissions(std::fs::Permissions::from_mode(0o640))
		.expect("change mode on the owned fixture");
	assert!(matches!(
		exact_receipt(&receipt, expected, RECEIPT_BYTES, 1, mount),
		Err(StageError::IdentityChanged)
	));
}

#[test]
fn pending_receipt_promotes_the_original_inode_and_requires_pending_absence() {
	let scratch = Scratch::new();
	let job = scratch.open();
	let mount = mount_id(&job).expect("observe fixture mount");
	let pending = scratch.path(std::str::from_utf8(&NAMES.pending).expect("ASCII pending name"));
	let final_name =
		scratch.path(std::str::from_utf8(&NAMES.final_name).expect("ASCII final name"));
	require_absent(&job, &NAMES).expect("both fixture names start absent");
	let receipt = create_fixture(&pending, RECEIPT_BYTES);
	let original_inode = receipt.metadata().expect("stat original receipt").ino();
	let original = capture(&receipt).expect("observe original receipt");
	let pending_pin = pin_receipt_name(&job, mount, original, &NAMES, false)
		.expect("hold exact pending receipt while final is absent");
	assert_eq!(
		pending_pin.metadata().expect("stat pending pin").ino(),
		original_inode
	);
	assert!(matches!(
		require_absent(&job, &NAMES),
		Err(StageError::IdentityChanged)
	));

	rename_pending(&job, &NAMES).expect("promote only into an absent final name");
	let installed = exact_receipt(&receipt, original, RECEIPT_BYTES, 1, mount)
		.expect("confirm promoted receipt contents and inode");
	confirm_transition(original, installed).expect("promotion preserves access and write times");
	let final_pin = pin_receipt_name(&job, mount, installed, &NAMES, true)
		.expect("hold exact final receipt while pending is absent");
	assert_eq!(
		final_pin.metadata().expect("stat final pin").ino(),
		original_inode
	);
	assert!(matches!(
		pending.symlink_metadata(),
		Err(cause) if cause.kind() == std::io::ErrorKind::NotFound
	));

	let changed = scratch.path("same-bytes");
	let independent = create_fixture(&changed, RECEIPT_BYTES);
	let foreign = capture(&independent).expect("observe same-byte foreign inode");
	assert!(matches!(
		pin_receipt_name(&job, mount, foreign, &NAMES, true),
		Err(StageError::ReadBack(ReadError::IdentityChanged))
	));

	let late_pending = create_fixture(&pending, OTHER_BYTES);
	assert!(matches!(
		pin_receipt_name(&job, mount, installed, &NAMES, true),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(
		std::fs::read(&pending).expect("read late pending bytes"),
		OTHER_BYTES
	);
	assert_eq!(
		std::fs::read(&final_name).expect("read final receipt bytes"),
		RECEIPT_BYTES
	);
	assert_ne!(
		late_pending.metadata().expect("stat late pending").ino(),
		original_inode
	);
}

#[test]
fn promotion_preserves_a_same_byte_final_incumbent_and_the_pending_receipt() {
	let scratch = Scratch::new();
	let job = scratch.open();
	let mount = mount_id(&job).expect("observe fixture mount");
	let pending = scratch.path(std::str::from_utf8(&NAMES.pending).expect("ASCII pending name"));
	let final_name =
		scratch.path(std::str::from_utf8(&NAMES.final_name).expect("ASCII final name"));
	let receipt = create_fixture(&pending, RECEIPT_BYTES);
	let original = capture(&receipt).expect("observe exact pending inode");
	let incumbent = create_fixture(&final_name, RECEIPT_BYTES);
	let incumbent_stamp = capture(&incumbent).expect("observe independent incumbent inode");
	assert_ne!(original.identity(), incumbent_stamp.identity());
	assert!(matches!(
		pin_receipt_name(&job, mount, original, &NAMES, false),
		Err(StageError::IdentityChanged)
	));
	assert!(matches!(
		rename_pending(&job, &NAMES),
		Err(StageError::System(cause)) if cause.raw_os_error() == Some(rustix::io::Errno::EXIST.raw_os_error())
	));
	assert_eq!(
		std::fs::read(&pending).expect("read original pending bytes"),
		RECEIPT_BYTES
	);
	assert_eq!(
		std::fs::read(&final_name).expect("read incumbent bytes"),
		RECEIPT_BYTES
	);
	assert_eq!(
		pending
			.metadata()
			.expect("stat original pending name")
			.ino(),
		original.identity().inode()
	);
	assert_eq!(
		final_name.metadata().expect("stat incumbent name").ino(),
		incumbent_stamp.identity().inode()
	);
	original
		.recheck(capture(&receipt).expect("reobserve pending descriptor"))
		.expect("refusal leaves pending receipt unchanged");
	incumbent_stamp
		.recheck(capture(&incumbent).expect("reobserve incumbent descriptor"))
		.expect("refusal leaves final incumbent unchanged");
}

fn create_fixture(path: &Path, bytes: &[u8]) -> File {
	let mut writer = OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(0o600)
		.open(path)
		.expect("create a private regular file in task-owned scratch");
	writer
		.set_permissions(std::fs::Permissions::from_mode(0o600))
		.expect("set the receipt mode independently of umask");
	writer.write_all(bytes).expect("write exact fixture bytes");
	writer
		.set_times(FileTimes::new().set_accessed(SystemTime::UNIX_EPOCH))
		.expect("set an explicit access time for native observations");
	let (reader, _) = reopen_regular_without_atime(&writer).expect("hold fixture read-only");
	reader
}
