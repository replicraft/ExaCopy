use super::super::{
	JobFileIdentity, MAX_REMOTE_MOUNT_RECORD_BYTES, MountObservations,
	RemoteDestinationEligibilityError, RemoteDestinationFacts, RemoteDestinationIds,
	RemoteKernelArchitecture, fs, is_writable, mount, remote_mount_row,
};
use super::MOUNT_ROW;

#[test]
fn writable_option_list_requires_one_leading_rw_token() {
	for options in [b"rw".as_slice(), b"rw,nosuid", b"rw,errors=remount-ro"] {
		assert!(is_writable(options), "writable options {options:?}");
	}
	for options in [
		b"".as_slice(),
		b"ro",
		b"rwx",
		b"rw=1",
		b"nosuid,rw",
		b"rw,rw",
		b"rw,nosuid,ro",
		b"rw,,nosuid",
		b"rw,nosuid,",
	] {
		assert!(!is_writable(options), "unsupported options {options:?}");
	}
}

#[test]
fn remote_mount_row_enforces_the_exact_byte_limit_without_the_line_delimiter() {
	let held = mount::Mount {
		id: 13,
		unique_id: 35,
		device: fs::makedev(8, 1),
	};
	let prefix = format!("{MOUNT_ROW},");
	let exact = format!(
		"{prefix}{}",
		"a".repeat(MAX_REMOTE_MOUNT_RECORD_BYTES - prefix.len())
	);
	assert_eq!(exact.len(), MAX_REMOTE_MOUNT_RECORD_BYTES);

	let table = MountObservations::parse(format!("{exact}\n").as_bytes())
		.expect("complete mountinfo row at the qualification limit");
	assert_eq!(
		remote_mount_row(&table, held).expect("maximum length is inclusive"),
		exact.as_bytes()
	);

	let table = MountObservations::parse(format!("{exact}a\n").as_bytes())
		.expect("mountinfo still parses one byte beyond the qualification limit");
	assert!(matches!(
		remote_mount_row(&table, held),
		Err(RemoteDestinationEligibilityError::UnsupportedObservation)
	));
}

#[test]
fn selected_mount_projection_preserves_native_bytes_and_option_order() {
	const ALIAS: &[u8] = b"17 1 8:1 / /alias rw - ext4 /dev/loop1 rw\n";
	const SELECTED: &[u8] =
		b"13 1 8:1 / /selected\\040\xff rw,nosuid,nodev - ext4 /dev/loop1 rw,user_xattr";
	const REORDERED: &[u8] =
		b"13 1 8:1 / /selected\\040\xff rw,nodev,nosuid - ext4 /dev/loop1 rw,user_xattr";
	let held = mount::Mount {
		id: 13,
		unique_id: 35,
		device: fs::makedev(8, 1),
	};
	let ids = RemoteDestinationIds {
		root: JobFileIdentity {
			device: held.device,
			inode: 42,
		},
		effective_uid: 1000,
		effective_gid: 1001,
		boot_id: [0x67; 16],
		mount_namespace: 9,
		mount_id: held.id,
		unique_mount: held.unique_id,
	};

	let project = |expected: &[u8]| {
		let data = [ALIAS, expected, b"\n"].concat();
		let table = MountObservations::parse(&data).expect("complete synthetic mountinfo");
		let selected = remote_mount_row(&table, held).expect("held whole writable ext4 row");
		assert_eq!(
			selected, expected,
			"the held row retains its original bytes"
		);
		RemoteDestinationFacts::new(
			ids,
			RemoteKernelArchitecture::X86_64,
			b"6.8.12-fixture",
			b"#1 SMP fixture",
			selected,
		)
		.expect("bounded synthetic destination facts")
	};
	let selected = project(SELECTED);
	let reordered = project(REORDERED);
	assert_eq!(selected.mount_record(), SELECTED);
	assert_eq!(reordered.mount_record(), REORDERED);
	assert_ne!(
		selected, reordered,
		"mount-option order changes the exact destination facts"
	);
}
