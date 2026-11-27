use std::io;

use super::{MAX_MOUNT_RECORDS, MAX_MOUNTINFO_BYTES, MountObservations};

#[test]
fn malformed_row_refuses_the_entire_mount_table() {
	const VALID_ROW: &[u8] = b"13 1 0:1 / /control rw - tmpfs tmpfs rw\n";
	MountObservations::parse(VALID_ROW).expect("the leading mount row is valid");

	for bad in [
		b"\n".as_slice(),
		b"21\n",
		b"21 0 8:1 / / rw - ext4 /dev/example rw\n",
		b"21 1\n",
		b"21 1 81 / / rw - ext4 /dev/example rw\n",
		b"21 1 \xff:1 / / rw - ext4 /dev/example rw\n",
		b"21 1 x:1 / / rw - ext4 /dev/example rw\n",
		b"21 1 8:\xff / / rw - ext4 /dev/example rw\n",
		b"21 1 8:4294967296 / / rw - ext4 /dev/example rw\n",
		b"21 1 8:1\n",
		b"21 1 8:1 / relative rw - ext4 /dev/example rw\n",
		b"21 1 8:1 / /  - ext4 /dev/example rw\n",
		b"21 1 8:1 / / rw shared:2\n",
		b"21 1 8:1 / / rw shared:2  - ext4 /dev/example rw\n",
		b"21 1 8:1 / / rw -  /dev/example rw\n",
		b"21 1 8:1 / / rw - ext4  rw\n",
		b"21 1 8:1 / / rw - ext4 /dev/example \n",
		b"21 1 8:1 / / rw - ext4 /dev/example rw unexpected\n",
	] {
		let table = [VALID_ROW, bad].concat();
		let result = MountObservations::parse(&table);
		assert!(
			matches!(result, Err(error) if error.kind() == io::ErrorKind::Unsupported),
			"the table must refuse malformed row {bad:?}"
		);
	}
}

#[test]
fn mount_record_limit_refuses_an_additional_valid_row() {
	use std::fmt::Write as _;

	let mut rows = String::new();
	for id in (1..=MAX_MOUNT_RECORDS).rev() {
		writeln!(rows, "{id} 1 0:1 / / rw - tmpfs tmpfs rw").expect("write fixture row");
	}

	let observations =
		MountObservations::parse(rows.as_bytes()).expect("admit the exact record limit");
	assert_eq!(
		observations.record_bytes(1),
		Some(b"1 1 0:1 / / rw - tmpfs tmpfs rw".as_slice())
	);

	let extra_id = MAX_MOUNT_RECORDS + 1;
	writeln!(rows, "{extra_id} 1 0:1 / / rw - tmpfs tmpfs rw").expect("write extra row");
	assert!(rows.len() < MAX_MOUNTINFO_BYTES);
	let result = MountObservations::parse(rows.as_bytes());
	assert!(
		matches!(result, Err(error) if error.kind() == io::ErrorKind::Unsupported),
		"one additional valid record must refuse the entire table"
	);
}

#[test]
fn nsfs_namespace_root_requires_an_inode() {
	let valid = b"17 13 0:4 net:[4294967295] /run/handle rw - nsfs nsfs rw\n";
	MountObservations::parse(valid).expect("admit the complete namespace handle");

	let missing_inode = b"17 13 0:4 net /run/handle rw - nsfs nsfs rw\n";
	let result = MountObservations::parse(missing_inode);
	assert!(
		matches!(result, Err(error) if error.kind() == io::ErrorKind::Unsupported),
		"a recognized namespace kind still requires an inode"
	);
}
