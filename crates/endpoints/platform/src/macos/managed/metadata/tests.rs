use std::fs::{self, File};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::fs::OpenOptionsExt as _;

use super::{
	BasicMetadataError, FIELD_BYTES, ManagedTimestamp, RESOURCE_BYTES, RESOURCE_FORK,
	ResourceBuffer, check_inventory, is_zero_fork,
};

#[test]
fn accepts_only_a_complete_zero_resource_fork_record() {
	let mut buffer = ResourceBuffer([0; RESOURCE_BYTES]);
	let header = [
		RESOURCE_BYTES as u32,
		libc::ATTR_CMN_RETURNED_ATTRS,
		0,
		0,
		libc::ATTR_FILE_RSRCLENGTH,
		0,
	];
	for (index, value) in header.into_iter().enumerate() {
		let start = FIELD_BYTES * index;
		buffer.0[start..start + FIELD_BYTES].copy_from_slice(&value.to_ne_bytes());
	}
	assert!(is_zero_fork(&buffer));
	for offset in 0..buffer.0.len() {
		let mut changed = ResourceBuffer(buffer.0);
		changed.0[offset] ^= 1;
		assert!(!is_zero_fork(&changed), "changed record byte {offset}");
	}
}

#[test]
fn timestamps_reject_out_of_range_and_native_sentinel_fractions() {
	assert!(ManagedTimestamp::from_stat_parts(0, 1_000_000_000).is_none());
	assert!(ManagedTimestamp::from_stat_parts(0, -1).is_none());
	let time = ManagedTimestamp::from_stat_parts(-23, 999_999_999).unwrap();
	assert_eq!(time.seconds(), -23);
	assert_eq!(time.nanoseconds(), 999_999_999);
}

#[test]
fn rejects_native_empty_xattr_and_nonempty_resource_fork() {
	let path = std::path::Path::new("/private/tmp").join(format!(
		"exacopy-basic-inventory-test-{}",
		std::process::id()
	));
	let file = File::options()
		.read(true)
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&path)
		.expect("exclusive native inventory fixture");
	// The held descriptor keeps the synthetic inode available after removal.
	fs::remove_file(path).expect("remove the private fixture name");

	// SAFETY: The fd stays live and each name and value points to immutable storage.
	let status = unsafe {
		libc::fsetxattr(
			file.as_raw_fd(),
			c"org.replicraft.exacopy.empty-fixture".as_ptr(),
			c"".as_ptr().cast(),
			0,
			0,
			libc::XATTR_CREATE,
		)
	};
	assert_eq!(status, 0, "install empty native attribute");
	assert!(matches!(
		check_inventory(file.as_fd()),
		Err(BasicMetadataError::ExtendedAttributes)
	));

	// SAFETY: The fd stays live and the static value supplies all four bytes.
	let status = unsafe {
		libc::fsetxattr(
			file.as_raw_fd(),
			RESOURCE_FORK.as_ptr(),
			b"fork".as_ptr().cast(),
			4,
			0,
			libc::XATTR_CREATE,
		)
	};
	assert_eq!(status, 0, "install a native resource fork");
	assert!(matches!(
		check_inventory(file.as_fd()),
		Err(BasicMetadataError::ResourceFork)
	));
}

#[test]
fn strict_inventory_has_no_provenance_exemption() {
	let path = std::path::Path::new("/private/tmp").join(format!(
		"exacopy-basic-provenance-test-{}",
		std::process::id()
	));
	let file = File::options()
		.read(true)
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&path)
		.expect("exclusive native provenance fixture");
	fs::remove_file(path).expect("remove synthetic fixture name");

	// SAFETY: The live descriptor and static attribute name remain valid.
	// Passing zero and null makes this a size-only query.
	let marker_bytes = unsafe {
		libc::fgetxattr(
			file.as_raw_fd(),
			c"com.apple.provenance".as_ptr(),
			std::ptr::null_mut(),
			0,
			0,
			0,
		)
	};
	if marker_bytes >= 0 {
		assert!(matches!(
			check_inventory(file.as_fd()),
			Err(BasicMetadataError::ExtendedAttributes)
		));
		eprintln!("native fixture exposed com.apple.provenance ({marker_bytes} bytes)");
	} else {
		assert_eq!(
			std::io::Error::last_os_error().raw_os_error(),
			Some(libc::ENOATTR)
		);
		check_inventory(file.as_fd()).expect("admit native fixture without visible attributes");
	}
}
