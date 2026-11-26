use std::fs::{self, File};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::fs::OpenOptionsExt as _;

use rustix::fs::{Timespec, Timestamps};

use apfs_mounted::metadata::ObservationError;

use super::{
	BasicMetadata, BasicMetadataError, ManagedTimestamp, check_inventory,
	require_absent_fork_attribute,
};

const RESOURCE_FORK: &std::ffi::CStr = c"com.apple.ResourceFork";

#[test]
fn empty_and_oversize_named_forks_are_distinct_from_absence() {
	assert!(require_absent_fork_attribute(Ok(None)).is_ok());
	assert!(matches!(
		require_absent_fork_attribute(Ok(Some(Vec::new()))),
		Err(BasicMetadataError::ResourceFork)
	));
	assert!(matches!(
		require_absent_fork_attribute(Err(ObservationError::Limit {
			limit: 0,
			observed: 16
		})),
		Err(BasicMetadataError::ResourceFork)
	));
	let error = rustix::io::Errno::ACCESS;
	assert!(matches!(
		require_absent_fork_attribute(Err(ObservationError::PermissionDenied(error.into()))),
		Err(BasicMetadataError::Inventory(source)) if source.raw_os_error() == Some(error.raw_os_error())
	));
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
fn projects_native_stat_and_detects_independent_timestamp_changes() {
	const MODE: u32 = 0o600;
	let path = std::path::Path::new("/private/tmp").join(format!(
		"exacopy-basic-projection-test-{}",
		std::process::id()
	));
	let file = File::options()
		.write(true)
		.create_new(true)
		.mode(MODE)
		.open(&path)
		.expect("create owner-private stat projection fixture");
	let original = Timestamps {
		last_access: Timespec {
			tv_sec: 1_610_000_000,
			tv_nsec: 123_456_789,
		},
		last_modification: Timespec {
			tv_sec: 1_620_000_000,
			tv_nsec: 987_654_321,
		},
	};
	rustix::fs::futimens(&file, &original).unwrap();
	let stat = rustix::fs::fstat(&file).unwrap();
	let metadata = BasicMetadata::from_stat(&stat).expect("project regular file stat fields");
	assert_eq!(metadata.uid(), stat.st_uid);
	assert_eq!(metadata.gid(), stat.st_gid);
	assert_eq!(metadata.mode(), MODE);
	assert_timestamp(metadata.atime(), &original.last_access);
	assert_timestamp(metadata.mtime(), &original.last_modification);
	assert!(metadata.matches(&stat));

	let mut changed_access = original.clone();
	changed_access.last_access.tv_nsec += 1;
	let mut changed_modification = original;
	changed_modification.last_modification.tv_nsec += 1;
	for changed in [changed_access, changed_modification] {
		rustix::fs::futimens(&file, &changed).unwrap();
		let stat = rustix::fs::fstat(&file).unwrap();
		assert!(
			!metadata.matches(&stat),
			"a one-nanosecond timestamp change must invalidate the original projection"
		);
		let observed = BasicMetadata::from_stat(&stat).unwrap();
		assert_timestamp(observed.atime(), &changed.last_access);
		assert_timestamp(observed.mtime(), &changed.last_modification);
	}
	fs::remove_file(path).expect("remove the private stat projection fixture");
}

fn assert_timestamp(observed: super::super::ManagedTimestamp, expected: &Timespec) {
	assert_eq!(observed.seconds(), expected.tv_sec);
	assert_eq!(i64::from(observed.nanoseconds()), expected.tv_nsec);
}

#[test]
#[allow(unsafe_code, reason = "native xattr and fork fixture setup")]
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
#[allow(
	unsafe_code,
	reason = "independent native provenance observation for the fixture"
)]
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
