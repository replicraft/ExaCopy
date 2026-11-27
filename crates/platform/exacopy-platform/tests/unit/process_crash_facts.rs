use std::error::Error;
use std::io;

use rustix::fs::makedev;
use rustix::io::Errno;

use super::MOUNTINFO;
use crate::linux::mount_observation::MountObservations;
use crate::linux::process_crash::mount::{Mount, is_fixture_mount};
use crate::linux::process_crash::{
	ProcessCrashProfileError, StageError, parse_boot_id, proc_error,
};

#[test]
fn parsed_mount_facts_require_the_held_id_and_one_canonical_shared_group() {
	let mount = Mount {
		id: 32,
		unique_id: 10_044,
		device: makedev(253, 1),
	};
	let table =
		MountObservations::parse(MOUNTINFO.as_bytes()).expect("parse synthetic mount table");
	let record = table.record(mount.id).expect("find synthetic mount record");
	assert!(
		!is_fixture_mount(&record, Mount { id: 31, ..mount }),
		"a different held mount ID cannot match the same parsed record"
	);

	for (fields, accepted) in [
		("shared:2 ", true),
		("shared:18446744073709551616 ", false),
		("shared:0 ", false),
		("shared:01 ", false),
		("", false),
		("shared:1 master:2 ", false),
	] {
		let row = MOUNTINFO.replacen("shared:1 ", fields, 1);
		let table = MountObservations::parse(row.as_bytes()).expect("parse synthetic mount table");
		let record = table.record(mount.id).expect("find synthetic mount record");
		assert_eq!(
			is_fixture_mount(&record, mount),
			accepted,
			"optional fields {fields:?}"
		);
	}
}

#[test]
fn rejects_wrong_length_or_noncanonical_boot_id_bytes() {
	for input in [
		b"00112233-4455-4677-8899-aabbccddeef\n".as_slice(),
		b"00112233-4455-4677-8899-aabbccddeeff\r\n",
		b"00112233-4455-4677-8899-Aabbccddeeff\n",
		b"00112233-4455-4677-8899-aabbccddee\xff\n",
	] {
		assert_eq!(parse_boot_id(input), None, "boot ID bytes {input:?}");
	}
}

#[test]
fn proc_errors_distinguish_unavailable_facts_from_io_failure() {
	for kind in [io::ErrorKind::Unsupported, io::ErrorKind::InvalidData] {
		assert!(
			matches!(
				proc_error(io::Error::from(kind)),
				ProcessCrashProfileError::UnsupportedProc
			),
			"proc observation error {kind:?}"
		);
	}

	let errno = Errno::ACCESS;
	assert!(
		matches!(
			proc_error(errno.into()),
			ProcessCrashProfileError::Io(error)
				if error.raw_os_error() == Some(errno.raw_os_error())
		),
		"a native proc I/O failure retains its original cause"
	);
}

#[test]
fn profile_refusals_identify_the_missing_or_changed_evidence() {
	for (error, context) in [
		(ProcessCrashProfileError::UnsupportedKernel, "kernel"),
		(
			ProcessCrashProfileError::UnsupportedProc,
			"procfs observations",
		),
		(ProcessCrashProfileError::UnsupportedMount, "mount evidence"),
		(
			ProcessCrashProfileError::EnvironmentChanged,
			"environment differs",
		),
	] {
		assert!(error.to_string().contains(context), "{error:?}");
		assert!(error.source().is_none(), "{error:?}");
	}
}

#[test]
fn profile_observation_failures_preserve_their_typed_causes() {
	let destination = ProcessCrashProfileError::Destination(StageError::UnsafeDirectory);
	assert!(
		destination
			.to_string()
			.contains("destination root admission")
	);
	assert!(matches!(
		destination
			.source()
			.and_then(|cause| cause.downcast_ref::<StageError>()),
		Some(StageError::UnsafeDirectory)
	));

	let errno = Errno::IO;
	let observation = ProcessCrashProfileError::from(errno);
	assert!(observation.to_string().contains("environment observation"));
	assert_eq!(
		observation
			.source()
			.and_then(|cause| cause.downcast_ref::<io::Error>())
			.and_then(io::Error::raw_os_error),
		Some(errno.raw_os_error())
	);
}
