use std::fs::{self, File};
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;

use rustix::fs::{self as native_fs, XattrFlags};

use super::super::{DATA, STAGE, job_context, name};
use super::{Fixture, RecoveryError, TARGET, job_name, job_path, open_staging};
use crate::macos::BasicMetadataError;
use crate::macos::staging::jobs::RecoveryName;
use crate::macos::staging::{MAX_STAGE_IO_BYTES, StageError};

const OUTSIDE_BYTES: &[u8] = b"incumbent bytes";

fn stage_fixture(fixture: &Fixture, bytes: &[u8]) -> PathBuf {
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container.create_job_directory(job_name()).unwrap();
	let stage = job.create_stage_directory().unwrap();
	let mut writer = stage
		.create_file(
			name(DATA.as_bytes()),
			name(TARGET.as_bytes()),
			job_context(),
			bytes.len() as u64,
		)
		.unwrap();
	for chunk in bytes.chunks(MAX_STAGE_IO_BYTES) {
		writer.write_next(chunk).unwrap();
	}
	writer.flush_and_close().unwrap();
	job_path(fixture).join(STAGE).join(DATA)
}

#[test]
#[ignore = "requires a native APFS stage with zero visible xattrs"]
fn explicit_private_read_back_reads_bounded_ranges_and_rechecks_atime_and_eof() {
	let fixture = Fixture::new();
	let mut bytes = vec![0x5a; MAX_STAGE_IO_BYTES];
	bytes.extend(b"last bytes");
	let stage = stage_fixture(&fixture, &bytes);
	let target = fixture.path(TARGET);
	fs::write(&target, OUTSIDE_BYTES).unwrap();
	let target_before = fs::metadata(&target).unwrap();
	let stage_before = fs::metadata(&stage).unwrap();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container.open_recovery_job(job_name()).unwrap();
	let inventory = job
		.inventory(name(DATA.as_bytes()), name(TARGET.as_bytes()))
		.unwrap();
	let observation = inventory.stage().unwrap();
	assert!(matches!(
		inventory.open_stage_read_back(inventory.target().unwrap()),
		Err(RecoveryError::InvalidEntry(RecoveryName::Stage))
	));
	let reader = inventory.open_stage_read_back(observation).unwrap();
	assert_eq!(reader.observation(), observation);
	assert_eq!(
		reader.initial_metadata().atime().seconds(),
		stage_before.atime()
	);
	assert_eq!(
		i64::from(reader.initial_metadata().atime().nanoseconds()),
		stage_before.atime_nsec()
	);

	let mut observed = vec![0; bytes.len()];
	assert!(matches!(
		reader.read_exact_at(0, &mut observed),
		Err(RecoveryError::Managed(StageError::InvalidRange))
	));
	assert!(matches!(
		reader.read_exact_at(reader.observation().length(), &mut [0]),
		Err(RecoveryError::Managed(StageError::InvalidRange))
	));
	assert!(matches!(
		reader.read_exact_at(u64::MAX, &mut [0]),
		Err(RecoveryError::Managed(StageError::InvalidRange))
	));
	assert!(observed.iter().all(|&byte| byte == 0));
	let (prefix, suffix) = observed.split_at_mut(MAX_STAGE_IO_BYTES);
	reader
		.read_exact_at(MAX_STAGE_IO_BYTES as u64, suffix)
		.unwrap();
	reader.read_exact_at(0, prefix).unwrap();
	let final_metadata = reader.revalidate().unwrap();
	assert_eq!(observed, bytes);
	let stage_after = fs::metadata(&stage).unwrap();
	assert_eq!(final_metadata.atime().seconds(), stage_after.atime());
	assert_eq!(
		i64::from(final_metadata.atime().nanoseconds()),
		stage_after.atime_nsec()
	);
	assert_eq!(final_metadata.mtime(), reader.initial_metadata().mtime());

	let target_after = fs::metadata(&target).unwrap();
	assert_eq!(
		(target_before.atime(), target_before.atime_nsec()),
		(target_after.atime(), target_after.atime_nsec())
	);
	assert_eq!(fs::read(&target).unwrap(), OUTSIDE_BYTES);
}

#[test]
fn strict_inventory_rejects_a_private_stage_xattr_before_returning_a_reader() {
	let fixture = Fixture::new();
	let stage = stage_fixture(&fixture, b"staged bytes with a visible xattr");
	native_fs::fsetxattr(
		File::open(&stage).unwrap(),
		c"com.exacopy.test.recovery",
		b"synthetic",
		XattrFlags::CREATE,
	)
	.unwrap();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container.open_recovery_job(job_name()).unwrap();
	let inventory = job
		.inventory(name(DATA.as_bytes()), name(TARGET.as_bytes()))
		.unwrap();
	assert!(matches!(
		inventory.open_stage_read_back(inventory.stage().unwrap()),
		Err(RecoveryError::Managed(StageError::BasicMetadata(
			BasicMetadataError::ExtendedAttributes
		)))
	));
}

#[test]
fn refuses_mismatched_expected_identity_and_a_replaced_stage_before_readable_open() {
	let fixture = Fixture::new();
	let stage = stage_fixture(&fixture, b"data");
	let target = fixture.path(TARGET);
	fs::write(&target, OUTSIDE_BYTES).unwrap();
	let before = fs::metadata(&target).unwrap();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container.open_recovery_job(job_name()).unwrap();
	let inventory = job
		.inventory(name(DATA.as_bytes()), name(TARGET.as_bytes()))
		.unwrap();
	let observed = inventory.stage().unwrap();
	assert!(matches!(
		inventory.open_stage_read_back(inventory.target().unwrap()),
		Err(RecoveryError::InvalidEntry(RecoveryName::Stage))
	));
	let retained = stage.with_extension("retained");
	// Synthetic rebind after the recorded inventory observation.
	fs::rename(&stage, &retained).unwrap();
	fs::write(&stage, b"new!").unwrap();
	assert!(matches!(
		inventory.open_stage_read_back(observed),
		Err(RecoveryError::InvalidEntry(RecoveryName::Stage))
	));
	let after = fs::metadata(&target).unwrap();
	assert_eq!(
		(before.atime(), before.atime_nsec()),
		(after.atime(), after.atime_nsec())
	);
	assert_eq!(fs::read(&target).unwrap(), OUTSIDE_BYTES);
	assert_eq!(fs::read(&retained).unwrap(), b"data");
	assert_eq!(fs::read(&stage).unwrap(), b"new!");
}

#[test]
#[ignore = "requires a native APFS stage with zero visible xattrs"]
fn before_and_after_reopen_a_rebound_stage_refuses_data_and_eof_checks() {
	let fixture = Fixture::new();
	let stage = stage_fixture(&fixture, b"data");
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container.open_recovery_job(job_name()).unwrap();
	let inventory = job
		.inventory(name(DATA.as_bytes()), name(TARGET.as_bytes()))
		.unwrap();
	let observation = inventory.stage().unwrap();
	let reader = inventory.open_stage_read_back(observation).unwrap();

	// Replace the fixture name outside the cooperative lease contract.
	let retained = stage.with_extension("retained");
	fs::rename(&stage, &retained).unwrap();
	fs::write(&stage, b"new!").unwrap();
	let expected = |result| {
		matches!(
			result,
			Err(RecoveryError::InvalidEntry(RecoveryName::Stage))
		)
	};
	assert!(expected(
		inventory.open_stage_read_back(observation).map(|_| ())
	));
	let mut received = [0; 4];
	assert!(expected(reader.read_exact_at(0, &mut received)));
	assert!(expected(reader.revalidate().map(|_| ())));
	assert_eq!(received, [0; 4]);
	assert_eq!(fs::read(retained).unwrap(), b"data");
	assert_eq!(fs::read(stage).unwrap(), b"new!");
}

#[test]
#[ignore = "requires a native APFS stage with zero visible xattrs"]
fn empty_private_stage_is_read_back_with_a_checked_eof() {
	let fixture = Fixture::new();
	stage_fixture(&fixture, b"");
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container.open_recovery_job(job_name()).unwrap();
	let inventory = job
		.inventory(name(DATA.as_bytes()), name(TARGET.as_bytes()))
		.unwrap();
	let reader = inventory
		.open_stage_read_back(inventory.stage().unwrap())
		.unwrap();
	assert_eq!(reader.observation().length(), 0);
	reader.read_exact_at(0, &mut []).unwrap();
	reader.revalidate().unwrap();
}
