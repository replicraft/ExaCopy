use std::fs;
use std::io::Write as _;
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::fs::OpenOptionsExt as _;

use super::{
	FILE_FLAG_OPEN_REPARSE_POINT, File, JournalJobId, OpenOptions, OsString, Path,
	WindowsBootstrapRoleKind, WindowsComponent, directory, job_directory_name, observe,
};
use exacopy_platform::windows::{WindowsCaptureStageError, WindowsCaptureStageScope};

const TARGET: &str = "owned-capture-target";
const TARGET_ALIAS: &str = "OWNED-CAPTURE-TARGET";
const STAGE_DIRECTORY: &str = "stage";
const PAYLOAD: &str = "payload";
const INCUMBENT: &[u8] = b"independently owned incumbent";
const DATA: &[u8] = b"synthetic private capture payload";

pub(super) fn check(
	original: &WindowsCaptureStageScope<'_>,
	root: &Path,
	drive: u8,
	job: JournalJobId,
) {
	use WindowsBootstrapRoleKind::{Directory, RegularFile};

	let stage = root
		.join(OsString::from_wide(&job_directory_name(job)))
		.join(STAGE_DIRECTORY);
	let stage_file = stage.join(PAYLOAD);
	let incumbent = root.join(TARGET_ALIAS);
	let target_units: Vec<_> = TARGET.encode_utf16().collect();
	let target = WindowsComponent::new(&target_units).unwrap();
	let source = DATA;
	let mut file = File::create_new(&incumbent).unwrap();
	file.write_all(INCUMBENT).unwrap();
	let incumbent_identity = observe(drive, &file, RegularFile);
	drop(file);
	let refused: Result<(), _> = original.with_capture_stage(target, source.len() as u64, |_| {
		panic!("an occupied target reached private stage creation")
	});
	assert!(matches!(
		refused,
		Err(WindowsCaptureStageError::TargetOccupied)
	));
	assert_eq!(
		fs::symlink_metadata(&stage).unwrap_err().kind(),
		std::io::ErrorKind::NotFound
	);
	assert_eq!(fs::read(&incumbent).unwrap(), INCUMBENT);
	assert_eq!(
		observe(drive, &open_leaf(&incumbent), RegularFile),
		incumbent_identity
	);
	fs::remove_file(incumbent).unwrap();

	let (directory_id, stage_id) = original
		.with_capture_stage(target, source.len() as u64, |mut writer| {
			let directory_id = writer.directory_identity();
			let stage_id = writer.stage_identity();
			let split = source.len() / 2;
			writer.write_at(0, &source[..split])?;
			let prefix = writer.sync_written_prefix(split as u64)?;
			assert_eq!(prefix.parent(), directory_id);
			assert_eq!(prefix.stage(), stage_id);
			assert_eq!(prefix.end(), split as u64);
			writer.write_at(prefix.end(), &source[split..])?;
			let mut verified = writer.finish()?;
			let mut bytes = [0; DATA.len()];
			verified
				.read_exact_at(0, &mut bytes)
				.map_err(WindowsCaptureStageError::Stage)?;
			verified
				.recheck()
				.map_err(WindowsCaptureStageError::Stage)?;
			assert_eq!(bytes.as_slice(), source);
			Ok((directory_id, stage_id))
		})
		.expect("create a protected held stage and read back its exact bytes");
	assert_eq!(
		observe(drive, &directory(&stage), Directory),
		super::identity(directory_id)
	);
	assert_eq!(
		observe(drive, &open_leaf(&stage_file), RegularFile),
		super::identity(stage_id)
	);
	let repeated: Result<(), _> = original.with_capture_stage(target, source.len() as u64, |_| {
		panic!("an occupied stage directory reached a second write operation")
	});
	assert!(matches!(
		repeated,
		Err(WindowsCaptureStageError::StageDirectoryOccupied)
	));
	assert_eq!(
		observe(drive, &open_leaf(&stage_file), RegularFile),
		super::identity(stage_id)
	);
	assert_eq!(fs::read(&stage_file).unwrap(), source);
	assert_eq!(
		fs::symlink_metadata(root.join(TARGET)).unwrap_err().kind(),
		std::io::ErrorKind::NotFound
	);
	fs::remove_file(stage_file).unwrap();
	fs::remove_dir(stage).unwrap();
}

fn open_leaf(path: &Path) -> File {
	OpenOptions::new()
		.read(true)
		.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
		.open(path)
		.unwrap()
}
