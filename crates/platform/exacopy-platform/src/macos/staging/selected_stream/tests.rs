use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use exacopy_endpoint::ReadView as _;

use super::super::StageError;
use super::super::tests::{Fixture, make_stage, open_staging};

#[test]
#[ignore = "requires managed APFS fixtures without visible extended attributes"]
fn independently_reads_private_unnamed_stream_and_observes_local_metadata() {
	const PAYLOAD: &[u8] = b"remote unnamed stream\0\xff";
	let fixture_owner = FixtureOwner(Fixture::new());
	let fixture = &fixture_owner.0;
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, u64::try_from(PAYLOAD.len()).unwrap()).unwrap();
	writer.write_next(PAYLOAD).unwrap();
	let stage = writer.flush_and_close().unwrap();
	assert!(stage.open_selected_stream_read_back(1).is_err());
	let reader = stage
		.open_selected_stream_read_back(stage.length())
		.unwrap();
	let mut actual = [0; PAYLOAD.len()];
	reader.read_exact_at(0, &mut actual).unwrap();
	assert_eq!(&actual, PAYLOAD);
	assert!(reader.read_exact_at(stage.length(), &mut [0]).is_err());
	let observed = reader.revalidate().unwrap();
	assert_eq!(observed.binding, stage.binding());
	assert_eq!(observed.stage, stage.observe_identity().unwrap());
	assert_eq!(
		observed.stage_directory,
		directory.observe_identity().unwrap()
	);
	assert_eq!(observed.destination, root.observe_identity().unwrap());
	assert_eq!(observed.stage_name.as_bytes(), b"candidate");
	assert_eq!(observed.target_name.as_bytes(), b"target");
	assert_eq!(observed.length, stage.length());
	assert_eq!(observed.mode, 0o600);
	let stat = fs::symlink_metadata(fixture.stage_path()).unwrap();
	assert_eq!(stat.uid(), observed.owner);
	assert_eq!(stat.gid(), observed.group);
	assert!(!fixture.path("target").exists());
}

#[test]
#[ignore = "requires managed APFS fixtures without visible extended attributes"]
fn empty_stream_revalidation_refuses_changed_local_mode() {
	let fixture_owner = FixtureOwner(Fixture::new());
	let fixture = &fixture_owner.0;
	let root = fixture.bind();
	let directory = open_staging(&root);
	let stage = make_stage(&directory, 0)
		.unwrap()
		.flush_and_close()
		.unwrap();
	let reader = stage.open_selected_stream_read_back(0).unwrap();
	assert_eq!(reader.revalidate().unwrap().length, 0);
	fs::set_permissions(fixture.stage_path(), fs::Permissions::from_mode(0o640)).unwrap();
	assert!(reader.revalidate().is_err());
	assert!(stage.open_selected_stream_read_back(0).is_err());
	assert!(!fixture.path("target").exists());
}

#[test]
fn length_or_mode_mismatch_preserves_private_and_public_names() {
	let fixture_owner = FixtureOwner(Fixture::new());
	let fixture = &fixture_owner.0;
	let root = fixture.bind();
	let directory = open_staging(&root);
	let stage = make_stage(&directory, 0)
		.unwrap()
		.flush_and_close()
		.unwrap();
	assert!(matches!(
		stage.open_selected_stream_read_back(1),
		Err(StageError::MetadataMismatch)
	));
	fs::set_permissions(fixture.stage_path(), fs::Permissions::from_mode(0o640)).unwrap();
	assert!(matches!(
		stage.open_selected_stream_read_back(0),
		Err(StageError::StageChanged)
	));
	assert_eq!(fs::symlink_metadata(fixture.stage_path()).unwrap().len(), 0);
	assert!(!fixture.path("target").exists());
}

struct FixtureOwner(Fixture);

impl Drop for FixtureOwner {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(self.0.path(""));
	}
}
