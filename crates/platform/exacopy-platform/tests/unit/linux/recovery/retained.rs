use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use super::{Fixture, PART, PAYLOAD, TARGET, binding, component, inventory};
use crate::linux::{ReadError, StageError};

#[test]
fn selected_stream_retains_source_stage_and_incumbent_when_private_name_changes() {
	const INCUMBENT: &[u8] = b"independent incumbent";
	const REPLACEMENT: &[u8] = b"replacement fixture inode";
	let fixture = Fixture::new();
	let source = fixture.scratch.path("source");
	fs::write(&source, PAYLOAD).unwrap();
	let source_inode = fs::metadata(&source).unwrap().ino();
	let stage = fixture.stage();
	fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
	let stage_inode = fs::metadata(&stage).unwrap().ino();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let observed = inventory.stage().unwrap();
	let mut verified = [0; PAYLOAD.len()];
	observed.read_exact_at(0, &mut verified).unwrap();
	observed.check_logical_eof().unwrap();
	let source_bytes = fs::read(&source).unwrap();
	assert_eq!(verified.as_slice(), source_bytes.as_slice());
	let retained = lease
		.prepare_retained_stage(&inventory, binding(2))
		.unwrap();

	let location = retained.inspect_selected_stream_location().unwrap();
	assert_eq!(location.binding, binding(2));
	assert_eq!(location.stage, observed.identity());
	assert_eq!(
		Some(location.directory),
		inventory.stage_directory_identity()
	);
	assert_eq!(location.destination, fixture.root.identity());
	assert_eq!(location.names.stage, component(PART));
	assert_eq!(location.names.target, component(TARGET));

	let ready = retained
		.prepare_selected_stream_metadata(observed.len())
		.unwrap();
	assert_eq!(ready.observed().stage(), observed.identity());
	let names = ready.names().unwrap();
	assert_eq!(names.stage, component(PART));
	assert_eq!(names.target, component(TARGET));

	let target = fixture.target();
	fs::write(&target, INCUMBENT).unwrap();
	let incumbent_inode = fs::metadata(&target).unwrap().ino();
	let moved = fixture.scratch.path("retained-original");
	fs::rename(&stage, &moved).unwrap();
	fs::write(&stage, REPLACEMENT).unwrap();
	fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
	let replacement_inode = fs::metadata(&stage).unwrap().ino();

	assert!(matches!(ready.recheck(), Err(StageError::IdentityChanged)));
	assert_eq!(fs::metadata(&source).unwrap().ino(), source_inode);
	assert_eq!(fs::metadata(&target).unwrap().ino(), incumbent_inode);
	assert_eq!(fs::metadata(&moved).unwrap().ino(), stage_inode);
	assert_eq!(fs::metadata(&stage).unwrap().ino(), replacement_inode);
	assert_eq!(fs::read(source).unwrap(), source_bytes);
	assert_eq!(fs::read(target).unwrap(), INCUMBENT);
	assert_eq!(fs::read(moved).unwrap(), PAYLOAD);
	assert_eq!(fs::read(stage).unwrap(), REPLACEMENT);
}

#[test]
fn selected_stream_refuses_changed_content_on_the_original_inode() {
	const CHANGED: &[u8] = b"different retained stage content";
	let fixture = Fixture::new();
	let stage = fixture.stage();
	fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
	let original_inode = fs::metadata(&stage).unwrap().ino();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let retained = lease
		.prepare_retained_stage(&inventory, binding(2))
		.unwrap();

	fs::write(&stage, CHANGED).unwrap();

	assert!(matches!(
		retained.inspect_selected_stream_location(),
		Err(StageError::ReadBack(ReadError::SourceChanged))
	));
	assert!(!fixture.target().exists());
	assert_eq!(fs::metadata(&stage).unwrap().ino(), original_inode);
	assert_eq!(fs::read(stage).unwrap(), CHANGED);
}

#[test]
fn retained_preparation_refuses_an_absent_stage_and_preserves_a_separate_entry() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let missing = lease
		.job()
		.inventory(component("missing-stage"), component(TARGET))
		.unwrap();
	let stage = fixture.stage();
	let stage_inode = fs::metadata(&stage).unwrap().ino();

	assert!(matches!(
		lease.prepare_retained_stage(&missing, binding(2)),
		Err(StageError::IdentityChanged)
	));
	assert!(!fixture.target().exists());
	assert_eq!(fs::metadata(&stage).unwrap().ino(), stage_inode);
	assert_eq!(fs::read(stage).unwrap(), PAYLOAD);
}
