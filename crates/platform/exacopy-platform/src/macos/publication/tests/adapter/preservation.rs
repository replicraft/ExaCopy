use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::{
	Fixture, INCUMBENT, PAYLOAD, PublishError, PublishRejection, STAGE_DIRECTORY, STAGE_NAME,
	TARGET_NAME, identity, name, write_new,
};

#[test]
#[ignore = "requires managed APFS fixtures without visible extended attributes"]
fn same_job_entry_and_epoch_cannot_authorize_another_physical_stage() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = root
		.open_stage_directory(name(STAGE_DIRECTORY))
		.expect("open provisioned stage directory");
	// Both stages have the same job, entry and epoch, and target the same absent name.
	let first = fixture.standard_stage(&directory);
	let other_name = "other-stage";
	let second = fixture.ready_stage(&directory, other_name, TARGET_NAME);
	assert_ne!(first.identity(), second.identity());
	let stage_directory = fixture.destination.path(STAGE_DIRECTORY);
	let first_path = stage_directory.join(STAGE_NAME);
	let second_path = stage_directory.join(other_name);
	let first_inode = identity(&first_path);
	let second_inode = identity(&second_path);
	assert_ne!(first_inode, second_inode);
	let authorization = fixture.authorize(first.binding());

	let result = second.publish_with_barriers(authorization, |_| {
		panic!("authorization mismatch must not lead to a directory barrier")
	});

	assert!(matches!(
		result,
		Err(PublishError::Rejected {
			reason: PublishRejection::BindingMismatch,
			policy_error: None
		})
	));
	assert_absent(&fixture.destination.path(TARGET_NAME));
	assert_eq!(identity(&first_path), first_inode);
	assert_eq!(identity(&second_path), second_inode);
	assert_eq!(fs::read(first_path).unwrap(), PAYLOAD);
	assert_eq!(fs::read(second_path).unwrap(), PAYLOAD);
}

#[test]
#[ignore = "requires managed APFS fixtures without visible extended attributes"]
fn late_hard_link_incumbent_preserves_both_links_and_private_stage() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = root.open_stage_directory(name(STAGE_DIRECTORY)).unwrap();
	let stage = fixture.standard_stage(&directory);
	let authorization = fixture.authorize(stage.binding());
	let stage_path = fixture.destination.path(STAGE_DIRECTORY).join(STAGE_NAME);
	let stage_inode = identity(&stage_path);
	let referent = fixture.destination.path("incumbent");
	let target = fixture.destination.path(TARGET_NAME);
	write_new(&referent, INCUMBENT);
	fs::hard_link(&referent, &target).expect("create independent late incumbent alias");
	let incumbent_inode = identity(&referent);

	assert!(matches!(
		stage.publish_with_barriers(authorization, |_| panic!("no barriers without rename")),
		Err(PublishError::Conflict { policy_error: None })
	));
	assert_eq!(identity(&target), incumbent_inode);
	assert_eq!(identity(&referent), incumbent_inode);
	assert_eq!(identity(&stage_path), stage_inode);
	assert_eq!(fs::read(referent).unwrap(), INCUMBENT);
	assert_eq!(fs::read(target).unwrap(), INCUMBENT);
	assert_eq!(fs::read(stage_path).unwrap(), PAYLOAD);
}

#[test]
#[ignore = "requires managed APFS fixtures without visible extended attributes"]
fn late_case_alias_is_preserved_when_the_volume_resolves_both_spellings() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = root.open_stage_directory(name(STAGE_DIRECTORY)).unwrap();
	let stage = fixture.standard_stage(&directory);
	let authorization = fixture.authorize(stage.binding());
	let stage_path = fixture.destination.path(STAGE_DIRECTORY).join(STAGE_NAME);
	let stage_inode = identity(&stage_path);
	let incumbent = fixture.destination.path("TARGET");
	let target = fixture.destination.path(TARGET_NAME);
	write_new(&incumbent, INCUMBENT);
	let incumbent_inode = identity(&incumbent);

	match target.symlink_metadata() {
		Ok(_) => {
			assert_eq!(identity(&target), incumbent_inode);
			assert!(matches!(
				stage
					.publish_with_barriers(authorization, |_| panic!("no barriers without rename")),
				Err(PublishError::Conflict { policy_error: None })
			));
			assert_eq!(identity(&target), incumbent_inode);
			assert_eq!(identity(&stage_path), stage_inode);
			assert_eq!(fs::read(stage_path).unwrap(), PAYLOAD);
		}
		Err(error) if error.kind() == io::ErrorKind::NotFound => {
			stage
				.publish_no_clobber(authorization)
				.expect("a case-sensitive APFS volume has a separate absent target");
			assert_eq!(identity(&target), stage_inode);
			assert_absent(&stage_path);
		}
		Err(error) => panic!("could not determine fixture filename equivalence: {error}"),
	}

	assert_eq!(identity(&incumbent), incumbent_inode);
	assert_eq!(fs::read(incumbent).unwrap(), INCUMBENT);
}

#[test]
#[ignore = "requires managed APFS fixtures without visible extended attributes"]
fn rejects_required_metadata_change_after_the_stage_is_ready() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = root.open_stage_directory(name(STAGE_DIRECTORY)).unwrap();
	let stage = fixture.standard_stage(&directory);
	let authorization = fixture.authorize(stage.binding());
	let stage_path = fixture.destination.path(STAGE_DIRECTORY).join(STAGE_NAME);
	let stage_inode = identity(&stage_path);
	fs::set_permissions(&stage_path, fs::Permissions::from_mode(0o640))
		.expect("change fixture metadata after sealing");

	assert!(matches!(
		stage.publish_with_barriers(authorization, |_| panic!("no barriers without rename")),
		Err(PublishError::Rejected {
			reason: PublishRejection::Stage(_),
			..
		})
	));
	assert_absent(&fixture.destination.path(TARGET_NAME));
	assert_eq!(identity(&stage_path), stage_inode);
	assert_eq!(fs::read(stage_path).unwrap(), PAYLOAD);
}

fn assert_absent(path: &Path) {
	assert!(
		matches!(path.symlink_metadata(), Err(error) if error.kind() == io::ErrorKind::NotFound)
	);
}
