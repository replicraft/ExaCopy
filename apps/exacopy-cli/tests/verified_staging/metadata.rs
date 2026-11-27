use std::fs::{self, File, Permissions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use exacopy_cli::assembly::linux::{StageFailure, stage_verified};
use exacopy_model::CopyPhase;
use exacopy_platform::linux::StageError;
use rustix::fs::{self as unix, XattrFlags};

use super::{
	Fixture, PERMISSION_BITS, PRIVATE_DIR, PRIVATE_MODE, assert_missing, request, stage_directory,
};

#[test]
fn inherited_stage_acl_refuses_required_metadata_after_readback() {
	const SOURCE_BYTES: &[u8] = b"retain verified stage";
	const SOURCE_MODE: u32 = 0o640;
	const NEW_TARGET: &[u8] = b"new-target";
	let fixture = Fixture::new(SOURCE_BYTES);
	let incumbent = fixture.incumbent();
	let source_path = fixture.source_path();
	fs::set_permissions(&source_path, Permissions::from_mode(SOURCE_MODE))
		.expect("set the ordinary permissions required from the source");
	let original_source = fs::symlink_metadata(&source_path).expect("inspect the source fixture");
	let source = fixture.open_source();
	let destination = fixture.open_destination();
	let directory = stage_directory(&destination);
	let directory_file = File::open(fixture.target_path(PRIVATE_DIR))
		.expect("open the disposable private stage directory");
	let acl = masked_named_user_acl(if original_source.uid() == 1 { 2 } else { 1 });
	unix::fsetxattr(
		&directory_file,
		c"system.posix_acl_default",
		&acl,
		XattrFlags::CREATE,
	)
	.expect("fixture filesystem must support POSIX default ACLs");

	let error = stage_verified(&source, &directory, request(NEW_TARGET), &mut [0; 4])
		.expect_err("reject the inherited stage ACL before metadata readiness");
	assert_eq!(error.phase(), CopyPhase::Verified, "{error}");
	assert!(
		matches!(
			error.failure(),
			StageFailure::Stage(StageError::UnexpectedExtendedAttributes)
		),
		"{error}"
	);

	let private = fixture.stage_path();
	let mut retained = File::open(&private).expect("open retained private stage");
	let held = retained
		.metadata()
		.expect("inspect held retained private stage");
	let assert_named_stage = || {
		let named = fs::symlink_metadata(&private).expect("inspect the named retained stage");
		assert_eq!((named.dev(), named.ino()), (held.dev(), held.ino()));
	};
	assert_named_stage();
	let mut access_acl = vec![0; acl.len()];
	let length = unix::fgetxattr(&retained, c"system.posix_acl_access", &mut access_acl[..])
		.expect("independently read the inherited access ACL");
	assert_eq!(length, acl.len());
	assert_eq!(access_acl, acl);
	assert_eq!(held.mode() & PERMISSION_BITS, PRIVATE_MODE);
	let mut bytes = [0; SOURCE_BYTES.len()];
	retained
		.read_exact(&mut bytes)
		.expect("read retained stage through its held descriptor");
	assert_eq!(&bytes, SOURCE_BYTES);
	let mut eof = [0; 1];
	assert_eq!(
		retained.read(&mut eof).expect("observe retained stage EOF"),
		0
	);
	assert_named_stage();
	assert_missing(fixture.target_path(NEW_TARGET));
	fixture.check_preserved(SOURCE_BYTES, &incumbent);
	let current_source = fs::symlink_metadata(source_path).expect("inspect the preserved source");
	assert_eq!(
		(
			current_source.dev(),
			current_source.ino(),
			current_source.mode()
		),
		(
			original_source.dev(),
			original_source.ino(),
			original_source.mode()
		)
	);
}

fn masked_named_user_acl(user: u32) -> Vec<u8> {
	// Linux POSIX ACL xattr version 2. The zero mask keeps the inherited
	// access ACL compatible with a stage created with mode 0600.
	const ACL_VERSION: u32 = 2;
	const USER_OBJECT: u16 = 0x01;
	const NAMED_USER: u16 = 0x02;
	const GROUP_OBJECT: u16 = 0x04;
	const MASK: u16 = 0x10;
	const OTHER: u16 = 0x20;
	const OWNER_ACCESS: u16 = 0o6;
	const READ: u16 = 0o4;
	const NO_ID: u32 = u32::MAX;
	let mut value = ACL_VERSION.to_le_bytes().to_vec();
	for (tag, permission, id) in [
		(USER_OBJECT, OWNER_ACCESS, NO_ID),
		(NAMED_USER, READ, user),
		(GROUP_OBJECT, 0, NO_ID),
		(MASK, 0, NO_ID),
		(OTHER, 0, NO_ID),
	] {
		value.extend_from_slice(&tag.to_le_bytes());
		value.extend_from_slice(&permission.to_le_bytes());
		value.extend_from_slice(&id.to_le_bytes());
	}
	value
}
