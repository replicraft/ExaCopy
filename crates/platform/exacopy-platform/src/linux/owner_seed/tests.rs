use std::fs::{self, OpenOptions, Permissions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink};

use super::{
	HeldOwnerSeed, KEY_NAME, OWNER_SEED_BYTES, OwnerSeedError, initialize_owner_seed, kernel_random,
};
use crate::scratch::Scratch;
use exacopy_endpoint::UnixComponent;

const PROFILE: &str = "profile";
const SEED_MODE: u32 = 0o600;
const DIRECTORY_MODE: u32 = 0o700;

fn selected() -> UnixComponent<'static> {
	UnixComponent::new(PROFILE.as_bytes()).unwrap()
}

#[test]
fn creates_and_reopens_exact_bytes_without_replacing_an_incumbent() {
	let scratch = Scratch::new();
	let parent = scratch.path(".");
	let seed_path = scratch.path(PROFILE).join(KEY_NAME.to_str().unwrap());
	let mut generated = [0; OWNER_SEED_BYTES];

	initialize_owner_seed(parent.as_os_str(), selected(), &mut generated).unwrap();
	let before = fs::metadata(&seed_path).unwrap();
	assert_eq!(fs::read(&seed_path).unwrap(), generated);
	assert_eq!(before.mode() & 0o777, SEED_MODE);
	assert_eq!(
		fs::metadata(scratch.path(PROFILE)).unwrap().mode() & 0o777,
		DIRECTORY_MODE
	);

	let mut seed = [0; OWNER_SEED_BYTES];
	let mut eof_probe = [0xff; 1];
	let handle =
		HeldOwnerSeed::open(parent.as_os_str(), selected(), &mut seed, &mut eof_probe).unwrap();
	assert_eq!(seed, generated);
	assert_eq!(eof_probe, [0xff]);
	assert_eq!(handle.identity().inode(), before.ino());
	assert_eq!(handle.identity().device(), before.dev());

	let mut attempted = [0; OWNER_SEED_BYTES];
	assert!(matches!(
		initialize_owner_seed(parent.as_os_str(), selected(), &mut attempted),
		Err(OwnerSeedError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
	));
	assert_eq!(fs::metadata(&seed_path).unwrap().ino(), before.ino());
	assert_eq!(fs::read(&seed_path).unwrap(), generated);
}

#[test]
fn held_seed_identity_survives_an_unlinked_name() {
	let scratch = Scratch::new();
	let parent = scratch.path(".");
	let seed_path = scratch.path(PROFILE).join(KEY_NAME.to_str().unwrap());
	let mut data = [0; OWNER_SEED_BYTES];
	initialize_owner_seed(parent.as_os_str(), selected(), &mut data).unwrap();

	let mut seed = [0; OWNER_SEED_BYTES];
	let held = HeldOwnerSeed::open(parent.as_os_str(), selected(), &mut seed, &mut [0]).unwrap();
	let identity = held.identity();
	fs::remove_file(&seed_path).unwrap();
	OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(SEED_MODE)
		.open(&seed_path)
		.unwrap()
		.write_all(&[7; OWNER_SEED_BYTES])
		.unwrap();

	assert_eq!(held._file.metadata().unwrap().nlink(), 0);
	assert_eq!(held._file.metadata().unwrap().ino(), identity.inode());
	assert_ne!(fs::metadata(&seed_path).unwrap().ino(), identity.inode());
}

#[test]
fn refuses_unexpected_seed_metadata_without_consuming_file_bytes() {
	let scratch = Scratch::new();
	let parent = scratch.path(".");
	let seed_path = scratch.path(PROFILE).join(KEY_NAME.to_str().unwrap());
	let mut generated = [0; OWNER_SEED_BYTES];
	initialize_owner_seed(parent.as_os_str(), selected(), &mut generated).unwrap();

	let mut reader = [0xff; OWNER_SEED_BYTES];
	let mut probe = [0xff; 1];
	fs::set_permissions(&seed_path, Permissions::from_mode(0o640)).unwrap();
	assert!(matches!(
		HeldOwnerSeed::open(parent.as_os_str(), selected(), &mut reader, &mut probe),
		Err(OwnerSeedError::UnsafeSeed)
	));
	fs::set_permissions(&seed_path, Permissions::from_mode(SEED_MODE)).unwrap();
	let linked = scratch.path("alias");
	fs::hard_link(&seed_path, &linked).unwrap();
	assert!(matches!(
		HeldOwnerSeed::open(parent.as_os_str(), selected(), &mut reader, &mut probe),
		Err(OwnerSeedError::UnsafeSeed)
	));
	fs::remove_file(&seed_path).unwrap();
	symlink(&linked, &seed_path).unwrap();
	assert!(matches!(
		HeldOwnerSeed::open(parent.as_os_str(), selected(), &mut reader, &mut probe),
		Err(OwnerSeedError::UnsafeSeed)
	));
	assert_eq!(reader, [0xff; OWNER_SEED_BYTES]);
	assert_eq!(probe, [0xff]);
	assert_eq!(fs::read(linked).unwrap(), generated);
}

#[test]
fn entropy_refuses_an_oversized_request_before_writing() {
	let mut buffer = [0xff; super::MAX_KERNEL_RANDOM_BYTES + 1];
	assert!(matches!(
		kernel_random(&mut buffer),
		Err(OwnerSeedError::Random)
	));
	assert_eq!(buffer, [0xff; super::MAX_KERNEL_RANDOM_BYTES + 1]);
}
