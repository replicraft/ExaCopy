use std::fs::{self, File};
use std::io::Read;
use std::os::fd::AsFd;
use std::path::PathBuf;

use super::{HeldSlot, ObserveError, SELECTED, UnixComponent};
use crate::linux::FileIdentity;
use crate::linux::handle::mount_id;

const SOURCE_BYTES: &[u8; 6] = b"source";

#[test]
#[ignore = "requires the runner's owned bind mount in a private user and mount namespace"]
fn refuses_same_device_bind_mount_at_the_selected_name() {
	let fixture = std::env::var_os("EXACOPY_PROTECTED_SLOT_MOUNT_FIXTURE")
		.map(PathBuf::from)
		.expect("run through the protected-slot native qualification runner");
	let parent_path = fixture.join("parent");
	let parent = File::open(&parent_path).expect("open held synthetic parent");
	let mut direct = File::open(parent_path.join(SELECTED)).expect("control opens synthetic mount");
	let source = File::open(fixture.join("source")).expect("open original synthetic mount source");
	let observed =
		FileIdentity::from_stat(&rustix::fs::fstat(&direct).expect("identify mounted file"));
	let original =
		FileIdentity::from_stat(&rustix::fs::fstat(&source).expect("identify mount source"));
	let parent_identity =
		FileIdentity::from_stat(&rustix::fs::fstat(&parent).expect("identify held parent"));
	assert_eq!(observed, original);
	assert_eq!(observed.device(), parent_identity.device());
	assert_ne!(
		mount_id(&direct).expect("mounted file ID"),
		mount_id(&parent).expect("held parent mount ID")
	);
	let mut buffer = [0; SOURCE_BYTES.len()];
	direct
		.read_exact(&mut buffer)
		.expect("read synthetic source control");
	assert_eq!(&buffer, SOURCE_BYTES);

	let slot = HeldSlot::from_authorized_parent(
		parent.as_fd(),
		UnixComponent::new(SELECTED.as_bytes()).expect("valid synthetic component"),
	)
	.expect("hold synthetic parent");
	assert!(matches!(slot.observe(), Err(ObserveError::CrossedMount)));
	assert_eq!(
		fs::read(fixture.join("source")).expect("source bytes"),
		SOURCE_BYTES
	);
}
