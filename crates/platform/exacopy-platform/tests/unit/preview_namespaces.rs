use std::fs as std_fs;
use std::os::unix::fs::symlink;

use super::super::*;
use crate::scratch::Scratch;

#[test]
fn recheck_refuses_stale_identity_for_either_live_namespace_pin() {
	let mut held = HeldNamespaces::current().expect("hold current procfs namespace pins");
	let fresh = HeldNamespaces::current().expect("independently hold current namespace pins");
	let facts = fresh.facts();
	assert_ne!(
		facts.mount, facts.user,
		"the two namespace identities are distinct"
	);
	assert_eq!(
		held.facts(),
		facts,
		"both pins initially match a fresh observation"
	);

	held.mount.identity = facts.user;
	assert!(matches!(
		held.recheck_current(),
		Err(SyncPreviewError::Changed)
	));

	held.mount.identity = facts.mount;
	held.user.identity = facts.mount;
	assert!(matches!(
		held.recheck_current(),
		Err(SyncPreviewError::Changed)
	));

	held.user.identity = facts.user;
	held.recheck_current()
		.expect("the held descriptors still match the actual namespaces");
}

#[test]
fn namespace_link_observation_refuses_missing_wrong_kind_and_wrong_label() {
	let fixture = Scratch::new();
	let mount = fixture.path("mnt");
	let user = fixture.path("user");
	let directory: OwnedFd = fixture.open().into();
	let payload = b"an ordinary file";

	std_fs::write(&mount, payload).expect("create an owned non-symlink control");
	assert!(matches!(
		NamespaceKind::Mount.link_inode(&directory),
		Err(SyncPreviewError::UnsupportedNamespace)
	));
	assert!(matches!(
		NamespaceKind::User.link_inode(&directory),
		Err(SyncPreviewError::UnsupportedNamespace)
	));
	// The independently readable target is well formed for the other namespace kind.
	symlink("mnt:[23]", &user).expect("create a mislabeled link in the owned fixture");
	assert!(matches!(
		NamespaceKind::User.link_inode(&directory),
		Err(SyncPreviewError::UnsupportedNamespace)
	));
	assert_eq!(
		std_fs::read(&mount).expect("read the owned ordinary file"),
		payload
	);
	assert_eq!(
		std_fs::read_link(&user).expect("read the original link target"),
		std::path::Path::new("mnt:[23]")
	);
}
