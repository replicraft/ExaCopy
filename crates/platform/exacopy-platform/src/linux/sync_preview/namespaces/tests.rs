use rustix::io::{FdFlags, fcntl_getfd};

use super::*;

#[path = "../../../../tests/unit/preview_namespaces.rs"]
mod preview_namespaces;

#[test]
fn accepts_only_fixed_kind_and_bounded_canonical_inode_text() {
	assert_eq!(
		parse_link(NamespaceKind::Mount, b"mnt:[4026531841]"),
		NonZeroU64::new(4026531841)
	);
	assert_eq!(
		parse_link(NamespaceKind::User, b"user:[18446744073709551615]"),
		NonZeroU64::new(u64::MAX)
	);
	for wrong in [
		b"user:[23]".as_slice(),
		b"mnt:[]",
		b"mnt:[0]",
		b"mnt:[023]",
		b"mnt:[+23]",
		b"mnt:[18446744073709551616]",
		b"mnt:[184467440737095516150]",
		b"mnt:[23]\0",
		b"mnt:[23",
		b"mnt:[23]/extra",
	] {
		assert!(
			parse_link(NamespaceKind::Mount, wrong).is_none(),
			"{wrong:?}"
		);
	}
}

#[test]
fn current_namespace_pins_are_read_only_and_match_fresh_observations() {
	let held = HeldNamespaces::current().expect("inspect namespaces through trusted procfs");
	let facts = held.facts();
	assert_ne!(facts.mount, facts.user);
	for pin in [&held.mount, &held.user] {
		let flags = fs::fcntl_getfl(&pin.fd).expect("inspect namespace handle flags");
		assert_eq!(flags & OFlags::ACCMODE, OFlags::RDONLY);
		assert!(fcntl_getfd(&pin.fd).unwrap().contains(FdFlags::CLOEXEC));
	}
	held.recheck_current()
		.expect("confirm current namespace scope");
	assert_eq!(held.facts(), facts);
	let mut different_device = fs::fstat(&held.mount.fd).expect("inspect mount pin");
	different_device.st_dev ^= 1;
	for changed in [
		NamespaceFacts {
			mount: FileIdentity::from_stat(&different_device),
			..facts
		},
		NamespaceFacts {
			mount: facts.user,
			..facts
		},
		NamespaceFacts {
			user: facts.mount,
			..facts
		},
	] {
		assert!(matches!(
			compare_facts(facts, changed),
			Err(SyncPreviewError::Changed)
		));
	}
}

#[test]
fn procfs_directory_cannot_be_used_as_a_namespace_object() {
	let directory = namespace_directory().expect("hold the caller's namespace directory");
	assert!(matches!(
		namespace_identity(&directory),
		Err(SyncPreviewError::UnsupportedNamespace)
	));
}

#[test]
fn distinguishes_missing_support_from_native_read_failure() {
	assert!(matches!(
		namespace_error(Errno::NOSYS),
		SyncPreviewError::UnsupportedNamespace
	));
	assert!(matches!(
		namespace_error(Errno::ACCESS),
		SyncPreviewError::System(error) if Errno::from_io_error(&error) == Some(Errno::ACCESS)
	));
}
