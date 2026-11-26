use std::error::Error as _;
use std::fs::{self, File};
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::process::Command;

use exacopy_endpoint::ReadView;
use rustix::fs::{FlockOperation, flock};

use super::{Fixture, grant, name, source_name};
use crate::macos::{BasicMetadataError, ManagedReadError, ManagedReadRoot};

#[test]
fn positioned_view_binds_ranges_and_reports_a_displaced_name() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	fixture.make_file("source", b"native APFS");
	let path = fixture.0.join("source");
	let independent = fs::metadata(&path).expect("inspect synthetic file");
	let root = fixture.bind().expect("admit isolated APFS fixture");
	let requested = name(b"source");
	let selected = source_name(b"source");
	let file = root.open_regular(&selected).expect("open managed source");
	let identities = file.observe_identities().expect("observe held identities");
	// Check the unchanged signed-identity projection against the legacy
	// native stat projection on this independently opened fixture.
	let descriptor = File::open(&path).expect("open identity oracle");
	let stat = rustix::fs::fstat(&descriptor).expect("observe stat identity");
	let fsid = super::super::PhysicalFsid::held(descriptor.as_fd())
		.expect("observe real FSID")
		.expect("physical identity available");
	let legacy = super::super::ManagedObjectIdentity::from_stat(&stat, fsid)
		.expect("project legacy signed identity fields");
	assert_eq!(identities.file, legacy);
	assert_eq!(identities.file.inode().get(), independent.ino());
	assert_eq!(
		identities.parent.inode().get(),
		fs::metadata(&fixture.0)
			.expect("inspect fixture root")
			.ino()
	);
	assert_eq!(file.component(), requested);
	let changed = file.change_time().expect("observe source change time");
	assert_eq!(changed.seconds(), independent.ctime());
	assert_eq!(i64::from(changed.nanoseconds()), independent.ctime_nsec());
	assert_eq!(ReadView::length(&file), independent.len());

	let mut tail = [0; 4];
	ReadView::read_exact_at(&file, 7, &mut tail).expect("read captured tail");
	assert_eq!(&tail, b"APFS");
	ReadView::recheck_observation(&file).expect("revalidate intact source and EOF");

	// A synthetic external actor displaces the observed name between calls.
	let retained = fixture.0.join("retained");
	fs::rename(&path, &retained).expect("retain observed source under a different name");
	let error = ReadView::recheck_observation(&file).expect_err("a missing binding must refuse");
	assert!(matches!(error, ManagedReadError::SourceChanged));
	assert!(error.to_string().contains("identity or metadata changed"));
	assert!(error.source().is_none());
	ReadView::read_exact_at(&file, 7, &mut tail).expect_err("displaced source cannot be read");
	assert_eq!(&tail, b"APFS", "the pre-read refusal preserves the buffer");
	assert_eq!(
		fs::read(retained).expect("read retained fixture independently"),
		b"native APFS"
	);
}

#[test]
fn strict_metadata_entry_points_refuse_a_visible_user_attribute() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	fixture.make_file("source", b"source");
	assert!(
		Command::new("/usr/bin/xattr")
			.args(["-w", "org.exacopy.test", "synthetic"])
			.arg(fixture.0.join("source"))
			.status()
			.expect("write visible fixture attribute")
			.success()
	);
	let root = fixture.bind().expect("admit isolated APFS fixture");
	let selected = source_name(b"source");
	let file = root
		.open_regular(&selected)
		.expect("observe data stream under the managed read contract");

	for result in [
		file.check_basic_metadata(),
		file.check_pre_read_basic_metadata(),
	] {
		let error = result.expect_err("strict copy must refuse visible extended attributes");
		assert!(matches!(
			error,
			ManagedReadError::BasicMetadata(BasicMetadataError::ExtendedAttributes)
		));
		assert!(error.to_string().contains("visible extended attributes"));
		assert!(
			error
				.source()
				.is_some_and(|cause| cause.downcast_ref::<BasicMetadataError>().is_some()),
			"the strict metadata cause remains available"
		);
	}
	let mut bytes = [0; 6];
	file.read_exact_at(0, &mut bytes)
		.expect("read stream under the managed comparison contract");
	assert_eq!(&bytes, b"source");
}

#[test]
fn refuses_a_nondirectory_import_and_preserves_the_native_child_open_error() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	fixture.make_file("source", b"source");
	let path = fixture.0.join("source");
	let regular = File::open(&path).expect("open file for a wrong-kind root import");
	assert!(matches!(
		ManagedReadRoot::from_provisioned_directory(regular, grant()),
		Err(ManagedReadError::UnsupportedNamespace)
	));
	let root = fixture.bind().expect("admit isolated APFS fixture");
	assert!(
		Command::new("/bin/chmod")
			.args(["+a", "everyone deny read"])
			.arg(&path)
			.status()
			.expect("deny direct reads on synthetic file")
			.success()
	);
	let native_error = File::open(&path).expect_err("the native ACL must deny reads");
	assert_eq!(native_error.raw_os_error(), Some(libc::EACCES));
	let error = root
		.open_regular(&source_name(b"source"))
		.expect_err("managed read must preserve an OS denial");
	assert!(matches!(error, ManagedReadError::System(_)));
	let source = error.source().expect("preserve the native error");
	let os_error = source
		.downcast_ref::<std::io::Error>()
		.expect("retain the I/O cause");
	assert_eq!(os_error.raw_os_error(), native_error.raw_os_error());
}

#[test]
fn dropping_a_reader_releases_its_lease_with_a_root_descriptor_alias() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	let writer = fixture.open();
	let root = fixture.bind().expect("hold the shared root lease");
	// The companion lease has an independent descriptor. An alias of the
	// observed root retains neither ownership nor the advisory lock.
	let alias = root
		.directory
		.as_fd()
		.try_clone_to_owned()
		.expect("duplicate root fd");
	drop(root);
	flock(&writer, FlockOperation::NonBlockingLockExclusive).expect("reader released its lease");
	drop(alias);
}

#[test]
fn a_large_request_crosses_native_chunks_without_changing_the_read_contract() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	let boundary = apfs_mounted::source::MAX_READ_BYTES;
	let mut expected = vec![0x27; boundary + 17];
	expected[boundary - 1..].fill(0x84);
	fixture.make_file("source", &expected);
	let root = fixture.bind().expect("admit isolated APFS fixture");
	let requested = source_name(b"source");
	let file = root.open_regular(&requested).expect("open pinned source");
	let mut observed = vec![0; expected.len()];
	file.read_exact_at(0, &mut observed)
		.expect("cross the native request boundary");
	assert_eq!(observed, expected);
	file.revalidate().expect("observe exact EOF");
}
