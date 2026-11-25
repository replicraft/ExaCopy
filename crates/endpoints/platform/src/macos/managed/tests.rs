use std::fs::{self, DirBuilder, File};
use std::io::{self, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_endpoint::UnixComponent;
use rustix::fs::{FlockOperation, flock};
use rustix::io::Errno;

use super::acl;
use crate::macos::{ManagedReadError, ManagedReadGrant, ManagedReadRoot};

fn grant() -> ManagedReadGrant {
	ManagedReadGrant::trusted_owner_authorizes_provisioned_root()
}

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		static NEXT: AtomicUsize = AtomicUsize::new(0);
		for _ in 0..64 {
			let id = NEXT.fetch_add(1, Ordering::Relaxed);
			let path = Path::new("/private/tmp").join(format!(
				"exacopy-macos-managed-read-{}-{id}",
				std::process::id()
			));
			match DirBuilder::new().mode(0o700).create(&path) {
				Ok(()) => return Self(path),
				Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
				Err(error) => panic!("cannot create synthetic private directory: {error}"),
			}
		}
		panic!("synthetic private directory creation attempts exhausted")
	}

	fn bind(&self) -> Result<ManagedReadRoot, ManagedReadError> {
		ManagedReadRoot::open_provisioned_path(&self.0, grant())
	}

	fn open(&self) -> File {
		File::open(&self.0).expect("open synthetic directory")
	}

	fn install_empty_acl(&self) {
		acl::set_fixture_empty_acl(self.open().as_fd()).expect("set explicit zero-entry ACL");
	}

	fn make_file(&self, name: &str, bytes: &[u8]) {
		File::options()
			.create_new(true)
			.write(true)
			.mode(0o600)
			.open(self.0.join(name))
			.expect("create synthetic regular file")
			.write_all(bytes)
			.expect("write synthetic file");
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).expect("clean up synthetic directory");
	}
}

fn name(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).expect("valid one-component fixture name")
}

#[test]
fn reads_exact_bounded_ranges_from_positively_admitted_apfs_fixture() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	fixture.make_file("data", b"prefix suffix");
	fixture.make_file("empty", b"");
	let root = fixture.bind().expect("admit isolated local APFS fixture");
	let file = root
		.open_regular(name(b"data"))
		.expect("open private regular file");
	let mut bytes = [0; 13];
	file.read_exact_at(0, &mut bytes)
		.expect("read exact whole file");
	assert_eq!(&bytes, b"prefix suffix");
	assert_eq!(file.length(), 13);
	assert!(!file.is_empty());
	file.revalidate()
		.expect("revalidate held identity and logical EOF");
	file.read_exact_at(7, &mut bytes[..6])
		.expect("read exact nonzero offset");
	assert_eq!(&bytes[..6], b"suffix");
	for offset in [8, 14, u64::MAX] {
		let mut buffer = [0xab; 6];
		assert!(matches!(
			file.read_exact_at(offset, &mut buffer),
			Err(ManagedReadError::RangeOutsideFile)
		));
		assert_eq!(buffer, [0xab; 6]);
	}
	root.open_regular(name(b"empty"))
		.expect("open empty file")
		.read_exact_at(0, &mut [])
		.expect("read zero-byte file");
	assert_eq!(
		fs::read(fixture.0.join("data")).expect("read independent fixture"),
		b"prefix suffix"
	);
}

#[test]
fn refuses_missing_and_nonempty_acl_evidence() {
	let fixture = Fixture::new();
	assert!(matches!(
		fixture.bind(),
		Err(ManagedReadError::UnsupportedNamespace)
	));
	assert!(
		Command::new("/bin/chmod")
			.args(["+a", "everyone allow list,search"])
			.arg(&fixture.0)
			.status()
			.expect("install synthetic nonempty ACL")
			.success()
	);
	assert!(
		!acl::has_explicit_empty_acl(fixture.open().as_fd()).expect("inspect nonempty fixture ACL")
	);
	assert!(matches!(
		fixture.bind(),
		Err(ManagedReadError::UnsupportedNamespace)
	));
	fixture.install_empty_acl();
	assert!(fixture.bind().is_ok(), "explicit zero-entry ACL admitted");
	fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o770))
		.expect("widen synthetic directory mode");
	assert!(matches!(
		fixture.bind(),
		Err(ManagedReadError::UnsupportedNamespace)
	));
}

#[test]
fn refuses_links_nonregular_entries_and_inexact_names() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	fixture.make_file("data", b"bytes");
	symlink("data", fixture.0.join("link")).expect("create synthetic symlink");
	fs::hard_link(fixture.0.join("data"), fixture.0.join("hardlink"))
		.expect("link synthetic regular file");
	fs::create_dir(fixture.0.join("directory")).expect("create synthetic child directory");
	assert!(
		Command::new("/usr/bin/mkfifo")
			.arg(fixture.0.join("fifo"))
			.status()
			.expect("create synthetic FIFO")
			.success()
	);
	let root = fixture.bind().expect("admit isolated local APFS fixture");
	for child in [
		b"link".as_slice(),
		b"hardlink",
		b"data",
		b"directory",
		b"fifo",
	] {
		assert!(
			matches!(
				root.open_regular(name(child)),
				Err(ManagedReadError::UnsupportedChild)
			),
			"{child:?}"
		);
	}
	assert!(matches!(
		root.open_regular(name(b"missing")),
		Err(ManagedReadError::Missing)
	));
	for rejected in [b"../data".as_slice(), b".", b"..", b"/data", b"data\0"] {
		assert!(UnixComponent::new(rejected).is_err());
	}
}

#[test]
fn revalidates_root_privacy_and_source_metadata_before_read() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	fixture.make_file("private", b"source");
	let root = fixture.bind().expect("admit isolated local APFS fixture");
	let file = root
		.open_regular(name(b"private"))
		.expect("open private regular file");
	fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o750))
		.expect("change synthetic root mode");
	let mut bytes = [0; 6];
	assert!(matches!(
		file.read_exact_at(0, &mut bytes),
		Err(ManagedReadError::UnsupportedNamespace)
	));
	fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700))
		.expect("restore synthetic root mode");
	fs::write(fixture.0.join("private"), b"changed extent")
		.expect("mutate synthetic source independently");
	assert!(matches!(
		file.read_exact_at(0, &mut bytes),
		Err(ManagedReadError::SourceChanged)
	));
	assert_eq!(bytes, [0; 6]);
}

#[test]
fn held_parent_pins_lookup_after_its_path_is_replaced() {
	let fixture = Fixture::new();
	let original = fixture.0.join("original");
	let moved = fixture.0.join("moved");
	DirBuilder::new()
		.mode(0o700)
		.create(&original)
		.expect("create synthetic managed directory");
	let directory = File::open(&original).expect("hold original directory");
	acl::set_fixture_empty_acl(directory.as_fd()).expect("set explicit zero-entry ACL");
	fixture.make_file("child", b"original");
	fs::rename(fixture.0.join("child"), original.join("child"))
		.expect("populate managed directory");
	let root = ManagedReadRoot::from_provisioned_directory(directory, grant())
		.expect("bind original directory");
	fs::rename(&original, moved).expect("move original directory");
	DirBuilder::new()
		.mode(0o700)
		.create(&original)
		.expect("create replacement directory");
	symlink("missing", original.join("child")).expect("install replacement symlink");
	let file = root
		.open_regular(name(b"child"))
		.expect("open beneath held original directory");
	let mut bytes = [0; 8];
	file.read_exact_at(0, &mut bytes)
		.expect("read original child");
	assert_eq!(&bytes, b"original");
}

#[test]
fn revalidation_rejects_selected_child_rebind() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	fixture.make_file("data", b"original");
	let root = fixture.bind().expect("admit isolated local APFS fixture");
	let file = root
		.open_regular(name(b"data"))
		.expect("open private regular file");
	fs::rename(fixture.0.join("data"), fixture.0.join("old-data"))
		.expect("move synthetic original aside");
	fixture.make_file("data", b"new file");
	let mut bytes = [0; 8];
	assert!(matches!(
		file.read_exact_at(0, &mut bytes),
		Err(ManagedReadError::SourceChanged)
	));
	assert_eq!(bytes, [0; 8]);
}

#[test]
fn outside_principal_mutation_grant_revokes_managed_admission() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	fixture.make_file("source", b"source");
	let root = fixture
		.bind()
		.expect("admit private directory before granting rights");
	let file = root
		.open_regular(name(b"source"))
		.expect("hold synthetic source");

	assert!(
		Command::new("/bin/chmod")
			.args([
				"+a",
				"user:_www allow search,add_file,delete_child,writeattr,writesecurity"
			])
			.arg(&fixture.0)
			.status()
			.expect("install mutation grant to outside system principal")
			.success()
	);
	let listing = Command::new("/bin/ls")
		.arg("-lde")
		.arg(&fixture.0)
		.output()
		.expect("read synthetic directory ACL");
	assert!(listing.status.success());
	let listing = String::from_utf8(listing.stdout).expect("UTF-8 synthetic ACL listing");
	let grant = listing.lines().nth(1).expect("native ACL entry");
	let account_id = Command::new("/usr/bin/id")
		.args(["-u", "_www"])
		.output()
		.expect("resolve outside UID");
	assert!(account_id.status.success());
	let account_id: u32 = std::str::from_utf8(&account_id.stdout)
		.expect("outside UID is text")
		.trim()
		.parse()
		.expect("outside UID is numeric");
	assert_ne!(account_id, rustix::process::geteuid().as_raw());
	let account_uuid = Command::new("/usr/bin/dsmemberutil")
		.args(["getuuid", "-U", "_www"])
		.output()
		.expect("resolve outside principal UUID");
	assert!(account_uuid.status.success());
	let account_uuid = std::str::from_utf8(&account_uuid.stdout)
		.expect("outside principal UUID is text")
		.trim();
	assert!(!account_uuid.is_empty());
	assert!(grant.contains("user:_www") || grant.contains(account_uuid));
	for right in [
		"allow",
		"search",
		"add_file",
		"delete_child",
		"writeattr",
		"writesecurity",
	] {
		assert!(
			grant.contains(right),
			"expected {right} in native grant: {grant}"
		);
	}
	println!("{}", grant.trim());
	assert!(matches!(
		fixture.bind(),
		Err(ManagedReadError::UnsupportedNamespace)
	));
	assert!(matches!(
		root.open_regular(name(b"source")),
		Err(ManagedReadError::UnsupportedNamespace)
	));
	let mut bytes = [0xab; 6];
	assert!(matches!(
		file.read_exact_at(0, &mut bytes),
		Err(ManagedReadError::UnsupportedNamespace)
	));
	assert_eq!(bytes, [0xab; 6], "read must stop before touching file data");
	assert_eq!(
		fs::read(fixture.0.join("source")).expect("read independent fixture"),
		b"source"
	);
}

#[test]
fn shared_root_leases_allow_parallel_readers_and_exclude_cooperating_writers() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	fixture.make_file("file", b"left-right");
	let writer = fixture.open();
	flock(&writer, FlockOperation::NonBlockingLockExclusive).expect("lock fixture as writer");
	assert!(matches!(
		fixture.bind(),
		Err(ManagedReadError::DirectoryBusy)
	));
	flock(&writer, FlockOperation::Unlock).expect("release writer lease");
	let first = fixture
		.bind()
		.expect("hold first independent shared root lease");
	let second = fixture
		.bind()
		.expect("hold second independent shared root lease");
	assert_eq!(
		flock(&writer, FlockOperation::NonBlockingLockExclusive),
		Err(Errno::AGAIN)
	);
	let read = first.open_regular(name(b"file")).expect("open held source");
	std::thread::scope(|scope| {
		let left = scope.spawn(|| {
			let mut bytes = [0; 4];
			read.read_exact_at(0, &mut bytes).expect("read left");
			bytes
		});
		let right = scope.spawn(|| {
			let mut bytes = [0; 5];
			read.read_exact_at(5, &mut bytes).expect("read right");
			read.revalidate()
				.expect("revalidate in a separate calling thread");
			bytes
		});
		assert_eq!(left.join().expect("join left"), *b"left");
		assert_eq!(right.join().expect("join right"), *b"right");
	});
	second
		.open_regular(name(b"file"))
		.expect("open under second shared lease");
	drop(first);
	assert_eq!(
		flock(&writer, FlockOperation::NonBlockingLockExclusive),
		Err(Errno::AGAIN)
	);
	drop(second);
	flock(&writer, FlockOperation::NonBlockingLockExclusive).expect("both reader leases released");
}

#[test]
fn path_admission_refuses_final_and_intermediate_symlinks() {
	let fixture = Fixture::new();
	let real = fixture.0.join("directory");
	fs::create_dir(&real).expect("create synthetic path root");
	let leaf = real.join("leaf");
	DirBuilder::new()
		.mode(0o700)
		.create(&leaf)
		.expect("create private root");
	let directory = File::open(&leaf).expect("hold independently provisioned fixture");
	acl::set_fixture_empty_acl(directory.as_fd()).expect("set explicit empty ACL");
	assert!(ManagedReadRoot::open_provisioned_path(&leaf, grant()).is_ok());
	symlink("directory/leaf", fixture.0.join("final-link")).expect("create final symlink");
	symlink("directory", fixture.0.join("intermediate-link")).expect("create intermediate symlink");
	for path in [
		fixture.0.join("final-link"),
		fixture.0.join("intermediate-link/leaf"),
	] {
		let result = ManagedReadRoot::open_provisioned_path(&path, grant());
		assert!(
			matches!(&result, Err(ManagedReadError::System(error)) if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR))),
			"descriptor walk should refuse symlinks, got {result:?}"
		);
	}
	for path in [
		PathBuf::from("relative"),
		fixture.0.join("directory/../directory/leaf"),
		fixture.0.join("directory/./leaf"),
		fixture.0.join("directory/leaf/"),
	] {
		assert!(matches!(
			ManagedReadRoot::open_provisioned_path(&path, grant()),
			Err(ManagedReadError::UnsupportedNamespace)
		));
	}
}

#[test]
fn logical_eof_revalidation_refuses_observed_appends() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	fixture.make_file("empty", b"");
	let root = fixture.bind().expect("admit valid managed root");
	let file = root
		.open_regular(name(b"empty"))
		.expect("open empty source");
	assert!(file.is_empty());
	file.revalidate().expect("observe EOF at offset zero");
	// Intentional same-principal cooperation violation to exercise detection.
	fs::write(
		fixture.0.join("empty"),
		b"appended by synthetic external author",
	)
	.expect("append fixture");
	assert!(matches!(
		file.revalidate(),
		Err(ManagedReadError::SourceChanged)
	));
}

#[test]
fn imported_descriptor_alias_cannot_unlock_the_private_reader_lease() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	let imported = fixture.open();
	let alias = imported
		.try_clone()
		.expect("retain imported descriptor alias");
	let writer = fixture.open();
	let root = ManagedReadRoot::from_provisioned_directory(imported, grant())
		.expect("bind an independently reopened directory");
	assert!(
		rustix::io::fcntl_getfd(&root.directory)
			.expect("read held descriptor flags")
			.contains(rustix::io::FdFlags::CLOEXEC)
	);
	flock(&alias, FlockOperation::Unlock).expect("unlock alias open file description");
	assert_eq!(
		flock(&writer, FlockOperation::NonBlockingLockExclusive),
		Err(Errno::AGAIN)
	);
	drop(root);
	flock(&writer, FlockOperation::NonBlockingLockExclusive).expect("private lease was released");
}

#[test]
fn dropping_a_reader_releases_its_lease_with_a_transient_descriptor_alias() {
	let fixture = Fixture::new();
	fixture.install_empty_acl();
	let writer = fixture.open();
	let root = fixture.bind().expect("hold the shared root lease");
	// A concurrent fork can retain the open description briefly before CLOEXEC.
	let alias = root.directory.try_clone().expect("duplicate lease fd");
	drop(root);
	flock(&writer, FlockOperation::NonBlockingLockExclusive).expect("reader released its lease");
	drop(alias);
}
