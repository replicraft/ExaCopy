use std::fs::{self, DirBuilder, File};
use std::io::{self, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};
use exacopy_model::{EntryId, JobId, RunEpoch};

use super::super::{ManagedReadError, ManagedReadGrant, ManagedReadRoot, acl};
use super::{ManagedStageGrant, ManagedStageRoot, StageBindingContext, StageDirectory, StageError};

const PRIVATE: &str = "private-stage";
const STAGE: &str = "candidate";
const TARGET: &str = "target";
const SOURCE: &str = "source";
const PAYLOAD: &[u8] = b"\0a preserved\xFF byte sequence";

pub(super) struct Fixture(PathBuf);

impl Fixture {
	pub(super) fn new() -> Self {
		static NEXT: AtomicUsize = AtomicUsize::new(0);
		const MAX_ATTEMPTS: usize = 64;
		for _ in 0..MAX_ATTEMPTS {
			let attempt = NEXT.fetch_add(1, Ordering::Relaxed);
			let path = Path::new("/private/tmp").join(format!(
				"exacopy-managed-stage-test-{}-{attempt}",
				std::process::id()
			));
			match DirBuilder::new().mode(0o700).create(&path) {
				Ok(()) => {
					install_empty_acl(&path);
					let private = path.join(PRIVATE);
					DirBuilder::new().mode(0o700).create(&private).unwrap();
					install_empty_acl(&private);
					return Self(path);
				}
				Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
				Err(error) => panic!("cannot allocate local APFS fixture: {error}"),
			}
		}
		panic!("local APFS fixture attempts exhausted");
	}

	pub(super) fn bind(&self) -> ManagedStageRoot {
		bind(self.open()).expect("admit provisioned APFS destination fixture")
	}

	fn open(&self) -> File {
		File::open(&self.0).expect("open fixture destination directory")
	}

	pub(super) fn path(&self, child: &str) -> PathBuf {
		self.0.join(child)
	}

	pub(super) fn stage_path(&self) -> PathBuf {
		self.path(PRIVATE).join(STAGE)
	}
}

// Only synthetic test paths get fixture ACLs.
fn install_empty_acl(path: &Path) {
	let file = File::open(path).expect("open synthetic directory for ACL setup");
	acl::set_fixture_empty_acl(file.as_fd()).expect("set explicit zero-entry ACL");
}

fn bind(file: File) -> Result<ManagedStageRoot, StageError> {
	ManagedStageRoot::from_provisioned_directory(
		file,
		ManagedStageGrant::trusted_owner_authorizes_provisioned_root(),
	)
}

pub(super) fn name(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).expect("valid fixture component")
}

pub(super) fn context() -> StageBindingContext {
	let mut job = [0; 16];
	job[6] = 0x70;
	job[8] = 0x80;
	StageBindingContext::new(
		JobId::try_from_bytes(job).expect("synthetic UUIDv7"),
		EntryId::new(1),
		RunEpoch::new(1),
	)
}

pub(super) fn open_staging(root: &ManagedStageRoot) -> StageDirectory<'_> {
	root.open_stage_directory(name(PRIVATE.as_bytes()))
		.expect("select the provisioned private child")
}

pub(super) fn fixture_stage_name() -> &'static super::ManagedStageName<'static> {
	static NAME: std::sync::LazyLock<super::ManagedStageName<'static>> =
		std::sync::LazyLock::new(|| super::ManagedStageName::new(name(STAGE.as_bytes())).unwrap());
	&NAME
}

pub(super) fn make_stage<'a>(
	directory: &'a StageDirectory<'a>,
	length: u64,
) -> Result<super::WriteStage<'a>, StageError> {
	directory.create_file(
		fixture_stage_name(),
		name(TARGET.as_bytes()),
		context(),
		length,
	)
}

fn make_file(path: &Path, bytes: &[u8]) {
	File::options()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(path)
		.unwrap()
		.write_all(bytes)
		.unwrap();
}

fn object(path: &Path) -> (u64, u64, u32, u64) {
	let stat = fs::symlink_metadata(path).unwrap();
	(stat.dev(), stat.ino(), stat.mode(), stat.nlink())
}

#[test]
fn writes_whole_extent_then_reopens_same_private_inode_for_read_back() {
	let fixture = Fixture::new();
	make_file(&fixture.path(SOURCE), PAYLOAD);
	let source = object(&fixture.path(SOURCE));
	let length = u64::try_from(PAYLOAD.len()).unwrap();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, length).unwrap();
	let staged = object(&fixture.stage_path());
	let identity = writer.identity();
	assert_eq!(writer.binding(), identity.binding());
	writer.write_next(&PAYLOAD[..7]).unwrap();
	writer.write_next(&PAYLOAD[7..]).unwrap();
	assert!(matches!(
		writer.write_next(&[0]),
		Err(StageError::InvalidRange)
	));

	let closed = writer
		.flush_and_close()
		.expect("synchronize and confirm writer closure");
	assert_eq!(closed.identity(), identity);
	assert_eq!(closed.binding(), identity.binding());
	assert_eq!(closed.target(), name(TARGET.as_bytes()));
	assert_eq!(closed.length(), length);
	let reader = closed.open_read_back().expect("independent read-only open");
	let mut bytes = [0; PAYLOAD.len()];
	reader.read_exact_at(7, &mut bytes[7..]).unwrap();
	reader.read_exact_at(0, &mut bytes[..7]).unwrap();
	reader.revalidate().unwrap();

	assert_eq!(bytes, PAYLOAD);
	assert_eq!(object(&fixture.stage_path()), staged);
	assert_eq!(object(&fixture.path(SOURCE)), source);
	assert_eq!(fs::read(fixture.path(SOURCE)).unwrap(), PAYLOAD);
	assert!(
		!fixture.path(TARGET).exists(),
		"stage never occupies the public target"
	);
	let debug = format!("{root:?} {directory:?} {closed:?} {reader:?}");
	for protected in [PRIVATE, STAGE, TARGET] {
		assert!(
			!debug.contains(protected),
			"debug leaked {protected}: {debug}"
		);
	}
}

#[test]
fn empty_and_incomplete_extents_have_distinct_results() {
	let empty = Fixture::new();
	let root = empty.bind();
	let directory = open_staging(&root);
	let closed = make_stage(&directory, 0)
		.unwrap()
		.flush_and_close()
		.unwrap();
	let reader = closed.open_read_back().unwrap();
	assert!(closed.is_empty());
	reader.read_exact_at(0, &mut []).unwrap();
	reader.revalidate().unwrap();
	assert!(matches!(
		reader.read_exact_at(0, &mut [0]),
		Err(StageError::InvalidRange)
	));
	assert_eq!(fs::metadata(empty.stage_path()).unwrap().len(), 0);

	let incomplete = Fixture::new();
	let root = incomplete.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 6).unwrap();
	assert!(matches!(
		writer.write_next(&[]),
		Err(StageError::InvalidRange)
	));
	assert!(matches!(
		writer.write_next(b"too many"),
		Err(StageError::InvalidRange)
	));
	writer.write_next(b"abc").unwrap();
	assert!(matches!(
		writer.flush_and_close(),
		Err(StageError::Incomplete)
	));
	assert_eq!(fs::read(incomplete.stage_path()).unwrap(), b"abc");
	assert!(!incomplete.path(TARGET).exists());
}

#[test]
fn oversized_declared_extent_has_no_creation_effect() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	assert!(matches!(
		make_stage(&directory, MAX_FILE_LENGTH + 1),
		Err(StageError::InvalidLength)
	));
	assert!(!fixture.stage_path().exists());
}

#[test]
fn exclusive_leases_conflict_with_managed_readers_at_root_and_child() {
	let fixture = Fixture::new();
	let shared = ManagedReadRoot::from_provisioned_directory(
		fixture.open(),
		ManagedReadGrant::trusted_owner_authorizes_provisioned_root(),
	)
	.unwrap();
	assert!(matches!(
		bind(fixture.open()),
		Err(StageError::DirectoryBusy)
	));
	drop(shared);
	let root = fixture.bind();
	assert!(matches!(
		bind(fixture.open()),
		Err(StageError::DirectoryBusy)
	));
	let private = fixture.path(PRIVATE);
	let shared_child = ManagedReadRoot::from_provisioned_directory(
		File::open(&private).unwrap(),
		ManagedReadGrant::trusted_owner_authorizes_provisioned_root(),
	)
	.unwrap();
	assert!(matches!(
		root.open_stage_directory(name(PRIVATE.as_bytes())),
		Err(StageError::DirectoryBusy)
	));
	drop(shared_child);
	let directory = open_staging(&root);
	assert!(matches!(
		ManagedReadRoot::from_provisioned_directory(
			File::open(&private).unwrap(),
			ManagedReadGrant::trusted_owner_authorizes_provisioned_root(),
		),
		Err(ManagedReadError::DirectoryBusy)
	));
	drop(directory);
	open_staging(&root);
}

#[test]
fn rejects_unprovisioned_children_and_symlink_without_creating_any_stage() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let unprovisioned = fixture.path("unprovisioned");
	DirBuilder::new()
		.mode(0o700)
		.create(&unprovisioned)
		.unwrap();
	assert!(matches!(
		root.open_stage_directory(name(b"unprovisioned")),
		Err(StageError::Managed(ManagedReadError::UnsupportedNamespace))
	));
	symlink(PRIVATE, fixture.path("indirection")).unwrap();
	assert!(matches!(
		root.open_stage_directory(name(b"indirection")),
		Err(StageError::DirectoryChanged)
	));
	assert!(matches!(
		root.open_stage_directory(name(b"absent")),
		Err(StageError::System(error)) if error.kind() == io::ErrorKind::NotFound
	));
	assert_eq!(
		fs::read_link(fixture.path("indirection")).unwrap(),
		Path::new(PRIVATE)
	);
	assert!(!fixture.stage_path().exists());
}

#[derive(Clone, Copy, Debug)]
enum Incumbent {
	Regular,
	Directory,
	Symlink,
	HardLink,
}

const INCUMBENTS: [Incumbent; 4] = [
	Incumbent::Regular,
	Incumbent::Directory,
	Incumbent::Symlink,
	Incumbent::HardLink,
];

fn install_incumbent(kind: Incumbent, path: &Path, source: &Path) {
	match kind {
		Incumbent::Regular => make_file(path, PAYLOAD),
		Incumbent::Directory => fs::create_dir(path).unwrap(),
		Incumbent::Symlink => symlink(source, path).unwrap(),
		Incumbent::HardLink => fs::hard_link(source, path).unwrap(),
	}
}

fn assert_incumbent(kind: Incumbent, path: &Path, source: &Path, identity: (u64, u64, u32, u64)) {
	assert_eq!(object(path), identity, "{kind:?} identity and metadata");
	match kind {
		Incumbent::Regular | Incumbent::HardLink => assert_eq!(fs::read(path).unwrap(), PAYLOAD),
		Incumbent::Directory => assert_eq!(fs::read_dir(path).unwrap().count(), 0),
		Incumbent::Symlink => assert_eq!(fs::read_link(path).unwrap(), source),
	}
}

#[test]
fn occupied_public_targets_refuse_before_creating_a_private_stage() {
	for kind in INCUMBENTS {
		let fixture = Fixture::new();
		let source = fixture.path(SOURCE);
		let target = fixture.path(TARGET);
		make_file(&source, PAYLOAD);
		install_incumbent(kind, &target, &source);
		let (source_identity, target_identity) = (object(&source), object(&target));
		let root = fixture.bind();
		let directory = open_staging(&root);
		assert!(
			matches!(make_stage(&directory, 1), Err(StageError::NameCollision)),
			"{kind:?}"
		);
		assert!(!fixture.stage_path().exists(), "{kind:?} created a stage");
		assert_incumbent(kind, &target, &source, target_identity);
		assert_eq!(object(&source), source_identity);
		assert_eq!(fs::read(source).unwrap(), PAYLOAD);
	}
}

#[test]
fn occupied_stage_names_are_never_opened_for_write() {
	for kind in INCUMBENTS {
		let fixture = Fixture::new();
		let source = fixture.path(SOURCE);
		let stage = fixture.stage_path();
		make_file(&source, PAYLOAD);
		install_incumbent(kind, &stage, &source);
		let (source_identity, stage_identity) = (object(&source), object(&stage));
		let root = fixture.bind();
		let directory = open_staging(&root);
		assert!(
			matches!(make_stage(&directory, 1), Err(StageError::NameCollision)),
			"{kind:?}"
		);
		assert_incumbent(kind, &stage, &source, stage_identity);
		assert_eq!(object(&source), source_identity);
		assert_eq!(fs::read(source).unwrap(), PAYLOAD);
		assert!(!fixture.path(TARGET).exists());
	}
}

#[test]
fn existing_staging_directory_reserves_its_public_name_and_apfs_aliases() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	assert!(matches!(
		directory.create_file(fixture_stage_name(), name(PRIVATE.as_bytes()), context(), 1),
		Err(StageError::NameCollision)
	));
	assert!(!fixture.stage_path().exists());
	let alias = "PRIVATE-STAGE";
	let result = directory.create_file(fixture_stage_name(), name(alias.as_bytes()), context(), 1);
	if fixture.path(alias).exists() {
		assert!(matches!(result, Err(StageError::NameCollision)));
		assert!(!fixture.stage_path().exists());
	} else {
		let writer =
			result.expect("a case-sensitive APFS volume treats the spelling as a separate name");
		assert!(!fixture.path(alias).exists());
		drop(writer);
	}
}

#[test]
fn replacing_stage_directory_retires_writer_without_modifying_either_entry() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 1).unwrap();
	let original = fixture.path("original-directory");
	fs::rename(fixture.path(PRIVATE), &original).unwrap();
	DirBuilder::new()
		.mode(0o700)
		.create(fixture.path(PRIVATE))
		.unwrap();
	install_empty_acl(&fixture.path(PRIVATE));
	make_file(&fixture.stage_path(), PAYLOAD);
	assert!(matches!(
		writer.write_next(&[1]),
		Err(StageError::DirectoryChanged)
	));
	assert!(matches!(
		writer.write_next(&[1]),
		Err(StageError::WriterRetired)
	));
	assert_eq!(fs::metadata(original.join(STAGE)).unwrap().len(), 0);
	assert_eq!(fs::read(fixture.stage_path()).unwrap(), PAYLOAD);
	assert!(!fixture.path(TARGET).exists());
}

#[test]
fn rebinding_closed_stage_name_rejects_both_reads_and_new_read_handles() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 3).unwrap();
	writer.write_next(b"old").unwrap();
	let stage = writer.flush_and_close().unwrap();
	let reader = stage.open_read_back().unwrap();
	let original = fixture.path("original-file");
	fs::rename(fixture.stage_path(), &original).unwrap();
	make_file(&fixture.stage_path(), b"new");

	let mut bytes = [0; 3];
	assert!(matches!(
		reader.read_exact_at(0, &mut bytes),
		Err(StageError::StageChanged)
	));
	assert_eq!(bytes, [0; 3]);
	assert!(matches!(
		stage.open_read_back(),
		Err(StageError::StageChanged)
	));
	assert_eq!(fs::read(original).unwrap(), b"old");
	assert_eq!(fs::read(fixture.stage_path()).unwrap(), b"new");
}
