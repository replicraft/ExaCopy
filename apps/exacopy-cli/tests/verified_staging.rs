//! Native Linux transfer tests for the verified, preserve-mode staging boundary.

#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, FileTimes, Metadata, OpenOptions, Permissions};
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, FileExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use exacopy_cli::assembly::linux::{StageFailure, stage_verified};
use exacopy_content::StreamInputError;
use exacopy_endpoint::UnixComponent;
use exacopy_model::{CopyBinding, CopyPhase, EntryId, JobId, RunEpoch, StageId};
use exacopy_platform::linux::{
	DestinationRoot, ExtendedAttributes, ReadError, ReadRoot, SourceFile, StageDirectory,
	StageError,
};
use exacopy_transfer::linux::StageRequest;
use rustix::fs::{self as unix, XattrFlags};

const SOURCE: &[u8] = b"input-\xff";
const STAGE: &[u8] = b"part-\xfe";
const TARGET: &[u8] = b"target-\xfd";
const PRIVATE_DIR: &[u8] = b"private";
const INCUMBENT: &[u8] = b"existing target";
const PERMISSION_BITS: u32 = 0o7777;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_MODE: u32 = 0o600;

// BLAKE3 1.8.7 canonical vectors. The nonempty input cycles the bytes 0 through 250.
// https://github.com/BLAKE3-team/BLAKE3/blob/1.8.7/test_vectors/test_vectors.json
const EMPTY_DIGEST: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
const VECTOR_LENGTH: usize = 1_025;
const VECTOR_DIGEST: &str = "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444";

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
	fn new(source: &[u8]) -> Self {
		const ATTEMPTS: usize = 128;
		let parent = std::env::temp_dir();
		let mut directories = DirBuilder::new();
		directories.mode(PRIVATE_DIRECTORY_MODE);
		let fixture = (0..ATTEMPTS)
			.find_map(|_| {
				let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
				let path = parent.join(format!(
					"exacopy-transfer-{}-{sequence}",
					std::process::id()
				));
				match directories.create(&path) {
					Ok(()) => Some(Self(path)),
					Err(error) if error.kind() == ErrorKind::AlreadyExists => None,
					Err(error) => panic!("could not create private transfer fixture: {error}"),
				}
			})
			.expect("allocate a fresh private transfer fixture");

		directories
			.create(fixture.0.join("input"))
			.expect("create private source root");
		directories
			.create(fixture.0.join("output"))
			.expect("create private destination root");
		fs::write(fixture.source_path(), source).expect("create source");
		fs::write(fixture.target_path(TARGET), INCUMBENT).expect("create incumbent");
		fixture
	}

	fn source_path(&self) -> PathBuf {
		self.0.join("input").join(OsStr::from_bytes(SOURCE))
	}

	fn target_path(&self, target: &[u8]) -> PathBuf {
		self.0.join("output").join(OsStr::from_bytes(target))
	}

	fn stage_path(&self) -> PathBuf {
		self.target_path(PRIVATE_DIR).join(OsStr::from_bytes(STAGE))
	}

	fn open_source(&self) -> SourceFile {
		let input = File::open(self.0.join("input")).expect("open source directory");
		let root = ReadRoot::from_directory(input).expect("admit source directory");
		root.open_regular(component(SOURCE))
			.expect("observe source")
	}

	fn open_destination(&self) -> DestinationRoot {
		let output = File::open(self.0.join("output")).expect("open destination directory");
		DestinationRoot::from_directory(output).expect("admit destination directory")
	}

	fn check_preserved(&self, expected_source: &[u8], expected_incumbent: &Metadata) {
		assert_eq!(
			fs::read(self.source_path()).expect("read original source"),
			expected_source
		);
		let target = self.target_path(TARGET);
		let current = fs::symlink_metadata(&target).expect("inspect preserved incumbent");
		assert_eq!(
			(
				current.dev(),
				current.ino(),
				current.mode(),
				current
					.modified()
					.expect("read incumbent modification time")
			),
			(
				expected_incumbent.dev(),
				expected_incumbent.ino(),
				expected_incumbent.mode(),
				expected_incumbent
					.modified()
					.expect("read original modification time")
			)
		);
		assert_eq!(
			fs::read(target).expect("read preserved incumbent"),
			INCUMBENT
		);
	}

	fn incumbent(&self) -> Metadata {
		fs::symlink_metadata(self.target_path(TARGET)).expect("inspect original incumbent")
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

fn component(name: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(name).expect("valid fixture name")
}

fn stage_directory(destination: &DestinationRoot) -> StageDirectory<'_> {
	destination
		.create_stage_directory(component(PRIVATE_DIR))
		.expect("create private stage directory")
}

fn request(target: &[u8]) -> StageRequest<'_> {
	let job = JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
		.expect("fixture job is UUIDv7");
	StageRequest {
		stage_name: component(STAGE),
		target: component(target),
		binding: CopyBinding::new(
			job,
			EntryId::new(1),
			RunEpoch::new(1),
			StageId::from_bytes([0x53; 16]),
		),
	}
}

fn assert_missing(path: PathBuf) {
	assert_eq!(
		fs::symlink_metadata(&path)
			.expect_err("fixture path must be absent")
			.kind(),
		ErrorKind::NotFound,
		"{path:?}"
	);
}

#[test]
fn stages_a_known_dense_stream_across_scratch_boundaries_and_preserves_metadata() {
	const SOURCE_MODE: u32 = 0o640;
	let data: Vec<_> = (0..=250_u8).cycle().take(VECTOR_LENGTH).collect();
	for scratch_length in [1, 17, 257, 1_024] {
		let fixture = Fixture::new(&data);
		let incumbent = fixture.incumbent();
		let path = fixture.source_path();
		let metadata = File::open(&path).expect("open source metadata fixture");
		metadata
			.set_permissions(Permissions::from_mode(SOURCE_MODE))
			.expect("set ordinary source mode");
		metadata
			.set_times(
				FileTimes::new()
					.set_accessed(UNIX_EPOCH + Duration::new(100, 15))
					.set_modified(UNIX_EPOCH + Duration::new(200, 25)),
			)
			.expect("set known source timestamps");
		let initial = metadata
			.metadata()
			.expect("inspect original source metadata");
		let source = fixture.open_source();
		let destination = fixture.open_destination();
		let directory = stage_directory(&destination);

		let stage = stage_verified(
			&source,
			&directory,
			request(TARGET),
			&mut vec![u8::MAX; scratch_length],
		)
		.expect("produce a sealed and verified dense stage");
		assert_eq!(stage.phase(), CopyPhase::ReadyToPublish);
		assert_eq!(
			stage.digest().to_string(),
			VECTOR_DIGEST,
			"scratch size {scratch_length}"
		);
		assert_eq!(
			stage.length(),
			u64::try_from(VECTOR_LENGTH).expect("fixture length fits in u64")
		);

		let stage_path = fixture.stage_path();
		let stage_root = ReadRoot::from_directory(
			File::open(fixture.target_path(PRIVATE_DIR))
				.expect("open stage directory for independent inspection"),
		)
		.expect("admit stage directory for inspection");
		let stage_entry = stage_root
			.open_regular(component(STAGE))
			.expect("reopen raw stage name");
		assert_eq!(stage.identity(), stage_entry.identity());
		assert_ne!(stage.identity(), source.identity());
		let staged = fs::metadata(&stage_path).expect("inspect metadata before reading stage");
		assert_eq!(staged.mode() & PERMISSION_BITS, SOURCE_MODE);
		assert_eq!(staged.uid(), initial.uid());
		assert_eq!(staged.gid(), initial.gid());
		assert_eq!(
			staged.modified().expect("stage mtime"),
			initial.modified().expect("source mtime")
		);
		assert_eq!(
			staged.accessed().expect("stage atime"),
			initial.accessed().expect("source atime")
		);
		assert_eq!(fs::read(stage_path).expect("read exact staged bytes"), data);
		let current = metadata
			.metadata()
			.expect("inspect retained source metadata");
		assert_eq!(
			(current.dev(), current.ino(), current.mode()),
			(initial.dev(), initial.ino(), initial.mode())
		);
		assert_eq!(
			current.modified().expect("source mtime after staging"),
			initial.modified().expect("original source mtime")
		);
		fixture.check_preserved(&data, &incumbent);
	}
}

#[test]
fn stages_an_empty_file_with_no_scratch_and_does_not_create_the_final_name() {
	const ABSENT_TARGET: &[u8] = b"absent-target";
	let fixture = Fixture::new(b"");
	let incumbent = fixture.incumbent();
	let source = fixture.open_source();
	let destination = fixture.open_destination();
	let directory = stage_directory(&destination);

	let stage = stage_verified(&source, &directory, request(ABSENT_TARGET), &mut [])
		.expect("seal an empty source with zero scratch bytes");
	assert_eq!(stage.phase(), CopyPhase::ReadyToPublish);
	assert_eq!(stage.length(), 0);
	assert_eq!(stage.digest().to_string(), EMPTY_DIGEST);
	assert!(
		fs::read(fixture.stage_path())
			.expect("read staged empty file")
			.is_empty()
	);
	assert_missing(fixture.target_path(ABSENT_TARGET));
	fixture.check_preserved(b"", &incumbent);
}

#[test]
fn preserves_sparse_logical_zeros_and_raw_unix_names() {
	const TAIL_OFFSET: usize = 16 * 1_024;
	let fixture = Fixture::new(b"head");
	let incumbent = fixture.incumbent();
	let writer = OpenOptions::new()
		.write(true)
		.open(fixture.source_path())
		.expect("open source fixture writer");
	writer
		.write_all_at(
			b"tail",
			u64::try_from(TAIL_OFFSET).expect("fixture offset fits in u64"),
		)
		.expect("place trailing data beyond the unwritten range");
	drop(writer);
	let mut logical = b"head".to_vec();
	logical.resize(TAIL_OFFSET, 0);
	logical.extend_from_slice(b"tail");
	let source = fixture.open_source();
	let destination = fixture.open_destination();
	let directory = stage_directory(&destination);

	let stage = stage_verified(&source, &directory, request(TARGET), &mut [u8::MAX; 509])
		.expect("stage a raw-name source with an unwritten range");
	assert_eq!(stage.phase(), CopyPhase::ReadyToPublish);
	assert_eq!(
		stage.length(),
		u64::try_from(logical.len()).expect("fixture length fits in u64")
	);
	assert_eq!(
		fs::read(fixture.stage_path()).expect("read stage at the raw Unix name"),
		logical
	);
	fixture.check_preserved(&logical, &incumbent);
}

#[test]
fn rejects_empty_scratch_for_nonempty_input_before_allocating_a_stage() {
	let fixture = Fixture::new(b"nonempty");
	let incumbent = fixture.incumbent();
	let source = fixture.open_source();
	let destination = fixture.open_destination();
	let directory = stage_directory(&destination);

	let error = stage_verified(&source, &directory, request(TARGET), &mut [])
		.expect_err("nonempty input needs scratch");
	assert_eq!(error.phase(), CopyPhase::Planned);
	assert!(
		matches!(
			error.failure(),
			StageFailure::Input(StreamInputError::EmptyScratch)
		),
		"{error}"
	);
	assert_missing(fixture.stage_path());
	fixture.check_preserved(b"nonempty", &incumbent);
}

#[test]
fn rejects_a_changed_observed_source_before_allocating_a_stage() {
	let fixture = Fixture::new(b"old");
	let incumbent = fixture.incumbent();
	let writer = OpenOptions::new()
		.write(true)
		.open(fixture.source_path())
		.expect("open fixture writer");
	writer
		.set_modified(UNIX_EPOCH + Duration::from_secs(100))
		.expect("seed the original modification time");
	let source = fixture.open_source();
	writer
		.write_all_at(b"new", 0)
		.expect("change source bytes after observation");
	drop(writer);
	let destination = fixture.open_destination();
	let directory = stage_directory(&destination);

	let error = stage_verified(&source, &directory, request(TARGET), &mut [0; 2])
		.expect_err("reject observed modification before staging");
	assert_eq!(error.phase(), CopyPhase::Planned);
	assert!(
		matches!(
			error.failure(),
			StageFailure::Source(ReadError::SourceChanged)
		),
		"{error}"
	);
	assert_missing(fixture.stage_path());
	fixture.check_preserved(b"new", &incumbent);
}

#[test]
fn rejects_visible_source_attributes_before_allocating_a_stage() {
	const ATTRIBUTE_DATA: &[u8] = b"keep xattr";
	let fixture = Fixture::new(b"with xattr");
	let incumbent = fixture.incumbent();
	let original = File::open(fixture.source_path()).expect("open fixture for extended attributes");
	unix::fsetxattr(
		&original,
		c"user.exacopy_test",
		ATTRIBUTE_DATA,
		XattrFlags::CREATE,
	)
	.expect("set unprivileged source fixture attribute");
	let source = fixture.open_source();
	let destination = fixture.open_destination();
	let directory = stage_directory(&destination);

	let error = stage_verified(&source, &directory, request(TARGET), &mut [0; 4])
		.expect_err("refuse unsupported source attributes");
	assert_eq!(error.phase(), CopyPhase::Planned);
	assert!(
		matches!(
			error.failure(),
			StageFailure::SourceAttributes(ExtendedAttributes::Present)
		),
		"{error}"
	);
	assert_missing(fixture.stage_path());
	let mut attribute_buf = [0; ATTRIBUTE_DATA.len()];
	let attribute = unix::fgetxattr(&original, c"user.exacopy_test", &mut attribute_buf[..])
		.expect("read preserved fixture attribute");
	assert_eq!(attribute, ATTRIBUTE_DATA.len());
	assert_eq!(&attribute_buf, ATTRIBUTE_DATA);
	fixture.check_preserved(b"with xattr", &incumbent);
}

#[test]
fn keeps_an_existing_private_stage_and_the_incumbent_on_exclusive_creation_failure() {
	let fixture = Fixture::new(b"source");
	let incumbent = fixture.incumbent();
	let source = fixture.open_source();
	let destination = fixture.open_destination();
	let directory = stage_directory(&destination);
	let path = fixture.stage_path();
	fs::write(&path, b"existing private evidence").expect("create an existing stage fixture");
	fs::set_permissions(&path, Permissions::from_mode(PRIVATE_MODE))
		.expect("set private fixture mode");
	let original = fs::metadata(&path).expect("inspect the existing stage");

	let error = stage_verified(&source, &directory, request(TARGET), &mut [0; 4])
		.expect_err("refuse to adopt the stage name");
	assert_eq!(error.phase(), CopyPhase::Planned);
	assert!(
		matches!(
			error.failure(),
			StageFailure::Stage(StageError::AlreadyExists)
		),
		"{error}"
	);
	let retained = fs::metadata(&path).expect("inspect the retained stage");
	assert_eq!(
		(retained.dev(), retained.ino(), retained.mode()),
		(original.dev(), original.ino(), original.mode())
	);
	assert_eq!(
		fs::read(path).expect("read retained evidence"),
		b"existing private evidence"
	);
	fixture.check_preserved(b"source", &incumbent);
}

#[test]
fn rejects_special_source_mode_before_allocating_a_stage() {
	const STICKY_FILE_MODE: u32 = 0o1600;
	let fixture = Fixture::new(b"source");
	let incumbent = fixture.incumbent();
	let source_path = fixture.source_path();
	fs::set_permissions(&source_path, Permissions::from_mode(STICKY_FILE_MODE))
		.expect("set a special non-executable mode on the fixture");
	let source = fixture.open_source();
	let destination = fixture.open_destination();
	let directory = stage_directory(&destination);

	let error = stage_verified(&source, &directory, request(TARGET), &mut [0; 3])
		.expect_err("not all source permissions are supported");
	assert_eq!(error.phase(), CopyPhase::Planned);
	assert!(
		matches!(
			error.failure(),
			StageFailure::UnsupportedSourceMode {
				mode: STICKY_FILE_MODE
			}
		),
		"{error}"
	);
	assert_missing(fixture.stage_path());
	assert_eq!(
		fs::metadata(source_path)
			.expect("inspect retained source")
			.mode()
			& PERMISSION_BITS,
		STICKY_FILE_MODE
	);
	fixture.check_preserved(b"source", &incumbent);
}
