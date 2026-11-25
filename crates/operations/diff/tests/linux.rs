//! Native Linux coverage for the public read-only comparison entry point.
#![cfg(target_os = "linux")]

use std::fs::{self, DirBuilder, File};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt as _, FileExt as _, MetadataExt as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_diff::linux::{CompareError, Difference, LiveComparison, Side, compare};
use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::{ReadError, ReadRoot, SourceFile};

const LEFT: &str = "left";
const RIGHT: &str = "right";

#[test]
fn compares_regular_files_and_preserves_both_inodes_and_contents() {
	let fixture = Fixture::new();
	let left_bytes = b"byte\x00stream\xff";
	let left_path = fixture.0.join(LEFT);
	let right_path = fixture.0.join(RIGHT);
	fs::write(&left_path, left_bytes).expect("write left fixture");
	fs::write(&right_path, left_bytes).expect("write right fixture");
	let original_left = fs::metadata(&left_path).expect("stat left fixture");
	let original_right = fs::metadata(&right_path).expect("stat right fixture");
	let left = fixture.open(LEFT);
	let right = fixture.open(RIGHT);
	assert_eq!(
		compare(&left, &right, &mut [0; 7]).expect("compare equal files"),
		LiveComparison::Equal { length: 12 }
	);

	let mut right_bytes = *left_bytes;
	right_bytes[left_bytes.len() - 1] = 0;
	fs::write(&right_path, right_bytes).expect("replace fixture bytes");
	let right = fixture.open(RIGHT);
	assert_eq!(
		compare(&left, &right, &mut [0; 7]).expect("compare different files"),
		LiveComparison::Different(Difference::FirstByte { offset: 11 })
	);

	for (path, original, bytes) in [
		(left_path, original_left, left_bytes),
		(right_path, original_right, &right_bytes),
	] {
		let metadata = fs::metadata(&path).expect("stat remaining fixture");
		assert_eq!(metadata.ino(), original.ino());
		assert_eq!(fs::read(path).expect("read remaining fixture"), bytes);
	}
	assert_eq!(
		fs::read_dir(&fixture.0)
			.expect("list fixture directory")
			.count(),
		2
	);
}

#[test]
fn sparse_holes_compare_as_logical_zeros_and_can_contain_a_mismatch() {
	const HOLE_LENGTH: u64 = 12_289;
	const CHANGED_OFFSET: u64 = 8_193;

	let fixture = Fixture::new();
	let sparse = File::create(fixture.0.join(LEFT)).expect("create sparse fixture");
	sparse
		.set_len(HOLE_LENGTH)
		.expect("extend with sparse zeros");
	let right_path = fixture.0.join(RIGHT);
	let zeros = vec![0; usize::try_from(HOLE_LENGTH).expect("fixture allocation")];
	fs::write(&right_path, zeros).expect("write actual zeros");

	let left = fixture.open(LEFT);
	let right = fixture.open(RIGHT);
	let mut scratch = [0; 4096];
	assert_eq!(
		compare(&left, &right, &mut scratch).expect("compare sparse bytes"),
		LiveComparison::Equal {
			length: HOLE_LENGTH,
		}
	);

	sparse
		.write_all_at(b"x", CHANGED_OFFSET)
		.expect("write within sparse hole");
	let updated_left = fixture.open(LEFT);
	assert_eq!(
		compare(&updated_left, &right, &mut scratch).expect("compare sparse mismatch"),
		LiveComparison::Different(Difference::FirstByte {
			offset: CHANGED_OFFSET,
		})
	);
}

#[test]
fn detects_stale_length_before_returning_a_difference() {
	let fixture = Fixture::new();
	fs::write(fixture.0.join(LEFT), b"object").expect("write left fixture");
	let right = File::create(fixture.0.join(RIGHT)).expect("write empty right fixture");
	let left_view = fixture.open(LEFT);
	let right_view = fixture.open(RIGHT);
	assert_eq!(
		compare(&left_view, &right_view, &mut []).expect("compare differing lengths"),
		LiveComparison::Different(Difference::Length { left: 6, right: 0 })
	);

	right.set_len(6).expect("change recorded length");
	assert!(matches!(
		compare(&left_view, &right_view, &mut []),
		Err(CompareError::Observation {
			side: Side::Right,
			source: ReadError::SourceChanged,
		})
	));
}

#[test]
fn rejects_virtual_regular_file_with_data_outside_recorded_extent() {
	let proc_root =
		ReadRoot::from_directory(File::open("/proc").expect("open procfs")).expect("bind procfs");
	let name = UnixComponent::new(b"version").expect("validate procfs component");
	let virtual_file = proc_root
		.open_regular(name)
		.expect("open virtual regular inode");
	assert_eq!(virtual_file.len(), 0);
	assert!(matches!(
		compare(&virtual_file, &virtual_file, &mut []),
		Err(CompareError::Observation {
			side: Side::Left,
			source: ReadError::UnexpectedDataAfterEnd,
		})
	));
}

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		static NEXT: AtomicUsize = AtomicUsize::new(0);
		for _ in 0..128 {
			let token = NEXT.fetch_add(1, Ordering::Relaxed);
			let path = std::env::temp_dir()
				.join(format!("exacopy-diff-tests-{}-{token}", std::process::id()));
			match DirBuilder::new().mode(0o700).create(&path) {
				Ok(()) => return Self(path),
				Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
				Err(error) => panic!("create fixture directory: {error}"),
			}
		}
		panic!("exhausted synthetic fixture directory attempts");
	}

	fn open(&self, name: &str) -> SourceFile {
		let directory = File::open(&self.0).expect("open fixture directory");
		let root = ReadRoot::from_directory(directory).expect("admit fixture root");
		root.open_regular(UnixComponent::new(name.as_bytes()).expect("valid fixture name"))
			.expect("open regular fixture file")
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}
