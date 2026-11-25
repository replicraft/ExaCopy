//! Native Linux source-handle containment, file identity, and positioned I/O.

#![cfg(target_os = "linux")]

mod common;

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::symlink;

use exacopy_endpoint::{IoError, UnixComponent};
use exacopy_platform::linux::{ReadError, ReadRoot};
use rustix::fs::{self as unix, Mode};
use rustix::io::Errno;

use common::Scratch;

#[test]
fn opens_a_raw_name_relative_to_the_held_directory_after_its_path_is_replaced() {
	let scratch = Scratch::new();
	let original_dir = scratch.path("held-source-root");
	let moved_dir = scratch.path("moved");
	let name = b"raw-\xff\\:name";
	let raw = OsStr::from_bytes(name);
	fs::create_dir(&original_dir).expect("create source directory");
	fs::write(original_dir.join(raw), b"original").expect("create raw source name");
	let root = ReadRoot::from_directory(File::open(&original_dir).expect("open source directory"))
		.expect("admit source root");
	scratch.assert_debug_redacts(&root, &["held-source-root"]);
	fs::rename(&original_dir, &moved_dir).expect("move the original root");
	fs::create_dir(&original_dir).expect("create replacement root");
	fs::write(original_dir.join(raw), b"replaced").expect("populate replacement root");

	let source = root
		.open_regular(UnixComponent::new(name).expect("validate raw name"))
		.expect("open by held root");
	scratch.assert_debug_redacts(&source, &["held-source-root", "raw-"]);
	let mut read = [0; 8];
	source
		.read_exact_at(0, &mut read)
		.expect("read from original root");
	assert_eq!(&read, b"original");
	assert_eq!(
		fs::read(original_dir.join(raw)).expect("read replacement"),
		b"replaced"
	);
	assert_eq!(
		fs::read(moved_dir.join(raw)).expect("read moved original"),
		b"original"
	);
}

#[test]
fn hard_links_share_identity_and_replacing_the_name_leaves_the_open_object_pinned() {
	let scratch = Scratch::new();
	fs::write(scratch.path("source"), b"original").expect("create original");
	fs::hard_link(scratch.path("source"), scratch.path("alias")).expect("create hard-link alias");
	fs::write(scratch.path("new"), b"original")
		.expect("create independent file with identical bytes");
	let root = ReadRoot::from_directory(scratch.open()).expect("admit source root");

	let source_name = UnixComponent::new(b"source").expect("valid source name");
	let pinned = root
		.open_regular(source_name)
		.expect("open original source");
	let alias = root
		.open_regular(UnixComponent::new(b"alias").expect("valid alias name"))
		.expect("open hard-link alias");
	assert_eq!(
		pinned.identity(),
		alias.identity(),
		"hard links share physical identity"
	);

	fs::rename(scratch.path("new"), scratch.path("source")).expect("rebind source name");
	let replacement = root
		.open_regular(source_name)
		.expect("open replacement source");
	assert_ne!(
		pinned.identity(),
		replacement.identity(),
		"equal bytes do not imply identity"
	);
	fs::write(scratch.path("source"), b"replaced").expect("update replacement bytes");

	let mut pinned_bytes = [0; 8];
	pinned
		.read_exact_at(0, &mut pinned_bytes)
		.expect("read pinned object");
	assert_eq!(&pinned_bytes, b"original");
	assert_eq!(
		fs::read(scratch.path("alias")).expect("read surviving alias"),
		b"original"
	);
	assert_eq!(
		fs::read(scratch.path("source")).expect("read replacement"),
		b"replaced"
	);
}

#[test]
fn rejects_links_inside_and_outside_the_root_and_invalid_components() {
	let scratch = Scratch::new();
	let granted = scratch.path("granted");
	fs::create_dir(&granted).expect("create granted root");
	fs::write(granted.join("inside"), b"inside").expect("create in-root file");
	fs::write(scratch.path("outside"), b"outside").expect("create out-of-root fixture");
	symlink("inside", granted.join("in-link")).expect("create in-root symlink");
	symlink("../outside", granted.join("out-link")).expect("create escaping symlink");
	let root = ReadRoot::from_directory(File::open(&granted).expect("open granted directory"))
		.expect("admit source root");

	for name in [b"in-link".as_slice(), b"out-link"] {
		let result = root.open_regular(UnixComponent::new(name).expect("valid symlink component"));
		assert!(
			matches!(&result, Err(ReadError::System(error)) if error.raw_os_error() == Some(Errno::LOOP.raw_os_error())),
			"{name:?} unexpectedly resolved: {result:?}",
		);
	}
	for name in [
		b"".as_slice(),
		b".",
		b"..",
		b"../outside",
		b"/outside",
		b"inside\0suffix",
	] {
		assert!(
			UnixComponent::new(name).is_err(),
			"{name:?} parsed as a component"
		);
	}
	assert_eq!(
		fs::read(granted.join("inside")).expect("read in-root file"),
		b"inside"
	);
	assert_eq!(
		fs::read(scratch.path("outside")).expect("read out-of-root file"),
		b"outside"
	);
}

#[test]
fn rejects_crossing_the_proc_mount_from_a_root_directory_handle() {
	let root = ReadRoot::from_directory(File::open("/").expect("open Linux root read-only"))
		.expect("admit Linux root");
	let result = root.open_regular(UnixComponent::new(b"proc").expect("valid mount component"));
	assert!(
		matches!(&result, Err(ReadError::System(error)) if error.raw_os_error() == Some(Errno::XDEV.raw_os_error())),
		"expected mount-boundary rejection at the proc mount: {result:?}",
	);
}

#[test]
fn checks_the_observed_eof_without_accepting_an_appended_suffix() {
	let scratch = Scratch::new();
	let path = scratch.path("source");
	let mut writer = OpenOptions::new()
		.create_new(true)
		.append(true)
		.open(path)
		.expect("create source fixture");
	let root = ReadRoot::from_directory(scratch.open()).expect("admit fixture");
	let source = root
		.open_regular(UnixComponent::new(b"source").expect("admitted name"))
		.expect("open empty source");
	source
		.check_logical_eof()
		.expect("empty stream ends at zero");
	writer.write_all(b"visible data").expect("append a suffix");
	assert!(matches!(
		source.check_logical_eof(),
		Err(ReadError::UnexpectedDataAfterEnd)
	));
}

#[test]
fn rejects_fifos_and_directories_as_nonregular_without_opening_a_data_stream() {
	let scratch = Scratch::new();
	let directory = scratch.open();
	unix::mkfifoat(&directory, "fifo", Mode::RUSR | Mode::WUSR)
		.expect("create a fixture FIFO with no peer");
	fs::create_dir(scratch.path("directory")).expect("create fixture subdirectory");
	fs::write(scratch.path("file"), b"").expect("create fixture regular file");
	let root = ReadRoot::from_directory(directory).expect("admit source root");

	for kind in [b"fifo".as_slice(), b"directory"] {
		let result = root.open_regular(UnixComponent::new(kind).expect("valid fixture name"));
		assert!(
			matches!(result, Err(ReadError::NotRegularFile)),
			"{kind:?}: {result:?}"
		);
	}
	let regular_handle = File::open(scratch.path("file")).expect("open regular file");
	assert!(matches!(
		ReadRoot::from_directory(regular_handle),
		Err(ReadError::NotDirectory)
	));
}

#[test]
fn reads_out_of_order_with_fixed_offsets_and_reports_eof_after_a_partial_read() {
	let scratch = Scratch::new();
	fs::write(scratch.path("source"), b"01234567").expect("create source with eight bytes");
	let root = ReadRoot::from_directory(scratch.open()).expect("admit source root");
	let source = root
		.open_regular(UnixComponent::new(b"source").expect("valid source name"))
		.expect("open stable-sized source");
	assert_eq!(source.len(), 8);
	assert!(!source.is_empty());

	let mut chunk = [0; 2];
	source
		.read_exact_at(6, &mut chunk)
		.expect("read final range");
	assert_eq!(&chunk, b"67");
	source
		.read_exact_at(1, &mut chunk)
		.expect("read earlier range");
	assert_eq!(&chunk, b"12");
	assert!(matches!(
		source.read_exact_at(7, &mut chunk),
		Err(ReadError::RangeOutsideFile)
	));

	OpenOptions::new()
		.write(true)
		.open(scratch.path("source"))
		.expect("open synthetic source as the external writer")
		.set_len(4)
		.expect("truncate the synthetic source after it was opened");
	let mut crossed_end = [0; 4];
	let result = source.read_exact_at(2, &mut crossed_end);
	assert!(
		matches!(
			result,
			Err(ReadError::Io(IoError::UnexpectedEof { offset: 4 }))
		),
		"unexpected EOF result: {result:?}"
	);
	assert_eq!(
		&crossed_end[..2],
		b"23",
		"the first read reached the shortened file"
	);
	assert_eq!(
		fs::read(scratch.path("source")).expect("read externally truncated file"),
		b"0123"
	);
}
