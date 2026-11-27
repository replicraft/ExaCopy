//! Native Linux source-handle containment, file identity, and positioned I/O.

#![cfg(target_os = "linux")]

mod common;

use std::error::Error as _;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use exacopy_endpoint::{IoError, ReadView, UnixComponent};
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
	root.recheck_regular_name(UnixComponent::new(name).unwrap(), &source)
		.expect("recheck the raw name under the moved held root");
	let other_case = UnixComponent::new(b"Raw-\xff\\:name").unwrap();
	assert!(matches!(
		root.recheck_regular_name(other_case, &source),
		Err(ReadError::IdentityChanged)
	));
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
fn rechecks_the_selected_name_without_opening_replacements_for_data() {
	let scratch = Scratch::new();
	let selected = scratch.path("selected");
	let preserved = scratch.path("preserved");
	let unrelated = scratch.path("unrelated");
	fs::write(&selected, b"selected").unwrap();
	fs::write(&unrelated, b"unrelated").unwrap();
	let root = ReadRoot::from_directory(scratch.open()).unwrap();
	let name = UnixComponent::new(b"selected").unwrap();
	let source = root.open_regular(name).unwrap();
	root.recheck_regular_name(name, &source).unwrap();

	fs::rename(&selected, &preserved).unwrap();
	assert!(matches!(
		root.recheck_regular_name(name, &source),
		Err(ReadError::IdentityChanged)
	));

	symlink(&unrelated, &selected).unwrap();
	assert!(matches!(
		root.recheck_regular_name(name, &source),
		Err(ReadError::IdentityChanged)
	));
	fs::remove_file(&selected).unwrap();

	// The FIFO has no peer, so revalidation must never wait on a data open.
	unix::mkfifoat(scratch.open(), "selected", Mode::RUSR | Mode::WUSR).unwrap();
	assert!(matches!(
		root.recheck_regular_name(name, &source),
		Err(ReadError::IdentityChanged)
	));
	assert_eq!(fs::read(preserved).unwrap(), b"selected");
	assert_eq!(fs::read(unrelated).unwrap(), b"unrelated");
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

#[test]
fn read_view_keeps_the_admitted_extent_and_checks_positioned_read_boundaries() {
	let scratch = Scratch::new();
	let path = scratch.path("source");
	fs::write(&path, b"abcdef").expect("create the six-byte fixture");
	let root = ReadRoot::from_directory(scratch.open()).expect("admit the fixture directory");
	let name = UnixComponent::new(b"source").expect("validate the fixture name");
	let source = root.open_regular(name).expect("open the six-byte fixture");

	assert_eq!(ReadView::length(&source), 6);
	ReadView::recheck_observation(&source).expect("confirm stable source and its logical end");
	let mut tail = [0; 2];
	ReadView::read_exact_at(&source, 4, &mut tail).expect("read up to the captured end");
	assert_eq!(&tail, b"ef");
	ReadView::read_exact_at(&source, 6, &mut []).expect("admit an empty read at EOF");
	assert!(matches!(
		ReadView::read_exact_at(&source, 7, &mut []),
		Err(ReadError::RangeOutsideFile)
	));
	assert!(matches!(
		ReadView::read_exact_at(&source, u64::MAX, &mut tail),
		Err(ReadError::RangeOutsideFile)
	));
	assert_eq!(&tail, b"ef", "range refusal leaves the buffer intact");
	ReadView::recheck_observation(&source).expect("confirm source after positioned reads");
	assert_eq!(
		fs::read(&path).expect("read the retained fixture"),
		b"abcdef"
	);
}

#[test]
fn same_inode_with_changed_mode_fails_named_and_read_view_revalidation() {
	let scratch = Scratch::new();
	let path = scratch.path("source");
	fs::write(&path, b"unchanged").expect("create the source fixture");
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
		.expect("set the fixture's initial mode");
	let root = ReadRoot::from_directory(scratch.open()).expect("admit the fixture directory");
	let name = UnixComponent::new(b"source").expect("validate the fixture name");
	let source = root.open_regular(name).expect("open the fixture");
	root.recheck_regular_name(name, &source)
		.expect("validate the initial name and metadata");

	fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
		.expect("simulate a metadata-only change by the fixture owner");
	let current = root.open_regular(name).expect("reopen the same fixture");
	assert_eq!(
		current.identity(),
		source.identity(),
		"the inode is unchanged"
	);
	assert_eq!(current.len(), source.len(), "the extent is unchanged");
	assert!(matches!(
		root.recheck_regular_name(name, &source),
		Err(ReadError::SourceChanged)
	));
	assert!(matches!(
		ReadView::recheck_observation(&source),
		Err(ReadError::SourceChanged)
	));
	assert_eq!(
		fs::read(&path).expect("read the retained fixture"),
		b"unchanged"
	);
}

#[test]
fn read_refusals_without_underlying_errors_have_specific_diagnostics() {
	for (error, expected) in [
		(ReadError::NotDirectory, "read root must be a directory"),
		(ReadError::NotRegularFile, "source must be a regular file"),
		(
			ReadError::UnsupportedProcfs,
			"descriptor reopening requires trusted procfs",
		),
		(
			ReadError::IdentityChanged,
			"reopened file does not match the pinned file",
		),
		(
			ReadError::InvalidLength,
			"file length exceeds the supported range",
		),
		(
			ReadError::InvalidTimestamp,
			"source has an invalid timestamp",
		),
		(
			ReadError::SourceChanged,
			"source metadata changed after open",
		),
		(
			ReadError::UnexpectedDataAfterEnd,
			"source returned data beyond its recorded length",
		),
		(
			ReadError::ExtendedAttributeListTooLarge,
			"source extended-attribute name list exceeds the Linux limit",
		),
		(
			ReadError::RangeOutsideFile,
			"read range exceeds the recorded file length",
		),
	] {
		assert_eq!(error.to_string(), expected);
		assert!(
			error.source().is_none(),
			"{error:?} has no underlying cause"
		);
	}
}

#[test]
fn read_error_diagnostics_preserve_typed_causes() {
	let error = ReadError::Io(IoError::UnexpectedEof { offset: 4 });
	assert_eq!(
		error.to_string(),
		"source read failed (unexpected end of file at offset 4)"
	);
	assert!(matches!(
		error
			.source()
			.and_then(|cause| cause.downcast_ref::<IoError>()),
		Some(IoError::UnexpectedEof { offset: 4 })
	));

	let denied = Errno::ACCESS.raw_os_error();
	for (error, diagnostic) in [
		(
			ReadError::ExtendedAttributesUnreadable(io::Error::from_raw_os_error(denied)),
			"source extended-attribute inspection failed (",
		),
		(
			ReadError::System(io::Error::from_raw_os_error(denied)),
			"source descriptor operation failed (",
		),
	] {
		assert!(error.to_string().starts_with(diagnostic), "{error:?}");
		let cause = error
			.source()
			.and_then(|cause| cause.downcast_ref::<io::Error>())
			.expect("retain the native I/O cause");
		assert_eq!(cause.raw_os_error(), Some(denied));
	}
}
