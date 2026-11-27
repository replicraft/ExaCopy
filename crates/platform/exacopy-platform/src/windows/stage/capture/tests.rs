use std::fs::{self, OpenOptions};
use std::io::Seek;
use std::os::windows::fs::FileExt;

use super::super::tests::{Fixture, component};
use super::*;

#[test]
#[ignore = "requires a provisioned native local NTFS stage fixture"]
fn capture_syncs_exact_prefix_and_reads_two_independent_views() {
	let fixture = Fixture::new();
	let parent = fixture.open();
	let root = WindowsStageDirectory::from_authorized_handle(parent.as_handle()).unwrap();
	let name: Vec<_> = "capture".encode_utf16().collect();
	let mut writer = root.create(component(&name), 6).unwrap();
	let original = writer.identity();

	assert_eq!(writer.unwritten_length().unwrap(), 6);
	assert!(matches!(
		writer.sync_written_prefix(0),
		Err(WindowsStageError::InvalidRange)
	));
	let mut writes = [
		(0, b"abc".as_slice(), Ok(())),
		(1, b"bc".as_slice(), Err(io::ErrorKind::Interrupted)),
		(1, b"bc".as_slice(), Ok(())),
		(2, b"c".as_slice(), Ok(())),
	]
	.into_iter();
	writer
		.write_with(0, b"abc", |file, offset, remaining| {
			let (expected_offset, expected_suffix, result) = writes
				.next()
				.expect("unexpected write after the whole prefix");
			assert_eq!(offset, expected_offset);
			assert_eq!(remaining, expected_suffix);
			result?;
			file.seek_write(&remaining[..1], offset)
		})
		.unwrap();
	assert!(
		writes.next().is_none(),
		"the full short-write script must run"
	);
	assert!(matches!(
		writer.sync_written_prefix(2),
		Err(WindowsStageError::InvalidRange)
	));
	let first = writer.sync_written_prefix(3).unwrap();
	assert_eq!(first.parent(), root.identity);
	assert_eq!(first.stage(), original);
	assert_eq!(first.end(), 3);
	writer.write_next(b"def").unwrap();
	let second = writer.sync_written_prefix(6).unwrap();
	assert_eq!(second.stage(), original);
	assert_eq!(second.end(), 6);
	eprintln!("ntfs-capture prefix_observations={first:?},{second:?}");
	let closed = writer.sync_and_close().unwrap();
	assert_eq!(closed.identity(), original);

	let original_cursor = (&closed.observation.file).stream_position().unwrap();
	let first = closed.open_read_back().unwrap();
	let second = closed.open_read_back().unwrap();
	let mut output = [0; 3];
	first.read_exact_at(3, &mut output).unwrap();
	assert_eq!(&output, b"def");
	second.read_exact_at(0, &mut output).unwrap();
	assert_eq!(&output, b"abc");
	assert!(matches!(
		first.read_exact_at(4, &mut output),
		Err(WindowsStageError::InvalidRange)
	));
	second.recheck_observation().unwrap();
	assert_eq!(
		(&closed.observation.file).stream_position().unwrap(),
		original_cursor
	);
	eprintln!(
		"ntfs-capture held_parent={:?} closed_stage={:?} unchanged_pin_cursor={original_cursor}",
		root.identity,
		closed.identity(),
	);

	let empty_name: Vec<_> = "empty".encode_utf16().collect();
	let empty = root
		.create(component(&empty_name), 0)
		.unwrap()
		.sync_and_close()
		.unwrap();
	let view = empty.open_read_back().unwrap();
	assert_eq!(view.length(), 0);
	view.read_exact_at(0, &mut []).unwrap();
	view.recheck_observation().unwrap();
}

#[test]
#[ignore = "requires a provisioned native local NTFS stage fixture"]
fn failed_prefix_barrier_retires_writer_and_preserves_bytes_for_inspection() {
	let fixture = Fixture::new();
	let parent = fixture.open();
	let root = WindowsStageDirectory::from_authorized_handle(parent.as_handle()).unwrap();
	let name: Vec<_> = "failed-prefix".encode_utf16().collect();
	let mut writer = root.create(component(&name), 6).unwrap();
	let original = writer.identity();
	writer.write_next(b"abc").unwrap();
	let failure = writer.sync_prefix_with(3, |_| Err(io::Error::other("fixture flush failure")));
	assert!(matches!(failure, Err(WindowsStageError::Barrier(_))));
	assert!(matches!(
		writer.sync_written_prefix(3),
		Err(WindowsStageError::WriterRetired)
	));
	assert!(matches!(
		writer.write_next(b"def"),
		Err(WindowsStageError::WriterRetired)
	));
	assert!(matches!(
		writer.sync_and_close(),
		Err(WindowsStageError::WriterRetired)
	));

	let retained = root
		.inspect_retained(component(&name), original, 3)
		.unwrap();
	let mut output = [0; 3];
	retained.read_exact_at(0, &mut output).unwrap();
	assert_eq!(&output, b"abc");
}

#[test]
#[ignore = "requires a provisioned native local NTFS stage fixture"]
fn retained_checks_exact_name_identity_extent_and_denies_writer_sharing() {
	let fixture = Fixture::new();
	let parent = fixture.open();
	let root = WindowsStageDirectory::from_authorized_handle(parent.as_handle()).unwrap();
	let name: Vec<_> = "retained".encode_utf16().collect();
	let mut writer = root.create(component(&name), 3).unwrap();
	let original = writer.identity();
	writer.write_next(b"abc").unwrap();
	assert!(
		root.inspect_retained(component(&name), original, 3)
			.is_err()
	);
	drop(writer.sync_and_close().unwrap());

	let case_alias: Vec<_> = "RETAINED".encode_utf16().collect();
	assert!(
		root.inspect_retained(component(&case_alias), original, 3)
			.is_err()
	);
	assert!(
		root.inspect_retained(component(&name), original, 2)
			.is_err()
	);
	let other_name: Vec<_> = "other".encode_utf16().collect();
	let other = root.create(component(&other_name), 0).unwrap();
	assert!(
		root.inspect_retained(component(&name), other.identity(), 3)
			.is_err()
	);

	let retained = root
		.inspect_retained(component(&name), original, 3)
		.unwrap();
	let stage_path = fixture.0.join("retained");
	let moved_path = fixture.0.join("retained-moved");
	assert!(OpenOptions::new().write(true).open(&stage_path).is_err());
	assert!(fs::rename(&stage_path, &moved_path).is_err());
	retained.recheck_observation().unwrap();
	eprintln!(
		"ntfs-inspection held_parent={:?} retained_stage={:?} exact_extent={} write_open_and_rename_refused=true",
		root.identity,
		retained.identity(),
		retained.length(),
	);
	drop(retained);
	let hard_link = fixture.0.join("hard-link");
	fs::hard_link(&stage_path, &hard_link).unwrap();
	assert!(matches!(
		root.inspect_retained(component(&name), original, 3),
		Err(WindowsStageError::Changed)
	));
	assert_eq!(fs::read(&hard_link).unwrap(), b"abc");
	fs::remove_file(hard_link).unwrap();
	fs::rename(&stage_path, &moved_path).unwrap();
	fs::write(&stage_path, b"xyz").unwrap();
	assert!(
		root.inspect_retained(component(&name), original, 3)
			.is_err()
	);
	assert_eq!(fs::read(moved_path).unwrap(), b"abc");
	assert_eq!(fs::read(stage_path).unwrap(), b"xyz");
}

#[test]
#[ignore = "requires a provisioned native local NTFS stage fixture"]
fn retained_refuses_unsupported_file_attributes() {
	let fixture = Fixture::new();
	let parent = fixture.open();
	let root = WindowsStageDirectory::from_authorized_handle(parent.as_handle()).unwrap();
	let name: Vec<_> = "attributes".encode_utf16().collect();
	let writer = root.create(component(&name), 0).unwrap();
	let original = writer.identity();
	drop(writer.sync_and_close().unwrap());

	let path = fixture.0.join("attributes");
	let original_permissions = fs::metadata(&path).unwrap().permissions();
	let mut readonly = original_permissions.clone();
	readonly.set_readonly(true);
	fs::set_permissions(&path, readonly).unwrap();
	let rejected = root.inspect_retained(component(&name), original, 0);
	fs::set_permissions(&path, original_permissions).unwrap();
	assert!(matches!(rejected, Err(WindowsStageError::Changed)));
	root.inspect_retained(component(&name), original, 0)
		.unwrap();
}

#[test]
#[ignore = "requires a provisioned native local NTFS stage fixture"]
fn prefix_postflush_extent_change_retires_writer_without_reset() {
	let fixture = Fixture::new();
	let parent = fixture.open();
	let root = WindowsStageDirectory::from_authorized_handle(parent.as_handle()).unwrap();
	let name: Vec<_> = "changed-prefix".encode_utf16().collect();
	let mut writer = root.create(component(&name), 6).unwrap();
	writer.write_next(b"abc").unwrap();

	let failure = writer.sync_prefix_with(3, |file| {
		file.set_len(4)?;
		file.sync_all()
	});
	assert!(matches!(failure, Err(WindowsStageError::Changed)));
	assert!(matches!(
		writer.write_next(b"def"),
		Err(WindowsStageError::WriterRetired)
	));
	let retained = fs::read(fixture.0.join("changed-prefix")).unwrap();
	assert_eq!(retained.len(), 4);
	assert_eq!(&retained[..3], b"abc");
}

#[test]
#[ignore = "requires native local NTFS and permission to create a file symbolic link"]
fn capture_symlink_cannot_select_the_referent_identity() {
	use std::os::windows::fs::symlink_file;

	let fixture = Fixture::new();
	let parent = fixture.open();
	let root = WindowsStageDirectory::from_authorized_handle(parent.as_handle()).unwrap();
	let name: Vec<_> = "original".encode_utf16().collect();
	let mut writer = root.create(component(&name), 3).unwrap();
	writer.write_next(b"abc").unwrap();
	let identity = writer.identity();
	drop(writer.sync_and_close().unwrap());

	let original = fixture.0.join("original");
	let link = fixture.0.join("alias");
	symlink_file(&original, &link).unwrap();
	let alias: Vec<_> = "alias".encode_utf16().collect();
	assert!(
		root.inspect_retained(component(&alias), identity, 3)
			.is_err()
	);
	assert_eq!(fs::read_link(link).unwrap(), original);
	assert_eq!(fs::read(&original).unwrap(), b"abc");
}
