//! Direct observations of simulator capabilities, transfers, and barriers.

use std::io::ErrorKind;

use exacopy_endpoint::{IoError, UnixComponent, read_exact_at, write_all_at};
use exacopy_testkit::{
	Area, DiskId, EffectError, EffectFault, EffectOperation, Entry, Failure, FileView, Rejection,
	Simulator, Snapshot, TransferFault, TransferOperation, WritableArea,
};

fn component(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).expect("valid fixture component")
}

fn file<'a>(snapshot: &'a Snapshot, area: Area, name: &UnixComponent<'_>) -> FileView<'a> {
	match snapshot.entry(area, name) {
		Some(Entry::File(file)) => file,
		result => panic!("expected a file at {area:?} {name:?}, observed {result:?}"),
	}
}

#[test]
fn raw_names_and_symlinks_are_distinct_and_source_aliases_survive() {
	let mut storage = Simulator::new(DiskId::new(1));
	let source = component(b"\xffsource");
	let stage = component(b"stage");
	let link = component(b"link");
	let identity = storage.seed_file(Area::Source, &source, b"source").unwrap();
	storage.seed_source_alias(&source, &source).unwrap();
	storage.seed_symlink(Area::Source, &link).unwrap();
	storage.seed_symlink(Area::Destination, &link).unwrap();
	assert!(matches!(
		storage.open_source(&link),
		Err(Rejection::NotAFile)
	));
	assert!(matches!(
		storage.open_source(&stage),
		Err(Rejection::Missing)
	));

	for target in [&source, &link] {
		let writer = storage.create_stage(&stage, target).unwrap();
		assert!(matches!(
			storage.create_stage(&stage, &stage),
			Err(EffectError::Rejected(Rejection::Conflict))
		));
		assert_eq!(
			storage.publish_no_clobber(writer.quiesce()),
			Err(EffectError::Rejected(Rejection::Conflict))
		);
		assert_eq!(
			storage.live_snapshot().entry(Area::Destination, &link),
			Some(Entry::Symlink)
		);
		assert_eq!(
			file(&storage.live_snapshot(), Area::Destination, &source),
			FileView {
				identity,
				bytes: b"source"
			}
		);
		storage.lose_volatile_state();
	}
}

#[test]
fn a_rebound_stage_cannot_be_reopened_or_published_using_its_old_identity() {
	let mut storage = Simulator::new(DiskId::new(1));
	let stage_name = component(b"stage");
	let target = component(b"target");
	let writer = storage.create_stage(&stage_name, &target).unwrap();
	let original = writer.identity();
	let replacement = storage.rebind_stage(&stage_name, b"other owner").unwrap();
	assert_ne!(original, replacement);
	// The already-open descriptor still names the original object.
	assert_eq!(storage.write_at(&writer, 0, b"owned").unwrap(), 5);
	let stage = writer.quiesce();
	assert!(matches!(
		storage.open_quiesced(&stage),
		Err(Rejection::StageRebound)
	));
	assert_eq!(
		storage.publish_no_clobber(stage),
		Err(EffectError::Rejected(Rejection::StageRebound))
	);
	let observed = storage.live_snapshot();
	assert_eq!(observed.entry(Area::Destination, &target), None);
	assert_eq!(
		file(&observed, Area::Private, &stage_name),
		FileView {
			identity: replacement,
			bytes: b"other owner",
		}
	);
}

#[test]
fn crash_and_wrong_disk_revoke_handles_while_preserving_persisted_identity() {
	let mut storage = Simulator::new(DiskId::new(1));
	let mut other_disk = Simulator::new(DiskId::new(2));
	let source = component(b"source");
	let stage_name = component(b"stage");
	let id = storage
		.seed_file(Area::Source, &source, b"source bytes")
		.unwrap();
	let other_id = other_disk
		.seed_file(Area::Source, &source, b"other bytes")
		.unwrap();
	assert_ne!(id, other_id);
	let reader = storage.open_source(&source).unwrap();
	let writer = storage.create_stage(&stage_name, &stage_name).unwrap();
	assert_eq!(
		other_disk.read_at(&reader, 0, &mut [0]).unwrap_err().kind(),
		ErrorKind::InvalidInput,
	);
	assert_eq!(
		other_disk
			.write_at(&writer, 0, b"wrong disk")
			.unwrap_err()
			.kind(),
		ErrorKind::InvalidInput,
	);

	let before = storage.live_snapshot();
	storage
		.inject_transfer(TransferOperation::Read, TransferFault::Interrupted)
		.unwrap();
	storage.process_crash();
	assert_eq!(storage.live_snapshot(), before);
	assert_eq!(
		storage.read_at(&reader, 0, &mut [0]).unwrap_err().kind(),
		ErrorKind::InvalidInput,
	);
	assert_eq!(
		storage.write_at(&writer, 0, b"stale").unwrap_err().kind(),
		ErrorKind::InvalidInput,
	);
	assert_eq!(
		storage.publish_no_clobber(writer.quiesce()),
		Err(EffectError::Rejected(Rejection::StaleHandle))
	);
	let current = storage.open_source(&source).unwrap();
	let mut first = [0];
	assert_eq!(storage.read_at(&current, 0, &mut first).unwrap(), 1);
	assert_eq!(&first, b"s");
	assert_eq!(
		file(&storage.live_snapshot(), Area::Source, &source).identity,
		id
	);
}

#[test]
fn short_transfers_and_interrupted_calls_advance_only_by_acknowledged_progress() {
	let mut storage = Simulator::new(DiskId::new(1));
	let source = component(b"source");
	let stage_name = component(b"stage");
	let original = b"prefix\xff\x00abc";
	storage.seed_file(Area::Source, &source, original).unwrap();
	let reader = storage.open_source(&source).unwrap();
	for direction in [TransferOperation::Read, TransferOperation::Write] {
		for fault in [
			TransferFault::Interrupted,
			TransferFault::Short(1),
			TransferFault::Interrupted,
			TransferFault::Short(2),
		] {
			storage.inject_transfer(direction, fault).unwrap();
		}
	}
	let mut copied = [0; 5];
	read_exact_at(6, &mut copied, |offset, buffer| {
		storage.read_at(&reader, offset, buffer)
	})
	.unwrap();
	assert_eq!(copied, *b"\xff\x00abc");
	let writer = storage.create_stage(&stage_name, &stage_name).unwrap();
	write_all_at(2, &copied, |offset, buffer| {
		storage.write_at(&writer, offset, buffer)
	})
	.unwrap();
	let stage = writer.quiesce();
	let reader = storage.open_quiesced(&stage).unwrap();
	assert_eq!(reader.identity(), stage.identity());
	let mut readback = [0; 7];
	read_exact_at(0, &mut readback, |offset, buffer| {
		storage.read_at(&reader, offset, buffer)
	})
	.unwrap();
	assert_eq!(readback, *b"\x00\x00\xff\x00abc");
	assert_eq!(
		file(&storage.live_snapshot(), Area::Source, &source).bytes,
		original
	);
}

#[test]
fn a_zero_transfer_is_not_success_and_error_after_effect_preserves_only_transferred_bytes() {
	let mut storage = Simulator::new(DiskId::new(1));
	let source = component(b"source");
	let stage = component(b"stage");
	storage.seed_file(Area::Source, &source, b"abcdef").unwrap();
	let reader = storage.open_source(&source).unwrap();
	let writer = storage.create_stage(&stage, &stage).unwrap();

	storage
		.inject_transfer(TransferOperation::Read, TransferFault::Short(0))
		.unwrap();
	let mut read = [9; 4];
	assert!(matches!(
		read_exact_at(1, &mut read, |offset, buffer| storage
			.read_at(&reader, offset, buffer)),
		Err(IoError::UnexpectedEof { offset: 1 }),
	));
	assert_eq!(read, [9; 4]);
	storage
		.inject_transfer(
			TransferOperation::Read,
			TransferFault::After {
				bytes: 2,
				failure: Failure::Io,
			},
		)
		.unwrap();
	assert!(matches!(
		read_exact_at(1, &mut read, |offset, buffer| storage
			.read_at(&reader, offset, buffer)),
		Err(IoError::System { offset: 1, .. }),
	));
	assert_eq!(read, [b'b', b'c', 9, 9]);

	storage
		.inject_transfer(TransferOperation::Write, TransferFault::Short(0))
		.unwrap();
	assert!(matches!(
		write_all_at(3, b"abcd", |offset, buffer| storage
			.write_at(&writer, offset, buffer)),
		Err(IoError::WriteZero { offset: 3 }),
	));
	assert_eq!(
		file(&storage.live_snapshot(), Area::Private, &stage).bytes,
		b""
	);

	storage
		.inject_transfer(TransferOperation::Write, TransferFault::Short(1))
		.unwrap();
	storage
		.inject_transfer(
			TransferOperation::Write,
			TransferFault::After {
				bytes: 2,
				failure: Failure::NoSpace,
			},
		)
		.unwrap();
	assert!(matches!(
		write_all_at(1, b"abcd", |offset, buffer| storage.write_at(&writer, offset, buffer)),
		Err(IoError::System { offset: 2, source }) if source.kind() == ErrorKind::StorageFull,
	));
	assert_eq!(
		file(&storage.live_snapshot(), Area::Private, &stage).bytes,
		b"\0abc"
	);
}

#[test]
fn file_and_directory_barriers_preserve_different_state() {
	for (file_barrier, directory_barrier) in
		[(false, false), (false, true), (true, false), (true, true)]
	{
		let mut storage = Simulator::new(DiskId::new(1));
		let stage_name = component(b"stage");
		let writer = storage.create_stage(&stage_name, &stage_name).unwrap();
		let identity = writer.identity();
		storage.write_at(&writer, 0, b"data").unwrap();
		let stage = writer.quiesce();
		if file_barrier {
			storage.flush_file(&stage).unwrap();
		}
		if directory_barrier {
			storage.flush_directory(WritableArea::Private).unwrap();
		}
		storage.process_crash();
		assert_eq!(
			file(&storage.live_snapshot(), Area::Private, &stage_name).bytes,
			b"data"
		);
		storage.lose_volatile_state();
		let after = storage.live_snapshot();
		let expected = directory_barrier.then_some(Entry::File(FileView {
			identity,
			bytes: if file_barrier { b"data" } else { b"" },
		}));
		assert_eq!(after.entry(Area::Private, &stage_name), expected);
		assert_eq!(after, storage.stable_snapshot());
	}
}

#[test]
fn cross_directory_removal_and_arrival_persist_independently() {
	for (private, destination) in [(false, false), (false, true), (true, false), (true, true)] {
		let mut storage = Simulator::new(DiskId::new(1));
		let stage_name = component(b"stage");
		let target_name = component(b"target");
		let writer = storage.create_stage(&stage_name, &target_name).unwrap();
		let identity = writer.identity();
		storage.write_at(&writer, 0, b"copy").unwrap();
		let stage = writer.quiesce();
		storage.flush_file(&stage).unwrap();
		storage.flush_directory(WritableArea::Private).unwrap();
		storage.publish_no_clobber(stage).unwrap();
		if private {
			storage.flush_directory(WritableArea::Private).unwrap();
		}
		if destination {
			storage.flush_directory(WritableArea::Destination).unwrap();
		}
		storage.process_crash();
		let observed = storage.live_snapshot();
		assert_eq!(observed.entry(Area::Private, &stage_name), None);
		let valid = Entry::File(FileView {
			identity,
			bytes: b"copy",
		});
		assert_eq!(observed.entry(Area::Destination, &target_name), Some(valid));
		storage.lose_volatile_state();
		let survivor = storage.live_snapshot();
		assert_eq!(
			survivor.entry(Area::Private, &stage_name),
			(!private).then_some(valid)
		);
		assert_eq!(
			survivor.entry(Area::Destination, &target_name),
			destination.then_some(valid)
		);
	}
}

#[test]
fn losing_create_result_leaves_an_unowned_name_instead_of_returning_a_write_handle() {
	let stage = component(b"stage");
	for (fault, outcome, created) in [
		(
			EffectFault::Before(Failure::NoSpace),
			EffectError::Failed(Failure::NoSpace),
			false,
		),
		(
			EffectFault::After(Failure::Io),
			EffectError::Unknown(Failure::Io),
			true,
		),
	] {
		let mut storage = Simulator::new(DiskId::new(1));
		storage
			.inject_effect(EffectOperation::Create, fault)
			.unwrap();
		assert_eq!(storage.create_stage(&stage, &stage).unwrap_err(), outcome);
		assert_eq!(
			storage
				.live_snapshot()
				.entry(Area::Private, &stage)
				.is_some(),
			created
		);
		assert_eq!(storage.stable_snapshot().entry(Area::Private, &stage), None);
		if created {
			assert!(matches!(
				storage.create_stage(&stage, &stage),
				Err(EffectError::Rejected(Rejection::Conflict))
			));
		}
		storage.lose_volatile_state();
		assert_eq!(storage.live_snapshot().entry(Area::Private, &stage), None);
	}
}

#[test]
fn fixture_limits_fail_without_materializing_unbounded_offsets_or_state() {
	let mut storage = Simulator::new(DiskId::new(1));
	let stage = component(b"stage");
	let writer = storage.create_stage(&stage, &stage).unwrap();
	let before = storage.live_snapshot();
	assert_eq!(
		storage
			.write_at(&writer, u64::MAX, b"x")
			.unwrap_err()
			.kind(),
		ErrorKind::FileTooLarge,
	);
	assert_eq!(storage.live_snapshot(), before);
	for number in 0..63 {
		let name = format!("{number:02}");
		storage
			.seed_file(Area::Source, &component(name.as_bytes()), b"x")
			.unwrap();
	}
	assert_eq!(
		storage.seed_file(Area::Source, &stage, b"x"),
		Err(Rejection::Limit)
	);
	for _ in 0..64 {
		storage
			.inject_transfer(TransferOperation::Read, TransferFault::Pass)
			.unwrap();
	}
	assert_eq!(
		storage.inject_transfer(TransferOperation::Read, TransferFault::Pass),
		Err(Rejection::Limit),
	);
}
