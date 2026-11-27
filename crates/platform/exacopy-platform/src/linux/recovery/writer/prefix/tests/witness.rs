use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;

use super::{Fixture, PREFIX, ReadView, fs, inventory, selection};
use crate::linux::{
	ProtectedWitnessEffect, ProtectedWitnessError, StageError, WitnessCredentialLane,
};

const WITNESS: [u8; 40] = *b"witness.0102030405060708090a0b0c0d0e0f10";

#[test]
#[ignore = "requires a task-owned unprivileged Linux same-credential link fixture"]
fn actual_descriptor_link_keeps_both_names_and_held_exclusion() {
	let fixture = Fixture::new();
	let path = fixture
		.stage()
		.ancestors()
		.nth(2)
		.unwrap()
		.join(OsStr::from_bytes(&WITNESS));
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let selected = selection(&inventory);
	let reader = lease.read_retained_prefix(&inventory, selected).unwrap();
	let stage = reader
		.sync_adopted(PREFIX.len() as u64, |_, _| Ok::<_, ()>(()))
		.unwrap()
		.zero_tail_for_witness(
			PREFIX.len() as u64,
			WitnessCredentialLane::observe().unwrap(),
			|_, _| Ok::<_, ()>(()),
		)
		.unwrap();
	let mut effects = Vec::new();
	let linked = stage
		.link_checked_witness(WITNESS, |effect| {
			effects.push(effect);
			Ok::<_, ProtectedWitnessError<()>>(())
		})
		.unwrap();
	assert_eq!(
		effects,
		[
			ProtectedWitnessEffect::Link,
			ProtectedWitnessEffect::FileBarrier,
			ProtectedWitnessEffect::JobBarrier,
		]
	);
	assert_eq!(fs::read(&path).unwrap(), PREFIX);
	assert_eq!(fs::metadata(&path).unwrap().ino(), selected.file.inode);
	assert_eq!(fs::metadata(fixture.stage()).unwrap().nlink(), 2);
	assert!(!fixture.target().exists());
	// V1 retains its single-link constraint.
	assert!(
		lease
			.job()
			.inventory(selected.stage, selected.target)
			.is_err()
	);
	let metadata = linked.observe_barriered_metadata().unwrap();
	assert_eq!(metadata.mode(), 0o600);
	assert_eq!(metadata.owner(), rustix::process::geteuid().as_raw());
	assert_eq!(metadata.group(), rustix::process::getegid().as_raw());
	assert_eq!(metadata.len(), PREFIX.len() as u64);
	assert_eq!(metadata.link_count(), 2);
	let mut bytes = [0; PREFIX.len()];
	linked.read_exact_at(0, &mut bytes).unwrap();
	assert_eq!(bytes, PREFIX);
	assert!(matches!(
		lease.reopen_stage_directory(&inventory),
		Err(StageError::JobBusy)
	));
	fs::remove_file(&path).unwrap();
	assert!(linked.observe_barriered_metadata().is_err());
}

#[test]
#[ignore = "requires a task-owned unprivileged Linux same-credential link fixture"]
fn occupied_slot_or_refused_later_barrier_never_removes_evidence() {
	for occupied in [true, false] {
		let fixture = Fixture::new();
		let path = fixture
			.stage()
			.ancestors()
			.nth(2)
			.unwrap()
			.join(OsStr::from_bytes(&WITNESS));
		let lease = fixture.lease();
		let inventory = inventory(&lease);
		let reader = lease
			.read_retained_prefix(&inventory, selection(&inventory))
			.unwrap();
		let stage = reader
			.sync_adopted(PREFIX.len() as u64, |_, _| Ok::<_, ()>(()))
			.unwrap()
			.zero_tail_for_witness(
				PREFIX.len() as u64,
				WitnessCredentialLane::observe().unwrap(),
				|_, _| Ok::<_, ()>(()),
			)
			.unwrap();
		if occupied {
			fs::write(&path, b"incumbent").unwrap();
		}
		let mut effects = Vec::new();
		let result = stage.link_checked_witness(WITNESS, |actual| {
			effects.push(actual);
			if actual == ProtectedWitnessEffect::FileBarrier {
				Err(ProtectedWitnessError::BarrierAdmission(17))
			} else {
				Ok(())
			}
		});
		if occupied {
			assert!(matches!(
				result,
				Err(ProtectedWitnessError::Preflight(
					StageError::IdentityChanged
				))
			));
			assert!(effects.is_empty());
			assert_eq!(fs::read(&path).unwrap(), b"incumbent");
			assert_eq!(fs::metadata(fixture.stage()).unwrap().nlink(), 1);
		} else {
			assert!(matches!(
				result,
				Err(ProtectedWitnessError::BarrierAdmission(17))
			));
			assert_eq!(
				effects,
				[
					ProtectedWitnessEffect::Link,
					ProtectedWitnessEffect::FileBarrier
				]
			);
			assert_eq!(fs::read(&path).unwrap(), PREFIX);
			assert_eq!(fs::metadata(fixture.stage()).unwrap().nlink(), 2);
		}
		assert!(!fixture.target().exists());
	}
}

#[test]
#[ignore = "requires a task-owned unprivileged Linux same-credential link fixture"]
fn witnessed_native_rename_observes_success_conflict_and_nonregular_incumbent() {
	use crate::linux::{PublishError, WitnessPublicationName, WitnessPublicationObservation};

	for incumbent in [None, Some(false), Some(true)] {
		let fixture = Fixture::new();
		let witness = fixture
			.stage()
			.ancestors()
			.nth(2)
			.unwrap()
			.join(OsStr::from_bytes(&WITNESS));
		let lease = fixture.lease();
		let inventory = inventory(&lease);
		let selected = selection(&inventory);
		let reader = lease.read_retained_prefix(&inventory, selected).unwrap();
		let candidate = reader
			.sync_adopted(PREFIX.len() as u64, |_, _| Ok::<_, ()>(()))
			.unwrap()
			.zero_tail_for_witness(
				PREFIX.len() as u64,
				WitnessCredentialLane::observe().unwrap(),
				|_, _| Ok::<_, ()>(()),
			)
			.unwrap();
		let linked = candidate
			.link_checked_witness(WITNESS, |_| Ok::<_, ProtectedWitnessError<()>>(()))
			.unwrap();
		// Standalone native control. The application-owned kind-7/model gate is
		// deliberately outside this low-level fixture.
		let rename = linked.prepare_rename().unwrap();
		match incumbent {
			Some(false) => fs::write(fixture.target(), b"incumbent").unwrap(),
			Some(true) => fs::create_dir(fixture.target()).unwrap(),
			None => {}
		}
		let observation = rename.submit(());
		assert_eq!(fs::read(&witness).unwrap(), PREFIX);
		assert_eq!(fs::metadata(&witness).unwrap().ino(), selected.file.inode);
		match (incumbent, observation) {
			(None, WitnessPublicationObservation::Published(stamp)) => {
				assert!(!fixture.stage().exists());
				assert_eq!(fs::read(fixture.target()).unwrap(), PREFIX);
				assert_eq!(stamp.identity().inode(), selected.file.inode);
				assert_eq!(stamp.link_count(), 2);
			}
			(Some(false), WitnessPublicationObservation::Conflict(stamp)) => {
				assert_ne!(stamp.identity().inode(), selected.file.inode);
				assert_eq!(fs::read(fixture.target()).unwrap(), b"incumbent");
				assert_eq!(fs::read(fixture.stage()).unwrap(), PREFIX);
			}
			(
				Some(true),
				WitnessPublicationObservation::Reconcile {
					submission: Err(PublishError::Conflict),
					names,
					..
				},
			) => {
				assert_eq!(names.public_target, WitnessPublicationName::Unobserved);
				assert!(fixture.target().is_dir());
				assert_eq!(fs::read(fixture.stage()).unwrap(), PREFIX);
			}
			(_, unexpected) => panic!("unexpected native rename observation: {unexpected:?}"),
		}
	}
}
