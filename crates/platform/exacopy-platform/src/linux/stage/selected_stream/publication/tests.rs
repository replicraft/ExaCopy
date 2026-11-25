use std::cell::Cell;
use std::fs::{self, FileTimes};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use exacopy_endpoint::linux_remote_qualification::RemoteDestinationQualification;
use exacopy_model::{CopyEffect, CopyEvent, CopySession, EntryId, JobId, RunEpoch, StageId};
use rustix::io::Errno;

use super::*;
use crate::linux::{DestinationRoot, observe_remote_destination};
use crate::scratch::Scratch;

const JOB: &str = "publication-job";
const STAGE: &str = "publication-stage";
const TARGET: &str = "publication-target";
const PAYLOAD: &[u8] = b"independently verified bytes";
const QUALIFICATION: [u8; 32] = [0xa5; 32];
const AUTHORITY: SelectedStreamPublicationAuthority = SelectedStreamPublicationAuthority {
	owner: [1; 32],
	scope: [2; 32],
	grant: [3; 32],
	qualification: QUALIFICATION,
	intent_digest: [4; 32],
	intent_sequence: NonZeroU64::MIN,
};

#[derive(Debug, Eq, PartialEq)]
enum GateFailure {
	Expired,
	Revoked,
}

struct FixtureGrantGuard<'grant> {
	_held: MutexGuard<'grant, SelectedStreamPublicationAuthority>,
	target: PathBuf,
}

impl Drop for FixtureGrantGuard<'_> {
	fn drop(&mut self) {
		assert!(
			self.target.exists(),
			"the held gate outlives the native rename"
		);
	}
}

#[test]
#[ignore = "requires native Linux and a disposable writable ext4 TMPDIR"]
fn publish_confirms_original_inode_and_releases_gate_before_both_real_barriers() {
	with_fresh(|scratch, root, ready| {
		let qualification = projection(root);
		let eligible = RemoteDestinationEligibility::admit(root, Some(&qualification)).unwrap();
		let expected = ready.observed();
		let grant = Mutex::new(AUTHORITY);
		let barriers = Cell::new(0);
		let synced = Cell::new(false);
		let result = ready
			.publish_with_barriers(
				&eligible,
				AUTHORITY,
				authorization(binding(1)),
				|request| {
					assert!(synced.get());
					assert_eq!(request.authority, AUTHORITY);
					assert_eq!(request.location.stage, expected.stage());
					assert_eq!(request.location.directory, expected.stage_directory());
					assert_eq!(request.location.destination, root.identity());
					assert_eq!(request.location.binding, binding(1));
					assert_eq!(request.location.names.stage, component(STAGE));
					assert_eq!(request.location.names.target, component(TARGET));
					assert!(!scratch.path(TARGET).exists());
					let held = grant.lock().unwrap();
					assert_eq!(*held, request.authority);
					Ok::<_, GateFailure>(FixtureGrantGuard {
						_held: held,
						target: scratch.path(TARGET),
					})
				},
				|file| {
					rustix::fs::fsync(file)?;
					synced.set(true);
					Ok(())
				},
				|directory| {
					assert!(grant.try_lock().is_ok(), "guard released after the rename");
					assert!(scratch.path(TARGET).exists());
					barriers.set(barriers.get() + 1);
					rustix::fs::fsync(directory)
				},
			)
			.unwrap();
		assert_eq!(barriers.get(), 2);
		assert_eq!(result.target(), expected.stage());
		assert_eq!(result.stage_directory(), expected.stage_directory());
		assert_eq!(result.destination(), expected.destination());
		assert_eq!(fs::read(scratch.path(TARGET)).unwrap(), PAYLOAD);
		assert!(!scratch.path(JOB).join("stage").join(STAGE).exists());
	});
}

#[test]
#[ignore = "requires native Linux and a disposable writable ext4 TMPDIR"]
fn qualification_binding_and_final_grant_refuse_before_rename() {
	for case in 0..4 {
		with_fresh(|scratch, root, ready| {
			let second = DestinationRoot::from_directory(scratch.open()).unwrap();
			let held = if case == 1 { &second } else { root };
			let qualification = projection(held);
			let eligible = RemoteDestinationEligibility::admit(held, Some(&qualification)).unwrap();
			let authority = if case == 0 {
				SelectedStreamPublicationAuthority {
					qualification: [0x9b; 32],
					..AUTHORITY
				}
			} else {
				AUTHORITY
			};
			let model = binding(if case == 2 { 2 } else { 1 });
			let gate = Mutex::new(GateFailure::Expired);
			let result =
				ready.publish_no_clobber(&eligible, authority, authorization(model), |_| {
					assert_eq!(case, 3, "no grant gate before native admission");
					let guard = gate.lock().unwrap();
					assert_eq!(*guard, GateFailure::Expired);
					Err::<std::sync::MutexGuard<'_, GateFailure>, _>(GateFailure::Expired)
				});
			match case {
				0 => assert!(matches!(
					result,
					Err(SelectedStreamPublishError::QualificationMismatch)
				)),
				1 => assert!(matches!(
					result,
					Err(SelectedStreamPublishError::Eligibility(
						RemoteDestinationEligibilityError::DifferentRoot
					))
				)),
				2 => assert!(matches!(
					result,
					Err(SelectedStreamPublishError::Native(
						PublishError::BindingMismatch
					))
				)),
				_ => assert!(matches!(
					result,
					Err(SelectedStreamPublishError::Gate(GateFailure::Expired))
				)),
			}
			assert_eq!(
				fs::read(scratch.path(JOB).join("stage").join(STAGE)).unwrap(),
				PAYLOAD
			);
			assert!(!scratch.path(TARGET).exists());
		});
	}
}

#[test]
#[ignore = "requires native Linux and a disposable writable ext4 TMPDIR"]
fn grant_revoked_during_file_barrier_is_checked_at_the_effect() {
	with_fresh(|scratch, root, ready| {
		let qualification = projection(root);
		let eligible = RemoteDestinationEligibility::admit(root, Some(&qualification)).unwrap();
		let revoked = Mutex::new(false);
		let result = ready.publish_with_barriers(
			&eligible,
			AUTHORITY,
			authorization(binding(1)),
			|request| {
				assert_eq!(request.authority, AUTHORITY);
				let guard = revoked.lock().unwrap();
				if *guard {
					Err(GateFailure::Revoked)
				} else {
					Ok(guard)
				}
			},
			|file| {
				rustix::fs::fsync(file)?;
				*revoked.lock().unwrap() = true;
				Ok(())
			},
			|_| panic!("revocation prevented the rename"),
		);
		assert!(matches!(
			result,
			Err(SelectedStreamPublishError::Gate(GateFailure::Revoked))
		));
		assert_eq!(
			fs::read(scratch.path(JOB).join("stage").join(STAGE)).unwrap(),
			PAYLOAD
		);
		assert!(!scratch.path(TARGET).exists());
	});
}

#[test]
#[ignore = "requires native Linux and a disposable writable ext4 TMPDIR"]
fn retained_stage_conflict_keeps_both_inodes_and_never_syncs_directories() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	{
		let job = root.create_job_directory(component(JOB)).unwrap();
		let directory = job.create_stage_directory().unwrap();
		drop(closed(&directory));
	}
	let job = root.open_recovery_job(component(JOB)).unwrap();
	let lease = root
		.try_recovery_write_lease(component(JOB), job.identity())
		.unwrap();
	let inventory = lease
		.job()
		.inventory(component(STAGE), component(TARGET))
		.unwrap();
	let observed = inventory.stage().unwrap();
	let mut bytes = [0; PAYLOAD.len()];
	observed.read_exact_at(0, &mut bytes).unwrap();
	observed.check_logical_eof().unwrap();
	assert_eq!(bytes, PAYLOAD);
	let stage = lease
		.prepare_retained_stage(&inventory, binding(1))
		.unwrap();
	let ready = stage
		.prepare_selected_stream_metadata(observed.len())
		.unwrap();

	let qualification = projection(&root);
	let eligible = RemoteDestinationEligibility::admit(&root, Some(&qualification)).unwrap();
	let gate = Mutex::new(AUTHORITY);
	let result = ready.publish_with_barriers(
		&eligible,
		AUTHORITY,
		authorization(binding(1)),
		|request| {
			let locked = gate.lock().unwrap();
			assert_eq!(*locked, request.authority);
			Ok::<_, GateFailure>(locked)
		},
		|file| {
			fs::write(scratch.path(TARGET), b"incumbent").unwrap();
			rustix::fs::fsync(file)
		},
		|_| panic!("exclusive rename did not succeed"),
	);
	assert!(matches!(
		result,
		Err(SelectedStreamPublishError::Native(PublishError::Conflict))
	));
	assert_eq!(fs::read(scratch.path(TARGET)).unwrap(), b"incumbent");
	assert_eq!(
		fs::read(scratch.path(JOB).join("stage").join(STAGE)).unwrap(),
		PAYLOAD
	);
}

#[test]
#[ignore = "requires native Linux and a disposable writable ext4 TMPDIR"]
fn barrier_and_post_rename_failures_preserve_effect_and_return_typed_error() {
	for case in 0..3 {
		with_fresh(|scratch, root, ready| {
			let qualification = projection(root);
			let eligible = RemoteDestinationEligibility::admit(root, Some(&qualification)).unwrap();
			let gate = Mutex::new(AUTHORITY);
			let barriers = Cell::new(0);
			let result = ready.publish_with_barriers(
				&eligible,
				AUTHORITY,
				authorization(binding(1)),
				|_| {
					assert_ne!(
						case, 0,
						"failed file sync cannot reach the publication gate"
					);
					Ok::<_, GateFailure>(gate.lock().unwrap())
				},
				|file| {
					if case == 0 {
						Err(Errno::IO)
					} else {
						rustix::fs::fsync(file)
					}
				},
				|directory| {
					barriers.set(barriers.get() + 1);
					if barriers.get() == 1 {
						if case == 1 {
							return Err(Errno::IO);
						}
						let target = scratch.path(TARGET);
						fs::write(&target, vec![b'x'; PAYLOAD.len()]).unwrap();
						File::open(target)
							.unwrap()
							.set_times(
								FileTimes::new()
									.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
							)
							.unwrap();
					}
					rustix::fs::fsync(directory)
				},
			);
			match case {
				0 => {
					assert_eq!(barriers.get(), 0);
					assert!(matches!(
						result,
						Err(SelectedStreamPublishError::Native(
							PublishError::StageChanged(StageError::BarrierFailed(_))
						))
					));
					assert!(!scratch.path(TARGET).exists());
					assert_eq!(
						fs::read(scratch.path(JOB).join("stage").join(STAGE)).unwrap(),
						PAYLOAD
					);
				}
				1 => {
					assert_eq!(barriers.get(), 2);
					assert!(matches!(
						result,
						Err(SelectedStreamPublishError::Native(
							PublishError::BarriersFailed(_)
						))
					));
					assert_eq!(fs::read(scratch.path(TARGET)).unwrap(), PAYLOAD);
					assert!(!scratch.path(JOB).join("stage").join(STAGE).exists());
				}
				_ => {
					assert_eq!(barriers.get(), 2);
					assert!(matches!(
						result,
						Err(SelectedStreamPublishError::Native(
							PublishError::ObservationFailed(_)
						))
					));
					assert_eq!(
						fs::read(scratch.path(TARGET)).unwrap(),
						vec![b'x'; PAYLOAD.len()]
					);
					assert!(!scratch.path(JOB).join("stage").join(STAGE).exists());
				}
			}
		});
	}
}

fn with_fresh(
	exercise: impl for<'stage> FnOnce(&Scratch, &DestinationRoot, SelectedStreamMetadataReady<'stage>),
) {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let job = root.create_job_directory(component(JOB)).unwrap();
	let directory = job.create_stage_directory().unwrap();
	let stage = closed(&directory);
	let location = stage.inspect_selected_stream_location().unwrap();
	assert_eq!(location.stage, stage.identity());
	assert_eq!(location.directory, directory.identity());
	assert_eq!(location.destination, root.identity());
	assert_eq!(location.names.target, component(TARGET));
	let mut bytes = [0; PAYLOAD.len()];
	stage.read_exact_at(0, &mut bytes).unwrap();
	assert_eq!(bytes, PAYLOAD);
	let length = stage.length();
	let ready = stage.prepare_selected_stream_metadata(length).unwrap();
	exercise(&scratch, &root, ready);
}

fn closed<'stage>(directory: &'stage crate::linux::StageDirectory<'stage>) -> ClosedStage<'stage> {
	let mut stage = directory
		.create_file(component(STAGE), component(TARGET), binding(1))
		.unwrap();
	stage.write_all_at(0, PAYLOAD).unwrap();
	stage.flush().unwrap();
	stage.close_writes().unwrap()
}

fn projection(root: &DestinationRoot) -> RemoteDestinationQualification {
	// A synthetic projection tests native observation and fencing, not trust enrollment.
	RemoteDestinationQualification::new(observe_remote_destination(root).unwrap(), QUALIFICATION)
		.unwrap()
}

fn binding(epoch: u64) -> CopyBinding {
	let job =
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap();
	CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(epoch),
		StageId::from_bytes([1; 16]),
	)
}

fn authorization(binding: CopyBinding) -> PublishNoClobber {
	let mut session = CopySession::new(binding);
	for event in [
		CopyEvent::StagePrepared,
		CopyEvent::WritersJoined,
		CopyEvent::DataFlushed,
		CopyEvent::ReadbackVerified,
		CopyEvent::MetadataReady,
		CopyEvent::StageSealed,
	] {
		let _ = session.apply(binding, event).unwrap();
	}
	let Some(CopyEffect::PublishNoClobber(permit)) = session
		.apply(binding, CopyEvent::PublishIntentRecorded)
		.unwrap()
	else {
		panic!("model refused fixture publication");
	};
	permit
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).unwrap()
}
