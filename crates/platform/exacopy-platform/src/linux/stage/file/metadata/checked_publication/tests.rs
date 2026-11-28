use std::cell::{Cell, RefCell};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_apply::{
	ApplyRole, ApplyStep, CheckedPublication, CheckedRenameFailure, GuardedCopyJob,
	GuardedStageDirectory, GuardedStageReader, GuardedStageWriter, HeldCheckedPublication,
};
use exacopy_endpoint::linux_publication::FreshReceiptError;
use exacopy_model::CopyBinding;
use rustix::io::Errno;

use super::super::tests::{authorization, binding, observed_source};
use super::{CheckedStageError, ClosedStage, DirectoryBarriersError, PublishError, StageError};
use crate::linux::guarded_staging::tests::FixtureAdmission;
use crate::linux::{DestinationRoot, JobDirectory, SourceObservation};
use crate::scratch::Scratch;

const PAYLOAD: &[u8] = b"retained content";

#[test]
fn final_refusal_and_late_incumbent_leave_the_exact_private_stage() {
	for conflict in [false, true] {
		with_stage(|fixture, _, closed, binding, _| {
			let part = fixture.path("job/stage/part");
			let target = fixture.path("target");
			let initial = identity(&part);
			let readied = Cell::new(false);
			let attempt = closed.publish_checked_with(
				authorization(binding),
				|| {
					readied.set(true);
					assert!(!target.exists());
					if conflict {
						// Controlled creation after native readiness exercises real NOREPLACE.
						fs::write(&target, b"incumbent").unwrap();
					}
					Ok::<_, ()>(())
				},
				|(), facts| {
					assert!(readied.get());
					assert_eq!((facts.stage.device, facts.stage.inode), initial);
					if conflict {
						Ok(())
					} else {
						Err(io::Error::other("fixture denied rename"))
					}
				},
				|names| {
					assert!(conflict, "a refused gate reached the rename");
					names.rename()
				},
				|_| panic!("conflict and refusal do not start settlement"),
			);
			if conflict {
				assert!(matches!(
					attempt,
					Err(CheckedRenameFailure::Conflict(CheckedStageError::Rename(
						PublishError::Conflict
					)))
				));
				assert_ne!(identity(&target), initial);
				assert_eq!(fs::read(target).unwrap(), b"incumbent");
			} else {
				assert!(matches!(attempt, Err(CheckedRenameFailure::Admission(_))));
				assert!(!target.exists());
			}
			assert_eq!(identity(&part), initial);
			assert_eq!(fs::read(&part).unwrap(), PAYLOAD);
		});
	}
}

#[test]
fn actual_publish_retains_inode_and_metadata_after_receipt_admission_refuses() {
	with_stage(|fixture, job, closed, binding, source| {
		let target = fixture.path("target");
		let selected = identity(&fixture.path("job/stage/part"));
		let stage = identity(&fixture.path("job/stage"));
		let destination = identity(&fixture.path("."));
		let hold = closed
			.publish_checked(authorization(binding), || Ok::<_, ()>(()), |(), _| Ok(()))
			.unwrap();
		let gate = FixtureAdmission::default();
		gate.refuse
			.set(Some(ApplyStep::Create(ApplyRole::ReceiptDirectory)));
		assert!(matches!(
			job.seal_fresh_receipt_admitted(b"fixture receipt", &gate),
			Err(FreshReceiptError::Namespace(StageError::Admission(_)))
		));
		assert_eq!(
			gate.steps.into_inner(),
			[ApplyStep::Create(ApplyRole::ReceiptDirectory)]
		);
		assert!(!fixture.path("job/receipts").exists());
		assert!(!fixture.path("job/stage/part").exists());
		let facts = hold.recheck_published().unwrap();
		assert_eq!((facts.target.device, facts.target.inode), selected);
		assert_eq!(
			(facts.stage_directory.device, facts.stage_directory.inode),
			stage
		);
		assert_eq!(
			(facts.destination.device, facts.destination.inode),
			destination
		);
		assert_eq!(identity(&target), selected);
		let stat = fs::metadata(&target).unwrap();
		assert_eq!(stat.mode() & 0o777, source.mode());
		assert_eq!((stat.uid(), stat.gid()), (source.owner(), source.group()));
		assert_eq!(
			(stat.atime(), stat.atime_nsec()),
			(
				source.accessed_at().seconds(),
				i64::from(source.accessed_at().nanoseconds())
			)
		);
		assert_eq!(
			(stat.mtime(), stat.mtime_nsec()),
			(
				source.modified_at().seconds(),
				i64::from(source.modified_at().nanoseconds())
			)
		);
		assert_eq!(stat.nlink(), 1);
		assert_eq!(fs::read(target).unwrap(), PAYLOAD);
	});
}

#[test]
fn settlement_attempts_both_original_barriers_even_after_ambiguous_return_or_failure() {
	for (ambiguous, observation_drift, stage_error, destination_error) in [
		(false, false, None, None),
		(false, false, Some(Errno::IO), None),
		(false, false, None, Some(Errno::NOSPC)),
		(false, false, Some(Errno::IO), Some(Errno::NOSPC)),
		(true, false, None, None),
		(true, false, Some(Errno::IO), Some(Errno::NOSPC)),
		(false, true, None, None),
		(true, true, Some(Errno::IO), Some(Errno::NOSPC)),
	] {
		with_stage(|fixture, _, closed, binding, _| {
			let original = fixture.path("job/stage/part");
			let target = fixture.path("target");
			let drift_link = fixture.path("job/stage/retained-drift-link");
			let selected = identity(&original);
			let stage = identity(&fixture.path("job/stage"));
			let destination = identity(&fixture.path("."));
			let order = RefCell::new(Vec::new());
			let active = Cell::new(false);
			let result = closed.publish_checked_with(
				authorization(binding),
				|| Ok::<_, ()>(()),
				|(), facts| {
					assert_eq!((facts.stage.device, facts.stage.inode), selected);
					assert!(!active.replace(true));
					Ok(FixtureRenameGuard {
						active: &active,
						target: &target,
					})
				},
				|names| {
					assert!(active.get());
					names.rename()?;
					if observation_drift {
						// Deliberate same-principal fault on the owned inode, before the first observation.
						fs::hard_link(&target, &drift_link).unwrap();
						assert_eq!(identity(&drift_link), selected);
					}
					if ambiguous {
						// Keep the real rename and model a lost result in this fixture only.
						return Err(PublishError::Uncertain(io::Error::other(
							"fixture lost reply",
						)));
					}
					Ok(())
				},
				|directory| {
					assert!(!active.get());
					assert!(!original.exists());
					assert_eq!(identity(&target), selected);
					if observation_drift {
						assert_eq!(identity(&drift_link), selected);
						assert_eq!(fs::symlink_metadata(&target).unwrap().nlink(), 2);
					}
					let stat = directory.metadata().unwrap();
					let current = (stat.dev(), stat.ino());
					order.borrow_mut().push(current);
					let fault = if current == stage {
						stage_error
					} else if current == destination {
						destination_error
					} else {
						panic!("unrelated directory")
					};
					match fault {
						Some(error) => Err(error),
						None => rustix::fs::fsync(directory),
					}
				},
			);
			assert_eq!(order.into_inner(), [stage, destination]);
			assert!(!original.exists());
			assert_eq!(identity(&target), selected);
			assert_eq!(fs::read(&target).unwrap(), PAYLOAD);
			if observation_drift {
				assert_eq!(identity(&drift_link), selected);
				assert_eq!(fs::read(&drift_link).unwrap(), PAYLOAD);
			} else {
				assert!(!drift_link.exists());
			}
			let incomplete =
				observation_drift || stage_error.is_some() || destination_error.is_some();
			let (observation, barriers) = match result {
				Ok(_) if !ambiguous && !incomplete => (None, None),
				Err(CheckedRenameFailure::PublishedIncomplete {
					observation,
					barriers,
				}) if !ambiguous && incomplete => (observation, barriers),
				Err(CheckedRenameFailure::Uncertain {
					cause: CheckedStageError::Rename(PublishError::Uncertain(_)),
					observation,
					barriers,
				}) if ambiguous => (observation, barriers),
				unexpected => panic!("unexpected settlement: {unexpected:?}"),
			};
			match (observation_drift, observation) {
				(false, None)
				| (true, Some(CheckedStageError::Custody(StageError::MetadataMismatch))) => {}
				unexpected => panic!("unexpected post-rename observation: {unexpected:?}"),
			}
			match (stage_error, destination_error, barriers) {
				(None, None, None) => {}
				(
					Some(expected),
					None,
					Some(CheckedStageError::Barriers(DirectoryBarriersError::Stage(cause))),
				)
				| (
					None,
					Some(expected),
					Some(CheckedStageError::Barriers(DirectoryBarriersError::Destination(cause))),
				) => {
					assert_eq!(cause.raw_os_error(), Some(expected.raw_os_error()));
				}
				(
					Some(expected_stage),
					Some(expected_destination),
					Some(CheckedStageError::Barriers(DirectoryBarriersError::Both {
						stage,
						destination,
					})),
				) => {
					assert_eq!(stage.raw_os_error(), Some(expected_stage.raw_os_error()));
					assert_eq!(
						destination.raw_os_error(),
						Some(expected_destination.raw_os_error())
					);
				}
				unexpected => panic!("unexpected barrier evidence: {unexpected:?}"),
			}
		});
	}
}

struct FixtureRenameGuard<'scope> {
	active: &'scope Cell<bool>,
	target: &'scope Path,
}

impl Drop for FixtureRenameGuard<'_> {
	fn drop(&mut self) {
		assert!(self.active.replace(false));
		assert!(
			self.target.exists(),
			"guard remained held through the actual rename"
		);
	}
}

fn with_stage(
	test: impl FnOnce(&Scratch, &JobDirectory<'_>, ClosedStage<'_>, CopyBinding, SourceObservation),
) {
	let fixture = Scratch::new();
	let source = observed_source(&fixture, 0o440);
	assert_eq!(source.len(), u64::try_from(PAYLOAD.len()).unwrap());
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job = root.create_job_directory(component(b"job")).unwrap();
	let directory = job.create_stage_directory().unwrap();
	let binding = binding();
	let gate = FixtureAdmission::default();
	let mut writer = GuardedStageDirectory::create_file_admitted(
		&directory,
		component(b"part"),
		component(b"target"),
		binding,
		&gate,
	)
	.unwrap();
	writer.write_window_admitted(0, PAYLOAD, &gate).unwrap();
	writer.flush_stage_admitted(&gate).unwrap();
	let closed = writer.close_writes().unwrap();
	let mut read_back = [0; PAYLOAD.len()];
	closed.read_exact_at(0, &mut read_back).unwrap();
	assert_eq!(&read_back, PAYLOAD);
	let closed = closed
		.apply_metadata_admitted(source, source.accessed_at(), &gate)
		.unwrap();
	closed.seal_stage_admitted(&gate).unwrap();
	test(&fixture, &job, closed, binding, source);
}

fn component(name: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(name).unwrap()
}

fn identity(path: &Path) -> (u64, u64) {
	let stat = fs::symlink_metadata(path).unwrap();
	(stat.dev(), stat.ino())
}
