use std::fs::{self, DirBuilder, File};
use std::io::ErrorKind;
use std::num::NonZeroU64;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};
use exacopy_platform::linux::DestinationRoot;

use super::{
	ChainHead, CheckpointStage, ClosedStage, FreshStage, NativeCaptureStage,
	NativeCaptureStageError, PrefixBarrier, PrefixScope, ReadView, RestartStage, SourceEpoch,
	UnixComponent,
};

const JOB: &str = "remote-stage-job";
const CURRENT: &str = "current-attempt";
const OLD: &str = "retained-attempt";
const TARGET: &str = "public-target";
const RETAINED: &[u8] = b"prior attempt remains available";
const INCUMBENT: &[u8] = b"public occupant remains intact";

#[test]
fn fsync_proof_is_exact_once_and_readback_is_independently_bound() {
	with_stage(5, |scratch, mut stage, proof| {
		assert_eq!(stage.unwritten_length().unwrap(), 5);
		let identity = stage.held_binding().unwrap();
		assert!(!proof.take_current(proof.scope, 2));
		stage.write_next(b"ab").unwrap();
		assert_eq!(stage.sync_prefix(2).unwrap(), identity);
		assert!(proof.take_current(proof.scope, 2));
		assert!(!proof.take_current(proof.scope, 2));
		stage.write_next(b"cde").unwrap();
		assert_eq!(stage.sync_prefix(5).unwrap(), identity);
		let closed = stage.sync_and_close().unwrap();
		assert!(!proof.take_current(proof.scope, 5));
		assert_eq!(
			NativeCaptureStage::closed_binding(&closed).unwrap(),
			identity
		);
		let read_back = closed.open_read_back().unwrap();
		assert_eq!(read_back.length(), 5);
		let mut bytes = [0; 5];
		read_back.read_exact_at(0, &mut bytes).unwrap();
		assert_eq!(&bytes, b"abcde");
		assert!(read_back.read_exact_at(5, &mut [0]).is_err());
		read_back.recheck_observation().unwrap();
		assert_eq!(fs::read(scratch.stage(OLD)).unwrap(), RETAINED);
		assert!(!scratch.0.join(TARGET).exists());
	});
}

#[test]
fn an_empty_attempt_has_real_eof_and_no_checkpoint() {
	with_stage(0, |_, stage, proof| {
		let identity = stage.held_binding().unwrap();
		assert_eq!(stage.unwritten_length().unwrap(), 0);
		let closed = stage.sync_and_close().unwrap();
		assert_eq!(closed.open_read_back().unwrap().length(), 0);
		assert_eq!(
			NativeCaptureStage::closed_binding(&closed).unwrap(),
			identity
		);
		assert!(!proof.take_current(proof.scope, 0));
	});
}

#[test]
fn a_bad_prefix_will_neither_prove_progress_nor_reuse_the_writer() {
	with_stage(4, |scratch, mut stage, proof| {
		stage.write_next(b"ab").unwrap();
		stage.sync_prefix(2).unwrap();
		assert!(matches!(
			stage.sync_prefix(3),
			Err(NativeCaptureStageError::Extent)
		));
		assert!(!proof.take_current(proof.scope, 2));
		assert!(matches!(
			stage.write_next(b"cd"),
			Err(NativeCaptureStageError::Uncertain)
		));
		assert_eq!(fs::read(scratch.stage(CURRENT)).unwrap(), b"ab");
		assert_eq!(fs::read(scratch.stage(OLD)).unwrap(), RETAINED);
	});
}

#[test]
fn invalid_writes_leave_the_candidate_empty() {
	let oversized = vec![0; NativeCaptureStage::MAX_CHUNK_BYTES + 1];
	for bytes in [b"".as_slice(), b"abc".as_slice(), oversized.as_slice()] {
		with_stage(2, |scratch, mut stage, proof| {
			assert!(matches!(
				stage.write_next(bytes),
				Err(NativeCaptureStageError::Extent)
			));
			assert!(!proof.take_current(proof.scope, 2));
			assert!(fs::read(scratch.stage(CURRENT)).unwrap().is_empty());
		});
	}
}

#[test]
fn a_rebound_stage_blocks_effects_and_keeps_both_files() {
	with_stage(5, |scratch, mut stage, proof| {
		stage.write_next(b"ab").unwrap();
		stage.sync_prefix(2).unwrap();
		let displaced = scratch.stage("displaced");
		fs::rename(scratch.stage(CURRENT), &displaced).unwrap();
		fs::write(scratch.stage(CURRENT), b"rival").unwrap();
		fs::set_permissions(scratch.stage(CURRENT), fs::Permissions::from_mode(0o600)).unwrap();
		assert!(stage.held_binding().is_err());
		assert!(!proof.take_current(proof.scope, 2));
		assert!(matches!(
			stage.write_next(b"cde"),
			Err(NativeCaptureStageError::Uncertain)
		));
		assert_eq!(fs::read(displaced).unwrap(), b"ab");
		assert_eq!(fs::read(scratch.stage(CURRENT)).unwrap(), b"rival");
		assert_eq!(fs::read(scratch.stage(OLD)).unwrap(), RETAINED);
	});
}

#[test]
fn a_new_public_occupant_blocks_terminal_binding_without_removal() {
	with_stage(3, |scratch, mut stage, _| {
		stage.write_next(b"abc").unwrap();
		let closed = stage.sync_and_close().unwrap();
		fs::write(scratch.0.join(TARGET), INCUMBENT).unwrap();
		assert!(NativeCaptureStage::closed_binding(&closed).is_err());
		assert_eq!(fs::read(scratch.0.join(TARGET)).unwrap(), INCUMBENT);
		assert_eq!(fs::read(scratch.stage(CURRENT)).unwrap(), b"abc");
		assert_eq!(fs::read(scratch.stage(OLD)).unwrap(), RETAINED);
	});
}

#[test]
fn dropping_the_writer_invalidates_an_unconsumed_proof_and_keeps_data() {
	with_stage(5, |scratch, mut stage, proof| {
		stage.write_next(b"abc").unwrap();
		stage.sync_prefix(3).unwrap();
		drop(stage);
		assert!(!proof.take_current(proof.scope, 3));
		assert_eq!(fs::read(scratch.stage(CURRENT)).unwrap(), b"abc");
	});
}

#[test]
fn a_different_job_entry_frame_source_epoch_inode_or_end_cannot_claim_a_barrier() {
	with_stage(5, |_, mut stage, proof| {
		stage.write_next(b"abc").unwrap();
		let scope = proof.scope;
		let other_file = PrefixScope {
			stage: scope.job,
			..scope
		};
		let other_job = PrefixScope {
			job: scope.stage,
			..scope
		};
		let other_frame = PrefixScope {
			prepared: ChainHead::after(3, [9; 32]).unwrap(),
			..scope
		};
		let other_source = PrefixScope {
			source: SourceEpoch::new(NonZeroU64::new(3).unwrap()),
			..scope
		};
		for (expected, end) in [
			(other_file, 3),
			(other_job, 3),
			(other_frame, 3),
			(other_source, 3),
			(scope, 2),
		] {
			stage.sync_prefix(3).unwrap();
			assert!(!proof.take_current(expected, end));
			assert!(!proof.take_current(scope, 3));
		}
	});
}

fn with_stage(
	length: u64,
	test: impl for<'lease> FnOnce(&Scratch, NativeCaptureStage<'lease>, &'lease PrefixBarrier),
) {
	let scratch = Scratch::new();
	let destination = DestinationRoot::from_directory(File::open(&scratch.0).unwrap()).unwrap();
	let job = destination.create_job_directory(component(JOB)).unwrap();
	let job_identity = job.identity();
	let directory = job.create_stage_directory().unwrap();
	let directory_identity = directory.identity();
	let mut old = directory
		.create_file(component(OLD), component(TARGET), binding(1))
		.unwrap();
	old.write_all_at(0, RETAINED).unwrap();
	old.flush().unwrap();
	drop(old);
	drop(directory);
	drop(job);

	let lease = destination
		.try_recovery_write_lease(component(JOB), job_identity)
		.unwrap();
	let candidate = lease
		.job()
		.inventory(component(CURRENT), component(TARGET))
		.unwrap();
	let mut factory = lease
		.prepare_fresh_stage(&candidate, directory_identity)
		.unwrap();
	let writer = factory.create_writer(binding(2)).unwrap();
	let proof = PrefixBarrier::new(PrefixScope {
		job: job_identity,
		prepared: ChainHead::after(3, [7; 32]).unwrap(),
		source: SourceEpoch::new(NonZeroU64::new(2).unwrap()),
		stage: writer.observe_prefix(0).unwrap(),
	});
	let stage = NativeCaptureStage::new(
		writer,
		lease.job(),
		component(CURRENT),
		component(TARGET),
		directory_identity,
		length,
		&proof,
	)
	.unwrap();
	test(&scratch, stage, &proof);
}

fn binding(epoch: u64) -> CopyBinding {
	let job =
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap();
	let stage = u8::try_from(epoch).unwrap();
	CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(epoch),
		StageId::from_bytes([stage; 16]),
	)
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).unwrap()
}

struct Scratch(PathBuf);

impl Scratch {
	fn new() -> Self {
		static NEXT: AtomicUsize = AtomicUsize::new(0);
		for _ in 0..128 {
			let id = NEXT.fetch_add(1, Ordering::Relaxed);
			let path =
				std::env::temp_dir().join(format!("exc-remote-stage-{}-{id}", std::process::id()));
			match DirBuilder::new().mode(0o700).create(&path) {
				Ok(()) => return Self(path),
				Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
				Err(error) => panic!("create remote stage fixture: {error}"),
			}
		}
		panic!("reserve remote stage fixture");
	}

	fn stage(&self, name: &str) -> PathBuf {
		self.0.join(JOB).join("stage").join(name)
	}
}

impl Drop for Scratch {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}
