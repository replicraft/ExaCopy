use std::future::Future;
use std::num::{NonZeroU64, NonZeroUsize};
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use exacopy_platform::linux::FileIdentity;
use exacopy_transfer::remote_capture::{
	CaptureCheckpoint, CaptureCheckpoints, CaptureError, CapturedReadAt, SourceEpoch, capture_live,
};
use exacopy_transfer::remote_resume::RestartStage;

use crate::assembly::linux::remote_stage::{NativeCaptureStage, PrefixBarrier};

use super::{Fixture, LENGTH, NONCE, STAGE, component, observation};

const BYTES: &[u8; LENGTH as usize] = b"remote stream";

#[test]
fn private_capture_syncs_its_exact_checkpoint_and_preserves_public_absence() {
	let fixture = Fixture::new();
	let lease = fixture.open_bootstrap(fixture.bootstrap());
	let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
	let mut journal = lease.open_writer(&candidate).unwrap();
	let mut allocation = journal
		.allocate(&candidate, NonZeroU64::MIN, observation(), NONCE)
		.unwrap();
	let bound = allocation.create(&mut journal).unwrap();
	let expected_stage = bound.prefix_scope.stage;
	let barrier = PrefixBarrier::new(bound.prefix_scope);
	let stage = NativeCaptureStage::new(
		bound.writer,
		lease.job(),
		bound.name,
		bound.target,
		bound.directory,
		bound.length,
		&barrier,
	)
	.unwrap();
	let mut checkpoints = journal.checkpoints(&barrier);
	let mut source = FixtureSource {
		finished: false,
		epoch: source_epoch(),
	};
	let mut scratch = [0; 5];
	let capture = run(capture_live(
		&mut source,
		source_epoch(),
		stage,
		&mut checkpoints,
		&mut scratch,
	))
	.unwrap();
	let (closed, observed) = capture.into_parts();
	assert_eq!(
		NativeCaptureStage::closed_binding(&closed).unwrap(),
		expected_stage
	);
	assert!(source.finished);
	assert_eq!(observed.length, LENGTH);
	assert_eq!(observed.source_digest, *blake3::hash(BYTES).as_bytes());
	let replay = fixture.replay();
	let [attempt] = replay.attempts() else {
		panic!("exactly one captured stage")
	};
	assert_eq!(attempt.checkpoint_count(), 1);
	assert_eq!(attempt.covered_extent(), LENGTH);
	assert_eq!(std::fs::read(fixture.stage("capture-1")).unwrap(), BYTES);
	assert!(!fixture.target().exists());
}

#[test]
fn stage_prefix_proof_cannot_be_used_twice_or_with_the_wrong_prepared_frame() {
	let fixture = Fixture::new();
	let lease = fixture.open_bootstrap(fixture.bootstrap());
	let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
	let mut journal = lease.open_writer(&candidate).unwrap();
	let mut allocation = journal
		.allocate(&candidate, NonZeroU64::MIN, observation(), NONCE)
		.unwrap();
	let bound = allocation.create(&mut journal).unwrap();
	let mut wrong = bound.prefix_scope;
	wrong.prepared = exacopy_journal::frame::ChainHead::after(
		bound.prefix_scope.prepared.sequence(),
		[0x77; 32],
	)
	.unwrap();
	let barrier = PrefixBarrier::new(wrong);
	let stage = NativeCaptureStage::new(
		bound.writer,
		lease.job(),
		bound.name,
		bound.target,
		bound.directory,
		bound.length,
		&barrier,
	)
	.unwrap();
	let mut checkpoints = journal.checkpoints(&barrier);
	let mut source = FixtureSource {
		finished: false,
		epoch: source_epoch(),
	};
	let mut scratch = [0; 5];
	let denied = run(capture_live(
		&mut source,
		source_epoch(),
		stage,
		&mut checkpoints,
		&mut scratch,
	));
	assert!(matches!(
		denied,
		Err(CaptureError::Checkpoint { offset: 0, .. })
	));
	assert!(!source.finished);
	assert_eq!(fixture.replay().attempts()[0].checkpoint_count(), 0);

	let retry = lease
		.candidate(component(b"capture-retry").unwrap())
		.unwrap();
	drop(allocation);
	let mut allocation = journal
		.allocate(&retry, super::epoch(2), observation(), [0x64; 16])
		.unwrap();
	let bound = allocation.create(&mut journal).unwrap();
	let barrier = PrefixBarrier::new(bound.prefix_scope);
	let stage = NativeCaptureStage::new(
		bound.writer,
		lease.job(),
		bound.name,
		bound.target,
		bound.directory,
		bound.length,
		&barrier,
	)
	.unwrap();
	let mut checkpoints = journal.checkpoints(&barrier);
	let mut repeat = RepeatedCheckpoint(&mut checkpoints);
	let mut source = FixtureSource {
		finished: false,
		epoch: SourceEpoch::new(super::epoch(2)),
	};
	let denied = run(capture_live(
		&mut source,
		SourceEpoch::new(super::epoch(2)),
		stage,
		&mut repeat,
		&mut scratch,
	));
	assert!(matches!(
		denied,
		Err(CaptureError::Checkpoint { offset: 0, .. })
	));
	assert_eq!(fixture.replay().attempts()[1].checkpoint_count(), 1);
	assert!(!fixture.target().exists());
}

struct RepeatedCheckpoint<'hold, C>(&'hold mut C);

impl<C: CaptureCheckpoints<FileIdentity>> CaptureCheckpoints<FileIdentity>
	for RepeatedCheckpoint<'_, C>
{
	type Error = C::Error;

	fn record(&mut self, stage: FileIdentity, range: CaptureCheckpoint) -> Result<(), Self::Error> {
		self.0.record(stage, range)?;
		self.0.record(stage, range)
	}
}

struct FixtureSource {
	finished: bool,
	epoch: SourceEpoch,
}

impl CapturedReadAt for FixtureSource {
	type Error = std::convert::Infallible;

	fn epoch(&self) -> SourceEpoch {
		self.epoch
	}

	fn length(&self) -> u64 {
		LENGTH
	}

	fn max_window_bytes(&self) -> NonZeroUsize {
		NonZeroUsize::new(4).unwrap()
	}

	async fn read_exact_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		let start = usize::try_from(offset).unwrap();
		bytes.copy_from_slice(&BYTES[start..start + bytes.len()]);
		Ok(())
	}

	async fn recheck(&mut self) -> Result<(), Self::Error> {
		assert!(!self.finished);
		Ok(())
	}

	async fn finish(&mut self) -> Result<(), Self::Error> {
		self.finished = true;
		Ok(())
	}
}

fn source_epoch() -> SourceEpoch {
	SourceEpoch::new(NonZeroU64::MIN)
}

fn run<F: Future>(future: F) -> F::Output {
	let mut future = pin!(future);
	let mut context = Context::from_waker(Waker::noop());
	match future.as_mut().poll(&mut context) {
		Poll::Ready(output) => output,
		Poll::Pending => panic!("the deterministic fixture unexpectedly suspended"),
	}
}
