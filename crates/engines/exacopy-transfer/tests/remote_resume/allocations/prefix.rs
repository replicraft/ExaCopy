use std::cell::{Cell, RefCell};
use std::num::NonZeroUsize;

use ed25519_dalek::SigningKey;
use exacopy_endpoint::{ReadView, UnixComponent};
use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;
use exacopy_journal::remote_download::finalization_replay::replay_remote_finalization_with_checkpoints;
use exacopy_journal::remote_download::{MAX_REMOTE_CHECKPOINT_BYTES, RemoteBootstrapTrust};
use exacopy_transfer::remote_capture::{CapturedReadAt, SourceEpoch};
use exacopy_transfer::remote_resume::prefix::{
	PrefixVerificationError as Error, RetainedPrefixIdentity, RetainedPrefixView,
	verify_retained_prefix,
};

use super::{
	Body, DEVICE, FramedJournal, LinuxFileIdentity, OLD, STAGING, StreamDigest, epoch, epochs,
	owner_with_policy, ready,
};

#[path = "prefix/continued.rs"]
mod continued;

const STAGE: u64 = 15;
const FRESH: u64 = OLD + 1;
const OLD_BYTES: &[u8] = b"abcdxy";
const FRESH_BYTES: &[u8] = b"abcdxyz!";
const QUALIFICATION: [u8; 32] = [0x71; 32];

struct Fixture {
	owner: super::RemoteDownloadOwnerRecord,
	journal: FramedJournal,
}

impl Fixture {
	fn new() -> Self {
		let key = SigningKey::from_bytes(&[0x52; 32]);
		let verifier = key.verifying_key();
		let owner = owner_with_policy(SftpDataOnlyV1::digest());
		let trust = RemoteBootstrapTrust::new(&owner, owner.manifest().profile, &verifier).unwrap();
		let mut journal = FramedJournal::new(&owner);
		journal.add_signed_bootstrap(&trust, &key);
		let epochs = epochs(1, OLD);
		let allocation = journal.allocate(None, epochs);
		let prepared = journal.bind(allocation, epochs, STAGE);
		for (ordinal, offset, bytes) in [(1, 0, b"ab"), (2, 2, b"cd")] {
			journal.append(Body::RangeCheckpoint {
				prepared,
				epochs,
				ordinal,
				offset,
				length: 2,
				digest: StreamDigest::from_bytes(*blake3::hash(bytes).as_bytes()),
			});
		}
		Self { owner, journal }
	}

	fn verify<'source, 'data>(
		&self,
		source: &'source mut Source<'data>,
		stage: &Stage<'_>,
		scratch: &mut [u8],
	) -> Result<
		exacopy_transfer::remote_resume::prefix::VerifiedRetainedPrefix<'source, Source<'data>>,
		Error<&'static str, &'static str>,
	> {
		let key = SigningKey::from_bytes(&[0x52; 32]).verifying_key();
		let trust =
			RemoteBootstrapTrust::new(&self.owner, self.owner.manifest().profile, &key).unwrap();
		let replay = replay_remote_finalization_with_checkpoints(
			self.journal.bytes.as_slice(),
			&trust,
			QUALIFICATION,
			None,
		)
		.unwrap();
		let inventory = replay.active_checkpoints().unwrap();
		ready(verify_retained_prefix(
			&inventory,
			source,
			epoch(FRESH),
			stage,
			scratch,
		))
	}
}

struct Source<'data> {
	reported_length: Option<u64>,
	bytes: &'data [u8],
	reads: Vec<(u64, usize)>,
	checks: usize,
	epoch: SourceEpoch,
	stale_on_read: bool,
	failed_read: Option<u64>,
	pause_read: bool,
}

impl<'data> Source<'data> {
	fn new(bytes: &'data [u8]) -> Self {
		Self {
			reported_length: None,
			bytes,
			reads: Vec::new(),
			checks: 0,
			epoch: epoch(FRESH),
			stale_on_read: false,
			failed_read: None,
			pause_read: false,
		}
	}
}

impl CapturedReadAt for Source<'_> {
	type Error = &'static str;

	fn epoch(&self) -> SourceEpoch {
		self.epoch
	}

	fn length(&self) -> u64 {
		self.reported_length
			.unwrap_or_else(|| u64::try_from(self.bytes.len()).unwrap())
	}

	fn max_window_bytes(&self) -> NonZeroUsize {
		NonZeroUsize::new(2).unwrap()
	}

	async fn read_exact_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		let start = usize::try_from(offset).unwrap();
		self.reads.push((offset, bytes.len()));
		if self.pause_read {
			std::future::pending::<()>().await;
		}
		if self.failed_read == Some(offset) {
			bytes.fill(0xff);
			return Err("interrupted window");
		}
		bytes.copy_from_slice(&self.bytes[start..start + bytes.len()]);
		if self.stale_on_read {
			self.epoch = epoch(FRESH + 1);
		}
		Ok(())
	}

	async fn recheck(&mut self) -> Result<(), Self::Error> {
		self.checks += 1;
		Ok(())
	}

	async fn finish(&mut self) -> Result<(), Self::Error> {
		panic!("prefix verification cannot finish the live source")
	}
}

struct Stage<'data> {
	name: &'data [u8],
	file: u64,
	bytes: &'data [u8],
	length: u64,
	reads: RefCell<Vec<(u64, usize)>>,
	checks: Cell<usize>,
	rebound: bool,
}

impl<'data> Stage<'data> {
	fn new(bytes: &'data [u8]) -> Self {
		Self {
			name: b"attempt-1",
			file: STAGE,
			bytes,
			length: u64::try_from(bytes.len()).unwrap(),
			reads: RefCell::new(Vec::new()),
			checks: Cell::new(0),
			rebound: false,
		}
	}
}

impl ReadView for Stage<'_> {
	type Error = &'static str;

	fn length(&self) -> u64 {
		self.length
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.checks.set(self.checks.get() + 1);
		Ok(())
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		let start = usize::try_from(offset).unwrap();
		self.reads.borrow_mut().push((offset, bytes.len()));
		bytes.copy_from_slice(&self.bytes[start..start + bytes.len()]);
		Ok(())
	}
}

impl RetainedPrefixView for Stage<'_> {
	fn identity(&self) -> RetainedPrefixIdentity<'_> {
		let native = if self.rebound && self.checks.get() > 1 {
			self.file + 1
		} else {
			self.file
		};
		RetainedPrefixIdentity {
			name: UnixComponent::new(self.name).unwrap(),
			directory: LinuxFileIdentity::new(DEVICE, STAGING),
			file: LinuxFileIdentity::new(DEVICE, native),
		}
	}
}

fn rereads_each_reused_byte_and_distinguishes_fresh_tail_from_historical_ranges() {
	let fixture = Fixture::new();
	let mut remote = Source::new(FRESH_BYTES);
	let on_disk = Stage::new(OLD_BYTES);
	let proof = fixture.verify(&mut remote, &on_disk, &mut [0; 3]).unwrap();
	assert_eq!(proof.epoch(), epoch(FRESH));
	assert_eq!(proof.source_length(), 8);
	assert_eq!(proof.checkpoint_extent(), 4);
	assert_eq!(proof.extent(), 6);
	assert_eq!(proof.digest(), *blake3::hash(OLD_BYTES).as_bytes());
	assert_eq!(
		proof.scope(),
		fixture.owner.manifest().scope.digest().unwrap()
	);
	assert_eq!(proof.context().owner, fixture.owner.digest());
	assert_eq!(proof.expected_qualification(), QUALIFICATION);
	assert_eq!(proof.previous_epochs(), epochs(1, OLD));
	assert_eq!(proof.boundary().head, fixture.journal.head);
	assert_eq!(proof.stage().head, fixture.journal.prepared.unwrap().0);
	let same = proof.into_source();
	assert_eq!(
		same.reads,
		(0..6).map(|offset| (offset, 1)).collect::<Vec<_>>()
	);
	assert_eq!(*on_disk.reads.borrow(), same.reads);
	assert_eq!(same.checks, 2);
	assert_eq!(on_disk.checks.get(), 2);
}

fn historical_digest_and_live_equality_are_independent_requirements() {
	let fixture = Fixture::new();
	let mut changed_remote = Source::new(b"abXdxyz!");
	assert!(matches!(
		fixture.verify(&mut changed_remote, &Stage::new(OLD_BYTES), &mut [0; 8]),
		Err(Error::SourceMismatch { offset: 2 })
	));
	let mut alike_but_corrupt = Source::new(b"abXdxyz!");
	assert!(matches!(
		fixture.verify(&mut alike_but_corrupt, &Stage::new(b"abXdxy"), &mut [0; 8]),
		Err(Error::CheckpointMismatch { offset: 2 })
	));
	let mut changed_tail = Source::new(b"abcdxYz!");
	assert!(matches!(
		fixture.verify(&mut changed_tail, &Stage::new(OLD_BYTES), &mut [0; 8]),
		Err(Error::TailMismatch { offset: 4 })
	));
}

fn current_stage_binding_and_source_epoch_are_checked_after_io() {
	let fixture = Fixture::new();
	let mut remote = Source::new(FRESH_BYTES);
	let mut stage = Stage::new(OLD_BYTES);
	stage.rebound = true;
	assert!(matches!(
		fixture.verify(&mut remote, &stage, &mut [0; 8]),
		Err(Error::StageIdentity)
	));
	assert!(!remote.reads.is_empty());
	let mut stale = Source::new(FRESH_BYTES);
	stale.stale_on_read = true;
	let stage = Stage::new(OLD_BYTES);
	assert!(matches!(
		fixture.verify(&mut stale, &stage, &mut [0; 8]),
		Err(Error::Epoch)
	));
	assert_eq!(stale.reads, [(0, 2)]);
	assert!(stage.reads.borrow().is_empty());
}

fn oversize_tail_short_source_and_short_scratch_refuse_without_reads() {
	let fixture = Fixture::new();
	let mut remote = Source::new(FRESH_BYTES);
	let mut stage = Stage::new(OLD_BYTES);
	stage.length = MAX_REMOTE_CHECKPOINT_BYTES + 5;
	assert!(matches!(
		fixture.verify(&mut remote, &stage, &mut [0; 8]),
		Err(Error::RetainedExtent { .. })
	));
	assert!(remote.reads.is_empty());
	assert!(stage.reads.borrow().is_empty());
	let mut short = Source::new(b"abcde");
	assert!(matches!(
		fixture.verify(&mut short, &Stage::new(OLD_BYTES), &mut [0; 8]),
		Err(Error::SourceShorter { .. })
	));
	assert!(short.reads.is_empty());
	assert!(matches!(
		fixture.verify(&mut remote, &Stage::new(OLD_BYTES), &mut [0; 1]),
		Err(Error::Input(_))
	));
	assert!(remote.reads.is_empty());
}

fn stale_epoch_signed_source_limit_and_missing_checkpoint_bytes_refuse_early() {
	let fixture = Fixture::new();
	let mut stale = Source::new(FRESH_BYTES);
	stale.epoch = epoch(OLD);
	assert!(matches!(
		fixture.verify(&mut stale, &Stage::new(OLD_BYTES), &mut [0; 8]),
		Err(Error::Epoch)
	));
	assert!(stale.reads.is_empty());
	let oversized = [0; 129];
	let mut oversized = Source::new(&oversized);
	assert!(matches!(
		fixture.verify(&mut oversized, &Stage::new(OLD_BYTES), &mut [0; 8]),
		Err(Error::SourceLimit {
			length: 129,
			limit: 128
		})
	));
	assert!(oversized.reads.is_empty());
	let mut fresh = Source::new(FRESH_BYTES);
	assert!(matches!(
		fixture.verify(&mut fresh, &Stage::new(b"abc"), &mut [0; 8]),
		Err(Error::RetainedExtent {
			extent: 3,
			checkpoint: 4
		})
	));
	assert!(fresh.reads.is_empty());
}

fn dirty_scratch_from_failed_source_window_never_reaches_local_comparison() {
	let fixture = Fixture::new();
	let mut remote = Source::new(FRESH_BYTES);
	remote.failed_read = Some(2);
	let stage = Stage::new(OLD_BYTES);
	assert!(matches!(
		fixture.verify(&mut remote, &stage, &mut [0; 8]),
		Err(Error::SourceRead {
			offset: 2,
			cause: "interrupted window"
		})
	));
	assert_eq!(remote.reads, [(0, 2), (2, 2)]);
	assert_eq!(*stage.reads.borrow(), [(0, 2)]);
	assert_eq!(stage.checks.get(), 1);
}

fn cancelling_a_pending_window_produces_no_local_comparison_or_prefix_result() {
	use std::future::Future as _;
	use std::pin::pin;
	use std::task::{Context, Waker};

	let fixture = Fixture::new();
	let key = SigningKey::from_bytes(&[0x52; 32]).verifying_key();
	let trust =
		RemoteBootstrapTrust::new(&fixture.owner, fixture.owner.manifest().profile, &key).unwrap();
	let replay = replay_remote_finalization_with_checkpoints(
		fixture.journal.bytes.as_slice(),
		&trust,
		QUALIFICATION,
		None,
	)
	.unwrap();
	let inventory = replay.active_checkpoints().unwrap();
	let mut remote = Source::new(FRESH_BYTES);
	remote.pause_read = true;
	let stage = Stage::new(OLD_BYTES);
	let mut scratch = [0; 8];
	{
		let mut verification = pin!(verify_retained_prefix(
			&inventory,
			&mut remote,
			epoch(FRESH),
			&stage,
			&mut scratch
		));
		assert!(
			verification
				.as_mut()
				.poll(&mut Context::from_waker(Waker::noop()))
				.is_pending()
		);
	}
	assert_eq!(remote.reads, [(0, 2)]);
	assert!(stage.reads.borrow().is_empty());
	assert_eq!(stage.checks.get(), 1);
}

fn every_changed_retained_or_fresh_byte_refuses_reuse() {
	let fixture = Fixture::new();
	for offset in 0..OLD_BYTES.len() {
		let mut altered_source = FRESH_BYTES.to_vec();
		altered_source[offset] ^= 1;
		let mut remote = Source::new(&altered_source);
		let local = Stage::new(OLD_BYTES);
		let outcome = fixture.verify(&mut remote, &local, &mut [0; 8]);
		match offset {
			0..=3 => assert!(matches!(outcome, Err(Error::SourceMismatch { .. }))),
			_ => assert!(matches!(outcome, Err(Error::TailMismatch { .. }))),
		}

		let mut altered_local = OLD_BYTES.to_vec();
		altered_local[offset] ^= 1;
		let mut remote = Source::new(FRESH_BYTES);
		let local = Stage::new(&altered_local);
		let outcome = fixture.verify(&mut remote, &local, &mut [0; 8]);
		match offset {
			0..=3 => assert!(matches!(outcome, Err(Error::CheckpointMismatch { .. }))),
			_ => assert!(matches!(outcome, Err(Error::TailMismatch { .. }))),
		}
	}
}

fn matching_fresh_bytes_cannot_extend_beyond_the_prior_writer_extent() {
	let fixture = Fixture::new();
	let mut remote = Source::new(b"abcdxyz!Q");
	let stage = Stage::new(b"abcdxyz!Q");
	assert!(matches!(
		fixture.verify(&mut remote, &stage, &mut [0; 16]),
		Err(Error::RetainedBeyondPrior {
			extent: 9,
			prior: 8
		})
	));
	assert!(remote.reads.is_empty());
	assert!(stage.reads.borrow().is_empty());
	assert_eq!(remote.checks, 0);
	assert_eq!(stage.checks.get(), 0);
}

#[test]
fn verified_prefix_matches_current_and_historical_failure_oracles() {
	rereads_each_reused_byte_and_distinguishes_fresh_tail_from_historical_ranges();
	historical_digest_and_live_equality_are_independent_requirements();
	current_stage_binding_and_source_epoch_are_checked_after_io();
	oversize_tail_short_source_and_short_scratch_refuse_without_reads();
	stale_epoch_signed_source_limit_and_missing_checkpoint_bytes_refuse_early();
	dirty_scratch_from_failed_source_window_never_reaches_local_comparison();
	cancelling_a_pending_window_produces_no_local_comparison_or_prefix_result();
	every_changed_retained_or_fresh_byte_refuses_reuse();
	matching_fresh_bytes_cannot_extend_beyond_the_prior_writer_extent();
}
