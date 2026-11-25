use std::num::{NonZeroU16, NonZeroU64};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::{UnixComponent, ssh_sftp::SshAuthority};
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::remote_download::replay::{
	RemoteDownloadReplay, RemoteReplayAttempt, RemoteReplayState, replay_remote_download,
	replay_remote_download_with_bootstrap,
};
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadBody as Body, RemoteDownloadContext,
	RemoteDownloadDestination, RemoteDownloadDurability, RemoteDownloadOwner,
	RemoteDownloadOwnerRecord, RemoteDownloadRecord, RemoteDownloadRoute, RemoteDownloadScope,
	RemoteDownloadSource, RemoteEpochs, RemoteSourceObservation,
};
use exacopy_journal::{
	JournalEpoch, LinuxFileIdentity, OwnerProfileId, OwnerTimestamp, OwnerToken, RootCapabilityId,
	StreamDigest, StreamLength,
};
use exacopy_transfer::remote_capture::{CaptureCheckpoint, CaptureCheckpoints};
use exacopy_transfer::remote_resume::{
	AllocatedCapture, AllocationBase, CaptureAttempt, RemoteScopeDigest, RestartJournal,
	RestartRecord, RestartRefusal, ResumeHistory, SyncedRestart, plan_restart, restart_live,
};

use super::fixture::{CONTENT, Fault, NEW, OLD, admission, epoch, head, history, setup};
use super::ready;

const DEVICE: u64 = 7;
const STAGING: u64 = 12;

fn owner() -> RemoteDownloadOwnerRecord {
	let scope = history().scope;
	let remote = RemoteDownloadSource::new(
		SshAuthority::new("transfer.example", NonZeroU16::new(22).unwrap(), "reader").unwrap(),
		[0x51; 32],
		RemoteDownloadRoute::Direct,
		b"incoming/data",
	)
	.unwrap();
	let mut root = [0x54; 16];
	root[8] = 0x94;
	let destination = RemoteDownloadDestination::new(
		RootCapabilityId::from_bytes(root).unwrap(),
		LinuxFileIdentity::new(DEVICE, 9),
		UnixComponent::new(b"target").unwrap(),
	);
	let scope_record = RemoteDownloadScope::new(
		scope.entry,
		remote,
		destination,
		StreamLength::new(scope.maximum_length).unwrap(),
		[0x56; 32],
		RemoteDownloadDurability::ProcessCrash,
	)
	.unwrap();
	let owner = RemoteDownloadOwner::new(
		OwnerToken::from_bytes([0x11; 16]).unwrap(),
		scope.job,
		OwnerProfileId::from_bytes([0x22; 16]).unwrap(),
		OwnerTimestamp::new(0, 0).unwrap(),
		LinuxFileIdentity::new(DEVICE, 20),
		scope_record,
	)
	.unwrap();
	RemoteDownloadOwnerRecord::sign(owner, &SigningKey::from_bytes(&[0x52; 32])).unwrap()
}

fn epochs(run: u64, source: u64) -> RemoteEpochs {
	RemoteEpochs {
		run: NonZeroU64::new(run).unwrap(),
		source: NonZeroU64::new(source).unwrap(),
	}
}

fn allocated(attempt: &RemoteReplayAttempt) -> AllocatedCapture {
	let epochs = attempt.epochs();
	AllocatedCapture {
		head: attempt.allocation(),
		run: JournalEpoch::new(epochs.run.get()),
		source: epoch(epochs.source.get()),
	}
}

struct FramedJournal {
	bytes: Vec<u8>,
	head: ChainHead,
	context: RemoteDownloadContext,
	nonce: [u8; 16],
	prepared: Option<(ChainHead, RemoteEpochs, u64)>,
}

impl FramedJournal {
	fn new(owner: &RemoteDownloadOwnerRecord) -> Self {
		let mut journal = Self {
			bytes: Vec::new(),
			head: ChainHead::start(),
			context: RemoteDownloadContext {
				owner: owner.digest(),
				job: owner.manifest().job,
				entry: owner.manifest().scope.entry,
			},
			nonce: [0; 16],
			prepared: None,
		};
		journal.append(Body::JobPrepared {
			scope: owner.manifest().scope.digest().unwrap(),
		});
		journal
	}

	fn add_signed_bootstrap(&mut self, trust: &RemoteBootstrapTrust<'_>, key: &SigningKey) {
		let mut reader = FrameReader::new(self.bytes.as_slice(), ChainHead::start());
		let job = reader.next_frame().unwrap().unwrap();
		assert!(reader.next_frame().unwrap().is_none());
		let payload = trust
			.sign(&job, LinuxFileIdentity::new(DEVICE, STAGING), key)
			.unwrap();
		let mut writer = FrameWriter::new(&mut self.bytes, self.head);
		self.head = writer
			.append(FrameKind::StageDirectoryPrepared, &payload)
			.unwrap();
	}

	fn append(&mut self, body: Body<'_>) -> ChainHead {
		let head = self.head;
		let record = RemoteDownloadRecord::new(
			self.context,
			(head != ChainHead::start()).then_some(head),
			body,
		)
		.unwrap()
		.encode()
		.unwrap();
		let mut writer = FrameWriter::new(&mut self.bytes, head);
		self.head = writer.append(body.kind(), &record).unwrap();
		self.head
	}

	fn allocate(&mut self, previous: Option<RemoteEpochs>, next: RemoteEpochs) -> ChainHead {
		let name = format!("attempt-{}", next.run);
		self.nonce = [u8::try_from(next.run.get()).unwrap(); 16];
		self.append(Body::StageAllocated {
			previous,
			next,
			name: UnixComponent::new(name.as_bytes()).unwrap(),
			nonce: self.nonce,
			source: RemoteSourceObservation::new(
				StreamLength::new(u64::try_from(CONTENT.len()).unwrap()).unwrap(),
				0o100644,
				0,
			)
			.unwrap(),
		})
	}

	fn bind(&mut self, allocation: ChainHead, epochs: RemoteEpochs, stage: u64) -> ChainHead {
		let head = self.append(Body::EntryPrepared {
			allocation,
			epochs,
			nonce: self.nonce,
			stage_directory: LinuxFileIdentity::new(DEVICE, STAGING),
			stage: LinuxFileIdentity::new(DEVICE, stage),
		});
		self.prepared = Some((head, epochs, stage));
		head
	}
}

impl CaptureCheckpoints<u64> for FramedJournal {
	type Error = &'static str;

	fn record(&mut self, stage: u64, range: CaptureCheckpoint) -> Result<(), Self::Error> {
		let (prepared, epochs, bound_stage) = self.prepared.ok_or("unbound stage")?;
		if stage != bound_stage || range.epoch.get() != epochs.source.get() {
			return Err("wrong checkpoint binding");
		}
		self.append(Body::RangeCheckpoint {
			prepared,
			epochs,
			ordinal: 1,
			offset: range.offset,
			length: range.length,
			digest: StreamDigest::from_bytes(range.digest),
		});
		Ok(())
	}
}

impl RestartJournal<u64> for FramedJournal {
	fn sync_restart(
		&mut self,
		record: RestartRecord<u64>,
	) -> Result<SyncedRestart<u64>, Self::Error> {
		if self.head != record.predecessor {
			return Err("incorrect live predecessor");
		}
		let head = self.bind(
			record.predecessor,
			epochs(record.next.run.get(), record.next.source.get()),
			record.next.stage,
		);
		Ok(SyncedRestart { record, head })
	}
}

fn from_selected_history(
	owner: &RemoteDownloadOwnerRecord,
	journal: &FramedJournal,
	replayed: &RemoteDownloadReplay,
) -> ResumeHistory<u64> {
	assert!(matches!(
		replayed.state(),
		RemoteReplayState::AllocationUnbound
	));
	let (pending, previous) = replayed.attempts().split_last().unwrap();
	let mut history = history();
	history.scope.owner = owner.digest();
	history.scope.approved_scope =
		RemoteScopeDigest::from_bytes(*owner.manifest().scope.digest().unwrap().as_bytes());
	let base = replayed.job_prepared().unwrap();
	history.allocation_base = replayed.stage_directory_prepared().map_or(
		AllocationBase::LegacyJobPrepared(base),
		AllocationBase::SignedStageDirectoryPrepared,
	);
	history.predecessor = replayed.boundary().head;
	let mut reader = FrameReader::new(journal.bytes.as_slice(), ChainHead::start());
	let pending_frame = std::iter::from_fn(|| reader.next_frame().unwrap())
		.find(|frame| frame.head() == history.predecessor)
		.expect("find the exact pending allocation");
	history.pending_allocation_predecessor = RemoteDownloadRecord::from_frame(&pending_frame)
		.unwrap()
		.predecessor()
		.unwrap();
	history.previous = previous.iter().rev().find_map(|attempt| {
		let stage = attempt.prepared()?;
		let epochs = attempt.epochs();
		Some(CaptureAttempt {
			run: JournalEpoch::new(epochs.run.get()),
			source: epoch(epochs.source.get()),
			stage: stage.file.inode(),
		})
	});
	history.previous_allocation = previous.last().map(allocated);
	history.pending_allocation = allocated(pending);
	history
}

#[test]
fn restart_replays_after_zero_one_or_multiple_unbound_allocations() {
	for (bound, unbound) in [(true, 1), (true, 2), (false, 2), (false, 0)] {
		let owner = owner();
		let mut journal = FramedJournal::new(&owner);
		let mut previous = None;
		if bound {
			let first = epochs(1, 5);
			let allocation = journal.allocate(None, first);
			journal.bind(allocation, first, OLD);
			previous = Some(first);
		}
		for index in 0..unbound {
			let run = previous.map_or(1, |epochs| epochs.run.get() + 1);
			let failed = epochs(run, 6 + index);
			journal.allocate(previous, failed);
			previous = Some(failed);
		}
		let run = previous.map_or(1, |epochs| epochs.run.get() + 1);
		let pending = journal.allocate(previous, epochs(run, 8));
		let replay = replay_remote_download(journal.bytes.as_slice(), &owner).unwrap();
		let history = from_selected_history(&owner, &journal, &replay);
		let plan = plan_restart(history, admission(history.scope)).unwrap();
		let (mut source, stage, _, _, _) = setup(CONTENT, Fault::None);
		let (_, _, synced) = ready(restart_live(
			plan,
			&mut source,
			stage,
			&mut journal,
			&mut [0; 8],
		))
		.unwrap()
		.into_parts();

		assert_eq!(synced.record.predecessor, pending);
		assert_eq!(synced.record.next.run, JournalEpoch::new(run));
		assert_eq!(
			synced.record.previous.map(|bound| bound.stage),
			bound.then_some(OLD)
		);
		let replay = replay_remote_download(journal.bytes.as_slice(), &owner).unwrap();
		assert!(
			matches!(replay.state(), RemoteReplayState::StageBound),
			"{:?}",
			replay.state()
		);
		let (fresh, prior) = replay.attempts().split_last().unwrap();
		assert_eq!(
			prior.len(),
			usize::from(bound) + usize::try_from(unbound).unwrap()
		);
		let unbound_attempts = if bound {
			assert_eq!(prior[0].prepared().unwrap().file.inode(), OLD);
			&prior[1..]
		} else {
			prior
		};
		assert!(
			unbound_attempts
				.iter()
				.all(|attempt| attempt.prepared().is_none())
		);
		assert_eq!(fresh.prepared().unwrap().file.inode(), NEW);
		assert_eq!(fresh.covered_extent(), 8);
	}
}

#[test]
fn refuses_out_of_order_or_reused_allocations_and_wrong_heads() {
	let prior = history();
	let admission = admission(prior.scope);
	for run in [0, 5, 7] {
		let mut wrong = prior;
		wrong.pending_allocation.run = JournalEpoch::new(run);
		assert_eq!(
			plan_restart(wrong, admission).unwrap_err(),
			RestartRefusal::RunEpoch
		);
	}
	for bad in [
		head(prior.predecessor.sequence() - 1),
		ChainHead::after(prior.predecessor.sequence(), [9; 32]).unwrap(),
	] {
		let mut wrong = prior;
		wrong.pending_allocation.head = bad;
		assert_eq!(
			plan_restart(wrong, admission).unwrap_err(),
			RestartRefusal::JournalBoundary
		);
	}
	let mut wrong = prior;
	wrong.previous_allocation.as_mut().unwrap().head = wrong.predecessor;
	assert_eq!(
		plan_restart(wrong, admission).unwrap_err(),
		RestartRefusal::JournalBoundary
	);

	let mut wrong = prior;
	wrong.previous.as_mut().unwrap().source = epoch(6);
	assert_eq!(
		plan_restart(wrong, admission).unwrap_err(),
		RestartRefusal::AllocationBinding
	);
	let mut wrong = prior;
	wrong.previous_allocation = None;
	assert_eq!(
		plan_restart(wrong, admission).unwrap_err(),
		RestartRefusal::AllocationBinding
	);
}

#[test]
fn exhausted_allocations_stop_without_rejecting_the_last_valid_reservation() {
	let mut history = history();
	let mut admission = admission(history.scope);
	history.previous = None;
	let previous = history.previous_allocation.as_mut().unwrap();
	previous.run = JournalEpoch::new(u64::MAX);
	history.pending_allocation.run = JournalEpoch::new(u64::MAX);
	assert_eq!(
		plan_restart(history, admission).unwrap_err(),
		RestartRefusal::RunEpoch
	);

	history.previous_allocation.as_mut().unwrap().run = JournalEpoch::new(u64::MAX - 1);
	history.previous_allocation.as_mut().unwrap().source = epoch(u64::MAX);
	history.pending_allocation.source = epoch(u64::MAX);
	admission.source = epoch(u64::MAX);
	assert_eq!(
		plan_restart(history, admission).unwrap_err(),
		RestartRefusal::StaleSource
	);

	history.previous_allocation.as_mut().unwrap().source = epoch(u64::MAX - 1);
	assert!(plan_restart(history, admission).is_ok());
	history.predecessor = head(u64::MAX);
	history.pending_allocation.head = history.predecessor;
	assert_eq!(
		plan_restart(history, admission).unwrap_err(),
		RestartRefusal::JournalBoundary
	);
}

#[test]
fn first_allocation_follows_the_signed_bootstrap() {
	let owner = owner();
	let signer = SigningKey::from_bytes(&[0x52; 32]);
	let key = signer.verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, owner.manifest().profile, &key).unwrap();
	let mut journal = FramedJournal::new(&owner);
	journal.add_signed_bootstrap(&trust, &signer);
	let pending = journal.allocate(None, epochs(1, 8));
	let replay = replay_remote_download_with_bootstrap(journal.bytes.as_slice(), &trust).unwrap();
	let history = from_selected_history(&owner, &journal, &replay);
	let proof = replay.stage_directory_prepared().unwrap();
	assert_eq!(
		history.allocation_base,
		AllocationBase::SignedStageDirectoryPrepared(proof)
	);
	assert_eq!(history.pending_allocation_predecessor, proof.head());
	let admission = admission(history.scope);
	let plan = plan_restart(history, admission).expect("allocation must follow exact signed head");

	let mut foreign = history;
	foreign.pending_allocation_predecessor =
		ChainHead::after(proof.head().sequence(), [0x63; 32]).unwrap();
	assert_eq!(
		plan_restart(foreign, admission).unwrap_err(),
		RestartRefusal::JournalBoundary
	);

	let mut legacy = history;
	legacy.allocation_base = AllocationBase::LegacyJobPrepared(replay.job_prepared().unwrap());
	assert_eq!(
		plan_restart(legacy, admission).unwrap_err(),
		RestartRefusal::JournalBoundary
	);

	let (mut source, stage, _, _, _) = setup(CONTENT, Fault::None);
	let (_, _, synced) = ready(restart_live(
		plan,
		&mut source,
		stage,
		&mut journal,
		&mut [0; 8],
	))
	.unwrap()
	.into_parts();
	assert_eq!(synced.record.predecessor, pending);
	let replay = replay_remote_download_with_bootstrap(journal.bytes.as_slice(), &trust).unwrap();
	assert!(matches!(replay.state(), RemoteReplayState::StageBound));
	assert_eq!(replay.attempts()[0].prepared().unwrap().head, synced.head);
}

#[test]
fn later_allocation_rereads_after_burned_signed_attempt() {
	let owner = owner();
	let signer = SigningKey::from_bytes(&[0x52; 32]);
	let key = signer.verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, owner.manifest().profile, &key).unwrap();
	let mut journal = FramedJournal::new(&owner);
	journal.add_signed_bootstrap(&trust, &signer);
	let first = epochs(1, 6);
	let burned = journal.allocate(None, first);
	let pending = journal.allocate(Some(first), epochs(2, 8));
	let replay = replay_remote_download_with_bootstrap(journal.bytes.as_slice(), &trust).unwrap();
	let history = from_selected_history(&owner, &journal, &replay);
	assert!(history.previous.is_none());
	assert_eq!(history.pending_allocation_predecessor, burned);
	let admission = admission(history.scope);
	let plan = plan_restart(history, admission).unwrap();

	let mut foreign = history;
	foreign.pending_allocation_predecessor =
		ChainHead::after(burned.sequence(), [0x64; 32]).unwrap();
	assert_eq!(
		plan_restart(foreign, admission).unwrap_err(),
		RestartRefusal::JournalBoundary
	);

	let (mut source, stage, _, _, _) = setup(CONTENT, Fault::None);
	let (_, _, synced) = ready(restart_live(
		plan,
		&mut source,
		stage,
		&mut journal,
		&mut [0; 8],
	))
	.unwrap()
	.into_parts();
	assert_eq!(synced.record.predecessor, pending);
	assert_eq!(synced.record.next.run.get(), 2);
	let replay = replay_remote_download_with_bootstrap(journal.bytes.as_slice(), &trust).unwrap();
	assert!(matches!(replay.state(), RemoteReplayState::StageBound));
	assert!(replay.attempts()[0].prepared().is_none());
	assert_eq!(replay.attempts()[1].prepared().unwrap().head, synced.head);
}
