use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ed25519_dalek::SigningKey;
use exacopy_journal::frame::FrameWriter;
use exacopy_journal::{
	DestinationRootBinding, JournalEntryId, JournalJobId, LinuxFileIdentity, ObservedTimestamp,
	OwnerDigest, OwnerProfileId, PublishIntentContext, RootCapabilityId, StreamDigest,
	StreamEvidence, StreamLength, VerificationRecorded,
};

use super::super::super::super::{
	DestinationPlanBinding, JournalBoundary, JournalReplay, LocalCopyPlan, PlanAttempt,
	SourcePlanBinding,
};
use super::*;

const TARGET: LinuxFileIdentity = LinuxFileIdentity::new(3, 4);
const STAGE_DIRECTORY: LinuxFileIdentity = LinuxFileIdentity::new(3, 5);
const OWNER: OwnerDigest = OwnerDigest::from_bytes([8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Call {
	Load,
	Inventory,
	Inspect,
	OpenJournal,
	ResumeJournal,
	Append(FrameKind),
	PublicationBarriers,
	OpenReceipts,
	CreateReceipt,
	SyncExistingReceipt,
	WriteReceipt,
	ReceiptFileBarrier,
	ReceiptDirectoryBarrier,
	JobDirectoryBarrier,
	RecheckNames,
}

#[derive(Default)]
struct State {
	calls: RefCell<Vec<Call>>,
	fail: Option<Call>,
	loads: Cell<usize>,
}

impl State {
	fn call(&self, call: Call) -> Result<(), Call> {
		self.calls.borrow_mut().push(call);
		if self.fail == Some(call) {
			return Err(call);
		}
		Ok(())
	}
}

struct Lease {
	state: Rc<State>,
	plan: LocalCopyPlan<'static>,
	replay: JournalReplay,
	disposition: RecoveryDisposition,
	existing: Option<()>,
}

impl Lease {
	fn new(fail: Option<Call>) -> Self {
		let plan = plan();
		let context = plan.context();
		let entry = plan.attempt().entry;
		let intent = PublishIntentContext {
			job: context.job,
			epoch: context.epoch,
			entry,
			effect_sequence: 1,
			plan_digest: context.plan_digest,
		};
		let stream = StreamEvidence {
			identity: TARGET,
			length: StreamLength::new(3).unwrap(),
			digest: StreamDigest::from_bytes([1; 32]),
		};
		let source = StreamEvidence {
			identity: plan.source().file_identity,
			..stream
		};
		Self {
			state: Rc::new(State {
				fail,
				..State::default()
			}),
			plan,
			replay: JournalReplay {
				boundary: JournalBoundary {
					head: head(6),
					offset: 600,
				},
				tail: JournalTail::Clean,
				source: None,
				source_link_count: None,
				source_metadata: None,
				preparation_head: None,
				stage: Some(TARGET),
				checkpoints: Vec::new(),
				sealed: None,
				verification: Some(
					VerificationRecorded::new(context, entry, source, stream).unwrap(),
				),
				verification_head: Some(head(4)),
				metadata: None,
				metadata_head: Some(head(5)),
				intent: Some(intent),
				intent_head: Some(head(6)),
				observation: None,
				observation_head: None,
				durability: None,
				durability_head: None,
				latest_epoch: context.epoch,
				last_effect_sequence: 1,
				recovery_stage_directory: None,
				published_recovery: false,
				receipt: None,
			},
			disposition: RecoveryDisposition::PublishedNeedsBarriers,
			existing: None,
		}
	}

	fn finish(&self) -> Result<RecoveryInspection, FinishError<Call, Call>> {
		let key = SigningKey::from_bytes(&[1; 32]).verifying_key();
		finish(
			self,
			self.plan.attempt().job_name,
			RecoveryProfile {
				id: OwnerProfileId::from_bytes([1; 16]).unwrap(),
				verifying_key: &key,
			},
			&mut [0; 3],
		)
	}
}

impl FinishLease for Lease {
	type InspectError = Call;
	type History = JournalReplay;
	type Inventory<'lease> = ();
	type Segment = ();
	type Journal = Writer;

	fn load(
		&self,
		_name: UnixComponent<'_>,
		_profile: RecoveryProfile<'_>,
	) -> Result<Self::History, Self::InspectError> {
		self.state.call(Call::Load)?;
		self.state.loads.set(self.state.loads.get() + 1);
		Ok(self.replay.clone())
	}

	fn evidence<'history>(
		&self,
		history: &'history Self::History,
	) -> Result<FinishEvidence<'history, Self::ExistingReceipt>, Self::InspectError> {
		const EXISTING: () = ();
		Ok(FinishEvidence {
			plan: self.plan,
			replay: history,
			authorization: OWNER,
			receipt: self.existing.map(|()| &EXISTING),
		})
	}

	fn inventory(
		&self,
		plan: LocalCopyPlan<'_>,
	) -> Result<Self::Inventory<'_>, Self::InspectError> {
		assert_eq!(plan, self.plan);
		self.state.call(Call::Inventory)
	}

	fn inspect<'lease>(
		&'lease self,
		history: &Self::History,
		_names: &Self::Inventory<'lease>,
		_scratch: &mut [u8],
	) -> Result<RecoveryInspection, Self::InspectError> {
		self.state.call(Call::Inspect)?;
		Ok(RecoveryInspection {
			journal: history.boundary,
			tail: history.tail,
			disposition: if self.state.loads.get() == 1 {
				self.disposition
			} else {
				RecoveryDisposition::Complete
			},
		})
	}

	fn stage_directory_identity<'lease>(
		&'lease self,
		_names: &Self::Inventory<'lease>,
	) -> Option<LinuxFileIdentity> {
		Some(STAGE_DIRECTORY)
	}

	fn open_journal(&self, history: &Self::History) -> Result<Self::Segment, Self::EffectError> {
		assert_eq!(history.boundary, self.replay.boundary);
		self.state.call(Call::OpenJournal)
	}

	fn resume_journal(
		&self,
		(): Self::Segment,
		boundary: JournalBoundary,
	) -> Result<Self::Journal, DurableJournalError> {
		assert_eq!(boundary, self.replay.boundary);
		self.state
			.call(Call::ResumeJournal)
			.map_err(|_| DurableJournalError::UnexpectedHead)?;
		Ok(Writer {
			state: Rc::clone(&self.state),
			writer: FrameWriter::new(Vec::new(), boundary.head),
		})
	}

	fn sync_publication<'lease>(
		&'lease self,
		_names: &Self::Inventory<'lease>,
	) -> Result<(), Self::EffectError> {
		self.state.call(Call::PublicationBarriers)
	}

	fn recheck_names<'lease>(
		&'lease self,
		_names: &Self::Inventory<'lease>,
	) -> Result<(), Self::EffectError> {
		self.state.call(Call::RecheckNames)
	}
}

struct Writer {
	state: Rc<State>,
	writer: FrameWriter<Vec<u8>>,
}

impl FinishJournal for Writer {
	fn append(
		&mut self,
		kind: FrameKind,
		payload: &[u8],
	) -> Result<ChainHead, DurableJournalError> {
		let head = self
			.writer
			.append(kind, payload)
			.map_err(DurableJournalError::Frame)?;
		self.state
			.call(Call::Append(kind))
			.map_err(|_| DurableJournalError::Sync(injected()))?;
		Ok(head)
	}
}

impl ReceiptLease for Lease {
	type EffectError = Call;
	type ExistingReceipt = ();
	type Directory<'lease> = &'lease State;

	fn open_receipt_directory(&self) -> Result<Self::Directory<'_>, Self::EffectError> {
		self.state.call(Call::OpenReceipts)?;
		Ok(&self.state)
	}

	fn sync_job_directory(&self) -> Result<(), Self::EffectError> {
		self.state.call(Call::JobDirectoryBarrier)
	}
}

impl<'lease> FinishReceiptDirectory for &'lease State {
	type Error = Call;
	type ExistingReceipt = ();
	type Record = ReceiptWriter<'lease>;

	fn sync_receipt(&self, (): &Self::ExistingReceipt) -> Result<(), Self::Error> {
		self.call(Call::SyncExistingReceipt)
	}

	fn create_receipt(&self) -> Result<Self::Record, Self::Error> {
		self.call(Call::CreateReceipt)?;
		Ok(ReceiptWriter {
			state: self,
			bytes: Vec::new(),
		})
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		self.call(Call::ReceiptDirectoryBarrier)
	}
}

struct ReceiptWriter<'lease> {
	state: &'lease State,
	bytes: Vec<u8>,
}

impl std::io::Write for ReceiptWriter<'_> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.state
			.call(Call::WriteReceipt)
			.map_err(|_| injected())?;
		self.bytes.extend_from_slice(bytes);
		Ok(bytes.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

impl exacopy_endpoint::linux_publication::ReceiptRecord for ReceiptWriter<'_> {
	fn sync_all(&self) -> io::Result<()> {
		let receipt =
			CopyReceipt::decode(&self.bytes).expect("canonical receipt before file barrier");
		assert_eq!(receipt.evidence().stream.identity, TARGET);
		assert_eq!(receipt.evidence().context.epoch.get(), 1);
		assert_eq!(receipt.durability_frame().sequence(), 10);
		self.state
			.call(Call::ReceiptFileBarrier)
			.map_err(|_| injected())
	}
}

fn injected() -> io::Error {
	io::Error::other("injected uncertain effect")
}

fn head(sequence: u64) -> ChainHead {
	ChainHead::after(sequence, [9; 32]).expect("nonzero fixture head")
}

fn plan() -> LocalCopyPlan<'static> {
	fn uuid(marker: u8) -> [u8; 16] {
		let mut bytes = [marker; 16];
		bytes[6] = 0x70;
		bytes[8] = 0x80;
		bytes
	}

	LocalCopyPlan::new(
		PlanAttempt {
			job: JournalJobId::from_bytes(uuid(1)).unwrap(),
			epoch: JournalEpoch::new(1),
			entry: JournalEntryId::from_bytes([2; 16]),
			job_name: UnixComponent::new(b"job").unwrap(),
			stage_name: UnixComponent::new(b"stage").unwrap(),
		},
		SourcePlanBinding {
			root_id: RootCapabilityId::from_bytes(uuid(3)).unwrap(),
			root_identity: LinuxFileIdentity::new(2, 1),
			file_identity: LinuxFileIdentity::new(2, 2),
			length: 3,
			modified_at: ObservedTimestamp::new(10, 0).unwrap(),
			changed_at: ObservedTimestamp::new(11, 0).unwrap(),
			component: UnixComponent::new(b"source").unwrap(),
		},
		DestinationPlanBinding {
			root: DestinationRootBinding {
				id: RootCapabilityId::from_bytes(uuid(4)).unwrap(),
				identity: LinuxFileIdentity::new(3, 1),
			},
			component: UnixComponent::new(b"target").unwrap(),
		},
	)
	.unwrap()
}

const NEW_RECEIPT: &[Call] = &[
	Call::Load,
	Call::Inventory,
	Call::Inspect,
	Call::OpenJournal,
	Call::ResumeJournal,
	Call::Append(FrameKind::RecoveryStarted),
	Call::Append(FrameKind::RecoveryDecision),
	Call::PublicationBarriers,
	Call::Append(FrameKind::PublishObserved),
	Call::Append(FrameKind::DurabilityRecorded),
	Call::OpenReceipts,
	Call::CreateReceipt,
	Call::WriteReceipt,
	Call::ReceiptFileBarrier,
	Call::ReceiptDirectoryBarrier,
	Call::JobDirectoryBarrier,
	Call::RecheckNames,
	Call::Append(FrameKind::ReceiptCommitted),
	Call::Load,
	Call::Inspect,
];

#[test]
fn records_authorization_and_barriers_before_committing_the_receipt() {
	let lease = Lease::new(None);
	assert_eq!(
		lease.finish().unwrap().disposition,
		RecoveryDisposition::Complete
	);
	assert_eq!(*lease.state.calls.borrow(), NEW_RECEIPT);
}

#[test]
fn stops_at_the_first_uncertain_effect_or_failed_observation() {
	for (index, failed) in NEW_RECEIPT
		.iter()
		.copied()
		.take(NEW_RECEIPT.len() - 2)
		.enumerate()
	{
		let lease = Lease::new(Some(failed));
		assert!(lease.finish().is_err(), "expected failure for {failed:?}");
		assert_eq!(
			*lease.state.calls.borrow(),
			&NEW_RECEIPT[..=index],
			"after {failed:?}"
		);
	}
}

#[test]
fn preserves_existing_observation_and_receipt_without_reissuing_records() {
	let mut lease = Lease::new(None);
	lease.disposition = RecoveryDisposition::PublishedNeedsReceipt {
		artifact_present: true,
	};
	lease.existing = Some(());
	let intent = lease.replay.intent.unwrap();
	lease.replay.observation = Some(
		PublishObserved::new(
			intent,
			lease.replay.intent_head.unwrap(),
			PublicationOutcome::Published { target: TARGET },
		)
		.unwrap(),
	);
	lease.replay.observation_head = Some(head(7));
	lease.replay.durability_head = Some(head(8));
	lease.replay.boundary = JournalBoundary {
		head: head(8),
		offset: 800,
	};
	assert_eq!(
		lease.finish().unwrap().disposition,
		RecoveryDisposition::Complete
	);
	assert_eq!(
		*lease.state.calls.borrow(),
		[
			Call::Load,
			Call::Inventory,
			Call::Inspect,
			Call::OpenJournal,
			Call::ResumeJournal,
			Call::Append(FrameKind::RecoveryStarted),
			Call::Append(FrameKind::RecoveryDecision),
			Call::PublicationBarriers,
			Call::OpenReceipts,
			Call::SyncExistingReceipt,
			Call::ReceiptDirectoryBarrier,
			Call::JobDirectoryBarrier,
			Call::RecheckNames,
			Call::Append(FrameKind::ReceiptCommitted),
			Call::Load,
			Call::Inspect,
		]
	);
}

#[test]
fn refuses_mutation_for_torn_or_ineligible_history() {
	let cases = [
		(
			JournalTail::Torn { bytes_read: 1 },
			RecoveryDisposition::PublishedNeedsBarriers,
		),
		(JournalTail::Clean, RecoveryDisposition::PossibleRetry),
		(JournalTail::Clean, RecoveryDisposition::Conflict),
		(JournalTail::Clean, RecoveryDisposition::Complete),
	];
	for (tail, disposition) in cases {
		let mut lease = Lease::new(None);
		lease.replay.tail = tail;
		lease.disposition = disposition;
		let inspection = lease.finish().unwrap();
		assert_eq!(inspection.disposition, disposition);
		assert_eq!(inspection.tail, tail);
		assert_eq!(
			*lease.state.calls.borrow(),
			[Call::Load, Call::Inventory, Call::Inspect]
		);
	}
}
