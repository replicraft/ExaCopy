use std::cell::RefCell;
use std::io::{self, Cursor, Read};

use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DarwinFileIdentity, DarwinNamespaceObservation, DarwinPublicationNames, DarwinRecoveryDecision,
	JournalJobId, OwnerError,
};

use crate::macos::inspection::capabilities::{
	InspectionStageReader, ObservationError, StageMetadata, StageObservation,
};
use crate::macos::replay::DarwinReplayStatus;
use crate::macos::replay::tests::fixture::{Fixture, identity};

use super::{
	DarwinInspectionAuthority, DarwinReceiptArtifact, InspectionInventory, InspectionJob,
	InspectionRecord, NamespaceOnly, ProtocolError, ReadBackError, StageReadBack, inspect,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Artifact {
	Plan,
	Owner,
	Segment,
	Receipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Call {
	Open(Artifact),
	Revalidate(Artifact),
	ObserveDestination,
	Inventory,
	OpenStage,
	InitialMetadata,
	ReadStage { offset: u64, length: usize },
	FinalMetadata,
	RevalidateInventory,
	Snapshot,
}

#[derive(Clone, Copy, Debug)]
enum Refusal {
	InventoryChanged,
	SegmentChanged,
}

#[test]
fn authenticated_inspection_revalidates_inventory_and_journal_before_returning() {
	let job = Job::new();
	let result = inspect(&job, job.authority(), NamespaceOnly).unwrap().0;
	assert_eq!(result.plan_bytes, job.history.plan.encode());
	assert_eq!(result.receipt, DarwinReceiptArtifact::PresentUncommitted);
	assert_eq!(
		result.namespace.stage,
		DarwinNamespaceObservation::Present(job.history.stage.identity)
	);
	assert_eq!(
		*job.calls.borrow(),
		[
			Call::Open(Artifact::Plan),
			Call::Revalidate(Artifact::Plan),
			Call::ObserveDestination,
			Call::Open(Artifact::Owner),
			Call::Revalidate(Artifact::Owner),
			Call::Open(Artifact::Segment),
			Call::Inventory,
			Call::Open(Artifact::Receipt),
			Call::RevalidateInventory,
			Call::Revalidate(Artifact::Segment),
			Call::Snapshot,
		]
	);
}

#[test]
fn inspection_preserves_current_names_when_a_recovery_decision_records_other_names() {
	let mut job = Job::new();
	job.history.records = job.history.recovered_intent();
	let incumbent = identity(50);
	job.target = DarwinNamespaceObservation::Present(incumbent);

	let inspection = crate::macos::inspection::inspect(&job, job.authority()).unwrap();
	let decision = DarwinRecoveryDecision::from_frame(
		inspection
			.replay
			.frame(FrameKind::RecoveryDecision)
			.unwrap(),
	)
	.unwrap();
	assert_eq!(
		decision.evidence().names,
		DarwinPublicationNames {
			stage: DarwinNamespaceObservation::Absent,
			target: DarwinNamespaceObservation::Present(job.history.stage.identity),
		}
	);
	assert_eq!(inspection.replay.status(), DarwinReplayStatus::Uncertain);
	assert_eq!(
		inspection.receipt,
		DarwinReceiptArtifact::PresentUncommitted
	);
	assert_eq!(
		inspection.namespace,
		DarwinPublicationNames {
			stage: DarwinNamespaceObservation::Present(job.history.stage.identity),
			target: DarwinNamespaceObservation::Present(incumbent),
		}
	);
	assert!(!job.calls.borrow().contains(&Call::OpenStage));
}

#[test]
fn inspection_refuses_stale_names_and_journal_without_returning_snapshot() {
	for refusal in [Refusal::InventoryChanged, Refusal::SegmentChanged] {
		let job = Job {
			refusal: Some(refusal),
			..Job::new()
		};
		let result = inspect(&job, job.authority(), NamespaceOnly);
		assert!(matches!(result, Err(ProtocolError::Platform(_))));
		let calls = job.calls.borrow();
		assert!(!calls.contains(&Call::Snapshot));
		let last = match refusal {
			Refusal::InventoryChanged => Call::RevalidateInventory,
			Refusal::SegmentChanged => Call::Revalidate(Artifact::Segment),
		};
		assert_eq!(calls.last(), Some(&last));
	}
}

#[test]
fn read_back_checks_metadata_around_reads_and_reports_digest_mismatch_first() {
	let weak = Job {
		initial_uid: 502,
		..Job::new()
	};
	let result = inspect(&weak, weak.authority(), StageReadBack(&mut [0; 8]));
	assert!(matches!(
		result,
		Err(ProtocolError::StageReadBack(
			ReadBackError::InitialMetadataMismatch
		))
	));
	assert_eq!(weak.calls.borrow().last(), Some(&Call::InitialMetadata));

	let job = Job {
		final_uid: 502,
		..Job::new()
	};
	let result = inspect(&job, job.authority(), StageReadBack(&mut [0; 8]));
	assert!(matches!(
		result,
		Err(ProtocolError::StageReadBack(ReadBackError::DigestMismatch))
	));
	assert!(job.calls.borrow().ends_with(&[
		Call::OpenStage,
		Call::InitialMetadata,
		Call::ReadStage {
			offset: 0,
			length: 8
		},
		Call::ReadStage {
			offset: 8,
			length: 3
		},
		Call::FinalMetadata,
	]));
}

struct Job {
	history: Fixture,
	calls: RefCell<Vec<Call>>,
	refusal: Option<Refusal>,
	target: DarwinNamespaceObservation,
	initial_uid: u32,
	final_uid: u32,
}

impl Job {
	fn new() -> Self {
		let history = Fixture::new();
		Self {
			initial_uid: history.plan.source().metadata.uid().get(),
			final_uid: history.plan.source().metadata.uid().get(),
			history,
			calls: RefCell::new(Vec::new()),
			refusal: None,
			target: DarwinNamespaceObservation::Absent,
		}
	}

	fn authority(&self) -> DarwinInspectionAuthority<'_> {
		DarwinInspectionAuthority {
			profile: self.history.plan.attempt().profile,
			key: &self.history.key,
			destination_root: self.history.plan.destination().root_id,
		}
	}

	fn record(&self, artifact: Artifact, bytes: Vec<u8>) -> Record<'_> {
		self.calls.borrow_mut().push(Call::Open(artifact));
		Record {
			artifact,
			bytes: Cursor::new(bytes),
			job: self,
		}
	}
}

impl InspectionJob for Job {
	type Error = Refusal;
	type Snapshot = DarwinPublicationNames;
	type Record<'job> = Record<'job>;
	type Inventory<'job> = Inventory<'job>;

	fn matches_job(&self, expected: JournalJobId) -> bool {
		expected == self.history.plan.attempt().job
	}

	fn identity(&self) -> Result<DarwinFileIdentity, OwnerError> {
		Ok(self.history.owner.manifest().state_root)
	}

	fn owner_uid(&self) -> u32 {
		self.history.owner.manifest().state_root_uid.get()
	}

	fn observe_destination(&self) -> Result<DarwinFileIdentity, ObservationError<Self::Error>> {
		self.calls.borrow_mut().push(Call::ObserveDestination);
		Ok(self.history.plan.destination().root_identity)
	}

	fn open_plan(&self) -> Result<Self::Record<'_>, Self::Error> {
		Ok(self.record(Artifact::Plan, self.history.plan.encode()))
	}

	fn open_owner(&self) -> Result<Self::Record<'_>, Self::Error> {
		Ok(self.record(Artifact::Owner, self.history.owner.as_bytes().to_vec()))
	}

	fn open_first_segment(&self) -> Result<Self::Record<'_>, Self::Error> {
		Ok(self.record(Artifact::Segment, self.history.records.bytes.clone()))
	}

	fn open_receipt(&self) -> Result<Option<Self::Record<'_>>, Self::Error> {
		Ok(Some(
			self.record(Artifact::Receipt, b"uncommitted".to_vec()),
		))
	}

	fn inventory<'job>(
		&'job self,
		stage: UnixComponent<'job>,
		target: UnixComponent<'job>,
	) -> Result<Self::Inventory<'job>, Self::Error> {
		assert_eq!(stage, self.history.stage.component);
		assert_eq!(target, self.history.plan.destination().component);
		self.calls.borrow_mut().push(Call::Inventory);
		Ok(Inventory(self))
	}
}

struct Record<'job> {
	artifact: Artifact,
	bytes: Cursor<Vec<u8>>,
	job: &'job Job,
}

impl Read for Record<'_> {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		assert_ne!(
			self.artifact,
			Artifact::Receipt,
			"uncommitted receipt was read"
		);
		self.bytes.read(bytes)
	}
}

impl InspectionRecord for Record<'_> {
	type Error = Refusal;

	fn length(&self) -> u64 {
		u64::try_from(self.bytes.get_ref().len()).unwrap()
	}

	fn revalidate(&self) -> Result<(), Self::Error> {
		self.job
			.calls
			.borrow_mut()
			.push(Call::Revalidate(self.artifact));
		if self.artifact == Artifact::Segment
			&& matches!(self.job.refusal, Some(Refusal::SegmentChanged))
		{
			return Err(Refusal::SegmentChanged);
		}
		Ok(())
	}
}

struct Inventory<'job>(&'job Job);

impl InspectionInventory for Inventory<'_> {
	type Error = Refusal;
	type Snapshot = DarwinPublicationNames;
	type Stage = DarwinFileIdentity;
	type Reader<'inventory>
		= StageReader<'inventory>
	where
		Self: 'inventory;

	const MAX_READ_BYTES: usize = 8;

	fn stage_directory_identity(&self) -> Option<DarwinFileIdentity> {
		Some(self.0.history.stage.directory)
	}

	fn stage(&self) -> Option<StageObservation<Self::Stage>> {
		let identity = self.0.history.stage.identity;
		Some(StageObservation {
			identity,
			held: identity,
			length: self.0.history.plan.source().length,
		})
	}

	fn open_stage_read_back(&self, stage: Self::Stage) -> Result<Self::Reader<'_>, Self::Error> {
		assert_eq!(stage, self.0.history.stage.identity);
		self.0.calls.borrow_mut().push(Call::OpenStage);
		Ok(StageReader(self.0))
	}

	fn revalidate(&self) -> Result<(), Self::Error> {
		self.0.calls.borrow_mut().push(Call::RevalidateInventory);
		if matches!(self.0.refusal, Some(Refusal::InventoryChanged)) {
			return Err(Refusal::InventoryChanged);
		}
		Ok(())
	}

	fn snapshot(&self) -> Self::Snapshot {
		self.0.calls.borrow_mut().push(Call::Snapshot);
		DarwinPublicationNames {
			stage: DarwinNamespaceObservation::Present(self.0.history.stage.identity),
			target: self.0.target,
		}
	}
}

struct StageReader<'job>(&'job Job);

impl StageReader<'_> {
	fn metadata(&self, uid: u32) -> StageMetadata {
		let metadata = self.0.history.plan.source().metadata;
		StageMetadata {
			uid,
			gid: metadata.gid(),
			mode: u32::from(metadata.mode()),
			atime: (
				metadata.accessed_at().seconds(),
				metadata.accessed_at().nanoseconds(),
			),
			mtime: (
				metadata.modified_at().seconds(),
				metadata.modified_at().nanoseconds(),
			),
		}
	}
}

impl InspectionStageReader for StageReader<'_> {
	type Error = Refusal;

	fn initial_metadata(&self) -> StageMetadata {
		self.0.calls.borrow_mut().push(Call::InitialMetadata);
		self.metadata(self.0.initial_uid)
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.0.calls.borrow_mut().push(Call::ReadStage {
			offset,
			length: bytes.len(),
		});
		let offset = usize::try_from(offset).unwrap();
		bytes.copy_from_slice(&b"sample-data"[offset..offset + bytes.len()]);
		Ok(())
	}

	fn revalidate(&self) -> Result<StageMetadata, Self::Error> {
		self.0.calls.borrow_mut().push(Call::FinalMetadata);
		Ok(self.metadata(self.0.final_uid))
	}
}
