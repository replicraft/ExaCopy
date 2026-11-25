use std::cell::Cell;
use std::io::{self, Cursor, Read};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::ReadView;
use exacopy_endpoint::linux_copy::{CopySourceObservation, InodeTimestamp};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_recovery::RecoveryJobView;
use exacopy_endpoint::linux_staging::ExtendedAttributes;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameWriter};
use exacopy_journal::{
	ApplyMetadataPolicyDigest, ApplyRequestedDurability, ApprovedPublicPlanDigest,
	ApprovedStreamDigest, BasicMetadata, DestinationRootBinding, EntryPreparation, EntryPrepared,
	JobPrepared, JournalEntryId, JournalEpoch, JournalJobId, LinuxFileIdentity, LiveSourceView,
	MetadataRecorded, ObservedTimestamp, OwnerManifest, OwnerProfileId, OwnerTimestamp, OwnerToken,
	PreparedTarget, PublicApplyOwnerManifest, PublicPlanEntryId, RootCapabilityId,
	SourceInodeMetadata, SourceTimes, StageSealed, StreamDigest, StreamEvidence, StreamLength,
	TargetObservation, VerificationRecorded,
};

use crate::copy_planning::linux_baseline_metadata_policy_digest;
use crate::linux::{DestinationPlanBinding, PlanAttempt, SourcePlanBinding};

use super::super::*;

pub(super) const BYTES: &[u8] = b"approved stage";
pub(super) const OTHER: &[u8] = b"changed stage!";
const JOB: LinuxFileIdentity = LinuxFileIdentity::new(7, 10);
const ROOT: LinuxFileIdentity = LinuxFileIdentity::new(7, 11);
pub(super) const STAGE: LinuxFileIdentity = LinuxFileIdentity::new(7, 12);

type TestResult<T> = Result<T, &'static str>;

#[derive(Clone)]
pub(super) struct Artifact {
	identity: LinuxFileIdentity,
	pub(super) bytes: Cursor<Vec<u8>>,
}

impl Artifact {
	pub(super) fn new(identity: LinuxFileIdentity, bytes: Vec<u8>) -> Self {
		Self {
			identity,
			bytes: Cursor::new(bytes),
		}
	}

	fn prepare_record(inode: u64, bytes: Vec<u8>) -> Self {
		Self::new(LinuxFileIdentity::new(7, inode), bytes)
	}
}

impl Read for Artifact {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		self.bytes.read(bytes)
	}
}

impl ReadView for Artifact {
	type Error = &'static str;
	fn length(&self) -> u64 {
		u64::try_from(self.bytes.get_ref().len()).unwrap()
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> TestResult<()> {
		let mut view = self.bytes.clone();
		view.set_position(offset);
		view.read_exact(bytes).map_err(|_| "short read")
	}

	fn recheck_observation(&self) -> TestResult<()> {
		Ok(())
	}
}

impl RecoveryRecord for Artifact {
	type Identity = JobFileIdentity;

	fn identity(&self) -> Self::Identity {
		identity(self.identity)
	}

	fn observation(&self) -> CopySourceObservation {
		let time = InodeTimestamp {
			seconds: 1,
			nanoseconds: 0,
		};
		CopySourceObservation {
			mode: 0o640,
			owner: 1000,
			group: 1000,
			links: 1,
			accessed_at: time,
			modified_at: time,
			changed_at: time,
		}
	}

	fn recheck_inode(&self) -> TestResult<()> {
		Ok(())
	}
	fn check_logical_eof(&self) -> TestResult<()> {
		Ok(())
	}
	fn extended_attributes(&self) -> TestResult<ExtendedAttributes> {
		Ok(ExtendedAttributes::NoneVisible)
	}
}

pub(super) struct Fixture {
	pub(super) owner: Option<Artifact>,
	pub(super) plan: Option<Artifact>,
	pub(super) journal: Option<Artifact>,
	pub(super) stage: Option<Artifact>,
	pub(super) target: Option<Artifact>,
	pub(super) inventory_calls: Cell<u32>,
	pub(super) missing_plan_error: bool,
}

pub(super) struct Inventory<'fixture>(&'fixture Fixture);

impl RecoveryInventoryView for Inventory<'_> {
	type Record = Artifact;
	type Error = &'static str;

	fn stage(&self) -> Option<&Artifact> {
		self.0.stage.as_ref()
	}
	fn target(&self) -> Option<&Artifact> {
		self.0.target.as_ref()
	}
	fn stage_directory_identity(&self) -> Option<JobFileIdentity> {
		self.stage().map(|_| JobFileIdentity {
			device: 7,
			inode: 25,
		})
	}
	fn recheck(&self) -> TestResult<()> {
		Ok(())
	}
}

impl RecoveryJobView for Fixture {
	type ReadError = &'static str;
	type NamespaceError = &'static str;
	type Record = Artifact;
	type Inventory<'a> = Inventory<'a>;

	fn identities(&self) -> (JobFileIdentity, JobFileIdentity) {
		(identity(JOB), identity(ROOT))
	}

	fn open_owner(&self) -> TestResult<Artifact> {
		self.owner.clone().ok_or("missing owner")
	}
	fn open_plan(&self) -> TestResult<Artifact> {
		self.plan.clone().ok_or("missing plan")
	}
	fn open_first_segment(&self) -> TestResult<Artifact> {
		self.journal.clone().ok_or("missing journal")
	}
	fn open_checkpoint(&self, _ordinal: u32) -> TestResult<Artifact> {
		Err("missing checkpoint")
	}
	fn open_optional_receipt(&self) -> TestResult<Option<Artifact>> {
		Ok(None)
	}

	fn inventory(
		&self,
		stage: UnixComponent<'_>,
		target: UnixComponent<'_>,
	) -> TestResult<Inventory<'_>> {
		assert_eq!(stage.as_bytes(), b"private-stage");
		assert_eq!(target.as_bytes(), b"target");
		self.inventory_calls.set(self.inventory_calls.get() + 1);
		Ok(Inventory(self))
	}
}

impl PublicStageJobView for Fixture {
	fn open_optional_owner(&self) -> TestResult<Option<Artifact>> {
		Ok(self.owner.clone())
	}
	fn open_optional_plan(&self) -> TestResult<Option<Artifact>> {
		if self.missing_plan_error {
			return Err("inaccessible plan");
		}
		Ok(self.plan.clone())
	}
	fn open_optional_first_segment(&self) -> TestResult<Option<Artifact>> {
		Ok(self.journal.clone())
	}
}

fn identity(file: LinuxFileIdentity) -> JobFileIdentity {
	JobFileIdentity {
		device: file.device(),
		inode: file.inode(),
	}
}

fn uuid(marker: u8) -> [u8; 16] {
	let mut bytes = [marker; 16];
	bytes[6] = 0x70;
	bytes[8] = 0x80;
	bytes
}

pub(super) fn name(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).unwrap()
}

pub(super) fn plan() -> LocalCopyPlan<'static> {
	let root_id = RootCapabilityId::from_bytes(uuid(7)).unwrap();
	let time = ObservedTimestamp::new(1, 0).unwrap();
	LocalCopyPlan::new(
		PlanAttempt {
			job: JournalJobId::from_bytes(uuid(1)).unwrap(),
			epoch: JournalEpoch::new(1),
			entry: JournalEntryId::from_bytes(uuid(2)),
			job_name: name(b"job"),
			stage_name: name(b"private-stage"),
		},
		SourcePlanBinding {
			root_id,
			root_identity: ROOT,
			file_identity: LinuxFileIdentity::new(7, 13),
			length: u64::try_from(BYTES.len()).unwrap(),
			modified_at: time,
			changed_at: time,
			component: name(b"source"),
		},
		DestinationPlanBinding {
			root: DestinationRootBinding {
				id: root_id,
				identity: ROOT,
			},
			component: name(b"target"),
		},
	)
	.unwrap()
}

pub(super) fn profile_id() -> OwnerProfileId {
	OwnerProfileId::from_bytes(uuid(3)).unwrap()
}
pub(super) fn signer() -> SigningKey {
	SigningKey::from_bytes(&[0x44; 32])
}

pub(super) fn owner(plan: LocalCopyPlan<'_>) -> PublicApplyOwnerRecord {
	PublicApplyOwnerRecord::sign(
		PublicApplyOwnerManifest {
			owner: OwnerManifest {
				token: OwnerToken::from_bytes([0x25; 16]).unwrap(),
				job: plan.attempt().job,
				profile: profile_id(),
				created: OwnerTimestamp::new(1, 0).unwrap(),
				state_root: JOB,
				destination_device: ROOT.device(),
				plan_digest: plan.digest(),
				directories: STAGE_DIRECTORIES.to_vec(),
			},
			binding: PublicApplyBinding {
				public_plan: ApprovedPublicPlanDigest::from_bytes([0x26; 32]),
				public_entry: PublicPlanEntryId::from_bytes(uuid(4)).unwrap(),
				private_entry: plan.attempt().entry,
				epoch: plan.attempt().epoch,
				source_root: plan.source().root_id,
				destination_root: plan.destination().root.id,
				stream_length: StreamLength::new(plan.source().length).unwrap(),
				stream_digest: ApprovedStreamDigest::from_bytes(*blake3::hash(BYTES).as_bytes()),
				metadata_policy: ApplyMetadataPolicyDigest::from_bytes(
					linux_baseline_metadata_policy_digest(),
				),
				expires_at: Some(OwnerTimestamp::new(2, 0).unwrap()),
				requested_durability: ApplyRequestedDurability::ProcessCrash,
			},
		},
		&signer(),
	)
	.unwrap()
}

pub(super) fn journal_payloads(
	plan: LocalCopyPlan<'_>,
	owner: &PublicApplyOwnerRecord,
	bytes: &[u8],
) -> Vec<(FrameKind, Vec<u8>)> {
	let source = plan.source();
	let target = plan.destination();
	let context = plan.context();
	let entry = plan.attempt().entry;
	let timestamp = source.modified_at;
	let length = StreamLength::new(source.length).unwrap();
	let staged = StreamEvidence {
		identity: STAGE,
		length,
		digest: StreamDigest::from_bytes(*blake3::hash(bytes).as_bytes()),
	};
	let expected_metadata = BasicMetadata::new(
		0o640,
		1000,
		1000,
		OwnerTimestamp::new(1, 0).unwrap(),
		OwnerTimestamp::new(1, 0).unwrap(),
	)
	.unwrap();
	vec![
		(
			FrameKind::JobPrepared,
			JobPrepared {
				context,
				owner_digest: owner.digest(),
				destination_root: target.root,
			}
			.encode(),
		),
		(
			FrameKind::EntryPrepared,
			EntryPrepared::new(
				context,
				entry,
				EntryPreparation {
					source: LiveSourceView::new(
						source.file_identity,
						source.length,
						SourceTimes {
							accessed_at: timestamp,
							modified_at: timestamp,
							changed_at: source.changed_at,
						},
					)
					.unwrap(),
					stage: STAGE,
					target: PreparedTarget {
						root: target.root.id,
						component: target.component,
						observation: TargetObservation::AbsentObserved,
					},
					source_metadata: SourceInodeMetadata::no_visible_extended_attributes(
						0o640, 1000, 1000, 1,
					)
					.unwrap(),
				},
			)
			.unwrap()
			.encode(),
		),
		(
			FrameKind::StageSealed,
			StageSealed {
				context,
				entry,
				stage: STAGE,
				length,
			}
			.encode(),
		),
		(
			FrameKind::VerificationRecorded,
			VerificationRecorded::new(
				context,
				entry,
				StreamEvidence {
					identity: source.file_identity,
					..staged
				},
				staged,
			)
			.unwrap()
			.encode(),
		),
		(
			FrameKind::MetadataRecorded,
			MetadataRecorded {
				context,
				entry,
				stage: STAGE,
				metadata: expected_metadata,
			}
			.encode(),
		),
	]
}

pub(super) fn serialize(payloads: impl IntoIterator<Item = (FrameKind, Vec<u8>)>) -> Vec<u8> {
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	for (kind, payload) in payloads {
		writer.append(kind, &payload).unwrap();
	}
	writer.into_inner()
}

impl Fixture {
	pub(super) fn new(frames: usize, staged: Option<&[u8]>) -> Self {
		let plan = plan();
		let owner = owner(plan);
		Self {
			owner: Some(Artifact::prepare_record(14, owner.as_bytes().to_vec())),
			plan: Some(Artifact::prepare_record(15, plan.encode().to_vec())),
			journal: Some(Artifact::prepare_record(
				16,
				serialize(
					journal_payloads(plan, &owner, BYTES)
						.into_iter()
						.take(frames),
				),
			)),
			stage: staged.map(|bytes| Artifact::new(STAGE, bytes.to_vec())),
			target: None,
			inventory_calls: Cell::new(0),
			missing_plan_error: false,
		}
	}

	pub(super) fn inspect(&self) -> InspectionResult<Self, PublicStageInspection> {
		inspect_public_stage_with_job(
			self,
			name(b"job"),
			RecoveryProfile {
				id: profile_id(),
				verifying_key: &signer().verifying_key(),
			},
			&mut [0; 4],
		)
	}

	pub(super) fn observation(&self) -> PublicStageObservation {
		let PublicStageInspection::Authenticated {
			history: PublicStageHistory::Journal { observation, .. },
			..
		} = self.inspect().unwrap()
		else {
			panic!("fixture expected an authenticated journal");
		};
		observation
	}
}
