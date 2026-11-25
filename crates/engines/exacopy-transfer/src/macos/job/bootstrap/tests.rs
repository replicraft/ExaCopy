use std::cell::RefCell;
use std::num::NonZeroU64;

use ed25519_dalek::SigningKey;
use exacopy_endpoint::{JournalFileBarrier, UnixComponent};
use exacopy_journal::{
	DarwinFileIdentity, DarwinOwnerRecord, DarwinRootBinding, DarwinVolumeIdentity,
	DurableJournalError, JournalEntryId, JournalEpoch, JournalJobId, ObservedTimestamp, OwnerError,
	OwnerProfileId, OwnerTimestamp, OwnerToken, RootCapabilityId,
};

use super::super::{DarwinJobProfile, JobPreparationStep};
use super::capabilities::{PrivateJob, PrivateJournalDirectory};
use super::engine::{self, BootstrapError};
use crate::macos::job::admission::{
	AdmissionFailure, ReadOnlySource, SourceIdentities, SourceMetadataObservation, Timestamp,
};
use crate::macos::journal_fixture::SimulatedSegment;
use crate::macos::plan::{
	DarwinCopyPlan, DestinationPlanBinding, PlanAttempt, SourceMetadata, SourcePlanBinding,
};

const UID: u32 = 501;
const JOB_UUID: [u8; 16] = uuid(5);
const ARTIFACTS: [JobPreparationStep; 4] = [
	JobPreparationStep::OwnerRecord,
	JobPreparationStep::PlanRecord,
	JobPreparationStep::JournalDirectory,
	JobPreparationStep::FirstSegment,
];

#[test]
fn preparation_stops_at_each_uncertain_artifact_and_preserves_its_phase() {
	let signer = SigningKey::from_bytes(&[1; 32]);
	let (plan, profile, destination) = fixture(&signer);
	for (position, step) in ARTIFACTS.into_iter().enumerate() {
		let job = TestJob::<true>::new(UID, Some(step));
		assert!(matches!(
			engine::prepare(&plan, profile, &job, destination),
			Err(BootstrapError::Artifact {
				step: actual,
				source: UncertainArtifact(attempted),
			}) if actual == step && attempted == step
		));
		assert_eq!(*job.attempted.borrow(), ARTIFACTS[..=position]);
	}
}

#[test]
fn invalid_owner_stops_preparation_before_record_writes() {
	let signer = SigningKey::from_bytes(&[1; 32]);
	let (plan, profile, destination) = fixture(&signer);
	let job = TestJob::<true>::new(0, None);
	assert!(matches!(
		engine::prepare(&plan, profile, &job, destination),
		Err(BootstrapError::Owner(OwnerError::InvalidOwnerUid))
	));
	assert!(job.attempted.borrow().is_empty());
}

#[test]
fn invalid_segment_returns_no_preparation_and_preserves_signed_inputs() {
	let signer = SigningKey::from_bytes(&[1; 32]);
	let (plan, profile, destination) = fixture(&signer);
	let job = TestJob::<true>::new(UID, None);
	assert!(matches!(
		engine::prepare(&plan, profile, &job, destination),
		Err(BootstrapError::Journal(DurableJournalError::NotRegularFile))
	));
	assert_eq!(*job.attempted.borrow(), ARTIFACTS);
	assert_eq!(*job.plan.borrow(), plan.encode());
	let owner = DarwinOwnerRecord::decode(&job.owner.borrow(), profile.id, &signer.verifying_key())
		.unwrap();
	assert_eq!(owner.manifest().state_root, job.identity().unwrap());
	assert_eq!(
		owner.manifest().destination_volume,
		destination.identity.volume()
	);
	assert_eq!(owner.manifest().plan_digest, plan.digest());
}

#[test]
fn weaker_segment_barrier_refuses_before_any_bootstrap_effect() {
	let signer = SigningKey::from_bytes(&[1; 32]);
	let (plan, profile, destination) = fixture(&signer);
	let job = TestJob::<false>::new(UID, None);
	assert!(matches!(
		engine::prepare(&plan, profile, &job, destination),
		Err(BootstrapError::Journal(
			DurableJournalError::UnexpectedBarrier {
				expected: JournalFileBarrier::DarwinFullFsync,
				actual: JournalFileBarrier::SyncAll,
			}
		))
	));
	assert!(job.attempted.borrow().is_empty());
	assert!(job.owner.borrow().is_empty());
	assert!(job.plan.borrow().is_empty());
}

struct UncertainArtifact(JobPreparationStep);

struct TestJob<const DARWIN: bool = true> {
	uid: u32,
	fail_on: Option<JobPreparationStep>,
	attempted: RefCell<Vec<JobPreparationStep>>,
	owner: RefCell<Vec<u8>>,
	plan: RefCell<Vec<u8>>,
}

impl<const DARWIN: bool> TestJob<DARWIN> {
	fn new(uid: u32, fail_on: Option<JobPreparationStep>) -> Self {
		Self {
			uid,
			fail_on,
			attempted: RefCell::new(Vec::new()),
			owner: RefCell::new(Vec::new()),
			plan: RefCell::new(Vec::new()),
		}
	}

	fn attempt(&self, step: JobPreparationStep) -> Result<(), UncertainArtifact> {
		self.attempted.borrow_mut().push(step);
		if self.fail_on == Some(step) {
			return Err(UncertainArtifact(step));
		}
		Ok(())
	}
}

impl<const DARWIN: bool> PrivateJob for TestJob<DARWIN> {
	type Error = UncertainArtifact;
	type JournalDirectory<'job> = TestJournalDirectory<'job, DARWIN>;

	fn owner_uid(&self) -> u32 {
		self.uid
	}

	fn identity(&self) -> Result<DarwinFileIdentity, OwnerError> {
		Ok(identity(3))
	}

	fn write_owner_record(&self, bytes: &[u8]) -> Result<(), UncertainArtifact> {
		self.attempt(JobPreparationStep::OwnerRecord)?;
		self.owner.borrow_mut().extend_from_slice(bytes);
		Ok(())
	}

	fn write_plan_record(&self, bytes: &[u8]) -> Result<(), UncertainArtifact> {
		self.attempt(JobPreparationStep::PlanRecord)?;
		self.plan.borrow_mut().extend_from_slice(bytes);
		Ok(())
	}

	fn create_journal_directory(&self) -> Result<Self::JournalDirectory<'_>, UncertainArtifact> {
		self.attempt(JobPreparationStep::JournalDirectory)?;
		Ok(TestJournalDirectory(self))
	}
}

struct TestJournalDirectory<'job, const DARWIN: bool>(&'job TestJob<DARWIN>);

impl<const DARWIN: bool> PrivateJournalDirectory for TestJournalDirectory<'_, DARWIN> {
	type Error = UncertainArtifact;

	type Segment = SimulatedSegment<DARWIN>;

	fn create_first_segment(self) -> Result<Self::Segment, UncertainArtifact> {
		self.0.attempt(JobPreparationStep::FirstSegment)?;
		// The engine must refuse a nonregular segment before writing.
		Ok(SimulatedSegment::new(Vec::new(), false))
	}
}

fn fixture(
	signer: &SigningKey,
) -> (
	DarwinCopyPlan<'static>,
	DarwinJobProfile<'_>,
	DarwinRootBinding,
) {
	let profile = DarwinJobProfile {
		id: OwnerProfileId::from_bytes(uuid(2)).unwrap(),
		signer,
		created: OwnerTimestamp::new(20, 0).unwrap(),
		owner_token: OwnerToken::from_bytes(uuid(3)).unwrap(),
	};
	let destination = DarwinRootBinding {
		id: RootCapabilityId::from_bytes(uuid(4)).unwrap(),
		identity: identity(1),
	};
	let timestamp = ObservedTimestamp::new(10, 0).unwrap();
	let plan = DarwinCopyPlan::new(
		PlanAttempt {
			job: JournalJobId::from_bytes(JOB_UUID).unwrap(),
			epoch: JournalEpoch::new(1),
			entry: JournalEntryId::from_bytes([6; 16]),
			profile: profile.id,
		},
		SourcePlanBinding {
			root_id: destination.id,
			root_identity: destination.identity,
			file_identity: identity(2),
			length: 1,
			metadata: SourceMetadata::new(0o600, UID, 20, timestamp, timestamp, timestamp).unwrap(),
			component: UnixComponent::new(b"source").unwrap(),
		},
		DestinationPlanBinding {
			root_id: destination.id,
			root_identity: destination.identity,
			component: UnixComponent::new(b"target").unwrap(),
		},
	)
	.unwrap();
	(plan, profile, destination)
}

fn identity(inode: u64) -> DarwinFileIdentity {
	DarwinFileIdentity::new(
		DarwinVolumeIdentity::new(1, [2, 3]).unwrap(),
		NonZeroU64::new(inode).unwrap(),
		None,
		OwnerTimestamp::new(10, 0).unwrap(),
	)
}

const fn uuid(marker: u8) -> [u8; 16] {
	let mut bytes = [marker; 16];
	bytes[6] = 0x70;
	bytes[8] = 0x80;
	bytes
}

#[test]
fn creation_requires_authorized_profile_destination_and_source_in_order() {
	use super::{BootstrapInputs, JobCreationFailure, admit_and_create};

	let signer = SigningKey::from_bytes(&[1; 32]);
	let (plan, profile, destination) = fixture(&signer);
	let trace = RefCell::new(Vec::new());
	let root = AdmissionRoot(&trace);
	let source = AdmissionSource(&trace, plan.source());
	let untrusted = RootCapabilityId::from_bytes(uuid(9)).unwrap();
	let inputs = |profile, source_root_id, destination_root_id| BootstrapInputs {
		source: &source,
		source_root_id,
		destination_root_id,
		profile,
	};

	let mismatched = DarwinJobProfile {
		id: OwnerProfileId::from_bytes(uuid(9)).unwrap(),
		..profile
	};
	assert!(matches!(
		admit_and_create(
			&plan,
			inputs(mismatched, destination.id, destination.id),
			&root
		),
		Err(JobCreationFailure::Profile(_))
	));
	assert!(trace.borrow().is_empty());
	assert!(matches!(
		admit_and_create(&plan, inputs(profile, destination.id, untrusted), &root),
		Err(JobCreationFailure::Destination(AdmissionFailure::Mismatch))
	));
	assert_eq!(trace.take(), ["name"]);
	assert!(matches!(
		admit_and_create(&plan, inputs(profile, untrusted, destination.id), &root),
		Err(JobCreationFailure::Source(AdmissionFailure::Mismatch))
	));
	assert_eq!(trace.take(), ["name", "destination"]);

	let job = admit_and_create(
		&plan,
		inputs(profile, destination.id, destination.id),
		&root,
	)
	.unwrap();
	assert_eq!(job.directory, JOB_UUID);
	assert_eq!(job.destination, destination);
	assert_eq!(
		trace.take(),
		[
			"name",
			"destination",
			"source",
			"metadata",
			"change time",
			"create"
		]
	);
}

struct AdmissionRoot<'trace>(&'trace RefCell<Vec<&'static str>>);

impl super::PrivateJobRoot for AdmissionRoot<'_> {
	type Name = [u8; 16];
	type Directory<'root>
		= [u8; 16]
	where
		Self: 'root;
	type Error = std::convert::Infallible;

	fn job_name(&self, bytes: [u8; 16]) -> Result<Self::Name, exacopy_model::InvalidJobId> {
		self.0.borrow_mut().push("name");
		Ok(bytes)
	}

	fn observe_empty(
		&self,
		target: UnixComponent<'_>,
	) -> Result<DarwinFileIdentity, AdmissionFailure<Self::Error>> {
		self.0.borrow_mut().push("destination");
		assert_eq!(target.as_bytes(), b"target");
		Ok(identity(1))
	}

	fn create_job(&self, name: Self::Name) -> Result<Self::Directory<'_>, Self::Error> {
		self.0.borrow_mut().push("create");
		Ok(name)
	}
}

struct AdmissionSource<'trace>(
	&'trace RefCell<Vec<&'static str>>,
	SourcePlanBinding<'trace>,
);

impl ReadOnlySource for AdmissionSource<'_> {
	type Error = std::convert::Infallible;

	fn component(&self) -> UnixComponent<'_> {
		self.1.component
	}

	fn length(&self) -> u64 {
		self.1.length
	}

	fn observe_identities(&self) -> Result<SourceIdentities, AdmissionFailure<Self::Error>> {
		self.0.borrow_mut().push("source");
		Ok(SourceIdentities {
			root: self.1.root_identity,
			file: self.1.file_identity,
		})
	}

	fn check_pre_read_metadata(&self) -> Result<SourceMetadataObservation, Self::Error> {
		self.0.borrow_mut().push("metadata");
		let metadata = self.1.metadata;
		Ok(SourceMetadataObservation {
			uid: metadata.uid().get(),
			gid: metadata.gid(),
			mode: u32::from(metadata.mode()),
			accessed: metadata.accessed_at().into(),
			modified: metadata.modified_at().into(),
		})
	}

	fn change_time(&self) -> Result<Timestamp, Self::Error> {
		self.0.borrow_mut().push("change time");
		Ok(self.1.metadata.changed_at().into())
	}
}
