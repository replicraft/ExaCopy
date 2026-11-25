use std::cell::RefCell;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::rc::Rc;

use exacopy_endpoint::linux_job::{
	JobBootstrapRoot, JobFileIdentity, JobJournalDirectory, JobRecord, JobWorkspace,
};
use exacopy_endpoint::{JournalFileBarrier, JournalSegment, UnixComponent};
use exacopy_journal::{
	DurableJournalError, JobPrepared, JournalContext, JournalEpoch, JournalJobId,
	LinuxFileIdentity, OwnerError, OwnerStateDirectory, PlanDigest,
};

use super::protocol::{BootstrapFailure, InitialJournal, prepare};
use super::{
	BootstrapError, JobBootstrap, JobStep, OwnerProfileId, OwnerRecord, OwnerTimestamp, OwnerToken,
	PreparedJob,
};
use super::{RootCapabilityId, SigningKey};

const DESTINATION: JobFileIdentity = JobFileIdentity {
	device: 7,
	inode: 101,
};
const JOB: JobFileIdentity = JobFileIdentity {
	device: 7,
	inode: 102,
};
const PLAN: &[u8] = b"canonical plan fixture bytes";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
	Namespace(JobStep),
	WriteOwner,
	SyncOwner,
	WritePlan,
	SyncPlan,
	AdmitSegment,
	AppendPrepared,
}

const WITH_PLAN: [Effect; 14] = [
	Effect::Namespace(JobStep::CreateJob),
	Effect::Namespace(JobStep::CreateOwner),
	Effect::WriteOwner,
	Effect::SyncOwner,
	Effect::Namespace(JobStep::CreatePlan),
	Effect::WritePlan,
	Effect::SyncPlan,
	Effect::Namespace(JobStep::CreateJournal),
	Effect::Namespace(JobStep::CreateSegment),
	Effect::AdmitSegment,
	Effect::Namespace(JobStep::SyncJournal),
	Effect::Namespace(JobStep::SyncJob),
	Effect::Namespace(JobStep::SyncDestination),
	Effect::AppendPrepared,
];

#[derive(Default, Debug)]
struct Trace {
	effects: Vec<Effect>,
	owner: Vec<u8>,
	plan: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Root {
	trace: Rc<RefCell<Trace>>,
	fail: Option<Effect>,
}

impl Root {
	fn new(fail: Option<Effect>) -> Self {
		Self {
			trace: Rc::new(RefCell::new(Trace::default())),
			fail,
		}
	}

	fn record(&self, effect: Effect) -> Result<(), Effect> {
		self.trace.borrow_mut().effects.push(effect);
		if self.fail == Some(effect) {
			Err(effect)
		} else {
			Ok(())
		}
	}
}

#[derive(Debug)]
struct Workspace(Root);

struct JournalDirectory(Root);

struct Record {
	root: Root,
	kind: RecordKind,
}

enum RecordKind {
	Owner,
	Plan,
}

impl JobBootstrapRoot<'_> for Root {
	type Error = Effect;
	type Job = Workspace;

	fn identity(&self) -> JobFileIdentity {
		DESTINATION
	}

	fn create_job_directory(&self, name: UnixComponent<'_>) -> Result<Self::Job, Self::Error> {
		assert_eq!(name.as_bytes(), b"test-job");
		self.record(Effect::Namespace(JobStep::CreateJob))?;
		Ok(Workspace(self.clone()))
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		self.record(Effect::Namespace(JobStep::SyncDestination))
	}
}

impl JobWorkspace for Workspace {
	type Error = Effect;
	type Record = Record;
	type Segment = Root;
	type Journal<'job> = JournalDirectory;

	fn identity(&self) -> JobFileIdentity {
		JOB
	}

	fn create_owner_record(&self) -> Result<Self::Record, Self::Error> {
		self.0.record(Effect::Namespace(JobStep::CreateOwner))?;
		Ok(Record {
			root: self.0.clone(),
			kind: RecordKind::Owner,
		})
	}

	fn create_plan_record(&self) -> Result<Self::Record, Self::Error> {
		self.0.record(Effect::Namespace(JobStep::CreatePlan))?;
		Ok(Record {
			root: self.0.clone(),
			kind: RecordKind::Plan,
		})
	}

	fn create_journal_directory(&self) -> Result<Self::Journal<'_>, Self::Error> {
		self.0.record(Effect::Namespace(JobStep::CreateJournal))?;
		Ok(JournalDirectory(self.0.clone()))
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		self.0.record(Effect::Namespace(JobStep::SyncJob))
	}
}

impl Write for Record {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		let effect = match self.kind {
			RecordKind::Owner => Effect::WriteOwner,
			RecordKind::Plan => Effect::WritePlan,
		};
		self.root.record(effect).map_err(io_failure)?;
		let mut trace = self.root.trace.borrow_mut();
		let record = match self.kind {
			RecordKind::Owner => &mut trace.owner,
			RecordKind::Plan => &mut trace.plan,
		};
		record.extend_from_slice(bytes);
		Ok(bytes.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

impl JobRecord for Record {
	fn sync_all(&self) -> io::Result<()> {
		let effect = match self.kind {
			RecordKind::Owner => Effect::SyncOwner,
			RecordKind::Plan => Effect::SyncPlan,
		};
		self.root.record(effect).map_err(io_failure)
	}
}

fn io_failure(effect: Effect) -> io::Error {
	io::Error::other(format!("injected failure at {effect:?}"))
}

impl JobJournalDirectory for JournalDirectory {
	type Error = Effect;
	type Segment = Root;

	fn create_first_segment(&self) -> Result<Self::Segment, Self::Error> {
		self.0.record(Effect::Namespace(JobStep::CreateSegment))?;
		Ok(self.0.clone())
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		self.0.record(Effect::Namespace(JobStep::SyncJournal))
	}
}

struct Journal(Root);

impl InitialJournal for Journal {
	type Segment = Root;
	type Error = Effect;
	type Frame = JobPrepared;

	fn from_new_segment(segment: Self::Segment) -> Result<Self, Self::Error> {
		segment.record(Effect::AdmitSegment)?;
		Ok(Self(segment))
	}

	fn append_job_prepared(
		&mut self,
		preparation: JobPrepared,
	) -> Result<Self::Frame, Self::Error> {
		self.0.record(Effect::AppendPrepared)?;
		Ok(preparation)
	}
}

fn request() -> JobBootstrap<'static> {
	JobBootstrap {
		name: UnixComponent::new(b"test-job").expect("valid fixture name"),
		context: JournalContext {
			job: JournalJobId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
				.expect("valid fixture job UUIDv7"),
			epoch: JournalEpoch::new(23),
			plan_digest: PlanDigest::from_bytes([0x71; 32]),
		},
		destination_id: RootCapabilityId::from_bytes([
			0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 2,
		])
		.expect("valid fixture root UUIDv4"),
		profile: OwnerProfileId::from_bytes([0x34; 16]).expect("valid fixture profile"),
		created: OwnerTimestamp::new(1_700_000_000, 123_456_789).expect("valid fixture timestamp"),
		owner_token: OwnerToken::from_bytes([0x72; 16]).expect("valid fixture owner token"),
	}
}

#[test]
fn preparation_binds_signed_owner_and_plan_after_all_prerequisite_barriers() {
	let root = Root::new(None);
	let request = request();
	let signer = SigningKey::from_bytes(&[0x57; 32]);
	let prepared =
		prepare::<_, Journal>(&root, request, &signer, Some(PLAN)).expect("complete bootstrap");

	let trace = root.trace.borrow();
	assert_eq!(trace.effects, WITH_PLAN);
	assert_eq!(trace.plan, PLAN);
	let owner = OwnerRecord::decode(&trace.owner, request.profile, &signer.verifying_key())
		.expect("authenticate the written owner record");
	assert_eq!(prepared.owner.as_bytes(), owner.as_bytes());
	assert_eq!(owner.manifest().job, request.context.job);
	assert_eq!(owner.manifest().plan_digest, request.context.plan_digest);
	assert_eq!(owner.manifest().destination_device, DESTINATION.device);
	assert_eq!(
		owner.manifest().state_root,
		LinuxFileIdentity::new(JOB.device, JOB.inode)
	);
	assert_eq!(
		owner.manifest().directories,
		[
			OwnerStateDirectory::Checkpoints,
			OwnerStateDirectory::Journal,
			OwnerStateDirectory::Receipts,
			OwnerStateDirectory::Stage,
		]
	);
	assert_eq!(prepared.initial_frame.context, request.context);
	assert_eq!(prepared.initial_frame.owner_digest, owner.digest());
	assert_eq!(
		prepared.initial_frame.destination_root.id,
		request.destination_id
	);
	assert_eq!(
		prepared.initial_frame.destination_root.identity,
		LinuxFileIdentity::new(DESTINATION.device, DESTINATION.inode)
	);
}

#[test]
fn bootstrap_without_a_plan_omits_its_effects_and_optional_state_directories() {
	let root = Root::new(None);
	let signer = SigningKey::from_bytes(&[0x57; 32]);
	let prepared =
		prepare::<_, Journal>(&root, request(), &signer, None).expect("complete basic bootstrap");

	let expected = [&WITH_PLAN[..4], &WITH_PLAN[7..]].concat();
	let trace = root.trace.borrow();
	assert_eq!(trace.effects, expected);
	assert!(trace.plan.is_empty());
	assert_eq!(
		prepared.owner.manifest().directories,
		[OwnerStateDirectory::Journal, OwnerStateDirectory::Stage]
	);
}

#[test]
fn each_failed_effect_stops_bootstrap_at_that_effect() {
	let signer = SigningKey::from_bytes(&[0x57; 32]);
	for (index, stopped_at) in WITH_PLAN.into_iter().enumerate() {
		let root = Root::new(Some(stopped_at));
		let Err(error) = prepare::<_, Journal>(&root, request(), &signer, Some(PLAN)) else {
			panic!("bootstrap unexpectedly continued past {stopped_at:?}");
		};
		let failure = match error {
			BootstrapFailure::Namespace(step, cause) => {
				assert_eq!(Effect::Namespace(step), cause);
				cause
			}
			BootstrapFailure::WriteOwner(_) => Effect::WriteOwner,
			BootstrapFailure::SyncOwner(_) => Effect::SyncOwner,
			BootstrapFailure::WritePlan(_) => Effect::WritePlan,
			BootstrapFailure::SyncPlan(_) => Effect::SyncPlan,
			BootstrapFailure::Journal(cause) => cause,
			BootstrapFailure::Owner(error) => panic!("unexpected owner validation error: {error}"),
		};
		assert_eq!(failure, stopped_at);
		assert_eq!(root.trace.borrow().effects, WITH_PLAN[..=index]);
	}
}

#[test]
fn token_alias_is_rejected_before_namespace_effects() {
	let root = Root::new(None);
	let signer = SigningKey::from_bytes(&[0x57; 32]);
	let request = request();
	for alias in [request.context.job.as_bytes(), request.profile.as_bytes()] {
		let invalid = JobBootstrap {
			owner_token: OwnerToken::from_bytes(*alias).expect("valid bytes for aliased token"),
			..request
		};
		assert!(matches!(
			prepare::<_, Journal>(&root, invalid, &signer, Some(PLAN)),
			Err(BootstrapFailure::Owner(OwnerError::InvalidToken))
		));
		assert!(root.trace.borrow().effects.is_empty());
	}
}

#[test]
fn public_stage_syncs_only_the_mandatory_public_owner_before_preparation() {
	use exacopy_journal::{
		ApplyMetadataPolicyDigest, ApplyRequestedDurability, ApprovedPublicPlanDigest,
		ApprovedStreamDigest, JournalEntryId, PublicApplyBinding, PublicApplyOwnerRecord,
		PublicPlanEntryId, StreamLength,
	};

	use super::protocol::prepare_public;

	let request = request();
	let root = Root::new(None);
	let signer = SigningKey::from_bytes(&[0x57; 32]);
	let binding = PublicApplyBinding {
		public_plan: ApprovedPublicPlanDigest::from_bytes([0x11; 32]),
		public_entry: PublicPlanEntryId::from_bytes([0x22; 16]).unwrap(),
		private_entry: JournalEntryId::from_bytes([0x33; 16]),
		epoch: request.context.epoch,
		source_root: request.destination_id,
		destination_root: request.destination_id,
		stream_length: StreamLength::new(29).unwrap(),
		stream_digest: ApprovedStreamDigest::from_bytes([0x44; 32]),
		metadata_policy: ApplyMetadataPolicyDigest::from_bytes([0x55; 32]),
		expires_at: None,
		requested_durability: ApplyRequestedDurability::ProcessCrash,
	};
	let prepared = prepare_public::<_, Journal>(&root, request, &signer, PLAN, binding).unwrap();
	let trace = root.trace.borrow();
	assert_eq!(trace.effects, WITH_PLAN);
	assert_eq!(trace.plan, PLAN);
	let key = signer.verifying_key();
	let authenticated =
		PublicApplyOwnerRecord::decode(&trace.owner, request.profile, &key).unwrap();
	assert_eq!(authenticated.manifest().binding, binding);
	assert_eq!(
		authenticated.manifest().owner.plan_digest,
		request.context.plan_digest
	);
	assert_eq!(prepared.initial_frame.owner_digest, authenticated.digest());
	assert_eq!(
		OwnerRecord::decode(&trace.owner, request.profile, &key),
		Err(OwnerError::WrongDomain)
	);

	let interrupted = Root::new(Some(Effect::Namespace(JobStep::CreateJournal)));
	assert!(prepare_public::<_, Journal>(&interrupted, request, &signer, PLAN, binding).is_err());
	let trace = interrupted.trace.borrow();
	assert!(!trace.effects.contains(&Effect::AppendPrepared));
	assert_eq!(
		PublicApplyOwnerRecord::decode(&trace.owner, request.profile, &key).unwrap(),
		authenticated
	);
	assert_eq!(
		OwnerRecord::decode(&trace.owner, request.profile, &key),
		Err(OwnerError::WrongDomain)
	);
}

#[test]
fn production_bootstrap_refuses_another_barrier_before_creating_the_job() {
	let root = Root::new(None);
	let signer = SigningKey::from_bytes(&[0x57; 32]);
	assert!(matches!(
		PreparedJob::create(&root, request(), &signer),
		Err(BootstrapError::Journal(
			DurableJournalError::UnexpectedBarrier {
				expected: JournalFileBarrier::SyncAll,
				actual: JournalFileBarrier::DarwinFullFsync,
			}
		))
	));
	assert!(root.trace.borrow().effects.is_empty());
}

impl Read for Root {
	fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
		Err(io::Error::other("wrong barrier fixture"))
	}
}

impl Write for Root {
	fn write(&mut self, _: &[u8]) -> io::Result<usize> {
		Err(io::Error::other("wrong barrier fixture"))
	}
	fn flush(&mut self) -> io::Result<()> {
		Err(io::Error::other("wrong barrier fixture"))
	}
}

impl Seek for Root {
	fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
		Err(io::Error::other("wrong barrier fixture"))
	}
}

impl JournalSegment for Root {
	const BARRIER: JournalFileBarrier = JournalFileBarrier::DarwinFullFsync;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		Err(io::Error::other("wrong barrier fixture"))
	}
	fn sync(&self) -> io::Result<()> {
		Err(io::Error::other("wrong barrier fixture"))
	}
}
