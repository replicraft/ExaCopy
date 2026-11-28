use std::io;

use exacopy_content::RangeMeasurement;
use exacopy_endpoint::JournalSegment;
use exacopy_endpoint::linux_apply::{
	ApplyJobRecord, ApplyRecord, GuardedCheckpointPages, GuardedCopyJob, GuardedJobRoot,
	GuardedJournalDirectory, HeldJobRecord, LocalApplyAdmission,
};
use exacopy_endpoint::linux_job::{JobBootstrapRoot, JobFileIdentity, JobWorkspace};
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DestinationRootBinding, DurableJournal, DurableJournalError, JobPrepared, OwnerDigest,
	PublicApplyOwnerManifest, PublicApplyOwnerRecord, RangeCheckpoint, RangePage,
	SourceMeasurementId, StreamDigest, SyncedFrame,
};
use exacopy_model::CopyBinding;

use super::super::super::{
	planning::journal_identity,
	records::{EntryEvidence, RecordedSeal, SealEvidence},
};
use super::{CheckedApplyAuthority, CheckedCopyError, PublicApplyStageRequest, append};
use crate::linux::job::{
	check_linux_barrier, copy_bootstrap_request, owner_manifest, validate_owner_token,
};
use crate::linux::{BootstrapError, JobStep, LocalCopyPlan};
use crate::linux_staging::{StageFailure, StageRecords};

pub(super) struct Pins<H> {
	owner: PublicApplyOwnerRecord,
	owner_pin: H,
	plan_bytes: Vec<u8>,
	plan_pin: H,
}

impl<H> Pins<H> {
	pub(super) fn owner_digest(&self) -> OwnerDigest {
		self.owner.digest()
	}

	pub(super) fn recheck<J, R, S, P, C, A>(
		&self,
		job: &J,
		request: &PublicApplyStageRequest<'_, '_, '_>,
	) -> Result<(), CheckedCopyError<R, S, P, C, A>>
	where
		H: HeldJobRecord<J, Error = S>,
	{
		let mut owner_bytes = vec![0; self.owner.as_bytes().len()];
		self.owner_pin
			.read_exact_job_record(job, &mut owner_bytes)
			.map_err(CheckedCopyError::Artifact)?;
		let owner = PublicApplyOwnerRecord::decode(
			&owner_bytes,
			request.profile.id,
			&request.profile.signer.verifying_key(),
		)
		.map_err(CheckedCopyError::Owner)?;
		let mut plan_bytes = vec![0; self.plan_bytes.len()];
		self.plan_pin
			.read_exact_job_record(job, &mut plan_bytes)
			.map_err(CheckedCopyError::Artifact)?;
		let plan = LocalCopyPlan::decode(&plan_bytes).map_err(CheckedCopyError::Plan)?;
		if owner.as_bytes() != self.owner.as_bytes()
			|| owner.manifest().binding != request.binding
			|| plan != *request.private_plan
			|| plan_bytes != self.plan_bytes
		{
			return Err(CheckedCopyError::Binding);
		}
		Ok(())
	}
}

type Prepared<J> = (
	J,
	Pins<<J as GuardedCopyJob>::HeldRecord>,
	DurableJournal<<J as JobWorkspace>::Segment>,
);
type BootstrapFailure<'root, D, J, R, A> = CheckedCopyError<
	R,
	<D as JobBootstrapRoot<'root>>::Error,
	<J as exacopy_endpoint::linux_copy::CopyWorkspace>::PublishError,
	<D as GuardedJobRoot<'root>>::CreateError,
	<A as CheckedApplyAuthority>::Error,
>;

pub(super) fn bootstrap<'root, D, J, R, A>(
	root: &'root D,
	request: &PublicApplyStageRequest<'_, '_, '_>,
	authority: &A,
) -> Result<Prepared<J>, BootstrapFailure<'root, D, J, R, A>>
where
	D: GuardedJobRoot<'root, Job = J>,
	J: GuardedCopyJob + JobWorkspace<Error = D::Error>,
	J::Segment: JournalSegment,
	A: CheckedApplyAuthority,
{
	let io =
		|step| move |source| CheckedCopyError::Bootstrap(BootstrapError::Platform { step, source });
	check_linux_barrier::<J::Segment>()
		.map_err(|cause| CheckedCopyError::Journal(FrameKind::JobPrepared, cause))?;
	let boot = copy_bootstrap_request(request.private_plan, request.profile);
	validate_owner_token(boot).map_err(CheckedCopyError::Owner)?;
	let identity = journal_identity(root.identity());
	let job = root
		.create_job_admitted(boot.name, authority)
		.map_err(CheckedCopyError::CreateJob)?;
	let manifest = PublicApplyOwnerManifest {
		owner: owner_manifest(boot, identity, job.identity(), true),
		binding: request.binding,
	};
	let owner = PublicApplyOwnerRecord::sign(manifest, request.profile.signer)
		.map_err(CheckedCopyError::Owner)?;
	let owner_pin = job
		.seal_job_record(ApplyJobRecord::Owner, owner.as_bytes(), authority)
		.map_err(|cause| CheckedCopyError::BootstrapRecord(ApplyJobRecord::Owner, cause))?;
	let plan_bytes = request.private_plan.encode();
	let plan_pin = job
		.seal_job_record(ApplyJobRecord::PrivatePlan, &plan_bytes, authority)
		.map_err(|cause| CheckedCopyError::BootstrapRecord(ApplyJobRecord::PrivatePlan, cause))?;
	let pins = Pins {
		owner,
		owner_pin,
		plan_bytes,
		plan_pin,
	};
	pins.recheck(&job, request)?;
	let owner_digest = pins.owner_digest();
	authority
		.bind_owner(owner_digest)
		.map_err(CheckedCopyError::Authority)?;
	let directory = job
		.create_journal_admitted(authority)
		.map_err(io(JobStep::CreateJournal))?;
	let segment = directory
		.create_first_segment_admitted(authority)
		.map_err(io(JobStep::CreateSegment))?;
	let mut journal = DurableJournal::from_new_segment(segment)
		.map_err(|cause| CheckedCopyError::Journal(FrameKind::JobPrepared, cause))?;
	directory
		.sync_journal_admitted(authority)
		.map_err(io(JobStep::SyncJournal))?;
	job.sync_job_admitted(authority)
		.map_err(io(JobStep::SyncJob))?;
	root.sync_destination_admitted(authority)
		.map_err(io(JobStep::SyncDestination))?;
	let preparation = JobPrepared {
		context: boot.context,
		owner_digest,
		destination_root: DestinationRootBinding {
			id: boot.destination_id,
			identity,
		},
	};
	let (_, _prepared_frame) = append(
		&mut journal,
		FrameKind::JobPrepared,
		ApplyRecord::Prepared,
		preparation.encode(),
		authority,
	)
	.map_err(|cause| CheckedCopyError::Journal(FrameKind::JobPrepared, cause))?;
	drop(directory);
	Ok((job, pins, journal))
}

pub(super) struct GuardedRecords<'records, 'name, Pages, Segment, A> {
	entry: &'records EntryEvidence<'name>,
	pages: &'records Pages,
	journal: &'records mut DurableJournal<Segment>,
	authority: &'records A,
	binding: CopyBinding,
	ordinal: u32,
}

impl<'records, 'name, Pages, Segment, A> GuardedRecords<'records, 'name, Pages, Segment, A> {
	pub(super) fn new(
		entry: &'records EntryEvidence<'name>,
		pages: &'records Pages,
		journal: &'records mut DurableJournal<Segment>,
		authority: &'records A,
		binding: CopyBinding,
	) -> Self {
		Self {
			entry,
			pages,
			journal,
			authority,
			binding,
			ordinal: 1,
		}
	}
}

impl<Identity, R, Pages, Segment, A> StageRecords<Identity, R, Pages::Error>
	for GuardedRecords<'_, '_, Pages, Segment, A>
where
	Identity: Into<JobFileIdentity>,
	Pages: GuardedCheckpointPages,
	Segment: JournalSegment,
	A: CheckedApplyAuthority,
{
	fn begin(
		&mut self,
		stage: Identity,
	) -> Result<SourceMeasurementId, StageFailure<R, Pages::Error>> {
		let stage = journal_identity(stage.into());
		let record = self
			.entry
			.prepared(stage)
			.map_err(StageFailure::EntryPreparation)?;
		self.authority
			.bind_stage(self.binding, stage)
			.map_err(|cause| {
				StageFailure::EntryJournal(DurableJournalError::Admission(io::Error::other(cause)))
			})?;
		let payload = record.encode();
		let measurement = SourceMeasurementId::from_prepared_payload(&payload);
		let (_, _entry_frame) = append(
			self.journal,
			FrameKind::EntryPrepared,
			ApplyRecord::Entry,
			payload,
			self.authority,
		)
		.map_err(StageFailure::EntryJournal)?;
		Ok(measurement)
	}

	fn record(
		&mut self,
		measurement: SourceMeasurementId,
		range: RangeMeasurement,
	) -> Result<(), StageFailure<R, Pages::Error>> {
		let page = RangePage::new(
			self.ordinal,
			range.offset,
			range.length,
			StreamDigest::from_bytes(*range.digest.as_bytes()),
			measurement,
		)
		.map_err(StageFailure::CheckpointEvidence)?;
		self.pages
			.persist_page_admitted(self.ordinal, &page.encode(), self.authority)
			.map_err(StageFailure::CheckpointPage)?;
		let checkpoint = RangeCheckpoint {
			context: self.entry.context,
			entry: self.entry.entry,
			page: page.reference(),
			source: measurement,
		};
		let (_, _checkpoint_frame) = append(
			self.journal,
			FrameKind::RangeCheckpoint,
			ApplyRecord::Range,
			checkpoint.encode(),
			self.authority,
		)
		.map_err(StageFailure::CheckpointJournal)?;
		// The existing stream recorder emits at most 4096 checkpoints.
		self.ordinal += 1;
		Ok(())
	}
}

type RecordedSealResult<'seal, R, S, P, C, A> =
	Result<(SyncedFrame, RecordedSeal<'seal>), CheckedCopyError<R, S, P, C, A>>;

pub(super) fn record_seal<'seal, R, S, P, C, A>(
	seal: &'seal SealEvidence,
	journal: &mut DurableJournal<impl JournalSegment>,
	authority: &impl LocalApplyAdmission,
) -> RecordedSealResult<'seal, R, S, P, C, A> {
	let mut sync = |kind, role, payload| {
		append(journal, kind, role, payload, authority)
			.map(|(_, frame)| frame)
			.map_err(|cause| CheckedCopyError::Journal(kind, cause))
	};
	let sealed = sync(
		FrameKind::StageSealed,
		ApplyRecord::Seal,
		seal.sealed.encode(),
	)?;
	let verification = sync(
		FrameKind::VerificationRecorded,
		ApplyRecord::Verification,
		seal.verification.encode(),
	)?;
	let metadata = sync(
		FrameKind::MetadataRecorded,
		ApplyRecord::Metadata,
		seal.metadata.encode(),
	)?;
	Ok((
		sealed,
		RecordedSeal {
			seal,
			verification,
			metadata,
		},
	))
}
