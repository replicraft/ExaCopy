//! Read-only inspection of a private managed APFS copy job and its initial history.

use std::io::{self, BufReader, Read as _};
use std::num::NonZeroU32;

use ed25519_dalek::VerifyingKey;
use exacopy_content::ContentDigest;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DarwinEntryPrepared, DarwinPreparedError, DarwinReceiptDigest, DarwinStageObservation,
	MAX_OWNER_BYTES, OwnerError, OwnerProfileId, RootCapabilityId,
};
use exacopy_platform::macos::ManagedObjectIdentity;
use exacopy_platform::macos::staging::jobs::{
	JobArtifact, JobName, RecoveryFileObservation, RecoveryInventory, RecoveryJob, RecoveryRecord,
};

use super::job::{STAGE_PAYLOAD, native_identity};
use super::plan::{DarwinCopyPlan, MAX_DARWIN_COPY_PLAN_BYTES};
use super::receipt::MAX_DARWIN_COPY_RECEIPT_BYTES;
use super::replay::{
	DarwinJournalReplay, DarwinReplayAuthority, DarwinReplayStatus, replay_journal,
};

mod error;
mod readback;
pub use error::{DarwinInspectionError, DarwinStageReadBackError};

/// Trust inputs independently supplied by the caller holding the recovered destination.
#[derive(Clone, Copy, Debug)]
pub struct DarwinInspectionAuthority<'key> {
	/// Profile selected from trusted local configuration.
	pub profile: OwnerProfileId,
	/// Verification key selected for that profile.
	pub key: &'key VerifyingKey,
	/// Capability identifier independently assigned to the held destination.
	pub destination_root: RootCapabilityId,
}

/// Receipt artifact observation under the job lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DarwinReceiptArtifact {
	/// The receipt directory or fixed receipt name was absent.
	Missing,
	/// A bounded private receipt exists without an accepted journal commitment.
	PresentUncommitted,
	/// The canonical artifact matches the accepted historical commitment.
	MatchesCommitment(DarwinReceiptDigest),
}

/// Authenticated initial history and freshly checked namespace observations.
#[derive(Debug)]
pub struct DarwinJobInspection {
	/// The canonical plan bytes authenticated by the signed owner.
	pub plan_bytes: Vec<u8>,
	/// The accepted prefix from the held first journal segment.
	pub replay: DarwinJournalReplay,
	/// The private receipt artifact observation, independent of live file content.
	pub receipt: DarwinReceiptArtifact,
	/// The observed private stage directory, if present.
	pub stage_directory: Option<ManagedObjectIdentity>,
	/// The observed private stage name, if occupied by a checked regular file.
	pub stage: Option<RecoveryFileObservation>,
	/// The observed public target name, if occupied by a checked regular file.
	pub target: Option<RecoveryFileObservation>,
}

/// Joins the native recovery inventory to the authenticated, read-only initial replay.
///
/// Reports current namespace observations and historical commitment under the held job
/// lease. The stage and target observations cover identity and extent.
///
/// # Errors
/// Refuses changed or unsafe artifacts, incompatible or unauthenticated history, and a
/// receipt that disagrees with an accepted commitment.
pub fn inspect_job(
	job: &RecoveryJob<'_>,
	authority: DarwinInspectionAuthority<'_>,
) -> Result<DarwinJobInspection, DarwinInspectionError> {
	inspect(job, authority, |_, _, _| Ok(())).map(|(inspection, ())| inspection)
}

/// Checks the retained private stage against accepted historical verification.
///
/// This opt-in inspection can advance the stage's access time. If the replay
/// includes required metadata, it must match both before and after the reads.
/// The returned digest describes the private stage observed during this
/// inspection. Neither the source nor the public target is opened for content.
///
/// # Errors
/// Refuses missing verification, changed bindings, invalid scratch bounds,
/// ineligible stage metadata, I/O failures, and digest or recorded metadata mismatches.
pub fn inspect_job_with_stage_read_back(
	job: &RecoveryJob<'_>,
	authority: DarwinInspectionAuthority<'_>,
	scratch: &mut [u8],
) -> Result<(DarwinJobInspection, ContentDigest), DarwinInspectionError> {
	inspect(job, authority, |replay, prepared, names| {
		readback::verify(replay, prepared, names, scratch)
			.map_err(DarwinInspectionError::StageReadBack)
	})
}

fn inspect<T>(
	job: &RecoveryJob<'_>,
	authority: DarwinInspectionAuthority<'_>,
	observe: impl FnOnce(
		&DarwinJournalReplay,
		Option<DarwinStageObservation<'_>>,
		&RecoveryInventory<'_>,
	) -> Result<T, DarwinInspectionError>,
) -> Result<(DarwinJobInspection, T), DarwinInspectionError> {
	let plan_bytes = read_record(
		job.open_plan()?,
		JobArtifact::Plan,
		MAX_DARWIN_COPY_PLAN_BYTES,
	)?;
	let plan = DarwinCopyPlan::decode(&plan_bytes, authority.profile)
		.map_err(DarwinInspectionError::Plan)?;
	let destination = plan.destination();
	if JobName::from_uuid_bytes(*plan.attempt().job.as_bytes()).ok() != Some(job.name())
		|| destination.root_id != authority.destination_root
		|| native_identity(job.observe_destination()?)? != destination.root_identity
	{
		return Err(DarwinInspectionError::PlanBinding);
	}
	let owner = read_record(job.open_owner()?, JobArtifact::Owner, MAX_OWNER_BYTES)?;
	let mut segment = job.open_first_segment()?;
	let replay = replay_journal(
		BufReader::new(&mut segment),
		&plan,
		&owner,
		DarwinReplayAuthority {
			profile: authority.profile,
			key: authority.key,
			state_root: native_identity(job.identity())?,
			state_root_uid: NonZeroU32::new(job.owner_uid()).ok_or(OwnerError::InvalidOwnerUid)?,
		},
	)
	.map_err(DarwinInspectionError::Replay)?;
	let prepared = replay
		.frame(FrameKind::EntryPrepared)
		.map(DarwinEntryPrepared::from_frame)
		.transpose()
		.map_err(DarwinInspectionError::Preparation)?
		.map(|entry| entry.preparation().stage);
	let stage_name = match prepared {
		Some(stage) => stage.component,
		None => UnixComponent::new(STAGE_PAYLOAD)
			.map_err(DarwinPreparedError::InvalidComponent)
			.map_err(DarwinInspectionError::Preparation)?,
	};
	let names = job.inventory(stage_name, destination.component)?;
	let receipt = match job.open_receipt()? {
		None => DarwinReceiptArtifact::Missing,
		Some(record) if replay.status() == DarwinReplayStatus::Complete => {
			let bytes = read_record(record, JobArtifact::Receipt, MAX_DARWIN_COPY_RECEIPT_BYTES)?;
			let receipt = replay
				.validate_receipt(&plan, &bytes)
				.map_err(DarwinInspectionError::Replay)?;
			DarwinReceiptArtifact::MatchesCommitment(receipt.digest())
		}
		Some(_) => DarwinReceiptArtifact::PresentUncommitted,
	};
	let observed = observe(&replay, prepared, &names)?;
	names.revalidate()?;
	segment.revalidate()?;
	let stage_directory = names.stage_directory_identity();
	let stage = names.stage();
	let target = names.target();
	drop(names);
	Ok((
		DarwinJobInspection {
			plan_bytes,
			replay,
			receipt,
			stage_directory,
			stage,
			target,
		},
		observed,
	))
}

fn read_record(
	mut record: RecoveryRecord<'_>,
	artifact: JobArtifact,
	limit: usize,
) -> Result<Vec<u8>, DarwinInspectionError> {
	let length = usize::try_from(record.len())
		.ok()
		.filter(|&length| length <= limit)
		.ok_or(DarwinInspectionError::ArtifactTooLarge { artifact, limit })?;
	let mut buffer = vec![0; length];
	record
		.read_exact(&mut buffer)
		.map_err(|error: io::Error| DarwinInspectionError::Read { artifact, error })?;
	record.revalidate()?;
	Ok(buffer)
}
