use std::error::Error;
use std::fmt;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use exacopy_endpoint::ReadView as _;
use exacopy_journal::{
	ApplyCrashProfile, ApplyProcessCrashEnvironment, ApplyQualification, ApplyQualificationDigest,
	ApprovedPublicPlanDigest, OwnerTimestamp, PublicApplyIntent,
};
use exacopy_platform::linux::{
	ProcessCrashEligibility, ProcessCrashEnvironment, ProcessCrashProfileError,
	ProcessCrashProfileId, PublishError, ReadError, RunningExecutable, StageError,
};
use exacopy_platform::{ProtectedSnapshotError, read_protected_snapshot_into};
use exacopy_transfer::linux::{
	PublicApplyIntentObservation, PublicApplyIntentPreparationError, PublicApplyIntentSelection,
	PublicApplyStageRequest, stage_public_apply_and_propose_intent,
};

use super::super::{CopyRoots, running_build};

mod record;
#[cfg(test)]
mod tests;

pub(super) use record::Qualification;
use record::{RECORD_BYTES, verify};

/// Separately provisioned selection for a local Linux apply qualification.
///
/// Supply this from independently administered host configuration. The request,
/// signed owner, journal and candidate record must never configure this trust.
/// Protected file custody establishes current bytes, and this separately
/// selected key and record digest establish the enrollment. The application
/// ships no default issuer, enrollment or CLI route for this operation.
/// The host also maintains the reviewed deployment and loaded-code closure.
/// Measuring the held main executable does not measure dynamic libraries.
pub struct LocalApplyQualificationEnrollment<'policy> {
	/// Exact signed attestation file under the existing Linux protected path policy.
	pub record_path: &'policy Path,
	/// Exact complete record digest selected after review of the local campaign.
	pub record_digest: ApplyQualificationDigest,
	/// Configured nonzero qualification issuer identifier.
	pub attestor_id: [u8; 16],
	/// Configured strong canonical verification key, independent of the owner key.
	pub attestor_key: &'policy VerifyingKey,
}

impl fmt::Debug for LocalApplyQualificationEnrollment<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("LocalApplyQualificationEnrollment")
			.finish_non_exhaustive()
	}
}

/// Failure to qualify and stage one explicitly selected public apply proposal.
#[derive(Debug)]
#[non_exhaustive]
pub enum QualifiedPublicApplyProposalError {
	/// The protected attestation bytes could not be obtained.
	Snapshot(ProtectedSnapshotError),
	/// An exact canonical record in the selected local purpose was required.
	Record,
	/// The selected issuer, owner role or exact reviewed record digest differed.
	Selection,
	/// The attestor's signature did not verify in the local qualification purpose.
	Signature,
	/// The qualification does not name the actual selected action or root identities.
	Scope,
	/// The native running executable could not be observed.
	Executable(io::Error),
	/// The observed running executable length or digest differed from the signed record.
	BuildMismatch,
	/// The exact held roots do not match the selected native profile and environment.
	Native(ProcessCrashProfileError),
	/// Trusted UTC was unavailable or outside the attestation or Plan window.
	Time,
	/// Existing staging, held journal readback or proposal encoding refused.
	Proposal(Box<PublicApplyIntentPreparationError<ReadError, StageError, PublishError>>),
}

impl fmt::Display for QualifiedPublicApplyProposalError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Snapshot(_) => "could not acquire the protected local qualification",
			Self::Record => "invalid local qualification record",
			Self::Selection => "local qualification differs from independent enrollment",
			Self::Signature => "local qualification signature was refused",
			Self::Scope => "local qualification differs from the selected action or roots",
			Self::Executable(_) => "could not observe the running executable",
			Self::BuildMismatch => "running executable differs from the qualified image",
			Self::Native(_) => "held roots differ from the qualified native environment",
			Self::Time => "local qualification or approved Plan is outside its time window",
			Self::Proposal(_) => "qualified staging or intent proposal refused",
		})
	}
}

impl Error for QualifiedPublicApplyProposalError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Snapshot(cause) => Some(cause),
			Self::Executable(cause) => Some(cause),
			Self::Native(cause) => Some(cause),
			Self::Proposal(cause) => match cause.as_ref() {
				PublicApplyIntentPreparationError::Stage(cause) => Some(cause),
				PublicApplyIntentPreparationError::SealReadback(cause) => Some(cause),
				PublicApplyIntentPreparationError::Format(cause) => Some(cause),
				_ => None,
			},
			_ => None,
		}
	}
}

/// Stages the approved content and prepares a historical intent for one exact local enrollment.
///
/// Uses the original held roots, real running image and live internal UTC. The
/// returned proposal authorizes neither journal append nor publication. The
/// output keeps the existing intent payload and never appends kind 7.
/// # Errors
/// Refuses unselected evidence, bad signature, a different action or build,
/// native mismatch and expired selection. Later failures preserve private artifacts.
pub fn stage_qualified_public_apply<'name>(
	roots: CopyRoots<'_>,
	enrollment: &LocalApplyQualificationEnrollment<'_>,
	request: PublicApplyStageRequest<'_, '_, 'name>,
	scratch: &mut [u8],
) -> Result<PublicApplyIntent<'name>, QualifiedPublicApplyProposalError> {
	use QualifiedPublicApplyProposalError as Failure;

	let qualification = read_selection(roots, enrollment, &request)?;
	let expiry = request.binding.expires_at.ok_or(Failure::Time)?;
	let mut last_time = now()?;
	qualification.check_time(last_time, expiry)?;

	let qualified = RunningQualification::open(roots, qualification)?;
	let selection = qualified.selection;
	let mut refused = None;
	let proposal = stage_public_apply_and_propose_intent(
		roots,
		request,
		selection,
		scratch,
		|_| {},
		|| {
			let mut sample = || {
				let environment = qualified.observe_environment()?;
				let current_time = now()?;
				qualified.record.check_time(current_time, expiry)?;
				if (current_time.seconds(), current_time.nanoseconds())
					< (last_time.seconds(), last_time.nanoseconds())
				{
					return Err(Failure::Time);
				}
				last_time = current_time;
				Ok(PublicApplyIntentObservation {
					now: current_time,
					profile: selection.qualification.profile,
					environment,
				})
			};
			match sample() {
				Ok(observed) => Some(observed),
				Err(error) => {
					refused = Some(error);
					None
				}
			}
		},
	);
	proposal.map_err(|error| refused.unwrap_or_else(|| Failure::Proposal(Box::new(error))))
}

pub(super) fn read_selection(
	roots: CopyRoots<'_>,
	enrollment: &LocalApplyQualificationEnrollment<'_>,
	request: &PublicApplyStageRequest<'_, '_, '_>,
) -> Result<Qualification, QualifiedPublicApplyProposalError> {
	use QualifiedPublicApplyProposalError as Failure;

	let mut bytes = [0; RECORD_BYTES];
	let mut readback = [0; RECORD_BYTES];
	let length = read_protected_snapshot_into(enrollment.record_path, &mut bytes, &mut readback)
		.map_err(Failure::Snapshot)?;
	let owner = request.profile.signer.verifying_key();
	let qualification = verify(&bytes[..length], enrollment, &owner)?;
	check_scope(&qualification, roots, request)?;
	Ok(qualification)
}

pub(super) struct RunningQualification<'root> {
	image: RunningExecutable,
	eligible: ProcessCrashEligibility<'root>,
	pub(super) record: Qualification,
	pub(super) selection: PublicApplyIntentSelection,
}

impl<'root> RunningQualification<'root> {
	pub(super) fn open(
		roots: CopyRoots<'root>,
		qualification: Qualification,
	) -> Result<Self, QualifiedPublicApplyProposalError> {
		use QualifiedPublicApplyProposalError as Failure;

		let image = RunningExecutable::open().map_err(Failure::Executable)?;
		if image.length() != qualification.image_length
			|| running_build::measure(&image, blake3::Hasher::new()).map_err(Failure::Executable)?
				!= qualification.image
		{
			return Err(Failure::BuildMismatch);
		}
		let eligible = ProcessCrashEligibility::admit(
			qualification.environment,
			roots.source,
			roots.destination,
		)
		.map_err(Failure::Native)?;
		let profile = match eligible.profile_id() {
			ProcessCrashProfileId::Arm64UbuntuExt4FixtureV1 => {
				ApplyCrashProfile::Arm64UbuntuExt4FixtureV1
			}
		};
		let selection = PublicApplyIntentSelection {
			approved_plan: ApprovedPublicPlanDigest::from_bytes(qualification.plan),
			qualification: ApplyQualification {
				record: qualification.digest,
				profile,
				environment: project_environment(qualification.environment),
			},
		};
		Ok(Self {
			image,
			eligible,
			record: qualification,
			selection,
		})
	}

	pub(super) fn observe_environment(
		&self,
	) -> Result<ApplyProcessCrashEnvironment, QualifiedPublicApplyProposalError> {
		use QualifiedPublicApplyProposalError as Failure;

		self.image
			.recheck_observation()
			.map_err(Failure::Executable)?;
		let observed = self.eligible.recheck_observed().map_err(Failure::Native)?;
		Ok(project_environment(observed))
	}
}

fn check_scope(
	qualification: &Qualification,
	roots: CopyRoots<'_>,
	request: &PublicApplyStageRequest<'_, '_, '_>,
) -> Result<(), QualifiedPublicApplyProposalError> {
	let source = roots.source.identity();
	let destination = roots.destination.identity();
	let binding = request.binding;
	if qualification.plan != request.approved.body().digest()
		|| qualification.plan != *binding.public_plan.as_bytes()
		|| qualification.entry != *request.approved.entry().entry_id.as_bytes()
		|| qualification.entry != *binding.public_entry.as_bytes()
		|| qualification.metadata != request.approved.entry().metadata_policy_digest
		|| qualification.metadata != *binding.metadata_policy.as_bytes()
		|| qualification.owner_profile != *request.profile.id.as_bytes()
		|| qualification.source.alias != roots.source_id
		|| qualification.destination.alias != roots.destination_id
		|| qualification.source.inode != source.inode()
		|| qualification.destination.inode != destination.inode()
		|| qualification.environment.device != source.device()
		|| qualification.environment.device != destination.device()
	{
		return Err(QualifiedPublicApplyProposalError::Scope);
	}
	Ok(())
}

fn project_environment(value: ProcessCrashEnvironment) -> ApplyProcessCrashEnvironment {
	ApplyProcessCrashEnvironment {
		boot_id: value.boot_id,
		mount_namespace: value.mount_namespace,
		unique_mount: value.unique_mount,
		device: value.device,
	}
}

fn now() -> Result<OwnerTimestamp, QualifiedPublicApplyProposalError> {
	use QualifiedPublicApplyProposalError::Time;
	let time = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(|_| Time)?;
	let seconds = i64::try_from(time.as_secs()).map_err(|_| Time)?;
	OwnerTimestamp::new(seconds, time.subsec_nanos()).map_err(|_| Time)
}
