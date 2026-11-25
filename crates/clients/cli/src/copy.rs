use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use exacopy_content::MAX_SCRATCH_BYTES;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{JournalEntryId, JournalEpoch, JournalJobId, OwnerTimestamp, OwnerToken};
use exacopy_platform::linux::{PublishError, ReadError, ReadRoot, StageError};
use exacopy_transfer::linux::{
	CopyProfile, CopyRoots, LocalCopyError, PlanAttempt, StageFailure, copy_new_file, plan_new_file,
};
use uuid::{Builder, Uuid};

use crate::args::CopyCommand;
use crate::copy_report::{CopyFailure, CopyOutcome, CopySuccess, ErrorKind};
use crate::linux_path::{open_destination, open_directory, split};
use crate::profile::{LocalProfile, kernel_random};

const JOB_PREFIX: &str = ".exacopy-";
const STAGE_NAME: &[u8] = b"data";
const INITIAL_EPOCH: u64 = 1;
const MAX_UUIDV7_MILLIS: u64 = (1 << 48) - 1;

pub(crate) fn execute(command: &CopyCommand) -> CopyOutcome {
	match copy(command) {
		Ok(success) => CopyOutcome::Published { receipt: success },
		Err(failure) => CopyOutcome::Failed { error: failure },
	}
}

fn copy(command: &CopyCommand) -> Result<CopySuccess, CopyFailure> {
	let (source_parent, source) = split(&command.source)
		.map_err(|error| CopyFailure::new(ErrorKind::InvalidRequest, error))?;
	let (target_parent, target) = split(&command.target)
		.map_err(|error| CopyFailure::new(ErrorKind::InvalidRequest, error))?;
	let profile = LocalProfile::open(&command.profile)
		.map_err(|error| CopyFailure::new(ErrorKind::ProfileAuthorization, error))?;
	let source_root = ReadRoot::from_directory(open_directory(source_parent).map_err(io_failure)?)
		.map_err(io_failure)?;
	let destination = open_destination(Path::new(target_parent))
		.map_err(|error| CopyFailure::new(stage_kind(&error), error))?;
	let roots = CopyRoots {
		source: &source_root,
		source_id: profile
			.root_id(source_root.identity())
			.map_err(io_failure)?,
		destination: &destination,
		destination_id: profile
			.root_id(destination.identity())
			.map_err(io_failure)?,
	};
	let (job, created) = job_identity()?;
	let job_id = Uuid::from_bytes(*job.as_bytes()).to_string();
	let job_directory = format!("{JOB_PREFIX}{job_id}");
	let mut entry = [0; 16];
	kernel_random(&mut entry).map_err(io_failure)?;
	let mut token = [0; 16];
	kernel_random(&mut token).map_err(io_failure)?;
	let owner_token = OwnerToken::from_bytes(token).map_err(io_failure)?;
	let attempt = PlanAttempt {
		job,
		epoch: JournalEpoch::new(INITIAL_EPOCH),
		entry: JournalEntryId::from_bytes(
			Builder::from_random_bytes(entry).into_uuid().into_bytes(),
		),
		job_name: UnixComponent::new(job_directory.as_bytes()).map_err(io_failure)?,
		stage_name: UnixComponent::new(STAGE_NAME).map_err(io_failure)?,
	};
	let plan = plan_new_file(roots, attempt, source, target)
		.map_err(|error| CopyFailure::new(copy_kind(&error), error))?;
	if profile.is_seed(plan.source().file_identity) {
		return Err(CopyFailure::new(
			ErrorKind::ProfileAuthorization,
			"the selected profile seed cannot be copied",
		));
	}
	let mut scratch = Vec::new();
	scratch
		.try_reserve_exact(MAX_SCRATCH_BYTES)
		.map_err(io_failure)?;
	scratch.resize(MAX_SCRATCH_BYTES, 0);
	let credential = CopyProfile {
		id: profile.id(),
		signer: profile.signer(),
		created,
		owner_token,
	};
	let receipt = copy_new_file(roots, &plan, credential, &mut scratch).map_err(|error| {
		CopyFailure::new(copy_kind(&error), error).with_job(&job_id, &job_directory)
	})?;
	Ok(CopySuccess {
		job_id,
		length: receipt.evidence().stream.length.get().to_string(),
		blake3: blake3::Hash::from_bytes(*receipt.evidence().stream.digest.as_bytes())
			.to_hex()
			.to_string(),
		receipt_digest: blake3::Hash::from_bytes(receipt.digest())
			.to_hex()
			.to_string(),
		job_directory,
	})
}

fn job_identity() -> Result<(JournalJobId, OwnerTimestamp), CopyFailure> {
	let time = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(io_failure)?;
	let millis = u64::try_from(time.as_millis()).map_err(io_failure)?;
	if millis > MAX_UUIDV7_MILLIS {
		return Err(io_failure(
			"current time is outside the UUIDv7 timestamp range",
		));
	}
	let created = OwnerTimestamp::new(
		i64::try_from(time.as_secs()).map_err(io_failure)?,
		time.subsec_nanos(),
	)
	.map_err(io_failure)?;
	let mut tail = [0; 10];
	kernel_random(&mut tail).map_err(io_failure)?;
	let job = Builder::from_unix_timestamp_millis(millis, &tail).into_uuid();
	Ok((
		JournalJobId::from_bytes(job.into_bytes()).map_err(io_failure)?,
		created,
	))
}

fn io_failure(error: impl std::fmt::Display) -> CopyFailure {
	CopyFailure::new(ErrorKind::Io, error)
}

fn copy_kind(error: &LocalCopyError) -> ErrorKind {
	match error {
		LocalCopyError::Conflict
		| LocalCopyError::StalePlan
		| LocalCopyError::Publication {
			source: PublishError::Conflict,
			recording: None,
		} => ErrorKind::Conflict,
		LocalCopyError::Plan(_) => ErrorKind::InvalidRequest,
		LocalCopyError::InspectTarget(error) | LocalCopyError::CreateStage(error) => {
			stage_kind(error)
		}
		LocalCopyError::Source(error) => read_kind(error),
		LocalCopyError::SourcePolicy(error) => stage_failure_kind(error),
		LocalCopyError::Stage(error) => stage_failure_kind(error.failure()),
		LocalCopyError::Publication {
			source: PublishError::Unsupported(_),
			recording: None,
		} => ErrorKind::Unsupported,
		LocalCopyError::Publication {
			source: PublishError::StageChanged(_) | PublishError::BindingMismatch,
			recording: None,
		} => ErrorKind::Integrity,
		LocalCopyError::Journal {
			kind:
				FrameKind::StageSealed | FrameKind::VerificationRecorded | FrameKind::MetadataRecorded,
			..
		}
		| LocalCopyError::Bootstrap(_) => ErrorKind::Io,
		LocalCopyError::Preparation(_)
		| LocalCopyError::Verification(_)
		| LocalCopyError::Timestamp(_) => ErrorKind::Integrity,
		// Intent synchronization and every later failure can leave evidence requiring
		// reconciliation. Future error variants also fail closed.
		_ => ErrorKind::RecoveryRequired,
	}
}

fn stage_failure_kind(error: &StageFailure) -> ErrorKind {
	match error {
		StageFailure::Input(_)
		| StageFailure::SourceAttributes(_)
		| StageFailure::UnsupportedSourceMode { .. } => ErrorKind::Unsupported,
		StageFailure::Source(error) => read_kind(error),
		StageFailure::Stage(error) => stage_kind(error),
		StageFailure::Copy(_) | StageFailure::EntryJournal(_) => ErrorKind::Io,
		_ => ErrorKind::Integrity,
	}
}

fn read_kind(error: &ReadError) -> ErrorKind {
	match error {
		ReadError::NotDirectory
		| ReadError::NotRegularFile
		| ReadError::UnsupportedProcfs
		| ReadError::InvalidLength
		| ReadError::ExtendedAttributeListTooLarge
		| ReadError::ExtendedAttributesUnreadable(_) => ErrorKind::Unsupported,
		ReadError::IdentityChanged | ReadError::SourceChanged => ErrorKind::Conflict,
		_ => ErrorKind::Io,
	}
}

fn stage_kind(error: &StageError) -> ErrorKind {
	match error {
		StageError::AlreadyExists | StageError::IdentityChanged => ErrorKind::Conflict,
		StageError::UnsafeDirectory
		| StageError::UnsupportedMode
		| StageError::DifferentOwnership
		| StageError::UnexpectedExtendedAttributes
		| StageError::ExtendedAttributesUnavailable(_)
		| StageError::InvalidLength => ErrorKind::Unsupported,
		StageError::MetadataMismatch | StageError::UnsafeFile => ErrorKind::Integrity,
		StageError::System(error)
			if matches!(
				error.raw_os_error(),
				Some(code) if code == rustix::io::Errno::NOSYS.raw_os_error()
					|| code == rustix::io::Errno::NOTSUP.raw_os_error()
			) =>
		{
			ErrorKind::Unsupported
		}
		_ => ErrorKind::Io,
	}
}
