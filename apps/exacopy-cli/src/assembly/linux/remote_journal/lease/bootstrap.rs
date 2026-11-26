use exacopy_endpoint::JournalSegment;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::{RemoteDownloadBody, RemoteDownloadOwner};
use exacopy_journal::{DurableJournal, JournalJobId, OwnerTimestamp, OwnerToken};
use exacopy_platform::linux::{JobDirectory, JobDirectoryCreationError, TargetStatus};

use crate::profile::LocalProfile;

use super::super::ledger::{append_payload_admitted, append_record_admitted, verify_readback};
use super::{
	BootstrapIdentity, Error, RemoteActivation, check_current, check_root, component, context,
	job_name, read_owner, readback_frame, record_identity,
};

pub(in crate::assembly::linux) fn bootstrap(
	profile: &LocalProfile,
	job: JournalJobId,
	created: OwnerTimestamp,
	owner_token: OwnerToken,
	activation: RemoteActivation<'_>,
) -> Result<BootstrapIdentity, Error> {
	let root = activation.root;
	let approved_scope = activation.scope;
	let name = job_name(job);
	let prepare = || {
		activation.recheck()?;
		if profile.verification_key().is_weak()
			|| owner_token.as_bytes() == job.as_bytes()
			|| owner_token.as_bytes() == profile.id().as_bytes()
			|| owner_token.as_bytes() == approved_scope.entry.as_bytes()
		{
			return Err(Error::Binding);
		}
		check_root(root, profile, approved_scope, name.as_bytes())?;
		if root.target_status(component(approved_scope.destination.target())?)?
			!= TargetStatus::Absent
		{
			return Err(Error::Conflict);
		}
		component(name.as_bytes())
	};
	let name = prepare().map_err(|cause| Error::BootstrapNotCreated(Box::new(cause)))?;
	let enter = || activation.enter_effect().map_err(std::io::Error::other);
	let workspace = root
		.create_job_directory_admitted(name, enter)
		.map_err(job_creation_error)?;
	bootstrap_created(
		profile,
		job,
		created,
		owner_token,
		activation,
		name,
		&workspace,
	)
	.map_err(|cause| Error::BootstrapIncomplete(Box::new(cause)))
}

fn job_creation_error(cause: JobDirectoryCreationError) -> Error {
	use JobDirectoryCreationError as Creation;
	match cause {
		Creation::NotCreated(cause) => Error::BootstrapNotCreated(Box::new(cause.into())),
		Creation::CreatedUnconfirmed(cause) => Error::BootstrapIncomplete(Box::new(cause.into())),
		Creation::OutcomeUncertain(cause) => {
			Error::BootstrapCreateUncertain(Box::new(cause.into()))
		}
		cause => Error::BootstrapCreateUncertain(Box::new(Error::Io(std::io::Error::other(cause)))),
	}
}

fn bootstrap_created(
	profile: &LocalProfile,
	job: JournalJobId,
	created: OwnerTimestamp,
	owner_token: OwnerToken,
	activation: RemoteActivation<'_>,
	name: UnixComponent<'_>,
	workspace: &JobDirectory<'_>,
) -> Result<BootstrapIdentity, Error> {
	let root = activation.root;
	let approved_scope = activation.scope;
	let enter = || activation.enter_effect().map_err(std::io::Error::other);
	let identity = workspace.identity();
	let manifest = RemoteDownloadOwner::new(
		owner_token,
		job,
		profile.id(),
		created,
		record_identity(identity),
		approved_scope.clone(),
	)?;
	let owner = activation.dialect.sign(manifest, profile.signer())?;
	workspace.write_owner_record_admitted(owner.as_bytes(), enter)?;
	let stage = workspace.create_stage_directory_admitted(enter)?;
	stage.sync_directory_admitted(enter)?;
	let journal = workspace.create_journal_directory_admitted(enter)?;
	let segment = journal.create_first_segment_admitted(enter)?;
	{
		let _guard = activation.enter_effect()?;
		segment.sync()?;
	}
	journal.sync_directory_admitted(enter)?;
	workspace.sync_directory_admitted(enter)?;
	root.sync_directory_admitted(enter)?;
	// The fresh writer and workspace still hold the original exclusive job lock.
	let held = root.open_recovery_job(name)?;
	if held.identity() != identity {
		return Err(Error::Binding);
	}
	let owner_file = held.open_owner()?;
	if read_owner(&owner_file, profile, activation.dialect)? != owner {
		return Err(Error::Binding);
	}
	let first_segment = held.open_first_segment()?;
	if !first_segment.is_empty() {
		return Err(Error::Binding);
	}
	let segment_identity = first_segment.identity();
	let mut writer = DurableJournal::from_new_segment(segment)?;
	let start = RemoteReplayBoundary {
		head: ChainHead::start(),
		offset: 0,
	};
	let job_body = RemoteDownloadBody::JobPrepared {
		scope: approved_scope.digest()?,
	};
	let job_boundary =
		append_record_admitted(&mut writer, start, context(&owner), job_body, enter)?;
	let job_current = check_current(&held, &owner_file, segment_identity, job_boundary.offset)?;
	let job_frame = verify_readback(&job_current, start, job_boundary, context(&owner), job_body)?;

	let keys = profile.verification_key();
	let trust = activation.dialect.trust(&owner, profile.id(), &keys)?;
	let directory = record_identity(stage.identity());
	stage.sync_directory_admitted(enter)?;
	let payload = trust.sign(&job_frame, directory, profile.signer())?;
	let (appended, _, boundary) = append_payload_admitted(
		&mut writer,
		job_boundary,
		FrameKind::StageDirectoryPrepared,
		payload,
		enter,
	)?;
	let bootstrap_current = check_current(&held, &owner_file, segment_identity, boundary.offset)?;
	let observed = readback_frame(
		&bootstrap_current,
		job_boundary,
		boundary,
		exacopy_journal::remote_download::MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES,
	)?;
	let signed = trust.from_frame(&observed, &job_frame)?;
	if observed.payload() != appended.payload()
		|| signed.head() != boundary.head
		|| signed.directory() != directory
	{
		return Err(Error::Binding);
	}
	stage.sync_directory_admitted(enter)?;
	Ok(BootstrapIdentity {
		job: identity,
		boundary,
	})
}
