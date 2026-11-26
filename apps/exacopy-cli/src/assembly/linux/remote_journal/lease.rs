use std::io::Write as _;
use std::num::NonZeroU64;

use ed25519_dalek::VerifyingKey;
use exacopy_endpoint::JournalSegment;
use exacopy_endpoint::linux_job::{JobRecord, JobWorkspace};
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::remote_download::finalization_replay::{
	RemoteFinalizationPhase, RemoteFinalizationReplay, replay_remote_finalization,
};
use exacopy_journal::remote_download::replay::{RemoteReplayBoundary, RemoteReplayIssue};
use exacopy_journal::remote_download::{
	MAX_REMOTE_DOWNLOAD_OWNER_BYTES, RemoteDownloadBody, RemoteDownloadOwner,
	RemoteDownloadOwnerRecord, RemoteDownloadScope,
};
use exacopy_journal::{
	DurableJournal, JournalJobId, LinuxFileIdentity, OwnerTimestamp, OwnerToken,
};
use exacopy_platform::linux::{
	DestinationRoot, FileIdentity, LinuxJournalSegment, RecoveryFile, RecoveryInventory,
	RecoveryJob, RecoveryWriteLease, TargetStatus,
};

use crate::profile::LocalProfile;

use super::admission::{OwnerDialect, RemoteActivation};
use super::ledger::{
	RemoteJobJournal, WriterStart, append_payload, append_record, context, readback_frame,
	verify_readback,
};
use super::{BootstrapIdentity, Error, ReplayIssue, component, job_name, record_identity};

mod finish;
mod retire;

pub(in crate::assembly::linux) fn bootstrap(
	profile: &LocalProfile,
	job: JournalJobId,
	created: OwnerTimestamp,
	owner_token: OwnerToken,
	activation: RemoteActivation<'_>,
) -> Result<BootstrapIdentity, Error> {
	activation.recheck()?;
	let root = activation.root;
	let approved_scope = activation.scope;
	if profile.verification_key().is_weak()
		|| owner_token.as_bytes() == job.as_bytes()
		|| owner_token.as_bytes() == profile.id().as_bytes()
		|| owner_token.as_bytes() == approved_scope.entry.as_bytes()
	{
		return Err(Error::Binding);
	}
	let name = job_name(job);
	check_root(root, profile, approved_scope, name.as_bytes())?;
	if root.target_status(component(approved_scope.destination.target())?)? != TargetStatus::Absent
	{
		return Err(Error::Conflict);
	}
	let name = component(name.as_bytes())?;
	let workspace = root.create_job_directory(name)?;
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
	{
		let mut record = JobWorkspace::create_owner_record(&workspace)?;
		record.write_all(owner.as_bytes())?;
		record.sync_all()?;
	}
	let stage = workspace.create_stage_directory()?;
	stage.sync_directory()?;
	let journal = workspace.create_journal_directory()?;
	let segment = journal.create_first_segment()?;
	segment.sync()?;
	journal.sync_directory()?;
	workspace.sync_directory()?;
	root.sync_directory()?;
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
	let job_boundary = append_record(&mut writer, start, context(&owner), job_body)?;
	let job_current = check_current(&held, &owner_file, segment_identity, job_boundary.offset)?;
	let job_frame = verify_readback(&job_current, start, job_boundary, context(&owner), job_body)?;

	let keys = profile.verification_key();
	let trust = activation.dialect.trust(&owner, profile.id(), &keys)?;
	let directory = record_identity(stage.identity());
	stage.sync_directory()?;
	let payload = trust.sign(&job_frame, directory, profile.signer())?;
	let (appended, _, boundary) = append_payload(
		&mut writer,
		job_boundary,
		FrameKind::StageDirectoryPrepared,
		payload,
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
	stage.sync_directory()?;
	Ok(BootstrapIdentity {
		job: identity,
		boundary,
	})
}

pub(in crate::assembly::linux) struct RemoteJobLease<'root> {
	lease: RecoveryWriteLease<'root>,
	owner: RemoteDownloadOwnerRecord,
	owner_file: RecoveryFile,
	segment: RecoveryFile,
	boundary: RemoteReplayBoundary,
	phase: RemoteFinalizationPhase,
	stage_directory: LinuxFileIdentity,
	last_source_epoch: Option<NonZeroU64>,
	activation: RemoteActivation<'root>,
	key: VerifyingKey,
}

impl<'root> RemoteJobLease<'root> {
	pub(in crate::assembly::linux) fn open_existing(
		profile: &LocalProfile,
		job: JournalJobId,
		activation: RemoteActivation<'root>,
	) -> Result<Self, Error> {
		Self::open(profile, job, activation, None)
	}

	pub(in crate::assembly::linux) fn open_bootstrap(
		profile: &LocalProfile,
		job: JournalJobId,
		activation: RemoteActivation<'root>,
		bootstrap: BootstrapIdentity,
	) -> Result<Self, Error> {
		Self::open(profile, job, activation, Some(bootstrap))
	}

	fn open(
		profile: &LocalProfile,
		job: JournalJobId,
		activation: RemoteActivation<'root>,
		bootstrap: Option<BootstrapIdentity>,
	) -> Result<Self, Error> {
		activation.recheck()?;
		let root = activation.root;
		let approved_scope = activation.scope;
		let name = job_name(job);
		check_root(root, profile, approved_scope, name.as_bytes())?;
		let name = component(name.as_bytes())?;
		let observed_job = root.open_recovery_job(name)?;
		let expected = observed_job.identity();
		if bootstrap
			.as_ref()
			.is_some_and(|identity| identity.job != expected)
		{
			return Err(Error::Binding);
		}
		let lease = root.try_recovery_write_lease(name, expected)?;
		observed_job.recheck()?;
		let held = lease.job();
		let owner_file = held.open_owner()?;
		let owner = read_owner(&owner_file, profile, activation.dialect)?;
		let manifest = owner.manifest();
		if manifest.job != job
			|| manifest.job_directory != record_identity(held.identity())
			|| manifest.scope.destination.parent() != record_identity(held.destination_identity())
			|| &manifest.scope != approved_scope
		{
			return Err(Error::Binding);
		}
		let mut segment = held.open_first_segment()?;
		let key = profile.verification_key();
		let trust = activation.dialect.trust(&owner, profile.id(), &key)?;
		let replay = replay_remote_finalization(
			&mut segment,
			&trust,
			activation.qualification_digest,
			None,
		)?;
		require_live_phase(&replay, activation)?;
		if let Some(bootstrap) = &bootstrap
			&& replay.boundary() != bootstrap.boundary
		{
			return Err(Error::Binding);
		}
		segment.check_logical_eof()?;
		segment.recheck_observation()?;
		held.recheck()?;
		let target = component(manifest.scope.destination.target())?;
		let stage_directory = replay
			.stage_directory_prepared()
			.ok_or(Error::Binding)?
			.directory();
		for attempt in replay.attempts() {
			let inventory = held.inventory(component(attempt.name())?, target)?;
			if inventory.target().is_some() {
				return Err(Error::Conflict);
			}
			match (
				attempt.prepared(),
				inventory.stage(),
				inventory.stage_directory_identity(),
			) {
				(Some(prepared), Some(file), Some(directory))
					if stage_directory == record_identity(directory)
						&& prepared.directory == stage_directory
						&& prepared.file == record_identity(file.identity()) => {}
				(None, None, Some(directory)) if stage_directory == record_identity(directory) => {}
				_ => return Err(Error::UnknownStage),
			}
		}
		let boundary = replay.boundary();
		let phase = replay.phase();
		let last_source_epoch = replay
			.attempts()
			.last()
			.map(|attempt| attempt.epochs().source);
		Ok(Self {
			lease,
			owner,
			owner_file,
			segment,
			boundary,
			phase,
			stage_directory,
			last_source_epoch,
			activation,
			key,
		})
	}

	pub(in crate::assembly::linux) fn job(&self) -> &RecoveryJob<'_> {
		self.lease.job()
	}

	pub(in crate::assembly::linux) fn candidate<'job>(
		&'job self,
		name: exacopy_endpoint::UnixComponent<'job>,
	) -> Result<CheckedCandidate<'job>, Error> {
		self.activation.recheck()?;
		let target = component(self.owner.manifest().scope.destination.target())?;
		let inventory = self.job().inventory(name, target)?;
		if inventory.stage().is_some() || inventory.target().is_some() {
			return Err(Error::Conflict);
		}
		let directory = inventory
			.stage_directory_identity()
			.filter(|identity| record_identity(*identity) == self.stage_directory)
			.ok_or(Error::UnknownStage)?;
		Ok(CheckedCandidate {
			job: self.job(),
			directory,
			inventory,
			name,
		})
	}

	pub(in crate::assembly::linux) fn open_writer(
		&self,
		candidate: &CheckedCandidate<'_>,
	) -> Result<RemoteJobJournal<'_>, Error> {
		if !matches!(
			self.phase,
			RemoteFinalizationPhase::Capture | RemoteFinalizationPhase::Retired
		) {
			return Err(Error::Lifecycle {
				phase: self.phase,
				boundary: self.boundary,
				issue: None,
			});
		}
		let (current, replay) = self.checked_scan(candidate)?;
		let writer = self.resume_writer()?;
		Ok(self.bind_writer(writer, current, &replay, candidate.directory))
	}

	fn checked_scan(
		&self,
		candidate: &CheckedCandidate<'_>,
	) -> Result<(RecoveryFile, RemoteFinalizationReplay<'_>), Error> {
		self.activation.recheck()?;
		if !std::ptr::eq(candidate.job, self.job())
			|| record_identity(candidate.directory) != self.stage_directory
		{
			return Err(Error::Binding);
		}
		candidate.inventory.recheck()?;
		let mut current = check_current(
			self.job(),
			&self.owner_file,
			self.segment.identity(),
			self.boundary.offset,
		)?;
		let replay = self.scan(&mut current)?;
		require_live_phase(&replay, self.activation)?;
		if replay.boundary() != self.boundary || replay.phase() != self.phase {
			return Err(Error::Binding);
		}
		Ok((current, replay))
	}

	fn scan(&self, file: &mut RecoveryFile) -> Result<RemoteFinalizationReplay<'_>, Error> {
		let trust =
			self.activation
				.dialect
				.trust(&self.owner, self.owner.manifest().profile, &self.key)?;
		let replay = replay_remote_finalization(
			&mut *file,
			&trust,
			self.activation.qualification_digest,
			None,
		)?;
		file.check_logical_eof()?;
		file.recheck_observation()?;
		Ok(replay)
	}

	fn resume_writer(&self) -> Result<DurableJournal<LinuxJournalSegment<'_>>, Error> {
		self.activation.recheck()?;
		let segment = self.lease.open_first_segment_for_append(&self.segment)?;
		Ok(DurableJournal::resume_first_segment(
			segment,
			self.boundary.head,
			self.boundary.offset,
		)?)
	}

	fn bind_writer<'lease>(
		&'lease self,
		writer: DurableJournal<LinuxJournalSegment<'lease>>,
		current: RecoveryFile,
		replay: &RemoteFinalizationReplay<'_>,
		directory: FileIdentity,
	) -> RemoteJobJournal<'lease> {
		RemoteJobJournal::open(
			writer,
			&self.lease,
			&self.owner,
			&self.owner_file,
			replay,
			WriterStart {
				segment: current,
				directory,
				activation: self.activation,
			},
		)
	}
}

pub(in crate::assembly::linux) struct CheckedCandidate<'job> {
	job: &'job RecoveryJob<'job>,
	directory: FileIdentity,
	pub(super) inventory: RecoveryInventory<'job>,
	pub(super) name: exacopy_endpoint::UnixComponent<'job>,
}

pub(super) fn check_current(
	job: &RecoveryJob<'_>,
	owner: &RecoveryFile,
	segment: FileIdentity,
	end: u64,
) -> Result<RecoveryFile, Error> {
	if job.open_owner()?.identity() != owner.identity() {
		return Err(Error::Binding);
	}
	owner.recheck_observation()?;
	let current = job.open_first_segment()?;
	if current.identity() != segment || current.len() != end {
		return Err(Error::Binding);
	}
	job.recheck()?;
	Ok(current)
}

fn read_owner(
	file: &RecoveryFile,
	profile: &LocalProfile,
	dialect: OwnerDialect,
) -> Result<RemoteDownloadOwnerRecord, Error> {
	let len = usize::try_from(file.len()).map_err(|_| Error::Binding)?;
	if len == 0 || len > MAX_REMOTE_DOWNLOAD_OWNER_BYTES {
		return Err(Error::Binding);
	}
	let mut bytes = vec![0; len];
	file.read_exact_at(0, &mut bytes)?;
	file.check_logical_eof()?;
	file.recheck_observation()?;
	dialect.decode(&bytes, profile.id(), &profile.verification_key())
}

fn require_live_phase(
	replay: &RemoteFinalizationReplay<'_>,
	activation: RemoteActivation<'_>,
) -> Result<(), Error> {
	use RemoteFinalizationPhase as Phase;
	let issue = replay.issue().map(|issue| match issue {
		RemoteReplayIssue::StageBootstrapMissing => ReplayIssue::PreBootstrap,
		RemoteReplayIssue::Framing(exacopy_journal::frame::FrameReadError::TornTail { .. }) => {
			ReplayIssue::Torn
		}
		_ => ReplayIssue::Refused,
	});
	let phase = replay.phase();
	if issue.is_some()
		|| !matches!(
			phase,
			Phase::Capture
				| Phase::Retired
				| Phase::Sealed
				| Phase::Verified
				| Phase::MetadataReady
		) {
		return Err(Error::Lifecycle {
			phase,
			boundary: replay.boundary(),
			issue,
		});
	}
	if phase == Phase::Retired
		&& !replay.retirements().last().is_some_and(|retired| {
			retired.head == replay.boundary().head
				&& retired.grant_digest == activation.grant_digest
				&& retired.qualification_digest == activation.qualification_digest
		}) {
		return Err(Error::Binding);
	}
	Ok(())
}

fn check_root(
	root: &DestinationRoot,
	profile: &LocalProfile,
	scope: &RemoteDownloadScope,
	job_name: &[u8],
) -> Result<(), Error> {
	if job_name == scope.destination.target()
		|| scope.destination.parent() != record_identity(root.identity())
		|| scope.destination.root() != profile.root_id(root.identity())?
	{
		return Err(Error::Binding);
	}
	Ok(())
}
