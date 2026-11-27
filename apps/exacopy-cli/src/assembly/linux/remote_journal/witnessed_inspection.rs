//! Terminal selector-2 inspection under shared, read-only job custody.

use exacopy_content::{MeasureError, measure_at};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_journal::remote_download::RemoteDownloadScope;
use exacopy_journal::remote_download::replay::{RemoteReplayBoundary, RemoteReplayIssue};
use exacopy_journal::remote_download::witness::records::RemoteWitnessedOutcome;
use exacopy_journal::remote_download::witness::replay::{
	RemoteCommittedReceiptInspection, RemoteWitnessedCloseoutReplay, RemoteWitnessedReplayPhase,
	RemoteWitnessedReplaySelection, replay_remote_witnessed_closeout,
};
use exacopy_journal::{JournalJobId, LinuxFileIdentity};
use exacopy_platform::linux::{
	DestinationRoot, ReadError, RetainedPrefixSelection, WitnessedTerminalSelection,
	observe_remote_destination,
};

use crate::profile::LocalProfile;

use super::admission::OwnerDialect;
use super::lease::{check_root, read_owner};
use super::{Error, ReplayIssue, component, job_name, record_identity};

/// The profile, signed scope and exact archived evidence are selected outside the job.
pub(in crate::assembly::linux) struct WitnessedInspectionRequest<'scope> {
	pub(in crate::assembly::linux) root: &'scope DestinationRoot,
	pub(in crate::assembly::linux) profile: &'scope LocalProfile,
	pub(in crate::assembly::linux) job: JournalJobId,
	pub(in crate::assembly::linux) scope: &'scope RemoteDownloadScope,
	pub(in crate::assembly::linux) selection: &'scope RemoteWitnessedReplaySelection<'scope>,
}

/// Point-in-time read-back association under the independently selected scope.
#[derive(Debug)]
pub(in crate::assembly::linux) struct WitnessedTerminalInspection {
	pub(in crate::assembly::linux) committed: RemoteReplayBoundary,
	pub(in crate::assembly::linux) recorded: RemoteWitnessedOutcome,
	pub(in crate::assembly::linux) canonical_receipt: Vec<u8>,
}

#[derive(Debug)]
pub(in crate::assembly::linux) enum WitnessedInspectionError {
	Job(Error),
	SubstrateChanged,
	History {
		phase: RemoteWitnessedReplayPhase,
		boundary: RemoteReplayBoundary,
		issue: Option<ReplayIssue>,
	},
	PublicData(MeasureError<ReadError>),
	PublicDigestMismatch,
	ReceiptMismatch,
}

impl From<Error> for WitnessedInspectionError {
	fn from(cause: Error) -> Self {
		Self::Job(cause)
	}
}

impl WitnessedInspectionRequest<'_> {
	/// Checks the committed receipt and the retained witnessed public object.
	/// The reported association carries no mutation or later observation authority.
	pub(in crate::assembly::linux) fn inspect(
		self,
		scratch: &mut [u8],
	) -> Result<WitnessedTerminalInspection, WitnessedInspectionError> {
		let key = self.profile.verification_key();
		if !self.selection.qualification.matches_owner(&key) {
			return Err(Error::Binding.into());
		}
		let dialect =
			OwnerDialect::select(self.scope.source.route(), self.scope.source.path_root())?;
		let name = job_name(self.job);
		check_root(self.root, self.profile, self.scope, name.as_bytes())?;
		self.check_substrate()?;
		let job = self
			.root
			.open_recovery_job(component(name.as_bytes())?)
			.map_err(Error::from)?;
		let lease = job.try_read_lease().map_err(Error::from)?;
		let held = lease
			.hold_witnessed_terminal_journal()
			.map_err(Error::from)?;
		let owner = read_owner(held.owner(), self.profile, dialect)?;
		let manifest = owner.manifest();
		if manifest.job != self.job
			|| manifest.job_directory != record_identity(job.identity())
			|| &manifest.scope != self.scope
		{
			return Err(Error::Binding.into());
		}
		let trust = dialect.trust(&owner, self.profile.id(), &key)?;
		let replay = replay_remote_witnessed_closeout(held.journal(), &trust, self.selection)
			.map_err(Error::from)?;
		let inspection = terminal_history(&replay, held.segment_length())?;
		if inspection.destination() != &self.scope.destination
			|| inspection.witness().job_directory() != record_identity(job.identity())
			|| inspection.destination().parent() != record_identity(job.destination_identity())
		{
			return Err(Error::Binding.into());
		}
		let selected = inspection.record();
		let artifacts = held
			.inspect(native_selection(&inspection)?)
			.map_err(Error::from)?;
		if artifacts.target().observation().mode() != u32::from(inspection.mode()) {
			return Err(Error::Binding.into());
		}
		let measured = measure_at(inspection.extent().get(), scratch, |at, bytes| {
			artifacts.target().read_exact_at(at, bytes)
		})
		.map_err(WitnessedInspectionError::PublicData)?;
		if measured.as_bytes() != inspection.stage_digest().as_bytes() {
			return Err(WitnessedInspectionError::PublicDigestMismatch);
		}
		let receipt = artifacts.receipt();
		let mut bytes = vec![0; usize::from(selected.length())];
		receipt.read_exact_at(0, &mut bytes).map_err(Error::from)?;
		receipt.check_logical_eof().map_err(Error::from)?;
		if !replay.matches_committed_receipt(record_identity(receipt.identity()), &bytes) {
			return Err(WitnessedInspectionError::ReceiptMismatch);
		}
		self.check_substrate()?;
		artifacts.recheck().map_err(Error::from)?;
		Ok(WitnessedTerminalInspection {
			committed: inspection.boundary(),
			recorded: inspection.outcome(),
			canonical_receipt: bytes,
		})
	}

	fn check_substrate(&self) -> Result<(), WitnessedInspectionError> {
		let observed = observe_remote_destination(self.root).map_err(Error::Qualification)?;
		if &observed != self.selection.qualification.facts() {
			return Err(WitnessedInspectionError::SubstrateChanged);
		}
		Ok(())
	}
}

pub(in crate::assembly::linux) fn terminal_history(
	replay: &RemoteWitnessedCloseoutReplay,
	native_end: u64,
) -> Result<RemoteCommittedReceiptInspection<'_>, WitnessedInspectionError> {
	let issue = replay.issue().map(|issue| match issue {
		RemoteReplayIssue::StageBootstrapMissing => ReplayIssue::PreBootstrap,
		RemoteReplayIssue::Framing(exacopy_journal::frame::FrameReadError::TornTail { .. }) => {
			ReplayIssue::Torn
		}
		_ => ReplayIssue::Refused,
	});
	if issue.is_some()
		|| replay.phase() != RemoteWitnessedReplayPhase::ReceiptCommitted
		|| replay.boundary().offset != native_end
	{
		return Err(WitnessedInspectionError::History {
			phase: replay.phase(),
			boundary: replay.boundary(),
			issue,
		});
	}
	replay
		.committed_receipt_inspection()
		.map_err(|cause| Error::from(cause).into())
}

fn native_selection<'name>(
	inspection: &'name RemoteCommittedReceiptInspection<'_>,
) -> Result<WitnessedTerminalSelection<'name>, Error> {
	let stage = inspection.stage();
	let metadata = inspection.metadata();
	let receipt = inspection.record();
	Ok(WitnessedTerminalSelection {
		job: identity(inspection.witness().job_directory()),
		destination: identity(inspection.destination().parent()),
		stage: RetainedPrefixSelection {
			stage: component(inspection.stage_name())?,
			target: component(inspection.destination().target())?,
			directory: identity(stage.directory),
			file: identity(stage.file),
		},
		witness_name: inspection.witness().witness_name(),
		pending_name: inspection
			.pending_name()
			.try_into()
			.map_err(|_| Error::Binding)?,
		final_name: inspection
			.final_name()
			.try_into()
			.map_err(|_| Error::Binding)?,
		uid: metadata.uid,
		gid: metadata.gid,
		extent: inspection.extent().get(),
		receipt: identity(receipt.receipt()),
		receipt_len: receipt.length(),
		journal_end: inspection.boundary().offset,
	})
}

fn identity(value: LinuxFileIdentity) -> JobFileIdentity {
	JobFileIdentity {
		device: value.device(),
		inode: value.inode(),
	}
}
