//! Selector-2 publication and terminal inspection under shared, read-only job custody.

use exacopy_content::{MeasureError, measure_at};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_journal::remote_download::RemoteDownloadScope;
use exacopy_journal::remote_download::replay::{RemoteReplayBoundary, RemoteReplayIssue};
use exacopy_journal::remote_download::witness::records::RemoteWitnessedOutcome;
use exacopy_journal::remote_download::witness::replay::{
	RemoteCommittedReceiptInspection, RemoteWitnessedCloseoutReplay,
	RemoteWitnessedPublicExpectation, RemoteWitnessedReplayPhase, RemoteWitnessedReplaySelection,
	replay_remote_witnessed_closeout,
};
use exacopy_journal::{JournalJobId, LinuxFileIdentity};
use exacopy_platform::linux::{
	DestinationRoot, ReadError, RecoveryFile, RetainedPrefixSelection, WitnessedPublishedSelection,
	WitnessedTerminalJournal, WitnessedTerminalSelection, observe_remote_destination,
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

/// Verified public data observed now at the exact historical kind-7 cut.
#[derive(Debug)]
pub(in crate::assembly::linux) struct WitnessedIntentAssessment {
	pub(in crate::assembly::linux) intent: RemoteReplayBoundary,
	pub(in crate::assembly::linux) target: LinuxFileIdentity,
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
		self.with_history(|held, replay| {
			let inspection = terminal_history(replay, held.segment_length())?;
			let selected = inspection.record();
			let artifacts = held
				.inspect(native_selection(&inspection)?)
				.map_err(Error::from)?;
			self.verify_public(inspection.publication(), artifacts.target(), scratch)?;
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
		})
	}

	/// Independently observes the already-named witnessed file at exact kind 7.
	/// The result describes only this held observation, with no append capability.
	pub(in crate::assembly::linux) fn inspect_publish_intent(
		self,
		scratch: &mut [u8],
	) -> Result<WitnessedIntentAssessment, WitnessedInspectionError> {
		self.with_history(|held, replay| {
			let inspection = intent_history(replay, held.segment_length())?;
			let artifacts = held
				.inspect_published(public_selection(&inspection)?)
				.map_err(Error::from)?;
			self.verify_public(&inspection, artifacts.target(), scratch)?;
			self.check_substrate()?;
			artifacts.recheck().map_err(Error::from)?;
			Ok(WitnessedIntentAssessment {
				intent: inspection.boundary(),
				target: record_identity(artifacts.target().identity()),
			})
		})
	}

	fn with_history<T>(
		&self,
		inspect: impl FnOnce(
			&WitnessedTerminalJournal<'_>,
			&RemoteWitnessedCloseoutReplay,
		) -> Result<T, WitnessedInspectionError>,
	) -> Result<T, WitnessedInspectionError> {
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
		inspect(&held, &replay)
	}

	fn verify_public(
		&self,
		expectation: &RemoteWitnessedPublicExpectation<'_>,
		target: &RecoveryFile,
		scratch: &mut [u8],
	) -> Result<(), WitnessedInspectionError> {
		if expectation.destination() != &self.scope.destination
			|| target.observation().mode() != u32::from(expectation.mode())
		{
			return Err(Error::Binding.into());
		}
		verify_public_digest(expectation, scratch, |at, bytes| {
			target.read_exact_at(at, bytes)
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

pub(in crate::assembly::linux) fn verify_public_digest(
	expectation: &RemoteWitnessedPublicExpectation<'_>,
	scratch: &mut [u8],
	read: impl FnMut(u64, &mut [u8]) -> Result<(), ReadError>,
) -> Result<(), WitnessedInspectionError> {
	let measured = measure_at(expectation.extent().get(), scratch, read)
		.map_err(WitnessedInspectionError::PublicData)?;
	if measured.as_bytes() != expectation.stage_digest().as_bytes() {
		return Err(WitnessedInspectionError::PublicDigestMismatch);
	}
	Ok(())
}

pub(in crate::assembly::linux) fn terminal_history(
	replay: &RemoteWitnessedCloseoutReplay,
	native_end: u64,
) -> Result<RemoteCommittedReceiptInspection<'_>, WitnessedInspectionError> {
	require_phase(
		replay,
		native_end,
		RemoteWitnessedReplayPhase::ReceiptCommitted,
	)?;
	replay
		.committed_receipt_inspection()
		.map_err(|cause| Error::from(cause).into())
}

pub(in crate::assembly::linux) fn intent_history(
	replay: &RemoteWitnessedCloseoutReplay,
	native_end: u64,
) -> Result<RemoteWitnessedPublicExpectation<'_>, WitnessedInspectionError> {
	require_phase(
		replay,
		native_end,
		RemoteWitnessedReplayPhase::PublishIntentRequiresObservation,
	)?;
	replay
		.publish_intent_inspection()
		.map_err(|cause| Error::from(cause).into())
}

fn require_phase(
	replay: &RemoteWitnessedCloseoutReplay,
	native_end: u64,
	expected: RemoteWitnessedReplayPhase,
) -> Result<(), WitnessedInspectionError> {
	let issue = replay.issue().map(|issue| match issue {
		RemoteReplayIssue::StageBootstrapMissing => ReplayIssue::PreBootstrap,
		RemoteReplayIssue::Framing(exacopy_journal::frame::FrameReadError::TornTail { .. }) => {
			ReplayIssue::Torn
		}
		_ => ReplayIssue::Refused,
	});
	if issue.is_some() || replay.phase() != expected || replay.boundary().offset != native_end {
		return Err(WitnessedInspectionError::History {
			phase: replay.phase(),
			boundary: replay.boundary(),
			issue,
		});
	}
	Ok(())
}

fn native_selection<'name>(
	inspection: &'name RemoteCommittedReceiptInspection<'_>,
) -> Result<WitnessedTerminalSelection<'name>, Error> {
	let published = public_selection(inspection.publication())?;
	let receipt = inspection.record();
	Ok(WitnessedTerminalSelection {
		job: published.job,
		destination: published.destination,
		stage: published.stage,
		witness_name: published.witness_name,
		uid: published.uid,
		gid: published.gid,
		extent: published.extent,
		journal_end: published.journal_end,
		pending_name: inspection
			.pending_name()
			.try_into()
			.map_err(|_| Error::Binding)?,
		final_name: inspection
			.final_name()
			.try_into()
			.map_err(|_| Error::Binding)?,
		receipt: identity(receipt.receipt()),
		receipt_len: receipt.length(),
	})
}

fn public_selection<'name>(
	inspection: &'name RemoteWitnessedPublicExpectation<'_>,
) -> Result<WitnessedPublishedSelection<'name>, Error> {
	let stage = inspection.stage();
	let metadata = inspection.metadata();
	Ok(WitnessedPublishedSelection {
		job: identity(inspection.witness().job_directory()),
		destination: identity(inspection.destination().parent()),
		stage: RetainedPrefixSelection {
			stage: component(inspection.stage_name())?,
			target: component(inspection.destination().target())?,
			directory: identity(stage.directory),
			file: identity(stage.file),
		},
		witness_name: inspection.witness().witness_name(),
		uid: metadata.uid,
		gid: metadata.gid,
		extent: inspection.extent().get(),
		journal_end: inspection.boundary().offset,
	})
}

fn identity(value: LinuxFileIdentity) -> JobFileIdentity {
	JobFileIdentity {
		device: value.device(),
		inode: value.inode(),
	}
}
