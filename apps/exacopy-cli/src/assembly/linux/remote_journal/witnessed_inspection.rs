//! Selector-2 terminal inspection under shared, read-only job custody.

use std::fmt;

use ed25519_dalek::VerifyingKey;
use exacopy_content::{MeasureError, measure_at};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::remote_source::SftpPathRoot;
use exacopy_journal::remote_download::qualification::continuation::{
	RemoteContinuationQualificationError, VerifiedRemoteWitnessQualification,
};
use exacopy_journal::remote_download::qualification::{
	RemoteQualificationError, RemoteQualificationRouteClass, RemoteQualificationTrust,
	verify_remote_destination_qualification,
};
use exacopy_journal::remote_download::replay::{RemoteReplayBoundary, RemoteReplayIssue};
use exacopy_journal::remote_download::witness::RemoteReceiptReady;
use exacopy_journal::remote_download::witness::records::RemoteWitnessedOutcome;
#[cfg(test)]
use exacopy_journal::remote_download::witness::replay::RemoteReceiptReadyInspection;
use exacopy_journal::remote_download::witness::replay::{
	RemoteCommittedReceiptInspection, RemoteWitnessedCloseoutReplay,
	RemoteWitnessedPublicExpectation, RemoteWitnessedReplayPhase, RemoteWitnessedReplaySelection,
	replay_remote_witnessed_closeout,
};
use exacopy_journal::remote_download::{RemoteDownloadScope, RemoteScopeDigest};
use exacopy_journal::{JournalJobId, LinuxFileIdentity};
use exacopy_platform::linux::{
	DestinationRoot, ReadError, RecoveryFile, RetainedPrefixSelection, WitnessedPublishedSelection,
	WitnessedTerminalJournal, WitnessedTerminalSelection, observe_remote_destination,
};

use crate::assembly::linux::remote_download::measure_running_executable;
use crate::profile::profile_id_for_key;

use super::admission::OwnerDialect;
use super::lease::{check_root_for_key, read_owner_for_key};
use super::{Error, ReplayIssue, component, job_name, record_identity};

/// Independent historical bindings retained outside the job.
#[derive(Debug)]
pub(crate) struct ArchivedWitnessedSelection {
	pub(crate) job: JournalJobId,
	pub(crate) owner_key: VerifyingKey,
	pub(crate) route: RemoteQualificationRouteClass,
	pub(crate) path_root: SftpPathRoot,
	pub(crate) scope: RemoteScopeDigest,
	pub(crate) op1_digest: [u8; 32],
	pub(crate) op2_digest: [u8; 32],
	pub(crate) base_grant_digest: [u8; 32],
	pub(crate) committed: RemoteReplayBoundary,
	pub(crate) receipt_digest: [u8; 32],
}

/// Terminal inspection under a held root and independently selected attestation trust.
pub(crate) struct WitnessedInspectionRequest<'selection> {
	pub(crate) root: &'selection DestinationRoot,
	pub(crate) archived: &'selection ArchivedWitnessedSelection,
	pub(crate) op1_record: &'selection [u8],
	pub(crate) op1_trust: &'selection RemoteQualificationTrust<'selection>,
	pub(crate) qualification: &'selection VerifiedRemoteWitnessQualification,
}

/// Point-in-time read-back association under the independently selected scope.
#[derive(Debug)]
pub(crate) struct WitnessedTerminalInspection {
	pub(crate) committed: RemoteReplayBoundary,
	pub(crate) recorded: RemoteWitnessedOutcome,
	pub(crate) stream_length: u64,
	pub(crate) canonical_receipt: Vec<u8>,
	pub(crate) receipt_digest: [u8; 32],
}

#[derive(Debug)]
pub(crate) enum WitnessedInspectionError {
	Job(Error),
	SubstrateChanged,
	ExecutionMismatch(RemoteContinuationQualificationError),
	OrdinaryQualification(RemoteQualificationError),
	SelectionMismatch,
	History {
		phase: RemoteWitnessedReplayPhase,
		boundary: RemoteReplayBoundary,
		issue: Option<ReplayIssue>,
	},
	PublicData(MeasureError<ReadError>),
	PublicDigestMismatch,
	ReceiptMismatch,
}

impl fmt::Display for WitnessedInspectionError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Job(cause) => cause.fmt(formatter),
			Self::SubstrateChanged => formatter.write_str("terminal inspection substrate changed"),
			Self::ExecutionMismatch(cause) => cause.fmt(formatter),
			Self::OrdinaryQualification(cause) => cause.fmt(formatter),
			Self::SelectionMismatch => {
				formatter.write_str("archived witness selection did not match")
			}
			Self::History {
				phase,
				boundary,
				issue,
			} => write!(
				formatter,
				"terminal inspection refused {phase:?} after byte {} ({issue:?})",
				boundary.offset,
			),
			Self::PublicData(cause) => cause.fmt(formatter),
			Self::PublicDigestMismatch => formatter.write_str("witnessed public digest changed"),
			Self::ReceiptMismatch => formatter.write_str("committed receipt did not match"),
		}
	}
}

impl std::error::Error for WitnessedInspectionError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Job(cause) => Some(cause),
			Self::ExecutionMismatch(cause) => Some(cause),
			Self::OrdinaryQualification(cause) => Some(cause),
			Self::PublicData(cause) => Some(cause),
			_ => None,
		}
	}
}

impl From<Error> for WitnessedInspectionError {
	fn from(cause: Error) -> Self {
		Self::Job(cause)
	}
}

impl WitnessedInspectionRequest<'_> {
	/// Checks the committed receipt and the retained witnessed public object.
	/// The reported association carries no mutation or later observation authority.
	pub(crate) fn inspect(
		self,
		scratch: &mut [u8],
	) -> Result<WitnessedTerminalInspection, WitnessedInspectionError> {
		self.with_history(|held, replay, scope| {
			let inspection = selected_terminal_history(
				replay,
				held.segment_length(),
				self.archived.committed,
				self.archived.receipt_digest,
			)?;
			let selected = inspection.record();
			let artifacts = held
				.inspect(native_selection(
					inspection.publication(),
					selected,
					inspection.pending_name(),
					inspection.final_name(),
				)?)
				.map_err(Error::from)?;
			let stream_length =
				Self::verify_public(scope, inspection.publication(), artifacts.target(), scratch)?;
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
				stream_length,
				canonical_receipt: bytes,
				receipt_digest: selected.digest(),
			})
		})
	}

	fn with_history<T>(
		&self,
		inspect: impl FnOnce(
			&WitnessedTerminalJournal<'_>,
			&RemoteWitnessedCloseoutReplay,
			&RemoteDownloadScope,
		) -> Result<T, WitnessedInspectionError>,
	) -> Result<T, WitnessedInspectionError> {
		let archived = self.archived;
		let key = &archived.owner_key;
		if self.op1_trust.owner_key != key
			|| self.op1_trust.scope.route != archived.route
			|| !self.qualification.matches_owner(key)
			|| self.qualification.scope().common.route != archived.route
			|| self.qualification.digest().as_bytes() != &archived.op2_digest
		{
			return Err(WitnessedInspectionError::SelectionMismatch);
		}
		let dialect = OwnerDialect::select_qualification(archived.route, archived.path_root)?;
		let profile = profile_id_for_key(key).map_err(Error::from)?;
		let build = measure_running_executable().map_err(Error::from)?;
		let observed = observe_remote_destination(self.root).map_err(Error::Qualification)?;
		self.qualification
			.match_current(build, &observed)
			.map_err(WitnessedInspectionError::ExecutionMismatch)?;
		if self.op1_trust.scope.build != build {
			return Err(WitnessedInspectionError::OrdinaryQualification(
				RemoteQualificationError::Scope,
			));
		}
		let op1 =
			verify_remote_destination_qualification(self.op1_record, self.op1_trust, &observed)
				.map_err(WitnessedInspectionError::OrdinaryQualification)?;
		if op1.digest() != archived.op1_digest {
			return Err(WitnessedInspectionError::SelectionMismatch);
		}

		let name = job_name(archived.job);
		let job = self
			.root
			.open_recovery_job(component(name.as_bytes())?)
			.map_err(Error::from)?;
		let lease = job.try_read_lease().map_err(Error::from)?;
		let held = lease
			.hold_witnessed_terminal_journal()
			.map_err(Error::from)?;
		let owner = read_owner_for_key(held.owner(), profile, key, dialect)?;
		let manifest = owner.manifest();
		let scope = &manifest.scope;
		if manifest.job != archived.job
			|| manifest.job_directory != record_identity(job.identity())
			|| scope.digest().map_err(Error::from)? != archived.scope
			|| OwnerDialect::select(scope.source.route(), scope.source.path_root())? != dialect
		{
			return Err(WitnessedInspectionError::SelectionMismatch);
		}
		check_root_for_key(self.root, key, scope, name.as_bytes())?;
		let trust = dialect.trust(&owner, profile, key)?;
		let selection = RemoteWitnessedReplaySelection {
			initial_v1_qualification: op1.digest(),
			fresh_v1_qualification: op1.digest(),
			qualification: self.qualification,
			grant_digest: archived.base_grant_digest,
		};
		let replay = replay_remote_witnessed_closeout(held.journal(), &trust, &selection)
			.map_err(Error::from)?;
		inspect(&held, &replay, scope)
	}

	fn verify_public(
		scope: &RemoteDownloadScope,
		expectation: &RemoteWitnessedPublicExpectation<'_>,
		target: &RecoveryFile,
		scratch: &mut [u8],
	) -> Result<u64, WitnessedInspectionError> {
		let length = target.len();
		if expectation.destination() != &scope.destination
			|| length != expectation.extent().get()
			|| target.observation().mode() != u32::from(expectation.mode())
		{
			return Err(Error::Binding.into());
		}
		verify_public_digest(expectation, scratch, |at, bytes| {
			target.read_exact_at(at, bytes)
		})?;
		Ok(length)
	}

	fn check_substrate(&self) -> Result<(), WitnessedInspectionError> {
		let observed = observe_remote_destination(self.root).map_err(Error::Qualification)?;
		if &observed != self.qualification.facts() {
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

pub(in crate::assembly::linux) fn selected_terminal_history(
	replay: &RemoteWitnessedCloseoutReplay,
	native_end: u64,
	committed: RemoteReplayBoundary,
	receipt_digest: [u8; 32],
) -> Result<RemoteCommittedReceiptInspection<'_>, WitnessedInspectionError> {
	let inspection = terminal_history(replay, native_end)?;
	if !first_unretired_witnessed_pass(replay)
		|| !matches!(inspection.outcome(), RemoteWitnessedOutcome::Submitted(_))
		|| inspection.boundary() != committed
		|| inspection.record().digest() != receipt_digest
	{
		return Err(WitnessedInspectionError::SelectionMismatch);
	}
	Ok(inspection)
}

pub(in crate::assembly::linux) fn first_unretired_witnessed_pass(
	replay: &RemoteWitnessedCloseoutReplay,
) -> bool {
	replay.pass_count().checked_sub(replay.attempts().len()) == Some(1)
		&& !replay.has_ordinary_retirements()
		&& replay.retirements().is_empty()
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

#[cfg(test)]
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

#[cfg(test)]
pub(in crate::assembly::linux) fn receipt_ready_history(
	replay: &RemoteWitnessedCloseoutReplay,
	native_end: u64,
) -> Result<RemoteReceiptReadyInspection<'_>, WitnessedInspectionError> {
	require_phase(
		replay,
		native_end,
		RemoteWitnessedReplayPhase::ReceiptReadyRequiresInspection,
	)?;
	replay
		.receipt_ready_inspection()
		.map_err(|cause| Error::from(cause).into())
}

#[cfg(test)]
pub(in crate::assembly::linux) fn verify_receipt_ready_bytes(
	inspection: &RemoteReceiptReadyInspection<'_>,
	identity: LinuxFileIdentity,
	bytes: &[u8],
) -> Result<(), WitnessedInspectionError> {
	if identity != inspection.record().receipt() || bytes != inspection.bytes() {
		return Err(WitnessedInspectionError::ReceiptMismatch);
	}
	Ok(())
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
	publication: &'name RemoteWitnessedPublicExpectation<'_>,
	receipt: RemoteReceiptReady,
	pending_name: &[u8],
	final_name: &[u8],
) -> Result<WitnessedTerminalSelection<'name>, Error> {
	let published = public_selection(publication)?;
	Ok(WitnessedTerminalSelection {
		job: published.job,
		destination: published.destination,
		stage: published.stage,
		witness_name: published.witness_name,
		uid: published.uid,
		gid: published.gid,
		extent: published.extent,
		journal_end: published.journal_end,
		pending_name: pending_name.try_into().map_err(|_| Error::Binding)?,
		final_name: final_name.try_into().map_err(|_| Error::Binding)?,
		receipt: identity(receipt.receipt()),
		receipt_len: receipt.length(),
	})
}

pub(super) fn public_selection<'name>(
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
