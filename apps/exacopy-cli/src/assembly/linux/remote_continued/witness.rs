pub(super) use super::prefix::WitnessPrefix;
use std::convert::Infallible;
use std::io::Read;

use ed25519_dalek::SigningKey;
use exacopy_endpoint::ReadView;
use exacopy_endpoint::connection_retry::{ConnectionBinding, RetryError};
use exacopy_journal::LinuxFileIdentity;
use exacopy_journal::frame::{FrameKind, FrameReader, FrameWriter};
use exacopy_journal::remote_download::qualification::continuation::CurrentRemoteWitnessQualification;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::budget::{
	WitnessedPassBudget, WitnessedPassProgress, WitnessedPassRemaining,
};
use exacopy_journal::remote_download::witness::replay::{
	RemoteWitnessedCloseoutReplay, RemoteWitnessedReplayPhase, RemoteWitnessedReplaySelection,
	replay_remote_witnessed_closeout,
};
use exacopy_journal::remote_download::witness::{
	RemoteWitnessIntent, RemoteWitnessIntentExpectation,
};
use exacopy_journal::remote_download::{RemoteBootstrapTrust, RemoteDownloadError};
use exacopy_platform::linux::{
	ActiveWitnessReservation, ContinuationReservationError, ProtectedWitnessError,
	SealedProtectedWitness, StageError, WitnessLinkCandidate, WitnessReservationObservationError,
};
use exacopy_sftp::{SftpSource, SftpSourceError};
use exacopy_transfer::remote_resume::prefix::{
	LentRetainedSuffix, PrefixVerificationError, SuffixSourceObservation,
};

use super::activation::{model_head, reservation_plan};
use crate::assembly::linux::remote_download::{
	BoundRouteRetirement, RemoteGrant, RemoteRouteCloseError, RetiredBoundRoute,
};
use crate::assembly::linux::remote_witness_authority::{
	BoundWitnessStage, ConsentRefusal, WitnessRetentionApproval,
};

pub(super) mod prepublication;
pub(super) mod zero_tail;

#[derive(Debug)]
pub(super) enum WitnessFailure<R> {
	Binding,
	Source(PrefixVerificationError<R, Infallible>),
	Route(RemoteRouteCloseError),
	Stage(StageError),
	Custody(WitnessReservationObservationError),
	Journal(ContinuationReservationError<WitnessAdmissionError>),
	Link(ProtectedWitnessError<WitnessAdmissionError>),
	WitnessedVerification(StageError),
	WitnessedDigestMismatch,
}

#[derive(Debug)]
pub(super) enum WitnessAdmissionError {
	Binding,
	Format(RemoteDownloadError),
	Consent(ConsentRefusal),
	Route(RetryError),
	Custody(WitnessReservationObservationError),
	Stage(StageError),
}

#[derive(Clone, Copy)]
pub(super) struct WitnessPass<'scope, 'name> {
	pub(super) trust: &'scope RemoteBootstrapTrust<'scope>,
	pub(super) selection: &'scope RemoteWitnessedReplaySelection<'scope>,
	pub(super) current: &'scope CurrentRemoteWitnessQualification<'scope>,
	pub(super) signer: &'scope SigningKey,
	pub(super) budget: WitnessedPassBudget,
	pub(super) approval: &'scope WitnessRetentionApproval<'scope, 'name>,
	pub(super) grant: &'scope RemoteGrant,
	pub(super) names: BoundWitnessStage<'name>,
}

pub(super) struct LinkedWitnessedStage<'view, 'lease, 'scope, 'name> {
	pub(super) chain: SealedProtectedWitness<'view, 'lease>,
	pub(super) intent: RemoteWitnessIntent,
	pub(super) digest: [u8; 32],
	source: SuffixSourceObservation,
	route: RetiredBoundRoute,
	pass: WitnessPass<'scope, 'name>,
}

impl LinkedWitnessedStage<'_, '_, '_, '_> {
	fn confirm_digest<R>(&self, scratch: &mut [u8]) -> Result<(), WitnessFailure<R>> {
		if hash_stage(self.chain.stage(), scratch).map_err(WitnessFailure::WitnessedVerification)?
			!= self.source.digest()
		{
			return Err(WitnessFailure::WitnessedDigestMismatch);
		}
		Ok(())
	}
}

impl<'scope, 'name> WitnessPass<'scope, 'name> {
	/// Complete both termination observations while the original lease and
	/// reservation remain held, then make the one permitted protected link.
	pub(super) async fn close_and_link<'view, 'lease, Check>(
		&self,
		source: LentRetainedSuffix<'view, '_, SftpSource<'_, Check>, WitnessPrefix<'lease>>,
		retirement: BoundRouteRetirement,
		stage: WitnessLinkCandidate<'view, 'lease>,
		active: ActiveWitnessReservation<'lease>,
		scratch: &mut [u8],
	) -> Result<LinkedWitnessedStage<'view, 'lease, 'scope, 'name>, WitnessFailure<SftpSourceError>>
	where
		Check: FnMut(ConnectionBinding) -> Result<(), RetryError>,
	{
		use WitnessFailure as Error;
		let binding = source.source().binding();
		if binding != retirement.binding()
			|| !stage.matches_reader(source.reader().native())
			|| active.plan() != reservation_plan(self.budget).map_err(|_| Error::Binding)?
		{
			return Err(Error::Binding);
		}
		active.replay_for_witness(&stage).map_err(Error::Custody)?;
		let source = source.finish().await.map_err(Error::Source)?;
		let route = retirement
			.finish(source.epoch())
			.await
			.map_err(Error::Route)?;
		if route.binding() != binding || !route.matches_invocation(self.grant) {
			return Err(Error::Binding);
		}
		if source.length() != self.names.source_extent
			|| stage.length() != source.length()
			|| !std::ptr::eq(self.selection.qualification, self.current.verified())
		{
			return Err(Error::Binding);
		}

		let prior = self
			.replay(active.replay_for_witness(&stage).map_err(Error::Custody)?)
			.map_err(|_| Error::Binding)?;
		let history = prior.active_prefix_history().map_err(|_| Error::Binding)?;
		let prepared = history.prepared();
		if model_head(prior.boundary()) != active.head()
			|| history.context() != self.names.context
			|| history.scope() != self.names.scope
			|| history.name() != self.names.retained.stage.as_bytes()
			|| history.epochs().source.get() != source.epoch().get()
			|| history.epochs().run.get() != u64::from(self.budget.new_run().get())
			|| history.source().length().get() != source.length()
			|| prepared.file
				!= LinuxFileIdentity::new(
					self.names.retained.file.device,
					self.names.retained.file.inode,
				)
			|| hash_stage(&stage, scratch).map_err(Error::Stage)? != source.digest()
		{
			return Err(Error::Binding);
		}
		let previous = prior.boundary();
		let available = self
			.budget
			.recheck_remaining(
				previous,
				WitnessedPassProgress::Continued {
					completed_checkpoints: self.budget.checkpoint_count(),
				},
			)
			.map_err(|_| Error::Binding)?;
		if !fits(self.budget, previous, available)
			|| u64::from(available.receipt_bytes()) != active.receipt_capacity()
		{
			return Err(Error::Binding);
		}
		let expected = RemoteWitnessIntentExpectation {
			coverage: prior
				.complete_coverage_predecessor()
				.map_err(|_| Error::Binding)?,
			qualification: self.current.verified(),
			stage_directory: prepared.directory,
			job_directory: self.names.job,
			consent: self.approval.commitment(),
		};
		let payload = {
			let _guard = self
				.approval
				.enter(self.grant, self.names)
				.map_err(|_| Error::Binding)?;
			self.trust
				.sign_witness_intent(&expected, self.signer)
				.map_err(|_| Error::Binding)?
		};
		let mut writer = FrameWriter::new(Vec::new(), previous.head);
		let head = writer
			.append(FrameKind::RemoteWitnessIntent, &payload)
			.map_err(|_| Error::Binding)?;
		let bytes = writer.into_inner();
		let next = RemoteReplayBoundary {
			head,
			offset: previous
				.offset
				.checked_add(bytes.len() as u64)
				.ok_or(Error::Binding)?,
		};
		let frame = FrameReader::new(bytes.as_slice(), previous.head)
			.next_frame()
			.map_err(|_| Error::Binding)?
			.ok_or(Error::Binding)?;
		let intent = self
			.trust
			.from_witness_intent_frame(&frame, next, &expected)
			.map_err(|_| Error::Binding)?;
		let token = active
			.append_witness_intent(
				stage,
				model_head(next),
				&bytes,
				intent.witness_name(),
				|actual| {
					let consent = self.approval.commitment();
					if actual.stage != self.names.retained
						|| actual.job.device() != self.names.job.device()
						|| actual.job.inode() != self.names.job.inode()
						|| actual.authority.qualification
							!= *self.current.verified().digest().as_bytes()
						|| actual.authority.base_grant != consent.base_grant_digest
						|| actual.authority.retention_approval != consent.approval_digest
						|| actual.previous != model_head(previous)
						|| actual.successor != model_head(next)
					{
						return Err(WitnessAdmissionError::Binding);
					}
					self.approval
						.enter(self.grant, self.names)
						.map_err(WitnessAdmissionError::Consent)
				},
				|input| {
					let exact = self.replay(input)?;
					let remaining = self
						.budget
						.recheck_remaining(exact.boundary(), WitnessedPassProgress::WitnessIntent)
						.map_err(|_| WitnessAdmissionError::Binding)?;
					if !fits(self.budget, exact.boundary(), remaining) {
						return Err(WitnessAdmissionError::Binding);
					}
					confirm_intent(&exact, intent)
				},
			)
			.map_err(Error::Journal)?;
		let chain = token
			.link_protected_witness(|held, _effect| {
				if held != model_head(next) {
					return Err(WitnessAdmissionError::Binding);
				}
				self.approval
					.enter(self.grant, self.names)
					.map_err(WitnessAdmissionError::Consent)
			})
			.map_err(Error::Link)?;
		Ok(LinkedWitnessedStage {
			chain,
			intent,
			digest: source.digest(),
			source,
			route,
			pass: *self,
		})
	}

	fn replay(
		&self,
		bytes: impl Read,
	) -> Result<RemoteWitnessedCloseoutReplay, WitnessAdmissionError> {
		replay_remote_witnessed_closeout(bytes, self.trust, self.selection)
			.map_err(WitnessAdmissionError::Format)
	}
}

pub(super) fn confirm_intent(
	replay: &RemoteWitnessedCloseoutReplay,
	intent: RemoteWitnessIntent,
) -> Result<[u8; 40], WitnessAdmissionError> {
	if replay.issue().is_some()
		|| replay.phase() != RemoteWitnessedReplayPhase::WitnessIntentRequiresInspection
		|| replay.boundary() != intent.boundary()
		|| replay.witness() != Some(intent)
	{
		return Err(WitnessAdmissionError::Binding);
	}
	Ok(intent.witness_name())
}

fn fits(
	budget: WitnessedPassBudget,
	at: RemoteReplayBoundary,
	need: WitnessedPassRemaining,
) -> bool {
	at.offset
		.checked_add(need.journal_bytes())
		.is_some_and(|end| end <= budget.reserved_end())
		&& at
			.head
			.sequence()
			.checked_add(u64::from(need.journal_frames()))
			.zip(
				budget
					.boundary()
					.head
					.sequence()
					.checked_add(u64::from(budget.reserved_frames())),
			)
			.is_some_and(|(end, last)| end <= last)
}

fn hash_stage(
	stage: &impl ReadView<Error = StageError>,
	scratch: &mut [u8],
) -> Result<[u8; 32], StageError> {
	let width = scratch.len().min(64 * 1024);
	if width == 0 {
		return Err(StageError::InvalidLength);
	}
	stage.recheck_observation()?;
	let length = stage.length();
	let mut hash = blake3::Hasher::new();
	let mut offset = 0;
	while offset < length {
		let count = usize::try_from((length - offset).min(width as u64))
			.map_err(|_| StageError::InvalidLength)?;
		stage.read_exact_at(offset, &mut scratch[..count])?;
		hash.update(&scratch[..count]);
		offset += count as u64;
	}
	stage.recheck_observation()?;
	Ok(*hash.finalize().as_bytes())
}
