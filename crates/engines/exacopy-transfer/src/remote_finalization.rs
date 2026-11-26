//! Linux preserve-mode finalization of one completed agentless SFTP capture.

use std::io::Write as _;

use exacopy_endpoint::linux_publication::{
	PublicationFailure, ReceiptDirectory as _, ReceiptRecord as _,
};
use exacopy_journal::frame::ChainHead;
use exacopy_journal::remote_download::RemoteScopeDigest;
use exacopy_journal::remote_download::finalization::{
	RemoteDownloadReceipt, RemoteFinalizationBody as Body, RemotePublicationObservation,
	RemoteReceiptDigest, RemoteReceiptFrames,
};
use exacopy_journal::{LinuxFileIdentity, NamespaceObservation, StreamDigest};
use exacopy_model::{CopyBinding, CopyEffect, CopyEvent, CopySession};

use crate::remote_capture::{CapturedStream, ObservedCapture};
use crate::remote_resume::{RestartedCapture, TargetState};

mod admission;
mod capabilities;
mod failure;
mod ledger;

pub use admission::RemoteFinalizationRequest;
pub use capabilities::{
	CurrentRemoteAuthority, RemoteAuthorityCheck, RemoteFinalizationJournal,
	RemoteFinalizationStage, RemotePublicationAuthority, RemotePublicationFacts,
	RemotePublicationFence, RemoteReadyStage, RemoteReadyStageFacts, RemoteReceiptWorkspace,
	RemoteStageLocation, RemoteStageNames,
};
pub use failure::{FinalizationCause, FinalizationFailure, FinalizationProgress};

use admission::Admitted;
use ledger::Ledger;

/// Settled result of a remote finalization operation after its journal barrier.
#[derive(Debug)]
#[non_exhaustive]
pub enum RemoteFinalizationOutcome {
	/// The selected stream was published with its explicit omissions and committed receipt.
	PublishedWithOmissions(CommittedRemoteReceipt),
	/// The exclusive operation refused a late incumbent and recorded that result.
	Conflict {
		/// Confirmed frame recording the actual no-replace refusal.
		observation: ChainHead,
	},
}

/// Complete immutable receipt from a live attempt, after kind-18 synchronization.
#[derive(Debug)]
pub struct CommittedRemoteReceipt {
	/// Consistency remains live-observed SFTP, with this exact source read pass and digest.
	pub capture: CapturedStream,
	/// Exact authenticated extent, policy, route and destination scope.
	pub scope: RemoteScopeDigest,
	/// Confirmed native file at the approved public name after the directory barriers.
	pub target: LinuxFileIdentity,
	/// Exact persisted remote receipt digest.
	pub digest: RemoteReceiptDigest,
	/// Exact synchronized record committing the receipt.
	pub commitment: ChainHead,
	/// Bytes written through the private receipt capability and synchronized.
	pub canonical_receipt: Vec<u8>,
}

/// Typed result of the generic finalization protocol.
pub type RemoteFinalizationResult<J, A, S, R> =
	Result<RemoteFinalizationOutcome, FinalizationFailure<J, A, S, R>>;

/// Finalizes an intact captured stage after the source terminal check and handle close.
///
/// The application owns the current held prefix, active scope/grant and
/// native destination eligibility. The stage wrapper and receipt workspace
/// refer to the same physical job, destination and current exclusive lease.
/// No native adapter or transport is selected here.
///
/// # Errors
/// Refuses stale authority, invalid capture binding or journal acknowledgements,
/// and retains uncertain effects for read-only reconciliation.
pub fn finalize_capture<S, J, A, R>(
	request: RemoteFinalizationRequest<'_>,
	capture: ObservedCapture<S>,
	journal: &mut J,
	authority: &mut A,
	receipts: &R,
) -> RemoteFinalizationResult<J::Error, A::Error, S::Error, R::Error>
where
	S: RemoteFinalizationStage,
	J: RemoteFinalizationJournal,
	A: RemoteAuthorityCheck,
	R: RemoteReceiptWorkspace,
{
	let (stage, stream) = capture.into_parts();
	execute(request, stage, stream, journal, authority, receipts)
}

/// Finalizes an intact restarted capture selected by the same strict journal.
///
/// # Errors
/// Refuses a mismatched synchronized restart or any unconfirmed finalization step.
pub fn finalize_restart<S, J, A, R>(
	request: RemoteFinalizationRequest<'_>,
	capture: RestartedCapture<S, LinuxFileIdentity>,
	journal: &mut J,
	authority: &mut A,
	receipts: &R,
) -> RemoteFinalizationResult<J::Error, A::Error, S::Error, R::Error>
where
	S: RemoteFinalizationStage,
	J: RemoteFinalizationJournal,
	A: RemoteAuthorityCheck,
	R: RemoteReceiptWorkspace,
{
	let (stage, stream, synced) = capture.into_parts();
	let scope = synced.record.scope;
	if synced.head != request.prepared.head()
		|| synced.record.predecessor != request.allocation.head()
		|| synced.record.next.source != stream.epoch
		|| synced.record.length != stream.length
		|| scope.owner != request.owner.digest()
		|| scope.job != request.owner.manifest().job
		|| scope.entry != request.owner.manifest().scope.entry
		|| scope.approved_scope.as_bytes() != request.authority.scope.as_bytes()
		|| scope.maximum_length != request.owner.manifest().scope.maximum_extent.get()
		|| !request.replay.attempts().last().is_some_and(|attempt| {
			attempt.epochs().run.get() == synced.record.next.run.get()
				&& attempt
					.prepared()
					.is_some_and(|prepared| prepared.file == synced.record.next.stage)
		}) {
		return Err(initial_failure(request));
	}
	execute(request, stage, stream, journal, authority, receipts)
}

fn initial_failure<J, A, S, R>(
	request: RemoteFinalizationRequest<'_>,
) -> FinalizationFailure<J, A, S, R> {
	FinalizationFailure {
		progress: FinalizationProgress::BeforeIntent,
		head: request.replay.boundary().head,
		cause: FinalizationCause::Binding,
	}
}

fn execute<S, J, A, R>(
	request: RemoteFinalizationRequest<'_>,
	stage: S,
	stream: CapturedStream,
	journal: &mut J,
	authority: &mut A,
	receipts: &R,
) -> RemoteFinalizationResult<J::Error, A::Error, S::Error, R::Error>
where
	S: RemoteFinalizationStage,
	J: RemoteFinalizationJournal,
	A: RemoteAuthorityCheck,
	R: RemoteReceiptWorkspace,
{
	let admitted = Admitted::new(request, stream).ok_or_else(|| initial_failure(request))?;
	let mut ledger = Ledger::new(journal, admitted.boundary, admitted.binding);
	ledger.check()?;
	if !admission::has_capacity(admitted.boundary) {
		return Err(ledger.fail(FinalizationCause::Capacity));
	}
	check_authority(authority, request.authority).map_err(|cause| ledger.fail(cause))?;
	let job_directory = request.owner.manifest().job_directory;
	receipts
		.check_job(job_directory)
		.map_err(|cause| ledger.fail(FinalizationCause::ReceiptNamespace(cause)))?;
	let expected_location = admitted.stage_location();
	let location = stage
		.inspect_location()
		.map_err(|cause| ledger.fail(FinalizationCause::Stage(cause)))?;
	if location != expected_location {
		return Err(ledger.fail(FinalizationCause::Binding));
	}
	let ready = stage
		.prepare_metadata(stream.length)
		.map_err(|cause| ledger.fail(FinalizationCause::Stage(cause)))?;
	let metadata = ready
		.recheck()
		.map_err(|cause| ledger.fail(FinalizationCause::Stage(cause)))?;
	let names = expected_location.names;
	if metadata.location(ready.names()) != expected_location || !admitted.matches_metadata(metadata)
	{
		return Err(ledger.fail(FinalizationCause::Binding));
	}

	let mut session = CopySession::new(admitted.model);
	let prepared = session
		.apply(admitted.model, CopyEvent::StagePrepared)
		.map_err(|cause| ledger.fail(FinalizationCause::Model(cause)))?;
	if !matches!(prepared, Some(CopyEffect::ReadSource(_))) {
		return Err(ledger.fail(FinalizationCause::ModelEffect));
	}
	for event in [
		CopyEvent::WritersJoined,
		CopyEvent::DataFlushed,
		CopyEvent::ReadbackVerified,
	] {
		observe(&mut session, admitted.model, event).map_err(|cause| ledger.fail(cause))?;
	}
	let (seal, _) = ledger.append(Body::StageSealed {
		directory: admitted.directory,
		length: admitted.length,
	})?;
	ledger.progress = FinalizationProgress::SealedBeforeIntent;
	let (verification, _) = ledger.append(Body::VerificationRecorded {
		length: admitted.length,
		source: StreamDigest::from_bytes(stream.source_digest),
		stage: StreamDigest::from_bytes(*stream.stage_digest.as_bytes()),
	})?;
	let (metadata_frame, _) = ledger.append(Body::MetadataRecorded(metadata.metadata))?;
	for event in [CopyEvent::MetadataReady, CopyEvent::StageSealed] {
		observe(&mut session, admitted.model, event).map_err(|cause| ledger.fail(cause))?;
	}

	recheck_stage(&ready, metadata, names).map_err(|cause| ledger.fail(cause))?;
	check_authority(authority, request.authority).map_err(|cause| ledger.fail(cause))?;
	ledger.progress = FinalizationProgress::IntentMayBeRecorded;
	let (intent, _) = ledger.append(Body::PublishIntent {
		seal: seal.head(),
		verification: verification.head(),
		directory: admitted.directory,
		target: admitted.target,
		qualification: request.authority.qualification,
	})?;
	let Some(CopyEffect::PublishNoClobber(permit)) = session
		.apply(admitted.model, CopyEvent::PublishIntentRecorded)
		.map_err(|cause| ledger.fail(FinalizationCause::Model(cause)))?
	else {
		return Err(ledger.fail(FinalizationCause::ModelEffect));
	};
	recheck_stage(&ready, metadata, names).map_err(|cause| ledger.fail(cause))?;
	ledger.check()?;
	check_authority(authority, request.authority).map_err(|cause| ledger.fail(cause))?;

	let fence = RemotePublicationFence {
		context: admitted.binding.context,
		authority: request.authority,
		intent: intent.head(),
	};
	let facts = match ready.publish(permit, fence) {
		Ok(facts) => facts,
		Err(PublicationFailure::Conflict(_)) => {
			observe(&mut session, admitted.model, CopyEvent::Conflict)
				.map_err(|cause| ledger.fail(cause))?;
			let (observation, _) = ledger.append(Body::PublishObserved(
				RemotePublicationObservation::Conflict,
			))?;
			return Ok(RemoteFinalizationOutcome::Conflict {
				observation: observation.head(),
			});
		}
		Err(PublicationFailure::Uncertain(cause)) => {
			ledger.progress = FinalizationProgress::PublicationUncertain;
			observe(&mut session, admitted.model, CopyEvent::OutcomeUncertain)
				.map_err(|cause| ledger.fail(cause))?;
			let observation = ledger
				.append::<A::Error, S::Error, R::Error>(Body::PublishObserved(
					RemotePublicationObservation::Uncertain {
						target: NamespaceObservation::Unobserved,
						stage: NamespaceObservation::Unobserved,
					},
				))
				.ok()
				.map(|(frame, _)| frame.head());
			return Err(ledger.fail(FinalizationCause::Publication { cause, observation }));
		}
	};
	if facts.target != admitted.binding.stage
		|| facts.directory != admitted.directory
		|| facts.parent != admitted.target.parent
	{
		ledger.progress = FinalizationProgress::PublicationUncertain;
		return Err(ledger.fail(FinalizationCause::Binding));
	}
	ledger.progress = FinalizationProgress::PublishedIncomplete;
	let (observed, _) = ledger.append(Body::PublishObserved(
		RemotePublicationObservation::Published(facts.target),
	))?;
	observe(&mut session, admitted.model, CopyEvent::Published)
		.map_err(|cause| ledger.fail(cause))?;
	let (durability, synced) = ledger.append(Body::DurabilityRecorded {
		metadata: metadata_frame.head(),
		directory: facts.directory,
		parent: facts.parent,
		qualification: request.authority.qualification,
	})?;
	observe(&mut session, admitted.model, CopyEvent::DirectoryFlushed)
		.map_err(|cause| ledger.fail(cause))?;
	let receipt = RemoteDownloadReceipt::from_synced_durability(
		request.owner,
		RemoteReceiptFrames {
			allocation: request.allocation,
			prepared: request.prepared,
			seal: &seal,
			verification: &verification,
			metadata: &metadata_frame,
			intent: &intent,
			observed: &observed,
			durability: &durability,
		},
		&synced,
	)
	.map_err(|cause| ledger.fail(FinalizationCause::Format(cause)))?;
	let digest = receipt
		.digest()
		.map_err(|cause| ledger.fail(FinalizationCause::Format(cause)))?;
	let canonical = receipt
		.encode()
		.map_err(|cause| ledger.fail(FinalizationCause::Format(cause)))?;
	persist_receipt(receipts, job_directory, &canonical).map_err(|cause| ledger.fail(cause))?;
	let (commitment, _) = ledger.append(Body::ReceiptCommitted { digest })?;
	observe(&mut session, admitted.model, CopyEvent::ReceiptRecorded)
		.map_err(|cause| ledger.fail(cause))?;
	Ok(RemoteFinalizationOutcome::PublishedWithOmissions(
		CommittedRemoteReceipt {
			capture: stream,
			scope: request.authority.scope,
			target: facts.target,
			digest,
			commitment: commitment.head(),
			canonical_receipt: canonical,
		},
	))
}

fn check_authority<A: RemoteAuthorityCheck, J, S, R>(
	authority: &mut A,
	expected: RemotePublicationAuthority,
) -> Result<(), FinalizationCause<J, A::Error, S, R>> {
	let current = authority.recheck().map_err(FinalizationCause::Authority)?;
	if current.binding != expected {
		return Err(FinalizationCause::Binding);
	}
	match current.target {
		TargetState::Absent => Ok(()),
		TargetState::Occupied => Err(FinalizationCause::TargetOccupied),
		TargetState::Unknown => Err(FinalizationCause::TargetUnknown),
	}
}

fn recheck_stage<S: RemoteReadyStage, J, A, R>(
	stage: &S,
	expected: RemoteReadyStageFacts,
	names: RemoteStageNames<'_>,
) -> Result<(), FinalizationCause<J, A, S::Error, R>> {
	let current = stage.recheck().map_err(FinalizationCause::Stage)?;
	if current != expected || stage.names() != names {
		return Err(FinalizationCause::Binding);
	}
	Ok(())
}

fn observe<J, A, S, R>(
	session: &mut CopySession,
	binding: CopyBinding,
	event: CopyEvent,
) -> Result<(), FinalizationCause<J, A, S, R>> {
	match session
		.apply(binding, event)
		.map_err(FinalizationCause::Model)?
	{
		None => Ok(()),
		Some(_) => Err(FinalizationCause::ModelEffect),
	}
}

fn persist_receipt<W: RemoteReceiptWorkspace, J, A, S>(
	workspace: &W,
	job_directory: LinuxFileIdentity,
	canonical: &[u8],
) -> Result<(), FinalizationCause<J, A, S, W::Error>> {
	workspace
		.check_job(job_directory)
		.map_err(FinalizationCause::ReceiptNamespace)?;
	let dir = workspace
		.create_receipt_directory()
		.map_err(FinalizationCause::ReceiptNamespace)?;
	let mut file = dir
		.create_receipt_record()
		.map_err(FinalizationCause::ReceiptNamespace)?;
	file.write_all(canonical)
		.map_err(FinalizationCause::ReceiptIo)?;
	file.sync_all().map_err(FinalizationCause::ReceiptIo)?;
	drop(file);
	dir.sync_directory()
		.map_err(FinalizationCause::ReceiptNamespace)?;
	workspace
		.sync_directory()
		.map_err(FinalizationCause::ReceiptNamespace)
}
