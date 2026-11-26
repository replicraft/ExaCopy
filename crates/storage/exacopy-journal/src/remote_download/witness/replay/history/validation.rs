use crate::frame::FrameKind;
use crate::remote_download::finalization::RemotePublishTarget;
use crate::remote_download::finalization_policy::SftpDataOnlyV1;
use crate::remote_download::replay::{MAX_REMOTE_REPLAY_ATTEMPTS, RemoteDownloadReplay};

use super::super::super::wire::witness_name;
use super::{
	Body, Error, Outcome, Phase, RemoteBootstrapTrust, RemoteRetainedWitness, RemoteWitnessBinding,
	WitnessCloseoutHistory,
};

pub(super) fn closeout(
	history: &WitnessCloseoutHistory<'_>,
	trust: &RemoteBootstrapTrust<'_>,
	body: Body<'_>,
) -> Result<Phase, Error> {
	let witness = history.facts.witness.ok_or(Error::FrameBinding)?;
	let intent = witness.boundary().head;
	Ok(match body {
		Body::Seal {
			directory,
			extent,
			witness: head,
			job_directory,
			name,
		} if directory == witness.stage_directory
			&& extent == witness.binding.coverage.end()
			&& head == intent
			&& job_directory == witness.job_directory
			&& name == witness_name(witness.nonce) =>
		{
			Phase::Sealed
		}
		Body::Verify { extent, .. } if extent == witness.binding.coverage.end() => Phase::Verified,
		Body::Metadata(_)
			if trust.owner().manifest().scope.metadata_policy == SftpDataOnlyV1::digest() =>
		{
			Phase::MetadataReady
		}
		Body::Intent {
			seal,
			verification,
			witness: head,
			directory,
			target,
			qualification,
			grant,
		} if seal == history.head(FrameKind::StageSealed)?
			&& verification == history.head(FrameKind::VerificationRecorded)?
			&& head == intent
			&& directory == witness.stage_directory
			&& matches_target(trust, target)
			&& qualification == witness.qualification_digest
			&& grant == witness.consent.base_grant_digest =>
		{
			Phase::PublishIntentRequiresObservation
		}
		Body::Observed(Outcome::Submitted(target)) if target == witness.binding.stage => {
			Phase::PublishedObserved
		}
		Body::Observed(Outcome::Recovered {
			target,
			witness: head,
		}) if target == witness.binding.stage && head == intent => Phase::PublishedObserved,
		Body::Observed(Outcome::Conflict) => Phase::Conflict,
		Body::Observed(Outcome::Uncertain { .. }) => Phase::Uncertain,
		Body::Durability {
			metadata,
			directory,
			target_parent,
			job_directory,
			qualification,
		} if metadata == history.head(FrameKind::MetadataRecorded)?
			&& directory == witness.stage_directory
			&& target_parent == witness.target_parent
			&& job_directory == witness.job_directory
			&& qualification == witness.qualification_digest =>
		{
			Phase::Durable
		}
		Body::CommittedReceipt { digest, inode }
			if history
				.facts
				.ready
				.is_some_and(|ready| ready.digest() == digest && ready.receipt() == inode) =>
		{
			Phase::ReceiptCommitted
		}
		_ => return Err(Error::Binding),
	})
}

pub(super) fn retirement(
	history: &WitnessCloseoutHistory<'_>,
	trust: &RemoteBootstrapTrust<'_>,
	prior: &RemoteDownloadReplay,
	binding: RemoteWitnessBinding,
	body: Body<'_>,
) -> Result<RemoteRetainedWitness, Error> {
	let Body::Retire {
		directory,
		target,
		qualification,
		grant,
		retained,
		..
	} = body
	else {
		return Err(Error::FrameBinding);
	};
	let attempt = prior.attempts().last().ok_or(Error::Binding)?;
	let prepared = attempt.prepared().ok_or(Error::Binding)?;
	if history.pass_count(prior.attempts().len()) >= MAX_REMOTE_REPLAY_ATTEMPTS
		|| directory != prepared.directory
		|| !matches_target(trust, target)
		|| qualification != *history.qualification.digest().as_bytes()
		|| grant != history.grant
		|| binding.prepared != prepared.head
		|| binding.stage != prepared.file
	{
		return Err(Error::Binding);
	}
	match (history.facts.witness, retained) {
		(None, RemoteRetainedWitness::NoIntent) => Ok(retained),
		(Some(witness), RemoteRetainedWitness::AbsentAfterIntent(head))
			if history.facts.phase == Some(Phase::WitnessIntentRequiresInspection)
				&& head == witness.boundary().head =>
		{
			Ok(retained)
		}
		(
			Some(witness),
			RemoteRetainedWitness::Preserved {
				intent,
				job_directory,
				name,
			},
		) if witness.boundary().head == intent
			&& witness.job_directory == job_directory
			&& name == witness_name(witness.nonce) =>
		{
			Ok(retained)
		}
		_ => Err(Error::Binding),
	}
}

fn matches_target(trust: &RemoteBootstrapTrust<'_>, target: RemotePublishTarget<'_>) -> bool {
	let destination = &trust.owner().manifest().scope.destination;
	target.root == destination.root()
		&& target.parent == destination.parent()
		&& target.component.as_bytes() == destination.target()
}
