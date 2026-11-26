use crate::MAX_FIRST_SEGMENT_BYTES;

use super::{
	CoverageBasis, Error, PriorPreparation, RemoteBootstrapTrust, RemoteContinuationClaims,
	RemoteDownloadContext, StreamLength,
};
use crate::remote_download::{MAX_REMOTE_CHECKPOINT_BYTES, MAX_REMOTE_CHECKPOINTS};

pub(super) fn claims(
	trust: &RemoteBootstrapTrust<'_>,
	claims: &RemoteContinuationClaims<'_>,
	prior_source_extent: StreamLength,
) -> Result<(), Error> {
	let owner = trust.owner().manifest();
	let prior = claims.prior;
	let destination = owner.scope.destination.parent();
	if claims.context != RemoteDownloadContext::for_owner(trust.owner())
		|| claims.scope != owner.scope.digest()?
		|| claims.directory.device() != destination.device()
		|| claims.stage.device() != destination.device()
		|| [owner.job_directory, destination, claims.directory].contains(&claims.stage)
		|| [owner.job_directory, destination].contains(&claims.directory)
		|| prior.nonce == [0; 16]
		|| claims.grant_digest == [0; 32]
		|| claims.qualification_digest == [0; 32]
		|| claims.previous.offset == 0
		|| claims.previous.offset >= MAX_FIRST_SEGMENT_BYTES
	{
		return Err(Error::Binding);
	}
	if prior.bootstrap.sequence() != 2
		|| prior.allocation.sequence() <= prior.bootstrap.sequence()
		|| prior.allocation.sequence().checked_add(1) != Some(prior.prepared.sequence())
		|| prior.epochs.run.get().checked_add(1) != Some(claims.epochs.run.get())
		|| claims.epochs.source <= prior.epochs.source
		|| !active_follows_original(prior.active, prior.prepared)
		|| !valid_coverage(claims)
	{
		return Err(Error::Binding);
	}
	let covered = claims.coverage.end.get();
	let adopted = claims.adopted_end.get();
	let maximum = owner.scope.maximum_extent.get();
	if covered == 0
		|| adopted < covered
		|| adopted - covered > MAX_REMOTE_CHECKPOINT_BYTES
		|| adopted > prior_source_extent.get()
		|| prior_source_extent.get() > maximum
		|| adopted > claims.source.length().get()
		|| claims.source.length().get() > maximum
	{
		return Err(Error::Binding);
	}
	Ok(())
}

fn active_follows_original(active: PriorPreparation, original: crate::frame::ChainHead) -> bool {
	match active {
		PriorPreparation::Original(head) => head == original,
		PriorPreparation::Continued(head) => head.sequence() > original.sequence(),
	}
}

fn valid_coverage(claims: &RemoteContinuationClaims<'_>) -> bool {
	let active = claims.prior.active;
	match claims.coverage.basis {
		CoverageBasis::Checkpoint { head, ordinal } => {
			ordinal > 0
				&& ordinal <= MAX_REMOTE_CHECKPOINTS
				&& head == claims.previous.head
				&& active.head().sequence().checked_add(u64::from(ordinal)) == Some(head.sequence())
		}
		CoverageBasis::ContinuedPrefix(head) => {
			active == PriorPreparation::Continued(head) && head == claims.previous.head
		}
	}
}
