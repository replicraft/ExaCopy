use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{FRAME_OVERHEAD_BYTES, Frame, MAX_PAYLOAD_BYTES};
use exacopy_journal::remote_download::finalization::{
	MAX_REMOTE_FINALIZATION_BYTES, RemoteFinalizationBinding, RemotePublishTarget,
};
use exacopy_journal::remote_download::finalization_replay::{
	RemoteFinalizationPhase, RemoteFinalizationReplay,
};
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::{
	RemoteDownloadBody, RemoteDownloadContext, RemoteDownloadOwnerRecord, RemoteDownloadRecord,
};
use exacopy_journal::{LinuxFileIdentity, MAX_FIRST_SEGMENT_BYTES, StreamLength};
use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};

use crate::remote_capture::CapturedStream;
use crate::remote_metadata::ApprovedSftpMetadata;

use super::{
	RemotePublicationAuthority, RemoteReadyStageFacts, RemoteStageLocation, RemoteStageNames,
};

const SINGLE_ENTRY: u64 = 1;
const COMPLETION_FRAMES: u64 = 7;
const RECONCILIATION_FRAMES: u64 = 5;

/// Exact capture prefix and independently selected authorization for finalization.
#[derive(Clone, Copy, Debug)]
pub struct RemoteFinalizationRequest<'history> {
	/// Authenticated owner selected under the active private job lease.
	pub owner: &'history RemoteDownloadOwnerRecord,
	/// Full-lifecycle scan of the selected held segment with its authenticated bootstrap.
	/// This historical view confers no native authority.
	pub replay: &'history RemoteFinalizationReplay<'history>,
	/// Original consumed StageAllocated frame from that exact prefix.
	pub allocation: &'history Frame,
	/// Original bound EntryPrepared frame from that exact prefix.
	pub prepared: &'history Frame,
	/// Explicit user-selected policy, checked against the signed scope.
	pub policy: ApprovedSftpMetadata,
	/// Expected scope, current grant and independent native qualification binding.
	pub authority: RemotePublicationAuthority,
}

pub(super) struct Admitted<'history> {
	pub binding: RemoteFinalizationBinding,
	pub model: CopyBinding,
	pub boundary: RemoteReplayBoundary,
	pub directory: LinuxFileIdentity,
	pub stage_name: UnixComponent<'history>,
	pub target: RemotePublishTarget<'history>,
	pub length: StreamLength,
}

impl<'history> Admitted<'history> {
	pub fn new(
		request: RemoteFinalizationRequest<'history>,
		stream: CapturedStream,
	) -> Option<Self> {
		if request.replay.phase() != RemoteFinalizationPhase::Capture
			|| request.replay.issue().is_some()
			|| request.replay.expected_qualification() != request.authority.qualification
		{
			return None;
		}
		let manifest = request.owner.manifest();
		let scope = &manifest.scope;
		let proof = request.replay.stage_directory_prepared()?;
		let active = request.replay.attempts().last()?;
		let staged = active.prepared()?;
		let allocated = RemoteDownloadRecord::from_frame(request.allocation).ok()?;
		let prepared = RemoteDownloadRecord::from_frame(request.prepared).ok()?;
		let context = RemoteDownloadContext {
			owner: request.owner.digest(),
			job: manifest.job,
			entry: scope.entry,
		};
		let RemoteDownloadBody::StageAllocated {
			next,
			source,
			nonce,
			name,
			..
		} = allocated.body()
		else {
			return None;
		};
		let RemoteDownloadBody::EntryPrepared {
			allocation,
			epochs,
			nonce: prepared_nonce,
			stage_directory,
			stage,
		} = prepared.body()
		else {
			return None;
		};
		let boundary = request.replay.boundary();
		let length = source.length();
		if request
			.policy
			.verify_recorded(scope.metadata_policy)
			.is_err()
			|| scope.digest().ok()? != request.authority.scope
			|| request.authority.parent != scope.destination.parent()
			|| request.authority.grant == [0; 32]
			|| request.authority.qualification == [0; 32]
			|| allocated.context() != context
			|| prepared.context() != context
			|| active.allocation() != allocation
			|| allocation != request.allocation.head()
			|| prepared.predecessor() != Some(allocation)
			|| staged.head != request.prepared.head()
			|| next != epochs
			|| active.epochs() != epochs
			|| next.source.get() != stream.epoch.get()
			|| nonce != prepared_nonce
			|| active.nonce() != &nonce
			|| staged.file != stage
			|| staged.directory != stage_directory
			|| proof.directory() != stage_directory
			|| active.source() != source
			|| active.name() != name.as_bytes()
			|| length.get() != stream.length
			|| length.get() > scope.maximum_extent.get()
			|| &stream.source_digest != stream.stage_digest.as_bytes()
		{
			return None;
		}
		let job = JobId::try_from_bytes(*context.job.as_bytes()).ok()?;
		let model = CopyBinding::new(
			job,
			EntryId::new(SINGLE_ENTRY),
			RunEpoch::new(epochs.run.get()),
			StageId::from_bytes(nonce),
		);
		Some(Self {
			binding: RemoteFinalizationBinding {
				context,
				prepared: staged.head,
				epochs,
				stage,
			},
			model,
			boundary,
			directory: stage_directory,
			stage_name: name,
			target: RemotePublishTarget {
				root: scope.destination.root(),
				parent: scope.destination.parent(),
				component: UnixComponent::new(scope.destination.target()).ok()?,
			},
			length,
		})
	}

	pub fn stage_location(&self) -> RemoteStageLocation<'history> {
		RemoteStageLocation {
			binding: self.model,
			stage: self.binding.stage,
			directory: self.directory,
			parent: self.target.parent,
			names: RemoteStageNames {
				stage: self.stage_name,
				target: self.target.component,
			},
		}
	}

	pub fn matches_metadata(&self, facts: RemoteReadyStageFacts) -> bool {
		use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;
		facts.length == self.length.get() && facts.mode == SftpDataOnlyV1::LOCAL_MODE
	}
}

pub(super) fn has_capacity(boundary: RemoteReplayBoundary) -> bool {
	// Keep space for recovery-start, decision, observation, durability and
	// receipt commitment even if they use the generic frame payload limit.
	let completion = u64::try_from(MAX_REMOTE_FINALIZATION_BYTES + FRAME_OVERHEAD_BYTES);
	let recovery = u64::try_from(MAX_PAYLOAD_BYTES + FRAME_OVERHEAD_BYTES);
	let (Ok(completion), Ok(recovery)) = (completion, recovery) else {
		return false;
	};
	boundary
		.head
		.sequence()
		.checked_add(COMPLETION_FRAMES + RECONCILIATION_FRAMES)
		.is_some()
		&& boundary
			.offset
			.checked_add(completion * COMPLETION_FRAMES + recovery * RECONCILIATION_FRAMES)
			.is_some_and(|end| end <= MAX_FIRST_SEGMENT_BYTES)
}

#[cfg(test)]
mod tests {
	use exacopy_journal::MAX_FIRST_SEGMENT_BYTES;
	use exacopy_journal::frame::{ChainHead, FRAME_OVERHEAD_BYTES, MAX_PAYLOAD_BYTES};
	use exacopy_journal::remote_download::finalization::MAX_REMOTE_FINALIZATION_BYTES;
	use exacopy_journal::remote_download::replay::RemoteReplayBoundary;

	use super::has_capacity;

	#[test]
	fn reserves_both_completion_and_reconciliation_before_any_append() {
		let reserve = u64::try_from(
			7 * (MAX_REMOTE_FINALIZATION_BYTES + FRAME_OVERHEAD_BYTES)
				+ 5 * (MAX_PAYLOAD_BYTES + FRAME_OVERHEAD_BYTES),
		)
		.unwrap();
		let boundary = RemoteReplayBoundary {
			head: ChainHead::after(u64::MAX - 12, [1; 32]).unwrap(),
			offset: MAX_FIRST_SEGMENT_BYTES - reserve,
		};
		assert!(has_capacity(boundary));
		assert!(!has_capacity(RemoteReplayBoundary {
			offset: boundary.offset + 1,
			..boundary
		}));
		assert!(!has_capacity(RemoteReplayBoundary {
			head: ChainHead::after(u64::MAX - 11, [1; 32]).unwrap(),
			..boundary
		}));
	}
}
