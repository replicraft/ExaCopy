use std::io::{Cursor, Read as _};

use exacopy_journal::frame::{ChainHead, FrameKind, FrameReadError, FrameReader};
use exacopy_journal::remote_download::continuation::{CoverageBasis, PriorPreparation};
use exacopy_journal::remote_download::finalization_replay::{
	RemoteFinalizationReplay, replay_remote_finalization_with_checkpoints,
};
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::{
	RemoteDownloadError, RemoteDownloadOwnerRecord, RemoteEpochs,
};
use exacopy_journal::{LinuxFileIdentity, MAX_FIRST_SEGMENT_BYTES};
use exacopy_model::retained_prefix::{
	Continuation, Guard, Head, History, Pass, PrefixProof, Prior, Refusal,
};
use exacopy_platform::linux::{
	DestinationRoot, RecoveryFile, RecoveryWriteLease, RemoteDestinationEligibility, StageError,
	WitnessCredentialLane, WitnessReservationAuthority, WitnessReservationObservationError,
	kernel_random,
};
use exacopy_transfer::remote_capture::CapturedReadAt;
use exacopy_transfer::remote_resume::prefix::VerifiedRetainedPrefix;

use super::{PositiveTailWitness, WitnessAdmissionError};
use crate::assembly::linux::remote_continued::activation::{
	AdmissionError, Kind40Admission, confirm_selected, model_head,
};
use crate::assembly::linux::remote_witness_authority::BoundWitnessStage;

#[derive(Debug)]
pub(in crate::assembly::linux::remote_continued) enum OriginalCaptureError {
	Binding,
	Stage(StageError),
	Format(RemoteDownloadError),
	Frame(FrameReadError),
	Proposed(AdmissionError<WitnessAdmissionError>),
	Model(Refusal),
}

pub(super) struct CaptureCustody<'scope, 'lane> {
	root: &'scope DestinationRoot,
	lease: &'scope RecoveryWriteLease<'scope>,
	eligibility: &'scope RemoteDestinationEligibility<'scope>,
	owner: &'scope RecoveryFile,
	segment: &'scope RecoveryFile,
	lane: &'lane WitnessCredentialLane,
}

impl<'scope, 'lane> CaptureCustody<'scope, 'lane> {
	pub(super) fn new(
		run: &PositiveTailWitness<'scope>,
		lane: &'lane WitnessCredentialLane,
	) -> Self {
		Self {
			root: run.root,
			lease: run.lease,
			eligibility: run.eligibility,
			owner: run.owner_file,
			segment: run.segment,
			lane,
		}
	}

	pub(super) fn recheck(&self) -> Result<(), WitnessReservationObservationError> {
		self.eligibility.recheck_for(self.root)?;
		self.open_owner()?;
		self.lane.recheck()?;
		Ok(())
	}

	pub(super) fn confirm_owner(
		&self,
		names: BoundWitnessStage<'_>,
		owner: &RemoteDownloadOwnerRecord,
	) -> Result<(), OriginalCaptureError> {
		use OriginalCaptureError as Error;

		let job = self.lease.job();
		let job_id = job.identity();
		let parent = job.destination_identity();
		let manifest = owner.manifest();
		let expected = owner.as_bytes();
		let held = self.open_owner().map_err(Error::Stage)?;
		if names.context.owner != owner.digest()
			|| names.context.job != manifest.job
			|| names.context.entry != manifest.scope.entry
			|| names.scope != manifest.scope.digest().map_err(Error::Format)?
			|| names.job != manifest.job_directory
			|| names.job != LinuxFileIdentity::new(job_id.device(), job_id.inode())
			|| manifest.scope.destination.parent()
				!= LinuxFileIdentity::new(parent.device(), parent.inode())
			|| manifest.scope.destination.target() != names.retained.target.as_bytes()
			|| parent != self.root.identity()
			|| held.len() != expected.len() as u64
		{
			return Err(Error::Binding);
		}
		let mut actual = vec![0; expected.len()];
		held.read_exact_at(0, &mut actual)
			.map_err(StageError::ReadBack)
			.map_err(Error::Stage)?;
		if actual != expected {
			return Err(Error::Binding);
		}
		self.open_owner().map_err(Error::Stage)?;
		Ok(())
	}

	fn open_owner(&self) -> Result<RecoveryFile, StageError> {
		let held = self.lease.job().open_owner()?;
		confirm_file(&held, self.owner)?;
		Ok(held)
	}

	fn open_segment(&self, total: u64) -> Result<RecoveryFile, OriginalCaptureError> {
		let held = self
			.lease
			.job()
			.open_first_segment()
			.map_err(OriginalCaptureError::Stage)?;
		if total > MAX_FIRST_SEGMENT_BYTES || held.len() != total {
			return Err(OriginalCaptureError::Binding);
		}
		confirm_file(&held, self.segment).map_err(OriginalCaptureError::Stage)?;
		Ok(held)
	}
}

fn confirm_file(held: &RecoveryFile, original: &RecoveryFile) -> Result<(), StageError> {
	if held.observation() != original.observation() {
		return Err(StageError::IdentityChanged);
	}
	original
		.recheck_observation()
		.map_err(StageError::ReadBack)?;
	held.check_logical_eof().map_err(StageError::ReadBack)?;
	held.recheck_observation().map_err(StageError::ReadBack)
}

pub(super) fn admit_original<R: CapturedReadAt>(
	custody: &CaptureCustody<'_, '_>,
	admission: &Kind40Admission<'_, '_>,
	proof: &VerifiedRetainedPrefix<'_, R>,
	(encoded, successor): (Vec<u8>, RemoteReplayBoundary),
	names: BoundWitnessStage<'_>,
	authority: WitnessReservationAuthority,
) -> Result<Continuation, OriginalCaptureError> {
	use OriginalCaptureError as Error;

	let claims = admission.expected.claims;
	let total = claims.previous.offset;
	let qualification = admission.selection.initial_v1_qualification;
	let held = custody.open_segment(total)?;
	let replay = replay_remote_finalization_with_checkpoints(
		held.take(total),
		admission.trust,
		qualification,
		None,
	)
	.map_err(Error::Format)?;
	let selected = select_original(&replay, claims.previous)?;
	let stage = proof.stage();
	if stage != selected.stage
		|| proof.active_preparation() != PriorPreparation::Original(stage.head)
		|| proof.recorded_grant().is_some()
		|| proof.expected_qualification() != qualification
		|| proof.checkpoint_extent() != selected.checkpoint_end
	{
		return Err(Error::Binding);
	}

	let held = custody.open_segment(total)?;
	let preparation = preparation_boundary(held.take(total), stage.head)?;
	let held = custody.open_segment(total)?;
	confirm_selected(
		held.take(total).chain(Cursor::new(encoded)),
		admission.trust,
		admission.selection,
		successor,
	)
	.map_err(Error::Proposed)?;
	custody.open_segment(total)?;

	let mut lease = [0; 32];
	kernel_random(&mut lease).map_err(|_| Error::Binding)?;
	let guard = guard(custody, names, authority, lease);
	Continuation::begin(
		Prior {
			guard,
			head: model_head(claims.previous),
			preparation,
			pass: Pass {
				run: selected.epochs.run,
				source: selected.epochs.source,
			},
			checkpoint_end: selected.checkpoint_end,
			authorized_end: selected.authorized_end,
			history: History::CleanCapture,
			// The actual prefix reader holds stage-access exclusion under
			// the already matched exclusive job lease.
			writer_quiesced: true,
		},
		Pass {
			run: claims.epochs.run,
			source: claims.epochs.source,
		},
		PrefixProof {
			local_end: proof.extent(),
			compared_end: proof.extent(),
			rehashed_end: proof.checkpoint_extent(),
			digest: proof.digest(),
		},
		proof.source_length(),
	)
	.map_err(Error::Model)
}

struct OriginalCheckpoint {
	epochs: RemoteEpochs,
	stage: exacopy_journal::remote_download::replay::RemotePreparedStage,
	checkpoint_end: u64,
	authorized_end: u64,
}

fn select_original(
	replay: &RemoteFinalizationReplay<'_>,
	cut: RemoteReplayBoundary,
) -> Result<OriginalCheckpoint, OriginalCaptureError> {
	use OriginalCaptureError as Error;

	if replay.boundary() != cut {
		return Err(Error::Binding);
	}
	// active_checkpoints refuses uncertain or finalized histories.
	let checkpoints = replay.active_checkpoints().map_err(Error::Format)?;
	let history = checkpoints.prefix_history().map_err(Error::Format)?;
	if !matches!(
		history.coverage_basis(),
		CoverageBasis::Checkpoint { head, .. } if head == cut.head
	) {
		return Err(Error::Binding);
	}
	Ok(OriginalCheckpoint {
		epochs: history.epochs(),
		stage: history.prepared(),
		checkpoint_end: history.covered_extent(),
		authorized_end: history.source().length().get(),
	})
}

fn preparation_boundary(
	input: impl std::io::Read,
	expected: ChainHead,
) -> Result<Head, OriginalCaptureError> {
	use OriginalCaptureError as Error;

	let mut frames = FrameReader::new(input, ChainHead::start());
	while let Some(frame) = frames.next_frame().map_err(Error::Frame)? {
		if frame.head() == expected && frame.kind() == FrameKind::EntryPrepared {
			return Ok(model_head(RemoteReplayBoundary {
				head: expected,
				offset: frames.offset(),
			}));
		}
	}
	Err(Error::Binding)
}

fn guard(
	custody: &CaptureCustody<'_, '_>,
	names: BoundWitnessStage<'_>,
	authority: WitnessReservationAuthority,
	lease: [u8; 32],
) -> Guard {
	let context = names.context;
	let authority = blake3::Hasher::new_derive_key("ExaCopy live retained prefix authority v1")
		.update(context.owner.as_bytes())
		.update(context.job.as_bytes())
		.update(context.entry.as_bytes())
		.update(names.scope.as_bytes())
		.update(&authority.qualification)
		.update(&authority.base_grant)
		.update(&authority.retention_approval)
		.finalize();
	let ids = custody.eligibility.facts().ids();
	let mut stage = blake3::Hasher::new_derive_key("ExaCopy live retained prefix stage v1");
	stage.update(&ids.boot_id);
	for number in [
		ids.mount_namespace,
		ids.mount_id,
		ids.unique_mount,
		ids.root.device,
		ids.root.inode,
		names.job.device(),
		names.job.inode(),
		names.retained.directory.device,
		names.retained.directory.inode,
		names.retained.file.device,
		names.retained.file.inode,
	] {
		stage.update(&number.to_le_bytes());
	}
	for name in [names.retained.stage, names.retained.target] {
		let bytes = name.as_bytes();
		stage
			.update(&(bytes.len() as u64).to_le_bytes())
			.update(bytes);
	}
	Guard {
		authority: *authority.as_bytes(),
		stage: *stage.finalize().as_bytes(),
		lease,
	}
}

#[cfg(test)]
pub(in crate::assembly::linux::remote_continued) fn check_original_vector(
	full: &[u8],
	prior: RemoteReplayBoundary,
	kind40: RemoteReplayBoundary,
	trust: &exacopy_journal::remote_download::RemoteBootstrapTrust<'_>,
	initial_v1_qualification: [u8; 32],
) {
	let old_end = usize::try_from(prior.offset).unwrap();
	let read = |length| {
		replay_remote_finalization_with_checkpoints(
			&full[..length],
			trust,
			initial_v1_qualification,
			None,
		)
		.unwrap()
	};
	let original = read(old_end);
	let checkpoint = select_original(&original, prior).unwrap();
	assert_eq!(checkpoint.checkpoint_end, 4);
	assert_eq!(checkpoint.authorized_end, 4);
	let prepared = preparation_boundary(&full[..old_end], checkpoint.stage.head).unwrap();
	assert_eq!(prepared.digest, checkpoint.stage.head.digest());
	assert!(prepared.end < prior.offset);
	assert!(select_original(&read(old_end - 1), prior).is_err());
	assert!(select_original(&read(usize::try_from(kind40.offset).unwrap()), prior).is_err());
	let before_checkpoint = read(usize::try_from(prepared.end).unwrap());
	assert!(select_original(&before_checkpoint, before_checkpoint.boundary()).is_err());
}
