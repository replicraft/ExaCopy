use exacopy_journal::frame::{FRAME_OVERHEAD_BYTES, FrameKind, FrameWriter};
use exacopy_journal::remote_download::finalization_replay::{
	RemoteFinalizationPhase, RemoteFinalizationReplay,
};
use exacopy_journal::remote_download::replay::MAX_REMOTE_REPLAY_ATTEMPTS;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::{
	RemoteDownloadBody, RemoteDownloadContext, RemoteDownloadRecord, RemoteEpochs,
	RemoteSourceObservation,
};
use exacopy_journal::{JournalJobId, LinuxFileIdentity, MAX_FIRST_SEGMENT_BYTES};
use exacopy_platform::linux::RecoveryFile;

use crate::profile::LocalProfile;

use super::super::{RetryCaptureStamp, next_epochs};
use super::{
	Error, RemoteActivation, RemoteJobLease, check_current, component, context, record_identity,
	require_live_phase,
};

/// One retained capture rechecked under its freshly acquired exclusive native lease.
///
/// It carries no remote identity proof, stage writer, or publication permit.
#[must_use]
pub struct RemoteRetryLease<'root> {
	lease: RemoteJobLease<'root>,
	stamp: RetryCaptureStamp,
	fresh: FreshRetryAllocation,
}

pub(in crate::assembly::linux) struct FreshRetryAllocation {
	boundary: RemoteReplayBoundary,
	name: Box<[u8]>,
	nonce: [u8; 16],
	epochs: RemoteEpochs,
	source: RemoteSourceObservation,
}

impl FreshRetryAllocation {
	pub(in crate::assembly::linux) fn name(&self) -> &[u8] {
		&self.name
	}

	pub(in crate::assembly::linux::remote_journal) fn parts(
		&self,
	) -> (
		RemoteReplayBoundary,
		[u8; 16],
		RemoteEpochs,
		RemoteSourceObservation,
	) {
		(self.boundary, self.nonce, self.epochs, self.source)
	}
}

impl<'root> RemoteJobLease<'root> {
	pub(in crate::assembly::linux) fn open_retry(
		profile: &LocalProfile,
		job: JournalJobId,
		activation: RemoteActivation<'root>,
		stamp: RetryCaptureStamp,
		fresh_name: Box<[u8]>,
		fresh_nonce: [u8; 16],
	) -> Result<RemoteRetryLease<'root>, Error> {
		let lease = Self::open_existing(profile, job, activation)?;
		let epochs = check_capacity(&stamp, &fresh_name, fresh_nonce)?;
		let fresh = FreshRetryAllocation {
			boundary: stamp.boundary,
			name: fresh_name,
			nonce: fresh_nonce,
			epochs,
			source: stamp.source,
		};
		let retry = RemoteRetryLease {
			lease,
			stamp,
			fresh,
		};
		retry.recheck()?;
		Ok(retry)
	}
}

impl<'root> RemoteRetryLease<'root> {
	pub(in crate::assembly::linux) fn activation(&self) -> RemoteActivation<'root> {
		self.lease.activation
	}

	pub(in crate::assembly::linux) fn source_epoch(&self) -> std::num::NonZeroU64 {
		self.fresh.epochs.source
	}

	pub(in crate::assembly::linux) fn consume(
		self,
		observed: RemoteSourceObservation,
		epoch: std::num::NonZeroU64,
	) -> Result<
		(
			RemoteJobLease<'root>,
			FreshRetryAllocation,
			RetryCaptureStamp,
		),
		Error,
	> {
		if observed != self.fresh.source || epoch != self.source_epoch() {
			return Err(Error::Binding);
		}
		self.recheck()?;
		Ok((self.lease, self.fresh, self.stamp))
	}
	/// Returns the earlier server-reported observation for rejection on mismatch.
	/// Matching it establishes no identity, byte equality or source authority.
	#[must_use]
	pub fn previous_source_observation(&self) -> RemoteSourceObservation {
		self.stamp.source
	}

	/// Rechecks the exact accepted history and native observations under this lease.
	///
	/// # Errors
	/// Refuses any changed scope, stage, journal, capacity or target observation.
	pub fn recheck(&self) -> Result<(), Error> {
		let lease = &self.lease;
		let stamp = &self.stamp;
		lease.activation.recheck()?;
		if lease.phase != RemoteFinalizationPhase::Capture
			|| lease.boundary != stamp.boundary
			|| context(&lease.owner) != stamp.context
			|| lease.activation.grant_digest != stamp.grant
			|| lease.activation.qualification_digest != stamp.qualification
			|| lease.stage_directory != record_identity(stamp.directory)
			|| lease.owner_file.observation() != stamp.owner.observation()
			|| lease.segment.observation() != stamp.segment.observation()
		{
			return Err(Error::Binding);
		}
		stamp.owner.recheck_observation()?;
		stamp.segment.recheck_observation()?;
		let mut current = self.check_records()?;
		let replay = lease.scan(&mut current)?;
		require_live_phase(&replay, lease.activation)?;
		if replay.phase() != RemoteFinalizationPhase::Capture
			|| replay.boundary() != stamp.boundary
			|| replay.boundary().offset != current.len()
		{
			return Err(Error::Binding);
		}
		self.check_attempt(&replay)?;
		let target = component(lease.owner.manifest().scope.destination.target())?;
		let inventory = lease.job().inventory(component(&stamp.name)?, target)?;
		if inventory.target().is_some() {
			return Err(Error::Conflict);
		}
		let stage = inventory.stage().ok_or(Error::UnknownStage)?;
		if stage.identity() != stamp.file || stage.len() != stamp.extent {
			return Err(Error::UnknownStage);
		}
		stage.check_logical_eof()?;
		stamp.anchor.recheck(&inventory)?;
		let fresh = lease
			.job()
			.inventory(component(&self.fresh.name)?, target)?;
		if fresh.stage().is_some() || fresh.target().is_some() {
			return Err(Error::Conflict);
		}
		if fresh.stage_directory_identity() != Some(stamp.directory) {
			return Err(Error::UnknownStage);
		}
		fresh.recheck()?;
		stamp.anchor.recheck(&inventory)?;
		let final_segment = self.check_records()?;
		final_segment.check_logical_eof()?;
		final_segment.recheck_observation()?;
		lease.activation.recheck()?;
		Ok(())
	}

	fn check_records(&self) -> Result<RecoveryFile, Error> {
		let stamp = &self.stamp;
		let current = check_current(
			self.lease.job(),
			&stamp.owner,
			stamp.segment.identity(),
			stamp.boundary.offset,
		)?;
		if current.observation() != stamp.segment.observation() {
			return Err(Error::Binding);
		}
		stamp.segment.recheck_observation()?;
		Ok(current)
	}

	fn check_attempt(&self, replay: &RemoteFinalizationReplay<'_>) -> Result<(), Error> {
		let stamp = &self.stamp;
		let last = replay.attempts().last().ok_or(Error::Binding)?;
		let prepared = last.prepared().ok_or(Error::Binding)?;
		if last.allocation() != stamp.allocation
			|| last.epochs() != stamp.epochs
			|| last.name() != stamp.name.as_ref()
			|| last.source() != stamp.source
			|| prepared.head != stamp.prepared
			|| prepared.directory != record_identity(stamp.directory)
			|| prepared.file != record_identity(stamp.file)
			|| last.covered_extent() > stamp.extent
			|| stamp.extent >= stamp.source.length().get()
		{
			return Err(Error::Binding);
		}
		if replay.attempts().len() >= MAX_REMOTE_REPLAY_ATTEMPTS
			|| self.fresh.nonce == [0; 16]
			|| replay.attempts().iter().any(|attempt| {
				attempt.name() == self.fresh.name.as_ref() || *attempt.nonce() == self.fresh.nonce
			}) {
			return Err(Error::Attempt);
		}
		if check_capacity(stamp, &self.fresh.name, self.fresh.nonce)? != self.fresh.epochs {
			return Err(Error::Binding);
		}
		Ok(())
	}
}

pub(in crate::assembly::linux::remote_journal) fn check_capacity(
	stamp: &RetryCaptureStamp,
	fresh_name: &[u8],
	fresh_nonce: [u8; 16],
) -> Result<RemoteEpochs, Error> {
	let source = stamp.epochs.source.checked_add(1).ok_or(Error::Attempt)?;
	let next = next_epochs(Some(stamp.epochs), source)?;
	check_preparation_capacity(
		stamp.boundary,
		stamp.context,
		RemoteDownloadBody::StageAllocated {
			previous: Some(stamp.epochs),
			next,
			name: component(fresh_name)?,
			nonce: fresh_nonce,
			source: stamp.source,
		},
		record_identity(stamp.directory),
		record_identity(stamp.file),
	)?;
	Ok(next)
}

pub(in crate::assembly::linux::remote_journal) fn check_preparation_capacity(
	boundary: RemoteReplayBoundary,
	context: RemoteDownloadContext,
	allocation: RemoteDownloadBody<'_>,
	directory: LinuxFileIdentity,
	prior_stage: LinuxFileIdentity,
) -> Result<(), Error> {
	let RemoteDownloadBody::StageAllocated { next, nonce, .. } = allocation else {
		return Err(Error::Binding);
	};
	let allocation = RemoteDownloadRecord::new(context, Some(boundary.head), allocation)?;
	let allocated = preview_frame(
		boundary,
		FrameKind::RemoteStageAllocated,
		&allocation.encode()?,
	)?;
	// The native identities use fixed-width byte strings. Use the known old
	// stage only to size the future preparation before its own inode exists.
	let prepared = RemoteDownloadRecord::new(
		context,
		Some(allocated.head),
		RemoteDownloadBody::EntryPrepared {
			allocation: allocated.head,
			epochs: next,
			nonce,
			stage_directory: directory,
			stage: prior_stage,
		},
	)?;
	frame_end(allocated.offset, prepared.encode()?.len())?;
	Ok(())
}

pub(in crate::assembly::linux::remote_journal) fn preview_frame(
	boundary: RemoteReplayBoundary,
	kind: FrameKind,
	payload: &[u8],
) -> Result<RemoteReplayBoundary, Error> {
	let offset = frame_end(boundary.offset, payload.len())?;
	let head = FrameWriter::new(std::io::sink(), boundary.head)
		.append(kind, payload)
		.map_err(|_| Error::Attempt)?;
	Ok(RemoteReplayBoundary { head, offset })
}

fn frame_end(offset: u64, payload_size: usize) -> Result<u64, Error> {
	FRAME_OVERHEAD_BYTES
		.checked_add(payload_size)
		.and_then(|width| u64::try_from(width).ok())
		.and_then(|width| offset.checked_add(width))
		.filter(|end| *end <= MAX_FIRST_SEGMENT_BYTES)
		.ok_or(Error::Attempt)
}
