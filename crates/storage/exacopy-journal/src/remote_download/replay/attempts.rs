use std::fmt;

use crate::LinuxFileIdentity;
use crate::frame::ChainHead;

use super::super::{
	RemoteDownloadBody, RemoteDownloadOwner, RemoteDownloadRecord, RemoteEpochs,
	RemoteSourceObservation, RemoteUncertainBoundary,
};
use super::{
	RemoteDownloadReplay, RemotePreparedStage, RemoteRecordedUncertainty, RemoteReplayIssue,
	RemoteReplayMismatch,
};

/// Retained allocation and historical private-prefix progress.
pub struct RemoteReplayAttempt {
	allocation: ChainHead,
	epochs: RemoteEpochs,
	name: Box<[u8]>,
	nonce: [u8; 16],
	source: RemoteSourceObservation,
	prepared: Option<RemotePreparedStage>,
	checkpoint_count: u16,
	covered_extent: u64,
}

impl RemoteReplayAttempt {
	/// Returns the exact accepted fresh allocation frame.
	#[must_use]
	pub const fn allocation(&self) -> ChainHead {
		self.allocation
	}

	/// Returns this allocation's bound job and source epochs.
	#[must_use]
	pub const fn epochs(&self) -> RemoteEpochs {
		self.epochs
	}

	/// Returns the validated raw basename for read-only inventory.
	#[must_use]
	pub fn name(&self) -> &[u8] {
		&self.name
	}

	/// Returns the nonzero nonce of that private allocation.
	#[must_use]
	pub const fn nonce(&self) -> &[u8; 16] {
		&self.nonce
	}

	/// Returns the original server-reported live observation.
	#[must_use]
	pub const fn source(&self) -> RemoteSourceObservation {
		self.source
	}

	/// Returns the accepted historical stage binding, when present.
	#[must_use]
	pub const fn prepared(&self) -> Option<RemotePreparedStage> {
		self.prepared
	}

	/// Returns the number of contiguous accepted prefix declarations.
	#[must_use]
	pub const fn checkpoint_count(&self) -> u16 {
		self.checkpoint_count
	}

	/// Returns the exclusive end of the accepted checkpoint prefix.
	#[must_use]
	pub const fn covered_extent(&self) -> u64 {
		self.covered_extent
	}
}

impl fmt::Debug for RemoteReplayAttempt {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("RemoteReplayAttempt")
			.field("allocation", &self.allocation)
			.field("epochs", &self.epochs)
			.field("source", &self.source)
			.field("prepared", &self.prepared)
			.field("checkpoint_count", &self.checkpoint_count)
			.field("covered_extent", &self.covered_extent)
			.finish_non_exhaustive()
	}
}

impl RemoteDownloadReplay {
	pub(super) fn accept(
		&mut self,
		record: &RemoteDownloadRecord<'_>,
		head: ChainHead,
		owner: &RemoteDownloadOwner,
		expected_scope: super::super::RemoteScopeDigest,
		max_attempts: usize,
	) -> Result<(), RemoteReplayIssue> {
		use RemoteDownloadBody as Body;
		use RemoteReplayMismatch as Mismatch;

		let problem = |problem| RemoteReplayIssue::Record {
			offset: self.boundary.offset,
			kind: record.body().kind(),
			problem,
		};

		if let Body::JobPrepared { scope } = record.body() {
			if self.job_prepared.is_some() {
				return Err(problem(Mismatch::Order));
			}
			if scope != expected_scope {
				return Err(problem(Mismatch::Scope));
			}
			self.job_prepared = Some(head);
			return Ok(());
		}

		if self.job_prepared.is_none() {
			return Err(problem(Mismatch::Order));
		}
		match record.body() {
			Body::JobPrepared { .. } => Err(problem(Mismatch::Order)),
			Body::StageAllocated {
				previous,
				next,
				name,
				nonce,
				source,
			} => {
				if self.attempts.len() >= max_attempts {
					return Err(RemoteReplayIssue::AttemptLimit);
				}
				let last_epochs = self.attempts.last().map(RemoteReplayAttempt::epochs);
				if previous != last_epochs
					|| source.length().get() > owner.scope.maximum_extent.get()
					|| self
						.attempts
						.iter()
						.any(|attempt| attempt.name() == name.as_bytes() || attempt.nonce == nonce)
				{
					return Err(problem(Mismatch::Allocation));
				}
				self.attempts.push(RemoteReplayAttempt {
					allocation: head,
					epochs: next,
					name: name.as_bytes().into(),
					nonce,
					source,
					prepared: None,
					checkpoint_count: 0,
					covered_extent: 0,
				});
				Ok(())
			}
			Body::EntryPrepared {
				allocation,
				epochs,
				nonce,
				stage_directory,
				stage,
			} => {
				if !self.admits_identity(owner, stage_directory, stage) {
					return Err(problem(Mismatch::StageBinding));
				}
				let attempt = self
					.attempts
					.last_mut()
					.ok_or_else(|| problem(Mismatch::Order))?;
				if attempt.prepared.is_some()
					|| attempt.allocation != allocation
					|| attempt.epochs != epochs
					|| attempt.nonce != nonce
				{
					return Err(problem(Mismatch::StageBinding));
				}
				attempt.prepared = Some(RemotePreparedStage {
					head,
					directory: stage_directory,
					file: stage,
				});
				Ok(())
			}
			Body::RangeCheckpoint {
				prepared,
				epochs,
				ordinal,
				offset,
				length,
				..
			} => {
				let attempt = self
					.attempts
					.last_mut()
					.ok_or_else(|| problem(Mismatch::Order))?;
				if attempt.prepared.map(|stage| stage.head) != Some(prepared)
					|| attempt.epochs != epochs
					|| attempt.checkpoint_count.checked_add(1) != Some(ordinal)
					|| attempt.covered_extent != offset
				{
					return Err(problem(Mismatch::Checkpoint));
				}
				let end = offset
					.checked_add(length)
					.filter(|end| *end <= attempt.source.length().get())
					.ok_or_else(|| problem(Mismatch::Checkpoint))?;
				attempt.checkpoint_count = ordinal;
				attempt.covered_extent = end;
				Ok(())
			}
			Body::FailureRecorded {
				attempt: anchor,
				epochs,
				boundary,
			} => {
				let attempt = self
					.attempts
					.last()
					.ok_or_else(|| problem(Mismatch::Order))?;
				let expected = match (boundary, attempt.prepared) {
					(RemoteUncertainBoundary::Creation, None) => Some(attempt.allocation),
					(RemoteUncertainBoundary::Creation, Some(_)) | (_, None) => None,
					(_, Some(prepared)) => Some(prepared.head),
				};
				if expected != Some(anchor) || attempt.epochs != epochs {
					return Err(problem(Mismatch::FailureBinding));
				}
				self.uncertainty = Some(RemoteRecordedUncertainty {
					head,
					attempt: anchor,
					epochs,
					boundary,
				});
				Ok(())
			}
		}
	}

	fn admits_identity(
		&self,
		owner: &RemoteDownloadOwner,
		directory: LinuxFileIdentity,
		file: LinuxFileIdentity,
	) -> bool {
		let destination = owner.scope.destination.parent();
		let job = owner.job_directory;
		directory.device() == destination.device()
			&& file.device() == destination.device()
			&& directory != file
			&& self
				.stage_directory_prepared
				.is_none_or(|bootstrap| bootstrap.directory() == directory)
			&& ![destination, job].contains(&directory)
			&& ![destination, job].contains(&file)
			&& self
				.attempts
				.iter()
				.filter_map(RemoteReplayAttempt::prepared)
				.all(|prepared| prepared.directory == directory && prepared.file != file)
	}
}
