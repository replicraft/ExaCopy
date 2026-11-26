//! Native private byte staging for a prepared remote capture under one job lease.

use std::cell::Cell;
use std::error::Error;
use std::fmt;

use exacopy_endpoint::{ClosedStage, FreshStage, MAX_FILE_LENGTH, ReadView, UnixComponent};
use exacopy_journal::frame::ChainHead;
use exacopy_platform::linux::{
	ClosedStage as LinuxClosedStage, FileIdentity, RecoveryFile, RecoveryInventory, RecoveryJob,
	StageError, WriteStage,
};
use exacopy_transfer::remote_capture::{CheckpointStage, SourceEpoch};
use exacopy_transfer::remote_resume::RestartStage;

mod finalization;

pub(super) use finalization::{FinalizingCaptureStage, PublicationContext, StageFinalizationError};

#[cfg(test)]
mod tests;

const MAX_STAGE_CHUNK_BYTES: usize = 64 * 1024;

/// The active local job, exact EntryPrepared frame and live source pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PrefixScope {
	pub(super) job: FileIdentity,
	pub(super) prepared: ChainHead,
	pub(super) source: SourceEpoch,
	pub(super) stage: FileIdentity,
}

pub(super) struct PrefixBarrier {
	scope: PrefixScope,
	pending: Cell<Option<u64>>,
}

impl PrefixBarrier {
	/// Creates proof storage for the caller's synchronized EntryPrepared.
	pub(super) const fn new(scope: PrefixScope) -> Self {
		Self {
			scope,
			pending: Cell::new(None),
		}
	}

	/// Consumes the active stage's successful file barrier at this exact end.
	pub(super) fn take_current(&self, expected: PrefixScope, end: u64) -> bool {
		let pending = self.pending.take();
		self.scope == expected && pending == Some(end)
	}
}

struct StageBarrier<'stage>(&'stage PrefixBarrier);

impl StageBarrier<'_> {
	fn clear(&self) {
		self.0.pending.set(None);
	}

	fn confirm(&self, identity: FileIdentity, end: u64) -> Result<(), StageError> {
		if self.0.scope.stage != identity {
			return Err(StageError::IdentityChanged);
		}
		self.0.pending.set(Some(end));
		Ok(())
	}
}

impl Drop for StageBarrier<'_> {
	fn drop(&mut self) {
		self.clear();
	}
}

/// One exclusively created stage after the application verified EntryPrepared.
pub(super) struct NativeCaptureStage<'stage> {
	writer: WriteStage<'stage>,
	scope: StageScope<'stage>,
	barrier: StageBarrier<'stage>,
	length: u64,
	written: Cell<Option<u64>>,
}

struct StageScope<'stage> {
	job: &'stage RecoveryJob<'stage>,
	stage_name: UnixComponent<'stage>,
	target_name: UnixComponent<'stage>,
	directory: FileIdentity,
}

impl<'stage> StageScope<'stage> {
	fn observe(
		&self,
		identity: FileIdentity,
		length: u64,
	) -> Result<RecoveryInventory<'stage>, StageError> {
		let inventory = self.job.inventory(self.stage_name, self.target_name)?;
		if inventory.stage_directory_identity() != Some(self.directory)
			|| inventory.target().is_some()
			|| !inventory
				.stage()
				.is_some_and(|file| file.identity() == identity && file.len() == length)
		{
			return Err(StageError::IdentityChanged);
		}
		inventory.recheck()?;
		Ok(inventory)
	}
}

impl<'stage> NativeCaptureStage<'stage> {
	/// The caller keeps the fresh factory and lease alive and supplies the exact
	/// names and directory bound by its synchronized EntryPrepared record.
	/// # Errors
	/// Refuses an unsafe declared extent or mismatched fresh stage.
	pub(super) fn new(
		writer: WriteStage<'stage>,
		job: &'stage RecoveryJob<'stage>,
		stage_name: UnixComponent<'stage>,
		target_name: UnixComponent<'stage>,
		directory: FileIdentity,
		length: u64,
		prefix_barrier: &'stage PrefixBarrier,
	) -> Result<Self, StageError> {
		let barrier = StageBarrier(prefix_barrier);
		barrier.clear();
		if length > MAX_FILE_LENGTH {
			return Err(StageError::InvalidLength);
		}
		let scope = StageScope {
			job,
			stage_name,
			target_name,
			directory,
		};
		let identity = writer.observe_prefix(0)?;
		if prefix_barrier.scope.job != job.identity()
			|| prefix_barrier.scope.stage != identity
			|| prefix_barrier.scope.prepared.sequence() == 0
		{
			return Err(StageError::IdentityChanged);
		}
		scope.observe(identity, 0)?;
		Ok(Self {
			writer,
			scope,
			barrier,
			length,
			written: Cell::new(Some(0)),
		})
	}

	fn observe_position(&self, position: u64) -> Result<FileIdentity, NativeCaptureStageError> {
		self.writer.observe_prefix(position).map_err(|error| {
			self.barrier.clear();
			self.written.set(None);
			error.into()
		})
	}

	fn begin_effect(&mut self) -> Result<u64, NativeCaptureStageError> {
		self.barrier.clear();
		self.written
			.take()
			.ok_or(NativeCaptureStageError::Uncertain)
	}
}

impl<'stage> FreshStage for NativeCaptureStage<'stage> {
	type Error = NativeCaptureStageError;
	type Closed = NativeClosedStage<'stage>;

	const MAX_CHUNK_BYTES: usize = MAX_STAGE_CHUNK_BYTES;

	fn unwritten_length(&self) -> Result<u64, Self::Error> {
		if self.written.get() != Some(0) {
			return Err(NativeCaptureStageError::Uncertain);
		}
		self.observe_position(0)?;
		Ok(self.length)
	}

	fn write_next(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
		let start = self.begin_effect()?;
		if bytes.is_empty() || bytes.len() > Self::MAX_CHUNK_BYTES {
			return Err(NativeCaptureStageError::Extent);
		}
		let count = u64::try_from(bytes.len()).map_err(|_| NativeCaptureStageError::Extent)?;
		let end = start
			.checked_add(count)
			.filter(|end| *end <= self.length)
			.ok_or(NativeCaptureStageError::Extent)?;
		self.writer.observe_prefix(start)?;
		self.writer.write_all_at(start, bytes)?;
		self.writer.observe_prefix(end)?;
		self.written.set(Some(end));
		Ok(())
	}

	fn sync_and_close(mut self) -> Result<Self::Closed, Self::Error> {
		if self.begin_effect()? != self.length {
			return Err(NativeCaptureStageError::Extent);
		}
		let identity = self.writer.sync_prefix(self.length)?;
		let closed = self.writer.close_writes()?;
		if closed.identity() != identity || closed.length() != self.length {
			return Err(StageError::IdentityChanged.into());
		}
		let inventory = self.scope.observe(identity, self.length)?;
		let result = NativeClosedStage {
			closed,
			inventory,
			names: (self.scope.stage_name, self.scope.target_name),
		};
		result.open_read_back()?.recheck_observation()?;
		Ok(result)
	}
}

impl CheckpointStage for NativeCaptureStage<'_> {
	type Binding = FileIdentity;

	fn sync_prefix(&mut self, end: u64) -> Result<Self::Binding, Self::Error> {
		if self.begin_effect()? != end || end == 0 {
			return Err(NativeCaptureStageError::Extent);
		}
		let identity = self.writer.sync_prefix(end)?;
		self.barrier.confirm(identity, end)?;
		self.written.set(Some(end));
		Ok(identity)
	}
}

impl RestartStage for NativeCaptureStage<'_> {
	fn held_binding(&self) -> Result<Self::Binding, Self::Error> {
		let end = self
			.written
			.get()
			.ok_or(NativeCaptureStageError::Uncertain)?;
		self.observe_position(end)
	}

	fn closed_binding(stage: &Self::Closed) -> Result<Self::Binding, Self::Error> {
		stage.open_read_back()?.recheck_observation()?;
		Ok(stage.closed.identity())
	}
}

pub(super) struct NativeClosedStage<'stage> {
	closed: LinuxClosedStage<'stage>,
	inventory: RecoveryInventory<'stage>,
	names: (UnixComponent<'stage>, UnixComponent<'stage>),
}

impl<'stage> ClosedStage for NativeClosedStage<'stage> {
	type Error = NativeCaptureStageError;
	type Reader<'reader>
		= NativeReadBack<'reader, 'stage>
	where
		Self: 'reader;

	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error> {
		self.inventory.recheck()?;
		let file = self.inventory.stage().ok_or(StageError::IdentityChanged)?;
		Ok(NativeReadBack {
			inventory: &self.inventory,
			file,
		})
	}
}

pub(super) struct NativeReadBack<'reader, 'stage> {
	inventory: &'reader RecoveryInventory<'stage>,
	file: &'reader RecoveryFile,
}

impl ReadView for NativeReadBack<'_, '_> {
	type Error = NativeCaptureStageError;

	fn length(&self) -> u64 {
		self.file.len()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.inventory.recheck()?;
		ReadView::recheck_observation(self.file).map_err(StageError::ReadBack)?;
		self.inventory.recheck()?;
		Ok(())
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		if buffer.len() > MAX_STAGE_CHUNK_BYTES {
			return Err(NativeCaptureStageError::Extent);
		}
		self.inventory.recheck()?;
		ReadView::read_exact_at(self.file, offset, buffer).map_err(StageError::ReadBack)?;
		Ok(())
	}
}

#[derive(Debug)]
pub enum NativeCaptureStageError {
	Extent,
	Uncertain,
	Native(StageError),
}

impl fmt::Display for NativeCaptureStageError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Extent => {
				f.write_str("remote stage extent or IO range does not match its capture")
			}
			Self::Uncertain => f.write_str("remote stage has unconfirmed progress"),
			Self::Native(error) => error.fmt(f),
		}
	}
}

impl Error for NativeCaptureStageError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Native(error) => Some(error),
			Self::Extent | Self::Uncertain => None,
		}
	}
}

impl From<StageError> for NativeCaptureStageError {
	fn from(error: StageError) -> Self {
		Self::Native(error)
	}
}
