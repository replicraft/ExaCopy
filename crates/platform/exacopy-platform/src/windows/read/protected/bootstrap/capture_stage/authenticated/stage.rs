use std::cell::Cell;
use std::fmt;

use exacopy_endpoint::{ClosedStage, FreshStage, ReadView};

use crate::windows::{
	MAX_WINDOWS_STAGE_IO_BYTES, WindowsStageError, WindowsStageIdentity, WindowsStagePrefix,
	WindowsStageReadBack, WindowsStageView,
};

use super::super::{Binding, CaptureCustody, WindowsCaptureStageError, WindowsCaptureStageWriter};
use super::{WindowsCaptureAdmission, WindowsCaptureEffect};

/// Private write authority lent only within one guarded capture.
pub struct WindowsGuardedCaptureStage<'stage, A> {
	stage: WindowsCaptureStageWriter<'stage>,
	admission: &'stage A,
	length: u64,
	written: u64,
	closed: &'stage Cell<bool>,
}

impl<'stage, A: WindowsCaptureAdmission> WindowsGuardedCaptureStage<'stage, A> {
	pub(super) fn new(
		stage: WindowsCaptureStageWriter<'stage>,
		admission: &'stage A,
		length: u64,
		closed: &'stage Cell<bool>,
	) -> Self {
		Self {
			stage,
			admission,
			length,
			written: 0,
			closed,
		}
	}

	/// Returns the original private stage directory identity.
	#[must_use]
	pub fn directory_identity(&self) -> WindowsStageIdentity {
		self.stage.directory_identity()
	}

	/// Returns the original private payload identity.
	#[must_use]
	pub fn stage_identity(&self) -> WindowsStageIdentity {
		self.stage.stage_identity()
	}

	/// Synchronizes the original private payload at exactly this written prefix.
	/// # Errors
	/// A refusal, wrong extent or unconfirmed observation stops the writer.
	pub fn sync_written_prefix(
		&mut self,
		end: u64,
	) -> Result<WindowsStagePrefix, WindowsCaptureStageError> {
		use WindowsCaptureStageError as Failure;
		let mut writer = self.stage.take_writer()?;
		if end == 0 || end != self.written {
			return Err(Failure::Stage(WindowsStageError::InvalidRange));
		}
		let guard = self
			.admission
			.enter(WindowsCaptureEffect::StagePrefixBarrier {
				stage: self.stage_identity(),
				end,
			})
			.map_err(Failure::Admission)?;
		let prefix = writer.sync_written_prefix(end).map_err(Failure::Stage)?;
		self.stage.custody.check_leaf(self.stage.leaf)?;
		drop(guard);
		self.stage.writer = Some(writer);
		Ok(prefix)
	}
}

impl<'stage, A: WindowsCaptureAdmission> FreshStage for WindowsGuardedCaptureStage<'stage, A> {
	type Error = WindowsCaptureStageError;
	type Closed = WindowsGuardedCaptureReadBack<'stage>;

	const MAX_CHUNK_BYTES: usize = MAX_WINDOWS_STAGE_IO_BYTES;

	fn unwritten_length(&self) -> Result<u64, Self::Error> {
		self.stage.custody.check_leaf(self.stage.leaf)?;
		self.stage
			.writer
			.as_ref()
			.ok_or(WindowsCaptureStageError::Stage(
				WindowsStageError::WriterRetired,
			))?
			.unwritten_length()
			.map_err(WindowsCaptureStageError::Stage)
	}

	fn write_next(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		use WindowsCaptureStageError as Failure;
		let mut writer = self.stage.take_writer()?;
		let end = u64::try_from(buffer.len())
			.ok()
			.and_then(|length| self.written.checked_add(length))
			.filter(|&end| end <= self.length && end > self.written)
			.ok_or(Failure::Stage(WindowsStageError::InvalidRange))?;
		if buffer.len() > MAX_WINDOWS_STAGE_IO_BYTES {
			return Err(Failure::Stage(WindowsStageError::InvalidRange));
		}
		let guard = self
			.admission
			.enter(WindowsCaptureEffect::StageWrite {
				stage: self.stage_identity(),
				offset: self.written,
				length: buffer.len(),
			})
			.map_err(Failure::Admission)?;
		writer.write_next(buffer).map_err(Failure::Stage)?;
		self.stage.custody.check_leaf(self.stage.leaf)?;
		drop(guard);
		self.written = end;
		self.stage.writer = Some(writer);
		Ok(())
	}

	fn sync_and_close(self) -> Result<Self::Closed, Self::Error> {
		use WindowsCaptureStageError as Failure;
		if self.written != self.length {
			return Err(Failure::Stage(WindowsStageError::Incomplete));
		}
		let custody = self.stage.custody;
		let leaf = self.stage.leaf;
		custody.check_leaf(leaf)?;
		let guard = self
			.admission
			.enter(WindowsCaptureEffect::StageCloseBarrier {
				stage: self.stage_identity(),
				end: self.length,
			})
			.map_err(Failure::Admission)?;
		let stage = self.stage.finish()?;
		drop(guard);
		self.closed.set(true);
		Ok(WindowsGuardedCaptureReadBack {
			stage,
			custody,
			leaf,
		})
	}
}

impl<A> fmt::Debug for WindowsGuardedCaptureStage<'_, A> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsGuardedCaptureStage")
			.finish_non_exhaustive()
	}
}

/// Same protected private stage after a confirmed close and file barrier.
pub struct WindowsGuardedCaptureReadBack<'stage> {
	stage: WindowsStageReadBack<'stage>,
	custody: &'stage CaptureCustody<'stage, 'stage>,
	leaf: &'stage Binding,
}

impl<'stage> ClosedStage for WindowsGuardedCaptureReadBack<'stage> {
	type Error = WindowsCaptureStageError;
	type Reader<'view>
		= WindowsGuardedCaptureView<'view, 'stage>
	where
		Self: 'view;

	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error> {
		self.custody.check_leaf(self.leaf)?;
		let stage = self
			.stage
			.open_read_back()
			.map_err(WindowsCaptureStageError::Stage)?;
		self.custody.check_leaf(self.leaf)?;
		Ok(WindowsGuardedCaptureView {
			stage,
			custody: self.custody,
			leaf: self.leaf,
		})
	}
}

impl fmt::Debug for WindowsGuardedCaptureReadBack<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsGuardedCaptureReadBack")
			.finish_non_exhaustive()
	}
}

/// Independently opened read-back of the same guarded private payload.
pub struct WindowsGuardedCaptureView<'view, 'stage> {
	stage: WindowsStageView<'view, 'stage>,
	custody: &'stage CaptureCustody<'stage, 'stage>,
	leaf: &'stage Binding,
}

impl ReadView for WindowsGuardedCaptureView<'_, '_> {
	type Error = WindowsCaptureStageError;

	fn length(&self) -> u64 {
		self.stage.length()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.custody.check_leaf(self.leaf)?;
		self.stage
			.recheck_observation()
			.map_err(WindowsCaptureStageError::Stage)?;
		self.custody.check_leaf(self.leaf)
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		self.custody.check_leaf(self.leaf)?;
		self.stage
			.read_exact_at(offset, buffer)
			.map_err(WindowsCaptureStageError::Stage)?;
		self.custody.check_leaf(self.leaf)
	}
}

impl fmt::Debug for WindowsGuardedCaptureView<'_, '_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsGuardedCaptureView")
			.finish_non_exhaustive()
	}
}
