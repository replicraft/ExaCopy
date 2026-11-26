use std::fmt;
use std::fs::File;

use apfs_mounted::identity::ObjectIdentity;
use apfs_mounted::metadata::{
	ExtendedSecurity, MAX_EXTENDED_SECURITY_BYTES, MetadataView, ObservationError,
};
use apfs_mounted::writer::{
	ClosedFile, InitialFlags, LifecycleEffect, MAX_PRIVATE_IO_BYTES, PrivateWriter, WriterError,
};
use apfs_mounted::{Directory, EntryName};
use exacopy_endpoint::UnixComponent;
use exacopy_model::CopyBinding;

use super::super::{ManagedObjectIdentity, acl, with_materialization_disabled};
use super::error::with_mounted_effect;
use super::{StageDirectory, StageError, StageIdentity};

/// Maximum byte count accepted by one private stage read or write.
pub const MAX_STAGE_IO_BYTES: usize = MAX_PRIVATE_IO_BYTES;

/// A checked raw private name and its caller-owned mounted adapter representation.
#[derive(Debug)]
pub struct ManagedStageName<'raw> {
	component: UnixComponent<'raw>,
	mounted: EntryName,
}

impl<'raw> ManagedStageName<'raw> {
	/// Validate the component against the mounted namespace before allocating a stage.
	/// # Errors
	/// Returns the native error if the component cannot be represented.
	pub fn new(component: UnixComponent<'raw>) -> Result<Self, StageError> {
		let mounted = EntryName::new(component.as_bytes()).map_err(StageError::Name)?;
		Ok(Self { component, mounted })
	}

	/// Returns the original validated bytes without normalization.
	#[must_use]
	pub const fn component(&self) -> UnixComponent<'raw> {
		self.component
	}
}

/// Sole synchronous writer for a newly created private file and declared logical extent.
///
/// Its handle remains private. The only admitted ranges are contiguous and advance from
/// offset zero. Any uncertain attempted write retires the handle and retains its private entry.
pub struct WriteStage<'stage> {
	location: StageLocation<'stage>,
	writer: Option<PrivateWriter<'stage>>,
}

impl<'stage> WriteStage<'stage> {
	/// Revalidates the held and named inode before recording stage preparation.
	/// # Errors
	/// Refuses a retired writer or a changed or unavailable stage observation.
	pub fn observe_identity(&self) -> Result<ManagedObjectIdentity, StageError> {
		let writer = self.writer.as_ref().ok_or(StageError::WriterRetired)?;
		with_materialization_disabled(|| {
			self.location.check_current()?;
			writer.with_metadata(check_stage_view_acl)??;
			self.location.observe_identity(writer.identity())
		})
	}

	pub(super) fn create(
		directory: &'stage StageDirectory<'stage>,
		name: &'stage ManagedStageName<'stage>,
		target: UnixComponent<'stage>,
		identity: StageIdentity,
		length: u64,
	) -> Result<Self, StageError> {
		let writer = PrivateWriter::create_with_initial_flags(
			directory.mounted_stage(),
			&name.mounted,
			length,
			InitialFlags::RequireZero,
		)?;
		let location = StageLocation {
			directory,
			name,
			target,
			identity,
			length,
		};
		let verify = || {
			writer.with_metadata(check_stage_view_acl)??;
			location.observe_identity(writer.identity())
		};
		verify().map_err(|error| StageError::CreatedUnverified(Box::new(error)))?;
		Ok(Self {
			location,
			writer: Some(writer),
		})
	}

	/// Returns the identity allocated before this private file was created.
	#[must_use]
	pub fn identity(&self) -> StageIdentity {
		self.location.identity
	}

	/// Returns the transaction binding this writer will report to the model.
	#[must_use]
	pub fn binding(&self) -> CopyBinding {
		self.identity().binding()
	}

	/// Returns the declared extent only while this writer has never transferred data.
	///
	/// # Errors
	/// Refuses retired writers, writers from another process, and writers that have
	/// already completed a nonempty write.
	pub fn unwritten_length(&self) -> Result<u64, StageError> {
		self.location.directory.check_process()?;
		let writer = self.writer.as_ref().ok_or(StageError::WriterRetired)?;
		if writer.position() != 0 {
			return Err(StageError::AlreadyWritten);
		}
		Ok(self.location.length)
	}

	/// Completes the next positioned chunk using at most 1 MiB from the supplied buffer.
	///
	/// # Errors
	/// Rejected ranges leave the writer unchanged. A failure after accepting a range
	/// retires this writer and retains its entry, which may contain a partial transfer.
	pub fn write_next(&mut self, bytes: &[u8]) -> Result<(), StageError> {
		self.write_next_with(bytes, PrivateWriter::write_next)
	}

	fn write_next_with(
		&mut self,
		bytes: &[u8],
		write: impl FnOnce(&mut PrivateWriter<'stage>, &[u8]) -> Result<(), WriterError>,
	) -> Result<(), StageError> {
		self.write_next_with_security(bytes, stage_view_security, write)
	}

	fn write_next_with_security(
		&mut self,
		bytes: &[u8],
		observe: impl Fn(&MetadataView<'_>) -> Result<ExtendedSecurity, ObservationError>,
		write: impl FnOnce(&mut PrivateWriter<'stage>, &[u8]) -> Result<(), WriterError>,
	) -> Result<(), StageError> {
		self.location.directory.check_process()?;
		let writer = self.writer.as_ref().ok_or(StageError::WriterRetired)?;
		let end = bounded_end(writer.position(), bytes.len(), self.location.length)?;
		if bytes.is_empty() {
			return Err(StageError::InvalidRange);
		}
		let mut writer = self.writer.take().ok_or(StageError::WriterRetired)?;
		with_mounted_effect(LifecycleEffect::Written { end }, || {
			self.location.check_current()?;
			writer.with_metadata(|view| Ok(check_stage_security(observe(&view))))??;
			write(&mut writer, bytes)?;
			if writer.position() != end {
				return Err(StageError::StageChanged);
			}
			writer.with_metadata(check_stage_view_acl)??;
			self.location.observe_identity(writer.identity())?;
			Ok::<_, StageError>(())
		})?;
		self.writer = Some(writer);
		Ok(())
	}

	/// Consumes the sole writer after the full declared extent and a Darwin file barrier.
	///
	/// The successful result permits independent read-back and records a successful
	/// F_FULLFSYNC call and checked descriptor closure.
	///
	/// # Errors
	/// Returns an error for incomplete data, failed revalidation, a retired writer,
	/// or unconfirmed synchronization or close. Every failure retains a private stage.
	pub fn flush_and_close(self) -> Result<ClosedStage<'stage>, StageError> {
		self.finish_with(PrivateWriter::flush_and_close)
	}

	fn finish_with(
		self,
		finish: impl FnOnce(PrivateWriter<'stage>) -> Result<ClosedFile<'stage>, WriterError>,
	) -> Result<ClosedStage<'stage>, StageError> {
		self.location.directory.check_process()?;
		let writer = self.writer.ok_or(StageError::WriterRetired)?;
		if writer.position() != self.location.length {
			return Err(StageError::Incomplete);
		}
		with_mounted_effect(LifecycleEffect::Closed, || {
			self.location.check_current()?;
			writer.with_metadata(check_stage_view_acl)??;
			let closed = finish(writer)?;
			let verify = || {
				self.location.observe_identity(closed.identity())?;
				closed.with_metadata(check_stage_view_acl)??;
				Ok(())
			};
			verify().map_err(|error| StageError::ClosedUnverified(Box::new(error)))?;
			Ok(ClosedStage {
				location: self.location,
				closed,
			})
		})
	}
}

impl fmt::Debug for WriteStage<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.debug_struct("WriteStage").finish_non_exhaustive()
	}
}

/// A private inode with a fully written extent and a closed write descriptor.
///
/// The adapter retains the companion's event anchor for separate read-back.
pub struct ClosedStage<'stage> {
	pub(super) location: StageLocation<'stage>,
	pub(super) closed: ClosedFile<'stage>,
}

impl ClosedStage<'_> {
	/// Revalidates the held and named private inode after the writer closed.
	/// # Errors
	/// Refuses a changed or unavailable stage observation.
	pub fn observe_identity(&self) -> Result<ManagedObjectIdentity, StageError> {
		with_materialization_disabled(|| {
			self.location.check_current()?;
			self.closed.with_metadata(check_stage_view_acl)??;
			self.location.observe_identity(self.closed.identity())
		})
	}

	/// Returns the logical extent fixed before staging began.
	#[must_use]
	pub fn length(&self) -> u64 {
		self.location.length
	}

	/// Reports whether the declared extent was empty.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.length() == 0
	}

	/// Returns the identity allocated for this stage before exclusive creation.
	#[must_use]
	pub fn identity(&self) -> StageIdentity {
		self.location.identity
	}

	/// Returns the transaction binding fixed at exclusive creation.
	#[must_use]
	pub fn binding(&self) -> CopyBinding {
		self.identity().binding()
	}

	/// Returns the checked public target component fixed at exclusive creation.
	#[must_use]
	pub fn target(&self) -> UnixComponent<'_> {
		self.location.target
	}
}

impl fmt::Debug for ClosedStage<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("ClosedStage")
			.finish_non_exhaustive()
	}
}

pub(in super::super) struct StageLocation<'stage> {
	directory: &'stage StageDirectory<'stage>,
	name: &'stage ManagedStageName<'stage>,
	pub(super) target: UnixComponent<'stage>,
	pub(super) identity: StageIdentity,
	pub(super) length: u64,
}

impl StageLocation<'_> {
	pub(in super::super) fn mounted_name(&self) -> &EntryName {
		&self.name.mounted
	}

	pub(in super::super) fn directory(&self) -> &Directory {
		self.directory.mounted_stage()
	}

	pub(in super::super) fn destination(&self) -> &Directory {
		self.directory.mounted_destination()
	}

	#[cfg(test)]
	pub(in super::super) fn stage_file(&self) -> &File {
		self.directory.descriptor()
	}

	#[cfg(test)]
	pub(in super::super) fn destination_file(&self) -> &File {
		self.directory.destination()
	}

	pub(in super::super) fn observe_directories(
		&self,
	) -> Result<(ManagedObjectIdentity, ManagedObjectIdentity), StageError> {
		self.directory.observe_directories()
	}

	pub(super) fn check_current(&self) -> Result<(), StageError> {
		self.directory.check_current()
	}

	pub(super) fn observe_identity(
		&self,
		expected: &ObjectIdentity,
	) -> Result<ManagedObjectIdentity, StageError> {
		self.check_current()?;
		expected
			.revalidate_named(self.directory(), self.mounted_name())
			.map_err(WriterError::from)?;
		let identity = ManagedObjectIdentity::from_mounted(expected);
		if identity.physical_fsid() != self.directory.physical_fsid().words() {
			return Err(StageError::StageChanged);
		}
		Ok(identity)
	}

	pub(super) fn open_metadata_handle(
		&self,
		expected: &ObjectIdentity,
	) -> Result<File, StageError> {
		self.observe_identity(expected)?;
		let file = self.directory().open_file(self.mounted_name())?;
		expected.revalidate_held(&file).map_err(WriterError::from)?;
		self.observe_identity(expected)?;
		Ok(file)
	}
}

fn stage_view_security(view: &MetadataView<'_>) -> Result<ExtendedSecurity, ObservationError> {
	view.extended_security(MAX_EXTENDED_SECURITY_BYTES)
}

fn check_stage_security(
	observed: Result<ExtendedSecurity, ObservationError>,
) -> Result<(), StageError> {
	if acl::stage_security(observed)? {
		Ok(())
	} else {
		Err(StageError::StageChanged)
	}
}

pub(super) fn check_stage_view_acl(
	view: MetadataView<'_>,
) -> Result<Result<(), StageError>, ObservationError> {
	Ok(check_stage_security(stage_view_security(&view)))
}

pub(super) fn bounded_end(offset: u64, length: usize, extent: u64) -> Result<u64, StageError> {
	if length > MAX_STAGE_IO_BYTES {
		return Err(StageError::InvalidRange);
	}
	let length = u64::try_from(length).map_err(|_| StageError::InvalidRange)?;
	offset
		.checked_add(length)
		.filter(|end| *end <= extent)
		.ok_or(StageError::InvalidRange)
}

#[cfg(test)]
mod tests;
