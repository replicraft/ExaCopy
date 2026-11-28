use std::fmt;
use std::io;
use std::os::windows::io::AsHandle as _;

use exacopy_endpoint::MAX_FILE_LENGTH;
use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
use windows_sys::Win32::Foundation::{
	OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, STATUS_OBJECT_NAME_COLLISION,
	STATUS_OBJECT_NAME_NOT_FOUND,
};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

use crate::windows::capture_creation::CreationDescriptor;
use crate::windows::native::{Refusal, RelativeFileOpen, open_relative_entry};
use crate::windows::stage::publication::native::{require_access, require_case_insensitive};
use crate::windows::{
	WindowsStageDirectory, WindowsStageError, WindowsStageIdentity, WindowsStagePrefix,
	WindowsStageReadBack, WindowsStageWriter,
};

use super::super::{FILE_METADATA_ACCESS, FILE_OPENED_INFORMATION, observe_leaf};
use super::{
	Binding, DIRECTORY_ACCESS, Directory, Error, Kind, WindowsBootstrapFreshSegment,
	WindowsComponent, acl, named_identity, refused, security,
};

mod authenticated;

pub use authenticated::{
	MAX_WINDOWS_CAPTURE_SEGMENT_BYTES, WindowsAuthenticatedCaptureScope, WindowsCaptureAdmission,
	WindowsCaptureEffect, WindowsCaptureJournalAdmission, WindowsCaptureJournalGuard,
	WindowsCaptureJournalSegment, WindowsGuardedCaptureReadBack, WindowsGuardedCaptureStage,
	WindowsGuardedCaptureView, WindowsPreparedCaptureScope,
};

const STAGE_DIRECTORY: [u16; 5] = [115, 116, 97, 103, 101];
const PAYLOAD_NAME: [u16; 7] = [112, 97, 121, 108, 111, 97, 100];
const MUTATION_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;

/// Failure at the protected private capture-stage boundary.
#[derive(Debug)]
#[non_exhaustive]
pub enum WindowsCaptureStageError {
	/// A protected original role, current actor or held observation failed.
	Custody(Error),
	/// The original fresh bootstrap writer is retired or lost custody.
	Bootstrap(io::Error),
	/// Target lookup found an incumbent. No target bytes were read.
	TargetOccupied,
	/// The fixed stage directory name was already occupied.
	StageDirectoryOccupied,
	/// Directory creation was submitted without a fully confirmed result.
	DirectoryCreateUnconfirmed(Error),
	/// Current app authority refused the selected effect before submission.
	Admission(io::Error),
	/// The scoped capture journal lost custody or has an unconfirmed effect.
	CaptureJournal(io::Error),
	/// Private stage creation, writing, barrier or close was refused.
	Stage(WindowsStageError),
}

impl fmt::Display for WindowsCaptureStageError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Custody(cause) => write!(formatter, "capture custody failed ({cause})"),
			Self::Bootstrap(cause) => write!(formatter, "bootstrap custody failed ({cause})"),
			Self::TargetOccupied => formatter.write_str("capture target is occupied"),
			Self::StageDirectoryOccupied => {
				formatter.write_str("private stage directory is occupied")
			}
			Self::DirectoryCreateUnconfirmed(cause) => {
				write!(
					formatter,
					"private directory creation needs reconciliation ({cause})"
				)
			}
			Self::Admission(cause) => write!(formatter, "capture effect refused ({cause})"),
			Self::CaptureJournal(cause) => write!(formatter, "capture journal failed ({cause})"),
			Self::Stage(cause) => fmt::Display::fmt(cause, formatter),
		}
	}
}

impl std::error::Error for WindowsCaptureStageError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Custody(cause) | Self::DirectoryCreateUnconfirmed(cause) => Some(cause),
			Self::Bootstrap(cause) | Self::Admission(cause) | Self::CaptureJournal(cause) => {
				Some(cause)
			}
			Self::Stage(cause) => Some(cause),
			Self::TargetOccupied | Self::StageDirectoryOccupied => None,
		}
	}
}

/// Creates one protected private stage after confirming the original bootstrap append.
pub struct WindowsCaptureStageScope<'name> {
	pub(super) bootstrap: WindowsBootstrapFreshSegment<'name>,
}

impl fmt::Debug for WindowsCaptureStageScope<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsCaptureStageScope")
			.finish_non_exhaustive()
	}
}

impl<'name> WindowsCaptureStageScope<'name> {
	/// Creates the fixed protected stage directory and its one fresh leaf.
	///
	/// This requires the original live bootstrap custody and independently
	/// selected target. The issuer must already grant controlled creation in
	/// that job and exclude retained namespace, data and security mutation
	/// capabilities. The caller selects and maintains the exact relative target;
	/// there is no target writer or publication capability in this scope.
	/// The kernel applies a protected descriptor for the admitted actor at creation.
	/// No ACL is repaired after opening. No namespace persistence is established.
	/// An `Ok` callback result by itself carries no completion or checkpoint fact.
	///
	/// # Errors
	/// Refuses a changed role, ambiguous or occupied target, unsupported case
	/// mode, preexisting private name or unconfirmed private effect. Any possibly
	/// created objects remain available for independent reconciliation.
	pub fn with_capture_stage<T>(
		&self,
		target: WindowsComponent<'_>,
		length: u64,
		use_stage: impl for<'stage> FnOnce(
			WindowsCaptureStageWriter<'stage>,
		) -> Result<T, WindowsCaptureStageError>,
	) -> Result<T, WindowsCaptureStageError> {
		let descriptor = self.prepare_capture(target, length)?;
		let custody = self.capture_custody(target, &descriptor, || Ok(()))?;
		let stage = custody.stage_directory()?;
		let writer = custody.create_payload(&stage, length, &descriptor, || Ok(()))?;
		let leaf = custody.capture_leaf(writer.identity())?;
		let output = use_stage(WindowsCaptureStageWriter {
			custody: &custody,
			writer: Some(writer),
			leaf: &leaf,
		})?;
		custody.check_leaf(&leaf)?;
		Ok(output)
	}

	fn prepare_capture(
		&self,
		target: WindowsComponent<'_>,
		length: u64,
	) -> Result<CreationDescriptor, WindowsCaptureStageError> {
		use WindowsCaptureStageError as Failure;
		if length > MAX_FILE_LENGTH {
			return Err(Failure::Stage(WindowsStageError::InvalidExtent));
		}
		self.bootstrap.check().map_err(Failure::Bootstrap)?;
		check_target(&self.bootstrap, target)?;
		CreationDescriptor::private_for_sid(&self.bootstrap.records.subject.sid)
			.ok_or(WindowsCaptureStageError::Custody(Error::Unprotected))
	}

	fn capture_custody<'stage, G>(
		&'stage self,
		target: WindowsComponent<'stage>,
		descriptor: &CreationDescriptor,
		enter: impl FnOnce() -> Result<G, WindowsCaptureStageError>,
	) -> Result<CaptureCustody<'stage, 'name>, WindowsCaptureStageError> {
		use WindowsCaptureStageError as Failure;
		let stage_name = WindowsComponent::new(&STAGE_DIRECTORY)
			.map_err(|_| Failure::Custody(Error::InvalidPath))?;
		let directory = self.open_capture_stage_directory(stage_name, target, descriptor, enter)?;
		Ok(CaptureCustody {
			bootstrap: &self.bootstrap,
			stage_name,
			target,
			directory,
		})
	}

	fn open_capture_stage_directory<G>(
		&self,
		name: WindowsComponent<'_>,
		target: WindowsComponent<'_>,
		descriptor: &CreationDescriptor,
		enter: impl FnOnce() -> Result<G, WindowsCaptureStageError>,
	) -> Result<Directory, WindowsCaptureStageError> {
		use WindowsCaptureStageError as Failure;
		let records = &self.bootstrap.records;
		let owner_job = &records.job;
		self.bootstrap.check().map_err(Failure::Bootstrap)?;
		check_target(&self.bootstrap, target)?;
		require_case_insensitive(owner_job.handle.as_handle())
			.map_err(|_| Failure::Custody(Error::Unprotected))?;
		let guard = enter()?;
		let handle = match descriptor.create(
			owner_job.handle.as_handle(),
			name,
			request(DIRECTORY_ACCESS | FILE_ADD_FILE),
			Kind::Directory,
		) {
			Ok(handle) => handle,
			Err(Refusal::OpenFailed(STATUS_OBJECT_NAME_COLLISION)) => {
				return Err(Failure::StageDirectoryOccupied);
			}
			Err(cause) => return Err(Failure::DirectoryCreateUnconfirmed(refused(cause))),
		};
		let binding = (|| {
			require_access(handle.as_handle(), DIRECTORY_ACCESS | FILE_ADD_FILE)
				.map_err(|_| Error::Unprotected)?;
			require_case_insensitive(handle.as_handle()).map_err(|_| Error::Unprotected)?;
			let identity = named_identity(handle.as_handle(), Kind::Directory, name)?;
			super::super::super::same_volume(identity, owner_job.binding.identity)
				.map_err(refused)?;
			Binding::capture(
				handle.as_handle(),
				identity,
				&records.subject,
				acl::Role::Private,
			)
		})()
		.map_err(Failure::DirectoryCreateUnconfirmed)?;
		drop(guard);
		Ok(Directory { handle, binding })
	}
}

pub(super) fn open_job_for_capture(
	root: &Directory,
	name: WindowsComponent<'_>,
	subject: &security::Subject,
) -> Result<Directory, Error> {
	let handle = open_relative_entry(
		root.handle.as_handle(),
		name,
		request(DIRECTORY_ACCESS | FILE_ADD_SUBDIRECTORY),
		Kind::Directory,
	)
	.map_err(refused)?;
	require_access(handle.as_handle(), DIRECTORY_ACCESS | FILE_ADD_SUBDIRECTORY)
		.map_err(|_| Error::Unprotected)?;
	require_case_insensitive(handle.as_handle()).map_err(|_| Error::Unprotected)?;
	let identity = named_identity(handle.as_handle(), Kind::Directory, name)?;
	super::super::super::same_volume(identity, root.binding.identity).map_err(refused)?;
	let binding = Binding::capture(handle.as_handle(), identity, subject, acl::Role::Private)?;
	Ok(Directory { handle, binding })
}

pub(super) fn check_capture_job(
	root: &Directory,
	job: &Directory,
	name: WindowsComponent<'_>,
) -> Result<(), Error> {
	let named = open_relative_entry(
		root.handle.as_handle(),
		name,
		request(DIRECTORY_ACCESS),
		Kind::Directory,
	)
	.map_err(refused)?;
	for handle in [job.handle.as_handle(), named.as_handle()] {
		require_case_insensitive(handle).map_err(|_| Error::Unprotected)?;
		job.binding
			.recheck(handle, named_identity(handle, Kind::Directory, name)?)?;
	}
	Ok(())
}

struct CaptureCustody<'stage, 'name> {
	bootstrap: &'stage WindowsBootstrapFreshSegment<'name>,
	stage_name: WindowsComponent<'stage>,
	target: WindowsComponent<'stage>,
	directory: Directory,
}

impl CaptureCustody<'_, '_> {
	fn stage_directory(&self) -> Result<WindowsStageDirectory<'_>, WindowsCaptureStageError> {
		self.check()?;
		WindowsStageDirectory::from_authorized_handle(self.directory.handle.as_handle())
			.map_err(WindowsCaptureStageError::Stage)
	}

	fn create_payload<'stage, G>(
		&self,
		stage: &'stage WindowsStageDirectory<'_>,
		length: u64,
		descriptor: &CreationDescriptor,
		enter: impl FnOnce() -> Result<G, WindowsCaptureStageError>,
	) -> Result<WindowsStageWriter<'stage>, WindowsCaptureStageError> {
		let payload = WindowsComponent::new(&PAYLOAD_NAME)
			.map_err(|_| WindowsCaptureStageError::Custody(Error::InvalidPath))?;
		let guard = enter()?;
		let writer = stage
			.create_protected(payload, length, descriptor)
			.map_err(WindowsCaptureStageError::Stage)?;
		drop(guard);
		Ok(writer)
	}

	fn check(&self) -> Result<(), WindowsCaptureStageError> {
		use WindowsCaptureStageError as Failure;
		self.bootstrap.check().map_err(Failure::Bootstrap)?;
		check_target(self.bootstrap, self.target)?;
		let named = open_relative_entry(
			self.bootstrap.records.job.handle.as_handle(),
			self.stage_name,
			request(DIRECTORY_ACCESS),
			Kind::Directory,
		)
		.map_err(refused)
		.map_err(Failure::Custody)?;
		for handle in [self.directory.handle.as_handle(), named.as_handle()] {
			require_case_insensitive(handle).map_err(|_| Failure::Custody(Error::Unprotected))?;
			let identity = named_identity(handle, Kind::Directory, self.stage_name)
				.map_err(Failure::Custody)?;
			self.directory
				.binding
				.recheck(handle, identity)
				.map_err(Failure::Custody)?;
		}
		self.bootstrap.check().map_err(Failure::Bootstrap)
	}

	fn capture_leaf(
		&self,
		expected: WindowsStageIdentity,
	) -> Result<Binding, WindowsCaptureStageError> {
		let (binding, length) = self.observe_leaf()?;
		if binding.identity != expected || length != 0 {
			return Err(WindowsCaptureStageError::Custody(Error::Changed));
		}
		Ok(binding)
	}

	fn check_leaf(&self, original: &Binding) -> Result<(), WindowsCaptureStageError> {
		let (observed, _) = self.observe_leaf()?;
		if observed != *original {
			return Err(WindowsCaptureStageError::Custody(Error::Changed));
		}
		Ok(())
	}

	fn observe_leaf(&self) -> Result<(Binding, usize), WindowsCaptureStageError> {
		use WindowsCaptureStageError as Failure;
		self.check()?;
		let name = WindowsComponent::new(&PAYLOAD_NAME)
			.map_err(|_| Failure::Custody(Error::InvalidPath))?;
		let file = open_relative_entry(
			self.directory.handle.as_handle(),
			name,
			request(FILE_METADATA_ACCESS),
			Kind::RegularFile,
		)
		.map_err(refused)
		.map_err(Failure::Custody)?;
		let (binding, stamp) =
			observe_leaf(file.as_handle(), name, &self.bootstrap.records.subject)
				.map_err(Failure::Custody)?;
		stamp
			.check_stream(file.as_handle(), Error::Unprotected)
			.map_err(Failure::Custody)?;
		self.check()?;
		Ok((binding, stamp.length))
	}
}

/// One exact private capture writer. It carries no publication operation.
pub struct WindowsCaptureStageWriter<'stage> {
	custody: &'stage CaptureCustody<'stage, 'stage>,
	writer: Option<WindowsStageWriter<'stage>>,
	leaf: &'stage Binding,
}

impl fmt::Debug for WindowsCaptureStageWriter<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsCaptureStageWriter")
			.finish_non_exhaustive()
	}
}

impl<'stage> WindowsCaptureStageWriter<'stage> {
	/// Returns the newly observed directory identity from original custody.
	#[must_use]
	pub fn directory_identity(&self) -> WindowsStageIdentity {
		self.custody.directory.binding.identity
	}

	/// Returns the exact created one-link stage identity.
	#[must_use]
	pub fn stage_identity(&self) -> WindowsStageIdentity {
		self.leaf.identity
	}

	/// Writes one contiguous private range under the protected capture scope.
	///
	/// # Errors
	/// A bounds, observation or I/O failure permanently stops this writer.
	pub fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), WindowsCaptureStageError> {
		self.operate(|writer| writer.write_at(offset, bytes))
	}

	/// Synchronizes the exact private prefix without recording a checkpoint.
	///
	/// # Errors
	/// A failed scope or barrier observation permanently stops this writer.
	pub fn sync_written_prefix(
		&mut self,
		end: u64,
	) -> Result<WindowsStagePrefix, WindowsCaptureStageError> {
		self.operate(|writer| writer.sync_written_prefix(end))
	}

	/// Confirms the native writer close and returns only the private read-back view.
	///
	/// # Errors
	/// Refuses incomplete data, lost custody or unconfirmed native effects.
	pub fn finish(mut self) -> Result<WindowsStageReadBack<'stage>, WindowsCaptureStageError> {
		let writer = self.take_writer()?;
		let closed = writer.finish().map_err(WindowsCaptureStageError::Stage)?;
		self.custody.check_leaf(self.leaf)?;
		Ok(closed)
	}

	fn operate<T>(
		&mut self,
		use_writer: impl FnOnce(&mut WindowsStageWriter<'stage>) -> Result<T, WindowsStageError>,
	) -> Result<T, WindowsCaptureStageError> {
		let mut writer = self.take_writer()?;
		let value = use_writer(&mut writer).map_err(WindowsCaptureStageError::Stage)?;
		self.custody.check_leaf(self.leaf)?;
		self.writer = Some(writer);
		Ok(value)
	}

	fn take_writer(&mut self) -> Result<WindowsStageWriter<'stage>, WindowsCaptureStageError> {
		let writer = self.writer.take().ok_or(WindowsCaptureStageError::Stage(
			WindowsStageError::WriterRetired,
		))?;
		self.custody.check_leaf(self.leaf)?;
		Ok(writer)
	}
}

fn check_target(
	bootstrap: &WindowsBootstrapFreshSegment<'_>,
	target: WindowsComponent<'_>,
) -> Result<(), WindowsCaptureStageError> {
	use WindowsCaptureStageError as Failure;
	let root = bootstrap.records.root.handle.as_handle();
	require_case_insensitive(root).map_err(|_| Failure::Custody(Error::Unprotected))?;
	let named = open_relative_entry(
		root,
		target,
		request(FILE_METADATA_ACCESS),
		Kind::RegularFile,
	);
	require_case_insensitive(root).map_err(|_| Failure::Custody(Error::Unprotected))?;
	match named {
		Ok(_) => Err(Failure::TargetOccupied),
		Err(Refusal::OpenFailed(STATUS_OBJECT_NAME_NOT_FOUND)) => Ok(()),
		Err(cause) => Err(Failure::Custody(refused(cause))),
	}
}

fn request(access: u32) -> RelativeFileOpen {
	RelativeFileOpen {
		access,
		share: MUTATION_SHARE,
		disposition: FILE_OPEN,
		attributes: OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE,
		expected_result: Some(FILE_OPENED_INFORMATION),
	}
}
