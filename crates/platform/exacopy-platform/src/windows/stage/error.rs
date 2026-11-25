use std::error::Error;
use std::fmt;
use std::io;

use exacopy_endpoint::IoError;

use crate::windows::native::Refusal;

/// Typed cause returned by a Windows staging handle operation.
#[derive(Debug)]
pub struct NativeStageError(Refusal);

impl fmt::Display for NativeStageError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.fmt(formatter)
	}
}

impl Error for NativeStageError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match &self.0 {
			Refusal::QueryFailed(error) => Some(error),
			_ => None,
		}
	}
}

/// A refusal or failed effect while preparing a retained private stage.
#[derive(Debug)]
#[non_exhaustive]
pub enum WindowsStageError {
	/// The declared length exceeds the signed file extent limit.
	InvalidExtent,
	/// An existing entry prevented exclusive creation.
	Occupied,
	/// The result of the exclusive creation could not be confirmed.
	CreateUncertain(NativeStageError),
	/// Creation was confirmed but the created file could not be admitted.
	CreatedUnconfirmed(Box<WindowsStageError>),
	/// A native handle operation failed.
	Native(NativeStageError),
	/// The held or named stage observation disagreed with the admitted capability.
	Changed,
	/// The range is not in the admitted bounded extent.
	InvalidRange,
	/// A failure has permanently retired the writable capability.
	WriterRetired,
	/// The writer has not completed the full declared extent.
	Incomplete,
	/// A write may have left partial data in the private stage.
	Write(IoError),
	/// The native file flush did not confirm the barrier.
	Barrier(io::Error),
	/// The writable handle did not report a successful close.
	CloseWriter(io::Error),
	/// A read could not complete and its output buffer must be discarded.
	Read(IoError),
}

impl WindowsStageError {
	pub(super) fn native(error: Refusal) -> Self {
		Self::Native(NativeStageError(error))
	}

	pub(super) fn creation_uncertain(error: Refusal) -> Self {
		Self::CreateUncertain(NativeStageError(error))
	}
}

impl fmt::Display for WindowsStageError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidExtent => {
				formatter.write_str("stage length exceeds the signed extent limit")
			}
			Self::Occupied => formatter.write_str("private stage name is occupied"),
			Self::CreateUncertain(error) => {
				write!(formatter, "exclusive stage creation is uncertain ({error})")
			}
			Self::CreatedUnconfirmed(error) => write!(
				formatter,
				"the created stage needs reconciliation ({error})"
			),
			Self::Native(error) => write!(formatter, "native stage operation failed ({error})"),
			Self::Changed => formatter.write_str("the held or named stage observation changed"),
			Self::InvalidRange => formatter.write_str("stage range is outside the admitted extent"),
			Self::WriterRetired => formatter.write_str("the stage writer has been retired"),
			Self::Incomplete => formatter.write_str("the stage extent is incomplete"),
			Self::Write(error) => write!(formatter, "private stage write failed ({error})"),
			Self::Barrier(error) => write!(formatter, "private stage flush failed ({error})"),
			Self::CloseWriter(error) => {
				write!(formatter, "private stage writer close failed ({error})")
			}
			Self::Read(error) => write!(formatter, "private stage read failed ({error})"),
		}
	}
}

impl Error for WindowsStageError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::CreateUncertain(error) | Self::Native(error) => Some(error),
			Self::CreatedUnconfirmed(error) => Some(error.as_ref()),
			Self::Write(error) | Self::Read(error) => Some(error),
			Self::Barrier(error) | Self::CloseWriter(error) => Some(error),
			_ => None,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::os::windows::io::{AsHandle, FromRawHandle, OwnedHandle};

	use windows_sys::Win32::System::Threading::CreateEventW;

	use crate::windows::native::{Kind, observe_file};

	#[test]
	#[allow(
		unsafe_code,
		reason = "a synthetic owned event exercises the native query refusal"
	)]
	fn non_file_handle_preserves_the_native_query_failure() {
		// SAFETY: Null optional name/security pointers request a new unnamed event.
		let raw = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
		assert!(!raw.is_null(), "create the synthetic event handle");
		// SAFETY: Successful creation transfers this unique live handle to its owner.
		let event = unsafe { OwnedHandle::from_raw_handle(raw) };
		assert!(matches!(
			observe_file(event.as_handle(), Kind::RegularFile),
			Err(Refusal::QueryFailed(error))
				if error.raw_os_error().is_some_and(|code| code != 0)
		));
	}

	#[test]
	fn confirmed_create_refusal_preserves_the_typed_observation_cause() {
		let error = WindowsStageError::CreatedUnconfirmed(Box::new(WindowsStageError::Changed));
		assert!(matches!(
			error
				.source()
				.and_then(|cause| cause.downcast_ref::<WindowsStageError>()),
			Some(WindowsStageError::Changed)
		));
	}
}
