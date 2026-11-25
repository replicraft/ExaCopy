use std::collections::VecDeque;
use std::{fmt, io};

/// The positional operation whose next call will consume a scripted fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferOperation {
	/// A source or stage read.
	Read,
	/// A stage write.
	Write,
}

/// The storage effect whose next call will consume a scripted fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectOperation {
	/// Exclusive stage creation.
	Create,
	/// The stage file contents barrier.
	FlushFile,
	/// The exclusive namespace change.
	Publish,
	/// A directory entries barrier.
	FlushDirectory,
}

/// The simulated reason an operation returned an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
	/// A storage I/O error.
	Io,
	/// The storage ran out of space.
	NoSpace,
}

impl Failure {
	pub(crate) fn into_io(self) -> io::Error {
		match self {
			Self::Io => io::Error::other("simulated storage I/O error"),
			Self::NoSpace => io::Error::from(io::ErrorKind::StorageFull),
		}
	}
}

/// One positional call's scripted behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferFault {
	/// Allow the call to make ordinary progress.
	Pass,
	/// Limit progress to at most this many bytes. Zero simulates a zero transfer.
	Short(usize),
	/// Report an interruption without transferring any bytes.
	Interrupted,
	/// Report failure without transferring any bytes.
	Before(Failure),
	/// Transfer up to the requested byte count, then return the error.
	After {
		/// The maximum actual progress before failure.
		bytes: usize,
		/// The error reported to the caller.
		failure: Failure,
	},
}

impl TransferFault {
	pub(crate) fn begin(self, requested: usize) -> io::Result<usize> {
		match self {
			Self::Pass => Ok(requested),
			Self::Short(bytes) | Self::After { bytes, .. } => Ok(requested.min(bytes)),
			Self::Interrupted => Err(io::ErrorKind::Interrupted.into()),
			Self::Before(failure) => Err(failure.into_io()),
		}
	}

	pub(crate) fn finish(self, transferred: usize) -> io::Result<usize> {
		match self {
			Self::After { failure, .. } => Err(failure.into_io()),
			_ => Ok(transferred),
		}
	}
}

/// One storage effect's scripted behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectFault {
	/// Allow the effect to complete ordinarily.
	Pass,
	/// Report an error before any change.
	Before(Failure),
	/// Perform the effect and lose its successful result.
	After(Failure),
}

/// A rejected simulated operation whose requested change did not take place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejection {
	/// The requested name was absent.
	Missing,
	/// The name referred to a link rather than a regular file.
	NotAFile,
	/// The target name was already occupied.
	Conflict,
	/// The private name now resolves to a different object or is absent.
	StageRebound,
	/// The handle was issued by another simulator or before a crash.
	StaleHandle,
	/// The simulator's fixture size or fault queue limit was reached.
	Limit,
}

impl From<Rejection> for io::Error {
	fn from(value: Rejection) -> Self {
		let kind = match value {
			Rejection::Missing => io::ErrorKind::NotFound,
			Rejection::NotAFile => io::ErrorKind::InvalidInput,
			Rejection::Conflict => io::ErrorKind::AlreadyExists,
			Rejection::StageRebound | Rejection::StaleHandle => io::ErrorKind::InvalidInput,
			Rejection::Limit => io::ErrorKind::FileTooLarge,
		};
		io::Error::new(kind, value)
	}
}

impl fmt::Display for Rejection {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(formatter, "simulator rejected operation: {self:?}")
	}
}

impl std::error::Error for Rejection {}

/// Failure to observe a successful storage effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectError {
	/// Validation rejected the effect before performing it.
	Rejected(Rejection),
	/// The failure is known to have occurred before the effect.
	Failed(Failure),
	/// The result is uncertain to the caller and requires inspecting storage.
	Unknown(Failure),
}

impl From<Rejection> for EffectError {
	fn from(rejection: Rejection) -> Self {
		Self::Rejected(rejection)
	}
}

impl fmt::Display for EffectError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			formatter,
			"simulated effect did not report success: {self:?}"
		)
	}
}

impl std::error::Error for EffectError {}

impl EffectFault {
	pub(crate) fn begin(self) -> Result<(), EffectError> {
		match self {
			Self::Before(failure) => Err(EffectError::Failed(failure)),
			_ => Ok(()),
		}
	}

	pub(crate) fn finish<T>(self, result: T) -> Result<T, EffectError> {
		match self {
			Self::After(failure) => Err(EffectError::Unknown(failure)),
			_ => Ok(result),
		}
	}
}

#[derive(Debug, Default)]
pub(crate) struct Faults {
	pub(crate) read: VecDeque<TransferFault>,
	pub(crate) write: VecDeque<TransferFault>,
	pub(crate) create: VecDeque<EffectFault>,
	pub(crate) flush_file: VecDeque<EffectFault>,
	pub(crate) publish: VecDeque<EffectFault>,
	pub(crate) flush_directory: VecDeque<EffectFault>,
}

pub(crate) fn queue_fault<T>(queue: &mut VecDeque<T>, fault: T) -> Result<(), Rejection> {
	const MAX_FAULTS_PER_OPERATION: usize = 64;
	if queue.len() == MAX_FAULTS_PER_OPERATION {
		return Err(Rejection::Limit);
	}
	queue.push_back(fault);
	Ok(())
}
