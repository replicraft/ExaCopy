use std::fmt;
use std::io;

use rustix::io::Errno;

use super::super::ReadError;

#[cfg(test)]
#[path = "../../../tests/unit/plan_error.rs"]
mod tests;

/// Failure to observe or write a protected native Plan bundle.
#[derive(Debug)]
#[non_exhaustive]
pub enum PlanBundleError {
	/// The selected output path or basename is outside this profile.
	InvalidOutput,
	/// The bundle overlaps a protected parent or mount evidence is uncertain.
	Scope(Option<io::Error>),
	/// The selected directory is unsafe, unavailable for checked open, or changed.
	Unsafe(Option<io::Error>),
	/// An occupied or changed name did not satisfy the selected record.
	Conflict,
	/// An exclusive create observed an existing name.
	AlreadyExists(io::Error),
	/// Native bundle I/O or a requested barrier failed.
	Io(io::Error),
	/// Reading an incumbent page under the required protections failed.
	ReuseRead(ReadError),
}

impl PlanBundleError {
	pub(super) fn bundle_open(error: Errno) -> Self {
		match error {
			Errno::LOOP | Errno::XDEV | Errno::NOTDIR => Self::Unsafe(Some(error.into())),
			_ => Self::io(error),
		}
	}

	pub(super) fn io(error: impl Into<io::Error>) -> Self {
		Self::Io(error.into())
	}

	pub(super) fn mount_observation(error: io::Error) -> Self {
		match error.kind() {
			io::ErrorKind::Unsupported => Self::Scope(Some(error)),
			_ => Self::Io(error),
		}
	}

	pub(super) const fn is_existing_name(&self) -> bool {
		matches!(self, Self::AlreadyExists(_))
	}
}

impl fmt::Display for PlanBundleError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::InvalidOutput => "invalid plan bundle output selection",
			Self::Scope(_) => "plan bundle scope is not established",
			Self::Unsafe(_) => "plan bundle directory is unsafe",
			Self::Conflict => "plan bundle record conflicts with the selection",
			Self::AlreadyExists(_) => "plan bundle name is occupied",
			Self::Io(_) => "plan bundle filesystem operation failed",
			Self::ReuseRead(_) => "incumbent plan page could not be safely read",
		};
		formatter.write_str(message)
	}
}

impl std::error::Error for PlanBundleError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Scope(Some(error))
			| Self::Unsafe(Some(error))
			| Self::AlreadyExists(error)
			| Self::Io(error) => Some(error),
			Self::ReuseRead(error) => Some(error),
			_ => None,
		}
	}
}
