//! Capabilities for a single held live remote read pass.

use std::future::Future;
use std::num::{NonZeroU64, NonZeroUsize};

use crate::UnixComponent;

/// The selected base for an exact slash-delimited SFTP path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SftpPathRoot {
	/// Use the authenticated account's starting directory.
	AccountRelative,
	/// Use the server's absolute slash namespace.
	Absolute,
}

/// One explicitly rooted SFTP name in already validated raw components.
/// This describes bytes sent to the server and confers no confinement.
#[derive(Clone, Copy)]
pub enum SftpPath<'path> {
	/// Interpret these components relative to the authenticated account.
	AccountRelative(&'path [UnixComponent<'path>]),
	/// Interpret these components after one leading slash.
	Absolute(&'path [UnixComponent<'path>]),
}

impl<'path> SftpPath<'path> {
	/// Returns the selected path base.
	#[must_use]
	pub const fn root(self) -> SftpPathRoot {
		match self {
			Self::AccountRelative(_) => SftpPathRoot::AccountRelative,
			Self::Absolute(_) => SftpPathRoot::Absolute,
		}
	}

	/// Returns the original validated raw components.
	#[must_use]
	pub const fn components(self) -> &'path [UnixComponent<'path>] {
		match self {
			Self::AccountRelative(components) | Self::Absolute(components) => components,
		}
	}
}

/// A caller-assigned identifier for one held live read pass.
///
/// A reopen or connection-generation change needs a fresh epoch before another
/// pass. This identifies a capture attempt and carries no stable file identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SourceEpoch(NonZeroU64);

impl SourceEpoch {
	/// Wraps the caller's nonzero identifier for a fresh held read pass.
	#[must_use]
	pub const fn new(id: NonZeroU64) -> Self {
		Self(id)
	}

	/// Returns the pass identifier for comparison or checkpoint binding.
	#[must_use]
	pub const fn get(self) -> u64 {
		self.0.get()
	}
}

/// A live read-only stream on one held handle and connection generation.
///
/// Implementations must fail on unconfirmed or stale completions. They may
/// complete short reads on this handle within their own bounded request policy.
/// The adapter cannot retry a call by transparently reopening the source.
pub trait CapturedReadAt {
	/// Adapter's error while reading or checking the captured observation.
	type Error;

	/// Identifies the exact read pass this capability can currently serve.
	fn epoch(&self) -> SourceEpoch;

	/// Returns the signed-offset-compatible extent observed when opening this pass.
	fn length(&self) -> u64;

	/// Limits the number of bytes per exact positioned read.
	fn max_window_bytes(&self) -> NonZeroUsize;

	/// Fills the entire requested range from this handle at the given offset.
	/// A failed call may have changed scratch bytes.
	fn read_exact_at(
		&mut self,
		offset: u64,
		bytes: &mut [u8],
	) -> impl Future<Output = Result<(), Self::Error>>;

	/// Rechecks required live observations of the held source before capture.
	/// The result describes this handle's observations within the adapter's
	/// limits, including the inability to detect every concurrent edit.
	///
	/// # Errors
	/// Refuses unavailable or changed required observations.
	fn recheck(&mut self) -> impl Future<Output = Result<(), Self::Error>>;

	/// Verifies exact EOF and final observations, and closes the held read handle.
	/// The adapter retains its epoch for comparison after successful closure.
	///
	/// # Errors
	/// Fails if the full source, final observations, EOF, or handle closure
	/// cannot be confirmed. A failed close provides no capture evidence.
	fn finish(&mut self) -> impl Future<Output = Result<(), Self::Error>>;
}
