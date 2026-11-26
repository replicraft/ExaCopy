use std::io::{self, Read};

use exacopy_endpoint::linux_staging::StagingSource as _;
use exacopy_endpoint::{ReadView, UnixComponent};

use super::{NamedReadView, ReadRoot, SyncPreviewError, names, pin};

/// A read-only opener under an independently selected, held artifact directory.
///
/// Only the caller's explicit raw name selects a member. There is no lookup
/// by a path or label read from a signed object, no discovery, and no fallback.
#[derive(Debug)]
pub struct SyncHistoryDirectory<'directory> {
	root: &'directory ReadRoot,
	byte_limit: u16,
}

impl<'directory> SyncHistoryDirectory<'directory> {
	/// Borrows a separately authorized read root with an explicit byte ceiling.
	#[must_use]
	pub const fn new(root: &'directory ReadRoot, byte_limit: u16) -> Self {
		Self { root, byte_limit }
	}

	/// Pins one exact named regular member under the held directory.
	///
	/// # Errors
	/// Refuses missing or unsupported names, incomplete name checks, changed
	/// identities, and lengths above the caller's bound.
	pub fn open_member(
		&self,
		name: UnixComponent<'directory>,
	) -> io::Result<SyncHistoryReader<'directory>> {
		let open = || -> Result<_, SyncPreviewError> {
			let pin = pin(self.root, name)?
				.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
				.map_err(SyncPreviewError::System)?;
			let initial = super::FileIdentity::from_stat(&rustix::fs::fstat(&pin)?);
			let view = NamedReadView::open(self.root, name)?;
			if initial != view.identity() {
				return Err(SyncPreviewError::Changed);
			}
			if view.length() > u64::from(self.byte_limit) || view.metadata().link_count() != 1 {
				return Err(SyncPreviewError::System(io::Error::from(
					io::ErrorKind::InvalidData,
				)));
			}
			view.recheck_observation()?;
			Ok(SyncHistoryReader {
				root: self.root,
				name,
				view,
				offset: 0,
			})
		};
		open().map_err(|error| match error {
			SyncPreviewError::System(error) => error,
			other => io::Error::other(other),
		})
	}
}

/// A pinned bounded regular artifact with no descriptor or write access.
#[derive(Debug)]
pub struct SyncHistoryReader<'directory> {
	root: &'directory ReadRoot,
	name: UnixComponent<'directory>,
	view: NamedReadView<'directory>,
	offset: u64,
}

impl Read for SyncHistoryReader<'_> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		if output.is_empty() {
			return Ok(0);
		}
		let remaining = self
			.view
			.length()
			.checked_sub(self.offset)
			.ok_or(io::ErrorKind::InvalidData)?;
		if remaining == 0 {
			names::confirm(self.root.directory(), self.name, Some(self.view.identity()))
				.map_err(io::Error::other)?;
			self.view.recheck_observation().map_err(io::Error::other)?;
			return Ok(0);
		}
		let output_len = u64::try_from(output.len()).map_err(io::Error::other)?;
		let count = usize::try_from(remaining.min(output_len)).map_err(io::Error::other)?;
		self.view
			.read_exact_at(self.offset, &mut output[..count])
			.map_err(io::Error::other)?;
		self.offset = self
			.offset
			.checked_add(u64::try_from(count).map_err(io::Error::other)?)
			.ok_or(io::ErrorKind::InvalidData)?;
		Ok(count)
	}
}
