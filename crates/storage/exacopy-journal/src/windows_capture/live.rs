use std::{fmt, io};

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_endpoint::{JournalFileBarrier, JournalSegment};

use crate::DurableJournal;
use crate::frame::{ChainHead, FRAME_OVERHEAD_BYTES, FrameKind};
use crate::windows_bootstrap::WindowsBootstrapFileIdentity;

use super::codec::{sign_prepared, sign_range};
use super::{
	WindowsCaptureError as Error, WindowsCapturePrefix, WindowsCaptureRoles,
	WindowsCaptureSelection, replay,
};

/// The caller's barrier-confirmed range end and digest from the originally held stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsCaptureRangeObservation {
	/// The original protected stage directory.
	pub stage_directory: WindowsBootstrapFileIdentity,
	/// The original protected stage payload.
	pub stage_payload: WindowsBootstrapFileIdentity,
	/// Exact exclusive end of the synced contiguous stage prefix.
	pub end_offset: u64,
	/// BLAKE3 digest of the one newly synced range.
	pub digest: [u8; 32],
}

/// A fresh capture's original, exclusively held journal writer and accepted cursor.
/// The native segment and fresh per-effect admission remain the caller's responsibility.
pub struct WindowsCaptureLive<S> {
	journal: DurableJournal<S>,
	key: VerifyingKey,
	roles: WindowsCaptureRoles,
	prepared: ChainHead,
	prefix: WindowsCapturePrefix,
}

impl<S> fmt::Debug for WindowsCaptureLive<S> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsCaptureLive")
			.field("prefix", &self.prefix)
			.finish_non_exhaustive()
	}
}

/// Signs, appends, syncs and confirms preparation on the original empty capture sibling.
/// The guard admits the actual segment-relative offset and complete frame length and remains
/// held through append and sync. Native role and source observations come from the caller.
/// # Errors
/// Refuses invalid selection, binding, signer, writer or admission. Bytes from any started
/// append remain in place. A failed append or confirmation yields no live capture writer.
pub fn append_prepared<S: JournalSegment, G>(
	mut journal: DurableJournal<S>,
	selection: &WindowsCaptureSelection<'_>,
	observed: WindowsCaptureRoles,
	observed_extent: u64,
	signer: &SigningKey,
	enter: impl FnOnce(u64, usize) -> io::Result<G>,
) -> Result<WindowsCaptureLive<S>, Error> {
	if journal.current_boundary() != Some((ChainHead::start(), 0)) {
		return Err(Error::Boundary);
	}
	if S::BARRIER != JournalFileBarrier::SyncAll {
		return Err(Error::Barrier);
	}
	let payload = sign_prepared(selection, observed, observed_extent, signer)?;
	let length = payload.len() + FRAME_OVERHEAD_BYTES;
	let (_, synced) = journal
		.append_frame_admitted(FrameKind::WindowsCapturePrepared, payload, || {
			enter(0, length)
		})
		.map_err(Error::Durable)?;
	journal
		.confirm_current_frame_using(&synced, replay::reread_boundary)
		.map_err(Error::Durable)?;
	Ok(WindowsCaptureLive {
		journal,
		key: *selection.bootstrap.owner_key(),
		roles: observed,
		prepared: synced.head(),
		prefix: WindowsCapturePrefix::prepared(synced.head(), length as u64, observed_extent),
	})
}

impl<S: JournalSegment> WindowsCaptureLive<S> {
	/// Returns the last authenticated and barrier-confirmed prefix of this invocation.
	#[must_use]
	pub const fn prefix(&self) -> WindowsCapturePrefix {
		self.prefix
	}

	/// Appends one exact range using the same original writer and a fresh guard.
	/// The prefix advances only after sync and exact held chain/EOF readback.
	/// # Errors
	/// Refuses changed stage identity, end, cadence, key, admission or journal evidence.
	/// Any submitted bytes remain in place, and no unconfirmed range advances the prefix.
	pub fn append_range<G>(
		&mut self,
		observation: WindowsCaptureRangeObservation,
		signer: &SigningKey,
		enter: impl FnOnce(u64, usize) -> io::Result<G>,
	) -> Result<(), Error> {
		if observation.stage_directory != self.roles.stage_directory
			|| observation.stage_payload != self.roles.stage_payload
		{
			return Err(Error::Roles);
		}
		let position = self.prefix.next_range().ok_or(Error::Range)?;
		if observation.end_offset != position.end() {
			return Err(Error::Range);
		}
		let payload = sign_range(
			self.prepared,
			self.prefix.head(),
			position,
			observation.digest,
			&self.key,
			signer,
		)?;
		let offset = self.prefix.segment_end();
		let length = payload.len() + FRAME_OVERHEAD_BYTES;
		let (_, synced) = self
			.journal
			.append_frame_admitted(FrameKind::WindowsCaptureRange, payload, || {
				enter(offset, length)
			})
			.map_err(Error::Durable)?;
		self.journal
			.confirm_current_frame_using(&synced, replay::reread_boundary)
			.map_err(Error::Durable)?;
		self.prefix.advance(synced.head(), position);
		Ok(())
	}
}
