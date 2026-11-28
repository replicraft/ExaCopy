use std::{fmt, io};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::remote_source::SourceEpoch;
use exacopy_endpoint::{ClosedStage, FreshStage, JournalSegment, ReadView};
use exacopy_journal::DurableJournal;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::windows_bootstrap::WindowsBootstrapBytes;
use exacopy_journal::windows_capture::{
	WindowsCaptureError, WindowsCaptureLive, WindowsCaptureRangeObservation, WindowsCaptureRoles,
};
use exacopy_platform::windows::{
	WindowsCaptureStageError, WindowsGuardedCaptureStage, WindowsStageIdentity, WindowsStagePrefix,
};
use exacopy_transfer::remote_capture::{CaptureCheckpoint, CaptureCheckpoints, CheckpointStage};

use super::grant::Effects;
use super::progress::Progress;

pub(super) fn prepared_payload(bytes: &WindowsBootstrapBytes) -> io::Result<Vec<u8>> {
	let mut input = FrameReader::new(&bytes.first_segment[..], ChainHead::start());
	let frame = input
		.next_frame()
		.map_err(io::Error::other)?
		.ok_or(io::ErrorKind::InvalidData)?;
	Ok(frame.payload().to_vec())
}

pub(super) fn append_bootstrap(
	segment: impl JournalSegment,
	payload: Vec<u8>,
	head: ChainHead,
) -> io::Result<()> {
	// The current compound V1 guard already encloses this writer and the
	// enclosing native barrier. Acquiring it here again would be incorrect.
	let mut journal = DurableJournal::from_new_segment(segment).map_err(io::Error::other)?;
	let (actual, synced) = journal
		.append_frame(FrameKind::JobPrepared, payload)
		.map_err(io::Error::other)?;
	if actual.head() != head {
		return Err(io::ErrorKind::InvalidData.into());
	}
	journal
		.confirm_current_frame(&synced)
		.map_err(io::Error::other)
}

/// Refusal or uncertainty at a signed private checkpoint boundary.
#[derive(Debug)]
#[non_exhaustive]
pub enum WindowsCaptureLedgerError {
	/// The live range or stage barrier is outside the admitted scope.
	Binding,
	/// The actual native durable writer could not be initialized.
	Open(exacopy_journal::DurableJournalError),
	/// Signed append or held confirmation failed.
	Storage(WindowsCaptureError),
}

impl fmt::Display for WindowsCaptureLedgerError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Binding => formatter.write_str("range and native stage barrier disagree"),
			Self::Open(cause) => write!(formatter, "capture journal open failed ({cause})"),
			Self::Storage(cause) => cause.fmt(formatter),
		}
	}
}

impl std::error::Error for WindowsCaptureLedgerError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Binding => None,
			Self::Open(cause) => Some(cause),
			Self::Storage(cause) => Some(cause),
		}
	}
}

pub(super) struct Ledger<'a, S, Enter> {
	pub(super) live: WindowsCaptureLive<S>,
	pub(super) roles: WindowsCaptureRoles,
	pub(super) directory: WindowsStageIdentity,
	pub(super) payload: WindowsStageIdentity,
	pub(super) epoch: SourceEpoch,
	pub(super) signing_key: &'a SigningKey,
	pub(super) enter: Enter,
	pub(super) progress: &'a Progress,
}

impl<S, Enter, Guard> CaptureCheckpoints<WindowsStagePrefix> for Ledger<'_, S, Enter>
where
	S: JournalSegment,
	Enter: Fn(u64, usize) -> io::Result<Guard>,
{
	type Error = WindowsCaptureLedgerError;

	fn record(
		&mut self,
		stage: WindowsStagePrefix,
		range: CaptureCheckpoint,
	) -> Result<(), Self::Error> {
		let end_offset = range
			.offset
			.checked_add(range.length)
			.ok_or(WindowsCaptureLedgerError::Binding)?;
		if range.epoch != self.epoch
			|| range.offset != self.live.prefix().covered_bytes()
			|| range.length == 0
			|| stage.parent() != self.directory
			|| stage.stage() != self.payload
			|| stage.end() != end_offset
		{
			return Err(WindowsCaptureLedgerError::Binding);
		}
		self.live
			.append_range(
				WindowsCaptureRangeObservation {
					stage_directory: self.roles.stage_directory,
					stage_payload: self.roles.stage_payload,
					end_offset,
					digest: range.digest,
				},
				self.signing_key,
				&self.enter,
			)
			.map_err(WindowsCaptureLedgerError::Storage)?;
		self.progress.checkpoint(self.roles, self.live.prefix());
		Ok(())
	}
}

pub(super) struct Stage<'stage, 'grant, 'lease> {
	pub(super) native: WindowsGuardedCaptureStage<'stage, Effects<'lease>>,
	pub(super) grant: &'grant Effects<'lease>,
}

impl<'stage, 'grant, 'lease> FreshStage for Stage<'stage, 'grant, 'lease> {
	type Error = WindowsCaptureStageError;
	type Closed = HeldReadBack<
		'grant,
		'lease,
		<WindowsGuardedCaptureStage<'stage, Effects<'lease>> as FreshStage>::Closed,
	>;

	const MAX_CHUNK_BYTES: usize =
		<WindowsGuardedCaptureStage<'stage, Effects<'lease>> as FreshStage>::MAX_CHUNK_BYTES;

	fn unwritten_length(&self) -> Result<u64, Self::Error> {
		self.grant
			.check_current()
			.map_err(WindowsCaptureStageError::Admission)?;
		self.native.unwritten_length()
	}

	fn write_next(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		self.native.write_next(buffer)
	}

	fn sync_and_close(self) -> Result<Self::Closed, Self::Error> {
		Ok(HeldReadBack {
			native: self.native.sync_and_close()?,
			grant: self.grant,
		})
	}
}

impl CheckpointStage for Stage<'_, '_, '_> {
	type Binding = WindowsStagePrefix;

	fn sync_prefix(&mut self, end: u64) -> Result<Self::Binding, Self::Error> {
		self.native.sync_written_prefix(end)
	}
}

pub(super) struct HeldReadBack<'grant, 'lease, C> {
	native: C,
	grant: &'grant Effects<'lease>,
}

impl<'grant, 'lease, C> ClosedStage for HeldReadBack<'grant, 'lease, C>
where
	C: ClosedStage<Error = WindowsCaptureStageError>,
{
	type Error = WindowsCaptureStageError;
	type Reader<'view>
		= CurrentReadBack<'grant, 'lease, C::Reader<'view>>
	where
		Self: 'view;

	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error> {
		self.grant
			.check_current()
			.map_err(WindowsCaptureStageError::Admission)?;
		let reader = self.native.open_read_back()?;
		self.grant
			.check_current()
			.map_err(WindowsCaptureStageError::Admission)?;
		Ok(CurrentReadBack {
			reader,
			grant: self.grant,
		})
	}
}

pub(super) struct CurrentReadBack<'grant, 'lease, R> {
	reader: R,
	grant: &'grant Effects<'lease>,
}

impl<R: ReadView<Error = WindowsCaptureStageError>> ReadView for CurrentReadBack<'_, '_, R> {
	type Error = WindowsCaptureStageError;

	fn length(&self) -> u64 {
		self.reader.length()
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		self.grant
			.check_current()
			.map_err(WindowsCaptureStageError::Admission)?;
		self.reader.read_exact_at(offset, buffer)?;
		self.grant
			.check_current()
			.map_err(WindowsCaptureStageError::Admission)
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.grant
			.check_current()
			.map_err(WindowsCaptureStageError::Admission)?;
		self.reader.recheck_observation()?;
		self.grant
			.check_current()
			.map_err(WindowsCaptureStageError::Admission)
	}
}
