use exacopy_endpoint::{JournalFileBarrier, JournalSegment};
use exacopy_journal::frame::{ChainHead, FRAME_OVERHEAD_BYTES, Frame, FrameKind};
use exacopy_journal::{DurableJournal, SyncedFrame};

use super::{Body, Error, RemoteDownloadContext, RemoteDownloadRecord, RemoteReplayBoundary};

pub(in crate::assembly::linux::remote_journal) fn append_record_admitted<S: JournalSegment, G>(
	writer: &mut DurableJournal<S>,
	previous: RemoteReplayBoundary,
	context: RemoteDownloadContext,
	body: Body<'_>,
	enter: impl FnOnce() -> std::io::Result<G>,
) -> Result<RemoteReplayBoundary, Error> {
	let record = make_record(previous.head, context, body)?;
	let (frame, _, bound) =
		append_payload_admitted(writer, previous, body.kind(), record.encode()?, enter)?;
	check_frame(&frame, previous.head, record)?;
	Ok(bound)
}

pub(in crate::assembly::linux::remote_journal) fn append_payload_admitted<S: JournalSegment, G>(
	writer: &mut DurableJournal<S>,
	previous: RemoteReplayBoundary,
	kind: FrameKind,
	payload: Vec<u8>,
	enter: impl FnOnce() -> std::io::Result<G>,
) -> Result<(Frame, SyncedFrame, RemoteReplayBoundary), Error> {
	let offset = FRAME_OVERHEAD_BYTES
		.checked_add(payload.len())
		.and_then(|bytes| u64::try_from(bytes).ok())
		.and_then(|bytes| previous.offset.checked_add(bytes))
		.ok_or(Error::Binding)?;
	let (frame, synced) = writer.append_frame_admitted(kind, payload, enter)?;
	if synced.barrier() != JournalFileBarrier::SyncAll
		|| synced.kind() != kind
		|| synced.head() != frame.head()
		|| frame.kind() != kind
		|| previous.head.sequence().checked_add(1) != Some(frame.head().sequence())
		|| previous.head.digest() != frame.previous_digest()
	{
		return Err(Error::Binding);
	}
	let boundary = RemoteReplayBoundary {
		head: frame.head(),
		offset,
	};
	Ok((frame, synced, boundary))
}

pub(super) fn make_record<'name>(
	previous: ChainHead,
	context: RemoteDownloadContext,
	body: Body<'name>,
) -> Result<RemoteDownloadRecord<'name>, Error> {
	Ok(RemoteDownloadRecord::new(
		context,
		(previous != ChainHead::start()).then_some(previous),
		body,
	)?)
}

pub(super) fn check_frame(
	frame: &Frame,
	previous: ChainHead,
	expected: RemoteDownloadRecord<'_>,
) -> Result<(), Error> {
	if previous.sequence().checked_add(1) != Some(frame.head().sequence())
		|| previous.digest() != frame.previous_digest()
		|| RemoteDownloadRecord::from_frame(frame)? != expected
		|| expected.encode()?.as_slice() != frame.payload()
	{
		return Err(Error::Binding);
	}
	Ok(())
}
