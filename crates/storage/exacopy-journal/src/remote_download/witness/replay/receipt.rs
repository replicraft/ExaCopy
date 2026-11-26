use crate::frame::{ChainHead, Frame, FrameKind};
use crate::remote_download::finalization_policy::SftpDataOnlyV1;
use crate::remote_download::wire::{write_head, write_version};

use super::super::{
	Error, MAX_REMOTE_WITNESS_RECEIPT_BYTES, RemoteWitnessIntent,
	wire::{self, SELECTOR},
};

const DOMAIN: &[u8] = b"ExaCopy/linux-remote-witnessed-continued-download-receipt/v1\0";
const VERSION: [u64; 3] = [1, 0, 15];
const OUTCOME_PUBLISHED_WITH_OMISSIONS: u8 = 2;
const PHASES: [FrameKind; 7] = [
	FrameKind::RemoteWitnessIntent,
	FrameKind::StageSealed,
	FrameKind::VerificationRecorded,
	FrameKind::MetadataRecorded,
	FrameKind::PublishIntent,
	FrameKind::PublishObserved,
	FrameKind::DurabilityRecorded,
];

pub(super) fn canonical_receipt(
	witness: RemoteWitnessIntent,
	frames: &[Frame],
) -> Result<Vec<u8>, Error> {
	if frames.len() != PHASES.len() || frames.iter().map(Frame::kind).ne(PHASES) {
		return Err(Error::FrameBinding);
	}
	let binding = witness.binding();
	let mut out = wire::encoder::<{ MAX_REMOTE_WITNESS_RECEIPT_BYTES as usize }>();
	out.map(8)?.u8(0)?;
	write_version(&mut out, VERSION)?;
	out.u8(1)?
		.bytes(binding.scope.as_bytes())?
		.u8(2)?
		.array(7)?;
	for frame in frames {
		out.array(2)?;
		write_head(&mut out, frame.head())?;
		out.bytes(frame.payload())?;
	}
	out.u8(3)?.bytes(&SftpDataOnlyV1::digest())?.u8(4)?;
	let omissions = SftpDataOnlyV1::omissions();
	out.array(omissions.len() as u64)?;
	for omission in omissions {
		out.u8(omission.code())?;
	}
	out.u8(5)?
		.u8(OUTCOME_PUBLISHED_WITH_OMISSIONS)?
		.u8(6)?
		.array(4)?;
	for head in [binding.allocation, binding.prepared, binding.continuation] {
		write_head(&mut out, head)?;
	}
	wire::write_coverage(&mut out, binding.coverage)?;
	out.u8(7)?.u8(SELECTOR)?;
	Ok(wire::finish(out))
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
	*blake3::Hasher::new()
		.update(DOMAIN)
		.update(bytes)
		.finalize()
		.as_bytes()
}

pub(super) fn frame_head(frames: &[Frame], kind: FrameKind) -> Result<ChainHead, Error> {
	frames
		.iter()
		.find(|frame| frame.kind() == kind)
		.map(Frame::head)
		.ok_or(Error::FrameBinding)
}
