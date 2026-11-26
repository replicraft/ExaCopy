use crate::LinuxFileIdentity;
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::remote_download::replay::RemoteReplayBoundary;
use crate::remote_download::wire::{write_head, write_identity};

use super::wire::{CONFIRMED, common, encoder, finish, hex};
use super::{
	Error, MAX_REMOTE_RECEIPT_READY_BYTES, RemoteWitnessIntent, check_successor,
	distinct_on_device, successor_end,
};

/// Maximum canonical witnessed receipt artifact size.
pub const MAX_REMOTE_WITNESS_RECEIPT_BYTES: u16 = 6144;

const MAX_DURABILITY_BYTES: usize = 551;
const PENDING_PREFIX: &[u8] = b"rw-receipt.pending.";
const FINAL_PREFIX: &[u8] = b"rw-receipt.final.";
const PENDING_NAME_BYTES: usize = 101;
const FINAL_NAME_BYTES: usize = 99;
const SUFFIX_BYTES: usize = 82;

/// Independently resolved artifacts and accepted prior authority for kind 42.
///
/// The caller establishes the full closeout graph, exact canonical receipt
/// bytes, protected file observations and successful barriers. This codec
/// compares those declarations and the actual kind 9 to the encoded payload.
#[derive(Debug)]
pub struct ReceiptReadyExpectation<'history> {
	/// Exact previously authenticated kind 41 in this closeout.
	pub witness: RemoteWitnessIntent,
	/// Authoritative actual kind 9 accepted by the scanner.
	pub durability: &'history Frame,
	/// Exact accepted durability boundary.
	pub boundary: RemoteReplayBoundary,
	/// Exact earlier metadata frame from the accepted closeout.
	pub metadata: ChainHead,
	/// Accepted successful kind-8 boundary immediately before kind 9.
	pub observed: RemoteReplayBoundary,
	/// Independently selected receipt file identity.
	pub receipt: LinuxFileIdentity,
	/// Length of the independently measured canonical receipt.
	pub length: u16,
	/// Digest of the complete canonical receipt bytes including their domain.
	pub digest: [u8; 32],
}

/// Canonical selected kind 42 tied to the exact accepted kind 9 and kind 41.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteReceiptReady {
	boundary: RemoteReplayBoundary,
	receipt: LinuxFileIdentity,
	length: u16,
	digest: [u8; 32],
}

impl RemoteReceiptReady {
	/// Canonically encodes exact receipt evidence as selected by the caller.
	///
	/// # Errors
	/// Refuses an inconsistent chain anchor, receipt length or recorded identity.
	pub fn encode(expected: &ReceiptReadyExpectation<'_>) -> Result<Vec<u8>, Error> {
		validate(expected)?;
		let witness = expected.witness;
		let mut out = encoder::<MAX_REMOTE_RECEIPT_READY_BYTES>();
		common(
			&mut out,
			witness.binding,
			expected.boundary.head,
			FrameKind::RemoteReceiptReady,
		)?;
		out.array(9)?;
		write_identity(&mut out, witness.job_directory)?;
		let (pending, final_name) = names(witness);
		out.bytes(&pending)?.bytes(&final_name)?;
		write_identity(&mut out, expected.receipt)?;
		out.u16(expected.length)?
			.bytes(&expected.digest)?
			.u8(CONFIRMED)?
			.u8(CONFIRMED)?
			.u8(CONFIRMED)?;
		let payload = finish(out);
		successor_end(expected.boundary, payload.len())?;
		Ok(payload)
	}

	/// Matches an actual frame to the one exact canonical caller-selected payload.
	///
	/// # Errors
	/// Refuses malformed, overlong, noncanonical or mismatched frame evidence.
	pub fn from_frame(
		frame: &Frame,
		end: RemoteReplayBoundary,
		expected: &ReceiptReadyExpectation<'_>,
	) -> Result<Self, Error> {
		if frame.payload().len() > MAX_REMOTE_RECEIPT_READY_BYTES {
			return Err(Error::Length);
		}
		check_successor(frame, FrameKind::RemoteReceiptReady, expected.boundary, end)?;
		if Self::encode(expected)? != frame.payload() {
			return Err(Error::Binding);
		}
		Ok(Self {
			boundary: end,
			receipt: expected.receipt,
			length: expected.length,
			digest: expected.digest,
		})
	}

	/// Returns the exact accepted frame boundary.
	#[must_use]
	pub const fn boundary(self) -> RemoteReplayBoundary {
		self.boundary
	}

	/// Returns the recorded exact sealed receipt inode.
	#[must_use]
	pub const fn receipt(self) -> LinuxFileIdentity {
		self.receipt
	}

	/// Returns the recorded sealed receipt byte count.
	#[must_use]
	pub const fn length(self) -> u16 {
		self.length
	}

	/// Returns the recorded canonical receipt digest.
	#[must_use]
	pub const fn digest(self) -> [u8; 32] {
		self.digest
	}
}

fn validate(expected: &ReceiptReadyExpectation<'_>) -> Result<(), Error> {
	let witness = expected.witness;
	if !(1..=MAX_REMOTE_WITNESS_RECEIPT_BYTES).contains(&expected.length)
		|| !distinct_on_device([
			witness.target_parent,
			witness.job_directory,
			witness.stage_directory,
			witness.binding.stage,
			expected.receipt,
		]) {
		return Err(Error::Binding);
	}
	check_successor(
		expected.durability,
		FrameKind::DurabilityRecorded,
		expected.observed,
		expected.boundary,
	)?;

	let intent_sequence = witness.boundary.head.sequence();
	if intent_sequence.checked_add(3) != Some(expected.metadata.sequence())
		|| intent_sequence.checked_add(5) != Some(expected.observed.head.sequence())
		|| expected.observed.offset <= witness.boundary.offset
	{
		return Err(Error::FrameBinding);
	}
	let mut out = encoder::<MAX_DURABILITY_BYTES>();
	common(
		&mut out,
		witness.binding,
		expected.observed.head,
		FrameKind::DurabilityRecorded,
	)?;
	out.array(9)?;
	write_head(&mut out, expected.metadata)?;
	write_identity(&mut out, witness.stage_directory)?;
	write_identity(&mut out, witness.target_parent)?;
	write_identity(&mut out, witness.job_directory)?;
	out.bytes(&witness.qualification_digest)?
		.u8(CONFIRMED)?
		.u8(CONFIRMED)?
		.u8(CONFIRMED)?
		.u8(CONFIRMED)?;
	if finish(out) != expected.durability.payload() {
		return Err(Error::Binding);
	}
	Ok(())
}

fn names(witness: RemoteWitnessIntent) -> ([u8; PENDING_NAME_BYTES], [u8; FINAL_NAME_BYTES]) {
	let mut suffix = [b'.'; SUFFIX_BYTES];
	hex(&mut suffix[..32], witness.binding.context.entry.as_bytes());
	hex(
		&mut suffix[33..49],
		&witness.binding.epochs.run.get().to_be_bytes(),
	);
	hex(&mut suffix[50..], &witness.nonce);
	let mut pending = [0; PENDING_NAME_BYTES];
	let (prefix, bytes) = pending.split_at_mut(PENDING_PREFIX.len());
	prefix.copy_from_slice(PENDING_PREFIX);
	bytes.copy_from_slice(&suffix);
	let mut final_name = [0; FINAL_NAME_BYTES];
	let (prefix, bytes) = final_name.split_at_mut(FINAL_PREFIX.len());
	prefix.copy_from_slice(FINAL_PREFIX);
	bytes.copy_from_slice(&suffix);
	(pending, final_name)
}
