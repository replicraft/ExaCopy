use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{
	DarwinDurabilityRecorded, DarwinPhaseError, DarwinPublishObserved, DarwinReceiptCommitted,
};
use minicbor::Decoder;

use super::super::fixture::frame;
use super::{DIGEST, Outcome, Records};

#[test]
fn payloads_refuse_truncation_overflow_trailing_bytes_and_noncanonical_encoding() {
	let records = Records::new();
	let observation = records.observed(Outcome::Published, records.published_names());
	let barriers = records.barrier_frame(&observation);
	let receipt = DarwinReceiptCommitted::new(&barriers, DIGEST)
		.unwrap()
		.encode();

	check_rejections(observation.payload(), DarwinPublishObserved::decode);
	check_rejections(barriers.payload(), DarwinDurabilityRecorded::decode);
	check_rejections(&receipt, DarwinReceiptCommitted::decode);
}

fn check_rejections<T: core::fmt::Debug>(
	payload: &[u8],
	decode: impl Fn(&[u8]) -> Result<T, DarwinPhaseError>,
) {
	for end in 0..payload.len() {
		assert!(decode(&payload[..end]).is_err(), "accepted at byte {end}");
	}
	let mut modified = payload.to_vec();
	modified.push(0);
	assert_eq!(
		decode(&modified).unwrap_err(),
		DarwinPhaseError::TrailingBytes
	);
	let mut modified = payload.to_vec();
	// Encode map key 0 in its non-shortest form without changing the represented value.
	modified.splice(1..2, [0x18, 0]);
	assert_eq!(
		decode(&modified).unwrap_err(),
		DarwinPhaseError::NonCanonical
	);
	assert_eq!(
		decode(&[0; 1024]).unwrap_err(),
		DarwinPhaseError::PayloadTooLong
	);
}

#[test]
fn journals_refuse_nonpreceding_and_wrong_kind_frames() {
	let records = Records::new();
	let observation = records.observed(Outcome::Published, records.published_names());
	let barriers = records.barrier_frame(&observation);
	let receipt = DarwinReceiptCommitted::new(&barriers, DIGEST)
		.unwrap()
		.encode();

	let anchor = |sequence| ChainHead::after(sequence, [0x01; 32]).unwrap();
	let early = frame(
		FrameKind::PublishObserved,
		observation.payload(),
		anchor(records.intent.head().sequence() - 1),
	);
	assert_eq!(
		DarwinPublishObserved::from_frame(&early),
		Err(DarwinPhaseError::InvalidFrameOrder),
	);
	let early = frame(
		FrameKind::DurabilityRecorded,
		barriers.payload(),
		anchor(observation.head().sequence() - 1),
	);
	assert_eq!(
		DarwinDurabilityRecorded::from_frame(&early),
		Err(DarwinPhaseError::InvalidFrameOrder),
	);
	let early = frame(
		FrameKind::ReceiptCommitted,
		&receipt,
		anchor(barriers.head().sequence() - 1),
	);
	assert_eq!(
		DarwinReceiptCommitted::from_frame(&early),
		Err(DarwinPhaseError::InvalidFrameOrder),
	);

	assert!(matches!(
		DarwinPublishObserved::from_frame(&barriers),
		Err(DarwinPhaseError::WrongKind { .. }),
	));
	assert!(matches!(
		DarwinDurabilityRecorded::from_frame(&records.intent),
		Err(DarwinPhaseError::WrongKind { .. }),
	));
	assert!(matches!(
		DarwinReceiptCommitted::from_frame(&observation),
		Err(DarwinPhaseError::WrongKind { .. }),
	));
}

#[test]
fn intent_chain_reference_cannot_substitute_for_effect_sequence_or_owner_binding() {
	let records = Records::new();
	let observation = records.observed(Outcome::Published, records.published_names());
	let payload = observation.payload();
	let mut effect_decoder = Decoder::new(payload);
	assert_eq!(effect_decoder.map().unwrap(), Some(8));
	for key in 0..4 {
		assert_eq!(effect_decoder.u8().unwrap(), key);
		effect_decoder.skip().unwrap();
	}
	assert_eq!(effect_decoder.u8().unwrap(), 4);
	let start = effect_decoder.position();
	assert_eq!(effect_decoder.u64().unwrap(), u64::MAX);
	let end = effect_decoder.position();

	let mut modified = payload.to_vec();
	modified[end - 1] ^= 1;
	let stale = DarwinPublishObserved::decode(&modified).unwrap();
	assert_eq!(
		stale.validate_intent(&records.intent),
		Err(DarwinPhaseError::BindingMismatch),
	);

	modified.splice(start..end, [0]);
	assert_eq!(
		DarwinPublishObserved::decode(&modified),
		Err(DarwinPhaseError::InvalidEffectSequence),
	);

	let binding = DarwinPublishObserved::from_frame(&observation)
		.unwrap()
		.binding();
	for token in [
		binding.owner_digest.as_bytes().as_slice(),
		binding.stage_id.as_bytes(),
	] {
		let mut modified = payload.to_vec();
		flip_matching_byte(&mut modified, token);
		let stale = DarwinPublishObserved::decode(&modified).unwrap();
		assert_eq!(
			stale.validate_intent(&records.intent),
			Err(DarwinPhaseError::BindingMismatch),
		);
	}
}

#[test]
fn wire_refuses_reserved_references_and_unrecognized_claims() {
	let records = Records::new();
	let observation = records.observed(Outcome::Published, records.published_names());
	let mut observed = observation.payload().to_vec();
	let intent_digest = records.intent.head().digest();
	let digest = observed
		.windows(intent_digest.len())
		.position(|bytes| bytes == intent_digest)
		.unwrap();
	observed[digest..digest + intent_digest.len()].fill(0);
	assert_eq!(
		DarwinPublishObserved::decode(&observed),
		Err(DarwinPhaseError::InvalidReference),
	);
	let mut observed = observation.payload().to_vec();
	*observed.last_mut().unwrap() = 6;
	assert_eq!(
		DarwinPublishObserved::decode(&observed),
		Err(DarwinPhaseError::UnsupportedEvidence),
	);

	let barrier_frame = records.barrier_frame(&observation);
	let mut barriers = barrier_frame.payload().to_vec();
	let end = barriers.len();
	// Body key 2 records the achieved level. The immediately preceding key 6 is
	// the public directory barrier operation. Both are mandatory.
	assert_eq!(&barriers[end - 4..], &[6, 1, 2, 0]);
	barriers[end - 1] = 1;
	assert_eq!(
		DarwinDurabilityRecorded::decode(&barriers),
		Err(DarwinPhaseError::UnsupportedEvidence),
	);
	barriers[end - 1] = 0;
	barriers[end - 3] = 2;
	assert_eq!(
		DarwinDurabilityRecorded::decode(&barriers),
		Err(DarwinPhaseError::UnsupportedEvidence),
	);

	let mut receipt = DarwinReceiptCommitted::new(&barrier_frame, DIGEST)
		.unwrap()
		.encode();
	flip_matching_byte(&mut receipt, b"receipts/receipt.cbor");
	assert_eq!(
		DarwinReceiptCommitted::decode(&receipt),
		Err(DarwinPhaseError::UnsupportedEvidence),
	);
}

fn flip_matching_byte(payload: &mut [u8], token: &[u8]) {
	let offset = payload
		.windows(token.len())
		.position(|bytes| bytes == token)
		.unwrap();
	payload[offset] ^= 1;
}
