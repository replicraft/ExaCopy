use exacopy_journal::frame::ChainHead;
use exacopy_journal::managed_activation_claim::{
	MANAGED_ACTIVATION_CLAIM_BYTES, ManagedActivationClaim, ManagedActivationClaimError as Error,
	encode_managed_activation_claim, match_managed_activation_claim,
};
use exacopy_journal::{JournalEntryId, JournalEpoch};

#[path = "../verification/managed_activation_claim/fixture.rs"]
mod fixture;

use fixture::{ROLES, commitment, reseal, selection, wire};

fn assert_exact(wire: &[u8; 496], selection: &ManagedActivationClaim, role: &str) {
	assert_eq!(
		encode_managed_activation_claim(selection).unwrap(),
		*wire,
		"{role}"
	);
	assert_eq!(
		match_managed_activation_claim(wire, selection)
			.unwrap()
			.as_bytes(),
		&commitment(role),
		"{role}",
	);
}

#[test]
fn managed_activation_claim_matches_frozen_record_and_domain_digest() {
	assert_eq!(MANAGED_ACTIVATION_CLAIM_BYTES, 496);
	let golden = wire();
	assert_eq!(&golden[492..], &[0xbc, 0xc7, 0x71, 0xcf]);
	let mut sealed = golden;
	reseal(&mut sealed);
	assert_eq!(sealed, golden);
	assert_exact(&golden, &selection(), "golden");
}

#[test]
fn managed_activation_claim_refuses_nonexact_length_and_bad_header() {
	let expected = selection();
	let golden = wire();
	for end in 0..golden.len() {
		assert!(
			matches!(
				match_managed_activation_claim(&golden[..end], &expected),
				Err(Error::Length)
			),
			"prefix length {end}"
		);
	}
	let mut trailing = [0; 497];
	trailing[..496].copy_from_slice(&golden);
	assert!(matches!(
		match_managed_activation_claim(&trailing, &expected),
		Err(Error::Length)
	));

	let mut magic = golden;
	magic[0] ^= 1;
	assert!(matches!(
		match_managed_activation_claim(&magic, &expected),
		Err(Error::Magic)
	));
	reseal(&mut magic);
	assert!(matches!(
		match_managed_activation_claim(&magic, &expected),
		Err(Error::Magic)
	));

	for version_byte in [8, 9] {
		let mut version = golden;
		version[version_byte] ^= 1;
		reseal(&mut version);
		assert!(matches!(
			match_managed_activation_claim(&version, &expected),
			Err(Error::UnsupportedVersion)
		));
	}
	for feature_bit in 0..16 {
		let mut features = golden;
		features[10..12].copy_from_slice(&(1_u16 << feature_bit).to_le_bytes());
		reseal(&mut features);
		assert!(
			matches!(
				match_managed_activation_claim(&features, &expected),
				Err(Error::UnsupportedFeatures)
			),
			"feature bit {feature_bit}"
		);
	}
	let mut corrupt = golden;
	corrupt[12..44].fill(0);
	assert!(matches!(
		match_managed_activation_claim(&corrupt, &expected),
		Err(Error::Checksum)
	));
}

#[test]
fn managed_activation_claim_refuses_invalid_fields_with_valid_crc() {
	let expected = selection();
	let golden = wire();
	for (role, range, _) in ROLES {
		let mut zeroed = golden;
		zeroed[range].fill(0);
		reseal(&mut zeroed);
		assert!(
			matches!(
				match_managed_activation_claim(&zeroed, &expected),
				Err(Error::Field)
			),
			"zero {role}"
		);
	}
	for offset in [98, 100, 346, 348] {
		let mut invalid_uuid = golden;
		invalid_uuid[offset] = 0;
		reseal(&mut invalid_uuid);
		assert!(
			matches!(
				match_managed_activation_claim(&invalid_uuid, &expected),
				Err(Error::Field)
			),
			"UUID version or variant at {offset}"
		);
	}
	for (source, destination) in [(148..180, 180), (380..412, 412)] {
		let mut alias = golden;
		alias.copy_within(source, destination);
		reseal(&mut alias);
		assert!(
			matches!(
				match_managed_activation_claim(&alias, &expected),
				Err(Error::Field)
			),
			"alias at {destination}"
		);
	}
	let invalid_edits: [fn(&mut ManagedActivationClaim); 7] = [
		|claim| claim.activation = [0; 32],
		|claim| claim.predecessor_generation = 0,
		|claim| claim.child.entry = JournalEntryId::from_bytes([0; 16]),
		|claim| claim.child.epoch = JournalEpoch::new(0),
		|claim| claim.prepared.head = ChainHead::start(),
		|claim| claim.execution_parent = claim.review_parent,
		|claim| claim.segment = claim.slot,
	];
	for edit in invalid_edits {
		let mut invalid = expected.clone();
		edit(&mut invalid);
		assert!(matches!(
			encode_managed_activation_claim(&invalid),
			Err(Error::Field)
		));
		assert!(matches!(
			match_managed_activation_claim(&golden, &invalid),
			Err(Error::Field)
		));
	}
}

#[test]
fn managed_activation_claim_checks_exact_sequence_and_extent_bounds() {
	let expected = selection();
	let golden = wire();
	let maximum_extent = 64_u64 * 1024 * 1024;
	for (role, sequence, extent) in [
		("minimum", 1, 92),
		("maximum", u64::MAX - 2, maximum_extent),
	] {
		let mut boundary = golden;
		boundary[444..452].copy_from_slice(&sequence.to_le_bytes());
		boundary[484..492].copy_from_slice(&extent.to_le_bytes());
		reseal(&mut boundary);
		let mut selected = expected.clone();
		selected.prepared.head =
			ChainHead::after(sequence, expected.prepared.head.digest()).unwrap();
		selected.prepared.extent = extent;
		assert_exact(&boundary, &selected, role);
	}
	for sequence in [0, u64::MAX - 1, u64::MAX] {
		let mut exhausted = golden;
		exhausted[444..452].copy_from_slice(&sequence.to_le_bytes());
		reseal(&mut exhausted);
		assert!(
			matches!(
				match_managed_activation_claim(&exhausted, &expected),
				Err(Error::Field)
			),
			"sequence {sequence}"
		);
	}
	for extent in [0, 91, maximum_extent + 1, u64::MAX] {
		let mut invalid = golden;
		invalid[484..492].copy_from_slice(&extent.to_le_bytes());
		reseal(&mut invalid);
		assert!(
			matches!(
				match_managed_activation_claim(&invalid, &expected),
				Err(Error::Field)
			),
			"extent {extent}"
		);
	}
}

#[test]
fn managed_activation_claim_requires_every_independently_selected_role() {
	let expected = selection();
	let golden = wire();
	for (role, range, edit) in ROLES {
		let mut recorded = golden;
		recorded[range.start] ^= 1;
		reseal(&mut recorded);
		let mut alternate = expected.clone();
		edit(&mut alternate);
		assert!(
			matches!(
				match_managed_activation_claim(&golden, &alternate),
				Err(Error::SelectionMismatch)
			),
			"different expected {role}"
		);
		assert!(
			matches!(
				match_managed_activation_claim(&recorded, &expected),
				Err(Error::SelectionMismatch)
			),
			"different recorded {role}"
		);
		assert_exact(&recorded, &alternate, role);
	}
	let mut swapped = golden;
	swapped[380..412].copy_from_slice(&golden[412..444]);
	swapped[412..444].copy_from_slice(&golden[380..412]);
	reseal(&mut swapped);
	let mut alternate = expected.clone();
	std::mem::swap(&mut alternate.slot, &mut alternate.segment);
	assert!(matches!(
		match_managed_activation_claim(&swapped, &expected),
		Err(Error::SelectionMismatch)
	));
	assert_exact(&swapped, &alternate, "swapped_native_roles");
}
