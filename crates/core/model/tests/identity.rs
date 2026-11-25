//! Tests for the public job identifier boundary.

use exacopy_model::{InvalidJobId, JobId};

const RFC_UUID_V7: [u8; 16] = [
	0x01, 0x8f, 0x23, 0x45, 0x67, 0x89, 0x7a, 0xbc, 0xa2, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
];
const VERSION_OCTET: usize = 6;
const VARIANT_OCTET: usize = 8;

#[test]
fn accepts_rfc_uuid_v7_as_job_id() {
	let result = JobId::try_from_bytes(RFC_UUID_V7);
	assert!(
		result.is_ok(),
		"RFC UUIDv7 fixture was rejected: {result:?}"
	);
}

#[test]
fn rejects_other_uuid_variants_with_the_v7_version_nibble() {
	const NCS_VARIANT: u8 = 0x62;
	const MICROSOFT_VARIANT: u8 = 0xc2;
	const RESERVED_VARIANT: u8 = 0xe2;
	for variant in [NCS_VARIANT, MICROSOFT_VARIANT, RESERVED_VARIANT] {
		let mut bytes = RFC_UUID_V7;
		bytes[VARIANT_OCTET] = variant;
		assert_eq!(
			JobId::try_from_bytes(bytes),
			Err(InvalidJobId),
			"variant octet {variant:#04x}"
		);
	}
}

#[test]
fn rejects_other_uuid_versions_with_the_rfc_variant() {
	const VERSION_4: u8 = 0x4a;
	const VERSION_6: u8 = 0x6a;
	const VERSION_8: u8 = 0x8a;
	for version in [VERSION_4, VERSION_6, VERSION_8] {
		let mut bytes = RFC_UUID_V7;
		bytes[VERSION_OCTET] = version;
		assert_eq!(
			JobId::try_from_bytes(bytes),
			Err(InvalidJobId),
			"version octet {version:#04x}"
		);
	}
}
