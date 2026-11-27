use super::WindowsStageIdentity;
use super::native::{ObjectId, parse_volume_guid};

#[test]
fn identity_exports_normalized_guid_and_all_native_bits() {
	let path: Vec<_> = r"\\?\Volume{AaBbCcDd-EeFf-1020-3040-A1B2C3D4E5F6}\stage"
		.encode_utf16()
		.collect();
	let (volume, relative) = parse_volume_guid(&path).unwrap();
	assert!(relative.iter().copied().eq("stage".encode_utf16()));

	let observed: WindowsStageIdentity = ObjectId {
		volume,
		volume_serial: 0xFEDC_BA98_7654_3210,
		file_id: [
			0x00, 0xFF, 0x42, 0x10, 0xA1, 0xB2, 0x00, 0xDF, 0x88, 0x79, 0x6A, 0x5B, 0xC4, 0x3D,
			0x2E, 0xF1,
		],
	};
	assert_eq!(
		observed.volume_guid(),
		*b"aabbccdd-eeff-1020-3040-a1b2c3d4e5f6"
	);
	assert_eq!(observed.volume_serial(), 0xFEDC_BA98_7654_3210);
	assert_eq!(
		observed.file_id(),
		[
			0x00, 0xFF, 0x42, 0x10, 0xA1, 0xB2, 0x00, 0xDF, 0x88, 0x79, 0x6A, 0x5B, 0xC4, 0x3D,
			0x2E, 0xF1,
		]
	);
}

#[test]
fn identity_export_preserves_native_volume_zero_values() {
	let path: Vec<_> = r"\\?\Volume{00000000-0000-0000-0000-000000000000}\stage"
		.encode_utf16()
		.collect();
	let (volume, _) = parse_volume_guid(&path).unwrap();
	let observed = ObjectId {
		volume,
		volume_serial: 0,
		file_id: [0x80; 16],
	};
	assert_eq!(
		observed.volume_guid(),
		*b"00000000-0000-0000-0000-000000000000"
	);
	assert_eq!(observed.volume_serial(), 0);
	assert_eq!(observed.file_id(), [0x80; 16]);
}
