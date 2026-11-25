use std::num::NonZeroU32;

use exacopy_journal::{DarwinOwnerRecord, DarwinVolumeIdentity, OwnerError};

use super::{
	DARWIN_UID_MAX, ROOT_DEVICE_BYTES, UID, VOLUME_DEVICE_BYTES, body, decode, manifest,
	signed_body, signing_key,
};

#[test]
fn root_and_out_of_range_uids_are_refused() {
	let mut claims = manifest();
	for uid in [1, DARWIN_UID_MAX] {
		claims.state_root_uid = NonZeroU32::new(uid).unwrap();
		let record = DarwinOwnerRecord::sign(claims.clone(), &signing_key()).unwrap();
		assert_eq!(decode(record.as_bytes()), Ok(record));
	}
	for uid in [DARWIN_UID_MAX + 1, u32::MAX] {
		claims.state_root_uid = NonZeroU32::new(uid).unwrap();
		assert_eq!(
			DarwinOwnerRecord::sign(claims.clone(), &signing_key()),
			Err(OwnerError::InvalidOwnerUid)
		);
		let mut signed = body();
		signed.splice(UID.., [0x1a].into_iter().chain(uid.to_be_bytes()));
		assert_eq!(
			decode(&signed_body(&signed)),
			Err(OwnerError::InvalidOwnerUid)
		);
	}
	let mut signed = body();
	signed.splice(UID.., [0]);
	assert_eq!(
		decode(&signed_body(&signed)),
		Err(OwnerError::InvalidOwnerUid)
	);
}

#[test]
fn matching_nodev_fields_do_not_supply_volume_identity() {
	const NODEV: i32 = -1;
	assert_eq!(
		DarwinVolumeIdentity::new(NODEV, [1234, 26]),
		Err(OwnerError::UnsupportedIdentity)
	);
	let mut invalid = body();
	for start in [VOLUME_DEVICE_BYTES, ROOT_DEVICE_BYTES] {
		invalid[start..start + 4].copy_from_slice(&NODEV.to_le_bytes());
	}
	assert_eq!(
		decode(&signed_body(&invalid)),
		Err(OwnerError::UnsupportedIdentity)
	);
}
