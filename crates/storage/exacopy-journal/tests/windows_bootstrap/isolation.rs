#[path = "../darwin_prepared/golden.rs"]
mod darwin_golden;

use std::num::{NonZeroU32, NonZeroU64};

use exacopy_journal::windows_bootstrap::{
	WindowsBootstrapInspectionError, WindowsBootstrapOwnerError, inspect, sign,
};
use exacopy_journal::{
	DarwinEntryPrepared, DarwinFileIdentity, DarwinJobPrepared, DarwinOwnerManifest,
	DarwinOwnerRecord, DarwinVolumeIdentity, JobPrepared, LinuxFileIdentity, OwnerError,
	OwnerManifest, OwnerRecord, OwnerStateDirectory, OwnerTimestamp, PlanDigest,
};

use super::fixture::{SERIAL, frame, owner, prepared, selection, signing_key};

fn hex(text: &str) -> Vec<u8> {
	let (pairs, tail) = text.as_bytes().as_chunks::<2>();
	assert!(tail.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

#[test]
fn old_owner_and_prepared_dialects_refuse_windows_and_vice_versa() {
	let signer = signing_key();
	let public = signer.verifying_key();
	let claims = owner(SERIAL);
	let selected = selection(&public, claims);
	let windows = sign(&claims, &signer).unwrap();
	assert_eq!(
		OwnerRecord::decode(&windows.owner, claims.profile, &public),
		Err(OwnerError::WrongDomain),
	);
	assert_eq!(
		DarwinOwnerRecord::decode(&windows.owner, claims.profile, &public),
		Err(OwnerError::WrongDomain),
	);
	let when = OwnerTimestamp::new(1, 0).unwrap();
	let linux = OwnerRecord::sign(
		OwnerManifest {
			token: claims.token,
			job: claims.job,
			profile: claims.profile,
			created: when,
			destination_device: 7,
			state_root: LinuxFileIdentity::new(7, 9),
			plan_digest: PlanDigest::from_bytes([0x33; 32]),
			directories: vec![OwnerStateDirectory::Journal, OwnerStateDirectory::Stage],
		},
		&signer,
	)
	.unwrap();
	let volume = DarwinVolumeIdentity::new(-2, [1234, 26]).unwrap();
	let darwin = DarwinOwnerRecord::sign(
		DarwinOwnerManifest {
			token: claims.token,
			job: claims.job,
			profile: claims.profile,
			created: when,
			destination_volume: volume,
			state_root: DarwinFileIdentity::new(volume, NonZeroU64::MIN, None, when),
			state_root_uid: NonZeroU32::new(501).unwrap(),
			plan_digest: PlanDigest::from_bytes([0x33; 32]),
		},
		&signer,
	)
	.unwrap();
	assert_eq!(
		OwnerRecord::decode(linux.as_bytes(), claims.profile, &public).unwrap(),
		linux
	);
	assert_eq!(
		DarwinOwnerRecord::decode(darwin.as_bytes(), claims.profile, &public).unwrap(),
		darwin
	);
	for old in [linux.as_bytes(), darwin.as_bytes()] {
		assert!(matches!(
			inspect(
				old,
				windows.first_segment.as_slice(),
				&selected,
				claims.roles
			),
			Err(WindowsBootstrapInspectionError::Owner(
				WindowsBootstrapOwnerError::Owner(OwnerError::Length | OwnerError::WrongDomain,)
			))
		));
	}

	let payload = prepared(SERIAL, &windows.owner);
	assert!(JobPrepared::decode(&payload).is_err());
	assert!(DarwinJobPrepared::decode(&payload).is_err());
	let linux_payload = hex(LINUX_PREPARED);
	let darwin_payload = hex(darwin_golden::JOB_HEX);
	assert!(JobPrepared::decode(&linux_payload).is_ok());
	assert!(DarwinJobPrepared::decode(&darwin_payload).is_ok());
	assert!(DarwinEntryPrepared::decode(&hex(darwin_golden::ENTRY_HEX)).is_ok());
	for old in [linux_payload, darwin_payload] {
		let segment = frame(&old, 1, 1, [0; 32]);
		assert!(matches!(
			inspect(&windows.owner, segment.as_slice(), &selected, claims.roles),
			Err(WindowsBootstrapInspectionError::PreparedMismatch)
		));
	}
}

// Existing independent local v1 prepared specimen, from tests/prepared.rs.
const LINUX_PREPARED: &str = concat!(
	"a600a300010100020001500182797455907a1488889c8407c718ca021818055820",
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	"06000aa3005820202122232425262728292a2b2c2d2e2f303132333435363738",
	"393a3b3c3d3e3f015820000102030405060708090a0b0c0d0e0f101112131415",
	"161718191a1b1c1d1e1f02a2005011223344556647778899aabbccddeeff01a4",
	"0001014808070605040302010248887766554433221103f6",
);
