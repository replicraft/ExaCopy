use std::ffi::OsStr;
use std::fmt::Write as _;

use super::*;

const DEVICE: u64 = 0x0123_4567_89ab_cdef;
const INODE: u64 = 0x1020_3040_5060_7080;
const REVISION: u64 = 0x1122_3344_5566_7788;

#[test]
fn exact_payload_and_signature_match_an_independent_layout() {
	let (signer, pin, path) = fixture();
	let (_, actual) = issue(&signer, &pin, path);
	let mut expected = vec![1];
	expected.extend([0xa1; 16]);
	expected.extend(REVISION.to_be_bytes());
	expected.extend(pin.identity.owner_profile);
	expected.extend(signer.verifying_key().to_bytes());
	expected.extend([1, 35, 69, 103, 137, 171, 205, 239]);
	expected.extend(INODE.to_be_bytes());
	expected.extend(path);
	expected.extend([0xd2; 32]);
	assert_eq!(expected.len(), 153);
	let message = [
		b"ExaCopy local managed sync Init ack v1\0".as_slice(),
		&expected,
	]
	.concat();
	expected.extend(signer.sign(&message).to_bytes());
	let mut hex = String::with_capacity(435);
	for byte in expected {
		write!(hex, "{byte:02x}").unwrap();
	}
	hex.push('\n');
	assert_eq!(actual.len(), 435);
	assert_eq!(actual.as_slice(), hex.as_bytes());
	let result = verify(
		&actual,
		&signer.verifying_key(),
		path,
		pin.identity.selection_id,
	)
	.unwrap();
	assert_eq!(result.pin(), pin);
	assert_eq!(result.device(), DEVICE);
	assert_eq!(result.inode().get(), INODE);
}

#[test]
fn independent_owner_path_and_selection_must_agree() {
	let (signer, pin, path) = fixture();
	let (owner, actual) = issue(&signer, &pin, path);
	let id = pin.identity.selection_id;
	let other = SigningKey::from_bytes(&[0x13; 32]).verifying_key();
	assert_eq!(
		verify(&actual, &other, path, id).unwrap_err(),
		ManagedAckError::Owner
	);
	assert_eq!(
		verify(&actual, &owner, [0xbd; 32], id).unwrap_err(),
		ManagedAckError::Path
	);
	assert_eq!(
		verify(&actual, &owner, path, [0x14; 16]).unwrap_err(),
		ManagedAckError::Selection
	);
	let weak = VerifyingKey::from_bytes(&[0; 32]).unwrap();
	assert!(weak.is_weak());
	assert_eq!(
		verify(&actual, &weak, path, id).unwrap_err(),
		ManagedAckError::Owner
	);

	let mut wrong_profile = pin;
	wrong_profile.identity.owner_profile = [0x67; 16];
	assert_eq!(
		sign_identity(&wrong_profile, DEVICE, nonzero(INODE), path, &signer).unwrap_err(),
		ManagedAckError::Owner
	);
	let mut wrong_key = pin;
	wrong_key.identity.owner_key = other.to_bytes();
	assert_eq!(
		sign_identity(&wrong_key, DEVICE, nonzero(INODE), path, &signer).unwrap_err(),
		ManagedAckError::Owner
	);
}

#[test]
fn rejects_changed_signed_fields_and_noncanonical_transport() {
	let (signer, pin, path) = fixture();
	let (owner, actual) = issue(&signer, &pin, path);
	let verify = |bytes: &[u8]| super::verify(bytes, &owner, path, pin.identity.selection_id);
	for offset in [17, 73, 81, 121, 153] {
		let mut changed = actual;
		changed[offset * 2] = if changed[offset * 2] == b'9' {
			b'8'
		} else {
			b'9'
		};
		assert_eq!(verify(&changed).unwrap_err(), ManagedAckError::Signature);
	}
	let mut version = actual;
	version[1] = b'2';
	let mut upper = actual;
	upper[2] = b'A';
	let mut trailing = actual.to_vec();
	trailing.push(b'\n');
	let mut crlf = actual.to_vec();
	crlf.insert(434, b'\r');
	for invalid in [
		&actual[..434],
		&actual[..433],
		&trailing,
		&crlf,
		&version,
		&upper,
	] {
		assert_eq!(verify(invalid).unwrap_err(), ManagedAckError::Encoding);
	}
	for range in [2..34, 34..50, 162..178] {
		let mut changed = actual;
		changed[range].fill(b'0');
		assert_eq!(verify(&changed).unwrap_err(), ManagedAckError::Selection);
	}
}

#[test]
fn native_device_zero_and_full_width_inode_remain_valid_expectations() {
	let (signer, pin, path) = fixture();
	let ack = sign_identity(&pin, 0, nonzero(u64::MAX), path, &signer).unwrap();
	let verified = verify(
		&ack,
		&signer.verifying_key(),
		path,
		pin.identity.selection_id,
	)
	.unwrap();
	assert_eq!(verified.device(), 0);
	assert_eq!(verified.inode().get(), u64::MAX);
}

#[test]
fn path_hash_uses_exact_raw_absolute_components() {
	let raw = b"/home/\xff-profile";
	let path = Path::new(OsStr::from_bytes(raw));
	assert_eq!(
		profile_path_digest(path).unwrap(),
		blake3::derive_key("ExaCopy local managed sync Init profile path v1", raw)
	);
	let over_components = "/a".repeat(65);
	let over_bytes = ["/", &"a".repeat(255)].concat().repeat(16);
	let over_name = format!("/x/{}", "a".repeat(256));
	for invalid in [
		"relative/profile",
		"/",
		"/profile",
		"//home/profile",
		"/home//profile",
		"/home/./profile",
		"/home/../profile",
		"/home/profile/",
		"/home/pro\0file",
		&over_components,
		&over_bytes,
		&over_name,
	] {
		assert_eq!(
			profile_path_digest(Path::new(invalid)),
			Err(ManagedAckError::Path)
		);
	}
	assert!(profile_path_digest(Path::new(&"/a".repeat(64))).is_ok());
}

fn fixture() -> (SigningKey, ManagedPolicyPin, [u8; 32]) {
	let signer = SigningKey::from_bytes(&[0x37; 32]);
	let owner = signer.verifying_key();
	let pin = ManagedPolicyPin {
		identity: ManagedPolicyIdentity {
			selection_id: [0xa1; 16],
			revision: nonzero(REVISION),
			owner_profile: *profile_id_for_key(&owner).unwrap().as_bytes(),
			owner_key: owner.to_bytes(),
		},
		digest: [0xd2; 32],
	};
	let path = profile_path_digest(Path::new("/managed/profile")).unwrap();
	(signer, pin, path)
}

fn issue(
	signer: &SigningKey,
	pin: &ManagedPolicyPin,
	path: [u8; 32],
) -> (VerifyingKey, [u8; MANAGED_ACK_BYTES]) {
	let bytes = sign_identity(pin, DEVICE, nonzero(INODE), path, signer).unwrap();
	(signer.verifying_key(), bytes)
}

fn nonzero(value: u64) -> NonZeroU64 {
	NonZeroU64::new(value).unwrap()
}
