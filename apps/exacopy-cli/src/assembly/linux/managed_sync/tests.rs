use super::*;

#[test]
fn independently_retained_public_key_must_identify_the_ordinary_owner() {
	let owner = SigningKey::from_bytes(&[7; ed25519_dalek::SECRET_KEY_LENGTH]).verifying_key();
	let identity = ManagedPolicyIdentity {
		selection_id: [8; 16],
		revision: NonZeroU64::MIN,
		owner_profile: *profile_id_for_key(&owner).unwrap().as_bytes(),
		owner_key: owner.to_bytes(),
	};
	assert_eq!(verify_owner_identity(&identity).unwrap(), owner);

	let foreign = SigningKey::from_bytes(&[9; ed25519_dalek::SECRET_KEY_LENGTH]).verifying_key();
	assert!(matches!(
		verify_owner_identity(&ManagedPolicyIdentity {
			owner_key: foreign.to_bytes(),
			..identity
		}),
		Err(ManagedSyncPreviewError::Selection)
	));

	// A weak key does not become acceptable by supplying its matching ID.
	let weak = VerifyingKey::from_bytes(&[0; 32]).unwrap();
	assert!(weak.is_weak());
	assert!(matches!(
		verify_owner_identity(&ManagedPolicyIdentity {
			owner_key: weak.to_bytes(),
			owner_profile: *profile_id_for_key(&weak).unwrap().as_bytes(),
			..identity
		}),
		Err(ManagedSyncPreviewError::Selection)
	));
}
