//! Independent wire and refusal controls for portable Windows bootstrap history.

#[path = "windows_bootstrap/fixture.rs"]
mod fixture;
#[path = "windows_bootstrap/isolation.rs"]
mod isolation;

use std::io::{Cursor, ErrorKind};

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_journal::frame::{FrameProblem, FrameReadError};
use exacopy_journal::windows_bootstrap::{
	FIRST_SEGMENT_NAME, JOURNAL_DIRECTORY_NAME, OWNER_FILE_NAME,
	WindowsBootstrapFileIdentity as Identity, WindowsBootstrapIdentityError as IdentityError,
	WindowsBootstrapInspectionError as Error, WindowsBootstrapOwner,
	WindowsBootstrapOwnerError as OwnerFailure, WindowsBootstrapRoles as Roles,
	WindowsBootstrapSelection, inspect, job_directory_name, sign,
};
use exacopy_journal::{JournalJobId, OwnerDigest, OwnerError, OwnerProfileId, OwnerToken};

use fixture::{
	BODY_KEY_START, BODY_LAYOUT, BODY_PROFILE_START, BODY_ROLES, BODY_TOKEN_START, DOMAIN,
	EndError, FRAME_PAYLOAD_END, GUID, HEADER_BYTES, JOB, OWNER_BODY, ROLE_GUID, ROLE_ID,
	ROLE_ID_STRIDE, SERIAL, frame, identity, observed, owner, owner_body, prepared, role_tuple,
	selection, signed, signing_key,
};

#[test]
fn independent_b1_and_zero_serial_oracles_match_both_signed_objects() {
	let key = signing_key();
	let public = key.verifying_key();
	for serial in [SERIAL, 0] {
		let claims = owner(serial);
		let selected = selection(&public, claims);
		let body = owner_body(serial, &public);
		let envelope = signed(&body, &key, DOMAIN, 5);
		let payload = prepared(serial, &envelope);
		let segment = frame(&payload, 1, 1, [0; 32]);
		assert_eq!(envelope.len(), 342);
		assert_eq!(payload.len(), 218);
		assert_eq!(segment.len(), 310);
		assert_eq!(
			&segment[..24],
			b"EXAJNL01\x01\x00\x01\x00\xda\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00",
		);
		let actual = sign(&claims, &key).unwrap();
		assert_eq!(actual.owner.as_slice(), envelope.as_slice());
		assert_eq!(actual.first_segment.as_slice(), segment.as_slice());
		let evidence = inspect(&envelope, segment.as_slice(), &selected, claims.roles).unwrap();
		assert_eq!(*evidence.owner(), claims);
		assert_eq!(
			evidence.owner_digest(),
			OwnerDigest::from_bytes(*blake3::hash(&envelope).as_bytes())
		);
		assert_eq!(evidence.boundary().head().sequence(), 1);
		assert_eq!(evidence.boundary().end_offset(), 310);
		assert_eq!(
			evidence.boundary().head().digest().as_slice(),
			&segment[278..]
		);
	}
	let name = job_directory_name(JournalJobId::from_bytes(JOB).unwrap());
	let expected: Vec<u16> = ".exacopy-018d45be-0000-7000-8000-000000000001"
		.encode_utf16()
		.collect();
	assert_eq!(name.as_slice(), expected.as_slice());
	for (actual, expected) in [
		(OWNER_FILE_NAME.as_slice(), "owner.cbor"),
		(JOURNAL_DIRECTORY_NAME.as_slice(), "journal"),
		(FIRST_SEGMENT_NAME.as_slice(), "00000000000000000001.exajnl"),
	] {
		assert!(actual.iter().copied().eq(expected.encode_utf16()));
	}
}

#[test]
fn independent_trust_selection_and_signature_domain_are_mandatory() {
	let signer = signing_key();
	let public = signer.verifying_key();
	let other = SigningKey::from_bytes(&[0x51; 32]).verifying_key();
	let weak = VerifyingKey::from_bytes(&[0; 32]).unwrap();
	let mut alternate_bytes = [0xff; 32];
	alternate_bytes[0] = 0xf0;
	alternate_bytes[31] = 0x7f;
	let noncanonical = VerifyingKey::from_bytes(&alternate_bytes).unwrap();
	assert!(weak.is_weak() && !noncanonical.is_weak());
	assert_ne!(
		noncanonical.to_edwards().compress().to_bytes(),
		alternate_bytes
	);
	let claims = owner(SERIAL);
	let selected = selection(&public, claims);
	let encoded = sign(&claims, &signer).unwrap();
	let mut foreign_job = JOB;
	foreign_job[15] ^= 1;
	for (trust, expected) in [
		(
			WindowsBootstrapSelection {
				key: &other,
				..selected
			},
			OwnerFailure::Owner(OwnerError::UntrustedKey),
		),
		(
			WindowsBootstrapSelection {
				key: &weak,
				..selected
			},
			OwnerFailure::Owner(OwnerError::InvalidSignature),
		),
		(
			WindowsBootstrapSelection {
				key: &noncanonical,
				..selected
			},
			OwnerFailure::Owner(OwnerError::InvalidSignature),
		),
		(
			WindowsBootstrapSelection {
				profile: OwnerProfileId::from_bytes([0x51; 16]).unwrap(),
				..selected
			},
			OwnerFailure::Owner(OwnerError::UntrustedProfile),
		),
		(
			WindowsBootstrapSelection {
				job: JournalJobId::from_bytes(foreign_job).unwrap(),
				..selected
			},
			OwnerFailure::Job,
		),
		(
			WindowsBootstrapSelection {
				root: identity(GUID, SERIAL, 0xf1),
				..selected
			},
			OwnerFailure::Root,
		),
	] {
		let error = inspect(
			&encoded.owner,
			encoded.first_segment.as_slice(),
			&trust,
			claims.roles,
		)
		.unwrap_err();
		assert!(matches!(&error, Error::Owner(actual) if *actual == expected));
		assert_eq!(error.diagnostic_prefix(), None);
	}
	let body = owner_body(SERIAL, &public);
	let other_domain = signed(&body, &signer, b"ExaCopy/owner/v1\0", 5);
	let mut wrong_copy = body.clone();
	wrong_copy[BODY_KEY_START] ^= 1;
	let wrong_copy = signed(&wrong_copy, &signer, DOMAIN, 5);
	for (bytes, expected) in [
		(other_domain, OwnerError::InvalidSignature),
		(wrong_copy, OwnerError::UntrustedKey),
	] {
		assert!(matches!(
			inspect(&bytes, encoded.first_segment.as_slice(), &selected, claims.roles),
			Err(Error::Owner(OwnerFailure::Owner(actual))) if actual == expected
		));
	}
}

#[test]
fn every_observed_role_binds_full_file_id_and_volume() {
	let signer = signing_key();
	let public = signer.verifying_key();
	let claims = owner(SERIAL);
	let selected = selection(&public, claims);
	let encoded = sign(&claims, &signer).unwrap();
	for index in 0..5 {
		let mut identities = observed(SERIAL);
		let mut changed = *identities[index].file_id();
		changed[15] ^= 0x80;
		identities[index] = Identity::new(GUID, SERIAL, changed).unwrap();
		let expected = if index == 0 {
			OwnerFailure::Root
		} else {
			OwnerFailure::Roles
		};
		assert!(matches!(
			inspect(&encoded.owner, encoded.first_segment.as_slice(), &selected, role_tuple(identities)),
			Err(Error::Owner(actual)) if actual == expected
		));
	}
	let mut swapped = observed(SERIAL);
	swapped.swap(2, 4);
	assert!(matches!(
		inspect(
			&encoded.owner,
			encoded.first_segment.as_slice(),
			&selected,
			role_tuple(swapped)
		),
		Err(Error::Owner(OwnerFailure::Roles))
	));
	let other_volume = observed(SERIAL ^ (1 << 63));
	assert!(matches!(
		inspect(
			&encoded.owner,
			encoded.first_segment.as_slice(),
			&selected,
			role_tuple(other_volume)
		),
		Err(Error::Owner(OwnerFailure::Root))
	));

	let [root, job, owner_file, journal, first] = observed(SERIAL);
	assert_eq!(
		Roles::new(root, job, owner_file, journal, root),
		Err(IdentityError::DuplicateFileId)
	);
	let wrong_serial = identity(GUID, SERIAL ^ (1 << 63), 5);
	assert_eq!(
		Roles::new(root, job, owner_file, journal, wrong_serial),
		Err(IdentityError::DifferentVolume)
	);
	let mut other_guid = GUID;
	other_guid[0] = b'a';
	let wrong_guid = identity(other_guid, SERIAL, 5);
	assert_eq!(
		Roles::new(root, job, owner_file, journal, wrong_guid),
		Err(IdentityError::DifferentVolume)
	);
	assert_eq!(first.volume_serial(), SERIAL);
	assert_eq!(
		Identity::new(GUID, 0, [0; 16]),
		Err(IdentityError::ZeroFileId)
	);
}

#[test]
fn valid_signature_does_not_admit_noncanonical_or_unsupported_owner_claims() {
	let signer = signing_key();
	let public = signer.verifying_key();
	let claims = owner(SERIAL);
	let selected = selection(&public, claims);
	let baseline = owner_body(SERIAL, &public);
	let stored = sign(&claims, &signer).unwrap();
	assert_eq!(&stored.owner[OWNER_BODY], baseline.as_slice());

	let mut invalid = Vec::new();
	for (offset, byte) in [
		(4, 2), // Format major.
		(6, 1), // Format minor.
		(8, 0), // Required field mask.
		(BODY_LAYOUT, 2),
		(BODY_ROLES, 0x9f), // Indefinite role tuple.
		(BODY_ROLES + ROLE_GUID + 10, b'A'),
		(0, 0xa8),  // Extra map entry.
		(9, 2),     // Wrong map key.
		(10, 0xd0), // Tag instead of a byte string.
	] {
		let mut changed = baseline.clone();
		changed[offset] = byte;
		invalid.push(changed);
	}
	let first_id = BODY_ROLES + ROLE_ID;
	let mut zero = baseline.clone();
	zero[first_id..first_id + 16].fill(0);
	invalid.push(zero);
	let mut duplicate = baseline.clone();
	duplicate.copy_within(first_id..first_id + 16, first_id + ROLE_ID_STRIDE);
	invalid.push(duplicate);
	let mut reused_token = baseline.clone();
	reused_token.copy_within(
		BODY_PROFILE_START..BODY_PROFILE_START + 16,
		BODY_TOKEN_START,
	);
	invalid.push(reused_token);
	let mut padded = baseline.clone();
	padded.splice(4..5, [0x18, 1]);
	invalid.push(padded);
	let mut padded_bstr = baseline.clone();
	padded_bstr.splice(10..11, [0x58, 0x10]);
	invalid.push(padded_bstr);
	for body in invalid {
		let bytes = signed(&body, &signer, DOMAIN, 5);
		let error = inspect(
			&bytes,
			stored.first_segment.as_slice(),
			&selected,
			claims.roles,
		)
		.unwrap_err();
		assert!(matches!(&error, Error::Owner(_)));
		assert_eq!(error.diagnostic_prefix(), None);
	}
	let reused_claims = WindowsBootstrapOwner {
		token: OwnerToken::from_bytes(*claims.job.as_bytes()).unwrap(),
		..claims
	};
	assert!(sign(&reused_claims, &signer).is_err());

	let mut wrong_envelope = stored.owner.to_vec();
	wrong_envelope[341] = 4;
	assert!(matches!(
		inspect(
			&wrong_envelope,
			stored.first_segment.as_slice(),
			&selected,
			claims.roles
		),
		Err(Error::Owner(OwnerFailure::Owner(OwnerError::WrongDomain)))
	));
	wrong_envelope.push(0);
	assert!(
		inspect(
			&wrong_envelope,
			stored.first_segment.as_slice(),
			&selected,
			claims.roles
		)
		.is_err()
	);
}

#[test]
fn invalid_owner_body_refuses_before_signature_verification() {
	let signer = signing_key();
	let public = signer.verifying_key();
	let claims = owner(SERIAL);
	let selected = selection(&public, claims);
	let mut reordered = owner_body(SERIAL, &public);
	let profile_key_offset = BODY_PROFILE_START - 2;
	let profile_field_bytes = 2 + claims.profile.as_bytes().len();
	let token_key_offset = BODY_TOKEN_START - 2;
	// Exchange equal-length fields while preserving the map values and fixed length.
	reordered[profile_key_offset..token_key_offset].rotate_left(profile_field_bytes);
	let mut unsupported = owner_body(SERIAL, &public);
	unsupported[8] = 2; // Unsupported required feature mask.

	let segment: &[u8] = &[];
	for (body, expected) in [
		(reordered, OwnerError::InvalidCbor),
		(unsupported, OwnerError::UnsupportedVersion),
	] {
		for domain in [DOMAIN, b"ExaCopy/owner/v1\0"] {
			let bytes = signed(&body, &signer, domain, 5);
			let error = inspect(&bytes, segment, &selected, claims.roles).unwrap_err();
			assert!(matches!(
				&error,
				Error::Owner(OwnerFailure::Owner(actual)) if *actual == expected
			));
			assert_eq!(error.diagnostic_prefix(), None);
		}
	}
}

#[test]
fn prepared_payload_and_entire_first_frame_must_match() {
	let signer = signing_key();
	let public = signer.verifying_key();
	let claims = owner(SERIAL);
	let selected = selection(&public, claims);
	let encoded = sign(&claims, &signer).unwrap();
	let payload = prepared(SERIAL, &encoded.owner);
	// Dialect, job, token, owner digest, layout, role ID.
	for offset in [10, 13, 31, 50, 83, 85 + ROLE_ID + 15] {
		let mut altered = payload.clone();
		altered[offset] ^= 1;
		let reframed = frame(&altered, 1, 1, [0; 32]);
		assert!(matches!(
			inspect(&encoded.owner, reframed.as_slice(), &selected, claims.roles),
			Err(Error::PreparedMismatch)
		));
	}
	let empty: &[u8] = &[];
	assert!(matches!(
		inspect(&encoded.owner, empty, &selected, claims.roles),
		Err(Error::MissingFirstFrame)
	));
	let mut bad_crc = encoded.first_segment;
	bad_crc[FRAME_PAYLOAD_END] ^= 1;
	let mut bad_digest = encoded.first_segment;
	bad_digest[309] ^= 1;
	let mut oversize = encoded.first_segment;
	oversize[12] = 219;
	for invalid in [
		frame(&payload, 2, 1, [0; 32]),
		frame(&payload, 1, 2, [0; 32]),
		frame(&payload, 1, 1, [1; 32]),
		bad_crc.to_vec(),
		bad_digest.to_vec(),
		oversize.to_vec(),
	] {
		let error =
			inspect(&encoded.owner, invalid.as_slice(), &selected, claims.roles).unwrap_err();
		assert_eq!(error.diagnostic_prefix(), None);
	}
	for cut in 0..encoded.first_segment.len() {
		let error = inspect(
			&encoded.owner,
			&encoded.first_segment[..cut],
			&selected,
			claims.roles,
		)
		.unwrap_err();
		assert_eq!(error.diagnostic_prefix(), None);
	}
	for cut in 0..encoded.owner.len() {
		let error = inspect(
			&encoded.owner[..cut],
			encoded.first_segment.as_slice(),
			&selected,
			claims.roles,
		)
		.unwrap_err();
		assert_eq!(error.diagnostic_prefix(), None);
	}
}

#[test]
fn terminal_io_and_suffixes_preserve_only_the_first_boundary() {
	let signer = signing_key();
	let public = signer.verifying_key();
	let claims = owner(SERIAL);
	let selected = selection(&public, claims);
	let encoded = sign(&claims, &signer).unwrap();
	let valid = inspect(
		&encoded.owner,
		encoded.first_segment.as_slice(),
		&selected,
		claims.roles,
	)
	.unwrap();
	let first = valid.boundary();
	let previous = first.head().digest();

	let failed = inspect(
		&encoded.owner,
		EndError(&encoded.first_segment),
		&selected,
		claims.roles,
	)
	.unwrap_err();
	assert!(matches!(
		&failed,
		Error::TerminalRead { source: FrameReadError::Io { offset: 310, source }, .. }
			if source.kind() == ErrorKind::Other
	));
	assert_eq!(failed.diagnostic_prefix(), Some(first));

	let trailing = [encoded.first_segment.as_slice(), b"X"].concat();
	let failed = inspect(&encoded.owner, trailing.as_slice(), &selected, claims.roles).unwrap_err();
	assert!(matches!(&failed, Error::TerminalRead { .. }));
	assert_eq!(failed.diagnostic_prefix(), Some(first));

	let zero_frame = frame(&[], 1, 2, previous);
	let extra = [encoded.first_segment.as_slice(), zero_frame.as_slice()].concat();
	let failed = inspect(&encoded.owner, extra.as_slice(), &selected, claims.roles).unwrap_err();
	assert!(matches!(&failed, Error::ExtraFrame { .. }));
	assert_eq!(failed.diagnostic_prefix(), Some(first));

	let nonzero = frame(b"ignored", 1, 2, previous);
	let bytes = [encoded.first_segment.as_slice(), nonzero.as_slice()].concat();
	let mut cursor = Cursor::new(bytes);
	let failed = inspect(&encoded.owner, &mut cursor, &selected, claims.roles).unwrap_err();
	assert!(matches!(
		&failed,
		Error::TerminalRead {
			source: FrameReadError::Corrupt {
				offset: 310,
				problem: FrameProblem::PayloadTooLarge(7),
			},
			..
		}
	));
	assert_eq!(failed.diagnostic_prefix(), Some(first));
	assert_eq!(cursor.position(), (310 + HEADER_BYTES) as u64);
}
