//! Portable controls for the signed Windows fresh-capture journal dialect.

#[path = "windows_capture/live.rs"]
mod live;
#[path = "windows_capture/wire_oracle.rs"]
mod wire_oracle;

use std::io::{self, Read};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::MAX_INTERRUPTED_RETRIES;
use exacopy_journal::frame::{FrameProblem, FrameReadError};
use exacopy_journal::windows_bootstrap::{
	self as bootstrap, WindowsBootstrapEvidence, WindowsBootstrapFileIdentity as Identity,
	WindowsBootstrapOwner, WindowsBootstrapRoles, WindowsBootstrapSelection,
};
use exacopy_journal::windows_capture::{
	CAPTURE_RANGE_BYTES, MAX_CAPTURE_RANGES, MAX_CAPTURE_SEGMENT_BYTES, MAX_PREPARED_BYTES,
	RANGE_BYTES, WindowsCaptureError as Error, WindowsCaptureRoles, WindowsCaptureSelection,
	inspect,
};
use exacopy_journal::{JournalJobId, OwnerProfileId, OwnerToken};

use wire_oracle::{
	FINAL_RANGE_HEADER_PREFIX, FIRST_RANGE_HEADER_PREFIX, MAX_PREPARED_HEADER_PREFIX,
	PREPARED_DOMAIN, PREPARED_KIND, PreparedFields, RANGE_DOMAIN, RANGE_KIND, RAW_TARGET,
	SINGLE_TARGET, range_body, signed_payload,
};

const GUID: [u8; 36] = *b"01a34567-89ab-cdef-9abc-012de3456789";
const SERIAL: u64 = 0xa181_7161_5141_3121;
const BLOCK: u64 = 67_108_864;

struct Fixture {
	key: SigningKey,
	bootstrap: WindowsBootstrapEvidence,
	roles: WindowsCaptureRoles,
}

impl Fixture {
	fn new() -> Self {
		let key = SigningKey::from_bytes(&[0x27; 32]);
		let claims = WindowsBootstrapOwner {
			profile: OwnerProfileId::from_bytes([0x62; 16]).unwrap(),
			job: JournalJobId::from_bytes([
				0x01, 0x8d, 0x45, 0xbe, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1,
			])
			.unwrap(),
			token: OwnerToken::from_bytes([0x61; 16]).unwrap(),
			roles: WindowsBootstrapRoles::new(
				identity(1),
				identity(2),
				identity(3),
				identity(4),
				identity(5),
			)
			.unwrap(),
		};
		let original = bootstrap::sign(&claims, &key).unwrap();
		assert_eq!(original.owner.len(), 342);
		assert_eq!(original.first_segment.len(), 310);
		let bootstrap = bootstrap::inspect(
			&original.owner,
			original.first_segment.as_slice(),
			&WindowsBootstrapSelection {
				profile: claims.profile,
				job: claims.job,
				key: &key.verifying_key(),
				root: identity(1),
			},
			claims.roles,
		)
		.unwrap();
		Self {
			key,
			bootstrap,
			roles: WindowsCaptureRoles {
				sibling: identity(0x91),
				stage_directory: identity(0xb2),
				stage_payload: identity(0xdf),
			},
		}
	}

	fn selection<'a>(&'a self, target: &'a [u16]) -> WindowsCaptureSelection<'a> {
		WindowsCaptureSelection {
			bootstrap: &self.bootstrap,
			sibling: self.roles.sibling,
			source_scope: [0x43; 32],
			invocation: [0x74; 32],
			generation: 0x91a2_b300_14d5_e6f7,
			epoch: 0xc1d2_e300_f415_2637,
			extent_ceiling: (4097 * BLOCK) + 7,
			target,
		}
	}

	fn fields(&self, extent: u64) -> PreparedFields {
		let selected = self.selection(&SINGLE_TARGET);
		PreparedFields {
			owner_digest: *self.bootstrap.owner_digest().as_bytes(),
			bootstrap_head_digest: self.bootstrap.boundary().head().digest(),
			sibling_id: *self.roles.sibling.file_id(),
			stage_directory_id: *self.roles.stage_directory.file_id(),
			stage_payload_id: *self.roles.stage_payload.file_id(),
			source_scope: selected.source_scope,
			grant_commitment: selected.invocation,
			generation: selected.generation,
			epoch: selected.epoch,
			extent,
		}
	}

	fn prepared(&self, target: &[u16], extent: u64) -> Vec<u8> {
		let body = self.fields(extent).body(target);
		frame(
			&signed_payload(&body, PREPARED_DOMAIN, &self.key),
			PREPARED_KIND,
			1,
			[0; 32],
		)
	}
}

fn identity(high: u8) -> Identity {
	let mut file_id = [0; 16];
	file_id[0] = 0x02;
	file_id[15] = high;
	Identity::new(GUID, SERIAL, file_id).unwrap()
}

fn frame(payload: &[u8], code: u16, sequence: u64, previous: [u8; 32]) -> Vec<u8> {
	let mut bytes = b"EXAJNL01\x01\0".to_vec();
	bytes.extend(code.to_le_bytes());
	bytes.extend(u32::try_from(payload.len()).unwrap().to_le_bytes());
	bytes.extend(sequence.to_le_bytes());
	bytes.extend(previous);
	assert_eq!(bytes.len(), 56);
	bytes.extend(payload);
	// Bitwise reflected CRC32C and independently specified envelope digest domain.
	let mut crc = !0_u32;
	for &byte in &bytes {
		crc ^= u32::from(byte);
		for _ in 0..8 {
			crc = (crc >> 1) ^ if crc & 1 == 0 { 0 } else { 0x82f6_3b78 };
		}
	}
	bytes.extend((!crc).to_le_bytes());
	let mut digest = blake3::Hasher::new();
	digest.update(b"ExaCopy/journal-record/v1\0");
	digest.update(&bytes);
	bytes.extend(digest.finalize().as_bytes());
	bytes
}

fn digest(frame: &[u8]) -> [u8; 32] {
	*frame.last_chunk::<32>().unwrap()
}

#[test]
fn independent_windows_capture_wire_requires_exact_selected_history() {
	let fixture = Fixture::new();
	let selected = fixture.selection(&RAW_TARGET);
	let prepared = fixture.prepared(&RAW_TARGET, BLOCK + 19);
	let first_digest = digest(&prepared);
	let body = range_body(first_digest, first_digest, 1, 0, BLOCK, [0x24; 32]);
	let first_range = frame(
		&signed_payload(&body, RANGE_DOMAIN, &fixture.key),
		RANGE_KIND,
		2,
		first_digest,
	);
	assert_eq!(first_range[..24], FIRST_RANGE_HEADER_PREFIX);
	let second_digest = digest(&first_range);
	let body = range_body(first_digest, second_digest, 2, BLOCK, 19, [0x25; 32]);
	let tail = frame(
		&signed_payload(&body, RANGE_DOMAIN, &fixture.key),
		RANGE_KIND,
		3,
		second_digest,
	);
	let complete = [prepared.as_slice(), &first_range, &tail].concat();
	let accepted = inspect(complete.as_slice(), &selected, fixture.roles).unwrap();
	assert_eq!(accepted.observed_extent(), BLOCK + 19);
	assert_eq!(accepted.covered_bytes(), BLOCK + 19);
	assert_eq!(accepted.ranges(), 2);
	assert_eq!(accepted.segment_end(), complete.len() as u64);
	assert_eq!(accepted.head().sequence(), 3);
	assert_eq!(accepted.head().digest(), digest(&tail));

	// A nonzero independently issued commitment must match even with the rest of the
	// source, V1 context, observed identities, target and all signatures unchanged.
	let changed = WindowsCaptureSelection {
		invocation: [0x73; 32],
		..selected
	};
	let refusal = inspect(complete.as_slice(), &changed, fixture.roles).unwrap_err();
	assert!(refusal.prefix.is_none() && matches!(refusal.source, Error::Payload));

	for offset in [0, 2, 34, 66, 97, 113, 114, 146, 178, 186, 202, 205] {
		let mut changed = fixture.fields(BLOCK + 19).body(&RAW_TARGET);
		changed[offset] ^= 1;
		let bad = frame(
			&signed_payload(&changed, PREPARED_DOMAIN, &fixture.key),
			PREPARED_KIND,
			1,
			[0; 32],
		);
		let refusal = inspect(bad.as_slice(), &selected, fixture.roles).unwrap_err();
		assert!(
			refusal.prefix.is_none() && matches!(refusal.source, Error::Payload),
			"offset {offset}"
		);
	}
	let other_key = SigningKey::from_bytes(&[0x28; 32]);
	for (domain, key) in [(RANGE_DOMAIN, &fixture.key), (PREPARED_DOMAIN, &other_key)] {
		let body = fixture.fields(0).body(&RAW_TARGET);
		let bad = frame(
			&signed_payload(&body, domain, key),
			PREPARED_KIND,
			1,
			[0; 32],
		);
		let refusal = inspect(bad.as_slice(), &selected, fixture.roles).unwrap_err();
		assert!(refusal.prefix.is_none() && matches!(refusal.source, Error::Signature));
	}
	for roles in [
		WindowsCaptureRoles {
			stage_directory: identity(4),
			..fixture.roles
		},
		WindowsCaptureRoles {
			stage_payload: fixture.roles.stage_directory,
			..fixture.roles
		},
		WindowsCaptureRoles {
			stage_payload: Identity::new(GUID, SERIAL - 1, *fixture.roles.stage_payload.file_id())
				.unwrap(),
			..fixture.roles
		},
	] {
		assert!(matches!(
			inspect(prepared.as_slice(), &selected, roles)
				.unwrap_err()
				.source,
			Error::Roles
		));
	}

	let first_two = [prepared.as_slice(), &first_range].concat();
	let expected = inspect(first_two.as_slice(), &selected, fixture.roles).unwrap();
	// Preserve the canonical range body and enclosing predecessor while changing
	// only the signature's domain or signer.
	for (domain, key) in [(PREPARED_DOMAIN, &fixture.key), (RANGE_DOMAIN, &other_key)] {
		let wrong_signature = frame(
			&signed_payload(&body, domain, key),
			RANGE_KIND,
			3,
			second_digest,
		);
		let wire = [first_two.as_slice(), &wrong_signature].concat();
		let refusal = inspect(wire.as_slice(), &selected, fixture.roles).unwrap_err();
		assert_eq!(refusal.prefix, Some(expected));
		assert!(matches!(refusal.source, Error::Signature));
	}

	let mut wrong_version = body;
	wrong_version[1] = 1;
	for invalid in [
		wrong_version,
		range_body([0xff; 32], second_digest, 2, BLOCK, 19, [0x25; 32]),
		range_body(first_digest, first_digest, 2, BLOCK, 19, [0x25; 32]),
		range_body(first_digest, second_digest, 1, BLOCK, 19, [0x25; 32]),
		range_body(first_digest, second_digest, 2, BLOCK + 1, 19, [0x25; 32]),
		range_body(first_digest, second_digest, 2, BLOCK, 18, [0x25; 32]),
		range_body(first_digest, second_digest, 2, BLOCK, 0, [0x25; 32]),
	] {
		let forged = frame(
			&signed_payload(&invalid, RANGE_DOMAIN, &fixture.key),
			RANGE_KIND,
			3,
			second_digest,
		);
		let wire = [first_two.as_slice(), &forged].concat();
		let issue = inspect(wire.as_slice(), &selected, fixture.roles).unwrap_err();
		assert_eq!(issue.prefix, Some(expected));
		assert!(matches!(issue.source, Error::Payload));
	}
	let skipped_sequence = frame(
		&signed_payload(&body, RANGE_DOMAIN, &fixture.key),
		RANGE_KIND,
		4,
		second_digest,
	);
	let skipped = [first_two.as_slice(), &skipped_sequence].concat();
	let refused = inspect(skipped.as_slice(), &selected, fixture.roles).unwrap_err();
	assert_eq!(refused.prefix, Some(expected));
	assert!(matches!(refused.source, Error::FrameBinding));

	for cut in 1..tail.len() {
		let wire = [first_two.as_slice(), &tail[..cut]].concat();
		let issue = inspect(wire.as_slice(), &selected, fixture.roles).unwrap_err();
		assert_eq!(issue.prefix, Some(expected), "cut {cut}");
		assert!(
			matches!(issue.source, Error::Read(FrameReadError::TornTail { .. })),
			"cut {cut}"
		);
	}
	let mut oversized = first_two;
	let mut length_only = tail[..56].to_vec();
	length_only[12..16].copy_from_slice(&181_u32.to_le_bytes());
	oversized.extend(length_only);
	let refused = inspect(oversized.as_slice(), &selected, fixture.roles).unwrap_err();
	assert_eq!(refused.prefix, Some(expected));
	assert!(matches!(
		refused.source,
		Error::Read(FrameReadError::Corrupt {
			problem: FrameProblem::PayloadTooLarge(181),
			..
		})
	));
}

#[test]
fn exact_range_cap_and_zero_extent_require_terminal_eof() {
	let fixture = Fixture::new();
	let target = [0x4e2d; 255];
	let selected = fixture.selection(&target);
	let extent = 4096 * BLOCK + 7;
	let mut wire = fixture.prepared(&target, extent);
	assert_eq!(wire[..24], MAX_PREPARED_HEADER_PREFIX);
	let prepared = digest(&wire);
	let mut previous = prepared;
	for ordinal in 1_u16..=4096 {
		let offset = (u64::from(ordinal) - 1) * BLOCK;
		let body = range_body(prepared, previous, ordinal, offset, BLOCK, [0x26; 32]);
		let next = frame(
			&signed_payload(&body, RANGE_DOMAIN, &fixture.key),
			RANGE_KIND,
			u64::from(ordinal) + 1,
			previous,
		);
		if ordinal == 4096 {
			assert_eq!(next[..24], FINAL_RANGE_HEADER_PREFIX);
		}
		previous = digest(&next);
		wire.extend(next);
	}
	assert_eq!(MAX_PREPARED_BYTES, wire_oracle::MAX_PREPARED_PAYLOAD);
	assert_eq!(RANGE_BYTES, wire_oracle::RANGE_PAYLOAD_BYTES);
	assert_eq!(wire.len(), wire_oracle::MAX_SEGMENT_BYTES);
	assert_eq!(MAX_CAPTURE_SEGMENT_BYTES, 1_114_982);
	assert_eq!(CAPTURE_RANGE_BYTES, BLOCK);
	assert_eq!(MAX_CAPTURE_RANGES, wire_oracle::MAX_RANGES);
	let accepted = inspect(wire.as_slice(), &selected, fixture.roles).unwrap();
	assert_eq!(accepted.covered_bytes(), extent - 7);
	assert_eq!(accepted.ranges(), 4096);
	assert_eq!(accepted.segment_end(), 1_114_982);
	assert_eq!(accepted.head().digest(), previous);
	wire.push(0);
	let refused = inspect(wire.as_slice(), &selected, fixture.roles).unwrap_err();
	assert_eq!(refused.prefix, Some(accepted));
	assert!(matches!(refused.source, Error::TrailingData));

	let zero = fixture.prepared(&SINGLE_TARGET, 0);
	let selected = fixture.selection(&SINGLE_TARGET);
	let accepted = inspect(zero.as_slice(), &selected, fixture.roles).unwrap();
	assert_eq!(accepted.ranges(), 0);
	assert_eq!(accepted.covered_bytes(), 0);
	let mut calls = 0_u8;
	let mut reader = InterruptAfter {
		input: zero.as_slice(),
		calls: &mut calls,
	};
	let refused = inspect(&mut reader, &selected, fixture.roles).unwrap_err();
	assert_eq!(refused.prefix, Some(accepted));
	assert!(
		matches!(refused.source, Error::Terminal(error) if error.kind() == io::ErrorKind::Other)
	);
	assert_eq!(calls, MAX_INTERRUPTED_RETRIES + 1);
}

struct InterruptAfter<'a> {
	input: &'a [u8],
	calls: &'a mut u8,
}

impl Read for InterruptAfter<'_> {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		if !self.input.is_empty() {
			return self.input.read(bytes);
		}
		*self.calls += 1;
		Err(io::ErrorKind::Interrupted.into())
	}
}
