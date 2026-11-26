//! Independent workflow leaf vectors and parser refusal controls.

use core::num::NonZeroU64;

use exacopy_core::UnixComponent;
use exacopy_manifest::sync_baseline::{
	ExpectedSelection, LeafCommitment, LeafError, MAX_PAIRED_BASELINE_BYTES, PAIRED_BASELINE_KIND,
	PairedBaselineLeaf,
};

const VECTORS: &str = include_str!("../verification/sync_baseline/vectors.tsv");
const NAME: &[u8] = b"pair-\xff";

struct Vector {
	name: &'static str,
	outcome: &'static str,
	commitment: LeafCommitment,
	bytes: Vec<u8>,
}

fn vectors() -> impl Iterator<Item = Vector> {
	VECTORS.lines().skip(1).map(|line| {
		let tokens = line.split('\t').collect::<Vec<_>>();
		let [name, outcome, digest, bytes] = tokens.as_slice() else {
			panic!("independent fixture has four columns");
		};
		let bytes = unhex(bytes);
		Vector {
			name,
			outcome,
			commitment: LeafCommitment {
				digest: unhex(digest).try_into().expect("fixed 32-byte digest"),
				kind: 0x0100,
				byte_len: u32::try_from(bytes.len()).expect("fixture page is bounded"),
				item_count: 1,
			},
			bytes,
		}
	})
}

fn unhex(input: &str) -> Vec<u8> {
	assert!(
		input.len().is_multiple_of(2),
		"hex fixture has byte alignment"
	);
	(0..input.len())
		.step_by(2)
		.map(|index| u8::from_str_radix(&input[index..index + 2], 16).expect("fixture hex byte"))
		.collect()
}

fn selection(name: &[u8]) -> ExpectedSelection<'_> {
	ExpectedSelection {
		roots: [[1; 32], [2; 32]],
		name: UnixComponent::new(name).expect("fixture is a valid raw component"),
		scope_digest: [7; 32],
		policy_digest: [8; 32],
		scan: NonZeroU64::new(11).expect("fixture scan is nonzero"),
	}
}

#[test]
fn independent_workflow_baseline_vectors_bind_scope_evidence_and_canonical_bytes() {
	let mut positives = 0;
	let mut negatives = 0;
	let max_name = [b'n'; 255];
	for vector in vectors() {
		let mut expected = selection(if vector.name == "maximum_name" {
			&max_name
		} else {
			NAME
		});
		if vector.outcome == "aliased_roots" {
			expected.roots[1] = expected.roots[0];
		}
		let admitted = PairedBaselineLeaf::verify(&vector.bytes, vector.commitment, expected);
		if vector.outcome == "ok" {
			positives += 1;
			let admitted = admitted.unwrap_or_else(|err| panic!("{}: {err}", vector.name));
			assert_eq!(admitted.selection(), expected, "{}", vector.name);
			let [left, right] = admitted.sides();
			assert_eq!(left.measured.identity.root, expected.roots[0]);
			assert_eq!(right.measured.identity.root, expected.roots[1]);
			assert_eq!(left.measured.identity.file, [3; 32]);
			assert_eq!(right.measured.identity.file, [4; 32]);
			assert_eq!(left.stream_digest, right.stream_digest);
			assert_eq!(left.metadata_digest, right.metadata_digest);
			assert_eq!(left.measured.identity, left.rechecked.identity);
			assert_eq!(right.measured.identity, right.rechecked.identity);
			let length = match vector.name {
				"empty_stream_reverse_reads" => 0,
				"signed_extent_max" => i64::MAX as u64,
				_ => 18,
			};
			assert_eq!(left.length, length);
			assert_eq!(left.metadata.mode, 0o754);
			assert_eq!(left.metadata.uid, u32::MAX);
			assert_eq!(left.metadata.gid, 1024);
		} else {
			negatives += 1;
			let error = match vector.outcome {
				"canonical" => LeafError::NonCanonical,
				"encoding" => LeafError::Encoding,
				"evidence" | "aliased_roots" => LeafError::InvalidEvidence,
				"kind" => LeafError::WrongKind,
				"selection" => LeafError::SelectionMismatch,
				_ => panic!("unknown fixture outcome {}", vector.outcome),
			};
			assert_eq!(admitted, Err(error), "{}", vector.name);
		}
	}
	assert_eq!(positives, 4);
	assert_eq!(negatives, 46);
}

#[test]
fn exact_expected_reference_refuses_wrong_kind_count_length_digest_and_domain() {
	let valid = vectors().next().expect("fixture has a valid baseline");
	let reference = valid.commitment;
	let check = |commitment| PairedBaselineLeaf::verify(&valid.bytes, commitment, selection(NAME));
	assert!(check(reference).is_ok());
	for (changed, error) in [
		(
			LeafCommitment {
				kind: 6,
				..reference
			},
			LeafError::WrongKind,
		),
		(
			LeafCommitment {
				item_count: 2,
				..reference
			},
			LeafError::Commitment,
		),
		(
			LeafCommitment {
				byte_len: reference.byte_len - 1,
				..reference
			},
			LeafError::Commitment,
		),
		(
			LeafCommitment {
				digest: [0; 32],
				..reference
			},
			LeafError::Commitment,
		),
		(
			LeafCommitment {
				digest: commitment_bytes(&valid.bytes, b"ExaCopy/document-page/v1\0").digest,
				..reference
			},
			LeafError::Commitment,
		),
	] {
		assert_eq!(check(changed), Err(error));
	}
}

#[test]
fn matching_commitment_still_refuses_every_truncated_prefix_and_oversized_slice() {
	let valid = vectors().next().expect("fixture has a valid baseline");
	for length in 0..valid.bytes.len() {
		let input = &valid.bytes[..length];
		let reference = commitment_bytes(input, b"ExaCopy/workflow-page/v1\0");
		assert!(
			PairedBaselineLeaf::verify(input, reference, selection(NAME)).is_err(),
			"retained {length} bytes"
		);
	}
	let oversized = [0; MAX_PAIRED_BASELINE_BYTES + 1];
	let reference = commitment_bytes(&oversized, b"ExaCopy/workflow-page/v1\0");
	assert_eq!(
		PairedBaselineLeaf::verify(&oversized, reference, selection(NAME)),
		Err(LeafError::Size)
	);
}

fn commitment_bytes(input: &[u8], domain: &[u8]) -> LeafCommitment {
	let byte_len = u32::try_from(input.len()).expect("fixture bytes are bounded");
	let mut hasher = blake3::Hasher::new();
	hasher
		.update(domain)
		.update(&PAIRED_BASELINE_KIND.to_le_bytes())
		.update(&u64::from(byte_len).to_le_bytes())
		.update(input);
	LeafCommitment {
		digest: *hasher.finalize().as_bytes(),
		kind: PAIRED_BASELINE_KIND,
		byte_len,
		item_count: 1,
	}
}
