use std::num::NonZeroU64;

use super::*;
use crate::workflow_sync::{
	LinuxStability, NativeObject, decode_endpoint, decode_envelope, decode_root,
	linux_stability_digest,
};

const VECTORS: &str = include_str!(concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/../../engines/exacopy-transfer/verification/sync_genesis/vectors.tsv"
));

#[test]
fn matches_independent_root_and_endpoint_envelopes_and_record_inputs() {
	for case in ["valid", "empty", "wide"] {
		let fields = vector(case);
		let timestamp = if case == "wide" {
			WorkflowTimestamp::new(i64::MIN, 999_999_999).unwrap()
		} else {
			WorkflowTimestamp::new(12, 19).unwrap()
		};
		let root_bytes = hex(fields[4]);
		let root_envelope = decode_envelope(&root_bytes).unwrap();
		let root = decode_root(root_envelope.body).unwrap();
		let encoded = encode_root_body(&root, timestamp).unwrap();
		let reference = compare(&root_bytes, &encoded, WorkflowKind::Root);
		assert_eq!(reference.digest.as_slice(), hex(fields[3]).as_slice());

		for (reference, field) in root.endpoints.into_iter().zip(&fields[5..7]) {
			let bytes = hex(field);
			let envelope = decode_envelope(&bytes).unwrap();
			let endpoint = decode_endpoint(envelope.body).unwrap();
			let encoded = encode_endpoint_body(&endpoint, timestamp).unwrap();
			assert_eq!(compare(&bytes, &encoded, WorkflowKind::Endpoint), reference);
		}
	}
}

#[test]
fn refuses_invalid_timestamp_record_ids_extents_and_reference_roles() {
	assert!(matches!(
		WorkflowTimestamp::new(0, 1_000_000_000),
		Err(WorkflowError::Shape)
	));
	let fields = vector("valid");
	let timestamp = WorkflowTimestamp::new(12, 19).unwrap();
	let bytes = hex(fields[4]);
	let mut root = decode_root(decode_envelope(&bytes).unwrap().body).unwrap();
	root.leaf.kind = WorkflowKind::Endpoint;
	assert!(matches!(
		encode_root_body(&root, timestamp),
		Err(WorkflowError::Shape)
	));
	root.leaf.kind = WorkflowKind::Leaf;
	root.leaf.byte_len = 2_049;
	assert!(matches!(
		encode_root_body(&root, timestamp),
		Err(WorkflowError::Size)
	));
	root.leaf.byte_len = 0;
	assert!(matches!(
		encode_root_body(&root, timestamp),
		Err(WorkflowError::Size)
	));
	root.leaf.byte_len = 2_048;
	assert!(encode_root_body(&root, timestamp).is_ok());
	root.id[8] = 0xff;
	assert!(matches!(
		encode_root_body(&root, timestamp),
		Err(WorkflowError::Shape)
	));

	let bytes = hex(fields[5]);
	let mut endpoint = decode_endpoint(decode_envelope(&bytes).unwrap().body).unwrap();
	endpoint.facts.max_bytes = crate::portable::MAX_LOGICAL_LENGTH + 1;
	assert!(matches!(
		encode_endpoint_body(&endpoint, timestamp),
		Err(WorkflowError::Size)
	));
	endpoint.facts.max_bytes = 0;
	assert!(encode_endpoint_body(&endpoint, timestamp).is_ok());
	endpoint.facts.location.boot = [0; 16];
	assert!(matches!(
		encode_endpoint_body(&endpoint, timestamp),
		Err(WorkflowError::Shape)
	));
}

#[test]
fn maximal_typed_location_round_trips_within_nested_cap() {
	let fields = vector("wide");
	let endpoint_bytes = hex(fields[5]);
	let mut endpoint = decode_endpoint(decode_envelope(&endpoint_bytes).unwrap().body).unwrap();
	let extreme = NativeObject {
		major: u32::MAX,
		minor: u32::MAX,
		inode: NonZeroU64::MAX,
	};
	let location = &mut endpoint.facts.location;
	location.mount_namespace = extreme;
	location.user_namespace = extreme;
	location.mount = NonZeroU64::MAX;
	location.parent = extreme;
	location.root = extreme;
	let timestamp = WorkflowTimestamp::new(i64::MAX, 999_999_999).unwrap();
	let encoded = encode_endpoint_body(&endpoint, timestamp).unwrap();
	assert_eq!(
		decode_endpoint(encoded.as_bytes()).unwrap().facts,
		endpoint.facts
	);
	let mut scratch = [0; LOCATION_BOUND];
	let nested = bounded(&mut scratch, |out| {
		write_location(out, endpoint.facts.location)
	})
	.unwrap();
	assert_eq!(nested.len(), 111);
}

#[test]
fn native_stability_matches_independent_cbor_and_detects_each_field_change() {
	let original = LinuxStability {
		file: [0x29; 32],
		length: 24,
		mode: 0o100_640,
		uid: 1_000,
		gid: 1_001,
		links: 1,
		modified: WorkflowTimestamp::new(-25, 23).unwrap(),
		changed: WorkflowTimestamp::new(25, 24).unwrap(),
	};
	let mut raw = b"ExaCopy/sync-baseline/linux-stability/v1\0".to_vec();
	raw.extend([0x88, 0x58, 0x20]);
	raw.extend([0x29; 32]);
	raw.extend([
		0x18, 24, // length
		0x19, 0x81, 0xa0, // complete regular-file mode
		0x19, 0x03, 0xe8, // uid
		0x19, 0x03, 0xe9, // gid
		0x01, // link count
		0x82, 0x38, 24, 23, // mtime
		0x82, 0x18, 25, 0x18, 24, // ctime
	]);
	let expected = *blake3::hash(&raw).as_bytes();
	assert_eq!(linux_stability_digest(original), expected);
	for changed in [
		LinuxStability {
			file: [0x28; 32],
			..original
		},
		LinuxStability {
			length: 23,
			..original
		},
		LinuxStability {
			mode: 0o640,
			..original
		},
		LinuxStability {
			uid: 1_001,
			..original
		},
		LinuxStability {
			gid: 1_000,
			..original
		},
		LinuxStability {
			links: 2,
			..original
		},
		LinuxStability {
			modified: original.changed,
			..original
		},
		LinuxStability {
			changed: original.modified,
			..original
		},
	] {
		assert_ne!(linux_stability_digest(changed), expected);
	}
}

fn compare(bytes: &[u8], encoded: &EncodedWorkflowBody, kind: WorkflowKind) -> WorkflowRef {
	let envelope = decode_envelope(bytes).unwrap();
	assert_eq!(encoded.as_bytes(), envelope.body);
	let independent_input = [
		b"ExaCopy/workflow-record/v1\0".as_slice(),
		&(kind as u16).to_le_bytes(),
		envelope.body,
	]
	.concat();
	assert_eq!(encoded.signing_input(), independent_input);
	assert_eq!(envelope.signing_input(kind), independent_input);
	let record = encoded
		.attach_signature(envelope.public_key, envelope.signature)
		.unwrap();
	assert_eq!(record.as_bytes(), bytes);
	assert_eq!(usize::from(record.reference().byte_len), bytes.len());
	assert_eq!(record.reference().kind, kind);
	assert_eq!(
		record.reference().digest,
		*blake3::hash(&independent_input).as_bytes()
	);
	record.reference()
}

fn vector(case: &str) -> Vec<&'static str> {
	let row = VECTORS
		.lines()
		.find(|line| {
			line.split_once('\t')
				.is_some_and(|(label, _)| label == case)
		})
		.unwrap();
	row.split('\t').collect()
}

fn hex(input: &str) -> Vec<u8> {
	let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}
