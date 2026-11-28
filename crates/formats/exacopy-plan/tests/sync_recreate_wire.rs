//! Independent bytes for the review-only signed recreate dialect.

use exacopy_plan::workflow_sync::recreate::{
	RecreateObservation, RecreateReason, RecreateSide, action_reference, decode_action,
	decode_parent, encode_action, encode_parent, encode_parent_envelope, observation_digests,
	parent_signing_input,
};
use exacopy_plan::workflow_sync::{MAX_MEMBER_BYTES, WorkflowError, decode_envelope};
use exacopy_plan::{PlanBody, PlanEntriesPage, UnixTimestamp};

const WIDE: &str = include_str!("sync_recreate_wire/wide.hex");
const STREAM_LIMIT: u64 = 64 * 1024 * 1024;
const MAJOR: u32 = 0xf123_4567;
const MINOR: u32 = 0xe89a_bcde;
const INODE: u64 = 0xfedc_ba98_7654_3210;

fn vector(name: &str) -> Vec<u8> {
	let (_, data) = WIDE
		.split("\n\n")
		.filter_map(|section| section.split_once('\n'))
		.find(|(label, _)| *label == name)
		.unwrap_or_else(|| panic!("missing independent fixture {name}"));
	let hex: Vec<_> = data
		.bytes()
		.filter(|byte| !byte.is_ascii_whitespace())
		.collect();
	let (pairs, remainder) = hex.as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn field<const N: usize>(name: &str) -> [u8; N] {
	vector(name).try_into().unwrap()
}

#[test]
fn signed_recreate_matches_independent_maximum_width_wire_members() {
	let parent_body = vector("parent_body");
	let parent_envelope = vector("parent_envelope");
	let action_page = vector("action_page");
	let child_body = vector("child_body");
	let child_page = vector("child_page");
	assert_eq!(
		[
			parent_body.len(),
			parent_envelope.len(),
			action_page.len(),
			child_body.len(),
			child_page.len(),
		],
		[451, 561, 494, 333, 741]
	);
	let public_octets = field::<32>("parent_public_octets");
	let signature = field::<64>("parent_signature");
	let envelope = decode_envelope(&parent_envelope).unwrap();
	assert_eq!(envelope.body, parent_body);
	assert_eq!(envelope.public_key, public_octets);
	assert_eq!(envelope.signature, signature);
	assert_eq!(
		encode_parent_envelope(&parent_body, public_octets, signature).unwrap(),
		parent_envelope,
	);
	let signing_input = parent_signing_input(&parent_body).unwrap();
	assert_eq!(signing_input, vector("parent_signing_input"));
	assert_eq!(
		*blake3::hash(&signing_input).as_bytes(),
		field::<32>("parent_digest")
	);

	let parent = decode_parent(&parent_body).unwrap();
	let action = decode_action(&action_page).unwrap();
	assert_eq!(encode_parent(&parent).unwrap(), parent_body);
	assert_eq!(encode_action(&action).unwrap(), action_page);
	let action_ref = action_reference(&action_page).unwrap();
	assert_eq!(action_ref.digest, field::<32>("action_digest"));
	assert_eq!(usize::from(action_ref.byte_len), action_page.len());
	assert_eq!(parent.action_page, action_ref);
	assert_eq!(
		parent.created_at,
		UnixTimestamp::new(281_474_976_710, 655_999_999).unwrap()
	);
	assert_eq!(
		parent.expires_at,
		UnixTimestamp::new(285_769_944_005, 655_999_999).unwrap()
	);
	assert_eq!(action.source.major, MAJOR);
	assert_eq!(action.source.minor, MINOR);
	assert_eq!(action.source.inode.get(), INODE);
	assert_eq!(action.side, RecreateSide::Right);
	assert_eq!(action.reason, RecreateReason::EditAgainstDeletion);
	assert_eq!(action.stream_length, STREAM_LIMIT);

	let subject = vector("subject");
	assert_eq!(subject.len(), 255);
	assert!(str::from_utf8(&subject).is_err());
	assert_eq!(action.name.as_bytes(), subject);
	assert_eq!(action.child_digest, field::<32>("child_digest"));
	let child = PlanBody::from_canonical_cbor(action.child_digest, &child_body).unwrap();
	let entries = PlanEntriesPage::from_canonical_cbor(action.child_page, &child_page).unwrap();
	let fields = child.fields();
	let entry = entries.entry();
	assert_eq!(child.digest(), action.child_digest);
	assert_eq!(entries.document_ref(), action.child_page);
	assert_eq!(fields.entry_pages, [action.child_page]);
	assert_eq!(fields.created_at, parent.created_at);
	assert_eq!(fields.expires_at, Some(parent.expires_at));
	assert_ne!(fields.plan_id.as_bytes(), &parent.id);
	assert!(fields.approval_required);
	assert_eq!(fields.required_grants, ["read-content", "create-new"]);
	assert_eq!(entry.source.basename, subject);
	assert_eq!(entry.destination.basename, subject);
	assert_ne!(entry.source.root_id, entry.destination.root_id);
	assert_eq!(entry.stream_length, STREAM_LIMIT);
	assert_eq!(entry.stream_digest, action.stream_digest);
	assert_eq!(
		entry.source_identity.unwrap().object_id,
		INODE.to_le_bytes()
	);
}

#[test]
fn ordered_coverage_matches_independent_preimages_and_binds_selected_inputs() {
	let parent = decode_parent(&vector("parent_body")).unwrap();
	let context = RecreateObservation {
		pair_id: parent.pair_id,
		predecessor_pair: [0x76; 32],
		endpoints: parent.endpoints,
		predecessor: parent.predecessor,
		scope: [0x87; 32],
		policy_pin: [0x98; 32],
		action_page: parent.action_page,
	};
	let expected = [field::<32>("coverage_left"), field::<32>("coverage_right")];
	assert_ne!(expected[0], expected[1]);
	for (name, digest) in ["coverage_left_input", "coverage_right_input"]
		.into_iter()
		.zip(expected)
	{
		assert_eq!(*blake3::hash(&vector(name)).as_bytes(), digest);
	}
	assert_eq!(parent.coverage, expected);
	assert_eq!(observation_digests(&context).unwrap(), expected);

	let mut alternate_pair = context.pair_id;
	alternate_pair[15] ^= 0x01;
	for substitution in [
		RecreateObservation {
			pair_id: alternate_pair,
			..context
		},
		RecreateObservation {
			predecessor_pair: [0x77; 32],
			..context
		},
		RecreateObservation {
			endpoints: [context.endpoints[1], context.endpoints[0]],
			..context
		},
		RecreateObservation {
			predecessor: exacopy_plan::workflow_sync::WorkflowRef {
				digest: [0x66; 32],
				..context.predecessor
			},
			..context
		},
		RecreateObservation {
			action_page: exacopy_plan::workflow_sync::recreate::RecreateActionRef {
				digest: [0xad; 32],
				..context.action_page
			},
			..context
		},
		RecreateObservation {
			scope: [0x88; 32],
			..context
		},
		RecreateObservation {
			policy_pin: [0x99; 32],
			..context
		},
	] {
		let observed = observation_digests(&substitution).unwrap();
		assert_ne!(observed[0], expected[0]);
		assert_ne!(observed[1], expected[1]);
	}
}

#[test]
fn parent_refuses_authority_and_noncanonical_reference_shapes() {
	let canonical = vector("parent_body");
	let parent = decode_parent(&canonical).unwrap();
	let mut invalid_version = parent.pair_id;
	invalid_version[6] ^= 0x30;
	let mut invalid_variant = parent.pair_id;
	invalid_variant[8] ^= 0x80;
	let pair_field = [&[0x50][..], &parent.pair_id].concat();
	let variants = [
		(
			"pair has wrong UUID version",
			replace(
				&canonical,
				&pair_field,
				&[&[0x50][..], &invalid_version].concat(),
			),
		),
		(
			"pair has wrong UUID variant",
			replace(
				&canonical,
				&pair_field,
				&[&[0x50][..], &invalid_variant].concat(),
			),
		),
		(
			"substituted bytes32 for pair UUID",
			replace(
				&canonical,
				&pair_field,
				&[&[0x58, 0x20][..], &[0x76; 32]].concat(),
			),
		),
		(
			"unknown required feature",
			replace(
				&canonical,
				&[0xa3, 0, 1, 1, 0, 2, 0x18, 69],
				&[0xa3, 0, 1, 1, 0, 2, 0x18, 197],
			),
		),
		(
			"missing right coverage",
			replace(
				&canonical,
				&[7, 0x82, 0xa3, 0, 0xf5],
				&[7, 0x81, 0xa3, 0, 0xf5],
			),
		),
		(
			"action reference replaces required array",
			replace(
				&canonical,
				&[8, 0x81, 0xa4, 0, 0x58, 0x20],
				&[8, 0xa4, 0, 0x58, 0x20],
			),
		),
		(
			"delegated grant",
			replace(
				&canonical,
				&[9, 1, 10, 0, 11, 0x80, 12, 0xf5],
				&[9, 1, 10, 0, 11, 0x81, 0xf6, 12, 0xf5],
			),
		),
		(
			"approval not required",
			replace(
				&canonical,
				&[9, 1, 10, 0, 11, 0x80, 12, 0xf5],
				&[9, 1, 10, 0, 11, 0x80, 12, 0xf4],
			),
		),
		(
			"duplicate numeric key",
			replace(
				&canonical,
				&[9, 1, 10, 0, 11, 0x80, 12, 0xf5],
				&[9, 1, 9, 0, 11, 0x80, 12, 0xf5],
			),
		),
		(
			"nonpreferred body-map length",
			[&[0xb8, 8][..], &canonical[1..]].concat(),
		),
		(
			"indefinite body map",
			[&[0xbf][..], &canonical[1..], &[0xff]].concat(),
		),
		("trailing bytes", [&canonical[..], &[0]].concat()),
	];
	for (name, sealed_body) in variants {
		assert!(decode_parent(&sealed_body).is_err(), "{name}");
	}
	assert!(matches!(
		decode_parent(&vec![0; MAX_MEMBER_BYTES + 1]),
		Err(WorkflowError::Size)
	));
}

#[test]
fn action_refuses_unsafe_components_unbounded_native_values_and_grants() {
	let canonical = vector("action_page");
	let subject = vector("subject");
	let name_field = [&[0x58, 0xff][..], &subject].concat();
	let oversize = [&[0x59, 1, 0][..], &subject, b"x"].concat();
	for component in [
		&[0x40][..],
		&[0x41, b'.'],
		&[0x42, b'.', b'.'],
		&[0x42, b'/', b'x'],
		&[0x41, 0],
		&oversize,
	] {
		assert!(decode_action(&replace(&canonical, &name_field, component)).is_err());
	}

	let major_field = [&[0x1a][..], &MAJOR.to_be_bytes()].concat();
	let wide_major = [0x1b, 0, 0, 0, 1, 0, 0, 0, 0];
	let inode_field = [&[0x1b][..], &INODE.to_be_bytes()].concat();
	let variants: [(&str, &[u8], &[u8]); 6] = [
		("major above u32", &major_field, &wide_major),
		("zero inode", &inode_field, &[0]),
		(
			"extent above the managed profile",
			&[8, 0xa4, 0, 0x1a, 4, 0, 0, 0],
			&[8, 0xa4, 0, 0x1a, 4, 0, 0, 1],
		),
		(
			"delegated grant",
			&[10, 0xf6, 11, 1, 12, 0, 4, 0x80],
			&[10, 0x41, 0, 11, 1, 12, 0, 4, 0x80],
		),
		(
			"other receipt type",
			&[10, 0xf6, 11, 1, 12, 0, 4, 0x80],
			&[10, 0xf6, 11, 1, 12, 1, 4, 0x80],
		),
		(
			"nonpreferred receipt code",
			&[10, 0xf6, 11, 1, 12, 0, 4, 0x80],
			&[10, 0xf6, 11, 1, 12, 0x18, 0, 4, 0x80],
		),
	];
	for (name, from, to) in variants {
		assert!(
			decode_action(&replace(&canonical, from, to)).is_err(),
			"{name}"
		);
	}
	assert!(matches!(
		decode_action(&vec![0; MAX_MEMBER_BYTES + 1]),
		Err(WorkflowError::Size)
	));
}

fn replace(item: &[u8], field: &[u8], new_field: &[u8]) -> Vec<u8> {
	let mut offsets = item
		.windows(field.len())
		.enumerate()
		.filter_map(|(offset, bytes)| (bytes == field).then_some(offset));
	let offset = offsets.next().expect("independent wire field");
	assert!(offsets.next().is_none(), "fixture field must occur once");
	[&item[..offset], new_field, &item[offset + field.len()..]].concat()
}
