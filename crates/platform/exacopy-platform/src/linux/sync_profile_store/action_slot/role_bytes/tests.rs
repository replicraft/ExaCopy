use super::{PreparedActionRoleBytes, RoleInput, UnixComponent};

const FIXTURES: &str = include_str!(concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/verification/managed_action_roles/preimages.tsv",
));

fn selected(name: &[u8]) -> RoleInput<'_> {
	RoleInput {
		boot: [
			0xd6, 0xcb, 0x1b, 0xa8, 0x74, 0x52, 0x4b, 0xf4, 0x81, 0xdc, 0x5a, 0xbf, 0xa1, 0x87,
			0xe7, 0xda,
		],
		namespaces: [
			[0x0102_0304_0506_0708, 0x1122_3344_5566_7788],
			[0x2122_2324_2526_2728, 0x3132_3334_3536_3738],
		],
		mounts: [0x4142_4344_4546_4748, 0x5152_5354_5556_5758],
		actor: [0x6162_6364, 0x7172_7374],
		profile: [0x8182_8384_8586_8788, 0xa1a2_a3a4_a5a6_a7a8],
		slot: [0x8182_8384_8586_8788, 0xb1b2_b3b4_b5b6_b7b8],
		name: UnixComponent::new(name).unwrap(),
		segment: [0x8182_8384_8586_8788, 0xc1c2_c3c4_c5c6_c7c8],
	}
}

fn assert_exact(case: &str, bytes: &PreparedActionRoleBytes) {
	let row = FIXTURES
		.lines()
		.find_map(|line| {
			let (name, value) = line.split_once('\t').unwrap();
			(name == case).then_some(value)
		})
		.unwrap();
	let (slot, segment) = row.split_once('\t').unwrap();
	assert_bytes(bytes.slot(), slot);
	assert_bytes(bytes.segment(), segment);
}

fn assert_bytes(actual: &[u8], expected: &str) {
	assert_eq!(2 * actual.len(), expected.len());
	let (pairs, remainder) = expected.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	for (value, expected) in actual.iter().zip(pairs) {
		let pair = std::str::from_utf8(expected).unwrap();
		assert_eq!(*value, u8::from_str_radix(pair, 16).unwrap());
	}
}

#[test]
fn role_bytes_match_independent_raw_component_bounds() {
	let mut maximum = [0xfe; 255];
	maximum[254] = 0x80;
	for (case, raw, slot_bytes, segment_bytes) in [
		("raw_name", b"\xfeaction\x80".as_slice(), 113, 156),
		("minimum_name", b"x".as_slice(), 106, 149),
		("maximum_name", maximum.as_slice(), 360, 403),
	] {
		let encoded = selected(raw).encode();
		assert_eq!(encoded.slot().len(), slot_bytes);
		assert_eq!(encoded.segment().len(), segment_bytes);
		assert_exact(case, &encoded);
	}
}

#[test]
fn role_bytes_bind_namespace_order_and_independent_segment_identity() {
	let name = b"\xfeaction\x80";
	let original = selected(name).encode();
	let mut replaced = selected(name);
	replaced.segment[1] ^= 1;
	let encoded = replaced.encode();
	assert_eq!(original.slot(), encoded.slot());
	assert_ne!(original.segment(), encoded.segment());
	assert_exact("replacement_segment", &encoded);

	let mut swapped = selected(name);
	swapped.namespaces.swap(0, 1);
	let encoded = swapped.encode();
	assert_ne!(original.slot(), encoded.slot());
	assert_ne!(original.segment(), encoded.segment());
	assert_exact("swapped_namespaces", &encoded);
}
