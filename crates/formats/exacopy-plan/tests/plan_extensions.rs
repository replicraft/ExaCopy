//! Canonical opaque Plan extension admission and complete-body capacity.

use exacopy_plan::{MAX_PLAN_BODY_BYTES, PlanBody, PlanError, PlanExtensions};
use minicbor::Encoder;

const BODY: &[u8] = include_bytes!("../verification/plan_body/vectors/incomplete-empty.body.cbor");
const DIGEST: [u8; 32] =
	*include_bytes!("../verification/plan_body/vectors/incomplete-empty.digest");

fn assert_extension_error(input: &[u8], expected: PlanError) {
	assert!(matches!(PlanExtensions::from_canonical_cbor(input), Err(error) if error == expected));
}

#[test]
fn opaque_values_are_exact_and_only_the_declared_grammar_is_supported() {
	let canonical = b"\xa1\x63a.b\x83\xf6\xf5\x20";
	let accepted = PlanExtensions::from_canonical_cbor(canonical).unwrap();
	assert_eq!(accepted.as_canonical_cbor(), canonical);
	for unsupported in [
		&b"\xa1\x63a.b\x40"[..],         // Bytes.
		&b"\xa1\x63a.b\xf9\x00\x00"[..], // Float.
		&b"\xa1\x63a.b\xc0\xf6"[..],     // Tag.
		&b"\xa1\x63abc\xf6"[..],         // Unqualified name.
		&b"\xa1\x63A.b\xf6"[..],         // Uppercase top-level key.
	] {
		assert_extension_error(unsupported, PlanError::Unsupported);
	}
	for noncanonical in [
		&b"\xa2\x63a.b\xf6\x63a.b\xf6"[..], // Duplicate key.
		&b"\xa2\x63z.b\xf6\x63a.b\xf6"[..], // Unsorted key.
		&b"\xa1\x63a.b\x18\x00"[..],        // Overlong positive integer.
		&b"\xa1\x63a.b\x38\x00"[..],        // Overlong negative integer.
		&b"\xa1\x63a.b\x7f\xff"[..],        // Indefinite text.
		&b"\xa1\x63a.b\x9f\xff"[..],        // Indefinite array.
		&b"\xa1\x63a.b\xbf\xff"[..],        // Indefinite map.
		&b"\xa1\x63a.b\xf6\x00"[..],        // Trailing bytes.
	] {
		assert_extension_error(noncanonical, PlanError::NonCanonical);
	}

	assert_extension_error(b"\xa1\x63a.b\x61\xff", PlanError::Malformed);
	assert_extension_error(b"\xa1\x64a..b\xf6", PlanError::Unsupported);
	for integer in [b"\x18\x18".as_slice(), b"\x19\x01\x00", b"\x39\x01\x00"] {
		let mut extension = b"\xa1\x63a.b".to_vec();
		extension.extend_from_slice(integer);
		assert!(PlanExtensions::from_canonical_cbor(&extension).is_ok());
	}
}

#[test]
fn excessive_declared_sizes_and_container_depth_are_rejected() {
	for excessive in [
		&b"\xb1"[..],                    // 17 top-level fields.
		&b"\xa1\x63a.b\xb8\x41"[..],     // 65 nested fields.
		&b"\xa1\x63a.b\x99\x10\x01"[..], // 4097 items.
	] {
		assert_extension_error(excessive, PlanError::Bounds);
	}
	let mut nested = b"\xa1\x63a.b".to_vec();
	nested.extend([0x81; 30]);
	nested.push(0xf6);
	assert!(PlanExtensions::from_canonical_cbor(&nested).is_ok());
	nested.insert(nested.len() - 1, 0x81);
	assert_extension_error(&nested, PlanError::Bounds);
	let last_container = nested.len() - 2;
	nested[last_container] = 0xa0;
	assert_extension_error(&nested, PlanError::Bounds);
	assert_extension_error(&vec![0; MAX_PLAN_BODY_BYTES + 1], PlanError::Size);
}

fn extension_with_text(length: usize) -> Vec<u8> {
	let text = "x".repeat(length);
	let mut bytes = vec![0; length + 10];
	let mut encoder = Encoder::new(&mut bytes[..]);
	encoder
		.map(1)
		.unwrap()
		.str("a.b")
		.unwrap()
		.str(&text)
		.unwrap();
	bytes
}

#[test]
fn complete_body_byte_limit_applies_to_input_and_construction() {
	let empty = PlanBody::from_canonical_cbor(DIGEST, BODY).unwrap();
	// A one-item map adds its header, key and a five-byte text header.
	let exact_payload = MAX_PLAN_BODY_BYTES - (BODY.len() - 1) - 10;
	let at_limit = extension_with_text(exact_payload);
	let mut fields = empty.fields().clone();
	fields.extensions = PlanExtensions::from_canonical_cbor(&at_limit).unwrap();
	let packed = PlanBody::new(fields).unwrap();
	assert_eq!(packed.canonical_cbor().len(), MAX_PLAN_BODY_BYTES);
	assert_eq!(
		PlanBody::from_canonical_cbor(packed.digest(), packed.canonical_cbor()),
		Ok(packed.clone())
	);

	let over_limit = extension_with_text(exact_payload + 1);
	let mut fields = empty.fields().clone();
	fields.extensions = PlanExtensions::from_canonical_cbor(&over_limit).unwrap();
	assert_eq!(PlanBody::new(fields), Err(PlanError::Size));

	let mut oversized = packed.canonical_cbor().to_vec();
	oversized.push(0);
	assert_eq!(
		PlanBody::from_canonical_cbor(DIGEST, &oversized),
		Err(PlanError::Size)
	);
}
