use super::{MAX_REPORT_BYTES, Report, SignedRecreateExport};

fn export() -> SignedRecreateExport {
	SignedRecreateExport {
		pair_id: *uuid::Uuid::parse_str("019b8db1-d7f0-7112-8001-010203040506")
			.unwrap()
			.as_bytes(),
		predecessor_pair_digest: [0xab; 32],
		parent_digest: [0xcd; 32],
		members: std::array::from_fn(|_| vec![0xef]),
	}
}

#[test]
fn signed_export_report_round_trips_the_exact_members_without_authority() {
	let source = export();
	let report = Report::exported(&source);
	let bytes = report.canonical_json(Some(&source)).unwrap();
	let decoded = Report::decode(&bytes).unwrap();
	assert!(decoded.matches(Some(&source), None));
	assert_closed_report_bytes(&bytes, &report);

	let mut wrong = Report::exported(&source);
	wrong.approval_present = true;
	assert!(wrong.canonical_json(Some(&source)).is_err());
	let mut upper = Report::exported(&source);
	upper.bundle.as_mut().unwrap().action_page_cbor_hex = "EF".into();
	assert!(upper.canonical_json(Some(&source)).is_err());
	assert!(Report::decode(&[b' '; MAX_REPORT_BYTES + 1]).is_none());
}

#[test]
fn refused_export_has_no_association_or_bundle() {
	let report = Report::refused("signed_bundle_refused");
	let bytes = report.canonical_json(None).unwrap();
	let decoded = Report::decode(&bytes).unwrap();
	assert!(decoded.matches(None, Some("signed_bundle_refused")));
	assert!(!decoded.matches(Some(&export()), None));
}

fn assert_closed_report_bytes(bytes: &[u8], report: &Report) {
	let document: serde_json::Value = serde_json::from_slice(bytes).unwrap();
	let outer_fields = [
		"schema",
		"schema_version",
		"authority",
		"approval_required",
		"approval_present",
		"delegated_grant_present",
		"action_intent_present",
		"copy_started",
		"baseline_advanced",
		"result",
		"pair_id",
		"predecessor_pair_digest",
		"parent_plan_digest",
		"bundle",
		"reason",
	];
	let mut outer = serde_json::to_vec(&outer_fields.map(|name| document[name].clone())).unwrap();
	outer.push(b'\n');

	let member_fields = [
		"parent_envelope_cbor_hex",
		"action_page_cbor_hex",
		"child_plan_body_cbor_hex",
		"child_plan_page_cbor_hex",
		"predecessor_root_envelope_cbor_hex",
		"left_endpoint_envelope_cbor_hex",
		"right_endpoint_envelope_cbor_hex",
		"predecessor_leaf_cbor_hex",
	];
	let members = member_fields.map(|name| document["bundle"][name].clone());
	let canonical_bundle = serde_json::to_string(report.bundle.as_ref().unwrap()).unwrap();
	let positional_bundle = serde_json::to_string(&members).unwrap();
	let original = str::from_utf8(bytes).unwrap();
	assert!(original.contains(&canonical_bundle));
	let nested = original.replacen(&canonical_bundle, &positional_bundle, 1);

	let prefix = bytes.strip_suffix(b"}\n").unwrap();
	let null = [prefix, b",\"reason\":null}\n"].concat();
	for altered in [outer.as_slice(), nested.as_bytes(), &null] {
		assert!(serde_json::from_slice::<Report>(altered).is_ok());
		assert!(Report::decode(altered).is_none());
	}

	let duplicate = [prefix, b",\"result\":\"exported\"}\n"].concat();
	assert!(Report::decode(&duplicate).is_none());
	let extra_lf = [bytes, b"\n"].concat();
	assert!(Report::decode(&extra_lf).is_none());
}
