use exacopy_endpoint::remote_source::SftpPathRoot;
use exacopy_journal::remote_download::qualification::RemoteQualificationRouteClass;
use exacopy_journal::{
	MAX_FIRST_SEGMENT_BYTES, remote_download::witness::MAX_REMOTE_WITNESS_RECEIPT_BYTES,
};
use serde_json::{Value, json};

use super::{ArchiveError, MAX_REPORT_BYTES, decode, report_selection};

const JOB: &str = "018f6cb3-b607-76aa-a4d3-6c6f4ba012ef";
// RFC 8032 public key for test vector 1. No private material is used.
const KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn specimen() -> Value {
	json!({
		"schema": "exacopy.cli.witnessed_remote_download",
		"schema_version": "1.1",
		"completed": 1,
		"pending": 0,
		"publication": "published",
		"verification": "verified_prefix_with_witness_readback",
		"consistency": "live_observed",
		"durability": "file_and_directory_barriers_observed",
		"durability_qualification": "process_crash_qualification",
		"preservation": "preserve",
		"metadata": "explicitly_omitted",
		"result": "published_with_omissions",
		"receipt": {
			"job_id": JOB,
			"job_directory": "/job\u{fffd}",
			"job_directory_bytes_hex": "2f6a6f62ff",
			"length": "25",
			"receipt_digest": "ea".repeat(32),
			"qualification_digest": "b2".repeat(32),
			"metadata_policy": "sftp-data-only-v1",
			"omissions": [
				"additional_content_streams_unenumerated",
				"source_unix_mode",
				"source_ownership",
				"source_timestamps",
				"source_acl",
				"source_xattrs_and_security_labels",
				"source_file_flags",
				"source_link_topology",
				"source_sparse_layout",
				"source_storage_representation",
			],
			"retained_witness": {
				"link_count": 2,
				"committed_sequence": "18",
				"committed_head_digest": "28".repeat(32),
				"canonical_receipt_length": 512,
			},
			"archive_selection": {
				"job": JOB,
				"owner_key": KEY,
				"route": "embedded-wireguard-tcp-v1",
				"path_root": "absolute",
				"scope": "eb".repeat(32),
				"op1_digest": "b1".repeat(32),
				"op2_digest": "b2".repeat(32),
				"base_grant_digest": "a3".repeat(32),
				"committed_sequence": "18",
				"committed_head_digest": "28".repeat(32),
				"committed_offset": "8963",
				"receipt_digest": "ea".repeat(32),
			},
		},
	})
}

#[test]
fn valid_strict_report_preserves_independent_selection() {
	let report = specimen();
	let parsed = decode(report.to_string().as_bytes()).unwrap();
	let selection = &parsed.selection;
	assert_eq!(parsed.receipt_length, 512);
	assert_eq!(parsed.stream_length, 25);
	assert_eq!(
		selection.job.as_bytes(),
		uuid::Uuid::parse_str(JOB).unwrap().as_bytes()
	);
	assert_eq!(
		blake3::Hash::from_bytes(selection.owner_key.to_bytes())
			.to_hex()
			.as_str(),
		KEY
	);
	assert_eq!(
		selection.route,
		RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1
	);
	assert_eq!(selection.path_root, SftpPathRoot::Absolute);
	assert_eq!(selection.scope.as_bytes(), &[0xeb; 32]);
	assert_eq!(selection.op1_digest, [0xb1; 32]);
	assert_eq!(selection.op2_digest, [0xb2; 32]);
	assert_eq!(selection.base_grant_digest, [0xa3; 32]);
	assert_eq!(selection.committed.head.sequence(), 18);
	assert_eq!(selection.committed.head.digest(), [0x28; 32]);
	assert_eq!(selection.committed.offset, 8963);
	assert_eq!(selection.receipt_digest, [0xea; 32]);
	assert_eq!(
		serde_json::to_value(report_selection(selection)).unwrap(),
		report["receipt"]["archive_selection"]
	);

	let mut report = report;
	let archive = &mut report["receipt"]["archive_selection"];
	archive["route"] = json!("direct-pinned-tcp-v1");
	archive["path_root"] = json!("account-relative");
	let parsed = decode(report.to_string().as_bytes()).unwrap();
	assert_eq!(
		parsed.selection.route,
		RemoteQualificationRouteClass::DirectPinnedTcpV1
	);
	assert_eq!(parsed.selection.path_root, SftpPathRoot::AccountRelative);
}

#[test]
fn duplicate_unknown_and_positional_fields_are_refused() {
	let report = specimen();
	let encoded = report.to_string();
	for (anchor, duplicate) in [
		("\"completed\":1", "\"completed\":1,\"completed\":1"),
		("\"length\":\"25\"", "\"length\":\"25\",\"length\":\"25\""),
		("\"link_count\":2", "\"link_count\":2,\"link_count\":2"),
		(
			"\"path_root\":\"absolute\"",
			"\"path_root\":\"absolute\",\"path_root\":\"absolute\"",
		),
	] {
		assert!(encoded.contains(anchor));
		assert_eq!(
			decode(encoded.replacen(anchor, duplicate, 1).as_bytes()).err(),
			Some(ArchiveError::Format),
			"{anchor}"
		);
	}
	for pointer in [
		"",
		"/receipt",
		"/receipt/retained_witness",
		"/receipt/archive_selection",
	] {
		let mut unknown = report.clone();
		unknown.pointer_mut(pointer).unwrap()["unexpected"] = json!(true);
		assert_eq!(
			decode(unknown.to_string().as_bytes()).err(),
			Some(ArchiveError::Format)
		);
	}
	let mut positional = report;
	let archive = &mut positional["receipt"]["archive_selection"];
	*archive = Value::Array(
		[
			"job",
			"owner_key",
			"route",
			"path_root",
			"scope",
			"op1_digest",
			"op2_digest",
			"base_grant_digest",
			"committed_sequence",
			"committed_head_digest",
			"committed_offset",
			"receipt_digest",
		]
		.into_iter()
		.map(|name| archive[name].clone())
		.collect(),
	);
	assert_eq!(
		decode(positional.to_string().as_bytes()).err(),
		Some(ArchiveError::Format)
	);
}

#[test]
fn incoherent_or_noncanonical_report_is_refused() {
	let report = specimen();
	for (pointer, replacement) in [
		("/schema", json!("exacopy.cli.remote_download")),
		("/schema_version", json!("1.0")),
		("/completed", json!(0)),
		("/pending", json!(1)),
		("/publication", json!("not_published")),
		("/result", json!("failed")),
		("/verification", json!("hash_readback")),
		(
			"/receipt/job_id",
			json!("018f6cb3-b607-76aa-a4d3-6c6f4ba012ee"),
		),
		("/receipt/job_directory", json!("/some-other-job")),
		("/receipt/job_directory_bytes_hex", json!("2F6A6F62FF")),
		("/receipt/length", json!("025")),
		("/receipt/length", json!("0")),
		("/receipt/receipt_digest", json!("11".repeat(32))),
		("/receipt/qualification_digest", json!("11".repeat(32))),
		("/receipt/metadata_policy", json!("anything")),
		("/receipt/omissions", json!([])),
		("/receipt/retained_witness/link_count", json!(1)),
		("/receipt/retained_witness/committed_sequence", json!("17")),
		(
			"/receipt/retained_witness/committed_head_digest",
			json!("10".repeat(32)),
		),
		(
			"/receipt/retained_witness/canonical_receipt_length",
			json!(0),
		),
		(
			"/receipt/retained_witness/canonical_receipt_length",
			json!(usize::from(MAX_REMOTE_WITNESS_RECEIPT_BYTES) + 1),
		),
		(
			"/receipt/archive_selection/job",
			json!("018f6cb3-b607-46aa-a4d3-6c6f4ba012ef"),
		),
		("/receipt/archive_selection/job", json!(JOB.to_uppercase())),
		(
			"/receipt/archive_selection/owner_key",
			json!("01".to_owned() + &"00".repeat(31)),
		),
		("/receipt/archive_selection/route", json!("direct")),
		(
			"/receipt/archive_selection/path_root",
			json!({"absolute": null}),
		),
		("/receipt/archive_selection/scope", json!("00".repeat(32))),
		(
			"/receipt/archive_selection/op1_digest",
			json!("b1".repeat(31)),
		),
		(
			"/receipt/archive_selection/base_grant_digest",
			json!("A3".repeat(32)),
		),
		("/receipt/archive_selection/committed_offset", json!("0")),
		("/receipt/archive_selection/committed_offset", json!("1")),
		(
			"/receipt/archive_selection/committed_offset",
			json!((MAX_FIRST_SEGMENT_BYTES + 1).to_string()),
		),
	] {
		let mut candidate = report.clone();
		*candidate.pointer_mut(pointer).unwrap() = replacement;
		assert_eq!(
			decode(candidate.to_string().as_bytes()).err(),
			Some(ArchiveError::Format),
			"{pointer}"
		);
	}
	let mut missing = report;
	missing["receipt"]
		.as_object_mut()
		.unwrap()
		.remove("archive_selection");
	assert_eq!(
		decode(missing.to_string().as_bytes()).err(),
		Some(ArchiveError::Format)
	);
}

#[test]
fn complete_report_is_bounded_and_requires_one_document() {
	let mut encoded = specimen().to_string().into_bytes();
	encoded.push(b'\n');
	assert!(decode(&encoded).is_ok());
	let with_suffix = [encoded.as_slice(), b"{}"].concat();
	assert_eq!(decode(&with_suffix).err(), Some(ArchiveError::Format));
	encoded.resize(MAX_REPORT_BYTES, b' ');
	assert!(decode(&encoded).is_ok());
	encoded.push(b' ');
	assert_eq!(decode(&encoded).err(), Some(ArchiveError::Format));
}
