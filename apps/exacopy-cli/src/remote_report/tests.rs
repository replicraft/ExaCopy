use std::os::unix::ffi::OsStringExt;

use super::*;

#[test]
fn published_with_omissions_uses_dedicated_nonclean_status_and_precise_evidence() {
	let outcome = published_report_fixture();
	assert_eq!(outcome.exit_code(), 11);
	let mut stdout = Vec::new();
	let mut stderr = Vec::new();
	outcome
		.write(Format::Json, &mut stdout, &mut stderr)
		.unwrap();
	let json: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
	assert_eq!(json["schema"], "exacopy.cli.remote_download");
	assert_eq!(json["schema_version"], "1.0");
	assert_eq!(json["result"], "published_with_omissions");
	assert_eq!(json["publication"], "published");
	assert_eq!(json["completed"], 1);
	assert_eq!(json["pending"], 0);
	assert_eq!(json["consistency"], "live_observed");
	assert_eq!(json["durability"], "file_and_directory_barriers_observed");
	assert_eq!(
		json["durability_qualification"],
		"process_crash_qualification"
	);
	assert_eq!(json["metadata"], "explicitly_omitted");
	assert_eq!(json["receipt"]["metadata_policy"], SftpDataOnlyV1::NAME);
	assert_eq!(
		json["receipt"]["omissions"],
		serde_json::json!(
			SftpDataOnlyV1::omissions()
				.iter()
				.map(|item| item.name())
				.collect::<Vec<_>>()
		),
	);
	assert_eq!(json["receipt"]["job_directory_bytes_hex"], "6a6f622dff");
	assert_eq!(json["receipt"]["blake3"], digest_hex(&[6; 32]));
	assert!(json["receipt"].get("retained_witness").is_none());
	assert!(stderr.is_empty());
}

#[test]
fn publication_uncertainty_and_published_without_completion_require_reconciliation() {
	for (state, expected) in [
		(
			RemotePublication::PublicationUncertain,
			"publication_uncertain",
		),
		(RemotePublication::Published, "published"),
		(RemotePublication::NotPublished, "not_published"),
	] {
		let outcome = RemoteOutcome::recovery_required(state, job());
		assert_eq!(outcome.exit_code(), 9);
		let json = serde_json::to_value(outcome.report()).unwrap();
		assert_eq!(json["result"], "failed");
		assert_eq!(json["publication"], expected);
		assert_eq!(json["error"]["code"], "E_RECOVERY_REQUIRED");
		assert_eq!(json["pending"], 1);
		assert_eq!(json["durability"], "unconfirmed");
		assert!(json["durability_qualification"].is_null());
		assert!(json.get("receipt").is_none());
	}
}

#[test]
fn cancellation_retains_its_status_and_success_output_failure_retains_receipt_location() {
	let cancel = RemoteOutcome::failed(RemoteFailureKind::Cancelled, None);
	assert_eq!(cancel.exit_code(), 10);
	assert_eq!(
		serde_json::to_value(cancel.report()).unwrap()["error"]["code"],
		"E_CANCELLED",
	);
	let receipt = published_report_fixture();
	let output = &mut Vec::new();
	assert_eq!(receipt.failed_output(output), 4);
	let output = String::from_utf8(std::mem::take(output)).unwrap();
	assert!(output.contains("was published with metadata omissions"));
	assert!(output.contains(&digest_hex(&[7; 32])));
	assert!(output.contains("6a6f622dff"));
}

#[cfg(feature = "experimental-ssh-wireguard")]
#[test]
fn unconfirmed_route_retirement_preserves_known_publication_and_job() {
	let outcome = published_report_fixture()
		.with_unconfirmed_route_retirement(RemoteRouteCloseError::WorkerFailed);
	let json = serde_json::to_value(outcome.report()).unwrap();
	assert_eq!(outcome.exit_code(), 9);
	assert_eq!(json["result"], "failed");
	assert_eq!(json["publication"], "published");
	assert_eq!(json["completed"], 0);
	assert_eq!(json["error"]["code"], "E_RECOVERY_REQUIRED");
	assert_eq!(
		json["error"]["message"],
		"remote download requires reconciliation (transport retirement unconfirmed)",
	);
	assert_eq!(json["error"]["job_directory_bytes_hex"], "6a6f622dff");
}

// Tests formatting only. Live construction requires the committed typed receipt and
// matching canonical evidence through RemoteOutcome::published.
fn published_report_fixture() -> RemoteOutcome {
	RemoteOutcome(Outcome::PublishedWithOmissions {
		receipt: PublishedReceipt {
			job: job().into(),
			length: "64".into(),
			blake3: Some(digest_hex(&[6; 32])),
			receipt_digest: digest_hex(&[7; 32]),
			qualification_digest: digest_hex(&[8; 32]),
			metadata_policy: SftpDataOnlyV1::NAME,
			omissions: SftpDataOnlyV1::omissions()
				.iter()
				.map(|item| item.name())
				.collect(),
			#[cfg(feature = "experimental-verified-prefix-resume")]
			retained_witness: None,
		},
	})
}

#[cfg(feature = "experimental-verified-prefix-resume")]
#[test]
fn observed_incumbent_with_unconfirmed_record_preserves_conflict_evidence() {
	let outcome = RemoteOutcome::witness_conflict_reconciliation(job());
	let json = serde_json::to_value(outcome.report()).unwrap();
	assert_eq!(outcome.exit_code(), 9);
	assert_eq!(json["publication"], "not_published");
	assert_eq!(json["error"]["code"], "E_RECOVERY_REQUIRED");
	assert_eq!(
		json["error"]["message"],
		"remote download requires reconciliation (incumbent observed; conflict record unconfirmed)"
	);
	assert!(json.get("receipt").is_none());
}

#[cfg(feature = "experimental-verified-prefix-resume")]
#[test]
fn witnessed_receipt_projection_reports_committed_evidence_and_retention() {
	use exacopy_journal::frame::ChainHead;
	use exacopy_journal::remote_download::replay::RemoteReplayBoundary;

	let outcome = RemoteOutcome::published_with_witness(
		job(),
		WitnessedSummary {
			committed: RemoteReplayBoundary {
				head: ChainHead::after(18, [9; 32]).unwrap(),
				offset: 4096,
			},
			length: 64,
			receipt_digest: [7; 32],
			canonical_receipt_length: 1024,
			qualification: [8; 32],
			witness_links: 2,
			metadata_omissions: SftpDataOnlyV1::omissions(),
		},
	);
	let json = serde_json::to_value(outcome.report()).unwrap();
	assert_eq!(outcome.exit_code(), 11);
	assert_eq!(json["schema"], "exacopy.cli.witnessed_remote_download");
	assert_eq!(json["schema_version"], "1.0");
	assert!(json["receipt"].get("blake3").is_none());
	assert_eq!(json["publication"], "published");
	assert_eq!(
		json["verification"],
		"verified_prefix_with_witness_readback"
	);
	assert_eq!(json["receipt"]["retained_witness"]["link_count"], 2);
	assert_eq!(
		json["receipt"]["retained_witness"]["committed_sequence"],
		"18"
	);
	assert_eq!(
		json["receipt"]["retained_witness"]["committed_head_digest"],
		digest_hex(&[9; 32])
	);
	assert_eq!(json["receipt"]["receipt_digest"], digest_hex(&[7; 32]));

	#[cfg(feature = "experimental-ssh-wireguard")]
	{
		let pending =
			outcome.with_unconfirmed_route_retirement(RemoteRouteCloseError::WorkerFailed);
		let json = serde_json::to_value(pending.report()).unwrap();
		assert_eq!(pending.exit_code(), 9);
		assert_eq!(json["publication"], "published");
		assert_eq!(
			json["error"]["message"],
			"remote download requires reconciliation (private witness retained, 2 links observed) (transport retirement unconfirmed)"
		);
	}
}

fn job() -> RemoteJob {
	let id = Uuid::from_bytes([1, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0]);
	RemoteJob {
		id: JournalJobId::from_bytes(*id.as_bytes()).unwrap(),
		directory: std::ffi::OsString::from_vec(b"job-\xff".to_vec()).into(),
	}
}
