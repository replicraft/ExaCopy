use std::os::unix::ffi::OsStringExt;

use uuid::Uuid;

use super::*;

const JOB_ID: &str = "01000000-0000-7000-8000-000000000000";
const JOB_DIRECTORY: &[u8] = b"/private-remote-sentinel\n\x1b/job-\xff";
const JOB_DISPLAY: &str = "/private-remote-sentinel\n\u{1b}/job-�";
const JOB_DIRECTORY_HEX: &str = "2f707269766174652d72656d6f74652d73656e74696e656c0a1b2f6a6f622dff";
const DISPLAY_POLICIES: [JobPathDisplay; 2] = [JobPathDisplay::Redacted, JobPathDisplay::Reveal];

#[test]
fn published_with_omissions_uses_dedicated_nonclean_status_and_precise_evidence() {
	let outcome = published_report_fixture();
	let json = json_output(&outcome, 11);
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
	assert_job_json(&json["receipt"]);
	assert_eq!(json["receipt"]["blake3"], digest_hex(&[6; 32]));
	assert!(json["receipt"].get("retained_witness").is_none());
	assert!(json["receipt"].get("archive_selection").is_none());
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
		let json = json_output(&outcome, 9);
		assert_eq!(json["schema"], "exacopy.cli.remote_download");
		assert_eq!(json["schema_version"], "1.0");
		assert_eq!(json["result"], "failed");
		assert_job_json(&json["error"]);
		assert_eq!(json["publication"], expected);
		assert_eq!(json["error"]["code"], "E_RECOVERY_REQUIRED");
		assert_eq!(json["pending"], 1);
		assert_eq!(json["durability"], "unconfirmed");
		assert!(json["durability_qualification"].is_null());
		assert!(json.get("receipt").is_none());
	}
}

#[test]
fn human_results_preserve_job_id_and_publication_with_explicit_path_disclosure() {
	let published = published_report_fixture();
	let uncertain =
		RemoteOutcome::recovery_required(RemotePublication::PublicationUncertain, job());
	let known = RemoteOutcome::recovery_required(RemotePublication::Published, job());
	let conflict = RemoteOutcome::failed(RemoteFailureKind::Conflict, Some(job()));

	for policy in DISPLAY_POLICIES {
		let mut stdout = Vec::new();
		let mut stderr = Vec::new();
		assert_eq!(
			published.write(Format::Human, policy, &mut stdout, &mut stderr),
			11,
		);
		assert!(stderr.is_empty());
		let text = String::from_utf8(stdout).unwrap();
		assert!(text.contains("Published 64 bytes"));
		assert!(text.contains(&digest_hex(&[7; 32])));
		assert_job_text(&text, policy);

		for (outcome, code, message) in [
			(
				&uncertain,
				9,
				"Publication is uncertain. Preserve the job for reconciliation.",
			),
			(
				&known,
				9,
				"The file was published. Receipt completion requires reconciliation.",
			),
			(&conflict, 3, "the destination name is already occupied"),
		] {
			let mut stdout = Vec::new();
			let mut stderr = Vec::new();
			assert_eq!(
				outcome.write(Format::Human, policy, &mut stdout, &mut stderr),
				code,
			);
			assert!(stdout.is_empty());
			let text = String::from_utf8(stderr).unwrap();
			assert!(text.contains(message));
			assert_job_text(&text, policy);
		}
	}
}

#[test]
fn failed_report_write_preserves_disposition_and_respects_text_path_policy() {
	let published = published_report_fixture();
	let uncertain =
		RemoteOutcome::recovery_required(RemotePublication::PublicationUncertain, job());

	for policy in DISPLAY_POLICIES {
		for format in [Format::Json, Format::Human] {
			let mut stderr = Vec::new();
			assert_eq!(
				published.write(format, policy, &mut BrokenWriter, &mut stderr),
				4,
			);
			let text = String::from_utf8(stderr).unwrap();
			assert!(text.contains("could not write the remote download result"));
			assert!(text.contains("was published with metadata omissions"));
			assert!(text.contains(&digest_hex(&[7; 32])));
			assert_job_text(&text, policy);
		}

		let mut stderr = Vec::new();
		assert_eq!(
			uncertain.write(Format::Json, policy, &mut BrokenWriter, &mut stderr),
			9,
		);
		let text = String::from_utf8(stderr).unwrap();
		assert!(text.contains("could not write the remote download result"));
		assert!(text.contains("Publication is uncertain. Preserve the job for reconciliation."));
		assert_job_text(&text, policy);
	}

	let published_json = json_output(&published, 11);
	assert_eq!(
		published_json["receipt"]["receipt_digest"],
		digest_hex(&[7; 32])
	);
	assert_job_json(&published_json["receipt"]);
	let uncertain_json = json_output(&uncertain, 9);
	assert_eq!(uncertain_json["publication"], "publication_uncertain");
	assert_job_json(&uncertain_json["error"]);
}

#[test]
fn cancellation_without_a_retained_job_keeps_its_status_and_omits_the_locator() {
	let cancel = RemoteOutcome::failed(RemoteFailureKind::Cancelled, None);
	let json = json_output(&cancel, 10);
	assert_eq!(json["error"]["code"], "E_CANCELLED");
	assert!(json["error"].get("job_id").is_none());
	assert!(json["error"].get("job_directory").is_none());
	assert!(json["error"].get("job_directory_bytes_hex").is_none());

	for policy in DISPLAY_POLICIES {
		let mut stdout = Vec::new();
		let mut stderr = Vec::new();
		assert_eq!(
			cancel.write(Format::Human, policy, &mut stdout, &mut stderr),
			10,
		);
		assert!(stdout.is_empty());
		assert_eq!(
			stderr.as_slice(),
			b"exacopy: remote download was cancelled\n"
		);
	}
}

fn assert_job_text(text: &str, policy: JobPathDisplay) {
	assert!(!text.contains('\u{1b}'));
	match policy {
		JobPathDisplay::Redacted => {
			let expected = format!("Job {JOB_ID} retained.");
			assert!(text.lines().any(|line| line == expected.as_str()));
			assert!(!text.contains("private-remote-sentinel"));
			assert!(!text.contains("2f707269766174652d"));
			assert!(!text.contains("Directory bytes in hex"));
		}
		JobPathDisplay::Reveal => {
			let display = r#""/private-remote-sentinel\n\u{1b}/job-�""#;
			let expected = format!(
				"Job {JOB_ID} retained in {display}. Directory bytes in hex: {JOB_DIRECTORY_HEX}."
			);
			assert!(text.lines().any(|line| line == expected.as_str()));
		}
	}
}

fn assert_job_json(job: &serde_json::Value) {
	assert_eq!(job["job_id"], JOB_ID);
	assert_eq!(job["job_directory"], JOB_DISPLAY);
	assert_eq!(job["job_directory_bytes_hex"], JOB_DIRECTORY_HEX);
}

fn json_output(outcome: &RemoteOutcome, code: u8) -> serde_json::Value {
	let outputs = DISPLAY_POLICIES.map(|policy| {
		let mut stdout = Vec::new();
		let mut stderr = Vec::new();
		assert_eq!(
			outcome.write(Format::Json, policy, &mut stdout, &mut stderr),
			code,
		);
		assert!(stderr.is_empty());
		assert!(stdout.ends_with(b"\n"));
		stdout
	});
	assert_eq!(outputs[0], outputs[1]);
	serde_json::from_slice(&outputs[0]).unwrap()
}

struct BrokenWriter;

impl io::Write for BrokenWriter {
	fn write(&mut self, _: &[u8]) -> io::Result<usize> {
		Err(io::ErrorKind::BrokenPipe.into())
	}

	fn flush(&mut self) -> io::Result<()> {
		Err(io::ErrorKind::BrokenPipe.into())
	}
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
	assert_job_json(&json["error"]);
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
			#[cfg(feature = "experimental-verified-prefix-resume")]
			archive_selection: None,
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
	let outcome = RemoteOutcome::published_with_witness(job(), archive::summary());
	let json = json_output(&outcome, 11);
	assert_job_json(&json["receipt"]);
	assert_eq!(json["schema"], "exacopy.cli.witnessed_remote_download");
	assert_eq!(json["schema_version"], "1.1");
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
		directory: std::ffi::OsString::from_vec(JOB_DIRECTORY.to_vec()).into(),
	}
}

#[cfg(feature = "experimental-verified-prefix-resume")]
mod archive;
