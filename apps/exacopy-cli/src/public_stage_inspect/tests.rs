use ed25519_dalek::SigningKey;
use exacopy_journal::frame::ChainHead;
use exacopy_journal::{
	ApplyMetadataPolicyDigest, ApplyRequestedDurability, ApprovedPublicPlanDigest,
	ApprovedStreamDigest, JournalEntryId, JournalEpoch, OwnerDigest, PlanDigest,
	PublicApplyBinding, PublicPlanEntryId, RootCapabilityId, StreamLength,
};
use exacopy_transfer::linux::RecoveryIssue;
use serde_json::{Value, json};

use super::*;

fn file_uuid(value: u8) -> [u8; 16] {
	let mut bytes = [value; 16];
	bytes[6] = 0x40;
	bytes[8] = 0x80;
	bytes
}

fn historical(history: PublicStageHistory) -> PublicStageInspection {
	PublicStageInspection::Authenticated {
		evidence: Box::new(AuthenticatedPublicStage {
			owner_digest: OwnerDigest::from_bytes([1; 32]),
			private_plan: PlanDigest::from_bytes([2; 32]),
			binding: PublicApplyBinding {
				public_plan: ApprovedPublicPlanDigest::from_bytes([3; 32]),
				public_entry: PublicPlanEntryId::from_bytes(file_uuid(4)).unwrap(),
				private_entry: JournalEntryId::from_bytes([5; 16]),
				epoch: JournalEpoch::new(1),
				source_root: RootCapabilityId::from_bytes(file_uuid(6)).unwrap(),
				destination_root: RootCapabilityId::from_bytes(file_uuid(7)).unwrap(),
				stream_length: StreamLength::new(0).unwrap(),
				stream_digest: ApprovedStreamDigest::from_bytes([8; 32]),
				metadata_policy: ApplyMetadataPolicyDigest::from_bytes([9; 32]),
				expires_at: None,
				requested_durability: ApplyRequestedDurability::ProcessCrash,
			},
		}),
		history,
	}
}

#[test]
fn public_stage_reports_checked_absence_without_inventing_evidence() {
	let missing = project(PublicStageInspection::OwnerMissing);
	assert_eq!(missing.exit, 9);
	assert_eq!(
		serde_json::to_value(missing).unwrap(),
		json!({
			"schema": "exacopy.public_stage_inspection",
			"schema_version": "1.0",
			"authority": "none",
			"status": "owner_missing_observed"
		})
	);
	for (history, status) in [
		(PublicStageHistory::PlanMissing, "plan_missing_observed"),
		(
			PublicStageHistory::JournalMissing,
			"journal_missing_observed",
		),
	] {
		let report = project(historical(history));
		assert_eq!(report.exit, 9);
		let value = serde_json::to_value(report).unwrap();
		assert_eq!(value["status"], status);
		assert_eq!(
			value["historical_binding"]["public_plan_digest"],
			"03".repeat(32)
		);
		assert!(value.get("journal").is_none());
	}
}

#[test]
fn public_stage_journal_reports_only_the_last_accepted_observation() {
	use PublicStageObservation as Stage;

	let torn = JournalTail::Torn { bytes_read: 7 };
	for (observation, tail, status, exit) in [
		(Stage::EmptyJournal, JournalTail::Clean, "empty_journal", 9),
		(
			Stage::RetainedPreparation,
			JournalTail::Clean,
			"retained_preparation",
			9,
		),
		(
			Stage::RetainedPartialStage,
			JournalTail::Clean,
			"retained_partial_stage",
			9,
		),
		(
			Stage::RetainedVerifiedStage,
			JournalTail::Clean,
			"retained_verified_stage",
			0,
		),
		(
			Stage::RetainedVerifiedStage,
			torn,
			"requires_reconciliation",
			9,
		),
		(Stage::UnexpectedTarget, torn, "unexpected_target", 3),
		(
			Stage::UnexpectedReceipt,
			JournalTail::Clean,
			"unexpected_receipt",
			9,
		),
		(
			Stage::RequiresReconciliation(RecoveryIssue::MetadataMismatch),
			JournalTail::Clean,
			"requires_reconciliation",
			9,
		),
	] {
		let report = project(historical(PublicStageHistory::Journal {
			boundary: JournalBoundary {
				head: ChainHead::start(),
				offset: 24,
			},
			tail,
			observation,
		}));
		assert_eq!(report.exit, exit, "{observation:?}");
		let value = serde_json::to_value(report).unwrap();
		assert_eq!(value["status"], status);
		assert_eq!(value["authority"], "none");
		assert_eq!(value["journal"]["accepted_offset"], "24");
		assert_eq!(
			value["journal"]["tail"],
			if tail == torn { "torn" } else { "clean" }
		);
	}
}

#[test]
fn accepted_owner_key_is_canonical_and_refusals_do_not_reveal_paths() {
	let expected = SigningKey::from_bytes(&[0x51; 32]).verifying_key();
	assert_eq!(verified_key(expected.to_bytes()), Some(expected));
	assert!(verified_key([0; 32]).is_none());
	let mut identity = [0; 32];
	identity[0] = 1;
	assert!(verified_key(identity).is_none());
	let noncanonical = (2..19)
		.find_map(|y| {
			let mut bytes = [0xff; 32];
			bytes[0] = 0xed + y;
			bytes[31] = 0x7f;
			let key = VerifyingKey::from_bytes(&bytes).ok()?;
			(!key.is_weak()).then_some(bytes)
		})
		.expect("synthetic strong noncanonical encoding");
	assert!(verified_key(noncanonical).is_none());
	let mut stderr = Vec::new();
	let mut stdout = Vec::new();
	let code = run(
		&PublicStageInspectCommand {
			job: "/should-not-be-opened/-selected-job".into(),
			owner_key: identity,
			format: Format::Json,
		},
		&mut stdout,
		&mut stderr,
	);
	assert_eq!(code, 8);
	assert!(stderr.is_empty());
	let value: Value = serde_json::from_slice(&stdout).unwrap();
	assert_eq!(value["reason"], "owner_key_refused");
	assert!(value.get("historical_binding").is_none());
	assert!(value.get("journal").is_none());
	assert!(
		!std::str::from_utf8(&stdout)
			.unwrap()
			.contains("selected-job")
	);
}
