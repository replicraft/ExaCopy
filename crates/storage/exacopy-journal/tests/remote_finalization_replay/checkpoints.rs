use exacopy_journal::remote_download::RemoteUncertainBoundary;
use exacopy_journal::remote_download::finalization_replay::replay_remote_finalization_with_checkpoints;

use super::*;

fn active_checkpoint_inventory_requires_exact_clean_current_history() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = Journal::start(&owner);
	journal.prepare(&trust, &owner);
	journal.checkpoint(1, 0);
	let first = journal.head;
	journal.checkpoint(2, 2);
	let result = replay_remote_finalization_with_checkpoints(
		journal.bytes.as_slice(),
		&trust,
		QUALIFICATION,
		None,
	)
	.unwrap();
	let inventory = result.active_checkpoints().unwrap();
	assert_eq!(inventory.context(), journal.context);
	assert_eq!(
		inventory.scope().unwrap(),
		owner.manifest().scope.digest().unwrap()
	);
	assert_eq!(
		inventory.maximum_extent(),
		owner.manifest().scope.maximum_extent
	);
	assert_eq!(inventory.expected_qualification(), QUALIFICATION);
	assert_eq!(inventory.prepared().head, journal.prepared);
	assert_eq!(inventory.prepared().directory, DIRECTORY);
	assert_eq!(inventory.prepared().file, STAGE);
	assert_eq!(inventory.epochs(), journal.epochs);
	assert_eq!(inventory.name(), b"attempt");
	assert_eq!(inventory.nonce(), &[0x61; 16]);
	assert_eq!(inventory.source().length(), length());
	assert_eq!(inventory.boundary().head, journal.head);
	assert_eq!(inventory.boundary().offset, journal.bytes.len() as u64);
	assert_eq!(inventory.covered_extent(), 4);
	let rows = inventory.checkpoints();
	assert_eq!(rows.len(), 2);
	for (index, row) in rows.iter().enumerate() {
		assert_eq!(usize::from(row.ordinal()), index + 1);
		assert_eq!(row.offset(), index as u64 * 2);
		assert_eq!(row.length(), 2);
		assert_eq!(row.digest(), StreamDigest::from_bytes([0x42; 32]));
	}
	assert_eq!(rows[0].head(), first);
	assert_eq!(rows[1].head(), journal.head);

	let legacy =
		replay_remote_finalization(journal.bytes.as_slice(), &trust, QUALIFICATION, None).unwrap();
	assert_eq!(legacy.boundary(), result.boundary());
	assert_eq!(legacy.phase(), result.phase());
	assert!(legacy.active_checkpoints().is_err());
	let debug = format!("{result:?}");
	assert!(debug.contains("active_checkpoint_count: Some(2)"));
	assert!(!debug.contains("RemoteVerifiedCheckpoint"));
}

fn every_torn_checkpoint_suffix_hides_previously_accepted_rows() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = Journal::start(&owner);
	journal.prepare(&trust, &owner);
	let prepared_end = journal.bytes.len();
	journal.checkpoint(1, 0);
	let first_end = journal.bytes.len();
	journal.checkpoint(2, 2);
	for end in prepared_end..=journal.bytes.len() {
		let input = &journal.bytes[..end];
		let scan = replay_remote_finalization_with_checkpoints(input, &trust, QUALIFICATION, None)
			.unwrap();
		let legacy = replay_remote_finalization(input, &trust, QUALIFICATION, None).unwrap();
		assert_eq!(scan.boundary(), legacy.boundary());
		assert_eq!(scan.issue().is_some(), legacy.issue().is_some());
		let inventory = scan.active_checkpoints();
		if end == first_end || end == journal.bytes.len() {
			assert_eq!(
				inventory.unwrap().checkpoints().len(),
				if end == first_end { 1 } else { 2 }
			);
		} else {
			assert!(inventory.is_err(), "torn or empty suffix admitted at {end}");
		}
	}
}

fn each_damaged_checkpoint_byte_refuses_inventory() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = Journal::start(&owner);
	journal.prepare(&trust, &owner);
	journal.checkpoint(1, 0);
	let last_checkpoint = journal.bytes.len();
	journal.checkpoint(2, 2);
	for offset in last_checkpoint..journal.bytes.len() {
		let mut damaged = journal.bytes.clone();
		damaged[offset] ^= 1;
		let result = replay_remote_finalization_with_checkpoints(
			damaged.as_slice(),
			&trust,
			QUALIFICATION,
			None,
		)
		.unwrap();
		assert!(
			result.issue().is_some(),
			"damaged frame admitted at {offset}"
		);
		assert!(result.active_checkpoints().is_err());
	}
}

fn semantic_mismatch_uncertainty_and_sealing_do_not_admit_reuse() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	for fault in 0..3 {
		let mut journal = Journal::start(&owner);
		journal.prepare(&trust, &owner);
		journal.checkpoint(1, 0);
		match fault {
			0 => journal.checkpoint(2, 1),
			1 => {
				journal.capture(Capture::FailureRecorded {
					attempt: journal.prepared,
					epochs: journal.epochs,
					boundary: RemoteUncertainBoundary::CheckpointAppend,
				});
			}
			_ => {
				journal.final_record(Final::StageSealed {
					directory: DIRECTORY,
					length: length(),
				});
			}
		}
		let result = replay_remote_finalization_with_checkpoints(
			journal.bytes.as_slice(),
			&trust,
			QUALIFICATION,
			None,
		)
		.unwrap();
		assert!(result.active_checkpoints().is_err());
	}
}

fn a_fresh_allocation_clears_old_checkpoint_rows_before_new_preparation() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = Journal::start(&owner);
	journal.prepare(&trust, &owner);
	journal.checkpoint(1, 0);
	journal.checkpoint(2, 2);
	let old = journal.epochs;
	journal.epochs = RemoteEpochs {
		run: NonZeroU64::new(2).unwrap(),
		source: NonZeroU64::new(8).unwrap(),
	};
	let nonce = [0x62; 16];
	let allocation = journal.capture(Capture::StageAllocated {
		previous: Some(old),
		next: journal.epochs,
		name: UnixComponent::new(b"next").unwrap(),
		nonce,
		source: RemoteSourceObservation::new(length(), 0o100644, 22).unwrap(),
	});
	let scan = replay_remote_finalization_with_checkpoints(
		journal.bytes.as_slice(),
		&trust,
		QUALIFICATION,
		None,
	)
	.unwrap();
	assert!(scan.issue().is_none());
	assert!(scan.active_checkpoints().is_err());
	let stage = LinuxFileIdentity::new(7, 14);
	journal.prepared = journal.capture(Capture::EntryPrepared {
		allocation,
		epochs: journal.epochs,
		nonce,
		stage_directory: DIRECTORY,
		stage,
	});
	let scan = replay_remote_finalization_with_checkpoints(
		journal.bytes.as_slice(),
		&trust,
		QUALIFICATION,
		None,
	)
	.unwrap();
	assert!(scan.active_checkpoints().is_err());
	journal.checkpoint(1, 0);
	let scan = replay_remote_finalization_with_checkpoints(
		journal.bytes.as_slice(),
		&trust,
		QUALIFICATION,
		None,
	)
	.unwrap();
	let inventory = scan.active_checkpoints().unwrap();
	assert_eq!(inventory.prepared().file, stage);
	assert_eq!(inventory.name(), b"next");
	assert_eq!(inventory.checkpoints().len(), 1);
	assert_eq!(inventory.covered_extent(), 2);
	assert_eq!(inventory.checkpoints()[0].head(), journal.head);
}

#[test]
fn checkpoint_inventory_matches_complete_history_and_failure_oracles() {
	active_checkpoint_inventory_requires_exact_clean_current_history();
	every_torn_checkpoint_suffix_hides_previously_accepted_rows();
	each_damaged_checkpoint_byte_refuses_inventory();
	semantic_mismatch_uncertainty_and_sealing_do_not_admit_reuse();
	a_fresh_allocation_clears_old_checkpoint_rows_before_new_preparation();
}
