use super::*;

fn data(length: u64, marker: u8) -> RegularFileEvidence {
	RegularFileEvidence {
		byte_len: length,
		content_digest: [marker; 32],
		required_metadata_digest: [marker ^ 0xff; 32],
	}
}

#[test]
fn manual_recreate_selects_only_the_current_survivor_and_exact_conflict() {
	use SyncConflict::{DeletionAgainstUnchanged, EditAgainstDeletion};
	use SyncSide::{Left, Right};

	for (from, to, source, target) in [(Left, Right, 0, 1), (Right, Left, 1, 0)] {
		for (key, conflict) in [
			(0x5a, DeletionAgainstUnchanged { absent: to }),
			(0xa5, EditAgainstDeletion { edited: from }),
		] {
			let selected = data(9, key);
			let mut observations = [SyncObservation::AbsentObserved; 2];
			observations[source] = SyncObservation::Present(selected);
			let preview = FirstSyncPreview {
				observations,
				decision: SyncPathDecision::Conflict(conflict),
			};
			assert_eq!(
				held_choice(&preview, from, conflict).unwrap(),
				(source, target, selected)
			);
			assert!(matches!(
				held_choice(&preview, to, conflict),
				Err(ManualRecreateError::ReviewChanged)
			));
			let opposite_approval = match conflict {
				DeletionAgainstUnchanged { .. } => EditAgainstDeletion { edited: from },
				_ => DeletionAgainstUnchanged { absent: to },
			};
			assert!(matches!(
				held_choice(&preview, from, opposite_approval),
				Err(ManualRecreateError::ReviewChanged)
			));
		}
	}
}

#[test]
fn manual_recreate_refuses_nonabsence_and_the_absent_peers_read_ceiling() {
	let selected = data(9, 0x5a);
	let conflict = SyncConflict::DeletionAgainstUnchanged {
		absent: SyncSide::Right,
	};
	for target in [
		SyncObservation::Present(data(9, 0xa5)),
		SyncObservation::Unknown,
		SyncObservation::UnsupportedEntry,
	] {
		let preview = FirstSyncPreview {
			observations: [SyncObservation::Present(selected), target],
			decision: SyncPathDecision::Conflict(conflict),
		};
		assert!(matches!(
			held_choice(&preview, SyncSide::Left, conflict),
			Err(ManualRecreateError::ReviewChanged)
		));
	}
	assert!(check_peer_limit(selected, 9).is_ok());
	assert!(matches!(
		check_peer_limit(selected, 8),
		Err(ManualRecreateError::PeerFileLimit)
	));
	assert!(matches!(
		check_peer_limit(data(MAX_PREVIEW_FILE_BYTES + 1, 0x5a), u64::MAX),
		Err(ManualRecreateError::PeerFileLimit)
	));
}
