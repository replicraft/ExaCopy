use std::cell::{Cell, RefCell};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::ReadView;
use exacopy_journal::OwnerProfileId;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::remote_download::RemoteBootstrapTrust;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::replay::{
	RemoteWitnessedPublicExpectation, RemoteWitnessedReplaySelection,
};
use exacopy_transfer::remote_witnessed_finalization::WitnessedAppendError;
use exacopy_transfer::remote_witnessed_recovery::{
	HeldWitnessRecovery, WitnessedRecoveryCause, WitnessedRecoveryCut, WitnessedRecoveryRequest,
	record_recovered_witness_observation,
};

use super::{CONTENT, LEGACY_ARCHIVE, boundary_of, owner_record, vector, witness_qualification};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
	Published,
	StillPrivate,
	WitnessOnly,
	CustodyLostDuringRead,
	PublicDigestChanged,
	AlreadyRecorded,
	DifferentNativeEof,
	DifferentAcceptedSuccessor,
	JournalReboundDuringConfirmation,
	UncertainAppend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservationError {
	PrivateStagePresent,
	TargetAbsent,
	WitnessReplaced,
	JournalRebound,
	SyncUncertain,
}

#[derive(Default)]
struct Observations {
	journal_reads: Cell<usize>,
	data_reads: RefCell<Vec<(u64, usize)>>,
	append_attempts: Vec<FrameKind>,
}

struct Held<'fixture> {
	scenario: Scenario,
	journal: &'fixture mut Vec<u8>,
	separate_reread: &'fixture [u8],
	observations: &'fixture mut Observations,
}

impl ReadView for Held<'_> {
	type Error = ObservationError;

	fn length(&self) -> u64 {
		CONTENT.len() as u64
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		// The original open target still reads correctly after replacement of its witness name.
		Ok(())
	}

	fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
		let bytes = if self.scenario == Scenario::PublicDigestChanged {
			b"ABCE"
		} else {
			CONTENT
		};
		let start = usize::try_from(offset).expect("fixture uses small positioned offsets");
		output.copy_from_slice(&bytes[start..start + output.len()]);
		self.observations
			.data_reads
			.borrow_mut()
			.push((offset, output.len()));
		Ok(())
	}
}

impl HeldWitnessRecovery for Held<'_> {
	type JournalRead<'held>
		= &'held [u8]
	where
		Self: 'held;

	fn read_journal(&self) -> Result<(Self::JournalRead<'_>, u64), Self::Error> {
		let calls = self.observations.journal_reads.get();
		self.observations.journal_reads.set(calls + 1);
		let bytes = if self.scenario == Scenario::DifferentAcceptedSuccessor
			&& !self.observations.append_attempts.is_empty()
		{
			self.separate_reread
		} else {
			self.journal.as_slice()
		};
		let native_end =
			bytes.len() as u64 + u64::from(self.scenario == Scenario::DifferentNativeEof);
		Ok((bytes, native_end))
	}

	fn recheck_journal(&self, _expected: RemoteReplayBoundary) -> Result<(), Self::Error> {
		if self.scenario == Scenario::JournalReboundDuringConfirmation
			&& !self.observations.append_attempts.is_empty()
		{
			return Err(ObservationError::JournalRebound);
		}
		Ok(())
	}

	fn check_public(
		&self,
		_expected: &RemoteWitnessedPublicExpectation<'_>,
	) -> Result<(), Self::Error> {
		match self.scenario {
			Scenario::StillPrivate => Err(ObservationError::PrivateStagePresent),
			Scenario::WitnessOnly => Err(ObservationError::TargetAbsent),
			Scenario::CustodyLostDuringRead
				if !self.observations.data_reads.borrow().is_empty() =>
			{
				Err(ObservationError::WitnessReplaced)
			}
			_ => Ok(()),
		}
	}

	fn append_recovered_observation(
		&mut self,
		cut: WitnessedRecoveryCut<'_, '_, '_>,
	) -> Result<(), WitnessedAppendError<Self::Error>> {
		let frame = cut.frame();
		assert_eq!(
			frame.previous(),
			cut.expected().boundary(),
			"append is bound to the exact independently read intent"
		);
		assert_eq!(
			frame.previous().offset,
			self.journal.len() as u64,
			"submitted append begins at the actual held EOF"
		);
		self.observations.append_attempts.push(frame.kind());
		self.journal.extend_from_slice(frame.encoded());
		if self.scenario == Scenario::UncertainAppend {
			return Err(WitnessedAppendError::Uncertain(
				ObservationError::SyncUncertain,
			));
		}
		Ok(())
	}
}

fn exercise(scenario: Scenario) {
	let profile = OwnerProfileId::from_bytes([0x22; 16]).unwrap();
	let owner_key = SigningKey::from_bytes(&[0x52; 32]).verifying_key();
	let owner = owner_record(profile, &owner_key);
	let trust = RemoteBootstrapTrust::new(&owner, profile, &owner_key).unwrap();
	let qualification = witness_qualification(&owner_key);
	let current = qualification
		.match_current([0x61; 32], qualification.facts())
		.unwrap();
	let selection = RemoteWitnessedReplaySelection {
		initial_v1_qualification: LEGACY_ARCHIVE,
		fresh_v1_qualification: [0x85; 32],
		qualification: &qualification,
		grant_digest: [0x72; 32],
	};

	let vectors = independent_fixture!("remote_continuation/witnessed_replay.hex");
	let recovered = vector(vectors, "recovered");
	let live = vector(vectors, "published");
	let live_end = boundary_of(&live, FrameKind::PublishObserved).offset as usize;
	let intent = boundary_of(&recovered, FrameKind::PublishIntent);
	let original = if scenario == Scenario::AlreadyRecorded {
		recovered.as_slice()
	} else {
		&recovered[..intent.offset as usize]
	};
	let mut journal = original.to_vec();
	let mut observations = Observations::default();
	let result = record_recovered_witness_observation(
		WitnessedRecoveryRequest {
			trust: &trust,
			selection: &selection,
			current: &current,
		},
		Held {
			scenario,
			journal: &mut journal,
			separate_reread: &live[..live_end],
			observations: &mut observations,
		},
		&mut [0; 2],
	);

	let reads = observations.data_reads.into_inner();
	if matches!(
		scenario,
		Scenario::StillPrivate
			| Scenario::WitnessOnly
			| Scenario::AlreadyRecorded
			| Scenario::DifferentNativeEof
	) {
		assert!(reads.is_empty(), "{scenario:?} attempted public read-back");
	} else {
		assert_eq!(
			reads,
			[(0, 2), (2, 2)],
			"{scenario:?} lacked whole-file read-back"
		);
	}
	let submitted = matches!(
		scenario,
		Scenario::Published
			| Scenario::DifferentAcceptedSuccessor
			| Scenario::JournalReboundDuringConfirmation
			| Scenario::UncertainAppend
	);
	if submitted {
		assert_eq!(
			observations.append_attempts,
			[FrameKind::PublishObserved],
			"{scenario:?}"
		);
		assert_eq!(
			journal, recovered,
			"{scenario:?} emitted bytes other than canonical tag 4"
		);
	} else {
		assert!(
			observations.append_attempts.is_empty(),
			"{scenario:?} authorized append"
		);
		assert_eq!(journal, original, "{scenario:?} changed the journal");
	}

	if scenario == Scenario::Published {
		assert_eq!(
			result.expect("fresh complete observation authorizes one recovered append"),
			boundary_of(&recovered, FrameKind::PublishObserved),
		);
		assert!(
			observations.journal_reads.get() >= 2,
			"append was never independently confirmed"
		);
		return;
	}
	let failure = result.expect_err("this history or observation must require reconciliation");
	let exact_intent = !matches!(
		scenario,
		Scenario::AlreadyRecorded | Scenario::DifferentNativeEof
	);
	assert_eq!(
		failure.confirmed,
		exact_intent.then_some(intent),
		"{scenario:?}"
	);
	match scenario {
		Scenario::CustodyLostDuringRead => assert!(matches!(
			failure.cause,
			WitnessedRecoveryCause::Native(ObservationError::WitnessReplaced)
		)),
		Scenario::PublicDigestChanged => {
			assert!(matches!(
				failure.cause,
				WitnessedRecoveryCause::Verification
			));
		}
		Scenario::DifferentAcceptedSuccessor => {
			assert!(
				observations.journal_reads.get() >= 2,
				"never read the divergent successor"
			);
		}
		Scenario::JournalReboundDuringConfirmation => assert!(matches!(
			failure.cause,
			WitnessedRecoveryCause::Native(ObservationError::JournalRebound)
		)),
		Scenario::UncertainAppend => assert!(matches!(
			failure.cause,
			WitnessedRecoveryCause::Append(WitnessedAppendError::Uncertain(
				ObservationError::SyncUncertain
			))
		)),
		_ => {}
	}
}

#[test]
fn recovered_kind_eight_matches_the_independent_tag_four_vector() {
	exercise(Scenario::Published);
}

#[test]
fn historical_intent_does_not_establish_current_publication_or_custody() {
	for scenario in [
		Scenario::StillPrivate,
		Scenario::WitnessOnly,
		Scenario::CustodyLostDuringRead,
		Scenario::PublicDigestChanged,
	] {
		exercise(scenario);
	}
}

#[test]
fn recovery_requires_a_clean_intent_and_an_independently_confirmed_exact_successor() {
	for scenario in [
		Scenario::AlreadyRecorded,
		Scenario::DifferentNativeEof,
		Scenario::DifferentAcceptedSuccessor,
		Scenario::JournalReboundDuringConfirmation,
		Scenario::UncertainAppend,
	] {
		exercise(scenario);
	}
}
