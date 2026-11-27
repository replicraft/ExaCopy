use std::cell::{Cell, RefCell};
use std::num::NonZeroU16;

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::remote_download::finalization::RemoteLocalMetadata;
use exacopy_journal::remote_download::finalization_replay::replay_remote_finalization_with_checkpoints;
use exacopy_journal::remote_download::qualification::continuation::{
	RemoteContinuationCoverageProfile, RemoteContinuationOperationProfile,
	RemoteContinuationQualificationScope, RemoteContinuationQualificationTrust,
	VerifiedRemoteWitnessQualification, verify_remote_witness_qualification,
};
use exacopy_journal::remote_download::qualification::{
	RemoteQualificationRouteClass, RemoteQualificationScope,
};
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::budget::WitnessedPassBudget;
use exacopy_journal::remote_download::witness::replay::{
	PreparedWitnessedCloseout, RemoteWitnessedReplaySelection, replay_remote_witnessed_closeout,
};
use exacopy_journal::remote_download::{RemoteBootstrapTrust, RemoteDownloadOwnerRecord};
use exacopy_journal::{OwnerProfileId, StreamLength};
use exacopy_transfer::remote_resume::prefix::SuffixSourceObservation;
use exacopy_transfer::remote_witnessed_finalization::{
	HeldWitnessPrepublication, WitnessedAppendError, WitnessedLiveCut,
	WitnessedPrepublicationCause, WitnessedPrepublicationRequest, prepare_witnessed_publication,
};

use super::{HeldSource, ReadView, Reader, epoch, ready, stage, verify_held_retained_prefix};

#[path = "prepublication/recovery.rs"]
mod recovery;

const CONTENT: &[u8] = b"ABCD";
const VERIFIED_METADATA: RemoteLocalMetadata = RemoteLocalMetadata {
	uid: 1001,
	gid: 1002,
};
const LEGACY_ARCHIVE: [u8; 32] = [0x71; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
	None,
	Read,
	Digest,
	SourceEpoch,
	BudgetRun,
	UnavailableJournal,
	Metadata,
	MetadataChanges,
	WrongPolicyIds,
	Consent,
	DefinitiveAppendRefusal,
	UnknownBeforeAppend,
	UncertainAppend,
	FalseAcknowledgement,
	HistoricalSeal,
}

#[derive(Debug)]
struct Holder<'evidence> {
	journal: &'evidence mut Vec<u8>,
	source: SuffixSourceObservation,
	boundary: RemoteReplayBoundary,
	events: &'evidence RefCell<Vec<FrameKind>>,
	fault: Fault,
	metadata_reads: Cell<usize>,
}

impl ReadView for Holder<'_> {
	type Error = &'static str;

	fn length(&self) -> u64 {
		CONTENT.len() as u64
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		Ok(())
	}

	fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
		if self.fault == Fault::Read {
			return Err("independent read failed");
		}
		let bytes = if self.fault == Fault::Digest {
			b"ABCE"
		} else {
			CONTENT
		};
		let start = usize::try_from(offset).unwrap();
		output.copy_from_slice(&bytes[start..start + output.len()]);
		Ok(())
	}
}

impl HeldWitnessPrepublication for Holder<'_> {
	type JournalRead<'held>
		= &'held [u8]
	where
		Self: 'held;

	fn source(&self) -> &SuffixSourceObservation {
		&self.source
	}

	fn check_live(&self, cut: WitnessedLiveCut<'_, '_>) -> Result<(), Self::Error> {
		if cut.previous != self.boundary {
			return Err("wrong live cut");
		}
		if self.fault == Fault::Consent && self.metadata_reads.get() == 2 {
			return Err("retention consent lost");
		}
		Ok(())
	}

	fn read_journal(&self) -> Result<Self::JournalRead<'_>, Self::Error> {
		if self.fault == Fault::UnavailableJournal {
			return Err("independent journal unavailable");
		}
		Ok(self.journal.as_slice())
	}

	fn check_metadata(&self) -> Result<RemoteLocalMetadata, Self::Error> {
		let reads = self.metadata_reads.get();
		self.metadata_reads.set(reads + 1);
		match self.fault {
			Fault::Metadata => Err("metadata barrier missing"),
			Fault::WrongPolicyIds => Ok(RemoteLocalMetadata {
				uid: 1000,
				..VERIFIED_METADATA
			}),
			Fault::MetadataChanges if reads != 0 => Ok(RemoteLocalMetadata {
				gid: 1003,
				..VERIFIED_METADATA
			}),
			_ => Ok(VERIFIED_METADATA),
		}
	}

	fn append(
		&mut self,
		cut: WitnessedLiveCut<'_, '_>,
		frame: &PreparedWitnessedCloseout,
	) -> Result<(), WitnessedAppendError<Self::Error>> {
		self.check_live(cut)
			.map_err(WitnessedAppendError::Refused)?;
		assert_eq!(cut.previous, frame.previous());
		self.events.borrow_mut().push(frame.kind());
		if frame.kind() == FrameKind::PublishIntent {
			match self.fault {
				Fault::UnknownBeforeAppend => {
					return Err(WitnessedAppendError::Unconfirmed("custody unconfirmed"));
				}
				Fault::DefinitiveAppendRefusal => {
					return Err(WitnessedAppendError::Refused("preflight"));
				}
				Fault::UncertainAppend | Fault::FalseAcknowledgement => {
					self.journal
						.extend_from_slice(&frame.encoded()[..frame.encoded().len() - 1]);
					return if self.fault == Fault::UncertainAppend {
						Err(WitnessedAppendError::Uncertain("sync failed"))
					} else {
						Ok(())
					};
				}
				_ => {}
			}
		}
		self.journal.extend_from_slice(frame.encoded());
		self.boundary = frame.successor();
		Ok(())
	}
}

fn vector(text: &str, label: &str) -> Vec<u8> {
	super::super::hex(
		text.lines()
			.find_map(|line| line.strip_prefix(label)?.strip_prefix(' '))
			.unwrap(),
	)
}

fn boundary_of(full: &[u8], kind: FrameKind) -> RemoteReplayBoundary {
	let mut reader = FrameReader::new(full, ChainHead::start());
	while let Some(frame) = reader.next_frame().unwrap() {
		if frame.kind() == kind {
			return RemoteReplayBoundary {
				head: frame.head(),
				offset: reader.offset(),
			};
		}
	}
	panic!("independent transcript lacks {kind:?}");
}

fn owner_record(profile: OwnerProfileId, owner_key: &VerifyingKey) -> RemoteDownloadOwnerRecord {
	RemoteDownloadOwnerRecord::decode(
		&super::super::hex(independent_fixture!("remote_finalization/owner.hex")),
		profile,
		owner_key,
	)
	.unwrap()
}

fn witness_qualification(owner_key: &VerifyingKey) -> VerifiedRemoteWitnessQualification {
	let attestor = SigningKey::from_bytes(&[0x62; 32]).verifying_key();
	verify_remote_witness_qualification(
		&vector(
			independent_fixture!("remote_continuation/witness_closeout.hex"),
			"qualification",
		),
		&RemoteContinuationQualificationTrust {
			attestor: [0x31; 16],
			attestor_key: &attestor,
			owner_key,
			scope: RemoteContinuationQualificationScope {
				common: RemoteQualificationScope {
					build: [0x61; 32],
					route: RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1,
					campaign_scope: [0x63; 32],
					campaign_evidence: [0x64; 32],
				},
				operation: RemoteContinuationOperationProfile::VerifiedRetainedAppendWithWitnessV1,
				coverage:
					RemoteContinuationCoverageProfile::RetainedAppendWithWitnessProcessCrashV1,
			},
		},
	)
	.unwrap()
}

fn exercise(fault: Fault, expected: &[FrameKind], evidence: FrameKind, reconcile: bool) {
	let profile = OwnerProfileId::from_bytes([0x22; 16]).unwrap();
	let owner_key = SigningKey::from_bytes(&[0x52; 32]).verifying_key();
	let owner = owner_record(profile, &owner_key);
	let trust = RemoteBootstrapTrust::new(&owner, profile, &owner_key).unwrap();
	let qualification = witness_qualification(&owner_key);
	// This is a synthetic native-facts fixture. The real adapter selects current observations.
	let current = qualification
		.match_current([0x61; 32], qualification.facts())
		.unwrap();
	let selection = RemoteWitnessedReplaySelection {
		initial_v1_qualification: LEGACY_ARCHIVE,
		fresh_v1_qualification: [0x85; 32],
		qualification: &qualification,
		grant_digest: [0x72; 32],
	};
	let full = vector(
		independent_fixture!("remote_continuation/witnessed_replay.hex"),
		"published",
	);
	let witness_cut = boundary_of(&full, FrameKind::RemoteWitnessIntent);
	let mut journal = full[..witness_cut.offset as usize].to_vec();
	let scanned = replay_remote_witnessed_closeout(journal.as_slice(), &trust, &selection).unwrap();
	let witness = scanned.witness().unwrap();
	let start = boundary_of(&full, FrameKind::RangeCheckpoint);
	let previous = replay_remote_finalization_with_checkpoints(
		&full[..start.offset as usize],
		&trust,
		LEGACY_ARCHIVE,
		None,
	)
	.unwrap();
	let history = previous
		.active_checkpoints()
		.unwrap()
		.prefix_history()
		.unwrap();
	let alive = Cell::new(true);
	let file_rebound = Cell::new(false);
	let epoch =
		epoch(witness.binding().epochs().source.get() + u64::from(fault == Fault::SourceEpoch));
	let mut live_source = HeldSource::new(CONTENT, &alive);
	live_source.inner.epoch = epoch;
	let captured = ready(verify_held_retained_prefix(
		&history,
		&mut live_source,
		epoch,
		Reader {
			stage: stage(CONTENT),
			alive: &alive,
			file_rebound: &file_rebound,
		},
		&mut [0; 4],
	))
	.unwrap();
	let (source, original) =
		ready(captured.with_reader(async |source| source.finish().await.unwrap()));
	let extent = StreamLength::new(CONTENT.len() as u64).unwrap();
	let consumed = NonZeroU16::new(1 + u16::from(fault == Fault::BudgetRun)).unwrap();
	let budget = WitnessedPassBudget::plan(start, extent, extent, consumed).unwrap();
	let events = RefCell::new(Vec::new());
	let boundary = if fault == Fault::HistoricalSeal {
		let sealed = boundary_of(&full, FrameKind::StageSealed);
		journal = full[..sealed.offset as usize].to_vec();
		sealed
	} else {
		witness_cut
	};
	let holder = Holder {
		journal: &mut journal,
		source,
		boundary,
		events: &events,
		fault,
		metadata_reads: Cell::new(0),
	};
	let outcome = prepare_witnessed_publication(
		WitnessedPrepublicationRequest {
			trust: &trust,
			selection: &selection,
			current: &current,
			witness,
			budget,
		},
		holder,
		&mut [0; 2],
	);
	let last = boundary_of(&full, evidence);
	if fault == Fault::None {
		let result = outcome.unwrap();
		assert_eq!(result.boundary(), last);
		let (held, cut) = result.into_parts();
		assert_eq!(held.boundary, cut);
		assert_eq!(held.metadata_reads.get(), 2);
	} else {
		let refusal = outcome.unwrap_err();
		let confirmed = (last != witness_cut).then_some(last);
		assert_eq!(refusal.confirmed, confirmed, "{fault:?}");
		assert_eq!(refusal.requires_reconciliation, reconcile, "{fault:?}");
		match fault {
			Fault::Read => assert!(matches!(
				refusal.cause,
				WitnessedPrepublicationCause::ReadBack(_)
			)),
			Fault::Digest => assert!(matches!(
				refusal.cause,
				WitnessedPrepublicationCause::Verification
			)),
			Fault::UncertainAppend => assert!(matches!(
				refusal.cause,
				WitnessedPrepublicationCause::Append {
					error: WitnessedAppendError::Uncertain(_),
					..
				}
			)),
			_ => {}
		}
	}
	assert_eq!(&*events.borrow(), expected);
	let accepted_length = match fault {
		Fault::UncertainAppend | Fault::FalseAcknowledgement => {
			boundary_of(&full, FrameKind::PublishIntent).offset as usize - 1
		}
		Fault::HistoricalSeal => boundary.offset as usize,
		_ => last.offset as usize,
	};
	assert_eq!(journal, &full[..accepted_length]);
	drop(original);
	assert!(!alive.get());
}

#[test]
fn live_prepublication_appends_exact_seal_verification_metadata_and_intent() {
	use FrameKind::*;
	exercise(
		Fault::None,
		&[
			StageSealed,
			VerificationRecorded,
			MetadataRecorded,
			PublishIntent,
		],
		PublishIntent,
		false,
	);
}

#[test]
fn live_prepublication_stops_without_reissuing_any_uncertain_frame() {
	use FrameKind::*;
	let to_metadata = &[StageSealed, VerificationRecorded, MetadataRecorded];
	let intent_attempted = &[
		StageSealed,
		VerificationRecorded,
		MetadataRecorded,
		PublishIntent,
	];
	for (fault, steps, last, reconcile) in [
		(Fault::SourceEpoch, &[][..], RemoteWitnessIntent, false),
		(Fault::BudgetRun, &[][..], RemoteWitnessIntent, false),
		(
			Fault::UnavailableJournal,
			&[][..],
			RemoteWitnessIntent,
			true,
		),
		(Fault::Read, &[StageSealed][..], StageSealed, true),
		(Fault::Digest, &[StageSealed][..], StageSealed, true),
		(
			Fault::Metadata,
			&[StageSealed, VerificationRecorded][..],
			VerificationRecorded,
			true,
		),
		(
			Fault::WrongPolicyIds,
			&[StageSealed, VerificationRecorded][..],
			VerificationRecorded,
			true,
		),
		(
			Fault::MetadataChanges,
			&to_metadata[..],
			MetadataRecorded,
			true,
		),
		(Fault::Consent, &to_metadata[..], MetadataRecorded, true),
		(
			Fault::DefinitiveAppendRefusal,
			&intent_attempted[..],
			MetadataRecorded,
			false,
		),
		(
			Fault::UnknownBeforeAppend,
			&intent_attempted[..],
			MetadataRecorded,
			true,
		),
		(
			Fault::UncertainAppend,
			&intent_attempted[..],
			MetadataRecorded,
			true,
		),
		(
			Fault::FalseAcknowledgement,
			&intent_attempted[..],
			MetadataRecorded,
			true,
		),
		(Fault::HistoricalSeal, &[][..], RemoteWitnessIntent, true),
	] {
		exercise(fault, steps, last, reconcile);
	}
}
