use ed25519_dalek::SigningKey;
use exacopy_journal::OwnerProfileId;
use exacopy_journal::frame::{ChainHead, FrameReader};
use exacopy_journal::remote_download::continuation::replay::{
	RemoteContinuationReplay, RemoteContinuationSelection, replay_remote_continuation,
};
use exacopy_journal::remote_download::continuation::{CoverageBasis, PriorPreparation};
use exacopy_journal::remote_download::qualification::continuation::{
	RemoteContinuationCoverageProfile, RemoteContinuationOperationProfile,
	RemoteContinuationQualificationScope, RemoteContinuationQualificationTrust,
	verify_remote_continuation_qualification,
};
use exacopy_journal::remote_download::qualification::{
	RemoteQualificationRouteClass, RemoteQualificationScope,
};
use exacopy_journal::remote_download::{
	MAX_REMOTE_CHECKPOINT_BYTES, RemoteBootstrapTrust, RemoteDownloadError,
	RemoteDownloadOwnerRecord,
};
use exacopy_transfer::remote_resume::prefix::verify_continued_retained_prefix;

use super::{Error, Source, Stage, epoch, epochs, ready};

macro_rules! independent_fixture {
	($name:literal) => {
		include_str!(concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/../../storage/exacopy-journal/tests/",
			$name
		))
	};
}

const STREAM: &[u8] = b"ABCDEFG";
const FRESH: &[u8] = b"ABCDEFGH";
const FRESH_EPOCH: u64 = 10;
const GRANT: [u8; 32] = [0x72; 32];
const NAME: [u8; 255] = {
	let mut name = [b's'; 255];
	name[254] = 0xff;
	name
};

fn hex(text: &str) -> Vec<u8> {
	let canonical: String = text.split_ascii_whitespace().collect();
	let (pairs, remainder) = canonical.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn journal() -> Vec<u8> {
	hex(independent_fixture!(
		"remote_continuation/replay_journal.hex"
	))
}

fn replay(bytes: &[u8]) -> RemoteContinuationReplay {
	let key = SigningKey::from_bytes(&[0x52; 32]).verifying_key();
	let profile = OwnerProfileId::from_bytes([0x22; 16]).unwrap();
	let owner = RemoteDownloadOwnerRecord::decode(
		&hex(independent_fixture!("remote_finalization/owner.hex")),
		profile,
		&key,
	)
	.unwrap();
	let attestor = SigningKey::from_bytes(&[0x62; 32]).verifying_key();
	let qualification = verify_remote_continuation_qualification(
		&hex(independent_fixture!(
			"remote_continuation/replay_qualification.hex"
		)),
		&RemoteContinuationQualificationTrust {
			attestor: [0x31; 16],
			attestor_key: &attestor,
			owner_key: &key,
			scope: RemoteContinuationQualificationScope {
				common: RemoteQualificationScope {
					build: [0x61; 32],
					route: RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1,
					campaign_scope: [0x63; 32],
					campaign_evidence: [0x64; 32],
				},
				operation: RemoteContinuationOperationProfile::VerifiedRetainedAppendV1,
				coverage: RemoteContinuationCoverageProfile::RetainedAppendProcessCrashV1,
			},
		},
	)
	.unwrap();
	replay_remote_continuation(
		bytes,
		&RemoteBootstrapTrust::new(&owner, profile, &key).unwrap(),
		&RemoteContinuationSelection {
			legacy_qualification: [0x71; 32],
			qualification: &qualification,
			grant_digest: GRANT,
		},
	)
	.unwrap()
}

fn boundary_at(bytes: &[u8], sequence: u64) -> (usize, ChainHead) {
	let mut reader = FrameReader::new(bytes, ChainHead::start());
	while let Some(frame) = reader.next_frame().unwrap() {
		if frame.head().sequence() == sequence {
			return (usize::try_from(reader.offset()).unwrap(), frame.head());
		}
	}
	panic!("missing fixture frame {sequence}");
}

fn source(bytes: &[u8]) -> Source<'_> {
	Source {
		epoch: epoch(FRESH_EPOCH),
		..Source::new(bytes)
	}
}

fn stage(bytes: &[u8]) -> Stage<'_> {
	Stage {
		name: &NAME,
		file: 13,
		..Stage::new(bytes)
	}
}

#[test]
fn independent_aggregate_and_suffix_are_both_freshly_verified_from_zero() {
	let bytes = journal();
	let scan = replay(&bytes);
	let history = scan.active_prefix_history().unwrap();
	let (_, original) = boundary_at(&bytes, 4);
	let (_, continued) = boundary_at(&bytes, 6);
	let (_, latest) = boundary_at(&bytes, 8);
	let ranges: Vec<_> = history.ranges().collect();
	assert_eq!(
		ranges
			.iter()
			.map(|range| (range.offset, range.length))
			.collect::<Vec<_>>(),
		[(0, 4), (4, 1), (5, 2)]
	);
	for (range, payload) in ranges.iter().zip([&b"ABCD"[..], &b"E"[..], &b"FG"[..]]) {
		assert_eq!(range.digest.as_bytes(), blake3::hash(payload).as_bytes());
	}
	let mut remote = source(FRESH);
	let local = stage(STREAM);
	let proof = ready(verify_continued_retained_prefix(
		&scan,
		&mut remote,
		epoch(FRESH_EPOCH),
		&local,
		&mut [0; 4],
	))
	.unwrap();
	assert_eq!(proof.digest(), *blake3::hash(STREAM).as_bytes());
	assert_eq!(proof.extent(), 7);
	assert_eq!(proof.checkpoint_extent(), 7);
	assert_eq!(proof.source_length(), 8);
	assert_eq!(proof.previous_epochs(), epochs(2, 9));
	assert_eq!(proof.stage().head, original);
	assert_eq!(
		proof.active_preparation(),
		PriorPreparation::Continued(continued)
	);
	assert_eq!(proof.boundary(), scan.boundary());
	assert_eq!(proof.recorded_grant(), Some(GRANT));
	assert_eq!(
		proof.expected_qualification(),
		history.expected_qualification()
	);
	assert_eq!(
		proof.coverage_basis(),
		CoverageBasis::Checkpoint {
			head: latest,
			ordinal: 2
		}
	);
	assert!(std::ptr::eq(proof.into_source(), &remote));
	assert_eq!(remote.reads, [(0, 2), (2, 2), (4, 1), (5, 2)]);
	assert_eq!(*local.reads.borrow(), remote.reads);
	assert_eq!((remote.checks, local.checks.get()), (2, 2));

	for index in 0..STREAM.len() {
		let mut changed = STREAM.to_vec();
		changed[index] ^= 0xff;
		let expected_offset = [0, 0, 0, 0, 4, 5, 5][index];
		let mut wrong_remote = source(&changed);
		assert!(matches!(
			ready(verify_continued_retained_prefix(
				&scan, &mut wrong_remote, epoch(FRESH_EPOCH), &local, &mut [0; 4],
			)),
			Err(Error::SourceMismatch { offset }) if offset == expected_offset
		));
		let wrong_local = stage(&changed);
		assert!(matches!(
			ready(verify_continued_retained_prefix(
				&scan, &mut wrong_remote, epoch(FRESH_EPOCH), &wrong_local, &mut [0; 4],
			)),
			Err(Error::CheckpointMismatch { offset }) if offset == expected_offset
		));
	}
}

#[test]
fn continued_zero_suffix_tail_and_active_extent_bounds_fail_closed() {
	let bytes = journal();
	let (legacy, _) = boundary_at(&bytes, 5);
	let (after_first_suffix, _) = boundary_at(&bytes, 7);
	let zero = hex(independent_fixture!(
		"remote_continuation/replay_zero_tail.hex"
	));
	let scan = replay(&zero);
	let local = stage(b"ABCD");
	let mut remote = source(b"ABCD");
	let proof = ready(verify_continued_retained_prefix(
		&scan,
		&mut remote,
		epoch(FRESH_EPOCH),
		&local,
		&mut [0; 3],
	))
	.unwrap();
	assert_eq!(proof.digest(), *blake3::hash(b"ABCD").as_bytes());
	assert_eq!(proof.checkpoint_extent(), 4);
	assert_eq!(
		proof.coverage_basis(),
		CoverageBasis::ContinuedPrefix(scan.boundary().head)
	);

	let scan = replay(&bytes[..after_first_suffix]);
	let mut remote = source(FRESH);
	let local = stage(STREAM);
	let proof = ready(verify_continued_retained_prefix(
		&scan,
		&mut remote,
		epoch(FRESH_EPOCH),
		&local,
		&mut [0; 4],
	))
	.unwrap();
	assert_eq!(proof.digest(), *blake3::hash(STREAM).as_bytes());
	assert_eq!(proof.extent(), 7);
	assert_eq!(proof.checkpoint_extent(), 5);
	assert_eq!(proof.into_source().reads, [(0, 2), (2, 2), (4, 1), (5, 2)]);
	let mut remote = source(b"ABCDEZH");
	assert!(matches!(
		ready(verify_continued_retained_prefix(
			&scan,
			&mut remote,
			epoch(FRESH_EPOCH),
			&local,
			&mut [0; 4],
		)),
		Err(Error::TailMismatch { offset: 5 })
	));

	let mut remote = source(FRESH);
	assert!(matches!(
		ready(verify_continued_retained_prefix(
			&scan,
			&mut remote,
			epoch(FRESH_EPOCH),
			&stage(FRESH),
			&mut [0; 4],
		)),
		Err(Error::RetainedBeyondPrior {
			extent: 8,
			prior: 7
		})
	));
	assert!(matches!(
		ready(verify_continued_retained_prefix(
			&scan,
			&mut remote,
			epoch(FRESH_EPOCH),
			&stage(b"ABCD"),
			&mut [0; 4],
		)),
		Err(Error::RetainedExtent {
			extent: 4,
			checkpoint: 5
		})
	));
	let huge = Stage {
		length: MAX_REMOTE_CHECKPOINT_BYTES + 6,
		..stage(STREAM)
	};
	assert!(matches!(
		ready(verify_continued_retained_prefix(
			&scan,
			&mut remote,
			epoch(FRESH_EPOCH),
			&huge,
			&mut [0; 4],
		)),
		Err(Error::RetainedExtent { checkpoint: 5, .. })
	));
	let mut too_long = Source {
		reported_length: Some(1_000_000_001),
		..source(FRESH)
	};
	assert!(matches!(
		ready(verify_continued_retained_prefix(
			&scan,
			&mut too_long,
			epoch(FRESH_EPOCH),
			&local,
			&mut [0; 4],
		)),
		Err(Error::SourceLimit {
			length: 1_000_000_001,
			limit: 1_000_000_000
		})
	));
	assert!(remote.reads.is_empty());
	assert!(too_long.reads.is_empty());

	for prior_epoch in [8, 9] {
		remote.epoch = epoch(prior_epoch);
		assert!(matches!(
			ready(verify_continued_retained_prefix(
				&scan,
				&mut remote,
				epoch(prior_epoch),
				&local,
				&mut [0; 4],
			)),
			Err(Error::Epoch)
		));
	}
	assert!(remote.reads.is_empty());
	for input in [&bytes[..legacy], &bytes[..bytes.len() - 1]] {
		let scan = replay(input);
		assert!(matches!(
			ready(verify_continued_retained_prefix(
				&scan,
				&mut remote,
				epoch(FRESH_EPOCH),
				&local,
				&mut [0; 4],
			)),
			Err(Error::History(RemoteDownloadError::Binding))
		));
	}
	assert!(remote.reads.is_empty());
}

#[test]
fn interrupted_continued_comparison_cannot_return_partial_hasher_or_drop_original_guard() {
	let scan = replay(&journal());
	let mut remote = Source {
		failed_read: Some(2),
		..source(FRESH)
	};
	let local = stage(STREAM);
	assert!(matches!(
		ready(verify_continued_retained_prefix(
			&scan,
			&mut remote,
			epoch(FRESH_EPOCH),
			&local,
			&mut [0; 4],
		)),
		Err(Error::SourceRead {
			offset: 2,
			cause: "interrupted window"
		})
	));
	assert_eq!(*local.reads.borrow(), [(0, 2)]);
	let mut remote = source(FRESH);
	let local = Stage {
		rebound: true,
		..stage(STREAM)
	};
	assert!(matches!(
		ready(verify_continued_retained_prefix(
			&scan,
			&mut remote,
			epoch(FRESH_EPOCH),
			&local,
			&mut [0; 4],
		)),
		Err(Error::StageIdentity)
	));
	assert_eq!(local.checks.get(), 2);
}
