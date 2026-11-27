//! Projects the replay budget and current witness qualification for hosted admission.

use std::num::NonZeroU16;

use exacopy_endpoint::linux_remote_qualification::RemoteDestinationQualification;
use exacopy_journal::StreamLength;
use exacopy_journal::remote_download::finalization_replay::RemoteFinalizationReplay;
use exacopy_journal::remote_download::qualification::continuation::CurrentRemoteWitnessQualification;
use exacopy_journal::remote_download::witness::budget::WitnessedPassBudget;

pub(super) fn witness_projection(
	current: &CurrentRemoteWitnessQualification<'_>,
) -> Option<RemoteDestinationQualification> {
	RemoteDestinationQualification::new(
		current.facts().clone(),
		*current.verified().digest().as_bytes(),
	)
}

pub(super) fn zero_tail_budget(
	replay: &RemoteFinalizationReplay<'_>,
	extent: StreamLength,
) -> Option<WitnessedPassBudget> {
	let active = replay.active_checkpoints().ok()?;
	let consumed = NonZeroU16::new(u16::try_from(replay.attempts().len()).ok()?)?;
	if u64::from(consumed.get()) != active.epochs().run.get() || active.source().length() != extent
	{
		return None;
	}
	WitnessedPassBudget::plan(active.boundary(), extent, extent, consumed).ok()
}

#[cfg(test)]
mod tests {
	use ed25519_dalek::SigningKey;
	use exacopy_journal::OwnerProfileId;
	use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
	use exacopy_journal::remote_download::finalization_replay::replay_remote_finalization_with_checkpoints;
	use exacopy_journal::remote_download::qualification::continuation::{
		RemoteContinuationCoverageProfile, RemoteContinuationOperationProfile,
		RemoteContinuationQualificationScope, RemoteContinuationQualificationTrust,
		verify_remote_witness_qualification,
	};
	use exacopy_journal::remote_download::qualification::{
		RemoteQualificationRouteClass, RemoteQualificationScope,
	};
	use exacopy_journal::remote_download::witness::replay::{
		RemoteWitnessedReplaySelection, replay_remote_witnessed_closeout,
	};
	use exacopy_journal::remote_download::{RemoteBootstrapTrust, RemoteDownloadOwnerRecord};

	use super::super::super::super::activation::{model_head, reservation_plan};
	use super::super::super::{field, hex};
	use super::{StreamLength, witness_projection, zero_tail_budget};

	#[test]
	fn original_capture_budget_and_native_projection_match_signed_next_pass() {
		let profile = OwnerProfileId::from_bytes([0x22; 16]).unwrap();
		let owner_key = SigningKey::from_bytes(&[0x52; 32]).verifying_key();
		let owner = RemoteDownloadOwnerRecord::decode(
			&hex(vector!("remote_finalization/owner.hex")),
			profile,
			&owner_key,
		)
		.unwrap();
		let trust = RemoteBootstrapTrust::new(&owner, profile, &owner_key).unwrap();
		let attestor = SigningKey::from_bytes(&[0x62; 32]).verifying_key();
		let build = [0x61; 32];
		let verified = verify_remote_witness_qualification(
			&field(
				vector!("remote_continuation/witness_closeout.hex"),
				"qualification",
			),
			&RemoteContinuationQualificationTrust {
				attestor: [0x31; 16],
				attestor_key: &attestor,
				owner_key: &owner_key,
				scope: RemoteContinuationQualificationScope {
					common: RemoteQualificationScope {
						build,
						route: RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1,
						campaign_scope: [0x63; 32],
						campaign_evidence: [0x64; 32],
					},
					operation:
						RemoteContinuationOperationProfile::VerifiedRetainedAppendWithWitnessV1,
					coverage:
						RemoteContinuationCoverageProfile::RetainedAppendWithWitnessProcessCrashV1,
				},
			},
		)
		.unwrap();
		let selection = RemoteWitnessedReplaySelection {
			initial_v1_qualification: [0x71; 32],
			fresh_v1_qualification: [0x85; 32],
			qualification: &verified,
			grant_digest: [0x72; 32],
		};
		assert!(
			verified
				.match_current([0x60; 32], verified.facts())
				.is_err()
		);
		let current = verified.match_current(build, verified.facts()).unwrap();
		let projected = witness_projection(&current).unwrap();
		assert_eq!(projected.facts(), verified.facts());
		assert_eq!(&projected.digest(), verified.digest().as_bytes());
		assert_ne!(projected.digest(), selection.initial_v1_qualification);
		assert_ne!(projected.digest(), selection.fresh_v1_qualification);

		let full = field(
			vector!("remote_continuation/witnessed_replay.hex"),
			"published",
		);
		let mut frames = FrameReader::new(full.as_slice(), ChainHead::start());
		let (prior, next) = loop {
			let previous = usize::try_from(frames.offset()).unwrap();
			if frames.next_frame().unwrap().unwrap().kind() == FrameKind::RemoteCaptureContinued {
				break (previous, usize::try_from(frames.offset()).unwrap());
			}
		};
		let original = |bytes| {
			replay_remote_finalization_with_checkpoints(
				bytes,
				&trust,
				selection.initial_v1_qualification,
				None,
			)
			.unwrap()
		};
		let replay = original(&full[..prior]);
		let next_replay =
			replay_remote_witnessed_closeout(&full[..next], &trust, &selection).unwrap();
		let next_capture = next_replay.active_prefix_history().unwrap();
		let extent = next_capture.source().length();
		let budget = zero_tail_budget(&replay, extent).unwrap();
		assert_eq!(budget.boundary(), replay.boundary());
		assert_eq!(budget.checkpoint_count(), 0);
		assert_eq!(
			u64::from(budget.new_run().get()),
			next_capture.epochs().run.get()
		);
		let reservation = reservation_plan(budget).unwrap();
		assert_eq!(reservation.accepted(), model_head(replay.boundary()));
		assert_eq!(reservation.reserve_end(), budget.reserved_end());
		assert_eq!(
			reservation.reserve_frames().get(),
			u64::from(budget.reserved_frames())
		);
		assert!(reservation.reserve_end() > next_replay.boundary().offset);
		assert!(zero_tail_budget(&replay, StreamLength::new(extent.get() + 1).unwrap()).is_none());
		assert!(zero_tail_budget(&original(&full[..prior - 1]), extent).is_none());
		assert!(zero_tail_budget(&original(&full[..next]), extent).is_none());
	}
}
