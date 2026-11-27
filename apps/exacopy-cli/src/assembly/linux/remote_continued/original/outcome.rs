use exacopy_journal::remote_download::finalization_policy::{SftpDataOnlyV1, SftpOmission};
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_model::retained_prefix::Head;
use exacopy_platform::linux::StageError;
use exacopy_platform::linux::WitnessPublicationObservation;
use exacopy_sftp::SftpSourceError;
use exacopy_transfer::remote_resume::prefix::PrefixVerificationError;

use super::super::witness::WitnessAdmissionError;
use super::super::witness::positive_tail::PositiveTailCause;
use super::super::witness::publication::WitnessedReceiptProgress;

#[derive(Debug)]
pub(crate) enum OriginalWitnessError {
	/// Selected job, original capture boundary, or held records disagreed.
	Startup,
	/// The live destination and independent OP2 selection did not match.
	Qualification,
	/// Current scope grant or explicit retention approval was refused.
	Authority,
	/// The authenticated source could not be observed or held.
	Source(SftpSourceError),
	/// The current prefix, positive tail or required capacity was refused.
	Prefix,
}

/// Preserves authority and transport refusals from the current prefix reader.
pub(super) fn prefix_error(
	cause: PrefixVerificationError<SftpSourceError, StageError>,
) -> OriginalWitnessError {
	match cause {
		PrefixVerificationError::SourceObservation(cause)
		| PrefixVerificationError::SourceRead { cause, .. }
		| PrefixVerificationError::SourceFinish(cause) => OriginalWitnessError::Source(cause),
		PrefixVerificationError::StageObservation(_)
		| PrefixVerificationError::StageRead { .. } => OriginalWitnessError::Startup,
		_ => OriginalWitnessError::Prefix,
	}
}

pub(super) fn preflight_error(cause: PositiveTailCause) -> OriginalWitnessError {
	match cause {
		PositiveTailCause::Gate(
			WitnessAdmissionError::Consent(_) | WitnessAdmissionError::Route(_),
		) => OriginalWitnessError::Authority,
		PositiveTailCause::Binding
		| PositiveTailCause::Prior(_)
		| PositiveTailCause::Stage(_)
		| PositiveTailCause::Gate(WitnessAdmissionError::Custody(_)) => OriginalWitnessError::Startup,
		_ => OriginalWitnessError::Prefix,
	}
}

#[derive(Debug)]
pub(crate) enum OriginalWitnessResult {
	/// Exact publication, durable receipt and final commitment were confirmed.
	Published {
		committed: RemoteReplayBoundary,
		canonical_receipt: Vec<u8>,
		receipt_digest: [u8; 32],
		length: u64,
		witness_links: u64,
		metadata_omissions: &'static [SftpOmission],
	},
	/// Exact native incumbent conflict with a confirmed kind 8 record.
	Conflict,
	/// The incumbent was preserved, but the outcome record requires reconciliation.
	ConflictUnconfirmed,
	/// The protected public inode was observed, but journal closeout is incomplete.
	PublishedUnconfirmed { witness_links: u64 },
	/// The native call did not establish publication or definite conflict.
	PublicationUncertain,
	/// An attempted continuation requires reconciliation without a confirmed public result.
	ReconcileBeforeConfirmedPublication { last_confirmed_capture: Head },
}

pub(super) fn project(
	observation: &WitnessPublicationObservation,
	progress: WitnessedReceiptProgress,
) -> OriginalWitnessResult {
	project_observed(
		match observation {
			WitnessPublicationObservation::Published(stamp) => Observed::Published {
				length: stamp.len(),
				witness_links: stamp.link_count(),
			},
			WitnessPublicationObservation::Conflict(_) => Observed::Conflict,
			WitnessPublicationObservation::Reconcile { .. } => Observed::Uncertain,
		},
		progress,
	)
}

#[derive(Clone, Copy)]
enum Observed {
	Published { length: u64, witness_links: u64 },
	Conflict,
	Uncertain,
}

fn project_observed(
	observation: Observed,
	progress: WitnessedReceiptProgress,
) -> OriginalWitnessResult {
	use OriginalWitnessResult as Result;
	match observation {
		Observed::Published {
			length,
			witness_links,
		} => {
			if let (Ok(_), Some(Ok(_)), Some(Ok(receipt))) = progress {
				Result::Published {
					committed: receipt.committed,
					canonical_receipt: receipt.bytes,
					receipt_digest: receipt.digest,
					length,
					witness_links,
					metadata_omissions: SftpDataOnlyV1::omissions(),
				}
			} else {
				Result::PublishedUnconfirmed { witness_links }
			}
		}
		Observed::Conflict if progress.0.is_ok() => Result::Conflict,
		Observed::Conflict => Result::ConflictUnconfirmed,
		Observed::Uncertain => Result::PublicationUncertain,
	}
}

#[cfg(test)]
mod tests {
	use exacopy_journal::frame::ChainHead;
	use exacopy_platform::linux::ContinuationReservationError;

	use super::super::super::witness::publication::WitnessedObservationError;
	use super::super::super::witness::publication::receipt::WitnessedReceiptCompletion;
	use super::{
		Observed, OriginalWitnessResult as Result, RemoteReplayBoundary, project_observed,
	};

	fn boundary() -> RemoteReplayBoundary {
		RemoteReplayBoundary {
			head: ChainHead::after(18, [1; 32]).unwrap(),
			offset: 320,
		}
	}

	#[test]
	fn source_refusal_is_kept_separate_from_retained_content_mismatch() {
		use super::{OriginalWitnessError, PrefixVerificationError, SftpSourceError, prefix_error};
		use exacopy_endpoint::connection_retry::{RetryBlock, RetryError};

		assert!(matches!(
			super::preflight_error(super::PositiveTailCause::Gate(
				super::WitnessAdmissionError::Consent(
					crate::assembly::linux::remote_witness_authority::ConsentRefusal::Clock,
				),
			)),
			OriginalWitnessError::Authority
		));
		assert!(matches!(
			super::preflight_error(super::PositiveTailCause::Gate(
				super::WitnessAdmissionError::Custody(
					exacopy_platform::linux::WitnessReservationObservationError::Native(
						exacopy_platform::linux::StageError::IdentityChanged,
					),
				),
			)),
			OriginalWitnessError::Startup
		));
		let refusal = PrefixVerificationError::SourceRead {
			offset: 0,
			cause: SftpSourceError::Binding(RetryError::Blocked(RetryBlock::GrantExpired)),
		};
		assert!(matches!(
			prefix_error(refusal),
			OriginalWitnessError::Source(SftpSourceError::Binding(RetryError::Blocked(
				RetryBlock::GrantExpired
			)))
		));
		assert!(matches!(
			prefix_error(PrefixVerificationError::SourceRead {
				offset: 0,
				cause: SftpSourceError::ReadTimeout,
			}),
			OriginalWitnessError::Source(SftpSourceError::ReadTimeout)
		));
		assert!(matches!(
			prefix_error(PrefixVerificationError::SourceMismatch { offset: 0 }),
			OriginalWitnessError::Prefix
		));
	}

	#[test]
	fn confirmed_native_result_without_receipt_is_never_success() {
		let end = boundary();
		assert!(matches!(
			project_observed(
				Observed::Published {
					length: 4,
					witness_links: 2
				},
				(Ok(end), Some(Ok(end)), None),
			),
			Result::PublishedUnconfirmed { witness_links: 2 }
		));
		assert!(matches!(
			project_observed(Observed::Uncertain, (Ok(end), None, None)),
			Result::PublicationUncertain
		));
		assert!(matches!(
			project_observed(Observed::Conflict, (Ok(end), None, None)),
			Result::Conflict
		));
	}

	#[test]
	fn observed_conflict_without_a_confirmed_record_requires_reconciliation() {
		assert!(matches!(
			project_observed(
				Observed::Conflict,
				(
					Err(WitnessedObservationError::Journal(
						ContinuationReservationError::Bounds
					)),
					None,
					None
				),
			),
			Result::ConflictUnconfirmed
		));
	}

	#[test]
	fn confirmed_receipt_is_returned_only_for_the_actual_published_result() {
		let end = boundary();
		let completion = WitnessedReceiptCompletion {
			ready: end,
			committed: end,
			bytes: vec![2, 3],
			digest: [3; 32],
		};
		let outcome = project_observed(
			Observed::Published {
				length: 4,
				witness_links: 2,
			},
			(Ok(end), Some(Ok(end)), Some(Ok(completion))),
		);
		let Result::Published {
			committed,
			canonical_receipt,
			receipt_digest,
			length,
			witness_links,
			metadata_omissions,
		} = outcome
		else {
			panic!("expected committed publication");
		};
		assert_eq!(committed, end);
		assert_eq!(canonical_receipt, [2, 3]);
		assert_eq!(receipt_digest, [3; 32]);
		assert_eq!(length, 4);
		assert_eq!(witness_links, 2);
		assert_eq!(metadata_omissions, super::SftpDataOnlyV1::omissions());
	}
}
