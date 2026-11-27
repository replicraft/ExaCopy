use exacopy_model::retained_prefix::Head;

use crate::linux::{
	FileIdentity, RetainedPrefixSelection, StageError, WitnessReservationAuthority,
	WitnessReservationObservationError,
};

/// Exact canonical receipt basenames in the original protected job root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessReceiptNames {
	/// Exact derived pending basename.
	pub pending: [u8; 101],
	/// Exact derived final basename.
	pub final_name: [u8; 99],
}

/// Native identities known before any receipt write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessReceiptIdentity {
	/// Original anonymous receipt inode.
	pub receipt: FileIdentity,
	/// Bound protected job root.
	pub job: FileIdentity,
	/// Bound public parent.
	pub destination: FileIdentity,
}

/// Bounded application-encoded frame for kind 42 or kind 18.
#[derive(Debug)]
pub struct WitnessReceiptAppend {
	/// Exact accepted predecessor.
	pub previous: Head,
	/// Exact proposed successor.
	pub successor: Head,
	/// Complete encoded frame, including framing.
	pub encoded: Vec<u8>,
}

/// Prospective canonical receipt and kind 42.
#[derive(Debug)]
pub struct WitnessReceiptPlan {
	/// Names independently derived from current authenticated replay.
	pub names: WitnessReceiptNames,
	/// Exact canonical bounded receipt bytes.
	pub bytes: Vec<u8>,
	/// Kind 42 to append only after positive physical checks and barriers.
	pub append: WitnessReceiptAppend,
}

/// Each requires separately checked live authority after native probes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessReceiptEffect {
	/// Bounded positioned write to the original reserved anonymous inode.
	Write,
	/// Full file barrier before independently reopening read-only.
	AnonymousFileBarrier,
	/// Exclusive descriptor-bound link in the held job root.
	LinkPending,
	/// Full barrier while the artifact is named only at pending.
	PendingFileBarrier,
	/// Full barrier on the exact job root while pending alone exists.
	PendingJobBarrier,
	/// Append and fully sync kind 42.
	AppendReady,
	/// One same-directory no-replace pending-to-final rename.
	Promote,
	/// Full barrier while the artifact is named only at final.
	FinalFileBarrier,
	/// Full barrier on the exact job root while final alone exists.
	FinalJobBarrier,
	/// Append and fully sync kind 18.
	AppendCommitted,
}

/// Exact receipt effect binding presented to the trusted current grant gate.
#[derive(Clone, Copy, Debug)]
pub struct WitnessReceiptRequest<'name> {
	/// Synchronous effect being requested.
	pub effect: WitnessReceiptEffect,
	/// Exact accepted current boundary.
	pub previous: Head,
	/// Exact proposed next journal boundary.
	pub successor: Head,
	/// Original stage and witnessed public target.
	pub stage: RetainedPrefixSelection<'name>,
	/// Original native identities.
	pub identity: WitnessReceiptIdentity,
	/// Both canonical job-root basenames.
	pub names: &'name WitnessReceiptNames,
	/// Original grant, qualification and retention consent.
	pub authority: WitnessReservationAuthority,
}

/// Strongest same-session observation of a receipt namespace call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WitnessReceiptPlacement {
	/// No receipt namespace call has been entered.
	#[default]
	NoSubmission,
	/// Pending link was submitted. Its positive result has not been confirmed.
	PendingLinkSubmitted,
	/// Kernel reported success creating the pending name.
	PendingLinked,
	/// Promotion was submitted. Its positive result has not been confirmed.
	PromotionSubmitted,
	/// Kernel reported success creating the final name by rename.
	FinalRenamed,
}

/// Failure during one live, non-retryable receipt transition.
#[derive(Debug)]
pub enum WitnessReceiptError<E> {
	/// Exact prior phase, native custody or immutable data could not be confirmed.
	Preflight(WitnessReservationObservationError),
	/// Noncanonical supplied name shape, receipt length or insufficient reserve.
	Bounds,
	/// Application could not build the next selection from exact held history.
	PriorReplay(E),
	/// Independent application replay refused the prospective successor.
	ProposedReplay(E),
	/// The current grant, consent or qualification refused the specified effect.
	Admission {
		/// Refused effect.
		effect: WitnessReceiptEffect,
		/// Original application refusal.
		cause: E,
	},
	/// A submitted write, barrier, link, rename or append did not confirm success.
	Submitted {
		/// Submitted effect.
		effect: WitnessReceiptEffect,
		/// Original syscall error or uncertainty.
		cause: StageError,
	},
	/// Independent native readback after submission failed.
	Readback(WitnessReservationObservationError),
	/// Independent application replay refused the actual held successor.
	SuccessorReplay(E),
}
