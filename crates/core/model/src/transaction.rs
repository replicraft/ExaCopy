use core::fmt;

use crate::identity::CopyBinding;

/// The current abstract phase of one preserve-mode copy attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyPhase {
	/// The copy has yet to prepare a private stage.
	Planned,
	/// The private stage is available for the source transfer.
	Prepared,
	/// All data writers have joined and their permits have been revoked.
	Quiesced,
	/// The stage data flush was reported successful.
	DataFlushed,
	/// Independent stage read-back was reported successful.
	Verified,
	/// Required metadata was reported complete.
	MetadataReady,
	/// The stage was reported sealed and may be the subject of a publication intent.
	ReadyToPublish,
	/// Publication intent has been recorded and a single exclusive publication authorized.
	PublishIntent,
	/// Exclusive publication was reported successful.
	Published,
	/// The required namespace barrier was reported successful.
	DurabilityConfirmed,
	/// A receipt was reported recorded.
	Receipted,
	/// A pre-existing or racing destination was preserved.
	Conflict,
	/// The observed source changed before publication intent.
	SourceChanged,
	/// Stage verification failed.
	VerificationFailed,
	/// The copy encountered an I/O failure before publication intent.
	IoFailed,
	/// This attempt stopped before authorizing publication.
	Cancelled,
	/// Further action requires reconciliation with observed state.
	RecoveryRequired,
}

impl CopyPhase {
	const fn precedes_publish_intent(self) -> bool {
		matches!(
			self,
			Self::Planned
				| Self::Prepared
				| Self::Quiesced
				| Self::DataFlushed
				| Self::Verified
				| Self::MetadataReady
				| Self::ReadyToPublish
		)
	}
}

/// Observations supplied by the executor or journal for the bound attempt.
///
/// The model checks ordering and identity. The caller must establish the underlying facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyEvent {
	/// A private stage was prepared for the attempt.
	StagePrepared,
	/// All writers joined and their write permits were revoked.
	WritersJoined,
	/// The stage data barrier succeeded.
	DataFlushed,
	/// Independent stage read-back satisfied the verification policy.
	ReadbackVerified,
	/// Required metadata was applied and checked.
	MetadataReady,
	/// Stage sealing completed.
	StageSealed,
	/// The publication intent reached the required journal barrier.
	PublishIntentRecorded,
	/// The authorized exclusive publication succeeded.
	Published,
	/// The publication namespace barrier succeeded.
	DirectoryFlushed,
	/// The receipt reached the required journal barrier.
	ReceiptRecorded,
	/// Exclusive publication encountered an incumbent.
	Conflict,
	/// The outcome of a publication or later effect requires recovery.
	OutcomeUncertain,
	/// Cancellation reached a pre-publication boundary.
	Cancelled,
	/// Pre-publication I/O failed.
	IoFailed,
	/// The source observation was invalidated before publication intent.
	SourceChanged,
	/// Independent verification detected a mismatch.
	VerificationFailed,
}

/// A typed request from the model for a preserve-mode operation.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub enum CopyEffect {
	/// Read the source through a read-only handle.
	ReadSource(ReadSource),
	/// Publish the owned stage only through an exclusive creation primitive.
	PublishNoClobber(PublishNoClobber),
}

/// The model's read-only source request. The executor owns the physical handle.
#[derive(Debug, Eq, PartialEq)]
pub struct ReadSource {
	binding: CopyBinding,
}

impl ReadSource {
	/// Returns the attempt to which this request applies.
	#[must_use]
	pub const fn binding(&self) -> CopyBinding {
		self.binding
	}
}

/// An abstract authorization for exclusive publication of the bound stage.
///
/// Executing this decision requires a matching stage handle, destination grant and an
/// adapter whose publication primitive preserves an incumbent atomically.
#[derive(Debug, Eq, PartialEq)]
pub struct PublishNoClobber {
	binding: CopyBinding,
}

impl PublishNoClobber {
	/// Returns the attempt to which this request applies.
	#[must_use]
	pub const fn binding(&self) -> CopyBinding {
		self.binding
	}
}

/// A rejected event leaves the attempt and its effect history unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
	/// The observation belongs to a different job, entry, generation or stage.
	MismatchedBinding,
	/// The observation is out of order or the attempt is already terminal.
	InvalidEvent {
		/// The phase at which the event was rejected.
		phase: CopyPhase,
		/// The rejected kind of event.
		event: CopyEvent,
	},
}

impl fmt::Display for TransitionError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::MismatchedBinding => {
				formatter.write_str("copy observation belongs to another attempt")
			}
			Self::InvalidEvent { phase, event } => {
				write!(
					formatter,
					"copy event {event:?} is invalid in phase {phase:?}"
				)
			}
		}
	}
}

impl core::error::Error for TransitionError {}

/// The sequential state of one copy attempt, with at most one effect per accepted observation.
///
/// Restart requires reconciliation by a separate recovery layer. Construct a session only for a
/// new attempt with a coordinator-assigned binding.
#[derive(Debug)]
pub struct CopySession {
	binding: CopyBinding,
	phase: CopyPhase,
}

impl CopySession {
	/// Creates a planned attempt for the supplied binding.
	#[must_use]
	pub const fn new(binding: CopyBinding) -> Self {
		Self {
			binding,
			phase: CopyPhase::Planned,
		}
	}

	/// Returns the current phase of this attempt.
	#[must_use]
	pub const fn phase(&self) -> CopyPhase {
		self.phase
	}

	/// Applies an observation and returns any newly authorized effect.
	///
	/// # Errors
	///
	/// Returns [`TransitionError`] if the observation belongs to another attempt or the
	/// current phase does not accept the event. A rejected observation issues no effect.
	pub fn apply(
		&mut self,
		binding: CopyBinding,
		event: CopyEvent,
	) -> Result<Option<CopyEffect>, TransitionError> {
		if binding != self.binding {
			return Err(TransitionError::MismatchedBinding);
		}

		let next = match (self.phase, event) {
			(CopyPhase::Planned, CopyEvent::StagePrepared) => CopyPhase::Prepared,
			(CopyPhase::Prepared, CopyEvent::WritersJoined) => CopyPhase::Quiesced,
			(CopyPhase::Quiesced, CopyEvent::DataFlushed) => CopyPhase::DataFlushed,
			(CopyPhase::DataFlushed, CopyEvent::ReadbackVerified) => CopyPhase::Verified,
			(CopyPhase::Verified, CopyEvent::MetadataReady) => CopyPhase::MetadataReady,
			(CopyPhase::MetadataReady, CopyEvent::StageSealed) => CopyPhase::ReadyToPublish,
			(CopyPhase::ReadyToPublish, CopyEvent::PublishIntentRecorded) => {
				CopyPhase::PublishIntent
			}
			(CopyPhase::PublishIntent, CopyEvent::Published) => CopyPhase::Published,
			(CopyPhase::Published, CopyEvent::DirectoryFlushed) => CopyPhase::DurabilityConfirmed,
			(CopyPhase::DurabilityConfirmed, CopyEvent::ReceiptRecorded) => CopyPhase::Receipted,
			(CopyPhase::PublishIntent, CopyEvent::Conflict) => CopyPhase::Conflict,
			(CopyPhase::DataFlushed, CopyEvent::VerificationFailed) => {
				CopyPhase::VerificationFailed
			}
			(
				CopyPhase::PublishIntent | CopyPhase::Published | CopyPhase::DurabilityConfirmed,
				CopyEvent::OutcomeUncertain,
			) => CopyPhase::RecoveryRequired,
			(phase, CopyEvent::Cancelled) if phase.precedes_publish_intent() => {
				CopyPhase::Cancelled
			}
			(phase, CopyEvent::IoFailed) if phase.precedes_publish_intent() => CopyPhase::IoFailed,
			(phase, CopyEvent::SourceChanged) if phase.precedes_publish_intent() => {
				CopyPhase::SourceChanged
			}
			(phase, event) => return Err(TransitionError::InvalidEvent { phase, event }),
		};
		self.phase = next;
		Ok(match next {
			CopyPhase::Prepared => Some(CopyEffect::ReadSource(ReadSource { binding })),
			CopyPhase::PublishIntent => {
				Some(CopyEffect::PublishNoClobber(PublishNoClobber { binding }))
			}
			_ => None,
		})
	}
}
