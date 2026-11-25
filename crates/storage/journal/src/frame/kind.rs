/// Allocated envelope kind. Payload support is checked separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum FrameKind {
	/// Job owner and policy established.
	JobPrepared = 1,
	/// Exclusive stage and target bound.
	EntryPrepared = 2,
	/// Verified range evidence referenced.
	RangeCheckpoint = 3,
	/// Stage writes complete and joined.
	StageSealed = 4,
	/// Read-back evidence recorded.
	VerificationRecorded = 5,
	/// Required metadata evidence recorded.
	MetadataRecorded = 6,
	/// Exclusive publication intent recorded.
	PublishIntent = 7,
	/// Publication outcome observed.
	PublishObserved = 8,
	/// Completed namespace barriers recorded.
	DurabilityRecorded = 9,
	/// Protected incumbent capture intended.
	IncumbentCaptureIntent = 10,
	/// Incumbent capture observed.
	IncumbentCaptured = 11,
	/// Protected source retirement intended.
	SourceRetireIntent = 12,
	/// Source quarantine observed.
	SourceRetired = 13,
	/// Conflict evidence and options recorded.
	ConflictRecorded = 14,
	/// Failure and uncertain effects recorded.
	FailureRecorded = 15,
	/// Requested cancellation recorded.
	CancellationRequested = 16,
	/// Checkpoint and owned inventory referenced.
	JobCheckpoint = 17,
	/// Final receipt committed.
	ReceiptCommitted = 18,
	/// Recovery started under a new epoch.
	RecoveryStarted = 19,
	/// Recovery observations and decision recorded.
	RecoveryDecision = 20,
	/// Authorized ownership transfer recorded.
	OwnershipTakeover = 21,
	/// Resume evidence bound.
	ResumeBound = 22,
	/// New connection generation recorded.
	ConnectionGenerationStarted = 23,
	/// Previously completed ranges rechecked.
	RangeRevalidated = 24,
	/// Remote effect outcome uncertain.
	RemoteEffectUncertain = 25,
	/// Remote effect reconciled.
	RemoteEffectReconciled = 26,
	/// Synchronization action intended.
	SyncActionIntent = 27,
	/// Synchronization action observed.
	SyncActionObserved = 28,
	/// Synchronization baseline advancement intended.
	SyncBaselineIntent = 29,
	/// Synchronization baseline committed.
	SyncBaselineCommitted = 30,
	/// Device binding evidence recorded.
	DeviceBindingValidated = 31,
	/// Forward lease observed.
	ForwardLeaseObserved = 32,
	/// Installer transaction intended.
	InstallIntent = 33,
	/// Installer effect observed.
	InstallObserved = 34,
	/// Installer receipt committed.
	InstallCommitted = 35,
	/// Credential acquisition blocked.
	CredentialBlocked = 36,
}

impl FrameKind {
	/// Returns this kind's numeric envelope discriminator.
	#[must_use]
	pub const fn code(self) -> u16 {
		self as u16
	}

	pub(super) fn from_code(code: u16) -> Option<Self> {
		Some(match code {
			code if code == Self::JobPrepared.code() => Self::JobPrepared,
			code if code == Self::EntryPrepared.code() => Self::EntryPrepared,
			code if code == Self::RangeCheckpoint.code() => Self::RangeCheckpoint,
			code if code == Self::StageSealed.code() => Self::StageSealed,
			code if code == Self::VerificationRecorded.code() => Self::VerificationRecorded,
			code if code == Self::MetadataRecorded.code() => Self::MetadataRecorded,
			code if code == Self::PublishIntent.code() => Self::PublishIntent,
			code if code == Self::PublishObserved.code() => Self::PublishObserved,
			code if code == Self::DurabilityRecorded.code() => Self::DurabilityRecorded,
			code if code == Self::IncumbentCaptureIntent.code() => Self::IncumbentCaptureIntent,
			code if code == Self::IncumbentCaptured.code() => Self::IncumbentCaptured,
			code if code == Self::SourceRetireIntent.code() => Self::SourceRetireIntent,
			code if code == Self::SourceRetired.code() => Self::SourceRetired,
			code if code == Self::ConflictRecorded.code() => Self::ConflictRecorded,
			code if code == Self::FailureRecorded.code() => Self::FailureRecorded,
			code if code == Self::CancellationRequested.code() => Self::CancellationRequested,
			code if code == Self::JobCheckpoint.code() => Self::JobCheckpoint,
			code if code == Self::ReceiptCommitted.code() => Self::ReceiptCommitted,
			code if code == Self::RecoveryStarted.code() => Self::RecoveryStarted,
			code if code == Self::RecoveryDecision.code() => Self::RecoveryDecision,
			code if code == Self::OwnershipTakeover.code() => Self::OwnershipTakeover,
			code if code == Self::ResumeBound.code() => Self::ResumeBound,
			code if code == Self::ConnectionGenerationStarted.code() => {
				Self::ConnectionGenerationStarted
			}
			code if code == Self::RangeRevalidated.code() => Self::RangeRevalidated,
			code if code == Self::RemoteEffectUncertain.code() => Self::RemoteEffectUncertain,
			code if code == Self::RemoteEffectReconciled.code() => Self::RemoteEffectReconciled,
			code if code == Self::SyncActionIntent.code() => Self::SyncActionIntent,
			code if code == Self::SyncActionObserved.code() => Self::SyncActionObserved,
			code if code == Self::SyncBaselineIntent.code() => Self::SyncBaselineIntent,
			code if code == Self::SyncBaselineCommitted.code() => Self::SyncBaselineCommitted,
			code if code == Self::DeviceBindingValidated.code() => Self::DeviceBindingValidated,
			code if code == Self::ForwardLeaseObserved.code() => Self::ForwardLeaseObserved,
			code if code == Self::InstallIntent.code() => Self::InstallIntent,
			code if code == Self::InstallObserved.code() => Self::InstallObserved,
			code if code == Self::InstallCommitted.code() => Self::InstallCommitted,
			code if code == Self::CredentialBlocked.code() => Self::CredentialBlocked,
			_ => return None,
		})
	}
}
