/// An observed commit boundary of the local transfer effect sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CopyCheckpoint {
	/// Private owner, plan and initial journal frame passed their barriers.
	PlanSynced = 1,
	/// Stage, verification and metadata evidence was synchronized.
	StageSealed,
	/// Fresh-copy publication intent was synchronized.
	IntentSynced,
	/// The exclusive namespace effect and its barriers completed.
	RenamedAndSynced,
	/// The fresh-copy receipt and its directory entries were synchronized.
	ReceiptSynced,
	/// The fresh-copy receipt commitment was synchronized.
	ReceiptCommitted,
	/// The retained-stage retry decision was synchronized.
	RetryDecisionSynced,
	/// The retained-stage retry intent was synchronized.
	RetryIntentSynced,
	/// The retained retry publication and its barriers completed.
	RetryRenamedAndSynced,
	/// A range page passed its file and directory barriers.
	RangePageSynced,
	/// The reference to a range page was synchronized.
	RangeFrameSynced,
	/// The next range resume generation was synchronized.
	RangeResumeStartedSynced,
	/// All resumed stage bytes passed the data barrier.
	RangeResumeDataFlushed,
	/// The range resume publication intent was synchronized.
	RangeResumeIntentSynced,
	/// Fresh copy metadata and its checks completed.
	CopyMetadataApplied,
	/// Resumed metadata and its checks completed.
	RangeResumeMetadataApplied,
}
