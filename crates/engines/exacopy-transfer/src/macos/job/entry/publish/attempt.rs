use exacopy_model::CopyBinding;

use crate::macos::receipt::DarwinCopyReceipt;

use super::{
	CopyFailure, PreparedCopy, PreparedEvidence, PublicationJournal, PublicationProgress,
	ReceiptStore, execute,
};

/// The prepared copy that can publish at most once and its last established boundary.
#[derive(Debug)]
pub struct PublicationAttempt<C> {
	copy: Option<C>,
	progress: PublicationProgress,
}

/// A refused or previously consumed publication attempt.
#[derive(Debug)]
pub enum AttemptFailure<A, P, R> {
	/// The prepared copy already consumed its only attempt.
	AlreadyAttempted,
	/// The verification or publication coordinator refused or failed.
	Copy(CopyFailure<A, P, R>),
}

type AttemptError<C, R> = AttemptFailure<
	<C as PreparedCopy>::Error,
	<C as PreparedCopy>::PublishError,
	<R as ReceiptStore>::Error,
>;

impl<C: PreparedCopy> PublicationAttempt<C> {
	/// Binds the private copy before its first attempt.
	#[must_use]
	pub const fn new(copy: C) -> Self {
		Self {
			copy: Some(copy),
			progress: PublicationProgress::Private,
		}
	}

	/// Returns the binding of the unconsumed copy.
	#[must_use]
	pub fn binding(&self) -> Option<CopyBinding> {
		self.copy.as_ref().map(PreparedCopy::binding)
	}

	/// Returns the most recent established publication boundary.
	#[must_use]
	pub const fn progress(&self) -> PublicationProgress {
		self.progress
	}

	/// Consumes the only publication attempt regardless of its result.
	///
	/// # Errors
	/// Refuses a repeated call or returns the exact coordinator or adapter failure.
	pub fn execute<'entry, R: ReceiptStore>(
		&mut self,
		prepared: PreparedEvidence<'_, 'entry>,
		journal: &mut impl PublicationJournal,
		receipts: &R,
		scratch: &mut [u8],
	) -> Result<DarwinCopyReceipt<'entry>, AttemptError<C, R>> {
		let copy = self.copy.take().ok_or(AttemptFailure::AlreadyAttempted)?;
		execute(
			prepared,
			copy,
			journal,
			receipts,
			scratch,
			&mut self.progress,
		)
		.map_err(AttemptFailure::Copy)
	}
}
