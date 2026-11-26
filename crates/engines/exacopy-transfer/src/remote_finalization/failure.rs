use std::io;

use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::remote_download::RemoteDownloadError;
use exacopy_model::TransitionError;

/// The last confirmed operational boundary when finalization stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FinalizationProgress {
	/// No publication intent was attempted.
	BeforeIntent,
	/// A seal is durable. The held stage remains closed and needs replay before restart.
	SealedBeforeIntent,
	/// A pre-intent journal write or observation may have left an uncertain prefix.
	PrivateJournalUncertain,
	/// An intent could have reached the journal. Publication may need reconciliation.
	IntentMayBeRecorded,
	/// The native publication outcome is uncertain.
	PublicationUncertain,
	/// The native adapter confirmed publication. Receipt completion is unresolved.
	PublishedIncomplete,
}

/// Typed failure of a remote publication attempt. Prior material stays in place.
#[derive(Debug)]
pub struct FinalizationFailure<J, A, S, R> {
	/// Last confirmed operational progress.
	pub progress: FinalizationProgress,
	/// Exact last acknowledged journal head, if the coordinator accepted one.
	pub head: ChainHead,
	/// Failed check or adapter operation.
	pub cause: FinalizationCause<J, A, S, R>,
}

/// Precise failure at a finalization boundary.
#[derive(Debug)]
#[non_exhaustive]
pub enum FinalizationCause<J, A, S, R> {
	/// Scope, capture, stage, grant, qualification or head did not agree.
	Binding,
	/// A current incumbent prevented admission. It was preserved.
	TargetOccupied,
	/// The approved target's current state could not be established.
	TargetUnknown,
	/// The first segment cannot hold the bounded completion and reconciliation suffix.
	Capacity,
	/// An entered model transition conflicted with the supplied evidence.
	Model(TransitionError),
	/// The model returned an unexpected effect.
	ModelEffect,
	/// A canonical declaration, receipt or commitment failed structural validation.
	Format(RemoteDownloadError),
	/// The journal could not establish its current exact boundary.
	JournalBoundary(J),
	/// An append could not confirm its original effect.
	Journal {
		/// Frame kind attempted.
		kind: FrameKind,
		/// Exact append error.
		cause: J,
	},
	/// Append result disagreed with the expected exact kind, bytes, head or barrier.
	JournalAcknowledgement(FrameKind),
	/// Current grant, qualification or destination native check failed.
	Authority(A),
	/// Stage metadata readiness or subsequent revalidation failed.
	Stage(S),
	/// Native outcome is uncertain. A failed best-effort observation append retired the writer.
	Publication {
		/// Adapter's actual native publication failure.
		cause: S,
		/// Whether the observed uncertainty was confirmed in the journal.
		observation: Option<ChainHead>,
	},
	/// A receipt namespace operation failed.
	ReceiptNamespace(R),
	/// Writing or synchronizing the receipt file failed.
	ReceiptIo(io::Error),
}

impl<J, A, S, R> FinalizationFailure<J, A, S, R> {
	/// Returns whether further writable activity requires read-only reconciliation.
	#[must_use]
	pub const fn requires_reconciliation(&self) -> bool {
		!matches!(self.progress, FinalizationProgress::BeforeIntent)
	}
}

impl<J: std::fmt::Display, A: std::fmt::Display, S: std::fmt::Display, R: std::fmt::Display>
	std::fmt::Display for FinalizationFailure<J, A, S, R>
{
	fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use FinalizationCause as Cause;
		write!(
			out,
			"remote finalization stopped at journal sequence {} ({:?}): ",
			self.head.sequence(),
			self.progress
		)?;
		match &self.cause {
			Cause::Binding => out.write_str("the selected evidence and held binding disagree"),
			Cause::TargetOccupied => out.write_str("the target is occupied"),
			Cause::TargetUnknown => out.write_str("target absence could not be established"),
			Cause::Capacity => {
				out.write_str("the first journal segment cannot hold completion and reconciliation")
			}
			Cause::Model(cause) => write!(out, "copy transition refused ({cause})"),
			Cause::ModelEffect => out.write_str("copy transition returned an unexpected effect"),
			Cause::Format(cause) => write!(out, "canonical evidence refused ({cause})"),
			Cause::JournalBoundary(cause) => {
				write!(out, "could not confirm journal boundary ({cause})")
			}
			Cause::Journal { kind, cause } => {
				write!(out, "could not synchronize {kind:?} ({cause})")
			}
			Cause::JournalAcknowledgement(kind) => {
				write!(out, "{kind:?} acknowledgement disagrees")
			}
			Cause::Authority(cause) => {
				write!(out, "current publication authority refused ({cause})")
			}
			Cause::Stage(cause) => write!(out, "could not confirm the ready stage ({cause})"),
			Cause::Publication { cause, .. } => {
				write!(out, "native publication requires reconciliation ({cause})")
			}
			Cause::ReceiptNamespace(cause) => write!(out, "receipt namespace failed ({cause})"),
			Cause::ReceiptIo(cause) => {
				write!(out, "receipt write or file barrier failed ({cause})")
			}
		}
	}
}

impl<J, A, S, R> std::error::Error for FinalizationFailure<J, A, S, R>
where
	J: std::error::Error + 'static,
	A: std::error::Error + 'static,
	S: std::error::Error + 'static,
	R: std::error::Error + 'static,
{
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		use FinalizationCause as Cause;
		match &self.cause {
			Cause::Model(cause) => Some(cause),
			Cause::Format(cause) => Some(cause),
			Cause::JournalBoundary(cause) | Cause::Journal { cause, .. } => Some(cause),
			Cause::Authority(cause) => Some(cause),
			Cause::Stage(cause) | Cause::Publication { cause, .. } => Some(cause),
			Cause::ReceiptNamespace(cause) => Some(cause),
			Cause::ReceiptIo(cause) => Some(cause),
			_ => None,
		}
	}
}
