use std::error::Error;
use std::fmt;

use exacopy_endpoint::linux_apply::{ApplyJobRecord, CheckedRenameFailure};
use exacopy_endpoint::linux_publication::FreshReceiptError;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurableJournalError, OwnerError, PublicApplyIntentError, PublicationRecordError,
};
use exacopy_model::TransitionError;

use crate::linux::{
	BootstrapError, CopyError, LocalCopyPlanError, PublicApplyCommitError,
	PublicApplyIntentPreparationError, PublicApplyReceiptError, ReceiptError,
};

/// Why a selected checked operation did not yield a committed public receipt.
#[derive(Debug)]
#[non_exhaustive]
pub enum CheckedApplyError<Phase, Native> {
	/// No public rename was submitted. Private effects may already exist.
	PreIntent(Phase),
	/// Intent may have reached storage, but no public rename was submitted.
	IntentUnconfirmed(Phase),
	/// The exact native submission and settlement classification.
	Rename(CheckedRenameFailure<Native, Phase>),
	/// Rename was acknowledged, but the checked closeout did not complete.
	Published(Phase),
	/// Rename was acknowledged, but subsequent held-inode checks failed.
	PublishedCustody(Native),
}

impl<Phase: fmt::Display, Native: fmt::Display> fmt::Display for CheckedApplyError<Phase, Native> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		use CheckedRenameFailure as Rename;

		match self {
			Self::PreIntent(cause) => write!(formatter, "no public rename submitted: {cause}"),
			Self::IntentUnconfirmed(cause) => {
				write!(formatter, "public intent requires reconciliation: {cause}")
			}
			Self::Published(cause) => write!(
				formatter,
				"publication acknowledged with incomplete closeout: {cause}"
			),
			Self::PublishedCustody(cause) => write!(
				formatter,
				"publication acknowledged with incomplete custody: {cause}"
			),
			Self::Rename(Rename::Preflight(cause)) => {
				write!(formatter, "native publication readiness refused: {cause}")
			}
			Self::Rename(Rename::Refused(cause)) => {
				write!(formatter, "final publication readiness refused: {cause}")
			}
			Self::Rename(Rename::Admission(cause)) => {
				write!(formatter, "publication admission refused: {cause}")
			}
			Self::Rename(Rename::Conflict(cause)) => {
				write!(formatter, "exclusive publication conflict: {cause}")
			}
			Self::Rename(Rename::NotPerformed(cause)) => {
				write!(formatter, "exclusive publication refused: {cause}")
			}
			Self::Rename(Rename::Uncertain { cause, .. }) => {
				write!(formatter, "publication outcome is uncertain: {cause}")
			}
			Self::Rename(Rename::PublishedIncomplete { .. }) => {
				formatter.write_str("publication acknowledged with incomplete native settlement")
			}
			Self::Rename(_) => formatter.write_str("exclusive publication failed"),
		}
	}
}

impl<Phase: Error + 'static, Native: Error + 'static> Error for CheckedApplyError<Phase, Native> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		use CheckedRenameFailure as Rename;

		match self {
			Self::PreIntent(cause)
			| Self::IntentUnconfirmed(cause)
			| Self::Published(cause)
			| Self::Rename(Rename::Refused(cause)) => Some(cause),
			Self::PublishedCustody(cause)
			| Self::Rename(
				Rename::Preflight(cause)
				| Rename::Conflict(cause)
				| Rename::NotPerformed(cause)
				| Rename::Uncertain { cause, .. },
			) => Some(cause),
			Self::Rename(Rename::Admission(cause)) => Some(cause),
			Self::Rename(Rename::PublishedIncomplete {
				observation,
				barriers,
			}) => barriers
				.as_ref()
				.or(observation.as_ref())
				.map(|cause| cause as _),
			Self::Rename(_) => None,
		}
	}
}

/// A specific preparation, qualification, journal or receipt refusal.
#[derive(Debug)]
#[non_exhaustive]
pub enum CheckedCopyError<Read, Stage, Publish, Create, Authority> {
	/// An ordinary checked preparation step failed.
	Preparation(Box<PublicApplyIntentPreparationError<Read, Stage, Publish>>),
	/// Creating this invocation's exclusive private job failed or is uncertain.
	CreateJob(Create),
	/// Original private bootstrap effect failed.
	Bootstrap(BootstrapError<Stage>),
	/// Sealing the original owner or private Plan failed.
	BootstrapRecord(ApplyJobRecord, Stage),
	/// The independently selected source name no longer binds the held source.
	Source(Read),
	/// An original artifact changed or could not be independently read.
	Artifact(Stage),
	/// The actual original owner is invalid.
	Owner(OwnerError),
	/// The reread private Plan is invalid.
	Plan(LocalCopyPlanError),
	/// One exact journal role could not be written or confirmed.
	Journal(FrameKind, DurableJournalError),
	/// Public v2 intent readback did not validate.
	Intent(PublicApplyIntentError),
	/// A publication, durability or receipt record could not be encoded or validated.
	Record(PublicationRecordError),
	/// The held evidence disagrees with the invocation or its expected next phase.
	Binding,
	/// The current authority or its actual qualifying observations refused.
	Authority(Authority),
	/// The original model session refused a checked observation.
	Model(TransitionError),
	/// Native sealing of the original new receipt could not complete.
	ReceiptSeal(FreshReceiptError<Stage>),
	/// The private receipt could not bind the checked streams and durability frame.
	Receipt(ReceiptError),
	/// The public wrapper could not bind the accepted private receipt and intent.
	PublicReceipt(PublicApplyReceiptError),
	/// The exact observed terminal suffix and receipt did not validate jointly.
	Commit(PublicApplyCommitError),
}

impl<R, S, P, C, A> CheckedCopyError<R, S, P, C, A> {
	pub(super) fn proposal(error: PublicApplyIntentPreparationError<R, S, P>) -> Self {
		Self::Preparation(Box::new(error))
	}
}

impl<R, S, P, C, A> From<CopyError<R, S, P>> for CheckedCopyError<R, S, P, C, A> {
	fn from(error: CopyError<R, S, P>) -> Self {
		Self::proposal(PublicApplyIntentPreparationError::Stage(error))
	}
}

impl<R, S, P, C, A> fmt::Display for CheckedCopyError<R, S, P, C, A>
where
	R: fmt::Display,
	S: fmt::Display,
	P: fmt::Display,
	C: fmt::Display,
	A: fmt::Display,
{
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		use PublicApplyIntentPreparationError as Proposal;

		match self {
			Self::Preparation(cause) => match cause.as_ref() {
				Proposal::Stage(cause) => write!(formatter, "private preparation refused: {cause}"),
				Proposal::SealReadback(cause) => {
					write!(formatter, "sealed journal readback refused: {cause}")
				}
				Proposal::Format(cause) => {
					write!(formatter, "public intent encoding refused: {cause}")
				}
				_ => formatter
					.write_str("public apply Plan, time or qualification selection refused"),
			},
			Self::CreateJob(cause) => write!(formatter, "private job creation failed: {cause}"),
			Self::Bootstrap(cause) => write!(formatter, "private bootstrap failed: {cause}"),
			Self::BootstrapRecord(role, cause) => {
				write!(formatter, "private {role:?} record seal failed: {cause}")
			}
			Self::Source(cause) => write!(formatter, "held source name changed: {cause}"),
			Self::Artifact(cause) => write!(formatter, "held artifact observation failed: {cause}"),
			Self::Owner(cause) => write!(formatter, "owner record refused: {cause}"),
			Self::Plan(cause) => write!(formatter, "private Plan refused: {cause}"),
			Self::Journal(kind, cause) => write!(formatter, "journal {kind:?} failed: {cause}"),
			Self::Intent(cause) => write!(formatter, "intent record refused: {cause}"),
			Self::Record(cause) => {
				write!(formatter, "publication evidence record refused: {cause}")
			}
			Self::Binding => {
				formatter.write_str("checked evidence disagrees with the selected operation")
			}
			Self::Authority(cause) => {
				write!(formatter, "current public apply authority refused: {cause}")
			}
			Self::Model(cause) => {
				write!(formatter, "public apply model observation refused: {cause}")
			}
			Self::ReceiptSeal(cause) => write!(formatter, "private receipt seal failed: {cause}"),
			Self::Receipt(cause) => write!(formatter, "copy receipt refused: {cause}"),
			Self::PublicReceipt(cause) => {
				write!(formatter, "public receipt wrapper refused: {cause}")
			}
			Self::Commit(cause) => {
				write!(formatter, "public apply commit evidence refused: {cause}")
			}
		}
	}
}

impl<R, S, P, C, A> Error for CheckedCopyError<R, S, P, C, A>
where
	R: Error + 'static,
	S: Error + 'static,
	P: Error + 'static,
	C: Error + 'static,
	A: Error + 'static,
{
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		use PublicApplyIntentPreparationError as Proposal;
		match self {
			Self::Preparation(cause) => match cause.as_ref() {
				Proposal::Stage(cause) => Some(cause),
				Proposal::SealReadback(cause) => Some(cause),
				Proposal::Format(cause) => Some(cause),
				_ => None,
			},
			Self::CreateJob(cause) => Some(cause),
			Self::Bootstrap(cause) => Some(cause),
			Self::Source(cause) => Some(cause),
			Self::Artifact(cause) | Self::BootstrapRecord(_, cause) => Some(cause),
			Self::Owner(cause) => Some(cause),
			Self::Plan(cause) => Some(cause),
			Self::Journal(_, cause) => Some(cause),
			Self::Intent(cause) => Some(cause),
			Self::Record(cause) => Some(cause),
			Self::Authority(cause) => Some(cause),
			Self::Model(cause) => Some(cause),
			Self::ReceiptSeal(cause) => Some(cause),
			Self::Receipt(cause) => Some(cause),
			Self::PublicReceipt(cause) => Some(cause),
			Self::Commit(cause) => Some(cause),
			Self::Binding => None,
		}
	}
}
