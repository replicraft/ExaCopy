//! Application composition for a private Linux remote-download job.

use std::fmt;
use std::io;
use std::num::NonZeroU64;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::connection_retry::RetryError;
use exacopy_journal::frame::FrameReadError;
use exacopy_journal::remote_download::finalization_replay::RemoteFinalizationPhase;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::{RemoteDownloadContext, RemoteDownloadError, RemoteEpochs};
use exacopy_journal::{DurableJournalError, JournalJobId, LinuxFileIdentity};
use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};
use exacopy_platform::linux::{
	FileIdentity, ReadError, RemoteDestinationEligibilityError, StageError,
};
use exacopy_transfer::remote_metadata::RemoteMetadataRefusal;
use uuid::Uuid;

use crate::profile::ProfileError;

mod admission;
mod lease;
mod ledger;
mod receipt;

pub(super) use admission::{CurrentGrant, RemoteActivation};
pub(super) use lease::{RemoteJobLease, bootstrap};
pub(super) use ledger::{IntentReadback, RemoteJobJournal};

#[cfg(test)]
mod tests;

pub(super) fn component(bytes: &[u8]) -> Result<UnixComponent<'_>, Error> {
	UnixComponent::new(bytes).map_err(|_| Error::Binding)
}

fn job_name(job: JournalJobId) -> String {
	format!(".exacopy-{}", Uuid::from_bytes(*job.as_bytes()))
}

pub(super) fn record_identity(identity: FileIdentity) -> LinuxFileIdentity {
	LinuxFileIdentity::new(identity.device(), identity.inode())
}

fn binding(
	context: RemoteDownloadContext,
	epochs: RemoteEpochs,
	nonce: [u8; 16],
) -> Result<CopyBinding, Error> {
	let job = JobId::try_from_bytes(*context.job.as_bytes()).map_err(|_| Error::Binding)?;
	Ok(CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(epochs.run.get()),
		StageId::from_bytes(nonce),
	))
}

fn next_epochs(previous: Option<RemoteEpochs>, source: NonZeroU64) -> Result<RemoteEpochs, Error> {
	let run = match previous {
		None => NonZeroU64::MIN,
		Some(previous) if source > previous.source => {
			previous.run.checked_add(1).ok_or(Error::Attempt)?
		}
		Some(_) => return Err(Error::Attempt),
	};
	Ok(RemoteEpochs { run, source })
}

#[derive(Debug)]
pub enum Error {
	Binding,
	Attempt,
	Conflict,
	UnknownStage,
	Stopped,
	Grant(RetryError),
	UnsupportedRoute,
	Metadata(RemoteMetadataRefusal),
	Qualification(RemoteDestinationEligibilityError),
	Lifecycle {
		phase: RemoteFinalizationPhase,
		boundary: RemoteReplayBoundary,
		issue: Option<ReplayIssue>,
	},
	Frame(FrameReadError),
	Read(ReadError),
	Native(StageError),
	Io(io::Error),
	Format(RemoteDownloadError),
	Journal(DurableJournalError),
	Profile(ProfileError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayIssue {
	PreBootstrap,
	Torn,
	Refused,
}

impl fmt::Display for Error {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Binding => formatter.write_str("remote job authority or native binding changed"),
			Self::Attempt => {
				formatter.write_str("remote job attempt exceeds its scope or uses stale labels")
			}
			Self::Conflict => formatter.write_str("a target or private stage name is occupied"),
			Self::UnknownStage => {
				formatter.write_str("private stage provenance needs reconciliation")
			}
			Self::Grant(cause) => cause.fmt(formatter),
			Self::Stopped => formatter.write_str("remote job writer requires reconciliation"),
			Self::UnsupportedRoute => {
				formatter.write_str("remote job route lacks a writable owner profile")
			}
			Self::Metadata(cause) => cause.fmt(formatter),
			Self::Qualification(cause) => cause.fmt(formatter),
			Self::Lifecycle {
				phase,
				boundary,
				issue,
			} => write!(
				formatter,
				"remote job needs reconciliation at {phase:?} after byte {} ({issue:?})",
				boundary.offset
			),
			Self::Frame(cause) => cause.fmt(formatter),
			Self::Read(cause) => cause.fmt(formatter),
			Self::Native(cause) => cause.fmt(formatter),
			Self::Io(cause) => cause.fmt(formatter),
			Self::Format(cause) => cause.fmt(formatter),
			Self::Journal(cause) => cause.fmt(formatter),
			Self::Profile(cause) => cause.fmt(formatter),
		}
	}
}

impl std::error::Error for Error {}

impl From<StageError> for Error {
	fn from(cause: StageError) -> Self {
		Self::Native(cause)
	}
}

impl From<ReadError> for Error {
	fn from(cause: ReadError) -> Self {
		Self::Read(cause)
	}
}

impl From<io::Error> for Error {
	fn from(cause: io::Error) -> Self {
		Self::Io(cause)
	}
}

impl From<FrameReadError> for Error {
	fn from(cause: FrameReadError) -> Self {
		Self::Frame(cause)
	}
}

impl From<RemoteDownloadError> for Error {
	fn from(cause: RemoteDownloadError) -> Self {
		Self::Format(cause)
	}
}

impl From<DurableJournalError> for Error {
	fn from(cause: DurableJournalError) -> Self {
		Self::Journal(cause)
	}
}

impl From<ProfileError> for Error {
	fn from(cause: ProfileError) -> Self {
		Self::Profile(cause)
	}
}

#[derive(Debug)]
pub(super) struct BootstrapIdentity {
	job: FileIdentity,
	boundary: RemoteReplayBoundary,
}
