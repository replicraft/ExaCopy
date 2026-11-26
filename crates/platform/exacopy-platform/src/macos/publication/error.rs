use std::error::Error;
use std::fmt;
use std::io;

use apfs_mounted::{
	InvalidEntryName,
	publication::{EntrySnapshotError, RenameEvidence, RenameRejection},
};
use rustix::io::Errno;

use super::super::staging::StageError;
use super::super::{ManagedObjectIdentity, ManagedReadError};

/// An attempted exclusive publication did not produce complete success evidence.
#[derive(Debug)]
#[non_exhaustive]
pub enum PublishError {
	/// No rename was issued.
	Rejected {
		/// Precondition that prevented the attempt.
		reason: PublishRejection,
		/// Failure to establish or restore the scoped thread policy, if any.
		policy_error: Option<ManagedReadError>,
	},
	/// Darwin returned EEXIST from the exclusive rename. The stage is retained.
	Conflict {
		/// Failure to restore the scoped thread policy, if any.
		policy_error: Option<ManagedReadError>,
	},
	/// The kernel returned an error without establishing a definite effect.
	Uncertain {
		/// Original Darwin error. Reconcile before further mutation.
		error: io::Error,
		/// Failure to restore the scoped thread policy, if any.
		policy_error: Option<ManagedReadError>,
	},
	/// The kernel reported success, but one or more later checks failed.
	Renamed {
		/// Directory barrier failures, if any. Both barriers were attempted.
		barriers: Option<DirectoryBarrierFailures>,
		/// Failure to independently observe the rename, if any.
		observation: Option<PublishedObservationError>,
		/// Checked target identity when the former stage name was observed absent.
		observed_target: Option<ManagedObjectIdentity>,
		/// Failure to restore the scoped thread policy, if any.
		policy_error: Option<ManagedReadError>,
	},
}

// Debug details are typed and retained in the variants. Display and source
// identify the first relevant error without disclosing filesystem paths.
impl fmt::Display for PublishError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Rejected { reason, .. } => write!(f, "APFS publication rejected ({reason})"),
			Self::Conflict { .. } => f.write_str("APFS publication target already exists"),
			Self::Uncertain { error, .. } => {
				write!(f, "APFS publication outcome uncertain ({error})")
			}
			Self::Renamed { .. } => {
				f.write_str("APFS rename completed with incomplete publication evidence")
			}
		}
	}
}

impl Error for PublishError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Rejected {
				reason: PublishRejection::Policy,
				policy_error: Some(error),
			}
			| Self::Conflict {
				policy_error: Some(error),
			} => Some(error),
			Self::Rejected { reason, .. } => Some(reason),
			Self::Conflict { policy_error: None } => None,
			Self::Uncertain { error, .. } => Some(error),
			Self::Renamed {
				barriers: Some(error),
				..
			} => Some(error),
			Self::Renamed {
				observation: Some(error),
				..
			} => Some(error),
			Self::Renamed { policy_error, .. } => {
				policy_error.as_ref().map(|err| err as &dyn Error)
			}
		}
	}
}

/// The precondition that prevented issuance of an exclusive rename.
#[derive(Debug)]
#[non_exhaustive]
pub enum PublishRejection {
	/// The model authorization refers to another job, entry, epoch, or stage.
	BindingMismatch,
	/// Root or stage evidence changed before the rename.
	Stage(StageError),
	/// The checked name could not be represented in the Darwin ABI.
	Name(InvalidEntryName),
	/// The companion refused the held or named source before calling Darwin.
	Mounted(RenameRejection),
	/// Both directories did not positively report exclusive rename support.
	ExclusiveRenameUnavailable,
	/// A volume capability query failed.
	Volume(io::Error),
	/// The required thread policy could not be established.
	Policy,
}

impl fmt::Display for PublishRejection {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::BindingMismatch => f.write_str("stage does not match authorization"),
			Self::Stage(error) => write!(f, "stage cannot be published ({error})"),
			Self::Mounted(error) => write!(f, "mounted publication refused ({error})"),
			Self::Name(_) => f.write_str("stage or target name could not enter the native call"),
			Self::ExclusiveRenameUnavailable => {
				f.write_str("required exclusive rename capability is unavailable")
			}
			Self::Volume(error) => write!(f, "volume capability query failed ({error})"),
			Self::Policy => f.write_str("required thread policy could not be established"),
		}
	}
}

impl Error for PublishRejection {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Stage(error) => Some(error),
			Self::Name(error) => Some(error),
			Self::Mounted(error) => Some(error),
			Self::Volume(error) => Some(error),
			_ => None,
		}
	}
}

/// Failed directory synchronization calls after a known successful rename.
#[derive(Debug)]
pub struct DirectoryBarrierFailures {
	stage: Option<io::Error>,
	destination: Option<io::Error>,
}

impl DirectoryBarrierFailures {
	pub(super) fn from_results(stage: io::Result<()>, destination: io::Result<()>) -> Option<Self> {
		let stage = stage.err();
		let destination = destination.err();
		(stage.is_some() || destination.is_some()).then_some(Self { stage, destination })
	}

	/// Error from synchronizing the directory that used to contain the stage.
	#[must_use]
	pub const fn stage(&self) -> Option<&io::Error> {
		self.stage.as_ref()
	}

	/// Error from synchronizing the directory that now contains the target.
	#[must_use]
	pub const fn destination(&self) -> Option<&io::Error> {
		self.destination.as_ref()
	}
}

impl fmt::Display for DirectoryBarrierFailures {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match (&self.stage, &self.destination) {
			(Some(stage), Some(destination)) => write!(
				f,
				"stage barrier failed ({stage}) and destination barrier failed ({destination})"
			),
			(Some(error), None) => write!(f, "stage barrier failed ({error})"),
			(None, Some(error)) => write!(f, "destination barrier failed ({error})"),
			(None, None) => f.write_str("missing directory barrier failure detail"),
		}
	}
}

impl Error for DirectoryBarrierFailures {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		self.stage()
			.or(self.destination())
			.map(|err| err as &dyn Error)
	}
}

/// The exclusive rename succeeded, but its resulting names could not be confirmed.
#[derive(Debug)]
#[non_exhaustive]
pub enum PublishedObservationError {
	/// The destination or private staging directory binding changed.
	Directories(Box<StageError>),
	/// The held stage no longer agrees with the required published observation.
	Stage(Box<StageError>),
	/// The private name, target name or held inode disagreed with the rename.
	NamesChanged,
	/// Incomplete post-barrier identity-only observations from the companion.
	MountedNames(Box<RenameEvidence>),
	/// The companion could not establish a coherent post-barrier snapshot.
	MountedSnapshot(Box<EntrySnapshotError>),
	/// A native identity or namespace query failed.
	System(io::Error),
}

impl fmt::Display for PublishedObservationError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Directories(error) => write!(
				f,
				"published directory binding could not be confirmed ({error})"
			),
			Self::Stage(error) => write!(f, "published stage could not be confirmed ({error})"),
			Self::NamesChanged | Self::MountedNames(_) => {
				f.write_str("published names or stage identity changed")
			}
			Self::MountedSnapshot(error) => {
				write!(f, "published entry observation failed ({error})")
			}
			Self::System(error) => write!(f, "published identity query failed ({error})"),
		}
	}
}

impl Error for PublishedObservationError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Directories(error) | Self::Stage(error) => Some(error.as_ref()),
			Self::MountedSnapshot(error) => Some(error.as_ref()),
			Self::System(error) => Some(error),
			Self::NamesChanged | Self::MountedNames(_) => None,
		}
	}
}

impl From<io::Error> for PublishedObservationError {
	fn from(error: io::Error) -> Self {
		Self::System(error)
	}
}

impl From<Errno> for PublishedObservationError {
	fn from(error: Errno) -> Self {
		Self::System(error.into())
	}
}
