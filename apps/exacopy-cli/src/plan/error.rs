use std::error::Error;
use std::fmt;
use std::io;

use crate::assembly::linux::NativePlanningError;
use exacopy_platform::linux::{PlanBundleError, PlanSeedError};
use exacopy_transfer::copy_planning::PlanningError;
use exacopy_transfer::public_plan::BundleWriteError;
use rustix::io::Errno;

use crate::profile::ProfileError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
	Invalid,
	Root,
	Profile,
	Clock,
	Entropy,
	Conflict,
	SourceForbidden,
	Planning,
	Encoding,
	BundleScope,
	BundleUnsafe,
	BundleConflict,
	AlreadyExists,
	BundleIo,
	ReuseRead,
}

pub(super) struct Failure {
	kind: Kind,
	source: Option<Box<dyn Error + Send + Sync>>,
}

impl Failure {
	pub(super) const fn plain(kind: Kind) -> Self {
		Self { kind, source: None }
	}

	pub(super) fn with(kind: Kind, source: impl Error + Send + Sync + 'static) -> Self {
		Self {
			kind,
			source: Some(Box::new(source)),
		}
	}

	pub(super) fn profile(error: ProfileError) -> Self {
		Self::with(Kind::Profile, ProfileCause(error))
	}

	pub(super) fn entropy(error: ProfileError) -> Self {
		Self::with(Kind::Entropy, ProfileCause(error))
	}

	pub(super) fn from_planning(error: NativePlanningError) -> Self {
		let kind = match &error {
			PlanningError::InvalidIdentity | PlanningError::InvalidBuffer => Kind::Invalid,
			PlanningError::Conflict => Kind::Conflict,
			PlanningError::SourceForbidden => Kind::SourceForbidden,
			_ => Kind::Planning,
		};
		Self::with(kind, error)
	}

	pub(super) fn bundle(error: PlanBundleError) -> Self {
		match error {
			PlanBundleError::InvalidOutput => Self::plain(Kind::Invalid),
			PlanBundleError::Scope(None) => Self::plain(Kind::BundleScope),
			PlanBundleError::Scope(Some(error)) => Self::with(Kind::BundleScope, error),
			PlanBundleError::Unsafe(None) => Self::plain(Kind::BundleUnsafe),
			PlanBundleError::Unsafe(Some(error)) => Self::with(Kind::BundleUnsafe, error),
			PlanBundleError::Conflict => Self::plain(Kind::BundleConflict),
			PlanBundleError::AlreadyExists(error) => Self::with(Kind::AlreadyExists, error),
			PlanBundleError::Io(error) => Self::with(Kind::BundleIo, error),
			PlanBundleError::ReuseRead(error) => Self::with(Kind::ReuseRead, error),
			_ => Self::with(Kind::BundleIo, error),
		}
	}

	pub(super) fn bundle_write(error: BundleWriteError<PlanBundleError>) -> Self {
		match error {
			BundleWriteError::PageName(error) => Self::with(Kind::Encoding, error),
			BundleWriteError::Output(error) => Self::bundle(error),
			_ => Self::with(Kind::BundleIo, error),
		}
	}

	pub(super) fn seed_observation(error: PlanSeedError) -> Self {
		match error {
			PlanSeedError::Unsafe => Self::plain(Kind::Profile),
			PlanSeedError::Io(error) => Self::with(Kind::Profile, error),
			_ => Self::with(Kind::Profile, error),
		}
	}

	pub(super) fn exit_code(&self) -> u8 {
		match self.kind {
			Kind::Invalid | Kind::Root | Kind::Profile | Kind::SourceForbidden => 2,
			Kind::Conflict | Kind::BundleConflict | Kind::AlreadyExists => 3,
			Kind::BundleScope | Kind::BundleUnsafe => 6,
			_ => 4,
		}
	}
}

impl fmt::Debug for Failure {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		out.debug_struct("PlanFailure")
			.field("kind", &self.kind)
			.finish_non_exhaustive()
	}
}

impl fmt::Display for Failure {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self.kind {
			Kind::Invalid => "the source, destination, or output selection is invalid",
			Kind::Root => "could not bind the selected source or destination parent",
			Kind::Profile => "could not bind the existing owner profile",
			Kind::Clock => "the current clock is outside the supported plan range",
			Kind::Entropy => "could not obtain plan identifier entropy",
			Kind::Conflict => "the selected destination is occupied",
			Kind::SourceForbidden => "the owner profile seed is outside the allowed source scope",
			Kind::Planning => "could not obtain the required read-only planning observations",
			Kind::Encoding => "could not encode the public plan",
			Kind::BundleScope => {
				"the explicit bundle overlaps a protected input or its mount ancestry is uncertain"
			}
			Kind::BundleUnsafe => {
				"the output parent or page storage is not a protected private directory"
			}
			Kind::BundleConflict | Kind::AlreadyExists => {
				"an existing plan output or page conflicts with this export"
			}
			Kind::BundleIo => "plan export failed; any created bundle files are retained",
			Kind::ReuseRead => "could not safely verify an incumbent plan page",
		};
		out.write_str(message)?;
		if let Some(code) = os_code(self.source()) {
			write!(out, " (OS error {code})")?;
		}
		Ok(())
	}
}

impl Error for Failure {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		self.source.as_deref().map(|source| source as &dyn Error)
	}
}

fn os_code(mut cause: Option<&(dyn Error + 'static)>) -> Option<i32> {
	for _ in 0..8 {
		let error = cause?;
		if let Some(io) = error.downcast_ref::<io::Error>() {
			if let Some(code) = io.raw_os_error() {
				return Some(code);
			}
			cause = io.get_ref().map(|cause| cause as &dyn Error);
			continue;
		}
		if let Some(errno) = error.downcast_ref::<Errno>() {
			return Some(errno.raw_os_error());
		}
		cause = error.source();
	}
	None
}

#[derive(Debug)]
struct ProfileCause(ProfileError);

impl fmt::Display for ProfileCause {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		out.write_str("owner profile operation failed")
	}
}

impl Error for ProfileCause {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		self.0.io_error().map(|error| error as _)
	}
}
