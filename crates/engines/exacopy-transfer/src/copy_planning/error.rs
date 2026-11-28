use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use exacopy_plan::{DocumentError, PlanError};

use crate::{linux_staging::StageFailure, manifest};

/// Planning stopped without a complete public plan.
#[derive(Debug)]
#[non_exhaustive]
pub enum PlanningError<Source, Target> {
	/// An identity was malformed or the selected paths or root aliases were contradictory.
	InvalidIdentity,
	/// The selected expiry did not follow Plan creation.
	InvalidExpiry,
	/// The supplied stream buffer fell outside the supported bound.
	InvalidBuffer,
	/// An existing object occupied the selected target.
	Conflict,
	/// The selected target could not be observed safely.
	ObserveTarget(Target),
	/// The selected source did not open as an admitted named read view.
	OpenSource(Source),
	/// The held source was excluded by the independent caller policy.
	SourceForbidden,
	/// The named source did not satisfy the source metadata policy.
	SourcePolicy(StageFailure<Source, Infallible>),
	/// A complete rechecked stream measurement could not be obtained.
	Measure(manifest::Error<Source>),
	/// The canonical leaf encoder rejected an entry.
	Page(DocumentError),
	/// The canonical body encoder rejected the plan.
	Body(PlanError),
}

impl<S: fmt::Display, D: fmt::Display> fmt::Display for PlanningError<S, D> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidIdentity => formatter.write_str("plan identity or root alias is invalid"),
			Self::InvalidExpiry => formatter.write_str("plan expiry must follow creation"),
			Self::InvalidBuffer => {
				formatter.write_str("plan measurement buffer is outside its bound")
			}
			Self::Conflict => formatter.write_str("the selected target is occupied"),
			Self::ObserveTarget(error) => {
				write!(formatter, "could not observe the target ({error})")
			}
			Self::OpenSource(error) => write!(formatter, "could not open the source ({error})"),
			Self::SourceForbidden => formatter.write_str("the held source is excluded by policy"),
			Self::SourcePolicy(error) => write!(formatter, "source policy failed ({error})"),
			Self::Measure(error) => write!(formatter, "source measurement failed ({error})"),
			Self::Page(error) => write!(formatter, "could not encode plan entry ({error})"),
			Self::Body(error) => write!(formatter, "could not encode plan body ({error})"),
		}
	}
}

impl<S: Error + 'static, D: Error + 'static> Error for PlanningError<S, D> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::ObserveTarget(error) => Some(error),
			Self::OpenSource(error) => Some(error),
			Self::SourcePolicy(error) => Some(error),
			Self::Measure(error) => Some(error),
			Self::Page(error) => Some(error),
			Self::Body(error) => Some(error),
			_ => None,
		}
	}
}
