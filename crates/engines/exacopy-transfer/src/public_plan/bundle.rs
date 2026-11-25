//! Write validated Plan artifacts with page-first barrier and name checks.

use core::fmt;

use exacopy_endpoint::NameError;
use exacopy_endpoint::plan_bundle::{PageCreation, PlanBundleSink};
use exacopy_plan::PlanBundleArtifacts;

/// Failure of the supplied bundle workflow.
#[derive(Debug)]
#[non_exhaustive]
pub enum BundleWriteError<E> {
	/// The generated name was refused by the component contract.
	PageName(NameError),
	/// The adapter refused an observation or operation.
	Output(E),
}

impl<E: fmt::Display> fmt::Display for BundleWriteError<E> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::PageName(error) => write!(formatter, "plan page name refused ({error})"),
			Self::Output(error) => write!(formatter, "plan bundle operation failed ({error})"),
		}
	}
}

impl<E: core::error::Error + 'static> core::error::Error for BundleWriteError<E> {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::PageName(error) => Some(error),
			Self::Output(error) => Some(error),
		}
	}
}

/// Commits one validated page followed by its exclusive envelope.
///
/// The call applies the current workflow's barriers and checks. The envelope's
/// final name can be visible during its write. A late effect failure leaves
/// the adapter's created files in place.
///
/// # Errors
/// Stops at the first invalid name, refused observation or failed effect.
pub fn write_plan_bundle<B: PlanBundleSink>(
	bundle: &B,
	artifacts: &PlanBundleArtifacts<'_>,
) -> Result<(), BundleWriteError<B::Error>> {
	bundle.check_scope().map_err(BundleWriteError::Output)?;
	bundle
		.ensure_output_absent()
		.map_err(BundleWriteError::Output)?;
	let pages = bundle.open_pages().map_err(BundleWriteError::Output)?;
	let name = artifacts.page_name().map_err(BundleWriteError::PageName)?;
	let expected = artifacts.page();
	let page = match bundle
		.create_page(&pages, name, expected)
		.map_err(BundleWriteError::Output)?
	{
		PageCreation::Created(page) => page,
		PageCreation::Existing => {
			let mut scratch = vec![0; expected.len()];
			bundle
				.verify_existing_page(&pages, name, expected, &mut scratch)
				.map_err(BundleWriteError::Output)?
		}
	};

	bundle
		.check_pages(&pages)
		.map_err(BundleWriteError::Output)?;
	bundle
		.sync_pages(&pages)
		.map_err(BundleWriteError::Output)?;
	bundle.sync_bundle().map_err(BundleWriteError::Output)?;

	bundle.check_scope().map_err(BundleWriteError::Output)?;
	bundle
		.check_pages(&pages)
		.map_err(BundleWriteError::Output)?;
	bundle
		.check_page(&pages, name, &page)
		.map_err(BundleWriteError::Output)?;
	let output = bundle
		.create_output(artifacts.envelope())
		.map_err(BundleWriteError::Output)?;
	bundle.sync_bundle().map_err(BundleWriteError::Output)?;
	bundle.check_scope().map_err(BundleWriteError::Output)?;
	bundle
		.check_pages(&pages)
		.map_err(BundleWriteError::Output)?;
	bundle
		.check_page(&pages, name, &page)
		.map_err(BundleWriteError::Output)?;
	bundle
		.check_output(&output)
		.map_err(BundleWriteError::Output)
}

#[cfg(test)]
mod tests;
