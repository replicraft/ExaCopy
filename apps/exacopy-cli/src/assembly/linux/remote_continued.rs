//! Selector-2 continuation wiring with a default-off first witnessed CLI path.

mod activation;
mod checkpoints;
#[cfg(feature = "experimental-verified-prefix-resume")]
mod original;
mod prefix;

#[cfg(all(test, feature = "experimental-verified-prefix-resume"))]
pub(super) use prefix::WitnessPrefix;
mod witness;

#[cfg(feature = "experimental-verified-prefix-resume")]
pub(crate) use original::{
	OriginalWitnessError, OriginalWitnessResult, OriginalWitnessResume, continue_original_capture,
	hold_original_witness_startup,
};

#[cfg(all(test, feature = "experimental-verified-prefix-resume"))]
pub(super) use original::preflight_original;

#[cfg(test)]
mod tests;
