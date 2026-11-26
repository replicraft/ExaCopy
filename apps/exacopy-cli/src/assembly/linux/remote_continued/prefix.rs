//! Adapts the original held native prefix to the engine's read-only interface.

use exacopy_endpoint::ReadView;
use exacopy_journal::LinuxFileIdentity;
use exacopy_platform::linux::{RetainedPrefixRead, StageError};
use exacopy_transfer::remote_resume::prefix::{RetainedPrefixIdentity, RetainedPrefixView};

pub(super) struct WitnessPrefix<'lease>(pub(super) RetainedPrefixRead<'lease>);

impl<'lease> WitnessPrefix<'lease> {
	pub(super) const fn native(&self) -> &RetainedPrefixRead<'lease> {
		&self.0
	}
}

impl ReadView for WitnessPrefix<'_> {
	type Error = StageError;

	fn length(&self) -> u64 {
		self.native().length()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.native().recheck_observation()
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		self.native().read_exact_at(offset, buffer)
	}
}

impl RetainedPrefixView for WitnessPrefix<'_> {
	fn identity(&self) -> RetainedPrefixIdentity<'_> {
		let selected = self.native().selection();
		RetainedPrefixIdentity {
			name: selected.stage,
			directory: LinuxFileIdentity::new(selected.directory.device, selected.directory.inode),
			file: LinuxFileIdentity::new(selected.file.device, selected.file.inode),
		}
	}
}
