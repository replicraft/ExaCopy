use exacopy_endpoint::linux_staging::{ExtendedAttributes, StagingSource};
use exacopy_endpoint::{ReadView, UnixComponent};

use super::{FileIdentity, ReadError, ReadRoot, SourceFile, SourceObservation};

#[cfg(test)]
mod tests;

/// A held regular file with its original selection under an authorized Linux parent.
#[derive(Debug)]
pub struct NamedReadView<'root> {
	root: &'root ReadRoot,
	name: UnixComponent<'root>,
	file: SourceFile,
}

impl<'root> NamedReadView<'root> {
	/// Opens and checks one original relative name under the caller-authorized root.
	///
	/// # Errors
	/// Reports refused names, unsupported reads, and changed or unreadable observations.
	pub fn open(root: &'root ReadRoot, name: UnixComponent<'root>) -> Result<Self, ReadError> {
		let file = root.open_regular(name)?;
		root.recheck_regular_name(name, &file)?;
		Ok(Self { root, name, file })
	}

	/// Returns the live identity of the file held by this view.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.file.identity()
	}
}

impl ReadView for NamedReadView<'_> {
	type Error = ReadError;

	fn length(&self) -> u64 {
		self.file.len()
	}

	fn recheck_observation(&self) -> Result<(), ReadError> {
		self.root.recheck_regular_name(self.name, &self.file)?;
		ReadView::recheck_observation(&self.file)?;
		self.root.recheck_regular_name(self.name, &self.file)
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), ReadError> {
		self.file.read_exact_at(offset, buffer)
	}
}

impl StagingSource for NamedReadView<'_> {
	type Identity = FileIdentity;
	type Metadata = SourceObservation;

	fn identity(&self) -> Self::Identity {
		NamedReadView::identity(self)
	}

	fn metadata(&self) -> Self::Metadata {
		self.file.observation()
	}

	fn extended_attributes(&self) -> Result<ExtendedAttributes, ReadError> {
		self.file.extended_attributes()
	}

	fn recheck_metadata(&self) -> Result<(), ReadError> {
		self.root.recheck_regular_name(self.name, &self.file)?;
		self.file.recheck_observation()?;
		self.root.recheck_regular_name(self.name, &self.file)
	}
}
