use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};

use super::{
	Error, WindowsBootstrapFreshSegment, WindowsBootstrapLayout, WindowsBootstrapRoleObservations,
	WindowsCaptureStageScope, read_at,
};

/// Original provisioned NTFS roles held before the bootstrap frame is appended.
pub struct WindowsCaptureBootstrapScope<'name> {
	bootstrap: WindowsBootstrapFreshSegment<'name>,
}

impl<'name> WindowsCaptureBootstrapScope<'name> {
	/// Acquires the original empty bootstrap and checked job child-create rights.
	///
	/// The caller establishes the independent native identities and custody
	/// premises of [WindowsBootstrapFreshSegment::open_provisioned].
	///
	/// # Errors
	/// Refuses changed roles, unsupported custody or missing native rights.
	pub fn open_provisioned(
		root: &'name [u16],
		expected: WindowsBootstrapRoleObservations,
		layout: WindowsBootstrapLayout<'name>,
	) -> Result<Self, Error> {
		let bootstrap = WindowsBootstrapFreshSegment::open_for_scope(root, expected, layout, true)?;
		Ok(Self { bootstrap })
	}

	/// Appends and confirms the exact first segment before admitting stage creation.
	///
	/// The application authenticates the independently supplied owner and encoded
	/// first segment using its bootstrap format. The bounded native writer is
	/// available only during the callback. The original handles stay held through
	/// append, exact byte and EOF checks, a file barrier, and stage operations.
	/// The native checks establish live file observations. The caller owns
	/// required namespace persistence checks and storage meaning.
	///
	/// # Errors
	/// Refuses invalid expected extents, mismatched owner or segment bytes,
	/// callback error or uncertain native effects. Failure consumes the scope
	/// and retains bytes that reached the segment for reconciliation.
	pub fn append_first_segment(
		mut self,
		expected_owner: &[u8],
		expected_segment: &[u8],
		append: impl for<'scope> FnOnce(WindowsCaptureBootstrapSegment<'scope, 'name>) -> io::Result<()>,
	) -> io::Result<WindowsCaptureStageScope<'name>> {
		let layout = self.bootstrap.records.layout;
		if expected_owner.len() != layout.owner_bytes
			|| expected_segment.len() != layout.first_segment_bytes
		{
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"invalid bootstrap extent",
			));
		}
		self.check_owner(expected_owner)?;
		append(WindowsCaptureBootstrapSegment(&mut self.bootstrap))?;
		let mut observed = vec![0; expected_segment.len()];
		self.check_first_segment(expected_segment, &mut observed)?;
		self.bootstrap.sync()?;
		self.check_owner(expected_owner)?;
		self.check_first_segment(expected_segment, &mut observed)?;
		Ok(WindowsCaptureStageScope {
			bootstrap: self.bootstrap,
		})
	}

	fn check_owner(&mut self, expected: &[u8]) -> io::Result<()> {
		let observed = self
			.bootstrap
			.records
			.read_owner()
			.map_err(io::Error::other)?;
		if observed != expected {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"bootstrap owner content changed",
			));
		}
		Ok(())
	}

	fn check_first_segment(&self, expected: &[u8], observed: &mut [u8]) -> io::Result<()> {
		let length = Some(expected.len() as u64);
		if self.bootstrap.regular_length()? != length {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"first segment extent changed",
			));
		}
		read_at(&self.bootstrap.records.segment.file, 0, observed).map_err(io::Error::other)?;
		if observed != expected || self.bootstrap.regular_length()? != length {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"first segment content changed",
			));
		}
		Ok(())
	}
}

impl fmt::Debug for WindowsCaptureBootstrapScope<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsCaptureBootstrapScope")
			.finish_non_exhaustive()
	}
}

/// Callback-scoped access to the original first segment.
pub struct WindowsCaptureBootstrapSegment<'scope, 'name>(
	&'scope mut WindowsBootstrapFreshSegment<'name>,
);

impl fmt::Debug for WindowsCaptureBootstrapSegment<'_, '_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsCaptureBootstrapSegment")
			.finish_non_exhaustive()
	}
}

impl Read for WindowsCaptureBootstrapSegment<'_, '_> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		self.0.read(output)
	}
}

impl Seek for WindowsCaptureBootstrapSegment<'_, '_> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.0.seek(position)
	}
}

impl Write for WindowsCaptureBootstrapSegment<'_, '_> {
	fn write(&mut self, input: &[u8]) -> io::Result<usize> {
		self.0.write(input)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.0.flush()
	}
}

impl JournalSegment for WindowsCaptureBootstrapSegment<'_, '_> {
	const BARRIER: JournalFileBarrier = WindowsBootstrapFreshSegment::BARRIER;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		self.0.regular_length()
	}

	fn sync(&self) -> io::Result<()> {
		self.0.sync()
	}
}
