use std::ffi::OsStr;
use std::fs::File;
use std::path::{Component, Path};
use std::sync::Arc;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::plan_bundle::{PageCreation, PlanBundleSink};
use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

use super::MountObservations;

mod ancestry;
mod error;
mod inputs;
mod records;

pub use error::PlanBundleError;
pub use inputs::{PlanInputDirectory, PlanOwnerSeedObservation, PlanSeedError, PlanSeedStamp};

use ancestry::{Directory, ancestry, require_disjoint};
use records::{Record, check_named, create, read_existing};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
	.union(OFlags::DIRECTORY)
	.union(OFlags::CLOEXEC)
	.union(OFlags::NOFOLLOW);
const PRIVATE_DIRECTORY: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::XUSR);
const BELOW: ResolveFlags = ResolveFlags::BENEATH
	.union(ResolveFlags::NO_SYMLINKS)
	.union(ResolveFlags::NO_MAGICLINKS)
	.union(ResolveFlags::NO_XDEV);

/// A held Linux Plan bundle and its fixed protected input scopes.
pub struct LinuxPlanBundle<'path> {
	path: &'path OsStr,
	output: UnixComponent<'path>,
	directory: File,
	chain: Vec<Directory>,
	protected: [&'path PlanInputDirectory; 3],
	binding: Arc<()>,
}

impl<'path> LinuxPlanBundle<'path> {
	/// Binds the selected no-link output parent and protected held inputs.
	///
	/// # Errors
	/// Refuses invalid names, unsafe paths, and unavailable mount evidence.
	pub fn open(
		path: &'path OsStr,
		output: UnixComponent<'path>,
		protected: [&'path PlanInputDirectory; 3],
	) -> Result<Self, PlanBundleError> {
		if output.as_bytes() == b"pages"
			|| Path::new(path)
				.components()
				.any(|component| component == Component::ParentDir)
		{
			return Err(PlanBundleError::InvalidOutput);
		}
		let directory = open_bundle_path(path)?;
		let mounts = MountObservations::capture().map_err(PlanBundleError::mount_observation)?;
		let chain = ancestry(&directory, &mounts, true)?;
		require_private_directory(&directory)?;
		let bundle = Self {
			path,
			output,
			directory,
			chain,
			protected,
			binding: Arc::new(()),
		};
		bundle.check_scope()?;
		Ok(bundle)
	}

	fn require_binding(&self, binding: &Arc<()>) -> Result<(), PlanBundleError> {
		if Arc::ptr_eq(&self.binding, binding) {
			Ok(())
		} else {
			Err(PlanBundleError::Scope(None))
		}
	}

	fn bind_record(&self, record: Record) -> PlanBundleRecord {
		PlanBundleRecord {
			record,
			binding: Arc::clone(&self.binding),
		}
	}

	fn open_checked_pages(&self) -> Result<File, PlanBundleError> {
		match fs::mkdirat(&self.directory, c"pages", PRIVATE_DIRECTORY) {
			Ok(()) | Err(Errno::EXIST) => {}
			Err(error) => return Err(PlanBundleError::io(error)),
		}
		let directory = File::from(
			fs::openat2(
				&self.directory,
				c"pages",
				DIRECTORY_FLAGS,
				Mode::empty(),
				BELOW,
			)
			.map_err(PlanBundleError::bundle_open)?,
		);
		self.check_pages_directory(&directory)?;
		Ok(directory)
	}

	fn check_pages_directory(&self, pages: &File) -> Result<(), PlanBundleError> {
		require_private_directory(pages)?;
		let original = fs::fstat(pages).map_err(PlanBundleError::bundle_open)?;
		let named = fs::statat(&self.directory, c"pages", AtFlags::SYMLINK_NOFOLLOW)
			.map_err(PlanBundleError::bundle_open)?;
		if (named.st_dev, named.st_ino, named.st_mode, named.st_uid)
			!= (
				original.st_dev,
				original.st_ino,
				original.st_mode,
				original.st_uid,
			) {
			return Err(PlanBundleError::Unsafe(None));
		}
		Ok(())
	}
}

/// A held checked pages directory with no exposed native descriptor.
pub struct PlanBundlePages {
	directory: File,
	binding: Arc<()>,
}

/// A synchronized, checked record held relative to its bundle instance.
pub struct PlanBundleRecord {
	record: Record,
	binding: Arc<()>,
}

impl PlanBundleSink for LinuxPlanBundle<'_> {
	type Pages = PlanBundlePages;
	type Record = PlanBundleRecord;
	type Error = PlanBundleError;

	fn ensure_output_absent(&self) -> Result<(), PlanBundleError> {
		match fs::statat(
			&self.directory,
			self.output.as_bytes(),
			AtFlags::SYMLINK_NOFOLLOW,
		) {
			Err(Errno::NOENT) => Ok(()),
			Ok(_) => Err(PlanBundleError::Conflict),
			Err(error) => Err(PlanBundleError::io(error)),
		}
	}

	fn check_scope(&self) -> Result<(), PlanBundleError> {
		let mounts = MountObservations::capture().map_err(PlanBundleError::mount_observation)?;
		let live = ancestry(&self.directory, &mounts, true)?;
		let selection = open_bundle_path(self.path)?;
		let named = ancestry(&selection, &mounts, true)?;
		if live != self.chain || live != named {
			return Err(PlanBundleError::Scope(None));
		}
		require_private_directory(&self.directory)?;
		require_disjoint(&live, self.protected.map(|input| &input.0), &mounts)
	}

	fn open_pages(&self) -> Result<Self::Pages, Self::Error> {
		Ok(PlanBundlePages {
			directory: self.open_checked_pages()?,
			binding: Arc::clone(&self.binding),
		})
	}

	fn create_page(
		&self,
		pages: &Self::Pages,
		name: UnixComponent<'_>,
		bytes: &[u8],
	) -> Result<PageCreation<Self::Record>, Self::Error> {
		self.require_binding(&pages.binding)?;
		match create(&pages.directory, name, bytes) {
			Ok(record) => Ok(PageCreation::Created(self.bind_record(record))),
			Err(error) if error.is_existing_name() => Ok(PageCreation::Existing),
			Err(error) => Err(error),
		}
	}

	fn verify_existing_page(
		&self,
		pages: &Self::Pages,
		name: UnixComponent<'_>,
		bytes: &[u8],
		scratch: &mut [u8],
	) -> Result<Self::Record, Self::Error> {
		self.require_binding(&pages.binding)?;
		let record = read_existing(&pages.directory, name, bytes, scratch)?;
		Ok(self.bind_record(record))
	}

	fn check_pages(&self, pages: &Self::Pages) -> Result<(), Self::Error> {
		self.require_binding(&pages.binding)?;
		self.check_pages_directory(&pages.directory)
	}

	fn sync_pages(&self, pages: &Self::Pages) -> Result<(), Self::Error> {
		self.require_binding(&pages.binding)?;
		pages.directory.sync_all().map_err(PlanBundleError::io)
	}

	fn sync_bundle(&self) -> Result<(), Self::Error> {
		self.directory.sync_all().map_err(PlanBundleError::io)
	}

	fn check_page(
		&self,
		pages: &Self::Pages,
		name: UnixComponent<'_>,
		page: &Self::Record,
	) -> Result<(), Self::Error> {
		self.require_binding(&pages.binding)?;
		self.require_binding(&page.binding)?;
		check_named(&pages.directory, name, &page.record)
	}

	fn create_output(&self, envelope: &[u8]) -> Result<Self::Record, Self::Error> {
		let record = create(&self.directory, self.output, envelope)?;
		Ok(self.bind_record(record))
	}

	fn check_output(&self, output: &Self::Record) -> Result<(), Self::Error> {
		self.require_binding(&output.binding)?;
		check_named(&self.directory, self.output, &output.record)
	}
}

fn open_bundle_path(path: &OsStr) -> Result<File, PlanBundleError> {
	fs::openat2(
		fs::CWD,
		path,
		DIRECTORY_FLAGS,
		Mode::empty(),
		ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
	)
	.map(File::from)
	.map_err(PlanBundleError::bundle_open)
}

fn require_private_directory(directory: &File) -> Result<(), PlanBundleError> {
	let info = fs::fstat(directory).map_err(PlanBundleError::bundle_open)?;
	if info.st_uid != rustix::process::geteuid().as_raw()
		|| Mode::from_raw_mode(info.st_mode) != PRIVATE_DIRECTORY
	{
		return Err(PlanBundleError::Unsafe(None));
	}
	Ok(())
}

#[cfg(test)]
mod tests;
