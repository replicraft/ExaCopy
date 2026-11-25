use std::ffi::OsStr;
use std::fs::File;
use std::path::{Component, Path};

use exacopy_codec::{DocumentRef, MAX_DOCUMENT_PAGE_BYTES, MAX_PLAN_JSON_BYTES, PlanEntriesPage};
use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::MountObservations;
use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

use super::error::{Failure, Kind};
use super::native::hex;
use crate::linux_path::split;

mod ancestry;
mod records;

use ancestry::{Directory, ancestry, require_disjoint};
use records::{check_named, create, read_existing};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
	.union(OFlags::DIRECTORY)
	.union(OFlags::CLOEXEC)
	.union(OFlags::NOFOLLOW);
const PRIVATE_DIRECTORY: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::XUSR);
const BELOW: ResolveFlags = ResolveFlags::BENEATH
	.union(ResolveFlags::NO_SYMLINKS)
	.union(ResolveFlags::NO_MAGICLINKS)
	.union(ResolveFlags::NO_XDEV);

pub(super) struct Bundle<'path> {
	path: &'path OsStr,
	output: UnixComponent<'path>,
	directory: File,
	chain: Vec<Directory>,
}

impl<'path> Bundle<'path> {
	pub(super) fn open(output: &'path Path) -> Result<Self, Failure> {
		let (path, output) = split(output).map_err(|error| Failure::with(Kind::Invalid, error))?;
		if output.as_bytes() == b"pages"
			|| Path::new(path)
				.components()
				.any(|component| component == Component::ParentDir)
		{
			return Err(Failure::plain(Kind::Invalid));
		}
		let directory = open_bundle_path(path)?;
		let mounts = MountObservations::capture().map_err(Failure::mount_observation)?;
		let chain = ancestry(&directory, &mounts, true)?;
		require_private_directory(&directory)?;
		Ok(Self {
			path,
			output,
			directory,
			chain,
		})
	}

	pub(super) fn ensure_output_absent(&self) -> Result<(), Failure> {
		match fs::statat(
			&self.directory,
			self.output.as_bytes(),
			AtFlags::SYMLINK_NOFOLLOW,
		) {
			Err(Errno::NOENT) => Ok(()),
			Ok(_) => Err(Failure::plain(Kind::BundleConflict)),
			Err(error) => Err(Failure::with(Kind::BundleIo, error)),
		}
	}

	pub(super) fn check_scope(&self, protected: [&File; 3]) -> Result<(), Failure> {
		let mounts = MountObservations::capture().map_err(Failure::mount_observation)?;
		let live = ancestry(&self.directory, &mounts, true)?;
		let selection = open_bundle_path(self.path)?;
		let named = ancestry(&selection, &mounts, true)?;
		if live != self.chain || live != named {
			return Err(Failure::plain(Kind::BundleScope));
		}
		require_private_directory(&self.directory)?;
		require_disjoint(&live, protected, &mounts)
	}

	pub(super) fn write(
		&self,
		protected: [&File; 3],
		reference: DocumentRef,
		page_bytes: &[u8],
		json: &[u8],
	) -> Result<(), Failure> {
		if json
			.len()
			.checked_add(1)
			.is_none_or(|size| size > MAX_PLAN_JSON_BYTES)
			|| page_bytes.len() > MAX_DOCUMENT_PAGE_BYTES
			|| PlanEntriesPage::from_canonical_cbor(reference, page_bytes).is_err()
		{
			return Err(Failure::plain(Kind::Encoding));
		}
		self.check_scope(protected)?;
		self.ensure_output_absent()?;
		let pages = self.open_pages()?;
		let page_name = format!("{}.exc", hex(&reference.page_id()));
		let page_name = UnixComponent::new(page_name.as_bytes())
			.map_err(|error| Failure::with(Kind::Encoding, error))?;
		let page = match create(&pages, page_name, page_bytes) {
			Ok(record) => record,
			Err(error) if error.is_existing_name() => read_existing(&pages, page_name, page_bytes)?,
			Err(error) => return Err(error),
		};

		self.check_pages(&pages)?;
		pages.sync_all().map_err(Failure::bundle_io)?;
		self.directory.sync_all().map_err(Failure::bundle_io)?;

		self.check_scope(protected)?;
		self.check_pages(&pages)?;
		check_named(&pages, page_name, &page)?;
		let mut envelope = Vec::with_capacity(json.len() + 1);
		envelope.extend_from_slice(json);
		envelope.push(b'\n');
		let output = create(&self.directory, self.output, &envelope)?;
		self.directory.sync_all().map_err(Failure::bundle_io)?;
		self.check_scope(protected)?;
		self.check_pages(&pages)?;
		check_named(&pages, page_name, &page)?;
		check_named(&self.directory, self.output, &output)
	}

	fn open_pages(&self) -> Result<File, Failure> {
		match fs::mkdirat(&self.directory, c"pages", PRIVATE_DIRECTORY) {
			Ok(()) | Err(Errno::EXIST) => {}
			Err(error) => return Err(Failure::with(Kind::BundleIo, error)),
		}
		let directory = File::from(
			fs::openat2(
				&self.directory,
				c"pages",
				DIRECTORY_FLAGS,
				Mode::empty(),
				BELOW,
			)
			.map_err(Failure::bundle_open)?,
		);
		self.check_pages(&directory)?;
		Ok(directory)
	}

	fn check_pages(&self, pages: &File) -> Result<(), Failure> {
		require_private_directory(pages)?;
		let original = fs::fstat(pages).map_err(Failure::bundle_open)?;
		let named = fs::statat(&self.directory, c"pages", AtFlags::SYMLINK_NOFOLLOW)
			.map_err(Failure::bundle_open)?;
		if (named.st_dev, named.st_ino, named.st_mode, named.st_uid)
			!= (
				original.st_dev,
				original.st_ino,
				original.st_mode,
				original.st_uid,
			) {
			return Err(Failure::plain(Kind::BundleUnsafe));
		}
		Ok(())
	}
}

fn open_bundle_path(path: &OsStr) -> Result<File, Failure> {
	fs::openat2(
		fs::CWD,
		path,
		DIRECTORY_FLAGS,
		Mode::empty(),
		ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
	)
	.map(File::from)
	.map_err(Failure::bundle_open)
}

fn require_private_directory(directory: &File) -> Result<(), Failure> {
	let info = fs::fstat(directory).map_err(Failure::bundle_open)?;
	if info.st_uid != rustix::process::geteuid().as_raw()
		|| Mode::from_raw_mode(info.st_mode) != PRIVATE_DIRECTORY
	{
		return Err(Failure::plain(Kind::BundleUnsafe));
	}
	Ok(())
}
