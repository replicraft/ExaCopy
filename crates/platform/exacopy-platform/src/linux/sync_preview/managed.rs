use std::marker::PhantomData;
use std::num::{NonZeroU32, NonZeroU64};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::rc::Rc;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_staging::StagingSource as _;
use rustix::fs::{self, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;

use super::history_scope::unique_mount_id;
use super::{
	CHILD_RESOLUTION, FileIdentity, SyncHistoryLocation, SyncPreviewEntry, SyncPreviewError,
	SyncPreviewPair, SyncPreviewRoots,
};
use crate::linux::handle::mount_id;
use crate::linux::mount_observation::ProcMounts;
use crate::linux::source::SourceTimestamp;

mod credentials;
mod error;

pub use error::ManagedSyncError;

const PRIVATE_MODE: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::XUSR);

/// A provisioned native identity to compare with a held Linux descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedSyncExpectedObject {
	/// Kernel device major.
	pub major: u32,
	/// Kernel device minor.
	pub minor: u32,
	/// Expected nonzero inode.
	pub inode: NonZeroU64,
}

impl ManagedSyncExpectedObject {
	fn matches(self, current: FileIdentity) -> bool {
		self.major == fs::major(current.device())
			&& self.minor == fs::minor(current.device())
			&& self.inode.get() == current.inode()
	}
}

/// A provisioned exact direct child of the managed common parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedSyncExpectedRoot<'selection> {
	/// Ordered raw child basename.
	pub name: UnixComponent<'selection>,
	/// Expected physical identity of the child directory.
	pub identity: ManagedSyncExpectedObject,
}

/// Expected native facts from an independently verified owner provisioning selection.
///
/// This description holds no open resources. The application verifies owner policy
/// before calling the platform and independently selects endpoint locators and limits.
#[derive(Clone, Copy, Debug)]
pub struct ManagedSyncNativeScope<'selection> {
	/// Exact canonical absolute path selected by the provisioner.
	pub parent_path: &'selection Path,
	/// Non-root actor user ID.
	pub uid: NonZeroU32,
	/// Non-root actor group ID.
	pub gid: NonZeroU32,
	/// Sole exact raw basename selected for both roots.
	pub subject: UnixComponent<'selection>,
	/// Expected current boot ID.
	pub boot: [u8; 16],
	/// Expected held mount namespace identity.
	pub mount_namespace: ManagedSyncExpectedObject,
	/// Expected held user namespace identity.
	pub user_namespace: ManagedSyncExpectedObject,
	/// Expected ordinary mount ID.
	pub ordinary_mount: NonZeroU64,
	/// Expected unique mount ID.
	pub unique_mount: NonZeroU64,
	/// Expected common parent identity.
	pub parent: ManagedSyncExpectedObject,
	/// Expected ordered direct child roots, left then right.
	pub roots: [ManagedSyncExpectedRoot<'selection>; 2],
}

impl ManagedSyncNativeScope<'_> {
	fn matches(self, current: [SyncHistoryLocation<'_>; 2]) -> bool {
		self.roots.into_iter().zip(current).all(|(root, fact)| {
			self.boot == fact.boot
				&& self.mount_namespace.matches(fact.mount_namespace)
				&& self.user_namespace.matches(fact.user_namespace)
				&& self.unique_mount == fact.unique_mount
				&& self.parent.matches(fact.parent)
				&& root.name == fact.root_name
				&& root.identity.matches(fact.root)
		})
	}
}

/// One thread-bound shared read lease on the exact managed common parent.
///
/// The provisioner excludes untrusted retained mutation handles and aliases.
/// Same-owner participants must take an exclusive lock on the same parent
/// before every affected namespace, metadata or content change, including
/// through retained handles. Administrators must preserve the selected scope.
#[must_use]
pub struct ManagedSyncReadLease<'held, 'selection> {
	roots: &'held SyncPreviewRoots<'selection>,
	scope: ManagedSyncNativeScope<'selection>,
	locked_parent: OwnedFd,
	directories: [DirectoryStamp; 3],
	ownership: credentials::OwnershipSentinels,
	thread_bound: PhantomData<Rc<()>>,
}

impl<'selection> SyncPreviewRoots<'selection> {
	/// Borrows the held common parent and the ordered live child roots.
	pub(in crate::linux) fn held_directories(&self) -> [BorrowedFd<'_>; 3] {
		let [left, right] = &self.roots;
		[
			self.parent.as_fd(),
			left.directory().as_fd(),
			right.directory().as_fd(),
		]
	}

	/// Acquires an independently scoped managed read lease before subject lookup.
	///
	/// The application must verify that the owner provisioner authorized this
	/// exact scope and the participating writers follow the common-parent lock.
	///
	/// # Errors
	/// Refuses changed or unsupported native scope, unsafe directories or credentials,
	/// and a busy or unavailable lock.
	pub fn acquire_managed_history_lease(
		&self,
		scope: ManagedSyncNativeScope<'selection>,
	) -> Result<ManagedSyncReadLease<'_, 'selection>, ManagedSyncError> {
		let admitted = self.observe_managed_scope(scope)?;
		let locked_parent = fs::openat2(
			&self.parent,
			c".",
			OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
			Mode::empty(),
			CHILD_RESOLUTION,
		)?;
		check_lock_parent(&locked_parent, admitted.directories[0], scope)?;
		fs::flock(&locked_parent, FlockOperation::NonBlockingLockShared).map_err(|error| {
			if error == Errno::WOULDBLOCK {
				ManagedSyncError::Busy
			} else {
				error.into()
			}
		})?;
		let lease = ManagedSyncReadLease {
			roots: self,
			scope,
			locked_parent,
			directories: admitted.directories,
			ownership: admitted.ownership,
			thread_bound: PhantomData,
		};
		lease.recheck_roots()?;
		Ok(lease)
	}

	fn observe_managed_scope(
		&self,
		scope: ManagedSyncNativeScope<'selection>,
	) -> Result<ManagedObservation<'selection>, ManagedSyncError> {
		if self.parent_path.as_os_str() != scope.parent_path.as_os_str()
			|| self.mount != scope.ordinary_mount.get()
			|| !scope.parent.matches(self.parent_identity)
			|| self.names != scope.roots.map(|root| root.name)
			|| !scope
				.roots
				.into_iter()
				.zip(&self.roots)
				.all(|(expected, root)| expected.identity.matches(root.identity()))
		{
			return Err(ManagedSyncError::ScopeMismatch);
		}
		self.namespaces.recheck_current()?;
		let proc = ProcMounts::open()?;
		let ownership = credentials::check(&proc, scope.uid, scope.gid)?;
		self.require_unmapped_history_mount()?;
		let facts = self.observe_history_location()?;
		if !scope.matches(facts) {
			return Err(ManagedSyncError::ScopeMismatch);
		}
		let [left, right] = &self.roots;
		let directories = [
			DirectoryStamp::capture(&self.parent, scope)?,
			DirectoryStamp::capture(left.directory(), scope)?,
			DirectoryStamp::capture(right.directory(), scope)?,
		];
		if credentials::check(&proc, scope.uid, scope.gid)? != ownership {
			return Err(ManagedSyncError::CredentialProfile);
		}
		self.recheck_scope()?;
		Ok(ManagedObservation {
			facts,
			directories,
			ownership,
		})
	}
}

impl<'selection> ManagedSyncReadLease<'_, 'selection> {
	/// Selects the leased scope's exact subject without accepting another name.
	///
	/// # Errors
	/// Refuses changed scope, failed lookup, credential drift and unavailable facts.
	pub fn observe(&self) -> Result<ManagedSyncPreviewPair<'_, 'selection>, ManagedSyncError> {
		self.recheck_roots()?;
		let pair = self.roots.observe(self.scope.subject)?;
		self.check_subject_owners(&pair)?;
		self.recheck_roots()?;
		Ok(ManagedSyncPreviewPair { lease: self, pair })
	}

	/// Rechecks the retained lease, actor, directories and exact root bindings.
	///
	/// This operation does not open the selected subject.
	///
	/// # Errors
	/// Refuses changed scope, credentials, mount attributes or directory ownership.
	pub fn recheck_roots(&self) -> Result<[SyncHistoryLocation<'selection>; 2], ManagedSyncError> {
		check_lock_parent(&self.locked_parent, self.directories[0], self.scope)?;
		let current = self.roots.observe_managed_scope(self.scope)?;
		if current.ownership != self.ownership {
			return Err(ManagedSyncError::CredentialProfile);
		}
		if current.directories != self.directories {
			return Err(SyncPreviewError::Changed.into());
		}
		check_lock_parent(&self.locked_parent, self.directories[0], self.scope)?;
		Ok(current.facts)
	}

	fn check_subject_owners(&self, pair: &SyncPreviewPair<'_, '_>) -> Result<(), ManagedSyncError> {
		for entry in pair.entries() {
			if let SyncPreviewEntry::Present(file) = entry {
				let metadata = file.metadata();
				if self.ownership.ambiguous(metadata.owner(), metadata.group()) {
					return Err(ManagedSyncError::AmbiguousSubjectOwnership);
				}
			}
		}
		Ok(())
	}
}

struct ManagedObservation<'selection> {
	facts: [SyncHistoryLocation<'selection>; 2],
	directories: [DirectoryStamp; 3],
	ownership: credentials::OwnershipSentinels,
}

/// The original ordered subject observations under one managed read lease.
#[must_use]
pub struct ManagedSyncPreviewPair<'view, 'selection> {
	lease: &'view ManagedSyncReadLease<'view, 'selection>,
	pair: SyncPreviewPair<'view, 'selection>,
}

impl<'view, 'selection> ManagedSyncPreviewPair<'view, 'selection> {
	pub(in crate::linux) fn held_roots(&self) -> &SyncPreviewRoots<'selection> {
		self.lease.roots
	}

	/// Returns the same borrowed observations for independent measurement.
	#[must_use]
	pub fn entries(&self) -> [SyncPreviewEntry<'_, 'view>; 2] {
		self.pair.entries()
	}

	/// Revalidates the exact historical scope, lease and original current observations.
	///
	/// # Errors
	/// Refuses changed or incomplete evidence before classification.
	pub fn recheck_history_location(
		&self,
	) -> Result<
		(
			UnixComponent<'selection>,
			[SyncHistoryLocation<'selection>; 2],
		),
		ManagedSyncError,
	> {
		self.lease.recheck_roots()?;
		self.pair.recheck()?;
		self.lease.check_subject_owners(&self.pair)?;
		let facts = self.lease.recheck_roots()?;
		Ok((self.lease.scope.subject, facts))
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryStamp {
	identity: FileIdentity,
	links: u64,
	size: i64,
	mtime: SourceTimestamp,
	ctime: SourceTimestamp,
}

impl DirectoryStamp {
	#[cfg_attr(
		all(target_arch = "x86_64", target_pointer_width = "64"),
		expect(
			clippy::useless_conversion,
			reason = "Linux stat link counts vary by ABI"
		)
	)]
	fn capture(fd: impl AsFd, scope: ManagedSyncNativeScope<'_>) -> Result<Self, ManagedSyncError> {
		let stat = fs::fstat(fd)?;
		// Ext4 exposes the effective POSIX ACL group class through these mode bits.
		if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
			|| Mode::from_raw_mode(stat.st_mode) != PRIVATE_MODE
			|| stat.st_uid != scope.uid.get()
			|| stat.st_gid != scope.gid.get()
		{
			return Err(ManagedSyncError::PrivateDirectoryRequired);
		}
		Ok(Self {
			identity: FileIdentity::from_stat(&stat),
			links: stat.st_nlink.into(),
			size: stat.st_size,
			mtime: SourceTimestamp::capture(stat.st_mtime, stat.st_mtime_nsec)
				.map_err(SyncPreviewError::from)?,
			ctime: SourceTimestamp::capture(stat.st_ctime, stat.st_ctime_nsec)
				.map_err(SyncPreviewError::from)?,
		})
	}
}

fn check_lock_parent(
	fd: &OwnedFd,
	expected: DirectoryStamp,
	scope: ManagedSyncNativeScope<'_>,
) -> Result<(), ManagedSyncError> {
	if DirectoryStamp::capture(fd, scope)? != expected
		|| mount_id(fd)? != scope.ordinary_mount.get()
		|| unique_mount_id(fd)? != scope.unique_mount
	{
		return Err(SyncPreviewError::Changed.into());
	}
	Ok(())
}
