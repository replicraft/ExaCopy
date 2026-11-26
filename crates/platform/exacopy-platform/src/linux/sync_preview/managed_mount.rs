use std::num::NonZeroU64;

use super::history_scope::whole_ext4_mount;
use super::{SyncPreviewError, SyncPreviewRoots};
use crate::linux::mount_observation::ProcMounts;

impl SyncPreviewRoots<'_> {
	/// Checks that the exact held whole ext4 mount has no mount ID mapping.
	///
	/// This observes the current thread's namespace and mount only. Managed
	/// admission also requires independent owner selection and a held lease.
	///
	/// # Errors
	/// Refuses changed scope, unsupported mount attributes, and ID-mapped mounts.
	pub fn require_unmapped_history_mount(&self) -> Result<(), SyncPreviewError> {
		let unique = self.checked_managed_mount()?;
		let observed = query::require_unmapped(unique, self.mount);
		if self.checked_managed_mount()? != unique {
			return Err(SyncPreviewError::Changed);
		}
		observed
	}

	fn checked_managed_mount(&self) -> Result<NonZeroU64, SyncPreviewError> {
		self.recheck_scope()?;
		let proc = ProcMounts::open().map_err(SyncPreviewError::System)?;
		let unique = whole_ext4_mount(&proc, &self.parent, self.mount)?;
		self.namespaces.recheck_current()?;
		Ok(unique)
	}
}

#[cfg(any(
	all(target_arch = "x86_64", target_pointer_width = "64"),
	all(target_arch = "aarch64", target_pointer_width = "64"),
))]
mod query {
	use std::io;
	use std::num::NonZeroU64;

	use rustix::io::Errno;

	use super::SyncPreviewError;
	use crate::managed_sync_statmount::{
		self, BASIC_PREFIX_BYTES, MountAttributes, STATMOUNT_MNT_BASIC,
	};

	// mnt_to_attr_flags in Linux v6.8 through v7.0 emits only these UAPI bits.
	const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
	const KNOWN_MOUNT_ATTRIBUTES: u64 = MOUNT_ATTR_IDMAP | 0x0020_00bf;

	pub(super) fn require_unmapped(
		unique: NonZeroU64,
		ordinary: u64,
	) -> Result<(), SyncPreviewError> {
		let observed = managed_sync_statmount::query(unique).map_err(query_error)?;
		require_exact_unmapped(&observed, unique, ordinary)
	}

	fn require_exact_unmapped(
		observed: &MountAttributes,
		unique: NonZeroU64,
		ordinary: u64,
	) -> Result<(), SyncPreviewError> {
		if observed.size != BASIC_PREFIX_BYTES || observed.mask != STATMOUNT_MNT_BASIC {
			return Err(SyncPreviewError::UnsupportedHistoryMountAttributes);
		}
		if observed.unique != unique.get()
			|| observed.ordinary == 0
			|| u64::from(observed.ordinary) != ordinary
		{
			return Err(SyncPreviewError::Changed);
		}
		if observed.attributes & !KNOWN_MOUNT_ATTRIBUTES != 0 {
			return Err(SyncPreviewError::UnsupportedHistoryMountAttributes);
		}
		if observed.attributes & MOUNT_ATTR_IDMAP != 0 {
			return Err(SyncPreviewError::IdMappedHistoryMount);
		}
		Ok(())
	}

	fn query_error(error: io::Error) -> SyncPreviewError {
		if error.kind() == io::ErrorKind::Unsupported {
			return SyncPreviewError::UnsupportedHistoryMountAttributes;
		}
		match Errno::from_io_error(&error) {
			Some(Errno::NOSYS | Errno::NOTSUP | Errno::INVAL) => {
				SyncPreviewError::UnsupportedHistoryMountAttributes
			}
			Some(Errno::NOENT) => SyncPreviewError::Changed,
			_ => SyncPreviewError::System(error),
		}
	}

	#[cfg(test)]
	mod tests {
		use super::{
			BASIC_PREFIX_BYTES, Errno, MOUNT_ATTR_IDMAP, MountAttributes, NonZeroU64,
			STATMOUNT_MNT_BASIC, SyncPreviewError, query_error, require_exact_unmapped,
		};

		const UNIQUE: NonZeroU64 = NonZeroU64::new(0x1_0000_0042).unwrap();
		const ORDINARY: u64 = 42;

		fn response() -> MountAttributes {
			MountAttributes {
				size: BASIC_PREFIX_BYTES,
				mask: STATMOUNT_MNT_BASIC,
				unique: UNIQUE.get(),
				ordinary: 42,
				attributes: 1,
			}
		}

		#[test]
		fn requires_reported_extent_and_basic_field_mask() {
			assert!(require_exact_unmapped(&response(), UNIQUE, ORDINARY).is_ok());
			for size in [0, 8, 16, 64, 71, 73, u32::MAX] {
				let response = MountAttributes { size, ..response() };
				assert!(matches!(
					require_exact_unmapped(&response, UNIQUE, ORDINARY),
					Err(SyncPreviewError::UnsupportedHistoryMountAttributes)
				));
			}
			for mask in [0, 1, STATMOUNT_MNT_BASIC | 1] {
				let response = MountAttributes { mask, ..response() };
				assert!(matches!(
					require_exact_unmapped(&response, UNIQUE, ORDINARY),
					Err(SyncPreviewError::UnsupportedHistoryMountAttributes)
				));
			}
		}

		#[test]
		fn refuses_unknown_mount_attributes() {
			for attributes in [0x40, 1 << 63, MOUNT_ATTR_IDMAP | 0x100] {
				let response = MountAttributes {
					attributes,
					..response()
				};
				assert!(matches!(
					require_exact_unmapped(&response, UNIQUE, ORDINARY),
					Err(SyncPreviewError::UnsupportedHistoryMountAttributes)
				));
			}
		}

		#[test]
		fn distinguishes_wrong_mount_and_idmapped_mount() {
			let mapped = MountAttributes {
				attributes: MOUNT_ATTR_IDMAP,
				..response()
			};
			assert!(matches!(
				require_exact_unmapped(&mapped, UNIQUE, ORDINARY),
				Err(SyncPreviewError::IdMappedHistoryMount)
			));
			assert!(matches!(
				require_exact_unmapped(&mapped, UNIQUE, ORDINARY + 1),
				Err(SyncPreviewError::Changed)
			));
			assert!(matches!(
				require_exact_unmapped(&mapped, NonZeroU64::MIN, ORDINARY),
				Err(SyncPreviewError::Changed)
			));
			let invalid = MountAttributes {
				ordinary: 0,
				..response()
			};
			assert!(matches!(
				require_exact_unmapped(&invalid, UNIQUE, 0),
				Err(SyncPreviewError::Changed)
			));
		}

		#[test]
		fn classifies_unsupported_query_without_fallback() {
			for error in [Errno::NOSYS, Errno::NOTSUP, Errno::INVAL] {
				assert!(matches!(
					query_error(error.into()),
					SyncPreviewError::UnsupportedHistoryMountAttributes
				));
			}
			assert!(matches!(
				query_error(Errno::NOENT.into()),
				SyncPreviewError::Changed
			));
			assert!(matches!(
				query_error(Errno::IO.into()),
				SyncPreviewError::System(_)
			));
		}

		#[test]
		fn preserves_the_native_permission_error_as_the_cause() {
			for errno in [Errno::PERM, Errno::ACCESS] {
				let failure = query_error(errno.into());
				assert!(matches!(&failure, SyncPreviewError::System(_)));
				let cause = std::error::Error::source(&failure)
					.and_then(|source| source.downcast_ref::<std::io::Error>())
					.expect("native permission error is the source");
				assert_eq!(cause.kind(), std::io::ErrorKind::PermissionDenied);
				assert_eq!(Errno::from_io_error(cause), Some(errno));
			}
		}
	}
}

#[cfg(not(any(
	all(target_arch = "x86_64", target_pointer_width = "64"),
	all(target_arch = "aarch64", target_pointer_width = "64"),
)))]
mod query {
	use std::num::NonZeroU64;

	use super::SyncPreviewError;

	pub(super) fn require_unmapped(_: NonZeroU64, _: u64) -> Result<(), SyncPreviewError> {
		Err(SyncPreviewError::UnsupportedHistoryMountAttributes)
	}
}
