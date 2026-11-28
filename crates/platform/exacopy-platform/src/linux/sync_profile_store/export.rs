use super::{
	OWNER_SEED_BYTES, Pin, SyncProfileStore, SyncProfileStoreError, SyncProfileStoreRecord,
};

/// Existing policy record and its shared profile lease for read-only Plan export.
pub struct HeldSyncExportProfile<'store> {
	record: SyncProfileStoreRecord<'store>,
}

impl SyncProfileStore {
	/// Holds one exact policy record under a shared cooperating profile lease.
	///
	/// The application authenticates the selected policy and live scope before
	/// requesting a seed observation.
	///
	/// # Errors
	/// Refuses an invalid or missing selection, a busy profile, or changed custody.
	pub fn read_for_export(
		&self,
		id: [u8; 16],
	) -> Result<HeldSyncExportProfile<'_>, SyncProfileStoreError> {
		Ok(HeldSyncExportProfile {
			record: self.read(id)?,
		})
	}
}

impl<'store> HeldSyncExportProfile<'store> {
	/// Borrows the exact selected record for policy authentication and rechecks.
	#[must_use]
	pub const fn record(&self) -> &SyncProfileStoreRecord<'store> {
		&self.record
	}

	/// Reads the fixed seed under the original policy record's shared lease.
	///
	/// The caller must wipe both buffers even after refusal. Keep the returned
	/// seed observation live through signing and verification.
	///
	/// # Errors
	/// Refuses changed profile or policy custody, or unsafe or inexact seed bytes.
	pub fn hold_seed_for_export(
		&self,
		bytes: &mut [u8; OWNER_SEED_BYTES],
		eof: &mut [u8; 1],
	) -> Result<HeldSyncExportSeed<'_, 'store>, SyncProfileStoreError> {
		self.record.recheck()?;
		let store = self.record.store;
		let pin = Pin::open_seed(&self.record.lease, store.owner, store.mount, bytes, eof)?;
		self.record.recheck()?;
		Ok(HeldSyncExportSeed { profile: self, pin })
	}
}

/// Exact seed observation borrowing the original held policy and shared lease.
pub struct HeldSyncExportSeed<'profile, 'store> {
	profile: &'profile HeldSyncExportProfile<'store>,
	pin: Pin,
}

impl HeldSyncExportSeed<'_, '_> {
	/// Rechecks the original seed, exact bytes, policy record and protected profile.
	///
	/// The caller must wipe both buffers even after refusal.
	///
	/// # Errors
	/// Refuses changed profile, policy or seed observations and inexact seed reads.
	pub fn recheck_seed(
		&self,
		expected: &[u8; OWNER_SEED_BYTES],
		scratch: &mut [u8; OWNER_SEED_BYTES],
		eof: &mut [u8; 1],
	) -> Result<(), SyncProfileStoreError> {
		let record = self.profile.record();
		record.recheck()?;
		self.pin
			.recheck_seed_bytes(&record.lease, expected, scratch, eof)?;
		record.recheck()
	}
}
