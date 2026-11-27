//! Crossing the process boundary with a signed managed Init acknowledgement.

use std::num::NonZeroU64;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_platform::linux::{FileIdentity, OWNER_SEED_BYTES, SyncProfileStore};
use exacopy_transfer::linux::sync_preview::FirstSyncPreview;

use zeroize::Zeroizing;

use crate::profile::profile_id_for_key;
use crate::sync_preview::managed_ack::{MANAGED_ACK_BYTES, profile_path_digest, sign, verify};
use crate::sync_preview::managed_policy::{ManagedPolicyPin, decode};

use super::{ManagedSyncInit, ManagedSyncPreviewError as Failure, initialize, preview_held};

pub(crate) struct InspectedProfileIdentity {
	pub(crate) physical: FileIdentity,
	pub(crate) owner_profile: [u8; 16],
	pub(crate) owner_key: [u8; 32],
}

pub(crate) fn inspect_profile_identity(
	profile: &Path,
) -> Result<InspectedProfileIdentity, Failure> {
	let store = SyncProfileStore::open(profile).map_err(Failure::Store)?;
	let physical = store.identity();
	if physical.inode() == 0 {
		return Err(Failure::Selection);
	}
	let mut seed = Zeroizing::new([0; OWNER_SEED_BYTES]);
	let mut probe = Zeroizing::new([0; 1]);
	let guard = store
		.open_seed(&mut seed, &mut probe)
		.map_err(Failure::Store)?;
	let key = SigningKey::from_bytes(&seed).verifying_key();
	let owner_profile = *profile_id_for_key(&key)
		.map_err(|_| Failure::Selection)?
		.as_bytes();
	let mut checked = Zeroizing::new([0; OWNER_SEED_BYTES]);
	guard
		.recheck_seed(&seed, &mut checked, &mut probe)
		.map_err(Failure::Store)?;
	Ok(InspectedProfileIdentity {
		physical,
		owner_profile,
		owner_key: key.to_bytes(),
	})
}

pub(crate) fn initialize_approved(
	profile: &Path,
	device: u64,
	inode: NonZeroU64,
	approved: &ManagedPolicyPin,
	request: &[u8],
) -> Result<[u8; MANAGED_ACK_BYTES], Failure> {
	let profile_digest = profile_path_digest(profile).map_err(|_| Failure::Selection)?;
	let policy = decode(request, approved).map_err(Failure::Policy)?;
	let store = SyncProfileStore::open(profile).map_err(Failure::Store)?;
	let physical = store.identity();
	if physical.device() != device || physical.inode() != inode.get() {
		return Err(Failure::Selection);
	}
	let request = ManagedSyncInit {
		profile,
		profile_identity: physical,
		selection_id: approved.identity.selection_id,
		selection_revision: approved.identity.revision,
		policy: &policy,
	};
	initialize(&store, request, Some(approved), |selection, signer| {
		sign(
			&selection.pin,
			selection.profile_identity,
			profile_digest,
			signer,
		)
		.map_err(|_| Failure::Acknowledgement)
	})
}

pub(crate) fn preview_acknowledged(
	profile: &Path,
	owner_key: [u8; 32],
	selection: [u8; 16],
	acknowledgement: &[u8],
	scratch: &mut [u8],
) -> Result<(FirstSyncPreview, NonZeroU64), Failure> {
	let owner = VerifyingKey::from_bytes(&owner_key).map_err(|_| Failure::Acknowledgement)?;
	let profile_digest = profile_path_digest(profile).map_err(|_| Failure::Selection)?;
	let acknowledgement = verify(acknowledgement, &owner, profile_digest, selection)
		.map_err(|_| Failure::Acknowledgement)?;
	let store = SyncProfileStore::open(profile).map_err(Failure::Store)?;
	let physical = store.identity();
	if physical.device() != acknowledgement.device()
		|| physical.inode() != acknowledgement.inode().get()
	{
		return Err(Failure::Selection);
	}
	let pin = acknowledgement.pin();
	let outcome = preview_held(&store, &pin, scratch)?;
	Ok((outcome, pin.identity.revision))
}
