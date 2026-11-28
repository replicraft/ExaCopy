//! Application composition for a selected owner-managed sync observation.

use std::fmt;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_endpoint::linux_staging::StagingSource as _;
use exacopy_manifest::sync_baseline::LinuxOwnerMode;
use exacopy_plan::workflow_sync::MAX_MEMBER_BYTES;
use exacopy_platform::linux::{
	FileIdentity, ManagedSyncError, ManagedSyncPreviewPair, NamedReadView, ReadError,
	SyncPreviewEntry, SyncPreviewError, SyncPreviewRoots, SyncProfileStore, SyncProfileStoreError,
	SyncProfileStoreRecord,
};
use exacopy_transfer::linux::sync_preview::{
	FirstSyncPreview, HeldSyncPreview, HistoricalPreviewFailure, LiveSyncSelection, PreviewInput,
	preview_with_history,
};
use exacopy_transfer::sync_genesis::{
	AuthenticatedSyncGenesis, RetainedSyncGenesisMembers, SyncGenesisError,
};
use zeroize::Zeroizing;

use crate::profile::profile_id_for_key;
pub use crate::sync_preview::managed_policy::{
	ManagedCooperation, ManagedHistoryMember, ManagedPolicy, ManagedPolicyEndpoint,
	ManagedPolicyError, ManagedPolicyHistory, ManagedPolicyLocation,
};
use crate::sync_preview::managed_policy::{
	ManagedPolicyIdentity, ManagedPolicyPin, decode, encode,
};

mod acknowledgement;
pub mod genesis;
mod history;
mod manual_recreate;
mod scope;
mod signed_recreate;

pub(crate) use signed_recreate::{
	SignedRecreateError, SignedRecreateExport, SignedRecreateRequest, export_recreate_acknowledged,
};

#[cfg(test)]
mod tests;

pub(crate) use acknowledgement::{
	initialize_approved, inspect_profile_identity, prepare_recreate_acknowledged,
	preview_acknowledged,
};

pub use manual_recreate::{
	ManualRecreateCandidate, ManualRecreateError, ManualRecreatePlanIds, ManualRecreateRoot,
	prepare_manual_recreate,
};

use history::authenticate;
use scope::{expected_native, fresh_endpoints, native_object, raw_path};

/// One explicit operator request to provision a single acknowledged managed sync selection.
///
/// The caller independently authorizes the selected existing profile and exact native roots.
/// Authorized writers must already participate in the configured parent-exclusion protocol.
pub struct ManagedSyncInit<'selection> {
	/// Exact existing ordinary local profile directory selected by its owner.
	pub profile: &'selection Path,
	/// Independently selected physical identity of that existing profile directory.
	pub profile_identity: FileIdentity,
	/// Independent selection ID for the immutable private slot.
	pub selection_id: [u8; 16],
	/// Positive revision of this managed selection.
	pub selection_revision: NonZeroU64,
	/// Independently supplied exact live and signed history selections.
	pub policy: &'selection ManagedPolicy,
}

/// Acknowledged immutable selection issued only by the explicit Init operation.
pub struct ManagedSyncSelection {
	profile: PathBuf,
	profile_identity: FileIdentity,
	pin: ManagedPolicyPin,
}

impl ManagedSyncSelection {
	/// Physical identity of the protected profile selected at initialization.
	#[must_use]
	pub const fn profile_identity(&self) -> FileIdentity {
		self.profile_identity
	}

	/// Exact immutable selection identifier.
	#[must_use]
	pub const fn selection_id(&self) -> [u8; 16] {
		self.pin.identity.selection_id
	}

	/// Positive revision independently selected for this immutable policy.
	#[must_use]
	pub const fn selection_revision(&self) -> NonZeroU64 {
		self.pin.identity.revision
	}

	/// Public key of the enrolled ordinary owner identity.
	#[must_use]
	pub const fn owner_key(&self) -> [u8; 32] {
		self.pin.identity.owner_key
	}

	/// Digest of the exact acknowledged policy.
	#[must_use]
	pub const fn policy_digest(&self) -> [u8; 32] {
		self.pin.digest
	}
}

/// Refused managed policy initialization or authenticated read-only preview.
#[derive(Debug)]
#[non_exhaustive]
pub enum ManagedSyncPreviewError {
	/// Independent selection differs from the held facts or retained policy pin.
	Selection,
	/// A required signed acknowledgement was invalid or could not be issued.
	Acknowledgement,
	/// The private bounded policy was refused.
	Policy(ManagedPolicyError),
	/// The selected app-private record could not be held, verified or stored.
	Store(SyncProfileStoreError),
	/// The created slot is retained because a final custody check failed.
	///
	/// No approved selection receipt was issued.
	CreationUnconfirmed(Box<Self>),
	/// Ordinary native root/path observation refused.
	Native(SyncPreviewError),
	/// Real selected and leased managed native scope refused.
	Managed(ManagedSyncError),
	/// The selected historical artifact could not be opened.
	ReadHistory(std::io::Error),
	/// Exact selected signed history was refused.
	History(SyncGenesisError),
	/// An independent live measurement or final comparison was refused.
	Preview(Box<HistoricalPreviewFailure<ReadError, Self>>),
}

impl fmt::Display for ManagedSyncPreviewError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Selection => formatter.write_str("managed synchronization selection refused"),
			Self::Acknowledgement => {
				formatter.write_str("managed synchronization acknowledgement refused")
			}
			Self::Policy(_) => formatter.write_str("managed synchronization policy refused"),
			Self::Store(_) => formatter.write_str("managed synchronization policy custody refused"),
			Self::CreationUnconfirmed(_) => {
				formatter.write_str("managed synchronization policy creation remains unconfirmed")
			}
			Self::Native(_) | Self::Managed(_) => {
				formatter.write_str("managed synchronization native scope refused")
			}
			Self::ReadHistory(_) | Self::History(_) => {
				formatter.write_str("selected synchronization history refused")
			}
			Self::Preview(_) => formatter.write_str("managed synchronization live preview refused"),
		}
	}
}

impl std::error::Error for ManagedSyncPreviewError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::CreationUnconfirmed(cause) => Some(cause.as_ref()),
			_ => None,
		}
	}
}

/// Acknowledges one explicitly selected immutable private policy.
///
/// This operation reads the existing owner seed from the same held profile only
/// to obtain its public identity. It creates no history and performs no sync effect.
///
/// # Errors
/// Refuses unqualified or changed authority, historical custody, an occupied slot,
/// and any unacknowledged write or verification.
pub fn initialize_managed_preview(
	request: ManagedSyncInit<'_>,
) -> Result<ManagedSyncSelection, ManagedSyncPreviewError> {
	let store = SyncProfileStore::open(request.profile).map_err(ManagedSyncPreviewError::Store)?;
	initialize(&store, request, None, |selection, _| Ok(selection))
}

fn initialize<T>(
	store: &SyncProfileStore,
	request: ManagedSyncInit<'_>,
	approved: Option<&ManagedPolicyPin>,
	acknowledge: impl FnOnce(ManagedSyncSelection, &SigningKey) -> Result<T, ManagedSyncPreviewError>,
) -> Result<T, ManagedSyncPreviewError> {
	type Failure = ManagedSyncPreviewError;

	let ManagedSyncInit {
		profile,
		profile_identity,
		selection_id,
		selection_revision,
		policy,
	} = request;
	if store.identity() != profile_identity {
		return Err(Failure::Selection);
	}
	let mut seed = Zeroizing::new([0; ed25519_dalek::SECRET_KEY_LENGTH]);
	let mut probe = Zeroizing::new([0; 1]);
	let owner_seed = store
		.open_seed(&mut seed, &mut probe)
		.map_err(Failure::Store)?;
	let signer = SigningKey::from_bytes(&seed);
	let key = signer.verifying_key();
	let identity = ManagedPolicyIdentity {
		selection_id,
		revision: selection_revision,
		owner_profile: *profile_id_for_key(&key)
			.map_err(|_| Failure::Selection)?
			.as_bytes(),
		owner_key: key.to_bytes(),
	};
	let (encoded, pin) = encode(&identity, policy).map_err(Failure::Policy)?;
	if approved.is_some_and(|expected| expected != &pin) {
		return Err(Failure::Selection);
	}
	let scope = expected_native(policy)?;
	let roots = SyncPreviewRoots::open(scope.parent_path, scope.roots.map(|root| root.name))
		.map_err(Failure::Native)?;
	let lease = roots
		.acquire_managed_history_lease(scope)
		.map_err(Failure::Managed)?;
	let history = store
		.open_history(raw_path(&policy.history.path))
		.map_err(Failure::Store)?;
	if native_object(history.read_root().identity())? != policy.history.directory {
		return Err(Failure::Selection);
	}
	store
		.check_disjoint(&history, &roots)
		.map_err(Failure::Store)?;
	let mut root_bytes = [0; MAX_MEMBER_BYTES];
	let actual = lease.recheck_roots().map_err(Failure::Managed)?;
	let endpoints = fresh_endpoints(policy, actual)?;
	authenticate(
		history.read_root(),
		policy,
		&identity,
		&key,
		endpoints,
		&mut root_bytes,
		false,
	)?;
	store
		.check_disjoint(&history, &roots)
		.map_err(Failure::Store)?;
	lease.recheck_roots().map_err(Failure::Managed)?;
	let mut seed_check = Zeroizing::new([0; ed25519_dalek::SECRET_KEY_LENGTH]);
	let mut seed_eof = Zeroizing::new([0; 1]);
	let sealed = owner_seed
		.create(
			selection_id,
			&encoded,
			&seed,
			&mut seed_check,
			&mut seed_eof,
		)
		.map_err(Failure::Store)?;
	let confirm = || {
		sealed.recheck().map_err(Failure::Store)?;
		store
			.check_disjoint(&history, &roots)
			.map_err(Failure::Store)?;
		lease.recheck_roots().map_err(Failure::Managed)?;
		Ok(())
	};
	confirm().map_err(|cause| Failure::CreationUnconfirmed(Box::new(cause)))?;

	acknowledge(
		ManagedSyncSelection {
			profile: profile.to_path_buf(),
			profile_identity,
			pin,
		},
		&signer,
	)
	.map_err(|cause| Failure::CreationUnconfirmed(Box::new(cause)))
}

/// Opens precisely the acknowledged selection and classifies one live subject.
///
/// This path has no access to the signing seed or policy initialization, and
/// refuses missing history without falling back to a first-run comparison.
///
/// # Errors
/// Refuses any incomplete, unbound, unavailable or changed authority or evidence.
pub fn preview_managed_history(
	selection: &ManagedSyncSelection,
	scratch: &mut [u8],
) -> Result<FirstSyncPreview, ManagedSyncPreviewError> {
	let store = selected_store(selection)?;
	preview_held(&store, &selection.pin, scratch)
}

fn selected_store(
	selection: &ManagedSyncSelection,
) -> Result<SyncProfileStore, ManagedSyncPreviewError> {
	type Failure = ManagedSyncPreviewError;

	let store = SyncProfileStore::open(&selection.profile).map_err(Failure::Store)?;
	if store.identity() != selection.profile_identity {
		return Err(Failure::Selection);
	}
	Ok(store)
}

fn preview_held(
	store: &SyncProfileStore,
	pin: &ManagedPolicyPin,
	scratch: &mut [u8],
) -> Result<FirstSyncPreview, ManagedSyncPreviewError> {
	with_history_view(store, pin, |baseline, current, _key| {
		preview_with_history(baseline, current, scratch)
			.map_err(|error| ManagedSyncPreviewError::Preview(Box::new(error)))
	})
}

fn with_history_view<T, E>(
	store: &SyncProfileStore,
	pin: &ManagedPolicyPin,
	observe: impl FnOnce(
		&AuthenticatedSyncGenesis<'_, '_>,
		&ManagedHistoryPreview<'_, '_, '_>,
		&VerifyingKey,
	) -> Result<T, E>,
) -> Result<T, E>
where
	E: From<ManagedSyncPreviewError>,
{
	type Failure = ManagedSyncPreviewError;

	let key = verify_owner_identity(&pin.identity)?;
	let record = store
		.read(pin.identity.selection_id)
		.map_err(Failure::Store)?;
	with_held_history_view(pin, &record, &key, false, |baseline, current, key, _| {
		observe(baseline, current, key)
	})
}

fn with_held_history_view<T, E>(
	pin: &ManagedPolicyPin,
	record: &SyncProfileStoreRecord<'_>,
	key: &VerifyingKey,
	retain_history: bool,
	observe: impl FnOnce(
		&AuthenticatedSyncGenesis<'_, '_>,
		&ManagedHistoryPreview<'_, '_, '_>,
		&VerifyingKey,
		Option<RetainedSyncGenesisMembers>,
	) -> Result<T, E>,
) -> Result<T, E>
where
	E: From<ManagedSyncPreviewError>,
{
	type Failure = ManagedSyncPreviewError;

	let identity = &pin.identity;
	let policy = decode(record.bytes(), pin).map_err(Failure::Policy)?;
	let scope = expected_native(&policy)?;
	let roots = SyncPreviewRoots::open(scope.parent_path, scope.roots.map(|root| root.name))
		.map_err(Failure::Native)?;
	let lease = roots
		.acquire_managed_history_lease(scope)
		.map_err(Failure::Managed)?;
	let history = record
		.open_history(raw_path(&policy.history.path))
		.map_err(Failure::Store)?;
	if native_object(history.read_root().identity())? != policy.history.directory {
		return Err(Failure::Selection.into());
	}
	let recheck_custody = || {
		record
			.recheck_history_scope(&history, &roots)
			.map_err(Failure::Store)
	};
	recheck_custody()?;
	let mut root_bytes = [0; MAX_MEMBER_BYTES];
	let actual = lease.recheck_roots().map_err(Failure::Managed)?;
	let endpoints = fresh_endpoints(&policy, actual)?;
	let (baseline, retained) = authenticate(
		history.read_root(),
		&policy,
		identity,
		key,
		endpoints,
		&mut root_bytes,
		retain_history,
	)?;
	let pair = lease.observe().map_err(Failure::Managed)?;
	let current = ManagedHistoryPreview {
		pair: &pair,
		policy: &policy,
		identity,
		recheck_custody: &recheck_custody,
	};
	let observed = observe(&baseline, &current, key, retained)?;
	recheck_custody()?;
	Ok(observed)
}

fn verify_owner_identity(
	identity: &ManagedPolicyIdentity,
) -> Result<VerifyingKey, ManagedSyncPreviewError> {
	use ManagedSyncPreviewError as Failure;

	let key = VerifyingKey::from_bytes(&identity.owner_key).map_err(|_| Failure::Selection)?;
	if key.is_weak()
		|| key.to_edwards().compress().to_bytes() != identity.owner_key
		|| profile_id_for_key(&key)
			.map_err(|_| Failure::Selection)?
			.as_bytes()
			!= &identity.owner_profile
	{
		return Err(Failure::Selection);
	}
	Ok(key)
}

struct ManagedHistoryPreview<'call, 'view, 'selected> {
	pair: &'call ManagedSyncPreviewPair<'view, 'selected>,
	policy: &'selected ManagedPolicy,
	identity: &'call ManagedPolicyIdentity,
	recheck_custody: &'call dyn Fn() -> Result<(), ManagedSyncPreviewError>,
}

impl<'view> HeldSyncPreview for ManagedHistoryPreview<'_, 'view, '_> {
	type View = NamedReadView<'view>;
	type Error = ManagedSyncPreviewError;

	fn observations(&self) -> [PreviewInput<'_, Self::View>; 2] {
		self.pair.entries().map(|entry| match entry {
			SyncPreviewEntry::Present(view) => {
				let observed = view.metadata();
				let Ok(mode) = u16::try_from(observed.mode()) else {
					return PreviewInput::Unsupported;
				};
				PreviewInput::Present {
					view,
					metadata: LinuxOwnerMode {
						mode,
						uid: observed.owner(),
						gid: observed.group(),
					},
				}
			}
			SyncPreviewEntry::Absent => PreviewInput::Absent,
			SyncPreviewEntry::Unsupported => PreviewInput::Unsupported,
		})
	}

	fn recheck_selection(&self) -> Result<LiveSyncSelection<'_>, Self::Error> {
		(self.recheck_custody)()?;
		let (subject, actual) = self
			.pair
			.recheck_history_location()
			.map_err(ManagedSyncPreviewError::Managed)?;
		let endpoints = fresh_endpoints(self.policy, actual)?;
		(self.recheck_custody)()?;
		Ok(LiveSyncSelection {
			profile: self.identity.owner_profile,
			revision: self.policy.history.revision,
			owner_key: self.identity.owner_key,
			subject,
			endpoints,
		})
	}
}
