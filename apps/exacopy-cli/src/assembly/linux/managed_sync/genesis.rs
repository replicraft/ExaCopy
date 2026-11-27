//! Explicit immutable genesis production from one held owner-managed sync pair.

use std::fmt;
use std::io;
use std::num::{NonZeroU16, NonZeroU64};
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_plan::workflow_sync::{EndpointFacts, WorkflowKind, WorkflowRef};
use exacopy_platform::linux::{
	FileIdentity, ManagedSyncNativeScope, OWNER_SEED_BYTES, ReadError, SyncGenesisEffectRequest,
	SyncGenesisIntent, SyncGenesisMemberBinding, SyncGenesisNativeIdentity, SyncGenesisOperation,
	SyncGenesisOutput, SyncGenesisPublishError, SyncGenesisPublishRequest, SyncGenesisPublished,
	SyncPreviewRoots, SyncProfileStore,
};
use exacopy_transfer::linux::sync_genesis_measurement::{
	GenesisMeasureFailure, HeldGenesisPair, measure_genesis_pair,
};
use exacopy_transfer::linux::sync_preview::LiveSyncSelection;
use exacopy_transfer::sync_genesis::{ExpectedSyncGenesis, SyncGenesisError, SyncGenesisRecords};
use zeroize::Zeroizing;

use crate::profile::profile_id_for_key;

use super::ManagedSyncPreviewError;

mod approval;
mod live;
pub mod recovery_observation;
mod staged;

use approval::Approval;
use live::LiveGenesisPair;

/// Finite independently approved cooperative writer enrollment for this exact scope.
///
/// Kernel leases constrain cooperating actors. The provisioner is responsible
/// for excluding uncontrolled mutators and retaining the expected digest.
pub struct ManagedGenesisEnrollment<'selection> {
	/// Nonzero stable identifier for the explicitly chosen enrollment.
	pub id: [u8; 16],
	/// Sorted, distinct nonzero active participant IDs in the chosen enrollment.
	pub participants: &'selection [[u8; 16]],
	/// Exact approval digest obtained independently from the offered roster and scope.
	pub expected_digest: [u8; 32],
}

/// Independently approved owner, live pair, enrollment and protected output.
pub struct ManagedGenesisRequest<'selection> {
	/// Canonical absolute existing profile path.
	pub profile: &'selection Path,
	/// Exact independently selected existing profile directory identity.
	pub profile_identity: FileIdentity,
	/// Expected canonical strong public key of that selected profile.
	pub owner_key: [u8; 32],
	/// Independently selected owner profile revision.
	pub profile_revision: NonZeroU64,
	/// Current exact native scope, actor and raw subject selected by the provisioner.
	pub native: ManagedSyncNativeScope<'selection>,
	/// Ordered exact endpoint expectations and stream ceilings.
	pub endpoints: [EndpointFacts<'selection>; 2],
	/// Independently approved finite cooperator policy.
	pub enrollment: ManagedGenesisEnrollment<'selection>,
	/// Canonical separately protected output parent path.
	pub output_parent: &'selection Path,
	/// Independently selected existing output parent identity.
	pub output_identity: SyncGenesisNativeIdentity,
	/// Unique approved operation determines the fixed output and private evidence names.
	pub operation: SyncGenesisOperation,
	/// Independently selected nonzero scan label.
	pub scan: NonZeroU64,
	/// Explicit recorded UUIDv7 identities and creation time.
	pub records: SyncGenesisRecords,
}

/// Confirmed immutable genesis resources for independent subsequent selection.
///
/// This report holds no live filesystem mutation, baseline or resume authority.
pub struct ManagedGenesisPublished {
	/// Observed exact published directory of the operation.
	pub publication: SyncGenesisPublished,
	/// The complete signed root's exact typed commitment.
	pub root: WorkflowRef,
	/// Ordered endpoints and paired leaf.
	pub children: [WorkflowRef; 3],
}

/// Refusal while preparing or publishing an exact selected genesis closure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ManagedGenesisError {
	/// Independently approved owner, enrollment or selected roles did not agree.
	Selection,
	/// Existing profile, native scope or path admission failed.
	Scope(ManagedSyncPreviewError),
	/// Two independently measured live read views did not qualify.
	Measurement(GenesisMeasureFailure<ReadError, ManagedSyncPreviewError>),
	/// Canonical signed history production or independent admission failed.
	Artifact(SyncGenesisError),
	/// Publication stopped before submission or retained an uncertain outcome.
	Output(SyncGenesisPublishError),
}

impl fmt::Display for ManagedGenesisError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Selection => formatter.write_str("managed sync genesis approval refused"),
			Self::Scope(error) => error.fmt(formatter),
			Self::Measurement(error) => error.fmt(formatter),
			Self::Artifact(error) => error.fmt(formatter),
			Self::Output(error) => error.fmt(formatter),
		}
	}
}

impl std::error::Error for ManagedGenesisError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Selection => None,
			Self::Scope(error) => Some(error),
			Self::Measurement(error) => Some(error),
			Self::Artifact(error) => Some(error),
			Self::Output(error) => Some(error),
		}
	}
}

/// Produces and verifies a new immutable generation-one closure in the approved output.
///
/// The owner approves this precise live scope, finite cooperating writers and
/// separate private output parent before calling. The routine uses the same
/// held owner seed and actual live read lease through each effect and creates
/// one no-clobber directory. It never mutates either synchronized root.
///
/// # Errors
/// Refuses changed or unselected authority, incomplete or unequal observations,
/// bounded encoding failures, and unconfirmed publication. It preserves partial
/// private evidence and incumbents on any effect refusal.
pub fn produce_managed_genesis(
	request: &ManagedGenesisRequest<'_>,
	scratch: &mut [u8],
) -> Result<ManagedGenesisPublished, ManagedGenesisError> {
	use ManagedGenesisError as Failure;
	use ManagedSyncPreviewError as Scope;

	let owner = VerifyingKey::from_bytes(&request.owner_key).map_err(|_| Failure::Selection)?;
	if owner.is_weak() || owner.to_edwards().compress().to_bytes() != request.owner_key {
		return Err(Failure::Selection);
	}
	let owner_profile = *profile_id_for_key(&owner)
		.map_err(|_| Failure::Selection)?
		.as_bytes();
	let store = SyncProfileStore::open(request.profile)
		.map_err(Scope::Store)
		.map_err(Failure::Scope)?;
	if store.identity() != request.profile_identity {
		return Err(Failure::Selection);
	}
	let mut seed = Zeroizing::new([0; OWNER_SEED_BYTES]);
	let mut eof = Zeroizing::new([0; 1]);
	let held_seed = store
		.open_seed(&mut seed, &mut eof)
		.map_err(Scope::Store)
		.map_err(Failure::Scope)?;
	let signer = SigningKey::from_bytes(&seed);
	if signer.verifying_key() != owner {
		return Err(Failure::Selection);
	}

	let native = request.native;
	let roots = SyncPreviewRoots::open(native.parent_path, native.roots.map(|root| root.name))
		.map_err(Scope::Native)
		.map_err(Failure::Scope)?;
	let lease = roots
		.acquire_managed_history_lease(native)
		.map_err(Scope::Managed)
		.map_err(Failure::Scope)?;
	let pair = lease
		.observe()
		.map_err(Scope::Managed)
		.map_err(Failure::Scope)?;
	let expected = LiveSyncSelection {
		profile: owner_profile,
		revision: request.profile_revision,
		owner_key: request.owner_key,
		subject: native.subject,
		endpoints: request.endpoints,
	};
	let current = LiveGenesisPair {
		pair: &pair,
		expected,
	};
	current.recheck_selection().map_err(Failure::Scope)?;
	let approval = Approval::select(request, owner_profile)?;
	let output = SyncGenesisOutput::open(request.output_parent, request.output_identity)
		.map_err(Scope::Store)
		.map_err(Failure::Scope)?;
	let measured = measure_genesis_pair(&current, expected, request.scan, scratch)
		.map_err(Failure::Measurement)?;
	let mut seed_check = Zeroizing::new([0; OWNER_SEED_BYTES]);
	let mut seed_eof = Zeroizing::new([0; 1]);
	let mut recheck = || -> Result<(), Failure> {
		held_seed
			.recheck_seed(&seed, &mut seed_check, &mut seed_eof)
			.map_err(Scope::Store)
			.map_err(Failure::Scope)?;
		measured.recheck().map_err(Failure::Measurement)?;
		approval.recheck()
	};
	recheck()?;
	let assembled = measured
		.assemble(request.records, &signer)
		.map_err(Failure::Artifact)?;
	let root = WorkflowRef {
		digest: assembled.root_digest(),
		kind: WorkflowKind::Root,
		byte_len: u16::try_from(assembled.root_bytes().len()).map_err(|_| Failure::Selection)?,
	};
	let [left, right, leaf] = assembled.members();
	let children = [left.1, right.1, leaf.1];
	let members = [assembled.root_bytes(), left.0, right.0, leaf.0];
	let intent = SyncGenesisIntent {
		operation: request.operation,
		output: request.output_identity,
		approval: approval.intent_commitment(root.digest),
		members: [
			binding(root, members[0])?,
			binding(children[0], members[1])?,
			binding(children[1], members[2])?,
			binding(children[2], members[3])?,
		],
	};
	let selection = measured.selection();
	let historical = ExpectedSyncGenesis {
		root_digest: root.digest,
		profile: selection.profile,
		revision: selection.revision,
		owner: &owner,
		subject: selection.subject,
		endpoints: selection.endpoints,
		scan: Some(measured.scan()),
	};
	let enter = |effect: SyncGenesisEffectRequest<'_>| {
		if effect.intent != &intent
			|| effect.output.device() != request.output_identity.device
			|| effect.output.inode() != request.output_identity.inode.get()
		{
			return Err(io::Error::other(
				"selected genesis effect differs from approval",
			));
		}
		recheck().map_err(io::Error::other)
	};
	let publication = output
		.publish(
			&held_seed,
			&pair,
			SyncGenesisPublishRequest {
				intent: &intent,
				members,
			},
			|observed| staged::verify(observed, &historical, children, measured.sides()),
			enter,
		)
		.map_err(Failure::Output)?;
	Ok(ManagedGenesisPublished {
		publication,
		root,
		children,
	})
}

fn binding(
	reference: WorkflowRef,
	bytes: &[u8],
) -> Result<SyncGenesisMemberBinding, ManagedGenesisError> {
	Ok(SyncGenesisMemberBinding {
		kind: reference.kind as u16,
		byte_len: NonZeroU16::new(reference.byte_len).ok_or(ManagedGenesisError::Selection)?,
		canonical_digest: reference.digest,
		raw_digest: *blake3::hash(bytes).as_bytes(),
	})
}
