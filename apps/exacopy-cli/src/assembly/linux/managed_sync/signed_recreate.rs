use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use exacopy_endpoint::UnixComponent;
use exacopy_model::{SyncConflict, SyncSide};
use exacopy_plan::UnixTimestamp;
use exacopy_plan::workflow_sync::recreate::{
	RecreateAction, RecreateObservation, RecreateParent, RecreateReason, RecreateSide,
	action_reference, encode_action, encode_parent, encode_parent_envelope, observation_digests,
	parent_signing_input,
};
use exacopy_platform::linux::{HeldSyncExportProfile, OWNER_SEED_BYTES};
use exacopy_transfer::linux::sync_preview::HeldSyncPreview as _;
use exacopy_transfer::sync_genesis::recreate::{
	ExpectedRecreateExport, RecreateSourceEvidence, verify_recreate_export,
};
use exacopy_transfer::sync_genesis::{
	AuthenticatedSyncGenesis, ExpectedSyncGenesis, RetainedSyncGenesisMembers,
};
use zeroize::Zeroizing;

use super::acknowledgement::with_acknowledgement;
use super::manual_recreate::{RecreateReview, prepare_current};
use super::scope::{component, native_object};
use super::{
	ManagedHistoryPreview, ManagedSyncPreviewError, ManualRecreateError, ManualRecreatePlanIds,
	verify_owner_identity, with_held_history_view,
};

pub(crate) struct SignedRecreateRequest<'input> {
	pub(crate) profile: &'input Path,
	pub(crate) owner_key: [u8; 32],
	pub(crate) selection: [u8; 16],
	pub(crate) acknowledgement: &'input [u8],
	pub(crate) pair_id: [u8; 16],
	pub(crate) parent_id: [u8; 16],
	pub(crate) action_id: [u8; 16],
	pub(crate) from: SyncSide,
	pub(crate) reviewed: SyncConflict,
	pub(crate) ids: ManualRecreatePlanIds,
	pub(crate) expires_at: UnixTimestamp,
}

pub(crate) struct SignedRecreateExport {
	pub(crate) pair_id: [u8; 16],
	pub(crate) predecessor_pair_digest: [u8; 32],
	pub(crate) parent_digest: [u8; 32],
	pub(crate) members: [Vec<u8>; 8],
}

pub(crate) enum SignedRecreateError {
	Scope(ManagedSyncPreviewError),
	Planning(ManualRecreateError),
	Custody,
	Clock,
	Bundle,
}

impl From<ManagedSyncPreviewError> for SignedRecreateError {
	fn from(error: ManagedSyncPreviewError) -> Self {
		Self::Scope(error)
	}
}

pub(crate) fn export_recreate_acknowledged(
	request: SignedRecreateRequest<'_>,
	scratch: &mut [u8],
	now: impl Fn() -> Option<UnixTimestamp>,
) -> Result<SignedRecreateExport, SignedRecreateError> {
	use SignedRecreateError as Error;
	let (exported, _) = with_acknowledgement(
		request.profile,
		request.owner_key,
		request.selection,
		request.acknowledgement,
		|store, pin| {
			let key = verify_owner_identity(&pin.identity)?;
			let profile = store
				.read_for_export(pin.identity.selection_id)
				.map_err(|_| Error::Custody)?;
			with_held_history_view(
				store,
				pin,
				profile.record(),
				&key,
				true,
				|baseline, current, key, retained| {
					let live = HeldRecreate {
						baseline,
						current,
						key,
						policy_digest: pin.digest,
						profile: &profile,
					};
					live.export(&request, retained.ok_or(Error::Bundle)?, scratch, &now)
				},
			)
		},
	)?;
	Ok(exported)
}

struct HeldRecreate<'a, 'root, 'view, 'name, 'store> {
	baseline: &'a AuthenticatedSyncGenesis<'root, 'name>,
	current: &'a ManagedHistoryPreview<'a, 'view, 'name>,
	key: &'a VerifyingKey,
	policy_digest: [u8; 32],
	profile: &'a HeldSyncExportProfile<'store>,
}

impl HeldRecreate<'_, '_, '_, '_, '_> {
	fn export(
		&self,
		request: &SignedRecreateRequest<'_>,
		retained: RetainedSyncGenesisMembers,
		scratch: &mut [u8],
		now: &impl Fn() -> Option<UnixTimestamp>,
	) -> Result<SignedRecreateExport, SignedRecreateError> {
		use SignedRecreateError as Error;
		let candidate = prepare_current(
			self.baseline,
			self.current,
			self.key,
			self.policy_digest,
			RecreateReview {
				from: request.from,
				conflict: request.reviewed,
				ids: request.ids,
				expires_at: Some(request.expires_at),
			},
			scratch,
		)
		.map_err(Error::Planning)?;
		let old = self.baseline.root();
		let selected_history = &self.current.policy.history;
		// Initial read matched the exact selected policy inventory; its authenticated
		// root supplies the endpoint order, independent of this new bundle.
		let references = [
			selected_history.root.reference,
			old.endpoints[0],
			old.endpoints[1],
			old.leaf,
		];
		let native = native_object(candidate.source_identity)?;
		let subject = UnixComponent::new(&candidate.subject).map_err(|_| Error::Bundle)?;
		let side = match candidate.from {
			SyncSide::Left => RecreateSide::Left,
			SyncSide::Right => RecreateSide::Right,
		};
		let reason = match candidate.conflict {
			SyncConflict::DeletionAgainstUnchanged { .. } => {
				RecreateReason::DeletionAgainstUnchanged
			}
			SyncConflict::EditAgainstDeletion { .. } => RecreateReason::EditAgainstDeletion,
			_ => return Err(Error::Bundle),
		};
		let action = encode_action(&RecreateAction {
			id: request.action_id,
			side,
			name: subject,
			source: native,
			stream_length: candidate.source.byte_len,
			stream_digest: candidate.source.content_digest,
			metadata_digest: candidate.source.required_metadata_digest,
			child_digest: candidate.child.digest(),
			child_page: candidate.child.page_ref(),
			reason,
		})
		.map_err(|_| Error::Bundle)?;
		let page = action_reference(&action).map_err(|_| Error::Bundle)?;
		let coverage = observation_digests(&RecreateObservation {
			pair_id: request.pair_id,
			predecessor_pair: old.pair,
			endpoints: old.endpoints,
			predecessor: references[0],
			scope: old.scope,
			policy_pin: self.policy_digest,
			action_page: page,
		})
		.map_err(|_| Error::Bundle)?;
		let body = encode_parent(&RecreateParent {
			id: request.parent_id,
			profile: self.current.identity.owner_profile,
			pair_id: request.pair_id,
			endpoints: old.endpoints,
			predecessor: references[0],
			filter: old.filter,
			policy: old.policy,
			coverage,
			action_page: page,
			created_at: request.ids.observed_at,
			expires_at: request.expires_at,
		})
		.map_err(|_| Error::Bundle)?;
		let mut seed = Zeroizing::new([0; OWNER_SEED_BYTES]);
		let mut probe = Zeroizing::new([0; 1]);
		let held_seed = self
			.profile
			.hold_seed_for_export(&mut seed, &mut probe)
			.map_err(|_| Error::Custody)?;
		let signer = SigningKey::from_bytes(&seed);
		if signer.verifying_key() != *self.key {
			return Err(Error::Custody);
		}
		let signed = parent_signing_input(&body).map_err(|_| Error::Bundle)?;
		let signature = signer.sign(&signed).to_bytes();
		let envelope = encode_parent_envelope(&body, self.key.to_bytes(), signature)
			.map_err(|_| Error::Bundle)?;
		let [root, left, right, leaf] = retained.members();
		let members = [
			envelope.as_slice(),
			action.as_slice(),
			candidate.child.canonical_body(),
			candidate.child.canonical_page(),
			root,
			left,
			right,
			leaf,
		];
		let expected = ExpectedSyncGenesis {
			root_digest: selected_history.root.reference.digest,
			profile: self.current.identity.owner_profile,
			revision: selected_history.revision,
			owner: self.key,
			subject: component(&self.current.policy.subject)?,
			endpoints: *self.baseline.endpoints(),
			scan: selected_history.scan,
		};
		let verified = verify_recreate_export(
			members,
			&ExpectedRecreateExport {
				history: &expected,
				predecessor: references,
				policy_digest: self.policy_digest,
				pair_id: request.pair_id,
				parent_id: request.parent_id,
				action_id: request.action_id,
				child_digest: candidate.child.digest(),
				created_at: request.ids.observed_at,
				expires_at: request.expires_at,
				now: now().ok_or(Error::Clock)?,
				root_aliases: candidate.roots.map(|root| root.child_alias),
				from: request.from,
				reviewed: request.reviewed,
				source: RecreateSourceEvidence {
					native,
					child: candidate.source_identity.into(),
					stream: candidate.source,
				},
			},
		)
		.map_err(|_| Error::Bundle)?;
		self.current.recheck_selection()?;
		let mut seed_check = Zeroizing::new([0; OWNER_SEED_BYTES]);
		held_seed
			.recheck_seed(&seed, &mut seed_check, &mut probe)
			.map_err(|_| Error::Custody)?;
		self.current.recheck_selection()?;
		let checked_at = now().ok_or(Error::Clock)?;
		if checked_at < request.ids.observed_at || checked_at >= request.expires_at {
			return Err(Error::Clock);
		}
		Ok(SignedRecreateExport {
			pair_id: request.pair_id,
			parent_digest: verified.parent_digest(),
			predecessor_pair_digest: verified.predecessor_pair_digest(),
			members: members.map(<[u8]>::to_vec),
		})
	}
}
