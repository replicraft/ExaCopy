//! Read-only admission for an explicitly approved protected replacement attempt.

use exacopy_model::protected_replace::{
	AdmissionHistory, Context, CurrentGrant, Digest, Entry, HistoryDisposition, JournalHead,
	Refusal, Selection, Session, StageReady,
};

#[cfg(test)]
mod tests;

/// Visibility and retention consequences accepted in the authenticated owner approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisibilityDisclosure {
	/// The public name may be absent and a racing opaque entry may be retained privately.
	///
	/// If the racing entry is a directory, its descendants may also become unavailable.
	PublicGapAndOpaqueRetention,
	/// The owner did not approve every required consequence.
	Incomplete,
}

/// Exact approved protected selection, including the owner and visibility consequences.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerApproval<'name> {
	/// Authenticated owner identity in the selected trust domain.
	pub owner: Digest,
	/// Complete single-entry selection authorized by that owner.
	pub selection: Selection<'name>,
	/// Consequences disclosed to and accepted by the owner for this selection.
	pub disclosure: VisibilityDisclosure,
}

/// One current journal boundary bound independently to the held scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeldJournalHead<'name> {
	/// Scope identified by the observer of this boundary.
	pub context: Context<'name>,
	/// Observed durable boundary of the journal.
	pub head: JournalHead,
}

/// Complete relevant replay tied to its independently observed terminal boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedReplay<'name> {
	/// Binding and exact terminal head established by the replay.
	pub boundary: HeldJournalHead<'name>,
	/// Whether any intent in the selected scope could already have taken effect.
	pub disposition: HistoryDisposition,
}

/// Observations from the bound incumbent lookup and held replacement stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedPreparation<'name> {
	/// Exact regular incumbent independently observed without following links.
	pub incumbent: Entry<'name>,
	/// Current verification and seal evidence for the held stage.
	pub stage: StageReady<'name>,
}

/// Current independent authorizations for the two distinct protected effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedGrants<'name> {
	/// Current unrevoked opaque slot relocation authority at the final shared clock sample.
	pub capture: CurrentGrant<'name>,
	/// Current unrevoked exclusive placement authority at the same clock sample.
	pub publication: CurrentGrant<'name>,
}

/// Read-only observations supplied under one exclusive live admission lease.
///
/// The implementation must serialize admission for the selected scope, exclude overlapping
/// leases, establish physical layout and alias exclusions, and serialize approval changes
/// through the admission decision. It must hold the lease until
/// dropped and report unavailable or ambiguous observations instead of inferring success.
/// The engine compares reports from this capability and relies on the owner for authentication,
/// independent observations, and lease enforcement.
pub trait HeldProtectedAdmission<'name> {
	/// Authenticate the current explicit owner approval independently of the request.
	fn owner_approval(&self) -> Option<OwnerApproval<'name>>;

	/// Check authoritative replay across all relevant attempts for these slots.
	///
	/// The complete history includes any earlier epoch that could affect these slots.
	fn replay(&self) -> Option<ProtectedReplay<'name>>;

	/// Observe the current durable head independently of the replay.
	fn durable_head(&self) -> Option<HeldJournalHead<'name>>;

	/// Independently observe the matching incumbent and currently held stage.
	fn preparation(&self) -> Option<ProtectedPreparation<'name>>;

	/// Revalidate the current held context, independent grants, and monotonic time.
	fn current_grants(&self) -> Option<ProtectedGrants<'name>>;
}

/// Reason a protected replacement could not be admitted without mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedAdmissionError {
	/// The authenticated approval does not match the selected owner and entire selection.
	Approval,
	/// The required visibility and retention consequences were not approved.
	Disclosure,
	/// Current stage and incumbent observations could not be obtained.
	PreparationUnavailable,
	/// A live grant, its scope, or its expiry could not be confirmed.
	Authority,
	/// Earlier intent or uncertain history requires reconciliation.
	ReconciliationRequired,
	/// The selected layout, incumbent or stage failed the model's admission checks.
	Model(Refusal),
}

/// A prepared model session retaining the exclusive admission lease for its lifetime.
pub struct PreparedAdmission<'name, L> {
	_session: Session<'name>,
	_lease: L,
}

/// Checks one owner-approved protected replacement under an owned live lease.
///
/// Approval covers the full selection and the disclosure. Both grants must be current
/// after replay and stage checks. The returned guard provides read-only admission evidence.
/// Future journal or namespace effects require their own current authority and checks.
///
/// # Errors
/// Refuses missing approval, incomplete disclosure, uncertain history, invalid preparation,
/// or unavailable or mismatched current authority.
pub fn admit<'name, L: HeldProtectedAdmission<'name>>(
	lease: L,
	owner: Digest,
	selection: Selection<'name>,
) -> Result<PreparedAdmission<'name, L>, ProtectedAdmissionError> {
	let approval = lease
		.owner_approval()
		.ok_or(ProtectedAdmissionError::Approval)?;
	if owner == [0; 32] || approval.owner != owner || approval.selection != selection {
		return Err(ProtectedAdmissionError::Approval);
	}
	if approval.disclosure != VisibilityDisclosure::PublicGapAndOpaqueRetention {
		return Err(ProtectedAdmissionError::Disclosure);
	}

	let history = fresh_history(&lease, selection.context)?;
	let preparation = lease
		.preparation()
		.ok_or(ProtectedAdmissionError::PreparationUnavailable)?;
	let session = Session::start(selection, preparation.incumbent, preparation.stage, history)
		.map_err(|refusal| match refusal {
			Refusal::History | Refusal::Evidence => ProtectedAdmissionError::ReconciliationRequired,
			other => ProtectedAdmissionError::Model(other),
		})?;
	let grants = lease
		.current_grants()
		.ok_or(ProtectedAdmissionError::Authority)?;
	if grants.capture.now != grants.publication.now
		|| !grants.capture.admits(selection.context, selection.capture)
		|| !grants
			.publication
			.admits(selection.context, selection.publication)
	{
		return Err(ProtectedAdmissionError::Authority);
	}
	Ok(PreparedAdmission {
		_session: session,
		_lease: lease,
	})
}

fn fresh_history<'name>(
	lease: &impl HeldProtectedAdmission<'name>,
	context: Context<'name>,
) -> Result<AdmissionHistory<'name>, ProtectedAdmissionError> {
	let replay = lease
		.replay()
		.ok_or(ProtectedAdmissionError::ReconciliationRequired)?;
	let current = lease
		.durable_head()
		.ok_or(ProtectedAdmissionError::ReconciliationRequired)?;
	if replay.disposition != HistoryDisposition::FreshPreIntent
		|| replay.boundary != current
		|| current.context != context
	{
		return Err(ProtectedAdmissionError::ReconciliationRequired);
	}
	Ok(AdmissionHistory {
		context,
		replayed: replay.boundary.head,
		current: current.head,
		disposition: replay.disposition,
	})
}
