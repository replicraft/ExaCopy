use core::cell::{Cell, RefCell};
use core::num::NonZeroU64;

use exacopy_endpoint::UnixComponent;
use exacopy_model::protected_replace::{
	Directory, EntryKind, FilesystemId, Grant, ImagePolicy, ObjectId, Slot,
};
use exacopy_model::{CopyBinding, EntryId, JobId, RegularFileEvidence, RunEpoch, StageId};

use super::{
	Context, CurrentGrant, Digest, Entry, HeldJournalHead, HeldProtectedAdmission,
	HistoryDisposition, JournalHead, OwnerApproval, ProtectedAdmissionError as Error,
	ProtectedGrants, ProtectedPreparation, ProtectedReplay, Refusal, Selection, StageReady,
	VisibilityDisclosure, admit,
};

const OWNER: Digest = [8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Observation {
	Approval,
	Replay,
	DurableHead,
	Preparation,
	Grants,
}

#[derive(Default)]
struct Fixture {
	held: Cell<bool>,
	calls: RefCell<Vec<Observation>>,
}

impl Fixture {
	fn lease(&self) -> FixtureLease<'_> {
		assert!(!self.held.replace(true));
		let selection = selection();
		let context = selection.context;
		let head = HeldJournalHead {
			context,
			head: JournalHead {
				sequence: 1,
				digest: [23; 32],
			},
		};
		FixtureLease {
			fixture: self,
			approval: Some(OwnerApproval {
				owner: OWNER,
				selection,
				disclosure: VisibilityDisclosure::PublicGapAndOpaqueRetention,
			}),
			replay: Some(ProtectedReplay {
				boundary: head,
				disposition: HistoryDisposition::FreshPreIntent,
			}),
			head: Some(head),
			preparation: Some(ProtectedPreparation {
				incumbent: Entry {
					slot: context.target,
					object: selection.incumbent,
					kind: EntryKind::Regular,
				},
				stage: StageReady {
					context,
					object: selection.replacement,
					measured: selection.replacement_evidence,
					quiesced: true,
					data_flushed: true,
					independently_verified: true,
					metadata_ready: true,
					sealed: true,
				},
			}),
			grants: Some(ProtectedGrants {
				capture: CurrentGrant {
					context,
					grant: selection.capture,
					now: 1,
				},
				publication: CurrentGrant {
					context,
					grant: selection.publication,
					now: 1,
				},
			}),
		}
	}
}

type Invalidate = fn(&mut FixtureLease<'_>);

struct FixtureLease<'fixture> {
	fixture: &'fixture Fixture,
	approval: Option<OwnerApproval<'static>>,
	replay: Option<ProtectedReplay<'static>>,
	head: Option<HeldJournalHead<'static>>,
	preparation: Option<ProtectedPreparation<'static>>,
	grants: Option<ProtectedGrants<'static>>,
}

impl FixtureLease<'_> {
	fn record(&self, observation: Observation) {
		assert!(self.fixture.held.get());
		self.fixture.calls.borrow_mut().push(observation);
	}
}

impl Drop for FixtureLease<'_> {
	fn drop(&mut self) {
		assert!(self.fixture.held.replace(false));
	}
}

impl HeldProtectedAdmission<'static> for FixtureLease<'_> {
	fn owner_approval(&self) -> Option<OwnerApproval<'static>> {
		self.record(Observation::Approval);
		self.approval
	}

	fn replay(&self) -> Option<ProtectedReplay<'static>> {
		self.record(Observation::Replay);
		self.replay
	}

	fn durable_head(&self) -> Option<HeldJournalHead<'static>> {
		self.record(Observation::DurableHead);
		self.head
	}

	fn preparation(&self) -> Option<ProtectedPreparation<'static>> {
		self.record(Observation::Preparation);
		self.preparation
	}

	fn current_grants(&self) -> Option<ProtectedGrants<'static>> {
		self.record(Observation::Grants);
		self.grants
	}
}

#[test]
fn holds_the_lease_only_for_successful_admission() {
	let fixture = Fixture::default();
	let admission = admit(fixture.lease(), OWNER, selection()).expect("exact held admission");
	assert!(fixture.held.get(), "success retains the exclusive lease");
	assert_eq!(
		fixture.calls.borrow().as_slice(),
		[
			Observation::Approval,
			Observation::Replay,
			Observation::DurableHead,
			Observation::Preparation,
			Observation::Grants,
		]
	);
	drop(admission);
	assert!(!fixture.held.get());
}

#[test]
fn requires_exact_owner_approval_and_disclosure() {
	let cases: [(Invalidate, Error); 5] = [
		(|lease| lease.approval = None, Error::Approval),
		(
			|lease| lease.approval.as_mut().unwrap().owner = [31; 32],
			Error::Approval,
		),
		(
			|lease| lease.approval.as_mut().unwrap().selection.context.plan = [31; 32],
			Error::Approval,
		),
		(
			|lease| lease.approval.as_mut().unwrap().selection.incumbent = ObjectId([31; 32]),
			Error::Approval,
		),
		(
			|lease| lease.approval.as_mut().unwrap().disclosure = VisibilityDisclosure::Incomplete,
			Error::Disclosure,
		),
	];
	for (invalidate, expected) in cases {
		let fixture = Fixture::default();
		let mut lease = fixture.lease();
		invalidate(&mut lease);
		assert_eq!(admit(lease, OWNER, selection()).err(), Some(expected));
		assert_eq!(fixture.calls.borrow().as_slice(), [Observation::Approval]);
		assert!(!fixture.held.get());
	}

	let fixture = Fixture::default();
	let mut lease = fixture.lease();
	let empty_owner = [0; 32];
	lease.approval.as_mut().unwrap().owner = empty_owner;
	assert_eq!(
		admit(lease, empty_owner, selection()).err(),
		Some(Error::Approval)
	);
}

#[test]
fn rejects_unavailable_or_inconsistent_pre_intent_replay() {
	let cases: [fn(&mut FixtureLease<'_>); 8] = [
		|lease| lease.replay = None,
		|lease| lease.head = None,
		|lease| lease.replay.as_mut().unwrap().disposition = HistoryDisposition::PriorIntent,
		|lease| lease.replay.as_mut().unwrap().disposition = HistoryDisposition::Indeterminate,
		|lease| lease.replay.as_mut().unwrap().boundary.context.lease = [31; 32],
		|lease| lease.head.as_mut().unwrap().context.lease = [31; 32],
		|lease| lease.head.as_mut().unwrap().head.sequence += 1,
		|lease| lease.head.as_mut().unwrap().head.digest = [31; 32],
	];
	for invalidate in cases {
		let fixture = Fixture::default();
		let mut lease = fixture.lease();
		invalidate(&mut lease);
		assert_eq!(
			admit(lease, OWNER, selection()).err(),
			Some(Error::ReconciliationRequired)
		);
		assert!(!fixture.calls.borrow().contains(&Observation::Preparation));
		assert!(!fixture.calls.borrow().contains(&Observation::Grants));
		assert!(!fixture.held.get());
	}

	let fixture = Fixture::default();
	let mut lease = fixture.lease();
	let mut other_lease = lease.head.unwrap();
	other_lease.context.lease = [31; 32];
	lease.head = Some(other_lease);
	lease.replay.as_mut().unwrap().boundary = other_lease;
	assert_eq!(
		admit(lease, OWNER, selection()).err(),
		Some(Error::ReconciliationRequired)
	);
}

#[test]
fn requires_both_current_grants_in_the_held_context() {
	let cases: [fn(&mut FixtureLease<'_>); 6] = [
		|lease| lease.grants = None,
		|lease| lease.grants.as_mut().unwrap().capture.context.lease = [31; 32],
		|lease| lease.grants.as_mut().unwrap().publication.context.layout = [31; 32],
		|lease| lease.grants.as_mut().unwrap().capture.grant.revision = NonZeroU64::new(2).unwrap(),
		|lease| lease.grants.as_mut().unwrap().publication.grant = selection().capture,
		|lease| {
			let grants = lease.grants.as_mut().unwrap();
			let deadline = grants.capture.grant.expires_before.get();
			grants.capture.now = deadline - 1;
			grants.publication.now = deadline - 2;
		},
	];
	for invalidate in cases {
		let fixture = Fixture::default();
		let mut lease = fixture.lease();
		invalidate(&mut lease);
		assert_eq!(
			admit(lease, OWNER, selection()).err(),
			Some(Error::Authority)
		);
		assert!(!fixture.held.get());
	}
}

#[test]
fn either_grant_expiring_at_the_shared_sample_refuses() {
	const NOW: u64 = 50;
	const LATER: u64 = 60;
	for (capture, publication) in [(NOW, LATER), (LATER, NOW)] {
		let mut selected = selection();
		selected.capture.expires_before = NonZeroU64::new(capture).unwrap();
		selected.publication.expires_before = NonZeroU64::new(publication).unwrap();
		let fixture = Fixture::default();
		let mut lease = fixture.lease();
		lease.approval.as_mut().unwrap().selection = selected;
		let grants = lease.grants.as_mut().unwrap();
		grants.capture.grant = selected.capture;
		grants.publication.grant = selected.publication;
		grants.capture.now = NOW;
		grants.publication.now = NOW;
		assert_eq!(admit(lease, OWNER, selected).err(), Some(Error::Authority));
	}
}

#[test]
fn uses_the_model_to_check_readiness_and_head_bounds() {
	let cases: [(Invalidate, Error); 4] = [
		(
			|lease| lease.preparation = None,
			Error::PreparationUnavailable,
		),
		(
			|lease| lease.preparation.as_mut().unwrap().stage.sealed = false,
			Error::Model(Refusal::Stage),
		),
		(
			|lease| lease.preparation.as_mut().unwrap().incumbent.kind = EntryKind::Opaque,
			Error::Model(Refusal::Incumbent),
		),
		(
			|lease| {
				lease.head.as_mut().unwrap().head.sequence = u64::MAX;
				lease.replay.as_mut().unwrap().boundary = lease.head.unwrap();
			},
			Error::ReconciliationRequired,
		),
	];
	for (invalidate, expected) in cases {
		let fixture = Fixture::default();
		let mut lease = fixture.lease();
		invalidate(&mut lease);
		assert_eq!(admit(lease, OWNER, selection()).err(), Some(expected));
		assert!(!fixture.calls.borrow().contains(&Observation::Grants));
		assert!(!fixture.held.get());
	}
}

fn selection() -> Selection<'static> {
	let job =
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap();
	Selection {
		context: Context {
			attempt: CopyBinding::new(
				job,
				EntryId::new(5),
				RunEpoch::new(2),
				StageId::from_bytes([1; 16]),
			),
			plan: [3; 32],
			qualification: [4; 32],
			layout: [5; 32],
			lease: [6; 32],
			source_root: Directory {
				id: ObjectId([11; 32]),
				filesystem: FilesystemId([1; 32]),
			},
			target: slot(12, b"public"),
			stage: slot(13, b"stage"),
			recovery: slot(14, b"recovery"),
		},
		source: ObjectId([15; 32]),
		replacement: ObjectId([16; 32]),
		incumbent: ObjectId([17; 32]),
		replacement_evidence: RegularFileEvidence {
			byte_len: 8,
			content_digest: [18; 32],
			required_metadata_digest: [19; 32],
		},
		max_replacement_bytes: 8,
		capture: grant(20),
		publication: grant(21),
		image: ImagePolicy::RetainObject,
	}
}

fn slot(id: u8, name: &'static [u8]) -> Slot<'static> {
	Slot {
		parent: Directory {
			id: ObjectId([id; 32]),
			filesystem: FilesystemId([2; 32]),
		},
		name: UnixComponent::new(name).unwrap(),
	}
}

fn grant(id: u8) -> Grant {
	Grant {
		id: [id; 32],
		revision: NonZeroU64::MIN,
		expires_before: NonZeroU64::new(50).unwrap(),
	}
}
