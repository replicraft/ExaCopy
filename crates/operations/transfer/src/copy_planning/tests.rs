use std::cell::{Cell, RefCell};
use std::io;

use exacopy_endpoint::ReadView;
use exacopy_endpoint::linux_staging::{ExtendedAttributes, SourceMetadata};

use super::*;

#[derive(Debug, Eq, PartialEq)]
enum Visit {
	Target,
	Open,
	Attributes,
	Recheck,
	Read(u64, usize),
}

type Trace = RefCell<Vec<Visit>>;

#[derive(Clone, Copy)]
struct Metadata(u32);

impl SourceMetadata for Metadata {
	type Timestamp = ();

	fn mode(self) -> u32 {
		self.0
	}

	fn accessed_at(self) -> Self::Timestamp {}
}

struct Source<'fixture> {
	trace: &'fixture Trace,
	bytes: &'fixture [u8],
	mode: u32,
	attributes: ExtendedAttributes,
	checks: Cell<u8>,
	stale_check: Option<u8>,
}

impl<'fixture> Source<'fixture> {
	fn regular(trace: &'fixture Trace, bytes: &'fixture [u8]) -> Self {
		Self {
			trace,
			bytes,
			mode: 0o644,
			attributes: ExtendedAttributes::NoneVisible,
			checks: Cell::new(0),
			stale_check: None,
		}
	}
}

impl ReadView for Source<'_> {
	type Error = io::Error;

	fn length(&self) -> u64 {
		u64::try_from(self.bytes.len()).unwrap()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.trace.borrow_mut().push(Visit::Recheck);
		let next = self.checks.get() + 1;
		self.checks.set(next);
		if self.stale_check == Some(next) {
			return Err(io::Error::other("source changed"));
		}
		Ok(())
	}

	fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
		self.trace
			.borrow_mut()
			.push(Visit::Read(offset, output.len()));
		let start = usize::try_from(offset).unwrap();
		output.copy_from_slice(&self.bytes[start..start + output.len()]);
		Ok(())
	}
}

impl StagingSource for Source<'_> {
	type Identity = JobFileIdentity;
	type Metadata = Metadata;

	fn identity(&self) -> JobFileIdentity {
		JobFileIdentity {
			device: 41,
			inode: 72,
		}
	}

	fn metadata(&self) -> Metadata {
		Metadata(self.mode)
	}

	fn extended_attributes(&self) -> Result<ExtendedAttributes, Self::Error> {
		self.trace.borrow_mut().push(Visit::Attributes);
		Ok(self.attributes)
	}

	fn recheck_metadata(&self) -> Result<(), Self::Error> {
		self.recheck_observation()
	}
}

struct Target<'fixture> {
	trace: &'fixture Trace,
	checks: Cell<u8>,
	occupied_check: Option<u8>,
}

impl CopyDestinationView for Target<'_> {
	type Error = io::Error;

	fn identity(&self) -> JobFileIdentity {
		JobFileIdentity {
			device: 41,
			inode: 8,
		}
	}

	fn observe_target(&self, name: UnixComponent<'_>) -> Result<TargetObservation, Self::Error> {
		assert_eq!(name.as_bytes(), b"new");
		self.trace.borrow_mut().push(Visit::Target);
		let next = self.checks.get() + 1;
		self.checks.set(next);
		Ok(if self.occupied_check == Some(next) {
			TargetObservation::Occupied
		} else {
			TargetObservation::Absent
		})
	}
}

fn request() -> CreateNewRequest<'static> {
	CreateNewRequest {
		plan_id: "00112233-4455-7677-8899-aabbccddeeff".parse().unwrap(),
		entry_id: Uuid::from_u128(1),
		source_view_id: Uuid::from_u128(2),
		measurement_id: Uuid::from_u128(3),
		source: PlanSelection {
			root_id: Uuid::from_u128(4),
			component: UnixComponent::new(b"source-\xff").unwrap(),
		},
		destination: PlanSelection {
			root_id: Uuid::from_u128(5),
			component: UnixComponent::new(b"new").unwrap(),
		},
		observed_at: UnixTimestamp::new(10, 5).unwrap(),
	}
}

fn plan(
	request: CreateNewRequest<'_>,
	source: Source<'_>,
	occupied_check: Option<u8>,
	scratch: &mut [u8],
) -> Result<PlannedCopy, PlanningError<io::Error, io::Error>> {
	let trace = source.trace;
	plan_create_new(
		request,
		|name| {
			assert_eq!(name.as_bytes(), b"source-\xff");
			trace.borrow_mut().push(Visit::Open);
			Ok(source)
		},
		|_| true,
		&Target {
			trace,
			checks: Cell::new(0),
			occupied_check,
		},
		scratch,
	)
}

#[test]
fn emits_linked_canonical_public_records_from_rechecked_bytes_and_names() {
	let trace = Trace::default();
	let request = request();
	let result = plan(request, Source::regular(&trace, b"abc"), None, &mut [0; 2]).unwrap();
	assert_eq!(
		*trace.borrow(),
		[
			Visit::Target,
			Visit::Open,
			Visit::Attributes,
			Visit::Recheck,
			Visit::Recheck,
			Visit::Read(0, 2),
			Visit::Read(2, 1),
			Visit::Recheck,
			Visit::Target,
			Visit::Attributes,
			Visit::Recheck,
		]
	);

	let body = PlanBody::from_canonical_cbor(result.digest(), result.canonical_body()).unwrap();
	assert_eq!(body.digest(), result.digest());
	let fields = body.fields();
	assert_eq!(fields.plan_id, request.plan_id);
	assert_eq!(fields.source_roots, [request.source.root_id]);
	assert_eq!(fields.destination_root, request.destination.root_id);
	assert_eq!(fields.created_at, request.observed_at);
	assert!(fields.complete && fields.approval_required);
	assert_eq!(fields.estimated_working_bytes, 3);
	assert_eq!(fields.resource_limits.buffer_budget_bytes(), 2);
	assert_eq!(fields.resource_limits.io_inflight_max(), 1);
	assert_eq!(fields.required_grants, ["read-content", "create-new"]);
	assert_eq!(fields.policy, COPY_POLICY);
	assert_eq!(fields.entry_pages, [result.page_ref()]);

	let page =
		PlanEntriesPage::from_canonical_cbor(result.page_ref(), result.canonical_page()).unwrap();
	let entry = page.entry();
	assert_eq!(entry.entry_id, request.entry_id);
	assert!(entry.source == request.source.path());
	assert!(entry.destination == request.destination.path());
	assert_eq!(entry.stream_length, 3);
	assert_eq!(entry.stream_digest, *blake3::hash(b"abc").as_bytes());
	let view = fields.source_views[0];
	assert_eq!(entry.source_view_id, view.view_id);
	assert_eq!(view.consistency, PlanViewConsistency::LiveObserved);
	assert_eq!(view.measurement_id, request.measurement_id);
	assert!(entry.source_identity == view.source_identity);
	let identity = entry.source_identity.unwrap();
	assert_eq!(identity.platform, PlanIdentityPlatform::Linux);
	assert_eq!(identity.volume_id, 41_u64.to_le_bytes());
	assert_eq!(identity.object_id, 72_u64.to_le_bytes());
	assert!(identity.generation.is_none());
	assert_eq!(
		entry.metadata_policy_digest,
		linux_baseline_metadata_policy_digest()
	);
}

#[test]
fn pinned_metadata_policy_identifier_matches_the_independent_c_digest() {
	let hex: String = linux_baseline_metadata_policy_digest()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect();
	assert_eq!(
		hex,
		"7c124934135712b89a782516402f3bc5d6f657908fb1dadabbb218a710d8d0c3"
	);
}

#[test]
fn known_incumbent_prevents_source_open_and_a_late_incumbent_prevents_emission() {
	let trace = Trace::default();
	for occupied_check in [1, 2] {
		trace.borrow_mut().clear();
		let result = plan(
			request(),
			Source::regular(&trace, b"a"),
			Some(occupied_check),
			&mut [0],
		);
		assert!(matches!(result, Err(PlanningError::Conflict)));
		let visits = trace.borrow();
		if occupied_check == 1 {
			assert_eq!(*visits, [Visit::Target]);
		} else {
			assert!(visits.contains(&Visit::Read(0, 1)));
			assert_eq!(visits.last(), Some(&Visit::Target));
		}
	}
}

#[test]
fn metadata_refusals_never_read_content() {
	let trace = Trace::default();
	for (mode, attributes) in [
		(0o4644, ExtendedAttributes::NoneVisible),
		(0o644, ExtendedAttributes::Present),
	] {
		trace.borrow_mut().clear();
		let mut source = Source::regular(&trace, b"a");
		source.mode = mode;
		source.attributes = attributes;
		assert!(matches!(
			plan(request(), source, None, &mut [0]),
			Err(PlanningError::SourcePolicy(_))
		));
		assert_eq!(
			*trace.borrow(),
			[
				Visit::Target,
				Visit::Open,
				Visit::Attributes,
				Visit::Recheck
			]
		);
	}
}

#[test]
fn stale_after_content_read_and_malformed_inputs_never_make_complete_plans() {
	let trace = Trace::default();
	let mut source = Source::regular(&trace, b"a");
	source.stale_check = Some(3);
	assert!(matches!(
		plan(request(), source, None, &mut [0]),
		Err(PlanningError::Measure(manifest::Error::FinalObservation(_)))
	));
	assert_eq!(trace.borrow().last(), Some(&Visit::Recheck));

	trace.borrow_mut().clear();
	assert!(matches!(
		plan(request(), Source::regular(&trace, b"a"), None, &mut []),
		Err(PlanningError::InvalidBuffer)
	));
	let mut req = request();
	req.destination = req.source;
	assert!(matches!(
		plan(req, Source::regular(&trace, b"a"), None, &mut [0]),
		Err(PlanningError::InvalidIdentity)
	));
	assert!(trace.borrow().is_empty());
}

#[test]
fn empty_file_builds_a_real_zero_length_entry_without_reading_payload() {
	let trace = Trace::default();
	let result = plan(request(), Source::regular(&trace, b""), None, &mut [0]).unwrap();
	let page =
		PlanEntriesPage::from_canonical_cbor(result.page_ref(), result.canonical_page()).unwrap();
	assert_eq!(page.entry().stream_length, 0);
	assert_eq!(page.entry().stream_digest, *blake3::hash(b"").as_bytes());
	assert!(
		!trace
			.borrow()
			.iter()
			.any(|visit| matches!(visit, Visit::Read(_, _)))
	);
}

#[test]
fn the_same_logical_parent_accepts_distinct_selected_names() {
	let trace = Trace::default();
	let mut request = request();
	request.destination.root_id = request.source.root_id;
	let result = plan(request, Source::regular(&trace, b"a"), None, &mut [0]).unwrap();
	let page =
		PlanEntriesPage::from_canonical_cbor(result.page_ref(), result.canonical_page()).unwrap();
	assert_eq!(
		page.entry().source.root_id,
		page.entry().destination.root_id
	);
}

#[test]
fn forbidden_held_identity_is_checked_before_source_metadata_or_content() {
	let trace = Trace::default();
	let result = plan_create_new(
		request(),
		|_| Ok(Source::regular(&trace, b"a")),
		|id| {
			assert_eq!(
				id,
				JobFileIdentity {
					device: 41,
					inode: 72
				}
			);
			false
		},
		&Target {
			trace: &trace,
			checks: Cell::new(0),
			occupied_check: None,
		},
		&mut [0],
	);
	assert!(matches!(result, Err(PlanningError::SourceForbidden)));
	assert_eq!(*trace.borrow(), [Visit::Target]);
}
