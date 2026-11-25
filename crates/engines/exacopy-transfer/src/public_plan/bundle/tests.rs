use std::cell::RefCell;

use exacopy_endpoint::UnixComponent;
use exacopy_plan::{PlanBody, PlanEntriesPage, RenderedPlanEnvelope};

use super::super::tests::{entry, fields};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
	Scope,
	Absent,
	Pages,
	CreatePage,
	AdoptPage,
	CheckPages,
	SyncPages,
	SyncBundle,
	CheckPage,
	CreateEnvelope,
	CheckEnvelope,
}

struct Recording {
	steps: RefCell<Vec<Step>>,
	page_exists: bool,
	fail_at: Option<usize>,
}

impl Recording {
	fn call(&self, event: Step) -> Result<(), Step> {
		let mut steps = self.steps.borrow_mut();
		steps.push(event);
		if self.fail_at == Some(steps.len()) {
			Err(event)
		} else {
			Ok(())
		}
	}
}

impl PlanBundleSink for Recording {
	type Error = Step;
	type Pages = ();
	type Record = ();
	fn check_scope(&self) -> Result<(), Step> {
		self.call(Step::Scope)
	}
	fn ensure_output_absent(&self) -> Result<(), Step> {
		self.call(Step::Absent)
	}
	fn open_pages(&self) -> Result<(), Step> {
		self.call(Step::Pages)
	}
	fn create_page(
		&self,
		_: &(),
		_: UnixComponent<'_>,
		_: &[u8],
	) -> Result<PageCreation<()>, Step> {
		self.call(Step::CreatePage)?;
		if self.page_exists {
			Ok(PageCreation::Existing)
		} else {
			Ok(PageCreation::Created(()))
		}
	}
	fn verify_existing_page(
		&self,
		_: &(),
		_: UnixComponent<'_>,
		expected: &[u8],
		scratch: &mut [u8],
	) -> Result<(), Step> {
		assert_eq!(expected.len(), scratch.len());
		self.call(Step::AdoptPage)
	}
	fn check_pages(&self, _: &()) -> Result<(), Step> {
		self.call(Step::CheckPages)
	}
	fn sync_pages(&self, _: &()) -> Result<(), Step> {
		self.call(Step::SyncPages)
	}
	fn sync_bundle(&self) -> Result<(), Step> {
		self.call(Step::SyncBundle)
	}
	fn check_page(&self, _: &(), _: UnixComponent<'_>, _: &()) -> Result<(), Step> {
		self.call(Step::CheckPage)
	}
	fn create_output(&self, envelope: &[u8]) -> Result<(), Step> {
		assert_eq!(envelope.last(), Some(&b'\n'));
		self.call(Step::CreateEnvelope)
	}
	fn check_output(&self, _: &()) -> Result<(), Step> {
		self.call(Step::CheckEnvelope)
	}
}

const CREATED: [Step; 14] = [
	Step::Scope,
	Step::Absent,
	Step::Pages,
	Step::CreatePage,
	Step::CheckPages,
	Step::SyncPages,
	Step::SyncBundle,
	Step::Scope,
	Step::CheckPages,
	Step::CheckPage,
	Step::CreateEnvelope,
	Step::SyncBundle,
	Step::Scope,
	Step::CheckPages,
];

fn with_artifacts(run: impl FnOnce(&PlanBundleArtifacts<'_>)) {
	let entry = entry();
	let page = PlanEntriesPage::new(entry).unwrap();
	let body = PlanBody::new(fields(entry, page.document_ref())).unwrap();
	let canonical = page.canonical_cbor();
	let bundle = RenderedPlanEnvelope::from_body(&body)
		.unwrap()
		.prepare(&canonical)
		.unwrap();
	run(&bundle);
}

#[test]
fn actual_commit_order_preserves_page_first_checks_and_reuse_rules() {
	with_artifacts(|artifacts| {
		for page_exists in [false, true] {
			let bundle = Recording {
				steps: RefCell::new(Vec::new()),
				page_exists,
				fail_at: None,
			};
			let mut expected = CREATED.to_vec();
			if page_exists {
				expected.insert(4, Step::AdoptPage);
			}
			expected.extend([Step::CheckPage, Step::CheckEnvelope]);
			write_plan_bundle(&bundle, artifacts).unwrap();
			assert_eq!(bundle.steps.into_inner(), expected);
		}
	});
}

#[test]
fn every_failed_effect_stops_the_order_without_later_effects() {
	with_artifacts(|artifacts| {
		let mut expected = CREATED.to_vec();
		expected.insert(4, Step::AdoptPage);
		expected.extend([Step::CheckPage, Step::CheckEnvelope]);
		for fail_at in 1..=expected.len() {
			let bundle = Recording {
				steps: RefCell::new(Vec::new()),
				page_exists: true,
				fail_at: Some(fail_at),
			};
			let result = write_plan_bundle(&bundle, artifacts);
			assert!(
				matches!(result, Err(BundleWriteError::Output(step)) if step == expected[fail_at - 1])
			);
			assert_eq!(bundle.steps.into_inner(), expected[..fail_at]);
		}
	});
}
