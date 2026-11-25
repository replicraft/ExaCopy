use super::*;
use crate::scratch::Scratch;

#[test]
fn pages_cannot_be_written_with_another_bundle_capability() {
	let scratch = Scratch::new();
	let path = scratch.path(".");
	let input = PlanInputDirectory::open(path.as_os_str()).unwrap();
	let plan = UnixComponent::new(b"plan.json").unwrap();
	let second = LinuxPlanBundle {
		path: path.as_os_str(),
		output: plan,
		directory: scratch.open(),
		chain: Vec::new(),
		protected: [&input; 3],
		binding: Arc::new(()),
	};
	let foreign = PlanBundlePages {
		directory: scratch.open(),
		binding: Arc::new(()),
	};
	let name = UnixComponent::new(b"candidate.exc").unwrap();

	assert!(matches!(
		second.create_page(&foreign, name, b"cannot write"),
		Err(PlanBundleError::Scope(None))
	));
	assert!(!scratch.path("candidate.exc").exists());
}
