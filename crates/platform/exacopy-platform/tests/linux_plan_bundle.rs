//! Native Linux checks for held Plan bundle effects and preserved records.

#![cfg(target_os = "linux")]

mod common;

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::plan_bundle::{PageCreation, PlanBundleSink};
use exacopy_platform::linux::{
	LinuxPlanBundle, PlanBundleError, PlanBundleRecord, PlanInputDirectory,
};
use rustix::io::Errno;

use common::Scratch;

const OUTPUT_NAME: &str = "plan.json";
const PAGE_NAME: &str = "candidate.exc";
const PAGE: &[u8] = b"opaque fixture page bytes";
const OUTPUT: &[u8] = br#"{"fixture":"opaque envelope"}"#;
const WRONG_PAGE: &[u8] = b"forged fixture page bytes";
const SOURCE: &[u8] = b"protected source bytes";
const PERMISSION_BITS: u32 = 0o7777;
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

struct BundleFixture {
	scratch: Scratch,
	output: PathBuf,
	inputs: [PlanInputDirectory; 3],
}

impl BundleFixture {
	fn new() -> Self {
		let scratch = Scratch::new();
		let metadata = scratch
			.open()
			.metadata()
			.expect("inspect the scratch fixture root");
		assert_eq!(metadata.mode() & PERMISSION_BITS, PRIVATE_DIR_MODE);
		let output = scratch.path("bundle");
		create_private_directory(&output);
		let inputs = ["source", "destination", "profile"].map(|name| {
			let path = scratch.path(name);
			create_private_directory(&path);
			PlanInputDirectory::open(path.as_os_str()).expect("hold protected input scope")
		});
		fs::write(scratch.path("source/input"), SOURCE).expect("write synthetic source");
		Self {
			scratch,
			output,
			inputs,
		}
	}

	fn open_at<'a>(
		&'a self,
		output: &'a Path,
		name: UnixComponent<'a>,
	) -> Result<LinuxPlanBundle<'a>, PlanBundleError> {
		let inputs = [&self.inputs[0], &self.inputs[1], &self.inputs[2]];
		LinuxPlanBundle::open(output.as_os_str(), name, inputs)
	}

	fn open(&self) -> LinuxPlanBundle<'_> {
		self.open_at(&self.output, component(OUTPUT_NAME))
			.expect("hold private output disjoint from the three protected parents")
	}

	fn assert_inputs_preserved(&self) {
		assert_eq!(
			fs::read(self.scratch.path("source/input")).expect("read protected source"),
			SOURCE
		);
		for name in ["destination", "profile"] {
			assert!(
				fs::read_dir(self.scratch.path(name))
					.expect("observe protected input directory")
					.next()
					.is_none(),
				"unexpected entry in protected {name} directory"
			);
		}
	}
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("fixture name is a valid Unix component")
}

fn create_private_directory(path: &Path) {
	DirBuilder::new()
		.mode(PRIVATE_DIR_MODE)
		.create(path)
		.expect("create fresh private fixture directory");
}

fn identity(path: &Path) -> (u64, u64) {
	let metadata = fs::symlink_metadata(path).expect("read fixture name identity");
	(metadata.dev(), metadata.ino())
}

fn require_created(result: PageCreation<PlanBundleRecord>) -> PlanBundleRecord {
	let PageCreation::Created(record) = result else {
		panic!("fresh page name unexpectedly had an incumbent");
	};
	record
}

#[test]
fn held_bundle_creates_and_reuses_the_page_and_preserves_the_envelope() {
	let fixture = BundleFixture::new();
	let bundle = fixture.open();
	let page_name = component(PAGE_NAME);
	let page_path = fixture.output.join("pages").join(PAGE_NAME);
	let output_path = fixture.output.join(OUTPUT_NAME);

	bundle
		.ensure_output_absent()
		.expect("envelope begins absent");
	let pages = bundle.open_pages().expect("create and hold private pages");
	let created = require_created(
		bundle
			.create_page(&pages, page_name, PAGE)
			.expect("create and sync a page"),
	);
	bundle
		.check_page(&pages, page_name, &created)
		.expect("recheck new page");
	bundle
		.check_pages(&pages)
		.expect("recheck the pages directory");
	bundle.sync_pages(&pages).expect("sync the pages directory");
	bundle.sync_bundle().expect("sync the parent of pages");

	let page_id = identity(&page_path);
	let reopened = bundle.open_pages().expect("hold preexisting private pages");
	assert!(matches!(
		bundle.create_page(&reopened, page_name, b"attempted overwrite"),
		Ok(PageCreation::Existing)
	));
	let mut read_back = [0; PAGE.len()];
	let reused = bundle
		.verify_existing_page(&reopened, page_name, PAGE, &mut read_back)
		.expect("admit byte-identical incumbent page");
	assert_eq!(read_back.as_slice(), PAGE);
	bundle
		.check_page(&reopened, page_name, &reused)
		.expect("recheck reused page");
	assert!(matches!(
		bundle.verify_existing_page(&reopened, page_name, WRONG_PAGE, &mut read_back),
		Err(PlanBundleError::Conflict)
	));
	assert_eq!(
		read_back.as_slice(),
		PAGE,
		"mismatch must come from measured bytes"
	);
	assert_eq!(identity(&page_path), page_id);
	assert_eq!(
		fs::read(&page_path).expect("read preserved page bytes"),
		PAGE
	);
	assert_absent(&output_path);

	let envelope = bundle
		.create_output(OUTPUT)
		.expect("exclusively create and sync envelope");
	bundle.sync_bundle().expect("sync envelope name");
	bundle
		.check_scope()
		.expect("protected scopes remain disjoint");
	bundle
		.check_output(&envelope)
		.expect("recheck held envelope");
	let envelope_id = identity(&output_path);
	assert!(matches!(
		bundle.ensure_output_absent(),
		Err(PlanBundleError::Conflict)
	));
	assert!(matches!(
		bundle.create_output(b"attempted overwrite"),
		Err(PlanBundleError::AlreadyExists(error))
			if error.raw_os_error() == Some(Errno::EXIST.raw_os_error())
	));
	assert_eq!(identity(&output_path), envelope_id);
	assert_eq!(
		fs::read(&output_path).expect("read retained envelope bytes"),
		OUTPUT
	);
	for path in [&page_path, &output_path] {
		let metadata = fs::symlink_metadata(path).expect("observe retained record metadata");
		assert!(metadata.is_file(), "record should be a regular file");
		assert_eq!(
			metadata.mode() & PERMISSION_BITS,
			PRIVATE_FILE_MODE,
			"incorrect mode for {path:?}"
		);
		assert_eq!(metadata.nlink(), 1, "unexpected alias for {path:?}");
	}
	fixture.assert_inputs_preserved();
}

#[test]
fn independently_opened_bundle_rejects_foreign_pages_and_records() {
	let fixture = BundleFixture::new();
	let first = fixture.open();
	let second = fixture.open();
	let first_pages = first.open_pages().expect("hold pages for the first bundle");
	let second_pages = second
		.open_pages()
		.expect("hold pages for the second bundle");
	let existing_name = component(PAGE_NAME);
	let absent_name = component("absent.exc");
	let page = require_created(
		first
			.create_page(&first_pages, existing_name, PAGE)
			.expect("create page under its owning capability"),
	);
	let output = first
		.create_output(OUTPUT)
		.expect("create envelope under its owner");
	let second_page = second
		.verify_existing_page(&second_pages, existing_name, PAGE, &mut [0; PAGE.len()])
		.expect("admit the same page under the second binding");
	let mut read_back = [0; PAGE.len()];

	assert!(matches!(
		second.create_page(&first_pages, absent_name, PAGE),
		Err(PlanBundleError::Scope(None))
	));
	assert!(matches!(
		second.verify_existing_page(&first_pages, existing_name, PAGE, &mut read_back),
		Err(PlanBundleError::Scope(None))
	));
	assert_eq!(
		read_back,
		[0; PAGE.len()],
		"wrong binding must leave scratch unchanged"
	);
	assert!(matches!(
		second.check_pages(&first_pages),
		Err(PlanBundleError::Scope(None))
	));
	assert!(matches!(
		second.sync_pages(&first_pages),
		Err(PlanBundleError::Scope(None))
	));
	assert!(matches!(
		second.check_page(&first_pages, existing_name, &second_page),
		Err(PlanBundleError::Scope(None))
	));
	assert!(matches!(
		second.check_page(&second_pages, existing_name, &page),
		Err(PlanBundleError::Scope(None))
	));
	assert!(matches!(
		second.check_output(&output),
		Err(PlanBundleError::Scope(None))
	));
	assert_absent(&fixture.output.join("pages/absent.exc"));

	first
		.check_page(&first_pages, existing_name, &page)
		.expect("own page remains valid");
	first
		.check_output(&output)
		.expect("own envelope remains valid");
	assert_eq!(
		fs::read(fixture.output.join("pages").join(PAGE_NAME)).expect("read incumbent page"),
		PAGE
	);
	assert_eq!(
		fs::read(fixture.output.join(OUTPUT_NAME)).expect("read incumbent envelope"),
		OUTPUT
	);
}

#[test]
fn bundle_refuses_reserved_name_parent_step_and_unsafe_output_directories() {
	let fixture = BundleFixture::new();
	let alias = fixture.scratch.path("fixture-output-alias");
	symlink(&fixture.output, &alias).expect("create fixture output alias");
	let public = fixture.scratch.path("nonprivate");
	create_private_directory(&public);
	fs::set_permissions(&public, fs::Permissions::from_mode(0o755))
		.expect("set nonprivate fixture mode");
	let parent_step = fixture.output.join("..").join("bundle");

	assert!(matches!(
		fixture.open_at(&fixture.output, component("pages")),
		Err(PlanBundleError::InvalidOutput)
	));
	assert!(matches!(
		fixture.open_at(&parent_step, component(OUTPUT_NAME)),
		Err(PlanBundleError::InvalidOutput)
	));
	let Err(alias_error) = fixture.open_at(&alias, component(OUTPUT_NAME)) else {
		panic!("bundle open must refuse a symlink");
	};
	fixture
		.scratch
		.assert_debug_redacts(&alias_error, &["fixture-output-alias"]);
	assert!(matches!(
		alias_error,
		PlanBundleError::Unsafe(Some(error))
			if error.raw_os_error() == Some(Errno::LOOP.raw_os_error())
				|| error.raw_os_error() == Some(Errno::NOTDIR.raw_os_error())
	));
	assert!(matches!(
		fixture.open_at(&public, component(OUTPUT_NAME)),
		Err(PlanBundleError::Unsafe(None))
	));
	assert_eq!(
		fs::read_link(&alias).expect("observe unchanged output alias"),
		fixture.output
	);
	assert!(
		fs::read_dir(&fixture.output)
			.expect("inspect original output")
			.next()
			.is_none()
	);
	assert!(
		fs::read_dir(&public)
			.expect("inspect refused output")
			.next()
			.is_none()
	);
	fixture.assert_inputs_preserved();
}

#[test]
fn bundle_refuses_rebinding_without_mutation() {
	let fixture = BundleFixture::new();
	let bundle = fixture.open();
	let saved = fixture.scratch.path("saved-bundle");
	fs::rename(&fixture.output, &saved).expect("move held bundle away from selected name");
	create_private_directory(&fixture.output);
	assert!(matches!(
		bundle.check_scope(),
		Err(PlanBundleError::Scope(None))
	));
	assert_ne!(identity(&saved), identity(&fixture.output));
	for path in [saved, fixture.output.clone()] {
		assert!(
			fs::read_dir(path)
				.expect("inspect each bundle after refusal")
				.next()
				.is_none()
		);
	}
	fixture.assert_inputs_preserved();
}

#[test]
fn pages_directory_recheck_refuses_replacement_and_mode_changes() {
	let fixture = BundleFixture::new();
	let bundle = fixture.open();
	let pages = bundle.open_pages().expect("create and hold pages");
	let page_name = component(PAGE_NAME);
	let _page = require_created(
		bundle
			.create_page(&pages, page_name, PAGE)
			.expect("create page before namespace change"),
	);
	let path = fixture.output.join("pages");
	let saved = fixture.output.join("saved-pages");

	fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
		.expect("change held pages protections");
	assert!(matches!(
		bundle.check_pages(&pages),
		Err(PlanBundleError::Unsafe(None))
	));
	assert!(matches!(
		bundle.open_pages(),
		Err(PlanBundleError::Unsafe(None))
	));
	fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
		.expect("restore fixture protections");
	bundle
		.check_pages(&pages)
		.expect("recheck restored directory protections");

	fs::rename(&path, &saved).expect("move held pages away from selected name");
	assert!(matches!(
		bundle.check_pages(&pages),
		Err(PlanBundleError::Io(error)) if error.raw_os_error() == Some(Errno::NOENT.raw_os_error())
	));
	create_private_directory(&path);
	assert!(matches!(
		bundle.check_pages(&pages),
		Err(PlanBundleError::Unsafe(None))
	));
	assert_ne!(identity(&path), identity(&saved));
	assert!(
		fs::read_dir(&path)
			.expect("inspect replacement pages")
			.next()
			.is_none()
	);
	assert_eq!(
		fs::read(saved.join(PAGE_NAME)).expect("read retained page"),
		PAGE
	);
	assert_absent(&fixture.output.join(OUTPUT_NAME));
}

#[path = "linux_plan_bundle/namespace.rs"]
mod namespace;

fn assert_absent(path: &Path) {
	assert_eq!(
		fs::symlink_metadata(path)
			.expect_err("fixture name must remain absent")
			.kind(),
		std::io::ErrorKind::NotFound,
		"unexpected namespace entry at {path:?}",
	);
}
