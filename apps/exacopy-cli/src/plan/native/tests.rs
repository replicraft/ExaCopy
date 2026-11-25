use std::fs::{self as std_fs, DirBuilder};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use exacopy_plan::PlanEntriesPage;

use exacopy_plan::PublicPlan;

use super::*;

struct Fixture(PathBuf);

impl Fixture {
	fn in_root(root: &Path) -> Self {
		let directory = root.join(format!("exacopy-plan-{}", fresh_reference().unwrap()));
		DirBuilder::new().mode(0o700).create(&directory).unwrap();
		Self(directory)
	}

	fn new() -> Self {
		Self::in_root(Path::new("/tmp"))
	}

	fn child(&self, name: &str) -> PathBuf {
		let child = self.0.join(name);
		DirBuilder::new().mode(0o700).create(&child).unwrap();
		child
	}

	fn command(&self) -> PlanCommand {
		let data = self.child("data");
		let bundle = self.child("bundle");
		let profile = self.0.join("profile");
		crate::profile::init(&profile).unwrap();
		let source = data.join("source");
		std_fs::write(&source, b"abc").unwrap();
		PlanCommand {
			source,
			destination: data.join("target"),
			profile,
			output: bundle.join("plan.json"),
		}
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = std_fs::remove_dir_all(&self.0);
	}
}

fn clock() -> SystemTime {
	UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

#[test]
fn exports_the_file_and_its_page_without_allocating_a_copy_job() {
	let fixture = Fixture::new();
	let command = fixture.command();
	let parent = command.output.parent().unwrap();
	let digest = export_at(&command, clock).unwrap();

	let exported = PublicPlan::from_json(&std_fs::read(&command.output).unwrap()).unwrap();
	assert_eq!(exported.digest(), digest);
	let body = exported.body().unwrap();
	assert!(body.fields().approval_required);
	assert_eq!(body.fields().created_at.seconds(), 1_700_000_000);
	assert_eq!(body.fields().plan_id.get_version_num(), 7);
	assert_eq!(body.fields().source_roots, [body.fields().destination_root]);
	let reference = body.fields().entry_pages[0];
	let pages = parent.join("pages");
	let page_file = pages.join(format!("{}.exc", hex(&reference.page_id())));
	let encoded = std_fs::read(&page_file).unwrap();
	let entry = PlanEntriesPage::from_canonical_cbor(reference, &encoded)
		.unwrap()
		.entry();
	assert_eq!(entry.source.basename, b"source");
	assert_eq!(entry.destination.basename, b"target");
	assert_eq!(entry.stream_digest, *blake3::hash(b"abc").as_bytes());

	assert_eq!(
		std_fs::metadata(&command.output).unwrap().mode() & 0o777,
		0o600
	);
	assert_eq!(std_fs::metadata(pages).unwrap().mode() & 0o777, 0o700);
	assert_eq!(std_fs::metadata(page_file).unwrap().mode() & 0o777, 0o600);
	assert_eq!(std_fs::read(&command.source).unwrap(), b"abc");
	assert!(!command.destination.exists());
	assert_eq!(
		std_fs::read_dir(command.source.parent().unwrap())
			.unwrap()
			.count(),
		1
	);
}

#[test]
fn scopes_exclude_inputs_and_reject_the_held_profile_seed() {
	let fixture = Fixture::new();
	let mut command = fixture.command();
	let safe_output = command.output.clone();
	command.output = command.source.parent().unwrap().join("plan.json");
	assert_eq!(export_at(&command, clock).unwrap_err().exit_code(), 6);
	assert!(!command.output.exists());

	command.output = command.profile.join("plan.json");
	assert_eq!(export_at(&command, clock).unwrap_err().exit_code(), 6);
	assert!(!command.output.exists());

	command.output = fixture.0.join("plan.json");
	assert_eq!(export_at(&command, clock).unwrap_err().exit_code(), 6);
	assert!(!command.output.exists());

	command.output = safe_output;
	let profile_alias = fixture.0.join("profile-alias");
	std::os::unix::fs::symlink(&command.profile, &profile_alias).unwrap();
	command.source = profile_alias.join("owner.seed");
	let original = std_fs::read(&command.source).unwrap();
	let failure = export_at(&command, clock).unwrap_err();
	assert_eq!(failure.exit_code(), 2);
	assert!(failure.to_string().contains("owner profile seed"));
	assert_eq!(std_fs::read(&command.source).unwrap(), original);
	assert_eq!(
		std_fs::read_dir(command.output.parent().unwrap())
			.unwrap()
			.count(),
		0
	);
}

#[test]
fn existing_plan_or_page_directory_link_preserves_incumbents() {
	use std::os::unix::fs::symlink;

	let fixture = Fixture::new();
	let command = fixture.command();
	std_fs::write(&command.output, b"incumbent plan").unwrap();
	assert_eq!(export_at(&command, clock).unwrap_err().exit_code(), 3);
	assert_eq!(std_fs::read(&command.output).unwrap(), b"incumbent plan");
	let bundle = command.output.parent().unwrap();
	assert!(!bundle.join("pages").exists());
	std_fs::remove_file(&command.output).unwrap();

	let outside = fixture.child("outside");
	std_fs::write(outside.join("guard"), b"retained").unwrap();
	symlink(&outside, bundle.join("pages")).unwrap();
	assert_eq!(export_at(&command, clock).unwrap_err().exit_code(), 6);
	assert_eq!(std_fs::read_link(bundle.join("pages")).unwrap(), outside);
	assert_eq!(std_fs::read(outside.join("guard")).unwrap(), b"retained");
	assert_eq!(std_fs::read_dir(outside).unwrap().count(), 1);
	assert!(!command.output.exists());
}

#[test]
fn group_writable_nonsticky_bundle_ancestor_refuses_before_export() {
	let fixture = Fixture::new();
	let mut command = fixture.command();
	let ancestor = fixture.child("group-writable");
	let bundle = ancestor.join("bundle");
	DirBuilder::new().mode(0o700).create(&bundle).unwrap();
	command.output = bundle.join("plan.json");
	std_fs::set_permissions(&ancestor, std_fs::Permissions::from_mode(0o775)).unwrap();
	let failure = export_at(&command, clock).unwrap_err();
	assert_eq!(failure.exit_code(), 6);
	assert!(!command.output.exists());
	assert!(!command.output.parent().unwrap().join("pages").exists());
}

#[test]
#[ignore = "requires disposable writable Linux whole-filesystem mount at /dev/shm"]
fn exports_across_an_observed_whole_tmpfs_mount() {
	let fixture = Fixture::new();
	let output_fixture = Fixture::in_root(Path::new("/dev/shm"));
	let mut command = fixture.command();
	command.output = output_fixture.0.join("plan.json");
	let input_device = std_fs::metadata(&command.source).unwrap().dev();
	let output_device = std_fs::metadata(&output_fixture.0).unwrap().dev();
	assert_ne!(
		input_device, output_device,
		"the fixture must cross filesystems"
	);
	export_at(&command, clock).unwrap();
	assert!(command.output.is_file());
	assert_eq!(std_fs::read(&command.source).unwrap(), b"abc");
	assert!(!command.destination.exists());
}
