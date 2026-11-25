//! Native descriptor and preservation checks for Linux public planning.

#![cfg(target_os = "linux")]

use std::cell::Cell;
use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, FileTimes, Metadata};
use std::io::ErrorKind;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use exacopy_cli::assembly::linux::plan_public_new_file;
use exacopy_codec::{
	PlanBody, PlanEntriesPage, PlanIdentityPlatform, PlanViewConsistency, UnixTimestamp,
};
use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_copy::{CopyDestinationView, TargetObservation};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_platform::linux::{DestinationRoot, ReadError, ReadRoot, StageError};
use exacopy_transfer::copy_planning::{CreateNewRequest, PlanSelection, PlanningError};
use exacopy_transfer::linux_staging::StageFailure;

const SOURCE: &[u8] = b"raw-\xff.source";
const TARGET: &[u8] = b"new-\xfe.target";
const SOURCE_CONTENT: &[u8] = b"abc";
const OLD_ATIME_SECONDS: u64 = 60;
const SCRATCH_MARKER: u8 = 0xe5;
const ROOT_ALIAS: &str = "d91b5000-1234-4312-b001-123456789abc";
const OTHER_ROOT_ALIAS: &str = "d91b5000-1234-4312-b001-123456789abd";
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		let temp = std::env::temp_dir();
		for _ in 0..128 {
			let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
			let path = temp.join(format!(
				"exacopy-public-plan-{}-{sequence}",
				std::process::id()
			));
			match DirBuilder::new().mode(0o700).create(&path) {
				Ok(()) => return Self(path),
				Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
				Err(error) => panic!("create private native plan fixture: {error}"),
			}
		}
		panic!("could not reserve a fresh native plan fixture")
	}

	fn named(&self, name: &[u8]) -> PathBuf {
		self.0.join(OsStr::from_bytes(name))
	}

	fn read_root(&self) -> ReadRoot {
		ReadRoot::from_directory(File::open(&self.0).unwrap()).unwrap()
	}

	fn destination_root(&self) -> DestinationRoot {
		DestinationRoot::from_directory(File::open(&self.0).unwrap()).unwrap()
	}

	fn names(&self) -> Vec<Vec<u8>> {
		let mut names: Vec<_> = fs::read_dir(&self.0)
			.unwrap()
			.map(|entry| entry.unwrap().file_name().into_vec())
			.collect();
		names.sort();
		names
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

fn selection<'name>(alias: &str, basename: &'name [u8]) -> PlanSelection<'name> {
	PlanSelection {
		root_id: alias.parse().unwrap(),
		component: UnixComponent::new(basename).unwrap(),
	}
}

fn request<'name>(
	from: &'name [u8],
	to: &'name [u8],
	same_parent: bool,
) -> CreateNewRequest<'name> {
	CreateNewRequest {
		plan_id: "019a0000-0000-7000-8000-000000000051".parse().unwrap(),
		entry_id: "f91b5000-1234-4312-b001-123456789abc".parse().unwrap(),
		source_view_id: "f91b5000-1234-4312-b001-123456789abd".parse().unwrap(),
		measurement_id: "f91b5000-1234-4312-b001-123456789abe".parse().unwrap(),
		source: selection(ROOT_ALIAS, from),
		destination: selection(
			if same_parent {
				ROOT_ALIAS
			} else {
				OTHER_ROOT_ALIAS
			},
			to,
		),
		observed_at: UnixTimestamp::new(1_700_000_000, 123_456_789).unwrap(),
	}
}

fn disk_identity(metadata: &Metadata) -> (u64, u64) {
	(metadata.dev(), metadata.ino())
}

fn assert_absent(path: &Path) {
	assert_eq!(
		fs::symlink_metadata(path).unwrap_err().kind(),
		ErrorKind::NotFound
	);
}

struct TargetObserver<'root, F> {
	destination: &'root DestinationRoot,
	checks: Cell<u8>,
	before_observation: F,
}

impl<F: Fn(u8)> CopyDestinationView for TargetObserver<'_, F> {
	type Error = StageError;

	fn identity(&self) -> JobFileIdentity {
		CopyDestinationView::identity(self.destination)
	}

	fn observe_target(&self, target: UnixComponent<'_>) -> Result<TargetObservation, StageError> {
		let check = self.checks.get() + 1;
		self.checks.set(check);
		(self.before_observation)(check);
		self.destination.observe_target(target)
	}
}

#[test]
fn same_parent_distinct_raw_names_emit_linked_records_without_creating_a_target() {
	let parent = Fixture::new();
	let source_path = parent.named(SOURCE);
	let target_path = parent.named(TARGET);
	fs::write(&source_path, SOURCE_CONTENT).unwrap();
	fs::write(parent.named(b"incumbent"), b"unrelated").unwrap();

	let source = parent.read_root();
	let destination = parent.destination_root();
	let starting_names = parent.names();
	let original = fs::metadata(&source_path).unwrap();
	let request = request(SOURCE, TARGET, true);
	let mut scratch = [SCRATCH_MARKER; 2];
	let plan = plan_public_new_file(
		&source,
		&destination,
		request,
		|held| {
			assert_eq!((held.device(), held.inode()), disk_identity(&original));
			true
		},
		&mut scratch,
	)
	.unwrap();

	let mut body_frame = b"ExaCopy/plan/v1\0".to_vec();
	body_frame.extend_from_slice(plan.canonical_body());
	let expected_body_digest = *blake3::hash(&body_frame).as_bytes();
	assert_eq!(plan.digest(), expected_body_digest);
	let admitted =
		PlanBody::from_canonical_cbor(expected_body_digest, plan.canonical_body()).unwrap();
	let body = admitted.fields();
	assert_eq!(body.plan_id, request.plan_id);
	assert_eq!(body.source_roots, [request.source.root_id]);
	assert_eq!(body.destination_root, request.source.root_id);
	assert!(body.complete && body.approval_required);
	assert_eq!(body.required_grants, ["read-content", "create-new"]);
	assert_eq!(body.entry_count, 1);
	assert_eq!(body.resource_limits.buffer_budget_bytes(), 2);
	assert_eq!(
		body.source_views[0].consistency,
		PlanViewConsistency::LiveObserved
	);
	assert_eq!(body.source_views[0].view_id, request.source_view_id);
	assert_eq!(body.source_views[0].measurement_id, request.measurement_id);

	let [reference] = body.entry_pages.as_slice() else {
		panic!("native producer must emit one declared page")
	};
	let mut page_frame = b"ExaCopy/document-page/v1\0\x01\x00".to_vec();
	page_frame.extend_from_slice(&(plan.canonical_page().len() as u64).to_le_bytes());
	page_frame.extend_from_slice(plan.canonical_page());
	assert_eq!(reference.page_id(), *blake3::hash(&page_frame).as_bytes());
	assert_eq!(*reference, plan.page_ref());
	let page = PlanEntriesPage::from_canonical_cbor(*reference, plan.canonical_page()).unwrap();
	let entry = page.entry();
	assert_eq!(entry.entry_id, request.entry_id);
	assert_eq!(entry.source.basename, SOURCE);
	assert_eq!(entry.destination.basename, TARGET);
	assert_eq!(entry.source.root_id, entry.destination.root_id);
	assert_eq!(entry.stream_length, 3);
	assert_eq!(
		entry.stream_digest,
		*blake3::hash(SOURCE_CONTENT).as_bytes()
	);
	assert_eq!(entry.source_view_id, body.source_views[0].view_id);
	let native = entry.source_identity.unwrap();
	assert_eq!(native.platform, PlanIdentityPlatform::Linux);
	assert_eq!(native.volume_id, original.dev().to_le_bytes());
	assert_eq!(native.object_id, original.ino().to_le_bytes());
	assert_eq!(native.generation, None);
	assert!(entry.source_identity == body.source_views[0].source_identity);

	assert_eq!(parent.names(), starting_names);
	assert_absent(&target_path);
	assert_eq!(
		disk_identity(&fs::metadata(&source_path).unwrap()),
		disk_identity(&original)
	);
	assert_eq!(fs::read(&source_path).unwrap(), SOURCE_CONTENT);
	assert_eq!(fs::read(parent.named(b"incumbent")).unwrap(), b"unrelated");
}

#[test]
fn same_alias_for_different_physical_roots_fails_before_target_or_source_admission() {
	let origin = Fixture::new();
	let target = Fixture::new();
	fs::write(target.named(TARGET), b"keep the incumbent").unwrap();
	let destination = target.destination_root();
	let observer = TargetObserver {
		destination: &destination,
		checks: Cell::new(0),
		before_observation: |_| panic!("a contradictory root must stop before target observation"),
	};
	let mut scratch = [SCRATCH_MARKER; 2];
	let result = plan_public_new_file(
		&origin.read_root(),
		&observer,
		request(SOURCE, TARGET, true),
		|_| panic!("a contradictory root must stop before source policy"),
		&mut scratch,
	);
	assert!(matches!(result, Err(PlanningError::InvalidIdentity)));
	assert_eq!(observer.checks.get(), 0);
	assert_eq!(scratch, [SCRATCH_MARKER; 2]);
	assert!(origin.names().is_empty());
	assert_eq!(target.names(), [TARGET.to_vec()]);
	assert_eq!(
		fs::read(target.named(TARGET)).unwrap(),
		b"keep the incumbent"
	);
}

#[test]
fn occupied_target_wins_over_missing_source_and_preserves_incumbent() {
	let origin = Fixture::new();
	let target = Fixture::new();
	let incumbent = target.named(TARGET);
	fs::write(&incumbent, b"existing destination bytes").unwrap();
	let identity = disk_identity(&fs::metadata(&incumbent).unwrap());

	let mut scratch = [SCRATCH_MARKER; 2];
	let result = plan_public_new_file(
		&origin.read_root(),
		&target.destination_root(),
		request(SOURCE, TARGET, false),
		|_| panic!("an occupied target must win before source policy"),
		&mut scratch,
	);
	assert!(matches!(result, Err(PlanningError::Conflict)));
	assert_eq!(scratch, [SCRATCH_MARKER; 2]);
	assert_absent(&origin.named(SOURCE));
	assert!(origin.names().is_empty());
	assert_eq!(target.names(), [TARGET.to_vec()]);
	assert_eq!(disk_identity(&fs::metadata(&incumbent).unwrap()), identity);
	assert_eq!(fs::read(&incumbent).unwrap(), b"existing destination bytes");
}

#[test]
fn symlink_targets_remain_occupied_without_source_payload_reads() {
	let origin = Fixture::new();
	let target = Fixture::new();
	let source_path = origin.named(SOURCE);
	let incumbent_payload = target.named(b"original-content");
	fs::write(&source_path, SOURCE_CONTENT).unwrap();
	fs::write(&incumbent_payload, b"incumbent payload").unwrap();
	for (link, relative) in [
		(b"real-link".as_slice(), "original-content"),
		(b"dangling-link", "missing"),
	] {
		symlink(relative, target.named(link)).unwrap();
	}
	let starting_names = target.names();
	for (link, relative) in [
		(b"real-link".as_slice(), "original-content"),
		(b"dangling-link", "missing"),
	] {
		let link_path = target.named(link);
		let identity = disk_identity(&fs::symlink_metadata(&link_path).unwrap());
		let mut scratch = [SCRATCH_MARKER; 2];
		let result = plan_public_new_file(
			&origin.read_root(),
			&target.destination_root(),
			request(SOURCE, link, false),
			|_| panic!("observing an occupied symlink must preempt the source"),
			&mut scratch,
		);
		assert!(matches!(result, Err(PlanningError::Conflict)));
		assert_eq!(scratch, [SCRATCH_MARKER; 2]);
		assert_eq!(fs::read_link(&link_path).unwrap(), Path::new(relative));
		assert_eq!(
			disk_identity(&fs::symlink_metadata(&link_path).unwrap()),
			identity
		);
	}
	assert_eq!(origin.names(), [SOURCE.to_vec()]);
	assert_eq!(target.names(), starting_names);
	assert_eq!(fs::read(&incumbent_payload).unwrap(), b"incumbent payload");
	assert_eq!(fs::read(source_path).unwrap(), SOURCE_CONTENT);
}

#[test]
fn same_bytes_under_a_rebound_source_name_cannot_complete_a_plan() {
	let origin = Fixture::new();
	let target = Fixture::new();
	let source_path = origin.named(SOURCE);
	let alternate = origin.named(b"replacement");
	let retained = origin.named(b"original-held");
	fs::write(&source_path, SOURCE_CONTENT).unwrap();
	fs::write(&alternate, SOURCE_CONTENT).unwrap();
	let original_identity = disk_identity(&fs::metadata(&source_path).unwrap());
	let new_identity = disk_identity(&fs::metadata(&alternate).unwrap());
	assert_ne!(new_identity, original_identity);

	let destination = target.destination_root();
	let observer = TargetObserver {
		destination: &destination,
		checks: Cell::new(0),
		before_observation: |check| {
			if check == 2 {
				fs::rename(&source_path, &retained).unwrap();
				fs::rename(&alternate, &source_path).unwrap();
			}
		},
	};
	let mut scratch = [SCRATCH_MARKER; 2];
	let result = plan_public_new_file(
		&origin.read_root(),
		&observer,
		request(SOURCE, TARGET, false),
		|held| {
			assert_eq!((held.device(), held.inode()), original_identity);
			true
		},
		&mut scratch,
	);
	assert!(matches!(
		result,
		Err(PlanningError::SourcePolicy(StageFailure::Source(
			ReadError::IdentityChanged
		)))
	));
	assert_eq!(observer.checks.get(), 2);
	assert_ne!(
		scratch, [SCRATCH_MARKER; 2],
		"the rebind occurred after measurement"
	);
	assert!(target.names().is_empty());
	assert_eq!(origin.names(), [b"original-held".to_vec(), SOURCE.to_vec()]);
	assert_eq!(
		disk_identity(&fs::metadata(&retained).unwrap()),
		original_identity
	);
	assert_eq!(
		disk_identity(&fs::metadata(&source_path).unwrap()),
		new_identity
	);
	assert_eq!(fs::read(&source_path).unwrap(), SOURCE_CONTENT);
	assert_eq!(fs::read(&retained).unwrap(), SOURCE_CONTENT);
}

fn old_access_time(path: &Path) -> SystemTime {
	let old = SystemTime::UNIX_EPOCH + Duration::from_secs(OLD_ATIME_SECONDS);
	File::open(path)
		.unwrap()
		.set_times(FileTimes::new().set_accessed(old))
		.unwrap();
	fs::metadata(path).unwrap().accessed().unwrap()
}

#[test]
fn opened_seed_alias_is_forbidden_before_reading_payload() {
	let origin = Fixture::new();
	let target = Fixture::new();
	let seed = origin.named(b"synthetic-profile-seed");
	let alias = origin.named(SOURCE);
	let calibration = origin.named(b"atime-positive-control");
	let secret = b"synthetic seed bytes must never reach scratch";
	fs::write(&seed, secret).unwrap();
	fs::hard_link(&seed, &alias).unwrap();
	fs::write(&calibration, b"atime control").unwrap();

	let control_start = old_access_time(&calibration);
	assert_eq!(fs::read(&calibration).unwrap(), b"atime control");
	let atime_advances = fs::metadata(&calibration).unwrap().accessed().unwrap() != control_start;
	eprintln!("native fixture atime positive control advanced: {atime_advances}");
	let starting_names = origin.names();
	let untouched_atime = old_access_time(&alias);
	let forbidden = disk_identity(&fs::metadata(&seed).unwrap());
	let gate_called = Cell::new(false);
	let mut scratch = [SCRATCH_MARKER; 16];
	let result = plan_public_new_file(
		&origin.read_root(),
		&target.destination_root(),
		request(SOURCE, TARGET, false),
		|held| {
			gate_called.set(true);
			(held.device(), held.inode()) != forbidden
		},
		&mut scratch,
	);
	assert!(matches!(result, Err(PlanningError::SourceForbidden)));
	assert!(gate_called.get());
	assert_eq!(scratch, [SCRATCH_MARKER; 16]);
	let after = fs::metadata(&alias).unwrap();
	if atime_advances {
		assert_eq!(after.accessed().unwrap(), untouched_atime);
	}
	assert_eq!(disk_identity(&after), forbidden);
	assert_eq!(disk_identity(&fs::metadata(&seed).unwrap()), forbidden);
	assert_eq!(origin.names(), starting_names);
	assert!(target.names().is_empty());
	assert_eq!(fs::read(&alias).unwrap(), secret);
	assert_eq!(fs::read(&seed).unwrap(), secret);
}
