use std::fs::{self, FileTimes, OpenOptions};
use std::io::Write as _;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use exacopy_endpoint::ReadView as _;
use exacopy_model::{CopyEffect, CopyEvent, CopySession, EntryId, JobId, RunEpoch, StageId};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_ARCHIVE, FILE_CASE_SENSITIVE_INFO,
	FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
	FILE_READ_ATTRIBUTES, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES,
	FileCaseSensitiveInfo, SYNCHRONIZE,
};

use super::*;
use crate::windows::WindowsStageDirectory;
use crate::windows::native::query;

mod profile;
mod reopen;

const STAGE: &[u16] = &[115, 116, 97, 103, 101];
const DESTINATION: &[u16] = &[100, 101, 115, 116, 105, 110, 97, 116, 105, 111, 110];
const PUBLIC: &[u16] = &[112, 117, 98, 108, 105, 99];
const DATA: &[u8] = b"exact private stage bytes";
const INCUMBENT: &[u8] = b"independent incumbent content";

struct Fixture {
	scope: PathBuf,
	stage: PathBuf,
	destination: PathBuf,
}

impl Fixture {
	fn new() -> Self {
		let root = std::env::var_os("EXACOPY_WINDOWS_NTFS_ROOT")
			.expect("provision a disposable owner-controlled local NTFS fixture root");
		static NEXT: AtomicU32 = AtomicU32::new(0);
		for _ in 0..64 {
			let attempt = NEXT.fetch_add(1, Ordering::Relaxed);
			let scope =
				Path::new(&root).join(format!("publication-{}-{attempt}", std::process::id()));
			match fs::create_dir(&scope) {
				Ok(()) => {
					let stage = scope.join("staging");
					let destination = scope.join("destination");
					fs::create_dir(&stage).unwrap();
					return Self {
						scope,
						stage,
						destination,
					};
				}
				Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
				Err(error) => panic!("cannot exclusively create publication fixture: {error}"),
			}
		}
		panic!("could not reserve an unused publication fixture");
	}

	fn clean(self, files: impl IntoIterator<Item = (PathBuf, ObjectId)>) {
		for (path, expected) in files {
			assert_eq!(file_identity(&path), expected);
			fs::remove_file(path).unwrap();
		}
		// No recursive or Drop cleanup. Unexpected entries, including residue
		// after an assertion failure, remain for the owning wrapper to report.
		fs::remove_dir(self.stage).unwrap();
		fs::remove_dir(self.destination).unwrap();
		fs::remove_dir(self.scope).unwrap();
	}
}

fn open_parent(path: &Path, access: u32) -> File {
	OpenOptions::new()
		.access_mode(
			access
				| FILE_LIST_DIRECTORY
				| FILE_TRAVERSE
				| FILE_READ_ATTRIBUTES
				| READ_CONTROL
				| SYNCHRONIZE,
		)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
		.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
		.open(path)
		.unwrap()
}

fn file_identity(path: &Path) -> ObjectId {
	let file = OpenOptions::new()
		.read(true)
		.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
		.open(path)
		.unwrap();
	observe(file.as_handle(), Kind::RegularFile).unwrap()
}

fn create_bytes(path: &Path, bytes: &[u8]) -> ObjectId {
	let mut file = File::create_new(path).unwrap();
	file.write_all(bytes).unwrap();
	file.sync_all().unwrap();
	drop(file);
	file_identity(path)
}

fn assert_absent(path: &Path) {
	assert_eq!(
		fs::symlink_metadata(path).unwrap_err().kind(),
		io::ErrorKind::NotFound
	);
}

fn assert_bytes(path: &Path, expected: ObjectId, bytes: &[u8]) {
	assert_eq!(fs::read(path).unwrap(), bytes);
	assert_eq!(file_identity(path), expected);
}

fn model(epoch: u64) -> CopyBinding {
	let job =
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap();
	CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(epoch),
		StageId::from_bytes([0x51; 16]),
	)
}

fn permit(binding: CopyBinding) -> PublishNoClobber {
	let mut session = CopySession::new(binding);
	for event in [
		CopyEvent::StagePrepared,
		CopyEvent::WritersJoined,
		CopyEvent::DataFlushed,
		CopyEvent::ReadbackVerified,
		CopyEvent::MetadataReady,
		CopyEvent::StageSealed,
	] {
		session.apply(binding, event).unwrap();
	}
	let Some(CopyEffect::PublishNoClobber(permit)) = session
		.apply(binding, CopyEvent::PublishIntentRecorded)
		.unwrap()
	else {
		panic!("fixture did not obtain the abstract model effect");
	};
	permit
}

fn new_writer<'stage>(stage: &'stage WindowsStageDirectory<'stage>) -> WindowsStageWriter<'stage> {
	let mut writer = stage
		.create(WindowsComponent::new(STAGE).unwrap(), DATA.len() as u64)
		.unwrap();
	writer.write_at(0, DATA).unwrap();
	writer
}

fn close_for_target<'stage>(
	writer: WindowsStageWriter<'stage>,
	target: WindowsPublicationDestination<'stage>,
) -> WindowsClosedPublicationStage<'stage> {
	writer
		.finish_for_publication(model(2), target, WindowsComponent::new(PUBLIC).unwrap())
		.unwrap()
}

fn verify_and_seal(closed: WindowsClosedPublicationStage<'_>) -> WindowsSealedPublicationStage<'_> {
	{
		let read_back = closed.open_read_back().unwrap();
		let mut actual = [0; DATA.len()];
		read_back.read_exact_at(0, &mut actual).unwrap();
		assert_eq!(actual, DATA);
		read_back.recheck_observation().unwrap();
	}
	let required = closed.observe_metadata().unwrap();
	closed.seal(&required).unwrap()
}

#[test]
#[ignore = "requires the hosted fixed local NTFS publication fixture"]
fn absent_target_moves_original_closed_stage() {
	let fixture = Fixture::new();
	let source = fixture.scope.join("source");
	let source_identity = create_bytes(&source, DATA);
	let private = fixture.stage.join("stage");
	let public = fixture.destination.join("public");
	let stage_file = open_parent(&fixture.stage, FILE_ADD_FILE);
	let root_file = open_parent(&fixture.scope, FILE_ADD_SUBDIRECTORY);
	let root = WindowsPublicationRoot::from_authorized_handle(root_file.as_handle()).unwrap();
	let destination = root
		.create_destination(WindowsComponent::new(DESTINATION).unwrap())
		.unwrap();
	let stage = WindowsStageDirectory::from_authorized_handle(stage_file.as_handle()).unwrap();
	let closed = close_for_target(new_writer(&stage), destination);
	let exact = closed.binding();
	let initial = fs::metadata(&private).unwrap();
	assert_ne!(initial.file_attributes() & FILE_ATTRIBUTE_ARCHIVE, 0);
	assert_ne!(exact.stage, source_identity);
	let result = verify_and_seal(closed).attempt_no_clobber(permit(exact.model));
	assert!(
		matches!(result.outcome(), WindowsPublicationOutcome::ObservedRename),
		"{:?}",
		result.outcome()
	);
	assert_eq!(result.binding(), exact);
	assert!(result.rename_pin.is_some() && result.target_pin.is_some());
	assert_absent(&private);
	assert_bytes(&public, exact.stage, DATA);
	assert_bytes(&source, source_identity, DATA);
	let published = fs::metadata(&public).unwrap();
	assert_eq!(published.creation_time(), initial.creation_time());
	assert_eq!(published.file_attributes(), initial.file_attributes());
	let retained = &result.stage.closed.read_back.observation.file;
	assert_eq!(
		observe(retained.as_handle(), Kind::RegularFile).unwrap(),
		exact.stage
	);
	let mut bytes = [0; DATA.len() + 1];
	assert_eq!(retained.seek_read(&mut bytes, 0).unwrap(), DATA.len());
	assert_eq!(&bytes[..DATA.len()], DATA);
	assert_eq!(
		retained.seek_read(&mut bytes, DATA.len() as u64).unwrap(),
		0
	);
	let stage_identity = exact.stage;
	drop(result);
	drop(stage_file);
	drop(root_file);
	fixture.clean([(public, stage_identity), (source, source_identity)]);
}

#[allow(
	unsafe_code,
	reason = "native case-mode observation for the hosted collision oracle"
)]
fn require_insensitive(parent: &WindowsPublicationDestination<'_>) {
	let mut info = FILE_CASE_SENSITIVE_INFO::default();
	// SAFETY: The class matches the initialized, correctly sized output type.
	unsafe { query(parent.handle(), FileCaseSensitiveInfo, &mut info) }.unwrap();
	assert_eq!(
		info.Flags, 0,
		"case-alias oracle requires case-insensitive NTFS lookup"
	);
}

#[test]
#[ignore = "requires the hosted fixed local NTFS publication fixture"]
fn late_incumbent_and_case_alias_are_preserved() {
	for stored in ["public", "PUBLIC"] {
		let fixture = Fixture::new();
		let private = fixture.stage.join("stage");
		let public = fixture.destination.join(stored);
		let stage_file = open_parent(&fixture.stage, FILE_ADD_FILE);
		let root_file = open_parent(&fixture.scope, FILE_ADD_SUBDIRECTORY);
		let root = WindowsPublicationRoot::from_authorized_handle(root_file.as_handle()).unwrap();
		let destination = root
			.create_destination(WindowsComponent::new(DESTINATION).unwrap())
			.unwrap();
		require_insensitive(&destination);
		let stage = WindowsStageDirectory::from_authorized_handle(stage_file.as_handle()).unwrap();
		let sealed = verify_and_seal(close_for_target(new_writer(&stage), destination));
		let exact = sealed.binding();
		let permit = permit(exact.model);
		let incumbent = create_bytes(&public, INCUMBENT);
		assert_ne!(incumbent, exact.stage);

		let result = sealed.attempt_no_clobber(permit);
		assert!(
			matches!(result.outcome(), WindowsPublicationOutcome::Conflict(_)),
			"{:?}",
			result.outcome()
		);
		assert_bytes(&public, incumbent, INCUMBENT);
		assert_bytes(&private, exact.stage, DATA);
		let stage_identity = exact.stage;
		drop(result);
		drop(stage_file);
		drop(root_file);
		fixture.clean([(public, incumbent), (private, stage_identity)]);
	}
}

#[test]
#[ignore = "requires the hosted fixed local NTFS publication fixture"]
fn writer_and_changed_stage_refuse_before_rename() {
	for drift in [false, true] {
		let fixture = Fixture::new();
		let private = fixture.stage.join("stage");
		let public = fixture.destination.join("public");
		let stage_file = open_parent(&fixture.stage, FILE_ADD_FILE);
		let root_file = open_parent(&fixture.scope, FILE_ADD_SUBDIRECTORY);
		let root = WindowsPublicationRoot::from_authorized_handle(root_file.as_handle()).unwrap();
		let destination = root
			.create_destination(WindowsComponent::new(DESTINATION).unwrap())
			.unwrap();
		let stage = WindowsStageDirectory::from_authorized_handle(stage_file.as_handle()).unwrap();
		let sealed = verify_and_seal(close_for_target(new_writer(&stage), destination));
		let exact = sealed.binding();

		let blocker = if drift {
			let attributes = OpenOptions::new()
				.access_mode(FILE_WRITE_ATTRIBUTES)
				.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
				.open(&private)
				.unwrap();
			let changed = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
			assert_ne!(fs::metadata(&private).unwrap().modified().unwrap(), changed);
			attributes
				.set_times(FileTimes::new().set_modified(changed))
				.unwrap();
			assert_eq!(fs::metadata(&private).unwrap().modified().unwrap(), changed);
			attributes
		} else {
			// The independently verified reader already excludes a data writer.
			assert_eq!(
				OpenOptions::new()
					.write(true)
					.open(&private)
					.unwrap_err()
					.raw_os_error(),
				Some(32)
			);
			// This second reader may coexist but prevents the later DELETE open.
			OpenOptions::new()
				.read(true)
				.share_mode(FILE_SHARE_READ)
				.open(&private)
				.unwrap()
		};
		let result = sealed.attempt_no_clobber(permit(exact.model));
		assert!(
			matches!(
				result.outcome(),
				WindowsPublicationOutcome::Rejected(WindowsPublicationError::Stage(_))
			),
			"{:?}",
			result.outcome()
		);
		assert!(result.rename_pin.is_none());
		let stage_identity = exact.stage;
		drop(result);
		drop(blocker);
		assert_absent(&public);
		assert_bytes(&private, stage_identity, DATA);
		drop(stage_file);
		drop(root_file);
		fixture.clean([(private, stage_identity)]);
	}
}

#[test]
#[ignore = "requires the hosted fixed local NTFS publication fixture"]
fn bound_target_and_metadata_refusals_preserve_entries() {
	reopen::inspect_retained_stage_and_unrelated_destination();
	profile::refuse_existing_destination_after_removed_predecessor();
	profile::refuse_reparse_destination();
	profile::refuse_initial_archive_transition();
	for with_ads in [false, true] {
		let fixture = Fixture::new();
		let private = fixture.stage.join("stage");
		let ads = fixture.stage.join("stage:hidden");
		let public = fixture.destination.join("public");
		let stage_file = open_parent(&fixture.stage, FILE_ADD_FILE);
		let root_file = open_parent(&fixture.scope, FILE_ADD_SUBDIRECTORY);
		let root = WindowsPublicationRoot::from_authorized_handle(root_file.as_handle()).unwrap();
		let destination = root
			.create_destination(WindowsComponent::new(DESTINATION).unwrap())
			.unwrap();
		let incumbent = create_bytes(&public, INCUMBENT);
		let readonly = open_parent(&fixture.scope, 0);
		assert!(matches!(
			WindowsPublicationRoot::from_authorized_handle(readonly.as_handle()),
			Err(WindowsPublicationError::DestinationAccess)
		));
		drop(readonly);
		let stage = WindowsStageDirectory::from_authorized_handle(stage_file.as_handle()).unwrap();
		let writer = new_writer(&stage);
		let identity = writer.identity();

		if with_ads {
			drop(File::create_new(&ads).expect("attach named data to the original fixture stage"));
			assert_eq!(fs::metadata(&ads).unwrap().len(), 0);
			let closed = close_for_target(writer, destination);
			assert!(matches!(
				closed.observe_metadata(),
				Err(WindowsPublicationError::UnsupportedMetadata)
			));
			drop(closed);
			assert_eq!(fs::metadata(&ads).unwrap().len(), 0);
			fs::remove_file(ads).unwrap();
		} else {
			let sealed = verify_and_seal(close_for_target(writer, destination));
			let result = sealed.attempt_no_clobber(permit(model(3)));
			assert!(matches!(
				result.outcome(),
				WindowsPublicationOutcome::Rejected(WindowsPublicationError::BindingMismatch)
			));
			assert!(result.rename_pin.is_none());
		}
		assert_bytes(&private, identity, DATA);
		assert_bytes(&public, incumbent, INCUMBENT);
		drop(stage_file);
		drop(root_file);
		fixture.clean([(private, identity), (public, incumbent)]);
	}
}

#[test]
#[ignore = "requires the hosted fixed local NTFS publication fixture"]
fn native_success_with_observation_failure_requires_reconciliation() {
	let fixture = Fixture::new();
	let private = fixture.stage.join("stage");
	let public = fixture.destination.join("public");
	let stage_file = open_parent(&fixture.stage, FILE_ADD_FILE);
	let root_file = open_parent(&fixture.scope, FILE_ADD_SUBDIRECTORY);
	let root = WindowsPublicationRoot::from_authorized_handle(root_file.as_handle()).unwrap();
	let destination = root
		.create_destination(WindowsComponent::new(DESTINATION).unwrap())
		.unwrap();
	let stage = WindowsStageDirectory::from_authorized_handle(stage_file.as_handle()).unwrap();
	let sealed = verify_and_seal(close_for_target(new_writer(&stage), destination));
	let exact = sealed.binding();
	let result = sealed.attempt_with_observation(permit(exact.model), |attempt| {
		attempt.observe_result()?;
		Err(WindowsPublicationError::TargetChanged)
	});
	assert!(
		matches!(
			result.outcome(),
			WindowsPublicationOutcome::RenamedUnconfirmed(WindowsPublicationError::TargetChanged)
		),
		"{:?}",
		result.outcome()
	);
	assert!(result.rename_pin.is_some() && result.target_pin.is_some());
	assert_absent(&private);
	assert_bytes(&public, exact.stage, DATA);
	let root_identity = observe(root_file.as_handle(), Kind::Directory).unwrap();
	drop(result);
	drop(stage_file);
	drop(root_file);

	reopen::inspect_reopened_publication(&fixture, root_identity, exact);
	assert_absent(&private);
	assert_bytes(&public, exact.stage, DATA);
	fixture.clean([(public, exact.stage)]);
}
