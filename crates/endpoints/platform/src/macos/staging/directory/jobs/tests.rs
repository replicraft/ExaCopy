use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};

use exacopy_model::{EntryId, RunEpoch};
use rustix::io::Errno;

use super::super::super::StageBindingContext;

use super::super::super::tests::{Fixture, context, name, open_staging};
use super::{Creation, JobArtifact, JobError, JobName, JobStep, checked_component};

mod recovery;

const UUID: [u8; 16] = [
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x7c, 0xde, 0x80, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
];
const PRIVATE: &str = "private-stage";
const JOB_NAME: &str = ".exacopy-01234567-89ab-7cde-8012-3456789abcde";
const OWNER: &str = "owner.cbor";
const PLAN: &str = "plan.cbor";
const JOURNAL: &str = "journal";
const FIRST_SEGMENT: &str = "00000000000000000001.exajnl";
const RECEIPTS: &str = "receipts";
const RECEIPT: &str = "receipt.cbor";
const STAGE: &str = "stage";
const DATA: &str = "data";
const TARGET: &str = "planned-target";
const STAGED_BYTES: &[u8] = b"staged fixture";

fn job_name() -> JobName {
	JobName::from_uuid_bytes(UUID).expect("valid synthetic job UUIDv7")
}

fn job_context() -> StageBindingContext {
	StageBindingContext::new(job_name().job_id(), EntryId::new(1), RunEpoch::new(1))
}

fn job_path(fixture: &Fixture) -> PathBuf {
	fixture.path(PRIVATE).join(JOB_NAME)
}

fn private_dir(path: &Path) {
	fs::DirBuilder::new()
		.mode(0o700)
		.create(path)
		.expect("create a synthetic incumbent");
}

fn assert_record(path: &Path, bytes: &[u8]) -> fs::Metadata {
	let metadata = fs::symlink_metadata(path).expect("inspect the record");
	assert!(metadata.is_file());
	assert_eq!(metadata.mode() & 0o777, 0o600);
	assert_eq!(metadata.nlink(), 1);
	assert_eq!(fs::read(path).expect("read record bytes"), bytes);
	metadata
}

#[test]
fn canonical_private_job_names_require_uuidv7_and_rfc_variant() {
	assert_eq!(job_name().to_string(), JOB_NAME);
	let mut invalid_version = UUID;
	invalid_version[6] = 0x4c;
	assert!(JobName::from_uuid_bytes(invalid_version).is_err());
	let mut invalid_variant = UUID;
	invalid_variant[8] = 0xc0;
	assert!(JobName::from_uuid_bytes(invalid_variant).is_err());
}

#[test]
fn fixed_job_artifacts_are_private_and_stage_revalidates_under_the_job() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container
		.create_job_directory(job_name())
		.expect("exclusive job creation and directory barriers");
	let job_path = job_path(&fixture);
	assert_eq!(job.name(), job_name());
	assert!(!fixture.path(JOB_NAME).exists());
	let metadata = fs::symlink_metadata(&job_path).expect("observe private job directory");
	assert!(metadata.is_dir());
	assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
	assert_eq!(metadata.ino(), job.identity().inode().get());
	assert_eq!(metadata.uid(), job.owner_uid());
	assert_ne!(job.identity().physical_fsid(), [0; 2]);

	let owner_bytes = b"opaque signed owner fixture";
	let owner = job.write_owner_record(owner_bytes).expect("owner barriers");
	assert_eq!(
		assert_record(&job_path.join(OWNER), owner_bytes).ino(),
		owner.inode().get()
	);
	assert_eq!(owner.device(), job.identity().device());
	assert_eq!(owner.physical_fsid(), job.identity().physical_fsid());

	let plan_bytes = b"opaque plan fixture";
	let plan = job.write_plan_record(plan_bytes).expect("plan barriers");
	assert_ne!(plan.inode(), owner.inode());
	assert_eq!(
		assert_record(&job_path.join(PLAN), plan_bytes).ino(),
		plan.inode().get()
	);

	let journal = job
		.create_journal_directory()
		.expect("first journal namespace barriers");
	let mut segment = journal
		.create_first_segment()
		.expect("exclusive segment entry barrier");
	let segment_path = job_path.join(JOURNAL).join(FIRST_SEGMENT);
	assert_record(&segment_path, b"");
	segment
		.write_all(b"opaque framed journal fixture")
		.expect("journal writer owns file");
	drop(segment);
	assert_record(&segment_path, b"opaque framed journal fixture");

	let receipts = job
		.create_receipt_directory()
		.expect("receipt namespace barriers");
	receipts
		.write_receipt(b"opaque receipt fixture")
		.expect("receipt barriers");
	assert_record(
		&job_path.join(RECEIPTS).join(RECEIPT),
		b"opaque receipt fixture",
	);

	let stage = job
		.create_stage_directory()
		.expect("nested private staging capability");
	assert!(matches!(
		stage.create_job_directory(job_name()),
		Err(JobError::NestedJob)
	));
	assert!(matches!(
		stage.create_file(name(DATA.as_bytes()), name(TARGET.as_bytes()), context(), 0),
		Err(super::StageError::JobBindingMismatch)
	));
	assert!(!job_path.join(STAGE).join(DATA).exists());
	let length = u64::try_from(STAGED_BYTES.len()).expect("fixture extent fits");
	let mut writer = stage
		.create_file(
			name(DATA.as_bytes()),
			name(TARGET.as_bytes()),
			job_context(),
			length,
		)
		.expect("nested stage writer is bound to a public target");
	writer.write_next(STAGED_BYTES).expect("write nested stage");
	let closed = writer
		.flush_and_close()
		.expect("barrier and close nested writer");
	let reader = closed.open_read_back().expect("reopen nested stage");
	let mut observed = [0; STAGED_BYTES.len()];
	reader
		.read_exact_at(0, &mut observed)
		.expect("read staged bytes");
	assert_eq!(&observed, STAGED_BYTES);
	assert_record(&job_path.join(STAGE).join(DATA), STAGED_BYTES);
	assert!(!fixture.path(TARGET).exists());
}

#[test]
fn exclusive_job_creation_preserves_occupied_names_and_aliases() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let incumbent = fixture.path("user-content");
	fs::write(&incumbent, b"preserve these bytes").expect("write synthetic incumbent");
	let canonical = job_path(&fixture);
	symlink(&incumbent, &canonical).expect("place an incumbent symlink at the job name");
	assert!(matches!(
		container.create_job_directory(job_name()),
		Err(JobError::Occupied { job, artifact: JobArtifact::Directory }) if job == job_name()
	));
	assert_eq!(
		fs::read_link(&canonical).expect("keep old symlink"),
		incumbent
	);
	assert_eq!(
		fs::read(&incumbent).expect("keep old bytes"),
		b"preserve these bytes"
	);
	fs::remove_file(&canonical).expect("replace the test's synthetic incumbent");

	let uppercase = fixture.path(PRIVATE).join(JOB_NAME.to_uppercase());
	private_dir(&uppercase);
	let upper_marker = uppercase.join("incumbent");
	fs::write(&upper_marker, b"case alias incumbent").expect("mark incumbent");
	let has_case_alias = fs::symlink_metadata(&canonical).is_ok();
	match (has_case_alias, container.create_job_directory(job_name())) {
		(
			true,
			Err(JobError::Occupied {
				artifact: JobArtifact::Directory,
				..
			}),
		) => {}
		(false, Ok(job)) => assert_eq!(job.name(), job_name()),
		(result, other) => panic!("unexpected kernel case-alias decision ({result}, {other:?})"),
	}
	assert_eq!(
		fs::read(upper_marker).expect("keep case alias sentinel"),
		b"case alias incumbent"
	);
}

#[test]
fn fixed_record_exclusive_creation_never_truncates_or_follows_incumbents() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container
		.create_job_directory(job_name())
		.expect("create job");
	let job_path = job_path(&fixture);
	assert!(matches!(
		job.write_owner_record(b""),
		Err(JobError::InvalidLength)
	));
	let oversized = vec![0; super::record::MAX_RECORD_BYTES + 1];
	assert!(matches!(
		job.write_owner_record(&oversized),
		Err(JobError::InvalidLength)
	));
	assert!(!job_path.join(OWNER).exists());

	job.write_owner_record(b"first owner record")
		.expect("first write");
	assert!(matches!(
		job.write_owner_record(b"replacement"),
		Err(JobError::Occupied {
			artifact: JobArtifact::Owner,
			..
		})
	));
	assert_record(&job_path.join(OWNER), b"first owner record");
	let incumbent = fixture.path(TARGET);
	fs::write(&incumbent, b"external incumbent").expect("write synthetic incumbent");
	symlink(&incumbent, job_path.join(PLAN)).expect("place a symlink at the plan name");
	assert!(matches!(
		job.write_plan_record(b"replacement"),
		Err(JobError::Occupied {
			artifact: JobArtifact::Plan,
			..
		})
	));
	assert_eq!(
		fs::read(&incumbent).expect("read untouched incumbent"),
		b"external incumbent"
	);

	let journal = job.create_journal_directory().expect("create journal");
	let mut original = journal
		.create_first_segment()
		.expect("create first segment");
	original
		.write_all(b"first journal bytes")
		.expect("write journal fixture");
	drop(original);
	assert!(matches!(
		journal.create_first_segment(),
		Err(JobError::Occupied {
			artifact: JobArtifact::FirstSegment,
			..
		})
	));
	assert_record(
		&job_path.join(JOURNAL).join(FIRST_SEGMENT),
		b"first journal bytes",
	);

	let receipts = job.create_receipt_directory().expect("create receipts");
	receipts
		.write_receipt(b"first receipt")
		.expect("write first receipt");
	assert!(matches!(
		receipts.write_receipt(b"replacement"),
		Err(JobError::Occupied {
			artifact: JobArtifact::Receipt,
			..
		})
	));
	assert_record(&job_path.join(RECEIPTS).join(RECEIPT), b"first receipt");
}

#[test]
fn lost_job_and_child_bindings_do_not_grant_mutation_to_replacements() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container
		.create_job_directory(job_name())
		.expect("create job");
	let journal = job.create_journal_directory().expect("create journal");
	let path = job_path(&fixture);
	let old_journal = path.join("old-journal");
	fs::rename(path.join(JOURNAL), &old_journal).expect("move the synthetic held journal");
	private_dir(&path.join(JOURNAL));
	assert!(matches!(
		journal.create_first_segment(),
		Err(JobError::IdentityChanged)
	));
	assert!(!old_journal.join(FIRST_SEGMENT).exists());
	assert!(!path.join(JOURNAL).join(FIRST_SEGMENT).exists());

	let stage = job.create_stage_directory().expect("create nested stage");
	let old_path = fixture.path(PRIVATE).join("old-job");
	fs::rename(&path, &old_path).expect("move the synthetic held job");
	private_dir(&path);
	assert!(matches!(
		job.write_owner_record(b"owner"),
		Err(JobError::IdentityChanged)
	));
	assert!(matches!(
		stage.create_file(
			name(DATA.as_bytes()),
			name(TARGET.as_bytes()),
			job_context(),
			0
		),
		Err(super::StageError::DirectoryChanged)
	));
	assert!(!path.join(OWNER).exists());
	assert!(!old_path.join(OWNER).exists());
	assert!(!old_path.join(STAGE).join(DATA).exists());
}

#[test]
fn failed_file_barrier_reports_reconciliation_and_preserves_artifact() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container
		.create_job_directory(job_name())
		.expect("create job");
	let bytes = b"retain for reconciliation";
	let result = super::record::write_record_with(
		&job.directory.lease,
		checked_component(OWNER.as_bytes()).expect("valid owner component"),
		bytes,
		Creation::new(job.name(), JobArtifact::Owner),
		|| job.check_current(),
		|_| Err(Errno::IO),
	);
	let Err(JobError::Uncertain {
		job: reported_job,
		artifact: JobArtifact::Owner,
		step: JobStep::FileBarrier,
		source,
	}) = result
	else {
		panic!("expected an uncertain file barrier, got {result:?}");
	};
	assert_eq!(reported_job, job_name());
	assert!(matches!(*source, JobError::System(error) if error.raw_os_error() == Some(libc::EIO)));
	assert_record(&job_path(&fixture).join(OWNER), bytes);
	assert!(matches!(
		job.write_owner_record(b"retry must not overwrite"),
		Err(JobError::Occupied {
			artifact: JobArtifact::Owner,
			..
		})
	));
}
