use std::fs;
use std::io;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _, symlink};

use rustix::fs as native_fs;
use rustix::io::Errno;

use super::{
	Fixture, JobArtifact, JobError, JobStep, RECEIPT, RECEIPTS, assert_record, job_name, job_path,
	open_staging,
};
use crate::macos::staging::jobs::RecoveryError;

const PENDING: &str = "receipt.pending";
const PAYLOAD: &[u8] = b"canonical receipt bytes";

#[test]
fn receipt_is_absent_until_file_barrier_and_renamed_before_directory_barrier() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container.create_job_directory(job_name()).unwrap();
	let receipts = job.create_receipt_directory().unwrap();
	let directory = job_path(&fixture).join(RECEIPTS);
	let final_name = directory.join(RECEIPT);
	let pending = directory.join(PENDING);
	let identity = receipts
		.write_receipt_with(
			PAYLOAD,
			|file, offset, bytes| file.write_at(bytes, offset),
			|file| {
				assert!(!final_name.exists());
				assert_eq!(
					assert_record(&pending, PAYLOAD).ino(),
					file.metadata().unwrap().ino()
				);
				native_fs::fcntl_fullfsync(file)
			},
			|directory| {
				assert!(!pending.exists());
				assert_record(&final_name, PAYLOAD);
				native_fs::fsync(directory)
			},
		)
		.unwrap();
	assert_eq!(
		assert_record(&final_name, PAYLOAD).ino(),
		identity.inode().get()
	);
}

#[test]
fn partial_write_stays_pending_and_recovery_refuses_to_open_it() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container.create_job_directory(job_name()).unwrap();
	let receipts = job.create_receipt_directory().unwrap();
	let result = receipts.write_receipt_with(
		PAYLOAD,
		|file, offset, bytes| {
			if offset == 0 {
				return file.write_at(&bytes[..1], offset);
			}
			Err(io::Error::from_raw_os_error(libc::ENOSPC))
		},
		|_| panic!("partial receipt must not reach the file barrier"),
		|_| panic!("partial receipt must not reach the directory barrier"),
	);
	assert!(matches!(
		result,
		Err(JobError::Uncertain {
			artifact: JobArtifact::ReceiptPending,
			step: JobStep::Write,
			..
		})
	));
	let directory = job_path(&fixture).join(RECEIPTS);
	let pending = directory.join(PENDING);
	assert_record(&pending, &PAYLOAD[..1]);
	assert!(!directory.join(RECEIPT).exists());
	assert!(matches!(
		receipts.write_receipt(PAYLOAD),
		Err(JobError::Occupied {
			artifact: JobArtifact::ReceiptPending,
			..
		})
	));
	drop(receipts);
	drop(job);
	let recovery = container.open_recovery_job(job_name()).unwrap();
	assert!(matches!(
		recovery.open_receipt(),
		Err(RecoveryError::PendingReceipt)
	));
	assert_record(&pending, &PAYLOAD[..1]);
}

#[test]
fn failed_file_barrier_leaves_pending_while_failed_directory_barrier_leaves_complete_final() {
	for (step, artifact) in [
		(JobStep::FileBarrier, JobArtifact::ReceiptPending),
		(JobStep::NamespaceBarrier, JobArtifact::Receipt),
	] {
		let fixture = Fixture::new();
		let root = fixture.bind();
		let container = open_staging(&root);
		let job = container.create_job_directory(job_name()).unwrap();
		let receipts = job.create_receipt_directory().unwrap();
		let directory = job_path(&fixture).join(RECEIPTS);
		let result = receipts.write_receipt_with(
			PAYLOAD,
			|file, offset, bytes| file.write_at(bytes, offset),
			|file| {
				if step == JobStep::FileBarrier {
					Err(Errno::IO)
				} else {
					native_fs::fcntl_fullfsync(file)
				}
			},
			|_| {
				assert_eq!(step, JobStep::NamespaceBarrier);
				Err(Errno::IO)
			},
		);
		assert!(matches!(result, Err(JobError::Uncertain {
			artifact: reported_artifact,
			step: reported_step,
			source,
			..
		}) if reported_step == step && reported_artifact == artifact &&
			matches!(&*source, JobError::System(error) if error.raw_os_error() == Some(libc::EIO))));
		let finished = step == JobStep::NamespaceBarrier;
		assert_record(
			&directory.join(if finished { RECEIPT } else { PENDING }),
			PAYLOAD,
		);
		assert!(
			!directory
				.join(if finished { PENDING } else { RECEIPT })
				.exists()
		);
	}
}

#[test]
fn late_final_incumbent_survives_native_exclusive_rename() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container.create_job_directory(job_name()).unwrap();
	let receipts = job.create_receipt_directory().unwrap();
	let directory = job_path(&fixture).join(RECEIPTS);
	let final_name = directory.join(RECEIPT);
	let incumbent = b"independent incumbent";
	let result = receipts.write_receipt_with(
		PAYLOAD,
		|file, offset, bytes| file.write_at(bytes, offset),
		|file| {
			fs::write(&final_name, incumbent).unwrap();
			native_fs::fcntl_fullfsync(file)
		},
		|_| panic!("failed rename must not reach the directory barrier"),
	);
	assert!(matches!(result, Err(JobError::Uncertain {
		artifact: JobArtifact::Receipt,
		step: JobStep::Publish,
		source,
		..
	}) if matches!(*source, JobError::Occupied { artifact: JobArtifact::Receipt, .. })));
	assert_eq!(fs::read(&final_name).unwrap(), incumbent);
	assert_record(&directory.join(PENDING), PAYLOAD);
	drop(receipts);
	drop(job);
	let recovery = container.open_recovery_job(job_name()).unwrap();
	assert!(matches!(
		recovery.open_receipt(),
		Err(RecoveryError::PendingReceipt)
	));
}

#[test]
fn pending_and_final_symlinks_are_neither_followed_nor_replaced() {
	for (name, artifact) in [
		(PENDING, JobArtifact::ReceiptPending),
		(RECEIPT, JobArtifact::Receipt),
	] {
		let fixture = Fixture::new();
		let root = fixture.bind();
		let container = open_staging(&root);
		let job = container.create_job_directory(job_name()).unwrap();
		let receipts = job.create_receipt_directory().unwrap();
		let directory = job_path(&fixture).join(RECEIPTS);
		let user_file = fixture.path("user-file");
		let original = b"protect user bytes";
		fs::write(&user_file, original).unwrap();
		symlink(&user_file, directory.join(name)).unwrap();
		assert!(
			matches!(receipts.write_receipt(PAYLOAD), Err(JobError::Occupied {
			artifact: reported, ..
		}) if reported == artifact)
		);
		assert_eq!(fs::read_link(directory.join(name)).unwrap(), user_file);
		assert_eq!(fs::read(&user_file).unwrap(), original);
		assert!(
			!directory
				.join(if name == RECEIPT { PENDING } else { RECEIPT })
				.exists()
		);
	}
}

#[test]
fn receipt_readback_refuses_same_length_corruption() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container.create_job_directory(job_name()).unwrap();
	let receipts = job.create_receipt_directory().unwrap();
	let directory = job_path(&fixture).join(RECEIPTS);
	let altered = [0; PAYLOAD.len()];
	let result = receipts.write_receipt_with(
		PAYLOAD,
		|file, offset, _| file.write_at(&altered, offset),
		|file| native_fs::fcntl_fullfsync(file),
		|_| panic!("a byte mismatch must not reach publication"),
	);
	assert!(matches!(result, Err(JobError::Uncertain {
		artifact: JobArtifact::ReceiptPending,
		step: JobStep::Verify,
		source,
		..
	}) if matches!(*source, JobError::ReceiptMismatch)));
	assert_record(&directory.join(PENDING), &altered);
	assert!(!directory.join(RECEIPT).exists());
}

#[test]
fn pending_rebinding_at_the_file_barrier_preserves_both_objects() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container.create_job_directory(job_name()).unwrap();
	let receipts = job.create_receipt_directory().unwrap();
	let directory = job_path(&fixture).join(RECEIPTS);
	let pending = directory.join(PENDING);
	let displaced = directory.join("displaced-fixture");
	let result = receipts.write_receipt_with(
		PAYLOAD,
		|file, offset, bytes| file.write_at(bytes, offset),
		|file| {
			fs::rename(&pending, &displaced).unwrap();
			let replacement = fs::OpenOptions::new()
				.create_new(true)
				.write(true)
				.mode(0o600)
				.open(&pending)
				.unwrap();
			replacement.write_all_at(PAYLOAD, 0).unwrap();
			native_fs::fcntl_fullfsync(file)
		},
		|_| panic!("rebound pending name must not reach publication"),
	);
	assert!(matches!(result, Err(JobError::Uncertain {
		artifact: JobArtifact::ReceiptPending,
		step: JobStep::Verify,
		source,
		..
	}) if matches!(*source, JobError::IdentityChanged)));
	assert_eq!(fs::read(&pending).unwrap(), PAYLOAD);
	assert_eq!(fs::read(&displaced).unwrap(), PAYLOAD);
	assert!(!directory.join(RECEIPT).exists());
}

#[test]
fn pending_name_repopulated_after_rename_keeps_both_inodes_and_requires_reconciliation() {
	use std::error::Error as _;
	use std::fs::File;

	const INCUMBENT: &[u8] = b"late pending bytes";
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let job = container
		.create_job_directory(job_name())
		.expect("create the private job");
	let receipts = job
		.create_receipt_directory()
		.expect("create the receipt directory");
	let directory = job_path(&fixture).join(RECEIPTS);
	let pending = directory.join(PENDING);
	let final_name = directory.join(RECEIPT);
	let mut original_inode = None;
	let mut incumbent_inode = None;
	let outcome = receipts
		.write_receipt_with(
			PAYLOAD,
			|file, offset, bytes| file.write_at(bytes, offset),
			|file| {
				original_inode = Some(file.metadata().expect("observe the pending inode").ino());
				native_fs::fcntl_fullfsync(file)
			},
			|directory| {
				let replacement = File::options()
					.create_new(true)
					.mode(0o600)
					.write(true)
					.open(&pending)
					.expect("simulate a late incumbent at the vacated pending name");
				replacement
					.write_all_at(INCUMBENT, 0)
					.expect("write replacement fixture bytes");
				incumbent_inode = Some(
					replacement
						.metadata()
						.expect("observe replacement inode")
						.ino(),
				);
				native_fs::fsync(directory)
			},
		)
		.expect_err("both names populated cannot establish a complete receipt");

	assert!(matches!(&outcome, JobError::Uncertain {
		job: reported,
		artifact: JobArtifact::Receipt,
		step: JobStep::Revalidate,
		source,
	} if *reported == job_name() && matches!(**source, JobError::IdentityChanged)));
	assert!(matches!(
		outcome
			.source()
			.and_then(|error| error.downcast_ref::<JobError>()),
		Some(JobError::IdentityChanged)
	));
	assert!(outcome.to_string().contains("requires reconciliation"));
	assert!(matches!(
		receipts.write_receipt(PAYLOAD),
		Err(JobError::Occupied {
			artifact: JobArtifact::Receipt,
			..
		})
	));
	assert_eq!(
		Some(assert_record(&final_name, PAYLOAD).ino()),
		original_inode
	);
	assert_eq!(
		Some(assert_record(&pending, INCUMBENT).ino()),
		incumbent_inode
	);
	assert_ne!(original_inode, incumbent_inode);
}
