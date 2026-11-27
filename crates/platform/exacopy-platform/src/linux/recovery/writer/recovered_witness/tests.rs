use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_model::retained_prefix::Head;

use super::{
	FRAME_OVERHEAD, RecoveredWitnessJournalError as Error, RecoveryWriteLease, StageError,
	WitnessObservationAppend,
};
use crate::linux::job::{FIRST_SEGMENT, JOURNAL, OWNER, STAGE};
use crate::linux::{DestinationRoot, RetainedPrefixSelection, WitnessedPublicSelection};
use crate::scratch::Scratch;

const JOB: &str = "observation-job";
const TARGET: &str = "public-target";
const STAGE_NAME: &str = "former-stage";
const WITNESS: &[u8; 40] = b"witness.1112131415161718191a1b1c1d1e1f20";
const PRIOR: &[u8] = b"original journal bytes";
const OWNER_BYTES: &[u8] = b"original owner bytes";
const PUBLIC_BYTES: &[u8] = b"preserved published bytes";
const EXTERNAL: &[u8] = b"unrelated late bytes";

#[test]
fn final_authority_refusal_leaves_the_exact_original_bytes() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let pins = lease.hold_witnessed_public(fixture.selection()).unwrap();
	let mut held = lease.hold_recovered_witness_journal().unwrap();

	let refused = held.append_recovered_observation(&pins, proposal(), || Ok(()), |_| Err(()));
	assert!(matches!(refused, Err(Error::Gate(()))));
	assert_eq!(fs::read(fixture.journal()).unwrap(), PRIOR);
	assert!(matches!(
		held.append_recovered_observation(&pins, proposal(), || Ok::<(), ()>(()), |_| Ok(())),
		Err(Error::Preflight(StageError::PriorBarrierFailure))
	));
	assert_eq!(fs::read(fixture.journal()).unwrap(), PRIOR);
}

#[test]
fn final_custody_refuses_a_late_eof_change_before_confirmation_and_write() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let pins = lease.hold_witnessed_public(fixture.selection()).unwrap();
	let mut held = lease.hold_recovered_witness_journal().unwrap();
	let result = held.append_recovered_observation(
		&pins,
		proposal(),
		|| {
			// Model an independent writer advancing EOF during preliminary admission.
			OpenOptions::new()
				.append(true)
				.open(fixture.journal())
				.unwrap()
				.write_all(EXTERNAL)
				.unwrap();
			Ok::<(), ()>(())
		},
		|_| panic!("changed journal reached the final authority check"),
	);
	assert!(matches!(result, Err(Error::Preflight(_))));
	assert_eq!(
		fs::read(fixture.journal()).unwrap(),
		[PRIOR, EXTERNAL].concat()
	);
}

#[test]
fn synthetic_append_rereads_exact_bytes_and_permanently_spends_the_lease() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let pins = lease.hold_witnessed_public(fixture.selection()).unwrap();
	let mut held = lease.hold_recovered_witness_journal().unwrap();
	let original = identity(&fixture.journal());
	let proposed = proposal();
	let expected = [PRIOR, proposed.encoded.as_slice()].concat();
	let end = proposed.successor.end;

	held.append_recovered_observation(&pins, proposed, || Ok::<(), ()>(()), |_| Ok(()))
		.unwrap();
	let (mut reader, observed_end) = held.journal().unwrap();
	let mut bytes = Vec::new();
	reader.read_to_end(&mut bytes).unwrap();
	assert_eq!(bytes, expected);
	assert_eq!(observed_end, end);
	held.recheck(end).unwrap();
	assert_eq!(identity(&fixture.journal()), original);
	pins.recheck().unwrap();

	drop(held);
	let current = lease.job().open_first_segment().unwrap();
	assert!(matches!(
		lease.open_first_segment_for_append(&current),
		Err(StageError::JobBusy)
	));
	assert!(matches!(
		lease.hold_recovered_witness_journal(),
		Err(StageError::JobBusy)
	));
	assert_eq!(fs::read(fixture.journal()).unwrap(), expected);
}

fn proposal() -> WitnessObservationAppend {
	// Synthetic transport bytes exercise native custody and exact I/O only.
	let encoded = vec![0x5a; FRAME_OVERHEAD + 1];
	let end = u64::try_from(PRIOR.len()).unwrap();
	WitnessObservationAppend {
		previous: Head {
			digest: [1; 32],
			sequence: 7,
			end,
		},
		successor: Head {
			digest: [2; 32],
			sequence: 8,
			end: end + u64::try_from(encoded.len()).unwrap(),
		},
		encoded,
	}
}

struct Fixture {
	scratch: Scratch,
	root: DestinationRoot,
}

impl Fixture {
	fn new() -> Self {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		let job = scratch.path(JOB);
		let target = scratch.path(TARGET);
		for directory in [&job, &job.join(STAGE), &job.join(JOURNAL)] {
			DirBuilder::new().mode(0o700).create(directory).unwrap();
		}
		write_private(&job.join(OWNER), OWNER_BYTES);
		write_private(&job.join(JOURNAL).join(FIRST_SEGMENT), PRIOR);
		write_private(&target, PUBLIC_BYTES);
		fs::hard_link(target, job.join(std::str::from_utf8(WITNESS).unwrap())).unwrap();
		Self { scratch, root }
	}

	fn lease(&self) -> RecoveryWriteLease<'_> {
		let name = component(JOB);
		let job = self.root.open_recovery_job(name).unwrap();
		self.root
			.try_recovery_write_lease(name, job.identity())
			.unwrap()
	}

	fn selection(&self) -> WitnessedPublicSelection<'static> {
		let job = self.scratch.path(JOB);
		let target = self.scratch.path(TARGET);
		let stat = fs::metadata(&target).unwrap();
		WitnessedPublicSelection {
			job: identity(&job),
			destination: self.root.identity().into(),
			stage: RetainedPrefixSelection {
				stage: component(STAGE_NAME),
				target: component(TARGET),
				directory: identity(&job.join(STAGE)),
				file: identity(&target),
			},
			witness_name: *WITNESS,
			uid: stat.uid(),
			gid: stat.gid(),
			extent: u64::try_from(PUBLIC_BYTES.len()).unwrap(),
		}
	}

	fn journal(&self) -> PathBuf {
		self.scratch.path(JOB).join(JOURNAL).join(FIRST_SEGMENT)
	}
}

fn component(name: &'static str) -> UnixComponent<'static> {
	UnixComponent::new(name.as_bytes()).unwrap()
}

fn identity(path: &Path) -> JobFileIdentity {
	let stat = fs::metadata(path).unwrap();
	JobFileIdentity {
		device: stat.dev(),
		inode: stat.ino(),
	}
}

fn write_private(path: &Path, bytes: &[u8]) {
	OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(path)
		.unwrap()
		.write_all(bytes)
		.unwrap();
}
