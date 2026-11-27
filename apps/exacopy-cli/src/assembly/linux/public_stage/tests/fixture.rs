use std::env;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::PathBuf;
use std::process;

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_endpoint::UnixComponent;
use exacopy_journal::{
	ApplyMetadataPolicyDigest, ApplyRequestedDurability, ApprovedPublicPlanDigest,
	ApprovedStreamDigest, OwnerProfileId, OwnerTimestamp, OwnerToken, PublicApplyBinding,
	PublicPlanEntryId, RootCapabilityId, StreamLength,
};
use exacopy_plan::{PlanPath, UnixTimestamp};
use exacopy_platform::linux::{DestinationRoot, ReadRoot};
use exacopy_transfer::copy_planning::{
	CreateNewRequest, PlanSelection, PlannedCopy, linux_baseline_metadata_policy_digest,
};
use exacopy_transfer::linux::{CopyProfile, PlanAttempt, RecoveryProfile};
use exacopy_transfer::public_plan::{AdmittedCopyPlan, ExpectedCopyPlan};

use super::super::super::{CopyRoots, plan_public_new_file};
use super::synthetic_job;

pub(super) const SOURCE: &str = "source-file";
pub(super) const TARGET: &str = "target-file";
pub(super) const APPROVED: &[u8] = b"approved public content";
pub(super) const CHANGED: &[u8] = b"modified public content";
pub(super) const INCUMBENT: &[u8] = b"fixture-owned incumbent";
const SOURCE_ROOT: uuid::Uuid = uuid::uuid!("20c427bb-3c4d-4ca6-ab71-305d22fee8d3");
const DESTINATION_ROOT: uuid::Uuid = uuid::uuid!("31554054-c335-41fe-8636-cecd607dbc20");
const BUFFER: usize = 4096;

pub(super) fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).unwrap()
}

pub(super) fn attempt(job_name: &str, marker: u8) -> PlanAttempt<'_> {
	let (job, entry, epoch) = synthetic_job(marker);
	PlanAttempt {
		job,
		epoch,
		entry,
		job_name: component(job_name),
		stage_name: component("candidate"),
	}
}

pub(super) const fn buffer() -> [u8; BUFFER] {
	[0; BUFFER]
}

pub(super) struct Fixture {
	root: PathBuf,
	signer: SigningKey,
	public_key: VerifyingKey,
	wrong_key: VerifyingKey,
}

impl Fixture {
	pub(super) fn new() -> Self {
		assert!(!rustix::process::geteuid().is_root());
		let parent = PathBuf::from(env::var_os("EXACOPY_PUBLIC_STAGE_EXT4_PARENT").unwrap());
		assert!(parent.is_absolute());
		let root = parent.join(format!("public-stage-{}", process::id()));
		DirBuilder::new().mode(0o700).create(&root).unwrap();
		let signer = SigningKey::from_bytes(&[7; 32]);
		let fixture = Self {
			root,
			public_key: signer.verifying_key(),
			signer,
			wrong_key: SigningKey::from_bytes(&[8; 32]).verifying_key(),
		};
		for directory in ["source", "destination"] {
			DirBuilder::new()
				.mode(0o700)
				.create(fixture.root.join(directory))
				.unwrap();
		}
		let mut file = OpenOptions::new()
			.create_new(true)
			.write(true)
			.mode(0o600)
			.open(fixture.source())
			.unwrap();
		file.write_all(APPROVED).unwrap();
		assert_eq!(APPROVED.len(), CHANGED.len());
		fixture
	}

	pub(super) fn source(&self) -> PathBuf {
		self.root.join("source").join(SOURCE)
	}

	fn destination(&self) -> PathBuf {
		self.root.join("destination")
	}

	pub(super) fn target(&self) -> PathBuf {
		self.destination().join(TARGET)
	}

	pub(super) fn job(&self, attempt: PlanAttempt<'_>) -> PathBuf {
		self.destination()
			.join(std::ffi::OsStr::from_bytes(attempt.job_name.as_bytes()))
	}

	pub(super) fn stage(&self, attempt: PlanAttempt<'_>) -> PathBuf {
		self.job(attempt).join("stage").join("candidate")
	}

	pub(super) fn journal(&self, attempt: PlanAttempt<'_>) -> PathBuf {
		self.job(attempt)
			.join("journal/00000000000000000001.exajnl")
	}

	pub(super) fn open_roots(&self) -> (ReadRoot, DestinationRoot) {
		let source = File::open(self.root.join("source")).unwrap();
		(
			ReadRoot::from_directory(source).unwrap(),
			self.open_destination(),
		)
	}

	pub(super) fn open_destination(&self) -> DestinationRoot {
		DestinationRoot::from_directory(File::open(self.destination()).unwrap()).unwrap()
	}

	pub(super) fn roots<'root>(
		source: &'root ReadRoot,
		destination: &'root DestinationRoot,
	) -> CopyRoots<'root> {
		CopyRoots {
			source,
			destination,
			source_id: RootCapabilityId::from_bytes(*SOURCE_ROOT.as_bytes()).unwrap(),
			destination_id: RootCapabilityId::from_bytes(*DESTINATION_ROOT.as_bytes()).unwrap(),
		}
	}

	pub(super) fn plan(roots: CopyRoots<'_>) -> (PlannedCopy, ExpectedCopyPlan<'static>) {
		let source = component(SOURCE);
		let destination = component(TARGET);
		let observed_at = UnixTimestamp::new(1_800_000_000, 0).unwrap();
		let bundle = plan_public_new_file(
			roots.source,
			roots.destination,
			CreateNewRequest {
				plan_id: uuid::uuid!("019a0000-0000-7000-8000-000000000021"),
				entry_id: uuid::uuid!("b8de42ce-9372-442b-8f40-833538ad4a61"),
				source_view_id: uuid::uuid!("0bb3ba31-6076-4dde-a152-e7eb640f6c08"),
				measurement_id: uuid::uuid!("c1200385-d2fb-4ff5-ab63-a519052c2374"),
				source: PlanSelection {
					root_id: SOURCE_ROOT,
					component: source,
				},
				destination: PlanSelection {
					root_id: DESTINATION_ROOT,
					component: destination,
				},
				observed_at,
			},
			|_| true,
			&mut buffer(),
		)
		.unwrap();
		let selection = ExpectedCopyPlan {
			digest: bundle.digest(),
			source: PlanPath {
				root_id: SOURCE_ROOT,
				basename: source.as_bytes(),
			},
			destination: PlanPath {
				root_id: DESTINATION_ROOT,
				basename: destination.as_bytes(),
			},
			metadata_policy_digest: linux_baseline_metadata_policy_digest(),
			now: observed_at,
		};
		(bundle, selection)
	}

	pub(super) fn binding(
		approved: &AdmittedCopyPlan<'_>,
		attempt: PlanAttempt<'_>,
	) -> PublicApplyBinding {
		let entry = approved.entry();
		PublicApplyBinding {
			public_plan: ApprovedPublicPlanDigest::from_bytes(approved.body().digest()),
			public_entry: PublicPlanEntryId::from_bytes(*entry.entry_id.as_bytes()).unwrap(),
			private_entry: attempt.entry,
			epoch: attempt.epoch,
			source_root: RootCapabilityId::from_bytes(*SOURCE_ROOT.as_bytes()).unwrap(),
			destination_root: RootCapabilityId::from_bytes(*DESTINATION_ROOT.as_bytes()).unwrap(),
			stream_length: StreamLength::new(entry.stream_length).unwrap(),
			stream_digest: ApprovedStreamDigest::from_bytes(entry.stream_digest),
			metadata_policy: ApplyMetadataPolicyDigest::from_bytes(entry.metadata_policy_digest),
			expires_at: None,
			requested_durability: ApplyRequestedDurability::ProcessCrash,
		}
	}

	pub(super) fn profile(&self) -> CopyProfile<'_> {
		CopyProfile {
			id: self.recovery().id,
			signer: &self.signer,
			created: OwnerTimestamp::new(1_800_000_000, 1).unwrap(),
			owner_token: OwnerToken::from_bytes([9; 16]).unwrap(),
		}
	}

	pub(super) fn recovery(&self) -> RecoveryProfile<'_> {
		RecoveryProfile {
			id: OwnerProfileId::from_bytes([6; 16]).unwrap(),
			verifying_key: &self.public_key,
		}
	}

	pub(super) fn wrong_recovery(&self) -> RecoveryProfile<'_> {
		RecoveryProfile {
			verifying_key: &self.wrong_key,
			..self.recovery()
		}
	}

	pub(super) fn finish(mut self) {
		fs::remove_dir_all(&self.root).unwrap();
		assert!(!self.root.try_exists().unwrap());
		self.root.clear();
		println!("EXACOPY_PUBLIC_STAGE_EXT4_RESULT preserved_and_cleaned");
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		if !self.root.as_os_str().is_empty() {
			let _ = fs::remove_dir_all(&self.root);
		}
	}
}
