use super::{
	ChainHead, DestinationFixture, DestinationRoot, FIRST_SEGMENT, File, FrameKind, FrameReader,
	JOB_DIRECTORY, JOURNAL, OWNER, OwnerRecord, STAGE, SigningKey, TARGET, UnixComponent,
	assert_absent, bootstrap, fixture_signer, fs, native_identity,
};

fn copy_attempt() -> exacopy_transfer::linux::PlanAttempt<'static> {
	use exacopy_journal::JournalEntryId;
	use exacopy_transfer::linux::PlanAttempt;

	let request = bootstrap(JOB_DIRECTORY);
	PlanAttempt {
		job: request.context.job,
		epoch: request.context.epoch,
		entry: JournalEntryId::from_bytes([0x15; 16]),
		job_name: request.name,
		stage_name: UnixComponent::new(b"payload").expect("stage fixture name"),
	}
}

fn copy_profile(signer: &SigningKey) -> exacopy_transfer::linux::CopyProfile<'_> {
	let request = bootstrap(JOB_DIRECTORY);
	exacopy_transfer::linux::CopyProfile {
		id: request.profile,
		signer,
		created: request.created,
		owner_token: request.owner_token,
	}
}

fn copy_roots<'root>(
	source: &'root exacopy_platform::linux::ReadRoot,
	destination: &'root DestinationRoot,
) -> exacopy_engine::linux::CopyRoots<'root> {
	let request = bootstrap(JOB_DIRECTORY);
	exacopy_engine::linux::CopyRoots {
		source,
		destination,
		source_id: request.destination_id,
		destination_id: request.destination_id,
	}
}

#[test]
fn journaled_copy_persists_a_receipt_bound_to_verified_bytes_and_observed_publication() {
	use exacopy_engine::linux::{copy_new_file, plan_new_file};
	use exacopy_journal::{
		DurabilityRecorded, MetadataRecorded, PublishObserved, ReceiptCommitted,
	};
	use exacopy_platform::linux::ReadRoot;
	use exacopy_transfer::linux::{CopyReceipt, LocalCopyPlan};

	const DATA: &[u8] = b"this regular source participates in the actual copy";
	let fixture = DestinationFixture::new();
	let source_path = fixture.path("source");
	fs::write(&source_path, DATA).expect("write source file");
	let source_before = fs::metadata(source_path.clone()).expect("inspect source identity");
	let source = ReadRoot::from_directory(File::open(&fixture.0).expect("open source root"))
		.expect("admit source root");
	let destination = fixture.open_root();
	let roots = copy_roots(&source, &destination);
	let target = UnixComponent::new(TARGET.as_bytes()).expect("valid target name");
	let plan = plan_new_file(
		roots,
		copy_attempt(),
		UnixComponent::new(b"source").expect("valid source name"),
		target,
	)
	.expect("bind observed local plan");
	assert_absent(&fixture.path(JOB_DIRECTORY));
	let signer = fixture_signer();
	let receipt = copy_new_file(roots, &plan, copy_profile(&signer), &mut [0; 7])
		.expect("copy, exclusively publish, and commit receipt");

	let job = fixture.path(JOB_DIRECTORY);
	let artifact = fs::read(job.join("plan.cbor")).expect("read private plan");
	assert_eq!(
		LocalCopyPlan::decode(&artifact).expect("validate canonical plan"),
		plan
	);
	let owner = OwnerRecord::decode(
		&fs::read(job.join(OWNER)).expect("open owner"),
		bootstrap(JOB_DIRECTORY).profile,
		&signer.verifying_key(),
	)
	.expect("verify persisted owner authorization");
	assert_eq!(owner.manifest().plan_digest, plan.digest());
	let source_after = fs::metadata(&source_path).expect("retained source inode");
	let published = fs::metadata(fixture.path(TARGET)).expect("published file identity");
	assert_eq!(fs::read(source_path).expect("read preserved source"), DATA);
	assert_eq!(fs::read(fixture.path(TARGET)).expect("read target"), DATA);
	assert_eq!(
		native_identity(&source_before),
		native_identity(&source_after)
	);
	assert_ne!(native_identity(&source_before), native_identity(&published));
	assert_eq!(
		native_identity(&published),
		receipt.evidence().stream.identity
	);
	assert_eq!(receipt.evidence().stream.length.get(), DATA.len() as u64);
	assert_eq!(
		receipt.evidence().stream.digest.as_bytes(),
		blake3::hash(DATA).as_bytes()
	);
	assert_absent(&job.join(STAGE).join("payload"));

	let encoded =
		fs::read(job.join("receipts").join("receipt.cbor")).expect("open committed receipt");
	assert_eq!(
		CopyReceipt::decode(&encoded).expect("decode exact receipt"),
		receipt
	);
	let mut reader = FrameReader::new(
		File::open(job.join(JOURNAL).join(FIRST_SEGMENT)).expect("reopen journal"),
		ChainHead::start(),
	);
	let sequence = [
		FrameKind::JobPrepared,
		FrameKind::EntryPrepared,
		FrameKind::StageSealed,
		FrameKind::VerificationRecorded,
		FrameKind::MetadataRecorded,
		FrameKind::PublishIntent,
		FrameKind::PublishObserved,
		FrameKind::DurabilityRecorded,
		FrameKind::ReceiptCommitted,
	];
	let frames = sequence.map(|expected| {
		let frame = reader
			.next_frame()
			.expect("check frame")
			.expect("read frame");
		assert_eq!(frame.kind(), expected);
		frame
	});
	let metadata = MetadataRecorded::from_frame(&frames[4]).expect("decode checked metadata");
	assert_eq!(metadata.stage, native_identity(&published));
	let observed = PublishObserved::from_frame(&frames[6]).expect("decode publication observation");
	observed
		.validate_intent(&frames[5])
		.expect("exact synchronized intent reference");
	let durable = DurabilityRecorded::from_frame(&frames[7]).expect("decode recorded barriers");
	durable
		.validate_evidence(&frames[4], &frames[5], &frames[6])
		.expect("check exact barrier prerequisites");
	let committed = ReceiptCommitted::from_frame(&frames[8]).expect("decode committed receipt");
	assert_eq!(committed.durability(), receipt.durability_frame());
	assert_eq!(committed.digest().as_bytes(), &receipt.digest());
	assert!(
		reader
			.next_frame()
			.expect("confirm clean end of log")
			.is_none()
	);
}

#[test]
fn late_preflight_conflict_and_changed_source_create_no_private_job() {
	use exacopy_engine::linux::{LocalCopyError, copy_new_file, plan_new_file};
	use exacopy_platform::linux::ReadRoot;

	let fixture = DestinationFixture::new();
	let source_path = fixture.path("source");
	fs::write(&source_path, b"source file").expect("write source");
	let source = ReadRoot::from_directory(File::open(&fixture.0).expect("open source root"))
		.expect("admit source root");
	let destination = fixture.open_root();
	let roots = copy_roots(&source, &destination);
	let target = UnixComponent::new(TARGET.as_bytes()).expect("valid target name");
	let plan = plan_new_file(
		roots,
		copy_attempt(),
		UnixComponent::new(b"source").expect("valid source name"),
		target,
	)
	.expect("create plan while target absent");
	let signer = fixture_signer();
	fs::write(fixture.path(TARGET), b"incumbent").expect("new incumbent");
	assert!(matches!(
		copy_new_file(roots, &plan, copy_profile(&signer), &mut [0; 7]),
		Err(LocalCopyError::Conflict)
	));
	assert_absent(&fixture.path(JOB_DIRECTORY));
	assert_eq!(
		fs::read(fixture.path(TARGET)).expect("retain incumbent"),
		b"incumbent"
	);
	fs::remove_file(fixture.path(TARGET)).expect("reset fixture");
	fs::write(&source_path, b"longer source file").expect("change length after planning");
	assert!(matches!(
		copy_new_file(roots, &plan, copy_profile(&signer), &mut [0; 7]),
		Err(LocalCopyError::StalePlan)
	));
	assert_absent(&fixture.path(JOB_DIRECTORY));
	assert_absent(&fixture.path(TARGET));
}

#[test]
fn conflicting_destination_capabilities_refuse_before_private_job_creation() {
	use exacopy_endpoint::linux_copy::{CopyDestinationView, TargetObservation};
	use exacopy_endpoint::linux_job::{JobBootstrapRoot, JobFileIdentity};
	use exacopy_engine::linux::plan_new_file;
	use exacopy_platform::linux::{JobDirectory, ReadRoot, StageError};
	use exacopy_transfer::linux::{CopyError, PlanningRoots, copy_with_capabilities};

	struct InconsistentDestination<'root>(&'root DestinationRoot);

	impl CopyDestinationView for InconsistentDestination<'_> {
		type Error = StageError;

		fn identity(&self) -> JobFileIdentity {
			CopyDestinationView::identity(self.0)
		}

		fn observe_target(&self, name: UnixComponent<'_>) -> Result<TargetObservation, StageError> {
			self.0.target_status(name)
		}
	}

	impl<'held> JobBootstrapRoot<'held> for InconsistentDestination<'_> {
		type Error = StageError;
		type Job = JobDirectory<'held>;

		fn identity(&self) -> JobFileIdentity {
			let mut identity = CopyDestinationView::identity(self.0);
			identity.inode ^= 1;
			identity
		}

		fn create_job_directory(
			&'held self,
			name: UnixComponent<'_>,
		) -> Result<Self::Job, Self::Error> {
			self.0.create_job_directory(name)
		}

		fn sync_directory(&self) -> Result<(), Self::Error> {
			self.0.sync_directory()
		}
	}

	let fixture = DestinationFixture::new();
	let source_bytes = b"retained source";
	fs::write(fixture.path("source"), source_bytes).expect("write source");
	let source = ReadRoot::from_directory(File::open(&fixture.0).expect("open source parent"))
		.expect("admit source root");
	let destination = fixture.open_root();
	let roots = copy_roots(&source, &destination);
	let target = UnixComponent::new(TARGET.as_bytes()).expect("target component");
	let input = UnixComponent::new(b"source").expect("source component");
	let plan = plan_new_file(roots, copy_attempt(), input, target).expect("admit initial plan");

	let inconsistent = InconsistentDestination(&destination);
	let roots = PlanningRoots {
		source: roots.source,
		source_id: roots.source_id,
		destination: &inconsistent,
		destination_id: roots.destination_id,
	};
	let signer = fixture_signer();
	let error = copy_with_capabilities(roots, &plan, copy_profile(&signer), &mut [0; 7], |_| {})
		.expect_err("bootstrap identity must agree with the destination view");
	assert!(matches!(error, CopyError::StalePlan), "{error}");
	assert_absent(&fixture.path(JOB_DIRECTORY));
	assert_absent(&fixture.path(TARGET));
	assert_eq!(
		fs::read(fixture.path("source")).expect("read source"),
		source_bytes
	);
}
