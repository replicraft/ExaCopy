//! Actual producer, no-clobber output and separately selected P063 preview.

#![cfg(all(target_os = "linux", feature = "experimental-linux-managed-sync"))]

use std::error::Error;
use std::ffi::OsStr;
use std::fs::File;
use std::num::{NonZeroU32, NonZeroU64};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};

use ed25519_dalek::SigningKey;
use exacopy_cli::assembly::linux::managed_sync::genesis::{
	ManagedGenesisEnrollment, ManagedGenesisError, ManagedGenesisRequest, produce_managed_genesis,
};
use exacopy_cli::assembly::linux::managed_sync::{
	ManagedCooperation, ManagedHistoryMember, ManagedPolicy, ManagedPolicyEndpoint,
	ManagedPolicyHistory, ManagedSyncInit, ManagedSyncPreviewError, initialize_managed_preview,
	preview_managed_history,
};
use exacopy_endpoint::UnixComponent;
use exacopy_model::{SyncCopyTarget, SyncPathDecision, SyncSide};
use exacopy_plan::workflow_sync::{EndpointFacts, LinuxLocation, WorkflowTimestamp};
use exacopy_platform::linux::{
	ManagedSyncError, ManagedSyncExpectedRoot, ManagedSyncNativeScope, SyncGenesisNativeIdentity,
	SyncGenesisOperation, SyncGenesisPublishError, SyncPreviewError, SyncPreviewRoots,
	SyncProfileStore, SyncProfileStoreError,
};
use exacopy_transfer::linux::sync_genesis_measurement::GenesisMeasureFailure;
use exacopy_transfer::sync_genesis::SyncGenesisRecords;
use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags};
use rustix::process::{getegid, geteuid};

#[path = "managed_sync_genesis_production/approval.rs"]
mod approval;
#[path = "managed_sync_genesis_production/evidence.rs"]
mod evidence;
#[path = "managed_sync_genesis_production/observe.rs"]
mod observe;
#[path = "managed_sync_genesis_production/rig.rs"]
mod rig;

use evidence::{NAMES, Published};
use observe::{admit, components, expected, observe_scope};
use rig::{Sandbox, assert_missing, native_object, object, open_child, read};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const SUBJECT: &[u8] = b"equal-subject-\xff";
const ROOT_NAMES: [&[u8]; 2] = [b"left-\xff", b"right-\xff"];
const SEED: [u8; 32] = [0x51; 32];
const ENROLLMENT: [u8; 16] = [0x41; 16];
const PARTICIPANTS: [[u8; 16]; 2] = [[0x51; 16], [0x52; 16]];
const INITIAL: &[u8] = b"abc";
const CHANGED: &[u8] = b"xyz";

#[test]
#[ignore = "requires independently selected owner-private whole ext4 producer anchors"]
fn production_managed_genesis_publishes_and_previews_exact_p063_history() -> TestResult {
	let (mut sandbox, anchor) = Sandbox::create(admit)?;
	let result = exercise(&mut sandbox, &anchor)?;
	sandbox.clean()?;
	if std::env::var_os("EXACOPY_MANAGED_SYNC_GENESIS_CAPTURE").is_some_and(|value| value == "1") {
		let frame = serde_json::to_string(&result)?;
		assert!(frame.len() <= 64 * 1024);
		println!("\nmanaged_sync_genesis_evidence={frame}");
	}
	println!("\nmanaged_sync_genesis_production=passed controls=8 cleanup=verified");
	Ok(())
}

fn exercise(sandbox: &mut Sandbox, anchor: &observe::Anchor) -> TestResult<serde_json::Value> {
	let directory = sandbox.directory.try_clone()?;
	let profile = sandbox.mkdir(&directory, b"profile")?;
	let output = sandbox.mkdir(&directory, b"output")?;
	let live = sandbox.mkdir(&directory, b"live")?;
	let [left, right] = [
		sandbox.mkdir(&live, ROOT_NAMES[0])?,
		sandbox.mkdir(&live, ROOT_NAMES[1])?,
	];
	sandbox.write_new(&left, SUBJECT, INITIAL)?;
	sandbox.write_new(&right, SUBJECT, INITIAL)?;
	let [left_file, right_file] = [
		open_child(&left, SUBJECT, OFlags::RDONLY)?,
		open_child(&right, SUBJECT, OFlags::RDONLY)?,
	];
	sandbox.write_new(&profile, b"owner.seed", &SEED)?;
	sandbox.write_new(&output, b"incumbent", b"unrelated incumbent")?;
	let profile_path = sandbox.path.join("profile");
	let output_path = sandbox.path.join("output");
	let live_path = sandbox.path.join("live");
	let profile_identity = SyncProfileStore::open(&profile_path)?.identity();
	assert_eq!(
		native_object(profile_identity),
		object(&profile.metadata()?)
	);

	let roots = SyncPreviewRoots::open(&live_path, components(ROOT_NAMES))?;
	let location = observe_scope(&roots, &live, [&left, &right], ROOT_NAMES)?;
	assert_eq!(
		(
			location.boot,
			location.mount_namespace,
			location.user_namespace,
			location.ordinary_mount,
			location.unique_mount
		),
		(
			anchor.location.boot,
			anchor.location.mount_namespace,
			anchor.location.user_namespace,
			anchor.location.ordinary_mount,
			anchor.location.unique_mount
		),
	);
	let facts = [object(&left.metadata()?), object(&right.metadata()?)];
	let instance = |index: usize| EndpointFacts {
		endpoint: [[0x21; 16], [0x22; 16]][index],
		root: [[0x31; 16], [0x32; 16]][index],
		parent: [0x33; 16],
		name: components(ROOT_NAMES)[index],
		location: LinuxLocation {
			boot: location.boot,
			mount_namespace: location.mount_namespace,
			user_namespace: location.user_namespace,
			mount: location.unique_mount,
			parent: location.parent,
			root: facts[index],
		},
		max_bytes: 3,
	};
	let endpoints = [instance(0), instance(1)];
	let signer = SigningKey::from_bytes(&SEED);
	let owner_key = signer.verifying_key().to_bytes();
	let mut owner_profile = [0; 16];
	blake3::Hasher::new_derive_key("ExaCopy local CLI profile ID v1")
		.update(&owner_key)
		.finalize_xof()
		.fill(&mut owner_profile);
	let owner_profile = uuid::Builder::from_custom_bytes(owner_profile)
		.into_uuid()
		.into_bytes();
	let outputs = output.metadata()?;
	let operation = SyncGenesisOperation::new([0x61; 16]).unwrap();
	let mut request = ManagedGenesisRequest {
		profile: &profile_path,
		profile_identity,
		owner_key,
		profile_revision: NonZeroU64::new(3).unwrap(),
		native: ManagedSyncNativeScope {
			parent_path: &live_path,
			uid: NonZeroU32::new(geteuid().as_raw()).ok_or("ordinary actor required")?,
			gid: NonZeroU32::new(getegid().as_raw()).ok_or("ordinary group required")?,
			subject: UnixComponent::new(SUBJECT)?,
			boot: location.boot,
			mount_namespace: expected(location.mount_namespace),
			user_namespace: expected(location.user_namespace),
			ordinary_mount: location.ordinary_mount,
			unique_mount: location.unique_mount,
			parent: expected(location.parent),
			roots: std::array::from_fn(|index| ManagedSyncExpectedRoot {
				name: components(ROOT_NAMES)[index],
				identity: expected(facts[index]),
			}),
		},
		endpoints,
		enrollment: ManagedGenesisEnrollment {
			id: ENROLLMENT,
			participants: &PARTICIPANTS,
			expected_digest: [0; 32],
		},
		output_parent: &output_path,
		output_identity: SyncGenesisNativeIdentity {
			device: outputs.dev(),
			inode: NonZeroU64::new(outputs.ino()).unwrap(),
		},
		operation,
		scan: NonZeroU64::new(29).unwrap(),
		records: SyncGenesisRecords {
			root: record_id(0x83),
			endpoints: [record_id(0x81), record_id(0x82)],
			created_at: WorkflowTimestamp::new(12, 19).unwrap(),
		},
	};
	request.enrollment.expected_digest = approval::enrollment(&request, owner_profile);
	let sources = [&left, &right];
	let pristine = evidence::inventory(&output)?;
	sandbox.preserve();
	// Reuse the same absent namespace on unrelated input refusals; each must prove
	// that all names and existing contents are unchanged.
	{
		let lease = writer(&directory)?;
		open_child(&right, SUBJECT, OFlags::WRONLY)?.write_all_at(CHANGED, 0)?;
		drop(lease);
		assert!(matches!(
			produce_managed_genesis(&request, &mut [0; 32]),
			Err(ManagedGenesisError::Measurement(
				GenesisMeasureFailure::ContentMismatch
			))
		));
		assert_eq!(evidence::inventory(&output)?, pristine);
		assert_eq!(read(&left, SUBJECT)?, INITIAL);
		assert_eq!(read(&right, SUBJECT)?, CHANGED);
	}
	{
		let lease = writer(&directory)?;
		open_child(&right, SUBJECT, OFlags::WRONLY)?.write_all_at(INITIAL, 0)?;
		fs::fchmod(&right_file, Mode::from_raw_mode(0o400))?;
		drop(lease);
		assert!(matches!(
			produce_managed_genesis(&request, &mut [0; 32]),
			Err(ManagedGenesisError::Measurement(
				GenesisMeasureFailure::MetadataMismatch
			))
		));
		assert_eq!(evidence::inventory(&output)?, pristine);
		assert_eq!(right_file.metadata()?.mode() & 0o7777, 0o400);
		let _lease = writer(&directory)?;
		fs::fchmod(&right_file, Mode::from_raw_mode(0o600))?;
	}
	let right_backup: &[u8] = b"retained-right";
	{
		let lease = writer(&directory)?;
		fs::renameat_with(
			&right,
			SUBJECT,
			&right,
			right_backup,
			fs::RenameFlags::NOREPLACE,
		)?;
		drop(lease);
		assert!(matches!(
			produce_managed_genesis(&request, &mut [0; 32]),
			Err(ManagedGenesisError::Measurement(
				GenesisMeasureFailure::Absent(SyncSide::Right)
			))
		));
		assert_eq!(evidence::inventory(&output)?, pristine);
		let lease = writer(&directory)?;
		fs::linkat(&left, SUBJECT, &right, SUBJECT, AtFlags::empty())?;
		drop(lease);
		assert!(matches!(
			produce_managed_genesis(&request, &mut [0; 32]),
			Err(ManagedGenesisError::Scope(
				ManagedSyncPreviewError::Managed(ManagedSyncError::Preview(
					SyncPreviewError::AliasedFiles
				))
			))
		));
		assert_eq!(evidence::inventory(&output)?, pristine);
		let held_alias = open_child(&right, SUBJECT, OFlags::RDONLY)?;
		assert_eq!(
			object(&held_alias.metadata()?),
			object(&left_file.metadata()?)
		);
		assert_eq!(held_alias.metadata()?.nlink(), 2);
		assert_eq!(read(&right, SUBJECT)?, INITIAL);
		let _lease = writer(&directory)?;
		fs::unlinkat(&right, SUBJECT, AtFlags::empty())?;
		fs::renameat_with(
			&right,
			right_backup,
			&right,
			SUBJECT,
			fs::RenameFlags::NOREPLACE,
		)?;
	}

	let profile_before = evidence::inventory(&profile)?;
	let saved_output = request.output_identity;
	request.output_parent = &profile_path;
	request.output_identity = SyncGenesisNativeIdentity {
		device: profile_identity.device(),
		inode: NonZeroU64::new(profile_identity.inode()).unwrap(),
	};
	request.enrollment.expected_digest = approval::enrollment(&request, owner_profile);
	assert!(matches!(
		produce_managed_genesis(&request, &mut [0; 32]),
		Err(ManagedGenesisError::Output(
			SyncGenesisPublishError::PreSubmission {
				stage: None,
				cause: SyncProfileStoreError::OverlappingRoles,
				..
			}
		))
	));
	assert_eq!(evidence::inventory(&profile)?, profile_before);
	assert_eq!(evidence::inventory(&output)?, pristine);
	request.output_parent = &output_path;
	request.output_identity = saved_output;
	request.enrollment.expected_digest = approval::enrollment(&request, owner_profile);

	let occupied_operation = SyncGenesisOperation::new([0x62; 16]).unwrap();
	let incumbent = occupied_operation.final_name();
	sandbox.write_new(&output, &incumbent, b"preexisting final")?;
	let before = evidence::inventory(&output)?;
	request.operation = occupied_operation;
	assert_occupied(&request);
	assert_eq!(evidence::inventory(&output)?, before);
	request.operation = operation;

	let source_stamps =
		evidence::live_sources(sources, [&left_file, &right_file], [INITIAL, INITIAL])?;
	let published = produce_managed_genesis(&request, &mut [0; 32])?;
	let checked = Published::read(&output, &request, owner_profile, &published)?;
	assert_eq!(
		evidence::live_sources(sources, [&left_file, &right_file], [INITIAL, INITIAL])?,
		source_stamps
	);
	let after = evidence::inventory(&output)?;
	assert_occupied(&request);
	assert_eq!(evidence::inventory(&output)?, after);
	checked.recheck(&output)?;

	let claim = checked.frame(sandbox, anchor, &request, owner_profile, &source_stamps);
	let final_path = output_path.join(OsStr::from_bytes(&checked.final_name));
	let mut policy = ManagedPolicy {
		actor_uid: request.native.uid,
		actor_gid: request.native.gid,
		cooperation: ManagedCooperation {
			enrollment_id: ENROLLMENT,
		},
		parent_path: live_path.as_os_str().as_bytes().to_vec(),
		parent_locator: endpoints[0].parent,
		location,
		subject: SUBJECT.to_vec(),
		endpoints: std::array::from_fn(|index| ManagedPolicyEndpoint {
			endpoint: endpoints[index].endpoint,
			root: endpoints[index].root,
			name: ROOT_NAMES[index].to_vec(),
			object: facts[index],
			max_bytes: endpoints[index].max_bytes,
		}),
		history: ManagedPolicyHistory {
			path: final_path.as_os_str().as_bytes().to_vec(),
			directory: object(&checked.directory.metadata()?),
			revision: request.profile_revision,
			root: member(0, checked.refs[0]),
			children: std::array::from_fn(|index| member(index + 1, checked.refs[index + 1])),
			scan: Some(request.scan),
		},
	};
	let slot_id = [0xa1; 16];
	let slot = b"managed-sync-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1.v1";

	policy.history.root.name = b"missing-root.cbor".to_vec();
	assert!(
		matches!(initialize_managed_preview(preview_request(&profile_path, profile_identity, slot_id, &policy)),
		Err(ManagedSyncPreviewError::ReadHistory(error)) if error.kind() == std::io::ErrorKind::NotFound)
	);
	assert_missing(&profile, slot);
	assert_eq!(evidence::inventory(&output)?, after);
	policy.history.root.name = NAMES[0].to_vec();

	let selection = initialize_managed_preview(preview_request(
		&profile_path,
		profile_identity,
		slot_id,
		&policy,
	))?;
	sandbox.track_created_slot(&profile, slot)?;
	assert_eq!(
		preview_managed_history(&selection, &mut [0; 32])?.decision,
		SyncPathDecision::NoChange
	);
	{
		let _lease = writer(&directory)?;
		open_child(&right, SUBJECT, OFlags::WRONLY)?.write_all_at(CHANGED, 0)?;
	}
	let report = preview_managed_history(&selection, &mut [0; 32])?;
	assert_eq!(
		report.decision,
		SyncPathDecision::CopyCandidate {
			from: SyncSide::Right,
			target: SyncCopyTarget::ExistingIncumbent,
		}
	);
	for (observation, bytes) in report.observations.into_iter().zip([INITIAL, CHANGED]) {
		let exacopy_model::SyncObservation::Present(evidence) = observation else {
			return Err("expected two independently measured files".into());
		};
		assert_eq!(evidence.content_digest, *blake3::hash(bytes).as_bytes());
	}
	evidence::live_sources(sources, [&left_file, &right_file], [INITIAL, CHANGED])?;
	assert_eq!(read(&profile, b"owner.seed")?, SEED);
	assert_eq!(evidence::inventory(&output)?, after);
	checked.recheck(&output)?;
	checked.track(sandbox, &output)?;
	sandbox.allow_cleanup();
	Ok(claim)
}

fn writer(directory: &File) -> TestResult<File> {
	let handle = open_child(directory, b"live", OFlags::RDONLY | OFlags::DIRECTORY)?;
	fs::flock(&handle, FlockOperation::NonBlockingLockExclusive)?;
	Ok(handle)
}

fn record_id(label: u8) -> [u8; 16] {
	let mut bytes = [label; 16];
	bytes[6] = 0x70;
	bytes[8] = 0x80;
	bytes
}

fn member(
	index: usize,
	reference: exacopy_plan::workflow_sync::WorkflowRef,
) -> ManagedHistoryMember {
	ManagedHistoryMember {
		name: NAMES[index].to_vec(),
		reference,
	}
}

fn assert_occupied(request: &ManagedGenesisRequest<'_>) {
	assert!(matches!(
		produce_managed_genesis(request, &mut [0; 32]),
		Err(ManagedGenesisError::Output(
			SyncGenesisPublishError::PreSubmission {
				stage: None,
				cause: SyncProfileStoreError::AlreadyExists,
				..
			}
		))
	));
}

fn preview_request<'a>(
	profile: &'a std::path::Path,
	profile_identity: exacopy_platform::linux::FileIdentity,
	selection_id: [u8; 16],
	policy: &'a ManagedPolicy,
) -> ManagedSyncInit<'a> {
	ManagedSyncInit {
		profile,
		profile_identity,
		selection_id,
		selection_revision: NonZeroU64::new(7).unwrap(),
		policy,
	}
}
