//! Exact observer expectations retained independently of the published slots.

use std::fs::File;
use std::num::{NonZeroU16, NonZeroU64};
use std::os::unix::fs::MetadataExt as _;

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_cli::assembly::linux::managed_sync::genesis::recovery_observation::{
	ManagedGenesisRecoveryBasis, observe_managed_genesis_recovery,
};
use exacopy_cli::assembly::linux::managed_sync::genesis::{
	ManagedGenesisPublished, ManagedGenesisRequest,
};
use exacopy_manifest::sync_baseline::{Identity, LinuxOwnerMode, Observation, SideEvidence};
use exacopy_plan::workflow_sync::{
	LinuxStability, WorkflowKind, WorkflowTimestamp, linux_stability_digest, native_id,
	project_pair,
};
use exacopy_platform::linux::{
	SyncGenesisIntent, SyncGenesisMemberBinding, SyncGenesisNativeIdentity,
	SyncGenesisRecoveryDisposition as State, SyncGenesisRecoveryIssue as Issue,
	SyncProfileStoreError,
};
use exacopy_transfer::sync_genesis::{
	ExpectedSyncGenesis, SyncGenesisSelection, assemble_sync_genesis,
};

use super::{INITIAL, TestResult, approval, rig};

pub(super) fn select_intent(
	request: &ManagedGenesisRequest<'_>,
	profile: [u8; 16],
	signer: &SigningKey,
	files: [&File; 2],
) -> TestResult<SyncGenesisIntent> {
	let owner = signer.verifying_key();
	let selection = SyncGenesisSelection {
		profile,
		revision: request.profile_revision,
		owner: &owner,
		subject: request.native.subject,
		endpoints: request.endpoints,
		scan: request.scan,
	};
	let pair = project_pair(
		selection.profile,
		selection.revision,
		selection.subject,
		selection.endpoints,
	)?;
	let [left, right] = files;
	let [left_root, right_root] = pair.roots;
	// The caller independently read these held streams and checked their names and stat
	// facts before construction. The fixture has no concurrent mutators.
	let sides = [
		fixture_side(left, left_root, request.native.boot, 1)?,
		fixture_side(right, right_root, request.native.boot, 2)?,
	];
	let prepared = assemble_sync_genesis(selection, request.records, sides, signer)?;
	let bind = |kind, bytes: &[u8], canonical_digest| -> TestResult<SyncGenesisMemberBinding> {
		Ok(SyncGenesisMemberBinding {
			kind: kind as u16,
			byte_len: NonZeroU16::try_from(u16::try_from(bytes.len())?)?,
			canonical_digest,
			raw_digest: *blake3::hash(bytes).as_bytes(),
		})
	};
	let [left, right, leaf] = prepared.members();
	let root = prepared.root_digest();
	Ok(SyncGenesisIntent {
		operation: request.operation,
		output: request.output_identity,
		approval: approval::intent(request, profile, root),
		members: [
			bind(WorkflowKind::Root, prepared.root_bytes(), root)?,
			bind(left.1.kind, left.0, left.1.digest)?,
			bind(right.1.kind, right.0, right.1.digest)?,
			bind(leaf.1.kind, leaf.0, leaf.1.digest)?,
		],
	})
}

fn fixture_side(
	file: &File,
	root: [u8; 32],
	boot: [u8; 16],
	position: u64,
) -> TestResult<SideEvidence> {
	let stat = file.metadata()?;
	assert_eq!(stat.size(), u64::try_from(INITIAL.len())?);
	let identity = Identity {
		root,
		file: native_id(boot, rig::object(&stat)),
	};
	let metadata = LinuxOwnerMode {
		mode: u16::try_from(stat.mode() & 0o777)?,
		uid: stat.uid(),
		gid: stat.gid(),
	};
	let measured = Observation {
		identity,
		position: NonZeroU64::try_from(position)?,
		stability: linux_stability_digest(LinuxStability {
			file: identity.file,
			length: stat.size(),
			mode: stat.mode(),
			uid: stat.uid(),
			gid: stat.gid(),
			links: stat.nlink(),
			modified: WorkflowTimestamp::new(stat.mtime(), stat.mtime_nsec().try_into()?)?,
			changed: WorkflowTimestamp::new(stat.ctime(), stat.ctime_nsec().try_into()?)?,
		}),
	};
	Ok(SideEvidence {
		measured,
		rechecked: Observation {
			position: NonZeroU64::new(3).unwrap(),
			..measured
		},
		length: stat.size(),
		stream_digest: *blake3::hash(INITIAL).as_bytes(),
		metadata,
		metadata_digest: metadata.digest()?,
	})
}

pub(super) fn assert_exact_final(
	request: &ManagedGenesisRequest<'_>,
	intent: &SyncGenesisIntent,
	profile: [u8; 16],
	owner: &VerifyingKey,
	published: &ManagedGenesisPublished,
) -> TestResult {
	// The acknowledged publication identifies its original stage independently of the
	// retained intent and directory being observed. This is a positive control.
	let original = published.publication.identity;
	let stage = SyncGenesisNativeIdentity {
		device: original.device(),
		inode: NonZeroU64::try_from(original.inode())?,
	};
	let history = ExpectedSyncGenesis {
		root_digest: intent.members[0].canonical_digest,
		profile,
		revision: request.profile_revision,
		owner,
		subject: request.native.subject,
		endpoints: request.endpoints,
		scan: Some(request.scan),
	};
	let basis = ManagedGenesisRecoveryBasis {
		intent,
		stage,
		history: &history,
	};
	let observe = |basis| {
		observe_managed_genesis_recovery(
			request.output_parent,
			request.output_identity,
			request.operation,
			Some(basis),
		)
	};
	let verified = observe(basis)?;
	assert!(matches!(verified.disposition, State::FinalBytesObserved));
	assert_eq!(verified.slots.published, Some(original));
	assert_eq!(verified.slots.stage, None);
	assert!(verified.slots.intent.is_some());

	let foreign_stage = SyncGenesisNativeIdentity {
		inode: NonZeroU64::try_from(request.profile_identity.inode())?,
		..stage
	};
	assert!(matches!(
		observe(ManagedGenesisRecoveryBasis {
			stage: foreign_stage,
			..basis
		})?
		.disposition,
		State::Unresolved(Issue::OriginalStageMismatch)
	));

	let mut foreign_intent = *intent;
	foreign_intent.approval[0] ^= 1;
	assert!(matches!(
		observe(ManagedGenesisRecoveryBasis {
			intent: &foreign_intent,
			..basis
		})?
		.disposition,
		State::Unresolved(Issue::Native(SyncProfileStoreError::Changed))
	));

	let mut foreign_session = history;
	for endpoint in &mut foreign_session.endpoints {
		endpoint.location.boot[0] ^= 1;
	}
	assert!(matches!(
		observe(ManagedGenesisRecoveryBasis {
			history: &foreign_session,
			..basis
		})?
		.disposition,
		State::Unresolved(Issue::Session)
	));

	let mut rejected_history = history;
	rejected_history.scan = Some(NonZeroU64::new(request.scan.get() ^ 1).unwrap());
	assert!(matches!(
		observe(ManagedGenesisRecoveryBasis {
			history: &rejected_history,
			..basis
		})?
		.disposition,
		State::Unresolved(Issue::Closure(_))
	));

	let mut missing_scan = history;
	missing_scan.scan = None;
	assert!(matches!(
		observe(ManagedGenesisRecoveryBasis {
			history: &missing_scan,
			..basis
		}),
		Err(SyncProfileStoreError::InvalidSelection)
	));
	Ok(())
}
