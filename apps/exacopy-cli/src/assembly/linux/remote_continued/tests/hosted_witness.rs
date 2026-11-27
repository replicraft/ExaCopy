use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use exacopy_endpoint::ReadView;
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::remote_source::{SftpPath, SftpPathRoot, SourceEpoch};
use exacopy_journal::frame::FrameKind;
use exacopy_journal::remote_download::continuation::{
	PriorPreparation, RemoteContinuationClaims, RemoteContinuationCoverage,
	RemoteContinuationExpectation, RemoteContinuationPrior,
};
use exacopy_journal::remote_download::finalization_replay::replay_remote_finalization_with_checkpoints;
use exacopy_journal::remote_download::qualification::continuation::{
	RemoteContinuationCoverageProfile, RemoteContinuationOperationProfile,
	RemoteContinuationQualificationScope, RemoteContinuationQualificationTrust,
	verify_remote_witness_qualification,
};
use exacopy_journal::remote_download::qualification::{
	RemoteQualificationTrust, verify_remote_destination_qualification,
};
use exacopy_journal::remote_download::witness::replay::{
	RemoteWitnessedReplayPhase, RemoteWitnessedReplaySelection, replay_remote_witnessed_closeout,
};
use exacopy_journal::remote_download::witness::witnessed_receipt_names;
use exacopy_journal::remote_download::{
	MAX_REMOTE_DOWNLOAD_OWNER_BYTES, RemoteDownloadRoute, RemoteEpochs, RemoteSourceObservation,
};
use exacopy_journal::{MAX_FIRST_SEGMENT_BYTES, StreamDigest, StreamLength};
use exacopy_platform::linux::{
	RemoteDestinationEligibility, RetainedPrefixSelection, TargetStatus, observe_remote_destination,
};
use exacopy_sftp::{PendingSftpPathRequest, open_pending_path_source};
use exacopy_transfer::remote_resume::prefix::verify_held_retained_prefix;
use serde_json::json;

use super::super::witness::{WitnessPass, WitnessPrefix, zero_tail::ZeroTailWitness};
use crate::assembly::linux::remote_download::{
	AttemptAdmission, ConnectedRemoteSource, RemoteGrant, SourceInvocation,
	measure_running_executable,
};
use crate::assembly::linux::remote_witness_authority::{
	BoundWitnessStage, ExplicitWitnessSelection, SelectedWitnessOwner, WitnessRetentionApproval,
};
use crate::linux_path::open_destination;
use crate::profile::LocalProfile;
use crate::remote_frontdoor::{ApprovedRoute, SshProfile};

mod facts;
mod inputs;
mod preflight;
mod seed;

use inputs::{
	Request, Route, Stop, Strategy, artifact, component, decode, hex, no_receipt, protected,
};
use preflight::{witness_projection, zero_tail_budget};

const RESULT: &str = "EXACOPY_HOSTED_WITNESS_RESULT";
const GRANT_DOMAIN: &str = "ExaCopy Linux remote foreground grant binding v1";
const WINDOW_BYTES: usize = 128 * 1024;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires independently approved hosted inputs and exact held Linux qualification"]
async fn witnesses_reviewed_held_remote_zero_tail() {
	if facts::requested() {
		match facts::report() {
			Ok(facts) => println!("\nEXACOPY_HOSTED_WITNESS_FACTS {facts}"),
			Err(reason) => println!(
				"\nEXACOPY_HOSTED_WITNESS_FACTS {}",
				json!({"status": "blocked", "reason": reason})
			),
		}
		return;
	}
	let outcome = hosted_pass().await;
	match outcome {
		Ok(report) => println!("\n{RESULT} {report}"),
		Err(stop) => {
			let (outcome, phase, reason) = stop.report();
			let mut report =
				json!({"schema_version": 1, "outcome": outcome, "phase": phase, "reason": reason});
			if let Stop::Op2Qualification {
				digest,
				request_blake3,
			} = stop
			{
				report["qualification_blake3"] = json!(hex(digest));
				report["request_blake3"] = json!(hex(request_blake3));
			}
			println!("\n{RESULT} {report}");
			assert_ne!(outcome, "failed", "held witness fixture failed at {phase}");
		}
	}
}

async fn hosted_pass() -> Result<serde_json::Value, Stop> {
	let (request, refusal, request_blake3) = Request::load()?;
	let build = measure_running_executable().map_err(|_| Stop::Substrate)?;
	let root = open_destination(&request.destination_root).map_err(|_| Stop::Substrate)?;
	let facts = observe_remote_destination(&root).map_err(|_| Stop::Substrate)?;
	let profile = LocalProfile::open(&request.owner_profile).map_err(|_| Stop::Request)?;
	let owner_key = profile.verification_key();
	let v1_key = request.v1.key()?;
	let op2_key = request.op2.key()?;
	let v1 = verify_remote_destination_qualification(
		&protected(&request.v1.record)?,
		&RemoteQualificationTrust {
			attestor: decode(&request.v1.attestor)?,
			attestor_key: &v1_key,
			owner_key: &owner_key,
			scope: request.v1.scope(request.route, build)?,
		},
		&facts,
	)
	.map_err(|_| Stop::Qualification)?;
	let (op2_record, op2_digest) = request.op2.selected_witness_record()?;
	let op2_refused = || Stop::Op2Qualification {
		digest: op2_digest,
		request_blake3,
	};
	let verified = verify_remote_witness_qualification(
		&op2_record,
		&RemoteContinuationQualificationTrust {
			attestor: decode(&request.op2.attestor)?,
			attestor_key: &op2_key,
			owner_key: &owner_key,
			scope: RemoteContinuationQualificationScope {
				common: request.op2.scope(request.route, build)?,
				operation: RemoteContinuationOperationProfile::VerifiedRetainedAppendWithWitnessV1,
				coverage:
					RemoteContinuationCoverageProfile::RetainedAppendWithWitnessProcessCrashV1,
			},
		},
	)
	.map_err(|_| op2_refused())?;
	let current = verified
		.match_current(build, &facts)
		.map_err(|_| op2_refused())?;
	if *verified.digest().as_bytes() != op2_digest || refusal {
		return Err(Stop::Request);
	}
	let op2_native = witness_projection(&current).ok_or_else(op2_refused)?;
	let eligibility =
		RemoteDestinationEligibility::admit(&root, Some(&op2_native)).map_err(|_| op2_refused())?;
	let id = uuid::Uuid::parse_str(&request.job_id).map_err(|_| Stop::Request)?;
	if id.hyphenated().to_string() != request.job_id {
		return Err(Stop::Request);
	}
	let job_name = format!(".exacopy-{id}");
	let name = component(job_name.as_bytes())?;
	let target = component(request.target.as_bytes())?;
	let stage = component(request.stage.as_bytes())?;
	let job = root.open_recovery_job(name).map_err(|_| Stop::Prefix)?;
	let lease = root
		.try_recovery_write_lease(name, job.identity())
		.map_err(|_| Stop::Prefix)?;
	let job = lease.job();
	let owner_file = job.open_owner().map_err(|_| Stop::Prefix)?;
	let owner_bytes = artifact(&owner_file, MAX_REMOTE_DOWNLOAD_OWNER_BYTES as u64)?;
	let dialect = request.route.dialect(&request.path_root);
	let owner = dialect
		.decode(&owner_bytes, profile.id(), &owner_key)
		.map_err(|_| Stop::Prefix)?;
	let manifest = owner.manifest();
	let scope = &manifest.scope;
	let scope_digest = scope.digest().map_err(|_| Stop::Prefix)?;
	let grant_digest = decode(&request.grant_digest)?;
	if manifest.job.as_bytes() != id.as_bytes()
		|| scope.destination.target() != target.as_bytes()
		|| scope.source.path_root() != request.path_root.native()
		|| scope.destination.root()
			!= profile
				.root_id(root.identity())
				.map_err(|_| Stop::Request)?
		|| scope_digest.as_bytes() != &decode::<32>(&request.scope_blake3)?
		|| grant_digest != blake3::derive_key(GRANT_DOMAIN, scope_digest.as_bytes())
		|| !no_receipt(job.open_receipt())
	{
		return Err(Stop::Request);
	}
	let ssh = SshProfile::load(&request.ssh_profile).map_err(|_| Stop::Request)?;
	let direct = matches!(
		(request.route, &ssh.route, scope.source.route()),
		(
			Route::DirectTcpV1,
			ApprovedRoute::Direct(_),
			RemoteDownloadRoute::ResolvedDirect { .. }
		)
	);
	let embedded = matches!(
		(request.route, scope.source.route()),
		(
			Route::EmbeddedWireguardTcpV1,
			RemoteDownloadRoute::EmbeddedWireGuard { .. }
		)
	);
	if !direct && !embedded {
		return Err(Stop::Route);
	}
	let wall = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(|_| Stop::Request)?;
	let approved = Duration::from_secs(request.approval_expires_unix)
		.checked_sub(wall)
		.filter(|duration| !duration.is_zero() && *duration <= ssh.grant_duration)
		.ok_or(Stop::Request)?;
	let deadline = Instant::now().checked_add(approved).ok_or(Stop::Request)?;
	let grant =
		Arc::new(RemoteGrant::new(scope_digest, grant_digest, deadline).ok_or(Stop::Request)?);
	let trust = dialect
		.trust(&owner, profile.id(), &owner_key)
		.map_err(|_| Stop::Prefix)?;
	let selection = RemoteWitnessedReplaySelection {
		initial_v1_qualification: decode(&request.initial_v1_qualification)?,
		fresh_v1_qualification: v1.digest(),
		qualification: &verified,
		grant_digest,
	};
	let segment = job.open_first_segment().map_err(|_| Stop::Prefix)?;
	let before = artifact(&segment, MAX_FIRST_SEGMENT_BYTES)?;
	let replay = replay_remote_finalization_with_checkpoints(
		before.as_slice(),
		&trust,
		selection.initial_v1_qualification,
		None,
	)
	.map_err(|_| Stop::Prefix)?;
	let checkpoints = replay.active_checkpoints().map_err(|_| Stop::Prefix)?;
	let history = checkpoints.prefix_history().map_err(|_| Stop::Prefix)?;
	let prior = history.boundary();
	let prepared = history.prepared();
	let extent = StreamLength::new(request.source_extent).map_err(|_| Stop::Request)?;
	if prior.offset != segment.len()
		|| prior.head.digest() != decode(&request.prior_head_blake3)?
		|| history.name() != stage.as_bytes()
		|| history.covered_extent() != extent.get()
		|| history.source().length() != extent
		|| history.active() != PriorPreparation::Original(prepared.head)
	{
		return Err(Stop::Prefix);
	}
	let bootstrap = replay
		.stage_directory_prepared()
		.ok_or(Stop::Prefix)?
		.head();
	let selected = RetainedPrefixSelection {
		stage,
		target,
		directory: JobFileIdentity {
			device: prepared.directory.device(),
			inode: prepared.directory.inode(),
		},
		file: JobFileIdentity {
			device: prepared.file.device(),
			inode: prepared.file.inode(),
		},
	};
	let inventory = job.inventory(stage, target).map_err(|_| Stop::Prefix)?;
	let reader = lease
		.read_retained_prefix(&inventory, selected)
		.map_err(|_| Stop::Prefix)?;
	let names = BoundWitnessStage {
		context: history.context(),
		scope: scope_digest,
		job: manifest.job_directory,
		retained: selected,
		adopted_extent: extent.get(),
		source_extent: extent.get(),
	};
	let budget = zero_tail_budget(&replay, extent).ok_or(Stop::Prefix)?;
	let explicit = ExplicitWitnessSelection::select(
		matches!(request.strategy, Strategy::VerifiedPrefix),
		request.allow_witness_retention,
	)
	.ok_or(Stop::Request)?;
	let approval = WitnessRetentionApproval::admit(
		explicit,
		SelectedWitnessOwner {
			owner: &owner,
			approved_scope: scope,
		},
		&lease,
		&reader,
		names,
		&grant,
		grant_digest,
	)
	.map_err(|_| Stop::Request)?;
	let run = NonZeroU64::from(budget.new_run());
	let (pending, final_receipt) =
		witnessed_receipt_names(history.context().entry, run, *checkpoints.nonce());
	let receipt_names = [component(&pending)?, component(&final_receipt)?];
	lease
		.require_job_root_names_absent(receipt_names)
		.map_err(|_| Stop::Prefix)?;
	let new_source = history
		.epochs()
		.source
		.get()
		.checked_add(1)
		.and_then(NonZeroU64::new)
		.ok_or(Stop::Prefix)?;
	let pass = WitnessPass {
		trust: &trust,
		selection: &selection,
		current: &current,
		signer: profile.signer(),
		budget,
		approval: &approval,
		grant: &grant,
		names,
	};
	let expected_source = decode(&request.source_blake3)?;
	let claims = RemoteContinuationClaims {
		context: history.context(),
		scope: scope_digest,
		previous: prior,
		prior: RemoteContinuationPrior {
			bootstrap,
			allocation: checkpoints.allocation(),
			prepared: prepared.head,
			active: history.active(),
			epochs: history.epochs(),
			name: stage,
			nonce: *checkpoints.nonce(),
		},
		directory: prepared.directory,
		stage: prepared.file,
		coverage: RemoteContinuationCoverage {
			basis: history.coverage_basis(),
			end: extent,
		},
		epochs: RemoteEpochs {
			run,
			source: new_source,
		},
		source: history.source(),
		adopted_end: extent,
		prefix_digest: StreamDigest::from_bytes(expected_source),
		grant_digest,
		qualification_digest: *verified.digest().as_bytes(),
	};
	let expected = RemoteContinuationExpectation {
		claims,
		prior_source_extent: extent,
	};
	let invocation = SourceInvocation::new(scope, &grant).map_err(|_| Stop::Prefix)?;
	let connecting = invocation.claim().map_err(|_| Stop::Prefix)?;
	let consume = async |connected: ConnectedRemoteSource<'_>| {
		let (mut session, mut route) = connected
			.into_current(scope_digest, &grant)
			.map_err(|_| Stop::Prefix)?;
		let raw = scope.source.path();
		let components = raw
			.strip_prefix(b"/")
			.unwrap_or(raw)
			.split(|byte| *byte == b'/')
			.map(component)
			.collect::<Result<Vec<_>, _>>()?;
		let path = match scope.source.path_root() {
			SftpPathRoot::AccountRelative => SftpPath::AccountRelative(&components),
			SftpPathRoot::Absolute => SftpPath::Absolute(&components),
		};
		let epoch = SourceEpoch::new(new_source);
		let pending = open_pending_path_source(
			&mut session,
			PendingSftpPathRequest {
				path,
				attempt: route.attempt(),
				epoch,
			},
			&mut route,
		)
		.await
		.map_err(|_| Stop::Prefix)?;
		let observed = pending.observation();
		let observed = RemoteSourceObservation::new(
			StreamLength::new(observed.length).map_err(|_| Stop::Prefix)?,
			observed.mode,
			observed.modified,
		)
		.map_err(|_| Stop::Prefix)?;
		if observed != claims.source {
			return Err(Stop::Prefix);
		}
		let binding = route.admit_pending(&pending).map_err(|_| Stop::Prefix)?;
		let retirement = route
			.prepare_retirement(binding)
			.map_err(|_| Stop::Prefix)?;
		let mut source = pending
			.activate(binding, |binding| route.check_binding(binding))
			.map_err(|_| Stop::Prefix)?;
		let mut scratch = vec![0; WINDOW_BYTES];
		let proof = verify_held_retained_prefix(
			&history,
			&mut source,
			epoch,
			WitnessPrefix(reader),
			&mut scratch,
		)
		.await
		.map_err(|_| Stop::Prefix)?;
		if proof.prefix().extent() != extent.get() || proof.prefix().digest() != expected_source {
			return Err(Stop::Prefix);
		}
		pass.run_zero_tail(
			proof,
			ZeroTailWitness {
				lease: &lease,
				eligibility: &eligibility,
				segment: &segment,
				expected: &expected,
				retirement,
				scratch: &mut scratch,
			},
			|result| {
				result
					.chain
					.stage()
					.recheck_observation()
					.map_err(|_| Stop::Closeout)?;
				if result.digest != expected_source {
					return Err(Stop::Closeout);
				}
				Ok(result.intent)
			},
		)
		.await
		.map_err(|_| Stop::Closeout)?
	};
	let intent = if direct {
		let connected = connecting
			.connect_direct(&ssh, &AttemptAdmission::Initial(None))
			.await
			.map_err(|_| Stop::Prefix)?;
		consume(connected).await?
	} else {
		#[cfg(feature = "experimental-ssh-wireguard")]
		{
			let scoped = connecting
				.with_embedded(
					&ssh,
					AttemptAdmission::Initial(None),
					|| false,
					async |connected, _| consume(connected).await,
				)
				.await
				.map_err(|_| Stop::Prefix)?;
			let intent = scoped.outcome?;
			scoped.retirement.map_err(|_| Stop::Closeout)?;
			intent
		}
		#[cfg(not(feature = "experimental-ssh-wireguard"))]
		{
			return Err(Stop::Route);
		}
	};
	let final_segment = job.open_first_segment().map_err(|_| Stop::Closeout)?;
	let bytes = artifact(&final_segment, MAX_FIRST_SEGMENT_BYTES).map_err(|_| Stop::Closeout)?;
	if final_segment.identity() != segment.identity() || !bytes.starts_with(&before) {
		return Err(Stop::Closeout);
	}
	let final_replay = replay_remote_witnessed_closeout(bytes.as_slice(), &trust, &selection)
		.map_err(|_| Stop::Closeout)?;
	if final_replay.issue().is_some()
		|| final_replay.boundary() != intent.boundary()
		|| prior.head.sequence().checked_add(2) != Some(intent.boundary().head.sequence())
		|| final_replay.boundary().offset != final_segment.len()
		|| final_replay.phase() != RemoteWitnessedReplayPhase::WitnessIntentRequiresInspection
		|| final_replay.witness() != Some(intent)
		|| !matches!(root.target_status(target), Ok(TargetStatus::Absent))
		|| !no_receipt(job.open_receipt())
	{
		return Err(Stop::Closeout);
	}
	lease
		.require_job_root_names_absent(receipt_names)
		.map_err(|_| Stop::Closeout)?;
	Ok(json!({
		"schema_version": 1, "outcome": "passed", "phase": "witness_closeout",
		"route": request.route.name(), "build_blake3": hex(build),
		"qualification_blake3": hex(op2_digest), "request_blake3": hex(request_blake3),
		"retention_approval_blake3": hex(intent.consent().approval_digest),
		"source_blake3": hex(expected_source), "prior_head_blake3": hex(prior.head.digest()),
		"terminal_head_blake3": hex(intent.boundary().head.digest()),
		"operation": 2, "coverage": 2, "authority_scope": "fixture_only", "journal_terminal_kind": FrameKind::RemoteWitnessIntent.code(),
		"same_inode_links": 2, "public_target_absent": true, "receipt_absent": true,
	}))
}
