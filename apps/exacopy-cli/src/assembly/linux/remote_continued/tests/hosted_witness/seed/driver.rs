//! Independently selected provisioning of one ordinary, fully covered capture.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;
use exacopy_journal::remote_download::qualification::{
	MAX_REMOTE_QUALIFICATION_BYTES, RemoteQualificationTrust,
	verify_remote_destination_qualification,
};
use exacopy_journal::remote_download::{
	MAX_REMOTE_CHECKPOINT_BYTES, RemoteDownloadDestination, RemoteDownloadDurability,
	RemoteDownloadRoute, RemoteDownloadScope, RemoteSourceObservation,
};
use exacopy_journal::{JournalEntryId, JournalJobId, OwnerTimestamp, OwnerToken, StreamLength};
use exacopy_platform::linux::{TargetStatus, observe_remote_destination};
use exacopy_platform::read_protected_snapshot_into;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::super::GRANT_DOMAIN;
use super::super::inputs::{Attestation, Route, component, decode, hex};
use super::{ExpectedSeed, capture_direct_seed};

use crate::assembly::linux::remote_download::{
	RemoteDestinationAttestation, RemoteDownloadRequest, RemoteGrant, RemoteJobAction,
	measure_running_executable,
};
use crate::assembly::linux::remote_journal::record_identity;
use crate::linux_path::open_destination;
use crate::profile::LocalProfile;
use crate::remote_frontdoor::{ApprovedRoute, GetRequest};

const REQUEST: &str = "EXACOPY_HOSTED_WITNESS_SEED_REQUEST";
const REQUEST_BLAKE3: &str = "EXACOPY_HOSTED_WITNESS_SEED_REQUEST_BLAKE3";
const BUILD_BLAKE3: &str = "EXACOPY_HOSTED_WITNESS_BUILD_BLAKE3";
const RESULT: &str = "EXACOPY_HOSTED_WITNESS_SEED";
const MAX_REQUEST_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
	schema_version: u32,
	route: Route,
	allow_seed_capture: bool,
	destination_root: PathBuf,
	owner_profile: PathBuf,
	owner_key: String,
	ssh_profile: PathBuf,
	target: String,
	source_operand: String,
	source_blake3: String,
	source_extent: u64,
	source_mode: u32,
	source_modified: u32,
	job_id: String,
	entry_id: String,
	owner_token: String,
	scope_blake3: String,
	grant_digest: String,
	grant_expires_unix: u64,
	v1_blake3: String,
	v1: Attestation,
}

#[derive(Clone, Copy)]
enum Refusal {
	Missing,
	Selection,
	Build,
	Substrate,
	Qualification,
	Capture,
}

impl Refusal {
	const fn reason(self) -> &'static str {
		match self {
			Self::Missing => "missing_authority",
			Self::Selection => "seed_selection_refused",
			Self::Build => "build_refused",
			Self::Substrate => "unsupported_substrate",
			Self::Qualification => "v1_qualification_refused",
			Self::Capture => "capture_or_reconciliation_required",
		}
	}
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a protected independently approved Linux seed request"]
async fn prepares_reviewed_held_remote_seed() {
	match provision().await {
		Ok(report) => println!("\n{RESULT} {report}"),
		Err(refusal) => {
			let failed = matches!(refusal, Refusal::Capture);
			let outcome = if failed { "failed" } else { "blocked" };
			let report = json!({
				"schema_version": 1,
				"outcome": outcome,
				"reason": refusal.reason(),
			});
			println!("\n{RESULT} {report}");
			assert!(!failed, "hosted witness seed requires reconciliation");
		}
	}
}

impl Request {
	fn load() -> Result<(Self, [u8; 32], [u8; 32]), Refusal> {
		let path = std::env::var_os(REQUEST).ok_or(Refusal::Missing)?;
		let expected = selected(REQUEST_BLAKE3)?;
		let build = selected(BUILD_BLAKE3)?;
		let bytes =
			protected::<MAX_REQUEST_BYTES>(Path::new(&path)).map_err(|()| Refusal::Selection)?;
		if *blake3::hash(&bytes).as_bytes() != expected {
			return Err(Refusal::Selection);
		}
		let request: Self = serde_json::from_slice(&bytes).map_err(|_| Refusal::Selection)?;
		if request.schema_version != 1
			|| !matches!(request.route, Route::DirectTcpV1)
			|| !request.allow_seed_capture
			|| !request.destination_root.is_absolute()
			|| !request.owner_profile.is_absolute()
			|| !request.ssh_profile.is_absolute()
			|| !request.target.is_ascii()
			|| request.target.starts_with(".exacopy-")
			|| !(1..=MAX_REMOTE_CHECKPOINT_BYTES).contains(&request.source_extent)
		{
			return Err(Refusal::Selection);
		}
		Ok((request, expected, build))
	}

	fn identity(
		&self,
		wall: Duration,
	) -> Result<(JournalJobId, JournalEntryId, RemoteJobAction), Refusal> {
		let uuid = Uuid::parse_str(&self.job_id).map_err(|_| Refusal::Selection)?;
		if uuid.to_string() != self.job_id {
			return Err(Refusal::Selection);
		}
		let job = JournalJobId::from_bytes(uuid.into_bytes()).map_err(|_| Refusal::Selection)?;
		let entry = decode::<16>(&self.entry_id).map_err(|_| Refusal::Selection)?;
		let token = decode::<16>(&self.owner_token).map_err(|_| Refusal::Selection)?;
		if entry == token || &entry == job.as_bytes() || &token == job.as_bytes() {
			return Err(Refusal::Selection);
		}
		let entry = JournalEntryId::from_bytes(entry);
		let token = OwnerToken::from_bytes(token).map_err(|_| Refusal::Selection)?;
		let seconds = i64::try_from(wall.as_secs()).map_err(|_| Refusal::Selection)?;
		let created =
			OwnerTimestamp::new(seconds, wall.subsec_nanos()).map_err(|_| Refusal::Selection)?;
		Ok((job, entry, RemoteJobAction::Create { token, created }))
	}
}

fn selected(name: &str) -> Result<[u8; 32], Refusal> {
	let value = std::env::var(name).map_err(|_| Refusal::Missing)?;
	decode(&value).map_err(|_| Refusal::Selection)
}

fn protected<const LIMIT: usize>(path: &Path) -> Result<Vec<u8>, ()> {
	if !path.is_absolute() {
		return Err(());
	}
	let mut bytes = vec![0; LIMIT];
	let mut readback = [0; 1024];
	let length = read_protected_snapshot_into(path, &mut bytes, &mut readback).map_err(|_| ())?;
	bytes.truncate(length);
	Ok(bytes)
}

async fn provision() -> Result<Value, Refusal> {
	let (request, request_digest, build) = Request::load()?;
	if measure_running_executable().map_err(|_| Refusal::Build)? != build {
		return Err(Refusal::Build);
	}
	let root = open_destination(&request.destination_root).map_err(|_| Refusal::Substrate)?;
	let profile = LocalProfile::open(&request.owner_profile).map_err(|_| Refusal::Selection)?;
	let owner_key = profile.verification_key();
	if owner_key.is_weak()
		|| owner_key.to_bytes() != decode(&request.owner_key).map_err(|_| Refusal::Selection)?
	{
		return Err(Refusal::Selection);
	}
	let target = component(request.target.as_bytes()).map_err(|_| Refusal::Selection)?;
	if root.target_status(target).map_err(|_| Refusal::Substrate)? != TargetStatus::Absent {
		return Err(Refusal::Selection);
	}
	let frontdoor = GetRequest::new(
		OsStr::new(&request.source_operand),
		request.destination_root.join(&request.target),
		request.owner_profile.clone(),
		request.ssh_profile.clone(),
		Some(SftpDataOnlyV1::NAME),
	)
	.map_err(|_| Refusal::Selection)?;
	let ssh = frontdoor.load_profile().map_err(|_| Refusal::Selection)?;
	let ApprovedRoute::Direct(endpoint) = &ssh.route else {
		return Err(Refusal::Selection);
	};
	let source = frontdoor
		.signed_source(
			&ssh,
			RemoteDownloadRoute::ResolvedDirect {
				endpoint: *endpoint,
			},
		)
		.map_err(|_| Refusal::Selection)?;
	let clock = Instant::now();
	let wall = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(|_| Refusal::Selection)?;
	let (job, entry, action) = request.identity(wall)?;
	let destination = RemoteDownloadDestination::new(
		profile
			.root_id(root.identity())
			.map_err(|_| Refusal::Selection)?,
		record_identity(root.identity()),
		target,
	);
	let scope = RemoteDownloadScope::new(
		entry,
		source,
		destination,
		StreamLength::new(ssh.maximum_extent).map_err(|_| Refusal::Selection)?,
		SftpDataOnlyV1::digest(),
		RemoteDownloadDurability::ProcessCrash,
	)
	.map_err(|_| Refusal::Selection)?;
	let digest = scope.digest().map_err(|_| Refusal::Selection)?;
	let grant_digest = blake3::derive_key(GRANT_DOMAIN, digest.as_bytes());
	if *digest.as_bytes() != decode(&request.scope_blake3).map_err(|_| Refusal::Selection)?
		|| grant_digest != decode(&request.grant_digest).map_err(|_| Refusal::Selection)?
		|| request.source_extent > scope.maximum_extent.get()
	{
		return Err(Refusal::Selection);
	}
	let remaining = Duration::from_secs(request.grant_expires_unix)
		.checked_sub(wall)
		.filter(|value| !value.is_zero() && *value <= ssh.grant_duration)
		.ok_or(Refusal::Selection)?;
	let deadline = clock.checked_add(remaining).ok_or(Refusal::Selection)?;
	let grant =
		Arc::new(RemoteGrant::new(digest, grant_digest, deadline).ok_or(Refusal::Selection)?);
	let expected_v1 = decode(&request.v1_blake3).map_err(|_| Refusal::Selection)?;
	let v1_key = request.v1.key().map_err(|_| Refusal::Qualification)?;
	let v1_scope = request
		.v1
		.scope(request.route, build)
		.map_err(|_| Refusal::Qualification)?;
	let v1_attestor = decode(&request.v1.attestor).map_err(|_| Refusal::Qualification)?;
	let v1_record = protected::<MAX_REMOTE_QUALIFICATION_BYTES>(&request.v1.record)
		.map_err(|()| Refusal::Qualification)?;
	let facts = observe_remote_destination(&root).map_err(|_| Refusal::Substrate)?;
	let selected_v1 = verify_remote_destination_qualification(
		&v1_record,
		&RemoteQualificationTrust {
			attestor: v1_attestor,
			attestor_key: &v1_key,
			owner_key: &owner_key,
			scope: v1_scope,
		},
		&facts,
	)
	.map_err(|_| Refusal::Qualification)?;
	if selected_v1.digest() != expected_v1 {
		return Err(Refusal::Qualification);
	}
	let length = StreamLength::new(request.source_extent).map_err(|_| Refusal::Selection)?;
	let source = RemoteSourceObservation::new(length, request.source_mode, request.source_modified)
		.map_err(|_| Refusal::Selection)?;
	let captured = capture_direct_seed(
		&RemoteDownloadRequest {
			root: &root,
			profile: &frontdoor.owner_profile,
			job,
			action,
			scope: &scope,
			metadata: frontdoor.metadata,
			grant: &grant,
			qualification: RemoteDestinationAttestation {
				record: &v1_record,
				attestor: v1_attestor,
				key: &v1_key,
				scope: v1_scope,
			},
		},
		&ssh,
		&grant,
		ExpectedSeed {
			source,
			digest: decode(&request.source_blake3).map_err(|_| Refusal::Selection)?,
		},
	)
	.await;
	grant.revoke();
	let evidence = captured.map_err(|_| Refusal::Capture)?;
	if evidence.original_qualification != expected_v1 {
		return Err(Refusal::Capture);
	}

	Ok(json!({
		"schema_version": 1,
		"outcome": "passed",
		"route": request.route.name(),
		"request_blake3": hex(request_digest),
		"build_blake3": hex(build),
		"job_id": request.job_id,
		"stage": evidence.stage,
		"scope_blake3": hex(*digest.as_bytes()),
		"grant_digest": hex(grant_digest),
		"initial_v1_qualification": hex(evidence.original_qualification),
		"source_blake3": hex(evidence.source_digest),
		"source_extent": request.source_extent,
		"prior_head_blake3": hex(evidence.boundary.head.digest()),
		"prior_sequence": evidence.boundary.head.sequence(),
		"prior_offset": evidence.boundary.offset,
		"terminal_kind": 3,
		"public_target": "absent",
		"legacy_receipt": "absent",
		"route_drained": true,
	}))
}
