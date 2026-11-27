use std::path::Path;

use exacopy_journal::remote_download::qualification::MAX_REMOTE_QUALIFICATION_BYTES;
use exacopy_journal::remote_download::qualification::continuation::{
	RemoteContinuationCoverageProfile, RemoteContinuationOperationProfile,
	RemoteContinuationQualificationScope, RemoteContinuationQualificationTrust,
	VerifiedRemoteWitnessQualification, verify_remote_witness_qualification,
};
use exacopy_journal::remote_download::{RemoteDownloadScope, RemoteScopeDigest};
use exacopy_platform::linux::{DestinationRoot, observe_remote_destination};

use crate::args::RemoteOptions;
use crate::assembly::linux::remote_download::{
	AttemptAdmission, ConnectingRemoteSource, measure_running_executable,
};
use crate::assembly::linux::{
	CheckedOriginalWitnessStartup, ExplicitWitnessSelection, OriginalWitnessError,
	OriginalWitnessResult, OriginalWitnessResume, continue_original_capture,
};
use crate::profile::{LocalProfile, kernel_random};
use crate::remote_frontdoor::SshProfile;
use crate::remote_report::{
	RemoteFailureKind as Failure, RemoteJob, RemoteOutcome, WitnessedSummary,
};

use super::Interrupt;
use super::qualification::{SelectedTrust, read_bounded};
use super::{outcome, resume, retry, selection};

const GRANT_DOMAIN: &str = "ExaCopy Linux first witnessed resume grant binding v1";

pub(super) struct Selection {
	pub(super) qualification: VerifiedRemoteWitnessQualification,
	pub(super) consent: ExplicitWitnessSelection,
}

impl Selection {
	pub(super) fn load(
		artifact: &Path,
		trust: &Path,
		options: &RemoteOptions,
		root: &DestinationRoot,
		owner: &LocalProfile,
		scope: &RemoteDownloadScope,
	) -> Result<Self, Failure> {
		let ordinary = [
			options.destination_qualification.as_path(),
			options.qualification_trust.as_path(),
		];
		if artifact == trust || ordinary.contains(&artifact) || ordinary.contains(&trust) {
			return Err(Failure::InvalidRequest);
		}
		let trust = SelectedTrust::load_witness(trust)?;
		let route = selection::route_class(scope.source.route())?;
		let build = measure_running_executable().map_err(|_| Failure::Authorization)?;
		if trust.scope.route != route || trust.scope.build != build {
			return Err(Failure::Authorization);
		}
		let record = read_bounded::<MAX_REMOTE_QUALIFICATION_BYTES>(artifact)?;
		let qualification = verify_remote_witness_qualification(
			&record,
			&RemoteContinuationQualificationTrust {
				attestor: trust.attestor,
				attestor_key: &trust.key,
				owner_key: &owner.verification_key(),
				scope: RemoteContinuationQualificationScope {
					common: trust.scope,
					operation:
						RemoteContinuationOperationProfile::VerifiedRetainedAppendWithWitnessV1,
					coverage:
						RemoteContinuationCoverageProfile::RetainedAppendWithWitnessProcessCrashV1,
				},
			},
		)
		.map_err(|_| Failure::Authorization)?;
		let facts = observe_remote_destination(root).map_err(|_| Failure::Authorization)?;
		qualification
			.match_current(build, &facts)
			.map_err(|_| Failure::Authorization)?;
		// The parser accepts this branch only with both the strategy and retention flag.
		let consent = ExplicitWitnessSelection::select(true, true).ok_or(Failure::Authorization)?;
		Ok(Self {
			qualification,
			consent,
		})
	}
}

pub(super) fn fresh_grant_digest(scope: RemoteScopeDigest) -> Result<[u8; 32], Failure> {
	let mut nonce = [0; 32];
	kernel_random(&mut nonce).map_err(|_| Failure::Io)?;
	Ok(*blake3::Hasher::new_derive_key(GRANT_DOMAIN)
		.update(scope.as_bytes())
		.update(&nonce)
		.finalize()
		.as_bytes())
}

pub(super) async fn run(
	request: OriginalWitnessResume<'_>,
	job: RemoteJob,
	connecting: ConnectingRemoteSource<'_>,
	ssh: &SshProfile,
	interrupted: &Interrupt,
	startup: Box<CheckedOriginalWitnessStartup<'_>>,
) -> RemoteOutcome {
	let qualification = *request.qualification.digest().as_bytes();
	// Retain the original shared lease and its donor pins through authentication.
	let result = retry::with_connection(
		connecting,
		ssh,
		interrupted,
		AttemptAdmission::Witnessed(startup),
		async move |connected, admission| {
			let AttemptAdmission::Witnessed(startup) = admission else {
				return Ok(Err(OriginalWitnessError::Startup));
			};
			interrupted.route(connected.cancellation_handle())?;
			Ok::<_, Failure>(continue_original_capture(request, *startup, connected).await)
		},
	)
	.await;
	match result {
		Err(error) => retry::project(Err(error), job, interrupted.cancelled(), true),
		Ok((result, retirement)) => {
			let report = match result {
				Ok(result) => finish(result, job, qualification, interrupted.cancelled()),
				Err(code) => RemoteOutcome::failed(code, Some(job)),
			};
			#[cfg(feature = "experimental-ssh-wireguard")]
			let report = match retirement {
				Some(error) => report.with_unconfirmed_route_retirement(error),
				None => report,
			};
			#[cfg(not(feature = "experimental-ssh-wireguard"))]
			debug_assert!(retirement.is_none());
			report
		}
	}
}

fn finish(
	result: Result<OriginalWitnessResult, OriginalWitnessError>,
	job: RemoteJob,
	qualification: [u8; 32],
	cancelled: bool,
) -> RemoteOutcome {
	match result {
		Ok(OriginalWitnessResult::Published {
			committed,
			canonical_receipt,
			length,
			receipt_digest,
			witness_links,
			metadata_omissions,
		}) => RemoteOutcome::published_with_witness(
			job,
			WitnessedSummary {
				committed,
				length,
				receipt_digest,
				canonical_receipt_length: canonical_receipt.len(),
				qualification,
				witness_links,
				metadata_omissions,
			},
		),
		Ok(OriginalWitnessResult::Conflict) => RemoteOutcome::failed(Failure::Conflict, Some(job)),
		Ok(OriginalWitnessResult::ConflictUnconfirmed) => {
			RemoteOutcome::witness_conflict_reconciliation(job)
		}
		Ok(OriginalWitnessResult::PublishedUnconfirmed { witness_links }) => {
			RemoteOutcome::witness_reconciliation(job, witness_links)
		}
		Ok(OriginalWitnessResult::ReconcileBeforeConfirmedPublication {
			last_confirmed_capture,
		}) => RemoteOutcome::witness_capture_reconciliation(
			job,
			last_confirmed_capture.sequence,
			last_confirmed_capture.end,
		),
		Ok(OriginalWitnessResult::PublicationUncertain) | Err(OriginalWitnessError::Startup) => {
			*resume::uncertain(&job)
		}
		Err(OriginalWitnessError::Qualification) => {
			RemoteOutcome::failed(Failure::Authorization, Some(job))
		}
		Err(OriginalWitnessError::Authority) => {
			let code = if cancelled {
				Failure::Cancelled
			} else {
				Failure::Authorization
			};
			RemoteOutcome::failed(code, Some(job))
		}
		Err(OriginalWitnessError::Source(error)) => {
			RemoteOutcome::failed(outcome::source_error(&error, cancelled), Some(job))
		}
		Err(OriginalWitnessError::Prefix) => RemoteOutcome::failed(Failure::Integrity, Some(job)),
	}
}
