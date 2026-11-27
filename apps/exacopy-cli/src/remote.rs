//! Linux foreground composition for the explicit remote download commands.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;
use tokio::runtime::Builder;

#[cfg(feature = "experimental-verified-prefix-resume")]
use crate::args::RemoteResumeStrategy;
use crate::args::{RemoteCommand, RemoteMetadata, RemoteRequest};
#[cfg(feature = "experimental-verified-prefix-resume")]
use crate::assembly::linux::OriginalWitnessResume;
use crate::assembly::linux::remote_download::{
	AttemptAdmission, RemoteDownloadRequest, RemoteGrant, RemoteJobAction, SourceInvocation,
};
use crate::linux_path::{open_destination, split};
use crate::profile::LocalProfile;
use crate::remote_frontdoor::{GetRequest, SshProfile, require_metadata};
use crate::remote_report::{RemoteFailureKind as Failure, RemoteJob, RemoteOutcome};

mod interrupt;
mod outcome;
pub(crate) mod qualification;
mod resume;
mod retry;
mod selection;
#[cfg(feature = "experimental-verified-prefix-resume")]
mod witness;

use interrupt::Interrupt;
use selection::{Selected, refused};

const GRANT_DOMAIN: &str = "ExaCopy Linux remote foreground grant binding v1";
const RUNTIME_SHUTDOWN: Duration = Duration::from_secs(2);

enum Invocation {
	Get(GetRequest),
	Resume(RemoteJob),
}

impl Invocation {
	fn parse(command: &RemoteCommand, policy: &str) -> Result<Self, Failure> {
		match &command.request {
			RemoteRequest::Get { source, target } => GetRequest::new(
				source,
				target.clone(),
				command.options.profile.clone(),
				command.options.ssh_profile.clone(),
				Some(policy),
			)
			.map(Self::Get)
			.map_err(|_| Failure::InvalidRequest),
			RemoteRequest::Resume { job, .. } => {
				let (_, name) = split(job).map_err(|_| Failure::InvalidRequest)?;
				selection::selected_job(job, name).map(Self::Resume)
			}
		}
	}
}

pub(crate) fn execute(command: &RemoteCommand) -> RemoteOutcome {
	let Ok(runtime) = Builder::new_multi_thread()
		.worker_threads(2)
		.enable_all()
		.build()
	else {
		return *refused(Failure::Io);
	};
	let interrupted = Arc::new(Interrupt::default());
	let Ok(listener) = Interrupt::register(&runtime, Arc::clone(&interrupted)) else {
		return *refused(Failure::Io);
	};
	let result = runtime.block_on(run(command, &interrupted));
	listener.abort();
	runtime.shutdown_timeout(RUNTIME_SHUTDOWN);
	result.unwrap_or_else(|outcome| *outcome)
}

async fn run(
	command: &RemoteCommand,
	interrupted: &Interrupt,
) -> Result<RemoteOutcome, Box<RemoteOutcome>> {
	let options = &command.options;
	let policy = match &options.metadata {
		RemoteMetadata::SftpDataOnlyV1 => SftpDataOnlyV1::NAME,
	};
	let request = Invocation::parse(command, policy).map_err(refused)?;
	let (selected_path, owner_path) = match &request {
		Invocation::Get(get) => (&get.destination, &get.owner_profile),
		Invocation::Resume(job) => (&job.directory, &options.profile),
	};
	let (parent, name) = split(selected_path).map_err(|_| refused(Failure::InvalidRequest))?;
	let owners = LocalProfile::open(owner_path).map_err(|_| refused(Failure::Authorization))?;
	let root = open_destination(Path::new(parent)).map_err(|_| refused(Failure::Io))?;

	#[cfg(feature = "experimental-verified-prefix-resume")]
	let witness_inputs = match &command.request {
		RemoteRequest::Resume {
			strategy:
				RemoteResumeStrategy::VerifiedPrefixWithWitness {
					qualification,
					trust,
				},
			..
		} => Some((qualification, trust)),
		_ => None,
	};
	let held_job;
	let (selected, ssh, metadata, startup) = match &request {
		Invocation::Get(get) => {
			let ssh = get
				.load_profile()
				.map_err(|cause| refused(outcome::frontdoor_error(&cause)))?;
			let selected =
				selection::fresh(get, options, &root, &owners, &ssh, interrupted).await?;
			(selected, ssh, get.metadata, None)
		}
		Invocation::Resume(job) => {
			let ssh = SshProfile::load(&options.ssh_profile)
				.map_err(|cause| refused(outcome::frontdoor_error(&cause)))?;
			let metadata =
				require_metadata(Some(policy)).map_err(|_| refused(Failure::Unsupported))?;
			held_job = root
				.open_recovery_job(name)
				.map_err(|_| resume::uncertain(job))?;
			let startup = resume::Startup::hold(job, &held_job)?;
			let (selected, checked) = resume::select(
				startup,
				name,
				&root,
				&owners,
				&ssh,
				options,
				#[cfg(feature = "experimental-verified-prefix-resume")]
				witness_inputs.is_some(),
			)?;
			(selected, ssh, metadata, Some(checked))
		}
	};
	let Selected {
		job,
		scope,
		action,
		qualification,
	} = selected;
	let had_job = matches!(action, RemoteJobAction::Resume);
	let retained = || had_job.then(|| resume::duplicate_job(&job));
	interrupted
		.check()
		.map_err(|code| RemoteOutcome::failed(code, retained()))?;
	let scope_digest = scope.digest().map_err(|_| refused(Failure::Integrity))?;
	let grant_digest = blake3::derive_key(GRANT_DOMAIN, scope_digest.as_bytes());
	#[cfg(feature = "experimental-verified-prefix-resume")]
	let witnessed = witness_inputs
		.map(|(qualification, trust)| {
			witness::Selection::load(qualification, trust, options, &root, &owners, &scope)
		})
		.transpose()
		.map_err(|code| RemoteOutcome::failed(code, retained()))?;
	#[cfg(feature = "experimental-verified-prefix-resume")]
	let grant_digest = if witnessed.is_some() {
		witness::fresh_grant_digest(scope_digest)
			.map_err(|code| RemoteOutcome::failed(code, retained()))?
	} else {
		grant_digest
	};
	let deadline = Instant::now()
		.checked_add(ssh.grant_duration)
		.ok_or_else(|| refused(Failure::InvalidRequest))?;
	let grant = RemoteGrant::new(scope_digest, grant_digest, deadline)
		.map(Arc::new)
		.ok_or_else(|| refused(Failure::Authorization))?;
	interrupted
		.grant(&grant)
		.map_err(|code| RemoteOutcome::failed(code, retained()))?;

	let invocation = SourceInvocation::new(&scope, &grant).map_err(|error| {
		RemoteOutcome::failed(
			outcome::start_error(&error, interrupted.cancelled()),
			retained(),
		)
	})?;
	let request = RemoteDownloadRequest {
		root: &root,
		profile: owner_path,
		job: job.id,
		action,
		scope: &scope,
		metadata,
		grant: &grant,
		qualification: qualification.attestation(),
	};
	let connecting = invocation.claim().map_err(|error| {
		RemoteOutcome::failed(
			outcome::start_error(&error, interrupted.cancelled()),
			retained(),
		)
	})?;
	#[cfg(feature = "experimental-verified-prefix-resume")]
	if let Some(witness::Selection {
		qualification: continuation,
		consent,
	}) = witnessed
	{
		let original = OriginalWitnessResume {
			root: &root,
			profile: &owners,
			job: job.id,
			scope: &scope,
			initial_v1_qualification: qualification.digest(),
			fresh_v1_qualification: qualification.digest(),
			qualification: &continuation,
			grant: &grant,
			consent,
		};
		let Some(resume::CheckedStartup::Witnessed(startup)) = startup else {
			return Err(resume::uncertain(&job));
		};
		return Ok(witness::run(
			original,
			job,
			connecting,
			&ssh,
			interrupted,
			startup,
			grant_digest,
		)
		.await);
	}
	let startup = match startup {
		None => None,
		Some(resume::CheckedStartup::Ordinary(checked)) => Some(checked),
		#[cfg(feature = "experimental-verified-prefix-resume")]
		Some(resume::CheckedStartup::Witnessed(_)) => return Err(resume::uncertain(&job)),
	};
	let first = retry::attempt(
		connecting,
		&ssh,
		&request,
		interrupted,
		AttemptAdmission::Initial(startup),
	)
	.await;
	let attempts =
		retry::continue_capture(first, had_job, &invocation, &ssh, &request, interrupted).await;
	Ok(attempts.finish(job, interrupted.cancelled()))
}
