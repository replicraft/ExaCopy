//! Default-off, single-invocation Windows fresh SFTP capture.

use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use std::{fmt, io};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::connection_retry::RetryError;
use exacopy_endpoint::remote_source::SourceEpoch;
use exacopy_endpoint::ssh_sftp::CredentialRequest;
use exacopy_journal::windows_bootstrap::{
	FIRST_SEGMENT_BYTES, FIRST_SEGMENT_NAME, JOURNAL_DIRECTORY_NAME, OWNER_BYTES, OWNER_FILE_NAME,
	WindowsBootstrapBytes, WindowsBootstrapFileIdentity, WindowsBootstrapInspectionError,
	WindowsBootstrapRoles, WindowsBootstrapSelection, inspect, job_directory_name,
};
use exacopy_platform::ProtectedSnapshotError;
use exacopy_platform::windows::{
	WindowsAuthenticatedCaptureScope, WindowsBootstrapLayout, WindowsBootstrapRoleObservations,
	WindowsCaptureStageError, WindowsComponent, WindowsStageIdentity,
};
use exacopy_sftp::{PendingSftpSourceRequest, SftpSourceError, open_pending_source};
use exacopy_ssh::{Ed25519Key, KnownHostTrust};
use exacopy_transfer::remote_capture::{CaptureError, CapturedStream};
use tokio::time::{Instant, timeout_at};

mod capture;
mod grant;
mod ledger;
mod progress;
mod route;
mod selection;

use capture::CaptureContext;
use grant::Effects;
use progress::Progress;
use route::{RoutedSession, SourceOwner};
use selection::{invalid_selection, invocation, native_identity};

const _: () = assert!(
	exacopy_platform::windows::MAX_WINDOWS_CAPTURE_SEGMENT_BYTES
		== exacopy_journal::windows_capture::MAX_CAPTURE_SEGMENT_BYTES
);

pub use grant::{WindowsCaptureAuthorization, WindowsCaptureGrant};
pub use ledger::WindowsCaptureLedgerError;
pub use progress::{
	WindowsCaptureCheckpointProgress, WindowsCaptureFailure, WindowsCaptureProgress,
};
pub use selection::WindowsCaptureSource;

/// Independently provisioned original job and exact signed bootstrap.
pub struct WindowsCaptureJob<'a> {
	/// Protected root at its selected absolute drive path.
	pub root: &'a Path,
	/// Independent profile, job, root and owner verification key.
	pub bootstrap: WindowsBootstrapSelection<'a>,
	/// Independently observed physical roles, selected before entering the SDK.
	pub roles: WindowsBootstrapRoleObservations,
	/// Original provisioned empty capture sibling.
	pub sibling: WindowsStageIdentity,
	/// Externally issued canonical owner and exact first segment.
	pub bytes: &'a WindowsBootstrapBytes,
	/// Trusted signer corresponding to the selected original owner key.
	pub signing_key: &'a SigningKey,
}

/// Trusted application inputs for a single capture over an exact route.
pub struct WindowsFreshCapture<'a> {
	/// Original protected NTFS job.
	pub job: WindowsCaptureJob<'a>,
	/// Approved literal peer and SFTP source.
	pub source: WindowsCaptureSource<'a>,
	/// Independently selected strict known-host trust snapshot.
	pub host_trust: KnownHostTrust,
	/// Nonrenewable one-invocation application authority.
	pub grant: &'a WindowsCaptureGrant<'a>,
}

/// Values the trusted caller records independently before the first native write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsCaptureSelectionReceipt {
	/// Public canonical invocation commitment.
	pub invocation: [u8; 32],
	/// Canonical resolved-direct source-scope digest.
	pub source_scope: [u8; 32],
	/// Actual admitted typed attempt's generation.
	pub generation: u64,
	/// Reserved and opened source pass.
	pub epoch: SourceEpoch,
	/// Independent maximum authorized source extent.
	pub extent_ceiling: u64,
}

/// Completed data measurements and last confirmed signed checkpoint.
///
/// On SDK success the native scope and original transport closeout also completed.
/// A failure can carry these earlier measurements while later checks remain uncertain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsFreshCaptureReport {
	/// Independently retained invocation/archive selectors.
	pub selection: WindowsCaptureSelectionReceipt,
	/// Actual private stage-directory identity.
	pub stage_directory: WindowsBootstrapFileIdentity,
	/// Actual private staged payload identity.
	pub stage_payload: WindowsBootstrapFileIdentity,
	/// Complete source and private independent read-back observations.
	pub stream: CapturedStream,
	/// Last physically confirmed signed capture-journal prefix.
	pub prefix: exacopy_journal::windows_capture::WindowsCapturePrefix,
}

/// Error details from the live source-to-private-stage transfer engine.
pub type WindowsCaptureTransferError =
	CaptureError<SftpSourceError, WindowsCaptureStageError, WindowsCaptureLedgerError>;

/// First refused or unconfirmed boundary of the invocation.
#[derive(Debug)]
#[non_exhaustive]
pub enum WindowsCaptureError {
	/// An independent selection or its live join failed.
	Selection(io::Error),
	/// Live authority refused the invocation or a later observation.
	Grant(io::Error),
	/// The selected actual TCP route was unavailable or differed.
	Route(io::Error),
	/// Pinned SSH or controlled session close failed.
	Ssh(exacopy_ssh::Error),
	/// The real connection supervisor refused the binding.
	Retry(RetryError),
	/// The original native records or empty sibling were not admitted.
	Custody(ProtectedSnapshotError),
	/// The selected V1 signed owner or frame was invalid.
	Bootstrap(WindowsBootstrapInspectionError),
	/// The trusted caller failed to retain independent selection before effects.
	SelectionReceipt(io::Error),
	/// The guarded original V1 append was refused or could not be confirmed.
	BootstrapAppend(io::Error),
	/// The held SFTP source observation or activation was refused.
	Source(SftpSourceError),
	/// A native stage or journal operation failed or was uncertain.
	Native(WindowsCaptureStageError),
	/// Opening or appending the guarded fresh capture journal failed.
	Ledger(WindowsCaptureLedgerError),
	/// The production live capture engine refused a boundary.
	Capture(Box<WindowsCaptureTransferError>),
	/// The active invocation reached its deadline. Private artifacts may remain.
	Deadline,
}

impl fmt::Display for WindowsCaptureError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Selection(cause) => write!(formatter, "capture selection failed ({cause})"),
			Self::Grant(cause) => write!(formatter, "capture grant refused ({cause})"),
			Self::Route(cause) => write!(formatter, "literal capture route failed ({cause})"),
			Self::Ssh(cause) => cause.fmt(formatter),
			Self::Retry(cause) => cause.fmt(formatter),
			Self::Custody(cause) => cause.fmt(formatter),
			Self::Bootstrap(cause) => cause.fmt(formatter),
			Self::SelectionReceipt(cause) => {
				write!(formatter, "retaining selection failed ({cause})")
			}
			Self::BootstrapAppend(cause) => write!(formatter, "V1 append unconfirmed ({cause})"),
			Self::Source(cause) => cause.fmt(formatter),
			Self::Native(cause) => cause.fmt(formatter),
			Self::Ledger(cause) => cause.fmt(formatter),
			Self::Capture(cause) => cause.fmt(formatter),
			Self::Deadline => formatter.write_str("the capture invocation reached its deadline"),
		}
	}
}

impl std::error::Error for WindowsCaptureError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Selection(cause)
			| Self::Grant(cause)
			| Self::Route(cause)
			| Self::SelectionReceipt(cause)
			| Self::BootstrapAppend(cause) => Some(cause),
			Self::Ssh(cause) => Some(cause),
			Self::Retry(cause) => Some(cause),
			Self::Custody(cause) => Some(cause),
			Self::Bootstrap(cause) => Some(cause),
			Self::Source(cause) => Some(cause),
			Self::Native(cause) => Some(cause),
			Self::Ledger(cause) => Some(cause),
			Self::Capture(cause) => Some(cause.as_ref()),
			Self::Deadline => None,
		}
	}
}

/// Captures an exact held regular file through actual pinned read-only SFTP.
///
/// The embedding authority provides independently selected original role
/// identities, trust, route, source path and live grant, and retains the
/// selection callback's values alongside the other immutable selections. Its
/// native provisioning must satisfy the cooperative protected-NTFS custody
/// contract, including exclusion of retained untrusted mutation capabilities.
/// Credential acquisition starts after native read-only admission and host
/// verification. The original V1 and separate capture appender remain held
/// through the engine's stage read-back and final native checks.
///
/// This operation may create private stages and append signed records. It
/// produces kernel-live observations and grants no further authority.
///
/// # Errors
/// Any refused or uncertain effect preserves physical artifacts for inspection.
/// The error retains reached historical observations and the original cause.
/// A successful return requires full source and stage verification, confirmed
/// live journal boundaries, and observed shutdown on the original route.
pub async fn capture_fresh_windows_sftp<B>(
	request: WindowsFreshCapture<'_>,
	broker: B,
	retain_selection: impl FnOnce(WindowsCaptureSelectionReceipt) -> io::Result<()>,
) -> Result<WindowsFreshCaptureReport, WindowsCaptureFailure>
where
	B: for<'a> AsyncFnOnce(CredentialRequest<'a>) -> Result<Ed25519Key, exacopy_ssh::Error>,
{
	let progress = Progress::default();
	run_capture(request, broker, retain_selection, &progress)
		.await
		.map_err(|cause| progress.failure(cause))
}

async fn run_capture<B>(
	request: WindowsFreshCapture<'_>,
	broker: B,
	retain_selection: impl FnOnce(WindowsCaptureSelectionReceipt) -> io::Result<()>,
	progress: &Progress,
) -> Result<WindowsFreshCaptureReport, WindowsCaptureError>
where
	B: for<'a> AsyncFnOnce(CredentialRequest<'a>) -> Result<Ed25519Key, exacopy_ssh::Error>,
{
	use WindowsCaptureError as Error;

	let WindowsFreshCapture {
		job,
		source,
		host_trust,
		grant,
	} = request;
	let _invocation_guard = grant.gate.claim().map_err(Error::Grant)?;
	let approved = &grant.approval;
	let source_scope = source.scope_digest().map_err(Error::Selection)?;
	if approved.source_scope != source_scope
		|| approved.extent_ceiling != source.extent_ceiling
		|| native_identity(job.sibling).map_err(Error::Selection)? != approved.sibling
		|| job.signing_key.verifying_key() != *job.bootstrap.key
	{
		return Err(Error::Selection(invalid_selection()));
	}
	let root_units: Vec<_> = job.root.as_os_str().encode_wide().take(32_768).collect();
	let job_name = job_directory_name(job.bootstrap.job);
	let layout = WindowsBootstrapLayout {
		job: component(&job_name)?,
		owner: component(&OWNER_FILE_NAME)?,
		journal: component(&JOURNAL_DIRECTORY_NAME)?,
		first_segment: component(&FIRST_SEGMENT_NAME)?,
		owner_bytes: OWNER_BYTES,
		first_segment_bytes: FIRST_SEGMENT_BYTES,
	};
	// Open every original role and the protected empty sibling before network
	// work, maintaining native ownership across the entire capture invocation.
	let mut scope = WindowsAuthenticatedCaptureScope::open_provisioned(
		&root_units,
		job.roles,
		layout,
		job.sibling,
	)
	.map_err(Error::Custody)?;
	let roles = scope.roles();
	let bootstrap = inspect(
		&job.bytes.owner,
		&job.bytes.first_segment[..],
		&job.bootstrap,
		bootstrap_roles(roles).map_err(Error::Selection)?,
	)
	.map_err(Error::Bootstrap)?;
	let head = bootstrap.boundary().head();
	if bootstrap.owner_digest() != approved.owner_digest
		|| head != approved.bootstrap_head
		|| native_identity(scope.capture_segment_identity()).map_err(Error::Selection)?
			!= approved.sibling
	{
		return Err(Error::Selection(invalid_selection()));
	}
	scope
		.confirm_owner_bytes(&job.bytes.owner)
		.map_err(Error::Custody)?;
	let payload = ledger::prepared_payload(job.bytes).map_err(Error::Selection)?;
	let deadline = Instant::from_std(grant.gate.expires);
	let mut owner = SourceOwner::new(grant);
	let attempt = owner.start()?;
	let mut routed =
		RoutedSession::connect(&source, &grant.gate, attempt, host_trust, broker).await?;
	let pending = timeout_at(
		deadline,
		open_pending_source(
			&mut routed.session,
			PendingSftpSourceRequest {
				path: source.path,
				attempt,
				epoch: approved.epoch,
			},
			&mut owner,
		),
	)
	.await
	.map_err(|_| Error::Deadline)?
	.map_err(Error::Source)?;
	let extent = pending.observation().length;
	if extent > approved.extent_ceiling {
		return Err(Error::Source(SftpSourceError::Extent));
	}
	let binding = owner.admit(routed.ticket, &pending, approved.epoch)?;
	let mut live_source = pending
		.activate(binding, |current| owner.check_completion(current))
		.map_err(Error::Source)?;
	if live_source.binding() != binding {
		return Err(Error::Retry(RetryError::StaleAdmission));
	}

	let selection = WindowsCaptureSelectionReceipt {
		invocation: invocation(approved, binding).map_err(Error::Selection)?,
		source_scope,
		generation: binding.attempt().generation().get(),
		epoch: binding.source_epoch(),
		extent_ceiling: approved.extent_ceiling,
	};
	retain_selection(selection).map_err(Error::SelectionReceipt)?;
	progress.update(|state| state.selection = Some(selection));
	let effects = Effects::new(
		&grant.gate,
		binding,
		scope.capture_segment_identity(),
		extent,
	);
	progress.update(|state| state.local_changes_may_exist = true);
	let stage = scope
		.append_first_segment(
			&job.bytes.owner,
			&job.bytes.first_segment,
			&effects,
			|segment| ledger::append_bootstrap(segment, payload, head),
		)
		.map_err(Error::BootstrapAppend)?;
	progress.update(|state| state.bootstrap = Some(bootstrap.boundary()));
	let context = CaptureContext {
		bootstrap: &bootstrap,
		selection,
		sibling: approved.sibling,
		target: approved.target,
		signing_key: job.signing_key,
		effects: &effects,
		extent,
		progress,
	};
	let report = timeout_at(
		deadline,
		stage.with_capture(
			approved.target,
			extent,
			async |stage, journal, admission| {
				context
					.run(&mut live_source, stage, journal, admission)
					.await
			},
		),
	)
	.await
	.map_err(|_| Error::Deadline)?
	.map_err(Error::Native)??;
	progress.update(|state| state.native_closeout_confirmed = true);
	drop(live_source);
	owner.check_completion(binding).map_err(Error::Retry)?;
	routed.close(deadline).await?;
	progress.update(|state| state.route_shutdown_confirmed = true);
	owner.check_completion(binding).map_err(Error::Retry)?;
	Ok(report)
}

fn component(name: &[u16]) -> Result<WindowsComponent<'_>, WindowsCaptureError> {
	WindowsComponent::new(name).map_err(|_| WindowsCaptureError::Selection(invalid_selection()))
}

fn bootstrap_roles(roles: WindowsBootstrapRoleObservations) -> io::Result<WindowsBootstrapRoles> {
	WindowsBootstrapRoles::new(
		native_identity(roles.root)?,
		native_identity(roles.job_directory)?,
		native_identity(roles.owner_file)?,
		native_identity(roles.journal_directory)?,
		native_identity(roles.first_segment)?,
	)
	.map_err(|_| invalid_selection())
}
