use exacopy_endpoint::connection_retry::{ConnectionAttempt, ConnectionBinding, RetryError};
use exacopy_endpoint::remote_source::SourceEpoch;
use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};
use exacopy_ssh::{FileObservation, ReadOnlySftp, RemotePositionedRead};

use super::SftpSource;
use crate::SftpSourceError;

/// A selected read-only path and a fresh source epoch for one connecting attempt.
pub struct PendingSftpSourceRequest<'path> {
	/// The exact account-relative SFTP name in validated components.
	pub path: &'path [UnixComponent<'path>],
	/// The application-owned attempt for this authenticated SSH session.
	pub attempt: ConnectionAttempt,
	/// The new live source pass reserved for the selected attempt.
	pub epoch: SourceEpoch,
}

/// Application checks for current route and connection authority around pending source use.
/// Checks are synchronous and must not retain locks across adapter awaits.
pub trait PendingSourceOwner {
	/// Checks the exact routed connecting attempt while source admission is still pending.
	/// # Errors
	/// Refuses stale, expired or revoked authority or route.
	fn check_connecting(&mut self, attempt: ConnectionAttempt) -> Result<(), RetryError>;

	/// Checks the same current attempt even if the callback admitted the source.
	/// # Errors
	/// Refuses stale, expired or revoked authority or route.
	fn check_attempt(&mut self, attempt: ConnectionAttempt) -> Result<(), RetryError>;
}

/// Metadata from one held read-only SFTP handle awaiting source admission.
/// It exposes no stream reads, source mutation or destination capability.
///
/// # Examples
/// A pending source cannot be read as capture data.
/// ```compile_fail,E0599
/// use exacopy_endpoint::remote_source::CapturedReadAt as _;
/// use exacopy_sftp::PendingSftpSource;
/// async fn read(mut pending: PendingSftpSource<'_>) {
///     let _ = pending.read_exact_at(0, &mut [0]).await;
/// }
/// ```
pub struct PendingSftpSource<'session> {
	reader: RemotePositionedRead<'session>,
	attempt: ConnectionAttempt,
	epoch: SourceEpoch,
	observation: FileObservation,
}

impl<'session> PendingSftpSource<'session> {
	/// Identifies the attempt that supplied the held observation.
	#[must_use]
	pub const fn attempt(&self) -> ConnectionAttempt {
		self.attempt
	}

	/// Identifies this reserved live source pass.
	#[must_use]
	pub const fn epoch(&self) -> SourceEpoch {
		self.epoch
	}

	/// Returns the regular-file observation of the exact held SFTP handle.
	#[must_use]
	pub const fn observation(&self) -> FileObservation {
		self.observation
	}

	/// Activates this same handle after the owner admitted its source observation.
	/// # Errors
	/// Refuses a foreign attempt, wrong source epoch or stale current binding.
	/// A rejected activation retires the held handle with its owning session.
	pub fn activate<Check>(
		self,
		binding: ConnectionBinding,
		mut check: Check,
	) -> Result<SftpSource<'session, Check>, SftpSourceError>
	where
		Check: FnMut(ConnectionBinding) -> Result<(), RetryError>,
	{
		if binding.attempt() != self.attempt {
			return Err(SftpSourceError::Binding(RetryError::StaleWork));
		}
		if binding.source_epoch() != self.epoch {
			return Err(SftpSourceError::Epoch);
		}
		check(binding).map_err(SftpSourceError::Binding)?;
		Ok(SftpSource {
			reader: Some(self.reader),
			epoch: self.epoch,
			binding,
			observation: self.observation,
			check,
		})
	}
}

/// Opens and checks one held source before the owner admits data access.
/// The caller binds the authenticated session to the supplied current route and attempt.
/// The callback can admit the exact held observation and use that same handle for private
/// capture. It keeps the attempt current until it returns. Public effects belong outside
/// this scope. Neither the held source nor the borrowed owner can escape the callback.
///
/// # Examples
/// A callback cannot return the held pending source.
/// ```compile_fail
/// use exacopy_sftp::{PendingSftpSourceRequest, PendingSourceOwner, with_pending_source};
/// use exacopy_ssh::ReadOnlySftp;
/// async fn escape(
///     ssh: ReadOnlySftp,
///     request: PendingSftpSourceRequest<'_>,
///     owner: &mut impl PendingSourceOwner,
/// ) {
///     let _escaped = with_pending_source(ssh, request, owner, async |source, _| {
///         Ok::<_, ()>(source)
///     }).await;
/// }
/// ```
/// # Errors
/// Returns ownership, SFTP open or extent errors before running the callback. A late owner
/// refusal discards successful private evidence. Callback errors are returned unchanged
/// even if the connection subsequently becomes stale, so durable uncertainty is retained.
pub async fn with_pending_source<T, E, Owner, Run>(
	mut session: ReadOnlySftp,
	request: PendingSftpSourceRequest<'_>,
	owner: &mut Owner,
	run: Run,
) -> Result<Result<T, E>, SftpSourceError>
where
	Owner: PendingSourceOwner,
	Run: for<'session, 'owner> AsyncFnOnce(
		PendingSftpSource<'session>,
		&'owner mut Owner,
	) -> Result<T, E>,
{
	let attempt = request.attempt;
	let pending = open_pending_source(&mut session, request, owner).await?;
	let outcome = run(pending, owner).await;
	let current = owner.check_attempt(attempt);
	if outcome.is_ok() {
		current.map_err(SftpSourceError::Binding)?;
	}
	Ok(outcome)
}

/// Opens the exact held observation while borrowing the caller-owned session.
/// A scoped application can keep native job and stage capabilities on its own
/// stack independently of this session. Activate the observation before any
/// data capture. After successful capture, recheck the same current attempt
/// before explicitly retiring its session and route or using that evidence.
/// Preserve typed capture errors for reconciliation.
/// # Errors
/// Refuses stale authority, an unconfirmed SFTP open or an unsupported extent.
pub async fn open_pending_source<'session>(
	session: &'session mut ReadOnlySftp,
	request: PendingSftpSourceRequest<'_>,
	owner: &mut impl PendingSourceOwner,
) -> Result<PendingSftpSource<'session>, SftpSourceError> {
	owner
		.check_connecting(request.attempt)
		.map_err(SftpSourceError::Binding)?;
	let reader = session.open_positioned(request.path).await;
	owner
		.check_connecting(request.attempt)
		.map_err(SftpSourceError::Binding)?;
	let reader = reader?;
	let observation = reader.observation();
	if observation.length > MAX_FILE_LENGTH {
		return Err(SftpSourceError::Extent);
	}
	Ok(PendingSftpSource {
		reader,
		attempt: request.attempt,
		epoch: request.epoch,
		observation,
	})
}
