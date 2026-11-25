use std::num::{NonZeroU64, NonZeroU128};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use exacopy_endpoint::connection_retry::{
	ConnectionBinding, ReconnectEvidence, RetryDecision, RetryError, RetryOwner, RetrySupervisor,
};
use exacopy_endpoint::remote_source::SourceEpoch;
use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};
use exacopy_sftp::{SftpSourceError, SftpSourceRequest};
use exacopy_ssh::{Password, ReadOnlySftp, connect};
use exacopy_transfer::remote_capture::CaptureError;
use tokio::sync::Notify;

use super::capture_sftp;

#[path = "../../../../../crates/net/exacopy-ssh/tests/in_process/key_auth.rs"]
mod key_auth;
#[path = "../../../../../crates/net/exacopy-ssh/tests/in_process/peer.rs"]
mod peer;
mod stage;

use peer::{
	Calls, ChangedObservation, Generated, NAME, SECRET, authority, fixture_trust, generated_peer,
};
use stage::{Checkpoints, Stage, Trace};

const LIVE_ID: NonZeroU64 = NonZeroU64::MIN;

fn request<'path>(
	path: &'path [UnixComponent<'static>],
	binding: ConnectionBinding,
) -> SftpSourceRequest<'path> {
	SftpSourceRequest {
		path,
		epoch: SourceEpoch::new(LIVE_ID),
		binding,
	}
}

fn path() -> [UnixComponent<'static>; 1] {
	[UnixComponent::new(NAME).unwrap()]
}

fn admitted() -> (RetrySupervisor, ConnectionBinding) {
	let mut supervisor =
		RetrySupervisor::new(RetryOwner::new(NonZeroU128::MIN), Duration::from_secs(30));
	let RetryDecision::Start(attempt) = supervisor.poll(Duration::ZERO).unwrap() else {
		panic!("the synthetic source requires one active connection attempt");
	};
	let binding = supervisor
		.admit(
			Duration::ZERO,
			attempt,
			ReconnectEvidence {
				route_checked_for: attempt,
				ssh_authenticated_for: attempt,
				source_checked_for: attempt,
				source_epoch: SourceEpoch::new(LIVE_ID),
			},
		)
		.unwrap();
	(supervisor, binding)
}

async fn open(file: Generated) -> (ReadOnlySftp, Arc<Calls>) {
	let (stream, pin, calls) = generated_peer(file);
	let authority = authority("transfer");
	let session = connect(
		stream,
		&authority,
		pin,
		fixture_trust(&authority, ""),
		&authority,
		|_| Password::new(SECRET.to_owned()),
	)
	.await
	.unwrap();
	(session, calls)
}

#[tokio::test]
async fn one_read_only_handle_captures_short_replies_across_multiple_windows() {
	let mut file = Generated::new(11);
	file.max_reply = 2;
	let (session, calls) = open(file).await;
	let (mut owner, binding) = admitted();
	let mut checkpoints = Checkpoints::default();
	let trace = Trace::default();
	let output = capture_sftp(
		session,
		request(&path(), binding),
		|current| owner.check_completion(Duration::ZERO, current),
		Stage::new(&trace, 11),
		&mut checkpoints,
		&mut [0; 3],
	)
	.await
	.unwrap();
	let (stage, capture) = output.into_parts();
	let expected: Vec<u8> = (0..11).collect();

	assert_eq!(stage.bytes(), expected);
	assert_eq!(capture.epoch, SourceEpoch::new(LIVE_ID));
	assert_eq!(capture.length, 11);
	assert_eq!(capture.source_digest, *blake3::hash(&expected).as_bytes());
	assert_eq!(capture.stage_digest.as_bytes(), &capture.source_digest);
	assert_eq!(trace.sizes(), [3, 3, 3, 2]);
	assert_eq!(checkpoints.ranges.len(), 1);
	assert_eq!(checkpoints.ranges[0].length, 11);
	assert_eq!(checkpoints.ranges[0].epoch, SourceEpoch::new(LIVE_ID));
	assert_eq!(calls.open.load(Ordering::Relaxed), 1);
	assert_eq!(calls.read.load(Ordering::Relaxed), 8);
	assert_eq!(calls.close.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn held_metadata_change_refuses_initial_capture_without_read_or_close() {
	let mut file = Generated::new(5);
	file.changed_handle = true;
	let (session, calls) = open(file).await;
	let (mut owner, binding) = admitted();
	let trace = Trace::default();
	let result = capture_sftp(
		session,
		request(&path(), binding),
		|current| owner.check_completion(Duration::ZERO, current),
		Stage::new(&trace, 5),
		&mut Checkpoints::default(),
		&mut [0; 3],
	)
	.await;

	assert!(matches!(
		result,
		Err(CaptureError::SourceObservation(SftpSourceError::Sftp(
			exacopy_ssh::Error::Changed
		)))
	));
	assert!(trace.sizes().is_empty());
	assert_eq!(calls.read.load(Ordering::Relaxed), 0);
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn terminal_eof_is_independent_of_the_last_completed_window() {
	let mut file = Generated::new(5);
	file.actual_length = 6;
	let (session, calls) = open(file).await;
	let (mut owner, binding) = admitted();
	let trace = Trace::default();
	let result = capture_sftp(
		session,
		request(&path(), binding),
		|current| owner.check_completion(Duration::ZERO, current),
		Stage::new(&trace, 5),
		&mut Checkpoints::default(),
		&mut [0; 3],
	)
	.await;
	assert!(matches!(
		result,
		Err(CaptureError::SourceFinish(SftpSourceError::Sftp(
			exacopy_ssh::Error::Changed
		)))
	));
	assert_eq!(trace.sizes(), [3, 2]);
	assert_eq!(calls.read.load(Ordering::Relaxed), 3);
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn an_empty_file_uses_only_the_terminal_eof_probe() {
	let (session, calls) = open(Generated::new(0)).await;
	let (mut owner, binding) = admitted();
	let trace = Trace::default();
	let result = capture_sftp(
		session,
		request(&path(), binding),
		|current| owner.check_completion(Duration::ZERO, current),
		Stage::new(&trace, 0),
		&mut Checkpoints::default(),
		&mut [0; 3],
	)
	.await
	.unwrap();
	assert_eq!(result.into_parts().1.length, 0);
	assert!(trace.sizes().is_empty());
	assert_eq!(calls.read.load(Ordering::Relaxed), 1);
	assert_eq!(calls.close.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn cancellation_in_a_started_read_never_passes_partial_bytes_to_the_stage() {
	let started = Arc::new(Notify::new());
	let mut file = Generated::new(5);
	file.pending_read = Some(started.clone());
	let (session, calls) = open(file).await;
	let (mut owner, binding) = admitted();
	let trace = Trace::default();
	let path = path();
	let mut checkpoints = Checkpoints::default();
	let mut scratch = [0; 3];
	{
		let capture = capture_sftp(
			session,
			request(&path, binding),
			|current| owner.check_completion(Duration::ZERO, current),
			Stage::new(&trace, 5),
			&mut checkpoints,
			&mut scratch,
		);
		tokio::pin!(capture);
		tokio::select! {
			result = &mut capture => panic!("the synthetic read must stay pending: {result:?}"),
			_ = started.notified() => {}
			_ = tokio::time::sleep(Duration::from_secs(2)) => panic!("the fixture never received READ"),
		}
	}

	assert!(trace.sizes().is_empty());
	assert!(checkpoints.ranges.is_empty());
	assert_eq!(calls.open.load(Ordering::Relaxed), 1);
	assert_eq!(calls.read.load(Ordering::Relaxed), 1);
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_returning_short_read_requires_the_same_binding_before_continuing() {
	let mut file = Generated::new(5);
	file.max_reply = 1;
	let (session, calls) = open(file).await;
	let (mut owner, binding) = admitted();
	let trace = Trace::default();
	let result = capture_sftp(
		session,
		request(&path(), binding),
		|current| {
			owner.check_completion(Duration::ZERO, current)?;
			if calls.read.load(Ordering::Relaxed) != 0 {
				return Err(RetryError::StaleWork);
			}
			Ok(())
		},
		Stage::new(&trace, 5),
		&mut Checkpoints::default(),
		&mut [0; 3],
	)
	.await;
	assert!(matches!(
		result,
		Err(CaptureError::Read {
			offset: 0,
			cause: SftpSourceError::Binding(RetryError::StaleWork),
		})
	));
	assert!(trace.sizes().is_empty());
	assert_eq!(calls.read.load(Ordering::Relaxed), 1);
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn successful_close_cannot_authorize_a_stale_return() {
	let (session, calls) = open(Generated::new(3)).await;
	let (mut owner, binding) = admitted();
	let trace = Trace::default();
	let result = capture_sftp(
		session,
		request(&path(), binding),
		|current| {
			owner.check_completion(Duration::ZERO, current)?;
			if calls.close.load(Ordering::Relaxed) != 0 {
				return Err(RetryError::StaleWork);
			}
			Ok(())
		},
		Stage::new(&trace, 3),
		&mut Checkpoints::default(),
		&mut [0; 3],
	)
	.await;
	assert!(matches!(
		result,
		Err(CaptureError::SourceFinish(SftpSourceError::Binding(
			RetryError::StaleWork
		)))
	));
	assert_eq!(trace.sizes(), [3]);
	assert_eq!(calls.close.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn refuses_disagreeing_epochs_before_open_and_large_extents_before_read() {
	let path = path();
	let (session, calls) = open(Generated::new(5)).await;
	let (mut owner, binding) = admitted();
	let trace = Trace::default();
	let mut mismatch = request(&path, binding);
	mismatch.epoch = SourceEpoch::new(NonZeroU64::new(2).unwrap());
	let result = capture_sftp(
		session,
		mismatch,
		|current| owner.check_completion(Duration::ZERO, current),
		Stage::new(&trace, 5),
		&mut Checkpoints::default(),
		&mut [0; 3],
	)
	.await;
	assert!(matches!(
		result,
		Err(CaptureError::SourceObservation(SftpSourceError::Epoch))
	));
	assert_eq!(calls.open.load(Ordering::Relaxed), 0);

	let too_large = MAX_FILE_LENGTH + 1;
	let (session, calls) = open(Generated::new(too_large)).await;
	let result = capture_sftp(
		session,
		request(&path, binding),
		|current| owner.check_completion(Duration::ZERO, current),
		Stage::new(&trace, too_large),
		&mut Checkpoints::default(),
		&mut [0; 3],
	)
	.await;
	assert!(matches!(
		result,
		Err(CaptureError::SourceObservation(SftpSourceError::Extent))
	));
	assert!(trace.sizes().is_empty());
	assert_eq!(calls.open.load(Ordering::Relaxed), 1);
	assert_eq!(calls.read.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn metadata_change_during_a_window_discards_its_bytes() {
	let mut file = Generated::new(5);
	file.change_during_window = Some(ChangedObservation::Named);
	let (session, calls) = open(file).await;
	let (mut owner, binding) = admitted();
	let trace = Trace::default();
	let result = capture_sftp(
		session,
		request(&path(), binding),
		|current| owner.check_completion(Duration::ZERO, current),
		Stage::new(&trace, 5),
		&mut Checkpoints::default(),
		&mut [0; 3],
	)
	.await;
	assert!(matches!(
		result,
		Err(CaptureError::Read {
			offset: 0,
			cause: SftpSourceError::Sftp(exacopy_ssh::Error::Changed),
		})
	));
	assert!(trace.sizes().is_empty());
	assert_eq!(calls.read.load(Ordering::Relaxed), 1);
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn close_acknowledgement_is_required_after_exact_eof() {
	let mut file = Generated::new(3);
	file.refuse_close = true;
	let (session, calls) = open(file).await;
	let (mut owner, binding) = admitted();
	let trace = Trace::default();
	let result = capture_sftp(
		session,
		request(&path(), binding),
		|current| owner.check_completion(Duration::ZERO, current),
		Stage::new(&trace, 3),
		&mut Checkpoints::default(),
		&mut [0; 3],
	)
	.await;
	assert!(matches!(
		result,
		Err(CaptureError::SourceFinish(SftpSourceError::Sftp(
			exacopy_ssh::Error::Status(russh_sftp::protocol::StatusCode::Failure,)
		)))
	));
	assert_eq!(trace.sizes(), [3]);
	assert_eq!(calls.read.load(Ordering::Relaxed), 2);
	assert_eq!(calls.close.load(Ordering::Relaxed), 1);
}
