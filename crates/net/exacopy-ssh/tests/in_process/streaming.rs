use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use exacopy_endpoint::UnixComponent;
use exacopy_ssh::{Error, MAX_READ_CHUNK_BYTES, MAX_STREAM_BYTES, Password, ReadOnlySftp, connect};
use russh_sftp::protocol::StatusCode;
use tokio::sync::Notify;

use super::peer::{Calls, Generated, NAME, SECRET, authority, fixture_trust, generated_peer};

const LARGE_LENGTH: u64 = 5 * 1024 * 1024 + 13;

async fn open(generated: Generated) -> (ReadOnlySftp, Arc<Calls>) {
	let (stream, pin, calls) = generated_peer(generated);
	let target = authority("transfer");
	let sftp = connect(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| Password::new(SECRET.to_owned()),
	)
	.await
	.unwrap();
	(sftp, calls)
}

#[tokio::test]
async fn streams_more_than_four_mib_through_short_replies_and_restores_the_session() {
	let (mut sftp, calls) = open(Generated::new(LARGE_LENGTH)).await;
	let path = [UnixComponent::new(NAME).unwrap()];
	let mut source = sftp.open_read(&path).await.unwrap();
	let observation = source.observation();
	assert_eq!(observation.length, LARGE_LENGTH);

	let mut chunk = [0; MAX_READ_CHUNK_BYTES];
	let mut total = 0u64;
	loop {
		let count = source.read_next(&mut chunk).await.unwrap();
		if count == 0 {
			break;
		}
		assert!(count < chunk.len());
		for (relative, byte) in chunk[..count].iter().enumerate() {
			assert_eq!(*byte, ((total + relative as u64) % 251) as u8);
		}
		total += count as u64;
	}
	assert_eq!(total, LARGE_LENGTH);
	assert_eq!(source.finish().await.unwrap(), observation);
	assert!(calls.read.load(Ordering::Relaxed) > 128);
	assert_eq!(calls.close.load(Ordering::Relaxed), 1);
	assert_eq!(sftp.stat(&path).await.unwrap(), observation);
}

#[tokio::test]
async fn early_and_extra_data_are_observed_at_different_boundaries() {
	let path = [UnixComponent::new(NAME).unwrap()];
	let mut chunk = [0; 8];
	let mut truncated = Generated::new(5);
	truncated.actual_length = 3;
	let (mut sftp, calls) = open(truncated).await;
	let mut source = sftp.open_read(&path).await.unwrap();
	assert_eq!(source.read_next(&mut chunk).await.unwrap(), 3);
	assert!(matches!(
		source.read_next(&mut chunk).await,
		Err(Error::Changed)
	));
	drop(source);
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
	assert!(matches!(sftp.stat(&path).await, Err(Error::Closed)));

	let mut extended = Generated::new(5);
	extended.actual_length = 6;
	let (mut sftp, calls) = open(extended).await;
	let mut source = sftp.open_read(&path).await.unwrap();
	assert_eq!(source.read_next(&mut chunk).await.unwrap(), 5);
	assert_eq!(source.read_next(&mut chunk).await.unwrap(), 0);
	assert!(matches!(source.finish().await, Err(Error::Changed)));
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
	assert!(matches!(sftp.stat(&path).await, Err(Error::Closed)));
}

#[tokio::test]
async fn both_final_observations_are_required_after_consuming_the_extent() {
	let path = [UnixComponent::new(NAME).unwrap()];
	for (changed_handle, changed_name, close_count) in [(true, false, 0), (false, true, 1)] {
		let mut generated = Generated::new(5);
		generated.changed_handle = changed_handle;
		generated.changed_name = changed_name;
		let (mut sftp, calls) = open(generated).await;
		let mut source = sftp.open_read(&path).await.unwrap();
		assert_eq!(source.read_next(&mut [0; 5]).await.unwrap(), 5);
		assert!(matches!(source.finish().await, Err(Error::Changed)));
		assert_eq!(calls.close.load(Ordering::Relaxed), close_count);
		assert!(matches!(sftp.stat(&path).await, Err(Error::Closed)));
	}
}

#[tokio::test]
async fn zero_length_still_requires_an_eof_probe_and_close_acknowledgement() {
	let path = [UnixComponent::new(NAME).unwrap()];
	for refuse_close in [false, true] {
		let mut generated = Generated::new(0);
		generated.refuse_close = refuse_close;
		let (mut sftp, calls) = open(generated).await;
		let mut source = sftp.open_read(&path).await.unwrap();
		assert_eq!(source.read_next(&mut [0; 1]).await.unwrap(), 0);
		assert_eq!(calls.read.load(Ordering::Relaxed), 0);
		let observation = source.observation();
		let result = source.finish().await;
		assert_eq!(calls.read.load(Ordering::Relaxed), 1);
		assert_eq!(calls.close.load(Ordering::Relaxed), 1);
		if refuse_close {
			assert!(matches!(result, Err(Error::Status(StatusCode::Failure))));
			assert!(matches!(sftp.stat(&path).await, Err(Error::Closed)));
		} else {
			assert_eq!(result.unwrap(), observation);
			assert_eq!(sftp.stat(&path).await.unwrap(), observation);
		}
	}
}

#[tokio::test]
async fn incomplete_finish_and_unfinished_drop_make_the_session_unusable() {
	let path = [UnixComponent::new(NAME).unwrap()];
	let (mut sftp, calls) = open(Generated::new(5)).await;
	let mut source = sftp.open_read(&path).await.unwrap();
	assert_eq!(source.read_next(&mut [0; 2]).await.unwrap(), 2);
	assert!(matches!(
		source.finish().await,
		Err(Error::IncompleteRead {
			expected: 5,
			read: 2
		})
	));
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
	assert!(matches!(sftp.stat(&path).await, Err(Error::Closed)));

	let (mut sftp, calls) = open(Generated::new(5)).await;
	drop(sftp.open_read(&path).await.unwrap());
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
	assert!(matches!(sftp.stat(&path).await, Err(Error::Closed)));
}

#[tokio::test]
async fn cancelling_an_in_flight_read_fences_the_handle_and_parent_session() {
	let path = [UnixComponent::new(NAME).unwrap()];
	let started = Arc::new(Notify::new());
	let mut generated = Generated::new(5);
	generated.pending_read = Some(started.clone());
	let (mut sftp, calls) = open(generated).await;
	let mut source = sftp.open_read(&path).await.unwrap();
	let mut chunk = [0; 5];
	{
		let read = source.read_next(&mut chunk);
		tokio::pin!(read);
		tokio::select! {
			_ = started.notified() => {}
			_ = &mut read => panic!("fixture read must stay in flight"),
			_ = tokio::time::sleep(Duration::from_secs(2)) => panic!("fixture read did not reach peer"),
		}
	}
	assert_eq!(calls.read.load(Ordering::Relaxed), 1);
	assert!(matches!(
		source.read_next(&mut chunk).await,
		Err(Error::Closed)
	));
	drop(source);
	assert!(matches!(sftp.stat(&path).await, Err(Error::Closed)));
}

#[tokio::test]
async fn admitted_extent_buffer_and_request_count_have_independent_bounds() {
	let path = [UnixComponent::new(NAME).unwrap()];
	let (mut sftp, calls) = open(Generated::new(MAX_STREAM_BYTES + 1)).await;
	assert!(matches!(sftp.open_read(&path).await, Err(Error::Limit)));
	assert_eq!(calls.read.load(Ordering::Relaxed), 0);
	assert!(matches!(sftp.stat(&path).await, Err(Error::Closed)));

	let (mut sftp, calls) = open(Generated::new(5)).await;
	let mut source = sftp.open_read(&path).await.unwrap();
	assert!(matches!(
		source.read_next(&mut [0; MAX_READ_CHUNK_BYTES + 1]).await,
		Err(Error::Limit)
	));
	drop(source);
	assert_eq!(calls.read.load(Ordering::Relaxed), 0);
	assert!(matches!(sftp.stat(&path).await, Err(Error::Closed)));

	let mut small_replies = Generated::new(4097);
	small_replies.max_reply = 1;
	let (mut sftp, calls) = open(small_replies).await;
	let mut source = sftp.open_read(&path).await.unwrap();
	let mut chunk = [0; 1];
	for _ in 0..4096 {
		assert_eq!(source.read_next(&mut chunk).await.unwrap(), 1);
	}
	assert!(matches!(
		source.read_next(&mut chunk).await,
		Err(Error::Limit)
	));
	drop(source);
	assert_eq!(calls.read.load(Ordering::Relaxed), 4096);
	assert!(matches!(sftp.stat(&path).await, Err(Error::Closed)));
}

#[tokio::test]
#[ignore = "waits for the actual 20-second operation deadline"]
async fn caller_delay_between_reads_spends_the_same_operation_deadline() {
	let path = [UnixComponent::new(NAME).unwrap()];
	let (mut sftp, calls) = open(Generated::new(5)).await;
	let mut source = sftp.open_read(&path).await.unwrap();
	assert_eq!(source.read_next(&mut [0; 2]).await.unwrap(), 2);

	tokio::time::sleep(Duration::from_secs(20)).await;

	assert!(matches!(
		source.read_next(&mut [0; 3]).await,
		Err(Error::Timeout)
	));
	drop(source);
	assert_eq!(calls.read.load(Ordering::Relaxed), 1);
	assert!(matches!(sftp.stat(&path).await, Err(Error::Closed)));
}
