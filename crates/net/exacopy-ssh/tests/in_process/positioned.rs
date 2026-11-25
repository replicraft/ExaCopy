use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use exacopy_endpoint::UnixComponent;
use exacopy_ssh::{
	Error, MAX_STREAM_BYTES, Password, ReadOnlySftp, RemotePositionedRead, WindowObservation,
	connect,
};
use tokio::sync::Notify;

use super::peer::{
	Calls, ChangedObservation, Generated, NAME, SECRET, authority, fixture_trust, generated_peer,
};

const HIGH_OFFSET: u64 = (1 << 32) + 19;

fn path() -> [UnixComponent<'static>; 1] {
	[UnixComponent::new(NAME).unwrap()]
}

async fn open(generated: Generated) -> (ReadOnlySftp, Arc<Calls>) {
	let (stream, pin, calls) = generated_peer(generated);
	let target = authority("transfer");
	let session = connect(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| Password::new(SECRET.to_owned()),
	)
	.await
	.unwrap();
	(session, calls)
}

async fn read_window(
	source: &mut RemotePositionedRead<'_>,
	offset: u64,
	length: u64,
) -> WindowObservation {
	let mut window = source.begin_window(offset, length).await.unwrap();
	let mut actual = 0;
	let mut chunk = [0; 8];
	loop {
		let count = window.read_next(&mut chunk).await.unwrap();
		if count == 0 {
			break;
		}
		for (index, byte) in chunk[..count].iter().enumerate() {
			assert_eq!(*byte, ((offset + actual + index as u64) % 251) as u8);
		}
		actual += count as u64;
	}
	assert_eq!(actual, length);
	window.finish().await.unwrap()
}

#[tokio::test]
async fn reads_out_of_order_windows_above_four_gib_on_one_handle() {
	let mut generated = Generated::new(HIGH_OFFSET + 13);
	generated.max_reply = 2;
	let (mut session, calls) = open(generated).await;
	let mut source = session.open_positioned(&path()).await.unwrap();
	let file = source.observation();

	// Read the suffix, then the prefix, then a separate high-offset interval.
	// The unread gaps remain unobserved even after EOF.
	for (offset, length) in [(HIGH_OFFSET + 9, 4), (0, 5), (HIGH_OFFSET, 7)] {
		let window = read_window(&mut source, offset, length).await;
		assert_eq!(
			(window.offset(), window.length(), window.file()),
			(offset, length, file)
		);
	}
	assert_eq!(calls.open.load(Ordering::Relaxed), 1);
	assert_eq!(calls.read.load(Ordering::Relaxed), 9);
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
	assert_eq!(source.finish().await.unwrap(), file);
	assert_eq!(calls.read.load(Ordering::Relaxed), 10);
	assert_eq!(calls.close.load(Ordering::Relaxed), 1);
	assert_eq!(session.stat(&path()).await.unwrap(), file);
}

#[tokio::test]
async fn accepts_the_largest_representable_interval_end_and_empty_file_eof() {
	let (mut session, calls) = open(Generated::new(u64::MAX)).await;
	let mut source = session.open_positioned(&path()).await.unwrap();
	let window = read_window(&mut source, u64::MAX - 1, 1).await;
	assert_eq!((window.offset(), window.length()), (u64::MAX - 1, 1));
	assert_eq!(source.finish().await.unwrap().length, u64::MAX);
	assert_eq!(calls.read.load(Ordering::Relaxed), 2);

	let (mut session, calls) = open(Generated::new(0)).await;
	let source = session.open_positioned(&path()).await.unwrap();
	assert_eq!(source.finish().await.unwrap().length, 0);
	assert_eq!(calls.read.load(Ordering::Relaxed), 1);
	assert_eq!(calls.close.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn rejects_empty_out_of_bounds_oversized_and_overflowing_windows_before_read() {
	for (file_length, offset, length) in [
		(0, 0, 0),
		(HIGH_OFFSET, HIGH_OFFSET, 1),
		(u64::MAX, 0, MAX_STREAM_BYTES + 1),
		(u64::MAX, u64::MAX - 1, 2),
	] {
		let (mut session, calls) = open(Generated::new(file_length)).await;
		let mut source = session.open_positioned(&path()).await.unwrap();
		assert!(matches!(
			source.begin_window(offset, length).await,
			Err(Error::Limit)
		));
		assert!(matches!(source.finish().await, Err(Error::Closed)));
		assert_eq!(calls.read.load(Ordering::Relaxed), 0);
		assert_eq!(calls.close.load(Ordering::Relaxed), 0);
		assert!(matches!(session.stat(&path()).await, Err(Error::Closed)));
	}
}

#[tokio::test]
async fn rejects_early_eof_in_a_window_and_extra_data_at_file_finish() {
	let mut short = Generated::new(HIGH_OFFSET + 4);
	short.actual_length = HIGH_OFFSET + 2;
	let (mut session, calls) = open(short).await;
	let mut source = session.open_positioned(&path()).await.unwrap();
	let mut window = source.begin_window(HIGH_OFFSET, 4).await.unwrap();
	assert_eq!(window.read_next(&mut [0; 4]).await.unwrap(), 2);
	assert!(matches!(
		window.read_next(&mut [0; 4]).await,
		Err(Error::Changed)
	));
	drop(window);
	assert!(matches!(source.finish().await, Err(Error::Closed)));
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);

	let mut long = Generated::new(HIGH_OFFSET);
	long.actual_length += 1;
	let (mut session, calls) = open(long).await;
	let mut source = session.open_positioned(&path()).await.unwrap();
	read_window(&mut source, 0, 3).await;
	assert!(matches!(source.finish().await, Err(Error::Changed)));
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
	assert!(matches!(session.stat(&path()).await, Err(Error::Closed)));
}

#[tokio::test]
async fn rechecks_metadata_at_window_admission_and_completion() {
	let mut changed = Generated::new(8);
	changed.changed_handle = true;
	let (mut session, calls) = open(changed).await;
	let mut source = session.open_positioned(&path()).await.unwrap();
	assert!(matches!(
		source.begin_window(0, 2).await,
		Err(Error::Changed)
	));
	assert!(matches!(source.finish().await, Err(Error::Closed)));
	assert_eq!(calls.read.load(Ordering::Relaxed), 0);

	for target in [ChangedObservation::Held, ChangedObservation::Named] {
		let mut changed = Generated::new(8);
		changed.change_during_window = Some(target);
		let (mut session, calls) = open(changed).await;
		let mut source = session.open_positioned(&path()).await.unwrap();
		let mut window = source.begin_window(1, 2).await.unwrap();
		assert_eq!(window.read_next(&mut [0; 2]).await.unwrap(), 2);
		assert!(matches!(window.finish().await, Err(Error::Changed)));
		assert!(matches!(source.finish().await, Err(Error::Closed)));
		assert_eq!(calls.close.load(Ordering::Relaxed), 0);
		assert!(matches!(session.stat(&path()).await, Err(Error::Closed)));
	}
}

#[tokio::test]
async fn unfinished_windows_and_sources_fence_the_session() {
	let (mut session, _) = open(Generated::new(5)).await;
	let mut source = session.open_positioned(&path()).await.unwrap();
	let mut window = source.begin_window(1, 2).await.unwrap();
	assert_eq!(window.read_next(&mut [0; 1]).await.unwrap(), 1);
	assert!(matches!(
		window.finish().await,
		Err(Error::IncompleteRead {
			expected: 2,
			read: 1
		})
	));
	assert!(matches!(source.finish().await, Err(Error::Closed)));
	assert!(matches!(session.stat(&path()).await, Err(Error::Closed)));

	let (mut session, _) = open(Generated::new(5)).await;
	let mut source = session.open_positioned(&path()).await.unwrap();
	drop(source.begin_window(1, 2).await.unwrap());
	assert!(matches!(source.finish().await, Err(Error::Closed)));
	assert!(matches!(session.stat(&path()).await, Err(Error::Closed)));

	let (mut session, calls) = open(Generated::new(5)).await;
	let mut source = session.open_positioned(&path()).await.unwrap();
	read_window(&mut source, 0, 2).await;
	drop(source);
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
	assert!(matches!(session.stat(&path()).await, Err(Error::Closed)));
}

#[tokio::test]
async fn cancelling_a_started_window_read_fences_the_handle_and_session() {
	let started = Arc::new(Notify::new());
	let mut generated = Generated::new(HIGH_OFFSET + 4);
	generated.pending_read = Some(started.clone());
	let (mut session, calls) = open(generated).await;
	let mut source = session.open_positioned(&path()).await.unwrap();
	let mut window = source.begin_window(HIGH_OFFSET, 4).await.unwrap();
	let mut chunk = [0; 4];
	{
		let read = window.read_next(&mut chunk);
		tokio::pin!(read);
		tokio::select! {
			_ = started.notified() => {}
			_ = &mut read => panic!("fixture read must remain in flight"),
			_ = tokio::time::sleep(Duration::from_secs(2)) => panic!("fixture read did not reach peer"),
		}
	}
	assert_eq!(calls.read.load(Ordering::Relaxed), 1);
	assert!(matches!(window.finish().await, Err(Error::Closed)));
	assert!(matches!(source.finish().await, Err(Error::Closed)));
	assert!(matches!(session.stat(&path()).await, Err(Error::Closed)));
}

#[tokio::test]
async fn request_budget_is_spent_by_short_replies_and_replenished_per_window() {
	const FIRST_LENGTH: u64 = 4096;
	let mut generated = Generated::new(FIRST_LENGTH * 2 + 1);
	generated.max_reply = 1;
	let (mut session, calls) = open(generated).await;
	let mut source = session.open_positioned(&path()).await.unwrap();
	read_window(&mut source, 0, FIRST_LENGTH).await;

	let mut window = source
		.begin_window(FIRST_LENGTH, FIRST_LENGTH + 1)
		.await
		.unwrap();
	for _ in 0..FIRST_LENGTH {
		assert_eq!(window.read_next(&mut [0; 8]).await.unwrap(), 1);
	}
	assert!(matches!(
		window.read_next(&mut [0; 8]).await,
		Err(Error::Limit)
	));
	drop(window);
	assert_eq!(calls.read.load(Ordering::Relaxed) as u64, FIRST_LENGTH * 2);
	assert!(matches!(source.finish().await, Err(Error::Closed)));
}

#[tokio::test]
#[ignore = "waits for the actual 20-second per-window deadline"]
async fn window_deadline_includes_caller_processing() {
	let (mut session, calls) = open(Generated::new(6)).await;
	let mut source = session.open_positioned(&path()).await.unwrap();
	let mut window = source.begin_window(0, 6).await.unwrap();
	assert_eq!(window.read_next(&mut [0; 3]).await.unwrap(), 3);

	tokio::time::sleep(Duration::from_secs(20)).await;

	assert!(matches!(
		window.read_next(&mut [0; 3]).await,
		Err(Error::Timeout)
	));
	drop(window);
	assert_eq!(calls.read.load(Ordering::Relaxed), 1);
	assert!(matches!(source.finish().await, Err(Error::Closed)));
}

#[tokio::test]
#[ignore = "checks total source lifetime beyond one 20-second operation deadline"]
async fn source_lifetime_spans_multiple_window_deadlines() {
	let (mut session, calls) = open(Generated::new(6)).await;
	let mut source = session.open_positioned(&path()).await.unwrap();
	read_window(&mut source, 0, 2).await;

	// Each gap fits the connection inactivity limit. Together they exceed
	// one operation deadline without keeping a window open.
	for offset in [2, 4] {
		tokio::time::sleep(Duration::from_secs(11)).await;
		read_window(&mut source, offset, 2).await;
	}

	assert_eq!(source.finish().await.unwrap().length, 6);
	assert_eq!(calls.open.load(Ordering::Relaxed), 1);
	assert_eq!(calls.close.load(Ordering::Relaxed), 1);
}
