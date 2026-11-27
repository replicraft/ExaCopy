use std::sync::atomic::Ordering;

use exacopy_endpoint::ssh_sftp::SftpVersionError;
use exacopy_ssh::{Error, Password, connect};

use super::peer::{SECRET, authority, fixture_trust, peer_with_sftp_version};

#[tokio::test]
async fn an_unsupported_sftp_version_cannot_create_a_read_only_session() {
	const UNSUPPORTED_VERSION: u32 = 4;
	let (stream, pin, calls) = peer_with_sftp_version(UNSUPPORTED_VERSION);
	let target = authority("transfer");
	let result = connect(
		stream,
		&target,
		pin,
		fixture_trust(&target, ""),
		&target,
		|_| Password::new(SECRET.to_owned()),
	)
	.await;

	let Err(error) = result else {
		panic!("unsupported SFTP version granted a read-only session");
	};
	assert!(
		matches!(
			error,
			Error::Version(SftpVersionError {
				version: UNSUPPORTED_VERSION
			})
		),
		"expected typed refusal for the selected SFTP version, got {error:?}"
	);
	assert_eq!(calls.auth.load(Ordering::Relaxed), 1);
	assert_eq!(calls.subsystem.load(Ordering::Relaxed), 1);
	assert_eq!(calls.init.load(Ordering::Relaxed), 1);
	assert_eq!(calls.unsupported.load(Ordering::Relaxed), 0);
	assert_eq!(calls.named_stat.load(Ordering::Relaxed), 0);
	assert_eq!(calls.held_stat.load(Ordering::Relaxed), 0);
	assert_eq!(calls.open.load(Ordering::Relaxed), 0);
	assert_eq!(calls.read.load(Ordering::Relaxed), 0);
	assert_eq!(calls.close.load(Ordering::Relaxed), 0);
}
