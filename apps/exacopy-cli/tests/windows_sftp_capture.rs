//! Opt-in foreground Windows NTFS and in-process SSH/SFTP capture control.
#![cfg(target_os = "windows")]

use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::num::{NonZeroU16, NonZeroU64, NonZeroU128};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use exacopy_cli::assembly::windows_capture::{
	WindowsCaptureAuthorization, WindowsCaptureError, WindowsCaptureGrant, WindowsCaptureJob,
	WindowsCaptureSource, WindowsFreshCapture, capture_fresh_windows_sftp,
};
use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::connection_retry::RetryOwner;
use exacopy_endpoint::remote_source::SourceEpoch;
use exacopy_endpoint::ssh_sftp::{
	CredentialSource, HostKeyFingerprint, InteractionPolicy, SshAuthority,
};
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::windows_capture::{
	MAX_CAPTURE_SEGMENT_BYTES, WindowsCaptureRoles, WindowsCaptureSelection, inspect,
};
use exacopy_platform::ProtectedSnapshotError;
use exacopy_platform::windows::{
	WindowsBootstrapRoleKind::{Directory, RegularFile},
	WindowsComponent, WindowsStageIdentity,
};
use russh::keys::PrivateKey;

#[path = "windows_sftp_capture/native.rs"]
mod native;
#[path = "windows_sftp_capture/peer.rs"]
mod peer;

use native::{
	Fixture, INCUMBENT, Job, OCCUPIED, absent, bounded_bytes, identity, metadata, reader,
};

const DEADLINE: Duration = Duration::from_secs(15);

struct Route<'a> {
	authority: &'a SshAuthority,
	peer: SocketAddr,
	key: &'a PrivateKey,
	path: &'a [UnixComponent<'a>],
	target: &'a [u16],
}

impl Route<'_> {
	fn source(&self) -> WindowsCaptureSource<'_> {
		WindowsCaptureSource {
			authority: self.authority,
			peer: self.peer,
			host_fingerprint: peer::fingerprint(self.key),
			path: self.path,
			extent_ceiling: peer::SOURCE_BYTES.len() as u64,
		}
	}

	fn grant<'a>(
		&'a self,
		job: &Job,
		sibling: WindowsStageIdentity,
		row: u8,
	) -> WindowsCaptureGrant<'a> {
		WindowsCaptureGrant::issue(WindowsCaptureAuthorization {
			nonce: [row; 32],
			source_scope: self.source().scope_digest().unwrap(),
			owner_digest: job.historical.owner_digest(),
			bootstrap_head: job.historical.boundary().head(),
			sibling: identity(sibling),
			supervisor: RetryOwner::new(NonZeroU128::new(u128::from(row)).unwrap()),
			epoch: SourceEpoch::new(NonZeroU64::new(u64::from(row)).unwrap()),
			target: WindowsComponent::new(self.target).unwrap(),
			extent_ceiling: self.source().extent_ceiling,
			expires_at: Instant::now() + DEADLINE,
		})
		.unwrap()
	}

	fn request<'a>(
		&'a self,
		fixture: &'a Fixture,
		job: &'a Job,
		signer: &'a SigningKey,
		key: &'a ed25519_dalek::VerifyingKey,
		sibling: WindowsStageIdentity,
		grant: &'a WindowsCaptureGrant<'a>,
	) -> WindowsFreshCapture<'a> {
		WindowsFreshCapture {
			job: WindowsCaptureJob {
				root: &fixture.root,
				bootstrap: job.select(key),
				roles: job.roles,
				sibling,
				bytes: &job.bytes,
				signing_key: signer,
			},
			source: self.source(),
			host_trust: peer::trust(self.authority, self.key),
			grant,
		}
	}
}

#[tokio::test]
#[ignore = "requires independently provisioned protected Windows NTFS capture roles"]
async fn captures_real_sftp_only_into_the_selected_original_ntfs_job() {
	let fixture = Fixture::select();
	let signer = SigningKey::from_bytes(&[41; 32]);
	let key = signer.verifying_key();
	let job = fixture.populate(false, &signer);
	let occupied = fixture.populate(true, &signer);
	let incumbent = fixture.root.join("existing-target");
	let incumbent_id = fixture.observe(&reader(&incumbent), RegularFile);
	fixture.confirm_record(&incumbent, incumbent_id, INCUMBENT);
	let target = "private-output";
	let target_units: Vec<_> = target.encode_utf16().collect();
	let target_path = fixture.root.join(target);
	absent(&target_path);

	let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
	listener.set_nonblocking(true).unwrap();
	let address = listener.local_addr().unwrap();
	let authority = SshAuthority::new(
		"127.0.0.1",
		NonZeroU16::new(address.port()).unwrap(),
		"transfer",
	)
	.unwrap();
	let host_key = peer::key();
	let path = [UnixComponent::new(peer::SOURCE_NAME).unwrap()];
	let route = Route {
		authority: &authority,
		peer: address,
		key: &host_key,
		path: &path,
		target: &target_units,
	};
	for (row, candidate, sibling, sibling_bytes) in [
		(1, &job, incumbent_id, &[][..]),
		(2, &job, job.sibling_id, &[][..]),
		(3, &occupied, occupied.sibling_id, OCCUPIED),
	] {
		let busy = (row == 2).then(|| reader(&job.sibling));
		let grant = route.grant(candidate, sibling, row);
		let failure = capture_fresh_windows_sftp(
			route.request(&fixture, candidate, &signer, &key, sibling, &grant),
			async |_| panic!("locally refused custody contacted the credential broker"),
			|_| panic!("locally refused custody reached selection retention"),
		)
		.await
		.expect_err("unsafe native sibling was admitted");
		assert!(
			match row {
				2 => matches!(
					failure.cause(),
					WindowsCaptureError::Custody(ProtectedSnapshotError::Busy)
				),
				_ => matches!(
					failure.cause(),
					WindowsCaptureError::Custody(ProtectedSnapshotError::Changed)
				),
			},
			"unexpected refusal at row {row}: {failure:?}"
		);
		let progress = failure.progress();
		assert!(!progress.local_changes_may_exist);
		assert!(progress.selection.is_none());
		assert!(progress.bootstrap.is_none());
		assert!(progress.checkpoint.is_none());
		assert!(progress.measured.is_none());
		assert!(!progress.native_closeout_confirmed);
		assert!(!progress.route_shutdown_confirmed);
		drop(busy);
		assert_eq!(
			listener.accept().unwrap_err().kind(),
			std::io::ErrorKind::WouldBlock
		);
		fixture.confirm_record(
			&candidate.owner,
			candidate.roles.owner_file,
			&candidate.bytes.owner,
		);
		fixture.confirm_record(&candidate.first, candidate.roles.first_segment, &[]);
		fixture.confirm_record(&candidate.sibling, candidate.sibling_id, sibling_bytes);
		fixture.confirm_record(&incumbent, incumbent_id, INCUMBENT);
		absent(&candidate.path.join("stage"));
		absent(&target_path);
	}

	let calls = Arc::new(peer::Calls::default());
	let source_bytes: Arc<[u8]> = Arc::from(peer::SOURCE_BYTES);
	let mut server = tokio::spawn(peer::serve(
		tokio::net::TcpListener::from_std(listener).unwrap(),
		host_key.clone(),
		source_bytes.clone(),
		calls.clone(),
	));
	let receipt = Cell::new(None);
	let credential_calls = Cell::new(0);
	let grant = route.grant(&job, job.sibling_id, 4);
	let result = capture_fresh_windows_sftp(
		route.request(&fixture, &job, &signer, &key, job.sibling_id, &grant),
		async |request| {
			credential_calls.set(credential_calls.get() + 1);
			assert_eq!(request.authority(), &authority);
			assert_eq!(
				request.fingerprint(),
				HostKeyFingerprint::from_sha256(peer::fingerprint(&host_key))
			);
			assert_eq!(request.source(), CredentialSource::SuppliedKey);
			assert_eq!(request.interaction(), InteractionPolicy::Forbidden);
			peer::credential()
		},
		|selected| {
			assert_eq!(calls.opens.load(Relaxed), 1);
			assert_eq!(calls.reads.load(Relaxed), 0);
			assert_eq!(calls.closes.load(Relaxed), 0);
			fixture.observe_record_extent(&job.first, job.roles.first_segment, 0);
			fixture.observe_record_extent(&job.sibling, job.sibling_id, 0);
			fixture.observe_record_extent(
				&job.owner,
				job.roles.owner_file,
				job.bytes.owner.len() as u64,
			);
			fixture.confirm_record(&incumbent, incumbent_id, INCUMBENT);
			absent(&job.path.join("stage"));
			absent(&target_path);
			assert!(receipt.replace(Some(selected)).is_none());
			Ok(())
		},
	)
	.await;
	if result.is_err() {
		server.abort();
		let _ = server.await;
		panic!("admitted fresh SDK invocation refused: {result:?}");
	}
	match tokio::time::timeout(DEADLINE, &mut server).await {
		Ok(done) => done.unwrap(),
		Err(_) => {
			server.abort();
			let _ = server.await;
			panic!("in-process peer did not drain");
		}
	}
	let report = result.unwrap();
	let retained = receipt.get().expect("selection is retained before effects");
	assert_eq!(retained, report.selection);
	assert_eq!(
		retained.source_scope,
		route.source().scope_digest().unwrap()
	);
	assert_eq!(retained.epoch.get(), 4);
	assert_eq!(retained.generation, 1);
	assert_eq!(retained.extent_ceiling, peer::SOURCE_BYTES.len() as u64);
	assert_ne!(retained.invocation, [0; 32]);
	assert_eq!(credential_calls.get(), 1);
	assert_eq!(calls.key.load(Relaxed), 1);
	assert_eq!(calls.subsystem.load(Relaxed), 1);
	assert_eq!(calls.opens.load(Relaxed), 1);
	assert!(calls.named_stat.load(Relaxed) > 0);
	assert!(calls.held_stat.load(Relaxed) > 0);
	assert!(calls.reads.load(Relaxed) > 1);
	assert_eq!(calls.eof.load(Relaxed), 1);
	assert_eq!(calls.closes.load(Relaxed), 1);
	assert_eq!(calls.unsupported.load(Relaxed), 0);

	assert_eq!(source_bytes.as_ref(), peer::SOURCE_BYTES);
	let digest = blake3::hash(peer::SOURCE_BYTES);
	assert_eq!(report.stream.source_digest, *digest.as_bytes());
	assert_eq!(report.stream.stage_digest.as_bytes(), digest.as_bytes());
	assert_eq!(report.stream.epoch, retained.epoch);
	assert_eq!(report.stream.length, peer::SOURCE_BYTES.len() as u64);

	let stage = job.path.join("stage");
	let stage_directory = fixture.observe(&metadata(&stage, true), Directory);
	let payload = stage.join("payload");
	let stage_payload = fixture.observe(&reader(&payload), RegularFile);
	assert_eq!(identity(stage_directory), report.stage_directory);
	assert_eq!(identity(stage_payload), report.stage_payload);
	fixture.confirm_record(&payload, stage_payload, peer::SOURCE_BYTES);
	fixture.confirm_record(&incumbent, incumbent_id, INCUMBENT);
	absent(&target_path);

	let historical = fixture.inspect_bootstrap(&job, &key);
	fixture.confirm_record(
		&job.first,
		job.roles.first_segment,
		&job.bytes.first_segment,
	);
	let sibling_file = reader(&job.sibling);
	assert_eq!(fixture.observe(&sibling_file, RegularFile), job.sibling_id);
	let encoded = bounded_bytes(&sibling_file, MAX_CAPTURE_SEGMENT_BYTES);
	fixture.observe_record_extent(&job.sibling, job.sibling_id, encoded.len() as u64);
	let prefix = inspect(
		&encoded[..],
		&WindowsCaptureSelection {
			bootstrap: &historical,
			sibling: identity(job.sibling_id),
			source_scope: retained.source_scope,
			invocation: retained.invocation,
			generation: retained.generation,
			epoch: retained.epoch.get(),
			extent_ceiling: retained.extent_ceiling,
			target: &target_units,
		},
		WindowsCaptureRoles {
			sibling: identity(job.sibling_id),
			stage_directory: identity(stage_directory),
			stage_payload: identity(stage_payload),
		},
	)
	.unwrap();
	assert_eq!(prefix, report.prefix);
	assert_eq!(prefix.observed_extent(), report.stream.length);
	assert_eq!(prefix.covered_bytes(), report.stream.length);
	assert_eq!(prefix.ranges(), 1);
	assert_eq!(prefix.head().sequence(), 2);
	assert_eq!(prefix.segment_end(), encoded.len() as u64);
	let mut frames = FrameReader::new(&encoded[..], ChainHead::start());
	assert_eq!(
		frames.next_frame().unwrap().unwrap().kind(),
		FrameKind::WindowsCapturePrepared
	);
	let range = frames.next_frame().unwrap().unwrap();
	assert_eq!(range.kind(), FrameKind::WindowsCaptureRange);
	// Fixed v1 range body: version, prepared and previous digests, ordinal, offset, length, digest.
	assert_eq!(&range.payload()[84..116], digest.as_bytes());
	assert!(frames.next_frame().unwrap().is_none());
}
