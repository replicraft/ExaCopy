use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use exacopy_endpoint::ssh_sftp::{HostKeyFingerprint, SshAuthority};
use exacopy_ssh::KnownHostTrust;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{HashAlg, PrivateKey};
use russh::{Channel, ChannelId, server};
use russh_sftp::{protocol as sftp, server as sftp_server};
use tokio::io::DuplexStream;
use tokio::sync::{Notify, oneshot};

use super::key_auth;

pub(super) const NAME: &[u8] = b"\xfffile";
pub(super) const CONTENT: &[u8] = b"abcde";
pub(super) const SECRET: &str = "synthetic-fixture-only";

#[derive(Default)]
pub(super) struct Calls {
	pub(super) auth: AtomicUsize,
	pub(super) key_auth: AtomicUsize,
	pub(super) subsystem: AtomicUsize,
	pub(super) unsupported: AtomicUsize,
	pub(super) open: AtomicUsize,
	pub(super) close: AtomicUsize,
	pub(super) read: AtomicUsize,
	pub(super) held_stat: AtomicUsize,
	pub(super) named_stat: AtomicUsize,
}

struct Peer {
	channel: Option<Channel<server::Msg>>,
	calls: Arc<Calls>,
	subsystem: bool,
	early_eof: bool,
	generated: Option<Generated>,
}

impl server::Handler for Peer {
	type Error = russh::Error;

	async fn auth_password(
		&mut self,
		user: &str,
		password: &str,
	) -> Result<server::Auth, Self::Error> {
		self.calls.auth.fetch_add(1, Ordering::Relaxed);
		Ok(if user == "transfer" && password == SECRET {
			server::Auth::Accept
		} else {
			server::Auth::reject()
		})
	}

	async fn auth_publickey(
		&mut self,
		user: &str,
		key: server::VerifiedPublicKey<'_>,
	) -> Result<server::Auth, Self::Error> {
		self.calls.key_auth.fetch_add(1, Ordering::Relaxed);
		Ok(key_auth::verify_credentials(user, key))
	}

	async fn channel_open_session(
		&mut self,
		channel: Channel<server::Msg>,
		reply: server::ChannelOpenHandle,
		_session: &mut server::Session,
	) -> Result<(), Self::Error> {
		self.channel = Some(channel);
		reply.accept().await;
		Ok(())
	}

	async fn subsystem_request(
		&mut self,
		id: ChannelId,
		name: &str,
		session: &mut server::Session,
	) -> Result<(), Self::Error> {
		assert_eq!(name, "sftp");
		self.calls.subsystem.fetch_add(1, Ordering::Relaxed);
		if !self.subsystem {
			return session.channel_failure(id);
		}
		session.channel_success(id)?;
		let state = Files {
			calls: self.calls.clone(),
			listed: false,
			early_eof: self.early_eof,
			generated: self.generated.take(),
			held_checks: 0,
		};
		sftp_server::run(self.channel.take().unwrap().into_stream(), state).await;
		Ok(())
	}

	async fn exec_request(
		&mut self,
		id: ChannelId,
		_data: &[u8],
		session: &mut server::Session,
	) -> Result<(), Self::Error> {
		self.calls.unsupported.fetch_add(1, Ordering::Relaxed);
		session.channel_failure(id)
	}
}

struct Files {
	calls: Arc<Calls>,
	listed: bool,
	early_eof: bool,
	generated: Option<Generated>,
	held_checks: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ChangedObservation {
	Held,
	Named,
}

pub(super) struct Generated {
	pub(super) selected_name: &'static [u8],
	pub(super) observed_length: u64,
	pub(super) actual_length: u64,
	pub(super) max_reply: u32,
	pub(super) changed_handle: bool,
	pub(super) changed_name: bool,
	pub(super) change_during_window: Option<ChangedObservation>,
	pub(super) refuse_close: bool,
	pub(super) pending_read: Option<Arc<Notify>>,
}

impl Generated {
	pub(super) const fn new(length: u64) -> Self {
		Self {
			selected_name: NAME,
			observed_length: length,
			actual_length: length,
			max_reply: 4093,
			changed_handle: false,
			changed_name: false,
			change_during_window: None,
			refuse_close: false,
			pending_read: None,
		}
	}
}

impl Files {
	fn selected_name(&self) -> &[u8] {
		self.generated
			.as_ref()
			.map_or(NAME, |generated| generated.selected_name)
	}

	fn changed_during_window(&self, observation: ChangedObservation) -> bool {
		self.calls.read.load(Ordering::Relaxed) != 0
			&& self
				.generated
				.as_ref()
				.is_some_and(|file| file.change_during_window == Some(observation))
	}

	fn attributes(&self, changed: bool) -> sftp::FileAttributes {
		let mut attrs = file_attrs();
		if let Some(generated) = &self.generated {
			attrs.size = Some(generated.observed_length);
			if changed {
				attrs.mtime = Some(23);
			}
		}
		attrs
	}
}

fn file_attrs() -> sftp::FileAttributes {
	sftp::FileAttributes {
		size: Some(CONTENT.len() as u64),
		permissions: Some(0o100600),
		mtime: Some(22),
		..sftp::FileAttributes::empty()
	}
}

impl sftp_server::Handler for Files {
	type Error = sftp::StatusCode;

	fn unimplemented(&self) -> Self::Error {
		self.calls.unsupported.fetch_add(1, Ordering::Relaxed);
		sftp::StatusCode::OpUnsupported
	}

	async fn lstat(&mut self, id: u32, path: sftp::SftpString) -> Result<sftp::Attrs, Self::Error> {
		assert_eq!(path.as_bytes(), self.selected_name());
		self.calls.named_stat.fetch_add(1, Ordering::Relaxed);
		let changed = self
			.generated
			.as_ref()
			.is_some_and(|file| file.changed_name)
			&& self.calls.close.load(Ordering::Relaxed) != 0;
		let changed = changed || self.changed_during_window(ChangedObservation::Named);
		Ok(sftp::Attrs {
			id,
			attrs: self.attributes(changed),
		})
	}

	async fn fstat(&mut self, id: u32, file: sftp::SftpHandle) -> Result<sftp::Attrs, Self::Error> {
		assert_eq!(file.as_bytes(), &[0, 255]);
		self.calls.held_stat.fetch_add(1, Ordering::Relaxed);
		self.held_checks += 1;
		let changed = self
			.generated
			.as_ref()
			.is_some_and(|file| file.changed_handle)
			&& self.held_checks > 1;
		let changed = changed || self.changed_during_window(ChangedObservation::Held);
		Ok(sftp::Attrs {
			id,
			attrs: self.attributes(changed),
		})
	}

	async fn opendir(
		&mut self,
		id: u32,
		path: sftp::SftpString,
	) -> Result<sftp::Handle, Self::Error> {
		assert_eq!(path.as_bytes(), b".");
		Ok(sftp::Handle {
			id,
			handle: sftp::SftpHandle::from("directory"),
		})
	}

	async fn readdir(&mut self, id: u32, dir: sftp::SftpHandle) -> Result<sftp::Name, Self::Error> {
		assert_eq!(dir.as_bytes(), b"directory");
		if std::mem::replace(&mut self.listed, true) {
			return Err(sftp::StatusCode::Eof);
		}
		Ok(sftp::Name {
			id,
			files: vec![
				sftp::File::dummy("."),
				sftp::File::dummy(".."),
				sftp::File::dummy(sftp::SftpString::from(NAME)),
			],
		})
	}

	async fn open(
		&mut self,
		id: u32,
		name: sftp::SftpString,
		flags: sftp::OpenFlags,
		_attrs: sftp::FileAttributes,
	) -> Result<sftp::Handle, Self::Error> {
		assert_eq!(name.as_bytes(), self.selected_name());
		assert_eq!(flags.bits(), sftp::OpenFlags::READ.bits());
		self.calls.open.fetch_add(1, Ordering::Relaxed);
		Ok(sftp::Handle {
			id,
			handle: sftp::SftpHandle::from(&[0, 255]),
		})
	}

	async fn read(
		&mut self,
		id: u32,
		file: sftp::SftpHandle,
		offset: u64,
		len: u32,
	) -> Result<sftp::Data, Self::Error> {
		assert_eq!(file.as_bytes(), &[0, 255]);
		assert!(len > 0);
		self.calls.read.fetch_add(1, Ordering::Relaxed);
		if let Some(generated) = &self.generated {
			if let Some(started) = &generated.pending_read {
				started.notify_one();
				std::future::pending::<()>().await;
			}
			let remaining = generated.actual_length.saturating_sub(offset);
			let count = remaining.min(u64::from(len.min(generated.max_reply)));
			if count == 0 {
				return Err(sftp::StatusCode::Eof);
			}
			let data = (offset..offset + count)
				.map(|index| (index % 251) as u8)
				.collect();
			return Ok(sftp::Data { id, data });
		}
		let start = usize::try_from(offset).unwrap();
		if start >= CONTENT.len() || self.early_eof {
			return Err(sftp::StatusCode::Eof);
		}
		let end = (start + (len as usize).min(2)).min(CONTENT.len());
		Ok(sftp::Data {
			id,
			data: CONTENT[start..end].to_vec(),
		})
	}

	async fn close(
		&mut self,
		id: u32,
		_file: sftp::SftpHandle,
	) -> Result<sftp::Status, Self::Error> {
		self.calls.close.fetch_add(1, Ordering::Relaxed);
		if self
			.generated
			.as_ref()
			.is_some_and(|file| file.refuse_close)
		{
			return Err(sftp::StatusCode::Failure);
		}
		Ok(sftp::Status {
			id,
			status_code: sftp::StatusCode::Ok,
			error_message: String::new(),
			language_tag: String::new(),
		})
	}
}

pub(super) fn peer(
	subsystem: bool,
	early_eof: bool,
) -> (DuplexStream, HostKeyFingerprint, Arc<Calls>) {
	let (stream, pin, calls, _) = peer_with_handle(subsystem, early_eof);
	(stream, pin, calls)
}

pub(super) fn peer_with_handle(
	subsystem: bool,
	early_eof: bool,
) -> (
	DuplexStream,
	HostKeyFingerprint,
	Arc<Calls>,
	oneshot::Receiver<server::Handle>,
) {
	peer_with_rekey(
		subsystem,
		early_eof,
		server::Config::default().limits.rekey_time_limit,
		None,
	)
}

pub(super) fn peer_with_rekey(
	subsystem: bool,
	early_eof: bool,
	rekey_time_limit: Duration,
	terminated: Option<oneshot::Sender<()>>,
) -> (
	DuplexStream,
	HostKeyFingerprint,
	Arc<Calls>,
	oneshot::Receiver<server::Handle>,
) {
	configured_peer(subsystem, early_eof, rekey_time_limit, terminated, None)
}

pub(super) fn generated_peer(
	generated: Generated,
) -> (DuplexStream, HostKeyFingerprint, Arc<Calls>) {
	let (stream, fingerprint, calls, _) = configured_peer(
		true,
		false,
		server::Config::default().limits.rekey_time_limit,
		None,
		Some(generated),
	);
	(stream, fingerprint, calls)
}

fn configured_peer(
	subsystem: bool,
	early_eof: bool,
	rekey_time_limit: Duration,
	terminated: Option<oneshot::Sender<()>>,
	generated: Option<Generated>,
) -> (
	DuplexStream,
	HostKeyFingerprint,
	Arc<Calls>,
	oneshot::Receiver<server::Handle>,
) {
	let key = fixture_key();
	let pin = HostKeyFingerprint::from_sha256(
		key.public_key()
			.fingerprint(HashAlg::Sha256)
			.sha256()
			.unwrap(),
	);
	let (client, socket) = tokio::io::duplex(64 * 1024);
	let calls = Arc::new(Calls::default());
	let peer = Peer {
		channel: None,
		calls: calls.clone(),
		subsystem,
		early_eof,
		generated,
	};
	let config = server::Config {
		keys: vec![key],
		limits: russh::Limits::new(1 << 30, 1 << 30, rekey_time_limit),
		..server::Config::default()
	};
	let (send_handle, receive_handle) = oneshot::channel();
	tokio::spawn(async move {
		if let Ok(session) = server::run_stream(Arc::new(config), socket, peer).await {
			let _ = send_handle.send(session.handle());
			let _ = session.await;
		}
		if let Some(terminated) = terminated {
			let _ = terminated.send(());
		}
	});
	(client, pin, calls, receive_handle)
}

pub(super) fn fixture_key() -> PrivateKey {
	let seed = Ed25519Keypair::from_seed(&[17; 32]);
	PrivateKey::new(KeypairData::Ed25519(seed), "").unwrap()
}

pub(super) fn fixture_trust(target: &SshAuthority, marker: &str) -> KnownHostTrust {
	let key = fixture_key().public_key().to_openssh().unwrap();
	let record = format!("{marker}{} {key}", target.host());
	KnownHostTrust::from_snapshot(target, Ok(record.as_bytes())).unwrap()
}

pub(super) fn authority(account: &str) -> SshAuthority {
	SshAuthority::new("sftp.example", NonZeroU16::new(22).unwrap(), account).unwrap()
}
