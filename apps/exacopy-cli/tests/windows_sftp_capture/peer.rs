use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_endpoint::ssh_sftp::SshAuthority;
use exacopy_ssh::{Ed25519Key, KnownHostTrust};
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use russh::{Channel, ChannelId, server};
use russh_sftp::{protocol as sftp, server as sftp_server};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

pub(crate) const SOURCE_NAME: &[u8] = b"\xff-synthetic-source";
pub(crate) const SOURCE_BYTES: &[u8] = b"original synthetic SFTP bytes across short replies";
const HOST_SEED: [u8; 32] = [17; 32];
const CLIENT_SEED: [u8; 32] = [32; 32];
const HANDLE: &[u8] = &[0, 255];

#[derive(Default)]
pub(crate) struct Calls {
	pub(crate) key: AtomicUsize,
	pub(crate) subsystem: AtomicUsize,
	pub(crate) named_stat: AtomicUsize,
	pub(crate) held_stat: AtomicUsize,
	pub(crate) opens: AtomicUsize,
	pub(crate) reads: AtomicUsize,
	pub(crate) eof: AtomicUsize,
	pub(crate) closes: AtomicUsize,
	pub(crate) unsupported: AtomicUsize,
}

pub(crate) fn key() -> PrivateKey {
	PrivateKey::new(
		KeypairData::Ed25519(Ed25519Keypair::from_seed(&HOST_SEED)),
		"",
	)
	.unwrap()
}

pub(crate) fn credential() -> Result<Ed25519Key, exacopy_ssh::Error> {
	Ed25519Key::from_seed(Zeroizing::new(CLIENT_SEED))
}

pub(crate) fn fingerprint(key: &PrivateKey) -> [u8; 32] {
	key.public_key()
		.fingerprint(HashAlg::Sha256)
		.sha256()
		.unwrap()
}

pub(crate) fn trust(authority: &SshAuthority, key: &PrivateKey) -> KnownHostTrust {
	let entry = format!(
		"[{}]:{} {}\n",
		authority.host(),
		authority.port(),
		key.public_key().to_openssh().unwrap(),
	);
	KnownHostTrust::from_snapshot(authority, Ok(entry.as_bytes())).unwrap()
}

pub(crate) async fn serve(
	listener: TcpListener,
	key: PrivateKey,
	source: Arc<[u8]>,
	calls: Arc<Calls>,
) {
	let (socket, address) = listener.accept().await.unwrap();
	assert!(address.ip().is_loopback());
	let config = server::Config {
		keys: vec![key],
		..server::Config::default()
	};
	let peer = Peer {
		channel: None,
		files: Some(Files {
			source,
			calls: calls.clone(),
		}),
		calls,
	};
	let session = server::run_stream(Arc::new(config), socket, peer)
		.await
		.unwrap();
	session.await.unwrap();
}

struct Peer {
	channel: Option<Channel<server::Msg>>,
	files: Option<Files>,
	calls: Arc<Calls>,
}

impl server::Handler for Peer {
	type Error = russh::Error;

	async fn auth_publickey(
		&mut self,
		user: &str,
		key: server::VerifiedPublicKey<'_>,
	) -> Result<server::Auth, Self::Error> {
		self.calls.key.fetch_add(1, Ordering::Relaxed);
		let public = Ed25519Keypair::from_seed(&CLIENT_SEED).public;
		Ok(
			if user == "transfer"
				&& key.algorithm == &Algorithm::Ed25519
				&& key.public_key.key_data().ed25519() == Some(&public)
			{
				server::Auth::Accept
			} else {
				server::Auth::reject()
			},
		)
	}

	async fn channel_open_session(
		&mut self,
		channel: Channel<server::Msg>,
		reply: server::ChannelOpenHandle,
		_session: &mut server::Session,
	) -> Result<(), Self::Error> {
		assert!(self.channel.replace(channel).is_none());
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
		session.channel_success(id)?;
		let channel = self.channel.take().unwrap().into_stream();
		sftp_server::run(channel, self.files.take().unwrap()).await;
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
	source: Arc<[u8]>,
	calls: Arc<Calls>,
}

impl Files {
	fn attrs(&self, id: u32) -> sftp::Attrs {
		sftp::Attrs {
			id,
			attrs: sftp::FileAttributes {
				size: Some(self.source.len() as u64),
				uid: Some(1001),
				gid: Some(1002),
				permissions: Some(0o100600),
				atime: Some(11),
				mtime: Some(12),
				..sftp::FileAttributes::empty()
			},
		}
	}
}

impl sftp_server::Handler for Files {
	type Error = sftp::StatusCode;

	fn unimplemented(&self) -> Self::Error {
		self.calls.unsupported.fetch_add(1, Ordering::Relaxed);
		sftp::StatusCode::OpUnsupported
	}

	async fn init(
		&mut self,
		version: u32,
		_extensions: HashMap<String, String>,
	) -> Result<sftp::Version, Self::Error> {
		assert_eq!(version, sftp::VERSION);
		Ok(sftp::Version {
			version,
			extensions: HashMap::new(),
		})
	}

	async fn lstat(&mut self, id: u32, path: sftp::SftpString) -> Result<sftp::Attrs, Self::Error> {
		assert_eq!(path.as_bytes(), SOURCE_NAME);
		self.calls.named_stat.fetch_add(1, Ordering::Relaxed);
		Ok(self.attrs(id))
	}

	async fn fstat(&mut self, id: u32, file: sftp::SftpHandle) -> Result<sftp::Attrs, Self::Error> {
		assert_eq!(file.as_bytes(), HANDLE);
		self.calls.held_stat.fetch_add(1, Ordering::Relaxed);
		Ok(self.attrs(id))
	}

	async fn open(
		&mut self,
		id: u32,
		name: sftp::SftpString,
		flags: sftp::OpenFlags,
		_attrs: sftp::FileAttributes,
	) -> Result<sftp::Handle, Self::Error> {
		assert_eq!(name.as_bytes(), SOURCE_NAME);
		assert_eq!(flags.bits(), sftp::OpenFlags::READ.bits());
		self.calls.opens.fetch_add(1, Ordering::Relaxed);
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
		assert_eq!(file.as_bytes(), HANDLE);
		assert!(len > 0);
		self.calls.reads.fetch_add(1, Ordering::Relaxed);
		let start = usize::try_from(offset).unwrap();
		assert!(start <= self.source.len());
		if start == self.source.len() {
			assert_eq!(len, 1);
			assert_eq!(self.calls.closes.load(Ordering::Relaxed), 0);
			self.calls.eof.fetch_add(1, Ordering::Relaxed);
			return Err(sftp::StatusCode::Eof);
		}
		let end = (start + len.min(3) as usize).min(self.source.len());
		Ok(sftp::Data {
			id,
			data: self.source[start..end].to_vec(),
		})
	}

	async fn close(
		&mut self,
		id: u32,
		file: sftp::SftpHandle,
	) -> Result<sftp::Status, Self::Error> {
		assert_eq!(file.as_bytes(), HANDLE);
		self.calls.closes.fetch_add(1, Ordering::Relaxed);
		Ok(sftp::Status {
			id,
			status_code: sftp::StatusCode::Ok,
			error_message: String::new(),
			language_tag: String::new(),
		})
	}
}
