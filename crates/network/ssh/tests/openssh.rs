//! Optional interoperability test against a private, current-user OpenSSH server.
#![cfg(all(
	feature = "experimental-ssh",
	any(target_os = "macos", target_os = "linux")
))]

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::num::NonZeroU16;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::ssh_sftp::{
	CredentialSource, HostKeyFingerprint, InteractionPolicy, SshAuthority,
};
use exacopy_ssh::{Ed25519Key, KnownHostTrust, connect_with_ed25519};
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

const SSHD: &str = "/usr/sbin/sshd";
const KEYGEN: &str = "/usr/bin/ssh-keygen";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(3);
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(25);
const MAX_DIAGNOSTIC_BYTES: u64 = 4096;
const FILE_NAME: &str = "fixture.bin";
const CONTENT: &[u8] = b"independent OpenSSH readback";

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
#[ignore = "requires a local OpenSSH server executable and unprivileged loopback sockets"]
async fn reads_a_file_from_a_private_openssh_subsystem_with_ed25519() {
	let fixture = Fixture::create().unwrap();
	let account = current_account().unwrap();
	assert_ne!(
		account, "root",
		"fixture requires the current unprivileged user"
	);
	fixture.configure(&account).unwrap();
	let (stream, port, mut daemon) = fixture.start().unwrap();

	let result = tokio::time::timeout(
		FIXTURE_TIMEOUT,
		check_contents(&fixture, &account, stream, port),
	)
	.await;
	daemon.stop();
	let diagnostic = fixture.diagnostic();
	assert!(
		matches!(result, Ok(Ok(()))),
		"OpenSSH fixture failed: {result:?}; daemon log: {diagnostic}",
	);
}

async fn check_contents(
	fixture: &Fixture,
	account: &str,
	stream: TcpStream,
	port: NonZeroU16,
) -> FixtureResult<()> {
	let target = SshAuthority::new("127.0.0.1", port, account)?;
	let host_key = PublicKey::read_openssh_file(fixture.path.join("host-key.pub"))?;
	let pin = HostKeyFingerprint::from_sha256(
		host_key
			.fingerprint(HashAlg::Sha256)
			.sha256()
			.ok_or("missing host fingerprint")?,
	);
	let public_record = format!("[127.0.0.1]:{} {}", port, host_key.to_openssh()?);
	let trust = KnownHostTrust::from_snapshot(&target, Ok(public_record.as_bytes()))?;

	let mut seed = Zeroizing::new([0; 32]);
	{
		let private = PrivateKey::read_openssh_file(fixture.path.join("client-key"))?;
		let private = private
			.key_data()
			.ed25519()
			.ok_or("fixture key is not Ed25519")?;
		seed.copy_from_slice(private.private.as_ref());
	}
	stream.set_nonblocking(true)?;
	let stream = tokio::net::TcpStream::from_std(stream)?;
	let mut sftp = connect_with_ed25519(stream, &target, pin, trust, &target, |request| {
		assert_eq!(request.authority(), &target);
		assert_eq!(request.source(), CredentialSource::SuppliedKey);
		assert_eq!(request.interaction(), InteractionPolicy::Forbidden);
		Ed25519Key::from_seed(seed)
	})
	.await?;

	let listed = sftp.list(&[]).await?;
	assert!(listed.iter().any(|name| name == FILE_NAME.as_bytes()));
	let path = [UnixComponent::new(FILE_NAME.as_bytes())?];
	let before = sftp.stat(&path).await?;
	assert_eq!(before.length, CONTENT.len() as u64);
	let mut readback = [0; CONTENT.len()];
	assert_eq!(sftp.read_file(&path, &mut readback).await?, before);
	assert_eq!(readback, CONTENT);
	Ok(())
}

struct Fixture {
	path: PathBuf,
}

impl Fixture {
	fn create() -> FixtureResult<Self> {
		let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
		let base = if cfg!(target_os = "macos") {
			"/private/tmp"
		} else {
			"/tmp"
		};
		let path = Path::new(base).join(format!("exacopy-sshd-{}-{now}", std::process::id()));
		DirBuilder::new().mode(0o700).create(&path)?;
		let fixture = Self { path };
		for name in ["host-key", "client-key"] {
			let status = Command::new(KEYGEN)
				.args(["-q", "-t", "ed25519", "-N", "", "-f"])
				.arg(fixture.path.join(name))
				.stdin(Stdio::null())
				.status()?;
			if !status.success() {
				return Err("ssh-keygen failed to create an ephemeral fixture key".into());
			}
			let key = fixture.path.join(name);
			if fs::metadata(&key)?.permissions().mode() & 0o777 != 0o600 {
				return Err("ssh-keygen did not use owner-only key permissions".into());
			}
			fs::set_permissions(key.with_extension("pub"), fs::Permissions::from_mode(0o600))?;
		}
		let data = fixture.path.join("data");
		DirBuilder::new().mode(0o700).create(&data)?;
		protected_file(&data.join(FILE_NAME))?.write_all(CONTENT)?;
		Ok(fixture)
	}

	fn configure(&self, account: &str) -> FixtureResult<()> {
		// The portable OpenSSH session path can run this system rc even
		// for an internal subsystem. Fixtures require it to be absent.
		match fs::symlink_metadata("/etc/ssh/sshrc") {
			Err(error) if error.kind() == io::ErrorKind::NotFound => {}
			Err(error) => return Err(error.into()),
			Ok(_) => return Err("OpenSSH fixture requires the system SSH rc to be absent".into()),
		}
		let config = self.path.join("sshd_config");
		let dir = self.path.display();
		write!(
			protected_file(&config)?,
			concat!(
				"ListenAddress 127.0.0.1\n",
				"HostKey {dir}/host-key\n",
				"PidFile {dir}/sshd.pid\n",
				"AuthorizedKeysFile {dir}/client-key.pub\n",
				"AllowUsers {account}\n",
				"PubkeyAuthentication yes\n",
				"AuthenticationMethods publickey\n",
				"PasswordAuthentication no\n",
				"KbdInteractiveAuthentication no\n",
				"UsePAM no\n",
				"UseDNS no\n",
				"PermitRootLogin no\n",
				"PermitTTY no\n",
				"PermitUserRC no\n",
				"PermitUserEnvironment no\n",
				"DisableForwarding yes\n",
				"AllowAgentForwarding no\n",
				"X11Forwarding no\n",
				"StrictModes no\n",
				"Subsystem sftp internal-sftp -R -d {dir}/data\n",
				"ForceCommand internal-sftp -R -d {dir}/data\n",
				"LogLevel VERBOSE\n",
			),
			dir = dir,
			account = account,
		)?;
		// This fixture checks a private 0700/0600 tree itself. /tmp is an
		// ancestor of the test keys, so its dedicated sshd disables StrictModes.
		let output = Command::new(SSHD).args(["-t", "-f"]).arg(config).output()?;
		if !output.status.success() {
			return Err(format!(
				"OpenSSH fixture preflight failed: {}",
				String::from_utf8_lossy(&output.stderr)
			)
			.into());
		}
		Ok(())
	}

	fn start(&self) -> FixtureResult<(TcpStream, NonZeroU16, Daemon)> {
		let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
		let address = listener.local_addr()?;
		let port = NonZeroU16::new(address.port()).ok_or("missing loopback port")?;
		let local = TcpStream::connect_timeout(&address, STARTUP_TIMEOUT)?;
		listener.set_nonblocking(true)?;
		let deadline = Instant::now() + STARTUP_TIMEOUT;
		let accepted = loop {
			match listener.accept() {
				Ok((stream, peer)) if peer == local.local_addr()? => break stream,
				Ok(_) => return Err("unexpected loopback connection".into()),
				Err(error)
					if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
				{
					std::thread::sleep(Duration::from_millis(5));
				}
				Err(error) => return Err(error.into()),
			}
		};
		drop(listener);
		let input = OwnedFd::from(accepted.try_clone()?);
		let output = OwnedFd::from(accepted);
		let child = Command::new(SSHD)
			.args(["-i", "-e", "-f"])
			.arg(self.path.join("sshd_config"))
			.stdin(Stdio::from(input))
			.stdout(Stdio::from(output))
			.stderr(Stdio::from(protected_file(&self.path.join("daemon.log"))?))
			.spawn()?;
		Ok((local, port, Daemon(child)))
	}

	fn diagnostic(&self) -> String {
		let mut bytes = Vec::new();
		if let Ok(file) = File::open(self.path.join("daemon.log")) {
			let _ = file.take(MAX_DIAGNOSTIC_BYTES).read_to_end(&mut bytes);
		}
		String::from_utf8_lossy(&bytes).into_owned()
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.path);
	}
}

struct Daemon(Child);

impl Daemon {
	fn stop(&mut self) {
		if matches!(self.0.try_wait(), Ok(None)) {
			let _ = self.0.kill();
			let _ = self.0.wait();
		}
	}
}

impl Drop for Daemon {
	fn drop(&mut self) {
		self.stop();
	}
}

fn current_account() -> FixtureResult<String> {
	let output = Command::new("/usr/bin/id").arg("-un").output()?;
	if !output.status.success() {
		return Err("fixture could not determine the unprivileged account".into());
	}
	let account = String::from_utf8(output.stdout)?.trim().to_owned();
	if account.is_empty()
		|| !account
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
	{
		return Err("fixture account is outside the supported name syntax".into());
	}
	Ok(account)
}

fn protected_file(path: &Path) -> io::Result<File> {
	OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(0o600)
		.open(path)
}
