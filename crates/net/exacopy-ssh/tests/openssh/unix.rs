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
use exacopy_ssh::{Ed25519Key, KnownHostTrust, MAX_READ_CHUNK_BYTES, connect_with_ed25519};
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

#[path = "positioned.rs"]
mod positioned;
#[path = "settings.rs"]
mod settings;

use settings::Settings;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(3);
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(25);
const MAX_DIAGNOSTIC_BYTES: u64 = 4096;
const FILE_NAME: &str = "fixture.bin";
const LARGE_FILE_NAME: &str = "generated.bin";
const LARGE_LENGTH: u64 = 5 * 1024 * 1024 + 19;
const CONTENT: &[u8] = b"independent OpenSSH readback";

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy)]
enum Reference {
	Sequential,
	Positioned,
}

#[tokio::test]
#[ignore = "requires a local OpenSSH server executable and unprivileged loopback sockets"]
async fn reads_a_file_from_a_private_openssh_subsystem_with_ed25519() {
	run_fixture(Reference::Sequential).await;
}

async fn run_fixture(reference: Reference) {
	let settings = Settings::from_env().expect("provision the optional private OpenSSH fixture");
	let account = current_account(&settings.id).expect("verify the unprivileged fixture account");
	let fixture = Fixture::create(&settings).expect("create private synthetic SSH files");
	if matches!(reference, Reference::Positioned) {
		positioned::create(&fixture.path.join("data")).expect("create a sparse synthetic file");
	}
	fixture
		.configure(&settings.sshd, &account)
		.expect("preflight the private OpenSSH daemon");
	let (stream, port, mut daemon) = fixture
		.start(&settings.sshd)
		.expect("start the private OpenSSH daemon");

	let result = tokio::time::timeout(
		FIXTURE_TIMEOUT,
		check_contents(&fixture, &account, stream, port, reference),
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
	reference: Reference,
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

	if matches!(reference, Reference::Positioned) {
		return positioned::check(&mut sftp).await;
	}

	let listed = sftp.list(&[]).await?;
	assert!(listed.iter().any(|name| name == FILE_NAME.as_bytes()));
	let path = [UnixComponent::new(FILE_NAME.as_bytes())?];
	let before = sftp.stat(&path).await?;
	assert_eq!(before.length, CONTENT.len() as u64);
	let mut readback = [0; CONTENT.len()];
	assert_eq!(sftp.read_file(&path, &mut readback).await?, before);
	assert_eq!(readback, CONTENT);

	let path = [UnixComponent::new(LARGE_FILE_NAME.as_bytes())?];
	let mut source = sftp.open_read(&path).await?;
	let observation = source.observation();
	assert_eq!(observation.length, LARGE_LENGTH);
	let mut chunk = [0; MAX_READ_CHUNK_BYTES];
	let mut total = 0;
	loop {
		let count = source.read_next(&mut chunk).await?;
		if count == 0 {
			break;
		}
		for (index, byte) in chunk[..count].iter().enumerate() {
			assert_eq!(*byte, generated_byte(total + index as u64));
		}
		total += count as u64;
	}
	assert_eq!(total, LARGE_LENGTH);
	assert_eq!(source.finish().await?, observation);
	Ok(())
}

struct Fixture {
	path: PathBuf,
}

impl Fixture {
	fn create(settings: &Settings) -> FixtureResult<Self> {
		let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
		let path = settings
			.root
			.join(format!("exacopy-sshd-{}-{now}", std::process::id()));
		DirBuilder::new().mode(0o700).create(&path)?;
		let fixture = Self { path };
		for name in ["host-key", "client-key"] {
			let status = Command::new(&settings.keygen)
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
		write_generated_file(&data.join(LARGE_FILE_NAME))?;
		Ok(fixture)
	}

	fn configure(&self, sshd: &Path, account: &str) -> FixtureResult<()> {
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
		// This fixture creates a 0700/0600 tree itself and its dedicated sshd
		// does not impose ownership policy on the provided scratch ancestors.
		let output = Command::new(sshd).args(["-t", "-f"]).arg(config).output()?;
		if !output.status.success() {
			return Err(format!(
				"OpenSSH fixture preflight failed: {}",
				String::from_utf8_lossy(&output.stderr)
			)
			.into());
		}
		Ok(())
	}

	fn start(&self, sshd: &Path) -> FixtureResult<(TcpStream, NonZeroU16, Daemon)> {
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
		let child = Command::new(sshd)
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

fn current_account(id: &Path) -> FixtureResult<String> {
	let effective_uid = Command::new(id).arg("-u").output()?;
	if !effective_uid.status.success()
		|| String::from_utf8(effective_uid.stdout)?
			.trim()
			.parse::<u32>()?
			== 0
	{
		return Err("OpenSSH fixture requires an unprivileged effective user".into());
	}
	let output = Command::new(id).arg("-un").output()?;
	if !output.status.success() {
		return Err("fixture could not determine the unprivileged account".into());
	}
	let account = String::from_utf8(output.stdout)?.trim().to_owned();
	if account.is_empty()
		|| account == "root"
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

fn write_generated_file(path: &Path) -> io::Result<()> {
	let mut file = protected_file(path)?;
	let mut chunk = [0; MAX_READ_CHUNK_BYTES];
	let mut total = 0;
	while total < LARGE_LENGTH {
		let count = (LARGE_LENGTH - total).min(chunk.len() as u64) as usize;
		for (index, byte) in chunk[..count].iter_mut().enumerate() {
			*byte = generated_byte(total + index as u64);
		}
		file.write_all(&chunk[..count])?;
		total += count as u64;
	}
	Ok(())
}

fn generated_byte(offset: u64) -> u8 {
	(offset % 251) as u8
}
