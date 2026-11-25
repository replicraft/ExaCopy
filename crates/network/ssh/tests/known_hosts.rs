//! Dedicated stored host trust policy and OpenSSH-format fixtures.

#![cfg(feature = "experimental-ssh")]

use std::io;
use std::num::NonZeroU16;

use exacopy_endpoint::ssh_sftp::{HostKeyFingerprint, KnownHostStatus, SshAuthority};
use exacopy_ssh::{KnownHostTrust, KnownHostsError};
use russh::keys::{HashAlg, PublicKey};

// Public fixture key encodings shipped in the reviewed russh known_hosts tests.
const KEY: &str =
	"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF";
const OTHER_KEY: &str =
	"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
const DEFAULT_HASH: &str = "|1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak=";
// Independent HMAC fixture for the exact token [2001:db8::7]:2200.
const PORT_HASH: &str = "|1|YWJjZGVmZ2hpamtsbW5vcHFyc3Q=|tcdvuVVO0+WKaRUDTfnhG1fqMWs=";
// Generated with OpenSSH 9.7p1 ssh-keygen -H and checked with -F.
const BRACKET_DEFAULT: &str = "|1|LcKH/uXMbqsW9AJnHaiBfUn9P+E=|KTMuf8GwgIgdaHnr3JJ/3XhavlY=";
const IPV6_BARE: &str = "|1|n7qeGyhJEbr0eZcU3MQ9+UVgdA8=|vUJfuiFi/DBygoaIZxbN4f3l9JE=";
const IPV6_BRACKET_DEFAULT: &str = "|1|f0LFnbMH3QYYiC2FKWfrAYHMRWM=|pGGVLgc8PjhX6YnyEuBtQHGZap8=";
const IPV6_EXPANDED: &str = "|1|SsyxUdyVrhRj2i5Z1sXvy8L0nBM=|OxLOAIVLB9PZxZAptMklchZzEOc=";
const MIXED_CASE: &str = "|1|cLaAiVcuVSOP2ZDXG7RURk8gchs=|D5/IjlONjW9KFPNaseCp4Ig53/8=";

fn authority(host: &str, port: u16) -> SshAuthority {
	SshAuthority::new(host, NonZeroU16::new(port).unwrap(), "backup").unwrap()
}

fn fingerprint(key: &str) -> HostKeyFingerprint {
	HostKeyFingerprint::from_sha256(
		key.parse::<PublicKey>()
			.unwrap()
			.fingerprint(HashAlg::Sha256)
			.sha256()
			.unwrap(),
	)
}

fn lookup(host: &SshAuthority, source: &str, key: &str) -> KnownHostStatus {
	let trust = KnownHostTrust::from_snapshot(host, Ok(source.as_bytes())).unwrap();
	trust.status(host, fingerprint(key))
}

fn refuse(input: &str) -> KnownHostsError {
	let host = authority("example.com", 22);
	KnownHostTrust::from_snapshot(&host, Ok(input.as_bytes()))
		.err()
		.unwrap()
}

#[test]
fn exact_literals_preserve_host_port_and_ip_authority() {
	let source = format!(
		"  # trusted fixture\r\n  One.EXAMPLE.,[case.example]:2200,2001:db8::7\t{KEY} comment\r\n"
	);
	for (hostname, port, expected) in [
		("one.example.", 22, KnownHostStatus::Trusted),
		("one.example", 22, KnownHostStatus::Unknown),
		("case.example", 2200, KnownHostStatus::Trusted),
		("case.example", 22, KnownHostStatus::Unknown),
		("2001:0db8:0:0:0:0:0:7", 22, KnownHostStatus::Trusted),
		("2001:db8::7", 2200, KnownHostStatus::Unknown),
	] {
		assert_eq!(lookup(&authority(hostname, port), &source, KEY), expected);
	}
	let host = authority("one.example.", 22);
	let other = authority("one.example.", 2200);
	let trust = KnownHostTrust::from_snapshot(&host, Ok(source.as_bytes())).unwrap();
	assert_eq!(
		trust.status(&other, fingerprint(KEY)),
		KnownHostStatus::Unavailable
	);
}

#[test]
fn stored_matching_keys_and_revocation_are_order_independent() {
	let host = authority("example.com", 22);
	let trusted = format!("example.com {KEY}\nexample.com {OTHER_KEY}\n");
	assert_eq!(lookup(&host, &trusted, KEY), KnownHostStatus::Trusted);
	assert_eq!(lookup(&host, &trusted, OTHER_KEY), KnownHostStatus::Trusted);

	for source in [
		format!("{trusted}@revoked example.com {KEY}\n"),
		format!("@revoked example.com {KEY}\n{trusted}"),
	] {
		assert_eq!(lookup(&host, &source, KEY), KnownHostStatus::Revoked);
		assert_eq!(lookup(&host, &source, OTHER_KEY), KnownHostStatus::Trusted);
	}
	assert_eq!(
		lookup(&host, &format!("example.com {OTHER_KEY}\n"), KEY),
		KnownHostStatus::Changed
	);
	assert_eq!(
		lookup(&host, &format!("@revoked example.com {OTHER_KEY}\n"), KEY),
		KnownHostStatus::Changed
	);
}

#[test]
fn hashed_hosts_bind_the_exact_canonical_default_or_bracketed_label() {
	let source = format!("{DEFAULT_HASH} {KEY}\n@revoked {PORT_HASH} {OTHER_KEY}\n");
	assert_eq!(
		lookup(&authority("example.com", 22), &source, KEY),
		KnownHostStatus::Trusted
	);
	assert_eq!(
		lookup(&authority("example.com", 2222), &source, KEY),
		KnownHostStatus::Unknown
	);
	assert_eq!(
		lookup(&authority("2001:0db8:0:0::7", 2200), &source, OTHER_KEY),
		KnownHostStatus::Revoked
	);
	assert_eq!(
		lookup(
			&authority("2001:db8::7", 22),
			&format!("{PORT_HASH} {OTHER_KEY}"),
			OTHER_KEY
		),
		KnownHostStatus::Unknown
	);
}

#[test]
fn openssh_hashes_cover_both_default_port_spellings_and_canonical_case() {
	for (token, target) in [
		(BRACKET_DEFAULT, authority("EXAMPLE.COM", 22)),
		(IPV6_BARE, authority("2001:DB8:0:0:0:0:0:7", 22)),
		(IPV6_BRACKET_DEFAULT, authority("2001:DB8:0:0:0:0:0:7", 22)),
		(MIXED_CASE, authority("MiXeD.Example", 22)),
	] {
		assert_eq!(
			lookup(&target, &format!("{token} {KEY}"), KEY),
			KnownHostStatus::Trusted
		);
		let source = format!("@revoked {token} {KEY}");
		assert_eq!(lookup(&target, &source, KEY), KnownHostStatus::Revoked);
		assert_eq!(
			lookup(&target, &source, OTHER_KEY),
			KnownHostStatus::Changed
		);
	}
}

#[test]
fn opaque_revocations_deny_reused_keys_without_matching_other_keys() {
	let target = authority("2001:db8::7", 22);
	assert_eq!(
		lookup(&target, &format!("{IPV6_EXPANDED} {KEY}"), KEY),
		KnownHostStatus::Unknown,
	);
	let source = format!("@revoked {IPV6_EXPANDED} {KEY}");
	assert_eq!(lookup(&target, &source, KEY), KnownHostStatus::Revoked);
	assert_eq!(
		lookup(&target, &source, OTHER_KEY),
		KnownHostStatus::Unknown
	);
	let other_host = authority("unrelated.example", 2200);
	assert_eq!(lookup(&other_host, &source, KEY), KnownHostStatus::Revoked);
	assert_eq!(
		lookup(&other_host, &format!("@revoked example.com {KEY}"), KEY),
		KnownHostStatus::Unknown,
	);
}

#[test]
fn unsupported_patterns_block_the_whole_snapshot() {
	for record in [
		format!("@cert-authority unrelated.example {KEY}"),
		format!("@unknown unrelated.example {KEY}"),
		format!("*.elsewhere.example {KEY}"),
		format!("!blocked.example,unrelated.example {KEY}"),
		format!("|2|opaque|unsupported {KEY}"),
		"unrelated.example ssh-ed25519-cert-v01@openssh.com body".to_owned(),
	] {
		let file = format!("example.com {KEY}\n{record}");
		assert_eq!(refuse(&file), KnownHostsError::Unsupported { line: 2 });
	}
}

#[test]
fn malformed_fields_and_hashes_refuse_instead_of_becoming_unknown() {
	for record in [
		"example.com ssh-ed25519 incomplete".to_owned(),
		format!("example.com, {KEY}"),
		format!("example.com,,elsewhere.example {KEY}"),
		format!("[example.com]:0022 {KEY}"),
		format!("[example.com]:65536 {KEY}"),
		format!("[example.com]:0 {KEY}"),
		format!("example.com {KEY}\0"),
		format!("{} {KEY}", DEFAULT_HASH.trim_end_matches('=')),
		format!("{} {KEY}", DEFAULT_HASH.replace("J1", "J_")),
		format!("{} {KEY}", DEFAULT_HASH.replace("jTo=", "jTp=")),
	] {
		assert_eq!(refuse(&record), KnownHostsError::Malformed { line: 1 });
	}
}

#[test]
fn acquisition_encoding_and_resource_failures_are_typed() {
	let host = authority("example.com", 22);
	let source = Err(io::Error::new(
		io::ErrorKind::PermissionDenied,
		"private local path",
	));
	let unavailable = KnownHostTrust::from_snapshot(&host, source).err().unwrap();
	assert_eq!(unavailable, KnownHostsError::Unavailable);
	assert!(!unavailable.to_string().contains("private local path"));
	assert_eq!(
		KnownHostTrust::from_snapshot(&host, Ok(b"\xff"))
			.err()
			.unwrap(),
		KnownHostsError::Encoding
	);
	assert_eq!(lookup(&host, "", KEY), KnownHostStatus::Unknown);
	assert_eq!(refuse(&"#".repeat(1024 * 1024 + 1)), KnownHostsError::Limit);
	assert_eq!(refuse(&"#".repeat(8 * 1024 + 1)), KnownHostsError::Limit);
	assert_eq!(refuse(&"\n".repeat(4097)), KnownHostsError::Limit);
	assert_eq!(
		refuse(&format!("{}example.com {KEY}", "x,".repeat(64))),
		KnownHostsError::Limit
	);
	assert_eq!(
		refuse(&format!("example.com ssh-ed25519 {}", "a".repeat(4097))),
		KnownHostsError::Limit
	);
}
