use std::num::{NonZeroU16, NonZeroU64, NonZeroU128};
use std::time::{Duration, Instant};

use exacopy_endpoint::connection_retry::{
	ReconnectEvidence, RetryDecision, RetryOwner, RetrySupervisor,
};
use exacopy_endpoint::remote_source::SourceEpoch;
use exacopy_journal::OwnerDigest;
use exacopy_journal::frame::ChainHead;
use exacopy_platform::windows::WindowsComponent;

use super::*;
use crate::assembly::windows_capture::WindowsCaptureGrant;

#[test]
fn selected_scope_preserves_dns_basis_account_bytes_route_and_raw_path() {
	let authority =
		SshAuthority::new("Host.Example.", NonZeroU16::new(22).unwrap(), "MiX").unwrap();
	let components = [
		UnixComponent::new(b"dir").unwrap(),
		UnixComponent::new(b"\xff").unwrap(),
	];
	let source = WindowsCaptureSource {
		authority: &authority,
		peer: "192.0.2.3:22".parse().unwrap(),
		host_fingerprint: [0x47; 32],
		path: &components,
		extent_ceiling: 513,
	};
	let mut exact = b"ExaCopy/windows-ntfs-capture/source/resolved-direct-relative/v1\0\x0d\0host.example.\x16\0\x03\0MiX".to_vec();
	exact.extend_from_slice(&[0x47; 32]);
	exact.extend_from_slice(b"\x04\xc0\0\x02\x03\x16\0\x05\0dir/\xff\x01\x02\0\0\0\0\0\0");
	assert_eq!(
		source.scope_digest().unwrap(),
		*blake3::hash(&exact).as_bytes()
	);

	let mapped = WindowsCaptureSource {
		peer: "[::ffff:192.0.2.3]:22".parse().unwrap(),
		..source
	};
	assert_eq!(
		mapped.scope_digest().unwrap_err().kind(),
		io::ErrorKind::InvalidInput
	);
	let wrong_port = WindowsCaptureSource {
		peer: "192.0.2.3:23".parse().unwrap(),
		..source
	};
	assert!(wrong_port.scope_digest().is_err());
	let empty_path = WindowsCaptureSource {
		path: &[],
		..source
	};
	assert!(empty_path.scope_digest().is_err());
	let excessive = [UnixComponent::new(&[b'x'; 255]).unwrap(); 17];
	let long_path = WindowsCaptureSource {
		path: &excessive,
		..source
	};
	assert!(long_path.scope_digest().is_err());
}

fn current_binding(owner: RetryOwner) -> ConnectionBinding {
	let mut supervisor = RetrySupervisor::new(owner, Duration::from_secs(60));
	let RetryDecision::Start(attempt) = supervisor.poll(Duration::ZERO).unwrap() else {
		panic!("the ready supervisor must start");
	};
	supervisor
		.admit(
			Duration::ZERO,
			attempt,
			ReconnectEvidence {
				route_checked_for: attempt,
				ssh_authenticated_for: attempt,
				source_checked_for: attempt,
				source_epoch: SourceEpoch::new(NonZeroU64::new(1).unwrap()),
			},
		)
		.unwrap()
}

#[test]
fn full_supervisor_width_changes_commitment_and_same_numbers_cannot_enter() {
	const OWNER: u128 = (1 << 120) + 7;
	let owner = RetryOwner::new(NonZeroU128::new(OWNER).unwrap());
	let binding = current_binding(owner);
	let foreign = current_binding(RetryOwner::new(NonZeroU128::new(7).unwrap()));
	assert_eq!(
		binding.attempt().generation(),
		foreign.attempt().generation()
	);
	assert_eq!(binding.source_epoch(), foreign.source_epoch());

	let target = WindowsComponent::new(&[0x00e9, 0x0078]).unwrap();
	let sibling =
		WindowsBootstrapFileIdentity::new(*b"12345678-0123-4567-89ab-123456789abc", 12, [0xaa; 16])
			.unwrap();
	let grant = WindowsCaptureGrant::issue(WindowsCaptureAuthorization {
		nonce: [0x10; 32],
		source_scope: [0x21; 32],
		owner_digest: OwnerDigest::from_bytes([0x32; 32]),
		bootstrap_head: ChainHead::after(1, [0x43; 32]).unwrap(),
		sibling,
		supervisor: owner,
		epoch: binding.source_epoch(),
		target,
		extent_ceiling: 2,
		expires_at: Instant::now() + Duration::from_secs(60),
	})
	.unwrap();
	let exact = [
		&b"ExaCopy/windows-ntfs-capture/grant/v1\0"[..],
		&[0x10; 32],
		&[0x21; 32],
		&[0x32; 32],
		&[0x43; 32],
		&[0xaa; 16],
		&b"\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..],
		&b"\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\x02\0\xe9\0x\0"[..],
	]
	.concat();
	let committed = invocation(&grant.approval, binding).unwrap();
	assert_eq!(committed, *blake3::hash(&exact).as_bytes());
	assert_ne!(committed, invocation(&grant.approval, foreign).unwrap());

	let guard = grant.gate.claim().unwrap();
	assert!(grant.gate.claim().is_err());
	assert!(grant.gate.admit(foreign).is_err());
	grant.gate.admit(binding).unwrap();
	assert!(grant.gate.check(foreign).is_err());
	assert!(grant.gate.check(binding).is_ok());
	drop(guard);
	assert!(grant.gate.check(binding).is_err());
	assert!(grant.gate.claim().is_err());
}
