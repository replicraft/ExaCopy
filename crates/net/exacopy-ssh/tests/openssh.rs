//! Optional interoperability evidence against a private OpenSSH reference server.
#![cfg(feature = "experimental-ssh")]

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[path = "openssh/unix.rs"]
mod unix;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[test]
#[ignore = "the independent daemon fixture needs Unix connected-socket descriptor wiring"]
fn private_openssh_reference_fixture_requires_qualification() {
	panic!(
		"the private OpenSSH daemon fixture has no runner for this host; run the in_process test target for caller-stream coverage"
	);
}
