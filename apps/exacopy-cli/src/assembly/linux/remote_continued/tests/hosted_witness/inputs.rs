use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::remote_source::SftpPathRoot;
use exacopy_journal::OwnerProfileId;
use exacopy_journal::remote_download::qualification::{
	RemoteQualificationRouteClass, RemoteQualificationScope,
};
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadError, RemoteDownloadOwnerRecord,
};
use exacopy_platform::linux::{RecoveryFile, StageError};
use exacopy_platform::read_protected_snapshot;
use serde::Deserialize;

pub(super) const REQUEST: &str = "EXACOPY_HOSTED_WITNESS_REQUEST";
const ROUTE: &str = "EXACOPY_HOSTED_WITNESS_ROUTE";
const REQUEST_BLAKE3: &str = "EXACOPY_HOSTED_WITNESS_REQUEST_BLAKE3";
const OP2_DIGEST: &str = "EXACOPY_HOSTED_WITNESS_QUALIFICATION_BLAKE3";
const OP2_RECORD_DOMAIN: &[u8] = b"ExaCopy/linux-remote-destination-qualification-record/v2\0";
const CASE: &str = "EXACOPY_HOSTED_WITNESS_CASE";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
	pub(super) schema_version: u32,
	pub(super) route: Route,
	pub(super) path_root: PathRoot,
	pub(super) strategy: Strategy,
	pub(super) allow_witness_retention: bool,
	pub(super) destination_root: PathBuf,
	pub(super) owner_profile: PathBuf,
	pub(super) ssh_profile: PathBuf,
	pub(super) job_id: String,
	pub(super) target: String,
	pub(super) stage: String,
	pub(super) scope_blake3: String,
	pub(super) grant_digest: String,
	pub(super) approval_expires_unix: u64,
	pub(super) initial_v1_qualification: String,
	pub(super) prior_head_blake3: String,
	pub(super) source_blake3: String,
	pub(super) source_extent: u64,
	pub(super) v1: Attestation,
	pub(super) op2: Attestation,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Route {
	DirectTcpV1,
	EmbeddedWireguardTcpV1,
}

impl Route {
	pub(super) const fn name(self) -> &'static str {
		match self {
			Self::DirectTcpV1 => "direct_tcp_v1",
			Self::EmbeddedWireguardTcpV1 => "embedded_wireguard_tcp_v1",
		}
	}

	const fn class(self) -> RemoteQualificationRouteClass {
		match self {
			Self::DirectTcpV1 => RemoteQualificationRouteClass::DirectPinnedTcpV1,
			Self::EmbeddedWireguardTcpV1 => RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1,
		}
	}
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Strategy {
	VerifiedPrefix,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PathRoot {
	AccountRelative,
	Absolute,
}

impl PathRoot {
	pub(super) const fn native(&self) -> SftpPathRoot {
		match self {
			Self::AccountRelative => SftpPathRoot::AccountRelative,
			Self::Absolute => SftpPathRoot::Absolute,
		}
	}
}

pub(super) enum Dialect {
	EmbeddedRelative,
	DirectRelative,
	Absolute,
}

impl Route {
	pub(super) const fn dialect(self, root: &PathRoot) -> Dialect {
		match (self, root) {
			(_, PathRoot::Absolute) => Dialect::Absolute,
			(Self::DirectTcpV1, PathRoot::AccountRelative) => Dialect::DirectRelative,
			(Self::EmbeddedWireguardTcpV1, PathRoot::AccountRelative) => Dialect::EmbeddedRelative,
		}
	}
}

impl Dialect {
	pub(super) fn decode(
		&self,
		bytes: &[u8],
		profile: OwnerProfileId,
		key: &VerifyingKey,
	) -> Result<RemoteDownloadOwnerRecord, RemoteDownloadError> {
		match self {
			Self::EmbeddedRelative => RemoteDownloadOwnerRecord::decode(bytes, profile, key),
			Self::DirectRelative => {
				RemoteDownloadOwnerRecord::decode_resolved_direct(bytes, profile, key)
			}
			Self::Absolute => RemoteDownloadOwnerRecord::decode_absolute_path(bytes, profile, key),
		}
	}

	pub(super) fn trust<'a>(
		&self,
		owner: &'a RemoteDownloadOwnerRecord,
		profile: OwnerProfileId,
		key: &'a VerifyingKey,
	) -> Result<RemoteBootstrapTrust<'a>, RemoteDownloadError> {
		match self {
			Self::EmbeddedRelative => RemoteBootstrapTrust::new(owner, profile, key),
			Self::DirectRelative => RemoteBootstrapTrust::new_resolved_direct(owner, profile, key),
			Self::Absolute => RemoteBootstrapTrust::new_absolute_path(owner, profile, key),
		}
	}
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attestation {
	pub(super) record: PathBuf,
	pub(super) attestor: String,
	pub(super) attestor_key: String,
	pub(super) campaign_scope: String,
	pub(super) campaign_evidence: String,
}

impl Attestation {
	pub(super) fn selected_witness_record(&self) -> Result<(Vec<u8>, [u8; 32]), Stop> {
		let expected = decode(&std::env::var(OP2_DIGEST).map_err(|_| Stop::Missing)?)?;
		let record = protected(&self.record)?;
		check_selected_witness_record(&record, expected)?;
		Ok((record, expected))
	}

	pub(super) fn scope(
		&self,
		route: Route,
		build: [u8; 32],
	) -> Result<RemoteQualificationScope, Stop> {
		Ok(RemoteQualificationScope {
			build,
			route: route.class(),
			campaign_scope: decode(&self.campaign_scope)?,
			campaign_evidence: decode(&self.campaign_evidence)?,
		})
	}

	pub(super) fn key(&self) -> Result<VerifyingKey, Stop> {
		VerifyingKey::from_bytes(&decode(&self.attestor_key)?).map_err(|_| Stop::Request)
	}
}

fn check_selected_witness_record(record: &[u8], expected: [u8; 32]) -> Result<(), Stop> {
	let actual = blake3::Hasher::new()
		.update(OP2_RECORD_DOMAIN)
		.update(record)
		.finalize();
	if *actual.as_bytes() != expected {
		return Err(Stop::Request);
	}
	Ok(())
}

impl Request {
	pub(super) fn load() -> Result<(Self, bool, [u8; 32]), Stop> {
		let path = std::env::var_os(REQUEST).ok_or(Stop::Missing)?;
		let raw = protected(Path::new(&path))?;
		let request_digest = decode(&std::env::var(REQUEST_BLAKE3).map_err(|_| Stop::Missing)?)?;
		if *blake3::hash(&raw).as_bytes() != request_digest {
			return Err(Stop::Request);
		}
		let request: Self = serde_json::from_slice(&raw).map_err(|_| Stop::Request)?;
		let case = std::env::var(CASE).map_err(|_| Stop::Missing)?;
		if request.schema_version != 1
			|| std::env::var(ROUTE).ok().as_deref() != Some(request.route.name())
			|| !matches!(case.as_str(), "positive" | "qualification-refusal")
			|| !request.destination_root.is_absolute()
			|| !request.owner_profile.is_absolute()
			|| !request.ssh_profile.is_absolute()
			|| !request.target.is_ascii()
			|| !request.stage.is_ascii()
		{
			return Err(Stop::Request);
		}
		Ok((request, case == "qualification-refusal", request_digest))
	}
}

pub(super) fn decode<const N: usize>(raw: &str) -> Result<[u8; N], Stop> {
	if raw.len() != 2 * N
		|| !raw
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
	{
		return Err(Stop::Request);
	}
	let mut bytes = [0; N];
	for (byte, digits) in bytes.iter_mut().zip(raw.as_bytes().as_chunks::<2>().0) {
		let digits = str::from_utf8(digits).map_err(|_| Stop::Request)?;
		*byte = u8::from_str_radix(digits, 16).map_err(|_| Stop::Request)?;
	}
	if bytes == [0; N] {
		return Err(Stop::Request);
	}
	Ok(bytes)
}

pub(super) fn protected(path: &Path) -> Result<Vec<u8>, Stop> {
	if !path.is_absolute() {
		return Err(Stop::Request);
	}
	read_protected_snapshot(path).map_err(|_| Stop::Request)
}

pub(super) fn artifact(file: &RecoveryFile, maximum: u64) -> Result<Vec<u8>, Stop> {
	if file.is_empty() || file.len() > maximum {
		return Err(Stop::Prefix);
	}
	let length = usize::try_from(file.len()).map_err(|_| Stop::Prefix)?;
	let mut bytes = vec![0; length];
	file.recheck_observation().map_err(|_| Stop::Prefix)?;
	file.read_exact_at(0, &mut bytes)
		.map_err(|_| Stop::Prefix)?;
	file.check_logical_eof().map_err(|_| Stop::Prefix)?;
	file.recheck_observation().map_err(|_| Stop::Prefix)?;
	Ok(bytes)
}

pub(super) fn no_receipt(result: Result<RecoveryFile, StageError>) -> bool {
	matches!(result, Err(StageError::System(error)) if error.kind() == ErrorKind::NotFound)
}

pub(super) fn component(raw: &[u8]) -> Result<UnixComponent<'_>, Stop> {
	UnixComponent::new(raw).map_err(|_| Stop::Request)
}

pub(super) fn hex(bytes: [u8; 32]) -> String {
	blake3::Hash::from_bytes(bytes).to_hex().to_string()
}

#[derive(Clone, Copy)]
pub(super) enum Stop {
	Missing,
	Request,
	Substrate,
	Qualification,
	Op2Qualification {
		digest: [u8; 32],
		request_blake3: [u8; 32],
	},
	Route,
	Prefix,
	Closeout,
}

impl Stop {
	pub(super) const fn report(self) -> (&'static str, &'static str, &'static str) {
		match self {
			Self::Missing => ("blocked", "preflight", "missing_authority"),
			Self::Request => ("blocked", "preflight", "request_refused"),
			Self::Substrate => ("blocked", "preflight", "unsupported_substrate"),
			Self::Qualification => ("blocked", "preflight", "qualification_refused"),
			Self::Op2Qualification { .. } => ("blocked", "preflight", "op2_qualification_refused"),
			Self::Route => ("blocked", "preflight", "route_not_supported"),
			Self::Prefix => ("failed", "held_prefix", "prefix_refused"),
			Self::Closeout => ("failed", "witness_closeout", "reconciliation_required"),
		}
	}
}

#[test]
fn selected_operation_two_bytes_refuse_substitution_before_qualification() {
	let selected = b"selector-two fixture bytes";
	let expected = *blake3::hash(
		b"ExaCopy/linux-remote-destination-qualification-record/v2\0selector-two fixture bytes",
	)
	.as_bytes();
	assert!(check_selected_witness_record(selected, expected).is_ok());

	let changed = b"selector-two fixture byte!";
	let mut wrong_selected_digest = expected;
	wrong_selected_digest[0] ^= 1;
	let unscoped_digest = *blake3::hash(selected).as_bytes();
	assert!(matches!(
		check_selected_witness_record(changed, expected),
		Err(Stop::Request)
	));
	assert!(matches!(
		check_selected_witness_record(selected, wrong_selected_digest),
		Err(Stop::Request)
	));
	assert!(matches!(
		check_selected_witness_record(selected, unscoped_digest),
		Err(Stop::Request)
	));
}
