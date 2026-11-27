use std::path::Path;

use ed25519_dalek::VerifyingKey;
use exacopy_journal::remote_download::qualification::{
	MAX_REMOTE_QUALIFICATION_BYTES, RemoteQualificationRouteClass, RemoteQualificationScope,
	RemoteQualificationTrust, verify_remote_destination_qualification,
};
use exacopy_platform::linux::{DestinationRoot, observe_remote_destination};
use exacopy_platform::read_protected_snapshot_into;
use serde::Deserialize;

use crate::args::RemoteOptions;
use crate::assembly::linux::remote_download::{
	RemoteDestinationAttestation, measure_running_executable,
};
use crate::remote_report::RemoteFailureKind as Failure;

const MAX_TRUST_BYTES: usize = 2048;

pub(super) struct Qualification {
	record: Vec<u8>,
	trust: SelectedTrust,
	pub(super) digest: [u8; 32],
}

impl Qualification {
	pub(super) fn open(
		options: &RemoteOptions,
		root: &DestinationRoot,
		owner_key: &VerifyingKey,
		route: RemoteQualificationRouteClass,
	) -> Result<Self, Failure> {
		if options.destination_qualification == options.qualification_trust {
			return Err(Failure::InvalidRequest);
		}
		let selection = read_bounded::<MAX_TRUST_BYTES>(&options.qualification_trust)?;
		let trust = SelectedTrust::decode(&selection)?;
		if trust.scope.route != route
			|| measure_running_executable().map_err(|_| Failure::Authorization)?
				!= trust.scope.build
		{
			return Err(Failure::Authorization);
		}
		let record =
			read_bounded::<MAX_REMOTE_QUALIFICATION_BYTES>(&options.destination_qualification)?;
		let native = observe_remote_destination(root).map_err(|_| Failure::Authorization)?;
		let confirmed = verify_remote_destination_qualification(
			&record,
			&RemoteQualificationTrust {
				attestor: trust.attestor,
				attestor_key: &trust.key,
				owner_key,
				scope: trust.scope,
			},
			&native,
		)
		.map_err(|_| Failure::Authorization)?;
		Ok(Self {
			record,
			trust,
			digest: confirmed.digest(),
		})
	}

	pub(super) fn attestation(&self) -> RemoteDestinationAttestation<'_> {
		RemoteDestinationAttestation {
			record: &self.record,
			attestor: self.trust.attestor,
			key: &self.trust.key,
			scope: self.trust.scope,
		}
	}
}

fn read_bounded<const MAX: usize>(path: &Path) -> Result<Vec<u8>, Failure> {
	let mut bytes = vec![0; MAX];
	let mut readback = [0; 1024];
	let length = read_protected_snapshot_into(path, &mut bytes, &mut readback)
		.map_err(|_| Failure::Authorization)?;
	bytes.truncate(length);
	Ok(bytes)
}

struct SelectedTrust {
	attestor: [u8; 16],
	key: VerifyingKey,
	scope: RemoteQualificationScope,
}

impl SelectedTrust {
	fn decode(bytes: &[u8]) -> Result<Self, Failure> {
		if bytes.len() > MAX_TRUST_BYTES {
			return Err(Failure::InvalidRequest);
		}
		let trust: WireTrust =
			serde_json::from_slice(bytes).map_err(|_| Failure::InvalidRequest)?;
		let attestor = fixed_hex(&trust.attestor)?;
		let key = VerifyingKey::from_bytes(&fixed_hex(&trust.attestor_key)?)
			.map_err(|_| Failure::InvalidRequest)?;
		if key.is_weak() {
			return Err(Failure::Authorization);
		}
		Ok(Self {
			attestor,
			key,
			scope: RemoteQualificationScope {
				build: fixed_hex(&trust.build)?,
				route: trust.route.class(),
				campaign_scope: fixed_hex(&trust.campaign_scope)?,
				campaign_evidence: fixed_hex(&trust.campaign_evidence)?,
			},
		})
	}
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTrust {
	#[serde(rename = "schema")]
	_schema: Schema,
	attestor: Box<str>,
	attestor_key: Box<str>,
	build: Box<str>,
	route: WireRoute,
	campaign_scope: Box<str>,
	campaign_evidence: Box<str>,
}

#[derive(Deserialize)]
enum Schema {
	#[serde(rename = "exacopy-remote-qualification-trust-v1")]
	V1,
}

#[derive(Deserialize)]
enum WireRoute {
	#[serde(rename = "direct-pinned-tcp-v1")]
	DirectPinnedTcpV1,
	#[serde(rename = "embedded-wireguard-tcp-v1")]
	EmbeddedWireGuardTcpV1,
}

impl WireRoute {
	fn class(self) -> RemoteQualificationRouteClass {
		match self {
			Self::DirectPinnedTcpV1 => RemoteQualificationRouteClass::DirectPinnedTcpV1,
			Self::EmbeddedWireGuardTcpV1 => RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1,
		}
	}
}

fn fixed_hex<const N: usize>(text: &str) -> Result<[u8; N], Failure> {
	let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
	if pairs.len() != N || !remainder.is_empty() {
		return Err(Failure::InvalidRequest);
	}
	let mut result = [0; N];
	for (octet, &[high, low]) in result.iter_mut().zip(pairs) {
		*octet = (nibble(high)? << 4) | nibble(low)?;
	}
	if result == [0; N] {
		return Err(Failure::InvalidRequest);
	}
	Ok(result)
}

fn nibble(byte: u8) -> Result<u8, Failure> {
	match byte {
		b'0'..=b'9' => Ok(byte - b'0'),
		b'a'..=b'f' => Ok(byte - b'a' + 10),
		_ => Err(Failure::InvalidRequest),
	}
}

#[cfg(test)]
mod tests {
	use ed25519_dalek::SigningKey;
	use serde_json::json;

	use super::*;

	fn fixture() -> serde_json::Value {
		let key = SigningKey::from_bytes(&[3; 32]).verifying_key();
		let public: String = key
			.to_bytes()
			.iter()
			.map(|byte| format!("{byte:02x}"))
			.collect();
		json!({
			"schema": "exacopy-remote-qualification-trust-v1",
			"attestor": "01".repeat(16),
			"attestor_key": public,
			"build": "02".repeat(32),
			"route": "direct-pinned-tcp-v1",
			"campaign_scope": "03".repeat(32),
			"campaign_evidence": "04".repeat(32),
		})
	}

	#[test]
	fn trust_config_requires_the_canonical_embedded_wireguard_route() {
		let mut trust = fixture();
		trust["route"] = json!("embedded-wireguard-tcp-v1");
		let selected = SelectedTrust::decode(trust.to_string().as_bytes())
			.ok()
			.map(|trust| trust.scope.route);
		assert_eq!(
			selected,
			Some(RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1),
			"the documented embedded WireGuard route must parse"
		);

		trust["route"] = json!("embedded-wire-guard-tcp-v1");
		assert!(matches!(
			SelectedTrust::decode(trust.to_string().as_bytes()),
			Err(Failure::InvalidRequest)
		));
	}

	#[test]
	fn trust_config_requires_exact_independent_claims_and_closed_shape() {
		let valid = fixture().to_string();
		let result = SelectedTrust::decode(valid.as_bytes()).ok().unwrap();
		assert_eq!(result.scope.build, [2; 32]);
		assert_eq!(
			result.scope.route,
			RemoteQualificationRouteClass::DirectPinnedTcpV1
		);
		for (field, value) in [
			("scope", json!("extra")),
			("build", json!("AB".repeat(32))),
			("campaign_evidence", json!("00".repeat(32))),
			("route", json!("any")),
		] {
			let mut invalid = fixture();
			invalid[field] = value;
			assert!(SelectedTrust::decode(invalid.to_string().as_bytes()).is_err());
		}
		let duplicate = format!("{{\"route\":\"direct-pinned-tcp-v1\",{}", &valid[1..]);
		assert!(SelectedTrust::decode(duplicate.as_bytes()).is_err());
		assert!(SelectedTrust::decode(&[b' '; MAX_TRUST_BYTES + 1]).is_err());
	}
}
