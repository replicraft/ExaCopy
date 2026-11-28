use std::fmt;
use std::marker::PhantomData;

use ed25519_dalek::VerifyingKey;
use exacopy_endpoint::remote_source::SftpPathRoot;
use exacopy_journal::frame::{ChainHead, FRAME_OVERHEAD_BYTES};
use exacopy_journal::remote_download::RemoteScopeDigest;
use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;
use exacopy_journal::remote_download::qualification::RemoteQualificationRouteClass;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::MAX_REMOTE_WITNESS_RECEIPT_BYTES;
use exacopy_journal::{JournalJobId, MAX_FIRST_SEGMENT_BYTES, StreamLength};
use serde::de::{MapAccess, Visitor, value::MapAccessDeserializer};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser};
use uuid::Uuid;

use super::{ArchiveError, ArchivedWitnessSelection, ArchivedWitnessedSelection, MAX_REPORT_BYTES};

const WITNESSED_REPORT_SCHEMA: &str = "exacopy.cli.witnessed_remote_download";
const WITNESSED_REPORT_VERSION: &str = "1.1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessReport {
	schema: String,
	schema_version: String,
	completed: u8,
	pending: u8,
	publication: String,
	verification: String,
	consistency: String,
	durability: String,
	durability_qualification: String,
	preservation: String,
	metadata: String,
	result: String,
	#[serde(deserialize_with = "object")]
	receipt: Receipt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
	job_id: String,
	job_directory: String,
	job_directory_bytes_hex: String,
	length: String,
	receipt_digest: String,
	qualification_digest: String,
	metadata_policy: String,
	omissions: Vec<String>,
	#[serde(deserialize_with = "object")]
	retained_witness: Witness,
	#[serde(deserialize_with = "object")]
	archive_selection: WireSelection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Witness {
	link_count: u64,
	committed_sequence: String,
	committed_head_digest: String,
	canonical_receipt_length: usize,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireSelection {
	job: String,
	owner_key: String,
	route: String,
	path_root: String,
	scope: String,
	op1_digest: String,
	op2_digest: String,
	base_grant_digest: String,
	committed_sequence: String,
	committed_head_digest: String,
	committed_offset: String,
	receipt_digest: String,
}

const DIRECT_ROUTE: &str = "direct-pinned-tcp-v1";
const EMBEDDED_ROUTE: &str = "embedded-wireguard-tcp-v1";
const RELATIVE_PATH: &str = "account-relative";
const ABSOLUTE_PATH: &str = "absolute";

// Serde struct visitors also support positional sequences. Require objects
// here while retaining the derive's duplicate- and unknown-field checks.
fn object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(deserializer: D) -> Result<T, D::Error> {
	struct Object<T>(PhantomData<T>);

	impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
		type Value = T;

		fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
			out.write_str("a JSON object")
		}

		fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
			T::deserialize(MapAccessDeserializer::new(map))
		}
	}

	deserializer.deserialize_map(Object(PhantomData))
}

pub(crate) fn decode(bytes: &[u8]) -> Result<ArchivedWitnessSelection, ArchiveError> {
	if bytes.len() > MAX_REPORT_BYTES {
		return Err(ArchiveError::Format);
	}
	let mut source = serde_json::Deserializer::from_slice(bytes);
	let report: SuccessReport = object(&mut source).map_err(|_| ArchiveError::Format)?;
	source.end().map_err(|_| ArchiveError::Format)?;
	if report.schema != WITNESSED_REPORT_SCHEMA
		|| report.schema_version != WITNESSED_REPORT_VERSION
		|| (report.completed, report.pending) != (1, 0)
		|| report.publication != "published"
		|| report.verification != "verified_prefix_with_witness_readback"
		|| report.consistency != "live_observed"
		|| report.durability != "file_and_directory_barriers_observed"
		|| report.durability_qualification != "process_crash_qualification"
		|| report.preservation != "preserve"
		|| report.metadata != "explicitly_omitted"
		|| report.result != "published_with_omissions"
	{
		return Err(ArchiveError::Format);
	}
	report.receipt.select()
}

impl Receipt {
	fn select(self) -> Result<ArchivedWitnessSelection, ArchiveError> {
		let witness = self.retained_witness;
		if self.metadata_policy != SftpDataOnlyV1::NAME
			|| !self
				.omissions
				.iter()
				.map(String::as_str)
				.eq(SftpDataOnlyV1::omissions().iter().map(|item| item.name()))
			|| witness.link_count != 2
			|| !(1..=usize::from(MAX_REMOTE_WITNESS_RECEIPT_BYTES))
				.contains(&witness.canonical_receipt_length)
		{
			return Err(ArchiveError::Format);
		}
		// The inspector independently opens the supplied destination and selects by UUID.
		let path = decode_path_hex(&self.job_directory_bytes_hex)?;
		if String::from_utf8_lossy(&path) != self.job_directory {
			return Err(ArchiveError::Format);
		}
		let stream_length =
			StreamLength::new(decimal(&self.length)?).map_err(|_| ArchiveError::Format)?;
		let selection = self.archive_selection.select()?;
		if job_id(&self.job_id)? != selection.job
			|| nonzero_hex(&self.qualification_digest)? != selection.op2_digest
			|| nonzero_hex(&self.receipt_digest)? != selection.receipt_digest
			|| decimal(&witness.committed_sequence)? != selection.committed.head.sequence()
			|| nonzero_hex(&witness.committed_head_digest)? != selection.committed.head.digest()
		{
			return Err(ArchiveError::Format);
		}
		Ok(ArchivedWitnessSelection {
			selection,
			receipt_length: witness.canonical_receipt_length,
			stream_length: stream_length.get(),
		})
	}
}

impl WireSelection {
	fn select(self) -> Result<ArchivedWitnessedSelection, ArchiveError> {
		let raw = nonzero_hex(&self.owner_key)?;
		let owner_key = VerifyingKey::from_bytes(&raw).map_err(|_| ArchiveError::Format)?;
		if owner_key.is_weak() || owner_key.to_edwards().compress().to_bytes() != raw {
			return Err(ArchiveError::Format);
		}
		let sequence = decimal(&self.committed_sequence)?;
		let head = ChainHead::after(sequence, nonzero_hex(&self.committed_head_digest)?)
			.ok_or(ArchiveError::Format)?;
		let offset = decimal(&self.committed_offset)?;
		let minimum = sequence
			.checked_mul(FRAME_OVERHEAD_BYTES as u64)
			.ok_or(ArchiveError::Format)?;
		if offset < minimum || offset > MAX_FIRST_SEGMENT_BYTES {
			return Err(ArchiveError::Format);
		}
		Ok(ArchivedWitnessedSelection {
			job: job_id(&self.job)?,
			owner_key,
			route: match self.route.as_str() {
				DIRECT_ROUTE => RemoteQualificationRouteClass::DirectPinnedTcpV1,
				EMBEDDED_ROUTE => RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1,
				_ => return Err(ArchiveError::Format),
			},
			path_root: match self.path_root.as_str() {
				RELATIVE_PATH => SftpPathRoot::AccountRelative,
				ABSOLUTE_PATH => SftpPathRoot::Absolute,
				_ => return Err(ArchiveError::Format),
			},
			scope: RemoteScopeDigest::from_bytes(nonzero_hex(&self.scope)?),
			op1_digest: nonzero_hex(&self.op1_digest)?,
			op2_digest: nonzero_hex(&self.op2_digest)?,
			base_grant_digest: nonzero_hex(&self.base_grant_digest)?,
			committed: RemoteReplayBoundary { head, offset },
			receipt_digest: nonzero_hex(&self.receipt_digest)?,
		})
	}
}

fn decimal(text: &str) -> Result<u64, ArchiveError> {
	if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
		return Err(ArchiveError::Format);
	}
	text.parse().map_err(|_| ArchiveError::Format)
}

fn job_id(text: &str) -> Result<JournalJobId, ArchiveError> {
	let uuid = Uuid::parse_str(text).map_err(|_| ArchiveError::Format)?;
	if uuid.to_string() != text {
		return Err(ArchiveError::Format);
	}
	JournalJobId::from_bytes(*uuid.as_bytes()).map_err(|_| ArchiveError::Format)
}

fn nonzero_hex(text: &str) -> Result<[u8; 32], ArchiveError> {
	let hash = blake3::Hash::from_hex(text).map_err(|_| ArchiveError::Format)?;
	if hash.as_bytes() == &[0; 32] || hash.to_hex().as_str() != text {
		return Err(ArchiveError::Format);
	}
	Ok(*hash.as_bytes())
}

fn decode_path_hex(text: &str) -> Result<Vec<u8>, ArchiveError> {
	if text.is_empty()
		|| !text.len().is_multiple_of(2)
		|| !text
			.bytes()
			.all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
	{
		return Err(ArchiveError::Format);
	}
	let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
	if !remainder.is_empty() {
		return Err(ArchiveError::Format);
	}
	let path = pairs.iter().map(|pair| {
		let pair = std::str::from_utf8(pair).map_err(|_| ArchiveError::Format)?;
		u8::from_str_radix(pair, 16).map_err(|_| ArchiveError::Format)
	});
	let path: Vec<u8> = path.collect::<Result<_, _>>()?;
	if path.contains(&0) {
		return Err(ArchiveError::Format);
	}
	Ok(path)
}

pub(crate) struct ReportSelection<'selection>(&'selection ArchivedWitnessedSelection);

/// Projects the checked producer's selected inputs and committed result into the report.
pub(crate) const fn report_selection(
	selection: &ArchivedWitnessedSelection,
) -> ReportSelection<'_> {
	ReportSelection(selection)
}

impl Serialize for ReportSelection<'_> {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		let selection = self.0;
		let route = match selection.route {
			RemoteQualificationRouteClass::DirectPinnedTcpV1 => DIRECT_ROUTE,
			RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1 => EMBEDDED_ROUTE,
			_ => return Err(ser::Error::custom("unsupported archived witness route")),
		};
		let path_root = match selection.path_root {
			SftpPathRoot::AccountRelative => RELATIVE_PATH,
			SftpPathRoot::Absolute => ABSOLUTE_PATH,
		};
		WireSelection {
			job: Uuid::from_bytes(*selection.job.as_bytes()).to_string(),
			owner_key: hex(&selection.owner_key.to_bytes()),
			route: route.to_owned(),
			path_root: path_root.to_owned(),
			scope: hex(selection.scope.as_bytes()),
			op1_digest: hex(&selection.op1_digest),
			op2_digest: hex(&selection.op2_digest),
			base_grant_digest: hex(&selection.base_grant_digest),
			committed_sequence: selection.committed.head.sequence().to_string(),
			committed_head_digest: hex(&selection.committed.head.digest()),
			committed_offset: selection.committed.offset.to_string(),
			receipt_digest: hex(&selection.receipt_digest),
		}
		.serialize(serializer)
	}
}

fn hex(bytes: &[u8; 32]) -> String {
	blake3::Hash::from_bytes(*bytes).to_hex().to_string()
}
