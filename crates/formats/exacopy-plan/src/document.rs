//! Public immutable document references and their digest domain.

use core::fmt;

use minicbor::{Decoder, Encoder};

use crate::cbor::{BodyBytes, EncodeError, canonical_bytes};

const PAGE_DOMAIN: &[u8] = b"ExaCopy/document-page/v1\0";
// The map prefix, four keys, digest, kind, maximum encoded length and u64 count.
const MAX_REFERENCE_BYTES: usize = 1 + 4 + (2 + 32) + 1 + 5 + 9;

/// Maximum canonical size of a public document page in bytes.
pub const MAX_DOCUMENT_PAGE_BYTES: usize = 256 * 1024;

/// The registry code carried by a public document page reference.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u16)]
pub enum DocumentPageKind {
	/// Copy or other operation plan entries.
	PlanEntries = 1,
	/// Manifest inventory entries.
	ManifestEntries = 2,
	/// Comparison entries.
	DiffEntries = 3,
	/// Entry receipt references.
	ReceiptEntries = 4,
	/// Exact patch operations.
	PatchOperations = 5,
	/// Metadata records.
	MetadataEntries = 6,
}

impl DocumentPageKind {
	fn read(value: u16) -> Result<Self, DocumentError> {
		match value {
			1 => Ok(Self::PlanEntries),
			2 => Ok(Self::ManifestEntries),
			3 => Ok(Self::DiffEntries),
			4 => Ok(Self::ReceiptEntries),
			5 => Ok(Self::PatchOperations),
			6 => Ok(Self::MetadataEntries),
			_ => Err(DocumentError::Unsupported),
		}
	}
}

/// A bounded content-addressed public document page reference.
///
/// Constructing or decoding a reference says nothing about the page's presence,
/// validity, or authorization. Use the matching page codec to verify fetched bytes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DocumentRef {
	page_id: [u8; 32],
	kind: DocumentPageKind,
	encoded_bytes: u32,
	item_count: u64,
}

impl DocumentRef {
	/// Constructs a reference with an expected kind, digest, byte size and count.
	///
	/// # Errors
	/// Rejects zero or excessive encoded lengths.
	pub fn new(
		page_id: [u8; 32],
		kind: DocumentPageKind,
		encoded_bytes: u64,
		item_count: u64,
	) -> Result<Self, DocumentError> {
		if encoded_bytes == 0 || encoded_bytes > MAX_DOCUMENT_PAGE_BYTES as u64 {
			return Err(DocumentError::Size);
		}
		let encoded_bytes = u32::try_from(encoded_bytes).map_err(|_| DocumentError::Size)?;
		Ok(Self {
			page_id,
			kind,
			encoded_bytes,
			item_count,
		})
	}

	/// Expected content-addressed identifier in the document-page domain.
	#[must_use]
	pub const fn page_id(self) -> [u8; 32] {
		self.page_id
	}

	/// Expected document page kind.
	#[must_use]
	pub const fn kind(self) -> DocumentPageKind {
		self.kind
	}

	/// Expected encoded page size.
	#[must_use]
	pub const fn encoded_bytes(self) -> u32 {
		self.encoded_bytes
	}

	/// Expected total descendant item count.
	#[must_use]
	pub const fn item_count(self) -> u64 {
		self.item_count
	}

	/// Encodes the registered numeric reference map in deterministic CBOR.
	#[must_use]
	pub fn canonical_cbor(self) -> Vec<u8> {
		canonical_bytes(|encoder| self.write_to(encoder))
	}

	pub(crate) fn write_to(self, encoder: &mut Encoder<BodyBytes>) -> Result<(), EncodeError> {
		encoder
			.map(4)?
			.u8(0)?
			.bytes(&self.page_id)?
			.u8(1)?
			.u16(self.kind as u16)?
			.u8(2)?
			.u32(self.encoded_bytes)?
			.u8(3)?
			.u64(self.item_count)?;
		Ok(())
	}

	/// Decodes a single complete canonical reference.
	///
	/// # Errors
	/// Rejects malformed, noncanonical, out-of-bounds and unknown-kind references.
	pub fn from_canonical_cbor(input: &[u8]) -> Result<Self, DocumentError> {
		if input.len() > MAX_REFERENCE_BYTES {
			return Err(DocumentError::Size);
		}
		let mut decoder = Decoder::new(input);
		let reference = Self::read_from(&mut decoder)?;
		if reference.canonical_cbor() != input {
			return Err(DocumentError::NonCanonical);
		}
		Ok(reference)
	}

	pub(crate) fn read_from(decoder: &mut Decoder<'_>) -> Result<Self, DocumentError> {
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		let page_id = fixed_bytes(decoder)?;
		expect_key(decoder, 1)?;
		let kind = DocumentPageKind::read(decoder.u16()?)?;
		expect_key(decoder, 2)?;
		let encoded_bytes = decoder.u64()?;
		expect_key(decoder, 3)?;
		let item_count = decoder.u64()?;
		Self::new(page_id, kind, encoded_bytes, item_count)
	}

	pub(crate) fn verify(self, kind: DocumentPageKind, page: &[u8]) -> Result<(), DocumentError> {
		if page.len() > MAX_DOCUMENT_PAGE_BYTES {
			return Err(DocumentError::Size);
		}
		if self.kind != kind {
			return Err(DocumentError::WrongKind);
		}
		if page.len() as u64 != u64::from(self.encoded_bytes) {
			return Err(DocumentError::LengthMismatch);
		}
		if self.page_id != document_page_id(kind, page) {
			return Err(DocumentError::DigestMismatch);
		}
		Ok(())
	}
}

pub(crate) fn document_page_id(kind: DocumentPageKind, page: &[u8]) -> [u8; 32] {
	*blake3::Hasher::new()
		.update(PAGE_DOMAIN)
		.update(&(kind as u16).to_le_bytes())
		.update(&(page.len() as u64).to_le_bytes())
		.update(page)
		.finalize()
		.as_bytes()
}

/// A rejected document reference or unsupported or invalid page.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum DocumentError {
	/// Encoded bytes exceed the applicable limit, or a reference has zero bytes.
	Size,
	/// The input has invalid CBOR types, fields, order, or required structure.
	Malformed,
	/// The required page version, kind, or entry shape is unsupported.
	Unsupported,
	/// The parent reference names a different document page kind.
	WrongKind,
	/// The page size disagrees with its reference.
	LengthMismatch,
	/// The page digest disagrees with its reference.
	DigestMismatch,
	/// The decoded item count disagrees with the reference.
	CountMismatch,
	/// The bytes differ from the canonical serialization.
	NonCanonical,
	/// An entry has invalid identifiers, names, or field values.
	InvalidEntry,
}

impl fmt::Display for DocumentError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Size => "document exceeds its encoded byte limits",
			Self::Malformed => "document has malformed required fields",
			Self::Unsupported => "document version or selected shape is unsupported",
			Self::WrongKind => "document reference has the wrong kind",
			Self::LengthMismatch => "document page length differs from its reference",
			Self::DigestMismatch => "document page digest differs from its reference",
			Self::CountMismatch => "document page count differs from its reference",
			Self::NonCanonical => "document bytes are not canonical",
			Self::InvalidEntry => "document entry has invalid values",
		})
	}
}

impl core::error::Error for DocumentError {}

impl From<minicbor::decode::Error> for DocumentError {
	fn from(_: minicbor::decode::Error) -> Self {
		Self::Malformed
	}
}

pub(crate) fn expect_map(decoder: &mut Decoder<'_>, fields: u64) -> Result<(), DocumentError> {
	if decoder.map()? == Some(fields) {
		Ok(())
	} else {
		Err(DocumentError::Malformed)
	}
}

pub(crate) fn expect_key(decoder: &mut Decoder<'_>, key: u8) -> Result<(), DocumentError> {
	if decoder.u8()? == key {
		Ok(())
	} else {
		Err(DocumentError::Malformed)
	}
}

pub(crate) fn fixed_bytes<const N: usize>(
	decoder: &mut Decoder<'_>,
) -> Result<[u8; N], DocumentError> {
	decoder
		.bytes()?
		.try_into()
		.map_err(|_| DocumentError::Malformed)
}
