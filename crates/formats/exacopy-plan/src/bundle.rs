//! Bounded file presentation of an unsigned public Plan and one entry page.

use core::fmt;

use exacopy_core::{NameError, UnixComponent};

use crate::{
	DocumentError, DocumentRef, MAX_DOCUMENT_PAGE_BYTES, MAX_PLAN_JSON_BYTES, PlanBody,
	PlanEntriesPage, PlanJsonError, PublicPlan,
};

const HEX_ID_BYTES: usize = 64;
const PAGE_EXTENSION: &[u8; 4] = b".exc";
const PAGE_NAME_BYTES: usize = HEX_ID_BYTES + PAGE_EXTENSION.len();
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// An unsigned envelope rendered through the public Plan codec.
pub struct RenderedPlanEnvelope {
	json: Vec<u8>,
	reference: Option<DocumentRef>,
}

impl RenderedPlanEnvelope {
	/// Renders the existing bounded unsigned JSON presentation.
	///
	/// # Errors
	/// Propagates invalid body or JSON output limits.
	pub fn from_body(body: &PlanBody<'_>) -> Result<Self, PlanJsonError> {
		let plan = PublicPlan::from_body(body)?;
		let json = plan.to_json()?;
		let reference = match body.fields().entry_pages.as_slice() {
			[reference] => Some(*reference),
			_ => None,
		};
		Ok(Self { json, reference })
	}

	/// Verifies the bound entry page and prepares the exact files.
	///
	/// # Errors
	/// Refuses an unsupported bundle shape, an out-of-bounds or mismatched page,
	/// and a JSON envelope that would become too large with its final LF.
	pub fn prepare<'page>(
		mut self,
		page: &'page [u8],
	) -> Result<PlanBundleArtifacts<'page>, PlanBundleEncodingError> {
		if self
			.json
			.len()
			.checked_add(1)
			.is_none_or(|size| size > MAX_PLAN_JSON_BYTES)
		{
			return Err(PlanBundleEncodingError::EnvelopeLimit);
		}
		if page.len() > MAX_DOCUMENT_PAGE_BYTES {
			return Err(PlanBundleEncodingError::Page(DocumentError::Size));
		}
		let reference = self.reference.ok_or(PlanBundleEncodingError::PageShape)?;
		PlanEntriesPage::from_canonical_cbor(reference, page)
			.map_err(PlanBundleEncodingError::Page)?;
		self.json.push(b'\n');
		Ok(PlanBundleArtifacts {
			name: page_name(reference.page_id()),
			page,
			envelope: self.json,
		})
	}
}

/// Exact artifact bytes and content-addressed page name for the bundle writer.
pub struct PlanBundleArtifacts<'page> {
	name: [u8; PAGE_NAME_BYTES],
	page: &'page [u8],
	envelope: Vec<u8>,
}

impl PlanBundleArtifacts<'_> {
	/// Returns the exact lowercase digest basename, with a fixed `.exc` suffix.
	///
	/// # Errors
	/// Reports an incompatible component validator if the generated name is refused.
	pub fn page_name(&self) -> Result<UnixComponent<'_>, NameError> {
		UnixComponent::new(&self.name)
	}

	/// Returns the exact verified canonical page bytes.
	#[must_use]
	pub const fn page(&self) -> &[u8] {
		self.page
	}

	/// Returns the exact bounded unsigned JSON followed by one LF.
	#[must_use]
	pub fn envelope(&self) -> &[u8] {
		&self.envelope
	}
}

fn page_name(id: [u8; 32]) -> [u8; PAGE_NAME_BYTES] {
	let mut output = [0; PAGE_NAME_BYTES];
	let (hex, suffix) = output.split_at_mut(HEX_ID_BYTES);
	for (pair, byte) in hex.as_chunks_mut::<2>().0.iter_mut().zip(id) {
		pair[0] = LOWER_HEX[usize::from(byte >> 4)];
		pair[1] = LOWER_HEX[usize::from(byte & 0xf)];
	}
	suffix.copy_from_slice(PAGE_EXTENSION);
	output
}

/// Refusal to prepare the bounded bundle artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PlanBundleEncodingError {
	/// The JSON envelope plus its final LF exceeds the format limit.
	EnvelopeLimit,
	/// This one-leaf file profile requires exactly one entry-page reference.
	PageShape,
	/// The page does not satisfy its format or bound reference.
	Page(DocumentError),
}

impl fmt::Display for PlanBundleEncodingError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::EnvelopeLimit => formatter.write_str("plan envelope exceeds the bundle limit"),
			Self::PageShape => formatter.write_str("plan bundle requires one entry page"),
			Self::Page(error) => write!(formatter, "plan bundle page refused ({error})"),
		}
	}
}

impl core::error::Error for PlanBundleEncodingError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::EnvelopeLimit | Self::PageShape => None,
			Self::Page(error) => Some(error),
		}
	}
}

#[cfg(test)]
mod tests;
