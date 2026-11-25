//! The registered opaque native identity shared by public plan records.

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};

use crate::cbor::{BodyBytes, EncodeError};
use crate::document::{DocumentError, expect_key, expect_map};

/// Maximum bytes in each opaque identity atom of the supported Plan profiles.
pub const MAX_PLAN_IDENTITY_BYTES: usize = 256;

/// Namespace of an opaque native identity observation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum PlanIdentityPlatform {
	/// Linux native identity.
	Linux = 0,
	/// Windows native identity.
	Windows = 1,
	/// macOS native identity.
	Macos = 2,
	/// Identity in a remote observation namespace.
	Remote = 3,
	/// Identity in a repository observation namespace.
	Repository = 4,
}

/// Opaque source identity in a selected observation namespace.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PlanSourceIdentity<'observation> {
	/// Namespace of this past observation.
	pub platform: PlanIdentityPlatform,
	/// Opaque stable-volume bytes.
	pub volume_id: &'observation [u8],
	/// Opaque object bytes.
	pub object_id: &'observation [u8],
	/// Optional reuse-detection observation.
	pub generation: Option<&'observation [u8]>,
}

impl PlanSourceIdentity<'_> {
	pub(crate) fn is_bounded(self) -> bool {
		[Some(self.volume_id), Some(self.object_id), self.generation]
			.into_iter()
			.flatten()
			.all(|atom| (1..=MAX_PLAN_IDENTITY_BYTES).contains(&atom.len()))
	}
}

pub(crate) fn write_identity(
	encoder: &mut Encoder<BodyBytes>,
	identity: Option<PlanSourceIdentity<'_>>,
) -> Result<(), EncodeError> {
	match identity {
		Some(identity) => {
			encoder
				.map(4)?
				.u8(0)?
				.u8(identity.platform as u8)?
				.u8(1)?
				.bytes(identity.volume_id)?
				.u8(2)?
				.bytes(identity.object_id)?
				.u8(3)?;
			match identity.generation {
				Some(generation) => encoder.bytes(generation)?,
				None => encoder.null()?,
			};
		}
		None => {
			encoder.null()?;
		}
	}
	Ok(())
}

pub(crate) fn read_identity<'page>(
	decoder: &mut Decoder<'page>,
) -> Result<Option<PlanSourceIdentity<'page>>, DocumentError> {
	if decoder.datatype()? == Type::Null {
		decoder.null()?;
		return Ok(None);
	}
	expect_map(decoder, 4)?;
	expect_key(decoder, 0)?;
	let platform = match decoder.u8()? {
		0 => PlanIdentityPlatform::Linux,
		1 => PlanIdentityPlatform::Windows,
		2 => PlanIdentityPlatform::Macos,
		3 => PlanIdentityPlatform::Remote,
		4 => PlanIdentityPlatform::Repository,
		_ => return Err(DocumentError::Unsupported),
	};
	expect_key(decoder, 1)?;
	let volume_id = decoder.bytes()?;
	expect_key(decoder, 2)?;
	let object_id = decoder.bytes()?;
	expect_key(decoder, 3)?;
	let generation = if decoder.datatype()? == Type::Null {
		decoder.null()?;
		None
	} else {
		Some(decoder.bytes()?)
	};
	Ok(Some(PlanSourceIdentity {
		platform,
		volume_id,
		object_id,
		generation,
	}))
}
