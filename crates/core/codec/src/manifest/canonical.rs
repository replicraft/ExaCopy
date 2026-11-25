use minicbor::Encoder;

use crate::cbor::{BodyBytes, EncodeError, canonical_bytes};
use crate::portable::{BLAKE3_CODE, REGULAR_CODE, UNIX_BYTES_CODE};

use super::SingleFileManifest;

const LIVE_OBSERVED_CODE: u8 = 0;

pub(super) fn encode(manifest: &SingleFileManifest) -> Vec<u8> {
	canonical_bytes(|encoder| encode_body(encoder, manifest))
}

fn encode_body(
	encoder: &mut Encoder<BodyBytes>,
	manifest: &SingleFileManifest,
) -> Result<(), EncodeError> {
	encoder
		.map(9)?
		.u8(0)?
		.array(2)?
		.u8(1)?
		.u8(0)?
		.u8(1)?
		.bytes(manifest.manifest_id().as_bytes())?
		.u8(2)?
		.u8(BLAKE3_CODE)?
		.u8(3)?
		.u8(LIVE_OBSERVED_CODE)?
		.u8(4)?
		.bool(true)?
		.u8(5)?
		.array(1)?;
	encode_entry(encoder, manifest)?;
	encoder.u8(6)?.array(0)?.u8(7)?.array(0)?.u8(127)?.map(0)?;
	Ok(())
}

fn encode_entry(
	encoder: &mut Encoder<BodyBytes>,
	manifest: &SingleFileManifest,
) -> Result<(), EncodeError> {
	// Entry text keys follow the encoded-key order. The path, component and
	// stream use their numeric allocations from the common field registry.
	encoder
		.map(4)?
		.str("path")?
		.map(2)?
		.u8(0)?
		.bytes(manifest.root_id().as_bytes())?
		.u8(1)?
		.array(1)?
		.map(2)?
		.u8(0)?
		.u8(UNIX_BYTES_CODE)?
		.u8(1)?
		.bytes(manifest.basename())?
		.str("streams")?
		.array(1)?
		.map(4)?
		.u8(0)?
		.bytes(b"")?
		.u8(1)?
		.u64(manifest.length())?
		.u8(2)?
		.u8(BLAKE3_CODE)?
		.u8(3)?
		.bytes(&manifest.content_digest())?
		.str("file_type")?
		.u8(REGULAR_CODE)?
		.str("metadata_ref")?
		.null()?;
	Ok(())
}
