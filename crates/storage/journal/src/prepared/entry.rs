use exacopy_endpoint::{MAX_UNIX_COMPONENT_BYTES, UnixComponent};
use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use super::observation::{read_source, read_source_metadata, write_source, write_source_metadata};
use super::wire::{
	expect_array, expect_key, expect_map, read_entry_header, read_fixed, read_identity,
	write_header, write_identity,
};
use super::{JournalContext, LiveSourceView, PreparedError, RootCapabilityId, SourceInodeMetadata};
use crate::frame::{Frame, FrameKind};
use crate::{JournalEntryId, LinuxFileIdentity};

const UNIX_BYTES: u64 = 1;
const TARGET_ABSENT_OBSERVED: u64 = 0;
// Full-width numeric values, UUIDs, native IDs, digests, and container headers.
const FIXED_ENTRY_BYTES: usize = 270;
const MAX_ENTRY_BYTES: usize = FIXED_ENTRY_BYTES + MAX_UNIX_COMPONENT_BYTES;
type EntryCursor = Cursor<[u8; MAX_ENTRY_BYTES]>;

/// The supported target metadata observation during preserving preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TargetObservation {
	/// Descriptor-relative lookup observed absence at preflight.
	AbsentObserved,
}

impl TargetObservation {
	fn code(self) -> u64 {
		match self {
			Self::AbsentObserved => TARGET_ABSENT_OBSERVED,
		}
	}

	fn from_code(code: u64) -> Result<Self, PreparedError> {
		match code {
			TARGET_ABSENT_OBSERVED => Ok(Self::AbsentObserved),
			_ => Err(PreparedError::UnsupportedTargetObservation),
		}
	}
}

/// One target component relative to the destination-root capability bound by the job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedTarget<'a> {
	/// The root capability identifier recorded in JobPrepared.
	pub root: RootCapabilityId,
	/// The raw Unix component, which may contain non-UTF-8 bytes.
	pub component: UnixComponent<'a>,
	/// The target observation from preflight.
	pub observation: TargetObservation,
}

/// The source, stage, and target observations from local entry preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryPreparation<'a> {
	/// The held source's native identity, extent, and times.
	pub source: LiveSourceView,
	/// The observation from the newly created, empty stage.
	pub stage: LinuxFileIdentity,
	/// The bound target path and its preflight observation.
	pub target: PreparedTarget<'a>,
	/// The local source metadata observation.
	pub source_metadata: SourceInodeMetadata,
}

/// The local v1 entry preparation observation for journal kind 2.
///
/// The target path encodes one component under the job's root. The recorded
/// preflight observation describes a point in time. Exclusive publication
/// still requires current authority, validation, and a no-clobber primitive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryPrepared<'a> {
	/// The job, epoch, and canonical plan digest.
	pub context: JournalContext,
	/// The plan's entry UUID associated with this stage.
	pub entry: JournalEntryId,
	preparation: EntryPreparation<'a>,
}

impl<'a> EntryPrepared<'a> {
	/// Assembles a preparation record from the coordinator's captured observations.
	///
	/// # Errors
	/// Returns an alias error if the source and stage have the same native identity.
	pub fn new(
		context: JournalContext,
		entry: JournalEntryId,
		preparation: EntryPreparation<'a>,
	) -> Result<Self, PreparedError> {
		if preparation.source.identity() == preparation.stage {
			return Err(PreparedError::SourceStageAlias);
		}
		Ok(Self {
			context,
			entry,
			preparation,
		})
	}

	/// Returns the preparation observations bound to this entry.
	#[must_use]
	pub const fn preparation(&self) -> EntryPreparation<'a> {
		self.preparation
	}

	/// Encodes a complete local v1 deterministic CBOR payload.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let canonical = self.encode_bounded();
		canonical.get_ref()[..canonical.position()].to_vec()
	}

	/// Checks the frame kind and decodes its canonical payload.
	///
	/// # Errors
	/// Returns a typed error for an incompatible kind or invalid payload.
	pub fn from_frame(frame: &'a Frame) -> Result<Self, PreparedError> {
		if frame.kind() != FrameKind::EntryPrepared {
			return Err(PreparedError::WrongRecordKind);
		}
		Self::decode(frame.payload())
	}

	/// Decodes a complete payload from an independently identified kind-2 frame.
	///
	/// The target component borrows the input.
	///
	/// # Errors
	/// Returns a typed error for malformed or unsupported bytes.
	pub fn decode(payload: &'a [u8]) -> Result<Self, PreparedError> {
		if payload.len() > MAX_ENTRY_BYTES {
			return Err(PreparedError::PayloadTooLarge);
		}
		let mut decoder = Decoder::new(payload);
		let (context, entry) = read_entry_header(&mut decoder)?;
		let preparation = read_preparation(&mut decoder)?;
		let record = Self::new(context, entry, preparation)?;
		let canonical = record.encode_bounded();
		if canonical.get_ref()[..canonical.position()] != *payload {
			return Err(PreparedError::NonCanonical);
		}
		Ok(record)
	}

	fn encode_bounded(&self) -> EntryCursor {
		let mut encoder = Encoder::new(Cursor::new([0; MAX_ENTRY_BYTES]));
		self.write_payload(&mut encoder)
			.expect("the validated entry preparation payload fits its fixed-size buffer");
		encoder.into_writer()
	}

	fn write_payload(
		&self,
		encoder: &mut Encoder<EntryCursor>,
	) -> Result<(), encode::Error<EndOfArray>> {
		write_header(encoder, &self.context, Some(self.entry))?;
		encoder.map(4)?.u8(0)?;
		write_source(encoder, self.preparation.source)?;
		encoder.u8(1)?;
		write_identity(encoder, self.preparation.stage)?;
		let target = self.preparation.target;
		encoder
			.u8(2)?
			.map(2)?
			.u8(0)?
			.bytes(target.root.as_bytes())?
			.u8(1)?
			.array(1)?
			.map(2)?
			.u8(0)?
			.u64(UNIX_BYTES)?
			.u8(1)?
			.bytes(target.component.as_bytes())?
			.u8(3)?
			.map(2)?
			.u8(0)?;
		write_source_metadata(encoder, self.preparation.source_metadata)?;
		encoder.u8(1)?.u64(target.observation.code())?;
		Ok(())
	}
}

fn read_preparation<'a>(decoder: &mut Decoder<'a>) -> Result<EntryPreparation<'a>, PreparedError> {
	expect_map(decoder, 4)?;
	expect_key(decoder, 0)?;
	let source = read_source(decoder)?;
	expect_key(decoder, 1)?;
	let stage = read_identity(decoder)?;
	expect_key(decoder, 2)?;
	let (root, component) = read_target_path(decoder)?;
	expect_key(decoder, 3)?;
	expect_map(decoder, 2)?;
	expect_key(decoder, 0)?;
	let source_metadata = read_source_metadata(decoder)?;
	expect_key(decoder, 1)?;
	let observation = TargetObservation::from_code(decoder.u64()?)?;
	let target = PreparedTarget {
		root,
		component,
		observation,
	};
	Ok(EntryPreparation {
		source,
		stage,
		target,
		source_metadata,
	})
}

fn read_target_path<'a>(
	decoder: &mut Decoder<'a>,
) -> Result<(RootCapabilityId, UnixComponent<'a>), PreparedError> {
	expect_map(decoder, 2)?;
	expect_key(decoder, 0)?;
	let root = RootCapabilityId::from_bytes(read_fixed(decoder)?)?;
	expect_key(decoder, 1)?;
	expect_array(decoder, 1)?;
	expect_map(decoder, 2)?;
	expect_key(decoder, 0)?;
	if decoder.u64()? != UNIX_BYTES {
		return Err(PreparedError::UnsupportedTargetEncoding);
	}
	expect_key(decoder, 1)?;
	let component =
		UnixComponent::new(decoder.bytes()?).map_err(PreparedError::InvalidTargetComponent)?;
	Ok((root, component))
}
