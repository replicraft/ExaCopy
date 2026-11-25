mod body;

use exacopy_endpoint::{MAX_UNIX_COMPONENT_BYTES, UnixComponent};
use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use self::body::{read_body, write_body};
use super::wire::{read_entry_header, write_header};
use super::{
	DarwinJobPrepared, DarwinPreparedError, DarwinRootBinding, DarwinSourceView,
	DarwinStageObservation, same_native_object,
};
use crate::frame::{Frame, FrameKind};
use crate::{JournalContext, JournalEntryId, OwnerDigest, PreparedError, TargetObservation};

// All fixed-width context, identity, extent, and metadata fields fit within
// 768 bytes; the only variable fields are the three bounded raw names.
const MAX_ENTRY_BYTES: usize = 768 + 3 * MAX_UNIX_COMPONENT_BYTES;
type EntryCursor = Cursor<[u8; MAX_ENTRY_BYTES]>;

/// The source, fresh stage, and exact target absence observations for one entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinEntryPreparation<'a> {
	/// The regular file observed through the held source capability.
	pub source: DarwinSourceView<'a>,
	/// The exclusively created empty stage and its initially observed directory.
	pub stage: DarwinStageObservation<'a>,
	/// The raw target name relative to the job destination root.
	pub target_component: UnixComponent<'a>,
	/// The observation from looking up this exact name through the destination root.
	pub target_observation: TargetObservation,
}

/// Managed APFS entry preparation for journal kind 2.
///
/// The recorded observations are point-in-time evidence. Replay still needs to
/// match the authenticated owner, plan and job and to revalidate live authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinEntryPrepared<'a> {
	context: JournalContext,
	entry: JournalEntryId,
	owner_digest: OwnerDigest,
	destination_root: DarwinRootBinding,
	preparation: DarwinEntryPreparation<'a>,
}

impl<'a> DarwinEntryPrepared<'a> {
	/// Creates a record for the entry and scope from the preceding job preparation.
	///
	/// # Errors
	/// Refuses cross-volume stage placement and inconsistent or aliased roles.
	pub fn new(
		job: &DarwinJobPrepared,
		entry: JournalEntryId,
		preparation: DarwinEntryPreparation<'a>,
	) -> Result<Self, DarwinPreparedError> {
		let record = Self {
			context: job.context(),
			entry,
			owner_digest: job.owner_digest(),
			destination_root: job.destination_root(),
			preparation,
		};
		record.validate_observations()?;
		Ok(record)
	}

	/// Checks the job, epoch, plan, exact owner digest, and full destination scope.
	///
	/// # Errors
	/// Returns an error if any of those recorded values differ from the job.
	pub fn validate_job(&self, job: &DarwinJobPrepared) -> Result<(), DarwinPreparedError> {
		if (self.context, self.owner_digest, self.destination_root)
			!= (job.context(), job.owner_digest(), job.destination_root())
		{
			return Err(DarwinPreparedError::JobMismatch);
		}
		Ok(())
	}

	/// Returns the bound job, epoch, and canonical plan digest.
	#[must_use]
	pub const fn context(&self) -> JournalContext {
		self.context
	}

	/// Returns the plan entry identity.
	#[must_use]
	pub const fn entry(&self) -> JournalEntryId {
		self.entry
	}

	/// Returns the digest of the exact signed owner bytes.
	#[must_use]
	pub const fn owner_digest(&self) -> OwnerDigest {
		self.owner_digest
	}

	/// Returns the exact destination root binding used during target lookup.
	#[must_use]
	pub const fn destination_root(&self) -> DarwinRootBinding {
		self.destination_root
	}

	/// Returns the entry's captured source, stage and target name.
	#[must_use]
	pub const fn preparation(&self) -> DarwinEntryPreparation<'a> {
		self.preparation
	}

	/// Returns the exact-name absence observation in this profile.
	#[must_use]
	pub const fn target_observation(&self) -> TargetObservation {
		self.preparation.target_observation
	}

	/// Encodes the deterministic managed APFS payload.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let canonical = self.encode_bounded();
		canonical.get_ref()[..canonical.position()].to_vec()
	}

	/// Decodes a complete, canonical, profile-specific kind-2 frame payload.
	///
	/// # Errors
	/// Refuses other kinds and invalid or unsupported payloads.
	pub fn from_frame(frame: &'a Frame) -> Result<Self, DarwinPreparedError> {
		if frame.kind() != FrameKind::EntryPrepared {
			return Err(PreparedError::WrongRecordKind.into());
		}
		Self::decode(frame.payload())
	}

	/// Decodes a complete payload from an independently identified kind-2 frame.
	///
	/// # Errors
	/// Refuses malformed, oversized, noncanonical or unsupported payloads.
	pub fn decode(payload: &'a [u8]) -> Result<Self, DarwinPreparedError> {
		if payload.len() > MAX_ENTRY_BYTES {
			return Err(PreparedError::PayloadTooLarge.into());
		}
		let mut decoder = Decoder::new(payload);
		let (context, entry) = read_entry_header(&mut decoder)?;
		let record = read_body(&mut decoder, context, entry)?;
		record.validate_observations()?;
		let canonical = record.encode_bounded();
		if canonical.get_ref()[..canonical.position()] != *payload {
			return Err(PreparedError::NonCanonical.into());
		}
		Ok(record)
	}

	fn validate_observations(&self) -> Result<(), DarwinPreparedError> {
		let DarwinEntryPreparation {
			source,
			stage,
			target_component,
			..
		} = self.preparation;
		let destination = self.destination_root.identity;
		if stage.directory.volume() != destination.volume()
			|| stage.identity.volume() != destination.volume()
		{
			return Err(DarwinPreparedError::VolumeMismatch);
		}
		if same_native_object(stage.directory, stage.identity)
			|| [source.root().identity, source.identity(), destination]
				.into_iter()
				.any(|identity| {
					same_native_object(identity, stage.directory)
						|| same_native_object(identity, stage.identity)
				})
			|| same_native_object(source.identity(), destination)
			|| (same_native_object(source.root().identity, destination)
				&& source.component() == target_component)
		{
			return Err(DarwinPreparedError::IdentityAlias);
		}
		Ok(())
	}

	fn encode_bounded(&self) -> EntryCursor {
		let mut encoder = Encoder::new(Cursor::new([0; MAX_ENTRY_BYTES]));
		self.write_payload(&mut encoder)
			.expect("the fixed fields and bounded name components fit their buffer");
		encoder.into_writer()
	}

	fn write_payload(
		&self,
		encoder: &mut Encoder<EntryCursor>,
	) -> Result<(), encode::Error<EndOfArray>> {
		write_header(encoder, self.context, Some(self.entry))?;
		write_body(encoder, self)
	}
}
