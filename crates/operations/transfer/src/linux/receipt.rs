use std::fmt;

use exacopy_endpoint::{MAX_UNIX_COMPONENT_BYTES, NameError, UnixComponent};
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{
	DestinationRootBinding, JournalContext, JournalEntryId, JournalEpoch, JournalJobId,
	LinuxFileIdentity, PlanDigest, RootCapabilityId, StreamDigest, StreamEvidence, StreamLength,
	SyncedFrame,
};
use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

#[cfg(test)]
mod tests;

const MAJOR_VERSION: u64 = 1;
const MINOR_VERSION: u64 = 0;
const REQUIRED_FEATURES: u64 = 0;
const FIELD_COUNT: u64 = 11;
const LINUX_BUFFERED_PROFILE: u64 = 1;
const DIGEST_DOMAIN: &[u8] = b"ExaCopy/linux-copy-receipt/v1\0";

// Two UUIDs plus the destination capability UUID, three 32-byte digests, six native
// identity words, up to three full-width unsigned integers, and the CBOR overhead.
const FIXED_RECEIPT_BYTES: usize = 259;

/// Maximum size of the private v1 Linux copy receipt artifact.
pub const MAX_COPY_RECEIPT_BYTES: usize = FIXED_RECEIPT_BYTES + MAX_UNIX_COMPONENT_BYTES;

type ReceiptBuffer = Cursor<[u8; MAX_COPY_RECEIPT_BYTES]>;
type ReceiptEncoder = Encoder<ReceiptBuffer>;
type ReceiptWriteError = encode::Error<EndOfArray>;

/// The immutable observations and copy plan bound by a single-entry receipt.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ReceiptEvidence<'name> {
	/// The job, run epoch and plan digest for this copy.
	pub context: JournalContext,
	/// The sole published entry in the copy.
	pub entry: JournalEntryId,
	/// The native source identity observed while reading its logical stream.
	pub source: LinuxFileIdentity,
	/// The logical and physical binding of the held destination directory.
	pub destination: DestinationRootBinding,
	/// The original bytes of the single destination name.
	pub target: UnixComponent<'name>,
	/// The published file identity, logical byte count, and standard BLAKE3-256 digest.
	pub stream: StreamEvidence,
}

/// A local preserve-mode success receipt for `receipts/receipt.cbor`.
///
/// The v1 Linux buffered profile records an exclusive publication, a live-observed
/// source, and a complete independent buffered hash read-back of the staged stream.
/// The kernel may have served the read-back from cache. The copy made independent
/// logical writes and met the Linux basic metadata policy. Extended attributes outside
/// observable namespaces, hard-link relationships, sparse allocation and inode change
/// time are outside its fidelity scope. Source content and namespace were retained.
///
/// The profile records successful post-rename fsync calls on the stage and destination
/// directories and a completed journal file barrier for the referenced kind-9 frame.
/// Filesystem durability qualification is unconfirmed. Interpreting a decoded artifact
/// as execution evidence requires matching it to the authoritative journal and the
/// committed receipt reference.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CopyReceipt<'name> {
	evidence: ReceiptEvidence<'name>,
	durability_frame: ChainHead,
}

impl<'name> CopyReceipt<'name> {
	/// Creates the artifact after this operation has synchronized its kind-9 observation.
	///
	/// The executor must supply the kind-9 frame from the matching publication and use
	/// stream evidence from that operation's verified stage.
	pub(super) fn from_synced_durability(
		evidence: ReceiptEvidence<'name>,
		frame: &SyncedFrame,
	) -> Result<Self, ReceiptError> {
		if frame.kind() != FrameKind::DurabilityRecorded {
			return Err(ReceiptError::InvalidDurabilityFrame);
		}
		Self::from_evidence(evidence, frame.head())
	}

	fn from_evidence(
		evidence: ReceiptEvidence<'name>,
		durability_frame: ChainHead,
	) -> Result<Self, ReceiptError> {
		let published = evidence.stream.identity;
		if evidence.source == published
			|| evidence.destination.identity == published
			|| evidence.destination.identity.device() != published.device()
		{
			return Err(ReceiptError::IdentityMismatch);
		}
		Ok(Self {
			evidence,
			durability_frame,
		})
	}

	/// Returns the plan and physical observations encoded in this receipt.
	#[must_use]
	pub const fn evidence(&self) -> ReceiptEvidence<'name> {
		self.evidence
	}

	/// Returns the journal sequence and frame digest of the durability observation.
	#[must_use]
	pub const fn durability_frame(&self) -> ChainHead {
		self.durability_frame
	}

	/// Encodes the exact bytes of the versioned private artifact in deterministic CBOR.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let encoded = self.encoded();
		encoded.get_ref()[..encoded.position()].to_vec()
	}

	fn encoded(&self) -> ReceiptBuffer {
		let mut encoder = Encoder::new(Cursor::new([0; MAX_COPY_RECEIPT_BYTES]));
		self.write(&mut encoder)
			.expect("validated receipt fields fit the bounded encoding buffer");
		encoder.into_writer()
	}

	// Key assignments for the local v1 format, independent of the public receipt schema.
	// Identities are [device, inode] Linux u64 values. The Unix name is raw bytes.
	// The stream value is [published identity, length, standard BLAKE3-256 digest].
	// The kind-9 reference is [sequence, journal-frame digest].
	fn write(&self, encoder: &mut ReceiptEncoder) -> Result<(), ReceiptWriteError> {
		let evidence = self.evidence;
		encoder
			.map(FIELD_COUNT)?
			.u8(0)?
			.array(3)?
			.u64(MAJOR_VERSION)?
			.u64(MINOR_VERSION)?
			.u64(REQUIRED_FEATURES)?
			.u8(1)?
			.bytes(evidence.context.job.as_bytes())?
			.u8(2)?
			.u64(evidence.context.epoch.get())?
			.u8(3)?
			.bytes(evidence.entry.as_bytes())?
			.u8(4)?
			.bytes(evidence.context.plan_digest.as_bytes())?
			.u8(5)?;
		write_identity(encoder, evidence.source)?;
		encoder
			.u8(6)?
			.array(2)?
			.bytes(evidence.destination.id.as_bytes())?;
		write_identity(encoder, evidence.destination.identity)?;
		encoder
			.u8(7)?
			.bytes(evidence.target.as_bytes())?
			.u8(8)?
			.array(3)?;
		write_identity(encoder, evidence.stream.identity)?;
		encoder
			.u64(evidence.stream.length.get())?
			.bytes(evidence.stream.digest.as_bytes())?
			.u8(9)?
			.array(2)?
			.u64(self.durability_frame.sequence())?
			.bytes(&self.durability_frame.digest())?
			.u8(10)?
			.u64(LINUX_BUFFERED_PROFILE)?;
		Ok(())
	}

	/// Decodes an exact canonical artifact, borrowing its raw destination name.
	///
	/// # Errors
	/// Rejects unsupported format or profile values, malformed or noncanonical CBOR,
	/// and observations outside the bounded single-entry Linux profile.
	pub fn decode(bytes: &'name [u8]) -> Result<Self, ReceiptError> {
		if bytes.len() > MAX_COPY_RECEIPT_BYTES {
			return Err(ReceiptError::TooLarge);
		}
		let mut decoder = Decoder::new(bytes);
		let receipt = Self::read(&mut decoder)?;
		let encoded = receipt.encoded();
		if decoder.position() != bytes.len() || &encoded.get_ref()[..encoded.position()] != bytes {
			return Err(ReceiptError::NonCanonical);
		}
		Ok(receipt)
	}

	fn read(decoder: &mut Decoder<'name>) -> Result<Self, ReceiptError> {
		if decoder.map()? != Some(FIELD_COUNT) {
			return Err(ReceiptError::InvalidCbor);
		}
		read_key(decoder, 0)?;
		read_array(decoder, 3)?;
		let major = decoder.u64()?;
		let minor = decoder.u64()?;
		let required = decoder.u64()?;
		if major != MAJOR_VERSION || minor != MINOR_VERSION || required != REQUIRED_FEATURES {
			return Err(ReceiptError::UnsupportedVersion);
		}
		read_key(decoder, 1)?;
		let job = JournalJobId::from_bytes(read_fixed(decoder)?)
			.map_err(|_| ReceiptError::InvalidBinding)?;
		read_key(decoder, 2)?;
		let epoch = JournalEpoch::new(decoder.u64()?);
		read_key(decoder, 3)?;
		let entry = JournalEntryId::from_bytes(read_fixed(decoder)?);
		read_key(decoder, 4)?;
		let plan_digest = PlanDigest::from_bytes(read_fixed(decoder)?);
		read_key(decoder, 5)?;
		let source = read_identity(decoder)?;
		read_key(decoder, 6)?;
		read_array(decoder, 2)?;
		let id = RootCapabilityId::from_bytes(read_fixed(decoder)?)
			.map_err(|_| ReceiptError::InvalidBinding)?;
		let destination = DestinationRootBinding {
			id,
			identity: read_identity(decoder)?,
		};
		read_key(decoder, 7)?;
		let target = UnixComponent::new(decoder.bytes()?).map_err(ReceiptError::InvalidTarget)?;
		read_key(decoder, 8)?;
		read_array(decoder, 3)?;
		let stream = StreamEvidence {
			identity: read_identity(decoder)?,
			length: StreamLength::new(decoder.u64()?).map_err(|_| ReceiptError::InvalidLength)?,
			digest: StreamDigest::from_bytes(read_fixed(decoder)?),
		};
		read_key(decoder, 9)?;
		read_array(decoder, 2)?;
		let durability_frame = ChainHead::after(decoder.u64()?, read_fixed(decoder)?)
			.ok_or(ReceiptError::InvalidDurabilityFrame)?;
		read_key(decoder, 10)?;
		if decoder.u64()? != LINUX_BUFFERED_PROFILE {
			return Err(ReceiptError::UnsupportedProfile);
		}

		Self::from_evidence(
			ReceiptEvidence {
				context: JournalContext {
					job,
					epoch,
					plan_digest,
				},
				entry,
				source,
				destination,
				target,
				stream,
			},
			durability_frame,
		)
	}

	/// Returns the BLAKE3-256 digest of the v1 domain followed by the exact artifact bytes.
	#[must_use]
	pub fn digest(&self) -> [u8; 32] {
		let mut hasher = blake3::Hasher::new();
		hasher.update(DIGEST_DOMAIN);
		let encoded = self.encoded();
		hasher.update(&encoded.get_ref()[..encoded.position()]);
		*hasher.finalize().as_bytes()
	}
}

fn read_key(decoder: &mut Decoder<'_>, key: u8) -> Result<(), ReceiptError> {
	if decoder.u8()? == key {
		Ok(())
	} else {
		Err(ReceiptError::InvalidCbor)
	}
}

fn read_array(decoder: &mut Decoder<'_>, length: u64) -> Result<(), ReceiptError> {
	if decoder.array()? == Some(length) {
		Ok(())
	} else {
		Err(ReceiptError::InvalidCbor)
	}
}

fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], ReceiptError> {
	decoder
		.bytes()?
		.try_into()
		.map_err(|_| ReceiptError::InvalidCbor)
}

fn write_identity(
	encoder: &mut ReceiptEncoder,
	identity: LinuxFileIdentity,
) -> Result<(), ReceiptWriteError> {
	encoder
		.array(2)?
		.u64(identity.device())?
		.u64(identity.inode())?;
	Ok(())
}

fn read_identity(decoder: &mut Decoder<'_>) -> Result<LinuxFileIdentity, ReceiptError> {
	read_array(decoder, 2)?;
	Ok(LinuxFileIdentity::new(decoder.u64()?, decoder.u64()?))
}

/// A receipt artifact outside the supported single-entry Linux format.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReceiptError {
	/// The input exceeds the maximum size of a receipt artifact.
	TooLarge,
	/// A field has an unexpected CBOR type, shape, order, or byte count.
	InvalidCbor,
	/// The encoding has a nonminimal representation or trailing bytes.
	NonCanonical,
	/// The major/minor version or required features are unsupported.
	UnsupportedVersion,
	/// The receipt names an unsupported observation profile.
	UnsupportedProfile,
	/// The job or destination capability identity is invalid.
	InvalidBinding,
	/// The recorded target bytes are not a supported Unix name.
	InvalidTarget(NameError),
	/// The stream length is outside the signed Linux extent limit.
	InvalidLength,
	/// The source, destination root and published file identities conflict.
	IdentityMismatch,
	/// The supplied journal reference cannot identify a completed kind-9 observation.
	InvalidDurabilityFrame,
}

impl From<minicbor::decode::Error> for ReceiptError {
	fn from(_: minicbor::decode::Error) -> Self {
		Self::InvalidCbor
	}
}

impl fmt::Display for ReceiptError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::TooLarge => formatter.write_str("copy receipt exceeds the artifact limit"),
			Self::InvalidCbor => formatter.write_str("copy receipt has invalid CBOR fields"),
			Self::NonCanonical => formatter.write_str("copy receipt CBOR is not canonical"),
			Self::UnsupportedVersion => {
				formatter.write_str("unsupported copy receipt version or features")
			}
			Self::UnsupportedProfile => {
				formatter.write_str("unsupported copy receipt observation profile")
			}
			Self::InvalidBinding => {
				formatter.write_str("invalid copy receipt job or root identity")
			}
			Self::InvalidTarget(cause) => {
				write!(formatter, "invalid copy receipt target ({cause})")
			}
			Self::InvalidLength => {
				formatter.write_str("copy receipt stream exceeds the extent limit")
			}
			Self::IdentityMismatch => {
				formatter.write_str("copy receipt native identities conflict")
			}
			Self::InvalidDurabilityFrame => {
				formatter.write_str("invalid copy receipt durability frame reference")
			}
		}
	}
}

impl std::error::Error for ReceiptError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::InvalidTarget(cause) => Some(cause),
			_ => None,
		}
	}
}
