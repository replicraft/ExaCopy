use std::io::Read;

use ed25519_dalek::VerifyingKey;

use crate::frame::{ChainHead, FrameKind, FrameReader};
use crate::{JournalJobId, OwnerDigest, OwnerProfileId};

use super::record::{authenticate_owner, digest};
use super::{
	FIRST_SEGMENT_BYTES, PREPARED_BYTES, WindowsBootstrapFileIdentity,
	WindowsBootstrapInspectionError, WindowsBootstrapOwner, WindowsBootstrapOwnerError,
	WindowsBootstrapRoles, codec,
};

/// Expected owner and job selection from an independent trust source.
#[derive(Clone, Copy, Debug)]
pub struct WindowsBootstrapSelection<'a> {
	/// The expected profile ID.
	pub profile: OwnerProfileId,
	/// The expected job ID.
	pub job: JournalJobId,
	/// The provisioned canonical strong verification key.
	pub key: &'a VerifyingKey,
	/// The independently admitted container root identity.
	pub root: WindowsBootstrapFileIdentity,
}

/// The first verified frame's boundary, including when used for diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsBootstrapPrefix {
	head: ChainHead,
	end_offset: u64,
}

impl WindowsBootstrapPrefix {
	/// Returns the verified frame's sequence and digest.
	#[must_use]
	pub const fn head(self) -> ChainHead {
		self.head
	}

	/// Returns the segment-relative end of the verified first frame.
	#[must_use]
	pub const fn end_offset(self) -> u64 {
		self.end_offset
	}
}

/// Authenticated historical storage evidence for the selected first segment.
///
/// Its scope ends at logical EOF on the supplied reader. Native storage
/// admission, physical EOF and current authority require separate evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsBootstrapEvidence {
	owner: WindowsBootstrapOwner,
	owner_digest: OwnerDigest,
	boundary: WindowsBootstrapPrefix,
}

impl WindowsBootstrapEvidence {
	/// Returns the authenticated owner claims.
	#[must_use]
	pub const fn owner(&self) -> &WindowsBootstrapOwner {
		&self.owner
	}

	/// Returns the digest of the complete authenticated canonical envelope.
	#[must_use]
	pub const fn owner_digest(&self) -> OwnerDigest {
		self.owner_digest
	}

	/// Returns the single accepted frame boundary.
	#[must_use]
	pub const fn boundary(&self) -> WindowsBootstrapPrefix {
		self.boundary
	}
}

/// Checks the independently selected owner, all observed roles and a segment at byte zero.
///
/// The caller supplies bounded, truthful role observations and a reader that
/// returns logical EOF at the actual intended end of the supplied bytes.
/// Use an adapter with a finite interruption budget for physical I/O. Physical
/// EOF, held names, identities, lengths and ACL/custody require native checks.
///
/// # Errors
/// Refuses invalid owner claims, a missing or mismatched first frame, or any
/// suffix or error on the terminal read. A terminal error may contain the first
/// validated boundary for diagnostics.
pub fn inspect(
	owner_bytes: &[u8],
	segment: impl Read,
	selection: &WindowsBootstrapSelection<'_>,
	observed_roles: WindowsBootstrapRoles,
) -> Result<WindowsBootstrapEvidence, WindowsBootstrapInspectionError> {
	use WindowsBootstrapInspectionError as Error;

	let owner = authenticate_owner(owner_bytes, selection, observed_roles).map_err(Error::Owner)?;
	let owner_digest = digest(owner_bytes);
	let prepared = codec::encode_prepared(&owner, owner_digest)
		.map_err(WindowsBootstrapOwnerError::from)
		.map_err(Error::Owner)?;
	let mut reader = FrameReader::new(segment, ChainHead::start());
	let first = reader
		.next_frame_with_payload_limit(|_| PREPARED_BYTES)
		.map_err(Error::FirstFrame)?
		.ok_or(Error::MissingFirstFrame)?;
	if first.kind() != FrameKind::JobPrepared
		|| first.payload() != prepared.as_slice()
		|| reader.offset() != FIRST_SEGMENT_BYTES as u64
	{
		return Err(Error::PreparedMismatch);
	}
	let prefix = WindowsBootstrapPrefix {
		head: first.head(),
		end_offset: reader.offset(),
	};
	match reader.next_frame_with_payload_limit(|_| 0) {
		Ok(None) => Ok(WindowsBootstrapEvidence {
			owner,
			owner_digest,
			boundary: prefix,
		}),
		Ok(Some(_)) => Err(Error::ExtraFrame { prefix }),
		Err(source) => Err(Error::TerminalRead { prefix, source }),
	}
}
