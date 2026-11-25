//! Public Plan v1 operation and policy codes.

use minicbor::{Decoder, Encoder};

use crate::cbor::{BodyBytes, EncodeError};
use crate::document::{expect_key, expect_map};

use super::PlanError;

macro_rules! registry_enum {
	($(#[$enum_doc:meta])* pub enum $name:ident {
		$($(#[$variant_doc:meta])* $variant:ident = $code:literal),+ $(,)?
	}) => {
		$(#[$enum_doc])*
		#[derive(Debug, Clone, Copy, Eq, PartialEq)]
		#[repr(u8)]
		pub enum $name {
			$($(#[$variant_doc])* $variant = $code),+
		}

		impl $name {
			pub(super) fn read(decoder: &mut Decoder<'_>) -> Result<Self, PlanError> {
				match decoder.u8()? {
					$($code => Ok(Self::$variant)),+,
					_ => Err(PlanError::Unsupported),
				}
			}
		}
	};
}

registry_enum! {
	/// Operation selected in the public Plan v1 body.
	pub enum PlanOperation {
		/// Copy selected entries.
		Copy = 0,
		/// Protected move.
		Move = 1,
		/// Restore selected entries.
		Restore = 2,
		/// Create a backup.
		Backup = 3,
		/// Prepare deduplication.
		Dedupe = 4,
		/// Reclaim previously retired storage.
		Reclaim = 5,
		/// Repair selected objects.
		Repair = 6,
	}
}

registry_enum! {
	/// Preservation policy in a public plan.
	pub enum PlanPreservation {
		/// Preserve source and pre-existing destination.
		Preserve = 0,
		/// Capture and preserve a displaced incumbent.
		ProtectedReplace = 1,
		/// Verify and qualify a move before source retirement.
		ProtectedMove = 2,
		/// Explicit bounded reclamation.
		ExplicitReclaim = 3,
	}
}

registry_enum! {
	/// Policy for collisions with an existing entry.
	pub enum PlanConflict {
		/// Stop on a conflict.
		Error = 0,
		/// Skip a conflicting entry.
		Skip = 1,
		/// Select an explicitly planned alternate name.
		Rename = 2,
		/// Require the protected-replacement workflow.
		ProtectedReplace = 3,
	}
}

registry_enum! {
	/// Verification required by the plan.
	pub enum PlanVerification {
		/// BLAKE3 read-back.
		Blake3Readback = 0,
		/// SHA-256 read-back.
		Sha256Readback = 1,
		/// Exact byte comparison.
		Bytes = 2,
	}
}

registry_enum! {
	/// Storage allocation policy.
	pub enum PlanStorage {
		/// Independent writes.
		Independent = 0,
		/// Explicit shared copy-on-write storage.
		SharedCow = 1,
	}
}

registry_enum! {
	/// Destination publication scope.
	pub enum PlanPublication {
		/// Publish each qualified entry separately.
		PerFile = 0,
		/// Publish a newly staged tree.
		NewTree = 1,
	}
}

registry_enum! {
	/// Requested source consistency policy.
	pub enum PlanConsistency {
		/// Select the strongest available policy under caller rules.
		Auto = 0,
		/// Measure a live source observation.
		LiveObserved = 1,
		/// Require file-stable source access.
		FileStable = 2,
		/// Require a filesystem tree snapshot.
		TreeSnapshot = 3,
		/// Require application-consistent capture.
		ApplicationConsistent = 4,
	}
}

registry_enum! {
	/// Source-view observation representation.
	pub enum PlanViewConsistency {
		/// Live observed source.
		LiveObserved = 0,
		/// File-stable source access.
		FileStable = 1,
		/// Filesystem tree snapshot.
		TreeSnapshot = 2,
		/// Application-consistent capture.
		ApplicationConsistent = 3,
	}
}

registry_enum! {
	/// Minimum requested durability.
	pub enum PlanDurability {
		/// Process-crash safety.
		ProcessCrash = 0,
		/// Qualified power-loss durability.
		QualifiedPowerLoss = 1,
	}
}

registry_enum! {
	/// Metadata fidelity policy.
	pub enum PlanFidelity {
		/// Require the selected data profile.
		RequiredData = 0,
		/// Require native metadata.
		NativeStrict = 1,
		/// Preserve the portable metadata profile.
		Portable = 2,
	}
}

registry_enum! {
	/// Requested source disposition after the required effects.
	pub enum PlanSourceRetirement {
		/// Retain the source.
		None = 0,
		/// Ask for the separately qualified quarantine workflow.
		Quarantine = 1,
	}
}

/// The registered Plan v1 safety policy. The symlink-following field is always false.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PlanPolicy {
	/// Required source and incumbent preservation.
	pub preservation: PlanPreservation,
	/// How to handle a reported collision.
	pub conflict: PlanConflict,
	/// Required verification method.
	pub verification: PlanVerification,
	/// Requested storage allocation.
	pub storage: PlanStorage,
	/// Requested publication scope.
	pub publication: PlanPublication,
	/// Required source consistency.
	pub consistency: PlanConsistency,
	/// Minimum durability to obtain before success.
	pub minimum_durability: PlanDurability,
	/// Required metadata fidelity.
	pub fidelity: PlanFidelity,
	/// Requested post-effect source disposition.
	pub source_retirement: PlanSourceRetirement,
}

impl PlanPolicy {
	pub(super) fn write_to(self, encoder: &mut Encoder<BodyBytes>) -> Result<(), EncodeError> {
		encoder
			.map(10)?
			.u8(0)?
			.u8(self.preservation as u8)?
			.u8(1)?
			.u8(self.conflict as u8)?
			.u8(2)?
			.u8(self.verification as u8)?
			.u8(3)?
			.u8(self.storage as u8)?
			.u8(4)?
			.u8(self.publication as u8)?
			.u8(5)?
			.u8(self.consistency as u8)?
			.u8(6)?
			.u8(self.minimum_durability as u8)?
			.u8(7)?
			.u8(self.fidelity as u8)?
			.u8(8)?
			.u8(self.source_retirement as u8)?
			.u8(9)?
			.bool(false)?;
		Ok(())
	}

	pub(super) fn read_from(decoder: &mut Decoder<'_>) -> Result<Self, PlanError> {
		expect_map(decoder, 10)?;
		expect_key(decoder, 0)?;
		let preservation = PlanPreservation::read(decoder)?;
		expect_key(decoder, 1)?;
		let conflict = PlanConflict::read(decoder)?;
		expect_key(decoder, 2)?;
		let verification = PlanVerification::read(decoder)?;
		expect_key(decoder, 3)?;
		let storage = PlanStorage::read(decoder)?;
		expect_key(decoder, 4)?;
		let publication = PlanPublication::read(decoder)?;
		expect_key(decoder, 5)?;
		let consistency = PlanConsistency::read(decoder)?;
		expect_key(decoder, 6)?;
		let minimum_durability = PlanDurability::read(decoder)?;
		expect_key(decoder, 7)?;
		let fidelity = PlanFidelity::read(decoder)?;
		expect_key(decoder, 8)?;
		let source_retirement = PlanSourceRetirement::read(decoder)?;
		expect_key(decoder, 9)?;
		if decoder.bool()? {
			return Err(PlanError::Unsupported);
		}
		Ok(Self {
			preservation,
			conflict,
			verification,
			storage,
			publication,
			consistency,
			minimum_durability,
			fidelity,
			source_retirement,
		})
	}
}
