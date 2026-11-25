//! Read-only two-way classification for one regular-file path.

/// Verified evidence for a regular file with one data stream.
///
/// The caller independently measures the actual stream and selected required
/// metadata. All observations and the baseline use the same digest algorithms,
/// stream selection and metadata policy. Quick metadata matches and unverified
/// cache entries are insufficient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegularFileEvidence {
	/// Measured data-stream length in bytes.
	pub byte_len: u64,
	/// Digest of the measured data stream.
	pub content_digest: [u8; 32],
	/// Digest of verified metadata required by the bound policy.
	pub required_metadata_digest: [u8; 32],
}

/// Current observation of the same logical path on one endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncObservation {
	/// A regular file measured under the bound comparison policy.
	Present(RegularFileEvidence),
	/// The path was observed absent within a complete, authorized inventory.
	AbsentObserved,
	/// Includes unreadable, unseen, excluded or insufficiently verified paths.
	Unknown,
	/// An entry is known to exist outside this slice's single-stream file profile.
	UnsupportedEntry,
}

/// Completeness for the pair's inventory under the conservative sync profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncInventoryCompleteness {
	/// Both authorized endpoint inventories are complete.
	Complete,
	/// At least one inventory is incomplete, even if this path was seen on both sides.
	Incomplete,
}

/// Prior baseline for this path, after pair, generation and policy validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncBaseline {
	/// No verified common history, including paths newly included by a filter.
	Uninitialized,
	/// Both endpoints previously had verified absence for this path.
	CommonAbsent,
	/// Both endpoints previously held the same verified file evidence.
	CommonPresent(RegularFileEvidence),
	/// Intentionally retained different versions require explicit manual resolution.
	Asymmetric,
}

/// Endpoint within the caller-validated pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncSide {
	/// First endpoint.
	Left,
	/// Second endpoint.
	Right,
}

/// Identifies what a reported copy candidate would have to preserve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncCopyTarget {
	/// A future transfer would require exclusive creation.
	AbsentName,
	/// A future transfer would require protected replacement.
	ExistingIncumbent,
}

/// Observed states that require preserving both sides for review.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncConflict {
	/// Different verified versions, including concurrent creation or required metadata changes.
	DivergentVersions,
	/// The peer still holds the common version. Deletion propagation requires separate approval.
	DeletionAgainstUnchanged {
		/// Endpoint where absence was observed.
		absent: SyncSide,
	},
	/// One endpoint changed the file while its peer removed the entry.
	EditAgainstDeletion {
		/// Endpoint with the changed file.
		edited: SyncSide,
	},
	/// At least one measured entry is outside the regular-file profile.
	UnsupportedEntry,
	/// Prior intentionally distinct versions need manual resolution.
	AsymmetricBaseline,
}

/// Missing evidence that prevents classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncBlock {
	/// The pair lacks complete inventory evidence.
	IncompleteInventory,
	/// The subject path lacks verified observation on at least one side.
	UnknownObservation,
}

/// Preview outcome for this path. A coordinator must separately admit and
/// revalidate any transfer, quarantine or durable baseline publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncPathDecision {
	/// The pair remains unchanged or has no file to propagate.
	NoChange,
	/// Both files currently match. This observation alone cannot advance a baseline.
	BaselineMatch,
	/// Both complete inventories observed absence after a common present file.
	/// Any retained tombstone still requires the workflow's evidence and receipt rules.
	BothAbsentAfterCommonPresent,
	/// An observed one-sided create or edit for future transfer review.
	CopyCandidate {
		/// Endpoint with the source version.
		from: SyncSide,
		/// Observed state of the opposite endpoint.
		target: SyncCopyTarget,
	},
	/// Preserve observations for explicit resolution.
	Conflict(SyncConflict),
	/// Gather sufficient evidence before deciding.
	Blocked(SyncBlock),
}

/// Classifies two observations in two-way mode without choosing filesystem effects.
///
/// The caller must validate the same raw logical path, distinct authorized roots
/// and the bound pair, policy and baseline generation before constructing these
/// inputs. This function trusts that evidence boundary and holds no path or
/// mutation capability. It applies the conservative inventory rule to the whole
/// pair, including otherwise locally complete paths.
#[must_use]
pub fn classify_two_way_path(
	completeness: SyncInventoryCompleteness,
	baseline: SyncBaseline,
	left: SyncObservation,
	right: SyncObservation,
) -> SyncPathDecision {
	use SyncObservation::{AbsentObserved, Present, Unknown, UnsupportedEntry};
	use SyncPathDecision::{
		BaselineMatch, Blocked, BothAbsentAfterCommonPresent, Conflict, NoChange,
	};
	use SyncSide::{Left, Right};

	if completeness == SyncInventoryCompleteness::Incomplete {
		return Blocked(SyncBlock::IncompleteInventory);
	}

	let common_file = match baseline {
		SyncBaseline::CommonPresent(file) => Some(file),
		_ => None,
	};
	match (left, right) {
		(Unknown, _) | (_, Unknown) => Blocked(SyncBlock::UnknownObservation),
		(UnsupportedEntry, _) | (_, UnsupportedEntry) => Conflict(SyncConflict::UnsupportedEntry),
		_ if baseline == SyncBaseline::Asymmetric => Conflict(SyncConflict::AsymmetricBaseline),
		(Present(left), Present(right)) if left == right => {
			if common_file == Some(left) {
				NoChange
			} else {
				BaselineMatch
			}
		}
		(Present(left), Present(_)) if common_file == Some(left) => {
			copy_candidate(Right, SyncCopyTarget::ExistingIncumbent)
		}
		(Present(_), Present(right)) if common_file == Some(right) => {
			copy_candidate(Left, SyncCopyTarget::ExistingIncumbent)
		}
		(Present(_), Present(_)) => Conflict(SyncConflict::DivergentVersions),
		(Present(file), AbsentObserved) => one_present(common_file, file, Left),
		(AbsentObserved, Present(file)) => one_present(common_file, file, Right),
		(AbsentObserved, AbsentObserved) if common_file.is_some() => BothAbsentAfterCommonPresent,
		(AbsentObserved, AbsentObserved) => NoChange,
	}
}

fn one_present(
	common_file: Option<RegularFileEvidence>,
	present: RegularFileEvidence,
	present_side: SyncSide,
) -> SyncPathDecision {
	match common_file {
		None => copy_candidate(present_side, SyncCopyTarget::AbsentName),
		Some(previous) if previous == present => {
			let absent = match present_side {
				SyncSide::Left => SyncSide::Right,
				SyncSide::Right => SyncSide::Left,
			};
			SyncPathDecision::Conflict(SyncConflict::DeletionAgainstUnchanged { absent })
		}
		Some(_) => SyncPathDecision::Conflict(SyncConflict::EditAgainstDeletion {
			edited: present_side,
		}),
	}
}

fn copy_candidate(from: SyncSide, target: SyncCopyTarget) -> SyncPathDecision {
	SyncPathDecision::CopyCandidate { from, target }
}
