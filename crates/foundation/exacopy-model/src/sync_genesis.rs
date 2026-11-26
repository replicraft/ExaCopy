//! Pure admission of one matched synchronization subject as a common seed.

use core::num::NonZeroU64;

use exacopy_core::UnixComponent;

use crate::RegularFileEvidence;

/// Opaque identity supplied by the admitted root profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootId(pub [u8; 32]);

/// Opaque identity supplied by the admitted regular-file profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId(pub [u8; 32]);

/// Selected observation scope and required metadata policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope<'name> {
	/// Binds owner and profile revision, ordered roots and mount session.
	pub selection: [u8; 32],
	/// The exact validated raw basename selected under each root.
	pub name: UnixComponent<'name>,
	/// Binds the selected stream, required metadata and comparison policy.
	pub policy: [u8; 32],
}

/// One explicitly selected scan of ordered left and right roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection<'name> {
	/// The roots in left, right order.
	pub roots: [RootId; 2],
	/// The exact subject and policy used for every observation.
	pub scope: Scope<'name>,
	/// Nonzero instance supplied by the coordinator for this scan.
	pub scan: NonZeroU64,
}

/// Live stability evidence reported by the selected read-only adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservationStamp<'name> {
	/// Authorized root carrying the observed name.
	pub root: RootId,
	/// Exact subject scope and policy.
	pub scope: Scope<'name>,
	/// Instance of the scan that supplied this observation.
	pub scan: NonZeroU64,
	/// Physically observed regular-file identity.
	pub file: FileId,
	/// Equality-relevant native stability observations from the admitted profile.
	pub stability: [u8; 32],
}

/// A completed independent read, including EOF and required metadata checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measurement<'name> {
	/// Rooted live observation that remained stable through the measurement.
	pub observation: ObservationStamp<'name>,
	/// Unique, increasing completion position in the coordinator's scan.
	pub completed_at: NonZeroU64,
	/// Independently measured stream and required metadata.
	pub evidence: RegularFileEvidence,
}

/// A fresh final observation of one name under the held pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecheckedObservation<'name> {
	/// The rechecked rooted observation.
	pub observation: ObservationStamp<'name>,
	/// Sample position from the same scan sequence as both completed reads.
	pub observed_at: NonZeroU64,
}

/// Why the paired observations do not support an initial common seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GenesisRefusal {
	/// Both selected roots claim the same identity.
	AliasedRoots,
	/// One or both sides lacks a complete supported present measurement.
	MissingMeasurement,
	/// A measurement belongs to a different root, scope, policy or scan.
	MeasurementBinding,
	/// Both completed measurements claim the same file identity.
	AliasedFiles,
	/// Both sides claim the same measurement completion position.
	ReusedMeasurement,
	/// The two measured lengths or digests differ.
	DifferentEvidence,
	/// A final observation is missing, changed or not later than both measurements.
	StaleRecheck,
}

/// Matched ordered measurements admitted as a common observation.
#[derive(Debug, PartialEq, Eq)]
pub struct AdmittedGenesis<'name> {
	selection: Selection<'name>,
	measurements: [Measurement<'name>; 2],
}

impl<'name> AdmittedGenesis<'name> {
	/// Returns the exact scope and scan used for admission.
	#[must_use]
	pub const fn selection(&self) -> Selection<'name> {
		self.selection
	}

	/// Returns the two independently completed measurements in left, right order.
	#[must_use]
	pub const fn measurements(&self) -> &[Measurement<'name>; 2] {
		&self.measurements
	}
}

/// Admits matching present evidence from one explicitly selected scan.
///
/// The caller supplies observations from held, disjoint roots, independently
/// measures both files, and samples both final names after the two reads.
/// Completion positions come from one strictly increasing scan sequence.
/// Opaque identities, scope and stability projections must faithfully encode the
/// admitted native facts and applicable policy. This function checks their equality
/// and ordering. The result carries observation evidence only.
///
/// # Errors
/// Refuses missing, reused, aliased, stale or mismatched evidence.
pub fn admit<'name>(
	selection: Selection<'name>,
	measurements: [Option<Measurement<'name>>; 2],
	rechecked: [Option<RecheckedObservation<'name>>; 2],
) -> Result<AdmittedGenesis<'name>, GenesisRefusal> {
	if selection.roots[0] == selection.roots[1] {
		return Err(GenesisRefusal::AliasedRoots);
	}
	let [Some(left), Some(right)] = measurements else {
		return Err(GenesisRefusal::MissingMeasurement);
	};
	for (measurement, root) in [left, right].into_iter().zip(selection.roots) {
		let observed = measurement.observation;
		if observed.root != root
			|| observed.scope != selection.scope
			|| observed.scan != selection.scan
		{
			return Err(GenesisRefusal::MeasurementBinding);
		}
	}
	if left.observation.file == right.observation.file {
		return Err(GenesisRefusal::AliasedFiles);
	}
	if left.completed_at == right.completed_at {
		return Err(GenesisRefusal::ReusedMeasurement);
	}
	if left.evidence != right.evidence {
		return Err(GenesisRefusal::DifferentEvidence);
	}
	let last_measurement = left.completed_at.max(right.completed_at);
	for (observed, measurement) in rechecked.into_iter().zip([left, right]) {
		if !observed.is_some_and(|observed| {
			observed.observed_at > last_measurement
				&& observed.observation == measurement.observation
		}) {
			return Err(GenesisRefusal::StaleRecheck);
		}
	}
	Ok(AdmittedGenesis {
		selection,
		measurements: [left, right],
	})
}
