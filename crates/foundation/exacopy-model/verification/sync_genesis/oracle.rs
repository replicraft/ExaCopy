//! Finite oracle defined by invalid observations, independent of model control flow.

#[derive(Clone, Copy)]
pub(super) enum Fault {
	AliasedRoots,
	MissingLeftRead,
	MissingRightRead,
	SwappedRoots,
	WrongSubject,
	WrongPolicy,
	OldScan,
	AliasedFiles,
	ReusedRead,
	UnequalLength,
	UnequalStream,
	UnequalMetadata,
	MissingLeftRecheck,
	MissingRightRecheck,
	ChangedFinalObservation,
	EarlyRecheck,
}

pub(super) fn bounded_histories() -> impl Iterator<Item = u32> {
	0..(1 << (Fault::EarlyRecheck as u32 + 1))
}

pub(super) const fn contains(mask: u32, fault: Fault) -> bool {
	mask & (1 << fault as u32) != 0
}

// The template provides complete, distinct and matched evidence. Each named
// fault invalidates at least one required fact. No fault creates positive evidence.
pub(super) const fn has_complete_matched_pair(mask: u32) -> bool {
	mask == 0
}
