use crate::{DocumentPageKind, PlanIdentityPlatform};

use super::super::super::{
	PlanConflict, PlanConsistency, PlanDurability, PlanFidelity, PlanOperation, PlanPreservation,
	PlanPublication, PlanSourceRetirement, PlanStorage, PlanVerification, PlanViewConsistency,
};
use super::super::PlanJsonError;

pub(super) trait WireName: Sized {
	fn parse(text: &str) -> Result<Self, PlanJsonError>;
	fn name(self) -> &'static str;
}

macro_rules! wire_names {
	($ty:ty, $($variant:ident => $wire:literal),+ $(,)?) => {
		impl WireName for $ty {
			fn parse(text: &str) -> Result<Self, PlanJsonError> {
				match text {
					$($wire => Ok(Self::$variant),)+
					_ => Err(PlanJsonError::Unsupported),
				}
			}

			fn name(self) -> &'static str {
				match self {
					$(Self::$variant => $wire,)+
				}
			}
		}
	};
}

wire_names!(PlanOperation,
	Copy => "copy",
	Move => "move",
	Restore => "restore",
	Backup => "backup",
	Dedupe => "dedupe",
	Reclaim => "reclaim",
	Repair => "repair",
);

wire_names!(PlanPreservation,
	Preserve => "preserve",
	ProtectedReplace => "protected_replace",
	ProtectedMove => "protected_move",
	ExplicitReclaim => "explicit_reclaim",
);
wire_names!(PlanConflict, Error => "error", Skip => "skip", Rename => "rename", ProtectedReplace => "protected-replace");
wire_names!(PlanVerification, Blake3Readback => "blake3_readback", Sha256Readback => "sha256_readback", Bytes => "bytes");
wire_names!(PlanStorage, Independent => "independent", SharedCow => "shared-cow");
wire_names!(PlanPublication, PerFile => "per_file", NewTree => "new_tree");
wire_names!(PlanConsistency,
	Auto => "auto",
	LiveObserved => "live_observed",
	FileStable => "file_stable",
	TreeSnapshot => "tree_snapshot",
	ApplicationConsistent => "application_consistent",
);
wire_names!(PlanViewConsistency,
	LiveObserved => "live_observed",
	FileStable => "file_stable",
	TreeSnapshot => "tree_snapshot",
	ApplicationConsistent => "application_consistent",
);
wire_names!(PlanDurability, ProcessCrash => "process_crash", QualifiedPowerLoss => "qualified_power_loss");
wire_names!(PlanFidelity, RequiredData => "required-data", NativeStrict => "native-strict", Portable => "portable");
wire_names!(PlanSourceRetirement, None => "none", Quarantine => "quarantine");

wire_names!(DocumentPageKind,
	PlanEntries => "plan_entries",
	ManifestEntries => "manifest_entries",
	DiffEntries => "diff_entries",
	ReceiptEntries => "receipt_entries",
	PatchOperations => "patch_operations",
	MetadataEntries => "metadata_entries",
);

wire_names!(PlanIdentityPlatform,
	Linux => "linux",
	Windows => "windows",
	Macos => "macos",
	Remote => "remote",
	Repository => "repository",
);
