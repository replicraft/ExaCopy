//! Windows filename admission for a single child of a held directory.
//!
//! The name contract is available on every host for planning and testing.

mod component;

pub use component::{MAX_WINDOWS_COMPONENT_UNITS, WindowsComponent, WindowsNameError};

#[cfg(all(
	target_os = "windows",
	feature = "experimental-windows-read",
	feature = "experimental-windows-copy"
))]
mod capture_creation;
#[cfg(all(target_os = "windows", feature = "experimental-windows-copy"))]
mod identity;
#[cfg(all(target_os = "windows", test, feature = "experimental-windows-copy"))]
mod identity_tests;
#[cfg(all(
	target_os = "windows",
	any(
		feature = "experimental-windows-copy",
		feature = "experimental-windows-read"
	)
))]
#[allow(
	unsafe_code,
	reason = "counted handle-relative open and initialized Windows observations"
)]
mod native;
#[cfg(all(target_os = "windows", feature = "experimental-windows-copy"))]
mod stage;
#[cfg(all(
	target_os = "windows",
	any(
		feature = "experimental-windows-copy",
		feature = "experimental-windows-read"
	)
))]
#[allow(
	unsafe_code,
	reason = "bounded initialized Windows stream inventory query"
)]
mod streams;

#[cfg(all(target_os = "windows", feature = "experimental-windows-copy"))]
pub use native::ObjectId as WindowsStageIdentity;
#[cfg(all(target_os = "windows", feature = "experimental-windows-copy"))]
pub use stage::{
	MAX_WINDOWS_STAGE_IO_BYTES, NativeStageError, WindowsClosedPublicationStage,
	WindowsPublicationAttempt, WindowsPublicationBinding, WindowsPublicationDestination,
	WindowsPublicationError, WindowsPublicationMetadata, WindowsPublicationOutcome,
	WindowsPublicationRoot, WindowsPublicationTargetObservation, WindowsRetainedStage,
	WindowsSealedPublicationStage, WindowsStageDirectory, WindowsStageError, WindowsStagePrefix,
	WindowsStageReadBack, WindowsStageView, WindowsStageWriter,
	WindowsUnconfirmedPublicationDirectory, inspect_windows_publication_target,
};

#[cfg(all(target_os = "windows", feature = "experimental-windows-read"))]
mod read;
#[cfg(all(
	feature = "experimental-windows-read",
	any(target_os = "windows", test)
))]
mod read_path;
#[cfg(all(target_os = "windows", feature = "experimental-windows-read"))]
pub use read::{WindowsReadError, WindowsReadFile};

#[cfg(all(target_os = "windows", feature = "experimental-windows-read"))]
pub(crate) use read::protected as protected_snapshot;

#[cfg(all(
	target_os = "windows",
	feature = "experimental-windows-copy",
	feature = "experimental-windows-read"
))]
pub use read::protected::bootstrap::{
	WindowsBootstrapFreshSegment, WindowsBootstrapLayout, WindowsBootstrapRecords,
	WindowsBootstrapRoleKind, WindowsBootstrapRoleObservations, WindowsBootstrapRootSelection,
	WindowsBootstrapSegment, WindowsCaptureStageError, WindowsCaptureStageScope,
	WindowsCaptureStageWriter, observe_windows_bootstrap_role_identity,
};
