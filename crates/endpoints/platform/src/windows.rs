//! Windows filename admission for a single child of a held directory.
//!
//! The name contract is available on every host for planning and testing.

mod component;

pub use component::{MAX_WINDOWS_COMPONENT_UNITS, WindowsComponent, WindowsNameError};

#[cfg(all(target_os = "windows", feature = "experimental-windows-copy"))]
#[allow(
	unsafe_code,
	reason = "counted handle-relative open and initialized Windows observations"
)]
mod native;
#[cfg(all(target_os = "windows", feature = "experimental-windows-copy"))]
mod stage;

#[cfg(all(target_os = "windows", feature = "experimental-windows-copy"))]
pub use native::ObjectId as WindowsStageIdentity;
#[cfg(all(target_os = "windows", feature = "experimental-windows-copy"))]
pub use stage::{
	MAX_WINDOWS_STAGE_IO_BYTES, NativeStageError, WindowsStageDirectory, WindowsStageError,
	WindowsStageReadBack, WindowsStageWriter,
};
