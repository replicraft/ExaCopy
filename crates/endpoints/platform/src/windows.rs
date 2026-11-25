//! Windows filename admission for a single child of a held directory.
//!
//! The name contract is available on every host for planning and testing.

mod component;

pub use component::{MAX_WINDOWS_COMPONENT_UNITS, WindowsComponent, WindowsNameError};
