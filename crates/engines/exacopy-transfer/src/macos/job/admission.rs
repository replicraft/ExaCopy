//! Checks that held source and destination capabilities agree with the copy plan.

mod engine;

pub use engine::{
	AdmissionFailure, ReadOnlySource, SourceIdentities, SourceMetadataObservation, Timestamp,
	bind_destination, check_source,
};
