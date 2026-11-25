//! Managed APFS seal, read-back, metadata, and exclusive publication evidence.

mod binding;
mod codec;
mod error;
mod intent;
mod metadata;
mod publication;
mod seal;
mod verification;

pub use binding::{DarwinPhaseBinding, DarwinPhaseDigest};
pub use error::DarwinPhaseError;
pub use intent::{DarwinPublishIntent, DarwinPublishTarget};
pub use metadata::{DarwinMetadataRecorded, DarwinRequiredMetadata};
pub use publication::{
	DarwinDurabilityRecorded, DarwinNamespaceObservation, DarwinPublicationBarriers,
	DarwinPublicationNames, DarwinPublicationOutcome, DarwinPublishObserved,
	DarwinReceiptCommitted, DarwinReceiptDigest,
};
pub use seal::DarwinStageSealed;
pub use verification::{DarwinStreamEvidence, DarwinVerificationRecorded};
