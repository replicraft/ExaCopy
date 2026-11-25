use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_publication::ReceiptRecord;
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{DurableJournalError, LinuxFileIdentity, OwnerDigest};

use super::super::super::{JournalBoundary, JournalReplay, LocalCopyPlan};
use super::super::{RecoveryInspection, RecoveryProfile};

pub(super) struct FinishEvidence<'history, R> {
	pub(super) plan: LocalCopyPlan<'history>,
	pub(super) replay: &'history JournalReplay,
	pub(super) authorization: OwnerDigest,
	pub(super) receipt: Option<&'history R>,
}

/// Access scoped to a single job whose exclusive lease remains held.
pub(super) trait FinishLease: ReceiptLease {
	type InspectError;
	type History;
	type Inventory<'lease>
	where
		Self: 'lease;
	type Segment;
	type Journal: FinishJournal;

	/// Authenticates and reads the bounded job artifacts through held handles.
	fn load(
		&self,
		name: UnixComponent<'_>,
		profile: RecoveryProfile<'_>,
	) -> Result<Self::History, Self::InspectError>;

	fn evidence<'history>(
		&self,
		history: &'history Self::History,
	) -> Result<FinishEvidence<'history, Self::ExistingReceipt>, Self::InspectError>;

	/// Pins current namespace entries under the job and its destination.
	fn inventory(&self, plan: LocalCopyPlan<'_>)
	-> Result<Self::Inventory<'_>, Self::InspectError>;

	/// Checks the current entries against the authenticated history, including read-back.
	fn inspect<'lease>(
		&'lease self,
		history: &Self::History,
		names: &Self::Inventory<'lease>,
		scratch: &mut [u8],
	) -> Result<RecoveryInspection, Self::InspectError>;

	fn stage_directory_identity<'lease>(
		&'lease self,
		names: &Self::Inventory<'lease>,
	) -> Option<LinuxFileIdentity>;

	/// Reopens the same observed segment without creating or truncating it.
	fn open_journal(&self, history: &Self::History) -> Result<Self::Segment, Self::EffectError>;

	/// Rereads and synchronizes the observed segment at the exact accepted boundary.
	fn resume_journal(
		&self,
		segment: Self::Segment,
		boundary: JournalBoundary,
	) -> Result<Self::Journal, DurableJournalError>;

	/// Synchronizes the published file, former stage directory, and destination directory.
	fn sync_publication<'lease>(
		&'lease self,
		names: &Self::Inventory<'lease>,
	) -> Result<(), Self::EffectError>;

	fn recheck_names<'lease>(
		&'lease self,
		names: &Self::Inventory<'lease>,
	) -> Result<(), Self::EffectError>;
}

pub(super) trait FinishJournal {
	/// Appends a complete frame and returns its chain head only after its barrier succeeds.
	fn append(&mut self, kind: FrameKind, payload: &[u8])
	-> Result<ChainHead, DurableJournalError>;
}

pub(super) trait ReceiptLease {
	type EffectError;
	type ExistingReceipt;
	type Directory<'lease>: FinishReceiptDirectory<Error = Self::EffectError, ExistingReceipt = Self::ExistingReceipt>
	where
		Self: 'lease;

	/// Opens or exclusively creates the fixed private directory.
	fn open_receipt_directory(&self) -> Result<Self::Directory<'_>, Self::EffectError>;
	fn sync_job_directory(&self) -> Result<(), Self::EffectError>;
}

pub(super) trait FinishReceiptDirectory {
	type Error;
	type ExistingReceipt;
	type Record: ReceiptRecord;

	/// Synchronizes the exact previously inspected receipt.
	fn sync_receipt(&self, receipt: &Self::ExistingReceipt) -> Result<(), Self::Error>;
	/// Creates the fixed private receipt without replacing an incumbent.
	fn create_receipt(&self) -> Result<Self::Record, Self::Error>;
	fn sync_directory(&self) -> Result<(), Self::Error>;
}
