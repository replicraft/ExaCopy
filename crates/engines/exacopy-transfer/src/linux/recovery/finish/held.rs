use std::fs::File;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_recovery::{RecoveryInventoryView, RecoveryJobView};
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{DurableJournal, DurableJournalError, LinuxFileIdentity};

use super::super::super::{JournalBoundary, LocalCopyPlan};
use super::super::{
	InspectionError, LeaseInventory, LeaseReadError, RecoveryHistory, RecoveryInspection,
	RecoveryLease, RecoveryProfile, RecoveryStep, record_identity,
};
use super::capabilities::{FinishEvidence, FinishJournal, FinishLease, ReceiptLease};

pub(super) struct HeldRecovery<'lease, L>(pub(super) &'lease L);

impl<L: RecoveryLease> FinishLease for HeldRecovery<'_, L> {
	type InspectError = InspectionError<LeaseReadError<L>, L::EffectError>;
	type History = RecoveryHistory<L::File>;
	type Inventory<'lease>
		= LeaseInventory<'lease, L>
	where
		Self: 'lease;
	type Segment = File;
	type Journal = DurableJournal;

	fn load(
		&self,
		name: UnixComponent<'_>,
		profile: RecoveryProfile<'_>,
	) -> Result<Self::History, Self::InspectError> {
		RecoveryHistory::load(self.0.job(), name, profile)
	}

	fn evidence<'history>(
		&self,
		history: &'history Self::History,
	) -> Result<FinishEvidence<'history, Self::ExistingReceipt>, Self::InspectError> {
		Ok(FinishEvidence {
			plan: history.plan()?,
			replay: &history.journal,
			authorization: history.owner.digest(),
			receipt: history.receipt.as_ref(),
		})
	}

	fn inventory(
		&self,
		plan: LocalCopyPlan<'_>,
	) -> Result<Self::Inventory<'_>, Self::InspectError> {
		self.0
			.job()
			.inventory(plan.attempt().stage_name, plan.destination().component)
			.map_err(RecoveryStep::Namespace.platform())
	}

	fn inspect<'lease>(
		&'lease self,
		history: &Self::History,
		names: &Self::Inventory<'lease>,
		scratch: &mut [u8],
	) -> Result<RecoveryInspection, Self::InspectError> {
		history.inspect(self.0.job(), names, scratch)
	}

	fn stage_directory_identity<'lease>(
		&'lease self,
		names: &Self::Inventory<'lease>,
	) -> Option<LinuxFileIdentity> {
		names.stage_directory_identity().map(record_identity)
	}

	fn open_journal(&self, history: &Self::History) -> Result<Self::Segment, Self::EffectError> {
		self.0.open_segment(&history.journal_file)
	}

	fn resume_journal(
		&self,
		segment: Self::Segment,
		boundary: JournalBoundary,
	) -> Result<Self::Journal, DurableJournalError> {
		DurableJournal::resume_first_segment(segment, boundary.head, boundary.offset)
	}

	fn sync_publication<'lease>(
		&'lease self,
		names: &Self::Inventory<'lease>,
	) -> Result<(), Self::EffectError> {
		self.0.synchronize_publication(names)
	}

	fn recheck_names<'lease>(
		&'lease self,
		names: &Self::Inventory<'lease>,
	) -> Result<(), Self::EffectError> {
		names.recheck()
	}
}

impl<L: RecoveryLease> ReceiptLease for HeldRecovery<'_, L> {
	type EffectError = L::EffectError;
	type ExistingReceipt = L::File;
	type Directory<'lease>
		= L::Directory<'lease>
	where
		Self: 'lease;

	fn open_receipt_directory(&self) -> Result<Self::Directory<'_>, Self::EffectError> {
		self.0.open_receipt_directory()
	}

	fn sync_job_directory(&self) -> Result<(), Self::EffectError> {
		self.0.sync_job_directory()
	}
}

impl FinishJournal for DurableJournal {
	fn append(
		&mut self,
		kind: FrameKind,
		payload: &[u8],
	) -> Result<ChainHead, DurableJournalError> {
		DurableJournal::append(self, kind, payload).map(|frame| frame.head())
	}
}
