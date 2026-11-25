use std::fs::File;
use std::io::{self, Write};

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_publication::ReceiptRecord;
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{DurableJournal, DurableJournalError, LinuxFileIdentity};
use exacopy_platform::linux::{
	RecoveryFile, RecoveryInventory, RecoveryReceiptDirectory, RecoveryWriteLease, StageError,
};

use super::super::super::{JournalBoundary, LocalCopyPlan};
use super::super::{
	RecoveryHistory, RecoveryInspectError, RecoveryInspection, RecoveryProfile, RecoveryStep,
	native_identity,
};
use super::capabilities::{
	FinishEvidence, FinishJournal, FinishLease, FinishReceiptDirectory, ReceiptLease,
};
use super::protocol::FinishError;
use super::{RecoveryFinishError, completion};

impl FinishLease for RecoveryWriteLease<'_> {
	type InspectError = RecoveryInspectError;
	type History = RecoveryHistory;
	type Inventory<'lease>
		= RecoveryInventory<'lease>
	where
		Self: 'lease;
	type Segment = File;
	type Journal = DurableJournal;

	fn load(
		&self,
		name: UnixComponent<'_>,
		profile: RecoveryProfile<'_>,
	) -> Result<Self::History, Self::InspectError> {
		RecoveryHistory::load(self.job(), name, profile)
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
		self.job()
			.inventory(plan.attempt().stage_name, plan.destination().component)
			.map_err(RecoveryStep::Namespace.platform())
	}

	fn inspect<'lease>(
		&'lease self,
		history: &Self::History,
		names: &Self::Inventory<'lease>,
		scratch: &mut [u8],
	) -> Result<RecoveryInspection, Self::InspectError> {
		history.inspect(self.job(), names, scratch)
	}

	fn stage_directory_identity<'lease>(
		&'lease self,
		names: &Self::Inventory<'lease>,
	) -> Option<LinuxFileIdentity> {
		names.stage_directory_identity().map(native_identity)
	}

	fn open_journal(&self, history: &Self::History) -> Result<Self::Segment, Self::EffectError> {
		self.open_first_segment_for_append(&history.journal_file)
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
		RecoveryWriteLease::sync_publication(self, names)
	}

	fn recheck_names<'lease>(
		&'lease self,
		names: &Self::Inventory<'lease>,
	) -> Result<(), Self::EffectError> {
		names.recheck()
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

impl ReceiptLease for RecoveryWriteLease<'_> {
	type EffectError = StageError;
	type ExistingReceipt = RecoveryFile;
	type Directory<'lease>
		= RecoveryReceiptDirectory<'lease>
	where
		Self: 'lease;

	fn open_receipt_directory(&self) -> Result<Self::Directory<'_>, Self::EffectError> {
		RecoveryWriteLease::open_receipt_directory(self)
	}

	fn sync_job_directory(&self) -> Result<(), Self::EffectError> {
		RecoveryWriteLease::sync_job_directory(self)
	}
}

impl FinishReceiptDirectory for RecoveryReceiptDirectory<'_> {
	type Error = StageError;
	type ExistingReceipt = RecoveryFile;
	type Record = NewReceipt;

	fn sync_receipt(&self, receipt: &Self::ExistingReceipt) -> Result<(), Self::Error> {
		RecoveryReceiptDirectory::sync_receipt(self, receipt)
	}

	fn create_receipt(&self) -> Result<Self::Record, Self::Error> {
		RecoveryReceiptDirectory::create_receipt(self).map(NewReceipt)
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		RecoveryReceiptDirectory::sync_directory(self)
	}
}

pub(super) struct NewReceipt(File);

impl Write for NewReceipt {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.0.write(bytes)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.0.flush()
	}
}

impl ReceiptRecord for NewReceipt {
	fn sync_all(&self) -> io::Result<()> {
		self.0.sync_all()
	}
}

impl From<FinishError<RecoveryInspectError, StageError>> for RecoveryFinishError {
	fn from(error: FinishError<RecoveryInspectError, StageError>) -> Self {
		match error {
			FinishError::Inspection(error) => Self::Inspection(error),
			FinishError::Completion(error) => Self::Completion(error),
			FinishError::Effect { step, source } => completion(step)(source),
			FinishError::IncompleteEvidence => Self::IncompleteEvidence,
			FinishError::EpochExhausted => Self::EpochExhausted,
			FinishError::Resume(error) => Self::Resume(error),
			FinishError::Decision(error) => Self::Decision(error),
			FinishError::Publication(error) => Self::Publication(error),
			FinishError::Journal { kind, source } => Self::Journal { kind, source },
			FinishError::Receipt(error) => Self::Receipt(error),
			FinishError::WriteReceipt(error) => Self::WriteReceipt(error),
		}
	}
}
