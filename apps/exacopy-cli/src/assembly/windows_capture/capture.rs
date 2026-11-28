use ed25519_dalek::SigningKey;
use exacopy_endpoint::remote_source::CapturedReadAt;
use exacopy_journal::DurableJournal;
use exacopy_journal::windows_bootstrap::{WindowsBootstrapEvidence, WindowsBootstrapFileIdentity};
use exacopy_journal::windows_capture::{
	WindowsCaptureRoles, WindowsCaptureSelection, append_prepared,
};
use exacopy_platform::windows::{
	WindowsCaptureJournalAdmission, WindowsCaptureJournalSegment, WindowsComponent,
	WindowsGuardedCaptureStage,
};
use exacopy_sftp::SftpSourceError;
use exacopy_transfer::remote_capture::capture_live;

use super::grant::Effects;
use super::ledger::{Ledger, Stage, WindowsCaptureLedgerError as LedgerError};
use super::progress::Progress;
use super::selection::native_identity;
use super::{
	WindowsCaptureError as Error, WindowsCaptureSelectionReceipt, WindowsFreshCaptureReport,
};

pub(super) struct CaptureContext<'a, 'lease> {
	pub(super) bootstrap: &'a WindowsBootstrapEvidence,
	pub(super) selection: WindowsCaptureSelectionReceipt,
	pub(super) sibling: WindowsBootstrapFileIdentity,
	pub(super) target: WindowsComponent<'a>,
	pub(super) signing_key: &'a SigningKey,
	pub(super) effects: &'a Effects<'lease>,
	pub(super) extent: u64,
	pub(super) progress: &'a Progress,
}

impl<'lease> CaptureContext<'_, 'lease> {
	pub(super) async fn run<'stage, R>(
		&self,
		source: &mut R,
		stage: WindowsGuardedCaptureStage<'stage, Effects<'lease>>,
		segment: WindowsCaptureJournalSegment<'stage>,
		admission: WindowsCaptureJournalAdmission<'stage, Effects<'lease>>,
	) -> Result<WindowsFreshCaptureReport, Error>
	where
		R: CapturedReadAt<Error = SftpSourceError>,
	{
		let selected = self.selection;
		let selection = WindowsCaptureSelection {
			bootstrap: self.bootstrap,
			sibling: self.sibling,
			source_scope: selected.source_scope,
			invocation: selected.invocation,
			generation: selected.generation,
			epoch: selected.epoch.get(),
			extent_ceiling: selected.extent_ceiling,
			target: self.target.as_units(),
		};
		let directory = stage.directory_identity();
		let payload = stage.stage_identity();
		let roles = WindowsCaptureRoles {
			sibling: self.sibling,
			stage_directory: native_identity(directory).map_err(Error::Selection)?,
			stage_payload: native_identity(payload).map_err(Error::Selection)?,
		};
		self.effects
			.bind_stage(directory, payload)
			.map_err(Error::Grant)?;
		let journal = DurableJournal::from_new_segment(segment)
			.map_err(|cause| Error::Ledger(LedgerError::Open(cause)))?;
		let enter = |offset, length| admission.enter(offset, length);
		let live = append_prepared(
			journal,
			&selection,
			roles,
			self.extent,
			self.signing_key,
			enter,
		)
		.map_err(|cause| Error::Ledger(LedgerError::Storage(cause)))?;
		self.progress.checkpoint(roles, live.prefix());
		let mut ledger = Ledger {
			live,
			roles,
			directory,
			payload,
			epoch: selected.epoch,
			signing_key: self.signing_key,
			enter,
			progress: self.progress,
		};
		let mut scratch = vec![0; 64 * 1024];
		let writer = Stage {
			native: stage,
			grant: self.effects,
		};
		let capture = capture_live(source, selected.epoch, writer, &mut ledger, &mut scratch)
			.await
			.map_err(|cause| Error::Capture(Box::new(cause)))?;
		let (_held_stage, stream) = capture.into_parts();
		let report = WindowsFreshCaptureReport {
			selection: selected,
			stage_directory: roles.stage_directory,
			stage_payload: roles.stage_payload,
			stream,
			prefix: ledger.live.prefix(),
		};
		self.progress.update(|state| state.measured = Some(report));
		self.effects.check_current().map_err(Error::Grant)?;
		Ok(report)
	}
}
