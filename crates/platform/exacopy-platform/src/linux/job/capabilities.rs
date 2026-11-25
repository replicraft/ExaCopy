use std::fs::File;
use std::io::{self, Write};

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_job::{
	JobBootstrapRoot, JobFileIdentity, JobJournalDirectory, JobRecord, JobWorkspace,
};

use super::{
	DestinationRoot, FileIdentity, JobDirectory, JournalDirectory, LinuxJournalSegment, StageError,
};

impl<'root> JobBootstrapRoot<'root> for DestinationRoot {
	type Error = StageError;
	type Job = JobDirectory<'root>;

	fn identity(&self) -> JobFileIdentity {
		file_identity(DestinationRoot::identity(self))
	}

	fn create_job_directory(
		&'root self,
		name: UnixComponent<'_>,
	) -> Result<Self::Job, Self::Error> {
		DestinationRoot::create_job_directory(self, name)
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		DestinationRoot::sync_directory(self)
	}
}

impl JobWorkspace for JobDirectory<'_> {
	type Error = StageError;
	type Record = NativeJobRecord;
	type Segment = LinuxJournalSegment<'static>;
	type Journal<'job>
		= JournalDirectory<'job>
	where
		Self: 'job;

	fn identity(&self) -> JobFileIdentity {
		file_identity(JobDirectory::identity(self))
	}

	fn create_owner_record(&self) -> Result<Self::Record, Self::Error> {
		JobDirectory::create_owner_record(self).map(NativeJobRecord)
	}

	fn create_plan_record(&self) -> Result<Self::Record, Self::Error> {
		JobDirectory::create_plan_record(self).map(NativeJobRecord)
	}

	fn create_journal_directory(&self) -> Result<Self::Journal<'_>, Self::Error> {
		JobDirectory::create_journal_directory(self)
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		JobDirectory::sync_directory(self)
	}
}

impl JobJournalDirectory for JournalDirectory<'_> {
	type Error = StageError;
	type Segment = LinuxJournalSegment<'static>;

	fn create_first_segment(&self) -> Result<Self::Segment, Self::Error> {
		JournalDirectory::create_first_segment(self)
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		JournalDirectory::sync_directory(self)
	}
}

/// Exclusive writer to one privately created owner or plan record.
pub struct NativeJobRecord(File);

impl Write for NativeJobRecord {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.0.write(bytes)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.0.flush()
	}
}

impl JobRecord for NativeJobRecord {
	fn sync_all(&self) -> io::Result<()> {
		self.0.sync_all()
	}
}

fn file_identity(identity: FileIdentity) -> JobFileIdentity {
	JobFileIdentity {
		device: identity.device(),
		inode: identity.inode(),
	}
}
