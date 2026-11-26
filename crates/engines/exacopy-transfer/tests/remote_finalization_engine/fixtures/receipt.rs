use std::cell::{Cell, RefCell};
use std::io::{self, Write};
use std::rc::Rc;

use exacopy_endpoint::linux_publication::{ReceiptDirectory, ReceiptRecord, ReceiptWorkspace};

use exacopy_journal::LinuxFileIdentity;
use exacopy_transfer::remote_finalization::RemoteReceiptWorkspace;

use super::{Fault, Step, Tape, enter};

pub struct Receipts {
	pub bytes: Rc<RefCell<Vec<u8>>>,
	fault: Fault,
	tape: Tape,
	checks: Cell<u8>,
}

impl Receipts {
	pub fn new(fault: Fault, tape: Tape) -> Self {
		Self {
			bytes: Rc::default(),
			checks: Cell::new(0),
			fault,
			tape,
		}
	}
}

impl RemoteReceiptWorkspace for Receipts {
	fn check_job(&self, expected: LinuxFileIdentity) -> Result<(), Self::Error> {
		assert_eq!(expected, LinuxFileIdentity::new(7, 11));
		let checks = self.checks.get() + 1;
		self.checks.set(checks);
		enter(&self.tape, self.fault, Step::ReceiptJob(checks))
	}
}

impl ReceiptWorkspace for Receipts {
	type Error = &'static str;
	type Directory<'a> = Directory<'a>;
	fn create_receipt_directory(&self) -> Result<Self::Directory<'_>, Self::Error> {
		enter(&self.tape, self.fault, Step::ReceiptDirectory)?;
		Ok(Directory(self))
	}
	fn sync_directory(&self) -> Result<(), Self::Error> {
		enter(&self.tape, self.fault, Step::JobDirectorySync)
	}
}

pub struct Directory<'a>(&'a Receipts);

impl ReceiptDirectory for Directory<'_> {
	type Error = &'static str;
	type Record = Record;
	fn create_receipt_record(&self) -> Result<Self::Record, Self::Error> {
		enter(&self.0.tape, self.0.fault, Step::ReceiptFile)?;
		Ok(Record(
			Rc::clone(&self.0.bytes),
			self.0.fault,
			Rc::clone(&self.0.tape),
		))
	}
	fn sync_directory(&self) -> Result<(), Self::Error> {
		enter(&self.0.tape, self.0.fault, Step::ReceiptDirectorySync)
	}
}

pub struct Record(Rc<RefCell<Vec<u8>>>, Fault, Tape);

impl Write for Record {
	fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
		enter(&self.2, self.1, Step::ReceiptWrite).map_err(io::Error::other)?;
		self.0.borrow_mut().extend_from_slice(buffer);
		Ok(buffer.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

impl ReceiptRecord for Record {
	fn sync_all(&self) -> io::Result<()> {
		enter(&self.2, self.1, Step::ReceiptFileSync).map_err(io::Error::other)
	}
}
