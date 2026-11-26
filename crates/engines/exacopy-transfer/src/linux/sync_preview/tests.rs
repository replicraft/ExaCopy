use std::cell::Cell;
use std::convert::Infallible;

use super::*;

struct View<'data> {
	content: &'data [u8],
	length: u64,
	reads: Cell<u32>,
	checks: Cell<u32>,
}

impl<'data> View<'data> {
	fn new(content: &'data [u8]) -> Self {
		Self {
			content,
			length: u64::try_from(content.len()).unwrap(),
			reads: Cell::new(0),
			checks: Cell::new(0),
		}
	}
}

impl ReadView for View<'_> {
	type Error = Infallible;

	fn length(&self) -> u64 {
		self.length
	}

	fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
		let offset = usize::try_from(offset).unwrap();
		output.copy_from_slice(&self.content[offset..offset + output.len()]);
		self.reads.set(self.reads.get() + 1);
		Ok(())
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.checks.set(self.checks.get() + 1);
		Ok(())
	}
}

fn present<'view>(view: &'view View<'_>) -> PreviewInput<'view, View<'view>> {
	PreviewInput::Present {
		view,
		metadata: LinuxOwnerMode {
			mode: 0o640,
			uid: 1000,
			gid: 1000,
		},
	}
}

#[test]
fn checks_both_limits_before_reading_and_refuses_incomplete_recheck() {
	let left = View::new(b"test");
	let mut right = View::new(b"test");
	right.length = MAX_PREVIEW_FILE_BYTES + 1;
	let result = preview_without_history([present(&left), present(&right)], &mut [0; 2], || {
		Ok::<_, Infallible>(())
	});
	assert!(matches!(
		result,
		Err(SyncPreviewFailure::FileLimit(SyncSide::Right))
	));
	assert_eq!((left.reads.get(), right.reads.get()), (0, 0));
	assert_eq!((left.checks.get(), right.checks.get()), (0, 0));

	right.length = left.length;
	let result = preview_without_history([present(&left), present(&right)], &mut [0; 2], || {
		assert_eq!((left.reads.get(), right.reads.get()), (2, 2));
		assert_eq!((left.checks.get(), right.checks.get()), (2, 2));
		Err("stale pair")
	});
	assert!(matches!(
		result,
		Err(SyncPreviewFailure::Pair("stale pair"))
	));
}
