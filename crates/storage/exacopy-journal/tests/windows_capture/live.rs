use std::cell::{Cell, RefCell};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::{JournalFileBarrier, JournalSegment};
use exacopy_journal::windows_capture::{
	WindowsCaptureError as Error, WindowsCaptureRangeObservation, append_prepared, inspect,
};
use exacopy_journal::{DurableJournal, DurableJournalError};

use super::wire_oracle::{RANGE_DOMAIN, RANGE_KIND, SINGLE_TARGET, range_body, signed_payload};
use super::{BLOCK, Fixture, digest, frame, identity};

#[derive(Default)]
struct Observations {
	written: RefCell<Vec<u8>>,
	active_guard: Cell<bool>,
	syncs: Cell<u32>,
	replay_bytes: RefCell<Option<Vec<u8>>>,
	eof_reads: Cell<u32>,
	refuse_readback: Cell<bool>,
}

impl Observations {
	fn enter(&self) -> Guard<'_> {
		assert!(!self.active_guard.replace(true));
		Guard(self)
	}
}

struct Guard<'a>(&'a Observations);

impl Drop for Guard<'_> {
	fn drop(&mut self) {
		assert!(self.0.active_guard.replace(false));
	}
}

struct Segment<'a> {
	cursor: Cursor<Vec<u8>>,
	facts: &'a Observations,
}

impl Read for Segment<'_> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		assert!(!self.facts.active_guard.get());
		if self.facts.refuse_readback.get() {
			return Err(io::ErrorKind::PermissionDenied.into());
		}
		let replay_bytes = self.facts.replay_bytes.borrow();
		let count = if let Some(bytes) = replay_bytes.as_ref() {
			let mut reader = Cursor::new(bytes.as_slice());
			reader.set_position(self.cursor.position());
			let count = reader.read(buffer)?;
			self.cursor.set_position(reader.position());
			count
		} else {
			self.cursor.read(buffer)?
		};
		if count == 0 && !buffer.is_empty() {
			self.facts.eof_reads.set(self.facts.eof_reads.get() + 1);
		}
		Ok(count)
	}
}

impl Write for Segment<'_> {
	fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
		assert!(self.facts.active_guard.get());
		let count = self.cursor.write(buffer)?;
		self.facts
			.written
			.borrow_mut()
			.extend_from_slice(&buffer[..count]);
		Ok(count)
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

impl Seek for Segment<'_> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.cursor.seek(position)
	}
}

impl JournalSegment for Segment<'_> {
	const BARRIER: JournalFileBarrier = JournalFileBarrier::SyncAll;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		Ok(Some(self.cursor.get_ref().len() as u64))
	}

	fn sync(&self) -> io::Result<()> {
		assert!(self.facts.active_guard.get());
		self.facts.syncs.set(self.facts.syncs.get() + 1);
		Ok(())
	}
}

#[test]
fn same_writer_advances_only_after_a_guarded_sync_and_exact_readback() {
	let fixture = Fixture::new();
	let facts = Observations::default();
	let selected = fixture.selection(&SINGLE_TARGET);
	let writer = DurableJournal::from_new_segment(Segment {
		cursor: Cursor::new(Vec::new()),
		facts: &facts,
	})
	.unwrap();
	let prepared = fixture.prepared(&SINGLE_TARGET, BLOCK + 7);
	let mut live = append_prepared(
		writer,
		&selected,
		fixture.roles,
		BLOCK + 7,
		&fixture.key,
		|offset, bytes| {
			assert_eq!((offset, bytes), (0, prepared.len()));
			Ok(facts.enter())
		},
	)
	.unwrap();
	assert_eq!(*facts.written.borrow(), prepared);
	assert_eq!(facts.syncs.get(), 1);
	assert_eq!(live.prefix().covered_bytes(), 0);
	let observation = WindowsCaptureRangeObservation {
		stage_directory: fixture.roles.stage_directory,
		stage_payload: fixture.roles.stage_payload,
		end_offset: BLOCK,
		digest: [0x4d; 32],
	};
	let before = live.prefix();
	let foreign = SigningKey::from_bytes(&[0x28; 32]);
	let refusal = live.append_range(observation, &foreign, |_, _| -> io::Result<()> {
		panic!("unselected signer entered")
	});
	assert!(matches!(refusal, Err(Error::Signature)));
	let refusal = live.append_range(
		WindowsCaptureRangeObservation {
			stage_payload: identity(0xef),
			..observation
		},
		&fixture.key,
		|_, _| -> io::Result<()> { panic!("changed stage entered") },
	);
	assert!(matches!(refusal, Err(Error::Roles)));
	let refusal = live.append_range(
		WindowsCaptureRangeObservation {
			end_offset: BLOCK - 1,
			..observation
		},
		&fixture.key,
		|_, _| -> io::Result<()> { panic!("incorrect prefix entered") },
	);
	assert!(matches!(refusal, Err(Error::Range)));
	let refusal = live.append_range(observation, &fixture.key, |_, _| {
		Err::<(), _>(io::ErrorKind::PermissionDenied.into())
	});
	assert!(matches!(
		refusal,
		Err(Error::Durable(DurableJournalError::Admission(_)))
	));
	assert_eq!(live.prefix(), before);
	assert_eq!(*facts.written.borrow(), prepared);
	assert_eq!(facts.syncs.get(), 1);

	let first_digest = digest(&prepared);
	let range = frame(
		&signed_payload(
			&range_body(first_digest, first_digest, 1, 0, BLOCK, [0x4d; 32]),
			RANGE_DOMAIN,
			&fixture.key,
		),
		RANGE_KIND,
		2,
		first_digest,
	);
	live.append_range(observation, &fixture.key, |offset, bytes| {
		assert_eq!((offset, bytes), (prepared.len() as u64, 272));
		Ok(facts.enter())
	})
	.unwrap();
	assert_eq!(
		*facts.written.borrow(),
		[prepared.as_slice(), &range].concat()
	);
	assert_eq!(facts.syncs.get(), 2);
	let accepted = live.prefix();
	assert_eq!(accepted.ranges(), 1);
	assert_eq!(accepted.covered_bytes(), BLOCK);
	assert_eq!(accepted.head().digest(), digest(&range));

	let observation = WindowsCaptureRangeObservation {
		end_offset: BLOCK + 7,
		..observation
	};
	facts.refuse_readback.set(true);
	let refusal = live.append_range(observation, &fixture.key, |offset, bytes| {
		assert_eq!((offset, bytes), (accepted.segment_end(), 272));
		Ok(facts.enter())
	});
	assert!(matches!(
		refusal,
		Err(Error::Durable(DurableJournalError::ReadFrame(_)))
	));
	assert_eq!(facts.syncs.get(), 3);
	assert_eq!(live.prefix(), accepted);
	facts.refuse_readback.set(false);
	let retained = facts.written.borrow().clone();
	let historical = inspect(retained.as_slice(), &selected, fixture.roles).unwrap();
	assert_eq!(historical.ranges(), 2);
	assert_eq!(historical.covered_bytes(), BLOCK + 7);
	let refusal = live.append_range(observation, &fixture.key, |_, _| -> io::Result<()> {
		panic!("retired writer entered")
	});
	assert!(matches!(
		refusal,
		Err(Error::Durable(DurableJournalError::Retired))
	));
	assert_eq!(*facts.written.borrow(), retained);
}

#[test]
fn terminal_replay_requires_input_eof_and_the_exact_live_boundary() {
	const EXTENT: u64 = 17;
	const RANGE_DIGEST: [u8; 32] = [0x5a; 32];
	let fixture = Fixture::new();
	let selected = fixture.selection(&SINGLE_TARGET);
	let prepared = fixture.prepared(&SINGLE_TARGET, EXTENT);
	let prepared_digest = digest(&prepared);
	let wire_range = |range_digest| {
		let body = range_body(prepared_digest, prepared_digest, 1, 0, EXTENT, range_digest);
		frame(
			&signed_payload(&body, RANGE_DOMAIN, &fixture.key),
			RANGE_KIND,
			2,
			prepared_digest,
		)
	};
	let tail = wire_range(RANGE_DIGEST);
	let original = [prepared.as_slice(), &tail].concat();
	let replacement = [prepared.as_slice(), &wire_range([0x5b; 32])].concat();
	assert_eq!(original.len(), replacement.len());
	let alternate = inspect(replacement.as_slice(), &selected, fixture.roles).unwrap();
	assert_eq!(alternate.observed_extent(), EXTENT);
	assert_eq!(alternate.covered_bytes(), EXTENT);
	assert_eq!(alternate.head().sequence(), 2);
	assert_ne!(alternate.head().digest(), digest(&tail));

	for (replace, decline, expected_extent) in [
		(false, false, EXTENT),
		(true, false, EXTENT),
		(false, false, EXTENT + 1),
		(false, true, EXTENT),
	] {
		let facts = Observations::default();
		let writer = DurableJournal::from_new_segment(Segment {
			cursor: Cursor::new(Vec::new()),
			facts: &facts,
		})
		.unwrap();
		let mut live = append_prepared(
			writer,
			&selected,
			fixture.roles,
			EXTENT,
			&fixture.key,
			|_, _| Ok(facts.enter()),
		)
		.unwrap();
		live.append_range(
			WindowsCaptureRangeObservation {
				stage_directory: fixture.roles.stage_directory,
				stage_payload: fixture.roles.stage_payload,
				end_offset: EXTENT,
				digest: RANGE_DIGEST,
			},
			&fixture.key,
			|_, _| Ok(facts.enter()),
		)
		.unwrap();
		let confirmed = live.prefix();
		assert_eq!(confirmed.head().digest(), digest(&tail));
		assert_eq!(confirmed.segment_end(), original.len() as u64);
		let prior_eof_reads = facts.eof_reads.get();
		if replace {
			*facts.replay_bytes.borrow_mut() = Some(replacement.clone());
		}
		facts.refuse_readback.set(decline);

		let result = live.inspect_current(&selected, fixture.roles, expected_extent);
		if decline {
			let refusal = result.unwrap_err();
			assert!(refusal.prefix.is_none());
			assert!(matches!(refusal.source, Error::Read(_)));
		} else {
			assert!(facts.eof_reads.get() > prior_eof_reads);
			if replace || expected_extent != EXTENT {
				let refusal = result.unwrap_err();
				assert!(refusal.prefix.is_none());
				assert!(matches!(refusal.source, Error::ReplayBoundary));
			} else {
				assert_eq!(result.unwrap(), confirmed);
			}
		}
		assert_eq!(*facts.written.borrow(), original);
		assert_eq!(facts.syncs.get(), 2);
		assert!(!facts.active_guard.get());
	}
}
