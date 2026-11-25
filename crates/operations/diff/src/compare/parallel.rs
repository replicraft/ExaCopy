use std::num::NonZeroUsize;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use super::{CompareError, LiveComparison, ReadView, compare_views_with, first_difference};

#[cfg(test)]
mod tests;

/// Maximum positioned read workers in one comparison.
pub const MAX_WORKERS: usize = 16;

pub(crate) fn compare_views_parallel<V>(
	left: &V,
	right: &V,
	scratch: &mut [u8],
	workers: NonZeroUsize,
) -> Result<LiveComparison, CompareError<V::Error>>
where
	V: ReadView + Sync,
	V::Error: Send,
{
	let workers = workers.get();
	if workers > MAX_WORKERS {
		return Err(CompareError::TooManyWorkers { workers });
	}
	compare_views_with(left, right, scratch.len(), |length| {
		let workers = workers
			.min(scratch.len() / 2)
			.min(usize::try_from(length).unwrap_or(usize::MAX));
		if workers == 1 {
			first_difference(left, right, 0..length, scratch, || true)
		} else {
			compare_parallel(left, right, length, scratch, workers)
		}
	})
}

fn compare_parallel<V>(
	left: &V,
	right: &V,
	length: u64,
	scratch: &mut [u8],
	workers: usize,
) -> Result<Option<u64>, CompareError<V::Error>>
where
	V: ReadView + Sync,
	V::Error: Send,
{
	let scratch_per_worker = scratch.len() / workers;
	let workers_u64 = u64::try_from(workers).map_err(|_| CompareError::InvalidRange)?;
	let partitions = (0..workers_u64)
		.map(|index| partition(length, workers_u64, index).ok_or(CompareError::InvalidRange))
		.collect::<Result<Vec<_>, _>>()?;
	let stop_before = AtomicUsize::new(workers);
	thread::scope(|scope| {
		let mut handles = Vec::with_capacity(workers);
		let mut start_error = None;
		for (index, (range, worker_scratch)) in partitions
			.into_iter()
			.zip(scratch.chunks_exact_mut(scratch_per_worker))
			.enumerate()
		{
			let offset = range.start;
			let stop_before = &stop_before;
			match thread::Builder::new().spawn_scoped(scope, move || {
				let result = first_difference(left, right, range, worker_scratch, || {
					index < stop_before.load(Ordering::Relaxed)
				});
				if !matches!(result, Ok(None)) {
					// Only later partitions can stop. The result is handed back via join.
					stop_before.fetch_min(index, Ordering::Relaxed);
				}
				result
			}) {
				Ok(handle) => handles.push((offset, handle)),
				Err(source) => {
					stop_before.store(0, Ordering::Relaxed);
					start_error = Some(CompareError::WorkerStart { offset, source });
					break;
				}
			}
		}
		let mut decision = None;
		let mut panic_error = None;
		for (offset, handle) in handles {
			match handle.join() {
				Ok(Ok(None)) => {}
				Ok(result) => {
					decision.get_or_insert(result);
				}
				Err(_) => {
					stop_before.store(0, Ordering::Relaxed);
					panic_error.get_or_insert(CompareError::WorkerPanicked { offset });
				}
			}
		}
		match start_error.or(panic_error) {
			Some(error) => Err(error),
			None => decision.unwrap_or(Ok(None)),
		}
	})
}

fn partition(length: u64, workers: u64, index: u64) -> Option<Range<u64>> {
	if index >= workers || workers > length {
		return None;
	}
	let width = length / workers;
	let remainder = length % workers;
	let start = index
		.checked_mul(width)?
		.checked_add(index.min(remainder))?;
	let count = width.checked_add(u64::from(index < remainder))?;
	Some(start..start.checked_add(count)?)
}
