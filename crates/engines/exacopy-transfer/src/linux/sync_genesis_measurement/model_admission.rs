//! Adapt exact in-memory observations to P-053's equality inputs.

use core::num::NonZeroU64;

use exacopy_model::RegularFileEvidence;
use exacopy_model::sync_genesis::{
	self, FileId, GenesisRefusal, Measurement, ObservationStamp, RecheckedObservation, RootId,
	Scope, Selection,
};
use exacopy_plan::workflow_sync::{LinuxLocation, NativeObject};

use super::{CompletedRead, FINAL_PAIR, GenesisFileFacts, LiveSyncSelection};

pub(super) fn admit<'name>(
	[selected, measured, rechecked]: [LiveSyncSelection<'name>; 3],
	policy: [u8; 32],
	scan: NonZeroU64,
	reads: &[CompletedRead; 2],
	final_files: [GenesisFileFacts; 2],
) -> Result<(), GenesisRefusal> {
	// These labels preserve exact equality across the three scope samples and
	// four native file samples in this call. They are neither stored nor exported.
	let [selected_scope, measured_scope, rechecked_scope] = labels([selected, measured, rechecked]);
	let [left_measured, right_measured] = reads.each_ref().map(|read| read.facts);
	let [left_stability, right_stability, left_final, right_final] = labels([
		left_measured,
		right_measured,
		final_files[0],
		final_files[1],
	]);
	let scopes = |label, live: LiveSyncSelection<'name>| Scope {
		selection: label,
		name: live.subject,
		policy,
	};
	let selection = Selection {
		roots: selected
			.endpoints
			.map(|endpoint| root_id(endpoint.location)),
		scope: scopes(selected_scope, selected),
		scan,
	};
	let measured_scope = scopes(measured_scope, measured);
	let rechecked_scope = scopes(rechecked_scope, rechecked);
	let measured_stability = [left_stability, right_stability];
	let final_stability = [left_final, right_final];
	// P-053 compares this field only for equality. Use exact owner/mode labels
	// here and retain the canonical metadata digest for the P-063 artifact.
	let metadata_labels = labels(reads.each_ref().map(|read| read.metadata));

	// Only this scan can supply these stamps. The held adapter supplies both
	// original facts, full bracketed reads and fresh final facts from the same
	// named descriptors and lease. Stream equality assumes BLAKE3 collision resistance.
	let measurements = core::array::from_fn(|index| {
		let read = &reads[index];
		let location = measured.endpoints[index].location;
		Some(Measurement {
			observation: ObservationStamp {
				root: root_id(location),
				scope: measured_scope,
				scan,
				file: FileId(native_object(location.boot, read.facts.object)),
				stability: measured_stability[index],
			},
			completed_at: read.measured.position,
			evidence: RegularFileEvidence {
				byte_len: read.stream.length,
				content_digest: read.stream.digest,
				required_metadata_digest: metadata_labels[index],
			},
		})
	});
	let final_observations = core::array::from_fn(|index| {
		let location = rechecked.endpoints[index].location;
		Some(RecheckedObservation {
			observation: ObservationStamp {
				root: root_id(location),
				scope: rechecked_scope,
				scan,
				file: FileId(native_object(location.boot, final_files[index].object)),
				stability: final_stability[index],
			},
			observed_at: FINAL_PAIR,
		})
	});
	sync_genesis::admit(selection, measurements, final_observations).map(|_| ())
}

fn root_id(location: LinuxLocation) -> RootId {
	RootId(native_object(location.boot, location.root))
}

fn native_object(boot: [u8; 16], object: NativeObject) -> [u8; 32] {
	let mut bytes = [0; 32];
	bytes[..16].copy_from_slice(&boot);
	bytes[16..20].copy_from_slice(&object.major.to_le_bytes());
	bytes[20..24].copy_from_slice(&object.minor.to_le_bytes());
	bytes[24..].copy_from_slice(&object.inode.get().to_le_bytes());
	bytes
}

fn labels<T: Eq, const N: usize>(facts: [T; N]) -> [[u8; 32]; N] {
	core::array::from_fn(|index| {
		let first = facts[..index]
			.iter()
			.position(|earlier| *earlier == facts[index])
			.unwrap_or(index);
		let mut label = [0; 32];
		let index = first.to_le_bytes();
		label[..index.len()].copy_from_slice(&index);
		label
	})
}
