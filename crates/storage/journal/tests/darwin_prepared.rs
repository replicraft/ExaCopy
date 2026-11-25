//! Managed APFS preparation payloads require their own bounded canonical profile.

use exacopy_endpoint::{MAX_FILE_LENGTH, MAX_UNIX_COMPONENT_BYTES, NameError, UnixComponent};
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::{
	DarwinEntryPrepared, DarwinJobPrepared, DarwinPreparedError, EntryPrepared, JobPrepared,
	OwnerDigest, PreparedError, TargetObservation,
};

#[path = "darwin_prepared/bindings.rs"]
mod bindings;
#[path = "darwin_prepared/fixtures.rs"]
mod fixtures;
#[path = "darwin_prepared/golden.rs"]
mod golden;

use self::fixtures::{context, destination, entry_id, owner, preparation};

#[test]
fn independent_golden_vectors_preserve_all_observations_and_raw_names() {
	let job_bytes = decode_hex(golden::JOB_HEX);
	let entry_bytes = decode_hex(golden::ENTRY_HEX);
	let job = DarwinJobPrepared::decode(&job_bytes).expect("independent job golden");
	let entry = DarwinEntryPrepared::decode(&entry_bytes).expect("independent entry golden");

	assert_eq!(job.context(), context());
	assert_eq!(job.destination_root(), destination());
	assert_eq!(
		job.owner_digest(),
		OwnerDigest::from_bytes(core::array::from_fn(|i| { u8::try_from(i + 32).unwrap() }))
	);
	assert_eq!(entry.context(), context());
	assert_eq!(entry.entry(), entry_id());
	assert_eq!(entry.preparation(), preparation());
	assert_eq!(
		entry.target_observation(),
		TargetObservation::AbsentObserved
	);
	assert_eq!(entry.validate_job(&job), Ok(()));
	assert_eq!(job.encode(), job_bytes);
	assert_eq!(entry.encode(), entry_bytes);

	let job = DarwinJobPrepared::new(context(), &owner(0xcd), destination()).unwrap();
	let entry = DarwinEntryPrepared::new(&job, entry_id(), preparation()).unwrap();
	let mut bound_job_bytes = job_bytes;
	let mut bound_entry_bytes = entry_bytes;
	for payload in [&mut bound_job_bytes, &mut bound_entry_bytes] {
		let offset = position(
			payload,
			&decode_hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
		);
		payload[offset..offset + 32].copy_from_slice(job.owner_digest().as_bytes());
	}
	assert_eq!(job.encode(), bound_job_bytes);
	assert_eq!(entry.encode(), bound_entry_bytes);
}

#[test]
fn frame_kind_and_profile_are_checked_independently() {
	let job_bytes = decode_hex(golden::JOB_HEX);
	let entry_bytes = decode_hex(golden::ENTRY_HEX);
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	writer.append(FrameKind::JobPrepared, &job_bytes).unwrap();
	writer
		.append(FrameKind::EntryPrepared, &entry_bytes)
		.unwrap();
	let bytes = writer.into_inner();
	let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
	let job = reader.next_frame().unwrap().unwrap();
	let entry = reader.next_frame().unwrap().unwrap();

	assert_eq!(
		DarwinJobPrepared::from_frame(&job).unwrap().encode(),
		job_bytes
	);
	assert_eq!(
		DarwinEntryPrepared::from_frame(&entry).unwrap().encode(),
		entry_bytes
	);
	assert_eq!(
		DarwinJobPrepared::from_frame(&entry),
		Err(PreparedError::WrongRecordKind.into())
	);
	assert_eq!(
		DarwinEntryPrepared::from_frame(&job),
		Err(PreparedError::WrongRecordKind.into())
	);
	assert_eq!(
		JobPrepared::from_frame(&job),
		Err(PreparedError::PayloadTooLarge)
	);
	assert_eq!(
		EntryPrepared::from_frame(&entry),
		Err(PreparedError::UnsupportedVersion)
	);

	// Essential profile discrimination still precedes body decoding when the
	// input fits the Linux bound.
	assert_eq!(
		JobPrepared::decode(&job_bytes[..32]),
		Err(PreparedError::UnsupportedVersion)
	);

	let (linux_job, linux_entry) = fixtures::linux_records();
	assert_eq!(
		DarwinJobPrepared::decode(&linux_job),
		Err(PreparedError::UnsupportedVersion.into())
	);
	assert_eq!(
		DarwinEntryPrepared::decode(&linux_entry),
		Err(PreparedError::UnsupportedVersion.into())
	);
}

#[test]
fn rejects_each_truncated_prefix_and_unbounded_input() {
	let job = decode_hex(golden::JOB_HEX);
	let entry = decode_hex(golden::ENTRY_HEX);
	for end in 0..job.len() {
		assert_eq!(
			DarwinJobPrepared::decode(&job[..end]),
			Err(PreparedError::Truncated.into()),
			"job prefix at {end}"
		);
	}
	for end in 0..entry.len() {
		assert_eq!(
			DarwinEntryPrepared::decode(&entry[..end]),
			Err(PreparedError::Truncated.into()),
			"entry prefix at {end}"
		);
	}
	let oversized = [0; 2048];
	assert_eq!(
		DarwinJobPrepared::decode(&oversized),
		Err(PreparedError::PayloadTooLarge.into())
	);
	assert_eq!(
		DarwinEntryPrepared::decode(&oversized),
		Err(PreparedError::PayloadTooLarge.into())
	);
}

#[test]
fn rejects_unrecognized_required_bits_and_noncanonical_encodings() {
	let job = decode_hex(golden::JOB_HEX);
	let entry = decode_hex(golden::ENTRY_HEX);
	for (bytes, decode) in [
		(
			&job,
			(|bytes: &[u8]| DarwinJobPrepared::decode(bytes).map(|_| ())) as fn(&[u8]) -> _,
		),
		(
			&entry,
			(|bytes: &[u8]| DarwinEntryPrepared::decode(bytes).map(|_| ())) as fn(&[u8]) -> _,
		),
	] {
		let assert_error = |payload: &[u8], error| {
			assert_eq!(decode(payload), Err(DarwinPreparedError::from(error)))
		};
		for version in [0, 1, 3] {
			let mut wrong = bytes.clone();
			wrong[4] = version;
			assert_error(&wrong, PreparedError::UnsupportedVersion);
		}
		let nonzero_minor = patch(bytes, &[0xa3, 0, 2, 1, 0, 2, 1], &[0xa3, 0, 2, 1, 1, 2, 1]);
		assert_error(&nonzero_minor, PreparedError::UnsupportedVersion);
		for required in [0, 2, 3] {
			let mut wrong = bytes.clone();
			wrong[8] = required;
			assert_error(&wrong, PreparedError::UnsupportedFeatures);
			let wrong_outer = patch(bytes, &[6, 1, 10], &[6, required, 10]);
			assert_error(&wrong_outer, PreparedError::UnsupportedFeatures);
		}
		let mut all_indefinite = bytes.clone();
		all_indefinite[0] = 0xbf;
		all_indefinite.push(0xff);
		assert_error(&all_indefinite, PreparedError::InvalidCbor);

		let duplicate_header_key = patch(bytes, &[6, 1, 10], &[5, 1, 10]);
		assert_error(&duplicate_header_key, PreparedError::InvalidCbor);
		let oversized_version = patch(
			bytes,
			&[0xa3, 0, 2, 1, 0, 2, 1],
			&[0xa3, 0, 0x18, 2, 1, 0, 2, 1],
		);
		assert_error(&oversized_version, PreparedError::NonCanonical);
		let long_byte_string = patch(
			bytes,
			&[0xa3, 0, 2, 1, 0, 2, 1, 1, 0x50],
			&[0xa3, 0, 2, 1, 0, 2, 1, 1, 0x58, 0x10],
		);
		assert_error(&long_byte_string, PreparedError::NonCanonical);
		let mut trailing = bytes.clone();
		trailing.push(0);
		assert_error(&trailing, PreparedError::NonCanonical);
	}
}

#[test]
fn rejects_unsupported_scope_identity_and_observation_fields() {
	let job = decode_hex(golden::JOB_HEX);
	let mut mismatched_plan = job.clone();
	let plan_ref = mismatched_plan
		.windows(32)
		.rposition(|bytes| bytes == context().plan_digest.as_bytes())
		.unwrap();
	mismatched_plan[plan_ref] ^= 1;
	assert_eq!(
		DarwinJobPrepared::decode(&mismatched_plan),
		Err(PreparedError::PlanMismatch.into())
	);

	let entry = decode_hex(golden::ENTRY_HEX);
	for (original, change, error) in [
		("a8000001", "a8000101", PreparedError::UnsupportedSourceView),
		(
			"a300020144efffffff",
			"a300010144efffffff",
			PreparedError::UnsupportedIdentity,
		),
		(
			"01481600000000000000",
			"01480000000000000000",
			PreparedError::UnsupportedIdentity,
		),
		(
			"200000000000000002f6",
			"20000000000000000200",
			PreparedError::UnsupportedIdentity,
		),
		(
			"021a0001000003",
			"021b800000000000000003",
			PreparedError::InvalidSourceLength,
		),
		(
			"0119031506",
			"011a3b9aca0006",
			PreparedError::InvalidTimestamp,
		),
		(
			"190180011901f5",
			"1901a4011901f5",
			PreparedError::UnsupportedSourceMetadata,
		),
		(
			"011901f502140200",
			"010002140200",
			PreparedError::UnsupportedSourceMetadata,
		),
		(
			"011901f502140200",
			"011901f502140201",
			PreparedError::UnsupportedTargetObservation,
		),
		(
			"03a2000101467374616765fe",
			"03a2000201467374616765fe",
			PreparedError::UnsupportedTargetEncoding,
		),
	] {
		let wrong = patch(&entry, &decode_hex(original), &decode_hex(change));
		assert_eq!(
			DarwinEntryPrepared::decode(&wrong),
			Err(error.into()),
			"mutated {original}"
		);
	}
	for (component, replaced, error) in [
		(&b"source\xff"[..], &b"/ource\xff"[..], NameError::Separator),
		(&b"stage\xfe"[..], &b"stage\0"[..], NameError::Nul),
		(&b"target\xfd"[..], &b"tar/et\xfd"[..], NameError::Separator),
	] {
		assert_eq!(
			DarwinEntryPrepared::decode(&patch(&entry, component, replaced)),
			Err(DarwinPreparedError::InvalidComponent(error))
		);
	}
}

#[test]
fn largest_names_and_extent_fit_the_encode_buffer() {
	let source_name = [0xfc; MAX_UNIX_COMPONENT_BYTES];
	let stage_name = [0xfd; MAX_UNIX_COMPONENT_BYTES];
	let target_name = [0xfe; MAX_UNIX_COMPONENT_BYTES];
	let job = DarwinJobPrepared::new(context(), &owner(0xcd), destination()).unwrap();
	let mut preparation = preparation();
	preparation.source =
		fixtures::source(UnixComponent::new(&source_name).unwrap(), MAX_FILE_LENGTH);
	preparation.stage.component = UnixComponent::new(&stage_name).unwrap();
	preparation.target_component = UnixComponent::new(&target_name).unwrap();
	let prepared = DarwinEntryPrepared::new(&job, entry_id(), preparation).unwrap();
	let payload = prepared.encode();
	assert_eq!(DarwinEntryPrepared::decode(&payload), Ok(prepared));
	assert_eq!(
		DarwinEntryPrepared::decode(&payload)
			.unwrap()
			.preparation()
			.source
			.length(),
		MAX_FILE_LENGTH
	);
}

fn position(input: &[u8], needle: &[u8]) -> usize {
	input
		.windows(needle.len())
		.position(|field| field == needle)
		.unwrap()
}

fn patch(input: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
	let index = position(input, needle);
	let mut bytes = input.to_vec();
	bytes.splice(index..index + needle.len(), replacement.iter().copied());
	bytes
}

fn decode_hex(hex: &str) -> Vec<u8> {
	let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}
