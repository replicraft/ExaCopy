//! Independent wire vectors and malformed payloads for preparation records.

use exacopy_endpoint::{MAX_FILE_LENGTH, MAX_UNIX_COMPONENT_BYTES, NameError, UnixComponent};
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::{
	DestinationRootBinding, EntryPreparation, EntryPrepared, JobPrepared, JournalContext,
	JournalEntryId, JournalEpoch, JournalJobId, LinuxFileIdentity, LiveSourceView,
	ObservedTimestamp, OwnerDigest, PlanDigest, PreparedError, PreparedTarget, RootCapabilityId,
	SourceInodeMetadata, SourceTimes, TargetObservation,
};

// These vectors come from a separate Python emitter for RFC 8949 numeric maps.
const JOB: &[u8] = b"\xa6\x00\xa3\x00\x01\x01\x00\x02\x00\x01\x50\x01\x82\x79\x74\x55\
\x90\x7a\x14\x88\x88\x9c\x84\x07\xc7\x18\xca\x02\x18\x18\x05\x58\
\x20\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\
\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\
\x1f\x06\x00\x0a\xa3\x00\x58\x20\x20\x21\x22\x23\x24\x25\x26\x27\
\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\
\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x01\x58\x20\x00\x01\x02\x03\x04\
\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\
\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x02\xa2\x00\x50\x11\
\x22\x33\x44\x55\x66\x47\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x01\
\xa4\x00\x01\x01\x48\x08\x07\x06\x05\x04\x03\x02\x01\x02\x48\x88\
\x77\x66\x55\x44\x33\x22\x11\x03\xf6";

const ENTRY: &[u8] = b"\xa7\x00\xa3\x00\x01\x01\x00\x02\x00\x01\x50\x01\x82\x79\x74\x55\
\x90\x7a\x14\x88\x88\x9c\x84\x07\xc7\x18\xca\x02\x18\x18\x03\x50\
\xaa\xbb\xcc\xdd\xee\xff\x47\x77\x99\x88\x77\x66\x55\x44\x33\x22\
\x05\x58\x20\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\
\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\
\x1d\x1e\x1f\x06\x00\x0a\xa4\x00\xa6\x00\x00\x01\xa4\x00\x01\x01\
\x48\x08\x07\x06\x05\x04\x03\x02\x01\x02\x48\x18\x17\x16\x15\x14\
\x13\x12\x11\x03\xf6\x02\x1a\x00\x01\x00\x00\x03\x82\x21\x19\x01\
\x90\x04\x82\x19\x02\xbc\x00\x05\x82\x19\x02\xbc\x19\x01\xf4\x01\
\xa4\x00\x01\x01\x48\x08\x07\x06\x05\x04\x03\x02\x01\x02\x48\xf8\
\xf7\xf6\xf5\xf4\xf3\xf2\xf1\x03\xf6\x02\xa2\x00\x50\x11\x22\x33\
\x44\x55\x66\x47\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x01\x81\xa2\
\x00\x01\x01\x48\x72\x65\x70\x6f\x72\x74\xff\x5c\x03\xa2\x00\xa5\
\x00\x19\x01\xa0\x01\x19\x04\xd2\x02\x19\x10\xe1\x03\x01\x04\x00\
\x01\x00";

#[test]
fn matches_independent_job_and_entry_golden_vectors() {
	let job = job_fixture();
	let entry = entry_fixture(b"report\xff\\");
	assert_eq!(job.encode(), JOB);
	assert_eq!(entry.encode(), ENTRY);
	assert_eq!(JobPrepared::decode(JOB), Ok(job));
	assert_eq!(EntryPrepared::decode(ENTRY), Ok(entry));
	assert_eq!(
		EntryPrepared::decode(ENTRY)
			.expect("canonical entry payload")
			.preparation()
			.target
			.component
			.as_bytes(),
		b"report\xff\\",
	);
}

#[test]
fn decodes_only_the_requested_verified_frame_kind() {
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	writer
		.append(FrameKind::JobPrepared, JOB)
		.expect("append job frame");
	writer
		.append(FrameKind::EntryPrepared, ENTRY)
		.expect("append entry frame");
	let bytes = writer.into_inner();
	let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());

	let job = reader
		.next_frame()
		.expect("verified frame")
		.expect("job frame present");
	assert_eq!(
		EntryPrepared::from_frame(&job),
		Err(PreparedError::WrongRecordKind)
	);
	assert_eq!(JobPrepared::from_frame(&job), Ok(job_fixture()));

	let entry = reader
		.next_frame()
		.expect("verified frame")
		.expect("entry frame present");
	assert_eq!(
		JobPrepared::from_frame(&entry),
		Err(PreparedError::WrongRecordKind)
	);
	assert_eq!(
		EntryPrepared::from_frame(&entry),
		Ok(entry_fixture(b"report\xff\\"))
	);
}

#[test]
fn rejects_every_truncated_prefix() {
	for end in 0..JOB.len() {
		assert_eq!(
			JobPrepared::decode(&JOB[..end]),
			Err(PreparedError::Truncated),
			"job prefix {end}"
		);
	}
	for end in 0..ENTRY.len() {
		assert_eq!(
			EntryPrepared::decode(&ENTRY[..end]),
			Err(PreparedError::Truncated),
			"entry prefix {end}"
		);
	}
}

#[test]
fn rejects_bad_headers_and_noncanonical_records() {
	let mut job = JOB.to_vec();
	job[0] = 0xbf;
	assert_eq!(JobPrepared::decode(&job), Err(PreparedError::InvalidCbor));
	job.splice(..1, [0xb8, 6]);
	assert_eq!(JobPrepared::decode(&job), Err(PreparedError::NonCanonical));

	let mut entry = ENTRY.to_vec();
	entry[4] = 2;
	assert_eq!(
		EntryPrepared::decode(&entry),
		Err(PreparedError::UnsupportedVersion)
	);
	entry[4] = 1;
	entry[8] = 1;
	assert_eq!(
		EntryPrepared::decode(&entry),
		Err(PreparedError::UnsupportedFeatures)
	);
	entry[8] = 0;
	entry[5] = 0;
	assert_eq!(
		EntryPrepared::decode(&entry),
		Err(PreparedError::InvalidCbor)
	);

	let mut with_trailing = ENTRY.to_vec();
	with_trailing.push(0);
	assert_eq!(
		EntryPrepared::decode(&with_trailing),
		Err(PreparedError::NonCanonical)
	);

	let wide_time = patch(
		ENTRY,
		&[0x82, 0x21, 0x19, 0x01, 0x90],
		&[0x82, 0x38, 1, 0x19, 0x01, 0x90],
	);
	assert_eq!(
		EntryPrepared::decode(&wide_time),
		Err(PreparedError::NonCanonical)
	);
}

#[test]
fn rejects_unbound_plan_root_and_native_generation() {
	let mut job = JOB.to_vec();
	let plan_ref = job
		.windows(32)
		.rposition(|bytes| bytes == digest(0))
		.expect("plan reference in body");
	job[plan_ref] = 255;
	assert_eq!(JobPrepared::decode(&job), Err(PreparedError::PlanMismatch));

	let job_bad_root = patch(JOB, root().as_bytes(), &[0; 16]);
	assert_eq!(
		JobPrepared::decode(&job_bad_root),
		Err(PreparedError::InvalidRoot)
	);
	let entry_bad_root = patch(ENTRY, root().as_bytes(), &[0; 16]);
	assert_eq!(
		EntryPrepared::decode(&entry_bad_root),
		Err(PreparedError::InvalidRoot)
	);

	let bad_identity = patch(JOB, &[3, 0xf6], &[3, 0x40]);
	assert_eq!(
		JobPrepared::decode(&bad_identity),
		Err(PreparedError::UnsupportedIdentity)
	);
}

#[test]
fn rejects_unsupported_source_or_target_observations() {
	let stable = patch(ENTRY, &[0xa6, 0, 0, 1, 0xa4], &[0xa6, 0, 1, 1, 0xa4]);
	assert_eq!(
		EntryPrepared::decode(&stable),
		Err(PreparedError::UnsupportedSourceView)
	);

	let oversized = patch(
		ENTRY,
		&[0x1a, 0, 1, 0, 0, 3, 0x82],
		&[0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0, 3, 0x82],
	);
	assert_eq!(
		EntryPrepared::decode(&oversized),
		Err(PreparedError::InvalidSourceLength)
	);

	let bad_time = patch(
		ENTRY,
		&[0x21, 0x19, 0x01, 0x90],
		&[0x21, 0x1a, 0x3b, 0x9a, 0xca, 0],
	);
	assert_eq!(
		EntryPrepared::decode(&bad_time),
		Err(PreparedError::InvalidTimestamp)
	);

	let bad_mode = patch(ENTRY, &[0xa5, 0, 0x19, 1, 0xa0], &[0xa5, 0, 0x19, 0x10, 0]);
	assert_eq!(
		EntryPrepared::decode(&bad_mode),
		Err(PreparedError::InvalidMode)
	);

	let bad_xattr = patch(ENTRY, &[3, 1, 4, 0, 1, 0], &[3, 1, 4, 1, 1, 0]);
	assert_eq!(
		EntryPrepared::decode(&bad_xattr),
		Err(PreparedError::UnsupportedSourceMetadata)
	);

	let mut bad_observation = ENTRY.to_vec();
	*bad_observation
		.last_mut()
		.expect("fixture contains target observation") = 1;
	assert_eq!(
		EntryPrepared::decode(&bad_observation),
		Err(PreparedError::UnsupportedTargetObservation)
	);

	let alias = patch(
		ENTRY,
		&0xf1f2_f3f4_f5f6_f7f8u64.to_le_bytes(),
		&0x1112_1314_1516_1718u64.to_le_bytes(),
	);
	assert_eq!(
		EntryPrepared::decode(&alias),
		Err(PreparedError::SourceStageAlias)
	);
}

#[test]
fn checks_raw_component_before_returning_entry() {
	for (name, error) in [
		(b"".as_slice(), NameError::Empty),
		(b"..", NameError::Reserved),
		(b"/file", NameError::Separator),
		(b"dir/file", NameError::Separator),
		(b"a\0b", NameError::Nul),
	] {
		let mut encoded = vec![0x40 + name.len() as u8];
		encoded.extend_from_slice(name);
		let bad_path = patch(ENTRY, b"\x48report\xff\\", &encoded);
		assert_eq!(
			EntryPrepared::decode(&bad_path),
			Err(PreparedError::InvalidTargetComponent(error)),
			"{name:?}"
		);
	}
	let windows = patch(
		ENTRY,
		b"\xa2\x00\x01\x01\x48report\xff\\",
		b"\xa2\x00\x02\x01\x48report\xff\\",
	);
	assert_eq!(
		EntryPrepared::decode(&windows),
		Err(PreparedError::UnsupportedTargetEncoding)
	);
}

#[test]
fn maximal_fields_fit_bounded_buffers() {
	let mut job = job_fixture();
	job.context.epoch = JournalEpoch::new(u64::MAX);
	let bytes = job.encode();
	assert_eq!(bytes.len(), 192);
	assert_eq!(JobPrepared::decode(&bytes), Ok(job));

	let component = [0xff; MAX_UNIX_COMPONENT_BYTES];
	let mut entry = entry_fixture(&component);
	entry.context.epoch = JournalEpoch::new(u64::MAX);
	let mut preparation = entry.preparation();
	let time = timestamp(i64::MIN, 999_999_999);
	preparation.source = LiveSourceView::new(
		preparation.source.identity(),
		MAX_FILE_LENGTH,
		SourceTimes {
			accessed_at: time,
			modified_at: time,
			changed_at: time,
		},
	)
	.expect("maximal source view");
	preparation.source_metadata =
		SourceInodeMetadata::no_visible_extended_attributes(0o7777, u32::MAX, u32::MAX, u64::MAX)
			.expect("maximal local metadata");
	entry = EntryPrepared::new(entry.context, entry.entry, preparation)
		.expect("distinct source and stage");
	let bytes = entry.encode();
	assert_eq!(bytes.len(), 525);
	assert_eq!(EntryPrepared::decode(&bytes), Ok(entry));

	let mut too_large = bytes;
	too_large.push(0);
	assert_eq!(
		EntryPrepared::decode(&too_large),
		Err(PreparedError::PayloadTooLarge)
	);
}

fn timestamp(seconds: i64, nanosecond: u32) -> ObservedTimestamp {
	ObservedTimestamp::new(seconds, nanosecond).expect("valid fixture time")
}

fn context() -> JournalContext {
	JournalContext {
		job: JournalJobId::from_bytes([
			0x01, 0x82, 0x79, 0x74, 0x55, 0x90, 0x7a, 0x14, 0x88, 0x88, 0x9c, 0x84, 0x07, 0xc7,
			0x18, 0xca,
		])
		.expect("fixture uses RFC UUIDv7"),
		epoch: JournalEpoch::new(24),
		plan_digest: PlanDigest::from_bytes(digest(0)),
	}
}

fn root() -> RootCapabilityId {
	RootCapabilityId::from_bytes([
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
		0xff,
	])
	.expect("fixture uses RFC UUIDv4")
}

fn native(inode: u64) -> LinuxFileIdentity {
	LinuxFileIdentity::new(0x0102_0304_0506_0708, inode)
}

fn job_fixture() -> JobPrepared {
	JobPrepared {
		context: context(),
		owner_digest: OwnerDigest::from_bytes(digest(32)),
		destination_root: DestinationRootBinding {
			id: root(),
			identity: native(0x1122_3344_5566_7788),
		},
	}
}

fn entry_fixture(name: &[u8]) -> EntryPrepared<'_> {
	let preparation = EntryPreparation {
		source: LiveSourceView::new(
			native(0x1112_1314_1516_1718),
			65_536,
			SourceTimes {
				accessed_at: timestamp(-2, 400),
				modified_at: timestamp(700, 0),
				changed_at: timestamp(700, 500),
			},
		)
		.expect("valid source extent"),
		stage: native(0xf1f2_f3f4_f5f6_f7f8),
		target: PreparedTarget {
			root: root(),
			component: UnixComponent::new(name).expect("valid fixture component"),
			observation: TargetObservation::AbsentObserved,
		},
		source_metadata: SourceInodeMetadata::no_visible_extended_attributes(0o640, 1234, 4321, 1)
			.expect("valid source mode"),
	};
	let entry = JournalEntryId::from_bytes([
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x47, 0x77, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33,
		0x22,
	]);
	EntryPrepared::new(context(), entry, preparation).expect("distinct source and stage identities")
}

fn digest(offset: u8) -> [u8; 32] {
	std::array::from_fn(|index| offset + index as u8)
}

fn patch(input: &[u8], pattern: &[u8], replacement: &[u8]) -> Vec<u8> {
	let mut matches = input
		.windows(pattern.len())
		.enumerate()
		.filter(|(_, bytes)| *bytes == pattern);
	let (offset, _) = matches
		.next()
		.expect("test pattern occurs in the golden payload");
	assert!(matches.next().is_none(), "test pattern is unique");
	let mut result = input.to_vec();
	result.splice(offset..offset + pattern.len(), replacement.iter().copied());
	result
}
