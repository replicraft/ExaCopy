use super::{INTENT_BYTES, IntentRecord, SyncGenesisIntent, SyncGenesisMemberBinding};
use super::{NonZeroU16, NonZeroU64, SyncGenesisNativeIdentity, SyncGenesisOperation};

fn record() -> IntentRecord {
	let output = SyncGenesisNativeIdentity {
		device: 0,
		inode: NonZeroU64::new(0x8070_6050_4030_2010).unwrap(),
	};
	let stage = SyncGenesisNativeIdentity {
		device: 0,
		inode: NonZeroU64::new(0x0102_0304_0506_0708).unwrap(),
	};
	let members = [6, 1, 1, 256].map(|kind| SyncGenesisMemberBinding {
		kind,
		byte_len: NonZeroU16::new(2048).unwrap(),
		canonical_digest: [0; 32],
		raw_digest: [0; 32],
	});
	let [root, left, right, leaf] = members;
	let members = [
		SyncGenesisMemberBinding {
			canonical_digest: [0x20; 32],
			raw_digest: [0x40; 32],
			..root
		},
		SyncGenesisMemberBinding {
			canonical_digest: [0x21; 32],
			raw_digest: [0x41; 32],
			..left
		},
		SyncGenesisMemberBinding {
			canonical_digest: [0x22; 32],
			raw_digest: [0x42; 32],
			..right
		},
		SyncGenesisMemberBinding {
			canonical_digest: [0x23; 32],
			raw_digest: [0x43; 32],
			..leaf
		},
	];
	let intent = SyncGenesisIntent {
		operation: SyncGenesisOperation::new(std::array::from_fn(|index| {
			u8::try_from(index + 1).unwrap()
		}))
		.unwrap(),
		output,
		approval: [0xa5; 32],
		members,
	};
	IntentRecord::new(intent, stage).unwrap()
}

#[test]
fn exact_v1_extent_layout_and_endianness() {
	let record = record();
	let wire = record.encode();
	assert_eq!(wire.len(), 364);
	assert_eq!(IntentRecord::decode(&wire), Some(record));
	assert_eq!(&wire[..12], b"EXSYNINT\x01\0\0\0");
	assert_eq!(&wire[12..28], &(1_u8..=16).collect::<Vec<_>>());
	assert_eq!(
		&wire[28..60],
		&[
			0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0, 0, 0, 0, 0,
			0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1,
		]
	);
	assert_eq!(&wire[60..92], &[0xa5; 32]);
	for (index, kind) in [6_u16, 1, 1, 256].into_iter().enumerate() {
		let start = 92 + index * 68;
		let slot = u8::try_from(index).unwrap();
		assert_eq!(&wire[start..start + 2], &kind.to_le_bytes());
		assert_eq!(&wire[start + 2..start + 4], &[0, 8]);
		assert_eq!(&wire[start + 4..start + 36], &[0x20 + slot; 32]);
		assert_eq!(&wire[start + 36..start + 68], &[0x40 + slot; 32]);
	}
}

#[test]
fn refuses_noncanonical_extent_shape_and_member_inventory() {
	let wire = record().encode();
	for size in 0..INTENT_BYTES {
		assert!(IntentRecord::decode(&wire[..size]).is_none());
	}
	assert!(IntentRecord::decode(&[wire.as_slice(), &[0]].concat()).is_none());
	let mut rejected = Vec::new();
	for offset in [0, 8, 10, 44, 92, 160, 228, 296] {
		let mut changed = wire;
		changed[offset] ^= 0x80;
		rejected.push(changed);
	}
	for (start, end) in [(12, 28), (36, 44), (52, 60), (94, 96)] {
		let mut changed = wire;
		changed[start..end].fill(0);
		rejected.push(changed);
	}
	for (start, end, original) in [(52, 60, 36), (164, 196, 96), (196, 228, 128)] {
		let mut changed = wire;
		changed.copy_within(original..original + end - start, start);
		rejected.push(changed);
	}
	let mut too_large = wire;
	too_large[94..96].copy_from_slice(&2049_u16.to_le_bytes());
	rejected.push(too_large);
	for changed in rejected {
		assert!(IntentRecord::decode(&changed).is_none());
	}
}

#[test]
fn structural_decode_does_not_adopt_swapped_same_kind_members_or_other_approval() {
	let intended = record();
	let wire = intended.encode();
	let mut swapped = wire;
	swapped[160..228].copy_from_slice(&wire[228..296]);
	swapped[228..296].copy_from_slice(&wire[160..228]);
	let swapped = IntentRecord::decode(&swapped).unwrap();
	assert_ne!(swapped, intended);

	let mut approval = wire;
	approval[60] ^= 1;
	assert_ne!(IntentRecord::decode(&approval).unwrap(), intended);
}

const ORACLE: &str = include_str!(concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/verification/sync_genesis_publication/intent.tsv"
));

fn oracle_row(row: &str) -> (&str, &str, Vec<u8>) {
	let mut fields = row.split('\t');
	let label = fields.next().unwrap();
	let verdict = fields.next().unwrap();
	let encoded = fields.next().unwrap().as_bytes();
	assert!(fields.next().is_none(), "{label}: extra column");
	let (pairs, tail) = encoded.as_chunks::<2>();
	assert!(tail.is_empty(), "{label}: incomplete hex pair");
	let digit = |byte| match byte {
		b'0'..=b'9' => byte - b'0',
		b'a'..=b'f' => byte - b'a' + 10,
		_ => panic!("{label}: invalid hex digit"),
	};
	let bytes = pairs
		.iter()
		.map(|pair| (digit(pair[0]) << 4) | digit(pair[1]))
		.collect();
	(label, verdict, bytes)
}

#[test]
fn independent_v1_oracle_distinguishes_shape_from_exact_selection() {
	let mut rows = ORACLE.lines();
	assert_eq!(rows.next(), Some("label\texpect\thex"));
	let (label, verdict, canonical) = oracle_row(rows.next().unwrap());
	assert_eq!((label, verdict), ("canonical", "accept"));
	let selected = IntentRecord::decode(&canonical).expect("independent canonical intent");
	assert_eq!(selected.encode().as_slice(), canonical.as_slice());
	for length in 0..INTENT_BYTES {
		assert!(
			IntentRecord::decode(&canonical[..length]).is_none(),
			"prefix {length}"
		);
	}

	let mut labels = std::collections::BTreeSet::from([label]);
	let mut counts = [1, 0, 0];
	for row in rows {
		let (label, verdict, bytes) = oracle_row(row);
		assert!(labels.insert(label), "duplicate oracle case {label}");
		let decoded = IntentRecord::decode(&bytes);
		match (label, verdict) {
			("zero_device", "accept") => {
				counts[0] += 1;
				let mut accepted = canonical.clone();
				accepted[28..36].fill(0);
				accepted[44..52].fill(0);
				assert_eq!(bytes, accepted);
				let expected = IntentRecord::new(
					SyncGenesisIntent {
						output: SyncGenesisNativeIdentity {
							device: 0,
							..selected.intent.output
						},
						..selected.intent
					},
					SyncGenesisNativeIdentity {
						device: 0,
						..selected.stage
					},
				)
				.unwrap();
				assert_eq!(decoded.as_ref(), Some(&expected));
				assert_eq!(expected.encode().as_slice(), bytes.as_slice());
			}
			(_, "shape") => {
				counts[1] += 1;
				assert!(decoded.is_none(), "{label}: invalid wire shape admitted");
			}
			(_, "binding") => {
				counts[2] += 1;
				let offered = decoded.unwrap_or_else(|| panic!("{label}: expected a valid shape"));
				assert_ne!(offered, selected, "{label}: independent selection matched");
				assert_eq!(offered.encode().as_slice(), bytes.as_slice(), "{label}");
			}
			_ => panic!("{label}: unexpected oracle verdict {verdict}"),
		}
	}
	assert_eq!(counts, [2, 14, 11]);
}
