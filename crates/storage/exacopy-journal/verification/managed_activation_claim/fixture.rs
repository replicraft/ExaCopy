use exacopy_journal::frame::ChainHead;
use exacopy_journal::managed_activation_claim::{
	ManagedActivationChild, ManagedActivationClaim, ManagedActivationPrepared,
};
use exacopy_journal::{
	ApprovedPublicPlanDigest, JournalEntryId, JournalEpoch, JournalJobId, OwnerProfileId,
	PublicPlanEntryId,
};

pub(super) fn selection() -> ManagedActivationClaim {
	ManagedActivationClaim {
		activation: octets(0x11),
		host_selection: octets(0x22),
		profile: OwnerProfileId::from_bytes(octets(0x33)).unwrap(),
		pair: hex("0186a634128e7aec9c6742a66e10b2cd"),
		predecessor_generation: 0x0102_0304_0506_0708,
		predecessor_root: octets(0x44),
		review_parent: octets(0x55),
		execution_parent: octets(0x66),
		action: octets(0x77),
		grant: octets(0x88),
		child: ManagedActivationChild {
			public_plan: ApprovedPublicPlanDigest::from_bytes(octets(0x99)),
			public_entry: PublicPlanEntryId::from_bytes(octets(0xaa)).unwrap(),
			private_plan: octets(0xbb),
			job: JournalJobId::from_bytes(hex("019a4019d27373d3a68140fc89725c12")).unwrap(),
			entry: JournalEntryId::from_bytes(octets(0xcc)),
			epoch: JournalEpoch::new(0x1122_3344_5566_7788),
		},
		slot: octets(0xdd),
		segment: octets(0xee),
		prepared: ManagedActivationPrepared {
			head: ChainHead::after(0x0123_4567_89ab_cdef, octets(0xf1)).unwrap(),
			extent: 0x0001_23a4,
		},
	}
}

fn octets<const N: usize>(start: u8) -> [u8; N] {
	let mut next = start;
	std::array::from_fn(|_| {
		let byte = next;
		next = next.wrapping_add(3);
		byte
	})
}

fn hex<const N: usize>(source: &str) -> [u8; N] {
	let digits: Vec<_> = source
		.chars()
		.filter(|character| !character.is_ascii_whitespace())
		.collect();
	assert_eq!(digits.len(), N * 2);
	std::array::from_fn(|index| {
		let high = digits[index * 2].to_digit(16).unwrap();
		let low = digits[index * 2 + 1].to_digit(16).unwrap();
		u8::try_from(high * 16 + low).unwrap()
	})
}

pub(super) fn wire() -> [u8; 496] {
	hex(include_str!("golden.hex"))
}

pub(super) fn commitment(role: &str) -> [u8; 32] {
	include_str!("commitments.hex")
		.lines()
		.map(|line| line.split_once(' ').unwrap())
		.find_map(|(name, digest)| (name == role).then(|| hex(digest)))
		.unwrap_or_else(|| panic!("missing independent commitment for {role}"))
}

pub(super) fn reseal(wire: &mut [u8; 496]) {
	let mut state = u32::MAX;
	for &byte in &wire[..492] {
		state ^= u32::from(byte);
		for _ in 0..8 {
			let feedback = if state & 1 == 0 { 0 } else { 0x82f6_3b78 };
			state = (state >> 1) ^ feedback;
		}
	}
	wire[492..].copy_from_slice(&(!state).to_le_bytes());
}

pub(super) type Role = (
	&'static str,
	std::ops::Range<usize>,
	fn(&mut ManagedActivationClaim),
);

pub(super) const ROLES: [Role; 21] = [
	("activation", 12..44, |claim| claim.activation[0] ^= 1),
	("host_selection", 44..76, |claim| {
		claim.host_selection[0] ^= 1
	}),
	("profile", 76..92, |claim| {
		let mut bytes = *claim.profile.as_bytes();
		bytes[0] ^= 1;
		claim.profile = OwnerProfileId::from_bytes(bytes).unwrap();
	}),
	("pair", 92..108, |claim| claim.pair[0] ^= 1),
	("predecessor_generation", 108..116, |claim| {
		claim.predecessor_generation ^= 1
	}),
	("predecessor_root", 116..148, |claim| {
		claim.predecessor_root[0] ^= 1
	}),
	("review_parent", 148..180, |claim| {
		claim.review_parent[0] ^= 1
	}),
	("execution_parent", 180..212, |claim| {
		claim.execution_parent[0] ^= 1
	}),
	("action", 212..228, |claim| claim.action[0] ^= 1),
	("grant", 228..260, |claim| claim.grant[0] ^= 1),
	("child_public_plan", 260..292, |claim| {
		let mut bytes = *claim.child.public_plan.as_bytes();
		bytes[0] ^= 1;
		claim.child.public_plan = ApprovedPublicPlanDigest::from_bytes(bytes);
	}),
	("child_public_entry", 292..308, |claim| {
		let mut bytes = *claim.child.public_entry.as_bytes();
		bytes[0] ^= 1;
		claim.child.public_entry = PublicPlanEntryId::from_bytes(bytes).unwrap();
	}),
	("child_private_plan", 308..340, |claim| {
		claim.child.private_plan[0] ^= 1
	}),
	("child_job", 340..356, |claim| {
		let mut bytes = *claim.child.job.as_bytes();
		bytes[0] ^= 1;
		claim.child.job = JournalJobId::from_bytes(bytes).unwrap();
	}),
	("child_entry", 356..372, |claim| {
		let mut bytes = *claim.child.entry.as_bytes();
		bytes[0] ^= 1;
		claim.child.entry = JournalEntryId::from_bytes(bytes);
	}),
	("child_epoch", 372..380, |claim| {
		claim.child.epoch = JournalEpoch::new(claim.child.epoch.get() ^ 1)
	}),
	("slot", 380..412, |claim| claim.slot[0] ^= 1),
	("segment", 412..444, |claim| claim.segment[0] ^= 1),
	("prepared_sequence", 444..452, |claim| {
		let head = claim.prepared.head;
		claim.prepared.head = ChainHead::after(head.sequence() ^ 1, head.digest()).unwrap();
	}),
	("prepared_digest", 452..484, |claim| {
		let head = claim.prepared.head;
		let mut digest = head.digest();
		digest[0] ^= 1;
		claim.prepared.head = ChainHead::after(head.sequence(), digest).unwrap();
	}),
	("prepared_extent", 484..492, |claim| {
		claim.prepared.extent ^= 1
	}),
];
