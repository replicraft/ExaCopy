use ed25519_dalek::{Signature, VerifyingKey};
use exacopy_journal::{ApplyQualificationDigest, OwnerTimestamp, RootCapabilityId};
use exacopy_platform::linux::ProcessCrashEnvironment;

use super::{LocalApplyQualificationEnrollment, QualifiedPublicApplyProposalError as Failure};

const MAGIC: &[u8; 8] = b"EXLPQA01";
const SIGNATURE_PURPOSE: &[u8] = b"ExaCopy/linux-public-apply-qualification/v1\0";
const DIGEST_PURPOSE: &str = "ExaCopy Linux public apply qualification record v1";
const BODY_BYTES: usize = 360;
pub(super) const RECORD_BYTES: usize = BODY_BYTES + 64;

// Mirrors the existing native running executable admission, without using a parsed
// length to allocate or open a file.
const MAX_IMAGE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct Root {
	pub(super) alias: RootCapabilityId,
	pub(super) inode: u64,
}

#[derive(Debug)]
pub(super) struct Qualification {
	pub(super) digest: ApplyQualificationDigest,
	pub(super) image_length: u64,
	pub(super) image: [u8; 32],
	pub(super) environment: ProcessCrashEnvironment,
	pub(super) source: Root,
	pub(super) destination: Root,
	pub(super) owner_profile: [u8; 16],
	pub(super) plan: [u8; 32],
	pub(super) entry: [u8; 16],
	pub(super) metadata: [u8; 32],
	valid_from: i64,
	valid_until: i64,
}

impl Qualification {
	pub(super) fn check_time(
		&self,
		now: OwnerTimestamp,
		plan_expiry: OwnerTimestamp,
	) -> Result<(), Failure> {
		let current = (now.seconds(), now.nanoseconds());
		let expires = (plan_expiry.seconds(), plan_expiry.nanoseconds());
		if !(self.valid_from..self.valid_until).contains(&current.0) || current >= expires {
			return Err(Failure::Time);
		}
		Ok(())
	}
}

pub(super) fn verify(
	bytes: &[u8],
	enrollment: &LocalApplyQualificationEnrollment<'_>,
	owner: &VerifyingKey,
) -> Result<Qualification, Failure> {
	if bytes.len() != RECORD_BYTES {
		return Err(Failure::Record);
	}
	let (body, signature) = bytes.split_at(BODY_BYTES);
	let body: &[u8; BODY_BYTES] = body.try_into().map_err(|_| Failure::Record)?;
	if field::<8>(body, 0) != *MAGIC {
		return Err(Failure::Record);
	}
	let attestor = enrollment.attestor_key;
	let digest = blake3::derive_key(DIGEST_PURPOSE, bytes);
	if enrollment.attestor_id == [0; 16]
		|| enrollment.attestor_id != field(body, 8)
		|| !canonical_strong(attestor)
		|| !canonical_strong(owner)
		|| attestor == owner
		|| owner.to_bytes() != field(body, 232)
		|| enrollment.record_digest.as_bytes() == &[0; 32]
		|| &digest != enrollment.record_digest.as_bytes()
	{
		return Err(Failure::Selection);
	}
	let signature = Signature::from_slice(signature).map_err(|_| Failure::Record)?;
	let signed = [SIGNATURE_PURPOSE, body.as_slice()].concat();
	attestor
		.verify_strict(&signed, &signature)
		.map_err(|_| Failure::Signature)?;
	decode_body(body, ApplyQualificationDigest::from_bytes(digest))
}

fn decode_body(
	body: &[u8; BODY_BYTES],
	digest: ApplyQualificationDigest,
) -> Result<Qualification, Failure> {
	let scope = field::<32>(body, 24);
	let evidence = field::<32>(body, 56);
	let qualification = Qualification {
		digest,
		image_length: u64::from_le_bytes(field(body, 88)),
		image: field(body, 96),
		environment: ProcessCrashEnvironment {
			boot_id: field(body, 128),
			mount_namespace: u64::from_le_bytes(field(body, 144)),
			unique_mount: u64::from_le_bytes(field(body, 152)),
			device: u64::from_le_bytes(field(body, 160)),
		},
		source: Root {
			alias: RootCapabilityId::from_bytes(field(body, 168)).map_err(|_| Failure::Record)?,
			inode: u64::from_le_bytes(field(body, 184)),
		},
		destination: Root {
			alias: RootCapabilityId::from_bytes(field(body, 192)).map_err(|_| Failure::Record)?,
			inode: u64::from_le_bytes(field(body, 208)),
		},
		owner_profile: field(body, 216),
		plan: field(body, 264),
		entry: field(body, 296),
		metadata: field(body, 312),
		valid_from: i64::from_le_bytes(field(body, 344)),
		valid_until: i64::from_le_bytes(field(body, 352)),
	};
	if [
		scope,
		evidence,
		qualification.image,
		qualification.plan,
		qualification.metadata,
	]
	.contains(&[0; 32])
		|| [
			qualification.environment.boot_id,
			qualification.owner_profile,
			qualification.entry,
		]
		.contains(&[0; 16])
		|| [
			qualification.environment.mount_namespace,
			qualification.environment.unique_mount,
			qualification.source.inode,
			qualification.destination.inode,
		]
		.contains(&0)
		|| !(1..=MAX_IMAGE_BYTES).contains(&qualification.image_length)
		|| qualification.valid_from < 0
		|| qualification.valid_from >= qualification.valid_until
	{
		return Err(Failure::Record);
	}
	Ok(qualification)
}

fn canonical_strong(key: &VerifyingKey) -> bool {
	!key.is_weak() && key.to_edwards().compress().to_bytes() == key.to_bytes()
}

fn field<const N: usize>(body: &[u8; BODY_BYTES], start: usize) -> [u8; N] {
	body[start..start + N]
		.try_into()
		.expect("fixed qualification field")
}
