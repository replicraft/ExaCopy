use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::assembly::linux::plan_public_new_file;
use exacopy_endpoint::plan_bundle::PlanBundleSink as _;
use exacopy_journal::LinuxFileIdentity;
use exacopy_plan::{PlanBody, RenderedPlanEnvelope, UnixTimestamp};
use exacopy_platform::linux::{FileIdentity, LinuxPlanBundle, PlanInputDirectory};
use exacopy_transfer::copy_planning::{CreateNewRequest, PlanSelection};
use exacopy_transfer::public_plan::write_plan_bundle;
use uuid::{Builder, Uuid};

use super::error::{Failure, Kind};
use crate::args::PlanCommand;
use crate::linux_path::split;
use crate::profile::{LocalProfile, kernel_random};

const BUFFER_BYTES: usize = 256 * 1024;
const MAX_UUIDV7_MILLIS: u128 = (1 << 48) - 1;

pub(super) fn export(command: &PlanCommand) -> Result<[u8; 32], Failure> {
	export_at(command, SystemTime::now)
}

fn export_at(
	command: &PlanCommand,
	clock: impl FnOnce() -> SystemTime,
) -> Result<[u8; 32], Failure> {
	let (source_parent, source_name) =
		split(&command.source).map_err(|error| Failure::with(Kind::Invalid, error))?;
	let (target_parent, target_name) =
		split(&command.destination).map_err(|error| Failure::with(Kind::Invalid, error))?;
	let src = PlanInputDirectory::open(source_parent)
		.map_err(|error| Failure::with(Kind::Root, error))?;
	let dst = PlanInputDirectory::open(target_parent)
		.map_err(|error| Failure::with(Kind::Root, error))?;
	let profile = LocalProfile::open(&command.profile).map_err(Failure::profile)?;
	let profile_dir = PlanInputDirectory::open(command.profile.as_os_str())
		.map_err(|error| Failure::with(Kind::Profile, error))?;
	let is_seed = |identity: FileIdentity| {
		profile.is_seed(LinuxFileIdentity::new(identity.device(), identity.inode()))
	};
	let profile_stamp = profile_dir
		.observe_seed(is_seed)
		.map_err(Failure::seed_observation)?;
	let (output_parent, output_name) =
		split(&command.output).map_err(|error| Failure::with(Kind::Invalid, error))?;
	let bundle = LinuxPlanBundle::open(output_parent, output_name, [&src, &dst, &profile_dir])
		.map_err(Failure::bundle)?;
	bundle.ensure_output_absent().map_err(Failure::bundle)?;

	let source = src
		.read_root()
		.map_err(|error| Failure::with(Kind::Root, error))?;
	let target = dst
		.destination_root()
		.map_err(|error| Failure::with(Kind::Root, error))?;

	let time = clock()
		.duration_since(UNIX_EPOCH)
		.map_err(|error| Failure::with(Kind::Clock, error))?;
	if time.as_millis() > MAX_UUIDV7_MILLIS {
		return Err(Failure::plain(Kind::Clock));
	}
	let observed_at = UnixTimestamp::new(
		i64::try_from(time.as_secs()).map_err(|error| Failure::with(Kind::Clock, error))?,
		time.subsec_nanos(),
	)
	.map_err(|error| Failure::with(Kind::Clock, error))?;
	let mut random = [0; 10];
	kernel_random(&mut random).map_err(Failure::entropy)?;
	let plan_id = Builder::from_unix_timestamp_millis(
		u64::try_from(time.as_millis()).map_err(|error| Failure::with(Kind::Clock, error))?,
		&random,
	)
	.into_uuid();
	let source_root = profile
		.root_id(source.identity())
		.map_err(Failure::profile)?;
	let target_root = profile
		.root_id(target.identity())
		.map_err(Failure::profile)?;
	let request = CreateNewRequest {
		plan_id,
		entry_id: fresh_reference()?,
		source_view_id: fresh_reference()?,
		measurement_id: fresh_reference()?,
		source: PlanSelection {
			root_id: Uuid::from_bytes(*source_root.as_bytes()),
			component: source_name,
		},
		destination: PlanSelection {
			root_id: Uuid::from_bytes(*target_root.as_bytes()),
			component: target_name,
		},
		observed_at,
	};
	let mut scratch = vec![0; BUFFER_BYTES];
	let result = plan_public_new_file(&source, &target, request, |id| !is_seed(id), &mut scratch)
		.map_err(Failure::from_planning)?;
	let digest = result.digest();
	let body = PlanBody::from_canonical_cbor(digest, result.canonical_body())
		.map_err(|error| Failure::with(Kind::Encoding, error))?;
	let rendered = RenderedPlanEnvelope::from_body(&body)
		.map_err(|error| Failure::with(Kind::Encoding, error))?;

	let current = profile_dir
		.observe_seed(is_seed)
		.map_err(Failure::seed_observation)?;
	if profile_stamp != current {
		return Err(Failure::plain(Kind::Profile));
	}
	let artifacts = rendered
		.prepare(result.canonical_page())
		.map_err(|_| Failure::plain(Kind::Encoding))?;
	write_plan_bundle(&bundle, &artifacts).map_err(Failure::bundle_write)?;
	Ok(digest)
}

fn fresh_reference() -> Result<Uuid, Failure> {
	let mut bytes = [0; 16];
	kernel_random(&mut bytes).map_err(Failure::entropy)?;
	Ok(Builder::from_random_bytes(bytes).into_uuid())
}

pub(super) fn hex(bytes: &[u8; 32]) -> String {
	let mut result = String::with_capacity(64);
	for byte in bytes {
		let _ = write!(result, "{byte:02x}");
	}
	result
}

#[cfg(test)]
mod tests;
