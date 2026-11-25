use std::fmt::Write as _;
use std::fs::File;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::assembly::linux::plan_public_new_file;
use exacopy_codec::{PlanBody, PublicPlan, UnixTimestamp};
use exacopy_journal::LinuxFileIdentity;
use exacopy_platform::linux::{DestinationRoot, ReadRoot};
use exacopy_transfer::copy_planning::{CreateNewRequest, PlanSelection};
use rustix::fs::{self, AtFlags, FileType, Mode, Stat};
use uuid::{Builder, Uuid};

use super::bundle::Bundle;
use super::error::{Failure, Kind};
use crate::args::PlanCommand;
use crate::linux_path::{open_directory, split};
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
	let src = open_directory(source_parent).map_err(|error| Failure::with(Kind::Root, error))?;
	let dst = open_directory(target_parent).map_err(|error| Failure::with(Kind::Root, error))?;
	let profile = LocalProfile::open(&command.profile).map_err(Failure::profile)?;
	let profile_dir = open_directory(command.profile.as_os_str())
		.map_err(|error| Failure::with(Kind::Profile, error))?;
	let profile_stamp = check_profile(&profile_dir, &profile)?;
	let bundle = Bundle::open(&command.output)?;
	let scopes = [&src, &dst, &profile_dir];
	bundle.check_scope(scopes)?;
	bundle.ensure_output_absent()?;

	let source = ReadRoot::from_directory(
		src.try_clone()
			.map_err(|error| Failure::with(Kind::Root, error))?,
	)
	.map_err(|error| Failure::with(Kind::Root, error))?;
	let target = DestinationRoot::from_directory(
		dst.try_clone()
			.map_err(|error| Failure::with(Kind::Root, error))?,
	)
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
	let result = plan_public_new_file(
		&source,
		&target,
		request,
		|id| !profile.is_seed(LinuxFileIdentity::new(id.device(), id.inode())),
		&mut scratch,
	)
	.map_err(Failure::from_planning)?;
	let digest = result.digest();
	let body = PlanBody::from_canonical_cbor(digest, result.canonical_body())
		.map_err(|error| Failure::with(Kind::Encoding, error))?;
	let envelope =
		PublicPlan::from_body(&body).map_err(|error| Failure::with(Kind::Encoding, error))?;
	let json = envelope
		.to_json()
		.map_err(|error| Failure::with(Kind::Encoding, error))?;

	let current = check_profile(&profile_dir, &profile)?;
	if (
		profile_stamp.st_mtime,
		profile_stamp.st_mtime_nsec,
		profile_stamp.st_ctime,
		profile_stamp.st_ctime_nsec,
	) != (
		current.st_mtime,
		current.st_mtime_nsec,
		current.st_ctime,
		current.st_ctime_nsec,
	) {
		return Err(Failure::plain(Kind::Profile));
	}
	bundle.write(scopes, result.page_ref(), result.canonical_page(), &json)?;
	Ok(digest)
}

fn check_profile(directory: &File, profile: &LocalProfile) -> Result<Stat, Failure> {
	let named = fs::statat(directory, c"owner.seed", AtFlags::SYMLINK_NOFOLLOW)
		.map_err(|error| Failure::with(Kind::Profile, error))?;
	if !profile.is_seed(LinuxFileIdentity::new(named.st_dev, named.st_ino))
		|| FileType::from_raw_mode(named.st_mode) != FileType::RegularFile
		|| Mode::from_raw_mode(named.st_mode) != Mode::RUSR | Mode::WUSR
		|| named.st_uid != rustix::process::geteuid().as_raw()
		|| named.st_nlink != 1
		|| usize::try_from(named.st_size) != Ok(ed25519_dalek::SECRET_KEY_LENGTH)
	{
		return Err(Failure::plain(Kind::Profile));
	}
	Ok(named)
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
