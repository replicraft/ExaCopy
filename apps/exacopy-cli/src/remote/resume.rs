use exacopy_endpoint::UnixComponent;
use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;
use exacopy_journal::remote_download::finalization_replay::{
	RemoteFinalizationPhase as Phase, replay_remote_finalization,
};
use exacopy_journal::remote_download::{
	MAX_REMOTE_DOWNLOAD_OWNER_BYTES, RemoteBootstrapTrust, RemoteDownloadDurability,
	RemoteDownloadError, RemoteDownloadOwnerRecord, RemoteDownloadRoute,
};
use exacopy_platform::linux::{DestinationRoot, RecoveryFile, RecoveryJob, RecoveryReadLease};

use crate::args::RemoteOptions;
use crate::assembly::linux::remote_download::RemoteJobAction;
use crate::profile::LocalProfile;
use crate::remote_frontdoor::{ApprovedRoute, SshProfile};
use crate::remote_report::{
	RemoteFailureKind as Failure, RemoteJob, RemoteOutcome, RemotePublication,
};

use super::qualification::Qualification;
use super::selection::{Selected, record_identity, refused, route_class};

/// Keeps the selected job read-locked until the authenticated carrier is ready.
pub(super) struct Startup<'held> {
	location: &'held RemoteJob,
	job: &'held RecoveryJob<'held>,
	lease: RecoveryReadLease<'held>,
}

impl<'held> Startup<'held> {
	pub(super) fn hold(
		location: &'held RemoteJob,
		job: &'held RecoveryJob<'held>,
	) -> Result<Self, Box<RemoteOutcome>> {
		let lease = job.try_read_lease().map_err(|_| uncertain(location))?;
		Ok(Self {
			location,
			job,
			lease,
		})
	}

	pub(super) fn into_lease(self) -> RecoveryReadLease<'held> {
		self.lease
	}
}

pub(super) fn select(
	startup: &Startup<'_>,
	name: UnixComponent<'_>,
	root: &DestinationRoot,
	owners: &LocalProfile,
	ssh: &SshProfile,
	options: &RemoteOptions,
) -> Result<Selected, Box<RemoteOutcome>> {
	let location = startup.location;
	let job = startup.job;
	let unknown = || uncertain(location);
	let owner_file = job.open_owner().map_err(|_| unknown())?;
	let bytes = read_owner(&owner_file).map_err(|_| unknown())?;
	let key = owners.verification_key();
	let (owner, format) =
		authenticate_owner(&bytes, owners, ssh).map_err(|_| refused(Failure::Authorization))?;
	let signed = owner.manifest();
	let scope = &signed.scope;
	let parent = record_identity(root.identity());
	if signed.job != location.id
		|| signed.job_directory != record_identity(job.identity())
		|| scope.destination.parent() != parent
		|| scope.destination.root()
			!= owners
				.root_id(root.identity())
				.map_err(|_| refused(Failure::Authorization))?
		|| scope.destination.target() == name.as_bytes()
		|| scope.source.authority() != &ssh.authority
		|| scope.source.host_key_sha256() != &ssh.pin_digest
		|| scope.maximum_extent.get() > ssh.maximum_extent
		|| scope.metadata_policy != SftpDataOnlyV1::digest()
		|| scope.requested_durability != RemoteDownloadDurability::ProcessCrash
		|| !approved_route(&ssh.route, scope.source.route())
	{
		return Err(refused(Failure::Authorization));
	}
	let qualification = Qualification::open(
		options,
		root,
		&key,
		route_class(scope.source.route()).map_err(refused)?,
	)
	.map_err(|_| unknown())?;
	let trust = match format {
		OwnerFormat::RelativeEmbedded => RemoteBootstrapTrust::new(&owner, owners.id(), &key),
		OwnerFormat::RelativeDirect => {
			RemoteBootstrapTrust::new_resolved_direct(&owner, owners.id(), &key)
		}
		OwnerFormat::Absolute => RemoteBootstrapTrust::new_absolute_path(&owner, owners.id(), &key),
	}
	.map_err(|_| unknown())?;
	let mut segment = job.open_first_segment().map_err(|_| unknown())?;
	let replay = replay_remote_finalization(&mut segment, &trust, qualification.digest, None)
		.map_err(|_| unknown())?;
	segment.check_logical_eof().map_err(|_| unknown())?;
	segment.recheck_observation().map_err(|_| unknown())?;
	owner_file.recheck_observation().map_err(|_| unknown())?;
	if job.open_owner().map_err(|_| unknown())?.identity() != owner_file.identity()
		|| job.open_first_segment().map_err(|_| unknown())?.identity() != segment.identity()
	{
		return Err(unknown());
	}
	job.recheck().map_err(|_| unknown())?;
	let clear = replay.issue().is_none() && replay.boundary().offset == segment.len();
	if let Some(outcome) = startup_outcome(replay.phase(), clear, location) {
		return Err(Box::new(outcome));
	}
	if !cfg!(feature = "experimental-ssh-wireguard")
		&& matches!(
			scope.source.route(),
			RemoteDownloadRoute::EmbeddedWireGuard { .. }
		) {
		return Err(Box::new(RemoteOutcome::failed(
			Failure::Unsupported,
			Some(duplicate_job(location)),
		)));
	}
	Ok(Selected {
		job: duplicate_job(location),
		scope: scope.clone(),
		action: RemoteJobAction::Resume,
		qualification,
	})
}

pub(super) fn uncertain(location: &RemoteJob) -> Box<RemoteOutcome> {
	Box::new(RemoteOutcome::recovery_required(
		RemotePublication::PublicationUncertain,
		duplicate_job(location),
	))
}

pub(super) fn duplicate_job(job: &RemoteJob) -> RemoteJob {
	RemoteJob {
		id: job.id,
		directory: job.directory.clone(),
	}
}

pub(super) fn startup_outcome(phase: Phase, clear: bool, job: &RemoteJob) -> Option<RemoteOutcome> {
	match phase {
		Phase::Published | Phase::Durable | Phase::ReceiptCommitted => Some(
			RemoteOutcome::recovery_required(RemotePublication::Published, duplicate_job(job)),
		),
		Phase::Conflict if clear => Some(RemoteOutcome::failed(
			Failure::Conflict,
			Some(duplicate_job(job)),
		)),
		Phase::Capture
		| Phase::Retired
		| Phase::Sealed
		| Phase::Verified
		| Phase::MetadataReady
			if clear =>
		{
			None
		}
		_ => Some(RemoteOutcome::recovery_required(
			RemotePublication::PublicationUncertain,
			duplicate_job(job),
		)),
	}
}

fn read_owner(file: &RecoveryFile) -> Result<Vec<u8>, Failure> {
	let length = usize::try_from(file.len())
		.ok()
		.filter(|length| (1..=MAX_REMOTE_DOWNLOAD_OWNER_BYTES).contains(length))
		.ok_or(Failure::Integrity)?;
	let mut bytes = vec![0; length];
	file.read_exact_at(0, &mut bytes).map_err(|_| Failure::Io)?;
	file.check_logical_eof().map_err(|_| Failure::Integrity)?;
	file.recheck_observation().map_err(|_| Failure::Integrity)?;
	Ok(bytes)
}

#[derive(Clone, Copy)]
enum OwnerFormat {
	RelativeEmbedded,
	RelativeDirect,
	Absolute,
}

fn authenticate_owner(
	bytes: &[u8],
	owners: &LocalProfile,
	ssh: &SshProfile,
) -> Result<(RemoteDownloadOwnerRecord, OwnerFormat), RemoteDownloadError> {
	let key = owners.verification_key();
	let (relative, format) = match &ssh.route {
		ApprovedRoute::EmbeddedWireGuard(_) => (
			RemoteDownloadOwnerRecord::decode(bytes, owners.id(), &key),
			OwnerFormat::RelativeEmbedded,
		),
		ApprovedRoute::Direct(_) | ApprovedRoute::ResolveAuthority(_) => (
			RemoteDownloadOwnerRecord::decode_resolved_direct(bytes, owners.id(), &key),
			OwnerFormat::RelativeDirect,
		),
	};
	match relative {
		Ok(owner) => Ok((owner, format)),
		// This discriminant is returned by the body decoder after strict signature verification.
		Err(RemoteDownloadError::UnsupportedVersion) => {
			RemoteDownloadOwnerRecord::decode_absolute_path(bytes, owners.id(), &key)
				.map(|owner| (owner, OwnerFormat::Absolute))
		}
		Err(error) => Err(error),
	}
}

fn approved_route(approved: &ApprovedRoute, selected: RemoteDownloadRoute) -> bool {
	match (approved, selected) {
		(ApprovedRoute::Direct(expected), RemoteDownloadRoute::ResolvedDirect { endpoint }) => {
			*expected == endpoint
		}
		(ApprovedRoute::ResolveAuthority(_), RemoteDownloadRoute::ResolvedDirect { .. }) => true,
		(
			ApprovedRoute::EmbeddedWireGuard(expected),
			RemoteDownloadRoute::EmbeddedWireGuard {
				peer,
				revision,
				inner,
			},
		) => {
			expected.peer_public_key == peer
				&& expected.revision == revision
				&& expected.remote_inner == inner
		}
		_ => false,
	}
}

#[cfg(test)]
mod tests {
	use std::path::Path;

	use super::super::selection::selected_job;
	use super::*;

	#[test]
	fn embedded_resume_requires_the_exact_protected_peer_revision_and_inner() {
		let profile = crate::remote_frontdoor::WireGuardRoute {
			outer: "198.51.100.10:51820".parse().unwrap(),
			outer_mtu: 1500,
			local_inner: "192.0.2.6".parse().unwrap(),
			remote_inner: "192.0.2.7:22".parse().unwrap(),
			local_public_key: [1; 32],
			peer_public_key: [2; 32],
			private_key_file: "/synthetic/wireguard".into(),
			revision: [3; 32],
		};
		let approved = ApprovedRoute::EmbeddedWireGuard(profile.clone());
		let selected = |peer, revision, inner| RemoteDownloadRoute::EmbeddedWireGuard {
			peer,
			revision,
			inner,
		};
		assert!(approved_route(
			&approved,
			selected(
				profile.peer_public_key,
				profile.revision,
				profile.remote_inner
			)
		));
		assert!(!approved_route(
			&approved,
			selected([4; 32], profile.revision, profile.remote_inner)
		));
		assert!(!approved_route(
			&approved,
			selected(profile.peer_public_key, [4; 32], profile.remote_inner)
		));
		assert!(!approved_route(
			&approved,
			selected(
				profile.peer_public_key,
				profile.revision,
				"192.0.2.7:2222".parse().unwrap()
			)
		));
		assert!(!approved_route(
			&approved,
			RemoteDownloadRoute::ResolvedDirect {
				endpoint: profile.remote_inner
			}
		));
	}

	#[tokio::test]
	async fn startup_lease_excludes_writers_through_the_carrier_await() {
		use std::fs::DirBuilder;
		use std::os::unix::fs::DirBuilderExt as _;
		use std::path::PathBuf;

		use exacopy_platform::linux::StageError;

		struct Scratch(PathBuf);

		impl Drop for Scratch {
			fn drop(&mut self) {
				let _ = std::fs::remove_dir_all(&self.0);
			}
		}

		let mut suffix = [0; 16];
		crate::profile::kernel_random(&mut suffix).unwrap();
		let path = std::env::temp_dir().join(format!(
			"exacopy-resume-startup-{}",
			uuid::Uuid::from_bytes(suffix),
		));
		DirBuilder::new().mode(0o700).create(&path).unwrap();
		let scratch = Scratch(path);
		let root = crate::linux_path::open_destination(&scratch.0).unwrap();
		let name = UnixComponent::new(b".exacopy-018d0454-2082-7444-8f45-7c4617e17ea2").unwrap();
		let location = selected_job(
			Path::new(std::str::from_utf8(name.as_bytes()).unwrap()),
			name,
		)
		.ok()
		.unwrap();
		drop(root.create_job_directory(name).unwrap());
		let held_job = root.open_recovery_job(name).unwrap();
		let startup = Startup::hold(&location, &held_job).ok().unwrap();
		let expected = held_job.identity();
		let root = &root;
		let carrier = async move {
			tokio::task::yield_now().await;
			assert!(matches!(
				root.try_recovery_write_lease(name, expected),
				Err(StageError::JobBusy),
			));
			drop(startup.into_lease());
			assert_eq!(
				root.try_recovery_write_lease(name, expected)
					.unwrap()
					.job()
					.identity(),
				expected,
			);
		};
		carrier.await;
	}

	#[test]
	fn only_clear_pre_intent_history_can_start_another_attempt() {
		let name = ".exacopy-018d0454-2082-7444-8f45-7c4617e17ea2";
		let job = selected_job(
			Path::new(name),
			UnixComponent::new(name.as_bytes()).unwrap(),
		)
		.ok()
		.unwrap();
		for phase in [
			Phase::Capture,
			Phase::Retired,
			Phase::Sealed,
			Phase::Verified,
			Phase::MetadataReady,
		] {
			assert!(startup_outcome(phase, true, &job).is_none());
			assert_eq!(startup_outcome(phase, false, &job).unwrap().exit_code(), 9);
		}
		for phase in [
			Phase::Intent,
			Phase::Published,
			Phase::Uncertain,
			Phase::Durable,
			Phase::ReceiptCommitted,
		] {
			assert_eq!(startup_outcome(phase, true, &job).unwrap().exit_code(), 9);
		}
		assert_eq!(
			startup_outcome(Phase::Conflict, true, &job)
				.unwrap()
				.exit_code(),
			3
		);
	}
}
