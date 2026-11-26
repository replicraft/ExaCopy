use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::wireguard::{InnerDial, InnerDialKind};
use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;
use exacopy_journal::remote_download::qualification::RemoteQualificationRouteClass;
use exacopy_journal::remote_download::{
	RemoteDownloadDestination, RemoteDownloadDurability, RemoteDownloadRoute, RemoteDownloadScope,
};
use exacopy_journal::{
	JournalEntryId, JournalJobId, LinuxFileIdentity, OwnerTimestamp, OwnerToken, StreamLength,
};
use exacopy_platform::linux::{DestinationRoot, FileIdentity, TargetStatus};
use tokio::net::lookup_host;
use uuid::{Builder, Uuid};

use crate::args::RemoteOptions;
use crate::assembly::linux::remote_download::RemoteJobAction;
use crate::linux_path::split;
use crate::profile::{LocalProfile, kernel_random};
use crate::remote_frontdoor::{AddressOrder, ApprovedRoute, GetRequest, SshProfile};
use crate::remote_report::{RemoteFailureKind as Failure, RemoteJob, RemoteOutcome};

use super::interrupt::Interrupt;
use super::qualification::Qualification;

const DNS_DEADLINE: Duration = Duration::from_secs(5);
const MAX_ADDRESSES: usize = 64;
const MAX_UUIDV7_MILLIS: u64 = (1 << 48) - 1;

pub(super) struct Selected {
	pub(super) job: RemoteJob,
	pub(super) scope: RemoteDownloadScope,
	pub(super) action: RemoteJobAction,
	pub(super) qualification: Qualification,
}

pub(super) async fn fresh(
	request: &GetRequest,
	options: &RemoteOptions,
	root: &DestinationRoot,
	owners: &LocalProfile,
	ssh: &SshProfile,
	interrupt: &Interrupt,
) -> Result<Selected, Box<RemoteOutcome>> {
	let class = match &ssh.route {
		ApprovedRoute::EmbeddedWireGuard(_) => {
			if !cfg!(feature = "experimental-ssh-wireguard") {
				return Err(refused(Failure::Unsupported));
			}
			RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1
		}
		_ => RemoteQualificationRouteClass::DirectPinnedTcpV1,
	};
	let qualification =
		Qualification::open(options, root, &owners.verification_key(), class).map_err(refused)?;
	interrupt.check().map_err(refused)?;
	let (parent, target) =
		split(&request.destination).map_err(|_| refused(Failure::InvalidRequest))?;
	if root
		.target_status(target)
		.map_err(|_| refused(Failure::Io))?
		!= TargetStatus::Absent
	{
		return Err(refused(Failure::Conflict));
	}
	let route = selected_route(ssh, interrupt).await.map_err(refused)?;
	let remote = request
		.signed_source(ssh, route)
		.map_err(|_| refused(Failure::Authorization))?;
	let (job, created, token, entry) = new_identity().map_err(refused)?;
	let destination = RemoteDownloadDestination::new(
		owners
			.root_id(root.identity())
			.map_err(|_| refused(Failure::Authorization))?,
		record_identity(root.identity()),
		target,
	);
	let maximum =
		StreamLength::new(ssh.maximum_extent).map_err(|_| refused(Failure::InvalidRequest))?;
	let scope = RemoteDownloadScope::new(
		entry,
		remote,
		destination,
		maximum,
		SftpDataOnlyV1::digest(),
		RemoteDownloadDurability::ProcessCrash,
	)
	.map_err(|_| refused(Failure::InvalidRequest))?;
	Ok(Selected {
		job: RemoteJob {
			id: job,
			directory: Path::new(parent).join(job_component(job)),
		},
		scope,
		action: RemoteJobAction::Create { token, created },
		qualification,
	})
}

pub(super) fn route_class(
	route: RemoteDownloadRoute,
) -> Result<RemoteQualificationRouteClass, Failure> {
	match route {
		RemoteDownloadRoute::ResolvedDirect { .. } => {
			Ok(RemoteQualificationRouteClass::DirectPinnedTcpV1)
		}
		RemoteDownloadRoute::EmbeddedWireGuard { .. } => {
			Ok(RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1)
		}
		_ => Err(Failure::Unsupported),
	}
}

async fn selected_route(
	ssh: &SshProfile,
	interrupt: &Interrupt,
) -> Result<RemoteDownloadRoute, Failure> {
	let endpoint = match &ssh.route {
		ApprovedRoute::Direct(endpoint) => *endpoint,
		ApprovedRoute::ResolveAuthority(order) => {
			interrupt.check()?;
			let bound = (ssh.authority.host(), ssh.authority.port().get());
			let endpoints = tokio::select! {
				biased;
				() = interrupt.wait() => return Err(Failure::Cancelled),
				result = tokio::time::timeout(DNS_DEADLINE, lookup_host(bound)) => {
					result.map_err(|_| Failure::Io)?.map_err(|_| Failure::Io)?
				}
			};
			let selected = choose_address(endpoints, *order, ssh.authority.port().get())?;
			interrupt.check()?;
			selected
		}
		ApprovedRoute::EmbeddedWireGuard(approved) => {
			return Ok(RemoteDownloadRoute::EmbeddedWireGuard {
				peer: approved.peer_public_key,
				revision: approved.revision,
				inner: approved.remote_inner,
			});
		}
	};
	Ok(RemoteDownloadRoute::ResolvedDirect { endpoint })
}

fn choose_address(
	addresses: impl Iterator<Item = std::net::SocketAddr>,
	order: AddressOrder,
	port: u16,
) -> Result<std::net::SocketAddr, Failure> {
	let (mut v4, mut v6) = (None, None);
	for (index, address) in addresses.take(MAX_ADDRESSES + 1).enumerate() {
		if index == MAX_ADDRESSES {
			return Err(Failure::Authorization);
		}
		if address.port() != port
			|| InnerDial::new(InnerDialKind::Stream, address).is_none()
			|| matches!(address.ip(), std::net::IpAddr::V6(ip) if ip.is_unicast_link_local())
		{
			continue;
		}
		if address.is_ipv4() {
			v4.get_or_insert(address);
		} else {
			v6.get_or_insert(address);
		}
	}
	match order {
		AddressOrder::Ipv4First => v4.or(v6),
		AddressOrder::Ipv6First => v6.or(v4),
	}
	.ok_or(Failure::Authorization)
}

pub(super) fn job_component(job: JournalJobId) -> String {
	format!(".exacopy-{}", Uuid::from_bytes(*job.as_bytes()))
}

pub(super) fn selected_job(path: &Path, name: UnixComponent<'_>) -> Result<RemoteJob, Failure> {
	let text = std::str::from_utf8(name.as_bytes()).map_err(|_| Failure::InvalidRequest)?;
	let suffix = text
		.strip_prefix(".exacopy-")
		.ok_or(Failure::InvalidRequest)?;
	let uuid = Uuid::parse_str(suffix).map_err(|_| Failure::InvalidRequest)?;
	let id = JournalJobId::from_bytes(uuid.into_bytes()).map_err(|_| Failure::InvalidRequest)?;
	if job_component(id).as_bytes() != name.as_bytes() {
		return Err(Failure::InvalidRequest);
	}
	Ok(RemoteJob {
		id,
		directory: PathBuf::from(path),
	})
}

fn new_identity() -> Result<(JournalJobId, OwnerTimestamp, OwnerToken, JournalEntryId), Failure> {
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(|_| Failure::Io)?;
	let millis = u64::try_from(now.as_millis())
		.ok()
		.filter(|millis| *millis <= MAX_UUIDV7_MILLIS)
		.ok_or(Failure::Io)?;
	let timestamp = OwnerTimestamp::new(
		i64::try_from(now.as_secs()).map_err(|_| Failure::Io)?,
		now.subsec_nanos(),
	)
	.map_err(|_| Failure::Io)?;
	let mut tail = [0; 10];
	let mut token = [0; 16];
	let mut entry = [0; 16];
	kernel_random(&mut tail).map_err(|_| Failure::Io)?;
	kernel_random(&mut token).map_err(|_| Failure::Io)?;
	kernel_random(&mut entry).map_err(|_| Failure::Io)?;
	let job = Builder::from_unix_timestamp_millis(millis, &tail).into_uuid();
	Ok((
		JournalJobId::from_bytes(job.into_bytes()).map_err(|_| Failure::Io)?,
		timestamp,
		OwnerToken::from_bytes(token).map_err(|_| Failure::Io)?,
		JournalEntryId::from_bytes(Builder::from_random_bytes(entry).into_uuid().into_bytes()),
	))
}

pub(super) fn record_identity(identity: FileIdentity) -> LinuxFileIdentity {
	LinuxFileIdentity::new(identity.device(), identity.inode())
}

pub(super) fn refused(code: Failure) -> Box<RemoteOutcome> {
	Box::new(RemoteOutcome::failed(code, None))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn bounded_resolution_selects_one_literal_and_preserves_preference() {
		let v4 = "192.0.2.20:22".parse().unwrap();
		let v6 = "[2001:db8::20]:22".parse().unwrap();
		let wrong = "192.0.2.21:2222".parse().unwrap();
		let values = [wrong, v4, v6];
		assert_eq!(
			choose_address(values.into_iter(), AddressOrder::Ipv6First, 22).ok(),
			Some(v6)
		);
		assert_eq!(
			choose_address(values.into_iter(), AddressOrder::Ipv4First, 22).ok(),
			Some(v4)
		);
		assert!(
			choose_address(
				std::iter::repeat_n(v4, MAX_ADDRESSES + 1),
				AddressOrder::Ipv4First,
				22
			)
			.is_err()
		);
	}
}
