use bytes::Bytes;
use exacopy_endpoint::ssh_sftp::{SftpAdvertisement, SftpCapabilities};
use russh::ChannelStream;
use russh::client::Msg;
use russh_sftp::protocol::{Init, Packet};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::error::Error;
use crate::shape::check_response_shape;

const MAX_FRAME_BYTES: usize = 256 * 1024;

pub(crate) struct Wire {
	stream: ChannelStream<Msg>,
	next: u32,
	pub(crate) capabilities: SftpCapabilities,
}

impl Wire {
	pub(crate) async fn init(mut stream: ChannelStream<Msg>) -> Result<Self, Error> {
		let Packet::Version(version) = exchange(&mut stream, Init::default().into()).await? else {
			return Err(Error::Protocol);
		};
		let advertises_v1 = |extension| {
			version
				.extensions
				.get(extension)
				.is_some_and(|value| value == "1")
		};
		let capabilities = SftpCapabilities::for_source(
			version.version,
			SftpAdvertisement {
				file_sync: advertises_v1("fsync@openssh.com"),
				posix_rename: advertises_v1("posix-rename@openssh.com"),
				hardlink: advertises_v1("hardlink@openssh.com"),
			},
		)
		.map_err(Error::Version)?;
		Ok(Self {
			stream,
			next: 1,
			capabilities,
		})
	}

	pub(crate) async fn request(
		&mut self,
		packet: impl FnOnce(u32) -> Packet,
	) -> Result<Packet, Error> {
		let id = self.next;
		self.next = id.checked_add(1).ok_or(Error::Limit)?;
		let response = exchange(&mut self.stream, packet(id)).await?;
		let reply_id = match &response {
			Packet::Status(reply) => reply.id,
			Packet::Attrs(reply) => reply.id,
			Packet::Handle(reply) => reply.id,
			Packet::Name(reply) => reply.id,
			Packet::Data(reply) => reply.id,
			_ => return Err(Error::Protocol),
		};
		if reply_id != id {
			return Err(Error::Protocol);
		}
		Ok(response)
	}
}

async fn exchange(stream: &mut ChannelStream<Msg>, packet: Packet) -> Result<Packet, Error> {
	let bytes = Bytes::try_from(packet).map_err(|_| Error::Protocol)?;
	if bytes.len() > MAX_FRAME_BYTES {
		return Err(Error::Limit);
	}
	stream.write_all(&bytes).await?;
	stream.flush().await?;
	receive(stream).await
}

async fn receive(stream: &mut (impl AsyncRead + Unpin)) -> Result<Packet, Error> {
	let len = stream.read_u32().await? as usize;
	if !(1..=MAX_FRAME_BYTES).contains(&len) {
		return Err(Error::Limit);
	}
	let mut incoming = vec![0; len];
	stream.read_exact(&mut incoming).await?;
	check_response_shape(&incoming)?;
	let mut body = Bytes::from(incoming);
	let response = Packet::try_from(&mut body).map_err(|_| Error::Protocol)?;
	if !body.is_empty() {
		return Err(Error::Protocol);
	}
	Ok(response)
}

#[cfg(test)]
mod tests {
	use bytes::Bytes;
	use russh_sftp::protocol::{Data, Packet};
	use tokio::io::{AsyncWriteExt, duplex};

	use super::{MAX_FRAME_BYTES, receive};
	use crate::Error;

	#[tokio::test]
	async fn rejects_frame_length_before_reading_the_payload() {
		let (mut receiver, mut sender) = duplex(8);
		// A body read would wait indefinitely because the sender only writes the length.
		sender.write_u32(MAX_FRAME_BYTES as u32 + 1).await.unwrap();
		assert!(matches!(receive(&mut receiver).await, Err(Error::Limit)));
	}

	#[tokio::test]
	async fn rejects_unconsumed_frame_bytes() {
		let (mut receiver, mut sender) = duplex(64);
		let packet = Bytes::try_from(Packet::Data(Data {
			id: 1,
			data: vec![0; 1],
		}))
		.unwrap();
		let body = &packet[4..];
		sender.write_u32(body.len() as u32 + 1).await.unwrap();
		sender.write_all(body).await.unwrap();
		sender.write_u8(0).await.unwrap();
		assert!(matches!(receive(&mut receiver).await, Err(Error::Protocol)));
	}
}
