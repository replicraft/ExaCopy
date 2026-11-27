use std::future::pending;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, split};
use tokio::time::{Instant, sleep_until};

use crate::protocol::INNER_MTU;

use super::{PacketEvent, PacketInterest, PacketIo, PumpError, Signals};
use crate::stack::{InnerTcp, PacketDisposition, PollHint, ReadProgress, TcpError, TcpState};

const CHUNK_BYTES: usize = 4096;
const WORK_BUDGET: usize = 16;
const CONNECT_LIMIT: Duration = Duration::from_secs(30);
pub(super) const CLOSE_LIMIT: Duration = Duration::from_secs(20);

pub(super) async fn run<I: PacketIo>(
	tcp: &mut InnerTcp,
	pipe: &mut DuplexStream,
	signals: &mut Signals,
	io: &mut I,
) -> Result<(), PumpError<I::Error>> {
	let (mut reader, mut writer) = split(pipe);
	let start = Instant::now();
	let mut deadlines = Deadlines::new(start).map_err(PumpError::Tcp)?;
	let mut inbound = Chunk::new();
	let mut outbound = Chunk::new();
	let mut path_backpressure = false;
	let mut app_half_closed = false;
	let mut local_fin_started = false;
	let mut peer_half_closed = false;
	let mut peer_eof_delivered = false;
	let mut packet_buffer = [0; INNER_MTU];
	let mut work = 0;
	loop {
		if signals.route.token.is_cancelled() {
			return Err(PumpError::RouteRevoked);
		}
		if signals.cancelled.is_cancelled() {
			return Err(PumpError::Cancelled);
		}
		if work == WORK_BUDGET {
			tokio::task::yield_now().await;
			work = 0;
			continue;
		}
		work += 1;
		io.check(tcp.binding()).map_err(PumpError::Route)?;
		let now = Instant::now();
		let elapsed = now
			.checked_duration_since(start)
			.ok_or(PumpError::Tcp(TcpError::Clock))?;
		let shutdown = *signals.shutdown.borrow();
		deadlines
			.observe_shutdown(shutdown)
			.map_err(PumpError::Tcp)?;
		if deadlines
			.active(tcp.state())
			.is_some_and(|deadline| now >= deadline)
		{
			return Err(PumpError::Deadline);
		}
		let hint = tcp.poll(elapsed).map_err(PumpError::Tcp)?;
		#[cfg(feature = "experimental-udp")]
		if let Some(open) = &signals.open {
			open.send_if_modified(|previous| {
				let current = tcp.state() == TcpState::Writable;
				let changed = *previous != current;
				*previous = current;
				changed
			});
		}
		if tcp.in_time_wait() {
			deadlines.enter_time_wait(now).map_err(PumpError::Tcp)?;
		}
		if hint == PollHint::Egress && !path_backpressure {
			match tcp
				.egress(|binding, packet| io.send(binding, packet))
				.map_err(PumpError::Route)?
			{
				Some(PacketDisposition::Accepted) => continue,
				Some(PacketDisposition::Backpressure) => path_backpressure = true,
				None => return Err(PumpError::UnexpectedEvent),
			}
		}

		if !outbound.is_empty() {
			let written = tcp.write(outbound.remaining()).map_err(PumpError::Tcp)?;
			outbound.consume(written);
			if written > 0 {
				continue;
			}
		}
		if app_half_closed
			&& outbound.is_empty()
			&& !local_fin_started
			&& tcp.state() == TcpState::Writable
		{
			tcp.close_send().map_err(PumpError::Tcp)?;
			local_fin_started = true;
			continue;
		}

		if inbound.is_empty() && !peer_half_closed {
			match tcp.read(&mut inbound.bytes).map_err(PumpError::Tcp)? {
				ReadProgress::Bytes(read) => inbound.fill(read.get()),
				ReadProgress::Pending => {}
				ReadProgress::Eof => peer_half_closed = true,
			}
		}
		// TIME-WAIT still owes delayed or repeated final ACKs. Keep the
		// driver alive until the stack has finished that phase.
		if local_fin_started && peer_eof_delivered && tcp.finished() {
			return Ok(());
		}
		if tcp.state() == TcpState::Closed {
			return Err(PumpError::Tcp(TcpError::Closed));
		}

		let deadline = deadlines.active(tcp.state());
		let stack_deadline = match hint {
			PollHint::At(time) => Some(
				start
					.checked_add(time)
					.ok_or(PumpError::Tcp(TcpError::Clock))?,
			),
			_ => None,
		};
		let interest = PacketInterest {
			receive: tcp.accepts_ingress(),
			writable: path_backpressure,
		};
		let send_eof = inbound.is_empty() && peer_half_closed && !peer_eof_delivered;
		let event = tokio::select! {
			() = signals.route.token.cancelled() => return Err(PumpError::RouteRevoked),
			() = signals.cancelled.cancelled() => return Err(PumpError::Cancelled),
			_ = signals.shutdown.changed(), if shutdown.is_none() => continue,
			() = at(deadline) => return Err(PumpError::Deadline),
			() = at(stack_deadline) => continue,
			read = reader.read(&mut outbound.bytes), if outbound.is_empty() && !app_half_closed => {
				let count = read.map_err(PumpError::Pipe)?;
				if count == 0 {
					app_half_closed = true;
				} else {
					outbound.fill(count);
				}
				continue;
			}
			written = send_to_pipe(&mut writer, inbound.remaining(), send_eof),
				if !inbound.is_empty() || send_eof =>
			{
				let count = written.map_err(PumpError::Pipe)?;
				inbound.consume(count);
				peer_eof_delivered |= send_eof;
				continue;
			}
			event = io.wait(interest, &mut packet_buffer) => event.map_err(PumpError::Route)?,
		};
		match event {
			PacketEvent::Writable if interest.writable => path_backpressure = false,
			PacketEvent::Received(count) if interest.receive => {
				io.check(tcp.binding()).map_err(PumpError::Route)?;
				let packet = packet_buffer
					.get(..count)
					.ok_or(PumpError::UnexpectedEvent)?;
				match tcp.ingress(packet) {
					Ok(())
					| Err(TcpError::Packet | TcpError::FlowMismatch | TcpError::Acknowledgement) => {}
					Err(error) => return Err(PumpError::Tcp(error)),
				}
			}
			_ => return Err(PumpError::UnexpectedEvent),
		}
	}
}

async fn send_to_pipe(
	writer: &mut (impl AsyncWrite + Unpin),
	bytes: &[u8],
	send_eof: bool,
) -> io::Result<usize> {
	if send_eof {
		writer.shutdown().await?;
		Ok(0)
	} else {
		let written = writer.write(bytes).await?;
		if written == 0 {
			return Err(io::ErrorKind::WriteZero.into());
		}
		Ok(written)
	}
}

struct Deadlines {
	connect: Instant,
	drain: Option<Instant>,
	linger: Option<Instant>,
}

impl Deadlines {
	fn new(start: Instant) -> Result<Self, TcpError> {
		Ok(Self {
			connect: start.checked_add(CONNECT_LIMIT).ok_or(TcpError::Clock)?,
			drain: None,
			linger: None,
		})
	}

	fn observe_shutdown(&mut self, requested: Option<Instant>) -> Result<(), TcpError> {
		if self.drain.is_none()
			&& let Some(requested) = requested
		{
			self.drain = Some(requested.checked_add(CLOSE_LIMIT).ok_or(TcpError::Clock)?);
		}
		Ok(())
	}

	fn enter_time_wait(&mut self, now: Instant) -> Result<(), TcpError> {
		if self.linger.is_none() {
			self.linger = Some(now.checked_add(CLOSE_LIMIT).ok_or(TcpError::Clock)?);
		}
		Ok(())
	}

	fn active(&self, state: TcpState) -> Option<Instant> {
		let close = self.linger.or(self.drain);
		if state == TcpState::Opening {
			return Some(close.map_or(self.connect, |limit| limit.min(self.connect)));
		}
		close
	}
}

async fn at(deadline: Option<Instant>) {
	match deadline {
		Some(deadline) => sleep_until(deadline).await,
		None => pending().await,
	}
}

struct Chunk {
	bytes: [u8; CHUNK_BYTES],
	start: usize,
	end: usize,
}

impl Chunk {
	const fn new() -> Self {
		Self {
			bytes: [0; CHUNK_BYTES],
			start: 0,
			end: 0,
		}
	}

	fn fill(&mut self, count: usize) {
		self.start = 0;
		self.end = count;
	}

	fn consume(&mut self, count: usize) {
		self.start += count;
	}

	fn is_empty(&self) -> bool {
		self.start == self.end
	}

	fn remaining(&self) -> &[u8] {
		&self.bytes[self.start..self.end]
	}
}

#[cfg(test)]
mod tests {
	use super::{CLOSE_LIMIT, CONNECT_LIMIT, Deadlines, Duration, Instant, TcpState};

	#[test]
	fn drain_and_linger_use_distinct_fixed_deadlines() {
		let start = Instant::now();
		let mut deadlines = Deadlines::new(start).unwrap();
		assert_eq!(
			deadlines.active(TcpState::Opening),
			Some(start + CONNECT_LIMIT)
		);
		assert_eq!(deadlines.active(TcpState::Writable), None);

		let shutdown = start + Duration::from_secs(5);
		deadlines.observe_shutdown(Some(shutdown)).unwrap();
		let drain = shutdown + CLOSE_LIMIT;
		assert_eq!(deadlines.active(TcpState::Opening), Some(drain));
		deadlines
			.observe_shutdown(Some(shutdown + Duration::from_secs(1)))
			.unwrap();
		assert_eq!(deadlines.active(TcpState::Closing), Some(drain));

		let time_wait = drain - Duration::from_secs(1);
		deadlines.enter_time_wait(time_wait).unwrap();
		let linger = time_wait + CLOSE_LIMIT;
		assert_eq!(deadlines.active(TcpState::Closing), Some(linger));
		deadlines
			.enter_time_wait(time_wait + Duration::from_secs(1))
			.unwrap();
		assert_eq!(deadlines.active(TcpState::Closing), Some(linger));
	}
}
