use super::native::ObjectId;

impl ObjectId {
	/// Returns the observed volume GUID as 36 lowercase, hyphenated ASCII bytes.
	#[must_use]
	pub const fn volume_guid(self) -> [u8; 36] {
		self.volume.0
	}

	/// Returns the exact unsigned native volume serial number.
	#[must_use]
	pub const fn volume_serial(self) -> u64 {
		self.volume_serial
	}

	/// Returns all 16 native file ID bytes in their observed order.
	#[must_use]
	pub const fn file_id(self) -> [u8; 16] {
		self.file_id
	}
}
