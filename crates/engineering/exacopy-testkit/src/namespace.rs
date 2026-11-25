use std::collections::BTreeMap;

use exacopy_endpoint::UnixComponent;

use crate::fault::Rejection;

pub(crate) const MAX_OBJECTS: usize = 64;
pub(crate) const MAX_NAMES_PER_AREA: usize = 64;
pub(crate) const MAX_FILE_BYTES: usize = 4096;

/// A fixture-assigned disk identity, distinct for distinct simulated volumes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiskId(u64);

impl DiskId {
	/// Wraps a disk number assigned by the test fixture.
	#[must_use]
	pub const fn new(number: u64) -> Self {
		Self(number)
	}
}

/// The identity of a regular file on a simulated disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectId {
	disk: DiskId,
	number: usize,
}

impl ObjectId {
	pub(crate) const fn new(disk: DiskId, number: usize) -> Self {
		Self { disk, number }
	}

	pub(crate) const fn number(self) -> usize {
		self.number
	}
}

/// One independently persisted directory in the simulator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Area {
	/// The directory whose contents are available only as a source.
	Source,
	/// The privately owned staging directory.
	Private,
	/// The public destination directory.
	Destination,
}

impl Area {
	const fn index(self) -> usize {
		match self {
			Self::Source => 0,
			Self::Private => 1,
			Self::Destination => 2,
		}
	}
}

/// The directories an attempt can ask to persist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritableArea {
	/// Persist the private directory entries.
	Private,
	/// Persist the destination directory entries.
	Destination,
}

impl From<WritableArea> for Area {
	fn from(value: WritableArea) -> Self {
		match value {
			WritableArea::Private => Self::Private,
			WritableArea::Destination => Self::Destination,
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NameEntry {
	File(ObjectId),
	Symlink,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Names([BTreeMap<Vec<u8>, NameEntry>; 3]);

impl Names {
	pub(crate) fn get(&self, area: Area, name: &[u8]) -> Option<NameEntry> {
		self.0[area.index()].get(name).copied()
	}

	pub(crate) fn admit(&self, area: Area, name: &[u8]) -> Result<(), Rejection> {
		let names = &self.0[area.index()];
		if names.contains_key(name) {
			return Err(Rejection::Conflict);
		}
		if names.len() == MAX_NAMES_PER_AREA {
			return Err(Rejection::Limit);
		}
		Ok(())
	}

	pub(crate) fn insert(&mut self, area: Area, name: Vec<u8>, entry: NameEntry) {
		self.0[area.index()].insert(name, entry);
	}

	pub(crate) fn remove(&mut self, area: Area, name: &[u8]) {
		self.0[area.index()].remove(name);
	}

	pub(crate) fn file_numbers(&self) -> impl Iterator<Item = usize> {
		self.0
			.iter()
			.flat_map(|names| names.values())
			.filter_map(|entry| match entry {
				NameEntry::File(identity) => Some(identity.number()),
				NameEntry::Symlink => None,
			})
	}

	pub(crate) fn persist(&mut self, live: &Self, area: Area) {
		self.0[area.index()].clone_from(&live.0[area.index()]);
	}
}

/// An externally inspectable entry in one storage snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Entry<'a> {
	/// A regular file with exactly the stored bytes.
	File(FileView<'a>),
	/// A link occupying a name without a followable target in this simulator.
	Symlink,
}

/// A regular file's independent identity and contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileView<'a> {
	/// The physical file to which the snapshot entry refers.
	pub identity: ObjectId,
	/// The byte contents in this particular snapshot.
	pub bytes: &'a [u8],
}

/// A captured view of directory entries and their file contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
	names: Names,
	files: BTreeMap<usize, Vec<u8>>,
}

impl Snapshot {
	pub(crate) fn new<'a>(names: &Names, bytes: impl Fn(usize) -> Option<&'a Vec<u8>>) -> Self {
		let mut files = BTreeMap::new();
		for number in names.file_numbers() {
			if let std::collections::btree_map::Entry::Vacant(entry) = files.entry(number)
				&& let Some(data) = bytes(number)
			{
				entry.insert(data.clone());
			}
		}
		Self {
			names: names.clone(),
			files,
		}
	}

	/// Observes the entry at one exact name without following links.
	#[must_use]
	pub fn entry(&self, area: Area, name: &UnixComponent<'_>) -> Option<Entry<'_>> {
		match self.names.get(area, name.as_bytes())? {
			NameEntry::File(identity) => Some(Entry::File(FileView {
				identity,
				bytes: self.files.get(&identity.number())?,
			})),
			NameEntry::Symlink => Some(Entry::Symlink),
		}
	}
}
