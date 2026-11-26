use super::Error;

const HEADER_BYTES: usize = 20;
const DACL_PRESENT: u16 = 0x0004;
const DACL_PROTECTED: u16 = 0x1000;
const SELF_RELATIVE: u16 = 0x8000;
const MAX_ACES: u16 = 256;

// MS-DTYP SID representations of LocalSystem and BUILTIN\Administrators.
pub(super) const SYSTEM: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
pub(super) const ADMINISTRATORS: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];

// Effective untrusted rights permitted on an upper directory. Bits 2 and 4
// add unrelated children. This profile admits only already-held safe children.
const UPPER_ALLOWED_ACCESS: u32 = 0xa012_00af;
const INHERIT_ONLY: u8 = 0x08;
const VALID_INHERITANCE_FLAGS: u8 = 0x1f;

#[derive(Clone, Copy)]
pub(super) enum Role {
	UpperDirectory,
	Private,
}

pub(super) fn approve(input: &[u8], user: &[u8], role: Role) -> Result<(), Error> {
	approve_inner(input, user, role).ok_or(Error::Unprotected)
}

fn approve_inner(input: &[u8], user: &[u8], role: Role) -> Option<()> {
	let header = input.get(..HEADER_BYTES)?;
	if header[0] != 1 || header[1] != 0 {
		return None;
	}
	let control = u16_from(header.get(2..4)?)?;
	let require = SELF_RELATIVE
		| DACL_PRESENT
		| if matches!(role, Role::Private) {
			DACL_PROTECTED
		} else {
			0
		};
	if control & require != require {
		return None;
	}
	let owner_offset = offset(header.get(4..8)?)?;
	let dacl_offset = offset(header.get(16..20)?)?;
	let owner = sid(input.get(owner_offset..)?)?;
	if match role {
		Role::UpperDirectory => !trusted(owner, user),
		Role::Private => owner != user,
	} {
		return None;
	}
	let dacl = input.get(dacl_offset..)?;
	let acl_size = usize::from(u16_from(dacl.get(2..4)?)?);
	let count = u16_from(dacl.get(4..6)?)?;
	if !matches!(dacl[0], 2 | 4)
		|| dacl[1] != 0
		|| count > MAX_ACES
		|| dacl.get(6..8)? != [0, 0]
		|| (dacl_offset < owner_offset.checked_add(owner.len())?
			&& owner_offset < dacl_offset.checked_add(acl_size)?)
	{
		return None;
	}

	let mut remaining = dacl.get(8..acl_size)?;
	for _ in 0..count {
		let ace_header = remaining.get(..8)?;
		let ace_size = usize::from(u16_from(ace_header.get(2..4)?)?);
		if ace_size < 8 || !ace_size.is_multiple_of(4) {
			return None;
		}
		let (ace, next) = remaining.split_at_checked(ace_size)?;
		remaining = next;
		let mask = u32_from(ace_header.get(4..8)?)?;
		let trustee = sid(&ace[8..])?;
		if trustee != &ace[8..] || ace_header[1] & !VALID_INHERITANCE_FLAGS != 0 {
			return None;
		}
		match ace_header[0] {
			// Evaluate a conservative sufficient condition, regardless of deny ordering.
			0 if !trusted(trustee, user) => {
				let refused = match role {
					Role::Private => mask != 0,
					Role::UpperDirectory => {
						ace_header[1] & INHERIT_ONLY == 0 && mask & !UPPER_ALLOWED_ACCESS != 0
					}
				};
				if refused {
					return None;
				}
			}
			0 | 1 => {}
			_ => return None,
		}
	}
	Some(())
}

fn trusted(sid: &[u8], user: &[u8]) -> bool {
	sid == user || sid == SYSTEM || sid == ADMINISTRATORS
}

pub(super) fn sid(input: &[u8]) -> Option<&[u8]> {
	let [1, count @ 0..=15, ..] = *input.get(..2)? else {
		return None;
	};
	input.get(..8 + usize::from(count) * 4)
}

fn offset(input: &[u8]) -> Option<usize> {
	let value = usize::try_from(u32_from(input)?).ok()?;
	(value >= HEADER_BYTES && value.is_multiple_of(4)).then_some(value)
}

fn u16_from(input: &[u8]) -> Option<u16> {
	Some(u16::from_le_bytes(input.try_into().ok()?))
}

fn u32_from(input: &[u8]) -> Option<u32> {
	Some(u32::from_le_bytes(input.try_into().ok()?))
}

#[cfg(test)]
mod tests;
