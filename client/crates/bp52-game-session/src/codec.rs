//! Small canonical codec helpers shared by journal and reducer state.

use bp52_chain_types::Role;
use bp52_codec::{CodecError, Reader, Writer};
use sha2::{Digest, Sha256};

const RECORD_TAG: &[u8] = b"BP52/session-event/v2";
const CONFIG_TAG: &[u8] = b"BP52/session-config/v1";
const SHARED_CONFIG_TAG: &[u8] = b"BP52/session-shared-config/v1";

pub(crate) const JOURNAL_MAGIC: &[u8; 8] = b"BP52SES4";

pub(crate) fn write_role(writer: &mut Writer, role: Role) {
    writer.write_u8(role.code());
}

pub(crate) fn read_role(reader: &mut Reader<'_>) -> Result<Role, CodecError> {
    match reader.read_u8()? {
        0 => Ok(Role::Alice),
        1 => Ok(Role::Bob),
        _ => Err(CodecError::NonCanonical),
    }
}

pub(crate) fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(message);
    hasher.finalize().into()
}

pub(crate) fn config_digest(bytes: &[u8]) -> [u8; 32] {
    tagged_hash(CONFIG_TAG, bytes)
}

pub(crate) fn shared_config_digest(bytes: &[u8]) -> [u8; 32] {
    tagged_hash(SHARED_CONFIG_TAG, bytes)
}

pub(crate) fn record_digest(
    config_hash: [u8; 32],
    sequence: u64,
    previous_hash: [u8; 32],
    event: &[u8],
) -> Result<[u8; 32], CodecError> {
    let event_len = u32::try_from(event.len()).map_err(|_| CodecError::LengthOverflow)?;
    let mut bytes = Vec::with_capacity(32 + 8 + 32 + 4 + event.len());
    bytes.extend_from_slice(&config_hash);
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&previous_hash);
    bytes.extend_from_slice(&event_len.to_le_bytes());
    bytes.extend_from_slice(event);
    Ok(tagged_hash(RECORD_TAG, &bytes))
}
