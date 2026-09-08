//! Opaque binary attachment framing shared with the browser codec.
use super::*;
use serde_json::{Value, json};
const MAGIC: u32 = 0x31424b50;
pub(super) fn decode(bytes: &[u8]) -> Result<(Value, Vec<Vec<u8>>), ApiError> {
    if bytes.len() < 8
        || bytes.len() > MAX_JSON_BODY_BYTES
        || u32::from_le_bytes(bytes[..4].try_into().unwrap()) != MAGIC
    {
        return Err(ApiError::bad_request("invalid binary frame"));
    }
    let length = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if length > 262144 || length > bytes.len() - 8 {
        return Err(ApiError::bad_request("invalid binary header"));
    }
    let mut value: Value = serde_json::from_slice(&bytes[8..8 + length])
        .map_err(|_| ApiError::bad_request("invalid binary metadata"))?;
    let mut at = 8 + length;
    let mut blobs = vec![];
    if let Some(messages) = value
        .pointer_mut("/body/messages")
        .and_then(Value::as_array_mut)
    {
        if messages.len() > 32 {
            return Err(ApiError::bad_request("too many messages"));
        }
        for message in messages {
            let marker = message
                .get("payload")
                .and_then(Value::as_object)
                .ok_or_else(|| ApiError::bad_request("missing attachment"))?;
            let index = marker.get("$b").and_then(Value::as_u64);
            let size = marker
                .get("n")
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| ApiError::bad_request("invalid attachment size"))?;
            if marker.len() != 2 || index != Some(blobs.len() as u64) || size > bytes.len() - at {
                return Err(ApiError::bad_request("invalid attachment"));
            }
            blobs.push(bytes[at..at + size].to_vec());
            at += size;
            message["payload"] = json!("");
        }
    }
    if at != bytes.len() {
        return Err(ApiError::bad_request("trailing binary data"));
    }
    Ok((value, blobs))
}
pub(super) fn encode(value: Value, blobs: Vec<Vec<u8>>) -> Result<Vec<u8>, ApiError> {
    let header = serde_json::to_vec(&value).map_err(|_| ApiError::internal())?;
    let size = 8 + header.len() + blobs.iter().map(Vec::len).sum::<usize>();
    if size > MAX_JSON_BODY_BYTES {
        return Err(ApiError::too_large("frame too large"));
    }
    let mut out = Vec::with_capacity(size);
    out.extend(MAGIC.to_le_bytes());
    out.extend((header.len() as u32).to_le_bytes());
    out.extend(header);
    for blob in blobs {
        out.extend(blob);
    }
    Ok(out)
}
pub(super) fn page(page: PollResponse) -> (Value, Vec<Vec<u8>>) {
    let mut blobs = vec![];
    let messages: Vec<_> = page
        .messages
        .into_iter()
        .map(|mut message| {
            let payload = std::mem::take(&mut message.payload);
            let marker = json!({"$b":blobs.len(),"n":payload.len()});
            blobs.push(payload);
            let mut value = serde_json::to_value(message).expect("serializable message");
            value["payload"] = marker;
            value
        })
        .collect();
    (
        json!({"epoch":page.epoch,"joined":page.joined,"nextCursor":page.next_cursor,"messages":messages}),
        blobs,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_payloads_are_exact_and_bounded() {
        let value = json!({"id":1,"handle":1,"body":{"messages":[{"payload":{"$b":0,"n":3}}]}});
        let encoded = encode(value, vec![vec![0, 128, 255]]).unwrap();
        let (_, data) = decode(&encoded).unwrap();
        assert_eq!(data, vec![vec![0, 128, 255]]);
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        assert!(decode(&encoded[..encoded.len() - 1]).is_err());
        let malformed = encode(
            json!({"body":{"messages":[{"payload":{"$b":1,"n":3}}]}}),
            vec![vec![1, 2, 3]],
        )
        .unwrap();
        assert!(decode(&malformed).is_err());
    }
}
