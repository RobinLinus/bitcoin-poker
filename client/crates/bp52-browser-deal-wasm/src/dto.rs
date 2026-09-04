use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::engine::{DealEngine, Status};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DealInitControl {
    shared_config_hash: [u8; 32],
    session_nonce: [u8; 32],
    game_id: [u8; 32],
    identity_keys: [[u8; 32]; 2],
}

/// Validated public control plus separately staged secret material.
pub(crate) struct DealInit {
    pub(crate) shared_config_hash: [u8; 32],
    pub(crate) session_nonce: [u8; 32],
    pub(crate) game_id: [u8; 32],
    pub(crate) local_secret: Zeroizing<[u8; 32]>,
    pub(crate) identity_keys: [[u8; 32]; 2],
    pub(crate) supplied_entropy: Zeroizing<[u8; 32]>,
}

impl DealInit {
    pub(crate) fn decode(
        control_json: &[u8],
        local_secret: [u8; 32],
        supplied_entropy: [u8; 32],
    ) -> Result<Self, String> {
        // Own staged secrets before parsing so every error path zeroizes them.
        let local_secret = Zeroizing::new(local_secret);
        let supplied_entropy = Zeroizing::new(supplied_entropy);
        let control: DealInitControl = serde_json::from_slice(control_json)
            .map_err(|error| format!("invalid DEAL initialization control: {error}"))?;
        if control.shared_config_hash == [0; 32]
            || control.session_nonce == [0; 32]
            || control.game_id == [0; 32]
        {
            return Err("DEAL verification bindings must be nonzero".to_owned());
        }
        if supplied_entropy.iter().all(|byte| *byte == 0) {
            return Err("DEAL worker entropy must be nonzero".to_owned());
        }
        Ok(Self {
            shared_config_hash: control.shared_config_hash,
            session_nonce: control.session_nonce,
            game_id: control.game_id,
            local_secret,
            identity_keys: control.identity_keys,
            supplied_entropy,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DealSnapshot {
    status: Status,
    local_role: u8,
    attempt: u32,
    next_sequence: u32,
    has_retained_preimages: bool,
}

pub(crate) fn snapshot_json(engine: &DealEngine) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&DealSnapshot {
        status: engine.status(),
        local_role: engine.local_role.to_u8(),
        attempt: engine.attempt_number(),
        next_sequence: engine.next_sequence(),
        has_retained_preimages: engine.retained_preimages.is_some(),
    })
    .map_err(|error| format!("could not serialize DEAL snapshot: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "sharedConfigHash": vec![1; 32],
            "sessionNonce": vec![2; 32],
            "gameId": vec![3; 32],
            "identityKeys": [vec![4; 32], vec![5; 32]],
        }))
        .unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn init_control_has_one_strict_serde_shape() {
        assert!(DealInit::decode(&control_json(), [6; 32], [7; 32]).is_ok());

        let mut extra: serde_json::Value =
            serde_json::from_slice(&control_json()).unwrap_or_else(|_| unreachable!());
        extra["obsolete"] = serde_json::Value::Bool(true);
        let extra = serde_json::to_vec(&extra).unwrap_or_else(|_| unreachable!());
        assert!(DealInit::decode(&extra, [6; 32], [7; 32]).is_err());

        let mut short: serde_json::Value =
            serde_json::from_slice(&control_json()).unwrap_or_else(|_| unreachable!());
        short["identityKeys"][0] = serde_json::json!(vec![4; 31]);
        let short = serde_json::to_vec(&short).unwrap_or_else(|_| unreachable!());
        assert!(DealInit::decode(&short, [6; 32], [7; 32]).is_err());
    }

    #[test]
    fn init_rejects_missing_entropy_and_public_bindings() {
        assert!(DealInit::decode(&control_json(), [6; 32], [0; 32]).is_err());

        let mut zero: serde_json::Value =
            serde_json::from_slice(&control_json()).unwrap_or_else(|_| unreachable!());
        zero["gameId"] = serde_json::json!(vec![0; 32]);
        let zero = serde_json::to_vec(&zero).unwrap_or_else(|_| unreachable!());
        assert!(DealInit::decode(&zero, [6; 32], [7; 32]).is_err());
    }
}
