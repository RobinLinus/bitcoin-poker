#![forbid(unsafe_code)]
#![doc = "Bitcoin-visible share/card opening predicates for BP52-DEAL-v1."]

/// Native Rust opening predicates.
pub mod opening;
/// Selective hole-card, community-card, and showdown reveals.
pub mod reveal;
/// Taproot/script integration.
pub mod scripts;

pub use opening::{
    BASE_PREIMAGE_LENGTH, DECK_SIZE, MAX_PREIMAGE_LENGTH, OpeningError, verify_card_opening,
    verify_share_opening,
};
pub use reveal::{
    ALICE_HOLE_SLOTS, BOB_HOLE_SLOTS, CommunityStage, FLOP_SLOTS, RIVER_SLOT, RevealError,
    TURN_SLOT, VerifiedCard, verify_community_reveal, verify_hole_card_delivery,
    verify_showdown_reveal,
};
pub use scripts::{
    CardOpeningTemplate, MAX_SCRIPT_ELEMENT_SIZE, SCRIPT_PATH_NUMS_KEY, ScriptTemplateError,
    card_opening_tapscript,
};
