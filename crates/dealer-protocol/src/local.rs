//! Private capabilities for copying a verified public result between local workers.
use crate::{ProtocolError, VerifiedAcceptedDeal, certificate::{decode_accepted, decode_config}};
use dealer_codec::{Encode, Reader};
use dealer_group::{N_SLOTS, RAW_SUM_CANDIDATES, decode_point, encode_point};
use dealer_uniqueness::VerifiedCatalogue;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const DOMAIN: &[u8] = b"POKER/local-accepted-dealer/v1";

impl VerifiedAcceptedDeal {
    /// Copy an already verified result under a private, locally delegated key.
    /// Neither this key nor its capability may be supplied by a remote peer.
    /// This avoids replaying the same proofs in each local construction worker.
    pub fn seal_local(&self, key: &[u8; 32]) -> Vec<u8> {
        let mut out=self.game_config.to_bytes();
        self.deal.body.encode(&mut out);
        out.extend(self.deal.signature_a);out.extend(self.deal.signature_b);
        for row in &self.catalogue.keys { for point in row {encode_point(point,&mut out);} }
        let mut mac=Hmac::<Sha256>::new_from_slice(key).expect("fixed HMAC key size");
        mac.update(DOMAIN);mac.update(&out);
        out.extend(mac.finalize().into_bytes());out
    }

    /// Open only a capability from this player's trusted local worker boundary.
    /// Peer certificates must use `verify_setup_certificate` instead.
    ///
    /// # Errors
    /// Rejects a wrong key, tampering, truncation, or noncanonical points.
    pub fn open_local(key: &[u8; 32], bytes: &[u8]) -> Result<Self,ProtocolError> {
        if bytes.len()<32 || bytes.len()>64*1024 {return Err(ProtocolError::Wire);}
        let (body,tag)=bytes.split_at(bytes.len()-32);
        let mut mac=Hmac::<Sha256>::new_from_slice(key).map_err(|_|ProtocolError::Wire)?;
        mac.update(DOMAIN);mac.update(body);mac.verify_slice(tag).map_err(|_|ProtocolError::Wire)?;
        let mut reader=Reader::new(body);
        let game_config=decode_config(&mut reader)?;let deal=decode_accepted(&mut reader)?;
        let mut rows=Vec::with_capacity(N_SLOTS);
        for _ in 0..N_SLOTS {
            let mut row=Vec::with_capacity(RAW_SUM_CANDIDATES);
            for _ in 0..RAW_SUM_CANDIDATES {row.push(decode_point(&mut reader,false).map_err(|_|ProtocolError::Wire)?);}
            rows.push(row.try_into().map_err(|_|ProtocolError::Wire)?);
        }
        reader.finish().map_err(|_|ProtocolError::Wire)?;
        let catalogue=VerifiedCatalogue {keys:rows.try_into().map_err(|_|ProtocolError::Wire)?,hash:deal.body.catalogue_hash};
        Ok(Self{deal,catalogue,game_config})
    }
}
