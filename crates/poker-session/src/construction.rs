//! Local worker delegation for deterministic graph construction. These receipts
//! are private capabilities, never peer assertions about a transaction graph.
use super::*;
use hmac::{Hmac, Mac};

#[derive(Serialize, Deserialize)]
struct ConstructionJob {
    terms: Terms,
    profile: Option<channel_hand::ChannelMaterialization>,
    scores: [Vec<u8>;2],
    #[serde(skip)]
    dealer: Vec<u8>,
    dealer_key: [u8;32],
    receipt_key: [u8;32],
    binding: [u8;32],
}

impl ConstructionJob {
    fn encode(mut self) -> Result<Vec<u8>> {
        let commitments=self.profile.as_mut().map(|p|std::mem::take(&mut p.commitments)).unwrap_or_default();
        let header=serde_json::to_vec(&self)?;
        let mut out=u32::try_from(header.len())?.to_le_bytes().to_vec();out.extend(header);
        out.extend(u32::try_from(commitments.len())?.to_le_bytes());
        for hash in commitments {out.extend(hash);}
        out.extend(self.dealer);
        let mut mac=Hmac::<Sha256>::new_from_slice(&self.receipt_key)?;
        mac.update(b"POKER/local-construction-job/v1");mac.update(&out);
        out.extend(mac.finalize().into_bytes());Ok(out)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len()<36 || bytes.len()>4_000_000 {return Err("invalid construction job size".into());}
        let (bytes,tag)=bytes.split_at(bytes.len()-32);
        let length=u32::from_le_bytes(bytes.get(..4).ok_or("truncated job")?.try_into()?) as usize;
        if length>64*1024 {return Err("construction header too large".into());}
        let mut job:Self=serde_json::from_slice(bytes.get(4..4+length).ok_or("truncated header")?)?;
        let mut mac=Hmac::<Sha256>::new_from_slice(&job.receipt_key)?;
        mac.update(b"POKER/local-construction-job/v1");mac.update(bytes);mac.verify_slice(tag)?;
        let start=4+length;
        let count=u32::from_le_bytes(bytes.get(start..start+4).ok_or("truncated count")?.try_into()?) as usize;
        if count>100_000 {return Err("too many construction commitments".into());}
        let end=start+4+count*32;
        let hashes=bytes.get(start+4..end).ok_or("truncated commitments")?;
        if let Some(profile)=&mut job.profile {
            if !profile.commitments.is_empty() {return Err("duplicate commitments".into());}
            profile.commitments=hashes.chunks_exact(32).map(|h|h.try_into().map_err(Into::into)).collect::<Result<_>>()?;
        } else if count!=0 {return Err("unexpected commitments".into());}
        job.dealer=bytes.get(end..).ok_or("truncated dealer")?.to_vec();Ok(job)
    }
}

impl Session {
    /// Private job for a local worker. Contains no dealer or identity secrets.
    pub fn construction_job(&self) -> Result<Vec<u8>> {
        if self.preparation.is_some() || self.ready.is_some() {return Err("already preparing".into());}
        let scores=self.scores.as_ref().ok_or("score keys missing")?;
        let dealer_key=derive(&self.seed,b"local-accepted-dealer");
        ConstructionJob {
            terms:self.terms.clone(),profile:self.channel_materialization.clone(),
            scores:[scores[0].encode(),scores[1].encode()],
            dealer:self.dealer.accepted()?.seal_local(&dealer_key),dealer_key,
            receipt_key:derive(&self.seed,b"construction"),
            binding:Sha256::digest(self.checkpoint_journal()?.as_slice()).into(),
        }.encode()
    }

    /// Construct a delegated inventory; the parent authenticates the exact context.
    pub fn construct_local(bytes: &[u8]) -> Result<Vec<u8>> {
        let job=ConstructionJob::decode(bytes)?;
        let deal=dealer_protocol::VerifiedAcceptedDeal::open_local(&job.dealer_key,&job.dealer)?;
        let mut graph=SettlementGraph::compile(&deal,job.terms.parameters()?,&job.terms.fees()?,
            [LamportPublicKey::decode(&job.scores[0])?,LamportPublicKey::decode(&job.scores[1])?])?;
        if let Some(p)=job.profile {
            let owner=match p.owner {0=>Role::Alice,1=>Role::Bob,_=>return Err("invalid owner".into())};
            graph=graph.with_channel_protection(owner,p.contest_blocks,p.hand_commitment,&p.commitments)?;
        }
        let activation=graph.activation(job.terms.origin_output()?,job.terms.scaled_fee(500))?;
        let inventory=SettlementPreparation::new(&graph,activation)?.encode_inventory()?;
        let mut inventory=construction_payload(&inventory,graph.payout_projection().ok_or("missing payout projection")?)?;
        let mut mac=Hmac::<Sha256>::new_from_slice(&job.receipt_key)?;
        mac.update(b"POKER/local-construction/v1");mac.update(&job.binding);mac.update(&inventory);
        inventory.extend(mac.finalize().into_bytes());Ok(inventory)
    }
    fn construction_mac(&self, inventory: &[u8]) -> Result<Hmac<Sha256>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&derive(&self.seed, b"construction"))?;
        mac.update(b"POKER/local-construction/v1");
        // Bind the exact terms, owner, public retirement commitments, accepted
        // dealer transcript and score keys of the delegated session snapshot.
        mac.update(&Sha256::digest(self.checkpoint_journal()?.as_slice()));
        mac.update(inventory);
        Ok(mac)
    }

    pub fn construction_receipt(&self) -> Result<Vec<u8>> {
        let mut inventory = construction_payload(&self.inventory()?,self.graph()?.payout_projection().ok_or("missing payout projection")?)?;
        let tag = self.construction_mac(&inventory)?.finalize().into_bytes();
        inventory.extend_from_slice(&tag);
        Ok(inventory)
    }

    pub fn accept_construction(&mut self, receipt: &[u8]) -> Result<()> {
        if self.preparation.is_some() || self.ready.is_some() || receipt.len() < 32
            || receipt.len() > 32_000_000 {
            return Err("invalid construction receipt".into());
        }
        let (inventory, tag) = receipt.split_at(receipt.len() - 32);
        self.construction_mac(inventory)?.verify_slice(tag)?;
        let size=u32::from_le_bytes(inventory.get(..4).ok_or("truncated construction receipt")?.try_into()?) as usize;
        let preparation=SettlementPreparation::from_inventory(inventory.get(4..4+size).ok_or("truncated construction inventory")?,self.terms.network())?;
        self.payout_projection=Some(inventory.get(4+size..).ok_or("missing payout projection")?.to_vec());
        self.preparation = Some(preparation);
        Ok(())
    }
}

fn construction_payload(inventory: &[u8], payouts: &[u8]) -> Result<Vec<u8>> {
    let mut bytes=u32::try_from(inventory.len())?.to_le_bytes().to_vec();
    bytes.extend(inventory);bytes.extend(payouts);Ok(bytes)
}
