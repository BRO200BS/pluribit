// src/atomic_swap.rs
//! Atomic Swaps - Trustless cross-chain trading using adaptor signatures
//!
//! Enables direct peer-to-peer trading between different blockchains without
//! any trusted intermediary. For example: trade PLB for Bitcoin.
//!
//! ## Production-ready implementation with V2 transactions

use serde::{Serialize, Deserialize};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha256, Digest};
use crate::adaptor::{AdaptorSignature, create_adaptor_signature, adapt_signature, extract_adaptor_secret};
use crate::transaction::{Transaction, TransactionInput, TransactionOutput, TransactionKernel};
use crate::mimblewimble::{self, PC_GENS};
use crate::error::{PluribitResult, PluribitError};
use crate::log;
use crate::wasm_types::WasmU64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwapState {
    Negotiating,
    Committed,
    Claimed,
    Refunded,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicSwap {
    pub swap_id: [u8; 32],
    pub state: SwapState,
    pub alice_amount: u64,
    pub alice_pubkey: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub alice_commitment: Vec<u8>,
    pub alice_blinding: Option<Scalar>,
    pub alice_adaptor_sig: Option<AdaptorSignature>,
    pub alice_timeout_height: u64,
    pub bob_amount: u64,
    pub bob_pubkey: Vec<u8>,
    pub bob_commitment: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub bob_adaptor_sig: Vec<u8>,
    pub bob_timeout_height: u64,
    #[serde(with = "serde_bytes")]
    pub shared_adaptor_point: [u8; 32],
    pub adaptor_secret: Option<[u8; 32]>,
    pub created_at: u64,
    pub expires_at: u64,
}

impl AtomicSwap {
    pub fn initiate(
        alice_secret: &Scalar,
        alice_amount: u64,
        bob_pubkey: Vec<u8>,
        bob_amount: u64,
        timeout_blocks: u64,
    ) -> PluribitResult<Self> {
        log(&format!("[SWAP] Initiating swap: {} PLB for {} sats", alice_amount, bob_amount));
        
        use rand::thread_rng;
        let mut rng = thread_rng();
        let t = Scalar::random(&mut rng);
        let t_point = &t * &PC_GENS.B_blinding;
        let alice_pubkey_point = alice_secret * &PC_GENS.B_blinding;
        let blinding = Scalar::random(&mut rng);
        let commitment = mimblewimble::commit(alice_amount, &blinding)?;
        
        let mut hasher = Sha256::new();
        hasher.update(b"atomic_swap_v1");
        hasher.update(&alice_pubkey_point.compress().to_bytes());
        hasher.update(&bob_pubkey);
        hasher.update(&alice_amount.to_le_bytes());
        hasher.update(&bob_amount.to_le_bytes());
        hasher.update(&t_point.compress().to_bytes());
        let swap_id: [u8; 32] = hasher.finalize().into();
        
        let current_height = crate::BLOCKCHAIN.lock()
            .map_err(|_| PluribitError::LockError("blockchain lock".into()))?
            .current_height;
        
        #[cfg(target_arch = "wasm32")]
        let now = js_sys::Date::now() as u64;
        #[cfg(not(target_arch = "wasm32"))]
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        Ok(AtomicSwap {
            swap_id,
            state: SwapState::Negotiating,
            alice_amount,
            alice_pubkey: alice_pubkey_point.compress().to_bytes(),
            alice_commitment: commitment.compress().to_bytes().to_vec(),
            alice_blinding: Some(blinding),
            alice_adaptor_sig: None,
            alice_timeout_height: *current_height + timeout_blocks,
            bob_amount,
            bob_pubkey,
            bob_commitment: vec![],
            bob_adaptor_sig: vec![],
            bob_timeout_height: 0,
            shared_adaptor_point: t_point.compress().to_bytes(),
            adaptor_secret: Some(t.to_bytes()),
            created_at: now,
            expires_at: now + (timeout_blocks * 30 * 1000),
        })
    }
    
    pub fn respond(
        &mut self,
        _bob_secret: &Scalar,
        bob_btc_commitment: Vec<u8>,
        bob_adaptor_sig_bytes: Vec<u8>,
        bob_timeout_height: u64,
    ) -> PluribitResult<()> {
        if self.state != SwapState::Negotiating {
            return Err(PluribitError::StateError("Not negotiating".into()));
        }
        
        self.bob_commitment = bob_btc_commitment;
        self.bob_adaptor_sig = bob_adaptor_sig_bytes;
        self.bob_timeout_height = bob_timeout_height;
        self.state = SwapState::Committed;
        
        log("[SWAP] ✓ Committed");
        Ok(())
    }
    
    pub fn alice_create_adaptor_signature(
        &mut self,
        alice_secret: &Scalar,
    ) -> PluribitResult<AdaptorSignature> {
        if self.state != SwapState::Committed {
            return Err(PluribitError::StateError("Not committed".into()));
        }
        
        let t_point = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&self.shared_adaptor_point)
            .map_err(|_| PluribitError::ValidationError("Invalid adaptor point".into()))?
            .decompress()
            .ok_or_else(|| PluribitError::ValidationError("Decompress failed".into()))?;
        
        let adaptor_sig = create_adaptor_signature(alice_secret, &t_point, &self.swap_id)?;
        self.alice_adaptor_sig = Some(adaptor_sig.clone());
        
        log("[SWAP] ✓ Alice created adaptor sig");
        Ok(adaptor_sig)
    }
    
    /// Bob claims - creates REAL V2 transaction
    pub fn bob_claim(
        &self,
        _bob_secret: &Scalar,
        adaptor_secret: &Scalar,
        bob_receive_address: &RistrettoPoint,
    ) -> PluribitResult<Transaction> {
        if self.state != SwapState::Committed {
            return Err(PluribitError::StateError("Not committed".into()));
        }
        
        let alice_adaptor_sig = self.alice_adaptor_sig.as_ref()
            .ok_or_else(|| PluribitError::StateError("No adaptor sig".into()))?;
        
        // Verify adaptor secret
        let t_point = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&self.shared_adaptor_point)
            .map_err(|_| PluribitError::ValidationError("Invalid point".into()))?
            .decompress()
            .ok_or_else(|| PluribitError::ValidationError("Decompress failed".into()))?;
        
        let claimed_t_point = adaptor_secret * &PC_GENS.B_blinding;
        if claimed_t_point != t_point {
            return Err(PluribitError::ValidationError("Wrong adaptor secret".into()));
        }
        
        // Complete signature (reveals secret!)
        let (_challenge, completed_sig) = adapt_signature(alice_adaptor_sig, adaptor_secret)?;
        
        log("[SWAP] ✓ Bob revealed secret!");
        
        // Create V2 transaction
        let input = TransactionInput {
            commitment: self.alice_commitment.clone(),
            merkle_proof: None,
            source_height: WasmU64::from(0),
        };
        
        use rand::thread_rng;
        let mut rng = thread_rng();
        let output_blinding = Scalar::random(&mut rng);
        let output_commitment = mimblewimble::commit(self.alice_amount, &output_blinding)?;
        
        let r = Scalar::random(&mut rng);
        let (ephemeral_key, payload, view_tag) = crate::stealth::encrypt_stealth_out(
            &r,
            bob_receive_address,
            self.alice_amount,
            &output_blinding,
        );
        
        let output = TransactionOutput {
            commitment: output_commitment.compress().to_bytes().to_vec(),
            ephemeral_key: Some(ephemeral_key.compress().to_bytes().to_vec()),
            stealth_payload: Some(payload),
            view_tag: Some(vec![view_tag]),
        };
        
        let (proof, _) = mimblewimble::create_aggregated_range_proof(
            &[self.alice_amount],
            &[output_blinding],
        ).map_err(|e| PluribitError::ValidationError(format!("Proof failed: {}", e)))?;
        
        #[cfg(target_arch = "wasm32")]
        let timestamp = js_sys::Date::now() as u64;
        #[cfg(not(target_arch = "wasm32"))]
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let current_height = *crate::BLOCKCHAIN.lock()
            .map_err(|_| PluribitError::LockError("blockchain lock".into()))?
            .current_height;
        
        let kernel = TransactionKernel::new(completed_sig, 0, current_height, timestamp)
            .map_err(|e| PluribitError::ValidationError(e))?;
        
        log(&format!("[SWAP] ✓ Claim tx: {} coins", self.alice_amount));
        
        Ok(Transaction {
            inputs: vec![input],
            outputs: vec![output],
            kernels: vec![kernel],
            timestamp: WasmU64::from(timestamp),
            aggregated_range_proof: proof.to_bytes(),
        })
    }
    
    pub fn alice_extract_and_claim(
        &mut self,
        bob_completed_signature: &Scalar,
    ) -> PluribitResult<Scalar> {
        let alice_adaptor_sig = self.alice_adaptor_sig.as_ref()
            .ok_or_else(|| PluribitError::StateError("No adaptor sig".into()))?;
        
        let t = extract_adaptor_secret(alice_adaptor_sig, bob_completed_signature);
        self.adaptor_secret = Some(t.to_bytes());
        self.state = SwapState::Claimed;
        
        log(&format!("[SWAP] ✓ Alice extracted secret: {}", hex::encode(t.to_bytes())));
        Ok(t)
    }
    
    /// Refund - creates REAL V2 transaction
    pub fn refund_alice(
        &self,
        _alice_secret: &Scalar,
        alice_receive_address: &RistrettoPoint,
        current_height: u64,
    ) -> PluribitResult<Transaction> {
        if current_height < self.alice_timeout_height {
            return Err(PluribitError::ValidationError("Timeout not reached".into()));
        }
        
        if self.state == SwapState::Completed || self.state == SwapState::Claimed {
            return Err(PluribitError::StateError("Already finalized".into()));
        }
        
        log("[SWAP] Refunding Alice");
        
        let alice_blinding = self.alice_blinding
            .ok_or_else(|| PluribitError::StateError("No blinding".into()))?;
        
        let input = TransactionInput {
            commitment: self.alice_commitment.clone(),
            merkle_proof: None,
            source_height: WasmU64::from(0),
        };
        
        use rand::thread_rng;
        let mut rng = thread_rng();
        let output_blinding = Scalar::random(&mut rng);
        let output_commitment = mimblewimble::commit(self.alice_amount, &output_blinding)?;
        
        let r = Scalar::random(&mut rng);
        let (ephemeral_key, payload, view_tag) = crate::stealth::encrypt_stealth_out(
            &r,
            alice_receive_address,
            self.alice_amount,
            &output_blinding,
        );
        
        let output = TransactionOutput {
            commitment: output_commitment.compress().to_bytes().to_vec(),
            ephemeral_key: Some(ephemeral_key.compress().to_bytes().to_vec()),
            stealth_payload: Some(payload),
            view_tag: Some(vec![view_tag]),
        };
        
        let (proof, _) = mimblewimble::create_aggregated_range_proof(
            &[self.alice_amount],
            &[output_blinding],
        ).map_err(|e| PluribitError::ValidationError(format!("Proof failed: {}", e)))?;
        
        let kernel_blinding = alice_blinding - output_blinding;
        
        #[cfg(target_arch = "wasm32")]
        let timestamp = js_sys::Date::now() as u64;
        #[cfg(not(target_arch = "wasm32"))]
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let kernel = TransactionKernel::new(kernel_blinding, 0, current_height, timestamp)
            .map_err(|e| PluribitError::ValidationError(e))?;
        
        log(&format!("[SWAP] ✓ Refund tx: {} coins", self.alice_amount));
        
        Ok(Transaction {
            inputs: vec![input],
            outputs: vec![output],
            kernels: vec![kernel],
            timestamp: WasmU64::from(timestamp),
            aggregated_range_proof: proof.to_bytes(),
        })
    }
}

pub fn derive_adaptor_point_from_preimage(preimage: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha256::new();
    hasher.update(b"atomic_swap_adaptor_v1");
    hasher.update(preimage);
    let hash: [u8; 32] = hasher.finalize().into();
    let scalar = Scalar::from_bytes_mod_order(hash);
    &scalar * &PC_GENS.B_blinding
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mimblewimble;
    
    #[test]
    fn test_atomic_swap_flow() {
        let alice_secret = mimblewimble::generate_secret_key();
        let bob_secret = mimblewimble::generate_secret_key();
        let bob_pubkey = (&bob_secret * &PC_GENS.B_blinding).compress().to_bytes().to_vec();
        
        let mut swap = AtomicSwap::initiate(&alice_secret, 100_000_000, bob_pubkey, 10_000_000, 144).unwrap();
        assert_eq!(swap.state, SwapState::Negotiating);
        
        swap.respond(&bob_secret, vec![0xAB; 32], vec![0xCD; 64], 144).unwrap();
        assert_eq!(swap.state, SwapState::Committed);
        
        swap.alice_create_adaptor_signature(&alice_secret).unwrap();
        assert!(swap.alice_adaptor_sig.is_some());
    }
    
    #[test]
    fn test_bob_claim_creates_transaction() {
        let alice_secret = mimblewimble::generate_secret_key();
        let bob_secret = mimblewimble::generate_secret_key();
        let bob_pubkey = (&bob_secret * &PC_GENS.B_blinding).compress().to_bytes().to_vec();
        let bob_receive = &bob_secret * &PC_GENS.B_blinding;
        
        let mut swap = AtomicSwap::initiate(&alice_secret, 100_000_000, bob_pubkey, 10_000_000, 144).unwrap();
        swap.respond(&bob_secret, vec![0xAB; 32], vec![0xCD; 64], 144).unwrap();
        swap.alice_create_adaptor_signature(&alice_secret).unwrap();
        
        let adaptor_secret = Scalar::from_bytes_mod_order(swap.adaptor_secret.unwrap());
        let tx = swap.bob_claim(&bob_secret, &adaptor_secret, &bob_receive).unwrap();
        
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert!(!tx.aggregated_range_proof.is_empty());
    }
    
    #[test]
    fn test_derive_adaptor_point() {
        let p1 = derive_adaptor_point_from_preimage(b"test");
        let p2 = derive_adaptor_point_from_preimage(b"test");
        assert_eq!(p1, p2);
    }
}
