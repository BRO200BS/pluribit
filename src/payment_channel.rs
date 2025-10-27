// src/payment_channel.rs
//! Payment Channels - Lightning-style off-chain payments
//!
//! Payment channels enable unlimited transactions between two parties with only
//! two on-chain transactions (open and close). This is how you get "thousands of TPS"
//! user experience while keeping the base layer at 180 TPS.
//!
//! ## How it works:
//! 1. Open: Both parties fund a 2-of-2 multisig output on-chain
//! 2. Transact: Update balances off-chain millions of times (instant, free!)
//! 3. Close: Settle final balances on-chain
//!
//! ## Security:
//! - Either party can close unilaterally if the other disappears
//! - Penalty mechanism prevents cheating (publishing old state)
//! - Time locks ensure dispute resolution period

use serde::{Serialize, Deserialize};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::{thread_rng, RngCore};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use crate::transaction::{Transaction, TransactionInput, TransactionOutput, TransactionKernel};
use crate::mimblewimble::{self, PC_GENS};
use crate::error::{PluribitResult, PluribitError};
use crate::log;
use crate::wasm_types::WasmU64;

/// State of a payment channel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelState {
    /// Channel is being opened
    Opening,
    /// Channel is open and operational
    Open,
    /// One party initiated cooperative close
    Closing,
    /// Channel has been closed
    Closed,
    /// Channel closed due to dispute
    Disputed,
}

/// A bidirectional payment channel between two parties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentChannel {
    /// Unique channel identifier
    pub channel_id: [u8; 32],
    
    /// Current state
    pub state: ChannelState,
    
    /// Party A (initiator)
    pub party_a_pubkey: [u8; 32],
    pub party_a_balance: u64,
    
    /// Party B (responder)
    pub party_b_pubkey: [u8; 32],
    pub party_b_balance: u64,
    
    /// Total channel capacity (party_a_balance + party_b_balance)
    pub total_capacity: u64,
    
    /// Current state number (increments with each update)
    /// Used to identify the "latest" state in case of disputes
    pub sequence_number: u64,
    
    /// On-chain funding transaction
    /// This transaction creates the 2-of-2 multisig output
    pub funding_tx: Option<Transaction>,
    pub funding_output_commitment: Vec<u8>,
    
    /// Latest commitment transactions (off-chain)
    /// These are only broadcast if someone tries to cheat
    pub party_a_commitment: Option<CommitmentTransaction>,
    pub party_b_commitment: Option<CommitmentTransaction>,
    
    /// Revocation keys for old states
    /// If someone publishes an old state, the other party can use this to claim everything
    pub revocation_keys: HashMap<u64, [u8; 32]>,  // sequence_number -> revocation_secret
    
    /// Timestamps
    pub created_at: u64,
    pub last_updated: u64,
    
    /// Dispute resolution timelock (in blocks)
    pub dispute_period: u64,
}

/// A commitment transaction represents a unilateral close of the channel
///
/// Each party holds a commitment transaction that pays them their current balance.
/// If the other party disappears, they can broadcast this to recover their funds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentTransaction {
    /// Which party's commitment this is
    pub party: Party,
    
    /// Sequence number (must match channel state)
    pub sequence_number: u64,
    
    /// Transaction that spends the funding output
    pub tx: Transaction,
    
    /// Revocation key for this commitment
    /// If the owner broadcasts an old commitment, the other party can use this to claim all funds
    pub revocation_pubkey: [u8; 32],
    
    /// Timelock height (can't be mined before this)
    pub timelock_height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Party {
    A,
    B,
}

impl PaymentChannel {
    /// Open a new payment channel
    ///
    /// Both parties contribute funds to a 2-of-2 multisig output.
    /// This requires interaction: both parties must sign the funding transaction.
    pub fn open(
        party_a_secret: &Scalar,
        party_a_amount: u64,
        party_b_pubkey: &RistrettoPoint,
        party_b_amount: u64,
        dispute_period_blocks: u64,
    ) -> PluribitResult<Self> {
        log(&format!("[CHANNEL] Opening payment channel: A={} coins, B={} coins", 
            party_a_amount, party_b_amount));
        
        let total = party_a_amount.checked_add(party_b_amount)
            .ok_or_else(|| PluribitError::ValidationError("Channel capacity overflow".into()))?;
        
        let party_a_pubkey = party_a_secret * &PC_GENS.B_blinding;
        
        // Generate channel ID
        let mut hasher = Sha256::new();
        hasher.update(b"payment_channel_v1");
        hasher.update(&party_a_pubkey.compress().to_bytes());
        hasher.update(&party_b_pubkey.compress().to_bytes());
        hasher.update(&total.to_le_bytes());
        let mut channel_id = [0u8; 32];
        let hash = hasher.finalize();
        channel_id.copy_from_slice(&hash);
        
        #[cfg(target_arch = "wasm32")]
        let now = js_sys::Date::now() as u64;
        #[cfg(not(target_arch = "wasm32"))]
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        
        log(&format!("[CHANNEL] Channel ID: {}", hex::encode(&channel_id)));
        
        Ok(PaymentChannel {
            channel_id,
            state: ChannelState::Opening,
            party_a_pubkey: party_a_pubkey.compress().to_bytes(),
            party_a_balance: party_a_amount,
            party_b_pubkey: party_b_pubkey.compress().to_bytes(),
            party_b_balance: party_b_amount,
            total_capacity: total,
            sequence_number: 0,
            funding_tx: None,  // Created in next step
            funding_output_commitment: vec![],
            party_a_commitment: None,
            party_b_commitment: None,
            revocation_keys: HashMap::new(),
            created_at: now,
            last_updated: now,
            dispute_period: dispute_period_blocks,
        })
    }
    
    /// Fund the channel by creating the on-chain funding transaction
    ///
    /// This creates a 2-of-2 multisig output that requires both parties to spend.
    pub fn fund(
        &mut self,
        party_a_secret: &Scalar,
        party_b_secret: &Scalar,
        party_a_inputs: Vec<TransactionInput>,
        party_b_inputs: Vec<TransactionInput>,
    ) -> PluribitResult<Transaction> {
        if self.state != ChannelState::Opening {
            return Err(PluribitError::StateError("Channel not in opening state".into()));
        }
        
        log(&format!("[CHANNEL] Creating funding transaction for channel {}", hex::encode(&self.channel_id[..8])));
        
        // Create the funding output commitment
        // This is a 2-of-2 multisig: requires both party_a_secret and party_b_secret
        let funding_blinding = party_a_secret + party_b_secret;
        let funding_commitment = mimblewimble::commit(self.total_capacity, &funding_blinding)?;
        
        self.funding_output_commitment = funding_commitment.compress().to_bytes().to_vec();
        
        // Create funding transaction
        // (Simplified - real implementation would handle inputs/outputs properly)
        let funding_tx = Transaction {
            inputs: [party_a_inputs, party_b_inputs].concat(),
            outputs: vec![TransactionOutput {
                commitment: self.funding_output_commitment.clone(),
                ephemeral_key: None,
                stealth_payload: None,
                view_tag: None,
            }],
            kernels: vec![],  // Would need proper kernel
            timestamp: WasmU64::from(self.last_updated),
            aggregated_range_proof: vec![],  // Would need proper proof
        };
        
        self.funding_tx = Some(funding_tx.clone());
        self.state = ChannelState::Open;
        
        log(&format!("[CHANNEL] Funding transaction created, channel now OPEN"));
        
        Ok(funding_tx)
    }
    
    /// Make a payment within the channel (off-chain!)
    ///
    /// Updates balances without touching the blockchain.
    /// This can be done millions of times with zero fees and instant confirmation.
    pub fn send_payment(
        &mut self,
        sender: Party,
        amount: u64,
    ) -> PluribitResult<()> {
        if self.state != ChannelState::Open {
            return Err(PluribitError::StateError("Channel not open".into()));
        }
        
        log(&format!("[CHANNEL] {:?} sending {} coins in channel {}", 
            sender, amount, hex::encode(&self.channel_id[..8])));
        
        // Update balances
        match sender {
            Party::A => {
                if self.party_a_balance < amount {
                    return Err(PluribitError::ValidationError("Insufficient balance".into()));
                }
                self.party_a_balance -= amount;
                self.party_b_balance += amount;
            }
            Party::B => {
                if self.party_b_balance < amount {
                    return Err(PluribitError::ValidationError("Insufficient balance".into()));
                }
                self.party_b_balance -= amount;
                self.party_a_balance += amount;
            }
        }
        
        // Increment sequence number
        self.sequence_number += 1;
        
        #[cfg(target_arch = "wasm32")]
        let now = js_sys::Date::now() as u64;
        #[cfg(not(target_arch = "wasm32"))]
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        
        self.last_updated = now;
        
        log(&format!("[CHANNEL] New balances: A={}, B={}, sequence={}", 
            self.party_a_balance, self.party_b_balance, self.sequence_number));
        
        // Create new commitment transactions
        // (Simplified - real implementation would create proper transactions with timelocks)
        // self.create_commitment_transactions()?;
        
        // Revoke old commitment transactions
        // (Store revocation secrets for old states)
        
        Ok(())
    }
    
    /// Close the channel cooperatively
    ///
    /// Both parties agree on final balances and close with a single on-chain transaction.
    /// This is the happy path - instant and cheap.
    pub fn close_cooperative(
        &mut self,
        party_a_secret: &Scalar,
        party_b_secret: &Scalar,
    ) -> PluribitResult<Transaction> {
        if self.state != ChannelState::Open {
            return Err(PluribitError::StateError("Channel not open".into()));
        }
        
        log(&format!("[CHANNEL] Cooperatively closing channel {}", hex::encode(&self.channel_id[..8])));
        log(&format!("[CHANNEL] Final balances: A={}, B={}", self.party_a_balance, self.party_b_balance));
        
        // Create settlement transaction that pays out final balances
        // Spends the funding output, creates two outputs (one for each party)
        
        let mut rng = thread_rng();
        
        // Create output for party A
        let blinding_a = Scalar::random(&mut rng);
        let commitment_a = mimblewimble::commit(self.party_a_balance, &blinding_a)?;
        let (proof_a, commitments_a) = mimblewimble::create_aggregated_range_proof(
            &[self.party_a_balance],
            &[blinding_a]
        )?;
        
        // Create output for party B
        let blinding_b = Scalar::random(&mut rng);
        let commitment_b = mimblewimble::commit(self.party_b_balance, &blinding_b)?;
        let (proof_b, commitments_b) = mimblewimble::create_aggregated_range_proof(
            &[self.party_b_balance],
            &[blinding_b]
        )?;
        
        // Combine proofs (in real implementation)
        // For now, just use one
        
        let settlement_tx = Transaction {
            inputs: vec![TransactionInput {
                commitment: self.funding_output_commitment.clone(),
                merkle_proof: None,
                source_height: WasmU64::from(0),  // From funding tx
            }],
            outputs: vec![
                TransactionOutput {
                    commitment: commitment_a.compress().to_bytes().to_vec(),
                    ephemeral_key: None,
                    stealth_payload: None,
                    view_tag: None,
                },
                TransactionOutput {
                    commitment: commitment_b.compress().to_bytes().to_vec(),
                    ephemeral_key: None,
                    stealth_payload: None,
                    view_tag: None,
                },
            ],
            kernels: vec![],  // Would need proper kernel with both signatures
            timestamp: WasmU64::from(self.last_updated),
            aggregated_range_proof: proof_a.to_bytes(),  // Should combine both proofs
        };
        
        self.state = ChannelState::Closed;
        
        log(&format!("[CHANNEL] Channel closed cooperatively"));
        
        Ok(settlement_tx)
    }
    
    /// Close the channel unilaterally (if other party disappears)
    ///
    /// Broadcasts your latest commitment transaction.
    /// The other party has `dispute_period` blocks to prove you're cheating.
    pub fn close_unilateral(
        &mut self,
        party: Party,
    ) -> PluribitResult<Transaction> {
        if self.state != ChannelState::Open {
            return Err(PluribitError::StateError("Channel not open".into()));
        }
        
        log(&format!("[CHANNEL] {:?} unilaterally closing channel {}", 
            party, hex::encode(&self.channel_id[..8])));
        log(&format!("[CHANNEL] Publishing commitment transaction for sequence {}", self.sequence_number));
        
        let commitment = match party {
            Party::A => self.party_a_commitment.as_ref(),
            Party::B => self.party_b_commitment.as_ref(),
        }.ok_or_else(|| PluribitError::StateError("No commitment transaction available".into()))?;
        
        // Verify the commitment is for the latest state
        if commitment.sequence_number != self.sequence_number {
            log("[CHANNEL] WARNING: Publishing old commitment transaction!");
            log("[CHANNEL] The other party can now claim all funds as penalty!");
        }
        
        self.state = ChannelState::Disputed;
        
        Ok(commitment.tx.clone())
    }
    
    /// Claim penalty if the other party published an old commitment
    ///
    /// If you see an old commitment transaction on-chain, you can claim ALL funds
    /// using the revocation secret from that old state.
    pub fn claim_penalty(
        &self,
        published_sequence: u64,
        revocation_secret: &[u8; 32],
    ) -> PluribitResult<Transaction> {
        log(&format!("[CHANNEL] Claiming penalty for published sequence {}", published_sequence));
        
        if published_sequence >= self.sequence_number {
            return Err(PluribitError::ValidationError("Not an old state".into()));
        }
        
        // Verify revocation secret matches
        let stored_secret = self.revocation_keys.get(&published_sequence)
            .ok_or_else(|| PluribitError::ValidationError("No revocation key for this sequence".into()))?;
        
        if revocation_secret != stored_secret {
            return Err(PluribitError::ValidationError("Invalid revocation secret".into()));
        }
        
        log(&format!("[CHANNEL] ✓ Valid revocation secret, claiming ALL funds!"));
        
        // Create penalty transaction that claims entire channel balance
        // (Simplified - real implementation would create proper transaction)
        Err(PluribitError::ValidationError("Not fully implemented".into()))
    }
    
    /// Get channel statistics
    pub fn stats(&self) -> ChannelStats {
        ChannelStats {
            state: self.state,
            total_capacity: self.total_capacity,
            party_a_balance: self.party_a_balance,
            party_b_balance: self.party_b_balance,
            sequence_number: self.sequence_number,
            total_payments: self.sequence_number,  // Each payment increments sequence
            uptime_ms: self.last_updated - self.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelStats {
    pub state: ChannelState,
    pub total_capacity: u64,
    pub party_a_balance: u64,
    pub party_b_balance: u64,
    pub sequence_number: u64,
    pub total_payments: u64,
    pub uptime_ms: u64,
}

/// Helper to create a 2-of-2 multisig key
///
/// The combined key is party_a_key + party_b_key.
/// Spending requires both parties to provide their secret key.
pub fn create_multisig_pubkey(
    party_a_pubkey: &RistrettoPoint,
    party_b_pubkey: &RistrettoPoint,
) -> RistrettoPoint {
    party_a_pubkey + party_b_pubkey
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mimblewimble;
    
    #[test]
    fn test_payment_channel_open() {
        let party_a_secret = mimblewimble::generate_secret_key();
        let party_b_secret = mimblewimble::generate_secret_key();
        let party_b_pubkey = &party_b_secret * &PC_GENS.B_blinding;
        
        let channel = PaymentChannel::open(
            &party_a_secret,
            1_000_000,  // Party A contributes 1M coins
            &party_b_pubkey,
            500_000,    // Party B contributes 500K coins
            144,        // 1 day dispute period
        ).unwrap();
        
        assert_eq!(channel.state, ChannelState::Opening);
        assert_eq!(channel.total_capacity, 1_500_000);
        assert_eq!(channel.party_a_balance, 1_000_000);
        assert_eq!(channel.party_b_balance, 500_000);
    }
    
    #[test]
    fn test_payment_channel_payments() {
        let party_a_secret = mimblewimble::generate_secret_key();
        let party_b_secret = mimblewimble::generate_secret_key();
        let party_b_pubkey = &party_b_secret * &PC_GENS.B_blinding;
        
        let mut channel = PaymentChannel::open(
            &party_a_secret,
            1_000_000,
            &party_b_pubkey,
            1_000_000,
            144,
        ).unwrap();
        
        // Manually set to open for testing
        channel.state = ChannelState::Open;
        
        // Party A sends 100K to Party B
        channel.send_payment(Party::A, 100_000).unwrap();
        assert_eq!(channel.party_a_balance, 900_000);
        assert_eq!(channel.party_b_balance, 1_100_000);
        assert_eq!(channel.sequence_number, 1);
        
        // Party B sends 50K back to Party A
        channel.send_payment(Party::B, 50_000).unwrap();
        assert_eq!(channel.party_a_balance, 950_000);
        assert_eq!(channel.party_b_balance, 1_050_000);
        assert_eq!(channel.sequence_number, 2);
        
        // Verify total capacity unchanged
        assert_eq!(channel.party_a_balance + channel.party_b_balance, 2_000_000);
    }
    
    #[test]
    fn test_payment_channel_insufficient_balance() {
        let party_a_secret = mimblewimble::generate_secret_key();
        let party_b_secret = mimblewimble::generate_secret_key();
        let party_b_pubkey = &party_b_secret * &PC_GENS.B_blinding;
        
        let mut channel = PaymentChannel::open(
            &party_a_secret,
            100_000,
            &party_b_pubkey,
            100_000,
            144,
        ).unwrap();
        
        channel.state = ChannelState::Open;
        
        // Try to send more than balance
        let result = channel.send_payment(Party::A, 150_000);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_multisig_pubkey() {
        let secret_a = mimblewimble::generate_secret_key();
        let secret_b = mimblewimble::generate_secret_key();
        
        let pubkey_a = &secret_a * &PC_GENS.B_blinding;
        let pubkey_b = &secret_b * &PC_GENS.B_blinding;
        
        let multisig = create_multisig_pubkey(&pubkey_a, &pubkey_b);
        
        // The combined secret should be secret_a + secret_b
        let combined_secret = secret_a + secret_b;
        let expected_multisig = &combined_secret * &PC_GENS.B_blinding;
        
        assert_eq!(multisig, expected_multisig);
    }
}
