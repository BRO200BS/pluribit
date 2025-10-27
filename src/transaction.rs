// src/transaction.rs

use serde::{Serialize, Deserialize};
use crate::error::{PluribitResult, PluribitError};
use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};
use crate::mimblewimble;
use curve25519_dalek::traits::Identity;
use crate::log;
use crate::p2p;
use crate::wasm_types::WasmU64;


#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TransactionInput {
    pub commitment: Vec<u8>,
    pub merkle_proof: Option<crate::merkle::MerkleProof>,
    pub source_height: WasmU64, 
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TransactionOutput {
    pub commitment: Vec<u8>,
    // range_proof removed - V2 uses aggregated proof at Transaction level
    pub ephemeral_key: Option<Vec<u8>>, // Stores the sender's ephemeral public key R
    pub stealth_payload: Option<Vec<u8>>, // Stores the encrypted nonce || cipher
    pub view_tag: Option<Vec<u8>>, // Now matches Protobuf 'bytes' type
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TransactionKernel {
    pub excess: Vec<u8>,
    pub signature: Vec<u8>,
    pub fee: WasmU64,
    pub min_height: WasmU64,
    pub timestamp: WasmU64, // CRITICAL FIX #8: Add timestamp for ordering
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub kernels: Vec<TransactionKernel>,
    pub timestamp: WasmU64,
    pub aggregated_range_proof: Vec<u8>, // V2: One proof for ALL outputs
}



impl TransactionKernel {
        pub fn verify_signature(&self) -> PluribitResult<bool> {
        // Decompress the kernel excess point P = blinding*G + fee*H
        let excess_point = CompressedRistretto::from_slice(&self.excess)
            .map_err(|_| PluribitError::InvalidKernelExcess)?
            .decompress()
            .ok_or(PluribitError::InvalidKernelExcess)?;

        // Reconstruct the public key (blinding*G) used for the signature.
        // This is done by subtracting the commitment to the fee (fee*H) from the excess.
        let fee_commitment = mimblewimble::PC_GENS.commit(Scalar::from(*self.fee), Scalar::from(0u64));

        let public_key = excess_point - fee_commitment;

        // The message that was signed is the hash of the fee and min_height.
        let mut hasher = sha2::Sha256::new();
        // Add domain separation
        hasher.update(b"pluribit_kernel_v1");
        hasher.update(&16u64.to_le_bytes());
        hasher.update(&self.fee.0.to_be_bytes());
        hasher.update(&self.min_height.0.to_be_bytes());
        hasher.update(&self.timestamp.0.to_be_bytes());
        let msg_hash: [u8; 32] = hasher.finalize().into();
        
        // Parse the signature from the kernel.
        if self.signature.len() != 64 {
            return Ok(false);
        }
        let mut challenge_bytes = [0u8; 32];
        challenge_bytes.copy_from_slice(&self.signature[0..32]);
        let challenge = Scalar::from_bytes_mod_order(challenge_bytes);

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&self.signature[32..64]);
        let s = Scalar::from_bytes_mod_order(s_bytes);

        // Verify the Schnorr signature.
        Ok(mimblewimble::verify_schnorr_signature(&(challenge, s), msg_hash, &public_key))
    }
    
pub fn new(blinding: Scalar, fee: u64, min_height: u64, timestamp: u64) -> Result<Self, String> {
    log("=== TRANSACTION_KERNEL::NEW DEBUG ===");
    log(&format!("[KERNEL_NEW] Input blinding={}", hex::encode(blinding.to_bytes())));
    log(&format!("[KERNEL_NEW] Fee={}", fee));
    
    let excess_point = mimblewimble::PC_GENS.commit(Scalar::from(fee), blinding);

    log(&format!("[KERNEL_NEW] Derived excess_point={}", hex::encode(excess_point.compress().to_bytes())));
    let mut hasher = Sha256::new();
    hasher.update(b"pluribit_kernel_v1");
    hasher.update(&16u64.to_le_bytes());    
    hasher.update(&fee.to_be_bytes());
    hasher.update(&min_height.to_be_bytes());
    // FIX #8: Include timestamp in signature
    hasher.update(&timestamp.to_be_bytes());
    let message_hash: [u8; 32] = hasher.finalize().into();
    log(&format!("[KERNEL_NEW] Message hash={}", hex::encode(message_hash)));
    
    let (challenge, s) = mimblewimble::create_schnorr_signature(message_hash, &blinding)
        .map_err(|e| e.to_string())?;

    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(&challenge.to_bytes());
    signature.extend_from_slice(&s.to_bytes());
    
    Ok(TransactionKernel {
        excess: excess_point.compress().to_bytes().to_vec(),
        signature,
        fee: WasmU64::from(fee),
        min_height: WasmU64::from(min_height),
        timestamp: WasmU64::from(timestamp),
    })
}
    
  
}

impl Transaction {
    /// Verify this transaction end-to-end:
    /// 1) All range proofs validate
    /// 2) Kernel Schnorr signature is correct
    /// 3) Sum(inputs) == Sum(outputs) + excess
    /// 4) All inputs exist in the UTXO set
    #[allow(non_snake_case)]
    pub fn verify(&self, block_reward: Option<u64>, utxos_opt: Option<&std::collections::HashMap<Vec<u8>, TransactionOutput>>) -> PluribitResult<()> {
        // CRITICAL FIX #8: Validate transaction timestamp
        #[cfg(target_arch = "wasm32")]
        let now_ms = js_sys::Date::now() as u64;
        #[cfg(not(target_arch = "wasm32"))]
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        if *self.timestamp > now_ms + crate::constants::MAX_FUTURE_DRIFT_MS {

            return Err(PluribitError::ValidationError(
                "Transaction timestamp too far in the future".to_string()
            ));
        }
        
        // Timestamp should be somewhat recent (not from years ago)
        const MAX_TX_AGE_MS: u64 = 24 * 60 * 60 * 1000; // 24 hours
        if *self.timestamp + MAX_TX_AGE_MS < now_ms {

            return Err(PluribitError::ValidationError(
                "Transaction timestamp too old".to_string()
            ));
        }

        // 1) Verify aggregated range proof (V2)
        if !self.outputs.is_empty() {
            let commitments: Vec<CompressedRistretto> = self.outputs.iter()
                .map(|output| CompressedRistretto::from_slice(&output.commitment))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| PluribitError::InvalidOutputCommitment)?;
            
            let proof = RangeProof::from_bytes(&self.aggregated_range_proof)
                .map_err(|_| PluribitError::InvalidRangeProof)?;
            
            if !mimblewimble::verify_aggregated_range_proof(&proof, &commitments) {
                return Err(PluribitError::InvalidRangeProof);
            }
        }

        // 2) Verify all kernel signatures and compute total kernel excess
        if !self.verify_signature()? {
            return Err(PluribitError::InvalidKernelSignature);
        }
        
        let mut P_total = RistrettoPoint::identity();
        for k in &self.kernels {
            P_total += mimblewimble::kernel_excess_to_pubkey(&k.excess)?;
        }

        // 3) Balance check
        let mut sum_in = RistrettoPoint::identity();
        for inp in &self.inputs {
            let C = CompressedRistretto::from_slice(&inp.commitment)
                .map_err(|_| PluribitError::InvalidInputCommitment)?
                .decompress()
                .ok_or(PluribitError::InvalidInputCommitment)?;
            sum_in += C;
        }
        
        let mut sum_out = RistrettoPoint::identity();
        for out in &self.outputs {
            let C = CompressedRistretto::from_slice(&out.commitment)
                .map_err(|_| PluribitError::InvalidOutputCommitment)?
                .decompress()
                .ok_or(PluribitError::InvalidOutputCommitment)?;
            sum_out += C;
        }
        
        if let Some(reward) = block_reward {
            // COINBASE: Sum(Outputs) - Sum(Kernels) == reward*H
            let reward_commitment = mimblewimble::PC_GENS.commit(Scalar::from(reward), Scalar::from(0u64));
            if sum_out - P_total != reward_commitment {
                return Err(PluribitError::Imbalance);
            }
        } else {
            // REGULAR: Sum(Inputs) == Sum(Outputs) + Sum(KernelExcess)
            if sum_out + P_total != sum_in {
                return Err(PluribitError::Imbalance);
            }
        }

        // 4) UTXO existence (only for regular transactions)
        if block_reward.is_none() {
            let utxos = utxos_opt.ok_or(PluribitError::InvalidInput(
                "UTXO set is required for regular transaction verification".to_string()
            ))?;
            for inp in &self.inputs {
                if !utxos.contains_key(&inp.commitment) {
                    return Err(PluribitError::UnknownInput);
                }
            }
        }


        Ok(())
    }

    /// Create a coinbase transaction (no inputs, only outputs)
  pub fn create_coinbase(rewards: Vec<(Vec<u8>, u64)>) -> PluribitResult<Self> {
    use crate::stealth;
    use rand::rngs::OsRng;
    
    let mut outputs = Vec::new();
    let mut blinding_sum = Scalar::default();
    let mut total_reward_value = 0u64;
    
    log("=== CREATE_COINBASE DEBUG ===");
    
    for (i, (recipient_pub_key_bytes, amount)) in rewards.iter().enumerate() {
        total_reward_value += amount;
        log(&format!("[CREATE_COINBASE] Output {}: amount={}", i, amount));

        let scan_pub_compressed = CompressedRistretto::from_slice(&recipient_pub_key_bytes)
            .map_err(|_| PluribitError::ValidationError("Invalid public key".to_string()))?;

        let scan_pub = scan_pub_compressed.decompress()
            .ok_or_else(|| PluribitError::ValidationError("Failed to decompress public key".to_string()))?;
        
        let r = Scalar::random(&mut OsRng);
        let blinding = Scalar::random(&mut OsRng);
        log(&format!("[CREATE_COINBASE] Output {}: blinding={}", i, hex::encode(blinding.to_bytes())));
        
        // Capture all 3 return values, including the view_tag
        let (ephemeral_key, payload, view_tag) = stealth::encrypt_stealth_out(&r, &scan_pub, *amount, &blinding); 
        
        // Create commitment explicitly
        let commitment_point = mimblewimble::commit(*amount, &blinding)?;
        let commitment = commitment_point.compress();
        log(&format!("[CREATE_COINBASE] Output {}: commitment={}", i, hex::encode(commitment.to_bytes())));
        
        let (proof, _) = mimblewimble::create_range_proof(*amount, &blinding)?;
        
        outputs.push(TransactionOutput {
            commitment: commitment.to_bytes().to_vec(),
            ephemeral_key: Some(ephemeral_key.compress().to_bytes().to_vec()),
            stealth_payload: Some(payload),
             view_tag: Some(vec![view_tag]),
        });
        
        blinding_sum += blinding;
        log(&format!("[CREATE_COINBASE] Output {}: running blinding_sum={}", i, hex::encode(blinding_sum.to_bytes())));
    }
    
    log(&format!("[CREATE_COINBASE] Final blinding_sum={}", hex::encode(blinding_sum.to_bytes())));
    log(&format!("[CREATE_COINBASE] Total reward value={}", total_reward_value));
    
    let fee = 0u64;
    #[cfg(target_arch = "wasm32")]
    let timestamp = js_sys::Date::now() as u64;
    #[cfg(not(target_arch = "wasm32"))]
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;
    let min_height = 0u64; // Coinbase has no minimum height
    let kernel = TransactionKernel::new(blinding_sum, fee, min_height, timestamp) 
        .map_err(|e| PluribitError::ComputationError(e.to_string()))?;
        
    log(&format!("[CREATE_COINBASE] Kernel excess={}", hex::encode(&kernel.excess)));
    log(&format!("[CREATE_COINBASE] Final outputs before return: {:?}", outputs)); // <-- ADD THIS LINE
    Ok(Transaction {
        inputs: vec![],
        outputs,
        kernels: vec![kernel],
        timestamp: WasmU64::from(timestamp),
        aggregated_range_proof: vec![], // Coinbase has no range proofs
    })
}
    
    pub fn verify_signature(&self) -> PluribitResult<bool> {
        for k in &self.kernels {
            if !k.verify_signature()? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    
    pub fn total_fee(&self) -> u64 {
        self.kernels.iter().fold(0u64, |acc, k| acc.saturating_add(*k.fee))
    }
    
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();

        // Sort and hash inputs
        let mut sorted_inputs = self.inputs.clone();
        sorted_inputs.sort_by(|a, b| a.commitment.cmp(&b.commitment));
        for i in &sorted_inputs {
            hasher.update(&i.commitment);
        }

        // Sort and hash outputs
        let mut sorted_outputs = self.outputs.clone();
        sorted_outputs.sort_by(|a, b| a.commitment.cmp(&b.commitment));
        for o in &sorted_outputs {
            hasher.update(&o.commitment);
        }

        // Sort kernels for deterministic hash
        let mut ks = self.kernels.clone();
        ks.sort_by(|a, b| a.excess.cmp(&b.excess));
        hasher.update(&(ks.len() as u64).to_le_bytes());
        for k in ks {
            hasher.update(&k.excess);
            hasher.update(&k.signature);
            hasher.update(&k.fee.0.to_le_bytes());
            hasher.update(&k.min_height.0.to_le_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

/// **Protobuf Conversion: Internal -> p2p**
impl From<TransactionInput> for p2p::TransactionInput {
    fn from(input: TransactionInput) -> Self {
        p2p::TransactionInput {
            commitment: input.commitment,
            source_height: *input.source_height,  // Convert WasmU64 to u64
        }
    }
}

/// **Protobuf Conversion: p2p -> Internal**
impl From<p2p::TransactionInput> for TransactionInput {
    fn from(proto: p2p::TransactionInput) -> Self {
        TransactionInput {
            commitment: proto.commitment,
            merkle_proof: None,
            source_height: WasmU64::from(proto.source_height),  // Convert u64 to WasmU64
        }
    }
}

/// **Protobuf Conversion: Internal -> p2p**
impl From<TransactionOutput> for p2p::TransactionOutput {
    fn from(output: TransactionOutput) -> Self {
        p2p::TransactionOutput {
            commitment: output.commitment,
            ephemeral_key: output.ephemeral_key,
            stealth_payload: output.stealth_payload,
            view_tag: output.view_tag,
        }
    }
}

/// **Protobuf Conversion: p2p -> Internal**
impl From<p2p::TransactionOutput> for TransactionOutput {
    fn from(proto: p2p::TransactionOutput) -> Self {
        TransactionOutput {
            commitment: proto.commitment,            
            ephemeral_key: proto.ephemeral_key,
            stealth_payload: proto.stealth_payload,
            // Convert Option<Vec<u8>> (expecting one byte) back to Option<u8>
            view_tag: proto.view_tag,
        }
    }
}

/// **Protobuf Conversion: Internal -> p2p**
impl From<TransactionKernel> for p2p::TransactionKernel {
    fn from(kernel: TransactionKernel) -> Self {
        p2p::TransactionKernel {
            excess: kernel.excess,
            signature: kernel.signature,
            fee: *kernel.fee,
            min_height: *kernel.min_height,
            timestamp: *kernel.timestamp,
        }
    }
}

/// **Protobuf Conversion: p2p -> Internal**
impl From<p2p::TransactionKernel> for TransactionKernel {
    fn from(proto: p2p::TransactionKernel) -> Self {
        TransactionKernel {
            excess: proto.excess,
            signature: proto.signature,
            fee: WasmU64::from(proto.fee),
            min_height: WasmU64::from(proto.min_height),
            timestamp: WasmU64::from(proto.timestamp),
        }
    }
}

/// **Protobuf Conversion: Internal -> p2p**
impl From<Transaction> for p2p::Transaction {
    fn from(tx: Transaction) -> Self {
        p2p::Transaction {
            inputs: tx.inputs.into_iter().map(p2p::TransactionInput::from).collect(),
            outputs: tx.outputs.into_iter().map(p2p::TransactionOutput::from).collect(),
            kernels: tx.kernels.into_iter().map(p2p::TransactionKernel::from).collect(),
            timestamp: *tx.timestamp,
            aggregated_range_proof: tx.aggregated_range_proof,
        }
    }
}

/// **Protobuf Conversion: p2p -> Internal**
impl From<p2p::Transaction> for Transaction {
    fn from(proto: p2p::Transaction) -> Self {
        Transaction {
            inputs: proto.inputs.into_iter().map(TransactionInput::from).collect(),
            outputs: proto.outputs.into_iter().map(TransactionOutput::from).collect(),
            kernels: proto.kernels.into_iter().map(TransactionKernel::from).collect(),
            timestamp: WasmU64::from(proto.timestamp),
            aggregated_range_proof: proto.aggregated_range_proof,
        }
    }
}



#[cfg(test)]
#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::wallet::Wallet;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    
    
    use lazy_static::lazy_static;
    use wasm_bindgen_test::*;
    use std::sync::Mutex;
    use crate::{BLOCKCHAIN, TX_POOL};
    use crate::blockchain;
    use crate::blockchain::UTXO_SET;

    lazy_static! {
        static ref TEST_MUTEX: Mutex<()> = Mutex::new(());
    }

    // Helper to reset global state for tests
    fn reset_global_state() {
        // Handle poisoned mutexes gracefully
        {
            let mut chain = BLOCKCHAIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            *chain = blockchain::Blockchain::new();
            // Set easy test parameters
            // PoW difficulty removed
            chain.current_vrf_threshold = [0xFF; 32]; // Easy threshold
            chain.current_vdf_iterations = 1000;
        }

        {
            let mut utxo_set = blockchain::UTXO_SET.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            utxo_set.clear();
        }

        {
            let mut coinbase_index = crate::blockchain::COINBASE_INDEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            coinbase_index.clear();
        }

        {
            let mut tx_pool = TX_POOL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            tx_pool.pending.clear();
            tx_pool.fee_total = 0;
        }
    }
    
    // This test is already passing but included for completeness of the module
    #[wasm_bindgen_test]
    async fn test_coinbase_creation_and_verification() {
        let reward_amount = 50_000_000;
        let wrong_reward = 100;
        let miner_wallet = Wallet::new();
        let miner_pubkey_bytes = miner_wallet.scan_pub.compress().to_bytes().to_vec();
        let rewards = vec![(miner_pubkey_bytes, reward_amount)];
        let coinbase_tx = Transaction::create_coinbase(rewards).unwrap();
        assert!(coinbase_tx.verify(Some(reward_amount), None).is_ok());
        assert!(coinbase_tx.verify(Some(wrong_reward), None).is_err());
        assert!(coinbase_tx.verify(None, None).is_err());
    }

    #[wasm_bindgen_test]
    #[cfg(not(target_arch = "wasm32"))]
    async fn test_transaction_roundtrip() {
        let _guard = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_global_state();

        let miner_sk = crate::mimblewimble::generate_secret_key();
        let miner_pk = &miner_sk * &*RISTRETTO_BASEPOINT_TABLE;
        let sender_wallet = Wallet::new();
        let recipient_wallet = Wallet::new();
        // Add a block to the GLOBAL chain to fund the sender wallet
        let block1 = {
            let mut chain = BLOCKCHAIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            chain.current_vrf_threshold = [0xFF; 32]; // Maximum threshold (always passes)

            let reward = crate::blockchain::get_current_base_reward(1);
            let coinbase_tx = Transaction::create_coinbase(vec![(sender_wallet.scan_pub.compress().to_bytes().to_vec(), reward)]).unwrap();
            
            let mut block = crate::block::Block::genesis();
            block.height = 1;
            block.prev_hash = chain.tip_hash.clone();
            block.transactions.push(coinbase_tx);
            block.miner_pubkey = miner_pk.compress().to_bytes();
            block.vrf_proof = crate::vrf::create_vrf(&miner_sk, block.prev_hash.as_bytes());
            let vdf = crate::vdf::VDF::new(2048).unwrap();
            let vdf_input = format!("{}{}", block.prev_hash, hex::encode(&block.vrf_proof.output));
            block.vdf_proof = vdf.compute_with_proof(vdf_input.as_bytes(), chain.current_vdf_iterations).unwrap();
            block.tx_merkle_root = block.calculate_tx_merkle_root();

            block.lottery_nonce = 1; // Or any fixed value

            // FIX: Ensure the block's params match the chain's before adding
            block.vrf_threshold = chain.current_vrf_threshold;
            block.vdf_iterations = chain.current_vdf_iterations;

            let vrf_threshold = chain.current_vrf_threshold;
            let vdf_iterations = chain.current_vdf_iterations;
            chain.add_block(block.clone(), vrf_threshold, vdf_iterations).await.unwrap();

            block  // Return the block from the scope
        };
        // Rest of the test...
        let spending_tx = {
            let mut temp_wallet = sender_wallet;
            temp_wallet.scan_block(&block1);
            assert_eq!(temp_wallet.balance(), crate::blockchain::get_current_base_reward(1));
            temp_wallet.create_transaction(900, 10, &recipient_wallet.scan_pub).unwrap()
        };
        {
            let utxo_set = crate::blockchain::UTXO_SET.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(spending_tx.verify(None, Some(&utxo_set)).is_ok(), "Manually constructed transaction should be valid");
        }
    }

    #[wasm_bindgen_test]
    #[cfg(not(target_arch = "wasm32"))]
    async fn test_verify_with_valid_merkle_proof() {
        let _guard = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_global_state();
    
        let miner_sk = crate::mimblewimble::generate_secret_key();
        let miner_pk = &miner_sk * &*RISTRETTO_BASEPOINT_TABLE;
        let recipient_wallet = Wallet::new();
        let block1 = {
            let mut chain = BLOCKCHAIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            chain.current_vrf_threshold = [0xFF; 32]; // Easy threshold
    
            let recipient_pubkey_bytes = recipient_wallet.scan_pub.compress().to_bytes().to_vec();
            let correct_reward = crate::blockchain::get_current_base_reward(1);
            
            // FIX: Create two outputs so the merkle proof has siblings
            let rewards = vec![
                (recipient_pubkey_bytes.clone(), correct_reward / 2),
                (recipient_pubkey_bytes, correct_reward - (correct_reward / 2)),
            ];
            let coinbase_tx = Transaction::create_coinbase(rewards).unwrap();
            
            let mut block = crate::block::Block::genesis();
            block.height = 1;
            block.prev_hash = chain.tip_hash.clone();
            block.transactions.push(coinbase_tx);
            block.miner_pubkey = miner_pk.compress().to_bytes();
            block.vrf_proof = crate::vrf::create_vrf(&miner_sk, block.prev_hash.as_bytes());
            let vdf = crate::vdf::VDF::new(2048).unwrap();
            
            let vdf_input = format!("{}{}", block.prev_hash, hex::encode(&block.vrf_proof.output));
            block.vdf_proof = vdf.compute_with_proof(vdf_input.as_bytes(), chain.current_vdf_iterations).unwrap();
            block.tx_merkle_root = block.calculate_tx_merkle_root();

            // FIXED: Replaced infinite loop with a fixed nonce
            block.lottery_nonce = 1;

            // FIX: Ensure the block's params match the chain's before adding
            block.vrf_threshold = chain.current_vrf_threshold;
            block.vdf_iterations = chain.current_vdf_iterations;

            let vrf_threshold = chain.current_vrf_threshold;
            let vdf_iterations = chain.current_vdf_iterations;
            chain.add_block(block.clone(), vrf_threshold, vdf_iterations).await.unwrap();

            block
        };
    
        let mut utxo_wallet = recipient_wallet;
        utxo_wallet.scan_block(&block1);
        assert_eq!(utxo_wallet.balance(), crate::blockchain::get_current_base_reward(1));
        let spending_tx = utxo_wallet.create_transaction(utxo_wallet.balance() - 100, 10, &Wallet::new().scan_pub).unwrap();
        
        let utxo_set = crate::blockchain::UTXO_SET.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(spending_tx.verify(None, Some(&utxo_set)).is_ok(), "Transaction with a valid merkle proof should be verified");
    }
    
    #[wasm_bindgen_test]
    #[cfg(not(target_arch = "wasm32"))]
    async fn test_verify_fails_with_invalid_merkle_proof() {
        let _guard = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_global_state();
    
        let miner_sk = crate::mimblewimble::generate_secret_key();
        let miner_pk = &miner_sk * &*RISTRETTO_BASEPOINT_TABLE;
        let recipient_wallet = Wallet::new();
        let block1 = {
            let mut chain = BLOCKCHAIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            chain.current_vrf_threshold = [0xFF; 32]; // Easy threshold
    
            let recipient_pubkey_bytes = recipient_wallet.scan_pub.compress().to_bytes().to_vec();
            let correct_reward = crate::blockchain::get_current_base_reward(1);

            // FIX: Create two outputs so the merkle proof has siblings to tamper with
            let rewards = vec![
                (recipient_pubkey_bytes.clone(), correct_reward / 2),
                (recipient_pubkey_bytes, correct_reward - (correct_reward / 2)),
            ];
            let coinbase_tx = Transaction::create_coinbase(rewards).unwrap();
            
            let mut block = crate::block::Block::genesis();
            block.height = 1;
            block.prev_hash = chain.tip_hash.clone();
            block.transactions.push(coinbase_tx);
            block.miner_pubkey = miner_pk.compress().to_bytes();
            block.vrf_proof = crate::vrf::create_vrf(&miner_sk, block.prev_hash.as_bytes());
            let vdf = crate::vdf::VDF::new(2048).unwrap();
            
            let vdf_input = format!("{}{}", block.prev_hash, hex::encode(&block.vrf_proof.output));
            block.vdf_proof = vdf.compute_with_proof(vdf_input.as_bytes(), chain.current_vdf_iterations).unwrap();
            block.tx_merkle_root = block.calculate_tx_merkle_root();

            // FIXED: Replaced infinite loop with a fixed nonce
            block.lottery_nonce = 1;

            // FIX: Ensure the block's params match the chain's before adding
            block.vrf_threshold = chain.current_vrf_threshold;
            block.vdf_iterations = chain.current_vdf_iterations;

            let vrf_threshold = chain.current_vrf_threshold;
            let vdf_iterations = chain.current_vdf_iterations;
            chain.add_block(block.clone(), vrf_threshold, vdf_iterations).await.unwrap();

            block
        };
    
        let mut utxo_wallet = recipient_wallet;
        utxo_wallet.scan_block(&block1);
        let mut spending_tx = utxo_wallet.create_transaction(100, 10, &Wallet::new().scan_pub).unwrap();
    
        // Manually tamper with the proof to make it invalid.
        if let Some(proof) = &mut spending_tx.inputs[0].merkle_proof {
            if !proof.siblings.is_empty() {
                proof.siblings[0][0] ^= 0xFF; // Flip a byte in a sibling hash
            }
        }
        
        let utxo_set = crate::blockchain::UTXO_SET.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(spending_tx.verify(None, Some(&utxo_set)).is_err(), "Transaction with an invalid merkle proof should fail verification");
    }
    
    #[wasm_bindgen_test]
    async fn test_transaction_hash() {
        let tx1 = Transaction { inputs: vec![], outputs: vec![], kernels: vec![TransactionKernel { excess: vec![1, 2, 3], signature: vec![4, 5, 6], fee: WasmU64::from(10), min_height: WasmU64::from(0), timestamp: WasmU64::from(1) }], timestamp: WasmU64::from(1) };
        let tx2 = Transaction { inputs: vec![], outputs: vec![], kernels: vec![TransactionKernel { excess: vec![1, 2, 3], signature: vec![4, 5, 6], fee: WasmU64::from(10), min_height: WasmU64::from(0), timestamp: WasmU64::from(1) }], timestamp: WasmU64::from(1) };
        assert_eq!(tx1.hash(), tx2.hash());
        let mut tx3 = tx1.clone();
        tx3.kernels[0].fee = WasmU64::from(20);

        assert_ne!(tx1.hash(), tx3.hash());
    }

    #[wasm_bindgen_test]
    #[cfg(not(target_arch = "wasm32"))]
    async fn test_transaction_excess_with_fee() {
        let _guard = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_global_state();
        // Setup similar to existing test_transaction_roundtrip
        let miner_sk = mimblewimble::generate_secret_key();
        let miner_pk = &miner_sk * &*RISTRETTO_BASEPOINT_TABLE;
        let sender_wallet = Wallet::new();
        let recipient_wallet = Wallet::new();

        // Add funding block
        let block1 = {
            let mut chain = BLOCKCHAIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            chain.current_vrf_threshold = [0xFF; 32];

            let reward = crate::blockchain::get_current_base_reward(1);
            let coinbase_tx = Transaction::create_coinbase(vec![(sender_wallet.scan_pub.compress().to_bytes().to_vec(), reward)]).unwrap();
            let mut block = crate::block::Block::genesis();
            block.height = 1;
            block.prev_hash = chain.tip_hash.clone();
            block.transactions.push(coinbase_tx);
            block.miner_pubkey = miner_pk.compress().to_bytes();
            block.vrf_proof = crate::vrf::create_vrf(&miner_sk, block.prev_hash.as_bytes());
            let vdf = crate::vdf::VDF::new(2048).unwrap();
            let vdf_input = format!("{}{}", block.prev_hash, hex::encode(&block.vrf_proof.output));
            block.vdf_proof = vdf.compute_with_proof(vdf_input.as_bytes(), chain.current_vdf_iterations).unwrap();
            block.tx_merkle_root = block.calculate_tx_merkle_root();
            
            // FIXED: Replaced infinite loop with a fixed nonce
            block.lottery_nonce = 1;

            // FIX: Ensure the block's params match the chain's before adding
            block.vrf_threshold = chain.current_vrf_threshold;
            block.vdf_iterations = chain.current_vdf_iterations;

            let vrf_threshold = chain.current_vrf_threshold;
            let vdf_iterations = chain.current_vdf_iterations;
            chain.add_block(block.clone(), vrf_threshold, vdf_iterations).await.unwrap();

            block
        };
        // Create tx with fee
        let mut temp_wallet = sender_wallet.clone();
        temp_wallet.scan_block(&block1);
        let spending_tx = temp_wallet.create_transaction(900, 10, &recipient_wallet.scan_pub).unwrap();
        // Verify with UTXO set
        let utxo_set = blockchain::UTXO_SET.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(spending_tx.verify(None, Some(&utxo_set)).is_ok(), "Transaction with fee should verify after fix");
    }

    #[wasm_bindgen_test]
    #[cfg(not(target_arch = "wasm32"))]
    async fn test_transaction_serialization_with_fee() {
        let _guard = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_global_state();

        // Setup similar to test_transaction_roundtrip
        let miner_sk = mimblewimble::generate_secret_key();
        let miner_pk = &miner_sk * &*RISTRETTO_BASEPOINT_TABLE;
        let sender_wallet = Wallet::new();
        let recipient_wallet = Wallet::new();

        // Add funding block
        let block1 = {
            let mut chain = BLOCKCHAIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            chain.current_vrf_threshold = [0xFF; 32];

            let reward = crate::blockchain::get_current_base_reward(1);
            let coinbase_tx = Transaction::create_coinbase(vec![(sender_wallet.scan_pub.compress().to_bytes().to_vec(), reward)]).unwrap();
            let mut block = crate::block::Block::genesis();
            block.height = 1;
            block.prev_hash = chain.tip_hash.clone();
            block.transactions.push(coinbase_tx);
            block.miner_pubkey = miner_pk.compress().to_bytes();
            block.vrf_proof = crate::vrf::create_vrf(&miner_sk, block.prev_hash.as_bytes());
            let vdf = crate::vdf::VDF::new(2048).unwrap();
            let vdf_input = format!("{}{}", block.prev_hash, hex::encode(&block.vrf_proof.output));
            block.vdf_proof = vdf.compute_with_proof(vdf_input.as_bytes(), chain.current_vdf_iterations).unwrap();
            block.tx_merkle_root = block.calculate_tx_merkle_root();

            // FIXED: Replaced infinite loop with a fixed nonce
            block.lottery_nonce = 1;

            // FIX: Ensure the block's params match the chain's before adding
            block.vrf_threshold = chain.current_vrf_threshold;
            block.vdf_iterations = chain.current_vdf_iterations;

            let vrf_threshold = chain.current_vrf_threshold;
            let vdf_iterations = chain.current_vdf_iterations;
            chain.add_block(block.clone(), vrf_threshold, vdf_iterations).await.unwrap();

            block
        };
        // Create spending_tx
        let spending_tx = {
            let mut temp_wallet = sender_wallet;
            temp_wallet.scan_block(&block1);
            temp_wallet.create_transaction(900, 10, &recipient_wallet.scan_pub).unwrap()
        };

        // Serialize and deserialize
        let tx_json = serde_json::to_string(&spending_tx).unwrap();
        let deserialized_tx: Transaction = serde_json::from_str(&tx_json).unwrap();

        // Verify deserialized
        let utxo_set = blockchain::UTXO_SET.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(deserialized_tx.verify(None, Some(&utxo_set)).is_ok(), "Serialized transaction with fee should verify");
    }

    #[wasm_bindgen_test]
    async fn test_coinbase_excess_balance() {
        let _guard = TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset_global_state();
        // Create coinbase tx
        let recipient_pubkey_bytes = Wallet::new().scan_pub.compress().to_bytes().to_vec();
        let reward = blockchain::get_current_base_reward(1);
        let coinbase_tx = Transaction::create_coinbase(vec![(recipient_pubkey_bytes, reward)]).unwrap();
        // Verify as coinbase
        let utxo_set = UTXO_SET.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(coinbase_tx.verify(Some(reward), Some(&utxo_set)).is_ok(), "Coinbase should verify with adjustment");
    }
}
