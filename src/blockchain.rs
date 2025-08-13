// src/blockchain.rs
use crate::block::Block;
use crate::transaction::{Transaction, TransactionOutput}; 
use crate::error::{PluribitError, PluribitResult};
use crate::vrf;
use crate::constants;
use crate::vdf::VDFProof;
use crate::vrf::VrfProof;
use crate::mimblewimble;
use crate::log;
use bulletproofs::RangeProof; // Added for range proof verification
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar; // Added for creating commitments
use curve25519_dalek::traits::Identity; // Added for RistrettoPoint::identity()
use std::collections::HashMap;
use num_bigint::BigUint;
use std::sync::Mutex;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use crate::constants::{
    INITIAL_POW_DIFFICULTY,
    DEFAULT_VRF_THRESHOLD,
    INITIAL_VDF_ITERATIONS,
    VRF_MIN_THRESHOLD,
    VRF_MAX_THRESHOLD,
    COINBASE_MATURITY,
    MTP_WINDOW,
    MAX_FUTURE_DRIFT_MS,
};


lazy_static! {
    pub static ref UTXO_SET: Mutex<HashMap<Vec<u8>, TransactionOutput>> =
        Mutex::new(HashMap::new());
    // commitment -> block_height (only for coinbase outputs)
    pub static ref COINBASE_INDEX: Mutex<HashMap<Vec<u8>, u64>> =
        Mutex::new(HashMap::new());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blockchain {
    pub blocks: Vec<Block>,
    #[serde(skip)]
    pub block_by_hash: HashMap<String, Block>,
    pub current_height: u64,
    
    // NEW difficulty and work tracking
    pub total_work: u64,
    pub current_pow_difficulty: u8,
    pub current_vrf_threshold: [u8; 32],
    pub current_vdf_iterations: u64,
}

impl Blockchain {

    /// Median-Time-Past of the last `window` blocks (inclusive of tip).
    fn median_time_past(&self, window: usize) -> u64 {
        let n = self.blocks.len().min(window);
        if n == 0 {
            return 0;
        }
        let start = self.blocks.len() - n;
        let mut ts: Vec<u64> = self.blocks[start..].iter().map(|b| b.timestamp).collect();
        ts.sort_unstable();
        ts[n / 2]
    }

    pub fn new() -> Self {
        let genesis = Block::genesis();
        let genesis_hash = genesis.hash();
        let mut block_by_hash = HashMap::new();
        block_by_hash.insert(genesis_hash.clone(), genesis.clone());
        
        Blockchain {
            blocks: vec![genesis],
            block_by_hash,
            current_height: 0,
            total_work: 0,
            current_pow_difficulty: INITIAL_POW_DIFFICULTY,
            current_vrf_threshold:  DEFAULT_VRF_THRESHOLD,
            current_vdf_iterations: INITIAL_VDF_ITERATIONS,
        }
    }
    
    /// FORK CHOICE RULE: VRF+VDF weighted work
    pub fn get_chain_work(blocks: &[Block]) -> u64 {
        use num_bigint::BigUint;
        use num_traits::{One, Zero, ToPrimitive};

        if blocks.is_empty() { return 0; }

        let two256 = BigUint::one() << 256;
        let mut total_u128: u128 = 0;

        for b in blocks {
            // 1) VRF component: higher work for lower thresholds
            let t = BigUint::from_bytes_be(&b.vrf_threshold);
            if t.is_zero() { continue; }
            let vrf_w: BigUint = &two256 / &t;

            // 2) VDF component: proportional to iterations committed in the header
            let vdf_w = BigUint::from(b.vdf_iterations);

            // 3) Combine (multiplicative) and downscale to <=64 bits, preserving order
            let w = vrf_w * vdf_w;

            // Compute bit length from the bytes to choose a safe shift
            let bytes = w.to_bytes_be();
            let bits = if bytes.is_empty() {
                0usize
            } else {
                (bytes.len() - 1) * 8 + (8 - bytes[0].leading_zeros() as usize)
            };

            let w64 = if bits > 64 {
                // Normalize by dropping the least significant bits until it fits
                (&w >> (bits - 64)).to_u64().unwrap_or(u64::MAX)
            } else {
                w.to_u64().unwrap_or(0)
            };

            total_u128 = total_u128.saturating_add(w64 as u128);
        }

        total_u128.min(u128::from(u64::MAX)) as u64
    }

    pub fn get_total_work(&self) -> u64 {
        self.total_work
    }
    
    pub fn get_latest_block(&self) -> &Block {
        self.blocks.last().expect("blockchain always has genesis")
    }

    /// Very simple selector: verify signature + avoid input conflicts.
    /// Returns (selected_txs, total_fees)
    pub fn select_transactions_for_block(&self, pool: &Vec<Transaction>) -> (Vec<Transaction>, u64) {
        fn to_hex(bytes: &[u8]) -> String {
            let mut s = String::with_capacity(bytes.len() * 2);
            for b in bytes { s.push_str(&format!("{:02x}", b)); }
            s
        }

        let mut selected: Vec<Transaction> = Vec::new();
        let mut used_inputs = std::collections::HashSet::<String>::new();
        let mut total_fees: u64 = 0;

        for tx in pool.iter() {
            // 1) Basic sanity: kernel signature
            if let Err(e) = tx.verify_signature() {     
                println!("[SELECT] skip tx: bad signature ({e})");
                continue;
            }

            // 2) Prevent double-spend inside the block
            let mut conflicts = false;
            for inp in &tx.inputs {
                // No `commitment_hex()`, so hex-encode the input commitment directly
                let key = to_hex(&inp.commitment);
                if !used_inputs.insert(key) { // already seen → conflict
                    conflicts = true;
                    break;
                }
            }
            if conflicts {
                println!("[SELECT] skip tx: input conflict with already selected tx");
                continue;
            }

            total_fees = total_fees.saturating_add(tx.kernel.fee);
            selected.push(tx.clone());
        }

        println!("[SELECT] chose {} tx(s) (fees = {})", selected.len(), total_fees);
        (selected, total_fees)
    }




    pub fn add_block(&mut self, mut block: Block) -> PluribitResult<()> {
        // Ensure hash is computed
        if block.hash.is_empty() {
            block.hash = block.compute_hash();
        }
        
        // === 1. Basic Validation ===
        if block.height != self.current_height + 1 {
            return Err(PluribitError::InvalidBlock(format!("Expected height {}, got {}", self.current_height + 1, block.height)));
        }
        if block.prev_hash != self.get_latest_block().hash() {
            return Err(PluribitError::InvalidBlock("Parent hash mismatch".into()));
        }

        // Timestamp sanity: Median-Time-Past & future-drift checks
        let mtp = self.median_time_past(MTP_WINDOW);
        if block.timestamp < mtp {
            return Err(PluribitError::InvalidBlock("Block timestamp < median-time-past".into()));
        }
        let now_ms = js_sys::Date::now() as u64;
        if block.timestamp > now_ms.saturating_add(MAX_FUTURE_DRIFT_MS) {
            return Err(PluribitError::InvalidBlock("Block timestamp too far in the future".into()));
        }

       // === 2. Sequential-Lottery Validation ===
        let miner_pubkey = CompressedRistretto::from_slice(&block.miner_pubkey)
            .map_err(|_| PluribitError::InvalidBlock("Invalid miner public key format".into()))?
            .decompress()
            .ok_or_else(|| PluribitError::InvalidBlock("Invalid miner public key".into()))?;
            
        let vrf_input = &block.vdf_proof.y;
        if !vrf::verify_vrf(&miner_pubkey, vrf_input, &block.vrf_proof) {
            return Err(PluribitError::InvalidBlock("Invalid VRF proof".into()));
        }

        // UPDATED: Check VRF output against the block's *committed* threshold
        if block.vrf_proof.output >= block.vrf_threshold {
            return Err(PluribitError::InvalidBlock("VRF output does not meet threshold".into()));
        }

        let vdf = crate::vdf::VDF::new_with_default_modulus()?;
        let vdf_input = format!("{}{}{}", block.prev_hash, hex::encode(&block.miner_pubkey), block.pow_nonce);
        if !vdf.verify(vdf_input.as_bytes(), &block.vdf_proof)? {
            return Err(PluribitError::InvalidBlock("Invalid VDF proof".into()));
        }

        // UPDATED: Enforce VDF iterations equal to the block's *committed* setting.
        if block.vdf_proof.iterations != block.vdf_iterations {
            return Err(PluribitError::InvalidBlock("Unexpected VDF iterations for this block".into()));
        }
        
        // === 3. Aggregate Transaction and State Validation ===
        {
            // Lock the UTXO set once for all checks.
            let mut utxos = UTXO_SET.lock().unwrap();

            let mut sum_in_pts = RistrettoPoint::identity();
            let mut sum_out_pts = RistrettoPoint::identity();
            let mut sum_kernel_non_cb = RistrettoPoint::identity();
            let mut coinbase_kernel = RistrettoPoint::identity();
            let mut total_fees = 0u64;

            log(&format!("[BLOCK VALIDATION] Starting validation for block #{}", block.height));
            log(&format!("[BLOCK VALIDATION] Number of transactions: {}", block.transactions.len()));

            for (tx_idx, tx) in block.transactions.iter().enumerate() {
                log(&format!("[BLOCK VALIDATION] Processing transaction #{}", tx_idx));
                log(&format!("[BLOCK VALIDATION] TX#{}: Inputs: {}, Outputs: {}, Fee: {}", 
                    tx_idx, tx.inputs.len(), tx.outputs.len(), tx.kernel.fee));
                
                if !tx.kernel.verify_signature()? {
                    log(&format!("[BLOCK VALIDATION] TX#{}: Kernel signature verification FAILED", tx_idx));
                    return Err(PluribitError::InvalidKernelSignature);
                }
                log(&format!("[BLOCK VALIDATION] TX#{}: Kernel signature verified", tx_idx));
                
                let kernel_excess_pt = mimblewimble::kernel_excess_to_pubkey(&tx.kernel.excess)?;
                let is_coinbase = tx.kernel.fee == 0 && tx.inputs.is_empty();

                if is_coinbase {
                    coinbase_kernel += kernel_excess_pt;
                    debug_assert_eq!(tx.kernel.fee, 0);
                } else {
                    sum_kernel_non_cb += kernel_excess_pt;
                    total_fees = total_fees
                        .checked_add(tx.kernel.fee)
                        .ok_or(PluribitError::InvalidBlock("fee overflow".into()))?;
                }

                log(&format!("[BLOCK VALIDATION] TX#{}: Kernel excess: {}", 
                    tx_idx, hex::encode(&tx.kernel.excess)));
                
                for (inp_idx, inp) in tx.inputs.iter().enumerate() {
                    if !utxos.contains_key(&inp.commitment) {
                        log(&format!("[BLOCK VALIDATION] TX#{} Input#{}: NOT FOUND in UTXO set: {}", 
                            tx_idx, inp_idx, hex::encode(&inp.commitment)));
                        return Err(PluribitError::UnknownInput);
                    }
                    
                    {
                        let cb = crate::blockchain::COINBASE_INDEX.lock().unwrap();
                        if let Some(&born_at) = cb.get(&inp.commitment) {
                            let spend_height = block.height;
                            let need = born_at + COINBASE_MATURITY;
                            if spend_height < need {
                                return Err(PluribitError::InvalidBlock("Coinbase spend immature".into()));
                            }
                        }
                    }
                    
                    let c = CompressedRistretto::from_slice(&inp.commitment)
                        .map_err(|_| PluribitError::InvalidInputCommitment)?
                        .decompress()
                        .ok_or(PluribitError::InvalidInputCommitment)?;
                    sum_in_pts += c;
                    log(&format!("[BLOCK VALIDATION] TX#{} Input#{}: {}", 
                        tx_idx, inp_idx, hex::encode(&inp.commitment)));
                }
                
                for (out_idx, out) in tx.outputs.iter().enumerate() {
                    let commitment_pt = CompressedRistretto::from_slice(&out.commitment)
                        .map_err(|_| PluribitError::InvalidOutputCommitment)?;
                    let proof = RangeProof::from_bytes(&out.range_proof)
                        .map_err(|_| PluribitError::InvalidRangeProof)?;
                    if !mimblewimble::verify_range_proof(&proof, &commitment_pt) {
                        log(&format!("[BLOCK VALIDATION] TX#{} Output#{}: Range proof verification FAILED", 
                            tx_idx, out_idx));
                        return Err(PluribitError::InvalidRangeProof);
                    }

                    let c = commitment_pt.decompress().ok_or(PluribitError::InvalidOutputCommitment)?;
                    sum_out_pts += c;
                    log(&format!("[BLOCK VALIDATION] TX#{} Output#{}: {} (verified range proof)", 
                        tx_idx, out_idx, hex::encode(&out.commitment)));
                }
                
                log(&format!("[BLOCK VALIDATION] TX#{}: Processing complete", tx_idx));
            }

            let base_reward = self.calculate_block_reward(block.height, self.current_pow_difficulty);
            let total_reward = base_reward + total_fees;
            let reward_commitment = mimblewimble::commit(total_reward, &Scalar::from(0u64))?;
            
            let left_side  = sum_out_pts + sum_kernel_non_cb;
            let right_side = sum_in_pts  + coinbase_kernel + reward_commitment;

            log(&format!("[BLOCK VALIDATION] Final sum of inputs:           {}", hex::encode(sum_in_pts.compress().to_bytes())));
            log(&format!("[BLOCK VALIDATION] Final sum of outputs:          {}", hex::encode(sum_out_pts.compress().to_bytes())));
            log(&format!("[BLOCK VALIDATION] Sum kernel (non-CB):           {}", hex::encode(sum_kernel_non_cb.compress().to_bytes())));
            log(&format!("[BLOCK VALIDATION] Kernel (coinbase only):        {}", hex::encode(coinbase_kernel.compress().to_bytes())));
            log(&format!("[BLOCK VALIDATION] reward commitment (base+fees): {} (base={}, fees={})", hex::encode(reward_commitment.compress().to_bytes()), base_reward, total_fees));
            log(&format!("[BLOCK VALIDATION] LHS (Out + K_nonCB):           {}", hex::encode(left_side.compress().to_bytes())));
            log(&format!("[BLOCK VALIDATION] RHS (In + K_CB + Reward):      {}", hex::encode(right_side.compress().to_bytes())));

            if left_side != right_side {
                log("[BLOCK VALIDATION] BALANCE CHECK FAILED!");
                log(&format!("[BLOCK VALIDATION] Total fees in block: {}", total_fees));
                log(&format!("[BLOCK VALIDATION] Base reward: {}", base_reward));
                return Err(PluribitError::Imbalance);
            }

            log("[BLOCK VALIDATION] Balance check PASSED");

            for tx in &block.transactions {
                for inp in &tx.inputs {
                    utxos.remove(&inp.commitment);
                    let mut cb = crate::blockchain::COINBASE_INDEX.lock().unwrap();
                    cb.remove(&inp.commitment);
                }

                let is_coinbase_tx = tx.kernel.fee == 0 && tx.inputs.is_empty();
                for out in &tx.outputs {
                    utxos.insert(out.commitment.clone(), out.clone());
                    if is_coinbase_tx {
                        let mut cb = crate::blockchain::COINBASE_INDEX.lock().unwrap();
                        cb.insert(out.commitment.clone(), block.height);
                    }
                }
            }
            
            log("[BLOCK VALIDATION] UTXO set updated successfully");
        }
        
        // === 4. Update Chain State ===
        // Note: total_work is calculated using get_chain_work on a slice of blocks during fork choice,
        // so we don't need to accumulate it here. We'll update the logic to re-calculate it if needed.
        // For simplicity, we can set it based on the new chain.
        self.blocks.push(block.clone());
        self.total_work = Self::get_chain_work(&self.blocks);
        self.block_by_hash.insert(block.hash(), block.clone());
        self.current_height += 1;

        // === 5. Difficulty Adjustment ===
        if self.current_height > 0 && self.current_height % constants::DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
            self.adjust_difficulty();
        }

        {
            let mut pool = crate::TX_POOL.lock().unwrap_or_else(|p| p.into_inner());
            let before = pool.pending.len();

            pool.pending.retain(|p|
                !block.transactions.iter().any(|t| t.kernel.excess == p.kernel.excess)
            );
            
            let utxos = crate::blockchain::UTXO_SET.lock().unwrap_or_else(|p| p.into_inner());
            pool.pending.retain(|p|
                p.inputs.iter().all(|i| utxos.contains_key(&i.commitment))
            );
            
            pool.fee_total = pool.pending.iter().map(|t| t.kernel.fee).sum();
            crate::log(&format!(
                "[RUST] Mempool: removed {} included/invalid txs ({} → {})",
                before - pool.pending.len(), before, pool.pending.len()
            ));
        }
        Ok(())
    }
    
    fn adjust_difficulty(&mut self) {
        let window = constants::DIFFICULTY_ADJUSTMENT_INTERVAL as usize;
        if self.blocks.len() < window + 1 {
            return;
        }
    
        let end_block = self.get_latest_block();
        let start_block = &self.blocks[self.blocks.len() - window];
    
        let actual_time_ms = end_block.timestamp.saturating_sub(start_block.timestamp);
        let expected_time_ms = constants::DIFFICULTY_ADJUSTMENT_INTERVAL * constants::TARGET_BLOCK_TIME * 1000;
        if actual_time_ms == 0 {
            return;
        }
    
        let mut ratio = actual_time_ms as f64 / expected_time_ms as f64;
        ratio = ratio.max(0.25).min(4.0);
    
        let new_vdf_iterations = ((self.current_vdf_iterations as f64) / ratio).round() as u64;
        let new_vdf_iterations = new_vdf_iterations.max(constants::MIN_VDF_ITERATIONS).min(constants::MAX_VDF_ITERATIONS);
        
        let new_pow_difficulty_f64 = (self.current_pow_difficulty as f64) / ratio;
        let new_pow_difficulty = (new_pow_difficulty_f64.round() as u8).max(1).min(64);
    
        let mut threshold_bigint = BigUint::from_bytes_be(&self.current_vrf_threshold);
        let ratio_numerator = (ratio * 1_000_000.0).round() as u128;
        let ratio_denominator = 1_000_000u128;
        threshold_bigint = (threshold_bigint * ratio_numerator) / ratio_denominator;
        
        let max_threshold = BigUint::from_bytes_be(&VRF_MAX_THRESHOLD);
        if threshold_bigint > max_threshold {
            threshold_bigint = max_threshold;
        }
        
        let min_threshold = BigUint::from_bytes_be(&VRF_MIN_THRESHOLD);
        if threshold_bigint < min_threshold {
            threshold_bigint = min_threshold;
        }
        
        let new_vrf_threshold_bytes = threshold_bigint.to_bytes_be();
        let mut new_vrf_threshold = [0u8; 32];
        let pad_len = 32_usize.saturating_sub(new_vrf_threshold_bytes.len());
        new_vrf_threshold[pad_len..].copy_from_slice(&new_vrf_threshold_bytes);

        log(&format!(
            "[DIFFICULTY] Adjustment at height {}: Actual Time: {:.2}s, Expected: {:.2}s, Ratio: {:.2}",
            self.current_height,
            actual_time_ms as f64 / 1000.0,
            expected_time_ms as f64 / 1000.0,
            ratio
        ));
        log(&format!(
            "[DIFFICULTY] VDF Iterations: {} -> {}",
            self.current_vdf_iterations, new_vdf_iterations
        ));
        log(&format!(
            "[DIFFICULTY] PoW Difficulty: {} -> {}",
            self.current_pow_difficulty, new_pow_difficulty
        ));
        log(&format!(
            "[DIFFICULTY] VRF Threshold: {}... -> {}...",
            hex::encode(&self.current_vrf_threshold[..4]), hex::encode(&new_vrf_threshold[..4])
        ));

        self.current_vdf_iterations = new_vdf_iterations;
        self.current_pow_difficulty = new_pow_difficulty;
        self.current_vrf_threshold = new_vrf_threshold;
    }

    pub fn calculate_block_reward(&self, height: u64, pow_difficulty: u8) -> u64 {
        let base_reward = get_current_base_reward(height);
        let pow_bonus = if pow_difficulty > 10 {
            (pow_difficulty as u64 - 10) * 100_000
        } else { 0 };
        base_reward + pow_bonus
    }
    
    // Keep these existing helper methods
    pub fn can_accept_block(&self, block: &Block) -> Result<(), PluribitError> {
        if block.height != self.current_height + 1 {
            return Err(PluribitError::InvalidBlock(format!(
                "Expected height {}, got {}",
                self.current_height + 1,
                block.height
            )));
        }
        
        if block.prev_hash != self.get_latest_block().hash() {
            return Err(PluribitError::InvalidBlock(
                "Block does not extend current chain tip".to_string()
            ));
        }
        
        Ok(())
    }
    
    pub fn create_utxo_snapshot(&self) -> PluribitResult<crate::UTXOSnapshot> {
        let mut current_utxos: HashMap<Vec<u8>, TransactionOutput> = HashMap::new();
        let mut total_kernels = 0u64;
        
        for block in &self.blocks {
            for tx in &block.transactions {
                for input in &tx.inputs {
                    current_utxos.remove(&input.commitment);
                }
                for output in &tx.outputs {
                    current_utxos.insert(output.commitment.clone(), output.clone());
                }
                total_kernels += 1;
            }
        }
        
        let mut utxo_vec: Vec<(Vec<u8>, TransactionOutput)> = current_utxos.into_iter().collect();
        utxo_vec.sort_by(|a, b| a.0.cmp(&b.0));
        
        let merkle_root = Block::calculate_utxo_merkle_root(&utxo_vec);
        
        Ok(crate::UTXOSnapshot {
            height: self.current_height,
            prev_block_hash: self.get_latest_block().hash(),
            utxos: utxo_vec,
            timestamp: js_sys::Date::now() as u64,
            merkle_root,
            total_kernels,
        })
    }
    
    pub fn restore_from_snapshot(&mut self, snapshot: crate::UTXOSnapshot) -> PluribitResult<()> {
        let calculated_root = Block::calculate_utxo_merkle_root(&snapshot.utxos);
        if calculated_root != snapshot.merkle_root {
            return Err(PluribitError::InvalidBlock("UTXO snapshot merkle root mismatch".to_string()));
        }
        
        let mut utxo_set = UTXO_SET.lock().unwrap();
        utxo_set.clear();
        
        for (commitment, output) in &snapshot.utxos {
            utxo_set.insert(commitment.clone(), output.clone());
        }
        
        let snapshot_block = Block {
            height: snapshot.height,
            prev_hash: snapshot.prev_block_hash.clone(),
            transactions: vec![],
            timestamp: snapshot.timestamp,
            pow_nonce: 0,
            vrf_proof: VrfProof::default(),
            vdf_proof: VDFProof::default(),
            miner_pubkey: [0u8; 32],
            tx_merkle_root: [0u8; 32],
            hash: String::new(),
            vdf_iterations: constants::INITIAL_VDF_ITERATIONS,
            vrf_threshold: constants::DEFAULT_VRF_THRESHOLD,
        };
                
        self.blocks = vec![self.blocks[0].clone(), snapshot_block];
        self.current_height = snapshot.height;
        
        Ok(())
    }
    
    pub fn prune_to_horizon(&mut self, keep_recent: u64) -> PluribitResult<()> {
        if self.current_height <= keep_recent {
            return Ok(());
        }
        
        let horizon_height = self.current_height - keep_recent;
        
        let mut horizon_utxos: HashMap<Vec<u8>, TransactionOutput> = HashMap::new();
        
        for i in 0..=horizon_height as usize {
            if i >= self.blocks.len() {
                break;
            }
            
            let block = &self.blocks[i];
            for tx in &block.transactions {
                for input in &tx.inputs {
                    horizon_utxos.remove(&input.commitment);
                }
                for output in &tx.outputs {
                    horizon_utxos.insert(output.commitment.clone(), output.clone());
                }
            }
        }
        
        let mut pruned_chain = vec![self.blocks[0].clone()];
        pruned_chain.extend_from_slice(&self.blocks[(horizon_height as usize + 1)..]);
        
        self.blocks = pruned_chain;
        
        self.block_by_hash.clear();
        for block in &self.blocks {
            self.block_by_hash.insert(block.hash(), block.clone());
        }
        
        Ok(())
    }
}

pub fn get_current_base_reward(height: u64) -> u64 {
    let height_in_era = height % crate::constants::REWARD_RESET_INTERVAL;
    let num_halvings = height_in_era / crate::constants::HALVING_INTERVAL;
    if num_halvings >= 64 { 0 } else { crate::constants::INITIAL_BASE_REWARD >> num_halvings }
}



   
    
#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;
    use crate::transaction::{Transaction, TransactionInput, TransactionOutput, TransactionKernel};
    use crate::mimblewimble;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::traits::Identity;
    use rand::thread_rng;

    #[test]
    fn test_kernel_excess_with_fee() {
        // Test that kernel excess correctly includes fee
        let blinding = Scalar::from(123u64);
        let fee = 100u64;
        
        let kernel = TransactionKernel::new(blinding, fee, 0).unwrap();
        let excess_point = mimblewimble::kernel_excess_to_pubkey(&kernel.excess).unwrap();
        
        // The excess should be: blinding * B_blinding + fee * B
        let expected = mimblewimble::PC_GENS.commit(Scalar::from(fee), blinding);
        
        assert_eq!(excess_point, expected, "Kernel excess should include fee commitment");
    }

    #[test]
    fn test_simple_transaction_balance() {
        // Test a simple transaction balances
        let input_value = 1000u64;
        let output_value = 900u64;
        let fee = 100u64;
        
        let input_blinding = Scalar::from(111u64);
        let output_blinding = Scalar::from(222u64);
        
        let input_commitment = mimblewimble::commit(input_value, &input_blinding).unwrap();
        let output_commitment = mimblewimble::commit(output_value, &output_blinding).unwrap();
        
        let kernel_blinding = input_blinding - output_blinding;
        let kernel_excess = mimblewimble::PC_GENS.commit(Scalar::from(fee), kernel_blinding);
        
        // Check: Input = Output + KernelExcess
        assert_eq!(
            input_commitment,
            output_commitment + kernel_excess,
            "Transaction should balance"
        );
    }

    #[test]
    fn test_coinbase_transaction_balance() {
        // Test that coinbase transaction balances correctly
        let reward = 50_000_000u64;
        let coinbase_blinding = Scalar::from(999u64);
        
        let coinbase_output = mimblewimble::commit(reward, &coinbase_blinding).unwrap();
        let coinbase_kernel_excess = mimblewimble::PC_GENS.commit(Scalar::from(0u64), coinbase_blinding);
        let reward_commitment = mimblewimble::commit(reward, &Scalar::from(0u64)).unwrap();
        
        // Check: CoinbaseOutput = KernelExcess + Reward
        assert_eq!(
            coinbase_output,
            coinbase_kernel_excess + reward_commitment,
            "Coinbase should balance"
        );
    }

    #[test]
    fn test_block_with_single_coinbase() {
        // Test block with only coinbase
        let base_reward = 50_000_000u64;
        let miner_wallet = Wallet::new();
        
        let coinbase_tx = Transaction::create_coinbase(vec![
            (miner_wallet.scan_pub.compress().to_bytes().to_vec(), base_reward)
        ]).unwrap();
        
        let mut sum_outputs = RistrettoPoint::identity();
        for out in &coinbase_tx.outputs {
            sum_outputs += CompressedRistretto::from_slice(&out.commitment).unwrap()
                .decompress().unwrap();
        }
        
        let kernel_excess = mimblewimble::kernel_excess_to_pubkey(&coinbase_tx.kernel.excess).unwrap();
        let reward_commitment = mimblewimble::commit(base_reward, &Scalar::from(0u64)).unwrap();
        
        assert_eq!(
            sum_outputs,
            kernel_excess + reward_commitment,
            "Coinbase-only block should balance"
        );
    }

#[test]
fn test_block_with_coinbase_and_transaction() {
    // Simplified test with controlled values
    let miner_wallet = Wallet::new();
    
    // Create a simple transaction
    let tx_input_value = 1000u64;
    let tx_output_value = 900u64;
    let tx_fee = 100u64;
    
    let tx_input_blinding = Scalar::from(111u64);
    let tx_output_blinding = Scalar::from(222u64);
    let tx_kernel_blinding = tx_input_blinding - tx_output_blinding;
    
    let regular_tx = Transaction {
        inputs: vec![TransactionInput {
            commitment: mimblewimble::commit(tx_input_value, &tx_input_blinding).unwrap()
                .compress().to_bytes().to_vec(),
            merkle_proof: None,
            source_height: 0,
        }],
        outputs: vec![TransactionOutput {
            commitment: mimblewimble::commit(tx_output_value, &tx_output_blinding).unwrap()
                .compress().to_bytes().to_vec(),
            range_proof: vec![0; 675], // Dummy proof
            ephemeral_key: None,
            stealth_payload: None,
        }],
        kernel: TransactionKernel::new(tx_kernel_blinding, tx_fee, 0).unwrap(),
    };
    
    // IMPORTANT: Coinbase gets base reward + all fees from the block!
    let base_reward = 50_000_000u64;
    let total_reward = base_reward + tx_fee; 
    let coinbase_tx = Transaction::create_coinbase(vec![
        (miner_wallet.scan_pub.compress().to_bytes().to_vec(), total_reward)
    ]).unwrap();
    
    // Calculate sums
    let mut sum_in  = RistrettoPoint::identity();
    let mut sum_out = RistrettoPoint::identity();
    let mut k_noncb = RistrettoPoint::identity();
    let mut k_cb    = RistrettoPoint::identity();

    for tx in &[coinbase_tx.clone(), regular_tx.clone()] {
        let k = mimblewimble::kernel_excess_to_pubkey(&tx.kernel.excess).unwrap();
        let is_coinbase = tx.kernel.fee == 0 && tx.inputs.is_empty();
        if is_coinbase { k_cb += k } else { k_noncb += k }

        for inp in &tx.inputs {
            sum_in += CompressedRistretto::from_slice(&inp.commitment).unwrap()
                .decompress().unwrap();
        }
        for out in &tx.outputs {
            sum_out += CompressedRistretto::from_slice(&out.commitment).unwrap()
                .decompress().unwrap();
        }
    }

    // IMPORTANT: Reward commitment must be base + fees here
    let base_reward = 50_000_000u64;
    let total_reward = base_reward + tx_fee;
    let reward_commitment = mimblewimble::commit(total_reward, &Scalar::from(0u64)).unwrap();

    // Check the correct block equation for kernels that include fee*B:
    assert_eq!(
        sum_out + k_noncb,
        sum_in + k_cb + reward_commitment,
        "Block with transaction should balance"
    );
}

#[test]
fn test_manual_block_validation_logic() {
    use rand::thread_rng;
    
    // Create wallets
    let miner_wallet = Wallet::new();
    
    // Setup initial UTXO
    let initial_value = 100_000;
    let initial_blinding = Scalar::random(&mut thread_rng());
    let initial_commitment = mimblewimble::commit(initial_value, &initial_blinding).unwrap();

    // Create a transaction with fee
    let send_amount = 600;
    let fee = 100;
    let change_amount = initial_value - send_amount - fee;
    
    let send_blinding = Scalar::random(&mut thread_rng());
    let change_blinding = Scalar::random(&mut thread_rng());
    
    let send_commitment = mimblewimble::commit(send_amount, &send_blinding).unwrap();
    let change_commitment = mimblewimble::commit(change_amount, &change_blinding).unwrap();
    
    let (send_proof, _) = mimblewimble::create_range_proof(send_amount, &send_blinding).unwrap();
    let (change_proof, _) = mimblewimble::create_range_proof(change_amount, &change_blinding).unwrap();
    
    // Kernel blinding: inputs - outputs
    let kernel_blinding = initial_blinding - send_blinding - change_blinding;
    let kernel = TransactionKernel::new(kernel_blinding, fee, 0).unwrap();
    
    let regular_tx = Transaction {
        inputs: vec![TransactionInput {
            commitment: initial_commitment.compress().to_bytes().to_vec(),
            merkle_proof: None,
            source_height: 0,
        }],
        outputs: vec![
            TransactionOutput {
                commitment: send_commitment.compress().to_bytes().to_vec(),
                range_proof: send_proof.to_bytes(),
                ephemeral_key: None,
                stealth_payload: None,
            },
            TransactionOutput {
                commitment: change_commitment.compress().to_bytes().to_vec(),
                range_proof: change_proof.to_bytes(),
                ephemeral_key: None,
                stealth_payload: None,
            }
        ],
        kernel,
    };
    
    // Coinbase gets base reward + all fees collected!
    let base_reward = 50_000_000;
    let total_coinbase_amount = base_reward + fee;  // include fees in the coinbase outputs
    let coinbase_tx = Transaction::create_coinbase(vec![
        (miner_wallet.scan_pub.compress().to_bytes().to_vec(), total_coinbase_amount)
    ]).unwrap();
    
    // Validate (split kernel excess into non-coinbase vs coinbase)
    let mut sum_in  = RistrettoPoint::identity();
    let mut sum_out = RistrettoPoint::identity();
    let mut k_noncb = RistrettoPoint::identity();
    let mut k_cb    = RistrettoPoint::identity();
    
    for tx in &[coinbase_tx, regular_tx] {
        let k = mimblewimble::kernel_excess_to_pubkey(&tx.kernel.excess).unwrap();
        let is_coinbase = tx.kernel.fee == 0 && tx.inputs.is_empty();
        if is_coinbase { k_cb += k } else { k_noncb += k }
        
        for inp in &tx.inputs {
            sum_in += CompressedRistretto::from_slice(&inp.commitment).unwrap()
                .decompress().unwrap();
        }
        
        for out in &tx.outputs {
            sum_out += CompressedRistretto::from_slice(&out.commitment).unwrap()
                .decompress().unwrap();
        }
    }
    
    // Since kernel excess already includes fee*B for non-coinbase txs,
    // the reward commitment must carry (base + fees).
    let reward_commitment = mimblewimble::commit(total_coinbase_amount, &Scalar::from(0u64)).unwrap();
    
    // Block balance equation:
    // ΣOut + ΣK(non-coinbase) == ΣIn + K(coinbase) + Commit(base + fees, 0)
    assert_eq!(
        sum_out + k_noncb,
        sum_in + k_cb + reward_commitment,
        "Block balance equation must hold"
    );
}


    
    #[test]
fn debug_transaction_creation() {
    let wallet = Wallet::new();
    let base_reward = 50_000_000u64;
    
    let coinbase_tx = Transaction::create_coinbase(vec![
        (wallet.scan_pub.compress().to_bytes().to_vec(), base_reward)
    ]).unwrap();
    
    // Debug print the transaction details
    println!("Coinbase transaction:");
    println!("  Outputs: {}", coinbase_tx.outputs.len());
    for (i, out) in coinbase_tx.outputs.iter().enumerate() {
        println!("    Output {}: commitment = {}", i, hex::encode(&out.commitment));
    }
    println!("  Kernel excess: {}", hex::encode(&coinbase_tx.kernel.excess));
    println!("  Kernel fee: {}", coinbase_tx.kernel.fee);
    
    // Manually verify the balance
    let output_point = CompressedRistretto::from_slice(&coinbase_tx.outputs[0].commitment)
        .unwrap().decompress().unwrap();
    let kernel_point = mimblewimble::kernel_excess_to_pubkey(&coinbase_tx.kernel.excess).unwrap();
    let reward_point = mimblewimble::commit(base_reward, &Scalar::from(0u64)).unwrap();
    
    println!("\nBalance check:");
    println!("  Output point: {:?}", output_point.compress());
    println!("  Kernel point: {:?}", kernel_point.compress());
    println!("  Reward point: {:?}", reward_point.compress());
    println!("  Kernel + Reward: {:?}", (kernel_point + reward_point).compress());
    
    assert_eq!(output_point, kernel_point + reward_point, "Should balance");
}
}


