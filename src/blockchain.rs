// src/blockchain.rs
use crate::block::Block;
use crate::transaction::{Transaction, TransactionOutput}; 
use crate::load_block_from_db;
use crate::error::{PluribitError, PluribitResult};
use crate::vrf;
use crate::constants;
use crate::wasm_types::WasmU64;
use crate::mimblewimble;
use crate::log;
use bulletproofs::RangeProof; // Added for range proof verification
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar; // Added for creating commitments
use curve25519_dalek::traits::Identity; // Added for RistrettoPoint::identity()
use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use crate::constants::{COINBASE_MATURITY, DEFAULT_VRF_THRESHOLD, INITIAL_VDF_ITERATIONS, MAX_FUTURE_DRIFT_MS};
use crate::save_coinbase_index_to_db;
use crate::{save_utxo_to_db, delete_utxo_from_db, save_block_filter_to_db, delete_coinbase_index_from_db};

lazy_static! {
    pub static ref UTXO_SET: Mutex<HashMap<Vec<u8>, TransactionOutput>> =
        Mutex::new(HashMap::new());
    
    // commitment -> block_height (only for coinbase outputs)
    pub static ref COINBASE_INDEX: Mutex<HashMap<Vec<u8>, u64>> =
        Mutex::new(HashMap::new());

    pub static ref BLOCKCHAIN: Mutex<Blockchain> = Mutex::new(Blockchain::new());
}

pub struct AuditStats {
    pub total_supply: u128,
    pub valid_blocks: u64,
    pub errors: u64,
    pub utxo_count: usize,
}

pub async fn perform_deep_audit<F>(mut log_callback: F) -> PluribitResult<AuditStats>
where
    F: FnMut(String),
{
    // 1. Get Chain Tip (Brief lock)
    let tip_height = {
        let chain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        *chain.current_height
    };

    let mut total_supply_checked: u128 = 0;
    let mut valid_blocks = 0;
    let mut errors = 0;

    // 2. Iterate through EVERY block
    for h in 1..=tip_height {
        if h % 1000 == 0 {
            log_callback(format!("... audited {} / {} blocks ...", h, tip_height));
        }

        // Async DB load (no lock held)
        let block = match crate::load_block_from_db(h).await {
            Ok(Some(b)) => b,
            _ => {
                log_callback(format!("❌ Missing block data at height {}", h));
                errors += 1;
                continue;
            }
        };

        // 3. Re-verify MimbleWimble Balance
        let mut sum_in = RistrettoPoint::identity();
        let mut sum_out = RistrettoPoint::identity();
        let mut sum_kernel_non_cb = RistrettoPoint::identity();
        let mut coinbase_kernel = RistrettoPoint::identity();
        let mut total_fees = 0u64;

        for tx in &block.transactions {
            // Sum Inputs
            for input in &tx.inputs {
                if let Ok(p) = CompressedRistretto::from_slice(&input.commitment).map_err(|_|()).and_then(|c| c.decompress().ok_or(())) {
                    sum_in += p;
                } else {
                    log_callback(format!("Invalid input commitment in block {}", h));
                    errors += 1;
                }
            }

            // Sum Outputs
            for output in &tx.outputs {
                if let Ok(p) = CompressedRistretto::from_slice(&output.commitment).map_err(|_|()).and_then(|c| c.decompress().ok_or(())) {
                    sum_out += p;
                } else {
                    log_callback(format!("Invalid output commitment in block {}", h));
                    errors += 1;
                }
            }

            // Sum Kernels
            let mut tx_excess = RistrettoPoint::identity();
            for k in &tx.kernels {
                if let Ok(p) = mimblewimble::kernel_excess_to_pubkey(&k.excess) {
                    tx_excess += p;
                }
            }
            
            if tx.inputs.is_empty() { // Coinbase tx
                coinbase_kernel += tx_excess;
            } else {
                sum_kernel_non_cb += tx_excess;
                total_fees += tx.total_fee();
            }
        }

        let base_reward = get_current_base_reward(h);
        total_supply_checked += base_reward as u128;

        let total_reward = base_reward + total_fees;
        // Verify commitment matches: Reward * H + 0 * G
        let reward_commit = mimblewimble::commit(total_reward, &Scalar::from(0u64))?;

        let left_side = sum_out + sum_kernel_non_cb;
        let right_side = sum_in + coinbase_kernel + reward_commit;

        if left_side != right_side {
            log_callback(format!("❌ Balance mismatch at height {}! Money created out of thin air?", h));
            errors += 1;
        } else {
            valid_blocks += 1;
        }
    }

    // 4. Get UTXO Count (Brief lock)
    let utxo_count = {
        let utxos = UTXO_SET.lock().unwrap_or_else(|p| p.into_inner());
        utxos.len()
    };

    Ok(AuditStats {
        total_supply: total_supply_checked,
        valid_blocks,
        errors,
        utxo_count,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockFilterEntry {
    pub ephemeral_key: Vec<u8>,
    pub view_tag: Vec<u8>,
    pub commitment: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blockchain {
    //  We only store the hash of the chain tip.
    pub tip_hash: String,
    
    // These fields represent the current state of the chain tip.
    pub current_height: WasmU64,
    
    // difficulty and work tracking
    pub total_work: WasmU64,
    pub current_vrf_threshold: [u8; 32],
    pub current_vdf_iterations: WasmU64,
    
    //compact block filters
    pub block_filters: HashMap<u64, Vec<BlockFilterEntry>>,
}

impl Blockchain {


    pub fn new() -> Self {
        let genesis = Block::genesis();
        
        Blockchain {
            // ADDED: Store only the genesis hash as the initial tip.
            tip_hash: genesis.hash(),
            
            // KEPT: Initialize state with genesis values.
            current_height: WasmU64::from(0),
            total_work: WasmU64::from(0),
            current_vrf_threshold:  DEFAULT_VRF_THRESHOLD,
            current_vdf_iterations: WasmU64::from(INITIAL_VDF_ITERATIONS),
            block_filters: HashMap::new(),
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

            // DIAGNOSTIC LOGGING
         //   log(&format!("[WORK] Block {}: vrf_threshold={}, vdf_iters={}, vrf_work={}", 
         //       b.height, 
         //       hex::encode(&b.vrf_threshold[..4]),
         //       b.vdf_iterations,
         //       vrf_w.to_string()));

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

    pub fn get_total_work(&self) -> WasmU64 {
        self.total_work.clone()
    }
    


    /// Simple selector: verify signature + avoid input conflicts.
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

        // --- OPTIMIZATION START: Create UTXO snapshot ONCE ---
        // We collect all valid input commitments into a HashSet for O(1) lookups
        // This prevents locking the global UTXO_SET for every single transaction in the loop.
        let valid_utxo_commitments: std::collections::HashSet<Vec<u8>> = {
            let utxos = crate::blockchain::UTXO_SET.lock().unwrap();
            utxos.keys().cloned().collect()
        };
        // --- OPTIMIZATION END ---

        for tx in pool.iter() {
            // 1) Basic sanity: kernel signature
            if let Err(e) = tx.verify_signature() {     
                // println!("[SELECT] skip tx: bad signature ({e})");
                continue;
            }

            // 2) Prevent double-spend inside the block
            let mut conflicts = false;
            for inp in &tx.inputs {
                let key = to_hex(&inp.commitment);
                if !used_inputs.insert(key) { // already seen → conflict
                    conflicts = true;
                    break;
                }
            }
            if conflicts {
                // println!("[SELECT] skip tx: input conflict with already selected tx");
                continue;
            }

            // 3) Verify inputs exist in our snapshot
            // We use the local HashSet instead of locking the Mutex
            if !tx.inputs.iter().all(|inp| valid_utxo_commitments.contains(&inp.commitment)) {
                // println!("[SELECT] skip tx: input(s) no longer in UTXO set");
                continue;
            }

            total_fees = total_fees.saturating_add(tx.total_fee());
            selected.push(tx.clone());
        }

      //  println!("[SELECT] chose {} tx(s) (fees = {})", selected.len(), total_fees);
        (selected, total_fees)
    }




    pub async fn add_block(&mut self, mut block: Block, expected_vrf_threshold: [u8; 32], expected_vdf_iterations: WasmU64) -> PluribitResult<()> {
        // Ensure hash is computed
        if block.hash.is_empty() {
            block.hash = block.compute_hash();
        }
        
        // === 1. Basic Validation ===
        if *block.height != *self.current_height + 1 {
            return Err(PluribitError::InvalidBlock(format!("Expected height {}, got {}", *self.current_height + 1, *block.height)));
        }
        if block.prev_hash != self.tip_hash {
            return Err(PluribitError::InvalidBlock("Parent hash mismatch".into()));
        }

        // Enhanced timestamp validation - ensure monotonic time
        if *block.height > 0 {
            let parent_result = load_block_from_db(*block.height - 1).await
                .map_err(|e| PluribitError::StateError(format!("DB error loading parent: {:?}", e)));
            if let Some(parent_block) = parent_result? {
                if *block.timestamp <= *parent_block.timestamp {
                    return Err(PluribitError::InvalidBlock(
                        "Block timestamp must be greater than parent".into()
                    ));
                }
            }
        }

        let now_ms = js_sys::Date::now() as u64;
        if *block.timestamp > now_ms.saturating_add(MAX_FUTURE_DRIFT_MS) {
            return Err(PluribitError::InvalidBlock("Block timestamp too far in the future".into()));
        }

        // This ensures the block is in its canonical, compact form before validation.
        block.apply_cut_through()?;

        // === 1b. Merkle root consistency ===
        let expected_root = block.calculate_tx_merkle_root();
        if block.tx_merkle_root != expected_root {
            return Err(PluribitError::InvalidBlock("Bad tx_merkle_root".into()));
        }

        // CRITICAL FIX #8: Validate transaction ordering within block
        let mut prev_tx_timestamp = 0u64;
        for (idx, tx) in block.transactions.iter().enumerate() {
            // Skip coinbase (first transaction)
            if idx == 0 && tx.inputs.is_empty() {
                continue;
            }
            
            // Transactions must be ordered by timestamp
            if *tx.timestamp < prev_tx_timestamp {
                return Err(PluribitError::InvalidBlock(
                    format!("Transaction {} has timestamp {} before previous transaction {}",
                        idx, *tx.timestamp, prev_tx_timestamp)
                ));
            }
            
            prev_tx_timestamp = *tx.timestamp;
        }


       // === 2. Sequential-Lottery Validation ===
        let miner_pubkey = CompressedRistretto::from_slice(&block.miner_pubkey)
            .map_err(|_| PluribitError::InvalidBlock("Invalid miner public key format".into()))?
            .decompress()
            .ok_or_else(|| PluribitError::InvalidBlock("Invalid miner public key".into()))?;

        // === 2a. Enforce epoch params ===
        // RATIONALE: We must validate difficulty parameters BEFORE accepting the block
        // This prevents attacks where miners could manipulate difficulty by submitting
        // blocks with incorrect parameters that get accepted before validation
        if block.vrf_threshold != expected_vrf_threshold {
            return Err(PluribitError::InvalidBlock(format!(
                "Invalid VRF threshold. Expected {}, got {}",
                hex::encode(expected_vrf_threshold), hex::encode(block.vrf_threshold)
            )));
        }
        if block.vdf_iterations != expected_vdf_iterations {
            return Err(PluribitError::InvalidBlock(format!(
                "Invalid VDF iterations. Expected {}, got {}",
                *expected_vdf_iterations, *block.vdf_iterations
            )));
        }

            
        let vrf_input = &block.vdf_proof.y;
        if !vrf::verify_vrf(&miner_pubkey, vrf_input, &block.vrf_proof) {
            return Err(PluribitError::InvalidBlock("Invalid VRF proof".into()));
        }

        // UPDATED: Check VRF output against the block's *committed* threshold
        if block.vrf_proof.output >= block.vrf_threshold {
            return Err(PluribitError::InvalidBlock("VRF output does not meet threshold".into()));
        }

        // CRITICAL FIX #10: Verify VDF input binds to this specific block height
        let vdf = crate::vdf::VDF::new_with_default_modulus()?;
        let vdf_input = format!("{}{}{}{}", 
            *block.height,           // FIX #10: Include height
            block.prev_hash, 
            hex::encode(&block.miner_pubkey), 
            block.lottery_nonce
        );
        if !vdf.verify(vdf_input.as_bytes(), &block.vdf_proof)? {
            return Err(PluribitError::InvalidBlock("Invalid VDF proof".into()));
        }

        // UPDATED: Enforce VDF iterations equal to the block's *committed* setting.
        if *block.vdf_proof.iterations != *block.vdf_iterations {
            return Err(PluribitError::InvalidBlock("Unexpected VDF iterations for this block".into()));
        }
        
        // === 3. Aggregate Transaction and State Validation ===
        // Collect UTXO changes WITHOUT holding locks during async calls
        let mut utxos_to_add = Vec::new();
        let mut utxos_to_remove = Vec::new();
        let mut coinbase_to_add = Vec::new();              
        {
            // FIX: Handle poisoned mutexes gracefully
            let utxos = UTXO_SET.lock().unwrap_or_else(|p| p.into_inner());
            
            let mut sum_in_pts = RistrettoPoint::identity();
            let mut sum_out_pts = RistrettoPoint::identity();
            let mut sum_kernel_non_cb = RistrettoPoint::identity();
            let mut coinbase_kernel = RistrettoPoint::identity();
            let mut total_fees = 0u64;

         //   log(&format!("[BLOCK VALIDATION] Starting validation for block #{}", block.height));
         //   log(&format!("[BLOCK VALIDATION] Number of transactions: {}", block.transactions.len()));
            for (tx_idx, tx) in block.transactions.iter().enumerate() {
          //      log(&format!("[BLOCK VALIDATION] Processing transaction #{}", tx_idx));
                let tx_fee = tx.total_fee();
          //      log(&format!("[BLOCK VALIDATION] TX#{}: Inputs: {}, Outputs: {}, Fee(total): {}",
          //          tx_idx, tx.inputs.len(), tx.outputs.len(), tx_fee));
                if !tx.verify_signature()? {
                    log(&format!("[BLOCK VALIDATION] TX#{}: Kernel signature verification FAILED", tx_idx));
                    return Err(PluribitError::InvalidKernelSignature); // [cite: 1968]
                }
         //      log(&format!("[BLOCK VALIDATION] TX#{}: All kernel signatures verified", tx_idx)); 

                // --- START: MODIFIED RANGE PROOF VERIFICATION ---
                if !tx.outputs.is_empty() { // Only verify if there are outputs
            //        log(&format!("[BLOCK VALIDATION] TX#{}: Verifying aggregated range proof...", tx_idx));
                    // 1. Collect all output commitments for this transaction
                    let commitments_result: Result<Vec<_>,_> = tx.outputs.iter()
                        .map(|output| CompressedRistretto::from_slice(&output.commitment))
                        .collect();

                    let commitments = match commitments_result {
                        Ok(c) => c,
                        Err(_) => {
                             log(&format!("[BLOCK VALIDATION] TX#{}: Failed to parse one or more output commitments", tx_idx));
                             return Err(PluribitError::InvalidOutputCommitment);
                        }
                    };

                    // 2. Parse the aggregated range proof from the transaction
                    let aggregated_proof = match RangeProof::from_bytes(&tx.aggregated_range_proof) { 
                        Ok(p) => p,
                        Err(_) => {
                            log(&format!("[BLOCK VALIDATION] TX#{}: Failed to parse aggregated range proof bytes", tx_idx));
                            return Err(PluribitError::InvalidRangeProof); 
                        }
                    };

                    // 3. Verify the single aggregated proof against all commitments
                    if !mimblewimble::verify_aggregated_range_proof(&aggregated_proof, &commitments) { 
                        log(&format!("[BLOCK VALIDATION] TX#{}: Aggregated range proof verification FAILED", tx_idx));
                        return Err(PluribitError::InvalidRangeProof); 
                    }
               //     log(&format!("[BLOCK VALIDATION] TX#{}: Aggregated range proof verified successfully for {} outputs", tx_idx, commitments.len()));
                } else {
                //     log(&format!("[BLOCK VALIDATION] TX#{}: No outputs, skipping range proof verification", tx_idx));
                }
                // --- END: MODIFIED RANGE PROOF VERIFICATION ---


                // Sum all kernel excess points
                let mut kernel_excess_pt = RistrettoPoint::identity(); 
                for k in &tx.kernels {
                    kernel_excess_pt += mimblewimble::kernel_excess_to_pubkey(&k.excess)?;
                }

                let is_coinbase = tx_fee == 0 && tx.inputs.is_empty(); 
                if is_coinbase {
                    coinbase_kernel += kernel_excess_pt; 
                    // FIX: Replace debug_assert_eq! with runtime check to prevent panic
                    if tx_fee != 0 {
                        return Err(PluribitError::InvalidBlock("Coinbase tx cannot have fee".into()));
                    }
                } else {
                    sum_kernel_non_cb += kernel_excess_pt; 
                    total_fees = total_fees
                        .checked_add(tx_fee)
                        .ok_or(PluribitError::InvalidBlock("fee overflow".into()))?; 
                }

               // log(&format!("[BLOCK VALIDATION] TX#{}: {} kernels processed",
               //     tx_idx, tx.kernels.len())); 
                for (inp_idx, inp) in tx.inputs.iter().enumerate() {
                    if !utxos.contains_key(&inp.commitment) {
                       log(&format!("[BLOCK VALIDATION] TX#{} Input#{}: NOT FOUND in UTXO set: {}",
                            tx_idx, inp_idx, hex::encode(&inp.commitment)));
                        return Err(PluribitError::UnknownInput); 
                    }

                    { // Scope for COINBASE_INDEX lock
                        // FIX: Handle poisoned mutex
                        let cb = crate::blockchain::COINBASE_INDEX.lock().unwrap_or_else(|p| p.into_inner()); 
                        if let Some(born_at) = cb.get(&inp.commitment) { 
                            let spend_height = *block.height;
                            let need = *born_at + COINBASE_MATURITY; 
                            if spend_height < need {
                                return Err(PluribitError::InvalidBlock("Coinbase spend immature".into())); 
                            }
                        }
                    } // Lock released

                    let c = CompressedRistretto::from_slice(&inp.commitment) 
                           .map_err(|_| PluribitError::InvalidInputCommitment)? 
                           .decompress() // [cite: 1983]
                           .ok_or(PluribitError::InvalidInputCommitment)?; 
                    sum_in_pts += c; 
                 //   log(&format!("[BLOCK VALIDATION] TX#{} Input#{}: {}",
                  //      tx_idx, inp_idx, hex::encode(&inp.commitment))); 
                }


                // Add output commitments to sum_out_pts (still needed for balance check)
                 for (out_idx, out) in tx.outputs.iter().enumerate() {
                     let c = CompressedRistretto::from_slice(&out.commitment)
                         .map_err(|_| PluribitError::InvalidOutputCommitment)? 
                         .decompress()
                         .ok_or(PluribitError::InvalidOutputCommitment)?; 
                     sum_out_pts += c; 
                     // Log added for context, proof verification happens above now
                  //   log(&format!("[BLOCK VALIDATION] TX#{} Output#{}: {} (aggregated proof verified)",
                   //      tx_idx, out_idx, hex::encode(&out.commitment))); 
                 }


             //  log(&format!("[BLOCK VALIDATION] TX#{}: Processing complete", tx_idx)); 
            }

            // Collect changes to apply after releasing lock
            for tx in &block.transactions {
                for inp in &tx.inputs {
                    utxos_to_remove.push(inp.commitment.clone());
                }
                let is_coinbase_tx = tx.total_fee() == 0 && tx.inputs.is_empty();
                for out in &tx.outputs {
                    utxos_to_add.push(out.clone());
                    if is_coinbase_tx {
                        coinbase_to_add.push((out.commitment.clone(), *block.height));
                    }
                }
            }

            let base_reward = get_current_base_reward(*block.height);

            let total_reward = base_reward + total_fees;
            let reward_commitment = mimblewimble::commit(total_reward, &Scalar::from(0u64))?;
            
            let left_side  = sum_out_pts + sum_kernel_non_cb;
            let right_side = sum_in_pts  + coinbase_kernel + reward_commitment;

         //   log(&format!("[BLOCK VALIDATION] Final sum of inputs:           {}", hex::encode(sum_in_pts.compress().to_bytes())));
         //   log(&format!("[BLOCK VALIDATION] Final sum of outputs:          {}", hex::encode(sum_out_pts.compress().to_bytes())));
         //   log(&format!("[BLOCK VALIDATION] Sum kernel (non-CB):           {}", hex::encode(sum_kernel_non_cb.compress().to_bytes())));
         //   log(&format!("[BLOCK VALIDATION] Kernel (coinbase only):        {}", hex::encode(coinbase_kernel.compress().to_bytes())));
         //   log(&format!("[BLOCK VALIDATION] reward commitment (base+fees): {} (base={}, fees={})", hex::encode(reward_commitment.compress().to_bytes()), base_reward, total_fees));
          //  log(&format!("[BLOCK VALIDATION] LHS (Out + K_nonCB):           {}", hex::encode(left_side.compress().to_bytes())));
          //  log(&format!("[BLOCK VALIDATION] RHS (In + K_CB + Reward):      {}", hex::encode(right_side.compress().to_bytes())));

            if left_side != right_side {
                log("[BLOCK VALIDATION] BALANCE CHECK FAILED!");
                log(&format!("[BLOCK VALIDATION] Total fees in block: {}", total_fees));
                log(&format!("[BLOCK VALIDATION] Base reward: {}", base_reward));
                return Err(PluribitError::Imbalance);
            }

        //    log("[BLOCK VALIDATION] Balance check PASSED");
        } // Lock released here
        
// === 3b. Apply UTXO updates and persist ===
        for commitment in &utxos_to_remove {
            delete_utxo_from_db(commitment).await
                .map_err(|_| PluribitError::StateError("Failed to delete UTXO".into()))?;
            
            // We blindly attempt to delete it. If it wasn't a coinbase output, this is a cheap no-op in RocksDB.
            // This ensures we don't leave dangling entries.
            delete_coinbase_index_from_db(commitment).await.ok();
            
            // FIX: Handle poisoned mutexes
            { UTXO_SET.lock().unwrap_or_else(|p| p.into_inner()).remove(commitment); }
            { COINBASE_INDEX.lock().unwrap_or_else(|p| p.into_inner()).remove(commitment); }
        }
        
        for output in &utxos_to_add {
            save_utxo_to_db(&output.commitment, output).await
                .map_err(|_| PluribitError::StateError("Failed to save UTXO".into()))?;
            
            // FIX: Handle poisoned mutexes
            { UTXO_SET.lock().unwrap_or_else(|p| p.into_inner()).insert(output.commitment.clone(), output.clone()); }
        }
        
        for (commitment, height) in coinbase_to_add {
            save_coinbase_index_to_db(&commitment, height).await
                .map_err(|_| PluribitError::StateError("Failed to save coinbase index".into()))?;
            
            // FIX: Handle poisoned mutexes
            { COINBASE_INDEX.lock().unwrap_or_else(|p| p.into_inner()).insert(commitment, height); }
        }
      //  log("[BLOCK VALIDATION] UTXO set updated successfully");

        // --- Generate and Save Block Filter ---
        // We do this *after* all validation is complete
        let mut filter_entries = Vec::<BlockFilterEntry>::new();
        for tx in &block.transactions {
            for output in &tx.outputs {
                if let (Some(ephemeral_key), Some(view_tag)) = 
                    (output.ephemeral_key.as_ref(), output.view_tag.as_ref()) 
                {
                    // Only add if it's a stealth output (has both key and tag)
                    if !ephemeral_key.is_empty() && !view_tag.is_empty() {
                        filter_entries.push(BlockFilterEntry {
                            ephemeral_key: ephemeral_key.clone(),
                            view_tag: view_tag.clone(),
                            commitment: output.commitment.clone(),
                        });
                    }
                }
            }
        }
        
        // Asynchronously save the filter to the DB
        if !filter_entries.is_empty() {
          //  log(&format!("[FILTER] Saving block filter for height {} with {} entries", *block.height, filter_entries.len()));
            
            self.block_filters.insert(*block.height, filter_entries.clone());
            
            // This function is defined in `src/lib.rs`
            save_block_filter_to_db(*block.height, &filter_entries).await
                .map_err(|e| PluribitError::StateError(format!("Failed to save block filter: {:?}", e)))?;
        }

        
        // === 4. Update Chain State ===
        // Note: total_work is calculated using get_chain_work on a slice of blocks during fork choice,
        // so we don't need to accumulate it here. 
        // MODIFIED: Update the state variables without adding the block to a Vec.
        self.tip_hash = block.hash();
        self.total_work = WasmU64::from(*self.total_work + Self::get_chain_work(&[block.clone()])); // Accumulate work

        // Store cumulative work in the block itself for quick comparison
        block.total_work = self.total_work;

        self.current_height = WasmU64::from(*self.current_height + 1);

        // === 5. Difficulty Adjustment ===
        // NOTE: This check is now handled externally by an async function that fetches
        // the required blocks from the DB before calling `adjust_difficulty`.
        if *self.current_height > 0 && *self.current_height % constants::DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
           // The actual call to adjust_difficulty will happen in lib.rs
        }

        {
            let mut pool = crate::TX_POOL.lock().unwrap_or_else(|p| p.into_inner());
            let before = pool.pending.len();

            pool.pending.retain(|p|
                !block.transactions.iter().any(|t| t.hash() == p.hash())
            );
            
            let utxos = crate::blockchain::UTXO_SET.lock().unwrap_or_else(|p| p.into_inner());
            pool.pending.retain(|p|
                p.inputs.iter().all(|i| utxos.contains_key(&i.commitment))
            );
            
            pool.fee_total = pool.pending.iter().map(|t| t.total_fee()).sum();

    //        crate::log(&format!(
    //            "[RUST] Mempool: removed {} included/invalid txs ({} → {})",
    //            before - pool.pending.len(), before, pool.pending.len()
    //        ));
        }
        Ok(())
    }
    
    // RATIONALE: This pure function calculates the next difficulty parameters without
    // modifying state. This separation allows us to validate difficulty BEFORE accepting
    // a block, preventing consensus failures from accepting invalid blocks.
    pub fn calculate_next_difficulty(
        end_block: &Block,
        start_block: &Block,
        current_vrf_threshold: [u8; 32],
        current_vdf_iterations: WasmU64,
    ) -> ([u8; 32], WasmU64) {
        use crate::constants::{TARGET_BLOCK_TIME, DIFFICULTY_ADJUSTMENT_INTERVAL};
        use num_bigint::BigUint;
        use num_traits::ToPrimitive;
        
        let actual_timespan = (*end_block.timestamp).saturating_sub(*start_block.timestamp);
        let target_timespan = (DIFFICULTY_ADJUSTMENT_INTERVAL * TARGET_BLOCK_TIME * 1000) as u64;

        // RATIONALE: Clamp adjustment factor to prevent extreme difficulty swings
        // that could be exploited for timestamp manipulation attacks (max 4x change)
        let actual_timespan = actual_timespan.max(target_timespan / 4).min(target_timespan * 4);

        // --- Adjust VDF iterations ---
        let vdf_iter_biguint = BigUint::from(*current_vdf_iterations);
        let new_vdf_iter_biguint = (vdf_iter_biguint * target_timespan) / actual_timespan;
        let new_vdf_iterations = new_vdf_iter_biguint.to_u64().unwrap_or(*current_vdf_iterations)
            .max(constants::MIN_VDF_ITERATIONS)
            .min(constants::MAX_VDF_ITERATIONS);

        // --- Adjust VRF threshold ---
        // RATIONALE: Higher threshold = easier difficulty. If blocks came too fast,
        // we need to make it harder (lower threshold)
        let vrf_thresh_biguint = BigUint::from_bytes_be(&current_vrf_threshold);
        let new_vrf_thresh_biguint = (vrf_thresh_biguint * actual_timespan) / target_timespan;

        let new_vrf_threshold_bytes = new_vrf_thresh_biguint.to_bytes_be();
        let mut new_vrf_threshold = [0u8; 32];
        if new_vrf_threshold_bytes.len() >= 32 {
            new_vrf_threshold.copy_from_slice(&new_vrf_threshold_bytes[..32]);
        } else {
            let offset = 32 - new_vrf_threshold_bytes.len();
            new_vrf_threshold[offset..].copy_from_slice(&new_vrf_threshold_bytes);
        }
        
        // RATIONALE: Enforce min/max bounds to prevent difficulty from becoming
        // impossibly hard or trivially easy
        if new_vrf_thresh_biguint < BigUint::from_bytes_be(&constants::VRF_MIN_THRESHOLD) {
            new_vrf_threshold = constants::VRF_MIN_THRESHOLD;
        } else if new_vrf_thresh_biguint > BigUint::from_bytes_be(&constants::VRF_MAX_THRESHOLD) {
            new_vrf_threshold = constants::VRF_MAX_THRESHOLD;
        }

   //     log(&format!("[DIFFICULTY] Timespan: {}ms. New VDF: {}, New VRF: {}",
   //         actual_timespan, new_vdf_iterations, hex::encode(&new_vrf_threshold[..4])));

        (new_vrf_threshold, WasmU64::from(new_vdf_iterations))
    }


    
    pub fn can_accept_block(&self, block: &Block) -> Result<(), PluribitError> {
       if *block.height != *self.current_height + 1 {
            return Err(PluribitError::InvalidBlock(format!(
                "Expected height {}, got {}",
                *self.current_height + 1,
                *block.height
            )));
        }
        
        if block.prev_hash != self.tip_hash {
            return Err(PluribitError::InvalidBlock(
                "Block does not extend current chain tip".to_string()
            ));
        }
        
        Ok(())
    }
    
pub fn create_utxo_snapshot(&self, _tip_block: &Block, _utxos: HashMap<Vec<u8>, TransactionOutput>) -> PluribitResult<crate::UTXOSnapshot> {
    Err(PluribitError::StateError("create_utxo_snapshot is not implemented".to_string()))
}
    
pub fn restore_from_snapshot(&mut self, _snapshot: crate::UTXOSnapshot) -> PluribitResult<()> {
    Err(PluribitError::StateError("restore_from_snapshot is not implemented".to_string()))
}
    
   
}

pub fn get_current_base_reward(height: u64) -> u64 {
    let height_in_era = height % crate::constants::REWARD_RESET_INTERVAL;
    let num_halvings = height_in_era / crate::constants::HALVING_INTERVAL;
    if num_halvings >= 64 { 0 } else { crate::constants::INITIAL_BASE_REWARD >> num_halvings }
}



   
    
#[cfg(test)]
mod tests {
    use crate::WasmU64;
    use crate::wallet::Wallet;
    use crate::transaction::{Transaction, TransactionInput, TransactionOutput, TransactionKernel};
    use crate::mimblewimble;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::traits::Identity;
    

    #[test]
    fn test_kernel_excess_with_fee() {
        // Test that kernel excess correctly includes fee
        let blinding = Scalar::from(123u64);
        let fee = 100u64;
        
        let kernel = TransactionKernel::new(blinding, fee, 0, 1).unwrap();
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
        
        let kernel_excess = mimblewimble::kernel_excess_to_pubkey(&coinbase_tx.kernels[0].excess).unwrap();
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
            source_height: WasmU64::from(0),
        }],
        outputs: vec![TransactionOutput {
            commitment: mimblewimble::commit(tx_output_value, &tx_output_blinding).unwrap()
                .compress().to_bytes().to_vec(),
            ephemeral_key: None,
            stealth_payload: None,
            view_tag: None,
        }],
        kernels: vec![TransactionKernel::new(tx_kernel_blinding, tx_fee, 0, 1).unwrap()],
        timestamp: WasmU64::from(1),
        aggregated_range_proof: vec![],
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
        let k = mimblewimble::kernel_excess_to_pubkey(&tx.kernels[0].excess).unwrap();
        let is_coinbase = tx.total_fee() == 0 && tx.inputs.is_empty();
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
    let kernel = TransactionKernel::new(kernel_blinding, fee, 0, 1).unwrap();
    
    let regular_tx = Transaction {
        inputs: vec![TransactionInput {
            commitment: initial_commitment.compress().to_bytes().to_vec(),
            merkle_proof: None,
            source_height: WasmU64::from(0),
        }],
        outputs: vec![
            TransactionOutput {
                commitment: send_commitment.compress().to_bytes().to_vec(),
                // Remove: range_proof: send_proof.to_bytes(),
                ephemeral_key: None,
                stealth_payload: None,
                view_tag: None, // Add this
            },
            TransactionOutput {
                commitment: change_commitment.compress().to_bytes().to_vec(),
                // Remove: range_proof: change_proof.to_bytes(),
                ephemeral_key: None,
                stealth_payload: None,
                view_tag: None, // Add this
            },
        ],
        kernels: vec![kernel],
        timestamp: WasmU64::from(1), // Fix this
        aggregated_range_proof: vec![], // Add this
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
        let k = mimblewimble::kernel_excess_to_pubkey(&tx.kernels[0].excess).unwrap();
        let is_coinbase = tx.total_fee() == 0 && tx.inputs.is_empty();
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
    println!("  Kernel excess: {}", hex::encode(&coinbase_tx.kernels[0].excess));
    println!("  Kernel fee: {}", coinbase_tx.kernels[0].fee);
    
    // Manually verify the balance
    let output_point = CompressedRistretto::from_slice(&coinbase_tx.outputs[0].commitment)
        .unwrap().decompress().unwrap();
    let kernel_point = mimblewimble::kernel_excess_to_pubkey(&coinbase_tx.kernels[0].excess).unwrap();
    let reward_point = mimblewimble::commit(base_reward, &Scalar::from(0u64)).unwrap();
    
    println!("\nBalance check:");
    println!("  Output point: {:?}", output_point.compress());
    println!("  Kernel point: {:?}", kernel_point.compress());
    println!("  Reward point: {:?}", reward_point.compress());
    println!("  Kernel + Reward: {:?}", (kernel_point + reward_point).compress());
    
    assert_eq!(output_point, kernel_point + reward_point, "Should balance");
}
}

