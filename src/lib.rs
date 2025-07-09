use wasm_bindgen::prelude::*;
use serde_wasm_bindgen;
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::collections::HashMap;
use serde_json;
use sha2::{Sha256, Digest};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;  
use bulletproofs::RangeProof;
use serde::Serialize;
use serde::Deserialize;
use js_sys::Date;
use std::collections::HashSet;


use crate::wallet::Wallet; 

use crate::consensus_manager::{ConsensusManager, ConsensusPhase};
use crate::vdf::{VDF, VDFProof, compute_vdf_proof};
use crate::transaction::{Transaction, TransactionOutput, TransactionKernel};
use crate::block::Block; 


pub mod constants;
pub mod error;
pub mod utils;
pub mod vdf;
pub mod mimblewimble;
pub mod transaction;
pub mod block;
pub mod blockchain;
pub mod vdf_clock;
pub mod consensus_manager;
pub mod slashing;
pub mod staking; 
pub mod stealth;
pub mod wallet;
pub mod address;
pub mod merkle;


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StakeLockTransaction {
    pub validator_id: String,
    pub stake_amount: u64,
    pub lock_duration: u64,
    pub lock_height: u64,
    pub block_hash: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VDFLockedStake {
    pub stake_tx: StakeLockTransaction,
    pub vdf_proof: VDFProof,
    pub unlock_height: u64,
    pub activation_time: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Validator {
    pub id: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub locked_stakes: Vec<VDFLockedStake>,
    pub total_locked: u64,
    pub active: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UTXO {
    pub commitment: Vec<u8>,
    pub range_proof: Vec<u8>,
    pub block_height: u64,
    pub index: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransactionPool {
    pub pending: Vec<transaction::Transaction>,
    pub fee_total: u64,
}



#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VoteData {
    pub block_hash: String,
    pub stake_amount: u64,
    pub vdf_proof: VDFProof,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UTXOSnapshot {
    pub height: u64,
    pub prev_block_hash: String,
    pub utxos: Vec<(Vec<u8>, TransactionOutput)>,
    pub timestamp: u64,
    pub merkle_root: [u8; 32],
    pub total_kernels: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactBlockData {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp: u64,
    pub aggregated_kernel: TransactionKernel,
    pub spent_commitments: Vec<Vec<u8>>,
    pub new_outputs: Vec<TransactionOutput>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateSetCommitment {
    pub validator_id: String,
    pub height: u64,
    pub candidate_hashes: Vec<String>, // Sorted list of block hashes seen
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalSelection {
    pub validator_id: String,
    pub height: u64,
    pub selected_block_hash: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVotePacket {
    pub block_hash: String,
    pub final_selection: FinalSelection,
    pub vdf_proof: VDFProof,
    pub candidate_commitment: CandidateSetCommitment,
    pub stake_amount: u64,
}

lazy_static! {
    static ref BLOCKCHAIN: Mutex<blockchain::Blockchain> = Mutex::new(blockchain::Blockchain::new());
    static ref VDF_CLOCK: Mutex<vdf_clock::VDFClock> = Mutex::new(vdf_clock::VDFClock::new(10));
    static ref CONSENSUS_MANAGER: Mutex<ConsensusManager> = Mutex::new(ConsensusManager::new());
    static ref VALIDATORS: Mutex<HashMap<String, Validator>> = Mutex::new(HashMap::new());
    static ref PENDING_STAKES: Mutex<HashMap<String, StakeLockTransaction>> = Mutex::new(HashMap::new());
    static ref BLOCK_VOTES: Mutex<HashMap<u64, HashMap<String, VoteData>>> = Mutex::new(HashMap::new());
    static ref UTXO_SET: Mutex<HashMap<Vec<u8>, UTXO>> = Mutex::new(HashMap::new());
    static ref TX_POOL: Mutex<TransactionPool> = Mutex::new(TransactionPool {
        pending: Vec::new(),
        fee_total: 0,
    });
        // Height -> ValidatorId -> Commitment
    static ref CANDIDATE_COMMITMENTS: Mutex<HashMap<u64, HashMap<String, CandidateSetCommitment>>> =
        Mutex::new(HashMap::new());

    // Height -> ValidatorId -> FinalSelection
    static ref FINAL_SELECTIONS: Mutex<HashMap<u64, HashMap<String, FinalSelection>>> =
        Mutex::new(HashMap::new());

    // Height -> BlockHash -> Block
    static ref CANDIDATE_BLOCKS: Mutex<HashMap<u64, HashMap<String, Block>>> =
        Mutex::new(HashMap::new());

        // Queue of pending staking rewards to be included in next block
    static ref PENDING_REWARDS: Mutex<Vec<(String, u64)>> = Mutex::new(Vec::new());
    
    // Cache of recent UTXOs for fast recovery during reorgs
    // Maps commitment -> (height, TransactionOutput)
    static ref RECENT_UTXO_CACHE: Mutex<HashMap<Vec<u8>, (u64, TransactionOutput)>> = 
        Mutex::new(HashMap::new());
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn wasm_log(s: &str);
}

#[cfg(not(target_arch = "wasm32"))]
fn native_log(s: &str) {
    // On native targets, just print to the console.
    println!("{}", s);
}

// Universal log function that dispatches to the correct implementation
pub fn log(s: &str) {
    #[cfg(target_arch = "wasm32")]
    wasm_log(s);


    #[cfg(not(target_arch = "wasm32"))]
    native_log(s);
}

#[wasm_bindgen]
pub fn wallet_scan_blockchain(wallet_json: &str) -> Result<String, JsValue> {
    // Deserialize the wallet
    let mut wallet: Wallet = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // Get the blockchain
    let chain = BLOCKCHAIN.lock().unwrap();
    
    // Scan each block
    for block in &chain.blocks {
        wallet.scan_block(block);
    }
    
    // Return the updated wallet as JSON
    serde_json::to_string(&wallet)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn wallet_get_address(wallet_json: &str) -> Result<String, JsValue> {
    let wallet: Wallet = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // The wallet's address is their scan public key in hex
    let address = hex::encode(wallet.scan_pub.compress().to_bytes());
    
    Ok(address)
}

#[wasm_bindgen]
pub fn validate_address(address_hex: &str) -> Result<bool, JsValue> {
    // Try to decode the hex
    let bytes = hex::decode(address_hex)
        .map_err(|_| JsValue::from_str("Invalid hex"))?;
    
    // Check if it's a valid compressed Ristretto point
    if bytes.len() != 32 {
        return Ok(false);
    }
    
    match CompressedRistretto::from_slice(&bytes) {
        Ok(compressed) => {
            // Check if it decompresses to a valid point
            Ok(compressed.decompress().is_some())
        }
        Err(_) => Ok(false)
    }
}

#[wasm_bindgen]
pub fn scan_pending_transactions(wallet_json: &str) -> Result<JsValue, JsValue> {
    let wallet: Wallet = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pool = TX_POOL.lock().unwrap();
    
    let mut found_outputs = Vec::new();

    // Create a dummy block to pass to the scan_block function
    for tx in &pool.pending {
        let mut temp_block = Block::genesis(); // A simple container
        temp_block.transactions.push(tx.clone());

        let mut temp_wallet = wallet.clone();
        temp_wallet.scan_block(&temp_block);
        
        // Check if new UTXOs were found
        if temp_wallet.owned_utxos.len() > wallet.owned_utxos.len() {
             for utxo in temp_wallet.owned_utxos.iter().skip(wallet.owned_utxos.len()) {
                // Here you can decide what info to return
                found_outputs.push(utxo.value);
             }
        }
    }
    
    serde_wasm_bindgen::to_value(&found_outputs)
        .map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn greet(name: &str) -> String {
    log(&format!("RUST: Hello from Rust, {}!", name));
    format!("Hello, {}! This is Rust speaking from Wasm.", name)
}

/// Computes a VDF proof.
/// Takes an input string (which will be hashed) and the number of iterations.
/// Returns the VDFProof struct serialized as a JsValue, or a JsValue error.
#[wasm_bindgen]
pub fn perform_vdf_computation(input_str: String, iterations: u64) -> Result<JsValue, JsValue> {
    log(&format!("[RUST] Starting VDF computation. Input: '{}', Iterations: {}", input_str, iterations));

    // 1. Create a VDF instance.
    //    Your VDF::new() takes a dummy _bit_length.
    //    It returns PluribitResult<VDF>.
    let vdf_instance = match VDF::new(2048) {
        Ok(instance) => instance,
        Err(e) => {
            let err_msg = format!("[RUST_ERROR] Failed to initialize VDF: {:?}", e);
            log(&err_msg);
            return Err(JsValue::from_str(&err_msg));
        }
    };
    log("[RUST] VDF instance created.");

    // 2. Prepare input bytes
    let input_bytes = input_str.as_bytes();

    // 3. Call compute_with_proof
    //    This is a method on your VDF struct.
    log(&format!("[RUST] Calling vdf_instance.compute_with_proof for {} iterations...", iterations));
    match vdf_instance.compute_with_proof(input_bytes, iterations) {
        Ok(proof_data) => {
            log("[RUST] VDF computation successful. Serializing proof...");
            // Serialize the VDFProof struct to JsValue
            match serde_wasm_bindgen::to_value(&proof_data) {
                Ok(js_proof) => {
                    log("[RUST] Proof serialized to JsValue successfully.");
                    Ok(js_proof)
                }
                Err(e_serde) => {
                    let err_msg = format!("[RUST_ERROR] Failed to serialize VDFProof to JsValue: {}", e_serde);
                    log(&err_msg);
                    Err(JsValue::from_str(&err_msg))
                }
            }
        }
        Err(e_vdf) => {
            let err_msg = format!("[RUST_ERROR] VDF computation failed: {:?}", e_vdf);
            log(&err_msg);
            Err(JsValue::from_str(&err_msg))
        }
    }
}

/// Verifies a VDF proof.
/// Takes an input string, the VDFProof (as JsValue),
/// Returns true if valid, false otherwise, or a JsValue error.
#[wasm_bindgen]
pub fn verify_vdf_proof(input_str: String, proof_js: JsValue) -> Result<bool, JsValue> {
    log(&format!("[RUST] Starting VDF verification. Input: '{}'", input_str));

    // 1. Create a VDF instance
    let vdf_instance = match VDF::new(2048) {
        Ok(instance) => instance,
        Err(e) => {
            let err_msg = format!("[RUST_ERROR] Failed to initialize VDF for verification: {:?}", e);
            log(&err_msg);
            return Err(JsValue::from_str(&err_msg));
        }
    };
    log("[RUST] VDF instance for verification created.");

    // 2. Deserialize VDFProof from JsValue
    let proof_data: VDFProof = match serde_wasm_bindgen::from_value(proof_js) {
        Ok(data) => data,
        Err(e_serde) => {
            let err_msg = format!("[RUST_ERROR] Failed to deserialize VDFProof from JsValue: {}", e_serde);
            log(&err_msg);
            return Err(JsValue::from_str(&err_msg));
        }
    };
    log("[RUST] VDFProof deserialized from JsValue successfully.");

    // 3. Prepare input bytes
    let input_bytes = input_str.as_bytes();

    // 4. Call verify
    log("[RUST] Calling vdf_instance.verify...");
    match vdf_instance.verify(input_bytes, &proof_data) {
        Ok(is_valid) => {
            log(&format!("[RUST] VDF verification result: {}", is_valid));
            Ok(is_valid)
        }
        Err(e_vdf) => {
            let err_msg = format!("[RUST_ERROR] VDF verification failed: {:?}", e_vdf);
            log(&err_msg);
            Err(JsValue::from_str(&err_msg))
        }
    }
}




#[wasm_bindgen]
pub fn create_genesis_block() -> Result<JsValue, JsValue> {
    let genesis = block::Block::genesis();
    log(&format!("[RUST] Genesis block created with hash: {}", genesis.hash()));
    serde_wasm_bindgen::to_value(&genesis)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}


#[wasm_bindgen]
pub fn wallet_create_transaction(
    wallet_json: &str,
    amount: u64,
    fee: u64,
    recipient_scan_pub_hex: &str,
) -> Result<JsValue, JsValue> {
    // 1. Deserialize the wallet state from the JSON string provided by JavaScript.
    let mut wallet: Wallet = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // 2. Decode the recipient's public key from the hex string.
    let pub_key_bytes = hex::decode(recipient_scan_pub_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let compressed_point = CompressedRistretto::from_slice(&pub_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key bytes: {}", e)))?; // Convert error to JsValue

    let recipient_scan_pub = compressed_point.decompress() // Now you can call decompress
        .ok_or_else(|| JsValue::from_str("Invalid recipient public key"))?;

    // 3. Call the internal create_transaction method on the Wallet struct.
    //    This method contains all the complex logic for coin selection and stealth output creation.
    let transaction = wallet.create_transaction(amount, fee, &recipient_scan_pub)
        .map_err(|e| JsValue::from_str(&e))?;
    
    // 4. Serialize the wallet's NEW state back to JSON. This is crucial because
    //    spending UTXOs and creating change modifies the wallet's state.
    let updated_wallet_json = serde_json::to_string(&wallet).unwrap();

    // 5. Create a result object to send back to JavaScript, containing
    //    both the new transaction and the updated wallet state.
    #[derive(Serialize)]
    struct TxCreationResult {
        transaction: Transaction,
        updated_wallet_json: String,
    }

    let result = TxCreationResult {
        transaction,
        updated_wallet_json,
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| e.into())
}



#[wasm_bindgen]
pub fn init_vdf_clock(ticks_per_block: u64) -> Result<JsValue, JsValue> {
    let mut clock = VDF_CLOCK.lock().unwrap();
    *clock = vdf_clock::VDFClock::new(ticks_per_block);
    log(&format!("[RUST] VDF clock initialized with {} ticks per block", ticks_per_block));

    serde_wasm_bindgen::to_value(&*clock)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn tick_vdf_clock() -> Result<JsValue, JsValue> {
    let mut clock = VDF_CLOCK.lock().unwrap();
    let vdf = VDF::new(2048)
        .map_err(|e| JsValue::from_str(&format!("Failed to create VDF: {:?}", e)))?;

    clock.tick(&vdf)
        .map_err(|e| JsValue::from_str(&format!("Failed to tick clock: {:?}", e)))?;
    log(&format!("[RUST] VDF clock ticked to {}", clock.current_tick));

    serde_wasm_bindgen::to_value(&*clock)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn get_vdf_clock_state() -> Result<JsValue, JsValue> {
    let clock = VDF_CLOCK.lock().unwrap();
    serde_wasm_bindgen::to_value(&*clock)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn check_block_submission(block_height: u64) -> Result<JsValue, JsValue> {
    let clock = VDF_CLOCK.lock().unwrap();
    let can_submit = clock.can_submit_block(block_height);
    let required_tick = block_height * clock.ticks_per_block;

    log(&format!(
        "[RUST] Block {} submission check: {} (current tick: {}, required: {})",
        block_height, can_submit, clock.current_tick, required_tick
    ));

    #[derive(serde::Serialize)]
    struct SubmissionStatus {
        can_submit: bool,
        current_tick: u64,
        required_tick: u64,
        ticks_remaining: i64,
    }

    let status = SubmissionStatus {
        can_submit,
        current_tick: clock.current_tick,
        required_tick,
        ticks_remaining: (required_tick as i64 - clock.current_tick as i64),
    };

    serde_wasm_bindgen::to_value(&status)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}



#[wasm_bindgen]
pub fn compute_block_hash(block_json: JsValue) -> Result<String, JsValue> {
    let block: block::Block = serde_wasm_bindgen::from_value(block_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize block: {}", e)))?;

    Ok(block.hash())
}
#[wasm_bindgen]
pub fn init_blockchain() -> Result<JsValue, JsValue> {
    let mut chain = BLOCKCHAIN.lock().unwrap();
    *chain = blockchain::Blockchain::new();
    log("[RUST] Blockchain initialized with genesis block");

    serde_wasm_bindgen::to_value(&*chain)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn add_block_to_chain(block_json: JsValue) -> Result<JsValue, JsValue> {
    let block: block::Block = serde_wasm_bindgen::from_value(block_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize block: {}", e)))?;

    let mut chain = BLOCKCHAIN.lock().unwrap();
    chain.add_block(block.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to add block: {}", e)))?;

    log(&format!("[RUST] Block added to chain. New height: {}", chain.current_height));

    serde_wasm_bindgen::to_value(&*chain)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn get_blockchain_state() -> Result<JsValue, JsValue> {
    let chain = BLOCKCHAIN.lock().unwrap();
    serde_wasm_bindgen::to_value(&*chain)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn get_latest_block_hash() -> Result<String, JsValue> {
    let chain = BLOCKCHAIN.lock().unwrap();
    Ok(chain.get_latest_block().hash())
}

#[wasm_bindgen]
pub fn consensus_tick() -> Result<JsValue, JsValue> {
    let mut manager = CONSENSUS_MANAGER.lock().unwrap();
    let result = manager.tick();
    
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn submit_pow_candidate(block_js: JsValue) -> Result<(), JsValue> {
    let block: Block = serde_wasm_bindgen::from_value(block_js)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize block: {}", e)))?;

    let mut manager = CONSENSUS_MANAGER.lock().unwrap();

    match manager.current_phase {
        ConsensusPhase::Mining => {
            // Check VDF timing
            let clock = VDF_CLOCK.lock().unwrap();
            if !clock.can_submit_block(block.height) {
                let required_tick = block.height * clock.ticks_per_block;
                return Err(JsValue::from_str(&format!(
                    "Cannot submit block yet. Current tick: {}, Required: {}",
                    clock.current_tick, required_tick
                )));
            }

            // Check if this block is better than current candidate
            if let Some(ref current_best) = manager.best_candidate_block {
                // For PoW: Lower hash = more work done = better block
                let block_hash = block.hash();
                let current_best_hash = current_best.hash();
                
                // Compare hashes lexicographically (as hex strings)
                // Lower hash value = more leading zeros = more work
                if block_hash > current_best_hash {
                    log(&format!("[RUST] Rejected candidate block - higher hash {} > {} (less work) than current best", 
                        &block_hash[..8], &current_best_hash[..8]));
                    return Ok(());
                }
                
                // If hashes are somehow equal (extremely unlikely), use timestamp as tiebreaker
                if block_hash == current_best_hash && block.timestamp > current_best.timestamp {
                    log("[RUST] Rejected candidate block - same hash but later timestamp");
                    return Ok(());
                }
            }

            // Log acceptance
            log(&format!("[RUST] Accepted new candidate block with hash {}", &block.hash()[..8]));

            manager.best_candidate_block = Some(block);
            log("[RUST] Accepted new candidate block.");
        }
        ConsensusPhase::Validation => {
            return Err(JsValue::from_str("Cannot submit block during validation phase"));
        }
    }

    Ok(())
}

#[wasm_bindgen]
pub fn get_block_with_hash(block_json: JsValue) -> Result<JsValue, JsValue> {
    let block: block::Block = serde_wasm_bindgen::from_value(block_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize block: {}", e)))?;

    // Create a struct that includes the hash
    #[derive(serde::Serialize)]
    struct BlockWithHash {
        #[serde(flatten)]
        block: block::Block,
        hash: String,
    }

    let block_with_hash = BlockWithHash {
        hash: block.hash(),
        block,
    };

    serde_wasm_bindgen::to_value(&block_with_hash)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn get_blockchain_with_hashes() -> Result<JsValue, JsValue> {
    let chain = BLOCKCHAIN.lock().unwrap();

    #[derive(serde::Serialize)]
    struct BlockWithHash {
        height: u64,
        prev_hash: String,
        timestamp: u64,
        nonce: u64,
        miner_id: String,
        difficulty: u8,
        hash: String,
    }

    let blocks_with_hashes: Vec<BlockWithHash> = chain.blocks.iter().map(|block| {
        BlockWithHash {
            height: block.height,
            prev_hash: block.prev_hash.clone(),
            timestamp: block.timestamp,
            nonce: block.nonce,
            miner_id: block.miner_id.clone(),
            difficulty: block.difficulty,
            hash: block.hash(),
        }
    }).collect();

    #[derive(serde::Serialize)]
    struct ChainWithHashes {
        blocks: Vec<BlockWithHash>,
        current_height: u64,
    }

    let result = ChainWithHashes {
        blocks: blocks_with_hashes,
        current_height: chain.current_height,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// Create stake lock transaction
#[wasm_bindgen]
pub fn create_stake_lock(validator_id: String, stake_amount: u64, lock_duration: u64) -> Result<JsValue, JsValue> {
    if stake_amount < 100 {
        return Err(JsValue::from_str("Minimum stake is 100"));
    }

    if lock_duration < 1 || lock_duration > 365 {
        return Err(JsValue::from_str("Lock duration must be between 1 and 365 blocks"));
    }

    let chain = BLOCKCHAIN.lock().unwrap();
    let current_height = chain.current_height;
    let current_block_hash = chain.blocks.last()
        .map(|b| b.hash())
        .unwrap_or_else(|| "genesis".to_string());

    let stake_tx = StakeLockTransaction {
        validator_id: validator_id.clone(),
        stake_amount,
        lock_duration,
        lock_height: current_height,
        block_hash: current_block_hash,
    };

    // Store pending stake
    let mut pending = PENDING_STAKES.lock().unwrap();
    pending.insert(validator_id.clone(), stake_tx.clone());

    log(&format!("[RUST] Created stake lock for {} - amount: {}, duration: {} blocks",
        validator_id, stake_amount, lock_duration));

    serde_wasm_bindgen::to_value(&stake_tx)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// Compute VDF for stake lock
#[wasm_bindgen]
pub fn compute_stake_vdf(validator_id: String) -> Result<JsValue, JsValue> {
    let pending = PENDING_STAKES.lock().unwrap();
    let stake_tx = pending.get(&validator_id)
        .ok_or_else(|| JsValue::from_str("No pending stake found"))?;

    // VDF input includes the stake transaction and block hash (chain-specific!)
    let vdf_input = format!("{}:{}:{}:{}",
        stake_tx.validator_id,
        stake_tx.stake_amount,
        stake_tx.lock_duration,
        stake_tx.block_hash  // This makes it chain-specific!
    );

    // Calculate required VDF iterations based on lock duration
    // T = lock_duration * ticks_per_block * squarings_per_tick
    let clock = VDF_CLOCK.lock().unwrap();
    let iterations = stake_tx.lock_duration * clock.ticks_per_block * 10; //1000; // 1000 squarings per tick

    log(&format!("[RUST] Computing VDF for stake lock: {} iterations", iterations));

    // Use your existing VDF implementation
    let vdf = VDF::new(2048).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let vdf_proof = compute_vdf_proof(vdf_input.as_bytes(), iterations, &vdf.modulus)
        .map_err(|e| JsValue::from_str(&e))?;

    #[derive(serde::Serialize)]
    struct VDFComputeResult {
        stake_tx: StakeLockTransaction,
        vdf_proof: VDFProof,
        iterations: u64,
    }

    let result = VDFComputeResult {
        stake_tx: stake_tx.clone(),
        vdf_proof,
        iterations,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// Activate stake with VDF proof
#[wasm_bindgen]
pub fn activate_stake_with_vdf(
    validator_id: String,
    vdf_proof_js: JsValue,
    spend_public_key: Vec<u8>,   // 32-bytes compressed Ristretto
    spend_private_key: Vec<u8>,   // 32-bytes private key
) -> Result<(), JsValue> {

    let vdf_result: serde_json::Value = serde_wasm_bindgen::from_value(vdf_proof_js)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse VDF result: {}", e)))?;

    // Extract components
    let stake_tx: StakeLockTransaction = serde_json::from_value(vdf_result["stake_tx"].clone())
        .map_err(|e| JsValue::from_str(&format!("Invalid stake_tx: {}", e)))?;
    let vdf_proof: VDFProof = serde_json::from_value(vdf_result["vdf_proof"].clone())
        .map_err(|e| JsValue::from_str(&format!("Invalid vdf_proof: {}", e)))?;

    // Verify the VDF proof
    let vdf_input = format!("{}:{}:{}:{}",
        stake_tx.validator_id,
        stake_tx.stake_amount,
        stake_tx.lock_duration,
        stake_tx.block_hash
    );

    let vdf = VDF::new(2048).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let is_valid = vdf.verify(vdf_input.as_bytes(), &vdf_proof)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    if !is_valid {
        return Err(JsValue::from_str("Invalid VDF proof"));
    }
    
    // Create locked stake
    let locked_stake = VDFLockedStake {
        stake_tx: stake_tx.clone(),
        vdf_proof,
        unlock_height: stake_tx.lock_height + stake_tx.lock_duration,
        activation_time: js_sys::Date::now() as u64,
    };

    // Add to validators with BOTH public and private keys
    let mut validators = VALIDATORS.lock().unwrap();
    let validator = validators.entry(validator_id.clone()).or_insert(Validator {
        id: validator_id.clone(),
        public_key: spend_public_key,
        private_key: spend_private_key,  // store private key for signing
        locked_stakes: Vec::new(),
        total_locked: 0,
        active: true,
    });

    validator.locked_stakes.push(locked_stake);
    validator.total_locked += stake_tx.stake_amount;

    // Remove from pending
    let mut pending = PENDING_STAKES.lock().unwrap();
    pending.remove(&validator_id);

    log(&format!("[RUST] Activated VDF-locked stake for {} - amount: {}",
        validator_id, stake_tx.stake_amount));

    Ok(())
}

// Vote for a block (only with active VDF-locked stake)
#[wasm_bindgen]
pub fn vote_for_block(
    validator_id: String,
    spend_private_key: Vec<u8>,
    selected_block_hash: String, // explicitly pass selected block
) -> Result<JsValue, JsValue> {
    use curve25519_dalek::scalar::Scalar;
    
    let validators = VALIDATORS.lock().unwrap();
    let chain = BLOCKCHAIN.lock().unwrap();
    let manager = CONSENSUS_MANAGER.lock().unwrap();

    // Check if validator exists and has active stake
    let validator = validators.get(&validator_id)
        .ok_or_else(|| JsValue::from_str("Validator not found"))?;

    if !validator.active || validator.total_locked == 0 {
        return Err(JsValue::from_str("Validator has no active locked stake"));
    }

    // Check current height and remove expired stakes
    let current_height = chain.current_height;
    let active_stake: u64 = validator.locked_stakes.iter()
        .filter(|stake| current_height <= stake.unlock_height)
        .map(|stake| stake.stake_tx.stake_amount)
        .sum();

    if active_stake == 0 {
        return Err(JsValue::from_str("All stakes have expired"));
    }
    
    log(&format!("[RUST] Validator {} attempting to vote in phase: {:?}", 
        validator_id, manager.current_phase));
    
    // Check if we're in validation phase
    match manager.current_phase {
        ConsensusPhase::Validation => {
            if let Some(ref candidate) = manager.best_candidate_block {
                log(&format!("[RUST] Found candidate block {} to vote for", candidate.height));

                // Drop locks before VDF computation
                let candidate_hash = candidate.hash();
                let candidate_height = candidate.height;
                drop(validators);
                drop(chain);
                drop(manager);
                
                // Get validator's SPEND private key for signing
                let private_key_bytes = spend_private_key;

                    


                // Convert private key bytes to Scalar
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&private_key_bytes);
                let private_key = Scalar::from_bytes_mod_order(key_array);
                
                // Use the calibrated VDF speed to calculate the iterations for the vote VDF.
                // The whitepaper specifies this VDF should take approximately 4 minutes (240 seconds).

                let calibrated_speed = *constants::VDF_ITERATIONS_PER_SECOND.lock().unwrap();
                let vote_duration_seconds = 25; // 25 seconds
                let vote_iterations = calibrated_speed * vote_duration_seconds;

                log(&format!("[RUST] Starting {}-second vote VDF ({} iterations) for block {}",
                    vote_duration_seconds, vote_iterations, &selected_block_hash[..8]));
                
                let vote_input = format!("{}||{}", validator_id, selected_block_hash);

                
                let vdf = VDF::new(2048).map_err(|e| JsValue::from_str(&e.to_string()))?;
                let start_time = js_sys::Date::now();
                
                let vote_vdf_proof = compute_vdf_proof(vote_input.as_bytes(), vote_iterations, &vdf.modulus)
                    .map_err(|e| JsValue::from_str(&e))?;
                    
                let compute_time = js_sys::Date::now() - start_time;
                
                if compute_time < 180000.0 { // Less than 3 minutes
                    log(&format!("[RUST] WARNING: VDF too fast! {}ms - increase iterations", compute_time));
                }
                log(&format!("[RUST] VDF computation took {}ms", compute_time));
                
                // Create vote message
                let vote_message = format!("vote:{}:{}:{}", 
                    candidate_height, 
                    candidate_hash, 
                    active_stake
                );
                
                // Create proper Schnorr signature
                let message_hash = Sha256::digest(vote_message.as_bytes());
                let mut hash_array = [0u8; 32];
                hash_array.copy_from_slice(&message_hash);
                
                let (challenge, s) = mimblewimble::create_schnorr_signature(hash_array, &private_key)
                    .map_err(|e| JsValue::from_str(&format!("Failed to create signature: {:?}", e)))?;
                
                // Serialize signature
                let mut signature = Vec::with_capacity(64);
                signature.extend_from_slice(&challenge.to_bytes());
                signature.extend_from_slice(&s.to_bytes());
                
                // Record vote with VDF proof
                let mut votes = BLOCK_VOTES.lock().unwrap();
                let height_votes = votes.entry(candidate_height).or_insert_with(HashMap::new);
                
                let vote_data = VoteData {
                    block_hash: candidate_hash.clone(),
                    stake_amount: active_stake,
                    vdf_proof: vote_vdf_proof.clone(),
                    signature,
                    timestamp: js_sys::Date::now() as u64,
                };
                
                height_votes.insert(validator_id.clone(), vote_data);
                
                log(&format!("[RUST] Validator {} voted for block {} with {} stake",
                    validator_id, candidate_height, active_stake));

                #[derive(serde::Serialize)]
                struct VoteResult {
                    validator_id: String,
                    block_height: u64,
                    block_hash: String,
                    stake_amount: u64,
                    vdf_proof: VDFProof,
                    compute_time_ms: f64,
                }

                let result = VoteResult {
                    validator_id,
                    block_height: candidate_height,
                    block_hash: candidate_hash,
                    stake_amount: active_stake,
                    vdf_proof: vote_vdf_proof,
                    compute_time_ms: compute_time,
                };

                serde_wasm_bindgen::to_value(&result)
                    .map_err(|e| JsValue::from_str(&e.to_string()))
            } else {
                Err(JsValue::from_str("No candidate block to vote for"))
            }
        },
        _ => Err(JsValue::from_str("Can only vote during validation phase"))
    }
}

#[wasm_bindgen]
pub fn verify_validator_vote(
    validator_id: String,
    block_height: u64,
    block_hash: String,
    stake_amount: u64,
    signature_bytes: Vec<u8>,
) -> Result<bool, JsValue> {
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::ristretto::CompressedRistretto;
    
    // Get validator's public key
    let validators = VALIDATORS.lock().unwrap();
    let validator = validators.get(&validator_id)
        .ok_or_else(|| JsValue::from_str("Validator not found"))?;
    let public_key_bytes = validator.public_key.clone();
    drop(validators);
    
    // Parse public key
    let public_key_compressed = CompressedRistretto::from_slice(&public_key_bytes)
        .map_err(|_| JsValue::from_str("Invalid public key format"))?;
    let public_key = public_key_compressed.decompress()
        .ok_or_else(|| JsValue::from_str("Failed to decompress public key"))?;
    
    // Parse signature
    if signature_bytes.len() != 64 {
        return Err(JsValue::from_str("Invalid signature length"));
    }
    
    let mut challenge_bytes = [0u8; 32];
    challenge_bytes.copy_from_slice(&signature_bytes[0..32]);
    let challenge = Scalar::from_bytes_mod_order(challenge_bytes);
    
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature_bytes[32..64]);
    let s = Scalar::from_bytes_mod_order(s_bytes);
    
    // Recreate vote message
    let vote_message = format!("vote:{}:{}:{}", block_height, block_hash, stake_amount);
    let message_hash = Sha256::digest(vote_message.as_bytes());
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&message_hash);
    
    // Verify signature
    let is_valid = mimblewimble::verify_schnorr_signature(&(challenge, s), hash_array, &public_key);
    
    Ok(is_valid)
}

// Get validator info
#[wasm_bindgen]
pub fn get_validators() -> Result<JsValue, JsValue> {
    let validators = VALIDATORS.lock().unwrap();
    let chain = BLOCKCHAIN.lock().unwrap();
    let current_height = chain.current_height;

    #[derive(serde::Serialize)]
    struct ValidatorInfo {
        id: String,
        total_locked: u64,
        active_stake: u64,
        num_locks: usize,
    }

    let validator_list: Vec<ValidatorInfo> = validators.values().map(|v| {
        let active_stake: u64 = v.locked_stakes.iter()
            .filter(|stake| current_height <= stake.unlock_height)
            .map(|stake| stake.stake_tx.stake_amount)
            .sum();

        ValidatorInfo {
            id: v.id.clone(),
            total_locked: v.total_locked,
            active_stake,
            num_locks: v.locked_stakes.len(),
        }
    }).collect();

    // CORRECTED TYPO HERE
    serde_wasm_bindgen::to_value(&validator_list)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}





// Get wallet balance
#[wasm_bindgen]
pub fn wallet_get_balance(wallet_json: &str) -> Result<u64, JsValue> {
    // 1. Deserialize the wallet state passed from JavaScript.
    let wallet: Wallet = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // 2. Call the internal balance() method on the Wallet struct.
    //    This method simply sums the value of the UTXOs the wallet owns.
    Ok(wallet.balance())
}


#[wasm_bindgen]
pub fn wallet_create() -> Result<String, JsValue> {
    // 1. Create a new Wallet instance using the logic in wallet.rs
    let wallet = Wallet::new();

    // 2. Serialize the new wallet to a JSON string and return it.
    // The JavaScript caller is now responsible for saving this string.
    serde_json::to_string(&wallet)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}


// Get transaction pool
#[wasm_bindgen]
pub fn get_tx_pool() -> Result<JsValue, JsValue> {
    let pool = TX_POOL.lock().unwrap();

    #[derive(serde::Serialize)]
    struct PoolInfo {
        pending_count: usize,
        fee_total: u64,
        transactions: Vec<transaction::Transaction>,
    }

    let info = PoolInfo {
        pending_count: pool.pending.len(),
        fee_total: pool.fee_total,
        transactions: pool.pending.clone(),
    };

    serde_wasm_bindgen::to_value(&info)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn mine_block_with_txs(
    height: u64,
    prev_hash: String,
    miner_id: String,
    miner_pubkey_bytes: Vec<u8>, 
    difficulty: u8,
    max_attempts: u64,
    vdf_proof_js: JsValue,
) -> Result<JsValue, JsValue> {
    log(&format!("[RUST] Starting PoW mining. Height: {}, Difficulty: {}", height, difficulty));

    let vdf_proof: VDFProof = serde_wasm_bindgen::from_value(vdf_proof_js)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize VDF proof: {}", e)))?;
    
    // --- Select transactions up to the block size limit ---
    let mut current_block_size: usize = 0;
    let mut fee_total = 0;
    let mut transactions_to_mine = Vec::new();
    let pool = TX_POOL.lock().unwrap();
    for tx in &pool.pending {
        let tx_size = bincode::serialize(tx).unwrap_or_default().len();
        if current_block_size + tx_size > constants::MAX_BLOCK_SIZE_BYTES {
            break;
        }
        transactions_to_mine.push(tx.clone());
        fee_total += tx.kernel.fee;
        current_block_size += tx_size;
    }
    drop(pool);
        
    // --- Correct Reward Calculation ---
    let base_reward = crate::blockchain::get_current_base_reward(height);
    let mut rewards_with_keys: Vec<(Vec<u8>, u64)> = Vec::new();

    if height <= constants::BOOTSTRAP_BLOCKS {
        // During bootstrap, the miner gets the full base reward + fees.
        let miner_reward = base_reward + fee_total;
        log(&format!("[RUST] Bootstrap Coinbase Reward: {}", miner_reward));
        rewards_with_keys.push((miner_pubkey_bytes.clone(), miner_reward));

    } else {
        // After bootstrap, the reward is split.
        let difficulty_bonus = if difficulty > 1 {
            let factor = constants::DIFFICULTY_BONUS_FACTOR;
            (difficulty as f64).log2().round() as u64 * factor
        } else {
            0
        };
        // Miner gets half the base reward, plus the full bonus and fees.
        let miner_reward = (base_reward / 2) + difficulty_bonus + fee_total;
        log(&format!("[RUST] Post-Bootstrap Coinbase Reward: {}", miner_reward));
        rewards_with_keys.push((miner_pubkey_bytes.clone(), miner_reward));

        // NOTE: The logic to distribute the other half to stakers would go here.
    }

    // --- Create Coinbase and Final Block ---
    let coinbase_tx = Transaction::create_coinbase(rewards_with_keys)
        .map_err(|e| JsValue::from_str(&format!("Failed to create coinbase: {:?}", e)))?;
    
    let mut final_txs = vec![coinbase_tx];
    final_txs.extend(transactions_to_mine.clone());
    
    let mut block = Block {
        height,
        prev_hash,
        transactions: final_txs,
        vdf_proof,
        timestamp: js_sys::Date::now() as u64,
        nonce: 0,
        miner_id: miner_id.clone(),
        difficulty,
        finalization_data: None,
    };

    block.apply_cut_through()
        .map_err(|e| JsValue::from_str(&format!("Cut-through failed: {}", e)))?;
    
    log(&format!("[RUST] Mining block with {} transactions (including coinbase)", block.transactions.len()));

    // --- Find Proof-of-Work ---
    for attempt in 0..max_attempts {
        block.nonce = attempt;
        if block.is_valid_pow() {
            log(&format!("[RUST] Found valid PoW! Nonce: {}, Hash: {}", attempt, block.hash()));

            #[derive(Serialize)]
            struct MiningResult {
                block: Block,
                used_transactions: Vec<Transaction>,
            }
            
            let result = MiningResult {
                block,
                used_transactions: transactions_to_mine, 
            };

            return serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&e.to_string()));
        }
    }

    Err(JsValue::from_str("Failed to find valid PoW within attempt limit"))
}



#[wasm_bindgen]
pub fn add_transaction_to_pool(tx_json: JsValue) -> Result<(), JsValue> {
    let tx: Transaction = serde_wasm_bindgen::from_value(tx_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize transaction: {}", e)))?;
    
    // Verify transaction signature
    if !tx.verify_signature().unwrap_or(false) {
        return Err(JsValue::from_str("Invalid transaction signature"));
    }
    
    // Verify all range proofs
    for output in &tx.outputs {
        let commitment = CompressedRistretto::from_slice(&output.commitment)
            .map_err(|_| JsValue::from_str("Invalid output commitment"))?;
        
        let proof = RangeProof::from_bytes(&output.range_proof)
            .map_err(|_| JsValue::from_str("Invalid range proof format"))?;
        
        if !mimblewimble::verify_range_proof(&proof, &commitment) {
            return Err(JsValue::from_str("Range proof verification failed"));
        }
    }
    
    // Verify kernel signature
    let excess_point = CompressedRistretto::from_slice(&tx.kernel.excess)
        .map_err(|_| JsValue::from_str("Invalid kernel excess"))?
        .decompress()
        .ok_or_else(|| JsValue::from_str("Failed to decompress kernel excess"))?;
    
    // Parse signature (challenge, s)
    if tx.kernel.signature.len() != 64 {
        return Err(JsValue::from_str("Invalid signature length"));
    }
    
    let challenge = Scalar::from_bytes_mod_order(
        tx.kernel.signature[0..32].try_into()
            .map_err(|_| JsValue::from_str("Invalid challenge bytes"))?
    );
    
    let signature_s = Scalar::from_bytes_mod_order(
        tx.kernel.signature[32..64].try_into()
            .map_err(|_| JsValue::from_str("Invalid signature bytes"))?
    );
    
    let kernel_message_hash: [u8; 32] = Sha256::digest(format!("fee:{}", tx.kernel.fee)).into();
    
    if !mimblewimble::verify_schnorr_signature(&(challenge, signature_s), kernel_message_hash, &excess_point) {
        return Err(JsValue::from_str("Kernel signature verification failed"));
    }
    
    // Verify balance (sum of inputs = sum of outputs + kernel excess)
    let mut input_sum = RistrettoPoint::identity();
    let mut output_sum = RistrettoPoint::identity();
    
    // Sum all input commitments
    for input in &tx.inputs {
        let input_commitment = CompressedRistretto::from_slice(&input.commitment)
            .map_err(|_| JsValue::from_str("Invalid input commitment"))?
            .decompress()
            .ok_or_else(|| JsValue::from_str("Failed to decompress input commitment"))?;
        input_sum += input_commitment;
    }
    
    // Sum all output commitments
    for output in &tx.outputs {
        let output_commitment = CompressedRistretto::from_slice(&output.commitment)
            .map_err(|_| JsValue::from_str("Invalid output commitment"))?
            .decompress()
            .ok_or_else(|| JsValue::from_str("Failed to decompress output commitment"))?;
        output_sum += output_commitment;
    }
    
    // Add kernel excess to output sum
    output_sum += excess_point;
    
    // Verify balance
    if input_sum != output_sum {
        return Err(JsValue::from_str("Transaction doesn't balance"));
    }
    
    // Check UTXO set to ensure inputs exist and aren't double-spent
    let utxo_set = UTXO_SET.lock().unwrap();
    for input in &tx.inputs {
        if !utxo_set.contains_key(&input.commitment) {
            return Err(JsValue::from_str("Input not found in UTXO set"));
        }
    }
    drop(utxo_set);
    
    // Add to pool
    let mut pool = TX_POOL.lock().unwrap();
    
    // Check if transaction already exists (by comparing kernel excess)
    for existing_tx in &pool.pending {
        if existing_tx.kernel.excess == tx.kernel.excess {
            return Err(JsValue::from_str("Transaction already in pool"));
        }
    }
    
    pool.fee_total += tx.kernel.fee;
    pool.pending.push(tx);
    
    log(&format!("[RUST] Added network transaction to pool. Total: {}", pool.pending.len()));
    
    Ok(())
}

#[wasm_bindgen]
pub fn verify_transaction(tx_json: JsValue) -> Result<bool, JsValue> {
    // Use add_transaction_to_pool logic but return bool instead of error
    match add_transaction_to_pool(tx_json) {
        Ok(_) => {
            // Remove from pool since we're just verifying
            let mut pool = TX_POOL.lock().unwrap();
            pool.pending.pop();
            pool.fee_total -= pool.pending.last().map(|tx| tx.kernel.fee).unwrap_or(0);
            Ok(true)
        },
        Err(_) => Ok(false)
    }
}

#[wasm_bindgen]
pub fn clear_transaction_pool() -> Result<(), JsValue> {
    let mut pool = TX_POOL.lock().unwrap();
    pool.pending.clear();
    pool.fee_total = 0;
    log("[RUST] Transaction pool cleared");
    Ok(())
}

#[wasm_bindgen]
pub fn get_transaction_hash(tx_json: JsValue) -> Result<String, JsValue> {
    let tx: Transaction = serde_wasm_bindgen::from_value(tx_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize transaction: {}", e)))?;
    
    // Hash based on kernel excess and signature (unique per transaction)
    let mut hasher = Sha256::new();
    hasher.update(&tx.kernel.excess);
    hasher.update(&tx.kernel.signature);
    hasher.update(&tx.kernel.fee.to_le_bytes());
    Ok(hex::encode(hasher.finalize()))
}

#[wasm_bindgen]
pub fn update_utxo_set_from_block(block_json: JsValue) -> Result<(), JsValue> {
    let block: Block = serde_wasm_bindgen::from_value(block_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize block: {}", e)))?;
    
    let mut utxo_set = UTXO_SET.lock().unwrap();
    
    // Remove spent outputs (inputs reference spent outputs)
    for tx in &block.transactions {
        for input in &tx.inputs {
            utxo_set.remove(&input.commitment);
        }
    }
    
    // Add new outputs
    for (tx_index, tx) in block.transactions.iter().enumerate() {
        for (output_index, output) in tx.outputs.iter().enumerate() {
            let utxo = UTXO {
                commitment: output.commitment.clone(),
                range_proof: output.range_proof.clone(),
                block_height: block.height,
                index: (tx_index * 1000 + output_index) as u32, // Simple indexing scheme
            };
            utxo_set.insert(output.commitment.clone(), utxo);
        }
    }
    
    log(&format!("[RUST] Updated UTXO set. Total UTXOs: {}", utxo_set.len()));
    Ok(())
}

#[wasm_bindgen]
pub fn get_utxo_set_size() -> usize {
    UTXO_SET.lock().unwrap().len()
}
#[wasm_bindgen]
pub fn sync_blockchain(blocks_json: JsValue) -> Result<JsValue, JsValue> {
    let blocks: Vec<Block> = serde_wasm_bindgen::from_value(blocks_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize blocks: {}", e)))?;
    
    let mut chain = BLOCKCHAIN.lock().unwrap();
    let mut synced_count = 0;
    
    for block in blocks {
        if block.height == chain.current_height + 1 {
            match chain.add_block(block) {
                Ok(_) => synced_count += 1,
                Err(e) => {
                    log(&format!("[RUST] Failed to sync block: {:?}", e));
                    break;
                }
            }
        }
    }
    
    log(&format!("[RUST] Synced {} blocks", synced_count));
    
    serde_wasm_bindgen::to_value(&*chain)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn validate_and_sync_chain(chain_json: JsValue) -> Result<JsValue, JsValue> {
    let remote_chain: blockchain::Blockchain = serde_wasm_bindgen::from_value(chain_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize chain: {}", e)))?;
    
    let mut local_chain = BLOCKCHAIN.lock().unwrap();
    
    // Don't sync if remote chain is shorter
    if remote_chain.current_height <= local_chain.current_height {
        return Ok(JsValue::from_bool(false));
    }
    
    log(&format!("[RUST] Validating remote chain from height {} to {}", 
        local_chain.current_height + 1, remote_chain.current_height));
    
    // Validate each block we don't have
    for i in (local_chain.current_height + 1)..=remote_chain.current_height {
        let block = remote_chain.blocks.iter()
            .find(|b| b.height == i)
            .ok_or_else(|| JsValue::from_str(&format!("Missing block {}", i)))?;
        
        // Validate PoW
        if !block.is_valid_pow() {
            return Err(JsValue::from_str(&format!("Block {} has invalid PoW", i)));
        }
        
        // Validate finalization for non-genesis blocks
        if block.height > 0 {
            if let Some(ref finalization) = block.finalization_data {
                // Verify stake threshold
                if finalization.total_stake_voted <= finalization.total_stake_active / 2 {
                    return Err(JsValue::from_str(&format!(
                        "Block {} has insufficient stake votes: {} of {} required", 
                        i, finalization.total_stake_voted, finalization.total_stake_active / 2 + 1
                    )));
                }
                
                // Verify each vote VDF
                for vote in &finalization.votes {
                    let vote_input = format!("{}||{}", vote.validator_id, vote.block_hash);
                    let vdf = VDF::new(2048).map_err(|e| JsValue::from_str(&e.to_string()))?;
                    
                    let is_valid = vdf.verify(vote_input.as_bytes(), &vote.vdf_proof)
                        .map_err(|e| JsValue::from_str(&format!("VDF verify error: {}", e)))?;
                    
                    if !is_valid {
                        return Err(JsValue::from_str(&format!(
                            "Block {} has invalid vote VDF from validator {}", 
                            i, vote.validator_id
                        )));
                    }
                }
            } else {
                return Err(JsValue::from_str(&format!("Block {} missing finalization data", i)));
            }
        }
        
        // Add block to local chain
        local_chain.add_block(block.clone())
            .map_err(|e| JsValue::from_str(&format!("Failed to add block {}: {:?}", i, e)))?;
        
 
    }
    
    log(&format!("[RUST] Successfully synced and validated {} blocks", 
        remote_chain.current_height - local_chain.current_height));
    
    Ok(JsValue::from_bool(true))
}

pub fn distribute_staker_rewards(
    staker_reward: u64,
    valid_votes: &Vec<crate::block::ValidatorVote>,
    total_voted_stake: u64,
) -> Result<(), JsValue> {
    if staker_reward > 0 && !valid_votes.is_empty() && total_voted_stake > 0 {
        let mut pending_rewards = PENDING_REWARDS.lock().unwrap();

        for vote in valid_votes {
            let validator_reward = (staker_reward as u128 * vote.stake_amount as u128 / total_voted_stake as u128) as u64;

            if validator_reward > 0 {
                pending_rewards.push((vote.validator_id.clone(), validator_reward));
            }
        }
    }
    Ok(())
}

#[wasm_bindgen]
pub fn wallet_get_data(wallet_json: &str) -> Result<JsValue, JsValue> {
    let wallet: Wallet = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    #[derive(Serialize)]
    struct WalletData {
        balance: u64,
        utxo_count: usize,
        scan_pub_key_hex: String,
        spend_pub_key_hex: String,
    }

    let data = WalletData {
        balance: wallet.balance(),
        utxo_count: wallet.owned_utxos.len(),
        scan_pub_key_hex: hex::encode(wallet.scan_pub.compress().to_bytes()),
        spend_pub_key_hex: hex::encode(wallet.spend_pub.compress().to_bytes()),
    };

    serde_wasm_bindgen::to_value(&data).map_err(|e| e.into())
}


#[wasm_bindgen]
pub fn get_current_difficulty() -> Result<u8, JsValue> {
    let chain = BLOCKCHAIN.lock().unwrap();
    Ok(chain.calculate_next_difficulty())
}
#[wasm_bindgen]
pub fn check_and_report_violations(reporter_id: String) -> Result<JsValue, JsValue> {
    let evidence_list = slashing::check_all_violations();
    
    if evidence_list.is_empty() {
        log("[SLASHING] No violations detected");
        return Ok(JsValue::from_str("No violations found"));
    }
    
    let mut slashed_count = 0;
    let mut total_reward = 0;
    
    for evidence in evidence_list {
        match slashing::process_slashing_evidence(evidence.clone()) {
            Ok(reward_amount) => {
                let validator_id = match &evidence {
                    slashing::SlashingEvidence::DoubleVote { validator_id, .. } => validator_id,
                    slashing::SlashingEvidence::DishonestVoting { validator_id, .. } => validator_id,
                };
                log(&format!("[SLASHING] Successfully slashed validator {}", validator_id));
                slashed_count += 1;
                total_reward += reward_amount;
            }
            Err(e) => {
                log(&format!("[SLASHING] Failed to process evidence: {}", e));
            }
        }
    }

    // Queue rewards for the reporter
    if total_reward > 0 {
        let mut rewards = PENDING_REWARDS.lock().unwrap();
        rewards.push((reporter_id.clone(), total_reward));
        log(&format!("[SLASHING] Queued {} total reward for reporter {}", total_reward, reporter_id));
    }
    
    Ok(JsValue::from_f64(slashed_count as f64))
}

#[wasm_bindgen]
pub fn report_double_vote(
    validator_id: String,
    height: u64,
    block_hash1: String,
    block_hash2: String,
) -> Result<(), JsValue> {
    let votes = BLOCK_VOTES.lock().unwrap();
    
    // Get the votes for this height
    let height_votes = votes.get(&height)
        .ok_or_else(|| JsValue::from_str("No votes found for this height"))?;
    
    // Get the validator's vote data
    let vote_data = height_votes.get(&validator_id)
        .ok_or_else(|| JsValue::from_str("Validator has not voted at this height"))?;
    
    // Create evidence
    let evidence = slashing::SlashingEvidence::DoubleVote { 
        validator_id: validator_id.clone(),
        height,
        vote1: block::ValidatorVote {
            validator_id: validator_id.clone(),
            block_hash: block_hash1.clone(),
            stake_amount: vote_data.stake_amount,
            vdf_proof: vote_data.vdf_proof.clone(),

            signature: vote_data.signature.clone(),
        },
        vote2: block::ValidatorVote {
            validator_id: validator_id.clone(),
            block_hash: block_hash2.clone(),
            stake_amount: vote_data.stake_amount,
            vdf_proof: vote_data.vdf_proof.clone(),
            signature: vote_data.signature.clone(),
        },

        vote1_block_hash: block_hash1,
        vote2_block_hash: block_hash2,
    };
    
    drop(votes);
    
    slashing::process_slashing_evidence(evidence)
        .map_err(|e| JsValue::from_str(&e))?;
    
    Ok(())
}


#[wasm_bindgen]
pub fn create_utxo_snapshot() -> Result<JsValue, JsValue> {
    let chain = BLOCKCHAIN.lock().unwrap();
    let snapshot = chain.create_utxo_snapshot()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    log(&format!("[RUST] Created UTXO snapshot at height {} with {} UTXOs", 
        snapshot.height, snapshot.utxos.len()));
    
    serde_wasm_bindgen::to_value(&snapshot)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn restore_from_utxo_snapshot(snapshot_js: JsValue) -> Result<(), JsValue> {
    let snapshot: UTXOSnapshot = serde_wasm_bindgen::from_value(snapshot_js)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize snapshot: {}", e)))?;
    
    let height = snapshot.height;
    
    let mut chain = BLOCKCHAIN.lock().unwrap();
    chain.restore_from_snapshot(snapshot)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    log(&format!("[RUST] Restored chain from UTXO snapshot at height {}", height));
    Ok(())
}

#[wasm_bindgen]
pub fn apply_block_cut_through(block_js: JsValue) -> Result<JsValue, JsValue> {
    let mut block: Block = serde_wasm_bindgen::from_value(block_js)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize block: {}", e)))?;
    
    let original_tx_count = block.transactions.len();
    block.apply_cut_through()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    log(&format!("[RUST] Applied cut-through: {} txs -> {} tx", 
        original_tx_count, block.transactions.len()));
    
    serde_wasm_bindgen::to_value(&block)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn prune_blockchain(keep_recent_blocks: u64) -> Result<(), JsValue> {
    let mut chain = BLOCKCHAIN.lock().unwrap();
    let original_length = chain.blocks.len();
    
    chain.prune_to_horizon(keep_recent_blocks)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    log(&format!("[RUST] Pruned blockchain: {} blocks -> {} blocks", 
        original_length, chain.blocks.len()));
    
    Ok(())
}

#[wasm_bindgen]
pub fn get_chain_storage_size() -> Result<JsValue, JsValue> {
    let chain = BLOCKCHAIN.lock().unwrap();
    let utxo_set = UTXO_SET.lock().unwrap();
    
    // Calculate approximate storage size
    let blocks_size: usize = chain.blocks.iter()
        .map(|b| {
            // Rough estimate of block size
            let tx_size: usize = b.transactions.iter()
                .map(|tx| {
                    tx.inputs.len() * 32 + 
                    tx.outputs.iter().map(|o| o.commitment.len() + o.range_proof.len()).sum::<usize>() +
                    96 // kernel size
                })
                .sum();
            tx_size + 200 // header overhead
        })
        .sum();
    
    let utxo_size = utxo_set.len() * (32 + 700); // commitment + range proof average
    
    #[derive(Serialize)]
    struct StorageInfo {
        blocks_count: usize,
        blocks_size_bytes: usize,
        utxo_count: usize,
        utxo_size_bytes: usize,
        total_size_bytes: usize,
        total_size_mb: f64,
    }
    
    let info = StorageInfo {
        blocks_count: chain.blocks.len(),
        blocks_size_bytes: blocks_size,
        utxo_count: utxo_set.len(),
        utxo_size_bytes: utxo_size,
        total_size_bytes: blocks_size + utxo_size,
        total_size_mb: (blocks_size + utxo_size) as f64 / 1_048_576.0,
    };
    
    serde_wasm_bindgen::to_value(&info)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn compute_block_vdf_proof(prev_hash: String) -> Result<JsValue, JsValue> {
    let vdf = VDF::new(2048)
        .map_err(|e| JsValue::from_str(&format!("Failed to create VDF: {:?}", e)))?;
    
    // For testing, use minimal iterations
    let vdf_iterations = 100;
    let vdf_proof = vdf.compute_with_proof(prev_hash.as_bytes(), vdf_iterations)
        .map_err(|e| JsValue::from_str(&format!("Failed to compute VDF: {:?}", e)))?;
    
    serde_wasm_bindgen::to_value(&vdf_proof)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
// In lib.rs

#[wasm_bindgen]
pub fn create_candidate_commitment(
    validator_id: String,
    height: u64,
    known_block_hashes: Vec<String>,
) -> Result<JsValue, JsValue> {
    // Get validator's private key
    let validators = VALIDATORS.lock().unwrap();
    let validator = validators.get(&validator_id)
        .ok_or_else(|| JsValue::from_str("Validator not found"))?;
    
    // Sort hashes for deterministic commitment
    let mut sorted_hashes = known_block_hashes;
    sorted_hashes.sort();
    sorted_hashes.dedup();
    
    // Create commitment
    let commitment = CandidateSetCommitment {
        validator_id: validator_id.clone(),
        height,
        candidate_hashes: sorted_hashes,
        timestamp: js_sys::Date::now() as u64,
        signature: vec![], // Will be filled next
    };
    
    // Sign the commitment
    let message = format!("{:?}", commitment);
    let signature = sign_message(message.clone(), validator.private_key.clone())?;
    
    let mut signed_commitment = commitment;
    signed_commitment.signature = signature;
    
    // Store it
    let mut commitments = CANDIDATE_COMMITMENTS.lock().unwrap();
    let height_commitments = commitments.entry(height).or_insert_with(HashMap::new);
    height_commitments.insert(validator_id, signed_commitment.clone());
    
    serde_wasm_bindgen::to_value(&signed_commitment)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn get_all_known_blocks_from_commitments(height: u64) -> Result<Vec<String>, JsValue> {
    let commitments = CANDIDATE_COMMITMENTS.lock().unwrap();
    let mut all_hashes = HashSet::new();
    
    if let Some(height_commitments) = commitments.get(&height) {
        for (_, commitment) in height_commitments {
            for hash in &commitment.candidate_hashes {
                all_hashes.insert(hash.clone());
            }
        }
    }
    
    Ok(all_hashes.into_iter().collect())
}

#[wasm_bindgen]
pub fn select_best_block(height: u64) -> Result<String, JsValue> {
    let blocks = CANDIDATE_BLOCKS.lock().unwrap();
    
    if let Some(height_blocks) = blocks.get(&height) {
        // Find block with lowest hash (most work)
        let best = height_blocks.values()
            .min_by(|a, b| a.hash().cmp(&b.hash()))
            .ok_or_else(|| JsValue::from_str("No blocks found"))?;
        
        Ok(best.hash())
    } else {
        Err(JsValue::from_str("No blocks at this height"))
    }
}

#[wasm_bindgen]
pub fn get_genesis_timestamp() -> u64 {
    crate::constants::GENESIS_TIMESTAMP_MS
}

#[wasm_bindgen]
pub fn wallet_get_stealth_address(wallet_json: &str) -> Result<String, JsValue> {
    let wallet: Wallet = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let scan_pub_bytes = wallet.scan_pub.compress().to_bytes();
    
    crate::address::encode_stealth_address(&scan_pub_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn create_transaction_to_stealth_address(
    wallet_json: &str,
    amount: u64,
    fee: u64,
    stealth_address: &str, // "pb1..." format
) -> Result<JsValue, JsValue> {
    // Decode stealth address to get recipient's scan public key
    let scan_pub_bytes = crate::address::decode_stealth_address(stealth_address)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // Convert to hex for existing function
    let scan_pub_hex = hex::encode(scan_pub_bytes);
    
    // Use existing transaction creation
    wallet_create_transaction(wallet_json, amount, fee, &scan_pub_hex)
}

#[wasm_bindgen]
pub fn sign_message(message: String, private_key_bytes: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    // Hash the message to create a 32-byte challenge
    let message_hash: [u8; 32] = Sha256::digest(message.as_bytes()).into();

    // Convert the private key bytes into a Scalar
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&private_key_bytes);
    let private_key = Scalar::from_bytes_mod_order(key_array);

    // Create the Schnorr signature
    let (challenge, s) = mimblewimble::create_schnorr_signature(message_hash, &private_key)
        .map_err(|e| JsValue::from_str(&format!("Failed to create signature: {:?}", e)))?;
    
    // Serialize the signature into a single byte vector
    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(&challenge.to_bytes());
    signature.extend_from_slice(&s.to_bytes());

    Ok(signature)
}
#[wasm_bindgen]
pub fn create_final_selection(
    validator_id: String,
    height: u64,
    selected_block_hash: String,
) -> Result<JsValue, JsValue> {
    // Get validator's private key for signing
    let validators = VALIDATORS.lock().unwrap();
    let validator = validators.get(&validator_id)
        .ok_or_else(|| JsValue::from_str("Validator not found"))?;
    
    let private_key = validator.private_key.clone(); // Need to store this!
    drop(validators);
    
    // Create final selection
    let selection = FinalSelection {
        validator_id: validator_id.clone(),
        height,
        selected_block_hash: selected_block_hash.clone(),
        signature: vec![], // Will be filled next
    };
    
    // Sign the selection
    let message = format!("selection:{}:{}:{}", 
        selection.validator_id, 
        selection.height, 
        selection.selected_block_hash
    );
   let signature = sign_message(message, private_key.clone())?;

    
    let mut signed_selection = selection;
    signed_selection.signature = signature;
    
    // Store it
    let mut selections = FINAL_SELECTIONS.lock().unwrap();
    let height_selections = selections.entry(height).or_insert_with(HashMap::new);
    height_selections.insert(validator_id, signed_selection.clone());
    
    serde_wasm_bindgen::to_value(&signed_selection)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn store_candidate_commitment(
    height: u64,
    validator_id: String,
    commitment_js: JsValue,
) -> Result<(), JsValue> {
    let commitment: CandidateSetCommitment = serde_wasm_bindgen::from_value(commitment_js)?;
    
    let mut commitments = CANDIDATE_COMMITMENTS.lock().unwrap();
    let height_commitments = commitments.entry(height).or_insert_with(HashMap::new);
    height_commitments.insert(validator_id, commitment);
    
    Ok(())
}

#[wasm_bindgen]
pub fn store_final_selection(
    height: u64,
    validator_id: String,
    selection_js: JsValue,
) -> Result<(), JsValue> {
    let selection: FinalSelection = serde_wasm_bindgen::from_value(selection_js)?;
    
    let mut selections = FINAL_SELECTIONS.lock().unwrap();
    let height_selections = selections.entry(height).or_insert_with(HashMap::new);
    height_selections.insert(validator_id, selection);
    
    Ok(())
}

#[wasm_bindgen]
pub fn get_candidate_blocks_at_height(height: u64) -> Result<JsValue, JsValue> {
    let blocks = CANDIDATE_BLOCKS.lock().unwrap();
    let height_blocks = blocks.get(&height)
        .map(|hb| hb.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    
    serde_wasm_bindgen::to_value(&height_blocks)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn remove_transactions_from_pool(txs_to_remove_js: JsValue) -> Result<(), JsValue> {
    let transactions: Vec<Transaction> = serde_wasm_bindgen::from_value(txs_to_remove_js)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut pool = TX_POOL.lock().unwrap();

    // Create a set of hashes to remove for efficient lookup
    let hashes_to_remove: std::collections::HashSet<String> = transactions.iter().map(|tx| tx.hash()).collect();

    let initial_count = pool.pending.len();

    // Retain only the transactions that are NOT in the removal set
    pool.pending.retain(|tx| !hashes_to_remove.contains(&tx.hash()));

    // Recalculate total fees
    pool.fee_total = pool.pending.iter().map(|tx| tx.kernel.fee).sum();

    let removed_count = initial_count - pool.pending.len();
    log(&format!("[TX_POOL] Removed {} transactions from the pool.", removed_count));

    Ok(())
}
/// Runs a raw VDF squaring loop for a specified number of iterations and returns the time taken in milliseconds.
/// This is used for calibration from the JS side.
#[wasm_bindgen]
pub fn run_vdf_benchmark(iterations: u64) -> Result<f64, JsValue> {
    let vdf = VDF::new(2048).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut x = num_bigint::BigUint::from(2u32); // Simple starting number
    let modulus = &*vdf.modulus;

    let start_time = Date::now();

    for _ in 0..iterations {
        x = (&x * &x) % modulus;
    }

    let end_time = Date::now();
    Ok(end_time - start_time)
}

/// Sets the globally accessible calibrated VDF speed.
#[wasm_bindgen]
pub fn set_calibrated_vdf_speed(iterations_per_second: u64) {
    let mut vdf_speed = constants::VDF_ITERATIONS_PER_SECOND.lock().unwrap();
    *vdf_speed = iterations_per_second;
    log(&format!("[RUST] VDF speed calibrated and set to {} iterations/sec", iterations_per_second));
}

#[wasm_bindgen]
#[allow(non_snake_case)]
pub fn calibrateVDF() -> Result<(), JsValue> {
    log("[RUST] Starting VDF calibration...");

    let benchmark_iterations = 10_000_000u64;
    let time_taken_ms = run_vdf_benchmark(benchmark_iterations)?;

    if time_taken_ms > 0.0 {
        let iterations_per_second = ((benchmark_iterations as f64 / time_taken_ms) * 1000.0) as u64;
        set_calibrated_vdf_speed(iterations_per_second);
    } else {
        // Fallback for extremely fast machines or timer issues
        let default_speed = 50000u64;
        set_calibrated_vdf_speed(default_speed);
        log(&format!("[RUST_WARN] VDF calibration too fast, using default speed of {}", default_speed));
    }

    Ok(())
}

#[wasm_bindgen]
pub fn wallet_scan_block(wallet_json: &str, block_json: JsValue) -> Result<String, JsValue> {
    let mut wallet: Wallet = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let block: Block = serde_wasm_bindgen::from_value(block_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    wallet.scan_block(&block);
    
    serde_json::to_string(&wallet)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn restore_blockchain_from_state(state_json: &str) -> Result<(), JsValue> {
    // Deserialize the entire blockchain state from the saved JSON.
    let chain_state: blockchain::Blockchain = serde_json::from_str(state_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let height = chain_state.current_height;

    let mut utxo_set = crate::UTXO_SET.lock().unwrap();
    utxo_set.clear();
    for block in &chain_state.blocks {
        for (tx_index, tx) in block.transactions.iter().enumerate() {
            // Remove spent outputs
            for input in &tx.inputs {
                utxo_set.remove(&input.commitment);
            }
            // Add new outputs
            for (output_index, output) in tx.outputs.iter().enumerate() {
                // Create a new UTXO struct from the output and its context
                let utxo = crate::UTXO {
                    commitment: output.commitment.clone(),
                    range_proof: output.range_proof.clone(),
                    block_height: block.height,
                    // Create a simple unique index for the UTXO
                    index: (tx_index * 1000 + output_index) as u32,
                };
                // Insert the correctly typed UTXO struct
                utxo_set.insert(output.commitment.clone(), utxo);
            }
        }
    }
    
    // Now, replace the global blockchain instance with the restored one.
    let mut chain = BLOCKCHAIN.lock().unwrap();
    *chain = chain_state;

    log(&format!("[RUST] Restored blockchain and UTXO set to height {}", height));
    Ok(())
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;
    use super::*;
    use crate::wallet::Wallet;
    use crate::block::Block;
    use crate::transaction::Transaction;
    use crate::consensus_manager::ConsensusResult;

    // Helper to reset global state between tests
    fn reset_globals() {
        BLOCKCHAIN.lock().unwrap().blocks.clear();
        BLOCKCHAIN.lock().unwrap().blocks.push(Block::genesis());
        BLOCKCHAIN.lock().unwrap().current_height = 0;
        VDF_CLOCK.lock().unwrap().current_tick = 0;
        VALIDATORS.lock().unwrap().clear();
        PENDING_STAKES.lock().unwrap().clear();
        BLOCK_VOTES.lock().unwrap().clear();
        UTXO_SET.lock().unwrap().clear();
        TX_POOL.lock().unwrap().pending.clear();
        TX_POOL.lock().unwrap().fee_total = 0;
        CANDIDATE_COMMITMENTS.lock().unwrap().clear();
        FINAL_SELECTIONS.lock().unwrap().clear();
        CANDIDATE_BLOCKS.lock().unwrap().clear();
        PENDING_REWARDS.lock().unwrap().clear();
    }
    
    #[wasm_bindgen_test]
    fn test_wallet_operations() {
        reset_globals();
        
        // Test wallet creation
        let wallet_json = wallet_create().unwrap();
        let _wallet: Wallet = serde_json::from_str(&wallet_json).unwrap();
        
        // Test balance
        let balance = wallet_get_balance(&wallet_json).unwrap();
        assert_eq!(balance, 0);
        
        // Test address operations
        let address = wallet_get_address(&wallet_json).unwrap();
        assert!(validate_address(&address).unwrap());
        
        let stealth_address = wallet_get_stealth_address(&wallet_json).unwrap();
        assert!(stealth_address.starts_with("pb"));
        
        // Test wallet data
        let wallet_data = wallet_get_data(&wallet_json).unwrap();
        let data: serde_json::Value = serde_wasm_bindgen::from_value(wallet_data).unwrap();
        assert_eq!(data["balance"], 0);
        assert_eq!(data["utxo_count"], 0);
    }
    
    #[wasm_bindgen_test]
    fn test_vdf_operations() {
        // Test VDF computation
        let input = "test_input".to_string();
        let iterations = 100;
        let proof_js = perform_vdf_computation(input.clone(), iterations).unwrap();
        
        // Test VDF verification
        let is_valid = verify_vdf_proof(input, proof_js).unwrap();
        assert!(is_valid);
        
        // Test VDF benchmark
        let time_ms = run_vdf_benchmark(1000).unwrap();
        assert!(time_ms > 0.0);
        
        // Test VDF calibration
        set_calibrated_vdf_speed(5000);
        let speed = *constants::VDF_ITERATIONS_PER_SECOND.lock().unwrap();
        assert_eq!(speed, 5000);
    }
    
    #[wasm_bindgen_test]
    fn test_blockchain_operations() {
        reset_globals();
        
        // Initialize blockchain
        let chain_js = init_blockchain().unwrap();
        let chain: blockchain::Blockchain = serde_wasm_bindgen::from_value(chain_js).unwrap();
        assert_eq!(chain.current_height, 0);
        assert_eq!(chain.blocks.len(), 1);
        
        // Test block hash computation
        let genesis = Block::genesis();
        let genesis_js = serde_wasm_bindgen::to_value(&genesis).unwrap();
        let hash = compute_block_hash(genesis_js).unwrap();
        assert_eq!(hash, genesis.hash());
        
        // Test latest block hash
        let latest_hash = get_latest_block_hash().unwrap();
        assert_eq!(latest_hash, genesis.hash());
        
        // Test difficulty
        let difficulty = get_current_difficulty().unwrap();
        assert_eq!(difficulty, 1);
    }
    
    #[wasm_bindgen_test]
    fn test_transaction_pool() {
        reset_globals();
        
        // Initially empty
        let pool_info = get_tx_pool().unwrap();
        let info: serde_json::Value = serde_wasm_bindgen::from_value(pool_info).unwrap();
        assert_eq!(info["pending_count"], 0);
        assert_eq!(info["fee_total"], 0);
        
        // Create a valid transaction
        let _wallet1 = Wallet::new();
        let _wallet2 = Wallet::new();
        
        // Give wallet1 some funds (would normally come from mining)
        let _utxo = crate::wallet::WalletUtxo {
            value: 1000,
            blinding: Scalar::random(&mut rand::thread_rng()),
            commitment: mimblewimble::commit(1000, &Scalar::from(1u64)).unwrap().compress(),
        };
        
        // Clear pool
        clear_transaction_pool().unwrap();
        let pool_info = get_tx_pool().unwrap();
        let info: serde_json::Value = serde_wasm_bindgen::from_value(pool_info).unwrap();
        assert_eq!(info["pending_count"], 0);
    }
    
    #[wasm_bindgen_test]
    fn test_staking_operations() {
        reset_globals();
        
        // Create stake lock
        let validator_id = "test_validator".to_string();
        let stake_amount = 1000;
        let lock_duration = 10;
        
        let stake_lock_js = create_stake_lock(
            validator_id.clone(), 
            stake_amount, 
            lock_duration
        ).unwrap();
        
        let stake_lock: StakeLockTransaction = serde_wasm_bindgen::from_value(stake_lock_js).unwrap();
        assert_eq!(stake_lock.validator_id, validator_id);
        assert_eq!(stake_lock.stake_amount, stake_amount);
        
        // Test minimum stake validation
        let result = create_stake_lock("test".to_string(), 50, 10);
        assert!(result.is_err());
        
        // Test duration validation
        let result = create_stake_lock("test".to_string(), 100, 400);
        assert!(result.is_err());
    }
    
    #[wasm_bindgen_test]
    fn test_consensus_operations() {
        reset_globals();
        
        // Initialize consensus
        let manager = CONSENSUS_MANAGER.lock().unwrap();
        assert_eq!(manager.current_phase, ConsensusPhase::Mining);
        drop(manager);
        
        // Test consensus tick
        let result_js = consensus_tick().unwrap();
        let result: ConsensusResult = serde_wasm_bindgen::from_value(result_js).unwrap();
        assert!(!result.block_added);
        
        // Test PoW candidate submission
        let mut block = Block::genesis();
        block.height = 1;
        block.difficulty = 1;
        
        // Find valid nonce
        while !block.is_valid_pow() {
            block.nonce += 1;
            if block.nonce > 100000 {
                panic!("Could not find valid PoW");
            }
        }
        
        // Set VDF clock to allow submission
        VDF_CLOCK.lock().unwrap().current_tick = 100;
        
        let block_js = serde_wasm_bindgen::to_value(&block).unwrap();
        let result = submit_pow_candidate(block_js);
        assert!(result.is_ok());
    }
    
    #[wasm_bindgen_test]
    fn test_utxo_operations() {
        reset_globals();
        
        // Test UTXO set size
        assert_eq!(get_utxo_set_size(), 0);
        
        // Add some UTXOs via block
        let output = TransactionOutput {
            commitment: vec![1, 2, 3],
            range_proof: vec![],
            ephemeral_key: None,
            stealth_payload: None,
        };
        
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![output],
            kernel: TransactionKernel {
                excess: vec![0; 32],
                signature: vec![0; 64],
                fee: 0,
            },
        };
        
        let mut block = Block::genesis();
        block.height = 1;
        block.transactions = vec![tx];
        
        let block_js = serde_wasm_bindgen::to_value(&block).unwrap();
        update_utxo_set_from_block(block_js).unwrap();
        
        assert_eq!(get_utxo_set_size(), 1);
    }
    
    #[wasm_bindgen_test]
    fn test_storage_operations() {
        reset_globals();
        
        // Create UTXO snapshot
        let snapshot_js = create_utxo_snapshot().unwrap();
        let snapshot: UTXOSnapshot = serde_wasm_bindgen::from_value(snapshot_js.clone()).unwrap();
        assert_eq!(snapshot.height, 0);
        
        // Test storage size calculation
        let storage_info = get_chain_storage_size().unwrap();
        let info: serde_json::Value = serde_wasm_bindgen::from_value(storage_info).unwrap();
        assert!(info["total_size_bytes"].is_u64());

        
        // Test pruning
        prune_blockchain(10).unwrap();
        
        // Test restoration
        restore_from_utxo_snapshot(snapshot_js).unwrap();
    }
    
    #[wasm_bindgen_test]
    fn test_slashing_operations() {
        reset_globals();
        
        // Setup validator
        let mut validators = VALIDATORS.lock().unwrap();
        validators.insert("validator1".to_string(), Validator {
            id: "validator1".to_string(),
            public_key: vec![1, 2, 3],
            private_key: vec![4, 5, 6],
            locked_stakes: vec![],
            total_locked: 1000,
            active: true,
        });
        drop(validators);
        
        // Check for violations (should be none)
        let result = check_and_report_violations("reporter".to_string()).unwrap();
        assert_eq!(result, JsValue::from_str("No violations found"));
        
        // Test double vote reporting (would need proper setup)
        let result = report_double_vote(
            "validator1".to_string(),
            100,
            "block1".to_string(),
            "block2".to_string(),
        );
        assert!(result.is_err()); // No votes exist
    }
    
    #[wasm_bindgen_test]
    fn test_block_mining() {
        reset_globals();
        *constants::VDF_ITERATIONS_PER_SECOND.lock().unwrap() = 100;
        
        // Test block VDF proof computation
        let prev_hash = "test_hash".to_string();
        let vdf_proof_js = compute_block_vdf_proof(prev_hash.clone()).unwrap(); // [758]
        let vdf_proof: VDFProof = serde_wasm_bindgen::from_value(vdf_proof_js.clone()).unwrap();
        assert!(!vdf_proof.y.is_empty());
        // Test mining with transactions
        // Create a valid keypair for the miner's reward output.
        let miner_secret_key = mimblewimble::generate_secret_key();
        let miner_public_key = mimblewimble::derive_public_key(&miner_secret_key);
        let miner_pubkey = miner_public_key.compress().to_bytes().to_vec();

        let result = mine_block_with_txs(
            1,
            Block::genesis().hash(),
            "miner1".to_string(),
            miner_pubkey, // [759]
            1,
            500000, // Increased attempts to prevent intermittent failures
            vdf_proof_js,
        );
        // Should succeed if we find valid PoW
        assert!(result.is_ok(), "Mining should succeed and return a valid block"); // [761]
    }
    
    #[wasm_bindgen_test]
    fn test_candidate_commitment_flow() {
        reset_globals();
        
        // Create candidate commitment
        let validator_id = "validator1".to_string();
        let height = 100;
        let known_hashes = vec!["hash1".to_string(), "hash2".to_string()];
        
        let commitment_js = create_candidate_commitment(
            validator_id.clone(),
            height,
            known_hashes.clone(),
        );
        
        // Should fail without validator
        assert!(commitment_js.is_err());
        
        // Setup validator
        VALIDATORS.lock().unwrap().insert(validator_id.clone(), Validator {
            id: validator_id.clone(),
            public_key: vec![1; 32],
            private_key: vec![2; 32],
            locked_stakes: vec![],
            total_locked: 1000,
            active: true,
        });
        
        // Now should work
        let _commitment_js = create_candidate_commitment(
            validator_id.clone(),
            height,
            known_hashes,
        ).unwrap();
        
        // Test getting all known blocks
        let all_hashes = get_all_known_blocks_from_commitments(height).unwrap();
        assert_eq!(all_hashes.len(), 2);
        
        // Store some blocks and test selection
        let mut blocks = CANDIDATE_BLOCKS.lock().unwrap();
        let height_blocks = blocks.entry(height).or_insert_with(HashMap::new);
        
        let mut block1 = Block::genesis();
        block1.height = height;
        block1.nonce = 1;
        height_blocks.insert("hash1".to_string(), block1);
        
        let mut block2 = Block::genesis();
        block2.height = height;  
        block2.nonce = 1000;
        height_blocks.insert("hash2".to_string(), block2);
        drop(blocks);
        
        // Test best block selection
        let best_hash = select_best_block(height).unwrap();
        assert!(!best_hash.is_empty());
    }
}
#[wasm_bindgen]
pub fn get_chain_work(blocks_json: JsValue) -> Result<u64, JsValue> {
    let blocks: Vec<Block> = serde_wasm_bindgen::from_value(blocks_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    Ok(blockchain::Blockchain::get_chain_work(&blocks))
}




#[wasm_bindgen]
pub fn rewind_block(block_js: JsValue) -> Result<(), JsValue> {
    let block: Block = serde_wasm_bindgen::from_value(block_js)?;
    
    let mut chain = BLOCKCHAIN.lock().unwrap();
    
    // Verify this is the tip
    if chain.current_height != block.height {
        return Err(JsValue::from_str(&format!(
            "Can only rewind from tip. Current height: {}, block height: {}",
            chain.current_height, block.height
        )));
    }
    
    // First, restore all inputs (spent UTXOs) back to the UTXO set
    {
        let mut utxo_set = blockchain::UTXO_SET.lock().unwrap();
        let mut global_utxo_set = UTXO_SET.lock().unwrap();
        let mut cache = RECENT_UTXO_CACHE.lock().unwrap();
        
        for tx in &block.transactions {
            // Skip coinbase transactions
            if tx.inputs.is_empty() {
                continue;
            }
            
            for input in &tx.inputs {
                // First check cache
                if let Some((height, output)) = cache.get(&input.commitment) {
                    utxo_set.insert(input.commitment.clone(), output.clone());
                    global_utxo_set.insert(input.commitment.clone(), UTXO {
                        commitment: input.commitment.clone(),
                        range_proof: output.range_proof.clone(),
                        block_height: *height,
                        index: 0,
                    });
                    log(&format!("[RUST] Restored UTXO from cache at height {}", height));
                    continue;
                }
                
                // If input has merkle proof, we can verify it existed
                if let Some(proof) = &input.merkle_proof {
                    // Verify the proof against the previous block's UTXO root
                    let roots = blockchain::UTXO_ROOTS.lock().unwrap();
                    if let Some(root) = roots.get(&(block.height - 1)) {
                        if !proof.verify(root) {
                            log(&format!("[RUST] Warning: Invalid merkle proof for input"));
                        }
                    }
                }
                
                // Still need to search for the actual output data
                // But with proof, we know it must exist somewhere
                let mut found = false;
                
                // Search backwards through the chain
                for search_height in (0..block.height).rev() {
                    if let Some(search_block) = chain.blocks.get(search_height as usize) {
                        for search_tx in &search_block.transactions {
                            for search_output in &search_tx.outputs {
                                if search_output.commitment == input.commitment {
                                    // Found the output that was spent
                                    utxo_set.insert(input.commitment.clone(), search_output.clone());
                                    
                                    global_utxo_set.insert(input.commitment.clone(), UTXO {
                                        commitment: input.commitment.clone(),
                                        range_proof: search_output.range_proof.clone(),
                                        block_height: search_height,
                                        index: 0,
                                    });
                                    
                                    // Add to cache for future reorgs
                                    cache.insert(
                                        input.commitment.clone(),
                                        (search_height, search_output.clone())
                                    );
                                    
                                    found = true;
                                    break;
                                }
                            }
                            if found { break; }
                        }
                    }
                    if found { break; }
                }
                
                if !found {
                    log(&format!("[RUST] Warning: Could not find source output for input {:?}", 
                        hex::encode(&input.commitment[..8])));
                }
            }
            
            // Remove outputs created by this block
            for output in &tx.outputs {
                utxo_set.remove(&output.commitment);
                global_utxo_set.remove(&output.commitment);
                cache.remove(&output.commitment);
            }
        }
        
        // Prune cache if it gets too large (keep last 1000 entries)
        if cache.len() > 1000 {
            let mut entries: Vec<_> = cache.drain().collect();
            entries.sort_by_key(|(_, (height, _))| *height);
            entries.reverse();
            entries.truncate(1000);
            *cache = entries.into_iter().collect();
        }
    }
    
    // Remove UTXO root for this height
    {
        let mut roots = blockchain::UTXO_ROOTS.lock().unwrap();
        roots.remove(&block.height);
    }
    
    // Remove block from chain
    chain.blocks.pop();
    chain.block_by_hash.remove(&block.hash());
    chain.current_height -= 1;
    
    // Recalculate difficulty if needed
    if chain.current_height > 0 && 
       chain.current_height % constants::DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
        chain.current_difficulty = chain.calculate_next_difficulty();
    }
    
    // Clear any consensus state related to this height
    {
        let mut votes = BLOCK_VOTES.lock().unwrap();
        votes.remove(&block.height);
    }
    {
        let mut commitments = CANDIDATE_COMMITMENTS.lock().unwrap();
        commitments.remove(&block.height);
    }
    {
        let mut selections = FINAL_SELECTIONS.lock().unwrap();
        selections.remove(&block.height);
    }
    {
        let mut candidates = CANDIDATE_BLOCKS.lock().unwrap();
        candidates.remove(&block.height);
    }
    
    // Return transactions to the mempool (except coinbase)
    {
        let mut tx_pool = TX_POOL.lock().unwrap();
        for tx in block.transactions {
            if !tx.inputs.is_empty() { // Skip coinbase
                // Verify the transaction is still valid before adding back
                match tx.verify(None) {
                    Ok(_) => {
                        tx_pool.pending.push(tx.clone());
                        tx_pool.fee_total += tx.kernel.fee;
                    }
                    Err(e) => {
                        log(&format!("[RUST] Not returning tx to pool: {:?}", e));
                    }
                }
            }
        }
    }
    
    log(&format!("[RUST] Successfully rewound block at height {}", block.height));
    Ok(())
}

#[wasm_bindgen]
pub fn wallet_unscan_block(wallet_json: &str, block_js: JsValue) -> Result<String, JsValue> {
    let mut wallet: Wallet = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let block: Block = serde_wasm_bindgen::from_value(block_js)?;
    
    // We need to remove any UTXOs that came from this block
    // First, collect all output commitments from this block
    let mut block_commitments = HashSet::new();
    for tx in &block.transactions {
        for output in &tx.outputs {
            block_commitments.insert(output.commitment.clone());
        }
    }
    
    // Remove any owned UTXOs that match commitments from this block
    let initial_count = wallet.owned_utxos.len();
    wallet.owned_utxos.retain(|utxo| {
        !block_commitments.contains(&utxo.commitment.to_bytes().to_vec())
    });
    
    let removed_count = initial_count - wallet.owned_utxos.len();
    if removed_count > 0 {
        log(&format!("[RUST] Removed {} UTXOs from wallet during unscan of block {}", 
            removed_count, block.height));
    }
    
    serde_json::to_string(&wallet)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}



#[wasm_bindgen]
pub fn store_network_vote(
    validator_id: String,
    block_height: u64,
    block_hash: String,
    stake_amount: u64,
    vdf_proof_js: JsValue,
    signature: Vec<u8>,
) -> Result<(), JsValue> {
    let vdf_proof: VDFProof = serde_wasm_bindgen::from_value(vdf_proof_js)?;
    
    let mut votes = BLOCK_VOTES.lock().unwrap();
    let height_votes = votes.entry(block_height).or_insert_with(HashMap::new);
    
    // Check for double voting
    if let Some(existing_vote) = height_votes.get(&validator_id) {
        if existing_vote.block_hash != block_hash {
            log(&format!("[RUST] WARNING: Validator {} attempting double vote at height {}", 
                validator_id, block_height));
            return Err(JsValue::from_str("Double vote detected"));
        }
    }
    
    let vote_data = VoteData {
        block_hash,
        stake_amount,
        vdf_proof,
        signature,
        timestamp: js_sys::Date::now() as u64,
    };
    
    height_votes.insert(validator_id.clone(), vote_data);
    
    log(&format!("[RUST] Stored vote from {} for block at height {}", 
        validator_id, block_height));
    
    Ok(())
}

#[wasm_bindgen]
pub fn store_candidate_block(
    height: u64,
    hash: String,
    block_js: JsValue,
) -> Result<(), JsValue> {
    let block: Block = serde_wasm_bindgen::from_value(block_js)?;
    
    // Verify the block is valid before storing
    if !block.is_valid_pow() {
        return Err(JsValue::from_str("Invalid PoW"));
    }
    
    if block.height != height {
        return Err(JsValue::from_str("Height mismatch"));
    }
    
    if block.hash() != hash {
        return Err(JsValue::from_str("Hash mismatch"));
    }
    
    let mut blocks = CANDIDATE_BLOCKS.lock().unwrap();
    let height_blocks = blocks.entry(height).or_insert_with(HashMap::new);
    
    // Limit candidates per height to prevent DoS
    if height_blocks.len() >= 100 {
        log(&format!("[RUST] Too many candidates at height {}, rejecting", height));
        return Err(JsValue::from_str("Too many candidates at this height"));
    }
    
    height_blocks.insert(hash.clone(), block);
    
    log(&format!("[RUST] Stored candidate block {} at height {}", 
        &hash[..16], height));
    
    Ok(())
}

#[wasm_bindgen]
pub fn get_block_by_hash(hash: &str) -> Result<JsValue, JsValue> {
    let chain = BLOCKCHAIN.lock().unwrap();
    
    // First check main chain
    if let Some(block) = chain.block_by_hash.get(hash) {
        return serde_wasm_bindgen::to_value(block)
            .map_err(|e| JsValue::from_str(&e.to_string()));
    }
    
    // Then check candidate blocks
    let candidates = CANDIDATE_BLOCKS.lock().unwrap();
    for (_height, height_blocks) in candidates.iter() {
        if let Some(block) = height_blocks.get(hash) {
            return serde_wasm_bindgen::to_value(block)
                .map_err(|e| JsValue::from_str(&e.to_string()));
        }
    }
    
    Err(JsValue::from_str("Block not found"))
}

#[wasm_bindgen]
pub fn verify_chain_segment(blocks_json: JsValue) -> Result<bool, JsValue> {
    let blocks: Vec<Block> = serde_wasm_bindgen::from_value(blocks_json)?;
    
    if blocks.is_empty() {
        return Ok(true);
    }
    
    // Verify each block connects to the previous
    for i in 1..blocks.len() {
        if blocks[i].prev_hash != blocks[i-1].hash() {
            log(&format!("[RUST] Chain segment broken at height {}", blocks[i].height));
            return Ok(false);
        }
        
        if blocks[i].height != blocks[i-1].height + 1 {
            log(&format!("[RUST] Height discontinuity at {}", blocks[i].height));
            return Ok(false);
        }
        
        if !blocks[i].is_valid_pow() {
            log(&format!("[RUST] Invalid PoW at height {}", blocks[i].height));
            return Ok(false);
        }
        
        if !blocks[i].has_valid_vdf_proof() {
            log(&format!("[RUST] Invalid VDF at height {}", blocks[i].height));
            return Ok(false);
        }
    }
    
    Ok(true)
}
