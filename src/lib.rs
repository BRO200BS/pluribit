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
use std::collections::HashSet;
use crate::vrf::VrfProof;

use crate::wallet::Wallet; 

use crate::vdf::{VDF, VDFProof};

use crate::transaction::{Transaction, TransactionOutput, TransactionKernel};
use crate::block::Block; 
use crate::constants::MAX_TX_POOL_SIZE;

pub mod constants;
pub mod error;
pub mod utils;
pub mod vdf;
pub mod mimblewimble;
pub mod transaction;
pub mod block;
pub mod blockchain;
pub mod stealth;
pub mod wallet;
pub mod address;
pub mod merkle;
pub mod vrf;




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

#[derive(Clone)]
#[allow(dead_code)]
struct PoWTicket {
    nonce: u64,
    hash: [u8; 32],
    timestamp: u64,
}

#[derive(Serialize, Default)]
pub struct MiningMetrics {
    pub pow_attempts: u64,
    pub vrf_attempts: u64,
    pub blocks_mined: u64,
    pub avg_pow_time_ms: u64,
    pub avg_vdf_time_ms: u64,
}


lazy_static! {
    static ref BLOCKCHAIN: Mutex<blockchain::Blockchain> = Mutex::new(blockchain::Blockchain::new());
    static ref TX_POOL: Mutex<TransactionPool> = Mutex::new(TransactionPool {
        pending: Vec::new(),
        fee_total: 0,
    });
    static ref POW_TICKET_CACHE: Mutex<HashMap<[u8; 32], Vec<PoWTicket>>> = 
        Mutex::new(HashMap::new());
    
    static ref MINING_METRICS: Mutex<MiningMetrics> = 
        Mutex::new(MiningMetrics::default());
        
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
pub fn get_block_by_hash(hash: String) -> Result<JsValue, JsValue> {
    let chain = BLOCKCHAIN.lock().unwrap();
    
    // Check all blocks including genesis
    for block in &chain.blocks {
        if block.hash() == hash {
            return serde_wasm_bindgen::to_value(&block).map_err(|e| e.into());
        }
    }
    
    // Also check the hash map
    if let Some(block) = chain.block_by_hash.get(&hash).cloned() {
        serde_wasm_bindgen::to_value(&block).map_err(|e| e.into())
    } else {
        Ok(JsValue::NULL)
    }
}


#[wasm_bindgen]
pub fn get_blockchain_with_hashes() -> Result<JsValue, JsValue> {
    let chain = BLOCKCHAIN.lock().unwrap();

    #[derive(serde::Serialize)]
    struct BlockWithHash {
        height: u64,
        prev_hash: String,
        timestamp: u64,
        pow_nonce: u64, 
        miner_id: String,
        hash: String,
    }

    let blocks_with_hashes: Vec<BlockWithHash> = chain.blocks.iter().map(|block| {
        BlockWithHash {
            height: block.height,
            prev_hash: block.prev_hash.clone(),
            timestamp: block.timestamp,
            pow_nonce: block.pow_nonce, 
            miner_id: hex::encode(block.miner_pubkey), // <-- Use miner_pubkey
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


// Introducing - PoWrPoST - Thermodynamic finality!
 #[wasm_bindgen]
 pub fn mine_block_header(
     height: u64,
     miner_secret_key_bytes: Vec<u8>,
     prev_hash: String,
     vdf_iterations: u64,
     vrf_threshold_bytes: Vec<u8>,
     start_nonce: u64,
     max_nonce: u64,
 ) -> Result<JsValue, JsValue> {
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    
    // Validate inputs
    if miner_secret_key_bytes.len() != 32 {
        return Err(JsValue::from_str("Invalid secret key length"));
    }
    
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&miner_secret_key_bytes);
    let secret_key = Scalar::from_bytes_mod_order(sk_bytes);
    let public_key = &secret_key * &*RISTRETTO_BASEPOINT_TABLE;
    let miner_pubkey = public_key.compress().to_bytes();
    
    let mut vrf_threshold = [0u8; 32];
    vrf_threshold.copy_from_slice(&vrf_threshold_bytes);
    
    // Sequential-lottery ticketing: VDF -> VRF (no PoW)
   // Mine just the header ticket (no transactions needed yet)
    for nonce in start_nonce..max_nonce {
        let mut test_block = Block::genesis();
        test_block.height = height;
        test_block.prev_hash = prev_hash.clone();
        test_block.miner_pubkey = miner_pubkey;
        test_block.pow_nonce = nonce;
        
        // 1) VDF ticket: input binds (prev_hash, miner_pubkey, nonce)
        let vdf = VDF::new(2048).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let vdf_input = format!("{}{}{}", prev_hash, hex::encode(miner_pubkey), nonce);
        let vdf_proof = vdf.compute_with_proof(vdf_input.as_bytes(), vdf_iterations)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // 2) VRF lottery over the VDF output (non-outsourcable per attempt)
        let vrf_proof = vrf::create_vrf(&secret_key, &vdf_proof.y);
        if vrf_proof.output >= vrf_threshold {
            continue;
        }

        // Found valid ticket!
        log(&format!("[MINING] Won lottery! Nonce: {}, VRF: {}", 
            nonce, hex::encode(&vrf_proof.output[..8])));
        
        #[derive(Serialize)]
        struct HeaderSolution {
            nonce: u64,
            vrf_proof: VrfProof,
            vdf_proof: VDFProof,
            miner_pubkey: Vec<u8>,
        }
        
        return serde_wasm_bindgen::to_value(&HeaderSolution {
            nonce,
            vrf_proof,
            vdf_proof,
            miner_pubkey: miner_pubkey.to_vec(),
        }).map_err(|e| e.into());
    }
    
    // No solution in this range
    Ok(JsValue::NULL)
}

#[wasm_bindgen]
pub fn complete_block_with_transactions(
     height: u64,
     prev_hash: String,
     nonce: u64,
     miner_pubkey_bytes: Vec<u8>,
     miner_scan_pubkey_bytes: Vec<u8>,
     vrf_proof_js: JsValue,
     vdf_proof_js: JsValue,
     pow_difficulty: u8,
     mempool_transactions_js: JsValue,  
 ) -> Result<JsValue, JsValue> {
    // Deserialize VRF proof
    let vrf_proof: VrfProof = serde_wasm_bindgen::from_value(vrf_proof_js)?;
    
    // Use the VDF proof computed during header mining
    let vdf_proof: VDFProof = serde_wasm_bindgen::from_value(vdf_proof_js)?;
    
    // NOW get current mempool transactions
    // Get transactions from parameter if provided, otherwise from local pool
    let mut transactions: Vec<Transaction> = if mempool_transactions_js.is_null() || mempool_transactions_js.is_undefined() {
        let pool = TX_POOL.lock().unwrap();
        pool.pending.clone()
    } else {
        serde_wasm_bindgen::from_value(mempool_transactions_js)?
    };
    let total_fees: u64 = transactions.iter().map(|tx| tx.kernel.fee).sum();
    
    // Calculate reward
    let chain = BLOCKCHAIN.lock().unwrap();
    let reward = chain.calculate_block_reward(height, pow_difficulty) + total_fees; // Miner collects fees!
    drop(chain);
    
    // Create coinbase
    let coinbase_tx = Transaction::create_coinbase(vec![(miner_scan_pubkey_bytes, reward)])
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    transactions.insert(0, coinbase_tx);
    
    // Build final block
    let mut miner_pubkey = [0u8; 32];
    miner_pubkey.copy_from_slice(&miner_pubkey_bytes);
    
    let mut block = Block {
        height,
        prev_hash,
        timestamp: js_sys::Date::now() as u64,
        transactions,
        pow_nonce: nonce, // acts as ticket_nonce; kept on-wire
        vrf_proof,
        vdf_proof,
        miner_pubkey,
        tx_merkle_root: [0u8; 32],
        hash: String::new(),
    };
    
    // Apply cut-through
    block.apply_cut_through()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    block.tx_merkle_root = block.calculate_tx_merkle_root();
    block.hash = block.compute_hash();
    
    log(&format!("[MINING] Completed block #{} with {} transactions", 
        height, block.transactions.len() - 1));
    
    serde_wasm_bindgen::to_value(&block).map_err(|e| e.into())
}




#[wasm_bindgen]
pub fn get_current_mining_params() -> Result<JsValue, JsValue> {
    let chain = BLOCKCHAIN.lock().unwrap();
    
    #[derive(Serialize)]
    struct MiningParams {
        pow_difficulty: u8,
        vrf_threshold: String,
        vdf_iterations: u64,
        current_height: u64,
        total_work: u64,
    }
    
    let params = MiningParams {
        pow_difficulty: chain.current_pow_difficulty,
        vrf_threshold: hex::encode(&chain.current_vrf_threshold),
        vdf_iterations: chain.current_vdf_iterations,
        current_height: chain.current_height,
        total_work: chain.total_work,
    };
    
    serde_wasm_bindgen::to_value(&params).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn get_mining_metrics() -> Result<JsValue, JsValue> {
    let metrics = MINING_METRICS.lock().unwrap();
    serde_wasm_bindgen::to_value(&*metrics).map_err(|e| e.into())
}


#[wasm_bindgen]
pub fn add_transaction_to_pool(tx_json: JsValue) -> Result<(), JsValue> {
    let tx: Transaction = serde_wasm_bindgen::from_value(tx_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize transaction: {}", e)))?;

    // 1) Kernel signature (single source of truth)
    if !tx.verify_signature().unwrap_or(false) {
        return Err(JsValue::from_str("Invalid transaction signature"));
    }

    // 2) Range proofs
    for output in &tx.outputs {
        let commitment = CompressedRistretto::from_slice(&output.commitment)
            .map_err(|_| JsValue::from_str("Invalid output commitment"))?;
        let proof = RangeProof::from_bytes(&output.range_proof)
            .map_err(|_| JsValue::from_str("Invalid range proof format"))?;
        if !mimblewimble::verify_range_proof(&proof, &commitment) {
            return Err(JsValue::from_str("Range proof verification failed"));
        }
    }

    // 3) Mimblewimble balance:
    //    sum(inputs) == sum(outputs) + kernel_excess
    //    (your kernel_excess is commit(fee, blinding), so adding it is correct)
    let mut input_sum = RistrettoPoint::identity();
    let mut output_sum = RistrettoPoint::identity();

    for input in &tx.inputs {
        let c = CompressedRistretto::from_slice(&input.commitment)
            .map_err(|_| JsValue::from_str("Invalid input commitment"))?
            .decompress()
            .ok_or_else(|| JsValue::from_str("Failed to decompress input commitment"))?;
        input_sum += c;
    }
    for output in &tx.outputs {
        let c = CompressedRistretto::from_slice(&output.commitment)
            .map_err(|_| JsValue::from_str("Invalid output commitment"))?
            .decompress()
            .ok_or_else(|| JsValue::from_str("Failed to decompress output commitment"))?;
        output_sum += c;
    }

    // kernel.excess -> point
    let excess_point = CompressedRistretto::from_slice(&tx.kernel.excess)
        .map_err(|_| JsValue::from_str("Invalid kernel excess"))?
        .decompress()
        .ok_or_else(|| JsValue::from_str("Failed to decompress kernel excess"))?;

    if input_sum != (output_sum + excess_point) {
        return Err(JsValue::from_str("Transaction doesn't balance"));
    }

    // 4) Inputs must exist in current UTXO set (and not be spent already)
    let utxo_set_guard = blockchain::UTXO_SET.lock().unwrap_or_else(|p| p.into_inner());
    for input in &tx.inputs {
        if !utxo_set_guard.contains_key(&input.commitment) {
            return Err(JsValue::from_str("Input not found in UTXO set"));
        }
    }
    drop(utxo_set_guard);

    // 5) Mempool policy & add
    let mut pool = TX_POOL.lock().unwrap_or_else(|p| p.into_inner());

    // (optional but recommended) prevent conflicts with pending txs
    for pending in &pool.pending {
        // same kernel = duplicate
        if pending.kernel.excess == tx.kernel.excess {
            return Err(JsValue::from_str("Transaction already in pool"));
        }
        // basic double-spend check vs pending txs
        for inp in &tx.inputs {
            if pending.inputs.iter().any(|i| i.commitment == inp.commitment) {
                return Err(JsValue::from_str("Conflicts with pending transaction (double spend)"));
            }
        }
    }

    if pool.pending.len() >= MAX_TX_POOL_SIZE {
        if let Some((idx, low)) = pool.pending.iter().enumerate().min_by_key(|(_, t)| t.kernel.fee) {
            if tx.kernel.fee > low.kernel.fee {
                log(&format!(
                    "[RUST] Pool full. Evicting tx with fee {} to add new tx with fee {}",
                    low.kernel.fee, tx.kernel.fee
                ));
                pool.fee_total -= low.kernel.fee;
                pool.pending.remove(idx);
            } else {
                return Err(JsValue::from_str(&format!(
                    "Transaction fee {} is too low for a full pool. Minimum required: {}",
                    tx.kernel.fee, low.kernel.fee + 1
                )));
            }
        } else {
            return Err(JsValue::from_str("Pool is full but could not determine minimum fee."));
        }
    }

    pool.fee_total += tx.kernel.fee;
    pool.pending.push(tx);
    log(&format!("[RUST] Added network transaction to pool. Total: {}", pool.pending.len()));
    Ok(())
}


#[wasm_bindgen]
pub fn verify_transaction(tx_json: JsValue) -> Result<bool, JsValue> {
    let tx: Transaction = serde_wasm_bindgen::from_value(tx_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize transaction: {}", e)))?;

    // Lock the UTXO set to pass it to the verify function.
    let utxos = crate::blockchain::UTXO_SET.lock().unwrap();
    
    // Call verify with the correct arguments.
    match tx.verify(None, Some(&utxos)) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
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
pub fn get_utxo_set_size() -> usize {
    blockchain::UTXO_SET.lock().unwrap().len()
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
    let utxo_set = blockchain::UTXO_SET.lock().unwrap();
    
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
pub fn get_genesis_block_hash() -> String {
    block::Block::genesis().hash()
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
pub fn get_chain_work(blocks_json: JsValue) -> Result<u64, JsValue> {
    let blocks: Vec<Block> = serde_wasm_bindgen::from_value(blocks_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    Ok(blockchain::Blockchain::get_chain_work(&blocks))
}




#[wasm_bindgen]
pub fn rewind_block(block_js: JsValue) -> Result<(), JsValue> {
    let block: Block = serde_wasm_bindgen::from_value(block_js)?;
    let mut chain = BLOCKCHAIN.lock().unwrap();

    // Verify this is the tip of the chain before rewinding
    if chain.current_height != block.height {
        return Err(JsValue::from_str(&format!(
            "Can only rewind from tip. Current height: {}, block height: {}",
            chain.current_height, block.height
        )));
    }

    // --- Start of Refactored State Manipulation ---
    { // This scope ensures mutex locks are released as soon as we're done with them.
        
        // 1. Lock the ONE canonical UTXO set.
        let mut utxo_set = blockchain::UTXO_SET.lock().unwrap();
        let mut cache = RECENT_UTXO_CACHE.lock().unwrap();

        for tx in &block.transactions {
            // For every input in the rewound transaction, we must find the
            // original TransactionOutput it came from and add it back to the UTXO set.
            if !tx.inputs.is_empty() { // Skip coinbase transactions which have no inputs.
                for input in &tx.inputs {
                    let mut found_output: Option<TransactionOutput> = None;

                    // A. First, try the fast cache to find the spent output.
                    if let Some((_height, output)) = cache.get(&input.commitment) {
                        found_output = Some(output.clone());
                    } else {
                        // B. If not in cache, search the chain backwards block by block.
                        'search: for search_block in chain.blocks.iter().rev() {
                            for search_tx in &search_block.transactions {
                                for search_output in &search_tx.outputs {
                                    if search_output.commitment == input.commitment {
                                        found_output = Some(search_output.clone());
                                        // Add to cache for future reorgs
                                        cache.insert(
                                            input.commitment.clone(),
                                            (search_block.height, search_output.clone())
                                        );
                                        break 'search; // Exit all loops once found.
                                    }
                                }
                            }
                        }
                    }

                    // C. If we found the original output, add it back to the live UTXO set.
                    if let Some(output_to_restore) = found_output {
                        utxo_set.insert(input.commitment.clone(), output_to_restore);
                    } else {
                        log(&format!("[RUST] Reorg Warning: Could not find source for input {:?}",
                            hex::encode(&input.commitment[..8])
                        ));
                    }
                }
            }

            // 2. Remove the outputs that were created in this block from the UTXO set and cache.
            for output in &tx.outputs {
                utxo_set.remove(&output.commitment);
                cache.remove(&output.commitment);
            }
        }
    } // All locks on UTXO_SET and RECENT_UTXO_CACHE are released here.
    // --- End of Refactored State Manipulation ---


    
    // Return the block's non-coinbase transactions to the mempool
    {
        let mut tx_pool = TX_POOL.lock().unwrap();
        let utxo_set = blockchain::UTXO_SET.lock().unwrap();
        for tx in &block.transactions {

            if !tx.inputs.is_empty() { // Skip coinbase
                // Verify the transaction is still valid with the new state before adding back
                if tx.verify(None, Some(&utxo_set)).is_ok() {
                    tx_pool.pending.push(tx.clone());
                    tx_pool.fee_total += tx.kernel.fee;
                }
            }
        }
    }

    // 4. Finally, update the chain's metadata.
    chain.block_by_hash.remove(&block.hash());
    chain.blocks.pop();
    chain.current_height -= 1;
    
    
    log(&format!("[RUST] Successfully rewound block at height {}", block.height + 1));
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




#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use wasm_bindgen_test::*;
    use super::*;
    use crate::wallet::Wallet;
    use crate::transaction::Transaction;

    // Helper to reset global state between tests
    fn reset_globals() {
        let mut chain = BLOCKCHAIN.lock().unwrap();
        *chain = blockchain::Blockchain::new();

        let mut utxo_set = blockchain::UTXO_SET.lock().unwrap();
        utxo_set.clear();

        let mut tx_pool = TX_POOL.lock().unwrap();
        tx_pool.pending.clear();
        tx_pool.fee_total = 0;
    }

}


