// native/src/db.rs
//
// FINAL IMPLEMENTATION: Replaces js_bridge.cjs with native RocksDB logic.
// This file contains the full implementation for all database functions,
// including wallet encryption, ported from the original CJS module.

use neon::prelude::*;
use neon::types::buffer::TypedArray;
use neon::types::JsBigInt;
use rocksdb::{DB, Options, IteratorMode, WriteBatch, Direction};
use std::sync::{Arc, Mutex, Once};
use lazy_static::lazy_static;
use std::env;
use neon_serde4::{from_value, to_value};
use std::collections::HashMap;

// Import pluribit core Rust structs and Protobuf definitions
use pluribit_core::{
    block::Block,
    transaction::TransactionOutput,
    p2p::{Block as P2pBlock, TransactionOutput as P2pTransactionOutput, ReorgMarker as P2pReorgMarker},
    wasm_types::WasmU64,
};
use prost::Message; // For encoding/decoding Protobuf messages

// For wallet encryption
use scrypt::{scrypt, Params as ScryptParams};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, Key, XNonce
};
use rand_core::RngCore;

// --- Database Singleton ---

lazy_static! {
    static ref DB_INSTANCE: Arc<Mutex<Option<DB>>> = Arc::new(Mutex::new(None));
    static ref INIT: Once = Once::new();
}
const DB_PATH: &str = "pluribit-data/rocksdb_native";

/// Initializes and returns the RocksDB instance (idempotent).
fn get_or_init_db() -> Result<Arc<Mutex<Option<DB>>>, String> {
    INIT.call_once(|| {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_max_open_files(512);
        opts.set_keep_log_file_num(10);
        opts.set_max_background_jobs(4);
       
        // Performance optimizations
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
        opts.set_max_write_buffer_number(3);
        opts.set_target_file_size_base(64 * 1024 * 1024);
        opts.set_level_zero_file_num_compaction_trigger(8);
        opts.set_level_zero_slowdown_writes_trigger(17);
        opts.set_level_zero_stop_writes_trigger(24);
       
        // Enable compression
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
       
        match DB::open(&opts, DB_PATH) {
            Ok(db) => {
                *DB_INSTANCE.lock().unwrap() = Some(db);
                eprintln!("[RocksDB] Native database opened successfully at {}", DB_PATH);
            }
            Err(e) => {
                eprintln!("[RocksDB] Failed to open native database: {}", e);
            }
        }
    });
   
    Ok(Arc::clone(&DB_INSTANCE))
}

/// Helper to execute a closure with the DB lock held.
fn with_db<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce(&DB) -> Result<T, String>,
{
    let db_arc = get_or_init_db()?;
    let db_guard = db_arc.lock().map_err(|e| format!("DB Lock poisoned: {}", e))?;
    let db = db_guard.as_ref().ok_or("Database not initialized")?;
    f(db)
}

// --- JS Type Conversion Helper ---

/// Safely converts a JsValue (BigInt or Number) to u64.
fn js_value_to_u64(cx: &mut FunctionContext, val: Handle<JsValue>) -> NeonResult<u64> {
    if let Ok(js_bigint) = val.downcast::<JsBigInt, _>(cx) {
        match js_bigint.to_u64(cx) {
            Ok(v) => Ok(v),
            Err(_) => cx.throw_error("Failed to convert BigInt to u64. It may be out of range."),
        }
    } else if let Ok(js_number) = val.downcast::<JsNumber, _>(cx) {
        Ok(js_number.value(cx) as u64)
    } else if let Ok(js_string) = val.downcast::<JsString, _>(cx) {
        // Handle u64 serialized as string (from WASM WasmU64)
        match js_string.value(cx).parse::<u64>() {
            Ok(v) => Ok(v),
            Err(_) => cx.throw_error("Failed to parse u64 from string."),
        }
    } else {
        cx.throw_error("Argument must be a Number, BigInt, or string-serialized u64.")
    }
}

// --- Wallet Encryption Helpers ---

const PASS_ENV: &str = "PLURIBIT_WALLET_PASSPHRASE";
// scrypt parameters matching js_bridge.cjs
const SCRYPT_LOG_N: u8 = 14; // N = 16384
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_DK_LEN: usize = 32;

/// Gets the wallet passphrase from the environment variable.
fn get_passphrase() -> Option<String> {
    env::var(PASS_ENV).ok().filter(|s| s.len() >= 8)
}

/// A struct representing the on-disk encrypted wallet format.
#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedEnvelope {
    enc: bool,
    v: u32,
    alg: String,
    kdf: String,
    scrypt: ScryptEnvelopeParams,
    s: String, // salt (base64)
    n: String, // nonce (base64)
    ct: String, // ciphertext (base64)
    tag: String, // auth tag (base64)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ScryptEnvelopeParams {
    #[serde(rename = "N")]
    n: u32,
    r: u32,
    p: u32,
    #[serde(rename = "dkLen")]
    dk_len: usize,
}

/// Checks if a string is an encrypted wallet envelope.
fn is_encrypted_envelope(data: &str) -> bool {
    serde_json::from_str::<EncryptedEnvelope>(data)
        .map_or(false, |env| env.enc && env.alg == "aes-256-gcm" && env.kdf == "scrypt")
}

/// Encrypts a plaintext wallet string using the provided passphrase.
fn encrypt_wallet(plaintext: &str, passphrase: &str) -> Result<String, String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let params = ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_DK_LEN)
        .map_err(|e| e.to_string())?;
    
    let mut key_bytes = [0u8; SCRYPT_DK_LEN];
    scrypt(passphrase.as_bytes(), &salt, &params, &mut key_bytes)
        .map_err(|e| e.to_string())?;
    
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Rationale: XChaCha20Poly1305::encrypt returns `Vec<u8>` which is `ciphertext || tag`
    let ct_with_tag = cipher.encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| e.to_string())?;

    // We must split them to match the JS implementation's envelope
    if ct_with_tag.len() <= 16 {
        return Err("Encryption produced invalid output".to_string());
    }
    let (ciphertext, tag) = ct_with_tag.split_at(ct_with_tag.len() - 16);

    let envelope = EncryptedEnvelope {
        enc: true,
        v: 1,
        alg: "aes-256-gcm".to_string(),
        kdf: "scrypt".to_string(),
        scrypt: ScryptEnvelopeParams {
            n: 1 << SCRYPT_LOG_N,
            r: SCRYPT_R,
            p: SCRYPT_P,
            dk_len: SCRYPT_DK_LEN,
        },
        s: base64::encode(salt),
        n: base64::encode(nonce_bytes),
        ct: base64::encode(ciphertext),
        tag: base64::encode(tag),
    };

    serde_json::to_string(&envelope).map_err(|e| e.to_string())
}

/// Decrypts an encrypted wallet envelope using the provided passphrase.
fn decrypt_wallet(envelope_str: &str, passphrase: &str) -> Result<String, String> {
    let env: EncryptedEnvelope = serde_json::from_str(envelope_str)
        .map_err(|e| format!("Failed to parse envelope: {}", e))?;

    let salt = base64::decode(&env.s).map_err(|e| e.to_string())?;
    let nonce_bytes = base64::decode(&env.n).map_err(|e| e.to_string())?;
    let ct_bytes = base64::decode(&env.ct).map_err(|e| e.to_string())?;
    let tag_bytes = base64::decode(&env.tag).map_err(|e| e.to_string())?;

    let params = ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_DK_LEN)
        .map_err(|e| e.to_string())?;

    let mut key_bytes = [0u8; SCRYPT_DK_LEN];
    scrypt(passphrase.as_bytes(), &salt, &params, &mut key_bytes)
        .map_err(|e| e.to_string())?;
    
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Reconstruct payload as (ciphertext || tag)
    let mut payload = Vec::with_capacity(ct_bytes.len() + tag_bytes.len());
    payload.extend_from_slice(&ct_bytes);
    payload.extend_from_slice(&tag_bytes);
    
    let pt_bytes = cipher.decrypt(nonce, payload.as_ref())
        .map_err(|e| format!("Decryption failed (likely wrong passphrase): {}", e))?;

    String::from_utf8(pt_bytes).map_err(|e| e.to_string())
}

// =============================================================================
// NEON EXPORTS - JAVASCRIPT-CALLABLE FUNCTIONS
// =============================================================================

/// (JS: initializeDatabase())
/// Initializes the RocksDB database instance. Safe to call multiple times.
pub fn initialize_database(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    get_or_init_db()
        .or_else(|e| cx.throw_error(e))?;
    Ok(cx.undefined())
}

/// (JS: saveBlock(blockBytes, isCanonical = true))
/// Saves a block from raw Protobuf bytes.
/// Args: 0: blockBytes (JsTypedArray<u8>), 1: isCanonical (JsBoolean, optional)
pub fn save_block(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let block_bytes = cx.argument::<JsTypedArray<u8>>(0)?.as_slice(&cx).to_vec(); // <-- Get raw bytes
    let is_canonical = cx.argument_opt(1)
        .and_then(|val| val.downcast::<JsBoolean, _>(&mut cx).ok())
        .map(|val| val.value(&mut cx))
        .unwrap_or(true); // Default to true

    // Decode bytes to P2P struct *just* to get hash/height
    let p2p_block = P2pBlock::decode(block_bytes.as_slice())
        .or_else(|e| cx.throw_error(format!("Failed to decode block: {}", e)))?;
    
    // Convert to internal Block to use .hash()
    let mut block = Block::from(p2p_block);
    block.hash = block.compute_hash();
    
    let hash = block.hash();
    let height = *block.height;

    with_db(|db| {
        let mut batch = WriteBatch::default();
        
        // Store block by hash (primary storage)
        let hash_key = format!("block:{}", hash);
        batch.put(hash_key.as_bytes(), &block_bytes); // <-- Save raw bytes

        if is_canonical {
            // Store height -> hash mapping (for canonical chain)
            let height_key = format!("height:{}", height);
            batch.put(height_key.as_bytes(), hash.as_bytes());
        
            // Update tip metadata
            let current_tip = db.get(b"meta:tip_height")
                .map_err(|e| format!("Failed to get tip: {}", e))?
                .and_then(|v| String::from_utf8(v).ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
        
            if height >= current_tip {
                batch.put(b"meta:tip_height", height.to_string().as_bytes());
                batch.put(b"meta:tip_hash", hash.as_bytes());
            }
        }
       
        db.write(batch).map_err(|e| format!("Write failed: {}", e))?;
        Ok(())
    }).or_else(|e| cx.throw_error(e))?;

    Ok(cx.undefined())
}

/// (JS: saveBlockWithHash(blockBytes))
/// Saves a block by its hash only (for side blocks/forks).
/// Args: 0: blockBytes (JsTypedArray<u8>)
pub fn save_block_with_hash(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let block_bytes = cx.argument::<JsTypedArray<u8>>(0)?.as_slice(&cx).to_vec(); // <-- Get raw bytes

    let p2p_block = P2pBlock::decode(block_bytes.as_slice())
        .or_else(|e| cx.throw_error(format!("Failed to decode block: {}", e)))?;
    
    let mut block = Block::from(p2p_block);
    block.hash = block.compute_hash();
    let hash = block.hash();

    with_db(|db| {
        let hash_key = format!("block:{}", hash);
        db.put(hash_key.as_bytes(), &block_bytes) // <-- Save raw bytes
            .map_err(|e| format!("Write failed: {}", e))?;
        Ok(())
    }).or_else(|e| cx.throw_error(e))?;

    Ok(cx.undefined())
}

/// (JS: loadBlock(height) / load_block_from_db(height))
/// Loads a canonical block by its height.
/// Args: 0: height (JsNumber, JsBigInt, or JsString)
/// Returns: Block object (JsValue) or JsNull
pub fn load_block(mut cx: FunctionContext) -> JsResult<JsValue> {
    let height_js = cx.argument::<JsValue>(0)?;
    let height = js_value_to_u64(&mut cx, height_js)?;

    let result = with_db(|db| {
        let height_key = format!("height:{}", height);
        let hash_bytes = db.get(height_key.as_bytes())
            .map_err(|e| format!("Failed to get height mapping: {}", e))?
            .ok_or_else(|| "Block not found".to_string())?;

        let hash_str = String::from_utf8(hash_bytes)
            .map_err(|e| format!("Invalid hash encoding: {}", e))?;

        let hash_key = format!("block:{}", hash_str);
        let data = db.get(hash_key.as_bytes())
            .map_err(|e| format!("Failed to get block: {}", e))?
            .ok_or_else(|| "Block data not found".to_string())?;

        Ok(data) // <-- Return raw Vec<u8>
    });

    match result {
        Ok(data) => {
            // 
            // Convert Vec<u8> to JsBuffer (which becomes Uint8Array in JS)
            let mut buffer = JsBuffer::new(&mut cx, data.len())?;
            buffer.as_mut_slice(&mut cx).copy_from_slice(&data);
            Ok(buffer.upcast()) // <-- Return buffer
        }
        Err(_) => Ok(cx.null().upcast())
    }
}

/// (JS: loadBlockByHash(hash))
/// Loads any block (canonical or side) by its hash.
/// Args: 0: hash (JsString)
/// Returns: Block object (JsValue) or JsNull
pub fn load_block_by_hash(mut cx: FunctionContext) -> JsResult<JsValue> {
    let hash = cx.argument::<JsString>(0)?.value(&mut cx);

    let result = with_db(|db| {
        let hash_key = format!("block:{}", hash);
        db.get(hash_key.as_bytes())
            .map_err(|e| format!("Failed to get block: {}", e))?
            .ok_or_else(|| "Block not found".to_string())
    });

    match result {
        Ok(data) => {
            // Convert Vec<u8> to JsBuffer
            let mut buffer = JsBuffer::new(&mut cx, data.len())?;
            buffer.as_mut_slice(&mut cx).copy_from_slice(&data);
            Ok(buffer.upcast()) // <-- Return buffer
        }
        Err(_) => Ok(cx.null().upcast())
    }
}

/// (JS: loadBlocks(startHeight, endHeight))
/// Loads a range of canonical blocks by height.
/// Args: 0: startHeight (JsValue), 1: endHeight (JsValue)
/// Returns: Array of Block objects (JsArray)
pub fn load_blocks(mut cx: FunctionContext) -> JsResult<JsArray> {
    let start_height_js = cx.argument::<JsValue>(0)?;
    let end_height_js = cx.argument::<JsValue>(1)?;
    let start_height = js_value_to_u64(&mut cx, start_height_js)?;
    let end_height = js_value_to_u64(&mut cx, end_height_js)?;

    let block_data_vec = with_db(|db| {
        let mut blocks_data = Vec::new(); // <-- Will be Vec<Vec<u8>>
        for height in start_height..=end_height {
            let height_key = format!("height:{}", height);
            if let Some(hash_bytes) = db.get(height_key.as_bytes()).ok().flatten() {
                if let Ok(hash_str) = String::from_utf8(hash_bytes) {
                    let hash_key = format!("block:{}", hash_str);
                    if let Some(data) = db.get(hash_key.as_bytes()).ok().flatten() {
                        blocks_data.push(data); // <-- Push raw Vec<u8>
                    }
                }
            }
        }
        Ok(blocks_data)
    }).or_else(|e: String| cx.throw_error(e))?;

    // Convert Vec<Vec<u8>> to JsArray of JsBuffers
    let js_array = cx.empty_array();
    for (i, block_data) in block_data_vec.iter().enumerate() {
        let mut buffer = JsBuffer::new(&mut cx, block_data.len())?;
        buffer.as_mut_slice(&mut cx).copy_from_slice(block_data);
        js_array.set(&mut cx, i as u32, buffer.upcast::<JsValue>())?; // <-- Set buffer in array
    }

    Ok(js_array)
}

/// (JS: getTipHeight() / get_tip_height_from_db())
/// Gets the current canonical tip height.
/// Returns: Tip height as JsString (for BigInt safety)
pub fn get_tip_height(mut cx: FunctionContext) -> JsResult<JsString> {
    let height = with_db(|db| {
        db.get(b"meta:tip_height")
            .map_err(|e| format!("Failed to get tip: {}", e))?
            .and_then(|v| String::from_utf8(v).ok())
            .ok_or_else(|| "Tip height not found".to_string())
    }).unwrap_or_else(|_| "0".to_string());
    
    Ok(cx.string(height))
}

/// (JS: getChainTip())
/// Gets the full block object at the canonical chain tip.
/// Returns: Block object (JsValue) or JsNull
pub fn get_chain_tip(mut cx: FunctionContext) -> JsResult<JsValue> {
    let height_str = with_db(|db| {
        db.get(b"meta:tip_height")
            .map_err(|e| format!("Failed to get tip: {}", e))?
            .and_then(|v| String::from_utf8(v).ok())
            .ok_or_else(|| "Tip height not found".to_string())
    }).unwrap_or_else(|_| "0".to_string());
    
    let height = height_str.parse::<u64>().unwrap_or(0);
    if height == 0 && height_str != "0" {
        return Ok(cx.null().upcast()); // Return null if no tip
    }

    // --- START FIX ---
    // Re-implement the logic of load_block here, using the height we just found.
    let result = with_db(|db| {
        // Get hash from height mapping
        let height_key = format!("height:{}", height);
        let hash_bytes = db.get(height_key.as_bytes())
            .map_err(|e| format!("Failed to get height mapping: {}", e))?
            .ok_or_else(|| "Block not found".to_string())?;
        
        let hash_str = String::from_utf8(hash_bytes)
            .map_err(|e| format!("Invalid hash encoding: {}", e))?;
        
        // Get block data by hash
        let hash_key = format!("block:{}", hash_str);
        let data = db.get(hash_key.as_bytes())
            .map_err(|e| format!("Failed to get block: {}", e))?
            .ok_or_else(|| "Block data not found".to_string())?;
        
        Ok(data)
    });

    match result {
        Ok(data) => {
            let p2p_block = P2pBlock::decode(data.as_slice())
                .or_else(|e| cx.throw_error(format!("Failed to decode block: {}", e)))?;
            let mut block = Block::from(p2p_block);
            block.hash = block.compute_hash(); 
            let js_value = to_value(&mut cx, &block)
                .or_else(|e| cx.throw_error(format!("Failed to serialize block: {}", e)))?;
            Ok(js_value)
        }
        Err(_) => Ok(cx.null().upcast())
    }
    // --- END FIX ---
}

/// (JS: getAllBlocks())
/// Loads all blocks from genesis to tip.
/// Returns: Array of Block objects (JsArray)
pub fn get_all_blocks(mut cx: FunctionContext) -> JsResult<JsArray> {
    let height_str = with_db(|db| {
        db.get(b"meta:tip_height")
            .map_err(|e| format!("Failed to get tip: {}", e))?
            .and_then(|v| String::from_utf8(v).ok())
            .ok_or_else(|| "Tip height not found".to_string())
    }).unwrap_or_else(|_| "0".to_string());
    
    let end_height = height_str.parse::<u64>().unwrap_or(0);
    let start_height: u64 = 0;

    // --- START FIX ---
    // Implement the logic of load_blocks(start_height, end_height) directly
    let blocks = with_db(|db| {
        let mut blocks = Vec::new();
        for height in start_height..=end_height {
            // Get hash from height mapping
            let height_key = format!("height:{}", height);
            if let Some(hash_bytes) = db.get(height_key.as_bytes()).ok().flatten() {
                if let Ok(hash_str) = String::from_utf8(hash_bytes) {
                    // Get block data by hash
                    let hash_key = format!("block:{}", hash_str);
                    if let Some(data) = db.get(hash_key.as_bytes()).ok().flatten() {
                        if let Ok(p2p_block) = P2pBlock::decode(data.as_slice()) {
                            let mut block = Block::from(p2p_block);
                            block.hash = block.compute_hash();
                            blocks.push(block);
                        }
                    }
                }
            }
        }
        Ok(blocks)
    }).or_else(|e: String| cx.throw_error(e))?;
    
    // Convert Vec<Block> to JsArray
    let js_array = cx.empty_array();
    for (i, block) in blocks.iter().enumerate() {
        let js_block = to_value(&mut cx, block)
            .or_else(|e| cx.throw_error(format!("Failed to serialize block: {}", e)))?;
        js_array.set(&mut cx, i as u32, js_block)?;
    }
    
    Ok(js_array)
    // --- END FIX ---
}

/// (JS: saveTotalWork(work) / save_total_work_to_db(work))
/// Saves the total chain work.
/// Args: 0: work (JsValue: BigInt, Number, or String)
pub fn save_total_work(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let work_js = cx.argument::<JsValue>(0)?;
    let work_u64 = js_value_to_u64(&mut cx, work_js)?;
    let work_str = work_u64.to_string();
    
    with_db(|db| {
        db.put(b"meta:total_work", work_str.as_bytes())
            .map_err(|e| format!("Failed to save work: {}", e))
    }).or_else(|e| cx.throw_error(e))?;
    
    Ok(cx.undefined())
}

/// (JS: loadTotalWork() / get_total_work_from_db())
/// Loads the total chain work.
/// Returns: Total work as JsString (for BigInt safety)
pub fn load_total_work(mut cx: FunctionContext) -> JsResult<JsString> {
    let work = with_db(|db| {
        db.get(b"meta:total_work")
            .map_err(|e| format!("Failed to get work: {}", e))?
            .and_then(|v| String::from_utf8(v).ok())
            .ok_or_else(|| "Total work not found".to_string())
    }).unwrap_or_else(|_| "0".to_string());
    
    Ok(cx.string(work))
}

/// (JS: save_utxo(commitmentHex, output))
/// Saves a UTXO as Protobuf bytes.
/// Args: 0: commitmentHex (JsString), 1: output (JsValue object)
pub fn save_utxo(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let commitment_hex = cx.argument::<JsString>(0)?.value(&mut cx);
    let output_js = cx.argument::<JsValue>(1)?;

    let output: TransactionOutput = from_value(&mut cx, output_js)
        .or_else(|e| cx.throw_error(format!("Failed to deserialize output: {}", e)))?;
    
    let p2p_output = P2pTransactionOutput::from(output);
    let data = p2p_output.encode_to_vec();

    with_db(|db| {
        let key = format!("utxo:{}", commitment_hex);
        db.put(key.as_bytes(), &data)
            .map_err(|e| format!("Failed to save UTXO: {}", e))
    }).or_else(|e| cx.throw_error(e))?;
    
    Ok(cx.undefined())
}

/// (JS: load_utxo(commitmentHex))
/// Loads a UTXO and returns it as a JS object.
/// Args: 0: commitmentHex (JsString)
/// Returns: Output object (JsValue) or JsNull
pub fn load_utxo(mut cx: FunctionContext) -> JsResult<JsValue> {
    let commitment_hex = cx.argument::<JsString>(0)?.value(&mut cx);

    let result = with_db(|db| {
        let key = format!("utxo:{}", commitment_hex);
        db.get(key.as_bytes())
            .map_err(|e| format!("Failed to get UTXO: {}", e))?
            .ok_or_else(|| "UTXO not found".to_string())
    });

    match result {
        Ok(data) => {
            let p2p_output = P2pTransactionOutput::decode(data.as_slice())
                .or_else(|e| cx.throw_error(format!("Failed to decode output: {}", e)))?;
            let output = TransactionOutput::from(p2p_output);
            let js_value = to_value(&mut cx, &output)
                .or_else(|e| cx.throw_error(format!("Failed to serialize output: {}", e)))?;
            Ok(js_value)
        }
        Err(_) => Ok(cx.null().upcast())
    }
}

/// (JS: delete_utxo(commitmentHex))
/// Deletes a UTXO.
/// Args: 0: commitmentHex (JsString)
pub fn delete_utxo(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let commitment_hex = cx.argument::<JsString>(0)?.value(&mut cx);
    
    with_db(|db| {
        let key = format!("utxo:{}", commitment_hex);
        db.delete(key.as_bytes())
            .map_err(|e| format!("Failed to delete UTXO: {}", e))
    }).or_else(|_| Ok(()))?; // Ignore not found errors
    
    Ok(cx.undefined())
}

/// (JS: loadAllUtxos())
/// Loads all UTXOs.
/// Returns: Array of [commitmentHex (JsString), output (JsValue object)]
pub fn load_all_utxos(mut cx: FunctionContext) -> JsResult<JsArray> {
    let utxos = with_db(|db| {
        let mut result = Vec::new();
        let iter = db.iterator(IteratorMode::From(b"utxo:", Direction::Forward));
        
        for item in iter {
            let (key, value) = item.map_err(|e| format!("Iterator error: {}", e))?;
            let key_str = String::from_utf8_lossy(&key);
            
            if !key_str.starts_with("utxo:") {
                break;
            }
            
            let commitment_hex = key_str.strip_prefix("utxo:").unwrap_or("").to_string();
            // Decode Protobuf bytes
            if let Ok(p2p_output) = P2pTransactionOutput::decode(value.as_ref()) {
                let output = TransactionOutput::from(p2p_output);
                result.push((commitment_hex, output));
            }
        }
        Ok(result)
    }).or_else(|e: String| cx.throw_error(e))?;
    
    let js_array = cx.empty_array();
    
    for (i, (commitment_hex, output)) in utxos.iter().enumerate() {
        let pair_array = cx.empty_array();
        let key = cx.string(commitment_hex);
        let value = to_value(&mut cx, output)
            .or_else(|e| cx.throw_error(format!("Failed to serialize output: {}", e)))?;
        
        pair_array.set(&mut cx, 0_u32, key)?;
        pair_array.set(&mut cx, 1_u32, value)?;
        js_array.set(&mut cx, i as u32, pair_array)?;
    }
    
    Ok(js_array)
}

/// (JS: clear_all_utxos())
/// Deletes all UTXOs from the database.
pub fn clear_all_utxos(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    with_db(|db| {
        let mut batch = WriteBatch::default();
        let iter = db.iterator(IteratorMode::From(b"utxo:", Direction::Forward));
        
        for item in iter {
            let (key, _) = item.map_err(|e| format!("Iterator error: {}", e))?;
            let key_str = String::from_utf8_lossy(&key);
            
            if !key_str.starts_with("utxo:") {
                break;
            }
            
            batch.delete(&key);
        }
        
        db.write(batch).map_err(|e| format!("Failed to clear UTXOs: {}", e))
    }).or_else(|e| cx.throw_error(e))?;
    
    Ok(cx.undefined())
}

/// (JS: save_block_filter(height, filter_json))
/// Saves a block filter for a given height.
/// Args: 0: height (JsValue), 1: filter_json (JsString)
pub fn save_block_filter(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let height_js = cx.argument::<JsValue>(0)?;
    let height = js_value_to_u64(&mut cx, height_js)?;
    let filter_json = cx.argument::<JsString>(1)?.value(&mut cx);
    
    with_db(|db| {
        // Pad height to 16 chars for correct lexicographical sorting by height
        let key = format!("filter:{:0>16}", height); 
        db.put(key.as_bytes(), filter_json.as_bytes())
            .map_err(|e| format!("Failed to save block filter: {}", e))
    }).or_else(|e| cx.throw_error(e))?;
    
    Ok(cx.undefined())
}

// --- ADD THIS NEW FUNCTION ---
/// (JS: load_block_filter_range(startHeight, endHeight))
/// Loads all block filters in a given height range.
/// Args: 0: startHeight (JsValue), 1: endHeight (JsValue)
/// Returns: Object map of { height_str: filter_json_str }
pub fn load_block_filter_range(mut cx: FunctionContext) -> JsResult<JsObject> {
    let start_height_js = cx.argument::<JsValue>(0)?;
    let end_height_js = cx.argument::<JsValue>(1)?;
    let start_height = js_value_to_u64(&mut cx, start_height_js)?;
    let end_height = js_value_to_u64(&mut cx, end_height_js)?;

    // Use the padded key for the start of the iterator range
    let start_key = format!("filter:{:0>16}", start_height);
    
    let filters = with_db(|db| {
        // This HashMap will store height as String -> filter as String
        let mut result = HashMap::new();
        let iter = db.iterator(IteratorMode::From(start_key.as_bytes(), Direction::Forward));
        
        for item in iter {
            let (key, value) = item.map_err(|e| format!("Iterator error: {}", e))?;
            let key_str = String::from_utf8_lossy(&key);
            
            // Stop iterating if we've gone past the filter prefix
            if !key_str.starts_with("filter:") {
                break;
            }
            
            // Extract height from key: "filter:0000...00123" -> "123"
            let height_str = match key_str.strip_prefix("filter:") {
                Some(h_str) => h_str.trim_start_matches('0').to_string(), // Get "123"
                None => continue,
            };
            
            // Parse the height to check if we've passed the end
            let height = height_str.parse::<u64>().unwrap_or(0);
            if height > end_height {
                break;
            }
            
            // Store the raw JSON string
            let filter_json = String::from_utf8_lossy(&value).to_string();
            // Use the un-padded height string as the key
            result.insert(height_str, filter_json); 
        }
        Ok(result)
    }).or_else(|e: String| cx.throw_error(e))?;
    
    // Serialize the HashMap<String, String> to a JS Object { "123": "[...]", "124": "[...]" }
    let js_object = cx.empty_object();
    for (height_str, filter_json) in filters {
        let js_height_str = cx.string(height_str);
        let js_filter_str = cx.string(filter_json);
        js_object.set(&mut cx, js_height_str, js_filter_str)?;
    }
    
    Ok(js_object)
}

// --- ADD THIS NEW FUNCTION ---
/// (JS: delete_block_filter(height))
/// Deletes a block filter for a given height (used in reorgs).
/// Args: 0: height (JsValue)
pub fn delete_block_filter(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let height_js = cx.argument::<JsValue>(0)?;
    let height = js_value_to_u64(&mut cx, height_js)?;
    
    with_db(|db| {
        let key = format!("filter:{:0>16}", height);
        db.delete(key.as_bytes())
            .map_err(|e| format!("Failed to delete block filter: {}", e))
    }).or_else(|_| Ok(()))?; // Ignore not found errors
    
    Ok(cx.undefined())
}

/// (JS: save_coinbase_index(commitmentHex, height))
/// Saves a coinbase index entry.
/// Args: 0: commitmentHex (JsString), 1: height (JsValue: BigInt, Number, or String)
pub fn save_coinbase_index(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let commitment_hex = cx.argument::<JsString>(0)?.value(&mut cx);
    let height_js = cx.argument::<JsValue>(1)?;
    let height = js_value_to_u64(&mut cx, height_js)?;
    
    with_db(|db| {
        let key = format!("cbidx:{}", commitment_hex);
        db.put(key.as_bytes(), height.to_string().as_bytes())
            .map_err(|e| format!("Failed to save coinbase index: {}", e))
    }).or_else(|e| cx.throw_error(e))?;
    
    Ok(cx.undefined())
}

/// (JS: delete_coinbase_index(commitmentHex))
/// Deletes a coinbase index entry.
/// Args: 0: commitmentHex (JsString)
pub fn delete_coinbase_index(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let commitment_hex = cx.argument::<JsString>(0)?.value(&mut cx);
    
    with_db(|db| {
        let key = format!("cbidx:{}", commitment_hex);
        db.delete(key.as_bytes())
            .map_err(|e| format!("Failed to delete coinbase index: {}", e))
    }).or_else(|_| Ok(()))?;
    
    Ok(cx.undefined())
}

/// (JS: loadAllCoinbaseIndexes())
/// Loads all coinbase indexes.
/// Returns: Object map of { commitmentHex: heightString } (JS side parses height to BigInt)
pub fn load_all_coinbase_indexes(mut cx: FunctionContext) -> JsResult<JsObject> {
    let indexes = with_db(|db| {
        let mut result = HashMap::new();
        let iter = db.iterator(IteratorMode::From(b"cbidx:", Direction::Forward));
        
        for item in iter {
            let (key, value) = item.map_err(|e| format!("Iterator error: {}", e))?;
            let key_str = String::from_utf8_lossy(&key);
            
            if !key_str.starts_with("cbidx:") {
                break;
            }
            
            let commitment_hex = key_str.strip_prefix("cbidx:").unwrap_or("").to_string();
            let height_str = String::from_utf8_lossy(&value).to_string();
            // Use WasmU64 to serialize as a JS-safe number/bigint
            let height_u64 = height_str.parse::<u64>().unwrap_or(0);
            result.insert(commitment_hex, WasmU64(height_u64));
        }
        
        Ok(result)
    }).or_else(|e: String| cx.throw_error(e))?;
    
    // Use neon-serde4 to serialize the HashMap<String, WasmU64>
    let js_value = to_value(&mut cx, &indexes)
        .or_else(|e| cx.throw_error(format!("Failed to serialize map: {}", e)))?;
    
    js_value.downcast::<JsObject, _>(&mut cx)
        .or_else(|e| cx.throw_error(format!("Failed to cast to object: {}", e)))
}

/// (JS: saveWallet(walletId, walletJson))
/// Saves wallet data, encrypting if passphrase is set.
/// Args: 0: walletId (JsString), 1: walletJson (JsString)
pub fn save_wallet(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let wallet_id = cx.argument::<JsString>(0)?.value(&mut cx);
    let wallet_json = cx.argument::<JsString>(1)?.value(&mut cx);
    
    let to_store = match get_passphrase() {
        Some(pass) => encrypt_wallet(&wallet_json, &pass)
            .or_else(|e| cx.throw_error(format!("Encryption failed: {}", e)))?,
        None => wallet_json,
    };

    with_db(|db| {
        let key = format!("wallet:{}", wallet_id);
        db.put(key.as_bytes(), to_store.as_bytes())
            .map_err(|e| format!("Failed to save wallet: {}", e))
    }).or_else(|e| cx.throw_error(e))?;
    
    Ok(cx.undefined())
}

/// (JS: loadWallet(walletId))
/// Loads wallet data, decrypting if necessary.
/// Args: 0: walletId (JsString)
/// Returns: Plaintext wallet JSON (JsString) or JsNull
pub fn load_wallet(mut cx: FunctionContext) -> JsResult<JsValue> {
    let wallet_id = cx.argument::<JsString>(0)?.value(&mut cx);
    
    let result = with_db(|db| {
        let key = format!("wallet:{}", wallet_id);
        db.get(key.as_bytes())
            .map_err(|e| format!("Failed to get wallet: {}", e))?
            .ok_or_else(|| "Wallet not found".to_string())
    });

    match result {
        Ok(data) => {
            let raw_str = String::from_utf8(data)
                .or_else(|_| cx.throw_error("Invalid wallet data encoding"))?;
            
            if is_encrypted_envelope(&raw_str) {
                match get_passphrase() {
                    Some(pass) => {
                        let decrypted = decrypt_wallet(&raw_str, &pass)
                            .or_else(|e| cx.throw_error(e))?;
                        Ok(cx.string(decrypted).upcast())
                    }
                    None => {
                        // Match js_bridge by throwing an error with a specific code
                        let err = cx.error("Wallet is encrypted; set PLURIBIT_WALLET_PASSPHRASE to decrypt.")?;
                        let obj = err.downcast::<JsObject, _>(&mut cx).or_throw(&mut cx)?;
                        let code = cx.string("WALLET_PASSPHRASE_REQUIRED");
                        obj.set(&mut cx, "code", code)?;
                        cx.throw(err)
                    }
                }
            } else {
                // It's plaintext
                Ok(cx.string(raw_str).upcast())
            }
        }
        Err(_) => Ok(cx.null().upcast())
    }
}

/// (JS: walletExists(walletId))
/// Checks if wallet data exists.
/// Args: 0: walletId (JsString)
/// Returns: JsBoolean
pub fn wallet_exists(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let wallet_id = cx.argument::<JsString>(0)?.value(&mut cx);
    
    let exists = with_db(|db| {
        let key = format!("wallet:{}", wallet_id);
        // Wrap the final boolean value in Ok()
        Ok(db.get(key.as_bytes())
            .map_err(|_| "Error checking wallet".to_string())?
            .is_some())
    }).unwrap_or(false);
    
    Ok(cx.boolean(exists))
}

/// (JS: isWalletEncrypted(walletId))
/// Checks if stored wallet data is in the encrypted format.
/// Args: 0: walletId (JsString)
/// Returns: JsBoolean
pub fn is_wallet_encrypted(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let wallet_id = cx.argument::<JsString>(0)?.value(&mut cx);
    
    let encrypted = with_db(|db| {
        let key = format!("wallet:{}", wallet_id);
        if let Some(data) = db.get(key.as_bytes()).ok().flatten() {
            if let Ok(raw_str) = String::from_utf8(data) {
                return Ok(is_encrypted_envelope(&raw_str));
            }
        }
        Ok(false) // Not found or invalid UTF-8
    }).unwrap_or(false);
    
    Ok(cx.boolean(encrypted))
}

/// (JS: save_channel(id, data))
/// Args: 0: id (JsString), 1: data (JsString - JSON serialization)
pub fn save_channel(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let id = cx.argument::<JsString>(0)?.value(&mut cx);
    let data = cx.argument::<JsString>(1)?.value(&mut cx);

    with_db(|db| {
        let key = format!("channel:{}", id);
        db.put(key.as_bytes(), data.as_bytes())
            .map_err(|e| format!("Failed to save channel: {}", e))
    }).or_else(|e| cx.throw_error(e))?;

    Ok(cx.undefined())
}

/// (JS: load_channel(id))
/// Args: 0: id (JsString)
pub fn load_channel(mut cx: FunctionContext) -> JsResult<JsValue> {
    let id = cx.argument::<JsString>(0)?.value(&mut cx);

    let result = with_db(|db| {
        let key = format!("channel:{}", id);
        db.get(key.as_bytes())
            .map_err(|e| format!("Failed to load channel: {}", e))?
            .ok_or_else(|| "Channel not found".to_string())
    });

    match result {
        Ok(data) => {
            let json_str = String::from_utf8(data).unwrap_or_default();
            Ok(cx.string(json_str).upcast())
        },
        Err(_) => Ok(cx.null().upcast())
    }
}
/// (JS: clear_all_coinbase_indexes())
/// Deletes all coinbase indexes from the database.
pub fn clear_all_coinbase_indexes(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    with_db(|db| {
        let mut batch = WriteBatch::default();
        let iter = db.iterator(IteratorMode::From(b"cbidx:", Direction::Forward));
        
        for item in iter {
            let (key, _) = item.map_err(|e| format!("Iterator error: {}", e))?;
            let key_str = String::from_utf8_lossy(&key);
            
            if !key_str.starts_with("cbidx:") {
                break;
            }
            batch.delete(&key);
        }
        db.write(batch).map_err(|e| format!("Failed to clear coinbase indexes: {}", e))
    }).or_else(|e| cx.throw_error(e))?;
    
    Ok(cx.undefined())
}
/// (JS: save_atomic_swap(id, data))
pub fn save_atomic_swap(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let id = cx.argument::<JsString>(0)?.value(&mut cx);
    let data = cx.argument::<JsString>(1)?.value(&mut cx);

    with_db(|db| {
        let key = format!("swap:{}", id);
        db.put(key.as_bytes(), data.as_bytes())
            .map_err(|e| format!("Failed to save swap: {}", e))
    }).or_else(|e| cx.throw_error(e))?;

    Ok(cx.undefined())
}

/// (JS: load_atomic_swap(id))
pub fn load_atomic_swap(mut cx: FunctionContext) -> JsResult<JsValue> {
    let id = cx.argument::<JsString>(0)?.value(&mut cx);

    let result = with_db(|db| {
        let key = format!("swap:{}", id);
        db.get(key.as_bytes())
            .map_err(|e| format!("Failed to load swap: {}", e))?
            .ok_or_else(|| "Swap not found".to_string())
    });

    match result {
        Ok(data) => {
            let json_str = String::from_utf8(data).unwrap_or_default();
            Ok(cx.string(json_str).upcast())
        },
        Err(_) => Ok(cx.null().upcast())
    }
}
/// (JS: saveDeferredBlock(block))
/// Saves a deferred block (Protobuf encoded).
/// Args: 0: block (JsValue object)
pub fn save_deferred_block(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let block_js = cx.argument::<JsValue>(0)?;

    let block: Block = from_value(&mut cx, block_js)
        .or_else(|e| cx.throw_error(format!("Failed to deserialize block: {}", e)))?;
    
    let p2p_block = P2pBlock::from(block.clone());
    let data = p2p_block.encode_to_vec();
    let key = format!("deferred:{:0>16}", *block.height); // Pad height for sorting

    with_db(|db| {
        db.put(key.as_bytes(), &data)
            .map_err(|e| format!("Write failed: {}", e))?;
        Ok(())
    }).or_else(|e| cx.throw_error(e))?;

    Ok(cx.undefined())
}

/// (JS: loadAllDeferredBlocks())
/// Loads all deferred blocks, in order by height.
/// Returns: Array of Block objects (JsArray)
pub fn load_all_deferred_blocks(mut cx: FunctionContext) -> JsResult<JsArray> {
    let blocks = with_db(|db| {
        let mut blocks = Vec::new();
        let iter = db.iterator(IteratorMode::From(b"deferred:", Direction::Forward));
        
        for item in iter {
            let (key, value) = item.map_err(|e| format!("Iterator error: {}", e))?;
            let key_str = String::from_utf8_lossy(&key);
            
            if !key_str.starts_with("deferred:") {
                break;
            }
            
            if let Ok(p2p_block) = P2pBlock::decode(value.as_ref()) {
                let mut block = Block::from(p2p_block);
                block.hash = block.compute_hash(); // Re-compute hash
                blocks.push(block);
            }
        }
        Ok(blocks)
    }).or_else(|e: String| cx.throw_error(e))?;
    
    let js_array = cx.empty_array();
    for (i, block) in blocks.iter().enumerate() {
        let js_block = to_value(&mut cx, block)
            .or_else(|e| cx.throw_error(format!("Failed to serialize block: {}", e)))?;
        js_array.set(&mut cx, i as u32, js_block)?;
    }
    
    Ok(js_array)
}

/// (JS: clearDeferredBlocks())
/// Deletes all deferred blocks.
pub fn clear_deferred_blocks(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    with_db(|db| {
        let mut batch = WriteBatch::default();
        let iter = db.iterator(IteratorMode::From(b"deferred:", Direction::Forward));
        
        for item in iter {
            let (key, _) = item.map_err(|e| format!("Iterator error: {}", e))?;
            let key_str = String::from_utf8_lossy(&key);
            
            if !key_str.starts_with("deferred:") {
                break;
            }
            
            batch.delete(&key);
        }
        
        db.write(batch).map_err(|e| format!("Failed to clear deferred blocks: {}", e))
    }).or_else(|e| cx.throw_error(e))?;
    
    Ok(cx.undefined())
}

/// (JS: save_reorg_marker(markerHex))
/// Saves a reorg marker.
/// Args: 0: marker (JsString, hex-encoded Protobuf bytes)
pub fn save_reorg_marker(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let marker_hex = cx.argument::<JsString>(0)?.value(&mut cx);
    let data = hex::decode(marker_hex)
        .or_else(|e| cx.throw_error(format!("Invalid marker hex: {}", e)))?;
    
    with_db(|db| {
        db.put(b"meta:reorg_in_progress", &data)
            .map_err(|e| format!("Failed to save reorg marker: {}", e))
    }).or_else(|e| cx.throw_error(e))?;
    
    Ok(cx.undefined())
}

/// (JS: clear_reorg_marker())
/// Clears the reorg marker.
pub fn clear_reorg_marker(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    with_db(|db| {
        db.delete(b"meta:reorg_in_progress")
            .map_err(|e| format!("Failed to clear reorg marker: {}", e))
    }).or_else(|_| Ok(()))?;
    
    Ok(cx.undefined())
}

/// (JS: check_incomplete_reorg())
/// Checks for an incomplete reorg marker.
/// Returns: Marker (JsString, hex-encoded Protobuf) or JsNull
pub fn check_incomplete_reorg(mut cx: FunctionContext) -> JsResult<JsValue> {
    let result = with_db(|db| {
        db.get(b"meta:reorg_in_progress")
            .map_err(|e| format!("Failed to check reorg marker: {}", e))?
            .ok_or_else(|| "No reorg marker".to_string())
    });
    
    match result {
        Ok(data) => {
            // Return as hex string, matching the CJS bridge
            let hex_string = hex::encode(data);
            Ok(cx.string(hex_string).upcast())
        }
        Err(_) => Ok(cx.null().upcast())
    }
}

/// (JS: save_block_to_staging(blockBytes))
/// Saves a block to the staging area for an atomic reorg.
/// Args: 0: blockBytes (JsTypedArray<u8>)
pub fn save_block_to_staging(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let block_bytes = cx.argument::<JsTypedArray<u8>>(0)?.as_slice(&cx).to_vec(); // <-- Get raw bytes

    let p2p_block = P2pBlock::decode(block_bytes.as_slice())
        .or_else(|e| cx.throw_error(format!("Failed to decode block: {}", e)))?;
    
    let mut block = Block::from(p2p_block);
    block.hash = block.compute_hash();
    let key = format!("staging:{}", block.hash());

    with_db(|db| {
        db.put(key.as_bytes(), &block_bytes) // <-- Save raw bytes
            .map_err(|e| format!("Write failed: {}", e))?;
        Ok(())
    }).or_else(|e| cx.throw_error(e))?;

    Ok(cx.undefined())
}

/// (JS: commit_staged_reorg(blocksBytesArray, oldHeights, newTipHeight, newTipHash))
/// Atomically commits a reorg from staged blocks.
/// Args: 0: blocksBytesArray (JsArray of JsTypedArray<u8>)
///       1: heightsToDelete (JsArray of JsValue)
///       2: newTipHeight (JsValue)
///       3: newTipHash (JsString)
pub fn commit_staged_reorg(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let blocks_array = cx.argument::<JsArray>(0)?; // <-- Array of byte arrays
    let old_heights_array = cx.argument::<JsArray>(1)?;
    let new_tip_height_js = cx.argument::<JsValue>(2)?;
    let new_tip_height = js_value_to_u64(&mut cx, new_tip_height_js)?;
    let new_tip_hash = cx.argument::<JsString>(3)?.value(&mut cx);
    
    with_db(|db| {
        let mut batch = WriteBatch::default();

        // 1. Get old block hashes to delete
        let mut old_block_hashes = Vec::new();
        let old_heights_len = old_heights_array.len(&mut cx);
        for i in 0..old_heights_len {
            let height_js = old_heights_array.get::<JsValue, _, _>(&mut cx, i)
                .map_err(|e| e.to_string())?;
            let height_u64 = js_value_to_u64(&mut cx, height_js)
                .map_err(|e| e.to_string())?;
            
            let height_key = format!("height:{}", height_u64);
            if let Some(hash_bytes) = db.get(&height_key).map_err(|e| e.to_string())? {
                old_block_hashes.push(hash_bytes);
                batch.delete(&height_key);
            }
        }
        
        // 2. Add new blocks from staging
        let blocks_len = blocks_array.len(&mut cx);
        for i in 0..blocks_len {
            // Get the JsTypedArray<u8> from the JsArray
            let block_bytes_handle = blocks_array.get::<JsTypedArray<u8>, _, _>(&mut cx, i)
                .map_err(|e| e.to_string())?;
            let block_bytes = block_bytes_handle.as_slice(&cx).to_vec();
            
            // Decode just to get hash/height
            let p2p_block = P2pBlock::decode(block_bytes.as_slice())
                .map_err(|e| format!("Failed to decode block for reorg: {}", e))?;
            let mut block = Block::from(p2p_block);
            block.hash = block.compute_hash();
            
            let hash = block.hash();
            let height_str = (*block.height).to_string();
            let staging_key = format!("staging:{}", hash);

            // Get data from staging (which should be identical to block_bytes)
            let data = db.get(&staging_key)
                .map_err(|e| e.to_string())?
                .ok_or(format!("Staging block {} not found", hash))?;

            // Add to canonical chain
            let hash_key = format!("block:{}", hash);
            let height_key = format!("height:{}", height_str);
            
            batch.put(hash_key.as_bytes(), &data);
            batch.put(height_key.as_bytes(), hash.as_bytes());
            batch.delete(staging_key.as_bytes());
        }

        // 3. Delete old orphaned block data
        for old_hash in old_block_hashes {
            let old_hash_str = String::from_utf8_lossy(&old_hash);
            let hash_key = format!("block:{}", old_hash_str);
            batch.delete(hash_key.as_bytes());
        }

        // 4. Update tip metadata
        batch.put(b"meta:tip_height", new_tip_height.to_string().as_bytes());
        batch.put(b"meta:tip_hash", new_tip_hash.as_bytes());

        // 5. Execute atomic commit
        db.write(batch).map_err(|e| format!("Atomic commit failed: {}", e))?;
        Ok(())
    }).or_else(|e| cx.throw_error(e))?;

    Ok(cx.undefined())
}

/// (JS: deleteCanonicalBlock(height))
/// Deletes a height->hash mapping (used for rewind).
/// Args: 0: height (JsValue: BigInt, Number, or String)
pub fn delete_canonical_block(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let height_js = cx.argument::<JsValue>(0)?;
    let height = js_value_to_u64(&mut cx, height_js)?;

    with_db(|db| {
        let height_key = format!("height:{}", height);
        db.delete(height_key.as_bytes())
            .map_err(|e| format!("Failed to delete height mapping: {}", e))
    }).or_else(|_| Ok(()))?; // Ignore not found
    
    Ok(cx.undefined())
}

/// (JS: setTipMetadata(height, hash))
/// Atomically sets the tip height and hash metadata.
/// Args: 0: height (JsValue: BigInt, Number, or String), 1: hash (JsString)
pub fn set_tip_metadata(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let height_js = cx.argument::<JsValue>(0)?;
    let height = js_value_to_u64(&mut cx, height_js)?;
    let hash = cx.argument::<JsString>(1)?.value(&mut cx);
    
    with_db(|db| {
        let mut batch = WriteBatch::default();
        batch.put(b"meta:tip_height", height.to_string().as_bytes());
        batch.put(b"meta:tip_hash", hash.as_bytes());
        db.write(batch).map_err(|e| format!("Failed to set tip metadata: {}", e))
    }).or_else(|e| cx.throw_error(e))?;

    Ok(cx.undefined())
}
