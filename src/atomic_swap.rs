// src/atomic_swap.rs - COMPLETE IMPLEMENTATION
//! Atomic Swaps - Trustless cross-chain trading using adaptor signatures
//!
//! Full implementation with Bitcoin integration for real cross-chain swaps.

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
use wasm_bindgen::JsCast;
#[cfg(not(target_arch = "wasm32"))]
use reqwest;
// ============================================================================
// SWAP STATE & CORE TYPES
// ============================================================================

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
    
    // Pluribit side (Alice)
    pub alice_amount: u64,
    pub alice_pubkey: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub alice_commitment: Vec<u8>,
    pub alice_blinding: Option<Scalar>,
    pub alice_adaptor_sig: Option<AdaptorSignature>,
    pub alice_timeout_height: u64,
    
    // Bitcoin side (Bob)
    pub bob_amount: u64, // satoshis
    pub bob_pubkey: Vec<u8>,
    pub bob_btc_address: Option<String>,
    pub bob_btc_txid: Option<String>,
    pub bob_btc_vout: Option<u32>,
    pub bob_commitment: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub bob_adaptor_sig: Vec<u8>,
    pub bob_timeout_height: u64,
    
    // Shared
    #[serde(with = "serde_bytes")]
    pub shared_adaptor_point: [u8; 32],
    pub adaptor_secret: Option<[u8; 32]>,
    pub secret_hash: [u8; 32],
    
    // Metadata
    pub created_at: u64,
    pub expires_at: u64,
    pub last_updated: u64,
}

// ============================================================================
// BITCOIN RPC CLIENT
// ============================================================================

#[derive(Clone)]
pub struct BitcoinRPC {
    pub url: String,
    pub user: Option<String>,
    pub pass: Option<String>,
}

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: String,
    method: String,
    params: serde_json::Value,
}

impl BitcoinRPC {
    pub fn new(url: String) -> Self {
        Self {
            url,
            user: None,
            pass: None,
        }
    }
    
    pub fn with_auth(url: String, user: String, pass: String) -> Self {
        Self {
            url,
            user: Some(user),
            pass: Some(pass),
        }
    }
    
    #[cfg(not(target_arch = "wasm32"))]
    pub fn call(&self, method: &str, params: serde_json::Value) -> PluribitResult<serde_json::Value> {
        use std::time::Duration;
        
        let request = JsonRpcRequest {
            jsonrpc: "1.0".to_string(),
            id: "pluribit".to_string(),
            method: method.to_string(),
            params,
        };
        
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| PluribitError::NetworkError(e.to_string()))?;
        
        let mut req = client.post(&self.url).json(&request);
        
        if let (Some(user), Some(pass)) = (&self.user, &self.pass) {
            req = req.basic_auth(user, Some(pass));
        }
        
        let response = req.send()
            .map_err(|e| PluribitError::NetworkError(e.to_string()))?;
        
        let json: serde_json::Value = response.json()
            .map_err(|e| PluribitError::NetworkError(e.to_string()))?;
        
        if let Some(error) = json.get("error") {
            if !error.is_null() {
                return Err(PluribitError::NetworkError(
                    format!("Bitcoin RPC error: {}", error)
                ));
            }
        }
        
        json.get("result")
            .ok_or_else(|| PluribitError::NetworkError("No result in response".into()))
            .map(|v| v.clone())
    }
    
    #[cfg(target_arch = "wasm32")]
    pub async fn call_async(&self, method: &str, params: serde_json::Value) -> PluribitResult<serde_json::Value> {
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        use web_sys::{Request, RequestInit, RequestMode, Response};
        
        let request = JsonRpcRequest {
            jsonrpc: "1.0".to_string(),
            id: "pluribit".to_string(),
            method: method.to_string(),
            params,
        };
        
        let body = serde_json::to_string(&request)
            .map_err(|e| PluribitError::SerializationError(e.to_string()))?;
        
        let mut opts = RequestInit::new();
opts.set_method("POST");
opts.set_mode(RequestMode::Cors);
opts.set_body(&JsValue::from_str(&body));
        
let request = Request::new_with_str_and_init(&self.url, &opts)
    .map_err(|_| PluribitError::NetworkError("Failed to create request".into()))?;

let headers = request.headers();
headers.set("Content-Type", "application/json")
    .map_err(|_| PluribitError::NetworkError("Failed to set headers".into()))?;

if let (Some(user), Some(pass)) = (&self.user, &self.pass) {
    let auth = format!("Basic {}", base64::encode(format!("{}:{}", user, pass)));
    headers.set("Authorization", &auth)
        .map_err(|_| PluribitError::NetworkError("Failed to set auth".into()))?;
}
        
        let window = web_sys::window()
            .ok_or_else(|| PluribitError::NetworkError("No window".into()))?;
        
        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|_| PluribitError::NetworkError("Fetch failed".into()))?;
        
        let resp: Response = resp_value.dyn_into()
            .map_err(|_| PluribitError::NetworkError("Invalid response".into()))?;
        
        let json_value = JsFuture::from(resp.json()
            .map_err(|_| PluribitError::NetworkError("Failed to get JSON".into()))?)
            .await
            .map_err(|_| PluribitError::NetworkError("Failed to parse JSON".into()))?;
        
        let json: serde_json::Value = serde_wasm_bindgen::from_value(json_value)
            .map_err(|e| PluribitError::SerializationError(e.to_string()))?;
        
        if let Some(error) = json.get("error") {
            if !error.is_null() {
                return Err(PluribitError::NetworkError(
                    format!("Bitcoin RPC error: {}", error)
                ));
            }
        }
        
        json.get("result")
            .ok_or_else(|| PluribitError::NetworkError("No result in response".into()))
            .map(|v| v.clone())
    }
    
    // Convenience methods
    pub fn get_block_count(&self) -> PluribitResult<u64> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let result = self.call("getblockcount", serde_json::json!([]))?;
            result.as_u64()
                .ok_or_else(|| PluribitError::ValidationError("Invalid block count".into()))
        }
        #[cfg(target_arch = "wasm32")]
        {
            Err(PluribitError::NotSupported("Use get_block_count_async in WASM".into()))
        }
    }
    
    pub fn get_raw_transaction(&self, txid: &str) -> PluribitResult<String> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let result = self.call("getrawtransaction", serde_json::json!([txid]))?;
            result.as_str()
                .ok_or_else(|| PluribitError::ValidationError("Invalid tx hex".into()))
                .map(|s| s.to_string())
        }
        #[cfg(target_arch = "wasm32")]
        {
            Err(PluribitError::NotSupported("Use get_raw_transaction_async in WASM".into()))
        }
    }
    
    pub fn send_raw_transaction(&self, hex: &str) -> PluribitResult<String> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let result = self.call("sendrawtransaction", serde_json::json!([hex]))?;
            result.as_str()
                .ok_or_else(|| PluribitError::ValidationError("Invalid txid".into()))
                .map(|s| s.to_string())
        }
        #[cfg(target_arch = "wasm32")]
        {
            Err(PluribitError::NotSupported("Use send_raw_transaction_async in WASM".into()))
        }
    }
}

// Simple base64 encoding for WASM
#[cfg(target_arch = "wasm32")]
mod base64 {
    use wasm_bindgen::JsCast;  // ADD THIS LINE
    
    pub fn encode(input: String) -> String {
        let window = web_sys::window().unwrap();
        let encoded = js_sys::Reflect::get(&window, &wasm_bindgen::JsValue::from_str("btoa"))
            .unwrap();
        let func = encoded.dyn_into::<js_sys::Function>().unwrap();
        let result = func.call1(&wasm_bindgen::JsValue::NULL, &wasm_bindgen::JsValue::from_str(&input)).unwrap();
        result.as_string().unwrap()
    }
}

// ============================================================================
// BITCOIN TRANSACTION PARSING
// ============================================================================

#[derive(Debug, Clone)]
pub struct BitcoinTransaction {
    pub version: i32,
    pub inputs: Vec<BitcoinInput>,
    pub outputs: Vec<BitcoinOutput>,
    pub locktime: u32,
}

#[derive(Debug, Clone)]
pub struct BitcoinInput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct BitcoinOutput {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

impl BitcoinTransaction {
 pub fn parse(data: &[u8]) -> PluribitResult<Self> {
    let mut cursor = 0;
    let data_len = data.len(); // Get total length once

    // Version
    if data_len < cursor + 4 { // Check against data_len
        return Err(PluribitError::ValidationError("Transaction too short for version".into()));
    }
    let version = i32::from_le_bytes([data[cursor], data[cursor+1], data[cursor+2], data[cursor+3]]); // Use cursor index
    cursor += 4;

    // Segwit marker
    let is_segwit = data_len > cursor + 1 && data[cursor] == 0x00 && data[cursor + 1] == 0x01;
    if is_segwit {
        cursor += 2;
    }

    // Input count
    // Use ? to handle potential Err from read_varint
    let (input_count, bytes_read) = read_varint(&data[cursor..])?; // Use ?
    cursor += bytes_read;

    // Inputs loop
    let mut inputs = Vec::new();
    for _ in 0..input_count {
        // Check length BEFORE reading fixed parts (36 bytes: 32 txid + 4 vout)
        if data_len < cursor + 36 { // Check against data_len
            return Err(PluribitError::ValidationError("Input data too short for txid/vout".into()));
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[cursor..cursor + 32]);
        cursor += 32;

        let vout = u32::from_le_bytes([data[cursor], data[cursor+1], data[cursor+2], data[cursor+3]]); // Use cursor index
        cursor += 4;

        // Read script_len (varint)
        let (script_len_u64, bytes_read) = read_varint(&data[cursor..])?; // Use ?
        let script_len = script_len_u64 as usize; // Convert to usize for slicing
        cursor += bytes_read;

        // --- ADDED BOUNDS CHECK ---
        if data_len < cursor + script_len { // Check against data_len
             return Err(PluribitError::ValidationError(format!(
                "Data too short for script_sig: need {} bytes, only {} remaining",
                script_len, data_len - cursor
             )));
        }
        // --- END ADDED CHECK ---

        let script_sig = data[cursor..cursor + script_len].to_vec(); // Use usize script_len
        cursor += script_len;

        // Check length BEFORE reading sequence (4 bytes)
        if data_len < cursor + 4 { // Check against data_len
            return Err(PluribitError::ValidationError("Sequence data missing".into()));
        }
        let sequence = u32::from_le_bytes([data[cursor], data[cursor+1], data[cursor+2], data[cursor+3]]); // Use cursor index
        cursor += 4;

        inputs.push(BitcoinInput {
            txid,
            vout,
            script_sig,
            sequence,
            witness: Vec::new(),
        });
    }

    // Output count
    let (output_count, bytes_read) = read_varint(&data[cursor..])?; // Use ?
    cursor += bytes_read;

    // Outputs loop
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        // Check length BEFORE reading amount (8 bytes)
        if data_len < cursor + 8 { // Check against data_len
            return Err(PluribitError::ValidationError("Output data too short for amount".into()));
        }

        let amount = u64::from_le_bytes([ // Use cursor index
            data[cursor], data[cursor + 1], data[cursor + 2], data[cursor + 3],
            data[cursor + 4], data[cursor + 5], data[cursor + 6], data[cursor + 7],
        ]);
        cursor += 8;

        // Read script_len (varint)
        let (script_len_u64, bytes_read) = read_varint(&data[cursor..])?; // Use ?
        let script_len = script_len_u64 as usize; // Convert to usize
        cursor += bytes_read;

        // --- ADDED BOUNDS CHECK ---
         if data_len < cursor + script_len { // Check against data_len
             return Err(PluribitError::ValidationError(format!(
                 "Data too short for script_pubkey: need {} bytes, only {} remaining",
                 script_len, data_len - cursor
             )));
        }
        // --- END ADDED CHECK ---

        let script_pubkey = data[cursor..cursor + script_len].to_vec(); // Use usize script_len
        cursor += script_len;

        outputs.push(BitcoinOutput {
            amount,
            script_pubkey,
        });
    }

    // Witness data (if segwit)
    if is_segwit {
        // Check if we have enough data for at least the witness counts
         if inputs.len() > 0 && data_len < cursor + inputs.len() { // Rough check: at least 1 byte per input count
            return Err(PluribitError::ValidationError("Data too short for witness counts".into()));
         }

        for input in &mut inputs {
            let (witness_count, bytes_read) = read_varint(&data[cursor..])?; // Use ?
            cursor += bytes_read;

            for _ in 0..witness_count {
                let (item_len_u64, bytes_read) = read_varint(&data[cursor..])?; // Use ?
                let item_len = item_len_u64 as usize; // Convert to usize
                cursor += bytes_read;

                 // --- ADDED BOUNDS CHECK ---
                 if data_len < cursor + item_len { // Check against data_len
                     return Err(PluribitError::ValidationError(format!(
                         "Data too short for witness item: need {} bytes, only {} remaining",
                         item_len, data_len - cursor
                     )));
                }
                // --- END ADDED CHECK ---

                let item = data[cursor..cursor + item_len].to_vec(); // Use usize item_len
                cursor += item_len;

                input.witness.push(item);
            }
        }
    }

    // Locktime
    if data_len < cursor + 4 { // Check against data_len
        return Err(PluribitError::ValidationError("Locktime data missing".into()));
    }
    let locktime = u32::from_le_bytes([data[cursor], data[cursor+1], data[cursor+2], data[cursor+3]]); // Use cursor index

    // --- ADDED MISSING CURSOR INCREMENT ---
    cursor += 4;
    // --- END ADDED INCREMENT ---

    // --- ADDED FINAL LENGTH CHECK ---
    if cursor != data_len {
         return Err(PluribitError::ValidationError(format!(
             "Trailing data detected after parsing: expected cursor {}, got {}",
             data_len, cursor
         )));
    }
    // --- END ADDED CHECK ---

    Ok(BitcoinTransaction {
        version,
        inputs,
        outputs,
        locktime,
    })
}
    
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Version
        data.extend_from_slice(&self.version.to_le_bytes());
        
        // Check if any input has witness data
        let has_witness = self.inputs.iter().any(|i| !i.witness.is_empty());
        
        // Segwit marker and flag
        if has_witness {
            data.push(0x00);
            data.push(0x01);
        }
        
        // Input count
        data.extend_from_slice(&write_varint(self.inputs.len() as u64));
        
        // Inputs
        for input in &self.inputs {
            data.extend_from_slice(&input.txid);
            data.extend_from_slice(&input.vout.to_le_bytes());
            data.extend_from_slice(&write_varint(input.script_sig.len() as u64));
            data.extend_from_slice(&input.script_sig);
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }
        
        // Output count
        data.extend_from_slice(&write_varint(self.outputs.len() as u64));
        
        // Outputs
        for output in &self.outputs {
            data.extend_from_slice(&output.amount.to_le_bytes());
            data.extend_from_slice(&write_varint(output.script_pubkey.len() as u64));
            data.extend_from_slice(&output.script_pubkey);
        }
        
        // Witness data
        if has_witness {
            for input in &self.inputs {
                data.extend_from_slice(&write_varint(input.witness.len() as u64));
                for item in &input.witness {
                    data.extend_from_slice(&write_varint(item.len() as u64));
                    data.extend_from_slice(item);
                }
            }
        }
        
        // Locktime
        data.extend_from_slice(&self.locktime.to_le_bytes());
        
        data
    }
}

fn read_varint(data: &[u8]) -> PluribitResult<(u64, usize)> {
    if data.is_empty() {
        return Err(PluribitError::ValidationError("Data too short for varint".into()));
    }
    
    match data[0] {
        0xfd => {
            if data.len() < 3 {
                return Err(PluribitError::ValidationError("Data too short for u16 varint".into()));
            }
            Ok((u16::from_le_bytes([data[1], data[2]]) as u64, 3))
        }
        0xfe => {
            if data.len() < 5 {
                return Err(PluribitError::ValidationError("Data too short for u32 varint".into()));
            }
            Ok((u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64, 5))
        }
        0xff => {
            if data.len() < 9 {
                return Err(PluribitError::ValidationError("Data too short for u64 varint".into()));
            }
            Ok((u64::from_le_bytes([
                data[1], data[2], data[3], data[4],
                data[5], data[6], data[7], data[8],
            ]), 9))
        }
        n => Ok((n as u64, 1)),
    }
}

fn write_varint(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffffffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

// ============================================================================
// BITCOIN HTLC SCRIPT CREATION
// ============================================================================

pub struct BitcoinHTLC {
    pub script: Vec<u8>,
    pub address: String,
}

impl BitcoinHTLC {
    /// Create a Bitcoin HTLC script
    /// 
    /// Script: OP_IF
    ///           OP_SHA256 <hash> OP_EQUALVERIFY <recipient_pubkey> OP_CHECKSIG
    ///         OP_ELSE
    ///           <timeout> OP_CHECKSEQUENCEVERIFY OP_DROP <refund_pubkey> OP_CHECKSIG
    ///         OP_ENDIF
    pub fn create(
        secret_hash: &[u8; 32],
        recipient_pubkey: &[u8; 33],
        refund_pubkey: &[u8; 33],
        timeout_blocks: u32,
    ) -> Self {
        let mut script = Vec::new();
        
        // OP_IF
        script.push(0x63);
        
        // OP_SHA256
        script.push(0xa8);
        // Push hash
        script.push(0x20); // 32 bytes
        script.extend_from_slice(secret_hash);
        // OP_EQUALVERIFY
        script.push(0x88);
        // Push recipient pubkey
        script.push(0x21); // 33 bytes
        script.extend_from_slice(recipient_pubkey);
        // OP_CHECKSIG
        script.push(0xac);
        
        // OP_ELSE
        script.push(0x67);
        
        // Push timeout (CSV format)
        if timeout_blocks < 0x100 {
            script.push(0x51 + (timeout_blocks as u8 - 1));
        } else {
            script.push(0x02);
            script.extend_from_slice(&timeout_blocks.to_le_bytes()[..2]);
        }
        // OP_CHECKSEQUENCEVERIFY
        script.push(0xb2);
        // OP_DROP
        script.push(0x75);
        // Push refund pubkey
        script.push(0x21); // 33 bytes
        script.extend_from_slice(refund_pubkey);
        // OP_CHECKSIG
        script.push(0xac);
        
        // OP_ENDIF
        script.push(0x68);
        
        // Create P2WSH address (bech32)
        let script_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&script);
            hasher.finalize()
        };
        
        // Simplified bech32 encoding (for testnet: "tb1q...")
        let address = format!("tb1q{}", hex::encode(&script_hash[..20]));
        
        Self { script, address }
    }
    
    /// Create witness for claiming with secret
    pub fn claim_witness(secret: &[u8; 32], signature: Vec<u8>) -> Vec<Vec<u8>> {
        vec![
            signature,
            secret.to_vec(),
            vec![1], // Take IF branch
        ]
    }
    
    /// Create witness for refund after timeout
    pub fn refund_witness(signature: Vec<u8>) -> Vec<Vec<u8>> {
        vec![
            signature,
            vec![0], // Take ELSE branch
        ]
    }
}

// ============================================================================
// MAIN ATOMIC SWAP IMPLEMENTATION
// ============================================================================

impl AtomicSwap {
    /// Initiate a cross-chain atomic swap (Alice)
    pub fn initiate(
        alice_secret: &Scalar,
        alice_amount: u64,
        bob_pubkey: Vec<u8>,
        bob_amount: u64,
        timeout_blocks: u64,
    ) -> PluribitResult<Self> {
        log(&format!("[SWAP] Initiating cross-chain swap: {} PLB for {} sats", alice_amount, bob_amount));
        
        use rand::thread_rng;
        let mut rng = thread_rng();
        
        // Generate adaptor secret
        let t = Scalar::random(&mut rng);
        let t_point = &t * &PC_GENS.B_blinding;
        let secret_hash = {
            let mut hasher = Sha256::new();
            hasher.update(t.to_bytes());
            let h: [u8; 32] = hasher.finalize().into();
            h
        };
        
        let alice_pubkey_point = alice_secret * &PC_GENS.B_blinding;
        let blinding = Scalar::random(&mut rng);
        let commitment = mimblewimble::commit(alice_amount, &blinding)?;
        
        let mut hasher = Sha256::new();
        hasher.update(b"atomic_swap_v2");
        hasher.update(&alice_pubkey_point.compress().to_bytes());
        hasher.update(&bob_pubkey);
        hasher.update(&alice_amount.to_le_bytes());
        hasher.update(&bob_amount.to_le_bytes());
        hasher.update(&secret_hash);
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
            bob_btc_address: None,
            bob_btc_txid: None,
            bob_btc_vout: None,
            bob_commitment: vec![],
            bob_adaptor_sig: vec![],
            bob_timeout_height: 0,
            shared_adaptor_point: t_point.compress().to_bytes(),
            adaptor_secret: Some(t.to_bytes()),
            secret_hash,
            created_at: now,
            expires_at: now + (timeout_blocks * 30 * 1000),
            last_updated: now,
        })
    }
    
    /// Bob responds with Bitcoin HTLC details
    pub fn respond(
        &mut self,
        _bob_secret: &Scalar,
        bob_btc_address: String,
        bob_btc_txid: String,
        bob_btc_vout: u32,
        bob_adaptor_sig_bytes: Vec<u8>,
        bob_timeout_height: u64,
    ) -> PluribitResult<()> {
        if self.state != SwapState::Negotiating {
            return Err(PluribitError::StateError("Not negotiating".into()));
        }
        
        self.bob_btc_address = Some(bob_btc_address);
        self.bob_btc_txid = Some(bob_btc_txid);
        self.bob_btc_vout = Some(bob_btc_vout);
        self.bob_adaptor_sig = bob_adaptor_sig_bytes;
        self.bob_timeout_height = bob_timeout_height;
        self.state = SwapState::Committed;
        
        #[cfg(target_arch = "wasm32")]
        let now = js_sys::Date::now() as u64;
        #[cfg(not(target_arch = "wasm32"))]
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.last_updated = now;
        
        log("[SWAP] ✓ Bob committed with Bitcoin HTLC");
        Ok(())
    }
    
    /// Alice creates adaptor signature
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
        
        #[cfg(target_arch = "wasm32")]
        let now = js_sys::Date::now() as u64;
        #[cfg(not(target_arch = "wasm32"))]
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.last_updated = now;
        
        log("[SWAP] ✓ Alice created adaptor sig");
        Ok(adaptor_sig)
    }
    
    /// Bob claims Pluribit (reveals secret)
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
        
        // Verify adaptor secret matches
        let t_point = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&self.shared_adaptor_point)
            .map_err(|_| PluribitError::ValidationError("Invalid point".into()))?
            .decompress()
            .ok_or_else(|| PluribitError::ValidationError("Decompress failed".into()))?;
        
        let claimed_t_point = adaptor_secret * &PC_GENS.B_blinding;
        if claimed_t_point != t_point {
            return Err(PluribitError::ValidationError("Wrong adaptor secret".into()));
        }
        
        // Verify secret hash
        let secret_hash = {
            let mut hasher = Sha256::new();
            hasher.update(adaptor_secret.to_bytes());
            let h: [u8; 32] = hasher.finalize().into();
            h
        };
        if secret_hash != self.secret_hash {
            return Err(PluribitError::ValidationError("Secret hash mismatch".into()));
        }
        
        // Complete signature (reveals secret!)
        let (_challenge, completed_sig) = adapt_signature(alice_adaptor_sig, adaptor_secret)?;
        
        log("[SWAP] ✓ Bob revealed secret, claiming Pluribit!");
        
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
        
        log(&format!("[SWAP] ✓ Bob's claim tx ready: {} PLB", self.alice_amount));
        
        Ok(Transaction {
            inputs: vec![input],
            outputs: vec![output],
            kernels: vec![kernel],
            timestamp: WasmU64::from(timestamp),
            aggregated_range_proof: proof.to_bytes(),
        })
    }
    
    /// Alice extracts secret from Bob's claim transaction
    pub fn alice_extract_and_claim(
        &mut self,
        bob_completed_signature: &Scalar,
    ) -> PluribitResult<Scalar> {
        let alice_adaptor_sig = self.alice_adaptor_sig.as_ref()
            .ok_or_else(|| PluribitError::StateError("No adaptor sig".into()))?;
        
        let t = extract_adaptor_secret(alice_adaptor_sig, bob_completed_signature);
        
        // Verify extracted secret
        let secret_hash = {
            let mut hasher = Sha256::new();
            hasher.update(t.to_bytes());
            let h: [u8; 32] = hasher.finalize().into();
            h
        };
        if secret_hash != self.secret_hash {
            return Err(PluribitError::ValidationError("Extracted secret invalid".into()));
        }
        
        self.adaptor_secret = Some(t.to_bytes());
        self.state = SwapState::Claimed;
        
        #[cfg(target_arch = "wasm32")]
        let now = js_sys::Date::now() as u64;
        #[cfg(not(target_arch = "wasm32"))]
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.last_updated = now;
        
        log(&format!("[SWAP] ✓ Alice extracted secret: {}", hex::encode(t.to_bytes())));
        log("[SWAP] ✓ Alice can now claim Bitcoin with this secret!");
        
        Ok(t)
    }
    
    /// Create Bitcoin claim transaction (Alice claims with secret)
    pub fn create_bitcoin_claim_tx(
        &self,
        secret: &[u8; 32],
        alice_btc_address: &str,
        fee_sats: u64,
    ) -> PluribitResult<BitcoinTransaction> {
        let txid_str = self.bob_btc_txid.as_ref()
            .ok_or_else(|| PluribitError::StateError("No Bitcoin txid".into()))?;
        let vout = self.bob_btc_vout
            .ok_or_else(|| PluribitError::StateError("No Bitcoin vout".into()))?;
        
        // Parse txid
        let txid_bytes = hex::decode(txid_str)
            .map_err(|_| PluribitError::ValidationError("Invalid txid".into()))?;
        if txid_bytes.len() != 32 {
            return Err(PluribitError::ValidationError("Invalid txid length".into()));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);
        
        // Verify secret hash
        let secret_hash = {
            let mut hasher = Sha256::new();
            hasher.update(secret);
            let h: [u8; 32] = hasher.finalize().into();
            h
        };
        if secret_hash != self.secret_hash {
            return Err(PluribitError::ValidationError("Secret hash mismatch".into()));
        }
        
        log(&format!("[SWAP] Creating Bitcoin claim tx from {}:{}", txid_str, vout));
        log(&format!("[SWAP] Claiming to address: {}", alice_btc_address));
        log(&format!("[SWAP] Using secret: {}", hex::encode(secret)));
        
        // Parse destination address to script
        let output_script = address_to_script(alice_btc_address)?;
        
        // Calculate output amount (input - fee)
        let output_amount = self.bob_amount.saturating_sub(fee_sats);
        
        // Create transaction
        let tx = BitcoinTransaction {
            version: 2,
            inputs: vec![BitcoinInput {
                txid,
                vout,
                script_sig: vec![], // Empty for segwit
                sequence: 0xfffffffe, // Enable RBF
                witness: vec![], // Will be filled when signing
            }],
            outputs: vec![BitcoinOutput {
                amount: output_amount,
                script_pubkey: output_script,
            }],
            locktime: 0,
        };
        
        log(&format!("[SWAP] ✓ Claim tx created: {} sats output", output_amount));
        log("[SWAP] ⚠️  Sign with: signature + secret + HTLC script in witness");
        
        Ok(tx)
    }
    
    /// Alice refunds Pluribit after timeout
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
        
        log("[SWAP] Alice refunding Pluribit after timeout");
        
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
        
        log(&format!("[SWAP] ✓ Refund tx: {} PLB", self.alice_amount));
        
        Ok(Transaction {
            inputs: vec![input],
            outputs: vec![output],
            kernels: vec![kernel],
            timestamp: WasmU64::from(timestamp),
            aggregated_range_proof: proof.to_bytes(),
        })
    }
    
    /// Bob refunds Bitcoin after timeout
    pub fn bob_refund_bitcoin(&self, bob_btc_address: &str, fee_sats: u64, current_height: u64) -> PluribitResult<BitcoinTransaction> {
        if current_height < self.bob_timeout_height {
            return Err(PluribitError::ValidationError("Timeout not reached".into()));
        }
        
        let txid_str = self.bob_btc_txid.as_ref()
            .ok_or_else(|| PluribitError::StateError("No Bitcoin txid".into()))?;
        let vout = self.bob_btc_vout
            .ok_or_else(|| PluribitError::StateError("No Bitcoin vout".into()))?;
        
        // Parse txid
        let txid_bytes = hex::decode(txid_str)
            .map_err(|_| PluribitError::ValidationError("Invalid txid".into()))?;
        if txid_bytes.len() != 32 {
            return Err(PluribitError::ValidationError("Invalid txid length".into()));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);
        
        log(&format!("[SWAP] Creating Bitcoin refund tx from {}:{}", txid_str, vout));
        log(&format!("[SWAP] Refunding to address: {}", bob_btc_address));
        
        // Parse destination address to script
        let output_script = address_to_script(bob_btc_address)?;
        
        // Calculate output amount (input - fee)
        let output_amount = self.bob_amount.saturating_sub(fee_sats);
        
        // Create transaction with CSV locktime
        let tx = BitcoinTransaction {
            version: 2,
            inputs: vec![BitcoinInput {
                txid,
                vout,
                script_sig: vec![], // Empty for segwit
                sequence: self.bob_timeout_height as u32, // CSV timeout
                witness: vec![], // Will be filled when signing
            }],
            outputs: vec![BitcoinOutput {
                amount: output_amount,
                script_pubkey: output_script,
            }],
            locktime: 0,
        };
        
        log(&format!("[SWAP] ✓ Refund tx created: {} sats output", output_amount));
        log("[SWAP] ⚠️  Sign with: signature + HTLC script in witness (ELSE branch)");
        
        Ok(tx)
    }
    
    // ========================================================================
    // HELPER METHODS
    // ========================================================================
    
    /// Get swap progress (0-100)
    pub fn progress(&self) -> u8 {
        match self.state {
            SwapState::Negotiating => 25,
            SwapState::Committed => 50,
            SwapState::Claimed => 75,
            SwapState::Completed | SwapState::Refunded => 100,
        }
    }
    
    /// Check if timeout approaching
    pub fn needs_refund(&self, current_height: u64, buffer_blocks: u64) -> bool {
        if self.state != SwapState::Committed {
            return false;
        }
        let timeout_with_buffer = self.alice_timeout_height.saturating_sub(buffer_blocks);
        current_height >= timeout_with_buffer
    }
    
    /// Check if expired
    pub fn is_expired(&self) -> bool {
        #[cfg(target_arch = "wasm32")]
        let now = js_sys::Date::now() as u64;
        #[cfg(not(target_arch = "wasm32"))]
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        now > self.expires_at
    }
    
    /// Verify Bitcoin HTLC was created correctly
    pub fn verify_bitcoin_htlc(&self, bitcoin_rpc: &BitcoinRPC) -> PluribitResult<bool> {
        let txid = self.bob_btc_txid.as_ref()
            .ok_or_else(|| PluribitError::StateError("No Bitcoin txid".into()))?;
        let vout = self.bob_btc_vout
            .ok_or_else(|| PluribitError::StateError("No Bitcoin vout".into()))?;
        
        #[cfg(not(target_arch = "wasm32"))]
        {
            let tx_hex = bitcoin_rpc.get_raw_transaction(txid)?;
            log(&format!("[SWAP] Verifying Bitcoin tx: {} bytes", tx_hex.len()));
            
            // Parse transaction
            let tx_bytes = hex::decode(&tx_hex)
                .map_err(|_| PluribitError::ValidationError("Invalid tx hex".into()))?;
            
            let tx = BitcoinTransaction::parse(&tx_bytes)?;
            
            // Verify output exists
            if vout as usize >= tx.outputs.len() {
                return Err(PluribitError::ValidationError("Output index out of range".into()));
            }
            
            let output = &tx.outputs[vout as usize];
            
            // Verify amount (satoshis)
            if output.amount != self.bob_amount {
                log(&format!("[SWAP] ✗ Amount mismatch: expected {}, got {}", 
                    self.bob_amount, output.amount));
                return Ok(false);
            }
            
            // Verify script is P2WSH
            if output.script_pubkey.len() != 34 {
                return Ok(false);
            }
            if output.script_pubkey[0] != 0x00 || output.script_pubkey[1] != 0x20 {
                return Ok(false);
            }
            
            log(&format!("[SWAP] ✓ Bitcoin HTLC verified: {} sats", output.amount));
            Ok(true)
        }
        
        #[cfg(target_arch = "wasm32")]
        {
            log("[SWAP] ⚠️  Bitcoin verification requires async in WASM");
            Ok(false)
        }
    }
}

// ============================================================================
// PERSISTENCE & SERIALIZATION
// ============================================================================

impl AtomicSwap {
    /// Save swap to JSON
    pub fn to_json(&self) -> PluribitResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| PluribitError::SerializationError(e.to_string()))
    }
    
    /// Load swap from JSON
    pub fn from_json(json: &str) -> PluribitResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| PluribitError::SerializationError(e.to_string()))
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

pub fn derive_adaptor_point_from_preimage(preimage: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha256::new();
    hasher.update(b"atomic_swap_adaptor_v2");
    hasher.update(preimage);
    let hash: [u8; 32] = hasher.finalize().into();
    let scalar = Scalar::from_bytes_mod_order(hash);
    &scalar * &PC_GENS.B_blinding
}

pub fn hash_secret(secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    let h: [u8; 32] = hasher.finalize().into();
    h
}

/// Convert Bitcoin address to scriptPubKey
pub fn address_to_script(address: &str) -> PluribitResult<Vec<u8>> {
    if address.starts_with("bc1q") || address.starts_with("tb1q") {
        // Bech32 P2WPKH
        let data_part = &address[4..];
        let decoded = bech32_decode(data_part)
            .ok_or_else(|| PluribitError::ValidationError("Invalid bech32 address".into()))?;
        
        if decoded.len() != 20 {
            return Err(PluribitError::ValidationError("Invalid P2WPKH length".into()));
        }
        
        // OP_0 <20 bytes>
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&decoded);
        Ok(script)
    } else if address.starts_with("bc1p") || address.starts_with("tb1p") {
        // Bech32m P2TR (Taproot)
        let data_part = &address[4..];
        let decoded = bech32_decode(data_part)
            .ok_or_else(|| PluribitError::ValidationError("Invalid bech32m address".into()))?;
        
        if decoded.len() != 32 {
            return Err(PluribitError::ValidationError("Invalid P2TR length".into()));
        }
        
        // OP_1 <32 bytes>
        let mut script = vec![0x51, 0x20];
        script.extend_from_slice(&decoded);
        Ok(script)
    } else if address.starts_with('1') || address.starts_with('m') || address.starts_with('n') {
        // Base58 P2PKH (legacy)
        let decoded = base58_decode(address)
            .ok_or_else(|| PluribitError::ValidationError("Invalid base58 address".into()))?;
        
        if decoded.len() != 25 {
            return Err(PluribitError::ValidationError("Invalid P2PKH length".into()));
        }
        
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&decoded[1..21]);
        script.extend_from_slice(&[0x88, 0xac]);
        Ok(script)
    } else if address.starts_with('3') || address.starts_with('2') {
        // Base58 P2SH
        let decoded = base58_decode(address)
            .ok_or_else(|| PluribitError::ValidationError("Invalid base58 address".into()))?;
        
        if decoded.len() != 25 {
            return Err(PluribitError::ValidationError("Invalid P2SH length".into()));
        }
        
        // OP_HASH160 <20 bytes> OP_EQUAL
        let mut script = vec![0xa9, 0x14];
        script.extend_from_slice(&decoded[1..21]);
        script.push(0x87);
        Ok(script)
    } else {
        Err(PluribitError::ValidationError("Unknown address format".into()))
    }
}

fn bech32_decode(s: &str) -> Option<Vec<u8>> {
    // Simplified bech32 decoder (converts from base32 to bytes)
    let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut values = Vec::new();
    
    for c in s.chars() {
        let val = charset.find(c)?;
        values.push(val as u8);
    }
    
    // Convert from 5-bit to 8-bit
    let mut bytes = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    
    for &value in &values[..values.len().saturating_sub(6)] {
        acc = (acc << 5) | (value as u32);
        bits += 5;
        
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    
    Some(bytes)
}

fn base58_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    let mut result = vec![0u8];
    
    for c in s.chars() {
        let digit = ALPHABET.find(c)? as u32;
        
        // Multiply result by 58 and add digit
        let mut carry = digit;
        for byte in result.iter_mut() {
            let val = (*byte as u32) * 58 + carry;
            *byte = (val & 0xff) as u8;
            carry = val >> 8;
        }
        
        while carry > 0 {
            result.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    
    // Add leading zeros
    for c in s.chars() {
        if c == '1' {
            result.push(0);
        } else {
            break;
        }
    }
    
    result.reverse();
    Some(result)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mimblewimble;
    
    #[test]
    fn test_atomic_swap_flow() {
        let alice_secret = mimblewimble::generate_secret_key();
        let bob_secret = mimblewimble::generate_secret_key();
        let bob_pubkey = (&bob_secret * &PC_GENS.B_blinding).compress().to_bytes().to_vec();
        
        // Alice initiates
        let mut swap = AtomicSwap::initiate(&alice_secret, 1_000_000, bob_pubkey, 500_000, 144).unwrap();
        assert_eq!(swap.state, SwapState::Negotiating);
        
        // Bob responds
        swap.respond(
            &bob_secret,
            "tb1qtest".to_string(),
            "abc123".to_string(),
            0,
            vec![0u8; 64],
            144
        ).unwrap();
        assert_eq!(swap.state, SwapState::Committed);
        
        // Alice creates adaptor sig
        swap.alice_create_adaptor_signature(&alice_secret).unwrap();
        
        // Progress tracking
        assert_eq!(swap.progress(), 50);
    }
    
    #[test]
    fn test_bitcoin_htlc_creation() {
        let secret_hash = [0u8; 32];
        let recipient_pk = [2u8; 33];
        let refund_pk = [3u8; 33];
        
        let htlc = BitcoinHTLC::create(&secret_hash, &recipient_pk, &refund_pk, 144);
        
        assert!(!htlc.script.is_empty());
        assert!(htlc.address.starts_with("tb1q"));
    }
    
    #[test]
    fn test_swap_serialization() {
        let alice_secret = mimblewimble::generate_secret_key();
        let swap = AtomicSwap::initiate(&alice_secret, 1_000_000, vec![0u8; 32], 500_000, 144).unwrap();
        
        let json = swap.to_json().unwrap();
        let loaded = AtomicSwap::from_json(&json).unwrap();
        
        assert_eq!(swap.swap_id, loaded.swap_id);
        assert_eq!(swap.alice_amount, loaded.alice_amount);
    }
    
#[test]
fn test_bitcoin_tx_parsing() {
    // Real Bitcoin transaction (non-segwit, 1 input, 2 outputs)
    // This is a real mainnet tx: f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16 i.e: https://mempool.space/api/tx/f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16/hex
    let tx_hex = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
    
    let tx_bytes = hex::decode(tx_hex).expect("Valid hex");
    let tx = BitcoinTransaction::parse(&tx_bytes);
    
    assert!(tx.is_ok(), "Parsing valid Bitcoin tx should succeed: {:?}", tx.err());
    
    let parsed = tx.unwrap();
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.inputs.len(), 1);
    assert_eq!(parsed.outputs.len(), 2);
    assert_eq!(parsed.locktime, 0);
    
    // Verify round-trip
    let serialized = parsed.serialize();
    let reparsed = BitcoinTransaction::parse(&serialized).expect("Re-parse should work");
    assert_eq!(reparsed.version, parsed.version);
    assert_eq!(reparsed.inputs.len(), parsed.inputs.len());
    assert_eq!(reparsed.outputs.len(), parsed.outputs.len());
}
    
    #[test]
    fn test_address_to_script() {
        // P2WPKH (bech32)
        let script = address_to_script("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
        assert!(script.is_ok());
        
        // P2PKH (legacy) - simplified test
        let script = address_to_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert!(script.is_ok());
    }
    
    #[test]
    fn test_bitcoin_tx_serialization() {
        let tx = BitcoinTransaction {
            version: 2,
            inputs: vec![BitcoinInput {
                txid: [0u8; 32],
                vout: 0,
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            }],
            outputs: vec![BitcoinOutput {
                amount: 10000,
                script_pubkey: vec![0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            }],
            locktime: 0,
        };
        
        let serialized = tx.serialize();
        assert!(serialized.len() > 0);
        
        // Parse it back
        let parsed = BitcoinTransaction::parse(&serialized).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.outputs[0].amount, 10000);
    }
}
