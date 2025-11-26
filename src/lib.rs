// src/lib.rs
use wasm_bindgen::prelude::*;
use serde_wasm_bindgen;
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Serialize, Deserialize};
use serde_json;
use sha2::{Sha256, Digest};
use curve25519_dalek::{ristretto::{CompressedRistretto, RistrettoPoint}, scalar::Scalar, traits::Identity};
use crate::atomic_swap::{AtomicSwap, SwapState};
use crate::payment_channel::{MuSigKernelMetadata, PaymentChannel, ChannelState, Party};
use crate::blockchain::{Blockchain, BlockFilterEntry};
use crate::vrf::VrfProof;
use crate::constants::DIFFICULTY_ADJUSTMENT_INTERVAL;
use crate::wallet::Wallet;
use bulletproofs::RangeProof;
use crate::vdf::{VDF, VDFProof};
use crate::blockchain::get_current_base_reward;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use rand::thread_rng;
use prost::Message;
use crate::error::PluribitError;
use crate::transaction::{Transaction, TransactionOutput, TransactionKernel};
use crate::block::Block; 
use crate::constants::MAX_TX_POOL_SIZE;
use crate::wasm_types::WasmU64;

pub mod constants;
pub mod wasm_types;

pub mod error;
pub mod utils;
pub mod vdf;
pub mod mimblewimble;
pub mod transaction;
pub mod block;
pub mod p2p;
pub mod blockchain;
pub mod stealth;
pub mod wallet;
pub mod address;
pub mod merkle;
pub mod vrf;
pub mod adaptor;
pub mod payment_channel;
pub mod atomic_swap;

// RATIONALE: Prevent DoS via extremely deep reorgs
const MAX_REORG_DEPTH: u64 = 1000000000; 

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
    pub aggregated_kernels: Vec<TransactionKernel>,
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

// RATIONALE: Prevent memory exhaustion attacks by bounding cache sizes
// LRU eviction ensures we keep most relevant data.
const MAX_SIDE_BLOCKS: usize = 10000;
const MAX_UTXO_CACHE: usize = 10000;

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

    // --- Caches with Bounded Sizes ---

    // Cache of recent UTXOs for fast recovery during reorgs
    // Maps commitment -> (height, TransactionOutput)
    static ref RECENT_UTXO_CACHE: Mutex<HashMap<Vec<u8>, (u64, TransactionOutput)>> =
        Mutex::new(HashMap::new());
    static ref UTXO_CACHE_LRU: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());

    /// Side blocks that are not on the current canonical chain (by hash)
    static ref SIDE_BLOCKS: Mutex<HashMap<String, Block>> = Mutex::new(HashMap::new());
    static ref SIDE_BLOCKS_LRU: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

    // in-process wallet sessions (Rust owns keys/state)
    static ref WALLET_SESSIONS: Mutex<HashMap<String, wallet::Wallet>> =
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

async fn delete_canonical_block(height: u64) -> Result<(), JsValue> {
    let promise = delete_canonical_block_raw(height);
    wasm_bindgen_futures::JsFuture::from(promise).await?;
    Ok(())
}

async fn set_tip_metadata(height: u64, hash: &str) -> Result<(), JsValue> {
    let promise = set_tip_metadata_raw(height, hash);
    wasm_bindgen_futures::JsFuture::from(promise).await?;
    Ok(())
}

// --- START: JS BRIDGE DEFINITION ---
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = load_block_from_db)]
    fn load_block_from_db_raw(height: u64) -> js_sys::Promise;

    #[wasm_bindgen(js_name = get_tip_height_from_db)]
    fn get_tip_height_from_db_raw() -> js_sys::Promise;
    
    #[wasm_bindgen(js_name = save_total_work_to_db)]
    fn save_total_work_to_db_raw(work: u64) -> js_sys::Promise;

    #[wasm_bindgen(js_name = get_total_work_from_db)]
    fn get_total_work_from_db_raw() -> js_sys::Promise;
    
    #[wasm_bindgen(js_name = saveBlock)]
    fn save_block_to_db_raw(block: JsValue) -> js_sys::Promise;

    #[wasm_bindgen(js_name = clear_all_utxos)]
    fn clear_all_utxos_raw() -> js_sys::Promise;

    #[wasm_bindgen(js_name = "loadBlocks")]
    fn load_blocks_from_db_raw(start: u64, end: u64) -> js_sys::Promise;

    #[wasm_bindgen(js_name = "loadAllUtxos")]
    fn load_all_utxos_raw() -> js_sys::Promise;

    #[wasm_bindgen(js_name = save_utxo)]
    fn save_utxo_raw(commitment_hex: &str, output: JsValue) -> js_sys::Promise;

    #[wasm_bindgen(js_name = load_utxo)]
    fn load_utxo_raw(commitment_hex: &str) -> js_sys::Promise;

    #[wasm_bindgen(js_name = delete_utxo)]
    fn delete_utxo_raw(commitment_hex: &str) -> js_sys::Promise;
    
    #[wasm_bindgen(js_name = saveBlockWithHash)]
    fn save_block_with_hash_raw(block: JsValue) -> js_sys::Promise;
    
    #[wasm_bindgen(js_name = loadBlockByHash)]
    fn load_block_by_hash_raw(hash: &str) -> js_sys::Promise;

    #[wasm_bindgen(js_name = deleteCanonicalBlock)]
    fn delete_canonical_block_raw(height: u64) -> js_sys::Promise;
    
    #[wasm_bindgen(js_name = setTipMetadata)]
    fn set_tip_metadata_raw(height: u64, hash: &str) -> js_sys::Promise;

    #[wasm_bindgen(js_name = save_reorg_marker)]
    fn save_reorg_marker_raw(marker: JsValue) -> js_sys::Promise;
    #[wasm_bindgen(js_name = clear_reorg_marker)]
    fn clear_reorg_marker_raw() -> js_sys::Promise;
    #[wasm_bindgen(js_name = save_block_to_staging)]
    fn save_block_to_staging_raw(block: JsValue) -> js_sys::Promise;
    #[wasm_bindgen(js_name = commit_staged_reorg)]
    fn commit_staged_reorg_raw(blocks: JsValue, old_heights: JsValue, new_tip_height: u64, new_tip_hash: &str) -> js_sys::Promise;

    #[wasm_bindgen(js_name = "save_coinbase_index")]
    fn save_coinbase_index_raw(commitment_hex: &str, height: u64) -> js_sys::Promise;

    #[wasm_bindgen(js_name = "delete_coinbase_index")]
    fn delete_coinbase_index_raw(commitment_hex: &str) -> js_sys::Promise;

    #[wasm_bindgen(js_name = "loadAllCoinbaseIndexes")]
    fn load_all_coinbase_indexes_raw() -> js_sys::Promise;

    #[wasm_bindgen(js_name = "save_block_filter")]
    fn save_block_filter_raw(height: u64, filter_json: &str) -> js_sys::Promise;

    #[wasm_bindgen(js_name = "load_block_filter_range")]
    fn load_block_filter_range_raw(start_height: u64, end_height: u64) -> js_sys::Promise;
    
    #[wasm_bindgen(js_name = "delete_block_filter")]
    fn delete_block_filter_raw(height: u64) -> js_sys::Promise;

    #[wasm_bindgen(js_name = postRustCommands)]
    fn post_rust_commands_raw(response_bytes: Vec<u8>);
    
}

// Helper to send an async response back to JS
fn post_rust_commands(response: p2p::RustToJsCommandBatch) {
    let mut response_bytes = Vec::new();
    if response.encode(&mut response_bytes).is_ok() {
        post_rust_commands_raw(response_bytes);
    } else {
        log("FATAL: Failed to encode async RustToJs_CommandBatch");
    }
}

#[wasm_bindgen]
pub fn handle_command(request_bytes: Vec<u8>) -> Vec<u8> {
    // 1. Decode the command from JavaScript
    let cmd_result = p2p::JsToRustCommand::decode(request_bytes.as_slice());

    // 2. Create a response batch
    let mut response = p2p::RustToJsCommandBatch::default();

    // 3. Match on the command
    match cmd_result {
        Ok(cmd) => {
            match cmd.command {
                // --- Wallet Management ---
                Some(p2p::js_to_rust_command::Command::CreateWallet(req)) => {
                    handle_create_wallet_internal(&mut response, req);
                }
                Some(p2p::js_to_rust_command::Command::RestoreWallet(req)) => {
                    handle_restore_wallet_internal(&mut response, req);
                }
                Some(p2p::js_to_rust_command::Command::LoadWallet(req)) => {
                    // This is async, so we spawn a future
                    wasm_bindgen_futures::spawn_local(handle_load_wallet_internal(req));
                    // Log that the command was *received*
                    // The async task will send the real response later.
                    add_log_command(&mut response, "info", "Wallet load started...");
                }
                Some(p2p::js_to_rust_command::Command::GetBalance(req)) => {
                    handle_get_balance_internal(&mut response, req);
                }
                Some(p2p::js_to_rust_command::Command::CreateTransaction(req)) => {
                    // This is async (wallet state must be exported)
                    wasm_bindgen_futures::spawn_local(handle_create_transaction_internal(req));
                    add_log_command(&mut response, "info", "Transaction creation initiated...");
                }

                // --- Node & Chain ---
                Some(p2p::js_to_rust_command::Command::ToggleMiner(req)) => {
                    // This is async (needs to get keys, start worker)
                    wasm_bindgen_futures::spawn_local(handle_toggle_miner_internal(req));
                }
                Some(p2p::js_to_rust_command::Command::GetStatus(_)) => {
                    handle_get_status_internal(&mut response);
                }
                Some(p2p::js_to_rust_command::Command::GetSupply(_)) => {
                    // This is async
                    wasm_bindgen_futures::spawn_local(handle_get_supply_internal());
                }
                Some(p2p::js_to_rust_command::Command::GetPeers(_)) => {
                    handle_get_peers_internal(&mut response);
                }
                Some(p2p::js_to_rust_command::Command::ConnectPeer(req)) => {
                    handle_connect_peer_internal(&mut response, req);
                }

                // --- System Ticks ---
                Some(p2p::js_to_rust_command::Command::SyncTick(req)) => {
                    // This is async
                    wasm_bindgen_futures::spawn_local(handle_sync_tick_internal(req));
                }

                // --- Atomic Swaps ---
                Some(p2p::js_to_rust_command::Command::SwapInitiate(req)) => {
                    wasm_bindgen_futures::spawn_local(handle_swap_initiate_internal(req));
                }
                Some(p2p::js_to_rust_command::Command::SwapList(_)) => {
                    handle_swap_list_internal(&mut response);
                }
                Some(p2p::js_to_rust_command::Command::SwapRespond(req)) => {
                    wasm_bindgen_futures::spawn_local(handle_swap_respond_internal(req));
                }
                Some(p2p::js_to_rust_command::Command::SwapClaim(req)) => {
                    wasm_bindgen_futures::spawn_local(handle_swap_claim_internal(req));
                }
                Some(p2p::js_to_rust_command::Command::SwapRefund(req)) => {
                    wasm_bindgen_futures::spawn_local(handle_swap_refund_internal(req));
                }

                // --- Payment Channels (Stubs) ---
                Some(p2p::js_to_rust_command::Command::ChannelOpen(req)) => {
                     wasm_bindgen_futures::spawn_local(handle_channel_open_internal(req));
                }
                Some(p2p::js_to_rust_command::Command::ChannelList(_)) => {
                    handle_channel_list_internal(&mut response);
                }
                Some(p2p::js_to_rust_command::Command::ChannelAccept(req)) => {
                    wasm_bindgen_futures::spawn_local(handle_channel_accept_internal(req));
                }
                Some(p2p::js_to_rust_command::Command::ChannelFund(req)) => {
                    wasm_bindgen_futures::spawn_local(handle_channel_fund_internal(req));
                }
                Some(p2p::js_to_rust_command::Command::ChannelPay(req)) => {
                    wasm_bindgen_futures::spawn_local(handle_channel_pay_internal(req));
                }
                Some(p2p::js_to_rust_command::Command::ChannelClose(req)) => {
                    wasm_bindgen_futures::spawn_local(handle_channel_close_internal(req));
                }

                // --- Catch-all ---
                None | Some(_) => {
                    add_log_command(&mut response, "error", "Received unknown or unimplemented command");
                }
            }
        },
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to decode JSToRust_Command: {}", e));
        }
    }

    // 4. Encode the response batch and return it
    let mut response_bytes = Vec::new();
    match response.encode(&mut response_bytes) {
        Ok(_) => {
            // Success, response_bytes is now populated
            response_bytes
        }
        Err(e) => {
            // Fallback if response encoding fails
            log(&format!("FATAL: Failed to encode RustToJs_CommandBatch: {}", e));
            // Return an empty (but valid) encoded batch
            p2p::RustToJsCommandBatch::default().encode_to_vec()
        }
    }
}

// ===================================================================
// INTERNAL HELPER FUNCTIONS
// (These are the stubs you need to implement)
// ===================================================================

// --- Command Response Helpers ---

/// Helper to add a log command to the response batch
fn add_log_command(response: &mut p2p::RustToJsCommandBatch, level: &str, message: &str) {
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::LogMessage(p2p::LogMessage {
            level: level.to_string(),
            message: message.to_string(),
        })),
    });
}

/// Helper to add a P2P publish command to the response batch
fn add_p2p_publish_command(response: &mut p2p::RustToJsCommandBatch, topic: String, data: Vec<u8>) {
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::P2pPublish(p2p::PublishP2pMessage {
            topic,
            data,
        })),
    });
}

// --- Wallet Management Helpers ---
fn wallet_session_get_balance_internal(wallet_id: &str) -> Result<u64, PluribitError> {
    let map = WALLET_SESSIONS.lock().unwrap();
    let w = map.get(wallet_id).ok_or_else(|| PluribitError::StateError("Wallet not loaded".into()))?;
    Ok(w.balance())
}

fn handle_create_wallet_internal(response: &mut p2p::RustToJsCommandBatch, req: p2p::CreateWalletRequest) {
    // This is synchronous, so we can just call the internal logic from src/lib.rs
    match wallet_session_create_with_mnemonic(&req.wallet_id) {
        Ok(phrase) => {
            add_log_command(response, "success", &format!("Wallet '{}' created.", req.wallet_id));
            add_log_command(response, "warn", "IMPORTANT: Write down your 12-word mnemonic phrase:");
            add_log_command(response, "info", &phrase);
            add_log_command(response, "warn", "This phrase is required to restore your wallet.");
            // TODO: We also need to tell JS to save the wallet blob
            // let blob = wallet_session_export(&req.wallet_id).unwrap();
            // add_save_wallet_command(response, req.wallet_id, blob);
        }
        Err(e) => {
            add_log_command(response, "error", &format!("Failed to create wallet: {:?}", e));
        }
    }
}

fn handle_restore_wallet_internal(response: &mut p2p::RustToJsCommandBatch, req: p2p::RestoreWalletRequest) {
    match wallet_session_restore_from_mnemonic(&req.wallet_id, &req.phrase) {
        Ok(_) => {
            add_log_command(response, "success", &format!("Wallet '{}' restored successfully.", req.wallet_id));
             // TODO: We also need to tell JS to save the wallet blob
            // let blob = wallet_session_export(&req.wallet_id).unwrap();
            // add_save_wallet_command(response, req.wallet_id, blob);
        }
        Err(e) => {
             add_log_command(response, "error", &format!("Failed to restore wallet: {:?}", e));
        }
    }
}

async fn handle_load_wallet_internal(req: p2p::LoadWalletRequest) {
    let wallet_id = req.wallet_id;
    let mut response = p2p::RustToJsCommandBatch::default();

    // Replicate the logic from worker.js's handleLoadWallet
    
    // We must acquire the lock *outside* any .await points.
    // This is complex. Let's start by just clearing.
    {
        let mut map = WALLET_SESSIONS.lock().unwrap();
        map.clear();
    }
    // TODO: Clear workerState.wallets in JS via a new command

    // 1. Load wallet JSON from DB (this is an async JS call)
    let wallet_json: String = match load_wallet_json_from_db(&wallet_id).await {
        Ok(Some(json)) => json,
        Ok(None) => {
            add_log_command(&mut response, "error", &format!("Wallet '{}' not found.", wallet_id));
            post_rust_commands(response);
            return;
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to load wallet '{}': {:?}", wallet_id, e));
            post_rust_commands(response);
            return;
        }
    };

    // 2. Open the wallet session (synchronous)
    if let Err(e) = wallet_session_open_internal(&wallet_id, &wallet_json) {
        add_log_command(&mut response, "error", &format!("Failed to open wallet session: {}", e.to_string()));
        post_rust_commands(response);
        return;
    }

    add_log_command(&mut response, "info", &format!("Wallet '{}' loaded. Checking for missed blocks...", wallet_id));

    // 3. Get wallet synced height (synchronous)
    let wallet_height = match wallet_session_get_synced_height(&wallet_id) {
        Ok(h) => h,
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to get wallet sync height: {:?}", e));
            post_rust_commands(response);
            return;
        }
    };

    // 4. Get chain tip height (asynchronous)
    let chain_tip_height = match get_tip_height_from_db().await {
        Ok(h) => h,
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to get tip height: {:?}", e));
            post_rust_commands(response);
            return;
        }
    };

    // 5. Scan missing blocks (asynchronous)
    if wallet_height < chain_tip_height {
        add_log_command(&mut response, "info", &format!("[WALLET] Scanning from height {} to {}...", wallet_height + 1, chain_tip_height));
        if let Err(e) = wallet_session_scan_range(&wallet_id, wallet_height + 1, chain_tip_height).await {
            add_log_command(&mut response, "error", &format!("Failed to scan range: {:?}", e));
            post_rust_commands(response);
            return;
        }
    } else {
        add_log_command(&mut response, "info", "[WALLET] Wallet is already fully synced.");
    }

    // 6. Persist updated wallet state (asynchronous)
    let persisted_json = match wallet_session_export(&wallet_id) {
        Ok(json) => json,
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to export wallet: {:?}", e));
            post_rust_commands(response);
            return;
        }
    };
    if let Err(e) = save_wallet_to_db(&wallet_id, &persisted_json).await {
        add_log_command(&mut response, "error", &format!("Failed to save wallet: {:?}", e));
        post_rust_commands(response);
        return;
    }

    // 7. Get final balance and address (synchronous)
    let balance = wallet_session_get_balance_internal(&wallet_id).unwrap_or(0);
    let address = wallet_session_get_address(&wallet_id).unwrap_or("Error".to_string());

    // 8. Add the final UI command
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::UiWalletLoaded(p2p::UiWalletLoaded {
            wallet_id: wallet_id.to_string(),
            balance: balance.to_string(),
            address: address,
        })),
    });

    // 9. Send the complete batch of commands back to JS
    post_rust_commands(response);
}

// --- ADD these new/modified helper functions to src/lib.rs ---

// This helper calls the JS bridge to load the wallet JSON
async fn load_wallet_json_from_db(wallet_id: &str) -> Result<Option<String>, JsValue> {
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = load_wallet_from_db)]
        fn load_wallet_raw(wallet_id: &str) -> js_sys::Promise;
    }
    
    let promise = load_wallet_raw(wallet_id);
    let result_js = wasm_bindgen_futures::JsFuture::from(promise).await?;
    
    if result_js.is_null() || result_js.is_undefined() {
        return Ok(None);
    }
    
    // The native_db.loadWallet function returns the JSON string directly
    result_js.as_string().ok_or_else(|| JsValue::from_str("DB returned non-string for wallet"))
        .map(Some)
}

// This helper calls the JS bridge to save the wallet JSON
async fn save_wallet_to_db(wallet_id: &str, wallet_json: &str) -> Result<(), JsValue> {
    #[wasm_bindgen]
    extern "C" {
        // Use a global name, just like the others
        #[wasm_bindgen(js_name = save_wallet_to_db)]
        fn save_wallet_raw(wallet_id: &str, wallet_json: &str) -> js_sys::Promise;
    }

    let promise = save_wallet_raw(wallet_id, wallet_json); // This now calls global `save_wallet_to_db`
    wasm_bindgen_futures::JsFuture::from(promise).await?;
    Ok(())
}

// This is the internal, synchronous version of wallet_session_get_address
fn wallet_session_get_address_internal(wallet_id: &str) -> Result<String, PluribitError> {
    let map = WALLET_SESSIONS.lock().map_err(|e| PluribitError::LockError(e.to_string()))?;
    let w = map.get(wallet_id).ok_or_else(|| PluribitError::StateError("Wallet not loaded".into()))?;
    let scan_pub_bytes = w.scan_pub.compress().to_bytes();
    crate::address::encode_stealth_address(&scan_pub_bytes)
        .map_err(|e| PluribitError::ValidationError(e.to_string()))
}

fn handle_get_balance_internal(response: &mut p2p::RustToJsCommandBatch, req: p2p::GetBalanceRequest) {
    // This is the function we already refactored
    match wallet_session_get_balance_internal(&req.wallet_id) {
        Ok(balance) => {
            response.commands.push(p2p::RustCommand {
                command: Some(p2p::rust_command::Command::UpdateUiBalance(p2p::UpdateUiBalance {
                    wallet_id: req.wallet_id,
                    balance_string: balance.to_string(),
                })),
            });
        }
        Err(e) => {
            add_log_command(response, "error", &format!("Failed to get balance: {}", e.to_string()));
        }
    }
}

async fn handle_create_transaction_internal(req: p2p::CreateTransactionRequest) {
    log("TODO: Implement handle_create_transaction_internal");
    // 1. Call wallet_session_send_to_stealth_internal
    // 2. If OK, get the transaction bytes
    // 3. Create a P2pMessage wrapper
    // 4. Create a RustToJs_CommandBatch
    // 5. Add a p2p_publish command to the batch
    // 6. Send the batch back to JS
}

// --- Node & Chain Helpers ---

async fn handle_toggle_miner_internal(req: p2p::ToggleMinerRequest) {
    log("TODO: Implement handle_toggle_miner_internal");
    // This is complex. It needs to:
    // 1. Lock a new `GlobalState.miner_state`
    // 2. If starting, get keys with `wallet_session_get_spend_privkey`
    // 3. Create a `StartMining` command for JS to spin up the mining *worker*
    // 4. If stopping, create a `StopMining` command
}

fn handle_get_status_internal(response: &mut p2p::RustToJsCommandBatch) {
    log("TODO: Implement handle_get_status_internal");
    // 1. Lock BLOCKCHAIN
    // 2. Get height, work, etc.
    // 3. Add LogMessage commands to response
}

async fn handle_get_supply_internal() {
    log("TODO: Implement handle_get_supply_internal");
    // 1. Call audit_total_supply
    // 2. Create RustToJs_CommandBatch
    // 3. Add UiTotalSupply command
    // 4. Send batch back to JS
}

fn handle_get_peers_internal(response: &mut p2p::RustToJsCommandBatch) {
    log("TODO: Implement handle_get_peers_internal");
    // 1. This state is in JS (workerState.p2p.getConnectedPeers)
    // 2. This command should be *removed* from Rust.
    // 3. The JS 'peers' command in main.js should just call worker.postMessage({ action: 'getPeers' })
    // 4. worker.js should handle it directly without calling Rust.
    add_log_command(response, "warn", "GetPeers logic should be handled in worker.js, not Rust.");
}

fn handle_connect_peer_internal(response: &mut p2p::RustToJsCommandBatch, req: p2p::ConnectPeerRequest) {
    log("TODO: Implement handle_connect_peer_internal");
    // 1. This is an I/O command.
    // 2. This command should be *removed* from Rust.
    // 3. The JS 'connect' command in main.js should just call worker.postMessage({ action: 'connectPeer', ... })
    // 4. worker.js should handle it directly without calling Rust.
    add_log_command(response, "warn", "ConnectPeer logic should be handled in worker.js, not Rust.");
}

// --- System Tick Helpers ---

async fn handle_sync_tick_internal(_req: p2p::SyncTickRequest) {
    log("TODO: Implement handle_sync_tick_internal");
    // This will replace the logic in worker.js `bootstrapSync`
    // 1. Lock STATE
    // 2. Check sync_state.status
    // 3. If "IDLE", change to "CONSENSUS"
    // 4. Create P2P message for TipRequest
    // 5. Create RustToJs_CommandBatch
    // 6. Add p2p_publish command
    // 7. Send batch back to JS
}

// --- L2 Helpers (Stubs) ---

async fn handle_swap_initiate_internal(req: p2p::SwapInitiateRequest) {
    log("TODO: Implement handle_swap_initiate_internal");
}

fn handle_swap_list_internal(response: &mut p2p::RustToJsCommandBatch) {
    log("TODO: Implement handle_swap_list_internal");
}

async fn handle_swap_respond_internal(req: p2p::SwapRespondRequest) {
    log("TODO: Implement handle_swap_respond_internal");
}

async fn handle_swap_claim_internal(req: p2p::SwapClaimRequest) {
    log("TODO: Implement handle_swap_claim_internal");
}

async fn handle_swap_refund_internal(req: p2p::SwapRefundRequest) {
    log("TODO: Implement handle_swap_refund_internal");
}

async fn handle_channel_open_internal(req: p2p::ChannelOpenRequest) {
    log("TODO: Implement handle_channel_open_internal");
}

fn handle_channel_list_internal(response: &mut p2p::RustToJsCommandBatch) {
    log("TODO: Implement handle_channel_list_internal");
}

async fn handle_channel_accept_internal(req: p2p::ChannelAcceptRequest) {
    log("TODO: Implement handle_channel_accept_internal");
}

async fn handle_channel_fund_internal(req: p2p::ChannelFundRequest) {
    log("TODO: Implement handle_channel_fund_internal");
}

async fn handle_channel_pay_internal(req: p2p::ChannelPayRequest) {
    log("TODO: Implement handle_channel_pay_internal");
}

async fn handle_channel_close_internal(req: p2p::ChannelCloseRequest) {
    log("TODO: Implement handle_channel_close_internal");
}




// --- START: Add async helpers for new bridge functions ---
async fn save_coinbase_index_to_db(commitment: &[u8], height: u64) -> Result<(), JsValue> {
    let hex = hex::encode(commitment);
    wasm_bindgen_futures::JsFuture::from(save_coinbase_index_raw(&hex, height)).await?;
    Ok(())
}

async fn delete_coinbase_index_from_db(commitment: &[u8]) -> Result<(), JsValue> {
    let hex = hex::encode(commitment);
    wasm_bindgen_futures::JsFuture::from(delete_coinbase_index_raw(&hex)).await?;
    Ok(())
}

async fn load_all_coinbase_indexes_from_db() -> Result<HashMap<Vec<u8>, u64>, JsValue> {
    let promise = load_all_coinbase_indexes_raw();
    let result_js = wasm_bindgen_futures::JsFuture::from(promise).await?;
    
    // Deserialize the Map<string, bigint> from JS
    let js_map: HashMap<String, WasmU64> = serde_wasm_bindgen::from_value(result_js)?;
    
    let mut rust_map = HashMap::new();
    for (hex_key, wasm_height) in js_map {
        let commitment_bytes = hex::decode(hex_key)
            .map_err(|e| JsValue::from_str(&format!("Invalid hex in coinbase index key: {}", e)))?;
        rust_map.insert(commitment_bytes, *wasm_height);
    }
    Ok(rust_map)
}

/// (Internal) Saves a block's filter to the DB via the JS bridge.
pub async fn save_block_filter_to_db(height: u64, filter: &Vec<BlockFilterEntry>) -> Result<(), JsValue> {
    // Serialize the filter to a JSON string
    let filter_json = serde_json::to_string(filter)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // Call the raw JS function and await its promise
    wasm_bindgen_futures::JsFuture::from(save_block_filter_raw(height, &filter_json)).await?;
    Ok(())
}

/// (Internal) Deletes a block's filter from the DB via the JS bridge.
pub async fn delete_block_filter_from_db(height: u64) -> Result<(), JsValue> {
    wasm_bindgen_futures::JsFuture::from(delete_block_filter_raw(height)).await?;
    Ok(())
}

#[wasm_bindgen]
pub fn wallet_check_filter(wallet_json: &str, filter_entries_json: &str) -> Result<bool, JsValue> {
    // 1. Load Wallet
    let wallet: Wallet = serde_json::from_str(wallet_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // 2. Load Filter Entries (reusing your existing struct from blockchain.rs [cite: 747])
    let entries: Vec<BlockFilterEntry> = serde_json::from_str(filter_entries_json)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // 3. Check View Tags (Fast Match)
    for entry in entries {
        if let Ok(compressed_point) = CompressedRistretto::from_slice(&entry.ephemeral_key) {
            if let Some(r_point) = compressed_point.decompress() {
                // Recalculate shared secret s = Hs(r * P_scan)
                let apr = (&r_point * &wallet.scan_priv).compress().to_bytes();
                let s_prime = stealth::hash_to_scalar(b"Stealth", &apr);
                let expected_view_tag = stealth::derive_view_tag(&s_prime);

                // Compare against the tag in the filter 
                // entry.view_tag is Vec<u8>, usually 1 byte
                if !entry.view_tag.is_empty() && entry.view_tag[0] == expected_view_tag {
                    return Ok(true); // Match found! Request full block.
                }
            }
        }
    }

    Ok(false)
}

/// (Public WASM Export) Loads a range of block filters from the DB.
/// Returns a JSValue (representing a JS object: { "height": "[...entries...]", ... })
#[wasm_bindgen]
pub async fn load_block_filter_range(start_height: u64, end_height: u64) -> Result<JsValue, JsValue> {
    let promise = load_block_filter_range_raw(start_height, end_height);
    let result_js = wasm_bindgen_futures::JsFuture::from(promise).await?;
    
    // The result from JS is already a serialized object/map.
    // We pass it directly back to the JS caller.
    Ok(result_js)
}

// helper
async fn save_block_with_hash(block: &Block) -> Result<(), JsValue> {
    let p2p_block = p2p::Block::from(block.clone());
    let block_bytes = p2p_block.encode_to_vec();
    let block_bytes_js = serde_wasm_bindgen::to_value(&block_bytes)?; // <-- Pass bytes
    wasm_bindgen_futures::JsFuture::from(save_block_with_hash_raw(block_bytes_js)).await?;
    Ok(())
}

async fn load_block_by_hash(hash: &str) -> Result<Option<Block>, JsValue> {
    let promise = load_block_by_hash_raw(hash);
    let result_js = wasm_bindgen_futures::JsFuture::from(promise).await?;
    if result_js.is_null() || result_js.is_undefined() {
        Ok(None)
    } else {
        // result_js is now a Uint8Array (JsValue)
        let block_bytes: Vec<u8> = serde_wasm_bindgen::from_value(result_js)?;

        // Decode bytes into p2p::Block (prost struct)
        let p2p_block = p2p::Block::decode(&block_bytes[..])
            .map_err(|e| JsValue::from_str(&format!("bad block proto: {e}")))?;

        let mut block: Block = Block::from(p2p_block);
        block.hash = block.compute_hash();
        Ok(Some(block))
    }
}

async fn save_reorg_marker(marker: &impl Serialize) -> Result<(), JsValue> {
    let marker_js = serde_wasm_bindgen::to_value(marker)?;
    wasm_bindgen_futures::JsFuture::from(save_reorg_marker_raw(marker_js)).await?;
    Ok(())
}

async fn clear_reorg_marker() -> Result<(), JsValue> {
    wasm_bindgen_futures::JsFuture::from(clear_reorg_marker_raw()).await?;
    Ok(())
}

async fn save_block_to_staging(block: &Block) -> Result<(), JsValue> {
    let p2p_block = p2p::Block::from(block.clone());
    let block_bytes = p2p_block.encode_to_vec();
    let block_bytes_js = serde_wasm_bindgen::to_value(&block_bytes)?; // <-- Pass bytes
    wasm_bindgen_futures::JsFuture::from(save_block_to_staging_raw(block_bytes_js)).await?;
    Ok(())
}

async fn commit_staged_reorg(blocks: &Vec<Block>, old_heights: &Vec<u64>, new_tip_height: u64, new_tip_hash: &str) -> Result<(), JsValue> {
    // Convert Vec<Block> to Vec<Vec<u8>>
    let blocks_bytes_vec: Vec<Vec<u8>> = blocks.iter().map(|b| {
        let p2p_block = p2p::Block::from(b.clone());
        p2p_block.encode_to_vec()
    }).collect();
    
    let blocks_bytes_js = serde_wasm_bindgen::to_value(&blocks_bytes_vec)?; // <-- Pass Vec<Vec<u8>>
    let old_heights_js = serde_wasm_bindgen::to_value(old_heights)?;
    let promise = commit_staged_reorg_raw(blocks_bytes_js, old_heights_js, new_tip_height, new_tip_hash);
    wasm_bindgen_futures::JsFuture::from(promise).await?;
    Ok(())
}


// Helper function to convert the raw JS Promise for saving a block
async fn save_block_to_db(block: Block) -> Result<(), JsValue> {
    // Convert to P2P struct
    let p2p_block = p2p::Block::from(block);
    // Encode to bytes
    let block_bytes = p2p_block.encode_to_vec();
    // Serialize the bytes to a JsValue (will become Uint8Array)
    let block_bytes_js = serde_wasm_bindgen::to_value(&block_bytes)?;
    
    let promise = save_block_to_db_raw(block_bytes_js); // <-- Pass bytes
    wasm_bindgen_futures::JsFuture::from(promise).await?;
    Ok(())
}

async fn save_reorg_marker_proto(marker: &p2p::ReorgMarker) -> Result<(), JsValue> {
    let marker_bytes = marker.encode_to_vec();
    // Convert the raw bytes to a hex string for safe storage in JS LevelDB
    let marker_hex = hex::encode(marker_bytes);
    let marker_js = JsValue::from_str(&marker_hex);
    wasm_bindgen_futures::JsFuture::from(save_reorg_marker_raw(marker_js)).await?;
    Ok(())
}

async fn save_total_work_to_db(work: u64) -> Result<(), JsValue> {
    let promise = save_total_work_to_db_raw(work);
    wasm_bindgen_futures::JsFuture::from(promise).await?;
    Ok(())
}

async fn get_total_work_from_db() -> Result<u64, JsValue> {
    let promise = get_total_work_from_db_raw();
    let result_js = wasm_bindgen_futures::JsFuture::from(promise).await?;

    // Use serde_wasm_bindgen to deserialize flexibly from String, Number, or BigInt
    let wasm_u64: WasmU64 = serde_wasm_bindgen::from_value(result_js)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize total_work: {}", e)))?; // Add error context

    Ok(*wasm_u64) // Dereference WasmU64 to get the inner u64 
}

async fn clear_all_utxos_from_db() -> Result<(), JsValue> {
    let promise = clear_all_utxos_raw();
    wasm_bindgen_futures::JsFuture::from(promise).await?;
    Ok(())
}

#[wasm_bindgen]
pub async fn force_reset_to_height(height: u64, hash: String) -> Result<(), JsValue> {
    log(&format!("[RECOVERY] Attempting force reset to height={}, hash={}", height, &hash[..12]));

    // --- 1. Load the target block from DB to ensure it exists and matches ---
    let target_block = load_block_from_db(height).await?
        .ok_or_else(|| JsValue::from_str(&format!("Target block {} not found in DB for reset", height)))?;

    if target_block.hash() != hash {
        return Err(JsValue::from_str(&format!(
            "Hash mismatch for target block {}. DB has {}, expected {}",
            height, target_block.hash(), hash
        )));
    }
    log("[RECOVERY] Target block verified in DB.");

    // --- 2. Clear existing in-memory state (acquire locks briefly) ---
    log("[RECOVERY] Clearing in-memory state...");
    { // Scope for locks
        let mut chain = BLOCKCHAIN.lock().map_err(|e| JsValue::from_str(&format!("Failed to lock BLOCKCHAIN for clear: {}", e)))?;
        *chain = blockchain::Blockchain::new(); // Reset to default (will be updated later)

        let mut utxo_set = blockchain::UTXO_SET.lock().map_err(|e| JsValue::from_str(&format!("Failed to lock UTXO_SET for clear: {}", e)))?;
        utxo_set.clear();

        let mut coinbase_index = blockchain::COINBASE_INDEX.lock().map_err(|e| JsValue::from_str(&format!("Failed to lock COINBASE_INDEX for clear: {}", e)))?;
        coinbase_index.clear();

        let mut tx_pool = TX_POOL.lock().map_err(|e| JsValue::from_str(&format!("Failed to lock TX_POOL for clear: {}", e)))?;
        tx_pool.pending.clear();
        tx_pool.fee_total = 0;

        // Clear side blocks cache
        SIDE_BLOCKS.lock().map_err(|e| JsValue::from_str(&format!("Failed to lock SIDE_BLOCKS for clear: {}", e)))?.clear();
        SIDE_BLOCKS_LRU.lock().map_err(|e| JsValue::from_str(&format!("Failed to lock SIDE_BLOCKS_LRU for clear: {}", e)))?.clear();

        // Clear recent UTXO cache (if you implement caching later)
        // RECENT_UTXO_CACHE.lock().map_err(|e| JsValue::from_str(&format!("Failed to lock RECENT_UTXO_CACHE for clear: {}", e)))?.clear();
        // UTXO_CACHE_LRU.lock().map_err(|e| JsValue::from_str(&format!("Failed to lock UTXO_CACHE_LRU for clear: {}", e)))?.clear();

    } // Locks released here
    log("[RECOVERY] In-memory state cleared.");

    // --- 3. Rebuild state up to the target height ---
    log(&format!("[RECOVERY] Rebuilding state up to height {}...", height));
    let mut calculated_total_work: u64 = 0; 

    // === ADDITION: Clear DB state before rebuilding ===
    clear_all_utxos_from_db().await?; 
    // We assume you will add a `clear_all_coinbase_indexes_from_db()` to worker.js
    // For now, we proceed, overwriting entries.
    log("[RECOVERY] Cleared old DB state.");


    for h in 0..=height {
        let block = load_block_from_db(h).await?
            .ok_or_else(|| JsValue::from_str(&format!("Missing block {} during state rebuild", h)))?;
        
        calculated_total_work = calculated_total_work.saturating_add(Blockchain::get_chain_work(&[block.clone()]));

        { // Scope for locks
            let mut utxo_set = blockchain::UTXO_SET.lock().map_err(|e| JsValue::from_str(&format!("Failed to lock UTXO_SET for rebuild height {}: {}", h, e)))?;
            let mut coinbase_index = blockchain::COINBASE_INDEX.lock().map_err(|e| JsValue::from_str(&format!("Failed to lock COINBASE_INDEX for rebuild height {}: {}", h, e)))?;

            for tx in &block.transactions {
                 for input in &tx.inputs {
                     utxo_set.remove(&input.commitment);
                     coinbase_index.remove(&input.commitment);
                     // === ADDITION: Persist DB change ===
                     delete_utxo_from_db(&input.commitment).await.ok();
                     delete_coinbase_index_from_db(&input.commitment).await.ok();
                 }
                 
                 let is_coinbase = tx.inputs.is_empty() && tx.total_fee() == 0; 
                 for output in &tx.outputs {
                     utxo_set.insert(output.commitment.clone(), output.clone());
                     // === ADDITION: Persist DB change ===
                     save_utxo_to_db(&output.commitment, output).await?;
                     
                     if is_coinbase {
                        coinbase_index.insert(output.commitment.clone(), h);
                        // === ADDITION: Persist DB change ===
                        save_coinbase_index_to_db(&output.commitment, h).await?;
                     }
                 }
            }
        } // Locks released for this block iteration
        if h % 100 == 0 || h == height { // Log progress periodically
             log(&format!("[RECOVERY] Rebuilt state up to height {}", h));
        }
    }
    log("[RECOVERY] State rebuild complete.");

     // --- 4. Update the main Blockchain struct state ---
     log("[RECOVERY] Finalizing BLOCKCHAIN state...");
     { // Scope for final lock
         let mut chain = BLOCKCHAIN.lock().map_err(|e| JsValue::from_str(&format!("Failed to lock BLOCKCHAIN for final update: {}", e)))?;
         *chain.current_height = *target_block.height;
         chain.tip_hash = target_block.hash(); // Use the hash from the verified target block
         chain.total_work = WasmU64::from(calculated_total_work); // Use the recalculated work
         chain.current_vrf_threshold = target_block.vrf_threshold;
         chain.current_vdf_iterations = target_block.vdf_iterations;

        log(&format!("[RECOVERY] BLOCKCHAIN state set: height={}, hash={}, work={}",
            chain.current_height, &chain.tip_hash[..12], chain.total_work));

     } // Lock released

    // --- 5. Optional: Persist recalculated work ---
    // It might be good practice to save the recalculated work back to the DB
    // in case the stored value was somehow corrupted during the failed reorg.
    if let Err(e) = save_total_work_to_db(calculated_total_work).await {
         log(&format!("[RECOVERY WARNING] Failed to save recalculated total work to DB: {:?}", e));
    }


    log(&format!("[RECOVERY] ✓ Force reset to height {} complete.", height));
    Ok(())
}
pub async fn save_utxo_to_db(commitment: &[u8], output: &TransactionOutput) -> Result<(), JsValue> {
    let hex = hex::encode(commitment);
    let output_js = serde_wasm_bindgen::to_value(output)?;
    wasm_bindgen_futures::JsFuture::from(save_utxo_raw(&hex, output_js)).await?;
    Ok(())
}

pub async fn load_utxo_from_db(commitment: &[u8]) -> Result<Option<TransactionOutput>, JsValue> {
    let hex = hex::encode(commitment);
    let result = wasm_bindgen_futures::JsFuture::from(load_utxo_raw(&hex)).await?;
    if result.is_null() || result.is_undefined() {
        Ok(None)
    } else {
        Ok(Some(serde_wasm_bindgen::from_value(result)?))
    }
}

pub async fn delete_utxo_from_db(commitment: &[u8]) -> Result<(), JsValue> {
    let hex = hex::encode(commitment);
    wasm_bindgen_futures::JsFuture::from(delete_utxo_raw(&hex)).await?;
    Ok(())
}


// Helper functions to convert the raw JS Promise into a Rust Future
// that yields a result we can use.
async fn load_block_from_db(height: u64) -> Result<Option<Block>, JsValue> {
    let promise = load_block_from_db_raw(height);
    let result_js = wasm_bindgen_futures::JsFuture::from(promise).await?;
    if result_js.is_null() || result_js.is_undefined() {
        Ok(None)
    } else {
        // result_js is now a Uint8Array (JsValue)
        let block_bytes: Vec<u8> = serde_wasm_bindgen::from_value(result_js)?; // <-- Deserializes Uint8Array to Vec<u8>

        // Decode bytes into p2p::Block (prost struct)
        let p2p_block = p2p::Block::decode(&block_bytes[..])
            .map_err(|e| JsValue::from_str(&format!("bad block proto: {e}")))?;

        // Convert p2p::Block to internal Block
        let mut block: Block = Block::from(p2p_block);
        block.hash = block.compute_hash();
        Ok(Some(block))
    }
}

async fn load_blocks_from_db(start: u64, end: u64) -> Result<Vec<Block>, JsValue> {
    let promise = load_blocks_from_db_raw(start, end);
    let result_js = wasm_bindgen_futures::JsFuture::from(promise).await?;
    if result_js.is_null() || result_js.is_undefined() {
        Ok(Vec::new())
    } else {
        // result_js is now a JS Array of Uint8Arrays
        let block_bytes_vec: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(result_js)?;

        let mut blocks = Vec::new();
        for block_bytes in block_bytes_vec {
            let p2p_block = p2p::Block::decode(&block_bytes[..])
                .map_err(|e| JsValue::from_str(&format!("bad block proto: {e}")))?;
            let mut block = Block::from(p2p_block);
            block.hash = block.compute_hash();
            blocks.push(block);
        }
        Ok(blocks)
    }
}

async fn get_tip_height_from_db() -> Result<u64, JsValue> {
    let promise = get_tip_height_from_db_raw();
    let result_js = wasm_bindgen_futures::JsFuture::from(promise).await?;
    
    // FIX: Use serde_wasm_bindgen to correctly deserialize the JS value (which could be a Number or a BigInt)
    // into your WasmU64 type, then convert it to a plain u64.
    let wasm_u64: WasmU64 = serde_wasm_bindgen::from_value(result_js)?;
    Ok(*wasm_u64) 
}

// Add these wasm_bindgen wrapper functions to your src/lib.rs file
// These expose atomic swaps and payment channels to the JavaScript client





// =============================================================================
// ATOMIC SWAP BINDINGS
// =============================================================================

/// Initiate an atomic swap (Alice's side)
/// 
/// # Parameters
/// - alice_secret_bytes: 32-byte secret key
/// - alice_amount: Amount Alice is trading (in PLB)
/// - bob_pubkey_bytes: Bob's public key (32 bytes)
/// - bob_amount: Amount Bob is trading (e.g., in satoshis)
/// - timeout_blocks: Number of blocks before timeout
///
/// # Returns
/// Serialized AtomicSwap object
#[wasm_bindgen]
pub fn atomic_swap_initiate(
    alice_secret_bytes: Vec<u8>,
    alice_amount: u64,
    bob_pubkey_bytes: Vec<u8>,
    bob_amount: u64,
    timeout_blocks: u64,
) -> Result<JsValue, JsValue> {
    if alice_secret_bytes.len() != 32 {
        return Err(JsValue::from_str("Alice secret must be 32 bytes"));
    }
    
    let mut alice_secret_arr = [0u8; 32];
    alice_secret_arr.copy_from_slice(&alice_secret_bytes);
    let alice_secret = Scalar::from_bytes_mod_order(alice_secret_arr);
    
    let swap = AtomicSwap::initiate(
        &alice_secret,
        alice_amount,
        bob_pubkey_bytes,
        bob_amount,
        timeout_blocks,
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    serde_wasm_bindgen::to_value(&swap).map_err(|e| e.into())
}

/// Bob responds to an atomic swap offer
///
/// # Parameters
/// - swap_json: Serialized AtomicSwap from initiate
/// - bob_secret_bytes: 32-byte secret key
/// - bob_btc_address: The P2WSH address of the HTLC
/// - bob_btc_txid: The transaction ID that funded the HTLC
/// - bob_btc_vout: The vout index of the HTLC
/// - bob_adaptor_sig_bytes: Bob's adaptor signature (if needed by protocol)
/// - bob_timeout_height: Bob's timeout block height
///
/// # Returns
/// Updated AtomicSwap object
#[wasm_bindgen]
pub fn atomic_swap_respond(
    swap_json: JsValue,
    bob_secret_bytes: Vec<u8>,
    bob_btc_address: String,      // FIX: Was bob_btc_commitment
    bob_btc_txid: String,         // FIX: Added
    bob_btc_vout: u32,            // FIX: Added
    bob_adaptor_sig_bytes: Vec<u8>, // FIX: Renamed from bob_adaptor_sig
    bob_timeout_height: u64,
) -> Result<JsValue, JsValue> {
    if bob_secret_bytes.len() != 32 {
        return Err(JsValue::from_str("Bob secret must be 32 bytes"));
    }
    
    let mut bob_secret_arr = [0u8; 32];
    bob_secret_arr.copy_from_slice(&bob_secret_bytes);
    let bob_secret = Scalar::from_bytes_mod_order(bob_secret_arr);
    
    let mut swap: AtomicSwap = serde_wasm_bindgen::from_value(swap_json)?;
    
    // FIX: Pass the correct arguments to the implementation [cite: 647]
    swap.respond(
        &bob_secret,
        bob_btc_address,
        bob_btc_txid,
        bob_btc_vout,
        bob_adaptor_sig_bytes,
        bob_timeout_height,
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    serde_wasm_bindgen::to_value(&swap).map_err(|e| e.into())
}

/// Alice creates an adaptor signature for the swap
///
/// # Parameters
/// - swap_json: Serialized AtomicSwap
/// - alice_secret_bytes: 32-byte secret key
///
/// # Returns
/// Updated AtomicSwap with adaptor signature
#[wasm_bindgen]
pub fn atomic_swap_alice_create_adaptor_sig(
    swap_json: JsValue,
    alice_secret_bytes: Vec<u8>,
) -> Result<JsValue, JsValue> {
    if alice_secret_bytes.len() != 32 {
        return Err(JsValue::from_str("Alice secret must be 32 bytes"));
    }
    
    let mut alice_secret_arr = [0u8; 32];
    alice_secret_arr.copy_from_slice(&alice_secret_bytes);
    let alice_secret = Scalar::from_bytes_mod_order(alice_secret_arr);
    
    let mut swap: AtomicSwap = serde_wasm_bindgen::from_value(swap_json)?;
    
    swap.alice_create_adaptor_signature(&alice_secret)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    serde_wasm_bindgen::to_value(&swap).map_err(|e| e.into())
}

/// Bob claims the swap (creates the claim transaction)
///
/// # Parameters
/// - swap_json: Serialized AtomicSwap
/// - bob_secret_bytes: Bob's secret key (32 bytes)
/// - adaptor_secret_bytes: The adaptor secret (32 bytes)
/// - bob_receive_address_bytes: Bob's receive address (32 bytes compressed Ristretto point)
///
/// # Returns
/// The claim transaction that Bob can broadcast
#[wasm_bindgen]
pub fn atomic_swap_bob_claim(
    swap_json: JsValue,
    bob_secret_bytes: Vec<u8>,
    adaptor_secret_bytes: Vec<u8>,
    bob_receive_address_bytes: Vec<u8>,
) -> Result<JsValue, JsValue> {
    if bob_secret_bytes.len() != 32 {
        return Err(JsValue::from_str("Bob secret must be 32 bytes"));
    }
    if adaptor_secret_bytes.len() != 32 {
        return Err(JsValue::from_str("Adaptor secret must be 32 bytes"));
    }
    if bob_receive_address_bytes.len() != 32 {
        return Err(JsValue::from_str("Receive address must be 32 bytes"));
    }
    
    let mut bob_secret_arr = [0u8; 32];
    bob_secret_arr.copy_from_slice(&bob_secret_bytes);
    let bob_secret = Scalar::from_bytes_mod_order(bob_secret_arr);
    
    let mut adaptor_secret_arr = [0u8; 32];
    adaptor_secret_arr.copy_from_slice(&adaptor_secret_bytes);
    let adaptor_secret = Scalar::from_bytes_mod_order(adaptor_secret_arr);
    
    let bob_receive = CompressedRistretto::from_slice(&bob_receive_address_bytes)
        .map_err(|_| JsValue::from_str("Invalid receive address"))?
        .decompress()
        .ok_or_else(|| JsValue::from_str("Failed to decompress receive address"))?;
    
    let swap: AtomicSwap = serde_wasm_bindgen::from_value(swap_json)?;
    
    let claim_tx = swap.bob_claim(&bob_secret, &adaptor_secret, &bob_receive)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    serde_wasm_bindgen::to_value(&claim_tx).map_err(|e| e.into())
}

/// Alice extracts the secret from Bob's completed signature
///
/// # Parameters
/// - swap_json: Serialized AtomicSwap
/// - bob_completed_signature_bytes: Bob's completed signature (32 bytes scalar)
///
/// # Returns
/// Updated AtomicSwap with extracted secret
#[wasm_bindgen]
pub fn atomic_swap_alice_extract_secret(
    swap_json: JsValue,
    bob_completed_signature_bytes: Vec<u8>,
) -> Result<JsValue, JsValue> {
    if bob_completed_signature_bytes.len() != 32 {
        return Err(JsValue::from_str("Signature must be 32 bytes"));
    }
    
    let mut sig_arr = [0u8; 32];
    sig_arr.copy_from_slice(&bob_completed_signature_bytes);
    let bob_sig = Scalar::from_bytes_mod_order(sig_arr);
    
    let mut swap: AtomicSwap = serde_wasm_bindgen::from_value(swap_json)?;
    
    let _secret = swap.alice_extract_and_claim(&bob_sig)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    serde_wasm_bindgen::to_value(&swap).map_err(|e| e.into())
}

/// Alice creates a refund transaction (if timeout reached)
///
/// # Parameters
/// - swap_json: Serialized AtomicSwap
/// - alice_secret_bytes: Alice's secret key (32 bytes)
/// - alice_receive_address_bytes: Alice's refund address (32 bytes compressed point)
/// - current_height: Current blockchain height
///
/// # Returns
/// Refund transaction
#[wasm_bindgen]
pub fn atomic_swap_refund_alice(
    swap_json: JsValue,
    alice_secret_bytes: Vec<u8>,
    alice_receive_address_bytes: Vec<u8>,
    current_height: u64,
) -> Result<JsValue, JsValue> {
    if alice_secret_bytes.len() != 32 {
        return Err(JsValue::from_str("Alice secret must be 32 bytes"));
    }
    if alice_receive_address_bytes.len() != 32 {
        return Err(JsValue::from_str("Receive address must be 32 bytes"));
    }
    
    let mut alice_secret_arr = [0u8; 32];
    alice_secret_arr.copy_from_slice(&alice_secret_bytes);
    let alice_secret = Scalar::from_bytes_mod_order(alice_secret_arr);
    
    let alice_receive = CompressedRistretto::from_slice(&alice_receive_address_bytes)
        .map_err(|_| JsValue::from_str("Invalid receive address"))?
        .decompress()
        .ok_or_else(|| JsValue::from_str("Failed to decompress receive address"))?;
    
    let swap: AtomicSwap = serde_wasm_bindgen::from_value(swap_json)?;
    
    let refund_tx = swap.refund_alice(&alice_secret, &alice_receive, current_height)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    serde_wasm_bindgen::to_value(&refund_tx).map_err(|e| e.into())
}

/// Get the current state of an atomic swap
#[wasm_bindgen]
pub fn atomic_swap_get_state(swap_json: JsValue) -> Result<String, JsValue> {
    let swap: AtomicSwap = serde_wasm_bindgen::from_value(swap_json)?;
    let state_str = match swap.state {
        SwapState::Negotiating => "Negotiating",
        SwapState::Committed => "Committed",
        SwapState::Claimed => "Claimed",
        SwapState::Refunded => "Refunded",
        SwapState::Completed => "Completed",
    };
    Ok(state_str.to_string())
}

// =============================================================================
// PAYMENT CHANNEL BINDINGS
// =============================================================================

/// Open a new payment channel (Party A initiates)
///
/// # Parameters
/// - party_a_secret_bytes: Party A's secret key (32 bytes)
/// - party_a_amount: Amount Party A contributes
/// - party_b_pubkey_bytes: Party B's public key (32 bytes compressed point)
/// - party_b_amount: Amount Party B contributes
/// - dispute_period_blocks: Dispute resolution period in blocks
///
/// # Returns
/// Serialized PaymentChannel object
#[wasm_bindgen]
pub fn payment_channel_open(
    party_a_secret_bytes: Vec<u8>,
    party_a_amount: u64,
    party_b_pubkey_bytes: Vec<u8>,
    party_b_amount: u64,
    dispute_period_blocks: u64,
) -> Result<JsValue, JsValue> {
    if party_a_secret_bytes.len() != 32 {
        return Err(JsValue::from_str("Party A secret must be 32 bytes"));
    }
    if party_b_pubkey_bytes.len() != 32 {
        return Err(JsValue::from_str("Party B pubkey must be 32 bytes"));
    }
    
    let mut party_a_secret_arr = [0u8; 32];
    party_a_secret_arr.copy_from_slice(&party_a_secret_bytes);
    let party_a_secret = Scalar::from_bytes_mod_order(party_a_secret_arr);
    
    let party_b_pubkey = CompressedRistretto::from_slice(&party_b_pubkey_bytes)
        .map_err(|_| JsValue::from_str("Invalid Party B pubkey"))?
        .decompress()
        .ok_or_else(|| JsValue::from_str("Failed to decompress Party B pubkey"))?;
    
    // FIX (Error 1): The method is `propose`, not `open` 
    // This also returns a proposal which must be sent to Party B.
    let (channel, proposal) = PaymentChannel::propose(
        &party_a_secret,
        party_a_amount,
        &party_b_pubkey,
        party_b_amount,
        dispute_period_blocks,
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // We must return both the channel state (for us) and the proposal (for them)
    #[derive(Serialize)]
    struct OpenResult {
        channel: PaymentChannel,
        proposal: crate::payment_channel::ChannelProposal,
    }

    let result = OpenResult { channel, proposal };
    serde_wasm_bindgen::to_value(&result).map_err(|e| e.into())
}

/// Fund a payment channel (create on-chain funding transaction)
///
/// NOTE: This binding is now from ONE party's perspective. It requires
/// arguments for the MuSig2 protocol.
///
/// # Parameters
/// - channel_json: Serialized PaymentChannel
/// - my_secret_bytes: This party's secret key (32 bytes)
/// - my_party_str: "A" or "B"
/// - my_nonce_bytes: This party's 32-byte secret nonce (r_i)
/// - my_nonce_point_bytes: This party's 32-byte public nonce (R_i = r_i*G)
/// - counterparty_nonce_point_bytes: The counterparty's 32-byte public nonce (R_j)
/// - counterparty_pubkey_bytes: The counterparty's 32-byte public key (P_j)
/// - my_funding_inputs_json: This party's inputs (serialized Vec<TransactionInput>)
/// - current_height: Current blockchain height
///
/// # Returns
/// Updated channel and MuSigKernelMetadata (which includes the partial signature)
#[wasm_bindgen]
pub fn payment_channel_fund(
    channel_json: JsValue,
    my_secret_bytes: Vec<u8>,
    my_party_str: String,
    my_nonce_bytes: Vec<u8>,
    my_nonce_point_bytes: Vec<u8>,
    counterparty_nonce_point_bytes: Vec<u8>,
    counterparty_pubkey_bytes: Vec<u8>,
    my_funding_inputs_json: JsValue,
    current_height: u64,
) -> Result<JsValue, JsValue> {
    // FIX (Error 2): This function was completely refactored to support MuSig2.

    // --- 1. Deserialize all arguments ---
    let mut channel: PaymentChannel = serde_wasm_bindgen::from_value(channel_json)?;
    let my_party = match my_party_str.as_str() {
        "A" => Party::A,
        "B" => Party::B,
        _ => return Err(JsValue::from_str("my_party must be 'A' or 'B'")),
    };

    let my_secret = Scalar::from_bytes_mod_order(my_secret_bytes.try_into().map_err(|_| JsValue::from_str("my_secret must be 32 bytes"))?);
    let my_nonce = Scalar::from_bytes_mod_order(my_nonce_bytes.try_into().map_err(|_| JsValue::from_str("my_nonce must be 32 bytes"))?);
    
    let my_nonce_point = CompressedRistretto::from_slice(&my_nonce_point_bytes)
        .map_err(|_| JsValue::from_str("Invalid my_nonce_point"))?
        .decompress().ok_or_else(|| JsValue::from_str("Failed to decompress my_nonce_point"))?;

    let counterparty_nonce_point = CompressedRistretto::from_slice(&counterparty_nonce_point_bytes)
        .map_err(|_| JsValue::from_str("Invalid counterparty_nonce_point"))?
        .decompress().ok_or_else(|| JsValue::from_str("Failed to decompress counterparty_nonce_point"))?;

    let counterparty_pubkey = CompressedRistretto::from_slice(&counterparty_pubkey_bytes)
        .map_err(|_| JsValue::from_str("Invalid counterparty_pubkey"))?
        .decompress().ok_or_else(|| JsValue::from_str("Failed to decompress counterparty_pubkey"))?;
    
    let my_funding_inputs = serde_wasm_bindgen::from_value(my_funding_inputs_json)?;

    // --- 2. Call the correct implementation method ---
    let (funding_tx, metadata) = channel.create_funding_transaction(
        &my_secret,
        my_party,
        &my_nonce,
        &my_nonce_point,
        &counterparty_nonce_point,
        &counterparty_pubkey,
        my_funding_inputs,
        current_height,
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    #[derive(serde::Serialize)]
    struct FundResult {
        channel: PaymentChannel,
        funding_tx: crate::transaction::Transaction,
        metadata: crate::payment_channel::MuSigKernelMetadata,
    }
    
    let result = FundResult {
        channel,
        funding_tx,
        metadata,
    };
    
    serde_wasm_bindgen::to_value(&result).map_err(|e| e.into())
}

/// Make a payment within the channel (off-chain!)
///
/// # Parameters
/// - channel_json: Serialized PaymentChannel
/// - sender_str: "A" or "B"
/// - sender_secret_bytes: Sender's 32-byte secret key
/// - amount: Amount to send
/// - current_height: Current blockchain height
///
/// # Returns
/// PaymentProposal object to send to the counterparty
#[wasm_bindgen]
pub fn payment_channel_make_payment(
    channel_json: JsValue,
    sender_str: String,
    sender_secret_bytes: Vec<u8>,
    amount: u64,
    current_height: u64,
) -> Result<JsValue, JsValue> {
    // FIX (Error 3): Renamed to `initiate_payment` and added missing args.
    let mut channel: PaymentChannel = serde_wasm_bindgen::from_value(channel_json)?;
    
    let party = match sender_str.as_str() {
        "A" => Party::A,
        "B" => Party::B,
        _ => return Err(JsValue::from_str("Sender must be 'A' or 'B'")),
    };

    let sender_secret = Scalar::from_bytes_mod_order(sender_secret_bytes.try_into().map_err(|_| JsValue::from_str("sender_secret must be 32 bytes"))?);

    let proposal = channel.initiate_payment(party, &sender_secret, amount, current_height)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // Return the proposal, not the channel
    serde_wasm_bindgen::to_value(&proposal).map_err(|e| e.into())
}

/// Close a channel cooperatively
///
/// # Parameters
/// - (See `payment_channel_fund` for MuSig2 parameter descriptions)
///
/// # Returns
/// (Settlement transaction with placeholder kernel, MuSig metadata)
#[wasm_bindgen]
pub fn payment_channel_close_cooperative(
    channel_json: JsValue,
    my_secret_bytes: Vec<u8>,
    my_party_str: String,
    my_nonce_bytes: Vec<u8>,
    my_nonce_point_bytes: Vec<u8>,
    counterparty_nonce_point_bytes: Vec<u8>,
    counterparty_pubkey_bytes: Vec<u8>,
    current_height: u64,
) -> Result<JsValue, JsValue> {
    // FIX (Error 4): This function was completely refactored to support MuSig2.
    
    // --- 1. Deserialize all arguments ---
    let mut channel: PaymentChannel = serde_wasm_bindgen::from_value(channel_json)?;
    let my_party = match my_party_str.as_str() {
        "A" => Party::A,
        "B" => Party::B,
        _ => return Err(JsValue::from_str("my_party must be 'A' or 'B'")),
    };

    let my_secret = Scalar::from_bytes_mod_order(my_secret_bytes.try_into().map_err(|_| JsValue::from_str("my_secret must be 32 bytes"))?);
    let my_nonce = Scalar::from_bytes_mod_order(my_nonce_bytes.try_into().map_err(|_| JsValue::from_str("my_nonce must be 32 bytes"))?);
    
    let my_nonce_point = CompressedRistretto::from_slice(&my_nonce_point_bytes)
        .map_err(|_| JsValue::from_str("Invalid my_nonce_point"))?
        .decompress().ok_or_else(|| JsValue::from_str("Failed to decompress my_nonce_point"))?;

    let counterparty_nonce_point = CompressedRistretto::from_slice(&counterparty_nonce_point_bytes)
        .map_err(|_| JsValue::from_str("Invalid counterparty_nonce_point"))?
        .decompress().ok_or_else(|| JsValue::from_str("Failed to decompress counterparty_nonce_point"))?;

    let counterparty_pubkey = CompressedRistretto::from_slice(&counterparty_pubkey_bytes)
        .map_err(|_| JsValue::from_str("Invalid counterparty_pubkey"))?
        .decompress().ok_or_else(|| JsValue::from_str("Failed to decompress counterparty_pubkey"))?;

    // --- 2. Call the correct implementation method ---
    let (settlement_tx, metadata) = channel.close_cooperative(
        &my_secret,
        my_party,
        &my_nonce,
        &my_nonce_point,
        &counterparty_nonce_point,
        &counterparty_pubkey,
        current_height,
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    #[derive(serde::Serialize)]
    struct CloseResult {
        channel: PaymentChannel,
        settlement_tx: crate::transaction::Transaction,
        metadata: crate::payment_channel::MuSigKernelMetadata,
    }
    
    let result = CloseResult {
        channel,
        settlement_tx,
        metadata,
    };
    
    serde_wasm_bindgen::to_value(&result).map_err(|e| e.into())
}

/// Close a channel unilaterally (if other party disappears)
///
/// # Parameters
/// - channel_json: Serialized PaymentChannel
/// - party_str: "A" or "B" - which party is closing
/// - my_kernel_blinding_bytes: 32-byte blinding scalar for *our* commitment tx
/// - current_height: Current blockchain height
///
/// # Returns
/// Commitment transaction to broadcast
#[wasm_bindgen]
pub fn payment_channel_close_unilateral(
    channel_json: JsValue,
    party_str: String,
    my_kernel_blinding_bytes: Vec<u8>,
    current_height: u64,
) -> Result<JsValue, JsValue> {
    // FIX (Error 5): Added missing arguments
    let mut channel: PaymentChannel = serde_wasm_bindgen::from_value(channel_json)?;
    
    let party_enum = match party_str.as_str() {
        "A" => Party::A,
        "B" => Party::B,
        _ => return Err(JsValue::from_str("Party must be 'A' or 'B'")),
    };

    let my_kernel_blinding = Scalar::from_bytes_mod_order(my_kernel_blinding_bytes.try_into().map_err(|_| JsValue::from_str("my_kernel_blinding must be 32 bytes"))?);
    
    let commitment_tx = channel.close_unilateral(
        party_enum,
        &my_kernel_blinding,
        current_height
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    serde_wasm_bindgen::to_value(&commitment_tx).map_err(|e| e.into())
}

/// Claim penalty if other party cheated (published old state)
///
/// # Parameters
/// - channel_json: Serialized PaymentChannel
/// - cheater_commitment_json: The `CommitmentState` they published
/// - my_secret_bytes: Our 32-byte secret key
/// - my_party_str: "A" or "B"
/// - current_height: Current blockchain height
///
/// # Returns
/// Penalty transaction that claims all funds
#[wasm_bindgen]
pub fn payment_channel_claim_penalty(
    channel_json: JsValue,
    cheater_commitment_json: JsValue,
    my_secret_bytes: Vec<u8>,
    my_party_str: String,
    current_height: u64,
) -> Result<JsValue, JsValue> {
    // FIX (Error 6): This binding had completely wrong arguments.
    
    let mut channel: PaymentChannel = serde_wasm_bindgen::from_value(channel_json)?;
    let cheater_commitment: crate::payment_channel::CommitmentState = serde_wasm_bindgen::from_value(cheater_commitment_json)?;
    
    let my_secret = Scalar::from_bytes_mod_order(my_secret_bytes.try_into().map_err(|_| JsValue::from_str("my_secret must be 32 bytes"))?);
    
    let my_party = match my_party_str.as_str() {
        "A" => Party::A,
        "B" => Party::B,
        _ => return Err(JsValue::from_str("my_party must be 'A' or 'B'")),
    };
    
    let penalty_tx = channel.claim_penalty(
        &cheater_commitment,
        &my_secret,
        my_party,
        current_height
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    serde_wasm_bindgen::to_value(&penalty_tx).map_err(|e| e.into())
}

/// Get channel statistics
///
/// # Parameters
/// - channel_json: Serialized PaymentChannel
///
/// # Returns
/// ChannelStats object with current state info
#[wasm_bindgen]
pub fn payment_channel_get_stats(channel_json: JsValue) -> Result<JsValue, JsValue> {
    let channel: PaymentChannel = serde_wasm_bindgen::from_value(channel_json)?;
    let stats = channel.stats();
    serde_wasm_bindgen::to_value(&stats).map_err(|e| e.into())
}

/// Get the current state of a payment channel
#[wasm_bindgen]
pub fn payment_channel_get_state(channel_json: JsValue) -> Result<String, JsValue> {
    let channel: PaymentChannel = serde_wasm_bindgen::from_value(channel_json)?;
    let state_str = match channel.state {
        // FIX: Renamed from Opening
        ChannelState::Negotiating => "Negotiating", 
        // FIX: Added missing variant
        ChannelState::ReadyToFund => "ReadyToFund", 
        // FIX: Destructure struct variant
        ChannelState::PendingOpen { .. } => "PendingOpen", 
        ChannelState::Open => "Open",
        ChannelState::Closing => "Closing",
        // FIX: Destructure struct variant
        ChannelState::Disputed { .. } => "Disputed", 
        // FIX: Destructure struct variant
        ChannelState::Closed { .. } => "Closed", 
    };
    Ok(state_str.to_string())
}

/// Get channel balances
///
/// # Parameters
/// - channel_json: Serialized PaymentChannel
///
/// # Returns
/// Object with party_a_balance and party_b_balance
#[wasm_bindgen]
pub fn payment_channel_get_balances(channel_json: JsValue) -> Result<JsValue, JsValue> {
    let channel: PaymentChannel = serde_wasm_bindgen::from_value(channel_json)?;
    
    #[derive(serde::Serialize)]
    struct Balances {
        party_a_balance: u64,
        party_b_balance: u64,
        total_capacity: u64,
        sequence_number: u64,
    }
    
    let balances = Balances {
        party_a_balance: channel.party_a_balance,
        party_b_balance: channel.party_b_balance,
        total_capacity: channel.total_capacity,
        sequence_number: channel.sequence_number,
    };
    
    serde_wasm_bindgen::to_value(&balances).map_err(|e| e.into())
}



// =========================
// Wallet session API (wasm)
// =========================
#[wasm_bindgen]
pub fn wallet_session_create(wallet_id: &str) -> Result<(), JsValue> {
    let mut map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    if map.contains_key(wallet_id) {
        return Err(JsValue::from_str("Wallet session already exists"));
    }
    let w = wallet::Wallet::new();
    map.insert(wallet_id.to_string(), w);
    Ok(())
}

/// Loads a wallet from JSON into the in-memory session map.
fn wallet_session_open_internal(wallet_id: &str, wallet_json: &str) -> Result<(), PluribitError> {
    let w: wallet::Wallet = serde_json::from_str(wallet_json)
        .map_err(|e| PluribitError::DeserializationError(format!("Wallet parse failed: {}", e)))?;

    let mut map = WALLET_SESSIONS.lock()
        .map_err(|e| PluribitError::LockError(e.to_string()))?;

    map.insert(wallet_id.to_string(), w);
    Ok(())
}
/// Export the current session wallet as JSON (for persistence).
#[wasm_bindgen]
pub fn wallet_session_export(wallet_id: &str) -> Result<String, JsValue> {
    let map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let w = map.get(wallet_id).ok_or_else(|| JsValue::from_str("Wallet not loaded"))?;
    serde_json::to_string(w).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn wallet_session_get_address(wallet_id: &str) -> Result<String, JsValue> {
    let map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let w = map.get(wallet_id).ok_or_else(|| JsValue::from_str("Wallet not loaded"))?;
    let scan_pub_bytes = w.scan_pub.compress().to_bytes();
    crate::address::encode_stealth_address(&scan_pub_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Scans a specific range of blocks (O(k)) 
#[wasm_bindgen]
pub async fn wallet_session_scan_range(
    wallet_id: &str, 
    start_height: u64, 
    end_height: u64
) -> Result<(), JsValue> {
    let mut map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let w = map.get_mut(wallet_id).ok_or_else(|| JsValue::from_str("Wallet not loaded"))?;

    if start_height > end_height {
        return Ok(()); // Nothing to scan
    }

    // Load only the blocks in the required range
    let blocks_to_scan = load_blocks_from_db(start_height, end_height).await?;

    for b in blocks_to_scan {
        w.scan_block(&b);
    }

    Ok(())
}

#[wasm_bindgen]
pub fn wallet_session_get_synced_height(wallet_id: &str) -> Result<u64, JsValue> {
    let map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let w = map.get(wallet_id).ok_or_else(|| JsValue::from_str("Wallet not loaded"))?;
    Ok(w.synced_height)
}

/// Scan the ENTIRE (O(n)) blockchain into this wallet session (Rust iterates blocks).
#[wasm_bindgen]
pub async fn wallet_session_scan_chain(wallet_id: &str) -> Result<(), JsValue> {
    let tip_height = get_tip_height_from_db().await?;
    // Call the O(k) function to scan the full range
    wallet_session_scan_range(wallet_id, 0, tip_height).await
}

#[wasm_bindgen]
pub async fn calculate_next_difficulty_params(current_height_js: JsValue) -> Result<JsValue, JsValue> {
    let current_height_wasm: WasmU64 = serde_wasm_bindgen::from_value(current_height_js)?;
    let current_height = *current_height_wasm;
    let next_height = current_height + 1;

    // Fetch current parameters as a fallback or if no adjustment is needed
    let (current_vrf_threshold, current_vdf_iterations) = {
        if let Some(tip_block) = load_block_from_db(current_height).await? {
            (tip_block.vrf_threshold, tip_block.vdf_iterations)
        } else if current_height == 0 {
            // Special case for genesis
            let genesis = Block::genesis();
            (genesis.vrf_threshold, genesis.vdf_iterations)
        } else {
            // Fallback if tip block is missing (should ideally not happen)
            log(&format!("[WARN] Could not load tip block {} to get current difficulty params", current_height));
            // FIX: Actually return an error instead of using potentially wrong defaults
            return Err(JsValue::from_str(&format!(
                "Cannot calculate difficulty: tip block at height {} not found", 
                current_height
            )));
        }
    };

    let (next_vrf_threshold, next_vdf_iterations) = if next_height > 0 && next_height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
        log(&format!("[DIFFICULTY] Calculating adjustment for upcoming block #{}", next_height));
        // Adjustment needed for the *next* block
        let start_height = next_height.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL); // Start of the interval just completed
        let end_height = next_height - 1; // End of the interval (the current tip)

        let start_block = load_block_from_db(start_height).await?
            .ok_or_else(|| JsValue::from_str(&format!("Missing start block {} for difficulty adjustment", start_height)))?;
        let end_block = load_block_from_db(end_height).await?
             .ok_or_else(|| JsValue::from_str(&format!("Missing end block {} for difficulty adjustment", end_height)))?; // Should be the current tip block

        // Use the pure calculation function
        Blockchain::calculate_next_difficulty(
            &end_block,
            &start_block,
            current_vrf_threshold, // Pass the params used during the interval
            current_vdf_iterations
        )
    } else {
        // No adjustment needed, use current parameters
        (current_vrf_threshold, current_vdf_iterations)
    };

    #[derive(Serialize)]
    struct NextParams {
        vrf_threshold: Vec<u8>,
        vdf_iterations: u64,
    }

    let params = NextParams {
        vrf_threshold: next_vrf_threshold.to_vec(),
        vdf_iterations: *next_vdf_iterations,
    };

    serde_wasm_bindgen::to_value(&params).map_err(|e| e.into())
}

/// Create a tx from a session wallet to a stealth address, update session state, return tx.
#[wasm_bindgen]
pub fn wallet_session_send_to_stealth(
    wallet_id: &str,
    amount: u64,
    fee: u64,
    stealth_address: &str,
) -> Result<JsValue, JsValue> {
    // 1) decode stealth address into scan pubkey, reuse existing constructor
    let scan_pub_bytes = crate::address::decode_stealth_address(stealth_address)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let scan_pub_hex = hex::encode(scan_pub_bytes);
    // 2) build tx using the session wallet
    let mut map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let w = map.get_mut(wallet_id).ok_or_else(|| JsValue::from_str("Wallet not loaded"))?;
    // Use existing helper by temporarily serializing (to avoid code duplication).
    let json = serde_json::to_string(w).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let result = wallet_create_transaction(&json, amount, fee, &scan_pub_hex)?;
    // Merge updated state back into session
    #[derive(serde::Deserialize)]
    struct TxResult { transaction: transaction::Transaction, updated_wallet_json: String }
    let parsed: TxResult = serde_wasm_bindgen::from_value(result.clone())
        .map_err(|e| JsValue::from_str(&format!("Bad tx result: {}", e)))?;
    let updated: wallet::Wallet = serde_json::from_str(&parsed.updated_wallet_json)
        .map_err(|e| JsValue::from_str(&format!("Updated wallet parse failed: {}", e)))?;
    *w = updated;
    Ok(result)
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
        let mut temp_block = Block::genesis();
        // A simple container
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
    match vdf_instance.compute_with_proof(input_bytes, WasmU64::from(iterations)) {
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
        .map_err(|e| JsValue::from_str(&format!("Invalid public key bytes: {}", e)))?;
        // Convert error to JsValue

    let recipient_scan_pub = compressed_point.decompress() // Now you can call decompress
        .ok_or_else(|| JsValue::from_str("Invalid recipient public key"))?;
    // 3. Call the internal create_transaction method on the Wallet struct.
    //    This method contains all the complex logic for coin selection and stealth output creation.
    let transaction = wallet.create_transaction(amount, fee, &recipient_scan_pub)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

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

// ADDED: New async initialization function that loads state from the DB.
#[wasm_bindgen]
pub async fn init_blockchain_from_db() -> Result<JsValue, JsValue> {
    let mut chain = BLOCKCHAIN.lock().unwrap();
    let tip_height = get_tip_height_from_db().await?;

    if tip_height > 0 {
        if let Some(tip_block) = load_block_from_db(tip_height).await? {
            // Restore chain state from the tip block in the DB.
            *chain.current_height = *tip_block.height;
            chain.tip_hash = tip_block.hash();
            chain.total_work = WasmU64::from(get_total_work_from_db().await?);
            chain.current_vrf_threshold = tip_block.vrf_threshold;
            chain.current_vdf_iterations = tip_block.vdf_iterations;
             log(&format!("[RUST] Restored blockchain from DB to height {}", tip_height));
        } else {
             return Err(JsValue::from_str("DB tip height is > 0 but tip block could not be loaded."));
        }
    } else {
        // If the DB is empty (height 0), initialize with a fresh genesis state.
        *chain = Blockchain::new();
        let genesis = Block::genesis();
        save_block_to_db(genesis).await?; 
        log("[RUST] Initialized new blockchain with genesis block.");
    }
    
    // --- O(U) State Loading ---
    
    // 1. Clear all in-memory state
    { 
        blockchain::UTXO_SET.lock().unwrap().clear();
        blockchain::COINBASE_INDEX.lock().unwrap().clear();
        let mut tx_pool = TX_POOL.lock().unwrap();
        tx_pool.pending.clear();
        tx_pool.fee_total = 0;
    }
    
    // 2. Load UTXO_SET from DB (using existing JS bridge function)
    let utxo_map_js = wasm_bindgen_futures::JsFuture::from(load_all_utxos_raw()).await?;
    let utxo_map_native: HashMap<String, TransactionOutput> = serde_wasm_bindgen::from_value(utxo_map_js)?;
    
    { // Scope for lock
        let mut utxo_set = blockchain::UTXO_SET.lock().unwrap();
        for (hex_key, output) in utxo_map_native {
             let commitment_bytes = hex::decode(hex_key)
                .map_err(|e| JsValue::from_str(&format!("Invalid hex in UTXO key: {}", e)))?;
            utxo_set.insert(commitment_bytes, output);
        }
        log(&format!("[RUST] Rebuilt UTXO set from DB, size: {}", utxo_set.len()));
    }
    
    // 3. Load COINBASE_INDEX from DB (using new JS bridge function)
    let coinbase_map_native = load_all_coinbase_indexes_from_db().await?;
    { // Scope for lock
        let mut coinbase_index = blockchain::COINBASE_INDEX.lock().unwrap();
        *coinbase_index = coinbase_map_native;
        log(&format!("[RUST] Rebuilt Coinbase Index from DB, size: {}", coinbase_index.len()));
    }
    // --- End O(U) State Loading ---

    serde_wasm_bindgen::to_value(&*chain).map_err(|e| e.into())
}


// ---- Results returned to JS -----------------------------------------------------
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum IngestResult {
    AcceptedAndExtended,
    StoredOnSide { tip_hash: String, height: u64 },
    NeedParent { hash: String, reason: String },
    Invalid { reason: String },
}

struct DifficultyParams {
    vrf_threshold: [u8; 32],
    vdf_iterations: u64,
}

enum ValidationDecision {
    ExtendCanonical { 
        expected_params: DifficultyParams,
    },
    StoreSideBlock { 
        tip_hash: String,
        height: u64,
    },
    RequestParent { 
        hash: String,
    },
    Reject { 
        reason: String,
    },
}

#[derive(Serialize, Deserialize)]
pub struct ReorgPlan {
    pub detach: Vec<String>,       // hashes to roll back (old canonical)
    pub attach: Vec<String>,       // hashes to apply (forward order)
    pub new_tip_hash: String,
    pub new_height: u64,
    pub requests: Vec<String>,     // missing parent hashes we still need
}

fn mempool_hygiene_after_block(block: &Block) {
    // [drop mined txs, drop spent-input txs, recompute fee_total]
    // (Source: your current add_block_to_chain)  //
    // L11-L29 from concatenated_output.txt
    let mut pool = TX_POOL.lock().unwrap();
    let mined_excesses: HashSet<Vec<u8>> = block.transactions.iter()
        .flat_map(|t| t.kernels.iter().map(|k| k.excess.clone()))
        .collect();
    pool.pending.retain(|t| !t.kernels.iter().any(|k| mined_excesses.contains(&k.excess)));

    let utxos = blockchain::UTXO_SET.lock().unwrap();
    pool.pending.retain(|t| t.inputs.iter().all(|inp| utxos.contains_key(&inp.commitment)));
    pool.fee_total = pool.pending.iter().map(|t| t.total_fee()).sum();
}

fn have_block(hash: &str) -> bool {
    let (tip_hash, _) = tip_hash_and_height();
    if tip_hash == hash { return true; } // Quick check for tip
    let side = SIDE_BLOCKS.lock().unwrap();
    side.contains_key(hash)
}


fn store_side_block(hash: String, block: Block) {
    let mut blocks = SIDE_BLOCKS.lock().unwrap();
    let mut lru = SIDE_BLOCKS_LRU.lock().unwrap();

    // RATIONALE: If at capacity, remove least recently used block
    // This is now just a cache - the DB is the source of truth
    if blocks.len() >= MAX_SIDE_BLOCKS && !blocks.contains_key(&hash) {
        if let Some(oldest) = lru.pop_front() {
            blocks.remove(&oldest);
            log(&format!("[CACHE] Evicted old side block: {}", &oldest[..8]));
        }
    }

    if !blocks.contains_key(&hash) {
        blocks.insert(hash.clone(), block.clone());
        lru.push_back(hash.clone());
        
        // Save to DB asynchronously - fire and forget
        let block_clone = block.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = save_block_with_hash(&block_clone).await {
                log(&format!("[ERROR] Failed to save side block to DB: {:?}", e));
            }
        });
    }
}

async fn get_block_any_async(hash: &str) -> Result<Option<Block>, JsValue> {
    // Check memory cache first
    if let Some(block) = SIDE_BLOCKS.lock().unwrap().get(hash).cloned() {
        return Ok(Some(block));
    }
    
    // Not in cache? Check the database
    load_block_by_hash(hash).await
}

// Keep the sync version for compatibility but it only checks memory
fn get_block_any(hash: &str) -> Option<Block> {
    SIDE_BLOCKS.lock().unwrap().get(hash).cloned()
}

 fn tip_hash_and_height() -> (String, u64) {
     let chain = BLOCKCHAIN.lock().unwrap();
    (chain.tip_hash.clone(), *chain.current_height)
 }



/// Pure validation logic - no side effects, no async, no mutations
fn validate_block_for_ingestion(
    block: &Block,
    current_tip_hash: &str,
    current_tip_height: u64,
) -> Result<ValidationDecision, String> {
    let block_hash = block.hash();
    let block_height = *block.height;

    // 1. Genesis validation
    if block_height == 0 {
        if block_hash != crate::constants::CANONICAL_GENESIS_HASH {
            return Ok(ValidationDecision::Reject {
                reason: format!("Invalid genesis hash. Expected {}, got {}",
                    crate::constants::CANONICAL_GENESIS_HASH, block_hash)
            });
        }
    }

    // 2. Timestamp validation
    let now_ms = js_sys::Date::now() as u64;
    if *block.timestamp > now_ms + crate::constants::MAX_FUTURE_DRIFT_MS {
        return Ok(ValidationDecision::Reject {
            reason: format!("Block timestamp {} is too far in the future", *block.timestamp)
        });
    }

    // 3. Check if block extends canonical tip (fast path)
    if block_height == current_tip_height + 1 && block.prev_hash == current_tip_hash {
        // Calculate expected difficulty parameters
        let (expected_vrf_threshold, expected_vdf_iterations) = {
            let chain = BLOCKCHAIN.lock().unwrap();
            
            if block_height > 0 && block_height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
                // Need adjustment - will be calculated async in apply phase
                (chain.current_vrf_threshold, chain.current_vdf_iterations)
            } else {
                (chain.current_vrf_threshold, chain.current_vdf_iterations)
            }
        };
        
        return Ok(ValidationDecision::ExtendCanonical {
            expected_params: DifficultyParams {
                vrf_threshold: expected_vrf_threshold,
                vdf_iterations: *expected_vdf_iterations,
            }
        });
    }

    // 4. Not extending tip - it's either a side block or orphan
    // We need async DB checks for this, so return a decision that requires lookup
    Ok(ValidationDecision::StoreSideBlock {
        tip_hash: block_hash,
        height: block_height,
    })
}

/// Async validation for side blocks/orphans (requires DB lookups)
async fn validate_side_or_orphan(
    block: &Block,
) -> Result<ValidationDecision, JsValue> {
    let block_hash = block.hash();
    let block_height = *block.height;

    // Check if already canonical
    if let Some(db_block_at_height) = load_block_from_db(block_height).await? {
        if db_block_at_height.hash() == block_hash {
            return Ok(ValidationDecision::Reject {
                reason: "Duplicate canonical block".to_string()
            });
        } else {
            return Ok(ValidationDecision::StoreSideBlock {
                tip_hash: block_hash,
                height: block_height,
            });
        }
    }

    // Check if already in side cache
    if SIDE_BLOCKS.lock().unwrap().contains_key(&block_hash) {
        return Ok(ValidationDecision::StoreSideBlock {
            tip_hash: block_hash,
            height: block_height,
        });
    }

    // Check if parent exists
    let (tip_h, _) = tip_hash_and_height();
    let parent_exists = if block.prev_hash == tip_h {
        true
    } else if SIDE_BLOCKS.lock().unwrap().contains_key(&block.prev_hash) {
        true
    } else {
        load_block_by_hash(&block.prev_hash).await?.is_some()
    };

    if parent_exists {
        Ok(ValidationDecision::StoreSideBlock {
            tip_hash: block_hash,
            height: block_height,
        })
    } else {
        Ok(ValidationDecision::RequestParent {
            hash: block.prev_hash.clone(),
        })
    }
}

/// Main entry point - now a thin coordinator
/// Unified entrypoint for all incoming blocks from the network.
/// - If parent missing -> store on side + ask JS to fetch the parent.
/// - Else -> valid side block; JS may ask for reorg via plan_reorg_for_tip.
#[wasm_bindgen(js_name = "ingest_block_bytes")]
pub async fn ingest_block_bytes(block_bytes: Vec<u8>) -> Result<JsValue, JsValue> {
    
    // 1. Decode and compute hash
    let p2p_block = p2p::Block::decode(&block_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("bad block proto: {e}")))?;
    let mut block: Block = Block::from(p2p_block);
    block.hash = block.compute_hash();

    // 2. Fast validation (synchronous, no DB)
    let (tip_hash, tip_height) = tip_hash_and_height();
    let decision = validate_block_for_ingestion(&block, &tip_hash, tip_height)
        .map_err(|e| JsValue::from_str(&e))?;

    // 3. Handle decision
    match decision {
        ValidationDecision::ExtendCanonical { expected_params } => {
            // Apply block to chain
            {
                let mut chain = BLOCKCHAIN.lock().unwrap();

                // Re-calculate difficulty if needed
                let (vrf_threshold, vdf_iterations) = if *block.height > 0 
                    && *block.height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 
                {
                    let start_height = block.height.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL);
                    let end_height = *block.height - 1;

                    let start_block = load_block_from_db(start_height).await?
                        .ok_or_else(|| JsValue::from_str(&format!("Missing start block {}", start_height)))?;
                    let end_block = load_block_from_db(end_height).await?
                        .ok_or_else(|| JsValue::from_str(&format!("Missing end block {}", end_height)))?;

                    let params_at_interval_end = (end_block.vrf_threshold, end_block.vdf_iterations);
                    Blockchain::calculate_next_difficulty(
                        &end_block,
                        &start_block,
                        params_at_interval_end.0,
                        params_at_interval_end.1
                    )
                } else {
                    (expected_params.vrf_threshold, WasmU64::from(expected_params.vdf_iterations))
                };

                // MTP check
                if *block.height > constants::MTP_WINDOW as u64 {
                    let mut timestamps = Vec::new();
                    for i in (*block.height - constants::MTP_WINDOW as u64)..*block.height {
                        if let Some(b) = load_block_from_db(i).await? {
                            timestamps.push(b.timestamp);
                        }
                    }
                    timestamps.sort_unstable();
                    let mtp = timestamps[timestamps.len() / 2];
                    if *block.timestamp < *mtp {
                        let res = IngestResult::Invalid { reason: "Timestamp < MTP".to_string() };
                        return serde_wasm_bindgen::to_value(&res).map_err(|e| e.into());
                    }
                }

                chain.add_block(block.clone(), vrf_threshold, vdf_iterations).await
                    .map_err(|e| JsValue::from_str(&format!("Failed to add block: {e}")))?;
                
                block.total_work = chain.total_work;
                chain.current_vrf_threshold = vrf_threshold;
                chain.current_vdf_iterations = vdf_iterations;
            }

            save_block_to_db(block.clone()).await?;
            save_total_work_to_db(*BLOCKCHAIN.lock().unwrap().total_work).await?;
            mempool_hygiene_after_block(&block);

            let res = IngestResult::AcceptedAndExtended;
            serde_wasm_bindgen::to_value(&res).map_err(|e| e.into())
        }
        
        ValidationDecision::StoreSideBlock { tip_hash, height } => {
            // Need async validation
            let async_decision = validate_side_or_orphan(&block).await?;
            
            match async_decision {
                ValidationDecision::StoreSideBlock { tip_hash, height } => {
                    store_side_block(block.hash(), block.clone());
                    let res = IngestResult::StoredOnSide { tip_hash, height };
                    serde_wasm_bindgen::to_value(&res).map_err(|e| e.into())
                }
                ValidationDecision::RequestParent { hash } => {
                    store_side_block(block.hash(), block.clone());
                    let res = IngestResult::NeedParent {
                        hash,
                        reason: "Parent block not found".to_string(),
                    };
                    serde_wasm_bindgen::to_value(&res).map_err(|e| e.into())
                }
                ValidationDecision::Reject { reason } => {
                    let res = IngestResult::Invalid { reason };
                    serde_wasm_bindgen::to_value(&res).map_err(|e| e.into())
                }
                _ => unreachable!(),
            }
        }
        
        ValidationDecision::RequestParent { hash } => {
            store_side_block(block.hash(), block.clone());
            let res = IngestResult::NeedParent {
                hash,
                reason: "Parent block not found".to_string(),
            };
            serde_wasm_bindgen::to_value(&res).map_err(|e| e.into())
        }
        
        ValidationDecision::Reject { reason } => {
            let res = IngestResult::Invalid { reason };
            serde_wasm_bindgen::to_value(&res).map_err(|e| e.into())
        }
    }
}


#[wasm_bindgen]
pub fn get_side_blocks_info() -> Result<JsValue, JsValue> {
    let side = SIDE_BLOCKS.lock().unwrap();
    
    #[derive(Serialize)]
    struct SideBlockInfo {
        hash: String,
        height: u64,
    }
    
    let info: Vec<SideBlockInfo> = side.iter()
        .map(|(hash, block)| SideBlockInfo {
            hash: hash.clone(),
            height: *block.height,
        })
        .collect();
    
    serde_wasm_bindgen::to_value(&info).map_err(|e| e.into())
}

/// Recursively calculates the GHOST weight for a given block hash.
/// RATIONALE: This is the core of the GHOST protocol. The "weight" is not a simple
/// block count but the sum of the cumulative proof-of-work of a block and all of
/// its descendants. This ensures that the protocol selects the chain with the most
/// total computational effort behind it, providing security against selfish mining
/// without regressing to a simple (and insecure) block-counting scheme.
fn calculate_ghost_weight(
    block_hash: &str,
    block_map: &HashMap<String, Block>,
    children_map: &HashMap<String, Vec<String>>,
    memo: &mut HashMap<String, u64>,
) -> u64 {
    // RATIONALE (Performance): Use memoization to avoid re-calculating the weight
    // of the same sub-trees, making the process efficient and DoS-resistant.
    if let Some(&weight) = memo.get(block_hash) {
        return weight;
    }

    // The weight of a block is its own work plus the weight of all its children's subtrees.
    let self_work = match block_map.get(block_hash) {
        Some(b) => Blockchain::get_chain_work(&[b.clone()]),
        None => return 0, // Should not happen if block_map is complete.
    };

    let mut total_weight = self_work;
    if let Some(children) = children_map.get(block_hash) {
        for child_hash in children {
            total_weight = total_weight.saturating_add(calculate_ghost_weight(
                child_hash,
                block_map,
                children_map,
                memo,
            ));
        }
    }

    memo.insert(block_hash.to_string(), total_weight);
    total_weight
}

/// Create a deterministic reorg plan from a candidate tip.
#[wasm_bindgen]
pub async fn plan_reorg_for_tip(tip_hash: String) -> Result<JsValue, JsValue> {
    let (canon_tip_hash, canon_tip_height) = tip_hash_and_height();

    // RATIONALE (Defensive): Early exit if the candidate is already the canonical tip.
    if tip_hash == canon_tip_hash {
        let plan = ReorgPlan {
            detach: vec![], attach: vec![], new_tip_hash: canon_tip_hash, new_height: canon_tip_height, requests: vec![],
        };
        return serde_wasm_bindgen::to_value(&plan).map_err(|e| e.into());
    }

    // Check if we have the candidate tip block at all
    let have_candidate = match get_block_any(&tip_hash) {
        Some(_) => true,
        None => {
            match load_block_by_hash(&tip_hash).await? {
                Some(_) => true,
                None => false,
            }
        }
    };
    if !have_candidate {
        // RATIONALE (Defensive): We must have the candidate to evaluate its work. If not, request it.
        log(&format!("[REORG] Don't have candidate tip {}. Requesting for work evaluation.", &tip_hash[..12]));
        let plan = ReorgPlan {
            detach: vec![],
            attach: vec![],
            new_tip_hash: canon_tip_hash,
            new_height: canon_tip_height,
            requests: vec![tip_hash],
        };
        return serde_wasm_bindgen::to_value(&plan).map_err(|e| e.into());
    }

    let mut canon_history: HashMap<u64, String> = HashMap::new();
    let mut missing_blocks: Vec<String> = Vec::new();
    
    // Load the canonical tip block
    let tip_block_from_db = match load_block_from_db(canon_tip_height).await? {
        Some(block) => block,
        None => {
            // If we can't even load the tip, request it and abort
            log(&format!("[REORG] Cannot load canonical tip at height {}", canon_tip_height));
            let plan = ReorgPlan {
                detach: vec![],
                attach: vec![],
                new_tip_hash: canon_tip_hash.clone(),
                new_height: canon_tip_height,
                requests: vec![canon_tip_hash], // Request the tip itself
            };
            return serde_wasm_bindgen::to_value(&plan).map_err(|e| e.into());
        }
    };

    canon_history.insert(*tip_block_from_db.height, tip_block_from_db.hash());
    let mut current_hash = tip_block_from_db.prev_hash;
    let mut current_expected_height = canon_tip_height - 1;

    // Walk backwards from the tip
    while current_expected_height > 0 {
        match load_block_from_db(current_expected_height).await? {
            Some(block) => {
                if block.hash() == current_hash {
                    // Good, this block matches expectations
                    canon_history.insert(current_expected_height, current_hash.clone());
                    current_hash = block.prev_hash;
                    current_expected_height -= 1;
                } else {
                    // We have a block but it's not the one we expected
                    log(&format!("[REORG] Block mismatch at height {}: expected {} but found {}", 
                        current_expected_height, current_hash, block.hash()));
                    missing_blocks.push(current_hash.clone());
                    break; // Can't continue without the right block
                }
            }
            None => {
                // Missing block entirely
                log(&format!("[REORG] Missing block at height {}, hash {}", 
                    current_expected_height, current_hash));
                missing_blocks.push(current_hash.clone());
                break; // Can't continue without this block
            }
        }
    }
    
    // Handle genesis special case
    if current_expected_height == 0 {
        if let Some(genesis) = load_block_from_db(0).await? {
            canon_history.insert(0, genesis.hash());
        }
    }

    // If we found missing blocks, request them before continuing
    if !missing_blocks.is_empty() {
        log(&format!("[REORG] Cannot build complete canonical history. Missing {} blocks", missing_blocks.len()));
        let plan = ReorgPlan {
            detach: vec![],
            attach: vec![],
            new_tip_hash: canon_tip_hash,
            new_height: canon_tip_height,
            requests: missing_blocks,
        };
        return serde_wasm_bindgen::to_value(&plan).map_err(|e| e.into());
    }

    let mut fork_path: Vec<Block> = Vec::new();
    let mut missing_parents: Vec<String> = Vec::new();
    let mut common_height: Option<u64> = None;
    // RATIONALE: We must be able to find the starting block for the fork from either the
    // side-chain cache OR the canonical database (in the case of a reorg from genesis).
    let mut current_fork_block = match get_block_any(&tip_hash) {
        Some(b) => b,
        None => {
            // Check database by hash
            match load_block_by_hash(&tip_hash).await? {
                Some(b) => b,
                None => {
                    // Last resort: try by height
                    load_block_from_db(canon_tip_height + 1).await?
                        .ok_or_else(|| JsValue::from_str("Candidate tip not found in cache or DB"))?
                }
            }
        }
    };

    let mut iterations = 0;
    loop {
        iterations += 1;
        if iterations > MAX_REORG_DEPTH {
            log(&format!("[REORG] Rejecting reorg deeper than {} blocks", MAX_REORG_DEPTH));
            return Err(JsValue::from_str("Reorg depth exceeds maximum allowed"));
        }

        // CRITICAL FIX: Add block to fork_path BEFORE checking for common ancestor
        // This ensures fork_path always contains at least the tip block when we proceed
        let found_common_ancestor = if let Some(canon_hash) = canon_history.get(&*current_fork_block.height) {
            if canon_hash == &current_fork_block.hash() {
                common_height = Some(*current_fork_block.height);
                true  // Found common ancestor
            } else {
                false  // Different hash at this height
            }
        } else {
            false  // Height not in canonical history
        };

        // Push the current block BEFORE breaking
        if !found_common_ancestor {
            fork_path.push(current_fork_block.clone());
        }

        // Break after we've added the block (if appropriate)
        if found_common_ancestor {
            break;
        }

        if current_fork_block.height == 0 {
            break;
        }

        let parent_hash = current_fork_block.prev_hash.clone();
        // RATIONALE: When building the fork path, we must check both the side-chain cache
        // AND the database to find parent blocks.
        if let Some(parent_block) = get_block_any(&parent_hash) {
            current_fork_block = parent_block;
        } else if let Some(parent_block_from_db) = load_block_by_hash(&parent_hash).await? {
            current_fork_block = parent_block_from_db;
            
        } else if let Some(parent_block_from_db) = load_block_from_db(current_fork_block.height - 1).await? {
            if parent_block_from_db.hash() == parent_hash {
                current_fork_block = parent_block_from_db;
            } else {
                missing_parents.push(parent_hash);
                if missing_parents.len() > 10 {
                    log("[REORG] Too many missing parents in fork, aborting plan");
                    return Err(JsValue::from_str("Too many missing blocks in fork chain"));
                }
                break;
            }
        } else {
            missing_parents.push(parent_hash);
            if missing_parents.len() > 10 {
                log("[REORG] Too many missing parents in fork, aborting plan");
                return Err(JsValue::from_str("Too many missing blocks in fork chain"));
            }
            break;
        }
    }
    
    if !missing_parents.is_empty() {
        let plan = ReorgPlan {
            detach: vec![],
            attach: vec![],
            new_tip_hash: canon_tip_hash,
            new_height: canon_tip_height,
            requests: missing_parents,
        };
        return serde_wasm_bindgen::to_value(&plan).map_err(|e| e.into());
    }

    // After the loop ends, if we still haven't found a common ancestor
    // and we're at genesis, do one final check
    if common_height.is_none() && !fork_path.is_empty() {
        if let Some(last_fork_block) = fork_path.last() {
            if last_fork_block.height == 0 {
                if let Some(genesis_hash) = canon_history.get(&0) {
                    if genesis_hash == &last_fork_block.hash() {
                        common_height = Some(0);
                    }
                }
            }
        }
    }

    let ancestor_h = match common_height {
        Some(h) => h,
        None => {
            log(&format!("[REORG] Could not find common ancestor for fork {}", &tip_hash[..12]));
            log(&format!("[REORG] Fork path length: {}, Canon history size: {}", 
                fork_path.len(), canon_history.len()));
            
            // Check if fork path is empty - this shouldn't happen
            if fork_path.is_empty() {
                log("[REORG] Fork path is empty, aborting reorg");
                let plan = ReorgPlan {
                    detach: vec![],
                    attach: vec![],
                    new_tip_hash: canon_tip_hash,
                    new_height: canon_tip_height,
                    requests: vec![],
                };
                return serde_wasm_bindgen::to_value(&plan).map_err(|e| e.into());
            }
            
            // If we walked back to genesis without finding a match
            if fork_path.last().unwrap().height == 0 {  // Safe now - we checked !is_empty above
                log("[REORG] Using genesis as common ancestor");
                0
            } else {
                log("[REORG] Missing parent blocks, aborting reorg");
                let plan = ReorgPlan {
                    detach: vec![],
                    attach: vec![],
                    new_tip_hash: canon_tip_hash,
                    new_height: canon_tip_height,
                    requests: missing_parents,
                };
                return serde_wasm_bindgen::to_value(&plan).map_err(|e| e.into());
            }
        }
    };
    
    fork_path.reverse();
    let attach_hashes: Vec<String> = fork_path.iter().map(|b| b.hash()).collect();
    
    let mut detach_segment = Vec::new();
    for h in (ancestor_h + 1)..=canon_tip_height {
        let block_to_detach = load_block_from_db(h).await?
            .ok_or_else(|| JsValue::from_str(&format!("Failed to load canonical block {} for detach plan", h)))?;
        detach_segment.push(block_to_detach);
    }
    let detach_hashes: Vec<String> = detach_segment.iter().map(|b| b.hash()).collect();
    
        // --- GHOST FORK-CHOICE RULE IMPLEMENTATION (SECURE VERSION) ---
        log("[REORG] Calculating GHOST weights for competing chains...");
        let (fork_weight, canon_weight) = {
            // 1. Build a complete map of all relevant blocks and their relationships.
            let mut block_map: HashMap<String, Block> = HashMap::new();
            let mut children_map: HashMap<String, Vec<String>> = HashMap::new();

            // Explicitly load and insert the canonical tip to ensure it's always in the map.
            // This is the core fix for the "Canonical Weight=0" bug.
            let canon_tip_block = load_block_from_db(canon_tip_height).await?
                .ok_or_else(|| JsValue::from_str("Could not load canonical tip for GHOST calculation"))?;
            //  Insert using BOTH the stored hash AND the recomputed hash (defensive)
            block_map.insert(canon_tip_hash.clone(), canon_tip_block.clone());
            block_map.insert(canon_tip_block.hash(), canon_tip_block);

            let all_relevant_blocks = [fork_path.clone(), detach_segment.clone()].concat();
            for block in all_relevant_blocks {
                children_map.entry(block.prev_hash.clone()).or_default().push(block.hash());
                block_map.insert(block.hash(), block);
            }
            // Also include all known side-blocks to correctly weigh the subtrees.
            for block in SIDE_BLOCKS.lock().unwrap().values() {
                if !block_map.contains_key(&block.hash()) {
                    children_map.entry(block.prev_hash.clone()).or_default().push(block.hash());
                    block_map.insert(block.hash(), block.clone());
                }
            }

            // RATIONALE: Add the common ancestor block to the map to provide a complete
            // tree structure for the GHOST weight calculation.
            if let Some(ancestor_block) = load_block_from_db(ancestor_h).await? {
                if !block_map.contains_key(&ancestor_block.hash()) {
                     block_map.insert(ancestor_block.hash(), ancestor_block);
                }
            }

            // The check below is now redundant due to the explicit load above, but is kept for safety.
            if !block_map.contains_key(&canon_tip_hash) {
                if let Some(tip_block) = load_block_from_db(canon_tip_height).await? {
                    block_map.insert(tip_block.hash(), tip_block);
                }
            }

            // 2. Calculate the proof-of-work weighted GHOST score for each chain.
            let mut memo: HashMap<String, u64> = HashMap::new();
            let fork_weight = calculate_ghost_weight(&tip_hash, &block_map, &children_map, &mut memo);
            let canon_weight = calculate_ghost_weight(&canon_tip_hash, &block_map, &children_map, &mut memo);
            
            // DIAGNOSTIC: Log the context used for GHOST calculation BEFORE closing the scope
            log(&format!("[GHOST DEBUG] block_map size: {}, canon_tip in map: {}, fork_tip in map: {}", 
                block_map.len(), 
                block_map.contains_key(&canon_tip_hash),
                block_map.contains_key(&tip_hash)));
            
            (fork_weight, canon_weight)
        };
    
    log(&format!("[REORG] GHOST PoW Weights: Fork Weight={}, Canonical Weight={}", fork_weight, canon_weight));
    log(&format!("[GHOST DEBUG] fork_path length: {}, detach_segment length: {}", 
        fork_path.len(), 
        detach_segment.len()));
    
    let should_switch = if fork_weight > canon_weight {
        true
    } else if fork_weight == canon_weight {
        // RATIONALE (Tie-breaking): Use the lexicographically smaller hash as a
        // deterministic tie-breaker to prevent network splits if work is identical.
        tip_hash < canon_tip_hash
    } else {
       false
    };
    
    // CRITICAL FIX: Add safety check for empty fork_path before attempting to switch
    if should_switch && fork_path.is_empty() {
        log(&format!("[REORG] ERROR: Attempting to switch to fork with empty fork_path. Fork hash: {}, Canon hash: {}", 
            &tip_hash[..12], &canon_tip_hash[..12]));
        log(&format!("[REORG] This indicates a logic error in fork path construction. Aborting reorg."));
        let plan = ReorgPlan {
            detach: vec![],
            attach: vec![],
            new_tip_hash: canon_tip_hash,
            new_height: canon_tip_height,
            requests: vec![],
        };
        return serde_wasm_bindgen::to_value(&plan).map_err(|e| e.into());
    }
    
    let (final_detach, final_attach, new_tip_hash, new_height) = if should_switch {
        // Now safe because we checked fork_path is not empty above
        let new_tip = fork_path.last().unwrap();
        (detach_hashes, attach_hashes, new_tip.hash(), *new_tip.height)
    } else {
        (vec![], vec![], canon_tip_hash, canon_tip_height)
    };
    
    #[derive(Serialize)]
    struct PlanOut<'a> {
        detach: &'a [String],
        attach: &'a [String],
        new_tip_hash: &'a str,
        new_height: u64,
        requests: Vec<String>,
        should_switch: bool,
    }
    
    let out = PlanOut {
        detach: &final_detach,
        attach: &final_attach,
        new_tip_hash: &new_tip_hash,
        new_height,
        requests: vec![],
        should_switch,
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| e.into())
}

// Helper types for lock-free change tracking
#[derive(Clone)]
enum UtxoChange {
    Add(Vec<u8>, TransactionOutput),
    Remove(Vec<u8>),
}

#[derive(Clone)]
enum FilterChange {
    Add(u64, Vec<BlockFilterEntry>),
    Remove(u64),
}

#[derive(Clone)]
enum CoinbaseChange {
    Add(Vec<u8>, u64),
    Remove(Vec<u8>),
}

enum WalletUpdate {
    RemoveBlockUtxos(HashSet<Vec<u8>>),
    ScanBlock(Block),
}

#[derive(Clone)]
struct StateSnapshot {
    current_height: u64,
    current_tip_hash: String,
    current_vrf_threshold: [u8; 32],
    current_vdf_iterations: u64,
}

struct ReorgChanges {
    utxo_changes: Vec<UtxoChange>,
    coinbase_changes: Vec<CoinbaseChange>,
    filter_changes: Vec<FilterChange>,
    wallet_updates: Vec<WalletUpdate>,
    mempool_txs_to_add: Vec<Transaction>,
    new_height: u64,
    new_tip_hash: String,
    new_vrf_threshold: [u8; 32],
    new_vdf_iterations: u64,
    total_work: u64,
    ancestor_height: u64,
}

impl ReorgChanges {
    fn new() -> Self {
        Self {
            utxo_changes: Vec::new(),
            coinbase_changes: Vec::new(),
            filter_changes: Vec::new(),
            wallet_updates: Vec::new(),
            mempool_txs_to_add: Vec::new(),
            new_height: 0,
            new_tip_hash: String::new(),
            new_vrf_threshold: [0u8; 32],
            new_vdf_iterations: 0,
            total_work: 0,
            ancestor_height: 0,
        }
    }
}

/// Atomically apply a reorganization plan
#[wasm_bindgen(js_name = "atomic_reorg")]
pub async fn atomic_reorg(plan_js: JsValue) -> Result<(), JsValue> {
    let plan: ReorgPlan = serde_wasm_bindgen::from_value(plan_js)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    if !plan.requests.is_empty() { 
        return Err(JsValue::from_str("Cannot apply reorg: plan has outstanding requests"));
    }
    if plan.detach.is_empty() && plan.attach.is_empty() { 
        log("[REORG] Plan requires no changes. Aborting.");
        return Ok(()); 
    }

    log(&format!("[REORG] Starting atomic reorg: Detaching {} blocks, Attaching {} blocks.", 
        plan.detach.len(), plan.attach.len())); 

    // ============================================================================
    // PHASE 1: DATA FETCHING (ASYNC, NO LOCKS HELD)
    // ============================================================================

    log("[REORG] Phase 1: Fetching blocks from database");

    // Get current tip height early (needed for loading detach blocks by height)
    let current_tip_height = {
        let chain = BLOCKCHAIN.lock().unwrap();
        *chain.current_height
    };

    let mut blocks_to_attach = Vec::new();
    for hash in &plan.attach { 
        let block = match get_block_any(hash) {
            Some(b) => b,
            None => {
                match load_block_by_hash(hash).await? {
                    Some(b) => b,
                    None => return Err(JsValue::from_str(&format!("Block {} not found", hash))),
                }
            }
        };
        blocks_to_attach.push(block); 
    }

    // FIXED: Load canonical blocks by height, not hash
    let mut blocks_to_detach = Vec::new();
    if !plan.detach.is_empty() {
        // Calculate the height of the common ancestor
        let ancestor_height = current_tip_height - plan.detach.len() as u64;
        
        // Load blocks by height (canonical chain) and verify hashes match the plan
        for (i, expected_hash) in plan.detach.iter().enumerate() {
            let height = ancestor_height + 1 + i as u64;
            
            let block = load_block_from_db(height).await?
                .ok_or_else(|| JsValue::from_str(&format!(
                    "Could not load canonical block at height {} for detachment", 
                    height
                )))?;
            
            // Verify the hash matches what the plan expects (detects race conditions)
            if &block.hash() != expected_hash {
                return Err(JsValue::from_str(&format!(
                    "Canonical chain mismatch during reorg: block at height {} has hash {}..., but plan expects {}... (another block may have been mined)",
                    height, &block.hash()[..12], &expected_hash[..12]
                )));
            }
            
            blocks_to_detach.push(block);
        }
    }

    // Fetch source blocks for restoring spent inputs
    let mut source_blocks = std::collections::HashMap::new();
    for block in &blocks_to_detach {
        for tx in &block.transactions {
            for input in &tx.inputs {
                if !source_blocks.contains_key(&input.source_height) {
                    let source_block = load_block_from_db(*input.source_height).await?
                        .ok_or_else(|| JsValue::from_str(&format!("Missing source block #{}", input.source_height)))?;
                    source_blocks.insert(input.source_height, source_block);
                }
            }
        }
    }

    // ============================================================================
    // PHASE 2: SNAPSHOT CURRENT STATE (LOCKS HELD BRIEFLY)
    // ============================================================================
    
    log("[REORG] Phase 2: Snapshotting current state");
    
    let (original_tip_height, state_snapshot) = {
        let chain = BLOCKCHAIN.lock().unwrap();
        let snapshot = StateSnapshot {
            current_height: *chain.current_height,
            current_tip_hash: chain.tip_hash.clone(),
            current_vrf_threshold: chain.current_vrf_threshold,
            current_vdf_iterations: *chain.current_vdf_iterations,
        };
        (chain.current_height, snapshot)
    }; // Lock released immediately

    // FIX #1: Write recovery marker BEFORE any state changes (now using Protobuf)
    let marker = p2p::ReorgMarker {
        original_tip_height: *original_tip_height,
        new_tip_height: plan.new_height,
        new_tip_hash: plan.new_tip_hash.clone(),
        blocks_to_attach: plan.attach.clone(), 
        blocks_to_detach_heights: ((state_snapshot.current_height - blocks_to_detach.len() as u64 + 1)..=*original_tip_height).collect(),
        timestamp: js_sys::Date::now() as u64,
    };

    // Use the new Protobuf-aware helper function
    save_reorg_marker_proto(&marker).await?;
    log("[REORG] Recovery marker (Protobuf) saved");

    // ============================================================================
    // PHASE 3: COMPUTE ALL CHANGES (NO LOCKS, PURE COMPUTATION)
    // ============================================================================
    
    log("[REORG] Phase 3: Computing state changes (lock-free)");
    
    let mut changes = ReorgChanges::new();
    let mut working_height = state_snapshot.current_height;
    let mut working_tip_hash = state_snapshot.current_tip_hash.clone();

    // === Step 3.1: Process Detached Blocks ===
    log(&format!("[REORG] Computing changes for {} detached blocks", blocks_to_detach.len()));
    
    for block in blocks_to_detach.iter().rev() {
        if working_height != *block.height {
            return Err(JsValue::from_str(&format!(
                "Reorg plan mismatch: expected height {}, got {}",
                working_height, block.height
            )));
        }
        if working_tip_hash != block.hash() {
            return Err(JsValue::from_str("Reorg plan mismatch: hash mismatch"));
        }

        log(&format!("[REORG] Planning detach of block #{} ({}...)", 
            block.height, &block.hash()[..12]));

        //plan filter deletion
        changes.filter_changes.push(FilterChange::Remove(*block.height));
        
        // Collect outputs to remove
        let block_outputs: HashSet<Vec<u8>> = block.transactions.iter()
            .flat_map(|tx| tx.outputs.iter().map(|o| o.commitment.clone()))
            .collect();

        for commitment in &block_outputs {
            changes.utxo_changes.push(UtxoChange::Remove(commitment.clone()));
            changes.coinbase_changes.push(CoinbaseChange::Remove(commitment.clone()));
        }

        // Schedule wallet update
        changes.wallet_updates.push(WalletUpdate::RemoveBlockUtxos(block_outputs));

        // Restore inputs that were spent in this block
        for tx in &block.transactions {
            for input in &tx.inputs {
                if let Some(source_block) = source_blocks.get(&input.source_height) {
                    let mut found_output = None;
                    for source_tx in &source_block.transactions {
                        if let Some(output) = source_tx.outputs.iter()
                            .find(|o| o.commitment == input.commitment) 
                        {
                            found_output = Some(output.clone());
                            break;
                        }
                    }
                    
                    if let Some(original_output) = found_output {
                        changes.utxo_changes.push(
                            UtxoChange::Add(input.commitment.clone(), original_output)
                        );
                        
                        let is_coinbase = source_block.transactions.iter()
                            .any(|t| t.inputs.is_empty() && 
                                t.outputs.iter().any(|o| o.commitment == input.commitment));
                        
                        if is_coinbase {
                            changes.coinbase_changes.push(
                                CoinbaseChange::Add(input.commitment.clone(), *input.source_height)
                            );
                        }
                    }
                }
            }
        }

        // Return non-coinbase transactions to mempool
        for tx in block.transactions.iter().filter(|t| !t.inputs.is_empty()) {
            changes.mempool_txs_to_add.push(tx.clone());
        }
        
        working_height -= 1;
    }

    // === Step 3.2: Find Common Ancestor ===
    let ancestor_block = if working_height > 0 {
        load_block_from_db(working_height).await?
            .ok_or_else(|| JsValue::from_str(&format!("Ancestor block #{} not found", working_height)))?
    } else {
        Block::genesis()
    };
    
    working_tip_hash = ancestor_block.hash();
    changes.ancestor_height = working_height;
    
    log(&format!("[REORG] Common ancestor: block #{} ({}...)", 
        working_height, &working_tip_hash[..12]));

    // === Step 3.3: Process Attached Blocks ===
    log(&format!("[REORG] Computing changes for {} attached blocks", blocks_to_attach.len()));
    
    for block in &blocks_to_attach {
        working_height += 1;
        
        log(&format!("[REORG] Planning attach of block #{} ({}...)", 
            block.height, &block.hash()[..12]));

        //Generate filter for attached block
        let mut filter_entries = Vec::<BlockFilterEntry>::new();
        for tx in &block.transactions {
            for output in &tx.outputs {
                if let (Some(ephemeral_key), Some(view_tag)) = 
                    (output.ephemeral_key.as_ref(), output.view_tag.as_ref()) 
                {
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
        if !filter_entries.is_empty() {
            log(&format!("[REORG] Planning filter for block #{}: {} entries", *block.height, filter_entries.len()));
            changes.filter_changes.push(FilterChange::Add(*block.height, filter_entries));
        }


        for tx in &block.transactions {
            // Remove inputs
            for inp in &tx.inputs {
                changes.utxo_changes.push(UtxoChange::Remove(inp.commitment.clone()));
                changes.coinbase_changes.push(CoinbaseChange::Remove(inp.commitment.clone()));
            }
            
            // Add outputs
            let is_coinbase = tx.total_fee() == 0 && tx.inputs.is_empty();
            for out in &tx.outputs {
                changes.utxo_changes.push(UtxoChange::Add(out.commitment.clone(), out.clone()));
                if is_coinbase {
                    changes.coinbase_changes.push(
                        CoinbaseChange::Add(out.commitment.clone(), *block.height)
                    );
                }
            }
        }

        // Schedule wallet scan
        changes.wallet_updates.push(WalletUpdate::ScanBlock(block.clone()));
        
        working_tip_hash = block.hash();
    }

    // === Step 3.4: Calculate Final State ===
    changes.new_height = working_height;
    changes.new_tip_hash = working_tip_hash;
    
    if let Some(last_block) = blocks_to_attach.last() {
        changes.new_vrf_threshold = last_block.vrf_threshold;
        changes.new_vdf_iterations = *last_block.vdf_iterations;
    } else {
        changes.new_vrf_threshold = ancestor_block.vrf_threshold;
        changes.new_vdf_iterations = *ancestor_block.vdf_iterations;
    }

    // Calculate work (expensive but lock-free)
    let detached_work = Blockchain::get_chain_work(&blocks_to_detach);
    let attached_work = Blockchain::get_chain_work(&blocks_to_attach);
    let current_total_work = { BLOCKCHAIN.lock().unwrap().total_work };
    changes.total_work = current_total_work
        .saturating_sub(detached_work)
        .saturating_add(attached_work);

        log(&format!("[REORG] Computed {} UTXO changes, {} coinbase changes, {} wallet updates",
         changes.utxo_changes.len(), changes.coinbase_changes.len(), changes.wallet_updates.len()));

    // ============================================================================
    // PHASE 4: APPLY ALL CHANGES (LOCKS HELD BRIEFLY IN SEQUENCE)
    // ============================================================================
    
    log("[REORG] Phase 4: Applying changes to global state");
    
    // Step 4.1: Apply UTXO changes (in memory AND database)
    {
        let mut utxo_set = blockchain::UTXO_SET.lock().unwrap();
        for change in &changes.utxo_changes {
            match change {
                UtxoChange::Add(commitment, output) => {
                    utxo_set.insert(commitment.clone(), output.clone());
                    // === ADDITION: Persist DB change ===
                    save_utxo_to_db(commitment, output).await?;
                }
                UtxoChange::Remove(commitment) => {
                    utxo_set.remove(commitment);
                    // === ADDITION: Persist DB change ===
                    delete_utxo_from_db(commitment).await.ok();
                }
            }
        }
    } // UTXO lock released
    
    // Step 4.2: Apply coinbase index changes (in memory AND database)
    {
        let mut coinbase_index = blockchain::COINBASE_INDEX.lock().unwrap();
        for change in &changes.coinbase_changes {
            match change {
                CoinbaseChange::Add(commitment, height) => {
                    coinbase_index.insert(commitment.clone(), *height);
                    // === ADDITION: Persist DB change ===
                    save_coinbase_index_to_db(commitment, *height).await?;
                }
                CoinbaseChange::Remove(commitment) => {
                    coinbase_index.remove(commitment);
                    // === ADDITION: Persist DB change ===
                    delete_coinbase_index_from_db(commitment).await.ok();
                }
            }
        }
    } // Coinbase lock released
    
    //Step 4.2b: Apply filter changes (in database only)
    {
        for change in &changes.filter_changes {
            match change {
                FilterChange::Add(height, entries) => {
                    // This function is defined later in this file
                    save_block_filter_to_db(*height, entries).await?;
                }
                FilterChange::Remove(height) => {
                    // This function is defined later in this file
                    delete_block_filter_from_db(*height).await.ok(); // Ignore errors
                }
            }
        }
        log("[REORG] Applied filter changes to database");
    } // No lock needed here
    
    // Step 4.3: Apply wallet updates
    {
        let mut wallet_sessions = WALLET_SESSIONS.lock().unwrap();
        for update in &changes.wallet_updates {
            match update {
                WalletUpdate::RemoveBlockUtxos(commitments) => {
                    for wallet in wallet_sessions.values_mut() {
                        wallet.remove_block_utxos(commitments);
                    }
                }
                WalletUpdate::ScanBlock(block) => {
                    for wallet in wallet_sessions.values_mut() {
                        wallet.scan_block(block);
                    }
                }
            }
        }
    } // Wallet lock released
    
    // Step 4.4: Update transaction pool
    {
        let mut tx_pool = TX_POOL.lock().unwrap();
        
        // Add transactions from detached blocks back to mempool
        for tx in &changes.mempool_txs_to_add {
            if !tx_pool.pending.iter().any(|p| p.hash() == tx.hash()) {
                tx_pool.pending.push(tx.clone());
            }
        }
        
        // Recalculate fee total
        tx_pool.fee_total = tx_pool.pending.iter().map(|t| t.total_fee()).sum();
    } // TX pool lock released
    
    // Step 4.5: Update blockchain metadata (final state update)
    {
        let mut chain = BLOCKCHAIN.lock().unwrap(); 
        chain.current_height = WasmU64::from(changes.new_height);
        chain.tip_hash = changes.new_tip_hash.clone();
        chain.total_work = WasmU64::from(changes.total_work);
        chain.current_vrf_threshold = changes.new_vrf_threshold;
        chain.current_vdf_iterations = WasmU64::from(changes.new_vdf_iterations);
        
        log(&format!("[REORG] Chain state updated: height={}, work={}", 
            chain.current_height, chain.total_work));
    } // Chain lock released

    log("[REORG] Phase 4 complete. Re-validating tip before commit...");
    let (current_tip_hash_before_commit, current_height_before_commit) = {
        let chain_now = BLOCKCHAIN.lock().unwrap();
        (chain_now.tip_hash.clone(), *chain_now.current_height)
    };

    // Compare against the state snapshotted *after* applying changes in memory (Phase 4)
    if current_tip_hash_before_commit != changes.new_tip_hash || current_height_before_commit != changes.new_height {
        log(&format!(
            "[REORG] CRITICAL: Chain state changed unexpectedly during reorg application!\n\
             Expected Tip after Phase 4: #{} ({}) \n\
             Actual Tip before Phase 5:   #{} ({})\n\
             Aborting commit phase to prevent inconsistency.",
            changes.new_height, &changes.new_tip_hash[..12],
            current_height_before_commit, &current_tip_hash_before_commit[..12]
        ));
        // CRITICAL: We MUST clear the reorg marker here because the reorg failed before commit
        clear_reorg_marker().await?;
        log("[REORG] Cleared recovery marker due to pre-commit state mismatch.");
        return Err(JsValue::from_str("Reorg aborted: Chain state changed during execution"));
    }
    log("[REORG] ✓ Pre-commit tip validation passed.");


    // ============================================================================
    // PHASE 5: PERSISTENCE (ASYNC, NO LOCKS) - Uses Fix #1's atomic commit
    // ============================================================================
    
    log("[REORG] Phase 5: Persisting changes to database");
    
    // Step 5.1: Save blocks to staging area (Fix #1)
    for block in &blocks_to_attach {
        save_block_to_staging(block).await?;
    }
    
    // Step 5.2: Atomic commit operation (Fix #1)
    commit_staged_reorg(
        &blocks_to_attach,
        &((changes.ancestor_height + 1)..=*original_tip_height).collect::<Vec<_>>(),
        changes.new_height,
        &changes.new_tip_hash
    ).await?;
    
    // Step 5.3: Persist total work
    save_total_work_to_db(changes.total_work).await?;
    
    // Step 5.4: Clear the reorg marker (reorg completed successfully) - Fix #1
    clear_reorg_marker().await?;
    
    // === VALIDATION: Ensure database matches in-memory state ===
    log("[REORG] Validating database consistency post-commit...");

    // Verify the new tip exists in the database
    match load_block_from_db(changes.new_height).await? {
        Some(db_block) => {
            let db_hash = db_block.hash();
            if db_hash != changes.new_tip_hash {
                let error_msg = format!(
                    "CRITICAL DATABASE INCONSISTENCY DETECTED!\n\
                     Expected tip hash: {}...\n\
                     Database has:      {}...\n\
                     Height: {}\n\
                     This indicates the reorg committed to memory but not to database.\n\
                     Manual recovery required!",
                    &changes.new_tip_hash[..16],
                    &db_hash[..16],
                    changes.new_height
                );
                log(&error_msg);
                return Err(JsValue::from_str(&error_msg));
            }
            
            log(&format!(
                "[REORG] ✓ Database validation passed - tip matches at height {}", 
                changes.new_height
            ));
        },
        None => {
            let error_msg = format!(
                "CRITICAL: New tip block at height {} not found in database after reorg!",
                changes.new_height
            );
            log(&error_msg);
            return Err(JsValue::from_str(&error_msg));
        }
    }

    // Optionally verify a few blocks before the tip as well
    if changes.new_height > 2 {
        let check_height = changes.new_height - 1;
        if load_block_from_db(check_height).await?.is_none() {
            let error_msg = format!(
                "CRITICAL: Block at height {} (one before tip) not found after reorg!",
                check_height
            );
            log(&error_msg);
            return Err(JsValue::from_str(&error_msg));
        }
    }

    log("[REORG] ✓ All validation checks passed");
    
    log(&format!("[REORG] Completed successfully. New tip: #{} ({}...), total work: {}",
        changes.new_height, &changes.new_tip_hash[..12], changes.total_work));
    
    Ok(())
}


#[wasm_bindgen]
pub fn get_blockchain_state() -> Result<JsValue, JsValue> {
    let chain = BLOCKCHAIN.lock().unwrap();
    serde_wasm_bindgen::to_value(&*chain)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn get_latest_block_hash() -> Result<String, JsValue> {
    let (tip_hash, _) = tip_hash_and_height();
    Ok(tip_hash)
}

#[wasm_bindgen]
pub async fn get_block_by_hash(hash: String) -> Result<JsValue, JsValue> {
    // 1. Check the side-chain cache first (fast path for forks).
    if let Some(block) = get_block_any(&hash) {
        return serde_wasm_bindgen::to_value(&Some(block)).map_err(|e| e.into());
    }

    // 2. If not in cache, walk back the canonical chain from the DB tip.
    let tip_height = get_tip_height_from_db().await?;
    
    // Start with the current tip block.
    if let Some(mut current_block) = load_block_from_db(tip_height).await? {
        loop {
            // Check if the current block is the one we're looking for.
            if current_block.hash() == hash {
                return serde_wasm_bindgen::to_value(&Some(current_block)).map_err(|e| e.into());
            }

            // If we've reached genesis and haven't found it, stop.
            if current_block.height == 0 {
                break;
            }

            // Load the parent block to continue walking backwards.
            if let Some(parent_block) = load_block_from_db(current_block.height - 1).await? {
                current_block = parent_block;
            } else {
                // The chain is broken in the DB, so we can't search further.
                break;
            }
        }
    }

    // 3. If the block was not found anywhere, return null.
    serde_wasm_bindgen::to_value(&Option::<Block>::None).map_err(|e| e.into())
}

/// Creates a new wallet session AND generates a mnemonic phrase.
/// Returns the mnemonic phrase to the caller.
#[wasm_bindgen]
pub fn wallet_session_create_with_mnemonic(wallet_id: &str) -> Result<String, JsValue> {
    let mut map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    if map.contains_key(wallet_id) {
        return Err(JsValue::from_str("Wallet session already exists"));
    }
    // Use the new wallet constructor
    let (w, phrase) = wallet::Wallet::new_with_mnemonic()
        .map_err(|e| JsValue::from_str(&e))?;

    map.insert(wallet_id.to_string(), w);
    Ok(phrase) // Return the mnemonic phrase
}

/// Creates a wallet session by restoring keys from a mnemonic phrase.
#[wasm_bindgen]
pub fn wallet_session_restore_from_mnemonic(wallet_id: &str, phrase: &str) -> Result<(), JsValue> {
    let mut map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    if map.contains_key(wallet_id) {
        return Err(JsValue::from_str("Wallet session already exists for this ID"));
    }
    // Use the new restore function
    let w = wallet::Wallet::from_mnemonic(phrase)
        .map_err(|e| JsValue::from_str(&e))?;

    map.insert(wallet_id.to_string(), w);
    Ok(())
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


// Introducing - REST - Randomized Expensive Sequential Time
//POW is used to "purchase" a VDF ticket. Valid VDF results are placed in a verifiable lottery via VRF.
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
    
   // Mine just the header ticket (no transactions needed yet)
    for nonce in start_nonce..max_nonce {
        let mut test_block = Block::genesis();
        test_block.height = WasmU64::from(height);
        test_block.prev_hash = prev_hash.clone();
        test_block.miner_pubkey = miner_pubkey;
        test_block.lottery_nonce = WasmU64::from(nonce);
        
        // CRITICAL FIX #10: VDF ticket binds (height, prev_hash, miner_pubkey, nonce)
        // Including height prevents replay attacks across different blocks
        let vdf = VDF::new(2048).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let vdf_input = format!("{}{}{}{}", height, prev_hash, hex::encode(miner_pubkey), nonce);
        let vdf_proof = vdf.compute_with_proof(vdf_input.as_bytes(), WasmU64::from(vdf_iterations))
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
            // NEW: Propagate committed params
            vrf_threshold: Vec<u8>,
            vdf_iterations: u64,
        }
        
        return serde_wasm_bindgen::to_value(&HeaderSolution {
            nonce,
            vrf_proof,
            vdf_proof,
            miner_pubkey: miner_pubkey.to_vec(),
            // NEW
            vrf_threshold: vrf_threshold_bytes.clone(),
            vdf_iterations,
        }).map_err(|e| e.into());
    }
    
    // No solution in this range
    Ok(JsValue::NULL)
}

#[wasm_bindgen]
pub fn get_mempool_data() -> Result<JsValue, JsValue> {
    let pool = TX_POOL.lock().unwrap();
    
    #[derive(Serialize)]
    struct MempoolData {
        pending_count: usize,
        fee_total: u64,
        transactions: Vec<Transaction>,
    }
    
    let data = MempoolData {
        pending_count: pool.pending.len(),
        fee_total: pool.fee_total,
        transactions: pool.pending.clone(),
    };
    
    serde_wasm_bindgen::to_value(&data)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn wallet_session_clear_all() -> Result<(), JsValue> {
    let mut map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    map.clear();
    log("[RUST] All active wallet sessions cleared.");
    Ok(())
}

#[wasm_bindgen]
pub async fn audit_total_supply() -> Result<String, JsValue> {
    // The total supply is the sum of the base block rewards for all blocks
    // in the canonical chain. Transaction fees represent a transfer of existing
    // value from users to the miner, not the creation of new supply.

    // Use the authoritative in-memory state directly instead of calling back to JS.
    let tip_height = {
        let chain = BLOCKCHAIN.lock().unwrap();
        *chain.current_height
    };

    let mut total_supply: u128 = 0;

    // Iterate from genesis+1 (height 1) to the current tip (genesis has no coinbase)
    for height in 1..=tip_height {
        // Add the base reward for the block at this height to the total
        total_supply += get_current_base_reward(height) as u128;
    }

    // Return the total supply as a string to avoid precision issues in JavaScript
    Ok(total_supply.to_string())
}

#[wasm_bindgen]
pub fn create_vrf_proof(miner_secret_key_bytes: Vec<u8>, vdf_y_bytes: Vec<u8>) -> Result<JsValue, JsValue> {
    if miner_secret_key_bytes.len() != 32 {
        return Err(JsValue::from_str("Secret key must be 32 bytes"));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&miner_secret_key_bytes);
    let secret_key = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(sk);

    let proof = crate::vrf::create_vrf(&secret_key, &vdf_y_bytes);
    serde_wasm_bindgen::to_value(&proof).map_err(|e| e.into())
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
    vrf_threshold_bytes: Vec<u8>,
    vdf_iterations: u64,
    _mempool_transactions_js: JsValue, // kept for API compatibility; ignored
) -> Result<JsValue, JsValue> {
    // Deserialize proofs
    let vrf_proof: VrfProof = serde_wasm_bindgen::from_value(vrf_proof_js)?;
    let vdf_proof: VDFProof = serde_wasm_bindgen::from_value(vdf_proof_js)?;

    // Snapshot mempool and select a valid, non-conflicting set
    let (mut selected, total_fees) = {
        let chain = BLOCKCHAIN.lock().unwrap();
        let pool_snapshot = {
            let pool = TX_POOL.lock().unwrap();
            pool.pending.clone()
        };

        chain.select_transactions_for_block(&pool_snapshot)
    };
    
    // Coinbase pays base + fees
    let base_reward = {
        blockchain::get_current_base_reward(height)
    };
    let coinbase_amount = base_reward + total_fees;
    let coinbase_tx = Transaction::create_coinbase(vec![
        (miner_scan_pubkey_bytes, coinbase_amount)
    ]).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // Assemble block (coinbase first)
    selected.insert(0, coinbase_tx);

    let mut miner_pubkey = [0u8; 32];
    miner_pubkey.copy_from_slice(&miner_pubkey_bytes);
    
    let mut block = Block {
        height: WasmU64::from(height),
        prev_hash,
        timestamp: WasmU64::from(js_sys::Date::now() as u64),
        transactions: selected,
        lottery_nonce: WasmU64::from(nonce),
        vrf_proof,
        vdf_proof,
        miner_pubkey: miner_pubkey,
        // Commit params into header
        vdf_iterations: WasmU64::from(vdf_iterations),
        vrf_threshold: {
            let mut t = [0u8; 32];
            t.copy_from_slice(&vrf_threshold_bytes);
            t
        },
        tx_merkle_root: [0u8; 32],
        total_work: WasmU64::from(0),
        hash: String::new(),
    };
    
    // Before cut-through
    let before_ct = block.transactions.len();

    block.apply_cut_through()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    log(&format!("[CUT-THROUGH] txs before={}, after={}", before_ct, block.transactions.len()));
        
    block.tx_merkle_root = block.calculate_tx_merkle_root();
    block.hash = block.compute_hash();
    
    log(&format!(
        "[MINING] Completed block #{} with {} txs (fees = {})",
        height, block.transactions.len().saturating_sub(1), total_fees
    ));
    
    serde_wasm_bindgen::to_value(&block).map_err(|e| e.into())
}

#[wasm_bindgen]
pub fn get_current_mining_params() -> Result<JsValue, JsValue> {
    let chain = BLOCKCHAIN.lock().unwrap();
    #[derive(Serialize)]
    struct MiningParams {
        vrf_threshold: String,
        vdf_iterations: u64,
        current_height: u64,
        total_work: u64,
    }
    
    let params = MiningParams {
        vrf_threshold: hex::encode(&chain.current_vrf_threshold),
        vdf_iterations: *chain.current_vdf_iterations,
        current_height: *chain.current_height,
        total_work: *chain.total_work,
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
    
    log("[POOL_ADD ENTRY] Attempting deserialization...");
    log(&format!("[POOL_ADD ENTRY] Received JsValue: {:?}", tx_json));
    let tx: Transaction = serde_wasm_bindgen::from_value(tx_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize transaction: {}", e)))?;

    let tx_hash_for_log = tx.hash(); // Get hash early for logging
    log(&format!("[POOL_ADD {}] Starting validation", &tx_hash_for_log[..8]));


    // 1) Kernel signature (single source of truth)
    match tx.verify_signature() {
        Ok(true) => log(&format!("[POOL_ADD {}] Signature verified", &tx_hash_for_log[..8])),
        Ok(false) => return Err(JsValue::from_str(&format!("[POOL_ADD {}] Failed signature verification", &tx_hash_for_log[..8]))),
        Err(e) => return Err(JsValue::from_str(&format!("[POOL_ADD {}] Error during signature verification: {}", &tx_hash_for_log[..8], e))),
    }

    // 2) Verify AGGREGATED range proof (V2)
    if !tx.outputs.is_empty() { // Only verify if there are outputs
        log(&format!("[POOL_ADD {}] Verifying aggregated range proof...", &tx_hash_for_log[..8]));

        // Collect all output commitments for this transaction
        let commitments_result: Result<Vec<_>,_> = tx.outputs.iter()
            .map(|output| CompressedRistretto::from_slice(&output.commitment))
            .collect();
        let commitments = match commitments_result {
            Ok(c) => c,
            Err(_) => {
                 log(&format!("[POOL_ADD {}] Failed to parse one or more output commitments", &tx_hash_for_log[..8]));
                 // Convert PluribitError to JsValue for the return type
                 return Err(JsValue::from_str("Invalid output commitment"));
            }
        }; // 

        // Parse the single aggregated range proof from the transaction
        let aggregated_proof = match RangeProof::from_bytes(&tx.aggregated_range_proof) { // 
            Ok(p) => p,
            Err(_) => {
                 log(&format!("[POOL_ADD {}] Failed to parse aggregated range proof bytes", &tx_hash_for_log[..8]));
                 // Convert PluribitError to JsValue
                 return Err(JsValue::from_str("Invalid range proof format")); // 
            }
        };

        // Verify the single aggregated proof against ALL commitments using the correct function
        if !mimblewimble::verify_aggregated_range_proof(&aggregated_proof, &commitments) { // 
            log(&format!("[POOL_ADD {}] Aggregated range proof verification FAILED", &tx_hash_for_log[..8]));
             // Convert PluribitError to JsValue
            return Err(JsValue::from_str("Range proof verification failed")); // 
        }
        log(&format!("[POOL_ADD {}] Aggregated range proof verified successfully for {} outputs", &tx_hash_for_log[..8], commitments.len()));

    } else {
         log(&format!("[POOL_ADD {}] No outputs, skipping range proof verification", &tx_hash_for_log[..8]));
    }
    log(&format!("[POOL_ADD {}] Range proofs verified", &tx_hash_for_log[..8]));

    // 3) Mimblewimble balance:
    //    sum(inputs) == sum(outputs) + kernel_excess
    //    (your kernel_excess is commit(fee, blinding), so adding it is correct)
    let mut input_sum = RistrettoPoint::identity();
    let mut output_sum = RistrettoPoint::identity();

    for (i, input) in tx.inputs.iter().enumerate() {
        let c = CompressedRistretto::from_slice(&input.commitment)
            .map_err(|_| JsValue::from_str("Invalid input commitment"))?
            .decompress()
            .ok_or_else(|| JsValue::from_str(&format!(
                "[POOL_ADD {}] Failed to decompress input commitment {}",
                 &tx_hash_for_log[..8], i
            )))?;
        input_sum += c;
    }
    for (i, output) in tx.outputs.iter().enumerate() {
        let c = CompressedRistretto::from_slice(&output.commitment)
            .map_err(|_| JsValue::from_str("Invalid output commitment"))?
            .decompress()
            .ok_or_else(|| JsValue::from_str(&format!(
                "[POOL_ADD {}] Failed to decompress output commitment {}",
                 &tx_hash_for_log[..8], i
            )))?;
        output_sum += c;
    }

    // Sum all kernel excess points
    let mut excess_total = RistrettoPoint::identity();
    for (i, k) in tx.kernels.iter().enumerate() {
        let p = CompressedRistretto::from_slice(&k.excess)
            .map_err(|_| JsValue::from_str("Invalid kernel excess"))?
            .decompress()
            .ok_or_else(|| JsValue::from_str(&format!(
                "[POOL_ADD {}] Failed to decompress kernel excess {}",
                 &tx_hash_for_log[..8], i
            )))?;
        excess_total += p;
    }
    if input_sum != (output_sum + excess_total) {
        return Err(JsValue::from_str("Transaction doesn't balance"));
    }

    // 4) Inputs must exist in current UTXO set (and coinbase spends must be mature)
    log(&format!("[POOL_ADD {}] Balance check passed, checking UTXO existence...", &tx_hash_for_log[..8]));
    {
        use crate::constants::COINBASE_MATURITY;
        // read the current tip height
        let tip = { crate::BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner()).current_height };
        let utxos = crate::blockchain::UTXO_SET.lock().unwrap_or_else(|p| p.into_inner());
        let cb    = crate::blockchain::COINBASE_INDEX.lock().unwrap_or_else(|p| p.into_inner());
        for input in &tx.inputs {
            if !utxos.contains_key(&input.commitment) {
                return Err(JsValue::from_str("Input not found in UTXO set"));
            }
            if let Some(&born_at) = cb.get(&input.commitment) {
                // tx admitted now will be mined in the *next* block
                if tip.saturating_add(1) < born_at.saturating_add(COINBASE_MATURITY) {
                    let confs = tip.saturating_add(1).saturating_sub(born_at);
                    return Err(JsValue::from_str(&format!(
                        "Coinbase spend is immature (have {} confs, need {})",
                        confs, COINBASE_MATURITY
                    )));
                }
            }
        }
    }
    log(&format!("[POOL_ADD {}] UTXO/maturity checks passed, checking pool policies...", &tx_hash_for_log[..8]));
    // 5) Mempool policy & add
    // Use map_err for better error context if lock fails
    let mut pool = TX_POOL.lock().map_err(|e| {
        JsValue::from_str(&format!("[POOL_ADD {}] Failed to lock TX_POOL: {}", &tx_hash_for_log[..8], e))
    })?;
    log(&format!("[POOL_ADD {}] Acquired pool lock", &tx_hash_for_log[..8]));
    // prevent conflicts with pending txs
    for pending in &pool.pending {
        // same hash = duplicate
        if pending.hash() == tx.hash() {
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
        if let Some((idx, low)) = pool.pending.iter().enumerate().min_by_key(|(_, t)| t.total_fee()) {
            if tx.total_fee() > low.total_fee() {
                log(&format!(
                    "[RUST] Pool full. Evicting tx with fee {} to add new tx with fee {}",
                    low.total_fee(), tx.total_fee()
                ));
                pool.fee_total -= low.total_fee();
                pool.pending.remove(idx);
            } else {
                return Err(JsValue::from_str(&format!(
                    "Transaction fee {} is too low for a full pool. Minimum required: {}",
                    tx.total_fee(), low.total_fee() + 1
                )));
            }
        } else {
            return Err(JsValue::from_str("Pool is full but could not determine minimum fee."));
        }
    }

    pool.fee_total = pool.fee_total.saturating_add(tx.total_fee());
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
    // Use the canonical Transaction::hash method
    Ok(tx.hash())
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
pub fn get_chain_storage_size() -> Result<JsValue, JsValue> {
    let _chain = BLOCKCHAIN.lock().unwrap();
    let utxo_set = blockchain::UTXO_SET.lock().unwrap();

    // This is a very rough estimate and should be improved if precise metrics are needed.
    let utxo_size = utxo_set.len() * (32 + 675); // commitment + range proof average

    #[derive(Serialize)]
    struct StorageInfo {
        utxo_count: usize,
        utxo_size_bytes: usize,
    }

    let info = StorageInfo {
        utxo_count: utxo_set.len(),
        utxo_size_bytes: utxo_size,
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
pub fn wallet_session_get_spend_pubkey(wallet_id: &str) -> Result<Vec<u8>, JsValue> {
    let map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let w = map.get(wallet_id).ok_or_else(|| JsValue::from_str("Wallet session not active"))?;
    Ok(w.spend_pub.compress().to_bytes().to_vec())
}


// This function lets JS get the scan pubkey from an active Rust session.
#[wasm_bindgen]
pub fn wallet_session_get_scan_pubkey(wallet_id: &str) -> Result<Vec<u8>, JsValue> {
    let map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let w = map.get(wallet_id).ok_or_else(|| JsValue::from_str("Wallet session not active"))?;
    Ok(w.scan_pub.compress().to_bytes().to_vec())
}

// This function lets JS get the private spend key needed by the mining worker.
#[wasm_bindgen]
pub fn wallet_session_get_spend_privkey(wallet_id: &str) -> Result<Vec<u8>, JsValue> {
    let map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let w = map.get(wallet_id).ok_or_else(|| JsValue::from_str("Wallet session not active"))?;
    Ok(w.spend_priv.to_bytes().to_vec())
}

/// Clear pending UTXO marks after transaction failure
#[wasm_bindgen]
pub fn wallet_clear_pending_utxos(commitments_js: JsValue) -> Result<(), JsValue> {
    let commitments: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(commitments_js)?;
    wallet::Wallet::clear_pending_utxos(&commitments);
    Ok(())
}


/// Scan a single block (used during live sync).
#[wasm_bindgen]
pub fn wallet_session_scan_block(wallet_id: &str, block_bytes: Vec<u8>) -> Result<(), JsValue> { // <-- CHANGED: from block_js: JsValue

    // 1. Decode bytes into p2p::Block
    let p2p_block = p2p::Block::decode(&block_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("bad block proto: {e}")))?;

    // 2. Convert p2p::Block into internal Block struct
    let mut block: Block = Block::from(p2p_block);
    block.hash = block.compute_hash(); // Ensure hash is set

    // 3. Proceed with original logic
    let mut map = WALLET_SESSIONS.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let w = map.get_mut(wallet_id).ok_or_else(|| JsValue::from_str("Wallet not loaded"))?;
    w.scan_block(&block);
    Ok(())
}

#[wasm_bindgen]
pub async fn get_canonical_hashes_after(start_height: u64) -> Result<JsValue, JsValue> {
    let tip_height = get_tip_height_from_db().await?;
    let mut hashes = Vec::new();
    
    let start = start_height;
    
    // Iterate from the block after the requester's tip to our current tip
    for height in (start + 1)..=tip_height {
        if let Some(block) = load_block_from_db(height).await? {
            hashes.push(block.hash());
        } else {
            return Err(JsValue::from_str(&format!("Could not load canonical block at height {}", height)));
        }
    }
    
    serde_wasm_bindgen::to_value(&hashes).map_err(|e| e.into())
}

#[wasm_bindgen]
pub async fn rewind_block(block_js: JsValue) -> Result<(), JsValue> {
    let block: Block = serde_wasm_bindgen::from_value(block_js)?;
    let mut chain = BLOCKCHAIN.lock().unwrap();

    // Verify this is the tip of the chain before rewinding
    if *chain.current_height != *block.height {
        return Err(JsValue::from_str(&format!(
            "Can only rewind from tip. Current height: {}, block height: {}",
            chain.current_height, block.height
        )));
    }

    // --- State Manipulation ---
    {
        let mut utxo_set = blockchain::UTXO_SET.lock().unwrap();
        let cache = RECENT_UTXO_CACHE.lock().unwrap();
        for tx in &block.transactions {
            // Restore spent inputs by finding their original output in the cache
            if !tx.inputs.is_empty() {
                for input in &tx.inputs {
                    if let Some((_height, output)) = cache.get(&input.commitment) {
                        utxo_set.insert(input.commitment.clone(), output.clone());
                    } else {
                        log(&format!(
                            "[RUST] Reorg Warning: Could not find source for input in cache {:?}",
                            hex::encode(&input.commitment[..8])
                        ));
                    }
                }
            }
            // Remove outputs created in this block
            for output in &tx.outputs {
                utxo_set.remove(&output.commitment);
                let mut cb = crate::blockchain::COINBASE_INDEX.lock().unwrap();
                cb.remove(&output.commitment);
            }
        }
    }

    // Return the block's non-coinbase transactions to the mempool
    {
        let mut tx_pool = TX_POOL.lock().unwrap();
        let utxo_set = blockchain::UTXO_SET.lock().unwrap();
        for tx in block.transactions.iter().filter(|t| !t.inputs.is_empty()) {
            if tx.verify(None, Some(&utxo_set)).is_ok() {
                tx_pool.pending.push(tx.clone());
                tx_pool.fee_total += tx.total_fee();
            }
        }
    }

    // Update the chain's metadata
    chain.current_height -= 1;
    
    // Asynchronously load the new tip to restore its consensus parameters
    if let Some(parent_block) = load_block_from_db(*chain.current_height).await? {
        chain.tip_hash = parent_block.hash();
        chain.current_vrf_threshold = parent_block.vrf_threshold;
        chain.current_vdf_iterations = parent_block.vdf_iterations;
    } else if chain.current_height == 0 {
        // If we rewound to genesis, reset to genesis state
        let genesis = Block::genesis();
        chain.tip_hash = genesis.hash();
        chain.current_vrf_threshold = genesis.vrf_threshold;
        chain.current_vdf_iterations = genesis.vdf_iterations;
    } else {
        return Err(JsValue::from_str("Failed to load new tip block during rewind."));
    }
    
    log(&format!("[RUST] Successfully rewound block at height {}", block.height));
    Ok(())
}

/// Generates a secret nonce (scalar) and public nonce (point) for MuSig2.
#[wasm_bindgen]
pub fn generate_musig_nonces() -> Result<JsValue, JsValue> {
    let mut rng = thread_rng();
    let secret_nonce = Scalar::random(&mut rng);
    // Use B_blinding for the public point to match kernel excess logic
    let public_nonce_point = &secret_nonce * &crate::mimblewimble::PC_GENS.B_blinding;

    #[derive(Serialize)]
    struct NonceResult {
        secret_nonce: Vec<u8>,
        public_nonce_point: Vec<u8>,
    }

    let result = NonceResult {
        secret_nonce: secret_nonce.to_bytes().to_vec(),
        public_nonce_point: public_nonce_point.compress().to_bytes().to_vec(),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| e.into())
}

/// Finalizes a 2-of-2 funding transaction after exchanging partial signatures.
#[wasm_bindgen]
pub fn finalize_funding_transaction(
    channel_json: JsValue,
    incomplete_tx_js: JsValue,
    metadata_js: JsValue,
    counterparty_partial_sig_bytes: Vec<u8>,
    party_a_pubkey_bytes: Vec<u8>,
    party_b_pubkey_bytes: Vec<u8>,
) -> Result<JsValue, JsValue> {
    let mut channel: PaymentChannel = serde_wasm_bindgen::from_value(channel_json)?;
    let incomplete_tx: Transaction = serde_wasm_bindgen::from_value(incomplete_tx_js)?;
    let metadata: MuSigKernelMetadata = serde_wasm_bindgen::from_value(metadata_js)?;
    
    let counterparty_sig_arr: [u8; 32] = counterparty_partial_sig_bytes.try_into()
        .map_err(|_| JsValue::from_str("Partial sig must be 32 bytes"))?;
    
    let party_a_pubkey = CompressedRistretto::from_slice(&party_a_pubkey_bytes)
        .map_err(|_| JsValue::from_str("Invalid Party A pubkey"))?
        .decompress().ok_or_else(|| JsValue::from_str("Failed to decompress Party A pubkey"))?;
        
    let party_b_pubkey = CompressedRistretto::from_slice(&party_b_pubkey_bytes)
        .map_err(|_| JsValue::from_str("Invalid Party B pubkey"))?
        .decompress().ok_or_else(|| JsValue::from_str("Failed to decompress Party B pubkey"))?;

    let final_tx = channel.finalize_funding_transaction(
        incomplete_tx,
        &metadata,
        &counterparty_sig_arr,
        &party_a_pubkey,
        &party_b_pubkey
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    #[derive(Serialize)]
    struct FinalizeResult {
        updated_channel: PaymentChannel,
        final_tx: Transaction,
    }
    
    let result = FinalizeResult { updated_channel: channel, final_tx };
    serde_wasm_bindgen::to_value(&result).map_err(|e| e.into())
}

/// Finalizes a 2-of-2 cooperative close transaction.
#[wasm_bindgen]
pub fn finalize_cooperative_close(
    channel_json: JsValue,
    incomplete_tx_js: JsValue,
    metadata_js: JsValue,
    counterparty_partial_sig_bytes: Vec<u8>,
    party_a_pubkey_bytes: Vec<u8>,
    party_b_pubkey_bytes: Vec<u8>,
) -> Result<JsValue, JsValue> {
    let mut channel: PaymentChannel = serde_wasm_bindgen::from_value(channel_json)?;
    let incomplete_tx: Transaction = serde_wasm_bindgen::from_value(incomplete_tx_js)?;
    let metadata: MuSigKernelMetadata = serde_wasm_bindgen::from_value(metadata_js)?;
    
    let counterparty_sig_arr: [u8; 32] = counterparty_partial_sig_bytes.try_into()
        .map_err(|_| JsValue::from_str("Partial sig must be 32 bytes"))?;
    
    let party_a_pubkey = CompressedRistretto::from_slice(&party_a_pubkey_bytes)
        .map_err(|_| JsValue::from_str("Invalid Party A pubkey"))?
        .decompress().ok_or_else(|| JsValue::from_str("Failed to decompress Party A pubkey"))?;
        
    let party_b_pubkey = CompressedRistretto::from_slice(&party_b_pubkey_bytes)
        .map_err(|_| JsValue::from_str("Invalid Party B pubkey"))?
        .decompress().ok_or_else(|| JsValue::from_str("Failed to decompress Party B pubkey"))?;

    let final_tx = channel.finalize_cooperative_close(
        incomplete_tx,
        &metadata,
        &counterparty_sig_arr,
        &party_a_pubkey,
        &party_b_pubkey
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    #[derive(Serialize)]
    struct FinalizeResult {
        updated_channel: PaymentChannel,
        final_tx: Transaction,
    }
    
    let result = FinalizeResult { updated_channel: channel, final_tx };
    serde_wasm_bindgen::to_value(&result).map_err(|e| e.into())
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

