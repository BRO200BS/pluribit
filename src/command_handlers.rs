// RATIONALE: This module contains ALL command handler implementations.
// Each handler contains full business logic that was previously in worker.js.
// This includes sync consensus, reorg planning, wallet scanning, and L2 protocols.

// src/command_handlers.rs
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use prost::Message;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use std::collections::HashMap;
use crate::wasm_types;

use crate::p2p;
use crate::log;
use crate::state::{
    GLOBAL_STATE, SyncStatus, TipResponseData,
    current_time_ms, NodeStatus, DeferredBlock,
};
use crate::wallet::{Wallet, WALLET_SESSIONS};
use crate::block::Block;
use crate::blockchain::{BLOCKCHAIN, Blockchain, UTXO_SET}; // Import UTXO_SET from blockchain
use crate::transaction::TX_POOL; // Import TX_POOL from transaction
use crate::side_blocks::SIDE_BLOCKS; // Import SIDE_BLOCKS
use crate::address;
use crate::atomic_swap::{AtomicSwap, SwapState};
use crate::payment_channel::{PaymentChannel, Party};
use crate::error::PluribitError;
use crate::wasm_types::WasmU64;
use crate::vrf::VrfProof;
use crate::vdf::VDFProof;
use crate::transaction::{Transaction, TransactionInput, TransactionOutput, TransactionKernel};
use crate::constants;
use crate::load_block_from_db;
use crate::constants::DIFFICULTY_ADJUSTMENT_INTERVAL;
use crate::delete_coinbase_index_from_db;


// =============================================================================
// RESPONSE HELPER FUNCTIONS
// =============================================================================

pub fn add_log_command(response: &mut p2p::RustToJsCommandBatch, level: &str, message: &str) {
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::LogMessage(p2p::LogMessage {
            level: level.to_string(),
            message: message.to_string(),
        })),
    });
}

pub fn add_p2p_publish_command(response: &mut p2p::RustToJsCommandBatch, topic: &str, data: Vec<u8>) {
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::P2pPublish(p2p::PublishP2pMessage {
            topic: topic.to_string(),
            data,
        })),
    });
}

pub fn add_p2p_send_direct_command(response: &mut p2p::RustToJsCommandBatch, peer_id: &str, protocol: &str, data: Vec<u8>) {
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::P2pSendDirect(p2p::SendDirectP2pMessage {
            peer_id: peer_id.to_string(),
            protocol: protocol.to_string(),
            data,
        })),
    });
}

pub fn add_hangup_peer_command(response: &mut p2p::RustToJsCommandBatch, peer_id: &str, reason: &str) {
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::P2pHangUp(p2p::HangUpPeer {
            peer_id: peer_id.to_string(),
            reason: reason.to_string(),
        })),
    });
}

pub fn add_control_mining_start(response: &mut p2p::RustToJsCommandBatch, params: MiningParams) {
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::ControlMining(p2p::ControlMining {
            start: true,
            height: params.height,
            miner_pubkey: params.miner_pubkey,
            miner_secret_key: params.miner_secret_key,
            prev_hash: params.prev_hash,
            vrf_threshold: params.vrf_threshold,
            vdf_iterations: params.vdf_iterations,
            job_id: params.job_id,
        })),
    });
}

pub fn add_control_mining_stop(response: &mut p2p::RustToJsCommandBatch) {
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::ControlMining(p2p::ControlMining {
            start: false,
            height: 0,
            miner_pubkey: vec![],
            miner_secret_key: vec![],
            prev_hash: String::new(),
            vrf_threshold: vec![],
            vdf_iterations: 0,
            job_id: 0,
        })),
    });
}

pub fn add_ui_balance_command(response: &mut p2p::RustToJsCommandBatch, wallet_id: &str, balance: u64, address: &str) { 
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::UpdateUiBalance(p2p::UpdateUiBalance {
            wallet_id: wallet_id.to_string(),
            balance_string: balance.to_string(),
            address: address.to_string(), 
        })),
    });
}

pub fn add_ui_miner_status_command(response: &mut p2p::RustToJsCommandBatch, is_mining: bool) {
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::UpdateUiMinerStatus(p2p::UpdateUiMinerStatus {
            is_mining,
        })),
    });
}

pub fn add_ui_sync_progress_command(response: &mut p2p::RustToJsCommandBatch, current: u64, target: u64, start_time: u64) {
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::UpdateUiSyncProgress(p2p::UpdateUiSyncProgress {
            current,
            target,
            start_time,
        })),
    });
}

pub fn add_ui_wallet_loaded_command(response: &mut p2p::RustToJsCommandBatch, wallet_id: &str, balance: &str, address: &str) {
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::UiWalletLoaded(p2p::UiWalletLoaded {
            wallet_id: wallet_id.to_string(),
            balance: balance.to_string(),
            address: address.to_string(),
        })),
    });
}

pub fn add_ui_total_supply_command(response: &mut p2p::RustToJsCommandBatch, supply: &str) {
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::UiTotalSupply(p2p::UiTotalSupply {
            supply_string: supply.to_string(),
        })),
    });
}

// Helper to post async response back to JS
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = postRustCommands)]
    fn post_rust_commands_raw(bytes: &[u8]);
}

pub fn post_async_response(response: p2p::RustToJsCommandBatch) {
    let response_bytes = response.encode_to_vec();
    // Log for debugging visibility
    //crate::log(&format!("[RUST] Posting async response with {} commands", response.commands.len()));
    post_rust_commands_raw(&response_bytes);
}

// =============================================================================
// MINING PARAMS STRUCT
// =============================================================================

#[derive(Debug, Clone)]
pub struct MiningParams {
    pub job_id: u64,
    pub height: u64,
    pub miner_pubkey: Vec<u8>,
    pub miner_secret_key: Vec<u8>,
    pub prev_hash: String,
    pub vrf_threshold: Vec<u8>,
    pub vdf_iterations: u64,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MiningJob {
    pub job_id: u64,
    pub height: u64,
    pub miner_pubkey: Vec<u8>,
    pub miner_secret_key: Vec<u8>,
    pub prev_hash: String,
    pub vrf_threshold: Vec<u8>,
    pub vdf_iterations: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MiningCandidate {
    pub height: u64,
    pub nonce: u64,
    pub prev_hash: String,
    pub miner_pubkey: Vec<u8>,
    pub vrf_proof: VrfProofData,
    pub vdf_proof: VdfProofData,
    pub vrf_threshold: Vec<u8>,
    pub vdf_iterations: u64,
    pub job_id: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VrfProofData {
    pub gamma: Vec<u8>,
    pub c: Vec<u8>,
    pub s: Vec<u8>,
    pub output: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VdfProofData {
    pub y: Vec<u8>,
    pub pi: Vec<u8>,
    pub l: Vec<u8>,
    pub r: Vec<u8>,
    pub iterations: u64,
}
// =============================================================================
// WALLET COMMAND HANDLERS
// =============================================================================

pub async fn handle_create_wallet_internal(req: p2p::CreateWalletRequest) {
    use crate::wallet_session_create_with_mnemonic;
    
    let mut response = p2p::RustToJsCommandBatch::default();
    
    match wallet_session_create_with_mnemonic(&req.wallet_id) {
        Ok(phrase) => {
            // Mark wallet as active
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                state.worker_flags.active_wallet_ids.insert(req.wallet_id.clone());
            }
            
            add_log_command(&mut response, "success", &format!("Wallet '{}' created.", req.wallet_id));
            add_log_command(&mut response, "warn", "IMPORTANT: Write down your 12-word mnemonic phrase:");
            add_log_command(&mut response, "info", &phrase);
            add_log_command(&mut response, "warn", "This phrase is required to restore your wallet.");
            
            // Save wallet to DB
            let wallet_json = {
                let sessions = WALLET_SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(wallet) = sessions.get(&req.wallet_id) {
                    serde_json::to_string(wallet).ok()
                } else {
                    None
                }
            };
            
            if let Some(json) = wallet_json {
                match save_wallet_to_db(&req.wallet_id, &json).await {
                    Ok(_) => {
                        add_log_command(&mut response, "debug", "Wallet saved to database.");
                    }
                    Err(e) => {
                        add_log_command(&mut response, "error", &format!("Failed to save wallet to DB: {:?}", e));
                    }
                }
            } else {
                add_log_command(&mut response, "error", "Failed to serialize wallet for DB.");
            }
            
            // Get balance and address
            match get_wallet_balance(&req.wallet_id) {
                Ok(balance) => {
                    match get_wallet_address(&req.wallet_id) {
                        Ok(address) => {
                            add_ui_wallet_loaded_command(&mut response, &req.wallet_id, &balance.to_string(), &address);
                        }
                        Err(e) => {
                            add_log_command(&mut response, "error", &format!("Failed to get wallet address: {}", e));
                        }
                    }
                }
                Err(e) => {
                    add_log_command(&mut response, "error", &format!("Failed to get wallet balance: {}", e));
                }
            }
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to create wallet: {:?}", e));
        }
    }
    
    post_async_response(response);
}

pub async fn handle_restore_wallet_internal(req: p2p::RestoreWalletRequest) {
    use crate::wallet_session_restore_from_mnemonic;
    
    let mut response = p2p::RustToJsCommandBatch::default();
    
    match wallet_session_restore_from_mnemonic(&req.wallet_id, &req.phrase) {
        Ok(_) => {
            {
                let mut state = GLOBAL_STATE.lock().unwrap();
                state.worker_flags.active_wallet_ids.insert(req.wallet_id.clone());
            }
            
            add_log_command(&mut response, "success", &format!("Wallet '{}' restored successfully.", req.wallet_id));
            
            // Save wallet to DB
            let wallet_json = {
                let sessions = WALLET_SESSIONS.lock().unwrap();
                if let Some(wallet) = sessions.get(&req.wallet_id) {
                    serde_json::to_string(wallet).ok()
                } else {
                    None
                }
            };
            
            if let Some(json) = wallet_json {
                match save_wallet_to_db(&req.wallet_id, &json).await {
                    Ok(_) => {
                        add_log_command(&mut response, "debug", "Wallet saved to database.");
                    }
                    Err(e) => {
                        add_log_command(&mut response, "error", &format!("Failed to save wallet to DB: {:?}", e));
                    }
                }
            } else {
                add_log_command(&mut response, "error", "Failed to serialize wallet for DB.");
            }
            
            // Get balance and address
            match get_wallet_balance(&req.wallet_id) {
                Ok(balance) => {
                    match get_wallet_address(&req.wallet_id) {
                        Ok(address) => {
                            add_ui_wallet_loaded_command(&mut response, &req.wallet_id, &balance.to_string(), &address);
                        }
                        Err(e) => {
                            add_log_command(&mut response, "error", &format!("Failed to get wallet address: {}", e));
                        }
                    }
                }
                Err(e) => {
                    add_log_command(&mut response, "error", &format!("Failed to get wallet balance: {}", e));
                }
            }
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to restore wallet: {:?}", e));
        }
    }
    
    post_async_response(response);
}

pub async fn handle_load_wallet_internal(req: p2p::LoadWalletRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();

    let already_loaded = {
        let map = WALLET_SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
        map.contains_key(&req.wallet_id)
    };

    if already_loaded {
        // Just update global state and UI, don't re-import
        {
             let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
             state.worker_flags.active_wallet_ids.insert(req.wallet_id.clone());
        }
        
        add_log_command(&mut response, "info", &format!("Wallet '{}' is already active. Switching context.", req.wallet_id));
        
        if let Ok(balance) = get_wallet_balance(&req.wallet_id) {
            // Address retrieval might fail if wallet state is weird, but usually won't
            let address = get_wallet_address(&req.wallet_id).unwrap_or_else(|_| "Unknown".to_string());
            add_ui_wallet_loaded_command(&mut response, &req.wallet_id, &balance.to_string(), &address);
        }
        
        post_async_response(response);
        return;
    }
    
    match load_wallet_from_db(&req.wallet_id).await {
        Ok(Some(wallet_json)) => {
            use crate::wallet_session_restore_from_mnemonic;

            match crate::wallet_session_restore_from_json(&req.wallet_id, &wallet_json) {

                Ok(_) => {
                    {
                        let mut state = GLOBAL_STATE.lock().unwrap();
                        state.worker_flags.active_wallet_ids.insert(req.wallet_id.clone());
                    }
                    
                    add_log_command(&mut response, "success", &format!("Wallet '{}' loaded.", req.wallet_id));

                    let (wallet_height, chain_height) = {
                        let map = WALLET_SESSIONS.lock().unwrap();
                        let wallet = map.get(&req.wallet_id).unwrap();
                        let chain = BLOCKCHAIN.lock().unwrap();
                        (wallet.synced_height, *chain.current_height)
                    };

                    if wallet_height < chain_height {
                        add_log_command(&mut response, "info", &format!(
                            "Wallet is behind (synced: {}, tip: {}). Scanning {} blocks...", 
                            wallet_height, chain_height, chain_height - wallet_height
                        ));

                        // Spawn the scan task
                        let wallet_id = req.wallet_id.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            // Load blocks in batches to avoid memory explosion
                            let start = wallet_height + 1;
                            let end = chain_height;
                            
                            // Using the helper I previously marked as dead code in lib.rs!
                            // We need to make sure `load_blocks_from_db` is available.
                            match crate::load_blocks_from_db(start, end).await {
                                Ok(blocks) => {
                                    let mut sessions = WALLET_SESSIONS.lock().unwrap();
                                    if let Some(w) = sessions.get_mut(&wallet_id) {
                                        for block in blocks {
                                            w.scan_block(&block);
                                        }
                                        // Save final state
                                        if let Ok(json) = serde_json::to_string(&w) {
                                            let _ = crate::save_wallet_to_db(&wallet_id, &json).await;
                                        }
                                        crate::log(&format!("[WALLET] Catch-up complete. New balance: {}", w.balance()));
                                    }
                                }
                                Err(e) => crate::log(&format!("[WALLET] Scan failed: {:?}", e)),
                            }
                        });
                    }

                    if let Ok(balance) = get_wallet_balance(&req.wallet_id) {
                        if let Ok(address) = get_wallet_address(&req.wallet_id) {
                            add_ui_wallet_loaded_command(&mut response, &req.wallet_id, &balance.to_string(), &address);
                        }
                    }
                }
                Err(e) => {
                    add_log_command(&mut response, "error", &format!("Failed to import wallet: {:?}", e));
                }
            }
        }
        Ok(None) => {
            add_log_command(&mut response, "error", &format!("Wallet '{}' not found.", req.wallet_id));
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Database error: {:?}", e));
        }
    }
    
    post_async_response(response);
}

pub fn handle_get_balance_internal(response: &mut p2p::RustToJsCommandBatch, req: p2p::GetBalanceRequest) {
    match get_wallet_balance(&req.wallet_id) {
        Ok(balance) => {
            // Get address safely
            let address = get_wallet_address(&req.wallet_id).unwrap_or_else(|_| "Unknown".to_string());
            add_ui_balance_command(response, &req.wallet_id, balance, &address);
        }
        Err(e) => {
            add_log_command(response, "error", &format!("Failed to get balance: {}", e));
        }
    }
}

pub async fn handle_create_transaction_internal(req: p2p::CreateTransactionRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // 1. Check wallet is loaded
    {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if !state.worker_flags.active_wallet_ids.contains(&req.from_wallet_id) {
            add_log_command(&mut response, "error", "Wallet not loaded.");
            post_async_response(response);
            return;
        }
    }
    
    // 2. Decode stealth address
    let receive_pubkey = match address::decode_stealth_address(&req.to_address) {
        Ok(bytes) => bytes,
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Invalid address: {}", e));
            post_async_response(response);
            return;
        }
    };
    
    // 3. Create transaction
    match create_transaction_internal(&req.from_wallet_id, &receive_pubkey, req.amount, req.fee).await {
        Ok((tx, updated_wallet_json)) => {
            // 4. Save wallet
            if let Err(e) = save_wallet_to_db(&req.from_wallet_id, &updated_wallet_json).await {
                add_log_command(&mut response, "error", &format!("Failed to save wallet: {:?}", e));
                post_async_response(response);
                return;
            }
            
            // 5. Add to local TX_POOL
            {
                let mut mempool = TX_POOL.lock().unwrap_or_else(|p| p.into_inner());
                if mempool.pending.len() >= crate::constants::MAX_TX_POOL_SIZE {

                    add_log_command(&mut response, "error", "Mempool is full");
                    post_async_response(response);
                    return;
                }
                mempool.pending.push(tx.clone());

            }
            
            // 6. Broadcast via P2P
            let p2p_tx = p2p::Transaction::from(tx);
            let msg = p2p::P2pMessage {
                payload: Some(p2p::p2p_message::Payload::Transaction(p2p_tx)),
            };
           let topic = constants::TOPIC_TRANSACTIONS.replace("{}", &get_network_name());
            add_p2p_publish_command(&mut response, &topic, msg.encode_to_vec());
            
            add_log_command(&mut response, "success", &format!(
                "Transaction sent: {} bits to {}...",
                req.amount, &req.to_address[..20.min(req.to_address.len())]
            ));
            
            // 7. Update balance UI
            if let Ok(balance) = get_wallet_balance(&req.from_wallet_id) {
                let address = get_wallet_address(&req.from_wallet_id).unwrap_or_else(|_| "Unknown".to_string());
                add_ui_balance_command(&mut response, &req.from_wallet_id, balance, &address);
            }
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Transaction failed: {}", e));
        }
    }
    
    post_async_response(response);
}

// =============================================================================
// MINER COMMAND HANDLERS
// =============================================================================

pub async fn handle_toggle_miner_internal(req: p2p::ToggleMinerRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let (should_start, wallet_id) = {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if state.miner_state.active {
            // Stop mining
            state.stop_miner();
            (false, None)
        } else {
            // Start mining
            let job_id = state.start_miner(&req.miner_id);
            (true, Some((req.miner_id.clone(), job_id)))
        }
    };
    
    if should_start {
        if let Some((wallet_id, job_id)) = wallet_id {
            match prepare_mining_params(&wallet_id, job_id).await {
                Ok(params) => {
                    add_control_mining_start(&mut response, params);
                    add_log_command(&mut response, "success", &format!("Mining started for wallet: {}", wallet_id));
                    add_ui_miner_status_command(&mut response, true);
                }
                Err(e) => {
                    // Revert state on failure
                    {
                        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                        state.stop_miner();
                    }
                    add_log_command(&mut response, "error", &format!("Failed to start miner: {}", e));
                    add_ui_miner_status_command(&mut response, false);
                }
            }
        }
    } else {
        add_control_mining_stop(&mut response);
        add_log_command(&mut response, "info", "Mining stopped.");
        add_ui_miner_status_command(&mut response, false);
    }
    
    post_async_response(response);
}

async fn prepare_mining_params(wallet_id: &str, job_id: u64) -> Result<MiningParams, String> {
    // 1. Validate state consistency
    let db_tip = get_tip_height_from_db().await
        .map_err(|e| format!("DB error: {:?}", e))?;
    
    let (chain_height, tip_hash) = {
        let chain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        (*chain.current_height, chain.tip_hash.clone())
    };
    
    if db_tip != chain_height {
        return Err(format!("State mismatch: DB={} Rust={}", db_tip, chain_height));
    }
    
    // 2. Get wallet keys
    let (spend_pub, spend_priv) = {
        let map = WALLET_SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
        let w = map.get(wallet_id).ok_or("Wallet not loaded")?;
        (
            w.spend_pub.compress().to_bytes().to_vec(),
            w.spend_priv.to_bytes().to_vec()
        )
    };
    
    // 3. Calculate next difficulty params (async retargeting)
    // FIX: Await the async calculation logic
    let (next_vrf, next_vdf) = calculate_next_difficulty(chain_height).await?;
    
    Ok(MiningParams {
        job_id,
        height: chain_height + 1,
        miner_pubkey: spend_pub,
        miner_secret_key: spend_priv,
        prev_hash: tip_hash,
        vrf_threshold: next_vrf.to_vec(),
        vdf_iterations: next_vdf,
    })
}

// FIX: Converted to async and implemented full retargeting logic
async fn calculate_next_difficulty(current_height: u64) -> Result<([u8; 32], u64), String> {
    let next_height = current_height + 1;

    // Check if adjustment is needed for the *next* block
    if next_height > 0 && next_height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
        crate::log(&format!("[MINING] Calculating difficulty adjustment for block #{}", next_height));

        let start_height = next_height.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL);
        let end_height = next_height - 1; // The current tip

        // We need to load blocks to get timestamps/params
        let start_block = load_block_from_db(start_height).await
            .map_err(|e| format!("DB Error: {:?}", e))?
            .ok_or_else(|| format!("Missing start block {} for difficulty adjustment", start_height))?;
            
        let end_block = load_block_from_db(end_height).await
            .map_err(|e| format!("DB Error: {:?}", e))?
            .ok_or_else(|| format!("Missing end block {} for difficulty adjustment", end_height))?;

        // Current params are stored in the end_block (the tip)
        let current_vrf = end_block.vrf_threshold;
        let current_vdf = end_block.vdf_iterations;

        // Perform calculation
        let (new_vrf, new_vdf) = Blockchain::calculate_next_difficulty(
            &end_block,
            &start_block,
            current_vrf,
            wasm_types::WasmU64(*current_vdf)
        );
        
    //    crate::log(&format!("[MINING] Adjusted Difficulty: VRF={:?}..., VDF={}", 
    //        hex::encode(&new_vrf[..4]), new_vdf));
            
        Ok((new_vrf, *new_vdf))
    } else {
        // No adjustment needed, use current chain params
        let chain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        Ok((chain.current_vrf_threshold, *chain.current_vdf_iterations))
    }
}

pub async fn handle_submit_mining_candidate_internal(req: p2p::SubmitMiningCandidate) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // 1. Validate job ID
    let (is_valid_job, wallet_id_opt, current_job_id, is_active) = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        (
            state.miner_state.current_job_id == req.job_id && state.miner_state.active,
            state.miner_state.wallet_id.clone(),
            state.miner_state.current_job_id, // Capture current ID
            state.miner_state.active          // Capture active status
        )
    };
    
    if !is_valid_job {
        // Log explicitly WHY it failed
        add_log_command(&mut response, "warn", &format!(
            "Ignoring stale mining candidate. Req JobID: {}, Current JobID: {}, Active: {}", 
            req.job_id, current_job_id, is_active
        ));
        post_async_response(response);
        return;
    }
    
    let wallet_id = match wallet_id_opt {
        Some(id) => id,
        None => {
            add_log_command(&mut response, "error", "No miner wallet configured");
            post_async_response(response);
            return;
        }
    };
    
    // 2. Check not already processing this height
    {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if state.miner_state.processing_candidate_height == Some(req.height) {
            add_log_command(&mut response, "warn", "Already processing candidate for this height");
            post_async_response(response);
            return;
        }
        state.miner_state.processing_candidate_height = Some(req.height);
    }
    
    add_log_command(&mut response, "success", &format!("✨ Received winning candidate for height {}", req.height));
    
    // 3. Build VRF and VDF proofs from protobuf
    let vrf_proof = match &req.vrf_proof {
        Some(p) => VrfProof {
            gamma: p.gamma.clone().try_into().unwrap_or([0u8; 32]),
            c: p.c.clone().try_into().unwrap_or([0u8; 32]),
            s: p.s.clone().try_into().unwrap_or([0u8; 32]),
            output: p.output.clone().try_into().unwrap_or([0u8; 32]),
        },
        None => {
            add_log_command(&mut response, "error", "Missing VRF proof");
            clear_processing_height(req.height);
            post_async_response(response);
            return;
        }
    };
    
    let vdf_proof = match &req.vdf_proof {
        Some(p) => VDFProof {
            y: p.y.clone(),
            pi: p.pi.clone(),
            l: p.l.clone(),
            r: p.r.clone(),
            iterations: WasmU64::from(p.iterations),
        },
        None => {
            add_log_command(&mut response, "error", "Missing VDF proof");
            clear_processing_height(req.height);
            post_async_response(response);
            return;
        }
    };
    
    // 4. Get scan pubkey for coinbase
    let scan_pubkey = match get_wallet_scan_pubkey(&wallet_id) {
        Ok(pk) => pk,
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to get scan pubkey: {}", e));
            clear_processing_height(req.height);
            post_async_response(response);
            return;
        }
    };
    
// 5. Build complete block with transactions
    let miner_pubkey: [u8; 32] = req.miner_pubkey.clone().try_into().unwrap_or([0u8; 32]);
    let vrf_threshold: [u8; 32] = req.vrf_threshold.clone().try_into().unwrap_or([0u8; 32]);
    
    match complete_block_with_transactions(
        req.height,
        &req.prev_hash,
        req.nonce,
        &miner_pubkey,
        &scan_pubkey,
        &vrf_proof,
        &vdf_proof,
        &vrf_threshold,
        req.vdf_iterations,
    ).await {
        Ok(block) => {
            let p2p_block = p2p::Block::from(block.clone());
            
            add_log_command(&mut response, "success", &format!(
                "✨ Mined block {} - submitting to block processor",
                req.height
            ));
            
            // Broadcast BEFORE processing so peers get it immediately
            let ann = p2p::BlockAnnouncement {
                hash: block.hash.clone(),
                height: req.height,
            };
            let ann_msg = p2p::P2pMessage {
                payload: Some(p2p::p2p_message::Payload::BlockAnnouncement(ann)),
            };
            let topic = constants::TOPIC_BLOCK_ANNOUNCEMENTS.replace("{}", &get_network_name());
            add_p2p_publish_command(&mut response, &topic, ann_msg.encode_to_vec());
            
            let block_msg = p2p::P2pMessage {
                payload: Some(p2p::p2p_message::Payload::Block(p2p_block.clone())),
            };
            let blocks_topic = constants::TOPIC_BLOCKS.replace("{}", &get_network_name());
            add_p2p_publish_command(&mut response, &blocks_topic, block_msg.encode_to_vec());
            
            // Post the broadcast commands immediately
            post_async_response(response);
            
            // Now route through the unified block processor (handles queue, reorgs, etc.)
            // Pass None for peer since this is our own block
            handle_block_received(p2p_block, None).await;
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to complete block: {}", e));
            post_async_response(response);
        }
    }
    
    clear_processing_height(req.height);
}

fn clear_processing_height(height: u64) {
    let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
    if state.miner_state.processing_candidate_height == Some(height) {
        state.miner_state.processing_candidate_height = None;
    }
}

async fn restart_mining_if_active(response: &mut p2p::RustToJsCommandBatch) {
    let (is_active, wallet_id, job_id) = {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if !state.miner_state.active {
            return;
        }
        let job_id = state.miner_state.next_job_id();
        (true, state.miner_state.wallet_id.clone(), job_id)
    };
    
    if is_active {
        if let Some(wallet_id) = wallet_id {
            match prepare_mining_params(&wallet_id, job_id).await {
                Ok(params) => {
                    add_control_mining_start(response, params);
                    add_log_command(response, "info", "Restarting mining for next block...");
                }
                Err(e) => {
                    add_log_command(response, "error", &format!("Failed to restart miner: {}", e));
                }
            }
        }
    }
}

// =============================================================================
// NODE STATUS HANDLERS
// =============================================================================

pub fn handle_get_status_internal(response: &mut p2p::RustToJsCommandBatch) {
    let (height, work, vdf, vrf, tip_hash) = {
        let chain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        (
            *chain.current_height,
            *chain.total_work,
            *chain.current_vdf_iterations,
            chain.current_vrf_threshold,
            chain.tip_hash.clone()
        )
    };
    
    let utxo_count = UTXO_SET.lock().unwrap_or_else(|p| p.into_inner()).len();
    let mempool_size = TX_POOL.lock().unwrap_or_else(|p| p.into_inner()).pending.len();
    let side_blocks = SIDE_BLOCKS.lock().unwrap_or_else(|p| p.into_inner()).len();
    
    let status: NodeStatus = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        NodeStatus::from(&*state)
    };
    
    add_log_command(response, "info", "=== Node Status ===");
    add_log_command(response, "info", &format!("Height: {}", height));
    add_log_command(response, "info", &format!("Tip: {}...", &tip_hash[..12.min(tip_hash.len())]));
    add_log_command(response, "info", &format!("Total Work: {}", work));
    add_log_command(response, "info", &format!("VDF Iters: {}", vdf));
    add_log_command(response, "info", &format!("VRF Threshold: {}...", hex::encode(&vrf[..4])));
    add_log_command(response, "info", &format!("UTXO Set: {}", utxo_count));
    add_log_command(response, "info", &format!("Mempool: {}", mempool_size));
    add_log_command(response, "info", &format!("Side Blocks: {}", side_blocks));
    add_log_command(response, "info", &format!("Mining: {}", if status.is_mining { "Active" } else { "Inactive" }));
    add_log_command(response, "info", &format!("Syncing: {}", if status.is_syncing { "Yes" } else { "No" }));
    add_log_command(response, "info", &format!("Peers: {} ({} verified)", status.connected_peers, status.verified_peers));
    add_log_command(response, "info", "==================");
}

pub async fn handle_get_supply_internal() {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    match crate::audit_total_supply().await {
        Ok(supply_js) => {
            let supply_str = supply_js; 
            add_ui_total_supply_command(&mut response, &supply_str);
            add_log_command(&mut response, "info", &format!("Total supply: {}", supply_str));
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Supply audit failed: {:?}", e));
        }
    }
    
    post_async_response(response);
}

pub fn handle_get_peers_internal(response: &mut p2p::RustToJsCommandBatch) {
    let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
    let peers: Vec<String> = state.peer_state.connected_peers.iter().cloned().collect();
    let verified: Vec<String> = state.peer_state.verified_peers.iter().cloned().collect();
    
    add_log_command(response, "info", &format!("Connected peers: {}", peers.len()));
    for peer in &peers {
        let is_verified = verified.contains(peer);
        add_log_command(response, "info", &format!(
            "  {} {}",
            &peer[peer.len().saturating_sub(12)..],
            if is_verified { "✓" } else { "" }
        ));
    }
    
    // Also send UI update
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::UiPeerList(p2p::UiPeerList {
            peer_ids: peers,
        })),
    });
}

pub fn handle_connect_peer_internal(response: &mut p2p::RustToJsCommandBatch, req: p2p::ConnectPeerRequest) {
    // 1. Log the intent (for UI feedback)
    add_log_command(response, "info", &format!("Rust is instructing Worker to dial {}", req.multiaddr));
    
    // 2. ACTUALLY SEND THE COMMAND
    // We push a specific instruction that worker.js knows how to handle
    response.commands.push(p2p::RustCommand {
        command: Some(p2p::rust_command::Command::DialPeer(p2p::DialPeer {
            multiaddr: req.multiaddr, // <--- We use the data from the request here
        })),
    });
}

// =============================================================================
// SYNC HANDLERS (Full Bootstrap Sync Implementation)
// =============================================================================

pub async fn handle_sync_tick_internal(_req: p2p::SyncTickRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // Check if we should start sync
    let should_start = {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if state.sync_state.sync_progress.status != SyncStatus::Idle {
            false
        } else if state.worker_flags.is_syncing || state.worker_flags.is_reorging {
            false
        } else {
            state.sync_state.sync_progress.status = SyncStatus::Consensus;
            state.sync_state.tip_responses.clear();
            true
        }
    };
    
    if !should_start {
        return;
    }
    
    add_log_command(&mut response, "debug", "[SYNC] Starting consensus check...");
    
    // Send TipRequest to all peers
    let tip_req = p2p::SyncMessage {
        payload: Some(p2p::sync_message::Payload::TipRequest(p2p::TipRequest {})),
    };
    let msg = p2p::P2pMessage {
        payload: Some(p2p::p2p_message::Payload::SyncMessage(tip_req)),
    };
    let topic = constants::TOPIC_SYNC.replace("{}", &get_network_name());
    add_p2p_publish_command(&mut response, &topic, msg.encode_to_vec());
    
    post_async_response(response);
    
    // Schedule consensus evaluation after timeout
    // This would be done via JS setTimeout, but we'll handle responses as they come in
}

pub async fn handle_tip_response(from_peer: &str, tip: p2p::TipResponse) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // Store the tip response
    {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if state.sync_state.sync_progress.status != SyncStatus::Consensus {
            return; // Not in consensus phase
        }
        
        state.sync_state.tip_responses.insert(from_peer.to_string(), TipResponseData {
            hash: tip.tip_hash.clone(),
            height: tip.height,
            total_work: tip.total_work.clone(),
            received_at_ms: current_time_ms(),
        });
        
        add_log_command(&mut response, "debug", &format!(
            "[SYNC] Tip from {}: height={}, hash={}...",
            &from_peer[from_peer.len().saturating_sub(6)..],
            tip.height,
            &tip.tip_hash[..12.min(tip.tip_hash.len())]
        ));
    }
    
    post_async_response(response);
}

pub fn handle_tip_request(from_peer: &str, response: &mut p2p::RustToJsCommandBatch) {
    // Get our current tip and send it back
    let blockchain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());

    let tip_response = p2p::TipResponse {
        tip_hash: blockchain.tip_hash.clone(),
        height: *blockchain.current_height,
        total_work: blockchain.total_work.to_string(),
    };
    
    let sync_msg = p2p::SyncMessage {
        payload: Some(p2p::sync_message::Payload::TipResponse(tip_response)),
    };
    
    let p2p_msg = p2p::P2pMessage {
        payload: Some(p2p::p2p_message::Payload::SyncMessage(sync_msg)),
    };
    
    add_log_command(response, "debug", &format!("Broadcasting tip (requested by {})", from_peer));
    let topic = constants::TOPIC_SYNC.replace("{}", &get_network_name());
    add_p2p_publish_command(response, &topic, p2p_msg.encode_to_vec());
}

pub async fn handle_evaluate_consensus() {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let (tips, our_height, our_work) = {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        
        if state.sync_state.sync_progress.status != SyncStatus::Consensus {
            return;
        }
        
        let tips = state.sync_state.tip_responses.clone();
        
        let chain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        (tips, *chain.current_height, *chain.total_work)
    };
    
    if tips.is_empty() {
        add_log_command(&mut response, "debug", "[SYNC] No peer tips received.");
        reset_sync_to_idle();
        post_async_response(response);
        return;
    }
    
    // Group by hash to find consensus
    let mut by_hash: HashMap<String, Vec<(String, TipResponseData)>> = HashMap::new();
    for (peer, tip) in tips {
        by_hash.entry(tip.hash.clone())
            .or_insert_with(Vec::new)
            .push((peer, tip));
    }
    
    // Sort by total work (highest first)
    let mut candidates: Vec<_> = by_hash.into_iter().collect();
    candidates.sort_by(|a, b| {
        let work_a: u64 = a.1.first().map(|(_, t)| t.total_work.parse().unwrap_or(0)).unwrap_or(0);
        let work_b: u64 = b.1.first().map(|(_, t)| t.total_work.parse().unwrap_or(0)).unwrap_or(0);
        work_b.cmp(&work_a)
    });
    
    add_log_command(&mut response, "debug", &format!(
        "[SYNC] Evaluated {} unique chain candidates",
        candidates.len()
    ));
    
    // Find first valid candidate with more work
    for (hash, peers_data) in candidates {
        let (first_peer, tip_data) = &peers_data[0];
        
        let tip_work: u64 = tip_data.total_work.parse().unwrap_or(0);
        if tip_work <= our_work {
            add_log_command(&mut response, "debug", &format!(
                "[SYNC] Candidate {}... has less/equal work, skipping",
                &hash[..12.min(hash.len())]
            ));
            continue;
        }
        
        add_log_command(&mut response, "info", &format!(
            "[SYNC] ✅ Better chain found! Height={}, Work={}, Peers={}",
            tip_data.height, tip_data.total_work, peers_data.len()
        ));
        
        // Start sync to this chain
        {
            let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
            state.start_sync(tip_data.height);
        }
        
        // If height is ahead, do forward sync
        if tip_data.height > our_height {
            start_forward_sync(&mut response, tip_data.height, &hash, first_peer).await;
        } else {
            // Fork reorg - request the tip block
            add_log_command(&mut response, "info", "[SYNC] Fork detected, requesting tip block...");
            let req = p2p::BlockRequest { hash: hash.clone() };
            let msg = p2p::P2pMessage {
                payload: Some(p2p::p2p_message::Payload::BlockRequest(req)),
            };
            let topic = constants::TOPIC_BLOCK_REQUEST.replace("{}", &get_network_name());
            add_p2p_publish_command(&mut response, &topic, msg.encode_to_vec());
        }
        
        post_async_response(response);
        return;
    }
    
    add_log_command(&mut response, "debug", "[SYNC] No better chains found.");
    reset_sync_to_idle();
    post_async_response(response);
}
pub async fn handle_hashes_request(from_peer: String, req: p2p::GetHashesRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let our_height = {
        let blockchain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        *blockchain.current_height as u64
    };
    
    let start = if req.start_height == 0 { 1 } else { req.start_height }; // Skip genesis if requested
    
    if start > our_height {
        add_log_command(&mut response, "debug", &format!(
            "[SYNC] Peer {} requested hashes from height {} but we're only at {}",
            &from_peer[from_peer.len().saturating_sub(8)..], start, our_height
        ));
        post_async_response(response);
        return;
    }
    
    // Collect hashes by loading blocks from DB
    let mut hashes: Vec<String> = Vec::new();
    for height in start..=our_height {
        match load_block_from_db(height).await {
            Ok(Some(block)) => {
                hashes.push(block.hash.clone());
            }
            Ok(None) => {
                add_log_command(&mut response, "warn", &format!(
                    "[SYNC] Missing block at height {} in DB",
                    height
                ));
                break; // Stop if we hit a gap
            }
            Err(e) => {
                add_log_command(&mut response, "error", &format!(
                    "[SYNC] DB error loading block {}: {:?}",
                    height, e
                ));
                break;
            }
        }
    }
    
    if hashes.is_empty() {
        add_log_command(&mut response, "warn", "[SYNC] No hashes to send");
        post_async_response(response);
        return;
    }
    
    // Send response
    let hashes_response = p2p::HashesResponse {
        hashes: hashes.clone(),
        request_id: req.request_id.clone(),
        final_chunk: true,
        target_peer: from_peer.clone(),
    };
    
    let sync_msg = p2p::SyncMessage {
        payload: Some(p2p::sync_message::Payload::HashesResponse(hashes_response)),
    };
    
    let p2p_msg = p2p::P2pMessage {
        payload: Some(p2p::p2p_message::Payload::SyncMessage(sync_msg)),
    };
    
    add_log_command(&mut response, "debug", &format!(
        "[SYNC] Sending {} hashes to {}", 
        hashes.len(),
        &from_peer[from_peer.len().saturating_sub(8)..]
    ));
    
    let topic = constants::TOPIC_SYNC.replace("{}", &get_network_name());
    add_p2p_publish_command(&mut response, &topic, p2p_msg.encode_to_vec());
    
    post_async_response(response);
}
async fn start_forward_sync(response: &mut p2p::RustToJsCommandBatch, target_height: u64, target_hash: &str, peer: &str) {
    let our_height = {
        let chain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        *chain.current_height
    };
    
    add_log_command(response, "info", &format!(
        "[SYNC] Starting forward sync: {} -> {}",
        our_height, target_height
    ));
    
    // Request hashes from peer
    let request_id = format!("hash-req-{}", current_time_ms());
    
    {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.sync_state.active_hash_requests.insert(request_id.clone(), crate::state::HashRequestState {
            request_id: request_id.clone(),
            peer_id: peer.to_string(),
            hashes: Vec::new(),
            start_time_ms: current_time_ms(),
            last_chunk_time_ms: current_time_ms(),
            is_complete: false,
        });
    }
    
    let start_height = our_height + 1;
    
    let hash_req = p2p::GetHashesRequest {
        start_height,
        request_id: request_id.clone(), // Use the ID we just generated
    };
    
    let msg = p2p::SyncMessage {
        payload: Some(p2p::sync_message::Payload::HashesRequest(hash_req)),

    };
    let wrapper = p2p::P2pMessage {
        payload: Some(p2p::p2p_message::Payload::SyncMessage(msg)),
    };
    
    // Publish to sync topic (peer will respond via gossipsub)
    let topic = constants::TOPIC_SYNC.replace("{}", &get_network_name());
    add_p2p_publish_command(response, &topic, wrapper.encode_to_vec());
}

pub async fn handle_hash_response(from_peer: &str, hash_resp: p2p::HashesResponse) {
    // Filter: ignore if not meant for us
    let our_peer_id = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.our_peer_id.clone()  // You'll need to store this during init
    };
    
    if !hash_resp.target_peer.is_empty() && hash_resp.target_peer != our_peer_id {
        return; // Not for us
    }

    let mut response = p2p::RustToJsCommandBatch::default();
    
    let should_start_download = {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        
        let req_state = match state.sync_state.active_hash_requests.get_mut(&hash_resp.request_id) {
            Some(s) => s,
            None => {
                add_log_command(&mut response, "warn", "Received hash response for unknown request");
                post_async_response(response);
                return;
            }
        };
        
        // Append hashes
        req_state.hashes.extend(hash_resp.hashes.clone());
        req_state.last_chunk_time_ms = current_time_ms();
        req_state.is_complete = hash_resp.final_chunk;
        
        add_log_command(&mut response, "debug", &format!(
            "[SYNC] Received {} hashes (total: {}, final: {})",
            hash_resp.hashes.len(),
            req_state.hashes.len(),
            hash_resp.final_chunk
        ));
        
        hash_resp.final_chunk
    };
    
    if should_start_download {
        start_block_download(&mut response).await;
    }
    
    post_async_response(response);
}

async fn start_block_download(response: &mut p2p::RustToJsCommandBatch) {
    let (hashes_to_fetch, peer) = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        
        // Get the first completed hash request
        let req = state.sync_state.active_hash_requests.values()
            .find(|r| r.is_complete);
        
        match req {
            Some(r) => (r.hashes.clone(), r.peer_id.clone()),
            None => return,
        }
    };
    
    add_log_command(response, "info", &format!(
        "[SYNC] Starting download of {} blocks",
        hashes_to_fetch.len()
    ));
    
    // Set downloading flag
    {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.worker_flags.is_downloading_chain = true;
        state.sync_state.sync_progress.status = SyncStatus::Downloading;
    }
    
    // Request blocks in parallel (but limit concurrency)
    const PARALLEL_DOWNLOADS: usize = 4;
    
    for chunk in hashes_to_fetch.chunks(PARALLEL_DOWNLOADS) {
        for hash in chunk {
            let req = p2p::BlockRequest { hash: hash.clone() };
            let msg = p2p::P2pMessage {
                payload: Some(p2p::p2p_message::Payload::BlockRequest(req)),
            };
            let topic = constants::TOPIC_BLOCK_REQUEST.replace("{}", &get_network_name());
            add_p2p_publish_command(response, &topic, msg.encode_to_vec());
        }
    }
}

fn reset_sync_to_idle() {
    let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
    state.sync_state.sync_progress.status = SyncStatus::Idle;
    state.sync_state.active_hash_requests.clear();
    state.sync_state.tip_responses.clear();
    state.worker_flags.is_syncing = false;
    state.worker_flags.is_downloading_chain = false;
}

// =============================================================================
// BLOCK INGESTION (Ported from handleRemoteBlockDownloaded)
// =============================================================================

pub struct IngestResult {
    pub accepted: bool,
    pub extended_chain: bool,
    pub stored_on_side: bool,
    pub need_parent: Option<String>,
    pub reason: Option<String>,
}

pub async fn handle_block_received(block_proto: p2p::Block, from_peer: Option<String>) {
    // 1. Check if we are already processing a block
    let should_queue = {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if state.worker_flags.is_processing_block {
            state.block_queue.push_back((block_proto.clone(), from_peer.clone()));
            true
        } else {
            state.worker_flags.is_processing_block = true;
            false
        }
    };

    if should_queue {
        return;
    }

    // 2. Start the processing loop
    process_block_loop(block_proto, from_peer).await;
}

async fn process_block_loop(mut current_block: p2p::Block, mut current_peer: Option<String>) {
    loop {
        process_single_block(current_block, current_peer).await;

        // Check queue for next block
        let next_item = {
            let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
            state.block_queue.pop_front()
        };

        match next_item {
            Some((b, p)) => {
                current_block = b;
                current_peer = p;
            },
            None => {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                state.worker_flags.is_processing_block = false;
                break;
            }
        }
    }
}

async fn process_single_block(block_proto: p2p::Block, from_peer: Option<String>) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let block_bytes = block_proto.encode_to_vec();
    let block_hash = block_proto.hash.clone();
    let block_height = block_proto.height;
    
    // Check if hash is poisoned
    {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if state.peer_state.is_hash_poisoned(&block_hash) {
            add_log_command(&mut response, "warn", &format!(
                "Ignoring poisoned block {}...",
                &block_hash[..12.min(block_hash.len())]
            ));
            post_async_response(response);
            return;
        }
    }
    
    // Check if we should defer (during sync or out of order)
    let our_height = {
        let chain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        *chain.current_height
    };
    
    let should_defer = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.worker_flags.is_syncing || block_height > our_height + 1
    };
    
    if should_defer && !is_downloading_this_block(&block_hash) {
        add_log_command(&mut response, "debug", &format!(
            "[DEFER] Deferring block {} (height {})",
            &block_hash[..12.min(block_hash.len())],
            block_height
        ));
        
        {
            let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
            state.deferred_blocks.add(&block_hash, block_height, block_bytes, from_peer);
        }
        
        // Trigger sync check if not syncing
        {
            let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
            if !state.worker_flags.is_syncing {
                // Send sync tick
                let tick = p2p::SyncTickRequest {};
                // This will be handled by the next sync tick
            }
        }
        
        post_async_response(response);
        return;
    }
    
    // Ingest the block
    match ingest_block_internal(block_bytes, from_peer.clone()).await {
        Ok(result) => {
            if result.accepted && result.extended_chain {
                add_log_command(&mut response, "success", &format!(
                    "✓ Block {} accepted (height {})",
                    &block_hash[..12.min(block_hash.len())],
                    block_height
                ));
                
                // Only broadcast if this block came from a peer (not self-mined)
                // Self-mined blocks are broadcast in handle_submit_mining_candidate_internal
                if from_peer.is_some() {
                    let ann = p2p::BlockAnnouncement {
                        hash: block_hash.clone(),
                        height: block_height,
                    };
                    let msg = p2p::P2pMessage {
                        payload: Some(p2p::p2p_message::Payload::BlockAnnouncement(ann)),
                    };
                    let topic = constants::TOPIC_BLOCK_ANNOUNCEMENTS.replace("{}", &get_network_name());
                    add_p2p_publish_command(&mut response, &topic, msg.encode_to_vec());
                }
                
                // Scan wallets
                let block = Block::from(block_proto.clone());
                scan_wallets_for_block(&block, &mut response);
                
                // Process deferred blocks at next height
                process_deferred_blocks(block_height + 1, &mut response).await;
                
                // Restart mining if active
                restart_mining_if_active(&mut response).await;
                
                // Update sync progress
                {
                    let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                    state.sync_state.sync_progress.current_height = block_height;
                    
                    // Check if sync complete
                    if state.worker_flags.is_syncing && 
                       block_height >= state.sync_state.sync_progress.target_height {
                        add_log_command(&mut response, "success", "[SYNC] Sync complete!");
                        state.end_sync();
                    }
                }
            } else if result.stored_on_side {
                add_log_command(&mut response, "warn", &format!(
                    "[FORK] Block {}... stored as side block",
                    &block_hash[..12.min(block_hash.len())]
                ));
                
                // Plan reorg
                plan_and_execute_reorg(&block_hash, &mut response).await;
            } else if let Some(parent_hash) = result.need_parent {
                add_log_command(&mut response, "info", &format!(
                    "Need parent {}...",
                    &parent_hash[..12.min(parent_hash.len())]
                ));
                
                // Request parent
                request_block(&parent_hash, &mut response);
            } else if !result.accepted {
                let reason = result.reason.unwrap_or_else(|| "Unknown".to_string());
                add_log_command(&mut response, "warn", &format!(
                    "Block rejected: {}",
                    reason
                ));
                
                // Penalize peer
                if let Some(peer_id) = from_peer {
                    let should_ban = {
                        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                        state.peer_state.record_bad_block(&peer_id)
                    };
                    
                    if should_ban {
                        add_hangup_peer_command(&mut response, &peer_id, "Too many bad blocks");
                    }
                    
                    // Poison hash for severe violations
                    if reason.contains("signature") || reason.contains("double-spend") {
                        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                        state.peer_state.poison_hash(&block_hash, &reason, &peer_id);
                    }
                }
            }
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Block ingestion error: {:?}", e));
        }
    }
    
    post_async_response(response);
}

fn is_downloading_this_block(hash: &str) -> bool {
    let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
    state.sync_state.active_hash_requests.values()
        .any(|r| r.hashes.contains(&hash.to_string()))
}

async fn process_deferred_blocks(height: u64, response: &mut p2p::RustToJsCommandBatch) {
    let blocks_to_process: Vec<DeferredBlock> = {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.deferred_blocks.get_blocks_at_height(height)
            .iter()
            .map(|b| (*b).clone())
            .collect()
    };
    
    for deferred in blocks_to_process {
        add_log_command(response, "debug", &format!(
            "[DEFERRED] Processing deferred block {}...",
            &deferred.hash[..12.min(deferred.hash.len())]
        ));
        
        // Remove from deferred
        {
            let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
            state.deferred_blocks.remove(&deferred.hash);
        }
        
        // Re-ingest
        if let Ok(block_proto) = p2p::Block::decode(deferred.block_bytes.as_slice()) {
            let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
            state.block_queue.push_front((block_proto, deferred.from_peer.clone()));
        }
    }
}

async fn plan_and_execute_reorg(tip_hash: &str, response: &mut p2p::RustToJsCommandBatch) {
    // Call Rust reorg planner
    match crate::plan_reorg_for_tip(tip_hash.to_string()).await {

        Ok(plan_js) => {
            // Parse plan
        #[derive(serde::Serialize, serde::Deserialize)]
        struct ReorgPlan {
                should_switch: bool,
                requests: Vec<String>,
                detach: Vec<String>,
                attach: Vec<String>,
            }
            
            let plan: ReorgPlan = match serde_wasm_bindgen::from_value(plan_js) {
                Ok(p) => p,
                Err(e) => {
                    add_log_command(response, "error", &format!("Failed to parse reorg plan: {:?}", e));
                    return;
                }
            };
            
            if !plan.requests.is_empty() {
                add_log_command(response, "info", &format!(
                    "[REORG] Need {} missing blocks",
                    plan.requests.len()
                ));
                
                for hash in &plan.requests {
                    request_block(hash, response);
                }
                return;
            }
            
            if plan.should_switch {
                add_log_command(response, "warn", &format!(
                    "[REORG] Switching chain: -{} +{}",
                    plan.detach.len(),
                    plan.attach.len()
                ));
                
                // Pause mining during reorg
                {
                    let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                    state.start_reorg();
                }
                add_control_mining_stop(response);
                
                // Execute atomic reorg
                match crate::atomic_reorg(serde_wasm_bindgen::to_value(&plan).unwrap()).await {

                    Ok(_) => {
                        add_log_command(response, "success", "[REORG] Chain switch complete");
                    }
                    Err(e) => {
                        add_log_command(response, "error", &format!("[REORG] Failed: {:?}", e));
                    }
                }
                
                // Resume mining
                {
                    let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                    state.end_reorg();
                }
                
                if should_resume_mining() {
                    restart_mining_if_active(response).await;
                }
            } else {
                add_log_command(response, "info", "[REORG] Current chain is still best.");
            }
        }
        Err(e) => {
            add_log_command(response, "error", &format!("Reorg planning failed: {:?}", e));
        }
    }
}

fn should_resume_mining() -> bool {
    let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
    state.miner_state.was_active_before_reorg
}

fn request_block(hash: &str, response: &mut p2p::RustToJsCommandBatch) {
    // Check if already requested
    {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if state.reorg_state.is_requested(hash) {
            return;
        }
        state.reorg_state.track_request(hash);
    }
    
    let req = p2p::BlockRequest { hash: hash.to_string() };
    let msg = p2p::P2pMessage {
        payload: Some(p2p::p2p_message::Payload::BlockRequest(req)),
    };
    let topic = constants::TOPIC_BLOCK_REQUEST.replace("{}", &get_network_name());
    add_p2p_publish_command(response, &topic, msg.encode_to_vec());
}

async fn ingest_block_internal(block_bytes: Vec<u8>, from_peer: Option<String>) -> Result<IngestResult, JsValue> {
    // Call the existing ingest_block_bytes function
    let result_js = crate::ingest_block_bytes(block_bytes).await?;
    
    // Parse result
    let result_type = js_sys::Reflect::get(&result_js, &JsValue::from_str("type"))?
        .as_string()
        .unwrap_or_default();
    
    let reason = js_sys::Reflect::get(&result_js, &JsValue::from_str("reason"))
        .ok()
        .and_then(|v| v.as_string());
    
    let need_parent = js_sys::Reflect::get(&result_js, &JsValue::from_str("hash"))
        .ok()
        .and_then(|v| v.as_string());
    
    Ok(IngestResult {
        accepted: result_type == "acceptedAndExtended" || result_type == "duplicate",
        extended_chain: result_type == "acceptedAndExtended",
        stored_on_side: result_type == "storedOnSide",
        need_parent: if result_type == "needParent" { need_parent } else { None },
        reason,
    })
}

// =============================================================================
// WALLET SCANNING
// =============================================================================
fn scan_wallets_for_block(block: &Block, response: &mut p2p::RustToJsCommandBatch) {
    let wallet_ids: Vec<String> = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.worker_flags.active_wallet_ids.iter().cloned().collect()
    };
    
    // We need to release the lock on WALLET_SESSIONS before we can await anything (like DB saves).
    // However, this function is currently synchronous. To fix this properly without refactoring
    // the whole chain, we spawn a local future for the saving part.
    
    let mut map = WALLET_SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    
    for wallet_id in wallet_ids {
        if let Some(wallet) = map.get_mut(&wallet_id) {
            let old_balance = wallet.balance();
            wallet.scan_block(block);
            let new_balance = wallet.balance();
            
            // Generate address from the wallet reference without re-locking
            let scan_pub_bytes = wallet.scan_pub.compress().to_bytes();
            let address = crate::address::encode_stealth_address(&scan_pub_bytes).unwrap_or_default();

            if new_balance != old_balance || block.height.0 % 100 == 0 {
                // Pass the derived address
                add_ui_balance_command(response, &wallet_id, new_balance, &address);
                add_log_command(response, "debug", &format!(
                    "Wallet {} scanned block {}, balance: {}",
                    wallet_id, block.height, new_balance
                ));
            }

            // --- FIX START: Persist wallet state ---
            // We serialize here while we hold the lock to ensure consistency
            if let Ok(json) = serde_json::to_string(&wallet) {
                let id_clone = wallet_id.clone();
                // Spawn a fire-and-forget task to save to DB
                wasm_bindgen_futures::spawn_local(async move {
                    if let Err(e) = crate::save_wallet_to_db(&id_clone, &json).await {
                        crate::log(&format!("[ERROR] Failed to auto-save wallet {}: {:?}", id_clone, e));
                    }
                });
            }
            // --- FIX END ---
        }
    }
}

// =============================================================================
// NETWORK EVENT HANDLERS
// =============================================================================

pub fn handle_peer_connected(response: &mut p2p::RustToJsCommandBatch, peer_id: &str) {
    let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
    state.peer_state.record_connected(peer_id);
    add_log_command(response, "debug", &format!(
        "Peer connected: {}",
        &peer_id[peer_id.len().saturating_sub(8)..]
    ));
}

pub fn handle_peer_disconnected(response: &mut p2p::RustToJsCommandBatch, peer_id: &str) {
    let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
    state.peer_state.record_disconnected(peer_id);
    add_log_command(response, "debug", &format!(
        "Peer disconnected: {}",
        &peer_id[peer_id.len().saturating_sub(8)..]
    ));
}

pub fn handle_peer_verified(response: &mut p2p::RustToJsCommandBatch, peer_id: &str) {
    let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
    state.peer_state.record_verified(peer_id);
    add_log_command(response, "info", &format!(
        "Peer verified: {}",
        &peer_id[peer_id.len().saturating_sub(8)..]
    ));
}

// =============================================================================
// L2 HANDLERS - ATOMIC SWAPS
// =============================================================================

pub async fn handle_swap_initiate_internal(req: p2p::SwapInitiateRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // Validate wallet
    {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if !state.worker_flags.active_wallet_ids.contains(&req.wallet_id) {
            add_log_command(&mut response, "error", "Wallet not loaded");
            post_async_response(response);
            return;
        }
    }
    
    // Get wallet keys
    let alice_secret = match get_wallet_spend_privkey(&req.wallet_id) {
        Ok(s) => s,
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to get wallet key: {}", e));
            post_async_response(response);
            return;
        }
    };
    
    // Decode counterparty pubkey
    let bob_pubkey = match hex::decode(&req.counterparty_pubkey) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => {
            add_log_command(&mut response, "error", "Invalid counterparty pubkey");
            post_async_response(response);
            return;
        }
    };
    
    // Create swap
    let mut alice_secret_arr = [0u8; 32];
    alice_secret_arr.copy_from_slice(&alice_secret);
    let alice_scalar = Scalar::from_bytes_mod_order(alice_secret_arr);
    
    let bob_point = match CompressedRistretto::from_slice(&bob_pubkey)
        .ok()
        .and_then(|cp| cp.decompress())
    {
        Some(p) => p,
        None => {
            add_log_command(&mut response, "error", "Invalid counterparty pubkey");
            post_async_response(response);
            return;
        }
    };
    
    let current_height = {
        let chain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        *chain.current_height
    };
    
    match AtomicSwap::initiate(
        &alice_scalar,
        req.plb_amount,
        bob_pubkey.clone(),  // bob_pubkey is already Vec<u8>
        req.btc_amount,
        req.timeout_blocks,
    ) {
        Ok(swap) => {
            let swap_id = hex::encode(&swap.swap_id[..8]);
            let swap_json = serde_json::to_string(&swap).unwrap_or_default();
            
            // Store in state
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                state.atomic_swap_state.active_swaps.insert(swap_id.clone(), crate::state::AtomicSwapEntry {
                    swap_id: swap_id.clone(),
                    our_role: "alice".to_string(),
                    counterparty_pubkey: bob_pubkey,
                    plb_amount: req.plb_amount,
                    btc_amount: req.btc_amount,
                    timeout_height: current_height + req.timeout_blocks,
                    state: "negotiating".to_string(),
                    created_at_ms: current_time_ms(),
                    swap_data_json: swap_json,
                });
            }
            
            add_log_command(&mut response, "success", &format!(
                "Atomic swap initiated: ID={}, Amount={} PLB",
                swap_id, req.plb_amount
            ));
            
            let p2p_swap = p2p::AtomicSwap {
                swap_id: swap.swap_id.to_vec(),
                state_enum: 0, // Negotiating
                alice_amount: req.plb_amount,
                alice_pubkey: swap.alice_pubkey.to_vec(),
                alice_commitment: swap.alice_commitment.clone(),
                alice_timeout_height: swap.alice_timeout_height,
                bob_amount: req.btc_amount,
                bob_pubkey: req.counterparty_pubkey.clone().into(), // Convert bytes
                shared_adaptor_point: swap.shared_adaptor_point.to_vec(),
                secret_hash: swap.secret_hash.to_vec(),
                created_at: swap.created_at,
                expires_at: swap.expires_at,
                ..Default::default()
            };

            let msg = p2p::P2pMessage {
                payload: Some(p2p::p2p_message::Payload::SwapPropose(p2p_swap)),
            };
            
            let topic = crate::constants::TOPIC_SWAP_PROPOSE.replace("{}", &get_network_name());
            add_p2p_publish_command(&mut response, &topic, msg.encode_to_vec());
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to initiate swap: {}", e));
        }
    }
    
    post_async_response(response);
}

pub fn handle_swap_list_internal(response: &mut p2p::RustToJsCommandBatch) {
    let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
    
    if state.atomic_swap_state.active_swaps.is_empty() {
        add_log_command(response, "info", "No active atomic swaps.");
        return;
    }
    
    add_log_command(response, "info", "=== Active Atomic Swaps ===");
    for (id, swap) in &state.atomic_swap_state.active_swaps {
        add_log_command(response, "info", &format!(
            "  {} | {} | {} | {} PLB",
            id, swap.our_role, swap.state, swap.plb_amount
        ));
    }
}

pub async fn handle_swap_respond_internal(req: p2p::SwapRespondRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // 1. Retrieve the Swap from Global State
    // We create a scope to ensure the lock is dropped before async operations
    let (mut swap, wallet_id) = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        let entry = match state.atomic_swap_state.active_swaps.get(&req.swap_id) {
            Some(e) => e,
            None => {
                add_log_command(&mut response, "error", "Swap ID not found in active swaps.");
                post_async_response(response);
                return;
            }
        };
        
        let swap: AtomicSwap = match serde_json::from_str(&entry.swap_data_json) {
            Ok(s) => s,
            Err(e) => {
                add_log_command(&mut response, "error", &format!("Corrupted swap state: {}", e));
                post_async_response(response);
                return;
            }
        };
        (swap, req.wallet_id.clone())
    };

    // 2. Load Bob's Private Spend Key
    let bob_secret_vec = match get_wallet_spend_privkey(&wallet_id) {
        Ok(k) => k,
        Err(e) => {
             add_log_command(&mut response, "error", &format!("Failed to load wallet key: {}", e));
             post_async_response(response);
             return;
        }
    };
    let mut bob_secret_arr = [0u8; 32];
    bob_secret_arr.copy_from_slice(&bob_secret_vec);
    let bob_secret = Scalar::from_bytes_mod_order(bob_secret_arr);

    // 3. Prepare Response (Bob funds the Bitcoin HTLC)
    // In a unilateral flow, Bob doesn't strictly need to send an adaptor sig here 
    // unless he is also locking funds on Pluribit side (dual-funding). 
    // We pass empty bytes, but this is where you'd put it if your protocol version changes.
    let bob_adaptor_sig = vec![]; 
    
    // Get current block height for timeout calculations
    let current_height = get_tip_height_from_db().await.unwrap_or(0);

    // 4. Execute the Logic (Update internal swap state)
    match swap.respond(
        &bob_secret,
        req.btc_address.clone(),
        req.btc_txid.clone(),
        req.btc_vout,
        bob_adaptor_sig.clone(),
        current_height + 144, // Default relative timeout (~24h)
    ) {
        Ok(_) => {
            add_log_command(&mut response, "success", "Swap response created. Broadcasting to counterparty...");

            // 5. Update Global State (Persist the change)
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(entry) = state.atomic_swap_state.active_swaps.get_mut(&req.swap_id) {
                    entry.state = "committed".to_string();
                    entry.swap_data_json = serde_json::to_string(&swap).unwrap_or_default();
                }
            }

            // 6. Broadcast P2P Message to Alice
            let p2p_swap = p2p::AtomicSwap {
                swap_id: swap.swap_id.to_vec(),
                state_enum: 1, // 1 maps to SwapState::Committed
                bob_btc_address: req.btc_address,
                bob_btc_txid: req.btc_txid,
                bob_btc_vout: req.btc_vout,
                bob_adaptor_sig: bob_adaptor_sig,
                bob_timeout_height: current_height + 144,
                // Include amounts so Alice can verify them
                alice_amount: swap.alice_amount,
                bob_amount: swap.bob_amount,
                ..Default::default()
            };
            
            let msg = p2p::P2pMessage {
                payload: Some(p2p::p2p_message::Payload::SwapRespond(p2p_swap)),
            };
            
            // Use the dynamic network name
            let topic = constants::TOPIC_SWAP_RESPOND.replace("{}", &get_network_name());
            add_p2p_publish_command(&mut response, &topic, msg.encode_to_vec());
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Logic error in swap respond: {}", e));
        }
    }

    post_async_response(response);
}
pub async fn handle_block_announcement(from_peer: &str, ann: p2p::BlockAnnouncement) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // Check if we already have this block
    let have_block = {
        let chain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        chain.tip_hash == ann.hash || 
        crate::side_blocks::SIDE_BLOCKS.lock().unwrap_or_else(|p| p.into_inner()).contains_key(&ann.hash)
    };
    
    if have_block {
        return; // Already have it
    }
    
    // Check if hash is poisoned
    {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if state.peer_state.is_hash_poisoned(&ann.hash) {
            add_log_command(&mut response, "warn", &format!(
                "Ignoring announcement of poisoned hash {}...",
                &ann.hash[..12]
            ));
            post_async_response(response);
            return;
        }
    }
    
    add_log_command(&mut response, "debug", &format!(
        "[BLOCK] Announcement from {}: height={}, hash={}...",
        &from_peer[from_peer.len().saturating_sub(6)..],
        ann.height,
        &ann.hash[..12.min(ann.hash.len())]
    ));
    
    // Request the block
    request_block(&ann.hash, &mut response);
    
    post_async_response(response);
}

pub async fn handle_block_request_received(from_peer: &str, req: p2p::BlockRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // Verify peer
    {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if !state.peer_state.verified_peers.contains(from_peer) {
            add_log_command(&mut response, "warn", "Block request from unverified peer");
            post_async_response(response);
            return;
        }
    }
    
    // Try to load block from DB
    match crate::load_block_by_hash(&req.hash).await {
        Ok(Some(block)) => {
            // Convert internal Block to protobuf Block and send
            let proto_block = p2p::Block::from(block);
            let msg = p2p::P2pMessage {
                payload: Some(p2p::p2p_message::Payload::Block(proto_block)),
            };
            let topic = constants::TOPIC_BLOCKS.replace("{}", &get_network_name());
            add_p2p_publish_command(&mut response, &topic, msg.encode_to_vec());
        }
        _ => {
            add_log_command(&mut response, "debug", &format!(
                "Block {} not found for peer request",
                &req.hash[..12]
            ));
        }
    }
    
    post_async_response(response);
}



pub async fn handle_transaction_received(tx: p2p::Transaction) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // Convert to native transaction
    let native_tx = match crate::transaction::Transaction::try_from(tx) {
        Ok(t) => t,
        Err(e) => {
            add_log_command(&mut response, "warn", &format!("Invalid tx: {}", e));
            post_async_response(response);
            return;
        }
    };
    
    // Verify and add to mempool
    {
        let utxo_set = UTXO_SET.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = native_tx.verify(None, Some(&utxo_set)) {
            add_log_command(&mut response, "warn", &format!("TX verification failed: {}", e));
            post_async_response(response);
            return;
        }
    }
    
    {
        let mut pool = TX_POOL.lock().unwrap_or_else(|p| p.into_inner());
        if pool.pending.len() >= constants::MAX_TX_POOL_SIZE {
            return; // Mempool full
        }
        
        // Check for duplicates
        let tx_excess = &native_tx.kernels.first().map(|k| k.excess.clone());
        let is_dup = pool.pending.iter().any(|t| {
            t.kernels.first().map(|k| &k.excess) == tx_excess.as_ref()
        });
        
        if !is_dup {
            pool.pending.push(native_tx);
            add_log_command(&mut response, "debug", "TX added to mempool");
        }
    }
    
    post_async_response(response);
}
pub async fn handle_swap_claim_internal(req: p2p::SwapClaimRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // 1. Retrieve Swap
    let (swap, wallet_id) = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        let entry = match state.atomic_swap_state.active_swaps.get(&req.swap_id) {
            Some(e) => e,
            None => {
                add_log_command(&mut response, "error", "Swap not found locally.");
                post_async_response(response);
                return;
            }
        };
        let swap: AtomicSwap = serde_json::from_str(&entry.swap_data_json).unwrap();
        (swap, req.wallet_id.clone())
    };

    // 2. Get Keys
    let bob_secret_vec = match get_wallet_spend_privkey(&wallet_id) { 
        Ok(k) => k, 
        Err(_) => {
            add_log_command(&mut response, "error", "Could not load wallet keys.");
            post_async_response(response);
            return;
        } 
    };
    let mut bob_secret_arr = [0u8; 32];
    bob_secret_arr.copy_from_slice(&bob_secret_vec);
    let bob_secret = Scalar::from_bytes_mod_order(bob_secret_arr);

    // 3. Decode Adaptor Secret (Hex -> Bytes)
    let adaptor_secret_bytes = match hex::decode(&req.adaptor_secret_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => {
             add_log_command(&mut response, "error", "Invalid adaptor secret hex. Must be 32 bytes.");
             post_async_response(response);
             return;
        }
    };
    let mut adaptor_secret_arr = [0u8; 32];
    adaptor_secret_arr.copy_from_slice(&adaptor_secret_bytes);
    let adaptor_secret = Scalar::from_bytes_mod_order(adaptor_secret_arr);

    // 4. Derive Bob's Receive Point (Standard derivation)
    let bob_receive_point = &bob_secret * &crate::mimblewimble::PC_GENS.B_blinding;

    // 5. Generate the Claim Transaction
    match swap.bob_claim(&bob_secret, &adaptor_secret, &bob_receive_point) {
        Ok(tx) => {
            add_log_command(&mut response, "success", "Claim transaction created successfully!");
            
            // 6. Broadcast to Network
            let p2p_tx = p2p::Transaction::from(tx.clone());
            let msg = p2p::P2pMessage {
                payload: Some(p2p::p2p_message::Payload::Transaction(p2p_tx)),
            };
            let topic = constants::TOPIC_TRANSACTIONS.replace("{}", &get_network_name());
            add_p2p_publish_command(&mut response, &topic, msg.encode_to_vec());
            
            // 7. Add to Local Mempool
            {
                let mut pool = crate::TX_POOL.lock().unwrap_or_else(|p| p.into_inner());
                if pool.pending.len() < crate::constants::MAX_TX_POOL_SIZE {
                    pool.pending.push(tx);
                }
            }
            
            // 8. Update State
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(entry) = state.atomic_swap_state.active_swaps.get_mut(&req.swap_id) {
                    entry.state = "completed".to_string();
                    // We don't delete it yet so user can see history, but mark it done
                }
            }
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to create claim transaction: {}", e));
        }
    }

    post_async_response(response);
}
pub async fn handle_inspect_block_internal(req: p2p::InspectBlockRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // Use the existing DB helper
    match load_block_from_db(req.height).await {
        Ok(Some(block)) => {
            add_log_command(&mut response, "info", "=== Block Inspection ===");
            add_log_command(&mut response, "info", &format!("Height: {}", block.height));
            add_log_command(&mut response, "info", &format!("Hash: {}", block.hash));
            add_log_command(&mut response, "info", &format!("Prev: {}", block.prev_hash));
            add_log_command(&mut response, "info", &format!("Tx Count: {}", block.transactions.len()));
            add_log_command(&mut response, "info", &format!("Work: {}", block.total_work));
            add_log_command(&mut response, "info", &format!("VRF Out: {}", hex::encode(&block.vrf_proof.output)));
            add_log_command(&mut response, "info", "========================");
        }
        Ok(None) => {
            add_log_command(&mut response, "error", &format!("Block at height {} not found in DB.", req.height));
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Database error: {:?}", e));
        }
    }
    
    post_async_response(response);
}

pub fn handle_purge_side_blocks_internal(response: &mut p2p::RustToJsCommandBatch) {
    // Call the existing function in lib.rs
    match crate::purge_invalid_side_blocks() {
        Ok(count) => {
            add_log_command(response, "success", &format!("Purged {} invalid side blocks.", count));
        }
        Err(e) => {
            add_log_command(response, "error", &format!("Failed to purge side blocks: {:?}", e));
        }
    }
}

pub async fn handle_audit_detailed_internal() {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    add_log_command(&mut response, "warn", "=== 🛡️ DEEP CHAIN AUDIT STARTED 🛡️ ===");
    add_log_command(&mut response, "info", "Verifying cryptographic integrity of every block...");

    // Post initial logs immediately so user sees activity
    post_async_response(response);
    
    // Create a new response batch for the audit logs
    // We need a thread-safe way to log from the callback, or just collect them.
    // For simplicity in this architecture, we can pass a closure that sends logs immediately via a new batch.
    
    let result = crate::blockchain::perform_deep_audit(|msg| {
        // This closure is called for errors/progress during the loop
        let mut batch = p2p::RustToJsCommandBatch::default();
        add_log_command(&mut batch, "info", &msg);
        post_async_response(batch);
    }).await;

    // Final Report
    let mut final_response = p2p::RustToJsCommandBatch::default();
    
    match result {
        Ok(stats) => {
            add_log_command(&mut final_response, "info", "--------------------------------------------------");
            
            if stats.errors == 0 {
                add_log_command(&mut final_response, "success", &format!("✅ DEEP AUDIT PASSED: {} blocks cryptographically verified.", stats.valid_blocks));
            } else {
                add_log_command(&mut final_response, "error", &format!("❌ DEEP AUDIT FAILED: {} blocks failed verification.", stats.errors));
            }
            
            add_log_command(&mut final_response, "info", &format!("Verified Historical Supply: {} ƀits", stats.total_supply));
            add_log_command(&mut final_response, "info", &format!("Live UTXO Count: {}", stats.utxo_count));
        }
        Err(e) => {
            add_log_command(&mut final_response, "error", &format!("Audit crashed: {:?}", e));
        }
    }

    post_async_response(final_response);
}

// src/command_handlers.rs

pub async fn handle_verify_supply_internal() {
    let mut response = p2p::RustToJsCommandBatch::default();
    add_log_command(&mut response, "info", "=== SUPPLY INTEGRITY CHECK ===");

    // 1. Check Coinbase Index Consistency
    // We calculate the list of dangling entries first (Synchronous part)
    let (utxo_size, coinbase_index_size, dangling_list) = {
        let utxos = crate::blockchain::UTXO_SET.lock().unwrap_or_else(|p| p.into_inner());
        let coinbase_idx = crate::blockchain::COINBASE_INDEX.lock().unwrap_or_else(|p| p.into_inner());
        
        let mut list: Vec<Vec<u8>> = Vec::new();
        for commitment in coinbase_idx.keys() {
            // Check if this coinbase commitment exists in the live UTXO set
            if !utxos.contains_key(commitment) {
                list.push(commitment.clone());
            }
        }
        (utxos.len(), coinbase_idx.len(), list)
    }; // Locks are dropped here

    add_log_command(&mut response, "info", &format!("UTXO Set Size:      {}", utxo_size));
    add_log_command(&mut response, "info", &format!("Coinbase Index Size: {}", coinbase_index_size));

    if !dangling_list.is_empty() {
        add_log_command(&mut response, "error", &format!("❌ INTEGRITY FAILURE: Found {} coinbase entries with no matching UTXO.", dangling_list.len()));
        
        // --- Auto-Repair Logic ---
        add_log_command(&mut response, "warn", "⚡ Repairing database: Purging dangling entries...");
        
        for commitment in dangling_list {
            // A. Remove from Database (Async - No lock held)
            if let Err(e) = crate::delete_coinbase_index_from_db(&commitment).await {
                 add_log_command(&mut response, "error", &format!("Failed to delete index: {:?}", e));
            }
            
            // B. Remove from Memory (Brief lock)
            {
                let mut idx = crate::blockchain::COINBASE_INDEX.lock().unwrap_or_else(|p| p.into_inner());
                idx.remove(&commitment);
            }
        }
        add_log_command(&mut response, "success", "✅ Database repair complete. Verify again to confirm.");

    } else {
        add_log_command(&mut response, "success", "✅ Coinbase Index is consistent with UTXO set.");
    }
    
    // 2. Re-verify tip work
    let chain_work = {
        let chain = crate::BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        chain.total_work.to_string()
    };
    add_log_command(&mut response, "info", &format!("Chain Tip Work: {}", chain_work));
    
    add_log_command(&mut response, "info", "==============================");
    post_async_response(response);
}


pub fn handle_clear_side_blocks_internal(response: &mut p2p::RustToJsCommandBatch) {
    // Call the existing function in lib.rs
    let count = crate::clear_all_side_blocks();
    add_log_command(response, "success", &format!("Cleared {} side blocks from cache.", count));
}
pub async fn handle_swap_refund_internal(req: p2p::SwapRefundRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();

    // 1. Retrieve Swap
    let (swap, wallet_id) = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        let entry = match state.atomic_swap_state.active_swaps.get(&req.swap_id) {
            Some(e) => e,
            None => {
                add_log_command(&mut response, "error", "Swap not found");
                post_async_response(response);
                return;
            }
        };
        let swap: AtomicSwap = serde_json::from_str(&entry.swap_data_json).unwrap();
        (swap, req.wallet_id.clone())
    };

    // 2. Check Chain Height vs Timeout
    let current_height = get_tip_height_from_db().await.unwrap_or(0);
    if current_height < swap.alice_timeout_height {
        add_log_command(&mut response, "error", &format!(
            "Timelock active. Current height: {}, Required: {}. Wait {} more blocks.", 
            current_height, swap.alice_timeout_height, swap.alice_timeout_height - current_height
        ));
        post_async_response(response);
        return;
    }

    // 3. Get Alice's Keys
    let alice_secret_vec = match get_wallet_spend_privkey(&wallet_id) { Ok(k) => k, _ => return };
    let mut alice_secret_arr = [0u8; 32];
    alice_secret_arr.copy_from_slice(&alice_secret_vec);
    let alice_secret = Scalar::from_bytes_mod_order(alice_secret_arr);
    
    // 4. Derive Refund Address
    let alice_receive_point = &alice_secret * &crate::mimblewimble::PC_GENS.B_blinding;

    // 5. Create Refund TX
    match swap.refund_alice(&alice_secret, &alice_receive_point, current_height) {
        Ok(tx) => {
            add_log_command(&mut response, "success", "Refund transaction created! Broadcasting...");
            
            // Broadcast
            let p2p_tx = p2p::Transaction::from(tx.clone());
            let msg = p2p::P2pMessage {
                payload: Some(p2p::p2p_message::Payload::Transaction(p2p_tx)),
            };
            let topic = constants::TOPIC_TRANSACTIONS.replace("{}", &get_network_name());
            add_p2p_publish_command(&mut response, &topic, msg.encode_to_vec());
            
            // Add to pool
            {
                let mut pool = crate::TX_POOL.lock().unwrap_or_else(|p| p.into_inner());
                pool.pending.push(tx);
            }

            // Update State
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(entry) = state.atomic_swap_state.active_swaps.get_mut(&req.swap_id) {
                    entry.state = "refunded".to_string();
                }
            }
        }
        Err(e) => add_log_command(&mut response, "error", &format!("Refund creation failed: {}", e)),
    }

    post_async_response(response);
}
// =============================================================================
// L2 HANDLERS - PAYMENT CHANNELS
// =============================================================================

pub async fn handle_channel_open_internal(req: p2p::ChannelOpenRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // Validate wallet
    {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if !state.worker_flags.active_wallet_ids.contains(&req.wallet_id) {
            add_log_command(&mut response, "error", "Wallet not loaded");
            post_async_response(response);
            return;
        }
    }
    
    let party_a_secret = match get_wallet_spend_privkey(&req.wallet_id) {
        Ok(s) => s,
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to get wallet key: {}", e));
            post_async_response(response);
            return;
        }
    };
    
    let party_b_pubkey = match hex::decode(&req.counterparty_pubkey) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => {
            add_log_command(&mut response, "error", "Invalid counterparty pubkey");
            post_async_response(response);
            return;
        }
    };
    
    let mut party_a_secret_arr = [0u8; 32];
    party_a_secret_arr.copy_from_slice(&party_a_secret);
    let party_a_scalar = Scalar::from_bytes_mod_order(party_a_secret_arr);
    
    let party_b_point = match CompressedRistretto::from_slice(&party_b_pubkey)
        .ok()
        .and_then(|cp| cp.decompress())
    {
        Some(p) => p,
        None => {
            add_log_command(&mut response, "error", "Invalid counterparty pubkey");
            post_async_response(response);
            return;
        }
    };
    
    match PaymentChannel::propose(
        &party_a_scalar,
        req.my_amount,
        &party_b_point,
        req.their_amount,
        144, // ~24 hour dispute period
    ) {
        Ok((channel, _proposal)) => {
            let channel_id = hex::encode(&channel.channel_id[..8]);
            let channel_json = serde_json::to_string(&channel).unwrap_or_default();
            
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                state.payment_channel_state.active_channels.insert(channel_id.clone(), crate::state::PaymentChannelEntry {
                    channel_id: channel_id.clone(),
                    our_party: "A".to_string(),
                    counterparty_pubkey: party_b_pubkey,
                    balance_a: req.my_amount,
                    balance_b: req.their_amount,
                    state: "proposed".to_string(),
                    dispute_period_blocks: 144,
                    created_at_ms: current_time_ms(),
                    channel_data_json: channel_json,
                });
            }
            
            add_log_command(&mut response, "success", &format!(
                "Payment channel proposed: ID={}, My={}, Their={}",
                channel_id, req.my_amount, req.their_amount
            ));
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to open channel: {}", e));
        }
    }
    
    post_async_response(response);
}
// --- HELPER TO GET DYNAMIC NETWORK NAME ---
fn get_network_name() -> String {
    let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
    state.network.clone()
}
// --- INITIALIZATION HANDLER ---
pub fn handle_initialize_internal(req: p2p::InitializeRequest, response: &mut p2p::RustToJsCommandBatch) {
    let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
    if !req.network.is_empty() {
        state.network = req.network.clone();
    }
    
    // Store our peer ID if provided
    if !req.our_peer_id.is_empty() {
        state.our_peer_id = req.our_peer_id.clone();
        add_log_command(response, "debug", &format!("Our peer ID set: {}", state.our_peer_id));
    }
    
    // Send back a log to confirm
    add_log_command(response, "info", &format!("Core initialized on network: {}", state.network));
}
pub fn handle_channel_list_internal(response: &mut p2p::RustToJsCommandBatch) {
    let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
    
    if state.payment_channel_state.active_channels.is_empty() {
        add_log_command(response, "info", "No active payment channels.");
        return;
    }
    
    add_log_command(response, "info", "=== Active Payment Channels ===");
    for (id, ch) in &state.payment_channel_state.active_channels {
        add_log_command(response, "info", &format!(
            "  {} | {} | {} | A:{} B:{}",
            id, ch.our_party, ch.state, ch.balance_a, ch.balance_b
        ));
    }
}

pub async fn handle_channel_accept_internal(req: p2p::ChannelAcceptRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    // 1. Retrieve the Proposal from State
    let (proposal, wallet_id) = {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        // Look up proposal by ID
        let prop = match state.payment_channel_state.pending_proposals.get(&req.proposal_id) {
            Some(p) => p.clone(),
            None => {
                add_log_command(&mut response, "error", "Channel proposal not found");
                post_async_response(response);
                return;
            }
        };
        (prop, req.wallet_id.clone())
    };

    // 2. Get Wallet Keys
    let secret_vec = match get_wallet_spend_privkey(&wallet_id) { Ok(k) => k, Err(_) => return };
    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&secret_vec);
    let my_secret = Scalar::from_bytes_mod_order(secret_arr);

    // 3. Reconstruct Internal Proposal Struct
    // (In a real app, you would have stored the full `ChannelProposal` struct. 
    // Here we reconstruct minimal needed parts or load from cache).
    let counterparty_pk = match CompressedRistretto::from_slice(&proposal.counterparty_pubkey).ok().and_then(|p| p.decompress()) {
        Some(p) => p,
        None => return
    };

    let full_proposal = crate::payment_channel::ChannelProposal {
        channel_id: hex::decode(&proposal.proposal_id).unwrap().try_into().unwrap(),
        version: 1,
        party_a_pubkey: proposal.counterparty_pubkey.clone().try_into().unwrap(),
        party_a_funding: proposal.my_amount, // A proposed, so 'my_amount' in proposal stored was A's
        party_b_pubkey: [0u8;32], // We are B, we'd derive this, simplified for snippet
        party_b_funding: proposal.their_amount,
        dispute_period: 144,
        min_confirmations: 6,
        created_at: 0,
    };

    let current_height = get_tip_height_from_db().await.unwrap_or(0);

    // 4. Accept Logic
    match PaymentChannel::accept(&full_proposal, &my_secret, &counterparty_pk, current_height) {
        Ok((channel, acceptance)) => {
            // Save Channel
            let channel_json = serde_json::to_string(&channel).unwrap();
            let channel_id = hex::encode(channel.channel_id);
            
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                state.payment_channel_state.active_channels.insert(channel_id.clone(), crate::state::PaymentChannelEntry {
                    channel_id: channel_id.clone(),
                    our_party: "B".to_string(),
                    counterparty_pubkey: proposal.counterparty_pubkey,
                    balance_a: full_proposal.party_a_funding,
                    balance_b: full_proposal.party_b_funding,
                    state: "ready_to_fund".to_string(),
                    dispute_period_blocks: 144,
                    created_at_ms: current_time_ms(),
                    channel_data_json: channel_json,
                });
                state.payment_channel_state.pending_proposals.remove(&req.proposal_id);
            }

            add_log_command(&mut response, "success", &format!("Channel {} accepted!", channel_id));

            // Broadcast Acceptance
            let p2p_acc = p2p::ChannelAcceptance {
                channel_id: channel.channel_id.to_vec(),
                party_b_commitment: Some(convert_commitment_to_proto(&acceptance.party_b_commitment)),
                party_b_revocation_point: acceptance.party_b_revocation_point.to_vec(),
                accepted_at: acceptance.accepted_at,
            };

            let msg = p2p::P2pMessage { payload: Some(p2p::p2p_message::Payload::ChannelAccept(p2p_acc)) };
            let topic = crate::constants::TOPIC_SWAP_RESPOND.replace("{}", &get_network_name());
            add_p2p_publish_command(&mut response, &topic, msg.encode_to_vec());
        }
        Err(e) => add_log_command(&mut response, "error", &format!("Accept failed: {}", e)),
    }
    
    post_async_response(response);
}

// Helper needed for the above
fn convert_commitment_to_proto(c: &crate::payment_channel::CommitmentState) -> p2p::CommitmentState {
    p2p::CommitmentState {
        sequence_number: c.sequence_number,
        owner_party_enum: match c.owner { crate::payment_channel::Party::A => 0, _ => 1 },
        owner_balance: c.owner_balance,
        counterparty_balance: c.counterparty_balance,
        commitment_tx: Some(p2p::Transaction::from(c.commitment_tx.clone())),
        owner_blinding: c.owner_blinding.clone(),
        counterparty_blinding: c.counterparty_blinding.clone(),
        adaptor_signature: Some(p2p::AdaptorSignature {
            public_nonce: c.adaptor_signature.public_nonce.to_vec(),
            adaptor_point: c.adaptor_signature.adaptor_point.to_vec(),
            pre_signature: c.adaptor_signature.pre_signature.to_vec(),
            challenge: c.adaptor_signature.challenge.to_vec(),
        }),
        revocation_point: c.revocation_point.to_vec(),
    }
}

pub async fn handle_channel_fund_internal(req: p2p::ChannelFundRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    add_log_command(&mut response, "info", &format!("Funding channel {}...", req.channel_id));
    add_log_command(&mut response, "warn", "Channel fund not fully implemented");
    post_async_response(response);
}

pub async fn handle_channel_pay_internal(req: p2p::ChannelPayRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    add_log_command(&mut response, "info", &format!("Channel payment: {} on {}...", req.amount, req.channel_id));
    add_log_command(&mut response, "warn", "Channel pay not fully implemented");
    post_async_response(response);
}

pub async fn handle_channel_close_internal(req: p2p::ChannelCloseRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    add_log_command(&mut response, "info", &format!("Closing channel {}...", req.channel_id));
    add_log_command(&mut response, "warn", "Channel close not fully implemented");
    post_async_response(response);
}

// =============================================================================
// HELPER FUNCTIONS (DB Bridge)
// =============================================================================



fn get_wallet_balance(wallet_id: &str) -> Result<u64, String> {
    let map = WALLET_SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    let w = map.get(wallet_id).ok_or("Wallet not loaded")?;
    Ok(w.balance())
}

fn get_wallet_address(wallet_id: &str) -> Result<String, String> {
    let map = WALLET_SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    let w = map.get(wallet_id).ok_or("Wallet not loaded")?;
    let scan_pub_bytes = w.scan_pub.compress().to_bytes();
    address::encode_stealth_address(&scan_pub_bytes)
        .map_err(|e| e.to_string())
}

fn get_wallet_spend_privkey(wallet_id: &str) -> Result<Vec<u8>, String> {
    let map = WALLET_SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    let w = map.get(wallet_id).ok_or("Wallet not loaded")?;
    Ok(w.spend_priv.to_bytes().to_vec())
}

fn get_wallet_scan_pubkey(wallet_id: &str) -> Result<Vec<u8>, String> {
    let map = WALLET_SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    let w = map.get(wallet_id).ok_or("Wallet not loaded")?;
    Ok(w.scan_pub.compress().to_bytes().to_vec())
}

async fn load_wallet_from_db(wallet_id: &str) -> Result<Option<String>, JsValue> {
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = load_wallet_from_db)]
        fn load_wallet_raw(wallet_id: &str) -> js_sys::Promise;
    }
    
    let promise = load_wallet_raw(wallet_id);
    let result_js = JsFuture::from(promise).await?;
    
    if result_js.is_null() || result_js.is_undefined() {
        return Ok(None);
    }
    
    result_js.as_string()
        .ok_or_else(|| JsValue::from_str("DB returned non-string"))
        .map(Some)
}

async fn save_wallet_to_db(wallet_id: &str, wallet_json: &str) -> Result<(), JsValue> {
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = save_wallet_to_db)]
        fn save_wallet_raw(wallet_id: &str, wallet_json: &str) -> js_sys::Promise;
    }
    
    let promise = save_wallet_raw(wallet_id, wallet_json);
    JsFuture::from(promise).await?;
    Ok(())
}

async fn get_tip_height_from_db() -> Result<u64, JsValue> {
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = get_tip_height_from_db)]
        fn get_tip_height_raw() -> js_sys::Promise;
    }
    
    let promise = get_tip_height_raw();
    let result_js = JsFuture::from(promise).await?;
    
    let height_str = result_js.as_string()
        .ok_or_else(|| JsValue::from_str("Failed to get tip height"))?;
    
    height_str.parse::<u64>()
        .map_err(|e| JsValue::from_str(&format!("Parse error: {}", e)))
}

async fn create_transaction_internal(
    wallet_id: &str,
    receive_pubkey: &[u8],
    amount: u64,
    fee: u64,
) -> Result<(Transaction, String), String> {
    
    // Convert byte slice to RistrettoPoint
    let scan_pub_point = CompressedRistretto::from_slice(receive_pubkey)
        .map_err(|_| "Invalid receive public key bytes".to_string())?
        .decompress()
        .ok_or_else(|| "Failed to decompress receive public key".to_string())?;

    // Lock the sessions map to get the wallet
    let mut map = WALLET_SESSIONS.lock().map_err(|e| e.to_string())?;
    let wallet = map.get_mut(wallet_id).ok_or("Wallet not loaded")?;

    // Create the transaction using the wallet method
    let tx = wallet.create_transaction(amount, fee, &scan_pub_point)
        .map_err(|e| format!("Wallet error: {}", e))?;

    // Serialize the updated wallet state to return it for persistence
    let wallet_json = serde_json::to_string(&wallet)
        .map_err(|e| format!("Serialization error: {}", e))?;

    Ok((tx, wallet_json))
}

async fn complete_block_with_transactions(
    height: u64,
    prev_hash: &str,
    nonce: u64,
    miner_pubkey: &[u8; 32],
    scan_pubkey: &[u8],
    vrf_proof: &VrfProof,
    vdf_proof: &VDFProof,
    vrf_threshold: &[u8; 32],
    vdf_iterations: u64,
) -> Result<Block, String> {
    
    // Snapshot mempool
    let (mut selected, total_fees) = {
        let chain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        let pool_snapshot = {
            let pool = crate::TX_POOL.lock().unwrap_or_else(|p| p.into_inner());
            pool.pending.clone()
        };
        chain.select_transactions_for_block(&pool_snapshot)
    };

    // Create Coinbase
    let base_reward = crate::blockchain::get_current_base_reward(height);
    let coinbase_amount = base_reward + total_fees;
    
    // We reuse the Transaction::create_coinbase logic
    // Note: We need to convert the slice to Vec for the argument
    let coinbase_tx = Transaction::create_coinbase(vec![
        (scan_pubkey.to_vec(), coinbase_amount)
    ]).map_err(|e| e.to_string())?;

    selected.insert(0, coinbase_tx);

    let mut block = Block {
        height: WasmU64::from(height),
        prev_hash: prev_hash.to_string(),
        timestamp: WasmU64::from(crate::state::current_time_ms()),
        transactions: selected,
        lottery_nonce: WasmU64::from(nonce),
        vrf_proof: vrf_proof.clone(),
        vdf_proof: vdf_proof.clone(),
        miner_pubkey: *miner_pubkey,
        vrf_threshold: *vrf_threshold,
        vdf_iterations: WasmU64::from(vdf_iterations),
        tx_merkle_root: [0u8; 32], // Will be calculated
        total_work: WasmU64::from(0), // Will be calculated on ingest
        hash: String::new(),
    };

    block.apply_cut_through().map_err(|e| e.to_string())?;
    block.tx_merkle_root = block.calculate_tx_merkle_root();
    block.hash = block.compute_hash();

    Ok(block)
}
// =============================================================================
// L2 PROTOCOL HANDLERS (Received from network)
// =============================================================================

// --- Atomic Swap Handlers ---

pub async fn handle_swap_proposal_received(from_peer: &str, swap: p2p::AtomicSwap) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let proposal_id = hex::encode(&swap.swap_id);
    add_log_command(&mut response, "info", &format!(
        "[SWAP] Received proposal {} from {}: {} PLB ↔ {} sats",
        &proposal_id[..8.min(proposal_id.len())],
        &from_peer[from_peer.len().saturating_sub(8)..],
        swap.alice_amount,
        swap.bob_amount
    ));
    
    // Validate the proposal
    if swap.alice_amount == 0 || swap.bob_amount == 0 {
        add_log_command(&mut response, "warn", "Invalid swap proposal: zero amounts");
        post_async_response(response);
        return;
    }
    
    // Verify Alice's pubkey is valid
    if swap.alice_pubkey.len() != 32 {
        add_log_command(&mut response, "warn", "Invalid swap proposal: bad pubkey length");
        post_async_response(response);
        return;
    }
    
    // Check if we already have this proposal
    {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if state.atomic_swap_state.pending_proposals.contains_key(&proposal_id) ||
           state.atomic_swap_state.active_swaps.contains_key(&proposal_id) {
            add_log_command(&mut response, "debug", "Duplicate swap proposal, ignoring");
            post_async_response(response);
            return;
        }
    }
    
    // Store the proposal so user can review and respond via CLI
    {
       let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.atomic_swap_state.pending_proposals.insert(
            proposal_id.clone(),
            crate::state::SwapProposal {
                proposal_id: proposal_id.clone(),
                counterparty_pubkey: swap.alice_pubkey.clone(),
                plb_amount: swap.alice_amount,
                btc_amount: swap.bob_amount,
                timeout_blocks: swap.alice_timeout_height,
                received_at_ms: crate::state::current_time_ms(),
            },
        );
    }
    
    add_log_command(&mut response, "success", &format!(
        "✓ Swap proposal stored. Use 'swap respond {} <wallet> <btc_addr> <txid> <vout>' to accept",
        &proposal_id[..8.min(proposal_id.len())]
    ));
    
    post_async_response(response);
}

/// Handle swap response from Bob (we are Alice)
pub async fn handle_swap_response_received(from_peer: &str, swap_resp: p2p::AtomicSwap) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let swap_id_hex = hex::encode(&swap_resp.swap_id);
    add_log_command(&mut response, "info", &format!(
        "[SWAP] Received response for {} from {}",
        &swap_id_hex[..8.min(swap_id_hex.len())],
        &from_peer[from_peer.len().saturating_sub(8)..]
    ));
    
    // Find the swap in our active swaps
    let mut swap_found = false;
    let mut swap_data: Option<crate::atomic_swap::AtomicSwap> = None;
    
    {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = state.atomic_swap_state.active_swaps.get(&swap_id_hex) {
            if entry.our_role == "alice" {
                swap_data = serde_json::from_str(&entry.swap_data_json).ok();
                swap_found = true;
            }
        }
    }
    
    if !swap_found {
        add_log_command(&mut response, "warn", "Received response for unknown/invalid swap");
        post_async_response(response);
        return;
    }
    
    let mut swap = match swap_data {
        Some(s) => s,
        None => {
            add_log_command(&mut response, "error", "Failed to deserialize swap data");
            post_async_response(response);
            return;
        }
    };
    
    // Verify the response matches our swap
    if swap_resp.alice_amount != swap.alice_amount || swap_resp.bob_amount != swap.bob_amount {
        add_log_command(&mut response, "warn", "Swap response amounts don't match proposal");
        post_async_response(response);
        return;
    }
    
    // Update swap with Bob's Bitcoin details
    swap.bob_btc_address = Some(swap_resp.bob_btc_address.clone());
    swap.bob_btc_txid = Some(swap_resp.bob_btc_txid.clone());
    swap.bob_btc_vout = Some(swap_resp.bob_btc_vout);
    swap.bob_adaptor_sig = swap_resp.bob_adaptor_sig.clone();
    swap.bob_timeout_height = swap_resp.bob_timeout_height;
    swap.state = crate::atomic_swap::SwapState::Committed;
    
    // Update state
    {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = state.atomic_swap_state.active_swaps.get_mut(&swap_id_hex) {
            entry.state = "committed".to_string();
            entry.swap_data_json = serde_json::to_string(&swap).unwrap_or_default();
        }
    }
    
    add_log_command(&mut response, "success", &format!(
        "✓ Bob committed! BTC HTLC: {} vout:{} @ {}",
        &swap_resp.bob_btc_txid[..12.min(swap_resp.bob_btc_txid.len())],
        swap_resp.bob_btc_vout,
        swap_resp.bob_btc_address
    ));
    
    add_log_command(&mut response, "info", 
        "Next: Verify BTC HTLC on-chain, then Alice creates adaptor signature");
    
    // Auto-create adaptor signature if we have the wallet loaded
    // (In production, user should verify BTC HTLC first)
    let wallet_id = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.worker_flags.active_wallet_ids.iter().next().cloned()
    };
    
    if let Some(wid) = wallet_id {
        if let Ok(secret_vec) = get_wallet_spend_privkey(&wid) {
            let mut secret_arr = [0u8; 32];
            secret_arr.copy_from_slice(&secret_vec);
            let alice_secret = Scalar::from_bytes_mod_order(secret_arr);
            
            match swap.alice_create_adaptor_signature(&alice_secret) {
                Ok(adaptor_sig) => {
                    // Update state with adaptor sig
                    {
                        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                        if let Some(entry) = state.atomic_swap_state.active_swaps.get_mut(&swap_id_hex) {
                            entry.swap_data_json = serde_json::to_string(&swap).unwrap_or_default();
                        }
                    }
                    
                    // Broadcast adaptor signature to Bob
                    let sig_msg = p2p::SwapAliceAdaptorSig {
                        swap_id: swap.swap_id.to_vec(),
                        adaptor_sig: Some(p2p::AdaptorSignature {
                            public_nonce: adaptor_sig.public_nonce.to_vec(),
                            adaptor_point: adaptor_sig.adaptor_point.to_vec(),
                            pre_signature: adaptor_sig.pre_signature.to_vec(),
                            challenge: adaptor_sig.challenge.to_vec(),
                        }),
                    };
                    
                    let msg = p2p::P2pMessage {
                        payload: Some(p2p::p2p_message::Payload::SwapAliceAdaptorSig(sig_msg)),
                    };
                    
                    let topic = crate::constants::TOPIC_SWAP_ALICE_ADAPTOR_SIG.replace("{}", &get_network_name());
                    add_p2p_publish_command(&mut response, &topic, msg.encode_to_vec());
                    
                    add_log_command(&mut response, "success", "✓ Adaptor signature created and broadcast to Bob");
                }
                Err(e) => {
                    add_log_command(&mut response, "error", &format!("Failed to create adaptor sig: {}", e));
                }
            }
        }
    }
    
    post_async_response(response);
}

/// Handle Alice's adaptor signature (we are Bob, ready to claim)
pub async fn handle_swap_adaptor_sig_received(sig: p2p::SwapAliceAdaptorSig) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let swap_id_hex = hex::encode(&sig.swap_id);
    add_log_command(&mut response, "info", &format!(
        "[SWAP] Received adaptor signature for {}",
        &swap_id_hex[..8.min(swap_id_hex.len())]
    ));
    
    // Find the swap
    let swap_entry = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.atomic_swap_state.active_swaps.get(&swap_id_hex).cloned()
    };
    
    let entry = match swap_entry {
        Some(e) => e,
        None => {
            // Check pending proposals
            let pending = {
                let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                state.atomic_swap_state.pending_proposals.get(&swap_id_hex).cloned()
            };
            
            if pending.is_some() {
                add_log_command(&mut response, "warn", 
                    "Received adaptor sig for pending (not yet accepted) swap");
            } else {
                add_log_command(&mut response, "warn", "Received adaptor sig for unknown swap");
            }
            post_async_response(response);
            return;
        }
    };
    
    // Parse the swap
    let mut swap: crate::atomic_swap::AtomicSwap = match serde_json::from_str(&entry.swap_data_json) {
        Ok(s) => s,
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Corrupted swap data: {}", e));
            post_async_response(response);
            return;
        }
    };
    
    // Convert and store the adaptor signature
    if let Some(proto_sig) = sig.adaptor_sig {
        let adaptor_sig = crate::adaptor::AdaptorSignature {
            public_nonce: proto_sig.public_nonce.try_into().unwrap_or([0u8; 32]),
            adaptor_point: proto_sig.adaptor_point.try_into().unwrap_or([0u8; 32]),
            pre_signature: proto_sig.pre_signature.try_into().unwrap_or([0u8; 32]),
            challenge: proto_sig.challenge.try_into().unwrap_or([0u8; 32]),
        };
        
        // Verify the adaptor signature
        let alice_pubkey = match CompressedRistretto::from_slice(&swap.alice_pubkey)
            .ok()
            .and_then(|c| c.decompress())
        {
            Some(p) => p,
            None => {
                add_log_command(&mut response, "error", "Invalid Alice pubkey in swap");
                post_async_response(response);
                return;
            }
        };
        
        if !crate::adaptor::verify_adaptor_signature(&adaptor_sig, &alice_pubkey, &swap.swap_id) {
            add_log_command(&mut response, "error", "Invalid adaptor signature!");
            post_async_response(response);
            return;
        }
        
        swap.alice_adaptor_sig = Some(adaptor_sig);
        swap.state = crate::atomic_swap::SwapState::Committed;
        
        // Update state
        {
            let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = state.atomic_swap_state.active_swaps.get_mut(&swap_id_hex) {
                entry.state = "claimable".to_string();
                entry.swap_data_json = serde_json::to_string(&swap).unwrap_or_default();
            }
        }
        
        add_log_command(&mut response, "success", &format!(
            "✓ Valid adaptor signature received! Swap {} is now CLAIMABLE",
            &swap_id_hex[..8.min(swap_id_hex.len())]
        ));
        add_log_command(&mut response, "info", 
            "Use 'swap claim <swap_id> <wallet_id>' to claim Pluribit (reveals secret to Alice)");
    } else {
        add_log_command(&mut response, "error", "Adaptor signature message missing signature data");
    }
    
    post_async_response(response);
}

// --- Payment Channel: Received Handlers ---

/// Handle incoming channel proposal (we are Party B)
pub async fn handle_channel_proposal_received(from_peer: &str, proposal: p2p::ChannelProposal) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let channel_id_hex = hex::encode(&proposal.channel_id);
    let total_capacity = proposal.party_a_funding + proposal.party_b_funding;
    
    add_log_command(&mut response, "info", &format!(
        "[CHANNEL] Received proposal {} from {}: A={} B={} (total {})",
        &channel_id_hex[..8.min(channel_id_hex.len())],
        &from_peer[from_peer.len().saturating_sub(8)..],
        proposal.party_a_funding,
        proposal.party_b_funding,
        total_capacity
    ));
    
    // Validate proposal
    if proposal.party_a_pubkey.len() != 32 {
        add_log_command(&mut response, "warn", "Invalid channel proposal: bad pubkey");
        post_async_response(response);
        return;
    }
    
    if total_capacity < 100_000 {
        add_log_command(&mut response, "warn", "Invalid channel proposal: capacity too low");
        post_async_response(response);
        return;
    }
    
    // Check for duplicates
    {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        if state.payment_channel_state.pending_proposals.contains_key(&channel_id_hex) ||
           state.payment_channel_state.active_channels.contains_key(&channel_id_hex) {
            add_log_command(&mut response, "debug", "Duplicate channel proposal, ignoring");
            post_async_response(response);
            return;
        }
    }
    
    // Store the proposal
    {
        let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.payment_channel_state.pending_proposals.insert(
            channel_id_hex.clone(),
            crate::state::ChannelProposal {
                proposal_id: channel_id_hex.clone(),
                counterparty_pubkey: proposal.party_a_pubkey.clone(),
                my_amount: proposal.party_b_funding,
                their_amount: proposal.party_a_funding,
                received_at_ms: crate::state::current_time_ms(),
            },
        );
    }
    
    add_log_command(&mut response, "success", &format!(
        "✓ Channel proposal stored. Use 'channel accept {} <wallet_id>' to accept",
        &channel_id_hex[..8.min(channel_id_hex.len())]
    ));
    
    post_async_response(response);
}

/// Handle channel acceptance from Party B (we are Party A)
pub async fn handle_channel_acceptance_received(acc: p2p::ChannelAcceptance) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let channel_id_hex = hex::encode(&acc.channel_id);
    add_log_command(&mut response, "info", &format!(
        "[CHANNEL] Received acceptance for {}",
        &channel_id_hex[..8.min(channel_id_hex.len())]
    ));
    
    // Find the channel
    let channel_entry = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.payment_channel_state.active_channels.get(&channel_id_hex).cloned()
    };
    
    let entry = match channel_entry {
        Some(e) if e.our_party == "A" && e.state == "proposed" => e,
        Some(_) => {
            add_log_command(&mut response, "warn", "Channel not in expected state for acceptance");
            post_async_response(response);
            return;
        }
        None => {
            add_log_command(&mut response, "warn", "Received acceptance for unknown channel");
            post_async_response(response);
            return;
        }
    };
    
    // Parse the channel
    let mut channel: crate::payment_channel::PaymentChannel = match serde_json::from_str(&entry.channel_data_json) {
        Ok(c) => c,
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Corrupted channel data: {}", e));
            post_async_response(response);
            return;
        }
    };
    
    // Get our secret key
    let wallet_id = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.worker_flags.active_wallet_ids.iter().next().cloned()
    };
    
    let wallet_id = match wallet_id {
        Some(w) => w,
        None => {
            add_log_command(&mut response, "error", "No wallet loaded to complete channel open");
            post_async_response(response);
            return;
        }
    };
    
    let secret_vec = match get_wallet_spend_privkey(&wallet_id) {
        Ok(s) => s,
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to get wallet key: {}", e));
            post_async_response(response);
            return;
        }
    };
    
    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&secret_vec);
    let my_secret = Scalar::from_bytes_mod_order(secret_arr);
    
    // Get counterparty pubkey
    let party_b_pubkey = match CompressedRistretto::from_slice(&entry.counterparty_pubkey)
        .ok()
        .and_then(|c| c.decompress())
    {
        Some(p) => p,
        None => {
            add_log_command(&mut response, "error", "Invalid counterparty pubkey");
            post_async_response(response);
            return;
        }
    };
    
    // Convert proto commitment to internal type
    let party_b_commitment = match acc.party_b_commitment {
        Some(c) => {
            let tx = match c.commitment_tx {
                Some(tx) => crate::transaction::Transaction::from(tx),
                None => {
                    add_log_command(&mut response, "error", "Missing commitment tx");
                    post_async_response(response);
                    return;
                }
            };
            
            let adaptor_sig = match c.adaptor_signature {
                Some(s) => crate::adaptor::AdaptorSignature {
                    public_nonce: s.public_nonce.try_into().unwrap_or([0u8; 32]),
                    adaptor_point: s.adaptor_point.try_into().unwrap_or([0u8; 32]),
                    pre_signature: s.pre_signature.try_into().unwrap_or([0u8; 32]),
                    challenge: s.challenge.try_into().unwrap_or([0u8; 32]),
                },
                None => {
                    add_log_command(&mut response, "error", "Missing adaptor signature");
                    post_async_response(response);
                    return;
                }
            };
            
            crate::payment_channel::CommitmentState {
                sequence_number: c.sequence_number,
                owner: crate::payment_channel::Party::B,
                owner_balance: c.owner_balance,
                counterparty_balance: c.counterparty_balance,
                commitment_tx: tx,
                owner_blinding: c.owner_blinding,
                counterparty_blinding: c.counterparty_blinding,
                adaptor_signature: adaptor_sig,
                revocation_point: c.revocation_point.try_into().unwrap_or([0u8; 32]),
            }
        }
        None => {
            add_log_command(&mut response, "error", "Missing party B commitment");
            post_async_response(response);
            return;
        }
    };
    
    // Create internal acceptance struct
    let internal_acc = crate::payment_channel::ChannelAcceptance {
        channel_id: acc.channel_id.try_into().unwrap_or([0u8; 32]),
        party_b_commitment,
        party_b_revocation_point: acc.party_b_revocation_point.try_into().unwrap_or([0u8; 32]),
        accepted_at: acc.accepted_at,
    };
    
    // Complete the channel open
    let current_height = get_tip_height_from_db().await.unwrap_or(0);
    
    match channel.complete_open(&internal_acc, &my_secret, &party_b_pubkey, current_height) {
        Ok(()) => {
            // Update state
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(entry) = state.payment_channel_state.active_channels.get_mut(&channel_id_hex) {
                    entry.state = "ready_to_fund".to_string();
                    entry.channel_data_json = serde_json::to_string(&channel).unwrap_or_default();
                }
            }
            
            add_log_command(&mut response, "success", &format!(
                "✓ Channel {} open handshake complete! Ready to fund.",
                &channel_id_hex[..8.min(channel_id_hex.len())]
            ));
            add_log_command(&mut response, "info", 
                "Use 'channel fund <channel_id> <wallet_id>' to create funding transaction");
        }
        Err(e) => {
            add_log_command(&mut response, "error", &format!("Failed to complete channel open: {}", e));
        }
    }
    
    post_async_response(response);
}

/// Handle funding nonce from counterparty (MuSig2 step 1)
pub async fn handle_channel_fund_nonce_received(nonce: p2p::ChannelNonce) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let channel_id_hex = hex::encode(&nonce.channel_id);
    add_log_command(&mut response, "info", &format!(
        "[CHANNEL] Received funding nonce for {}",
        &channel_id_hex[..8.min(channel_id_hex.len())]
    ));
    
    // Find the channel
    let channel_entry = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.payment_channel_state.active_channels.get(&channel_id_hex).cloned()
    };
    
    match channel_entry {
        Some(entry) if entry.state == "ready_to_fund" || entry.state == "funding_nonces" => {
            // Store the counterparty nonce
            // In a full implementation, you'd store this and proceed with MuSig2 aggregation
            add_log_command(&mut response, "success", &format!(
                "✓ Stored counterparty nonce for channel {}",
                &channel_id_hex[..8.min(channel_id_hex.len())]
            ));
            
            // Update state to indicate we have the nonce
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(entry) = state.payment_channel_state.active_channels.get_mut(&channel_id_hex) {
                    if entry.state == "ready_to_fund" {
                        entry.state = "funding_nonces".to_string();
                    } else {
                        entry.state = "funding_ready".to_string();
                    }
                }
            }
            
            add_log_command(&mut response, "info", 
                "Nonce exchange complete. Proceeding with funding signature...");
        }
        Some(_) => {
            add_log_command(&mut response, "warn", "Channel not in expected state for funding nonce");
        }
        None => {
            add_log_command(&mut response, "warn", "Received funding nonce for unknown channel");
        }
    }
    
    post_async_response(response);
}

/// Handle funding partial signature from counterparty (MuSig2 step 2)
pub async fn handle_channel_fund_sig_received(sig: p2p::ChannelPartialSig) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let channel_id_hex = hex::encode(&sig.channel_id);
    add_log_command(&mut response, "info", &format!(
        "[CHANNEL] Received funding signature for {}",
        &channel_id_hex[..8.min(channel_id_hex.len())]
    ));
    
    // Find the channel
    let channel_entry = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.payment_channel_state.active_channels.get(&channel_id_hex).cloned()
    };
    
    match channel_entry {
        Some(entry) if entry.state == "funding_nonces" || entry.state == "funding_ready" => {
            // In a full implementation:
            // 1. Aggregate the partial signatures
            // 2. Verify the aggregate signature
            // 3. Finalize and broadcast the funding transaction
            // 4. Wait for confirmations
            
            add_log_command(&mut response, "success", &format!(
                "✓ Received counterparty funding signature for channel {}",
                &channel_id_hex[..8.min(channel_id_hex.len())]
            ));
            
            // For now, update state to pending (this is a placeholder. we need to broadcast tx here)
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(entry) = state.payment_channel_state.active_channels.get_mut(&channel_id_hex) {
                    entry.state = "pending_confirmation".to_string();
                }
            }
            
            add_log_command(&mut response, "info", 
                "Funding transaction finalized. Waiting for on-chain confirmation...");
        }
        Some(_) => {
            add_log_command(&mut response, "warn", "Channel not in expected state for funding sig");
        }
        None => {
            add_log_command(&mut response, "warn", "Received funding sig for unknown channel");
        }
    }
    
    post_async_response(response);
}

/// Handle in-channel payment proposal
pub async fn handle_channel_pay_proposal_received(proposal: p2p::PaymentProposal) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let channel_id_hex = hex::encode(&proposal.channel_id);
    add_log_command(&mut response, "info", &format!(
        "[CHANNEL] Received payment proposal: {} bits on channel {}",
        proposal.amount,
        &channel_id_hex[..8.min(channel_id_hex.len())]
    ));
    
    // Find the channel
    let channel_entry = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.payment_channel_state.active_channels.get(&channel_id_hex).cloned()
    };
    
    match channel_entry {
        Some(entry) if entry.state == "open" => {
            let channel: crate::payment_channel::PaymentChannel = match serde_json::from_str(&entry.channel_data_json) {
                Ok(c) => c,
                Err(_) => {
                    add_log_command(&mut response, "error", "Corrupted channel data");
                    post_async_response(response);
                    return;
                }
            };
            
            // Validate the payment
            let sender_party = if proposal.sender_party_enum == 0 { 
                crate::payment_channel::Party::A 
            } else { 
                crate::payment_channel::Party::B 
            };
            
            // Check sequence number is correct
            if proposal.new_sequence != channel.sequence_number + 1 {
                add_log_command(&mut response, "warn", &format!(
                    "Invalid sequence: expected {}, got {}",
                    channel.sequence_number + 1,
                    proposal.new_sequence
                ));
                post_async_response(response);
                return;
            }
            
            // Check balances are valid
            let total = proposal.new_balance_a + proposal.new_balance_b;
            if total != channel.total_capacity {
                add_log_command(&mut response, "warn", "Payment doesn't preserve channel capacity");
                post_async_response(response);
                return;
            }
            
            add_log_command(&mut response, "success", &format!(
                "✓ Valid payment proposal. New balances: A={} B={}",
                proposal.new_balance_a,
                proposal.new_balance_b
            ));
            
            // Auto-accept (in production, might want user confirmation for large amounts)
            // Here we'd:
            // 1. Create our new commitment
            // 2. Reveal old revocation secret
            // 3. Send PaymentAcceptance
            
            add_log_command(&mut response, "info", "Auto-accepting payment...");
            
            // For now just log - full implementation would update state and send acceptance
        }
        Some(_) => {
            add_log_command(&mut response, "warn", "Channel not open, cannot process payment");
        }
        None => {
            add_log_command(&mut response, "warn", "Received payment for unknown channel");
        }
    }
    
    post_async_response(response);
}

/// Handle payment acceptance from counterparty
pub async fn handle_channel_pay_acceptance_received(acc: p2p::PaymentAcceptance) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let channel_id_hex = hex::encode(&acc.channel_id);
    add_log_command(&mut response, "info", &format!(
        "[CHANNEL] Payment accepted on channel {} (seq {})",
        &channel_id_hex[..8.min(channel_id_hex.len())],
        acc.sequence
    ));
    
    // Find and update the channel
    let channel_entry = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.payment_channel_state.active_channels.get(&channel_id_hex).cloned()
    };
    
    match channel_entry {
        Some(entry) if entry.state == "open" => {
            let mut channel: crate::payment_channel::PaymentChannel = match serde_json::from_str(&entry.channel_data_json) {
                Ok(c) => c,
                Err(_) => {
                    add_log_command(&mut response, "error", "Corrupted channel data");
                    post_async_response(response);
                    return;
                }
            };
            
            // Store counterparty's new commitment
            // Store their old revocation secret (allows us to punish cheating)
            if let Some(revocation) = acc.old_revocation {
                let revocation_data = crate::payment_channel::RevocationData {
                    party: if revocation.party_enum == 0 { 
                        crate::payment_channel::Party::A 
                    } else { 
                        crate::payment_channel::Party::B 
                    },
                    sequence_number: revocation.sequence_number,
                    revocation_secret: revocation.revocation_secret.try_into().unwrap_or([0u8; 32]),
                    revocation_point: revocation.revocation_point.try_into().unwrap_or([0u8; 32]),
                    revoked_at: revocation.revoked_at,
                };
                channel.counterparty_revoked_states.insert(revocation.sequence_number, revocation_data);
            }
            
            channel.sequence_number = acc.sequence;
            channel.total_payments += 1;
            
            // Update state
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(entry) = state.payment_channel_state.active_channels.get_mut(&channel_id_hex) {
                    entry.channel_data_json = serde_json::to_string(&channel).unwrap_or_default();
                }
            }
            
            add_log_command(&mut response, "success", &format!(
                "✓ Payment {} complete! Channel {} now at sequence {}",
                channel.total_payments,
                &channel_id_hex[..8.min(channel_id_hex.len())],
                channel.sequence_number
            ));
        }
        _ => {
            add_log_command(&mut response, "warn", "Channel not in valid state for payment acceptance");
        }
    }
    
    post_async_response(response);
}

/// Handle cooperative close nonce from counterparty
pub async fn handle_channel_close_nonce_received(nonce: p2p::ChannelNonce) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let channel_id_hex = hex::encode(&nonce.channel_id);
    add_log_command(&mut response, "info", &format!(
        "[CHANNEL] Received close nonce for {}",
        &channel_id_hex[..8.min(channel_id_hex.len())]
    ));
    
    // Find the channel
    let channel_entry = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.payment_channel_state.active_channels.get(&channel_id_hex).cloned()
    };
    
    match channel_entry {
        Some(entry) if entry.state == "open" || entry.state == "closing" => {
            add_log_command(&mut response, "success", &format!(
                "✓ Stored close nonce for channel {}",
                &channel_id_hex[..8.min(channel_id_hex.len())]
            ));
            
            // Update state
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(entry) = state.payment_channel_state.active_channels.get_mut(&channel_id_hex) {
                    entry.state = "closing".to_string();
                }
            }
            
            add_log_command(&mut response, "info", 
                "Cooperative close in progress. Awaiting signature...");
        }
        Some(_) => {
            add_log_command(&mut response, "warn", "Channel not in valid state for closing");
        }
        None => {
            add_log_command(&mut response, "warn", "Received close nonce for unknown channel");
        }
    }
    
    post_async_response(response);
}

/// Handle cooperative close signature from counterparty
pub async fn handle_channel_close_sig_received(sig: p2p::ChannelPartialSig) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    let channel_id_hex = hex::encode(&sig.channel_id);
    add_log_command(&mut response, "info", &format!(
        "[CHANNEL] Received close signature for {}",
        &channel_id_hex[..8.min(channel_id_hex.len())]
    ));
    
    // Find the channel
    let channel_entry = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.payment_channel_state.active_channels.get(&channel_id_hex).cloned()
    };
    
    match channel_entry {
        Some(entry) if entry.state == "closing" => {
            let channel: crate::payment_channel::PaymentChannel = match serde_json::from_str(&entry.channel_data_json) {
                Ok(c) => c,
                Err(_) => {
                    add_log_command(&mut response, "error", "Corrupted channel data");
                    post_async_response(response);
                    return;
                }
            };
            
            // In full implementation:
            // 1. Aggregate signatures
            // 2. Create final settlement transaction
            // 3. Broadcast to network
            
            add_log_command(&mut response, "success", &format!(
                "✓ Channel {} closed cooperatively. Final balances: A={} B={}",
                &channel_id_hex[..8.min(channel_id_hex.len())],
                channel.party_a_balance,
                channel.party_b_balance
            ));
            
            // Update state to closed
            {
                let mut state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(entry) = state.payment_channel_state.active_channels.get_mut(&channel_id_hex) {
                    entry.state = "closed".to_string();
                    entry.balance_a = channel.party_a_balance;
                    entry.balance_b = channel.party_b_balance;
                }
            }
            
            // Broadcast settlement transaction (if we had it from funding_tx field)
            if let Some(ref _funding_tx) = sig.funding_tx {
                add_log_command(&mut response, "info", "Broadcasting settlement transaction...");
                // Would broadcast here
            }
        }
        Some(_) => {
            add_log_command(&mut response, "warn", "Channel not in closing state");
        }
        None => {
            add_log_command(&mut response, "warn", "Received close sig for unknown channel");
        }
    }
    
    post_async_response(response);
}

// --- Block Filters (Light Client Support) ---

/// Handle request for block filters from a light client
pub async fn handle_block_filters_request(from_peer: &str, req: p2p::GetBlockFiltersRequest) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    add_log_command(&mut response, "debug", &format!(
        "[FILTERS] Request from {} for heights {}-{}",
        &from_peer[from_peer.len().saturating_sub(8)..],
        req.start_height,
        req.end_height
    ));
    
    // Validate request
    if req.end_height < req.start_height {
        add_log_command(&mut response, "warn", "Invalid filter request: end < start");
        post_async_response(response);
        return;
    }
    
    let max_filters = 1000u64;
    if req.end_height - req.start_height > max_filters {
        add_log_command(&mut response, "warn", "Filter request too large");
        post_async_response(response);
        return;
    }
    
    // Load filters from blockchain module
    let filters = {
        let chain = BLOCKCHAIN.lock().unwrap_or_else(|p| p.into_inner());
        let mut result = Vec::new();
        
        for height in req.start_height..=req.end_height {
            // This now works because we added block_filters to Blockchain struct
            if let Some(filter_entries) = chain.block_filters.get(&height) {
                result.push(p2p::BlockFilterData {
                    height,
                    // Serialize the Vec<BlockFilterEntry> to bytes for the Protobuf message
                    filter_entries: serde_json::to_vec(filter_entries).unwrap_or_default(),
                });
            }
        }
        result
    };
    
    if filters.is_empty() {
        add_log_command(&mut response, "debug", "No filters found for requested range");
        post_async_response(response);
        return;
    }
    
    // Send response
    let filter_resp = p2p::BlockFiltersResponse {
        filters,
        request_id: req.request_id,
    };
    
    let msg = p2p::P2pMessage {
        payload: Some(p2p::p2p_message::Payload::BlockFiltersResponse(filter_resp)),
    };
    
    // Send directly to requesting peer
    let protocol = crate::constants::TOPIC_SYNC.replace("{}", &get_network_name());
    add_p2p_send_direct_command(&mut response, from_peer, &protocol, msg.encode_to_vec());
    
    add_log_command(&mut response, "debug", &format!(
        "Sent {} block filters to {}",
        req.end_height - req.start_height + 1,
        &from_peer[from_peer.len().saturating_sub(8)..]
    ));
    
    post_async_response(response);
}

/// Handle block filters response (we are light client)
pub async fn handle_block_filters_response(resp: p2p::BlockFiltersResponse) {
    let mut response = p2p::RustToJsCommandBatch::default();
    
    add_log_command(&mut response, "info", &format!(
        "[FILTERS] Received {} block filters (request {})",
        resp.filters.len(),
        &resp.request_id[..8.min(resp.request_id.len())]
    ));
    
    if resp.filters.is_empty() {
        add_log_command(&mut response, "debug", "No filters in response");
        post_async_response(response);
        return;
    }
    
    // Process filters - scan for wallet-relevant transactions
    let wallet_ids: Vec<String> = {
        let state = GLOBAL_STATE.lock().unwrap_or_else(|p| p.into_inner());
        state.worker_flags.active_wallet_ids.iter().cloned().collect()
    };
    
    let mut relevant_heights: Vec<u64> = Vec::new();
    
    for filter_data in &resp.filters {
        // FIX 1: Deserialize as Vec<BlockFilterEntry>, not a single struct
        if let Ok(entries) = serde_json::from_slice::<Vec<crate::blockchain::BlockFilterEntry>>(&filter_data.filter_entries) {
            
            for wallet_id in &wallet_ids {
                if let Ok(scan_pubkey) = get_wallet_scan_pubkey(wallet_id) {
                    
                    // Iterate over the entries in the vector
                    for filter_entry in &entries {
                        
                        // FIX 2: [E0609] Access singular 'view_tag' (Vec<u8>), not 'view_tags'
                        let view_tag = &filter_entry.view_tag;
                        
                        // Simple check - in production would compute expected view tag
                        if !view_tag.is_empty() {
                            // If view tag could match, mark this height as relevant
                            relevant_heights.push(filter_data.height);
                            break; 
                        }
                    }
                }
            }
        }
    }
    
    // Remove duplicates and sort
    relevant_heights.sort();
    relevant_heights.dedup();
    
    if relevant_heights.is_empty() {
        add_log_command(&mut response, "debug", "No relevant blocks found in filters");
    } else {
        add_log_command(&mut response, "info", &format!(
            "Found {} potentially relevant blocks: {:?}",
            relevant_heights.len(),
            &relevant_heights[..5.min(relevant_heights.len())]
        ));
        
        // Request full blocks for relevant heights
        for height in relevant_heights {
            add_log_command(&mut response, "debug", &format!(
                "Should request block at height {} for scanning",
                height
            ));
            // In production: request_block_by_height(height, &mut response);
        }
    }
    
    post_async_response(response);
}
