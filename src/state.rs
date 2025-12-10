// src/state.rs
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use crate::block::Block;
use crate::atomic_swap::AtomicSwap;
use crate::payment_channel::PaymentChannel;
use crate::wasm_types::WasmU64;
use crate::p2p;

// =============================================================================
// SYNC STATE
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    Idle,
    Consensus,
    Downloading,
    Cooldown,
}

impl Default for SyncStatus {
    fn default() -> Self {
        SyncStatus::Idle
    }
}

#[derive(Debug, Default)]
pub struct SyncProgress {
    pub current_height: u64,
    pub target_height: u64,
    pub status: SyncStatus,
    pub start_time_ms: u64,
}

#[derive(Debug, Default)]
pub struct SyncState {
    pub sync_progress: SyncProgress,
    pub consecutive_failures: u32,
    pub active_hash_requests: HashMap<String, HashRequestState>, // request_id -> state
    pub tip_responses: HashMap<String, TipResponseData>, // peer_id -> data
}

#[derive(Debug)]
pub struct HashRequestState {
    pub request_id: String,
    pub peer_id: String,
    pub hashes: Vec<String>,
    pub start_time_ms: u64,
    pub last_chunk_time_ms: u64,
    pub is_complete: bool,
}

#[derive(Debug, Clone)]
pub struct TipResponseData {
    pub hash: String,
    pub height: u64,
    pub total_work: String, // Keep as string to handle BigInts safely
    pub received_at_ms: u64,
}

impl SyncState {
    pub fn reset(&mut self) {
        self.sync_progress = SyncProgress::default();
        self.consecutive_failures = 0;
        self.active_hash_requests.clear();
        self.tip_responses.clear();
    }
}

// =============================================================================
// REORG STATE
// =============================================================================

#[derive(Debug, Default)]
pub struct ReorgState {
    pub pending_forks: HashMap<u64, Vec<Block>>, // height -> blocks
    pub requested_blocks: HashSet<String>,        // hashes currently requested
    pub requested_at: HashMap<String, u64>,       // hash -> timestamp_ms
}

impl ReorgState {
    pub const REQUEST_TTL_MS: u64 = 15000;
    
    pub fn track_request(&mut self, hash: &str) {
        self.requested_blocks.insert(hash.to_string());
        self.requested_at.insert(hash.to_string(), current_time_ms());
    }
    
    pub fn is_requested(&self, hash: &str) -> bool {
        if !self.requested_blocks.contains(hash) {
            return false;
        }
        // Check TTL
        if let Some(ts) = self.requested_at.get(hash) {
            if current_time_ms() - ts > Self::REQUEST_TTL_MS {
                return false; // Expired
            }
        }
        true
    }
}

// =============================================================================
// MINER STATE
// =============================================================================

#[derive(Debug, Default)]
pub struct MinerState {
    pub active: bool,
    pub wallet_id: Option<String>,
    pub current_job_id: u64,
    pub processing_candidate_height: Option<u64>,
    pub was_active_before_reorg: bool,
}

impl MinerState {
    pub fn next_job_id(&mut self) -> u64 {
        self.current_job_id += 1;
        self.current_job_id
    }
}

// =============================================================================
// PEER STATE & SCORING
// =============================================================================

#[derive(Debug, Clone)]
pub struct PeerScore {
    pub score: i32,
    pub bad_block_count: u32,
    pub last_violation_ms: u64,
}

impl Default for PeerScore {
    fn default() -> Self {
        Self {
            score: 100,
            bad_block_count: 0,
            last_violation_ms: 0,
        }
    }
}

#[derive(Debug, Default)]
pub struct PeerState {
    pub connected_peers: HashSet<String>,
    pub verified_peers: HashSet<String>,
    pub scores: HashMap<String, PeerScore>,
    pub poisoned_hashes: HashSet<String>,
}

impl PeerState {
    pub fn record_connected(&mut self, peer_id: &str) {
        self.connected_peers.insert(peer_id.to_string());
        self.scores.entry(peer_id.to_string()).or_insert_with(PeerScore::default);
    }

    pub fn record_disconnected(&mut self, peer_id: &str) {
        self.connected_peers.remove(peer_id);
        self.verified_peers.remove(peer_id);
    }

    pub fn record_verified(&mut self, peer_id: &str) {
        self.verified_peers.insert(peer_id.to_string());
    }

    pub fn record_bad_block(&mut self, peer_id: &str) -> bool {
        let score = self.scores.entry(peer_id.to_string()).or_insert_with(PeerScore::default);
        score.bad_block_count += 1;
        score.last_violation_ms = current_time_ms();
        score.score -= 25;
        score.bad_block_count >= 3 || score.score <= 0
    }

    pub fn poison_hash(&mut self, hash: &str, _reason: &str, peer_id: &str) {
        self.poisoned_hashes.insert(hash.to_string());
        // Heavy penalty for sending poisoned hash
        if let Some(score) = self.scores.get_mut(peer_id) {
            score.score = 0;
        }
    }

    pub fn is_hash_poisoned(&self, hash: &str) -> bool {
        self.poisoned_hashes.contains(hash)
    }
}

// =============================================================================
// L2 & WORKER FLAGS
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicSwapEntry {
    pub swap_id: String,
    pub our_role: String,
    pub counterparty_pubkey: Vec<u8>,
    pub plb_amount: u64,
    pub btc_amount: u64,
    pub timeout_height: u64,
    pub state: String,
    pub created_at_ms: u64,
    pub swap_data_json: String, // Full serialized AtomicSwap
}

#[derive(Debug, Default)]
pub struct AtomicSwapState {
    pub active_swaps: HashMap<String, AtomicSwapEntry>,
    pub pending_proposals: HashMap<String, SwapProposal>,
}

#[derive(Debug, Clone)]
pub struct SwapProposal {
    pub proposal_id: String,
    pub counterparty_pubkey: Vec<u8>,
    pub plb_amount: u64,
    pub btc_amount: u64,
    pub timeout_blocks: u64,
    pub received_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentChannelEntry {
    pub channel_id: String,
    pub our_party: String,
    pub counterparty_pubkey: Vec<u8>,
    pub balance_a: u64,
    pub balance_b: u64,
    pub state: String,
    pub dispute_period_blocks: u64,
    pub created_at_ms: u64,
    pub channel_data_json: String, // Full serialized PaymentChannel
}

#[derive(Debug, Default)]
pub struct PaymentChannelState {
    pub active_channels: HashMap<String, PaymentChannelEntry>,
    pub pending_proposals: HashMap<String, ChannelProposal>,
}

#[derive(Debug, Clone)]
pub struct ChannelProposal {
    pub proposal_id: String,
    pub counterparty_pubkey: Vec<u8>,
    pub my_amount: u64,
    pub their_amount: u64,
    pub received_at_ms: u64,
}

#[derive(Debug, Default)]
pub struct WorkerFlags {
    pub is_reorging: bool,
    pub is_syncing: bool,
    pub is_downloading_chain: bool,
    pub active_wallet_ids: HashSet<String>,
    pub is_processing_block: bool,
}

#[derive(Debug, Default)]
pub struct DeferredBlocks {
    pub blocks: Vec<DeferredBlock>,
}

#[derive(Debug, Clone)]
pub struct DeferredBlock {
    pub hash: String,
    pub height: u64,
    pub block_bytes: Vec<u8>,
    pub received_at_ms: u64,
    pub from_peer: Option<String>,
}

impl DeferredBlocks {
    pub fn add(&mut self, hash: &str, height: u64, bytes: Vec<u8>, from_peer: Option<String>) {
        self.blocks.push(DeferredBlock {
            hash: hash.to_string(),
            height,
            block_bytes: bytes,
            received_at_ms: current_time_ms(),
            from_peer,
        });
    }

    pub fn get_blocks_at_height(&self, height: u64) -> Vec<&DeferredBlock> {
        self.blocks.iter().filter(|b| b.height == height).collect()
    }

    pub fn remove(&mut self, hash: &str) {
        self.blocks.retain(|b| b.hash != hash);
    }
    
    pub fn clear(&mut self) {
        self.blocks.clear();
    }
}

// =============================================================================
// GLOBAL STATE SINGLETON
// =============================================================================

#[derive(Debug)]
pub struct GlobalState {
    pub network: String,
    pub our_peer_id: String,  
    pub sync_state: SyncState,
    pub reorg_state: ReorgState,
    pub miner_state: MinerState,
    pub peer_state: PeerState,
    pub worker_flags: WorkerFlags,
    pub deferred_blocks: DeferredBlocks,
    pub atomic_swap_state: AtomicSwapState,
    pub payment_channel_state: PaymentChannelState,
    pub block_queue: VecDeque<(p2p::Block, Option<String>)>,
}
impl Default for GlobalState {
    fn default() -> Self {
        Self {
            network: "mainnet".to_string(), // Default fallback
            our_peer_id: String::new(),  
            sync_state: SyncState::default(),
            reorg_state: ReorgState::default(),
            miner_state: MinerState::default(),
            peer_state: PeerState::default(),
            worker_flags: WorkerFlags::default(),
            deferred_blocks: DeferredBlocks::default(),
            atomic_swap_state: AtomicSwapState::default(),
            payment_channel_state: PaymentChannelState::default(),
            block_queue: VecDeque::new(),
        }
    }
}
impl GlobalState {
    pub fn start_sync(&mut self, target_height: u64) {
        self.sync_state.sync_progress.status = SyncStatus::Downloading;
        self.sync_state.sync_progress.target_height = target_height;
        self.sync_state.sync_progress.start_time_ms = current_time_ms();
        self.worker_flags.is_syncing = true;
    }
    
    pub fn end_sync(&mut self) {
        self.sync_state.sync_progress.status = SyncStatus::Idle;
        self.sync_state.consecutive_failures = 0;
        self.worker_flags.is_syncing = false;
        self.worker_flags.is_downloading_chain = false;
    }

    pub fn start_reorg(&mut self) {
        self.worker_flags.is_reorging = true;
        if self.miner_state.active {
            self.miner_state.was_active_before_reorg = true;
            self.miner_state.active = false;
        }
    }

    pub fn end_reorg(&mut self) {
        self.worker_flags.is_reorging = false;
        if self.miner_state.was_active_before_reorg {
            self.miner_state.active = true;
            self.miner_state.was_active_before_reorg = false;
        }
    }

    pub fn start_miner(&mut self, wallet_id: &str) -> u64 {
        self.miner_state.active = true;
        self.miner_state.wallet_id = Some(wallet_id.to_string());
        self.miner_state.next_job_id()
    }

    pub fn stop_miner(&mut self) {
        self.miner_state.active = false;
        self.miner_state.processing_candidate_height = None;
    }
}

// Helper structs for Node Status Response
#[derive(Serialize)]
pub struct NodeStatus {
    pub is_mining: bool,
    pub is_syncing: bool,
    pub is_reorging: bool,
    pub connected_peers: usize,
    pub verified_peers: usize,
    pub active_wallets: usize,
}

impl From<&GlobalState> for NodeStatus {
    fn from(state: &GlobalState) -> Self {
        Self {
            is_mining: state.miner_state.active,
            is_syncing: state.worker_flags.is_syncing,
            is_reorging: state.worker_flags.is_reorging,
            connected_peers: state.peer_state.connected_peers.len(),
            verified_peers: state.peer_state.verified_peers.len(),
            active_wallets: state.worker_flags.active_wallet_ids.len(),
        }
    }
}



lazy_static! {
    pub static ref GLOBAL_STATE: Mutex<GlobalState> = Mutex::new(GlobalState::default());
}
pub fn get_our_peer_id() -> String {
    let state = GLOBAL_STATE.lock().unwrap();
    state.our_peer_id.clone()
}
pub fn current_time_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::SystemTime;
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64
    }
}
