// src/constants.rs

// ─── Consensus timing ──────────────────────────────────────────────────────────

/// Target block time (seconds).
pub const TARGET_BLOCK_TIME: u64 = 30; // 30 seconds

/// Retarget window (≈ 1 hour @ 5 min/blk).
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 12;

/// Median-Time-Past window used to sanity-check block timestamps.
pub const MTP_WINDOW: usize = 11;

/// How far in the future a block time may be (milliseconds).
/// 2 hours is conventional and safe for clock skew.
pub const MAX_FUTURE_DRIFT_MS: u64 = 2 * 60 * 60 * 1000;


/// Seconds/year (365 days; use this to keep block counts integral).
pub const SECONDS_PER_YEAR: u64 = 31_536_000;

/// Integer blocks/year at TARGET_BLOCK_TIME (floored).
/// With 120s blocks: 31,536,000 / 120 = 262,800.
pub const BLOCKS_PER_YEAR: u64 = SECONDS_PER_YEAR / TARGET_BLOCK_TIME;

/// Maximum number of transactions allowed in the mempool.
pub const MAX_TX_POOL_SIZE: usize = 4096;

// ─── Genesis anchors ───────────────────────────────────────────────────────────

/// Fixed timestamp used by the genesis block.
pub const GENESIS_TIMESTAMP_MS: u64 = 1_750_000_658_000; // 2025-06-15 14:57:38 UTC

/// Canonical genesis block hash for network consensus.
/// All nodes must agree on this exact genesis or they're on different networks.
pub const CANONICAL_GENESIS_HASH: &str = 
    "198d259fd16259ff54fdf91e07da5d32cc7732caa0e76f91703fcc4447ff9ec0";

/// Bitcoin block hash anchoring the genesis state.
pub const GENESIS_BITCOIN_HASH: &str =
    "00000000000000000000656b995c9fec9ff94b554dc4aad46c06b71f94088c3c";

// ─── Unit Topology ─────────────────────────────────────────────────────────────
pub const ONE_BYTE: u64 = 8;
pub const ONE_KB: u64 = 1024 * ONE_BYTE; // 8,192 atomic bits
pub const ONE_MB: u64 = 1024 * ONE_KB;   // 8,388,608 atomic bits

// ─── Block reward schedule ─────────────────────────────────────────────────────

/// Base reward at the start of each era.
/// 50 Kiloƀytes = 50 * 1024 * 8 = 409,600 atomic ƀits
pub const INITIAL_BASE_REWARD: u64 = 50 * ONE_KB;

/// Halving cadence: once every 2 years.
pub const YEARS_PER_HALVING: u64 = 2;
/// Blocks between halvings (computed).
/// With 120s blocks: 2 * 262,800 = 525,600.
pub const HALVING_INTERVAL: u64 = YEARS_PER_HALVING * BLOCKS_PER_YEAR;

/// Era length: reward schedule resets every 20 years.
pub const YEARS_PER_RESET: u64 = 20;
/// Blocks after which the halving cycle resets.
/// With 120s blocks: 20 * 262,800 = 5,256,000.
pub const REWARD_RESET_INTERVAL: u64 = YEARS_PER_RESET * BLOCKS_PER_YEAR;

// ─── VDF (time) parameters ────────────────────────────────────────────────────

/// VDF security parameter used when constructing the VDF instance.
pub const VDF_SECURITY_PARAM: u32 = 2048;

/// Minimum/maximum VDF iterations allowed after retargeting.
pub const MIN_VDF_ITERATIONS: u64 = 1_000;
pub const MAX_VDF_ITERATIONS: u64 = 1_000_000_000;

/// Default VDF iterations at startup 
pub const INITIAL_VDF_ITERATIONS: u64 = 2_000;

pub const VDF_RSA_MODULUS_HEX: &str =
"C7970CEEDCC3B0754490201A7AA613CD73911081C790F5F1A8726F463550BB5B7FF0DB8E1EA1189EC72F93D1650011BD721AEEACC2ACDE32A04107F0648C2813A31F5B0B7765FF8B44B4B6FFC93384B646EB09C7CF5E8592D40EA33C80039F35B4F14A04B51F7BFD781BE4D1673164BA8EB991C2C4D730BBBE35F592BDEF524AF7E8DAEFD26C66FC02C479AF89D64D373F442709439DE66CEB955F3EA37D5159F6135809F85334B5CB1813ADDC80CD05609F10AC6A95AD65872C909525BDAD32BC729592642920F24C61DC5B3C3B7923E56B16A4D9D373D8721F24A3FC0F1B3131F55615172866BCCC30F95054C824E733A5EB6817F7BC16399D48C6361CC7E5";

/// sanity-check for the modulus we expect at runtime.
pub const VDF_RSA_MODULUS_BITS: u64 = 2048;

/// SHA-256 fingerprint of the modulus bytes (tamper check).
pub const VDF_RSA_MODULUS_SHA256_HEX: &str = "6ae9d033c1d76c4f535b5ad5c0073933a0b375b4120a75fbb66be814eab1a9ce";

// ─── VRF (lottery) parameters ─────────────────────────────────────────────────

/// Default VRF threshold used at startup for leader election.
pub const DEFAULT_VRF_THRESHOLD: [u8; 32] = [
    0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Minimum threshold clamp 
pub const VRF_MIN_THRESHOLD: [u8; 32] = [
    0x00, 0x28, 0xF5, 0xC2, 0x8F, 0x5C, 0x28, 0xF5,
    0xC2, 0x8F, 0x5C, 0x28, 0xF5, 0xC2, 0x8F, 0x5C,
    0x28, 0xF5, 0xC2, 0x8F, 0x5C, 0x28, 0xF5, 0xC2,
    0x8F, 0x5C, 0x28, 0xF5, 0xC2, 0x8F, 0x5C, 0x29,
];

/// Maximum threshold clamp (all 0xFF).
pub const VRF_MAX_THRESHOLD: [u8; 32] = [0xFF; 32];

// ─── Spending rules ────────────────────────────────────────────────────────────

/// Confirmations required before a coinbase output is spendable.
pub const COINBASE_MATURITY: u64 = 6; // will be 696 for mainnet blocks ~ 2.5 days

// ─── Domain separation tags (single source of truth) ───────────────────────────

pub const DOMAIN_VDF_INPUT: &[u8]        = b"pluribit_vdf_input_v2";
pub const DOMAIN_SCHNORR_NONCE: &[u8]    = b"pluribit_schnorr_nonce_v1";
pub const DOMAIN_SCHNORR_CHALLENGE: &[u8]= b"pluribit_schnorr_v1";
pub const DOMAIN_VRF_NONCE: &[u8]        = b"pluribit_vrf_nonce_v1";
pub const DOMAIN_VRF_CHALLENGE: &[u8]    = b"pluribit_vrf_challenge_v1";
pub const DOMAIN_VRF_OUTPUT: &[u8]       = b"pluribit_vrf_output_v1";
pub const DOMAIN_BLOCK_HASH: &[u8]       = b"pluribit_block_v3";
pub const DOMAIN_TX_HASH: &[u8]          = b"pluribit_tx_v2";
// ─── P2P Topic Templates ───────────────────────────────────────────────────────
// The {} placeholder is for the network name (e.g. "mainnet", "testnet")
// These MUST match the definitions in libp2p-node.js

// Core Chain Topics
pub const TOPIC_BLOCKS: &str = "/pluribit/{}/blocks/1.0.0.1";
pub const TOPIC_TRANSACTIONS: &str = "/pluribit/{}/transactions/1.0.0.1";
pub const TOPIC_BLOCK_ANNOUNCEMENTS: &str = "/pluribit/{}/block-announcements/1.0.0.1";

// Sync & Request Topics
pub const TOPIC_BLOCK_REQUEST: &str = "/pluribit/{}/block-request/1.0.0.1";
pub const TOPIC_SYNC: &str = "/pluribit/{}/sync/1.0.0.1";
pub const TOPIC_GET_HASHES_REQUEST: &str = "/pluribit/{}/get-hashes-request/1.0.0.1";
pub const TOPIC_HASHES_RESPONSE: &str = "/pluribit/{}/hashes-response/1.0.0.1";

// Dandelion Privacy
pub const TOPIC_DANDELION_STEM: &str = "/pluribit/{}/dandelion-stem/1.0.0.1";

// Peer Exchange
pub const PROTOCOL_PEX: &str = "/pluribit/{}/pex/1.0.0.1";

// L2: Payment Channels
pub const TOPIC_CHANNEL_PROPOSE: &str = "/pluribit/{}/channel-propose/1.0.0.1";
pub const TOPIC_CHANNEL_ACCEPT: &str = "/pluribit/{}/channel-accept/1.0.0.1";
pub const TOPIC_CHANNEL_FUND_NONCE: &str = "/pluribit/{}/channel-fund-nonce/1.0.0.1";
pub const TOPIC_CHANNEL_FUND_SIG: &str = "/pluribit/{}/channel-fund-sig/1.0.0.1";
pub const TOPIC_CHANNEL_PAY_PROPOSE: &str = "/pluribit/{}/channel-pay-propose/1.0.0.1";
pub const TOPIC_CHANNEL_PAY_ACCEPT: &str = "/pluribit/{}/channel-pay-accept/1.0.0.1";
pub const TOPIC_CHANNEL_CLOSE_NONCE: &str = "/pluribit/{}/channel-close-nonce/1.0.0.1";
pub const TOPIC_CHANNEL_CLOSE_SIG: &str = "/pluribit/{}/channel-close-sig/1.0.0.1";

// L2: Atomic Swaps
pub const TOPIC_SWAP_PROPOSE: &str = "/pluribit/{}/swap-propose/1.0.0.1";
pub const TOPIC_SWAP_RESPOND: &str = "/pluribit/{}/swap-respond/1.0.0.1";
pub const TOPIC_SWAP_ALICE_ADAPTOR_SIG: &str = "/pluribit/{}/swap-alice-sig/1.0.0.1";
