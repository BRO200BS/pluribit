// worker.js
if (typeof CustomEvent === 'undefined') {
  class CustomEvent extends Event {
    constructor(type, options) {
      super(type, options);
      this.detail = options?.detail || null;
    }
  }
  global.CustomEvent = CustomEvent;
}
if (typeof Promise.withResolvers !== 'function') {
  Promise.withResolvers = function withResolvers() {
    let resolve, reject;
    const promise = new Promise((res, rej) => {
      resolve = res;
      reject = rej;
    });
    return { promise, resolve, reject };
  };
}
import bridge from './js_bridge.cjs';
const { JSONStringifyWithBigInt, JSONParseWithBigInt, convertLongsToBigInts } = bridge; 
import { pipe } from 'it-pipe';
import http from 'http';
import util from 'node:util';
import { parentPort, Worker as ThreadWorker } from 'worker_threads';
import crypto from 'crypto';    
import path from 'path';
import { fileURLToPath } from 'url';
import { multiaddr } from '@multiformats/multiaddr';
import { CONFIG } from './config.js';
let blockRequestCleanupTimer = null;






// --- MODULE IMPORTS ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Manually expose DB functions to the global scope for Wasm
import * as db from './js_bridge.cjs';
global.load_block_from_db = db.load_block_from_db;
global.get_tip_height_from_db = db.get_tip_height_from_db;
global.save_total_work_to_db = db.save_total_work_to_db;
global.get_total_work_from_db = db.get_total_work_from_db;
global.loadBlocks = db.loadBlocks;
global.saveBlock = db.saveBlock;
global.save_utxo = db.save_utxo;
global.load_utxo = db.load_utxo;
global.delete_utxo = db.delete_utxo;
global.clear_all_utxos = db.clear_all_utxos;
global.saveBlockWithHash = db.saveBlockWithHash;
global.loadBlockByHash = db.loadBlockByHash;
global.save_reorg_marker = db.save_reorg_marker;
global.clear_reorg_marker = db.clear_reorg_marker;
global.check_incomplete_reorg = db.check_incomplete_reorg;
global.save_block_to_staging = db.save_block_to_staging;
global.commit_staged_reorg = db.commit_staged_reorg;


const wasmPath = path.join(__dirname, './pkg-node/pluribit_core.js');
const { default: init, ...pluribit } = await import(wasmPath);


import { PluribitP2P, TOPICS, P2PBlock, p2p } from './libp2p-node.js';



const walletOperationQueues = new Map(); // walletId -> Promise chain



process.on('uncaughtException', (err) => {
  const msg = err?.stack || err?.message || String(err);
  if (parentPort) parentPort.postMessage({ type: 'log', payload: { level: 'error', message: `uncaughtException: ${msg}` } });
});

process.on('unhandledRejection', (reason) => {
  const name = reason?.name || '';
  const msg  = reason?.message || '';
  const isAbort = name === 'AbortError' || /aborted/i.test(msg);

  const text = isAbort
    ? `unhandledRejection (Abort): ${msg || String(reason)}`
    : (reason?.stack || msg || String(reason));

  if (parentPort) {
    parentPort.postMessage({
      type: 'log',
      payload: { level: isAbort ? 'debug' : 'error', message: text }
    });
  }
});

// helper to avoid crashing on timer callbacks
const safe = (fn) => (...args) => {
  try { return fn(...args); }
  catch (e) {
    const msg = e?.stack || e?.message || String(e);
    if (parentPort) parentPort.postMessage({ type: 'log', payload: { level: 'error', message: `Fatal in ${fn.name}: ${msg}` } });
  }
};

// --- MUTEX IMPLEMENTATION ---
class Mutex {
    constructor() {
        this._promise = Promise.resolve();
    }
    
    async acquire() {
        let releaseFunction;
        const newPromise = new Promise(resolve => {
            releaseFunction = resolve;
        });
        
        const currentPromise = this._promise;
        this._promise = currentPromise.then(() => newPromise);
        
        await currentPromise;
        return releaseFunction;
    }
    
    async run(fn) {
        const release = await this.acquire();
        try {
            return await fn();
        } finally {
            release();
        }
    }
}
const globalMutex = new Mutex();

// --- REORG STATE ---
const reorgState = {
    pendingForks: new Map(),
    requestedBlocks: new Set(),   // hashes currently requested
    requestedAt: new Map(),       // hash -> timestamp (ms)
};

// De-dupe & auto-GC stuck requests
const REQUEST_TTL_MS = 15000;
function trackRequest(hash) {
  reorgState.requestedBlocks.add(hash);
  reorgState.requestedAt.set(hash, Date.now());
  setTimeout(() => {
    const t0 = reorgState.requestedAt.get(hash);
    if (t0 && Date.now() - t0 >= REQUEST_TTL_MS) {
      reorgState.requestedBlocks.delete(hash);
      reorgState.requestedAt.delete(hash);
    }
  }, REQUEST_TTL_MS + 50);
}



// --- SYNC STATE (best tip seen from peers) ---
const syncState = {
  // State for accumulating hash chunks
  hashRequestState: new Map(), // requestId -> { hashes: [], resolve, reject }
  // : track sync progress
  syncProgress: {
    currentHeight: 0,
    targetHeight: 0,
    // RATIONALE (Hardening): Adds a simple state machine to prevent invalid or concurrent syncs.
    // This stops a new sync from starting while another is already in the sensitive download phase.
    status: 'IDLE', // IDLE | CONSENSUS | DOWNLOADING | COOLDOWN
  },
  // RATIONALE (Fix #6): Rate limiting for peers requesting hashes *from us*.
  // This prevents a single peer from spamming our node with expensive DB lookups.
  peerHashRequestTimes: new Map(), // peerId -> lastRequestTimestamp
  // RATIONALE (Circuit Breaker): Tracks failures to halt sync if the network is unreliable or under attack.
  consecutiveFailures: 0,
  // RATIONALE (Fix #5): A dedicated mutex for the hash request state.
  hashRequestMutex: new Mutex()
};

const blockRequestState = {
    // --- State for reassembling chunked blocks ---
    peerRequests: new Map(), // peer -> Map(blockHash -> lastRequestTime)
    globalRequests: new Map(), // blockHash -> Set(peerIds)
    MAX_PEERS_PER_BLOCK: 3,
    MIN_REQUEST_INTERVAL: 1000, // 1 second between same block requests
    CLEANUP_INTERVAL: 60000 // Clean up old entries every minute
};
// --- WORKER STATE  ---
export const workerState = {
    initialized: false,
    minerActive: false,
    minerId: null,
    p2p: null,
    wallets: new Map(),
    miningWorker: null,
    currentJobId: 0,    
    isReorging: false,
    wasMinerActiveBeforeReorg: false,
    isSyncing: false, 
    isDownloadingChain: false, 
    // RATIONALE (Peer Scoring): A graduated penalty system is better than an immediate ban.
    // Peers start with a score of 100 and lose points for bad behavior.
    peerScores: new Map(), // peerId -> score
    processingCandidateHeight: null,
    atomicSwaps: new Map(), // swap_id -> { swap, state, ... }
    pendingSwapProposals: new Map(), // swap_id -> proposal
    paymentChannels: new Map(), // channel_id -> channel_data
    pendingChannelProposals: new Map(), // proposal_id -> proposal
    musigSessions: new Map() // session_id -> { type, channelId, myNonce, theirNonce, ... }
};

// === HTTP API Server for Block Explorer ===
const API_PORT = process.env.PLURIBIT_API_PORT || 3001;
let apiServer = null;

function startApiServer() {
    apiServer = http.createServer(async (req, res) => {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Content-Type', 'application/json');
        
        try {
            const url = new URL(req.url, `http://localhost:${API_PORT}`);

            // Regex patterns
            const hashPattern = /^\/api\/block\/hash\/([a-f0-9]{64})$/i; // Matches hash requests
            const heightPattern = /^\/api\/block\/(\d+)$/;          // Matches height requests

            // Match results
            const hashMatch = url.pathname.match(hashPattern);
            const heightMatch = url.pathname.match(heightPattern);


            if (url.pathname === '/api/stats') {
                const tipHeight = await db.getTipHeight();
                const totalWork = await db.loadTotalWork();
                const utxoSetSize = pluribit.get_utxo_set_size();

                const tipBlock = tipHeight > 0n ? await db.loadBlock(tipHeight) : null;
                
                res.writeHead(200);
                res.end(JSONStringifyWithBigInt({
                    height: tipHeight,
                    totalWork,
                    utxoCount: utxoSetSize,
                    tipHash: tipBlock?.hash || 'N/A',
                    timestamp: tipBlock?.timestamp || 0,
                    vdfIterations: tipBlock?.vdfIterations || 0
                }));
            }
            
            else if (url.pathname === '/api/mempool') {
                try {
                    // Call the Rust function to get mempool data
                    const mempoolData = await pluribit.get_mempool_data();
                    
                    res.writeHead(200);
                    res.end(JSONStringifyWithBigInt(mempoolData));
                } catch (e) {
                    log(`[API] Mempool error: ${e.message}`, 'error');
                    res.writeHead(500);
                    res.end(JSONStringifyWithBigInt({ 
                        error: e.message,
                        pending_count: 0,
                        fee_total: 0,
                        transactions: []
                    }));
                }
            }
            
            else if (hashMatch) { // <<< Check for HASH match first
                const hash = hashMatch[1]; // Get captured hash from regex group 1
                log(`[API /api/block/hash/] Matched hash: ${hash.substring(0,12)}...`);
                const tipHeight = await db.getTipHeight();
                 
                let foundBlock = null; // Initialize foundBlock
                // Search backwards (consider adding a depth limit if needed)
                for (let h = tipHeight; h >= 0n; h--) {
                    const block = await db.loadBlock(h);
                    if (block && block.hash === hash) {
                        foundBlock = block; // Assign the found block
                        break; // Exit loop once found
                    }
                }
                
                if (foundBlock) { // Check if foundBlock has a value
                    res.writeHead(200);
                    res.end(JSONStringifyWithBigInt(foundBlock)); // Send the found block
                } else {
                    res.writeHead(404);
                    res.end(JSONStringifyWithBigInt({ error: 'Block not found' }));
                }
            }
            else if (heightMatch) { // <<< Check for HEIGHT match second
                try {
                    const heightStr = heightMatch[1]; // Get captured height string
                    const height = BigInt(heightStr);
                    log(`[API /api/block/:height] Matched height: ${height}`);
                
                const block = await db.loadBlock(height);
                if (!block) {
                    res.writeHead(404);
                    res.end(JSONStringifyWithBigInt({ error: 'Block not found' }));
                    return;
                }
                        res.writeHead(200);
                        res.end(JSONStringifyWithBigInt(block));
                } catch (e) {
                    log(`[API /api/block/:height] Invalid height format or DB error: ${e.message}`, 'warn');
                    res.writeHead(400); // Bad Request for invalid BigInt conversion
                    res.end(JSONStringifyWithBigInt({ error: 'Invalid block height format or database error' }));
                }
            }
            else if (url.pathname.startsWith('/api/blocks/recent')) {
                const count = BigInt(Math.min(parseInt(url.searchParams.get('count') || '10'), 100));
                const tipHeight = await db.getTipHeight();
                const blocks = [];
                
                for (let i = 0n; i < count && tipHeight - i >= 0n; i++) {
                    const block = await db.loadBlock(tipHeight - i);
                    if (block) {
                        blocks.push({
                            height: block.height,
                            hash: block.hash,
                            timestamp: block.timestamp,
                            txCount: block.transactions?.length || 0,
                            miner: block.minerPubkey ? Buffer.from(block.minerPubkey).toString('hex').slice(0, 16) + '...' : 'N/A'
                        });
                    }
                }
                
                res.writeHead(200);
                res.end(JSONStringifyWithBigInt(blocks));
            }
            else if (url.pathname === '/api/metrics/difficulty') {
                const tipHeight = await db.getTipHeight();
                const samples = BigInt(Math.min(100, Number(tipHeight)));
                const metrics = [];
                
                const startHeight = tipHeight - samples > 0n ? tipHeight - samples : 0n;
                for (let i = startHeight; i <= tipHeight; i++) {
                    const block = await db.loadBlock(i);
                    if (block) {
                        metrics.push({
                            height: block.height,
                            vrfThreshold: Array.from(block.vrfThreshold).slice(0, 4),
                            vdfIterations: block.vdfIterations,
                            timestamp: block.timestamp
                        });
                    }
                }
                
                res.writeHead(200);
                res.end(JSONStringifyWithBigInt(metrics));
            }
            else if (url.pathname === '/api/metrics/rewards') {
                const tipHeight = await db.getTipHeight();
                const samples = BigInt(Math.min(100, Number(tipHeight)));
                const rewards = [];
                
                const INITIAL_BASE_REWARD = 50_000_000n;
                const HALVING_INTERVAL = 525_600n;
                const REWARD_RESET_INTERVAL = 5_256_000n;
                
                const startHeight = tipHeight - samples > 1n ? tipHeight - samples : 1n;
                for (let h = startHeight; h <= tipHeight; h++) {
                    const height_in_era = h % REWARD_RESET_INTERVAL;
                    const num_halvings = height_in_era / HALVING_INTERVAL;
                    const reward = num_halvings >= 64n ? 0n : INITIAL_BASE_REWARD >> num_halvings;
                    
                    rewards.push({ height: h, reward });
                }
                
                res.writeHead(200);
                res.end(JSONStringifyWithBigInt(rewards));
            }
            else if (url.pathname === '/api/metrics/supply') {
                const tipHeight = await db.getTipHeight();
                
                const INITIAL_BASE_REWARD = 50_000_000n;
                const HALVING_INTERVAL = 525_600n;
                const REWARD_RESET_INTERVAL = 5_256_000n;
                
                let totalSupply = 0n;
                for (let h = 1n; h <= tipHeight; h++) {
                    const height_in_era = h % REWARD_RESET_INTERVAL;
                    const num_halvings = height_in_era / HALVING_INTERVAL;
                    const reward = num_halvings >= 64n ? 0n : INITIAL_BASE_REWARD >> num_halvings;
                    totalSupply += reward;
                }
                
                const blocksPerYear = 262_800n;
                let annualIssuance = 0n;
                for (let i = 0n; i < blocksPerYear; i++) {
                    const h = tipHeight + i + 1n;
                    const height_in_era = h % REWARD_RESET_INTERVAL;
                    const num_halvings = height_in_era / HALVING_INTERVAL;
                    const reward = num_halvings >= 64n ? 0n : INITIAL_BASE_REWARD >> num_halvings;
                    annualIssuance += reward;
                }
                
                const stockToFlow = annualIssuance > 0n ? (Number(totalSupply) * 1000) / (Number(annualIssuance) / 1000) : 0;

                // Function to safely convert smallest unit (BigInt) to a decimal string
                const toCoinString = (bigintValue) => {
                    let str = bigintValue.toString();
                    if (str.length <= 8) {
                        str = str.padStart(9, '0');
                    }
                    const decimalIndex = str.length - 8;
                    return str.slice(0, decimalIndex) + '.' + str.slice(decimalIndex);
                };
                
                res.writeHead(200);
                res.end(JSONStringifyWithBigInt({
                    totalSupply,
                    annualIssuance,
                    stockToFlow,
                    supplyInCoins: parseFloat(toCoinString(totalSupply)),
                    annualIssuanceInCoins: parseFloat(toCoinString(annualIssuance))
                }));
            }
            else if (pathname.startsWith('/api/tx/')) { // <<< ADD TRANSACTION SEARCH ENDPOINT
                const txHash = pathname.split('/')[3]; // Get hash from path

                // Validate hash format (64 hex characters)
                if (!/^[a-f0-9]{64}$/i.test(txHash)) {
                    res.writeHead(400); // Bad Request
                    res.end(JSONStringifyWithBigInt({ error: 'Invalid transaction hash format' }));
                    return;
                }

                log(`[API /api/tx/] Searching for transaction hash: ${txHash.substring(0, 12)}...`);
                let foundBlock = null;
                const tipHeight = await db.getTipHeight();
                // Search backwards from the tip (limit depth for performance)
                const searchDepth = Math.min(Number(tipHeight), 1000); // Example: Search last 1000 blocks

                for (let h = tipHeight; h > tipHeight - BigInt(searchDepth) && h >= 0n; h--) {
                    const block = await db.loadBlock(h); // Load from LevelDB
                    if (block && block.transactions) {
                        for (const tx of block.transactions) {
                            // Check kernel excess (assuming it's the TX hash)
                            if (tx.kernels && tx.kernels[0] && tx.kernels[0].excess) {
                                try {
                                    // Ensure excess is treated as bytes and convert to hex
                                    const currentTxHash = Buffer.from(tx.kernels[0].excess || []).toString('hex');
                                    if (currentTxHash === txHash) {
                                        foundBlock = block; // Store the block containing the tx
                                        break; // Found in this tx
                                    }
                                } catch (e) {
                                    log(`[API /api/tx/] Error calculating hash for tx in block ${h}: ${e.message}`, 'warn');
                                }
                            }
                        }
                    }
                    if (foundBlock) break; // Found in this block, stop searching earlier blocks
                }

                if (foundBlock) {
                    log(`[API /api/tx/] Found transaction ${txHash.substring(0,12)} in block #${foundBlock.height}`);
                    res.writeHead(200);
                    // Return the block height and hash where the transaction was found
                    res.end(JSONStringifyWithBigInt({ blockHeight: foundBlock.height, blockHash: foundBlock.hash }));
                } else {
                    log(`[API /api/tx/] Transaction ${txHash.substring(0,12)} not found within search depth.`);
                    res.writeHead(404); // Not Found
                    res.end(JSONStringifyWithBigInt({ error: 'Transaction not found (or is too old)' }));
                }
            }
             else {
                res.writeHead(404);
                res.end(JSONStringifyWithBigInt({ error: 'Not found' }));
            }
        } catch (e) {
            log(`[API] Error: ${e.message}`, 'error');
            // Avoid setting headers if already sent (e.g., from within a handler)
            if (!res.headersSent) {
                res.writeHead(500);
            }
            res.end(JSONStringifyWithBigInt({ error: e.message }));
        }
    });
    
    apiServer.listen(API_PORT, () => {
        log(`[API] Block explorer API running on http://localhost:${API_PORT}`, 'success');
    });
}


// --- MINER CONTROL HELPERS ---
let minerIdleWaiters = [];
function waitForMiningIdle(timeoutMs = 2000) {
    return new Promise((resolve) => {
        const timer = setTimeout(() => resolve(false), timeoutMs);
        minerIdleWaiters.push(() => { clearTimeout(timer); resolve(true); });
    });
}

function attachMiningWorkerHandlers(worker) {
    worker.on('message', async (msg) => {
        if (msg.type === 'CANDIDATE_FOUND') {
            await handleMiningCandidate(msg.candidate, msg.jobId);
        } else if (msg.type === 'STATUS') {
            log(msg.message, 'debug');
            if (/Mining (stopped|loop ended)/i.test(msg.message)) {
                const waiters = minerIdleWaiters.splice(0);
                waiters.forEach(fn => fn());
            }
        }
    });
}

async function abortCurrentMiningJob(timeoutMs = 2000) {
    if (!workerState.miningWorker) return;
    const done = waitForMiningIdle(timeoutMs);
    try {
        workerState.miningWorker.postMessage({ type: 'STOP' });
    } catch {}
    await done;
}

// --- LOGGING ---
function log(message, level = 'info') {
    if (parentPort) {
        parentPort.postMessage({ type: 'log', payload: { message, level } });
    } else {
        console.log(`[WORKER LOG - ${level.toUpperCase()}]: ${message}`);
    }
}

/**
 * Check for and recover from incomplete reorgs
 * Call this during worker initialization before any mining starts
 */
async function checkAndRecoverFromIncompleteReorg() {
    try {
        const markerStr = await db.check_incomplete_reorg();
        if (!markerStr) {
            log('[RECOVERY] No incomplete reorg detected', 'debug');
            return;
        }
        
        const marker = JSONParseWithBigInt(markerStr);
        log('[RECOVERY] ⚠️  Incomplete reorg detected from previous session!', 'error');
        log(`[RECOVERY] Original tip: height ${marker.original_tip_height}`, 'error');
        log(`[RECOVERY] Attempted new tip: height ${marker.new_tip_height}, hash ${marker.new_tip_hash.substring(0,12)}...`, 'error');
        
        // Strategy: Rollback to the original tip since the reorg didn't complete
        log(`[RECOVERY] Attempting rollback to height ${marker.original_tip_height}...`, 'warn');
        
        // Load the original tip from database
        const originalTipBlock = await db.loadBlock(marker.original_tip_height);
        if (!originalTipBlock) {
            log(`[RECOVERY] ✗ FATAL: Cannot find original tip block at height ${marker.original_tip_height}!`, 'error');
            log('[RECOVERY] Manual database inspection and repair required.', 'error');
            log('[RECOVERY] Consider restoring from backup or resyncing from genesis.', 'error');
            process.exit(1);
        }
        
        log(`[RECOVERY] Found original tip: ${originalTipBlock.hash.substring(0,12)}...`, 'info');
        
        try {
            await pluribit.force_reset_to_height(
                marker.original_tip_height, 
                originalTipBlock.hash
            );
            log(`[RECOVERY] ✓ Rust state reset to height ${marker.original_tip_height}`, 'success');
        } catch (e) {
            // If force_reset_to_height doesn't exist, try loading blocks to resync
            log('[RECOVERY] Attempting to resync chain state...', 'warn');
            
            // Clear and rebuild UTXO set by replaying the chain
            await pluribit.clear_utxo_set();
            for (let h = 0n; h <= marker.original_tip_height; h++) {
                const block = await db.loadBlock(h);
                if (block) {
                    await pluribit.process_block_for_recovery(block);
                }
            }
            log('[RECOVERY] ✓ Chain state reconstructed', 'success');
        }
        
        // Clear the reorg marker now that we've recovered
        await db.clear_reorg_marker();
        log('[RECOVERY] ✓ Recovery complete - reorg marker cleared', 'success');
        
        // Verify consistency
        const dbTipHeight = await db.getTipHeight();
        const rustState = await pluribit.get_blockchain_state();
        if (dbTipHeight.toString() !== rustState.current_height.toString()) {
            log(`[RECOVERY] ✗ WARNING: Heights still don't match! DB=${dbTipHeight}, Rust=${rustState.current_height}`, 'error');
        } else {
            log('[RECOVERY] ✓ Database and memory state now consistent', 'success');
        }
        
    } catch (error) {
        log(`[RECOVERY] ✗ Recovery failed: ${error.message}`, 'error');
        log('[RECOVERY] The node may be in an inconsistent state. Manual intervention required.', 'error');
        // Don't exit - let the operator decide what to do
    }
}


// --- MAIN EXECUTION ---
export async function main() {
    log('Worker starting initialization...');
    parentPort.on('message', async (event) => {
        const { action, ...params } = event;
        try {
            switch (action) {
                case 'initializeNetwork': await initializeNetwork(); break;
               case 'createWalletWithMnemonic': await handleCreateWalletWithMnemonic(params); break; 
               case 'restoreWalletFromMnemonic': await handleRestoreWalletFromMnemonic(params); break; 
                case 'inspectBlock':
                    try {
                        const height = BigInt(params.height); // Use BigInt for consistency
                        const block = await global.load_block_from_db(height); // Assuming global exists

                        if (block) {
                            log(`--- Block ${height} Inspection ---`);
                            const coinbase = block.transactions.find(tx => !tx.inputs || tx.inputs.length === 0); // Safer find

                            if (coinbase) {
                                log(`Coinbase Tx: ${coinbase.outputs?.length || 0} output(s)`);
                                if (coinbase.kernels && coinbase.kernels.length > 0) {
                                    log(`  Kernel fee: ${coinbase.kernels[0].fee ?? 'N/A'}`); // Use BigInt directly
                                } else {
                                    log(`  Coinbase Kernel: N/A`);
                                }

                                // Show output details
                                for (let i = 0; i < (coinbase.outputs?.length || 0); i++) {
                                    const out = coinbase.outputs[i];
                                    // Convert commitment bytes to hex for display
                                    let commitmentHex = 'N/A';
                                    try {
                                        // Assuming commitment is Uint8Array or Array-like
                                        commitmentHex = Array.from(out.commitment || [])
                                                            .map(b => b.toString(16).padStart(2, '0'))
                                                            .join('')
                                                            .slice(0, 16) + '...';
                                    } catch (e) { log(`  Error parsing commitment for output ${i}`, 'warn'); }

                                    log(`  Output ${i}: commitment=${commitmentHex}`);
                                    log(`    Has Ephemeral Key: ${!!out.ephemeralKey}`); // Proto uses camelCase
                                    log(`    Has Stealth Payload: ${!!out.stealthPayload}`); // Proto uses camelCase

                                    // Handle optional bytes viewTag
                                    let viewTagDisplay = 'N/A';
                                    if (out.viewTag && out.viewTag.length > 0) {
                                         // Assuming viewTag is Uint8Array or Array-like containing the single byte
                                        try {
                                           viewTagDisplay = out.viewTag[0].toString(); // Get the first byte's value
                                        } catch(e) { log(`  Error parsing viewTag for output ${i}`, 'warn'); }
                                    }
                                    log(`    View Tag: ${viewTagDisplay}`);
                                }
                            } else {
                                log(`No coinbase transaction found in block ${height}`);
                            }

                            log(`Total transaction count: ${block.transactions?.length || 0}`);
                            log(`--------------------------`);

                        } else {
                            log(`Block ${height} not found in DB`);
                        }
                    } catch(e) {
                        log(`Error inspecting block ${params.height}: ${e.message}`, 'error');
                    }
                    break; // Added missing break
                case 'loadWallet': 
                    await handleLoadWallet(params);
                    
                    // DEBUG: Check for duplicate commitments
                    const walletId = params.walletId; // ✅ Extract from params
                    const walletJson = await pluribit.wallet_session_export(walletId);
                    const wallet = JSON.parse(walletJson);
                    
                    const commitments = new Set();
                    const duplicates = [];
                    
                    for (const utxo of wallet.owned_utxos || []) {
                        const key = Buffer.from(utxo.commitment).toString('hex');
                        if (commitments.has(key)) {
                            duplicates.push(key);
                        }
                        commitments.add(key);
                    }
                    
                    if (duplicates.length > 0) {
                        log(`⚠️  Wallet ${walletId} has ${duplicates.length} duplicate UTXOs!`);
                        duplicates.forEach(d => log(`  Duplicate: ${d.slice(0, 16)}...`));
                    } else {
                        log(`✅ Wallet ${walletId} has no duplicates (${commitments.size} unique UTXOs)`);
                    }
                    break;
                case 'createTransaction': await handleCreateTransaction(params); break;
                case 'setMinerActive':
                    if (!params.active) {
                        await stopMining();
                    } else {
                        workerState.minerActive = true;
                        workerState.minerId = params.minerId;
                        await startPoSTMining(); // Use the worker-based mining
                    }
                    parentPort.postMessage({ type: 'minerStatus', payload: { active: params.active } });
                    break;
                case 'getBalance':
                    try {
                        // Call the session-based balance function directly.
                        if (!workerState.wallets.has(params.walletId)) {
                           throw new Error("Wallet session not active. Please load the wallet.");
                        }
                        const balance = await pluribit.wallet_session_get_balance(params.walletId);
                        parentPort.postMessage({ type: 'walletBalance', payload: { wallet_id: params.walletId, balance: balance }});
                    } catch(e) {
                        log(`Could not get balance: ${e}`, 'error');
                    }
                    break;
                case 'getMiningParams':
                    try {
                        const params = await pluribit.get_current_mining_params();
                        log(`[STATUS] Height: ${params.current_height}, Work: ${params.total_work}, VDF Iters: ${params.vdf_iterations}`);
                    } catch (e) {
                        log(`Could not get params: ${e}`, 'error');
                    }
                    break;
                case 'getPeers':
                    if (workerState.p2p) {
                        const peers = workerState.p2p.getConnectedPeers().map(p => ({ id: p.id.toString() }));
                        parentPort.postMessage({ type: 'peerList', payload: peers });
                    }
                    break;
                case 'connectPeer':
                    if (workerState.p2p) {
                        try {
                            const addrStr = String(params.address || '');
                            const allowPrivate = process.env.PLURIBIT_ALLOW_PRIVATE_DIALS === '1';
                            // More comprehensive private IP check
                            const privatePatterns = [
                                /^\/ip4\/127\./,
                                /^\/ip4\/0\.0\.0\.0/,
                                /^\/ip4\/10\./,
                                /^\/ip4\/192\.168\./,
                                /^\/ip4\/172\.(1[6-9]|2[0-9]|3[01])\./,
                                /^\/ip6\/::1/,
                                /^\/ip6\/fe80::/
                            ];
                            
                            if (!allowPrivate && privatePatterns.some(p => p.test(addrStr))) {
                                throw new Error('Refusing to dial private/loopback address (set PLURIBIT_ALLOW_PRIVATE_DIALS=1 to override)');
                            }
                            
                            const addr = multiaddr(addrStr);
                            await workerState.p2p.node.dial(addr);
                            log(`Manually connected to ${params.address}`, 'success');
                            setTimeout(() => bootstrapSync(), 400);
                        } catch (e) {
                            log(`Failed to connect: ${e.message}`, 'error');
                        }
                    }
                    break;

                case 'auditDetailed':
                    try {
                        const tip = await db.getTipHeight();
                        console.log(`Tip height: ${tip}`);
                        // ✅ Use BigInt comparison instead of Math.min
                        const maxHeight = tip < 5n ? tip : 5n;
                        for (let h = 0n; h <= maxHeight; h++) {
                            const block = await db.loadBlock(h);
                            const coinbase = block.transactions.find(tx => tx.inputs.length === 0);
                            console.log(`Block ${h}: ${coinbase ? coinbase.outputs.length + ' coinbase outputs' : 'no coinbase'}`);
                        }
                    } catch(e) {
                        log(`Audit failed: ${e}`, 'error');
                    }
                    break;

                case 'verifySupply':
                    try {
                        const tip = await db.getTipHeight();
                        let totalCoinbaseOutputs = 0;
                        let uniqueCommitments = new Set();
                        
                        for (let h = 1n; h <= tip; h++) {

                            const block = await db.loadBlock(h);
                            for (const tx of block.transactions) {
                                if (tx.inputs.length === 0) { // Coinbase
                                    for (const output of tx.outputs) {
                                        totalCoinbaseOutputs++;
                                        uniqueCommitments.add(output.commitment.toString());
                                    }
                                }
                            }
                        }
                        
                        log(`Total coinbase outputs created: ${totalCoinbaseOutputs}`, 'info');
                        log(`Unique commitments: ${uniqueCommitments.size}`, 'info');
                        log(`Expected: 50 (one per block)`, 'info');
                        
                        // Check current UTXO set size
                        const utxoSetSize = await pluribit.get_utxo_set_size();
                        log(`Current UTXO set size: ${utxoSetSize}`, 'info');
                        
                    } catch(e) {
                        log(`Verify failed: ${e}`, 'error');
                    }
                    break;


                //audit total supply
                case 'getSupply':
                    try {
                        // Debug: check both sources
                        const dbTip = await db.getTipHeight();
                        const rustTip = await pluribit.get_blockchain_state();
                        log(`DB tip: ${dbTip}, Rust chain state tip: ${rustTip.current_height}`, 'info');
                        
                        const supplyString = await pluribit.audit_total_supply();
                        parentPort.postMessage({ type: 'totalSupply', payload: { supply: supplyString } });
                    } catch (e) {
                        const msg = e?.message || String(e);
                        log(`Could not get supply: ${msg}`, 'error');
                        parentPort.postMessage({ type: 'error', error: `Supply audit failed: ${msg}` });
                    }
                    break;

                case 'channelOpen':
                    await handleChannelOpen(params);
                    break;
                case 'channelList':
                    await handleChannelList(params);
                    break;
                case 'channelAccept':
                    await handleChannelAccept(params);
                    break;
                case 'channelFund':
                    await handleChannelFund(params);
                    break;
                case 'channelPay':
                    await handleChannelPay(params);
                    break;
                case 'channelClose':
                    await handleChannelClose(params);
                    break;       
                
                case 'swapInitiate':
                    await handleSwapInitiate(params);
                    break;
                case 'swapList':
                    await handleSwapList(params);
                    break;
                case 'swapRespond':
                    await handleSwapRespond(params);
                    break;
                case 'swapRefund':
                    await handleSwapRefund(params);
                    break;
                
                case 'shutdown':
                  await gracefulShutdown(0); // the worker’s gracefulShutdown closes libp2p & miner, then process.exit(0)
                  break;
            }
        } catch (error) {
            const msg = (error && error.message) ? error.message : String(error);
            log(`Error handling action '${action}': ${msg}`, 'error');
            parentPort.postMessage({ type: 'error', error: msg });
        }
    });
}


async function fetchBlockDirectly(peerId, hash) {
    const NET = process.env.PLURIBIT_NET || 'mainnet';
    const BLOCK_TRANSFER_PROTOCOL = `/pluribit/${NET}/block-transfer/1.0.0`;

    try {
        const connection = workerState.p2p.node.getConnections(peerId)[0];
        if (!connection) {
            throw new Error(`No stable connection to peer ${peerId}`);
        }

        const stream = await connection.newStream(BLOCK_TRANSFER_PROTOCOL);
        
        const request = p2p.DirectBlockRequest.create({ hash });
        const encodedRequest = p2p.DirectBlockRequest.encode(request).finish();
        
        await pipe([encodedRequest], stream.sink);

        const chunks = [];
        for await (const chunk of stream.source) {
            chunks.push(chunk.subarray());
        }
        
        // The response is now a BlockTransferResponse wrapper
        const response = p2p.BlockTransferResponse.decode(Buffer.concat(chunks));

        if (response.payload === 'blockData' && response.blockData) {
            reorgState.requestedBlocks.delete(hash);
            reorgState.requestedAt.delete(hash);
            // The returned object is already a plain JS object, ready for use
            return response.blockData;
        } else if (response.payload === 'errorReason') {
            log(`Peer ${peerId} responded with an error for block ${hash}: ${response.errorReason}`, 'warn');
            return null;
        }
        
        return null;
    } catch (e) {
        log(`Direct fetch for ${hash.substring(0, 12)} failed: ${e.message}. Falling back to pubsub.`, 'debug');
        // 2. FALLBACK: If the direct stream fails, broadcast a general request.
        try {
            // This promise will be resolved by the general TOPICS.BLOCKS handler when the block arrives.
            const { promise, resolve } = Promise.withResolvers();
            const timeout = setTimeout(() => resolve(null), 7000); // 7-second timeout for the fallback.

            const temporaryHandler = (message) => {
                if (message.payload && message.payload.hash === hash) {
                    clearTimeout(timeout);
                    // IMPORTANT: We must remove this temporary listener once the block is found.
                    const handlers = workerState.p2p.handlers.get(TOPICS.BLOCKS) || [];
                    const index = handlers.indexOf(temporaryHandler);
                    if (index > -1) {
                        handlers.splice(index, 1);
                    }
                    resolve(message.payload);
                }
            };
            
            // Temporarily add our specific resolver to the list of general block handlers.
            if (!workerState.p2p.handlers.has(TOPICS.BLOCKS)) {
                 workerState.p2p.handlers.set(TOPICS.BLOCKS, []);
            }
            workerState.p2p.handlers.get(TOPICS.BLOCKS).push(temporaryHandler);
            
            // Publish the request to the general topic that all nodes listen to.
            await workerState.p2p.publish(TOPICS.BLOCK_REQUEST, { hash });

            return await promise;
        } catch (fallbackError) {
            log(`Pubsub fallback failed for ${hash.substring(0, 12)}: ${fallbackError.message}`, 'warn');
            return null;
        }
    }
}

// RATIONALE: Parallel block fetcher to download from multiple peers, increasing
// resilience against a single peer failing or being slow.
async function fetchBlocksParallel(blockHashes, peerIds) {
    // --- RATIONALE (Fix #7): Limit concurrent requests per peer ---
    // Previously, a malicious peer could provide a long list of hashes, forcing our node
    // to amplify its network traffic by making many parallel requests to honest peers.
    // We now limit concurrent requests *per peer* to prevent this amplification.

    const results = new Map(); 
    const pending = new Set(blockHashes);
    const inFlight = new Map(); 
    const peerInFlightCounts = new Map(peerIds.map(p => [p, 0]));
    const MAX_IN_FLIGHT_PER_PEER = 2;
    
    // Round-robin peer selection
    let peerIndex = 0;
    const getNextPeer = () => {
        const peer = peerIds[peerIndex % peerIds.length];
        peerIndex++;
        return peer;
    };
    
    while (pending.size > 0 || inFlight.size > 0) {
        const { PARALLEL_DOWNLOADS, MAX_FETCH_ATTEMPTS } = CONFIG.SYNC;

        // Start new downloads up to limit
        while (inFlight.size < PARALLEL_DOWNLOADS && pending.size > 0) {
            const hash = pending.values().next().value;

            // Find a peer that is not at its concurrent request limit
            let peer = null;
            for (let i = 0; i < peerIds.length; i++) {
                const candidate = getNextPeer();
                if ((peerInFlightCounts.get(candidate) || 0) < MAX_IN_FLIGHT_PER_PEER) {
                    peer = candidate;
                    break;
                }
            }
            if (!peer) break; // All available peers are busy, wait for a slot.

            pending.delete(hash);
            peerInFlightCounts.set(peer, (peerInFlightCounts.get(peer) || 0) + 1);


            const fetchPromise = (async () => {
                for (let attempt = 1; attempt <= MAX_FETCH_ATTEMPTS; attempt++) {
                    const block = await fetchBlockDirectly(peer, hash);
                    if (block) {
                        results.set(hash, block);
                        return { hash, success: true, peer };
                    }
                    if (attempt < MAX_FETCH_ATTEMPTS) {
                        await new Promise(r => setTimeout(r, 100 * attempt)); // Exponential backoff
                    }
                }
                return { hash, success: false, peer };
            })();
            
            inFlight.set(hash, fetchPromise);
        }
        
        // Wait for at least one to complete
        if (inFlight.size > 0) {
            const completed = await Promise.race(inFlight.values());

            // Decrement the counter for the peer that just finished
            peerInFlightCounts.set(completed.peer, (peerInFlightCounts.get(completed.peer) || 1) - 1);
            
            inFlight.delete(completed.hash);

            if (!completed.success) {
                log(`[SYNC] Failed to fetch block ${completed.hash.substring(0, 12)} after ${MAX_FETCH_ATTEMPTS} attempts`, 'warn');
            }
        }
    }
    
    return results;
    }
    
    
async function triggerReorgPlan(blockHash) {
    try {
        const blockHashShort = blockHash.substring(0, 12);
        log(`[REORG] Planning reorg from fork tip ${blockHashShort}...`, 'warn');

        const plan_js = await pluribit.plan_reorg_for_tip(blockHash);
        const plan = plan_js;

        if (plan.requests && plan.requests.length > 0) {
            log(`[REORG] Plan requires missing blocks. Requesting ${plan.requests.length} block(s)...`, 'info');
            for (const hash of plan.requests) {
                if (!reorgState.requestedBlocks.has(hash)) {
                    trackRequest(hash);
                    log(`[REORG] Broadcasting request for missing block ${hash.substring(0,12)}`);
                    await workerState.p2p.publish(TOPICS.BLOCK_REQUEST, { hash });
                }
            }
            return; // Wait for blocks to arrive
        }

        if (plan.should_switch) {
            log(`[REORG] Fork is heavier. Applying reorg: -${plan.detach?.length||0} +${plan.attach?.length||0}`, 'warn');
            workerState.wasMinerActiveBeforeReorg = workerState.minerActive;
            let __resumeMining = workerState.minerActive;

            await abortCurrentMiningJob();
            workerState.isReorging = true;
            
            try {
                // Attempt the reorg
                await pluribit.atomic_reorg(plan_js);
                log('[REORG] ✓ Atomic reorg completed successfully', 'success');
                
                // Verify database consistency after reorg
                const dbTip = await db.getTipHeight();
                const rustState = await pluribit.get_blockchain_state();
                
                if (dbTip.toString() !== rustState.current_height.toString()) {
                    throw new Error(
                        `Reorg completed but states don't match! DB=${dbTip}, Rust=${rustState.current_height}`
                    );
                }
                
                log('[REORG] ✓ Post-reorg validation passed', 'success');
                
            } catch (reorgError) {
                log(`[REORG] ✗ CRITICAL: Reorg failed: ${reorgError.message}`, 'error');
                
                // Attempt recovery by resetting to database state
                try {
                    log('[REORG] Attempting emergency recovery...', 'warn');
                    const dbTipHeight = await db.getTipHeight();
                    const dbTipBlock = await db.loadBlock(dbTipHeight);
                    
                    if (dbTipBlock) {
                        // Reset Rust state to match database
                        await pluribit.force_reset_to_height(dbTipHeight, dbTipBlock.hash);
                        log(`[REORG] ✓ Recovered: reset to DB state (height ${dbTipHeight})`, 'success');
                    } else {
                        log('[REORG] ✗ Recovery impossible - database corrupted', 'error');
                    }
                } catch (recoveryError) {
                    log(`[REORG] ✗ Recovery also failed: ${recoveryError.message}`, 'error');
                }
                
                // Don't try to resume mining after a failed reorg
                __resumeMining = false;
                
                // Re-throw the error so it's visible
                throw reorgError;
                
            } finally {
                workerState.isReorging = false;
            }

            if (__resumeMining) {
                workerState.minerActive = true;
                try {
                    await startPoSTMining();
                    log('[REORG] ✓ Mining resumed after reorg', 'success');
                } catch (miningError) {
                    log(`[REORG] ✗ Failed to restart mining: ${miningError.message}`, 'error');
                }
            }
            workerState.wasMinerActiveBeforeReorg = false;
        } else {
            log(`[REORG] No switch needed; staying on current canonical chain.`, 'info');
        }
    } catch (e) {
        const util = await import('node:util');
        const errorDetails = util.inspect(e, { depth: 5 });
        log(`[REORG] Failed to plan/execute reorg: ${errorDetails}`, 'error');
    }
}
    
    // Forward sync implementation
async function syncForward(targetHeight, targetHash, trustedPeers) {
    // RATIONALE (State Machine): Prevent multiple syncs from running concurrently.
    if (syncState.syncProgress.status === 'DOWNLOADING') {

        log('[SYNC] Sync process already running. Skipping new request.', 'warn');
        return;
    }
    // RATIONALE (Circuit Breaker): Halt sync if there are too many consecutive failures.
    if (syncState.consecutiveFailures >= CONFIG.SYNC.MAX_CONSECUTIVE_SYNC_FAILURES) {
        log(`[SYNC] Halting sync due to ${syncState.consecutiveFailures} consecutive failures. Requires manual restart or cooldown.`, 'error');
        return;
    }

    syncState.syncProgress.status = 'DOWNLOADING';
    // Set the global flag to activate the block deferral mechanism.
    workerState.isSyncing = true;
    
    const { TIMEOUT_MS, BATCH_SIZE, CHECKPOINT_INTERVAL, MAX_HASHES_PER_SYNC } = CONFIG.SYNC;

    const startTime = Date.now();
    try {
        let currentHeight = await db.getTipHeight();
        let previousBlock = await db.loadBlock(currentHeight);
        syncState.syncProgress.currentHeight = currentHeight;
        syncState.syncProgress.targetHeight = targetHeight;

        if (!trustedPeers || trustedPeers.length === 0) {
            log('[SYNC] No verified Pluribit peers available for sync. Waiting for connections...', 'warn');
            return;
        }
        
        // --- RATIONALE: Cross-validate hashes with multiple peers ---
        // Previously, we trusted the first peer for the entire hash list. Now, we fetch
        // the list from up to 3 peers and ensure they agree. This prevents a single
        // malicious peer from feeding us a bogus chain structure.
        const peersToQuery = trustedPeers.slice(0, 3);
        const hashLists = await Promise.all(
            peersToQuery.map(peer => requestAllHashes(peer, currentHeight))
        );

        if (hashLists.some(list => list.length > MAX_HASHES_PER_SYNC)) {
            throw new Error(`Peer provided hash list larger than limit of ${MAX_HASHES_PER_SYNC}`);
        }

        // Validate that the lists are identical.
        const firstList = hashLists[0];
        for (let i = 1; i < hashLists.length; i++) {
            if (hashLists[i].length !== firstList.length || 
                (firstList.length > 0 && hashLists[i][hashLists[i].length - 1] !== firstList[firstList.length - 1])) {
                throw new Error('Peer hash lists do not match. Aborting sync.');
            }
        }

        const allHashes = firstList;

        if (allHashes.length === 0) {
            log(`[SYNC] Already at target height`, 'info');
            return;
        }
        
        log(`[SYNC] Need to download ${allHashes.length} blocks from height ${currentHeight + 1n} to ${targetHeight}`, 'info');


        // --- RATIONALE (Fix #3, #8, Timestamp/Sequence Validation): Stream-validate blocks ---
        // The old logic downloaded an entire batch of blocks before validating any.
        // This new logic fetches and validates blocks sequentially within a batch. If any block is
        // invalid or out of sequence, the process aborts immediately.

        for (let i = 0; i < allHashes.length; i += BATCH_SIZE) {
            if (Date.now() - startTime > TIMEOUT_MS) {
                throw new Error(`SYNC: Timeout after ${i} blocks`);
            }

            const batchHashes = allHashes.slice(i, i + BATCH_SIZE);
            log(`[SYNC] Processing batch of ${batchHashes.length} blocks (height ${currentHeight + 1n}...)`, 'info');


            // RATIONALE (Peer Scoring): Filter out peers with low scores.
            const availablePeers = trustedPeers.filter(p => (workerState.peerScores.get(p) || 100) > 0);
            if (availablePeers.length === 0) {
                throw new Error("No trustworthy peers available for block download.");
            }

            const blockResults = await fetchBlocksParallel(batchHashes, availablePeers);

            // Process this small batch sequentially to ensure chain continuity.
            for (const hash of batchHashes) {
                const block = blockResults.get(hash);
                if (!block) throw new Error(`Failed to fetch required block ${hash}`);
                if (block.hash !== hash) throw new Error(`Fetched block hash mismatch for ${hash}`);

                const blockHeightBigInt = BigInt(block.height.toString());

                // NEW: Check if we already have a block at this height in our canonical chain
                const canonicalBlockAtHeight = await load_block_from_db(blockHeightBigInt);
                
                if (canonicalBlockAtHeight) {
                    if (canonicalBlockAtHeight.hash === block.hash) {
                        // We already have this exact block - skip it
                        log(`[SYNC] Already have block ${block.hash.substring(0,12)} at height ${block.height}, skipping...`, 'debug');
                        
                        syncState.syncProgress.currentHeight = blockHeightBigInt;
                        currentHeight = blockHeightBigInt;
                        previousBlock = block;
                        
                        // Still send progress updates for UI
                        const currentBlockIndex = i + batchHashes.indexOf(hash);
                        if (currentBlockIndex % 10 === 0 || currentBlockIndex === allHashes.length - 1) {
                            parentPort.postMessage({
                                type: 'syncProgress',
                                payload: {
                                    current: blockHeightBigInt,
                                    target: targetHeight,
                                    startTime: startTime,
                                }
                            });
                        }
                        continue; // Skip to next block
                    } else {
                        // Different block at same height = fork detected!
                        log(`[SYNC] Fork detected at height ${block.height}. Our hash: ${canonicalBlockAtHeight.hash.substring(0,12)}, peer hash: ${block.hash.substring(0,12)}`, 'warn');
                        log(`[SYNC] Halting linear sync and triggering reorg evaluation...`, 'warn');
                        
                        // Ingest the fork block (will return storedOnSide)
                        const blockBytes = p2p.Block.encode(block).finish();
                        const result = await pluribit.ingest_block_bytes(blockBytes);
                        
                        if (result.type === 'storedOnSide') {
                            await triggerReorgPlan(result.tip_hash || block.hash);
                        }
                        
                        // Exit sync - reorg handler takes over
                        syncState.consecutiveFailures = 0;
                        syncState.syncProgress.status = 'IDLE';
                        workerState.isSyncing = false;
                        parentPort.postMessage({ type: 'syncComplete' });
                        return;
                    }
                }

                // No block at this height - proceed with normal ingestion
                const blockBytes = p2p.Block.encode(block).finish();
                const result = await pluribit.ingest_block_bytes(blockBytes);

                if (result.type === 'storedOnSide') {
                    log(`[SYNC] Fork detected at height ${block.height}. Halting sync and initiating reorg plan directly.`, 'warn');
                    
                    await triggerReorgPlan(result.tip_hash || block.hash);
                    
                    syncState.consecutiveFailures = 0;
                    syncState.syncProgress.status = 'IDLE';
                    workerState.isSyncing = false;
                    parentPort.postMessage({ type: 'syncComplete' });
                    return;
                }

                if (result.type === 'invalid') {
                    // RATIONALE (Peer Scoring): If we get an invalid block, penalize all peers
                    // who claimed to have this chain tip, as one of them is lying.
                    const PENALTY = 25; // Score penalty for providing an invalid block.
                    log(`[SYNC] Invalid block ${hash} received. Penalizing ${trustedPeers.length} peers.`, 'warn');
                    for (const peer of trustedPeers) {
                        const currentScore = workerState.peerScores.get(peer) || 100;
                        const newScore = Math.max(0, currentScore - PENALTY);
                        workerState.peerScores.set(peer, newScore);
                        log(`[SYNC] Peer ${peer.slice(-6)} score: ${currentScore} -> ${newScore}`, 'debug');
                        if (newScore === 0) {
                            log(`[SYNC] Peer ${peer.slice(-6)} score reached 0. Disconnecting.`, 'warn');
                            try { workerState.p2p.node.hangUp(peer); } catch(e) {}
                        }
                    }
                    throw new Error(`Invalid block ${hash}: ${result.reason}`);
                } else if (result.type === 'needParent') {
                    throw new Error(`Sync process integrity failure: received needParent for sequential block ${hash}`);
                }
                
                // Send a progress update to the main thread periodically.
                const currentBlockIndex = i + batchHashes.indexOf(hash);
                if (currentBlockIndex % 10 === 0 || currentBlockIndex === allHashes.length - 1) {
                    parentPort.postMessage({
                        type: 'syncProgress',
                        payload: {
                            current: blockHeightBigInt,
                            target: targetHeight,
                            startTime: startTime,
                        }
                    });
                }
                
                syncState.syncProgress.currentHeight = blockHeightBigInt;
                                
                if (blockHeightBigInt % BigInt(CHECKPOINT_INTERVAL) === 0n) {
                    const chainState = await pluribit.get_blockchain_state();
                    await db.saveTotalWork(chainState.total_work);
                    log(`[SYNC] Checkpoint saved at height ${blockHeightBigInt}`, 'info');
                }
                                
                // Update wallets periodically
                if (blockHeightBigInt % 100n === 0n) {
                    const release = await globalMutex.acquire();
                    try {
                        for (const walletId of workerState.wallets.keys()) {
                            await pluribit.wallet_session_scan_block(walletId, block);
                        }
                    } finally {
                        release();
                    }
                }
                
                // Update previousBlock for the next iteration.
                previousBlock = block;
                currentHeight = blockHeightBigInt;
            }

        }
        
        log(`[SYNC] Completed sync to height ${targetHeight}`, 'success');        
        
    
        // RATIONALE (Circuit Breaker): Reset failure count on a successful sync.
        syncState.consecutiveFailures = 0;
        
        // On success, reset state and notify UI
        parentPort.postMessage({ type: 'syncComplete' });
        syncState.syncProgress.status = 'IDLE';
        workerState.isSyncing = false;        
        
        
    } catch (e) {
        log(`[SYNC] Sync failed: ${e.message}`, 'error');
        // RATIONALE (Circuit Breaker): Increment failure count.
        syncState.consecutiveFailures++;
        // Check if we've hit the max number of retries
        if (syncState.consecutiveFailures >= CONFIG.SYNC.MAX_CONSECUTIVE_SYNC_FAILURES) {
            log(`[SYNC] Halting sync after ${CONFIG.SYNC.MAX_CONSECUTIVE_SYNC_FAILURES} consecutive failures. Will not retry automatically.`, 'error');
            
            // Give up and reset the state
            parentPort.postMessage({ type: 'syncComplete' });
            syncState.syncProgress.status = 'IDLE';
            workerState.isSyncing = false;
        } else {
            // Implement exponential backoff for the retry delay
            const backoffDelay = 2000 * Math.pow(2, syncState.consecutiveFailures);
            log(`[SYNC] Entering cooldown. Retrying in ${backoffDelay / 1000} seconds...`, 'warn');
            syncState.syncProgress.status = 'COOLDOWN';
            
            // Do NOT set workerState.isSyncing to false; the sync process is paused, not finished.
            // Do NOT send 'syncComplete' to the UI; we are still trying.
            
            // Schedule a new attempt after the cooldown period.
            setTimeout(() => {
                // Reset status to allow bootstrapSync to run, then try the whole process again.
                syncState.syncProgress.status = 'IDLE';
                bootstrapSync(); 
            }, backoffDelay);
        }    
    }
}




async function startPoSTMining() {
    const release = await globalMutex.acquire(); 
    try {
        if (!workerState.minerActive) return;

        // === NEW: Validate state consistency before mining ===
        const dbTipHeight = await db.getTipHeight();
        let chain = await pluribit.get_blockchain_state();  // Use 'let' so we can reassign
        const rustTipHeight = BigInt(chain.current_height);
        
        if (dbTipHeight !== rustTipHeight) {
            log(`[MINING] ✗ State inconsistency detected!`, 'error');
            log(`[MINING]    Database tip height: ${dbTipHeight}`, 'error');
            log(`[MINING]    Rust memory tip height: ${rustTipHeight}`, 'error');
            
            const dbTipBlock = await db.loadBlock(dbTipHeight);
            if (dbTipBlock) {
                log(`[MINING]    Database tip hash: ${dbTipBlock.hash.substring(0,12)}...`, 'error');
            }
            log(`[MINING]    Rust tip hash: ${chain.tip_hash.substring(0,12)}...`, 'error');
            
            log(`[MINING] Attempting to resync state...`, 'warn');
            
            try {
                await pluribit.force_reset_to_height(dbTipHeight, dbTipBlock.hash);
                log('[MINING] ✓ State resynced from database', 'success');
                
                // ONLY reload after resync
                chain = await pluribit.get_blockchain_state();
            } catch (resyncError) {
                log(`[MINING] ✗ Resync failed: ${resyncError.message}`, 'error');
                log('[MINING] Cannot start mining - manual recovery required', 'error');
                return;
            }
        }
        // === END NEW CODE ===

        // Ensure mining worker exists
        if (!workerState.miningWorker) {
            workerState.miningWorker = new ThreadWorker(new URL('./mining-worker.js', import.meta.url));
            attachMiningWorkerHandlers(workerState.miningWorker);
        }
        
        // Reuse the chain variable - no need to reload!
        const currentHeight = BigInt(chain.current_height);
        const nextHeight = currentHeight + 1n;

        // --- START: MODIFIED DIFFICULTY PARAMETER LOGIC ---
        let vrfThresholdToUse;
        let vdfIterationsToUse;

        // Call the new Rust function to get parameters for the *next* block
        try {
            const nextParams = await pluribit.calculate_next_difficulty_params(currentHeight); // Pass current height
            vrfThresholdToUse = Array.from(nextParams.vrf_threshold); // Convert Vec<u8> from Rust
            vdfIterationsToUse = BigInt(nextParams.vdf_iterations); // Convert u64 from Rust
            log(`[MINING] Using difficulty params for block #${nextHeight}: VRF=${Buffer.from(vrfThresholdToUse).toString('hex').substring(0,8)}..., VDF=${vdfIterationsToUse}`);
        } catch (e) {
             log(`[MINING] Error calculating next difficulty params: ${e?.message || e}. Falling back to current params.`, 'error');
             // Fallback to current params if calculation fails
             vrfThresholdToUse = Array.from(chain.current_vrf_threshold); 
             vdfIterationsToUse = BigInt(chain.current_vdf_iterations); 
        }        
        
        // Get the miner's secret key
        const minerSecretKey = await pluribit.wallet_session_get_spend_privkey(workerState.minerId);

        // Abort any in-flight job, then send a fresh mining job
        await abortCurrentMiningJob();
        // Send mining job to worker
        workerState.currentJobId++;
        workerState.miningWorker.postMessage({
            type: 'MINE_BLOCK',
            jobId: workerState.currentJobId,
            height: BigInt(chain.current_height) + 1n,
            minerPubkey: await pluribit.wallet_session_get_spend_pubkey(workerState.minerId),
            minerSecretKey: minerSecretKey,
            prevHash: await pluribit.get_latest_block_hash(),
            vrfThreshold: vrfThresholdToUse,
            vdfIterations: vdfIterationsToUse
        });
    } finally {
        // Always release the lock when the function is done
        release(); 
    }
}

async function stopMining() {
    workerState.minerActive = false;
    // If using the separate mining worker thread
    if (workerState.miningWorker) {
        // Simply send the stop signal, don't terminate the thread.
        workerState.miningWorker.postMessage({ type: 'STOP' });
    }
}

async function handleMiningCandidate(candidate, jobId) {
    // Invalidate candidates from stale jobs
    if (jobId !== workerState.currentJobId) {
        log(`[MINING] Ignoring stale candidate from old job #${jobId}`, 'debug');
        return;
    }
    // If we are already busy processing a candidate for this specific height, ignore the new one.
    if (candidate.height === workerState.processingCandidateHeight) {
        log(`[MINING] Ignoring duplicate candidate for height ${candidate.height} while another is processing.`, 'warn');
        return;
    }
    workerState.processingCandidateHeight = candidate.height; 
    try {
        // The candidate already won the lottery in the worker!
        log(`[MINING] ✨ Received winning block candidate from worker!`, 'success');

        // Assemble the full block
        const block = await pluribit.complete_block_with_transactions(
            BigInt(candidate.height),
            candidate.prevHash,
            BigInt(candidate.nonce),
            candidate.miner_pubkey,
            await pluribit.wallet_session_get_scan_pubkey(workerState.minerId),
            candidate.vrf_proof,  // VRF proof already computed in worker
            candidate.vdf_proof,
            candidate.vrfThreshold,
            BigInt(candidate.vdfIterations),
            null
        );
log(`[JS PRE-SAVE MINED] Block #${block?.height} Coinbase output 0 viewTag: ${block?.transactions?.[0]?.outputs?.[0]?.viewTag ?? 'N/A'}`, 'debug'); // <-- ADD THIS LINE
        // Process the new block
        await handleRemoteBlockDownloaded({ block });
    } catch (error) {
        log(`[MINING] Error processing candidate for height ${candidate.height}: ${error.message}`, 'error');
        // Clear the flag ONLY if an error occurs *within this function* before handleRemoteBlockDownloaded takes over
        if (candidate.height === workerState.processingCandidateHeight) {
             workerState.processingCandidateHeight = null;
        }
    }
}



async function handleRemoteBlockDownloaded({ block }) {
    log(`[JS RECEIVED BLOCK] Block #${block?.height} Coinbase output 0 viewTag: ${block?.transactions?.[0]?.outputs?.[0]?.viewTag ?? 'N/A'}`, 'debug'); // <-- ADD THIS LINE (at the top)
    const release = await globalMutex.acquire();
    try {
        const currentHeight = (await pluribit.get_blockchain_state()).current_height;

        // If we're in a formal sync OR if the block is way ahead of us, defer it.
        if (workerState.isSyncing || BigInt(block.height) > BigInt(currentHeight) + 1n) {
            if (!workerState.isSyncing) {
                log(`[DEFER] Deferring out-of-order block #${block.height} while at height ${currentHeight}. Triggering sync check.`, 'info');
                // This is a good place to trigger a sync check, as we've clearly missed blocks.
                setTimeout(safe(bootstrapSync), 500);
            }
            await db.saveDeferredBlock(block);
            return;
        }

        if (workerState.isDownloadingChain) {
            log(`[DEBUG] Skipping request handling during chain download for block ${block.height}`);
            return;
        }

        log(`[DEBUG] Processing block #${block.height} hash: ${block.hash.substring(0,12)}...`);

        try {
            // RATIONALE: Encode the JavaScript block object into Protobuf binary format.
            // This is required by the new, more secure 'ingest_block_bytes' Rust function.
            const blockBytes = p2p.Block.encode(block).finish();


            // RATIONALE (BUGFIX): The `ingest_block_bytes` function returns a `JsValue`
            // from Rust, which `wasm-bindgen` automatically converts into a plain JavaScript
            // object. The original code incorrectly tried to deserialize this object again
            // using a non-existent `serde_wasm_bindgen.fromValue` function, causing the TypeError.
            //
            // The fix is to use the returned JavaScript object directly, as it is already
            // in the correct format.
            const result_js = await pluribit.ingest_block_bytes(blockBytes);
            const result = result_js; // Use the object directly.

            const t = String(result?.type || '').toLowerCase();
            const reason = String(result?.reason || '').toLowerCase();
            log(`[DEBUG] ingest_block returned type: ${result?.type}, full result: ${JSON.stringify(result)}`);

            if (t === 'needparent'){
              const h = result.hash;
              if (!reorgState.requestedBlocks.has(h)) {
                trackRequest(h);
                log(`Requesting missing parent ${h.substring(0,12)}...`, 'info');
                await workerState.p2p.publish(TOPICS.BLOCK_REQUEST, { hash: h });
              }
              return; // wait for parent
            }

            if (t === 'acceptedandextended') {
              try {
                await workerState.p2p.publish(TOPICS.BLOCK_ANNOUNCEMENTS, { 
                    hash: block.hash, 
                    height: block.height.toString() 
                });
              } catch(e) {
                console.error(`[MINING DEBUG] Failed to announce block:`, e);
              }

              try {
                await workerState.p2p.publish(TOPICS.BLOCKS, block);
                log(`[MINING DEBUG] Full block broadcast on ${TOPICS.BLOCKS}`, 'debug');
              } catch (e) {
                log(`[MINING DEBUG] Failed to publish full block: ${e?.message || e}`, 'warn');
              }

              log(`[DEBUG] Active wallets in workerState: ${Array.from(workerState.wallets.keys()).join(', ')}`);
              const blockForWasm = convertLongsToBigInts(block);

              try {
                for (const walletId of workerState.wallets.keys()) {
                  try {
                    // Use the converted block object here
                    await pluribit.wallet_session_scan_block(walletId, blockForWasm); 
                    const updatedJson = await pluribit.wallet_session_export(walletId);
                    await db.saveWallet(walletId, updatedJson);
                    const newBalance = await pluribit.wallet_session_get_balance(walletId);
                    parentPort.postMessage({ type: 'walletBalance', payload: { wallet_id: walletId, balance: newBalance }});
                    log(`Balance updated for ${walletId} after new block.`, 'debug');
                  } catch (e) {
                    log(`Wallet scan/save failed for ${walletId}: ${e?.message || e}`, 'warn');
                  }
                }
              } catch (e) {
                  const msg = e?.stack || e?.message || String(e);
                  log(`Fatal error during wallet scan loop: ${msg}`, 'error');
              }

              if (workerState.minerActive) {
                log('[MINING] New block accepted. Restarting miner for next block...', 'info');
                (async () => { await abortCurrentMiningJob(); await startPoSTMining(); })();
              }
              return;
            }

            if (t === 'storedonside') {
                try {
                    const blockHash = result.tip_hash || block.hash || 'unknown'; 
                    const blockHashShort = blockHash.length >= 12 ? blockHash.substring(0, 12) : blockHash; 
                    log(`[REORG] Block ${blockHashShort} is a fork tip. Planning reorg...`, 'warn'); 
                    
                    const plan_js = await pluribit.plan_reorg_for_tip(blockHash); 
                    const plan = plan_js; 

                    if (plan.requests && plan.requests.length > 0) {
                        log(`[REORG] Plan requires missing blocks. Requesting ${plan.requests.length} block(s)...`, 'info'); 
                        
                        for (const hash of plan.requests) {
                            if (!reorgState.requestedBlocks.has(hash)) { 
                                trackRequest(hash);
                                
                                log(`[REORG] Broadcasting request for missing block ${hash.substring(0,12)}`);
                                // Publish a general request. The block will be processed by this same function when it arrives.
                                await workerState.p2p.publish(TOPICS.BLOCK_REQUEST, { hash }); 
                            }
                        }
                        
                        // After requesting blocks, we must wait for them to arrive before retrying the plan.
                        // The retry logic is now handled by the arrival of the requested blocks which will trigger this function again.
                        return; // Stop processing this path for now.
                    }

                    if (plan.should_switch) { 
                        log(`[REORG] Fork is heavier. Applying reorg: -${plan.detach?.length||0} +${plan.attach?.length||0}`, 'warn'); 
                        workerState.wasMinerActiveBeforeReorg = workerState.minerActive; 
                        const __resumeMining = workerState.minerActive; 

                        await abortCurrentMiningJob(); 
                        workerState.isReorging = true;
                        try {
                            await pluribit.atomic_reorg(plan_js); 
                        } finally {
                            workerState.isReorging = false; 
                        }

                        if (__resumeMining) { 
                            workerState.minerActive = true; 
                            await startPoSTMining(); 
                        }
                        workerState.wasMinerActiveBeforeReorg = false; 
                    } else {
                        log(`[REORG] No switch needed; staying on current canonical chain.`, 'info'); 
                    }
                } catch (e) {
                    const util = await import('node:util'); 
                    const errorDetails = util.inspect(e, { depth: 5 }); 
                    log(`[REORG] Failed to plan/execute reorg: ${errorDetails}`, 'error'); 
                }
                return;
            }

            if (t === 'invalid') {
              log(`Invalid block rejected: ${result.reason ?? ''}`, 'warn');
              return;
            }

            log(`Unhandled ingest result: ${JSON.stringify(result)}`, 'debug');

        } catch (e) {
            log(`Failed to process downloaded block: ${e.stack || e.message || e}`, 'error');
        }
    } finally {
        // Clear the processing flag if this block matches the one we were processing
        if (block.height === workerState.processingCandidateHeight) {
            log(`[MINING DEBUG] Clearing processing flag for height ${blockHeight}`, 'debug');
            workerState.processingCandidateHeight = null;
        }
        release();
        // This ensures the miner restarts with the latest chain state
        // after any block attempt, success or failure.
        if (workerState.minerActive && !workerState.isReorging && !workerState.isSyncing) {
            log('[MINING] Resetting mining job after block processing...', 'info');
            
            // Abort any old job and start a new one with fresh chain parameters.
            // Using a small timeout prevents a tight error loop if a block is consistently invalid.
            setTimeout(async () => { 
                await abortCurrentMiningJob(); 
                await startPoSTMining(); 
            }, 500);
        }
    }
}

async function debugReorgState() {
    const chain = await pluribit.get_blockchain_state();
    const sideBlocks = await pluribit.get_side_blocks_info(); // ✅ Proper async call
    
    log('[REORG DEBUG] =================');
    log(`[REORG DEBUG] Canonical tip: height=${chain.current_height}, work=${chain.total_work}`);
    log(`[REORG DEBUG] Side blocks: ${sideBlocks.length}`);
    
    for (const block of sideBlocks) {
        log(`[REORG DEBUG]   Fork block: height=${block.height}, hash=${block.hash.substring(0,12)}`);
    }
    log('[REORG DEBUG] =================');
}

function cleanupForkCache(keepAboveHeight) {
    for (const height of reorgState.pendingForks.keys()) {
        if (height <= keepAboveHeight) {
            reorgState.pendingForks.delete(height);
        }
    }
    reorgState.requestedBlocks.clear();
    reorgState.requestedAt.clear();
}

// SIMPLIFIED Network Initialization
async function initializeNetwork() {
// Periodic reorg state debugging
setInterval(safe(debugReorgState), 60000); // Every 60 seconds

    log('Initializing Pluribit network...');

    
    // --- CRITICAL FIX #3: Verify genesis BEFORE touching database ---
    const CANONICAL_GENESIS_HASH = await pluribit.get_genesis_block_hash();
    const generatedHash = CANONICAL_GENESIS_HASH; // They should always match now

    log('Genesis block hash verified successfully.', 'success');

    
    // Now it's safe to initialize database
    await db.initializeDatabase();
    
    await checkAndRecoverFromIncompleteReorg();





    // --- DATABASE AND RUST STATE INITIALIZATION ---
    // REMOVED: The old logic that loaded all blocks into an array.

    // Ensure genesis block exists in DB for new chains.
    const tipHeight = await db.getTipHeight();
    if (tipHeight === 0n && !(await db.loadBlock(0))) { 
        log('Creating and saving new genesis block to DB.', 'info');
        // We get the genesis block from Rust and save it to the DB at height 0.
        const genesisBlock = await pluribit.create_genesis_block();
        log(`[JS PRE-SAVE GENESIS] Coinbase output 0 viewTag: ${genesisBlock?.transactions?.[0]?.outputs?.[0]?.viewTag ?? 'N/A'}`, 'debug'); // <-- ADD THIS LINE
        await db.saveBlock(genesisBlock);
    }

    // NEW: Call the async Rust function to initialize its state from our DB.
    try {
        await pluribit.init_blockchain_from_db();
    } catch (e) {
        log(`Fatal error during Rust state initialization: ${e?.message ?? e}`, 'error');
        throw e;
    }
    
    log('Initializing P2P stack...');
    const tcpPort = process.env.PLURIBIT_TCP_PORT || CONFIG.P2P.TCP_PORT;
    const wsPort = process.env.PLURIBIT_WS_PORT || CONFIG.P2P.WS_PORT;

    log(`Attempting to start P2P node on TCP:${tcpPort} and WS:${wsPort} (use PLURIBIT_TCP_PORT/PLURIBIT_WS_PORT to override)`);

    workerState.p2p = new PluribitP2P(log, { 
      tcpPort: parseInt(tcpPort, 10), 
      wsPort: parseInt(wsPort, 10) 
    });

    await workerState.p2p.initialize();

    await setupMessageHandlers();


    const MAX_DEFERRED_BLOCKS_ON_STARTUP = 1000;
    try {
        let leftoverBlocks = await db.loadAllDeferredBlocks();
        if (leftoverBlocks.length > 0) {
            log(`[RECOVERY] Found ${leftoverBlocks.length} leftover deferred blocks. Processing now...`, 'warn');
            if (leftoverBlocks.length > MAX_DEFERRED_BLOCKS_ON_STARTUP) {
                log(`[RECOVERY] Capping processing to first ${MAX_DEFERRED_BLOCKS_ON_STARTUP} blocks.`, 'warn');
                leftoverBlocks = leftoverBlocks.slice(0, MAX_DEFERRED_BLOCKS_ON_STARTUP);
            }
            for (const block of leftoverBlocks) {
                await handleRemoteBlockDownloaded({ block });
            }
            await db.clearDeferredBlocks();
            log(`[RECOVERY] Finished processing leftover blocks.`, 'success');
        }
    } catch (e) {
        log(`Error during deferred block recovery: ${e.message}`, 'error');
    }


    workerState.p2p.node.addEventListener('pluribit:peer-verified', safe((evt) => {
        log(`[SYNC] New verified peer detected (${evt.detail.slice(-6)}). Checking for a better chain...`, 'info');
        // Add a small delay to allow network chatter to settle before syncing.
        setTimeout(safe(bootstrapSync), 500);
    }));

    // Kick off an initial attempt (will no-op if no peers yet)
    // Start the sync process after a brief pause for initial connections.
    // The bootstrapSync function itself will handle retries with backoff.
    const BASE_DELAY_MS = 2000;
    setTimeout(safe(bootstrapSync), BASE_DELAY_MS);

// RATIONALE: Prevent memory leaks from accumulating request history
blockRequestCleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [peer, requests] of blockRequestState.peerRequests) {
        for (const [hash, time] of requests) {
            if (now - time > blockRequestState.CLEANUP_INTERVAL) {
                requests.delete(hash);
            }
        }
        if (requests.size === 0) {
            blockRequestState.peerRequests.delete(peer);
        }
    }
    
    // RATIONALE ( Memory Leak): Periodically clean up the hash request
    // rate-limiting map to prevent it from growing indefinitely with stale peer entries.
    const PEER_HASH_REQUEST_CLEANUP_INTERVAL = 5 * 60 * 1000; // 5 minutes
    const PEER_HASH_REQUEST_ENTRY_TTL = 15 * 60 * 1000; // 15 minutes
    setInterval(() => {
        const now = Date.now();
        for (const [peerId, timestamp] of syncState.peerHashRequestTimes.entries()) {
            if (now - timestamp > PEER_HASH_REQUEST_ENTRY_TTL) {
                syncState.peerHashRequestTimes.delete(peerId);
            }
        }
    }, PEER_HASH_REQUEST_CLEANUP_INTERVAL);
 }, blockRequestState.CLEANUP_INTERVAL);

async function gracefulShutdown(code = 0) {
  try {
    log('Shutting down...');
    workerState.minerActive = false;

    if (blockRequestCleanupTimer) clearInterval(blockRequestCleanupTimer);
    
    // Close API server
    if (apiServer) {
        apiServer.close();
    }
    
    // give the mining loop a tick to exit
    await new Promise(r => setTimeout(r, 5));
    if (workerState.p2p) {
      await workerState.p2p.stop(); // closes mdns/ping/etc cleanly
    }
  } catch (e) {
    log(`Shutdown error: ${e?.message || e}`, 'warn');
  } finally {
    process.exit(code);
  }
}

process.on('SIGINT', () => gracefulShutdown(0));
process.on('SIGTERM', () => gracefulShutdown(0));






    log('P2P stack online.', 'success');
    parentPort.postMessage({ type: 'networkInitialized' });
   // Start API server for block explorer
    startApiServer();
    log('Network initialization complete.', 'success');
}


// Ask peers for their tip, but only when someone is there to hear us.
// Retries with a short backoff if nobody is subscribed yet.
// worker.js

async function bootstrapSync(attempt = 1) {
  if (syncState.syncProgress.status !== 'IDLE') {
      log('[SYNC] Bootstrap skipped: a sync is already in progress.', 'debug');
      return;
  }
  syncState.syncProgress.status = 'CONSENSUS';

  const MAX_ATTEMPTS = 5;
  const BASE_DELAY_MS = 2000;

  const scheduleRetry = (message) => {
    if (syncState.syncProgress.status !== 'CONSENSUS') return;
    if (attempt >= MAX_ATTEMPTS) {
        log(`[SYNC] Initial sync failed after ${MAX_ATTEMPTS} attempts. Will rely on new peer connections to trigger sync.`, 'warn');
        syncState.syncProgress.status = 'IDLE';
        return;
    }
    const delay = BASE_DELAY_MS * Math.pow(2, attempt - 1);
    log(`[SYNC] ${message}. Retrying in ${delay}ms (attempt ${attempt + 1}/${MAX_ATTEMPTS})`, 'info');
    setTimeout(() => bootstrapSync(attempt + 1), delay);
  };

  try {
    const { p2p } = workerState;
    if (!p2p || !p2p.node) {
        syncState.syncProgress.status = 'IDLE';
        return;
    }

    const allPeers = p2p.getConnectedPeers?.() ?? [];
    const verifiedPeers = allPeers.filter(p => p2p.isPeerVerified(p.id));
if (verifiedPeers.length === 0) {
        // RATIONALE: If no peers are found, the status must be reset
        // to 'IDLE' *before* scheduling a retry. This prevents the 'CONSENSUS'
        // state from blocking a new sync attempt triggered by a peer connecting
        // and becoming verified in the interim.
        syncState.syncProgress.status = 'IDLE';
        scheduleRetry("No verified peers found");
        return;
}
    log(`[SYNC] Found ${verifiedPeers.length} verified peers. Querying for chain tip...`, 'info');

    const tipResponses = new Map();
    const tipHandler = (message, { from }) => {
        // The 'message' is now the SyncMessage object. Check its 'payload' oneof field.
        if (message.payload === 'tipResponse') {
            const response = message.tipResponse; // Get the nested data
            log(
                `[SYNC] Received TIP_RESPONSE from ${from.toString().slice(-6)}: ` +
                `Height=${response.height}, Work=${response.totalWork}, Hash=${response.tipHash.substring(0, 12)}...`,
                'debug'
            );
            tipResponses.set(from.toString(), {
                hash: response.tipHash,
                height: BigInt(response.height),
                totalWork: BigInt(response.totalWork)
            });
        }
    };

    await p2p.subscribe(TOPICS.SYNC, tipHandler);
    // Publish the new wrapped message for a request
    await p2p.publish(TOPICS.SYNC, { tipRequest: {} });

    // --- START: CORRECTED setTimeout LOGIC ---
setTimeout(() => {
        (async () => {
            await p2p.unsubscribe(TOPICS.SYNC, tipHandler);

            if (syncState.syncProgress.status !== 'CONSENSUS') return;

            try {
                if (tipResponses.size === 0) {
                    scheduleRetry("No peers responded with a valid chain tip");
                    return; 
                }

                log(`[SYNC] Consensus Phase: Collected ${tipResponses.size} valid tip(s) for evaluation.`, 'info');
                
                const bestTip = [...tipResponses.values()].sort((a, b) => (b.totalWork > a.totalWork) ? 1 : -1)[0];
                
                
                const peersForBestTip = [];
                for (const [peer, tip] of tipResponses.entries()) {
                    if (tip.hash === bestTip.hash) {
                        peersForBestTip.push(peer);
                    }
                }

                const { CONSENSUS_THRESHOLD, MIN_AGREEING_PEERS } = CONFIG.SYNC;
                const agreement = peersForBestTip.length / tipResponses.size;
                
                if (agreement < CONSENSUS_THRESHOLD || peersForBestTip.length < MIN_AGREEING_PEERS) {
                    log(`[SYNC] No consensus on best chain tip. Best candidate (Work=${bestTip.totalWork}) only had ${Math.round(agreement * 100)}% agreement.`, 'warn');
                    syncState.syncProgress.status = 'IDLE';
                    return; 
                }

                const myState = await pluribit.get_blockchain_state();
                if (bestTip.totalWork > BigInt(myState.total_work)) {
                    log(`[SYNC] Consensus reached on better chain (Height=${bestTip.height}, Work=${bestTip.totalWork}).`, 'success');
                    
                    // SET THE SYNC FLAG IMMEDIATELY to prevent the gossip handler from interfering.
                    workerState.isSyncing = true;
                    
                    if (bestTip.height > myState.current_height) {
                        // Scenario 1: The better chain is longer. This is a simple fast-forward.
                        log(`[SYNC] Better chain is longer. Starting forward sync...`, 'info');
                        await syncForward(bestTip.height, bestTip.hash, peersForBestTip);
                    } else {
                        // Scenario 2: The better chain has more work but isn't longer. This is a fork that requires a reorg.
                        log(`[SYNC] Fork with more work detected. Fetching tip to initiate reorg...`, 'info');
                        syncState.syncProgress.status = 'DOWNLOADING'; // Use same status to prevent concurrent syncs
                        
                        // Fetch only the single block that is the tip of the better fork.
                        const tipBlock = await fetchBlockDirectly(peersForBestTip[0], bestTip.hash);
                        
                        if (tipBlock) {
                            // Feed this block into the regular ingestion pipeline. The Rust `ingest_block_bytes`
                            // function will see it's a fork tip and trigger the reorg planner automatically.
                            await handleRemoteBlockDownloaded({ block: tipBlock });
                        } else {
                            throw new Error(`Failed to fetch fork tip ${bestTip.hash} to start reorg.`);
                        }

                        // After the reorg is handled (or fails), reset the sync state.
                        syncState.syncProgress.status = 'IDLE';
                        workerState.isSyncing = false;
                        parentPort.postMessage({ type: 'syncComplete' });
                    }

                } else {
                    log('[SYNC] Already synced to the best known chain.', 'info');
                    syncState.syncProgress.status = 'IDLE';
                }
            } catch (err) {
                 log(`[SYNC] Error during consensus or sync trigger: ${err.message}`, 'error');
                 syncState.syncProgress.status = 'IDLE'; // Reset on error
            }
        })();
    }, 2000);
    // --- END: CORRECTED setTimeout LOGIC ---

  } catch (e) {
    log(`[SYNC] Unexpected error in bootstrapSync: ${String(e?.message || e)}`, 'warn');
    syncState.syncProgress.status = 'IDLE';
  }
}



async function requestAllHashes(peerId, startHeight) {
    // RATIONALE: This function has been refactored to prevent a deadlock.
    // The mutex is now acquired only to write to the shared state map, and
    // then released *before* awaiting the network response.

    const requestId = crypto.randomUUID();
    const { promise, resolve, reject } = Promise.withResolvers();

    // 1. Acquire mutex ONLY to safely add the request to the shared map.
    const release = await syncState.hashRequestMutex.acquire();
    try {
        syncState.hashRequestState.set(requestId, { hashes: [], resolve, reject, peerId });
    } finally {
        release();
    }

    // 2. Set a timeout to prevent waiting forever. The cleanup is wrapped in a
    //    mutex operation to prevent race conditions.
    const timeout = setTimeout(() => {
        syncState.hashRequestMutex.run(async () => {
            if (syncState.hashRequestState.has(requestId)) {
                reject(new Error(`Hash request to peer ${peerId} timed out`));
                syncState.hashRequestState.delete(requestId);
            }
        }).catch(err => log(`[SYNC] Error during timeout cleanup: ${err.message}`, 'error'));
    }, 30000);

    try {
        // 3. Publish the request *after* releasing the lock.
        await workerState.p2p.publish(TOPICS.GET_HASHES_REQUEST, {
             startHeight: startHeight.toString(),
            requestId: requestId
        });

        // 4. Await the promise. The response handler can now acquire the lock to resolve it.
        const fullHashes = await promise;
        clearTimeout(timeout);
        return fullHashes;
    } catch (error) {
        // 5. If any part of the process fails, ensure the timeout is cleared.
        clearTimeout(timeout);
        // Rethrow the error to be handled by the caller (syncForward).
        throw error;
    }
}




async function setupMessageHandlers() {
    const { p2p } = workerState;

await p2p.subscribe(TOPICS.BLOCKS, async (block) => {
    // The received message IS the block object from the Protobuf payload.
    // We just need to validate it has the properties of a block and process it.
    if (block && typeof block.height !== 'undefined') {
        log(`Received full block #${block.height} from network`, 'info');
        await handleRemoteBlockDownloaded({ block: block });
    } else {
        log(`[WARN] Received an invalid or empty message on the BLOCKS topic.`, 'warn');
    }
});


// (Note: You will need to define new Protobuf messages for these payloads)
    // (For now, we assume the payload is the raw JSON object for simplicity)

    await p2p.subscribe(TOPICS.CHANNEL_PROPOSE, async (proposal, { from }) => {
        await handleChannelPropose(proposal, from);
    });

    await p2p.subscribe(TOPICS.CHANNEL_ACCEPT, async (acceptance, { from }) => {
        await handleChannelAccept(acceptance, from);
    });

    await p2p.subscribe(TOPICS.CHANNEL_FUND_NONCE, async (message, { from }) => {
        await handleChannelFundNonce(message, from);
    });

    await p2p.subscribe(TOPICS.CHANNEL_FUND_SIG, async (message, { from }) => {
        await handleChannelFundSig(message, from);
    });

    await p2p.subscribe(TOPICS.CHANNEL_PAY_PROPOSE, async (proposal, { from }) => {
        await handleChannelPayPropose(proposal, from);
    });

    await p2p.subscribe(TOPICS.CHANNEL_PAY_ACCEPT, async (acceptance, { from }) => {
        await handleChannelPayAccept(acceptance, from);
    });

    await p2p.subscribe(TOPICS.CHANNEL_CLOSE_NONCE, async (message, { from }) => {
        await handleChannelCloseNonce(message, from);
    });

    await p2p.subscribe(TOPICS.CHANNEL_CLOSE_SIG, async (message, { from }) => {
        await handleChannelCloseSig(message, from);
    });


await p2p.subscribe(TOPICS.SWAP_PROPOSE, async (proposal, { from }) => {
        await handleSwapPropose(proposal, from);
    });

    await p2p.subscribe(TOPICS.SWAP_RESPOND, async (response, { from }) => {
        await handleSwapRespondP2P(response, from);
    });
    
    await p2p.subscribe(TOPICS.SWAP_ALICE_ADAPTOR_SIG, async (message, { from }) => {
        await handleSwapAliceSig(message, from);
    });

    // Handle incoming transactions
    // Expect raw transaction object, not wrapper.
    // RATIONALE: The P2P layer deserializes the Transaction protobuf and passes
    // the raw transaction object directly to this handler.
    await p2p.subscribe(TOPICS.TRANSACTIONS, async (transaction) => {
        if (transaction && transaction.inputs) {  // Validate it's a transaction
            try {
                log(`Received transaction from network`, 'info');

                // Convert Longs/BigInts first
                const txForRust = convertLongsToBigInts(transaction);

                // --- ADD THIS LOG LINE ---
                console.log('[DEBUG TX HANDLER] Transaction object being passed to Rust:', util.inspect(txForRust, { depth: null, colors: true }));
                // --- END ADD ---

                // Directly pass the transaction (after BigInt conversion) to Rust
                await pluribit.add_transaction_to_pool(txForRust); // Pass the converted object
                log(`Added network transaction to pool.`, 'success');
            } catch (e) {
                const errorMsg = e?.message || String(e);
                log(`Failed to add network transaction: ${errorMsg}`, 'warn');
            }
        } else {
            log(`[P2P] Received invalid transaction message: ${JSON.stringify(transaction).substring(0, 100)}`, 'warn');
        }
    });
    
    await p2p.subscribe(TOPICS.BLOCK_REQUEST, async (message, { from }) => {
        const { hash } = message;
        if (!hash) return;
        
        try {
            const block = await pluribit.get_block_by_hash(hash);
            if (block) {
                const blockString = JSONStringifyWithBigInt(block);
                const bytes = new TextEncoder().encode(blockString);

                if (bytes.byteLength <= CONFIG.MAX_MESSAGE_SIZE) {
                    // Block is small enough, send it
                    await p2p.publish(TOPICS.BLOCKS, block);
                } else {
                    // Block is too large - log and skip
                    log(`Block ${hash.substring(0,12)} is too large (${bytes.byteLength} bytes). Cannot send via gossipsub.`, 'warn');
                }
            }
        } catch (e) {
            log(`Failed to serve block request: ${e.message}`, 'warn');
        }
    });
    

    // Handle lightweight block announcements (no change)
    await p2p.subscribe(TOPICS.BLOCK_ANNOUNCEMENTS, async (message, { from }) => {
        const h = message?.hash;  
        if (!h) return;
        // Skip if this is our own broadcast echoing back
        if (from.toString() === workerState.p2p.node.peerId.toString()) {
            log(`[DEBUG] Ignoring our own block announcement for ${h.substring(0,12)}`);
            return;
        }
        try {
            const have = await pluribit.get_block_by_hash(h);
            if (have) return; // already have it
            if (reorgState.requestedBlocks.has(h)) return; // already requested

            trackRequest(h);
            log(`ANN: missing block ${h.substring(0,12)} from ${String(from).slice(-6)}; fetching directly…`, 'info');

            // Try direct stream fetch from the announcing peer first
            const direct = await fetchBlockDirectly(from, h);
            if (direct) {
              await handleRemoteBlockDownloaded({ block: direct });
              return;
            }

            // Fallback: broadcast a network request (pubsub)
            await p2p.publish(TOPICS.BLOCK_REQUEST, { hash: h });

        } catch (e) {
            log(`ANN handler error: ${e.message || e}`, 'warn');
        }
    });

    // Register block-transfer responder via P2P wrapper (libp2p-node will proxy to this)
    const NET = process.env.PLURIBIT_NET || 'mainnet';
    const BLOCK_TRANSFER_PROTOCOL = `/pluribit/${NET}/block-transfer/1.0.0`;
    await p2p.subscribe(BLOCK_TRANSFER_PROTOCOL, async (hash) => {
      try { return await pluribit.get_block_by_hash(hash); }
      catch { return null; }
    });


    // New handler to respond to hash requests from other peers
    await p2p.subscribe(TOPICS.GET_HASHES_REQUEST, async (message, { from }) => {
        // A node should not respond to its own requests.
        if (from.toString() === workerState.p2p.node.peerId.toString()) {
            return;
        }
        try {
            const start_height = BigInt(message.startHeight);
            const { requestId } = message;
            
            // RATIONALE (Fix #6): Add rate limiting for this expensive request.
            const now = Date.now();
            const peerIdStr = from.toString();
            if ((now - (syncState.peerHashRequestTimes.get(peerIdStr) || 0)) < CONFIG.SYNC.MIN_HASH_REQUEST_INTERVAL_MS) {
                log(`[SYNC] Rate-limited hash request from ${peerIdStr}`, 'warn');
                return;
            }
            syncState.peerHashRequestTimes.set(peerIdStr, now);
            
            // RATIONALE (Fix #10): Validate the requested start height to prevent abuse.
            const tipHeight = await db.getTipHeight();
            // FIX: Convert the config value to a BigInt before performing arithmetic.
            if (start_height < tipHeight - BigInt(CONFIG.SYNC.MAX_HASH_REQUEST_RANGE)) {
                log(`[SYNC] Ignoring hash request for start height ${start_height} (too far behind tip ${tipHeight})`, 'warn');
                return;
            }
            
            // FIX: Removed redundant BigInt() wrapper - start_height is already BigInt
            const hashes = await pluribit.get_canonical_hashes_after(start_height);
            
            const HASH_CHUNK_SIZE = 1000; // Send 1000 hashes per message
            
            if (hashes.length === 0) {
                await p2p.publish(TOPICS.HASHES_RESPONSE, { 
                    hashes: [], 
                    requestId, 
                    finalChunk: true 
                });
            } else {
                for (let i = 0; i < hashes.length; i += HASH_CHUNK_SIZE) {
                    const chunk = hashes.slice(i, i + HASH_CHUNK_SIZE);
                    const isFinal = (i + HASH_CHUNK_SIZE) >= hashes.length;
                    
                    await p2p.publish(TOPICS.HASHES_RESPONSE, { 
                        hashes: chunk, 
                        requestId: requestId,   
                        finalChunk: isFinal      
                    });
                }
            }
            log(`SYNC: Sent ${hashes.length} hashes to peer ${String(from).slice(-6)} in chunks`, 'info');
        } catch (e) {
            // Better error handling for non-Error objects
            const errorMsg = e?.message || e?.toString() || String(e);
            log(`SYNC: Failed to serve hashes to peer: ${errorMsg}`, 'warn');
        }
    });

    // New handler to receive the list of hashes
    await p2p.subscribe(TOPICS.HASHES_RESPONSE, async (message, { from }) => {
        const { hashes, requestId, finalChunk } = message; 

        
        // RATIONALE: Use mutex to prevent race conditions on shared state.
        const release = await syncState.hashRequestMutex.acquire();
        try {
            const request = syncState.hashRequestState.get(requestId);
            if (!request) {
                return; // Ignore stale or unknown responses
            }
        
            // --- RATIONALE: Enforce a hard limit on total hashes received ---
            // This is the core fix for the memory exhaustion (OOM) attack. We check the
            // size *before* appending to memory.
            if (request.hashes.length + (hashes || []).length > CONFIG.SYNC.MAX_HASHES_PER_SYNC) {
                const error = new Error(`Peer ${request.peerId} exceeded max hash limit of ${CONFIG.SYNC.MAX_HASHES_PER_SYNC}`);
                request.reject(error);
                syncState.hashRequestState.delete(requestId);
                // Penalize the peer for this behavior.
                const PENALTY = 50; // A large penalty for a severe infraction.
                const currentScore = workerState.peerScores.get(request.peerId) || 100;
                const newScore = Math.max(0, currentScore - PENALTY);
                workerState.peerScores.set(request.peerId, newScore);
                if (newScore === 0) {
                    try { workerState.p2p.node.hangUp(request.peerId); } catch(e) {}
                }
                return;
            }

            // Append the received chunk of hashes
            request.hashes.push(...(hashes || []));

            // --- START: Explicitly check the final_chunk flag ---
            // RATIONALE: The sync promise will time out if it's never resolved. This
            // guard ensures we only resolve when we receive a message that explicitly
            // marks the end of the hash stream.
            if (finalChunk === true) {
                request.resolve(request.hashes);
                syncState.hashRequestState.delete(requestId);
            }
        } finally {
            release();
        }
    });
 

await p2p.subscribe(TOPICS.SYNC, async (message, { from }) => {
        // 'message' is the SyncMessage. Check if it's a request.
        if (message.payload === 'tipRequest') {
            const st = await pluribit.get_blockchain_state();

            log(
                `[SYNC] Received TIP_REQUEST from ${from.toString().slice(-6)}. Responding with my tip: ` +
                `Height=${st.current_height}, Work=${st.total_work}, Hash=${st.tip_hash.substring(0, 12)}...`, 
                'debug'
            );

            // Publish the new wrapped response message
            await p2p.publish(TOPICS.SYNC, {
                tipResponse: {
                   height: st.current_height,
                   totalWork: String(st.total_work),
                   tipHash: st.tip_hash,
                }
            });
        }
    });
}


// --- PAYMENT CHANNEL CLI HANDLERS ---

async function handleChannelOpen({ walletId, counterpartyPubkey, myAmount, theirAmount }) {
    log(`[CHANNEL] Received command to open channel with ${counterpartyPubkey}`);
    // TODO:
    // 1. Get wallet secret key: `const secret = await pluribit.wallet_session_get_spend_privkey(walletId);`
    // 2. Call Wasm: `const result = await pluribit.payment_channel_open(secret, myAmount, ...);`
    // 3. Deserialize `result`: `const { channel, proposal } = JSON.parse(result);`
    // 4. Store channel: `workerState.paymentChannels.set(channel.channel_id, channel);`
    // 5. Publish proposal: `await workerState.p2p.publish(TOPICS.CHANNEL_PROPOSE, proposal);`
    // 6. Log success to user.
    log("[CHANNEL] STUB: handleChannelOpen logic not yet implemented.", 'warn');
}

async function handleChannelList() {
    log("[CHANNEL] STUB: handleChannelList logic not yet implemented.", 'warn');
    // TODO: List channels from `workerState.paymentChannels`
    // TODO: List proposals from `workerState.pendingChannelProposals`
}



async function handleChannelFund({ walletId, channelId }) {
    log(`[CHANNEL] Received command to fund channel ${channelId}`);
    // TODO: This is the start of the MuSig2 "dance"
    // 1. Get channel from `workerState.paymentChannels`.
    // 2. Generate nonces (requires a new Wasm function `generate_musig_nonces()`).
    // 3. Store nonces in `workerState.musigSessions`.
    // 4. Publish fund_nonce: `await workerState.p2p.publish(TOPICS.CHANNEL_FUND_NONCE, { channelId, publicNoncePoint, ... });`
    log("[CHANNEL] STUB: handleChannelFund logic not yet implemented.", 'warn');
}

async function handleChannelPay({ walletId, channelId, amount }) {
    log(`[CHANNEL] Received command to pay ${amount} in channel ${channelId}`);
    // TODO: This is the start of the payment "dance"
    // 1. Get channel and wallet keys.
    // 2. Call Wasm `payment_channel_make_payment` (which is now `initiate_payment`).
    // 3. This returns a `proposal`.
    // 4. Publish proposal: `await workerState.p2p.publish(TOPICS.CHANNEL_PAY_PROPOSE, proposal);`
    log("[CHANNEL] STUB: handleChannelPay logic not yet implemented.", 'warn');
}

async function handleChannelClose({ walletId, channelId }) {
    log(`[CHANNEL] Received command to close channel ${channelId}`);
    // TODO: This is the start of the *cooperative close* MuSig2 "dance"
    // (Similar to handleChannelFund)
    log("[CHANNEL] STUB: handleChannelClose logic not yet implemented.", 'warn');
}

// --- PAYMENT CHANNEL P2P HANDLERS ---

async function handleChannelPropose(proposal, from) {
    // TODO:
    // 1. Generate a unique ID for the proposal.
    // 2. Store it: `workerState.pendingChannelProposals.set(proposalId, proposal);`
    // 3. Log to user: `log(Received channel proposal [id] from [from]. Type 'channel_accept [id]' to accept.)`
    log(`[CHANNEL] STUB: Received channel proposal from ${from}. Logic not implemented.`, 'warn');
}

async function handleChannelAccept(acceptance, from) {
    // TODO:
    // 1. Get our channel: `const channel = workerState.paymentChannels.get(acceptance.channel_id);`
    // 2. Call Wasm: `const updatedChannel = await pluribit.payment_channel_complete_open(channel, acceptance, ...);`
    // 3. Store updated channel.
    // 4. Log to user: `log(Channel ${acceptance.channel_id} is now ready to fund. Run 'channel_fund ...')`
    log(`[CHANNEL] STUB: Received channel acceptance from ${from}. Logic not implemented.`, 'warn');
}

async function handleChannelFundNonce(message, from) {
    // TODO: This is the complex part of the "dance"
    // (See logic described in my previous response)
    log(`[CHANNEL] STUB: Received FUND_NONCE from ${from}. Logic not implemented.`, 'warn');
}

async function handleChannelFundSig(message, from) {
    // TODO: This is the complex part of the "dance"
    log(`[CHANNEL] STUB: Received FUND_SIG from ${from}. Logic not implemented.`, 'warn');
}

async function handleChannelPayPropose(proposal, from) {
    // TODO:
    // 1. Get channel and wallet keys.
    // 2. Call Wasm `payment_channel_accept_payment`.
    // 3. This returns an `acceptance`.
    // 4. Publish acceptance: `await workerState.p2p.publish(TOPICS.CHANNEL_PAY_ACCEPT, acceptance);`
    log(`[CHANNEL] STUB: Received PAY_PROPOSE from ${from}. Logic not implemented.`, 'warn');
}

async function handleChannelPayAccept(acceptance, from) {
    // TODO:
    // 1. Get channel.
    // 2. Call Wasm `payment_channel_complete_payment`.
    // 3. Store updated channel.
    // 4. Log to user: `log(Payment in channel ${acceptance.channel_id} complete.)`
    log(`[CHANNEL] STUB: Received PAY_ACCEPT from ${from}. Logic not implemented.`, 'warn');
}

// --- ATOMIC SWAP CLI HANDLERS ---

async function handleSwapInitiate({ walletId, counterpartyPubkey, plbAmount, btcAmount, timeoutBlocks }) {
    log(`[SWAP] Initiating swap: ${plbAmount} PLB for ${btcAmount} sats...`);
    // TODO:
    // 1. Get wallet secret: `const secret = await pluribit.wallet_session_get_spend_privkey(walletId);`
    // 2. Call Wasm: `const swapJson = await pluribit.atomic_swap_initiate(secret, plbAmount, hexToBytes(counterpartyPubkey), btcAmount, timeoutBlocks);` [cite: 859-860]
    // 3. Deserialize: `const swap = JSON.parse(swapJson);`
    // 4. Store: `workerState.atomicSwaps.set(swap.swap_id, { swap, role: 'alice' });`
    // 5. Publish: `await workerState.p2p.publish(TOPICS.SWAP_PROPOSE, swap);`
    // 6. Log to user.
    log("[SWAP] STUB: handleSwapInitiate logic not yet implemented.", 'warn');
}

async function handleSwapList() {
    log("[SWAP] STUB: handleSwapList logic not yet implemented.", 'warn');
    // TODO: List swaps from `workerState.atomicSwaps`
    // TODO: List proposals from `workerState.pendingSwapProposals`
}

async function handleSwapRespond({ walletId, swapId, btcAddress, btcTxid, btcVout }) {
    log(`[SWAP] Responding to swap ${swapId} with HTLC ${btcTxid}:${btcVout}`);
    // TODO:
    // 1. Get proposal: `const proposal = workerState.pendingSwapProposals.get(swapId);`
    // 2. Get wallet secret.
    // 3. Get timeout (e.g., from proposal or config).
    // 4. Call Wasm: `const swapJson = await pluribit.atomic_swap_respond(JSON.stringify(proposal), secret, btcAddress, btcTxid, btcVout, [], timeout);` 
    // 5. Deserialize: `const swap = JSON.parse(swapJson);`
    // 6. Store: `workerState.atomicSwaps.set(swap.swap_id, { swap, role: 'bob' });`
    // 7. Publish: `await workerState.p2p.publish(TOPICS.SWAP_RESPOND, swap);`
    log("[SWAP] STUB: handleSwapRespond logic not yet implemented.", 'warn');
}

async function handleSwapRefund({ walletId, swapId }) {
    log(`[SWAP] Attempting to refund swap ${swapId}`);
    // TODO:
    // 1. Get swap: `const { swap, role } = workerState.atomicSwaps.get(swapId);`
    // 2. Get wallet secret.
    // 3. Get current height.
    // 4. If role == 'alice':
    //    `const refundTx = await pluribit.atomic_swap_refund_alice(JSON.stringify(swap), secret, ...);` [cite: 867-868]
    // 5. If role == 'bob':
    //    (This would need a Bitcoin library to broadcast a refund)
    // 6. Broadcast Pluribit refund tx.
    log("[SWAP] STUB: handleSwapRefund logic not yet implemented.", 'warn');
}

// --- ATOMIC SWAP P2P HANDLERS ---

async function handleSwapPropose(proposal, from) {
    // TODO:
    // 1. Store proposal: `workerState.pendingSwapProposals.set(proposal.swap_id, proposal);`
    // 2. Log to user: `log(Received swap proposal ${proposal.swap_id} from ${from}. Use 'swap_respond' to accept.)`
    log(`[SWAP] STUB: Received swap proposal from ${from}. Logic not implemented.`, 'warn');
}

async function handleSwapRespondP2P(response, from) {
    // This is Alice receiving Bob's response
    log(`[SWAP] Received response for swap ${response.swap_id} from ${from}`);
    // TODO:
    // 1. Get our swap: `const { swap, role } = workerState.atomicSwaps.get(response.swap_id);`
    // 2. Get wallet secret.
    // 3. Call Wasm: `const updatedSwapJson = await pluribit.atomic_swap_alice_create_adaptor_sig(JSON.stringify(response), secret);` [cite: 862-863]
    // 4. Deserialize: `const updatedSwap = JSON.parse(updatedSwapJson);`
    // 5. Store updated swap.
    // 6. Publish adaptor sig: `await workerState.p2p.publish(TOPICS.SWAP_ALICE_ADAPTOR_SIG, { swapId: updatedSwap.swap_id, adaptorSig: updatedSwap.alice_adaptor_sig });`
    log("[SWAP] STUB: handleSwapRespondP2P logic not yet implemented.", 'warn');
}

async function handleSwapAliceSig(message, from) {
    // This is Bob receiving Alice's adaptor signature
    log(`[SWAP] Received Alice's adaptor sig for swap ${message.swapId}`);
    // TODO:
    // 1. Get our swap: `const { swap, role } = workerState.atomicSwaps.get(message.swapId);`
    // 2. Store `message.adaptorSig` in our swap object.
    // 3. Now Bob can claim. This involves:
    //    a. Get adaptor secret (this is complex, from adaptor sig + our secret)
    //    b. Call Wasm `atomic_swap_bob_claim` [cite: 864-865]
    //    c. Broadcast the resulting Pluribit transaction.
    // 4. Log to user: `log(Ready to claim swap ${message.swapId}. Run 'swap_claim ...')`
    log("[SWAP] STUB: handleSwapAliceSig logic not yet implemented.", 'warn');
}



// Helper function to update wallets after reorg
async function updateWalletsAfterReorg() {
    log(`[REORG] Persisting updated wallet states...`);
    const release = await globalMutex.acquire();
    try {
        for (const walletId of workerState.wallets.keys()) {
            try {
                const updatedJson = await pluribit.wallet_session_export(walletId);
                await db.saveWallet(walletId, updatedJson);
                log(`[REORG] Wallet '${walletId}' state saved successfully.`);
                const newBalance = await pluribit.wallet_session_get_balance(walletId);
                parentPort.postMessage({ type: 'walletBalance', payload: { wallet_id: walletId, balance: newBalance }});
            } catch (e) {
                log(`[REORG] Failed to save wallet '${walletId}' post-reorg: ${e.message}`, 'error');
            }
        }
    } finally {
        release();
    }
}



async function handleCreateWalletWithMnemonic({ walletId }) {
    if (!walletId) return log('Wallet ID cannot be empty.', 'error');
    if (await db.walletExists(walletId)) {
        return log(`Wallet '${walletId}' already exists. Use 'load'.`, 'error');
    }
    try {
        // Call the new Rust function
        const phrase = await pluribit.wallet_session_create_with_mnemonic(walletId);

        // Export immediately to save the newly created wallet state
        const blob = await pluribit.wallet_session_export(walletId);
        await db.saveWallet(walletId, blob);

        log(`New wallet '${walletId}' created successfully.`, 'success');
        log('IMPORTANT: Write down your 12-word mnemonic phrase and keep it safe:', 'warn'); // Use 'warn' level?
        log(phrase, 'info'); // Log phrase plainly or maybe 'success'?
        log('This phrase is required to restore your wallet.', 'warn'); // Use 'warn' level?
        parentPort.postMessage({ type: 'log', payload: { level: 'success', message: `Wallet '${walletId}' created. Mnemonic logged above.`}}); // Notify main
    } catch (e) {
        log(`Failed to create wallet '${walletId}': ${e?.message || e}`, 'error');
        // Clean up session if creation failed partially
        try { await pluribit.wallet_session_clear(walletId); } catch {}
    }
}

async function handleRestoreWalletFromMnemonic({ walletId, phrase }) {
    if (!walletId) return log('Wallet ID cannot be empty.', 'error');
    if (await db.walletExists(walletId)) {
        return log(`Wallet '${walletId}' already exists. Use 'load'.`, 'error');
    }
    if (!phrase || phrase.split(' ').length !== 12) {
         return log(`Invalid mnemonic phrase provided. Must be 12 words.`, 'error');
    }
    try {
        // Call the new Rust restore function
        await pluribit.wallet_session_restore_from_mnemonic(walletId, phrase);

        // Export immediately to save the restored wallet state
        const blob = await pluribit.wallet_session_export(walletId);
        await db.saveWallet(walletId, blob);

        log(`Wallet '${walletId}' restored successfully from mnemonic phrase.`, 'success');
        log(`Use 'load ${walletId}' to activate it.`, 'info');
         parentPort.postMessage({ type: 'log', payload: { level: 'success', message: `Wallet '${walletId}' restored.`}}); // Notify main
    } catch (e) {
        log(`Failed to restore wallet '${walletId}': ${e?.message || e}`, 'error');
        // Clean up session if restore failed partially
        try { await pluribit.wallet_session_clear(walletId); } catch {}
    }
}

async function handleLoadWallet({ walletId }) {
    const release = await globalMutex.acquire();
        try {
          await pluribit.wallet_session_clear_all();
          workerState.wallets.clear();
          let walletRecord;
          try {
            walletRecord = await db.loadWallet(walletId);
          } catch (e) {
            if (e?.code === 'WALLET_PASSPHRASE_REQUIRED') {
              return log(`Wallet '${walletId}' is encrypted. Set PLURIBIT_WALLET_PASSPHRASE and retry.`, 'error');
            }
            return log(`Failed to load wallet '${walletId}': ${e?.message || e}`, 'error');
          }
          if (walletRecord == null) {
            return log(`Wallet '${walletId}' not found.`, 'error');
          }

        // Load JSON blob straight into Rust session (JS never parses keys)
        const walletJson = (typeof walletRecord === 'string') ? walletRecord : JSON.stringify(walletRecord);
        await pluribit.wallet_session_open(walletId, walletJson);

        log(`Scanning blockchain for wallet '${walletId}'...`, 'info');
        await pluribit.wallet_session_scan_chain(walletId);

        // Persist updated state (from Rust session) and report summary
        const persisted = await pluribit.wallet_session_export(walletId);
        await db.saveWallet(walletId, persisted);
        const balance = await pluribit.wallet_session_get_balance(walletId);
        const address = await pluribit.wallet_session_get_address(walletId);

        // Instead of storing the full wallet data, just mark the session as active.
        workerState.wallets.set(walletId, true); 

        parentPort.postMessage({
            type: 'walletLoaded',
            payload: { walletId, balance, address }
        });
   } finally {
        release();
    }
}

async function handleCreateTransaction({ from, to, amount, fee }) {
  // RATIONALE: This function is now atomic.
  // Wallet state is only persisted AFTER
  // the transaction has been successfully validated and broadcast to the network.
  // A broadcast failure will now correctly revert the in-memory wallet changes.
  // Keep a copy of the pre-transaction state in case we need to revert
  const originalWalletState = await pluribit.wallet_session_export(from);
  const release = await globalMutex.acquire();
  try {
    // 1. Create the transaction. This mutates the in-memory Rust wallet session.
    const result = await pluribit.wallet_session_send_to_stealth(
      from, BigInt(amount), BigInt(fee), to
    );
    // 2. Add to our own mempool first. This also serves as a final validation.
        try {
            await pluribit.add_transaction_to_pool(result.transaction);
        } catch (e) {
            // FIX #6: Transaction validation failed - clear pending marks
            const commitments = result.transaction.inputs.map(inp => inp.commitment);
            await pluribit.wallet_clear_pending_utxos(commitments);
            throw e;
        }
       
    // 3. Attempt to broadcast the transaction to the network.
    // Send raw transaction object, not wrapped.
    // RATIONALE: The P2P layer encodes this as a Transaction protobuf message.
    // The Transaction schema expects fields like 'inputs', 'outputs', 'kernels',
    // NOT wrapper fields like 'type' and 'payload'. The wrapper causes encoding
    // to fail, resulting in a malformed message that peers silently drop.
    //try {
    //  await workerState.p2p.publish(TOPICS.TRANSACTIONS, result.transaction);
    //    } catch (e) {
    //        // FIX #6: Broadcast failed - clear pending marks
    //        const commitments = result.transaction.inputs.map(inp => inp.commitment);
    //        await pluribit.wallet_clear_pending_utxos(commitments);
    //        log(`[RUST] Transaction broadcast failed, UTXOs unmarked: ${e?.message || e}`, 'warn');
    //        throw e;
    //   }


    // ✨ CHANGED: Use Dandelion stem instead of direct broadcast
    try {
      await workerState.p2p.stemTransaction(result.transaction); // Instead of publish
    } catch (e) {
        const commitments = result.transaction.inputs.map(inp => inp.commitment);
        await pluribit.wallet_clear_pending_utxos(commitments);
        log(`[RUST] Transaction broadcast failed, UTXOs unmarked: ${e?.message || e}`, 'warn');
        throw e;
    }


    // 4. ONLY if broadcast succeeds, persist the new wallet state.
    const persisted = await pluribit.wallet_session_export(from);
    await db.saveWallet(from, persisted);

    // 5. Notify the UI of success.
    const excessHex = result.transaction.kernels[0].excess.map(b => b.toString(16).padStart(2, '0')).join('');
    log(`Transaction created and broadcast. Hash: ${excessHex.substring(0,16)}...`, 'success');

    const newBalance = await pluribit.wallet_session_get_balance(from);
    parentPort.postMessage({ type: 'walletBalance', payload: { wallet_id: from, balance: newBalance }});
  } catch (e) {
    const msg = e?.stack || e?.message || String(e);
    log(`Transaction failed: ${msg}`, 'error');
    // RATIONALE: If any step failed, revert the in-memory wallet session
    // to its state before this transaction was attempted.
    log(`Reverting wallet state for '${from}'...`, 'warn');
    await pluribit.wallet_session_open(from, originalWalletState);
    parentPort.postMessage({ type: 'error', error: `Transaction failed: ${msg}` });
  } finally {
     release();
   }
}


if (parentPort) {
    main();
}
