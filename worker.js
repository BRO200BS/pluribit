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

import { parentPort, Worker } from 'worker_threads';
import { Worker as ThreadWorker } from 'worker_threads';

import path from 'path';
import { fileURLToPath } from 'url';
import { base64ToArrayBuffer } from './utils.js'; 
import { multiaddr } from '@multiformats/multiaddr';


// --- MODULE IMPORTS ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const wasmPath = path.join(__dirname, './pkg-node/pluribit_core.js');
const { default: _, ...pluribit } = await import(wasmPath);
import { PluribitP2P, TOPICS } from './libp2p-node.js';
import * as db from './db.js';

// --- MUTEX FOR RESOURCE LOCKING ---
let isLocked = false;
const acquireLock = async () => {
    while (isLocked) {
        await new Promise(resolve => setTimeout(resolve, 10));
    }
    isLocked = true;
};
const releaseLock = () => {
    isLocked = false;
};

// --- REORG STATE ---
const reorgState = {
    pendingForks: new Map(),
    requestedBlocks: new Set(),
};

// --- WORKER STATE (simplified) ---
export const workerState = {
    initialized: false,
    minerActive: false,
    minerId: null,
    p2p: null,
    wallets: new Map(),
    miningWorker: null, 
};

// --- LOGGING ---
function log(message, level = 'info') {
    if (parentPort) {
        parentPort.postMessage({ type: 'log', payload: { message, level } });
    } else {
        console.log(`[WORKER LOG - ${level.toUpperCase()}]: ${message}`);
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
                case 'initWallet': await handleInitWallet(params); break;
                case 'loadWallet': await handleLoadWallet(params); break;
                case 'createTransaction': await handleCreateTransaction(params); break;
                case 'setMinerActive':
                    workerState.minerActive = params.active;
                    workerState.minerId = params.active ? params.minerId : null;
                    log(`PoWrPoST Miner ${params.active ? `activated for ${params.minerId}` : 'deactivated'}.`);
                    parentPort.postMessage({ type: 'minerStatus', payload: { active: params.active } });
                    
                    if (workerState.minerActive) {
                        startPoSTMining();
                    } else if (workerState.miningWorker) {
                        // Stop mining worker
                        workerState.miningWorker.terminate();
                        workerState.miningWorker = null;
                    }
                    break;
                case 'getBalance':
                    try {
                        const walletJson = workerState.wallets.get(params.walletId);
                        if (!walletJson) throw new Error("Wallet not loaded");
                        const balance = await pluribit.wallet_get_balance(walletJson);
                        parentPort.postMessage({ type: 'walletBalance', payload: { wallet_id: params.walletId, balance: balance }});
                    } catch(e) {
                        log(`Could not get balance: ${e}`, 'error');
                    }
                    break;
                case 'getMiningParams':
                    try {
                        const params = await pluribit.get_current_mining_params();
                        log(`[STATUS] Height: ${params.current_height}, Work: ${params.total_work}, PoW Diff: ${params.pow_difficulty}, VDF Iters: ${params.vdf_iterations}`);
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
                            const addr = multiaddr(params.address);
                            await workerState.p2p.node.dial(addr);
                            log(`Manually connected to ${params.address}`, 'success');
                        } catch (e) {
                            log(`Failed to connect: ${e.message}`, 'error');
                        }
                    }
                    break;
            }
        } catch (error) {
            log(`Error handling action '${action}': ${error.message}`, 'error');
            parentPort.postMessage({ type: 'error', error: error.message });
        }
    });
}

//  Mining Loop
async function startPoSTMining() {
    if (!workerState.minerActive || !workerState.minerId) {
        log('Mining stopped.');
        return;
    }

    const minerWalletJson = workerState.wallets.get(workerState.minerId);
    if (!minerWalletJson) {
        log('Miner wallet not loaded, stopping.', 'error');
        return;
    }
    
    const walletData = JSON.parse(minerWalletJson);
    const minerSecretKey = new Uint8Array(Object.values(walletData.spend_priv));
    const minerScanPubkey = new Uint8Array(Object.values(walletData.scan_pub));

    // Create mining worker
    const miningWorkerPath = path.join(__dirname, 'mining-worker.js');
    workerState.miningWorker = new ThreadWorker(miningWorkerPath);
    
    workerState.miningWorker.on('message', async (msg) => {
        if (msg.type === 'BLOCK_MINED') {
            const txCount = msg.block.transactions.length - 1; // Subtract coinbase
            log(`[MINING] Block #${msg.block.height} MINED! Including ${txCount} transactions.`, 'success');
            
            try {
                // Process the block
                await handleRemoteBlockDownloaded({ block: msg.block });
                
                // Broadcast to network
                await workerState.p2p.publish(TOPICS.BLOCKS, {
                    type: 'NEW_BLOCK',
                    payload: msg.block
                });
                
                // Continue mining next block
                setTimeout(() => startNextMiningJob(), 1000);
            } catch (e) {
                log(`Error processing mined block: ${e.message}`, 'error');
                setTimeout(() => startNextMiningJob(), 5000);
            }
        } else if (msg.type === 'STATUS') {
            log(`[MINING] ${msg.message}`);
        }
    });

    workerState.miningWorker.on('error', (err) => {
        log(`Mining worker error: ${err.message}`, 'error');
    });

    workerState.miningWorker.on('exit', (code) => {
        if (code !== 0 && workerState.minerActive) {
            log(`Mining worker crashed, restarting...`, 'error');
            setTimeout(() => startPoSTMining(), 1000);
        }
    });

    // Start mining
    startNextMiningJob();
}

async function startNextMiningJob() {
    if (!workerState.minerActive || !workerState.miningWorker) return;
    
    try {
        const chainState = await pluribit.get_blockchain_state();
        const chain = typeof chainState === 'string' ? JSON.parse(chainState) : chainState;
        const height = Number(chain.current_height) + 1;
        const prevHash = await pluribit.get_latest_block_hash();
        
        const minerWalletJson = workerState.wallets.get(workerState.minerId);
        const walletData = JSON.parse(minerWalletJson);
        
        workerState.miningWorker.postMessage({
            type: 'MINE_BLOCK',
            height,
            minerSecretKey: Array.from(new Uint8Array(Object.values(walletData.spend_priv))),
            minerScanPubkey: Array.from(new Uint8Array(Object.values(walletData.scan_pub))),
            prevHash,
            powDifficulty: chain.current_pow_difficulty,
            vrfThreshold: Array.from(chain.current_vrf_threshold),
            vdfIterations: chain.current_vdf_iterations
        });
        
        log(`[MINING] Started mining block #${height}`);
    } catch (e) {
        log(`Error starting mining job: ${e.message}`, 'error');
        setTimeout(() => startNextMiningJob(), 5000);
    }
}

async function handleRemoteBlockDownloaded({ block }) {
    try {
        await acquireLock();
        // Special handling for genesis block
        if (block.height === 0) {
            log(`Ignoring genesis block broadcast`);
            releaseLock();
            return;
        }

        // --- START: NEW FORK RESOLUTION LOGIC ---
        // Check if this block was requested to resolve a fork.
        if (reorgState.requestedBlocks.has(block.hash)) {
            log(`Received requested block #${block.height} for fork resolution.`, 'info');

            // Add the block to our map of pending fork blocks.
            if (!reorgState.pendingForks.has(block.height)) {
                reorgState.pendingForks.set(block.height, new Map());
            }
            reorgState.pendingForks.get(block.height).set(block.hash, block);

            // Mark the block as received.
            reorgState.requestedBlocks.delete(block.hash);

            // Now that we have the missing piece, find any fork that was waiting for
            // this block and try to continue building its chain history.
            let waitingForkTip = null;
            for (const forksAtHeight of reorgState.pendingForks.values()) {
                for (const forkBlock of forksAtHeight.values()) {
                    if (forkBlock.prev_hash === block.hash) {
                        waitingForkTip = forkBlock;
                        break;
                    }
                }
                if (waitingForkTip) break;
            }
            
            if (waitingForkTip) {
                log(`Continuing fork resolution for tip ${waitingForkTip.hash.substring(0,12)}...`, 'info');
                await requestForkChain(waitingForkTip);
            }

            // End processing for this block here since it's part of a reorg.
            releaseLock();
            return;
        }
        // --- END: NEW FORK RESOLUTION LOGIC ---

        // Get the blockchain state and handle it properly
        const chainStateRaw = await pluribit.get_blockchain_state();
        
        // Parse the chain state if it's a string or ensure it has the right structure
        let chainState;
        try {
            if (typeof chainStateRaw === 'string') {
                chainState = JSON.parse(chainStateRaw);
            } else if (chainStateRaw && typeof chainStateRaw === 'object') {
                // It might be a JsValue that needs to be converted
                chainState = chainStateRaw;
            } else {
                throw new Error('Invalid chain state format');
            }
        } catch (parseError) {
            log(`Failed to parse chain state: ${parseError.message}`, 'error');
            releaseLock();
            return;
        }

        // Validate the chain state structure
        if (!chainState || !chainState.blocks || !Array.isArray(chainState.blocks) || chainState.blocks.length === 0) {
            log('Invalid or empty blockchain state', 'error');
            releaseLock();
            return;
        }

        const currentTip = chainState.blocks[chainState.blocks.length - 1];

        // Check if we already have this block
        const existingBlock = await pluribit.get_block_by_hash(block.hash);
        if (existingBlock) {
            log(`Already have block #${block.height}, ignoring duplicate`);
            releaseLock();
            return;
        }

        const isFork = block.height > 0 && block.prev_hash !== currentTip.hash;
        const isNextBlock = block.prev_hash === currentTip.hash && block.height === currentTip.height + 1;

        if (isFork) {
            await handlePotentialReorg(block);
        } else if (isNextBlock) {
            log(`Processing block #${block.height} from network.`);
            await pluribit.add_block_to_chain(block);

            await db.saveBlock(block);

            const newChainStateRaw = await pluribit.get_blockchain_state();
            let newChainState;
            try {
                if (typeof newChainStateRaw === 'string') {
                    newChainState = JSON.parse(newChainStateRaw);
                } else {
                    newChainState = newChainStateRaw;
                }
            } catch (e) {
                newChainState = { current_height: block.height }; // Fallback
            }
            
            log(`Block #${block.height} added to chain. New height: ${newChainState.current_height}`, 'success');

            // Rescan wallets with the new block
            for (const [walletId, walletJson] of workerState.wallets.entries()) {
                try {
                    const updatedWalletJson = await pluribit.wallet_scan_block(walletJson, block);
                    if (updatedWalletJson !== walletJson) {
                        workerState.wallets.set(walletId, updatedWalletJson);
                        const updatedWalletData = JSON.parse(updatedWalletJson);
                        await db.saveWallet(walletId, updatedWalletData); // Add this line to persist
                        
                        const newBalance = await pluribit.wallet_get_balance(updatedWalletJson);
                        log(`Wallet ${walletId} balance updated to: ${newBalance}`);
                        parentPort.postMessage({ type: 'walletBalance', payload: { wallet_id: walletId, balance: newBalance }});
                    }
                } catch (e) {
                    log(`Failed to scan block for wallet ${walletId}: ${e.message}`, 'error');
                }
            }
        } else {
            // Added more specific logging for ignored blocks
            if (block.height <= currentTip.height && block.height > 0) {
                 log(`Ignoring stale block #${block.height} (our height is ${currentTip.height}).`, 'warn');
            } else if (block.height > 0) {
                 log(`Ignoring block #${block.height} as it is not the next block and not a fork. Our tip is #${currentTip.height}.`, 'warn');
            }
        }
    } catch (e) {
        log(`Failed to process downloaded block: ${e.message}`, 'error');
        console.error(e); // Add stack trace for debugging
    } finally {
        releaseLock();
    }
}

async function handlePotentialReorg(newBlock) {
    try {
        const chainStateRaw = await pluribit.get_blockchain_state();
        let chainState;
        
        if (typeof chainStateRaw === 'string') {
            chainState = JSON.parse(chainStateRaw);
        } else {
            chainState = chainStateRaw;
        }
        
        if (!chainState || typeof chainState.current_height === 'undefined') {
            log('Invalid chain state during reorg handling', 'error');
            return;
        }
        
        log(`Fork detected at height ${newBlock.height}. Our height: ${chainState.current_height}.`, 'warn');

        if (!reorgState.pendingForks.has(newBlock.height)) {
            reorgState.pendingForks.set(newBlock.height, new Map());
        }
        reorgState.pendingForks.get(newBlock.height).set(newBlock.hash, newBlock);

        await requestForkChain(newBlock);
    } catch (e) {
        log(`Error in handlePotentialReorg: ${e.message}`, 'error');
    }
}

async function requestForkChain(tipBlock) {
    let currentBlock = tipBlock;
    const chainState = await pluribit.get_blockchain_state();

    while (currentBlock.height > 0) {
        if (currentBlock.height <= chainState.current_height) {
            const ourBlock = chainState.blocks[currentBlock.height];
            if (ourBlock && ourBlock.hash === currentBlock.hash) {
                log(`Found common ancestor at height ${currentBlock.height}`, 'info');
                await evaluateFork(currentBlock.height, tipBlock);
                return;
            }
        }

        if (!reorgState.requestedBlocks.has(currentBlock.prev_hash)) {
            reorgState.requestedBlocks.add(currentBlock.prev_hash);
            log(`Requesting parent block ${currentBlock.prev_hash.substring(0, 16)}...`);
            await workerState.p2p.publish(TOPICS.BLOCK_REQUEST, {
                type: 'BLOCK_REQUEST',
                hash: currentBlock.prev_hash,
            });
            return;
        }

        const parentBlocks = reorgState.pendingForks.get(currentBlock.height - 1);
        if (parentBlocks && parentBlocks.has(currentBlock.prev_hash)) {
            currentBlock = parentBlocks.get(currentBlock.prev_hash);
        } else {
            log(`Fork chain is incomplete, missing parent for block at height ${currentBlock.height}.`, 'warn');
            return;
        }
    }
}

async function evaluateFork(commonAncestorHeight, forkTip) {
    try {
        const chainState = await pluribit.get_blockchain_state();
        const forkChain = [];
        let currentBlock = forkTip;

        while (currentBlock.height > commonAncestorHeight) {
            forkChain.unshift(currentBlock);
            const parentBlocks = reorgState.pendingForks.get(currentBlock.height - 1);
            if (!parentBlocks || !parentBlocks.has(currentBlock.prev_hash)) {
                log(`Fork chain incomplete, missing block at height ${currentBlock.height - 1}`, 'error');
                return;
            }
            currentBlock = parentBlocks.get(currentBlock.prev_hash);
        }

        const ourChainSegment = chainState.blocks.slice(commonAncestorHeight + 1);
        const ourWork = await pluribit.get_chain_work(ourChainSegment);
        const forkWork = await pluribit.get_chain_work(forkChain);

        log(`Chain work comparison - Our chain: ${ourWork}, Fork: ${forkWork}`, 'info');

        if (forkWork > ourWork) {
            log(`Fork has more work. Initiating reorganization...`, 'warn');
            await performReorganization(commonAncestorHeight, forkChain);
        } else {
            log(`Our chain has more or equal work. Keeping current chain.`, 'info');
            cleanupForkCache(commonAncestorHeight);
        }
    } catch (e) {
        log(`Error evaluating fork: ${e}`, 'error');
    }
}

async function performReorganization(commonAncestorHeight, newChain) {
    try {
        log(`Reorganizing from height ${commonAncestorHeight}...`);
        const chainState = await pluribit.get_blockchain_state();
        
        for (let height = chainState.current_height; height > commonAncestorHeight; height--) {
            const blockToRewind = chainState.blocks[height];
            await pluribit.rewind_block(blockToRewind);
            for (const [walletId, walletJson] of workerState.wallets.entries()) {
                const updatedWallet = await pluribit.wallet_unscan_block(walletJson, blockToRewind);
                workerState.wallets.set(walletId, updatedWallet);
            }
        }

        for (const block of newChain) {
            await pluribit.add_block_to_chain(block);
            await db.saveBlock(block);
            for (const [walletId, walletJson] of workerState.wallets.entries()) {
                const updatedWallet = await pluribit.wallet_scan_block(walletJson, block);
                workerState.wallets.set(walletId, updatedWallet);
            }
        }
        
        for (const [walletId] of workerState.wallets.entries()) {
            await handleLoadWallet({ walletId });
        }

        const newTip = newChain[newChain.length - 1];
        log(`Reorganization complete. New tip at height ${newTip.height}`, 'success');
        cleanupForkCache(newTip.height);

    } catch (e) {
        log(`Critical error during reorganization: ${e}`, 'error');
    }
}

function cleanupForkCache(keepAboveHeight) {
    for (const height of reorgState.pendingForks.keys()) {
        if (height <= keepAboveHeight) {
            reorgState.pendingForks.delete(height);
        }
    }
    reorgState.requestedBlocks.clear();
}

// SIMPLIFIED Network Initialization
async function initializeNetwork() {
    log('Initializing PoWrPoST network...');

    // --- START: Genesis Hash Verification ---
    // DO NOT CHANGE!
    const CANONICAL_GENESIS_HASH = "dc9cbb5eff2c08015f48762c884167334c57d5fac989cdff8f903618ce5552f1";

    // STEP 2: Get the hash from the Wasm module.
    const generatedHash = await pluribit.get_genesis_block_hash();
    // STEP 3: Compare and exit if they don't match.
    if (generatedHash !== CANONICAL_GENESIS_HASH) {
        const errorMsg = `CRITICAL: Genesis hash mismatch! Expected ${CANONICAL_GENESIS_HASH}, but got ${generatedHash}. Exiting to prevent network fork.`;
        log(errorMsg, 'error');
        // A critical error like this should stop the worker immediately.
        return process.exit(1);
    }
    log('Genesis block hash verified successfully.', 'success');
    // --- END: Genesis Hash Verification ---

    const blocks = await db.getAllBlocks();
    if (blocks.length > 0) {
        blocks.sort((a, b) => a.height - b.height);
        await pluribit.init_blockchain();
        for (let i = 1; i < blocks.length; i++) {
            await pluribit.add_block_to_chain(blocks[i]);
        }
        log(`Restored blockchain to height ${blocks[blocks.length - 1].height}`, 'success');
    } else {
        log('Creating new genesis block.', 'info');
        await pluribit.init_blockchain();
        const chainState = await pluribit.get_blockchain_state();
        if (chainState.blocks && chainState.blocks.length > 0) {
            await db.saveBlock(chainState.blocks[0]);
        }
    }
    
    log('Initializing P2P stack...');
    const tcpPort = process.env.TCP_PORT || 26660;
    const wsPort = process.env.WS_PORT || 26661;

    log(`Attempting to start P2P node on TCP:${tcpPort} and WS:${wsPort}`);

    workerState.p2p = new PluribitP2P(log, { 
      tcpPort: parseInt(tcpPort), 
      wsPort: parseInt(wsPort) 
    });

    await workerState.p2p.initialize();

    await setupMessageHandlers();

    log('P2P stack online.', 'success');
    parentPort.postMessage({ type: 'networkInitialized' });
    log('Network initialization complete.', 'success');
}


async function setupMessageHandlers() {
    const { p2p } = workerState;
    
    await p2p.subscribe(TOPICS.TRANSACTIONS, async (message) => {
        if (message.payload) {
            try {
                log(`Received transaction from network`);
                
                // The object is already in the correct format after JSONParseWithBigInt.
                // Pass it directly to the Wasm function.
                await pluribit.add_transaction_to_pool(message.payload);
                
                log(`Added network transaction to pool.`);
            } catch (e) {
                log(`Failed to add network transaction: ${e}`, 'warn');
            }
        }
    });
    
    await p2p.subscribe(TOPICS.BLOCKS, async (message) => {
        if (message.payload) {
            handleRemoteBlockDownloaded({ block: message.payload });
        }
    });
    
    await p2p.subscribe(TOPICS.BLOCK_REQUEST, async (message) => {
        if (message.hash) {
            // First try to get from Rust
            const block = await pluribit.get_block_by_hash(message.hash);
            if (block) {
                await p2p.publish(TOPICS.BLOCKS, {
                    type: 'BLOCK_RESPONSE',
                    payload: block,
                    requestId: message.requestId
                });
            } else {
                // If not found, check if it's genesis
                const chainState = await pluribit.get_blockchain_state();
                if (chainState.blocks.length > 0 && chainState.blocks[0].hash === message.hash) {
                    await p2p.publish(TOPICS.BLOCKS, {
                        type: 'BLOCK_RESPONSE',
                        payload: chainState.blocks[0],
                        requestId: message.requestId
                    });
                }
            }
        }
    });
}



async function handleInitWallet({ walletId }) {
    if (!walletId) return log('Wallet ID cannot be empty.', 'error');
    if (await db.walletExists(walletId)) {
        return log(`Wallet '${walletId}' already exists. Use 'load'.`, 'error');
    }
    const walletJson = await pluribit.wallet_create();
    const walletData = JSON.parse(walletJson);
    await db.saveWallet(walletId, walletData);
    workerState.wallets.set(walletId, walletJson);
    log(`New wallet '${walletId}' created and saved.`, 'success');
    await handleLoadWallet({ walletId });
}

async function handleLoadWallet({ walletId }) {
    const walletData = await db.loadWallet(walletId);
    if (!walletData) {
        return log(`Wallet '${walletId}' not found.`, 'error');
    }

    let walletJson = JSON.stringify(walletData);

    log(`Scanning blockchain for wallet '${walletId}'...`, 'info');
    const allBlocks = await db.getAllBlocks();
    for (const block of allBlocks) {
        walletJson = await pluribit.wallet_scan_block(walletJson, block);
    }

    const updatedWalletData = JSON.parse(walletJson);
    await db.saveWallet(walletId, updatedWalletData);
    
    workerState.wallets.set(walletId, walletJson);
    const balance = await pluribit.wallet_get_balance(walletJson);
    const address = await pluribit.wallet_get_stealth_address(walletJson);
    
    parentPort.postMessage({
        type: 'walletLoaded',
        payload: { walletId, balance, address }
    });
}

async function handleCreateTransaction({ from, to, amount, fee }) {
    const fromWalletJson = workerState.wallets.get(from);
    if (!fromWalletJson) return log(`Sender wallet '${from}' is not loaded.`, 'error');
    try {
        await acquireLock();
        const result = await pluribit.create_transaction_to_stealth_address(
            fromWalletJson, BigInt(amount), BigInt(fee), to
        );
        const updatedWalletData = JSON.parse(result.updated_wallet_json);
        await db.saveWallet(from, updatedWalletData);
        workerState.wallets.set(from, result.updated_wallet_json);
        
        if (workerState.p2p) {
            await workerState.p2p.publish(TOPICS.TRANSACTIONS, {
                type: 'new_transaction',
                payload: result.transaction
            });
        }
        
        // Convert the excess bytes to hex before trying to substring
        const excessHex = result.transaction.kernel.excess.map(b => 
            b.toString(16).padStart(2, '0')
        ).join('');
        log(`Transaction created. Hash: ${excessHex.substring(0,16)}...`, 'success');
        
        const newBalance = await pluribit.wallet_get_balance(result.updated_wallet_json);
        parentPort.postMessage({ type: 'walletBalance', payload: { wallet_id: from, balance: newBalance }});
    } catch (e) {
        log(`Transaction failed: ${e}`, 'error');
    } finally {
        releaseLock();
    }
}

if (parentPort) {
    main();
}
