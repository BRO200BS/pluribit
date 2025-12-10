// worker.js
// Polyfill CustomEvent for Node.js (required by libp2p dependencies)
if (typeof globalThis.CustomEvent !== 'function') {
    globalThis.CustomEvent = class CustomEvent extends Event {
        constructor(type, eventInitDict = {}) {
            super(type, eventInitDict);
            this.detail = eventInitDict.detail ?? null;
        }
    };
}

// Polyfill Promise.withResolvers for Node.js < 22
if (typeof Promise.withResolvers !== 'function') {
    Promise.withResolvers = function() {
        let resolve, reject;
        const promise = new Promise((res, rej) => {
            resolve = res;
            reject = rej;
        });
        return { promise, resolve, reject };
    };
}
process.on('uncaughtException', (err) => {
    if (err.message?.includes('maConn')) {
        console.warn('[P2P] Caught known circuit-relay bug, continuing...');
        return;
    }
    console.error('Uncaught exception:', err);
    throw err;
});
// THIN I/O SHIM - All state and logic is in Rust (pluribit_core WASM)
import { parentPort, Worker as ThreadWorker } from 'worker_threads';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { PluribitP2P, TOPICS } from './libp2p-node.js';
import { multiaddr } from '@multiformats/multiaddr';
const require = createRequire(import.meta.url);
const native_db = require('./native/index.node');
const { p2p } = require('./src/p2p_pb.cjs');
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Global references
let p2pNode = null;
let miningWorker = null;
let pluribit = null;
let isShuttingDown = false;

// --- FIX START: Logging Setup ---
const LOG_DIR = path.join(__dirname, 'pluribit-data');
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}
const MINING_LOG_PATH = path.join(LOG_DIR, 'mining.log');

function appendMiningLog(message) {
    const timestamp = new Date().toISOString();
    const logLine = `[${timestamp}] ${message}\n`;
    fs.appendFile(MINING_LOG_PATH, logLine, (err) => {
        if (err) console.error('Failed to write to mining log:', err);
    });
}
// --- FIX END ---

// =============================================================================
// DB BRIDGE FUNCTIONS (Exposed to Rust)
// =============================================================================

global.load_block_from_db = async (height) => {
    const buffer = native_db.load_block_from_db(height);
    return buffer ? new Uint8Array(buffer) : null;
};
global.loadBlockByHash = async (hash) => {
    const buffer = native_db.loadBlockByHash(hash);
    return buffer ? new Uint8Array(buffer) : null;
};
global.saveBlock = async (bytes, isCanon) => native_db.saveBlock(Buffer.from(bytes), isCanon);
global.saveBlockWithHash = async (bytes) => native_db.saveBlockWithHash(Buffer.from(bytes));
global.loadBlocks = async (start, end) => {
    const bufs = native_db.loadBlocks(start, end);
    return bufs ? bufs.map(b => new Uint8Array(b)) : [];
};
global.get_tip_height_from_db = async () => {
    const h = native_db.get_tip_height_from_db();
    return h !== null ? h.toString() : '0';
};
global.save_total_work_to_db = async (w) => native_db.save_total_work_to_db(w);
global.get_total_work_from_db = async () => native_db.get_total_work_from_db();
global.save_utxo = async (k, v) => native_db.save_utxo(k, v);
global.load_utxo = async (k) => {
    return native_db.load_utxo(k);  // Pass through directly
};
global.delete_utxo = async (k) => native_db.delete_utxo(k);
global.clear_all_utxos = async () => native_db.clear_all_utxos();
global.loadAllUtxos = async () => {
    const arr = native_db.loadAllUtxos();
    if (!arr || arr.length === 0) return {};
    
    // Convert [[key, value], ...] to {key: value, ...}
    const result = {};
    for (const [k, v] of arr) {
        result[k] = v;  // k is already a string, v is already a JS object
    }
    return result;
};
global.save_reorg_marker = async (d) => native_db.save_reorg_marker(d);
global.clear_reorg_marker = async () => native_db.clear_reorg_marker();
global.check_incomplete_reorg = async () => native_db.check_incomplete_reorg();
global.save_block_to_staging = async (b) => native_db.save_block_to_staging(Buffer.from(b));
global.commit_staged_reorg = async (blks, hts, tipH, tipHash) => {
    const bufs = blks.map(b => Buffer.from(b));
    return native_db.commit_staged_reorg(bufs, hts, tipH, tipHash);
};
global.save_coinbase_index = async (h, tx) => native_db.save_coinbase_index(h, tx);
global.delete_coinbase_index = async (h) => native_db.delete_coinbase_index(h);
global.loadAllCoinbaseIndexes = async () => native_db.loadAllCoinbaseIndexes();
global.save_block_filter = async (h, f) => native_db.save_block_filter(h, f);
global.load_block_filter_range = async (s, e) => native_db.load_block_filter_range(s, e);
global.delete_block_filter = async (h) => native_db.delete_block_filter(h);
global.load_wallet_from_db = async (id) => native_db.loadWallet(id);
global.save_wallet_to_db = async (id, json) => native_db.saveWallet(id, json);

// Bridge callback
global.postRustCommands = (bytes) => {
    if (bytes && bytes.length > 0) executeRustCommands(new Uint8Array(bytes));
};

// =============================================================================
// COMMAND EXECUTION
// =============================================================================

function executeRustCommands(bytes) {
    let batch;
    try {
        batch = p2p.RustToJs_CommandBatch.decode(bytes);
    } catch (e) {
        console.error('Failed to decode Rust commands:', e);
        return;
    }

    // DEBUG: Log what we received
    //console.log('[DEBUG] Received', batch.commands?.length || 0, 'commands');

    for (const item of batch.commands) {
        // DEBUG: Log each command type
        //console.log('[DEBUG] Command:', item.command, 'Fields:', Object.keys(item).filter(k => item[k] != null));
        
       // const cmd = item.command;
       // if (!cmd) continue;

        if (item.logMessage) {
            parentPort.postMessage({ type: 'log', payload: { level: item.logMessage.level, message: item.logMessage.message } });
        } else if (item.p2pPublish) {
            if (p2pNode) p2pNode.publish(item.p2pPublish.topic, item.p2pPublish.data).catch(console.error);
        } else if (item.p2pSendDirect) {
            if (p2pNode) p2pNode.sendDirect(item.p2pSendDirect.peerId, item.p2pSendDirect.protocol, item.p2pSendDirect.data).catch(console.error);
        } else if (item.p2pHangUp) {
            if (p2pNode) p2pNode.node.hangUp(item.p2pHangUp.peerId).catch(console.error);
        } else if (item.controlMining) {
            handleMiningControl(item.controlMining);
        } else if (item.updateUiBalance) {
            parentPort.postMessage({ 
                type: 'walletBalance', 
                payload: { 
                    wallet_id: item.updateUiBalance.walletId, 
                    balance: item.updateUiBalance.balanceString,
                    address: item.updateUiBalance.address // <--- Add this line
                } 
            });
        } else if (item.updateUiMinerStatus) {
            parentPort.postMessage({ type: 'minerStatus', payload: { active: item.updateUiMinerStatus.isMining } });
        } else if (item.updateUiSyncProgress) {
            parentPort.postMessage({ type: 'syncProgress', payload: { current: item.updateUiSyncProgress.current, target: item.updateUiSyncProgress.target, startTime: item.updateUiSyncProgress.startTime } });
        } else if (item.uiNetworkInitialized) {
            parentPort.postMessage({ type: 'networkInitialized' });
        } else if (item.uiWalletLoaded) {
            parentPort.postMessage({ type: 'walletLoaded', payload: { walletId: item.uiWalletLoaded.walletId, balance: item.uiWalletLoaded.balance, address: item.uiWalletLoaded.address } });
        } else if (item.uiPeerList) {
            parentPort.postMessage({ type: 'peerList', payload: item.uiPeerList.peerIds });
        } else if (item.uiTotalSupply) {
            parentPort.postMessage({ type: 'totalSupply', payload: { supply: item.uiTotalSupply.supplyString } });
        } else if (item.uiSwapProposal) {
             parentPort.postMessage({ type: 'log', payload: { level: 'info', message: `New Swap Proposal from ${item.uiSwapProposal.fromPeer}!` } });
        } else if (item.uiChannelProposal) {
             parentPort.postMessage({ type: 'log', payload: { level: 'info', message: `New Channel Proposal from ${item.uiChannelProposal.fromPeer}!` } });
        } else if (item.dialPeer) {
            const addr = item.dialPeer.multiaddr;
            if (p2pNode) {
                parentPort.postMessage({ type: 'log', payload: { level: 'info', message: `Dialing ${addr}...` } });
                try {
                    // Convert to Multiaddr object
                    const ma = multiaddr(addr); 
                    p2pNode.node.dial(ma)
                        .then(() => parentPort.postMessage({ type: 'log', payload: { level: 'success', message: `Connected to ${addr}` } }))
                        .catch(err => parentPort.postMessage({ type: 'log', payload: { level: 'error', message: `Dial failed: ${err.message}` } }));
                } catch (e) {
                     console.error('Invalid multiaddr from Rust:', addr);
                }
            }
        }
        
    }
}

function handleMiningControl(params) {
    if (params.start) {
        if (!miningWorker) {
            miningWorker = new ThreadWorker(new URL('./mining-worker.js', import.meta.url));
            miningWorker.on('message', (msg) => {
                // FIX: Handle the new message types
                if (msg.type === 'MINING_LOG') {
                    // Write to file, do NOT send to UI
                    appendMiningLog(msg.message);
                } 
                else if (msg.type === 'CANDIDATE_FOUND') {
                    console.log(`[Worker] Submitting candidate for Job ID: ${msg.jobId}`);
                    
                    // Log the win to file as well for history
                    appendMiningLog(`*** CANDIDATE FOUND *** Nonce: ${msg.candidate.nonce}, Job: ${msg.jobId}`);

                    const candidatePayload = {
                        nonce: msg.candidate.nonce.toString(),
                        vrfProof: msg.candidate.vrf_proof,
                        vdfProof: msg.candidate.vdf_proof,
                        height: msg.candidate.height.toString(),
                        prevHash: msg.candidate.prevHash,
                        minerPubkey: msg.candidate.miner_pubkey,
                        vrfThreshold: msg.candidate.vrfThreshold,
                        vdfIterations: msg.candidate.vdfIterations.toString(),
                        jobId: msg.jobId.toString() 
                    };

                    const candidate = p2p.SubmitMiningCandidate.create(candidatePayload);
                    const cmd = p2p.JSToRust_Command.create({ submitCandidate: candidate });
                    const bytes = p2p.JSToRust_Command.encode(cmd).finish();
                    
                    const resp = pluribit.handle_command(bytes);
                    executeRustCommands(new Uint8Array(resp));
                } 
                else if (msg.type === 'STATUS') {
                    // Critical status updates still go to UI (e.g., Start, Stop, Fatal Error)
                    parentPort.postMessage({ type: 'log', payload: { level: 'info', message: msg.message } });
                    // Also log to file for continuity
                    appendMiningLog(`[STATUS] ${msg.message}`);
                }
            });
        }
        miningWorker.postMessage({
            type: 'MINE_BLOCK',
            jobId: Number(params.jobId),
            height: BigInt(params.height),
            minerPubkey: new Uint8Array(params.minerPubkey),
            minerSecretKey: new Uint8Array(params.minerSecretKey),
            prevHash: params.prevHash,
            vrfThreshold: new Uint8Array(params.vrfThreshold),
            vdfIterations: BigInt(params.vdfIterations)
        });
    } else {
        if (miningWorker) miningWorker.postMessage({ type: 'STOP' });
    }
}

async function initializeNetwork() {
    // 1. Get Network Name from Environment (passed from main thread via process.env usually, 
    // or we can grab it from a config. Since this is a worker, we rely on what passed 
    // or defaults). 
    // Note: process.env works in Node worker threads.
    const networkName = process.env.PLURIBIT_NET || 'mainnet';
    const tcpPort = parseInt(process.env.PLURIBIT_TCP_PORT || '26658', 10);
    const wsPort = parseInt(process.env.PLURIBIT_WS_PORT || '26659', 10);
    // 2. Initialize Rust Core FIRST
    const initCmd = p2p.JSToRust_Command.create({ 
        initialize: { network: networkName } 
    });
    const initBytes = p2p.JSToRust_Command.encode(initCmd).finish();
    const initResp = pluribit.handle_command(initBytes);
    executeRustCommands(new Uint8Array(initResp));

    // 3. Initialize P2P
    p2pNode = new PluribitP2P(
        // FIX: Accept 'level' as the second argument
        (msg, level = 'info') => parentPort.postMessage({
            type: 'log', 
            payload: { level: level, message: msg }
        }),
        { 
            tcpPort: tcpPort,
            wsPort: wsPort,
            onPeerVerified: (peerId) => {
                const event = p2p.JSToRust_NetworkEvent.create({ peerVerified: { peerId }});
                const bytes = p2p.JSToRust_NetworkEvent.encode(event).finish();
                executeRustCommands(new Uint8Array(pluribit.handle_network_event(bytes)));
            }
        }
    );
    await p2pNode.initialize();
    if (isShuttingDown) return;
    
    // 4. Send our peer ID to Rust now that P2P is ready
    const ourPeerId = p2pNode.node.peerId.toString();
    const peerIdCmd = p2p.JSToRust_Command.create({ 
        initialize: { network: networkName, ourPeerId: ourPeerId } 
    });
    const peerIdBytes = p2p.JSToRust_Command.encode(peerIdCmd).finish();
    executeRustCommands(new Uint8Array(pluribit.handle_command(peerIdBytes)));
    
    const topics = Object.values(TOPICS);
    for (const topic of topics) {
        if (isShuttingDown) return;
        await p2pNode.subscribe(topic, (data, meta) => {
            const event = p2p.JSToRust_NetworkEvent.create({
                p2pMessage: { topic, data: meta.rawData || data, fromPeerId: meta.from.toString() }
            });
            const bytes = p2p.JSToRust_NetworkEvent.encode(event).finish();
            const resp = pluribit.handle_network_event(bytes);
            executeRustCommands(new Uint8Array(resp));
        });
    }
    
    // Forward peer events
    p2pNode.node.addEventListener('peer:connect', (evt) => {
        const event = p2p.JSToRust_NetworkEvent.create({ peerConnected: { peerId: evt.detail.toString() }});
        const bytes = p2p.JSToRust_NetworkEvent.encode(event).finish();
        executeRustCommands(new Uint8Array(pluribit.handle_network_event(bytes)));
    });
    p2pNode.node.addEventListener('peer:disconnect', (evt) => {
        const event = p2p.JSToRust_NetworkEvent.create({ peerDisconnected: { peerId: evt.detail.toString() }});
        const bytes = p2p.JSToRust_NetworkEvent.encode(event).finish();
        executeRustCommands(new Uint8Array(pluribit.handle_network_event(bytes)));
    });
    
    // Sync peers that connected before listeners were ready ---
    if (p2pNode.node.getConnections) {
        const connections = p2pNode.node.getConnections();
        for (const conn of connections) {
            const peerId = conn.remotePeer.toString();
            
            // Manually trigger the "Peer Connected" event for Rust
            const event = p2p.JSToRust_NetworkEvent.create({ 
                peerConnected: { peerId: peerId }
            });
            const bytes = p2p.JSToRust_NetworkEvent.encode(event).finish();
            
            // Send to Rust immediately
            const resp = pluribit.handle_network_event(bytes);
            executeRustCommands(new Uint8Array(resp));
        }
    }
    
    // Listen for Direct Sync messages from libp2p-node.js
    if (typeof p2pNode.node.addEventListener === 'function') {
        p2pNode.node.addEventListener('pluribit:sync-message', (evt) => {
            const { topic, data, from } = evt.detail;
            
            // We reuse the generic P2pMessageReceived structure for this.
            // Rust will distinguish it based on the topic string (which will be the sync protocol).
            const event = p2p.JSToRust_NetworkEvent.create({
                p2pMessage: { 
                    topic: topic, 
                    data: data, 
                    fromPeerId: from 
                }
            });
            
            const bytes = p2p.JSToRust_NetworkEvent.encode(event).finish();
            
            // Pass to Rust core
            const resp = pluribit.handle_network_event(bytes);
            executeRustCommands(new Uint8Array(resp));
        });
    }


    parentPort.postMessage({ type: 'networkInitialized' });
    
    // Tickers
    setInterval(() => {
        const cmd = p2p.JSToRust_Command.create({ syncTick: {} });
        const bytes = p2p.JSToRust_Command.encode(cmd).finish();
        executeRustCommands(new Uint8Array(pluribit.handle_command(bytes)));
    }, 5000); // Sync tick
    
    setInterval(() => {
        const cmd = p2p.JSToRust_Command.create({ evaluateConsensus: {} });
        const bytes = p2p.JSToRust_Command.encode(cmd).finish();
        executeRustCommands(new Uint8Array(pluribit.handle_command(bytes)));
    }, 2000); // Consensus tick
}

async function main() {
    const wasmPath = path.join(__dirname, './pkg-node/pluribit_core.js');
    const wasm = await import(wasmPath);
    pluribit = wasm;
    
    native_db.initializeDatabase();
    await pluribit.init_blockchain_from_db();
    
    parentPort.on('message', async (event) => {
        const { action, payload, ...rest } = event;
        
        // Special cases for worker-managed IO
        if (action === 'initializeNetwork') {
            await initializeNetwork();
            return;
        }
        if (action === 'shutdown') {
            isShuttingDown = true;
            if(miningWorker) miningWorker.terminate();
            if(p2pNode) await p2pNode.stop();
            process.exit(0);
        }
        if (action === 'connectPeer') {
            if(p2pNode && rest.address) {
                try {
                    // Convert string string to Multiaddr object
                    const ma = multiaddr(rest.address);
                    await p2pNode.node.dial(ma);
                    parentPort.postMessage({ type: 'log', payload: { level: 'success', message: `Manually dialed ${rest.address}` } });
                } catch(e) {
                    parentPort.postMessage({ type: 'log', payload: { level: 'error', message: `Dial failed: ${e.message}` } });
                }
            }
            return;
        }
        
        // NEW: Handle raw protobuf commands from main.js
        if (action === 'handle_command' && payload) {
          //  console.log('[DEBUG] handle_command received, payload length:', payload.length);
            try {
                const response = pluribit.handle_command(payload);
                if (response && response.length > 0) {
                    executeRustCommands(new Uint8Array(response));
                }
            } catch (err) {
                console.error('[DEBUG] handle_command error:', err);
            }
            return;
        }
        
        // Everything else goes to Rust
        let cmdObj;
        // FIX: Match the action names that main.js actually sends
        if (action === 'createWallet' || action === 'createWalletWithMnemonic') {
            cmdObj = { createWallet: { walletId: rest.walletId } };
        }
        else if (action === 'restoreWallet' || action === 'restoreWalletFromMnemonic') {
            cmdObj = { restoreWallet: { walletId: rest.walletId, phrase: rest.phrase } };
        }
        else if (action === 'channelOpen') {
            cmdObj = { 
                channelOpen: { 
                    walletId: rest.walletId, 
                    counterpartyPubkey: rest.counterpartyPubkey,
                    myAmount: BigInt(rest.myAmount),
                    theirAmount: BigInt(rest.theirAmount)
                } 
            };
        }
        else if (action === 'channelList') cmdObj = { channelList: {} };
        else if (action === 'channelAccept') {
            cmdObj = { 
                channelAccept: { 
                    walletId: rest.walletId, 
                    proposalId: rest.proposalId 
                } 
            };
        }
        else if (action === 'channelFund') {
            cmdObj = { 
                channelFund: { 
                    walletId: rest.walletId, 
                    channelId: rest.channelId 
                } 
            };
        }
        else if (action === 'channelPay') {
            cmdObj = { 
                channelPay: { 
                    walletId: rest.walletId, 
                    channelId: rest.channelId,
                    amount: BigInt(rest.amount)
                } 
            };
        }
        else if (action === 'channelClose') {
            cmdObj = { 
                channelClose: { 
                    walletId: rest.walletId, 
                    channelId: rest.channelId 
                } 
            };
        }
        else if (action === 'loadWallet') cmdObj = { loadWallet: { walletId: rest.walletId } };
        else if (action === 'getBalance') cmdObj = { getBalance: { walletId: rest.walletId } };
        else if (action === 'createTransaction') {
                    cmdObj = { 
                        createTransaction: { 
                            fromWalletId: rest.from, 
                            toAddress: rest.to, 
                            // Convert to String to ensure safe Protobuf uint64 parsing
                            // (Protobuf.js accepts strings for longs universally)
                            amount: rest.amount.toString(), 
                            fee: rest.fee.toString() 
                        } 
                    };
                }
        else if (action === 'setMinerActive') cmdObj = { toggleMiner: { minerId: rest.minerId } };
        else if (action === 'status' || action === 'getMiningParams') cmdObj = { getStatus: {} };
        else if (action === 'supply' || action === 'getSupply') cmdObj = { getSupply: {} };
        else if (action === 'swap_initiate' || action === 'swapInitiate') {
            cmdObj = { swapInitiate: { walletId: rest.walletId, counterpartyPubkey: rest.counterpartyPubkey, plbAmount: BigInt(rest.plbAmount), btcAmount: BigInt(rest.btcAmount), timeoutBlocks: BigInt(rest.timeoutBlocks) } };
        }
        else if (action === 'swap_list' || action === 'swapList') cmdObj = { swapList: {} };
        else if (action === 'getPeers') cmdObj = { getPeers: {} };
        else if (action === 'verifySupply') {
            cmdObj = { verifySupply: {} }; // Now maps to its own command
        }
        else if (action === 'auditDetailed') {
            cmdObj = { auditDetailed: {} }; // Now maps to its own command
        }
        else if (action === 'inspectBlock') {
            cmdObj = { inspectBlock: { height: rest.height.toString() } };
        }
        else if (action === 'purgeSideBlocks') {
            cmdObj = { purgeSideBlocks: {} };
        }
        else if (action === 'clearSideBlocks') {
            cmdObj = { clearSideBlocks: {} };
        }
        else if (action === 'retrySync') {
             cmdObj = { syncTick: {} };
        }
        if (cmdObj) {
           // console.log('[DEBUG] Sending command to Rust:', Object.keys(cmdObj)[0]);
            const cmd = p2p.JSToRust_Command.create(cmdObj);
            const bytes = p2p.JSToRust_Command.encode(cmd).finish();
            try {
                const response = pluribit.handle_command(bytes);
              //  console.log('[DEBUG] Rust response length:', response?.length);
                if (response && response.length > 0) {
                    executeRustCommands(new Uint8Array(response));
                }
            } catch (err) {
                console.error('[DEBUG] handle_command error:', err);
            }
        } else {
            console.log('[DEBUG] Unknown action:', action);
        }
    });
}

main();
