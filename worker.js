// worker.js - Pluribit Node.js Worker

import { parentPort, Worker } from 'worker_threads';
import path from 'path';
import { fileURLToPath } from 'url';

// --- MODULE IMPORTS ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const wasmPath = path.join(__dirname, './pkg-node/pluribit_core.js');
const { default: _, ...pluribit } = await import(wasmPath);

import PluribitP2P, { setLockFunctions } from './p2p.js';
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

const reorgState = {
    pendingForks: new Map(), // height -> Map(hash -> block)
    requestedBlocks: new Set(), // hashes we've requested
};

setLockFunctions(acquireLock, rel); 
function rel() { releaseLock(); } 


// --- STATE ---
export const workerState = {
    initialized: false,
    minerActive: false,
    minerId: null,
    currentlyMining: false,
    consensusPhase: null,
    validatorActive: false,
    validatorId: null,
    p2p: null,
    wallets: new Map(),
};

const validationState = {
    commitmentSent: false,
    reconciled: false,
    selectedBlock: null,
    vdfStarted: false,
    voted: false,
    candidateBlocks: [],
};

// --- CONSTANTS ---
const BOOTSTRAP_BLOCKS = 2; // Should match src/constants.rs
const TICKS_PER_CYCLE = 120;
const MINING_PHASE_END_TICK = 60;
const VALIDATION_PHASE_END_TICK = 90;
const COMMITMENT_END_TICK = 10;
const RECONCILIATION_END_TICK = 20;

// --- LOGGING ---
function log(message, level = 'info') {
    // Gracefully handle cases where parentPort is not available (like during test setup)
    if (parentPort) {
        parentPort.postMessage({ type: 'log', payload: { message, level } });
    } else {
        console.log(`[WORKER LOG - ${level.toUpperCase()}]: ${message}`);
    }
}

// --- MAIN EXECUTION WRAPPER ---
export async function main() {
    log('Worker starting initialization...');
    log('WASM initialized successfully.', 'success');
    workerState.initialized = true;
    parentPort.postMessage({ type: 'workerReady' });

    // --- MESSAGE HANDLING ---
    parentPort.on('message', async (event) => {
        if (!workerState.initialized) {
            log('Worker not yet initialized.', 'error');
            return;
        }
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
                    log(`Miner ${params.active ? `activated for ${params.minerId}` : 'deactivated'}.`, 'info');
                    parentPort.postMessage({ type: 'minerStatus', payload: { active: params.active } });
                    break;
                case 'createStake':
                    await handleCreateStake(params);
                    break;
                case 'activateStake':
                    await handleActivateStake(params);
                    break;
                case 'getValidators':
                    try {
                        const validators = await pluribit.get_validators();
                        log('Current Active Validators:', 'success');
                        console.table(validators); // Using console.table for nice formatting
                    } catch (e) {
                        log(`Could not get validators: ${e}`, 'error');
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
                case 'setValidatorActive':
                    workerState.validatorActive = params.active;
                    workerState.validatorId = params.active ? params.validatorId : null;
                    log(`Validator mode ${params.active ? `activated for ${params.validatorId}` : 'deactivated'}.`, 'info');
                    parentPort.postMessage({ type: 'validatorStatus', payload: { active: params.active } });
                    break;
            }
        } catch (error) {
            log(`Error handling action '${action}': ${error.message}`, 'error');
            parentPort.postMessage({ type: 'error', error: error.message });
        }
    });
}


// --- CORE FUNCTIONS ---
async function initializeNetwork() {
    log('Initializing network...');
    
    // Load all blocks from database
    const blocks = await db.getAllBlocks();
    
    if (blocks.length > 0) {
        log(`Loading ${blocks.length} blocks from database...`, 'success');
        
        // Sort blocks by height to ensure correct order
        blocks.sort((a, b) => a.height - b.height);
        
        // Recreate the blockchain state
        await pluribit.init_blockchain();
        
        // Add each block (skip genesis as it's already there)
        for (let i = 1; i < blocks.length; i++) {
            await pluribit.add_block_to_chain(blocks[i]);
        }
        
        log(`Restored blockchain to height ${blocks[blocks.length - 1].height}`, 'success');
    } else {
        log('No existing blockchain found. Creating new genesis block.', 'info');
        await pluribit.init_blockchain();
        
        // Save genesis block
        const chainState = await pluribit.get_blockchain_state();
        if (chainState.blocks && chainState.blocks.length > 0) {
            await db.saveBlock(chainState.blocks[0]);
        }
    }
    
    // --- START FIX: LOAD AND RESTORE VALIDATOR STATE ---
    log('Loading validator state from database...', 'info');
    try {
        const savedValidators = await db.loadValidators();
        if (savedValidators && savedValidators.length > 0) {
            await pluribit.restore_validators_from_persistence(savedValidators);
            log(`Restored ${savedValidators.length} active validators.`, 'success');
        } else {
            log('No saved validators found. Starting with empty validator set.', 'info');
        }
    } catch (error) {
        log(`Failed to load validator state: ${error.message}`, 'error');
    }
    // --- END FIX ---
    
    await pluribit.calibrateVDF();
    await pluribit.init_vdf_clock(BigInt(TICKS_PER_CYCLE));

    workerState.p2p = new PluribitP2P(log);
    workerState.p2p.onMessage('CANDIDATE', handleRemoteCandidate);
    workerState.p2p.onMessage('CANDIDATE_COMMITMENT', handleRemoteCommitment);
    workerState.p2p.onMessage('VOTE', handleRemoteVote);    
    workerState.p2p.onMessage('BLOCK_ANNOUNCEMENT', handleRemoteBlockAnnouncement);
    workerState.p2p.onMessage('BLOCK_DOWNLOADED', handleRemoteBlockDownloaded);
    workerState.p2p.onMessage('BLOCK_REQUEST', handleBlockRequest);
    workerState.p2p.onMessage('BLOCK_RESPONSE', handleBlockResponse);    
    workerState.p2p.onMessage('TRANSACTION', handleRemoteTransaction);
       
    await workerState.p2p.start();
    log('P2P Network Started.', 'success');

    setInterval(handleConsensusTick, 1000);
    setInterval(handleVDFTick, 1000);

    parentPort.postMessage({ type: 'networkInitialized' });
    log('Network initialization complete.', 'success');
}

// Add helper function to save validator state whenever it changes
async function saveValidatorState() {
    try {
        const validators = await pluribit.get_validators_for_persistence();
        await db.saveValidators(validators);
        log('Validator state saved to database.', 'info');
    } catch (error) {
        log(`Failed to save validator state: ${error.message}`, 'error');
    }
}

async function handleRemoteTransaction({ tx }) {
    try {
        await acquireLock();
        
        // Add transaction to mempool
        const txJson = serde_wasm_bindgen.to_value(tx);
        await pluribit.add_transaction_to_pool(txJson);
        
        log(`Received transaction from network. Hash: ${tx.kernel.excess.substring(0,16)}...`, 'info');
    } catch (e) {
        log(`Failed to add remote transaction: ${e}`, 'warn');
    } finally {
        releaseLock();
    }
}

function resetValidationState() {
    validationState.commitmentSent = false;
    validationState.reconciled = false;
    validationState.selectedBlock = null;
    validationState.vdfStarted = false;
    validationState.voted = false;
    validationState.candidateBlocks = [];
}

async function handleConsensusTick() {
    try {
        await acquireLock();
        const vdfClockState = await pluribit.get_vdf_clock_state();
        const currentTick = Number(vdfClockState.current_tick);
        const tickInCycle = currentTick % TICKS_PER_CYCLE;
        let currentPhase;

        if (tickInCycle < MINING_PHASE_END_TICK) {
            currentPhase = 'Mining';
            if (workerState.consensusPhase !== 'Mining') resetValidationState();
        } else if (tickInCycle < VALIDATION_PHASE_END_TICK) {
            currentPhase = 'Validation';
            const validationTicks = tickInCycle - MINING_PHASE_END_TICK;
            if (validationTicks < COMMITMENT_END_TICK) await handleProvisionalCommitment();
            else if (validationTicks < RECONCILIATION_END_TICK) await handleReconciliation();
            else await handleVDFVoting();
            // After successful validation phase
            if (workerState.consensusPhase === 'Validation' && tickInCycle >= VALIDATION_PHASE_END_TICK - 1) {
                // Check for slashing violations
                const violations = await pluribit.check_and_report_violations(workerState.minerId || 'system');
                if (violations > 0) {
                    log(`Detected and reported ${violations} slashing violations`, 'warn');
                }
            }
        } else {
            currentPhase = 'Propagation';
        }
        
        if (workerState.consensusPhase !== currentPhase) {
             workerState.consensusPhase = currentPhase;
             log(`Entering new phase: ${currentPhase}`, 'info');
        }

        parentPort.postMessage({
            type: 'consensusUpdate',
            payload: {
                state: {
                    current_phase: currentPhase,
                    current_tick: currentTick,
                }
            }
        });

        if (currentPhase === 'Mining' && workerState.minerActive && !workerState.currentlyMining) {
            releaseLock();
            startMining();
            return;
        }
        

        
    } catch (e) {
        log(`Consensus tick error: ${e.message}`, 'error');
    } finally {
        if (isLocked) releaseLock();
    }
}

async function handleVDFTick() {
    if (isLocked) return;
    try {
        await acquireLock();
        await pluribit.tick_vdf_clock();
    } catch (e) {
        log(`VDF tick error: ${e.message}`, 'error');
    } finally {
        releaseLock();
    }
}

async function startMining() {
    if (workerState.currentlyMining || !workerState.minerActive) return;
    workerState.currentlyMining = true;
    log(`Starting PoW mining for wallet: ${workerState.minerId}...`, 'info');

    try {
        await acquireLock();
        const nextHeight = Number((await pluribit.get_blockchain_state()).current_height) + 1;

        const submissionCheck = await pluribit.check_block_submission(BigInt(nextHeight));
        
        if (!submissionCheck.can_submit) {
            log(`Cannot mine yet - VDF clock not ready. Ticks remaining: ${submissionCheck.ticks_remaining}`, 'warn');
            setTimeout(() => {
                workerState.currentlyMining = false;
            }, Number(submissionCheck.ticks_remaining) * 1000);
            releaseLock();
            return;
        }
        releaseLock();

        const minerWalletJson = workerState.wallets.get(workerState.minerId);
        if (!minerWalletJson) throw new Error(`Miner wallet '${workerState.minerId}' is not loaded.`);

        const walletData = await pluribit.wallet_get_data(minerWalletJson);
        const minerPubKeyBytes = new Uint8Array(walletData.scan_pub_key_hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const latestHash = await pluribit.get_latest_block_hash();
        const difficulty = await pluribit.get_current_difficulty();
        const vdf_proof = await pluribit.compute_block_vdf_proof(latestHash);

        log(`Mining block #${nextHeight} at difficulty ${difficulty}...`, 'info');

        const miningResult = await pluribit.mine_block_with_txs(
            BigInt(nextHeight), latestHash, workerState.minerId, minerPubKeyBytes,
            difficulty, BigInt(10000000), vdf_proof
        );

        if (miningResult && miningResult.block) {
            await acquireLock();
            log(`Block #${miningResult.block.height} MINED! Nonce: ${miningResult.block.nonce}`, 'success');
            
            const currentHeight = miningResult.block.height;

            if (currentHeight <= BOOTSTRAP_BLOCKS) {
                log(`Finalizing bootstrap block #${currentHeight}...`, 'info');
                try {
                    const newChainState = await pluribit.add_block_to_chain(miningResult.block);
                    await db.saveBlock(miningResult.block);

                    log(`Block #${currentHeight} added to chain. New height: ${newChainState.current_height}`, 'success');

                    const minerWallet = workerState.wallets.get(workerState.minerId);
                    const updatedWalletJson = await pluribit.wallet_scan_block(minerWallet, miningResult.block);
                    workerState.wallets.set(workerState.minerId, updatedWalletJson);
                    const newBalance = await pluribit.wallet_get_balance(updatedWalletJson);
                    parentPort.postMessage({ type: 'walletBalance', payload: { wallet_id: workerState.minerId, balance: newBalance }});

                    if (workerState.p2p) await workerState.p2p.seedBlock(miningResult.block);

                } catch (e) {
                    log(`Failed to add bootstrap block to chain: ${e}`, 'error');
                }
            } else {
                validationState.candidateBlocks.push(miningResult.block);
                if (workerState.p2p) {
                    workerState.p2p.broadcast({ type: 'CANDIDATE', block: miningResult.block });
                }
            }

            if (miningResult.used_transactions?.length > 0) {
                await pluribit.remove_transactions_from_pool(miningResult.used_transactions);
            }
            releaseLock();
        } else {
            log('Mining attempt did not produce a block.', 'warn');
        }

    } catch (e) {
        log(`Mining error: ${e.message}`, 'error');
    } finally {
        if (isLocked) releaseLock();
        workerState.currentlyMining = false;
    }
}

async function handleProvisionalCommitment() {
    if (!workerState.validatorActive || validationState.commitmentSent) return;
    
    try {
        const chainState = await pluribit.get_blockchain_state();
        const targetHeight = Number(chainState.current_height) + 1;

        
        const candidateHashes = validationState.candidateBlocks
            .filter(b => b.height === targetHeight)
            .map(b => b.hash);

        if (candidateHashes.length === 0) {
            log('No candidate blocks to commit to yet.', 'info');
            return;
        }

        log(`Creating commitment for ${candidateHashes.length} candidate blocks...`, 'info');
        const commitment = await pluribit.create_candidate_commitment(
            workerState.validatorId,
            BigInt(targetHeight),
            candidateHashes
        );

        if (workerState.p2p) {
            workerState.p2p.broadcast({ type: 'CANDIDATE_COMMITMENT', commitment });
        }
        log('Commitment broadcast to network.', 'success');
        validationState.commitmentSent = true;

    } catch(e) {
        log(`Error creating commitment: ${e}`, 'error');
    }
}

async function handleReconciliation() {
    if (!workerState.validatorActive || validationState.reconciled) return;

    try {
        const chainState = await pluribit.get_blockchain_state();
        const targetHeight = Number(chainState.current_height) + 1;


        // 1. Get ALL unique block hashes that ANY validator has committed to.
        // This is the crucial change to align with the whitepaper's reconciliation phase.
        const allKnownHashes = new Set(await pluribit.get_all_known_blocks_from_commitments(BigInt(targetHeight)));
        if (allKnownHashes.size === 0) {
            log('Reconciliation: No candidate commitments received from network yet.', 'warn');
            validationState.reconciled = true; // Mark as done for this cycle if no candidates exist.
            return;
        }
        
        // 2. Filter our locally-known candidate blocks to only include those in the global set.
        const reconcilableCandidates = validationState.candidateBlocks.filter(b => 
            b.height === targetHeight && allKnownHashes.has(b.hash)
        );

        if (reconcilableCandidates.length === 0) {
            log('Reconciliation: None of our local candidates are in the public commitment set.', 'warn');
            validationState.reconciled = true;
            return;
        }

        // 3. Find the best block from the RECONCILED set using the whitepaper's scoring.
        // The scoring function is highest difficulty, with lowest hash as the tie-breaker.
        let bestBlock = reconcilableCandidates[0];
        for (let i = 1; i < reconcilableCandidates.length; i++) {
            const candidate = reconcilableCandidates[i];
            if (candidate.difficulty > bestBlock.difficulty) {
                bestBlock = candidate;
            } else if (candidate.difficulty === bestBlock.difficulty) {
                if (candidate.hash < bestBlock.hash) {
                    bestBlock = candidate;
                }
            }
        }
        
        validationState.selectedBlock = bestBlock.hash;
        log(`Reconciliation complete. Selected best global candidate: ${bestBlock.hash.substring(0, 16)}...`, 'success');

    } catch(e) {
        log(`Error during reconciliation: ${e}`, 'error');
    } finally {
        validationState.reconciled = true;
    }
}

async function handleVDFVoting() {
    if (!workerState.validatorActive || validationState.vdfStarted) return;
    
    if (!validationState.reconciled || !validationState.selectedBlock) {
        log('VDF Voting: Waiting for reconciliation to complete.', 'info');
        return;
    }
    
    validationState.vdfStarted = true;
    log(`Offloading VDF vote computation for block ${validationState.selectedBlock.substring(0, 16)}...`, 'info');

    try {
        const validatorWalletJson = workerState.wallets.get(workerState.validatorId);
        if (!validatorWalletJson) throw new Error("Validator wallet not loaded");

        const walletData = JSON.parse(validatorWalletJson);
        const spendPrivKey = new Uint8Array(walletData.spend_priv);

        const vdfWorker = new Worker(path.join(__dirname, 'vdf-worker.js'));

        vdfWorker.on('message', (event) => {
            if (event.success) {
                log('VDF vote computation complete!', 'success');
                validationState.voted = true;
                if (workerState.p2p) {
                    workerState.p2p.broadcast({ type: 'VOTE', voteData: event.payload });
                }
            } else {
                log(`VDF vote computation failed: ${event.error}`, 'error');
                validationState.vdfStarted = false;
            }
            vdfWorker.terminate();
        });

        vdfWorker.postMessage({
            validatorId: workerState.validatorId,
            spendPrivKey: spendPrivKey,
            selectedBlockHash: validationState.selectedBlock,
        });

    } catch (e) {
        log(`Failed to start VDF voting worker: ${e}`, 'error');
        validationState.vdfStarted = false;
    }
}

async function handleRemoteCandidate({ block }) {
    try {
        await acquireLock();
        const chainState = await pluribit.get_blockchain_state();
        const expectedHeight = chainState.current_height + 1;

        if (block && block.height === expectedHeight) {
            // Verify the block has valid PoW before accepting
            if (!block.is_valid_pow) {
                log(`Rejected invalid PoW block from network`, 'warn');
                return;
            }
            
            if (!validationState.candidateBlocks.some(b => b.hash === block.hash)) {
                log(`Received new valid candidate block #${block.height} from network.`, 'info');
                validationState.candidateBlocks.push(block);
                
                // Store in Rust for voting
                await pluribit.store_candidate_block(block.height, block.hash, block);
            }
        }
    } catch (e) {
        log(`Rejected remote candidate: ${e}`, 'warn');
    } finally {
        releaseLock();
    }
}

async function handleRemoteCommitment({ commitment }) {
     try {
        await acquireLock();
        if (commitment) {
            log(`Received commitment from validator ${commitment.validator_id.substring(0, 12)}...`, 'info');
            await pluribit.store_candidate_commitment(
                commitment.height,
                commitment.validator_id,
                commitment
            );
        }
    } catch (e) {
        log(`Failed to store remote commitment: ${e}`, 'warn');
    } finally {
        releaseLock();
    }
}

async function handleRemoteVote({ voteData }) {
    try {
        await acquireLock();
        if (voteData) {
            log(`Received vote from validator ${voteData.validator_id.substring(0, 12)}... for block ${voteData.block_hash.substring(0,16)}`, 'info');
            
            // Store vote in Rust for finalization
            await pluribit.store_network_vote(
                voteData.validator_id,
                voteData.block_height,
                voteData.block_hash,
                voteData.stake_amount,
                voteData.vdf_proof,
                voteData.signature
            );
        }
    } catch (e) {
        log(`Failed to process remote vote: ${e}`, 'warn');
    } finally {
        releaseLock();
    }
}

async function handleRemoteBlockAnnouncement({ height, magnetURI }) {
    try {
        await acquireLock();
        const chainState = await pluribit.get_blockchain_state();
        if (height === chainState.current_height + 1) {
            log(`Received announcement for next block #${height}. Downloading...`, 'info');
            if (workerState.p2p) workerState.p2p.downloadBlock(height, magnetURI);
        }
    } finally {
        releaseLock();
    }
}

async function handleRemoteBlockDownloaded({ block }) {
    try {
        await acquireLock();
        
        // First check if this might trigger a reorg
        await handlePotentialReorg(block);
        
        const chainState = await pluribit.get_blockchain_state();
        
        // Only add if it extends our current chain
        if (block.height === chainState.current_height + 1 && 
            block.prev_hash === chainState.blocks[chainState.current_height].hash) {
            
            log(`Downloaded block #${block.height} from network.`, 'info');
            const newChainState = await pluribit.add_block_to_chain(block);
            await db.saveBlock(block);
            log(`Remote block #${block.height} added to chain. New height: ${newChainState.current_height}`, 'success');

            for (const [walletId, walletJson] of workerState.wallets.entries()) {
                const updatedWalletJson = await pluribit.wallet_scan_block(walletJson, block);
                if (updatedWalletJson !== walletJson) {
                    workerState.wallets.set(walletId, updatedWalletJson);
                    const newBalance = await pluribit.wallet_get_balance(updatedWalletJson);
                    parentPort.postMessage({ type: 'walletBalance', payload: { wallet_id: walletId, balance: newBalance }});
                }
            }
        }
    } catch (e) {
        log(`Failed to process downloaded block: ${e}`, 'error');
    } finally {
        releaseLock();
    }
}

async function handleCreateStake({ walletId, amount }) {
    try {
        const lock_duration = 100; 
        log(`Creating stake lock for '${walletId}' with amount ${amount}...`, 'info');
        await pluribit.create_stake_lock(walletId, BigInt(amount), BigInt(lock_duration));
        await saveValidatorState();
        log('Stake lock created and is pending activation. Run "activate_stake" to compute VDF and finalize.', 'success');
    } catch (e) {
        log(`Failed to create stake lock: ${e}`, 'error');
    }
}

async function handleActivateStake({ walletId }) {
    try {
        log(`Computing VDF for stake activation for '${walletId}'. This may take some time...`, 'info');
        const vdfResult = await pluribit.compute_stake_vdf(walletId);
        log('VDF computation complete. Activating stake...', 'success');

        const walletJson = workerState.wallets.get(walletId);
        if (!walletJson) throw new Error(`Wallet '${walletId}' is not loaded.`);
        
        const walletData = JSON.parse(walletJson);
        const spendPubKey = new Uint8Array(Object.values(walletData.spend_pub));
        const spendPrivKey = new Uint8Array(Object.values(walletData.spend_priv));
        
        await pluribit.activate_stake_with_vdf(
            walletId,
            vdfResult,
            spendPubKey,
            spendPrivKey
        );

        await saveValidatorState();

        log(`Stake for '${walletId}' is now active!`, 'success');

    } catch (e) {
        log(`Failed to activate stake: ${e}`, 'error');
    }
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

    // --- START FIX ---
    // After loading, scan the entire blockchain to update the wallet's state.
    log(`Scanning blockchain for wallet '${walletId}'...`, 'info');
    const allBlocks = await db.getAllBlocks();
    for (const block of allBlocks) {
        // The wallet_scan_block function from Rust returns the *updated* wallet JSON string.
        walletJson = await pluribit.wallet_scan_block(walletJson, block);
    }
    // --- END FIX ---

    // Save the newly synced wallet state back to the database.
    const updatedWalletData = JSON.parse(walletJson);
    await db.saveWallet(walletId, updatedWalletData);
    
    // Store the updated state in the worker and get the final balance.
    workerState.wallets.set(walletId, walletJson);
    const balance = await pluribit.wallet_get_balance(walletJson);
    const address = await pluribit.wallet_get_stealth_address(walletJson);
    
    parentPort.postMessage({
        type: 'walletLoaded',
        payload: { walletId, balance, address }
    });
}

async function handlePotentialReorg(newBlock) {
    try {
        await acquireLock();
        
        const chainState = await pluribit.get_blockchain_state();
        const currentTip = chainState.blocks[chainState.blocks.length - 1];
        
        // Check if this creates a fork
        if (newBlock.height <= chainState.current_height && 
            newBlock.hash !== chainState.blocks[newBlock.height].hash) {
            
            log(`Fork detected at height ${newBlock.height}. Block hash: ${newBlock.hash.substring(0, 16)}...`, 'warn');
            
            // Store this fork block
            if (!reorgState.pendingForks.has(newBlock.height)) {
                reorgState.pendingForks.set(newBlock.height, new Map());
            }
            reorgState.pendingForks.get(newBlock.height).set(newBlock.hash, newBlock);
            
            // Request parent blocks until we find common ancestor
            await requestForkChain(newBlock);
        } else if (newBlock.prev_hash !== currentTip.hash && newBlock.height === currentTip.height + 1) {
            // This is a competing block at the next height
            log(`Competing block received at height ${newBlock.height}`, 'info');
            
            // Store as potential fork
            if (!reorgState.pendingForks.has(newBlock.height)) {
                reorgState.pendingForks.set(newBlock.height, new Map());
            }
            reorgState.pendingForks.get(newBlock.height).set(newBlock.hash, newBlock);
            
            // Request the parent to build the fork chain
            await requestForkChain(newBlock);
        }
    } catch (e) {
        log(`Error in handlePotentialReorg: ${e}`, 'error');
    } finally {
        releaseLock();
    }
}

async function requestForkChain(tipBlock) {
    let currentBlock = tipBlock;
    const chainState = await pluribit.get_blockchain_state();
    
    while (currentBlock.height > 0) {
        // Check if we have this block in our main chain
        if (currentBlock.height <= chainState.current_height) {
            const ourBlock = chainState.blocks[currentBlock.height];
            if (ourBlock && ourBlock.hash === currentBlock.hash) {
                // Found common ancestor
                log(`Found common ancestor at height ${currentBlock.height}`, 'info');
                await evaluateFork(currentBlock.height, tipBlock);
                return;
            }
        }
        
        // Request parent if we don't have it
        if (!reorgState.requestedBlocks.has(currentBlock.prev_hash)) {
            reorgState.requestedBlocks.add(currentBlock.prev_hash);
            if (workerState.p2p) {
                workerState.p2p.broadcast({
                    type: 'BLOCK_REQUEST',
                    hash: currentBlock.prev_hash,
                    height: currentBlock.height - 1
                });
            }
            return; // Wait for response
        }
        
        // Check if we have the parent in our fork cache
        const parentBlocks = reorgState.pendingForks.get(currentBlock.height - 1);
        if (parentBlocks && parentBlocks.has(currentBlock.prev_hash)) {
            currentBlock = parentBlocks.get(currentBlock.prev_hash);
        } else {
            // Parent not yet received, wait
            return;
        }
    }
}

async function evaluateFork(commonAncestorHeight, forkTip) {
    try {
        const chainState = await pluribit.get_blockchain_state();
        
        // Build the fork chain from common ancestor to tip
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
        
        // Calculate work for both chains
        const ourChainSegment = chainState.blocks.slice(commonAncestorHeight + 1);
        const ourWork = await pluribit.get_chain_work(ourChainSegment);
        const forkWork = await pluribit.get_chain_work(forkChain);
        
        log(`Chain work comparison - Our chain: ${ourWork}, Fork: ${forkWork}`, 'info');
        
        if (forkWork > ourWork) {
            log(`Fork has more work (${forkWork} > ${ourWork}). Initiating reorganization...`, 'warn');
            await performReorganization(commonAncestorHeight, forkChain);
        } else {
            log(`Our chain has more work. Keeping current chain.`, 'info');
            // Clean up fork blocks we don't need
            cleanupForkCache(commonAncestorHeight);
        }
    } catch (e) {
        log(`Error evaluating fork: ${e}`, 'error');
    }
}

async function performReorganization(commonAncestorHeight, newChain) {
    try {
        log(`Starting reorganization from height ${commonAncestorHeight}`, 'warn');
        
        const chainState = await pluribit.get_blockchain_state();
        const blocksToRewind = [];
        
        // 1. Collect blocks to rewind
        for (let height = chainState.current_height; height > commonAncestorHeight; height--) {
            const block = chainState.blocks[height];
            if (block) {
                blocksToRewind.push(block);
            }
        }
        
        // 2. Rewind the chain in Rust
        log(`Rewinding ${blocksToRewind.length} blocks...`, 'info');
        for (const block of blocksToRewind) {
            await pluribit.rewind_block(block);
            
            // Update wallets - remove any UTXOs from this block
            for (const [walletId, walletJson] of workerState.wallets.entries()) {
                const updatedWallet = await pluribit.wallet_unscan_block(walletJson, block);
                if (updatedWallet !== walletJson) {
                    workerState.wallets.set(walletId, updatedWallet);
                    const newBalance = await pluribit.wallet_get_balance(updatedWallet);
                    parentPort.postMessage({ 
                        type: 'walletBalance', 
                        payload: { wallet_id: walletId, balance: newBalance }
                    });
                }
            }
        }
        
        // 3. Apply new blocks from fork
        log(`Applying ${newChain.length} blocks from fork...`, 'info');
        for (const block of newChain) {
            const result = await pluribit.add_block_to_chain(block);
            await db.saveBlock(block);
            
            // Update wallets - scan for new UTXOs
            for (const [walletId, walletJson] of workerState.wallets.entries()) {
                const updatedWallet = await pluribit.wallet_scan_block(walletJson, block);
                if (updatedWallet !== walletJson) {
                    workerState.wallets.set(walletId, updatedWallet);
                    const newBalance = await pluribit.wallet_get_balance(updatedWallet);
                    parentPort.postMessage({ 
                        type: 'walletBalance', 
                        payload: { wallet_id: walletId, balance: newBalance }
                    });
                }
            }
            
            log(`Applied block #${block.height} from fork`, 'success');
        }
        
        // 4. Clean up fork cache
        cleanupForkCache(newChain[newChain.length - 1].height);
        
        // 5. Broadcast our new tip
        const newTip = newChain[newChain.length - 1];
        if (workerState.p2p) {
            workerState.p2p.broadcast({
                type: 'BLOCK_ANNOUNCEMENT',
                height: newTip.height,
                hash: newTip.hash
            });
        }
        
        log(`Reorganization complete. New chain tip at height ${newTip.height}`, 'success');
        
    } catch (e) {
        log(`Critical error during reorganization: ${e}`, 'error');
    }
}

function cleanupForkCache(keepAboveHeight) {
    const heights = Array.from(reorgState.pendingForks.keys());
    for (const height of heights) {
        if (height <= keepAboveHeight) {
            reorgState.pendingForks.delete(height);
        }
    }
    reorgState.requestedBlocks.clear();
}

async function handleBlockRequest({ hash, height }) {
    try {
        await acquireLock();
        const chainState = await pluribit.get_blockchain_state();
        
        // Check if we have this block
        if (height < chainState.blocks.length) {
            const block = chainState.blocks[height];
            if (block && block.hash === hash) {
                // Send the block to peers
                if (workerState.p2p) {
                    workerState.p2p.broadcast({
                        type: 'BLOCK_RESPONSE',
                        block: block
                    });
                }
            }
        }
    } catch (e) {
        log(`Error handling block request: ${e}`, 'error');
    } finally {
        releaseLock();
    }
}

async function handleBlockResponse({ block }) {
    try {
        await acquireLock();
        
        // Store the block in our fork cache
        if (!reorgState.pendingForks.has(block.height)) {
            reorgState.pendingForks.set(block.height, new Map());
        }
        reorgState.pendingForks.get(block.height).set(block.hash, block);
        
        // Remove from requested set
        reorgState.requestedBlocks.delete(block.hash);
        
        // Continue building fork chain if needed
        const forkBlocks = Array.from(reorgState.pendingForks.values())
            .flatMap(m => Array.from(m.values()));
        
        for (const forkBlock of forkBlocks) {
            if (forkBlock.prev_hash === block.hash) {
                await requestForkChain(forkBlock);
                break;
            }
        }
    } catch (e) {
        log(`Error handling block response: ${e}`, 'error');
    } finally {
        releaseLock();
    }
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
        
        // UNCOMMENTED AND FIXED:
        if (workerState.p2p) {
            workerState.p2p.broadcast({ type: 'TRANSACTION', tx: result.transaction });
        }
        
        log(`Transaction created. Hash: ${result.transaction.kernel.excess.substring(0,16)}...`, 'success');
        const newBalance = await pluribit.wallet_get_balance(result.updated_wallet_json);
        parentPort.postMessage({ type: 'walletBalance', payload: { wallet_id: from, balance: newBalance }});
    } catch (e) {
        log(`Transaction failed: ${e}`, 'error');
    } finally {
        releaseLock();
    }
}

// Only run main if this is the main worker thread, not when imported by a test
if (parentPort) {
    main();
}
