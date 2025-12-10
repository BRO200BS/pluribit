import { parentPort } from 'worker_threads';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- MODULE LOADING (SIMPLIFIED) ---
let pluribit;

async function loadModule() {
    try {
        const nativePath = path.join(__dirname, 'native', 'index.node');
        pluribit = require(nativePath);
        // FIX: Send initialization success to log file, not UI
        parentPort.postMessage({ 
            type: 'MINING_LOG', 
            message: 'Miner: Native module loaded successfully'
        });
    } catch (e) {
        // Fatal errors still go to UI
        parentPort.postMessage({ 
            type: 'STATUS', 
            message: `FATAL: Failed to load native module: ${e.message}` 
        });
        throw e;
    }
}
// --- END SIMPLIFIED LOADING ---

let currentJobId = null;

const BATCH_SIZE = 50n;

async function findMiningCandidate(params) {
  const { jobId, height, minerPubkey, minerSecretKey, prevHash, vrfThreshold, vdfIterations } = params;
  let nonce = 0n;
  let consecutiveErrors = 0;
  const MAX_CONSECUTIVE_ERRORS = 5;
   
    // FIX: "Starting" message goes to UI (info level) so user knows it's working
    parentPort.postMessage({
        type: 'STATUS',
        message: `⛏️  Miner active. Hashing for block #${height}... (Logs -> mining.log)`
    });

  while (currentJobId === jobId) {
        try {
            const result = pluribit.findMiningCandidateBatch(
                height,
                minerPubkey,
                minerSecretKey,
                prevHash,
                vrfThreshold,
                vdfIterations,
                nonce,
                BATCH_SIZE
            );

            if (result) {
                consecutiveErrors = 0;
                parentPort.postMessage({
                    type: 'CANDIDATE_FOUND',
                    jobId,
                    candidate: {
                        nonce: BigInt(result.nonce),
                        vdf_proof: result.vdf_proof,
                        vrf_proof: result.vrf_proof,
                        height,
                        prevHash,
                        miner_pubkey: minerPubkey,
                        vrfThreshold,
                        vdfIterations
                    }
                });
               
                // FIX: Winning is a high-priority UI event
                parentPort.postMessage({
                    type: 'STATUS',
                    message: `💎 💰 LOTTERY WON! Nonce ${result.nonce} satisfies VRF threshold!`
                });
                return; 
            }
           
            nonce += BATCH_SIZE;
           
            // FIX: Periodic updates go to MINING_LOG (File only)
            if (nonce % (BATCH_SIZE * 50n) === 0n) { // Reduced frequency slightly
                parentPort.postMessage({
                    type: 'MINING_LOG',
                    message: `[Job ${jobId}] Block #${height}: Checked ${nonce} nonces...`
                });
            }
           
            await new Promise(resolve => setImmediate(resolve));
           
        } catch (e) {
            consecutiveErrors++;
            // FIX: Errors go to log file to avoid spamming UI, unless fatal
            parentPort.postMessage({
                type: 'MINING_LOG',
                message: `Error at nonce ${nonce}: ${e?.message || e}`
            });
            if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                parentPort.postMessage({ 
                    type: 'STATUS', // Fatal stop goes to UI
                    message: `🛑 Miner stopped: Too many consecutive errors.` 
                });
                currentJobId = null;
                return;
            }
            nonce += BATCH_SIZE;
            await new Promise(resolve => setImmediate(resolve));
        }
    }
}

async function main() {
    await loadModule();

  parentPort.on('message', async (msg) => {
    if (msg.type === 'STOP') {
      currentJobId = null;
      parentPort.postMessage({ type: 'MINING_LOG', message: 'Mining loop stopped by user.' });
    } else if (msg.type === 'MINE_BLOCK') {
      currentJobId = msg.jobId; 
      findMiningCandidate(msg).catch(e => {
                parentPort.postMessage({ 
                    type: 'STATUS', 
                    message: `Uncaught error in mining task: ${e?.message || e}` 
                });
             });
    }
  });
}

main().catch(err => {
    parentPort.postMessage({ 
        type: 'STATUS', 
        message: `Module initialization failed: ${err.message}` 
    });
    process.exit(1);
});
