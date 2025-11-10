// mining-worker.js
import { parentPort } from 'worker_threads';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- MODULE LOADING (SIMPLIFIED) ---
// We only need the native module now, as it contains the full mining loop.
let pluribit;

async function loadModule() {
    try {
        const nativePath = path.join(__dirname, 'native', 'index.node');
        pluribit = require(nativePath);
        parentPort.postMessage({ 
            type: 'STATUS', 
            message: 'Using native mining loop (10-50x faster)' // Updated message
        });
    } catch (e) {
        parentPort.postMessage({ 
            type: 'STATUS', 
            message: `FATAL: Failed to load native module: ${e.message}` // Updated message
        });
        throw e;
    }
}
// --- END SIMPLIFIED LOADING ---

let currentJobId = null; // Use a job ID to manage state and prevent race conditions

// --- REWRITTEN MINING FUNCTION ---
const BATCH_SIZE = 1000n; // Process 1000 nonces in native code per batch

async function findMiningCandidate(params) {
  const { jobId, height, minerPubkey, minerSecretKey, prevHash, vrfThreshold, vdfIterations } = params;
  let nonce = 0n;
  let consecutiveErrors = 0; // ← ADD: Circuit breaker
  const MAX_CONSECUTIVE_ERRORS = 5; // ← ADD: Halt after 5 bad batches
   
    parentPort.postMessage({
        type: 'STATUS',
        message: `Starting mining job #${jobId} for block #${height}`
    });

  // This loop is async, allowing 'STOP' messages to be processed between batches.
  while (currentJobId === jobId) {
        try {
            // This is a SYNCHRONOUS, BLOCKING call to the native addon.
            // It blocks the worker's event loop for the duration of the batch.
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
                consecutiveErrors = 0; // ← ADD: Reset on success
                // We found a candidate!
                parentPort.postMessage({
                    type: 'CANDIDATE_FOUND',
                    jobId,
                    candidate: {
                        // The native code returns the core parts
                        nonce: BigInt(result.nonce), // Convert string nonce back to BigInt
                        vdf_proof: result.vdf_proof,
                        vrf_proof: result.vrf_proof,
                        // We fill in the rest from the job params
                        height,
                        prevHash,
                        miner_pubkey: minerPubkey,
                        vrfThreshold,
                        vdfIterations
                    }
                });
               
                parentPort.postMessage({
                    type: 'STATUS',
                    message: `Won lottery at nonce ${result.nonce}! VRF: ${Buffer.from(result.vrf_proof.output).toString('hex').substring(0,12)}...`
                });
                return; // Stop mining this block
            }
           
            // No candidate found in this batch, prepare for the next
            nonce += BATCH_SIZE;
           
            // Periodic status update (e.g., every 10 batches)
            if (nonce % (BATCH_SIZE * 10n) === 0n) {
                parentPort.postMessage({
                    type: 'STATUS',
                    message: `Mining block #${height}: Tried ${nonce} nonces...`
                });
            }
           
            // *** CRITICAL ***
            // Yield to the event loop to allow `parentPort.on('message')`
            // to process a potential 'STOP' message.
            await new Promise(resolve => setImmediate(resolve));
           
        } catch (e) {
            consecutiveErrors++; // ← ADD: Increment counter
            parentPort.postMessage({
                type: 'STATUS',
                message: `Error at nonce ${nonce}: ${e?.message || e}`
            });
            if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) { // ← ADD: Self-stop if too many
                parentPort.postMessage({ 
                    type: 'STATUS', 
                    message: `Too many consecutive errors (${consecutiveErrors}). Stopping job ${jobId}.` 
                });
                currentJobId = null;  // Self-stop
                return;
            }
            nonce += BATCH_SIZE; // Skip batch on error
            // Also yield on error
            await new Promise(resolve => setImmediate(resolve));
        }
    }
   
  // Loop was stopped by a 'STOP' message
  if (currentJobId !== jobId) {
    parentPort.postMessage({
      type: 'STATUS',
      message: `Mining job #${jobId} stopped.`
    });
  }
}
// --- END REWRITTEN FUNCTION ---


// This ensures the module is loaded *before* we start listening for messages.
async function main() {
    await loadModule();

  parentPort.on('message', async (msg) => {
    if (msg.type === 'STOP') {
      currentJobId = null; // Atomically stop any running job.
    } else if (msg.type === 'MINE_BLOCK') {
      currentJobId = msg.jobId; // Atomically set the new active job.
      // Fire off the mining loop. It will run and yield until
      // it finds a block or `currentJobId` is set to null.
      findMiningCandidate(msg).catch(e => {
                parentPort.postMessage({ 
                    type: 'STATUS', 
                    message: `Uncaught error in mining task: ${e?.message || e}` 
                });
            });
    }
  });
}

// Run the main function and catch any initialization errors.
main().catch(err => {
    parentPort.postMessage({ 
        type: 'STATUS', 
        message: `Module initialization failed: ${err.message}` 
    });
    process.exit(1);
});
