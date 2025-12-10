import { Worker } from 'worker_threads';
import path from 'path';
import { fileURLToPath } from 'url';
import chalk from 'chalk';
import readline from 'readline';
import util from 'node:util';
import {printGlitchLogo} from './logo.js';
import pkg from './src/p2p_pb.cjs';
const { p2p } = pkg;

// --- Setup ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
let isVerbose = false;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: chalk.cyan('> ')
});

// --- State Management ---
/** @type {string | null} */
let loadedWalletId = null;
let isMining = false;
let isStaking = false;
let isNetworkOnline = false;

// --- Worker Setup ---
const worker = new Worker(new URL('./worker.js', import.meta.url), {
    env: process.env // Explicitly pass environment variables to worker
});

/**
 * Formats atomic bits into the Pluribit Binary Topology.
 * 1 Byte = 8 Bits
 * 1 KB = 1024 Bytes
 * 1 MB = 1024 KB
 */
function formatPluribit(atomicBitsBigInt) {
    // Convert to Number for display formatting (precision is fine for UI)
    const bits = Number(atomicBitsBigInt);
    
    // < 1 ƀyte (Less than 8 bits)
    if (bits < 8) {
        return `${bits} ƀits`;
    }
    
    // < 1 Kiloƀyte (8,192 bits)
    if (bits < 8192) {
        const bytes = bits / 8;
        // If it divides evenly, don't show decimals
        return Number.isInteger(bytes) ? `${bytes} ƀytes` : `${bytes.toFixed(2)} ƀytes`;
    }
    
    // < 1 Megaƀyte (8,388,608 bits)
    if (bits < 8388608) {
        const kb = bits / 8192; // 8 * 1024
        return `${kb.toFixed(2)} Kƀ`;
    }
    
    // Megaƀytes and beyond
    const mb = bits / 8388608; // 8 * 1024 * 1024
    return `${mb.toFixed(4)} Mƀ`;
}

worker.on('message', (event) => {
    const { type, payload, error } = event;

    switch (type) {
        case 'log':
            const { level, message } = payload;

            // 1. HARD FILTERS: Always ignore these unless we are deep debugging
            // These are low-value spam from libraries or heartbeats
            if (
                message.includes('DHT') || 
                message.includes('Tags') ||
                message.includes('dial') && !message.includes('failed') || // Ignore dial attempts, keep failures
                message.includes('Tried') // Mining nonces
            ) {
                if (!isVerbose) break;
            }

            // 2. REPETITIVE NOISE FILTER
            // Hide routine sync messages even if they are marked INFO, unless verbose
            const NOISY_PATTERNS = [
                '[SYNC] No better chains found',
                '[SYNC] Starting consensus check',
                '[SYNC] Evaluated',
                'Broadcasting tip',
                'Peer verified' 
            ];

            if (!isVerbose && NOISY_PATTERNS.some(pattern => message.includes(pattern))) {
                break;
            }

            // 3. LEVEL FILTER
            // By default, hide DEBUG. Show everything else.
            if (!isVerbose && level === 'debug') break;

            /** @type {Record<string, typeof chalk>} */
            const levelColor = {
                debug: chalk.gray, // Make debug gray so it's less intrusive
                info: chalk.blue,
                success: chalk.green,
                warn: chalk.yellow,
                error: chalk.red,
            };
            
            const colorFn = levelColor[level] || chalk.white;
            const prefix = `[${colorFn(level.toUpperCase())}]`;

            // Clear current line (prompt), print log, redraw prompt
            readline.clearLine(process.stdout, 0);
            readline.cursorTo(process.stdout, 0);
            console.log(`${prefix} ${message}`);
            rl.prompt(true);
            break;

        case 'syncProgress': {
            // This handler draws a single-line progress bar that updates in place.
            const { current, target, startTime } = payload;
            
            // FIX: Explicitly convert BigInts to Numbers for calculation
            const percent = ((Number(current) / Number(target)) * 100).toFixed(2);
            
            const elapsedTime = (Date.now() - startTime) / 1000; // in seconds
            
            // FIX: Explicitly convert BigInt to Number here as well
            const blocksPerSecond = elapsedTime > 0 ? (Number(current) / elapsedTime).toFixed(1) : 0;

            const barWidth = 30;
            const filledWidth = Math.floor(barWidth * (Number(percent) / 100));
            const progressBar = '█'.repeat(filledWidth) + '░'.repeat(barWidth - filledWidth);

            // Use process.stdout.write with a carriage return (\r) to update the line in place.
            readline.clearLine(process.stdout, 0);
            readline.cursorTo(process.stdout, 0);
            process.stdout.write(
                chalk.yellow(`[SYNC] Downloading: ${progressBar} ${percent}% `) +
                chalk.cyan(`(${current}/${target}) | ${blocksPerSecond} blk/s`)
            );
            break;
        }


        case 'syncComplete': {
            // This handler cleans up the progress bar and redraws the command prompt.
            readline.clearLine(process.stdout, 0);
            readline.cursorTo(process.stdout, 0);
            rl.prompt(true);
            break;
        }

        case 'networkInitialized':
            isNetworkOnline = true; 
            console.log(chalk.green.bold('\nNetwork Online. Type "help" for commands.'));
            rl.prompt();
            break;
            
        case 'peerList':
            console.log(chalk.cyan.bold('\nConnected Peers:'));
            if (payload.length === 0) {
                console.log('  (None)');
            } else {
                // FIX: payload is an array of strings, so we log the item directly
                payload.forEach((peerId) => console.log(`  - ${peerId}`));
            }
            rl.prompt(true);
            break;     
               
        case 'walletLoaded':
            loadedWalletId = payload.walletId;
            console.log(chalk.green(`\nWallet '${payload.walletId}' loaded successfully.`));
            // --- FIX START: Use formatPluribit for consistency ---
            const loadedBalanceBigInt = BigInt(payload.balance);
            console.log(chalk.yellow(`Balance: ${formatPluribit(loadedBalanceBigInt)} | Address: ${payload.address}`));
            // --- FIX END ---
            rl.prompt(true);
            break;
            
        case 'walletBalance':
            // payload now has: wallet_id, balance, address
            const balBigInt = BigInt(payload.balance);
            const addrStr = payload.address || "Unknown";
            
            console.log(chalk.cyan(`\nWallet: ${payload.wallet_id}`));
            console.log(chalk.white(`Address: ${addrStr}`));
            console.log(chalk.yellow(`Balance: ${formatPluribit(balBigInt)}`));
            rl.prompt(true);
            break;
        
        case 'minerStatus':
            isMining = payload.active;
            break;
        
        case 'validatorStatus':
            isStaking = payload.active;
            break;

        case 'totalSupply': 
            const supplyAsBigInt = BigInt(payload.supply);
            console.log(chalk.yellow(`\nTotal Supply: ${formatPluribit(supplyAsBigInt)}`));
            rl.prompt(true);
            break;

        case 'error':
            readline.clearLine(process.stdout, 0);
            readline.cursorTo(process.stdout, 0);
            console.error(chalk.red.bold(`\n[WORKER ERROR] ${error}`));
            rl.prompt(true);
            break;

           
    }
});

worker.on('error', (err) => {
    console.error('Worker thread error:', err?.stack || err?.message || util.inspect(err, { depth: 5 }));
});

worker.on('exit', (code) => {
    if (code !== 0) console.error(chalk.red.bold(`Worker stopped with exit code ${code}`));
});


// --- Command Handling ---
rl.on('line', (line) => {
    const args = line.trim().split(' ');
    const command = args.shift();

    if (command) {
        handleCommand(command.toLowerCase(), args);
    }
    
}).on('close', () => {
    console.log(chalk.cyan('Shutting down...'));
    worker.terminate();
    process.exit(0);
});

/**
 * @param {string} command
 * @param {string[]} args
 */
async function handleCommand(command, args) {
    switch (command) {
        case 'help':
            console.log(chalk.bold('\n--- Wallet ---'));
            console.log('  create <wallet_name>          - Create a new wallet (outputs mnemonic)');
            console.log('  restore <wallet_name> "<phrase>" - Restore wallet from 12-word phrase');
            console.log('  load <wallet_name>            - Load an existing wallet');
            console.log('  balance                       - Show loaded wallet balance');
            console.log('  send <to_address> <amount>    - Send a transaction');
            
            console.log(chalk.bold('\n--- Node & Chain ---'));
            console.log('  mine                          - Toggle mining on/off');
            console.log(chalk.gray('  (Mining details are logged to ./pluribit-data/mining.log)'));
            console.log('  status                        - Show current chain status');
            console.log('  supply                        - Audit the total circulating supply');
            console.log('  peers                         - List connected P2P peers');
            console.log('  connect <multiaddr>           - Manually connect to a peer');
            console.log('  retry_sync                    - Manually force a sync');
            console.log('  exit                          - Shutdown the node');

            console.log(chalk.bold('\n--- Payment Channels (L2) ---'));
            console.log('  channel_open <pubkey> <my_amt> <their_amt> - Open a payment channel');
            console.log('  channel_list                  - List all channels');
            console.log('  channel_accept <proposal_id>  - Accept a channel proposal');
            console.log('  channel_fund <channel_id>     - Fund an accepted channel');
            console.log('  channel_pay <channel_id> <amt> - Make a payment in channel');
            console.log('  channel_close <channel_id>    - Close and settle channel');

            console.log(chalk.bold('\n--- Atomic Swaps (L2) ---'));
            console.log('  swap_initiate <pubkey> <plb_amt> <btc_sats> <blocks> - Propose a swap');
            console.log('  swap_list                     - List all active and pending swaps');
            console.log('  swap_respond <swap_id> <btc_addr> <btc_txid> <vout> - Respond to a swap proposal');
            console.log('  swap_claim <swap_id> <secret_hex>   - (Bob) Claim Pluribit after Alice claims BTC');
            console.log('  swap_refund <swap_id>         - (Alice) Refund Pluribit if swap times out');
           
            console.log(chalk.bold('\n--- Debug & Audit ---'));
            console.log('  inspect <height>              - Show full details of a block');
            console.log('  audit                         - Run a detailed UTXO/supply audit');
            console.log('  verify                        - Verify coinbase index consistency');
            console.log('  purge_side                    - Purge orphaned side blocks');
            console.log('  clear_side                    - Clear side block cache');
            console.log('\n');
            break;

        case 'verbose':
            isVerbose = !isVerbose;
            console.log(chalk.yellow(`Verbose logging: ${isVerbose ? 'ON' : 'OFF'}`));
            break;

        case 'audit':
            worker.postMessage({ action: 'auditDetailed' });
            break;
        case 'purge_side':
            worker.postMessage({ action: 'purgeSideBlocks' });
            break;

        case 'clear_side':
            worker.postMessage({ action: 'clearSideBlocks' });
            break;

        case 'inspect':
            worker.postMessage({ action: 'inspectBlock', height: args[0] });
            break;
        case 'verify':
            worker.postMessage({ action: 'verifySupply' });
            break;

        case 'whodid':
            if (args[0]) {
                worker.postMessage({ action: 'checkMiners', height: args[0] });
            } else {
                console.log('Usage: whodid <height>');
            }
            break;

        case 'create':
            if (args[0]) {
                worker.postMessage({ action: 'createWalletWithMnemonic', walletId: args[0] });
            } else {
                console.log('Usage: create <wallet_name>');
            }
            break;

        case 'restore':
            // Expect: restore wallet_name "word1 word2 ... word12"
            if (args.length < 2) {
                console.log('Usage: restore <wallet_name> "<mnemonic phrase>"');
                break;
            }
            const walletName = args[0];
            // Join the rest of the args, assuming they might contain spaces if not quoted properly
            const phrase = args.slice(1).join(' ').replace(/^"(.*)"$/, '$1'); // Remove surrounding quotes if present
            if (phrase.split(' ').length !== 12) {
                 console.log(chalk.red('Error: Mnemonic phrase must be 12 words. Ensure it is enclosed in quotes if it contains spaces.'));
            } else {
                worker.postMessage({ action: 'restoreWalletFromMnemonic', walletId: walletName, phrase: phrase });
            }
            break;

        case 'retry_sync':
                    console.log(chalk.yellow('Forcing manual sync retry...'));
                    // Send the specific retry action we added to the worker
                    worker.postMessage({ action: 'retrySync' }); 
                    break;


        case 'load':
            if (args[0]) {
                // 1. Create the Protobuf request object
                const request = p2p.JSToRust_Command.create({
                    loadWallet: { walletId: args[0] }
                });

                // 2. Encode to Uint8Array
                const requestBytes = p2p.JSToRust_Command.encode(request).finish();

                // 3. Send the RAW BYTES to the worker
                worker.postMessage({
                    action: 'handle_command', // Use our new, single action
                    payload: requestBytes 
                });
            } else {
                console.log('Usage: load <wallet_name>');
            }
            break;

        case 'connect':
            if (args[0]) {
                worker.postMessage({ action: 'connectPeer', address: args[0] });
            } else {
                console.log('Usage: connect <multiaddr>');
            }
            break;

        case 'send':
            if (args.length < 2) {
                console.log('Usage: send <to_address> <amount>');
            } else if (loadedWalletId === null) {
                console.log(chalk.red('Error: No wallet loaded.'));
            } else {
                try {
                    // FIX: Parse as BigInt to support full 64-bit range
                    const amt = BigInt(args[1]);
                    if (amt <= 0n) {
                         console.log(chalk.red('Error: amount must be positive.'));
                         break;
                    }
                    worker.postMessage({
                        action: 'createTransaction',
                        from: loadedWalletId,
                        to: args[0],
                        amount: amt, // Pass BigInt to worker
                        fee: 1n      // Pass BigInt to worker
                    });
                } catch (e) {
                    console.log(chalk.red('Error: Invalid amount format.'));
                }
            }
            break;

        case 'mine':
            if (!isNetworkOnline) {
                console.log(chalk.red('Error: Network is not yet online. Please wait.'));
            } else if (loadedWalletId === null) {
                console.log(chalk.red('Error: Load a wallet before mining.'));
            } else {
                worker.postMessage({ action: 'setMinerActive', active: !isMining, minerId: loadedWalletId });
            }
            break;
            
        case 'status':
            worker.postMessage({ action: 'getMiningParams' });
            break;

        case 'supply':
            // Audit the total circulating supply via worker
            worker.postMessage({ action: 'getSupply' });
            break;

        case 'balance':
            if (loadedWalletId === null) {
                console.log(chalk.red('Error: No wallet loaded.'));
            } else {
                // 1. Create the Protobuf request object
                const request = p2p.JSToRust_Command.create({
                    getBalance: { walletId: loadedWalletId }
                });
                
                // 2. Encode to Uint8Array
                const requestBytes = p2p.JSToRust_Command.encode(request).finish();

                // 3. Send the RAW BYTES to the worker
                worker.postMessage({
                    action: 'handle_command',
                    payload: requestBytes 
                });
            }
            break;
            
        case 'peers':
            worker.postMessage({ action: 'getPeers' });
            break;

        case 'channel_open':
            // Usage: channel_open <counterparty_pubkey> <my_amount> <their_amount>
            if (args.length < 3) {
                console.log('Usage: channel_open <counterparty_pubkey> <my_amount> <their_amount>');
            } else if (!loadedWalletId) {
                console.log(chalk.red('Error: Load a wallet first.'));
            } else {
                worker.postMessage({
                    action: 'channelOpen',
                    walletId: loadedWalletId,
                    counterpartyPubkey: args[0],
                    myAmount: BigInt(args[1]),
                    theirAmount: BigInt(args[2])
                });
            }
            break;

        case 'channel_list':
            worker.postMessage({ action: 'channelList' });
            break;

        case 'channel_accept':
            // Usage: channel_accept <proposal_id>
            if (!args[0]) {
                console.log('Usage: channel_accept <proposal_id>');
            } else if (!loadedWalletId) {
                console.log(chalk.red('Error: Load a wallet first.'));
            } else {
                worker.postMessage({
                    action: 'channelAccept',
                    walletId: loadedWalletId,
                    proposalId: args[0]
                });
            }
            break;

        case 'channel_fund':
            // Usage: channel_fund <channel_id>
            if (!args[0]) {
                console.log('Usage: channel_fund <channel_id>');
            } else if (!loadedWalletId) {
                console.log(chalk.red('Error: Load a wallet first.'));
            } else {
                // TODO: Need to pass funding inputs
                worker.postMessage({
                    action: 'channelFund',
                    walletId: loadedWalletId,
                    channelId: args[0]
                });
            }
            break;

        case 'channel_pay':
            // Usage: channel_pay <channel_id> <amount>
            if (args.length < 2) {
                console.log('Usage: channel_pay <channel_id> <amount>');
            } else if (!loadedWalletId) {
                console.log(chalk.red('Error: Load a wallet first.'));
            } else {
                worker.postMessage({
                    action: 'channelPay',
                    walletId: loadedWalletId,
                    channelId: args[0],
                    amount: BigInt(args[1])
                });
            }
            break;

        case 'channel_close':
            // Usage: channel_close <channel_id>
            if (!args[0]) {
                console.log('Usage: channel_close <channel_id>');
            } else if (!loadedWalletId) {
                console.log(chalk.red('Error: Load a wallet first.'));
            } else {
                worker.postMessage({
                    action: 'channelClose',
                    walletId: loadedWalletId,
                    channelId: args[0]
                });
            }
            break;

        case 'swap_initiate':
            // Usage: swap_initiate <counterparty_pubkey> <plb_amount> <btc_amount> <timeout_blocks>
            if (args.length < 4) {
                console.log('Usage: swap_initiate <counterparty_pubkey> <plb_amount> <btc_sats_amount> <timeout_blocks>');
            } else if (!loadedWalletId) {
                console.log(chalk.red('Error: Load a wallet first.'));
            } else {
                worker.postMessage({
                    action: 'swapInitiate',
                    walletId: loadedWalletId,
                    counterpartyPubkey: args[0],
                    plbAmount: BigInt(args[1]),
                    btcAmount: BigInt(args[2]),
                    timeoutBlocks: BigInt(args[3])
                });
            }
            break;

        case 'swap_list':
            worker.postMessage({ action: 'swapList' });
            break;

        case 'swap_respond':
            // Usage: swap_respond <swap_id> <btc_htlc_address> <btc_txid> <btc_vout>
            if (args.length < 4) {
                console.log('Usage: swap_respond <swap_id> <btc_htlc_address> <btc_txid> <btc_vout>');
            } else if (!loadedWalletId) {
                console.log(chalk.red('Error: Load a wallet first.'));
            } else {
                worker.postMessage({
                    action: 'swapRespond',
                    walletId: loadedWalletId,
                    swapId: args[0],
                    btcAddress: args[1],
                    btcTxid: args[2],
                    btcVout: parseInt(args[3], 10)
                });
            }
            break;

        case 'swap_refund':
            // Usage: swap_refund <swap_id>
            if (!args[0]) {
                console.log('Usage: swap_refund <swap_id>');
            } else if (!loadedWalletId) {
                console.log(chalk.red('Error: Load a wallet first.'));
            } else {
                worker.postMessage({
                    action: 'swapRefund',
                    walletId: loadedWalletId,
                    swapId: args[0]
                });
            }
            break;

        case 'swap_claim':
            // Usage: swap_claim <swap_id> <adaptor_secret_hex>
            if (args.length < 2) {
                console.log('Usage: swap_claim <swap_id> <adaptor_secret_hex_from_btc_tx>');
            } else if (!loadedWalletId) {
                console.log(chalk.red('Error: Load a wallet first.'));
            } else {
                worker.postMessage({
                    action: 'swapClaim',
                    walletId: loadedWalletId,
                    swapId: args[0],
                    adaptorSecretHex: args[1]
                });
            }
            break;


        case 'exit':
            await gracefulShutdown(0);
            return; // don't prompt again

        default:
            if(command) console.log(`Unknown command: "${command}". Type "help".`);
            break;
    }
    rl.prompt();
}


// -------- Graceful shutdown (main) ----------
let shuttingDown = false;
async function gracefulShutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(chalk.cyan('Shutting down...'));

  // Ask worker to stop cleanly (it will close libp2p, stop miner, etc.)
  try { worker.postMessage({ action: 'shutdown' }); } catch {}

  // Wait for the worker to exit, with a fallback terminator
  /** @type {Promise<void>} */
  const done = new Promise((resolve) => {
    const onExit = () => {
      worker.removeListener('exit', onExit);
      resolve();
    };
    worker.on('exit', onExit);
    // Hard fallback after 5s if worker doesn't exit by itself
    setTimeout(() => {
      worker.terminate().finally(() => resolve());
    }, 5000);
  });
  await done;
  process.exit(code);
}

// Handle Ctrl-C directly (so we don't crash mdns sockets)
process.on('SIGINT', () => rl.close());
process.on('SIGTERM', () => rl.close());

// --- Initial Start ---
// Display  logo on startup
printGlitchLogo(); // Try printLogo() or printCompactLogo() for different styles!

worker.postMessage({ action: 'initializeNetwork' });
