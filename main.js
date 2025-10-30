import { Worker } from 'worker_threads';
import path from 'path';
import { fileURLToPath } from 'url';
import chalk from 'chalk';
import readline from 'readline';
import util from 'node:util';
import {printGlitchLogo} from './logo.js';

// --- Setup ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
const worker = new Worker(new URL('./worker.js', import.meta.url));

worker.on('message', (event) => {
    const { type, payload, error } = event;

    switch (type) {
        case 'log':
            // Hide debug-level messages to reduce console noise
            if (payload.level === 'debug' && payload.message.startsWith('[P2P]')) break;

            /** @type {Record<string, typeof chalk>} */
            const levelColor = {
                info: chalk.blue,
                success: chalk.green,
                warn: chalk.yellow,
                error: chalk.red,
            };
            const colorFn = levelColor[payload.level] || chalk.white;
            // Clear the current line, print the log, then redraw the prompt
            readline.clearLine(process.stdout, 0);
            readline.cursorTo(process.stdout, 0);
            console.log(`[${colorFn(payload.level.toUpperCase())}] ${payload.message}`);
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
                payload.forEach((/** @type {any} */ peer) => console.log(`  - ${peer.id}`));
            }
            rl.prompt(true);
            break;        
               
        case 'walletLoaded':
            loadedWalletId = payload.walletId;
            console.log(chalk.green(`\nWallet '${payload.walletId}' loaded successfully.`));
            console.log(chalk.yellow(`Balance: ${payload.balance} | Address: ${payload.address}`));
            rl.prompt(true);
            break;
            
        case 'walletBalance':
            console.log(chalk.yellow(`\nBalance updated for ${payload.wallet_id}: ${payload.balance}`));
            rl.prompt(true);
            break;
        
        case 'minerStatus':
            isMining = payload.active;
            break;
        
        case 'validatorStatus':
            isStaking = payload.active;
            break;

        case 'totalSupply': 
            console.log(chalk.yellow(`\nTotal Supply: ${payload.supply} bits`));
            // Use BigInt for the division to maintain precision
            const supplyAsBigInt = BigInt(payload.supply);
            const coins = (supplyAsBigInt / 100_000_000n).toString();
            console.log(`   (Which is ${coins} PLB)`);
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
            console.log('\nAvailable Commands:');
            console.log('  create <wallet_name>   - Create a new wallet (outputs mnemonic)');
            console.log('  restore <wallet_name> "<mnemonic phrase>" - Restore wallet from phrase');
            console.log('  load <wallet_name>     - Load an existing wallet');
            console.log('  send <to> <amount>     - Send a transaction');
            console.log('  mine                   - Toggle PoW+PoST mining on/off');
            console.log('  status                 - Show current chain status');
            console.log('  balance                - Show wallet balance');
            console.log('  supply                 - Audit the total circulating supply');
            console.log('  connect <peer>         - Manually connect to a peer');
            console.log('  peers                  - List connected P2P peers');
            console.log('  exit                   - Shutdown the node\n');
            break;

        case 'audit':
            worker.postMessage({ action: 'auditDetailed' });
            break;
        case 'inspect':
            worker.postMessage({ action: 'inspectBlock', height: args[0] });
            break;
        case 'verify':
            worker.postMessage({ action: 'verifySupply' });
            break;

        case 'whodid':
            worker.postMessage({ action: 'checkMiners' });
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

        case 'load':
            if (args[0]) worker.postMessage({ action: 'loadWallet', walletId: args[0] });
            else console.log('Usage: load <wallet_name>');
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
                const amt = Number(args[1]);
                if (!Number.isFinite(amt) || amt <= 0) {
                  console.log(chalk.red('Error: amount must be a positive finite number.'));
                  break;
                }
                worker.postMessage({
                    action: 'createTransaction',
                    from: loadedWalletId,
                    to: args[0],
                    amount: amt,
                    fee: 1
                });
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
                worker.postMessage({ action: 'getBalance', walletId: loadedWalletId });
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
