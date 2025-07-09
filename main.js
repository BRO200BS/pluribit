import { Worker } from 'worker_threads';
import path from 'path';
import { fileURLToPath } from 'url';
import chalk from 'chalk';
import readline from 'readline';

// --- Setup ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: chalk.cyan('> ')
});

// --- State Management ---
let loadedWalletId = null;
let isMining = false;
let isStaking = false;

// --- Worker Setup ---
const worker = new Worker(path.join(__dirname, 'worker.js'));

worker.on('message', (event) => {
    const { type, payload, error } = event;

    switch (type) {
        case 'log':
            const levelColor = {
                info: chalk.blue,
                success: chalk.green,
                warn: chalk.yellow,
                error: chalk.red,
            }[payload.level] || chalk.white;
            // Clear the current line, print the log, then redraw the prompt
            readline.clearLine(process.stdout, 0);
            readline.cursorTo(process.stdout, 0);
            console.log(`[${levelColor(payload.level.toUpperCase())}] ${payload.message}`);
            rl.prompt(true);
            break;

        case 'networkInitialized':
            console.log(chalk.green.bold('\nNetwork Online. Type "help" for commands.'));
            rl.prompt();
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

        case 'error':
            readline.clearLine(process.stdout, 0);
            readline.cursorTo(process.stdout, 0);
            console.error(chalk.red.bold(`\n[WORKER ERROR] ${error}`));
            rl.prompt(true);
            break;
            
            
    }
});

worker.on('error', (err) => console.error(chalk.red.bold('Worker thread error:'), err));
worker.on('exit', (code) => {
    if (code !== 0) console.error(chalk.red.bold(`Worker stopped with exit code ${code}`));
});


// --- Command Handling ---
rl.on('line', (line) => {
    const args = line.trim().split(' ');
    const command = args.shift().toLowerCase();

    handleCommand(command, args);
    
}).on('close', () => {
    console.log(chalk.cyan('Shutting down...'));
    worker.terminate();
    process.exit(0);
});

async function handleCommand(command, args) {
    switch (command) {
        case 'help':
            console.log('\nAvailable Commands:');
            console.log('  create <wallet_name>   - Create a new wallet');
            console.log('  load <wallet_name>     - Load an existing wallet');
            console.log('  send <to> <amount>     - Send a transaction');
            console.log('  mine                   - Toggle mining on/off');
            console.log('  stake <amount>         - Create a stake lock transaction');
            console.log('  activate_stake         - Activate a pending stake with a VDF');
            console.log('  exit                   - Shutdown the node\n');
            break;
        case 'create':
            if (args[0]) worker.postMessage({ action: 'initWallet', walletId: args[0] });
            else console.log('Usage: create <wallet_name>');
            break;
        case 'load':
            if (args[0]) worker.postMessage({ action: 'loadWallet', walletId: args[0] });
            else console.log('Usage: load <wallet_name>');
            break;
        case 'send':
            if (args.length < 2) {
                console.log('Usage: send <to_address> <amount>');
            } else if (!loadedWalletId) {
                console.log(chalk.red('Error: No wallet loaded.'));
            } else {
                worker.postMessage({
                    action: 'createTransaction',
                    from: loadedWalletId,
                    to: args[0],
                    amount: Number(args[1]),
                    fee: 1 // Default fee
                });
            }
            break;
        case 'mine':
             if (!loadedWalletId) {
                console.log(chalk.red('Error: Load a wallet before mining.'));
            } else {
                worker.postMessage({ action: 'setMinerActive', active: !isMining, minerId: loadedWalletId });
            }
            break;
        case 'stake':
            if (!loadedWalletId) {
                console.log(chalk.red('Error: Load a wallet before staking.'));
            } else if (!args[0] || isNaN(Number(args[0]))) {
                console.log('Usage: stake <amount>');
            } else {
                worker.postMessage({ 
                    action: 'createStake',
                    walletId: loadedWalletId, 
                    amount: Number(args[0]) 
                });
            }
            break;
        case 'activate_stake':
            if (!loadedWalletId) {
                console.log(chalk.red('Error: Load a wallet before activating a stake.'));
            } else {
                worker.postMessage({ action: 'activateStake', walletId: loadedWalletId });
            }
            break;
        case 'validators':
            worker.postMessage({ action: 'getValidators' });
            break;
        case 'exit':
            rl.close();
            break;
        case 'balance':
            if (!loadedWalletId) {
                console.log(chalk.red('Error: No wallet loaded.'));
            } else {
                worker.postMessage({ action: 'getBalance', walletId: loadedWalletId });
            }
            break;
        case 'validator':
            if (args[0] === 'on' && loadedWalletId) {
                worker.postMessage({ action: 'setValidatorActive', active: true, validatorId: loadedWalletId });
            } else if (args[0] === 'off') {
                worker.postMessage({ action: 'setValidatorActive', active: false });
            } else {
                console.log('Usage: validator <on|off>');
            }
            break;
        default:
            if(command) console.log(`Unknown command: "${command}". Type "help".`);
            break;
    }
    // Always redraw the prompt after a command
    rl.prompt();
}


// --- Initial Start ---
worker.postMessage({ action: 'initializeNetwork' });
