import { Level } from 'level';
import path from 'path';

// Define database paths
const DB_PATH = path.resolve(process.cwd(), 'pluribit-data');

// Use 'let' to allow these to be reassigned for testing
let chainDb = new Level(path.join(DB_PATH, 'chain'), { valueEncoding: 'json' });
let walletDb = new Level(path.join(DB_PATH, 'wallets'), { valueEncoding: 'json' });
let metaDb = new Level(path.join(DB_PATH, 'meta'), { valueEncoding: 'json' });

export function __setDbs(testChainDb, testWalletDb, testMetaDb) {
    chainDb = testChainDb;
    walletDb = testWalletDb;
    metaDb = testMetaDb || metaDb;
}

// --- BLOCK FUNCTIONS ---
export async function saveBlock(block) {
    await chainDb.put(block.height.toString(), block);
    
    // Update tip height
    const currentTip = await getTipHeight();
    if (block.height > currentTip) {
        await metaDb.put('tip_height', block.height);
    }
}

export async function loadBlock(height) {
    try {
        return await chainDb.get(height.toString());
    } catch (error) {
        if (error.code === 'LEVEL_NOT_FOUND') {
            return null;
        }
        throw error;
    }
}

export async function getTipHeight() {
    try {
        return await metaDb.get('tip_height');
    } catch (error) {
        if (error.code === 'LEVEL_NOT_FOUND') {
            return 0; // Genesis height
        }
        throw error;
    }
}

export async function getChainTip() {
    const tipHeight = await getTipHeight();
    return await loadBlock(tipHeight);
}

export async function getAllBlocks() {
    const blocks = [];
    const tipHeight = await getTipHeight();
    
    for (let i = 0; i <= tipHeight; i++) {
        const block = await loadBlock(i);
        if (block) blocks.push(block);
    }
    
    return blocks;
}

// --- WALLET FUNCTIONS (unchanged) ---
export async function saveWallet(walletId, walletData) {
    await walletDb.put(walletId, walletData);
}

export async function loadWallet(walletId) {
    try {
        return await walletDb.get(walletId);
    } catch (error) {
        if (error.code === 'LEVEL_NOT_FOUND') {
            return null;
        }
        throw error;
    }
}

// --- VALIDATOR STATE FUNCTIONS ---
export async function saveValidators(validators) {
    await metaDb.put('validators', validators);
}

export async function loadValidators() {
    try {
        return await metaDb.get('validators');
    } catch (error) {
        if (error.code === 'LEVEL_NOT_FOUND') {
            return null; // No validators saved yet
        }
        throw error;
    }
}

export async function clearValidators() {
    try {
        await metaDb.del('validators');
    } catch (error) {
        if (error.code === 'LEVEL_NOT_FOUND') {
            return; // Already cleared
        }
        throw error;
    }
}


export async function walletExists(walletId) {
    return (await loadWallet(walletId)) !== null;
}
