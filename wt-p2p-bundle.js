console.log('[P2P] Loading Pluribit WebTorrent P2P module...');

import WebTorrent from 'webtorrent';
import { Buffer } from 'buffer';
import crypto from 'crypto-browserify';
import pako from 'pako';

// Ensure Buffer is available globally for WebTorrent, which expects it.
if (typeof window !== 'undefined') {
    window.Buffer = Buffer;
}

/**
 * PluribitP2P class manages the WebTorrent-based peer-to-peer network,
 * handling block/snapshot distribution and real-time messaging for consensus.
 */
class PluribitP2P {
    constructor() {
        console.log('[P2P] Constructor called');
        this.client = null;
        this.handlers = new Map();
        this.blockTorrents = new Map();
        this.peerId = null;
        this.knownBlocks = new Map();
        this.knownSnapshots = new Map();
        this.pendingBlocks = new Set();
        this.connectedWires = new Set();
        this.peerDiscoveryInterval = null;
    }

    /**
     * Initializes the WebTorrent client and starts periodic tasks.
     * This is the main entry point for activating the P2P layer.
     * @returns {Promise<string>} A promise that resolves with the client's peer ID.
     */
    async start() {
        console.log('[P2P] Starting WebTorrent-based P2P network...');
        try {
            this.client = new WebTorrent({
                dht: true,
                maxConns: 55, // Default is 55
                tracker: {
                    rtcConfig: {
                        iceServers: [
                            { urls: 'stun:stun.l.google.com:19302' },
                            { urls: 'stun:global.stun.twilio.com:3478' }
                        ]
                    },
                    announce: this.getTrackers()
                }
            });

            this.peerId = this.client.peerId.toString('hex');
            console.log('[P2P] WebTorrent client started with peer ID:', this.peerId);

            // Set up global event listeners for the client
            this.client.on('error', (err) => this.handleError(err));
            this.client.on('torrent', (torrent) => this.setupTorrentHandlers(torrent));

            this.startPeriodicTasks();
            return this.peerId;

        } catch (error) {
            console.error('[P2P] Failed to start WebTorrent client:', error);
            throw error;
        }
    }
    
    /**
     * Returns a list of public WebTorrent trackers for peer discovery.
     * @returns {string[]} An array of tracker URLs.
     */
    getTrackers() {
        return [
            'wss://tracker.btorrent.xyz',
            'wss://tracker.openwebtorrent.com',
            'wss://tracker.webtorrent.dev',
            'wss://tracker.files.fm:7073/announce'
        ];
    }
    
    /**
     * Attaches generic event handlers to any new torrent instance.
     * @param {object} torrent - The WebTorrent torrent instance.
     */
    setupTorrentHandlers(torrent) {
        // The 'wire' event is the entry point for real-time communication
        torrent.on('wire', (wire) => this.setupWireProtocol(wire));
        torrent.on('error', (err) => console.error(`[P2P] Torrent error (${torrent.name}):`, err));
    }

    /**
     * Sets up the custom real-time message protocol on a new peer connection.
     * @param {object} wire - The WebTorrent wire object representing a direct connection to a peer.
     */
    setupWireProtocol(wire) {
        if (this.connectedWires.has(wire)) return;
        
        const self = this;
        const EXTENSION_NAME = 'pluribit_protocol_v2';

        wire.use(function(wire) {
            wire.on('extended', function(extensionName, buffer) {
                if (extensionName === EXTENSION_NAME) {
                    try {
                        const message = JSON.parse(buffer.toString());
                        self.handleWireMessage(message, wire);
                    } catch (e) {
                        console.error('[P2P] Failed to parse incoming wire message:', e);
                    }
                }
            });

            // Bootstrap new peers by sending them our current state.
            const syncMessage = {
                type: 'INDEX_SYNC',
                knownBlocks: Object.fromEntries(self.knownBlocks),
                knownSnapshots: Object.fromEntries(self.knownSnapshots)
            };
            self.sendWireMessage(wire, syncMessage, EXTENSION_NAME);
        });

        this.connectedWires.add(wire);
        wire.on('close', () => this.connectedWires.delete(wire));
    }

    /**
     * A low-level utility to send a JSON message to a specific peer.
     * @param {object} wire - The wire connection to send the message over.
     * @param {object} message - The JavaScript object to be sent.
     * @param {string} extensionName - The name of the wire protocol extension.
     */
    sendWireMessage(wire, message, extensionName = 'pluribit_protocol_v2') {
        if (wire.destroyed) return;
        try {
            wire.extended(extensionName, Buffer.from(JSON.stringify(message)));
        } catch (e) {
            console.error('[P2P] Failed to serialize and send wire message:', e);
        }
    }
    
    /**
     * The central router for all incoming custom P2P messages.
     * @param {object} message - The parsed JSON message from a peer.
     * @param {object} wire - The wire connection the message came from.
     */
    handleWireMessage(message, wire) {
        switch (message.type) {
            case 'INDEX_SYNC':
                // A peer sent its full index, let's sync up.
                for (const [heightStr, magnetURI] of Object.entries(message.knownBlocks)) {
                    const height = parseInt(heightStr);
                    if (!this.knownBlocks.has(height)) {
                        this.knownBlocks.set(height, magnetURI);
                        this.downloadBlock(height, magnetURI);
                    }
                }
                if (message.knownSnapshots) {
                    for (const [heightStr, snapshotInfo] of Object.entries(message.knownSnapshots)) {
                        const height = parseInt(heightStr);
                        if (!this.knownSnapshots.has(height)) {
                            this.knownSnapshots.set(height, snapshotInfo);
                            console.log(`[P2P] Discovered UTXO snapshot for height #${height}.`);
                        }
                    }
                }
                break;

            case 'BLOCK_ANNOUNCEMENT':
                // A peer announced a single new block.
                if (!this.knownBlocks.has(message.height)) {
                    this.knownBlocks.set(message.height, message.magnetURI);
                    this.downloadBlock(message.height, message.magnetURI);
                }
                break;

            case 'SNAPSHOT_ANNOUNCEMENT':
                 // A peer announced a single new UTXO snapshot.
                 if (!this.knownSnapshots.has(message.height)) {
                    this.knownSnapshots.set(message.height, message);
                    console.log(`[P2P] Received announcement for new UTXO snapshot at height ${message.height}.`);
                }
                break;

            case 'TRANSACTION':
            case 'CANDIDATE':
            case 'VOTE':
                // Delegate these messages to the main application logic in worker.js.
                const handler = this.handlers.get(message.type);
                if (handler) {
                    handler(message);
                } else {
                    console.warn(`[P2P] No handler registered for message type: ${message.type}`);
                }
                break;
            
            default:
                console.warn(`[P2P] Received unknown wire message type: ${message.type}`);
        }
    }

    /**
     * Creates and seeds a torrent for a new block, then announces it.
     * @param {object} block - The full block object to be seeded.
     * @returns {Promise<object>} A promise that resolves with the torrent object.
     */
    async seedBlock(block) {
        const blockData = Buffer.from(JSON.stringify(block));
        const file = new File([blockData], `block-${block.height}.json`, { type: 'application/json' });
        
        return new Promise((resolve) => {
            this.client.seed(file, { name: `pluribit-block-${block.height}`, announce: this.getTrackers() }, 
            (torrent) => {
                this.blockTorrents.set(block.height, torrent);
                this.knownBlocks.set(block.height, torrent.magnetURI);
                this.broadcast({ type: 'BLOCK_ANNOUNCEMENT', height: block.height, magnetURI: torrent.magnetURI });
                this.setupTorrentHandlers(torrent);
                resolve(torrent);
            });
        });
    }

    /**
     * Downloads a block from the network given its magnet URI.
     * @param {number} height - The height of the block to download.
     * @param {string} magnetURI - The magnet link for the block's torrent.
     */
    async downloadBlock(height, magnetURI) {
        if (this.blockTorrents.has(height) || this.pendingBlocks.has(height)) return;

        this.pendingBlocks.add(height);
        const torrent = this.client.add(magnetURI, { path: '/tmp/pluribit-blocks' });

        torrent.on('done', () => {
            this.pendingBlocks.delete(height);
            torrent.files[0].getBuffer((err, buffer) => {
                if (err) return console.error('[P2P] Failed to read downloaded block:', err);
                try {
                    const block = JSON.parse(buffer.toString());
                    this.blockTorrents.set(height, torrent);
                    const handler = this.handlers.get('BLOCK_DOWNLOADED');
                    if (handler) handler({ block });
                } catch (e) {
                    console.error('[P2P] Failed to parse downloaded block:', e);
                }
            });
        });

        torrent.on('error', (err) => {
            console.error(`[P2P] Error downloading block #${height}:`, err);
            this.pendingBlocks.delete(height);
        });
    }

    /**
     * Broadcasts a message to all currently connected peers.
     * @param {object} data - The message object to broadcast.
     */
    async broadcast(data) {
        const message = { ...data, timestamp: Date.now() };
        if (this.connectedWires.size === 0) return;
        this.connectedWires.forEach(wire => this.sendWireMessage(wire, message));
    }

    /**
     * Starts periodic tasks for network maintenance.
     */
    startPeriodicTasks() {
        this.peerDiscoveryInterval = setInterval(() => {
            const peerCount = this.getPeerCount();
            // This log is still useful for monitoring.
            console.log('[P2P] Connected to', peerCount, 'unique peers');
            
            // The WebTorrent client handles re-announcing automatically.
            // The manual loop was incorrect and has been removed.
            if (peerCount === 0) {
                console.log('[P2P] No peers currently connected. Client will continue to announce to trackers automatically.');
            }
        }, 30000);
    }
    
    /**
     * Allows the main application (worker.js) to register callback handlers for message types.
     * @param {string} type - The message type (e.g., 'TRANSACTION').
     * @param {function} handler - The function to call when a message of that type is received.
     */
    onMessage(type, handler) {
        this.handlers.set(type, handler);
    }

    /**
     * Gets the current number of unique connected peers.
     * @returns {number} The count of unique peers.
     */
    getPeerCount() {
        const uniquePeers = new Set();
        this.client.torrents.forEach(t => t.wires.forEach(w => uniquePeers.add(w.peerId.toString('hex'))));
        return uniquePeers.size;
    }

    /**
     * A simple error handler for non-critical WebRTC/tracker issues.
     * @param {Error} err - The error object.
     */
    handleError(err) {
        const msg = err.message || 'Unknown error';
        if (msg.includes('Ice connection failed') || msg.includes('Signaling server')) {
            console.warn('[P2P] A non-critical WebRTC/tracker connection issue occurred.');
        } else {
            console.error('[P2P] A critical WebTorrent error occurred:', err);
        }
    }

    /**
     * Gracefully stops the P2P client and all associated tasks.
     * @returns {Promise<void>}
     */
    async stop() {
        console.log('[P2P] Stopping P2P network...');
        if (this.peerDiscoveryInterval) clearInterval(this.peerDiscoveryInterval);
        if (this.client) {
            return new Promise(resolve => this.client.destroy(err => {
                if (err) console.error('[P2P] Error destroying client:', err);
                console.log('[P2P] WebTorrent client stopped');
                resolve();
            }));
        }
    }

    /**
     * Creates and seeds a torrent for a new UTXO snapshot, then announces it.
     * @param {object} snapshot - The full snapshot object.
     * @returns {Promise<string>} A promise that resolves with the snapshot's magnet URI.
     */
    async seedUTXOSnapshot(snapshot) {
        const compressed = pako.deflate(JSON.stringify(snapshot));
        const file = new File([compressed], `utxo-snapshot-${snapshot.height}.json.gz`, { type: 'application/gzip' });
        
        return new Promise((resolve) => {
            this.client.seed(file, { name: `pluribit-utxo-${snapshot.height}`, announce: this.getTrackers() }, 
            (torrent) => {
                const snapshotInfo = {
                    type: 'SNAPSHOT_ANNOUNCEMENT',
                    magnetURI: torrent.magnetURI,
                    height: snapshot.height,
                    utxo_count: snapshot.utxos.length,
                    timestamp: snapshot.timestamp,
                    merkle_root: snapshot.merkle_root
                };
                this.knownSnapshots.set(snapshot.height, snapshotInfo);
                this.broadcast(snapshotInfo);
                this.setupTorrentHandlers(torrent);
                resolve(torrent.magnetURI);
            });
        });
    }

    /**
     * Gets the height of the latest snapshot this peer knows about.
     * @returns {Promise<number>}
     */
    async getLatestSnapshotHeight() {
        if (this.knownSnapshots.size === 0) return 0;
        return Math.max(0, ...Array.from(this.knownSnapshots.keys()));
    }

    /**
     * Gets the metadata for a snapshot at a specific height.
     * @param {number} height - The height of the snapshot to look up.
     * @returns {Promise<object|null>} The snapshot metadata or null if not found.
     */
    async getUTXOSnapshotInfo(height) {
        return this.knownSnapshots.get(height) || null;
    }

    /**
     * Downloads and decompresses a UTXO snapshot torrent.
     * @param {number} height - The height of the snapshot to download.
     * @returns {Promise<object>} A promise that resolves with the parsed snapshot object.
     */
    async downloadUTXOSnapshot(height) {
        const snapshotInfo = this.knownSnapshots.get(height);
        if (!snapshotInfo) {
            throw new Error(`No metadata found for snapshot at height ${height}.`);
        }
        
        return new Promise((resolve, reject) => {
            const torrent = this.client.add(snapshotInfo.magnetURI, { path: '/tmp/pluribit-snapshots' });
            torrent.on('done', () => {
                torrent.files[0].getBuffer((err, buffer) => {
                    if (err) return reject(err);
                    try {
                        const decompressed = pako.inflate(buffer, { to: 'string' });
                        const snapshot = JSON.parse(decompressed);
                        resolve(snapshot);
                    } catch(e) {
                        reject(e);
                    }
                });
            });
            torrent.on('error', reject);
        });
    }
    
    /**
     * A utility function to generate a SHA1 hash.
     * @param {string} str - The input string.
     * @returns {string} The SHA1 hash as a hex string.
     */
    sha1(str) {
        return crypto.createHash('sha1').update(str).digest('hex');
    }

    /**
     * A utility function to compare two Uint8Arrays.
     * @param {Uint8Array} a - The first array.
     * @param {Uint8Array} b - The second array.
     * @returns {boolean} True if the arrays are equal.
     */
    arraysEqual(a, b) {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }
}

export default PluribitP2P;
