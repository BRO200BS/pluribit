import { createLibp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { webSockets } from '@libp2p/websockets';
import { webRTC } from '@libp2p/webrtc';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { circuitRelayTransport, circuitRelayServer } from '@libp2p/circuit-relay-v2';
import { mdns } from '@libp2p/mdns' 
import { dcutr } from '@libp2p/dcutr';
import { multiaddr } from '@multiformats/multiaddr';
import { CONFIG } from './config.js';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import * as raw from 'multiformats/codecs/raw';
import { pipe } from 'it-pipe';
import { kadDHT } from '@libp2p/kad-dht';
import { gossipsub } from '@chainsafe/libp2p-gossipsub';
import { bootstrap } from '@libp2p/bootstrap';
import { identify } from '@libp2p/identify';
import { ping } from '@libp2p/ping'; 
import { createEd25519PeerId, createFromPubKey, createFromPrivKey } from '@libp2p/peer-id-factory';
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string';
import { toString as uint8ArrayToString } from 'uint8arrays/to-string';
import bridge from './js_bridge.cjs';
import crypto from 'crypto';
import nacl from 'tweetnacl';
import fs from 'fs/promises';
import path from 'path';

// Rationale: In an ES Module project, CommonJS files must be loaded using `createRequire`.
// By naming the generated file with a .cjs extension, we ensure Node.js always
// treats it as a CommonJS module, making the require() call succeed.
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { p2p } = require('./src/p2p_pb.cjs');
const { Block } = p2p;
export { Block as P2PBlock, p2p };




// ---- Signing helpers (stable stringify + sha256) ----
/**
 * @param {any} obj
 * @returns {string}
 */
function stableStringify(obj) {
  const seen = new WeakSet();
  /**
   * @param {any} v
   * @returns {any}
   */
  const walk = (v) => {
    if (v && typeof v === 'object') {
      if (seen.has(v)) return null;
      seen.add(v);
      if (Array.isArray(v)) return v.map(walk);
      /** @type {Record<string, any>} */
      const out = {};
      for (const k of Object.keys(v).sort()) out[k] = walk(v[k]);
      return out;
    }
    return v;
  };
  return JSON.stringify(walk(obj));
}

/**
 * @param {string} inputUtf8
 * @returns {string}
 */
function sha256Hex(inputUtf8) {
  return crypto.createHash('sha256').update(inputUtf8, 'utf8').digest('hex');
}

// Network scoping to prevent cross-talk between networks
const NET = process.env.PLURIBIT_NET || 'mainnet';

// Topic definitions
export const TOPICS = {
  BLOCKS: `/pluribit/${NET}/blocks/1.0.0`,
  TRANSACTIONS: `/pluribit/${NET}/transactions/1.0.0`,
  BLOCK_REQUEST: `/pluribit/${NET}/block-request/1.0.0`,
  SYNC: `/pluribit/${NET}/sync/1.0.0`,   
  GET_HASHES_REQUEST: `/pluribit/${NET}/get-hashes-request/1.0.0`,
  HASHES_RESPONSE: `/pluribit/${NET}/hashes-response/1.0.0`,
  BLOCK_ANNOUNCEMENTS: `/pluribit/${NET}/block-announcements/1.0.0`,
  DANDELION_STEM: `/pluribit/${NET}/dandelion-stem/1.0.0`,
  CHANNEL_PROPOSE: `/pluribit/${NET}/channel-propose/1.0.0`,
  CHANNEL_ACCEPT: `/pluribit/${NET}/channel-accept/1.0.0`,
  CHANNEL_FUND_NONCE: `/pluribit/${NET}/channel-fund-nonce/1.0.0`,
  CHANNEL_FUND_SIG: `/pluribit/${NET}/channel-fund-sig/1.0.0`,
  CHANNEL_PAY_PROPOSE: `/pluribit/${NET}/channel-pay-propose/1.0.0`,
  CHANNEL_PAY_ACCEPT: `/pluribit/${NET}/channel-pay-accept/1.0.0`,
  CHANNEL_CLOSE_NONCE: `/pluribit/${NET}/channel-close-nonce/1.0.0`,
  CHANNEL_CLOSE_SIG: `/pluribit/${NET}/channel-close-sig/1.0.0`,
  SWAP_PROPOSE: `/pluribit/${NET}/swap-propose/1.0.0`,
  SWAP_RESPOND: `/pluribit/${NET}/swap-respond/1.0.0`,
  SWAP_ALICE_ADAPTOR_SIG: `/pluribit/${NET}/swap-alice-sig/1.0.0`
};

export class PluribitP2P {
    /**
     * @param {(msg: string, level?: string) => void} log
     * @param {{ isBootstrap?: boolean, tcpPort?: number, wsPort?: number }} options
     */
    constructor(log, options = {}) {
        this._peerVerificationState = new Map(); // peerId -> { powSolved: bool, isSubscribed: bool }
        this.log = log;
        this.node = null;
        this.handlers = new Map();
        this.isBootstrap = options.isBootstrap || (process.env.PLURIBIT_IS_BOOTSTRAP === 'true');
        this._peerChallenges = new Map(); // peer -> {challenge, timestamp, attempts}
        this._maxChallengeAttempts = 3;
        this._challengeDifficulty = '00000'; // Require 5 leading zeros in PoW (i.e. 1 in 16^5, or 1 in 1,048,576 hashes)
        // Periodic cleanup of stale challenges to prevent memory leak
        this._challengeGcTimer = setInterval(() => {
            const now = Date.now();
            for (const [peerId, challenge] of this._peerChallenges) {
                if (now - challenge.timestamp > 120000) { // 2 minutes
                    this._peerChallenges.delete(peerId);
                }
            }
        }, 60000); // Run every minute
        this.config = {
          listen: {
            tcp: options.tcpPort || 26658,
            ws: options.wsPort || 26659
          },
          bootstrap: this.isBootstrap ? [] : [
            // Public IPFS/libp2p bootstrappers (DNSADDR -> stable peer IDs)
            '/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN',
            '/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa',
            '/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb',
            '/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt',
            '/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ'
          ]
        };
        
        // Dandelion state
        this._stemRelay = null; // Current stem relay peer
        this._stemRelayRefreshTimer = null;
        this._embargoedTransactions = new Map(); // txHash -> embargo timer
        this._stemRelayLastRefresh = 0;
        
        // Track which transactions we've seen in stem phase
        this._seenStemTransactions = new Set();
    }
    
    /**
     * Select a random verified peer for stem relay
     * @private
     * @returns {string | null} Peer ID or null if none available
     */
    _selectStemRelay() {
        if (!this.node) return null;
        
        const verifiedPeers = this.getConnectedPeers()
            .filter(p => this.isPeerVerified(p.id))
            .map(p => p.id);
        
        if (verifiedPeers.length === 0) return null;
        
        // Random selection
        const randomIndex = Math.floor(Math.random() * verifiedPeers.length);
        return verifiedPeers[randomIndex];
    }

    /**
     * Refresh the stem relay peer periodically
     * @private
     */
    _refreshStemRelay() {
        const now = Date.now();
        if (now - this._stemRelayLastRefresh < CONFIG.DANDELION.STEM_RELAY_REFRESH_INTERVAL_MS) {
            return;
        }
        
        this._stemRelay = this._selectStemRelay();
        this._stemRelayLastRefresh = now;
        
        if (this._stemRelay) {
            this.log(`[Dandelion] Selected new stem relay: ${this._stemRelay.slice(-6)}`, 'debug');
        }
    }

    /**
     * Compute transaction hash for deduplication
     * @private
     * @param {any} transaction
     * @returns {string}
     */
    _getTxHash(transaction) {
        // Use the kernel excess as a unique identifier
        if (transaction.kernels && transaction.kernels[0]?.excess) {
            return Buffer.from(transaction.kernels[0].excess)
                .toString('hex')
                .substring(0, 16);
        }
        // Fallback: hash the entire transaction
        return crypto.createHash('sha256')
            .update(JSON.stringify(transaction))
            .digest('hex')
            .substring(0, 16);
    }

    /**
     * Initiate Dandelion stem phase for a transaction
     * @param {any} transaction - The transaction object
     * @returns {Promise<void>}
     */
    async stemTransaction(transaction) {
        if (!CONFIG.DANDELION.ENABLED) {
            // Dandelion disabled, just broadcast normally
            await this.publish(TOPICS.TRANSACTIONS, transaction);
            return;
        }

        this._refreshStemRelay();
        
        const stemRelay = this._stemRelay;
        if (!stemRelay) {
            this.log('[Dandelion] No stem relay available, broadcasting directly', 'warn');
            await this.publish(TOPICS.TRANSACTIONS, transaction);
            return;
        }

        const txHash = this._getTxHash(transaction);
        
        // Create stem message
        const stemMessage = {
            transaction: transaction,
            hopCount: 0,
            timestamp: Date.now()
        };

        try {
            // Send via direct protocol instead of gossip
            await this._sendStemDirect(stemRelay, stemMessage);
            this.log(`[Dandelion] Sent transaction ${txHash} to stem relay ${stemRelay.slice(-6)}`, 'info');
        } catch (e) {
            this.log(`[Dandelion] Stem send failed: ${e.message}, falling back to broadcast`, 'warn');
            await this.publish(TOPICS.TRANSACTIONS, transaction);
        }
    }

    /**
     * Send a stem transaction directly to a peer
     * @private
     * @param {string} peerId
     * @param {any} stemMessage
     * @returns {Promise<void>}
     */
    async _sendStemDirect(peerId, stemMessage) {
        if (!this.node) throw new Error('Node not initialized');
        
        
        try {
            const connection = this.node.getConnections().find(
                c => c.remotePeer.toString() === peerId
            );
            
            if (!connection) {
                throw new Error(`No connection to peer ${peerId}`);
            }

            const stream = await connection.newStream(TOPICS.DANDELION_STEM);
            
            // Encode the stem message
            const encoded = p2p.DandelionStem.encode(stemMessage).finish();
            
            await pipe([encoded], stream.sink);
            
        } catch (e) {
            throw new Error(`Direct stem send failed: ${e.message}`);
        }
    }

    /**
     * Decide whether to continue stem or switch to fluff
     * @private
     * @param {number} hopCount
     * @returns {boolean} true if should continue stem, false if should fluff
     */
    _shouldContinueStem(hopCount) {
        // Force fluff if we've exceeded max hops
        if (hopCount >= CONFIG.DANDELION.MAX_STEM_HOPS) {
            return false;
        }
        
        // Require minimum hops
        if (hopCount < CONFIG.DANDELION.MIN_STEM_HOPS) {
            return true;
        }
        
        // Probabilistic decision
        return Math.random() < CONFIG.DANDELION.STEM_PROBABILITY;
    }

    /**
     * Handle an incoming stem-phase transaction
     * @private
     * @param {any} stemMessage
     * @param {string} from - Peer ID who sent this
     * @returns {Promise<void>}
     */
    async _handleStemTransaction(stemMessage, from) {
        const { transaction, hopCount, timestamp } = stemMessage;
        const txHash = this._getTxHash(transaction);

        // Immediately publish locally via gossipsub to add to our own mempool.
        // The existing TOPICS.TRANSACTIONS handler will process this due to emitSelf: true.
        // This ensures the transaction is in the pool before block selection, fixing the race condition.
        try {
            await this.publish(TOPICS.TRANSACTIONS, transaction);
            this.log(`[Dandelion] Published received stem tx ${txHash} locally for mempool add`, 'debug');
        } catch (e) {
            this.log(`[Dandelion] Failed local publish for stem tx ${txHash}: ${e.message}`, 'warn');
            // Don't necessarily stop Dandelion relay just because local add failed (it might already be there)
        }

        // Deduplication: ignore if we've already seen this transaction
        if (this._seenStemTransactions.has(txHash)) {
            this.log(`[Dandelion] Ignoring duplicate stem transaction ${txHash}`, 'debug');
            return;
        }
        
        this._seenStemTransactions.add(txHash);
        
        // Clean up old entries (prevent memory leak)
        if (this._seenStemTransactions.size > 10000) {
            const oldestEntries = Array.from(this._seenStemTransactions).slice(0, 5000);
            oldestEntries.forEach(hash => this._seenStemTransactions.delete(hash));
        }
        
        // Check embargo timeout
        const age = Date.now() - timestamp;
        if (age > CONFIG.DANDELION.EMBARGO_TIMEOUT_MS) {
            this.log(`[Dandelion] Transaction ${txHash} exceeded embargo, fluffing`, 'info');
            await this.publish(TOPICS.TRANSACTIONS, transaction);
            return;
        }
        
        // Decide: continue stem or switch to fluff?
        if (this._shouldContinueStem(hopCount)) {
            // Continue stem phase
            this._refreshStemRelay();
            const nextRelay = this._stemRelay;
            
            if (!nextRelay || nextRelay === from) {
                // No relay available or would send back to sender -> fluff instead
                // Fluffing is now implicitly handled by the initial local publish.
                // No further action needed here if we decide not to stem.
                 return;
            }
            
            const nextStemMessage = {
                transaction: transaction,
                hopCount: hopCount + 1,
                timestamp: timestamp
            };
            
            try {
                await this._sendStemDirect(nextRelay, nextStemMessage);
                this.log(`[Dandelion] Relayed stem transaction ${txHash} (hop ${hopCount + 1})`, 'debug');
            } catch (e) {
                // If stem relay fails, the initial local publish acts as the fallback fluff.
                this.log(`[Dandelion] Stem relay failed, fluffing: ${e.message}`, 'warn');
            }
        } else {
            // Switch to fluff phase
            this.log(`[Dandelion] Fluffing transaction ${txHash} after ${hopCount} hops`, 'info');
            // Fluffing is now implicitly handled by the initial local publish.
            // No further action needed here.
        }
    }   
    
    
    /**
     * @param {string} peerId
     * @param {{ powSolved?: boolean, isSubscribed?: boolean }} param1
     * @returns {boolean}
     */
    _updateVerificationState(peerId, { powSolved, isSubscribed }) {
        const state = this._peerVerificationState.get(peerId) || { 
            powSolved: false, 
            isSubscribed: false,
            firstSeen: Date.now()
        };
        const wasVerified = state.powSolved && state.isSubscribed;

        if (powSolved !== undefined) state.powSolved = powSolved;
        if (isSubscribed !== undefined) state.isSubscribed = isSubscribed;

        const isNowVerified = state.powSolved && state.isSubscribed;    
        
        this._peerVerificationState.set(peerId, state);

        if (isNowVerified && !wasVerified) {
            this.log(`[P2P] ✅ Fully Verified Peer: ${peerId}`, 'success');        
            // RATIONALE: When a peer becomes fully verified, it's a strong signal
            // that we should check if their chain is better than ours. This is a
            // much more reliable trigger for initiating a sync than the noisy
            // 'subscription-change' event.
            try {
                if (this.node) {
                    this.node.dispatchEvent(new CustomEvent('pluribit:peer-verified', { detail: peerId }));
                }
            } catch (e) {
                const err = /** @type {Error} */ (e);
                this.log(`[P2P] Error dispatching peer-verified event: ${err.message}`, 'warn');
            }       
        }
        
        // Return true if verified 
        return isNowVerified ;
    }


    /**
     * Send challenge to peer
     * @param {string} peerId
     * @returns {Promise<boolean>}
     */
    async sendDirectChallenge(peerId) {
        try {
            const challenge = crypto.randomBytes(32).toString('hex');
            
            this._peerChallenges.set(peerId, {
                challenge,
                timestamp: Date.now(),
                attempts: 0
            });
            
            if (!this.node) throw new Error('Node not initialized');
            
            const connections = this.node.getConnections();
            const connection = connections.find(c => c.remotePeer.toString() === peerId);
            if (!connection) throw new Error('No connection to peer');
            
            const stream = await connection.newStream('/pluribit/challenge/1.0.0');
            
            const message = p2p.Challenge.create({ challenge, from: this.node.peerId.toString() });
            const encodedMessage = p2p.Challenge.encode(message).finish();
            
            await pipe([encodedMessage], stream.sink);
            
            const chunks = [];
            for await (const chunk of stream.source) {
                chunks.push(chunk.subarray());
            }
            const responseBuffer = Buffer.concat(chunks);
            // @ts-ignore - protobuf decode signature varies
            const response = p2p.ChallengeResponse.decode(responseBuffer);
           
            const verify = crypto.createHash('sha256')
                .update(challenge)
                // @ts-ignore - protobuf message property access
                .update(response.nonce || '')
                .digest('hex');
            
            // @ts-ignore - protobuf message property access
            if (verify === response.solution && (response.solution || '').startsWith(this._challengeDifficulty)) {
                this._updateVerificationState(peerId, { powSolved: true, isSubscribed: undefined });
                this._peerChallenges.delete(peerId);
                this.log(`[P2P] ✓ Peer ${peerId} solved challenge`, 'success');
                return true;
            }
            
            return false;
        } catch (e) {
            const err = /** @type {Error} */ (e);
            const msg = err?.message || '';
            const isExpected = /protocol selection failed|No connection to peer/i.test(msg);
            const logLevel = isExpected ? 'debug' : 'error';
            this.log(`[P2P] Failed to send challenge to ${peerId}: ${msg}`, logLevel);
            return false;
        }
    }


    /**
     * @param {import('@libp2p/interface').PeerId} id
     * @param {import('@multiformats/multiaddr').Multiaddr[]} multiaddrs
     * @returns {Promise<void>}
     */
    async _addToAddressBookCompat(id, multiaddrs) {
        if (!this.node) return;
        const ps = this.node.peerStore;
        if (!ps || !multiaddrs?.length) return;

        try {
            // @ts-ignore - addressBook API varies across libp2p versions
            if (ps.addressBook?.add) {
                // @ts-ignore
                return await ps.addressBook.add(id, multiaddrs);
            }
            // @ts-ignore
            if (ps.addressBook?.set) {
                // @ts-ignore
                return await ps.addressBook.set(id, multiaddrs);
            }
            // @ts-ignore
            if (ps.merge) {
                // @ts-ignore
                return await ps.merge(id, { multiaddrs });
            }
            // @ts-ignore
            if (ps.patch) {
                // @ts-ignore
                return await ps.patch(id, { multiaddrs });
            }
            this.log('[P2P] No compatible addressBook API found', 'debug');
        } catch (e) {
            const err = /** @type {Error} */ (e);
            const isAbort = err?.name === 'AbortError' || /aborted/i.test(err?.message || '');
            this.log(`[P2P] address book update ${isAbort ? 'aborted' : 'failed'} for ${id.toString()}: ${err?.message || err}`, isAbort ? 'debug' : 'warn');
        }
    }


    // Simple per-peer token bucket
    _buckets = new Map();
    _dhtSeen = new Map();  // nsKey -> last accepted timestamp
    /** @type {any} */
    _bucketGcTimer = null;
    
    /**
     * @param {string} from
     * @returns {boolean}
     */
    _allowMessage(from) {
        const now = Date.now();
        const windowMs = CONFIG.RATE_LIMIT_WINDOW;
        const cap = CONFIG.RATE_LIMIT_MESSAGES;

        let b = this._buckets.get(from);
        if (!b) {
            b = { tokens: cap, windowStart: now };
            this._buckets.set(from, b);
        }

        // refill per window
        if (now - b.windowStart >= windowMs) {
            b.tokens = cap;
            b.windowStart = now;
        }

        b.last = now;
        if (b.tokens <= 0) return false;
        b.tokens -= 1;
        return true;
    }

    _rendezvousStr = process.env.PLURIBIT_RENDEZVOUS || 'pluribit:mainnet:v1';
    /** @type {CID | null} */
    _rendezvousCid = null;
    /** @type {any} */
    _rendezvousTimer = null;


    /**
     * @param {CID} cid
     * @returns {Promise<boolean>}
     */
    async _provideCompat(cid) {
        if (!this.node) return false;
        const cr = this.node.contentRouting;
        if (cr?.provide) {
            const ret = cr.provide(cid);
            // @ts-ignore - check if it's an async iterator
            if (ret?.[Symbol.asyncIterator]) {
                // @ts-ignore
                for await (const _ of ret) {} // drain
            } else {
                await ret; // Promise<void> or undefined
            }
            return true;
        }
        // @ts-ignore - dht service API varies
        const dht = this.node.services?.dht;
        // @ts-ignore
        if (dht?.provide) { 
            // @ts-ignore
            await dht.provide(cid); 
            return true; 
        }
        return false;
    }

    /**
     * @param {CID} cid
     * @param {{ timeout?: number }} opts
     * @returns {Promise<Array<any>>}
     */
    async _findProvidersCompat(cid, opts) {
        /** @type {Array<any>} */
        const out = [];
        if (!this.node) return out;
        const cr = this.node.contentRouting;
        if (cr?.findProviders) {
            // @ts-ignore - findProviders signature varies
            const res = cr.findProviders(cid, opts);
            // @ts-ignore - check if it's an async iterator
            if (res?.[Symbol.asyncIterator]) {
                // @ts-ignore
                for await (const p of res) out.push(p);
            } else {
                const arr = await res; // some versions return Promise<Provider[]>
                if (Array.isArray(arr)) out.push(...arr);
            }
            return out;
        }
        // @ts-ignore - dht service API varies
        const dht = this.node.services?.dht;
        // @ts-ignore
        if (dht?.findProviders) {
            // @ts-ignore
            for await (const p of dht.findProviders(cid, opts)) out.push(p);
        }
        return out;
    }



    /**
     * @returns {Promise<CID>}
     */
    async _getRendezvousCID() {
        if (this._rendezvousCid) return this._rendezvousCid;
        const bytes = new TextEncoder().encode(this._rendezvousStr);
        const digest = await sha256.digest(bytes);
        this._rendezvousCid = CID.createV1(raw.code, digest);
        return this._rendezvousCid;
    }

    async _announceAndDiscoverProviders() {
        try {
            const cid = await this._getRendezvousCID();

            // Announce
            try {
                const ok = await this._provideCompat(cid);
                if (ok) this.log(`[P2P] 📣 Provided rendezvous CID ${cid.toString()}`);
            } catch (e) {
                const err = /** @type {Error} */ (e);
                const isAbort = err?.name === 'AbortError' || /aborted/i.test(err?.message || '');
                this.log(`[P2P] Provide ${isAbort ? 'aborted' : 'error'}: ${err?.message || err}`, isAbort ? 'debug' : 'warn');
            }

            // Discover (with a timeout)
            let providers = await this._findProvidersCompat(cid, { timeout: 15_000 });

            if (!this.node) return;
            const myId = this.node.peerId.toString();
            for (const p of providers) {
                const id = p.id?.toString?.();
                if (!id || id === myId) continue;

                const connections = this.node.getConnections();
                const already = connections.some(c => c.remotePeer.toString() === id);
                if (!already) {
                    try {
                        if (p.multiaddrs?.length) {
                            await this._addToAddressBookCompat(p.id, p.multiaddrs);
                        }
                        await this.node.dial(p.id);
                        
                        // The peer:connect event will handle challenging
                        this.log(`[P2P] 🔌 Connected to rendezvous provider ${id}`);
                        
                    } catch (e) {
                        const err = /** @type {Error} */ (e);
                        const isAbort = err?.name === 'AbortError' || /aborted/i.test(err?.message || '');
                        this.log(`[P2P] Rendezvous dial ${isAbort ? 'aborted' : 'failed'}: ${id} – ${err?.message || err}`, isAbort ? 'debug' : 'warn');
                    }
                }
            }
        } catch (e) {
            const err = /** @type {Error} */ (e);
            this.log(`[P2P] Rendezvous error: ${err?.message || err}`, 'warn');
        }
    }



    async initialize() {
        this.log('[P2P] Initializing libp2p node...');
        
        // --- START MODIFICATION ---
        const NET = process.env.PLURIBIT_NET || 'mainnet';
        
        if (NET === 'testnet') {
            // 1. Try to load TESTNET config
            try {
                const fs = await import('fs/promises');
                const configData = await fs.readFile('./bootstrap.testnet.json', 'utf-8');
                const config = JSON.parse(configData);
                if (config.bootstrapNodes && config.bootstrapNodes.length > 0) {
                     this.config.bootstrap = config.bootstrapNodes;
                    this.log('[P2P] Loaded TESTNET bootstrap addresses from config');
                }
            } catch (err) {
                this.log('[P2P] TESTNET: No bootstrap.testnet.json found, using defaults', 'warn');
            }
        } else if (!this.isBootstrap) {
            // 2. Try to load MAINNET config
            try {
                const fs = await import('fs/promises');
                const configData = await fs.readFile('./bootstrap-config.json', 'utf-8');
                const config = JSON.parse(configData);
                if (config.bootstrapNodes && config.bootstrapNodes.length > 0) {
                   this.config.bootstrap = config.bootstrapNodes;
                    this.log('[P2P] Loaded bootstrap addresses from config');
                }
            } catch (err) {
                this.log('[P2P] No bootstrap config found, using defaults', 'warn');
            }
        }
        // --- END MODIFICATION ---


    const peerId = await this.loadOrCreatePeerId();
    
    this.log(`[P2P DEBUG] loadOrCreatePeerId returned: ${peerId.toString()}`, 'debug');
    this.log(`[P2P DEBUG] privateKey length: ${peerId.privateKey?.length}`, 'debug');
    
    // Import the keys module to unmarshal the private key
    const keys = await import('@libp2p/crypto/keys');
    
    // Unmarshal the private key bytes to get a proper PrivateKey object
    let privateKeyObj;
    try {
        // Try the protobuf unmarshalling
        privateKeyObj = keys.privateKeyFromProtobuf(peerId.privateKey);
    } catch (e) {
        // If that fails, try the supportedKeys approach
        this.log(`[P2P DEBUG] protobuf unmarshal failed, trying supportedKeys: ${e.message}`, 'debug');
        const { supportedKeys } = keys;
        privateKeyObj = await supportedKeys.ed25519.unmarshalEd25519PrivateKey(peerId.privateKey);
    }
    
    this.log(`[P2P DEBUG] Unmarshalled key type: ${privateKeyObj.type}`, 'debug');
    
    // Create libp2p node
    this.node = await createLibp2p({
        privateKey: privateKeyObj,  // Pass the proper key object
        addresses: {
            listen: [
                `/ip4/0.0.0.0/tcp/${this.config.listen.tcp}`,
                `/ip4/0.0.0.0/tcp/${this.config.listen.ws}/ws`
            ]
        },
            transports: [
                tcp(),
                webSockets(),
                webRTC(),
                // Conditionally configure relay client
                circuitRelayTransport({
                    discoverRelays: this.isBootstrap ? 0 : 1
                })
            ],
            connectionEncrypters: [noise()],
            streamMuxers: [yamux()],
            services: {
                // Conditionally enable the relay server for bootstrap nodes
                ...(this.isBootstrap && { relay: circuitRelayServer() }),

                identify: identify(),
                dht: kadDHT({
                    // Use the public IPFS DHT protocol so we can use content routing on the open network
                    protocol: '/ipfs/kad/1.0.0',
                    clientMode: !this.isBootstrap,
                    // @ts-ignore - validators API varies across versions
                    validators: {
                        pluribit: {
                            // @ts-ignore
                            validate: (/** @type {any} */ key, /** @type {any} */ value) => {
                                try {
                                    const data = JSON.parse(uint8ArrayToString(value));
                                    return data.type === 'pluribit' && data.timestamp;
                                } catch {
                                    return false;
                                }
                            }
                        }
                    }
                }),

                pubsub: gossipsub({
                    // @ts-ignore - option name varies by version
                    allowPublishToZeroTopicPeers: true,
                    emitSelf: true,
                }),
                ping: ping(),
                dcutr: dcutr(),
            },
            peerDiscovery: this.config.bootstrap.length > 0 
                ?
                [
                    bootstrap({
                        list: this.config.bootstrap,
                        // @ts-ignore - interval/timeout options may not exist in all versions
                        interval: 30000,
                        timeout: 30000
                    }),
                    mdns() 
                ]
                : [mdns()],
            connectionManager: {
                // @ts-ignore - connection manager options vary by version
                minConnections: CONFIG.P2P.MIN_CONNECTIONS,
                maxConnections: CONFIG.P2P.MAX_CONNECTIONS, 
                autoDial: true,
                autoDialInterval: 2000, 
                maxParallelDials: 10,
                dialTimeout: 30000      
            }
        });

        // Setup event handlers
        this.setupEventHandlers();
        
        // Start the node
        await this.node.start();
        this.log(`[P2P] Node started with ID: ${this.node.peerId.toString()}`);
this.log(`[P2P DEBUG] Node peerId matches loaded peerId: ${this.node.peerId.toString() === peerId.toString()}`, 'debug');
if (this.node.peerId.toString() !== peerId.toString()) {
    this.log(`[P2P ERROR] MISMATCH! Loaded: ${peerId.toString()}, Node using: ${this.node.peerId.toString()}`, 'error');
}
        // Self-verify for loopback messages (emitSelf: true in gossipsub)
        this._updateVerificationState(this.node.peerId.toString(), { 
            powSolved: true, 
            isSubscribed: true 
        });

        // Register custom protocol for direct challenge-response
        const CHALLENGE_PROTOCOL = '/pluribit/challenge/1.0.0';

        await this.node.handle(CHALLENGE_PROTOCOL, async ({ stream, connection }) => {
            try {
                const chunks = [];
                for await (const chunk of stream.source) {
                    chunks.push(chunk.subarray());
                }
                // Decode the Protobuf 'Challenge' message
                const buffer = Buffer.concat(chunks);
                // @ts-ignore - protobuf decode signature
                const data = p2p.Challenge.decode(buffer);
                
                // @ts-ignore - protobuf message property access
                const { challenge, from } = data;
                const difficulty = this._challengeDifficulty;
                let nonce = 0;
                let solution = '';
                
                while (true) {
                    solution = crypto.createHash('sha256')
                        .update(challenge || '')
                        .update(String(nonce))
                        .digest('hex');
                    if (solution.startsWith(difficulty)) {
                        break;
                    }
                    nonce++;
                }
                
                // Create and encode the Protobuf 'ChallengeResponse' message
                const response = p2p.ChallengeResponse.create({
                    solution,
                    nonce: String(nonce),
                    from: this.node ? this.node.peerId.toString() : ''
                });
                const encodedResponse = p2p.ChallengeResponse.encode(response).finish();
                
                await pipe([encodedResponse], stream.sink);
                
                // We can use 'from' directly from the message payload
                this.log(`[P22P] Solved challenge from ${from} with nonce ${nonce}`, 'info');
            } catch (e) {
                const err = /** @type {Error} */ (e);
                this.log(`[P2P] Error handling challenge protocol: ${err.message}`, 'error');
            }
        });      
        
        // Register protocol for direct block transfers
        const BLOCK_TRANSFER_PROTOCOL = `/pluribit/${NET}/block-transfer/1.0.0`;
        await this.node.handle(BLOCK_TRANSFER_PROTOCOL, async ({ stream, connection }) => {
            try {
                const peerId = connection.remotePeer.toString();
                
                // CRITICAL: Require verified peer
                if (!this.isPeerVerified(peerId)) {
                    this.log(`[P2P] Denying block transfer from unverified peer ${peerId}`, 'warn');
                    try { await stream.close(); } catch {}
                    return;
                }
                
                // Rate limiting
                if (!this._allowMessage(peerId)) {
                    this.log(`[P2P] Rate limited block transfer from ${peerId}`, 'warn');
                    try { await stream.close(); } catch {}
                    return;
                }
                        
                const chunks = [];
                for await (const chunk of stream.source) {
                    chunks.push(chunk.subarray());
                }
                const buffer = Buffer.concat(chunks);
                // @ts-ignore - protobuf decode signature
                const request = p2p.DirectBlockRequest.decode(buffer);
                
                // @ts-ignore - protobuf message property access
                if (!request.hash || !/^[0-9a-f]{64}$/i.test(request.hash)) {
                    const errResp = p2p.BlockTransferResponse.create({ errorReason: 'INVALID_HASH' });
                    await pipe([p2p.BlockTransferResponse.encode(errResp).finish()], stream.sink);
                    return;
                }
                
                const handlers = this.handlers.get(BLOCK_TRANSFER_PROTOCOL) || [];
                for (const handler of handlers) {
                    // @ts-ignore - protobuf message property access
                    const block = await handler(request.hash);
                    if (block) {
                        // Protobuf.js handles BigInts correctly when creating the message
                        const response = p2p.BlockTransferResponse.create({ blockData: block });
                        const encodedResponse = p2p.BlockTransferResponse.encode(response).finish();
                        await pipe([encodedResponse], stream.sink);
                        return;
                    }
                }
                
                // Not found
                const errResp = p2p.BlockTransferResponse.create({ errorReason: 'NOT_FOUND' });
                await pipe([p2p.BlockTransferResponse.encode(errResp).finish()], stream.sink);

            } catch (e) {
                const err = /** @type {Error} */ (e);
                this.log(`[P2P] Error handling block transfer protocol: ${err.message}`, 'error');
            }
        });
        

        
        await this.node.handle(TOPICS.DANDELION_STEM, async ({ stream, connection }) => {
            const peerId = connection.remotePeer.toString(); // Get PeerID early for logging
            this.log(`[Dandelion] Received incoming STEM connection from ${peerId.slice(-6)}`, 'debug'); // Log connection
            try {
                
                // Require verified peer
                if (!this.isPeerVerified(peerId)) {
                    this.log(`[Dandelion] Rejecting stem from unverified peer ${peerId.slice(-6)}`, 'warn'); //
                    try { await stream.close(); } catch {}
                    return;
                }
                
                // Rate limiting
                if (!this._allowMessage(peerId)) {
                    this.log(`[Dandelion] Rate limited stem from ${peerId.slice(-6)}`, 'warn'); //
                    try { await stream.close(); } catch {}
                    return;
                }
                
                const chunks = [];
                for await (const chunk of stream.source) {
                    chunks.push(chunk.subarray());
                }
                const buffer = Buffer.concat(chunks);
                const stemMessage = p2p.DandelionStem.decode(buffer);

                const txHash = this._getTxHash(stemMessage.transaction); // Get hash for logging
                this.log(`[Dandelion] Decoded stem message for tx ${txHash} from ${peerId.slice(-6)}`, 'debug'); // Log successful decode

                await this._handleStemTransaction(stemMessage, peerId);
                
            } catch (e) {
                const err = /** @type {Error} */ (e);
                this.log(`[Dandelion] Error handling stem protocol from ${peerId.slice(-6)}: ${err.message}`, 'error'); //
            }
        });
        
        // Start periodic stem relay refresh
        this._stemRelayRefreshTimer = setInterval(() => {
            this._refreshStemRelay();
        }, CONFIG.DANDELION.STEM_RELAY_REFRESH_INTERVAL_MS);
        
        
        const addrs = this.node.getMultiaddrs();
        addrs.forEach(addr => this.log(`[P2P] Listening on ${addr.toString()}`));

        // Proactively dial bootstrap peers once
        if (!this.isBootstrap && Array.isArray(this.config.bootstrap) && this.config.bootstrap.length) {
            const tasks = this.config.bootstrap.map(async (addr) => {
                try {
                    if (!this.node) return;
                    await this.node.dial(multiaddr(addr));
                    this.log(`[P2P] 🔌 Dialed bootstrap ${addr}`);
                } catch (e) {
                    const err = /** @type {Error} */ (e);
                    this.log(`[P2P] Could not dial bootstrap ${addr}: ${err.message}`, 'warn');
                }
            });
            await Promise.allSettled(tasks);
        }

        // Start DHT (guard in case libp2p already started it)
        try {
            // @ts-ignore - dht API varies
            if (this.node.services.dht?.isStarted?.() === false) {
                // @ts-ignore
                await this.node.services.dht.start();
            }
        } catch { /* ignore if already started */ }
        
        // Light GC for rate-limit buckets to bound memory
        this._bucketGcTimer = setInterval(() => {
            const now = Date.now();
            for (const [k, b] of this._buckets) {
                if ((now - (b.last || b.windowStart)) > 15 * 60_000) this._buckets.delete(k);
            }
        }, 5 * 60_000);
        
        // Zero-infra rendezvous: announce & discover via public DHT provider records
        await this._announceAndDiscoverProviders();
        this._rendezvousTimer = setInterval(() => {
            this._announceAndDiscoverProviders().catch((e) => {
                const err = /** @type {Error} */ (e);
                const isAbort = err?.name === 'AbortError' || /aborted/i.test(err?.message || '');
                this.log(`[P2P] Rendezvous ${isAbort ? 'aborted (timeout/cancel)' : 'failed'}: ${err?.message || err}`, isAbort ? 'debug' : 'warn');
            });
        }, 10 * 60 * 1000); //every 10 mins
        
        return this.node;
    }

async loadOrCreatePeerId() {
    const peerIdPath = './pluribit-data/peer-id.json';

    // --- BOOTSTRAP: Load permanent key from file ---
    if (this.isBootstrap) {
        this.log('[P2P] Attempting to load permanent bootstrap PeerID from file...');
        try {
            const data = await fs.readFile(peerIdPath, 'utf-8');
            const stored = JSON.parse(data);
            
            // Import the marshalled key using libp2p's crypto utilities
            const { unmarshalPrivateKey } = await import('@libp2p/crypto/keys');
            const keyBytes = uint8ArrayFromString(stored.privKey, 'base64');
            const privateKey = await unmarshalPrivateKey(keyBytes);
            
            // Create peer ID from the unmarshalled private key
            const peerId = await createFromPrivKey(privateKey);
            
            this.log(`[P2P] Successfully loaded permanent bootstrap ID: ${peerId.toString()}`, 'success');
            return peerId;

        } catch (e) {
            this.log('[P2P] FATAL: Could not load "peer-id.json".', 'error');
            this.log('[P2P] A bootstrap node MUST have a "peer-id.json" file.', 'error');
            this.log('[P2P] Run this node without PLURIBIT_IS_BOOTSTRAP="true" once to generate one.', 'error');
            process.exit(1);
        }
    }
    
    // --- MINER: Load or create local key from file ---
    try {
        await fs.mkdir('./pluribit-data', { recursive: true });
        this.log('[P2P] Attempting to load peer-id.json...', 'debug');
        
        const data = await fs.readFile(peerIdPath, 'utf-8');
        this.log('[P2P] File read successfully', 'debug');
        
        const stored = JSON.parse(data);
        this.log(`[P2P] JSON parsed, stored ID: ${stored.id}`, 'debug');

        // Import the marshalled key using libp2p's crypto utilities
        const { unmarshalPrivateKey } = await import('@libp2p/crypto/keys');
        const keyBytes = uint8ArrayFromString(stored.privKey, 'base64');
        this.log(`[P2P] Key bytes decoded, ${keyBytes.length} bytes`, 'debug');
        
        const privateKey = await unmarshalPrivateKey(keyBytes);
        this.log(`[P2P] Private key unmarshalled successfully`, 'debug');
        
        // Create peer ID from the unmarshalled private key
        const peerId = await createFromPrivKey(privateKey);
        this.log(`[P2P] PeerId created from key: ${peerId.toString()}`, 'debug');
        
        // Verify it matches what we stored
        if (peerId.toString() !== stored.id) {
            this.log(`[P2P] WARNING: Generated ID ${peerId.toString()} doesn't match stored ID ${stored.id}`, 'warn');
            this.log(`[P2P] This might indicate key corruption. Regenerating...`, 'warn');
            throw new Error('ID mismatch - regenerating');
        }
        
        this.log(`[P2P] Successfully loaded existing peer ID: ${peerId.toString()}`, 'info');
        return peerId;
        
    } catch (e) {
        this.log(`[P2P] Failed to load existing peer ID: ${e.message}`, 'debug');
        
        // Create new peer ID
        this.log('[P2P] Creating new peer ID...', 'info');
        const peerId = await createEd25519PeerId();
        
        if (!peerId.privateKey) {
            throw new Error('Generated PeerId missing private key');
        }
        
        // Marshal the private key properly using libp2p's utilities
        const { marshalPrivateKey, unmarshalPrivateKey } = await import('@libp2p/crypto/keys');
        
        // The privateKey property is already a Uint8Array of the marshalled key
        const marshalledKey = peerId.privateKey;
        
        const data = {
            id: peerId.toString(),
            privKey: uint8ArrayToString(marshalledKey, 'base64'),
            pubKey: uint8ArrayToString(peerId.publicKey, 'base64')
        };
        
        await fs.writeFile(peerIdPath, JSON.stringify(data, null, 2), { mode: 0o600 });
        try { await fs.chmod(peerIdPath, 0o600); } catch {}
        
        this.log(`[P2P] Created new peer ID: ${peerId.toString()}`, 'success');
        return peerId;
    }
}

    /**
     * @param {string} peerId
     * @returns {boolean}
     */
    isPeerVerified(peerId) {
        const state = this._peerVerificationState.get(peerId.toString());
        if (!state) return false;
        // A peer is verified if they have solved the PoW and are subscribed to our main topic.
        return state.powSolved && state.isSubscribed;
    }

    setupEventHandlers() {
        if (!this.node) return;
        
        this.node.addEventListener('peer:connect', async (evt) => {
            const peerId = evt.detail.toString();
            this.log(`[P2P] Connected to ${peerId}`, 'debug');
            setTimeout(() => { try { bootstrapSync() } catch(e){} }, 3000); // Trigger a sync check 3s after ANY new peer connects
            // Give the connection a moment to stabilize before sending a challenge.
            setTimeout(async () => {
                try {
                    await this.sendDirectChallenge(peerId);
                } catch (e) {
                    const err = /** @type {Error} */ (e);
                    this.log(`[P2P] Challenge error for ${peerId}: ${err.message}`, 'error');
                }
            }, 2000); // Increased delay to 2 seconds
        });
        
        this.node.addEventListener('peer:disconnect', (evt) => {
            const peerId = evt.detail;
            this.log(`[P2P] Disconnected from ${peerId.toString()}`, 'debug');
            // Clean up state for disconnected peer
            const peerIdStr = peerId.toString();
            this._peerChallenges.delete(peerIdStr);
            this._peerVerificationState.delete(peerIdStr);
            this._buckets.delete(peerIdStr);
        });
        
        // Add discovery events with auto-dial
        this.node.addEventListener('peer:discovery', async (evt) => {
            const { id, multiaddrs } = evt.detail;

            if (!this.node) return;
            
            // ignore self
            if (id?.toString?.() === this.node.peerId.toString()) return;

            // persist addresses so the conn mgr can use them
            if (multiaddrs?.length) {
                await this._addToAddressBookCompat(id, multiaddrs);
            }

            this.log(`[P2P] Discovered peer: ${id.toString()} (${multiaddrs?.length ?? 0} addrs)`, 'debug');

            // if we're under the target and not already connected, dial now
            const connections = this.node.getConnections();
            const already = connections.some(c => c.remotePeer.toString() === id.toString());
            const total = connections.length;
            const target = CONFIG.P2P.MIN_CONNECTIONS;

            if (!already && total < target) {
                try {
                    await this.node.dial(id);
                    this.log(`[P2P] Auto-dialed discovered peer ${id.toString()}`, 'debug');
                } catch (e) {
                    const err = /** @type {Error} */ (e);
                    this.log(`[P2P] Auto-dial to ${id.toString()} failed: ${err.message}`, 'warn');
                }
            }
        });

        
        // Add connection events for debugging
        this.node.addEventListener('connection:open', (evt) => {
            const connection = evt.detail;
            this.log(`[P2P] Connection opened to ${connection.remotePeer.toString()}`, 'debug');
        });
        
        this.node.addEventListener('connection:close', (evt) => {
            const connection = evt.detail;
            this.log(`[P2P] Connection closed to ${connection.remotePeer.toString()}`, 'debug');
        });
        
        // GossipSub message handler
        this.node.services.pubsub.addEventListener('message', (evt) => {
            this.log(`[P2P PUBSUB EVENT] 'message' event fired for topic: ${evt.detail.topic}`, 'debug');
            this.handleGossipMessage(evt.detail);
        });
        
        // ** Listen for subscription changes to confirm Pluribit peers **
        this.node.services.pubsub.addEventListener('subscription-change', (evt) => {
            const { peerId, subscriptions } = evt.detail;
            // Check if the peer is now subscribed to our main block topic
            const sub = subscriptions.find(s => s.topic === TOPICS.BLOCKS);

            if (sub) {
                if (sub.subscribe) {
                    // Peer subscribed, update state
                    this._updateVerificationState(peerId.toString(), { isSubscribed: true, powSolved: undefined });
                } else {
                    // Peer unsubscribed, update state
                    this._updateVerificationState(peerId.toString(), { isSubscribed: false, powSolved: undefined });
                }
            }
        });
    }

    /**
     * @param {any} msg
     * @returns {Promise<void>}
     */
    async handleGossipMessage(msg) {
        try {
            const from = msg.from?.toString?.() ?? String(msg.from);

            this.log(`[P2P RAW] Received message on topic ${msg.topic} from ${from}`, 'debug');
            // CRITICAL: Verify ALL peers (including self for loopback)
            if (!this.isPeerVerified(from)) {
                this.log(`[P2P] Dropping message from unverified peer ${from}`, 'warn');
                return;
            }

            if (!Object.values(TOPICS).includes(msg.topic)) {
                return;
            }

            const bytes = msg?.data;
            if (bytes && bytes.byteLength > CONFIG.MAX_MESSAGE_SIZE) {
                this.log(`[P2P] Dropping oversize message on ${msg.topic} from ${from}`, 'warn');
                return;
            }

            if (!this._allowMessage(from)) {
                this.log(`[P2P] Rate-limited ${from} on ${msg.topic}`, 'warn');
                return;
            }

            // The `P2PMessage.decode`
            // function will throw an error if the received binary data does not
            // perfectly match the schema (e.g., wrong types, missing fields),
            // which we catch below. 
            // @ts-ignore - protobuf decode signature
            const p2pMessage = p2p.P2pMessage.decode(msg.data);
            // @ts-ignore - protobuf message property access
            const payloadType = p2pMessage.payload;
            // @ts-ignore - dynamic property access on protobuf message
            const data = p2pMessage[payloadType];

            // Rationale: We now dispatch based on the `oneof` payload type defined
            // in our schema. This is more explicit and safer than relying on a
            // string topic from the network.
            const handlers = this.handlers.get(msg.topic) || [];
            for (const handler of handlers) {
                try {
                    // Rationale: Pass the raw bytes along with the decoded data.
                    // Handlers that interface with WASM (like block ingestion) can use
                    // the raw bytes for maximum performance and security, while other
                    // handlers can use the convenient decoded JS object.
                    await handler(data, { from, topic: msg.topic, rawData: msg.data });
                } catch (e) {
                    const err = /** @type {Error} */ (e);
                    this.log(`[P2P] Handler error for ${msg.topic}: ${err.message}`, 'error');
                }
            }
        } catch (e) {
            // Rationale: Catching errors from `P2PMessage.decode` is our primary
            // defense. If an attacker sends malformed binary data, the decoder
            // will throw, we'll log it, and drop the message, protecting the rest
            // of the application. This prevents crashes from invalid data.
            const err = /** @type {Error} */ (e);
            this.log(`[P2P] Failed to decode Protobuf message or handle it: ${err.message}`, 'error');
        }
    }


    // Public API

    /**
     * @param {string} topic
     * @param {Function} handler
     * @returns {Promise<void>}
     */
    async subscribe(topic, handler) {
        if (!this.node) return;
        
        if (!this.handlers.has(topic)) {
            this.handlers.set(topic, []);
            this.node.services.pubsub.subscribe(topic);
            this.log(`[P2P] Subscribed to ${topic}`);
        }
        this.handlers.get(topic)?.push(handler);
    }

    /**
     * @param {string} topic
     * @param {any} data
     * @returns {Promise<void>}
     */
    async publish(topic, data) {
        if (!this.node) return;
        
        // Rationale: We replace JSON serialization with Protobuf serialization.
        // 1. Determine the payload type based on the topic.
        // 2. Create a P2PMessage object with the correct `oneof` field set.
        // 3. Encode it into a binary Uint8Array.
        // This process is type-safe and produces a compact binary message.
        const payloadType = this._getPayloadTypeForTopic(topic);
        if (!payloadType) {
            throw new Error(`No Protobuf payload type for topic ${topic}`);
        }

        const message = p2p.P2pMessage.create({ [payloadType]: data });
        const bytes = p2p.P2pMessage.encode(message).finish();

        if (bytes.byteLength > CONFIG.MAX_MESSAGE_SIZE) {
            throw new Error(`Refusing to publish >MAX_MESSAGE_SIZE on ${topic}`);
        }
        await this.node.services.pubsub.publish(topic, bytes);
    }

    // ---- DHT: Signed write ----
    /**
     * @param {string} key
     * @param {any} value
     * @returns {Promise<void>}
     */
    async store(key, value) {
        if (!this.node) return;
        
        const nsKey = `/pluribit/${key}`;
        const payload = { type: 'pluribit', value, timestamp: Date.now() };
        // canonical material to sign (avoid reordering issues)
        const toSign = stableStringify({
            ns: nsKey,
            payload,
            from: this.node.peerId.toString(),
            v: 1
        });
        const hashHex = sha256Hex(toSign);
        const hashBytes = uint8ArrayFromString(hashHex, 'hex');
        
        // sign with our ed25519 private key
        // @ts-ignore - privateKey may not exist on all PeerId types
        const privKey = this.node.peerId.privateKey;
        // @ts-ignore - publicKey may not exist on all PeerId types
        const pubKey = this.node.peerId.publicKey;
        if (!privKey || !pubKey) {
            throw new Error('PeerId missing keys');
        }
        
        const sig = nacl.sign.detached(hashBytes, privKey);
        const envelope = {
            ns: nsKey,
            payload,                 // { type, value, timestamp }
            from: this.node.peerId.toString(),
            // @ts-ignore - publicKey type compatibility
            pubKey: uint8ArrayToString(pubKey, 'base64'),
            sig: uint8ArrayToString(sig, 'base64'),
            alg: 'ed25519',
            v: 1
        };
        // @ts-ignore - DHT API put returns AsyncIterable in some versions
        const result = await this.node.services.dht.put(
            uint8ArrayFromString(nsKey),
            uint8ArrayFromString(JSON.stringify(envelope))
        );
        // Drain the async iterable if it exists
        // @ts-ignore
        if (result?.[Symbol.asyncIterator]) {
            // @ts-ignore
            for await (const _ of result) {}
        }
    }


    // ---- DHT: Verify on read ----
    /**
     * @param {string} key
     * @returns {Promise<any>}
     */
    async get(key) {
        try {
            if (!this.node) return null;
            
            const nsKey = `/pluribit/${key}`;
            // @ts-ignore - DHT API get returns AsyncIterable in some versions
            const result = await this.node.services.dht.get(uint8ArrayFromString(nsKey));
            
            let resultValue;
            // @ts-ignore - check if it's an async iterable
            if (result?.[Symbol.asyncIterator]) {
                // @ts-ignore
                for await (const event of result) {
                    if (event.name === 'VALUE') {
                        resultValue = event.value;
                        break;
                    }
                }
            } else {
                resultValue = result;
            }
            
            if (!resultValue) return null;
            
            // @ts-ignore - resultValue type compatibility
            const env = JSON.parse(uint8ArrayToString(resultValue));

            // quick shape checks
            if (!env || env.ns !== nsKey || env.v !== 1 || env.alg !== 'ed25519') {
                this.log(`[DHT] Rejected value for ${nsKey}: bad envelope`, 'warn');
                return null;
            }
            if (!env.pubKey || !env.sig || !env.payload) {
                this.log(`[DHT] Rejected value for ${nsKey}: missing fields`, 'warn');
                return null;
            }

            // recompute the signed material
            const toSign = stableStringify({
                ns: env.ns,
                payload: env.payload,
                from: env.from,
                v: env.v
            });
            const hashHex = sha256Hex(toSign);
            const hashBytes = uint8ArrayFromString(hashHex, 'hex');
            const pub = uint8ArrayFromString(env.pubKey, 'base64');
            const sig = uint8ArrayFromString(env.sig, 'base64');

            const ok = nacl.sign.detached.verify(hashBytes, sig, pub);
            if (!ok) {
                this.log(`[DHT] Rejected value for ${nsKey}: signature invalid`, 'warn');
                return null;
            }

            // bind claimed "from" to pubKey -> derived PeerId
            try {
                // @ts-ignore - createFromPubKey signature varies
                const derived = await createFromPubKey({ publicKey: pub });

                if (derived.toString() !== env.from) {
                    this.log(`[DHT] Rejected value for ${nsKey}: pubKey does not match 'from'`, 'warn');
                    return null;
                }
            } catch (e) {
                const err = /** @type {Error} */ (e);
                this.log(`[DHT] Could not derive PeerId from pubKey: ${err?.message || err}`, 'warn');
                return null;
            }

            // freshness guard: drop payloads older than 24h
            if (Date.now() - (env.payload?.timestamp || 0) > 86_400_000) return null;

            // skew guard: drop payloads >5m in the future
            if ((env.payload?.timestamp || 0) > Date.now() + 5 * 60_000) return null;

            // anti-replay: only accept strictly newer timestamps per key
            const last = this._dhtSeen.get(nsKey) || 0;
            if ((env.payload?.timestamp || 0) <= last) return null;
            this._dhtSeen.set(nsKey, env.payload.timestamp);

            return env.payload?.value ?? null;
        } catch (e) {
            const err = /** @type {Error} */ (e);
            this.log(`[DHT] get error for /pluribit/${key}: ${err?.message || err}`, 'debug');
            return null;
        }
    }

    getConnectedPeers() {
        if (!this.node) {
            return [];
        }

        const connections = this.node.getConnections();

        // Map over connections to get peer IDs, then immediately filter out any
        // that are undefined. This is the crucial step.
        return connections
            .map(c => c.remotePeer)
            .filter(peerId => peerId != null) // This ensures only valid PeerId objects proceed
            .map(peerId => {
                try {
                    // Now we can safely call peerStore.get because peerId is guaranteed to be valid.
                    // @ts-ignore - peerStore.get() API has varied across versions
                    const peer = this.node.peerStore.get(peerId);
                    
                    // @ts-ignore
                    const protocols = peer?.protocols ?? [];
                    
                    return {
                        id: peerId.toString(),
                        protocols
                    };
                } catch (e) {
                    // This fallback is just in case peerStore.get fails for other reasons.
                    return {
                        id: peerId.toString(),
                        protocols: []
                    };
                }
            });
    }
    
    /**
     * Removes a specific handler for a given topic.
     * @param {string} topic - The topic to unsubscribe the handler from.
     * @param {Function} handler - The specific handler function to remove.
     */
    async unsubscribe(topic, handler) {
        if (!this.handlers.has(topic)) {
            return;
        }
        const handlers = this.handlers.get(topic);
        if (!handlers) return;
        const index = handlers.indexOf(handler);
        if (index > -1) {
            handlers.splice(index, 1);
            this.log(`[P2P] Unsubscribed a handler from ${topic}`, 'debug');
        }
    }

    async stop() {
        if (this._rendezvousTimer) {
            clearInterval(this._rendezvousTimer);
            // @ts-ignore - timer type compatibility
            this._rendezvousTimer = null;
        }
        if (this._challengeGcTimer) {
            clearInterval(this._challengeGcTimer);
            // @ts-ignore - timer type compatibility
            this._challengeGcTimer = null;
        }
        if (this._stemRelayRefreshTimer) {
            clearInterval(this._stemRelayRefreshTimer);
            this._stemRelayRefreshTimer = null;
        }
        
        // Clear embargo timers
        for (const timer of this._embargoedTransactions.values()) {
            clearTimeout(timer);
        }
        this._embargoedTransactions.clear();
        
        if (this.node) {
            await this.node.stop();
        }
    }

    /**
     * Helper to map topics to Protobuf oneof field names.
     * @param {string} topic
     * @returns {string | null}
     */
    _getPayloadTypeForTopic(topic) {
        switch (topic) {
            case TOPICS.BLOCKS: return 'block';
            case TOPICS.TRANSACTIONS: return 'transaction';
            case TOPICS.BLOCK_ANNOUNCEMENTS: return 'blockAnnouncement';
            case TOPICS.BLOCK_REQUEST: return 'blockRequest';
            case TOPICS.GET_HASHES_REQUEST: return 'getHashesRequest';
            case TOPICS.HASHES_RESPONSE: return 'hashesResponse';
            case TOPICS.SYNC: return 'syncMessage';
            case TOPICS.DANDELION_STEM: return 'dandelionStem';

            // --- Atomic Swaps ---
            case TOPICS.SWAP_PROPOSE: return 'swapPropose';
            case TOPICS.SWAP_RESPOND: return 'swapRespond';
            case TOPICS.SWAP_ALICE_ADAPTOR_SIG: return 'swapAliceAdaptorSig';
            
            // --- Payment Channels ---
            case TOPICS.CHANNEL_PROPOSE: return 'channelPropose';
            case TOPICS.CHANNEL_ACCEPT: return 'channelAccept';
            case TOPICS.CHANNEL_FUND_NONCE: return 'channelFundNonce';
            case TOPICS.CHANNEL_FUND_SIG: return 'channelFundSig';
            case TOPICS.CHANNEL_PAY_PROPOSE: return 'channelPayPropose';
            case TOPICS.CHANNEL_PAY_ACCEPT: return 'channelPayAccept';
            case TOPICS.CHANNEL_CLOSE_NONCE: return 'channelCloseNonce';
            case TOPICS.CHANNEL_CLOSE_SIG: return 'channelCloseSig';

            default: return null;
        }
    }

}
