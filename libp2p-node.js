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
import crypto from 'crypto';
import nacl from 'tweetnacl';
import fs from 'fs/promises';
import path from 'path';
import { peerIdFromString } from '@libp2p/peer-id'; // <--- FIXED: Added missing import

// Rationale: In an ES Module project, CommonJS files must be loaded using `createRequire`.
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { p2p } = require('./src/p2p_pb.cjs');
const { Block } = p2p;
export { Block as P2PBlock, p2p };

const PEER_STORE_PATH = './pluribit-data/peers.json';

/**
 * @param {any} obj
 * @returns {string}
 */
function stableStringify(obj) {
  const seen = new WeakSet();
  const walk = (v) => {
    if (v && typeof v === 'object') {
      if (seen.has(v)) return null;
      seen.add(v);
      if (Array.isArray(v)) return v.map(walk);
      const out = {};
      for (const k of Object.keys(v).sort()) out[k] = walk(v[k]);
      return out;
    }
    return v;
  };
  return JSON.stringify(walk(obj));
}

function sha256Hex(inputUtf8) {
  return crypto.createHash('sha256').update(inputUtf8, 'utf8').digest('hex');
}

const NET = process.env.PLURIBIT_NET || 'mainnet';

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
  SWAP_ALICE_ADAPTOR_SIG: `/pluribit/${NET}/swap-alice-sig/1.0.0`,
};

const PEX_PROTOCOL = `/pluribit/${NET}/pex/1.0.0`;

export class PluribitP2P {
    constructor(log, options = {}) {
        this._peerVerificationState = new Map();
        this._badBlockPeers = new Map();
        this._trustedPeers = new Set();
        this.log = log;
        this.node = null;
        this.handlers = new Map();
        this.isBootstrap = options.isBootstrap || (process.env.PLURIBIT_IS_BOOTSTRAP === 'true');
        this._peerChallenges = new Map();
        this._maxChallengeAttempts = 3;
        
        this._ipChallengeTracker = new Map();
        this._connectionAttempts = 0;
        this._currentChallengeDifficulty = CONFIG.P2P.DYNAMIC_POW.MIN_DIFFICULTY;

        this._challengeGcTimer = setInterval(() => {
            const now = Date.now();
            for (const [peerId, challenge] of this._peerChallenges) {
                if (now - challenge.timestamp > 120000) { 
                    this._peerChallenges.delete(peerId);
                }
            }
        }, 60000);

        this.config = {
          listen: {
            tcp: options.tcpPort || 26658,
            ws: options.wsPort || 26659
          },
          bootstrap: this.isBootstrap ? [] : [
            '/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN',
            '/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa',
            '/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb',
            '/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt',
            '/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ'
          ]
        };
        
        this._stemRelay = null;
        this._stemRelayRefreshTimer = null;
        this._embargoedTransactions = new Map();
        this._stemRelayLastRefresh = 0;
        this._seenStemTransactions = new Set();

        this._poisonedHashes = new Set();
        this._pendingBlockRequests = new Map();

        setInterval(() => {
            const now = Date.now();
            for (const [hash, info] of this._pendingBlockRequests.entries()) {
                if (now - info.requestedAt > 30_000) {
                    this._pendingBlockRequests.delete(hash);
                }
            }
        }, 15_000);
    } 
    
    _extractTrustedPeers() {
        if (!this.config.bootstrap || !Array.isArray(this.config.bootstrap)) return;
        
        for (const addrStr of this.config.bootstrap) {
            try {
                const ma = multiaddr(addrStr);
                const peerId = ma.getPeerId();
                if (peerId) {
                    this._trustedPeers.add(peerId);
                    this.log(`[P2P] 🛡️ Added Bootstrap Boss to Trusted List: ${peerId}`, 'debug');
                }
            } catch (e) {
            }
        }
    }
    
    recordBadBlock(peerId, hash = null) {
        const peerIdStr = peerId.toString();

        if (peerIdStr === this.node.peerId.toString()) {
            return false;
        }
        if (this._trustedPeers.has(peerIdStr)) {
            return false;
        }
        const entry = this._badBlockPeers.get(peerIdStr) || { count: 0, bannedUntil: 0 };
        entry.count++;

        if (entry.count >= 3) {
            this.banPeer(peerId, `bad block x${entry.count}`, true, hash);
        }

        this._badBlockPeers.set(peerIdStr, entry);
        return entry.count >= 3;
    }
    
    isPeerBannedForBadBlocks(peerId) {
        const entry = this._badBlockPeers.get(peerId.toString());
        if (!entry || !entry.bannedUntil) return false;
        if (Date.now() >= entry.bannedUntil) {
            entry.bannedUntil = 0;
            entry.count = 0;
            return false;
        }
        return true;
    }

    poisonHash(hash, reason = 'unknown', fromPeer = null) {
        if (this._poisonedHashes.has(hash)) return;

        this._poisonedHashes.add(hash);
        const short = hash.slice(0, 12);
        this.log(`[CONSENSUS SHIELD] POISONED hash ${short}… — ${reason}${fromPeer ? ` (from ${fromPeer.slice(-8)})` : ''}`, 'warn');

        if (fromPeer) {
            this.banPeer(fromPeer, `sent poisoned hash (${reason})`, true);
        }
    }

    isHashPoisoned(hash) {
        return this._poisonedHashes.has(hash);
    }

    async banPeer(peerIdStr, reason = 'unknown', permanent = false, poisonedHash = null) {
        if (!this.node) return;

        if (peerIdStr === this.node.peerId.toString()) return;
        if (this._trustedPeers.has(peerIdStr)) return;

        const short = peerIdStr.slice(-8);
        this.log(`[P2P] ⚡ BANNED peer ${short} — ${reason}`, 'warn');

        const banMs = permanent ? Number.MAX_SAFE_INTEGER : 30 * 60 * 1000;
        this._badBlockPeers.set(peerIdStr, {
            count: 999,
            bannedUntil: Date.now() + banMs
        });

        if (poisonedHash) {
            this.poisonHash(poisonedHash, reason, peerIdStr);
        }

        try {
            await this.node.hangUp(peerIdStr);
        } catch (_) {}
    }   
    
    _selectStemRelay() {
        if (!this.node) return null;
        
        const verifiedPeers = this.getConnectedPeers()
            .filter(p => this.isPeerVerified(p.id))
            .map(p => p.id);
        
        if (verifiedPeers.length === 0) return null;
        
        const randomIndex = Math.floor(Math.random() * verifiedPeers.length);
        return verifiedPeers[randomIndex];
    }

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

    _getTxHash(transaction) {
        if (transaction.kernels && transaction.kernels[0]?.excess) {
            return Buffer.from(transaction.kernels[0].excess)
                .toString('hex')
                .substring(0, 16);
        }
        return crypto.createHash('sha256')
            .update(JSON.stringify(transaction))
            .digest('hex')
            .substring(0, 16);
    }

    async stemTransaction(transaction) {
        if (!CONFIG.DANDELION.ENABLED) {
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
        
        const stemMessage = {
            transaction: transaction,
            hopCount: 0,
            timestamp: Date.now()
        };

        try {
            await this._sendStemDirect(stemRelay, stemMessage);
            this.log(`[Dandelion] Sent transaction ${txHash} to stem relay ${stemRelay.slice(-6)}`, 'info');
        } catch (e) {
            this.log(`[Dandelion] Stem send failed: ${e.message}, falling back to broadcast`, 'warn');
            await this.publish(TOPICS.TRANSACTIONS, transaction);
        }
    }

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
            const encoded = p2p.DandelionStem.encode(stemMessage).finish();
            await pipe([encoded], stream.sink);
            
        } catch (e) {
            throw new Error(`Direct stem send failed: ${e.message}`);
        }
    }

    _shouldContinueStem(hopCount) {
        if (hopCount >= CONFIG.DANDELION.MAX_STEM_HOPS) return false;
        if (hopCount < CONFIG.DANDELION.MIN_STEM_HOPS) return true;
        return Math.random() < CONFIG.DANDELION.STEM_PROBABILITY;
    }

    async _handleStemTransaction(stemMessage, from) {
        const { transaction, hopCount, timestamp } = stemMessage;
        const txHash = this._getTxHash(transaction);

        try {
            await this.publish(TOPICS.TRANSACTIONS, transaction);
            this.log(`[Dandelion] Published received stem tx ${txHash} locally for mempool add`, 'debug');
        } catch (e) {
            this.log(`[Dandelion] Failed local publish for stem tx ${txHash}: ${e.message}`, 'warn');
        }

        if (this._seenStemTransactions.has(txHash)) return;
        
        this._seenStemTransactions.add(txHash);
        
        if (this._seenStemTransactions.size > 10000) {
            const oldestEntries = Array.from(this._seenStemTransactions).slice(0, 5000);
            oldestEntries.forEach(hash => this._seenStemTransactions.delete(hash));
        }
        
        const age = Date.now() - timestamp;
        if (age > CONFIG.DANDELION.EMBARGO_TIMEOUT_MS) {
            this.log(`[Dandelion] Transaction ${txHash} exceeded embargo, fluffing`, 'info');
            await this.publish(TOPICS.TRANSACTIONS, transaction);
            return;
        }
        
        if (this._shouldContinueStem(hopCount)) {
            this._refreshStemRelay();
            const nextRelay = this._stemRelay;
            
            // <--- FIXED: Fallback to Fluff if relay unavailable or relay is sender
            if (!nextRelay || nextRelay === from) {
                this.log(`[Dandelion] No valid relay (or relay is sender), fluffing tx ${txHash}`, 'debug');
                await this.publish(TOPICS.TRANSACTIONS, transaction);
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
                this.log(`[Dandelion] Stem relay failed, fluffing: ${e.message}`, 'warn');
                await this.publish(TOPICS.TRANSACTIONS, transaction); // Fallback fluff
            }
        } else {
            this.log(`[Dandelion] Fluffing transaction ${txHash} after ${hopCount} hops`, 'info');
            await this.publish(TOPICS.TRANSACTIONS, transaction);
        }
    }   
    
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
            try {
                if (this.node) {
                    this.node.dispatchEvent(new CustomEvent('pluribit:peer-verified', { detail: peerId }));
                }
            } catch (e) {
                const err = /** @type {Error} */ (e);
                this.log(`[P2P] Error dispatching peer-verified event: ${err.message}`, 'warn');
            }       
        }
        return isNowVerified ;
    }

    async sendDirectChallenge(peerId) {
        let connection;
        let ip;

        try {
            if (!this.node) throw new Error('Node not initialized');

            const connections = this.node.getConnections();
            connection = connections.find(c => c.remotePeer.toString() === peerId);
            if (!connection) throw new Error('No connection to peer');
            ip = this.getIpFromMultiaddr(connection.remoteAddr);

            const challenge = crypto.randomBytes(32).toString('hex');
            
            this._peerChallenges.set(peerId, {
                challenge,
                timestamp: Date.now(),
                attempts: 0
             });
            
            const stream = await connection.newStream('/pluribit/challenge/1.0.0');
            
            const currentDifficulty = this._currentChallengeDifficulty;
            const message = p2p.Challenge.create({ 
                challenge, 
                from: this.node.peerId.toString(),
                difficulty: currentDifficulty 
            });

            const encodedMessage = p2p.Challenge.encode(message).finish();
            await pipe([encodedMessage], stream.sink);
            
            const chunks = [];
            for await (const chunk of stream.source) {
                chunks.push(chunk.subarray());
            }
            const responseBuffer = Buffer.concat(chunks);
            const response = p2p.ChallengeResponse.decode(responseBuffer);
           
            const verify = crypto.createHash('sha256')
                .update(challenge)
                // @ts-ignore
                .update(response.nonce || '')
                .digest('hex');
            
            // @ts-ignore
            if (verify === response.solution && (response.solution || '').startsWith(currentDifficulty)) {
                this._updateVerificationState(peerId, { powSolved: true, isSubscribed: undefined });
                this._peerChallenges.delete(peerId);
                this.log(`[P2P] ✓ Peer ${peerId} solved challenge (difficulty: ${currentDifficulty.length})`, 'success');

                if (this._badBlockPeers.has(peerId)) {
                    this.log(`[P2P] 🖕 Banned peer ${peerId.slice(-8)} solved hard PoW — hanging up anyway`, 'warn');
                    try { await this.node.hangUp(peerId); } catch {}
                    return false;
                }
                if (ip) this._ipChallengeTracker.delete(ip);
                return true;
            }

            this.log(`[P2P] ✗ Peer ${peerId} FAILED challenge (difficulty: ${currentDifficulty.length}). Hanging up.`, 'warn');
            if (ip) {
                const entry = this._ipChallengeTracker.get(ip) || { failures: 0, lastAttempt: Date.now() };
                entry.failures++;
                entry.lastAttempt = Date.now();
                this._ipChallengeTracker.set(ip, entry);
            }
            try { this.node.hangUp(peerId); } catch {}
            return false;

        } catch (e) {
            const err = /** @type {Error} */ (e);
            const msg = err?.message || '';
            const isExpected = /protocol selection failed|No connection to peer|stream reset/i.test(msg);
            const logLevel = isExpected ? 'debug' : 'error';
            this.log(`[P2P] Failed to send challenge to ${peerId}: ${msg}`, logLevel);

            if (ip && !isExpected) {
                 const entry = this._ipChallengeTracker.get(ip) || { failures: 0, lastAttempt: Date.now() };
                 entry.failures++;
                 entry.lastAttempt = Date.now();
                 this._ipChallengeTracker.set(ip, entry);
                 if (connection) {
                    try { connection.close(); } catch {}
                 }
            }
            return false;
        }
    }

    async _addToAddressBookCompat(id, multiaddrs) {
        if (!this.node) return;
        const ps = this.node.peerStore;
        if (!ps || !multiaddrs?.length) return;

        try {
            // @ts-ignore
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
        } catch (e) {
            const err = /** @type {Error} */ (e);
            this.log(`[P2P] address book update failed for ${id.toString()}: ${err?.message || err}`, 'debug');
        }
    }

    _buckets = new Map();
    _dhtSeen = new Map();
    _bucketGcTimer = null;
    
    _allowMessage(from) {
        const now = Date.now();
        const windowMs = CONFIG.RATE_LIMIT_WINDOW;
        const cap = CONFIG.RATE_LIMIT_MESSAGES;

        let b = this._buckets.get(from);
        if (!b) {
            b = { tokens: cap, windowStart: now };
            this._buckets.set(from, b);
        }

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
    _rendezvousCid = null;
    _rendezvousTimer = null;

    async _provideCompat(cid) {
        if (!this.node) return false;
        const cr = this.node.contentRouting;
        if (cr?.provide) {
            const ret = cr.provide(cid);
            // @ts-ignore
            if (ret?.[Symbol.asyncIterator]) {
                // @ts-ignore
                for await (const _ of ret) {} 
            } else {
                await ret; 
            }
            return true;
        }
        // @ts-ignore
        const dht = this.node.services?.dht;
        // @ts-ignore
        if (dht?.provide) { 
            // @ts-ignore
            await dht.provide(cid); 
            return true; 
        }
        return false;
    }

    async _findProvidersCompat(cid, opts) {
        const out = [];
        if (!this.node) return out;
        const cr = this.node.contentRouting;
        if (cr?.findProviders) {
            // @ts-ignore
            const res = cr.findProviders(cid, opts);
            // @ts-ignore
            if (res?.[Symbol.asyncIterator]) {
                // @ts-ignore
                for await (const p of res) out.push(p);
            } else {
                const arr = await res; 
                if (Array.isArray(arr)) out.push(...arr);
            }
            return out;
        }
        // @ts-ignore
        const dht = this.node.services?.dht;
        // @ts-ignore
        if (dht?.findProviders) {
            // @ts-ignore
            for await (const p of dht.findProviders(cid, opts)) out.push(p);
        }
        return out;
    }

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

            try {
                const ok = await this._provideCompat(cid);
                if (ok) this.log(`[P2P] 📣 Provided rendezvous CID ${cid.toString()}`);
            } catch (e) {
                // ignore
            }

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
                        this.log(`[P2P] 🔌 Connected to rendezvous provider ${id}`);
                    } catch (e) {
                         // ignore
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
        
        const NET = process.env.PLURIBIT_NET || 'mainnet';
        
        if (NET === 'testnet') {
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

        const peerId = await this.loadOrCreatePeerId();
        this._extractTrustedPeers();
        
        const keys = await import('@libp2p/crypto/keys');
        
        let privateKeyObj;
        try {
            privateKeyObj = keys.privateKeyFromProtobuf(peerId.privateKey);
        } catch (e) {
            this.log(`[P2P DEBUG] protobuf unmarshal failed, trying supportedKeys: ${e.message}`, 'debug');
            const { supportedKeys } = keys;
            privateKeyObj = await supportedKeys.ed25519.unmarshalEd25519PrivateKey(peerId.privateKey);
        }
        
        this.node = await createLibp2p({
            privateKey: privateKeyObj, 
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
                circuitRelayTransport({
                    discoverRelays: this.isBootstrap ? 0 : 2
                })
            ],
            connectionEncrypters: [noise()],
            streamMuxers: [yamux()],
            services: {
                ...(this.isBootstrap && { relay: circuitRelayServer() }),
                identify: identify(),
                dht: kadDHT({
                    protocol: '/ipfs/kad/1.0.0',
                    clientMode: false,
                    // @ts-ignore
                    validators: {
                        pluribit: {
                            // @ts-ignore
                            validate: (key, value) => {
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
                    // @ts-ignore
                    allowPublishToZeroTopicPeers: true,
                    emitSelf: true,
                    // @ts-ignore
                    scoreThresholds: {
                        gossipThreshold: CONFIG.P2P.GOSSIPSUB_SCORING.graftThreshold,
                        publishThreshold: CONFIG.P2P.GOSSIPSUB_SCORING.pruneThreshold,
                        seenThreshold: 0,
                    },
                    // @ts-ignore
                    directPeers: [],
                    // @ts-ignore
                    peerScoreParams: {
                        IPColocationFactorWeight: -10,
                        IPColocationFactorThreshold: 5,
                        scoreCap: CONFIG.P2P.GOSSIPSUB_SCORING.scoreCap,
                        invalidMessage: {
                            penalty: CONFIG.P2P.GOSSIPSUB_SCORING.invalidMessagePenalty,
                            cap: CONFIG.P2P.GOSSIPSUB_SCORING.scoreCap,
                        },
                        duplicateMessage: {
                            penalty: CONFIG.P2P.GOSSIPSUB_SCORING.duplicateMessagePenalty,
                            cap: CONFIG.P2P.GOSSIPSUB_SCORING.scoreCap,
                        },
                    }
                }),
                ping: ping(),
                dcutr: dcutr(),
            },
            peerDiscovery: this.config.bootstrap.length > 0 
                ?
                [
                    bootstrap({
                        list: this.config.bootstrap,
                        // @ts-ignore
                        interval: 30000,
                        timeout: 30000
                    }),
                    mdns() 
                ]
                : [mdns()],
            connectionManager: {
                // @ts-ignore
                minConnections: CONFIG.P2P.MIN_CONNECTIONS,
                maxConnections: CONFIG.P2P.MAX_CONNECTIONS, 
                autoDial: true,
                autoDialInterval: 2000, 
                maxParallelDials: 10,
                dialTimeout: 30000      
            }
        });

        this.setupEventHandlers();
        
        await this.node.start();
        await this.loadPeers();

        setInterval(() => this.savePeers(), 5 * 60 * 1000);
        this.log(`[P2P] Node started with ID: ${this.node.peerId.toString()}`);

        this._updateVerificationState(this.node.peerId.toString(), { 
            powSolved: true, 
            isSubscribed: true 
        });

        const CHALLENGE_PROTOCOL = '/pluribit/challenge/1.0.0';

        await this.node.handle(CHALLENGE_PROTOCOL, async ({ stream, connection }) => {
            try {
                const chunks = [];
                for await (const chunk of stream.source) {
                    chunks.push(chunk.subarray());
                }
                const buffer = Buffer.concat(chunks);
                const data = p2p.Challenge.decode(buffer);
                
                // @ts-ignore
                const { challenge, from, difficulty} = data;

                if (difficulty === undefined || difficulty === null || !challenge) {
                    try { await stream.close(); } catch {}
                    return;
                }
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
                
                const response = p2p.ChallengeResponse.create({
                    solution,
                    nonce: String(nonce),
                    from: this.node ? this.node.peerId.toString() : ''
                });
                const encodedResponse = p2p.ChallengeResponse.encode(response).finish();
                
                await pipe([encodedResponse], stream.sink);
                
                this.log(`[P2P] Solved challenge from ${from} with nonce ${nonce}`, 'info');
            } catch (e) {
                const err = /** @type {Error} */ (e);
                this.log(`[P2P] Error handling challenge protocol: ${err.message}`, 'error');
            }
        });      
        
        await this.node.handle(PEX_PROTOCOL, this._handlePexRequest.bind(this));
        
        const BLOCK_TRANSFER_PROTOCOL = `/pluribit/${NET}/block-transfer/1.0.0`;
        await this.node.handle(BLOCK_TRANSFER_PROTOCOL, async ({ stream, connection }) => {
            try {
                const peerId = connection.remotePeer.toString();
                
                if (!this.isPeerVerified(peerId)) {
                    this.log(`[P2P] Denying block transfer from unverified peer ${peerId}`, 'warn');
                    try { await stream.close(); } catch {}
                    return;
                }
                
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
                const request = p2p.DirectBlockRequest.decode(buffer);
                
                // @ts-ignore
                if (!request.hash || !/^[0-9a-f]{64}$/i.test(request.hash)) {
                    const errResp = p2p.BlockTransferResponse.create({ errorReason: 'INVALID_HASH' });
                    await pipe([p2p.BlockTransferResponse.encode(errResp).finish()], stream.sink);
                    return;
                }
                
                const handlers = this.handlers.get(BLOCK_TRANSFER_PROTOCOL) || [];
                for (const handler of handlers) {
                    const block = await handler(request.hash);
                    if (block) {
                        const response = p2p.BlockTransferResponse.create({ blockData: block });
                        const encodedResponse = p2p.BlockTransferResponse.encode(response).finish();
                        await pipe([encodedResponse], stream.sink);
                        return;
                    }
                }
                
                const errResp = p2p.BlockTransferResponse.create({ errorReason: 'NOT_FOUND' });
                await pipe([p2p.BlockTransferResponse.encode(errResp).finish()], stream.sink);

            } catch (e) {
                const err = /** @type {Error} */ (e);
                this.log(`[P2P] Error handling block transfer protocol: ${err.message}`, 'error');
            }
        });
        
        await this.node.handle(TOPICS.DANDELION_STEM, async ({ stream, connection }) => {
            const peerId = connection.remotePeer.toString(); 
            this.log(`[Dandelion] Received incoming STEM connection from ${peerId.slice(-6)}`, 'debug');
            try {
                if (!this.isPeerVerified(peerId)) {
                    this.log(`[Dandelion] Rejecting stem from unverified peer ${peerId.slice(-6)}`, 'warn'); 
                    try { await stream.close(); } catch {}
                    return;
                }
                
                if (!this._allowMessage(peerId)) {
                    this.log(`[Dandelion] Rate limited stem from ${peerId.slice(-6)}`, 'warn');
                    try { await stream.close(); } catch {}
                    return;
                }
                
                const chunks = [];
                for await (const chunk of stream.source) {
                    chunks.push(chunk.subarray());
                }
                const buffer = Buffer.concat(chunks);
                const stemMessage = p2p.DandelionStem.decode(buffer);

                const txHash = this._getTxHash(stemMessage.transaction);
                this.log(`[Dandelion] Decoded stem message for tx ${txHash} from ${peerId.slice(-6)}`, 'debug'); 

                await this._handleStemTransaction(stemMessage, peerId);
                
            } catch (e) {
                const err = /** @type {Error} */ (e);
                this.log(`[Dandelion] Error handling stem protocol from ${peerId.slice(-6)}: ${err.message}`, 'error'); 
            }
        });
        
        this._stemRelayRefreshTimer = setInterval(() => {
            this._refreshStemRelay();
        }, CONFIG.DANDELION.STEM_RELAY_REFRESH_INTERVAL_MS);
        
        
        const addrs = this.node.getMultiaddrs();
        addrs.forEach(addr => this.log(`[P2P] Listening on ${addr.toString()}`));

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

        try {
            // @ts-ignore
            if (this.node.services.dht?.isStarted?.() === false) {
                // @ts-ignore
                await this.node.services.dht.start();
            }
        } catch { }
        
        this._bucketGcTimer = setInterval(() => {
            const now = Date.now();
            for (const [k, b] of this._buckets) {
                if ((now - (b.last || b.windowStart)) > 15 * 60_000) this._buckets.delete(k);
            }
        }, 5 * 60_000);
        
        await this._announceAndDiscoverProviders();
        this._rendezvousTimer = setInterval(() => {
            this._announceAndDiscoverProviders().catch((e) => {
                 // ignore
            });
        }, CONFIG.P2P.RENDEZVOUS_DISCOVERY_INTERVAL_MS); 
        
        setInterval(() => {
            const rate = this._connectionAttempts;
            this._connectionAttempts = 0;

            const { MIN_DIFFICULTY, MAX_DIFFICULTY, SURGE_THRESHOLD } = CONFIG.P2P.DYNAMIC_POW;
            const minLen = MIN_DIFFICULTY.length;
            const maxLen = MAX_DIFFICULTY.length;
            let currentLen = this._currentChallengeDifficulty.length;
            if (rate > SURGE_THRESHOLD) {
                currentLen = Math.min(currentLen + 1, maxLen);
                if (currentLen > this._currentChallengeDifficulty.length) {
                    this._currentChallengeDifficulty = '0'.repeat(currentLen);
                    this.log(`[SECURITY] Connection surge detected (${rate}/min). Increasing PoW difficulty to ${currentLen} zeros.`, 'warn');
                }
            } else if (rate < SURGE_THRESHOLD / 2) {
                currentLen = Math.max(currentLen - 1, minLen);
                if (currentLen < this._currentChallengeDifficulty.length) {
                    this._currentChallengeDifficulty = '0'.repeat(currentLen);
                    this.log(`[SECURITY] Network calm (${rate}/min). Reducing PoW difficulty to ${currentLen} zeros.`, 'info');
                }
            }
        }, CONFIG.P2P.DYNAMIC_POW.ADJUSTMENT_INTERVAL_MS);
               
        setInterval(async () => {
            if (!this.node) return;
            
            const connectedCount = this.node.getConnections().length;
            const maxConns = CONFIG.P2P.MAX_CONNECTIONS;
            
            if (connectedCount < maxConns) {
                try {
                    // @ts-ignore
                    const neighborGen = this.node.services.dht.getClosestPeers(this.node.peerId.toBytes());
                    for await (const event of neighborGen) {}
                } catch (e) {
                }
            }
        }, 30000); 
        
        return this.node;
    }

   async loadOrCreatePeerId() {
        const peerIdPath = './pluribit-data/peer-id.json';

        // --- BOOTSTRAP NODE LOADING LOGIC ---
        if (this.isBootstrap) {
            this.log('[P2P] Attempting to load permanent bootstrap PeerID from file...');
            try {
                await fs.mkdir('./pluribit-data', { recursive: true });
                const data = await fs.readFile(peerIdPath, 'utf-8');
                const stored = JSON.parse(data);

                // FIX: Import as namespace to handle ESM/CJS interop safely
                const keysModule = await import('@libp2p/crypto/keys');
                
                // Try finding the function on the module or default export
                const unmarshal = keysModule.unmarshalPrivateKey || keysModule.default?.unmarshalPrivateKey;
                const keyBytes = uint8ArrayFromString(stored.privKey, 'base64');

                let privateKeyObj;
                if (typeof unmarshal === 'function') {
                    privateKeyObj = await unmarshal(keyBytes);
                } else {
                    // Fallback: Try older method name if unmarshalPrivateKey is missing
                    const fromProto = keysModule.privateKeyFromProtobuf || keysModule.default?.privateKeyFromProtobuf;
                    if (typeof fromProto === 'function') {
                         privateKeyObj = await fromProto(keyBytes);
                    } else {
                        throw new Error("Could not find unmarshalPrivateKey function in crypto library");
                    }
                }

                const peerId = await createFromPrivKey(privateKeyObj);

                if (peerId.toString() !== stored.id) {
                    throw new Error(`Loaded PeerID ${peerId} does not match stored ID ${stored.id}`);
                }

                this.log(`[P2P] Successfully loaded permanent bootstrap ID: ${stored.id}`, 'success');
                return peerId;
            } catch (e) {
                this.log(`[P2P] Bootstrap load failed: ${e.message}`, 'error');
                this.log('[P2P] FATAL: Could not load "peer-id.json" for bootstrap node.', 'error');
                process.exit(1);
            }
        }

        // --- NORMAL NODE LOADING LOGIC ---
        try {
            await fs.mkdir('./pluribit-data', { recursive: true });

            const data = await fs.readFile(peerIdPath, 'utf-8');
            const stored = JSON.parse(data);

            const { unmarshalPrivateKey } = await import('@libp2p/crypto/keys');
            const keyBytes = uint8ArrayFromString(stored.privKey, 'base64');

            const privateKey = await unmarshalPrivateKey(keyBytes);
            const peerId = await createFromPrivKey(privateKey);

            if (peerId.toString() !== stored.id) {
                throw new Error('ID mismatch - regenerating');
            }

            this.log(`[P2P] Successfully loaded existing peer ID: ${peerId.toString()}`, 'info');
            return peerId;

        } catch (e) {
            this.log('[P2P] Creating new peer ID...', 'info');
            const peerId = await createEd25519PeerId();

            if (!peerId.privateKey) {
                throw new Error('Generated PeerId missing private key');
            }

            const marshalledKey = peerId.privateKey;

            const data = {
                id: peerId.toString(),
                privKey: uint8ArrayToString(marshalledKey, 'base64'),
                pubKey: uint8ArrayToString(peerId.publicKey, 'base64')
            };

            await fs.writeFile(peerIdPath, JSON.stringify(data, null, 2), { mode: 0o600 });
            try { await fs.chmod(peerIdPath, 0o600); } catch { }

            this.log(`[P2P] Created new peer ID: ${peerId.toString()}`, 'success');
            return peerId;
        }
    }

    isPeerVerified(peerId) {
        const state = this._peerVerificationState.get(peerId.toString());
        if (!state) return false;
        return state.powSolved && state.isSubscribed;
    }

    getIpFromMultiaddr(ma) {
        try {
            const tuples = ma.stringTuples();
            const ipTuple = tuples.find(t => t[0] === 4 || t[0] === 41);
            return ipTuple ? ipTuple[1] : null;
        } catch (e) {
            return null;
        }
    }

    setupEventHandlers() {
        if (!this.node) return;
        
        this.node.addEventListener('peer:connect', async (evt) => {
            const peerId = evt.detail.toString();
    
            if (this.isPeerBannedForBadBlocks(peerId)) {
                this.log(`[P2P] ⚡ Rejecting reconnection from permanently banned peer ${peerId.slice(-8)}`, 'warn');
                try { await this.node.hangUp(peerId); } catch {}
                return;
            }
    
            this.log(`[P2P] Connected to ${peerId}`, 'debug');

            const isBootstrap = this.config.bootstrap.some(addr => addr.includes(peerId));
            if (isBootstrap) {
                this.log('[P2P] Connected to bootstrap, triggering immediate rendezvous...', 'info');
                this._announceAndDiscoverProviders().catch(e => {});
            }
    
            setTimeout(() => { 
                // @ts-ignore
                if (typeof global.bootstrapSync === 'function') global.bootstrapSync(); 
            }, 3000); 

            setTimeout(async () => {
                try {
                    const badEntry = this._badBlockPeers.get(peerId);
                    if (badEntry && badEntry.count >= 1) {
                        this._currentChallengeDifficulty = '0'.repeat(20 + Math.min(badEntry.count, 10));
                        this.log(`[P2P] Bad peer ${peerId.slice(-8)} gets ${this._currentChallengeDifficulty.length} zero difficulty`, 'warn');
                    }

                    await this.sendDirectChallenge(peerId);
                } catch (e) {
                }
            }, 2000);
        });
        
        this.node.addEventListener('peer:disconnect', (evt) => {
            const peerId = evt.detail;
            this.log(`[P2P] Disconnected from ${peerId.toString()}`, 'debug');
            const peerIdStr = peerId.toString();
            this._peerChallenges.delete(peerIdStr);
            this._peerVerificationState.delete(peerIdStr);
            this._buckets.delete(peerIdStr);
        });
        
        this.node.addEventListener('peer:discovery', async (evt) => {
            const { id, multiaddrs } = evt.detail;

            if (!this.node) return;
            if (id?.toString?.() === this.node.peerId.toString()) return;

            if (multiaddrs?.length) {
                await this._addToAddressBookCompat(id, multiaddrs);
            }

            this.log(`[P2P] Discovered peer: ${id.toString()} (${multiaddrs?.length ?? 0} addrs)`, 'debug');

            const connections = this.node.getConnections();
            const already = connections.some(c => c.remotePeer.toString() === id.toString());
            const total = connections.length;
            const target = CONFIG.P2P.MIN_CONNECTIONS;

            if (!already && total < target) {
                try {
                    await this.node.dial(id);
                    this.log(`[P2P] Auto-dialed discovered peer ${id.toString()}`, 'debug');
                } catch (e) {
                }
            }
        });

        this.node.addEventListener('connection:open', (evt) => {
            const connection = evt.detail;
            const peerIdStr = connection.remotePeer.toString();
            this.log(`[P2P] Connection opened to ${peerIdStr}`, 'debug');

            const ip = this.getIpFromMultiaddr(connection.remoteAddr);
                        
            if (!ip) {
                this.log(`[P2P] Relay connection from ${peerIdStr}, skipping IP rate limit`, 'debug');
            }

            const now = Date.now();
            const { BASE_BACKOFF_MS, MAX_BACKOFF_MS, MAX_FAILURES } = CONFIG.P2P.IP_BACKOFF;
            const entry = this._ipChallengeTracker.get(ip) || { failures: 0, lastAttempt: 0 };

            const backoffTime = Math.min(
                BASE_BACKOFF_MS * Math.pow(2, Math.min(entry.failures, MAX_FAILURES)),
                MAX_BACKOFF_MS
            );

            if (now - entry.lastAttempt < backoffTime) {
                this.log(`[SECURITY] IP ${ip} is in exponential backoff (${entry.failures} failures). Rejecting connection.`, 'warn');
                try { connection.close(); } catch {}
                return;
            }
            
            entry.lastAttempt = now;
            this._ipChallengeTracker.set(ip, entry);
            this._connectionAttempts++;
        });
        
        this.node.addEventListener('connection:close', (evt) => {
            const connection = evt.detail;
            this.log(`[P2P] Connection closed to ${connection.remotePeer.toString()}`, 'debug');
        });
        
        this.node.services.pubsub.addEventListener('message', (evt) => {
            this.handleGossipMessage(evt.detail);
        });
        
        this.node.services.pubsub.addEventListener('subscription-change', (evt) => {
            const { peerId, subscriptions } = evt.detail;
            const sub = subscriptions.find(s => s.topic === TOPICS.BLOCKS);

            if (sub) {
                if (sub.subscribe) {
                    this._updateVerificationState(peerId.toString(), { isSubscribed: true, powSolved: undefined });
                } else {
                    this._updateVerificationState(peerId.toString(), { isSubscribed: false, powSolved: undefined });
                }
            }
        });
    }

    async handleGossipMessage(msg) {
        try {
            const from = msg.from?.toString?.() ?? String(msg.from);
            
            if (this.isPeerBannedForBadBlocks(from)) {
                return;
            }
            
            if (!this.isPeerVerified(from)) {
                return;
            }

            if (!Object.values(TOPICS).includes(msg.topic)) {
                return;
            }

            const bytes = msg?.data;
            if (bytes && bytes.byteLength > CONFIG.MAX_MESSAGE_SIZE) {
                return;
            }

            if (!this._allowMessage(from)) {
                return;
            }

            const p2pMessage = p2p.P2pMessage.decode(msg.data);
            // @ts-ignore
            const payloadType = p2pMessage.payload;
            // @ts-ignore
            const data = p2pMessage[payloadType];

            if (data?.hash && this.isHashPoisoned(data.hash)) {
                this.log(`[CONSENSUS SHIELD] Dropping message with poisoned hash ${data.hash.slice(0,12)}… from ${from.slice(-8)}`, 'warn');
                this.banPeer(from, 'sent poisoned hash', true);
                return;
            }

            const handlers = this.handlers.get(msg.topic) || [];
            for (const handler of handlers) {
                try {
                    await handler(data, { from, topic: msg.topic, rawData: msg.data });
                } catch (e) {
                    const err = /** @type {Error} */ (e);

                    if (data?.hash) {
                        this.poisonHash(data.hash, `handler rejected: ${err.message}`, from);
                    }

                    this.log(`[P2P] Handler error from ${from.slice(-8)} on ${msg.topic}: ${err.message}`, 'warn');
                    this.banPeer(from, `handler error (${err.message})`, true);
                }
            }
        } catch (e) {
            const err = /** @type {Error} */ (e);
            const from = msg.from?.toString?.() ?? 'unknown';

            this.log(`[P2P] Malformed protobuf from ${from.slice(-8)}: ${err.message}`, 'warn');
            this.banPeer(from, `malformed protobuf (${err.message})`, true);
        }
    }

    async subscribe(topic, handler) {
        if (!this.node) return;
        
        if (!this.handlers.has(topic)) {
            this.handlers.set(topic, []);
            this.node.services.pubsub.subscribe(topic);
            this.log(`[P2P] Subscribed to ${topic}`);
        }
        this.handlers.get(topic)?.push(handler);
    }

    async publish(topic, data) {
        if (!this.node) return;
        
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

    async store(key, value) {
        if (!this.node) return;
        
        const nsKey = `/pluribit/${key}`;
        const payload = { type: 'pluribit', value, timestamp: Date.now() };
        const toSign = stableStringify({
            ns: nsKey,
            payload,
            from: this.node.peerId.toString(),
            v: 1
        });
        const hashHex = sha256Hex(toSign);
        const hashBytes = uint8ArrayFromString(hashHex, 'hex');
        
        // @ts-ignore
        const privKey = this.node.peerId.privateKey;
        // @ts-ignore
        const pubKey = this.node.peerId.publicKey;
        if (!privKey || !pubKey) {
            throw new Error('PeerId missing keys');
        }
        
        const sig = nacl.sign.detached(hashBytes, privKey);
        const envelope = {
            ns: nsKey,
            payload,                 
            from: this.node.peerId.toString(),
            // @ts-ignore
            pubKey: uint8ArrayToString(pubKey, 'base64'),
            sig: uint8ArrayToString(sig, 'base64'),
            alg: 'ed25519',
            v: 1
        };
        // @ts-ignore
        const result = await this.node.services.dht.put(
            uint8ArrayFromString(nsKey),
            uint8ArrayFromString(JSON.stringify(envelope))
        );
        // @ts-ignore
        if (result?.[Symbol.asyncIterator]) {
            // @ts-ignore
            for await (const _ of result) {}
        }
    }

    async get(key) {
        try {
            if (!this.node) return null;
            
            const nsKey = `/pluribit/${key}`;
            // @ts-ignore
            const result = await this.node.services.dht.get(uint8ArrayFromString(nsKey));
            
            let resultValue;
            // @ts-ignore
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
            
            const env = JSON.parse(uint8ArrayToString(resultValue));

            if (!env || env.ns !== nsKey || env.v !== 1 || env.alg !== 'ed25519') {
                return null;
            }
            if (!env.pubKey || !env.sig || !env.payload) {
                return null;
            }

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
                return null;
            }

            try {
                // @ts-ignore
                const derived = await createFromPubKey({ publicKey: pub });
                if (derived.toString() !== env.from) {
                    return null;
                }
            } catch (e) {
                return null;
            }

            if (Date.now() - (env.payload?.timestamp || 0) > 86_400_000) return null;
            if ((env.payload?.timestamp || 0) > Date.now() + 5 * 60_000) return null;

            const last = this._dhtSeen.get(nsKey) || 0;
            if ((env.payload?.timestamp || 0) <= last) return null;
            this._dhtSeen.set(nsKey, env.payload.timestamp);

            return env.payload?.value ?? null;
        } catch (e) {
            return null;
        }
    }

    getConnectedPeers() {
        if (!this.node) {
            return [];
        }

        const connections = this.node.getConnections();

        // <--- FIXED: Safely verify peerStore records without throwing
        return connections
            .map(c => c.remotePeer)
            .filter(peerId => peerId != null) 
            .map(peerId => {
                try {
                    // Modern libp2p peerStore.get is likely async, but synchronous
                    // access via connections map is safer for basic ID retrieval.
                    // Here we just return the ID to avoid race conditions.
                    return {
                        id: peerId.toString(),
                        protocols: [] // Protocol check not strictly needed here
                    };
                } catch (e) {
                    return {
                        id: peerId.toString(),
                        protocols: []
                    };
                }
            });
    }
    
    async getKnownPeers() {
        if (!this.node) return [];
        const peers = [];
        
        const allPeers = await this.node.peerStore.all();
        
        for (const peer of allPeers) {
            peers.push(peer.id.toString());
        }
        return peers;
    }

    async reVerifyPeer(peerId, timeoutMs = 5000) {
        try {
            if (!this.node) return false;
            
            const connections = this.node.getConnections();
            const connection = connections.find(c => c.remotePeer.toString() === peerId);
            if (!connection) return false;
            
            const challenge = crypto.randomBytes(16).toString('hex');
            
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), timeoutMs);
            
            try {
                const stream = await connection.newStream('/pluribit/challenge/1.0.0', {
                    signal: controller.signal
                });
                
                const message = p2p.Challenge.create({ 
                    challenge, 
                    from: this.node.peerId.toString(),
                    difficulty: "" 
                });
                
                await pipe([p2p.Challenge.encode(message).finish()], stream.sink);
                
                const chunks = [];
                for await (const chunk of stream.source) {
                    chunks.push(chunk.subarray());
                    break; 
                }
                
                clearTimeout(timeout);
                return chunks.length > 0;
                
            } catch (e) {
                clearTimeout(timeout);
                return false;
            }
            
        } catch (e) {
            return false;
        }
    }
    
    async savePeers() {
        if (!this.node) return;
        try {
            const peersToSave = [];
            const allPeers = await this.node.peerStore.all();
            
            for (const peer of allPeers) {
                const addrs = peer.addresses.map(a => a.multiaddr.toString());
                if (addrs.length > 0) {
                    peersToSave.push({
                        id: peer.id.toString(),
                        addrs: addrs
                    });
                }
            }
            
            await fs.mkdir(path.dirname(PEER_STORE_PATH), { recursive: true });
            await fs.writeFile(PEER_STORE_PATH, JSON.stringify(peersToSave, null, 2));
            this.log(`[PERSISTENCE] Saved ${peersToSave.length} peers to disk.`, 'debug');
        } catch (e) {
            this.log(`[PERSISTENCE] Failed to save peers: ${e.message}`, 'warn');
        }
    }

    async loadPeers() {
        if (!this.node) return;
        try {
            try {
                await fs.access(PEER_STORE_PATH);
            } catch {
                this.log('[PERSISTENCE] No saved peers found. Starting fresh.', 'debug');
                return;
            }

            const data = await fs.readFile(PEER_STORE_PATH, 'utf-8');
            const peers = JSON.parse(data);
            
            let count = 0;
            for (const p of peers) {
                try {
                    // <--- FIXED: Use string conversion for address book
                    const peerId = peerIdFromString(p.id);
                    const multiaddrs = p.addrs.map(a => multiaddr(a));                   
               
                     await this._addToAddressBookCompat(peerId, multiaddrs);
                     count++;
                } catch (e) {
                    // ignore malformed entries
                }
            }
            this.log(`[PERSISTENCE] Loaded ${count} peers from disk.`, 'info');
        } catch (e) {
            this.log(`[PERSISTENCE] Failed to load peers: ${e.message}`, 'error');
        }
    }
    
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
            // @ts-ignore
            this._rendezvousTimer = null;
        }
        if (this._challengeGcTimer) {
            clearInterval(this._challengeGcTimer);
            // @ts-ignore
            this._challengeGcTimer = null;
        }
        if (this._stemRelayRefreshTimer) {
            clearInterval(this._stemRelayRefreshTimer);
            this._stemRelayRefreshTimer = null;
        }
        
        for (const timer of this._embargoedTransactions.values()) {
            clearTimeout(timer);
        }
        this._embargoedTransactions.clear();
        await this.savePeers();
        if (this.node) {
            await this.node.stop();
        }
    }

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

            case TOPICS.SWAP_PROPOSE: return 'swapPropose';
            case TOPICS.SWAP_RESPOND: return 'swapRespond';
            case TOPICS.SWAP_ALICE_ADAPTOR_SIG: return 'swapAliceAdaptorSig';
            
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

    async exchangePeers(peerId) {
        if (!this.node) return;
        try {
            const connection = this.node.getConnections().find(c => c.remotePeer.toString() === peerId);
            if (!connection) return;

            const allPeers = await this.node.peerStore.all();
            const shareablePeers = allPeers
                .filter(p => p.addresses.length > 0 && p.id.toString() !== peerId) 
                .sort(() => Math.random() - 0.5)
                .slice(0, 20)
                .map(p => ({
                    id: p.id.toString(),
                    addrs: p.addresses.map(a => a.multiaddr.toString())
                }));

            if (shareablePeers.length === 0) return;

            const stream = await connection.newStream(PEX_PROTOCOL);
            const payload = JSON.stringify(shareablePeers);
            
            await pipe(
                [new TextEncoder().encode(payload)],
                stream.sink
            );
            
        } catch (e) {
            this.log(`[PEX] Failed to exchange with ${peerId.slice(-6)}: ${e.message}`, 'debug');
        }
    }

    async _handlePexRequest({ stream, connection }) {
        try {
            const remotePeerId = connection.remotePeer.toString();
            
            const chunks = [];
            for await (const chunk of stream.source) {
                chunks.push(chunk.subarray());
            }
            const data = Buffer.concat(chunks).toString();
            const peers = JSON.parse(data);

            let newCount = 0;
            for (const p of peers) {
                if (p.id === this.node.peerId.toString()) continue;

                try {
                    const multiaddrs = p.addrs.map(a => multiaddr(a));
                    // <--- FIXED: Ensure PeerID object is used for address book
                    const peerId = peerIdFromString(p.id);
                    await this._addToAddressBookCompat(peerId, multiaddrs);
                    
                    this.node.dispatchEvent(new CustomEvent('peer:discovery', { 
                        detail: { id: peerId, multiaddrs } 
                    }));
                    newCount++;
                } catch(e) {}
            }
            
            if (newCount > 0) {
                this.log(`[PEX] Learned ${newCount} new peers from ${remotePeerId.slice(-6)}`, 'debug');
            }
        } catch (e) {
            this.log(`[PEX] Error handling incoming PEX: ${e.message}`, 'debug');
        } finally {
            try { await stream.close(); } catch{}
        }
    }
}
