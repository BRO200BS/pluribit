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

import { kadDHT } from '@libp2p/kad-dht';
import { gossipsub } from '@chainsafe/libp2p-gossipsub';
import { bootstrap } from '@libp2p/bootstrap';
import { identify } from '@libp2p/identify';
import { ping } from '@libp2p/ping'; 
import { createEd25519PeerId } from '@libp2p/peer-id-factory';
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string';
import { toString as uint8ArrayToString } from 'uint8arrays/to-string';
import { JSONStringifyWithBigInt, JSONParseWithBigInt } from './utils.js';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';

// Topic definitions
export const TOPICS = {
  BLOCKS: '/pluribit/blocks/1.0.0',
  TRANSACTIONS: '/pluribit/transactions/1.0.0',
  BLOCK_REQUEST: '/pluribit/block-request/1.0.0',
  SYNC: '/pluribit/sync/1.0.0',   
};

export class PluribitP2P {
constructor(log, options = {}) {
    this.log = log;
    this.node = null;
    this.handlers = new Map();
    this.isBootstrap = options.isBootstrap || false;
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
}

  // Simple per-peer token bucket
  _buckets = new Map();
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

    if (b.tokens <= 0) return false;
    b.tokens -= 1;
    return true;
  }

  _rendezvousStr = process.env.PLURIBIT_RENDEZVOUS || 'pluribit:mainnet:v1';
  _rendezvousCid = null;
  _rendezvousTimer = null;

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

      // Announce ourselves as a provider for the rendezvous CID
      // (this populates provider records on the public DHT)
      for await (const _event of this.node.contentRouting.provide(cid)) {
        // no-op: iterate to drive the async iterable to completion
      }
      this.log(`[P2P] 📣 Provided rendezvous CID ${cid.toString()}`);

      // Discover other providers and auto-dial them
      const providers = [];
      for await (const p of this.node.contentRouting.findProviders(cid, { timeout: 15_000 })) {
        providers.push(p);
      }

      const myId = this.node.peerId.toString();
      for (const p of providers) {
        const id = p.id?.toString?.();
        if (!id || id === myId) continue;

        const already = this.node.getConnections(id).length > 0;
        if (!already) {
          try {
            // Save any announced multiaddrs, then dial
            if (p.multiaddrs?.length) {
              await this.node.peerStore.addressBook.add(p.id, p.multiaddrs);
            }
            await this.node.dial(p.id);
            this.log(`[P2P] 🔌 Dialed rendezvous provider ${id}`);
          } catch (e) {
            this.log(`[P2P] Rendezvous dial to ${id} failed: ${e.message}`, 'warn');
          }
        }
      }
    } catch (e) {
      this.log(`[P2P] Rendezvous error: ${e.message}`, 'warn');
    }
  }



async initialize() {
    this.log('[P2P] Initializing libp2p node...');
    
    // Try to load bootstrap addresses from config
    if (!this.isBootstrap) {
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

    // Create libp2p node
    this.node = await createLibp2p({
        peerId,
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

              validators: {
                pluribit: {
                  func: (key, value) => {
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
                allowPublishToZeroPeers: true,
                seenTTL: 120 * 1000,
                emitSelf: false,
                gossipIncoming: true,
                fallbackToFloodsub: false,
                floodPublish: false,
                doPX: true,
                msgIdFn: (msg) => {
                    const hash = crypto.createHash('sha256');
                    hash.update(msg.data);
                    return hash.digest();
                },
                globalSignaturePolicy: 'StrictSign',
                scoreParams: {
                    topics: {
                        [TOPICS.BLOCKS]: {
                            topicWeight: 1.0,
                            timeInMeshWeight: 0.5,
                            timeInMeshQuantum: 12000,
                            timeInMeshCap: 300,
                            firstMessageDeliveriesWeight: 1.0,
                            firstMessageDeliveriesDecay: 0.5,
                            firstMessageDeliveriesCap: 100,
                            meshMessageDeliveriesWeight: -1.0,
                            meshMessageDeliveriesDecay: 0.5,
                            meshMessageDeliveriesThreshold: 5,
                            meshMessageDeliveriesCap: 10,
                            meshMessageDeliveriesActivation: 30000,
                            meshMessageDeliveriesWindow: 5000,
                            invalidMessageDeliveriesWeight: -10.0,
                            invalidMessageDeliveriesDecay: 0.5
                        },
                        [TOPICS.TRANSACTIONS]: {
                            topicWeight: 0.5,
                            timeInMeshWeight: 0.5,
                            timeInMeshQuantum: 12000,
                            timeInMeshCap: 300,
                            firstMessageDeliveriesWeight: 0.5,
                            firstMessageDeliveriesDecay: 0.5,
                            firstMessageDeliveriesCap: 1000
                        }
                    }
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
                    interval: 30000,
                    timeout: 30000
                }),
                mdns() 
            ]
            : [mdns()],
       connectionManager: {
            minConnections: this.isBootstrap ? 0 : CONFIG.P2P.MIN_CONNECTIONS, 
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
    
    const addrs = this.node.getMultiaddrs();
    addrs.forEach(addr => this.log(`[P2P] Listening on ${addr.toString()}`));

    // Proactively dial bootstrap peers once
    if (!this.isBootstrap && Array.isArray(this.config.bootstrap) && this.config.bootstrap.length) {
      const tasks = this.config.bootstrap.map(async (addr) => {
        try {
          await this.node.dial(multiaddr(addr));
          this.log(`[P2P] 🔌 Dialed bootstrap ${addr}`);
        } catch (e) {
          this.log(`[P2P] Could not dial bootstrap ${addr}: ${e.message}`, 'warn');
        }
      });
      await Promise.allSettled(tasks);
    }

    // Start DHT (guard in case libp2p already started it)
    try {
      if (this.node.services.dht?.isStarted?.() === false) {
        await this.node.services.dht.start();
      }
    } catch { /* ignore if already started */ }
    
    // Zero-infra rendezvous: announce & discover via public DHT provider records
    await this._announceAndDiscoverProviders();
    this._rendezvousTimer = setInterval(
      () => this._announceAndDiscoverProviders(),
      10 * 60 * 1000 // every 10 minutes
    );
    
    return this.node;
}

  async loadOrCreatePeerId() {
    const peerIdPath = './pluribit-data/peer-id.json';
    try {
      await fs.mkdir('./pluribit-data', { recursive: true });
      const data = await fs.readFile(peerIdPath, 'utf-8');
      const stored = JSON.parse(data);
      return await createEd25519PeerId({
        privateKey: uint8ArrayFromString(stored.privKey, 'base64')
      });
    } catch {
      // Create new
      const peerId = await createEd25519PeerId();
      const data = {
        id: peerId.toString(),
        privKey: uint8ArrayToString(peerId.privateKey, 'base64'),
        pubKey: uint8ArrayToString(peerId.publicKey, 'base64')
      };
      await fs.writeFile(peerIdPath, JSON.stringify(data, null, 2));
      this.log('[P2P] Created new peer ID');
      return peerId;
    }
  }

setupEventHandlers() {
this.node.addEventListener('peer:connect', (evt) => {
    const peerId = evt.detail;
    this.log(`[P2P] ✅ Connected to ${peerId.toString()}`);
});
    
    this.node.addEventListener('peer:disconnect', (evt) => {
        const peerId = evt.detail;
        this.log(`[P2P] Disconnected from ${peerId.toString()}`);
    });
    
// Add discovery events with auto-dial
this.node.addEventListener('peer:discovery', async (evt) => {
  const { id, multiaddrs } = evt.detail;

  // ignore self
  if (id?.toString?.() === this.node.peerId.toString()) return;

  // persist addresses so the conn mgr can use them
  if (multiaddrs?.length) {
    try {
      await this.node.peerStore.addressBook.add(id, multiaddrs);
    } catch (e) {
      this.log(`[P2P] addressBook.add failed for ${id.toString()}: ${e.message}`, 'warn');
    }
  }

  this.log(`[P2P] 📣 Discovered peer: ${id.toString()} (${multiaddrs?.length ?? 0} addrs)`);

  // if we're under the target and not already connected, dial now
  const already = this.node.getConnections(id).length > 0;
  const total = this.node.getConnections().length;
  const target = CONFIG.P2P.MIN_CONNECTIONS;

  if (!already && total < target) {
    try {
      await this.node.dial(id);
      this.log(`[P2P] 🔌 Auto-dialed discovered peer ${id.toString()}`);
    } catch (e) {
      this.log(`[P2P] Auto-dial to ${id.toString()} failed: ${e.message}`, 'warn');
    }
  }
});

    
    // Add connection events for debugging
this.node.addEventListener('connection:open', (evt) => {
    const connection = evt.detail;
    this.log(`[P2P] ✅ Connection opened to ${connection.remotePeer.toString()}`);
});
    
    this.node.addEventListener('connection:close', (evt) => {
        const connection = evt.detail;
        this.log(`[P2P] Connection closed to ${connection.remotePeer.toString()}`);
    });
    
    // GossipSub message handler
    this.node.services.pubsub.addEventListener('message', (evt) => {
        this.handleGossipMessage(evt.detail);
    });
}

    async handleGossipMessage(msg) {
      try {
        // 1) Drop oversize payloads
        const bytes = msg?.data;
        if (bytes && bytes.byteLength > CONFIG.MAX_MESSAGE_SIZE) {
          this.log(`[P2P] Dropping oversize message on ${msg.topic} from ${msg.from}`, 'warn');
          return;
        }

        // 2) Per-peer rate limit
        const from = msg.from?.toString?.() ?? String(msg.from);
        if (!this._allowMessage(from)) {
          this.log(`[P2P] Rate-limited ${from} on ${msg.topic}`, 'warn');
          return;
        }

        // 3) Parse and dispatch
        const data = JSONParseWithBigInt(uint8ArrayToString(msg.data));
        const handlers = this.handlers.get(msg.topic) || [];
        for (const handler of handlers) {
          try {
            await handler(data, { from, topic: msg.topic });
          } catch (e) {
            this.log(`[P2P] Handler error for ${msg.topic}: ${e.message}`, 'error');
          }
        }
      } catch (e) {
        this.log(`[P2P] Failed to parse message: ${e.message}`, 'error');
      }
    }


  // Public API

  async subscribe(topic, handler) {
    if (!this.handlers.has(topic)) {
      this.handlers.set(topic, []);
      this.node.services.pubsub.subscribe(topic);
      this.log(`[P2P] Subscribed to ${topic}`);
    }
    this.handlers.get(topic).push(handler);
  }

  async publish(topic, data) {
    const message = {
      ...data,
      timestamp: Date.now(),
      from: this.node.peerId.toString()
    };
    await this.node.services.pubsub.publish(
      topic,
      uint8ArrayFromString(JSONStringifyWithBigInt(message))
    );
  }

    async store(key, value) {
      const nsKey = `/pluribit/${key}`;
      const data = { type: 'pluribit', value, timestamp: Date.now() };
      await this.node.services.dht.put(
        uint8ArrayFromString(nsKey),
        uint8ArrayFromString(JSON.stringify(data))
      );
    }


async get(key) {
  try {
    const nsKey = `/pluribit/${key}`;
    const result = await this.node.services.dht.get(uint8ArrayFromString(nsKey));
    const data = JSON.parse(uint8ArrayToString(result));
    return data.value;
  } catch {
    return null;
  }
}

  getConnectedPeers() {
    // Get all connected peer IDs
    const peerIds = this.node.getPeers();

    // Map over the peer IDs to get their details
    return peerIds.map(peerId => {
      // CORRECTED: First, get the full peer object from the peerStore
      const peer = this.node.peerStore.get(peerId);
      
      // If the peer exists, get its protocols, otherwise return an empty array
      const protocols = peer ? peer.protocols : [];
      
      return {
        id: peerId.toString(),
        protocols: protocols
      };
    });
  }

async stop() {
  if (this._rendezvousTimer) {
    clearInterval(this._rendezvousTimer);
    this._rendezvousTimer = null;
  }
  await this.node.stop();
}
}
