export const CONFIG = {
  // Network limits
  MAX_MESSAGE_SIZE: 1024 * 1024, // 1mb: large enough for block headers, prevents memory bombs
  RATE_LIMIT_MESSAGES: 1200,      // 1200/min/peer to blunt flood attacks
  RATE_LIMIT_WINDOW: 60_000,
  
  // libp2p settings
  P2P: {
    TCP_PORT: 26658,
    WS_PORT: 26659,
    MAX_CONNECTIONS: 150,
    MIN_CONNECTIONS: 5
  },
  
  // Sync (IBD) settings
  SYNC: {
    TIMEOUT_MS: 24 * 60 * 60 * 1000, // 24 hours for IBD
    INTER_REQUEST_DELAY_MS: 25,  // Minimal delay for rate limiting
    MAX_FETCH_ATTEMPTS: 15,       // Retries for a single failed block fetch
    PARALLEL_DOWNLOADS: 50,        // Number of concurrent block downloads
    BATCH_SIZE: 100,             // Blocks per batch
    CHECKPOINT_INTERVAL: 1000,   // Save progress every N blocks

    // --- RATIONALE (Hardening Recommendations) ---
    // These new settings harden the node against various sync-related attacks by
    // enforcing strict limits on data from peers.

    // (Fix #1) Prevents memory exhaustion from a malicious peer sending a giant list of bogus hashes.
    MAX_HASHES_PER_SYNC: 2_000_000, // Max hashes to accept (~100MB RAM usage).
    // (Fix #4) Requires a stronger majority for consensus on the best chain tip.
    CONSENSUS_THRESHOLD: 0.5,
    PEER_COUNT_FOR_STRICT_CONSENSUS:51,
    MIN_AGREEING_PEERS: 1, // An absolute minimum number of peers that must agree on a tip.
    // (Fix #6) Prevents DoS from a peer spamming requests for the node's block hashes.
    MIN_HASH_REQUEST_INTERVAL_MS: 1, // 1 seconds between requests per peer.
    // (Fix #10) Prevents peers from requesting absurdly old or future block hashes.
    MAX_HASH_REQUEST_RANGE: 100_000, // Peer can't ask for hashes more than this many blocks behind the tip.
    // (Circuit Breaker) Stops sync attempts after too many consecutive failures.
    MAX_CONSECUTIVE_SYNC_FAILURES: 5,
  },
  
  
  // Dandelion++ Protocol Settings
  DANDELION: {
    // Probability of continuing stem phase (vs switching to fluff)
    STEM_PROBABILITY: 0.90, // 90% chance to continue stem
    
    // Maximum stem phase hops before forced fluff
    MAX_STEM_HOPS: 10,
    
    // Minimum stem phase hops before allowing fluff
    MIN_STEM_HOPS: 1,
    
    // Embargo timer: max time to hold a transaction in stem (ms)
    EMBARGO_TIMEOUT_MS: 30000, // 30 seconds
    
    // How often to refresh stem relay peers (ms)
    STEM_RELAY_REFRESH_INTERVAL_MS: 600000, // 10 minutes
    
    // Enable Dandelion protocol
    ENABLED: true
  }
};
