// src/block.rs
use serde::{Serialize, Deserialize};
use crate::transaction::Transaction;
use crate::vdf::VDFProof;
use crate::vrf::VrfProof;
use sha2::{Sha256, Digest};
use crate::wasm_types::WasmU64;
use crate::{constants::{GENESIS_TIMESTAMP_MS, GENESIS_BITCOIN_HASH, DEFAULT_VRF_THRESHOLD, INITIAL_VDF_ITERATIONS}, error::PluribitError};
use crate::p2p;

use crate::error::PluribitResult;
use std::collections::HashSet;
use crate::transaction::{TransactionInput, TransactionOutput, TransactionKernel};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
   pub height: WasmU64,
   pub prev_hash: String,
   pub timestamp: WasmU64,
   pub transactions: Vec<Transaction>,
   
   // SEQLOT Fields
   pub lottery_nonce: WasmU64,
   pub vrf_proof: VrfProof,
   pub vdf_proof: VDFProof,
   #[serde(with = "serde_bytes")]
   pub miner_pubkey: [u8; 32],
   
   // NEW: Consensus-committed parameters
   #[serde(with = "serde_bytes")]
   pub vrf_threshold: [u8; 32],
   pub vdf_iterations: WasmU64,

   // Merkle root
   #[serde(with = "serde_bytes")]
   pub tx_merkle_root: [u8; 32],
   
   //cumulative work
   pub total_work: WasmU64, 
   
   //  hash as a computed field during serialization
   #[serde(skip_deserializing)]
   pub hash: String,
}

impl Block {
   pub fn genesis() -> Self {
       // Hash the Bitcoin block anchor to create our genesis `prev_hash`
       let mut hasher = Sha256::new();
       hasher.update(b"pluribit_genesis_anchor_v1"); // Domain separator
       hasher.update(GENESIS_BITCOIN_HASH.as_bytes());
       let genesis_prev_hash = hex::encode(hasher.finalize());

       let mut block = Block {
           height: WasmU64::from(0),
           prev_hash: genesis_prev_hash,
           timestamp: WasmU64::from(GENESIS_TIMESTAMP_MS), 
           transactions: vec![],
           lottery_nonce: WasmU64::from(0),
           vrf_proof: VrfProof::default(),
           vdf_proof: VDFProof::default(),
           miner_pubkey: [0u8; 32],
           vrf_threshold: DEFAULT_VRF_THRESHOLD,
           vdf_iterations: WasmU64::from(INITIAL_VDF_ITERATIONS),
           tx_merkle_root: Sha256::digest(&[]).into(),
           total_work: WasmU64::from(0),
           hash: String::new(), // Will be computed below
       };
       block.hash = block.compute_hash();
       block
   }
   
   /// Calculates the hash of the block header.
   pub fn compute_hash(&self) -> String {
       let mut hasher = Sha256::new();
       hasher.update(b"pluribit_block_v3"); // Version bump for replay protection
       hasher.update(&self.height.0.to_le_bytes());
       hasher.update(self.prev_hash.as_bytes());
       hasher.update(&self.timestamp.0.to_le_bytes());
       hasher.update(&self.tx_merkle_root);
       // FIX #10: Include lottery nonce in hash to bind VDF to specific block height
       hasher.update(&self.lottery_nonce.0.to_le_bytes());
       hasher.update(&self.vrf_proof.output);
       hasher.update(&self.vdf_proof.y);
       hasher.update(&self.miner_pubkey);
       // ADDED: Commit to consensus parameters
       hasher.update(&self.vrf_threshold);
       hasher.update(&self.vdf_iterations.0.to_le_bytes());
       hex::encode(hasher.finalize())
   }

   /// dont trust, verify!
    pub fn hash(&self) -> String {
        // Always recompute from canonical header fields
        self.compute_hash()
    }
   

   
   /// Calculates the Merkle root of the block's transactions.
   pub fn calculate_tx_merkle_root(&self) -> [u8; 32] {
       if self.transactions.is_empty() {
           return Sha256::digest(&[]).into();
       }

       let mut leaves: Vec<[u8; 32]> = self.transactions.iter()
           .map(|tx| Sha256::digest(tx.hash().as_bytes()).into())
           .collect();

       while leaves.len() > 1 {
           if leaves.len() % 2 == 1 {
               leaves.push(*leaves.last().unwrap());
           }
           leaves = leaves.chunks(2)
               .map(|pair| {
                   let mut h = Sha256::new();
                   h.update(&pair[0]);
                   h.update(&pair[1]);
                   h.finalize().into()
               })
               .collect();
       }
       leaves[0]
   }

    /// Apply cut-through to remove intermediate transactions
    pub fn apply_cut_through(&mut self) -> PluribitResult<()> {
        // CRITICAL FIX #4: Validate no double-spends exist before cut-through
        let mut seen_inputs = HashSet::new();
        for tx in &self.transactions {
            for input in &tx.inputs {
                if !seen_inputs.insert(input.commitment.clone()) {
                    return Err(PluribitError::InvalidBlock(
                        format!("Double-spend detected: commitment {} spent multiple times in block",
                            hex::encode(&input.commitment[..8]))
                    ));
                }
            }
        }
        
        // Also validate outputs are unique (shouldn't happen but defense in depth)
        let mut seen_outputs = HashSet::new();
        for tx in &self.transactions {
            for output in &tx.outputs {
                if !seen_outputs.insert(output.commitment.clone()) {
                    return Err(PluribitError::InvalidBlock(
                        "Duplicate output commitment in block".to_string()
                    ));
                }
            }
        }

        // No work needed if there's only a coinbase transaction (or fewer).
        if self.transactions.len() <= 1 {
            return Ok(());
        }

        // 1. ISOLATE THE COINBASE TRANSACTION
        let coinbase_tx = if !self.transactions.is_empty() && self.transactions[0].inputs.is_empty() {
            Some(self.transactions.remove(0))
        } else {
            None
        };

        // If there were no regular transactions, put the coinbase back and finish.
        if self.transactions.is_empty() {
            if let Some(cb) = coinbase_tx {
                self.transactions.push(cb);
            }
            return Ok(());
        }

        // 2. COLLECT AND ANALYZE TRANSACTIONS
        let all_inputs: Vec<TransactionInput> = self.transactions.iter().flat_map(|tx| tx.inputs.clone()).collect();
        let all_outputs: Vec<TransactionOutput> = self.transactions.iter().flat_map(|tx| tx.outputs.clone()).collect();
        
        // Find outputs that are spent within this same set
        let block_outputs: HashSet<Vec<u8>> = all_outputs.iter().map(|o| o.commitment.clone()).collect();
        let internal_spends: HashSet<Vec<u8>> = all_inputs.iter()
            .filter(|input| block_outputs.contains(&input.commitment))
            .map(|input| input.commitment.clone())
            .collect();

        // If there are no internal spends, don't aggregate - keep transactions separate
        if internal_spends.is_empty() {
            // Put coinbase back at the beginning
            if let Some(cb) = coinbase_tx {
                self.transactions.insert(0, cb);
            }
            return Ok(());
        }

        // 3. PERFORM CUT-THROUGH
        let external_inputs: Vec<TransactionInput> = all_inputs.into_iter()
            .filter(|input| !internal_spends.contains(&input.commitment))
            .collect();

        let unspent_outputs: Vec<TransactionOutput> = all_outputs.into_iter()
            .filter(|output| !internal_spends.contains(&output.commitment))
            .collect();
        
        // Collect all kernels (NO signature aggregation - concatenate)
        let mut all_kernels: Vec<TransactionKernel> = Vec::new();
        for tx in &self.transactions {
            all_kernels.extend(tx.kernels.clone());
        }
        
        // Create aggregated transaction with all kernels
        let aggregated_tx = Transaction {
            inputs: external_inputs,  // ✅ Use filtered inputs
            outputs: unspent_outputs, // ✅ Use filtered outputs
            kernels: all_kernels,
            timestamp: WasmU64::from(0),
            aggregated_range_proof: vec![], // Aggregated tx has no proof
        };

        // 4. REBUILD TRANSACTION LIST
        let mut final_transactions = Vec::new();
        if let Some(cb) = coinbase_tx {
            final_transactions.push(cb);
        }
        final_transactions.push(aggregated_tx);

        self.transactions = final_transactions;
        Ok(())
    }

    pub fn calculate_utxo_merkle_root(utxos: &[(Vec<u8>, TransactionOutput)]) -> [u8; 32] {
        if utxos.is_empty() {
            return Sha256::digest(&[]).into();
        }

        let leaves: Vec<[u8; 32]> = utxos.iter()
            .map(|(commitment, output)| {
                let mut hasher = Sha256::new();
                hasher.update(commitment);
                hasher.finalize().into()
            })
            .collect();

        let (_proofs, root) = crate::merkle::build_merkle_tree_with_proofs(&leaves);
        root
    }
}

/// **Conversion from Protobuf to internal struct**
impl From<p2p::Block> for Block {
    fn from(proto: p2p::Block) -> Self {
        let mut miner_pubkey = [0u8; 32];
        if proto.miner_pubkey.len() == 32 {
            miner_pubkey.copy_from_slice(&proto.miner_pubkey);
        } else if !proto.miner_pubkey.is_empty() {
            crate::log(&format!("[PROTO WARNING] Invalid miner_pubkey length: {}", proto.miner_pubkey.len()));
        }
        
        let mut vrf_threshold = [0u8; 32];
        if proto.vrf_threshold.len() == 32 {
            vrf_threshold.copy_from_slice(&proto.vrf_threshold);
        } else if !proto.vrf_threshold.is_empty() {
            crate::log(&format!("[PROTO WARNING] Invalid vrf_threshold length: {}", proto.vrf_threshold.len()));
        }
        
        let mut tx_merkle_root = [0u8; 32];
        if proto.tx_merkle_root.len() == 32 {
            tx_merkle_root.copy_from_slice(&proto.tx_merkle_root);
        } else if !proto.tx_merkle_root.is_empty() {
            crate::log(&format!("[PROTO WARNING] Invalid tx_merkle_root length: {}", proto.tx_merkle_root.len()));
        }

        Block {
            height: WasmU64::from(proto.height),
            prev_hash: proto.prev_hash,
            timestamp: WasmU64::from(proto.timestamp),
            transactions: proto.transactions.into_iter().map(Transaction::from).collect(),
            lottery_nonce: WasmU64::from(proto.lottery_nonce),
            vrf_proof: proto.vrf_proof.map(VrfProof::from).unwrap_or_default(),
            vdf_proof: proto.vdf_proof.map(VDFProof::from).unwrap_or_default(),
            miner_pubkey,
            vrf_threshold,
            vdf_iterations: WasmU64::from(proto.vdf_iterations),
            tx_merkle_root,
            // SECURITY: Never trust total_work from network - always recompute
            total_work: WasmU64::from(0),
            // SECURITY: Hash will be recomputed in ingest_block_bytes
            hash: String::new(),
        }
    }
}

/// **Conversion from internal struct to Protobuf**
impl From<Block> for p2p::Block {
    fn from(block: Block) -> Self {
        p2p::Block {
            height: *block.height,
            prev_hash: block.prev_hash,
            timestamp: *block.timestamp,
            transactions: block.transactions.into_iter().map(p2p::Transaction::from).collect(),
            lottery_nonce: *block.lottery_nonce,
            vrf_proof: Some(p2p::VrfProof::from(block.vrf_proof)),
            vdf_proof: Some(p2p::VdfProof::from(block.vdf_proof)),
            miner_pubkey: block.miner_pubkey.to_vec(),
            vrf_threshold: block.vrf_threshold.to_vec(),
            vdf_iterations: *block.vdf_iterations,
            tx_merkle_root: block.tx_merkle_root.to_vec(),
            total_work: *block.total_work,
            hash: block.hash,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;
    use crate::mimblewimble;
    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn test_apply_cut_through() {
        // Create some test wallets
        let alice = Wallet::new();
        let _bob = Wallet::new();
        let _charlie = Wallet::new();

        // Create an external UTXO that Alice already owns (from a previous block)
        let alice_external_blinding = Scalar::from(999u64);
        let alice_external_commitment = mimblewimble::commit(50_000_000, &alice_external_blinding)
            .unwrap().compress().to_bytes().to_vec();

        // Transaction 1: Alice (50 external) -> Bob (20) + Alice_change (29) + fee (1)
        let tx1_bob_blinding = Scalar::from(456u64);
        let tx1_change_blinding = Scalar::from(789u64);
        let tx1_kernel_blinding = alice_external_blinding - tx1_bob_blinding - tx1_change_blinding;
        
        let bob_commitment = mimblewimble::commit(20_000_000, &tx1_bob_blinding).unwrap();
        let alice_change_commitment = mimblewimble::commit(29_000_000, &tx1_change_blinding).unwrap();
        
        let (bob_range_proof, _) = mimblewimble::create_range_proof(20_000_000, &tx1_bob_blinding).unwrap();
        let (change_range_proof, _) = mimblewimble::create_range_proof(29_000_000, &tx1_change_blinding).unwrap();

        let tx1 = Transaction {
            inputs: vec![TransactionInput {
                commitment: alice_external_commitment.clone(),
                merkle_proof: None,
                source_height: WasmU64::from(0),
            }],
            outputs: vec![
                TransactionOutput {
                    commitment: bob_commitment.compress().to_bytes().to_vec(),

                    // Remove: range_proof: bob_range_proof.to_bytes(),
                    ephemeral_key: None,
                    stealth_payload: None,
                    view_tag: None, // Add this
                },
                TransactionOutput {
                    commitment: alice_change_commitment.compress().to_bytes().to_vec(),

                    // Remove: range_proof: change_range_proof.to_bytes(),
                    ephemeral_key: None,
                    stealth_payload: None,
                    view_tag: None, // Add this
                }],
            kernels: vec![TransactionKernel::new(tx1_kernel_blinding, 1_000_000, 0, 1).unwrap()],
            timestamp: WasmU64::from(1), // Fix this
            aggregated_range_proof: vec![], // Add this
        };

        // Transaction 2: Alice_change (29) -> Charlie (28) + fee (1)
        let tx2_charlie_blinding = Scalar::from(321u64);
        let tx2_kernel_blinding = tx1_change_blinding - tx2_charlie_blinding;
        
        let charlie_commitment = mimblewimble::commit(28_000_000, &tx2_charlie_blinding).unwrap();
        let (charlie_range_proof, _) = mimblewimble::create_range_proof(28_000_000, &tx2_charlie_blinding).unwrap();

        let tx2 = Transaction {
            inputs: vec![TransactionInput {
                commitment: alice_change_commitment.compress().to_bytes().to_vec(),
                merkle_proof: None,
                source_height: WasmU64::from(0),
            }],
            outputs: vec![
                TransactionOutput {
                    commitment: charlie_commitment.compress().to_bytes().to_vec(),

                    // Remove: range_proof: charlie_range_proof.to_bytes(),
                    ephemeral_key: None,
                    stealth_payload: None,
                    view_tag: None, // Add this
                },
            ],
            kernels: vec![TransactionKernel::new(tx2_kernel_blinding, 1_000_000, 1,2).unwrap()],
            timestamp: WasmU64::from(2), // Fix this
            aggregated_range_proof: vec![], // Add this
        };

        // Create coinbase transaction
        let coinbase_tx = Transaction::create_coinbase(vec![
            (alice.scan_pub.compress().to_bytes().to_vec(), 50_000_000)
        ]).unwrap();

        // Create a block with coinbase and the two transactions
        let mut block = Block::genesis();
        block.height = WasmU64::from(1);
        block.transactions = vec![coinbase_tx, tx1, tx2];
        
        // Store original kernel count
        let original_kernel_count = block.transactions.len();

        // Apply cut-through
        block.apply_cut_through().unwrap();
        
        // Verify results:
        // Should have 2 transactions (coinbase + aggregated regular txs)
        assert_eq!(block.transactions.len(), 2, 
            "Should have coinbase and one aggregated transaction");

        // First transaction should be coinbase
        assert_eq!(block.transactions[0].inputs.len(), 0, "First tx should be coinbase");

        // Second transaction should have the external input and unspent outputs
        let aggregated_tx = &block.transactions[1];
        assert_eq!(aggregated_tx.inputs.len(), 1, "Should have one external input");
        assert_eq!(aggregated_tx.inputs[0].commitment, alice_external_commitment, 
            "External input should be Alice's external UTXO");

        // Should have 2 outputs: Bob's + Charlie's (Alice's change was cut through)
        assert_eq!(aggregated_tx.outputs.len(), 2, "Should have two unspent outputs");

        // Verify the outputs contain Bob's and Charlie's
        let output_commitments: HashSet<Vec<u8>> = aggregated_tx.outputs.iter()
            .map(|o| o.commitment.clone())
            .collect();

        assert!(output_commitments.contains(&bob_commitment.compress().to_bytes().to_vec()),
            "Should contain Bob's output");
        assert!(output_commitments.contains(&charlie_commitment.compress().to_bytes().to_vec()),
            "Should contain Charlie's output");

        // Verify total fees are preserved (aggregated kernel)
        assert_eq!(aggregated_tx.total_fee(), 2_000_000, "Total fees should be preserved");
    }

    #[test]
    fn test_cut_through_with_no_internal_spends() {
        // Test that cut-through works correctly when there are no internal spends
        let alice = Wallet::new();
        let _bob = Wallet::new();
        
        let coinbase_tx = Transaction::create_coinbase(vec![
            (alice.scan_pub.compress().to_bytes().to_vec(), 50_000_000)
        ]).unwrap();

        // Create a transaction spending external UTXO (not from this block)
        let external_commitment = mimblewimble::commit(30_000_000, &Scalar::from(999u64))
            .unwrap().compress().to_bytes().to_vec();
        let bob_blinding = Scalar::from(111u64);
        let bob_commitment = mimblewimble::commit(29_000_000, &bob_blinding).unwrap();
        let (bob_range_proof, _) = mimblewimble::create_range_proof(29_000_000, &bob_blinding).unwrap();

        let tx = Transaction {
            inputs: vec![TransactionInput {
                commitment: external_commitment.clone(),
                merkle_proof: None,
                source_height: WasmU64::from(0),
            }],
            outputs: vec![
                TransactionOutput {
                    commitment: bob_commitment.compress().to_bytes().to_vec(),
                    // Remove: range_proof: bob_range_proof.to_bytes(),
                    ephemeral_key: None,
                    stealth_payload: None,
                    view_tag: None, // Add this
                },
            ],
            kernels: vec![TransactionKernel::new(Scalar::from(888u64), 1_000_000, 0, 1).unwrap()],
            timestamp: WasmU64::from(1), // Fix this
            aggregated_range_proof: vec![], // Add this
        };

        let mut block = Block::genesis();
        block.height = WasmU64::from(1);
        block.transactions = vec![coinbase_tx.clone(), tx.clone()];
        
        block.apply_cut_through().unwrap();

        // With no internal spends, transactions should remain separate
        assert_eq!(block.transactions.len(), 2, "Should keep 2 separate transactions");
        // First should still be coinbase
        assert_eq!(block.transactions[0].inputs.len(), 0, "First tx should be coinbase");
        // Second should be unchanged
        assert_eq!(block.transactions[1].inputs.len(), 1, "Second tx should have 1 input");
        assert_eq!(block.transactions[1].inputs[0].commitment, external_commitment, 
            "Input should be unchanged");
        assert_eq!(block.transactions[1].outputs.len(), 1, "Should have 1 output");
    }
}
