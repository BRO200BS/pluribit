// src/block.rs
use std::collections::HashSet;
use crate::transaction::Transaction;
use crate::vdf::{VDFProof, VDF};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use num_bigint::BigUint;
use num_traits::One;
use hex;
use bincode;
use crate::error::PluribitResult;
use crate::transaction::TransactionInput;
use crate::transaction::TransactionOutput;
use crate::transaction::TransactionKernel;
use crate::constants::{GENESIS_TIMESTAMP_MS, GENESIS_BITCOIN_HASH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockFinalization {
    pub votes: Vec<ValidatorVote>,
    pub total_stake_voted: u64,
    pub total_stake_active: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVote {
    pub validator_id: String,
    pub block_hash: String,
    pub stake_amount: u64,
    #[serde(default)]
    pub vdf_proof: VDFProof,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub height: u64,
    pub prev_hash: String,
    //#[serde(default)]
    pub transactions: Vec<Transaction>,
    //#[serde(default)] 
    pub vdf_proof: VDFProof,
    pub timestamp: u64,
    pub nonce: u64,
    pub miner_id: String,
    pub difficulty: u8,
    pub finalization_data: Option<BlockFinalization>,
}

impl Block {
    /// Genesis block: height 0, empty txs, zero timestamp, difficulty = 1.
    pub fn genesis() -> Self {
        Block {
            height: 0,
            prev_hash: "0".repeat(64),
            transactions: vec![],
            vdf_proof: VDFProof::default(), // Use default for cleanliness
            timestamp: GENESIS_TIMESTAMP_MS, // Use the new constant
            nonce: 0,
            miner_id: format!("genesis_anchor_{}", GENESIS_BITCOIN_HASH), 
            difficulty: 1,
            finalization_data: None,
        }
    }

    /// Compute the Merkle root of `transactions`:
    /// - Hash each tx via SHA256(bincode::serialize(tx))
    /// - Pairwise-hash up, duplicating the last if odd.
    pub fn tx_root(&self) -> [u8; 32] {
        fn hash_pair(a: &[u8], b: &[u8]) -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(a);
            h.update(b);
            h.finalize().into()
        }

        let mut leaves: Vec<[u8; 32]> = self.transactions.iter()
            .map(|tx| {
                let data = bincode::serialize(tx).expect("tx serialization failed");
                Sha256::digest(&data).into()
            })
            .collect();

        if leaves.is_empty() {
            return Sha256::digest(&[]).into();
        }

        while leaves.len() > 1 {
            if leaves.len() % 2 == 1 {
                leaves.push(*leaves.last().unwrap());
            }
            leaves = leaves.chunks(2)
                .map(|pair| hash_pair(&pair[0], &pair[1]))
                .collect();
        }

        leaves[0]
    }

    /// Header hash covers:
    /// height ∥ prev_hash ∥ tx_root ∥ miner_id ∥ nonce ∥ timestamp ∥ difficulty
    /// ∥ VDF proof bytes ∥ finalization_data hash
    pub fn hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(&self.height.to_le_bytes());
        h.update(self.prev_hash.as_bytes());
        h.update(&self.tx_root());
        h.update(self.miner_id.as_bytes());
        h.update(&self.nonce.to_le_bytes());
        h.update(&self.timestamp.to_le_bytes());
        h.update(&[self.difficulty]);
        h.update(&self.vdf_proof.y);
        h.update(&self.vdf_proof.pi);
        h.update(&self.vdf_proof.l);
        h.update(&self.vdf_proof.r);

        hex::encode(h.finalize())
    }

    /// Bit-level PoW: parse hash as BigUint and require < 2^(256 - difficulty)
    pub fn is_valid_pow(&self) -> bool {
        let hash_bytes = match hex::decode(self.hash()) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let value = BigUint::from_bytes_be(&hash_bytes);
        let target = BigUint::one() << (256 - self.difficulty as usize);
        value < target
    }

    /// Verify the VDF proof against `prev_hash` as the challenge.
    pub fn has_valid_vdf_proof(&self) -> bool {
        if self.height == 0 {
            return true;
        }
        let vdf = match VDF::new(2048) { // Add the parameter
            Ok(v) => v,
            Err(_) => return false,
        };
        match vdf.verify(self.prev_hash.as_bytes(), &self.vdf_proof) {
            Ok(valid) => valid,
            Err(_) => false,
        }
    }

    /// Prevent timewarp: must be > parent_ts and ≤ parent_ts + 2h.
    pub fn has_valid_timestamp(&self, parent_ts: u64) -> bool {
        let max_future = parent_ts + 2 * 60 * 60 * 1000;
        (self.timestamp > parent_ts) && (self.timestamp <= max_future)
    }
    
        /// Apply cut-through to remove intermediate transactions
    pub fn apply_cut_through(&mut self) -> PluribitResult<()> {
        if self.transactions.is_empty() {
            return Ok(());
        }
        
        // Collect all inputs and outputs
        let mut all_inputs: Vec<TransactionInput> = Vec::new();
        let mut all_outputs: Vec<TransactionOutput> = Vec::new();
        let mut all_kernels: Vec<TransactionKernel> = Vec::new();
        
        for tx in &self.transactions {
            all_inputs.extend(tx.inputs.clone());
            all_outputs.extend(tx.outputs.clone());
            all_kernels.push(tx.kernel.clone());
        }
        
        // Create output lookup map
        let output_set: HashSet<Vec<u8>> = all_outputs.iter()
            .map(|o| o.commitment.clone())
            .collect();
        
        // Filter inputs - only keep those that reference outputs from previous blocks
        let external_inputs: Vec<TransactionInput> = all_inputs.into_iter()
            .filter(|input| !output_set.contains(&input.commitment))
            .collect();
        
        // Filter outputs - only keep those not spent in this block
        let spent_set: HashSet<Vec<u8>> = external_inputs.iter()
            .map(|i| i.commitment.clone())
            .collect();
        
        // Also need to check internal spends
        let internal_spent: HashSet<Vec<u8>> = self.transactions.iter()
            .flat_map(|tx| tx.inputs.iter())
            .filter(|input| output_set.contains(&input.commitment))
            .map(|input| input.commitment.clone())
            .collect();
        
        let unspent_outputs: Vec<TransactionOutput> = all_outputs.into_iter()
            .filter(|output| !spent_set.contains(&output.commitment) && 
                           !internal_spent.contains(&output.commitment))
            .collect();
        
        // Aggregate all kernels
        let aggregated_kernel = TransactionKernel::aggregate(&all_kernels)?;
        
        // Replace all transactions with single aggregated transaction
        self.transactions = vec![Transaction {
            inputs: external_inputs,
            outputs: unspent_outputs,
            kernel: aggregated_kernel,
        }];
        
        Ok(())
    }
    
    /// Get the net UTXO changes from this block
    pub fn get_utxo_changes(&self) -> (Vec<Vec<u8>>, Vec<TransactionOutput>) {
        let mut spent_commitments = Vec::new();
        let mut new_outputs = Vec::new();
        
        for tx in &self.transactions {
            for input in &tx.inputs {
                spent_commitments.push(input.commitment.clone());
            }
            for output in &tx.outputs {
                new_outputs.push(output.clone());
            }
        }
        
        (spent_commitments, new_outputs)
    }
    
    /// Calculate merkle root of current UTXO set (for snapshots)
    pub fn calculate_utxo_merkle_root(utxos: &[(Vec<u8>, TransactionOutput)]) -> [u8; 32] {
        if utxos.is_empty() {
            return [0u8; 32];
        }
        
        // Sort UTXOs by commitment for deterministic ordering
        let mut sorted_utxos = utxos.to_vec();
        sorted_utxos.sort_by(|a, b| a.0.cmp(&b.0));
        
        // Calculate leaf hashes
        let mut hashes: Vec<[u8; 32]> = sorted_utxos.iter()
            .map(|(commitment, output)| {
                let mut hasher = Sha256::new();
                hasher.update(commitment);
                hasher.update(&output.range_proof);
                hasher.finalize().into()
            })
            .collect();
        
        // Build merkle tree
        while hashes.len() > 1 {
            if hashes.len() % 2 == 1 {
                hashes.push(*hashes.last().unwrap());
            }
            
            hashes = hashes.chunks(2)
                .map(|pair| {
                    let mut hasher = Sha256::new();
                    hasher.update(&pair[0]);
                    hasher.update(&pair[1]);
                    hasher.finalize().into()
                })
                .collect();
        }
        
        hashes[0]
    }
    
    
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Transaction, TransactionInput, TransactionOutput, TransactionKernel};
    use sha2::{Digest, Sha256};
    use crate::mimblewimble;

    #[test]
    fn merkle_root_empty() {
        let b = Block::genesis();
        let expected_hash: [u8; 32] = Sha256::digest(&[]).into();
        assert_eq!(b.tx_root(), expected_hash);
    }

    #[test]
    fn different_tx_order_changes_root() {
        let mut a = Block::genesis();
        let mut b = Block::genesis();
        
        let tx1 = Transaction {
            inputs: vec![],
            outputs: vec![],
            kernel: TransactionKernel { excess: vec![1], signature: vec![], fee: 10 },
        };
        let tx2 = Transaction {
            inputs: vec![],
            outputs: vec![],
            kernel: TransactionKernel { excess: vec![2], signature: vec![], fee: 20 },
        };

        a.transactions = vec![tx1.clone(), tx2.clone()];
        b.transactions = vec![tx2, tx1];
        
        assert_ne!(a.tx_root(), b.tx_root());
    }

    #[test]
    fn test_apply_cut_through_aggregates_correctly() {
        use curve25519_dalek::scalar::Scalar;
        use rand::thread_rng;
        
        // Create proper test data
        let mut rng = thread_rng();
        
        // Create an output C1 (from a previous block)
        let blinding1 = Scalar::random(&mut rng);
        let c1_point = mimblewimble::commit(100, &blinding1).unwrap();
        let c1_commitment_bytes = c1_point.compress().to_bytes().to_vec();

        // Tx1: Spends C1 (100) and creates C2 (70), fee = 30
        let blinding2 = Scalar::random(&mut rng);
        let c2_point = mimblewimble::commit(70, &blinding2).unwrap();
        let kernel_blinding1 = blinding2 - blinding1; // Output blinding - input blinding
        
        // Create valid kernel with proper excess point
        let excess1 = mimblewimble::commit(30, &kernel_blinding1).unwrap(); // fee*H + kernel_blinding*G
        
        let tx1 = Transaction {
            inputs: vec![TransactionInput { commitment: c1_commitment_bytes.clone(), merkle_proof: None, source_height: 0 }],
            outputs: vec![TransactionOutput { 
                commitment: c2_point.compress().to_bytes().to_vec(), 
                range_proof: vec![1; 100], // Dummy proof
                ephemeral_key: None, 
                stealth_payload: None 
            }],
            kernel: TransactionKernel { 
                excess: excess1.compress().to_bytes().to_vec(), 
                signature: vec![0; 64], // Dummy but correct size
                fee: 30 
            }
        };

        // Tx2: Spends C2 (70) and creates C3 (60), fee = 10
        let blinding3 = Scalar::random(&mut rng);
        let c3_point = mimblewimble::commit(60, &blinding3).unwrap();
        let kernel_blinding2 = blinding3 - blinding2;
        
        let excess2 = mimblewimble::commit(10, &kernel_blinding2).unwrap();
        
        let tx2 = Transaction {
            inputs: vec![TransactionInput { commitment: c2_point.compress().to_bytes().to_vec(), merkle_proof: None, source_height: 0 }],
            outputs: vec![TransactionOutput { 
                commitment: c3_point.compress().to_bytes().to_vec(), 
                range_proof: vec![2; 100], // Dummy proof
                ephemeral_key: None,
                stealth_payload: None
            }],
            kernel: TransactionKernel { 
                excess: excess2.compress().to_bytes().to_vec(), 
                signature: vec![0; 64], 
                fee: 10 
            }
        };

        let mut block = Block::genesis();
        block.transactions = vec![tx1, tx2];

        block.apply_cut_through().unwrap();

        assert_eq!(block.transactions.len(), 1, "Block should have only one aggregated transaction after cut-through");
        
        let final_tx = &block.transactions[0];
        assert_eq!(final_tx.inputs.len(), 1, "Aggregated tx should have one input");
        assert_eq!(final_tx.inputs[0].commitment, c1_commitment_bytes, "The input should be the external input C1");
        
        assert_eq!(final_tx.outputs.len(), 1, "Aggregated tx should have one output");
        assert_eq!(final_tx.outputs[0].commitment, c3_point.compress().to_bytes().to_vec(), "The output should be the unspent output C3");
        
        assert_eq!(final_tx.kernel.fee, 40, "Kernel fees should be aggregated (30 + 10)");
    }

    #[test]
    fn pow_checks_target() {
        let mut b = Block::genesis();
        b.nonce = 0;
        b.difficulty = 10;
        assert!(!b.is_valid_pow());
    }

    #[test]
    fn timestamp_bounds() {
        let mut b = Block::genesis();
        b.timestamp = 1_000;
        assert!(b.has_valid_timestamp(0));
        
        b.timestamp = 0 + 2 * 60 * 60 * 1000 + 1;
        assert!(!b.has_valid_timestamp(0));
    }
}
