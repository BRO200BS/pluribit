// src/blockchain.rs
use crate::vdf::VDFProof;
use crate::block::Block;
use crate::transaction::TransactionKernel;
use crate::transaction::TransactionOutput;
use crate::transaction::Transaction;
use crate::error::{PluribitError, PluribitResult};
use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use crate::UTXOSnapshot;
use crate::constants;

pub fn get_current_base_reward(height: u64) -> u64 {
    // Use the modulo operator to find the height within the current 100-year cycle.
    let height_in_era = height % crate::constants::REWARD_RESET_INTERVAL;
    
    // Calculate halvings based on the height within the current era.
    let num_halvings = height_in_era / crate::constants::HALVING_INTERVAL;
        
    // Use a right bit-shift for efficient division by powers of 2.
    // We protect against shifting more than 63 bits, which would always result in 0 anyway.
    if num_halvings >= 64 {
        0
    } else {
        crate::constants::INITIAL_BASE_REWARD >> num_halvings
    }
}


lazy_static! {
    /// Global UTXO set: maps compressed commitment bytes to their TransactionOutput
    pub static ref UTXO_SET: Mutex<HashMap<Vec<u8>, TransactionOutput>> =
        Mutex::new(HashMap::new());
    /// Maps block height to UTXO merkle root at that height
    pub static ref UTXO_ROOTS: Mutex<HashMap<u64, [u8; 32]>> = 
        Mutex::new(HashMap::new());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blockchain {
    pub blocks: Vec<Block>,
    #[serde(skip)]
    pub block_by_hash: HashMap<String, Block>,
    pub current_height: u64,
    pub last_difficulty_adjustment: u64,
    pub current_difficulty: u8,
}

impl Blockchain {
    /// Create a new chain, insert genesis block, seed UTXO set
    pub fn new() -> Self {
        let genesis = Block::genesis();
        let genesis_hash = genesis.hash();
        let mut block_by_hash = HashMap::new();
        block_by_hash.insert(genesis_hash.clone(), genesis.clone());

        // Seed UTXO_SET with all outputs from genesis
        {
            let mut utxos = UTXO_SET.lock().unwrap();
            for tx in &genesis.transactions {
                for out in &tx.outputs {
                    utxos.insert(out.commitment.clone(), out.clone());
                }
            }
        }

        Blockchain {
            blocks: vec![genesis],
            block_by_hash,
            current_height: 0,
            last_difficulty_adjustment: 0,
            current_difficulty: 1, // start at difficulty=1
        }
    }
    /// Calculate the total work (sum of difficulties) for a chain
    pub fn get_chain_work(blocks: &Vec<Block>) -> u64 {
        blocks.iter().map(|block| block.difficulty as u64).sum()
    }
    
    /// Get chain work from genesis to current tip
    pub fn get_total_work(&self) -> u64 {
        Self::get_chain_work(&self.blocks)
    }
    /// Get the latest block
    pub fn get_latest_block(&self) -> &Block {
        self.blocks
            .last()
            .expect("blockchain always has at least the genesis block")
    }

    /// Retarget every 144 blocks toward 20m per block
    pub fn calculate_next_difficulty(&self) -> u8 {
         if self.current_height == 0
            || (self.current_height + 1) % constants::DIFFICULTY_ADJUSTMENT_INTERVAL != 0
        {
            return self.current_difficulty;
        }

        let start_height = self.current_height.saturating_sub(constants::DIFFICULTY_ADJUSTMENT_INTERVAL - 1);
        
        let start_block = &self.blocks[start_height as usize];
        let end_block = &self.blocks[self.current_height as usize];

        let actual_time = end_block.timestamp - start_block.timestamp;
        
        // Calculate the expected time using the constants, converting seconds to milliseconds
        let expected_time = constants::DIFFICULTY_ADJUSTMENT_INTERVAL * (constants::TARGET_BLOCK_TIME * 1000);


        let mut new_diff = self.current_difficulty;
        if actual_time < expected_time / 2 {
            new_diff = (self.current_difficulty + 1).min(8);
        } else if actual_time > expected_time * 2 {
            new_diff = self.current_difficulty.saturating_sub(1).max(1);
        }
        new_diff
    }

    /// Validate and append a block:
    /// 1) height & parent  
    /// 2) PoW  
    /// 3) VDF proof  
    /// 4) every tx via `Transaction::verify()`  
    /// 5) UTXO-set updates  
    /// 6) difficulty retarget  
    pub fn add_block(&mut self, block: Block) -> PluribitResult<()> {
        // 1. Height continuity
        if block.height != self.current_height + 1 {
            return Err(PluribitError::InvalidBlock(format!(
                "Expected height {}, got {}",
                self.current_height + 1,
                block.height
            )));
        }
        // 2. Parent hash
        if block.prev_hash != self.get_latest_block().hash() {
            return Err(PluribitError::InvalidBlock(
                "Parent hash mismatch".into(),
            ));
        }
        // 3. Proof-of‐Work
        if !block.is_valid_pow() {
            return Err(PluribitError::InvalidBlock("Invalid PoW".into()));
        }
        // 4. VDF proof
        if !block.has_valid_vdf_proof() {
            return Err(PluribitError::InvalidBlock(
                "Invalid or missing VDF proof".into(),
            ));
        }

        // 5. Verify all transactions with proper context
        let total_fees = block.transactions.iter()
            .filter(|tx| !tx.inputs.is_empty()) // Fees from non-coinbase txs
            .map(|tx| tx.kernel.fee)
            .sum();
        
        let expected_reward = self.calculate_block_reward(block.height, block.difficulty, total_fees);

        for tx in &block.transactions {
            if tx.inputs.is_empty() {
                // It's a coinbase, pass the expected reward for the special check.
                tx.verify(Some(expected_reward))?;
            } else {
                // It's a regular transaction, no reward context needed.
                tx.verify(None)?;
            }
        }

        // 6. Update UTXO set: spend inputs, add outputs
        {
            let mut utxos = UTXO_SET.lock().unwrap();
            for tx in &block.transactions {
                // spend
                for inp in &tx.inputs {
                    if utxos.remove(&inp.commitment).is_none() {
                        return Err(PluribitError::UnknownInput);
                    }
                }
                // add new outputs
                for out in &tx.outputs {
                    utxos.insert(out.commitment.clone(), out.clone());
                }
            }
            
            // Calculate and store UTXO merkle root after this block
            let utxo_vec: Vec<(Vec<u8>, TransactionOutput)> = utxos.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let merkle_root = Block::calculate_utxo_merkle_root(&utxo_vec);
            
            let mut roots = UTXO_ROOTS.lock().unwrap();
            roots.insert(self.current_height + 1, merkle_root);
        }

        // 7. Append block & update maps/height
        let h = block.hash();
        // We need to keep a reference to the block before it's moved into the map
        //let new_block_ref = block.clone(); 
        self.blocks.push(block.clone());
        self.block_by_hash.insert(h, block);
        self.current_height += 1;

        // 8. Retarget difficulty if needed
        self.current_difficulty = self.calculate_next_difficulty();


        Ok(())
    }
    
    /// Create a UTXO snapshot at current height
    pub fn create_utxo_snapshot(&self) -> PluribitResult<UTXOSnapshot> {
        let mut current_utxos: HashMap<Vec<u8>, TransactionOutput> = HashMap::new();
        let mut total_kernels = 0u64;
        
        // Process all blocks to build UTXO set
        for block in &self.blocks {
            for tx in &block.transactions {
                // Remove spent outputs
                for input in &tx.inputs {
                    current_utxos.remove(&input.commitment);
                }
                // Add new outputs
                for output in &tx.outputs {
                    current_utxos.insert(output.commitment.clone(), output.clone());
                }
                // Count kernels
                total_kernels += 1;
            }
        }
        
        // Convert to sorted vec for deterministic ordering
        let mut utxo_vec: Vec<(Vec<u8>, TransactionOutput)> = current_utxos.into_iter().collect();
        utxo_vec.sort_by(|a, b| a.0.cmp(&b.0));
        
        // Calculate merkle root
        let merkle_root = Block::calculate_utxo_merkle_root(&utxo_vec);
        
        Ok(UTXOSnapshot {
            height: self.current_height,
            prev_block_hash: self.get_latest_block().hash(),
            utxos: utxo_vec,
            timestamp: js_sys::Date::now() as u64,
            merkle_root,
            total_kernels,
        })
    }
    
    /// Restore chain state from UTXO snapshot
    pub fn restore_from_snapshot(&mut self, snapshot: UTXOSnapshot) -> PluribitResult<()> {
        // Verify merkle root
        let calculated_root = Block::calculate_utxo_merkle_root(&snapshot.utxos);
        if calculated_root != snapshot.merkle_root {
            return Err(PluribitError::InvalidBlock("UTXO snapshot merkle root mismatch".to_string()));
        }
        
        // Clear current UTXO set
        let mut utxo_set = UTXO_SET.lock().unwrap();
        utxo_set.clear();
        
        // Restore UTXOs
        for (commitment, output) in &snapshot.utxos {
            utxo_set.insert(commitment.clone(), output.clone());
        }
        
        // Create synthetic block representing the snapshot
        let snapshot_block = Block {
            height: snapshot.height,
            prev_hash: snapshot.prev_block_hash.clone(),
            transactions: vec![Transaction {
                inputs: vec![],
                outputs: snapshot.utxos.iter().map(|(_, o)| o.clone()).collect(),
                kernel: TransactionKernel {
                    excess: vec![0u8; 32],
                    signature: vec![0u8; 64],
                    fee: 0,
                },
            }],
            vdf_proof: VDFProof { y: vec![], pi: vec![], l: vec![], r: vec![] },
            timestamp: snapshot.timestamp,
            nonce: 0,
            miner_id: "snapshot".to_string(),
            difficulty: 1,
            finalization_data: None,
        };
        
        // Reset chain to snapshot
        self.blocks = vec![self.blocks[0].clone(), snapshot_block]; // Keep genesis
        self.current_height = snapshot.height;
        
        Ok(())
    }
    
    /// Apply aggressive pruning for browser storage
    pub fn prune_to_horizon(&mut self, keep_recent: u64) -> PluribitResult<()> {
        if self.current_height <= keep_recent {
            return Ok(());
        }
        
        let horizon_height = self.current_height - keep_recent;
        
        // Create UTXO snapshot at horizon
        let mut horizon_utxos: HashMap<Vec<u8>, TransactionOutput> = HashMap::new();
        
        // Process blocks up to horizon
        for i in 0..=horizon_height as usize {
            if i >= self.blocks.len() {
                break;
            }
            
            let block = &self.blocks[i];
            for tx in &block.transactions {
                for input in &tx.inputs {
                    horizon_utxos.remove(&input.commitment);
                }
                for output in &tx.outputs {
                    horizon_utxos.insert(output.commitment.clone(), output.clone());
                }
            }
        }
        
        // Create horizon block
        let horizon_block = Block {
            height: horizon_height,
            prev_hash: self.blocks[horizon_height as usize].hash(),
            transactions: vec![Transaction {
                inputs: vec![],
                outputs: horizon_utxos.into_values().collect(),
                kernel: TransactionKernel {
                    excess: vec![0u8; 32],
                    signature: vec![0u8; 64],
                    fee: 0,
                },
            }],
            vdf_proof: VDFProof { y: vec![], pi: vec![], l: vec![], r: vec![] },
            timestamp: self.blocks[horizon_height as usize].timestamp,
            nonce: 0,
            miner_id: "horizon".to_string(),
            difficulty: 1,
            finalization_data: None,
        };
        
        // Keep genesis, horizon, and recent blocks
        let mut pruned_chain = vec![self.blocks[0].clone(), horizon_block];
        pruned_chain.extend_from_slice(&self.blocks[(horizon_height as usize + 1)..]);
        
        self.blocks = pruned_chain;
        
        // Update block_by_hash
        self.block_by_hash.clear();
        for block in &self.blocks {
            self.block_by_hash.insert(block.hash(), block.clone());
        }
        
        Ok(())
    }

    /// Calculate the total block reward based on consensus rules.
    fn calculate_block_reward(&self, height: u64, difficulty: u8, total_fees: u64) -> u64 {
        let base_reward = get_current_base_reward(height);

        if height <= crate::constants::BOOTSTRAP_BLOCKS {
            // During bootstrap, miner gets full base reward + fees, with no difficulty bonus.
            base_reward + total_fees
        } else {
            // After bootstrap, the miner reward includes a bonus and is split.
            // The validator reward pool is handled separately by the consensus manager.
            let difficulty_bonus = if difficulty > 1 {
                let factor = crate::constants::DIFFICULTY_BONUS_FACTOR;
                (difficulty as f64).log2().round() as u64 * factor
            } else {
                0
            };
            // The coinbase transaction only contains the miner's half of the base reward.
            (base_reward / 2) + difficulty_bonus + total_fees
        }
    }

    /// Verify a block can be added at the current state
    pub fn can_accept_block(&self, block: &Block) -> Result<(), PluribitError> {
        // Height check
        if block.height != self.current_height + 1 {
            return Err(PluribitError::InvalidBlock(format!(
                "Expected height {}, got {}",
                self.current_height + 1,
                block.height
            )));
        }
        
        // Parent check
        if block.prev_hash != self.get_latest_block().hash() {
            return Err(PluribitError::InvalidBlock(
                "Block does not extend current chain tip".to_string()
            ));
        }
        
        // PoW check
        if !block.is_valid_pow() {
            return Err(PluribitError::InvalidBlock(
                "Invalid proof of work".to_string()
            ));
        }
        
        // VDF check
        if !block.has_valid_vdf_proof() {
            return Err(PluribitError::InvalidBlock(
                "Invalid VDF proof".to_string()
            ));
        }
        
        Ok(())
    }
    
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{HALVING_INTERVAL, INITIAL_BASE_REWARD, DIFFICULTY_ADJUSTMENT_INTERVAL, GENESIS_TIMESTAMP_MS};


    


    //  Test for Genesis Block
    #[test]
    fn test_new_blockchain_has_genesis() {
        // Clear UTXO set before test
        {
            UTXO_SET.lock().unwrap().clear();
        }
        
        let chain = Blockchain::new();
        assert_eq!(chain.current_height, 0);
        assert_eq!(chain.blocks.len(), 1);
        assert_eq!(chain.blocks[0].height, 0);
        
        // Genesis block has no transactions, so UTXO set should be empty
        assert!(UTXO_SET.lock().unwrap().is_empty(), "Genesis block should not seed the UTXO set");
    }

    //  Test for Reward Halving
    #[test]
    fn test_get_current_base_reward_halving() {
        // First block has full reward
        assert_eq!(get_current_base_reward(0), INITIAL_BASE_REWARD);
        
        // Block before first halving
        assert_eq!(get_current_base_reward(HALVING_INTERVAL - 1), INITIAL_BASE_REWARD);
        
        // Block at first halving (reward is halved)
        assert_eq!(get_current_base_reward(HALVING_INTERVAL), INITIAL_BASE_REWARD / 2); 
        
        // Block after first halving
        assert_eq!(get_current_base_reward(HALVING_INTERVAL), INITIAL_BASE_REWARD >> 1);
        
        // Block at second halving
        assert_eq!(get_current_base_reward(HALVING_INTERVAL * 2), INITIAL_BASE_REWARD / 4);
    }
    
    #[test]
    fn test_difficulty_adjustment() {
        let mut chain = Blockchain::new();
        
        // Add enough blocks to reach the adjustment interval
        for i in 1..DIFFICULTY_ADJUSTMENT_INTERVAL {
            let mut block = Block::genesis();
            block.height = i;
            block.prev_hash = chain.get_latest_block().hash();
            block.timestamp = GENESIS_TIMESTAMP_MS + (i * constants::TARGET_BLOCK_TIME * 1000);
            // Don't add to chain.blocks, just update height
            if i == DIFFICULTY_ADJUSTMENT_INTERVAL - 1 {
                chain.blocks.push(block);
            }
        }
        chain.current_height = DIFFICULTY_ADJUSTMENT_INTERVAL - 1;
        
        // Add start block at index 0 (already there from genesis)
        // Ensure we have enough blocks
        while chain.blocks.len() <= (DIFFICULTY_ADJUSTMENT_INTERVAL - 1) as usize {
            let mut block = Block::genesis();
            block.height = chain.blocks.len() as u64;
            block.timestamp = GENESIS_TIMESTAMP_MS + (block.height * constants::TARGET_BLOCK_TIME * 1000);
            chain.blocks.push(block);
        }
        
        chain.current_difficulty = 4;
        
        let expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL * (constants::TARGET_BLOCK_TIME * 1000);
        
        // Test slow blocks (3x expected time)
        let start_idx = chain.current_height.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL - 1) as usize;
        chain.blocks[start_idx].timestamp = GENESIS_TIMESTAMP_MS;
        chain.blocks[chain.current_height as usize].timestamp = GENESIS_TIMESTAMP_MS + (expected_time * 3);
        assert_eq!(chain.calculate_next_difficulty(), 3, "Difficulty should decrease when time is > 2x expected");
        
        // Test fast blocks (1/3 expected time)
        chain.blocks[chain.current_height as usize].timestamp = GENESIS_TIMESTAMP_MS + (expected_time / 3);
        assert_eq!(chain.calculate_next_difficulty(), 5, "Difficulty should increase when time is < 0.5x expected");
    }
    #[test]
    fn test_add_block_validation() {
        let mut chain = Blockchain::new();
        
        // Create invalid block (wrong height)
        let mut block = Block::genesis();
        block.height = 2; // Should be 1
        
        let result = chain.add_block(block);
        assert!(result.is_err());
        
        // Create invalid block (wrong parent)
        let mut block = Block::genesis();
        block.height = 1;
        block.prev_hash = "wrong_hash".to_string();
        
        let result = chain.add_block(block);
        assert!(result.is_err());
    }


}
