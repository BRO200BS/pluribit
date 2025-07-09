// src/staking.rs

use crate::{VDFLockedStake, Validator};
use crate::{PENDING_STAKES, VALIDATORS, log};
use crate::vdf::{VDF, VDFProof};
use js_sys::Date;
use std::collections::HashMap;
use sha2::Digest; // Only Digest is needed now


/// Returns a **cloned** map of all active validators (ID → Validator).
pub fn current_validators() -> HashMap<String, Validator> {
    VALIDATORS
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, v)| v.active)
        .map(|(id, v)| (id.clone(), v.clone()))
        .collect()
}

/// Compute 2/3 +1 quorum threshold of total *active* stake.
pub fn quorum_threshold() -> u64 {
    let total_active: u64 = current_validators()
        .values()
        .map(|v| v.total_locked)
        .sum();
    // ⅔ of total, plus one:
    (total_active * 2) / 3 + 1
}

/// Lock new stake: moves a pending `StakeLockTransaction` through VDF into an active `Validator`.
pub fn activate_stake(validator_id: &str, iterations: u64) -> Result<(), String> {
    // 1) Pull pending stake
    let stake_tx = {
        let mut pending = PENDING_STAKES.lock().unwrap();
        pending
            .remove(validator_id)
            .ok_or_else(|| "No pending stake for this validator".to_string())?
    };
    // 2) Build VDF input
    let input = format!(
        "{}:{}:{}:{}",
        stake_tx.validator_id,
        stake_tx.stake_amount,
        stake_tx.lock_duration,
        stake_tx.block_hash
    );
    // 3) Run VDF
    let vdf = VDF::new(2048).map_err(|e| format!("VDF init error: {:?}", e))?;
    let proof: VDFProof = vdf
        .compute_with_proof(input.as_bytes(), iterations)
        .map_err(|e| format!("VDF compute error: {:?}", e))?;
    // 4) Create locked stake record
    let now = Date::now() as u64;
    let locked = VDFLockedStake {
        stake_tx: stake_tx.clone(),
        vdf_proof: proof.clone(),
        unlock_height: stake_tx.lock_height + stake_tx.lock_duration,
        activation_time: now,
    };
    // 5) Insert into validators (or new)
    let mut vals = VALIDATORS.lock().unwrap();
    let entry = vals.entry(validator_id.to_string()).or_insert_with(|| Validator {
        id: validator_id.to_string(),
        public_key: vec![], 
        private_key: vec![], 
        locked_stakes: vec![],
        total_locked: 0,
        active: true,
    });
    entry.locked_stakes.push(locked);
    entry.total_locked += stake_tx.stake_amount;
    Ok(())
}

/// Prune expired stakes at the current block height.
pub fn prune_expired_stakes(current_height: u64) {
    let mut vals = VALIDATORS.lock().unwrap();
    for (_id, v) in vals.iter_mut() {
        v.locked_stakes
            .retain(|s| s.unlock_height > current_height);
        v.total_locked = v.locked_stakes.iter().map(|s| s.stake_tx.stake_amount).sum();
        if v.total_locked == 0 {
            v.active = false;
        }
    }
}

pub fn calculate_time_weighted_stake(stake: &VDFLockedStake) -> u64 {
    let weight_factor = 1.0 + (stake.stake_tx.lock_duration as f64 / 365.0);
    (stake.stake_tx.stake_amount as f64 * weight_factor) as u64
}


/// Allows a validator to unstake early, burning a portion of their stake.
/// Returns the amount of stake that was burned.
pub fn unstake_early(validator_id: &str, stake_commitment_hash: &str, current_height: u64) -> Result<u64, String> {
    let mut vals = VALIDATORS.lock().unwrap();
    let validator = vals.get_mut(validator_id)
        .ok_or_else(|| "Validator not found".to_string())?;

    // Find the specific stake to remove
    let stake_index = validator.locked_stakes.iter().position(|s| {
        // A unique identifier for a stake would be ideal, here we use a hash of its data
        let mut hasher = sha2::Sha256::new();
        hasher.update(s.stake_tx.block_hash.as_bytes());
        hasher.update(&s.stake_tx.stake_amount.to_le_bytes());
        hex::encode(hasher.finalize()) == stake_commitment_hash
    }).ok_or_else(|| "Specific stake lock not found for this validator".to_string())?;

    let stake = &validator.locked_stakes[stake_index];

    // Ensure it's not already expired
    if current_height >= stake.unlock_height {
        return Err("Cannot early-unstake an expired lock. It should be pruned automatically.".to_string());
    }

    // Calculate penalty based on whitepaper formula (Definition 10)
    let total_duration = stake.stake_tx.lock_duration;
    let served_duration = current_height.saturating_sub(stake.stake_tx.lock_height);
    let max_penalty_rate = 0.50; // 50% max penalty rate from paper

    let time_remaining_ratio = 1.0 - (served_duration as f64 / total_duration as f64);
    let penalty_rate = time_remaining_ratio * max_penalty_rate;

    let staked_amount = stake.stake_tx.stake_amount;
    let burn_penalty = (staked_amount as f64 * penalty_rate) as u64;

    // The amount to be returned to the user (this would require a transaction)
    let return_amount = staked_amount - burn_penalty;

    // Remove the stake and update validator's total
    validator.locked_stakes.remove(stake_index);
    validator.total_locked = validator.total_locked.saturating_sub(staked_amount);

    log(&format!(
        "[STAKING] Early unstake for {}. Original: {}, Returned: {}, Burned: {}",
        validator_id, staked_amount, return_amount, burn_penalty
    ));

    // For now, we just burn the funds. Returning them would require a new transaction type.
    // The burned amount is effectively removed from the total supply.
    Ok(burn_penalty)
}
#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;
    use super::*;
    use crate::StakeLockTransaction;

    use lazy_static::lazy_static;
    use std::sync::Mutex;

        lazy_static! {
            static ref TEST_MUTEX: Mutex<()> = Mutex::new(());
        }

    #[test]
    fn test_calculate_time_weighted_stake() {
        let stake = VDFLockedStake {
            stake_tx: StakeLockTransaction {
                validator_id: "test".to_string(),
                stake_amount: 1000,
                lock_duration: 365, // 1 year
                lock_height: 0,
                block_hash: "hash".to_string(),
            },
            vdf_proof: VDFProof::default(),
            unlock_height: 365,
            activation_time: 0,
        };
        
        // 1 year lock = 2.0x weight factor
        let weighted = calculate_time_weighted_stake(&stake);
        assert_eq!(weighted, 2000);
        
        // Test with 6 month lock
        let mut stake_6m = stake.clone();
        stake_6m.stake_tx.lock_duration = 182;
        let weighted_6m = calculate_time_weighted_stake(&stake_6m);
        assert_eq!(weighted_6m, 1498); // ~1.5x weight
    }
    
    #[wasm_bindgen_test]
    fn test_activate_stake() {
        // Add pending stake
        let stake_tx = StakeLockTransaction {
            validator_id: "validator1".to_string(),
            stake_amount: 5000,
            lock_duration: 100,
            lock_height: 10,
            block_hash: "block123".to_string(),
        };
        
        PENDING_STAKES.lock().unwrap().insert("validator1".to_string(), stake_tx);
        
        // Activate with small iterations for testing
        let result = activate_stake("validator1", 100);
        assert!(result.is_ok());
        
        // Check validator was created
        let validators = VALIDATORS.lock().unwrap();
        let validator = validators.get("validator1").unwrap();
        assert_eq!(validator.total_locked, 5000);
        assert_eq!(validator.locked_stakes.len(), 1);
        assert!(validator.active);
        
        // Pending stake should be removed
        drop(validators);
        assert!(PENDING_STAKES.lock().unwrap().get("validator1").is_none());
    }
    
    #[test]
    fn test_prune_expired_stakes() {
        // Clear validators to ensure a clean state for this test
        VALIDATORS.lock().unwrap().clear();

        // Create validator with mixed stakes
        let mut validators = VALIDATORS.lock().unwrap();
        validators.insert("validator1".to_string(), Validator {
            id: "validator1".to_string(),
            public_key: vec![1, 2, 3],
            private_key: vec![4, 5, 6],
            locked_stakes: vec![
                VDFLockedStake {
                    stake_tx: StakeLockTransaction {
                        validator_id: "validator1".to_string(),
                        stake_amount: 1000,
                        lock_duration: 50,
                        lock_height: 0,
                        block_hash: "hash1".to_string(),
                    },
                    vdf_proof: VDFProof::default(),
                    unlock_height: 50,
                    activation_time: 0,
                },
                VDFLockedStake {
                    stake_tx: StakeLockTransaction {
                        validator_id: "validator1".to_string(),
                        stake_amount: 2000,
                        lock_duration: 200,
                        lock_height: 0,
                        block_hash: "hash2".to_string(),
                    },
                    vdf_proof: VDFProof::default(),
                    unlock_height: 200,
                    activation_time: 0,
                },
            ],
            total_locked: 3000,
            active: true,
        });
        drop(validators);
        
        // Prune at height 100
        prune_expired_stakes(100);
        
        let validators = VALIDATORS.lock().unwrap();
        let validator = validators.get("validator1").unwrap();
        assert_eq!(validator.locked_stakes.len(), 1); // Only one stake remains
        assert_eq!(validator.total_locked, 2000); // Only the 2000 stake
        assert!(validator.active); // Still active
    }
    
    #[test]
    fn test_early_unstake() {
        let _guard = TEST_MUTEX.lock().unwrap();
        // Clear validators to ensure a clean state for this test
        VALIDATORS.lock().unwrap().clear();

        // Setup validator with stake
        let stake_tx = StakeLockTransaction {
            validator_id: "validator1".to_string(),
            stake_amount: 10000,
            lock_duration: 100,
            lock_height: 0,
            block_hash: "blockabc".to_string(),
        };
        
        let mut validators = VALIDATORS.lock().unwrap();
        validators.insert("validator1".to_string(), Validator {
            id: "validator1".to_string(),
            public_key: vec![],
            private_key: vec![],
            locked_stakes: vec![VDFLockedStake {
                stake_tx: stake_tx.clone(),
                vdf_proof: VDFProof::default(),
                unlock_height: 100,
                activation_time: 0,
            }],
            total_locked: 10000,
            active: true,
        });
        drop(validators);
        
        // Calculate commitment hash
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"blockabc");
        hasher.update(&10000u64.to_le_bytes());
        let commitment_hash = hex::encode(hasher.finalize());
        
        // Unstake at height 25 (25% through lock period)
        let burn_amount = unstake_early("validator1", &commitment_hash, 25).unwrap();
        
        // Should burn 37.5% (75% remaining * 50% max penalty)
        assert_eq!(burn_amount, 3750);
        
        // Check validator state
        let validators = VALIDATORS.lock().unwrap();
        let validator = validators.get("validator1").unwrap();
        assert_eq!(validator.total_locked, 0);
        assert_eq!(validator.locked_stakes.len(), 0);
    }
    
    #[test]
    fn test_quorum_threshold() {
        // Clear validators before running the test to ensure isolation
        VALIDATORS.lock().unwrap().clear();
        
        // Setup validators
        let mut validators = VALIDATORS.lock().unwrap();
        validators.insert("v1".to_string(), Validator {
            id: "v1".to_string(),
            public_key: vec![],
            private_key: vec![],
            locked_stakes: vec![],
            total_locked: 100,
            active: true,
        });
        validators.insert("v2".to_string(), Validator {
            id: "v2".to_string(),
            public_key: vec![],
            private_key: vec![],
            locked_stakes: vec![],
            total_locked: 200,
            active: true,
        });
        validators.insert("v3".to_string(), Validator {
            id: "v3".to_string(),
            public_key: vec![],
            private_key: vec![],
            locked_stakes: vec![],
            total_locked: 150,
            active: false, // Inactive
        });
        drop(validators);
        
        // Total active stake = 300, quorum = 201 (2/3 * 300 + 1)
        assert_eq!(quorum_threshold(), 201);
    }
}
