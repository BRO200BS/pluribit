// src/wallet.rs
// Manages user keys, UTXOs, transaction creation, and blockchain scanning.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use rand::rngs::OsRng;
use crate::merkle;
use lazy_static::lazy_static;
use std::sync::Mutex;
use crate::WasmU64;
lazy_static! {
    static ref PENDING_UTXOS: Mutex<HashSet<Vec<u8>>> = Mutex::new(HashSet::new());
}
// CRITICAL FIX #7: Custom serialization for Scalar to enforce canonical form
mod scalar_serde {
    use super::*;
    
    pub fn serialize<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Always serialize in canonical form
        serializer.serialize_bytes(&scalar.to_bytes())
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom("Scalar must be 32 bytes"));
        }
        
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        
        // CRITICAL: Only accept canonical scalars
        let optional_scalar: Option<Scalar> = Scalar::from_canonical_bytes(array).into();
        optional_scalar.ok_or_else(|| D::Error::custom("Non-canonical scalar encoding rejected"))

    }
}


use crate::HashSet;
use crate::{
    block::Block,
    mimblewimble, // For commit() and create_range_proof()
    stealth,      // For stealth address primitives
    transaction::{Transaction, TransactionInput, TransactionOutput, TransactionKernel},
};
use crate::log;

/// Represents a UTXO that the wallet owns and can spend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletUtxo {
    pub value: u64,
    #[serde(with = "scalar_serde")]
    pub blinding: Scalar,
    pub commitment: CompressedRistretto,
    pub block_height: u64,
    pub merkle_proof: Option<merkle::MerkleProof>, // Added field
}

/// The main Wallet struct, holding keys and owned funds.
#[derive(Debug, Clone, Serialize, Deserialize)] 
pub struct Wallet {
    #[serde(with = "scalar_serde")]
    pub scan_priv: Scalar,
    #[serde(with = "scalar_serde")]
    pub spend_priv: Scalar,
    pub scan_pub: RistrettoPoint,
    pub spend_pub: RistrettoPoint,
    pub owned_utxos: Vec<WalletUtxo>,
}

impl Wallet {
    /// Creates a new wallet with randomly generated scan and spend keys.
    pub fn new() -> Self {
        let scan_priv = mimblewimble::generate_secret_key();
        let spend_priv = mimblewimble::generate_secret_key();
        let scan_pub = mimblewimble::derive_public_key(&scan_priv);
        let spend_pub = mimblewimble::derive_public_key(&spend_priv);

        Wallet {
            scan_priv,
            spend_priv,
            scan_pub,
            spend_pub,
            owned_utxos: Vec::new(),
        }
    }

    /// Remove UTXOs that came from a specific block (for reorg handling)
    pub fn remove_block_utxos(&mut self, block_commitments: &HashSet<Vec<u8>>) -> usize {
        let initial_count = self.owned_utxos.len();
        
        self.owned_utxos.retain(|utxo| {
            !block_commitments.contains(&utxo.commitment.to_bytes().to_vec())
        });
        
        initial_count - self.owned_utxos.len()
    }
    
    /// Get the list of UTXOs as commitments for comparison
    pub fn get_utxo_commitments(&self) -> HashSet<Vec<u8>> {
        self.owned_utxos.iter()
            .map(|utxo| utxo.commitment.to_bytes().to_vec())
            .collect()
    }


    /// Calculates the wallet's total balance from its owned UTXOs.
    pub fn balance(&self) -> u64 {
        self.owned_utxos.iter().map(|utxo| utxo.value).sum()
    }

    /// Scans a block for outputs belonging to this wallet using the stealth protocol.
  pub fn scan_block(&mut self, block: &Block) {
        // STEP 1: Remove spent inputs ONCE at the start
        for tx in &block.transactions {
            for input in &tx.inputs {
                self.owned_utxos.retain(|u| u.commitment.to_bytes() != *input.commitment);
            }
        }
        
        // STEP 2: Add new outputs (simplified logic)
        for tx in &block.transactions {
            for output in &tx.outputs {
                if let (Some(r_bytes), Some(payload)) = (&output.ephemeral_key, &output.stealth_payload) {
                    if let Ok(compressed_point) = CompressedRistretto::from_slice(r_bytes) {
                        if let Some(r_point) = compressed_point.decompress() {
                            if let Some((value, blinding)) = stealth::decrypt_stealth_output(&self.scan_priv, &r_point, payload) {
                                // Verify commitment matches
                                let commitment = mimblewimble::commit(value, &blinding).unwrap();
                                let commitment_bytes = commitment.compress().to_bytes().to_vec();
                                
                                if commitment_bytes != output.commitment {
                                    continue;
                                }
                                
                                // Verify range proof
                                let proof = match RangeProof::from_bytes(&output.range_proof) {
                                    Ok(p) => p,
                                    Err(_) => {
                                        log(&format!("[WALLET] Invalid range proof format for output {}", 
                                            hex::encode(&output.commitment[..8])));
                                        continue;
                                    }
                                };
                                
                                if !mimblewimble::verify_range_proof(&proof, &CompressedRistretto::from_slice(&output.commitment).unwrap()) {
                                    log(&format!("[WALLET] Range proof verification failed for output {}", 
                                        hex::encode(&output.commitment[..8])));
                                    continue;
                                }
                                
                                // ✅ SIMPLIFIED: Just check if we don't already have it
                                if !self.owned_utxos.iter().any(|u| u.commitment.to_bytes() == commitment_bytes.as_slice()) {
                                    log(&format!("[WALLET] Found incoming UTXO! Value: {}", value));
                                    self.owned_utxos.push(WalletUtxo {
                                        value,
                                        blinding,
                                        commitment: CompressedRistretto::from_slice(&commitment_bytes).unwrap(),
                                        block_height: *block.height,
                                        merkle_proof: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        // ✅ NO second input removal loop needed
    }
    


    /// Creates a transaction to send a specified amount to a recipient.
    pub fn create_transaction(
        &mut self,
        amount: u64,
        fee: u64,
        recipient_scan_pub: &RistrettoPoint,
    ) -> Result<Transaction, String> {
        log("=== CREATE_TRANSACTION DEBUG ===");
        let total_needed = amount.checked_add(fee).ok_or("Amount plus fee overflowed")?;
        log(&format!("[WALLET] Amount={}, Fee={}", amount, fee));
        log(&format!("[WALLET] Selecting UTXOs to cover {}...", total_needed));
        log(&format!("[WALLET] Available UTXOs before selection: {}", self.owned_utxos.len()));

        // --- START: ATOMIC COIN SELECTION WITH LOCK ORDERING ---

        // 1. Acquire UTXO_SET lock first to get a snapshot of valid UTXOs.
        let valid_commitments: HashSet<Vec<u8>> = {
            let utxo_set = crate::blockchain::UTXO_SET.lock().unwrap();
            utxo_set.keys().cloned().collect()
        }; // Lock is released immediately after snapshot is created.

        let mut selected_inputs = Vec::new();
        let mut selected_utxos = Vec::new();
        let mut input_blinding_sum = Scalar::default();
        let mut total_from_selected: u64 = 0;

        // 2. Now acquire the PENDING_UTXOS lock to perform the atomic selection.
        let mut pending = PENDING_UTXOS.lock().unwrap();
        
        self.owned_utxos.retain_mut(|utxo| {
            if total_from_selected >= total_needed {
                return true; // Keep this UTXO, we have enough.
            }

            let commitment_bytes = utxo.commitment.to_bytes().to_vec();

            // Check against the snapshot (NO nested lock!) and the pending set.
            if valid_commitments.contains(&commitment_bytes) && !pending.contains(&commitment_bytes) {
                // Select this UTXO
                log(&format!("[WALLET] Selected UTXO: value={}, commitment={}", utxo.value, hex::encode(&utxo.commitment.to_bytes()[..8])));
                total_from_selected += utxo.value;
                input_blinding_sum += utxo.blinding;
                log(&format!("[WALLET] Total selected so far: {}", total_from_selected));
                
                selected_inputs.push(TransactionInput {
                    commitment: commitment_bytes.clone(),
                    merkle_proof: None,
                    source_height: WasmU64::from(utxo.block_height),
                });
                selected_utxos.push(utxo.clone());

                // Immediately mark as pending to prevent other concurrent calls from selecting it.
                pending.insert(commitment_bytes);

                return false; // Remove this UTXO from owned_utxos for this transaction.
            }

            true // Keep UTXO if it's invalid, pending, or not needed.
        });

        // --- END: ATOMIC COIN SELECTION ---
        
        if total_from_selected < total_needed {
            // If we don't have enough funds, revert the changes.
            log("[WALLET] Insufficient funds.");
            self.owned_utxos.extend(selected_utxos); // Add the UTXOs back.
            for input in selected_inputs {
                pending.remove(&input.commitment); // Un-mark as pending.
            }
            return Err("Insufficient funds after excluding invalid/pending UTXOs".to_string());
        }

        // 3. Create Outputs
        log(&format!("[WALLET] Creating outputs..."));
        let mut outputs = Vec::new();
        let mut output_blinding_sum = Scalar::default();
        
        let (recipient_output, recipient_blinding) = create_stealth_output(amount, recipient_scan_pub)?;
        outputs.push(recipient_output);
        output_blinding_sum += recipient_blinding;
        
        let change_amount = total_from_selected - total_needed;
        if change_amount > 0 {
            log(&format!("[WALLET] Change amount: {}", change_amount));
            let (change_output, change_blinding) = create_stealth_output(change_amount, &self.scan_pub)?;
            outputs.push(change_output);
            output_blinding_sum += change_blinding;
        }

        // 4. Create the Transaction Kernel
        let current_height = crate::BLOCKCHAIN.lock().unwrap().current_height;
        #[cfg(target_arch = "wasm32")]
        let timestamp = js_sys::Date::now() as u64;
        #[cfg(not(target_arch = "wasm32"))]
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        
        let kernel_blinding = input_blinding_sum - output_blinding_sum;
        
        log(&format!("[WALLET] Transaction blinding factors:"));
        log(&format!("  blinding_sum_in: {}", hex::encode(input_blinding_sum.to_bytes())));
        log(&format!("  blinding_sum_out: {}", hex::encode(output_blinding_sum.to_bytes())));
        log(&format!("  kernel_blinding: {}", hex::encode(kernel_blinding.to_bytes())));

        let kernel = TransactionKernel::new(kernel_blinding, fee, *current_height, timestamp)
            .map_err(|e| {
                // If kernel creation fails, we must also revert
                self.owned_utxos.extend(selected_utxos);
                for input in &selected_inputs { // Use a borrow (&) instead of moving
                    pending.remove(&input.commitment);
                }
                e
            })?;
            
        // 5. Assemble the final transaction
        log("[WALLET] Assembling final transaction...");
        Ok(Transaction {
            inputs: selected_inputs,
            outputs,
            kernels: vec![kernel],
            timestamp: WasmU64::from(timestamp),
        })
    }
    

    /// Clear pending marks for specific commitments (call after tx broadcast failure)
    pub fn clear_pending_utxos(commitments: &[Vec<u8>]) {

        
        let mut pending = PENDING_UTXOS.lock().unwrap();
        for commitment in commitments {
            pending.remove(commitment);
        }
    }
    
 }  

/// A public helper function to create a single stealth output.
/// Returns the transaction output and the blinding factor used.
pub fn create_stealth_output(
    value: u64,
    scan_pub: &RistrettoPoint,
) -> Result<(TransactionOutput, Scalar), String> {
    let r = Scalar::random(&mut OsRng);
    let blinding = Scalar::random(&mut OsRng);

    let (ephemeral_key, payload) = stealth::encrypt_stealth_out(&r, scan_pub, value, &blinding);

    let (range_proof, commitment) = mimblewimble::create_range_proof(value, &blinding)
        .map_err(|e| e.to_string())?;

    Ok((
        TransactionOutput {
            commitment: commitment.to_bytes().to_vec(),
            range_proof: range_proof.to_bytes(),
            ephemeral_key: Some(ephemeral_key.compress().to_bytes().to_vec()),
            stealth_payload: Some(payload),
        },
        blinding,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::mimblewimble;
    use crate::transaction::Transaction;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    #[test]
    fn test_wallet_scan_block_finds_utxo() {
        let mut recipient_wallet = Wallet::new();
        assert_eq!(recipient_wallet.balance(), 0);

        let value = 1000;
        let r = Scalar::random(&mut OsRng);
        let blinding = Scalar::random(&mut OsRng);
        let (ephemeral_key, payload) = stealth::encrypt_stealth_out(
            &r,
            &recipient_wallet.scan_pub,
            value,
            &blinding,
        );
        let commitment = mimblewimble::commit(value, &blinding).unwrap();
        let (range_proof, _) = mimblewimble::create_range_proof(value, &blinding).unwrap();
        let output = TransactionOutput {
            commitment: commitment.compress().to_bytes().to_vec(),
            range_proof: range_proof.to_bytes(),
            ephemeral_key: Some(ephemeral_key.compress().to_bytes().to_vec()),
            stealth_payload: Some(payload),
        };
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![output],
            kernels: vec![TransactionKernel {
                excess: vec![0; 32],
                signature: vec![0; 64],
                fee: 0,
                min_height: 0, // Added missing field
                timestamp: 1,
            }],
            timestamp: 1,
        };
        let mut block = Block::genesis();
        block.transactions.push(tx);

        recipient_wallet.scan_block(&block);

        assert_eq!(recipient_wallet.balance(), value);
        assert_eq!(recipient_wallet.owned_utxos.len(), 1);
        assert_eq!(recipient_wallet.owned_utxos[0].value, value);
    }
#[test]
fn test_wallet_create_transaction() {
    // Add proper test isolation
    use lazy_static::lazy_static;
    use std::sync::Mutex;
    
    lazy_static! {
        static ref WALLET_TEST_MUTEX: Mutex<()> = Mutex::new(());
    }
    
    let _guard = WALLET_TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    
    // Reset any global state that might be accessed
    {
        let mut chain = crate::BLOCKCHAIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *chain = crate::blockchain::Blockchain::new();
    }
    
    let mut sender = Wallet::new();
    let recipient = Wallet::new();
    // Give sender some UTXOs
    let utxo_commitment = mimblewimble::commit(1000, &Scalar::from(1u64))
        .unwrap()
        .compress()
        .to_bytes()
        .to_vec();
    
    // Add to global UTXO set so create_transaction can find it
    let utxo_output = crate::transaction::TransactionOutput {
        commitment: utxo_commitment.clone(),
        range_proof: vec![0; 675], // Dummy proof for test
        ephemeral_key: None,
        stealth_payload: None,
    };
    {
        crate::blockchain::UTXO_SET.lock().unwrap().insert(utxo_commitment.clone(), utxo_output);
    }
    
    sender.owned_utxos.push(WalletUtxo {
        value: 1000,
        blinding: Scalar::from(1u64),
        commitment: mimblewimble::commit(1000, &Scalar::from(1u64))
            .unwrap()
            .compress(),
        block_height: 0,
        merkle_proof: None,
    });
    
    // Create transaction
    let tx = sender.create_transaction(600, 50, &recipient.scan_pub);
    assert!(tx.is_ok());

    let tx = tx.unwrap();
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 2); // Payment + change
    assert_eq!(tx.total_fee(), 50);
    
    // Clean up
    crate::blockchain::UTXO_SET.lock().unwrap().clear();    
    
    // NOTE: Change is no longer immediately added to wallet - it will be found by scan_block when confirmed
    // After spending, wallet has 0 balance until the transaction is mined and scanned
    assert_eq!(sender.balance(), 0);
}

    #[test]
    fn test_wallet_insufficient_funds() {
        let mut sender = Wallet::new();
        let recipient = Wallet::new();
 
        let utxo_commitment = mimblewimble::commit(100, &Scalar::from(1u64))
            .unwrap()
            .compress()
            .to_bytes()
            .to_vec();
        
        // Add to global UTXO set
        let utxo_output = crate::transaction::TransactionOutput {
            commitment: utxo_commitment.clone(),
            range_proof: vec![0; 675],
            ephemeral_key: None,
            stealth_payload: None,
        };
        {
            crate::blockchain::UTXO_SET.lock().unwrap().insert(utxo_commitment.clone(), utxo_output);
        }
                    
        // Give sender insufficient funds
        sender.owned_utxos.push(WalletUtxo {
            value: 100,
            blinding: Scalar::from(1u64),
            commitment: mimblewimble::commit(100, &Scalar::from(1u64))
                .unwrap()
                .compress(),
            block_height: 0,
            merkle_proof: None, // Added missing field
        });
        // Try to send more than available
        let result = sender.create_transaction(150, 10, &recipient.scan_pub);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient"));
        
        // Clean up
        crate::blockchain::UTXO_SET.lock().unwrap().clear();
        // Wallet should still have original UTXO
        assert_eq!(sender.balance(), 100);
    }
}
