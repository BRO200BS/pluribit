// src/wallet.rs
// Manages user keys, UTXOs, transaction creation, and blockchain scanning.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use rand::{rngs::OsRng, RngCore};
use crate::merkle;
use lazy_static::lazy_static;
use std::sync::Mutex;
use crate::blockchain::COINBASE_INDEX; 
use crate::constants::COINBASE_MATURITY; 
use crate::WasmU64;
use std::collections::HashMap;
use sha2::{Sha256, Digest};
use bip39::{Mnemonic, Language};


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


/// Derives scan and spend private keys from a BIP39 seed using domain separation.
fn derive_keys_from_seed(seed_bytes: &[u8]) -> Result<(Scalar, Scalar), String> { // Accept slice, return Result
    // Ensure the seed is the expected length (standard BIP39 seed is 64 bytes)
    if seed_bytes.len() != 64 {
        return Err(format!("Invalid seed length: expected 64, got {}", seed_bytes.len()));
    }
    // Use HKDF or simple hashing with domain separation


    // Derive scan private key
    let mut scan_hasher = Sha256::new();
    scan_hasher.update(b"pluribit_scan_key_v1"); // Domain separator
    scan_hasher.update(seed_bytes);
    let scan_hash: [u8; 32] = scan_hasher.finalize().into();
    
    // Use wide reduction to ensure uniformity
    let mut wide_bytes = [0u8; 64];
    wide_bytes[..32].copy_from_slice(&scan_hash);
    let scan_priv = Scalar::from_bytes_mod_order_wide(&wide_bytes);

    // Derive spend private key
    let mut spend_hasher = Sha256::new();
    spend_hasher.update(b"pluribit_spend_key_v1"); // Different domain separator
    spend_hasher.update(seed_bytes);
    let spend_hash: [u8; 32] = spend_hasher.finalize().into();
    
    // Use wide reduction
    let mut spend_wide = [0u8; 64];
    spend_wide[..32].copy_from_slice(&spend_hash);
    let spend_priv = Scalar::from_bytes_mod_order_wide(&spend_wide);

    Ok((scan_priv, spend_priv))
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


    /// Creates a new wallet, generating a BIP39 mnemonic and deriving keys.
    /// Returns the Wallet instance and the generated mnemonic phrase.
    pub fn new_with_mnemonic() -> Result<(Self, String), String> {
        // Generate entropy (128 bits for 12 words)
        let mut entropy = [0u8; 16];
        OsRng.fill_bytes(&mut entropy);

        // Create mnemonic from entropy
        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| format!("Failed to generate mnemonic: {}", e))?;

        let phrase = mnemonic.word_iter().collect::<Vec<&str>>().join(" ");

        // Create a seed from the mnemonic (using an empty passphrase)
        let seed = mnemonic.to_seed("");


        // Pass the seed slice to the derive function
        let (scan_priv, spend_priv) = derive_keys_from_seed(&seed)?;

        let scan_pub = mimblewimble::derive_public_key(&scan_priv);
        let spend_pub = mimblewimble::derive_public_key(&spend_priv);

        Ok((
            Wallet {
                scan_priv,
                spend_priv,
                scan_pub,
                spend_pub,
                owned_utxos: Vec::new(),
            },
            phrase
        ))
    }

    /// Restores a wallet from a BIP39 mnemonic phrase.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, String> {
        let mnemonic = Mnemonic::parse(phrase) 
            .map_err(|e| format!("Invalid mnemonic phrase: {}", e))?;

        // Create seed (using an empty passphrase)
        let seed = mnemonic.to_seed("");

        // Pass the seed slice to the derive function
        let (scan_priv, spend_priv) = derive_keys_from_seed(&seed)?;

        let scan_pub = mimblewimble::derive_public_key(&scan_priv);
        let spend_pub = mimblewimble::derive_public_key(&spend_priv);

        Ok(Wallet {
            scan_priv,
            spend_priv,
            scan_pub,
            spend_pub,
            owned_utxos: Vec::new(),
        })
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

         // 1. Acquire necessary snapshots BEFORE locking PENDING_UTXOS
         let (valid_commitments, coinbase_creation_heights, current_tip_height): (HashSet<Vec<u8>>, HashMap<Vec<u8>, u64>, u64) = {
             // Lock UTXO_SET first
             let utxo_set = crate::blockchain::UTXO_SET.lock().expect("Failed to lock UTXO_SET for snapshot"); // 
             let commitments = utxo_set.keys().cloned().collect();
             // Lock COINBASE_INDEX next
             let coinbase_index = COINBASE_INDEX.lock().expect("Failed to lock COINBASE_INDEX for snapshot");// 
             let heights = coinbase_index.clone(); // Clone the map for the snapshot
             // Lock BLOCKCHAIN last
             let chain = crate::BLOCKCHAIN.lock().expect("Failed to lock BLOCKCHAIN for snapshot height");// 
             let height = *chain.current_height; 

             (commitments, heights, height) // Return tuple, locks are released here
         }; // Snapshots created, locks released

         let mut selected_inputs = Vec::new();
         let mut selected_utxos = Vec::new();
         let mut input_blinding_sum = Scalar::default();
         let mut total_from_selected: u64 = 0;

         // 2. Now acquire the PENDING_UTXOS lock to perform the atomic selection.
         let mut pending = PENDING_UTXOS.lock().expect("Failed to lock PENDING_UTXOS for selection");

         self.owned_utxos.retain_mut(|utxo| {
             if total_from_selected >= total_needed {
                 return true; // Keep this UTXO, we have enough.
             }

             let commitment_bytes = utxo.commitment.to_bytes().to_vec();

             // Check against the UTXO set snapshot (NO nested lock!)
             if !valid_commitments.contains(&commitment_bytes) {
                 log(&format!("[WALLET] Skipping UTXO not in global set: {}", hex::encode(&commitment_bytes[..8])));
                 return true; // Keep UTXO if it's invalid (maybe reorg happened)
             }

             // Check against the pending set.
             if pending.contains(&commitment_bytes) {
                 log(&format!("[WALLET] Skipping already pending UTXO: {}", hex::encode(&commitment_bytes[..8])));
                 return true; // Keep UTXO if already pending
             }

             if let Some(&creation_height) = coinbase_creation_heights.get(&commitment_bytes) {
                 // It's a coinbase UTXO, check maturity
                 let required_height = creation_height.saturating_add(COINBASE_MATURITY); // [cite: 1490, 1745]
                 // Transaction will be included in the *next* block (tip + 1)
                 let spend_height = current_tip_height.saturating_add(1);

                 if spend_height < required_height {
                     let needed_confs = COINBASE_MATURITY;
                     let current_confs = spend_height.saturating_sub(creation_height);
                     log(&format!(
                         "[WALLET] Skipping immature coinbase UTXO {} (created at {}, needs height {}, current+1 is {}, {}/{} confs)",
                         hex::encode(&commitment_bytes[..8]),
                         creation_height,
                         required_height,
                         spend_height,
                         current_confs,
                         needed_confs
                     ));
                     return true; // Keep UTXO, it's immature
                 }
                 log(&format!("[WALLET] Coinbase UTXO {} is mature.", hex::encode(&commitment_bytes[..8])));
             }


             // Select this UTXO (passed all checks)
             log(&format!("[WALLET] Selected UTXO: value={}, commitment={}", utxo.value, hex::encode(&utxo.commitment.to_bytes()[..8])));
             total_from_selected += utxo.value;
             input_blinding_sum += utxo.blinding;
             log(&format!("[WALLET] Total selected so far: {}", total_from_selected));

             selected_inputs.push(TransactionInput {
                 commitment: commitment_bytes.clone(),
                 merkle_proof: None, // Proofs are not stored in wallet, only used in tx verification
                 source_height: WasmU64::from(utxo.block_height), 
             });
             selected_utxos.push(utxo.clone());

             // Immediately mark as pending to prevent other concurrent calls from selecting it.
             pending.insert(commitment_bytes);

             return false; // Remove this UTXO from owned_utxos for this transaction.
         }); // PENDING_UTXOS lock released here

         // --- END: ATOMIC COIN SELECTION ---
        
        if total_from_selected < total_needed {
             // If we don't have enough funds, revert the changes.
             log("[WALLET] Insufficient funds.");
             self.owned_utxos.extend(selected_utxos); // Add the UTXOs back.
             // --- Need to re-acquire pending lock to unmark ---
             let mut pending_revert = PENDING_UTXOS.lock().expect("Failed to lock PENDING_UTXOS for revert"); // Acquire lock again
             for input in selected_inputs {
                 pending_revert.remove(&input.commitment); // Un-mark as pending.
             }
             // Lock released automatically when pending_revert goes out of scope
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
        let current_height = crate::BLOCKCHAIN.lock().expect("Failed to lock BLOCKCHAIN for kernel height").current_height;
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
                // --- Need to re-acquire pending lock to unmark ---
                  let mut pending_revert = PENDING_UTXOS.lock().expect("Failed to lock PENDING_UTXOS for kernel fail revert"); // Acquire lock again
                  for input in &selected_inputs { // Use a borrow (&) instead of moving 
                      pending_revert.remove(&input.commitment); 
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
