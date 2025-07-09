// src/wallet.rs
// Manages user keys, UTXOs, transaction creation, and blockchain scanning.

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use crate::merkle;
use crate::blockchain::UTXO_SET;
use crate::HashSet;
use crate::BLOCKCHAIN;
use crate::{
    block::Block,
    mimblewimble, // For commit() and create_range_proof()
    stealth,      // For stealth address primitives
    transaction::{Transaction, TransactionInput, TransactionOutput, TransactionKernel},
};
/// Represents a UTXO that the wallet owns and can spend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletUtxo {
    pub value: u64,
    pub blinding: Scalar,
    pub commitment: CompressedRistretto,
}

/// The main Wallet struct, holding keys and owned funds.
#[derive(Debug, Clone, Serialize, Deserialize)] 
pub struct Wallet {
    pub scan_priv: Scalar,
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
        for tx in &block.transactions {
            for output in &tx.outputs {
                // Check if the output has the necessary data for a stealth payment.
                if let (Some(r_bytes), Some(payload)) = (&output.ephemeral_key, &output.stealth_payload) {
                    if let Ok(compressed_point) = CompressedRistretto::from_slice(r_bytes) {
                        if let Some(r_point) = compressed_point.decompress() {
                        
                            // 1. Attempt to decrypt the payload with our private scan key.
                            if let Some((value, blinding)) = stealth::decrypt_stealth_output(&self.scan_priv, &r_point, payload) {
                                
                                // 2. If successful, verify the commitment matches the on-chain one.
                                let commitment = mimblewimble::commit(value, &blinding).unwrap();
                                if commitment.compress().to_bytes().to_vec() == output.commitment {
                                    
                                    // 3. We own this output. Add it to our UTXO set.
                                    println!("[WALLET] Found incoming UTXO! Value: {}", value);
                                    self.owned_utxos.push(WalletUtxo {
                                        value,
                                        blinding,
                                        commitment: commitment.compress(),
                                    });
                                }
                            }
                        }
                    }/////
                }
            }
        }
    }

    /// Creates a transaction to send a specified amount to a recipient.
    pub fn create_transaction(
        &mut self,
        amount: u64,
        fee: u64,
        recipient_scan_pub: &RistrettoPoint,
    ) -> Result<Transaction, String> {
        let total_needed = amount + fee;

        // Get current height for merkle proof generation
        let current_height = BLOCKCHAIN.lock().unwrap().current_height;
        
        // Get current UTXO set for proof generation
        let utxo_set = UTXO_SET.lock().unwrap();
        let utxo_vec: Vec<(Vec<u8>, crate::transaction::TransactionOutput)> = 
            utxo_set.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        // 1. Coin Selection: Find UTXOs to fund the transaction
        let mut inputs_to_spend = Vec::new();
        let mut input_utxos = Vec::new();
        let mut total_available = 0;
        let mut blinding_sum_in = Scalar::default();

        // Simple greedy selection
        self.owned_utxos.retain(|utxo| {
            if total_available < total_needed {
                total_available += utxo.value;
                blinding_sum_in += utxo.blinding;
                
                // Generate merkle proof for this input
                let commitment_bytes = utxo.commitment.to_bytes().to_vec();
                let merkle_proof = merkle::generate_utxo_proof(&commitment_bytes, &utxo_vec).ok();
                
                inputs_to_spend.push(TransactionInput { 
                    commitment: commitment_bytes,
                    merkle_proof,
                });
                input_utxos.push(utxo.clone());
                false // Remove from available UTXOs
            } else {
                true // Keep in available UTXOs
            }
        });

        if total_available < total_needed {
            // If funds are insufficient, return the selected UTXOs to the wallet
            self.owned_utxos.extend(input_utxos);
            return Err("Insufficient funds".to_string());
        }

        // 2. Create Outputs
        let mut outputs = Vec::new();
        let mut blinding_sum_out = Scalar::default();

        // a. Create the recipient's stealth output
        let (recipient_output, recipient_blinding) = create_stealth_output(amount, recipient_scan_pub)?;
        outputs.push(recipient_output);
        blinding_sum_out += recipient_blinding;

        // b. Create change output back to ourselves, if necessary
        let change = total_available - total_needed;
        if change > 0 {
            // Send change back to our own stealth address
            let (change_output, change_blinding) = create_stealth_output(change, &self.scan_pub)?;
            let change_utxo = WalletUtxo {
                value: change,
                blinding: change_blinding,
                commitment: CompressedRistretto::from_slice(&change_output.commitment).unwrap(),
            };
            outputs.push(change_output);
            blinding_sum_out += change_blinding;
            // Immediately add change UTXO back to our owned set
            self.owned_utxos.push(change_utxo); 
        }

        // 3. Create the Transaction Kernel
        // The kernel excess is the difference between output and input blinding factors
        let kernel_blinding = blinding_sum_out - blinding_sum_in;
        let kernel = TransactionKernel::new(kernel_blinding, fee)?;

        // 4. Assemble the final transaction
        Ok(Transaction {
            inputs: inputs_to_spend,
            outputs,
            kernel,
        })
    }
}

/// A private helper function to create a single stealth output.
/// Returns the transaction output and the blinding factor used.
fn create_stealth_output(
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
    use crate::transaction::Transaction;
    use crate::mimblewimble;
    use crate::block::Block;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    #[test]
    fn test_wallet_scan_block_finds_utxo() {
        let mut recipient_wallet = Wallet::new();
        assert_eq!(recipient_wallet.balance(), 0);

        let value = 1000;
        let r = Scalar::random(&mut OsRng);
        let blinding = Scalar::random(&mut OsRng);

        // Corrected: encrypt_stealth_out returns a tuple, not a Result
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
            kernel: TransactionKernel {
                excess: vec![0; 32],
                signature: vec![0; 64],
                fee: 0,
            },
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
    let mut sender = Wallet::new();
    let recipient = Wallet::new();
    
    // Give sender some UTXOs
    sender.owned_utxos.push(WalletUtxo {
        value: 1000,
        blinding: Scalar::from(1u64),
        commitment: mimblewimble::commit(1000, &Scalar::from(1u64)).unwrap().compress(),
    });
    
    // Create transaction
    let tx = sender.create_transaction(600, 50, &recipient.scan_pub);
    assert!(tx.is_ok());
    
    let tx = tx.unwrap();
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 2); // Payment + change
    assert_eq!(tx.kernel.fee, 50);
    
    // Sender should have change UTXO
    assert_eq!(sender.balance(), 350); // 1000 - 600 - 50
}

#[test]
fn test_wallet_insufficient_funds() {
    let mut sender = Wallet::new();
    let recipient = Wallet::new();
    
    // Give sender insufficient funds
    sender.owned_utxos.push(WalletUtxo {
        value: 100,
        blinding: Scalar::from(1u64),
        commitment: mimblewimble::commit(100, &Scalar::from(1u64)).unwrap().compress(),
    });
    
    // Try to send more than available
    let result = sender.create_transaction(150, 10, &recipient.scan_pub);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Insufficient funds"));
    
    // Wallet should still have original UTXO
    assert_eq!(sender.balance(), 100);
}
}
