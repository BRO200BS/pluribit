// src/transaction.rs

use serde::{Serialize, Deserialize};
use crate::error::{PluribitResult, PluribitError};
use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};
use crate::mimblewimble;
use crate::blockchain::UTXO_SET;
use curve25519_dalek::traits::Identity;
use crate::log;
// Removed unused import: use crate::log;


#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransactionInput {
    pub commitment: Vec<u8>,
    pub merkle_proof: Option<crate::merkle::MerkleProof>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransactionOutput {
    pub commitment: Vec<u8>,
    pub range_proof: Vec<u8>,
    pub ephemeral_key: Option<Vec<u8>>, // Stores the sender's ephemeral public key R
    pub stealth_payload: Option<Vec<u8>>, // Stores the encrypted nonce || cipher
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TransactionKernel {
    pub excess: Vec<u8>,       // Compressed Ristretto public key
    pub signature: Vec<u8>,    // Schnorr signature bytes (challenge || s)
    pub fee: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub kernel: TransactionKernel,
}

impl TransactionInput {
    pub fn verify_merkle_proof(&self, height: u64) -> PluribitResult<bool> {
        let proof = self.merkle_proof.as_ref()
            .ok_or_else(|| PluribitError::ValidationError("Missing merkle proof".to_string()))?;
        
        let roots = crate::blockchain::UTXO_ROOTS.lock().unwrap();
        let root = roots.get(&height)
            .ok_or_else(|| PluribitError::ValidationError(
                format!("No UTXO root found for height {}", height)
            ))?;
        
        Ok(proof.verify(root))
    }
}

impl TransactionKernel {
    
pub fn new(blinding: Scalar, fee: u64) -> Result<Self, String> {

    log("=== TRANSACTION_KERNEL::NEW DEBUG ===");
    log(&format!("[KERNEL_NEW] Input blinding={}", hex::encode(blinding.to_bytes())));
    log(&format!("[KERNEL_NEW] Fee={}", fee));
    
    // The kernel excess IS a commitment to the fee, blinded by the kernel's secret.
    // P = fee*H + blinding*G
    let excess_point = mimblewimble::PC_GENS.commit(Scalar::from(fee), blinding);

    log(&format!("[KERNEL_NEW] Derived excess_point={}", hex::encode(excess_point.compress().to_bytes())));
    
    let mut hasher = Sha256::new();
    hasher.update(&fee.to_le_bytes());
    let message_hash: [u8; 32] = hasher.finalize().into();
    log(&format!("[KERNEL_NEW] Message hash={}", hex::encode(message_hash)));

    let (challenge, s) = mimblewimble::create_schnorr_signature(message_hash, &blinding)
        .map_err(|e| e.to_string())?;

    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(&challenge.to_bytes());
    signature.extend_from_slice(&s.to_bytes());
    
    Ok(TransactionKernel {
        excess: excess_point.compress().to_bytes().to_vec(),
        signature,
        fee,
    })
}
    
    /// Properly aggregate multiple kernels with signature aggregation
    pub fn aggregate(kernels: &[TransactionKernel]) -> PluribitResult<TransactionKernel> {
        
        
        if kernels.is_empty() {
            return Err(PluribitError::InvalidInput("No kernels to aggregate".to_string()));
        }
        
        if kernels.len() == 1 {
            return Ok(kernels[0].clone());
        }
        
        let mut total_fee = 0u64;
        let mut signatures = Vec::new();
        let mut public_keys = Vec::new();
        
        for kernel in kernels {
            total_fee += kernel.fee;
            
            let pubkey = mimblewimble::kernel_excess_to_pubkey(&kernel.excess)?;
            public_keys.push(pubkey);
            
            if kernel.signature.len() != 64 {
                return Err(PluribitError::InvalidKernelSignature);
            }
            
            let challenge = Scalar::from_bytes_mod_order(
                kernel.signature[0..32].try_into()
                    .map_err(|_| PluribitError::InvalidKernelSignature)?
            );
            let s = Scalar::from_bytes_mod_order(
                kernel.signature[32..64].try_into()
                    .map_err(|_| PluribitError::InvalidKernelSignature)?
            );
            
            signatures.push((challenge, s));
        }
        
        let aggregate_pubkey: RistrettoPoint = public_keys.iter().sum();
        
        let mut hasher = Sha256::new();
        hasher.update(&total_fee.to_le_bytes());
        let message_hash: [u8; 32] = hasher.finalize().into();
        
        let (agg_challenge, agg_s) = mimblewimble::aggregate_schnorr_signatures(
            &signatures,
            &public_keys,
            message_hash
        )?;
        
        let mut signature_bytes = Vec::with_capacity(64);
        signature_bytes.extend_from_slice(&agg_challenge.to_bytes());
        signature_bytes.extend_from_slice(&agg_s.to_bytes());
        
        Ok(TransactionKernel {
            excess: aggregate_pubkey.compress().to_bytes().to_vec(),
            signature: signature_bytes,
            fee: total_fee,
        })
    }
}

impl Transaction {
    /// Verify this transaction end-to-end:
    /// 1) All range proofs validate
    /// 2) Kernel Schnorr signature is correct
    /// 3) Sum(inputs) == Sum(outputs) + excess
    /// 4) All inputs exist in the UTXO set
    #[allow(non_snake_case)]
    pub fn verify(&self, block_reward: Option<u64>) -> PluribitResult<()> {
        // 1) Range proofs
        for output in &self.outputs {
            let C = CompressedRistretto::from_slice(&output.commitment)
                .map_err(|_| PluribitError::InvalidOutputCommitment)?;
            let proof = RangeProof::from_bytes(&output.range_proof)
                .map_err(|_| PluribitError::InvalidRangeProof)?;
            if !mimblewimble::verify_range_proof(&proof, &C) {
                return Err(PluribitError::InvalidRangeProof);
            }
        }

        // 2) Schnorr kernel signature
        if !self.verify_signature()? {
            return Err(PluribitError::InvalidKernelSignature);
        }
        let P = mimblewimble::kernel_excess_to_pubkey(&self.kernel.excess)?;

        // 3) Balance check
        let mut sum_in = RistrettoPoint::identity();
        for inp in &self.inputs {
            let C = CompressedRistretto::from_slice(&inp.commitment)
                .map_err(|_| PluribitError::InvalidInputCommitment)?
                .decompress()
                .ok_or(PluribitError::InvalidInputCommitment)?;
            sum_in += C;
        }
        
        let mut sum_out = RistrettoPoint::identity();
        for out in &self.outputs {
            let C = CompressedRistretto::from_slice(&out.commitment)
                .map_err(|_| PluribitError::InvalidOutputCommitment)?
                .decompress()
                .ok_or(PluribitError::InvalidOutputCommitment)?;
            sum_out += C;
        }
        
        if let Some(reward) = block_reward {
            // This is a COINBASE transaction.
            // We verify that: Sum(Outputs) - KernelExcess == reward*H
            let reward_commitment = mimblewimble::PC_GENS.commit(Scalar::from(reward), Scalar::from(0u64));

            if sum_out - P != reward_commitment {
                return Err(PluribitError::Imbalance);
            }
        } else {
            // ---------- REGULAR TRANSACTION BALANCE CHECK ----------
            // The core Mimblewimble equation: Sum(Inputs) == Sum(Outputs) + KernelExcess
            if sum_out + P != sum_in {
                return Err(PluribitError::Imbalance);
            }
        }

        // 4) UTXO existence and merkle proofs (only for regular transactions)
        if block_reward.is_none() {
            let utxos = UTXO_SET.lock().unwrap();
            for inp in &self.inputs {
                if !utxos.contains_key(&inp.commitment) {
                    return Err(PluribitError::UnknownInput);
                }
                

                if inp.merkle_proof.is_none() {
                       return Err(PluribitError::ValidationError(
                           "Missing required merkle proof".to_string()
                    ));
                }
                    

                
            }
        }

        Ok(())
    }

    /// Create a coinbase transaction (no inputs, only outputs)
  pub fn create_coinbase(rewards: Vec<(Vec<u8>, u64)>) -> PluribitResult<Self> {
    use crate::stealth;
    use rand::rngs::OsRng;
    
    let mut outputs = Vec::new();
    let mut blinding_sum = Scalar::default();
    let mut total_reward_value = 0u64;
    
    log("=== CREATE_COINBASE DEBUG ===");
    
    for (i, (recipient_pub_key_bytes, amount)) in rewards.iter().enumerate() {
        total_reward_value += amount;
        log(&format!("[CREATE_COINBASE] Output {}: amount={}", i, amount));

        let scan_pub_compressed = CompressedRistretto::from_slice(&recipient_pub_key_bytes)
            .map_err(|_| PluribitError::ValidationError("Invalid public key".to_string()))?;

        let scan_pub = scan_pub_compressed.decompress()
            .ok_or_else(|| PluribitError::ValidationError("Failed to decompress public key".to_string()))?;
        
        let r = Scalar::random(&mut OsRng);
        let blinding = Scalar::random(&mut OsRng);
        log(&format!("[CREATE_COINBASE] Output {}: blinding={}", i, hex::encode(blinding.to_bytes())));
        
        let (ephemeral_key, payload) = stealth::encrypt_stealth_out(&r, &scan_pub, *amount, &blinding);
        
        // Create commitment explicitly
        let commitment_point = mimblewimble::commit(*amount, &blinding)?;
        let commitment = commitment_point.compress();
        log(&format!("[CREATE_COINBASE] Output {}: commitment={}", i, hex::encode(commitment.to_bytes())));
        
        let (proof, _) = mimblewimble::create_range_proof(*amount, &blinding)?;
        
        outputs.push(TransactionOutput {
            commitment: commitment.to_bytes().to_vec(),
            range_proof: proof.to_bytes(),
            ephemeral_key: Some(ephemeral_key.compress().to_bytes().to_vec()),
            stealth_payload: Some(payload),
        });
        
        blinding_sum += blinding;
        log(&format!("[CREATE_COINBASE] Output {}: running blinding_sum={}", i, hex::encode(blinding_sum.to_bytes())));
    }
    
    log(&format!("[CREATE_COINBASE] Final blinding_sum={}", hex::encode(blinding_sum.to_bytes())));
    log(&format!("[CREATE_COINBASE] Total reward value={}", total_reward_value));
    
    let fee = 0u64;
    let kernel = TransactionKernel::new(blinding_sum, fee)
        .map_err(|e| PluribitError::ComputationError(e.to_string()))?;
    
    log(&format!("[CREATE_COINBASE] Kernel excess={}", hex::encode(&kernel.excess)));
    
    Ok(Transaction {
        inputs: vec![],
        outputs,
        kernel,
    })
}
    
    #[allow(non_snake_case)]
    pub fn verify_signature(&self) -> PluribitResult<bool> {
        // Decompress the kernel excess point P = blinding*G + fee*H
        let P = CompressedRistretto::from_slice(&self.kernel.excess)
            .map_err(|_| PluribitError::InvalidKernelExcess)?
            .decompress()
            .ok_or(PluribitError::InvalidKernelExcess)?;

        // Reconstruct the public key (blinding*G) used for the signature.
        // This is done by subtracting the commitment to the fee (fee*H) from the excess.
        let fee_commitment = mimblewimble::PC_GENS.commit(Scalar::from(self.kernel.fee), Scalar::from(0u64));
        let public_key = P - fee_commitment;

        // The message that was signed is the hash of the fee.
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.kernel.fee.to_le_bytes());
        let msg_hash: [u8; 32] = hasher.finalize().into();
        
        // Parse the signature from the kernel.
        if self.kernel.signature.len() != 64 {
            return Ok(false);
        }
        let mut challenge_bytes = [0u8; 32];
        challenge_bytes.copy_from_slice(&self.kernel.signature[0..32]);
        let challenge = Scalar::from_bytes_mod_order(challenge_bytes);

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&self.kernel.signature[32..64]);
        let s = Scalar::from_bytes_mod_order(s_bytes);

        // Verify the Schnorr signature.
        Ok(mimblewimble::verify_schnorr_signature(&(challenge, s), msg_hash, &public_key))
    }

    /// Get a unique hash for this transaction based on kernel
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.kernel.excess);
        hasher.update(&self.kernel.signature);
        hasher.update(&self.kernel.fee.to_le_bytes());
        hex::encode(hasher.finalize())
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet; // Added for coinbase test
    use curve25519_dalek::scalar::Scalar; // Added for regular tx test
    use crate::mimblewimble::kernel_excess_to_pubkey;

    // New Test for Coinbase Logic
    #[test]
    fn test_coinbase_creation_and_verification() {
        // 1. Define the context for the coinbase transaction.
        let reward_amount = 50_000_000;
        let wrong_reward = 100;
        
        // Create a dummy recipient (the miner's wallet).
        let miner_wallet = Wallet::new();
        let miner_pubkey_bytes = miner_wallet.scan_pub.compress().to_bytes().to_vec();
        let rewards = vec![(miner_pubkey_bytes, reward_amount)];

        // 2. Create the coinbase transaction.
        let coinbase_tx = Transaction::create_coinbase(rewards).unwrap();

        // 3. Verify the transaction with the CORRECT reward context. This should succeed.
        assert!(
            coinbase_tx.verify(Some(reward_amount)).is_ok(),
            "Coinbase verification should succeed with the correct reward"
        );

        // 4. Verify the transaction with the WRONG reward context. This must fail.
        assert!(
            coinbase_tx.verify(Some(wrong_reward)).is_err(),
            "Coinbase verification should fail with an incorrect reward"
        );

        // 5. Verify the transaction as if it were a regular transaction. This must fail.
        assert!(
            coinbase_tx.verify(None).is_err(),
            "Coinbase verification should fail when treated as a regular transaction"
        );
    }

    // Existing Test (Modified slightly for clarity)
    #[test]
    fn test_transaction_roundtrip() {
        // This test is a placeholder for a full regular transaction test.
        // It needs to be expanded to be meaningful.
        let blinding = Scalar::from(5u64);
        let commitment = mimblewimble::commit(5, &blinding).unwrap();

        let inp = TransactionInput { commitment: commitment.compress().to_bytes().to_vec(), merkle_proof: None };

        
        // This tx is invalid as created, but shows the structure.
        let tx = Transaction { 
            inputs: vec![inp.clone()], 
            outputs: vec![], 
            kernel: TransactionKernel { 
                excess: vec![], 
                signature: vec![], 
                fee: 0 
            } 
        };
        
        // To make this test pass, you would need to:
        // 1. Properly construct outputs and a kernel.
        // 2. Add the input commitment to the global UTXO_SET for the verify() call.
        let mut utxos = UTXO_SET.lock().unwrap();
        utxos.insert(inp.commitment.clone(), TransactionOutput {
            commitment: inp.commitment.clone(),
            range_proof: vec![],
            ephemeral_key: None,
            stealth_payload: None,
        });
        
        // As written, this tx is invalid and verify() will fail.
        // The goal is to show where the test would go.
        assert!(tx.verify(None).is_err());
    }
    #[test]
fn test_transaction_kernel_aggregate() {
    // Create multiple kernels
    let kernels = vec![
        TransactionKernel::new(Scalar::from(1u64), 10).unwrap(),
        TransactionKernel::new(Scalar::from(2u64), 20).unwrap(),
        TransactionKernel::new(Scalar::from(3u64), 30).unwrap(),
    ];
    
    // Aggregate
    let agg_kernel = TransactionKernel::aggregate(&kernels).unwrap();
    
    // Check fee aggregation
    assert_eq!(agg_kernel.fee, 60);
    
    // Check excess is valid point
    let excess_point = kernel_excess_to_pubkey(&agg_kernel.excess);
    assert!(excess_point.is_ok());
}

#[test]
fn test_transaction_verify_regular() {
    // Create a transaction that spends existing UTXO
    let blinding_in = Scalar::from(1u64);
    let blinding_out = Scalar::from(2u64);
    let value_in = 100u64;
    let value_out = 90u64;
    let fee = 10u64;
    // Create input commitment and add to UTXO set
    let input_commitment = mimblewimble::commit(value_in, &blinding_in).unwrap();
    UTXO_SET.lock().unwrap().insert(
        input_commitment.compress().to_bytes().to_vec(),
        TransactionOutput {
            commitment: input_commitment.compress().to_bytes().to_vec(),
            range_proof: vec![],
            ephemeral_key: None,
            stealth_payload: None,
        }
    );
    // Create output with range proof
    let (range_proof, output_commitment) = mimblewimble::create_range_proof(value_out, &blinding_out).unwrap();
    // Create kernel
    let kernel_blinding = blinding_in - blinding_out;
    let kernel = TransactionKernel::new(kernel_blinding, fee).unwrap();

    // ADD A DUMMY MERKLE PROOF TO SATISFY THE VERIFY FUNCTION
    let dummy_proof = crate::merkle::MerkleProof {
        leaf_hash: [0u8; 32],
        siblings: vec![],
        leaf_index: 0,
    };

    let tx = Transaction {
        inputs: vec![TransactionInput {
            commitment: input_commitment.compress().to_bytes().to_vec(),
            merkle_proof: Some(dummy_proof), // <-- ADDED DUMMY PROOF
        }],
        outputs: vec![TransactionOutput {
            commitment: output_commitment.to_bytes().to_vec(),
            range_proof: range_proof.to_bytes(),
            ephemeral_key: None,
            stealth_payload: None,
         }],
        kernel,
    };
    // Should verify successfully
    assert!(tx.verify(None).is_ok());
    
    // Clean up
    UTXO_SET.lock().unwrap().clear();
}

#[test]
fn test_transaction_hash() {
    let tx1 = Transaction {
        inputs: vec![],
        outputs: vec![],
        kernel: TransactionKernel {
            excess: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            fee: 10,
        },
    };
    
    let tx2 = Transaction {
        inputs: vec![],
        outputs: vec![],
        kernel: TransactionKernel {
            excess: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            fee: 10,
        },
    };
    
    // Same transaction should have same hash
    assert_eq!(tx1.hash(), tx2.hash());
    
    // Different fee should give different hash
    let mut tx3 = tx1.clone();
    tx3.kernel.fee = 20;
    assert_ne!(tx1.hash(), tx3.hash());
}
    
}
