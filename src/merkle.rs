// src/merkle.rs
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use crate::error::{PluribitResult, PluribitError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProof {
    /// The hash of the leaf being proven
    pub leaf_hash: [u8; 32],
    /// The sibling hashes needed to reconstruct the root
    pub siblings: Vec<[u8; 32]>,
    /// The position of the leaf in the tree (for ordering)
    pub leaf_index: u64,
}

impl MerkleProof {
    /// Verify this proof against a given root
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        let mut current_hash = self.leaf_hash;
        let mut index = self.leaf_index;
        
        for sibling in &self.siblings {
            let mut hasher = Sha256::new();
            
            // The bit tells us if we're left (0) or right (1) child
            if index & 1 == 0 {
                // We're left child, sibling is right
                hasher.update(&current_hash);
                hasher.update(sibling);
            } else {
                // We're right child, sibling is left
                hasher.update(sibling);
                hasher.update(&current_hash);
            }
            
            current_hash = hasher.finalize().into();
            index >>= 1;
        }
        
        &current_hash == root
    }
}

/// Build a Merkle tree and generate proofs for all leaves
pub fn build_merkle_tree_with_proofs(leaves: &[[u8; 32]]) -> (Vec<MerkleProof>, [u8; 32]) {
    if leaves.is_empty() {
        return (vec![], [0u8; 32]);
    }
    
    let mut proofs = Vec::with_capacity(leaves.len());
    let mut tree_levels = vec![leaves.to_vec()];
    
    // Build tree bottom-up
    while tree_levels.last().unwrap().len() > 1 {
        let current_level = tree_levels.last().unwrap();
        let mut next_level = Vec::new();
        
        for i in (0..current_level.len()).step_by(2) {
            let mut hasher = Sha256::new();
            hasher.update(&current_level[i]);
            
            if i + 1 < current_level.len() {
                hasher.update(&current_level[i + 1]);
            } else {
                // Duplicate last node if odd number
                hasher.update(&current_level[i]);
            }
            
            next_level.push(hasher.finalize().into());
        }
        
        tree_levels.push(next_level);
    }
    
    // Generate proofs for each leaf
    for (leaf_idx, leaf_hash) in leaves.iter().enumerate() {
        let mut siblings = Vec::new();
        let mut idx = leaf_idx;
        
        // Walk up the tree collecting siblings
        for level in 0..tree_levels.len() - 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            
            if sibling_idx < tree_levels[level].len() {
                siblings.push(tree_levels[level][sibling_idx]);
            } else {
                // Use the node itself if no sibling exists
                siblings.push(tree_levels[level][idx]);
            }
            
            idx /= 2;
        }
        
        proofs.push(MerkleProof {
            leaf_hash: *leaf_hash,
            siblings,
            leaf_index: leaf_idx as u64,
        });
    }
    
    let root = tree_levels.last().unwrap()[0];
    (proofs, root)
}

/// Generate a single proof for a specific UTXO
pub fn generate_utxo_proof(
    utxo_commitment: &[u8],
    all_utxos: &[(Vec<u8>, crate::transaction::TransactionOutput)],
) -> PluribitResult<MerkleProof> {
    // Find the UTXO's position
    let position = all_utxos.iter()
        .position(|(comm, _)| comm == utxo_commitment)
        .ok_or_else(|| PluribitError::ValidationError("UTXO not found in set".to_string()))?;
    
    // Calculate leaf hashes
    let leaves: Vec<[u8; 32]> = all_utxos.iter()
        .map(|(commitment, output)| {
            let mut hasher = Sha256::new();
            hasher.update(commitment);
            hasher.update(&output.range_proof);
            hasher.finalize().into()
        })
        .collect();
    
    let (proofs, _root) = build_merkle_tree_with_proofs(&leaves);
    
    Ok(proofs[position].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_merkle_proof_single_element() {
        let leaf = [1u8; 32];
        let (proofs, root) = build_merkle_tree_with_proofs(&[leaf]);
        
        assert_eq!(proofs.len(), 1);
        assert_eq!(root, leaf);
        assert!(proofs[0].verify(&root));
    }
    
    #[test]
    fn test_merkle_proof_multiple_elements() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let (proofs, root) = build_merkle_tree_with_proofs(&leaves);
        
        // All proofs should verify
        for proof in &proofs {
            assert!(proof.verify(&root));
        }
        
        // Tampered proof should fail
        let mut bad_proof = proofs[0].clone();
        bad_proof.siblings[0][0] ^= 1;
        assert!(!bad_proof.verify(&root));
    }
}
