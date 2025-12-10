// src/vrf.rs
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use rand::thread_rng;
use crate::p2p;

/// VRF proof data structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VrfProof {
    pub gamma: [u8; 32],
    pub c: [u8; 32],
    pub s: [u8; 32],
    pub output: [u8; 32],
}

impl Default for VrfProof {
    fn default() -> Self {
        VrfProof {
            gamma: [0u8; 32],
            c: [0u8; 32],
            s: [0u8; 32],
            output: [0u8; 32],
        }
    }
}

/// Hash arbitrary input to a curve point
fn hash_to_point(input: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha256::new();
    hasher.update(b"pluribit_vrf_h2p_v1");
    hasher.update(input);
    let hash_bytes: [u8; 32] = hasher.finalize().into();
    let hash_scalar = Scalar::from_bytes_mod_order(hash_bytes);
    &hash_scalar * &*RISTRETTO_BASEPOINT_TABLE
}

/// Create a VRF proof
pub fn create_vrf(secret_key: &Scalar, input: &[u8]) -> VrfProof {
    // Removed println! statements for performance and to keep stdout clean.
    // The previous debug logs exposed the Secret Key, which is unsafe.
    
    // Hash input to curve point
    let h = hash_to_point(input);
    
    // Compute gamma = x*H
    let gamma = secret_key * &h;
    
    // Generate random nonce
    let mut rng = thread_rng();
    let k = Scalar::random(&mut rng);
    
    // Compute k*G and k*H
    let k_g = &k * &*RISTRETTO_BASEPOINT_TABLE;
    let k_h = &k * &h;
    
    // Compute challenge c = H(h, gamma, k*G, k*H)
    let mut hasher = Sha256::new();
    // Add domain separation
    hasher.update(b"pluribit_vrf_v2");
    hasher.update(b"pluribit_vrf_challenge_v1");
    hasher.update(&h.compress().to_bytes());
    hasher.update(&gamma.compress().to_bytes());
    hasher.update(&k_g.compress().to_bytes());
    hasher.update(&k_h.compress().to_bytes());
    let c_bytes: [u8; 32] = hasher.finalize().into();
    
    let c_scalar = Scalar::from_bytes_mod_order(c_bytes);
    
    // Compute s = k + c*x
    let s_scalar = k + (c_scalar * secret_key);
    
    // Compute VRF output
    let mut output_hasher = Sha256::new();
    output_hasher.update(b"pluribit_vrf_output_v1");
    output_hasher.update(&gamma.compress().to_bytes());
    let output: [u8; 32] = output_hasher.finalize().into();
    
    VrfProof {
        gamma: gamma.compress().to_bytes(),
        c: c_bytes,  // Store the raw hash bytes, not the scalar bytes!
        s: s_scalar.to_bytes(),
        output,
    }
}

/// Verify a VRF proof
pub fn verify_vrf(public_key: &RistrettoPoint, input: &[u8], proof: &VrfProof) -> bool {
    // Removed println! debug statements.
    
    // Recompute h = H(input)
    let h = hash_to_point(input);
    
    // Parse scalars from proof
    let c_scalar = Scalar::from_bytes_mod_order(proof.c);
    let s_scalar = Scalar::from_bytes_mod_order(proof.s);

    // Parse gamma point
    let gamma_compressed = match CompressedRistretto::from_slice(&proof.gamma) {
        Ok(p) => p,
        Err(_) => return false,
    };
    
    let gamma_point = match gamma_compressed.decompress() {
        Some(p) => p,
        None => return false,
    };

    // Compute u = s*G - c*PK (should equal k*G)
    let s_g = &s_scalar * &*RISTRETTO_BASEPOINT_TABLE;
    let c_pk = &c_scalar * public_key;
    let u_check = s_g - c_pk;

    // Compute v = s*H - c*Gamma (should equal k*H)
    let s_h = &s_scalar * &h;
    let c_gamma = &c_scalar * &gamma_point;
    let v_check = s_h - c_gamma;

    // Recompute challenge
    let mut hasher = Sha256::new();
    hasher.update(b"pluribit_vrf_v2");
    hasher.update(b"pluribit_vrf_challenge_v1");
    hasher.update(&h.compress().to_bytes());
    hasher.update(&gamma_point.compress().to_bytes());
    hasher.update(&u_check.compress().to_bytes());
    hasher.update(&v_check.compress().to_bytes());
    let c_recomputed: [u8; 32] = hasher.finalize().into();
    
    // Check challenge matches
    if c_recomputed != proof.c {
        return false;
    }

    // Verify output
    let mut output_hasher = Sha256::new();
    output_hasher.update(b"pluribit_vrf_output_v1");
    output_hasher.update(&proof.gamma);
    let expected_output: [u8; 32] = output_hasher.finalize().into();
    
    if expected_output != proof.output {
        return false;
    }
    
    true
}

/// **Protobuf Conversion: Internal -> p2p**
impl From<VrfProof> for p2p::VrfProof {
    fn from(proof: VrfProof) -> Self {
        p2p::VrfProof {
            gamma: proof.gamma.to_vec(),
            c: proof.c.to_vec(),
            s: proof.s.to_vec(),
            output: proof.output.to_vec(),
        }
    }
}

/// **Protobuf Conversion: p2p -> Internal**
impl From<p2p::VrfProof> for VrfProof {
    fn from(proto: p2p::VrfProof) -> Self {
        let mut gamma = [0u8; 32];
        if proto.gamma.len() == 32 {
            gamma.copy_from_slice(&proto.gamma);
        } else if !proto.gamma.is_empty() {
            crate::log(&format!("[PROTO WARNING] Invalid gamma length: {}", proto.gamma.len()));
        }

        let mut c = [0u8; 32];
        if proto.c.len() == 32 {
            c.copy_from_slice(&proto.c);
        } else if !proto.c.is_empty() {
            crate::log(&format!("[PROTO WARNING] Invalid c length: {}", proto.c.len()));
        }

        let mut s = [0u8; 32];
        if proto.s.len() == 32 {
            s.copy_from_slice(&proto.s);
        } else if !proto.s.is_empty() {
            crate::log(&format!("[PROTO WARNING] Invalid s length: {}", proto.s.len()));
        }

        let mut output = [0u8; 32];
        if proto.output.len() == 32 {
            output.copy_from_slice(&proto.output);
        } else if !proto.output.is_empty() {
            crate::log(&format!("[PROTO WARNING] Invalid output length: {}", proto.output.len()));
        }

        VrfProof { gamma, c, s, output }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use crate::mimblewimble;

    #[test]
    fn test_vrf_roundtrip() {
        let secret_key = mimblewimble::generate_secret_key();
        let public_key = &secret_key * &*RISTRETTO_BASEPOINT_TABLE;
        let input = b"test input";
        
        let proof = create_vrf(&secret_key, input);
        let is_valid = verify_vrf(&public_key, input, &proof);
        
        assert!(is_valid, "VRF proof should be valid");
    }

    #[test]
    fn test_vrf_wrong_key_fails() {
        let secret_key1 = mimblewimble::generate_secret_key();
        let secret_key2 = mimblewimble::generate_secret_key();
        let public_key2 = &secret_key2 * &*RISTRETTO_BASEPOINT_TABLE;
        let input = b"test input";
        
        let proof = create_vrf(&secret_key1, input);
        let is_valid = verify_vrf(&public_key2, input, &proof);
        
        assert!(!is_valid, "VRF proof should fail with wrong key");
    }
}
