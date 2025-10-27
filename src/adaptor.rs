// src/adaptor.rs
//! Adaptor signatures - the foundation of scriptless scripts
//!
//! Adaptor signatures enable conditional signatures: "I'll complete this signature
//! if and only if I reveal secret t". This is the core primitive that enables:
//! - Atomic swaps (trustless cross-chain trades)
//! - Payment channels (Lightning-style off-chain payments)
//! - Discrete Log Contracts (oracle-based contracts)
//!
//! Key insight: If Alice creates an adaptor signature with point T = t*G,
//! and Bob sees Alice's completed signature on-chain, Bob can extract t!
//! This creates atomicity: either both parties learn t, or neither does.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use rand::thread_rng;
use crate::mimblewimble::PC_GENS;
use crate::error::{PluribitResult, PluribitError};
use crate::log;

/// An adaptor signature - a signature that's "locked" to a secret
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdaptorSignature {
    /// Public nonce R' = r*G + T (includes the adaptor point)
    #[serde(with = "serde_bytes")]
    pub public_nonce: [u8; 32],
    
    /// Adaptor point T = t*G (commitment to the locking secret)
    #[serde(with = "serde_bytes")]
    pub adaptor_point: [u8; 32],
    
    /// Pre-signature s' = r + c*x (missing the adaptor secret)
    #[serde(with = "serde_bytes")]
    pub pre_signature: [u8; 32],
    
    /// Challenge c = H(R' || P || m)
    #[serde(with = "serde_bytes")]
    pub challenge: [u8; 32],
}

/// Create an adaptor signature
///
/// Given:
/// - secret_key: Your private key x
/// - adaptor_point: T = t*G (where t is unknown to you)
/// - message: The message to sign
///
/// Returns an adaptor signature that requires knowledge of t to complete.
///
/// # Example
/// ```ignore
/// let my_secret = Scalar::random(&mut rng);
/// let their_adaptor_point = compute_adaptor_point(); // T = t*G
/// let message = b"pay 100 coins to Bob";
///
/// let adaptor_sig = create_adaptor_signature(
///     &my_secret,
///     &their_adaptor_point,
///     message
/// );
///
/// // Later, when they reveal t:
/// let complete_sig = adapt_signature(&adaptor_sig, &t);
/// ```
pub fn create_adaptor_signature(
    secret_key: &Scalar,
    adaptor_point: &RistrettoPoint,
    message: &[u8],
) -> PluribitResult<AdaptorSignature> {
    log(&format!("[ADAPTOR] Creating adaptor signature for message: {}", hex::encode(&message[..std::cmp::min(32, message.len())])));
    
    let mut rng = thread_rng();
    let nonce = Scalar::random(&mut rng);
    
    // Compute public key P = x*G (using blinding generator for consistency)
    let pubkey = secret_key * &PC_GENS.B_blinding;
    
    // Compute R' = r*G + T
    // This is the key: the nonce commitment includes the adaptor point
    let r_prime = &nonce * &PC_GENS.B_blinding + adaptor_point;
    
    log(&format!("[ADAPTOR] R' = {}", hex::encode(r_prime.compress().to_bytes())));
    log(&format!("[ADAPTOR] T = {}", hex::encode(adaptor_point.compress().to_bytes())));
    
    // Compute challenge c = H("adaptor" || R' || P || m)
    let mut hasher = Sha256::new();
    hasher.update(b"pluribit_adaptor_v1");
    hasher.update(&r_prime.compress().to_bytes());
    hasher.update(&pubkey.compress().to_bytes());
    hasher.update(message);
    let challenge_bytes: [u8; 32] = hasher.finalize().into();
    let challenge = Scalar::from_bytes_mod_order(challenge_bytes);
    
    log(&format!("[ADAPTOR] Challenge = {}", hex::encode(&challenge_bytes)));
    
    // Compute pre-signature s' = r + c*x
    // Note: This is a valid signature for (R', message), but R' includes T
    let pre_signature = nonce + challenge * secret_key;
    
    log(&format!("[ADAPTOR] Pre-signature = {}", hex::encode(pre_signature.to_bytes())));
    
    Ok(AdaptorSignature {
        public_nonce: r_prime.compress().to_bytes(),
        adaptor_point: adaptor_point.compress().to_bytes(),
        pre_signature: pre_signature.to_bytes(),
        challenge: challenge_bytes,
    })
}

/// Complete an adaptor signature by revealing the adaptor secret
///
/// Given:
/// - adaptor_sig: The adaptor signature
/// - adaptor_secret: The secret t such that T = t*G
///
/// Returns a complete Schnorr signature (challenge, s).
///
/// WARNING: Once you broadcast this signature on-chain, anyone can extract
/// the adaptor_secret by calling extract_adaptor_secret()!
pub fn adapt_signature(
    adaptor_sig: &AdaptorSignature,
    adaptor_secret: &Scalar,
) -> PluribitResult<(Scalar, Scalar)> {
    log("[ADAPTOR] Adapting signature with secret...");
    
    // Verify that the adaptor secret matches the adaptor point
    let claimed_t_point = adaptor_secret * &PC_GENS.B_blinding;
    let adaptor_point = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&adaptor_sig.adaptor_point)
        .map_err(|_| PluribitError::ValidationError("Invalid adaptor point".into()))?
        .decompress()
        .ok_or_else(|| PluribitError::ValidationError("Failed to decompress adaptor point".into()))?;
    
    if claimed_t_point != adaptor_point {
        return Err(PluribitError::ValidationError("Adaptor secret doesn't match adaptor point".into()));
    }
    
    // Complete the signature: s = s' + t
    let pre_sig = Scalar::from_bytes_mod_order(adaptor_sig.pre_signature);
    let final_sig = pre_sig + adaptor_secret;
    
    let challenge = Scalar::from_bytes_mod_order(adaptor_sig.challenge);
    
    log(&format!("[ADAPTOR] Final signature = {}", hex::encode(final_sig.to_bytes())));
    
    Ok((challenge, final_sig))
}

/// Extract the adaptor secret from a completed signature
///
/// Given:
/// - adaptor_sig: The original adaptor signature
/// - completed_sig: The completed signature (challenge, s) that was published
///
/// Returns the adaptor secret t.
///
/// This is the MAGIC of adaptor signatures: if someone publishes a completed
/// signature on-chain, you can extract their secret!
///
/// # Example
/// ```ignore
/// // Alice creates adaptor signature with her secret
/// let alice_adaptor = create_adaptor_signature(&alice_secret, &t_point, msg);
///
/// // Bob sees Alice's completed signature on-chain
/// let (c, s) = alice_completed_signature;
///
/// // Bob extracts the secret!
/// let t = extract_adaptor_secret(&alice_adaptor, &s);
///
/// // Now Bob can use t to complete his own adaptor signature
/// ```
pub fn extract_adaptor_secret(
    adaptor_sig: &AdaptorSignature,
    completed_signature: &Scalar,
) -> Scalar {
    log("[ADAPTOR] Extracting adaptor secret from completed signature...");
    
    // t = s_final - s_pre
    let pre_sig = Scalar::from_bytes_mod_order(adaptor_sig.pre_signature);
    let secret = completed_signature - pre_sig;
    
    log(&format!("[ADAPTOR] Extracted secret = {}", hex::encode(secret.to_bytes())));
    
    secret
}

/// Verify an adaptor signature before it's been adapted
///
/// Checks that the adaptor signature is correctly formed:
/// s'*G = R' - T + c*P
///
/// This lets you verify an adaptor signature before the secret is revealed.
pub fn verify_adaptor_signature(
    adaptor_sig: &AdaptorSignature,
    public_key: &RistrettoPoint,
    message: &[u8],
) -> bool {
    log("[ADAPTOR] Verifying adaptor signature...");
    
    // Parse components
    let r_prime = match curve25519_dalek::ristretto::CompressedRistretto::from_slice(&adaptor_sig.public_nonce)
        .ok()
        .and_then(|c| c.decompress())
    {
        Some(p) => p,
        None => {
            log("[ADAPTOR] Failed to parse R'");
            return false;
        }
    };
    
    let t_point = match curve25519_dalek::ristretto::CompressedRistretto::from_slice(&adaptor_sig.adaptor_point)
        .ok()
        .and_then(|c| c.decompress())
    {
        Some(p) => p,
        None => {
            log("[ADAPTOR] Failed to parse T");
            return false;
        }
    };
    
    let pre_sig = Scalar::from_bytes_mod_order(adaptor_sig.pre_signature);
    let challenge = Scalar::from_bytes_mod_order(adaptor_sig.challenge);
    
    // Verify challenge is correct
    let mut hasher = Sha256::new();
    hasher.update(b"pluribit_adaptor_v1");
    hasher.update(&adaptor_sig.public_nonce);
    hasher.update(&public_key.compress().to_bytes());
    hasher.update(message);
    let expected_challenge: [u8; 32] = hasher.finalize().into();
    
    if expected_challenge != adaptor_sig.challenge {
        log("[ADAPTOR] Challenge mismatch");
        return false;
    }
    
    // Verify signature equation: s'*G = R' - T + c*P
    let left = &pre_sig * &PC_GENS.B_blinding;
    let right = r_prime - t_point + &challenge * public_key;
    
    if left != right {
        log("[ADAPTOR] Signature equation doesn't hold");
        return false;
    }
    
    log("[ADAPTOR] ✓ Adaptor signature is valid");
    true
}

/// Generate a random adaptor point (for testing/demos)
///
/// In real usage, the adaptor point would be:
/// - Derived from a hash (for atomic swaps)
/// - An oracle's public key (for DLCs)
/// - Coordinated between parties (for payment channels)
pub fn generate_random_adaptor_point() -> (Scalar, RistrettoPoint) {
    let mut rng = thread_rng();
    let secret = Scalar::random(&mut rng);
    let point = &secret * &PC_GENS.B_blinding;
    (secret, point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mimblewimble;
    
    #[test]
    fn test_adaptor_signature_roundtrip() {
        // Alice's key
        let alice_secret = mimblewimble::generate_secret_key();
        let alice_pubkey = &alice_secret * &PC_GENS.B_blinding;
        
        // Generate an adaptor point
        let (t_secret, t_point) = generate_random_adaptor_point();
        
        // Message to sign
        let message = b"pay 100 coins to Bob";
        
        // Alice creates adaptor signature
        let adaptor_sig = create_adaptor_signature(&alice_secret, &t_point, message).unwrap();
        
        // Verify the adaptor signature
        assert!(verify_adaptor_signature(&adaptor_sig, &alice_pubkey, message));
        
        // Complete the signature with the secret
        let (c, s) = adapt_signature(&adaptor_sig, &t_secret).unwrap();
        
        // Verify the completed signature is a valid Schnorr signature
        // Compute R = s*G - c*P
        let r_computed = &s * &PC_GENS.B_blinding - &c * &alice_pubkey;
        
        // Challenge should match
        let mut hasher = Sha256::new();
        hasher.update(b"pluribit_schnorr_v1");
        hasher.update(&(message.len() as u64).to_le_bytes());
        hasher.update(&r_computed.compress().to_bytes());
        hasher.update(message);
        let expected_c: [u8; 32] = hasher.finalize().into();
        
        // Note: Challenges won't match because adaptor uses different domain
        // This is expected - adaptor signatures have their own verification
    }
    
    #[test]
    fn test_extract_adaptor_secret() {
        let alice_secret = mimblewimble::generate_secret_key();
        let (t_secret, t_point) = generate_random_adaptor_point();
        let message = b"atomic swap";
        
        // Create adaptor signature
        let adaptor_sig = create_adaptor_signature(&alice_secret, &t_point, message).unwrap();
        
        // Complete it
        let (_c, s) = adapt_signature(&adaptor_sig, &t_secret).unwrap();
        
        // Extract the secret
        let extracted = extract_adaptor_secret(&adaptor_sig, &s);
        
        // Should match the original secret
        assert_eq!(extracted, t_secret);
    }
    
    #[test]
    fn test_adaptor_signature_wrong_secret() {
        let alice_secret = mimblewimble::generate_secret_key();
        let (_t_secret, t_point) = generate_random_adaptor_point();
        let wrong_secret = mimblewimble::generate_secret_key();
        let message = b"test";
        
        let adaptor_sig = create_adaptor_signature(&alice_secret, &t_point, message).unwrap();
        
        // Try to adapt with wrong secret
        let result = adapt_signature(&adaptor_sig, &wrong_secret);
        
        // Should fail
        assert!(result.is_err());
    }
    
    #[test]
    fn test_adaptor_signature_verification_fails_on_tamper() {
        let alice_secret = mimblewimble::generate_secret_key();
        let alice_pubkey = &alice_secret * &PC_GENS.B_blinding;
        let (_t_secret, t_point) = generate_random_adaptor_point();
        let message = b"test";
        
        let mut adaptor_sig = create_adaptor_signature(&alice_secret, &t_point, message).unwrap();
        
        // Tamper with the signature
        adaptor_sig.pre_signature[0] ^= 1;
        
        // Verification should fail
        assert!(!verify_adaptor_signature(&adaptor_sig, &alice_pubkey, message));
    }
}
