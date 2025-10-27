// src/stealth.rs
// Wallet-layer stealth subaddress primitives for Pluriƀit
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use crate::log;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha256, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit}, // Replace NewAead with KeyInit
    XChaCha20Poly1305, Key, XNonce
};
use rand_core::{OsRng, RngCore}; // RngCore is needed for the fill_bytes method

/// Hash-to-scalar function: H_s(label || data) -> Scalar
pub fn hash_to_scalar(label: &[u8], data: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(data);
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order(hash.into())
}

/// Derives the 1-byte view tag from the shared secret scalar 's'.
/// H("view_tag" || s.to_bytes())[0]
pub fn derive_view_tag(shared_secret: &Scalar) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(b"pluribit_view_tag_v1"); // Domain separator for view tag
    hasher.update(shared_secret.to_bytes());
    hasher.finalize()[0] // Take the first byte as the tag
}

/// Derive a stealth subaddress public key D_i = Hs("SubAddr"||Ps||i)*G + Pv
pub fn derive_subaddress(scan_pub: &RistrettoPoint, spend_pub: &RistrettoPoint, index: u32) -> RistrettoPoint {
    // Compress scan_pub to bytes
    let ps_bytes = scan_pub.compress().to_bytes();
    // i as big-endian
    let idx_bytes = index.to_be_bytes();
    // Compute Hs
    let tweak = hash_to_scalar(b"SubAddr", &[&ps_bytes[..], &idx_bytes[..]].concat());
    
    // CORRECTED: D_i = tweak*G + Pv
    // Use the RISTRETTO_BASEPOINT_TABLE for multiplication by G
    let tweak_g = &tweak * &*RISTRETTO_BASEPOINT_TABLE;
    tweak_g + spend_pub
}

/// Encrypt a stealth output: returns (R, ciphertext)
/// - r: ephemeral secret scalar
/// - scan_pub: recipient's public scan key
/// - value: u64 amount
/// - blinding: blinding factor scalar
pub fn encrypt_stealth_out(
    r: &Scalar,
    scan_pub: &RistrettoPoint,
    value: u64,
    blinding: &Scalar,
) -> (RistrettoPoint, Vec<u8>, u8) {
    // CORRECTED: R = r*G
    let r_point = r * &*RISTRETTO_BASEPOINT_TABLE;

    // Shared secret S = Hs(r * Ps)
    let rps = (scan_pub * r).compress().to_bytes();
    let s = hash_to_scalar(b"Stealth", &rps);

    // Derive the view tag from the shared secret 's'
    let view_tag = derive_view_tag(&s);

    // Derive symmetric key from shared secret
    let key = Key::from_slice(s.as_bytes());
    let cipher = XChaCha20Poly1305::new(key);

    // Random nonce
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Serialize plaintext: 8 bytes value || 32 bytes blinding
    let mut pt = Vec::with_capacity(40);
    pt.extend_from_slice(&value.to_be_bytes());
    pt.extend_from_slice(blinding.as_bytes());

    // Encrypt
    let ct = cipher.encrypt(nonce, pt.as_ref())
        .expect("encryption failure");

    // Output: nonce || ciphertext
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);

    (r_point, out, view_tag)
}

/// Try to decrypt a stealth output. Returns Some((value, blinding)) on success.
#[allow(non_snake_case)]
pub fn decrypt_stealth_output(
    scan_priv: &Scalar,
    R: &RistrettoPoint,
    data: &[u8],
) -> Option<(u64, Scalar)> {
    // --- ADD LOGGING ---
    let r_hex = hex::encode(R.compress().to_bytes());
    log(&format!("[DECRYPT] Entered. R={}, data_len={}", &r_hex[..8], data.len()));
    // --- END LOGGING ---

    if data.len() < 24 {
        // --- ADD LOGGING ---
        log("[DECRYPT] Failed: Data length < 24.");
        // --- END LOGGING ---
        return None;
    }
    let (nonce_bytes, ct) = data.split_at(24);

    // Compute shared secret S' = Hs("Stealth" || scan_priv * R)
    let apr = (R * scan_priv).compress().to_bytes();
    let s = hash_to_scalar(b"Stealth", &apr);
    // --- ADD LOGGING ---
    log(&format!("[DECRYPT] Calculated shared secret s': {}", hex::encode(s.to_bytes())));
    // --- END LOGGING ---

    // Derive key
    let key = Key::from_slice(s.as_bytes());
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce_bytes);

    // Decrypt
    // --- ADD LOGGING ---
    log("[DECRYPT] Attempting cipher.decrypt...");
    // --- END LOGGING ---
    let pt = match cipher.decrypt(nonce, ct) {
        Ok(plaintext) => {
            // --- ADD LOGGING ---
            log(&format!("[DECRYPT] Decryption successful. Plaintext len={}", plaintext.len()));
            // --- END LOGGING ---
            plaintext
        },
        Err(e) => {
            // --- ADD LOGGING ---
            log(&format!("[DECRYPT] Decryption FAILED: {}", e));
            // --- END LOGGING ---
            return None;
        }
    };

    if pt.len() != 40 {
        // --- ADD LOGGING ---
        log(&format!("[DECRYPT] Failed: Plaintext length != 40 (was {}).", pt.len()));
        // --- END LOGGING ---
        return None;
    }

    // Parse
    let mut amt_bytes = [0u8; 8];
    amt_bytes.copy_from_slice(&pt[..8]);
    let value = u64::from_be_bytes(amt_bytes);

    let mut blind_bytes = [0u8; 32];
    blind_bytes.copy_from_slice(&pt[8..40]);

    // --- ADD LOGGING ---
    log(&format!("[DECRYPT] Parsed value: {}", value));
    log(&format!("[DECRYPT] Parsed blinding bytes: {}", hex::encode(blind_bytes)));
    log("[DECRYPT] Checking if blinding bytes are canonical scalar...");
    // --- END LOGGING ---

    // Use canonical scalar representation only
    let blinding = if let Some(scalar) = Scalar::from_canonical_bytes(blind_bytes).into() {
        // --- ADD LOGGING ---
        log("[DECRYPT] Blinding bytes ARE canonical.");
        // --- END LOGGING ---
        scalar
    } else {
        // --- ADD LOGGING ---
        log("[DECRYPT] Blinding bytes ARE NOT canonical. Decryption fails.");
        // --- END LOGGING ---
        return None;
    };

    // Verification that the reconstructed commitment matches the on-chain one
    // must be performed by the calling function.
    // --- ADD LOGGING ---
    log("[DECRYPT] Returning Some((value, blinding)).");
    // --- END LOGGING ---
    Some((value, blinding))
}
#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;
    
    #[test]
    fn test_hash_to_scalar() {
        let label = b"test_label";
        let data = b"test_data";
        
        let scalar1 = hash_to_scalar(label, data);
        let scalar2 = hash_to_scalar(label, data);
        
        // Should be deterministic
        assert_eq!(scalar1, scalar2);
        
        // Different inputs should give different outputs
        let scalar3 = hash_to_scalar(b"different", data);
        assert_ne!(scalar1, scalar3);
    }
    
    #[test]
    fn test_derive_subaddress() {
        let scan_priv = Scalar::random(&mut OsRng);
        let spend_priv = Scalar::random(&mut OsRng);
        let scan_pub = &scan_priv * &*RISTRETTO_BASEPOINT_TABLE;
        let spend_pub = &spend_priv * &*RISTRETTO_BASEPOINT_TABLE;
        
        // Derive subaddresses
        let sub1 = derive_subaddress(&scan_pub, &spend_pub, 0);
        let sub2 = derive_subaddress(&scan_pub, &spend_pub, 1);
        let sub3 = derive_subaddress(&scan_pub, &spend_pub, 0);
        
        // Different indices should give different addresses
        assert_ne!(sub1, sub2);
        
        // Same index should give same address
        assert_eq!(sub1, sub3);
        
        // Should not equal the original spend pub
        assert_ne!(sub1, spend_pub);
    }
    
    #[test]
    fn test_stealth_encryption_decryption() {
        let scan_priv = Scalar::random(&mut OsRng);
        let scan_pub = &scan_priv * &*RISTRETTO_BASEPOINT_TABLE;
        
        let value = 123456u64;
        let blinding = Scalar::random(&mut OsRng);
        let r = Scalar::random(&mut OsRng);
        
        // Encrypt
        let (ephemeral_key, ciphertext, _view_tag) = encrypt_stealth_out(&r, &scan_pub, value, &blinding);
        
        // Decrypt
        let result = decrypt_stealth_output(&scan_priv, &ephemeral_key, &ciphertext);
        
        assert!(result.is_some());
        let (decrypted_value, decrypted_blinding) = result.unwrap();
        assert_eq!(decrypted_value, value);
        assert_eq!(decrypted_blinding, blinding);
    }
    
    #[test]
    fn test_stealth_decryption_wrong_key() {
        let scan_priv1 = Scalar::random(&mut OsRng);
        let scan_pub1 = &scan_priv1 * &*RISTRETTO_BASEPOINT_TABLE;
        let scan_priv2 = Scalar::random(&mut OsRng);
        
        let value = 100u64;
        let blinding = Scalar::random(&mut OsRng);
        let r = Scalar::random(&mut OsRng);
        
        // Encrypt with pub1
        let (ephemeral_key, ciphertext, _view_tag) = encrypt_stealth_out(&r, &scan_pub1, value, &blinding);
        
        // Try to decrypt with priv2 (wrong key)
        let result = decrypt_stealth_output(&scan_priv2, &ephemeral_key, &ciphertext);
        
        // Should fail or give wrong values
        if let Some((dec_val, _dec_blind)) = result {
            assert_ne!(dec_val, value);
            // The probability of accidentally getting the right value is negligible
        }
    }
    
    #[test]
    fn test_stealth_ciphertext_tampering() {
        let scan_priv = Scalar::random(&mut OsRng);
        let scan_pub = &scan_priv * &*RISTRETTO_BASEPOINT_TABLE;
        
        let value = 1000u64;
        let blinding = Scalar::random(&mut OsRng);
        let r = Scalar::random(&mut OsRng);
        
        // Encrypt
        let (ephemeral_key, mut ciphertext, _view_tag) = encrypt_stealth_out(&r, &scan_pub, value, &blinding);

        // Tamper with ciphertext
        if ciphertext.len() > 30 {
            ciphertext[30] ^= 0xFF;
        }
        
        // Decryption should fail due to AEAD
        let result = decrypt_stealth_output(&scan_priv, &ephemeral_key, &ciphertext);
        assert!(result.is_none());
    }
    
    #[test]
    fn test_stealth_nonce_uniqueness() {
        let scan_pub = &Scalar::random(&mut OsRng) * &*RISTRETTO_BASEPOINT_TABLE;
        let value = 100u64;
        let blinding = Scalar::random(&mut OsRng);
        
        // Create multiple encryptions
        let mut nonces = Vec::new();
        for _ in 0..10 {
            let r = Scalar::random(&mut OsRng);
            let (_, ciphertext, _view_tag) = encrypt_stealth_out(&r, &scan_pub, value, &blinding);

            
            // Extract nonce (first 24 bytes)
            let nonce = &ciphertext[..24];
            nonces.push(nonce.to_vec());
        }
        
        // All nonces should be unique
        let unique_count = nonces.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, nonces.len());
    }
}
