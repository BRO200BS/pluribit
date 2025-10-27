use crate::constants::*;
use crate::error::{PluribitError, PluribitResult};
use crate::utils::calculate_power_safely;
use crate::constants::{VDF_RSA_MODULUS_BITS, VDF_SECURITY_PARAM};
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::thread_rng;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant, SystemTime};
use serde::{Serialize, Deserialize};
use crate::wasm_types::WasmU64;
use crate::p2p;

// VDF proof for efficient verification using Wesolowski's construction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VDFProof {
    pub y: Vec<u8>,     // Result y = x^(2^t) mod N
    pub pi: Vec<u8>,    // Proof π = x^q mod N
    pub l: Vec<u8>,     // Prime l (serialized as bytes)
    pub r: Vec<u8>,     // Remainder r = 2^t mod l (serialized as bytes)
    pub iterations: WasmU64,
}

// A single tick from the VDF clock
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct VDFClockTick {
    pub output_y: Vec<u8>,      // VDF output
    pub proof: VDFProof,        // VDF proof
    pub sequence_number: WasmU64,   // Increasing sequence number
    pub prev_output_hash: String, // Hash of previous output
    #[serde(skip)]
    pub timestamp: Instant,     // Wall clock time
  //  #[serde(with = "crate::merkle::timestamp_serde")]//
    pub system_time: SystemTime, // System time
    pub iterations: WasmU64,        // Store difficulty used for this tick
}

impl Default for VDFClockTick {
    fn default() -> Self {
        Self {
            output_y: Vec::new(),
            proof: VDFProof {
                y: Vec::new(),
                pi: Vec::new(),
                l: Vec::new(),
                r: Vec::new(),
                iterations: WasmU64::from(0),
            },
            sequence_number: WasmU64::from(0),
            prev_output_hash: String::new(),
            timestamp: Instant::now(),
            system_time: SystemTime::now(),
            iterations: WasmU64::from(INITIAL_VDF_ITERATIONS), // Initialize with default
        }
    }
}

/// VDF using sequential squaring with RSA modulus.
/// Uses a standardized RSA-2048 modulus with no known factorization.
pub struct VDF {
    modulus: BigUint,
    security_param: u32,
}

impl VDF {
    
    pub fn new_with_default_modulus() -> Result<Self, crate::error::PluribitError> {
        let bytes = hex::decode(VDF_RSA_MODULUS_HEX)
            .map_err(|_| crate::error::PluribitError::InvalidBlock("Bad VDF modulus hex".into()))?;
        if bytes.is_empty() { return Err(crate::error::PluribitError::InvalidBlock("Empty VDF modulus".into())); }

        // fingerprint check 
        let calc = hex::encode(Sha256::digest(&bytes));
        if !VDF_RSA_MODULUS_SHA256_HEX.is_empty() && calc != VDF_RSA_MODULUS_SHA256_HEX {
            return Err(crate::error::PluribitError::InvalidBlock("VDF modulus SHA-256 mismatch".into()));
        }

        let n = BigUint::from_bytes_be(&bytes);
        if n.bits() != VDF_RSA_MODULUS_BITS {
            return Err(crate::error::PluribitError::InvalidBlock("VDF modulus bitlen mismatch".into()));
        }
        if (&n & BigUint::from(1u8)).is_zero() {
            return Err(crate::error::PluribitError::InvalidBlock("VDF modulus must be odd".into()));
        }

        Ok(Self { modulus: n, security_param: VDF_SECURITY_PARAM })
    }
    
    // Generate a prime number of the specified bit length
    pub fn generate_prime(bit_length: usize) -> PluribitResult<BigUint> {
        if bit_length < 16 || bit_length > 4096 {
            return Err(PluribitError::ValidationError(format!(
                "Invalid bit length for prime generation: {}", bit_length
            )));
        }

        let mut rng = thread_rng();
        let mut attempts = 0;
        let max_attempts = 1000;  // Prevent infinite loops

        while attempts < max_attempts {
            // Generate a random odd number of the required bit length
            let mut candidate = rng.gen_biguint(bit_length as u64);

            // Ensure the number is odd (all primes except 2 are odd)
            if candidate.is_even() {
                candidate += BigUint::one();
            }

            // Ensure the number has the correct bit length
            if candidate.bits() != bit_length as u64 {
                attempts += 1;
                continue;
            }

            // Check primality using the Miller-Rabin test
            if is_prime(&candidate, 40) { // Increased rounds for stronger primality testing
                return Ok(candidate);
            }
            
            attempts += 1;
        }
        
        Err(PluribitError::VdfError(format!(
            "Failed to generate prime after {} attempts", max_attempts
        )))
    }

    // Generate a small prime for the Wesolowski proof
    pub fn generate_proof_prime() -> PluribitResult<BigUint> {
        // Generate a ~128-bit prime for l as recommended by Wesolowski
        Self::generate_prime(128)
    }

    // Compute the VDF with Wesolowski proof: x^(2^t) mod N
    pub fn compute_with_proof(&self, input: &[u8], iterations: WasmU64) -> PluribitResult<VDFProof> {
        if *iterations > MAX_VDF_ITERATIONS {
            return Err(PluribitError::ValidationError(format!(
                "Iterations {} exceeds maximum allowed {}", *iterations, MAX_VDF_ITERATIONS
            )));
        }
    
        // Hash the input to get our starting value
        let mut hasher = Sha256::new();
        hasher.update(input);
        let hash = hasher.finalize();
        let x = BigUint::from_bytes_be(&hash);

        // Get a reference to the modulus
        let modulus = &self.modulus;

        // Generate proof prime l
        let l = match Self::generate_proof_prime() {
            Ok(prime) => prime,
            Err(e) => return Err(e)
        };

        // Calculate r = 2^t mod l
        let r = BigUint::from(2u32).modpow(&BigUint::from(*iterations), &l);
        
        // Calculate y = x^(2^t) mod N (iterative squaring)
        let mut y = x.clone();
        for _ in 0..*iterations {
            y = (&y * &y) % modulus;
        }

        // First, calculate 2^t mod l
        let two_t_mod_l = BigUint::from(2u32).modpow(&BigUint::from(iterations), &l);
        
        // For large t, calculate q = floor((2^t - (2^t mod l)) / l) carefully
        let power = match calculate_power_safely(*iterations) {
            Ok(p) => p,
            Err(e) => return Err(PluribitError::VdfError(e))
        };
        
        let q_times_l = power - two_t_mod_l;
        let q = &q_times_l / &l;

        // Calculate proof π = x^q mod N
        let pi = x.modpow(&q, modulus);

        Ok(VDFProof {
            y: y.to_bytes_be(),
            pi: pi.to_bytes_be(),
            l: l.to_bytes_be(),
            r: r.to_bytes_be(),
            iterations,
        })
    }

    // Verify a VDF output using Wesolowski's efficient verification
    pub fn verify(&self, input: &[u8], proof: &VDFProof) -> PluribitResult<bool> {
        // Hash the input to get our starting value x
        let mut hasher = Sha256::new();
        hasher.update(input);
        let hash = hasher.finalize();
        let x = BigUint::from_bytes_be(&hash);

        // Get a reference to the modulus
        let modulus = &self.modulus;

        // Parse y and π from the proof
        let y = BigUint::from_bytes_be(&proof.y);
        let pi = BigUint::from_bytes_be(&proof.pi);
        let l = BigUint::from_bytes_be(&proof.l);
        let r = BigUint::from_bytes_be(&proof.r);
        
        // Verify l is a reasonable prime to prevent attacks
        if l.bits() < 120 || !is_prime(&l, 20) {
            return Err(PluribitError::VdfError("Invalid proof prime l".to_string()));
        }

        // Verify: y == pi^l * x^r mod N
        let pi_l = pi.modpow(&l, modulus);
        let x_r = x.modpow(&r, modulus);
        let right_side = (pi_l * x_r) % modulus;

        Ok(y == right_side)
    }

    // Convert desired delay time to iteration count
    pub fn time_to_iterations(&self, time: Duration) -> u64 {
        // Calculate iterations based on calibration
        let seconds = time.as_secs_f64();
        let iterations_per_second = 10_000_000.0; // Calibrated iterations per second
        
        // Calculate with minimum threshold
        let iterations = (seconds * iterations_per_second) as u64;
        iterations.max(MIN_VDF_ITERATIONS).min(MAX_VDF_ITERATIONS)
    }

    // Get the modulus as bytes for serialization
    pub fn get_modulus_bytes(&self) -> Vec<u8> {
        self.modulus.to_bytes_be()
    }

    // Recreate VDF from serialized modulus
    pub fn from_modulus_bytes(bytes: &[u8]) -> PluribitResult<Self> {
        if bytes.is_empty() {
            return Err(PluribitError::ValidationError("Empty modulus bytes".into()));
        }
        let n = BigUint::from_bytes_be(bytes);
        if n.bits() != VDF_RSA_MODULUS_BITS {
            return Err(PluribitError::ValidationError("Bad modulus size".into()));
        }
        if (&n & BigUint::from(1u8)).is_zero() {
            return Err(PluribitError::ValidationError("Modulus must be odd".into()));
        }
        Ok(VDF {
            modulus: n,
            security_param: VDF_SECURITY_PARAM,
        })
   }
   
    /// Back-compat shim for older call-sites using `VDF::new(2048)`.
    pub fn new(_bits: usize) -> PluribitResult<Self> {
        Self::new_with_default_modulus()
    }
   
}

/// **Protobuf Conversion: Internal -> p2p**
impl From<VDFProof> for p2p::VdfProof {
    fn from(proof: VDFProof) -> Self {
        p2p::VdfProof {
            y: proof.y,
            pi: proof.pi,
            l: proof.l,
            r: proof.r,
            iterations: *proof.iterations,
        }
    }
}

/// **Protobuf Conversion: p2p -> Internal**
impl From<p2p::VdfProof> for VDFProof {
    fn from(proto: p2p::VdfProof) -> Self {
        VDFProof {
            y: proto.y,
            pi: proto.pi,
            l: proto.l,
            r: proto.r,
            iterations: WasmU64::from(proto.iterations),
        }
    }
}


// Miller-Rabin primality test
pub fn is_prime(n: &BigUint, k: usize) -> bool {
    if n <= &BigUint::one() {
        return false;
    }

    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
        return true;
    }

    if n.is_even() {
        return false;
    }

    // Write n-1 as 2^r * d where d is odd
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let n_minus_1 = n - &one;

    let mut r = 0;
    let mut d = n_minus_1.clone();

    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    // Witness loop
    let mut rng = thread_rng();

    'witness: for _ in 0..k {
        // Choose random a in the range [2, n-2]
        let a = rng.gen_biguint_range(&two, &(n_minus_1.clone() - &one));

        // Compute a^d mod n
        let mut x = a.modpow(&d, n);

        if x == one || x == n_minus_1 {
            continue 'witness;
        }

        for _ in 0..r-1 {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }

        return false;
    }

    true
}


impl Default for VDFProof {
    fn default() -> Self {
        VDFProof {
            y: vec![],
            pi: vec![],
            l: vec![],
            r: vec![],
            iterations: WasmU64::from(0),
        }
    }
}

// Helper function to compute VDF proof
pub fn compute_vdf_proof(input: &[u8], iterations: u64, modulus: &BigUint) -> Result<VDFProof, String> {
    if iterations > MAX_VDF_ITERATIONS {
        return Err(format!("Iterations {} exceeds maximum allowed {}", 
                       iterations, MAX_VDF_ITERATIONS));
    }

    // Hash the input to get our starting value
    let mut hasher = Sha256::new();
    hasher.update(input);
    let hash = hasher.finalize();
    let x = BigUint::from_bytes_be(&hash);
    
    // Generate a suitable prime l for Wesolowski's proof
    let l = match VDF::generate_prime(128) {
        Ok(p) => p,
        Err(_) => return Err("Failed to generate prime for proof".to_string())
    };
    
    // Calculate r = 2^t mod l
    let r = BigUint::from(2u32).modpow(&BigUint::from(iterations), &l);
    
    // Calculate y = x^(2^t) mod N (iterative squaring)
    let mut y = x.clone();
    
    // Use chunked squaring for large iteration counts to prevent stack overflows
    let chunk_size = 1000;
    let full_chunks = iterations / chunk_size;
    let remainder = iterations % chunk_size;
    
    for _ in 0..full_chunks {
        for _ in 0..chunk_size {
            y = (&y * &y) % modulus;
        }
    }
    
    for _ in 0..remainder {
        y = (&y * &y) % modulus;
    }
    
    // Calculate q = (2^t - r) / l safely
    let power = match calculate_power_safely(iterations) {
        Ok(p) => p,
        Err(e) => return Err(e)
    };
    
    let q_times_l = power - r.clone();
    let q = &q_times_l / &l;
    
    // Calculate proof π = x^q mod N
    let pi = x.modpow(&q, modulus);
    
    Ok(VDFProof {
        y: y.to_bytes_be(),
        pi: pi.to_bytes_be(),
        l: l.to_bytes_be(),
        r: r.to_bytes_be(),
        iterations: WasmU64::from(iterations),
    })
}



#[cfg(test)]
mod tests {
    use super::*;

    // New Test for VDF Proof and Verification
    #[test]
    fn test_vdf_roundtrip() {
        let vdf = VDF::new(2048).unwrap();
        let input = b"hello world";
        let iterations = 100; // Use a small number for a fast test

        // 1. Compute the VDF proof
        let proof = vdf.compute_with_proof(input, WasmU64::from(iterations)).unwrap();

        assert!(!proof.y.is_empty());
        assert!(!proof.pi.is_empty());

        // 2. Verify the proof
        let is_valid = vdf.verify(input, &proof).unwrap();
        assert!(is_valid, "VDF proof should be valid"); // Verification checks if y == pi^l * x^r mod N 
    }

    // New Test for Invalid VDF Proof
    #[test]
    fn test_vdf_fails_on_bad_proof() {
        let vdf = VDF::new(2048).unwrap();
        let input = b"hello world";
        let iterations = 100;

        let mut proof = vdf.compute_with_proof(input, WasmU64::from(iterations)).unwrap();
        
        // Tamper with the proof
        proof.y[0] = proof.y[0].wrapping_add(1);

        let is_valid = vdf.verify(input, &proof).unwrap();
        assert!(!is_valid, "VDF proof should be invalid after tampering");
    }
}
