use std::{fmt, io};
use std::sync::mpsc;

// Error handling types
pub type PluribitResult<T> = Result<T, PluribitError>;

#[derive(Debug)]
pub enum PluribitError {
    IoError(io::Error),
    SerializationError(String),
    DeserializationError(String),
    HashError(String),
    VdfError(String),
    NetworkError(String),
    NotSupported(String),
    ValidationError(String),
    ResourceExhaustedError(String),
    ThreadError(String),
    StateError(String),
    LockError(String),
    InvalidInput(String),
    ComputationError(String),
    InvalidBlock(String), 
        InvalidOutputCommitment,
         InsufficientFunds(String),
    InvalidInputCommitment,
    InvalidRangeProof,
    InvalidKernelExcess,
    InvalidKernelSignature,
    Imbalance,
    UnknownInput,
    DoubleVote(String),
    InsufficientStake,
    InvalidVote(String),
}

impl fmt::Display for PluribitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PluribitError::IoError(e) => write!(f, "I/O error: {}", e),
            PluribitError::SerializationError(s) => write!(f, "Serialization error: {}", s),
            PluribitError::DeserializationError(s) => write!(f, "Deserialization error: {}", s),
            PluribitError::HashError(s) => write!(f, "Hash error: {}", s),
            PluribitError::VdfError(s) => write!(f, "VDF error: {}", s),
            PluribitError::ValidationError(s) => write!(f, "Validation error: {}", s),
            PluribitError::ResourceExhaustedError(s) => write!(f, "Resource exhausted: {}", s),
            PluribitError::ThreadError(s) => write!(f, "Thread error: {}", s),
            PluribitError::StateError(s) => write!(f, "State error: {}", s),
            PluribitError::LockError(s) => write!(f, "Lock error: {}", s),
            PluribitError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            PluribitError::ComputationError(msg) => write!(f, "Computation error: {}", msg),
            PluribitError::InvalidBlock(msg) => write!(f, "Invalid block: {}", msg),  
            PluribitError::InvalidOutputCommitment => write!(f, "Invalid output commitment"),
            PluribitError::InvalidInputCommitment => write!(f, "Invalid input commitment"),
            PluribitError::InvalidRangeProof => write!(f, "Invalid range proof"),
            PluribitError::InvalidKernelExcess => write!(f, "Invalid kernel excess"),
            PluribitError::InvalidKernelSignature => write!(f, "Invalid kernel signature"),
            PluribitError::Imbalance => write!(f, "Transaction does not balance"),
            PluribitError::UnknownInput => write!(f, "Unknown input UTXO"),
            PluribitError::DoubleVote(msg) => write!(f, "Double vote detected: {}", msg),
            PluribitError::InsufficientStake => write!(f, "Insufficient stake for operation"),
            PluribitError::InvalidVote(msg) => write!(f, "Invalid vote: {}", msg),
            PluribitError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            PluribitError::NotSupported(msg) => write!(f, "Not supported: {}", msg),
            PluribitError::InsufficientFunds(msg) => write!(f, "Insufficient funds: {}", msg),

        }
    }
}

impl From<io::Error> for PluribitError {
    fn from(error: io::Error) -> Self {
        PluribitError::IoError(error)
    }
}

impl<T> From<std::sync::PoisonError<T>> for PluribitError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        PluribitError::LockError(error.to_string())
    }
}

impl From<mpsc::SendError<u64>> for PluribitError {
    fn from(error: mpsc::SendError<u64>) -> Self {
        PluribitError::ThreadError(format!("Channel send error: {}", error))
    }
}

impl From<mpsc::RecvError> for PluribitError {
    fn from(error: mpsc::RecvError) -> Self {
        PluribitError::ThreadError(format!("Channel receive error: {}", error))
    }
}

