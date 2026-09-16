use thiserror::Error;

use crate::comparator::ComparisonError;
use crate::hasher::HashError;
use crate::manifest::ManifestError;
use crate::scanner::ScanError;
use crate::storage::StorageError;

#[derive(Debug, Error)]
pub enum HashGuardError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Manifest(#[from] ManifestError),

    #[error(transparent)]
    Comparison(#[from] ComparisonError),

    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error(transparent)]
    Hash(#[from] HashError),

    #[error(transparent)]
    Scan(#[from] ScanError),
}

pub type Result<T> = std::result::Result<T, HashGuardError>;
