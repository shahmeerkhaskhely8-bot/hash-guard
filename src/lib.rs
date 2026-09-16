#![forbid(unsafe_code)]

pub mod cli;
pub mod comparator;
pub mod error;
pub mod hasher;
pub mod manifest;
pub mod scanner;
pub mod storage;

pub use comparator::{Change, ChangeKind, Comparator, ComparisonError, ComparisonReport};
pub use error::{HashGuardError, Result};
pub use hasher::{Blake3Digest, HashAlgorithm, HashError, HashOutput, Hasher};
pub use manifest::{FileRecord, Manifest, ManifestError, ManifestTimestamp, ManifestVersion};
pub use scanner::{ScanError, Scanner};
pub use storage::{Storage, StorageError};
