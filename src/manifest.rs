//! Serializable manifest format for stored file digests.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hasher::{Blake3Digest, HashAlgorithm};

/// Supported manifest schema versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ManifestVersion(u32);

impl ManifestVersion {
    pub const CURRENT: Self = Self(1);

    pub const fn new(version: u32) -> Self {
        Self(version)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// UTC timestamp stored as an ISO 8601 string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ManifestTimestamp(String);

impl ManifestTimestamp {
    pub fn new(timestamp: String) -> Self {
        Self(timestamp)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Metadata and hash for a single file relative to the scan root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
    pub hash: Blake3Digest,
}

impl FileRecord {
    pub fn new(
        path: impl AsRef<Path>,
        size: u64,
        hash: Blake3Digest,
    ) -> Result<Self, ManifestError> {
        let path = path.as_ref().to_string_lossy().into_owned();

        if path.is_empty() {
            return Err(ManifestError::InvalidFileRecord {
                reason: "path must not be empty",
            });
        }

        Ok(Self { path, size, hash })
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Versioned collection of file records produced by a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: ManifestVersion,
    pub algorithm: HashAlgorithm,
    pub timestamp: ManifestTimestamp,
    pub records: Vec<FileRecord>,
}

impl Manifest {
    pub fn new(
        version: ManifestVersion,
        algorithm: HashAlgorithm,
        timestamp: ManifestTimestamp,
        records: Vec<FileRecord>,
    ) -> Result<Self, ManifestError> {
        if version.get() == 0 {
            return Err(ManifestError::UnsupportedVersion { version: 0 });
        }

        if version > ManifestVersion::CURRENT {
            return Err(ManifestError::VersionTooNew {
                found: version.get(),
                supported: ManifestVersion::CURRENT.get(),
            });
        }

        if algorithm != HashAlgorithm::Blake3 {
            return Err(ManifestError::UnsupportedAlgorithm { algorithm });
        }

        validate_unique_paths(&records)?;

        Ok(Self {
            version,
            algorithm,
            timestamp,
            records,
        })
    }
}

fn validate_unique_paths(records: &[FileRecord]) -> Result<(), ManifestError> {
    let mut seen = HashSet::with_capacity(records.len());

    for record in records {
        if !seen.insert(record.path.as_str()) {
            return Err(ManifestError::DuplicatePath {
                path: record.path.clone(),
            });
        }
    }

    Ok(())
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("unsupported manifest version: {version}")]
    UnsupportedVersion { version: u32 },

    #[error("manifest version {found} is newer than supported maximum {supported}")]
    VersionTooNew { found: u32, supported: u32 },

    #[error("unsupported hash algorithm: {algorithm:?}")]
    UnsupportedAlgorithm { algorithm: HashAlgorithm },

    #[error("invalid file record: {reason}")]
    InvalidFileRecord { reason: &'static str },

    #[error("duplicate path in manifest: {path}")]
    DuplicatePath { path: String },
}
