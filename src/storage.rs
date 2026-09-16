//! Manifest persistence (read/write).

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::manifest::{Manifest, ManifestError};

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("failed to read manifest from {}", path.display())]
    ReadManifest {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write manifest to {}", path.display())]
    WriteManifest {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse manifest JSON from {}", path.display())]
    ParseJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to serialize manifest JSON to {}", path.display())]
    SerializeJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("manifest validation failed for {}", path.display())]
    InvalidManifest {
        path: PathBuf,
        #[source]
        source: ManifestError,
    },
}

/// Loads and saves manifest files from disk.
#[derive(Debug, Default)]
pub struct Storage;

impl Storage {
    /// Reads and validates a manifest from a JSON file.
    pub fn read_manifest(path: &Path) -> Result<Manifest, StorageError> {
        let file = File::open(path).map_err(|source| StorageError::ReadManifest {
            path: path.to_path_buf(),
            source,
        })?;
        let reader = BufReader::new(file);
        let manifest = serde_json::from_reader(reader).map_err(|source| StorageError::ParseJson {
            path: path.to_path_buf(),
            source,
        })?;

        Self::validate_manifest(path, manifest)
    }

    /// Validates and writes a manifest as pretty-printed JSON.
    pub fn write_manifest(path: &Path, manifest: &Manifest) -> Result<(), StorageError> {
        Self::validate_manifest(path, manifest.clone())?;

        let file = File::create(path).map_err(|source| StorageError::WriteManifest {
            path: path.to_path_buf(),
            source,
        })?;
        let mut writer = BufWriter::new(file);

        serde_json::to_writer_pretty(&mut writer, manifest).map_err(|source| {
            StorageError::SerializeJson {
                path: path.to_path_buf(),
                source,
            }
        })?;

        writer.write_all(b"\n").map_err(|source| StorageError::WriteManifest {
            path: path.to_path_buf(),
            source,
        })?;

        writer.flush().map_err(|source| StorageError::WriteManifest {
            path: path.to_path_buf(),
            source,
        })?;

        Ok(())
    }

    fn validate_manifest(path: &Path, manifest: Manifest) -> Result<Manifest, StorageError> {
        Manifest::new(
            manifest.version,
            manifest.algorithm,
            manifest.timestamp,
            manifest.records,
        )
        .map_err(|source| StorageError::InvalidManifest {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::hasher::{Blake3Digest, HashAlgorithm};
    use crate::manifest::{
        FileRecord, Manifest, ManifestError, ManifestTimestamp, ManifestVersion,
    };

    use super::*;

    fn temp_manifest_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "hash-guard-storage-{name}-{}",
            std::process::id()
        ))
    }

    fn sample_digest() -> Blake3Digest {
        Blake3Digest::new(blake3::hash(b"hello").to_hex().to_string())
            .expect("blake3 hex output is always valid")
    }

    fn sample_manifest() -> Result<Manifest, ManifestError> {
        let record = FileRecord::new("docs/readme.txt", 5, sample_digest())?;
        Manifest::new(
            ManifestVersion::CURRENT,
            HashAlgorithm::Blake3,
            ManifestTimestamp::new("2026-09-16T00:00:00Z".to_string()),
            vec![record],
        )
    }

    #[test]
    fn round_trip_preserves_manifest() -> Result<(), StorageError> {
        let path = temp_manifest_path("round-trip");
        let _ = fs::remove_file(&path);

        let manifest = sample_manifest().map_err(|source| StorageError::InvalidManifest {
            path: path.clone(),
            source,
        })?;

        Storage::write_manifest(&path, &manifest)?;
        let loaded = Storage::read_manifest(&path)?;

        assert_eq!(loaded, manifest);

        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn written_json_is_pretty_printed() -> Result<(), StorageError> {
        let path = temp_manifest_path("pretty");
        let _ = fs::remove_file(&path);

        let manifest = sample_manifest().map_err(|source| StorageError::InvalidManifest {
            path: path.clone(),
            source,
        })?;
        Storage::write_manifest(&path, &manifest)?;

        let contents = fs::read_to_string(&path).map_err(|source| StorageError::ReadManifest {
            path: path.clone(),
            source,
        })?;

        assert!(contents.contains('\n'));
        assert!(contents.contains("  \"version\""));

        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn malformed_json_is_rejected() {
        let path = temp_manifest_path("malformed");
        let _ = fs::remove_file(&path);
        fs::write(&path, "{ not valid json").expect("test setup write");

        let result = Storage::read_manifest(&path);
        assert!(matches!(result, Err(StorageError::ParseJson { .. })));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let path = temp_manifest_path("bad-version");
        let _ = fs::remove_file(&path);
        fs::write(
            &path,
            r#"{
  "version": 0,
  "algorithm": "blake3",
  "timestamp": "2026-09-16T00:00:00Z",
  "records": []
}"#,
        )
        .expect("test setup write");

        let result = Storage::read_manifest(&path);
        assert!(matches!(
            result,
            Err(StorageError::InvalidManifest {
                source: ManifestError::UnsupportedVersion { version: 0 },
                ..
            })
        ));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let path = temp_manifest_path("bad-algorithm");
        let _ = fs::remove_file(&path);
        fs::write(
            &path,
            r#"{
  "version": 1,
  "algorithm": "sha256",
  "timestamp": "2026-09-16T00:00:00Z",
  "records": []
}"#,
        )
        .expect("test setup write");

        let result = Storage::read_manifest(&path);
        assert!(matches!(result, Err(StorageError::ParseJson { .. })));

        let _ = fs::remove_file(path);
    }
}
