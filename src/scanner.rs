//! Filesystem traversal for discovering files to hash.

use std::fs;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use crate::hasher::{HashError, Hasher};
use crate::manifest::{FileRecord, ManifestError};

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("invalid scan root {}: {reason}", path.display())]
    InvalidRoot { path: PathBuf, reason: &'static str },

    #[error("filesystem error during {operation} on {}", path.display())]
    Io {
        path: PathBuf,
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to hash {}", path.display())]
    Hash {
        path: PathBuf,
        #[source]
        source: HashError,
    },

    #[error("failed to build record for {}", path.display())]
    Record {
        path: PathBuf,
        #[source]
        source: ManifestError,
    },

    #[error("path {} is outside scan root {}", path.display(), root.display())]
    PathOutsideRoot { root: PathBuf, path: PathBuf },

    #[error("could not derive a valid relative path for {}", path.display())]
    InvalidRelativePath { path: PathBuf },
}

/// Walks directories and collects file paths for processing.
#[derive(Debug, Default)]
pub struct Scanner;

impl Scanner {
    /// Recursively scans `root`, hashes regular files, and returns sorted records.
    pub fn scan(root: &Path) -> Result<Vec<FileRecord>, ScanError> {
        let root = Self::resolve_root(root)?;
        let mut records = Vec::new();
        Self::scan_directory(&root, &root, &mut records)?;
        records.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(records)
    }

    fn resolve_root(root: &Path) -> Result<PathBuf, ScanError> {
        if root.as_os_str().is_empty() {
            return Err(ScanError::InvalidRoot {
                path: root.to_path_buf(),
                reason: "path must not be empty",
            });
        }

        let metadata = fs::symlink_metadata(root).map_err(|source| ScanError::Io {
            path: root.to_path_buf(),
            operation: "stat root",
            source,
        })?;

        if metadata.file_type().is_symlink() {
            return Err(ScanError::InvalidRoot {
                path: root.to_path_buf(),
                reason: "root must not be a symlink",
            });
        }

        if !metadata.is_dir() {
            return Err(ScanError::InvalidRoot {
                path: root.to_path_buf(),
                reason: "root must be a directory",
            });
        }

        if root.is_absolute() {
            Ok(root.to_path_buf())
        } else {
            let current_dir = std::env::current_dir().map_err(|source| ScanError::Io {
                path: root.to_path_buf(),
                operation: "resolve current directory",
                source,
            })?;
            Ok(current_dir.join(root))
        }
    }

    fn scan_directory(
        root: &Path,
        current: &Path,
        records: &mut Vec<FileRecord>,
    ) -> Result<(), ScanError> {
        for entry in fs::read_dir(current).map_err(|source| ScanError::Io {
            path: current.to_path_buf(),
            operation: "read directory",
            source,
        })? {
            let entry = entry.map_err(|source| ScanError::Io {
                path: current.to_path_buf(),
                operation: "read directory entry",
                source,
            })?;
            let path = entry.path();

            let metadata = fs::symlink_metadata(&path).map_err(|source| ScanError::Io {
                path: path.clone(),
                operation: "stat entry",
                source,
            })?;
            let file_type = metadata.file_type();

            if file_type.is_symlink() {
                continue;
            }

            if file_type.is_file() {
                let relative_path = relative_path_string(root, &path)?;
                let hash_output = Hasher::hash_file(&path).map_err(|source| ScanError::Hash {
                    path: path.clone(),
                    source,
                })?;
                let record = FileRecord::new(relative_path, hash_output.bytes_read, hash_output.digest)
                    .map_err(|source| ScanError::Record {
                        path,
                        source,
                    })?;
                records.push(record);
            } else if file_type.is_dir() {
                Self::scan_directory(root, &path, records)?;
            }
        }

        Ok(())
    }
}

fn relative_path_string(root: &Path, path: &Path) -> Result<String, ScanError> {
    let relative = path.strip_prefix(root).map_err(|_| ScanError::PathOutsideRoot {
        root: root.to_path_buf(),
        path: path.to_path_buf(),
    })?;

    let mut normalized = String::new();
    let mut needs_separator = false;

    for component in relative.components() {
        match component {
            Component::Normal(name) => {
                if needs_separator {
                    normalized.push('/');
                }
                normalized.push_str(&name.to_string_lossy());
                needs_separator = true;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ScanError::InvalidRelativePath {
                    path: path.to_path_buf(),
                });
            }
        }
    }

    if normalized.is_empty() {
        return Err(ScanError::InvalidRelativePath {
            path: path.to_path_buf(),
        });
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn temp_scan_dir(name: &str) -> Result<PathBuf, ScanError> {
        let dir = std::env::temp_dir().join(format!(
            "hash-guard-scanner-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).map_err(|source| ScanError::Io {
            path: dir.clone(),
            operation: "create test directory",
            source,
        })?;
        Ok(dir)
    }

    fn write_file(path: &Path, contents: &[u8]) -> Result<(), ScanError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| ScanError::Io {
                path: parent.to_path_buf(),
                operation: "create parent directory",
                source,
            })?;
        }

        fs::write(path, contents).map_err(|source| ScanError::Io {
            path: path.to_path_buf(),
            operation: "write test file",
            source,
        })
    }

    #[test]
    fn scan_empty_directory_returns_no_records() -> Result<(), ScanError> {
        let root = temp_scan_dir("empty")?;
        let records = Scanner::scan(&root)?;
        assert!(records.is_empty());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn scan_collects_nested_regular_files_with_relative_paths() -> Result<(), ScanError> {
        let root = temp_scan_dir("nested")?;
        write_file(&root.join("alpha.txt"), b"alpha")?;
        write_file(&root.join("nested/beta.txt"), b"beta")?;

        let records = Scanner::scan(&root)?;

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].path(), "alpha.txt");
        assert_eq!(records[1].path(), "nested/beta.txt");
        assert_eq!(records[0].size, 5);
        assert_eq!(
            records[0].hash.as_str(),
            blake3::hash(b"alpha").to_hex().to_string().as_str()
        );

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn scan_sorts_records_by_relative_path() -> Result<(), ScanError> {
        let root = temp_scan_dir("sorted")?;
        write_file(&root.join("z-last.txt"), b"z")?;
        write_file(&root.join("a-first.txt"), b"a")?;
        write_file(&root.join("middle/m.txt"), b"m")?;

        let records = Scanner::scan(&root)?;
        let paths: Vec<&str> = records.iter().map(FileRecord::path).collect();

        assert_eq!(paths, vec!["a-first.txt", "middle/m.txt", "z-last.txt"]);

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn scan_rejects_missing_root() {
        let missing = std::env::temp_dir().join(format!(
            "hash-guard-scanner-missing-{}",
            std::process::id()
        ));
        let result = Scanner::scan(&missing);
        assert!(matches!(result, Err(ScanError::Io { .. })));
    }

    #[test]
    fn scan_rejects_file_root() -> Result<(), ScanError> {
        let root = temp_scan_dir("file-root")?;
        let file_path = root.join("not-a-dir.txt");
        write_file(&file_path, b"root")?;

        let result = Scanner::scan(&file_path);
        assert!(matches!(
            result,
            Err(ScanError::InvalidRoot {
                reason: "root must be a directory",
                ..
            })
        ));

        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn scan_skips_symlinks() -> Result<(), ScanError> {
        use std::os::unix::fs::symlink;

        let root = temp_scan_dir("symlinks")?;
        write_file(&root.join("real.txt"), b"real")?;
        symlink(root.join("real.txt"), root.join("linked.txt"))?;
        symlink(root.join("nested-target"), root.join("nested-link"))?;
        fs::create_dir_all(root.join("nested-target"))?;
        write_file(&root.join("nested-target/inside.txt"), b"inside")?;

        let records = Scanner::scan(&root)?;
        let paths: Vec<&str> = records.iter().map(FileRecord::path).collect();

        assert_eq!(paths, vec!["real.txt"]);

        let _ = fs::remove_dir_all(root);
        Ok(())
    }
}
