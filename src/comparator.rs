//! Domain types and logic for comparing manifests and describing changes.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hasher::HashAlgorithm;
use crate::manifest::{FileRecord, Manifest};

/// Classification of a difference between an expected and actual file set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

/// A single detected change with the records needed to inspect it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Change {
    Added {
        record: FileRecord,
    },
    Modified {
        expected: FileRecord,
        actual: FileRecord,
    },
    Deleted {
        record: FileRecord,
    },
}

impl Change {
    pub fn kind(&self) -> ChangeKind {
        match self {
            Self::Added { .. } => ChangeKind::Added,
            Self::Modified { .. } => ChangeKind::Modified,
            Self::Deleted { .. } => ChangeKind::Deleted,
        }
    }

    pub fn path(&self) -> &str {
        match self {
            Self::Added { record } => record.path(),
            Self::Modified { expected, .. } => expected.path(),
            Self::Deleted { record } => record.path(),
        }
    }
}

/// Aggregated result of comparing two manifests.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ComparisonReport {
    pub changes: Vec<Change>,
}

impl ComparisonReport {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum ComparisonError {
    #[error("cannot compare manifests using different algorithms: expected {expected:?}, actual {actual:?}")]
    AlgorithmMismatch {
        expected: HashAlgorithm,
        actual: HashAlgorithm,
    },

    #[error("cannot compare manifests using different schema versions: expected {expected}, actual {actual}")]
    VersionMismatch { expected: u32, actual: u32 },
}

/// Detects differences between expected and actual file digests.
#[derive(Debug, Default)]
pub struct Comparator;

impl Comparator {
    /// Compares two manifests after validating compatible version and algorithm.
    pub fn compare(
        baseline: &Manifest,
        current: &Manifest,
    ) -> Result<ComparisonReport, ComparisonError> {
        if baseline.algorithm != current.algorithm {
            return Err(ComparisonError::AlgorithmMismatch {
                expected: baseline.algorithm,
                actual: current.algorithm,
            });
        }

        if baseline.version != current.version {
            return Err(ComparisonError::VersionMismatch {
                expected: baseline.version.get(),
                actual: current.version.get(),
            });
        }

        Ok(Self::compare_records(&baseline.records, &current.records))
    }

    /// Compares baseline records against newly scanned records by relative path.
    pub fn compare_records(
        baseline: &[FileRecord],
        current: &[FileRecord],
    ) -> ComparisonReport {
        let baseline_by_path = index_records_by_path(baseline);
        let current_by_path = index_records_by_path(current);

        let mut changes = Vec::new();

        for (path, expected) in baseline_by_path.iter() {
            match current_by_path.get(path) {
                None => changes.push(Change::Deleted {
                    record: (*expected).clone(),
                }),
                Some(actual) if expected.hash != actual.hash => {
                    changes.push(Change::Modified {
                        expected: (*expected).clone(),
                        actual: (*actual).clone(),
                    });
                }
                Some(_) => {}
            }
        }

        for (path, actual) in current_by_path.iter() {
            if !baseline_by_path.contains_key(path) {
                changes.push(Change::Added {
                    record: (*actual).clone(),
                });
            }
        }

        sort_changes(&mut changes);
        ComparisonReport { changes }
    }
}

fn index_records_by_path<'a>(
    records: &'a [FileRecord],
) -> HashMap<&'a str, &'a FileRecord> {
    let mut indexed = HashMap::with_capacity(records.len());

    for record in records {
        indexed.insert(record.path.as_str(), record);
    }

    indexed
}

fn sort_changes(changes: &mut [Change]) {
    changes.sort_by(|left, right| left.path().cmp(right.path()));
}

#[cfg(test)]
mod tests {
    use crate::hasher::Blake3Digest;
    use crate::manifest::{Manifest, ManifestTimestamp, ManifestVersion};

    use super::*;

    fn digest_from_byte(value: u8) -> Blake3Digest {
        Blake3Digest::new(blake3::hash(&[value]).to_hex().to_string())
            .expect("blake3 hex output is always valid")
    }

    fn record(path: &str, size: u64, hash_seed: u8) -> FileRecord {
        FileRecord::new(path, size, digest_from_byte(hash_seed)).expect("valid test record")
    }

    fn sample_manifest(records: Vec<FileRecord>) -> Manifest {
        Manifest::new(
            ManifestVersion::CURRENT,
            HashAlgorithm::Blake3,
            ManifestTimestamp::new("2026-09-16T00:00:00Z".to_string()),
            records,
        )
        .expect("valid test manifest")
    }

    fn change_kinds(report: &ComparisonReport) -> Vec<ChangeKind> {
        report.changes.iter().map(Change::kind).collect()
    }

    fn change_paths(report: &ComparisonReport) -> Vec<&str> {
        report.changes.iter().map(Change::path).collect()
    }

    #[test]
    fn identical_records_produce_no_changes() {
        let baseline = vec![
            record("alpha.txt", 1, 1),
            record("nested/beta.txt", 2, 2),
        ];

        let report = Comparator::compare_records(&baseline, &baseline);

        assert!(report.is_empty());
    }

    #[test]
    fn detects_added_files() {
        let baseline = vec![record("existing.txt", 1, 1)];
        let current = vec![
            record("existing.txt", 1, 1),
            record("new.txt", 2, 2),
        ];

        let report = Comparator::compare_records(&baseline, &current);

        assert_eq!(change_kinds(&report), vec![ChangeKind::Added]);
        assert_eq!(change_paths(&report), vec!["new.txt"]);
    }

    #[test]
    fn detects_deleted_files() {
        let baseline = vec![
            record("keep.txt", 1, 1),
            record("remove.txt", 2, 2),
        ];
        let current = vec![record("keep.txt", 1, 1)];

        let report = Comparator::compare_records(&baseline, &current);

        assert_eq!(change_kinds(&report), vec![ChangeKind::Deleted]);
        assert_eq!(change_paths(&report), vec!["remove.txt"]);
    }

    #[test]
    fn detects_modified_files_by_hash() {
        let baseline = vec![record("tracked.txt", 10, 10)];
        let current = vec![record("tracked.txt", 10, 11)];

        let report = Comparator::compare_records(&baseline, &current);

        assert_eq!(change_kinds(&report), vec![ChangeKind::Modified]);
        assert_eq!(change_paths(&report), vec!["tracked.txt"]);

        let Change::Modified { expected, actual } = &report.changes[0] else {
            panic!("expected modified change");
        };
        assert_eq!(expected.hash, digest_from_byte(10));
        assert_eq!(actual.hash, digest_from_byte(11));
    }

    #[test]
    fn unchanged_hash_with_different_size_is_not_modified() {
        let baseline = vec![record("same-hash.txt", 10, 5)];
        let current = vec![record("same-hash.txt", 20, 5)];

        let report = Comparator::compare_records(&baseline, &current);

        assert!(report.is_empty());
    }

    #[test]
    fn detects_mixed_changes_and_sorts_by_path() {
        let baseline = vec![
            record("deleted.txt", 1, 1),
            record("modified.txt", 2, 2),
            record("stable.txt", 3, 3),
        ];
        let current = vec![
            record("added.txt", 4, 4),
            record("modified.txt", 2, 9),
            record("stable.txt", 3, 3),
        ];

        let report = Comparator::compare_records(&baseline, &current);

        assert_eq!(
            change_paths(&report),
            vec!["added.txt", "deleted.txt", "modified.txt"]
        );
        assert_eq!(
            change_kinds(&report),
            vec![
                ChangeKind::Added,
                ChangeKind::Deleted,
                ChangeKind::Modified,
            ]
        );
    }

    #[test]
    fn compare_manifests_returns_report_for_compatible_manifests() {
        let baseline = sample_manifest(vec![record("file.txt", 1, 1)]);
        let current = sample_manifest(vec![
            record("file.txt", 1, 1),
            record("new.txt", 2, 2),
        ]);

        let report = Comparator::compare(&baseline, &current).expect("compatible manifests");

        assert_eq!(change_kinds(&report), vec![ChangeKind::Added]);
    }

    #[test]
    fn empty_baselines_and_currents_produce_no_changes() {
        let report = Comparator::compare_records(&[], &[]);
        assert!(report.is_empty());
    }

    #[test]
    fn compare_manifests_rejects_version_mismatch() {
        let baseline = sample_manifest(vec![record("file.txt", 1, 1)]);
        let mut current = sample_manifest(vec![record("file.txt", 1, 1)]);
        current.version = ManifestVersion::new(2);

        let result = Comparator::compare(&baseline, &current);

        assert!(matches!(
            result,
            Err(ComparisonError::VersionMismatch {
                expected: 1,
                actual: 2,
            })
        ));
    }
}
