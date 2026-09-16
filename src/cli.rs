use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use crate::comparator::{Change, ChangeKind, Comparator, ComparisonReport};
use crate::hasher::HashAlgorithm;
use crate::manifest::{FileRecord, Manifest, ManifestTimestamp, ManifestVersion};
use crate::scanner::Scanner;
use crate::storage::Storage;
use crate::{HashGuardError, Result};

/// Exit code returned when verification detects changes.
pub const VERIFY_CHANGES_EXIT_CODE: i32 = 2;

#[derive(Debug, Parser)]
#[command(name = "hash-guard", version, about = "File integrity verification with BLAKE3")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan a directory and write a new baseline manifest
    Init {
        /// Directory to scan
        path: PathBuf,

        /// Manifest output path
        #[arg(short, long, default_value = "hash-guard.manifest.json")]
        output: PathBuf,
    },

    /// Verify a directory against an existing baseline manifest
    Verify {
        /// Baseline manifest file
        manifest: PathBuf,

        /// Directory to rescan
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

/// Runs the parsed CLI command and returns a process exit code.
pub fn run() -> Result<i32> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path, output } => run_init(&path, &output),
        Commands::Verify { manifest, path } => run_verify(&manifest, &path),
    }
}

fn run_init(path: &std::path::Path, output: &std::path::Path) -> Result<i32> {
    let records = Scanner::scan(path)?;
    let manifest = Manifest::new(
        ManifestVersion::CURRENT,
        HashAlgorithm::default_algorithm(),
        current_timestamp()?,
        records,
    )?;

    Storage::write_manifest(output, &manifest)?;

    println!("Initialized baseline manifest");
    println!("  manifest:  {}", output.display());
    println!("  root:      {}", path.display());
    println!("  files:     {}", manifest.records.len());
    println!("  algorithm: {:?}", manifest.algorithm);
    println!("  timestamp: {}", manifest.timestamp.as_str());

    Ok(0)
}

fn run_verify(manifest_path: &Path, path: &Path) -> Result<i32> {
    let root = absolutize_path(path)?;
    let manifest_path = absolutize_path(manifest_path)?;

    let baseline = Storage::read_manifest(&manifest_path)?;
    let mut current_records = Scanner::scan(&root)?;
    exclude_manifest_from_records(&root, &manifest_path, &mut current_records);
    let current = Manifest::new(
        baseline.version,
        baseline.algorithm,
        current_timestamp()?,
        current_records,
    )?;

    let report = Comparator::compare(&baseline, &current)?;

    if report.is_empty() {
        println!("Verification passed");
        println!("  manifest: {}", manifest_path.display());
        println!("  root:     {}", root.display());
        println!("  files:    {}", baseline.records.len());
        return Ok(0);
    }

    print_verification_report(&manifest_path, &root, &report);
    Ok(VERIFY_CHANGES_EXIT_CODE)
}

fn print_verification_report(
    manifest_path: &std::path::Path,
    root: &std::path::Path,
    report: &ComparisonReport,
) {
    let counts = change_counts(report);

    println!("Verification failed");
    println!("  manifest: {}", manifest_path.display());
    println!("  root:     {}", root.display());
    println!("  changes:  {}", report.changes.len());
    println!(
        "  summary:  {} added, {} modified, {} deleted",
        counts.added, counts.modified, counts.deleted
    );
    println!();
    println!("Changes:");

    for change in &report.changes {
        print_change(change);
    }
}

fn print_change(change: &Change) {
    match change {
        Change::Added { record } => {
            println!(
                "  [added]    {}  size={}  hash={}",
                record.path(),
                record.size,
                record.hash.as_str()
            );
        }
        Change::Deleted { record } => {
            println!(
                "  [deleted]  {}  size={}  hash={}",
                record.path(),
                record.size,
                record.hash.as_str()
            );
        }
        Change::Modified { expected, actual } => {
            println!("  [modified] {}", expected.path());
            println!(
                "               expected  size={}  hash={}",
                expected.size,
                expected.hash.as_str()
            );
            println!(
                "               actual    size={}  hash={}",
                actual.size,
                actual.hash.as_str()
            );
        }
    }
}

struct ChangeCounts {
    added: usize,
    modified: usize,
    deleted: usize,
}

fn change_counts(report: &ComparisonReport) -> ChangeCounts {
    let mut counts = ChangeCounts {
        added: 0,
        modified: 0,
        deleted: 0,
    };

    for change in &report.changes {
        match change.kind() {
            ChangeKind::Added => counts.added += 1,
            ChangeKind::Modified => counts.modified += 1,
            ChangeKind::Deleted => counts.deleted += 1,
        }
    }

    counts
}

fn absolutize_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        let current_dir = std::env::current_dir().map_err(HashGuardError::from)?;
        Ok(current_dir.join(path))
    }
}

fn exclude_manifest_from_records(
    root: &Path,
    manifest_path: &Path,
    records: &mut Vec<FileRecord>,
) {
    let Some(manifest_relative) = relative_path_if_under_root(root, manifest_path) else {
        return;
    };

    records.retain(|record| record.path() != manifest_relative);
}

fn relative_path_if_under_root(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
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
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }

    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn current_timestamp() -> Result<ManifestTimestamp> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            HashGuardError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "system clock predates the Unix epoch",
            ))
        })?
        .as_secs();

    Ok(ManifestTimestamp::new(format_utc_timestamp(seconds)))
}

fn format_utc_timestamp(unix_secs: u64) -> String {
    let days = unix_secs / 86_400;
    let time_of_day = unix_secs % 86_400;
    let hours = time_of_day / 3_600;
    let minutes = (time_of_day % 3_600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = civil_from_days(days as i64);

    let mut timestamp = String::with_capacity(20);
    let _ = write!(
        timestamp,
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z"
    );
    timestamp
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe as i32 + (era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }

    (year, month, day)
}
