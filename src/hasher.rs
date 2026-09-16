//! Hash algorithm identifiers, digest types, and streaming BLAKE3 computation.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default read buffer size for streaming file hashes (8 KiB).
pub const DEFAULT_BUFFER_SIZE: usize = 8192;

/// Supported cryptographic hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Blake3,
}

impl HashAlgorithm {
    pub const fn default_algorithm() -> Self {
        Self::Blake3
    }
}

/// Hex-encoded BLAKE3 digest (64 characters).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Blake3Digest(String);

impl Blake3Digest {
    const EXPECTED_LEN: usize = 64;

    pub fn new(digest: String) -> Result<Self, HashError> {
        if digest.len() != Self::EXPECTED_LEN {
            return Err(HashError::InvalidDigestLength {
                expected: Self::EXPECTED_LEN,
                found: digest.len(),
            });
        }

        if !digest.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HashError::InvalidDigestEncoding);
        }

        Ok(Self(digest))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Output of a completed streaming hash operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashOutput {
    pub digest: Blake3Digest,
    pub bytes_read: u64,
}

#[derive(Debug, Error)]
pub enum HashError {
    #[error("I/O error while hashing")]
    Io(#[from] std::io::Error),

    #[error("invalid BLAKE3 digest length: expected {expected}, found {found}")]
    InvalidDigestLength { expected: usize, found: usize },

    #[error("invalid BLAKE3 digest encoding: expected lowercase hex")]
    InvalidDigestEncoding,

    #[error("read buffer size must be greater than zero")]
    InvalidBufferSize,

    #[error("total bytes read exceeds u64::MAX")]
    SizeOverflow,
}

/// Computes cryptographic digests using the BLAKE3 algorithm.
#[derive(Debug, Default)]
pub struct Hasher;

impl Hasher {
    /// Opens `path` and streams its contents through BLAKE3.
    pub fn hash_file(path: &Path) -> Result<HashOutput, HashError> {
        let file = File::open(path)?;
        Self::hash_reader(file)
    }

    /// Streams all bytes from `reader` through BLAKE3 using the default buffer size.
    pub fn hash_reader<R: Read>(reader: R) -> Result<HashOutput, HashError> {
        let mut buffer = [0u8; DEFAULT_BUFFER_SIZE];
        Self::hash_read_loop(reader, &mut buffer)
    }

    /// Streams all bytes from `reader` through BLAKE3 using a caller-selected buffer size.
    pub fn hash_reader_with_buffer<R: Read>(
        reader: R,
        buffer_size: usize,
    ) -> Result<HashOutput, HashError> {
        if buffer_size == 0 {
            return Err(HashError::InvalidBufferSize);
        }

        let mut buffer = vec![0u8; buffer_size];
        Self::hash_read_loop(reader, &mut buffer)
    }

    fn hash_read_loop<R: Read>(
        mut reader: R,
        buffer: &mut [u8],
    ) -> Result<HashOutput, HashError> {
        let mut hasher = blake3::Hasher::new();
        let mut bytes_read = 0_u64;

        loop {
            let chunk_len = reader.read(buffer)?;
            if chunk_len == 0 {
                break;
            }

            hasher.update(&buffer[..chunk_len]);
            bytes_read = bytes_read
                .checked_add(u64::try_from(chunk_len).map_err(|_| HashError::SizeOverflow)?)
                .ok_or(HashError::SizeOverflow)?;
        }

        let digest = Blake3Digest::new(hasher.finalize().to_hex().to_string())?;
        Ok(HashOutput {
            digest,
            bytes_read,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn expected_blake3_hex(data: &[u8]) -> String {
        blake3::hash(data).to_hex().to_string()
    }

    #[test]
    fn empty_input_yields_zero_bytes_and_known_digest() -> Result<(), HashError> {
        let output = Hasher::hash_reader(Cursor::new([]))?;

        assert_eq!(output.bytes_read, 0);
        assert_eq!(
            output.digest.as_str(),
            expected_blake3_hex(&[]).as_str()
        );

        Ok(())
    }

    #[test]
    fn small_input_fits_in_one_read() -> Result<(), HashError> {
        let data = b"hash-guard small file";
        let output = Hasher::hash_reader(Cursor::new(data.as_slice()))?;

        assert_eq!(output.bytes_read, u64::try_from(data.len()).expect("test data fits in u64"));
        assert_eq!(
            output.digest.as_str(),
            expected_blake3_hex(data).as_str()
        );

        Ok(())
    }

    #[test]
    fn multi_chunk_input_matches_single_shot_hash() -> Result<(), HashError> {
        let data: Vec<u8> = (0..100).map(|index| (index % 251) as u8).collect();
        let buffer_size = 16;

        let output = Hasher::hash_reader_with_buffer(Cursor::new(data.as_slice()), buffer_size)?;

        assert_eq!(output.bytes_read, u64::try_from(data.len()).expect("test data fits in u64"));
        assert_eq!(
            output.digest.as_str(),
            expected_blake3_hex(&data).as_str()
        );

        Ok(())
    }

    #[test]
    fn zero_buffer_size_is_rejected() {
        let result = Hasher::hash_reader_with_buffer(Cursor::new(b"data"), 0);
        assert!(matches!(result, Err(HashError::InvalidBufferSize)));
    }
}
