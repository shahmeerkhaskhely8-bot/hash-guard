# hash-guard 🛡️

`hash-guard` is a lightning-fast, secure, and completely offline file integrity verification Command Line Interface (CLI) tool written in **Rust** using the high-performance **Blake3** cryptographic hashing algorithm. It is engineered for precision, ensuring that critical files remain uncorrupted and free from unauthorized tampering.

---

## 🚀 Key Features

- **Blazing Fast Hashing:** Powered by the Blake3 cryptographic hash function, delivering extreme performance and modern security standards.
- **100% Offline Architecture:** Operates completely locally on your machine without making any network requests or relying on external servers.
- **Baseline Integrity Verification:** Easily initialize baseline cryptographic signatures and compare files over time to detect data corruption or unauthorized modifications instantly.
- **Memory Safety & Performance:** Built entirely in Rust, guaranteeing memory safety with zero allocation overhead.

---

## 🛠️ How It Works

1. **Initialization (`init`):** Computes a cryptographic Blake3 hash of your specified target file and stores it as a trusted baseline reference point.
2. **Verification (`verify`):** Re-calculates the current hash of the file and compares it directly against the original baseline to confirm data authenticity and integrity.

---

## 📦 Installation Guide

Ensure you have **Rust** and **Cargo** installed on your system. Then, follow these steps to clone and build the project locally:

```bash
# Clone the repository
git clone [https://github.com/shahmeerkhaskhely8-bot/hash-guard.git](https://github.com/shahmeerkhaskhely8-bot/hash-guard.git)

# Navigate into the project directory
cd hash-guard

# Build the project in release mode
cargo build --release
