# Stake Knife - Ethereum Staking CLI Tool - For Pectra Validators

[![CI Status](https://github.com/dbkbali/stake-knife/actions/workflows/ci.yml/badge.svg)](https://github.com/dbkbali/stake-knife/actions/workflows/ci.yml)
[![Release Workflow](https://github.com/dbkbali/stake-knife/actions/workflows/release.yml/badge.svg)](https://github.com/dbkbali/stake-knife/actions/workflows/release.yml)
[![Version](https://img.shields.io/badge/version-0.1.1-blue)](https://github.com/dbkbali/stake-knife/blob/main/Cargo.toml)

A command-line tool for Ethereum validator staking operations with secure key management that generates keystores and deposit.json files for validator provisioning. Stake Knife is specifically designed for post-Pectra validators (32-2048 ETH) with 0x02 execution withdrawal credentials.

## Features

✅ Implemented:
- Generate 24-word BIP-39 mnemonic phrases
- Multiple output formats (plain text, JSON)
- Future-proof subcommand architecture
- Validator wallet creation (BLS key generation)
- Keystore file generation (EIP-2335)
- Batch keystore generation (`--validator-count`)
- Specific starting index (`--validator-index`)
- EIP-2334 compliant key derivation
  - Keystore recovery from mnemonic
  - Selectable withdrawal credential type (`--bls-mode` 01/02)
    - `01`: Pre-Pectra BLS withdrawal credentials (exactly 32 ETH per validator)
    - `02`: Post-Pectra execution withdrawal credentials (32-2048 ETH per validator, default)
  - Conditional amount validation based on credential type
  - Per-validator ETH amounts via `--eth-amounts` flag
  - Optional structured JSON output including private keys (`--format json`)
  - Parameter validation (password length, ETH amount, address format)

Not Yet Implemented:
- allow json output to secure file with encryption

## Installation

### From Source
```sh
# Clone the repository
git clone https://github.com/dbkbali/stake-knife.git
cd stake-knife

# Build and install
cargo install --path .
```

### From Releases
Download the latest binary for your platform from the [releases page](https://github.com/dbkbali/stake-knife/releases).

#### Linux x86_64
```sh
curl -LO https://github.com/dbkbali/stake-knife/releases/download/v[VERSION]/stake-knife-[VERSION]-linux-x86_64.tar.gz
tar -xzf stake-knife-[VERSION]-linux-x86_64.tar.gz
chmod +x stake-knife-[VERSION]-linux-x86_64
./stake-knife-[VERSION]-linux-x86_64 --help
```

#### macOS ARM64 (Apple Silicon)
```sh
curl -LO https://github.com/dbkbali/stake-knife/releases/download/v[VERSION]/stake-knife-[VERSION]-macos-arm64.tar.gz
tar -xzf stake-knife-[VERSION]-macos-arm64.tar.gz
chmod +x stake-knife-[VERSION]-macos-arm64
./stake-knife-[VERSION]-macos-arm64 --help
```

## Usage

### Mnemonic Generation
```sh
# Generate mnemonic (default plain text)
stake-knife mnemonic

# Generate mnemonic in JSON format
stake-knife mnemonic --format json
```

### Wallet Generation

```sh
# Basic wallet generation with new mnemonic (32 ETH)
# Uses default --bls-mode 02 (post-Pectra/execution withdrawal credentials)
stake-knife wallet generate \
  --withdrawal-address 0x71C7656EC7ab88b098defB751B7401B5f6d8976F \
  --password yourpassword \
  --eth-amounts 32

# Generate multiple validators (96 ETH = 3 validators)
stake-knife wallet generate \
  --withdrawal-address 0x71C7656EC7ab88b098defB751B7401B5f6d8976F \
  --password yourpassword \
  --eth-amounts 96 \
  --validator-count 3 \
  --bls-mode 02  # Explicitly setting post-Pectra mode (default)

# Using an existing mnemonic with BLS mode 01 (pre-Pectra/BLS withdrawal credentials)
stake-knife wallet generate \
  --mnemonic "your 24 word mnemonic phrase here" \
  --withdrawal-address 0x71C7656EC7ab88b098defB751B7401B5f6d8976F \
  --password yourpassword \
  --eth-amounts 32,32,32 \
  --validator-count 3 \
  --bls-mode 01  # Pre-Pectra mode (BLS withdrawal credentials)
```

For more examples, see [Wallet Generation Examples](./examples.md)

### Key Derivation
- Uses EIP-2334 standard derivation path: `m/12381/3600/i/0/0` where `i` is validator index
- Same mnemonic + index always produces identical keys
- Compatible with eth-deposit-cli key derivation

### Recovery Process
To regenerate lost keystores, use the original command that was utilized to generate the keystores with the same parameters:

```sh
stake-knife wallet generate \
  --mnemonic "your original 24 word mnemonic" \
  --eth-amounts 32,32,32 \  # Must match original amounts
  --withdrawal-address 0x... \  # Must match original
  --password yourpassword \  # Must match original
  --validator-count 3 \  # Must match original count
  --validator-index 0 \  # Must match original starting index
  --output-dir ./recovered_keys
```

This will regenerate your keystore files and the deposit data files in the specified output directory.

### Parameters
| Parameter | Description | Required | Validation |
|-----------|-------------|----------|------------|
| `--mnemonic` | Existing 24-word mnemonic | No | 24 words |
| `--password` | Keystore password | Yes | Min 8 chars |
| `--withdrawal-address` | Ethereum withdrawal address | Yes | 0x prefix, 42 chars |
| `--eth-amounts` | Comma-separated ETH amounts | Yes | For BLS mode 02: 32-2048 ETH per validator |
| `--validator-count` | Number of validators | No (defaults to 1) | ≥1 |
| `--validator-index` | Starting validator index | No (defaults to 0) | ≥0 |
| `--bls-mode` | Credential type (`01` or `02`) | No (defaults to `02`/Pectra) | `01` (Eth1) or `02` (Pectra) |
| `--format` | Output format (`files` or `json`) | No (defaults to `files`) | `files` or `json` |
| `--output-dir` | Output directory (for `--format files`) | No (defaults to `./output`) | Valid path |
| `--kdf` | Keystore KDF (`Scrypt` or `Pbkdf2`) | No (defaults to `Scrypt`) | `Scrypt` or `Pbkdf2` |
| `--chain` | Network chain (`mainnet` or `hoodie`) | No (defaults to `mainnet`) | `mainnet` or `hoodie` |

⚠️ **Important Notes:**
1. When generating new mnemonics, they are displayed with an IMPORTANT warning - store this securely!
2. For recovery, you must use the exact same parameters as original generation.
3. When using `--format json`, the output includes the mnemonic, keystores, deposit data, and private keys to stdout.
4. When using `--format files`, files are written to the output directory and a summary is printed to stdout.
5. If `--eth-amounts` contains a single value and `--validator-count` > 1, the total ETH will be distributed evenly.
6. If `--validator-count` > 1, then `--eth-amounts` must be provided with either a single value or exactly that many values.
7. The default `--bls-mode` is `02` (post-Pectra with execution withdrawal credentials).
8. For `--bls-mode 01` (pre-Pectra), ETH amounts must be exactly 32 ETH per validator.
9. For `--bls-mode 02` (post-Pectra), ETH amounts can range from 32 to 2048 ETH per validator.

## Development Status

Check the [releases page](https://github.com/dbkbali/stake-knife/releases) for the latest version and release notes.

## Testing

```sh
# Run all tests
cargo test

# Run integration tests
cargo test -- --ignored

# Test specific component
cargo test test_mnemonic_generation
```

### Reference Tests
- Included in `tests/test_compatibility.rs` is a reference test that compares output with the official [ethereum staking deposit cli tool](https://github.com/ethereum/staking-deposit-cli).
- This tool was used to generate the reference keystores and deposit data files in the `test/reference_data` directory using the following parameters:

```sh
# Command used with ethereum staking deposit cli tool
./deposit new-mnemonic \
  --mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art" \
  --execution_address="0x71C7656EC7ab88b098defB751B7401B5f6d8976F" \
  --num_validators=3 \
  --validator_start_index=5

# Password used: "testpassword123"
```

## Project Structure

```
src/
├── main.rs       # CLI interface and command routing
├── mnemonic.rs   # BIP-39 mnemonic implementation
├── wallet.rs     # Validator wallet functionality
├── keygen.rs     # EIP-2334 Key derivation
├── keystore.rs   # EIP-2335 keystore creation
├── deposit.rs    # Deposit data generation (post-Pectra)
├── utils.rs      # Utility functions
```

## Standards Compliance

Stake Knife follows these Ethereum standards:
- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) for mnemonic generation
- [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333) for key derivation
- [EIP-2334](https://eips.ethereum.org/EIPS/eip-2334) for path derivation
- [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335) for keystore format
- Consensus Layer deposit contract specifications

## Contributing

Pull requests welcome! Please:
1. Open an issue first to discuss changes
2. Follow existing code style
3. Include tests for new features

## License

MIT 
