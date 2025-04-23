# Stake Knife - Ethereum Staking CLI Tool - For Pectra Validators

[![CI Status](https://github.com/dbkbali/stake-knife/actions/workflows/ci.yml/badge.svg)](https://github.com/dbkbali/stake-knife/actions/workflows/ci.yml)


A command-line tool for Ethereum validator staking operations with secure key management that generates keystores and deposit.json files for validator provisioning.

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
  - Conditional amount validation based on credential type
  - Per-validator ETH amounts via `--eth-amounts` flag (for Pectra/02)
  - Optional structured JSON output including private keys (`--format json`)
  - Parameter validation (password length, ETH amount, address format)

  🛠 In Development:
- Deposit data generation
- more testing

## Installation

```sh
cargo install --path .
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

[Wallet Generation Examples](./examples.md)

### Key Derivation
- Uses EIP-2334 standard derivation path: `m/12381/3600/i/0/0` where `i` is validator index
- Same mnemonic + index always produces identical keys
- Compatible with eth-deposit-cli key derivation

### Recovery Process
To regenerate lost keystores use the original command that was utilized to generate the keystores with the same parameters:

```sh
stake-knife wallet generate \
  --mnemonic "your original 24 word mnemonic" \
  --eth-amounts 32,32,32 \  # Must match original amount
  --withdrawal-address 0x... \  # Must match original
  --password yourpassword \  # Must match original
  --validator-index 5 \  # Must match original
  --validator-count 3 \  # Must match original
  --output-dir ./recovered_keys
```

This will generate 3 recovered keystore files and the deposit data files in the specified output directory.

### Parameters
| Parameter | Description | Required | Validation |
|-----------|-------------|----------|------------|
| `--mnemonic` | Existing 24-word mnemonic | No | 24 words |
| `--password` | Keystore password | Yes | Min 8 chars |
| `--withdrawal-address` | Ethereum withdrawal address | Yes | 0x prefix, 42 chars |
| `--bls-mode` | Credential type (`01` or `02`) | No (defaults to `02`/Pectra) | `01` (Eth1) or `02` (Pectra) |
| `--validator-index` | Starting validator index | No (defaults to 0) | ≥0 |
| `--validator-count` | Number of validators | No (defaults to 1) | ≥1 |
| `--eth-amounts` | Comma-separated ETH amounts | No for single validator | Each amount depends on `--bls-mode` (`01`: exactly 32; `02`: 32-2048) |
| `--format` | Output format (`files` or `json`) | No (defaults to `files`) | `files` or `json` |
| `--output-dir` | Output directory (for `--format files`) | No (defaults to `./output`) | Valid path |
| `--kdf` | Keystore KDF (`Scrypt` or `Pbkdf2`) | No (defaults to `Scrypt`) | `Scrypt` or `Pbkdf2` |
| `--chain` | Network chain (`mainnet` or `hoodi`) | No (defaults to `mainnet`) | `mainnet` or `hoodi` |

⚠️ **Important Notes:**
1. When generating new mnemonics, they are displayed with an IMPORTANT warning - store this securely!
2. For recovery, you must use the exact same parameters as original generation.
3. When using `--format json`, the output includes the mnemonic, keystores, deposit data, and private keys.
4. When using `--format files`, files are written to the output directory and a summary is printed to stdout.
5. If `--eth-amounts` is not provided for a single validator, a default of 32 ETH will be used.
6. If `validator_count > 1`, then `--eth-amounts` must be provided with exactly that many values.

## Development Status

Current Version: 0.1.0  
Next Milestone: Wallet generation (ETA v0.2.0)

## Testing

```sh
# Run all tests
cargo test

# Run integration tests
cargo test -- --ignored

# Test specific component
cargo test test_mnemonic_generation
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
```

## Contributing

Pull requests welcome! Please:
1. Open an issue first to discuss changes
2. Follow existing code style
3. Include tests for new features

## License

MIT 
