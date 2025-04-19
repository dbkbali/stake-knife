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
- Parameter validation (password length, ETH amount, address format)
- Dry run mode (`--dry-run`)

🛠 In Development:
- Deposit data generation

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
```sh
# Generate single validator wallet
stake-knife wallet generate \
  --eth-amount 32 \
  --withdrawal-address 0x... \
  --password yourpassword \
  --output-dir ./keys

# Generate multiple validators (batch mode)
stake-knife wallet generate \
  --eth-amount 96 \  # 3 validators * 32 ETH
  --withdrawal-address 0x... \
  --password yourpassword \
  --validator-index 5 \  # Start at index 5
  --validator-count 3 \  # Generate 3 validators - eth amount must be a multiple of 32ETH
  --output-dir ./keys

# JSON output format
stake-knife wallet generate \
  --eth-amount 32 \
  --withdrawal-address 0x... \
  --password yourpassword \
  --format json

# Dry run (validate without writing files)
stake-knife wallet generate \
  --eth-amount 32 \
  --withdrawal-address 0x... \
  --password yourpassword \
  --dry-run
```

### Key Derivation
- Uses EIP-2334 standard derivation path: `m/12381/3600/i/0/0` where `i` is validator index
- Same mnemonic + index always produces identical keys
- Compatible with eth-staking-smith key derivation

### Recovery Process
To regenerate lost keystores:
```sh
stake-knife wallet generate \
  --mnemonic "your original 24 word mnemonic" \
  --eth-amount 96 \  # Must match original amount
  --withdrawal-address 0x... \  # Must match original
  --password yourpassword \  # Must match original
  --validator-index 5 \  # Must match original
  --validator-count 3 \  # Must match original
  --output-dir ./recovered_keys
```

### Parameters
| Parameter | Description | Required | Validation |
|-----------|-------------|----------|------------|
| `--mnemonic` | Existing 24-word mnemonic | No | 24 words |
| `--password` | Keystore password | Yes | Min 8 chars |
| `--eth-amount` | Total ETH amount | Yes | 32-2048 ETH, multiple of 32 |
| `--withdrawal-address` | Ethereum withdrawal address | Yes | 0x prefix |
| `--validator-index` | Starting validator index | No | ≥0 |
| `--validator-count` | Number of validators | No | ≥1 |
| `--output-dir` | Output directory | No | Valid path |
| `--format` | Output format (plain/json) | No | plain/json |
| `--dry-run` | Validate without writing files | No | Boolean |

⚠️ **Important Notes:**
1. When generating new mnemonics, they are displayed with an IMPORTANT warning - store this securely!
2. For recovery, you must use the exact same parameters as original generation.
3. JSON output includes mnemonic when generated (but not when provided).

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

## Usage: Two-Step Workflow

### 1. Generate Validator Keystores (Infra Provider)
```sh
stake-knife wallet generate \
  --eth-amount 128
  --mnemonic "<mnemonic>" \
  --validator-count 4 \
  --password <password> \
  --output-dir ./output
```
- Generates 4 validator keystores (indices 0-3) using the given mnemonic each assumed to have a 32 Eth stake.
- Save the mnemonic securely for future validator/key recovery.
- **NOTE:** If you do not specify `--mnemonic` and use `--format json`, the generated mnemonic will be included in the JSON output along with a warning. This ensures you have a backup for recovery. If you provide a mnemonic, it is *not* included in the JSON output.

### 2. Generate Deposit Data (Staker or Infra)
```sh
stake-knife depositjson \
  --mnemonic "<mnemonic>" \
  --validator-index 0 \
  --validator-count 4 \
  --withdrawal-address 0x... \
  --eth-amount 32 \
  --output-dir ./output
```
- Generates deposit_data.json files for indices 0-3 with the specified withdrawal address and amount (in ETH).
- These files are used for submitting deposits to the Ethereum deposit contract.

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

MIT © 2025
