# Stake Knife - Ethereum Staking CLI Tool

A command-line tool for Ethereum validator operations with secure key management.

## Features

✅ Implemented:
- Generate 24-word BIP-39 mnemonic phrases
- Multiple output formats (plain text, JSON)
- Future-proof subcommand architecture

🛠 In Development:
- Validator wallet creation (BLS key generation)
- Keystore file generation (EIP-2335)
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

### Wallet Operations (Coming Soon)
```sh
# Generate validator wallet files
stake-knife wallet --output-dir ./keys
```

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
  --mnemonic "<mnemonic>" \
  --validator-count 4 \
  --password <password> \
  --output-dir ./output
```
- Generates 4 validator keystores (indices 0-3) using the given mnemonic.
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
