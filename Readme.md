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

## Project Structure

```
src/
├── main.rs       # CLI interface and command routing
├── mnemonic.rs   # BIP-39 mnemonic implementation
└── wallet.rs     # Validator wallet functionality (in progress)
```

## Contributing

Pull requests welcome! Please:
1. Open an issue first to discuss changes
2. Follow existing code style
3. Include tests for new features

## License

MIT © 2025
