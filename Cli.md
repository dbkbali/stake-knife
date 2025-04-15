### CLI Documentation for Stake Knife

This CLI supports post-Pectra validators (32-2048 ETH, 0x02 execution credentials) with clear roles for the staker (owns execution wallet, deposits ETH, controls withdrawals) and infrastructure provider (manages validator mnemonic, signing keys, exit messages).

```
stake-knife <subcommand> [options]

Subcommands:
  mnemonic              Generate a validator mnemonic (for infrastructure provider)
    --format <json|text>  Output format (default: text)

  wallet generate       Generate a validator wallet (post-Pectra, 0x02 execution credentials)
    --mnemonic          Optional validator mnemonic (else generate new)
    --eth-amount        ETH amount to stake (32-2048 ETH)
    --withdrawal-address Staker's execution address (required, 0x prefixed)
    --password          Keystore password (for infrastructure provider)
    --chain             Chain ID (default: 1, mainnet)
    --mode              Output mode: files|json|keymanager (default: files)
    --output-dir        Output directory (default: ./output, use '-' for stdout)

  keys                  Generate raw validator signing keys (for infrastructure provider)
    --mnemonic          Validator mnemonic (required)
    --index             Validator index (default: 0)
    --format            json|file (default: json)
    --output-dir        Output directory (default: ./output)

  keystore              Create EIP-2335 keystores for signing keys (for infrastructure provider)
    --mnemonic          Validator mnemonic (required)
    --index             Validator index (default: 0)
    --password          Keystore password (required)
    --format            json|file (default: file)
    --output-dir        Output directory (default: ./output)

  deposit               Generate deposit data (for staker)
    --mnemonic          Validator mnemonic (required)
    --eth-amount        Total ETH to stake (32-2048 ETH per validator)
    --max-per-validator Max ETH per validator (default: 2048)
    --withdrawal-address Staker’s execution address (required)
    --chain             Chain ID (default: 1)
    --format            json|file (default: file)
    --output-dir        Output directory (default: ./output)
```
