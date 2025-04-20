use anyhow::{anyhow, Context, Result}; // Add Context
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json; // Import json macro
use std::path::PathBuf;
use blst;
use types::SecretKey;

mod mnemonic;
mod wallet;
mod keygen;
mod keystore;

use wallet::{Chain, OutputMode, KdfMode, WalletParams};

/// Supported output formats for mnemonic generation
#[derive(ValueEnum, Clone, Debug, PartialEq)] // Added PartialEq
pub enum OutputFormat {
    /// Plain text output
    Plain,
    /// JSON formatted output
    Json,
}

use serde::Serialize; // Import Serialize

/// Withdrawal credential type options
#[derive(ValueEnum, Clone, Debug, PartialEq, Serialize)]
pub enum WithdrawalCredentialType {
    /// 0x01 ETH1 Address Credential (Use '01' on CLI)
    #[clap(name = "01")] // Map CLI value "01" to this variant
    Eth1,
    /// 0x02 Execution Layer Address Credential (Use '02' on CLI) (Default)
    #[clap(name = "02")] // Map CLI value "02" to this variant
    Pectra,
}

// Removed duplicate OutputFormat enum definition that was here

/// CLI for Ethereum 2 staking operations
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate BIP-39 mnemonic phrases
    Mnemonic {
        /// Output format
        #[arg(value_enum, short, long, default_value_t = OutputFormat::Plain)]
        format: OutputFormat,
    },
    /// Generate deposit_data.json files for validators
    DepositJson {
        /// BIP-39 mnemonic for validator key derivation
        #[arg(long)]
        mnemonic: String,

        /// Validator index (start)
        #[arg(long, default_value_t = 0)]
        validator_index: u32,

        /// Number of validators to generate deposit data for
        #[arg(long, default_value_t = 1)]
        validator_count: u32,

        /// Withdrawal address for 0x02 credentials
        #[arg(long)]
        withdrawal_address: String,

        /// ETH amount per validator (in ETH)
        #[arg(long)]
        eth_amount: u64,

        /// Output directory for deposit data
        #[arg(long, default_value = "./output")]
        output_dir: PathBuf,
    },
    /// Manage validator wallets
    Wallet {
        #[command(subcommand)]
        command: WalletCommand,
    },
}

#[derive(Subcommand, Debug)]
enum WalletCommand {
    /// Generate a new validator wallet
    Generate {
        /// Optional BIP-39 mnemonic (generates new if not provided)
        #[arg(long)]
        mnemonic: Option<String>,

        /// Amount of ETH to stake (used if --create-deposit-json is NOT specified)
        #[arg(long, default_value_t = 32)] // Keep a default for the old path
        eth_amount: u64,

        /// Comma-separated list of ETH amounts per validator (only used if --create-deposit-json is specified and validator-count > 1)
        #[arg(long, value_delimiter = ',', num_args = 1..)] // Removed 'requires'
        amounts: Option<Vec<u64>>,

        /// Withdrawal address (ETH1 for 0x01, EL for 0x02)
        #[arg(long)]
        withdrawal_address: String,

        /// Withdrawal credential type (0x01 or 0x02)
        #[arg(value_enum, long, default_value_t = WithdrawalCredentialType::Pectra)]
        withdrawal_credential_type: WithdrawalCredentialType,

        /// Password for keystore encryption
        #[arg(long)]
        password: String,

        /// Validator index for HD derivation (default: 0)
        #[arg(long, default_value_t = 0)]
        validator_index: u32,

        /// Number of validators to generate (default: 1)
        #[arg(long, default_value_t = 1)]
        validator_count: u32,

        /// Output format (json or files)
        #[arg(value_enum, long, default_value_t = OutputMode::Files)]
        format: OutputMode,

        /// Create deposit data structure in JSON output (requires --format json)
        #[arg(long, default_value_t = false)]
        create_deposit_json: bool,

        /// Output directory for wallet files
        #[arg(long, default_value = "./output")]
        output_dir: PathBuf,

        /// KDF type for keystore encryption
        #[arg(value_enum, long, default_value_t = KdfMode::Scrypt)]
        kdf: KdfMode,

        /// Dry run (validate only)
        #[arg(long)]
        dry_run: bool,
    },
}

/// Main entry point
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Mnemonic { format } => {
            // TODO: Update mnemonic generation to support output format
            let mnemonic = mnemonic::generate_mnemonic()?;
            match format {
                OutputFormat::Plain => println!("{}", mnemonic),
                OutputFormat::Json => println!("{{\"mnemonic\": \"{}\"}}", mnemonic),
            }
            Ok(())
        },
        Commands::Wallet { command } => match command {
            WalletCommand::Generate {
                mnemonic, // Removed duplicate mnemonic binding here
                eth_amount, // Keep for old path
                amounts,    // New
                withdrawal_address,
                withdrawal_credential_type, // New
                password,
                validator_index,
                validator_count,
                format,
                create_deposit_json, // New
                output_dir,
                kdf,
                dry_run,
            } => {
                // --- Parameter Validation ---
                // Define amount constants based on credential type FIRST
                let (min_amount_rule, max_amount_rule, exact_amount_rule): (u64, u64, Option<u64>) =
                    match withdrawal_credential_type {
                        WithdrawalCredentialType::Eth1 => (32, 32, Some(32)), // Eth1 requires exactly 32
                        WithdrawalCredentialType::Pectra => (32, 2048, None), // Pectra requires 32-2048
                    };

                if create_deposit_json {
                    // Ensure format is JSON if creating deposit data structure
                    if format != OutputMode::Json {
                        return Err(anyhow!("--create-deposit-json requires --format json"));
                    }

                    if validator_count > 1 {
                        // Expect --amounts, validate it using rules for the specified credential type
                        match &amounts {
                            Some(amt_vec) => {
                                if amt_vec.len() != validator_count as usize {
                                    return Err(anyhow!("CLI Error: Number of amounts ({}) must match validator_count ({}) when validator_count > 1", amt_vec.len(), validator_count));
                                }
                                for (i, amount) in amt_vec.iter().enumerate() {
                                    if let Some(exact) = exact_amount_rule {
                                        if *amount != exact {
                                            return Err(anyhow!("CLI Error: Amount for validator {} ({}) must be exactly {} for {:?} credentials", validator_index + i as u32, amount, exact, withdrawal_credential_type));
                                        }
                                    } else if *amount < min_amount_rule || *amount > max_amount_rule {
                                        return Err(anyhow!("CLI Error: Amount for validator {} ({}) is outside the allowed range [{}, {}] for {:?} credentials", validator_index + i as u32, amount, min_amount_rule, max_amount_rule, withdrawal_credential_type));
                                    }
                                    // No divisibility check needed here based on current understanding
                                }
                            }
                            None => {
                                return Err(anyhow!("CLI Error: --amounts is required when --create-deposit-json is specified and validator_count > 1"));
                            }
                        }
                    } else { // validator_count == 1
                        // Expect --eth-amount, validate it using rules. --amounts should NOT be provided.
                        if amounts.is_some() {
                            return Err(anyhow!("CLI Error: --amounts should not be provided when --create-deposit-json is specified and validator_count is 1. Use --eth-amount instead."));
                        }
                        if let Some(exact) = exact_amount_rule {
                             if eth_amount != exact {
                                return Err(anyhow!("CLI Error: ETH amount ({}) must be exactly {} for {:?} credentials when validator_count is 1", eth_amount, exact, withdrawal_credential_type));
                            }
                        } else if eth_amount < min_amount_rule || eth_amount > max_amount_rule {
                            return Err(anyhow!("CLI Error: ETH amount ({}) is outside the allowed range [{}, {}] for {:?} credentials when validator_count is 1", eth_amount, min_amount_rule, max_amount_rule, withdrawal_credential_type));
                        }
                    }
                } else {
                    // Validation for the old path (create_deposit_json is false)
                    // Only validate eth_amount using rules. amounts should be None.
                    if amounts.is_some() {
                         return Err(anyhow!("CLI Error: --amounts should only be provided when --create-deposit-json is specified"));
                    }
                     if let Some(exact) = exact_amount_rule {
                         if eth_amount != exact {
                            return Err(anyhow!("CLI Error: ETH amount ({}) must be exactly {} for {:?} credentials", eth_amount, exact, withdrawal_credential_type));
                        }
                    } else if eth_amount < min_amount_rule || eth_amount > max_amount_rule {
                         return Err(anyhow!("CLI Error: ETH amount ({}) is outside the allowed range [{}, {}] for {:?} credentials", eth_amount, min_amount_rule, max_amount_rule, withdrawal_credential_type));
                    }
                }

                // --- Print Parameters (Files mode only) ---
                if format == OutputMode::Files {
                    println!("Generating validator wallet(s) with:");
                    // Decide which amount info to show based on flags
                    if create_deposit_json {
                         println!("  Amounts per validator: {:?}", amounts.as_ref().unwrap());
                    } else {
                         println!("  ETH amount per validator: {} ETH", eth_amount);
                    }
                    println!("  Withdrawal address: {}", &withdrawal_address);
                    println!("  Withdrawal credential type: {:?}", &withdrawal_credential_type);
                    println!("  Output mode: {:?}", &format);
                    println!("  Validator index: {}", validator_index);
                    println!("  Validator count: {}", validator_count);
                    println!("  KDF: {:?}", kdf);
                }

                // --- Prepare Mnemonic ---
                let mut used_mnemonic = mnemonic.clone();
                if used_mnemonic.is_none() {
                    let generated = mnemonic::generate_mnemonic()?;
                    used_mnemonic = Some(generated.clone());
                }

                // Output mnemonic and warning if generated (only in Files mode)
                if format == OutputMode::Files {
                    if mnemonic.is_none() {
                        println!("\n[IMPORTANT] Generated new mnemonic for validator key derivation:");
                        println!("{}", used_mnemonic.as_ref().unwrap());
                        println!("[WARNING] Save this mnemonic securely! It is required for future validator recovery or scaling.");
                    } else {
                        println!("Mnemonic used for validator key derivation:");
                        println!("{}", used_mnemonic.as_ref().unwrap());
                    }
                }

                // Check for dry run before generating anything
                if dry_run {
                    if format == OutputMode::Files {
                        println!("DRY RUN - no files will be generated");
                    } else { // JSON output for dry run
                        let parameters = if create_deposit_json {
                            json!({
                                "amounts": amounts.as_ref().unwrap(),
                                "withdrawal_address": withdrawal_address,
                                "withdrawal_credential_type": withdrawal_credential_type,
                                "validator_index": validator_index,
                                "validator_count": validator_count,
                                "mnemonic_provided": mnemonic.is_some(),
                                "kdf": kdf,
                            })
                        } else {
                            json!({
                                "eth_amount": eth_amount,
                                "withdrawal_address": withdrawal_address,
                                "withdrawal_credential_type": withdrawal_credential_type,
                                "validator_index": validator_index,
                                "validator_count": validator_count,
                                "mnemonic_provided": mnemonic.is_some(),
                                "kdf": kdf,
                            })
                        };
                        let json_output = json!({
                            "dry_run": true,
                            "message": "No files will be generated",
                            "parameters": parameters
                        });
                        println!("{}", serde_json::to_string_pretty(&json_output)?);
                    }
                    return Ok(());
                }

                // --- Generate Validators ---
                let mut keystore_paths = Vec::new();
                let mut keystore_jsons = Vec::new();
                let mut private_keys_hex = Vec::new(); // For new JSON format
                let mut deposit_data_placeholders = Vec::new(); // For new JSON format

                for i in 0..validator_count {
                    let idx = validator_index + i;
                    // Determine the correct amount for the current validator index
                    let current_eth_amount = if create_deposit_json && validator_count > 1 {
                        amounts.as_ref().unwrap()[i as usize] // amounts is guaranteed Some and correct length by validation above
                    } else {
                        eth_amount // Use eth_amount if !create_deposit_json OR if validator_count == 1
                    };

                    let params = WalletParams {
                        mnemonic: used_mnemonic.clone(),
                        eth_amount: current_eth_amount, // Use the determined amount
                        withdrawal_address: withdrawal_address.clone(),
                        withdrawal_credential_type: withdrawal_credential_type.clone(), // Pass the type from CLI args
                        password: Some(password.clone()),
                        chain: Chain::Mainnet, // TODO: Make chain configurable?
                        output_dir: output_dir.clone(),
                        kdf_mode: kdf.clone(),
                        dry_run,
                        validator_index: idx,
                    };
                    // Add context to fallible operations
                    params.validate().context("Failed to validate WalletParams")?;
                    let keys = params.generate_keys().context("Failed to generate keys")?;

                    // Debug: Print the public key for each validator index
                    // Consider removing or making conditional based on verbosity flag
                    // println!("DEBUG: Validator index {} public key: 0x{}",
                    //          idx,
                    //          hex::encode(keys.key_pair.keypair.pk.serialize()));

                    // --- Keystore Generation ---
                    // Convert KdfMode to KdfType for keystore generation
                    let kdf_type = match kdf {
                        KdfMode::Scrypt => keystore::KdfType::Scrypt,
                        KdfMode::Pbkdf2 => keystore::KdfType::Pbkdf2,
                    };
                    // Generate keystore with the secret key
                    // We need to get the raw secret key bytes and convert to blst::min_pk::SecretKey
                    // First get the bytes
                    let secret_key_bytes = keys.key_pair.keypair.sk.serialize();

                    // Create a new blst::min_pk::SecretKey from the raw bytes
                    let secret_key = blst::min_pk::SecretKey::from_bytes(secret_key_bytes.as_ref())
                        .map_err(|e| anyhow!("Failed to convert secret key bytes for index {}: {:?}", idx, e)) // Add error detail
                        .context("BLS SecretKey conversion failed")?;

                    // Removed DEBUG block

                    let keystore = keystore::generate_keystore(
                        &secret_key,
                        &password, // Pass the String ref, should coerce to &str
                        &format!("m/12381/3600/{}/0/0", idx), // EIP-2334 compliant signing key path
                        kdf_type,
                    ).context("Failed to generate keystore")?; // Add context

                    // --- Collect Output Data ---
                    match format {
                        OutputMode::Files => {
                            keystore::write_keystore(&keystore, &output_dir)
                                .context("Failed to write keystore file")?; // Add context
                            let path = output_dir.join(format!("keystore-m_12381_3600_{}_0_0-{}.json", idx, chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S"))); // Use EIP-2335 naming convention
                            keystore_paths.push(path.display().to_string());
                        },
                        OutputMode::Json => {
                            let keystore_value = serde_json::to_value(&keystore)
                                .context("Failed to serialize keystore to JSON value")?; // Add context
                            keystore_jsons.push(keystore_value);
                            // If creating deposit JSON structure, also collect private key and placeholder
                            if create_deposit_json {
                                private_keys_hex.push(format!("0x{}", hex::encode(secret_key_bytes.as_ref())));
                                // TODO: Replace {} with actual deposit data generation later
                                deposit_data_placeholders.push(json!({
                                    "placeholder": true,
                                    "message": "Deposit data generation not yet implemented",
                                    "validator_index": idx,
                                    "amount_eth": current_eth_amount,
                                    "withdrawal_credential_type": withdrawal_credential_type,
                                }));
                            }
                        }
                    }
                } // End of loop

                // --- Output Summary ---
                match format {
                    OutputMode::Files => {
                        println!("\nGenerated {} validator keystore file(s):", validator_count);
                        for (i, path) in keystore_paths.iter().enumerate() {
                            println!("  Validator {}: {}", validator_index + i as u32, path);
                        }
                        // Note: No deposit data or private keys printed in Files mode per current plan
                    },
                    OutputMode::Json => {
                        if create_deposit_json {
                            // Use the NEW structure from the example
                            let json_output = json!({
                                "deposit_data": deposit_data_placeholders, // Array of placeholders for now
                                "keystores": keystore_jsons,
                                "mnemonic": { "seed": used_mnemonic.as_ref().unwrap() }, // Use the actual mnemonic string
                                "private_keys": private_keys_hex
                            });
                            println!("{}", serde_json::to_string_pretty(&json_output)?);
                        } else {
                            // Use the OLD structure (existing code, slightly adapted)
                            let parameters = json!({
                                "eth_amount": eth_amount, // Single value used in this path
                                "withdrawal_address": withdrawal_address,
                                "withdrawal_credential_type": withdrawal_credential_type, // Added type here
                                "validator_index": validator_index,
                                "validator_count": validator_count,
                                "mnemonic_provided": mnemonic.is_some(),
                                "kdf": kdf,
                            });
                            // Always include the mnemonic in the old JSON format
                            let json_output = json!({
                                // Add warning only if mnemonic was generated
                                "warning": if mnemonic.is_none() {
                                    Some("[IMPORTANT] Save this mnemonic securely! It is required for future validator recovery or scaling.")
                                } else {
                                    None // No warning if mnemonic was provided
                                },
                                "mnemonic": used_mnemonic.as_ref().unwrap(), // Always include
                                "keystores": keystore_jsons,
                                "parameters": parameters
                            });
                            println!("{}", serde_json::to_string_pretty(&json_output)
                                .context("Failed to serialize final JSON output (old format)")?); // Add context
                        }
                    }
                }
                Ok(())
            } // End WalletCommand::Generate
        },
        Commands::DepositJson {
            mnemonic: _mnemonic,
            validator_index,
            validator_count,
            withdrawal_address,
            eth_amount,
            output_dir,
        } => {
            println!("Generating deposit_data.json with:");
            println!("  Mnemonic: <hidden>");
            println!("  Validator index: {}", validator_index);
            println!("  Validator count: {}", validator_count);
            println!("  Withdrawal address: {}", withdrawal_address);
            println!("  ETH amount per validator: {}", eth_amount);
            println!("  Output dir: {:?}", output_dir);
            // TODO: Call deposit data generation logic here
            Ok(())
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Plain => write!(f, "plain"),
            OutputFormat::Json => write!(f, "json"),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "plain" => Ok(OutputFormat::Plain),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Invalid format: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_cmd::Command;
    use predicates::prelude::*;

    #[test]
    fn test_mnemonic_plain_output() -> Result<()> {
        let mut cmd = Command::cargo_bin("stake-knife")?;
        let output: std::process::Output = cmd.arg("mnemonic").output()?;
        let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
        
        println!("Test output: {}", stdout);
        
        // Check output with assertions
        assert!(predicate::str::is_match(r"^[a-z]+( [a-z]+){23}\n?$").unwrap().eval(&stdout));
        
        Ok(())
    }

    #[test]
    fn test_mnemonic_json_output() -> Result<()> {
        let mut cmd = Command::cargo_bin("stake-knife")?;
        let output: std::process::Output = cmd.arg("mnemonic").arg("--format").arg("json").output()?;
        let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);

        println!("Test JSON output: {}", stdout);

        assert!(predicate::str::is_match(r#"\{"mnemonic": "[a-z]+( [a-z]+){23}"\}"#).unwrap().eval(&stdout));
        Ok(())
    }
}
