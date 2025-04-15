use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use blst;
use types::SecretKey;

mod mnemonic;
mod wallet;
mod keygen;
mod keystore;

use wallet::{Chain, OutputMode, KdfMode, WalletParams};

/// Supported output formats for mnemonic generation
#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    /// Plain text output
    Plain,
    /// JSON formatted output
    Json,
}

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
        
        /// Amount of ETH to stake (32-2048, must be multiple of 32)
        #[arg(long)]
        eth_amount: u64,
        
        /// Withdrawal address for 0x02 credentials
        #[arg(long)]
        withdrawal_address: String,

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
                mnemonic,
                eth_amount,
                withdrawal_address,
                password,
                validator_index,
                validator_count,
                format,
                output_dir,
                kdf,
                dry_run,
            } => {
                // Print parameters for verification (only in Files mode)
                if format == OutputMode::Files {
                    println!("Generating validator wallet(s) with:");
                    println!("  ETH amount: {} ETH", eth_amount);
                    println!("  Withdrawal address: {}", &withdrawal_address);
                    println!("  Output mode: {:?}", &format);
                    println!("  Validator index: {}", validator_index);
                    println!("  Validator count: {}", validator_count);
                }

                // Prepare mnemonic (generate if not provided)
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
                    } else {
                        // For JSON output, return a structured response
                        use serde_json::json;
                        let json_output = json!({
                            "dry_run": true,
                            "message": "No files will be generated",
                            "parameters": {
                                "eth_amount": eth_amount,
                                "withdrawal_address": withdrawal_address,
                                "validator_index": validator_index,
                                "validator_count": validator_count,
                                "mnemonic_provided": mnemonic.is_some()
                            }
                        });
                        println!("{}", serde_json::to_string_pretty(&json_output)?);
                    }
                    return Ok(());
                }

                // Generate validators in batch
                let mut keystore_paths = Vec::new();
                let mut keystore_jsons = Vec::new();
                for i in 0..validator_count {
                    let idx = validator_index + i;
                    let params = WalletParams {
                        mnemonic: used_mnemonic.clone(),
                        eth_amount,
                        withdrawal_address: withdrawal_address.clone(),
                        password: Some(password.clone()),
                        chain: Chain::Mainnet,
                        output_dir: output_dir.clone(),
                        kdf_mode: kdf.clone(),
                        dry_run,
                        validator_index: idx,
                    };
                    params.validate()?;
                    let keys = params.generate_keys()?;
                    
                    // Debug: Print the public key for each validator index
                    println!("DEBUG: Validator index {} public key: 0x{}", 
                             idx, 
                             hex::encode(keys.key_pair.keypair.pk.serialize()));
                    
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
                    // We need to convert the ZeroizeHash to a byte slice
                    let secret_key = blst::min_pk::SecretKey::from_bytes(secret_key_bytes.as_ref())
                        .map_err(|_| anyhow!("Failed to convert secret key"))?;
                    
                    let keystore = keystore::generate_keystore(
                        &secret_key,
                        &password,
                        &format!("m/12381/3600/{}/0/0", idx), // EIP-2334 compliant signing key path
                        kdf_type,
                    )?;
                    match format {
                        OutputMode::Files => {
                            keystore::write_keystore(&keystore, &output_dir)?;
                            let path = output_dir.join(format!("keystore-idx-{}.json", idx));
                            keystore_paths.push(path.display().to_string());
                        },
                        OutputMode::Json => {
                            // Parse the keystore to a JSON Value instead of storing it as a string
                            // This prevents escaping in the final output
                            let keystore_value = serde_json::to_value(&keystore)?;
                            keystore_jsons.push(keystore_value);
                        }
                    }
                }
                // Output summary
                match format {
                    OutputMode::Files => {
                        println!("\nGenerated {} validator keystore(s):", validator_count);
                        for (i, path) in keystore_paths.iter().enumerate() {
                            println!("  Index {}: {}", validator_index + i as u32, path);
                        }
                    },
                    OutputMode::Json => {
                        // If the mnemonic was generated by the CLI (not provided by user), include it in the JSON output with a warning
                        if mnemonic.is_none() {
                            // Create a JSON object with parsed keystores and command parameters
                            use serde_json::json;
                            let json_output = json!({
                                "warning": "[IMPORTANT] Save this mnemonic securely! It is required for future validator recovery or scaling.",
                                "mnemonic": used_mnemonic.as_ref().unwrap(),
                                "keystores": keystore_jsons,
                                "parameters": {
                                    "eth_amount": eth_amount,
                                    "withdrawal_address": withdrawal_address,
                                    "validator_index": validator_index,
                                    "validator_count": validator_count,
                                    "mnemonic_provided": false
                                }
                            });
                            let json = serde_json::to_string_pretty(&json_output)?;
                            println!("{}", json);
                        } else {
                            // Create a JSON array with all keystores and parameters
                            use serde_json::json;
                            let json_output = json!({
                                "keystores": keystore_jsons,
                                "parameters": {
                                    "eth_amount": eth_amount,
                                    "withdrawal_address": withdrawal_address,
                                    "validator_index": validator_index,
                                    "validator_count": validator_count,
                                    "mnemonic_provided": true
                                }
                            });
                            let json = serde_json::to_string_pretty(&json_output)?;
                            println!("{}", json);
                        }
                    }
                }
                Ok(())
            }
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
