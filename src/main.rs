use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use std::path::PathBuf;

mod mnemonic;
mod wallet;
mod keygen;
mod keystore;
mod deposit;

use wallet::{Chain, OutputMode, KdfMode, WalletParams};

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputFormat {
    Plain,
    Json,
}

use serde::{Serialize, Deserialize};
use serde::ser::Serializer;

#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub enum BlsMode {
    /// Eth1 type credentials (0x01 prefix)
    #[value(name = "01")]
    Eth1,
    /// Pectra/EIP-7002 type credentials (0x02 prefix)
    #[value(name = "02")]
    Pectra,
}

// Custom serialization for BlsMode
impl Serialize for BlsMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            BlsMode::Eth1 => "01",
            BlsMode::Pectra => "02",
        };
        serializer.serialize_str(s)
    }
}

impl std::fmt::Display for BlsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlsMode::Eth1 => write!(f, "01"),
            BlsMode::Pectra => write!(f, "02"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Mnemonic {
        #[arg(value_enum, short, long, default_value_t = OutputFormat::Plain)]
        format: OutputFormat,
    },
    Wallet {
        #[command(subcommand)]
        command: WalletCommand,
    },
}

#[derive(Subcommand, Debug)]
enum WalletCommand {
    Generate {
        #[arg(long)]
        mnemonic: Option<String>,
        #[arg(long = "eth-amounts", value_delimiter = ',', num_args = 1..)]
        eth_amounts: Vec<u64>,
        #[arg(long)]
        withdrawal_address: String,
        #[arg(value_enum, long, default_value_t = BlsMode::Pectra)]
        bls_mode: BlsMode,
        #[arg(long)]
        password: String,
        #[arg(long, default_value_t = 0)]
        validator_index: u32,
        #[arg(long, default_value_t = 1)]
        validator_count: u32,
        #[arg(value_enum, long, default_value_t = OutputMode::Files)]
        format: OutputMode,
        #[arg(long, default_value = "./output")]
        output_dir: PathBuf,
        #[arg(value_enum, long, default_value_t = KdfMode::Scrypt)]
        kdf: KdfMode,
        #[arg(long, value_enum, default_value_t = Chain::Mainnet)]
        chain: Chain,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Mnemonic { format } => {
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
                eth_amounts,
                withdrawal_address,
                bls_mode,
                password,
                validator_index,
                validator_count,
                format,
                output_dir,
                kdf,
                chain,
            } => {
                // Global parameter validation (BLS mode-independent)
                
                // 1. Validate withdrawal address format
                if !withdrawal_address.starts_with("0x") || withdrawal_address.len() != 42 {
                    return Err(anyhow!("CLI Error: Withdrawal address must be a valid Ethereum address starting with 0x and 42 characters long"));
                }
                
                // 2. Validate password length
                if password.len() < 8 {
                    return Err(anyhow!("CLI Error: Password must be at least 8 characters long"));
                }
                
                // 3. Validate eth_amounts and validator_count consistency
                if eth_amounts.is_empty() && validator_count > 1 {
                    return Err(anyhow!("CLI Error: ETH amounts are required when validator_count > 1"));
                }
                
                if eth_amounts.len() > 1 && eth_amounts.len() != validator_count as usize {
                    return Err(anyhow!("CLI Error: Number of ETH amounts ({}) must match validator_count ({})", 
                        eth_amounts.len(), validator_count));
                }
                
                // BLS mode-specific validation
                match bls_mode {
                    BlsMode::Eth1 => {
                        // For Eth1 (01) mode:
                        // - Each validator must have exactly 32 ETH
                        // - If multiple validators, total ETH must be a multiple of 32
                        
                        if eth_amounts.len() == 1 {
                            let total_eth = eth_amounts[0];
                            
                            // Check if it's a multiple of 32
                            if total_eth % 32 != 0 {
                                return Err(anyhow!("CLI Error: For BLS mode 01, ETH amount ({}) must be a multiple of 32", total_eth));
                            }
                            
                            // Calculate how many validators we can create
                            let calculated_count = total_eth / 32;
                            
                            // If validator_count is 1 but calculated_count > 1, adjust validator_count
                            // This makes validator_count optional when eth_amounts is a multiple of 32
                            if validator_count == 1 && calculated_count > 1 {
                                println!("Note: Creating {} validators based on total ETH amount of {}", calculated_count, total_eth);
                            }
                            // If validator_count is explicitly specified and doesn't match, that's an error
                            else if calculated_count != validator_count as u64 {
                                return Err(anyhow!("CLI Error: ETH amount ({}) allows for {} validators, but validator_count is set to {}", 
                                    total_eth, calculated_count, validator_count));
                            }
                        } else {
                            // Multiple amounts specified - each amount must be exactly 32 ETH
                            for amount in &eth_amounts {
                                if *amount != 32 {
                                    return Err(anyhow!("CLI Error: For BLS mode 01, each validator must have exactly 32 ETH, but found {}", *amount));
                                }
                            }
                        }
                    },
                    BlsMode::Pectra => {
                        // For Pectra (02) mode:
                        // - Each validator must have between 32 and 2048 ETH
                        
                        if eth_amounts.len() == 1 && validator_count > 1 {
                            // Single amount specified for multiple validators
                            let total_eth = eth_amounts[0];
                            
                            // For multiple validators, the total ETH must be distributed evenly
                            let amount_per_validator = total_eth / validator_count as u64;
                            
                            // Check if each validator would get at least 32 ETH and at most 2048 ETH
                            if amount_per_validator < 32 || amount_per_validator > 2048 {
                                return Err(anyhow!("CLI Error: For BLS mode 02 with {} validators, each validator would get {} ETH, \
                                    which is outside the allowed range [32, 2048]", validator_count, amount_per_validator));
                            }
                        } else {
                            // Validate each amount is between 32 and 2048 ETH
                            for (i, amount) in eth_amounts.iter().enumerate() {
                                if *amount < 32 || *amount > 2048 {
                                    return Err(anyhow!("CLI Error: ETH amount for validator {} ({} ETH) is outside the allowed range [32, 2048] for BLS mode 02", 
                                        i, *amount));
                                }
                            }
                        }
                    }
                }

                // Check if mnemonic was provided
                let mnemonic_provided = mnemonic.is_some();
                
                // Prepare mnemonic
                let used_mnemonic = match mnemonic {
                    Some(m) => m,
                    None => mnemonic::generate_mnemonic()?,
                };

                // Prepare collections for output
                let mut keystore_paths = Vec::new();
                let mut keystore_objects = Vec::new();
                let mut all_deposit_data = Vec::new();
                let mut private_keys = Vec::new();

                // Expand eth_amounts if needed (single value case)
                // Calculate actual validator count based on ETH amounts for BLS mode 01
                let actual_validator_count = if !eth_amounts.is_empty() && bls_mode == BlsMode::Eth1 && eth_amounts.len() == 1 && eth_amounts[0] > 32 && eth_amounts[0] % 32 == 0 {
                    eth_amounts[0] / 32
                } else {
                    validator_count as u64
                };
                
                // Handle empty eth_amounts case
                if eth_amounts.is_empty() {
                    // For empty eth_amounts, use default values based on BLS mode
                    if validator_count > 1 {
                        // This should have been caught by validation earlier
                        return Err(anyhow!("CLI Error: ETH amounts are required when validator_count > 1"));
                    }
                    
                    // For validator_count == 1, use default ETH amount based on BLS mode
                    let default_eth_amount = match bls_mode {
                        BlsMode::Eth1 => 32, // Default for BLS mode 01 is 32 ETH
                        BlsMode::Pectra => 32, // Default for BLS mode 02 is also 32 ETH
                    };
                    
                    let expanded_eth_amounts = vec![default_eth_amount];
                    
                    // Define loop_count for this case
                    let loop_count = validator_count;
                    
                    // Prepare collections for output
                    let mut keystore_paths = Vec::new();
                    let mut keystore_objects = Vec::new();
                    let mut all_deposit_data = Vec::new();
                    let mut private_keys = Vec::new();
                    
                    // Continue with the rest of the function using the default values
                    for i in 0..loop_count {
                        let idx = validator_index + i;
                        let current_eth_amount = expanded_eth_amounts[i as usize];
                        
                        let params = WalletParams {
                            mnemonic: Some(used_mnemonic.clone()),
                            eth_amount: current_eth_amount,
                            withdrawal_address: withdrawal_address.clone(),
                            bls_mode: bls_mode.clone(),
                            password: Some(password.clone()),
                            chain: chain.clone(),
                            output_dir: output_dir.clone(),
                            kdf_mode: kdf.clone(),
                            validator_index: idx,
                        };
                        
                        let keys = params.generate_keys()?;
                        
                        // Always generate keystores in memory
                        let keystore_path = format!("keystore-m_12381_3600_{}_0_0.json", idx);
                        
                        // Create the correct HD path according to EIP-2334
                        // m / purpose / coin_type / account_index / withdrawal_key_index / validator_index
                        let hd_path = format!("m/12381/3600/{}/0/0", idx);
                        
                        // Create keystore file here
                        let secret_key_bytes = keys.key_pair.keypair.sk.serialize();
                        let secret_key = blst::min_pk::SecretKey::from_bytes(secret_key_bytes.as_bytes())
                            .map_err(|e| anyhow!("Failed to convert secret key: {:?}", e))?;
                        let keystore = keystore::generate_keystore(
                            &secret_key,
                            &password,
                            &hd_path,
                            match kdf {
                                KdfMode::Scrypt => keystore::KdfType::Scrypt,
                                KdfMode::Pbkdf2 => keystore::KdfType::Pbkdf2,
                            }
                        )?;
                        
                        keystore_paths.push(keystore_path);
                        // Store the keystore object for JSON output
                        keystore_objects.push(keystore.clone());
                        
                        // Store the private key for JSON output (hex encoded)
                        if format == OutputMode::Json {
                            private_keys.push(hex::encode(secret_key_bytes.as_bytes()));
                        }
                        
                        // Only write to file if format is Files
                        if format == OutputMode::Files {
                            keystore::write_keystore(&keystore, &output_dir)?;
                        }

                        // Always generate deposit data
                        let deposit_data_result = deposit::generate_deposit_data(
                            &keys.key_pair.keypair.pk,
                            &keys.key_pair.keypair.sk,
                            &withdrawal_address,
                            &bls_mode,
                            current_eth_amount,
                            &chain,
                        );

                        if let Ok(deposit_data) = deposit_data_result {
                            all_deposit_data.push(deposit_data.clone());
                        }
                    }
                    
                    // Write deposit data to a single file if format is Files
                    if format == OutputMode::Files && !all_deposit_data.is_empty() {
                        let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
                        let file_name = format!("deposit-{}.json", timestamp);
                        let file_path = output_dir.join(&file_name);
                        
                        // Create output directory if it doesn't exist
                        std::fs::create_dir_all(&output_dir)?;
                        
                        let json_string = serde_json::to_string_pretty(&all_deposit_data)?;
                        std::fs::write(&file_path, json_string)?;
                        println!("Generated deposit data file: {}", file_path.display());
                    }

                    // Output results
                    match format {
                        OutputMode::Files => {
                            let amounts_str = expanded_eth_amounts.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
                            println!("ETH amounts: {} ETH", amounts_str);
                            println!("Withdrawal address: {}", withdrawal_address);
                            println!("BLS mode: {:?}", bls_mode);
                            println!("Generated {} validator keystore file(s)", validator_count);
                            if !all_deposit_data.is_empty() {
                                println!("Generated {} deposit data file(s)", all_deposit_data.len());
                            }

                            for (i, path) in keystore_paths.iter().enumerate() {
                                println!("Validator {}: {}", i, path);
                            }
                        },
                        OutputMode::Json => {
                            let output = json!({
                                "keystores": keystore_objects,
                                "deposit_data": all_deposit_data,
                                "private_keys": private_keys,
                                "parameters": {
                                    "mnemonic": used_mnemonic,
                                    "mnemonic_provided": mnemonic_provided,
                                    "validator_count": validator_count,
                                    "validator_index": validator_index,
                                    "eth_amounts": expanded_eth_amounts,
                                    "withdrawal_address": withdrawal_address,
                                    "bls_mode": bls_mode.to_string(),
                                    "chain": chain,
                                    "kdf": kdf
                                },
                                "message": null
                            });
                            println!("{}", serde_json::to_string_pretty(&output)?);
                        }
                    }
                    
                    // Return early since we've handled this case
                    return Ok(());
                }
                
                let expanded_eth_amounts = match bls_mode {
                    BlsMode::Eth1 => {
                        if eth_amounts.len() == 1 && eth_amounts[0] > 32 {
                            // For Eth1 mode, each validator gets exactly 32 ETH
                            vec![32; actual_validator_count as usize]
                        } else {
                            eth_amounts.clone()
                        }
                    },
                    BlsMode::Pectra => {
                        if eth_amounts.len() == 1 && validator_count > 1 {
                            // For Pectra mode with a single amount, we distribute evenly
                            let amount_per_validator = eth_amounts[0] / validator_count as u64;
                            vec![amount_per_validator; validator_count as usize]
                        } else {
                            eth_amounts.clone()
                        }
                    }
                };

                // Use actual_validator_count for iteration
                let loop_count = if bls_mode == BlsMode::Eth1 && eth_amounts.len() == 1 && eth_amounts[0] > 32 && eth_amounts[0] % 32 == 0 {
                    actual_validator_count as u32
                } else {
                    validator_count
                };
                
                for i in 0..loop_count {
                    let idx = validator_index + i;
                    let current_eth_amount = expanded_eth_amounts[i as usize];

                    let params = WalletParams {
                        mnemonic: Some(used_mnemonic.clone()),
                        eth_amount: current_eth_amount,
                        withdrawal_address: withdrawal_address.clone(),
                        bls_mode: bls_mode.clone(),
                        password: Some(password.clone()),
                        chain: chain.clone(),
                        output_dir: output_dir.clone(),
                        kdf_mode: kdf.clone(),

                        validator_index: idx,
                    };

                    let keys = params.generate_keys()?;

                    // Always generate keystores in memory
                    let keystore_path = format!("keystore-m_12381_3600_{}_0_0.json", idx);
                    // let keystore_file_path: PathBuf = output_dir.join(&keystore_path);
                    
                    // Create the correct HD path according to EIP-2334
                    // m / purpose / coin_type / account_index / withdrawal_key_index / validator_index
                    let hd_path = format!("m/12381/3600/{}/0/0", idx);
                    
                    // Create keystore file here
                    let secret_key_bytes = keys.key_pair.keypair.sk.serialize();
                    let secret_key = blst::min_pk::SecretKey::from_bytes(secret_key_bytes.as_bytes())
                        .map_err(|e| anyhow!("Failed to convert secret key: {:?}", e))?;
                    let keystore = keystore::generate_keystore(
                        &secret_key,
                        &password,
                        &hd_path,
                        match kdf {
                            KdfMode::Scrypt => keystore::KdfType::Scrypt,
                            KdfMode::Pbkdf2 => keystore::KdfType::Pbkdf2,
                        }
                    )?;
                    
                    keystore_paths.push(keystore_path);
                    // Store the keystore object for JSON output
                    keystore_objects.push(keystore.clone());
                    
                    // Store the private key for JSON output (hex encoded)
                    if format == OutputMode::Json {
                        private_keys.push(hex::encode(secret_key_bytes.as_bytes()));
                    }
                    
                    // Only write to file if format is Files
                    if format == OutputMode::Files {
                        keystore::write_keystore(&keystore, &output_dir)?;
                    }

                    // Always generate deposit data
                    let deposit_data_result = deposit::generate_deposit_data(
                        &keys.key_pair.keypair.pk,
                        &keys.key_pair.keypair.sk,
                        &withdrawal_address,
                        &bls_mode,
                        current_eth_amount,
                        &chain,
                    );

                    if let Ok(deposit_data) = deposit_data_result {
                        all_deposit_data.push(deposit_data.clone());
                    }
                }

                // Write deposit data to a single file if format is Files
                if format == OutputMode::Files && !all_deposit_data.is_empty() {
                    let timestamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
                    let file_name = format!("deposit-{}.json", timestamp);
                    let file_path = output_dir.join(&file_name);
                    
                    // Create output directory if it doesn't exist
                    std::fs::create_dir_all(&output_dir)?;
                    
                    let json_string = serde_json::to_string_pretty(&all_deposit_data)?;
                    std::fs::write(&file_path, json_string)?;
                    println!("Generated deposit data file: {}", file_path.display());
                }

                // Output results
                match format {
                    OutputMode::Files => {
                        let amounts_str = eth_amounts.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
                        println!("ETH amounts: {} ETH", amounts_str);
                        println!("Withdrawal address: {}", withdrawal_address);
                        println!("BLS mode: {:?}", bls_mode);
                        println!("Generated {} validator keystore file(s)", validator_count);
                        if !all_deposit_data.is_empty() {
                            println!("Generated {} deposit data file(s)", all_deposit_data.len());
                        }

                        for (i, path) in keystore_paths.iter().enumerate() {
                            println!("Validator {}: {}", i, path);
                        }
                    },
                    OutputMode::Json => {
                        let output = json!({
                            "keystores": keystore_objects,
                            "deposit_data": all_deposit_data,
                            "private_keys": private_keys,
                            "parameters": {
                                "mnemonic": used_mnemonic,
                                "mnemonic_provided": mnemonic_provided,
                                "message" : "warning please do not share the mnemonic or private keys and ensure they are securely encrypted and access is limited",
                                "validator_count": actual_validator_count,
                                "eth_amount": if eth_amounts.len() == 1 { eth_amounts[0] } else { 0 },
                                "eth_amounts": eth_amounts,
                                "withdrawal_address": withdrawal_address,
                                "bls_mode": bls_mode,
                                "chain": chain,
                                "kdf": kdf,
                                "password": password,
                            },
                            "message": null
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                    }
                }

                Ok(())
            }
        }
    }
}
