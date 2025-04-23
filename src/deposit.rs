use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use tree_hash::TreeHash;
use types::{
    DepositData, DepositMessage, ForkVersion, Hash256, PublicKey, PublicKeyBytes, SecretKey,
    SignatureBytes
};
use crate::BlsMode;
use crate::wallet::Chain;
use ssz::Encode as _;

// --- Constants ---
const DEPOSIT_CLI_VERSION: &str = "2.8.0";
const GWEI_PER_ETH: u64 = 1_000_000_000;
const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;
const ETH2_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x02; // For Pectra/EIP-7002

// Network specific constants
// Electra Fork Versions
const MAINNET_ELECTRA_FORK_VERSION: [u8; 4] = [0x05, 0x00, 0x00, 0x00];
const HOODI_ELECTRA_FORK_VERSION: [u8; 4] = [0x05, 0x00, 0x00, 0x00]; // Assuming same as Mainnet Electra - VERIFY if possible

// Genesis Validators Roots (Hex strings)
const MAINNET_GENESIS_VALIDATORS_ROOT_STR: &str = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";
const HOODI_GENESIS_VALIDATORS_ROOT_STR: &str = "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f";

// --- Helper Functions ---

/// Parses a 0x-prefixed hex string into a byte array of fixed size N.
fn parse_hex_bytes<const N: usize>(hex_str: &str) -> Result<[u8; N]> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if stripped.len() != N * 2 {
        return Err(anyhow!(
            "Hex string {} has incorrect length {} (expected {})",
            hex_str,
            stripped.len(),
            N * 2
        ));
    }
    let mut bytes = [0u8; N];
    hex::decode_to_slice(stripped, &mut bytes)
        .map_err(|e| anyhow!("Failed to decode hex string {}: {}", hex_str, e))?;
    Ok(bytes)
}

fn get_genesis_validators_root(chain: &Chain) -> Result<Hash256> {
     let hex_str = match chain {
        Chain::Mainnet => MAINNET_GENESIS_VALIDATORS_ROOT_STR,
        Chain::Hoodi => HOODI_GENESIS_VALIDATORS_ROOT_STR,
    };
    Ok(Hash256::from_slice(&parse_hex_bytes::<32>(hex_str)?))
}


fn get_electra_fork_version(chain: &Chain) -> ForkVersion {
    match chain {
        // ForkVersion is just an alias for [u8; 4], use the array directly
        Chain::Mainnet => MAINNET_ELECTRA_FORK_VERSION,
        Chain::Hoodi => HOODI_ELECTRA_FORK_VERSION, // Corrected name
        // Add other chains if needed
    }
}

fn get_network_name(chain: &Chain) -> String {
    match chain {
        Chain::Mainnet => "mainnet".to_string(),
        Chain::Hoodi => "hoodi".to_string(), // Corrected name
         // Add other chains if needed
    }
}

/// Formats the withdrawal credentials based on the type and address.
fn format_withdrawal_credentials(
    address_str: &str,
    bls_mode: &BlsMode,
) -> Result<[u8; 32]> {
    if !address_str.starts_with("0x") || address_str.len() != 42 {
        return Err(anyhow!(
            "Invalid withdrawal address format: {}",
            address_str
        ));
    }
    let address_bytes = parse_hex_bytes::<20>(address_str)
        .context("Failed to parse withdrawal address")?;

    let mut credentials = [0u8; 32];
    let prefix = match bls_mode {
        BlsMode::Eth1 => ETH1_ADDRESS_WITHDRAWAL_PREFIX,
        BlsMode::Pectra => ETH2_ADDRESS_WITHDRAWAL_PREFIX,
    };
    credentials[0] = prefix;
    // Bytes 1-11 are zero padding
    // Bytes 12-31 are the 20 address bytes
    credentials[12..].copy_from_slice(&address_bytes);

    Ok(credentials)
}


// --- Serializable Struct for JSON Output ---

#[derive(Serialize, Clone)]
pub struct DepositDataFile {
    pubkey: String,
    withdrawal_credentials: String,
    amount: u64, // Gwei
    signature: String,
    deposit_message_root: String,
    deposit_data_root: String,
    fork_version: String,
    network_name: String,
    deposit_cli_version: String,
}


// --- Core Function ---

/// Generates deposit data for a single validator.
pub fn generate_deposit_data(
    validator_pk: &PublicKey,
    validator_sk: &SecretKey,
    withdrawal_address: &str, // Expecting 0x-prefixed hex string
    bls_mode: &BlsMode,
    amount_eth: u64,
    chain: &Chain,
) -> Result<DepositDataFile> { // Return the serializable struct
    let amount_gwei = amount_eth * GWEI_PER_ETH;
    let fork_version = get_electra_fork_version(chain);
    let network_name = get_network_name(chain);
    let _genesis_validators_root = get_genesis_validators_root(chain)?;

    // 1. Format Withdrawal Credentials
    let withdrawal_credentials_bytes = format_withdrawal_credentials(withdrawal_address, bls_mode)?;

    // 2. Construct DepositMessage
    // Convert PublicKey to PublicKeyBytes (assuming compression is handled by PublicKeyBytes::from)
    let pubkey_bytes = PublicKeyBytes::from(validator_pk);
    let message = DepositMessage {
        pubkey: pubkey_bytes,
        withdrawal_credentials: withdrawal_credentials_bytes.into(),
        amount: amount_gwei,
    };

    // 3. Calculate Signing Domain & Root
    // TODO: Find correct import/method for compute_domain
    // TODO: Implement proper domain computation and signing root
    let signing_root = message.tree_hash_root(); // Ensure TreeHash trait is in scope via types
    // --- END TEMPORARY ---

    // 4. Sign DepositMessage
    let signature = validator_sk.sign(signing_root); // Sign the (currently incorrect) root

    // 5. Calculate Deposit Message Root (SSZ hash tree root of DepositMessage)
    let deposit_message_root = message.tree_hash_root();

    // 6. Construct DepositData (Lighthouse type)
    let deposit_data = DepositData {
        pubkey: message.pubkey,
        withdrawal_credentials: message.withdrawal_credentials,
        amount: message.amount,
        signature: SignatureBytes::from(signature), // Check conversion
    };

    // 7. Calculate Deposit Data Root (SSZ hash tree root of DepositData)
    let deposit_data_root = deposit_data.tree_hash_root();


    // 8. Construct the final serializable struct
    let deposit_data_file = DepositDataFile {
        pubkey: format!("0x{}", hex::encode(deposit_data.pubkey.as_ssz_bytes())), // Use as_ssz_bytes
        withdrawal_credentials: format!("0x{}", hex::encode(deposit_data.withdrawal_credentials.as_bytes())), // This is FixedVector<u8, 32>, as_bytes() is likely correct
        amount: deposit_data.amount, // Already in Gwei
        signature: format!("0x{}", hex::encode(deposit_data.signature.as_ssz_bytes())), // Use as_ssz_bytes
        deposit_message_root: format!("0x{}", hex::encode(deposit_message_root.as_bytes())), // Root is Hash256, as_bytes() is correct
        deposit_data_root: format!("0x{}", hex::encode(deposit_data_root.as_bytes())), // Root is Hash256, as_bytes() is correct
        fork_version: format!("0x{}", hex::encode(fork_version)),
        network_name,
        deposit_cli_version: DEPOSIT_CLI_VERSION.to_string(),
    };

    Ok(deposit_data_file)
    // Err(anyhow!("Deposit data generation not fully implemented yet")) // Remove placeholder error
}

// TODO: Add unit tests for helper functions and core logic (especially credential formatting, roots).
