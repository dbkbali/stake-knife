use anyhow::{anyhow, Context, Result};
use ethereum_hashing::hash as eth_hash;
use serde::Serialize;
use smallvec::SmallVec;
// Import the Encode trait directly from ethereum_ssz version 0.7.1
use ethereum_ssz::Encode;
use tree_hash::TreeHash;
use types::{
    DepositData, DepositMessage, ForkVersion, Hash256, PublicKey, PublicKeyBytes, SecretKey,
    SignatureBytes
};
use crate::BlsMode;
use crate::wallet::Chain;
// We already have the TreeHash trait imported directly

// --- Constants ---
const DEPOSIT_CLI_VERSION: &str = "2.8.0";
const GWEI_PER_ETH: u64 = 1_000_000_000;
const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;
const ETH2_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x02; // For Pectra/EIP-7002

// Domain type for deposits
const DOMAIN_DEPOSIT: u32 = 3;

// Network specific constants
// Electra Fork Versions
#[allow(dead_code)]
const MAINNET_ELECTRA_FORK_VERSION: [u8; 4] = [0x00, 0x00, 0x00, 0x00]; // Mainnet fork version
#[allow(dead_code)]
const HOODI_ELECTRA_FORK_VERSION: [u8; 4] = [0x10, 0x00, 0x09, 0x10]; // Hoodi fork version

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

fn get_genesis_validators_root(_chain: &Chain) -> Result<Hash256> {
    // Always use a zero hash for the genesis validators root when generating deposit data
    // This matches the official implementation which uses EMPTY_ROOT
    Ok(Hash256::from_slice(&[0u8; 32]))
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

/// Computes the domain for signing based on domain type, fork version, and genesis validators root
fn compute_domain(domain_type: u32, fork_version: ForkVersion, genesis_validators_root: Hash256) -> [u8; 32] {
    // According to ETH2 specs and the official implementation:
    // 1. Create a ForkData structure with currentVersion and genesisValidatorsRoot
    // 2. Compute the hash tree root of this structure
    // 3. Set the domain type in the first 4 bytes of the domain
    // 4. Set the first 28 bytes of the fork data root starting at offset 4
    
    // First, compute the fork data root
    // ForkData = { currentVersion: ForkVersion, genesisValidatorsRoot: Hash256 }
    struct ForkData {
        current_version: ForkVersion,
        genesis_validators_root: Hash256,
    }
    
    impl TreeHash for ForkData {
        fn tree_hash_type() -> tree_hash::TreeHashType {
            tree_hash::TreeHashType::Container
        }
        
        fn tree_hash_packed_encoding(&self) -> SmallVec<[u8; 32]> {
            unreachable!("Containers are not packed")
        }
        
        fn tree_hash_packing_factor() -> usize {
            unreachable!("Containers are not packed")
        }
        
        fn tree_hash_root(&self) -> tree_hash::Hash256 {
            // Create a buffer to hold the concatenated values
            let mut buffer = [0u8; 64];
            
            // Copy the current_version into the first 4 bytes
            buffer[0..4].copy_from_slice(&self.current_version);
            
            // Copy the genesis_validators_root into the next 32 bytes
            buffer[4..36].copy_from_slice(self.genesis_validators_root.as_ref());
            
            // Hash the concatenated buffer
            let hash_bytes = eth_hash(&buffer);
            
            // Convert to the expected Hash256 type
            tree_hash::Hash256::from_slice(&hash_bytes)
        }
    }
    
    // Create the ForkData and compute its hash tree root
    let fork_data = ForkData {
        current_version: fork_version,
        genesis_validators_root,
    };
    
    let fork_data_root = fork_data.tree_hash_root();
    
    // Create the domain
    let mut domain = [0u8; 32];
    
    // Set the domain type in the first 4 bytes
    domain[0..4].copy_from_slice(&domain_type.to_le_bytes());
    
    // Set the first 28 bytes of the fork data root starting at offset 4
    let fork_data_root_bytes: &[u8] = fork_data_root.as_ref();
    domain[4..32].copy_from_slice(&fork_data_root_bytes[0..28]);
    
    domain
}

/// Computes the signing root by combining message root and domain
fn compute_signing_root(message_root: Hash256, domain: [u8; 32]) -> Hash256 {
    // According to ETH2 specs, we need to create a SigningData structure and compute its hash tree root
    // SigningData = { object_root: Hash256, domain: Domain }
    
    // Create a simple struct that implements TreeHash to represent SigningData
    struct SigningData {
        object_root: Hash256,
        domain: [u8; 32],
    }
    
    // Implement TreeHash for SigningData
impl TreeHash for SigningData {
        fn tree_hash_type() -> tree_hash::TreeHashType {
            tree_hash::TreeHashType::Container
        }
        
        fn tree_hash_packed_encoding(&self) -> SmallVec<[u8; 32]> {
            unreachable!("Containers are not packed")
        }
        
        fn tree_hash_packing_factor() -> usize {
            unreachable!("Containers are not packed")
        }
        
        fn tree_hash_root(&self) -> tree_hash::Hash256 {
            // The official implementation computes the signing root as follows:
            // 1. The object_root is already a hash, so we use it directly
            // 2. The domain needs to be converted to a Hash256
            // 3. We concatenate the two 32-byte values and hash the result
            
            // Create a buffer to hold the concatenated values
            let mut buffer = [0u8; 64];
            
            // Copy the object_root into the first 32 bytes
            buffer[0..32].copy_from_slice(self.object_root.as_ref());
            
            // Copy the domain into the next 32 bytes
            buffer[32..64].copy_from_slice(&self.domain);
            
            // Hash the concatenated buffer
            let hash_bytes = eth_hash(&buffer);
            
            // Convert to the expected Hash256 type
            tree_hash::Hash256::from_slice(&hash_bytes)
        }
    }
    
    // Create SigningData and compute its tree hash root
    let signing_data = SigningData {
        object_root: message_root,
        domain,
    };
    
    // Convert the tree_hash_root result to the expected Hash256 type
    let hash = signing_data.tree_hash_root();
    Hash256::from_slice(hash.as_ref())
}

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
    let genesis_validators_root = get_genesis_validators_root(chain)?;

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

    // 3. Calculate Signing Domain & Root according to ETH2 specs
    let message_root = tree_hash::TreeHash::tree_hash_root(&message);
    let domain = compute_domain(DOMAIN_DEPOSIT, fork_version, genesis_validators_root);
    let signing_root = compute_signing_root(message_root, domain);

    // 4. Sign DepositMessage with the correct signing root
    let signature = validator_sk.sign(signing_root);

    // 5. Calculate Deposit Message Root (SSZ hash tree root of DepositMessage)
    let deposit_message_root = tree_hash::TreeHash::tree_hash_root(&message);

    // 6. Construct DepositData (Lighthouse type)
    let deposit_data = DepositData {
        pubkey: message.pubkey,
        withdrawal_credentials: message.withdrawal_credentials,
        amount: message.amount,
        signature: SignatureBytes::from(signature), // Check conversion
    };

    // 7. Calculate Deposit Data Root (SSZ hash tree root of DepositData)
    let deposit_data_root = tree_hash::TreeHash::tree_hash_root(&deposit_data);


    // 8. Construct the final serializable struct
    let deposit_data_file = DepositDataFile {
        pubkey: hex::encode(deposit_data.pubkey.as_ssz_bytes()),
        withdrawal_credentials: hex::encode(deposit_data.withdrawal_credentials.to_vec()),
        amount: deposit_data.amount, // Already in Gwei
        signature: hex::encode(deposit_data.signature.as_ssz_bytes()),
        deposit_message_root: hex::encode(deposit_message_root.to_vec()),
        deposit_data_root: hex::encode(deposit_data_root.to_vec()),
        fork_version: hex::encode(fork_version),
        network_name,
        deposit_cli_version: DEPOSIT_CLI_VERSION.to_string(),
    };

    Ok(deposit_data_file)
    // Err(anyhow!("Deposit data generation not fully implemented yet")) // Remove placeholder error
}

// TODO: Add unit tests for helper functions and core logic (especially credential formatting, roots).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlsMode;
    use crate::wallet::Chain;
    use blst::min_pk::SecretKey as BlstSecretKey;
    use hex;

    // Helper function to create a test secret key
    fn create_test_secret_key() -> (SecretKey, PublicKey) {
        // Create a deterministic test key
        let seed = [1u8; 32]; // Simple seed for testing
        let sk = BlstSecretKey::key_gen(&seed, &[]).unwrap();
        
        // Convert to the types expected by our functions
        let secret_key = SecretKey::deserialize(&sk.serialize()).unwrap();
        // Generate public key directly from the secret key using the public API
        let public_key = secret_key.public_key();
        
        (secret_key, public_key)
    }

    #[test]
    fn test_parse_hex_bytes() {
        // Test valid hex string with 0x prefix
        let result = parse_hex_bytes::<4>("0x01020304").unwrap();
        assert_eq!(result, [1, 2, 3, 4]);
        
        // Test valid hex string without 0x prefix
        let result = parse_hex_bytes::<4>("05060708").unwrap();
        assert_eq!(result, [5, 6, 7, 8]);
        
        // Test invalid length
        let result = parse_hex_bytes::<4>("0x0102");
        assert!(result.is_err());
        
        // Test invalid hex characters
        let result = parse_hex_bytes::<4>("0x0102ZZ");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_get_genesis_validators_root() {
        // Test that both chains return a zero hash
        let mainnet_root = get_genesis_validators_root(&Chain::Mainnet).unwrap();
        let hoodi_root = get_genesis_validators_root(&Chain::Hoodi).unwrap();
        
        // Both should be zero hashes
        let zero_hash = [0u8; 32];
        assert_eq!(mainnet_root.to_vec(), zero_hash);
        assert_eq!(hoodi_root.to_vec(), zero_hash);
        
        // Both chains should return the same value
        assert_eq!(mainnet_root, hoodi_root);
    }
    
    #[test]
    fn test_get_electra_fork_version() {
        // Test mainnet
        let version = get_electra_fork_version(&Chain::Mainnet);
        assert_eq!(version, MAINNET_ELECTRA_FORK_VERSION);
        
        // Test hoodi
        let version = get_electra_fork_version(&Chain::Hoodi);
        assert_eq!(version, HOODI_ELECTRA_FORK_VERSION);
    }
    
    #[test]
    fn test_get_network_name() {
        assert_eq!(get_network_name(&Chain::Mainnet), "mainnet");
        assert_eq!(get_network_name(&Chain::Hoodi), "hoodi");
    }
    
    #[test]
    fn test_format_withdrawal_credentials_eth1() {
        // Test ETH1 (01) credentials
        let address = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
        let result = format_withdrawal_credentials(address, &BlsMode::Eth1).unwrap();
        
        // First byte should be 0x01 for ETH1
        assert_eq!(result[0], ETH1_ADDRESS_WITHDRAWAL_PREFIX);
        
        // Next 11 bytes should be zeros
        for i in 1..12 {
            assert_eq!(result[i], 0);
        }
        
        // Last 20 bytes should be the ETH address (without 0x prefix)
        let address_bytes = hex::decode(&address[2..]).unwrap();
        for i in 0..20 {
            assert_eq!(result[i+12], address_bytes[i]);
        }
    }
    
    #[test]
    fn test_format_withdrawal_credentials_pectra() {
        // Test Pectra (02) credentials
        let address = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
        let result = format_withdrawal_credentials(address, &BlsMode::Pectra).unwrap();
        
        // First byte should be 0x02 for Pectra
        assert_eq!(result[0], ETH2_ADDRESS_WITHDRAWAL_PREFIX);
        
        // Next 11 bytes should be zeros
        for i in 1..12 {
            assert_eq!(result[i], 0);
        }
        
        // Last 20 bytes should be the ETH address (without 0x prefix)
        let address_bytes = hex::decode(&address[2..]).unwrap();
        for i in 0..20 {
            assert_eq!(result[i+12], address_bytes[i]);
        }
    }
    
    #[test]
    fn test_format_withdrawal_credentials_invalid_address() {
        // Test invalid address (too short)
        let result = format_withdrawal_credentials("0x123", &BlsMode::Eth1);
        assert!(result.is_err());
        
        // Test invalid address (no 0x prefix)
        let result = format_withdrawal_credentials("71C7656EC7ab88b098defB751B7401B5f6d8976F", &BlsMode::Eth1);
        assert!(result.is_err());
        
        // Test invalid address (invalid hex)
        let result = format_withdrawal_credentials("0x71C7656EC7ab88b098defB751B7401B5f6d897ZZ", &BlsMode::Eth1);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_generate_deposit_data_eth1() {
        // Create test keys
        let (sk, pk) = create_test_secret_key();
        
        // Generate deposit data for ETH1 mode
        let result = generate_deposit_data(
            &pk,
            &sk,
            "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
            &BlsMode::Eth1,
            32, // 32 ETH
            &Chain::Mainnet
        ).unwrap();
        
        // Verify basic properties
        assert!(!result.pubkey.is_empty());
        assert!(!result.withdrawal_credentials.is_empty());
        assert_eq!(result.amount, 32 * GWEI_PER_ETH);
        assert!(!result.signature.is_empty());
        assert!(!result.deposit_message_root.is_empty());
        assert!(!result.deposit_data_root.is_empty());
        assert_eq!(result.fork_version, "00000000");
        assert_eq!(result.network_name, "mainnet");
        assert_eq!(result.deposit_cli_version, DEPOSIT_CLI_VERSION);
        
        // Verify withdrawal credentials starts with 01 for ETH1
        assert_eq!(&result.withdrawal_credentials[0..2], "01");
    }
    
    #[test]
    fn test_generate_deposit_data_pectra() {
        // Create test keys
        let (sk, pk) = create_test_secret_key();
        
        // Generate deposit data for Pectra mode
        let result = generate_deposit_data(
            &pk,
            &sk,
            "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
            &BlsMode::Pectra,
            64, // 64 ETH (Pectra allows more than 32)
            &Chain::Mainnet
        ).unwrap();
        
        // Verify basic properties
        assert!(!result.pubkey.is_empty());
        assert!(!result.withdrawal_credentials.is_empty());
        assert_eq!(result.amount, 64 * GWEI_PER_ETH);
        assert!(!result.signature.is_empty());
        assert!(!result.deposit_message_root.is_empty());
        assert!(!result.deposit_data_root.is_empty());
        assert_eq!(result.fork_version, "00000000");
        assert_eq!(result.network_name, "mainnet");
        assert_eq!(result.deposit_cli_version, DEPOSIT_CLI_VERSION);
        
        // Verify withdrawal credentials starts with 02 for Pectra
        assert_eq!(&result.withdrawal_credentials[0..2], "02");
    }
    
    // Helper function to create a test secret key with a specific seed
    #[allow(dead_code)]
    fn create_test_secret_key_with_seed(seed_value: u8) -> (SecretKey, PublicKey) {
        // Create a deterministic test key with the provided seed
        let mut seed = [0u8; 32];
        seed[0] = seed_value; // Use different seed values to get different keys
        let sk = BlstSecretKey::key_gen(&seed, &[]).unwrap();
        
        // Convert to the types expected by our functions
        let secret_key = SecretKey::deserialize(&sk.serialize()).unwrap();
        let public_key = secret_key.public_key();
        
        (secret_key, public_key)
    }

    #[test]
    fn test_generate_deposit_data_different_chains() {
        // Create different test keys for each chain to ensure different signatures
        let (sk1, pk1) = create_test_secret_key();
        
        // Create a second key with a different seed
        let mut seed = [0u8; 32];
        seed[0] = 42; // Different seed value
        let sk2 = BlstSecretKey::key_gen(&seed, &[]).unwrap();
        let sk2 = SecretKey::deserialize(&sk2.serialize()).unwrap();
        let pk2 = sk2.public_key();
        
        let withdrawal_address = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
        
        // Generate deposit data for mainnet
        let mainnet_result = generate_deposit_data(
            &pk1,
            &sk1,
            withdrawal_address,
            &BlsMode::Eth1,
            32,
            &Chain::Mainnet
        ).unwrap();
        
        // Generate deposit data for hoodi
        let hoodi_result = generate_deposit_data(
            &pk2,
            &sk2,
            withdrawal_address,
            &BlsMode::Eth1,
            32,
            &Chain::Hoodi
        ).unwrap();
        
        // Network name should be different
        assert_eq!(mainnet_result.network_name, "mainnet");
        assert_eq!(hoodi_result.network_name, "hoodi");
        
        // Verify the fork versions are different
        let mainnet_fork = get_electra_fork_version(&Chain::Mainnet);
        let hoodi_fork = get_electra_fork_version(&Chain::Hoodi);
        assert_ne!(mainnet_fork, hoodi_fork, "Fork versions should be different");
        
        // Verify the genesis validators roots are now the same (zero hash) for both chains
        // This matches the official implementation
        let mainnet_root = get_genesis_validators_root(&Chain::Mainnet).unwrap();
        let hoodi_root = get_genesis_validators_root(&Chain::Hoodi).unwrap();
        assert_eq!(mainnet_root, hoodi_root, "Genesis validators roots should both be zero hash");
        
        // Verify that the deposit data signatures are different
        // This will be true because we're using different keys and different chains
        assert_ne!(mainnet_result.signature, hoodi_result.signature, 
            "Signatures should be different for different keys and chains");
        
        // Additional verification: same key, different chains should still have different signatures
        let mainnet_result2 = generate_deposit_data(
            &pk1,
            &sk1,
            withdrawal_address,
            &BlsMode::Eth1,
            32,
            &Chain::Mainnet
        ).unwrap();
        
        let hoodi_result2 = generate_deposit_data(
            &pk1,
            &sk1,
            withdrawal_address,
            &BlsMode::Eth1,
            32,
            &Chain::Hoodi
        ).unwrap();
        
        // Even with the same key, different chains should produce different signatures
        // due to domain separation (different fork versions and genesis validators roots)
        assert_ne!(mainnet_result2.signature, hoodi_result2.signature,
            "Same key but different chains should still produce different signatures");
    }
}
