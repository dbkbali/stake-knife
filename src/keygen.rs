use anyhow::{anyhow, Result};
use bip39::{Language, Mnemonic};
use eth2_key_derivation::DerivedKey;
use eth2_wallet::{KeyType, ValidatorPath};
use types::{Keypair, SecretKey};

/// Represents a validator key pair
#[derive(Debug)]
pub struct ValidatorKeyPair {
    pub keypair: Keypair,
}

/// Generate or validate a BIP-39 mnemonic
pub fn get_mnemonic(mnemonic_str: Option<String>) -> Result<Mnemonic> {
    match mnemonic_str {
        Some(phrase) => {
            // Validate existing mnemonic
            Mnemonic::parse_in(Language::English, &phrase)
                .map_err(|e| anyhow!("Invalid mnemonic: {}", e))
        }
        None => {
            // Generate new mnemonic
            Mnemonic::generate_in(Language::English, 24)
                .map_err(|e| anyhow!("Failed to generate mnemonic: {}", e))
        }
    }
}

/// Generate validator keys from a mnemonic following EIP-2333 and EIP-2334
/// 
/// * `mnemonic` - The BIP-39 mnemonic
/// * `validator_index` - The validator index (i) for the EIP-2334 path
pub fn generate_validator_keys(mnemonic: &Mnemonic, validator_index: u32) -> Result<ValidatorKeyPair> {
    // Debug: Print the mnemonic phrase to verify it's consistent
    // println!("DEBUG: Using mnemonic: {}", mnemonic.to_string()); // Commented out
    // println!("DEBUG: Validator index: {}", validator_index); // Commented out

    // Generate seed from mnemonic (empty password)
    let seed = mnemonic.to_seed("");
    // println!("DEBUG: Seed (first 8 bytes): {:?}", &seed[..8]); // Commented out

    // Create master key from seed using eth2 key derivation
    let master = DerivedKey::from_seed(&seed)
        .map_err(|_| anyhow!("Failed to derive master key"))?;

    // Use ValidatorPath to handle EIP-2334 path construction
    let voting_path = ValidatorPath::new(validator_index, KeyType::Voting);
    
    // Derive through the path nodes to get the signing key
    let signing_key = voting_path.iter_nodes().fold(master, |dk, i| dk.child(*i));
    
    // Convert to BLS keypair
    let secret_key = SecretKey::deserialize(signing_key.secret())
        .map_err(|_| anyhow!("Failed to deserialize secret key"))?;
    let public_key = secret_key.public_key();
    let keypair = Keypair::from_components(public_key, secret_key);

    Ok(ValidatorKeyPair { keypair })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_new_mnemonic_generation() -> Result<()> {
        let mnemonic = get_mnemonic(None)?;
        assert_eq!(mnemonic.word_count(), 24);
        
        // Verify mnemonic is valid
        let mnemonic_str = mnemonic.to_string();
        let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
        assert_eq!(words.len(), 24);
        assert!(words.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase())));
        
        Ok(())
    }

    #[test]
    fn test_existing_mnemonic_validation() -> Result<()> {
        // Valid mnemonic should work
        let mnemonic = get_mnemonic(Some(TEST_MNEMONIC.to_string()))?;
        assert_eq!(mnemonic.word_count(), 24);

        // Invalid mnemonic should fail
        let result = get_mnemonic(Some("invalid mnemonic".to_string()));
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_validator_key_generation() -> Result<()> {
        let mnemonic = get_mnemonic(None)?;
        let validator_index = 0;
        let keys = generate_validator_keys(&mnemonic, validator_index)?;
        
        // Verify public key is derived from secret key
        // Verify public key is correct size
        assert_eq!(keys.keypair.pk.serialize().len(), 48); // BLS12-381 G1 point is 48 bytes
        
        Ok(())
    }

    #[test]
    fn test_deterministic_key_generation() -> Result<()> {
        // Same mnemonic and index should produce same keys
        let mnemonic1 = get_mnemonic(Some(TEST_MNEMONIC.to_string()))?;
        let mnemonic2 = get_mnemonic(Some(TEST_MNEMONIC.to_string()))?;
        let validator_index = 0;

        let keys1 = generate_validator_keys(&mnemonic1, validator_index)?;
        let keys2 = generate_validator_keys(&mnemonic2, validator_index)?;

        assert_eq!(keys1.keypair.pk.serialize(), keys2.keypair.pk.serialize());

        Ok(())
    }

    #[test]
    fn test_different_mnemonics_different_keys() -> Result<()> {
        // Different mnemonics should produce different keys
        let mnemonic1 = get_mnemonic(None)?;
        let mnemonic2 = get_mnemonic(None)?;
        let validator_index = 0;

        let keys1 = generate_validator_keys(&mnemonic1, validator_index)?;
        let keys2 = generate_validator_keys(&mnemonic2, validator_index)?;

        assert_ne!(keys1.keypair.pk.serialize(), keys2.keypair.pk.serialize());

        Ok(())
    }
    
    #[test]
    fn test_different_indices_different_keys() -> Result<()> {
        // Same mnemonic but different indices should produce different keys
        let mnemonic = get_mnemonic(Some(TEST_MNEMONIC.to_string()))?;
        
        let keys1 = generate_validator_keys(&mnemonic, 0)?;
        let keys2 = generate_validator_keys(&mnemonic, 1)?;
        let keys3 = generate_validator_keys(&mnemonic, 100)?;

        // All keys should be different
        assert_ne!(keys1.keypair.pk.serialize(), keys2.keypair.pk.serialize());
        assert_ne!(keys1.keypair.pk.serialize(), keys3.keypair.pk.serialize());
        assert_ne!(keys2.keypair.pk.serialize(), keys3.keypair.pk.serialize());

        Ok(())
    }
}
