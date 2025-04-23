



use anyhow::{anyhow, Result};
use clap::ValueEnum;
use serde::Serialize;
use std::path::PathBuf;
use crate::keygen::ValidatorKeyPair;
use bip39::Mnemonic;

/// Validator keys and mnemonic
#[derive(Debug)]
pub struct ValidatorKeys {
    #[allow(dead_code)]
    pub mnemonic: Mnemonic,
    pub key_pair: ValidatorKeyPair,
}

/// Supported Ethereum networks
#[derive(Debug, Clone, ValueEnum, Serialize)]
pub enum Chain {
    /// Ethereum mainnet
    Mainnet,
    /// Hoodi testnet
    Hoodi, // Corrected spelling
}

/// Output format for wallet generation
#[derive(Debug, Clone, ValueEnum, Default, PartialEq)]
pub enum OutputMode {
    /// Write artifacts to disk in output directory
    #[default]
    Files,
    /// Return artifacts as JSON structure
    Json,

}

/// KDF type for keystore encryption
#[derive(Debug, Clone, ValueEnum, Default, PartialEq, Serialize)] // Added Serialize
pub enum KdfMode {
    /// Use scrypt KDF (more secure, slower)
    #[default]
    Scrypt,
    /// Use PBKDF2 KDF (less secure, faster)
    Pbkdf2,
}

/// Parameters for wallet generation
#[derive(Debug, Clone)]
pub struct WalletParams {
    /// Optional BIP-39 mnemonic for key derivation
    pub mnemonic: Option<String>,
    /// Amount of ETH to stake per validator
    pub eth_amount: u64,
    /// Staker's withdrawal address
    pub withdrawal_address: String,
    /// BLS mode (determines withdrawal credential type)
    pub bls_mode: crate::BlsMode, // Use type from main.rs
    /// Password for encrypting the keystore
    pub password: Option<String>,
    /// Target network
    #[allow(dead_code)]
    pub chain: Chain,
    /// Output directory for wallet files
    pub output_dir: PathBuf,
    /// KDF type for keystore encryption
    pub kdf_mode: KdfMode,
    /// Validator index for key derivation path
    pub validator_index: u32,
}

/// Generated wallet artifacts
#[derive(Debug, Serialize, Clone)]
pub struct WalletArtifacts {
    /// 0x02 withdrawal credentials
    pub withdrawal_credentials: String,
    pub keystore: Option<crate::keystore::Keystore>,
}

/// Output variants for wallet generation
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum WalletOutput {
    /// Write artifacts to files in directory
    Files {
        output_dir: PathBuf,
        artifacts: WalletArtifacts,
    },
    /// Return artifacts as JSON
    Json(WalletArtifacts),
}

impl WalletParams {
    /// Generate validator keys from the provided or new mnemonic
    pub fn generate_keys(&self) -> Result<ValidatorKeys> {
        // Get or generate mnemonic
        let mnemonic = crate::keygen::get_mnemonic(self.mnemonic.clone())?;

        // Generate validator keys with the specified index
        let key_pair = crate::keygen::generate_validator_keys(&mnemonic, self.validator_index)?;

        Ok(ValidatorKeys {
            mnemonic,
            key_pair,
        })
    }

    /// Validate all wallet parameters before generation
    /// NOTE: Amount validation is now solely handled in main.rs based on CLI context
    pub fn validate(&self) -> Result<()> {
        // Amount validation removed - handled in main.rs

        // Validate withdrawal address
        if !self.withdrawal_address.starts_with("0x") {
            return Err(anyhow::anyhow!("Withdrawal address must start with 0x"));
        }
        if self.withdrawal_address.len() != 42 {
            return Err(anyhow::anyhow!("Withdrawal address must be 42 characters long"));
        }
        if !self.withdrawal_address[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow::anyhow!("Withdrawal address contains invalid characters"));
        }

        // Validate mnemonic if provided
        if let Some(ref mnemonic) = self.mnemonic {
            let mnemonic = crate::keygen::get_mnemonic(Some(mnemonic.clone()))?;
            if mnemonic.word_count() != 24 {
                return Err(anyhow!("Mnemonic must be 24 words for validator keys"));
            }
        }

        // Validate password
        if let Some(pass) = &self.password {
            if pass.len() < 8 {
                return Err(anyhow::anyhow!("Password must be at least 8 characters long"));
            }
        }

        // Validate output directory path
        if let Some(parent) = self.output_dir.parent() {
            if !parent.exists() {
                return Err(anyhow::anyhow!("Parent directory does not exist: {}", parent.display()));
            }
        }

        // Validate output directory
        if self.output_dir.to_str().is_none() {
            return Err(anyhow::anyhow!("Output directory path is invalid UTF-8"));
        }

        // All validations passed
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_params() -> WalletParams {
        WalletParams {
            mnemonic: None,
            eth_amount: 32,
            withdrawal_address: "0x71C7656EC7ab88b098defB751B7401B5f6d8976F".to_string(),
            bls_mode: crate::BlsMode::Pectra, // Add default type for tests
            password: Some("testpassword123".to_string()),
            chain: Chain::Hoodi,
            output_dir: PathBuf::from("./output"),
            kdf_mode: KdfMode::Scrypt,
            validator_index: 0,
        }
    }

    // Removed test_eth_amount_validation as this logic is now solely handled in main.rs and tested via integration tests

    #[test]
    fn test_withdrawal_address_validation() -> Result<()> {
        let mut params = create_test_params();

        // Valid address
        assert!(params.validate().is_ok());

        // Invalid addresses
        params.withdrawal_address = "not-an-address".to_string();
        assert!(params.validate().is_err());
        params.withdrawal_address = "0x123".to_string();
        assert!(params.validate().is_err());
        params.withdrawal_address = "0xXYZ7656EC7ab88b098defB751B7401B5f6d8976F".to_string();
        assert!(params.validate().is_err());

        Ok(())
    }

    #[test]
    fn test_password_validation() -> Result<()> {
        let mut params = create_test_params();

        // Valid password
        assert!(params.validate().is_ok());

        // Invalid passwords
        params.password = Some("short".to_string());
        assert!(params.validate().is_err());
        params.password = None;
        assert!(params.validate().is_ok()); // None is ok for validation, required at keystore creation

        Ok(())
    }

    #[test]
    fn test_mnemonic_validation() -> Result<()> {
        let mut params = create_test_params();

        // No mnemonic is valid (will generate new)
        assert!(params.validate().is_ok());

        // Valid 24-word mnemonic
        params.mnemonic = Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art".to_string());
        assert!(params.validate().is_ok());

        // Invalid mnemonics
        params.mnemonic = Some("not a valid mnemonic phrase at all".to_string());
        assert!(params.validate().is_err());

        // 12-word mnemonic should fail (we require 24 words)
        params.mnemonic = Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string());
        assert!(params.validate().is_err());

        Ok(())
    }

    #[test]
    fn test_wallet_output_formats() -> Result<()> {
        let _params = create_test_params();
        let artifacts = WalletArtifacts {
            withdrawal_credentials: "0x1234567890123456789012345678901234567890".to_string(),
            keystore: None,
        };

        // Test Files output
        let output_dir = PathBuf::from("test_output");
        let files_output = WalletOutput::Files {
            output_dir: output_dir.clone(),
            artifacts: artifacts.clone(),
        };
        match files_output {
            WalletOutput::Files { output_dir: dir, artifacts: _ } => {
                assert_eq!(dir, output_dir);
            }
            _ => panic!("Expected Files variant"),
        }

        // Test Json output
        let json_output = WalletOutput::Json(artifacts.clone());
        match json_output {
            WalletOutput::Json(artifacts) => {
                assert_eq!(artifacts.withdrawal_credentials, "0x1234567890123456789012345678901234567890");
            }
            _ => panic!("Expected Json variant"),
        }

        Ok(())
    }

    #[test]
    fn test_wallet_artifacts() -> Result<()> {
        let params = create_test_params();
        let _keys = params.generate_keys()?;
        
        let artifacts = WalletArtifacts {
            withdrawal_credentials: "0x1234567890123456789012345678901234567890".to_string(),
            keystore: None,
        };

        // Check withdrawal credentials format
        assert!(artifacts.withdrawal_credentials.starts_with("0x"));
        assert_eq!(artifacts.withdrawal_credentials.len(), 42); // 0x + 40 hex chars
        assert!(artifacts.withdrawal_credentials.chars().skip(2).all(|c| c.is_ascii_hexdigit()));

        Ok(())
    }

    #[test]
    fn test_key_generation() -> Result<()> {
        let params = create_test_params();
        let keys = params.generate_keys()?;

        // Verify we got valid keys
        assert_eq!(keys.key_pair.keypair.pk.serialize().len(), 48);

        // Verify deterministic generation with same mnemonic
        let mut params2 = params.clone();
        params2.mnemonic = Some(keys.mnemonic.to_string());
        let keys2 = params2.generate_keys()?;

        assert_eq!(keys.key_pair.keypair.pk.serialize(), keys2.key_pair.keypair.pk.serialize());

        Ok(())
    }
}
