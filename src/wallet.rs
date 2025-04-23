



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
