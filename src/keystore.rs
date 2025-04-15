use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use blst::min_pk::SecretKey;
use sha2::{Sha256, Digest};
use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use std::collections::HashMap;
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::Path;
use scrypt::{scrypt, Params as ScryptParams};
use hex;

/// EIP-2335 keystore parameters
const SCRYPT_N: u32 = 262144; // 2^18
const SCRYPT_P: u32 = 1;
const SCRYPT_R: u32 = 8;
const SCRYPT_DKLEN: usize = 32;

/// EIP-2335 keystore version
const VERSION: u32 = 4;

/// Keystore crypto functions
const CIPHER: &str = "aes-128-ctr";

/// KDF options
#[derive(Debug, Clone, Copy)]
pub enum KdfType {
    Scrypt,
    Pbkdf2,
}

impl KdfType {


    fn derive_key(&self, password: &[u8], salt: &[u8], output: &mut [u8]) -> Result<()> {
        match self {
            KdfType::Scrypt => {
                scrypt(
                    password,
                    salt,
                    &ScryptParams::new(SCRYPT_N.ilog2() as u8, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)?,
                    output,
                )?;
            }
            KdfType::Pbkdf2 => {
                use pbkdf2::pbkdf2_hmac;
                pbkdf2_hmac::<sha2::Sha256>(
                    password,
                    salt,
                    262144, // Same as scrypt N parameter
                    output,
                );
            }
        }
        Ok(())
    }
}

/// EIP-2335 keystore structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    /// Keystore version (must be 4)
    pub version: u32,
    /// Random UUID for keystore
    pub uuid: String,
    /// Path for BLS key derivation
    pub path: String,
    /// Public key
    pub pubkey: String,
    /// Crypto parameters
    pub crypto: CryptoData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Crypto parameters for keystore
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoData {
    /// KDF parameters
    pub kdf: KdfData,
    /// Cipher parameters
    pub cipher: CipherData,
    /// Checksum for verification
    pub checksum: ChecksumData,
}

/// KDF parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "function")]
#[serde(rename_all = "lowercase")]
pub enum KdfData {
    Scrypt {
        params: ScryptData,
        message: String,
    },
    Pbkdf2 {
        params: Pbkdf2Data,
        message: String,
    },
}

/// PBKDF2 parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct Pbkdf2Data {
    pub dklen: usize,
    pub c: u32,
    pub salt: String,
    pub prf: String,
}

/// Scrypt parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct ScryptData {
    pub dklen: usize,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    pub salt: String,
}

/// Cipher parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherData {
    /// Cipher algorithm
    pub function: String,
    /// Cipher parameters
    pub params: CipherParams,
    /// Encrypted private key
    pub message: String,
}

/// AES-128-CTR parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    /// Initialization vector
    pub iv: String,
}

/// Checksum parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumData {
    /// Checksum function (sha256)
    pub function: String,
    /// Checksum parameters (empty)
    pub params: HashMap<String, String>,
    /// Checksum message
    pub message: String,
}

/// Generate an EIP-2335 keystore for a BLS secret key
pub fn generate_keystore(secret_key: &SecretKey, password: &str, path: &str, kdf_type: KdfType) -> Result<Keystore> {
    // Generate random salt and IV
    let mut salt = [0u8; 32];
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);

    // Derive encryption key
    let mut encryption_key = [0u8; SCRYPT_DKLEN];
    kdf_type.derive_key(password.as_bytes(), &salt, &mut encryption_key)?;

    // Encrypt secret key
    let mut cipher = Ctr128BE::<Aes128>::new(
        generic_array::GenericArray::from_slice(&encryption_key[..16]),
        generic_array::GenericArray::from_slice(&iv),
    );
    let mut encrypted_key = secret_key.serialize();
    cipher.apply_keystream(&mut encrypted_key);

    // Calculate checksum
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&encryption_key[16..]);
    hasher.update(&encrypted_key);
    let checksum = hasher.finalize();

    // Get public key in compressed format
    let pubkey = secret_key.sk_to_pk().compress();

    // Create KDF data based on type
    let kdf = match kdf_type {
        KdfType::Scrypt => KdfData::Scrypt {
            params: ScryptData {
                dklen: SCRYPT_DKLEN,
                n: SCRYPT_N,
                p: SCRYPT_P,
                r: SCRYPT_R,
                salt: hex::encode(salt),
            },
            message: String::new(),
        },
        KdfType::Pbkdf2 => KdfData::Pbkdf2 {
            params: Pbkdf2Data {
                dklen: SCRYPT_DKLEN,
                c: 262144,
                salt: hex::encode(salt),
                prf: "hmac-sha256".to_string(),
            },
            message: String::new(),
        },
    };

    // Create keystore
    let keystore = Keystore {
        version: VERSION,
        uuid: Uuid::new_v4().to_string(),
        path: path.to_string(),
        pubkey: hex::encode(pubkey),
        description: Some("Validator signing key".to_string()),
        crypto: CryptoData {
            kdf,
            cipher: CipherData {
                function: "aes-128-ctr".to_string(),
                params: CipherParams {
                    iv: hex::encode(iv),
                },
                message: hex::encode(encrypted_key),
            },
            checksum: ChecksumData {
                function: "sha256".to_string(),
                params: Default::default(),
                message: hex::encode(checksum),
            },
        },
    };

    Ok(keystore)
}

/// Write a keystore to a file
pub fn write_keystore(keystore: &Keystore, output_dir: &Path) -> Result<()> {
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir)?;

    // Generate keystore filename: UTC--<ISO8601>-<UUID>
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S%.3fZ");
    let filename = format!("UTC--{}--{}", timestamp, keystore.uuid);
    let path = output_dir.join(filename);

    // Write keystore JSON
    let json = serde_json::to_string_pretty(keystore)?;
    std::fs::write(path, json)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use blst::min_pk::SecretKey;

    /// Test vectors from EIP-2335
    const TEST_VECTORS: [&str; 2] = [
        // Scrypt test vector
        r#"{
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
                        "r": 8,
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
                }
            },
            "description": "This is a test keystore that uses scrypt to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/3600/0/0/0",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "version": 4
        }"#,
        // PBKDF2 test vector
        r#"{
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                }
            },
            "description": "This is a test keystore that uses pbkdf2 to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/3600/0/0/0",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "version": 4
        }"#
    ];

    fn create_test_key() -> SecretKey {
        // Create a deterministic test key
        let ikm = [1u8; 32]; // Use fixed input key material for testing
        SecretKey::key_gen(&ikm, &[]).expect("Failed to generate test key")
    }

    #[test]
    fn test_keystore_format() -> Result<()> {
        // Test both scrypt and pbkdf2 test vectors
        for (_i, test_vector) in TEST_VECTORS.iter().enumerate() {
            let test_keystore: Keystore = serde_json::from_str(test_vector)?;

            // Generate a keystore with the same parameters
            let mut ikm = [0u8; 32];
            let mut rng = OsRng;
            rng.fill_bytes(&mut ikm);
            let secret_key = SecretKey::key_gen(&ikm, &[]).unwrap();
            let password = "testpassword";
            let path = test_keystore.path.clone();
            let kdf_type = match &test_keystore.crypto.kdf {
                KdfData::Scrypt { .. } => KdfType::Scrypt,
                KdfData::Pbkdf2 { .. } => KdfType::Pbkdf2,
            };

            let keystore = generate_keystore(&secret_key, password, &path, kdf_type)?;

            // Verify field lengths
            let salt_len = match &keystore.crypto.kdf {
                KdfData::Scrypt { params, .. } => hex::decode(&params.salt)?.len(),
                KdfData::Pbkdf2 { params, .. } => hex::decode(&params.salt)?.len(),
            };
            assert_eq!(salt_len, 32);
            assert_eq!(hex::decode(&keystore.crypto.cipher.params.iv)?.len(), 16);
            assert_eq!(hex::decode(&keystore.crypto.cipher.message)?.len(), 32);
            assert_eq!(hex::decode(&keystore.crypto.checksum.message)?.len(), 32);

            // Verify scrypt params if applicable
            if let KdfData::Scrypt { params, .. } = &keystore.crypto.kdf {
                assert_eq!(params.r, SCRYPT_R);
            }
        }

        Ok(())
    }

    #[test]
    fn test_keystore_file_output() -> Result<()> {
        let secret_key = create_test_key();
        let password = "test1234";
        let path = "m/12381/3600/0/0/0";

        // Test both KDF types
        for kdf_type in [KdfType::Scrypt, KdfType::Pbkdf2] {
            let keystore = generate_keystore(&secret_key, password, path, kdf_type)?;

            // Create a temporary directory for testing
            let temp_dir = tempdir()?;
            let _keystore_path = temp_dir.path().join("keystore.json");

            write_keystore(&keystore, temp_dir.path())?;

            // Verify file exists and is valid JSON
            let files: Vec<_> = std::fs::read_dir(temp_dir.path())?.collect();
            assert_eq!(files.len(), 1);

            let file_content = std::fs::read_to_string(&files[0].as_ref().unwrap().path())?;
            let parsed: Keystore = serde_json::from_str(&file_content)?;

            assert_eq!(parsed.version, VERSION);
            assert_eq!(parsed.uuid, keystore.uuid);
        }
        Ok(())
    }

    #[test]
    fn test_keystore_decryption() -> Result<()> {
        // Test vectors use password "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"
        let password_bytes = hex::decode("7465737470617373776f7264f09f9491")?;
        let password = String::from_utf8(password_bytes)?;
        let expected_secret = hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")?;

        // Test both scrypt and pbkdf2 vectors
        for (i, test_vector) in TEST_VECTORS.iter().enumerate() {
            let test_keystore: Keystore = serde_json::from_str(test_vector)?;
            
            // Derive encryption key
            let mut encryption_key = [0u8; SCRYPT_DKLEN];
            
            // Get salt and derive key based on KDF type
            let (kdf_type, salt) = match &test_keystore.crypto.kdf {
                KdfData::Scrypt { params, .. } => (KdfType::Scrypt, hex::decode(&params.salt)?),
                KdfData::Pbkdf2 { params, .. } => (KdfType::Pbkdf2, hex::decode(&params.salt)?),
            };
            kdf_type.derive_key(password.as_bytes(), &salt, &mut encryption_key)?;

            // Verify checksum
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&encryption_key[16..]);
            let encrypted_key = hex::decode(&test_keystore.crypto.cipher.message)?;
            hasher.update(&encrypted_key);
            let checksum = hasher.finalize();
            assert_eq!(hex::encode(checksum), test_keystore.crypto.checksum.message, "Checksum mismatch for vector {}", i);

            // Decrypt secret key
            let iv = hex::decode(&test_keystore.crypto.cipher.params.iv)?;
            let mut cipher = Ctr128BE::<Aes128>::new(
                generic_array::GenericArray::from_slice(&encryption_key[..16]),
                generic_array::GenericArray::from_slice(&iv),
            );
            let mut decrypted_key = encrypted_key.clone();
            cipher.apply_keystream(&mut decrypted_key);

            // Verify decrypted secret matches
            assert_eq!(decrypted_key, expected_secret, "Secret mismatch for vector {}", i);

            // Create secret key and verify public key matches
            let secret_key = SecretKey::from_bytes(&decrypted_key)
                .map_err(|e| anyhow!("Failed to create secret key: {:?}", e))?;
            let public_key = secret_key.sk_to_pk();
            assert_eq!(
                hex::encode(public_key.to_bytes()),
                "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
                "Public key mismatch for test vector"
            );
        }
        Ok(())
    }
}
