use anyhow::Result;
use assert_cmd::Command;
use tempfile::TempDir;
use serde_json::Value;
use std::fs;
use regex::Regex;

// Valid 24-word test mnemonic
const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

const SMITH_MNEMONIC: &str = "ribbon place hobby useless drink exhaust dolphin giraffe orchard talk census connect labor fade wage hole cigar lobster mechanic dolphin spice cactus cup nuclear";

#[test]
fn test_consistent_key_derivation() -> Result<()> {
    // Create temporary directories for test output
    let temp_dir1 = TempDir::new()?;
    let temp_dir2 = TempDir::new()?;
    
    let output_path1 = temp_dir1.path().to_str().unwrap();
    let output_path2 = temp_dir2.path().to_str().unwrap();
    
    // Generate keys for validator index 5 (first run)
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output1 = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--mnemonic").arg(TEST_MNEMONIC)
        .arg("--eth-amount").arg("32")
        .arg("--withdrawal-address").arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password").arg("testpassword123")
        .arg("--validator-index").arg("5")
        .arg("--validator-count").arg("1")
        .arg("--output-dir").arg(output_path1)
        .output()?;
    
    assert!(output1.status.success(), "First command failed: {}", String::from_utf8_lossy(&output1.stderr));
    
    // Generate keys for validator index 5 again (second run)
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output2 = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--mnemonic").arg(TEST_MNEMONIC)
        .arg("--eth-amount").arg("32")
        .arg("--withdrawal-address").arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password").arg("testpassword123")
        .arg("--validator-index").arg("5")
        .arg("--validator-count").arg("1")
        .arg("--output-dir").arg(output_path2)
        .output()?;
    
    assert!(output2.status.success(), "Second command failed: {}", String::from_utf8_lossy(&output2.stderr));
    
    // Get the keystore files
    let keystore_files1 = fs::read_dir(output_path1)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let path = entry.path();
            path.is_file() && path.file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |name| name.starts_with("UTC--"))
        })
        .collect::<Vec<_>>();
    
    let keystore_files2 = fs::read_dir(output_path2)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let path = entry.path();
            path.is_file() && path.file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |name| name.starts_with("UTC--"))
        })
        .collect::<Vec<_>>();
    
    assert_eq!(keystore_files1.len(), 1, "Expected 1 keystore file in first run");
    assert_eq!(keystore_files2.len(), 1, "Expected 1 keystore file in second run");
    
    // Extract public keys from keystores
    let content1 = fs::read_to_string(keystore_files1[0].path())?;
    let content2 = fs::read_to_string(keystore_files2[0].path())?;
    
    let keystore1: Value = serde_json::from_str(&content1)?;
    let keystore2: Value = serde_json::from_str(&content2)?;
    
    let pubkey1 = keystore1["pubkey"].as_str().expect("Missing pubkey in first keystore");
    let pubkey2 = keystore2["pubkey"].as_str().expect("Missing pubkey in second keystore");
    
    // Keys should be identical for the same mnemonic and index
    assert_eq!(pubkey1, pubkey2, "Keys generated with the same mnemonic and index should be identical");
    
    Ok(())
}

#[test]
fn test_different_indices_different_keys() -> Result<()> {
    // Known public keys from eth-staking-smith for indices 5,6,7
    const EXPECTED_PUBKEYS: [&str; 3] = [
        "a0f42b08f7612bc9e639dc735f17d49738b54722316ae7d4080ee8cba27f2bfbee2496f84095c9ee002a0329e4c9e59d",
        "b07f3aa566e548b737b827f6a782fa5cde12cd25615ece69fea40a728c4c90387592aa5a174218574d9a59d722906ae4",
        "94ab82672325bf9764444ba5a1c25946365039ef5c82d706cc8f1a1f99c249a08dd5700459c2d5b2113f8afe311d6029"
    ];

    // Create temporary directory for test output
    let temp_dir = TempDir::new()?;
    let output_path = temp_dir.path().to_str().unwrap();
    
    // Generate keys for validator indices 5,6,7 (matching eth-staking-smith)
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--mnemonic").arg(TEST_MNEMONIC)
        .arg("--eth-amount").arg("96") // 3 validators * 32 ETH
        .arg("--withdrawal-address").arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password").arg("testpassword123")
        .arg("--validator-index").arg("5") // Start at index 5
        .arg("--validator-count").arg("3") // Generate 3 validators (indices 5,6,7)
        .arg("--output-dir").arg(output_path)
        .output()?;
    
    assert!(output.status.success(), "Command failed: {}", String::from_utf8_lossy(&output.stderr));
    
    // Get the keystore files
    let mut keystore_files = fs::read_dir(output_path)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let path = entry.path();
            path.is_file() && path.file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |name| name.starts_with("UTC--"))
        })
        .collect::<Vec<_>>();
    
    assert_eq!(keystore_files.len(), 3, "Expected 3 keystore files");
    
    // Extract public keys from keystores
    // Sort keystores by path to ensure consistent ordering
    let mut keystores = Vec::new();
    for file in &keystore_files {
        let content = fs::read_to_string(file.path())?;
        let keystore: Value = serde_json::from_str(&content)?;
        let path = keystore["path"].as_str().expect("Missing path in keystore").to_string();
        let pubkey = keystore["pubkey"].as_str().expect("Missing pubkey in keystore").to_string();
        keystores.push((path.clone(), pubkey));
    }
    keystores.sort_by(|a, b| a.0.cmp(&b.0));

    // Verify each public key matches eth-staking-smith's output
    for (i, (path, pubkey)) in keystores.iter().enumerate() {
        println!("Validator {}: path={}, pubkey={}", i, path, pubkey);
        assert_eq!(pubkey, EXPECTED_PUBKEYS[i], "Public key mismatch for validator {}", i);
    }
    
    Ok(())
}
