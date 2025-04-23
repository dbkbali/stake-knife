use assert_cmd::Command;
use anyhow::Result;
use std::fs;
use std::path::Path;
use serde_json::Value;
use tempfile::TempDir;
use regex::Regex;

/// Test that verifies:
/// 1. Batch keystore generation with automatic mnemonic
/// 2. Recovery of those keystores using the same mnemonic produces identical keys
#[test]
fn test_keystore_generation_and_recovery() -> Result<()> {
    // Create temporary directories for test output
    let temp_dir_initial = TempDir::new()?;
    let temp_dir_recovery = TempDir::new()?;
    
    let initial_path = temp_dir_initial.path().to_str().unwrap();
    let recovery_path = temp_dir_recovery.path().to_str().unwrap();
    
    // Step 1: Generate keystores with automatic mnemonic
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts").arg("96") // 3 validators * 32 ETH
        .arg("--withdrawal-address").arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password").arg("testpassword123")
        .arg("--validator-index").arg("5") // Start at index 5
        .arg("--validator-count").arg("3") // Generate 3 validators
        .arg("--output-dir").arg(initial_path)
        .output()?;
    
    assert!(output.status.success(), "First command failed: {}", String::from_utf8_lossy(&output.stderr));
    
    // Extract the mnemonic from the output
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("DEBUG: Command output: {}", stdout);
    
    let mnemonic_regex = Regex::new(r"\[IMPORTANT\] Generated new mnemonic for validator key derivation:\s*\n([\w\s]+)")?;
    
    let mnemonic = match mnemonic_regex.captures(&stdout) {
        Some(captures) => {
            match captures.get(1) {
                Some(m) => {
                    let extracted = m.as_str().trim().to_string();
                    println!("DEBUG: Raw extracted mnemonic: '{}'", extracted);
                    extracted
                },
                None => panic!("Mnemonic capture group not found")
            }
        },
        None => {
            println!("DEBUG: Regex failed to match. Output was:\n{}", stdout);
            panic!("Mnemonic not found in output")
        }
    };
    
    println!("Extracted mnemonic: {}", mnemonic);
    
    // Verify the mnemonic is 24 words
    let word_count = mnemonic.split_whitespace().count();
    assert_eq!(word_count, 24, "Expected 24-word mnemonic, got {} words", word_count);
    
    // Validate that the mnemonic is properly formatted
    assert!(!mnemonic.is_empty(), "Extracted mnemonic should not be empty");
    assert!(!mnemonic.contains("\n"), "Mnemonic should not contain newlines");
    
    // Get the initial keystores and their public keys
    let initial_files = fs::read_dir(initial_path)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let path = entry.path();
            path.is_file() && path.file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |name| name.starts_with("UTC--"))
        })
        .collect::<Vec<_>>();
    
    // Should have 3 keystore files
    assert_eq!(initial_files.len(), 3, "Expected 3 keystore files, found {}", initial_files.len());
    
    // Extract public keys, paths, and validator indices from initial keystores
    let mut initial_keystores = Vec::new();
    
    for file in &initial_files {
        let content = fs::read_to_string(file.path())?;
        let keystore: Value = serde_json::from_str(&content)?;
        
        let pubkey = keystore["pubkey"].as_str().expect("Keystore missing pubkey field").to_string();
        let path = keystore["path"].as_str().expect("Keystore missing path field").to_string();
        
        // Extract validator index from path (format: m/12381/3600/INDEX/0/0)
        let parts: Vec<&str> = path.split('/').collect();
        let validator_index = parts[3].parse::<u32>().expect("Failed to parse validator index");
        
        // Verify path format follows EIP-2334
        assert!(path.starts_with("m/12381/3600/"), "Invalid path format: {}", path);
        assert!(path.ends_with("/0/0"), "Invalid path format: {}", path);
        
        initial_keystores.push((validator_index, pubkey, path));
    }
    
    // Sort keystores by validator index
    initial_keystores.sort_by_key(|k| k.0);
    
    // Extract sorted pubkeys and paths
    let initial_pubkeys: Vec<String> = initial_keystores.iter().map(|k| k.1.clone()).collect();
    let initial_paths: Vec<String> = initial_keystores.iter().map(|k| k.2.clone()).collect();
    
    println!("DEBUG: Initial keystores sorted by validator index:");
    for (idx, pubkey, path) in &initial_keystores {
        println!("  Index {}: Path: {}, Pubkey: {}", idx, path, pubkey);
    }
    
    // Step 2: Recover keystores using the same mnemonic
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--mnemonic").arg(&mnemonic)
        .arg("--eth-amounts").arg("96") 
        .arg("--withdrawal-address").arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password").arg("testpassword123")
        .arg("--validator-index").arg("5") // Same index as before
        .arg("--validator-count").arg("3") // Same count as before
        .arg("--output-dir").arg(recovery_path)
        .output()?;
    
    assert!(output.status.success(), "Recovery command failed: {}", String::from_utf8_lossy(&output.stderr));
    
    println!("Recovery using extracted mnemonic: {}", mnemonic);
    
    // Get the recovered keystores
    let recovery_files = fs::read_dir(recovery_path)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let path = entry.path();
            path.is_file() && path.file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |name| name.starts_with("UTC--"))
        })
        .collect::<Vec<_>>();
    
    // Should have 3 keystore files
    assert_eq!(recovery_files.len(), 3, "Expected 3 recovery keystore files, found {}", recovery_files.len());
    
    // Extract public keys, paths, and validator indices from recovered keystores
    let mut recovery_keystores = Vec::new();
    
    for file in &recovery_files {
        let content = fs::read_to_string(file.path())?;
        let keystore: Value = serde_json::from_str(&content)?;
        
        let pubkey = keystore["pubkey"].as_str().expect("Keystore missing pubkey field").to_string();
        let path = keystore["path"].as_str().expect("Keystore missing path field").to_string();
        
        // Extract validator index from path (format: m/12381/3600/INDEX/0/0)
        let parts: Vec<&str> = path.split('/').collect();
        let validator_index = parts[3].parse::<u32>().expect("Failed to parse validator index");
        
        recovery_keystores.push((validator_index, pubkey, path));
    }
    
    // Sort keystores by validator index
    recovery_keystores.sort_by_key(|k| k.0);
    
    // Extract sorted pubkeys and paths
    let recovery_pubkeys: Vec<String> = recovery_keystores.iter().map(|k| k.1.clone()).collect();
    let recovery_paths: Vec<String> = recovery_keystores.iter().map(|k| k.2.clone()).collect();
    
    println!("DEBUG: Recovery keystores sorted by validator index:");
    for (idx, pubkey, path) in &recovery_keystores {
        println!("  Index {}: Path: {}, Pubkey: {}", idx, path, pubkey);
    }
    
    // Verify that all public keys and paths match between initial and recovery
    for i in 0..3 {
        println!("DEBUG: Comparing validator {}:", i + 5);
        println!("  Original pubkey: {}", initial_pubkeys[i]);
        println!("  Recovery pubkey: {}", recovery_pubkeys[i]);
        println!("  Original path: {}", initial_paths[i]);
        println!("  Recovery path: {}", recovery_paths[i]);
        
        // Verify paths match exactly
        assert_eq!(initial_paths[i], recovery_paths[i], 
                   "Path mismatch for validator {}", i + 5);
        
        // Verify public keys match exactly
        assert_eq!(initial_pubkeys[i], recovery_pubkeys[i], 
                   "Public key mismatch for validator {}", i + 5);
    }
    
    // Verify all public keys are different from each other (within the same batch)
    for i in 0..3 {
        for j in i+1..3 {
            assert_ne!(initial_pubkeys[i], initial_pubkeys[j], 
                       "Public keys should be different for validators {} and {}", i + 5, j + 5);
        }
    }
    
    Ok(())
}
