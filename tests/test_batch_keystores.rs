use assert_cmd::Command;
use anyhow::Result;
use std::fs;
use serde_json::Value;
use std::thread;
use std::time::Duration;

#[test]
fn test_multiple_validator_keystores() -> Result<()> {
    // Create a temporary directory for test output
    let temp_dir = tempfile::tempdir()?;
    let output_path = temp_dir.path().to_str().unwrap();
    
    // Run command to generate 3 validator keystores each with 96ETH
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts").arg("96") // 3 validators * 32 ETH
        .arg("--withdrawal-address").arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password").arg("testpassword123")
        .arg("--validator-index").arg("5") // Start at index 5
        .arg("--validator-count").arg("3") // Generate 3 validators
        .arg("--output-dir").arg(output_path)
        .output()?;
    
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("stdout: {}", stdout);
    // Check output contains expected information
    assert!(stdout.contains("Generated deposit data file:"));
    assert!(stdout.contains("ETH amounts: 96 ETH")); // Updated string
    assert!(stdout.contains("keystore-m_12381_3600_5_0_0"));
    assert!(stdout.contains("keystore-m_12381_3600_6_0_0"));
    assert!(stdout.contains("keystore-m_12381_3600_7_0_0"));
    assert!(stdout.contains("Generated 3 validator"));
    assert!(stdout.contains("Generated 3 deposit data"));
    
    // Give the file system some time to complete writing
    thread::sleep(Duration::from_secs(1));
    
    // Print directory contents for debugging
    println!("Output directory contents:");
    for entry in fs::read_dir(output_path)? {
        if let Ok(entry) = entry {
            println!("  {:?}", entry.path());
        }
    }
    
    // Verify files were created - look for UTC keystore files (EIP-2335 format)
    let files = fs::read_dir(output_path)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let path = entry.path();
            path.is_file() && path.file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |name| name.starts_with("UTC--"))
        })
        .collect::<Vec<_>>();
    
    // Should have 3 keystore files
    assert_eq!(files.len(), 3, "Expected 3 keystore files, found {}", files.len());
    
    // Check each keystore file for correct path
    for file in files {
        let content = fs::read_to_string(file.path())?;
        let keystore: Value = serde_json::from_str(&content)?;
        
        // Extract path and check format (EIP-2334 compliant)
        let path = keystore["path"].as_str().expect("Keystore missing path field");
        
        // Correct EIP-2334 format for signing keys: m/12381/3600/i/0/0
        let expected_pattern = format!("m/12381/3600/{}/0/0", path.split('/').nth(3).unwrap());
        assert_eq!(path, expected_pattern, "Path doesn't match EIP-2334 format");
        
        // Extract index from path (3rd component)
        let index = path.split('/').nth(3).unwrap().parse::<u32>()?;
        assert!(index >= 5 && index <= 7, "Index {} not in expected range 5-7", index);
        
        // Verify this is a valid EIP-2335 keystore
        assert!(keystore["version"].as_u64() == Some(4), "Invalid keystore version");
        assert!(keystore["uuid"].as_str().is_some(), "Missing UUID");
        assert!(keystore["crypto"].is_object(), "Missing crypto section");
    }
    
    // Test JSON output mode
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts").arg("64") // 2 validators * 32 ETH
        .arg("--withdrawal-address").arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password").arg("testpassword123")
        .arg("--validator-index").arg("10") // Start at index 10
        .arg("--validator-count").arg("2") // Generate 2 validators
        .arg("--format").arg("json")
        .output()?;
    
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Extract JSON from output
    let json_start = stdout.find('{').expect("No JSON found in output");
    let json_text = &stdout[json_start..];
    let json: Value = serde_json::from_str(json_text)?;
    
    // Check JSON structure
    assert!(json.get("keystores").is_some(), "keystores field missing in JSON output");
    let keystores = json["keystores"].as_array().unwrap();
    assert_eq!(keystores.len(), 2, "Expected 2 keystores in JSON output");
    
    // Check paths in keystores
    let mut found_indices = vec![false, false]; // For indices 10 and 11
    for keystore in keystores {
        // Verify EIP-2335 keystore structure
        assert!(keystore["version"].as_u64() == Some(4), "Invalid keystore version");
        assert!(keystore["uuid"].as_str().is_some(), "Missing UUID");
        assert!(keystore["crypto"].is_object(), "Missing crypto section");
        
        // Check EIP-2334 derivation path
        let path = keystore["path"].as_str().expect("Keystore missing path field");
        
        // Correct EIP-2334 format for signing keys: m/12381/3600/i/0/0
        let expected_pattern = format!("m/12381/3600/{}/0/0", path.split('/').nth(3).unwrap());
        assert_eq!(path, expected_pattern, "Path doesn't match EIP-2334 format");
        
        // Extract index from path (3rd component)
        let index = path.split('/').nth(3).unwrap().parse::<u32>()?;
        assert!(index >= 10 && index <= 11, "Index {} not in expected range 10-11", index);
        
        // Mark this index as found
        if index == 10 {
            found_indices[0] = true;
        } else if index == 11 {
            found_indices[1] = true;
        }
    }
    
    // Verify we found both indices
    assert!(found_indices[0], "Missing keystore for index 10");
    assert!(found_indices[1], "Missing keystore for index 11");
    
    Ok(())
}
