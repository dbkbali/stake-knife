use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;


const REFERENCE_DEPOSIT_DATA_PATH: &str = "tests/reference_data/deposit_data-1745512048.json";
const REFERENCE_DATA_DIR: &str = "tests/reference_data";

// This test compares stake-knife output with the official staking-deposit-cli output
#[test]
fn test_compatibility_with_official_tool() -> Result<(), Box<dyn std::error::Error>> {
    // Create temporary directory for output
    // Create a temporary directory and ensure it exists
    let output_dir = tempfile::tempdir()?;
    println!("Using output directory: {}", output_dir.path().display());
    
    // Use the exact mnemonic that was used to generate the reference files
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let withdrawal_address = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
    // Run stake-knife with the same parameters that were used to generate the reference files
    let mut cmd = Command::cargo_bin("stake-knife")?;
    
    // Build the command with all parameters
    let args = [
        "wallet", "generate",
        "--mnemonic", mnemonic,
        "--withdrawal-address", withdrawal_address,
        "--eth-amounts", "96", // 3 validators (32 ETH each)
        "--password", "testpassword123",
        "--chain", "mainnet",
        "--format", "files",
        "--bls-mode", "01",
        "--validator-index", "5",
        "--output-dir", output_dir.path().to_str().unwrap(),
    ];
    
    println!("Running command: stake-knife wallet generate with parameters:");
    println!("  --withdrawal-address: {}", withdrawal_address);
    println!("  --eth-amount: 96");
    println!("  --output-dir: {}", output_dir.path().display());
    cmd.args(args);
    
    let output = cmd.output()?;
    
    // Check if the command was successful
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!("stake-knife command failed: stderr: {}, stdout: {}", stderr, stdout);
    }
    
    println!("Command executed successfully");
    
    // Find the generated deposit data file (it has a pattern like deposit-YYYYMMDD-HHMMSS.json)
    let deposit_data_path = fs::read_dir(output_dir.path())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_file() && 
              path.file_name().map_or(false, |name| {
                  let name_str = name.to_string_lossy();
                  name_str.starts_with("deposit-") && name_str.ends_with(".json")
              }))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Deposit data file not found"))?;
    
    // Find all keystore files in the output directory
    println!("Looking for keystore files in: {}", output_dir.path().display());
    
    // List all files in the output directory
    println!("Files in output directory:");
    for entry in fs::read_dir(output_dir.path())? {
        if let Ok(entry) = entry {
            println!("  {}", entry.path().display());
        }
    }

    // Get all keystore files (they start with UTC--)
    let keystore_files: Vec<PathBuf> = fs::read_dir(output_dir.path())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && 
                path.file_name().map_or(false, |name| {
                    let name_str = name.to_string_lossy();
                    name_str.starts_with("UTC--")
                }))
        .collect();
    
    println!("Found {} keystore files", keystore_files.len());
    
    if keystore_files.is_empty() {
        panic!("No keystore files found in generated output");
    }
    
    // Get all reference keystore files
    let reference_keystore_files: Vec<PathBuf> = fs::read_dir(REFERENCE_DATA_DIR)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().map_or(false, |ext| ext == "json"))
        .filter(|path| path.to_str().map_or(false, |s| s.contains("keystore")))
        .collect();
    
    assert!(!reference_keystore_files.is_empty(), "No keystore files found in reference data");
    
    // Verify we have the same number of keystores
    assert_eq!(keystore_files.len(), reference_keystore_files.len(), 
               "Number of keystore files mismatch");
    
    // Load deposit data files
    let generated_deposit_data: Value = serde_json::from_str(&fs::read_to_string(&deposit_data_path)?)?;
    let reference_deposit_data: Value = serde_json::from_str(&fs::read_to_string(REFERENCE_DEPOSIT_DATA_PATH)?)?;
    
    // Compare deposit data
    compare_deposit_data(&generated_deposit_data, &reference_deposit_data);
    
    // Compare each keystore file
    // Note: We can't directly match files by name since the naming conventions might differ
    // Instead, we'll compare them by their validator indices extracted from the path
    for generated_keystore_path in &keystore_files {
        let generated_keystore: Value = serde_json::from_str(&fs::read_to_string(generated_keystore_path)?)?;
        
        // Extract the validator index from the generated keystore path
        let gen_path = generated_keystore["path"].as_str().unwrap();
        
        // Find a matching reference keystore with the same path
        let mut found_match = false;
        for reference_keystore_path in &reference_keystore_files {
            let reference_keystore: Value = serde_json::from_str(&fs::read_to_string(reference_keystore_path)?)?;
            let ref_path = reference_keystore["path"].as_str().unwrap();
            
            // If paths match, compare the keystores
            if extract_validator_path(gen_path) == extract_validator_path(ref_path) {
                println!("Comparing keystore with path {}", gen_path);
                compare_keystore(&generated_keystore, &reference_keystore);
                found_match = true;
                break;
            }
        }
        
        assert!(found_match, "No matching reference keystore found for path {}", gen_path);
    }
    
    Ok(())
}

// Extract the validator path (e.g., "m/12381/3600/5/0/0" from a full path)
fn extract_validator_path(path: &str) -> String {
    // Extract the indices part (e.g., "5/0/0" from "m/12381/3600/5/0/0")
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 6 {
        // Return just the validator index part (e.g., "5")
        return parts[3].to_string();
    }
    path.to_string() // Return the full path if we can't parse it
}

fn compare_deposit_data(generated: &Value, reference: &Value) {
    // Compare deposit data structure - verify all fields match exactly
    for (i, (gen_validator, ref_validator)) in generated.as_array().unwrap().iter()
                                                .zip(reference.as_array().unwrap().iter())
                                                .enumerate() {
        println!("Comparing validator {} deposit data", i);
        
        // Since we're using the same mnemonic, we should get the exact same pubkeys
        let gen_pubkey = gen_validator["pubkey"].as_str().unwrap();
        let ref_pubkey = ref_validator["pubkey"].as_str().unwrap();
        assert_eq!(gen_pubkey, ref_pubkey, 
                   "Pubkey mismatch for validator {}: {} vs {}", i, gen_pubkey, ref_pubkey);
        
        // Check withdrawal credentials - should be identical since we're using the same withdrawal address
        let gen_wc = gen_validator["withdrawal_credentials"].as_str().unwrap();
        let ref_wc = ref_validator["withdrawal_credentials"].as_str().unwrap();
        assert_eq!(gen_wc, ref_wc, 
                   "Withdrawal credentials mismatch for validator {}: {} vs {}", i, gen_wc, ref_wc);
        
        // Check amount matches exactly
        let gen_amount = if gen_validator["amount"].is_number() {
            gen_validator["amount"].as_u64().unwrap()
        } else {
            gen_validator["amount"].as_str().unwrap().parse::<u64>().unwrap()
        };
        
        let ref_amount = if ref_validator["amount"].is_number() {
            ref_validator["amount"].as_u64().unwrap()
        } else {
            ref_validator["amount"].as_str().unwrap().parse::<u64>().unwrap()
        };
        
        assert_eq!(gen_amount, ref_amount,
                  "Amount mismatch for validator {}: {} vs {}", i, gen_amount, ref_amount);
        
        // Check signature matches exactly
        let gen_sig = gen_validator["signature"].as_str().unwrap();
        let ref_sig = ref_validator["signature"].as_str().unwrap();
        assert_eq!(gen_sig, ref_sig,
                  "Signature mismatch for validator {}", i);
        
        // Check deposit message root matches exactly
        let gen_msg_root = gen_validator["deposit_message_root"].as_str().unwrap();
        let ref_msg_root = ref_validator["deposit_message_root"].as_str().unwrap();
        assert_eq!(gen_msg_root, ref_msg_root,
                  "Deposit message root mismatch for validator {}", i);
        
        // Check deposit data root matches exactly
        let gen_data_root = gen_validator["deposit_data_root"].as_str().unwrap();
        let ref_data_root = ref_validator["deposit_data_root"].as_str().unwrap();
        assert_eq!(gen_data_root, ref_data_root,
                  "Deposit data root mismatch for validator {}", i);
        
        // Check fork version matches exactly
        let gen_fork = gen_validator["fork_version"].as_str().unwrap();
        let ref_fork = ref_validator["fork_version"].as_str().unwrap();
        assert_eq!(gen_fork, ref_fork,
                  "Fork version mismatch for validator {}", i);
        
        // Check network name matches exactly
        let gen_network = gen_validator["network_name"].as_str().unwrap();
        let ref_network = ref_validator["network_name"].as_str().unwrap();
        assert_eq!(gen_network, ref_network,
                  "Network name mismatch for validator {}", i);
    }
}

fn compare_keystore(generated: &Value, reference: &Value) {
    // Compare keystore structure - verify all fields match exactly
    
    // Check KDF function and parameters
    assert_eq!(generated["crypto"]["kdf"]["function"].as_str().unwrap(),
               reference["crypto"]["kdf"]["function"].as_str().unwrap(),
               "KDF function mismatch");
    
    // Check KDF params - dklen, n, r, p
    assert_eq!(generated["crypto"]["kdf"]["params"]["dklen"].as_u64().unwrap(),
               reference["crypto"]["kdf"]["params"]["dklen"].as_u64().unwrap(),
               "KDF dklen mismatch");
    
    assert_eq!(generated["crypto"]["kdf"]["params"]["n"].as_u64().unwrap(),
               reference["crypto"]["kdf"]["params"]["n"].as_u64().unwrap(),
               "KDF n mismatch");
    
    assert_eq!(generated["crypto"]["kdf"]["params"]["r"].as_u64().unwrap(),
               reference["crypto"]["kdf"]["params"]["r"].as_u64().unwrap(),
               "KDF r mismatch");
    
    assert_eq!(generated["crypto"]["kdf"]["params"]["p"].as_u64().unwrap(),
               reference["crypto"]["kdf"]["params"]["p"].as_u64().unwrap(),
               "KDF p mismatch");
    
    // Check cipher function and parameters
    assert_eq!(generated["crypto"]["cipher"]["function"].as_str().unwrap(),
               reference["crypto"]["cipher"]["function"].as_str().unwrap(),
               "Cipher function mismatch");
    
    // Check checksum function
    assert_eq!(generated["crypto"]["checksum"]["function"].as_str().unwrap(),
               reference["crypto"]["checksum"]["function"].as_str().unwrap(),
               "Checksum function mismatch");
    
    // Check path format (should follow EIP-2334)
    let gen_path = generated["path"].as_str().unwrap();
    let ref_path = reference["path"].as_str().unwrap();
    
    assert!(gen_path.starts_with("m/12381/3600/"),
            "Generated keystore path should follow EIP-2334: {}", gen_path);
    assert!(ref_path.starts_with("m/12381/3600/"),
            "Reference keystore path should follow EIP-2334: {}", ref_path);
    
    // Since we're using the same mnemonic and validator index, the paths should match exactly
    assert_eq!(gen_path, ref_path, 
               "Path mismatch: {} vs {}", gen_path, ref_path);
    
    // Check version
    assert_eq!(generated["version"].as_i64().unwrap(), 
               reference["version"].as_i64().unwrap(),
               "Version mismatch");
    
    // Check UUID format
    assert!(generated["uuid"].as_str().unwrap().contains("-"),
            "Generated UUID should be properly formatted");
    assert!(reference["uuid"].as_str().unwrap().contains("-"),
            "Reference UUID should be properly formatted");
    
    // Check pubkey matches exactly
    let gen_pubkey = generated["pubkey"].as_str().unwrap();
    let ref_pubkey = reference["pubkey"].as_str().unwrap();
    assert_eq!(gen_pubkey, ref_pubkey,
               "Pubkey mismatch: {} vs {}", gen_pubkey, ref_pubkey);
    
    // Note: We don't compare the actual encrypted key contents, UUID, or salt values
    // since these will be different even with the same inputs due to randomization
}
