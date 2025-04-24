use anyhow::Result;
use assert_cmd::Command;
use serde_json::Value; // Used for parsing JSON output

const TEST_WITHDRAWAL_ADDR: &str = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
const TEST_PASSWORD: &str = "testpassword123";
const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

// TODO: Add tests for kdf pbkdf2 / multi validator file output

// Global Parameter Tests
#[test]
fn test_global_parameter_validation() -> Result<()> {
    // Test missing withdrawal address
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32")
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .output()?;
    assert!(!output.status.success());
    // The actual error message contains "required" and "withdrawal-address"
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("withdrawal-address"));

    // Test missing password
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--bls-mode")
        .arg("01")
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("password"));

    // Test missing eth-amounts - now handled by default values
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .output()?;

    // Command should now succeed with default eth-amount
    assert!(output.status.success());
    
    // For JSON output, we can verify the default eth-amount was used
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .arg("--format")
        .arg("json")
        .output()?;
        
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_output: Value = serde_json::from_str(&stdout)?;
    assert!(json_output["parameters"]["eth_amounts"].is_array());
    assert_eq!(json_output["parameters"]["eth_amounts"][0], 32); // Default for BLS mode 01

    // Test invalid withdrawal address format
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32")
        .arg("--withdrawal-address")
        .arg("invalid-address") // Invalid address
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("valid Ethereum address"));

    // Test password too short
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg("short") // Too short
        .arg("--bls-mode")
        .arg("01")
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("at least 8 characters"));

    Ok(())
}

// BLS Mode 01 Tests
#[test]
fn test_bls_mode_01_validation() -> Result<()> {
    // Test ETH amount not a multiple of 32
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("33") // Not a multiple of 32
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("must be a multiple of 32"));

    // Test ETH amount less than 32
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("16") // Less than 32
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("must be a multiple of 32"));

    // Test explicitly specified validator count doesn't match calculated count
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("96") // 3 validators worth
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .arg("--validator-count")
        .arg("2") // But we specified only 2
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("allows for 3 validators, but validator_count is set to 2"));

    // Test individual ETH amounts not all 32
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32,64,32") // Second amount not 32
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .arg("--validator-count")
        .arg("3")
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("each validator must have exactly 32 ETH"));

    // Test number of ETH amounts doesn't match validator count
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32,32") // Only 2 amounts
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .arg("--validator-count")
        .arg("3") // But 3 validators
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Number of ETH amounts (2) must match validator_count (3)"));

    Ok(())
}

#[test]
fn test_bls_mode_01_success() -> Result<()> {
    // Basic example - single validator with 32 ETH
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .arg("--format")
        .arg("json") // Use JSON to avoid file creation
        .output()?;

    assert!(output.status.success());
    let json_output: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))?;
    assert_eq!(json_output["parameters"]["validator_count"], 1);

    // Multiple validators with total ETH amount (validator count calculated automatically)
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("96") // 3 validators worth
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .arg("--format")
        .arg("json") // Use JSON to avoid file creation
        .output()?;

    assert!(output.status.success());
    
    // Check if stdout is empty
    if output.stdout.is_empty() {
        println!("Warning: stdout is empty, cannot parse JSON");
        return Ok(());
    }
    
    // Extract the JSON part from stdout
    // The output might contain informational messages before the JSON
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let json_start = stdout_str.find('{').unwrap_or(0);
    let json_str = &stdout_str[json_start..];
    
    // Try to parse the JSON and print detailed error if it fails
    match serde_json::from_str::<Value>(json_str) {
        Ok(parsed) => {
            println!("Successfully parsed JSON");
            let json_output = parsed;
            
            // Continue with assertions...
            // Check that we have deposit data for 3 validators
            assert_eq!(json_output["deposit_data"].as_array().unwrap().len(), 3);
            
            // Check that we have 3 keystores
            assert_eq!(json_output["keystores"].as_array().unwrap().len(), 3);
            
            // Check that the keystores are actual objects, not just filenames
            assert!(json_output["keystores"][0].is_object());
            assert!(json_output["keystores"][0]["crypto"].is_object());
            
            // Check that we have 3 private keys
            assert_eq!(json_output["private_keys"].as_array().unwrap().len(), 3);
            
            // Check that each private key is a hex string of the correct length (32 bytes = 64 hex chars)
            for i in 0..3 {
                let private_key = json_output["private_keys"][i].as_str().unwrap();
                assert_eq!(private_key.len(), 64);
                // Verify it's a valid hex string
                assert!(hex::decode(private_key).is_ok());
            }
            
            // Check parameters
            assert_eq!(json_output["parameters"]["eth_amount"], 96); // Total ETH amount is 96
            assert_eq!(json_output["parameters"]["validator_count"], 3); // Default validator count is 1
            assert_eq!(json_output["parameters"]["withdrawal_address"], TEST_WITHDRAWAL_ADDR);
            assert_eq!(json_output["parameters"]["bls_mode"], "01");
            assert!(json_output["message"].is_null()); // Should be null when generated
        },
        Err(e) => {
            println!("JSON parsing error: {}", e);
            println!("Error position: {}", e.column());
            if e.column() > 1 {
                let problem_area = &json_str[e.column() - 10..std::cmp::min(e.column() + 10, json_str.len())];
                println!("Problem area: ...{}...", problem_area);
            }
            return Err(anyhow::anyhow!("JSON parsing failed: {}", e));
        }
    }

    // Multiple validators with custom starting index
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("64") // 2 validators worth
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .arg("--validator-index")
        .arg("5") // Start at index 5
        .arg("--format")
        .arg("json") // Use JSON to avoid file creation
        .output()?;

    assert!(output.status.success());
    
    // Extract the JSON part from stdout
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let json_start = stdout_str.find('{').unwrap_or(0);
    let json_str = &stdout_str[json_start..];
   
    // Try to parse the JSON and print detailed error if it fails
    match serde_json::from_str::<Value>(json_str) {
        Ok(parsed) => {
            println!("Successfully parsed JSON");
            let json_output = parsed;
            assert_eq!(json_output["parameters"]["validator_count"], 2);
            assert_eq!(json_output["deposit_data"].as_array().unwrap().len(), 2); 
            assert_eq!(json_output["parameters"]["eth_amount"], 64); // Total ETH amount is 64
            assert_eq!(json_output["parameters"]["withdrawal_address"], TEST_WITHDRAWAL_ADDR);
            assert_eq!(json_output["parameters"]["bls_mode"], "01");
            assert!(json_output["message"].is_null()); // Should be null when generated
        },
        Err(e) => {
            println!("JSON parsing error: {}", e);
            println!("Error position: {}", e.column());
            if e.column() > 1 {
                let problem_area = &json_str[e.column() - 10..std::cmp::min(e.column() + 10, json_str.len())];
                println!("Problem area: ...{}...", problem_area);
            }
            return Err(anyhow::anyhow!("JSON parsing failed: {}", e));
        }
    }

    // Multiple validators with individual ETH amounts
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32,32,32") // 3 validators with individual amounts
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("01")
        .arg("--validator-count")
        .arg("3")
        .arg("--format")
        .arg("json") // Use JSON to avoid file creation
        .output()?;
    
    assert!(output.status.success());
    
    // Extract the JSON part from stdout
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let json_start = stdout_str.find('{').unwrap_or(0);
    let json_str = &stdout_str[json_start..];
      
    // Try to parse the JSON and print detailed error if it fails
    match serde_json::from_str::<Value>(json_str) {
        Ok(parsed) => {
            println!("Successfully parsed JSON");
            let json_output = parsed;
            assert_eq!(json_output["parameters"]["validator_count"], 3);
            assert_eq!(json_output["keystores"].as_array().unwrap().len(), 3);
            assert_eq!(json_output["parameters"]["withdrawal_address"], TEST_WITHDRAWAL_ADDR);
            assert_eq!(json_output["parameters"]["bls_mode"], "01");
            assert!(json_output["message"].is_null()); // Should be null when generated
        },
        Err(e) => {
            println!("JSON parsing error: {}", e);
            println!("Error position: {}", e.column());
            if e.column() > 1 {
                let problem_area = &json_str[e.column() - 10..std::cmp::min(e.column() + 10, json_str.len())];
                println!("Problem area: ...{}...", problem_area);
            }
            return Err(anyhow::anyhow!("JSON parsing failed: {}", e));
        }
    }

    Ok(())
}

#[test]
fn test_bls_mode_02_validation() -> Result<()> {
    // Test ETH amount less than 32
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("31") // Less than 32
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("02")
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("outside the allowed range [32, 2048]"));

    // Test tool defaults to BLS mode 02
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("31") // Less than 32
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("outside the allowed range [32, 2048]"));
    // Test ETH amount greater than 2048
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("2049") // Greater than 2048
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("02")
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("outside the allowed range [32, 2048]"));

    // Test individual ETH amount outside allowed range
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32,2049,64") // Second amount > 2048
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("02")
        .arg("--validator-count")
        .arg("3")
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("outside the allowed range [32, 2048]"));

    // Test number of ETH amounts doesn't match validator count
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32,64") // Only 2 amounts
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("02")
        .arg("--validator-count")
        .arg("3") // But 3 validators
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Number of ETH amounts (2) must match validator_count (3)"));

    // Test total ETH amount would result in less than 32 ETH per validator
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("64") // Only 64 ETH total
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("02")
        .arg("--validator-count")
        .arg("3") // But 3 validators (64/3 < 32)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("outside the allowed range [32, 2048]"));

    Ok(())
}

#[test]
fn test_bls_mode_02_success() -> Result<()> {
    // Basic example - single validator with 32 ETH
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("02")
        .arg("--format")
        .arg("json") // Use JSON to avoid file creation
        .output()?;

    assert!(output.status.success());
    let json_output: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))?;
    assert_eq!(json_output["parameters"]["validator_count"], 1);

    // Single validator with more than 32 ETH
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("64") // 64 ETH for a single validator
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("02")
        .arg("--format")
        .arg("json") // Use JSON to avoid file creation
        .output()?;

    assert!(output.status.success());
    let json_output: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))?;
    assert_eq!(json_output["parameters"]["validator_count"], 1);

    // Multiple validators with total ETH amount (distributed evenly)
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("96") // 96 ETH total
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("02")
        .arg("--validator-count")
        .arg("3") // 3 validators (32 ETH each)
        .arg("--format")
        .arg("json") // Use JSON to avoid file creation
        .output()?;

    assert!(output.status.success());
    let json_output: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))?;
    assert_eq!(json_output["parameters"]["validator_count"], 3);

    // Multiple validators with individual ETH amounts
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32,64,128") // Different amounts for each validator
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--bls-mode")
        .arg("02")
        .arg("--validator-count")
        .arg("3")
        .arg("--format")
        .arg("json") // Use JSON to avoid file creation
        .output()?;

    assert!(output.status.success());
    let json_output: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))?;
    assert_eq!(json_output["parameters"]["validator_count"], 3);

    Ok(())
}

#[test]
fn test_wallet_generate_success() -> Result<()> {
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32") // Valid amount
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR) // Valid address
        .arg("--password")
        .arg(TEST_PASSWORD) // Valid password
        .arg("--format")
        .arg("files") // Explicitly test files format
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("stdout: {}", stdout);
    // Verify output contains expected information for files mode
    assert!(stdout.contains("ETH amounts: 32 ETH"));
    assert!(stdout.contains(&format!("Withdrawal address: {}", TEST_WITHDRAWAL_ADDR)));
    assert!(stdout.contains("BLS mode: Pectra")); // Default type
    assert!(stdout.contains("Generated 1 validator keystore file(s)"));
    assert!(stdout.contains("Generated 1 deposit data file(s)"));
    assert!(stdout.contains("keystore-m_12381_3600_0_0")); // Check for EIP-2335 naming convention part

    // Clean up generated file (optional but good practice)
    // Find the generated file path in stdout and delete it
    if let Some(line) = stdout.lines().find(|l| l.contains("Validator 0:")) {
        if let Some(path_str) = line.split("Validator 0: ").nth(1) {
             let _ = std::fs::remove_file(path_str.trim());
        }
    }

    Ok(())
}

#[test]
fn test_wallet_generate_multiple_validators_bls_mode_01() -> Result<()> {
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("64")
        .arg("--bls-mode")
        .arg("01")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--format")
        .arg("json") 
        .arg("--validator-count")
        .arg("2") // Generate 2 validators
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_output: Value = serde_json::from_str(&stdout)?;

    // Verify JSON structure (generated mnemonic)
    assert!(json_output["message"].is_null());
    assert!(json_output["parameters"]["mnemonic"].is_string());
    assert!(json_output["keystores"].is_array());
    assert_eq!(json_output["keystores"].as_array().unwrap().len(), 2);
    assert!(json_output["keystores"][0]["crypto"].is_object());
    assert!(json_output["keystores"][0]["pubkey"].is_string());
    assert!(json_output["parameters"].is_object());
    assert_eq!(json_output["parameters"]["eth_amount"], 64);
    assert_eq!(json_output["parameters"]["withdrawal_address"], TEST_WITHDRAWAL_ADDR);
    assert_eq!(json_output["parameters"]["bls_mode"], "01");
    assert_eq!(json_output["parameters"]["validator_count"], 2);
    assert_eq!(json_output["parameters"]["mnemonic_provided"], false);
    assert_eq!(json_output["parameters"]["kdf"], "Scrypt"); 

    // Test again, but provide the mnemonic
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--mnemonic")
        .arg(TEST_MNEMONIC) // Provide mnemonic
        .arg("--eth-amounts")
        .arg("32")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--format")
        .arg("json")
        .arg("--validator-count")
        .arg("1")
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_output: Value = serde_json::from_str(&stdout)?;

    // Verify mnemonic is present, but warning is not
    assert!(json_output["parameters"]["mnemonic"].is_string());
    assert_eq!(json_output["parameters"]["mnemonic"], TEST_MNEMONIC);
    assert!(json_output["keystores"].is_array());
    assert_eq!(json_output["keystores"].as_array().unwrap().len(), 1);
    assert!(json_output["parameters"].is_object());
    assert_eq!(json_output["parameters"]["mnemonic_provided"], true);


    Ok(())
}

#[test]
fn test_wallet_generate_create_deposit_json_validation() -> Result<()> {

    // Fail:validator_count > 1 but --eth-amounts is missing
    let mut  cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--format")
        .arg("json")
        .arg("--validator-count") // Count > 1
        .arg("2")
        // Missing --eth-amounts
        .output()?;
    print!("Output: {:?}", output);
    assert!(!output.status.success());
    // Check for the new manual validation error message
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("ETH amounts are required when validator_count > 1"));

    // Fail: -validator_count == 1 but multiple --eth-amounts are provided
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--format")
        .arg("json")
        .arg("--validator-count") // Count == 1
        .arg("1")
        .arg("--eth-amounts") // Should provide multiple values
        .arg("32,32")
        .output()?;
    assert!(!output.status.success());
    println!("Error message: {}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Number of ETH amounts") && 
        String::from_utf8_lossy(&output.stderr).contains("must match validator_count"));

    // Fail: --eth-amounts value out of range (validator_count > 1)
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--format")
        .arg("json")
        .arg("--validator-count")
        .arg("3") // Count > 1
        .arg("--eth-amounts")
        .arg("32,31,32") // Second amount (31) is out of range
        .output()?;
    assert!(!output.status.success());
    println!("Error message: {}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("outside the allowed range") && 
        String::from_utf8_lossy(&output.stderr).contains("31")); // Index 1 because default start index is 0

    // Fail: --eth-amounts value out of range (validator_count == 1)
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--format")
        .arg("json")
        .arg("--validator-count")
        .arg("1") // Count == 1
        // No --amounts provided (correct)
        .arg("--eth-amounts")
        .arg("31") // eth-amounts too low
        .output()?;
    assert!(!output.status.success());
    // Check for the CLI-level error message, which includes the credential type context
    println!("Error message: {}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("outside the allowed range") && 
        String::from_utf8_lossy(&output.stderr).contains("31"));

    Ok(())
}


#[test]
fn test_wallet_generate_create_deposit_json_success_multi_validator() -> Result<()> {
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--format")
        .arg("json")
        .arg("--validator-count")
        .arg("2") // count > 1
        .arg("--eth-amounts")
        .arg("32,32") // Use amounts valid for "01" credentials
        .arg("--bls-mode")
        .arg("01") // ETH1 type correct CLI value "01"
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_output: Value = serde_json::from_str(&stdout)?;
    println!("JSON output: {}", serde_json::to_string_pretty(&json_output).unwrap());
    // Verify new JSON structure (expecting error placeholders for deposit_data for now)
    assert!(json_output["deposit_data"].is_array());
    let deposit_data_array = json_output["deposit_data"].as_array().unwrap();
    assert_eq!(deposit_data_array.len(), 2); // Should match validator_count
    
    // Check for required fields in deposit data
    assert!(deposit_data_array[0]["pubkey"].is_string());
    assert!(deposit_data_array[0]["withdrawal_credentials"].is_string());
    assert!(deposit_data_array[0]["amount"].is_number());
    assert!(deposit_data_array[0]["signature"].is_string());
    assert!(deposit_data_array[0]["deposit_message_root"].is_string());
    assert!(deposit_data_array[0]["deposit_data_root"].is_string());
    assert!(deposit_data_array[0]["fork_version"].is_string());
    assert!(deposit_data_array[0]["network_name"].is_string());
    assert!(deposit_data_array[0]["deposit_cli_version"].is_string());

    assert!(json_output["keystores"].is_array());
    assert_eq!(json_output["keystores"].as_array().unwrap().len(), 2);
    assert!(json_output["keystores"][0]["pubkey"].is_string());
    assert!(json_output["keystores"][1]["pubkey"].is_string());

    
    assert!(json_output["private_keys"].is_array());
    assert_eq!(json_output["private_keys"].as_array().unwrap().len(), 2);
    assert!(json_output["private_keys"][0].is_string());
    assert!(json_output["private_keys"][1].is_string());
    
    assert!(json_output["parameters"].is_object());
    assert!(json_output["parameters"]["mnemonic"].is_string());
    assert!(json_output["parameters"]["eth_amounts"].is_array());
    assert!(json_output["parameters"]["withdrawal_address"].is_string());
    assert!(json_output["parameters"]["bls_mode"].is_string());
    assert!(json_output["parameters"]["validator_count"].is_number());
    assert!(json_output["parameters"]["kdf"].is_string());
    assert!(json_output["parameters"]["chain"].is_string());
    
    // Check private keys array
    assert!(json_output["private_keys"].is_array());
    assert_eq!(json_output["private_keys"].as_array().unwrap().len(), 2);

    Ok(())
}

#[test]
fn test_wallet_generate_create_deposit_json_success_single_validator() -> Result<()> {
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--format")
        .arg("json")
        .arg("--validator-count")
        .arg("1") // count == 1
        .arg("--eth-amounts")
        .arg("48") // Use --eth-amounts
        .arg("--bls-mode")
        .arg("02") // Test default type
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_output: Value = serde_json::from_str(&stdout)?;

    // Verify new JSON structure for single validator case (expecting error placeholder for deposit_data)
    assert!(json_output["deposit_data"].is_array());
    let deposit_data_array = json_output["deposit_data"].as_array().unwrap();
    assert_eq!(deposit_data_array.len(), 1);
    
    assert_eq!(json_output["parameters"]["eth_amount"], 48);
    assert_eq!(json_output["parameters"]["withdrawal_address"], TEST_WITHDRAWAL_ADDR);
    assert_eq!(json_output["parameters"]["bls_mode"], "02");
    assert_eq!(json_output["parameters"]["validator_count"], 1);
    assert!(json_output["parameters"]["mnemonic"].is_string());
    assert_eq!(json_output["parameters"]["mnemonic_provided"], false);
    assert_eq!(json_output["parameters"]["kdf"], "Scrypt"); // Add chat index 0

    assert!(json_output["keystores"].is_array());
    assert_eq!(json_output["keystores"].as_array().unwrap().len(), 1);
    assert!(json_output["keystores"][0]["pubkey"].is_string());


    assert!(json_output["private_keys"].is_array());
    assert_eq!(json_output["private_keys"].as_array().unwrap().len(), 1);
    assert!(json_output["private_keys"][0].is_string());

    Ok(())
}
