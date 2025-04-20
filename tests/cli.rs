use anyhow::Result;
use assert_cmd::Command;
use predicates::prelude::*; // Used for checking output
use serde_json::Value; // Used for parsing JSON output

const TEST_WITHDRAWAL_ADDR: &str = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
const TEST_PASSWORD: &str = "testpassword123";

#[test]
fn test_wallet_generate_validation() -> Result<()> {
    let mut cmd = Command::cargo_bin("stake-knife")?;

    // Test invalid ETH amount
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amount")
        .arg("31") // Invalid amount
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("ETH amount (31) is outside the allowed range [32, 2048]")); // Updated error message check

    // Test invalid withdrawal address
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amount")
        .arg("32") // Valid amount for this check
        .arg("--withdrawal-address")
        .arg("invalid-address") // Invalid address
        .arg("--password")
        .arg(TEST_PASSWORD)
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("must start with 0x"));

    // Test invalid password
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amount")
        .arg("32") // Valid amount
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR) // Valid address
        .arg("--password")
        .arg("short") // Invalid password
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Password must be at least 8 characters long"));

    Ok(())
}

#[test]
fn test_wallet_generate_success() -> Result<()> {
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amount")
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

    // Verify output contains expected information for files mode
    assert!(stdout.contains("ETH amount per validator: 32 ETH"));
    assert!(stdout.contains(&format!("Withdrawal address: {}", TEST_WITHDRAWAL_ADDR)));
    assert!(stdout.contains("Withdrawal credential type: Pectra")); // Default type
    assert!(stdout.contains("Generated 1 validator keystore file(s)"));
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
fn test_wallet_generate_dry_run() -> Result<()> {
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amount")
        .arg("32") // Valid amount
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR) // Valid address
        .arg("--password")
        .arg(TEST_PASSWORD) // Valid password
        .arg("--dry-run")
        .arg("--format")
        .arg("files") // Test dry run with files format
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify dry run message is present for files mode
    assert!(stdout.contains("DRY RUN - no files will be generated"));

    Ok(())
}

#[test]
fn test_wallet_generate_dry_run_json() -> Result<()> {
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amount")
        .arg("32")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--dry-run")
        .arg("--format")
        .arg("json") // Test dry run with json format
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_output: Value = serde_json::from_str(&stdout)?;

    // Verify dry run JSON structure
    assert!(json_output["dry_run"].as_bool().unwrap());
    assert_eq!(json_output["message"], "No files will be generated");
    assert_eq!(json_output["parameters"]["eth_amount"], 32);
    assert_eq!(json_output["parameters"]["withdrawal_address"], TEST_WITHDRAWAL_ADDR);
    assert_eq!(json_output["parameters"]["withdrawal_credential_type"], "Pectra"); // Default
    assert_eq!(json_output["parameters"]["kdf"], "Scrypt"); // Default

    Ok(())
}

#[test]
fn test_wallet_generate_json_output_old_format() -> Result<()> {
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amount")
        .arg("32")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--format")
        .arg("json") // JSON output without --create-deposit-json
        .arg("--validator-count")
        .arg("2") // Generate 2 validators
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_output: Value = serde_json::from_str(&stdout)?;

    // Verify old JSON structure (generated mnemonic)
    assert!(json_output["warning"].is_string());
    assert!(json_output["mnemonic"].is_string());
    assert!(json_output["keystores"].is_array());
    assert_eq!(json_output["keystores"].as_array().unwrap().len(), 2);
    assert!(json_output["keystores"][0]["crypto"].is_object());
    assert!(json_output["keystores"][0]["pubkey"].is_string());
    assert!(json_output["parameters"].is_object());
    assert_eq!(json_output["parameters"]["eth_amount"], 32);
    assert_eq!(json_output["parameters"]["withdrawal_address"], TEST_WITHDRAWAL_ADDR);
    assert_eq!(json_output["parameters"]["withdrawal_credential_type"], "Pectra");
    assert_eq!(json_output["parameters"]["validator_count"], 2);
    assert_eq!(json_output["parameters"]["mnemonic_provided"], false);
    assert_eq!(json_output["parameters"]["kdf"], "Scrypt"); // Add check for default KDF
    assert!(json_output["warning"].is_string()); // Should have warning when generated

    // Test again, but provide the mnemonic
    let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--mnemonic")
        .arg(test_mnemonic) // Provide mnemonic
        .arg("--eth-amount")
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
    assert!(json_output["mnemonic"].is_string());
    assert_eq!(json_output["mnemonic"], test_mnemonic);
    assert!(json_output["warning"].is_null()); // No warning when mnemonic provided
    assert!(json_output["keystores"].is_array());
    assert_eq!(json_output["keystores"].as_array().unwrap().len(), 1);
    assert!(json_output["parameters"].is_object());
    assert_eq!(json_output["parameters"]["mnemonic_provided"], true);


    Ok(())
}

#[test]
fn test_wallet_generate_create_deposit_json_validation() -> Result<()> {
    let mut cmd = Command::cargo_bin("stake-knife")?;

    // Fail: --create-deposit-json without --format json
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--create-deposit-json") // Flag is present
        .arg("--amounts") // Required amounts
        .arg("32")
        // .arg("--format").arg("files") // Default is files
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("--create-deposit-json requires --format json"));

    // Fail: --create-deposit-json with validator_count > 1 but --amounts is missing
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--create-deposit-json")
        .arg("--format")
        .arg("json")
        .arg("--validator-count") // Count > 1
        .arg("2")
        // Missing --amounts
        .output()?;
    assert!(!output.status.success());
    // Check for the new manual validation error message
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("--amounts is required when --create-deposit-json is specified and validator_count > 1"));

    // Fail: --create-deposit-json with validator_count == 1 but --amounts IS provided
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--create-deposit-json")
        .arg("--format")
        .arg("json")
        .arg("--validator-count") // Count == 1
        .arg("1")
        .arg("--amounts") // Should not be provided here
        .arg("64")
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("--amounts should not be provided when --create-deposit-json is specified and validator_count is 1"));


    // Fail: --amounts count mismatch (validator_count > 1)
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--create-deposit-json")
        .arg("--format")
        .arg("json")
        .arg("--validator-count")
        .arg("3") // Count > 1
        .arg("--amounts")
        .arg("32,64") // Only 2 amounts provided, expected 3
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Number of amounts (2) must match validator_count (3) when validator_count > 1")); // Updated error check

    // Fail: --amounts value out of range (validator_count > 1)
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--create-deposit-json")
        .arg("--format")
        .arg("json")
        .arg("--validator-count")
        .arg("2") // Count > 1
        .arg("--amounts")
        .arg("32,31") // Second amount too low
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Amount for validator 1 (31) is outside the allowed range [32, 2048]")); // Index 1 because default start index is 0

    // Fail: --eth-amount value out of range (validator_count == 1)
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--withdrawal-address")
        .arg(TEST_WITHDRAWAL_ADDR)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .arg("--create-deposit-json")
        .arg("--format")
        .arg("json")
        .arg("--validator-count")
        .arg("1") // Count == 1
        // No --amounts provided (correct)
        .arg("--eth-amount")
        .arg("31") // eth-amount too low
        .output()?;
    assert!(!output.status.success());
    // Check for the CLI-level error message, which includes the credential type context
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("CLI Error: ETH amount (31) is outside the allowed range [32, 2048] for Pectra credentials when validator_count is 1"));

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
        .arg("--create-deposit-json")
        .arg("--format")
        .arg("json")
        .arg("--validator-count")
        .arg("2") // count > 1
        .arg("--amounts")
        .arg("32,32") // Use amounts valid for "01" credentials
        .arg("--withdrawal-credential-type")
        .arg("01") // Use the correct CLI value "01"
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_output: Value = serde_json::from_str(&stdout)?;

    // Verify new JSON structure
    assert!(json_output["deposit_data"].is_array());
    assert_eq!(json_output["deposit_data"].as_array().unwrap().len(), 2);
    assert!(json_output["deposit_data"][0]["placeholder"].as_bool().unwrap()); // Check placeholder
    assert_eq!(json_output["deposit_data"][0]["amount_eth"], 32);
    assert_eq!(json_output["deposit_data"][0]["withdrawal_credential_type"], "Eth1"); // JSON still uses Enum variant name
    assert_eq!(json_output["deposit_data"][1]["amount_eth"], 32); // Check second amount is 32

    assert!(json_output["keystores"].is_array());
    assert_eq!(json_output["keystores"].as_array().unwrap().len(), 2);
    assert!(json_output["keystores"][0]["pubkey"].is_string());
    assert!(json_output["keystores"][1]["pubkey"].is_string());

    assert!(json_output["mnemonic"]["seed"].is_string());

    assert!(json_output["private_keys"].is_array());
    assert_eq!(json_output["private_keys"].as_array().unwrap().len(), 2);
    assert!(json_output["private_keys"][0].is_string());
    assert!(json_output["private_keys"][0].as_str().unwrap().starts_with("0x"));
    assert!(json_output["private_keys"][1].is_string());
    assert!(json_output["private_keys"][1].as_str().unwrap().starts_with("0x"));

    // Ensure parameters object is NOT present in the new format
    assert!(json_output["parameters"].is_null()); // Ensure old parameters object is gone

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
        .arg("--create-deposit-json")
        .arg("--format")
        .arg("json")
        .arg("--validator-count")
        .arg("1") // count == 1
        // No --amounts (correct)
        .arg("--eth-amount")
        .arg("48") // Use --eth-amount
        .arg("--withdrawal-credential-type")
        .arg("02") // Test default type
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_output: Value = serde_json::from_str(&stdout)?;

    // Verify new JSON structure for single validator case
    assert!(json_output["deposit_data"].is_array());
    assert_eq!(json_output["deposit_data"].as_array().unwrap().len(), 1);
    assert!(json_output["deposit_data"][0]["placeholder"].as_bool().unwrap());
    assert_eq!(json_output["deposit_data"][0]["amount_eth"], 48); // Check correct amount used
    assert_eq!(json_output["deposit_data"][0]["withdrawal_credential_type"], "Pectra");

    assert!(json_output["keystores"].is_array());
    assert_eq!(json_output["keystores"].as_array().unwrap().len(), 1);
    assert!(json_output["keystores"][0]["pubkey"].is_string());

    assert!(json_output["mnemonic"]["seed"].is_string());

    assert!(json_output["private_keys"].is_array());
    assert_eq!(json_output["private_keys"].as_array().unwrap().len(), 1);
    assert!(json_output["private_keys"][0].is_string());
    assert!(json_output["private_keys"][0].as_str().unwrap().starts_with("0x"));

    assert!(json_output["parameters"].is_null());

    Ok(())
}
