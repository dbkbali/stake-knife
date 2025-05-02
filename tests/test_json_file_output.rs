use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

#[test]
fn test_json_output_to_secure_file() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for the test
    let temp_dir = tempdir()?;
    let json_output_path = temp_dir.path().join("validator-keys.json");
    
    // Run the command with --json-output-file
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let assert = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32")
        .arg("--withdrawal-address")
        .arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password")
        .arg("test123456")
        .arg("--format")
        .arg("json")
        .arg("--json-output-file")
        .arg(&json_output_path)
        .assert()
        .success();
    
    // Check that the output contains the success message
    let output = String::from_utf8(assert.get_output().stdout.clone())?;
    assert!(output.contains(&format!("Secure JSON output written to: {}", json_output_path.display())));
    
    // Check that the file exists
    assert!(json_output_path.exists());
    
    // Check the file permissions (0600 = read/write for owner only)
    let metadata = fs::metadata(&json_output_path)?;
    let permissions = metadata.permissions();
    assert_eq!(permissions.mode() & 0o777, 0o600);
    
    // Check that the file contains valid JSON with expected structure
    let json_content = fs::read_to_string(&json_output_path)?;
    let json_value: Value = serde_json::from_str(&json_content)?;
    
    // Verify the JSON structure
    assert!(json_value.is_object());
    assert!(json_value.get("keystores").is_some());
    assert!(json_value.get("deposit_data").is_some());
    assert!(json_value.get("private_keys").is_some());
    assert!(json_value.get("parameters").is_some());
    
    Ok(())
}

#[test]
fn test_json_output_file_validation() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for the test
    let temp_dir = tempdir()?;
    let json_output_path = temp_dir.path().join("validator-keys.json");
    
    // Try to use --json-output-file with --format files (should fail)
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let assert = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32")
        .arg("--withdrawal-address")
        .arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password")
        .arg("test123456")
        .arg("--format")
        .arg("files")
        .arg("--json-output-file")
        .arg(&json_output_path)
        .assert()
        .failure();
    
    // Check that the error message is correct
    let error_output = String::from_utf8(assert.get_output().stderr.clone())?;
    assert!(error_output.contains("--json-output-file can only be used with --format json"));
    
    // Check that the file was not created
    assert!(!json_output_path.exists());
    
    Ok(())
}

#[test]
fn test_json_output_file_creates_directories() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for the test
    let temp_dir = tempdir()?;
    let nested_dir_path = temp_dir.path().join("nested").join("directories");
    let json_output_path = nested_dir_path.join("validator-keys.json");
    
    // Run the command with a nested directory path that doesn't exist yet
    let mut cmd = Command::cargo_bin("stake-knife")?;
    cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amounts")
        .arg("32")
        .arg("--withdrawal-address")
        .arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password")
        .arg("test123456")
        .arg("--format")
        .arg("json")
        .arg("--json-output-file")
        .arg(&json_output_path)
        .assert()
        .success();
    
    // Check that the nested directories were created
    assert!(nested_dir_path.exists());
    assert!(json_output_path.exists());
    
    // Check the directory permissions
    let dir_metadata = fs::metadata(&nested_dir_path)?;
    let dir_permissions = dir_metadata.permissions();
    // Directory should have at least 0700 permissions (rwx for owner only)
    assert_eq!(dir_permissions.mode() & 0o700, 0o700);
    
    Ok(())
}
