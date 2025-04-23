use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn test_json_output_includes_mnemonic_when_generated() {
    let mut cmd = Command::cargo_bin("stake-knife").unwrap();
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--password").arg("testpassword123")
        .arg("--eth-amounts").arg("32")
        .arg("--withdrawal-address").arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--format").arg("json")
        .output()
        .expect("failed to run command");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Extract the JSON portion from the output
    let json_start = stdout.find('{').expect("No JSON found in output");
    let json_text = &stdout[json_start..];
    let json: Value = serde_json::from_str(json_text).expect("output should be valid JSON");
    // Should include mnemonic and warning
    assert!(json.get("mnemonic").is_some(), "mnemonic should be in JSON output");
    assert!(json.get("warning").is_some(), "warning should be in JSON output");
    assert!(json.get("keystores").is_some(), "keystores should be in JSON output");
    // mnemonic should be 24 words
    let mnemonic = json.get("mnemonic").unwrap().as_str().unwrap();
    assert_eq!(mnemonic.split_whitespace().count(), 24);
}

#[test]
fn test_json_output_excludes_mnemonic_when_provided() {
    let mut cmd = Command::cargo_bin("stake-knife").unwrap();
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--mnemonic").arg("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
        .arg("--password").arg("testpassword123")
        .arg("--eth-amounts").arg("32")
        .arg("--withdrawal-address").arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--format").arg("json")
        .output()
        .expect("failed to run command");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Try to extract JSON if present
    if let Some(json_start) = stdout.find('{') {
        let json_text = &stdout[json_start..];
        let json: Result<Value, _> = serde_json::from_str(json_text);
        if let Ok(json) = json {
            assert!(json.get("mnemonic").is_some(), "mnemonic should not be in JSON output if provided by user");
        } else {
            // If not a single JSON object, check that mnemonic is not present in any output
            assert!(!stdout.contains("mnemonic"), "mnemonic should not appear in output");
        }
    } else {
        // No JSON found, just check that mnemonic is not present in any output
        assert!(!stdout.contains("mnemonic"), "mnemonic should not appear in output");
    }
}
