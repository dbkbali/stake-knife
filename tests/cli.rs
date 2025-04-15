use anyhow::Result;
use assert_cmd::Command;

#[test]
fn test_wallet_generate_validation() -> Result<()> {
    let mut cmd = Command::cargo_bin("stake-knife")?;

    // Test invalid ETH amount
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amount")
        .arg("31")
        .arg("--withdrawal-address")
        .arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password")
        .arg("testpassword123")
        .output()?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("ETH amount must be between 32 and 2048"));

    // Test invalid withdrawal address
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amount")
        .arg("32")
        .arg("--withdrawal-address")
        .arg("invalid-address")
        .arg("--password")
        .arg("testpassword123")
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
        .arg("32")
        .arg("--withdrawal-address")
        .arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password")
        .arg("short")
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
        .arg("32")
        .arg("--withdrawal-address")
        .arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password")
        .arg("testpassword123")
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify output contains expected information
    assert!(stdout.contains("ETH amount: 32 ETH"));
    assert!(stdout.contains("Withdrawal address: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F"));
    assert!(stdout.contains("Generated 1 validator keystore"));
    // No longer checking for public key in output as it's now in the keystore file

    Ok(())
}

#[test]
fn test_wallet_generate_dry_run() -> Result<()> {
    let mut cmd = Command::cargo_bin("stake-knife")?;
    let output = cmd
        .arg("wallet")
        .arg("generate")
        .arg("--eth-amount")
        .arg("32")
        .arg("--withdrawal-address")
        .arg("0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        .arg("--password")
        .arg("testpassword123")
        .arg("--dry-run")
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify dry run message is present
    // In the batch implementation, the dry run check happens before the loop
    assert!(stdout.contains("DRY RUN"));

    Ok(())
}
