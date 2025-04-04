use clap::{Parser,ValueEnum};
use anyhow::Result;
use std::path::PathBuf;
mod mnemonic;


/// Supported output formats
#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Plain,
    Json,
}

/// CLI for Ethereum 2 staking operations
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
enum Commands {
    /// Generate BIP-39 mnemonic phrases
    Mnemonic {
        /// Output format
        #[arg(value_enum, short, long, default_value_t = OutputFormat::Plain)]
        format: OutputFormat,
    },
    /// Manage validator wallets
    Wallet {
        /// Output directory for wallet files
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
    },
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Plain => write!(f, "plain"),
            OutputFormat::Json => write!(f, "json"),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "plain" => Ok(OutputFormat::Plain),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Invalid format: {}", s)),
        }
    }
}

fn main() -> Result<()> {
    match Commands::parse() {
        Commands::Mnemonic { format } => {
            let phrase = mnemonic::generate_mnemonic()?;
            print_output(&phrase, format)
        }
        Commands::Wallet { output_dir: _output_dir } => {
            println!("Wallet functionality coming soon");
            Ok(())
        }
    }
}

/// Prints the mnemonic in the requested format
fn print_output(phrase: &str, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!(r#"{{"mnemonic":"{}"}}"#, phrase),
        OutputFormat::Plain => println!("{}", phrase),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_cmd::Command;
    use predicates::prelude::*;

    #[test]
    fn test_mnemonic_plain_output() -> Result<()> {
        let mut cmd = Command::cargo_bin("stake-knife")?;
        let output: std::process::Output = cmd.arg("mnemonic").output()?;
        let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
        
        println!("Test output: {}", stdout);
        
        // Check output with assertions
        assert!(predicate::str::is_match(r"^[a-z]+( [a-z]+){23}\n?$").unwrap().eval(&stdout));
        
        Ok(())
    }

    #[test]
    fn test_mnemonic_json_output() -> Result<()> {
        let mut cmd = Command::cargo_bin("stake-knife")?;
        let output: std::process::Output = cmd.arg("mnemonic").arg("--format").arg("json").output()?;
        let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);

        println!("Test JSON output: {}", stdout);

        assert!(predicate::str::is_match(r#"\{"mnemonic":"[a-z]+( [a-z]+){23}"\}"#).unwrap().eval(&stdout));
        Ok(())
    }
}
