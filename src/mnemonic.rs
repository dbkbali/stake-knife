use bip39::{Mnemonic, Language};
use anyhow::Result;

/// Generates a new 24-word BIP-39 mnemonic phrase
/// 
/// # Returns
/// - `Result<String>`: The generated mnemonic phrase or error
pub fn generate_mnemonic() -> Result<String> {
    // Create random mnemonic with 24 words (256 bits of entropy)
    let mnemonic = Mnemonic::generate_in(Language::English, 24)?;
    Ok(mnemonic.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;

    #[test]
    fn test_generate_mnemonic() {
        let phrase = generate_mnemonic().unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24, "Mnemonic should have 24 words");
        
        // Verify the phrase is valid according to BIP-39
        Mnemonic::parse_in(Language::English, &phrase).unwrap();
    }

    #[test]
    fn test_mnemonic_entropy() {
        // Generate multiple mnemonics and verify they're different
        let phrase1 = generate_mnemonic().unwrap();
        let phrase2 = generate_mnemonic().unwrap();
        assert_ne!(phrase1, phrase2, "Mnemonics should be randomly different");
    }
}
