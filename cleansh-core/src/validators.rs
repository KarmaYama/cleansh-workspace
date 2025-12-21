// File: cleansh-core/src/validators.rs
//! Programmatic validation functions for specific sensitive data types.
//!
//! This module provides additional validation logic beyond regular expression matching
//! for sensitive information such as SSN and UK NINO. These functions help reduce
//! false positives by applying structural and known invalid pattern checks.
//!
//! License: MIT OR APACHE 2.0

use std::borrow::Cow;
use std::collections::HashSet;
use once_cell::sync::Lazy;

/// Helper function to validate SSN based on US Social Security Administration rules.
///
/// This implementation aims for a robust programmatic check without external data.
/// It validates the structural components against known invalid patterns.
///
/// # Arguments
///
/// * `ssn` - The SSN string slice to validate. Expected format "XXX-XX-XXXX".
///
/// # Returns
///
/// `true` if the SSN passes basic structural and invalid pattern checks, `false` otherwise.
pub fn is_valid_ssn_programmatically(ssn: &str) -> bool {
    let mut parts = ssn.split('-');

    // Use a single pattern match to validate the structure and extract parts.
    // This is more concise and less error-prone than a series of `if let` checks.
    let (Some(area), Some(group), Some(serial), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return false;
    };

    if area.len() != 3 || group.len() != 2 || serial.len() != 4 {
        return false;
    }

    let Some(area_num) = area.parse::<u16>().ok() else { return false; };
    let Some(group_num) = group.parse::<u8>().ok() else { return false; };
    let Some(serial_num) = serial.parse::<u16>().ok() else { return false; };

    // Check for invalid SSN patterns based on historical and current rules.
    let invalid_area = (area_num == 0) || (area_num == 666) || (area_num >= 800);
    let invalid_group = group_num == 0;
    let invalid_serial = serial_num == 0;
    
    !(invalid_area || invalid_group || invalid_serial)
}

// Use a `once_cell` to create a static HashSet for efficient lookups.
static INVALID_NINO_PREFIXES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.extend(["BF", "BG", "EH", "GB", "JE", "NK", "KN", "LI", "NT", "TN", "ZZ"]);
    set
});

static INVALID_NINO_PREFIX_CHARS: Lazy<HashSet<char>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.extend(['D', 'F', 'I', 'Q', 'U', 'V', 'O']);
    set
});

static VALID_NINO_SUFFIX_CHARS: Lazy<HashSet<char>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.extend(['A', 'B', 'C', 'D']);
    set
});

/// Helper function to validate UK National Insurance Number (NINO) based on HMRC rules.
///
/// This implementation aims for a robust programmatic check without external data.
/// It validates the structural components against known invalid patterns and characters.
///
/// # Arguments
///
/// * `nino` - The NINO string slice to validate. Expected format "AA######A" (where # are digits).
///
/// # Returns
///
/// `true` if the NINO passes basic structural and invalid pattern checks, `false` otherwise.
pub fn is_valid_uk_nino_programmatically(nino: &str) -> bool {
    const NINO_LENGTH: usize = 9;

    let nino_normalized: Cow<str> = if nino.chars().any(|c: char| c.is_ascii_lowercase()) {
        Cow::Owned(nino.to_uppercase())
    } else {
        Cow::Borrowed(nino)
    };
    
    let nino_no_spaces = nino_normalized.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    
    if nino_no_spaces.len() != NINO_LENGTH {
        return false;
    }

    let mut chars = nino_no_spaces.chars();
    
    // Check prefix chars using iterators for efficiency
    let (Some(prefix_char1), Some(prefix_char2)) = (chars.next(), chars.next()) else { return false; };
    if !prefix_char1.is_ascii_alphabetic() || !prefix_char2.is_ascii_alphabetic() {
        return false;
    }
    
    // Check for invalid prefix characters and combinations
    let prefix_str = &nino_no_spaces[0..2];
    if INVALID_NINO_PREFIXES.contains(prefix_str) {
        return false;
    }
    if INVALID_NINO_PREFIX_CHARS.contains(&prefix_char1) || INVALID_NINO_PREFIX_CHARS.contains(&prefix_char2) {
        return false;
    }

    // Check that the middle 6 characters are digits
    if !chars.by_ref().take(6).all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Check suffix character
    let Some(suffix_char) = chars.next() else { return false; };
    if !VALID_NINO_SUFFIX_CHARS.contains(&suffix_char) {
        return false;
    }

    // Check if there are any remaining characters
    if chars.next().is_some() {
        return false;
    }

    true
}

/// Validates a number using the Luhn algorithm.
///
/// The Luhn algorithm, also known as the Mod 10 algorithm, is a simple checksum
/// formula used to validate a variety of identification numbers, such as
/// credit card numbers.
///
/// # Arguments
///
/// * `num_str` - A string slice containing only digits.
///
/// # Returns
///
/// `true` if the number is valid according to the Luhn algorithm, `false` otherwise.
pub fn is_valid_luhn(num_str: &str) -> bool {
    let mut sum = 0;
    let mut alternate = false;

    for c in num_str.chars().rev() {
        let Some(mut digit) = c.to_digit(10) else { return false; };

        if alternate {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
        alternate = !alternate;
    }

    sum % 10 == 0
}

/// Helper function to validate credit card numbers based on the Luhn algorithm.
///
/// This function first strips all non-digit characters from the input string
/// and then applies the Luhn algorithm to the resulting digit string.
///
/// # Arguments
///
/// * `cc_number` - The credit card number string slice to validate.
///
/// # Returns
///
/// `true` if the number is valid according to the Luhn algorithm, `false` otherwise.
pub fn is_valid_credit_card_programmatically(cc_number: &str) -> bool {
    let digits: String = cc_number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return false;
    }
    is_valid_luhn(&digits)
}