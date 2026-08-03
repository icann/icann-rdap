//! RFC 9839 functions.

/// Determines if a character is problematic according to RFC9839.
fn is_problematic(c: char) -> bool {
    let cp = c as u32;

    // 1. Surrogates: U+D800 to U+DFFF
    // (Note: Rust's 'char' type technically shouldn't contain these,
    // but they can appear in unchecked byte sequences or UTF-16)
    if (0xD800..=0xDFFF).contains(&cp) {
        return true;
    }

    // 2. Noncharacters: U+FDD0..U+FDEF and those ending in FFFE/FFFF
    if (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE) == 0xFFFE {
        return true;
    }

    // 3. Control Characters: C0 (00-1F, 7F) and C1 (80-9F)
    // Excludes JSON whitespace: tab (0x09), LF (0x0A), CR (0x0D) per RFC 8259
    if cp == 0x7F || (0x80..=0x9F).contains(&cp) {
        return true;
    }
    if (0x00..=0x1F).contains(&cp) && cp != 0x09 && cp != 0x0A && cp != 0x0D {
        return true;
    }

    false
}

/// Sanitizes problematic code points.
pub fn sanitize_rfc9839(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if is_problematic(c) {
                '\u{FFFD}' // Unicode Replacement Character
            } else {
                c
            }
        })
        .collect()
}
